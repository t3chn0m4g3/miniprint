# miniprint

<img align="right" width="212" height="288" src="https://user-images.githubusercontent.com/3712226/54886937-78f7b180-4e5b-11e9-8ccc-18716f2b5a3b.png">

miniprint is a medium-interaction printer honeypot. It exposes a raw
JetDirect/PJL printer service and a passive web-admin surface that looks like a
network printer accidentally exposed to the internet.

The honeypot is intentionally complementary to IPP-focused honeypots such as
IPPHoney: miniprint does not listen on IPP/631.

## What It Emulates

| Surface | Default port | Behavior |
|:--|:--|:--|
| Raw/JetDirect | `9100/tcp` | PJL commands, virtual filesystem, raw jobs, PostScript capture |
| Web admin | `8080/tcp` in the container, `80/tcp` via Compose | Passive status pages, device info, login probes, admin/config probes |
| IPP | Not exposed | Use a dedicated IPP honeypot instead |

PJL support includes `ECHO`, `USTATUSOFF`, `INFO ID`, `INFO STATUS`,
`FSDIRLIST`, `FSQUERY`, `FSMKDIR`, `FSUPLOAD`, `FSDOWNLOAD`, `FSAPPEND`,
`FSDELETE`, `FSINIT`, and `RDYMSG`.

The HTTP surface recognizes interesting printer attack probes and logs them with
CVE-style hints. It never performs outbound requests, real authentication
bypass, firmware parsing, or PostScript execution.

## Run With Docker

Docker Compose is the recommended production path:

```bash
docker compose up -d --build
```

This publishes:

```text
9100/tcp -> raw PJL printer
80/tcp   -> fake web-admin surface
```

Runtime output is written to:

```text
log/miniprint.json
uploads/
```

The container is built on Python 3.14, runs as a non-root user, uses a read-only
root filesystem, drops Linux capabilities, uses `no-new-privileges`, and has a
healthcheck for both exposed services.

The Docker image starts miniprint with explicit conservative application limits:

| Limit | Docker value |
|:--|--:|
| Connection timeout | `60s` |
| Total concurrent PJL and HTTP connections | `16` |
| PJL session deadline | `300s` |
| HTTP socket timeout | `15s` |
| Request size | `65,536 bytes` |
| Print/PostScript job artifact | `1,048,576 bytes` |
| Virtual filesystem file | `262,144 bytes` |
| Response size | `131,072 bytes` |

Compose additionally caps the container at `1` CPU, `256m` memory, `128` PIDs,
and a conservative `nofile` ulimit. `nproc` is intentionally not set because it
can be evaluated against the host UID's total process count before the app even
starts.

The Dockerfile is multiarch-ready for `linux/amd64` and `linux/arm64`. Those are
the platforms shared by the pinned Python base image and the pinned `uv` image.

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t miniprint:latest .
```

The container healthcheck performs local TCP checks against the PJL and HTTP
listeners, using the running server arguments from `/proc/1/cmdline`; `--no-http`
disables the HTTP probe and custom ports are honored. Empty loopback connections are filtered so routine healthchecks do
not fill `log/miniprint.json` with connection open/close events.

The image defaults to UID/GID `2000:2000` for T-Pot data volumes. Override these
with Docker build arguments `MINIPRINT_UID` and `MINIPRINT_GID` when needed.
Existing Linux bind mounts must be writable by the configured UID/GID.

## Local Development

This repository uses `uv` directly. `pyproject.toml` is the source of dependency
truth and `uv.lock` pins the resolved versions. The old `requirements*.txt`
workflow is intentionally not kept in parallel.

```bash
uv sync
uv run python ./server.py
```

Useful development checks from the repository root:

```bash
uv run pytest
uv run ruff check .
uv run bandit -c pyproject.toml -r .
uv export --locked --no-dev --no-emit-project --format requirements.txt -o /tmp/miniprint-runtime.txt
uv run pip-audit -r /tmp/miniprint-runtime.txt
```

`pytest` is configured to discover tests from `tests/`, so the root command
above is enough.

## CLI

```text
usage: miniprint [-h] [-b HOST] [--pjl-port PJL_PORT] [--http-port HTTP_PORT]
                 [--no-http] [-l LOG_FILE] [-t TIMEOUT]
                 [--session-timeout SESSION_TIMEOUT] [--uploads-dir UPLOADS_DIR]
                 [--max-connections MAX_CONNECTIONS]
                 [--max-request-bytes MAX_REQUEST_BYTES]
                 [--max-job-bytes MAX_JOB_BYTES]
                 [--max-virtual-file-bytes MAX_VIRTUAL_FILE_BYTES]
                 [--max-response-bytes MAX_RESPONSE_BYTES]
```

Examples:

```bash
uv run python ./server.py --bind 0.0.0.0 --log-file log/miniprint.json
uv run python ./server.py --bind 127.0.0.1 --no-http
uv run python ./server.py --max-job-bytes 1048576 --max-connections 16
```

To interact with the PJL surface manually, PRET can be used:

```bash
python ./pret.py localhost pjl
```

## Logging And Artifacts

Logs are newline-delimited JSON. Events include connection context and
classification metadata. Fields with no value are omitted rather than logged as
`null`. Connection-scoped events use canonical source, destination, and session
fields such as:

```json
{
  "timestamp": "2026-06-16T11:00:00.000000Z",
  "info": "HTTP request received",
  "session_id": "...",
  "src_ip": "203.0.113.10",
  "src_port": 52144,
  "dest_ip": "198.51.100.20",
  "dest_port": 8080,
  "session_start": "2026-06-16T11:00:00.000000Z",
  "protocol": "http",
  "user_agent": "curl/8.0",
  "event": "ssrf_probe",
  "cve_hint": "CVE-2024-51980,CVE-2024-51981,CVE-2025-9269"
}
```

### Log schema

Each logged connection has one terminal event with `session_end` and
`session_duration`: `connection_closed`, `empty_connection`,
`http_connection_closed`, or `connection_limit`. Empty loopback health checks
are suppressed. HTTP requests emit `http_request_completed` without
`session_end`; the HTTP connection closes separately, including on errors.
This replaces the former HTTP close event emitted per request.

`command_error` records a failed PJL command's `error_type`, `payload_sha256`,
and `payload_preview`; subsequent commands can still run. `session_timeout`
marks the PJL total deadline. `session_error` and `artifact_error` record
unexpected session or artifact failures with `error_type` and are followed
by the terminal connection event.

Lifecycle/control events such as `server_start`, `signal`, and `server_stop`
are emitted to the console, including Docker logs, but are intentionally not
written to `log/miniprint.json`. The file log also omits the generic logging
`level` field so analysts can focus on protocol, action, event, source,
destination, and payload correlation fields.

Full attacker-supplied files and print jobs are not copied into the log. They
are stored under `uploads/` with timestamp/hash-based filenames. Logs contain
payload hashes and short previews for correlation.

## Safety Model

miniprint is a passive emulator. The web surface is designed to look
interesting to scanners and opportunistic attackers while keeping host risk low:

* SSRF-looking parameters are detected and logged, but no outbound request is made.
* Login/default-password attempts are logged, but no real session is issued.
* Firmware and PostScript probes are classified, but never parsed or executed.
* PJL file operations, including append, delete, and init, are confined to an
  in-memory fake filesystem.
* Request, response, virtual file, and print-job sizes are bounded.

## Maintenance Notes

Dependency updates:

```bash
uv lock --upgrade
uv sync
uv run pytest
```

Docker verification:

```bash
docker compose build
docker compose config
docker buildx build --platform linux/amd64,linux/arm64 -t miniprint:latest .
```

Running-container smoke test:

```bash
docker compose up -d --build
MINIPRINT_CONTAINER_SMOKE=1 uv run pytest tests/test_container_smoke.py -q
```

The smoke test expects a running container named `miniprint`, PJL on
`127.0.0.1:9100`, HTTP on `127.0.0.1:80`, and logs at `log/miniprint.json`.
Override those with `MINIPRINT_CONTAINER`, `MINIPRINT_HOST`,
`MINIPRINT_PJL_PORT`, `MINIPRINT_HTTP_PORT`, and `MINIPRINT_LOG_FILE`.

Protocol smoke checks:

```bash
printf '@PJL INFO ID\r\n' | nc 127.0.0.1 9100
curl http://127.0.0.1/deviceinfo.xml
```

## Thanks

* frbexiga at BinaryEdge
* Jens Mueller for the hacking-printers.net wiki

Print streams selected by `@PJL ENTER LANGUAGE=` are captured through UEL or EOF
with `.ps`, `.pcl`, `.pdf`, or `.prn` suffixes. `save_print_job` includes `language`
and `artifact_type`. PJL command bytes and print payload bytes have separate
cumulative limits; `job_too_large` and `connection_too_large` close the session
while retaining the captured prefix. Unknown commands are logged at info level
with a name, SHA-256 and bounded preview.
