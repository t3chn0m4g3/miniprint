# miniprint

A medium interaction printer honeypot for PJL on TCP 9100 and an embedded web
administration interface on TCP 80. It captures printer payloads and records
probes as newline-delimited JSON. Device configuration changes are simulated;
admin, LDAP, SMTP and SSRF handlers do not open outbound connections.

## Run

```bash
docker compose up -d --build
```

The container runs as UID/GID 2000, with a read-only root filesystem, dropped
capabilities, `no-new-privileges`, 256 MiB memory, one CPU and 128 PIDs. Build
arguments `MINIPRINT_UID` and `MINIPRINT_GID` override ownership. On Linux,
bind-mounted directories must be writable by those IDs.

| Host path | Container path | Content |
|---|---|---|
| `log/` | `/app/log/` | `miniprint.json` |
| `uploads/` | `/app/uploads/` | Captured jobs and firmware |
| `data/` | `/app/data/` | Persistent `identity.json` |

The healthcheck reads the running server arguments from `/proc/1/cmdline`,
respects custom ports and `--no-http`, and probes loopback only. Empty loopback
health checks do not generate session events.

## Personas and identity

Use `--persona brother`, `hp`, `lexmark`, or `random`; the default is `random`.
`MINIPRINT_PERSONA` supplies the default for CLI and Compose, and an explicit CLI
flag takes precedence.

| Persona | Model | HTTP banner |
|---|---|---|
| Brother | MFC-L9570CDW | `Debut/1.30` |
| HP | LaserJet 4200 | `HP-ChaiServer/3.0` |
| Lexmark | MX521ade | `Lexmark_Web_Server` |

The first random selection and the generated serial, hostname, MAC suffix and
firmware are stored in `--state-dir` (default `data/`). Restarts retain that
identity. Delete `identity.json` or use `--reroll-identity` to generate another.
Selecting a different fixed persona replaces the stored identity. An unwritable
state directory produces a console warning and an identity held only in memory.

HTTP, PJL and seed filesystem content use the same device profile. Banners and
routes have source references in `personas.py`; the profiles approximate device
behavior and do not emulate every firmware endpoint.

Virtual files, variables and ready messages remain available across reconnects
from the same source IP. This state is held in memory, with a 24-hour idle TTL
and an LRU limit of 256 sources. Restarting clears it. Commands are synchronized
per source; `FSINIT` resets only that source's virtual filesystem.

## Protocols and limits

PJL supports filesystem commands, INFO ID/STATUS/CONFIG/VARIABLES/FILESYS/MEMORY/
PAGECOUNT/PRODINFO, Brother BRFIRMWARE, INQUIRE/DINQUIRE/SET/DEFAULT, JOB/EOJ,
ECHO, USTATUSOFF, RDYMSG and simulated RNVRAM bytes. Filesystem operations use
pyfakefs, without access to host files.

`@PJL ENTER LANGUAGE=POSTSCRIPT`, `PCL`, `PCLXL` or `PDF` captures bytes through
the next UEL (`ESC%-12345X`) or EOF. Other languages use `.prn`. Delimiters may
cross TCP chunks; binary bodies may contain PJL-like text. A standalone `%!`
stream is captured as PostScript. Captured artifacts use time/hash filenames,
never attacker-supplied host paths.

| Limit | Default |
|---|---:|
| Total concurrent HTTP and PJL connections | 16 |
| PJL idle timeout (`--timeout`) | 60 s |
| PJL total deadline (`--session-timeout`) | 300 s |
| HTTP socket timeout | 15 s |
| PJL command bytes / ordinary HTTP body (`--max-request-bytes`) | 65,536 |
| Cumulative print-job bytes / firmware body (`--max-job-bytes`) | 1,048,576 |
| Each virtual file (`--max-virtual-file-bytes`) | 262,144 |
| Each command response (`--max-response-bytes`) | 131,072 |

The hard PJL connection byte limit is command bytes plus job bytes. Limit events
close PJL connections and preserve captured job prefixes. Oversized HTTP bodies
receive 413. FSUPLOAD returns FILEERROR=1 if the complete reply exceeds the
response limit, so its advertised SIZE always matches the binary body.

HTTP uses HTTP/1.1, a single persona Server header and device-themed error pages.
Keep-Alive requests share a connection/session ID.

## Brother lure chain

For the Brother persona only:

1. `GET /etc/mnt_info.csv` exposes model, `Serial No.` and node name.
2. Derive the default password locally with `brother.brother_default_password`.
3. POST `username=admin&password=...` to `/login`, or POST the password from the
   `LogBox` form to `/general/status.html`. A successful login sets `AuthCookie`.
4. Visit `/admin/network`, `/admin/ldap`, `/admin/smtp`, `/admin/snmp` and
   `/admin/firmware`. Settings POSTs return `saved`. LDAP/SMTP server changes
   generate passback events. Firmware POSTs capture raw or multipart file data.
5. A nonnumeric `@PJL SET FORMLINES=...` closes the PJL connection and simulates
   a 60–120 second reboot for that source IP across HTTP and PJL.

Cookies expire after 30 minutes, are bound to the source IP, and are limited to
1024 in-memory sessions. Passwords and secret form values are omitted from
logs; `secret_supplied` records whether a secret was supplied.

The password implementation uses the official Metasploit default salt index
254. Tests use vectors independently checked against that Ruby routine. The
serial in Rapid7's published worked example is masked, so it cannot serve as an
unmasked test vector.

| Event | CVE hint | Persona |
|---|---|---|
| `serial_leak_probe` | CVE-2024-51977 | Brother |
| `default_password_probe`, `default_password_success` | CVE-2024-51978 | Brother |
| `pjl_crash_probe` | CVE-2024-51982 | Brother |
| `passback_attempt` | CVE-2024-51984 | Brother |
| `path_traversal_probe` | CVE-2025-1127 | Lexmark |
| `ssrf_probe` | CVE-2025-9269 | Lexmark |

CVE hints classify observed lure behavior; they do not claim a real firmware
vulnerability. WSD CVEs are not assigned to arbitrary HTTP URL parameters.
SNMP, LPD, WSD and IPP listeners are outside this implementation.

## Log schema

`log/miniprint.json` is JSONL. Session records contain `session_id`, `src_ip`,
`src_port`, `dest_ip`, `dest_port`, `session_start`, `protocol` and `persona`.
Null fields are omitted. Lifecycle events (`server_start`, `server_stop`,
`signal`, `identity_ephemeral`) are console-only.

Each logged connection ends once with `session_end` and `session_duration`:
PJL uses `connection_closed`, `empty_connection`, or `connection_limit`; HTTP
uses `http_connection_closed` or `connection_limit`. Each HTTP request emits
`http_request_completed` without `session_end`.

| Field | Meaning |
|---|---|
| `virtual_path` | Path inside the fake filesystem |
| `file_name` | Artifact basename in `uploads/` |
| `payload_sha256` | SHA-256 of the command or saved payload |
| `payload_preview` | Bounded preview, with HTTP secrets redacted |
| `artifact_type` | `ps`, `pcl`, `pdf`, `raw`, or `firmware` |
| `language` | Selected print language |
| `cve_hint` | Comma-separated hints from the selected persona |
| `secret_supplied` | Boolean; no plaintext credential |
| `form_fields` | Admin form fields as `name`/`value` pairs, secrets omitted, at most 32 |
| `passback_target` | First non-empty server or host value of a `passback_attempt` |

Artifact events include `save_print_job`, `save_raw_print_job`,
`save_postscript` and `save_firmware`, with `file_name`, hash and byte `size`.
`command_error` includes `error_type`, command hash and preview, while the
session continues. `session_error`, `artifact_error`, `http_error`,
`session_timeout`, `request_too_large`, `job_too_large`, `connection_too_large`
and `reboot_suppressed` explain failures or controlled closure.

Breaking changes: HTTP now listens on container port 80; identity state needs
its own writable volume; command responses are bytes; virtual paths use
`virtual_path`; HTTP request completion and connection closure are separate;
UID/GID defaults are 2000; persona selection defaults to a persisted random
choice. Consumers must aggregate by session ID through `session_end`.

The updated ewsposter adapter preserves open sessions across polling runs,
deduplicates completed sessions, skips empty connections by default
(`send_empty_connections = false`) and selects firmware before document before
raw artifacts. All artifacts are listed in additional data. `size` and `limit`
are represented by purpose-specific fields such as `artifact_size` and
`request_too_large_size`.

## T-Pot integration

T-Pot builds its own image from a release tag, with UID/GID 2000 and
`/opt/miniprint` paths. Its host port 80 belongs to h0neytr4p, so T-Pot starts
miniprint with `--http-port 8000` and publishes ports 9100 and 8000. Log, upload
and state directories are `${TPOT_DATA_PATH}/miniprint/{log,uploads,data}`.
The local Compose file of this repository uses port 80 and is not a drop-in
addition to T-Pot. Docker allows non-root binding on port 80 with all
capabilities dropped; set `net.ipv4.ip_unprivileged_port_start=0` in deployment
sysctls if another runtime requires it.

## Development and verification

```bash
uv sync
uv run python server.py --bind 127.0.0.1 --http-port 8080 --persona brother
uv run python server.py --no-http --persona hp
uv run python server.py --help
uv run pytest
uv run ruff check .
```

Run the opt-in smoke suite against a built, running container:

```bash
MINIPRINT_CONTAINER_SMOKE=1 uv run pytest tests/test_container_smoke.py
```

For an isolated container, set `MINIPRINT_CONTAINER`, `MINIPRINT_PJL_PORT`,
`MINIPRINT_HTTP_PORT`, `MINIPRINT_LOG_FILE` and `MINIPRINT_UPLOADS_DIR`. The
Brother-chain smoke test requires that container to use `--persona brother`.
PRET can exercise `id`, `info config`, `env`, `ls`, `put` and reconnects.

Runtime dependencies and development tools are declared in `pyproject.toml`
and pinned by `uv.lock`. Python 3.14 and `uv` are required for local development.
