Align `honeypots/miniprint.py` with the completed 2026 miniprint lure schema.
The miniprint implementation is published on branch
[`lure-2026`](https://github.com/t3chn0m4g3/miniprint/tree/lure-2026).

## Changes

- Aggregate by session ID through `session_end`, defer open sessions across polling
  runs, rewind to their first line and deduplicate completed IDs using fileIndex.
  Sessions older than ten minutes can be emitted after an interrupted capture.
- Keep request/job limit measurements separate from artifact sizes.
- Preserve `virtual_path`, `persona`, `language`, `artifact_type` and unioned CVE hints.
- Attach firmware before print documents before raw payloads, using size to break ties;
  list every artifact name and hash in additional data.
- Summarize every Keep-Alive HTTP request and union `secret_supplied` over the session.
- Skip empty connections by default (`send_empty_connections = false`).
- Keep malwaredir and legacy uploaddir support, real source ports, append counters,
  missing-artifact handling and UTC timestamps.
- Remove XML-invalid control characters from Request text so binary/PJL probes
  cannot abort EWS serialization. Binary attachments are unchanged.

## Validation

- `python -m unittest discover tests`: 14 tests, OK.
- miniprint: 90 tests and two subtests pass; three opt-in container smoke tests pass.
- Real hardened-container logs replayed through two separate offline `ews.py -E`
  runs: 344 alerts, 344 unique session IDs, 24 attached artifacts, target ports
  80/9100, four empty PJL sessions excluded. The split session appears once after
  closure. On macOS, only the Linux abstract-socket process lock was adapted in a
  temporary wrapper; the EWS entry point, adapter and spool writer were unchanged.

## Real container log examples

These are actual JSONL lines from the 2026-10-09 container run. HTTP request
completion has no `session_end`; connection closure has it exactly once.

```jsonl
{"timestamp": "2026-10-09T12:13:40.745855Z", "info": "Serial number CSV requested", "persona": "brother", "session_id": "6d34cd13-5b2a-498d-a27a-8fb9a16c3806", "src_ip": "172.17.0.1", "src_port": 62774, "dest_ip": "172.17.0.2", "dest_port": 80, "session_start": "2026-10-09T12:13:40.745508Z", "protocol": "http", "event": "serial_leak_probe", "cve_hint": "CVE-2024-51977"}
{"timestamp": "2026-10-09T12:13:40.746204Z", "info": "HTTP request completed", "persona": "brother", "session_id": "6d34cd13-5b2a-498d-a27a-8fb9a16c3806", "src_ip": "172.17.0.1", "src_port": 62774, "dest_ip": "172.17.0.2", "dest_port": 80, "session_start": "2026-10-09T12:13:40.745508Z", "protocol": "http", "action": "request_completed", "event": "http_request_completed"}
{"timestamp": "2026-10-09T12:13:40.747175Z", "info": "Login attempt observed", "persona": "brother", "session_id": "6d34cd13-5b2a-498d-a27a-8fb9a16c3806", "src_ip": "172.17.0.1", "src_port": 62774, "dest_ip": "172.17.0.2", "dest_port": 80, "session_start": "2026-10-09T12:13:40.745508Z", "protocol": "http", "action": "auth", "event": "default_password_success", "username": "admin", "secret_supplied": true, "cve_hint": "CVE-2024-51978"}
{"timestamp": "2026-10-09T12:13:40.747450Z", "info": "HTTP request completed", "persona": "brother", "session_id": "6d34cd13-5b2a-498d-a27a-8fb9a16c3806", "src_ip": "172.17.0.1", "src_port": 62774, "dest_ip": "172.17.0.2", "dest_port": 80, "session_start": "2026-10-09T12:13:40.745508Z", "protocol": "http", "action": "request_completed", "event": "http_request_completed"}
{"timestamp": "2026-10-09T12:13:40.793692Z", "info": "Admin settings received", "persona": "brother", "session_id": "6d34cd13-5b2a-498d-a27a-8fb9a16c3806", "src_ip": "172.17.0.1", "src_port": 62774, "dest_ip": "172.17.0.2", "dest_port": 80, "session_start": "2026-10-09T12:13:40.745508Z", "protocol": "http", "event": "passback_attempt", "fields": {"server": ["ba328c02812247e09ddf48ea2109aa4b.example.test"]}, "secret_supplied": true, "cve_hint": "CVE-2024-51984"}
{"timestamp": "2026-10-09T12:13:40.794050Z", "info": "HTTP request completed", "persona": "brother", "session_id": "6d34cd13-5b2a-498d-a27a-8fb9a16c3806", "src_ip": "172.17.0.1", "src_port": 62774, "dest_ip": "172.17.0.2", "dest_port": 80, "session_start": "2026-10-09T12:13:40.745508Z", "protocol": "http", "action": "request_completed", "event": "http_request_completed"}
{"timestamp": "2026-10-09T12:13:40.836250Z", "info": "HTTP connection closed", "persona": "brother", "session_id": "6d34cd13-5b2a-498d-a27a-8fb9a16c3806", "src_ip": "172.17.0.1", "src_port": 62774, "dest_ip": "172.17.0.2", "dest_port": 80, "session_start": "2026-10-09T12:13:40.745508Z", "protocol": "http", "action": "close_conn", "event": "http_connection_closed", "session_end": "2026-10-09T12:13:40.836217Z", "session_duration": 0.090709}
{"timestamp": "2026-10-09T12:20:42.804114Z", "info": "Connection opened", "persona": "brother", "session_id": "f1248666-e923-400c-a7a0-5e1d8e048a72", "src_ip": "172.17.0.1", "src_port": 62216, "dest_ip": "172.17.0.2", "dest_port": 9100, "session_start": "2026-10-09T12:20:42.803890Z", "protocol": "pjl", "action": "open_conn", "event": "connection"}
{"timestamp": "2026-10-09T12:20:42.807765Z", "info": "Saved print artifact", "persona": "brother", "session_id": "f1248666-e923-400c-a7a0-5e1d8e048a72", "src_ip": "172.17.0.1", "src_port": 62216, "dest_ip": "172.17.0.2", "dest_port": 9100, "session_start": "2026-10-09T12:20:42.803890Z", "protocol": "pjl", "action": "saving", "event": "save_print_job", "file_name": "2026-10-09_12-20-42-806116_d6084bc6461af61f.ps", "artifact_type": "ps", "language": "POSTSCRIPT", "payload_sha256": "d6084bc6461af61f28c8bcfa63d02cd614091a910587e05b5e06993f9acc755e", "size": 500018}
{"timestamp": "2026-10-09T12:20:42.807926Z", "info": "Connection closed", "persona": "brother", "session_id": "f1248666-e923-400c-a7a0-5e1d8e048a72", "src_ip": "172.17.0.1", "src_port": 62216, "dest_ip": "172.17.0.2", "dest_port": 9100, "session_start": "2026-10-09T12:20:42.803890Z", "protocol": "pjl", "action": "close_conn", "event": "connection_closed", "session_end": "2026-10-09T12:20:42.807908Z", "session_duration": 0.004018}
```
