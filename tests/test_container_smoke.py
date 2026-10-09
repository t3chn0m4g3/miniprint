from __future__ import annotations

import csv
import http.client
import io
import json
import os
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MINIPRINT_CONTAINER_SMOKE") != "1",
    reason="set MINIPRINT_CONTAINER_SMOKE=1 to test a running Docker container",
)

CONTAINER_NAME = os.environ.get("MINIPRINT_CONTAINER", "miniprint")
HOST = os.environ.get("MINIPRINT_HOST", "127.0.0.1")
PJL_PORT = int(os.environ.get("MINIPRINT_PJL_PORT", "9100"))
HTTP_PORT = int(os.environ.get("MINIPRINT_HTTP_PORT", "80"))
LOG_FILE = Path(os.environ.get("MINIPRINT_LOG_FILE", "log/miniprint.json"))
UPLOADS_DIR = Path(os.environ.get("MINIPRINT_UPLOADS_DIR", "uploads"))

EXPECTED_CMD_LIMITS = {
    "--timeout": "60",
    "--session-timeout": "300",
    "--max-connections": "16",
    "--max-request-bytes": "65536",
    "--max-job-bytes": "1048576",
    "--max-virtual-file-bytes": "262144",
    "--max-response-bytes": "131072",
}


def _docker(*args: str) -> str:
    completed = subprocess.run(  # nosec B603,B607 - opt-in smoke test with fixed docker CLI arguments.
        ["docker", *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return completed.stdout


def _docker_json(*args: str) -> Any:
    return json.loads(_docker(*args))


def _docker_exec(command: str) -> str:
    return _docker("exec", CONTAINER_NAME, "sh", "-c", command).strip()


def _log_offset() -> int:
    return LOG_FILE.stat().st_size if LOG_FILE.exists() else 0


def _upload_snapshot() -> set[Path]:
    if not UPLOADS_DIR.exists():
        return set()
    return {path for path in UPLOADS_DIR.iterdir() if path.is_file()}


def _remove_new_uploads(before: set[Path]) -> None:
    if not UPLOADS_DIR.exists():
        return
    for path in UPLOADS_DIR.iterdir():
        if path.is_file() and path not in before and path.name != ".gitkeep":
            path.unlink()


def _read_log_records(offset: int) -> list[dict[str, Any]]:
    if not LOG_FILE.exists():
        return []
    with LOG_FILE.open("rb") as handle:
        handle.seek(offset)
        lines = handle.read().decode("utf-8", errors="replace").splitlines()
    records = []
    for line in lines:
        if not line.strip():
            continue
        records.append(json.loads(line))
    return records


def _wait_for_records(offset: int, predicate: Any, timeout: float = 8.0) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout
    last_records: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        last_records = _read_log_records(offset)
        if predicate(last_records):
            return last_records
        time.sleep(0.2)
    pytest.fail(f"expected log records not observed; saw events {[record.get('event') for record in last_records]!r}")


def _send_pjl(payload: bytes, expect_response: bool = True) -> bytes:
    with socket.create_connection((HOST, PJL_PORT), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        if not expect_response:
            return b""
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def _http_get(path: str, user_agent: str) -> tuple[int, str]:
    connection = http.client.HTTPConnection(HOST, HTTP_PORT, timeout=5)
    try:
        connection.request("GET", path, headers={"User-Agent": user_agent})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", errors="replace")
    finally:
        connection.close()


def _assert_no_null_or_deprecated_fields(records: list[dict[str, Any]]) -> None:
    for record in records:
        assert "level" not in record
        assert "dst_port" not in record
        assert "user_agen" not in record
        null_fields = [key for key, value in record.items() if value is None]
        assert null_fields == []


def _assert_session_fields(record: dict[str, Any]) -> None:
    for field in ("session_id", "src_ip", "src_port", "dest_ip", "dest_port", "session_start"):
        assert field in record


def _assert_one_cpu_limit(host_config: dict[str, Any]) -> None:
    if host_config.get("NanoCpus") == 1_000_000_000:
        return
    cpu_period = host_config.get("CpuPeriod")
    cpu_quota = host_config.get("CpuQuota")
    assert cpu_period and cpu_quota
    assert cpu_quota / cpu_period == pytest.approx(1.0)


def test_container_runtime_hardening_and_limits() -> None:
    container = _docker_json("inspect", CONTAINER_NAME)[0]
    state = container["State"]
    host_config = container["HostConfig"]
    config = container["Config"]

    assert state["Running"] is True
    assert state.get("Health", {}).get("Status") == "healthy"
    assert config["User"] == "miniprint"
    assert host_config["ReadonlyRootfs"] is True
    assert "ALL" in host_config["CapDrop"]
    assert "no-new-privileges:true" in host_config["SecurityOpt"]
    assert host_config["Memory"] == 256 * 1024 * 1024
    assert host_config["MemorySwap"] == 256 * 1024 * 1024
    assert host_config["PidsLimit"] == 128
    assert "/tmp" in host_config["Tmpfs"]
    assert "noexec" in host_config["Tmpfs"]["/tmp"]
    _assert_one_cpu_limit(host_config)

    ulimits = {item["Name"]: item for item in host_config["Ulimits"]}
    assert ulimits["nofile"] == {"Name": "nofile", "Soft": 1024, "Hard": 2048}
    assert "nproc" not in ulimits
    assert _docker_exec("ulimit -n") == "1024"
    assert _docker_exec("ulimit -Hn") == "2048"
    assert _docker_exec("ulimit -u") == "unlimited"

    cmd = config["Cmd"]
    for flag, expected_value in EXPECTED_CMD_LIMITS.items():
        index = cmd.index(flag)
        assert cmd[index + 1] == expected_value


def test_container_protocol_logging_and_request_limit() -> None:
    marker = uuid.uuid4().hex
    user_agent = f"miniprint-smoke/{marker}"
    offset = _log_offset()
    uploads_before = _upload_snapshot()

    try:
        status, body = _http_get(f"/network/config?url=http://169.254.169.254/{marker}", user_agent)
        assert status == 401
        assert "Authentication Required" in body

        pjl_response = _send_pjl(f"@PJL ECHO SMOKE-{marker}\r\n".encode("ascii"))
        assert f"SMOKE-{marker}".encode("ascii") in pjl_response

        oversized_pjl_request = b"x" * (int(EXPECTED_CMD_LIMITS["--max-request-bytes"]) + 4096)
        _send_pjl(oversized_pjl_request, expect_response=False)

        def observed(records: list[dict[str, Any]]) -> bool:
            return (
                any(
                    record.get("event") == "ssrf_probe" and record.get("user_agent") == user_agent for record in records
                )
                and any(marker in record.get("payload_preview", "") for record in records)
                and any(record.get("event") == "request_too_large" for record in records)
                and any(record.get("event") in {"connection_closed", "http_connection_closed"} for record in records)
            )

        records = _wait_for_records(offset, observed)
    finally:
        _remove_new_uploads(uploads_before)

    _assert_no_null_or_deprecated_fields(records)

    http_record = next(record for record in records if record.get("event") == "ssrf_probe")
    pjl_record = next(record for record in records if marker in record.get("payload_preview", ""))
    limit_record = next(record for record in records if record.get("event") == "request_too_large")
    terminal_record = next(
        record for record in records if record.get("event") in {"connection_closed", "http_connection_closed"}
    )

    for record in (http_record, pjl_record, limit_record, terminal_record):
        _assert_session_fields(record)
    assert http_record["user_agent"] == user_agent
    assert limit_record["size"] > int(EXPECTED_CMD_LIMITS["--max-request-bytes"])
    assert terminal_record["session_end"].endswith("Z")
    assert terminal_record["session_duration"] >= 0


def test_container_brother_chain_and_large_job_capture() -> None:
    from brother import brother_default_password

    marker = uuid.uuid4().hex
    offset = _log_offset()
    before = _upload_snapshot()
    try:
        connection = http.client.HTTPConnection(HOST, HTTP_PORT, timeout=3)
        try:
            connection.request("GET", "/etc/mnt_info.csv")
            response = connection.getresponse()
            assert response.status == 200
            serial = next(csv.DictReader(io.StringIO(response.read().decode())))["Serial No."]
            assert response.version == 11
            assert len([v for k, v in response.getheaders() if k.lower() == "server"]) == 1
            from urllib.parse import urlencode

            body = urlencode({"username": "admin", "password": brother_default_password(serial)})
            connection.request(
                "POST", "/login", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response = connection.getresponse()
            assert response.status == 200
            cookie = response.getheader("Set-Cookie").split(";")[0]
            response.read()
            connection.request(
                "POST",
                "/admin/ldap",
                body=urlencode({"server": marker + ".example.test", "password": "do-not-log-" + marker}),
                headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"},
            )
            response = connection.getresponse()
            assert response.status == 200
            response.read()
        finally:
            connection.close()
        payload = ("%!PS " + marker + "\n").encode() + b"x" * 500000
        with socket.create_connection((HOST, PJL_PORT), timeout=3) as sock:
            sock.sendall(b"\x1b%-12345X@PJL JOB\r\n@PJL ENTER LANGUAGE=POSTSCRIPT\r\n" + payload + b"\x1b%-12345X")
            sock.shutdown(socket.SHUT_WR)
            while sock.recv(4096):
                pass
        records = _wait_for_records(
            offset,
            lambda rows: (
                any(row.get("event") == "save_print_job" for row in rows)
                and any(row.get("event") == "passback_attempt" for row in rows)
            ),
        )
        artifact = next(row for row in records if row.get("event") == "save_print_job")
        assert (UPLOADS_DIR / artifact["file_name"]).read_bytes() == payload
        assert artifact["language"] == "POSTSCRIPT" and artifact["artifact_type"] == "ps"
        assert "do-not-log-" + marker not in repr(records)
        assert all(row.get("persona") == "brother" for row in records)
        http_sessions = {row["session_id"] for row in records if row.get("protocol") == "http"}
        for sid in http_sessions:
            assert sum("session_end" in row for row in records if row["session_id"] == sid) == 1
    finally:
        _remove_new_uploads(before)
