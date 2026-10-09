from __future__ import annotations

import hashlib
import html
import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from connection_limits import ConnectionLimitedMixIn
from telemetry import ContextLoggerAdapter, format_utc


DEVICE_PROFILE = {
    "manufacturer": "Brother",
    "model": "MFC-L9570CDW",
    "serial": "E78321M4N957143",
    "firmware": "ZP-1.59.2024",
    "location": "Accounting 2F",
    "hostname": "BRN957143",
}
SSRF_PARAMETERS = {"url", "uri", "target", "server", "dest", "callback", "address", "host"}
LOGIN_PATHS = {"/login", "/admin/login", "/general/login.html", "/web/admin/login"}
INFO_PATHS = {
    "/",
    "/status",
    "/device",
    "/deviceinfo",
    "/deviceinfo.xml",
    "/general/status.html",
    "/web/general/status.html",
}
ADMIN_PATHS = {"/admin", "/admin/config", "/web/admin/config", "/network/config"}
FIRMWARE_PATHS = {"/firmware", "/firmware/update", "/admin/firmware", "/web/admin/firmware"}


class WebAdminServer(ConnectionLimitedMixIn, ThreadingHTTPServer):
    protocol = "http"
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        logger: logging.Logger,
        max_request_bytes: int,
        *,
        max_connections: int = 16,
        connection_slots: threading.BoundedSemaphore | None = None,
        handler_timeout: float = 15,
    ) -> None:
        self.logger = logger
        self.max_request_bytes = max_request_bytes
        self.handler_timeout = handler_timeout
        self.connection_slots = (
            connection_slots if connection_slots is not None else threading.BoundedSemaphore(max_connections)
        )
        super().__init__(server_address, handler_class)


class WebAdminHandler(BaseHTTPRequestHandler):
    server_version = "Debut/1.30"
    sys_version = ""

    def setup(self) -> None:
        self.timeout = self.server.handler_timeout
        super().setup()
        self.session_id = str(uuid.uuid4())
        self.session_start = datetime.now(UTC)
        src_ip, src_port = self.client_address
        local_address = self.request.getsockname()
        dest_ip, dest_port = local_address[0], local_address[1]
        self.log = ContextLoggerAdapter(
            self.server.logger,
            {
                "session_id": self.session_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "session_start": format_utc(self.session_start),
                "protocol": "http",
            },
        )

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        finally:
            if getattr(self, "raw_requestline", b""):
                self.request_seen = True

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            # Suppress empty health checks; complete parsed and malformed requests alike.
            if getattr(self, "request_seen", False):
                self.log.info(
                    "HTTP connection closed",
                    extra=self._session_end_extra(
                        {
                            "action": "close_conn",
                            "event": "http_connection_closed",
                        }
                    ),
                )

    def log_message(self, fmt: str, *args: Any) -> None:
        self.log.debug(
            "HTTP access",
            extra={"action": "access", "event": "http_access", "request_line": fmt % args},
        )

    def do_GET(self) -> None:
        self._handle_request(b"")

    def do_HEAD(self) -> None:
        self._handle_request(b"", head_only=True)

    def do_POST(self) -> None:
        self._handle_request(self._read_body())

    def do_PUT(self) -> None:
        self._handle_request(self._read_body())

    def _read_body(self) -> bytes:
        try:
            content_length = max(0, int(self.headers.get("Content-Length", "0")))
        except ValueError:
            content_length = 0
        if content_length > self.server.max_request_bytes:
            self.log.warning(
                "HTTP body exceeded configured limit",
                extra={
                    "action": "limit",
                    "event": "http_body_too_large",
                    "size": content_length,
                    "limit": self.server.max_request_bytes,
                },
            )
            return self.rfile.read(self.server.max_request_bytes)
        return self.rfile.read(content_length) if content_length else b""

    def _handle_request(self, body: bytes, head_only: bool = False) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        body_text = body.decode("utf-8", errors="replace")
        body_params = parse_qs(body_text, keep_blank_values=True)
        cve_hints, event = self._classify_request(path, query, body_text, body_params)
        request_extra = {
            "action": "request",
            "event": event,
            "request": self.command,
            "url": self.path,
        }
        if user_agent := self.headers.get("User-Agent"):
            request_extra["user_agent"] = user_agent
        if body:
            request_extra["payload_sha256"] = hashlib.sha256(body).hexdigest()
            request_extra["payload_preview"] = self._preview(body)
        if cve_hints:
            request_extra["cve_hint"] = ",".join(cve_hints)
        self.log.info("HTTP request received", extra=request_extra)

        try:
            if path in LOGIN_PATHS:
                self._handle_login(body_params, head_only)
            elif path in ADMIN_PATHS:
                self._send_html(HTTPStatus.UNAUTHORIZED, self._admin_page(), head_only=head_only)
            elif path in FIRMWARE_PATHS:
                self._send_json(
                    HTTPStatus.ACCEPTED,
                    {"status": "queued", "message": "Firmware image received for validation"},
                    head_only=head_only,
                )
            elif path.endswith(".xml") or path == "/deviceinfo.xml":
                self._send_xml(HTTPStatus.OK, self._device_xml(), head_only=head_only)
            elif path in INFO_PATHS or path == "/":
                self._send_html(HTTPStatus.OK, self._status_page(), head_only=head_only)
            else:
                self._send_html(HTTPStatus.NOT_FOUND, self._not_found_page(path), head_only=head_only)
        finally:
            self.log.info(
                "HTTP request completed",
                extra={"action": "request_completed", "event": "http_request_completed"},
            )

    def _session_end_extra(self, extra: dict[str, Any]) -> dict[str, Any]:
        session_end = datetime.now(UTC)
        return {
            **extra,
            "session_end": format_utc(session_end),
            "session_duration": round((session_end - self.session_start).total_seconds(), 6),
        }

    def _classify_request(
        self,
        path: str,
        query: dict[str, list[str]],
        body_text: str,
        body_params: dict[str, list[str]],
    ) -> tuple[list[str], str]:
        hints: list[str] = []
        event = "http_probe"
        lower_path = path.lower()
        lower_body = body_text.lower()
        if ".." in lower_path or "%2e" in self.path.lower():
            hints.append("CVE-2025-1127")
            event = "path_traversal_probe"
        if self._has_ssrf_probe(query) or self._has_ssrf_probe(body_params):
            hints.extend(["CVE-2024-51980", "CVE-2024-51981", "CVE-2025-9269"])
            event = "ssrf_probe"
        if path in LOGIN_PATHS:
            hints.append("CVE-2024-51978")
            event = "login_probe"
        if path in INFO_PATHS or "serial" in lower_path or "deviceinfo" in lower_path:
            hints.append("CVE-2024-51977")
            event = "device_info_probe"
        if "%!ps" in lower_body or "%!" in lower_body or "setpagedevice" in lower_body:
            hints.append("CVE-2025-65079..65081")
            event = "postscript_probe"
        if path in FIRMWARE_PATHS or "firmware" in lower_path:
            event = "firmware_probe"
        return list(dict.fromkeys(hints)), event

    @staticmethod
    def _has_ssrf_probe(params: dict[str, list[str]]) -> bool:
        for key, values in params.items():
            if key.lower() not in SSRF_PARAMETERS:
                continue
            for value in values:
                lowered = value.lower()
                if lowered.startswith(("http://", "https://", "ftp://", "gopher://")):
                    return True
        return False

    @staticmethod
    def _preview(data: bytes, limit: int = 96) -> str:
        return data[:limit].decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")

    def _handle_login(self, params: dict[str, list[str]], head_only: bool) -> None:
        username = self._first(params, "username") or self._first(params, "user") or ""
        secret_supplied = bool(self._first(params, "password") or self._first(params, "pass"))
        self.log.info(
            "Login attempt observed",
            extra={
                "action": "auth",
                "event": "default_password_probe"
                if username.lower() in {"admin", "administrator"}
                else "login_attempt",
                "username": username[:64],
                "secret_supplied": secret_supplied,
                "cve_hint": "CVE-2024-51978",
            },
        )
        self._send_html(HTTPStatus.UNAUTHORIZED, self._login_page(failed=bool(username)), head_only=head_only)

    @staticmethod
    def _first(params: dict[str, list[str]], name: str) -> str | None:
        values = params.get(name)
        if not values:
            return None
        return values[0]

    def _send_json(self, status: HTTPStatus, data: dict[str, Any], head_only: bool = False) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send_response(status, body, "application/json; charset=utf-8", head_only=head_only)

    def _send_xml(self, status: HTTPStatus, text: str, head_only: bool = False) -> None:
        self._send_response(status, text.encode("utf-8"), "application/xml; charset=utf-8", head_only=head_only)

    def _send_html(self, status: HTTPStatus, text: str, head_only: bool = False) -> None:
        self._send_response(status, text.encode("utf-8"), "text/html; charset=utf-8", head_only=head_only)

    def _send_response(self, status: HTTPStatus, body: bytes, content_type: str, head_only: bool = False) -> None:
        self.send_response(status.value)
        self.send_header("Server", "Debut/1.30")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    @staticmethod
    def _status_page() -> str:
        escaped = {key: html.escape(value) for key, value in DEVICE_PROFILE.items()}
        return f"""<!doctype html>
<html lang="en">
<head><title>{escaped["model"]}</title></head>
<body>
<h1>{escaped["manufacturer"]} {escaped["model"]}</h1>
<dl>
<dt>Status</dt><dd>Ready</dd>
<dt>Serial Number</dt><dd>{escaped["serial"]}</dd>
<dt>Firmware</dt><dd>{escaped["firmware"]}</dd>
<dt>Location</dt><dd>{escaped["location"]}</dd>
<dt>Hostname</dt><dd>{escaped["hostname"]}</dd>
</dl>
<form method="post" action="/login">
<input name="username" value="admin">
<input name="password" type="password">
<button type="submit">Log in</button>
</form>
</body>
</html>"""

    @staticmethod
    def _login_page(failed: bool = False) -> str:
        message = "<p>Authentication failed.</p>" if failed else ""
        return f"""<!doctype html>
<html lang="en"><head><title>Printer Login</title></head>
<body><h1>Printer Web Based Management</h1>{message}
<form method="post" action="/login">
<label>User <input name="username"></label>
<label>Password <input name="password" type="password"></label>
<button type="submit">Log in</button>
</form></body></html>"""

    @staticmethod
    def _admin_page() -> str:
        return """<!doctype html>
<html lang="en"><head><title>Authentication Required</title></head>
<body><h1>Authentication Required</h1></body></html>"""

    @staticmethod
    def _not_found_page(path: str) -> str:
        return f"""<!doctype html>
<html lang="en"><head><title>Not Found</title></head>
<body><h1>Not Found</h1><p>{html.escape(path)}</p></body></html>"""

    @staticmethod
    def _device_xml() -> str:
        escaped = {key: html.escape(value) for key, value in DEVICE_PROFILE.items()}
        return f"""<?xml version="1.0" encoding="utf-8"?>
<DeviceInfo>
  <Manufacturer>{escaped["manufacturer"]}</Manufacturer>
  <Model>{escaped["model"]}</Model>
  <SerialNumber>{escaped["serial"]}</SerialNumber>
  <FirmwareVersion>{escaped["firmware"]}</FirmwareVersion>
  <Hostname>{escaped["hostname"]}</Hostname>
</DeviceInfo>"""


def create_http_server(
    address: tuple[str, int],
    logger: logging.Logger,
    max_request_bytes: int,
    *,
    max_connections: int = 16,
    connection_slots: threading.BoundedSemaphore | None = None,
    handler_timeout: float = 15,
) -> WebAdminServer:
    return WebAdminServer(
        address,
        WebAdminHandler,
        logger,
        max_request_bytes,
        max_connections=max_connections,
        connection_slots=connection_slots,
        handler_timeout=handler_timeout,
    )
