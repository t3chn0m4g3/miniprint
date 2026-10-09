from __future__ import annotations

import hashlib
import hmac
import csv
import io
import time
from http.cookies import SimpleCookie
from email.parser import BytesParser
from email.policy import default as email_policy
import html
import json
import logging
import threading
import uuid
from datetime import UTC, datetime
from http import HTTPStatus
from ipaddress import ip_address
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse, urlencode, urlunparse

from connection_limits import ConnectionLimitedMixIn
from telemetry import ContextLoggerAdapter, format_utc
from personas import PERSONAS, Identity, new_identity
from device_state import DeviceStateStore
from brother import AuthSessions, brother_default_password
from printer import Printer


SSRF_PARAMETERS = {"url", "uri", "target", "server", "dest", "callback", "address", "host"}
# Form names are attacker-chosen; log them as values so they never become schema keys.
MAX_FORM_FIELDS = 32
MAX_FORM_FIELD_NAME = 64


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
        identity: Identity | None = None,
        device_store: DeviceStateStore | None = None,
        uploads_dir: str = "uploads",
        max_job_bytes: int = 1048576,
    ) -> None:
        self.identity = identity or new_identity("brother")
        self.persona = PERSONAS[self.identity.persona]
        self.profile = self.identity.profile()
        self.info_paths = {
            "/",
            "/status",
            "/device",
            "/deviceinfo",
            "/deviceinfo.xml",
            self.persona.status_path.split("?", 1)[0],
        }
        self.login_paths = {"/login", "/admin/login", self.persona.login_path}
        self.admin_paths = {"/admin", "/admin/config", "/network/config"}
        self.firmware_paths = {
            "/firmware",
            "/firmware/update",
            "/admin/firmware",
            self.persona.admin_prefix + "/firmware",
        }
        self.device_store = device_store or DeviceStateStore()
        self.uploads_dir = uploads_dir
        self.max_job_bytes = max_job_bytes
        self.auth = AuthSessions()
        self.logger = ContextLoggerAdapter(logger, {"persona": self.persona.name})
        self.max_request_bytes = max_request_bytes
        self.handler_timeout = handler_timeout
        self.connection_slots = (
            connection_slots if connection_slots is not None else threading.BoundedSemaphore(max_connections)
        )
        super().__init__(server_address, handler_class)


class WebAdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = ""
    sys_version = ""

    def version_string(self) -> str:
        return self.server.persona.banner

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        del explain
        self.close_connection = True
        self._send_html(
            HTTPStatus(code),
            self._not_found_page(message or HTTPStatus(code).phrase),
            head_only=getattr(self, "command", None) == "HEAD",
        )

    def do_OPTIONS(self) -> None:
        self._send_response(HTTPStatus.OK, b"", "text/html", extra_headers={"Allow": "GET, HEAD, POST, PUT, OPTIONS"})

    def do_DELETE(self) -> None:
        self.send_error(405)

    def do_PATCH(self) -> None:
        self.send_error(405)

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
        device = self.server.device_store.get(self.client_address[0])
        if device.reboot_until > time.monotonic():
            self.close_connection = True
            self.request_seen = True
            self.log.info("Device reboot in progress", extra={"event": "reboot_suppressed"})
            return
        self.request_completed = False
        try:
            super().handle_one_request()
        except Exception as exc:
            self.close_connection = True
            self.log.warning("HTTP request failed", extra={"event": "http_error", "error_type": type(exc).__name__})
        finally:
            if getattr(self, "raw_requestline", b""):
                self.request_seen = True
                if not self.request_completed:
                    self.log.info(
                        "HTTP request completed",
                        extra={"event": "http_request_completed", "action": "request_completed"},
                    )

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            # Suppress empty health checks; complete parsed and malformed requests alike.
            if getattr(self, "request_seen", False) or not ip_address(self.client_address[0]).is_loopback:
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
        self.request_seen = True
        self.log.debug(
            "HTTP access",
            extra={
                "action": "access",
                "event": "http_access",
                "request_line": (fmt % args).replace(
                    getattr(self, "path", ""), self._safe_url(getattr(self, "path", ""))
                ),
            },
        )

    def do_GET(self) -> None:
        self._handle_request(b"")

    def do_HEAD(self) -> None:
        self._handle_request(b"", head_only=True)

    def do_POST(self) -> None:
        body = self._read_body()
        if body is not None:
            self._handle_request(body)

    def do_PUT(self) -> None:
        body = self._read_body()
        if body is not None:
            self._handle_request(body)

    def _read_body(self) -> bytes | None:
        try:
            content_length = max(0, int(self.headers.get("Content-Length", "0")))
        except ValueError:
            content_length = 0
        path = urlparse(self.path).path
        limit = self.server.max_job_bytes if path in self.server.firmware_paths else self.server.max_request_bytes
        if content_length > limit:
            self.close_connection = True
            self.log.warning(
                "HTTP body exceeded configured limit",
                extra={
                    "action": "limit",
                    "event": "http_body_too_large",
                    "size": content_length,
                    "limit": limit,
                },
            )
            self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"status": "too_large"})
            return None
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
            "url": self._safe_url(self.path),
        }
        if user_agent := self.headers.get("User-Agent"):
            request_extra["user_agent"] = user_agent
        if body:
            request_extra["payload_sha256"] = hashlib.sha256(body).hexdigest()
            if (
                path in self.server.login_paths
                or path in self.server.admin_paths
                or path.startswith(self.server.persona.admin_prefix + "/")
            ):
                request_extra["secret_supplied"] = any(
                    self._secret_key(key) and any(values) for key, values in body_params.items()
                )
            elif "application/x-www-form-urlencoded" in self.headers.get("Content-Type", ""):
                request_extra["payload_preview"] = self._preview(
                    urlencode(self._safe_params(body_params), doseq=True).encode()
                )
        if cve_hints:
            request_extra["cve_hint"] = ",".join(cve_hints)
        self.log.info("HTTP request received", extra=request_extra)

        try:
            if self.server.persona.name == "brother" and path == "/etc/mnt_info.csv":
                self.log.info(
                    "Serial number CSV requested", extra={"event": "serial_leak_probe", "cve_hint": "CVE-2024-51977"}
                )
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow(["Model Name", "Serial No.", "Node Name"])
                writer.writerow([self.server.persona.model, self.server.identity.serial, self.server.identity.hostname])
                self._send_response(HTTPStatus.OK, output.getvalue().encode(), "text/csv", head_only=head_only)
            elif path in self.server.login_paths and (path not in self.server.info_paths or self.command == "POST"):
                self._handle_login(body_params, head_only)
            elif path in self.server.admin_paths or (
                path.startswith(self.server.persona.admin_prefix + "/") and path not in self.server.info_paths
            ):
                self._handle_admin(path, body_params, body, head_only)
            elif path in self.server.firmware_paths:
                self._handle_admin(path, body_params, body, head_only)
            elif path.endswith(".xml") or path == "/deviceinfo.xml":
                self._send_xml(HTTPStatus.OK, self._device_xml(), head_only=head_only)
            elif path in self.server.info_paths or path in ("/", self.server.persona.status_path.split("?", 1)[0]):
                self._send_html(HTTPStatus.OK, self._status_page(), head_only=head_only)
            else:
                self._send_html(HTTPStatus.NOT_FOUND, self._not_found_page(path), head_only=head_only)
        finally:
            self.request_completed = True
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
            hints.extend(self._hint("path_traversal_probe"))
            event = "path_traversal_probe"
        if self._has_ssrf_probe(query) or self._has_ssrf_probe(body_params):
            hints.extend(self._hint("ssrf_probe"))
            event = "ssrf_probe"
        if path in self.server.login_paths:
            hints.extend(self._hint("default_password_probe"))
            event = "login_probe"
        if path in self.server.info_paths or "serial" in lower_path or "deviceinfo" in lower_path:
            hints.extend(self._hint("serial_leak_probe"))
            event = "device_info_probe"
        if "%!ps" in lower_body or "%!" in lower_body or "setpagedevice" in lower_body:
            event = "postscript_probe"
        if path in self.server.firmware_paths or "firmware" in lower_path:
            event = "firmware_probe"
        return list(dict.fromkeys(hints)), event

    def _hint(self, event: str) -> list[str]:
        hint = self.server.persona.cve_hints.get(event)
        return [hint] if hint else []

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

    @staticmethod
    def _secret_key(key: str) -> bool:
        return any(part in key.lower() for part in ("password", "secret", "token", "passwd")) or key.lower() in (
            "pass",
            "pwd",
            "logbox",
        )

    def _safe_params(self, params: dict[str, list[str]]) -> dict[str, list[str]]:
        return {
            key: ["<redacted>"] if self._secret_key(key) else [value[:256] for value in values]
            for key, values in params.items()
        }

    def _safe_url(self, url: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not any(self._secret_key(key) for key in params):
            return url
        return urlunparse(parsed._replace(query=urlencode(self._safe_params(params), doseq=True)))

    def _authenticated(self) -> bool:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie.get("AuthCookie")
            return bool(token and self.server.auth.valid(token.value, self.client_address[0]))
        except Exception:
            return False

    def _handle_login(self, params: dict[str, list[str]], head_only: bool) -> None:
        username = self._first(params, "username") or self._first(params, "user") or "admin"
        password = self._first(params, "password") or self._first(params, "pass") or ""
        success = (
            self.server.persona.name == "brother"
            and self.command == "POST"
            and username.lower() == "admin"
            and hmac.compare_digest(password, brother_default_password(self.server.identity.serial))
        )
        event = "default_password_success" if success else "default_password_probe"
        self.log.info(
            "Login attempt observed",
            extra={
                "action": "auth",
                "event": event,
                "username": username[:64],
                "secret_supplied": bool(password),
                "cve_hint": self.server.persona.cve_hints.get(event),
            },
        )
        if success:
            token = self.server.auth.create(self.client_address[0])
            self._send_response(
                HTTPStatus.OK,
                self._settings_page("/admin").encode(),
                "text/html; charset=utf-8",
                head_only=head_only,
                extra_headers={"Set-Cookie": f"AuthCookie={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800"},
            )
        else:
            self._send_html(
                HTTPStatus.UNAUTHORIZED, self._login_page(failed=self.command == "POST"), head_only=head_only
            )

    def _settings_page(self, path: str) -> str:
        links = "".join(
            f'<li><a href="/admin/{page}">{page.upper()}</a></li>'
            for page in ("network", "ldap", "smtp", "snmp", "firmware")
        )
        return f'<html><head><title>{html.escape(self.server.persona.title)}</title></head><body><h1>{html.escape(path)}</h1><ul>{links}</ul><form method="post"><input name="server"><input type="password" name="password"><button>Save</button></form><form method="post" action="/admin/firmware" enctype="multipart/form-data"><input type="file" name="firmware"><button>Update</button></form></body></html>'

    def _handle_admin(self, path: str, params: dict[str, list[str]], body: bytes, head_only: bool):
        if self.server.persona.name != "brother" or not self._authenticated():
            self._send_html(HTTPStatus.UNAUTHORIZED, self._admin_page(), head_only=head_only)
            return
        if self.command not in ("POST", "PUT"):
            self._send_html(HTTPStatus.OK, self._settings_page(path), head_only=head_only)
            return
        if path in self.server.firmware_paths:
            payload = body
            content_type = self.headers.get("Content-Type", "")
            if content_type.startswith("multipart/form-data"):
                message = BytesParser(policy=email_policy).parsebytes(
                    ("Content-Type: " + content_type + "\r\n\r\n").encode() + body
                )
                payload = next((part.get_payload(decode=True) for part in message.walk() if part.get_filename()), b"")
            if len(payload) > self.server.max_job_bytes:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"status": "too_large"})
                return
            printer = Printer(
                self.log, persona=self.server.persona, identity=self.server.identity, upload_dir=self.server.uploads_dir
            )
            printer._save_artifact(".bin", payload, "save_firmware", artifact_type="firmware")
            self._send_json(
                HTTPStatus.ACCEPTED, {"status": "queued", "message": "Firmware image received for validation"}
            )
            return
        sensitive = any(self._secret_key(key) and any(value) for key, value in params.items())
        target_keys = [key for key in params if "server" in key.lower() or "host" in key.lower()]
        event = (
            "passback_attempt"
            if any(part in path.lower() for part in ("ldap", "smtp")) and target_keys
            else "admin_settings_saved"
        )
        safe_params = self._safe_params(params)
        form_fields = [
            {"name": key[:MAX_FORM_FIELD_NAME], "value": value}
            for key, values in safe_params.items()
            if not self._secret_key(key)
            for value in values
        ][:MAX_FORM_FIELDS]
        passback_target = None
        if event == "passback_attempt":
            passback_target = next(
                (value for key in target_keys if not self._secret_key(key) for value in safe_params[key] if value),
                None,
            )
        self.log.info(
            "Admin settings received",
            extra={
                "event": event,
                "form_fields": form_fields,
                "passback_target": passback_target,
                "secret_supplied": sensitive,
                "cve_hint": self.server.persona.cve_hints.get(event),
            },
        )
        self._send_json(HTTPStatus.OK, {"status": "saved"})

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

    def _send_response(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        head_only: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status.value)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _status_page(self) -> str:
        escaped = {key: html.escape(value) for key, value in self.server.profile.items()}
        return f"""<!doctype html>
<html lang="en">
<head><title>{html.escape(self.server.persona.title)}</title></head>
<body>
<h1>{escaped["manufacturer"]} {escaped["model"]}</h1>
<dl>
<dt>Status</dt><dd>Ready</dd>
<dt>Serial Number</dt><dd>{escaped["serial"]}</dd>
<dt>Firmware</dt><dd>{escaped["firmware"]}</dd>
<dt>Location</dt><dd>{escaped["location"]}</dd>
<dt>Hostname</dt><dd>{escaped["hostname"]}</dd>
</dl>
<form method="post" action="{html.escape(self.server.persona.login_path)}">
<input name="username" value="admin">
<input type="password" id="LogBox" name="password">
<button type="submit">Log in</button>
</form>
</body>
</html>"""

    def _login_page(self, failed: bool = False) -> str:
        message = "<p>Authentication failed.</p>" if failed else ""
        return f"""<!doctype html>
<html lang="en"><head><title>{html.escape(self.server.persona.title)} Login</title></head>
<body><h1>Printer Web Based Management</h1>{message}
<form method="post" action="{html.escape(self.server.persona.login_path)}">
<label>User <input name="username"></label>
<label>Password <input type="password" id="LogBox" name="password"></label>
<button type="submit">Log in</button>
</form></body></html>"""

    def _admin_page(self) -> str:
        return f"""<!doctype html>
<html lang="en"><head><title>{html.escape(self.server.persona.title)}</title></head>
<body><h1>Authentication Required</h1></body></html>"""

    def _not_found_page(self, path: str) -> str:
        return f"""<!doctype html>
<html lang="en"><head><title>{html.escape(self.server.persona.title)}</title></head>
<body><h1>Not Found</h1><p>{html.escape(path)}</p></body></html>"""

    def _device_xml(self) -> str:
        escaped = {key: html.escape(value) for key, value in self.server.profile.items()}
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
    identity: Identity | None = None,
    device_store: DeviceStateStore | None = None,
    uploads_dir: str = "uploads",
    max_job_bytes: int = 1048576,
) -> WebAdminServer:
    return WebAdminServer(
        address,
        WebAdminHandler,
        logger,
        max_request_bytes,
        max_connections=max_connections,
        connection_slots=connection_slots,
        handler_timeout=handler_timeout,
        identity=identity,
        device_store=device_store,
        uploads_dir=uploads_dir,
        max_job_bytes=max_job_bytes,
    )
