from __future__ import annotations

import logging
import socket
import threading
import time
import unittest
import uuid
from http.client import HTTPConnection
from unittest.mock import patch
from urllib.parse import urlencode

from web_admin import WebAdminHandler, create_http_server


class ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class WebAdminTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.handler = ListHandler()
        self.logger = logging.getLogger(f"test-web-{id(self)}")
        self.logger.handlers.clear()
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.server = create_http_server(("127.0.0.1", 0), self.logger, 2048)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host = "127.0.0.1"
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        path: str,
        data: bytes | None = None,
        method: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        connection = HTTPConnection(self.host, self.port, timeout=3)
        request_method = method or ("POST" if data is not None else "GET")
        try:
            connection.request(request_method, path, body=data, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read().decode("utf-8")
        finally:
            connection.close()

    def wait_for_event(self, event: str, count: int = 1) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if self.events().count(event) >= count:
                return
            time.sleep(0.01)
        self.fail(f"Missing {event}: {self.events()}")

    def events(self) -> list[str | None]:
        return [getattr(record, "event", None) for record in self.handler.records]

    def hints(self) -> str:
        return ",".join(str(getattr(record, "cve_hint", "")) for record in self.handler.records)

    def test_negative_content_length_does_not_wait_for_eof(self) -> None:
        with socket.create_connection((self.host, self.port), timeout=1) as sock:
            sock.sendall(b"POST /login HTTP/1.0\r\nContent-Length: -1\r\n\r\n")
            sock.settimeout(0.5)
            self.assertIn(b"401", sock.recv(4096))

    def test_http_idle_timeout_releases_slot(self) -> None:
        self.server.handler_timeout = 0.1
        with socket.create_connection((self.host, self.port), timeout=1) as sock:
            sock.settimeout(1)
            self.assertEqual(sock.recv(4096), b"")
        status, _ = self.request("/")
        self.assertEqual(status, 200)

    def test_http_limit_rejects_before_spawning_thread(self) -> None:
        self.server.connection_slots = threading.BoundedSemaphore(1)
        self.assertTrue(self.server.connection_slots.acquire(blocking=False))
        try:
            with socket.create_connection((self.host, self.port), timeout=1) as sock:
                sock.settimeout(1)
                self.assertEqual(sock.recv(4096), b"")
            self.wait_for_event("connection_limit")
        finally:
            self.server.connection_slots.release()
        status, _ = self.request("/")
        self.assertEqual(status, 200)

    def test_keepalive_has_one_session_end_for_multiple_requests(self) -> None:
        with patch.object(WebAdminHandler, "protocol_version", "HTTP/1.1"):
            connection = HTTPConnection(self.host, self.port, timeout=2)
            try:
                for path in ("/", "/status"):
                    connection.request("GET", path)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                self.wait_for_event("http_request_completed", count=2)
                completed = [r for r in self.handler.records if r.event == "http_request_completed"]
                self.assertEqual(len(completed), 2)
                self.assertFalse(any(hasattr(r, "session_end") for r in completed))
            finally:
                connection.close()
            self.wait_for_event("http_connection_closed")
        self.assertEqual(sum(hasattr(r, "session_end") for r in self.handler.records), 1)
        self.assertEqual(len({r.session_id for r in self.handler.records}), 1)

    def test_status_page_exposes_printer_signals(self) -> None:
        status, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("MFC-L9570CDW", body)
        self.assertIn("Serial Number", body)
        self.assertIn("device_info_probe", self.events())
        self.assertIn("CVE-2024-51977", self.hints())

    def test_http_logs_use_canonical_session_fields(self) -> None:
        status, _ = self.request("/", headers={"User-Agent": "curl/8.0"})
        self.assertEqual(status, 200)

        self.wait_for_event("http_connection_closed")
        request_record = next(record for record in self.handler.records if record.event == "device_info_probe")
        close_record = next(record for record in self.handler.records if record.event == "http_connection_closed")
        self.assertEqual(request_record.src_ip, "127.0.0.1")
        self.assertIsInstance(request_record.src_port, int)
        self.assertEqual(request_record.dest_ip, "127.0.0.1")
        self.assertEqual(request_record.dest_port, self.port)
        self.assertEqual(request_record.user_agent, "curl/8.0")
        self.assertTrue(request_record.session_start.endswith("Z"))
        self.assertTrue(close_record.session_end.endswith("Z"))
        self.assertGreaterEqual(close_record.session_duration, 0)
        self.assertFalse(hasattr(request_record, "dst_port"))
        self.assertFalse(hasattr(request_record, "user_agen"))

    def test_device_xml(self) -> None:
        status, body = self.request("/deviceinfo.xml")
        self.assertEqual(status, 200)
        self.assertIn("<SerialNumber>", body)
        self.assertIn("CVE-2024-51977", self.hints())

    def test_login_probe_is_logged_without_auth_bypass(self) -> None:
        body = urlencode({"username": "admin", "token": uuid.uuid4().hex}).encode("utf-8")
        status, response = self.request("/login", data=body)
        self.assertEqual(status, 401)
        self.assertIn("Authentication failed", response)
        self.assertIn("default_password_probe", self.events())
        self.assertIn("CVE-2024-51978", self.hints())

    def test_ssrf_probe_is_passively_classified(self) -> None:
        status, body = self.request("/network/config?url=http://169.254.169.254/latest/meta-data/")
        self.assertEqual(status, 401)
        self.assertIn("Authentication Required", body)
        self.assertIn("ssrf_probe", self.events())
        self.assertNotIn("CVE-2025-9269", self.hints())
        self.assertNotIn("CVE-2024-51980", self.hints())

    def test_path_traversal_probe_is_logged(self) -> None:
        status, body = self.request("/../../etc/passwd")
        self.assertEqual(status, 404)
        self.assertIn("Not Found", body)
        self.assertIn("path_traversal_probe", self.events())
        self.assertNotIn("CVE-2025-1127", self.hints())

    def test_postscript_firmware_probe_is_logged(self) -> None:
        status, body = self.request("/firmware/update", data=b"%!PS\nsetpagedevice", method="POST")
        self.assertEqual(status, 401)
        self.assertIn("Authentication Required", body)
        self.assertIn("firmware_probe", self.events())
        self.assertNotIn("CVE-2025-65079..65081", self.hints())
