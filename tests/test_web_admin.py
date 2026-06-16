from __future__ import annotations

import logging
import threading
import unittest
import uuid
from http.client import HTTPConnection
from urllib.parse import urlencode

from web_admin import create_http_server


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

    def events(self) -> list[str | None]:
        return [getattr(record, "event", None) for record in self.handler.records]

    def hints(self) -> str:
        return ",".join(str(getattr(record, "cve_hint", "")) for record in self.handler.records)

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
        self.assertIn("CVE-2025-9269", self.hints())

    def test_path_traversal_probe_is_logged(self) -> None:
        status, body = self.request("/../../etc/passwd")
        self.assertEqual(status, 404)
        self.assertIn("Not Found", body)
        self.assertIn("path_traversal_probe", self.events())
        self.assertIn("CVE-2025-1127", self.hints())

    def test_postscript_firmware_probe_is_logged(self) -> None:
        status, body = self.request("/firmware/update", data=b"%!PS\nsetpagedevice", method="POST")
        self.assertEqual(status, 202)
        self.assertIn("queued", body)
        self.assertIn("firmware_probe", self.events())
        self.assertIn("CVE-2025-65079..65081", self.hints())
