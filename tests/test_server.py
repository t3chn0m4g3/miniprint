from __future__ import annotations

import contextlib
import io
import json
import logging
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from server import JSONFormatter, LimitedThreadingTCPServer, PJLRequestHandler, ServerConfig, configure_logger, healthcheck


class ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class ServerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.handler = ListHandler()
        self.logger = logging.getLogger(f"test-server-{id(self)}")
        self.logger.handlers.clear()
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.server: LimitedThreadingTCPServer | None = None
        self.thread: threading.Thread | None = None

    def tearDown(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)
        self.tmpdir.cleanup()

    def start_server(self, **overrides: object) -> tuple[str, int]:
        config_values = {
            "host": "127.0.0.1",
            "pjl_port": 0,
            "http_enabled": False,
            "uploads_dir": self.tmpdir.name,
            "timeout": 1,
        }
        config_values.update(overrides)
        config = ServerConfig(**config_values)
        self.server = LimitedThreadingTCPServer(("127.0.0.1", 0), PJLRequestHandler, config, self.logger)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server.server_address

    def wait_for_event(self, event: str, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            events = [getattr(record, "event", None) for record in self.handler.records]
            if event in events:
                return
            time.sleep(0.02)
        events = [getattr(record, "event", None) for record in self.handler.records]
        self.fail(f"{event!r} not observed in {events!r}")

    @staticmethod
    def exchange(address: tuple[str, int], payload: bytes, expect_response: bool = True) -> bytes:
        with socket.create_connection(address, timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            if not expect_response:
                return b""
            return sock.recv(4096)

    def test_parse_commands_preserves_raw_segments(self) -> None:
        commands = PJLRequestHandler.parse_commands(b"hello@PJL INFO ID\r\n@PJL USTATUSOFF\r\n")
        self.assertEqual(commands, [b"hello", b"@PJL INFO ID\r\n", b"@PJL USTATUSOFF\r\n"])

    def test_escape_reset_sequence_is_removed(self) -> None:
        address = self.start_server()
        response = self.exchange(address, b"\x1b%-12345X@PJL INFO ID\r\n")
        self.assertIn(b"@PJL INFO ID", response)

    def test_new_pjl_filesystem_commands_are_dispatched(self) -> None:
        address = self.start_server()
        response = self.exchange(
            address,
            (
                b'@PJL FSAPPEND FORMAT:BINARY SIZE=3 NAME="0:/via-server.bin"\r\nabc\r\n'
                b'@PJL FSQUERY NAME="0:/via-server.bin"\r\n'
            ),
        )

        self.assertIn(b'@PJL FSQUERY NAME="0:/via-server.bin" TYPE=FILE SIZE=3', response)
        self.wait_for_event("fsappend")

    def test_invalid_utf8_is_logged_without_crashing(self) -> None:
        address = self.start_server()
        self.exchange(address, b"\xff\xfeplain text", expect_response=False)
        self.wait_for_event("invalid_utf8")

    def test_request_limit_is_enforced(self) -> None:
        address = self.start_server(max_request_bytes=8)
        self.exchange(address, b"123456789", expect_response=False)
        self.wait_for_event("request_too_large")

    def test_request_limit_is_enforced_across_chunks(self) -> None:
        address = self.start_server(max_request_bytes=4096)
        payload = b"@PJL USTATUSOFF\r\n" * 300
        self.exchange(address, payload, expect_response=False)
        self.wait_for_event("request_too_large")
        limit_record = next(record for record in self.handler.records if record.event == "request_too_large")
        self.assertGreater(limit_record.size, 4096)

    def test_loopback_healthcheck_does_not_emit_log_records(self) -> None:
        address = self.start_server()
        self.assertEqual(healthcheck("127.0.0.1", address[1], 0, False), 0)
        time.sleep(0.1)
        self.assertEqual(self.handler.records, [])

    def test_pjl_connection_logs_use_canonical_session_fields(self) -> None:
        address = self.start_server()
        self.exchange(address, b"@PJL INFO ID\r\n")
        self.wait_for_event("connection_closed")

        closed_record = next(record for record in self.handler.records if record.event == "connection_closed")
        self.assertEqual(closed_record.src_ip, "127.0.0.1")
        self.assertIsInstance(closed_record.src_port, int)
        self.assertEqual(closed_record.dest_ip, "127.0.0.1")
        self.assertEqual(closed_record.dest_port, address[1])
        self.assertTrue(closed_record.session_start.endswith("Z"))
        self.assertTrue(closed_record.session_end.endswith("Z"))
        self.assertGreaterEqual(closed_record.session_duration, 0)
        self.assertFalse(hasattr(closed_record, "dst_port"))
        self.assertFalse(hasattr(closed_record, "user_agen"))

    def test_json_formatter_omits_null_and_deprecated_fields(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JSONFormatter())
        logger = logging.getLogger(f"test-json-formatter-{id(self)}")
        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

        logger.info(
            "formatter probe",
            extra={"dest_port": 9100, "optional_field": None, "user_agent": None},
        )

        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["dest_port"], 9100)
        self.assertNotIn("optional_field", payload)
        self.assertNotIn("user_agent", payload)
        self.assertNotIn("dst_port", payload)
        self.assertNotIn("user_agen", payload)

    def test_file_logger_omits_server_lifecycle_events_but_console_logs_them(self) -> None:
        log_path = Path(self.tmpdir.name) / "miniprint.json"
        console = io.StringIO()
        with contextlib.redirect_stderr(console):
            logger = configure_logger(str(log_path))
            try:
                logger.info("Servers started", extra={"action": "start", "event": "server_start"})
                logger.info("Connection opened", extra={"action": "open_conn", "event": "connection"})
                logger.info("Shutdown requested", extra={"action": "stop", "event": "signal", "signal": 15})
                logger.info("Servers stopped", extra={"action": "stop", "event": "server_stop"})
                for handler in logger.handlers:
                    handler.flush()
            finally:
                for handler in logger.handlers[:]:
                    logger.removeHandler(handler)
                    handler.close()

        file_records = [json.loads(line) for line in log_path.read_text().splitlines()]
        console_records = [json.loads(line) for line in console.getvalue().splitlines()]

        self.assertEqual([record["event"] for record in file_records], ["connection"])
        self.assertNotIn("level", file_records[0])
        self.assertEqual(
            [record["event"] for record in console_records],
            ["server_start", "connection", "signal", "server_stop"],
        )
        self.assertTrue(all("level" in record for record in console_records))

    def test_parallel_clients_receive_responses(self) -> None:
        address = self.start_server(max_connections=8)
        responses: list[bytes] = []

        def worker() -> None:
            responses.append(self.exchange(address, b"@PJL INFO STATUS\r\n"))

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)

        self.assertEqual(len(responses), 4)
        for response in responses:
            self.assertIn(b"@PJL INFO STATUS", response)

    def test_connection_limit_logs_rejection(self) -> None:
        address = self.start_server(max_connections=1, timeout=2)
        hold_socket = socket.create_connection(address, timeout=2)
        try:
            time.sleep(0.1)
            self.exchange(address, b"@PJL INFO ID\r\n", expect_response=False)
        finally:
            hold_socket.close()
        self.wait_for_event("connection_limit")
