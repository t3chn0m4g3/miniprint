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
from unittest.mock import patch
from http.client import HTTPConnection

from web_admin import create_http_server

from server import (
    JSONFormatter,
    LimitedThreadingTCPServer,
    PJLRequestHandler,
    ServerConfig,
    configure_logger,
    healthcheck,
    container_healthcheck_config,
    config_from_args,
)


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
            "state_dir": self.tmpdir.name,
            "persona": "hp",
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
            response = bytearray()
            while data := sock.recv(4096):
                response.extend(data)
            return bytes(response)

    def test_command_exception_keeps_session_open(self) -> None:
        address = self.start_server()
        with patch("printer.Printer.command_fsmkdir", side_effect=OSError("broken")):
            response = self.exchange(address, b'@PJL FSMKDIR NAME="0:/test"\r\n@PJL INFO ID\r\n')
        self.assertIn(b"@PJL INFO ID", response)
        self.wait_for_event("connection_closed")
        errors = [record for record in self.handler.records if record.event == "command_error"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].error_type, "OSError")
        self.assertTrue(errors[0].payload_sha256)
        self.assertEqual(sum(hasattr(record, "session_end") for record in self.handler.records), 1)

    def test_session_deadline_bounds_idle_receive(self) -> None:
        address = self.start_server(timeout=10, session_timeout=0.15)
        with socket.create_connection(address, timeout=2) as sock:
            sock.sendall(b"@PJL USTATUSOFF\r\n")
            sock.settimeout(1)
            started = time.monotonic()
            self.assertEqual(sock.recv(4096), b"")
            self.assertLess(time.monotonic() - started, 1)
        self.wait_for_event("session_timeout")
        self.wait_for_event("connection_closed")

    def test_session_deadline_is_not_reset_by_incoming_data(self) -> None:
        address = self.start_server(timeout=1, session_timeout=0.2)
        with socket.create_connection(address, timeout=2) as sock:
            for _ in range(3):
                sock.sendall(b"@PJL USTATUSOFF\r\n")
                time.sleep(0.05)
            sock.settimeout(1)
            self.assertEqual(sock.recv(4096), b"")
        self.wait_for_event("session_timeout")

    def test_artifact_failure_still_emits_one_session_end(self) -> None:
        address = self.start_server()
        with patch("printer.Printer.save_raw_print_job", side_effect=OSError("disk full")):
            self.exchange(address, b"raw print body", expect_response=False)
            self.wait_for_event("connection_closed")
        self.assertEqual(sum(hasattr(record, "session_end") for record in self.handler.records), 1)
        self.assertIn("artifact_error", [record.event for record in self.handler.records])

    def test_connection_limit_is_shared_between_http_and_pjl(self) -> None:
        address = self.start_server(max_connections=1)
        web_server = create_http_server(
            ("127.0.0.1", 0),
            self.logger,
            2048,
            connection_slots=self.server.connection_slots,
        )
        web_thread = threading.Thread(target=web_server.serve_forever, daemon=True)
        web_thread.start()
        try:
            with socket.create_connection(address, timeout=2) as sock:
                sock.sendall(b"@PJL INFO ID\r\n")
                self.assertIn(b"@PJL INFO ID", sock.recv(4096))
                with socket.create_connection(web_server.server_address, timeout=2) as http_sock:
                    self.assertEqual(http_sock.recv(4096), b"")
                self.wait_for_event("connection_limit")
                rejection = next(record for record in self.handler.records if record.event == "connection_limit")
                self.assertEqual(rejection.protocol, "http")
                self.assertTrue(rejection.session_end)
            self.wait_for_event("connection_closed")
            self.assertTrue(self.server.connection_slots.acquire(timeout=1))
            self.server.connection_slots.release()
            connection = HTTPConnection(*web_server.server_address, timeout=2)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
            finally:
                connection.close()
        finally:
            web_server.shutdown()
            web_server.server_close()
            web_thread.join(timeout=2)

    def test_response_limit_does_not_split_fsupload_body(self) -> None:
        address = self.start_server(max_response_bytes=100)
        response = self.exchange(
            address,
            (
                b'@PJL FSDOWNLOAD SIZE=10 NAME="0:/f"\r\n0123456789'
                b"@PJL ECHO " + b"x" * 40 + b"\r\n"
                b'@PJL FSUPLOAD NAME="0:/f"\r\n'
            ),
        )
        self.assertIn(b"SIZE=10\r\n0123456789", response)
        self.assertTrue(response.endswith(b"0123456789"))

    def test_reconnect_preserves_fs_variables_and_ready_message(self) -> None:
        address = self.start_server()
        self.exchange(
            address, b'@PJL FSAPPEND SIZE=3 NAME="0:/persist"\nabc@PJL SET COPIES=7\n@PJL RDYMSG DISPLAY="Busy"\n'
        )
        response = self.exchange(address, b'@PJL FSQUERY NAME="0:/persist"\n@PJL INQUIRE COPIES\n@PJL INFO STATUS\n')
        self.assertIn(b"TYPE=FILE SIZE=3", response)
        self.assertIn(b"COPIES\r\n7", response)
        self.assertIn(b'DISPLAY="Busy"', response)
        self.assertTrue(all(record.persona == "hp" for record in self.handler.records))

    def test_brother_crash_closes_and_suppresses_only_same_source(self) -> None:
        address = self.start_server(persona="brother")
        response = self.exchange(address, b"@PJL SET FORMLINES=bad\n@PJL INFO ID\n")
        self.assertEqual(response, b"")
        self.wait_for_event("pjl_crash_probe")
        self.assertEqual(self.exchange(address, b"@PJL INFO ID\n"), b"")
        self.wait_for_event("reboot_suppressed")
        # macOS does not provide 127.0.0.2 by default; route this request to
        # a second source state without changing the host network configuration.
        original_get = self.server.device_store.get
        with patch.object(self.server.device_store, "get", side_effect=lambda source: original_get("127.0.0.2")):
            self.assertIn(b"Brother", self.exchange(address, b"@PJL INFO ID\n"))
        self.server.device_store.get("127.0.0.1").reboot_until = 0
        self.assertIn(b"Brother", self.exchange(address, b"@PJL INFO ID\n"))
        self.assertNotIn("command_error", [r.event for r in self.handler.records])

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


class HealthcheckConfigTestCase(unittest.TestCase):
    def test_container_healthcheck_uses_running_server_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cmdline = Path(directory) / "cmdline"
            cmdline.write_bytes(b"/app/.venv/bin/python\0./server.py\0--no-http\0--pjl-port\09101\0--http-port\08081\0")
            config = container_healthcheck_config(str(cmdline))
        self.assertFalse(config.http_enabled)
        self.assertEqual(config.pjl_port, 9101)
        self.assertEqual(config.http_port, 8081)

    def test_container_healthcheck_fails_for_unknown_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cmdline = Path(directory) / "cmdline"
            cmdline.write_bytes(b"sleep\0infinity\0")
            with self.assertRaises(ValueError):
                container_healthcheck_config(str(cmdline))

    def test_session_timeout_cli_default_and_override(self) -> None:
        self.assertEqual(config_from_args([]).session_timeout, 300)
        self.assertEqual(config_from_args(["--session-timeout", "42"]).session_timeout, 42)
