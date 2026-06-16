"""
miniprint - a medium interaction printer honeypot
Copyright (C) 2019 Dan Salmon - salmon@protonmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import socket
import socketserver
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from printer import (
    DEFAULT_MAX_JOB_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_VIRTUAL_FILE_BYTES,
    RESET_SEQUENCE,
    Printer,
)
from web_admin import create_http_server


DEFAULT_CHUNK_BYTES = 4096
DEFAULT_MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_CONNECTIONS = 16
DEFAULT_TIMEOUT = 60
DEFAULT_PJL_PORT = 9100
DEFAULT_HTTP_PORT = 8080
FILE_LOG_EXCLUDED_EVENTS = {"server_start", "signal", "server_stop"}
STANDARD_LOG_ATTRS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "message",
    "module",
    "msecs",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


def format_utc(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ServerConfig:
    host: str = "localhost"
    pjl_port: int = DEFAULT_PJL_PORT
    http_port: int = DEFAULT_HTTP_PORT
    log_file: str = "./miniprint.log"
    timeout: int = DEFAULT_TIMEOUT
    uploads_dir: str = "uploads"
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_job_bytes: int = DEFAULT_MAX_JOB_BYTES
    max_virtual_file_bytes: int = DEFAULT_MAX_VIRTUAL_FILE_BYTES
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    http_enabled: bool = True


class JSONFormatter(logging.Formatter):
    def __init__(self, *, include_level: bool = True) -> None:
        super().__init__()
        self.include_level = include_level

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        del datefmt
        return datetime.fromtimestamp(record.created, UTC).isoformat().replace("+00:00", "Z")

    def format(self, record: logging.LogRecord) -> str:
        log_record: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "info": record.getMessage(),
        }
        if self.include_level:
            log_record["level"] = record.levelname
        for key, value in record.__dict__.items():
            if key in STANDARD_LOG_ATTRS or key.startswith("_") or value is None:
                continue
            log_record[key] = value
        return json.dumps(log_record, default=str, ensure_ascii=False)


class FileLogEventFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return getattr(record, "event", None) not in FILE_LOG_EXCLUDED_EVENTS


class ContextLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        base_extra = dict(self.extra)
        call_extra = kwargs.get("extra")
        if call_extra:
            base_extra.update(call_extra)
        kwargs["extra"] = base_extra
        return msg, kwargs


class LimitedThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[socketserver.BaseRequestHandler],
        config: ServerConfig,
        logger: logging.Logger,
    ) -> None:
        self.config = config
        self.logger = logger
        self.connection_slots = threading.BoundedSemaphore(config.max_connections)
        super().__init__(server_address, handler_class)


class PJLRequestHandler(socketserver.BaseRequestHandler):
    @staticmethod
    def parse_commands(data: bytes) -> list[bytes]:
        parts = re.split(rb"(@PJL)", data)
        parts = [part for part in parts if part]
        commands: list[bytes] = []
        for index, part in enumerate(parts):
            if part == b"@PJL":
                continue
            if index > 0 and parts[index - 1] == b"@PJL":
                commands.append(b"@PJL" + part)
            else:
                commands.append(part)
        return commands

    def setup(self) -> None:
        super().setup()
        self.slot_acquired = self.server.connection_slots.acquire(blocking=False)
        self.session_id = str(uuid.uuid4())
        self.data_seen = False
        self.bytes_received = 0
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
                "protocol": "pjl",
            },
        )

    def finish(self) -> None:
        if getattr(self, "slot_acquired", False):
            self.server.connection_slots.release()
        super().finish()

    def handle(self) -> None:
        if not self.slot_acquired:
            self.log.warning(
                "Connection refused because the active connection limit was reached",
                extra=self._session_end_extra({"action": "reject", "event": "connection_limit"}),
            )
            return

        config = self.server.config
        self.request.settimeout(config.timeout)
        printer = Printer(
            self.log,
            upload_dir=config.uploads_dir,
            max_job_bytes=config.max_job_bytes,
            max_response_bytes=config.max_response_bytes,
            max_virtual_file_bytes=config.max_virtual_file_bytes,
        )
        try:
            self._handle_loop(printer)
        finally:
            if self.data_seen:
                if printer.printing_raw_job:
                    printer.save_raw_print_job()
                if printer.receiving_postscript:
                    printer.save_postscript()
                self.log.info(
                    "Connection closed",
                    extra=self._session_end_extra({"action": "close_conn", "event": "connection_closed"}),
                )
            elif not self._is_loopback_client():
                self.log.info(
                    "Empty connection closed",
                    extra=self._session_end_extra({"action": "close_conn", "event": "empty_connection"}),
                )

    def _handle_loop(self, printer: Printer) -> None:
        config = self.server.config
        while True:
            try:
                data = self.request.recv(DEFAULT_CHUNK_BYTES)
            except TimeoutError:
                self.log.info("Connection timed out", extra={"action": "timeout", "event": "idle"})
                break
            except OSError as exc:
                self.log.warning(
                    "Socket receive failed",
                    extra={"action": "receive", "event": "receive_failed", "error": str(exc)},
                )
                break

            if not data:
                break
            if not self.data_seen:
                self.data_seen = True
                self.log.info("Connection opened", extra={"action": "open_conn", "event": "connection"})
            self.bytes_received += len(data)
            if self.bytes_received > config.max_request_bytes:
                self.log.warning(
                    "Request exceeded configured limit",
                    extra={
                        "action": "limit",
                        "event": "request_too_large",
                        "size": self.bytes_received,
                        "limit": config.max_request_bytes,
                        "payload_sha256": Printer.payload_hash(data),
                        "payload_preview": Printer.payload_preview(data),
                    },
                )
                break

            self._process_data(printer, data.replace(RESET_SEQUENCE, b""))

    def _is_loopback_client(self) -> bool:
        try:
            return ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def _session_end_extra(self, extra: dict[str, Any]) -> dict[str, Any]:
        session_end = datetime.now(UTC)
        return {
            **extra,
            "session_end": format_utc(session_end),
            "session_duration": round((session_end - self.session_start).total_seconds(), 6),
        }

    def _process_data(self, printer: Printer, data: bytes) -> None:
        if not data:
            return
        if self._contains_invalid_utf8(data):
            self.log.info(
                "Request contained invalid UTF-8 bytes",
                extra={
                    "action": "decode",
                    "event": "invalid_utf8",
                    "payload_sha256": Printer.payload_hash(data),
                    "payload_preview": Printer.payload_preview(data),
                },
            )

        if data.startswith(b"%!"):
            printer.receiving_postscript = True
            printer.append_postscript(data)
            self.log.info(
                "Received first PostScript chunk",
                extra={"action": "postscript", "event": "print_job"},
            )
            if b"%%EOF" in data:
                printer.save_postscript()
            return

        if printer.receiving_postscript:
            printer.append_postscript(data)
            if b"%%EOF" in data:
                printer.save_postscript()
            return

        response = bytearray()
        for command in self.parse_commands(data):
            response.extend(self._process_command(printer, command))
        if response:
            if len(response) > self.server.config.max_response_bytes:
                response = response[: self.server.config.max_response_bytes]
                self.log.warning(
                    "Truncated oversized response",
                    extra={
                        "action": "limit",
                        "event": "response_truncated",
                        "limit": self.server.config.max_response_bytes,
                    },
                )
            self.request.sendall(bytes(response))
            self.log.info("Response sent", extra={"action": "response", "event": "response_sent"})

    @staticmethod
    def _contains_invalid_utf8(data: bytes) -> bool:
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return False

    def _process_command(self, printer: Printer, command: bytes) -> bytes:
        command = command.lstrip()
        if not command:
            return b""
        if not command.startswith(b"@PJL "):
            printer.append_raw_print_job(command)
            return b""

        command_body = command[5:].lstrip()
        text = command_body.decode("utf-8", errors="replace").lstrip()
        command_name = text.split(None, 1)[0].upper() if text else ""
        self.log.debug(
            "PJL command received",
            extra={
                "action": "request",
                "event": "command_received",
                "command": command_name,
                "payload_sha256": Printer.payload_hash(command),
                "payload_preview": Printer.payload_preview(command),
            },
        )

        if printer.printing_raw_job:
            printer.save_raw_print_job()

        if command_name == "ECHO":
            response = printer.command_echo(text)
        elif command_name == "USTATUSOFF":
            response = printer.command_ustatusoff(text)
        elif text.startswith("INFO ID"):
            response = printer.command_info_id(text)
        elif text.startswith("INFO STATUS"):
            response = printer.command_info_status(text)
        elif command_name == "FSDIRLIST":
            response = printer.command_fsdirlist(text)
        elif command_name == "FSQUERY":
            response = printer.command_fsquery(text)
        elif command_name == "FSMKDIR":
            response = printer.command_fsmkdir(text)
        elif command_name == "FSUPLOAD":
            response = printer.command_fsupload(text)
        elif command_name == "FSDOWNLOAD":
            response = printer.command_fsdownload(command_body)
        elif command_name == "FSAPPEND":
            response = printer.command_fsappend(command_body)
        elif command_name == "FSDELETE":
            response = printer.command_fsdelete(text)
        elif command_name == "FSINIT":
            response = printer.command_fsinit(text)
        elif command_name == "RDYMSG":
            response = printer.command_rdymsg(text)
        else:
            self.log.warning(
                "Unknown PJL command received",
                extra={"action": "cmd_unknown", "event": "unknown_command", "command": command_name},
            )
            response = ""
        return response.encode("utf-8", errors="replace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="miniprint",
        description="miniprint - a medium interaction printer honeypot",
    )
    parser.add_argument("-b", "--bind", dest="host", default="localhost")
    parser.add_argument("--pjl-port", type=int, default=DEFAULT_PJL_PORT)
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--no-http", action="store_true")
    parser.add_argument("-l", "--log-file", dest="log_file", default="./miniprint.log")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--uploads-dir", default="uploads")
    parser.add_argument("--max-connections", type=int, default=DEFAULT_MAX_CONNECTIONS)
    parser.add_argument("--max-request-bytes", type=int, default=DEFAULT_MAX_REQUEST_BYTES)
    parser.add_argument("--max-job-bytes", type=int, default=DEFAULT_MAX_JOB_BYTES)
    parser.add_argument("--max-virtual-file-bytes", type=int, default=DEFAULT_MAX_VIRTUAL_FILE_BYTES)
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES)
    return parser


def config_from_args(argv: list[str] | None = None) -> ServerConfig:
    args = build_parser().parse_args(argv)
    return ServerConfig(
        host=args.host,
        pjl_port=args.pjl_port,
        http_port=args.http_port,
        log_file=args.log_file,
        timeout=args.timeout,
        uploads_dir=args.uploads_dir,
        max_connections=args.max_connections,
        max_request_bytes=args.max_request_bytes,
        max_job_bytes=args.max_job_bytes,
        max_virtual_file_bytes=args.max_virtual_file_bytes,
        max_response_bytes=args.max_response_bytes,
        http_enabled=not args.no_http,
    )


def configure_logger(log_file: str) -> logging.Logger:
    logger = logging.getLogger("miniprint")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(JSONFormatter(include_level=True))
    stream_handler.setLevel(logging.DEBUG)
    logger.addHandler(stream_handler)

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(JSONFormatter(include_level=False))
        file_handler.setLevel(logging.DEBUG)
        file_handler.addFilter(FileLogEventFilter())
        logger.addHandler(file_handler)
    return logger


def healthcheck(host: str, pjl_port: int, http_port: int, http_enabled: bool) -> int:
    try:
        with socket.create_connection((host, pjl_port), timeout=2):
            pass
        if http_enabled:
            with socket.create_connection((host, http_port), timeout=2):
                pass
    except OSError:
        return 1
    return 0


def serve(config: ServerConfig, logger: logging.Logger) -> None:
    Path(config.uploads_dir).mkdir(parents=True, exist_ok=True)
    pjl_server = LimitedThreadingTCPServer((config.host, config.pjl_port), PJLRequestHandler, config, logger)
    http_server = None
    servers: list[Any] = [pjl_server]
    if config.http_enabled:
        http_server = create_http_server((config.host, config.http_port), logger, config.max_request_bytes)
        servers.append(http_server)

    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

    logger.info(
        "Servers started",
        extra={
            "action": "start",
            "event": "server_start",
            "pjl_port": config.pjl_port,
            "http_port": config.http_port if config.http_enabled else None,
        },
    )

    stop_event = threading.Event()

    def request_stop(signum: int, _frame: Any) -> None:
        logger.info("Shutdown requested", extra={"action": "stop", "event": "signal", "signal": signum})
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, request_stop)

    try:
        stop_event.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        logger.info("Servers stopped", extra={"action": "stop", "event": "server_stop"})


def main(argv: list[str] | None = None) -> int:
    config = config_from_args(argv)
    if os.environ.get("MINIPRINT_HEALTHCHECK") == "1":
        return healthcheck("127.0.0.1", config.pjl_port, config.http_port, config.http_enabled)
    logger = configure_logger(config.log_file)
    serve(config, logger)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
