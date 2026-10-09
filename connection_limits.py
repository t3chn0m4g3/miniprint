from __future__ import annotations

import socket
import threading
import uuid
from datetime import UTC, datetime

from telemetry import ContextLoggerAdapter, format_utc


class ConnectionLimitedMixIn:
    """Acquire a connection slot before ThreadingMixIn starts a worker."""

    connection_slots: threading.BoundedSemaphore
    protocol: str

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self.connection_slots.acquire(blocking=False):
            now = format_utc(datetime.now(UTC))
            local_address = request.getsockname()
            log = ContextLoggerAdapter(
                self.logger,
                {
                    "session_id": str(uuid.uuid4()),
                    "src_ip": client_address[0],
                    "src_port": client_address[1],
                    "dest_ip": local_address[0],
                    "dest_port": local_address[1],
                    "session_start": now,
                    "protocol": self.protocol,
                },
            )
            try:
                log.warning(
                    "Connection limit reached",
                    extra={
                        "action": "reject",
                        "event": "connection_limit",
                        "session_end": now,
                        "session_duration": 0,
                    },
                )
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.connection_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connection_slots.release()
