"""Bounded PJL framing and UEL-delimited print capture, independent of recv chunks."""

from __future__ import annotations

import re
from collections.abc import Callable

from printer import RESET_SEQUENCE, Printer


class StreamLimit(Exception):
    def __init__(self, event: str, size: int, limit: int):
        self.event, self.size, self.limit = event, size, limit
        super().__init__(event)


class PJLStream:
    def __init__(
        self,
        printer: Printer,
        command: Callable[[bytes], object],
        *,
        max_request_bytes: int = 65536,
        max_job_bytes: int = 1048576,
    ):
        self.printer, self.command = printer, command
        self.max_request_bytes, self.max_job_bytes = max_request_bytes, max_job_bytes
        self.request_bytes = self.job_bytes = 0
        self.pending = bytearray()
        self.language: str | None = None
        self.job = bytearray()
        self.finished = False

    def _count_request(self, size: int):
        self.request_bytes += size
        if self.request_bytes > self.max_request_bytes:
            raise StreamLimit("request_too_large", self.request_bytes, self.max_request_bytes)

    def _append_job(self, data: bytes):
        available = max(0, self.max_job_bytes - self.job_bytes)
        self.job.extend(data[:available])
        self.job_bytes += len(data)
        if self.job_bytes > self.max_job_bytes:
            raise StreamLimit("job_too_large", self.job_bytes, self.max_job_bytes)

    def _save_job(self):
        language = self.language or "RAW"
        kind = {"POSTSCRIPT": "ps", "PCL": "pcl", "PCLXL": "pcl", "PDF": "pdf"}.get(language, "raw")
        suffix = "." + kind if kind != "raw" else ".prn"
        data = bytes(self.job)
        self.job.clear()
        self.language = None
        self.printer._save_artifact(suffix, data, "save_print_job", artifact_type=kind, language=language)

    def feed(self, data: bytes, *, eof: bool = False):
        self.pending.extend(data)
        while self.pending:
            if self.language:
                index = self.pending.find(RESET_SEQUENCE)
                if index >= 0:
                    body = bytes(self.pending[:index])
                    del self.pending[: index + len(RESET_SEQUENCE)]
                    self._append_job(body)
                    self._save_job()
                    continue
                count = len(self.pending) if eof else max(0, len(self.pending) - len(RESET_SEQUENCE))
                body = bytes(self.pending[:count])
                del self.pending[:count]
                self._append_job(body)
                break
            if self.pending.startswith(RESET_SEQUENCE):
                del self.pending[: len(RESET_SEQUENCE)]
                self._count_request(len(RESET_SEQUENCE))
                continue
            if not eof and RESET_SEQUENCE.startswith(self.pending):
                break
            if self.pending.startswith(b"%!"):
                self.language = "POSTSCRIPT"
                continue
            if not eof and b"%!".startswith(self.pending):
                break
            end = self.pending.find(b"\n")
            if end < 0 and not eof:
                if self.request_bytes + len(self.pending) > self.max_request_bytes:
                    raise StreamLimit(
                        "request_too_large", self.request_bytes + len(self.pending), self.max_request_bytes
                    )
                break
            end = len(self.pending) if end < 0 else end + 1
            header = bytes(self.pending[:end])
            stripped = header.lstrip()
            if stripped.upper().startswith((b"@PJL FSDOWNLOAD ", b"@PJL FSAPPEND ")):
                size = self.printer.get_parameters(header).get("SIZE")
                try:
                    length = max(0, int(size)) if size is not None else 0
                except ValueError:
                    length = 0
                if end + length + self.request_bytes > self.max_request_bytes:
                    raise StreamLimit("request_too_large", end + length + self.request_bytes, self.max_request_bytes)
                if len(self.pending) < end + length and not eof:
                    break
                end += min(length, len(self.pending) - end)
            frame = bytes(self.pending[:end])
            del self.pending[:end]
            self._count_request(len(frame))
            match = re.fullmatch(rb"@PJL\s+ENTER\s+LANGUAGE\s*=\s*([A-Za-z0-9_-]+)\s*", stripped, re.IGNORECASE)
            if match:
                self.language = match[1].decode().upper()
                self.printer.logger.info(
                    "Print language selected",
                    extra={
                        "action": "print",
                        "event": "print_job",
                        "language": self.language,
                    },
                )
            elif stripped:
                self.command(frame)

    def finish(self):
        if self.finished:
            return
        self.finished = True
        try:
            self.feed(b"", eof=True)
        finally:
            if self.language is not None:
                self._save_job()
