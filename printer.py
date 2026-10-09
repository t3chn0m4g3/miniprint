"""
miniprint - a medium interaction printer honeypot
Copyright (C) 2019 Dan Salmon - salmon@protonmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
import secrets
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pyfakefs import fake_filesystem

from device_state import DeviceState, RebootRequested
from personas import PERSONAS, Identity, Persona, new_identity

DEFAULT_MAX_JOB_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 128 * 1024
DEFAULT_MAX_VIRTUAL_FILE_BYTES = 256 * 1024
PJL_FILE_NOT_FOUND = "FILEERROR=3\r\n"
PJL_BAD_REQUEST = "FILEERROR=2\r\n"
RESET_SEQUENCE = b"\x1b%-12345X"


class Printer:
    def __init__(
        self,
        logger: Any,
        printer_id: str = "hp LaserJet 4200",
        code: int = 10001,
        ready_msg: str = "Ready",
        online: bool = True,
        upload_dir: str | os.PathLike[str] = "uploads",
        max_job_bytes: int = DEFAULT_MAX_JOB_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_virtual_file_bytes: int = DEFAULT_MAX_VIRTUAL_FILE_BYTES,
        persona: Persona | None = None,
        identity: Identity | None = None,
        device: DeviceState | None = None,
    ) -> None:
        self.persona = persona or PERSONAS["hp"]
        self.identity = identity or new_identity(self.persona.name)
        self.device = device or DeviceState(ready_msg=ready_msg)
        self.printer_id = self.persona.pjl_id if persona is not None else printer_id
        self.code = code
        self.online = online
        self.logger = logger
        self.upload_dir = Path(upload_dir)
        self.max_job_bytes = max_job_bytes
        self.max_response_bytes = max_response_bytes
        self.max_virtual_file_bytes = max_virtual_file_bytes
        self.param_pattern = re.compile(r'(\S+)\s*=\s*(?:"([^"]*)"|(\S+))')
        self.printing_raw_job = False
        self.current_raw_print_job = bytearray()
        self.receiving_postscript = False
        self.postscript_data = bytearray()

        with self.device.lock:
            if self.device.fs is None:
                self.reset_virtual_filesystem()
            else:
                self.fs = self.device.fs
                self.fos = fake_filesystem.FakeOsModule(self.fs)

    @property
    def ready_msg(self) -> str:
        return self.device.ready_msg

    @ready_msg.setter
    def ready_msg(self, value: str):
        self.device.ready_msg = value

    def reset_virtual_filesystem(self) -> None:
        self.fs = fake_filesystem.FakeFilesystem()
        self.device.fs = self.fs
        self.fos = fake_filesystem.FakeOsModule(self.fs)
        self._seed_filesystem()

    def _seed_filesystem(self) -> None:
        self.fs.create_dir("/PJL")
        self.fs.create_dir("/PostScript")
        self.fs.create_dir("/saveDevice/SavedJobs/InProgress")
        self.fs.create_dir("/saveDevice/SavedJobs/KeepJob")
        self.fs.create_dir("/webServer/default")
        self.fs.create_dir("/webServer/home")
        self.fs.create_dir("/webServer/lib")
        self.fs.create_dir("/webServer/objects")
        self.fs.create_dir("/webServer/permanent")
        for filename, target in (
            ("csconfig", "/webServer/default/csconfig"),
            ("device.html", "/webServer/home/device.html"),
            ("hostmanifest", "/webServer/home/hostmanifest"),
        ):
            template = (self.persona.seed_dir / filename).read_text()
            content = template.replace("{serial}", self.identity.serial).replace("{hostname}", self.identity.hostname)
            content = content.replace("{firmware}", self.identity.firmware)
            self.fs.create_file(target, contents=content)
        self.fs.create_file("/webServer/lib/keys")
        self.fs.create_file("/webServer/lib/security")

    @staticmethod
    def _as_text(data: bytes | str) -> str:
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return data

    @staticmethod
    def _as_bytes(data: bytes | str) -> bytes:
        if isinstance(data, str):
            return data.encode("utf-8", errors="replace")
        return data

    @staticmethod
    def payload_hash(data: bytes | str) -> str:
        return hashlib.sha256(Printer._as_bytes(data)).hexdigest()

    @staticmethod
    def payload_preview(data: bytes | str, limit: int = 96) -> str:
        raw = Printer._as_bytes(data)[:limit]
        return raw.decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")

    def _log_payload(self, level: str, message: str, data: bytes | str, **extra: Any) -> None:
        log_extra = {
            "payload_sha256": self.payload_hash(data),
            "payload_preview": self.payload_preview(data),
            **extra,
        }
        getattr(self.logger, level)(message, extra=log_extra)

    def _artifact_name(self, suffix: str, data: bytes) -> str:
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H-%M-%S-%f")
        digest = hashlib.sha256(data).hexdigest()[:16]
        return f"{timestamp}_{digest}{suffix}"

    def _save_artifact(self, suffix: str, data: bytes, event: str, **metadata: Any) -> str | None:
        if not data:
            self.logger.info("Nothing to save", extra={"action": "saving", "event": event})
            return None
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        filename = self._artifact_name(suffix, data)
        path = self.upload_dir / filename
        with path.open("wb") as handle:
            handle.write(data)
        self.logger.info(
            "Saved print artifact",
            extra={
                "action": "saving",
                "event": event,
                "file_name": filename,
                "artifact_type": {".ps": "ps", ".pcl": "pcl", ".pdf": "pdf"}.get(suffix, "raw"),
                **metadata,
                "payload_sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            },
        )
        return str(path)

    def _response(self, data: bytes | str) -> bytes:
        encoded = self._as_bytes(data)
        if len(encoded) <= self.max_response_bytes:
            return encoded
        self.logger.warning(
            "Response exceeded configured limit",
            extra={
                "action": "limit",
                "event": "response_too_large",
                "size": len(encoded),
                "limit": self.max_response_bytes,
            },
        )
        return encoded[: self.max_response_bytes]

    def get_parameters(self, command: bytes | str) -> dict[str, str]:
        text = self._as_text(command).split("\n", 1)[0].removesuffix("\r")
        return {
            match.group(1).upper(): match.group(2) if match.group(2) is not None else match.group(3)
            for match in self.param_pattern.finditer(text)
        }

    def _split_file_payload(self, request: bytes | str) -> tuple[bytes, bytes, dict[str, str], bool]:
        raw = self._as_bytes(request)
        header, separator, payload = raw.partition(b"\n")
        header = header.removesuffix(b"\r")
        parameters = self.get_parameters(header)
        size = parameters.get("SIZE")
        if size is not None:
            try:
                expected_size = int(size)
            except ValueError:
                return header, b"", parameters, False
            if expected_size < 0:
                return header, b"", parameters, False
            payload = payload[:expected_size]
        elif separator:
            payload = payload.removesuffix(b"\r\n") if payload.endswith(b"\r\n") else payload.removesuffix(b"\n")
        return header, payload, parameters, True

    @staticmethod
    def format_device_name(path: str) -> str:
        return f'"0:{path}"'

    def normalize_device_path(self, value: str | None) -> str | None:
        if not value:
            return None
        cleaned = value.strip().strip('"')
        if ":" in cleaned:
            volume, cleaned = cleaned.split(":", 1)
            if volume != "0":
                return None
        if ".." in cleaned.replace("\\", "/").split("/"):
            self.logger.warning(
                "Rejected virtual filesystem path traversal",
                extra={"action": "reject", "event": "path_traversal", "virtual_path": cleaned},
            )
            return None
        cleaned = cleaned.replace("\\", "/")
        normalized = posixpath.normpath("/" + cleaned.lstrip("/"))
        if normalized == "/.":
            return "/"
        return normalized

    def does_path_exist(self, path: str) -> bool:
        normalized = self.normalize_device_path(path)
        return bool(normalized and self.fos.path.exists(normalized))

    def append_raw_print_job(self, data: bytes | str) -> bytes:
        raw = self._as_bytes(data)
        if not raw:
            return b""
        self.printing_raw_job = True
        available = self.max_job_bytes - len(self.current_raw_print_job)
        if available <= 0:
            self._log_payload(
                "warning",
                "Raw print job exceeded configured limit",
                raw,
                action="limit",
                event="raw_job_too_large",
                limit=self.max_job_bytes,
            )
            return b""
        if len(raw) > available:
            self.current_raw_print_job.extend(raw[:available])
            self._log_payload(
                "warning",
                "Truncated raw print job at configured limit",
                raw,
                action="limit",
                event="raw_job_truncated",
                limit=self.max_job_bytes,
            )
            return b""
        self.current_raw_print_job.extend(raw)
        self._log_payload(
            "debug",
            "Appending raw print job",
            raw,
            action="append",
            event="append_raw_print_job",
            size=len(raw),
        )
        return b""

    def append_postscript(self, data: bytes | str) -> None:
        raw = self._as_bytes(data)
        available = self.max_job_bytes - len(self.postscript_data)
        if available <= 0:
            self._log_payload(
                "warning",
                "PostScript job exceeded configured limit",
                raw,
                action="limit",
                event="postscript_too_large",
                limit=self.max_job_bytes,
            )
            return
        if len(raw) > available:
            self.postscript_data.extend(raw[:available])
            self._log_payload(
                "warning",
                "Truncated PostScript job at configured limit",
                raw,
                action="limit",
                event="postscript_truncated",
                limit=self.max_job_bytes,
            )
            return
        self.postscript_data.extend(raw)

    def command_fsdownload(self, request: bytes | str) -> bytes:
        _, file_bytes, request_parameters, payload_valid = self._split_file_payload(request)
        if not payload_valid:
            return self._response(f"@PJL FSDOWNLOAD {PJL_BAD_REQUEST}")
        requested_name = request_parameters.get("NAME")
        file_name = self.normalize_device_path(requested_name)
        if not file_name:
            return self._response(f"@PJL FSDOWNLOAD {PJL_BAD_REQUEST}")
        if len(file_bytes) > self.max_virtual_file_bytes:
            self.logger.warning(
                "Rejected virtual filesystem write above configured limit",
                extra={
                    "action": "limit",
                    "event": "fsdownload_too_large",
                    "virtual_path": file_name,
                    "size": len(file_bytes),
                    "limit": self.max_virtual_file_bytes,
                },
            )
            return self._response(f"@PJL FSDOWNLOAD NAME={self.format_device_name(file_name)} FILEERROR=1\r\n")

        if self.fos.path.exists(file_name) and self.fos.path.isfile(file_name):
            self.fos.remove(file_name)
        try:
            self.fs.create_file(file_path=file_name, contents=file_bytes)
        except OSError:
            self.logger.warning(
                "Virtual filesystem write failed",
                extra={"action": "write", "event": "fsdownload_failed", "virtual_path": file_name},
            )
            return self._response(f"@PJL FSDOWNLOAD NAME={self.format_device_name(file_name)} {PJL_FILE_NOT_FOUND}")

        self.logger.info(
            "Virtual filesystem file written",
            extra={
                "action": "write",
                "event": "fsdownload",
                "virtual_path": file_name,
                "size": len(file_bytes),
            },
        )
        return b""

    def command_fsappend(self, request: bytes | str) -> bytes:
        _, payload, request_parameters, payload_valid = self._split_file_payload(request)
        if not payload_valid:
            return self._response(f"@PJL FSAPPEND {PJL_BAD_REQUEST}")
        requested_name = request_parameters.get("NAME")
        file_name = self.normalize_device_path(requested_name)
        if not file_name:
            return self._response(f"@PJL FSAPPEND {PJL_BAD_REQUEST}")

        parent_dir = posixpath.dirname(file_name) or "/"
        if self.fos.path.exists(file_name):
            if not self.fos.path.isfile(file_name):
                return self._response(f"@PJL FSAPPEND NAME={self.format_device_name(file_name)} {PJL_FILE_NOT_FOUND}")
            current_size = self.fos.stat(file_name).st_size
            mode = "ab"
        elif self.fos.path.isdir(parent_dir):
            current_size = 0
            mode = "wb"
        else:
            return self._response(f"@PJL FSAPPEND NAME={self.format_device_name(file_name)} {PJL_FILE_NOT_FOUND}")

        total_size = current_size + len(payload)
        if total_size > self.max_virtual_file_bytes:
            self.logger.warning(
                "Rejected virtual filesystem append above configured limit",
                extra={
                    "action": "limit",
                    "event": "fsappend_too_large",
                    "virtual_path": file_name,
                    "size": len(payload),
                    "total_size": total_size,
                    "limit": self.max_virtual_file_bytes,
                },
            )
            return self._response(f"@PJL FSAPPEND NAME={self.format_device_name(file_name)} FILEERROR=1\r\n")

        try:
            file_module = fake_filesystem.FakeFileOpen(self.fs)
            with file_module(file_name, mode) as handle:
                handle.write(payload)
        except OSError:
            self.logger.warning(
                "Virtual filesystem append failed",
                extra={"action": "append", "event": "fsappend_failed", "virtual_path": file_name},
            )
            return self._response(f"@PJL FSAPPEND NAME={self.format_device_name(file_name)} {PJL_FILE_NOT_FOUND}")

        self.logger.info(
            "Virtual filesystem file appended",
            extra={
                "action": "append",
                "event": "fsappend",
                "virtual_path": file_name,
                "size": len(payload),
                "total_size": total_size,
            },
        )
        return b""

    def command_echo(self, request: bytes | str) -> bytes:
        text = self._as_text(request)
        response = "@PJL " + text.rstrip("\r\n") + "\r\n\x0c"
        self.logger.info("Responding with echo", extra={"action": "response", "event": "echo"})
        return self._response(response)

    def command_fsdirlist(self, request: bytes | str) -> bytes:
        request_parameters = self.get_parameters(request)
        requested_dir = self.normalize_device_path(request_parameters.get("NAME"))
        if not requested_dir:
            return self._response(f"@PJL FSDIRLIST {PJL_BAD_REQUEST}")

        self.logger.debug(
            "Requested directory listing",
            extra={"action": "request", "event": "fsdirlist", "virtual_path": requested_dir},
        )
        if not self.fos.path.exists(requested_dir) or not self.fos.path.isdir(requested_dir):
            return_entries = "FILEERROR = 3"
        else:
            return_entries = " ENTRY=1\r\n. TYPE=DIR\r\n.. TYPE=DIR"
            for entry in self.fos.scandir(requested_dir):
                if entry.is_file():
                    size = self.fos.stat(posixpath.join(requested_dir, str(entry.name))).st_size
                    return_entries += f"\r\n{entry.name} TYPE=FILE SIZE={size}"
                elif entry.is_dir():
                    return_entries += f"\r\n{entry.name} TYPE=DIR"

        response = f"@PJL FSDIRLIST NAME={self.format_device_name(requested_dir)}{return_entries}"
        return self._response(response)

    def command_fsmkdir(self, request: bytes | str) -> bytes:
        request_parameters = self.get_parameters(request)
        requested_dir = self.normalize_device_path(request_parameters.get("NAME"))
        if not requested_dir:
            return self._response(f"@PJL FSMKDIR {PJL_BAD_REQUEST}")

        self.logger.info(
            "Creating virtual directory",
            extra={"action": "request", "event": "fsmkdir", "virtual_path": requested_dir},
        )
        if not self.fos.path.exists(requested_dir):
            self.fs.create_dir(requested_dir)
        return b""

    def command_fsdelete(self, request: bytes | str) -> bytes:
        request_parameters = self.get_parameters(request)
        requested_name = self.normalize_device_path(request_parameters.get("NAME"))
        if not requested_name:
            return self._response(f"@PJL FSDELETE {PJL_BAD_REQUEST}")
        if not self.fos.path.exists(requested_name) or not self.fos.path.isfile(requested_name):
            return self._response(f"@PJL FSDELETE NAME={self.format_device_name(requested_name)} {PJL_FILE_NOT_FOUND}")

        try:
            self.fos.remove(requested_name)
        except OSError:
            self.logger.warning(
                "Virtual filesystem delete failed",
                extra={"action": "delete", "event": "fsdelete_failed", "virtual_path": requested_name},
            )
            return self._response(f"@PJL FSDELETE NAME={self.format_device_name(requested_name)} {PJL_FILE_NOT_FOUND}")

        self.logger.info(
            "Virtual filesystem file deleted",
            extra={"action": "delete", "event": "fsdelete", "virtual_path": requested_name},
        )
        return b""

    def command_fsinit(self, request: bytes | str) -> bytes:
        request_parameters = self.get_parameters(request)
        volume = request_parameters.get("VOLUME") or request_parameters.get("NAME")
        if volume and self.normalize_device_path(volume) is None:
            return self._response(f"@PJL FSINIT {PJL_BAD_REQUEST}")

        self.reset_virtual_filesystem()
        self.logger.info(
            "Virtual filesystem initialized",
            extra={"action": "init", "event": "fsinit", "volume": volume or "0:"},
        )
        return b""

    def command_fsquery(self, request: bytes | str) -> bytes:
        request_parameters = self.get_parameters(request)
        requested_item = self.normalize_device_path(request_parameters.get("NAME"))
        if not requested_item:
            return self._response(f"@PJL FSQUERY {PJL_BAD_REQUEST}")

        if self.fos.path.exists(requested_item):
            if self.fos.path.isfile(requested_item):
                size = self.fos.stat(requested_item).st_size
                return_data = f"NAME={self.format_device_name(requested_item)} TYPE=FILE SIZE={size}"
            elif self.fos.path.isdir(requested_item):
                return_data = f"NAME={self.format_device_name(requested_item)} TYPE=DIR"
            else:
                return_data = f"NAME={self.format_device_name(requested_item)} TYPE=UNKNOWN"
        else:
            return_data = f"NAME={self.format_device_name(requested_item)} {PJL_FILE_NOT_FOUND}"
        return self._response("@PJL FSQUERY " + return_data)

    def command_fsupload(self, request: bytes | str) -> bytes:
        request_parameters = self.get_parameters(request)
        upload_file = self.normalize_device_path(request_parameters.get("NAME"))
        if not upload_file:
            return self._response(f"@PJL FSUPLOAD {PJL_BAD_REQUEST}")

        self.logger.info(
            "Virtual file requested",
            extra={"action": "request", "event": "fsupload", "virtual_path": upload_file},
        )
        if self.fos.path.exists(upload_file) and self.fos.path.isfile(upload_file):
            file_module = fake_filesystem.FakeFileOpen(self.fs)
            with file_module(upload_file, "rb") as handle:
                contents = handle.read()
            header = (
                f"@PJL FSUPLOAD FORMAT:BINARY NAME={self.format_device_name(upload_file)} "
                f"OFFSET=0 SIZE={len(contents)}\r\n"
            ).encode()
            # Never truncate a binary body while advertising the original SIZE.
            if len(header) + len(contents) > self.max_response_bytes:
                self.logger.warning(
                    "File response exceeded configured limit",
                    extra={
                        "action": "limit",
                        "event": "response_too_large",
                        "size": len(header) + len(contents),
                        "limit": self.max_response_bytes,
                    },
                )
                return self._response("@PJL FSUPLOAD FILEERROR=1\r\n")
            return header + contents
        return self._response(f"@PJL FSUPLOAD NAME={self.format_device_name(upload_file)}\r\n{PJL_FILE_NOT_FOUND}")

    def command_info_id(self, request: bytes | str) -> bytes:
        del request
        response = f"@PJL INFO ID\r\n{self.printer_id}\r\n\x0c"
        return self._response(response)

    def command_info_status(self, request: bytes | str) -> bytes:
        del request
        response = f'@PJL INFO STATUS\r\nCODE={self.code}\r\nDISPLAY="{self.ready_msg}"\r\nONLINE={str(self.online).upper()}\r\n\x0c'
        return self._response(response)

    def command_info(self, request: bytes | str) -> bytes:
        text = self._as_text(request).strip().upper()
        family = text.split()[-1]
        if family == "ID":
            return self.command_info_id(request)
        if family == "STATUS":
            return self.command_info_status(request)
        if family == "VARIABLES":
            value = "\r\n".join(f"{key}={value}" for key, value in self.device.variables.items())
        else:
            value = self.persona.info(family, self.identity)
        return self._response(f"@PJL INFO {family}\r\n{value}\r\n\x0c")

    def command_variable(self, request: bytes | str) -> bytes:
        text = self._as_text(request).strip()
        command, _, value = text.partition(" ")
        command = command.upper()
        if command in ("INQUIRE", "DINQUIRE"):
            store = self.device.defaults if command == "DINQUIRE" else self.device.variables
            return self._response(f"@PJL {command} {value.upper()}\r\n{store.get(value.upper(), '?')}\r\n\x0c")
        params = self.get_parameters(value)
        if self.persona.name == "brother" and command == "SET" and "FORMLINES" in params:
            try:
                int(params["FORMLINES"])
            except ValueError:
                duration = 60 + secrets.randbelow(61)
                self.device.reboot_until = time.monotonic() + duration
                self.logger.info(
                    "Simulated printer reboot",
                    extra={
                        "event": "pjl_crash_probe",
                        "command": "SET",
                        "variable": "FORMLINES",
                        "cve_hint": "CVE-2024-51982",
                        "reboot_seconds": duration,
                    },
                )
                raise RebootRequested()
        for key, val in params.items():
            self.device.variables[key] = val
            if command == "DEFAULT":
                self.device.defaults[key] = val
        self.logger.info(
            "PJL variable updated", extra={"event": "variable_set", "command": command, "variable": ",".join(params)}
        )
        return b""

    def command_job(self, request: bytes | str) -> bytes:
        command = self._as_text(request).split()[0].upper()
        self.logger.info("Job boundary observed", extra={"event": "job_boundary", "command": command})
        return b""

    def command_rnvram(self, request: bytes | str) -> bytes:
        del request
        self.logger.info("NVRAM requested", extra={"event": "rnvram"})
        return self._response(b"@PJL RNVRAM\r\n\x00\x01\x00\x00\r\n\x0c")

    def command_rdymsg(self, request: bytes | str) -> bytes:
        request_parameters = self.get_parameters(request)
        rdymsg = request_parameters.get("DISPLAY")
        if rdymsg is None:
            return self._response(f"@PJL RDYMSG {PJL_BAD_REQUEST}")
        self.ready_msg = rdymsg
        self.logger.info(
            "Ready message changed",
            extra={"action": "request", "event": "rdymsg", "rdymsg": self.ready_msg},
        )
        return b""

    def command_ustatusoff(self, request: bytes | str) -> bytes:
        del request
        self.logger.info("Status updates disabled", extra={"action": "request", "event": "ustatusoff"})
        return b""

    def save_postscript(self) -> str | None:
        data = bytes(self.postscript_data)
        artifact = self._save_artifact(".ps", data, "save_postscript")
        self.postscript_data.clear()
        self.receiving_postscript = False
        return artifact

    def save_raw_print_job(self) -> str | None:
        data = bytes(self.current_raw_print_job)
        artifact = self._save_artifact(".txt", data, "save_raw_print_job")
        self.current_raw_print_job.clear()
        self.printing_raw_job = False
        return artifact
