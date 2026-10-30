from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyfakefs import fake_filesystem

from printer import Printer


class ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class PrinterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.handler = ListHandler()
        self.logger = logging.getLogger(f"test-printer-{id(self)}")
        self.logger.handlers.clear()
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)
        self.logger.propagate = False
        self.printer = Printer(self.logger, upload_dir=self.tmpdir.name)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_echo(self) -> None:
        response = self.printer.command_echo("ECHO DELIMITER20687")
        self.assertEqual(response, b"@PJL ECHO DELIMITER20687\r\n\x0c")

    def test_virtual_files_have_a_cumulative_budget(self) -> None:
        replies = [
            self.printer.command_fsdownload(
                f'FSDOWNLOAD SIZE=32768 NAME="0:/file{i}"\r\n'.encode() + b"x" * 32768
            )
            for i in range(10)
        ]
        self.assertIn(b"FILEERROR=1", replies[-1])
        self.assertLessEqual(self.printer.fs.get_disk_usage().used, 262144)
        self.assertTrue(self.printer.does_path_exist("/file0"))
        self.assertFalse(self.printer.does_path_exist("/file9"))
        self.assertEqual(self.handler.records[-1].event, "virtual_state_limit")

    def test_quota_rejection_preserves_existing_file(self) -> None:
        self.printer.command_fsdownload(b'FSDOWNLOAD SIZE=3 NAME="0:/keep"\r\nold')
        for i in range(7):
            self.printer.command_fsdownload(
                f'FSDOWNLOAD SIZE=32768 NAME="0:/fill{i}"\r\n'.encode() + b"x" * 32768
            )
        response = self.printer.command_fsdownload(
            b'FSDOWNLOAD SIZE=65536 NAME="0:/keep"\r\n' + b"y" * 65536
        )
        self.assertIn(b"FILEERROR=1", response)
        self.assertTrue(self.printer.command_fsupload(b'FSUPLOAD NAME="0:/keep"').endswith(b"old"))
        self.printer.command_fsdelete(b'FSDELETE NAME="0:/fill0"')
        self.assertEqual(self.printer.command_fsappend(b'FSAPPEND SIZE=1 NAME="0:/keep"\r\n!'), b"")
        self.assertTrue(self.printer.command_fsupload(b'FSUPLOAD NAME="0:/keep"').endswith(b"old!"))

    def test_virtual_entry_limit_includes_empty_files_and_directories(self) -> None:
        for i in range(128):
            self.printer.command_fsdownload(f'FSDOWNLOAD SIZE=0 NAME="0:/empty{i}"\r\n')
        response = self.printer.command_fsmkdir('FSMKDIR NAME="0:/overflow"')
        self.assertIn(b"FILEERROR=1", response)
        self.assertFalse(self.printer.does_path_exist("/overflow"))

    def test_implicit_directories_cannot_bypass_entry_limit(self) -> None:
        path = "/".join(["x"] * 129)
        response = self.printer.command_fsdownload(f'FSDOWNLOAD SIZE=1 NAME="0:/{path}"\r\nx')
        self.assertIn(b"FILEERROR=1", response)
        self.assertFalse(self.printer.does_path_exist("/x"))

    def test_virtual_paths_are_bounded(self) -> None:
        path = "/".join(["a" * 100] * 11)
        response = self.printer.command_fsmkdir(f'FSMKDIR NAME="0:/{path}"')
        self.assertIn(b"FILEERROR", response)
        self.assertFalse(self.printer.does_path_exist("/" + "a" * 100))

    def test_variable_entry_limit_survives_reconnect(self) -> None:
        for i in range(100):
            self.printer.command_variable(f"DEFAULT TEST{i}=1")
        reconnected = Printer(self.logger, upload_dir=self.tmpdir.name, device=self.printer.device)
        response = reconnected.command_variable("SET OVERFLOW=1")
        self.assertIn(b"FILEERROR=1", response)
        self.assertNotIn("OVERFLOW", self.printer.device.variables)
        self.assertLessEqual(len(self.printer.device.variables), 64)
        self.assertLessEqual(len(self.printer.device.defaults), 64)
        self.assertEqual(reconnected.command_variable("SET COPIES=2"), b"")

    def test_variable_byte_limit_rejects_update_atomically(self) -> None:
        before = self.printer.device.variables.copy()
        response = self.printer.command_variable("SET COPIES=2 OTHER=" + "x" * 8193)
        self.assertIn(b"FILEERROR=1", response)
        self.assertEqual(self.printer.device.variables, before)

    def test_ready_message_is_bounded(self) -> None:
        response = self.printer.command_rdymsg('RDYMSG DISPLAY="' + "x" * 8193 + '"')
        self.assertIn(b"FILEERROR=1", response)
        self.assertEqual(self.printer.ready_msg, "Ready")

    def test_artifact_collision_does_not_follow_symlink(self) -> None:
        outside = Path(self.tmpdir.name) / "outside"
        outside.write_bytes(b"keep")
        (Path(self.tmpdir.name) / "collision.prn").symlink_to(outside)
        with (
            patch.object(self.printer, "_artifact_name", return_value="collision.prn"),
            self.assertRaises(FileExistsError),
        ):
            self.printer._save_artifact(".prn", b"replace", "save_print_job")
        self.assertEqual(outside.read_bytes(), b"keep")

    def test_fsdownload_and_query(self) -> None:
        command = (
            b'FSDOWNLOAD FORMAT:BINARY SIZE=52 NAME="0:/test2.txt"\r\n'
            b"this is a file with only one line and no line breaks\r\n"
        )
        response = self.printer.command_fsdownload(command)
        self.assertEqual(response, b"")

        query_response = self.printer.command_fsquery(b'@PJL FSQUERY NAME="0:/test2.txt"')
        self.assertEqual(query_response, b'@PJL FSQUERY NAME="0:/test2.txt" TYPE=FILE SIZE=52')

    def test_fsappend_creates_and_appends_binary_file(self) -> None:
        create_response = self.printer.command_fsappend(
            b'FSAPPEND FORMAT:BINARY SIZE=3 NAME="0:/append.bin"\r\nabc\r\n',
        )
        append_response = self.printer.command_fsappend(
            b'FSAPPEND FORMAT:BINARY SIZE=3 NAME="0:/append.bin"\r\ndef\r\n',
        )

        file_module = fake_filesystem.FakeFileOpen(self.printer.fs)
        with file_module("/append.bin", "rb") as handle:
            contents = handle.read()

        self.assertEqual(create_response, b"")
        self.assertEqual(append_response, b"")
        self.assertEqual(contents, b"abcdef")
        self.assertEqual(
            self.printer.command_fsquery(b'@PJL FSQUERY NAME="0:/append.bin"'),
            b'@PJL FSQUERY NAME="0:/append.bin" TYPE=FILE SIZE=6',
        )

    def test_fsappend_limit_is_enforced(self) -> None:
        printer = Printer(self.logger, upload_dir=self.tmpdir.name, max_virtual_file_bytes=4)
        self.assertEqual(printer.command_fsappend(b'FSAPPEND SIZE=3 NAME="0:/small.bin"\r\nabc'), b"")

        response = printer.command_fsappend(b'FSAPPEND SIZE=2 NAME="0:/small.bin"\r\nde')

        self.assertIn(b"FILEERROR=1", response)
        self.assertEqual(
            printer.command_fsquery(b'@PJL FSQUERY NAME="0:/small.bin"'),
            b'@PJL FSQUERY NAME="0:/small.bin" TYPE=FILE SIZE=3',
        )
        self.assertEqual(self.handler.records[-1].event, "fsappend_too_large")

    def test_fsdelete_removes_only_virtual_files(self) -> None:
        self.printer.command_fsdownload(b'FSDOWNLOAD SIZE=5 NAME="0:/delete.txt"\r\nhello')

        response = self.printer.command_fsdelete(b'@PJL FSDELETE NAME="0:/delete.txt"')
        missing = self.printer.command_fsdelete(b'@PJL FSDELETE NAME="0:/delete.txt"')

        self.assertEqual(response, b"")
        self.assertFalse(self.printer.does_path_exist("/delete.txt"))
        self.assertEqual(missing, b'@PJL FSDELETE NAME="0:/delete.txt" FILEERROR=3\r\n')
        self.assertEqual(self.handler.records[-1].event, "fsdelete")

    def test_fsinit_resets_to_seeded_virtual_filesystem(self) -> None:
        self.printer.command_fsmkdir(b'@PJL FSMKDIR NAME="0:/scratch"')
        self.printer.command_fsdownload(b'FSDOWNLOAD SIZE=4 NAME="0:/scratch/temp.bin"\r\ntemp')
        self.assertTrue(self.printer.does_path_exist("/scratch/temp.bin"))

        response = self.printer.command_fsinit(b'@PJL FSINIT VOLUME="0:"')

        self.assertEqual(response, b"")
        self.assertFalse(self.printer.does_path_exist("/scratch/temp.bin"))
        self.assertTrue(self.printer.does_path_exist("/webServer/home/device.html"))
        self.assertEqual(self.handler.records[-1].event, "fsinit")

    def test_fsdirlist(self) -> None:
        response = self.printer.command_fsdirlist(b'@PJL FSDIRLIST NAME="0:/webServer/home"')
        self.assertIn(b"@PJL FSDIRLIST", response)
        self.assertIn(b"device.html TYPE=FILE", response)

    def test_fsmkdir(self) -> None:
        response = self.printer.command_fsmkdir(b'@PJL FSMKDIR NAME="0:/testdir"')
        self.assertEqual(response, b"")
        self.assertTrue(self.printer.does_path_exist("/testdir"))

    def test_fsupload_missing_and_present(self) -> None:
        missing = self.printer.command_fsupload(b'@PJL FSUPLOAD NAME="0:/none"')
        self.assertEqual(missing, b'@PJL FSUPLOAD NAME="0:/none"\r\nFILEERROR=3\r\n')

        present = self.printer.command_fsupload(b'@PJL FSUPLOAD NAME="0:/webServer/home/device.html"')
        self.assertIn(b'@PJL FSUPLOAD FORMAT:BINARY NAME="0:/webServer/home/device.html"', present)
        self.assertIn(b"<title>Printer Content</title>", present)

    def test_fsupload_preserves_binary_bytes_and_size(self) -> None:
        payload = b"\x00\xff\xfe\xc3\xa4"
        self.printer.command_fsdownload(b'FSDOWNLOAD SIZE=5 NAME="0:/binary.bin"\r\n' + payload)
        response = self.printer.command_fsupload('FSUPLOAD NAME="0:/binary.bin"')
        self.assertEqual(response, b'@PJL FSUPLOAD FORMAT:BINARY NAME="0:/binary.bin" OFFSET=0 SIZE=5\r\n' + payload)

    def test_file_payload_accepts_lf_and_does_not_override_header(self) -> None:
        payload = b'NAME="0:/wrong.bin"'
        for command in ("FSDOWNLOAD", "FSAPPEND"):
            with self.subTest(command=command):
                self.printer.reset_virtual_filesystem()
                handler = getattr(self.printer, f"command_{command.lower()}")
                handler(f'{command} SIZE={len(payload)} NAME="0:/right.bin"\n'.encode() + payload)
                with fake_filesystem.FakeFileOpen(self.printer.fs)("/right.bin", "rb") as handle:
                    self.assertEqual(handle.read(), payload)
                self.assertFalse(self.printer.does_path_exist("/wrong.bin"))

    def test_fsupload_rejects_body_above_response_limit(self) -> None:
        printer = Printer(self.logger, upload_dir=self.tmpdir.name, max_response_bytes=128)
        printer.command_fsdownload(b'FSDOWNLOAD SIZE=200 NAME="0:/large.bin"\r\n' + b"x" * 200)
        self.assertEqual(printer.command_fsupload('FSUPLOAD NAME="0:/large.bin"'), b"@PJL FSUPLOAD FILEERROR=1\r\n")

    def test_response_limit_counts_bytes_without_reencoding(self) -> None:
        printer = Printer(self.logger, upload_dir=self.tmpdir.name, max_response_bytes=1)
        self.assertEqual(printer._response("ä"), b"\xc3")

    def test_get_parameters(self) -> None:
        params = self.printer.get_parameters(b'@PJL RDYMSG DISPLAY = "rdymsg"')
        self.assertEqual(params["DISPLAY"], "rdymsg")

        params = self.printer.get_parameters(b'@PJL COMMAND A=1 B=2 C="quoted value"')
        self.assertEqual(params["A"], "1")
        self.assertEqual(params["B"], "2")
        self.assertEqual(params["C"], "quoted value")

    def test_info_commands(self) -> None:
        self.assertEqual(self.printer.command_info_id(b""), b"@PJL INFO ID\r\nhp LaserJet 4200\r\n\x0c")
        self.assertEqual(
            self.printer.command_info_status(b""),
            b'@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY="Ready"\r\nONLINE=TRUE\r\n\x0c',
        )

    def test_postscript_job_saved_as_binary_artifact(self) -> None:
        payload = b"%!\n(Hello World) print\n%%EOF"
        self.printer.receiving_postscript = True
        self.printer.append_postscript(payload)
        artifact = self.printer.save_postscript()

        self.assertIsNotNone(artifact)
        self.assertEqual(self.printer.postscript_data, bytearray())
        self.assertFalse(self.printer.receiving_postscript)
        self.assertEqual(Path(str(artifact)).read_bytes(), payload)

    def test_raw_print_job_saved_as_binary_artifact(self) -> None:
        payload = b"TEST - this is the first line of my raw print job"
        response = self.printer.append_raw_print_job(payload)
        self.assertEqual(response, b"")
        self.assertEqual(bytes(self.printer.current_raw_print_job), payload)
        self.assertTrue(self.printer.printing_raw_job)

        artifact = self.printer.save_raw_print_job()
        self.assertIsNotNone(artifact)
        self.assertFalse(self.printer.printing_raw_job)
        self.assertEqual(self.printer.current_raw_print_job, bytearray())
        self.assertEqual(Path(str(artifact)).read_bytes(), payload)

    def test_rdymsg(self) -> None:
        response = self.printer.command_rdymsg(b'@PJL RDYMSG DISPLAY="hello"')
        self.assertEqual(response, b"")
        self.assertEqual(self.printer.ready_msg, "hello")

    def test_missing_parameters_return_pjl_errors(self) -> None:
        self.assertEqual(self.printer.command_fsquery(b"@PJL FSQUERY"), b"@PJL FSQUERY FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_fsappend(b"@PJL FSAPPEND"), b"@PJL FSAPPEND FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_fsdelete(b"@PJL FSDELETE"), b"@PJL FSDELETE FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_fsinit(b'@PJL FSINIT VOLUME="1:"'), b"@PJL FSINIT FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_rdymsg(b"@PJL RDYMSG"), b"@PJL RDYMSG FILEERROR=2\r\n")

    def test_path_traversal_is_rejected(self) -> None:
        response = self.printer.command_fsquery(b'@PJL FSQUERY NAME="0:/../../etc/passwd"')
        self.assertEqual(response, b"@PJL FSQUERY FILEERROR=2\r\n")
        self.assertEqual(self.handler.records[-1].event, "path_traversal")

    def test_virtual_file_limit_is_enforced(self) -> None:
        printer = Printer(self.logger, upload_dir=self.tmpdir.name, max_virtual_file_bytes=4)
        response = printer.command_fsdownload('FSDOWNLOAD NAME="0:/too-big.txt"\r\n12345')
        self.assertIn(b"FILEERROR=1", response)
        self.assertFalse(printer.does_path_exist("/too-big.txt"))

    def test_full_payload_is_not_logged_for_raw_jobs(self) -> None:
        secret_payload = b"confidential document body"
        self.printer.append_raw_print_job(secret_payload)
        messages = "\n".join(record.getMessage() for record in self.handler.records)
        self.assertNotIn(secret_payload.decode("utf-8"), messages)
        self.assertTrue(any(hasattr(record, "payload_sha256") for record in self.handler.records))

    def test_upload_dir_is_created_when_needed(self) -> None:
        nested = os.path.join(self.tmpdir.name, "nested", "uploads")
        printer = Printer(self.logger, upload_dir=nested)
        printer.append_raw_print_job(b"hello")
        artifact = printer.save_raw_print_job()
        self.assertIsNotNone(artifact)
        self.assertTrue(Path(str(artifact)).exists())
