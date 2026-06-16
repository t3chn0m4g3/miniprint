from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path

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
        self.assertEqual(response, "@PJL ECHO DELIMITER20687\x1b")

    def test_fsdownload_and_query(self) -> None:
        command = (
            b'FSDOWNLOAD FORMAT:BINARY SIZE=52 NAME="0:/test2.txt"\r\n'
            b"this is a file with only one line and no line breaks\r\n"
        )
        response = self.printer.command_fsdownload(command)
        self.assertEqual(response, "")

        query_response = self.printer.command_fsquery('@PJL FSQUERY NAME="0:/test2.txt"')
        self.assertEqual(query_response, '@PJL FSQUERY NAME="0:/test2.txt" TYPE=FILE SIZE=52')

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

        self.assertEqual(create_response, "")
        self.assertEqual(append_response, "")
        self.assertEqual(contents, b"abcdef")
        self.assertEqual(
            self.printer.command_fsquery('@PJL FSQUERY NAME="0:/append.bin"'),
            '@PJL FSQUERY NAME="0:/append.bin" TYPE=FILE SIZE=6',
        )

    def test_fsappend_limit_is_enforced(self) -> None:
        printer = Printer(self.logger, upload_dir=self.tmpdir.name, max_virtual_file_bytes=4)
        self.assertEqual(printer.command_fsappend(b'FSAPPEND SIZE=3 NAME="0:/small.bin"\r\nabc'), "")

        response = printer.command_fsappend(b'FSAPPEND SIZE=2 NAME="0:/small.bin"\r\nde')

        self.assertIn("FILEERROR=1", response)
        self.assertEqual(printer.command_fsquery('@PJL FSQUERY NAME="0:/small.bin"'), '@PJL FSQUERY NAME="0:/small.bin" TYPE=FILE SIZE=3')
        self.assertEqual(self.handler.records[-1].event, "fsappend_too_large")

    def test_fsdelete_removes_only_virtual_files(self) -> None:
        self.printer.command_fsdownload(b'FSDOWNLOAD SIZE=5 NAME="0:/delete.txt"\r\nhello')

        response = self.printer.command_fsdelete('@PJL FSDELETE NAME="0:/delete.txt"')
        missing = self.printer.command_fsdelete('@PJL FSDELETE NAME="0:/delete.txt"')

        self.assertEqual(response, "")
        self.assertFalse(self.printer.does_path_exist("/delete.txt"))
        self.assertEqual(missing, '@PJL FSDELETE NAME="0:/delete.txt" FILEERROR=3\r\n')
        self.assertEqual(self.handler.records[-1].event, "fsdelete")

    def test_fsinit_resets_to_seeded_virtual_filesystem(self) -> None:
        self.printer.command_fsmkdir('@PJL FSMKDIR NAME="0:/scratch"')
        self.printer.command_fsdownload(b'FSDOWNLOAD SIZE=4 NAME="0:/scratch/temp.bin"\r\ntemp')
        self.assertTrue(self.printer.does_path_exist("/scratch/temp.bin"))

        response = self.printer.command_fsinit("@PJL FSINIT VOLUME=\"0:\"")

        self.assertEqual(response, "")
        self.assertFalse(self.printer.does_path_exist("/scratch/temp.bin"))
        self.assertTrue(self.printer.does_path_exist("/webServer/home/device.html"))
        self.assertEqual(self.handler.records[-1].event, "fsinit")

    def test_fsdirlist(self) -> None:
        response = self.printer.command_fsdirlist('@PJL FSDIRLIST NAME="0:/webServer/home"')
        self.assertIn("@PJL FSDIRLIST", response)
        self.assertIn("device.html TYPE=FILE", response)

    def test_fsmkdir(self) -> None:
        response = self.printer.command_fsmkdir('@PJL FSMKDIR NAME="0:/testdir"')
        self.assertEqual(response, "")
        self.assertTrue(self.printer.does_path_exist("/testdir"))

    def test_fsupload_missing_and_present(self) -> None:
        missing = self.printer.command_fsupload('@PJL FSUPLOAD NAME="0:/none"')
        self.assertEqual(missing, '@PJL FSUPLOAD NAME="0:/none"\r\nFILEERROR=3\r\n')

        present = self.printer.command_fsupload('@PJL FSUPLOAD NAME="0:/webServer/home/device.html"')
        self.assertIn('@PJL FSUPLOAD FORMAT:BINARY NAME="0:/webServer/home/device.html"', present)
        self.assertIn("<title>Printer Content</title>", present)

    def test_get_parameters(self) -> None:
        params = self.printer.get_parameters('@PJL RDYMSG DISPLAY = "rdymsg"')
        self.assertEqual(params["DISPLAY"], "rdymsg")

        params = self.printer.get_parameters('@PJL COMMAND A=1 B=2 C="quoted value"')
        self.assertEqual(params["A"], "1")
        self.assertEqual(params["B"], "2")
        self.assertEqual(params["C"], "quoted value")

    def test_info_commands(self) -> None:
        self.assertEqual(self.printer.command_info_id(""), "@PJL INFO ID\r\nhp LaserJet 4200\r\n\x1b")
        self.assertEqual(
            self.printer.command_info_status(""),
            '@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY="Ready"\r\nONLINE=True',
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
        self.assertEqual(response, "")
        self.assertEqual(bytes(self.printer.current_raw_print_job), payload)
        self.assertTrue(self.printer.printing_raw_job)

        artifact = self.printer.save_raw_print_job()
        self.assertIsNotNone(artifact)
        self.assertFalse(self.printer.printing_raw_job)
        self.assertEqual(self.printer.current_raw_print_job, bytearray())
        self.assertEqual(Path(str(artifact)).read_bytes(), payload)

    def test_rdymsg(self) -> None:
        response = self.printer.command_rdymsg('@PJL RDYMSG DISPLAY="hello"')
        self.assertEqual(response, "")
        self.assertEqual(self.printer.ready_msg, "hello")

    def test_missing_parameters_return_pjl_errors(self) -> None:
        self.assertEqual(self.printer.command_fsquery("@PJL FSQUERY"), "@PJL FSQUERY FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_fsappend("@PJL FSAPPEND"), "@PJL FSAPPEND FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_fsdelete("@PJL FSDELETE"), "@PJL FSDELETE FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_fsinit('@PJL FSINIT VOLUME="1:"'), "@PJL FSINIT FILEERROR=2\r\n")
        self.assertEqual(self.printer.command_rdymsg("@PJL RDYMSG"), "@PJL RDYMSG FILEERROR=2\r\n")

    def test_path_traversal_is_rejected(self) -> None:
        response = self.printer.command_fsquery('@PJL FSQUERY NAME="0:/../../etc/passwd"')
        self.assertEqual(response, "@PJL FSQUERY FILEERROR=2\r\n")
        self.assertEqual(self.handler.records[-1].event, "path_traversal")

    def test_virtual_file_limit_is_enforced(self) -> None:
        printer = Printer(self.logger, upload_dir=self.tmpdir.name, max_virtual_file_bytes=4)
        response = printer.command_fsdownload('FSDOWNLOAD NAME="0:/too-big.txt"\r\n12345')
        self.assertIn("FILEERROR=1", response)
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
