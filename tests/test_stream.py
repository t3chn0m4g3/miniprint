import logging

import pytest

from printer import RESET_SEQUENCE, Printer


def make_stream(tmp_path, **limits):
    from pjl_stream import PJLStream

    printer = Printer(logging.getLogger("stream"), upload_dir=tmp_path)
    commands = []
    return PJLStream(printer, commands.append, **limits), commands


@pytest.mark.parametrize(
    "language,suffix", [("POSTSCRIPT", ".ps"), ("PCL", ".pcl"), ("PDF", ".pdf"), ("OTHER", ".prn")]
)
def test_large_jobs_bypass_command_limit(tmp_path, language, suffix):
    stream, commands = make_stream(tmp_path, max_request_bytes=64, max_job_bytes=600000)
    payload = b"\x00@PJL ECHO not-a-command\xff" * 20000
    stream.feed(f"@PJL ENTER LANGUAGE={language}\r\n".encode() + payload + RESET_SEQUENCE + b"@PJL INFO ID\r\n")
    stream.finish()
    artifact = next(tmp_path.glob("*" + suffix))
    assert artifact.read_bytes() == payload
    assert commands[-1] == b"@PJL INFO ID\r\n"


@pytest.mark.parametrize("split", range(1, 10))
def test_uel_split_across_chunks(tmp_path, split):
    stream, commands = make_stream(tmp_path)
    stream.feed(b"@PJL ENTER LANGUAGE=PDF\nabc" + RESET_SEQUENCE[:split])
    stream.feed(RESET_SEQUENCE[split:] + b"@PJL INFO ID\n")
    stream.finish()
    assert next(tmp_path.glob("*.pdf")).read_bytes() == b"abc"
    assert commands == [b"@PJL INFO ID\n"]


def test_partial_uel_at_eof_is_payload(tmp_path):
    stream, _ = make_stream(tmp_path)
    stream.feed(b"@PJL ENTER LANGUAGE=PCL\nabc\x1b%-1")
    stream.finish()
    assert next(tmp_path.glob("*.pcl")).read_bytes() == b"abc\x1b%-1"


def test_binary_fs_payload_ignores_embedded_pjl(tmp_path):
    stream, commands = make_stream(tmp_path)
    payload = b"@PJL INFO ID\n\xff"
    frame = f'@PJL FSDOWNLOAD SIZE={len(payload)} NAME="0:/x"\n'.encode() + payload
    for byte in frame + b"@PJL INFO STATUS\n":
        stream.feed(bytes([byte]))
    stream.finish()
    assert commands == [frame, b"@PJL INFO STATUS\n"]


def test_job_limit_is_cumulative_and_saves_prefix(tmp_path):
    from pjl_stream import StreamLimit

    stream, _ = make_stream(tmp_path, max_job_bytes=5)
    with pytest.raises(StreamLimit):
        stream.feed(b"@PJL ENTER LANGUAGE=PCL\nabcdef" + RESET_SEQUENCE)
    stream.finish()
    assert next(tmp_path.glob("*.pcl")).read_bytes() == b"abcde"


def test_command_limit_applies_to_pending_header(tmp_path):
    from pjl_stream import StreamLimit

    stream, _ = make_stream(tmp_path, max_request_bytes=8)
    with pytest.raises(StreamLimit):
        stream.feed(b"@PJL ABCDEFG")
