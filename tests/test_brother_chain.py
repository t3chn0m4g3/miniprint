import csv
import io
import logging
import threading
import time
from http.client import HTTPConnection
from urllib.parse import urlencode

import pytest

from personas import PERSONAS, load_identity
from brother import brother_default_password
from web_admin import create_http_server


@pytest.mark.parametrize("serial,password", [("E78321M4N957143", "QpHXKTkK"), ("E78321M4N123456", "KKx:&4gs")])
def test_password_matches_executed_metasploit_reference(serial, password):
    # Independently executed official Ruby routine, default salt lookup index 254.
    assert brother_default_password(serial) == password


@pytest.fixture
def web(tmp_path):
    records = []

    class Handler(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger(str(tmp_path))
    logger.setLevel(logging.DEBUG)
    logger.addHandler(Handler())
    logger.propagate = False
    identity = load_identity("brother", tmp_path / "state", logger)
    server = create_http_server(
        ("127.0.0.1", 0), logger, 2048, identity=identity, uploads_dir=str(tmp_path / "uploads"), max_job_bytes=4096
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, records, tmp_path
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def request(server, path, body=None, cookie=None):
    conn = HTTPConnection(*server.server_address, timeout=2)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers["Cookie"] = cookie
    try:
        conn.request("POST" if body is not None else "GET", path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read(), response.getheader("Set-Cookie")
    finally:
        conn.close()


def login(server):
    password = brother_default_password(server.identity.serial)
    status, _, cookie = request(
        server, "/general/status.html", urlencode({"password": password, "loginurl": "/general/status.html"})
    )
    assert status == 200
    assert cookie and cookie.startswith("AuthCookie=")
    return cookie.split(";")[0], password


def test_serial_login_passback_firmware_chain(web):
    server, records, tmp_path = web
    status, body, _ = request(server, "/etc/mnt_info.csv")
    assert status == 200
    rows = list(csv.DictReader(io.StringIO(body.decode())))
    assert rows[0]["Serial No."] == server.identity.serial
    assert request(server, "/admin/ldap")[0] == 401
    cookie, password = login(server)
    assert (
        request(
            server, "/admin/ldap", urlencode({"server": "ldap.example.test", "password": "PRIVATE-SECRET"}), cookie
        )[0]
        == 200
    )
    assert request(server, "/admin/firmware", b"\x00FIRMWARE\xff", cookie)[0] == 202
    artifacts = list((tmp_path / "uploads").iterdir())
    assert len(artifacts) == 1 and artifacts[0].read_bytes() == b"\x00FIRMWARE\xff"
    events = {r.event for r in records}
    assert {"serial_leak_probe", "default_password_success", "passback_attempt", "save_firmware"} <= events
    logs = repr([r.__dict__ for r in records])
    assert password not in logs
    assert "PRIVATE-SECRET" not in logs
    assert any(getattr(r, "secret_supplied", False) for r in records)
    passback = next(r for r in records if r.event == "passback_attempt")
    assert passback.form_fields == [{"name": "server", "value": "ldap.example.test"}]
    assert passback.passback_target == "ldap.example.test"
    assert not hasattr(passback, "fields")


def test_form_fields_are_bounded(web):
    server, records, _ = web
    cookie, _ = login(server)
    params = [("k" * 100, "v" * 300)] + [(f"f{index}", "v") for index in range(40)]
    assert request(server, "/admin/network", urlencode(params), cookie)[0] == 200
    saved = next(r for r in records if r.event == "admin_settings_saved")
    assert len(saved.form_fields) == 32
    assert saved.form_fields[0] == {"name": "k" * 64, "value": "v" * 256}
    assert saved.passback_target is None


def test_passback_target_skips_ports_and_empty_hosts(web):
    server, records, _ = web
    cookie, _ = login(server)
    params = [("port", "25"), ("smtp_host", ""), ("smtp_server", "mail.example.test")]
    assert request(server, "/admin/smtp", urlencode(params), cookie)[0] == 200
    passback = next(r for r in records if r.event == "passback_attempt")
    assert passback.passback_target == "mail.example.test"


def test_cookie_expiry_wrong_password_and_upload_limit(web):
    server, records, _ = web
    assert request(server, "/login", urlencode({"username": "admin", "password": "wrong"}))[0] == 401
    cookie, _ = login(server)
    with server.auth.lock:
        server.auth.sessions[cookie.split("=", 1)[1]] = (time.monotonic() - 1, "127.0.0.1")
    assert request(server, "/admin/ldap", cookie=cookie)[0] == 401
    cookie, _ = login(server)
    assert request(server, "/admin/firmware", b"x" * 4097, cookie)[0] == 413


def test_crash_probe_only_affects_brother_source():
    from printer import Printer
    from device_state import DeviceStateStore, RebootRequested

    store = DeviceStateStore()
    printer = Printer(logging.getLogger("p"), persona=PERSONAS["brother"], device=store.get("a"))
    with pytest.raises(RebootRequested):
        printer.command_variable("SET FORMLINES=invalid")
    assert 59 < store.get("a").reboot_until - time.monotonic() <= 120
    assert store.get("b").reboot_until == 0
    hp = Printer(logging.getLogger("p"), persona=PERSONAS["hp"])
    assert hp.command_variable("SET FORMLINES=invalid") == b""


def test_multipart_firmware_is_saved_without_envelope(web):
    server, _, tmp_path = web
    cookie, _ = login(server)
    body = b'--upload\r\nContent-Disposition: form-data; name="firmware"; filename="evil.bin"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xffimage\r\n--upload--\r\n'
    connection = HTTPConnection(*server.server_address, timeout=2)
    try:
        connection.request(
            "POST",
            "/admin/firmware",
            body=body,
            headers={"Cookie": cookie, "Content-Type": "multipart/form-data; boundary=upload"},
        )
        response = connection.getresponse()
        assert response.status == 202
        response.read()
    finally:
        connection.close()
    assert next((tmp_path / "uploads").iterdir()).read_bytes() == b"\x00\xffimage"
