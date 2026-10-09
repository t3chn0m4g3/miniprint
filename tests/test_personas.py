import logging
from unittest.mock import patch

from device_state import DeviceStateStore
from personas import PERSONAS, load_identity


def test_random_identity_is_stable(tmp_path):
    with patch("personas.secrets.choice", side_effect=lambda items: items[0]):
        first = load_identity("random", tmp_path, logging.getLogger("identity"))
    assert load_identity("random", tmp_path, logging.getLogger("identity")) == first
    assert (tmp_path / "identity.json").is_file()


def test_explicit_persona_replaces_identity_and_reroll_changes_serial(tmp_path):
    first = load_identity("hp", tmp_path, logging.getLogger("identity"))
    other = load_identity("brother", tmp_path, logging.getLogger("identity"))
    assert first.persona != other.persona
    again = load_identity("brother", tmp_path, logging.getLogger("identity"), reroll=True)
    assert other.serial != again.serial


def test_store_lru_and_ttl():
    clock = [0]
    store = DeviceStateStore(max_entries=2, ttl=5, clock=lambda: clock[0])
    original = store.get("a")
    store.get("b")
    assert store.get("a") is original
    store.get("c")
    assert len(store.entries) == 2
    clock[0] = 6
    assert store.get("a") is not original


def test_identity_fallback_for_unwritable_directory(tmp_path, caplog):
    path = tmp_path / "not-directory"
    path.write_text("x")
    identity = load_identity("lexmark", path, logging.getLogger("identity"))
    assert identity.persona == "lexmark"
    assert "in memory" in caplog.text


def test_corrupt_identity_is_replaced(tmp_path):
    (tmp_path / "identity.json").write_text("{}")
    assert load_identity("hp", tmp_path, logging.getLogger("identity")).persona == "hp"


def test_all_personas_have_consistent_seed_files(tmp_path):
    from printer import Printer

    for name, persona in PERSONAS.items():
        identity = load_identity(name, tmp_path / name, logging.getLogger("identity"))
        printer = Printer(logging.getLogger("printer"), persona=persona, identity=identity)
        data = printer.command_fsupload('FSUPLOAD NAME="0:/webServer/home/device.html"')
        assert persona.vendor.encode() in data
        assert identity.serial.encode() in data
        assert printer.command_info_id("").endswith(b"\r\n\x0c")


def test_fsinit_isolated_by_source_and_shared_across_printers():
    from printer import Printer

    store = DeviceStateStore()
    first = Printer(logging.getLogger("p"), device=store.get("a"))
    second = Printer(logging.getLogger("p"), device=store.get("b"))
    first.command_fsappend(b'FSAPPEND SIZE=1 NAME="0:/x"\na')
    reconnect = Printer(logging.getLogger("p"), device=store.get("a"))
    assert reconnect.does_path_exist("/x")
    second.command_fsinit("FSINIT")
    assert reconnect.does_path_exist("/x")
    reconnect.command_fsinit("FSINIT")
    assert not reconnect.does_path_exist("/x")


def test_cli_persona_takes_precedence_over_environment():
    from server import config_from_args

    with patch.dict("os.environ", {"MINIPRINT_PERSONA": "lexmark"}):
        assert config_from_args([]).persona == "lexmark"
        assert config_from_args(["--persona", "hp"]).persona == "hp"


def test_variables_default_and_info_families():
    from printer import Printer

    printer = Printer(logging.getLogger("p"))
    printer.command_variable("DEFAULT COPIES=2")
    printer.command_variable("SET COPIES=7")
    assert b"\r\n7\r\n" in printer.command_variable("INQUIRE COPIES")
    assert b"\r\n2\r\n" in printer.command_variable("DINQUIRE COPIES")
    for family in ("CONFIG", "MEMORY", "FILESYS", "PAGECOUNT", "PRODINFO", "VARIABLES"):
        response = printer.command_info("INFO " + family)
        assert response.startswith(("@PJL INFO " + family + "\r\n").encode())
        assert response.endswith(b"\r\n\x0c")
        if family == "FILESYS":
            # PRET skips the header and reads volume identifiers from subsequent rows.
            assert response.splitlines()[1].startswith(b"VOLUME ")
            assert response.splitlines()[2].startswith(b"0:")


def test_http_profiles_headers_and_error_pages(tmp_path):
    import threading
    from http.client import HTTPConnection

    from web_admin import create_http_server

    for name, persona in PERSONAS.items():
        identity = load_identity(name, tmp_path / name, logging.getLogger("identity"))
        server = create_http_server(("127.0.0.1", 0), logging.getLogger("web"), 2048, identity=identity)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for method, path, expected in [
                ("GET", persona.status_path, 200),
                ("OPTIONS", "/", 200),
                ("DELETE", "/", 405),
                ("PATCH", "/", 405),
                ("GET", "/missing", 404),
            ]:
                connection = HTTPConnection(*server.server_address, timeout=2)
                try:
                    connection.request(method, path)
                    response = connection.getresponse()
                    body = response.read()
                    assert response.status == expected, (name, method, path)
                    assert response.version == 11
                    assert [v for k, v in response.getheaders() if k.lower() == "server"] == [persona.banner]
                    assert b"Python" not in body
                    if method == "GET":
                        assert persona.vendor.encode() in body
                finally:
                    connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
