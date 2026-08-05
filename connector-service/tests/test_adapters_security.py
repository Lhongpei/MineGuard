from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import enterprise_connector.net as connector_net
from enterprise_connector.adapters import file_drop
from enterprise_connector.adapters.file_drop import collect_file_drop
from enterprise_connector.adapters.http_poll import collect_http_poll
from enterprise_connector.adapters.parsing import parse_records
from enterprise_connector.adapters.sqlite_query import collect_sqlite_query
from enterprise_connector.errors import SourceError
from enterprise_connector.models import SourceConfig
from enterprise_connector.net import request_bytes


class _Handler(BaseHTTPRequestHandler):
    body = b'[{"observed_at":"2026-07-29T00:00:00+08:00","value":1}]'
    seen_token: str | None = None

    def do_GET(self) -> None:  # noqa: N802
        type(self).seen_token = self.headers.get("X-Test-Token")
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/data")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sqlite_adapter_is_read_only(source_db: Path) -> None:
    source = SourceConfig(
        id="db",
        adapter="sqlite-query",
        source_name="db",
        source_system="mes",
        truth_statement="read only",
        database=source_db,
        query="SELECT * FROM five_quantity",
    )
    assert len(collect_sqlite_query(source)[0].records) == 8
    with pytest.raises(SourceError, match="只允许"):
        collect_sqlite_query(replace(source, query="DELETE FROM five_quantity"))
    connection = sqlite3.connect(source_db)
    assert connection.execute("SELECT COUNT(*) FROM five_quantity").fetchone()[0] == 8
    connection.close()


def test_duplicate_input_fields_are_rejected(source_db: Path) -> None:
    with pytest.raises(SourceError, match="重复字段"):
        parse_records(
            b'[{"outer":{"production":1,"production":999}}]',
            data_format="json",
            records_path=None,
            max_records=10,
        )
    with pytest.raises(SourceError, match="重复字段"):
        parse_records(
            b"observed_at,production,production\n2026-07-29,1,999\n",
            data_format="csv",
            records_path=None,
            max_records=10,
        )
    source = SourceConfig(
        id="db",
        adapter="sqlite-query",
        source_name="db",
        source_system="mes",
        truth_statement="read only",
        database=source_db,
        query="SELECT production AS duplicated, electricity AS duplicated FROM five_quantity",
    )
    with pytest.raises(SourceError, match="重复列名"):
        collect_sqlite_query(source)


def test_file_drop_requires_two_stable_scans_and_uses_no_follow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "drop"
    root.mkdir()
    path = root / "data.json"
    path.write_text('[{"observed_at":"2026-07-29","value":1}]', encoding="utf-8")
    source = SourceConfig(
        id="file",
        adapter="file-drop",
        source_name="file",
        source_system="drop",
        truth_statement="read only",
        path=root,
        glob="*.json",
        stable_seconds=1,
    )
    file_drop._STABILITY.clear()
    moments = iter((10.0, 12.0))
    monkeypatch.setattr(file_drop.time, "monotonic", lambda: next(moments))
    assert collect_file_drop(source) == ()
    batches = collect_file_drop(source)
    assert len(batches) == 1 and batches[0].records[0]["value"] == 1
    symlink = root / "link.json"
    try:
        symlink.symlink_to(path)
    except OSError:
        return
    moments = iter((14.0, 16.0))
    monkeypatch.setattr(file_drop.time, "monotonic", lambda: next(moments))
    collect_file_drop(source)
    assert all(batch.original_filename != "link.json" for batch in collect_file_drop(source))


def test_stable_empty_file_is_empty_batch_not_permanent_stability_wait(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "empty-drop"
    root.mkdir()
    (root / "empty.json").write_text("[]", encoding="utf-8")
    source = SourceConfig(
        id="empty-file",
        adapter="file-drop",
        source_name="empty-file",
        source_system="drop",
        truth_statement="read only",
        path=root,
        stable_seconds=1,
    )
    file_drop._STABILITY.clear()
    moments = iter((10.0, 12.0))
    monkeypatch.setattr(file_drop.time, "monotonic", lambda: next(moments))
    assert collect_file_drop(source) == ()
    batches = collect_file_drop(source)
    assert len(batches) == 1 and batches[0].records == ()


def test_file_drop_rejects_unbounded_candidate_set(tmp_path: Path) -> None:
    root = tmp_path / "many-files"
    root.mkdir()
    for index in range(3):
        (root / f"{index}.json").write_text("[]", encoding="utf-8")
    source = SourceConfig(
        id="bounded-file",
        adapter="file-drop",
        source_name="bounded-file",
        source_system="drop",
        truth_statement="read only",
        path=root,
        max_files_per_poll=2,
    )
    file_drop._STABILITY.clear()
    with pytest.raises(SourceError, match="max_files_per_poll"):
        collect_file_drop(source)


@pytest.mark.skipif(os.name != "posix", reason="POSIX bytes filenames only")
def test_file_drop_rejects_non_utf8_filename_as_source_error(tmp_path: Path) -> None:
    root = tmp_path / "non-utf8-drop"
    root.mkdir()
    raw_path = os.path.join(os.fsencode(root), b"bad-\xff.json")
    descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, b"[]")
    finally:
        os.close(descriptor)
    source = SourceConfig(
        id="non-utf8-file",
        adapter="file-drop",
        source_name="non-utf8-file",
        source_system="drop",
        truth_statement="read only",
        path=root,
        glob="*.json",
    )
    file_drop._STABILITY.clear()
    with pytest.raises(SourceError, match="有效 UTF-8"):
        collect_file_drop(source)


def test_http_poll_uses_env_header_and_fixed_allowlist(
    http_server: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    port = http_server.server_port
    monkeypatch.setenv("ERP_TEST_TOKEN", "opaque-secret")
    source = SourceConfig(
        id="http",
        adapter="http-poll",
        source_name="http",
        source_system="erp",
        truth_statement="read only",
        url=f"http://127.0.0.1:{port}/data",
        allowed_hosts=("127.0.0.1",),
        allowed_ports=(port,),
        allow_private_network=True,
        headers={"X-Test-Token": "ERP_TEST_TOKEN"},
    )
    assert collect_http_poll(source)[0].records[0]["value"] == 1
    assert _Handler.seen_token == "opaque-secret"


def test_redirect_and_oversized_response_are_rejected(http_server: ThreadingHTTPServer) -> None:
    port = http_server.server_port
    kwargs = {
        "headers": {},
        "body": None,
        "timeout": 1,
        "max_response_bytes": 10,
        "allowed_hosts": ("127.0.0.1",),
        "allowed_ports": (port,),
        "allow_private_network": True,
    }
    with pytest.raises(SourceError, match="重定向"):
        request_bytes("GET", f"http://127.0.0.1:{port}/redirect", **kwargs)
    _Handler.body = json.dumps({"data": "x" * 100}).encode()
    try:
        with pytest.raises(SourceError, match="大小上限"):
            request_bytes("GET", f"http://127.0.0.1:{port}/data", **kwargs)
    finally:
        _Handler.body = b'[{"observed_at":"2026-07-29T00:00:00+08:00","value":1}]'


def test_metadata_ip_is_always_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "enterprise_connector.net.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("169.254.169.254", 80))],
    )
    with pytest.raises(SourceError, match="禁止访问"):
        request_bytes(
            "GET",
            "http://metadata.local/data",
            headers={},
            body=None,
            timeout=1,
            max_response_bytes=100,
            allowed_hosts=("metadata.local",),
            allowed_ports=(80,),
            allow_private_network=True,
        )


def test_source_database_permissions_not_changed(source_db: Path) -> None:
    before = os.stat(source_db).st_mode
    source = SourceConfig(
        id="db",
        adapter="sqlite-query",
        source_name="db",
        source_system="mes",
        truth_statement="read only",
        database=source_db,
        query="SELECT * FROM five_quantity",
    )
    collect_sqlite_query(source)
    assert os.stat(source_db).st_mode == before


def test_https_uses_default_or_configured_ca_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str | None] = []

    class Response:
        status = 200

        @staticmethod
        def getheader(_name: str, default: str | None = None) -> str | None:
            return default

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return []

        @staticmethod
        def read(_maximum: int) -> bytes:
            return b"{}"

    class Connection:
        def __init__(self, *_args: object, context: object | None = None, **_kwargs: object):
            self.context = context

        def request(self, *_args: object, **_kwargs: object) -> None:
            return

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            return

    monkeypatch.setattr(
        connector_net,
        "_validate_target",
        lambda *_args, **_kwargs: ("agent.internal", 443, "203.0.113.1"),
    )
    monkeypatch.setattr(connector_net, "_PinnedHTTPSConnection", Connection)
    monkeypatch.setattr(
        connector_net.ssl,
        "create_default_context",
        lambda *, cafile=None: seen.append(cafile) or object(),
    )
    common = {
        "headers": {},
        "body": None,
        "timeout": 1,
        "max_response_bytes": 100,
        "allowed_hosts": ("agent.internal",),
        "allowed_ports": (443,),
        "allow_private_network": False,
    }
    request_bytes("GET", "https://agent.internal/data", **common)
    bundle = tmp_path / "private-ca.pem"
    bundle.write_text("demo", encoding="utf-8")
    request_bytes("GET", "https://agent.internal/data", ca_bundle=bundle, **common)
    assert seen == [None, str(bundle)]
