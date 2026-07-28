from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mine_edge.adapters import FileDropAdapter, HttpPollAdapter, JsonlAdapter
from mine_edge.errors import AdapterError


def test_jsonl_adapter_reads_without_modifying(tmp_path) -> None:
    path = tmp_path / "readings.jsonl"
    content = '{"kind":"methane"}\n\n{"kind":"personnel"}\n'
    path.write_text(content, encoding="utf-8")
    records = JsonlAdapter(path, source_id="gateway").poll()
    assert [item.data["kind"] for item in records] == ["methane", "personnel"]
    assert path.read_text(encoding="utf-8") == content
    assert JsonlAdapter.read_only is True


def test_file_drop_reads_json_array_and_leaves_files(tmp_path) -> None:
    path = tmp_path / "batch.json"
    path.write_text(json.dumps([{"a": 1}, {"a": 2}]), encoding="utf-8")
    records = FileDropAdapter(tmp_path).poll()
    assert [item.data["a"] for item in records] == [1, 2]
    assert path.exists()


def test_file_drop_jsonl_keeps_file_drop_provenance(tmp_path) -> None:
    path = tmp_path / "batch.jsonl"
    path.write_text('{"a":1}\n', encoding="utf-8")
    record = FileDropAdapter(tmp_path, source_id="drop-a").poll()[0]
    assert record.channel == "file_drop"
    assert record.source_id == "drop-a:batch.jsonl"


def test_invalid_jsonl_reports_line(tmp_path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"ok":true}\nnot-json\n', encoding="utf-8")
    with pytest.raises(AdapterError, match="第 2 行"):
        JsonlAdapter(path).poll()


def test_http_adapter_always_uses_get(monkeypatch) -> None:
    captured = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, _limit):
            return b'{"observations":[{"kind":"methane"}]}'

    class Opener:
        def open(self, request, timeout):
            captured["method"] = request.get_method()
            captured["timeout"] = timeout
            return Response()

    def fake_build_opener(*handlers):
        captured["redirect_policy"] = type(handlers[0]).__name__
        return Opener()

    monkeypatch.setattr("urllib.request.build_opener", fake_build_opener)
    records = HttpPollAdapter(
        "https://source.example/readings", timeout_seconds=3
    ).poll()
    assert captured == {
        "method": "GET",
        "timeout": 3,
        "redirect_policy": "_NoRedirectHandler",
    }
    assert records[0].channel == "http_poll"


def test_http_adapter_refuses_redirect_without_leaking_bearer_token() -> None:
    received_authorization: list[str | None] = []

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            received_authorization.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"[]")

        def log_message(self, _format, *_args):
            return

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{target.server_address[1]}/capture",
            )
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
    redirect_thread.start()
    try:
        adapter = HttpPollAdapter(
            f"http://127.0.0.1:{redirect.server_address[1]}/source",
            token="source-secret",
        )
        with pytest.raises(AdapterError, match="拒绝重定向"):
            adapter.poll()
        assert received_authorization == []
    finally:
        redirect.shutdown()
        redirect.server_close()
        redirect_thread.join(timeout=5)
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=5)
