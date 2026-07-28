from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import replace

from mine_edge.adapters import ReadOnlyAdapter
from mine_edge.http_api import create_server
from mine_edge.scheduler import SourceManager
from mine_edge.service import EdgeService
from mine_edge.settings import SourceSettings
from mine_edge.storage import Repository


class RunningServer:
    def __init__(self, settings, web_root, source_manager=None) -> None:
        self.settings = settings
        self.service = EdgeService(Repository(settings.database_path), settings)
        self.source_manager = source_manager
        self.server = create_server(
            self.service,
            settings,
            port=0,
            web_root=web_root,
            source_manager=source_manager,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        if self.source_manager is not None:
            self.source_manager.start()
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.source_manager is not None:
            self.source_manager.stop()

    def request(self, path, *, method="GET", body=None, token=None):
        headers = {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            return response.status, json.load(response)


def test_health_is_public_and_other_api_requires_token(settings, tmp_path) -> None:
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("ok", encoding="utf-8")
    secured = replace(settings, api_token="secret-token")
    with RunningServer(secured, web) as running:
        status, health = running.request("/api/v1/health")
        assert status == 200
        assert health["production_control_api"] is False
        try:
            running.request("/api/v1/alerts")
        except urllib.error.HTTPError as error:
            assert error.code == 401
        status, body = running.request(
            "/api/v1/alerts", token="secret-token"
        )
        assert status == 200
        assert body["items"] == []


def test_manual_api_records_provenance_and_alert(settings, tmp_path) -> None:
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("ok", encoding="utf-8")
    payload = {
        "kind": "methane",
        "metric": "methane_concentration",
        "value": 1.1,
        "unit": "%",
        "location_code": "face-101",
        "observed_at": "2026-07-28T08:00:00+08:00",
        "provenance": {
            "source_id": "shift-report",
            "operator_id": "operator-1",
            "reason": "网关故障",
            "evidence_ref": "report-1",
        },
    }
    with RunningServer(settings, web) as running:
        status, result = running.request(
            "/api/v1/ingest/manual", method="POST", body=payload
        )
        assert status == 201
        assert len(result["alert_ids"]) == 1
        _, observations = running.request("/api/v1/observations")
        assert observations["items"][0]["quality"] == "manual"
        assert observations["items"][0]["provenance"]["operator_id"] == "operator-1"


def test_control_and_delete_are_not_exposed(settings, tmp_path) -> None:
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("ok", encoding="utf-8")
    with RunningServer(settings, web) as running:
        for path, method, expected in [
            ("/api/v1/control/fan", "POST", 404),
            ("/api/v1/observations/anything", "DELETE", 405),
        ]:
            try:
                running.request(path, method=method, body={})
            except urllib.error.HTTPError as error:
                assert error.code == expected


class _EmptyAdapter(ReadOnlyAdapter):
    def poll(self):
        return []


def test_source_health_and_connector_actions_are_exposed(settings, tmp_path) -> None:
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("ok", encoding="utf-8")
    source = SourceSettings(
        source_id="gas:gateway",
        adapter="jsonl",
        location="/read-only/gas.jsonl",
        interval_seconds=1,
        jitter_seconds=0,
        timeout_seconds=0.1,
        missing_after_seconds=10,
    )
    service = EdgeService(Repository(settings.database_path), settings)
    manager = SourceManager(
        (source,),
        service,
        adapter_factory=lambda _config: _EmptyAdapter(),
        jitter=lambda _start, _end: 0,
    )
    with RunningServer(settings, web, source_manager=manager) as running:
        status, health = running.request("/api/v1/health")
        assert status == 200
        assert health["sources_summary"]["total"] == 1
        assert health["sources_summary"]["methane_accelerated"] == 0
        assert health["source_heartbeat"]["signal"] == "ok"

        status, sources = running.request("/api/v1/sources")
        assert status == 200
        assert sources["items"][0]["source_id"] == "gas:gateway"
        adaptive = sources["items"][0]["methane_adaptive_sampling"]
        assert adaptive["mode"] == "regular"
        assert adaptive["poll_schedule_only"] is True
        assert adaptive["device_write_capability"] is False
        assert sources["configuration"][0]["read_only"] is True
        assert sources["configuration"][0][
            "methane_adaptive_sampling"
        ]["restart_behavior"] == "restore_unexpired_bounded_window"

        status, disabled = running.request(
            "/api/v1/sources/gas%3Agateway/disable",
            method="POST",
            body={},
        )
        assert status == 200
        assert disabled["health"] == "disabled"

        status, enabled = running.request(
            "/api/v1/sources/gas%3Agateway/enable",
            method="POST",
            body={},
        )
        assert status == 200
        assert enabled["enabled"] is True
