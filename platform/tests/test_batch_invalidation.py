from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from mineguard.api import create_server
from mineguard.casework import LocalRepository, VersionConflictError


ROOT = Path(__file__).resolve().parents[1]


def _request(batch_id: str) -> dict[str, Any]:
    analysis = json.loads(
        (ROOT / "examples" / "production_inconsistent.json").read_text(
            encoding="utf-8"
        )
    )
    analysis["mine_id"] = "M001"
    return {
        "batch_id": batch_id,
        "portfolio_name": "批次作废测试",
        "expected_mine_ids": ["M001"],
        "analyses": [analysis],
    }


def _result(batch_id: str = "test-batch") -> dict[str, Any]:
    return {
        "batch_id": batch_id,
        "portfolio_name": "批次作废测试",
        "items": [
            {
                "mine_id": "M001",
                "technical_status": "inconsistent",
                "review_priority": "P1",
                "summary": "test",
                "analysis": {
                    "mine_id": "M001",
                    "status": "inconsistent",
                    "raw_anomaly_statistic": 4.0,
                    "data_quality": {"score": 80.0},
                },
            }
        ]
    }


def _save(repository: LocalRepository, batch_id: str) -> None:
    repository.save_portfolio_batch(
        _request(batch_id),
        _result(batch_id),
        "test",
        context_obj={"kind": "governed_production_ingest"},
    )


def test_batch_invalidation_filters_derived_views_and_can_restore(
    tmp_path: Path,
) -> None:
    repository = LocalRepository(tmp_path / "batch-lifecycle.db")
    try:
        _save(repository, "production-001")
        case_id = repository.list_cases()[0]["case_id"]
        assert repository.list_algorithm_features()
        assert repository.verify_batch_lifecycle_chain("production-001")

        invalidated = repository.set_batch_active(
            "production-001",
            active=False,
            expected_version=1,
            actor="admin",
            reason="上游确认该批次重复报送",
        )
        assert invalidated["changed"] is True
        assert invalidated["lifecycle"]["active"] is False
        assert repository.list_batches() == []
        assert repository.get_latest_batch() is None
        assert repository.list_cases() == []
        assert repository.count_open_cases() == 0
        assert repository.list_algorithm_features() == []

        # Direct identifiers and explicit audit reads preserve traceability.
        assert repository.get_batch("production-001")["lifecycle"][
            "active"
        ] is False
        assert repository.get_case(case_id)["case_id"] == case_id
        assert repository.list_algorithm_features(
            include_invalidated=True
        )
        assert [event["action"] for event in repository.get_batch_lifecycle_events(
            "production-001"
        )] == ["created", "invalidated"]
        assert repository.verify_batch_lifecycle_chain("production-001")

        with pytest.raises(VersionConflictError):
            repository.set_batch_active(
                "production-001",
                active=True,
                expected_version=1,
                actor="admin",
                reason="使用过期版本恢复",
            )

        restored = repository.set_batch_active(
            "production-001",
            active=True,
            expected_version=2,
            actor="admin",
            reason="数据责任人完成复核，撤销作废",
        )
        assert restored["lifecycle"]["active"] is True
        assert repository.list_batches()[0]["batch_id"] == "production-001"
        assert repository.list_cases()[0]["case_id"] == case_id
        assert repository.list_algorithm_features()
        assert repository.verify_batch_lifecycle_chain("production-001")
    finally:
        repository.close()


def test_legacy_pilot_isolation_is_scoped_and_idempotent(
    tmp_path: Path,
) -> None:
    repository = LocalRepository(tmp_path / "pilot-isolation.db")
    try:
        for batch_id in ("pilot-old-1", "pilot-old-2", "production-1"):
            _save(repository, batch_id)

        isolated = repository.isolate_legacy_pilot_batches(
            actor="admin",
            reason="隔离旧演示数据",
        )
        assert [item["batch_id"] for item in isolated] == [
            "pilot-old-1",
            "pilot-old-2",
        ]
        assert [
            batch["batch_id"] for batch in repository.list_batches()
        ] == ["production-1"]
        assert repository.isolate_legacy_pilot_batches(
            actor="admin",
            reason="重复执行",
        ) == []
    finally:
        repository.close()


@contextmanager
def _running_server(
    database_path: Path,
) -> Iterator[tuple[Any, str, int]]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=database_path,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield server, str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _http(
    host: str,
    port: int,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    encoded = None if body is None else json.dumps(body).encode()
    headers = (
        {}
        if encoded is None
        else {"Content-Type": "application/json; charset=utf-8"}
    )
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_batch_status_api_uses_optimistic_version_and_preserves_audit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "batch-status-api.db"
    with _running_server(database) as (_, host, port):
        status, created = _http(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            _request("pilot-api"),
        )
        assert status == 200
        assert created["batch_id"] == "pilot-api"

        status, changed = _http(
            host,
            port,
            "POST",
            "/v1/analysis-batches/pilot-api/status",
            {
                "active": False,
                "reason": "演示批次隔离",
                "expected_version": 1,
            },
        )
        assert status == 200
        assert changed["lifecycle"]["active"] is False
        assert changed["lifecycle_chain_valid"] is True

        status, overview = _http(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        assert overview["batch"] is None

        status, active_list = _http(
            host,
            port,
            "GET",
            "/v1/analysis-batches",
        )
        assert status == 200
        assert active_list["items"] == []

        status, full_list = _http(
            host,
            port,
            "GET",
            "/v1/analysis-batches?include_invalidated=true",
        )
        assert status == 200
        assert full_list["items"][0]["batch_id"] == "pilot-api"
        assert full_list["items"][0]["lifecycle"]["active"] is False

        status, detail = _http(
            host,
            port,
            "GET",
            "/v1/analysis-batches/pilot-api",
        )
        assert status == 200
        assert detail["batch"]["batch_id"] == "pilot-api"
        assert detail["lifecycle_chain_valid"] is True
        assert [event["action"] for event in detail["lifecycle_events"]] == [
            "created",
            "invalidated",
        ]

        status, stale = _http(
            host,
            port,
            "POST",
            "/v1/analysis-batches/pilot-api/status",
            {
                "active": True,
                "reason": "stale",
                "expected_version": 1,
            },
        )
        assert status == 409
        assert stale["error"]["code"] == "version_conflict"


def test_direct_sandbox_does_not_replace_existing_governed_overview(
    tmp_path: Path,
) -> None:
    with _running_server(tmp_path / "dashboard-mode.db") as (
        server,
        host,
        port,
    ):
        server.repository.save_portfolio_batch(
            _request("governed-001"),
            _result("governed-001"),
            "test",
            context_obj={"kind": "governed_production_ingest"},
        )
        status, _ = _http(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            _request("direct-newer"),
        )
        assert status == 200

        status, overview = _http(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        assert overview["batch"]["batch_id"] == "governed-001"
        assert overview["batch_data_mode"] == "governed_trusted"
