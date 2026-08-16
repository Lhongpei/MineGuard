from __future__ import annotations

import copy
import http.client
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

import mineguard.api as api_module
from mineguard.api import create_server


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def running_server(database_path: Path) -> Iterator[tuple[str, int]]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=str(database_path),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: Any | None = None,
) -> tuple[int, dict[str, Any]]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    headers = (
        {}
        if encoded is None
        else {"Content-Type": "application/json; charset=utf-8"}
    )
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        raw_body = response.read()
        payload = json.loads(raw_body) if raw_body else {}
        return response.status, payload
    finally:
        connection.close()


def production_analysis(name: str, mine_id: str) -> dict[str, Any]:
    payload = json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))
    payload["mine_id"] = mine_id
    return payload


def batch_request(batch_id: str = "batch-20260726") -> dict[str, Any]:
    return {
        "batch_id": batch_id,
        "portfolio_name": "北部试点辖区",
        "expected_mine_ids": ["M001", "M002"],
        "analyses": [
            production_analysis("production_inconsistent.json", "M001"),
            production_analysis("production_consistent.json", "M002"),
        ],
    }


def post_batch(
    host: str,
    port: int,
    body: dict[str, Any],
) -> dict[str, Any]:
    status, payload = request(
        host,
        port,
        "POST",
        "/v1/analyze/production/batch",
        body,
    )
    assert status == 200
    assert payload["batch_id"] == body["batch_id"]
    assert payload["portfolio_name"] == body["portfolio_name"]
    return payload


def find_item(
    batch: dict[str, Any],
    mine_id: str,
) -> dict[str, Any]:
    return next(
        item for item in batch["items"] if item["mine_id"] == mine_id
    )


def get_case_detail(
    host: str,
    port: int,
    case_id: str,
) -> dict[str, Any]:
    status, payload = request(
        host,
        port,
        "GET",
        f"/v1/cases/{case_id}",
    )
    assert status == 200
    assert set(payload) >= {"case", "events", "audit_chain_valid"}
    assert payload["case"]["case_id"] == case_id
    assert payload["audit_chain_valid"] is True
    assert payload["integrity_valid"] is True
    return payload


def get_run_id(
    dashboard_item: dict[str, Any],
    case: dict[str, Any],
) -> str:
    run_id = (
        dashboard_item.get("analysis_run_id")
        or case.get("analysis_run_id")
    )
    assert isinstance(run_id, str)
    assert run_id
    return run_id


def assert_digest(value: Any) -> None:
    assert isinstance(value, str)
    assert len(value) >= 32
    assert value.strip() == value


def test_batch_is_idempotent_and_rejects_payload_conflicts(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "idempotency.sqlite3"
    body = batch_request()

    with running_server(database_path) as (host, port):
        first = post_batch(host, port, body)
        second = post_batch(host, port, body)

        assert first["technical_status_counts"] == (
            second["technical_status_counts"]
        )
        assert first["review_priority_counts"] == (
            second["review_priority_counts"]
        )

        status, cases = request(host, port, "GET", "/v1/cases")
        assert status == 200
        assert set(cases) >= {"items", "total"}
        assert cases["total"] == 1
        assert len(cases["items"]) == 1
        assert len(
            {item["case_id"] for item in cases["items"]}
        ) == 1

        conflicting = copy.deepcopy(body)
        conflicting["portfolio_name"] = "同一ID但不同内容"
        status, conflict = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            conflicting,
        )
        assert status == 409
        assert "error" in conflict

        status, cases_after_conflict = request(
            host,
            port,
            "GET",
            "/v1/cases",
        )
        assert status == 200
        assert cases_after_conflict["total"] == 1


def test_batch_preview_is_compute_only_and_query_is_strict(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "preview.sqlite3"
    body = batch_request(batch_id="pilot-preview")

    with running_server(database_path) as (host, port):
        status, preview = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch?preview=1",
            body,
        )
        assert status == 200
        assert preview["batch_id"] == body["batch_id"]
        assert preview["portfolio_name"] == body["portfolio_name"]
        assert "batch" not in preview
        assert "temporal_audit" not in preview

        for query in (
            "preview=0",
            "preview=",
            "preview=1&preview=1",
            "preview=1&unknown=1",
            "unknown=1",
        ):
            status, payload = request(
                host,
                port,
                "POST",
                f"/v1/analyze/production/batch?{query}",
                body,
            )
            assert status == 400
            assert payload["error"]["code"] == "invalid_query"

        status, overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        assert overview["batch"] is None

    with sqlite3.connect(database_path) as connection:
        counts = {
            table: connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("batches", "cases", "analysis_feature_windows")
        }
    assert counts == {
        "batches": 0,
        "cases": 0,
        "analysis_feature_windows": 0,
    }


def test_idempotent_batch_retries_failed_temporal_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = api_module.refresh_temporal_audit
    calls: list[set[str] | None] = []

    def fail_once(
        repository: Any,
        *,
        mine_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        calls.append(None if mine_ids is None else set(mine_ids))
        if len(calls) == 1:
            raise RuntimeError("simulated temporal refresh failure")
        return original(repository, mine_ids=mine_ids)

    monkeypatch.setattr(
        api_module,
        "refresh_temporal_audit",
        fail_once,
    )
    database_path = tmp_path / "retry-temporal.sqlite3"
    body = batch_request(batch_id="retry-temporal-batch")
    body["expected_mine_ids"].append("M003")

    with running_server(database_path) as (host, port):
        first = post_batch(host, port, body)
        second = post_batch(host, port, body)

    assert first["temporal_audit"]["status"] == "refresh_failed"
    assert second["temporal_audit"]["status"] != "refresh_failed"
    assert calls == [
        {"M001", "M002"},
        {"M001", "M002"},
    ]


def test_dashboard_case_detail_and_case_actions(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "case-actions.sqlite3"

    with running_server(database_path) as (host, port):
        post_batch(host, port, batch_request())

        status, overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        assert set(overview) >= {
            "batch",
            "open_case_count",
            "local_trial",
        }
        assert overview["local_trial"] is True
        assert overview["open_case_count"] == 1
        assert overview["batch"]["batch_id"] == "batch-20260726"

        pending_item = find_item(overview["batch"], "M001")
        assert pending_item["review_priority"] == "P1"
        assert isinstance(pending_item["case_id"], str)
        assert pending_item["case_id"]
        assert isinstance(pending_item["workflow_status"], str)
        assert pending_item["workflow_status"]
        case_id = pending_item["case_id"]

        status, case_list = request(host, port, "GET", "/v1/cases")
        assert status == 200
        assert set(case_list) >= {"items", "total"}
        assert case_list["total"] == 1
        assert case_list["items"][0]["case_id"] == case_id

        initial = get_case_detail(host, port, case_id)
        assert initial["events"]
        initial_case = initial["case"]
        initial_version = initial_case["version"]
        assert isinstance(initial_version, int)
        assert initial_version >= 1

        status, _ = request(
            host,
            port,
            "POST",
            f"/v1/cases/{case_id}/actions",
            {
                "action": "start_review",
                "expected_version": initial_version,
            },
        )
        assert status == 200

        reviewing = get_case_detail(host, port, case_id)
        reviewing_case = reviewing["case"]
        reviewing_version = reviewing_case["version"]
        assert reviewing_version > initial_version
        assert (
            reviewing_case["workflow_status"]
            != initial_case["workflow_status"]
        )

        for incomplete_close in (
            {
                "action": "close",
                "expected_version": reviewing_version,
                "disposition": "confirmed",
            },
            {
                "action": "close",
                "expected_version": reviewing_version,
                "note": "已完成原始记录复核",
            },
        ):
            status, _ = request(
                host,
                port,
                "POST",
                f"/v1/cases/{case_id}/actions",
                incomplete_close,
            )
            assert status in {400, 409}

        unchanged = get_case_detail(host, port, case_id)
        assert unchanged["case"]["version"] == reviewing_version

        status, _ = request(
            host,
            port,
            "POST",
            f"/v1/cases/{case_id}/actions",
            {
                "action": "close",
                "expected_version": initial_version,
                "note": "使用过期版本提交",
                "disposition": "confirmed",
            },
        )
        assert status == 409

        status, _ = request(
            host,
            port,
            "POST",
            f"/v1/cases/{case_id}/actions",
            {
                "action": "close",
                "expected_version": reviewing_version,
                "note": "现场原始记录已核查并完成处置",
                "disposition": "confirmed",
            },
        )
        assert status == 200

        closed = get_case_detail(host, port, case_id)
        assert closed["case"]["workflow_status"] == "closed"
        assert closed["case"]["version"] > reviewing_version
        assert len(closed["events"]) >= 3

        status, closed_overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        assert closed_overview["open_case_count"] == 0
        closed_item = find_item(closed_overview["batch"], "M001")
        assert closed_item["case_id"] == case_id
        assert closed_item["workflow_status"] == "closed"


def test_analysis_run_exposes_reproducibility_hashes(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "analysis-run.sqlite3"

    with running_server(database_path) as (host, port):
        post_batch(host, port, batch_request())

        status, overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        pending_item = find_item(overview["batch"], "M001")
        case_detail = get_case_detail(
            host,
            port,
            pending_item["case_id"],
        )
        run_id = get_run_id(pending_item, case_detail["case"])

        status, payload = request(
            host,
            port,
            "GET",
            f"/v1/analysis-runs/{run_id}",
        )
        assert status == 200
        run = payload.get("run", payload)
        assert run["analysis_run_id"] == run_id
        assert_digest(run["snapshot_hash"])
        assert_digest(run["result_hash"])
        assert run["snapshot_hash"] != run["result_hash"]
        assert run["snapshot_hash_valid"] is True
        assert run["result_hash_valid"] is True
        assert isinstance(run["engine_version"], str)
        assert run["engine_version"]


def test_reference_labels_are_append_only_and_scenarios_are_versioned(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "historical-knowledge.sqlite3"

    with running_server(database_path) as (host, port):
        post_batch(host, port, batch_request(batch_id="history-api"))
        status, overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        item = find_item(overview["batch"], "M001")
        detail = get_case_detail(host, port, item["case_id"])
        run_id = get_run_id(item, detail["case"])
        label_path = f"/v1/analysis-runs/{run_id}/reference-labels"

        status, labels = request(host, port, "GET", label_path)
        assert status == 200
        assert labels["current"] is None
        assert labels["history"] == []
        assert labels["chain_valid"] is None

        status, labelled = request(
            host,
            port,
            "POST",
            label_path,
            {
                "label": "verified_normal",
                "expected_sequence": 0,
                "note": "已核对原始台账、设备记录和现场材料。",
            },
        )
        assert status == 201
        assert labelled["current"]["label"] == "verified_normal"
        assert labelled["current"]["sequence"] == 1
        assert labelled["current"]["reference_eligible"] is True
        assert labelled["chain_valid"] is True

        status, stale = request(
            host,
            port,
            "POST",
            label_path,
            {
                "label": "unresolved",
                "expected_sequence": 0,
                    "note": "故意使用过期序号提交并验证冲突。",
            },
        )
        assert status == 409
        assert stale["error"]["code"] == "version_conflict"

        scenario = {
            "scenario": {
                "scenario_id": "approved-maintenance",
                "version": 1,
                "name": "经批准的检修窗口",
                "description": "只解释对应工况下的历史偏离，不覆盖物理冲突。",
                "mine_ids": ["M001"],
                "regime": "maintenance",
                "shift": None,
                "season": None,
                "maintenance": True,
                "required_event_codes": ["WORK-ORDER-APPROVED"],
                "required_tags": [],
                "feature_bounds": {
                    "raw_anomaly": {"lower": 0.0, "upper": 100.0}
                },
                "active": True,
            }
        }
        status, created = request(
            host,
            port,
            "POST",
            "/v1/admin/legitimate-scenarios",
            scenario,
        )
        assert status == 201
        assert created["scenario"]["created"] is True
        assert created["scenario"]["hash_valid"] is True

        status, listed = request(
            host,
            port,
            "GET",
            "/v1/admin/legitimate-scenarios",
        )
        assert status == 200
        assert listed["items"][0]["scenario_id"] == (
            "approved-maintenance"
        )
        assert "不可删除" in listed["immutability_notice"]

        changed = json.loads(json.dumps(scenario))
        changed["scenario"]["description"] = "同版本不同内容"
        status, conflict = request(
            host,
            port,
            "POST",
            "/v1/admin/legitimate-scenarios",
            changed,
        )
        assert status == 409
        assert conflict["error"]["code"] == (
            "legitimate_scenario_conflict"
        )


def test_sqlite_state_survives_server_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "persistent-workflow.sqlite3"
    body = batch_request(batch_id="restart-batch")

    with running_server(database_path) as (host, port):
        post_batch(host, port, body)
        status, first_overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        first_item = find_item(first_overview["batch"], "M001")
        case_id = first_item["case_id"]
        case_detail = get_case_detail(host, port, case_id)
        run_id = get_run_id(first_item, case_detail["case"])

    assert database_path.is_file()
    assert database_path.stat().st_size > 0

    with running_server(database_path) as (host, port):
        status, restored_overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 200
        assert restored_overview["batch"]["batch_id"] == "restart-batch"
        assert restored_overview["open_case_count"] == 1
        restored_item = find_item(
            restored_overview["batch"],
            "M001",
        )
        assert restored_item["case_id"] == case_id

        status, restored_cases = request(
            host,
            port,
            "GET",
            "/v1/cases",
        )
        assert status == 200
        assert restored_cases["total"] == 1
        assert restored_cases["items"][0]["case_id"] == case_id

        restored_detail = get_case_detail(host, port, case_id)
        assert restored_detail["events"]
        assert restored_detail["audit_chain_valid"] is True

        status, run_payload = request(
            host,
            port,
            "GET",
            f"/v1/analysis-runs/{run_id}",
        )
        assert status == 200
        restored_run = run_payload.get("run", run_payload)
        assert restored_run["analysis_run_id"] == run_id
        assert_digest(restored_run["snapshot_hash"])
        assert_digest(restored_run["result_hash"])


def test_overview_keeps_open_cases_from_earlier_batches(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "cross-batch-open-cases.sqlite3"

    with running_server(database_path) as (host, port):
        post_batch(host, port, batch_request(batch_id="batch-with-case"))
        newest = {
            "batch_id": "newest-all-consistent",
            "portfolio_name": "北部试点辖区",
            "expected_mine_ids": ["M003"],
            "analyses": [
                production_analysis(
                    "production_consistent.json",
                    "M003",
                )
            ],
        }
        post_batch(host, port, newest)

        status, overview = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )

    assert status == 200
    assert overview["batch"]["batch_id"] == "newest-all-consistent"
    assert overview["current_batch_open_case_count"] == 0
    assert overview["open_case_count"] == 1
