from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import http.client
import json
from pathlib import Path
import threading
from typing import Any, Iterator
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

import pytest

from mineguard.api import create_server
from mineguard.auth import Role
from mineguard.periodic_reports import (
    build_periodic_regulatory_report,
    resolve_reporting_period,
)


def _analytics() -> dict[str, Any]:
    return {
        "window_start": "2026-07-01T00:00:00+08:00",
        "window_end": "2026-07-31T23:59:59+08:00",
        "expected_report_count": 2,
        "received_report_count": 1,
        "coverage_rate": 0.5,
        "mine_risk_ranking": [
            {
                "mine_id": "M001",
                "expected_reports": 2,
                "received_reports": 1,
                "coverage_rate": 0.5,
                "data_issue_reports": 1,
                "open_cases": 2,
                "open_p1_cases": 1,
                "open_p2_cases": 0,
                "pending_approval_cases": 1,
            }
        ],
        "case_performance": {
            "new_case_count": 2,
            "closed_case_count": 0,
            "open_backlog_count": 2,
            "pending_approval_count": 1,
        },
        "repeated_anomalies": [],
        "metric_definitions": {"报送覆盖率": "实收矿次除以应报矿次。"},
    }


def test_reporting_periods_are_fixed_and_reject_arbitrary_inputs() -> None:
    now = datetime(2026, 7, 28, 1, 0, tzinfo=UTC)
    month = resolve_reporting_period(
        "monthly",
        "2026-07",
        "Asia/Shanghai",
        now=now,
    )
    assert month.start_at.isoformat() == "2026-07-01T00:00:00+08:00"
    assert month.end_at.isoformat() == "2026-07-31T23:59:59.999999+08:00"
    assert month.data_end_at.isoformat() == "2026-07-28T09:00:00+08:00"
    assert month.complete is False

    quarter = resolve_reporting_period(
        "quarterly",
        "2026-Q2",
        "Asia/Shanghai",
        now=now,
    )
    assert quarter.start_at.isoformat() == "2026-04-01T00:00:00+08:00"
    assert quarter.end_at.isoformat() == "2026-06-30T23:59:59.999999+08:00"
    assert quarter.complete is True

    invalid = [
        ("custom", "2026-07", "Asia/Shanghai"),
        ("monthly", "2026-07-01/2026-07-31", "Asia/Shanghai"),
        ("monthly", "2026-13", "Asia/Shanghai"),
        ("quarterly", "2026-Q5", "Asia/Shanghai"),
        ("monthly", "2026-07", "../../etc/passwd"),
        ("monthly", "<script>", "Asia/Shanghai"),
        ("monthly", "2026-08", "Asia/Shanghai"),
    ]
    for kind, key, timezone in invalid:
        with pytest.raises(ValueError):
            resolve_reporting_period(
                kind,
                key,
                timezone,
                now=now,
            )


def test_report_never_turns_missing_or_blocked_data_into_normal() -> None:
    now = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)
    period = resolve_reporting_period(
        "monthly",
        "2026-07",
        "Asia/Shanghai",
        now=now,
    )
    alerts = [
        {
            "alert_id": "alert-operational",
            "mine_id": "M001",
            "detected_at": "2026-07-20T08:00:00+08:00",
            "last_seen_at": "2026-07-20T09:00:00+08:00",
            "operational": True,
            "level": "orange",
            "status": "open",
            "title": "需要复核",
        },
        {
            "alert_id": "alert-shadow",
            "mine_id": "M001",
            "detected_at": "2026-07-20T08:00:00+08:00",
            "last_seen_at": "2026-07-20T09:00:00+08:00",
            "operational": False,
            "level": "red",
            "status": "open",
            "title": "影子试算",
        },
    ]
    runs = [
        {
            "run_id": "run-m001",
            "mine_id": "M001",
            "window_end": "2026-07-20T23:59:00+08:00",
            "created_at": "2026-07-21T00:01:00+08:00",
            "status": "insufficient_history",
            "overall_clue_level": 0,
            "result": {"technical_clues": []},
        },
        {
            "run_id": "run-m002",
            "mine_id": "M002",
            "window_end": "2026-07-21T23:59:00+08:00",
            "created_at": "2026-07-22T00:01:00+08:00",
            "status": "blocked",
            "overall_clue_level": 0,
            "result": {"technical_clues": []},
        },
    ]
    report = build_periodic_regulatory_report(
        period=period,
        mine_ids={"M001", "M002"},
        analytics=_analytics(),
        alerts=alerts,
        verification_runs=runs,
        mine_catalog=[
            {"mine_id": "M001", "mine_name": "<img src=x onerror=alert(1)>"},
            {"mine_id": "M002", "mine_name": "测试二矿"},
        ],
        safety_dashboard={
            "generated_at": now.isoformat(),
            "summary": {"total_open": 1},
            "shadow_summary": {"total_open": 1},
        },
        generated_at=now,
        governed_mode=True,
    )

    assert report["data_quality"]["status"] == "blocked"
    assert report["summary"]["reporting"]["missing_report"] == 1
    assert report["summary"]["reporting"]["no_report_records"] == 1
    assert report["summary"]["verification"]["insufficient_history"] == 1
    assert report["summary"]["verification"]["blocked"] == 1
    assert report["summary"]["safety_alerts"]["operational_total"] == 1
    assert report["summary"]["safety_alerts"]["shadow_total"] == 1
    assert report["summary"]["safety_alerts"]["red"] == 0
    by_mine = {item["mine_id"]: item for item in report["mines"]}
    assert by_mine["M001"]["reporting"]["status"] == "missing_report"
    assert by_mine["M001"]["verification"]["status"] == (
        "insufficient_history"
    )
    assert by_mine["M002"]["reporting"]["status"] == "no_report_records"
    assert by_mine["M002"]["verification"]["status"] == "blocked"
    assert by_mine["M002"]["overall_status"] == "blocked"
    assert by_mine["M001"]["mine_name"].startswith("<img")
    assert "不是安全、违法、责任或处罚认定" in report["disclaimer"]
    assert report["delivery"]["automatically_sent"] is False

    repeated = build_periodic_regulatory_report(
        period=period,
        mine_ids={"M001", "M002"},
        analytics=_analytics(),
        alerts=alerts,
        verification_runs=runs,
        mine_catalog=[],
        safety_dashboard={},
        generated_at=datetime(2026, 8, 3, tzinfo=UTC),
        governed_mode=True,
    )
    assert repeated["report_reference"] == report["report_reference"]


def _request(
    server: Any,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    host, port = server.server_address[:2]
    connection = http.client.HTTPConnection(host, port, timeout=5)
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = dict(headers or {})
    if encoded is not None:
        request_headers["Content-Type"] = "application/json"
    try:
        connection.request(
            method,
            path,
            body=encoded,
            headers=request_headers,
        )
        response = connection.getresponse()
        raw = response.read()
        return (
            response.status,
            json.loads(raw) if raw else {},
            {
                name.lower(): value
                for name, value in response.getheaders()
            },
        )
    finally:
        connection.close()


@contextmanager
def _server(tmp_path: Path) -> Iterator[Any]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=True,
        auth_database_path=tmp_path / "auth.db",
        bootstrap_admin=("admin", "correct admin password"),
        job_database_path=tmp_path / "jobs.db",
    )
    for mine_id in ("M001", "M002"):
        server.edge_repository.upsert_mine(
            {
                "mine_id": mine_id,
                "mine_name": f"测试矿井 {mine_id}",
                "gas_category": "high_gas",
                "approved_underground_personnel": 100,
            },
            actor_id="test",
        )
    server.auth_store.create_user(
        "viewer-m001",
        "scoped viewer password",
        Role.VIEWER,
        ["M001"],
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _login(server: Any) -> str:
    status, _, headers = _request(
        server,
        "POST",
        "/v1/auth/login",
        body={
            "username": "viewer-m001",
            "password": "scoped viewer password",
        },
    )
    assert status == 200
    return headers["set-cookie"].split(";", 1)[0]


def test_report_api_is_authenticated_scoped_strict_and_read_only(
    tmp_path: Path,
) -> None:
    with _server(tmp_path) as server:
        local_now = datetime.now(ZoneInfo("Asia/Shanghai"))
        period_key = local_now.strftime("%Y-%m")
        query = urlencode(
            {
                "kind": "monthly",
                "period": period_key,
                "timezone": "Asia/Shanghai",
            }
        )
        path = f"/v1/reports/regulatory?{query}"
        status, unauthenticated, _ = _request(server, "GET", path)
        assert status == 401
        assert unauthenticated["error"]["code"] == "authentication_required"

        cookie = _login(server)
        status, payload, headers = _request(
            server,
            "GET",
            path,
            headers={"Cookie": cookie},
        )
        assert status == 200
        report = payload["report"]
        assert report["scope"]["mine_ids"] == ["M001"]
        assert report["summary"]["reporting"]["no_report_records"] == 1
        assert report["summary"]["verification"]["not_run"] == 1
        assert report["data_quality"]["status"] == "blocked"
        assert "M002" not in json.dumps(payload)
        assert headers["cache-control"] == "no-store"

        bad_queries = [
            "",
            f"kind=monthly&period={period_key}",
            (
                f"kind=monthly&period={period_key}"
                "&timezone=Asia%2FShanghai&extra=1"
            ),
            (
                f"kind=monthly&kind=quarterly&period={period_key}"
                "&timezone=Asia%2FShanghai"
            ),
            (
                f"kind=monthly&period={period_key}"
                "&timezone=..%2F..%2Fetc%2Fpasswd"
            ),
        ]
        for bad_query in bad_queries:
            suffix = f"?{bad_query}" if bad_query else ""
            status, bad, _ = _request(
                server,
                "GET",
                f"/v1/reports/regulatory{suffix}",
                headers={"Cookie": cookie},
            )
            assert status == 400
            assert bad["error"]["code"] == "invalid_query"

        status, _, method_headers = _request(
            server,
            "POST",
            "/v1/reports/regulatory",
            body={},
            headers={"Cookie": cookie},
        )
        assert status == 405
        assert method_headers["allow"] == "GET"
