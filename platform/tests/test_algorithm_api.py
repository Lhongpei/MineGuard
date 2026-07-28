from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mineguard.api import create_server


@contextmanager
def algorithm_server(
    tmp_path: Path,
) -> Iterator[tuple[Any, str, int]]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=True,
        auth_database_path=tmp_path / "auth.db",
        bootstrap_admin=("admin", "correct admin password"),
        secure_cookie=False,
        job_database_path=tmp_path / "jobs.db",
        evidence_database_path=tmp_path / "evidence.db",
        evidence_directory=tmp_path / "evidence",
        evidence_secret=b"test-evidence-secret-with-32-bytes!",
        governance_database_path=tmp_path / "governance.db",
        source_key_directory=tmp_path / "source-keys",
        backup_directory=tmp_path / "backups",
        backup_secret=b"test-backup-secret-with-32-bytes!!",
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


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: Any | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
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
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        return (
            response.status,
            json.loads(response.read()),
            response_headers,
        )
    finally:
        connection.close()


def login(
    host: str,
    port: int,
    username: str,
    password: str,
) -> tuple[str, str]:
    status, payload, headers = request(
        host,
        port,
        "POST",
        "/v1/auth/login",
        {"username": username, "password": password},
    )
    assert status == 200
    return (
        headers["set-cookie"].split(";", 1)[0],
        str(payload["csrf_token"]),
    )


def auth_headers(
    cookie: str,
    csrf: str | None = None,
) -> dict[str, str]:
    result = {"Cookie": cookie}
    if csrf is not None:
        result["X-CSRF-Token"] = csrf
    return result


def create_user(
    host: str,
    port: int,
    admin_cookie: str,
    admin_csrf: str,
    *,
    username: str,
    role: str,
    mine_scopes: list[str],
) -> None:
    status, _, _ = request(
        host,
        port,
        "POST",
        "/v1/admin/users",
        {
            "username": username,
            "password": f"{username} secure password",
            "role": role,
            "mine_scopes": mine_scopes,
        },
        headers=auth_headers(admin_cookie, admin_csrf),
    )
    assert status == 201


def temporal_request(
    mine_id: str = "M001",
) -> dict[str, Any]:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    values = [10.0, 10.2, 9.8, 10.1, 9.9, 25.0]
    return {
        "observations": [
            {
                "mine_id": mine_id,
                "source_id": "belt-1",
                "metric_code": "source.normalized_residual",
                "timestamp": (
                    start + timedelta(hours=index)
                ).isoformat(),
                "signed_residual": value,
            }
            for index, value in enumerate(values)
        ],
        "parameters": {
            "baseline_window": 20,
            "min_history": 5,
            "min_baseline_quality": 0.6,
            "minimum_scale": 0.000001,
            "mad_z_threshold": 4.0,
            "ewma_alpha": 0.25,
            "ewma_z_threshold": 3.0,
            "cusum_drift": 0.5,
            "cusum_threshold": 5.0,
            "page_hinkley_delta": 0.1,
            "page_hinkley_threshold": 8.0,
            "max_latency_seconds": 900.0,
            "max_revision_count": 1,
            "exclude_detected_anomalies_from_baseline": True,
            "episode_max_normal_points": 0,
            "episode_max_gap_seconds": None,
        },
    }


def persist_feature(
    server: Any,
    *,
    batch_id: str,
    mine_id: str,
    observed_at: datetime,
    value: float,
) -> None:
    request_payload = {
        "batch_id": batch_id,
        "portfolio_name": "时序接口测试",
        "expected_mine_ids": [mine_id],
        "analyses": [
            {
                "mine_id": mine_id,
                "window_start": (
                    observed_at - timedelta(hours=1)
                ).isoformat(),
                "window_end": observed_at.isoformat(),
                "observations": [],
            }
        ],
    }
    response_payload = {
        "items": [
            {
                "mine_id": mine_id,
                "technical_status": "consistent",
                "review_priority": "NONE",
                "summary": "test",
                "analysis": {
                    "mine_id": mine_id,
                    "status": "consistent",
                    "raw_anomaly_statistic": value,
                    "data_quality": {"score": 90.0},
                },
            }
        ]
    }
    server.repository.save_portfolio_batch(
        request_payload,
        response_payload,
        "test",
        context_obj={
            "kind": "governed_production_ingest",
            "profile_id": "test-profile",
            "profile_version": "1",
            "registry_snapshot_hash": "a" * 64,
            "observation_envelopes": [],
        },
    )


def test_temporal_direct_analysis_requires_admin_auth_and_csrf(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (_, host, port):
        status, payload, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/temporal",
            temporal_request(),
        )
        assert status == 401
        assert payload["error"]["code"] == "authentication_required"

        admin_cookie, admin_csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        status, payload, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/temporal",
            temporal_request(),
            headers=auth_headers(admin_cookie),
        )
        assert status == 403
        assert payload["error"]["code"] == "csrf_invalid"

        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="supervisor",
            role="supervisor",
            mine_scopes=["M001"],
        )
        supervisor_cookie, supervisor_csrf = login(
            host,
            port,
            "supervisor",
            "supervisor secure password",
        )
        status, payload, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/temporal",
            temporal_request(),
            headers=auth_headers(
                supervisor_cookie,
                supervisor_csrf,
            ),
        )
        assert status == 403
        assert payload["error"]["code"] == "trusted_ingest_required"

        status, payload, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/temporal",
            temporal_request(),
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert payload["series_count"] == 1
        assert payload["series"][0]["status"] == "anomalous"
        assert payload["series"][0]["episodes"]
        assert payload["series"][0]["source_health"]["point_count"] == 6
        final_point = payload["series"][0]["points"][-1]
        assert final_point["thresholds"]["rolling_upper"] is not None
        assert final_point["signals"]


def test_algorithm_endpoints_reject_subnormal_numeric_scales(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (_, host, port):
        cookie, csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        temporal_payload = temporal_request()
        temporal_payload["parameters"]["minimum_scale"] = 5e-324

        status, payload, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/temporal",
            temporal_payload,
            headers=auth_headers(cookie, csrf),
        )
        assert status == 400
        assert payload["error"]["code"] == "validation_error"

        aggregation_payload = {
            "measurement_type": "instantaneous_rate",
            "window_start": "2026-07-20T00:00:00Z",
            "window_end": "2026-07-20T01:00:00Z",
            "observations": [
                {
                    "observation_id": "boundary",
                    "value": 1.0,
                    "observed_at": "2026-07-20T00:00:00Z",
                }
            ],
            "expected_interval_seconds": 5e-324,
        }
        status, payload, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/aggregation",
            aggregation_payload,
            headers=auth_headers(cookie, csrf),
        )
        assert status == 400
        assert payload["error"]["code"] == "validation_error"


@pytest.mark.parametrize(
    "query",
    [
        "days=0",
        "days=366",
        "days=abc",
        "days=",
        "days=1.0",
        "days=30&days=31",
        "days=30&mine_id=M001",
    ],
)
def test_temporal_dashboard_rejects_invalid_day_windows(
    tmp_path: Path,
    query: str,
) -> None:
    with algorithm_server(tmp_path) as (_, host, port):
        cookie, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        status, payload, _ = request(
            host,
            port,
            "GET",
            f"/v1/dashboard/temporal?{query}",
            headers=auth_headers(cookie),
        )
        assert status == 400
        assert payload["error"]["code"] == "invalid_query"


def test_temporal_dashboard_cold_start_and_empty_history_are_structured(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (server, host, port):
        status, payload, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=30",
        )
        assert status == 401
        assert payload["error"]["code"] == "authentication_required"

        admin_cookie, admin_csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="coldviewer",
            role="viewer",
            mine_scopes=["M-COLD"],
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="emptyviewer",
            role="viewer",
            mine_scopes=["M-EMPTY"],
        )
        now = datetime.now(UTC)
        for index, value in enumerate([1.0, 1.1]):
            persist_feature(
                server,
                batch_id=f"cold-{index}",
                mine_id="M-COLD",
                observed_at=now - timedelta(hours=2 - index),
                value=value,
            )

        empty_cookie, _ = login(
            host,
            port,
            "emptyviewer",
            "emptyviewer secure password",
        )
        status, empty, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=30",
            headers=auth_headers(empty_cookie),
        )
        assert status == 200
        assert empty["status"] == "insufficient_history"
        assert empty["reason"] == "no_usable_history"
        assert empty["series"] == []
        assert empty["episodes"] == []
        assert empty["health"]["feature_row_count"] == 0
        assert empty["detector_thresholds"]["baseline"][
            "minimum_history"
        ] == 8

        cold_cookie, _ = login(
            host,
            port,
            "coldviewer",
            "coldviewer secure password",
        )
        status, cold, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=30",
            headers=auth_headers(cold_cookie),
        )
        assert status == 200
        assert cold["status"] == "insufficient_history"
        assert cold["reason"] == "cold_start"
        assert cold["series_count"] == 1
        assert cold["series"][0]["mine_id"] == "M-COLD"
        assert cold["series"][0]["insufficient_history"] is True
        assert cold["series"][0]["episodes"] == []
        assert cold["health"]["point_count"] == 2


def test_temporal_dashboard_excludes_direct_admin_sandbox_features(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (server, host, port):
        cookie, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        now = datetime.now(UTC)
        request_payload = {
            "batch_id": "direct-only",
            "portfolio_name": "管理员试算",
            "expected_mine_ids": ["M-DIRECT"],
            "analyses": [
                {
                    "mine_id": "M-DIRECT",
                    "window_start": (now - timedelta(hours=1)).isoformat(),
                    "window_end": now.isoformat(),
                    "observations": [],
                }
            ],
        }
        response_payload = {
            "items": [
                {
                    "mine_id": "M-DIRECT",
                    "technical_status": "consistent",
                    "review_priority": "NONE",
                    "summary": "sandbox",
                    "analysis": {
                        "mine_id": "M-DIRECT",
                        "status": "consistent",
                        "raw_anomaly_statistic": 999.0,
                        "data_quality": {"score": 99.0},
                    },
                }
            ]
        }
        server.repository.save_portfolio_batch(
            request_payload,
            response_payload,
            "test",
            context_obj={"kind": "direct_admin_sandbox"},
        )

        status, payload, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=7",
            headers=auth_headers(cookie),
        )

        assert status == 200
        assert payload["status"] == "insufficient_history"
        assert payload["reason"] == "no_usable_history"
        assert payload["health"]["rejected_feature_row_count"] >= 1
        assert payload["series"] == []


def test_temporal_dashboard_is_event_time_ordered_and_mine_scoped(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (server, host, port):
        admin_cookie, admin_csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="mineviewer",
            role="viewer",
            mine_scopes=["M001"],
        )
        now = datetime.now(UTC)
        visible_values = [
            10.0,
            10.2,
            9.8,
            10.1,
            9.9,
            10.0,
            10.1,
            9.9,
            30.0,
        ]
        hidden_values = [500.0] * len(visible_values)
        # Persist in reverse order to prove detector input follows event time,
        # rather than insertion/processing time.
        for index in reversed(range(len(visible_values))):
            observed_at = now - timedelta(
                hours=len(visible_values) - index
            )
            persist_feature(
                server,
                batch_id=f"visible-{index}",
                mine_id="M001",
                observed_at=observed_at,
                value=visible_values[index],
            )
            persist_feature(
                server,
                batch_id=f"hidden-{index}",
                mine_id="M002",
                observed_at=observed_at,
                value=hidden_values[index],
            )

        findings_before = server.repository.list_detector_findings()
        viewer_cookie, _ = login(
            host,
            port,
            "mineviewer",
            "mineviewer secure password",
        )
        status, payload, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=7",
            headers=auth_headers(viewer_cookie),
        )
        assert status == 200
        assert payload["status"] == "anomalous"
        assert payload["reason"] == "detector_signal"
        assert payload["series_count"] == 1
        assert payload["health"]["feature_row_count"] == 9
        assert payload["health"]["observation_count"] == 9
        assert {item["mine_id"] for item in payload["series"]} == {
            "M001"
        }
        assert payload["episodes"]
        assert {
            episode["mine_id"] for episode in payload["episodes"]
        } == {"M001"}
        series = payload["series"][0]
        timestamps = [
            datetime.fromisoformat(point["timestamp"])
            for point in series["points"]
        ]
        assert timestamps == sorted(timestamps)
        assert series["points"][-1]["observed_value"] == 30.0
        assert series["points"][-1]["thresholds"][
            "rolling_upper"
        ] is not None
        assert series["source_health"]["point_count"] == 9
        assert server.repository.list_detector_findings() == findings_before
        # Parsing the already-returned JSON again proves every nested enum,
        # datetime, threshold, episode and health value is serializable.
        json.loads(json.dumps(payload))

        status, admin_payload, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=7",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert {
            item["mine_id"] for item in admin_payload["series"]
        } == {"M001", "M002"}
        assert admin_payload["health"]["feature_row_count"] == 18


def test_temporal_dashboard_uses_warmup_but_reports_only_visible_window(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (server, host, port):
        cookie, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        now = datetime.now(UTC)
        for index in range(8):
            persist_feature(
                server,
                batch_id=f"warmup-{index}",
                mine_id="M-WARM",
                observed_at=now - timedelta(days=2, hours=8 - index),
                value=10.0 + index / 100,
            )
        for index in range(3):
            persist_feature(
                server,
                batch_id=f"visible-{index}",
                mine_id="M-WARM",
                observed_at=now - timedelta(hours=3 - index),
                value=10.05 + index / 100,
            )

        status, payload, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=1",
            headers=auth_headers(cookie),
        )

        assert status == 200
        assert payload["status"] == "normal"
        assert payload["health"]["warmup_feature_row_count"] == 8
        assert payload["health"]["point_count"] == 3
        series = next(
            item for item in payload["series"] if item["mine_id"] == "M-WARM"
        )
        assert len(series["points"]) == 3
        assert series["points"][0]["baseline_sample_count"] == 8
        assert series["points"][0]["insufficient_history"] is False


def test_temporal_dashboard_uses_receive_authority_not_batch_id_order(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (server, host, port):
        cookie, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        observed_at = datetime.now(UTC) - timedelta(hours=1)
        persist_feature(
            server,
            batch_id="Z-old",
            mine_id="M-REV",
            observed_at=observed_at,
            value=10.0,
        )
        persist_feature(
            server,
            batch_id="A-new",
            mine_id="M-REV",
            observed_at=observed_at,
            value=25.0,
        )

        status, payload, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/temporal?days=7",
            headers=auth_headers(cookie),
        )

        assert status == 200
        series = next(
            item for item in payload["series"] if item["mine_id"] == "M-REV"
        )
        assert len(series["points"]) == 1
        assert series["points"][0]["observed_value"] == 25.0


def test_temporal_dashboard_fails_closed_when_feature_query_is_truncated(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (server, host, port):
        cookie, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        original = server.repository.list_algorithm_features

        def overflow(**kwargs: Any) -> list[dict[str, Any]]:
            assert kwargs["feature_version"] == "2.1.0"
            assert kwargs["include_overflow_sentinel"] is True
            return [{}] * 100_001

        server.repository.list_algorithm_features = overflow
        try:
            status, payload, _ = request(
                host,
                port,
                "GET",
                "/v1/dashboard/temporal?days=7",
                headers=auth_headers(cookie),
            )
        finally:
            server.repository.list_algorithm_features = original

        assert status == 200
        assert payload["status"] == "insufficient_history"
        assert payload["reason"] == "data_truncated"
        assert payload["health"]["feature_limit_reached"] is True
        assert payload["series"] == []
        assert payload["episodes"] == []


@pytest.mark.parametrize("days", [1, 365])
def test_temporal_dashboard_accepts_day_boundaries(
    tmp_path: Path,
    days: int,
) -> None:
    with algorithm_server(tmp_path) as (_, host, port):
        cookie, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        status, payload, _ = request(
            host,
            port,
            "GET",
            f"/v1/dashboard/temporal?days={days}",
            headers=auth_headers(cookie),
        )
        assert status == 200
        assert payload["window"]["days"] == days
        assert payload["status"] == "insufficient_history"


def test_flow_and_measurement_aggregation_are_available_to_admins(
    tmp_path: Path,
) -> None:
    with algorithm_server(tmp_path) as (_, host, port):
        cookie, csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        flow_request = json.loads(
            (
                Path(__file__).parents[1]
                / "examples"
                / "flow_normal.json"
            ).read_text(encoding="utf-8")
        )
        status, flow, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/flow",
            flow_request,
            headers=auth_headers(cookie, csrf),
        )
        assert status == 200
        assert flow["status"] == "optimal"
        assert flow["quality_sufficient"] is True
        assert flow["edge_windows"]
        assert flow["inventory_trajectory"]

        aggregation_request = {
            "measurement_type": "interval_delta",
            "window_start": "2026-07-20T00:00:00Z",
            "window_end": "2026-07-21T00:00:00Z",
            "observations": [
                {
                    "observation_id": "first-half",
                    "value": 40.0,
                    "observed_at": "2026-07-20T12:00:00Z",
                    "interval_start": "2026-07-20T00:00:00Z",
                    "interval_end": "2026-07-20T12:00:00Z",
                },
                {
                    "observation_id": "second-half",
                    "value": 60.0,
                    "observed_at": "2026-07-21T00:00:00Z",
                    "interval_start": "2026-07-20T12:00:00Z",
                    "interval_end": "2026-07-21T00:00:00Z",
                },
            ],
            "min_coverage": 0.9,
            "expected_interval_seconds": 43200.0,
        }
        status, aggregation, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/aggregation",
            aggregation_request,
            headers=auth_headers(cookie, csrf),
        )
        assert status == 200
        assert aggregation["status"] == "sufficient"
        assert aggregation["aggregate_value"] == 100.0
        assert aggregation["coverage_ratio"] == 1.0
