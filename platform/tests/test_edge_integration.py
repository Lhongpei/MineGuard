from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import http.client
import json
import sqlite3
import threading
from typing import Any, Iterator
from pathlib import Path

import pytest

import mineguard.api as api_module
from mineguard.api import create_server
from mineguard.edge_ingest import (
    EdgeAuthenticationError,
    EdgeClient,
    EdgeTelemetryBatch,
    authenticate_edge_request,
    sign_transport_headers,
    transport_signature,
)
from mineguard.edge_store import (
    AlertVersionConflictError,
    EdgeBatchConflictError,
    EdgeTelemetryRepository,
    SafetyRuleConflictError,
)
from mineguard.safety import DEFAULT_RULE_SNAPSHOT
from mineguard.safety_service import evaluate_edge_batch_safety


SECRET = b"edge-test-secret-with-at-least-32-bytes!!"
CLIENT = EdgeClient(
    client_id="mine-edge-M001",
    secret=SECRET,
    mine_ids=frozenset({"M001"}),
)


def _now_text() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _batch_identifier(label: str) -> str:
    suffix = hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]
    return f"{CLIENT.client_id}--batch_{suffix}"


def _interval(
    *,
    aggregation: str = "snapshot",
) -> dict[str, Any]:
    # The batch helper records received_at first; keep the window safely before it.
    end = datetime.now(UTC) - timedelta(seconds=1)
    return {
        "start": (end - timedelta(minutes=5)).isoformat(),
        "end": end.isoformat(),
        "timezone": "Asia/Shanghai",
        "aggregation": aggregation,
        "shift_code": "day-A",
    }


def _batch(*, batch_id: str = "edge-M001-000001") -> dict[str, Any]:
    batch_id = _batch_identifier(batch_id)
    now = _now_text()
    return {
        "schema_version": "edge-telemetry-batch-v1",
        "batch_id": batch_id,
        "client_id": CLIENT.client_id,
        "mine_id": "M001",
        "sent_at": now,
        "sequence_start": 1,
        "sequence_end": 1,
        "rule_profile": {
            "profile_id": "qinyuan-safety-default",
            "version": 1,
            "sha256": "a" * 64,
        },
        "observations": [
            {
                "source_id": "personnel-total",
                "observation_id": f"{batch_id}-personnel",
                "metric_code": "personnel.underground_count",
                "value": 100,
                "unit": "person",
                "location_code": "underground-total",
                "observed_at": now,
                "received_at": now,
                "sequence_no": 1,
                "revision": 0,
                "acquisition_mode": "api_poll",
                "source_record_id": f"personnel:{batch_id}",
                "source_record_sha256": "b" * 64,
                "source_signature": None,
                "status_code": "online",
                "quality": {
                    "valid": True,
                    "completeness": 1.0,
                    "timeliness": 1.0,
                    "device_health": "healthy",
                    "clock_synchronized": True,
                    "flags": [],
                },
                "manual_attestation": None,
            }
        ],
        "local_alerts": [],
    }


def _body(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


@contextmanager
def _server() -> Iterator[Any]:
    server = create_server(
        "127.0.0.1",
        0,
        edge_clients={CLIENT.client_id: CLIENT},
    )
    server.edge_repository.upsert_mine(
        {
            "mine_id": "M001",
            "mine_name": "测试一矿",
            "gas_category": "high_gas",
            "approved_underground_personnel": 100,
        },
        actor_id="test",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(
    server: Any,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address[:2]
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.request(
            method,
            path,
            body=body,
            headers=headers or {},
        )
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def test_edge_wire_model_rejects_manual_without_attestation() -> None:
    document = _batch()
    observation = document["observations"][0]
    observation["acquisition_mode"] = "authenticated_manual_entry"
    with pytest.raises(ValueError, match="manual_attestation"):
        EdgeTelemetryBatch.model_validate(document)


@pytest.mark.parametrize(
    ("metric_code", "value", "unit"),
    [
        ("production.belt_instantaneous_t_h", 120.5, "t/h"),
        ("production.belt_speed_m_s", 2.6, "m/s"),
        ("production.belt_scale_running", 1, "count"),
        ("production.belt_scale_fault", 0, "count"),
        ("personnel.area_count", 36, "person"),
        ("personnel.no_card_entry_count", 2, "count"),
        ("personnel.person_card_mismatch_count", 1, "count"),
        ("personnel.overtime_count", 3, "count"),
    ],
)
def test_edge_wire_accepts_detailed_non_pii_metrics(
    metric_code: str,
    value: float,
    unit: str,
) -> None:
    document = _batch(batch_id=metric_code)
    observation = document["observations"][0]
    observation.update(
        {
            "metric_code": metric_code,
            "value": value,
            "unit": unit,
            "location_code": "area-or-device-1",
            "interval": _interval(
                aggregation=(
                    "instantaneous_rate"
                    if metric_code
                    == "production.belt_instantaneous_t_h"
                    else "snapshot"
                )
            ),
        }
    )
    parsed = EdgeTelemetryBatch.model_validate(document)
    assert parsed.observations[0].metric_code == metric_code
    assert parsed.observations[0].interval is not None


@pytest.mark.parametrize(
    ("metric_code", "value", "unit"),
    [
        ("source.heartbeat_age_seconds", 75.5, "s"),
        ("source.consecutive_failures", 3, "count"),
        ("source.missing_state", 1, "count"),
    ],
)
def test_edge_wire_accepts_non_business_source_health(
    metric_code: str,
    value: float,
    unit: str,
) -> None:
    document = _batch(batch_id=metric_code)
    observation = document["observations"][0]
    observation.update(
        {
            "source_id": "personnel-gateway",
            "metric_code": metric_code,
            "value": value,
            "unit": unit,
            "location_code": "personnel-gateway",
        }
    )
    parsed = EdgeTelemetryBatch.model_validate(document)
    assert parsed.observations[0].metric_code == metric_code


@pytest.mark.parametrize(
    ("metric_code", "value", "unit", "location_code"),
    [
        ("source.heartbeat_age_seconds", 1, "count", "personnel-total"),
        ("source.consecutive_failures", 1.5, "count", "personnel-total"),
        ("source.missing_state", 2, "count", "personnel-total"),
        ("source.missing_state", 1, "count", "other-source"),
    ],
)
def test_edge_wire_rejects_invalid_source_health(
    metric_code: str,
    value: float,
    unit: str,
    location_code: str,
) -> None:
    document = _batch(batch_id=f"invalid-{metric_code}-{value}")
    observation = document["observations"][0]
    observation.update(
        {
            "metric_code": metric_code,
            "value": value,
            "unit": unit,
            "location_code": location_code,
        }
    )
    with pytest.raises(ValueError):
        EdgeTelemetryBatch.model_validate(document)


@pytest.mark.parametrize(
    "interval",
    [
        {
            "start": "2026-07-28T00:05:00Z",
            "end": "2026-07-28T00:00:00Z",
            "timezone": "UTC",
            "aggregation": "snapshot",
        },
        {
            "start": "2026-07-28T00:00:00Z",
            "end": "2026-07-28T00:05:00Z",
            "timezone": "Mars/Olympus",
            "aggregation": "snapshot",
        },
        {
            "start": "2026-07-28T00:00:00Z",
            "end": "2026-07-28T00:05:00Z",
            "timezone": "UTC",
            "aggregation": "snapshot",
            "person_id": "forbidden-pii",
        },
    ],
)
def test_edge_wire_rejects_invalid_or_pii_interval_fields(
    interval: dict[str, Any],
) -> None:
    document = _batch()
    document["observations"][0]["interval"] = interval
    with pytest.raises(ValueError, match="interval|Extra inputs"):
        EdgeTelemetryBatch.model_validate(document)


@pytest.mark.parametrize(
    ("metric_code", "value", "unit"),
    [
        ("production.belt_instantaneous_t_h", 1, "t"),
        ("production.belt_scale_running", 2, "count"),
        ("personnel.no_card_entry_count", 1.5, "count"),
        ("detonator.used_count", 1, "kg"),
    ],
)
def test_edge_wire_rejects_detailed_metric_unit_or_value_mismatch(
    metric_code: str,
    value: float,
    unit: str,
) -> None:
    document = _batch()
    document["observations"][0].update(
        {
            "metric_code": metric_code,
            "value": value,
            "unit": unit,
        }
    )
    with pytest.raises(ValueError):
        EdgeTelemetryBatch.model_validate(document)


@pytest.mark.parametrize(
    "batch_id",
    [
        "edge-M001-legacy-000001",
        "another-client--batch_" + "a" * 32,
        CLIENT.client_id + "--batch_" + "A" * 32,
        CLIENT.client_id + "--batch_" + "a" * 31,
    ],
)
def test_edge_wire_model_rejects_unscoped_or_unstable_batch_id(
    batch_id: str,
) -> None:
    document = _batch()
    document["batch_id"] = batch_id
    with pytest.raises(ValueError, match="batch_id"):
        EdgeTelemetryBatch.model_validate(document)


def test_legacy_batch_id_is_only_available_for_stored_audit_replay() -> None:
    document = _batch()
    document["batch_id"] = "edge-M001-legacy-000001"
    batch = EdgeTelemetryBatch.model_validate(
        document,
        context={"allow_legacy_batch_id": True},
    )
    assert batch.batch_id == "edge-M001-legacy-000001"


def test_stored_legacy_batch_remains_recalculable_after_intake_hardening() -> None:
    document = _batch()
    legacy_batch_id = "batch_" + "c" * 32
    document["batch_id"] = legacy_batch_id
    raw = _body(document)
    batch = EdgeTelemetryBatch.model_validate(
        document,
        context={"allow_legacy_batch_id": True},
    )
    with _server() as server:
        server.edge_repository.ingest_batch(
            batch,
            body_sha256=hashlib.sha256(raw).hexdigest(),
            raw_body=raw,
        )
        status, result = _request(
            server,
            "POST",
            f"/v1/edge-telemetry-batches/{legacy_batch_id}/recalculate",
        )
        receipt = server.edge_repository.get_receipt(legacy_batch_id)
    assert status == 200
    assert result["mine_id"] == "M001"
    assert receipt is not None
    assert receipt["batch_id"] == legacy_batch_id


def test_edge_hmac_authenticates_raw_body_and_detects_tampering() -> None:
    body = _body(_batch())
    headers = sign_transport_headers(CLIENT, body)
    client, _, nonce, digest = authenticate_edge_request(
        {CLIENT.client_id: CLIENT},
        headers,
        body,
        method="POST",
        path="/v1/edge-telemetry-batches",
    )
    assert client.client_id == CLIENT.client_id
    assert nonce
    assert digest == hashlib.sha256(body).hexdigest()
    with pytest.raises(EdgeAuthenticationError):
        authenticate_edge_request(
            {CLIENT.client_id: CLIENT},
            headers,
            body + b" ",
            method="POST",
            path="/v1/edge-telemetry-batches",
        )


def test_edge_hmac_matches_neutral_contract_fixed_vector() -> None:
    signature = transport_signature(
        b"example-edge-transport-secret-not-for-production",
        method="POST",
        path="/v1/edge-telemetry-batches",
        client_id="mine-edge-M001",
        timestamp="2026-07-28T10:15:03Z",
        nonce="AAECAwQFBgcICQoLDA0ODw",
        contract_version="edge-telemetry-batch-v1",
        content_sha256=(
            "f289284d73836288cae3191eeac928b62d78c8988418e1016e4f956c08af2aab"
        ),
    )
    assert signature == (
        "8d56b417514d8f78c9d0e5c431880aa5eb5df49b15cbaea1ec59efe1ac0b6001"
    )


def test_authenticated_intake_rejects_cross_client_batch_namespace() -> None:
    document = _batch()
    document["batch_id"] = "another-client--batch_" + "a" * 32
    body = _body(document)
    headers = {
        **sign_transport_headers(CLIENT, body),
        "Content-Type": "application/json",
    }
    with _server() as server:
        status, error = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers=headers,
        )
        stored = server.edge_repository.get_receipt(document["batch_id"])
    assert status == 422
    assert error["code"] == "VALIDATION_FAILED"
    assert stored is None


def test_authenticated_client_id_must_match_namespaced_body_client() -> None:
    document = _batch()
    document["client_id"] = "another-client"
    document["batch_id"] = "another-client--batch_" + "b" * 32
    body = _body(document)
    headers = {
        **sign_transport_headers(CLIENT, body),
        "Content-Type": "application/json",
    }
    with _server() as server:
        status, error = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers=headers,
        )
        stored = server.edge_repository.get_receipt(document["batch_id"])
    assert status == 403
    assert error["code"] == "CLIENT_SCOPE_DENIED"
    assert stored is None


def test_store_is_idempotent_and_conflicting_batch_fails() -> None:
    repository = EdgeTelemetryRepository()
    try:
        document = _batch()
        batch = EdgeTelemetryBatch.model_validate(document)
        body = _body(document)
        digest = hashlib.sha256(body).hexdigest()
        first = repository.ingest_batch(
            batch,
            body_sha256=digest,
            raw_body=body,
        )
        duplicate = repository.ingest_batch(
            batch,
            body_sha256=digest,
            raw_body=body,
        )
        assert first["status"] == "accepted"
        assert duplicate["status"] == "duplicate"
        with pytest.raises(EdgeBatchConflictError):
            repository.ingest_batch(
                batch,
                body_sha256="f" * 64,
                raw_body=body,
            )
    finally:
        repository.close()


def test_unapproved_rule_is_visible_only_as_shadow_alert() -> None:
    document = _batch()
    body = _body(document)
    headers = {
        **sign_transport_headers(CLIENT, body),
        "Content-Type": "application/json",
    }
    with _server() as server:
        status, receipt = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers=headers,
        )
        assert status == 201
        assert receipt["accepted_observations"] == 1
        assert receipt["regulatory_outcome"] == (
            "not_determined_at_intake"
        )

        status, dashboard = _request(
            server,
            "GET",
            "/v1/dashboard/safety",
        )
        assert status == 200
        assert dashboard["summary"]["orange"] == 0
        assert dashboard["shadow_summary"]["orange"] == 1
        alert = next(
            item
            for item in dashboard["alerts"]
            if item["category"] == "personnel"
        )
        assert alert["source"] == "platform_recalculation"
        assert alert["operational"] is False
        assert alert["mode"] == "shadow"
        assert alert["due_at"] is None
        assert alert["overdue"] is False
        assert alert["details"]["production_control_permitted"] is False
        notifications = server.edge_repository.list_notifications(
            mine_ids={"M001"}
        )
        assert not any(
            item["payload"]["technical_warning"]["rule_code"]
            == "personnel"
            for item in notifications
        )


def test_interval_and_belt_metric_are_persisted_and_exposed() -> None:
    document = _batch(batch_id="belt-window")
    observation = document["observations"][0]
    observation.update(
        {
            "metric_code": "production.belt_instantaneous_t_h",
            "value": 126.5,
            "unit": "t/h",
            "location_code": "main-belt-01",
            "interval": _interval(aggregation="instantaneous_rate"),
        }
    )
    body = _body(document)
    with _server() as server:
        status, receipt = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        stored = server.edge_repository.recent_observations(
            "M001",
            metric_codes={"production.belt_instantaneous_t_h"},
        )
        _, dashboard = _request(server, "GET", "/v1/dashboard/safety")
    assert status == 201
    assert receipt["accepted_observations"] == 1
    assert stored[0]["interval"]["aggregation"] == "instantaneous_rate"
    latest = dashboard["mines"][0]["latest_metrics"]
    belt = latest["production.belt_instantaneous_t_h@main-belt-01"]
    assert belt["interval"]["shift_code"] == "day-A"


def test_edge_store_adds_interval_column_to_existing_database(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy-edge.sqlite3"
    repository = EdgeTelemetryRepository(database_path)
    repository.close()
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "ALTER TABLE edge_observations DROP COLUMN interval_json"
        )
    migrated = EdgeTelemetryRepository(database_path)
    migrated.close()
    with sqlite3.connect(database_path) as connection:
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(edge_observations)"
            ).fetchall()
        }
    assert "interval_json" in columns


def test_non_safety_batch_does_not_create_rule_governance_alert() -> None:
    document = _batch(batch_id="edge-M001-production-only")
    observation = document["observations"][0]
    observation.update(
        {
            "source_id": "production-meter",
            "observation_id": "edge-M001-production-only-output",
            "metric_code": "production.output_t",
            "value": 123.0,
            "unit": "t",
            "location_code": "mine-output",
            "source_record_id": "production:edge-M001-production-only",
        }
    )
    body = _body(document)
    with _server() as server:
        intake_status, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        alerts_status, alerts = _request(
            server,
            "GET",
            "/v1/safety/alerts?mine_id=M001",
        )
    assert intake_status == 201
    assert alerts_status == 200
    assert alerts["items"] == []


def test_main_fan_stop_is_independently_recalculated_as_red() -> None:
    document = _batch(batch_id="edge-M001-main-fan-stop")
    observation = document["observations"][0]
    observation.update(
        {
            "source_id": "fan-plc",
            "observation_id": "edge-M001-main-fan-stop-state",
            "metric_code": "ventilation.main_fan_running",
            "value": 0,
            "unit": "count",
            "location_code": "main-fan-1",
            "source_record_id": "fan:edge-M001-main-fan-stop",
        }
    )
    body = _body(document)
    with _server() as server:
        intake_status, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        alerts_status, alerts = _request(
            server,
            "GET",
            "/v1/safety/alerts?mine_id=M001",
        )
    assert intake_status == 201
    assert alerts_status == 200
    fan_alert = next(
        item
        for item in alerts["items"]
        if item["rule_code"] == "main_fan_stopped"
    )
    assert fan_alert["level"] == "red"
    assert fan_alert["source"] == "platform_recalculation"
    assert fan_alert["details"]["production_control_permitted"] is False


def test_main_fan_state_rejects_non_binary_value() -> None:
    document = _batch(batch_id="edge-M001-main-fan-invalid")
    observation = document["observations"][0]
    observation.update(
        {
            "metric_code": "ventilation.main_fan_running",
            "value": 0.5,
            "unit": "count",
        }
    )
    with pytest.raises(ValueError, match="must contain 0 or 1"):
        EdgeTelemetryBatch.model_validate(document)


def test_second_safety_batch_reloads_strict_persisted_state() -> None:
    first = _batch(batch_id="edge-M001-state-first")
    second = _batch(batch_id="edge-M001-state-second")
    with _server() as server:
        for document in (first, second):
            body = _body(document)
            status, _ = _request(
                server,
                "POST",
                "/v1/edge-telemetry-batches",
                body=body,
                headers={
                    **sign_transport_headers(CLIENT, body),
                    "Content-Type": "application/json",
                },
            )
            assert status == 201
        status, runs = _request(server, "GET", "/v1/safety/runs")
    assert status == 200
    assert runs["count"] == 2
    assert all(
        item["result"]["status"] if "status" in item["result"] else True
        for item in runs["items"]
    )


def test_rejected_low_completeness_fan_signal_cannot_create_alert() -> None:
    document = _batch(batch_id="edge-M001-rejected-fan")
    observation = document["observations"][0]
    observation.update(
        {
            "source_id": "fan-plc",
            "observation_id": "rejected-fan-state",
            "metric_code": "ventilation.main_fan_running",
            "value": 0,
            "unit": "count",
            "location_code": "main-fan-1",
            "source_record_id": "fan:rejected-low-completeness",
        }
    )
    observation["quality"]["completeness"] = 0.49
    body = _body(document)
    with _server() as server:
        status, receipt = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        _, alerts = _request(
            server,
            "GET",
            "/v1/safety/alerts?mine_id=M001",
        )
        evaluation = server.edge_repository.get_batch_evaluation(
            document["batch_id"]
        )
    assert status == 201
    assert receipt["accepted_observations"] == 0
    assert receipt["rejected_observations"] == 1
    assert evaluation is not None
    assert evaluation["status"] == "completed"
    assert evaluation["result_status"] == "no_new_accepted_observations"
    assert not any(
        item["rule_code"] == "main_fan_stopped"
        for item in alerts["items"]
    )


def test_conflicting_observation_identity_cannot_change_alert_state() -> None:
    first = _batch(batch_id="edge-M001-fan-running")
    first_observation = first["observations"][0]
    first_observation.update(
        {
            "source_id": "fan-plc",
            "observation_id": "stable-fan-observation",
            "metric_code": "ventilation.main_fan_running",
            "value": 1,
            "unit": "count",
            "location_code": "main-fan-1",
            "source_record_id": "fan:stable-observation",
        }
    )
    second = json.loads(json.dumps(first))
    second["batch_id"] = _batch_identifier("edge-M001-fan-conflict")
    second["observations"][0]["value"] = 0
    second["sent_at"] = _now_text()
    with _server() as server:
        first_body = _body(first)
        first_status, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=first_body,
            headers={
                **sign_transport_headers(CLIENT, first_body),
                "Content-Type": "application/json",
            },
        )
        second_body = _body(second)
        second_status, receipt = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=second_body,
            headers={
                **sign_transport_headers(CLIENT, second_body),
                "Content-Type": "application/json",
            },
        )
        _, alerts = _request(
            server,
            "GET",
            "/v1/safety/alerts?mine_id=M001",
        )
    assert first_status == 201
    assert second_status == 201
    assert receipt["accepted_observations"] == 0
    assert receipt["rejected_observations"] == 1
    assert not any(
        item["rule_code"] == "main_fan_stopped"
        for item in alerts["items"]
    )


def test_highest_revision_in_same_batch_is_the_only_evaluated_value() -> None:
    document = _batch(batch_id="edge-M001-two-revisions")
    original = document["observations"][0]
    original["observation_id"] = "personnel-revised-reading"
    original["value"] = 100
    revised = json.loads(json.dumps(original))
    revised["revision"] = 1
    revised["sequence_no"] = 2
    revised["value"] = 50
    revised["source_record_sha256"] = "c" * 64
    document["observations"].append(revised)
    document["sequence_end"] = 2
    body = _body(document)
    with _server() as server:
        status, receipt = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        _, alerts = _request(
            server,
            "GET",
            "/v1/safety/alerts?mine_id=M001",
        )
        _, runs = _request(server, "GET", "/v1/safety/runs")
        _, dashboard = _request(server, "GET", "/v1/dashboard/safety")
    assert status == 201
    assert receipt["accepted_observations"] == 2
    assert not any(
        item["category"] == "personnel"
        for item in alerts["items"]
    )
    assert runs["items"][0]["result"]["accepted_observation_ids"] == [
        "personnel-revised-reading"
    ]
    state = runs["items"][0]["result"]["states"][0]
    assert state["last_value"] == 50
    assert state["last_revision"] == 1
    mine = next(
        item for item in dashboard["mines"] if item["mine_id"] == "M001"
    )
    latest = mine["latest_metrics"][
        "personnel.underground_count@underground-total"
    ]
    assert latest["value"] == 50
    assert latest["revision"] == 1


def test_evaluation_failure_is_persisted_and_duplicate_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _batch(batch_id="edge-M001-evaluation-retry")
    body = _body(document)
    original_evaluator = api_module.evaluate_edge_batch_safety
    monkeypatch.setattr(
        api_module,
        "evaluate_edge_batch_safety",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("simulated evaluation failure")
        ),
    )
    with _server() as server:
        first_status, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        failed = server.edge_repository.get_batch_evaluation(
            document["batch_id"]
        )
        monkeypatch.setattr(
            api_module,
            "evaluate_edge_batch_safety",
            original_evaluator,
        )
        second_status, second_receipt = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        completed = server.edge_repository.get_batch_evaluation(
            document["batch_id"]
        )
        _, alerts = _request(
            server,
            "GET",
            "/v1/safety/alerts?mine_id=M001",
        )
    assert first_status == 201
    assert failed is not None
    assert failed["status"] == "failed"
    assert failed["error_code"] == "RuntimeError"
    assert second_status == 200
    assert second_receipt["status"] == "duplicate"
    assert completed is not None
    assert completed["status"] == "completed"
    assert completed["attempts"] == 2
    failure_alert = next(
        item
        for item in alerts["items"]
        if item["rule_code"] == "platform_safety_recalculation_failed"
    )
    assert failure_alert["status"] == "resolved"


def test_disabled_mine_retains_raw_data_without_operational_alert() -> None:
    document = _batch(batch_id="edge-M001-disabled-mine-fan")
    observation = document["observations"][0]
    observation.update(
        {
            "source_id": "fan-plc",
            "observation_id": "disabled-mine-fan-stop",
            "metric_code": "ventilation.main_fan_running",
            "value": 0,
            "unit": "count",
            "location_code": "main-fan-1",
            "source_record_id": "fan:disabled-mine-stop",
        }
    )
    body = _body(document)
    with _server() as server:
        server.edge_repository.upsert_mine(
            {
                "mine_id": "M001",
                "mine_name": "测试一矿",
                "gas_category": "high_gas",
                "approved_underground_personnel": 100,
                "enabled": False,
            },
            actor_id="test",
        )
        status, receipt = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        _, dashboard = _request(server, "GET", "/v1/dashboard/safety")
        raw = server.edge_repository.recent_observations(
            "M001",
            metric_codes={"ventilation.main_fan_running"},
        )
        evaluation = server.edge_repository.get_batch_evaluation(
            document["batch_id"]
        )
    assert status == 201
    assert receipt["accepted_observations"] == 1
    assert len(raw) == 1
    assert evaluation is not None
    assert evaluation["result_status"] == "monitoring_disabled"
    assert dashboard["summary"]["red"] == 0
    assert dashboard["alerts"] == []
    mine = next(
        item for item in dashboard["mines"] if item["mine_id"] == "M001"
    )
    assert mine["risk_level"] == "monitoring_disabled"
    assert mine["open_alerts"] == []


def test_edge_nonce_replay_and_scope_are_rejected() -> None:
    body = _body(_batch())
    headers = sign_transport_headers(CLIENT, body, nonce="A" * 22)
    with _server() as server:
        first, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers=headers,
        )
        second, payload = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers=headers,
        )
    assert first == 201
    assert second == 401
    assert payload["code"] == "AUTHENTICATION_FAILED"


def test_alert_ledger_uses_optimistic_locking_and_hash_chain() -> None:
    repository = EdgeTelemetryRepository()
    try:
        alert = repository.upsert_platform_alert(
            mine_id="M001",
            category="personnel",
            rule_code="personnel",
            level="yellow",
            title="人员预警",
            summary="请复核",
            location_code="underground-total",
            detected_at=datetime.now(UTC),
            observation_ids=["obs-1"],
            details={"advisory_only": True},
            rule_profile={"version": "v1", "fingerprint": "a" * 64},
        )
        updated = repository.apply_alert_action(
            alert["alert_id"],
            action="acknowledge",
            expected_version=alert["version"],
            actor_id="reviewer",
        )
        assert updated["status"] == "acknowledged"
        with pytest.raises(AlertVersionConflictError):
            repository.apply_alert_action(
                alert["alert_id"],
                action="start",
                expected_version=alert["version"],
                actor_id="reviewer",
            )
        detail = repository.get_alert(alert["alert_id"])
        assert detail is not None
        assert detail["audit_chain_valid"] is True
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("path", "example", "expected_key", "expected_status"),
    [
        (
            "/v1/analyze/safety",
            "safety-evaluation.json",
            "active_leads",
            200,
        ),
        (
            "/v1/analyze/verification",
            "production-verification.json",
            "baselines",
            201,
        ),
    ],
)
def test_new_algorithm_http_endpoints(
    path: str,
    example: str,
    expected_key: str,
    expected_status: int,
) -> None:
    document = json.loads(
        (
            Path(__file__).parents[1] / "examples" / example
        ).read_text(encoding="utf-8")
    )
    body = _body(document)
    with _server() as server:
        status, payload = _request(
            server,
            "POST",
            path,
            body=body,
            headers={"Content-Type": "application/json"},
        )
    assert status == expected_status
    assert expected_key in payload


def test_verification_run_is_idempotent_and_visible_on_dashboard() -> None:
    document = json.loads(
        (
            Path(__file__).parents[1]
            / "examples"
            / "production-verification.json"
        ).read_text(encoding="utf-8")
    )
    body = _body(document)
    with _server() as server:
        first_status, first = _request(
            server,
            "POST",
            "/v1/analyze/verification",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        second_status, second = _request(
            server,
            "POST",
            "/v1/analyze/verification",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        list_status, listed = _request(
            server,
            "GET",
            "/v1/verification/runs?mine_id=M001",
        )
        dashboard_status, dashboard = _request(
            server,
            "GET",
            "/v1/dashboard/safety",
        )
    assert first_status == 201
    assert second_status == 200
    assert first["run_id"] == second["run_id"]
    assert second["created"] is False
    assert list_status == 200
    assert listed["count"] == 1
    assert dashboard_status == 200
    assert dashboard["verification_heatmap"][0]["mine_id"] == "M001"
    assert dashboard["verification_heatmap"][0]["status"] == (
        "insufficient_history"
    )
    mine = next(
        item for item in dashboard["mines"] if item["mine_id"] == "M001"
    )
    assert mine["production_verification"]["status"] == (
        "insufficient_history"
    )


def test_safety_rule_requires_explicit_admin_approval() -> None:
    document = _batch(batch_id="edge-M001-approved-rule")
    body = _body(document)
    with _server() as server:
        listed_status, listed = _request(
            server,
            "GET",
            "/v1/admin/safety-rules",
        )
        assert listed_status == 200
        proposal = next(
            item
            for item in listed["items"]
            if item["rule_version"] == DEFAULT_RULE_SNAPSHOT.version
        )
        assert proposal["status"] == "proposal"

        action_status, approved = _request(
            server,
            "POST",
            (
                f"/v1/admin/safety-rules/"
                f"{DEFAULT_RULE_SNAPSHOT.version}/actions"
            ),
            body=_body(
                {
                    "action": "approve",
                    "expected_fingerprint": proposal["fingerprint"],
                    "note": "测试审批记录：已核对方案阈值和适用范围。",
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        assert action_status == 200
        assert approved["status"] == "approved"

        intake_status, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=body,
            headers={
                **sign_transport_headers(CLIENT, body),
                "Content-Type": "application/json",
            },
        )
        assert intake_status == 201
        _, alerts = _request(
            server,
            "GET",
            "/v1/safety/alerts?mine_id=M001",
        )
        _, dashboard = _request(
            server,
            "GET",
            "/v1/dashboard/safety",
        )
    assert not any(
        item["rule_code"] == "safety_rule_approval_required"
        for item in alerts["items"]
    )
    personnel = next(
        item for item in alerts["items"] if item["category"] == "personnel"
    )
    assert personnel["operational"] is True
    assert personnel["mode"] == "operational"
    assert dashboard["summary"]["orange"] == 1
    assert dashboard["shadow_summary"]["orange"] == 0


def test_shadow_alert_is_promoted_only_after_rule_approval() -> None:
    shadow_document = _batch(batch_id="edge-M001-shadow-before-approval")
    operational_document = _batch(
        batch_id="edge-M001-operational-after-approval"
    )
    with _server() as server:
        shadow_body = _body(shadow_document)
        shadow_status, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=shadow_body,
            headers={
                **sign_transport_headers(CLIENT, shadow_body),
                "Content-Type": "application/json",
            },
        )
        shadow = next(
            item
            for item in server.edge_repository.list_alerts(
                mine_ids={"M001"}
            )
            if item["category"] == "personnel"
        )
        proposal = next(
            item
            for item in server.edge_repository.list_safety_rules()
            if item["rule_version"] == DEFAULT_RULE_SNAPSHOT.version
        )
        server.edge_repository.change_safety_rule_status(
            proposal["rule_version"],
            action="approve",
            expected_fingerprint=proposal["fingerprint"],
            actor_id="test-approver",
            note="测试批准：影子预警晋升为正式预警。",
        )
        operational_body = _body(operational_document)
        operational_status, _ = _request(
            server,
            "POST",
            "/v1/edge-telemetry-batches",
            body=operational_body,
            headers={
                **sign_transport_headers(CLIENT, operational_body),
                "Content-Type": "application/json",
            },
        )
        promoted = server.edge_repository.get_alert(shadow["alert_id"])
        notifications = server.edge_repository.list_notifications(
            mine_ids={"M001"}
        )
    assert shadow_status == 201
    assert operational_status == 201
    assert shadow["operational"] is False
    assert promoted is not None
    assert promoted["operational"] is True
    assert promoted["due_at"] is not None
    assert any(
        event["event_type"] == "promoted_from_shadow"
        for event in promoted["events"]
    )
    assert any(
        item["payload"]["technical_warning"]["rule_code"] == "personnel"
        for item in notifications
    )


def test_alert_resolution_and_closure_require_two_reviewers() -> None:
    repository = EdgeTelemetryRepository()
    try:
        alert = repository.upsert_platform_alert(
            mine_id="M001",
            category="workflow-test",
            rule_code="four-eyes-close",
            level="yellow",
            title="双人复核测试",
            summary="仅用于验证办理与关闭职责分离。",
            location_code="test",
            detected_at=datetime.now(UTC),
            observation_ids=["four-eyes-observation"],
            details={"advisory_only": True},
            rule_profile={
                "version": "test-v1",
                "fingerprint": "a" * 64,
            },
        )
        resolved = repository.apply_alert_action(
            alert["alert_id"],
            action="resolve",
            expected_version=alert["version"],
            actor_id="reviewer-a",
            note="复核人员甲记录处理结果。",
        )
        with pytest.raises(
            ValueError,
            match="cannot both resolve and close",
        ):
            repository.apply_alert_action(
                alert["alert_id"],
                action="close",
                expected_version=resolved["version"],
                actor_id="reviewer-a",
                note="同一人员不得自行关闭。",
            )
        closed = repository.apply_alert_action(
            alert["alert_id"],
            action="close",
            expected_version=resolved["version"],
            actor_id="reviewer-b",
            note="复核人员乙完成独立关闭审核。",
        )
    finally:
        repository.close()
    assert closed["status"] == "closed"


def test_safety_rule_retirement_preserves_approval_record() -> None:
    repository = EdgeTelemetryRepository()
    try:
        snapshot = DEFAULT_RULE_SNAPSHOT.model_copy(
            update={"version": "rule-lifecycle-test"}
        )
        record, created = repository.register_safety_rule(
            snapshot=snapshot.model_dump(mode="json"),
            fingerprint=snapshot.fingerprint,
            actor_id="author",
        )
        assert created is True
        approved = repository.change_safety_rule_status(
            record["rule_version"],
            action="approve",
            expected_fingerprint=record["fingerprint"],
            actor_id="approver",
            note="审批说明至少十个字符并永久保留",
        )
        retired = repository.change_safety_rule_status(
            record["rule_version"],
            action="retire",
            expected_fingerprint=record["fingerprint"],
            actor_id="retirer",
            note="退役说明至少十个字符并永久保留",
        )
    finally:
        repository.close()
    assert approved["approved_by"] == "approver"
    assert retired["approved_at"] == approved["approved_at"]
    assert retired["approved_by"] == "approver"
    assert retired["approval_note"] == "审批说明至少十个字符并永久保留"
    assert retired["retired_at"] is not None
    assert retired["retired_by"] == "retirer"
    assert retired["retirement_note"] == "退役说明至少十个字符并永久保留"


def test_legacy_approved_rule_is_not_silently_reinterpreted() -> None:
    repository = EdgeTelemetryRepository()
    try:
        snapshot = DEFAULT_RULE_SNAPSHOT.model_dump(mode="json")
        snapshot["version"] = "legacy-approved-without-main-fan"
        snapshot.pop("main_fan")
        fingerprint = hashlib.sha256(
            json.dumps(
                snapshot,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        record, _ = repository.register_safety_rule(
            snapshot=snapshot,
            fingerprint=fingerprint,
            actor_id="legacy-author",
        )
        repository.change_safety_rule_status(
            record["rule_version"],
            action="approve",
            expected_fingerprint=fingerprint,
            actor_id="legacy-approver",
            note="旧规则审批记录仅用于升级兼容性测试",
        )
        repository.upsert_mine(
            {
                "mine_id": "M001",
                "mine_name": "测试一矿",
                "gas_category": "high_gas",
                "approved_underground_personnel": 100,
            },
            actor_id="test",
        )
        result = evaluate_edge_batch_safety(
            repository,
            EdgeTelemetryBatch.model_validate(_batch()),
        )
        alerts = repository.list_alerts(mine_ids={"M001"})
    finally:
        repository.close()
    assert result["status"] == "evaluated"
    governance = next(
        item
        for item in alerts
        if item["rule_code"] == "safety_rule_approval_required"
    )
    assert governance["details"][
        "legacy_approved_rule_without_main_fan"
    ] == "legacy-approved-without-main-fan"
    assert governance["rule_profile"]["approval_status"] == "not_approved"


def test_safety_rule_timezones_and_four_eyes_are_enforced() -> None:
    repository = EdgeTelemetryRepository()
    try:
        now = datetime.now(UTC)
        first_snapshot = DEFAULT_RULE_SNAPSHOT.model_copy(
            update={
                "version": "timezone-rule-one",
                "effective_from": now - timedelta(seconds=1),
                "effective_to": now + timedelta(hours=1),
            }
        ).model_dump(mode="json")
        first_snapshot["effective_from"] = (
            (now + timedelta(hours=8, seconds=-1))
            .replace(tzinfo=None)
            .isoformat()
            + "+08:00"
        )
        first_fingerprint = hashlib.sha256(
            _body(first_snapshot)
        ).hexdigest()
        first, _ = repository.register_safety_rule(
            snapshot=first_snapshot,
            fingerprint=first_fingerprint,
            actor_id="rule-author",
        )
        with pytest.raises(
            SafetyRuleConflictError,
            match="author cannot approve",
        ):
            repository.change_safety_rule_status(
                first["rule_version"],
                action="approve",
                expected_fingerprint=first_fingerprint,
                actor_id="rule-author",
                note="起草人不能审批自己起草的同一规则版本",
            )
        repository.change_safety_rule_status(
            first["rule_version"],
            action="approve",
            expected_fingerprint=first_fingerprint,
            actor_id="independent-approver",
            note="独立审批人已核对时区和完整规则指纹",
        )
        effective = repository.effective_safety_rule(now)
        assert effective is not None
        assert effective["rule_version"] == first["rule_version"]

        second_snapshot = DEFAULT_RULE_SNAPSHOT.model_copy(
            update={
                "version": "timezone-rule-overlap",
                "effective_from": now,
                "effective_to": now + timedelta(hours=2),
            }
        ).model_dump(mode="json")
        second_fingerprint = hashlib.sha256(
            _body(second_snapshot)
        ).hexdigest()
        second, _ = repository.register_safety_rule(
            snapshot=second_snapshot,
            fingerprint=second_fingerprint,
            actor_id="second-author",
        )
        with pytest.raises(
            SafetyRuleConflictError,
            match="overlaps",
        ):
            repository.change_safety_rule_status(
                second["rule_version"],
                action="approve",
                expected_fingerprint=second_fingerprint,
                actor_id="second-approver",
                note="重叠有效期必须阻断且不得依赖字符串时区排序",
            )
    finally:
        repository.close()
