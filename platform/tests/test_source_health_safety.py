from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any

from mineguard.edge_ingest import EdgeTelemetryBatch
from mineguard.edge_store import EdgeTelemetryRepository
from mineguard.safety_service import evaluate_edge_batch_safety


_CLIENT_ID = "mine-edge-M001"


def _batch(
    label: str,
    *,
    missing: bool,
    status_code: str,
    heartbeat_age_seconds: float,
    consecutive_failures: int,
    quality_valid: bool = True,
    observed_at: datetime | None = None,
) -> EdgeTelemetryBatch:
    observed = (observed_at or datetime.now(UTC)).astimezone(UTC)
    batch_digest = hashlib.sha256(label.encode()).hexdigest()[:32]
    measurements: tuple[tuple[str, float, str], ...] = (
        ("source.heartbeat_age_seconds", heartbeat_age_seconds, "s"),
        (
            "source.consecutive_failures",
            float(consecutive_failures),
            "count",
        ),
        ("source.missing_state", float(missing), "count"),
    )
    observations: list[dict[str, Any]] = []
    for sequence_no, (metric, value, unit) in enumerate(
        measurements,
        start=1,
    ):
        identity = f"{label}-{metric}"
        observations.append(
            {
                "source_id": "personnel-gateway",
                "observation_id": identity,
                "metric_code": metric,
                "value": value,
                "unit": unit,
                "location_code": "personnel-gateway",
                "observed_at": observed,
                "received_at": observed,
                "sequence_no": sequence_no,
                "revision": 0,
                "acquisition_mode": "automatic_adapter",
                "source_record_id": identity,
                "source_record_sha256": hashlib.sha256(
                    identity.encode()
                ).hexdigest(),
                "source_signature": None,
                "status_code": status_code,
                "quality": {
                    "valid": quality_valid,
                    "completeness": 1.0,
                    "timeliness": 1.0,
                    "device_health": (
                        "fault" if missing else "healthy"
                    ),
                    "clock_synchronized": True,
                    "flags": ["edge_agent_generated_source_health"],
                },
                "manual_attestation": None,
            }
        )
    return EdgeTelemetryBatch.model_validate(
        {
            "schema_version": "edge-telemetry-batch-v1",
            "batch_id": f"{_CLIENT_ID}--batch_{batch_digest}",
            "client_id": _CLIENT_ID,
            "mine_id": "M001",
            "sent_at": observed,
            "sequence_start": 1,
            "sequence_end": len(observations),
            "rule_profile": {
                "profile_id": "qinyuan-safety-default",
                "version": 1,
                "sha256": "a" * 64,
            },
            "observations": observations,
            "local_alerts": [],
        }
    )


def test_explicit_missing_state_opens_operational_technical_warning() -> None:
    repository = EdgeTelemetryRepository()
    try:
        result = evaluate_edge_batch_safety(
            repository,
            _batch(
                "missing-cycle",
                missing=True,
                status_code="missing_data",
                heartbeat_age_seconds=125.5,
                consecutive_failures=4,
            ),
        )
        alerts = repository.list_alerts(mine_ids={"M001"})
        notifications = repository.list_notifications(
            mine_ids={"M001"},
        )
    finally:
        repository.close()

    assert result["status"] == "evaluated_source_health"
    assert result["source_health"][0]["status"] == "missing_alert_active"
    alert = next(
        item
        for item in alerts
        if item["rule_code"] == "source_data_missing"
    )
    assert alert["category"] == "data_quality"
    assert alert["level"] == "yellow"
    assert alert["operational"] is True
    assert alert["mode"] == "operational"
    assert alert["details"]["data_freshness"] == "missing"
    assert alert["details"]["heartbeat_age_seconds"] == 125.5
    assert alert["details"]["consecutive_failures"] == 4
    assert alert["details"]["production_control_permitted"] is False
    assert not any(
        item["rule_code"] == "safety_rule_approval_required"
        for item in alerts
    )
    assert any(
        item["payload"]["technical_warning"]["rule_code"]
        == "source_data_missing"
        for item in notifications
    )
    missing_notification = next(
        item
        for item in notifications
        if item["payload"]["technical_warning"]["rule_code"]
        == "source_data_missing"
    )
    assert (
        missing_notification["payload"]["technical_warning"][
            "approval_status"
        ]
        == "system_integrity_control"
    )


def test_unconfirmed_zero_never_masks_missing_and_trusted_recovery_is_idempotent(
) -> None:
    repository = EdgeTelemetryRepository()
    try:
        started = datetime.now(UTC) - timedelta(seconds=3)
        opened = evaluate_edge_batch_safety(
            repository,
            _batch(
                "missing-open",
                missing=True,
                status_code="missing_data",
                heartbeat_age_seconds=90,
                consecutive_failures=3,
                observed_at=started,
            ),
        )
        deferred = evaluate_edge_batch_safety(
            repository,
            _batch(
                "startup-grace",
                missing=False,
                status_code="awaiting_first_data",
                heartbeat_age_seconds=2,
                consecutive_failures=0,
                observed_at=started + timedelta(seconds=1),
            ),
        )
        alert_id = opened["alert_ids"][0]
        still_open = repository.get_alert(alert_id)
        recovered = evaluate_edge_batch_safety(
            repository,
            _batch(
                "trusted-recovery",
                missing=False,
                status_code="ok",
                heartbeat_age_seconds=0.2,
                consecutive_failures=0,
                observed_at=started + timedelta(seconds=2),
            ),
        )
        replay = evaluate_edge_batch_safety(
            repository,
            _batch(
                "trusted-recovery-replay",
                missing=False,
                status_code="ok",
                heartbeat_age_seconds=0.2,
                consecutive_failures=0,
                observed_at=started + timedelta(seconds=2),
            ),
        )
        final = repository.get_alert(alert_id)
    finally:
        repository.close()

    assert deferred["source_health"][0]["status"] == "recovery_deferred"
    assert still_open is not None
    assert still_open["status"] == "open"
    assert recovered["source_health"][0]["status"] == (
        "missing_alert_recovered"
    )
    assert replay["source_health"][0]["status"] == "available"
    assert final is not None
    assert final["status"] == "resolved"
    assert [
        item["event_type"] for item in final["events"]
    ] == ["created", "auto_resolved"]
