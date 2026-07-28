from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib

from mineguard.edge_ingest import EdgeTelemetryBatch
from mineguard.edge_store import EdgeTelemetryRepository
from mineguard.safety_service import evaluate_edge_batch_safety


CLIENT_ID = "mine-edge-M001"
METRICS = (
    "personnel.no_card_entry_count",
    "personnel.person_card_mismatch_count",
    "personnel.overtime_count",
)


def _batch(label: str, value: int, observed_at: datetime) -> EdgeTelemetryBatch:
    digest = hashlib.sha256(label.encode()).hexdigest()[:32]
    observations = []
    for sequence_no, metric in enumerate(METRICS, start=1):
        identity = f"{label}-{metric}"
        observations.append(
            {
                "source_id": "personnel-system",
                "observation_id": identity,
                "metric_code": metric,
                "value": value,
                "unit": "count",
                "location_code": "gate-summary",
                "observed_at": observed_at,
                "received_at": observed_at,
                "sequence_no": sequence_no,
                "revision": 0,
                "acquisition_mode": "api_poll",
                "source_record_id": identity,
                "source_record_sha256": hashlib.sha256(
                    identity.encode()
                ).hexdigest(),
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
        )
    return EdgeTelemetryBatch.model_validate(
        {
            "schema_version": "edge-telemetry-batch-v1",
            "batch_id": f"{CLIENT_ID}--batch_{digest}",
            "client_id": CLIENT_ID,
            "mine_id": "M001",
            "sent_at": observed_at,
            "sequence_start": 1,
            "sequence_end": len(observations),
            "rule_profile": {
                "profile_id": "edge-local-profile",
                "version": 1,
                "sha256": "a" * 64,
            },
            "observations": observations,
            "local_alerts": [],
        }
    )


def test_personnel_integrity_counts_create_and_recover_review_clues() -> None:
    repository = EdgeTelemetryRepository()
    started = datetime.now(UTC) - timedelta(seconds=2)
    try:
        evaluate_edge_batch_safety(
            repository,
            _batch("personnel-active", 2, started),
        )
        active = {
            item["rule_code"]: item
            for item in repository.list_alerts(mine_ids={"M001"})
            if item["category"] == "personnel"
        }
        evaluate_edge_batch_safety(
            repository,
            _batch("personnel-clear", 0, started + timedelta(seconds=1)),
        )
        recovered = {
            item["rule_code"]: item
            for item in repository.list_alerts(mine_ids={"M001"})
            if item["category"] == "personnel"
        }
    finally:
        repository.close()

    assert set(active) == {
        "personnel_no_card_entry",
        "personnel_card_identity_mismatch",
        "personnel_underground_overtime",
    }
    assert active["personnel_no_card_entry"]["level"] == "orange"
    assert active["personnel_card_identity_mismatch"]["level"] == "orange"
    assert active["personnel_underground_overtime"]["level"] == "yellow"
    assert all(item["mode"] == "shadow" for item in active.values())
    assert all(
        item["details"]["production_control_permitted"] is False
        for item in active.values()
    )
    assert all(item["status"] == "resolved" for item in recovered.values())

