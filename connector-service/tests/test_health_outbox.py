from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from conftest import write_config

import enterprise_connector.service as connector_service_module
from enterprise_connector.client import signature_material
from enterprise_connector.config import load_config
from enterprise_connector.service import ConnectorService, CycleResult
from enterprise_connector.state import StateStore


def _payload(outcome: str = "success_nonempty") -> dict[str, object]:
    success = outcome == "success_nonempty"
    return {
        "contract_version": "enterprise-source-health/v1",
        "draft_key": "draft:operator-qy-001:five-quantity:monthly:2026-07",
        "reporting_month": "2026-07",
        "source_id": "ledger",
        "source_system": "mes-ledger",
        "outcome": outcome,
        "attempted_at": "2026-07-31T00:00:00.000Z",
        "completed_at": "2026-07-31T00:00:01.000Z",
        "record_count": 8 if success else 0,
        "coverage_as_of": "2026-07-31" if success else None,
        "error_code": None if outcome != "error" else "source_collection_error",
        "snapshot_sha256": "a" * 64 if success else None,
        "autofill_event_id": "cevt_snapshot" if success else None,
        "source_revision": 1 if success else None,
    }


def test_health_outbox_state_transition_heartbeat_and_restart(tmp_path: Path) -> None:
    path = tmp_path / "health-state.sqlite3"
    state = StateStore(path)
    first = state.register_health(
        "pipeline",
        _payload(),
        heartbeat_seconds=300,
        completed_epoch=1.0,
        now=1.0,
    )
    assert first
    assert state.register_health(
        "pipeline",
        _payload(),
        heartbeat_seconds=300,
        completed_epoch=2.0,
        now=2.0,
    ) is None
    pending_body = json.loads(state.pending_health(now=2.0)[0].payload_json)
    assert pending_body["event_id"] == first
    assert pending_body["snapshot_sha256"] == "a" * 64
    state.mark_health_delivered(first, 202, now=3.0)
    assert state.register_health(
        "pipeline",
        _payload(),
        heartbeat_seconds=300,
        completed_epoch=299.0,
        now=299.0,
    ) is None
    heartbeat = state.register_health(
        "pipeline",
        _payload(),
        heartbeat_seconds=300,
        completed_epoch=301.0,
        now=301.0,
    )
    assert heartbeat and heartbeat != first
    error = state.register_health(
        "pipeline",
        _payload("error"),
        heartbeat_seconds=300,
        completed_epoch=302.0,
        now=302.0,
    )
    assert error and error not in {first, heartbeat}
    state.close()

    reopened = StateStore(path)
    try:
        assert [item.event_id for item in reopened.pending_health(now=303.0)] == [
            heartbeat,
            error,
        ]
    finally:
        reopened.close()


def test_health_retention_only_prunes_old_delivered_nonlatest_rows(tmp_path: Path) -> None:
    state = StateStore(tmp_path / "health-retention.sqlite3")
    try:
        delivered_old = state.register_health(
            "pipeline",
            _payload(),
            heartbeat_seconds=1,
            completed_epoch=1.0,
            now=1.0,
        )
        assert delivered_old
        state.mark_health_delivered(delivered_old, 202, now=1.0)

        pending_old = state.register_health(
            "pipeline",
            _payload("error"),
            heartbeat_seconds=1,
            completed_epoch=2.0,
            now=2.0,
        )
        assert pending_old
        dead_old = state.register_health(
            "pipeline",
            _payload("stability_wait"),
            heartbeat_seconds=1,
            completed_epoch=3.0,
            now=3.0,
        )
        assert dead_old
        state.mark_health_dead(dead_old, "durable rejection", 422, now=3.0)

        delivered_latest = state.register_health(
            "pipeline",
            _payload(),
            heartbeat_seconds=1,
            completed_epoch=4.0,
            now=4.0,
        )
        assert delivered_latest
        state.mark_health_delivered(delivered_latest, 202, now=4.0)

        trigger_payload = {**_payload(), "source_id": "other-source"}
        trigger = state.register_health(
            "other-pipeline",
            trigger_payload,
            heartbeat_seconds=1,
            completed_epoch=91 * 24 * 60 * 60,
            now=91 * 24 * 60 * 60,
        )
        assert trigger
        retained = {
            row["event_id"]: row["status"]
            for row in state.connection.execute(
                "SELECT event_id,status FROM health_deliveries"
            ).fetchall()
        }
        assert delivered_old not in retained
        assert retained[pending_old] == "pending"
        assert retained[dead_old] == "dead"
        assert retained[delivered_latest] == "delivered"
        assert retained[trigger] == "pending"
    finally:
        state.close()


def test_health_hmac_material_signs_the_health_path() -> None:
    body = b'{"contract_version":"enterprise-source-health/v1"}'
    material = signature_material(
        1722400000,
        "request-health",
        body,
        path="/api/v1/machine/source-health",
    ).decode()
    assert material.splitlines()[:5] == [
        "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1",
        "POST",
        "/api/v1/machine/source-health",
        "1722400000",
        "request-health",
    ]


def test_empty_source_run_cycle_emits_health_without_erasing_snapshot(
    tmp_path: Path, source_db: Path, monkeypatch
) -> None:
    connection = sqlite3.connect(source_db)
    connection.execute("DELETE FROM five_quantity")
    connection.commit()
    connection.close()
    path = write_config(tmp_path / "connector.toml", source_db)
    monkeypatch.setenv("TEST_CONNECTOR_SECRET", "s" * 32)
    service = ConnectorService(load_config(path))
    monkeypatch.setattr(service.client, "send_health", lambda *_args, **_kwargs: 202)
    try:
        service.acquire()
        result = service.run_cycle()
        assert result.discovered == 0
        assert result.health_delivered == 1
        assert result.source_errors == 0
        row = service.store.connection.execute(
            "SELECT outcome,payload_json,status FROM health_deliveries"
        ).fetchone()
        payload = json.loads(row["payload_json"])
        assert row["outcome"] == "success_empty" and row["status"] == "delivered"
        assert payload["coverage_as_of"] is None
        assert payload["snapshot_sha256"] is None
        assert service.store.connection.execute(
            "SELECT COUNT(*) FROM observations"
        ).fetchone()[0] == 0
    finally:
        service.close()


def test_unexpected_source_failure_is_isolated_from_following_source(
    tmp_path: Path,
    source_db: Path,
    monkeypatch,
) -> None:
    path = write_config(
        tmp_path / "connector.toml",
        source_db,
        second_source_db=source_db,
    )
    monkeypatch.setenv("TEST_CONNECTOR_SECRET", "s" * 32)
    service = ConnectorService(load_config(path))
    real_collect = connector_service_module._collect

    def fail_first(source):
        if source.id == "ledger":
            raise RuntimeError("sensitive upstream row must not be persisted")
        return real_collect(source)

    monkeypatch.setattr(connector_service_module, "_collect", fail_first)
    try:
        service.acquire()
        result = CycleResult()
        service.collect(result)
        assert result.source_errors == 1
        assert result.discovered == 1
        ledger_health = service.store.connection.execute(
            """
            SELECT last_error FROM source_health
            WHERE pipeline_id='mine-one-five-quantity' AND source_id='ledger'
            """
        ).fetchone()
        assert ledger_health["last_error"] == "internal:RuntimeError"
        payload = json.loads(
            service.store.connection.execute(
                """
                SELECT payload_json FROM health_deliveries
                WHERE source_id='ledger' ORDER BY sequence DESC LIMIT 1
                """
            ).fetchone()[0]
        )
        assert payload["error_code"] == "source_internal_error"
        assert "sensitive upstream" not in json.dumps(payload)
        assert service.store.connection.execute(
            "SELECT COUNT(*) FROM observations WHERE source_id='scale'"
        ).fetchone()[0] == 1
    finally:
        service.close()
