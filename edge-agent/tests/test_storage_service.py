from __future__ import annotations

import re
from dataclasses import replace

import pytest

from mine_edge.errors import ValidationError
from mine_edge.service import EdgeService
from mine_edge.storage import Repository


def test_ingest_is_idempotent_and_alert_is_atomic(settings, methane_raw) -> None:
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    first = service.ingest(methane_raw, channel="http_poll", source_id="gas")
    second = service.ingest(methane_raw, channel="http_poll", source_id="gas")

    assert first.inserted is True
    assert len(first.alert_ids) == 1
    assert second.duplicate is True
    assert repository.stats() == {
        "observations": 1,
        "alerts": 1,
        "outbox_pending": 2,
        "outbox_delivered": 0,
    }


def test_methane_sampling_evidence_is_internal_and_uses_normalized_value(
    settings,
    methane_raw,
) -> None:
    methane_raw["value"] = 8_200
    methane_raw["unit"] = "ppm"
    methane_raw["quality"] = {
        "valid": True,
        "completeness": 1.0,
        "timeliness": 1.0,
        "device_health": "healthy",
        "clock_synchronized": True,
        "flags": [],
    }
    result = EdgeService(
        Repository(settings.database_path),
        settings,
    ).ingest(
        methane_raw,
        channel="http_poll",
        source_id="gas",
    )

    evidence = result.methane_sampling_evidence
    assert evidence is not None
    assert evidence.metric_code == "methane.concentration_percent"
    assert evidence.value_percent == pytest.approx(0.82)
    assert evidence.quality_valid is True
    assert evidence.local_alert_generated is True
    assert "methane_sampling_evidence" not in result.to_dict()


def test_higher_revision_is_separate_delivery(settings, methane_raw) -> None:
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    service.ingest(methane_raw, channel="http_poll", source_id="gas")
    methane_raw["revision"] = 2
    methane_raw["value"] = 0.9
    revised = service.ingest(methane_raw, channel="http_poll", source_id="gas")
    assert revised.inserted
    assert repository.stats()["observations"] == 2
    assert repository.stats()["outbox_pending"] == 4


def test_same_revision_with_changed_content_is_rejected(settings, methane_raw) -> None:
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    service.ingest(methane_raw, channel="http_poll", source_id="gas")
    methane_raw["value"] = 0.91
    with pytest.raises(ValidationError, match="必须增加 revision"):
        service.ingest(methane_raw, channel="http_poll", source_id="gas")


def test_stale_revision_is_rejected(settings, methane_raw) -> None:
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    methane_raw["revision"] = 2
    service.ingest(methane_raw, channel="http_poll", source_id="gas")
    methane_raw["revision"] = 1
    with pytest.raises(ValidationError, match="拒绝过期修订"):
        service.ingest(methane_raw, channel="http_poll", source_id="gas")


def test_cross_mine_data_is_rejected(settings, methane_raw) -> None:
    methane_raw["mine_id"] = "another-mine"
    with pytest.raises(ValidationError, match="拒绝跨矿数据"):
        EdgeService(Repository(settings.database_path), settings).ingest(
            methane_raw, channel="http_poll", source_id="gas"
        )


def test_manual_ingest_requires_provenance(settings, methane_raw) -> None:
    with pytest.raises(ValidationError, match="provenance"):
        EdgeService(Repository(settings.database_path), settings).ingest_manual(
            methane_raw
        )


def test_fan_status_and_local_alert_are_put_in_v1_outbox(settings) -> None:
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    result = service.ingest(
        {
            "event_id": "fan-stop-1",
            "kind": "ventilation",
            "metric": "main_fan_running",
            "value": False,
            "unit": "bool",
            "location_code": "main-fan-1",
            "observed_at": "2026-07-28T00:00:00Z",
        },
        channel="http_poll",
        source_id="fan-plc",
    )
    assert len(result.alert_ids) == 1
    assert repository.stats()["alerts"] == 1
    assert repository.stats()["outbox_pending"] == 2


def test_batch_claim_is_stable_across_retry(settings, methane_raw) -> None:
    repository = Repository(settings.database_path)
    EdgeService(repository, settings).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )
    first = repository.claim_batch(limit=100, client_id=settings.client_id)
    assert first is not None
    assert first.batch_id.startswith(f"{settings.client_id}--batch_")
    assert len(first.batch_id) <= 128
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", first.batch_id)
    delay = repository.mark_batch_failed(
        first.batch_id,
        error="offline",
        base_delay_seconds=1,
        max_delay_seconds=60,
    )
    assert delay == 1
    # Set retry due without sleeping.
    with repository._connect() as connection:
        connection.execute(
            "UPDATE outbox SET next_attempt_at=0 WHERE batch_id=?", (first.batch_id,)
        )
    second = repository.claim_batch(limit=100, client_id=settings.client_id)
    assert second is not None
    assert second.batch_id == first.batch_id


def test_delivered_records_remain_auditable(settings, methane_raw) -> None:
    repository = Repository(settings.database_path)
    EdgeService(repository, settings).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )
    batch = repository.claim_batch(limit=100, client_id=settings.client_id)
    assert batch is not None
    repository.mark_batch_delivered(batch.batch_id)
    assert repository.stats()["outbox_pending"] == 0
    assert repository.stats()["outbox_delivered"] == 2
    assert len(repository.list_outbox(status="delivered")) == 2


def test_non_loopback_requires_api_token(settings) -> None:
    unsafe = replace(settings, host="0.0.0.0")
    with pytest.raises(Exception, match="API_TOKEN"):
        unsafe.validate_server_binding()
