from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from datetime import datetime
from pathlib import Path

import pytest
from conftest import write_config

from enterprise_connector.adapters.sqlite_query import collect_sqlite_query
from enterprise_connector.client import sign, signature_material
from enterprise_connector.config import load_config
from enterprise_connector.errors import ConnectorError, SourceError
from enterprise_connector.models import FieldMapping, RawBatch
from enterprise_connector.normalize import METRICS, SCOPES, canonical_json, normalize_batches
from enterprise_connector.service import _current_reporting_target
from enterprise_connector.state import StateStore


def _event(tmp_path: Path, source_db: Path):
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    events = normalize_batches(pipeline, source, collect_sqlite_query(source))
    assert len(events) == 1
    return config, pipeline, source, events[0]


def _changed(event, value: float):
    payload = copy.deepcopy(event.payload)
    content = json.loads(payload["source"]["content"])
    day = next(item for item in content["days"] if item["date"] == "2026-07-29")
    day["reported_quantity"]["daily_total"]["production_t"]["value"] = value
    text = canonical_json(content)
    return replace(
        event,
        content_sha256=hashlib.sha256(text.encode()).hexdigest(),
        payload={
            **payload,
            "source": {**payload["source"], "content": text},
        },
    )


def _mark_fresh(state: StateStore, event, timestamp: float, maximum: float = 100.0) -> None:
    state.record_collection_health(
        event.pipeline_id,
        event.source_id,
        status="ok",
        record_count=max(1, event.record_count),
        now=timestamp,
    )
    state.record_snapshot_health(
        event.pipeline_id,
        event.source_id,
        event.draft_key,
        event.period_key,
        record_count=max(1, event.record_count),
        now=timestamp,
    )
    metadata = state.latest_observation_metadata(
        event.pipeline_id, event.source_id, event.draft_key
    )
    assert metadata is not None
    health_id = state.register_health(
        event.pipeline_id,
        {
            "contract_version": "enterprise-source-health/v1",
            "draft_key": event.draft_key,
            "reporting_month": event.period_key,
            "source_id": event.source_id,
            "source_system": event.payload["source"]["source_system"],
            "outcome": "success_nonempty",
            "attempted_at": f"2026-07-29T00:00:{int(timestamp) % 60:02d}Z",
            "completed_at": f"2026-07-29T00:00:{int(timestamp) % 60:02d}Z",
            "record_count": max(1, event.record_count),
            "coverage_as_of": "2026-07-31",
            "error_code": None,
            "snapshot_sha256": metadata["delivered_content_sha256"],
            "autofill_event_id": metadata["event_id"],
            "source_revision": metadata["source_revision"],
        },
        heartbeat_seconds=maximum / 2,
        completed_epoch=timestamp,
        now=timestamp,
    )
    assert health_id
    state.mark_health_delivered(health_id, 202, now=timestamp)


def test_month_snapshot_is_complete_v2_and_deterministic(tmp_path: Path, source_db: Path) -> None:
    _config, pipeline, source, event = _event(tmp_path, source_db)
    assert event.draft_key.endswith(":monthly:2026-07")
    assert event.period_key == "2026-07"
    assert event.payload["source"]["source_id"] == "ledger"
    assert event.payload["source"]["truth_statement"] is True
    assert event.payload["workflow_name"] == "daily_coal_health"
    content = json.loads(event.payload["source"]["content"])
    assert content["connector_snapshot"]["source_id"] == source.id
    assert content["days"][0]["date"] == "2026-07-01"
    assert content["days"][-1]["date"] == "2026-07-31"
    assert len(content["days"]) == 31
    for day in content["days"]:
        quantity = day["reported_quantity"]
        assert set(quantity["daily_total"]) == set(METRICS)
        assert set(quantity["shifts"]) == set(SCOPES) - {"daily_total"}
        for scope in set(SCOPES) - {"daily_total"}:
            assert set(quantity["shifts"][scope]["measurements"]) == set(METRICS)
    repeated = normalize_batches(pipeline, source, collect_sqlite_query(source))[0]
    assert repeated.content_sha256 == event.content_sha256


def test_recollecting_identical_history_updates_transport_time_not_business_revision(
    tmp_path: Path, source_db: Path
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    batches = collect_sqlite_query(source)
    first = normalize_batches(
        pipeline,
        source,
        batches,
        now=datetime.fromisoformat("2026-08-04T00:00:00+00:00"),
    )[0]
    second = normalize_batches(
        pipeline,
        source,
        batches,
        now=datetime.fromisoformat("2026-08-05T00:00:00+00:00"),
    )[0]
    assert first.payload["source"]["observed_at"] != second.payload["source"]["observed_at"]
    assert first.content_sha256 == second.content_sha256
    state = StateStore(tmp_path / "identical-recollection.sqlite3")
    try:
        assert state.register(first)
        assert state.register(second) is None
    finally:
        state.close()


def test_three_heterogeneous_source_schemas_align_to_one_monthly_draft(
    tmp_path: Path, source_db: Path
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    base = pipeline.sources[0]
    energy = replace(
        base,
        id="energy-meter",
        source_system="energy-api",
        timestamp_field="meter_time",
        scope_field="bucket",
        scope_values={"DAY": "daily_total"},
        mappings=(
            FieldMapping(target="electricity_kwh", source="active_kwh", reduce="latest"),
        ),
    )
    explosives = replace(
        base,
        id="explosives-ledger",
        source_system="blasting-ledger",
        timestamp_field="issued_on",
        scope_field="team_code",
        scope_values={"0": "zero_shift"},
        mappings=(
            FieldMapping(
                target="explosives_kg",
                source="issued_kg",
                reduce="sum",
            ),
        ),
    )
    energy_event = normalize_batches(
        pipeline,
        energy,
        (
            RawBatch(
                source_id=energy.id,
                original_filename="energy.json",
                records=(
                    {
                        "meter_time": "2026-07-29T23:50:00+08:00",
                        "bucket": "DAY",
                        "active_kwh": 456.7,
                    },
                ),
            ),
        ),
    )[0]
    explosives_event = normalize_batches(
        pipeline,
        explosives,
        (
            RawBatch(
                source_id=explosives.id,
                original_filename="blasting.csv",
                records=(
                    {
                        "issued_on": "2026-07-29T01:00:00+08:00",
                        "team_code": "0",
                        "issued_kg": 2.5,
                    },
                ),
            ),
        ),
    )[0]
    ledger_event = normalize_batches(pipeline, base, collect_sqlite_query(base))[0]
    assert {
        ledger_event.draft_key,
        energy_event.draft_key,
        explosives_event.draft_key,
    } == {"draft:operator-qy-001:five-quantity:monthly:2026-07"}
    assert len({event.source_id for event in (ledger_event, energy_event, explosives_event)}) == 3


def test_latest_rejects_conflicting_values_at_same_business_time(
    tmp_path: Path, source_db: Path
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = replace(
        pipeline.sources[0],
        id="meter",
        timestamp_field="meter_time",
        scope_field="bucket",
        scope_values={"DAY": "daily_total"},
        mappings=(
            FieldMapping(
                target="electricity_kwh",
                source="active_kwh",
                reduce="latest",
            ),
        ),
    )
    records = (
        {
            "meter_time": "2026-07-29T23:50:00+08:00",
            "bucket": "DAY",
            "active_kwh": 456.7,
        },
        {
            "meter_time": "2026-07-29T23:50:00+08:00",
            "bucket": "DAY",
            "active_kwh": 456.8,
        },
    )
    for ordered_records in (records, tuple(reversed(records))):
        with pytest.raises(SourceError, match="相同业务时间出现冲突值"):
            normalize_batches(
                pipeline,
                source,
                (
                    RawBatch(
                        source_id=source.id,
                        original_filename="meter.json",
                        records=ordered_records,
                    ),
                ),
            )


def test_missing_values_are_null_not_imputed(tmp_path: Path, source_db: Path) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    batch = RawBatch(
        source_id=source.id,
        original_filename="partial.json",
        records=(
            {
                "observed_at": "2026-07-29T00:00:00+08:00",
                "scope": "zero_shift",
                "production": 10,
            },
        ),
    )
    content = json.loads(
        normalize_batches(pipeline, source, (batch,))[0].payload["source"]["content"]
    )
    day_29 = next(item for item in content["days"] if item["date"] == "2026-07-29")
    measurements = day_29["reported_quantity"]["shifts"]["zero_shift"]["measurements"]
    assert measurements["production_t"]["value"] == 10.0
    assert measurements["electricity_kwh"]["value"] is None
    assert measurements["electricity_kwh"]["quality_flags"] == ["missing"]


def test_complete_source_field_drift_cannot_create_a_fresh_all_null_snapshot(
    tmp_path: Path, source_db: Path
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    drifted = RawBatch(
        source_id=source.id,
        original_filename="drifted-schema.json",
        records=(
            {
                "observed_at": "2026-07-29T00:00:00+08:00",
                "scope": "zero_shift",
                "renamed_production": 10,
                "renamed_electricity": 20,
            },
        ),
    )
    with pytest.raises(SourceError, match="未映射到任何非空规范值"):
        normalize_batches(pipeline, source, (drifted,))


def test_conflicting_values_never_last_write_win(tmp_path: Path, source_db: Path) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    batch = RawBatch(
        source_id=source.id,
        original_filename="conflict.json",
        records=(
            {
                "observed_at": "2026-07-29T00:00:00+08:00",
                "scope": "zero_shift",
                "production": 10,
            },
            {
                "observed_at": "2026-07-29T00:01:00+08:00",
                "scope": "zero_shift",
                "production": 11,
            },
        ),
    )
    with pytest.raises(SourceError, match="冲突值"):
        normalize_batches(pipeline, source, (batch,))


@pytest.mark.parametrize("malicious", ["1,2,3", "1e999", "9" * 129])
def test_malformed_or_oversized_numbers_are_bounded(
    tmp_path: Path, source_db: Path, malicious: str
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    batch = RawBatch(
        source_id=source.id,
        original_filename="malicious.json",
        records=(
            {
                "observed_at": "2026-07-29",
                "scope": "daily_total",
                "production": malicious,
            },
        ),
    )
    with pytest.raises(SourceError, match="数字|指数|上限"):
        normalize_batches(pipeline, source, (batch,))


def test_legal_thousands_separator_is_supported(tmp_path: Path, source_db: Path) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    batch = RawBatch(
        source_id=source.id,
        original_filename="grouped.json",
        records=(
            {
                "observed_at": "2026-07-29",
                "scope": "daily_total",
                "production": "1,234.5",
            },
        ),
    )
    content = json.loads(
        normalize_batches(pipeline, source, (batch,))[0].payload["source"]["content"]
    )
    day = next(item for item in content["days"] if item["date"] == "2026-07-29")
    assert day["reported_quantity"]["daily_total"]["production_t"]["value"] == 1234.5


def test_missing_whole_day_is_explicitly_represented(tmp_path: Path, source_db: Path) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    batch = RawBatch(
        source_id=source.id,
        original_filename="gapped.json",
        records=(
            {"observed_at": "2026-07-29", "scope": "daily_total", "production": 10},
            {"observed_at": "2026-07-31", "scope": "daily_total", "production": 11},
        ),
    )
    content = json.loads(
        normalize_batches(pipeline, source, (batch,))[0].payload["source"]["content"]
    )
    assert content["days"][0]["date"] == "2026-07-01"
    assert content["days"][-1]["date"] == "2026-07-31"
    missing = next(item for item in content["days"] if item["date"] == "2026-07-30")
    assert missing["operating_state"] == "unknown"
    assert all(
        item["value"] is None for item in missing["reported_quantity"]["daily_total"].values()
    )
    coverage = content["connector_snapshot"]["coverage"]
    assert coverage["expected_date_count"] == 31
    assert coverage["observed_date_count"] == 2
    assert "2026-07-30" in coverage["missing_dates"]


def test_current_month_cutoff_and_future_month_are_explicit(
    tmp_path: Path, source_db: Path
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    current = RawBatch(
        source_id=source.id,
        original_filename="current.json",
        records=({"observed_at": "2026-08-02", "scope": "daily_total", "production": 10},),
    )
    content = json.loads(
        normalize_batches(
            pipeline,
            source,
            (current,),
            now=datetime.fromisoformat("2026-08-04T00:00:00+00:00"),
        )[0].payload["source"]["content"]
    )
    assert [item["date"] for item in content["days"]] == [
        "2026-08-01",
        "2026-08-02",
        "2026-08-03",
        "2026-08-04",
    ]
    coverage = content["connector_snapshot"]["coverage"]
    assert coverage["coverage_as_of"] == "2026-08-04"
    assert coverage["reporting_lag_days"] == 0
    future = replace(
        current,
        records=({"observed_at": "2026-09-01", "scope": "daily_total", "production": 10},),
    )
    with pytest.raises(SourceError, match="未来月份"):
        normalize_batches(
            pipeline,
            source,
            (future,),
            now=datetime.fromisoformat("2026-08-04T00:00:00+00:00"),
        )


@pytest.mark.parametrize(
    ("lag_days", "expected_end"),
    [(1, "2026-07-31"), (2, "2026-07-30"), (31, "2026-07-01")],
)
def test_month_boundary_lag_uses_one_enterprise_cutoff_for_target_and_snapshot(
    tmp_path: Path,
    source_db: Path,
    lag_days: int,
    expected_end: str,
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = replace(config.pipelines[0], reporting_lag_days=lag_days)
    source = pipeline.sources[0]
    collected_at = datetime.fromisoformat("2026-08-01T00:00:00+00:00")
    batch = RawBatch(
        source_id=source.id,
        original_filename="month-boundary.json",
        records=(
            {
                "observed_at": "2026-07-01T00:00:00+08:00",
                "scope": "daily_total",
                "production": 10,
            },
        ),
    )
    event = normalize_batches(
        pipeline,
        source,
        (batch,),
        now=collected_at,
    )[0]
    content = json.loads(event.payload["source"]["content"])
    coverage = content["connector_snapshot"]["coverage"]
    assert content["days"][-1]["date"] == expected_end
    assert coverage["period_end"] == expected_end
    assert coverage["coverage_as_of"] == expected_end
    assert event.payload["source"]["coverage_as_of"] == expected_end
    draft_key, target_month, target_cutoff = _current_reporting_target(
        pipeline, collected_at.timestamp()
    )
    assert target_month == "2026-07"
    assert target_cutoff == expected_end
    assert draft_key == event.draft_key


def test_state_aba_is_revisioned_and_restart_is_idempotent(tmp_path: Path, source_db: Path) -> None:
    _config, _pipeline, _source, event_a = _event(tmp_path, source_db)
    event_b = _changed(event_a, 351.0)
    state_path = tmp_path / "state-aba.sqlite3"
    store = StateStore(state_path)
    try:
        first = store.register(event_a)
        assert first is not None
        assert store.register(event_a) is None
        second = store.register(event_b)
        third = store.register(event_a)
        assert second is not None and third is not None
        assert len({first, second, third}) == 3
        revisions = [
            row[0]
            for row in store.connection.execute(
                "SELECT source_revision FROM observations ORDER BY sequence"
            )
        ]
        assert revisions == [1, 2, 3]
        third_payload = json.loads(
            store.connection.execute(
                "SELECT payload_json FROM observations WHERE event_id = ?", (third,)
            ).fetchone()[0]
        )
        assert third_payload["source"]["revision"] == 3
        assert (
            json.loads(third_payload["source"]["content"])["connector_snapshot"]["source_revision"]
            == 3
        )
    finally:
        store.close()
    reopened = StateStore(state_path)
    try:
        assert reopened.register(event_a) is None
    finally:
        reopened.close()


def test_required_sources_trigger_once_per_latest_generation(
    tmp_path: Path, source_db: Path
) -> None:
    _config, pipeline, source, event_a = _event(tmp_path, source_db)
    source_b = replace(source, id="scale", source_name="scale")
    event_b = replace(
        event_a,
        source_id="scale",
        payload={
            **copy.deepcopy(event_a.payload),
            "source": {**copy.deepcopy(event_a.payload["source"]), "source_id": "scale"},
        },
    )
    state = StateStore(tmp_path / "state-generation.sqlite3")
    try:
        event_a_id = state.register(event_a)
        event_b_id = state.register(event_b)
        assert event_a_id and event_b_id and source_b.id == "scale"
        first = state.prepare_delivery(event_a_id, ("ledger", "scale"))
        assert first is not None and first.trigger_workflow is False
        state.mark_delivered(event_a_id, 201)
        second = state.prepare_delivery(event_b_id, ("ledger", "scale"))
        assert second is not None and second.trigger_workflow is True
        state.mark_delivered(event_b_id, 202)
        changed_id = state.register(_changed(event_a, 351.0))
        assert changed_id
        changed = state.prepare_delivery(changed_id, ("ledger", "scale"))
        assert changed is not None and changed.trigger_workflow is True
        state.mark_delivered(changed_id, 202)
        optional = replace(
            event_a,
            source_id="optional-quality",
            payload={
                **copy.deepcopy(event_a.payload),
                "source": {
                    **copy.deepcopy(event_a.payload["source"]),
                    "source_id": "optional-quality",
                },
            },
        )
        optional_id = state.register(optional)
        assert optional_id
        optional_delivery = state.prepare_delivery(optional_id, ("ledger", "scale"))
        assert optional_delivery is not None and optional_delivery.trigger_workflow is True
        state.mark_delivered(optional_id, 202)
        optional_dead_id = state.register(_changed(optional, 777.0))
        assert optional_dead_id
        state.mark_dead(optional_dead_id, "optional source rejected", 409)
        required_after_optional_dead_id = state.register(_changed(event_a, 352.0))
        assert required_after_optional_dead_id
        required_after_optional_dead = state.prepare_delivery(
            required_after_optional_dead_id, ("ledger", "scale")
        )
        assert (
            required_after_optional_dead is not None
            and required_after_optional_dead.trigger_workflow is True
        )
        state.mark_delivered(required_after_optional_dead_id, 202)
        completed = state.connection.execute(
            "SELECT COUNT(*) FROM workflow_generations WHERE status='completed'"
        ).fetchone()[0]
        assert completed == 4
    finally:
        state.close()


def test_required_freshness_is_period_scoped_and_boundary_is_stale(
    tmp_path: Path, source_db: Path
) -> None:
    _config, _pipeline, _source, event = _event(tmp_path, source_db)
    state = StateStore(tmp_path / "freshness-boundary.sqlite3")
    try:
        event_id = state.register(event)
        assert event_id
        _mark_fresh(state, event, 100.0, maximum=10.0)
        delivery = state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source={event.source_id: 10.0},
            now=110.0,
        )
        assert delivery is not None and delivery.trigger_workflow is False

        # A fresh poll in a different reporting month cannot refresh July.
        august = replace(
            event,
            draft_key=event.draft_key.replace("2026-07", "2026-08"),
            period_key="2026-08",
        )
        assert state.register(august)
        _mark_fresh(state, august, 200.0, maximum=100.0)
        delivery = state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source={event.source_id: 100.0},
            now=200.0,
        )
        assert delivery is not None and delivery.trigger_workflow is False
    finally:
        state.close()


def test_autofill_waits_for_health_retry_then_triggers_exactly_once(
    tmp_path: Path, source_db: Path
) -> None:
    _config, _pipeline, _source, event = _event(tmp_path, source_db)
    state = StateStore(tmp_path / "health-before-autofill.sqlite3")
    try:
        event_id = state.register(event)
        assert event_id
        state.record_collection_health(
            event.pipeline_id,
            event.source_id,
            status="ok",
            record_count=event.record_count,
            now=1.0,
        )
        state.record_snapshot_health(
            event.pipeline_id,
            event.source_id,
            event.draft_key,
            event.period_key,
            record_count=event.record_count,
            now=1.0,
        )
        metadata = state.latest_observation_metadata(
            event.pipeline_id, event.source_id, event.draft_key
        )
        assert metadata
        health_id = state.register_health(
            event.pipeline_id,
            {
                "contract_version": "enterprise-source-health/v1",
                "draft_key": event.draft_key,
                "reporting_month": event.period_key,
                "source_id": event.source_id,
                "source_system": "mes-ledger",
                "outcome": "success_nonempty",
                "attempted_at": "2026-07-31T00:00:01Z",
                "completed_at": "2026-07-31T00:00:01Z",
                "record_count": event.record_count,
                "coverage_as_of": "2026-07-31",
                "error_code": None,
                "snapshot_sha256": metadata["delivered_content_sha256"],
                "autofill_event_id": metadata["event_id"],
                "source_revision": metadata["source_revision"],
            },
            heartbeat_seconds=50,
            completed_epoch=1.0,
            now=1.0,
        )
        assert health_id
        policy = {event.source_id: 100.0}
        assert state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source=policy,
            now=2.0,
        ) is None
        state.mark_health_retry(health_id, "Agent 503", 1, 503, now=2.0)
        assert state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source=policy,
            now=3.0,
        ) is None
        state.mark_health_delivered(health_id, 202, now=3.0)
        ready = state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source=policy,
            now=3.0,
        )
        assert ready is not None and ready.trigger_workflow is True
        state.mark_delivered(event_id, 202, now=3.0)
        assert state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source=policy,
            now=4.0,
        ) is None
        assert state.connection.execute(
            "SELECT COUNT(*) FROM workflow_generations WHERE status='completed'"
        ).fetchone()[0] == 1
    finally:
        state.close()


def test_exact_dead_health_binding_blocks_until_a_new_health_event_recovers(
    tmp_path: Path, source_db: Path
) -> None:
    _config, _pipeline, _source, event = _event(tmp_path, source_db)
    state = StateStore(tmp_path / "dead-health-before-autofill.sqlite3")
    try:
        event_id = state.register(event)
        assert event_id
        state.record_collection_health(
            event.pipeline_id,
            event.source_id,
            status="ok",
            record_count=max(1, event.record_count),
            now=1.0,
        )
        state.record_snapshot_health(
            event.pipeline_id,
            event.source_id,
            event.draft_key,
            event.period_key,
            record_count=max(1, event.record_count),
            now=1.0,
        )
        metadata = state.latest_observation_metadata(
            event.pipeline_id, event.source_id, event.draft_key
        )
        assert metadata
        health_payload = {
            "contract_version": "enterprise-source-health/v1",
            "draft_key": event.draft_key,
            "reporting_month": event.period_key,
            "source_id": event.source_id,
            "source_system": event.payload["source"]["source_system"],
            "outcome": "success_nonempty",
            "attempted_at": "2026-07-31T00:00:01Z",
            "completed_at": "2026-07-31T00:00:01Z",
            "record_count": max(1, event.record_count),
            "coverage_as_of": "2026-07-31",
            "error_code": None,
            "snapshot_sha256": metadata["delivered_content_sha256"],
            "autofill_event_id": metadata["event_id"],
            "source_revision": metadata["source_revision"],
        }
        dead_health_id = state.register_health(
            event.pipeline_id,
            health_payload,
            heartbeat_seconds=5.0,
            completed_epoch=1.0,
            now=1.0,
        )
        assert dead_health_id
        state.mark_health_dead(dead_health_id, "Agent rejected health", 422, now=2.0)
        policy = {event.source_id: 100.0}
        assert state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source=policy,
            now=3.0,
        ) is None

        recovered_health_id = state.register_health(
            event.pipeline_id,
            {
                **health_payload,
                "attempted_at": "2026-07-31T00:00:07Z",
                "completed_at": "2026-07-31T00:00:07Z",
            },
            heartbeat_seconds=5.0,
            completed_epoch=7.0,
            now=7.0,
        )
        assert recovered_health_id and recovered_health_id != dead_health_id
        state.mark_health_delivered(recovered_health_id, 202, now=7.0)
        ready = state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source=policy,
            now=7.0,
        )
        assert ready is not None and ready.trigger_workflow is True
    finally:
        state.close()


@pytest.mark.parametrize("outcome", ["success_empty", "error", "mismatched_success"])
def test_newer_nonbinding_health_does_not_strand_an_older_observation(
    tmp_path: Path, source_db: Path, outcome: str
) -> None:
    _config, _pipeline, _source, event = _event(tmp_path, source_db)
    state = StateStore(tmp_path / f"newer-{outcome}-health.sqlite3")
    try:
        event_id = state.register(event)
        assert event_id
        _mark_fresh(state, event, 1.0)
        is_mismatch = outcome == "mismatched_success"
        health_id = state.register_health(
            event.pipeline_id,
            {
                "contract_version": "enterprise-source-health/v1",
                "draft_key": event.draft_key,
                "reporting_month": event.period_key,
                "source_id": event.source_id,
                "source_system": event.payload["source"]["source_system"],
                "outcome": "success_nonempty" if is_mismatch else outcome,
                "attempted_at": "2026-07-31T00:00:02Z",
                "completed_at": "2026-07-31T00:00:02Z",
                "record_count": 1 if is_mismatch else 0,
                "coverage_as_of": "2026-07-31" if is_mismatch else None,
                "error_code": "source_collection_error" if outcome == "error" else None,
                "snapshot_sha256": "f" * 64 if is_mismatch else None,
                "autofill_event_id": "cevt_unrelated" if is_mismatch else None,
                "source_revision": 999 if is_mismatch else None,
            },
            heartbeat_seconds=50.0,
            completed_epoch=2.0,
            now=2.0,
        )
        assert health_id
        delivery = state.prepare_delivery(
            event_id,
            (event.source_id,),
            max_staleness_by_source={event.source_id: 100.0},
            now=3.0,
        )
        assert delivery is not None and delivery.trigger_workflow is False
        latest = state.connection.execute(
            "SELECT event_id,status FROM health_deliveries ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        assert latest["event_id"] == health_id and latest["status"] == "pending"
    finally:
        state.close()


def test_stale_required_source_recovers_by_health_without_fake_revision(
    tmp_path: Path, source_db: Path
) -> None:
    _config, _pipeline, _source, event_a = _event(tmp_path, source_db)
    event_b = replace(
        event_a,
        source_id="scale",
        payload={
            **copy.deepcopy(event_a.payload),
            "source": {
                **copy.deepcopy(event_a.payload["source"]),
                "source_id": "scale",
                "source_system": "scale-system",
            },
        },
    )
    state = StateStore(tmp_path / "freshness-recovery.sqlite3")
    maximums = {"ledger": 100.0, "scale": 100.0}
    try:
        event_a_id = state.register(event_a)
        event_b_id = state.register(event_b)
        assert event_a_id and event_b_id
        _mark_fresh(state, event_a, 1.0)
        _mark_fresh(state, event_b, 1.0)
        first = state.prepare_delivery(
            event_a_id,
            ("ledger", "scale"),
            max_staleness_by_source=maximums,
            now=2.0,
        )
        assert first is not None and first.trigger_workflow is False
        state.mark_delivered(event_a_id, 202, now=2.0)
        second = state.prepare_delivery(
            event_b_id,
            ("ledger", "scale"),
            max_staleness_by_source=maximums,
            now=2.0,
        )
        assert second is not None and second.trigger_workflow is True
        state.mark_delivered(event_b_id, 202, now=2.0)

        state.record_collection_health(
            "mine-one-five-quantity",
            "scale",
            status="error",
            record_count=0,
            error="bounded",
            now=20.0,
        )
        error_health_id = state.register_health(
            event_b.pipeline_id,
            {
                "contract_version": "enterprise-source-health/v1",
                "draft_key": event_b.draft_key,
                "reporting_month": event_b.period_key,
                "source_id": event_b.source_id,
                "source_system": "scale-system",
                "outcome": "error",
                "attempted_at": "2026-07-29T00:00:20Z",
                "completed_at": "2026-07-29T00:00:20Z",
                "record_count": 0,
                "coverage_as_of": None,
                "error_code": "source_collection_error",
                "snapshot_sha256": None,
                "autofill_event_id": None,
                "source_revision": None,
            },
            heartbeat_seconds=50.0,
            completed_epoch=20.0,
            now=20.0,
        )
        assert error_health_id
        state.mark_health_delivered(error_health_id, 202, now=20.0)
        changed_event = _changed(event_a, 351.0)
        changed_id = state.register(changed_event)
        assert changed_id
        _mark_fresh(state, changed_event, 20.0)
        blocked = state.prepare_delivery(
            changed_id,
            ("ledger", "scale"),
            max_staleness_by_source=maximums,
            now=20.0,
        )
        assert blocked is not None and blocked.trigger_workflow is False
        state.mark_delivered(changed_id, 202, now=20.0)

        assert not state.source_snapshot_is_fresh(
            event_b.pipeline_id,
            event_b.source_id,
            event_b.draft_key,
            100.0,
            now=21.0,
        )
        state.record_collection_health(
            event_b.pipeline_id,
            event_b.source_id,
            status="ok",
            record_count=max(1, event_b.record_count),
            now=21.0,
        )
        state.record_snapshot_health(
            event_b.pipeline_id,
            event_b.source_id,
            event_b.draft_key,
            event_b.period_key,
            record_count=max(1, event_b.record_count),
            now=21.0,
        )
        assert state.register(event_b, now=21.0) is None
        _mark_fresh(state, event_b, 21.0)
        assert state.source_snapshot_is_fresh(
            event_b.pipeline_id,
            event_b.source_id,
            event_b.draft_key,
            100.0,
            now=21.0,
        )
        revisions = state.connection.execute(
            """
            SELECT source_revision FROM observations
            WHERE source_id='scale' ORDER BY sequence
            """
        ).fetchall()
        assert [row[0] for row in revisions] == [1]
    finally:
        state.close()


def test_hmac_material_matches_public_six_line_contract() -> None:
    body = b'{"hello":"coal"}'
    material = signature_material(1_722_400_000, "request-1", body)
    expected = (
        "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1\n"
        "POST\n/api/v1/machine/autofill\n1722400000\nrequest-1\n" + hashlib.sha256(body).hexdigest()
    ).encode()
    assert material == expected
    import hmac

    assert (
        sign(b"s" * 32, 1_722_400_000, "request-1", body)
        == hmac.new(b"s" * 32, expected, hashlib.sha256).hexdigest()
    )


def test_operator_status_shows_never_seen_required_source(tmp_path: Path, source_db: Path) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    state = StateStore(tmp_path / "status.sqlite3")
    try:
        status = state.pipeline_status(config.pipelines)[0]
        assert status["required_sources_not_ready"] == ["ledger"]
        assert status["ready_for_workflow"] is False
        assert status["sources"][0]["seen"] is False
    finally:
        state.close()


def test_newer_empty_health_period_makes_pipeline_not_ready(
    tmp_path: Path, source_db: Path
) -> None:
    config, _pipeline, _source, event = _event(tmp_path, source_db)
    state = StateStore(tmp_path / "empty-current-status.sqlite3")
    try:
        event_id = state.register(event)
        assert event_id
        state.mark_delivered(event_id, 202)
        empty_id = state.register_health(
            event.pipeline_id,
            {
                "contract_version": "enterprise-source-health/v1",
                "draft_key": event.draft_key.replace("2026-07", "2026-08"),
                "reporting_month": "2026-08",
                "source_id": event.source_id,
                "source_system": "mes-ledger",
                "outcome": "success_empty",
                "attempted_at": "2026-08-04T00:00:00Z",
                "completed_at": "2026-08-04T00:00:01Z",
                "record_count": 0,
                "coverage_as_of": None,
                "error_code": None,
                "snapshot_sha256": None,
                "autofill_event_id": None,
                "source_revision": None,
            },
            heartbeat_seconds=300,
            completed_epoch=1.0,
            now=1.0,
        )
        assert empty_id
        state.mark_health_delivered(empty_id, 202, now=1.0)
        status = state.pipeline_status(config.pipelines)[0]
        assert status["latest_period"] == "2026-08"
        assert status["required_sources_not_ready"] == ["ledger"]
        assert status["ready_for_workflow"] is False
    finally:
        state.close()


def test_disaster_replay_and_revision_seed_recovery(tmp_path: Path, source_db: Path) -> None:
    _config, _pipeline, _source, event = _event(tmp_path, source_db)
    state = StateStore(tmp_path / "primary-state.sqlite3")
    try:
        event_id = state.register(event)
        assert event_id
        state.mark_delivered(event_id, 202)
        before = state.connection.execute(
            "SELECT event_id,source_revision,payload_json FROM observations"
        ).fetchone()
        assert state.replay_delivered(event_id) == 1
        after = state.connection.execute(
            "SELECT event_id,source_revision,payload_json,status FROM observations"
        ).fetchone()
        assert tuple(after[:3]) == tuple(before)
        assert after["status"] == "pending"
    finally:
        state.close()

    recovered = StateStore(tmp_path / "recovered-state.sqlite3")
    try:
        recovered_id = recovered.register(replace(event, revision_floor=7))
        assert recovered_id
        revision = recovered.connection.execute(
            "SELECT source_revision FROM observations"
        ).fetchone()[0]
        assert revision == 8
    finally:
        recovered.close()


def test_durable_rejection_requires_audited_new_event_supersede(
    tmp_path: Path, source_db: Path
) -> None:
    _config, _pipeline, _source, event = _event(tmp_path, source_db)
    state = StateStore(tmp_path / "durable-rejection.sqlite3")
    try:
        old_event_id = state.register(event)
        assert old_event_id
        state.mark_dead(
            old_event_id,
            "Agent 返回状态码 409 code=connector_ingestion_rejected",
            409,
        )
        with pytest.raises(ConnectorError, match="supersede-dead"):
            state.retry_dead(old_event_id)
        superseded = state.supersede_dead(
            old_event_id,
            reason="Agent 端人工解除暂停并完成拒绝原因复核",
        )
        assert superseded["new_event_id"] != old_event_id
        assert superseded["source_revision"] == 2
        rows = state.connection.execute(
            """
            SELECT event_id,status,source_revision,payload_json
            FROM observations ORDER BY sequence
            """
        ).fetchall()
        assert [(row["status"], row["source_revision"]) for row in rows] == [
            ("dead", 1),
            ("pending", 2),
        ]
        new_payload = json.loads(rows[1]["payload_json"])
        assert new_payload["event_id"] == superseded["new_event_id"]
        assert new_payload["source"]["revision"] == 2
        assert state.connection.execute(
            "SELECT COUNT(*) FROM recovery_actions WHERE action_type='supersede_dead'"
        ).fetchone()[0] == 1
    finally:
        state.close()


def test_v1_intermediate_health_table_migrates_without_losing_observations(
    tmp_path: Path, source_db: Path
) -> None:
    _config, _pipeline, _source, event = _event(tmp_path, source_db)
    path = tmp_path / "migration.sqlite3"
    state = StateStore(path)
    event_id = state.register(event)
    assert event_id
    state.connection.executescript(
        """
        DROP TABLE source_health;
        CREATE TABLE source_health (
            pipeline_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('ok','waiting_or_empty','error')),
            record_count INTEGER NOT NULL,
            last_poll_at REAL NOT NULL,
            last_success_at REAL,
            last_nonempty_at REAL,
            last_error TEXT,
            PRIMARY KEY (pipeline_id,source_id)
        );
        INSERT INTO source_health VALUES (
            'mine-one-five-quantity','ledger','waiting_or_empty',0,1,NULL,NULL,NULL
        );
        UPDATE metadata SET value='1' WHERE key='schema_version';
        """
    )
    state.close()
    migrated = StateStore(path)
    try:
        assert migrated.status()["schema_version"] == 2
        assert migrated.connection.execute(
            "SELECT status FROM source_health"
        ).fetchone()[0] == "empty"
        assert migrated.connection.execute(
            "SELECT event_id FROM observations"
        ).fetchone()[0] == event_id
    finally:
        migrated.close()
