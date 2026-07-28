from __future__ import annotations

import pytest

from mine_edge.errors import ValidationError
from mine_edge.models import ObservationKind
from mine_edge.normalization import (
    normalize_observation,
    normalize_timestamp,
    normalize_value,
)


@pytest.mark.parametrize(
    ("kind", "metric", "value", "unit", "expected_value", "expected_unit"),
    [
        (ObservationKind.COAL_OUTPUT, "output", 1500, "kg", 1.5, "t"),
        (ObservationKind.COAL_OUTPUT, "output", 2, "吨", 2.0, "t"),
        (ObservationKind.ELECTRICITY, "energy", 1.2, "MWh", 1200.0, "kWh"),
        (ObservationKind.ELECTRICITY, "energy", 1000, "Wh", 1.0, "kWh"),
        (ObservationKind.PERSONNEL, "count", 7, "人", 7, "person"),
        (
            ObservationKind.PERSONNEL,
            "no_card_entry_count",
            2,
            "count",
            2,
            "count",
        ),
        (ObservationKind.METHANE, "gas", 0.0082, "fraction", 0.82, "%"),
        (ObservationKind.METHANE, "gas", 8200, "ppm", 0.82, "%"),
        (ObservationKind.EXPLOSIVES, "used", 1200, "g", 1.2, "kg"),
        (
            ObservationKind.EXPLOSIVES,
            "detonator_used",
            12,
            "发",
            12,
            "count",
        ),
        (
            ObservationKind.COAL_OUTPUT,
            "belt_instantaneous_output",
            1250,
            "kg/h",
            1.25,
            "t/h",
        ),
        (
            ObservationKind.COAL_OUTPUT,
            "belt_speed",
            2.4,
            "m/s",
            2.4,
            "m/s",
        ),
        (
            ObservationKind.SOURCE_HEALTH,
            "heartbeat_age_seconds",
            1500,
            "ms",
            1.5,
            "s",
        ),
        (
            ObservationKind.SOURCE_HEALTH,
            "consecutive_failures",
            3,
            "count",
            3,
            "count",
        ),
        (
            ObservationKind.SOURCE_HEALTH,
            "missing_state",
            "缺失",
            "state",
            True,
            "bool",
        ),
        (ObservationKind.VENTILATION, "airflow", 1200, "m3/min", 20.0, "m3/s"),
        (ObservationKind.VENTILATION, "pressure", 1.2, "kPa", 1200.0, "Pa"),
        (ObservationKind.VENTILATION, "main_fan_running", "运行", "", True, "bool"),
    ],
)
def test_value_normalization(
    kind: ObservationKind,
    metric: str,
    value: object,
    unit: str,
    expected_value: object,
    expected_unit: str,
) -> None:
    actual_value, actual_unit = normalize_value(kind, metric, value, unit)
    assert actual_value == pytest.approx(expected_value)
    assert actual_unit == expected_unit


def test_timestamp_uses_configured_timezone() -> None:
    assert (
        normalize_timestamp("2026-07-28T08:00:00", "+08:00")
        == "2026-07-28T00:00:00.000Z"
    )
    assert normalize_timestamp(1_774_915_200_000).endswith("Z")


def test_observation_has_stable_id_and_complete_wire_fields(
    methane_raw: dict[str, object],
) -> None:
    first = normalize_observation(
        methane_raw,
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="http_poll",
        forced_source_id="gas-gateway",
    )
    second = normalize_observation(
        methane_raw,
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="http_poll",
        forced_source_id="gas-gateway",
    )
    assert first.observation_id == second.observation_id
    wire = first.to_wire_dict()
    assert set(wire) == {
            "source_id",
            "observation_id",
            "metric_code",
            "value",
            "unit",
            "location_code",
            "observed_at",
            "received_at",
            "sequence_no",
            "revision",
            "acquisition_mode",
            "source_record_sha256",
            "source_record_id",
            "source_signature",
            "status_code",
            "quality",
            "manual_attestation",
        }
    assert len(wire["source_record_sha256"]) == 64
    assert wire["source_id"] == "gas-gateway"
    assert wire["metric_code"] == "methane.concentration_percent"
    assert wire["acquisition_mode"] == "api_poll"
    assert wire["manual_attestation"] is None
    assert set(wire["quality"]) == {
        "valid",
        "completeness",
        "timeliness",
        "device_health",
        "clock_synchronized",
        "flags",
    }


def test_manual_requires_full_provenance(methane_raw: dict[str, object]) -> None:
    methane_raw["provenance"] = {
        "channel": "manual",
        "source_id": "shift-report",
        "operator_id": "operator-1",
    }
    with pytest.raises(ValidationError, match="人工补录必须提供"):
        normalize_observation(
            methane_raw,
            default_mine_id="mine-001",
            default_timezone="+08:00",
            forced_channel="manual",
            forced_source_id="shift-report",
        )


def test_manual_is_explicitly_marked(methane_raw: dict[str, object]) -> None:
    methane_raw["provenance"] = {
        "source_id": "shift-report",
        "operator_id": "operator-1",
        "reason": "自动网关中断",
        "evidence_ref": "report-1",
    }
    observation = normalize_observation(
        methane_raw,
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="manual",
        forced_source_id="shift-report",
    )
    assert observation.quality == "manual"
    assert observation.acquisition_mode == "authenticated_manual_entry"
    assert observation.provenance.reason == "自动网关中断"
    wire = observation.to_wire_dict()
    assert wire["manual_attestation"] == {
        "actor_id": "operator-1",
        "actor_name": "operator-1",
        "recorded_at": observation.provenance.acquired_at,
        "reason": "自动网关中断",
    }


def test_airflow_wire_projection_uses_contract_unit() -> None:
    observation = normalize_observation(
        {
            "event_id": "air-1",
            "kind": "ventilation",
            "metric": "airflow",
            "value": 20,
            "unit": "m3/s",
            "location_code": "main-return",
            "observed_at": "2026-07-28T00:00:00Z",
        },
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="adapter",
        forced_source_id="fan-plc",
    )
    wire = observation.to_wire_dict()
    assert wire["metric_code"] == "ventilation.airflow_m3_min"
    assert wire["value"] == 1200
    assert wire["unit"] == "m3/min"


def test_main_fan_state_is_projected_as_binary_contract_value() -> None:
    observation = normalize_observation(
        {
            "event_id": "fan-stop-1",
            "kind": "ventilation",
            "metric": "main_fan_running",
            "value": False,
            "unit": "bool",
            "location_code": "main-fan-1",
            "observed_at": "2026-07-28T00:00:00Z",
        },
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="adapter",
        forced_source_id="fan-plc",
    )
    wire = observation.to_wire_dict()
    assert wire["metric_code"] == "ventilation.main_fan_running"
    assert wire["value"] == 0
    assert wire["unit"] == "count"


@pytest.mark.parametrize(
    (
        "kind",
        "metric",
        "value",
        "unit",
        "metric_code",
        "wire_value",
        "wire_unit",
    ),
    [
        (
            "coal_output",
            "belt_instantaneous_output",
            120.5,
            "t/h",
            "production.belt_instantaneous_t_h",
            120.5,
            "t/h",
        ),
        (
            "coal_output",
            "belt_speed",
            2.6,
            "m/s",
            "production.belt_speed_m_s",
            2.6,
            "m/s",
        ),
        (
            "coal_output",
            "belt_scale_running",
            "运行",
            "state",
            "production.belt_scale_running",
            1,
            "count",
        ),
        (
            "coal_output",
            "belt_scale_fault",
            "故障",
            "state",
            "production.belt_scale_fault",
            1,
            "count",
        ),
        (
            "personnel",
            "area_count",
            36,
            "人",
            "personnel.area_count",
            36,
            "person",
        ),
        (
            "personnel",
            "no_card_entry_count",
            2,
            "count",
            "personnel.no_card_entry_count",
            2,
            "count",
        ),
        (
            "personnel",
            "person_card_mismatch_count",
            1,
            "次",
            "personnel.person_card_mismatch_count",
            1,
            "count",
        ),
        (
            "personnel",
            "overtime_count",
            3,
            "count",
            "personnel.overtime_count",
            3,
            "count",
        ),
        (
            "explosives",
            "detonator_issued",
            20,
            "发",
            "detonator.issued_count",
            20,
            "count",
        ),
        (
            "explosives",
            "detonator_used",
            18,
            "枚",
            "detonator.used_count",
            18,
            "count",
        ),
        (
            "explosives",
            "detonator_remaining",
            2,
            "count",
            "detonator.remaining_count",
            2,
            "count",
        ),
    ],
)
def test_detailed_non_pii_metrics_project_to_wire(
    kind,
    metric,
    value,
    unit,
    metric_code,
    wire_value,
    wire_unit,
) -> None:
    observation = normalize_observation(
        {
            "event_id": f"{metric}-1",
            "kind": kind,
            "metric": metric,
            "value": value,
            "unit": unit,
            "location_code": "area-or-device-1",
            "observed_at": "2026-07-28T00:00:00Z",
        },
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="adapter",
        forced_source_id="gateway-1",
    )
    wire = observation.to_wire_dict()
    assert wire["metric_code"] == metric_code
    assert wire["value"] == pytest.approx(wire_value)
    assert wire["unit"] == wire_unit


def test_optional_interval_is_normalized_and_projected() -> None:
    observation = normalize_observation(
        {
            "kind": "personnel",
            "metric": "area_count",
            "value": 36,
            "unit": "人",
            "location_code": "working-face-101",
            "observed_at": "2026-07-28T08:05:00+08:00",
            "interval": {
                "start": "2026-07-28T08:00:00",
                "end": "2026-07-28T08:05:00",
                "timezone": "Asia/Shanghai",
                "aggregation": "snapshot",
                "shift_code": "day-A",
            },
        },
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="adapter",
        forced_source_id="personnel-gateway",
    )
    assert observation.interval is not None
    assert observation.to_wire_dict()["interval"] == {
        "start": "2026-07-28T00:00:00.000Z",
        "end": "2026-07-28T00:05:00.000Z",
        "timezone": "Asia/Shanghai",
        "aggregation": "snapshot",
        "shift_code": "day-A",
    }


@pytest.mark.parametrize(
    ("metric", "value", "unit", "metric_code", "wire_value", "wire_unit"),
    [
        (
            "heartbeat_age_seconds",
            75,
            "s",
            "source.heartbeat_age_seconds",
            75,
            "s",
        ),
        (
            "consecutive_failures",
            4,
            "count",
            "source.consecutive_failures",
            4,
            "count",
        ),
        (
            "missing_state",
            "无数据",
            "state",
            "source.missing_state",
            1,
            "count",
        ),
    ],
)
def test_source_health_metrics_use_source_as_location(
    metric,
    value,
    unit,
    metric_code,
    wire_value,
    wire_unit,
) -> None:
    observation = normalize_observation(
        {
            "event_id": f"health-{metric}",
            "kind": "source_health",
            "metric": metric,
            "value": value,
            "unit": unit,
            "location_code": "gateway-1",
            "observed_at": "2026-07-28T00:00:00Z",
        },
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="adapter",
        forced_source_id="gateway-1",
    )
    wire = observation.to_wire_dict()
    assert wire["metric_code"] == metric_code
    assert wire["value"] == pytest.approx(wire_value)
    assert wire["unit"] == wire_unit
    assert wire["location_code"] == wire["source_id"]


def test_source_health_rejects_ambiguous_location() -> None:
    with pytest.raises(ValidationError, match="location_code"):
        normalize_observation(
            {
                "kind": "source_health",
                "metric": "missing_state",
                "value": 1,
                "unit": "count",
                "location_code": "some-other-device",
                "observed_at": "2026-07-28T00:00:00Z",
            },
            default_mine_id="mine-001",
            default_timezone="+08:00",
            forced_channel="adapter",
            forced_source_id="gateway-1",
        )


@pytest.mark.parametrize(
    "interval",
    [
        {
            "start": "2026-07-28T08:05:00+08:00",
            "end": "2026-07-28T08:00:00+08:00",
            "aggregation": "snapshot",
        },
        {
            "start": "2026-07-28T08:00:00+08:00",
            "end": "2026-07-28T08:05:00+08:00",
            "aggregation": "made_up",
        },
        {
            "start": "2026-07-28T08:00:00+08:00",
            "end": "2026-07-28T08:05:00+08:00",
            "aggregation": "snapshot",
            "person_id": "forbidden-pii",
        },
    ],
)
def test_invalid_interval_fails_closed(interval) -> None:
    with pytest.raises(ValidationError, match="interval"):
        normalize_observation(
            {
                "kind": "personnel",
                "metric": "area_count",
                "value": 1,
                "unit": "person",
                "observed_at": "2026-07-28T08:05:00+08:00",
                "interval": interval,
            },
            default_mine_id="mine-001",
            default_timezone="+08:00",
            forced_channel="adapter",
            forced_source_id="personnel-gateway",
        )


@pytest.mark.parametrize(
    ("value", "unit"),
    [(1.5, "count"), (2, "kg")],
)
def test_detonator_count_is_never_treated_as_explosive_mass(value, unit) -> None:
    with pytest.raises(ValidationError, match="雷管"):
        normalize_value(
            ObservationKind.EXPLOSIVES,
            "detonator.used_count",
            value,
            unit,
        )


@pytest.mark.parametrize(
    "raw",
    [
        {"kind": "unknown"},
        {
            "kind": "personnel",
            "metric": "count",
            "value": 1.2,
            "unit": "人",
            "observed_at": "2026-01-01T00:00:00Z",
        },
        {
            "kind": "methane",
            "metric": "gas",
            "value": float("nan"),
            "unit": "%",
            "observed_at": "2026-01-01T00:00:00Z",
        },
    ],
)
def test_invalid_values_fail_closed(raw: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        normalize_observation(
            raw,
            default_mine_id="mine-001",
            default_timezone="+08:00",
            forced_channel="test",
            forced_source_id="test-source",
        )
