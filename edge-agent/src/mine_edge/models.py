"""Local domain and wire objects.

The objects in this package deliberately do not import the regulatory platform.
They form a small, versioned edge wire protocol that can later be mapped at the
HTTP boundary.
"""

from __future__ import annotations

import dataclasses
import enum
from datetime import UTC, datetime
from typing import Any

from .errors import ValidationError

JsonScalar = str | int | float | bool | None

_WIRE_METRICS = {
    "production.output_t",
    "production.belt_instantaneous_t_h",
    "production.belt_speed_m_s",
    "production.belt_scale_running",
    "production.belt_scale_fault",
    "electricity.total_kwh",
    "electricity.production_kwh",
    "electricity.ventilation_kwh",
    "electricity.drainage_kwh",
    "electricity.compressed_air_kwh",
    "electricity.hoisting_kwh",
    "electricity.wash_plant_kwh",
    "personnel.underground_count",
    "personnel.area_count",
    "personnel.unauthorized_entry_count",
    "personnel.no_card_entry_count",
    "personnel.person_card_mismatch_count",
    "personnel.overtime_count",
    "methane.concentration_percent",
    "ventilation.airflow_m3_min",
    "ventilation.pressure_pa",
    "ventilation.speed_m_s",
    "ventilation.main_fan_running",
    "ventilation.main_fan_fault",
    "ventilation.main_fan_changeover",
    "explosive.issued_kg",
    "explosive.used_kg",
    "explosive.remaining_kg",
    "detonator.issued_count",
    "detonator.used_count",
    "detonator.remaining_count",
    "source.heartbeat_age_seconds",
    "source.consecutive_failures",
    "source.missing_state",
    "coal.use_t",
    "transport.shipped_t",
    "sales.invoice_t",
}


INTERVAL_AGGREGATIONS = frozenset(
    {
        "window_total",
        "interval_delta",
        "cumulative_register",
        "snapshot",
        "instantaneous_rate",
    }
)


class ObservationKind(enum.StrEnum):
    """Six business classes plus source-health transport telemetry."""

    COAL_OUTPUT = "coal_output"
    ELECTRICITY = "electricity"
    PERSONNEL = "personnel"
    METHANE = "methane"
    EXPLOSIVES = "explosives"
    VENTILATION = "ventilation"
    SOURCE_HEALTH = "source_health"


class AlertLevel(enum.StrEnum):
    BLUE = "blue"
    YELLOW = "yellow"
    ORANGE = "orange"
    RED = "red"

    @property
    def rank(self) -> int:
        return {
            AlertLevel.BLUE: 1,
            AlertLevel.YELLOW: 2,
            AlertLevel.ORANGE: 3,
            AlertLevel.RED: 4,
        }[self]


@dataclasses.dataclass(frozen=True, slots=True)
class Provenance:
    """Traceable origin of an observation.

    Manual data is never allowed to masquerade as a sensor reading.  It must
    contain operator, reason and evidence fields.
    """

    channel: str
    source_id: str
    source_event_id: str | None = None
    acquired_at: str | None = None
    operator_id: str | None = None
    operator_name: str | None = None
    reason: str | None = None
    evidence_ref: str | None = None
    original_unit: str | None = None
    original_value: JsonScalar = None

    def __post_init__(self) -> None:
        if not self.channel.strip():
            raise ValidationError("provenance.channel 不能为空")
        if not self.source_id.strip():
            raise ValidationError("provenance.source_id 不能为空")
        if self.channel == "manual":
            missing = [
                name
                for name, value in (
                    ("operator_id", self.operator_id),
                    ("reason", self.reason),
                    ("evidence_ref", self.evidence_ref),
                )
                if not value or not value.strip()
            ]
            if missing:
                raise ValidationError(
                    "人工补录必须提供 "
                    + ", ".join(f"provenance.{item}" for item in missing)
                )

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class IntervalWindow:
    start: str
    end: str
    timezone: str
    aggregation: str
    shift_code: str | None = None

    def __post_init__(self) -> None:
        if not self.start or not self.end:
            raise ValidationError("interval.start/end 不能为空")
        if not self.timezone or len(self.timezone) > 64:
            raise ValidationError("interval.timezone 长度必须为 1-64")
        if self.aggregation not in INTERVAL_AGGREGATIONS:
            raise ValidationError("interval.aggregation 枚举值无效")
        if self.shift_code is not None and not 1 <= len(self.shift_code) <= 64:
            raise ValidationError("interval.shift_code 长度必须为 1-64")

    def to_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        if self.shift_code is None:
            result.pop("shift_code")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class Observation:
    observation_id: str
    mine_id: str
    kind: ObservationKind
    metric: str
    value: JsonScalar
    unit: str
    observed_at: str
    received_at: str
    provenance: Provenance
    location_code: str = "unknown"
    sequence_no: int = 0
    revision: int = 0
    acquisition_mode: str = "automatic_adapter"
    source_record_sha256: str = ""
    source_record_id: str = ""
    source_signature: str | None = None
    status_code: str | None = None
    quality_detail: dict[str, Any] = dataclasses.field(default_factory=dict)
    quality: str = "raw"
    metadata: dict[str, JsonScalar] = dataclasses.field(default_factory=dict)
    interval: IntervalWindow | None = None

    def __post_init__(self) -> None:
        for name in ("observation_id", "mine_id", "metric", "observed_at", "received_at"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"{name} 不能为空")
        if self.quality not in {"raw", "normalized", "manual"}:
            raise ValidationError("quality 必须为 raw、normalized 或 manual")
        if self.sequence_no < 0:
            raise ValidationError("sequence_no 不得小于零")
        if self.revision < 0:
            raise ValidationError("revision 必须大于等于 0")
        if self.sequence_no > 9_007_199_254_740_991:
            raise ValidationError("sequence_no 超出 JSON 安全整数范围")
        if self.revision > 9_007_199_254_740_991:
            raise ValidationError("revision 超出 JSON 安全整数范围")
        if self.acquisition_mode not in {
            "automatic_adapter",
            "file_drop",
            "api_poll",
            "authenticated_manual_entry",
        }:
            raise ValidationError(
                "acquisition_mode 不符合 edge-telemetry-batch-v1"
            )
        if len(self.source_record_sha256) != 64 or any(
            item not in "0123456789abcdef" for item in self.source_record_sha256
        ):
            raise ValidationError("source_record_sha256 必须是 64 位小写 SHA-256")
        if not self.source_record_id or len(self.source_record_id) > 256:
            raise ValidationError("source_record_id 长度必须为 1-256")
        if self.source_signature is not None and (
            len(self.source_signature) != 64
            or any(item not in "0123456789abcdef" for item in self.source_signature)
        ):
            raise ValidationError("source_signature 必须是 64 位小写 SHA-256")

    def to_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        result["kind"] = self.kind.value
        return result

    def to_wire_dict(self) -> dict[str, Any]:
        """Return the stable edge-telemetry-batch-v1 observation shape."""

        metric_code, wire_value, wire_unit = self._wire_measurement()
        manual_attestation = None
        if self.acquisition_mode == "authenticated_manual_entry":
            manual_attestation = {
                "actor_id": self.provenance.operator_id,
                "actor_name": (
                    self.provenance.operator_name or self.provenance.operator_id
                ),
                "recorded_at": self.provenance.acquired_at,
                "reason": self.provenance.reason,
            }
        result = {
            "source_id": self.provenance.source_id,
            "observation_id": self.observation_id,
            "metric_code": metric_code,
            "value": wire_value,
            "unit": wire_unit,
            "location_code": self.location_code,
            "observed_at": self.observed_at,
            "received_at": self.received_at,
            "sequence_no": self.sequence_no,
            "revision": self.revision,
            "acquisition_mode": self.acquisition_mode,
            "source_record_id": self.source_record_id,
            "source_record_sha256": self.source_record_sha256,
            "source_signature": self.source_signature,
            "status_code": self.status_code,
            "quality": self.quality_detail,
            "manual_attestation": manual_attestation,
        }
        if self.interval is not None:
            result["interval"] = self.interval.to_dict()
        return result

    def wire_supported(self) -> bool:
        try:
            self._wire_measurement()
        except ValidationError:
            return False
        return True

    def _wire_measurement(self) -> tuple[str, float, str]:
        aliases = {
            (ObservationKind.COAL_OUTPUT, "output"): "production.output_t",
            (ObservationKind.COAL_OUTPUT, "raw_coal_output"): "production.output_t",
            (ObservationKind.COAL_OUTPUT, "coal_output"): "production.output_t",
            (
                ObservationKind.COAL_OUTPUT,
                "belt_instantaneous_output",
            ): "production.belt_instantaneous_t_h",
            (
                ObservationKind.COAL_OUTPUT,
                "belt_flow",
            ): "production.belt_instantaneous_t_h",
            (
                ObservationKind.COAL_OUTPUT,
                "belt_speed",
            ): "production.belt_speed_m_s",
            (
                ObservationKind.COAL_OUTPUT,
                "belt_scale_running",
            ): "production.belt_scale_running",
            (
                ObservationKind.COAL_OUTPUT,
                "belt_scale_fault",
            ): "production.belt_scale_fault",
            (ObservationKind.ELECTRICITY, "energy"): "electricity.total_kwh",
            (ObservationKind.ELECTRICITY, "active_energy"): "electricity.total_kwh",
            (ObservationKind.ELECTRICITY, "total_kwh"): "electricity.total_kwh",
            (ObservationKind.PERSONNEL, "count"): "personnel.underground_count",
            (
                ObservationKind.PERSONNEL,
                "underground_count",
            ): "personnel.underground_count",
            (
                ObservationKind.PERSONNEL,
                "area_count",
            ): "personnel.area_count",
            (
                ObservationKind.PERSONNEL,
                "unauthorized_entry_count",
            ): "personnel.unauthorized_entry_count",
            (
                ObservationKind.PERSONNEL,
                "no_card_entry_count",
            ): "personnel.no_card_entry_count",
            (
                ObservationKind.PERSONNEL,
                "no_card_count",
            ): "personnel.no_card_entry_count",
            (
                ObservationKind.PERSONNEL,
                "person_card_mismatch_count",
            ): "personnel.person_card_mismatch_count",
            (
                ObservationKind.PERSONNEL,
                "overtime_count",
            ): "personnel.overtime_count",
            (ObservationKind.METHANE, "gas"): "methane.concentration_percent",
            (
                ObservationKind.METHANE,
                "methane_concentration",
            ): "methane.concentration_percent",
            (ObservationKind.EXPLOSIVES, "used"): "explosive.used_kg",
            (
                ObservationKind.EXPLOSIVES,
                "explosive_consumed",
            ): "explosive.used_kg",
            (
                ObservationKind.EXPLOSIVES,
                "explosive_issued",
            ): "explosive.issued_kg",
            (
                ObservationKind.EXPLOSIVES,
                "explosive_remaining",
            ): "explosive.remaining_kg",
            (
                ObservationKind.EXPLOSIVES,
                "detonator_issued",
            ): "detonator.issued_count",
            (
                ObservationKind.EXPLOSIVES,
                "detonator_used",
            ): "detonator.used_count",
            (
                ObservationKind.EXPLOSIVES,
                "detonator_remaining",
            ): "detonator.remaining_count",
            (ObservationKind.VENTILATION, "airflow"): "ventilation.airflow_m3_min",
            (ObservationKind.VENTILATION, "pressure"): "ventilation.pressure_pa",
            (ObservationKind.VENTILATION, "speed"): "ventilation.speed_m_s",
            (
                ObservationKind.VENTILATION,
                "main_fan_running",
            ): "ventilation.main_fan_running",
            (
                ObservationKind.VENTILATION,
                "fan_running",
            ): "ventilation.main_fan_running",
            (
                ObservationKind.VENTILATION,
                "main_fan_fault",
            ): "ventilation.main_fan_fault",
            (
                ObservationKind.VENTILATION,
                "main_fan_changeover",
            ): "ventilation.main_fan_changeover",
            (
                ObservationKind.SOURCE_HEALTH,
                "heartbeat_age",
            ): "source.heartbeat_age_seconds",
            (
                ObservationKind.SOURCE_HEALTH,
                "heartbeat_age_seconds",
            ): "source.heartbeat_age_seconds",
            (
                ObservationKind.SOURCE_HEALTH,
                "consecutive_failures",
            ): "source.consecutive_failures",
            (
                ObservationKind.SOURCE_HEALTH,
                "missing_state",
            ): "source.missing_state",
        }
        metric_code = (
            self.metric
            if self.metric in _WIRE_METRICS
            else aliases.get((self.kind, self.metric))
        )
        if metric_code is None:
            raise ValidationError(
                f"指标 {self.metric!r} 不能投影到 edge-telemetry-batch-v1"
            )
        binary_metric = metric_code.startswith(
            ("ventilation.main_fan", "production.belt_scale_")
        ) or metric_code == "source.missing_state"
        source_health_metric = metric_code.startswith("source.")
        if source_health_metric and self.location_code != self.provenance.source_id:
            raise ValidationError(
                "source.* 指标的 location_code 必须等于 source_id"
            )
        if isinstance(self.value, bool) and binary_metric:
            value = float(self.value)
        elif isinstance(self.value, bool) or not isinstance(
            self.value, (int, float)
        ):
            raise ValidationError("上行合同只接受数值观测")
        else:
            value = float(self.value)
        if not -1e15 <= value <= 1e15:
            raise ValidationError("上行数值超出合同范围")
        unit = self.unit
        if metric_code == "ventilation.airflow_m3_min" and unit == "m3/s":
            value *= 60
            unit = "m3/min"
        if binary_metric:
            unit = "count"
        exact_units = {
            "production.belt_instantaneous_t_h": "t/h",
            "production.belt_speed_m_s": "m/s",
            "production.belt_scale_running": "count",
            "production.belt_scale_fault": "count",
            "personnel.area_count": "person",
            "personnel.unauthorized_entry_count": "count",
            "personnel.no_card_entry_count": "count",
            "personnel.person_card_mismatch_count": "count",
            "personnel.overtime_count": "count",
            "source.heartbeat_age_seconds": "s",
            "source.consecutive_failures": "count",
            "source.missing_state": "count",
        }
        expected = exact_units.get(metric_code)
        if expected is None:
            expected_units = {
                "production.": "t",
                "electricity.": "kWh",
                "personnel.": "person",
                "methane.": "%",
                "ventilation.airflow": "m3/min",
                "ventilation.pressure": "Pa",
                "ventilation.speed": "m/s",
                "ventilation.main_fan": "count",
                "explosive.": "kg",
                "detonator.": "count",
                "coal.": "t",
                "transport.": "t",
                "sales.": "t",
            }
            expected = next(
                (
                    required
                    for prefix, required in expected_units.items()
                    if metric_code.startswith(prefix)
                ),
                None,
            )
        if expected is not None and unit != expected:
            raise ValidationError(
                f"指标 {metric_code} 的上行单位必须为 {expected}"
            )
        if (
            metric_code.startswith("detonator.")
            or metric_code.startswith("personnel.")
            or metric_code in {
                "source.consecutive_failures",
                "source.missing_state",
            }
            or binary_metric
        ) and not value.is_integer():
            raise ValidationError(f"指标 {metric_code} 必须使用整数值")
        if binary_metric and value not in {0.0, 1.0}:
            raise ValidationError(f"指标 {metric_code} 必须为 0 或 1")
        return metric_code, value, unit


@dataclasses.dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    mine_id: str
    observation_id: str
    rule_id: str
    level: AlertLevel
    title: str
    message: str
    triggered_at: str
    measured_value: JsonScalar
    threshold: JsonScalar
    unit: str
    location_code: str
    status: str = "open"

    def to_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        result["level"] = self.level.value
        return result

    def to_wire_dict(self) -> dict[str, Any]:
        return {
            "local_alert_id": self.alert_id,
            "rule_code": self.rule_id,
            "level": self.level.value,
            "detected_at": self.triggered_at,
            "location_code": self.location_code,
            "observation_ids": [self.observation_id],
            "summary": self.message,
            "advisory_only": True,
        }


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
