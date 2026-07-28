"""Strict timestamp, scalar and unit normalization."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import ValidationError
from .models import (
    INTERVAL_AGGREGATIONS,
    IntervalWindow,
    JsonScalar,
    Observation,
    ObservationKind,
    Provenance,
    utc_now,
)

_TZ_PATTERN = re.compile(r"^([+-])(\d{2}):(\d{2})$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHIFT_CODE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_TIMEZONE_NAME_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9._+-]*(?:/[A-Za-z0-9._+-]+)+$"
)

_BELT_RATE_METRICS = {
    "belt_instantaneous_output",
    "belt_flow",
    "production.belt_instantaneous_t_h",
}
_BELT_SPEED_METRICS = {
    "belt_speed",
    "production.belt_speed_m_s",
}
_BELT_RUNNING_METRICS = {
    "belt_scale_running",
    "production.belt_scale_running",
}
_BELT_FAULT_METRICS = {
    "belt_scale_fault",
    "production.belt_scale_fault",
}
_PERSONNEL_EVENT_COUNT_METRICS = {
    "unauthorized_entry_count",
    "personnel.unauthorized_entry_count",
    "no_card_count",
    "no_card_entry_count",
    "personnel.no_card_entry_count",
    "person_card_mismatch_count",
    "personnel.person_card_mismatch_count",
    "overtime_count",
    "personnel.overtime_count",
}
_DETONATOR_METRICS = {
    "detonator_issued",
    "detonator_used",
    "detonator_remaining",
    "detonator.issued_count",
    "detonator.used_count",
    "detonator.remaining_count",
}
_SOURCE_HEARTBEAT_METRICS = {
    "heartbeat_age",
    "heartbeat_age_seconds",
    "source.heartbeat_age_seconds",
}
_SOURCE_FAILURE_METRICS = {
    "consecutive_failures",
    "source.consecutive_failures",
}
_SOURCE_MISSING_METRICS = {
    "missing_state",
    "source.missing_state",
}

_UNIT_ALIASES = {
    "吨": "t",
    "ton": "t",
    "tonne": "t",
    "t": "t",
    "千克": "kg",
    "公斤": "kg",
    "kg": "kg",
    "g": "g",
    "kwh": "kWh",
    "千瓦时": "kWh",
    "mwh": "MWh",
    "wh": "Wh",
    "人": "person",
    "persons": "person",
    "person": "person",
    "count": "count",
    "个": "count",
    "次": "count",
    "发": "count",
    "枚": "count",
    "%": "%",
    "percent": "%",
    "百分比": "%",
    "fraction": "fraction",
    "ppm": "ppm",
    "m³/s": "m3/s",
    "m3/s": "m3/s",
    "m³/min": "m3/min",
    "m3/min": "m3/min",
    "pa": "Pa",
    "kpa": "kPa",
    "bool": "bool",
    "state": "state",
    "ratio": "ratio",
    "m/s": "m/s",
    "t/h": "t/h",
    "tph": "t/h",
    "吨/小时": "t/h",
    "吨/时": "t/h",
    "kg/h": "kg/h",
    "千克/小时": "kg/h",
    "s": "s",
    "sec": "s",
    "second": "s",
    "seconds": "s",
    "秒": "s",
    "ms": "ms",
    "millisecond": "ms",
    "milliseconds": "ms",
    "毫秒": "ms",
    "min": "min",
    "minute": "min",
    "minutes": "min",
    "分钟": "min",
    "": "",
}


def _timezone(value: str) -> tzinfo:
    match = _TZ_PATTERN.fullmatch(value.strip())
    if match:
        sign, hours, minutes = match.groups()
        hour = int(hours)
        minute = int(minutes)
        if hour > 23 or minute > 59:
            raise ValidationError("本地时区偏移无效")
        delta = timedelta(hours=hour, minutes=minute)
        if sign == "-":
            delta = -delta
        return timezone(delta)
    name = value.strip()
    if name == "UTC" or _TIMEZONE_NAME_PATTERN.fullmatch(name):
        try:
            return ZoneInfo(name)
        except ZoneInfoNotFoundError as error:
            raise ValidationError(f"未知 IANA 时区：{name}") from error
    raise ValidationError("时区必须采用 +08:00、UTC 或 IANA 名称")


def normalize_timestamp(value: Any, default_timezone: str = "+08:00") -> str:
    if isinstance(value, bool):
        raise ValidationError("时间戳不能是布尔值")
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 10_000_000_000:
            seconds /= 1000
        try:
            parsed = datetime.fromtimestamp(seconds, UTC)
        except (OverflowError, OSError, ValueError) as error:
            raise ValidationError("Unix 时间戳超出范围") from error
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as error:
            raise ValidationError("observed_at 必须是 ISO-8601 或 Unix 时间戳") from error
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_timezone(default_timezone))
    else:
        raise ValidationError("observed_at 不能为空")
    return parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _finite_number(value: Any) -> float:
    if isinstance(value, bool):
        raise ValidationError("数值指标不能是布尔值")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValidationError(f"指标值不是有效数值：{value!r}") from error
    if not math.isfinite(result):
        raise ValidationError("指标值必须是有限数")
    return result


def _binary_value(value: Any, *, fault_semantics: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = _finite_number(value)
        if numeric in {0.0, 1.0}:
            return bool(numeric)
    normalized = str(value).strip().lower()
    if fault_semantics:
        true_values = {"1", "true", "on", "fault", "故障", "alarm", "报警"}
        false_values = {
            "0",
            "false",
            "off",
            "normal",
            "healthy",
            "正常",
            "无故障",
        }
    else:
        true_values = {"1", "true", "on", "running", "运行"}
        false_values = {"0", "false", "off", "stopped", "停机", "停止"}
    if normalized in true_values:
        return True
    if normalized in false_values:
        return False
    raise ValidationError("二值状态必须为 0/1、布尔值或受支持的状态枚举")


def _missing_state_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric = _finite_number(value)
        if numeric in {0.0, 1.0}:
            return bool(numeric)
    normalized = str(value).strip().lower()
    if normalized in {
        "1",
        "true",
        "missing",
        "absent",
        "stale",
        "缺失",
        "断流",
        "无数据",
    }:
        return True
    if normalized in {
        "0",
        "false",
        "present",
        "available",
        "healthy",
        "正常",
        "有数据",
    }:
        return False
    raise ValidationError("缺数状态必须为 0/1、布尔值或受支持的缺数状态枚举")


def _canonical_unit(unit: Any) -> str:
    if unit is None:
        return ""
    text = str(unit).strip()
    result = _UNIT_ALIASES.get(text.lower())
    if result is None:
        result = _UNIT_ALIASES.get(text)
    if result is None:
        raise ValidationError(f"不支持的单位：{text!r}")
    return result


def normalize_value(
    kind: ObservationKind,
    metric: str,
    value: Any,
    unit: Any,
) -> tuple[JsonScalar, str]:
    canonical = _canonical_unit(unit)
    if kind is ObservationKind.COAL_OUTPUT:
        if metric in _BELT_RUNNING_METRICS | _BELT_FAULT_METRICS:
            if canonical not in {"", "bool", "state", "count"}:
                raise ValidationError("皮带秤状态单位必须为 bool/state/count")
            return _binary_value(
                value,
                fault_semantics=metric in _BELT_FAULT_METRICS,
            ), "bool"
        number = _finite_number(value)
        if number < 0:
            raise ValidationError("产量或皮带指标不得为负数")
        if metric in _BELT_SPEED_METRICS:
            if canonical != "m/s":
                raise ValidationError("皮带速度单位必须为 m/s")
            return number, "m/s"
        if metric in _BELT_RATE_METRICS:
            factors = {"t/h": 1.0, "kg/h": 0.001}
            if canonical not in factors:
                raise ValidationError("皮带瞬时产量单位必须为 t/h 或 kg/h")
            return number * factors[canonical], "t/h"
        factors = {"t": 1.0, "kg": 0.001}
        if canonical not in factors:
            raise ValidationError("产煤量单位必须为 t 或 kg")
        return number * factors[canonical], "t"
    if kind is ObservationKind.ELECTRICITY:
        number = _finite_number(value)
        if number < 0:
            raise ValidationError("电量不得为负数")
        factors = {"kWh": 1.0, "MWh": 1000.0, "Wh": 0.001}
        if canonical not in factors:
            raise ValidationError("电量单位必须为 Wh、kWh 或 MWh")
        return number * factors[canonical], "kWh"
    if kind is ObservationKind.PERSONNEL:
        number = _finite_number(value)
        if canonical not in {"person", "count"}:
            raise ValidationError("人员数量单位必须为 person/人或 count")
        if number < 0 or not number.is_integer():
            raise ValidationError("人员数量必须为非负整数")
        return (
            (int(number), "count")
            if metric in _PERSONNEL_EVENT_COUNT_METRICS
            else (int(number), "person")
        )
    if kind is ObservationKind.METHANE:
        number = _finite_number(value)
        if canonical == "fraction":
            number *= 100
        elif canonical == "ppm":
            number /= 10_000
        elif canonical != "%":
            raise ValidationError("甲烷浓度单位必须为 %、fraction 或 ppm")
        if not 0 <= number <= 100:
            raise ValidationError("甲烷浓度必须在 0%-100% 范围内")
        return number, "%"
    if kind is ObservationKind.EXPLOSIVES:
        number = _finite_number(value)
        if number < 0:
            raise ValidationError("火工品数量不得为负数")
        if metric in _DETONATOR_METRICS:
            if canonical != "count":
                raise ValidationError("雷管数量单位必须为 count/发/枚")
            if not number.is_integer():
                raise ValidationError("雷管数量必须为非负整数")
            return int(number), "count"
        factors = {"kg": 1.0, "t": 1000.0, "g": 0.001}
        if canonical not in factors:
            raise ValidationError("火工品质量单位必须为 g、kg 或 t")
        return number * factors[canonical], "kg"
    if kind is ObservationKind.VENTILATION:
        if metric in {
            "main_fan_running",
            "fan_running",
            "main_fan_fault",
            "main_fan_changeover",
            "ventilation.main_fan_running",
            "ventilation.main_fan_fault",
            "ventilation.main_fan_changeover",
        }:
            if canonical not in {"", "bool", "state", "count"}:
                raise ValidationError("风机状态单位必须为 bool/state/count")
            return _binary_value(
                value,
                fault_semantics=metric
                in {"main_fan_fault", "ventilation.main_fan_fault"},
            ), "bool"
        number = _finite_number(value)
        if number < 0:
            raise ValidationError("通风指标不得为负数")
        if metric.endswith("_ratio") or metric == "airflow_ratio":
            if canonical not in {"ratio", ""}:
                raise ValidationError("风量比单位必须为 ratio")
            return number, "ratio"
        factors = {"m3/s": 1.0, "m3/min": 1 / 60, "Pa": 1.0, "kPa": 1000.0}
        if canonical == "m/s":
            return number, "m/s"
        target = {"m3/s": "m3/s", "m3/min": "m3/s", "Pa": "Pa", "kPa": "Pa"}
        if canonical not in factors:
            raise ValidationError(
                "通风指标单位必须为 m3/s、m3/min、Pa、kPa 或 m/s"
            )
        return number * factors[canonical], target[canonical]
    if kind is ObservationKind.SOURCE_HEALTH:
        if metric in _SOURCE_MISSING_METRICS:
            if canonical not in {"", "bool", "state", "count"}:
                raise ValidationError("缺数状态单位必须为 bool/state/count")
            return _missing_state_value(value), "bool"
        number = _finite_number(value)
        if number < 0:
            raise ValidationError("数据源健康指标不得为负数")
        if metric in _SOURCE_HEARTBEAT_METRICS:
            factors = {"s": 1.0, "ms": 0.001, "min": 60.0}
            if canonical not in factors:
                raise ValidationError("心跳时延单位必须为 s、ms 或 min")
            return number * factors[canonical], "s"
        if metric in _SOURCE_FAILURE_METRICS:
            if canonical != "count":
                raise ValidationError("连续失败次数单位必须为 count")
            if not number.is_integer():
                raise ValidationError("连续失败次数必须为非负整数")
            return int(number), "count"
        raise ValidationError(f"不支持的数据源健康指标：{metric}")
    raise ValidationError(f"不支持的观测类别：{kind}")


def normalize_interval(
    value: Any,
    *,
    default_timezone: str,
) -> IntervalWindow | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError("interval 必须是对象")
    allowed = {"start", "end", "timezone", "aggregation", "shift_code"}
    unknown = set(value) - allowed
    if unknown:
        raise ValidationError(
            "interval 包含未知字段：" + ", ".join(sorted(unknown))
        )
    timezone_value = value.get("timezone")
    if not isinstance(timezone_value, str) or not timezone_value.strip():
        raise ValidationError("interval.timezone 不能为空")
    timezone_name = timezone_value.strip()
    _timezone(timezone_name)
    if len(timezone_name) > 64:
        raise ValidationError("interval.timezone 最长 64 字符")
    aggregation = str(value.get("aggregation") or "").strip()
    if aggregation not in INTERVAL_AGGREGATIONS:
        raise ValidationError(
            "interval.aggregation 必须为 " + "、".join(sorted(INTERVAL_AGGREGATIONS))
        )
    start = normalize_timestamp(value.get("start"), timezone_name)
    end = normalize_timestamp(value.get("end"), timezone_name)
    start_time = datetime.fromisoformat(start.replace("Z", "+00:00"))
    end_time = datetime.fromisoformat(end.replace("Z", "+00:00"))
    if end_time <= start_time:
        raise ValidationError("interval.end 必须晚于 interval.start")
    shift_code = _optional_text(value.get("shift_code"))
    if (
        shift_code is not None
        and _SHIFT_CODE_PATTERN.fullmatch(shift_code) is None
    ):
        raise ValidationError("interval.shift_code 必须是最长 64 字符的安全标识符")
    return IntervalWindow(
        start=start,
        end=end,
        timezone=timezone_name,
        aggregation=aggregation,
        shift_code=shift_code,
    )


def _metadata(value: Any) -> dict[str, JsonScalar]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError("metadata 必须是对象")
    result: dict[str, JsonScalar] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ValidationError("metadata 键必须为非空字符串")
        if item is not None and not isinstance(item, (str, int, float, bool)):
            raise ValidationError("metadata 值只能是标量")
        if isinstance(item, float) and not math.isfinite(item):
            raise ValidationError("metadata 浮点值必须为有限数")
        result[key] = item
    return result


def normalize_observation(
    raw: dict[str, Any],
    *,
    default_mine_id: str,
    default_timezone: str,
    forced_channel: str | None = None,
    forced_source_id: str | None = None,
) -> Observation:
    if not isinstance(raw, dict):
        raise ValidationError("观测必须是 JSON 对象")
    try:
        kind = ObservationKind(str(raw.get("kind", "")).strip())
    except ValueError as error:
        allowed = ", ".join(item.value for item in ObservationKind)
        raise ValidationError(f"kind 必须为受支持类别之一：{allowed}") from error
    metric = str(raw.get("metric", "")).strip()
    if not metric:
        raise ValidationError("metric 不能为空")
    observed_at = normalize_timestamp(raw.get("observed_at"), default_timezone)
    interval = normalize_interval(
        raw.get("interval"),
        default_timezone=default_timezone,
    )
    original_value = raw.get("value")
    original_unit = "" if raw.get("unit") is None else str(raw.get("unit"))
    value, unit = normalize_value(kind, metric, original_value, original_unit)
    provenance_raw = raw.get("provenance") or {}
    if not isinstance(provenance_raw, dict):
        raise ValidationError("provenance 必须是对象")
    channel = forced_channel or str(provenance_raw.get("channel", "")).strip()
    source_id = forced_source_id or str(provenance_raw.get("source_id", "")).strip()
    source_event_id_raw = provenance_raw.get("source_event_id", raw.get("event_id"))
    source_event_id = (
        str(source_event_id_raw).strip() if source_event_id_raw is not None else None
    )
    if source_event_id == "":
        source_event_id = None
    acquired_at = normalize_timestamp(
        provenance_raw.get("acquired_at", utc_now()), default_timezone
    )
    provenance = Provenance(
        channel=channel,
        source_id=source_id,
        source_event_id=source_event_id,
        acquired_at=acquired_at,
        operator_id=_optional_text(provenance_raw.get("operator_id")),
        operator_name=_optional_text(provenance_raw.get("operator_name")),
        reason=_optional_text(provenance_raw.get("reason")),
        evidence_ref=_optional_text(provenance_raw.get("evidence_ref")),
        original_unit=original_unit,
        original_value=original_value
        if original_value is None or isinstance(original_value, (str, int, float, bool))
        else str(original_value),
    )
    if channel == "manual":
        if (
            provenance.operator_id is None
            or _IDENTIFIER_PATTERN.fullmatch(provenance.operator_id) is None
        ):
            raise ValidationError("人工补录 operator_id 必须是安全合同标识符")
        if provenance.operator_name is not None and len(provenance.operator_name) > 128:
            raise ValidationError("人工补录 operator_name 最长 128 字符")
        if provenance.reason is not None and len(provenance.reason) > 1000:
            raise ValidationError("人工补录 reason 最长 1000 字符")
    mine_id = str(raw.get("mine_id") or default_mine_id).strip()
    if not mine_id:
        raise ValidationError("mine_id 不能为空")
    if _IDENTIFIER_PATTERN.fullmatch(mine_id) is None:
        raise ValidationError("mine_id 必须是安全的合同标识符")
    if _IDENTIFIER_PATTERN.fullmatch(source_id) is None:
        raise ValidationError("source_id 必须是安全的合同标识符")
    try:
        sequence_no = int(raw.get("sequence_no", 0))
        revision = int(raw.get("revision", 0))
    except (TypeError, ValueError) as error:
        raise ValidationError("sequence_no 和 revision 必须是整数") from error
    default_mode = {
        "manual": "authenticated_manual_entry",
        "jsonl": "file_drop",
        "file_drop": "file_drop",
        "http_poll": "api_poll",
        "http_ingest": "api_poll",
    }.get(channel, "automatic_adapter")
    acquisition_mode = str(raw.get("acquisition_mode", default_mode)).strip()
    raw_digest = hashlib.sha256(
        json.dumps(
            raw,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    supplied_digest = str(raw.get("source_record_sha256") or raw_digest).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_digest):
        raise ValidationError("source_record_sha256 必须是 64 位十六进制 SHA-256")
    source_record_id = str(
        raw.get("source_record_id")
        or source_event_id
        or f"{source_id}:{raw_digest[:32]}"
    ).strip()
    if not source_record_id or len(source_record_id) > 256:
        raise ValidationError("source_record_id 长度必须为 1-256")
    source_signature = _optional_text(raw.get("source_signature"))
    if source_signature is not None:
        source_signature = source_signature.lower()
        if re.fullmatch(r"[0-9a-f]{64}", source_signature) is None:
            raise ValidationError("source_signature 必须是 64 位十六进制 SHA-256")
    status_code = _optional_text(
        raw.get("status_code")
        or (
            raw.get("metadata", {}).get("device_status")
            if isinstance(raw.get("metadata"), dict)
            else None
        )
    )
    if status_code is not None and len(status_code) > 64:
        raise ValidationError("status_code 最长 64 字符")
    location_code = str(raw.get("location_code") or "unknown").strip()
    if not location_code or len(location_code) > 128:
        raise ValidationError("location_code 长度必须为 1-128")
    if kind is ObservationKind.SOURCE_HEALTH and location_code != source_id:
        raise ValidationError(
            "source_health 的 location_code 必须等于 source_id"
        )
    identity = source_event_id or _digest(
        {
            "mine_id": mine_id,
            "kind": kind.value,
            "metric": metric,
            "value": value,
            "unit": unit,
            "observed_at": observed_at,
            "channel": channel,
            "source_id": source_id,
            "interval": None if interval is None else interval.to_dict(),
        }
    )
    observation_id = f"obs_{_digest({'source_id': source_id, 'identity': identity})}"
    received_at = utc_now()
    if observed_at > received_at:
        raise ValidationError("observed_at 不得晚于边缘节点接收时间")
    if interval is not None and interval.end > received_at:
        raise ValidationError("interval.end 不得晚于边缘节点接收时间")
    return Observation(
        observation_id=observation_id,
        mine_id=mine_id,
        kind=kind,
        metric=metric,
        value=value,
        unit=unit,
        observed_at=observed_at,
        received_at=received_at,
        provenance=provenance,
        location_code=location_code,
        sequence_no=sequence_no,
        revision=revision,
        acquisition_mode=acquisition_mode,
        source_record_sha256=supplied_digest,
        source_record_id=source_record_id,
        source_signature=source_signature,
        status_code=status_code,
        quality_detail=_quality_detail(raw.get("quality"), channel=channel),
        quality="manual" if channel == "manual" else "normalized",
        metadata=_metadata(raw.get("metadata")),
        interval=interval,
    )


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).strip() or None


def _quality_detail(value: Any, *, channel: str) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "valid": True,
        "completeness": 1.0,
        "timeliness": 1.0,
        "device_health": "unknown",
        "clock_synchronized": False,
        "flags": ["manual_entry"] if channel == "manual" else [],
    }
    if value is None or isinstance(value, str):
        return defaults
    if not isinstance(value, dict):
        raise ValidationError("quality 必须是合同质量对象")
    allowed = {
        "valid",
        "completeness",
        "timeliness",
        "device_health",
        "clock_synchronized",
        "flags",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ValidationError("quality 包含未知字段：" + ", ".join(sorted(unknown)))
    result = {**defaults, **value}
    if not isinstance(result["valid"], bool):
        raise ValidationError("quality.valid 必须是布尔值")
    for name in ("completeness", "timeliness"):
        try:
            result[name] = float(result[name])
        except (TypeError, ValueError) as error:
            raise ValidationError(f"quality.{name} 必须是数值") from error
        if not 0 <= result[name] <= 1:
            raise ValidationError(f"quality.{name} 必须在 0-1 范围内")
    if result["device_health"] not in {"healthy", "degraded", "fault", "unknown"}:
        raise ValidationError("quality.device_health 枚举值无效")
    if not isinstance(result["clock_synchronized"], bool):
        raise ValidationError("quality.clock_synchronized 必须是布尔值")
    flags = result["flags"]
    if (
        not isinstance(flags, list)
        or len(flags) > 64
        or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in flags)
        or len(flags) != len(set(flags))
    ):
        raise ValidationError("quality.flags 必须是最多 64 个唯一非空字符串")
    return result


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()[:32]
