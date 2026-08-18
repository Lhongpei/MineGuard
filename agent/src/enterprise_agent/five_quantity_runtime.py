"""Durable one-mine ten-quantity V3 reporting and risk-response runtime.

Legacy five-quantity V2 drafts remain readable and resendable without changing
their signed JSON.  Every newly imported draft carries the explicit V3 catalog
marker and uses the eleven-atomic-field ten-quantity contract.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import threading
import time
import uuid
from contextlib import suppress
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .errors import ConflictError, NotFoundError, PlatformError, ValidationBlockedError
from .five_quantity_csv_persistence import (
    CSV_MAPPING_PROFILE_CONTRACT,
    FiveQuantityCsvPersistence,
)
from .five_quantity_exchange import (
    HTTP_SIGNING_CONTEXT,
    HTTP_SIGNING_CONTEXT_V3,
    MESSAGE_SIGNING_CONTEXT,
    MESSAGE_SIGNING_CONTEXT_V3,
    FiveQuantityPlatformClient,
    MineIdentity,
    sign_message,
    verify_message,
)
from .five_quantity_import import (
    ALLOWED_SUFFIXES,
    MAX_IMPORT_BYTES,
    PERIOD_KEYS,
    SHIFT_KEYS,
    csv_header_unit_issue,
    import_five_quantity_bytes,
    inspect_five_quantity_csv,
)
from .five_quantity_mapping import ApprovedColumnMapping, map_csv_inspection
from .quantity_catalog import (
    AGGREGATIONS,
    LEGACY_V2_METRICS,
    METRIC_LABELS,
    METRICS,
    REQUIRED_SHIFT_METRICS,
    TEN_QUANTITY_ANALYSIS_CONTRACT,
    TEN_QUANTITY_SUBMISSION_CONTRACT,
    TEN_QUANTITY_SUBMISSION_MESSAGE_TYPE,
    UNITS,
)
from .util import jcs_json, parse_aware_datetime, sha256_jcs, utc_now, utc_text

ZERO_HASH = "0" * 64
_FQ_SCHEMA_VERSION = 4
_FQ_SCHEMA_COMPONENT = "five_quantity_v2"

_PUBLIC_AUDIT_EVENT_TYPES = {
    "five_quantity_csv_preview_created": "data_import_preview_created",
    "five_quantity_csv_preview_consumed": "data_import_preview_confirmed",
    "five_quantity_imported": "production_data_imported",
    "five_quantity_confirmed_and_queued": "submission_confirmed_and_queued",
    "five_quantity_outbox_delivered": "submission_delivered",
}


def _public_audit_event_type(event_type: str) -> str:
    mapped = _PUBLIC_AUDIT_EVENT_TYPES.get(event_type)
    if mapped is not None:
        return mapped
    if event_type.startswith("five_quantity_"):
        return "submission_" + event_type.removeprefix("five_quantity_")
    return event_type
LEGACY_SUBMISSION_CONTRACT = "five-quantity-submission-v2"
CURRENT_SUBMISSION_CONTRACT = TEN_QUANTITY_SUBMISSION_CONTRACT
_DRAFT_PAYLOAD_KEYS = {
    "mine",
    "reporting_month",
    "timezone",
    "period_start",
    "period_end",
    "closed_at",
    "comparison_context",
    "days",
    "sources",
    "agent_processing",
}
_FINAL_PAYLOAD_KEYS = _DRAFT_PAYLOAD_KEYS | {"human_confirmation"}
_CORRECTION_LOCKED_PAYLOAD_FIELDS = (
    "mine",
    "reporting_month",
    "timezone",
    "period_start",
    "period_end",
    "comparison_context",
)
_MEASUREMENT_KEYS = {
    "metric_code",
    "value",
    "unit",
    "aggregation",
    "quality_flags",
    "source_refs",
}
_MISSING_FLAGS = {"missing", "unavailable", "not_applicable"}
_ALLOWED_FLAGS = {
    "reported",
    "missing",
    "unavailable",
    "not_applicable",
    "partial",
    "unit_converted",
    "corrected",
    "source_format_warning",
}
_UNITS = UNITS
_AGGREGATIONS = {
    "ventilation_m3_min": frozenset({"time_weighted_average", "snapshot"}),
    **{
        metric: frozenset({aggregation})
        for metric, aggregation in AGGREGATIONS.items()
        if metric != "ventilation_m3_min"
    },
}
_METRIC_LABELS = METRIC_LABELS
_COMPARISON_KEYS = {
    "capacity_band",
    "mining_method",
    "shift_system",
    "coal_type",
    "operating_regime",
}
_RESPONSE_KINDS = {
    "explanation",
    "correction_submitted",
    "clarification_request",
    "unable_to_determine",
}
_REASON_CODES = {
    "equipment_maintenance",
    "power_outage",
    "planned_shutdown",
    "restart_transition",
    "geology_change",
    "production_plan_change",
    "shift_arrangement",
    "ventilation_adjustment",
    "blasting_plan_change",
    "meter_or_source_error",
    "transcription_or_mapping_error",
    "other",
    "unknown_under_investigation",
}
_ACTION_TYPES = {"investigation", "data_correction", "corrective", "preventive"}
_ACTION_STATUSES = {"planned", "in_progress", "completed", "not_applicable"}


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是对象")
    return value


def _text(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} 必须是 1-{maximum} 字符")
    if any(
        ord(character) < 32 and character not in {"\n", "\t"} for character in value
    ):
        raise ValueError(f"{label} 包含控制字符")
    return value.strip()


def _iso_date(value: Any, label: str) -> date:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是 ISO 日期")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} 必须是 ISO 日期") from error


def _uuid_text(value: Any, label: str) -> str:
    text = _text(value, label, 64)
    try:
        uuid.UUID(text)
    except (ValueError, AttributeError) as error:
        raise ValueError(f"{label} 必须是 UUID") from error
    return text


def _identifier_text(value: Any, label: str) -> str:
    text = _text(value, label, 128)
    if not text[0].isalnum() or any(
        not (character.isascii() and (character.isalnum() or character in "._:-"))
        for character in text
    ):
        raise ValueError(f"{label} 必须是安全标识")
    return text


def _sha256_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} 必须是小写 SHA-256")
    return value


def validate_five_quantity_payload(
    payload: dict[str, Any],
    *,
    identity: MineIdentity,
    confirmed: bool,
    contract_version: str = LEGACY_SUBMISSION_CONTRACT,
) -> None:
    """Validate only after an explicit supported contract-version dispatch."""

    if not isinstance(payload, dict):
        raise ValueError("报送 payload 必须是对象")
    if contract_version == CURRENT_SUBMISSION_CONTRACT:
        is_ten_quantity = True
        active_metrics = METRICS
    elif contract_version == LEGACY_SUBMISSION_CONTRACT:
        is_ten_quantity = False
        active_metrics = LEGACY_V2_METRICS
    else:
        raise ValueError("报送 contract_version 不受支持")
    expected_keys = _FINAL_PAYLOAD_KEYS if confirmed else _DRAFT_PAYLOAD_KEYS
    if set(payload) != expected_keys:
        raise ValueError("报送 payload 字段不完整或包含未知字段")
    mine = _object(payload["mine"], "mine")
    if mine != identity.mine:
        raise ValueError("草稿矿井/经营主体与本实例启动身份不一致")
    context = _object(payload["comparison_context"], "comparison_context")
    if set(context) != _COMPARISON_KEYS or context != identity.comparison_context:
        raise ValueError("同类矿上下文必须与本实例受控配置完全一致")
    reporting_month = payload["reporting_month"]
    if (
        not isinstance(reporting_month, str)
        or len(reporting_month) != 7
        or reporting_month[4] != "-"
    ):
        raise ValueError("reporting_month 格式非法")
    start = _iso_date(payload["period_start"], "period_start")
    end = _iso_date(payload["period_end"], "period_end")
    if end < start:
        raise ValueError("period_end 不能早于 period_start")
    if payload["timezone"] != identity.timezone:
        raise ValueError("timezone 与本实例配置不一致")
    parse_aware_datetime(payload["closed_at"], "closed_at")
    days = payload["days"]
    if not isinstance(days, list) or not 1 <= len(days) <= 366:
        raise ValueError("days 必须包含 1-366 个日报")
    dates: list[date] = []
    sources = payload["sources"]
    maximum_sources = 256 if is_ten_quantity else 512
    if not isinstance(sources, list) or not 1 <= len(sources) <= maximum_sources:
        raise ValueError(f"sources 必须包含 1-{maximum_sources} 个来源")
    source_ids: set[str] = set()
    for index, source_value in enumerate(sources):
        source = _object(source_value, f"sources[{index}]")
        all_source_fields = {
            "source_id",
            "acquisition_mode",
            "source_system",
            "source_record_id",
            "source_location",
            "captured_at",
            "media_type",
            "evidence_sha256",
            "normalization",
        }
        required_source_fields = (
            {
                "source_id",
                "acquisition_mode",
                "source_system",
                "source_record_id",
                "captured_at",
                "evidence_sha256",
            }
            if is_ten_quantity
            else all_source_fields
        )
        if not required_source_fields.issubset(source) or not set(source).issubset(
            all_source_fields
        ):
            raise ValueError(f"sources[{index}] 字段不完整")
        source_id = _text(source["source_id"], f"sources[{index}].source_id", 128)
        if source_id in source_ids:
            raise ValueError("source_id 不得重复")
        source_ids.add(source_id)
        if source["acquisition_mode"] not in {"manual_import", "direct_collection"}:
            raise ValueError("acquisition_mode 只能追溯人工导入或直采")
        if len(str(source["evidence_sha256"])) != 64:
            raise ValueError("来源证据摘要非法")
        parse_aware_datetime(source["captured_at"], "source.captured_at")
        if any(
            forbidden in source
            for forbidden in ("trust_level", "trust_score", "reliability_weight")
        ):
            raise ValueError("采集方式不得带信任等级或算法权重")
    for day_index, day_value in enumerate(days):
        day = _object(day_value, f"days[{day_index}]")
        if set(day) != {"date", "operating_state", "reported_quantity"}:
            raise ValueError(f"days[{day_index}] 字段非法")
        current_date = _iso_date(day["date"], f"days[{day_index}].date")
        if (
            not start <= current_date <= end
            or current_date.strftime("%Y-%m") != reporting_month
        ):
            raise ValueError("日报日期超出月报期间")
        dates.append(current_date)
        if day["operating_state"] not in {
            "producing",
            "stopped",
            "maintenance",
            "restarting",
            "unknown",
        }:
            raise ValueError("operating_state 非法")
        quantity = _object(day["reported_quantity"], "reported_quantity")
        if set(quantity) != {"daily_total", "shifts"}:
            raise ValueError("reported_quantity 字段非法")
        shifts = _object(quantity["shifts"], "shifts")
        if set(shifts) != set(SHIFT_KEYS):
            raise ValueError("必须显式提供零点、八点、四点三个班次")
        measurement_sets: list[tuple[str, dict[str, Any]]] = [
            ("daily_total", _object(quantity["daily_total"], "daily_total"))
        ]
        for shift_key in SHIFT_KEYS:
            shift = _object(shifts[shift_key], shift_key)
            if set(shift) != {"shift_code", "start_at", "end_at", "measurements"}:
                raise ValueError(f"{shift_key} 字段非法")
            shift_start = parse_aware_datetime(shift["start_at"], "shift.start_at")
            shift_end = parse_aware_datetime(shift["end_at"], "shift.end_at")
            if shift_end <= shift_start:
                raise ValueError("班次结束必须晚于开始")
            measurement_sets.append(
                (
                    shift_key,
                    _object(shift["measurements"], f"{shift_key}.measurements"),
                )
            )
        for scope, measurements in measurement_sets:
            measurement_keys = set(measurements)
            if scope == "daily_total" or not is_ten_quantity:
                valid_set = measurement_keys == set(active_metrics)
            else:
                valid_set = set(REQUIRED_SHIFT_METRICS).issubset(
                    measurement_keys
                ) and measurement_keys.issubset(set(METRICS))
            if not valid_set:
                raise ValueError(
                    "日报必须含全部 11 个原子指标；V3 班次必须含前 7 项，"
                    "销售、运输、入洗、开票班次明细可省略"
                )
            for metric in measurements:
                measurement = _object(measurements[metric], metric)
                if set(measurement) != _MEASUREMENT_KEYS:
                    raise ValueError(f"{metric} 测量字段非法")
                if (
                    measurement["metric_code"] != metric
                    or measurement["unit"] != _UNITS[metric]
                ):
                    raise ValueError(f"{metric} 编码或单位非法")
                if measurement["aggregation"] not in _AGGREGATIONS[metric]:
                    allowed = " / ".join(sorted(_AGGREGATIONS[metric]))
                    raise ValueError(
                        f"{metric}.aggregation 非法，应为 {allowed}"
                    )
                value = measurement["value"]
                if value is not None:
                    if isinstance(value, bool) or not isinstance(value, (int, float)):
                        raise ValueError(f"{metric}.value 必须是数字或 null")
                    if not 0 <= float(value) <= 1_000_000_000_000_000:
                        raise ValueError(f"{metric}.value 超出范围")
                    if metric in {
                        "detonators_count",
                        "mine_entry_persons",
                    } and not isinstance(value, int):
                        raise ValueError(f"{metric} 非空时必须是整数")
                flags = measurement["quality_flags"]
                if (
                    not isinstance(flags, list)
                    or not flags
                    or len(flags) > 8
                    or len(flags) != len(set(flags))
                    or not set(flags).issubset(_ALLOWED_FLAGS)
                ):
                    raise ValueError(f"{metric}.quality_flags 非法")
                if value is None and not set(flags) & _MISSING_FLAGS:
                    raise ValueError(f"{metric} 为 null 时必须说明缺失原因")
                if value is not None and set(flags) & _MISSING_FLAGS:
                    raise ValueError(f"{metric} 非空值与缺失标志冲突")
                refs = measurement["source_refs"]
                if (
                    not isinstance(refs, list)
                    or not refs
                    or len(refs) > 16
                    or len(refs) != len(set(refs))
                    or not set(refs).issubset(source_ids)
                ):
                    raise ValueError(f"{metric}.source_refs 引用了未知来源")
    if dates != sorted(dates) or len(dates) != len(set(dates)):
        raise ValueError("days 必须按日期升序且不得重复")
    if dates[0] != start or dates[-1] != end:
        raise ValueError("period_start/end 必须等于首尾日报日期")
    expected_dates = [
        start + timedelta(days=offset)
        for offset in range((end - start).days + 1)
    ]
    if dates != expected_dates:
        raise ValueError("days 必须无间断覆盖 period_start 至 period_end")
    processing = _object(payload["agent_processing"], "agent_processing")
    required_processing = {
        "normalization_performed",
        "model_assistance_used",
        "processing_record_sha256",
    }
    optional_processing = required_processing | {"model_output_sha256"}
    if not required_processing.issubset(processing) or not set(processing).issubset(
        optional_processing
    ):
        raise ValueError("agent_processing 字段非法")
    if (
        processing["model_assistance_used"] is True
        and "model_output_sha256" not in processing
    ):
        raise ValueError("模型参与时必须记录模型输出摘要")
    if confirmed:
        confirmation = _object(payload["human_confirmation"], "human_confirmation")
        if (
            set(confirmation)
            != {
                "confirmed",
                "confirmer_id",
                "confirmer_name",
                "role",
                "confirmed_at",
                "content_sha256",
            }
            or confirmation["confirmed"] is not True
        ):
            raise ValueError("human_confirmation 非法")


def _audit_hash(
    previous_hash: str,
    sequence: int,
    event_type: str,
    actor: str,
    occurred_at: str,
    details: dict[str, Any],
) -> str:
    return hashlib.sha256(
        jcs_json(
            {
                "previous_hash": previous_hash,
                "sequence": sequence,
                "event_type": event_type,
                "actor": actor,
                "occurred_at": occurred_at,
                "details": details,
            }
        ).encode("utf-8")
    ).hexdigest()


def _json_copy(value: Any) -> Any:
    return json.loads(jcs_json(value))


def _merge_machine_measurement(
    previous: dict[str, Any],
    incoming: dict[str, Any],
    *,
    location: str,
) -> dict[str, Any]:
    for field in ("metric_code", "unit", "aggregation"):
        if previous.get(field) != incoming.get(field):
            raise ConflictError(f"多来源数据结构冲突：{location}.{field}")
    previous_value = previous.get("value")
    incoming_value = incoming.get("value")
    if previous_value is None and incoming_value is not None:
        return _json_copy(incoming)
    if previous_value is not None and incoming_value is None:
        return _json_copy(previous)
    result = _json_copy(previous)
    if (
        previous_value is not None
        and incoming_value is not None
        and float(previous_value) != float(incoming_value)
    ):
        raise ConflictError(f"不同来源对 {location} 提供了冲突数值")
    result["quality_flags"] = sorted(
        set(previous.get("quality_flags", []))
        | set(incoming.get("quality_flags", []))
    )
    result["source_refs"] = sorted(
        set(previous.get("source_refs", []))
        | set(incoming.get("source_refs", []))
    )
    return result


def _merge_machine_payloads(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Rebuild one V3 month draft from every source's latest contribution."""

    if not payloads:
        raise ValueError("机器来源贡献不能为空")
    result = _json_copy(payloads[0])
    source_by_id = {
        str(source["source_id"]): _json_copy(source)
        for source in result["sources"]
    }
    day_by_date = {str(day["date"]): _json_copy(day) for day in result["days"]}
    for payload in payloads[1:]:
        for field in (
            "mine",
            "reporting_month",
            "timezone",
            "comparison_context",
        ):
            if sha256_jcs(payload.get(field)) != sha256_jcs(result.get(field)):
                raise ConflictError(f"draft_key 的十量身份、口径或月份冲突：{field}")
        for source in payload["sources"]:
            source_id = str(source["source_id"])
            previous_source = source_by_id.get(source_id)
            if previous_source is not None and sha256_jcs(
                previous_source
            ) != sha256_jcs(source):
                raise ConflictError("不同贡献包含冲突的 V3 source_id")
            source_by_id[source_id] = _json_copy(source)
        for incoming_day in payload["days"]:
            day_text = str(incoming_day["date"])
            previous_day = day_by_date.get(day_text)
            if previous_day is None:
                day_by_date[day_text] = _json_copy(incoming_day)
                continue
            old_state = previous_day["operating_state"]
            new_state = incoming_day["operating_state"]
            if old_state == "unknown":
                previous_day["operating_state"] = new_state
            elif new_state != "unknown" and old_state != new_state:
                raise ConflictError(f"不同来源对 {day_text} 运行状态存在冲突")
            old_quantity = previous_day["reported_quantity"]
            new_quantity = incoming_day["reported_quantity"]
            for metric in METRICS:
                old_quantity["daily_total"][metric] = _merge_machine_measurement(
                    old_quantity["daily_total"][metric],
                    new_quantity["daily_total"][metric],
                    location=f"{day_text}.daily_total.{metric}",
                )
            for shift_key in SHIFT_KEYS:
                old_shift = old_quantity["shifts"][shift_key]
                new_shift = new_quantity["shifts"][shift_key]
                for field in ("shift_code", "start_at", "end_at"):
                    if old_shift[field] != new_shift[field]:
                        raise ConflictError(
                            f"不同来源对 {day_text}.{shift_key}.{field} 存在冲突"
                        )
                for metric in METRICS:
                    old_shift["measurements"][metric] = (
                        _merge_machine_measurement(
                            old_shift["measurements"][metric],
                            new_shift["measurements"][metric],
                            location=f"{day_text}.{shift_key}.{metric}",
                        )
                    )
    days = [day_by_date[key] for key in sorted(day_by_date)]
    result["days"] = days
    result["period_start"] = days[0]["date"]
    result["period_end"] = days[-1]["date"]
    result["sources"] = [source_by_id[key] for key in sorted(source_by_id)]
    result["closed_at"] = max(
        (str(payload["closed_at"]) for payload in payloads),
        key=lambda value: parse_aware_datetime(value, "closed_at"),
    )
    processing_record = {
        "kind": "machine_latest_source_snapshot_merge/v1",
        "contribution_payload_sha256": sorted(
            sha256_jcs(payload) for payload in payloads
        ),
        "day_count": len(days),
        "source_count": len(result["sources"]),
    }
    result["agent_processing"] = {
        "normalization_performed": True,
        "model_assistance_used": False,
        "processing_record_sha256": sha256_jcs(processing_record),
    }
    return result


def _v2_machine_preflight(
    payload: dict[str, Any],
    *,
    revision: int,
    contract_version: str = LEGACY_SUBMISSION_CONTRACT,
) -> dict[str, Any]:
    """Deterministic enterprise-side pre-submission check, not a ruling."""

    missing_count = 0
    mismatches: list[str] = []
    period_start = date.fromisoformat(str(payload["period_start"]))
    period_end = date.fromisoformat(str(payload["period_end"]))
    expected_day_count = (period_end - period_start).days + 1
    missing_day_count = max(0, expected_day_count - len(payload["days"]))
    month_start = date.fromisoformat(f"{payload['reporting_month']}-01")
    following_month = (month_start.replace(day=28) + timedelta(days=4)).replace(
        day=1
    )
    month_end = following_month - timedelta(days=1)
    leading_days = max(0, (period_start - month_start).days)
    trailing_days = max(0, (month_end - period_end).days)
    calendar_coverage = {
        "kind": (
            "full_month"
            if leading_days == 0 and trailing_days == 0
            else "partial_window"
        ),
        "reporting_month": payload["reporting_month"],
        "month_start": month_start.isoformat(),
        "month_end": month_end.isoformat(),
        "declared_period_start": period_start.isoformat(),
        "declared_period_end": period_end.isoformat(),
        "declared_day_count": len(payload["days"]),
        "calendar_day_count": month_end.day,
        "leading_days_outside_window": leading_days,
        "trailing_days_outside_window": trailing_days,
    }
    is_ten_quantity = contract_version == CURRENT_SUBMISSION_CONTRACT
    if contract_version not in {
        CURRENT_SUBMISSION_CONTRACT,
        LEGACY_SUBMISSION_CONTRACT,
    }:
        raise ValueError("机器预检 contract_version 不受支持")
    active_metrics = METRICS if is_ten_quantity else LEGACY_V2_METRICS
    required_shift_metrics = (
        REQUIRED_SHIFT_METRICS
        if is_ten_quantity
        else frozenset(LEGACY_V2_METRICS)
    )
    sum_metrics = tuple(
        metric
        for metric in required_shift_metrics
        if metric != "ventilation_m3_min"
    )
    for day in payload["days"]:
        quantity = day["reported_quantity"]
        missing_count += sum(
            quantity["daily_total"][metric]["value"] is None
            for metric in active_metrics
        )
        missing_count += sum(
            quantity["shifts"][key]["measurements"][metric]["value"] is None
            for key in SHIFT_KEYS
            for metric in required_shift_metrics
        )
        for metric in sum_metrics:
            daily_value = quantity["daily_total"][metric]["value"]
            shift_values = [
                quantity["shifts"][key]["measurements"][metric]["value"]
                for key in SHIFT_KEYS
            ]
            if daily_value is None or any(value is None for value in shift_values):
                continue
            shift_sum = sum(float(value) for value in shift_values)
            tolerance = max(1e-6, abs(float(daily_value)) * 1e-6)
            if abs(float(daily_value) - shift_sum) > tolerance:
                mismatches.append(f"{day['date']} {metric} 日合计与三班合计不一致")
    payload_sha256 = sha256_jcs(payload)
    warnings: list[str] = []
    if missing_count:
        warnings.append(f"仍有 {missing_count} 个明确缺失或不可用测量值")
    if missing_day_count:
        warnings.append(f"统计期间缺少 {missing_day_count} 个完整日报日期")
    if calendar_coverage["kind"] == "partial_window":
        warnings.append(
            "当前声明的是月内部分统计窗口，并非整月日历覆盖；"
            "报送前请核对采集截止日"
        )
    warnings.extend(mismatches[:19])
    return {
        "contract_version": (
            "ten-quantity-machine-preflight/v2"
            if is_ten_quantity
            else "five-quantity-machine-preflight/v1"
        ),
        "status": (
            "attention_required"
            if missing_count or missing_day_count or mismatches
            else "ready_for_human_review"
        ),
        "bound_revision": revision,
        "payload_sha256": payload_sha256,
        "missing_count": missing_count,
        "missing_day_count": missing_day_count,
        "calendar_coverage": calendar_coverage,
        "arithmetic_mismatch_count": len(mismatches),
        "source_count": len(payload["sources"]),
        "checked_at": utc_text(),
        "warnings": warnings[:20],
        "scope": "enterprise_pre_submission_check",
        "regulatory_determination": False,
        "read_only": True,
    }


def _column_mapping_sha256(value: Any) -> str:
    """Hash effective source-column targets while ignoring advisory wording."""

    if not isinstance(value, list):
        raise ConflictError("已有导入记录的字段映射元数据非法")
    mappings: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or item.get("kind") != "column_mapping":
            continue
        source_column = item.get("source_column")
        metric = item.get("metric")
        period = item.get("period")
        if (
            isinstance(source_column, bool)
            or not isinstance(source_column, int)
            or not isinstance(metric, str)
            or not isinstance(period, str)
        ):
            raise ConflictError("已有导入记录的字段映射元数据非法")
        mappings.append(
            {
                "source_column": source_column,
                "metric": metric,
                "period": period,
            }
        )
    mappings.sort(
        key=lambda item: (item["source_column"], item["metric"], item["period"])
    )
    return sha256_jcs(mappings)


def _verify_stored_v3_submission(
    message: Any,
    *,
    identity: MineIdentity,
) -> dict[str, Any]:
    """Verify one locally persisted enterprise submission without re-signing it.

    Correction drafts are rooted in the exact signed predecessor bytes kept in
    the outbox.  Recomputing the V3 HMAC here prevents a damaged or externally
    altered database row from becoming the parent of a new revision chain.
    """

    required = {
        "contract_version",
        "message_type",
        "message_id",
        "correlation_id",
        "causation_id",
        "idempotency_key",
        "revision",
        "predecessor",
        "created_at",
        "sender",
        "recipient",
        "mine_id",
        "payload",
        "signature_envelope",
    }
    if not isinstance(message, dict) or set(message) != required:
        raise ConflictError("十量 V3 报文结构不完整")
    if (
        message.get("contract_version") != CURRENT_SUBMISSION_CONTRACT
        or message.get("message_type") != TEN_QUANTITY_SUBMISSION_MESSAGE_TYPE
        or message.get("mine_id") != identity.mine_id
    ):
        raise ConflictError("报文不是本矿十量 V3 报送")
    sender = message.get("sender")
    recipient = message.get("recipient")
    if (
        not isinstance(sender, dict)
        or sender
        != {
            "system_id": identity.system_id,
            "party_id": identity.operator_id,
            "role": "enterprise_agent",
        }
        or not isinstance(recipient, dict)
        or recipient
        != {
            "system_id": identity.regulator_system_id,
            "party_id": identity.regulator_party_id,
            "role": "regulatory_platform",
        }
    ):
        raise ConflictError("十量 V3 报文参与方与本矿配置不一致")
    envelope = message.get("signature_envelope")
    if not isinstance(envelope, dict) or set(envelope) != {
        "algorithm",
        "canonicalization",
        "key_id",
        "signed_at",
        "nonce",
        "payload_sha256",
        "signature",
    }:
        raise ConflictError("十量 V3 签名信封不完整")
    declared_key_id = envelope.get("key_id")
    if not isinstance(declared_key_id, str):
        raise ConflictError("十量 V3 签名 key_id 非法")
    verification_secret: str | None = None
    if declared_key_id == identity.key_id:
        verification_secret = identity.message_hmac_secret
    else:
        for historical_key in identity.historical_enterprise_signing_keys:
            if declared_key_id == historical_key.key_id:
                verification_secret = historical_key.secret
                break
    if verification_secret is None:
        raise ConflictError("十量 V3 签名 key_id 未在企业应用验签密钥环登记")
    try:
        validate_five_quantity_payload(
            message.get("payload"),
            identity=identity,
            confirmed=True,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )
        recomputed = json.loads(jcs_json(message))
        supplied_payload_hash = str(envelope.get("payload_sha256", ""))
        supplied_signature = str(envelope.get("signature", ""))
        sign_message(recomputed, secret=verification_secret)
    except (TypeError, ValueError) as error:
        raise ConflictError("十量 V3 报文未通过本地完整性校验") from error
    recomputed_envelope = recomputed["signature_envelope"]
    if not hmac.compare_digest(
        supplied_payload_hash,
        str(recomputed_envelope["payload_sha256"]),
    ) or not hmac.compare_digest(
        supplied_signature,
        str(recomputed_envelope["signature"]),
    ):
        raise ConflictError("十量 V3 报文签名或 payload 摘要不一致")
    return json.loads(jcs_json(message))


def _verify_stored_intake_receipt(
    receipt: Any,
    *,
    submission: dict[str, Any],
    identity: MineIdentity,
) -> dict[str, Any]:
    """Verify a persisted government receipt and its exact submission binding.

    ``verify_message`` authenticates the government application signature and
    both participants.  The intake contract's business bindings are checked
    separately because a validly signed receipt for another revision, message,
    or payload must never authorize a correction chain.
    """

    try:
        verify_message(
            receipt,
            secret=identity.message_hmac_secret,
            identity=identity,
            expected_contract="intake-receipt-v2",
            expected_type="intake_receipt",
        )
        assert isinstance(receipt, dict)
        _uuid_text(receipt.get("message_id"), "回执 message_id")
        _uuid_text(receipt.get("correlation_id"), "回执 correlation_id")
        _uuid_text(receipt.get("causation_id"), "回执 causation_id")
        _identifier_text(receipt.get("idempotency_key"), "回执 idempotency_key")
        receipt_created_at = parse_aware_datetime(
            receipt.get("created_at"), "回执 created_at"
        )
        if receipt.get("revision") != 1 or receipt.get("predecessor") is not None:
            raise ValueError("回执版本或前序字段非法")
        payload = _object(receipt.get("payload"), "回执 payload")
        if set(payload) != {
            "receipt_id",
            "submission_message_id",
            "submission_revision",
            "received_payload_sha256",
            "received_at",
            "intake_status",
            "analysis_state",
            "regulatory_outcome",
            "analysis_run_id",
        }:
            raise ValueError("回执 payload 字段不完整或包含未知字段")
        _uuid_text(payload.get("receipt_id"), "回执 receipt_id")
        _uuid_text(payload.get("submission_message_id"), "回执报送 message_id")
        _uuid_text(payload.get("analysis_run_id"), "回执 analysis_run_id")
        received_at = parse_aware_datetime(
            payload.get("received_at"), "回执 received_at"
        )
        submission_created_at = parse_aware_datetime(
            submission.get("created_at"), "报送 created_at"
        )
        if received_at < submission_created_at or receipt_created_at < received_at:
            raise ValueError("回执时间早于报送或政府接收时间")
        submission_revision = payload.get("submission_revision")
        if (
            isinstance(submission_revision, bool)
            or not isinstance(submission_revision, int)
            or submission_revision < 1
        ):
            raise ValueError("回执 submission_revision 非法")
        if payload.get("intake_status") not in {"accepted", "duplicate"}:
            raise ValueError("回执 intake_status 非法")
        if payload.get("analysis_state") != "queued":
            raise ValueError("回执 analysis_state 非法")
        if payload.get("regulatory_outcome") != "not_determined_at_intake":
            raise ValueError("回执不得声称接收阶段已形成监管结论")
    except (PlatformError, TypeError, ValueError) as error:
        raise ConflictError("政府接收回执未通过应用签名与契约校验") from error

    envelope = submission["signature_envelope"]
    if (
        receipt["correlation_id"] != submission["correlation_id"]
        or receipt["causation_id"] != submission["message_id"]
        or payload["submission_message_id"] != submission["message_id"]
        or payload["submission_revision"] != submission["revision"]
        or payload["received_payload_sha256"] != envelope["payload_sha256"]
    ):
        raise ConflictError("政府接收回执与报送消息、版本或 payload 摘要不绑定")
    return json.loads(jcs_json(receipt))


class FiveQuantityStore:
    """V2 tables isolated from legacy draft tables in the same local database."""

    def __init__(
        self,
        repository: Any,
        *,
        identity: MineIdentity,
        four_eyes_required: bool = False,
        human_preparer_actor_ids: frozenset[str] = frozenset(),
    ):
        self.repository = repository
        self.identity = identity
        self.four_eyes_required = bool(four_eyes_required)
        self.human_preparer_actor_ids = frozenset(human_preparer_actor_ids)
        self._initialize()

    @staticmethod
    def _audit_triggers_intact(db: Any) -> bool:
        def normalise(value: str) -> str:
            return " ".join(value.split())

        expected = {
            "fq_audit_no_update": normalise(
                """CREATE TRIGGER fq_audit_no_update
                BEFORE UPDATE ON fq_audit BEGIN
                    SELECT RAISE(ABORT, 'fq_audit is append-only');
                END"""
            ),
            "fq_audit_no_delete": normalise(
                """CREATE TRIGGER fq_audit_no_delete
                BEFORE DELETE ON fq_audit BEGIN
                    SELECT RAISE(ABORT, 'fq_audit is append-only');
                END"""
            ),
        }
        rows = db.execute(
            "SELECT name,sql FROM sqlite_master "
            "WHERE type='trigger' AND tbl_name='fq_audit'",
        ).fetchall()
        definitions: dict[str, str] = {}
        for row in rows:
            name = str(row["name"])
            sql = row["sql"]
            if name not in expected or not isinstance(sql, str):
                return False
            definitions[name] = normalise(sql)
        return definitions == expected

    @staticmethod
    def _install_audit_triggers(db: Any) -> None:
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS fq_audit_no_update
            BEFORE UPDATE ON fq_audit BEGIN
                SELECT RAISE(ABORT, 'fq_audit is append-only');
            END"""
        )
        db.execute(
            """CREATE TRIGGER IF NOT EXISTS fq_audit_no_delete
            BEFORE DELETE ON fq_audit BEGIN
                SELECT RAISE(ABORT, 'fq_audit is append-only');
            END"""
        )

    def _verify_audit_in_transaction(
        self, db: Any, *, require_anchor: bool = True
    ) -> dict[str, Any]:
        if not self._audit_triggers_intact(db):
            return {
                "valid": False,
                "failure": "audit_trigger_missing_or_replaced",
                "event_count": 0,
                "head_hash": ZERO_HASH,
            }
        rows = db.execute("SELECT * FROM fq_audit ORDER BY sequence").fetchall()
        previous = ZERO_HASH
        valid = True
        failure: str | None = None
        for expected_sequence, row in enumerate(rows, start=1):
            try:
                details = json.loads(str(row["details_json"]))
            except (TypeError, json.JSONDecodeError):
                valid = False
                failure = "audit_details_invalid"
                break
            if not isinstance(details, dict):
                valid = False
                failure = "audit_details_invalid"
                break
            expected_hash = _audit_hash(
                previous,
                expected_sequence,
                str(row["event_type"]),
                str(row["actor"]),
                str(row["occurred_at"]),
                details,
            )
            if (
                int(row["sequence"]) != expected_sequence
                or str(row["previous_hash"]) != previous
                or not hmac.compare_digest(str(row["event_hash"]), expected_hash)
            ):
                valid = False
                failure = "audit_chain_invalid"
                break
            previous = str(row["event_hash"])
        anchor = db.execute(
            "SELECT event_count,head_hash FROM fq_audit_anchor WHERE singleton=1"
        ).fetchone()
        if valid and require_anchor and (
            anchor is None
            or int(anchor["event_count"]) != len(rows)
            or not hmac.compare_digest(str(anchor["head_hash"]), previous)
        ):
            valid = False
            failure = "audit_tail_or_anchor_mismatch"
        return {
            "valid": valid,
            "failure": failure,
            "event_count": len(rows),
            "head_hash": previous,
            "anchor_present": anchor is not None,
        }

    def verify_audit(self) -> dict[str, Any]:
        """Verify the complete V2 chain, independent of display pagination."""

        with self.repository._read() as db:
            return self._verify_audit_in_transaction(db)

    def runtime_integrity_boundary_intact(self, db: Any) -> bool:
        """Check only fixed FQ guards after the trusted startup full scan.

        Historical rows are deliberately not revisited here.  They are covered
        by the Repository's external-write latch, while every controlled FQ
        append validates and advances the singleton tail anchor transactionally.
        """

        if not self._audit_triggers_intact(db) or not self._archive_guards_intact(db):
            return False
        version = db.execute(
            "SELECT version FROM fq_schema_versions WHERE component=?",
            (_FQ_SCHEMA_COMPONENT,),
        ).fetchone()
        anchor = db.execute(
            "SELECT event_count,head_hash FROM fq_audit_anchor WHERE singleton=1"
        ).fetchone()
        if version is None or int(version["version"]) != _FQ_SCHEMA_VERSION:
            return False
        if anchor is None or int(anchor["event_count"]) < 0:
            return False
        head_hash = str(anchor["head_hash"])
        return len(head_hash) == 64 and all(
            character in "0123456789abcdef" for character in head_hash
        )

    def _outbox_four_eyes_failure(self, db: Any, outbox: Any) -> str | None:
        """Check persisted approval state for one message, not caller claims."""

        if not self.four_eyes_required:
            return None
        kind = str(outbox["message_kind"])
        aggregate_id = str(outbox["aggregate_id"])
        message_id = str(outbox["message_id"])
        if kind == "delivery_ack":
            return None
        if kind == "submission":
            aggregate = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (aggregate_id,)
            ).fetchone()
            if aggregate is None:
                return "submission_aggregate_missing"
            if aggregate["status"] != "queued":
                return "submission_not_queued"
            if aggregate["submission_message_id"] != message_id:
                return "submission_message_mismatch"
            try:
                confirmation = self._loads(aggregate["confirmation_json"])
            except (TypeError, json.JSONDecodeError):
                return "submission_confirmation_invalid"
            if not isinstance(confirmation, dict):
                return "submission_confirmation_missing"
            confirmer = confirmation.get("actor_id")
            last_actor = aggregate["last_content_actor"]
            preparer = aggregate["human_preparer_actor"]
            revision = int(aggregate["revision"])
            prepared_revision = aggregate["human_prepared_revision"]
            if (
                not isinstance(preparer, str)
                or not preparer
                or preparer not in self.human_preparer_actor_ids
            ):
                return "submission_human_preparer_missing_or_unconfigured"
            if not isinstance(prepared_revision, int) or prepared_revision != revision:
                return "submission_human_prepared_revision_mismatch"
            if not isinstance(last_actor, str) or not last_actor:
                return "submission_last_content_actor_missing"
            if (
                not isinstance(confirmer, str)
                or not confirmer
                or confirmer in (preparer, last_actor)
            ):
                return "submission_independent_reviewer_missing"
            if confirmation.get("draft_revision") != revision:
                return "submission_confirmation_revision_mismatch"
            return None
        if kind == "risk_response":
            aggregate = db.execute(
                "SELECT * FROM fq_responses WHERE response_id=?", (aggregate_id,)
            ).fetchone()
            if aggregate is None:
                return "risk_response_aggregate_missing"
            if aggregate["status"] != "queued":
                return "risk_response_not_queued"
            if aggregate["message_id"] != message_id:
                return "risk_response_message_mismatch"
            try:
                confirmation = self._loads(aggregate["confirmation_json"])
            except (TypeError, json.JSONDecodeError):
                return "risk_response_confirmation_invalid"
            if not isinstance(confirmation, dict):
                return "risk_response_confirmation_missing"
            confirmer = confirmation.get("actor_id")
            last_actor = aggregate["last_content_actor"]
            revision = int(aggregate["revision"])
            if (
                not isinstance(last_actor, str)
                or not last_actor
                or not isinstance(confirmer, str)
                or not confirmer
                or confirmer == last_actor
            ):
                return "risk_response_independent_reviewer_missing"
            if confirmation.get("response_revision") != revision:
                return "risk_response_confirmation_revision_mismatch"
            return None
        return "unsupported_outbox_message_kind"

    def assert_outbox_sendable(self, message_id: str) -> None:
        """Recheck audit and persisted approval immediately before network I/O."""

        with self.repository._read() as db:
            integrity = self._verify_audit_in_transaction(db)
            if not integrity["valid"]:
                raise ConflictError(
                    "报送审计链或审计锚点异常；本次未向监管端发送"
                )
            outbox = db.execute(
                "SELECT * FROM fq_outbox WHERE message_id=?", (message_id,)
            ).fetchone()
            if outbox is None or outbox["status"] != "sending":
                raise ConflictError("发送消息状态已变化；本次未向监管端发送")
            failure = self._outbox_four_eyes_failure(db, outbox)
            if failure is not None:
                raise ConflictError(
                    "发送消息未满足持久化四眼复核条件；"
                    f"本次未向监管端发送（{failure}）"
                )

    def _initialize(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS fq_imports (
                import_id TEXT PRIMARY KEY,
                content_sha256 TEXT NOT NULL UNIQUE,
                filename TEXT NOT NULL,
                acquisition_mode TEXT NOT NULL CHECK (
                    acquisition_mode IN ('manual_import','direct_collection')
                ),
                source_path TEXT,
                status TEXT NOT NULL,
                error_message TEXT,
                draft_id TEXT,
                suggestions_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS fq_drafts (
                draft_id TEXT PRIMARY KEY,
                import_id TEXT NOT NULL UNIQUE,
                revision INTEGER NOT NULL CHECK (revision >= 1),
                submission_revision INTEGER NOT NULL CHECK (submission_revision >= 1),
                correlation_id TEXT,
                predecessor_message_id TEXT,
                predecessor_payload_sha256 TEXT,
                contract_version TEXT NOT NULL DEFAULT 'five-quantity-submission-v2'
                    CHECK(contract_version IN (
                        'five-quantity-submission-v2',
                        'ten-quantity-submission-v3'
                    )),
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                confirmation_json TEXT,
                submission_message_id TEXT UNIQUE,
                receipt_json TEXT,
                created_by TEXT,
                last_content_actor TEXT,
                human_preparer_actor TEXT,
                human_prepared_revision INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(import_id) REFERENCES fq_imports(import_id)
            )""",
            """CREATE TABLE IF NOT EXISTS fq_outbox (
                message_id TEXT PRIMARY KEY,
                message_kind TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                body_json TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                receipt_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE INDEX IF NOT EXISTS idx_fq_outbox_due
                ON fq_outbox(status, next_attempt_at)""",
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_fq_draft_predecessor_unique
                ON fq_drafts(predecessor_message_id)
                WHERE predecessor_message_id IS NOT NULL""",
            """CREATE TABLE IF NOT EXISTS fq_inbox (
                message_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE,
                correlation_id TEXT NOT NULL,
                delivery_cursor TEXT NOT NULL,
                body_json TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                received_at TEXT NOT NULL,
                acknowledged_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS fq_responses (
                response_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE,
                revision INTEGER NOT NULL CHECK (revision >= 1),
                status TEXT NOT NULL,
                document_json TEXT NOT NULL,
                confirmation_json TEXT,
                message_id TEXT UNIQUE,
                receipt_json TEXT,
                created_by TEXT,
                last_content_actor TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(report_id) REFERENCES fq_inbox(report_id)
            )""",
            """CREATE TABLE IF NOT EXISTS fq_chat_messages (
                message_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user','assistant')),
                content TEXT NOT NULL,
                tools_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(report_id) REFERENCES fq_inbox(report_id)
            )""",
            """CREATE INDEX IF NOT EXISTS idx_fq_chat_report
                ON fq_chat_messages(report_id, created_at)""",
            """CREATE TABLE IF NOT EXISTS fq_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS fq_machine_source_contributions (
                client_id TEXT NOT NULL,
                draft_key TEXT NOT NULL,
                source_id TEXT NOT NULL,
                source_revision INTEGER NOT NULL CHECK(source_revision >= 1),
                event_id TEXT NOT NULL,
                ingestion_id TEXT NOT NULL UNIQUE,
                import_id TEXT NOT NULL,
                draft_id TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                source_observed_at TEXT,
                source_coverage_as_of TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(client_id,draft_key,source_id),
                FOREIGN KEY(import_id) REFERENCES fq_imports(import_id),
                FOREIGN KEY(draft_id) REFERENCES fq_drafts(draft_id)
            )""",
            """CREATE INDEX IF NOT EXISTS idx_fq_machine_contribution_draft
                ON fq_machine_source_contributions(draft_id,source_id)""",
            """CREATE TABLE IF NOT EXISTS fq_machine_source_artifacts (
                client_id TEXT NOT NULL,
                draft_key TEXT NOT NULL,
                source_id TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                import_id TEXT NOT NULL,
                first_ingestion_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(client_id,draft_key,source_id,content_sha256),
                FOREIGN KEY(import_id) REFERENCES fq_imports(import_id)
            )""",
            """CREATE TABLE IF NOT EXISTS fq_audit (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS fq_audit_anchor (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                event_count INTEGER NOT NULL CHECK(event_count >= 0),
                head_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS fq_schema_versions (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL CHECK(version >= 1),
                updated_at TEXT NOT NULL
            )""",
        )
        with self.repository._transaction() as db:
            for statement in statements:
                db.execute(statement)
            version_row = db.execute(
                "SELECT version FROM fq_schema_versions WHERE component=?",
                (_FQ_SCHEMA_COMPONENT,),
            ).fetchone()
            schema_version = int(version_row["version"]) if version_row else 0
            if schema_version > _FQ_SCHEMA_VERSION:
                raise ValueError(
                    "本地五量数据库版本高于当前程序支持范围；"
                    "禁止用旧程序启动或回写，请升级程序"
                )
            trigger_rows = db.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND name IN ('fq_audit_no_update','fq_audit_no_delete')"
            ).fetchall()
            if schema_version >= 1 or trigger_rows:
                if not self._audit_triggers_intact(db):
                    raise ValueError(
                        "五量审计保护触发器缺失或被替换；正式流程已拒绝启动"
                    )
            else:
                self._install_audit_triggers(db)

            baseline = self._verify_audit_in_transaction(db, require_anchor=False)
            if not baseline["valid"]:
                raise ValueError(
                    "五量审计链在数据库升级前已损坏；禁止自动修复或继续写入"
                )
            if schema_version < _FQ_SCHEMA_VERSION:
                db.execute(
                    "INSERT OR REPLACE INTO fq_audit_anchor("
                    "singleton,event_count,head_hash,updated_at) VALUES (1,?,?,?)",
                    (baseline["event_count"], baseline["head_hash"], utc_text()),
                )
            for table in ("fq_drafts", "fq_responses"):
                columns = {
                    str(row["name"])
                    for row in db.execute(f"PRAGMA table_info({table})").fetchall()
                }
                if "created_by" not in columns:
                    db.execute(f"ALTER TABLE {table} ADD COLUMN created_by TEXT")
                if "last_content_actor" not in columns:
                    db.execute(
                        f"ALTER TABLE {table} ADD COLUMN last_content_actor TEXT"
                    )
                if table == "fq_drafts" and "human_preparer_actor" not in columns:
                    db.execute(
                        "ALTER TABLE fq_drafts ADD COLUMN human_preparer_actor TEXT"
                    )
                if table == "fq_drafts" and "human_prepared_revision" not in columns:
                    db.execute(
                        "ALTER TABLE fq_drafts ADD COLUMN "
                        "human_prepared_revision INTEGER"
                    )
                if table == "fq_drafts" and "contract_version" not in columns:
                    # Every row created before this migration is V2.  The
                    # additive column records that fact without touching its
                    # immutable payload JSON or append-only audit history.
                    db.execute(
                        "ALTER TABLE fq_drafts ADD COLUMN contract_version TEXT "
                        "NOT NULL DEFAULT 'five-quantity-submission-v2' "
                        "CHECK(contract_version IN ("
                        "'five-quantity-submission-v2',"
                        "'ten-quantity-submission-v3'))"
                    )
            archive_trigger_rows = db.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name IN ('fq_outbox','fq_drafts')"
            ).fetchall()
            if (
                (schema_version >= 4 or archive_trigger_rows)
                and not self._archive_guards_intact(db)
            ):
                raise ValueError(
                    "十量签名归档保护索引或触发器缺失、被替换或存在额外对象；"
                    "正式流程已拒绝启动"
                )
            # Backfill actor attribution from the existing append-only V2
            # audit log. Invalid legacy detail JSON is left NULL and will be
            # rejected by the formal four-eyes gate instead of being guessed.
            draft_actors: dict[str, tuple[str, str]] = {}
            response_actors: dict[str, tuple[str, str]] = {}
            audit_rows = (
                db.execute(
                    "SELECT event_type,actor,details_json FROM fq_audit "
                    "ORDER BY sequence"
                ).fetchall()
                if schema_version < 2
                else ()
            )
            for audit_row in audit_rows:
                try:
                    details = json.loads(str(audit_row["details_json"]))
                except (TypeError, json.JSONDecodeError):
                    continue
                if not isinstance(details, dict):
                    continue
                event_type = str(audit_row["event_type"])
                actor = str(audit_row["actor"])
                draft_id = details.get("draft_id")
                if (
                    isinstance(draft_id, str)
                    and event_type
                    in {
                        "five_quantity_imported",
                        "five_quantity_machine_autofilled",
                        "five_quantity_review_saved",
                        "five_quantity_machine_sync_resumed",
                    }
                ):
                    created, _ = draft_actors.get(draft_id, (actor, actor))
                    draft_actors[draft_id] = (created, actor)
                response_id = details.get("response_id")
                if (
                    isinstance(response_id, str)
                    and event_type
                    in {"risk_response_draft_created", "risk_response_saved"}
                ):
                    created, _ = response_actors.get(response_id, (actor, actor))
                    response_actors[response_id] = (created, actor)
            for draft_id, (created, latest) in draft_actors.items():
                db.execute(
                    "UPDATE fq_drafts SET created_by=COALESCE(created_by,?), "
                    "last_content_actor=COALESCE(last_content_actor,?) "
                    "WHERE draft_id=?",
                    (created, latest, draft_id),
                )
                if latest in self.human_preparer_actor_ids:
                    db.execute(
                        "UPDATE fq_drafts SET human_preparer_actor=?,"
                        "human_prepared_revision=revision "
                        "WHERE draft_id=? AND human_preparer_actor IS NULL "
                        "AND import_id IN (SELECT import_id FROM fq_imports "
                        "WHERE acquisition_mode='manual_import')",
                        (latest, draft_id),
                    )
            for response_id, (created, latest) in response_actors.items():
                db.execute(
                    "UPDATE fq_responses SET created_by=COALESCE(created_by,?), "
                    "last_content_actor=COALESCE(last_content_actor,?) "
                    "WHERE response_id=?",
                    (created, latest, response_id),
                )
            if self.four_eyes_required and schema_version < 2:
                # An older release may contain a locally queued, not-yet-sent
                # record confirmed by its own editor. Reopen it safely instead
                # of allowing the background sender to bypass the new gate.
                for table, identifier, kind, event_type in (
                    (
                        "fq_drafts",
                        "draft_id",
                        "submission",
                        "five_quantity_legacy_queue_reopened_for_four_eyes",
                    ),
                    (
                        "fq_responses",
                        "response_id",
                        "risk_response",
                        "risk_response_legacy_queue_reopened_for_four_eyes",
                    ),
                ):
                    queued = db.execute(
                        f"SELECT * FROM {table} WHERE status='queued'"
                    ).fetchall()
                    for aggregate in queued:
                        aggregate_id = str(aggregate[identifier])
                        outbox = db.execute(
                            "SELECT * FROM fq_outbox WHERE aggregate_id=? "
                            "AND message_kind=?",
                            (aggregate_id, kind),
                        ).fetchone()
                        if outbox is not None and outbox["status"] == "succeeded":
                            continue
                        failure = (
                            "queued_aggregate_missing_outbox"
                            if outbox is None
                            else self._outbox_four_eyes_failure(db, outbox)
                        )
                        if failure is None:
                            continue
                        if outbox is not None:
                            db.execute(
                                "UPDATE fq_outbox SET status='cancelled',"
                                "idempotency_key=?,last_error=?,updated_at=? "
                                "WHERE message_id=?",
                                (
                                    f"cancelled-four-eyes.{outbox['message_id']}",
                                    failure,
                                    utc_text(),
                                    outbox["message_id"],
                                ),
                            )
                        message_column = (
                            "submission_message_id"
                            if table == "fq_drafts"
                            else "message_id"
                        )
                        reopened_status = (
                            "ready_review" if table == "fq_drafts" else "draft"
                        )
                        db.execute(
                            f"UPDATE {table} SET status=?,"
                            f"confirmation_json=NULL,{message_column}=NULL,"
                            "updated_at=? WHERE " + identifier + "=?",
                            (reopened_status, utc_text(), aggregate_id),
                        )
                        self._append_audit(
                            db,
                            event_type,
                            "system-migration",
                            {
                                identifier: aggregate_id,
                                "cancelled_message_id": (
                                    outbox["message_id"]
                                    if outbox is not None
                                    else None
                                ),
                                "reason": failure,
                            },
                        )
            contribution_columns = {
                str(row["name"])
                for row in db.execute(
                    "PRAGMA table_info(fq_machine_source_contributions)"
                ).fetchall()
            }
            if "source_observed_at" not in contribution_columns:
                db.execute(
                    "ALTER TABLE fq_machine_source_contributions "
                    "ADD COLUMN source_observed_at TEXT"
                )
            if "source_coverage_as_of" not in contribution_columns:
                db.execute(
                    "ALTER TABLE fq_machine_source_contributions "
                    "ADD COLUMN source_coverage_as_of TEXT"
                )
            db.execute(
                """
                INSERT OR IGNORE INTO fq_machine_source_artifacts(
                    client_id,draft_key,source_id,content_sha256,import_id,
                    first_ingestion_id,created_at
                )
                SELECT client_id,draft_key,source_id,content_sha256,import_id,
                    ingestion_id,created_at
                FROM fq_machine_source_contributions
            """
            )
            if not archive_trigger_rows:
                self._install_archive_guards(db)
            if not self._archive_guards_intact(db):
                raise ValueError("十量签名归档保护安装失败；正式流程已拒绝启动")
            db.execute(
                "UPDATE fq_outbox SET status='failed', "
                "last_error='recovered_after_restart' WHERE status='sending'"
            )
            projection = self._verify_submission_archive_projection(db)
            if not projection["valid"]:
                raise ValueError(
                    "十量报送审计与本地签名归档投影不一致；拒绝启动"
                    f"（{projection['failure']}）"
                )
            if schema_version < _FQ_SCHEMA_VERSION:
                db.execute(
                    "INSERT INTO fq_schema_versions(component,version,updated_at) "
                    "VALUES (?,?,?) ON CONFLICT(component) DO UPDATE SET "
                    "version=excluded.version,updated_at=excluded.updated_at",
                    (_FQ_SCHEMA_COMPONENT, _FQ_SCHEMA_VERSION, utc_text()),
                )
            final_integrity = self._verify_audit_in_transaction(db)
            if not final_integrity["valid"]:
                raise ValueError("报送审计链或审计锚点不完整；拒绝启动")

    @staticmethod
    def _archive_guard_definitions() -> tuple[dict[str, str], dict[str, str]]:
        def normalise(value: str) -> str:
            return " ".join(value.split())

        triggers = {
            "fq_outbox_archive_no_update": normalise(
                """CREATE TRIGGER fq_outbox_archive_no_update
                BEFORE UPDATE ON fq_outbox
                WHEN NEW.message_id IS NOT OLD.message_id
                    OR NEW.message_kind IS NOT OLD.message_kind
                    OR NEW.aggregate_id IS NOT OLD.aggregate_id
                    OR NEW.idempotency_key IS NOT OLD.idempotency_key
                    OR NEW.body_json IS NOT OLD.body_json
                    OR NEW.body_sha256 IS NOT OLD.body_sha256
                    OR NEW.created_at IS NOT OLD.created_at
                    OR (
                        NEW.receipt_json IS NOT OLD.receipt_json
                        AND NOT (
                            OLD.receipt_json IS NULL
                            AND NEW.receipt_json IS NOT NULL
                            AND NEW.status='succeeded'
                        )
                    )
                    OR (
                        (OLD.status='succeeded' OR OLD.receipt_json IS NOT NULL)
                        AND NEW.status IS NOT OLD.status
                    )
                BEGIN
                    SELECT RAISE(ABORT, 'fq_outbox signed archive is immutable');
                END"""
            ),
            "fq_outbox_archive_no_delete": normalise(
                """CREATE TRIGGER fq_outbox_archive_no_delete
                BEFORE DELETE ON fq_outbox
                BEGIN
                    SELECT RAISE(ABORT, 'fq_outbox signed archive is immutable');
                END"""
            ),
            "fq_draft_submission_archive_no_update": normalise(
                """CREATE TRIGGER fq_draft_submission_archive_no_update
                BEFORE UPDATE ON fq_drafts
                WHEN OLD.submission_message_id IS NOT NULL
                    AND (
                        NEW.revision IS NOT OLD.revision
                        OR NEW.submission_revision IS NOT OLD.submission_revision
                        OR NEW.correlation_id IS NOT OLD.correlation_id
                        OR NEW.predecessor_message_id IS NOT OLD.predecessor_message_id
                        OR NEW.predecessor_payload_sha256
                            IS NOT OLD.predecessor_payload_sha256
                        OR NEW.contract_version IS NOT OLD.contract_version
                        OR NEW.payload_json IS NOT OLD.payload_json
                        OR NEW.confirmation_json IS NOT OLD.confirmation_json
                        OR NEW.submission_message_id IS NOT OLD.submission_message_id
                        OR (
                            NEW.status IS NOT OLD.status
                            AND NOT (
                                OLD.status='queued'
                                AND NEW.status='submitted'
                                AND OLD.receipt_json IS NULL
                                AND NEW.receipt_json IS NOT NULL
                            )
                        )
                        OR (
                            NEW.receipt_json IS NOT OLD.receipt_json
                            AND NOT (
                                OLD.receipt_json IS NULL
                                AND NEW.receipt_json IS NOT NULL
                                AND OLD.status='queued'
                                AND NEW.status='submitted'
                            )
                        )
                    )
                BEGIN
                    SELECT RAISE(ABORT, 'fq_draft submission projection is immutable');
                END"""
            ),
            "fq_draft_submission_archive_no_delete": normalise(
                """CREATE TRIGGER fq_draft_submission_archive_no_delete
                BEFORE DELETE ON fq_drafts
                WHEN OLD.submission_message_id IS NOT NULL
                BEGIN
                    SELECT RAISE(ABORT, 'fq_draft submission projection is immutable');
                END"""
            ),
        }
        indexes = {
            "idx_fq_draft_predecessor_unique": normalise(
                """CREATE UNIQUE INDEX idx_fq_draft_predecessor_unique
                ON fq_drafts(predecessor_message_id)
                WHERE predecessor_message_id IS NOT NULL"""
            )
        }
        return triggers, indexes

    @classmethod
    def _archive_guards_intact(cls, db: Any) -> bool:
        expected_triggers, expected_indexes = cls._archive_guard_definitions()
        trigger_rows = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
            "AND tbl_name IN ('fq_outbox','fq_drafts')"
        ).fetchall()
        actual_triggers: dict[str, str] = {}
        for row in trigger_rows:
            name = str(row["name"])
            sql = row["sql"]
            if name not in expected_triggers or not isinstance(sql, str):
                return False
            actual_triggers[name] = " ".join(sql.split())
        if actual_triggers != expected_triggers:
            return False
        index_rows = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='index' "
            "AND name='idx_fq_draft_predecessor_unique'"
        ).fetchall()
        actual_indexes = {
            str(row["name"]): " ".join(str(row["sql"]).split())
            for row in index_rows
            if isinstance(row["sql"], str)
        }
        return actual_indexes == expected_indexes

    @classmethod
    def _install_archive_guards(cls, db: Any) -> None:
        trigger_definitions, _ = cls._archive_guard_definitions()
        for sql in trigger_definitions.values():
            db.execute(
                sql.replace("CREATE TRIGGER ", "CREATE TRIGGER IF NOT EXISTS ", 1)
            )

    def _verify_submission_archive_projection(self, db: Any) -> dict[str, Any]:
        """Cross-check append-only audit facts against submission projections."""

        confirmed: dict[str, tuple[str, str | None]] = {}
        delivered: set[str] = set()

        def failure(reason: str, message_id: str | None = None) -> dict[str, Any]:
            return {
                "valid": False,
                "failure": reason,
                "message_id": message_id,
            }

        for row in db.execute(
            "SELECT event_type,details_json FROM fq_audit ORDER BY sequence"
        ).fetchall():
            try:
                details = json.loads(str(row["details_json"]))
            except (TypeError, json.JSONDecodeError):
                return failure("audit_details_invalid")
            if not isinstance(details, dict):
                return failure("audit_details_invalid")
            event_type = str(row["event_type"])
            if event_type == "five_quantity_confirmed_and_queued":
                message_id = details.get("message_id")
                draft_id = details.get("draft_id")
                payload_sha256 = details.get("payload_sha256")
                if not isinstance(message_id, str) or not isinstance(draft_id, str):
                    return failure("confirmed_audit_binding_invalid")
                previous = confirmed.get(message_id)
                current = (
                    draft_id,
                    payload_sha256 if isinstance(payload_sha256, str) else None,
                )
                if previous is not None and previous != current:
                    return failure("confirmed_audit_binding_conflict", message_id)
                confirmed[message_id] = current
            elif event_type == "five_quantity_outbox_delivered":
                message_id = details.get("message_id")
                if details.get("kind") == "submission":
                    if not isinstance(message_id, str):
                        return failure("delivered_audit_binding_invalid")
                    delivered.add(message_id)

        for message_id, (draft_id, audited_payload_hash) in confirmed.items():
            draft = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            outbox = db.execute(
                "SELECT * FROM fq_outbox WHERE message_id=? "
                "AND aggregate_id=? AND message_kind='submission'",
                (message_id, draft_id),
            ).fetchone()
            if draft is None:
                return failure("confirmed_draft_missing", message_id)
            if outbox is None:
                return failure("confirmed_outbox_missing", message_id)
            body_json = str(outbox["body_json"])
            if not hmac.compare_digest(
                hashlib.sha256(body_json.encode()).hexdigest(),
                str(outbox["body_sha256"]),
            ):
                return failure("confirmed_outbox_body_hash_mismatch", message_id)
            try:
                body = json.loads(body_json)
            except json.JSONDecodeError:
                return failure("confirmed_outbox_body_invalid", message_id)
            if not isinstance(body, dict) or body.get("message_id") != message_id:
                return failure("confirmed_outbox_message_mismatch", message_id)
            if body.get("contract_version") == CURRENT_SUBMISSION_CONTRACT:
                try:
                    _verify_stored_v3_submission(body, identity=self.identity)
                except ConflictError:
                    return failure("confirmed_v3_signature_invalid", message_id)
            envelope = body.get("signature_envelope")
            declared_payload_hash = (
                envelope.get("payload_sha256") if isinstance(envelope, dict) else None
            )
            if (
                audited_payload_hash is not None
                and declared_payload_hash != audited_payload_hash
            ):
                return failure("confirmed_audit_payload_hash_mismatch", message_id)

        for message_id in delivered:
            binding = confirmed.get(message_id)
            if binding is None:
                return failure("delivered_without_confirmed_audit", message_id)
            draft_id, _ = binding
            source = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            outbox = db.execute(
                "SELECT * FROM fq_outbox WHERE message_id=? "
                "AND aggregate_id=? AND message_kind='submission'",
                (message_id, draft_id),
            ).fetchone()
            if source is None or outbox is None:
                return failure("delivered_projection_missing", message_id)
            if (
                outbox["status"] != "succeeded"
                or outbox["receipt_json"] is None
                or source["status"] not in {"submitted", "acknowledged"}
                or source["submission_message_id"] != message_id
                or source["receipt_json"] is None
            ):
                return failure("delivered_projection_incomplete", message_id)
            if not hmac.compare_digest(
                str(outbox["receipt_json"]), str(source["receipt_json"])
            ):
                return failure("delivered_receipt_projection_mismatch", message_id)
            if source["contract_version"] == CURRENT_SUBMISSION_CONTRACT:
                try:
                    self._verify_archived_submission(db, source)
                except ConflictError:
                    return failure("delivered_v3_archive_invalid", message_id)

        succeeded_rows = db.execute(
            "SELECT message_id FROM fq_outbox "
            "WHERE message_kind='submission' AND status='succeeded'"
        ).fetchall()
        for row in succeeded_rows:
            message_id = str(row["message_id"])
            if message_id not in delivered:
                return failure("succeeded_without_delivered_audit", message_id)
        return {
            "valid": True,
            "failure": None,
            "confirmed_count": len(confirmed),
            "delivered_count": len(delivered),
        }

    @staticmethod
    def _loads(value: str | None) -> Any:
        return json.loads(value) if value is not None else None

    def _is_human_preparer(self, actor: str) -> bool:
        return actor in self.human_preparer_actor_ids

    def _assert_human_preparer(self, actor: str) -> None:
        if self.four_eyes_required and not self._is_human_preparer(actor):
            raise ValidationBlockedError(
                "正式流程仅允许配置中的具名经办账号接收、核对并保存草稿；"
                "机器账号、连接器账号、系统观察器或复核账号不能充当经办人"
            )

    def _append_audit(
        self,
        db: Any,
        event_type: str,
        actor: str,
        details: dict[str, Any],
    ) -> None:
        integrity = self._verify_audit_in_transaction(db)
        if not integrity["valid"]:
            raise ConflictError(
                "报送审计链或审计锚点异常；已拒绝写入，请联系管理员核验数据库"
            )
        previous = db.execute(
            "SELECT sequence,event_hash FROM fq_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = str(previous["event_hash"]) if previous else ZERO_HASH
        occurred_at = utc_text()
        event_hash = _audit_hash(
            previous_hash, sequence, event_type, actor, occurred_at, details
        )
        db.execute(
            "INSERT INTO fq_audit VALUES (?,?,?,?,?,?,?)",
            (
                sequence,
                event_type,
                actor,
                occurred_at,
                jcs_json(details),
                previous_hash,
                event_hash,
            ),
        )
        db.execute(
            "INSERT INTO fq_audit_anchor(singleton,event_count,head_hash,updated_at) "
            "VALUES (1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET "
            "event_count=excluded.event_count,head_hash=excluded.head_hash,"
            "updated_at=excluded.updated_at",
            (sequence, event_hash, occurred_at),
        )

    def create_import(
        self,
        imported: dict[str, Any],
        *,
        source_path: str | None,
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        contract_version = imported.get("contract_version")
        if contract_version != CURRENT_SUBMISSION_CONTRACT:
            raise ValueError("新导入只能创建十量 V3 草稿")
        acquisition_mode = str(imported["acquisition_mode"])
        human_prepared = (
            acquisition_mode == "manual_import" and self._is_human_preparer(actor)
        )
        if self.four_eyes_required and acquisition_mode == "manual_import":
            self._assert_human_preparer(actor)
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_imports WHERE content_sha256=?",
                (imported["content_sha256"],),
            ).fetchone()
            if existing is not None:
                existing_draft = db.execute(
                    "SELECT contract_version FROM fq_drafts WHERE draft_id=?",
                    (existing["draft_id"],),
                ).fetchone()
                if (
                    existing_draft is not None
                    and existing_draft["contract_version"]
                    == LEGACY_SUBMISSION_CONTRACT
                ):
                    raise ConflictError(
                        "相同原件已有只读五量 V2 草稿；系统不会覆盖或升级其审计记录，"
                        "请从源系统重新导出十量文件后建稿"
                    )
                existing_mapping = _column_mapping_sha256(
                    self._loads(existing["suggestions_json"])
                )
                requested_mapping = _column_mapping_sha256(imported["suggestions"])
                if not hmac.compare_digest(existing_mapping, requested_mapping):
                    raise ConflictError(
                        "相同 CSV 原件已按另一套字段映射生成草稿；"
                        "当前确认映射未被采用，请放弃旧草稿后使用修订后的源文件重试"
                    )
                result = dict(existing)
                result["duplicate"] = True
                return result
            import_id = str(uuid.uuid4())
            draft_id = str(uuid.uuid4())
            db.execute(
                """INSERT INTO fq_imports(
                    import_id,content_sha256,filename,acquisition_mode,source_path,
                    status,error_message,draft_id,suggestions_json,created_at
                ) VALUES (?,?,?,?,?,'ready_review',NULL,?,?,?)""",
                (
                    import_id,
                    imported["content_sha256"],
                    imported["filename"],
                    imported["acquisition_mode"],
                    source_path,
                    draft_id,
                    jcs_json(imported["suggestions"]),
                    now,
                ),
            )
            db.execute(
                """INSERT INTO fq_drafts(
                    draft_id,import_id,revision,submission_revision,
                    contract_version,status,
                    payload_json,created_by,last_content_actor,
                    human_preparer_actor,human_prepared_revision,
                    created_at,updated_at
                ) VALUES (?,?,1,1,?,'ready_review',?,?,?,?,?,?,?)""",
                (
                    draft_id,
                    import_id,
                    contract_version,
                    jcs_json(imported["payload"]),
                    actor,
                    actor,
                    actor if human_prepared else None,
                    1 if human_prepared else None,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "five_quantity_imported",
                actor,
                {
                    "import_id": import_id,
                    "draft_id": draft_id,
                    "content_sha256": imported["content_sha256"],
                    "acquisition_mode": imported["acquisition_mode"],
                },
            )
            return {
                "import_id": import_id,
                "draft_id": draft_id,
                "status": "ready_review",
                "duplicate": False,
            }

    def create_or_update_machine_import(
        self,
        imported: dict[str, Any],
        *,
        ingestion_id: str,
        lease_owner: str,
        client_id: str,
        draft_key: str,
        source_id: str,
        source_revision: int,
        source_observed_at: str,
        source_coverage_as_of: str,
        source_required: bool,
        freshness_max_seconds: int,
        actor: str,
        identity: MineIdentity,
    ) -> dict[str, Any]:
        """Atomically replace one source snapshot and rebuild the V2 draft."""

        now = utc_text()
        contract_version = imported.get("contract_version")
        if contract_version != CURRENT_SUBMISSION_CONTRACT:
            raise ValueError("机器来源只能创建十量 V3 草稿")
        with self.repository._transaction() as db:
            ingestion = db.execute(
                "SELECT * FROM connector_ingestions WHERE ingestion_id = ?",
                (ingestion_id,),
            ).fetchone()
            if (
                ingestion is None
                or ingestion["status"] != "bound"
                or ingestion["lease_owner"] != lease_owner
                or ingestion["client_id"] != client_id
                or ingestion["draft_key"] != draft_key
                or ingestion["source_id"] != source_id
                or int(ingestion["source_revision"]) != source_revision
                or ingestion["source_observed_at"] != source_observed_at
                or ingestion["source_coverage_as_of"] != source_coverage_as_of
            ):
                raise ConflictError("机器自动填报租约或来源快照已变化")

            previous = db.execute(
                """
                SELECT * FROM fq_machine_source_contributions
                WHERE client_id = ? AND draft_key = ? AND source_id = ?
                """,
                (client_id, draft_key, source_id),
            ).fetchone()
            if previous is not None:
                previous_revision = int(previous["source_revision"])
                if source_revision < previous_revision:
                    raise ConflictError("机器来源 revision 倒退")
                if (
                    source_revision == previous_revision
                    and imported["content_sha256"] != previous["content_sha256"]
                ):
                    raise ConflictError("同一机器来源 revision 的内容发生冲突")

            binding = db.execute(
                """
                SELECT * FROM connector_draft_bindings
                WHERE client_id = ? AND draft_key = ?
                """,
                (client_id, draft_key),
            ).fetchone()
            draft_id = (
                str(binding["draft_id"])
                if binding is not None
                else str(uuid.uuid4())
            )
            draft_row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id = ?",
                (draft_id,),
            ).fetchone()
            if binding is not None and draft_row is None:
                raise ConflictError("机器 draft_key 绑定记录损坏")
            if (
                draft_row is not None
                and draft_row["contract_version"] != CURRENT_SUBMISSION_CONTRACT
            ):
                raise ConflictError("五量 V2 机器草稿为只读，不能由 V3 来源覆盖")
            replacement_of: str | None = None
            if draft_row is not None:
                if draft_row["status"] == "discarded":
                    replacement_of = draft_id
                    draft_id = str(uuid.uuid4())
                    draft_row = None
                else:
                    current_payload = json.loads(draft_row["payload_json"])
                    if (
                        int(draft_row["revision"])
                        != int(binding["last_machine_revision"])
                        or sha256_jcs(current_payload)
                        != str(binding["last_machine_payload_sha256"])
                    ):
                        raise ConflictError(
                            "草稿已有人工编辑；机器来源不能覆盖；"
                            "请由具名用户审计后恢复自动同步"
                        )
                    pending = db.execute(
                        """
                        SELECT 1 FROM fq_outbox
                        WHERE aggregate_id = ? AND message_kind = 'submission'
                        LIMIT 1
                        """,
                        (draft_id,),
                    ).fetchone()
                    if (
                        draft_row["status"] != "ready_review"
                        or draft_row["confirmation_json"] is not None
                        or draft_row["submission_message_id"] is not None
                        or pending is not None
                    ):
                        raise ConflictError(
                            "已确认或已发送的报送草稿不能自动改写"
                        )

            same_content = (
                previous is not None
                and imported["content_sha256"] == previous["content_sha256"]
            )
            repeated_snapshot = (
                same_content
                and previous is not None
                and source_revision == int(previous["source_revision"])
            )
            effective_payload = (
                json.loads(previous["payload_json"])
                if repeated_snapshot and previous is not None
                else imported["payload"]
            )
            contribution_rows = db.execute(
                """
                SELECT * FROM fq_machine_source_contributions
                WHERE client_id = ? AND draft_key = ? AND source_id != ?
                ORDER BY source_id
                """,
                (client_id, draft_key, source_id),
            ).fetchall()
            contribution_payloads = [
                json.loads(row["payload_json"]) for row in contribution_rows
            ]
            contribution_payloads.append(effective_payload)
            merged = _merge_machine_payloads(contribution_payloads)
            validate_five_quantity_payload(
                merged,
                identity=identity,
                confirmed=False,
                contract_version=CURRENT_SUBMISSION_CONTRACT,
            )
            reporting_month = str(merged["reporting_month"])
            expected_draft_key = (
                f"draft:{identity.operator_id}:five-quantity:monthly:"
                f"{reporting_month}"
            )
            if draft_key != expected_draft_key:
                raise ConflictError(
                    "draft_key 必须等于当前经营主体和月份的权威报送草稿键"
                )
            if binding is not None and binding["reporting_month"] != reporting_month:
                raise ConflictError("draft_key 已绑定其他报送月份")

            content_row = db.execute(
                "SELECT * FROM fq_imports WHERE content_sha256 = ?",
                (imported["content_sha256"],),
            ).fetchone()
            content_owned_by_binding = False
            if content_row is not None:
                content_owned_by_binding = (
                    db.execute(
                        """
                        SELECT 1 FROM fq_machine_source_artifacts
                        WHERE client_id=? AND draft_key=? AND source_id=?
                            AND content_sha256=? AND import_id=?
                        LIMIT 1
                        """,
                        (
                            client_id,
                            draft_key,
                            source_id,
                            imported["content_sha256"],
                            content_row["import_id"],
                        ),
                    ).fetchone()
                    is not None
                )
            if (
                content_row is not None
                and content_row["draft_id"] != draft_id
                and not content_owned_by_binding
            ):
                raise ConflictError("相同来源文件已绑定其他报送草稿")
            duplicate_content = content_row is not None
            draft_import_id: str
            if content_row is None:
                import_id = str(uuid.uuid4())
                draft_import_id = import_id
                db.execute(
                    """
                    INSERT INTO fq_imports(
                        import_id,content_sha256,filename,acquisition_mode,
                        source_path,status,error_message,draft_id,
                        suggestions_json,created_at
                    ) VALUES (?,?,?,'direct_collection',?,'ready_review',
                        NULL,?,?,?)
                    """,
                    (
                        import_id,
                        imported["content_sha256"],
                        imported["filename"],
                        f"connector:{source_id}"[:1000],
                        draft_id,
                        jcs_json(imported["suggestions"]),
                        now,
                    ),
                )
            elif replacement_of is not None:
                import_id = str(content_row["import_id"])
                draft_import_id = str(uuid.uuid4())
                replacement_hash = hashlib.sha256(
                    (
                        "machine-replacement-snapshot-v1\n"
                        f"{replacement_of}\n{draft_id}\n{jcs_json(merged)}"
                    ).encode()
                ).hexdigest()
                db.execute(
                    """
                    INSERT INTO fq_imports(
                        import_id,content_sha256,filename,acquisition_mode,
                        source_path,status,error_message,draft_id,
                        suggestions_json,created_at
                    ) VALUES (?,?,?,'direct_collection',?,'ready_review',
                        NULL,?,?,?)
                    """,
                    (
                        draft_import_id,
                        replacement_hash,
                        f"machine-replacement-{reporting_month}.json",
                        f"connector:replacement:{replacement_of}"[:1000],
                        draft_id,
                        jcs_json(imported["suggestions"]),
                        now,
                    ),
                )
            else:
                import_id = str(content_row["import_id"])
                draft_import_id = import_id

            if draft_row is None:
                draft_revision = 1
                db.execute(
                    """
                    INSERT INTO fq_drafts(
                        draft_id,import_id,revision,submission_revision,
                        contract_version,status,
                        payload_json,created_by,last_content_actor,
                        human_preparer_actor,human_prepared_revision,
                        created_at,updated_at
                    ) VALUES (?,?,1,1,?,'ready_review',?,?,?,NULL,NULL,?,?)
                    """,
                    (
                        draft_id,
                        draft_import_id,
                        contract_version,
                        jcs_json(merged),
                        actor,
                        actor,
                        now,
                        now,
                    ),
                )
                if binding is None:
                    db.execute(
                        """
                        INSERT INTO connector_draft_bindings(
                            client_id,draft_key,draft_id,reporting_month,
                            last_machine_revision,last_machine_payload_sha256,
                            created_at
                        ) VALUES (?,?,?,?,?,?,?)
                        """,
                        (
                            client_id,
                            draft_key,
                            draft_id,
                            reporting_month,
                            draft_revision,
                            sha256_jcs(merged),
                            now,
                        ),
                    )
                else:
                    db.execute(
                        """
                        UPDATE connector_draft_bindings
                        SET draft_id=?,reporting_month=?,
                            last_machine_revision=?,
                            last_machine_payload_sha256=?
                        WHERE client_id=? AND draft_key=?
                        """,
                        (
                            draft_id,
                            reporting_month,
                            draft_revision,
                            sha256_jcs(merged),
                            client_id,
                            draft_key,
                        ),
                    )
            else:
                changed = sha256_jcs(current_payload) != sha256_jcs(merged)
                draft_revision = int(draft_row["revision"]) + int(changed)
                if changed:
                    db.execute(
                        """
                        UPDATE fq_drafts
                        SET revision = ?, payload_json = ?,
                            last_content_actor = ?, human_preparer_actor = NULL,
                            human_prepared_revision = NULL, updated_at = ?
                        WHERE draft_id = ?
                        """,
                        (
                            draft_revision,
                            jcs_json(merged),
                            actor,
                            now,
                            draft_id,
                        ),
                    )

            db.execute(
                """
                INSERT OR IGNORE INTO fq_machine_source_artifacts(
                    client_id,draft_key,source_id,content_sha256,import_id,
                    first_ingestion_id,created_at
                ) VALUES (?,?,?,?,?,?,?)
                """,
                (
                    client_id,
                    draft_key,
                    source_id,
                    imported["content_sha256"],
                    import_id,
                    ingestion_id,
                    now,
                ),
            )
            db.execute(
                """
                INSERT INTO fq_machine_source_contributions(
                    client_id,draft_key,source_id,source_revision,event_id,
                    ingestion_id,import_id,draft_id,content_sha256,
                    source_observed_at,source_coverage_as_of,payload_json,
                    created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(client_id,draft_key,source_id) DO UPDATE SET
                    source_revision=excluded.source_revision,
                    event_id=excluded.event_id,
                    ingestion_id=excluded.ingestion_id,
                    import_id=excluded.import_id,
                    content_sha256=excluded.content_sha256,
                    source_observed_at=excluded.source_observed_at,
                    source_coverage_as_of=excluded.source_coverage_as_of,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (
                    client_id,
                    draft_key,
                    source_id,
                    source_revision,
                    ingestion["event_id"],
                    ingestion_id,
                    import_id,
                    draft_id,
                    imported["content_sha256"],
                    source_observed_at,
                    source_coverage_as_of,
                    jcs_json(effective_payload),
                    now,
                    now,
                ),
            )
            if replacement_of is not None:
                db.execute(
                    """
                    UPDATE fq_machine_source_contributions SET draft_id=?
                    WHERE client_id=? AND draft_key=?
                    """,
                    (draft_id, client_id, draft_key),
                )
            self.repository.apply_connector_snapshot_health_in_transaction(
                db,
                client_id=client_id,
                draft_key=draft_key,
                reporting_month=reporting_month,
                source_id=source_id,
                source_system=str(ingestion["source_system"]),
                source_required=source_required,
                freshness_max_seconds=freshness_max_seconds,
                completed_at=source_observed_at,
                record_count=len(effective_payload["days"]),
                coverage_as_of=source_coverage_as_of,
                snapshot_sha256=imported["content_sha256"],
                autofill_event_id=str(ingestion["event_id"]),
                source_revision=source_revision,
                ingestion_id=ingestion_id,
                received_at=now,
            )
            payload_sha256 = sha256_jcs(merged)
            if binding is not None:
                db.execute(
                    """
                    UPDATE connector_draft_bindings
                    SET last_machine_revision = ?,
                        last_machine_payload_sha256 = ?
                    WHERE client_id = ? AND draft_key = ?
                    """,
                    (draft_revision, payload_sha256, client_id, draft_key),
                )
            # Always persist the deterministic check.  trigger_workflow only
            # controls whether the caller requested the broader workflow; a
            # quiet ingestion still needs a revision/hash-bound safety record.
            preflight = _v2_machine_preflight(
                merged,
                revision=draft_revision,
                contract_version=CURRENT_SUBMISSION_CONTRACT,
            )
            contribution_count = len(contribution_rows) + 1
            import_summary = {
                # Persist the contract that actually produced this new record.
                # Existing rows keep their legacy V2 label unchanged and remain
                # readable; no migration rewrites historical ingestion bytes.
                "mode": "ten_quantity_v3_direct_collection",
                "import_id": import_id,
                "duplicate_content": duplicate_content,
                "merge": {
                    "source_id": source_id,
                    "source_revision": source_revision,
                    "same_content": same_content,
                    "repeated_snapshot": repeated_snapshot,
                    "contribution_count": contribution_count,
                    "day_count": len(merged["days"]),
                    "evidence_source_count": len(merged["sources"]),
                },
            }
            updated = db.execute(
                """
                UPDATE connector_ingestions
                SET status = 'imported', draft_id = ?,
                    import_summary_json = ?, draft_revision = ?,
                    draft_payload_sha256 = ?, workflow_result_json = ?,
                    updated_at = ?
                WHERE ingestion_id = ? AND status = 'bound'
                    AND lease_owner = ?
                """,
                (
                    draft_id,
                    jcs_json(import_summary),
                    draft_revision,
                    payload_sha256,
                    jcs_json(preflight) if preflight is not None else None,
                    now,
                    ingestion_id,
                    lease_owner,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("机器自动填报租约已失效")
            self._append_audit(
                db,
                "five_quantity_machine_autofilled",
                actor,
                {
                    "ingestion_id": ingestion_id,
                    "event_id": ingestion["event_id"],
                    "draft_id": draft_id,
                    "import_id": import_id,
                    "source_id": source_id,
                    "source_revision": source_revision,
                    "content_sha256": imported["content_sha256"],
                    "draft_revision": draft_revision,
                    "payload_sha256": payload_sha256,
                    "preflight_performed": preflight is not None,
                    "replacement_of_discarded_draft_id": replacement_of,
                },
            )
            if replacement_of is not None:
                self._append_audit(
                    db,
                    "five_quantity_machine_draft_replaced",
                    actor,
                    {
                        "discarded_draft_id": replacement_of,
                        "replacement_draft_id": draft_id,
                        "reporting_month": reporting_month,
                        "payload_sha256": payload_sha256,
                    },
                )
        return {
            "draft_id": draft_id,
            "draft_revision": draft_revision,
            "payload_sha256": payload_sha256,
            "import_summary": import_summary,
            "preflight": preflight,
        }

    def record_quarantine(
        self,
        *,
        filename: str,
        content_sha256: str,
        acquisition_mode: str,
        source_path: str | None,
        error_message: str,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_imports WHERE content_sha256=?", (content_sha256,)
            ).fetchone()
            if existing is not None:
                return dict(existing)
            import_id = str(uuid.uuid4())
            db.execute(
                """INSERT INTO fq_imports(
                    import_id,content_sha256,filename,acquisition_mode,source_path,
                    status,error_message,draft_id,suggestions_json,created_at
                ) VALUES (?,?,?,?,?,'quarantined',?,NULL,'[]',?)""",
                (
                    import_id,
                    content_sha256,
                    filename[:255],
                    acquisition_mode,
                    source_path,
                    error_message[:1000],
                    now,
                ),
            )
            self._append_audit(
                db,
                "five_quantity_quarantined",
                "system-watcher",
                {
                    "import_id": import_id,
                    "content_sha256": content_sha256,
                    "error": error_message[:500],
                },
            )
            return {"import_id": import_id, "status": "quarantined"}

    def list_imports(
        self, limit: int = 100, *, include_discarded: bool = False
    ) -> list[dict[str, Any]]:
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_imports "
                + ("" if include_discarded else "WHERE status!='discarded' ")
                + "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                **dict(row),
                "suggestions": self._loads(row["suggestions_json"]),
                "suggestions_json": None,
            }
            for row in rows
        ]

    def _draft(self, row: Any) -> dict[str, Any]:
        contract_version = str(row["contract_version"])
        predecessor = (
            {
                "message_id": row["predecessor_message_id"],
                "payload_sha256": row["predecessor_payload_sha256"],
            }
            if row["predecessor_message_id"] is not None
            and row["predecessor_payload_sha256"] is not None
            else None
        )
        return {
            "draft_id": row["draft_id"],
            "import_id": row["import_id"],
            "revision": row["revision"],
            "submission_revision": row["submission_revision"],
            "correlation_id": row["correlation_id"],
            "predecessor": predecessor,
            "contract_version": contract_version,
            "read_only": contract_version == LEGACY_SUBMISSION_CONTRACT,
            "status": row["status"],
            "payload": self._loads(row["payload_json"]),
            "confirmation": self._loads(row["confirmation_json"]),
            "submission_message_id": row["submission_message_id"],
            "receipt": self._loads(row["receipt_json"]),
            "created_by": row["created_by"],
            "last_content_actor": row["last_content_actor"],
            "human_preparer_actor": row["human_preparer_actor"],
            "human_prepared_revision": row["human_prepared_revision"],
            "review_gate": self._review_gate(
                row["last_content_actor"],
                status=row["status"],
                confirmation=self._loads(row["confirmation_json"]),
                human_preparer_actor=row["human_preparer_actor"],
                human_prepared_revision=row["human_prepared_revision"],
                current_revision=row["revision"],
                require_human_preparer=True,
            ),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _review_gate(
        self,
        last_actor: Any,
        *,
        status: Any = None,
        confirmation: Any = None,
        human_preparer_actor: Any = None,
        human_prepared_revision: Any = None,
        current_revision: Any = None,
        require_human_preparer: bool = False,
    ) -> dict[str, Any]:
        if not self.four_eyes_required:
            return {
                "required": False,
                "state": "not_required",
                "message": "当前由业务管理员完成填报、确认和报送，不要求双人复核",
            }
        if not isinstance(last_actor, str) or not last_actor:
            return {
                "required": True,
                "state": "actor_record_missing",
                "message": "历史草稿缺少经办人记录，请重新导入或另存后再复核",
            }
        if require_human_preparer and (
            not isinstance(human_preparer_actor, str)
            or not human_preparer_actor
            or not isinstance(human_prepared_revision, int)
            or human_prepared_revision != current_revision
        ):
            return {
                "required": True,
                "state": "awaiting_human_preparer",
                "last_content_actor": last_actor,
                "message": (
                    "自动生成或历史草稿尚未由具名经办账号接收核对；"
                    "请经办人打开草稿并点击保存，再交由另一账号复核"
                ),
            }
        if status in {"queued", "submitted"} and isinstance(confirmation, dict):
            reviewer = confirmation.get("actor_id")
            independently_reviewed = bool(
                isinstance(reviewer, str)
                and reviewer
                and reviewer != last_actor
                and (
                    not require_human_preparer
                    or reviewer != human_preparer_actor
                )
            )
            return {
                "required": True,
                "state": (
                    "independent_review_completed"
                    if independently_reviewed
                    else "legacy_separation_unverified"
                ),
                "last_content_actor": last_actor,
                "human_preparer_actor": human_preparer_actor,
                "reviewer_actor": reviewer,
                "message": (
                    "已由不同具名账号完成四眼复核并进入受控发送流程"
                    if independently_reviewed
                    else "历史记录无法证明经办复核分离，不得作为新正式报送依据"
                ),
            }
        return {
            "required": True,
            "state": "awaiting_independent_reviewer",
            "last_content_actor": last_actor,
            "human_preparer_actor": human_preparer_actor,
            "message": "待另一具名账号复核；最后创建/编辑人不能确认或入发送队列",
        }

    def _assert_independent_actor(
        self,
        row: Any,
        actor: str,
        *,
        subject: str,
        require_human_preparer: bool = False,
    ) -> None:
        if not self.four_eyes_required:
            return
        last_actor = row["last_content_actor"]
        if not isinstance(last_actor, str) or not last_actor:
            raise ValidationBlockedError(
                f"{subject}缺少可核验的创建/编辑人记录；请重新导入或另存后再复核"
            )
        if actor == last_actor:
            raise ValidationBlockedError(
                "四眼复核已启用：当前账号是本修订版的最后创建/编辑人，"
                "请退出并由另一名具备复核报送权限的具名账号操作"
            )
        if require_human_preparer:
            preparer = row["human_preparer_actor"]
            prepared_revision = row["human_prepared_revision"]
            if (
                not isinstance(preparer, str)
                or not preparer
                or not isinstance(prepared_revision, int)
                or prepared_revision != int(row["revision"])
            ):
                raise ValidationBlockedError(
                    "该自动生成或历史草稿尚未由配置中的具名经办账号核对并保存；"
                    "不能直接复核报送"
                )
            if actor == preparer:
                raise ValidationBlockedError(
                    "四眼复核已启用：经办保存人与确认人必须是两个不同具名账号"
                )

    def get_draft(self, draft_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("报送草稿不存在")
        return self._draft(row)

    def machine_sync_state(self, draft_id: str) -> dict[str, Any] | None:
        """Describe whether a machine-managed draft may still auto-update."""

        with self.repository._read() as db:
            draft = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if draft is None:
                raise NotFoundError("报送草稿不存在")
            binding = db.execute(
                "SELECT * FROM connector_draft_bindings WHERE draft_id=?",
                (draft_id,),
            ).fetchone()
            if binding is None:
                evidence = db.execute(
                    "SELECT 1 FROM connector_ingestions WHERE draft_id=? LIMIT 1",
                    (draft_id,),
                ).fetchone()
                if evidence is None:
                    return None
                return {
                    "state": "paused",
                    "reason_code": "machine_draft_replaced_or_unbound",
                    "message": "该历史机器草稿已不再是当前自动同步目标",
                    "can_resume": False,
                }
            current_hash = sha256_jcs(json.loads(draft["payload_json"]))
            revision_matches = int(draft["revision"]) == int(
                binding["last_machine_revision"]
            )
            payload_matches = current_hash == str(
                binding["last_machine_payload_sha256"]
            )
            if draft["status"] != "ready_review":
                reason_code = f"draft_{draft['status']}"
                message = "草稿已确认、发送或放弃，自动同步已暂停"
                can_resume = False
            elif not revision_matches or not payload_matches:
                reason_code = "human_changes_detected"
                message = "检测到人工修改，自动同步已暂停以避免覆盖"
                can_resume = True
            else:
                return {
                    "state": "active",
                    "reason_code": None,
                    "message": "机器来源可继续更新此待复核草稿",
                    "can_resume": False,
                    "authoritative_client_id": str(binding["client_id"]),
                    "last_machine_revision": int(
                        binding["last_machine_revision"]
                    ),
                }
            return {
                "state": "paused",
                "reason_code": reason_code,
                "message": message,
                "can_resume": can_resume,
                "authoritative_client_id": str(binding["client_id"]),
                "last_machine_revision": int(binding["last_machine_revision"]),
            }

    def resume_machine_sync(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        actor: str,
        identity: MineIdentity,
    ) -> dict[str, Any]:
        """Explicitly discard human edits and restore latest machine snapshots."""

        now = utc_text()
        with self.repository._transaction() as db:
            draft = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if draft is None:
                raise NotFoundError("报送草稿不存在")
            if draft["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
                raise ConflictError("五量 V2 草稿仅供读取，不能恢复自动同步")
            if int(draft["revision"]) != expected_revision:
                raise ConflictError("草稿修订号已变化，请刷新后重试")
            binding = db.execute(
                "SELECT * FROM connector_draft_bindings WHERE draft_id=?",
                (draft_id,),
            ).fetchone()
            if binding is None:
                raise ConflictError("该草稿不是当前机器自动同步目标")
            pending = db.execute(
                "SELECT 1 FROM fq_outbox WHERE aggregate_id=? "
                "AND message_kind='submission' LIMIT 1",
                (draft_id,),
            ).fetchone()
            if (
                draft["status"] != "ready_review"
                or draft["confirmation_json"] is not None
                or draft["submission_message_id"] is not None
                or pending is not None
            ):
                raise ConflictError("仅未确认、待复核的机器草稿可以恢复自动同步")
            contributions = db.execute(
                """
                SELECT * FROM fq_machine_source_contributions
                WHERE client_id=? AND draft_key=? ORDER BY source_id
                """,
                (binding["client_id"], binding["draft_key"]),
            ).fetchall()
            if not contributions:
                raise ConflictError("机器来源快照缺失，不能恢复自动同步")
            merged = _merge_machine_payloads(
                [json.loads(row["payload_json"]) for row in contributions]
            )
            validate_five_quantity_payload(
                merged,
                identity=identity,
                confirmed=False,
                contract_version=CURRENT_SUBMISSION_CONTRACT,
            )
            if merged["reporting_month"] != binding["reporting_month"]:
                raise ConflictError("机器来源月份与草稿绑定不一致")
            revision = expected_revision + 1
            payload_hash = sha256_jcs(merged)
            previous_hash = sha256_jcs(json.loads(draft["payload_json"]))
            db.execute(
                """
                UPDATE fq_drafts SET revision=?,status='ready_review',
                    payload_json=?,confirmation_json=NULL,
                    last_content_actor=?,human_preparer_actor=NULL,
                    human_prepared_revision=NULL,updated_at=?
                WHERE draft_id=?
                """,
                (revision, jcs_json(merged), actor, now, draft_id),
            )
            db.execute(
                """
                UPDATE connector_draft_bindings
                SET last_machine_revision=?,last_machine_payload_sha256=?
                WHERE client_id=? AND draft_key=?
                """,
                (
                    revision,
                    payload_hash,
                    binding["client_id"],
                    binding["draft_key"],
                ),
            )
            self._append_audit(
                db,
                "five_quantity_machine_sync_resumed",
                actor,
                {
                    "draft_id": draft_id,
                    "revision": revision,
                    "discarded_human_payload_sha256": previous_hash,
                    "restored_machine_payload_sha256": payload_hash,
                    "requires_new_event": True,
                    "source_revisions": [
                        {
                            "source_id": str(row["source_id"]),
                            "source_revision": int(row["source_revision"]),
                        }
                        for row in contributions
                    ],
                },
            )
        return self.get_draft(draft_id)

    def list_drafts(
        self, limit: int = 100, *, include_discarded: bool = False
    ) -> list[dict[str, Any]]:
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_drafts "
                + ("" if include_discarded else "WHERE status!='discarded' ")
                + "ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._draft(row) for row in rows]

    def _verify_archived_submission(
        self,
        db: Any,
        source: Any,
        *,
        identity: MineIdentity | None = None,
    ) -> dict[str, Any]:
        """Return a fully verified immutable V3 submission archive.

        This is deliberately transaction-local so correction creation and any
        later pre-send lineage gate can validate the same database snapshot.
        The two receipt copies are required to be byte-identical canonical JSON;
        neither copy is accepted merely because the other one verifies.
        """

        active_identity = identity or self.identity
        if source["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
            raise ConflictError("五量 V2 历史报文不属于十量 V3 签名归档")
        source_message_id = source["submission_message_id"]
        if not isinstance(source_message_id, str) or not source_message_id:
            raise ConflictError("前序报送缺少不可变消息 ID")
        outbox = db.execute(
            """
            SELECT * FROM fq_outbox
            WHERE message_id=? AND aggregate_id=? AND message_kind='submission'
            """,
            (source_message_id, source["draft_id"]),
        ).fetchone()
        if (
            outbox is None
            or outbox["status"] != "succeeded"
            or outbox["receipt_json"] is None
            or source["receipt_json"] is None
        ):
            raise ConflictError("前序十量 V3 尚未形成完整送达回执")

        source_body_json = str(outbox["body_json"])
        actual_body_sha256 = hashlib.sha256(
            source_body_json.encode("utf-8")
        ).hexdigest()
        if not hmac.compare_digest(actual_body_sha256, str(outbox["body_sha256"])):
            raise ConflictError("前序十量 V3 outbox 原文摘要不一致")
        try:
            source_message = _verify_stored_v3_submission(
                json.loads(source_body_json),
                identity=active_identity,
            )
        except json.JSONDecodeError as error:
            raise ConflictError("前序十量 V3 outbox 原文不是合法 JSON") from error
        source_submission_revision = int(source["submission_revision"])
        if (
            source_message["message_id"] != source_message_id
            or source_message["revision"] != source_submission_revision
            or source_message["correlation_id"] != source["correlation_id"]
        ):
            raise ConflictError("前序草稿与已签名十量 V3 消息血缘不一致")

        outbox_receipt_json = str(outbox["receipt_json"])
        source_receipt_json = str(source["receipt_json"])
        if not hmac.compare_digest(outbox_receipt_json, source_receipt_json):
            raise ConflictError("前序草稿与 outbox 保存的政府回执不一致")
        try:
            receipt = _verify_stored_intake_receipt(
                json.loads(outbox_receipt_json),
                submission=source_message,
                identity=active_identity,
            )
        except json.JSONDecodeError as error:
            raise ConflictError("前序政府接收回执不是合法 JSON") from error

        try:
            draft_payload = json.loads(str(source["payload_json"]))
        except json.JSONDecodeError as error:
            raise ConflictError("前序草稿内容不是合法 JSON") from error
        signed_business_payload = json.loads(jcs_json(source_message["payload"]))
        signed_business_payload.pop("human_confirmation", None)
        if not hmac.compare_digest(
            sha256_jcs(signed_business_payload),
            sha256_jcs(draft_payload),
        ):
            raise ConflictError("前序草稿内容与已签名送达内容不一致")
        return {
            "message": source_message,
            "receipt": receipt,
            "outbox": dict(outbox),
            "business_payload": signed_business_payload,
        }

    def create_correction_draft(
        self,
        source_draft_id: str,
        *,
        expected_revision: int,
        expected_submission_revision: int,
        actor: str,
        identity: MineIdentity,
    ) -> dict[str, Any]:
        """Create the unique editable successor of an acknowledged V3 message.

        The predecessor is read from the immutable signed outbox body rather
        than reconstructed from the mutable review model. Replaying the same
        request returns the already-created direct child and never forks the
        lineage.
        """

        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        if (
            isinstance(expected_submission_revision, bool)
            or not isinstance(expected_submission_revision, int)
            or expected_submission_revision < 1
        ):
            raise ValueError("expected_submission_revision 必须是正整数")
        self._assert_human_preparer(actor)
        now = utc_text()
        with self.repository._transaction() as db:
            integrity = self._verify_audit_in_transaction(db)
            if not integrity["valid"]:
                raise ConflictError(
                    "报送审计链或审计锚点异常；已拒绝创建更正草稿"
                )
            source = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?",
                (source_draft_id,),
            ).fetchone()
            if source is None:
                raise NotFoundError("前序报送草稿不存在")
            if source["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
                raise ConflictError("五量 V2 历史报文不能升级或发起十量 V3 更正")
            if int(source["revision"]) != expected_revision:
                raise ConflictError("前序草稿状态已变化，请刷新后重试")
            source_submission_revision = int(source["submission_revision"])
            if source_submission_revision != expected_submission_revision:
                raise ConflictError("前序报送版本已变化，请刷新后重试")
            if source["status"] not in {"submitted", "acknowledged"}:
                raise ConflictError("仅已送达并取得政府回执的十量 V3 版本可以更正")
            archive = self._verify_archived_submission(
                db,
                source,
                identity=identity,
            )
            source_message = archive["message"]
            source_message_id = source_message["message_id"]
            predecessor_hash = source_message["signature_envelope"][
                "payload_sha256"
            ]
            signed_business_payload = archive["business_payload"]

            children = db.execute(
                """
                SELECT * FROM fq_drafts
                WHERE predecessor_message_id=?
                ORDER BY created_at,draft_id
                """,
                (source_message_id,),
            ).fetchall()
            if children:
                if len(children) != 1:
                    raise ConflictError("十量 V3 更正链存在多个直接后继，已拒绝继续")
                child = children[0]
                if (
                    child["contract_version"] != CURRENT_SUBMISSION_CONTRACT
                    or child["correlation_id"] != source_message["correlation_id"]
                    or int(child["submission_revision"])
                    != source_submission_revision + 1
                    or child["predecessor_payload_sha256"] != predecessor_hash
                ):
                    raise ConflictError("已存在的十量 V3 后继草稿血缘异常")
                return {
                    "draft": self._draft(child),
                    "created": False,
                    "duplicate": True,
                    "source_draft_id": source_draft_id,
                }

            later = db.execute(
                """
                SELECT draft_id,submission_revision FROM fq_drafts
                WHERE contract_version=? AND correlation_id=?
                    AND submission_revision>?
                ORDER BY submission_revision DESC LIMIT 1
                """,
                (
                    CURRENT_SUBMISSION_CONTRACT,
                    source_message["correlation_id"],
                    source_submission_revision,
                ),
            ).fetchone()
            if later is not None:
                raise ConflictError(
                    "所选版本不是当前十量 V3 修订链末版，禁止从历史版本分叉"
                )

            correction_payload = signed_business_payload
            validate_five_quantity_payload(
                correction_payload,
                identity=identity,
                confirmed=False,
                contract_version=CURRENT_SUBMISSION_CONTRACT,
            )
            submission_revision = source_submission_revision + 1
            draft_id = str(uuid.uuid4())
            import_id = str(uuid.uuid4())
            correction_artifact_sha256 = hashlib.sha256(
                (
                    "ten-quantity-correction-draft-v1\n"
                    f"{source_message_id}\n{submission_revision}"
                ).encode()
            ).hexdigest()
            filename = (
                f"correction-{correction_payload['reporting_month']}"
                f"-r{submission_revision}.json"
            )
            db.execute(
                """
                INSERT INTO fq_imports(
                    import_id,content_sha256,filename,acquisition_mode,source_path,
                    status,error_message,draft_id,suggestions_json,created_at
                ) VALUES (?,?,?,'manual_import',?,'ready_review',NULL,?,'[]',?)
                """,
                (
                    import_id,
                    correction_artifact_sha256,
                    filename,
                    f"correction:{source_message_id}",
                    draft_id,
                    now,
                ),
            )
            db.execute(
                """
                INSERT INTO fq_drafts(
                    draft_id,import_id,revision,submission_revision,
                    correlation_id,predecessor_message_id,
                    predecessor_payload_sha256,contract_version,status,
                    payload_json,confirmation_json,submission_message_id,
                    receipt_json,created_by,last_content_actor,
                    human_preparer_actor,human_prepared_revision,
                    created_at,updated_at
                ) VALUES (?,?,1,?,?,?,?,?,'ready_review',?,NULL,NULL,NULL,?,?,?,1,?,?)
                """,
                (
                    draft_id,
                    import_id,
                    submission_revision,
                    source_message["correlation_id"],
                    source_message_id,
                    predecessor_hash,
                    CURRENT_SUBMISSION_CONTRACT,
                    jcs_json(correction_payload),
                    actor,
                    actor,
                    actor,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "ten_quantity_correction_draft_created",
                actor,
                {
                    "source_draft_id": source_draft_id,
                    "source_message_id": source_message_id,
                    "source_payload_sha256": predecessor_hash,
                    "draft_id": draft_id,
                    "import_id": import_id,
                    "correlation_id": source_message["correlation_id"],
                    "submission_revision": submission_revision,
                    "draft_payload_sha256": sha256_jcs(correction_payload),
                },
            )
            created = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?",
                (draft_id,),
            ).fetchone()
            assert created is not None
            return {
                "draft": self._draft(created),
                "created": True,
                "duplicate": False,
                "source_draft_id": source_draft_id,
            }

    def discard_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        now = utc_text()
        reason = _text(reason, "放弃原因", 1000)
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("报送草稿不存在")
            if row["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
                raise ConflictError("五量 V2 草稿仅供读取，不能放弃或改写审计状态")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("草稿修订号已变化，请刷新后重试")
            if row["status"] == "discarded":
                return self._draft(row)
            if row["predecessor_message_id"] is not None:
                raise ConflictError(
                    "正式更正草稿是已送达报送链的唯一后继，不能放弃或删除；"
                    "如暂不更正可保留草稿，后续继续编辑并复核"
                )
            outbox = db.execute(
                "SELECT 1 FROM fq_outbox WHERE aggregate_id=? "
                "AND message_kind='submission' LIMIT 1",
                (draft_id,),
            ).fetchone()
            if (
                row["status"] != "ready_review"
                or row["confirmation_json"] is not None
                or row["submission_message_id"] is not None
                or outbox is not None
            ):
                raise ConflictError("已确认、已入发送队列或已送达的草稿不能放弃")
            revision = expected_revision + 1
            db.execute(
                "UPDATE fq_drafts SET status='discarded',revision=?,updated_at=? "
                "WHERE draft_id=?",
                (revision, now, draft_id),
            )
            db.execute(
                "UPDATE fq_imports SET status='discarded' WHERE import_id=?",
                (row["import_id"],),
            )
            self._append_audit(
                db,
                "five_quantity_draft_discarded",
                actor,
                {
                    "draft_id": draft_id,
                    "import_id": row["import_id"],
                    "revision": revision,
                    "reason": reason,
                },
            )
        return self.get_draft(draft_id)

    def replace_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        payload: dict[str, Any],
        actor: str,
        identity: MineIdentity,
    ) -> dict[str, Any]:
        now = utc_text()
        self._assert_human_preparer(actor)
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("报送草稿不存在")
            if row["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
                raise ConflictError("五量 V2 草稿仅供读取，不能保存为 V3 或改写审计")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("草稿已被其他操作修改，请刷新后重试")
            if row["status"] in {
                "queued",
                "submitted",
                "acknowledged",
                "discarded",
            }:
                raise ConflictError("已报送或已放弃草稿不可覆盖，请创建新版本")
            if row["predecessor_message_id"] is not None:
                predecessor_source = db.execute(
                    "SELECT * FROM fq_drafts WHERE submission_message_id=?",
                    (row["predecessor_message_id"],),
                ).fetchone()
                if predecessor_source is None:
                    raise ConflictError("正式更正草稿缺少已送达的直接前序")
                predecessor_message = self._verify_archived_submission(
                    db,
                    predecessor_source,
                    identity=identity,
                )["message"]
                if (
                    predecessor_message["message_id"]
                    != row["predecessor_message_id"]
                    or predecessor_message["correlation_id"]
                    != row["correlation_id"]
                    or predecessor_message["signature_envelope"]["payload_sha256"]
                    != row["predecessor_payload_sha256"]
                ):
                    raise ConflictError("正式更正草稿与直接前序血缘不一致")
                predecessor_payload = predecessor_message["payload"]
                changed_fields = [
                    field
                    for field in _CORRECTION_LOCKED_PAYLOAD_FIELDS
                    if payload.get(field) != predecessor_payload.get(field)
                ]
                if changed_fields:
                    raise ConflictError(
                        "更正版本必须沿用直接前序的矿井、统计期间、时区和同类矿口径；"
                        "若需申报其他期间，请新建首报"
                    )
            revision = expected_revision + 1
            db.execute(
                """UPDATE fq_drafts SET revision=?,status='ready_review',
                    payload_json=?,confirmation_json=NULL,
                    last_content_actor=?,human_preparer_actor=?,
                    human_prepared_revision=?,updated_at=?
                    WHERE draft_id=?""",
                (revision, jcs_json(payload), actor, actor, revision, now, draft_id),
            )
            self._append_audit(
                db,
                "five_quantity_review_saved",
                actor,
                {
                    "draft_id": draft_id,
                    "revision": revision,
                    "payload_sha256": sha256_jcs(payload),
                },
            )
        return self.get_draft(draft_id)

    def confirm_and_enqueue(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        confirmation: dict[str, Any],
        message: dict[str, Any],
        actor: str,
        machine_source_policies: tuple[dict[str, Any], ...],
        health_now_epoch: float,
        identity: MineIdentity,
    ) -> dict[str, Any]:
        now = utc_text()
        if (
            not isinstance(message, dict)
            or message.get("contract_version") != CURRENT_SUBMISSION_CONTRACT
            or message.get("message_type") != TEN_QUANTITY_SUBMISSION_MESSAGE_TYPE
        ):
            raise ValueError("十量 V3 草稿只能进入十量 V3 报送队列")
        _verify_stored_v3_submission(message, identity=identity)
        message_json = jcs_json(message)
        with self.repository._transaction() as db:
            integrity = self._verify_audit_in_transaction(db)
            if not integrity["valid"]:
                raise ConflictError(
                    "报送审计链或审计锚点异常；已拒绝确认和进入发送队列"
                )
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("报送草稿不存在")
            if row["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
                raise ConflictError("五量 V2 草稿仅供读取，不能重新确认或入发送队列")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("草稿修订号已变化")
            submission_revision = int(row["submission_revision"])
            if message.get("revision") != submission_revision:
                raise ConflictError("待发送消息与草稿报送版本不一致")
            if submission_revision == 1:
                if (
                    row["predecessor_message_id"] is not None
                    or row["predecessor_payload_sha256"] is not None
                    or message.get("predecessor") is not None
                    or message.get("causation_id") is not None
                    or message.get("correlation_id") != message.get("message_id")
                ):
                    raise ConflictError("十量 V3 首报血缘字段非法")
            else:
                expected_predecessor = {
                    "message_id": row["predecessor_message_id"],
                    "payload_sha256": row["predecessor_payload_sha256"],
                }
                if (
                    row["correlation_id"] is None
                    or None in expected_predecessor.values()
                    or message.get("correlation_id") != row["correlation_id"]
                    or message.get("predecessor") != expected_predecessor
                    or message.get("causation_id")
                    != row["predecessor_message_id"]
                ):
                    raise ConflictError("十量 V3 更正消息与草稿前序血缘不一致")
                predecessor_source = db.execute(
                    "SELECT * FROM fq_drafts WHERE submission_message_id=?",
                    (row["predecessor_message_id"],),
                ).fetchone()
                if predecessor_source is None:
                    raise ConflictError("十量 V3 更正的直接前序尚未成功送达")
                predecessor_message = self._verify_archived_submission(
                    db,
                    predecessor_source,
                    identity=identity,
                )["message"]
                if (
                    predecessor_message["revision"] + 1
                    != submission_revision
                    or predecessor_message["correlation_id"]
                    != row["correlation_id"]
                    or predecessor_message["signature_envelope"][
                        "payload_sha256"
                    ]
                    != row["predecessor_payload_sha256"]
                ):
                    raise ConflictError("十量 V3 更正未直接延续上一报送版本")
                changed_fields = [
                    field
                    for field in _CORRECTION_LOCKED_PAYLOAD_FIELDS
                    if message["payload"].get(field)
                    != predecessor_message["payload"].get(field)
                ]
                if changed_fields:
                    raise ConflictError(
                        "更正消息改变了直接前序的矿井、统计期间、时区或"
                        "同类矿口径，已拒绝进入发送队列"
                    )
            self._assert_independent_actor(
                row,
                actor,
                subject="十量草稿",
                require_human_preparer=True,
            )
            if row["status"] == "discarded":
                raise ConflictError("已放弃草稿不能确认或报送")
            if row["status"] in {"queued", "submitted", "acknowledged"}:
                existing = db.execute(
                    "SELECT * FROM fq_outbox WHERE aggregate_id=? "
                    "AND message_kind='submission'",
                    (draft_id,),
                ).fetchone()
                if existing is None:
                    raise ConflictError("草稿状态与 outbox 不一致")
                return dict(existing)
            row_payload = json.loads(str(row["payload_json"]))
            signed_payload = message.get("payload")
            if not isinstance(signed_payload, dict):
                raise ConflictError("待发送十量 V3 消息缺少签名 payload")
            signed_business_payload = json.loads(jcs_json(signed_payload))
            payload_confirmation = signed_business_payload.pop(
                "human_confirmation", None
            )
            expected_confirmation_keys = {
                "actor_id",
                "confirmer_name",
                "role",
                "attestation",
                "confirmed_at",
                "draft_revision",
                "payload_sha256",
            }
            if (
                sha256_jcs(signed_business_payload) != sha256_jcs(row_payload)
                or not isinstance(confirmation, dict)
                or set(confirmation) != expected_confirmation_keys
                or not isinstance(payload_confirmation, dict)
                or confirmation.get("actor_id") != actor
                or confirmation.get("draft_revision") != int(row["revision"])
                or confirmation.get("payload_sha256") != sha256_jcs(row_payload)
                or payload_confirmation.get("confirmed") is not True
                or payload_confirmation.get("confirmer_id")
                != confirmation.get("actor_id")
                or payload_confirmation.get("confirmer_name")
                != confirmation.get("confirmer_name")
                or payload_confirmation.get("role") != confirmation.get("role")
                or payload_confirmation.get("confirmed_at")
                != confirmation.get("confirmed_at")
                or payload_confirmation.get("content_sha256")
                != sha256_jcs(confirmation)
            ):
                raise ConflictError(
                    "待发送消息、当前草稿与人工确认记录未精确绑定"
                )
            same_business_submission = db.execute(
                "SELECT aggregate_id FROM fq_outbox "
                "WHERE idempotency_key=? AND message_kind='submission' LIMIT 1",
                (message["idempotency_key"],),
            ).fetchone()
            if (
                same_business_submission is not None
                and same_business_submission["aggregate_id"] != draft_id
            ):
                raise ConflictError(
                    "本矿该月份的同一报送版本已经确认；请放弃重复草稿。"
                    "如需更正，必须从已提交版本发起正式更正流程。"
                )
            health = (
                self.repository
                .connector_source_health_for_draft_in_transaction(
                    db,
                    draft_id,
                    policies=machine_source_policies,
                    now_epoch=health_now_epoch,
                )
            )
            if health["freshness"]["overall_state"] not in {
                "fresh",
                "not_applicable",
            }:
                stale_sources = health["freshness"][
                    "stale_required_source_ids"
                ]
                source_text = "、".join(stale_sources) or "未配置来源"
                raise ValidationBlockedError(
                    "必需机器来源未通过动态新鲜度与当前快照绑定检查："
                    f"{source_text}"
                )
            binding = db.execute(
                "SELECT 1 FROM connector_draft_bindings WHERE draft_id=?",
                (draft_id,),
            ).fetchone()
            if binding is not None:
                current_payload = json.loads(str(row["payload_json"]))
                current_payload_sha256 = sha256_jcs(current_payload)
                latest = db.execute(
                    """
                    SELECT workflow_result_json
                    FROM connector_ingestions
                    WHERE draft_id=? AND status='completed'
                        AND workflow_result_json IS NOT NULL
                    ORDER BY completed_at DESC,created_at DESC,ingestion_id DESC
                    LIMIT 1
                    """,
                    (draft_id,),
                ).fetchone()
                stored_preflight: dict[str, Any] | None = None
                if latest is not None:
                    try:
                        candidate = json.loads(
                            str(latest["workflow_result_json"])
                        )
                    except (TypeError, json.JSONDecodeError):
                        candidate = None
                    if isinstance(candidate, dict):
                        stored_preflight = candidate
                preflight_is_current = bool(
                    stored_preflight is not None
                    and stored_preflight.get("contract_version")
                    == "ten-quantity-machine-preflight/v2"
                    and stored_preflight.get("bound_revision")
                    == int(row["revision"])
                    and stored_preflight.get("payload_sha256")
                    == current_payload_sha256
                )
                if not preflight_is_current:
                    recalculated = _v2_machine_preflight(
                        current_payload,
                        revision=int(row["revision"]),
                        contract_version=CURRENT_SUBMISSION_CONTRACT,
                    )
                    self._append_audit(
                        db,
                        "five_quantity_machine_preflight_recomputed",
                        actor,
                        {
                            "draft_id": draft_id,
                            "reason": (
                                "missing"
                                if stored_preflight is None
                                else "obsolete"
                            ),
                            "preflight": recalculated,
                        },
                    )
            db.execute(
                """UPDATE fq_drafts SET status='queued',confirmation_json=?,
                    submission_message_id=?,correlation_id=?,updated_at=?
                    WHERE draft_id=?""",
                (
                    jcs_json(confirmation),
                    message["message_id"],
                    message["correlation_id"],
                    now,
                    draft_id,
                ),
            )
            db.execute(
                """INSERT INTO fq_outbox(
                    message_id,message_kind,aggregate_id,idempotency_key,body_json,
                    body_sha256,status,next_attempt_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,'queued',?,?,?)""",
                (
                    message["message_id"],
                    "submission",
                    draft_id,
                    message["idempotency_key"],
                    message_json,
                    hashlib.sha256(message_json.encode("utf-8")).hexdigest(),
                    now,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "five_quantity_confirmed_and_queued",
                actor,
                {
                    "draft_id": draft_id,
                    "message_id": message["message_id"],
                    "payload_sha256": message["signature_envelope"]["payload_sha256"],
                },
            )
        return self.get_draft(draft_id)

    def due_outbox(self, limit: int = 20) -> list[dict[str, Any]]:
        now = utc_text()
        with self.repository._transaction() as db:
            integrity = self._verify_audit_in_transaction(db)
            if not integrity["valid"]:
                raise ConflictError(
                    "报送审计链或审计锚点异常；发送队列已停止，未向监管端发送"
                )
            rows = db.execute(
                """SELECT * FROM fq_outbox
                   WHERE status IN ('queued','failed') AND next_attempt_at<=?
                   ORDER BY created_at LIMIT ?""",
                (now, limit),
            ).fetchall()
            for row in rows:
                failure = self._outbox_four_eyes_failure(db, row)
                if failure is not None:
                    raise ConflictError(
                        "发送队列存在未满足持久化四眼复核条件的消息；"
                        f"队列已停止（{failure}）"
                    )
            result = []
            for row in rows:
                db.execute(
                    "UPDATE fq_outbox SET status='sending',"
                    "attempts=attempts+1,updated_at=? "
                    "WHERE message_id=?",
                    (now, row["message_id"]),
                )
                item = dict(row)
                item["body"] = self._loads(row["body_json"])
                item["attempts"] = int(row["attempts"]) + 1
                result.append(item)
            return result

    def outbox_succeeded(
        self, message_id: str, *, receipt: dict[str, Any] | None
    ) -> None:
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_outbox WHERE message_id=?", (message_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("outbox 消息不存在")
            kind = str(row["message_kind"])
            archived_v3_message: dict[str, Any] | None = None
            receipt_json = jcs_json(receipt) if receipt is not None else None
            if kind == "submission":
                body_json = str(row["body_json"])
                actual_body_sha256 = hashlib.sha256(body_json.encode()).hexdigest()
                if not hmac.compare_digest(
                    actual_body_sha256,
                    str(row["body_sha256"]),
                ):
                    raise ConflictError("待归档报送正文摘要不一致")
                try:
                    body = json.loads(body_json)
                except json.JSONDecodeError as error:
                    raise ConflictError("待归档报送正文不是合法 JSON") from error
                if body.get("contract_version") == CURRENT_SUBMISSION_CONTRACT:
                    archived_v3_message = _verify_stored_v3_submission(
                        body,
                        identity=self.identity,
                    )
                    if receipt is None:
                        raise ConflictError("十量 V3 成功送达必须保存政府签名接收回执")
                    verified_receipt = _verify_stored_intake_receipt(
                        receipt,
                        submission=archived_v3_message,
                        identity=self.identity,
                    )
                    receipt_json = jcs_json(verified_receipt)
            db.execute(
                """UPDATE fq_outbox SET status='succeeded',receipt_json=?,
                    last_error=NULL,updated_at=? WHERE message_id=?""",
                (receipt_json, now, message_id),
            )
            if kind == "submission":
                db.execute(
                    "UPDATE fq_drafts SET status='submitted',"
                    "receipt_json=?,updated_at=? "
                    "WHERE draft_id=?",
                    (receipt_json, now, row["aggregate_id"]),
                )
                if archived_v3_message is not None:
                    source = db.execute(
                        "SELECT * FROM fq_drafts WHERE draft_id=?",
                        (row["aggregate_id"],),
                    ).fetchone()
                    if source is None:
                        raise ConflictError("十量 V3 归档对应草稿不存在")
                    self._verify_archived_submission(db, source)
            elif kind == "delivery_ack":
                inbox = db.execute(
                    "SELECT delivery_cursor FROM fq_inbox WHERE report_id=?",
                    (row["aggregate_id"],),
                ).fetchone()
                if inbox is None:
                    raise ConflictError("ack 对应的 inbox 风险不存在")
                db.execute(
                    "UPDATE fq_inbox SET status='acknowledged',acknowledged_at=? "
                    "WHERE report_id=?",
                    (now, row["aggregate_id"]),
                )
                db.execute(
                    """INSERT INTO fq_settings(setting_key,setting_value,updated_at)
                       VALUES ('analysis_cursor',?,?)
                       ON CONFLICT(setting_key) DO UPDATE SET
                         setting_value=excluded.setting_value,
                         updated_at=excluded.updated_at""",
                    (inbox["delivery_cursor"], now),
                )
            elif kind == "risk_response":
                db.execute(
                    "UPDATE fq_responses SET status='submitted',"
                    "receipt_json=?,updated_at=? "
                    "WHERE response_id=?",
                    (jcs_json(receipt), now, row["aggregate_id"]),
                )
            self._append_audit(
                db,
                "five_quantity_outbox_delivered",
                "system-exchange",
                {"message_id": message_id, "kind": kind},
            )

    def outbox_failed(self, message_id: str, *, error: str, attempts: int) -> None:
        delay_seconds = min(3600, max(5, 5 * (2 ** min(attempts - 1, 9))))
        next_attempt = utc_text(utc_now() + timedelta(seconds=delay_seconds))
        with self.repository._transaction() as db:
            db.execute(
                """UPDATE fq_outbox SET status='failed',last_error=?,
                    next_attempt_at=?,updated_at=? WHERE message_id=?""",
                (error[:1000], next_attempt, utc_text(), message_id),
            )

    def last_cursor(self) -> str | None:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT setting_value FROM fq_settings "
                "WHERE setting_key='analysis_cursor'"
            ).fetchone()
        return str(row["setting_value"]) if row else None

    def store_report_with_ack(
        self, report: dict[str, Any], ack: dict[str, Any]
    ) -> dict[str, Any]:
        payload = report["payload"]
        now = utc_text()
        report_json = jcs_json(report)
        ack_json = jcs_json(ack)
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_inbox WHERE message_id=? OR report_id=?",
                (report["message_id"], payload["report_id"]),
            ).fetchone()
            if existing is not None:
                if (
                    existing["body_sha256"]
                    != hashlib.sha256(report_json.encode("utf-8")).hexdigest()
                ):
                    raise ConflictError("同一风险消息身份出现不同内容")
                return {"duplicate": True, **dict(existing)}
            db.execute(
                """INSERT INTO fq_inbox(
                    message_id,report_id,correlation_id,delivery_cursor,body_json,
                    body_sha256,status,received_at
                ) VALUES (?,?,?,?,?,?,'stored',?)""",
                (
                    report["message_id"],
                    payload["report_id"],
                    report["correlation_id"],
                    payload["delivery_cursor"],
                    report_json,
                    hashlib.sha256(report_json.encode("utf-8")).hexdigest(),
                    now,
                ),
            )
            db.execute(
                """INSERT INTO fq_outbox(
                    message_id,message_kind,aggregate_id,idempotency_key,body_json,
                    body_sha256,status,next_attempt_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,'queued',?,?,?)""",
                (
                    ack["message_id"],
                    "delivery_ack",
                    payload["report_id"],
                    ack["idempotency_key"],
                    ack_json,
                    hashlib.sha256(ack_json.encode("utf-8")).hexdigest(),
                    now,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "analysis_report_stored",
                "system-exchange",
                {
                    "report_id": payload["report_id"],
                    "message_id": report["message_id"],
                    "outcome": payload["outcome"],
                },
            )
            return {"duplicate": False, "report_id": payload["report_id"]}

    def _report(self, row: Any) -> dict[str, Any]:
        message = self._loads(row["body_json"])
        return {
            "report_id": row["report_id"],
            "message_id": row["message_id"],
            "status": row["status"],
            "delivery_cursor": row["delivery_cursor"],
            "received_at": row["received_at"],
            "acknowledged_at": row["acknowledged_at"],
            "report": message,
        }

    def list_reports(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_inbox ORDER BY received_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._report(row) for row in rows]

    def get_report(self, report_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM fq_inbox WHERE report_id=?", (report_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("风险报告不存在")
        return self._report(row)

    def create_response(self, report_id: str, *, actor: str) -> dict[str, Any]:
        report_record = self.get_report(report_id)
        findings = report_record["report"]["payload"]["findings"]
        now = utc_text()
        document = {
            "response_id": str(uuid.uuid4()),
            "report_id": report_id,
            "analysis_report_message_id": report_record["message_id"],
            "responded_at": now,
            "finding_responses": [
                {
                    "finding_id": finding["finding_id"],
                    "response_kind": "unable_to_determine",
                    "reason_code": "unknown_under_investigation",
                    "facts": "待企业人员核对并填写具体事实。",
                    "evidence_refs": [],
                    "actions": [],
                    "corrected_submission_message_id": None,
                }
                for finding in findings
            ],
            "attachments": [],
            "agent_assistance": {
                "used": False,
                "conversation_id": None,
                "assistance_record_sha256": None,
            },
        }
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_responses WHERE report_id=?", (report_id,)
            ).fetchone()
            if existing is not None:
                return self._response(existing)
            db.execute(
                """INSERT INTO fq_responses(
                    response_id,report_id,revision,status,document_json,
                    created_by,last_content_actor,created_at,updated_at
                ) VALUES (?,?,1,'draft',?,?,?,?,?)""",
                (
                    document["response_id"],
                    report_id,
                    jcs_json(document),
                    actor,
                    actor,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "risk_response_draft_created",
                actor,
                {"response_id": document["response_id"], "report_id": report_id},
            )
        return self.get_response(document["response_id"])

    def _response(self, row: Any) -> dict[str, Any]:
        return {
            "response_id": row["response_id"],
            "report_id": row["report_id"],
            "revision": row["revision"],
            "status": row["status"],
            "document": self._loads(row["document_json"]),
            "confirmation": self._loads(row["confirmation_json"]),
            "message_id": row["message_id"],
            "receipt": self._loads(row["receipt_json"]),
            "created_by": row["created_by"],
            "last_content_actor": row["last_content_actor"],
            "review_gate": self._review_gate(
                row["last_content_actor"],
                status=row["status"],
                confirmation=self._loads(row["confirmation_json"]),
            ),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_response(self, response_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM fq_responses WHERE response_id=?", (response_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("风险回复不存在")
        return self._response(row)

    def replace_response(
        self,
        response_id: str,
        *,
        expected_revision: int,
        document: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_responses WHERE response_id=?", (response_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("风险回复不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("风险回复已被其他操作修改")
            if row["status"] in {"queued", "submitted"}:
                raise ConflictError("已发送的风险回复不可覆盖")
            revision = expected_revision + 1
            db.execute(
                """UPDATE fq_responses SET revision=?,status='draft',document_json=?,
                    confirmation_json=NULL,last_content_actor=?,updated_at=?
                    WHERE response_id=?""",
                (revision, jcs_json(document), actor, now, response_id),
            )
            self._append_audit(
                db,
                "risk_response_saved",
                actor,
                {"response_id": response_id, "revision": revision},
            )
        return self.get_response(response_id)

    def confirm_response_and_enqueue(
        self,
        response_id: str,
        *,
        expected_revision: int,
        confirmation: dict[str, Any],
        message: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        message_json = jcs_json(message)
        with self.repository._transaction() as db:
            integrity = self._verify_audit_in_transaction(db)
            if not integrity["valid"]:
                raise ConflictError(
                    "报送审计链或审计锚点异常；已拒绝风险回复确认和发送"
                )
            row = db.execute(
                "SELECT * FROM fq_responses WHERE response_id=?", (response_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("风险回复不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("风险回复修订号已变化")
            self._assert_independent_actor(row, actor, subject="风险回复")
            if row["status"] in {"queued", "submitted"}:
                return self._response(row)
            db.execute(
                """UPDATE fq_responses SET status='queued',document_json=?,
                    confirmation_json=?,message_id=?,updated_at=?
                    WHERE response_id=?""",
                (
                    jcs_json(message["payload"]),
                    jcs_json(confirmation),
                    message["message_id"],
                    now,
                    response_id,
                ),
            )
            db.execute(
                """INSERT INTO fq_outbox(
                    message_id,message_kind,aggregate_id,idempotency_key,body_json,
                    body_sha256,status,next_attempt_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,'queued',?,?,?)""",
                (
                    message["message_id"],
                    "risk_response",
                    response_id,
                    message["idempotency_key"],
                    message_json,
                    hashlib.sha256(message_json.encode("utf-8")).hexdigest(),
                    now,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "risk_response_confirmed_and_queued",
                actor,
                {"response_id": response_id, "message_id": message["message_id"]},
            )
        return self.get_response(response_id)

    def append_chat(
        self,
        *,
        report_id: str,
        actor_id: str,
        question: str,
        answer: str,
        tools: list[str],
    ) -> list[dict[str, Any]]:
        now = utc_text()
        with self.repository._transaction() as db:
            for role, content, used_tools in (
                ("user", question, []),
                ("assistant", answer, tools),
            ):
                db.execute(
                    "INSERT INTO fq_chat_messages VALUES (?,?,?,?,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        report_id,
                        actor_id,
                        role,
                        content,
                        jcs_json(used_tools),
                        now,
                    ),
                )
            self._append_audit(
                db,
                "risk_chat_turn",
                actor_id,
                {
                    "report_id": report_id,
                    "question_sha256": hashlib.sha256(question.encode()).hexdigest(),
                    "tools": tools,
                },
            )
        return self.chat_messages(report_id)

    def chat_messages(self, report_id: str) -> list[dict[str, Any]]:
        self.get_report(report_id)
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_chat_messages WHERE report_id=? "
                "ORDER BY created_at,rowid",
                (report_id,),
            ).fetchall()
        return [
            {
                "message_id": row["message_id"],
                "role": row["role"],
                "content": row["content"],
                "tools": self._loads(row["tools_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def audit(self, limit: int = 200) -> dict[str, Any]:
        with self.repository._read() as db:
            integrity = self._verify_audit_in_transaction(db)
            rows = db.execute(
                "SELECT * FROM (SELECT * FROM fq_audit ORDER BY sequence DESC LIMIT ?) "
                "ORDER BY sequence",
                (max(1, min(int(limit), 1000)),),
            ).fetchall()
        events = []
        for row in rows:
            details = self._loads(row["details_json"])
            stored = dict(row)
            stored_event_type = str(stored["event_type"])
            events.append(
                {
                    **stored,
                    "event_code": stored_event_type,
                    "event_type": _public_audit_event_type(stored_event_type),
                    "details": details,
                    "details_json": None,
                }
            )
        return {
            **integrity,
            "displayed_count": len(events),
            "truncated": integrity["event_count"] > len(events),
            "events": events,
        }


def _validate_analysis_report(report: dict[str, Any], identity: MineIdentity) -> None:
    payload = _object(report.get("payload"), "analysis payload")
    required = {
        "report_id",
        "submission_message_id",
        "submission_revision",
        "mine",
        "reporting_month",
        "period_start",
        "period_end",
        "issued_at",
        "algorithm",
        "outcome",
        "summary",
        "findings",
        "response_required",
        "response_due_at",
        "delivery_cursor",
    }
    if set(payload) != required or payload["mine"] != identity.mine:
        raise PlatformError("算法报告 payload 字段或矿井绑定非法")
    if payload["outcome"] not in {"risk", "data_insufficient"}:
        raise PlatformError("企业风险收件箱只接收需要回复的风险/数据不足报告")
    if payload["response_required"] is not True:
        raise PlatformError("风险报告必须明确要求回复")
    findings = payload["findings"]
    if not isinstance(findings, list) or not findings:
        raise PlatformError("风险报告缺少结构化 finding")
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(
            finding.get("finding_id"), str
        ):
            raise PlatformError("风险 finding 结构非法")
        if finding["finding_id"] in finding_ids:
            raise PlatformError("风险 finding_id 重复")
        finding_ids.add(finding["finding_id"])
        if finding.get("requires_response") is not True:
            raise PlatformError("投递到企业的 finding 必须要求回复")
        if not isinstance(finding.get("evidence"), list) or not finding["evidence"]:
            raise PlatformError("风险 finding 缺少算法证据")
    algorithm = _object(payload["algorithm"], "algorithm")
    expected_engine = (
        "mineguard-ten-quantity-engine"
        if report.get("contract_version") == TEN_QUANTITY_ANALYSIS_CONTRACT
        else "mineguard-five-quantity-engine"
    )
    if algorithm.get("engine_id") != expected_engine:
        raise PlatformError("报告不是政府登记的五量/十量监管引擎输出")


def _validate_response_document(
    document: dict[str, Any], report: dict[str, Any]
) -> None:
    required = {
        "response_id",
        "report_id",
        "analysis_report_message_id",
        "responded_at",
        "finding_responses",
        "attachments",
        "agent_assistance",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("风险回复草稿字段非法")
    _uuid_text(document["response_id"], "response_id")
    _uuid_text(document["report_id"], "report_id")
    _uuid_text(document["analysis_report_message_id"], "analysis_report_message_id")
    parse_aware_datetime(document["responded_at"], "responded_at")
    report_message = report["report"]
    if (
        document["report_id"] != report["report_id"]
        or document["analysis_report_message_id"] != report_message["message_id"]
    ):
        raise ValueError("风险回复与报告绑定不一致")
    findings = {item["finding_id"] for item in report_message["payload"]["findings"]}
    responses = document["finding_responses"]
    if (
        not isinstance(responses, list)
        or not 1 <= len(responses) <= 100
        or any(not isinstance(item, dict) for item in responses)
        or {item.get("finding_id") for item in responses} != findings
    ):
        raise ValueError("必须逐项回复当前报告的全部 finding")
    attachments = document["attachments"]
    if not isinstance(attachments, list) or len(attachments) > 100:
        raise ValueError("attachments 必须是最多 100 项的数组")
    attachment_ids: set[str] = set()
    for index, attachment in enumerate(attachments):
        if not isinstance(attachment, dict) or set(attachment) != {
            "evidence_id",
            "title",
            "media_type",
            "size_bytes",
            "sha256",
            "retention_location",
        }:
            raise ValueError(f"attachments[{index}] 字段非法")
        evidence_id = _identifier_text(
            attachment["evidence_id"], f"attachments[{index}].evidence_id"
        )
        if evidence_id in attachment_ids:
            raise ValueError("附件 evidence_id 不得重复")
        attachment_ids.add(evidence_id)
        _text(attachment["title"], f"attachments[{index}].title", 256)
        _text(attachment["media_type"], f"attachments[{index}].media_type", 128)
        size = attachment["size_bytes"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= 1_073_741_824
        ):
            raise ValueError("附件 size_bytes 非法")
        _sha256_text(attachment["sha256"], f"attachments[{index}].sha256")
        if attachment["retention_location"] != "enterprise_local":
            raise ValueError("附件原件必须保留在企业侧")
    for item in responses:
        if set(item) != {
            "finding_id",
            "response_kind",
            "reason_code",
            "facts",
            "evidence_refs",
            "actions",
            "corrected_submission_message_id",
        }:
            raise ValueError("finding response 字段非法")
        _uuid_text(item["finding_id"], "finding_id")
        if item["response_kind"] not in _RESPONSE_KINDS:
            raise ValueError("response_kind 非法")
        if item["reason_code"] not in _REASON_CODES:
            raise ValueError("reason_code 非法")
        _text(item.get("facts"), "企业事实说明", 8000)
        refs = item["evidence_refs"]
        if (
            not isinstance(refs, list)
            or len(refs) > 50
            or len(refs) != len(set(refs))
            or any(not isinstance(ref, str) for ref in refs)
            or not set(refs).issubset(attachment_ids)
        ):
            raise ValueError("回复引用了未声明的证据")
        actions = item["actions"]
        if not isinstance(actions, list) or len(actions) > 50:
            raise ValueError("actions 必须是最多 50 项的数组")
        for action in actions:
            if not isinstance(action, dict) or set(action) != {
                "action_type",
                "description",
                "status",
            }:
                raise ValueError("整改措施字段非法")
            if action["action_type"] not in _ACTION_TYPES:
                raise ValueError("action_type 非法")
            if action["status"] not in _ACTION_STATUSES:
                raise ValueError("action status 非法")
            _text(action["description"], "整改措施说明", 2000)
        corrected = item.get("corrected_submission_message_id")
        if item["response_kind"] == "correction_submitted":
            _uuid_text(corrected, "更正报表消息编号")
        elif corrected is not None:
            raise ValueError("非更正回复不得携带更正报表消息编号")
    assistance = document["agent_assistance"]
    if not isinstance(assistance, dict) or set(assistance) != {
        "used",
        "conversation_id",
        "assistance_record_sha256",
    }:
        raise ValueError("agent_assistance 字段非法")
    if not isinstance(assistance["used"], bool):
        raise ValueError("agent_assistance.used 必须是布尔值")
    if assistance["used"]:
        _text(assistance["conversation_id"], "conversation_id", 128)
        _sha256_text(assistance["assistance_record_sha256"], "assistance_record_sha256")
    elif (
        assistance["conversation_id"] is not None
        or assistance["assistance_record_sha256"] is not None
    ):
        raise ValueError("未使用智能体时不得声明辅助记录")


class FiveQuantityRuntime:
    def __init__(
        self,
        repository: Any,
        *,
        identity: MineIdentity,
        platform_client: FiveQuantityPlatformClient | None = None,
        watched_directories: tuple[str, ...] = (),
        quarantine_directory: str | Path | None = None,
        csv_preview_directory: str | Path | None = None,
        poll_seconds: float = 5.0,
        stable_seconds: float = 2.0,
        auto_start: bool = False,
        llm_provider: Any | None = None,
        four_eyes_required: bool = False,
        human_preparer_actor_ids: frozenset[str] = frozenset(),
    ):
        self.four_eyes_required = bool(four_eyes_required)
        self.store = FiveQuantityStore(
            repository,
            identity=identity,
            four_eyes_required=self.four_eyes_required,
            human_preparer_actor_ids=human_preparer_actor_ids,
        )
        self.identity = identity
        self.csv_persistence = FiveQuantityCsvPersistence(
            repository,
            identity=identity,
            evidence_directory=csv_preview_directory,
            audit_sink=self.store._append_audit,
        )
        self.platform_client = platform_client
        self.poll_seconds = max(0.5, min(float(poll_seconds), 60.0))
        self.stable_seconds = max(0.5, min(float(stable_seconds), 60.0))
        self.watched_directories = self._watched(watched_directories)
        self.quarantine_directory = self._quarantine_directory(
            quarantine_directory,
            repository=repository,
            watched=self.watched_directories,
        )
        self.csv_mapping_provider = llm_provider
        self._watch_state: dict[str, tuple[int, int, float]] = {}
        self._processed_paths: dict[str, tuple[int, int]] = {}
        self._machine_source_policies: tuple[dict[str, Any], ...] = ()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        if auto_start:
            self.start()

    def configure_machine_source_policies(
        self, policies: tuple[dict[str, Any], ...]
    ) -> None:
        self._machine_source_policies = tuple(
            json.loads(jcs_json(policy)) for policy in policies
        )

    def machine_source_health(self, draft_id: str) -> dict[str, Any]:
        return self.store.repository.connector_source_health_for_draft(
            draft_id,
            policies=self._machine_source_policies,
        )

    @staticmethod
    def _watched(values: tuple[str, ...]) -> tuple[Path, ...]:
        result = []
        for value in values:
            path = Path(value).expanduser()
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f"十量监听目录无效或为符号链接：{path}")
            resolved = path.resolve()
            if resolved == Path(resolved.anchor):
                raise ValueError("拒绝把文件系统根目录设为监听目录")
            result.append(resolved)
        if len(result) != len(set(result)):
            raise ValueError("十量监听目录不得重复")
        return tuple(result)

    @staticmethod
    def _quarantine_directory(
        value: str | Path | None,
        *,
        repository: Any,
        watched: tuple[Path, ...],
    ) -> Path:
        if value is None:
            repository_path = str(getattr(repository, "path", ":memory:"))
            state_directory = (
                Path("./data").resolve()
                if repository_path == ":memory:"
                else Path(repository_path).resolve().parent
            )
            candidate = state_directory / "five-quantity-quarantine"
        else:
            candidate = Path(value).expanduser()
        if candidate.is_symlink():
            raise ValueError("十量隔离目录不能是符号链接")
        resolved = candidate.resolve()
        if resolved == Path(resolved.anchor):
            raise ValueError("拒绝把文件系统根目录设为十量隔离目录")
        for source in watched:
            if resolved == source or resolved.is_relative_to(source):
                raise ValueError(
                    "十量隔离目录必须位于 Agent 状态目录，不能放在来源目录中"
                )
        resolved.mkdir(parents=True, mode=0o700, exist_ok=True)
        if resolved.is_symlink() or not resolved.is_dir():
            raise ValueError("十量隔离目录创建失败或不是普通目录")
        with suppress(OSError):
            os.chmod(resolved, 0o700)
        return resolved

    @staticmethod
    def _write_quarantine_file(path: Path, content: bytes) -> None:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise OSError("隔离文件写入失败")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="five-quantity-exchange",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(5.0, self.poll_seconds + 1))
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            with suppress(Exception):
                self.csv_persistence.expire_previews()
            with suppress(Exception):
                self.scan_watched_directories()
            with suppress(Exception):
                self.process_outbox_once()
            with suppress(Exception):
                self.poll_analysis_once()
            self._stop.wait(self.poll_seconds)

    def _approved_csv_mappings(
        self,
        schema_fingerprint: str,
    ) -> tuple[list[ApprovedColumnMapping], str | None]:
        profiles = self.csv_persistence.list_mapping_profiles(
            schema_fingerprint=schema_fingerprint,
            limit=10,
        )
        if not profiles:
            return [], None
        # The UI creates one stable profile name per exact schema fingerprint.
        # If an administrator later adds more named profiles, never combine
        # them implicitly: two configurations may assign the same abbreviation
        # to different targets.
        preferred_name = f"csv-schema-{schema_fingerprint[:24]}"
        profile = next(
            (
                item
                for item in profiles
                if item.get("profile_name") == preferred_name
            ),
            profiles[0],
        )
        approved = [
            ApprovedColumnMapping(
                source_header=item["source_header"],
                metric=item["metric"],
                scope=item["scope"],
                shift=item["shift"],
                unit=item["unit"],
                profile_id=item["profile_id"],
                profile_revision=item["profile_revision"],
            )
            for item in profile["approved_mappings"]
        ]
        return approved, str(profile["profile_id"])

    @staticmethod
    def _mapped_csv_inspection(
        inspection: dict[str, Any],
        mapping_result: dict[str, Any],
    ) -> dict[str, Any]:
        enriched = json.loads(jcs_json(inspection))
        candidates = {
            int(item["source_index"]): item
            for item in mapping_result["candidates"]
        }
        blocked = {int(value) for value in mapping_result["blocked_columns"]}
        for column in enriched["columns"]:
            source_index = int(column["source_index"])
            candidate = candidates.get(source_index)
            if candidate is not None:
                column.update(
                    {
                        "target_metric": candidate["target_metric"],
                        "target_period": candidate["target_period"],
                        "target_unit": candidate["target_unit"],
                        "confidence": candidate["confidence"],
                        "source": candidate["source"],
                        "reason": candidate["reason"],
                        "status": candidate["status"],
                    }
                )
                unit_issue = csv_header_unit_issue(
                    candidate["target_metric"],
                    column["source_header"],
                )
                if unit_issue is not None:
                    column.update(
                        {
                            "target_metric": None,
                            "target_period": None,
                            "target_unit": None,
                            "confidence": 0.0,
                            "reason": unit_issue,
                            "status": "blocked",
                        }
                    )
            elif source_index in blocked:
                column.update(
                    {
                        "target_metric": None,
                        "target_period": None,
                        "target_unit": None,
                        "confidence": 0.0,
                        "status": "blocked",
                    }
                )
        for warning in mapping_result.get("warnings", [])[:50]:
            enriched["warnings"].append(
                {
                    "code": "mapping_advice",
                    "message": str(warning)[:500],
                    "severity": "warning",
                }
            )
        return enriched

    def preview_csv(
        self,
        *,
        filename: str,
        content: bytes,
        actor: str,
    ) -> dict[str, Any]:
        """Create an actor-bound, advisory-only CSV mapping preview."""

        inspection = inspect_five_quantity_csv(filename=filename, content=content)
        approved, applied_profile_id = self._approved_csv_mappings(
            inspection["schema_fingerprint"]
        )
        mapping_result = map_csv_inspection(
            inspection,
            approved_mappings=approved,
            llm_provider=self.csv_mapping_provider,
        )
        enriched = self._mapped_csv_inspection(inspection, mapping_result)
        mapping_advice = {
            "schema_version": "five-quantity-csv-mapping-advice-v1",
            "content_sha256": inspection["content_sha256"],
            "columns": [
                {
                    "source_index": item["source_index"],
                    "target_metric": item["target_metric"],
                    "target_period": item["target_period"],
                    "source": item["source"],
                    "confidence": item["confidence"],
                    "status": item["status"],
                }
                for item in enriched["columns"]
            ],
            "llm": mapping_result["llm"],
        }
        preview = self.csv_persistence.create_preview(
            original_filename=filename,
            content=content,
            inspection=inspection,
            actor=actor,
            mapping_advice=mapping_advice,
        )
        return {
            "preview_id": preview["preview_id"],
            "status": preview["status"],
            "revision": preview["revision"],
            "expires_at": preview["expires_at"],
            "inspection_sha256": preview["inspection_sha256"],
            "mapping_profile_applied": applied_profile_id,
            "mapping_assistant": mapping_result["llm"],
            **enriched,
        }

    @staticmethod
    def _csv_mapping_profile_document(
        inspection: dict[str, Any],
        mappings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        headers = {
            int(item["source_index"]): str(item["source_header"])
            for item in inspection["columns"]
        }
        columns = []
        for item in mappings:
            period = item["target_period"]
            metric = item["target_metric"]
            columns.append(
                {
                    "source_header": headers[item["source_index"]],
                    "metric": metric,
                    "scope": "daily_total" if period == "daily_total" else "shift",
                    "shift": None if period == "daily_total" else period,
                    "unit": UNITS[metric],
                }
            )
        return {
            "schema_version": CSV_MAPPING_PROFILE_CONTRACT,
            "columns": columns,
        }

    def materialize_csv_preview(
        self,
        *,
        preview_id: str,
        mappings: list[dict[str, Any]],
        save_profile: bool,
        actor: str,
    ) -> dict[str, Any]:
        """Materialise confirmed mappings into a draft, never a submission."""

        if not isinstance(mappings, list) or not 1 <= len(mappings) <= 256:
            raise ValidationBlockedError("至少需要确认一个 CSV 十量字段映射")
        if not isinstance(save_profile, bool):
            raise ValidationBlockedError("save_profile 必须是布尔值")
        preview = self.csv_persistence.get_preview(preview_id, actor=actor)
        inspection = preview["inspection"]
        allowed_columns = {
            int(item["source_index"]): item for item in inspection["columns"]
        }
        advice_columns = {
            int(item["source_index"]): item
            for item in preview["mapping_advice"]["columns"]
        }
        date_column = int(inspection["date_column"]["source_index"])
        selected_targets: set[tuple[str, str]] = set()
        selected_sources: set[int] = set()
        for item in mappings:
            if not isinstance(item, dict) or set(item) != {
                "source_index",
                "target_metric",
                "target_period",
            }:
                raise ValidationBlockedError("CSV 映射结构非法")
            source_index = item["source_index"]
            metric = item["target_metric"]
            period = item["target_period"]
            if metric not in METRICS or period not in PERIOD_KEYS:
                raise ValidationBlockedError("CSV 映射目标不在十量白名单内")
            target = (metric, period)
            if (
                isinstance(source_index, bool)
                or not isinstance(source_index, int)
                or source_index == date_column
                or source_index not in allowed_columns
            ):
                raise ValidationBlockedError("CSV 映射引用了预览中不存在的业务列")
            unit_issue = csv_header_unit_issue(
                metric,
                allowed_columns[source_index]["source_header"],
            )
            if unit_issue is not None:
                raise ValidationBlockedError(unit_issue)
            if source_index in selected_sources:
                raise ValidationBlockedError("同一来源列不能重复映射")
            if target in selected_targets:
                raise ValidationBlockedError("多个来源列不能指向同一规范字段")
            selected_sources.add(source_index)
            selected_targets.add(target)
        content = self.csv_persistence.read_preview_evidence(
            preview_id,
            actor=actor,
        )
        model_assistance_used = any(
            advice_columns.get(item["source_index"], {}).get("source") == "llm"
            and advice_columns.get(item["source_index"], {}).get("target_metric")
            == item["target_metric"]
            and advice_columns.get(item["source_index"], {}).get("target_period")
            == item["target_period"]
            for item in mappings
        )
        imported = import_five_quantity_bytes(
            filename=preview["original_filename"],
            content=content,
            acquisition_mode="manual_import",
            identity=self.identity,
            column_mappings=mappings,
            model_assistance_used=model_assistance_used,
            model_output_sha256=(
                preview["mapping_advice"]["llm"]["output_sha256"]
                if model_assistance_used
                else None
            ),
        )
        validate_five_quantity_payload(
            imported["payload"],
            identity=self.identity,
            confirmed=False,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )
        result = self.store.create_import(imported, source_path=None, actor=actor)
        if not result.get("draft_id"):
            raise ConflictError("相同 CSV 原件已存在，但没有可复核草稿")
        profile: dict[str, Any] | None = None
        if save_profile:
            profile = self.csv_persistence.approve_mapping_profile(
                profile_name=(
                    f"csv-schema-{inspection['schema_fingerprint'][:24]}"
                ),
                schema_fingerprint=inspection["schema_fingerprint"],
                mapping=self._csv_mapping_profile_document(inspection, mappings),
                approved_by=actor,
                human_approved=True,
            )
        self.csv_persistence.consume_preview(
            preview_id,
            expected_revision=preview["revision"],
            expected_inspection_sha256=preview["inspection_sha256"],
            resulting_draft_id=result["draft_id"],
            actor=actor,
            mapping_profile_id=(profile["profile_id"] if profile is not None else None),
        )
        if result.get("draft_id"):
            result["draft"] = self.store.get_draft(result["draft_id"])
        result["preview_id"] = preview_id
        result["mapping_profile"] = profile
        result["model_assistance_used"] = model_assistance_used
        return result

    def ingest_bytes(
        self,
        *,
        filename: str,
        content: bytes,
        acquisition_mode: str,
        actor: str,
        source_path: str | None = None,
    ) -> dict[str, Any]:
        imported = import_five_quantity_bytes(
            filename=filename,
            content=content,
            acquisition_mode=acquisition_mode,
            identity=self.identity,
        )
        validate_five_quantity_payload(
            imported["payload"],
            identity=self.identity,
            confirmed=False,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )
        result = self.store.create_import(
            imported, source_path=source_path, actor=actor
        )
        if result.get("draft_id"):
            result["draft"] = self.store.get_draft(result["draft_id"])
        return result

    def ingest_machine_source(
        self,
        *,
        ingestion_id: str,
        lease_owner: str,
        client_id: str,
        draft_key: str,
        source_id: str,
        source_revision: int,
        filename: str,
        source_name: str,
        source_system: str,
        original_filename: str | None,
        observed_at: str,
        coverage_as_of: str,
        format_name: str,
        content: bytes,
        actor_id: str,
        source_required: bool,
        freshness_max_seconds: int,
    ) -> dict[str, Any]:
        """Normalise one connector snapshot into the formal V2 review inbox."""

        expected_suffix = f".{format_name}"
        if not isinstance(filename, str) or not filename.lower().endswith(
            expected_suffix
        ):
            raise ValueError(
                f"机器来源文件名必须以 {expected_suffix} 结尾并与 format 一致"
            )
        imported = import_five_quantity_bytes(
            filename=filename,
            content=content,
            acquisition_mode="direct_collection",
            identity=self.identity,
        )
        if (
            coverage_as_of != imported["payload"]["period_end"]
            or not coverage_as_of.startswith(
                f"{imported['payload']['reporting_month']}-"
            )
        ):
            raise ValueError(
                "source.coverage_as_of 必须等于规范化快照的 period_end"
            )
        for evidence_source in imported["payload"]["sources"]:
            internal_source_id = str(evidence_source["source_id"])
            evidence_source["source_system"] = source_system
            evidence_source["captured_at"] = observed_at
            evidence_source["source_record_id"] = (
                f"connector:{source_id}:r{source_revision}:{internal_source_id}"
            )[:256]
            evidence_source["source_location"] = (
                f"{original_filename or source_name}#source={source_id}"
            )[:256]
            evidence_source["normalization"] = (
                "Authenticated connector transport; deterministic V3 mapping; "
                "missing values remain null and no value is estimated or imputed."
            )
        validate_five_quantity_payload(
            imported["payload"],
            identity=self.identity,
            confirmed=False,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )
        return self.store.create_or_update_machine_import(
            imported,
            ingestion_id=ingestion_id,
            lease_owner=lease_owner,
            client_id=client_id,
            draft_key=draft_key,
            source_id=source_id,
            source_revision=source_revision,
            source_observed_at=observed_at,
            source_coverage_as_of=coverage_as_of,
            source_required=source_required,
            freshness_max_seconds=freshness_max_seconds,
            actor=actor_id,
            identity=self.identity,
        )

    @staticmethod
    def _read_no_follow(path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("监听目标不是普通文件")
            if info.st_size <= 0 or info.st_size > MAX_IMPORT_BYTES:
                raise ValueError("监听文件为空或超过 20 MiB")
            chunks = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) != info.st_size:
                raise ValueError("读取期间文件发生变化")
            return content
        finally:
            os.close(descriptor)

    def scan_watched_directories(self) -> list[dict[str, Any]]:
        results = []
        now = time.monotonic()
        for directory in self.watched_directories:
            for path in sorted(directory.iterdir()):
                if path.is_symlink() or path.suffix.casefold() not in ALLOWED_SUFFIXES:
                    continue
                result: dict[str, Any] | None = None
                try:
                    info = path.stat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                fingerprint = (info.st_size, info.st_mtime_ns)
                key = str(path)
                if self._processed_paths.get(key) == fingerprint:
                    continue
                prior = self._watch_state.get(key)
                if prior is None or prior[:2] != fingerprint:
                    self._watch_state[key] = (*fingerprint, now)
                    continue
                if now - prior[2] < self.stable_seconds:
                    continue
                try:
                    content = self._read_no_follow(path)
                    result = self.ingest_bytes(
                        filename=path.name,
                        content=content,
                        acquisition_mode="direct_collection",
                        actor="system-watcher",
                        source_path=str(path),
                    )
                except Exception as error:
                    with suppress(Exception):
                        content = self._read_no_follow(path)
                        digest = hashlib.sha256(content).hexdigest()
                        target = self.quarantine_directory / (
                            f"{digest[:16]}-{path.name}"
                        )
                        self._write_quarantine_file(target, content)
                        result = self.store.record_quarantine(
                            filename=path.name,
                            content_sha256=digest,
                            acquisition_mode="direct_collection",
                            source_path=str(path),
                            error_message=str(error),
                        )
                    if result is None:
                        continue
                self._processed_paths[key] = fingerprint
                results.append(result)
        return results

    def save_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        payload: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        draft = self.store.get_draft(draft_id)
        if draft["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
            raise ConflictError("五量 V2 草稿仅供读取，不能保存或升级")
        validate_five_quantity_payload(
            payload,
            identity=self.identity,
            confirmed=False,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )
        return self.store.replace_draft(
            draft_id,
            expected_revision=expected_revision,
            payload=payload,
            actor=actor,
            identity=self.identity,
        )

    def machine_sync_state(self, draft_id: str) -> dict[str, Any] | None:
        return self.store.machine_sync_state(draft_id)

    def resume_machine_sync(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        accepted: bool,
        actor: str,
    ) -> dict[str, Any]:
        if accepted is not True:
            raise ValidationBlockedError(
                "必须明确确认放弃本草稿的人工修改后才能恢复自动同步"
            )
        if isinstance(expected_revision, bool) or not isinstance(
            expected_revision, int
        ):
            raise ValueError("expected_revision 必须是整数")
        return self.store.resume_machine_sync(
            draft_id,
            expected_revision=expected_revision,
            actor=actor,
            identity=self.identity,
        )

    def discard_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        return self.store.discard_draft(
            draft_id,
            expected_revision=expected_revision,
            actor=actor,
            reason=reason,
        )

    def create_correction_draft(
        self,
        source_draft_id: str,
        *,
        expected_revision: int,
        expected_submission_revision: int,
        accepted: bool,
        actor: str,
    ) -> dict[str, Any]:
        if accepted is not True:
            raise ValidationBlockedError(
                "必须明确确认以已送达版本为基线创建下一版更正草稿"
            )
        return self.store.create_correction_draft(
            source_draft_id,
            expected_revision=expected_revision,
            expected_submission_revision=expected_submission_revision,
            actor=actor,
            identity=self.identity,
        )

    def _base_message(
        self,
        *,
        contract_version: str,
        message_type: str,
        payload: dict[str, Any],
        correlation_id: str,
        causation_id: str | None,
        revision: int = 1,
        predecessor: dict[str, str] | None = None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        message_id = str(uuid.uuid4())
        now = utc_text()
        if contract_version in {
            TEN_QUANTITY_SUBMISSION_CONTRACT,
            TEN_QUANTITY_ANALYSIS_CONTRACT,
        }:
            signature_algorithm = "hmac-sha256-v3"
        elif contract_version in {
            LEGACY_SUBMISSION_CONTRACT,
            "risk-delivery-ack-v2",
            "enterprise-risk-response-v2",
        }:
            signature_algorithm = "hmac-sha256-v2"
        else:
            raise ValueError("应用消息 contract_version 不受支持")
        message = {
            "contract_version": contract_version,
            "message_type": message_type,
            "message_id": message_id,
            "correlation_id": correlation_id,
            "causation_id": causation_id,
            "idempotency_key": idempotency_key,
            "revision": revision,
            "predecessor": predecessor,
            "created_at": now,
            "sender": {
                "system_id": self.identity.system_id,
                "party_id": self.identity.operator_id,
                "role": "enterprise_agent",
            },
            "recipient": {
                "system_id": self.identity.regulator_system_id,
                "party_id": self.identity.regulator_party_id,
                "role": "regulatory_platform",
            },
            "mine_id": self.identity.mine_id,
            "payload": payload,
            "signature_envelope": {
                "algorithm": signature_algorithm,
                "canonicalization": "rfc8785-jcs",
                "key_id": self.identity.key_id,
                "signed_at": now,
                "nonce": os.urandom(16).hex(),
                "payload_sha256": ZERO_HASH,
                "signature": ZERO_HASH,
            },
        }
        if message_type in {
            "five_quantity_submission",
            TEN_QUANTITY_SUBMISSION_MESSAGE_TYPE,
        } and revision == 1:
            message["correlation_id"] = message_id
        return sign_message(message, secret=self.identity.message_hmac_secret)

    def confirm_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        actor_id: str,
        confirmer_name: str,
        confirmer_role: str,
        attestation: str,
        accepted: bool,
    ) -> dict[str, Any]:
        if actor_id == "demo":
            raise ValidationBlockedError("演示账号只能建稿和查看，不能确认或报送")
        if accepted is not True:
            raise ValidationBlockedError("必须由企业人员明确确认后才能报送")
        draft = self.store.get_draft(draft_id)
        if draft["contract_version"] != CURRENT_SUBMISSION_CONTRACT:
            raise ValidationBlockedError("五量 V2 草稿仅供读取，不能重新确认或发送")
        if draft["revision"] != expected_revision:
            raise ConflictError("草稿修订号已变化")
        sync_state = self.store.machine_sync_state(draft_id)
        if sync_state is not None:
            health = self.machine_source_health(draft_id)
            stale_sources = health["freshness"][
                "stale_required_source_ids"
            ]
            if health["freshness"]["overall_state"] != "fresh":
                source_text = "、".join(stale_sources) or "未配置来源"
                raise ValidationBlockedError(
                    "必需机器来源未通过动态新鲜度与当前快照绑定检查："
                    f"{source_text}"
                )
        payload = json.loads(jcs_json(draft["payload"]))
        confirmed_at = utc_text()
        confirmation_record = {
            "actor_id": _text(actor_id, "actor_id", 128),
            "confirmer_name": _text(confirmer_name, "confirmer_name", 128),
            "role": _text(confirmer_role, "confirmer_role", 128),
            "attestation": _text(attestation, "attestation", 1000),
            "confirmed_at": confirmed_at,
            "draft_revision": expected_revision,
            "payload_sha256": sha256_jcs(payload),
        }
        confirmation = {
            "confirmed": True,
            "confirmer_id": actor_id,
            "confirmer_name": confirmer_name.strip(),
            "role": confirmer_role.strip(),
            "confirmed_at": confirmed_at,
            "content_sha256": sha256_jcs(confirmation_record),
        }
        payload["human_confirmation"] = confirmation
        validate_five_quantity_payload(
            payload,
            identity=self.identity,
            confirmed=True,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )
        idempotency = (
            f"tq3.{self.identity.mine_id}."
            f"{payload['reporting_month']}.r{draft['submission_revision']}"
        )
        submission_revision = int(draft["submission_revision"])
        if submission_revision == 1:
            correlation_id = str(uuid.uuid4())
            causation_id = None
            predecessor = None
        else:
            correlation_id = draft.get("correlation_id")
            predecessor = draft.get("predecessor")
            if (
                not isinstance(correlation_id, str)
                or not correlation_id
                or not isinstance(predecessor, dict)
                or not isinstance(predecessor.get("message_id"), str)
                or not isinstance(predecessor.get("payload_sha256"), str)
            ):
                raise ConflictError("十量 V3 更正草稿缺少完整的前序签名血缘")
            causation_id = predecessor["message_id"]
        message = self._base_message(
            contract_version=CURRENT_SUBMISSION_CONTRACT,
            message_type=TEN_QUANTITY_SUBMISSION_MESSAGE_TYPE,
            payload=payload,
            correlation_id=correlation_id,
            causation_id=causation_id,
            revision=submission_revision,
            predecessor=predecessor,
            idempotency_key=idempotency,
        )
        self.store.confirm_and_enqueue(
            draft_id,
            expected_revision=expected_revision,
            confirmation=confirmation_record,
            message=message,
            actor=actor_id,
            machine_source_policies=self._machine_source_policies,
            health_now_epoch=time.time(),
            identity=self.identity,
        )
        return self.store.get_draft(draft_id)

    def process_outbox_once(self) -> list[dict[str, Any]]:
        if self.platform_client is None:
            return []
        results = []
        for item in self.store.due_outbox():
            message = item["body"]
            try:
                self.store.assert_outbox_sendable(item["message_id"])
                if item["message_kind"] == "submission":
                    receipt = self.platform_client.submit(message)
                    verify_message(
                        receipt,
                        secret=self.identity.message_hmac_secret,
                        identity=self.identity,
                        expected_contract="intake-receipt-v2",
                        expected_type="intake_receipt",
                    )
                    if (
                        receipt["causation_id"] != message["message_id"]
                        or receipt["payload"].get("submission_message_id")
                        != message["message_id"]
                        or receipt["payload"].get("received_payload_sha256")
                        != message["signature_envelope"]["payload_sha256"]
                    ):
                        raise PlatformError("接收回执未正确绑定报送消息")
                elif item["message_kind"] == "delivery_ack":
                    report_record = self.store.get_report(item["aggregate_id"])
                    legacy_report = (
                        report_record["report"].get("contract_version")
                        == "analysis-report-v2"
                    )
                    if legacy_report:
                        self.platform_client.acknowledge(
                            item["aggregate_id"], message, legacy=True
                        )
                    else:
                        self.platform_client.acknowledge(
                            item["aggregate_id"], message
                        )
                    receipt = None
                elif item["message_kind"] == "risk_response":
                    response = self.store.get_response(item["aggregate_id"])
                    report_record = self.store.get_report(response["report_id"])
                    legacy_report = (
                        report_record["report"].get("contract_version")
                        == "analysis-report-v2"
                    )
                    receipt = (
                        self.platform_client.respond(
                            response["report_id"], message, legacy=True
                        )
                        if legacy_report
                        else self.platform_client.respond(
                            response["report_id"], message
                        )
                    )
                    verify_message(
                        receipt,
                        secret=self.identity.message_hmac_secret,
                        identity=self.identity,
                        expected_contract="response-receipt-v2",
                        expected_type="response_receipt",
                    )
                    if (
                        receipt["causation_id"] != message["message_id"]
                        or receipt["payload"].get("enterprise_response_message_id")
                        != message["message_id"]
                        or receipt["payload"].get("risk_status")
                        != "not_cleared_by_receipt"
                    ):
                        raise PlatformError("风险回复回执绑定或风险状态非法")
                else:
                    raise ValueError("未知 outbox 消息类型")
                self.store.outbox_succeeded(item["message_id"], receipt=receipt)
                results.append(
                    {"message_id": item["message_id"], "status": "succeeded"}
                )
            except Exception as error:
                self.store.outbox_failed(
                    item["message_id"], error=str(error), attempts=item["attempts"]
                )
                results.append({"message_id": item["message_id"], "status": "failed"})
        return results

    def poll_analysis_once(self) -> dict[str, Any] | None:
        if self.platform_client is None:
            return None
        report = self.platform_client.pull_next(after_cursor=self.store.last_cursor())
        if report is None:
            return None
        report_contract = report.get("contract_version")
        if report_contract != TEN_QUANTITY_ANALYSIS_CONTRACT:
            raise PlatformError("V3 分析路由返回了非 analysis-report-v3 报告")
        verify_message(
            report,
            secret=self.identity.message_hmac_secret,
            identity=self.identity,
            expected_contract=report_contract,
            expected_type="analysis_report",
        )
        _validate_analysis_report(report, self.identity)
        payload = report["payload"]
        ack_payload = {
            "report_id": payload["report_id"],
            "analysis_report_message_id": report["message_id"],
            "delivery_cursor": payload["delivery_cursor"],
            "received_at": utc_text(),
            "local_inbox_record_id": f"INBOX-{report['message_id']}",
            "delivery_status": "stored",
        }
        ack = self._base_message(
            contract_version="risk-delivery-ack-v2",
            message_type="risk_delivery_ack",
            payload=ack_payload,
            correlation_id=report["correlation_id"],
            causation_id=report["message_id"],
            idempotency_key=f"delivery-ack.{report['message_id']}",
        )
        return self.store.store_report_with_ack(report, ack)

    def risk_explanation(
        self, report_id: str, question: str, *, actor: str
    ) -> dict[str, Any]:
        question = _text(question, "问题", 2000)
        if any(
            phrase in question.casefold()
            for phrase in ("股票", "天气", "写代码", "游戏", "娱乐", "体育比分")
        ):
            answer = (
                "该对话只解释当前煤矿十量风险报告，请围绕异常日期、指标、"
                "证据、原因或回复材料提问。"
            )
            tools: list[str] = []
        else:
            record = self.store.get_report(report_id)
            payload = record["report"]["payload"]
            findings = payload["findings"]
            metric_codes = sorted(
                {
                    metric
                    for finding in findings
                    for metric in finding.get("affected_metrics", [])
                }
            )
            metrics = [_METRIC_LABELS.get(metric, metric) for metric in metric_codes]
            dates = sorted(
                {
                    day
                    for finding in findings
                    for day in finding.get("affected_dates", [])
                }
            )
            methods = sorted(
                {
                    evidence.get("method")
                    for finding in findings
                    for evidence in finding.get("evidence", [])
                    if evidence.get("method")
                }
            )
            tools = ["report_summary", "affected_scope", "evidence_method_explainer"]
            method_text = []
            if "l1_reconciliation" in methods:
                method_text.append(
                    "L1 求解器在联合约束下寻找最小必要调整；超阈值表示"
                    "多项数据难以同时协调，不等于自动认定造假"
                )
            if "minimal_conflict_set" in methods:
                method_text.append("最小冲突集用于缩小需要核对的日期和指标组合")
            if any(
                method in methods
                for method in (
                    "robust_temporal_baseline",
                    "past_only_rolling_mad",
                    "past_only_ewma",
                    "past_only_cusum",
                    "past_only_page_hinkley",
                    "temporal_drift",
                    "change_point",
                )
            ):
                method_text.append(
                    "时序模块只使用当前日期以前的本矿同工况历史：Rolling MAD"
                    "检查稳健离群，EWMA 检查持续偏移，CUSUM 和 Page-Hinkley"
                    "检查累积变化，并结合漂移与变化点复核"
                )
            if "anonymous_peer_baseline" in methods:
                method_text.append("同类矿证据只使用匿名统计区间，不展示其他煤矿明细")
            checklist = "；".join(
                [
                    "核对原表对应日期和班次",
                    "确认单位及日报与班次口径",
                    "查找检修、停复产、供电或生产计划记录",
                    "如数值有误先提交更正报表，再在回复中引用更正消息",
                ]
            )
            answer = (
                f"报告结论：{payload['summary']}\n"
                f"涉及日期：{'、'.join(dates) or '报告未列明'}；"
                f"涉及指标：{'、'.join(metrics) or '报告未列明'}。\n"
                + ("；".join(method_text) + "。\n" if method_text else "")
                + f"建议核对：{checklist}。企业原因说明只会被记录，"
                "不能直接消除风险；更正数据需由政府同一算法重算。"
            )
        messages = self.store.append_chat(
            report_id=report_id,
            actor_id=actor,
            question=question,
            answer=answer,
            tools=tools,
        )
        return {"answer": answer, "tools": tools, "messages": messages}

    def save_response(
        self,
        response_id: str,
        *,
        expected_revision: int,
        document: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        current = self.store.get_response(response_id)
        if document.get("response_id") != response_id:
            raise ValueError("response_id 不得修改")
        report = self.store.get_report(current["report_id"])
        _validate_response_document(document, report)
        return self.store.replace_response(
            response_id,
            expected_revision=expected_revision,
            document=document,
            actor=actor,
        )

    def confirm_response(
        self,
        response_id: str,
        *,
        expected_revision: int,
        actor_id: str,
        confirmer_name: str,
        confirmer_role: str,
        attestation: str,
        accepted: bool,
    ) -> dict[str, Any]:
        if actor_id == "demo":
            raise ValidationBlockedError("演示账号只能建稿和查看，不能确认或报送")
        if accepted is not True:
            raise ValidationBlockedError("必须由企业人员明确确认风险回复")
        response = self.store.get_response(response_id)
        if response["revision"] != expected_revision:
            raise ConflictError("风险回复修订号已变化")
        report = self.store.get_report(response["report_id"])
        document = json.loads(jcs_json(response["document"]))
        chat_messages = self.store.chat_messages(response["report_id"])
        if chat_messages:
            document["agent_assistance"] = {
                "used": True,
                "conversation_id": f"risk-chat:{response['report_id']}",
                "assistance_record_sha256": sha256_jcs(chat_messages),
            }
        _validate_response_document(document, report)
        confirmed_at = utc_text()
        confirmation_record = {
            "actor_id": _text(actor_id, "actor_id", 128),
            "confirmer_name": _text(confirmer_name, "confirmer_name", 128),
            "role": _text(confirmer_role, "confirmer_role", 128),
            "attestation": _text(attestation, "attestation", 1000),
            "confirmed_at": confirmed_at,
            "response_revision": expected_revision,
            "document_sha256": sha256_jcs(document),
        }
        human = {
            "confirmed": True,
            "confirmer_id": actor_id,
            "confirmer_name": confirmer_name.strip(),
            "role": confirmer_role.strip(),
            "confirmed_at": confirmed_at,
            "content_sha256": sha256_jcs(confirmation_record),
        }
        document["responded_at"] = confirmed_at
        document["human_confirmation"] = human
        message = self._base_message(
            contract_version="enterprise-risk-response-v2",
            message_type="enterprise_risk_response",
            payload=document,
            correlation_id=report["report"]["correlation_id"],
            causation_id=report["message_id"],
            revision=1,
            idempotency_key=f"risk-response.{report['report_id']}.{response_id}.r1",
        )
        return self.store.confirm_response_and_enqueue(
            response_id,
            expected_revision=expected_revision,
            confirmation=confirmation_record,
            message=message,
            actor=actor_id,
        )

    def status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "mine_id": self.identity.mine_id,
            "mine_name": self.identity.mine_name,
            "operator_id": self.identity.operator_id,
            "system_id": self.identity.system_id,
            "platform_configured": self.platform_client is not None,
            "watched_directories": [str(path) for path in self.watched_directories],
            "quarantine_directory": str(self.quarantine_directory),
            "csv_mapping_preview_enabled": True,
            "csv_mapping_ai_configured": self.csv_mapping_provider is not None,
            "four_eyes_required": self.four_eyes_required,
            "acquisition_modes": ["manual_import", "direct_collection"],
            "acquisition_trust_tiering": False,
            "message_signature_domain": MESSAGE_SIGNING_CONTEXT_V3,
            "transport_signature_domain": HTTP_SIGNING_CONTEXT_V3,
            "legacy_message_signature_domain": MESSAGE_SIGNING_CONTEXT,
            "legacy_transport_signature_domain": HTTP_SIGNING_CONTEXT,
            "distinct_application_and_transport_secrets": (
                self.platform_client is not None
                and not hmac.compare_digest(
                    self.identity.message_hmac_secret.encode("utf-8"),
                    self.platform_client.config.transport_hmac_secret.encode("utf-8"),
                )
            ),
            "regulator_verification_key_ids": [
                self.identity.regulator_key_id,
                *(
                    [self.identity.previous_regulator_key_id]
                    if self.identity.previous_regulator_key_id is not None
                    else []
                ),
            ],
            "last_acknowledged_cursor": self.store.last_cursor(),
        }
