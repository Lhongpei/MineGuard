"""Deterministic validation and missing-information questions."""

from __future__ import annotations

import math
import re
from datetime import timedelta
from typing import Any

from .models import DRAFT_SCHEMA_VERSION
from .security import MAX_SAFE_INTEGER, observation_payload
from .util import parse_aware_datetime, sha256_json

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_VALUE = 1_000_000_000_000.0
_CORE_CONTEXT = ("regime_code", "shift_code", "season_code", "maintenance")
_CONTEXT_FIELDS = {
    *_CORE_CONTEXT,
    "approved_event_codes",
    "tags",
}
_OBSERVATION_FIELDS = {
    "source_id",
    "observation_id",
    "metric_code",
    "value",
    "unit",
    "observed_at",
    "received_at",
    "interval_start",
    "interval_end",
    "reset_before",
    "sequence_no",
    "revision",
    "payload_sha256",
    "signature",
}


def _issue(
    code: str,
    path: str,
    message: str,
    *,
    severity: str = "blocking",
) -> dict[str, str]:
    return {
        "code": code,
        "path": path,
        "message": message,
        "severity": severity,
    }


def _required_text(
    value: Any,
    path: str,
    label: str,
    issues: list[dict[str, str]],
    *,
    identifier: bool = False,
    maximum: int = 128,
) -> None:
    if not isinstance(value, str) or not value.strip():
        issues.append(_issue("required", path, f"请填写{label}"))
        return
    if len(value) > maximum:
        issues.append(_issue("too_long", path, f"{label}长度不能超过 {maximum}"))
    if identifier and not _IDENTIFIER.fullmatch(value):
        issues.append(
            _issue(
                "invalid_identifier",
                path,
                f"{label}只能使用字母、数字、点、下划线、冒号和连字符",
            )
        )


def validate_draft(document: dict[str, Any]) -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    business_checks: list[dict[str, Any]] = []
    if document.get("schema_version") != DRAFT_SCHEMA_VERSION:
        issues.append(
            _issue(
                "unsupported_schema",
                "/schema_version",
                f"仅支持 {DRAFT_SCHEMA_VERSION}",
            )
        )

    for field, label in (
        ("enterprise_id", "企业编号"),
        ("enterprise_name", "企业名称"),
        ("unified_social_credit_code", "统一社会信用代码"),
        ("mine_id", "矿井编号"),
        ("mine_name", "矿井名称"),
        ("profile_id", "分析配置编号"),
        ("profile_version", "分析配置版本"),
    ):
        _required_text(
            document.get(field),
            f"/{field}",
            label,
            issues,
            identifier=field
            in {"enterprise_id", "mine_id", "profile_id", "profile_version"},
            maximum=(
                256
                if field in {"enterprise_name", "mine_name"}
                else (64 if field == "profile_version" else 128)
            ),
        )
    credit_code = document.get("unified_social_credit_code")
    if (
        isinstance(credit_code, str)
        and credit_code.strip()
        and not re.fullmatch(r"[0-9A-HJ-NPQRTUWXY]{18}", credit_code)
    ):
        issues.append(
            _issue(
                "invalid_credit_code",
                "/unified_social_credit_code",
                "统一社会信用代码必须是 18 位规范代码",
            )
        )

    window_start = window_end = None
    for field, _label in (
        ("window_start", "统计开始时间"),
        ("window_end", "统计结束时间"),
    ):
        try:
            parsed = parse_aware_datetime(document.get(field), field)
            if field == "window_start":
                window_start = parsed
            else:
                window_end = parsed
        except ValueError as error:
            issues.append(_issue("invalid_datetime", f"/{field}", str(error)))
    if window_start is not None and window_end is not None:
        if window_end <= window_start:
            issues.append(
                _issue(
                    "invalid_window",
                    "/window_end",
                    "统计结束时间必须晚于开始时间",
                )
            )
        elif window_end - window_start > timedelta(days=366):
            issues.append(
                _issue(
                    "window_too_long",
                    "/window_end",
                    "单次报送统计窗口不能超过 366 天",
                )
            )

    context = document.get("operational_context")
    if not isinstance(context, dict):
        issues.append(_issue("invalid_type", "/operational_context", "工况必须是对象"))
        context = {}
    unknown_context = set(context) - _CONTEXT_FIELDS
    if unknown_context:
        issues.append(
            _issue(
                "unsupported_fields",
                "/operational_context",
                "工况包含不支持的字段："
                + ", ".join(sorted(str(item) for item in unknown_context)),
            )
        )
    for axis in _CORE_CONTEXT:
        value = context.get(axis)
        path = f"/operational_context/{axis}"
        if axis == "maintenance":
            if not isinstance(value, bool):
                issues.append(_issue("required", path, "请明确是否处于检修状态"))
        elif not isinstance(value, str) or not value.strip():
            issues.append(_issue("required", path, f"请填写工况字段 {axis}"))
        elif len(value) > 64:
            issues.append(_issue("too_long", path, f"工况字段 {axis} 不能超过 64 字符"))
    for field in ("approved_event_codes", "tags"):
        value = context.get(field, [])
        maximum_items = 32 if field == "approved_event_codes" else 64
        maximum_length = 64 if field == "approved_event_codes" else 128
        if (
            not isinstance(value, list)
            or len(value) > maximum_items
            or any(
                not isinstance(item, str)
                or not item.strip()
                or len(item) > maximum_length
                for item in value
            )
            or len(value) != len(set(value))
        ):
            issues.append(
                _issue(
                    "invalid_list",
                    f"/operational_context/{field}",
                    f"{field} 必须是最多 {maximum_items} 个不重复非空字符串",
                )
            )

    observations = document.get("observations")
    if not isinstance(observations, list) or not observations:
        issues.append(
            _issue(
                "observations_required",
                "/observations",
                "至少需要一条来源观测",
            )
        )
        observations = []
    elif len(observations) > 10_000:
        issues.append(
            _issue(
                "too_many_observations",
                "/observations",
                "单个草稿最多包含 10000 条来源观测",
            )
        )

    seen_ids: set[str] = set()
    provenance = document.get("field_provenance")
    if not isinstance(provenance, dict):
        issues.append(
            _issue(
                "invalid_provenance",
                "/field_provenance",
                "字段来源记录必须是对象",
            )
        )
        provenance = {}
    event_snapshot_records = provenance.get(
        "/operational_context/approved_event_codes"
    )
    if not (
        isinstance(event_snapshot_records, list)
        and any(
            isinstance(record, dict)
            and record.get("source_kind") == "approved_document"
            and record.get("extraction_method")
            == "regulator_event_snapshot_import"
            and isinstance(record.get("content_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", record["content_sha256"])
            is not None
            for record in event_snapshot_records
        )
    ):
        issues.append(
            _issue(
                "regulator_event_snapshot_required",
                "/operational_context/approved_event_codes",
                "已批准事件代码（包括确认为空）必须导入与当前矿井和统计窗口"
                "完全一致的监管事件快照，普通手填或一般文件来源不能替代",
            )
        )

    for index, observation in enumerate(observations):
        base = f"/observations/{index}"
        if not isinstance(observation, dict):
            issues.append(_issue("invalid_type", base, "观测必须是对象"))
            continue
        unknown_fields = set(observation) - _OBSERVATION_FIELDS
        if unknown_fields:
            issues.append(
                _issue(
                    "unsupported_fields",
                    base,
                    "观测包含不支持的字段："
                    + ", ".join(sorted(str(item) for item in unknown_fields)),
                )
            )
        for field, label in (
            ("source_id", "来源编号"),
            ("observation_id", "观测编号"),
            ("unit", "单位"),
        ):
            maximum = (
                32 if field == "unit" else (256 if field == "observation_id" else 128)
            )
            _required_text(
                observation.get(field),
                f"{base}/{field}",
                label,
                issues,
                identifier=field != "unit",
                maximum=maximum,
            )
        observation_id = observation.get("observation_id")
        if isinstance(observation_id, str) and observation_id:
            if observation_id in seen_ids:
                issues.append(
                    _issue(
                        "duplicate_observation_id",
                        f"{base}/observation_id",
                        "同一草稿内观测编号不能重复",
                    )
                )
            seen_ids.add(observation_id)
        value = observation.get("value")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or abs(float(value)) > _MAX_VALUE
        ):
            issues.append(
                _issue(
                    "invalid_value",
                    f"{base}/value",
                    f"观测值必须是绝对值不超过 {_MAX_VALUE:g} 的有限数",
                )
            )
        metric_code = observation.get("metric_code")
        if (
            isinstance(metric_code, str)
            and metric_code
            and metric_code != "inventory.raw_change_t"
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and value < 0
        ):
            issues.append(
                _issue(
                    "negative_quantity",
                    f"{base}/value",
                    f"指标 {metric_code} 的数量不能为负数",
                )
            )
        observed_at = received_at = None
        for field in ("observed_at", "received_at"):
            try:
                parsed = parse_aware_datetime(
                    observation.get(field), f"observations[{index}].{field}"
                )
                if field == "observed_at":
                    observed_at = parsed
                else:
                    received_at = parsed
            except ValueError as error:
                issues.append(_issue("invalid_datetime", f"{base}/{field}", str(error)))
        if (
            observed_at is not None
            and received_at is not None
            and received_at < observed_at
        ):
            issues.append(
                _issue(
                    "received_before_observed",
                    f"{base}/received_at",
                    "接收时间不能早于观测时间",
                )
            )
        interval_start = observation.get("interval_start")
        interval_end = observation.get("interval_end")
        if (interval_start is None) != (interval_end is None):
            issues.append(
                _issue(
                    "incomplete_interval",
                    base,
                    "区间开始和结束时间必须同时填写",
                )
            )
        elif interval_start is not None:
            try:
                start = parse_aware_datetime(
                    interval_start, f"observations[{index}].interval_start"
                )
                end = parse_aware_datetime(
                    interval_end, f"observations[{index}].interval_end"
                )
                if end <= start:
                    issues.append(
                        _issue(
                            "invalid_interval",
                            f"{base}/interval_end",
                            "观测区间结束时间必须晚于开始时间",
                        )
                    )
            except ValueError as error:
                issues.append(_issue("invalid_datetime", base, str(error)))
        for field in ("sequence_no", "revision"):
            value_int = observation.get(field)
            if (
                isinstance(value_int, bool)
                or not isinstance(value_int, int)
                or value_int < 0
                or value_int > MAX_SAFE_INTEGER
            ):
                issues.append(
                    _issue(
                        "invalid_safe_integer",
                        f"{base}/{field}",
                        f"{field} 必须是 0 到 {MAX_SAFE_INTEGER} 的整数",
                    )
                )
        if not isinstance(observation.get("reset_before"), bool):
            issues.append(
                _issue(
                    "invalid_boolean",
                    f"{base}/reset_before",
                    "reset_before 必须是布尔值",
                )
            )
        payload_sha256 = observation.get("payload_sha256")
        signature = observation.get("signature")
        digest_has_valid_format = (
            isinstance(payload_sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", payload_sha256) is not None
        )
        if not digest_has_valid_format:
            issues.append(
                _issue(
                    "source_payload_digest_required",
                    f"{base}/payload_sha256",
                    "必须提供来源网关签发的 64 位小写十六进制载荷摘要",
                )
            )
        if (
            not isinstance(signature, str)
            or re.fullmatch(r"[0-9a-f]{64}", signature) is None
        ):
            issues.append(
                _issue(
                    "source_signature_required",
                    f"{base}/signature",
                    "必须提供来源网关签发的 64 位小写十六进制 HMAC；"
                    "填报智能体不能代签",
                )
            )
        if digest_has_valid_format:
            try:
                expected_payload_sha256 = sha256_json(
                    observation_payload(observation)
                )
            except (KeyError, TypeError, ValueError):
                # Business-field validation above reports the primary cause.
                expected_payload_sha256 = None
            if (
                expected_payload_sha256 is not None
                and payload_sha256 != expected_payload_sha256
            ):
                issues.append(
                    _issue(
                        "source_payload_digest_mismatch",
                        f"{base}/payload_sha256",
                        "来源摘要与规范化观测载荷不一致；数据可能已被修改，"
                        "必须从来源网关重新获取签名观测",
                    )
                )
        for critical in (
            "source_id",
            "observation_id",
            "value",
            "unit",
            "observed_at",
            "received_at",
            "interval_start",
            "interval_end",
            "reset_before",
            "sequence_no",
            "revision",
            "payload_sha256",
            "signature",
        ):
            pointer = f"{base}/{critical}"
            records = provenance.get(pointer)
            if not isinstance(records, list) or not records:
                issues.append(
                    _issue(
                        "provenance_required",
                        pointer,
                        "关键观测字段必须保留来源记录",
                    )
                )

    for pointer in (
        "/enterprise_id",
        "/enterprise_name",
        "/unified_social_credit_code",
        "/mine_id",
        "/mine_name",
        "/window_start",
        "/window_end",
        "/profile_id",
        "/profile_version",
        "/operational_context/regime_code",
        "/operational_context/shift_code",
        "/operational_context/season_code",
        "/operational_context/maintenance",
        "/operational_context/approved_event_codes",
        "/operational_context/tags",
    ):
        records = provenance.get(pointer)
        if not isinstance(records, list) or not records:
            issues.append(
                _issue(
                    "provenance_required",
                    pointer,
                    "报送字段必须保留来源记录",
                )
            )

    metric_totals: dict[str, float] = {}
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        metric = observation.get("metric_code")
        value = observation.get("value")
        if (
            isinstance(metric, str)
            and metric
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        ):
            metric_totals[metric] = metric_totals.get(metric, 0.0) + float(value)

    def first_metric(*names: str) -> float | None:
        for name in names:
            if name in metric_totals:
                return metric_totals[name]
        return None

    def balance_check(
        code: str,
        label: str,
        residual: float | None,
        scale_values: tuple[float | None, ...],
    ) -> None:
        if residual is None:
            business_checks.append(
                {
                    "code": code,
                    "status": "not_evaluated",
                    "message": f"{label}缺少必要指标，未执行预检",
                }
            )
            return
        scale = max(
            (abs(value) for value in scale_values if value is not None),
            default=0.0,
        )
        ratio = abs(residual) / max(scale, 1.0)
        status = "warning" if ratio > 0.05 else "pass"
        message = (
            f"{label}差额 {residual:.3f}，相对差额 {ratio:.2%}；"
            "该预检不替代监管平台核验"
        )
        business_checks.append(
            {
                "code": code,
                "status": status,
                "residual": residual,
                "relative_gap": ratio,
                "message": message,
            }
        )
        if status == "warning":
            issues.append(
                _issue(
                    code,
                    "/observations",
                    message,
                    severity="warning",
                )
            )

    production = first_metric("coal.reported_output_t", "coal.production_t")
    transport = first_metric("coal.main_transport_t")
    balance_check(
        "production_transport_gap",
        "产量与主运输量",
        (
            production - transport
            if production is not None and transport is not None
            else None
        ),
        (production, transport),
    )

    opening = first_metric("coal.opening_inventory_t")
    purchase = first_metric("coal.purchase_in_t")
    sales = first_metric("sales.raw_shipped_t", "coal.sale_out_t")
    processing = first_metric("wash.feed_t", "coal.processing_input_t")
    closing = first_metric("coal.closing_inventory_t")
    detailed = (opening, production, purchase, sales, processing, closing)
    detailed_residual = (
        opening + production + purchase - sales - processing - closing
        if all(value is not None for value in detailed)
        else None
    )
    balance_check(
        "stock_flow_gap",
        "库存收发存",
        detailed_residual,
        detailed,
    )

    inventory_change = first_metric("inventory.raw_change_t")
    legacy_values = (production, processing, sales, inventory_change)
    legacy_residual = (
        production - processing - sales - inventory_change
        if all(value is not None for value in legacy_values)
        else None
    )
    balance_check(
        "raw_coal_flow_gap",
        "原煤去向",
        legacy_residual,
        legacy_values,
    )

    blocking = [item for item in issues if item["severity"] == "blocking"]
    warnings = [item for item in issues if item["severity"] == "warning"]
    return {
        "valid": not blocking,
        "blocking_count": len(blocking),
        "warning_count": len(warnings),
        "issues": issues,
        "business_checks": business_checks,
    }


def questions_for_draft(document: dict[str, Any]) -> list[dict[str, Any]]:
    result = validate_draft(document)
    questions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for issue in result["issues"]:
        path = issue["path"]
        if path in seen:
            continue
        seen.add(path)
        questions.append(
            {
                "question_id": f"q-{len(questions) + 1}",
                "path": path,
                "code": issue["code"],
                "question": issue["message"],
                "required": issue["severity"] == "blocking",
            }
        )
    return questions
