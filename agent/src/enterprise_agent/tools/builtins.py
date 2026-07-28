"""Built-in deterministic coal reporting tools.

These functions calculate from the selected draft, succeeded submissions in
the injected repository, or quantities explicitly supplied by the caller.
They never infer missing measurements and never issue a legal conclusion.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from enterprise_agent.security import observation_payload
from enterprise_agent.util import sha256_json
from enterprise_agent.validation import validate_draft

from .core import (
    ENERGY_FACTORS_MJ,
    HEX64,
    MASS_FACTORS_T,
    bounded_strings,
    conversion_factor,
    convert,
    decimal_median,
    disclaimer,
    draft,
    finite_decimal,
    json_number,
    mad,
    observation_values,
    parsed_time,
    percentile,
    public_document,
    repository,
    total_metric,
)
from .protocol import (
    ToolContext,
    ToolProtocolError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
    strict_object,
)

_ID = {"type": "string", "minLength": 1, "maxLength": 256}
_METRIC = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
}
_UNIT = {"type": "string", "minLength": 1, "maxLength": 16}
_NUMBER = {
    "type": "number",
    "minimum": -1_000_000_000_000,
    "maximum": 1_000_000_000_000,
}
_NONNEGATIVE = {"type": "number", "minimum": 0, "maximum": 1_000_000_000_000}
_NULLABLE_NUMBER = {"type": ["number", "null"]}
_STRING_ARRAY = {
    "type": "array",
    "maxItems": 10_000,
    "items": {"type": "string", "maxLength": 256},
}
_DISCLAIMER = {"type": "string", "minLength": 1, "maxLength": 256}
_MAX_RETURNED_DETAILS = 100
_MAX_RETURNED_ISSUES = 200


def _bounded_details(
    items: Sequence[Any], maximum: int = _MAX_RETURNED_DETAILS
) -> tuple[list[Any], int, bool, str]:
    material = list(items)
    return (
        material[:maximum],
        len(material),
        len(material) > maximum,
        sha256_json(material),
    )


def _draft_summary(arguments: Mapping[str, Any], context: ToolContext) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for index, observation in enumerate(value["observations"]):
        if not isinstance(observation, dict):
            continue
        metric = observation.get("metric_code")
        unit = observation.get("unit")
        if not isinstance(metric, str) or not metric or not isinstance(unit, str):
            continue
        number = finite_decimal(
            observation.get("value"), f"$.draft.observations[{index}].value"
        )
        item = groups.setdefault(
            (metric, unit),
            {
                "metric_code": metric,
                "unit": unit,
                "count": 0,
                "total": Decimal(0),
                "minimum": number,
                "maximum": number,
                "observation_ids": [],
            },
        )
        item["count"] += 1
        item["total"] += number
        item["minimum"] = min(item["minimum"], number)
        item["maximum"] = max(item["maximum"], number)
        item["observation_ids"].append(str(observation.get("observation_id", "")))
    metrics = []
    for _key, item in sorted(groups.items()):
        ids, id_count, ids_truncated, ids_sha256 = _bounded_details(
            item["observation_ids"]
        )
        metrics.append(
            {
                **{key: item[key] for key in ("metric_code", "unit", "count")},
                "total": json_number(item["total"]),
                "minimum": json_number(item["minimum"]),
                "maximum": json_number(item["maximum"]),
                "observation_ids": ids,
                "observation_id_count": id_count,
                "observation_ids_truncated": ids_truncated,
                "observation_ids_sha256": ids_sha256,
            }
        )
    returned_metrics, metric_group_count, metric_groups_truncated, groups_sha256 = (
        _bounded_details(metrics)
    )
    data = {
        "draft_id": value["draft_id"],
        "revision": int(value["_meta"]["revision"]),
        "status": str(value["status"]),
        "mine_id": str(value.get("mine_id", "")),
        "window_start": str(value.get("window_start", "")),
        "window_end": str(value.get("window_end", "")),
        "observation_count": len(value["observations"]),
        "metric_groups": returned_metrics,
        "metric_group_count": metric_group_count,
        "returned_metric_group_count": len(returned_metrics),
        "metric_groups_truncated": metric_groups_truncated,
        "metric_groups_sha256": groups_sha256,
        "document_sha256": sha256_json(public_document(value)),
        "uncertainty": {
            "aggregation": "仅对相同指标和完全相同单位求和，未进行口径推断",
            "mixed_units_separated": True,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"草稿含 {len(value['observations'])} 条观测、"
            f"{metric_group_count} 个指标单位组。"
        ),
    )


def _deterministic_preflight(
    arguments: Mapping[str, Any], context: ToolContext
) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    checked = validate_draft(public_document(value))
    all_issues = [
        {
            "code": str(item.get("code", "")),
            "path": str(item.get("path", "")),
            "message": str(item.get("message", "")),
            "severity": str(item.get("severity", "")),
        }
        for item in checked["issues"]
    ]
    issues, issue_count, issues_truncated, issues_sha256 = _bounded_details(
        all_issues, _MAX_RETURNED_ISSUES
    )
    business_checks = [
        {
            "code": str(item.get("code", "")),
            "status": str(item.get("status", "")),
            "message": str(item.get("message", "")),
            "residual": (
                item["residual"]
                if isinstance(item.get("residual"), (int, float))
                and not isinstance(item.get("residual"), bool)
                and math.isfinite(float(item["residual"]))
                else None
            ),
            "relative_gap": (
                item["relative_gap"]
                if isinstance(item.get("relative_gap"), (int, float))
                and not isinstance(item.get("relative_gap"), bool)
                and math.isfinite(float(item["relative_gap"]))
                else None
            ),
        }
        for item in checked["business_checks"]
    ]
    data = {
        "draft_id": value["draft_id"],
        "revision": int(value["_meta"]["revision"]),
        "passes_structural_preflight": bool(checked["valid"]),
        "blocking_count": int(checked["blocking_count"]),
        "warning_count": int(checked["warning_count"]),
        "issues": issues,
        "issue_count": issue_count,
        "returned_issue_count": len(issues),
        "issues_truncated": issues_truncated,
        "issues_sha256": issues_sha256,
        "business_checks": business_checks,
        "uncertainty": {
            "not_checked": [
                "来源密钥真实性",
                "监管规则最终判定",
                "未提供的业务事实",
            ]
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"预检发现 {data['blocking_count']} 个阻断项、"
            f"{data['warning_count']} 个警告。"
        ),
    )


def _source_evidence_check(
    arguments: Mapping[str, Any], context: ToolContext
) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    provenance = value.get("field_provenance")
    if not isinstance(provenance, dict):
        provenance = {}
    records: list[dict[str, Any]] = []
    hash_matches = 0
    signatures_formatted = 0
    complete_provenance = 0
    critical = (
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
    )
    for index, observation in enumerate(value["observations"]):
        if not isinstance(observation, dict):
            continue
        digest = observation.get("payload_sha256")
        signature = observation.get("signature")
        try:
            expected = sha256_json(observation_payload(observation))
        except (KeyError, TypeError, ValueError):
            expected = None
        digest_format = isinstance(digest, str) and HEX64.fullmatch(digest) is not None
        digest_match = digest_format and expected is not None and digest == expected
        signature_format = (
            isinstance(signature, str) and HEX64.fullmatch(signature) is not None
        )
        paths_present = sum(
            1
            for field in critical
            if isinstance(provenance.get(f"/observations/{index}/{field}"), list)
            and bool(provenance[f"/observations/{index}/{field}"])
        )
        provenance_complete = paths_present == len(critical)
        hash_matches += int(digest_match)
        signatures_formatted += int(signature_format)
        complete_provenance += int(provenance_complete)
        records.append(
            {
                "observation_id": str(observation.get("observation_id", "")),
                "source_id": str(observation.get("source_id", "")),
                "payload_digest_format_valid": digest_format,
                "payload_digest_matches": digest_match,
                "signature_format_valid": signature_format,
                "signature_cryptographically_verified": False,
                "provenance_fields_present": paths_present,
                "provenance_fields_expected": len(critical),
                "provenance_complete": provenance_complete,
            }
        )
    total = len(records)
    returned_records, record_count, records_truncated, records_sha256 = (
        _bounded_details(records)
    )
    data = {
        "draft_id": value["draft_id"],
        "observation_count": total,
        "payload_digest_match_count": hash_matches,
        "signature_format_valid_count": signatures_formatted,
        "signature_cryptographically_verified": False,
        "provenance_complete_count": complete_provenance,
        "records": returned_records,
        "record_count": record_count,
        "returned_record_count": len(returned_records),
        "records_truncated": records_truncated,
        "records_sha256": records_sha256,
        "uncertainty": {
            "signature_verification": (
                "工具不持有来源网关密钥，只检查签名格式；密码学验签必须由"
                "受信任监管接入层执行"
            ),
            "metric_code_signed": False,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"{total} 条观测中 {hash_matches} 条载荷摘要匹配，"
            f"{signatures_formatted} 条签名格式正确；未执行密钥验签。"
        ),
    )


def _align_observation_time(
    arguments: Mapping[str, Any], context: ToolContext
) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    selected = arguments.get("metric_codes", [])
    selected_metrics = (
        set(
            bounded_strings(
                selected,
                path="$.metric_codes",
                maximum=128,
            )
        )
        if selected
        else None
    )
    bucket_seconds = int(arguments.get("bucket_seconds", 3600))
    tolerance_seconds = int(arguments.get("tolerance_seconds", 300))
    rows: list[dict[str, Any]] = []
    outside = 0
    delayed = 0
    window_start = parsed_time(value.get("window_start"), "$.draft.window_start")
    window_end = parsed_time(value.get("window_end"), "$.draft.window_end")
    for index, observation in enumerate(value["observations"]):
        if not isinstance(observation, dict):
            continue
        metric = observation.get("metric_code")
        if selected_metrics is not None and metric not in selected_metrics:
            continue
        observed = parsed_time(
            observation.get("observed_at"),
            f"$.draft.observations[{index}].observed_at",
        )
        received = parsed_time(
            observation.get("received_at"),
            f"$.draft.observations[{index}].received_at",
        )
        epoch = observed.timestamp()
        bucket_epoch = math.floor(epoch / bucket_seconds) * bucket_seconds
        bucket_start = datetime.fromtimestamp(bucket_epoch, UTC)
        offset = epoch - bucket_epoch
        nearest_boundary = min(offset, bucket_seconds - offset)
        in_window = window_start <= observed <= window_end
        delay = (received - observed).total_seconds()
        outside += int(not in_window)
        delayed += int(delay > tolerance_seconds)
        rows.append(
            {
                "observation_id": str(observation.get("observation_id", "")),
                "metric_code": str(metric or ""),
                "observed_at": observed.isoformat().replace("+00:00", "Z"),
                "bucket_start": bucket_start.isoformat().replace("+00:00", "Z"),
                "offset_seconds": offset,
                "nearest_boundary_seconds": nearest_boundary,
                "in_reporting_window": in_window,
                "receive_delay_seconds": delay,
                "delay_exceeds_tolerance": delay > tolerance_seconds,
            }
        )
    returned_rows, record_count, records_truncated, records_sha256 = (
        _bounded_details(rows)
    )
    data = {
        "draft_id": value["draft_id"],
        "bucket_seconds": bucket_seconds,
        "tolerance_seconds": tolerance_seconds,
        "aligned_count": len(rows),
        "outside_window_count": outside,
        "delayed_count": delayed,
        "records": returned_rows,
        "record_count": record_count,
        "returned_record_count": len(returned_rows),
        "records_truncated": records_truncated,
        "records_sha256": records_sha256,
        "uncertainty": {
            "clock_sync_not_verified": True,
            "boundary_rule": "UTC Unix 时间向下取整，窗口端点均包含",
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"对齐 {len(rows)} 条观测；{outside} 条不在报送窗口，"
            f"{delayed} 条接收延迟超过显式阈值。"
        ),
    )


def _convert_coal_units(
    arguments: Mapping[str, Any], _context: ToolContext
) -> ToolResult:
    value = finite_decimal(arguments["value"], "$.value")
    from_unit = str(arguments["from_unit"])
    to_unit = str(arguments["to_unit"])
    factor = conversion_factor(from_unit, to_unit)
    converted = convert(value, from_unit, to_unit, "$.value")
    dimension = (
        "mass"
        if from_unit in MASS_FACTORS_T and to_unit in MASS_FACTORS_T
        else "energy"
    )
    data = {
        "input_value": json_number(value),
        "from_unit": from_unit,
        "to_unit": to_unit,
        "dimension": dimension,
        "exact_factor": format(factor, "f"),
        "converted_value": json_number(converted),
        "uncertainty": {
            "conversion": "所列质量和 SI 能量单位采用精确定义换算，未包含测量误差"
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"{data['input_value']} {from_unit} = "
            f"{data['converted_value']} {to_unit}。"
        ),
    )


def _quantity(
    item: Mapping[str, Any], target_unit: str, path: str
) -> tuple[dict[str, Any], Decimal]:
    number = finite_decimal(item["value"], f"{path}.value", nonnegative=True)
    unit = str(item["unit"])
    converted = convert(number, unit, target_unit, f"{path}.value")
    return (
        {
            "evidence_id": str(item["evidence_id"]),
            "value": json_number(number),
            "unit": unit,
            "converted_value": json_number(converted),
        },
        converted,
    )


def _mass_balance(arguments: Mapping[str, Any], _context: ToolContext) -> ToolResult:
    target = str(arguments.get("target_unit", "t"))
    if target not in MASS_FACTORS_T:
        raise ToolProtocolError(
            "质量平衡目标单位必须是受支持的质量单位",
            code="invalid_mass_unit",
            path="$.target_unit",
        )
    evidence_ids = [
        str(arguments["opening"]["evidence_id"]),
        str(arguments["closing"]["evidence_id"]),
        *(str(item["evidence_id"]) for item in arguments["inflows"]),
        *(str(item["evidence_id"]) for item in arguments["outflows"]),
    ]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ToolProtocolError(
            "质量平衡中的 evidence_id 不能重复",
            code="duplicate_evidence_id",
            path="$",
        )
    opening_record, opening = _quantity(arguments["opening"], target, "$.opening")
    closing_record, closing = _quantity(arguments["closing"], target, "$.closing")
    inflow_records: list[dict[str, Any]] = []
    outflow_records: list[dict[str, Any]] = []
    inflow = Decimal(0)
    outflow = Decimal(0)
    for index, item in enumerate(arguments["inflows"]):
        record, number = _quantity(item, target, f"$.inflows[{index}]")
        inflow_records.append(record)
        inflow += number
    for index, item in enumerate(arguments["outflows"]):
        record, number = _quantity(item, target, f"$.outflows[{index}]")
        outflow_records.append(record)
        outflow += number
    residual = opening + inflow - outflow - closing
    throughput = max(opening + inflow, outflow + closing)
    relative = abs(residual) / throughput if throughput > 0 else None
    tolerance = finite_decimal(
        arguments.get("relative_tolerance", 0.05),
        "$.relative_tolerance",
        nonnegative=True,
    )
    within = relative is not None and relative <= tolerance
    returned_inflows, inflow_count, inflows_truncated, inflows_sha256 = (
        _bounded_details(inflow_records)
    )
    returned_outflows, outflow_count, outflows_truncated, outflows_sha256 = (
        _bounded_details(outflow_records)
    )
    data = {
        "target_unit": target,
        "opening": opening_record,
        "closing": closing_record,
        "inflows": returned_inflows,
        "outflows": returned_outflows,
        "inflow_count": inflow_count,
        "outflow_count": outflow_count,
        "inflows_truncated": inflows_truncated,
        "outflows_truncated": outflows_truncated,
        "inflows_sha256": inflows_sha256,
        "outflows_sha256": outflows_sha256,
        "total_inflows": json_number(inflow),
        "total_outflows": json_number(outflow),
        "residual": json_number(residual),
        "relative_gap": json_number(relative) if relative is not None else None,
        "relative_tolerance": json_number(tolerance),
        "within_supplied_tolerance": within,
        "uncertainty": {
            "measurement_uncertainty_included": False,
            "zero_throughput": throughput == 0,
            "formula": "opening + sum(inflows) - sum(outflows) - closing",
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"质量平衡差额 {data['residual']} {target}；"
            + (
                f"相对差额 {float(relative):.2%}。"
                if relative is not None
                else "零吞吐量，不能计算相对差额。"
            )
        ),
    )


def _coal_flow_component(
    value: Mapping[str, Any],
    label: str,
    aliases: Sequence[str],
) -> dict[str, Any] | None:
    for metric in aliases:
        total, unit, observation_ids = total_metric(value, metric)
        if total is not None and unit is not None:
            return {
                "label": label,
                "metric_code": metric,
                "value": total,
                "unit": unit,
                "observation_ids": observation_ids,
            }
    return None


def _coal_flow_balance(
    arguments: Mapping[str, Any], context: ToolContext
) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    tolerance = finite_decimal(
        arguments.get("relative_tolerance", 0.05),
        "$.relative_tolerance",
        nonnegative=True,
    )
    components = {
        "production": _coal_flow_component(
            value,
            "原煤产量",
            ("coal.reported_output_t", "coal.production_t"),
        ),
        "transport": _coal_flow_component(
            value, "主运输量", ("coal.main_transport_t",)
        ),
        "opening": _coal_flow_component(
            value, "期初库存", ("coal.opening_inventory_t",)
        ),
        "purchase": _coal_flow_component(
            value, "购入量", ("coal.purchase_in_t",)
        ),
        "sales": _coal_flow_component(
            value, "销售出库", ("sales.raw_shipped_t", "coal.sale_out_t")
        ),
        "processing": _coal_flow_component(
            value, "入洗加工", ("wash.feed_t", "coal.processing_input_t")
        ),
        "closing": _coal_flow_component(
            value, "期末库存", ("coal.closing_inventory_t",)
        ),
        "inventory_change": _coal_flow_component(
            value, "库存变化", ("inventory.raw_change_t",)
        ),
    }
    equations = (
        (
            "production_transport",
            "产量与主运输量",
            (("production", 1), ("transport", -1)),
        ),
        (
            "stock_flow",
            "库存收发存",
            (
                ("opening", 1),
                ("production", 1),
                ("purchase", 1),
                ("sales", -1),
                ("processing", -1),
                ("closing", -1),
            ),
        ),
        (
            "raw_coal_destination",
            "原煤去向",
            (
                ("production", 1),
                ("processing", -1),
                ("sales", -1),
                ("inventory_change", -1),
            ),
        ),
    )
    results: list[dict[str, Any]] = []
    for code, label, terms in equations:
        missing = [key for key, _sign in terms if components[key] is None]
        present = [
            (components[key], sign)
            for key, sign in terms
            if components[key] is not None
        ]
        units = {item["unit"] for item, _sign in present}
        evidence = []
        for key, sign in terms:
            if components[key] is None:
                continue
            ids, id_count, ids_truncated, ids_sha256 = _bounded_details(
                components[key]["observation_ids"]
            )
            evidence.append(
                {
                    "role": key,
                    "label": str(components[key]["label"]),
                    "metric_code": str(components[key]["metric_code"]),
                    "value": json_number(components[key]["value"]),
                    "unit": str(components[key]["unit"]),
                    "sign": sign,
                    "observation_ids": ids,
                    "observation_id_count": id_count,
                    "observation_ids_truncated": ids_truncated,
                    "observation_ids_sha256": ids_sha256,
                }
            )
        if missing:
            status = "not_evaluated"
            residual = relative = within = None
            reason = "缺少指标：" + "、".join(missing)
            unit = next(iter(units)) if len(units) == 1 else None
        elif len(units) != 1:
            status = "not_evaluated"
            residual = relative = within = None
            reason = "参与方程的指标单位不一致，未自动猜测换算"
            unit = None
        else:
            unit = next(iter(units))
            residual = sum(
                (item["value"] * Decimal(sign) for item, sign in present),
                Decimal(0),
            )
            scale = max(
                (abs(item["value"]) for item, _sign in present),
                default=Decimal(0),
            )
            relative = abs(residual) / scale if scale > 0 else None
            within = relative is not None and relative <= tolerance
            status = "within_tolerance" if within else "outside_tolerance"
            reason = (
                "差额在所示预检阈值内"
                if within
                else (
                    "所有参与量均为零，无法计算相对差额"
                    if relative is None
                    else "差额超过所示预检阈值"
                )
            )
        results.append(
            {
                "code": code,
                "label": label,
                "status": status,
                "unit": unit,
                "residual": (
                    json_number(residual) if residual is not None else None
                ),
                "relative_gap": (
                    json_number(relative) if relative is not None else None
                ),
                "within_tolerance": within,
                "missing_roles": missing,
                "evidence": evidence,
                "reason": reason,
            }
        )
    evaluated = sum(item["status"] != "not_evaluated" for item in results)
    outside = sum(item["status"] == "outside_tolerance" for item in results)
    data = {
        "draft_id": value["draft_id"],
        "revision": int(value["_meta"]["revision"]),
        "relative_tolerance": json_number(tolerance),
        "evaluated_equation_count": evaluated,
        "outside_tolerance_count": outside,
        "equations": results,
        "uncertainty": {
            "measurement_uncertainty_included": False,
            "metric_aliases_are_fixed": True,
            "automatic_unit_conversion": False,
            "threshold_is_preflight_only": True,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"三套煤流方程中已评价 {evaluated} 套，"
            f"{outside} 套超过所示预检阈值。"
        ),
    )


def _washing_yield(arguments: Mapping[str, Any], _context: ToolContext) -> ToolResult:
    target = str(arguments.get("target_unit", "t"))
    if target not in MASS_FACTORS_T:
        raise ToolProtocolError(
            "洗选产率目标单位必须是受支持的质量单位",
            code="invalid_mass_unit",
            path="$.target_unit",
        )
    evidence_ids = [
        str(arguments["feed"]["evidence_id"]),
        *(str(item["evidence_id"]) for item in arguments["products"]),
    ]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ToolProtocolError(
            "洗选产率中的 evidence_id 不能重复",
            code="duplicate_evidence_id",
            path="$",
        )
    feed_record, feed = _quantity(arguments["feed"], target, "$.feed")
    if feed <= 0:
        raise ToolProtocolError(
            "入洗量必须大于零", code="zero_feed", path="$.feed.value"
        )
    products: list[dict[str, Any]] = []
    totals: dict[str, Decimal] = {
        "clean": Decimal(0),
        "middlings": Decimal(0),
        "gangue": Decimal(0),
        "other": Decimal(0),
    }
    for index, item in enumerate(arguments["products"]):
        record, number = _quantity(item, target, f"$.products[{index}]")
        kind = str(item["kind"])
        totals[kind] += number
        products.append({**record, "kind": kind})
    product_total = sum(totals.values(), Decimal(0))
    residual = feed - product_total
    total_recovery = product_total / feed
    clean_yield = totals["clean"] / feed
    tolerance = finite_decimal(
        arguments.get("relative_tolerance", 0.05),
        "$.relative_tolerance",
        nonnegative=True,
    )
    relative_gap = abs(residual) / feed
    returned_products, product_count, products_truncated, products_sha256 = (
        _bounded_details(products)
    )
    data = {
        "target_unit": target,
        "feed": feed_record,
        "products": returned_products,
        "product_count": product_count,
        "products_truncated": products_truncated,
        "products_sha256": products_sha256,
        "product_totals": {
            key: json_number(number) for key, number in totals.items()
        },
        "total_products": json_number(product_total),
        "clean_coal_yield": json_number(clean_yield),
        "total_recovery": json_number(total_recovery),
        "mass_residual": json_number(residual),
        "relative_gap": json_number(relative_gap),
        "relative_tolerance": json_number(tolerance),
        "within_supplied_tolerance": relative_gap <= tolerance,
        "uncertainty": {
            "quality_adjustment_included": False,
            "moisture_basis_aligned": False,
            "measurement_uncertainty_included": False,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"精煤产率 {float(clean_yield):.2%}，产品总回收率 "
            f"{float(total_recovery):.2%}，质量差额 {data['mass_residual']} {target}。"
        ),
    )


def _history_rows(
    context: ToolContext,
    current: Mapping[str, Any],
    metric_code: str,
    maximum: int,
    context_match: bool,
) -> list[dict[str, Any]]:
    repo = repository(context)
    target_start = parsed_time(current.get("window_start"), "$.draft.window_start")
    history_reader = getattr(repo, "historical_observations", None)
    if callable(history_reader):
        raw_rows = history_reader(
            mine_id=str(current.get("mine_id", "")),
            metric_code=metric_code,
            exclude_draft_id=str(current.get("draft_id", "")),
            before_window_start=str(current.get("window_start", "")),
            limit=min(maximum, 500),
        )
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for row in raw_rows:
            if not isinstance(row, Mapping):
                continue
            draft_id = row.get("draft_id")
            if isinstance(draft_id, str) and draft_id:
                grouped.setdefault(draft_id, []).append(row)
        results: list[dict[str, Any]] = []
        current_context = current.get("operational_context")
        for candidate_id, rows in grouped.items():
            candidate_end = None
            try:
                candidate_end = parsed_time(
                    rows[0].get("window_end"), "$.history.window_end"
                )
            except ToolProtocolError:
                continue
            if candidate_end >= target_start:
                continue
            if context_match:
                candidate_context = rows[0].get("operational_context")
                if not isinstance(candidate_context, dict) or not isinstance(
                    current_context, dict
                ):
                    continue
                if (
                    rows[0].get("profile_id") != current.get("profile_id")
                    or rows[0].get("profile_version")
                    != current.get("profile_version")
                ):
                    continue
                if any(
                    candidate_context.get(key) != current_context.get(key)
                    for key in (
                        "regime_code",
                        "shift_code",
                        "season_code",
                        "maintenance",
                    )
                ):
                    continue
            units = {
                str(row.get("unit"))
                for row in rows
                if isinstance(row.get("unit"), str) and row.get("unit")
            }
            if len(units) != 1:
                continue
            numbers: list[Decimal] = []
            observation_ids: list[str] = []
            for row in rows:
                try:
                    numbers.append(
                        finite_decimal(row.get("value"), "$.history.value")
                    )
                except ToolProtocolError:
                    numbers = []
                    break
                observation_ids.append(str(row.get("observation_id", "")))
            if not numbers:
                continue
            results.append(
                {
                    "draft_id": candidate_id,
                    "window_end": candidate_end,
                    "value": sum(numbers, Decimal(0)),
                    "unit": next(iter(units)),
                    "observation_ids": observation_ids,
                }
            )
            if len(results) >= maximum:
                break
        return results

    candidates = repo.list_drafts(
        include_deleted=False,
        limit=min(maximum + 1, context.max_history_drafts),
        offset=0,
    )
    results: list[dict[str, Any]] = []
    current_context = current.get("operational_context")
    for candidate in candidates:
        if candidate.get("draft_id") == current.get("draft_id"):
            continue
        if candidate.get("status") != "submitted":
            continue
        if candidate.get("mine_id") != current.get("mine_id"):
            continue
        try:
            candidate_end = parsed_time(
                candidate.get("window_end"), "$.history.window_end"
            )
        except ToolProtocolError:
            continue
        if candidate_end >= target_start:
            continue
        if context_match:
            candidate_context = candidate.get("operational_context")
            if not isinstance(candidate_context, dict) or not isinstance(
                current_context, dict
            ):
                continue
            if any(
                candidate_context.get(key) != current_context.get(key)
                for key in ("regime_code", "shift_code", "season_code", "maintenance")
            ):
                continue
            if (
                candidate.get("profile_id") != current.get("profile_id")
                or candidate.get("profile_version") != current.get("profile_version")
            ):
                continue
        total, unit, observation_ids = total_metric(candidate, metric_code)
        if total is None or unit is None:
            continue
        results.append(
            {
                "draft_id": str(candidate.get("draft_id", "")),
                "window_end": candidate_end,
                "value": total,
                "unit": unit,
                "observation_ids": observation_ids,
            }
        )
        if len(results) >= maximum:
            break
    return results


def _historical_baseline_data(
    arguments: Mapping[str, Any],
    context: ToolContext,
) -> dict[str, Any]:
    current = draft(context, str(arguments["draft_id"]))
    metric = str(arguments["metric_code"])
    minimum = int(arguments.get("min_history", 5))
    maximum = int(arguments.get("max_history", 500))
    if maximum < minimum:
        raise ToolProtocolError(
            "max_history 不能小于 min_history",
            code="invalid_history_bounds",
            path="$.max_history",
        )
    context_match = bool(arguments.get("context_match", True))
    current_total, current_unit, current_ids = total_metric(current, metric)
    history = _history_rows(context, current, metric, maximum, context_match)
    if current_total is None or current_unit is None:
        return {
            "draft_id": current["draft_id"],
            "metric_code": metric,
            "status": "current_metric_missing",
            "unit": None,
            "current_value": None,
            "sample_size": 0,
            "minimum_history": minimum,
            "median": None,
            "mad": None,
            "q05": None,
            "q25": None,
            "q75": None,
            "q95": None,
            "robust_z": None,
            "current_observation_ids": [],
            "current_observation_id_count": 0,
            "current_observation_ids_truncated": False,
            "current_observation_ids_sha256": sha256_json([]),
            "history_draft_ids": [],
            "history_draft_id_count": 0,
            "history_draft_ids_truncated": False,
            "history_draft_ids_sha256": sha256_json([]),
            "excluded_mixed_unit_count": 0,
            "context_matched": context_match,
            "profile_compatibility_required": context_match,
            "uncertainty": {
                "reason": "当前草稿没有该指标",
                "future_data_excluded": True,
                "only_succeeded_submissions": True,
                "history_query_limit": maximum,
                "complete_history_guaranteed": False,
            },
            "disclaimer": disclaimer(),
        }
    compatible = [row for row in history if row["unit"] == current_unit]
    excluded = len(history) - len(compatible)
    values = [row["value"] for row in compatible]
    if len(values) < minimum:
        status = "insufficient_history"
        middle = dispersion = q05 = q25 = q75 = q95 = robust_z = None
    else:
        status = "evaluated"
        middle = decimal_median(values)
        dispersion = mad(values, middle)
        q05 = percentile(values, Decimal("0.05"))
        q25 = percentile(values, Decimal("0.25"))
        q75 = percentile(values, Decimal("0.75"))
        q95 = percentile(values, Decimal("0.95"))
        robust_scale = Decimal("1.4826") * dispersion
        robust_z = (
            (current_total - middle) / robust_scale if robust_scale > 0 else None
        )
    returned_current_ids, current_id_count, current_ids_truncated, current_ids_hash = (
        _bounded_details(current_ids)
    )
    all_history_ids = [row["draft_id"] for row in compatible]
    returned_history_ids, history_id_count, history_ids_truncated, history_ids_hash = (
        _bounded_details(all_history_ids)
    )
    return {
        "draft_id": current["draft_id"],
        "metric_code": metric,
        "status": status,
        "unit": current_unit,
        "current_value": json_number(current_total),
        "sample_size": len(values),
        "minimum_history": minimum,
        "median": json_number(middle) if middle is not None else None,
        "mad": json_number(dispersion) if dispersion is not None else None,
        "q05": json_number(q05) if q05 is not None else None,
        "q25": json_number(q25) if q25 is not None else None,
        "q75": json_number(q75) if q75 is not None else None,
        "q95": json_number(q95) if q95 is not None else None,
        "robust_z": json_number(robust_z) if robust_z is not None else None,
        "current_observation_ids": returned_current_ids,
        "current_observation_id_count": current_id_count,
        "current_observation_ids_truncated": current_ids_truncated,
        "current_observation_ids_sha256": current_ids_hash,
        "history_draft_ids": returned_history_ids,
        "history_draft_id_count": history_id_count,
        "history_draft_ids_truncated": history_ids_truncated,
        "history_draft_ids_sha256": history_ids_hash,
        "excluded_mixed_unit_count": excluded,
        "context_matched": context_match,
        "profile_compatibility_required": context_match,
        "uncertainty": {
            "reason": (
                "MAD 为零，无法给出稳健 z 值"
                if status == "evaluated" and robust_z is None
                else (
                    "历史样本不足"
                    if status == "insufficient_history"
                    else "分位数和 MAD 只描述已提交历史，不代表未来分布"
                )
            ),
            "future_data_excluded": True,
            "only_succeeded_submissions": True,
            "history_query_limit": maximum,
            "complete_history_guaranteed": False,
        },
        "disclaimer": disclaimer(),
    }


def _historical_robust_baseline(
    arguments: Mapping[str, Any], context: ToolContext
) -> ToolResult:
    data = _historical_baseline_data(arguments, context)
    return ToolResult(
        data=data,
        summary=(
            f"历史基线状态：{data['status']}；可比成功提交样本 "
            f"{data['sample_size']} 个。"
        ),
    )


def _ordered_series(
    value: Mapping[str, Any], metric_code: str
) -> tuple[list[Decimal], list[str], str | None]:
    rows = observation_values(value, metric_code)
    parsed: list[tuple[datetime, Decimal, str, str]] = []
    for index, (observation, number) in enumerate(rows):
        timestamp = parsed_time(
            observation.get("observed_at"),
            f"$.draft.metric_observations[{index}].observed_at",
        )
        parsed.append(
            (
                timestamp,
                number,
                str(observation.get("observation_id", "")),
                str(observation.get("unit", "")),
            )
        )
    parsed.sort(key=lambda item: (item[0], item[2]))
    units = {item[3] for item in parsed}
    if len(units) > 1:
        raise ToolProtocolError(
            "同一时间序列存在多个单位",
            code="mixed_metric_units",
            path="$.metric_code",
        )
    return (
        [item[1] for item in parsed],
        [item[2] for item in parsed],
        next(iter(units)) if units else None,
    )


def _sensor_drift_data(
    arguments: Mapping[str, Any], context: ToolContext
) -> dict[str, Any]:
    value = draft(context, str(arguments["draft_id"]))
    metric = str(arguments["metric_code"])
    values, ids, unit = _ordered_series(value, metric)
    minimum = int(arguments.get("min_points", 8))
    if len(values) < minimum:
        status = "insufficient_points"
        window_size = 0
        early = late = drift = relative = early_mad = late_mad = None
    else:
        status = "evaluated"
        window_size = max(3, len(values) // 4)
        early_values = values[:window_size]
        late_values = values[-window_size:]
        early = decimal_median(early_values)
        late = decimal_median(late_values)
        drift = late - early
        denominator = abs(early)
        relative = drift / denominator if denominator > 0 else None
        early_mad = mad(early_values, early)
        late_mad = mad(late_values, late)
    returned_ids, id_count, ids_truncated, ids_sha256 = _bounded_details(ids)
    return {
        "draft_id": value["draft_id"],
        "metric_code": metric,
        "status": status,
        "unit": unit,
        "point_count": len(values),
        "minimum_points": minimum,
        "window_size": window_size,
        "early_median": json_number(early) if early is not None else None,
        "late_median": json_number(late) if late is not None else None,
        "absolute_drift": json_number(drift) if drift is not None else None,
        "relative_drift": json_number(relative) if relative is not None else None,
        "early_mad": json_number(early_mad) if early_mad is not None else None,
        "late_mad": json_number(late_mad) if late_mad is not None else None,
        "observation_ids": returned_ids,
        "observation_id_count": id_count,
        "observation_ids_truncated": ids_truncated,
        "observation_ids_sha256": ids_sha256,
        "uncertainty": {
            "reason": (
                "时间序列点数不足"
                if status == "insufficient_points"
                else (
                    "早段中位数为零，无法计算相对漂移"
                    if relative is None
                    else "早末窗口中位数差不能区分传感器漂移与真实工况变化"
                )
            ),
            "causality_determined": False,
        },
        "disclaimer": disclaimer(),
    }


def _sensor_drift(arguments: Mapping[str, Any], context: ToolContext) -> ToolResult:
    data = _sensor_drift_data(arguments, context)
    return ToolResult(
        data=data,
        summary=(
            f"漂移检查状态：{data['status']}；共 {data['point_count']} 个时序点。"
        ),
    )


def _change_point_data(
    arguments: Mapping[str, Any], context: ToolContext
) -> dict[str, Any]:
    value = draft(context, str(arguments["draft_id"]))
    metric = str(arguments["metric_code"])
    values, ids, unit = _ordered_series(value, metric)
    minimum_segment = int(arguments.get("min_segment_points", 3))
    if len(values) < minimum_segment * 2:
        status = "insufficient_points"
        best_index = None
        left_mean = right_mean = gap = normalized = left_mad = right_mad = None
    else:
        prefix = [Decimal(0)]
        for number in values:
            prefix.append(prefix[-1] + number)
        center = decimal_median(values)
        scale = Decimal("1.4826") * mad(values, center)
        best_index = minimum_segment
        best_gap = Decimal(-1)
        best_left = best_right = Decimal(0)
        for split in range(minimum_segment, len(values) - minimum_segment + 1):
            left = prefix[split] / Decimal(split)
            right = (prefix[-1] - prefix[split]) / Decimal(len(values) - split)
            candidate_gap = abs(left - right)
            if candidate_gap > best_gap:
                best_index = split
                best_gap = candidate_gap
                best_left = left
                best_right = right
        status = "candidate_found"
        left_mean = best_left
        right_mean = best_right
        gap = best_right - best_left
        normalized = abs(gap) / scale if scale > 0 else None
        left_mad = mad(values[:best_index])
        right_mad = mad(values[best_index:])
    returned_ids, id_count, ids_truncated, ids_sha256 = _bounded_details(ids)
    return {
        "draft_id": value["draft_id"],
        "metric_code": metric,
        "status": status,
        "unit": unit,
        "point_count": len(values),
        "minimum_segment_points": minimum_segment,
        "split_index": best_index,
        "first_right_observation_id": (
            ids[best_index]
            if best_index is not None and best_index < len(ids)
            else None
        ),
        "left_mean": json_number(left_mean) if left_mean is not None else None,
        "right_mean": json_number(right_mean) if right_mean is not None else None,
        "signed_gap": json_number(gap) if gap is not None else None,
        "normalized_gap": (
            json_number(normalized) if normalized is not None else None
        ),
        "left_mad": json_number(left_mad) if left_mad is not None else None,
        "right_mad": json_number(right_mad) if right_mad is not None else None,
        "observation_ids": returned_ids,
        "observation_id_count": id_count,
        "observation_ids_truncated": ids_truncated,
        "observation_ids_sha256": ids_sha256,
        "uncertainty": {
            "reason": (
                "每侧时序点不足"
                if status == "insufficient_points"
                else (
                    "全序列 MAD 为零，无法标准化候选差异"
                    if normalized is None
                    else "返回最大均值分段差候选，未计算统计显著性或因果"
                )
            ),
            "multiple_testing_adjusted": False,
            "causality_determined": False,
        },
        "disclaimer": disclaimer(),
    }


def _detect_change_point(
    arguments: Mapping[str, Any], context: ToolContext
) -> ToolResult:
    data = _change_point_data(arguments, context)
    return ToolResult(
        data=data,
        summary=(
            f"变化点检查状态：{data['status']}；候选分割位置 "
            f"{data['split_index']}。"
        ),
    )


def _cross_validation_explanation(
    arguments: Mapping[str, Any], context: ToolContext
) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    metrics = bounded_strings(
        arguments["metric_codes"],
        path="$.metric_codes",
        maximum=8,
    )
    checked = validate_draft(public_document(value))
    evidence = _source_evidence_check(arguments, context).data
    flow = _coal_flow_balance(
        {
            "draft_id": value["draft_id"],
            "relative_tolerance": 0.05,
        },
        context,
    ).data
    components: list[dict[str, Any]] = []
    for check in flow["equations"]:
        components.append(
            {
                "component": f"physical:{check['code']}",
                "status": str(check["status"]),
                "summary": (
                    f"{check['label']}：{check['reason']}；"
                    f"差额 {check['residual']} {check['unit'] or ''}"
                ),
                "evidence_count": sum(
                    len(item["observation_ids"]) for item in check["evidence"]
                ),
                "uncertainty": "缺失指标时不评价；固定 5% 仅为企业端预检阈值",
            }
        )
    for metric in metrics:
        base_args = {
            "draft_id": value["draft_id"],
            "metric_code": metric,
            "min_history": int(arguments.get("min_history", 5)),
            "max_history": int(arguments.get("max_history", 500)),
            "context_match": bool(arguments.get("context_match", True)),
        }
        baseline = _historical_baseline_data(base_args, context)
        drift_data = _sensor_drift_data(
            {
                "draft_id": value["draft_id"],
                "metric_code": metric,
                "min_points": int(arguments.get("min_points", 8)),
            },
            context,
        )
        change_data = _change_point_data(
            {
                "draft_id": value["draft_id"],
                "metric_code": metric,
                "min_segment_points": int(
                    arguments.get("min_segment_points", 3)
                ),
            },
            context,
        )
        baseline_status = str(baseline["status"])
        if baseline_status == "evaluated":
            baseline_summary = (
                f"当前值 {baseline['current_value']} {baseline['unit']}，"
                f"历史中位数 {baseline['median']}，稳健 z={baseline['robust_z']}"
            )
        else:
            baseline_summary = f"历史基线未充分评价：{baseline_status}"
        components.extend(
            [
                {
                    "component": f"history:{metric}",
                    "status": baseline_status,
                    "summary": baseline_summary,
                    "evidence_count": int(baseline["sample_size"]),
                    "uncertainty": str(baseline["uncertainty"]["reason"]),
                },
                {
                    "component": f"drift:{metric}",
                    "status": str(drift_data["status"]),
                    "summary": (
                        f"早末窗口绝对变化 {drift_data['absolute_drift']} "
                        f"{drift_data['unit'] or ''}"
                    ),
                    "evidence_count": int(drift_data["point_count"]),
                    "uncertainty": str(drift_data["uncertainty"]["reason"]),
                },
                {
                    "component": f"change_point:{metric}",
                    "status": str(change_data["status"]),
                    "summary": (
                        f"最大分段均值差候选 {change_data['signed_gap']} "
                        f"{change_data['unit'] or ''}"
                    ),
                    "evidence_count": int(change_data["point_count"]),
                    "uncertainty": str(change_data["uncertainty"]["reason"]),
                },
            ]
        )
    blocking = int(checked["blocking_count"])
    warnings = int(checked["warning_count"])
    incomplete = sum(
        item["status"]
        in {
            "not_evaluated",
            "insufficient_history",
            "insufficient_points",
            "current_metric_missing",
        }
        for item in components
    )
    if blocking:
        attention = "blocking_data_quality"
    elif warnings:
        attention = "review_preflight_warnings"
    elif incomplete:
        attention = "insufficient_evidence"
    else:
        attention = "no_warning_in_evaluated_components"
    data = {
        "draft_id": value["draft_id"],
        "revision": int(value["_meta"]["revision"]),
        "attention": attention,
        "blocking_count": blocking,
        "warning_count": warnings,
        "incomplete_component_count": incomplete,
        "payload_digest_match_count": int(evidence["payload_digest_match_count"]),
        "signature_format_valid_count": int(
            evidence["signature_format_valid_count"]
        ),
        "signature_cryptographically_verified": False,
        "components": components,
        "uncertainty": {
            "fusion": (
                "各组件并列展示，未用主观权重合成风险概率；"
                "历史只使用当前统计窗口之前的成功提交草稿"
            ),
            "legal_conclusion": False,
            "causality_determined": False,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"交叉核对关注状态：{attention}；"
            f"{len(components)} 个组件中 {incomplete} 个证据不足。"
        ),
    )


def _schemas() -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    issue = strict_object(
        {
            "code": {"type": "string"},
            "path": {"type": "string"},
            "message": {"type": "string"},
            "severity": {"type": "string"},
        },
        required=("code", "path", "message", "severity"),
    )
    business = strict_object(
        {
            "code": {"type": "string"},
            "status": {"type": "string"},
            "message": {"type": "string"},
            "residual": _NULLABLE_NUMBER,
            "relative_gap": _NULLABLE_NUMBER,
        },
        required=("code", "status", "message", "residual", "relative_gap"),
    )
    quantity_input = strict_object(
        {"evidence_id": _ID, "value": _NONNEGATIVE, "unit": _UNIT},
        required=("evidence_id", "value", "unit"),
    )
    quantity_output = strict_object(
        {
            "evidence_id": {"type": "string"},
            "value": {"type": "number"},
            "unit": {"type": "string"},
            "converted_value": {"type": "number"},
        },
        required=("evidence_id", "value", "unit", "converted_value"),
    )
    baseline_output = strict_object(
        {
            "draft_id": {"type": "string"},
            "metric_code": {"type": "string"},
            "status": {"type": "string"},
            "unit": {"type": ["string", "null"]},
            "current_value": _NULLABLE_NUMBER,
            "sample_size": {"type": "integer"},
            "minimum_history": {"type": "integer"},
            "median": _NULLABLE_NUMBER,
            "mad": _NULLABLE_NUMBER,
            "q05": _NULLABLE_NUMBER,
            "q25": _NULLABLE_NUMBER,
            "q75": _NULLABLE_NUMBER,
            "q95": _NULLABLE_NUMBER,
            "robust_z": _NULLABLE_NUMBER,
            "current_observation_ids": _STRING_ARRAY,
            "current_observation_id_count": {"type": "integer"},
            "current_observation_ids_truncated": {"type": "boolean"},
            "current_observation_ids_sha256": {
                "type": "string",
                "pattern": r"[0-9a-f]{64}",
            },
            "history_draft_ids": _STRING_ARRAY,
            "history_draft_id_count": {"type": "integer"},
            "history_draft_ids_truncated": {"type": "boolean"},
            "history_draft_ids_sha256": {
                "type": "string",
                "pattern": r"[0-9a-f]{64}",
            },
            "excluded_mixed_unit_count": {"type": "integer"},
            "context_matched": {"type": "boolean"},
            "profile_compatibility_required": {"type": "boolean"},
            "uncertainty": strict_object(
                {
                    "reason": {"type": "string"},
                    "future_data_excluded": {"type": "boolean"},
                    "only_succeeded_submissions": {"type": "boolean"},
                    "history_query_limit": {"type": "integer"},
                    "complete_history_guaranteed": {"type": "boolean"},
                },
                required=(
                    "reason",
                    "future_data_excluded",
                    "only_succeeded_submissions",
                    "history_query_limit",
                    "complete_history_guaranteed",
                ),
            ),
            "disclaimer": _DISCLAIMER,
        },
        required=(
            "draft_id",
            "metric_code",
            "status",
            "unit",
            "current_value",
            "sample_size",
            "minimum_history",
            "median",
            "mad",
            "q05",
            "q25",
            "q75",
            "q95",
            "robust_z",
            "current_observation_ids",
            "current_observation_id_count",
            "current_observation_ids_truncated",
            "current_observation_ids_sha256",
            "history_draft_ids",
            "history_draft_id_count",
            "history_draft_ids_truncated",
            "history_draft_ids_sha256",
            "excluded_mixed_unit_count",
            "context_matched",
            "profile_compatibility_required",
            "uncertainty",
            "disclaimer",
        ),
    )
    series_output = {
        "common": {
            "draft_id": {"type": "string"},
            "metric_code": {"type": "string"},
            "status": {"type": "string"},
            "unit": {"type": ["string", "null"]},
            "point_count": {"type": "integer"},
            "observation_ids": _STRING_ARRAY,
            "observation_id_count": {"type": "integer"},
            "observation_ids_truncated": {"type": "boolean"},
            "observation_ids_sha256": {
                "type": "string",
                "pattern": r"[0-9a-f]{64}",
            },
            "disclaimer": _DISCLAIMER,
        }
    }
    schemas: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    schemas["draft_summary"] = (
        strict_object({"draft_id": _ID}, required=("draft_id",)),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "revision": {"type": "integer"},
                "status": {"type": "string"},
                "mine_id": {"type": "string"},
                "window_start": {"type": "string"},
                "window_end": {"type": "string"},
                "observation_count": {"type": "integer"},
                "metric_groups": {
                    "type": "array",
                    "maxItems": 10_000,
                    "items": strict_object(
                        {
                            "metric_code": {"type": "string"},
                            "unit": {"type": "string"},
                            "count": {"type": "integer"},
                            "total": {"type": "number"},
                            "minimum": {"type": "number"},
                            "maximum": {"type": "number"},
                            "observation_ids": _STRING_ARRAY,
                            "observation_id_count": {"type": "integer"},
                            "observation_ids_truncated": {"type": "boolean"},
                            "observation_ids_sha256": {
                                "type": "string",
                                "pattern": r"[0-9a-f]{64}",
                            },
                        },
                        required=(
                            "metric_code",
                            "unit",
                            "count",
                            "total",
                            "minimum",
                            "maximum",
                            "observation_ids",
                            "observation_id_count",
                            "observation_ids_truncated",
                            "observation_ids_sha256",
                        ),
                    ),
                },
                "metric_group_count": {"type": "integer"},
                "returned_metric_group_count": {"type": "integer"},
                "metric_groups_truncated": {"type": "boolean"},
                "metric_groups_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "document_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "uncertainty": strict_object(
                    {
                        "aggregation": {"type": "string"},
                        "mixed_units_separated": {"type": "boolean"},
                    },
                    required=("aggregation", "mixed_units_separated"),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "revision",
                "status",
                "mine_id",
                "window_start",
                "window_end",
                "observation_count",
                "metric_groups",
                "metric_group_count",
                "returned_metric_group_count",
                "metric_groups_truncated",
                "metric_groups_sha256",
                "document_sha256",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    schemas["deterministic_preflight"] = (
        strict_object({"draft_id": _ID}, required=("draft_id",)),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "revision": {"type": "integer"},
                "passes_structural_preflight": {"type": "boolean"},
                "blocking_count": {"type": "integer"},
                "warning_count": {"type": "integer"},
                "issues": {
                    "type": "array",
                    "maxItems": 200_000,
                    "items": issue,
                },
                "issue_count": {"type": "integer"},
                "returned_issue_count": {"type": "integer"},
                "issues_truncated": {"type": "boolean"},
                "issues_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "business_checks": {
                    "type": "array",
                    "maxItems": 128,
                    "items": business,
                },
                "uncertainty": strict_object(
                    {
                        "not_checked": {
                            "type": "array",
                            "items": {"type": "string"},
                        }
                    },
                    required=("not_checked",),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "revision",
                "passes_structural_preflight",
                "blocking_count",
                "warning_count",
                "issues",
                "issue_count",
                "returned_issue_count",
                "issues_truncated",
                "issues_sha256",
                "business_checks",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    evidence_record = strict_object(
        {
            "observation_id": {"type": "string"},
            "source_id": {"type": "string"},
            "payload_digest_format_valid": {"type": "boolean"},
            "payload_digest_matches": {"type": "boolean"},
            "signature_format_valid": {"type": "boolean"},
            "signature_cryptographically_verified": {"type": "boolean"},
            "provenance_fields_present": {"type": "integer"},
            "provenance_fields_expected": {"type": "integer"},
            "provenance_complete": {"type": "boolean"},
        },
        required=(
            "observation_id",
            "source_id",
            "payload_digest_format_valid",
            "payload_digest_matches",
            "signature_format_valid",
            "signature_cryptographically_verified",
            "provenance_fields_present",
            "provenance_fields_expected",
            "provenance_complete",
        ),
    )
    schemas["source_evidence_check"] = (
        strict_object({"draft_id": _ID}, required=("draft_id",)),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "observation_count": {"type": "integer"},
                "payload_digest_match_count": {"type": "integer"},
                "signature_format_valid_count": {"type": "integer"},
                "signature_cryptographically_verified": {"type": "boolean"},
                "provenance_complete_count": {"type": "integer"},
                "records": {
                    "type": "array",
                    "maxItems": 10_000,
                    "items": evidence_record,
                },
                "record_count": {"type": "integer"},
                "returned_record_count": {"type": "integer"},
                "records_truncated": {"type": "boolean"},
                "records_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "uncertainty": strict_object(
                    {
                        "signature_verification": {"type": "string"},
                        "metric_code_signed": {"type": "boolean"},
                    },
                    required=("signature_verification", "metric_code_signed"),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "observation_count",
                "payload_digest_match_count",
                "signature_format_valid_count",
                "signature_cryptographically_verified",
                "provenance_complete_count",
                "records",
                "record_count",
                "returned_record_count",
                "records_truncated",
                "records_sha256",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    schemas["align_observation_time"] = (
        strict_object(
            {
                "draft_id": _ID,
                "metric_codes": {
                    "type": "array",
                    "maxItems": 128,
                    "uniqueItems": True,
                    "items": _METRIC,
                },
                "bucket_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 31_536_000,
                },
                "tolerance_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 31_536_000,
                },
            },
            required=("draft_id",),
        ),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "bucket_seconds": {"type": "integer"},
                "tolerance_seconds": {"type": "integer"},
                "aligned_count": {"type": "integer"},
                "outside_window_count": {"type": "integer"},
                "delayed_count": {"type": "integer"},
                "records": {
                    "type": "array",
                    "maxItems": 10_000,
                    "items": strict_object(
                        {
                            "observation_id": {"type": "string"},
                            "metric_code": {"type": "string"},
                            "observed_at": {"type": "string"},
                            "bucket_start": {"type": "string"},
                            "offset_seconds": {"type": "number"},
                            "nearest_boundary_seconds": {"type": "number"},
                            "in_reporting_window": {"type": "boolean"},
                            "receive_delay_seconds": {"type": "number"},
                            "delay_exceeds_tolerance": {"type": "boolean"},
                        },
                        required=(
                            "observation_id",
                            "metric_code",
                            "observed_at",
                            "bucket_start",
                            "offset_seconds",
                            "nearest_boundary_seconds",
                            "in_reporting_window",
                            "receive_delay_seconds",
                            "delay_exceeds_tolerance",
                        ),
                    ),
                },
                "record_count": {"type": "integer"},
                "returned_record_count": {"type": "integer"},
                "records_truncated": {"type": "boolean"},
                "records_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "uncertainty": strict_object(
                    {
                        "clock_sync_not_verified": {"type": "boolean"},
                        "boundary_rule": {"type": "string"},
                    },
                    required=("clock_sync_not_verified", "boundary_rule"),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "bucket_seconds",
                "tolerance_seconds",
                "aligned_count",
                "outside_window_count",
                "delayed_count",
                "records",
                "record_count",
                "returned_record_count",
                "records_truncated",
                "records_sha256",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    all_units = sorted({*MASS_FACTORS_T, *ENERGY_FACTORS_MJ})
    schemas["convert_coal_units"] = (
        strict_object(
            {
                "value": _NUMBER,
                "from_unit": {"type": "string", "enum": all_units},
                "to_unit": {"type": "string", "enum": all_units},
            },
            required=("value", "from_unit", "to_unit"),
        ),
        strict_object(
            {
                "input_value": {"type": "number"},
                "from_unit": {"type": "string"},
                "to_unit": {"type": "string"},
                "dimension": {"type": "string", "enum": ["mass", "energy"]},
                "exact_factor": {"type": "string"},
                "converted_value": {"type": "number"},
                "uncertainty": strict_object(
                    {"conversion": {"type": "string"}},
                    required=("conversion",),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "input_value",
                "from_unit",
                "to_unit",
                "dimension",
                "exact_factor",
                "converted_value",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    mass_units = sorted(MASS_FACTORS_T)
    schemas["calculate_mass_balance"] = (
        strict_object(
            {
                "opening": quantity_input,
                "closing": quantity_input,
                "inflows": {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": quantity_input,
                },
                "outflows": {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": quantity_input,
                },
                "target_unit": {"type": "string", "enum": mass_units},
                "relative_tolerance": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                },
            },
            required=("opening", "closing", "inflows", "outflows"),
        ),
        strict_object(
            {
                "target_unit": {"type": "string"},
                "opening": quantity_output,
                "closing": quantity_output,
                "inflows": {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": quantity_output,
                },
                "outflows": {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": quantity_output,
                },
                "inflow_count": {"type": "integer"},
                "outflow_count": {"type": "integer"},
                "inflows_truncated": {"type": "boolean"},
                "outflows_truncated": {"type": "boolean"},
                "inflows_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "outflows_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "total_inflows": {"type": "number"},
                "total_outflows": {"type": "number"},
                "residual": {"type": "number"},
                "relative_gap": _NULLABLE_NUMBER,
                "relative_tolerance": {"type": "number"},
                "within_supplied_tolerance": {"type": "boolean"},
                "uncertainty": strict_object(
                    {
                        "measurement_uncertainty_included": {"type": "boolean"},
                        "zero_throughput": {"type": "boolean"},
                        "formula": {"type": "string"},
                    },
                    required=(
                        "measurement_uncertainty_included",
                        "zero_throughput",
                        "formula",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "target_unit",
                "opening",
                "closing",
                "inflows",
                "outflows",
                "inflow_count",
                "outflow_count",
                "inflows_truncated",
                "outflows_truncated",
                "inflows_sha256",
                "outflows_sha256",
                "total_inflows",
                "total_outflows",
                "residual",
                "relative_gap",
                "relative_tolerance",
                "within_supplied_tolerance",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    coal_flow_evidence = strict_object(
        {
            "role": {"type": "string"},
            "label": {"type": "string"},
            "metric_code": {"type": "string"},
            "value": {"type": "number"},
            "unit": {"type": "string"},
            "sign": {"type": "integer", "enum": [-1, 1]},
            "observation_ids": _STRING_ARRAY,
            "observation_id_count": {"type": "integer"},
            "observation_ids_truncated": {"type": "boolean"},
            "observation_ids_sha256": {
                "type": "string",
                "pattern": r"[0-9a-f]{64}",
            },
        },
        required=(
            "role",
            "label",
            "metric_code",
            "value",
            "unit",
            "sign",
            "observation_ids",
            "observation_id_count",
            "observation_ids_truncated",
            "observation_ids_sha256",
        ),
    )
    coal_flow_equation = strict_object(
        {
            "code": {"type": "string"},
            "label": {"type": "string"},
            "status": {"type": "string"},
            "unit": {"type": ["string", "null"]},
            "residual": _NULLABLE_NUMBER,
            "relative_gap": _NULLABLE_NUMBER,
            "within_tolerance": {"type": ["boolean", "null"]},
            "missing_roles": {
                "type": "array",
                "maxItems": 8,
                "items": {"type": "string"},
            },
            "evidence": {
                "type": "array",
                "maxItems": 8,
                "items": coal_flow_evidence,
            },
            "reason": {"type": "string"},
        },
        required=(
            "code",
            "label",
            "status",
            "unit",
            "residual",
            "relative_gap",
            "within_tolerance",
            "missing_roles",
            "evidence",
            "reason",
        ),
    )
    schemas["calculate_coal_flow_balance"] = (
        strict_object(
            {
                "draft_id": _ID,
                "relative_tolerance": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                },
            },
            required=("draft_id",),
        ),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "revision": {"type": "integer"},
                "relative_tolerance": {"type": "number"},
                "evaluated_equation_count": {"type": "integer"},
                "outside_tolerance_count": {"type": "integer"},
                "equations": {
                    "type": "array",
                    "minItems": 3,
                    "maxItems": 3,
                    "items": coal_flow_equation,
                },
                "uncertainty": strict_object(
                    {
                        "measurement_uncertainty_included": {"type": "boolean"},
                        "metric_aliases_are_fixed": {"type": "boolean"},
                        "automatic_unit_conversion": {"type": "boolean"},
                        "threshold_is_preflight_only": {"type": "boolean"},
                    },
                    required=(
                        "measurement_uncertainty_included",
                        "metric_aliases_are_fixed",
                        "automatic_unit_conversion",
                        "threshold_is_preflight_only",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "revision",
                "relative_tolerance",
                "evaluated_equation_count",
                "outside_tolerance_count",
                "equations",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    product_input = strict_object(
        {
            "evidence_id": _ID,
            "value": _NONNEGATIVE,
            "unit": _UNIT,
            "kind": {
                "type": "string",
                "enum": ["clean", "middlings", "gangue", "other"],
            },
        },
        required=("evidence_id", "value", "unit", "kind"),
    )
    product_output = strict_object(
        {
            **quantity_output["properties"],
            "kind": {"type": "string"},
        },
        required=(*quantity_output["required"], "kind"),
    )
    schemas["calculate_washing_yield"] = (
        strict_object(
            {
                "feed": quantity_input,
                "products": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1_000,
                    "items": product_input,
                },
                "target_unit": {"type": "string", "enum": mass_units},
                "relative_tolerance": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                },
            },
            required=("feed", "products"),
        ),
        strict_object(
            {
                "target_unit": {"type": "string"},
                "feed": quantity_output,
                "products": {
                    "type": "array",
                    "maxItems": 1_000,
                    "items": product_output,
                },
                "product_count": {"type": "integer"},
                "products_truncated": {"type": "boolean"},
                "products_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "product_totals": strict_object(
                    {
                        key: {"type": "number"}
                        for key in ("clean", "middlings", "gangue", "other")
                    },
                    required=("clean", "middlings", "gangue", "other"),
                ),
                "total_products": {"type": "number"},
                "clean_coal_yield": {"type": "number"},
                "total_recovery": {"type": "number"},
                "mass_residual": {"type": "number"},
                "relative_gap": {"type": "number"},
                "relative_tolerance": {"type": "number"},
                "within_supplied_tolerance": {"type": "boolean"},
                "uncertainty": strict_object(
                    {
                        "quality_adjustment_included": {"type": "boolean"},
                        "moisture_basis_aligned": {"type": "boolean"},
                        "measurement_uncertainty_included": {"type": "boolean"},
                    },
                    required=(
                        "quality_adjustment_included",
                        "moisture_basis_aligned",
                        "measurement_uncertainty_included",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "target_unit",
                "feed",
                "products",
                "product_count",
                "products_truncated",
                "products_sha256",
                "product_totals",
                "total_products",
                "clean_coal_yield",
                "total_recovery",
                "mass_residual",
                "relative_gap",
                "relative_tolerance",
                "within_supplied_tolerance",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    baseline_input = strict_object(
        {
            "draft_id": _ID,
            "metric_code": _METRIC,
            "min_history": {"type": "integer", "minimum": 3, "maximum": 500},
            "max_history": {"type": "integer", "minimum": 3, "maximum": 500},
            "context_match": {"type": "boolean"},
        },
        required=("draft_id", "metric_code"),
    )
    schemas["build_historical_baseline"] = (baseline_input, baseline_output)
    drift_uncertainty = strict_object(
        {
            "reason": {"type": "string"},
            "causality_determined": {"type": "boolean"},
        },
        required=("reason", "causality_determined"),
    )
    drift_props = {
        **series_output["common"],
        "minimum_points": {"type": "integer"},
        "window_size": {"type": "integer"},
        "early_median": _NULLABLE_NUMBER,
        "late_median": _NULLABLE_NUMBER,
        "absolute_drift": _NULLABLE_NUMBER,
        "relative_drift": _NULLABLE_NUMBER,
        "early_mad": _NULLABLE_NUMBER,
        "late_mad": _NULLABLE_NUMBER,
        "uncertainty": drift_uncertainty,
    }
    schemas["detect_sensor_drift"] = (
        strict_object(
            {
                "draft_id": _ID,
                "metric_code": _METRIC,
                "min_points": {
                    "type": "integer",
                    "minimum": 6,
                    "maximum": 10_000,
                },
            },
            required=("draft_id", "metric_code"),
        ),
        strict_object(drift_props, required=tuple(drift_props)),
    )
    change_uncertainty = strict_object(
        {
            "reason": {"type": "string"},
            "multiple_testing_adjusted": {"type": "boolean"},
            "causality_determined": {"type": "boolean"},
        },
        required=("reason", "multiple_testing_adjusted", "causality_determined"),
    )
    change_props = {
        **series_output["common"],
        "minimum_segment_points": {"type": "integer"},
        "split_index": {"type": ["integer", "null"]},
        "first_right_observation_id": {"type": ["string", "null"]},
        "left_mean": _NULLABLE_NUMBER,
        "right_mean": _NULLABLE_NUMBER,
        "signed_gap": _NULLABLE_NUMBER,
        "normalized_gap": _NULLABLE_NUMBER,
        "left_mad": _NULLABLE_NUMBER,
        "right_mad": _NULLABLE_NUMBER,
        "uncertainty": change_uncertainty,
    }
    schemas["detect_change_point"] = (
        strict_object(
            {
                "draft_id": _ID,
                "metric_code": _METRIC,
                "min_segment_points": {
                    "type": "integer",
                    "minimum": 2,
                    "maximum": 5_000,
                },
            },
            required=("draft_id", "metric_code"),
        ),
        strict_object(change_props, required=tuple(change_props)),
    )
    component = strict_object(
        {
            "component": {"type": "string"},
            "status": {"type": "string"},
            "summary": {"type": "string"},
            "evidence_count": {"type": "integer"},
            "uncertainty": {"type": "string"},
        },
        required=(
            "component",
            "status",
            "summary",
            "evidence_count",
            "uncertainty",
        ),
    )
    schemas["explain_cross_validation"] = (
        strict_object(
            {
                "draft_id": _ID,
                "metric_codes": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 8,
                    "uniqueItems": True,
                    "items": _METRIC,
                },
                "min_history": {"type": "integer", "minimum": 3, "maximum": 500},
                "max_history": {
                    "type": "integer",
                    "minimum": 3,
                    "maximum": 500,
                },
                "context_match": {"type": "boolean"},
                "min_points": {
                    "type": "integer",
                    "minimum": 6,
                    "maximum": 10_000,
                },
                "min_segment_points": {
                    "type": "integer",
                    "minimum": 2,
                    "maximum": 5_000,
                },
            },
            required=("draft_id", "metric_codes"),
        ),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "revision": {"type": "integer"},
                "attention": {"type": "string"},
                "blocking_count": {"type": "integer"},
                "warning_count": {"type": "integer"},
                "incomplete_component_count": {"type": "integer"},
                "payload_digest_match_count": {"type": "integer"},
                "signature_format_valid_count": {"type": "integer"},
                "signature_cryptographically_verified": {"type": "boolean"},
                "components": {
                    "type": "array",
                    "maxItems": 64,
                    "items": component,
                },
                "uncertainty": strict_object(
                    {
                        "fusion": {"type": "string"},
                        "legal_conclusion": {"type": "boolean"},
                        "causality_determined": {"type": "boolean"},
                    },
                    required=("fusion", "legal_conclusion", "causality_determined"),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "revision",
                "attention",
                "blocking_count",
                "warning_count",
                "incomplete_component_count",
                "payload_digest_match_count",
                "signature_format_valid_count",
                "signature_cryptographically_verified",
                "components",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    # Every deterministic tool result carries the same explicit governance
    # marker.  The harness and UI can therefore enforce the distinction
    # without relying on translated prose.
    for _input_schema, output_schema in schemas.values():
        output_schema["properties"]["not_a_regulatory_determination"] = {
            "type": "boolean",
            "enum": [True],
        }
        output_schema["required"].append("not_a_regulatory_determination")
    return schemas


def _governed(executor):
    def run(arguments: Mapping[str, Any], context: ToolContext) -> ToolResult:
        result = executor(arguments, context)
        return ToolResult(
            data={
                **result.data,
                "not_a_regulatory_determination": True,
            },
            summary=result.summary,
            artifacts=result.artifacts,
        )

    return run


def builtin_tool_specs() -> tuple[ToolSpec, ...]:
    from .advanced import advanced_tool_specs
    from .audits import audit_tool_specs

    schemas = _schemas()
    definitions = (
        (
            "draft_summary",
            "汇总当前草稿的指标、单位、数量范围和可复核摘要，不推断缺失值。",
            _draft_summary,
        ),
        (
            "deterministic_preflight",
            "运行与提交前一致的确定性结构、来源和基础业务预检。",
            _deterministic_preflight,
        ),
        (
            "source_evidence_check",
            "检查来源载荷摘要、签名格式及字段来源完整度，不持密钥代验签。",
            _source_evidence_check,
        ),
        (
            "align_observation_time",
            "按显式 UTC 桶和延迟阈值对齐观测时间，标记窗口外及延迟记录。",
            _align_observation_time,
        ),
        (
            "convert_coal_units",
            "使用精确定义换算常用煤炭质量和 SI 能量单位。",
            _convert_coal_units,
        ),
        (
            "calculate_mass_balance",
            "根据显式证据量计算期初、流入、流出、期末质量平衡差额。",
            _mass_balance,
        ),
        (
            "calculate_coal_flow_balance",
            "从草稿固定指标映射计算产量主运、库存收发存和原煤去向三套平衡。",
            _coal_flow_balance,
        ),
        (
            "calculate_washing_yield",
            "根据显式入洗量和产品量计算精煤产率、回收率及质量闭合差。",
            _washing_yield,
        ),
        (
            "build_historical_baseline",
            "仅用同矿、目标窗口之前的成功提交草稿构建中位数/MAD稳健基线。",
            _historical_robust_baseline,
        ),
        (
            "detect_sensor_drift",
            "比较同一草稿时序早末稳健窗口，给出漂移证据但不判定原因。",
            _sensor_drift,
        ),
        (
            "detect_change_point",
            "在线性时间内搜索最大分段均值差候选，并明确统计局限。",
            _detect_change_point,
        ),
        (
            "explain_cross_validation",
            "并列解释物理、来源、历史、漂移和变化点证据，不合成合法性结论。",
            _cross_validation_explanation,
        ),
    )
    categories = {
        "draft_summary": "draft_governance",
        "deterministic_preflight": "draft_governance",
        "source_evidence_check": "source_evidence",
        "align_observation_time": "temporal_quality",
        "convert_coal_units": "unit_conversion",
        "calculate_mass_balance": "physical_reconciliation",
        "calculate_coal_flow_balance": "physical_reconciliation",
        "calculate_washing_yield": "physical_reconciliation",
        "build_historical_baseline": "historical_analysis",
        "detect_sensor_drift": "historical_analysis",
        "detect_change_point": "historical_analysis",
        "explain_cross_validation": "cross_validation",
    }
    repository_grounded = {
        "draft_summary",
        "deterministic_preflight",
        "source_evidence_check",
        "align_observation_time",
        "calculate_coal_flow_balance",
        "build_historical_baseline",
        "detect_sensor_drift",
        "detect_change_point",
        "explain_cross_validation",
    }
    base_specs = tuple(
        ToolSpec(
            name=name,
            description=description,
            input_schema=schemas[name][0],
            output_schema=schemas[name][1],
            execute=_governed(executor),
            mutating=False,
            requires_approval=False,
            timeout_seconds=20.0 if name == "explain_cross_validation" else 10.0,
            category=categories[name],
            evidence_grounding=(
                "repository_grounded"
                if name in repository_grounded
                else "user_supplied"
            ),
            network_access=False,
            scenario_only=name
            in {"calculate_mass_balance", "calculate_washing_yield"},
        )
        for name, description, executor in definitions
    )
    return base_specs + advanced_tool_specs() + audit_tool_specs()


def build_registry(service: Any) -> ToolRegistry:
    """Harness compatibility factory using the service's repository."""

    repo = getattr(service, "repository", None)
    if repo is None:
        raise ToolProtocolError(
            "service 未提供 repository",
            code="repository_required",
            path="$.service",
        )
    return ToolRegistry(
        builtin_tool_specs(),
        context=ToolContext(repository=repo),
    )


def default_registry(service: Any) -> ToolRegistry:
    return build_registry(service)
