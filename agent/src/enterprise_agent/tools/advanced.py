"""Additional deterministic coal decision-support tools.

The tools in this module either calculate only from explicit caller-supplied
quantities or read a bounded, copied draft/history view. They never fetch
external data, infer missing measurements, optimize a production decision, or
make a regulatory determination.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from enterprise_agent.util import sha256_json

from .core import (
    MASS_FACTORS_T,
    convert,
    decimal_median,
    disclaimer,
    draft,
    finite_decimal,
    json_number,
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
    ToolResult,
    ToolSpec,
    strict_object,
)

_ID = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}",
}
_METRIC = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
}
_NUMBER = {
    "type": "number",
    "minimum": -1_000_000_000_000,
    "maximum": 1_000_000_000_000,
}
_NONNEGATIVE = {
    "type": "number",
    "minimum": 0,
    "maximum": 1_000_000_000_000,
}
_PERCENT = {"type": "number", "minimum": 0, "maximum": 100}
_NULLABLE_NUMBER = {"type": ["number", "null"]}
_DISCLAIMER = {"type": "string", "minLength": 1, "maxLength": 256}
_STRING_ARRAY = {
    "type": "array",
    "maxItems": 10_000,
    "items": {"type": "string", "maxLength": 256},
}
_MAX_DETAILS = 100
_QUALITY_PROPERTIES = (
    "ash_percent",
    "total_sulfur_percent",
    "total_moisture_percent",
    "gross_calorific_value_mj_kg",
)
_CONSTRAINTS = {
    "max_ash_percent": ("ash_percent", "<="),
    "max_total_sulfur_percent": ("total_sulfur_percent", "<="),
    "max_total_moisture_percent": ("total_moisture_percent", "<="),
    "min_gross_calorific_value_mj_kg": (
        "gross_calorific_value_mj_kg",
        ">=",
    ),
}
_OUTFLOW_METRICS = (
    "sales.raw_shipped_t",
    "coal.sale_out_t",
    "wash.feed_t",
    "coal.processing_input_t",
    "coal.main_transport_t",
)
_ADDITIVE_TREND_METRICS = (
    "coal.reported_output_t",
    "coal.production_t",
    "coal.main_transport_t",
    "coal.purchase_in_t",
    "sales.raw_shipped_t",
    "coal.sale_out_t",
    "wash.feed_t",
    "coal.processing_input_t",
)
_FORMULA_VERSION = "enterprise-coal-deterministic-v1"


def _bounded(
    values: Sequence[Any],
    maximum: int = _MAX_DETAILS,
) -> tuple[list[Any], int, bool, str]:
    material = list(values)
    return (
        material[:maximum],
        len(material),
        len(material) > maximum,
        sha256_json(material),
    )


def _percentage(value: Any, path: str) -> Decimal:
    number = finite_decimal(value, path, nonnegative=True)
    if number > 100:
        raise ToolProtocolError(
            "百分比不能超过 100",
            code="percentage_out_of_range",
            path=path,
        )
    return number


def _convert_quality_basis(
    arguments: Mapping[str, Any],
    _context: ToolContext,
) -> ToolResult:
    property_code = str(arguments["property_code"])
    from_basis = str(arguments["from_basis"])
    to_basis = str(arguments["to_basis"])
    value = _percentage(arguments["value_percent"], "$.value_percent")
    moisture = _percentage(
        arguments["total_moisture_ar_percent"],
        "$.total_moisture_ar_percent",
    )
    moisture_ad = (
        _percentage(
            arguments["moisture_ad_percent"],
            "$.moisture_ad_percent",
        )
        if "moisture_ad_percent" in arguments
        else None
    )
    ash = _percentage(arguments["ash_ar_percent"], "$.ash_ar_percent")
    if moisture + ash >= 100:
        raise ToolProtocolError(
            "收到基全水分与灰分之和必须小于 100%",
            code="invalid_quality_denominator",
            path="$",
        )
    if property_code == "ash" and "daf" in {from_basis, to_basis}:
        raise ToolProtocolError(
            "灰分不能换算为干燥无灰基含量",
            code="ash_daf_undefined",
            path="$.to_basis",
        )
    if "ad" in {from_basis, to_basis} and moisture_ad is None:
        raise ToolProtocolError(
            "涉及空气干燥基（ad）时必须提供 moisture_ad_percent",
            code="moisture_ad_required",
            path="$.moisture_ad_percent",
        )
    if moisture_ad is not None and moisture_ad >= 100:
        raise ToolProtocolError(
            "空气干燥基水分必须小于 100%",
            code="invalid_quality_denominator",
            path="$.moisture_ad_percent",
        )
    ad_denominator = (
        (Decimal(100) - moisture) * Decimal(100) / (Decimal(100) - moisture_ad)
        if moisture_ad is not None
        else None
    )
    denominators: dict[str, Decimal | None] = {
        "ar": Decimal(100),
        "ad": ad_denominator,
        "d": Decimal(100) - moisture,
        "daf": Decimal(100) - moisture - ash,
    }
    denominator_from = denominators[from_basis]
    denominator_to = denominators[to_basis]
    if denominator_from is None or denominator_to is None:
        raise ToolProtocolError(
            "煤质基准换算参数不足",
            code="quality_basis_parameters_missing",
            path="$",
        )
    input_consistency_checked = property_code == "ash"
    if property_code == "ash":
        expected = ash * Decimal(100) / denominator_from
        if abs(value - expected) > Decimal("0.000001"):
            raise ToolProtocolError(
                "灰分输入值与 ash_ar_percent、全水分及声明基准不一致",
                code="inconsistent_ash_input",
                path="$.value_percent",
            )
    factor = denominator_from / denominator_to
    converted = value * factor
    if converted < 0 or converted > 100:
        raise ToolProtocolError(
            "换算结果超出物理百分比范围，请核对基准和输入值",
            code="impossible_quality_result",
            path="$",
        )
    data = {
        "status": "scenario_calculated",
        "formula_id": "coal_quality_basis_mass_fraction_v1",
        "input_origin": "caller_supplied_scenario",
        "evidence_verified": False,
        "property_code": property_code,
        "input_value_percent": json_number(value),
        "from_basis": from_basis,
        "to_basis": to_basis,
        "total_moisture_ar_percent": json_number(moisture),
        "moisture_ad_percent": (
            json_number(moisture_ad) if moisture_ad is not None else None
        ),
        "ash_ar_percent": json_number(ash),
        "basis_denominators_percent": {
            key: json_number(number) if number is not None else None
            for key, number in denominators.items()
        },
        "conversion_factor": json_number(factor),
        "converted_value_percent": json_number(converted),
        "input_consistency_checked": input_consistency_checked,
        "formula": "X_to = X_from × denominator_from ÷ denominator_to",
        "uncertainty": {
            "laboratory_method_verified": False,
            "calorific_value_supported": False,
            "nonlinear_quality_indices_supported": False,
            "basis_note": (
                "仅按声明的收到基质量分母做预核算；不替代实验室按现行标准"
                "和对应试验方法出具的煤质结果"
            ),
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"{property_code} 从 {from_basis} 换算到 {to_basis}："
            f"{data['converted_value_percent']}%。"
        ),
    )


def _evaluate_coal_blend(
    arguments: Mapping[str, Any],
    _context: ToolContext,
) -> ToolResult:
    raw_components = list(arguments["components"])
    component_ids = [str(item["component_id"]) for item in raw_components]
    if len(component_ids) != len(set(component_ids)):
        raise ToolProtocolError(
            "配煤组分编号不能重复",
            code="duplicate_component_id",
            path="$.components",
        )
    bases = {str(item["quality_basis"]) for item in raw_components}
    if len(bases) != 1:
        raise ToolProtocolError(
            "所有组分必须声明相同煤质基准",
            code="mixed_quality_basis",
            path="$.components",
        )
    quality_basis = next(iter(bases))
    if quality_basis != "ar" and any(
        "total_moisture_percent" in item["quality"] for item in raw_components
    ):
        raise ToolProtocolError(
            "全水分只允许在收到基（ar）配煤场景中使用",
            code="invalid_moisture_basis",
            path="$.components",
        )
    if quality_basis == "daf" and any(
        "ash_percent" in item["quality"] for item in raw_components
    ):
        raise ToolProtocolError(
            "灰分不能声明为干燥无灰基（daf）",
            code="ash_daf_undefined",
            path="$.components",
        )
    components: list[dict[str, Any]] = []
    total_mass = Decimal(0)
    values_by_property: dict[str, list[tuple[str, Decimal, Decimal]]] = {
        key: [] for key in _QUALITY_PROPERTIES
    }
    for index, item in enumerate(raw_components):
        mass = finite_decimal(
            item["mass_value"],
            f"$.components[{index}].mass_value",
            nonnegative=True,
        )
        if mass <= 0:
            raise ToolProtocolError(
                "配煤组分质量必须大于零",
                code="zero_component_mass",
                path=f"$.components[{index}].mass_value",
            )
        mass_t = convert(
            mass,
            str(item["mass_unit"]),
            "t",
            f"$.components[{index}].mass_value",
        )
        quality = item["quality"]
        provided: list[str] = []
        for property_code in _QUALITY_PROPERTIES:
            if property_code not in quality:
                continue
            number = finite_decimal(
                quality[property_code],
                f"$.components[{index}].quality.{property_code}",
                nonnegative=True,
            )
            maximum = (
                Decimal(100) if property_code.endswith("_percent") else Decimal(60)
            )
            if number > maximum:
                raise ToolProtocolError(
                    "煤质输入超出允许范围",
                    code="quality_value_out_of_range",
                    path=f"$.components[{index}].quality.{property_code}",
                )
            values_by_property[property_code].append(
                (str(item["component_id"]), mass_t, number)
            )
            provided.append(property_code)
        components.append(
            {
                "component_id": str(item["component_id"]),
                "mass_t": json_number(mass_t),
                "quality_basis": quality_basis,
                "provided_properties": provided,
            }
        )
        total_mass += mass_t
    if not any(values_by_property.values()):
        raise ToolProtocolError(
            "至少需要提供一项煤质指标",
            code="quality_values_required",
            path="$.components",
        )

    properties: list[dict[str, Any]] = []
    property_results: dict[str, Decimal | None] = {}
    for property_code in _QUALITY_PROPERTIES:
        rows = values_by_property[property_code]
        covered_mass = sum((mass for _item, mass, _value in rows), Decimal(0))
        contributor_ids = [item for item, _mass, _value in rows]
        missing_ids = [
            item for item in component_ids if item not in set(contributor_ids)
        ]
        complete = covered_mass == total_mass
        weighted = (
            sum((mass * value for _item, mass, value in rows), Decimal(0)) / total_mass
            if complete
            else None
        )
        property_results[property_code] = weighted
        properties.append(
            {
                "property_code": property_code,
                "unit": ("%" if property_code.endswith("_percent") else "MJ/kg"),
                "status": "evaluated" if complete else "incomplete",
                "value": json_number(weighted) if weighted is not None else None,
                "coverage_mass_ratio": json_number(covered_mass / total_mass),
                "contributor_ids": contributor_ids,
                "missing_component_ids": missing_ids,
            }
        )

    raw_constraints = arguments.get("constraints")
    constraints = raw_constraints if isinstance(raw_constraints, Mapping) else {}
    evaluations: list[dict[str, Any]] = []
    for field, (property_code, operator) in _CONSTRAINTS.items():
        if field not in constraints:
            continue
        limit = finite_decimal(
            constraints[field],
            f"$.constraints.{field}",
            nonnegative=True,
        )
        actual = property_results[property_code]
        if actual is None:
            status = "not_evaluated"
        elif operator == "<=":
            status = (
                "meets_supplied_constraint"
                if actual <= limit
                else "does_not_meet_supplied_constraint"
            )
        else:
            status = (
                "meets_supplied_constraint"
                if actual >= limit
                else "does_not_meet_supplied_constraint"
            )
        evaluations.append(
            {
                "constraint_code": field,
                "property_code": property_code,
                "operator": operator,
                "limit": json_number(limit),
                "actual": json_number(actual) if actual is not None else None,
                "status": status,
            }
        )
    if not evaluations:
        overall = "not_requested"
    elif any(
        item["status"] == "does_not_meet_supplied_constraint" for item in evaluations
    ):
        overall = "one_or_more_supplied_constraints_not_met"
    elif any(item["status"] == "not_evaluated" for item in evaluations):
        overall = "not_evaluated"
    else:
        overall = "all_supplied_constraints_met"
    data = {
        "quality_basis": quality_basis,
        "component_count": len(components),
        "total_mass_t": json_number(total_mass),
        "components": components,
        "properties": properties,
        "constraint_evaluations": evaluations,
        "overall_constraint_status": overall,
        "status": "scenario_calculated",
        "formula_id": "mass_weighted_linear_blend_v1",
        "input_origin": "caller_supplied_scenario",
        "evidence_verified": False,
        "uncertainty": {
            "mass_weighted_linear_model": True,
            "quality_basis_aligned": True,
            "laboratory_methods_verified": False,
            "sampling_uncertainty_included": False,
            "nonlinear_properties_optimized": False,
            "recipe_optimized": False,
            "reason": (
                "仅评价给定配比的质量加权平均；结焦性、可磨性、灰熔融性等"
                "非线性指标及实际混匀偏差未计算"
            ),
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"已评价 {len(components)} 个配煤组分；约束状态 {overall}，未执行配方优化。"
        ),
    )


def _inventory_coverage(
    arguments: Mapping[str, Any],
    context: ToolContext,
) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    outflow_metric = str(arguments.get("outflow_metric_code", "sales.raw_shipped_t"))
    closing, closing_unit, closing_ids = total_metric(value, "coal.closing_inventory_t")
    outflow, outflow_unit, outflow_ids = total_metric(value, outflow_metric)
    start = parsed_time(value.get("window_start"), "$.draft.window_start")
    end = parsed_time(value.get("window_end"), "$.draft.window_end")
    duration_days = Decimal(str((end - start).total_seconds())) / Decimal(86400)
    if duration_days <= 0:
        raise ToolProtocolError(
            "统计窗口持续时间必须大于零",
            code="invalid_reporting_window",
            path="$.draft_id",
        )
    closing_t = (
        convert(closing, str(closing_unit), "t", "$.closing_inventory")
        if closing is not None and closing_unit is not None
        else None
    )
    outflow_t = (
        convert(outflow, str(outflow_unit), "t", "$.outflow")
        if outflow is not None and outflow_unit is not None
        else None
    )
    if len(closing_ids) > 1:
        status = "ambiguous_closing_inventory_snapshots"
        closing_t = average_daily = coverage = None
    elif closing_t is None:
        status = "closing_inventory_missing"
        average_daily = coverage = None
    elif outflow_t is None:
        status = "outflow_missing"
        average_daily = coverage = None
    elif outflow_t <= 0:
        status = "zero_outflow"
        average_daily = coverage = None
    else:
        average_daily = outflow_t / duration_days
        candidate = closing_t / average_daily
        if candidate > Decimal("1000000000000"):
            status = "rate_too_small"
            coverage = None
        else:
            status = "evaluated"
            coverage = candidate
    returned_closing_ids, closing_count, closing_truncated, closing_hash = _bounded(
        closing_ids
    )
    returned_outflow_ids, outflow_count, outflow_truncated, outflow_hash = _bounded(
        outflow_ids
    )
    data = {
        "draft_id": value["draft_id"],
        "revision": int(value["_meta"]["revision"]),
        "document_sha256": sha256_json(public_document(value)),
        "status": status,
        "outflow_metric_code": outflow_metric,
        "reporting_window_days": json_number(duration_days),
        "closing_inventory_t": (
            json_number(closing_t) if closing_t is not None else None
        ),
        "average_daily_outflow_t": (
            json_number(average_daily) if average_daily is not None else None
        ),
        "coverage_days": (json_number(coverage) if coverage is not None else None),
        "closing_observation_ids": returned_closing_ids,
        "closing_observation_id_count": closing_count,
        "closing_observation_ids_truncated": closing_truncated,
        "closing_observation_ids_sha256": closing_hash,
        "outflow_observation_ids": returned_outflow_ids,
        "outflow_observation_id_count": outflow_count,
        "outflow_observation_ids_truncated": outflow_truncated,
        "outflow_observation_ids_sha256": outflow_hash,
        "uncertainty": {
            "formula_version": _FORMULA_VERSION,
            "formula": "closing inventory ÷ (window outflow ÷ window days)",
            "outflow_aggregation_assumption": (
                "所选指标的窗口内观测被视为可加总区间量；累计表读数或库存快照不得使用"
            ),
            "unique_closing_snapshot_required": True,
            "future_demand_forecast": False,
            "inventory_ownership_verified": False,
            "inventory_cutoff_alignment_verified": False,
            "reason": (
                "覆盖天数只是按当前统计窗口平均出库速度静态折算，"
                "不代表未来需求、可售库存或安全库存"
            ),
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"库存覆盖测算状态：{status}；"
            + (
                f"静态覆盖约 {data['coverage_days']} 天。"
                if coverage is not None
                else "未生成覆盖天数。"
            )
        ),
    )


def _series(
    value: Mapping[str, Any],
    metric_code: str,
    path: str,
) -> tuple[list[tuple[datetime, Decimal, str]], str | None]:
    raw = observation_values(value, metric_code)
    units = {
        str(observation.get("unit"))
        for observation, _number in raw
        if observation.get("unit") is not None
    }
    if len(units) > 1:
        raise ToolProtocolError(
            f"指标 {metric_code} 存在多个单位",
            code="mixed_metric_units",
            path=path,
        )
    rows = [
        (
            parsed_time(
                observation.get("observed_at"),
                f"{path}.observations[{index}].observed_at",
            ).astimezone(UTC),
            number,
            str(observation.get("observation_id", "")),
        )
        for index, (observation, number) in enumerate(raw)
    ]
    rows.sort(key=lambda item: (item[0], item[2]))
    return rows, next(iter(units)) if units else None


def _compare_metric_series(
    arguments: Mapping[str, Any],
    context: ToolContext,
) -> ToolResult:
    value = draft(context, str(arguments["draft_id"]))
    left_metric = str(arguments["left_metric_code"])
    right_metric = str(arguments["right_metric_code"])
    if left_metric == right_metric:
        raise ToolProtocolError(
            "左右指标必须不同",
            code="same_metric",
            path="$.right_metric_code",
        )
    tolerance_seconds = int(arguments.get("tolerance_seconds", 300))
    relative_tolerance = finite_decimal(
        arguments.get("relative_tolerance", 0.05),
        "$.relative_tolerance",
        nonnegative=True,
    )
    left, left_unit = _series(value, left_metric, "$.left_metric_code")
    right, right_unit = _series(value, right_metric, "$.right_metric_code")
    pairs: list[dict[str, Any]] = []
    relative_gaps: list[Decimal] = []
    signed_gaps: list[Decimal] = []
    outside = 0
    left_unmatched = 0
    right_unmatched = 0
    converted = False
    left_index = right_index = 0
    while left_index < len(left) and right_index < len(right):
        left_time, left_value, left_id = left[left_index]
        right_time, raw_right_value, right_id = right[right_index]
        signed_seconds = (right_time - left_time).total_seconds()
        if abs(signed_seconds) <= tolerance_seconds:
            right_value = raw_right_value
            if (
                left_unit is not None
                and right_unit is not None
                and left_unit != right_unit
            ):
                right_value = convert(
                    raw_right_value,
                    right_unit,
                    left_unit,
                    "$.right_metric_code",
                )
                converted = True
            gap = left_value - right_value
            scale = max(abs(left_value), abs(right_value))
            relative = abs(gap) / scale if scale > 0 else Decimal(0)
            within = relative <= relative_tolerance
            outside += int(not within)
            relative_gaps.append(relative)
            signed_gaps.append(gap)
            pairs.append(
                {
                    "left_observation_id": left_id,
                    "right_observation_id": right_id,
                    "left_observed_at": left_time.isoformat().replace("+00:00", "Z"),
                    "right_observed_at": right_time.isoformat().replace("+00:00", "Z"),
                    "time_gap_seconds": abs(signed_seconds),
                    "left_value": json_number(left_value),
                    "right_value_in_left_unit": json_number(right_value),
                    "signed_gap": json_number(gap),
                    "relative_gap": json_number(relative),
                    "within_tolerance": within,
                }
            )
            left_index += 1
            right_index += 1
        elif left_time < right_time:
            left_unmatched += 1
            left_index += 1
        else:
            right_unmatched += 1
            right_index += 1
    left_unmatched += len(left) - left_index
    right_unmatched += len(right) - right_index
    if not left:
        status = "left_metric_missing"
    elif not right:
        status = "right_metric_missing"
    elif not pairs:
        status = "no_aligned_pairs"
    else:
        status = "evaluated"
    returned_pairs, pair_count, pairs_truncated, pairs_hash = _bounded(pairs)
    data = {
        "draft_id": value["draft_id"],
        "revision": int(value["_meta"]["revision"]),
        "document_sha256": sha256_json(public_document(value)),
        "status": status,
        "left_metric_code": left_metric,
        "right_metric_code": right_metric,
        "comparison_unit": left_unit,
        "tolerance_seconds": tolerance_seconds,
        "relative_tolerance": json_number(relative_tolerance),
        "left_point_count": len(left),
        "right_point_count": len(right),
        "matched_pair_count": pair_count,
        "left_unmatched_count": left_unmatched,
        "right_unmatched_count": right_unmatched,
        "outside_tolerance_count": outside,
        "median_signed_gap": (
            json_number(decimal_median(signed_gaps)) if signed_gaps else None
        ),
        "median_absolute_relative_gap": (
            json_number(decimal_median(relative_gaps)) if relative_gaps else None
        ),
        "p95_absolute_relative_gap": (
            json_number(percentile(relative_gaps, Decimal("0.95")))
            if relative_gaps
            else None
        ),
        "pairs": returned_pairs,
        "pair_count": pair_count,
        "returned_pair_count": len(returned_pairs),
        "pairs_truncated": pairs_truncated,
        "pairs_sha256": pairs_hash,
        "uncertainty": {
            "formula_version": _FORMULA_VERSION,
            "threshold_origin": (
                "caller_supplied_with_defaults"
                if "relative_tolerance" in arguments or "tolerance_seconds" in arguments
                else "system_defaults"
            ),
            "pairing_rule": (
                "按观测时间升序执行一对一顺序匹配；仅匹配时间差不超过显式阈值的记录"
            ),
            "business_relation_verified": False,
            "automatic_exact_unit_conversion": converted,
            "measurement_uncertainty_included": False,
            "causality_determined": False,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"时序指标对比状态：{status}；匹配 {pair_count} 对，"
            f"{outside} 对超过相对差阈值。"
        ),
    )


def _history_points(
    current: Mapping[str, Any],
    metric_code: str,
    *,
    maximum: int,
    context_match: bool,
    normalization: str,
    context: ToolContext,
) -> tuple[list[dict[str, Any]], int, int]:
    reader = getattr(repository(context), "historical_observations", None)
    if not callable(reader):
        raise ToolProtocolError(
            "仓库不支持历史观测查询",
            code="history_unavailable",
            path="$.draft_id",
        )
    raw = reader(
        mine_id=str(current.get("mine_id", "")),
        metric_code=metric_code,
        exclude_draft_id=str(current.get("draft_id", "")),
        before_window_start=str(current.get("window_start", "")),
        limit=min(maximum * 10, 500),
    )
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in raw:
        if isinstance(row, Mapping) and isinstance(row.get("draft_id"), str):
            grouped.setdefault(str(row["draft_id"]), []).append(row)
    current_context = current.get("operational_context")
    points: list[dict[str, Any]] = []
    excluded_context = 0
    excluded_invalid = 0
    for draft_id, rows in grouped.items():
        first = rows[0]
        if context_match:
            candidate_context = first.get("operational_context")
            if (
                not isinstance(candidate_context, Mapping)
                or not isinstance(current_context, Mapping)
                or first.get("profile_id") != current.get("profile_id")
                or first.get("profile_version") != current.get("profile_version")
                or any(
                    candidate_context.get(key) != current_context.get(key)
                    for key in (
                        "regime_code",
                        "shift_code",
                        "season_code",
                        "maintenance",
                    )
                )
            ):
                excluded_context += 1
                continue
        try:
            start = parsed_time(first.get("window_start"), "$.history.window_start")
            end = parsed_time(first.get("window_end"), "$.history.window_end")
            units = {str(row.get("unit")) for row in rows if row.get("unit")}
            if end <= start or len(units) != 1:
                raise ValueError
            numbers = [
                finite_decimal(row.get("value"), "$.history.value") for row in rows
            ]
        except (ToolProtocolError, ValueError):
            excluded_invalid += 1
            continue
        total = sum(numbers, Decimal(0))
        duration_days = Decimal(str((end - start).total_seconds())) / Decimal(86400)
        normalized = total / duration_days if normalization == "per_day" else total
        points.append(
            {
                "draft_id": draft_id,
                "window_start": start.astimezone(UTC),
                "window_end": end.astimezone(UTC),
                "value": normalized,
                "unit": next(iter(units)),
                "observation_ids": [str(row.get("observation_id", "")) for row in rows],
                "current": False,
            }
        )
        if len(points) >= maximum:
            break
    return points, excluded_context, excluded_invalid


def _historical_trend(
    arguments: Mapping[str, Any],
    context: ToolContext,
) -> ToolResult:
    current = draft(context, str(arguments["draft_id"]))
    metric_code = str(arguments["metric_code"])
    minimum = int(arguments.get("min_history", 5))
    maximum = int(arguments.get("max_history", 50))
    if maximum < minimum:
        raise ToolProtocolError(
            "max_history 不能小于 min_history",
            code="invalid_history_bounds",
            path="$.max_history",
        )
    context_match = bool(arguments.get("context_match", True))
    normalization = str(arguments.get("normalization", "total"))
    flat_threshold = finite_decimal(
        arguments.get("flat_relative_change_30d", 0.02),
        "$.flat_relative_change_30d",
        nonnegative=True,
    )
    current_total, current_unit, current_ids = total_metric(current, metric_code)
    history, excluded_context, excluded_invalid = _history_points(
        current,
        metric_code,
        maximum=maximum,
        context_match=context_match,
        normalization=normalization,
        context=context,
    )
    if current_total is not None and current_unit is not None:
        start = parsed_time(current.get("window_start"), "$.draft.window_start")
        end = parsed_time(current.get("window_end"), "$.draft.window_end")
        duration_days = Decimal(str((end - start).total_seconds())) / Decimal(86400)
        current_value = (
            current_total / duration_days
            if normalization == "per_day"
            else current_total
        )
        history.append(
            {
                "draft_id": str(current["draft_id"]),
                "window_start": start.astimezone(UTC),
                "window_end": end.astimezone(UTC),
                "value": current_value,
                "unit": current_unit,
                "observation_ids": current_ids,
                "current": True,
            }
        )
    compatible = [
        point
        for point in history
        if current_unit is not None and point["unit"] == current_unit
    ]
    excluded_mixed_unit = len(history) - len(compatible)
    compatible.sort(key=lambda item: (item["window_end"], item["draft_id"]))
    history_count = sum(not point["current"] for point in compatible)
    slopes: list[Decimal] = []
    for left_index, left in enumerate(compatible):
        for right in compatible[left_index + 1 :]:
            days = Decimal(
                str((right["window_end"] - left["window_end"]).total_seconds())
            ) / Decimal(86400)
            if days > 0:
                slopes.append((right["value"] - left["value"]) / days)
    values = [point["value"] for point in compatible]
    level_median = decimal_median(values) if values else None
    if current_total is None or current_unit is None:
        status = "current_metric_missing"
        slope = change_30d = relative_30d = None
        direction = "not_evaluated"
    elif history_count < minimum:
        status = "insufficient_history"
        slope = change_30d = relative_30d = None
        direction = "not_evaluated"
    elif not slopes:
        status = "insufficient_time_spread"
        slope = change_30d = relative_30d = None
        direction = "not_evaluated"
    else:
        status = "evaluated"
        slope = decimal_median(slopes)
        change_30d = slope * Decimal(30)
        relative_30d = (
            change_30d / abs(level_median)
            if level_median is not None and level_median != 0
            else None
        )
        if relative_30d is None:
            direction = (
                "direction_only_increasing"
                if slope > 0
                else ("direction_only_decreasing" if slope < 0 else "flat")
            )
        elif abs(relative_30d) <= flat_threshold:
            direction = "flat_within_threshold"
        else:
            direction = "increasing" if relative_30d > 0 else "decreasing"
    point_records: list[dict[str, Any]] = []
    for point in compatible:
        ids, id_count, ids_truncated, ids_hash = _bounded(point["observation_ids"])
        point_records.append(
            {
                "draft_id": point["draft_id"],
                "window_start": point["window_start"]
                .isoformat()
                .replace("+00:00", "Z"),
                "window_end": point["window_end"].isoformat().replace("+00:00", "Z"),
                "value": json_number(point["value"]),
                "current": bool(point["current"]),
                "observation_ids": ids,
                "observation_id_count": id_count,
                "observation_ids_truncated": ids_truncated,
                "observation_ids_sha256": ids_hash,
            }
        )
    returned_points, point_count, points_truncated, points_hash = _bounded(
        point_records
    )
    data = {
        "draft_id": current["draft_id"],
        "revision": int(current["_meta"]["revision"]),
        "document_sha256": sha256_json(public_document(current)),
        "metric_code": metric_code,
        "status": status,
        "normalization": normalization,
        "unit": (
            f"{current_unit}/day"
            if current_unit is not None and normalization == "per_day"
            else current_unit
        ),
        "history_sample_size": history_count,
        "minimum_history": minimum,
        "point_count": point_count,
        "current_value": (
            next(
                (
                    json_number(point["value"])
                    for point in compatible
                    if point["current"]
                ),
                None,
            )
        ),
        "level_median": (
            json_number(level_median) if level_median is not None else None
        ),
        "theil_sen_slope_per_day": (json_number(slope) if slope is not None else None),
        "slope_scaled_change_30d": (
            json_number(change_30d) if change_30d is not None else None
        ),
        "relative_slope_scaled_change_30d": (
            json_number(relative_30d) if relative_30d is not None else None
        ),
        "flat_relative_change_30d": json_number(flat_threshold),
        "direction": direction,
        "points": returned_points,
        "returned_point_count": len(returned_points),
        "points_truncated": points_truncated,
        "points_sha256": points_hash,
        "excluded_context_count": excluded_context,
        "excluded_invalid_count": excluded_invalid,
        "excluded_mixed_unit_count": excluded_mixed_unit,
        "uncertainty": {
            "formula_version": "theil_sen_descriptive_trend_v1",
            "parameter_source": "system_fixed",
            "metric_semantics": "additive_window_total",
            "future_data_excluded": True,
            "only_succeeded_submissions_in_history": True,
            "context_matched": context_match,
            "linear_projection_is_forecast": False,
            "seasonality_modeled": False,
            "causality_determined": False,
            "reason": (
                "Theil-Sen 斜率只描述可比历史点的稳健线性方向；"
                "30 天变化是斜率尺度展示，不是未来预测"
            ),
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"历史趋势状态：{status}；可比历史样本 {history_count} 个，"
            f"方向 {direction}。"
        ),
    )


def _schemas() -> dict[str, tuple[dict[str, Any], dict[str, Any]]]:
    mass_units = sorted(MASS_FACTORS_T)
    schemas: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    schemas["convert_coal_quality_basis"] = (
        strict_object(
            {
                "property_code": {
                    "type": "string",
                    "enum": ["ash", "total_sulfur", "volatile_matter"],
                },
                "value_percent": _PERCENT,
                "from_basis": {
                    "type": "string",
                    "enum": ["ar", "ad", "d", "daf"],
                },
                "to_basis": {
                    "type": "string",
                    "enum": ["ar", "ad", "d", "daf"],
                },
                "total_moisture_ar_percent": _PERCENT,
                "moisture_ad_percent": _PERCENT,
                "ash_ar_percent": _PERCENT,
            },
            required=(
                "property_code",
                "value_percent",
                "from_basis",
                "to_basis",
                "total_moisture_ar_percent",
                "ash_ar_percent",
            ),
        ),
        strict_object(
            {
                "status": {"type": "string", "enum": ["scenario_calculated"]},
                "formula_id": {"type": "string"},
                "input_origin": {
                    "type": "string",
                    "enum": ["caller_supplied_scenario"],
                },
                "evidence_verified": {"type": "boolean", "enum": [False]},
                "property_code": {"type": "string"},
                "input_value_percent": {"type": "number"},
                "from_basis": {"type": "string"},
                "to_basis": {"type": "string"},
                "total_moisture_ar_percent": {"type": "number"},
                "moisture_ad_percent": _NULLABLE_NUMBER,
                "ash_ar_percent": {"type": "number"},
                "basis_denominators_percent": strict_object(
                    {
                        "ar": {"type": "number"},
                        "ad": _NULLABLE_NUMBER,
                        "d": {"type": "number"},
                        "daf": {"type": "number"},
                    },
                    required=("ar", "ad", "d", "daf"),
                ),
                "conversion_factor": {"type": "number"},
                "converted_value_percent": {"type": "number"},
                "input_consistency_checked": {"type": "boolean"},
                "formula": {"type": "string"},
                "uncertainty": strict_object(
                    {
                        "laboratory_method_verified": {"type": "boolean"},
                        "calorific_value_supported": {"type": "boolean"},
                        "nonlinear_quality_indices_supported": {"type": "boolean"},
                        "basis_note": {"type": "string"},
                    },
                    required=(
                        "laboratory_method_verified",
                        "calorific_value_supported",
                        "nonlinear_quality_indices_supported",
                        "basis_note",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "status",
                "formula_id",
                "input_origin",
                "evidence_verified",
                "property_code",
                "input_value_percent",
                "from_basis",
                "to_basis",
                "total_moisture_ar_percent",
                "moisture_ad_percent",
                "ash_ar_percent",
                "basis_denominators_percent",
                "conversion_factor",
                "converted_value_percent",
                "input_consistency_checked",
                "formula",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    quality_schema = strict_object(
        {
            "ash_percent": _PERCENT,
            "total_sulfur_percent": _PERCENT,
            "total_moisture_percent": _PERCENT,
            "gross_calorific_value_mj_kg": {
                "type": "number",
                "minimum": 0,
                "maximum": 60,
            },
        }
    )
    blend_component = strict_object(
        {
            "component_id": _ID,
            "mass_value": _NONNEGATIVE,
            "mass_unit": {"type": "string", "enum": mass_units},
            "quality_basis": {"type": "string", "enum": ["ar", "d", "daf"]},
            "quality": quality_schema,
        },
        required=(
            "component_id",
            "mass_value",
            "mass_unit",
            "quality_basis",
            "quality",
        ),
    )
    constraint_schema = strict_object(
        {
            "max_ash_percent": _PERCENT,
            "max_total_sulfur_percent": _PERCENT,
            "max_total_moisture_percent": _PERCENT,
            "min_gross_calorific_value_mj_kg": {
                "type": "number",
                "minimum": 0,
                "maximum": 60,
            },
        }
    )
    schemas["evaluate_coal_blend"] = (
        strict_object(
            {
                "components": {
                    "type": "array",
                    "minItems": 2,
                    "maxItems": 20,
                    "items": blend_component,
                },
                "constraints": constraint_schema,
            },
            required=("components",),
        ),
        strict_object(
            {
                "status": {"type": "string", "enum": ["scenario_calculated"]},
                "formula_id": {"type": "string"},
                "input_origin": {
                    "type": "string",
                    "enum": ["caller_supplied_scenario"],
                },
                "evidence_verified": {"type": "boolean", "enum": [False]},
                "quality_basis": {"type": "string"},
                "component_count": {"type": "integer"},
                "total_mass_t": {"type": "number"},
                "components": {
                    "type": "array",
                    "maxItems": 20,
                    "items": strict_object(
                        {
                            "component_id": {"type": "string"},
                            "mass_t": {"type": "number"},
                            "quality_basis": {"type": "string"},
                            "provided_properties": {
                                "type": "array",
                                "maxItems": 4,
                                "items": {"type": "string"},
                            },
                        },
                        required=(
                            "component_id",
                            "mass_t",
                            "quality_basis",
                            "provided_properties",
                        ),
                    ),
                },
                "properties": {
                    "type": "array",
                    "minItems": 4,
                    "maxItems": 4,
                    "items": strict_object(
                        {
                            "property_code": {"type": "string"},
                            "unit": {"type": "string"},
                            "status": {"type": "string"},
                            "value": _NULLABLE_NUMBER,
                            "coverage_mass_ratio": {"type": "number"},
                            "contributor_ids": _STRING_ARRAY,
                            "missing_component_ids": _STRING_ARRAY,
                        },
                        required=(
                            "property_code",
                            "unit",
                            "status",
                            "value",
                            "coverage_mass_ratio",
                            "contributor_ids",
                            "missing_component_ids",
                        ),
                    ),
                },
                "constraint_evaluations": {
                    "type": "array",
                    "maxItems": 4,
                    "items": strict_object(
                        {
                            "constraint_code": {"type": "string"},
                            "property_code": {"type": "string"},
                            "operator": {"type": "string"},
                            "limit": {"type": "number"},
                            "actual": _NULLABLE_NUMBER,
                            "status": {"type": "string"},
                        },
                        required=(
                            "constraint_code",
                            "property_code",
                            "operator",
                            "limit",
                            "actual",
                            "status",
                        ),
                    ),
                },
                "overall_constraint_status": {"type": "string"},
                "uncertainty": strict_object(
                    {
                        "mass_weighted_linear_model": {"type": "boolean"},
                        "quality_basis_aligned": {"type": "boolean"},
                        "laboratory_methods_verified": {"type": "boolean"},
                        "sampling_uncertainty_included": {"type": "boolean"},
                        "nonlinear_properties_optimized": {"type": "boolean"},
                        "recipe_optimized": {"type": "boolean"},
                        "reason": {"type": "string"},
                    },
                    required=(
                        "mass_weighted_linear_model",
                        "quality_basis_aligned",
                        "laboratory_methods_verified",
                        "sampling_uncertainty_included",
                        "nonlinear_properties_optimized",
                        "recipe_optimized",
                        "reason",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "status",
                "formula_id",
                "input_origin",
                "evidence_verified",
                "quality_basis",
                "component_count",
                "total_mass_t",
                "components",
                "properties",
                "constraint_evaluations",
                "overall_constraint_status",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    schemas["calculate_inventory_coverage"] = (
        strict_object(
            {
                "draft_id": _ID,
                "outflow_metric_code": {
                    "type": "string",
                    "enum": list(_OUTFLOW_METRICS),
                },
            },
            required=("draft_id",),
        ),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "revision": {"type": "integer"},
                "document_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "status": {"type": "string"},
                "outflow_metric_code": {"type": "string"},
                "reporting_window_days": {"type": "number"},
                "closing_inventory_t": _NULLABLE_NUMBER,
                "average_daily_outflow_t": _NULLABLE_NUMBER,
                "coverage_days": _NULLABLE_NUMBER,
                "closing_observation_ids": _STRING_ARRAY,
                "closing_observation_id_count": {"type": "integer"},
                "closing_observation_ids_truncated": {"type": "boolean"},
                "closing_observation_ids_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "outflow_observation_ids": _STRING_ARRAY,
                "outflow_observation_id_count": {"type": "integer"},
                "outflow_observation_ids_truncated": {"type": "boolean"},
                "outflow_observation_ids_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "uncertainty": strict_object(
                    {
                        "formula_version": {"type": "string"},
                        "formula": {"type": "string"},
                        "outflow_aggregation_assumption": {"type": "string"},
                        "unique_closing_snapshot_required": {"type": "boolean"},
                        "future_demand_forecast": {"type": "boolean"},
                        "inventory_ownership_verified": {"type": "boolean"},
                        "inventory_cutoff_alignment_verified": {"type": "boolean"},
                        "reason": {"type": "string"},
                    },
                    required=(
                        "formula_version",
                        "formula",
                        "outflow_aggregation_assumption",
                        "unique_closing_snapshot_required",
                        "future_demand_forecast",
                        "inventory_ownership_verified",
                        "inventory_cutoff_alignment_verified",
                        "reason",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "revision",
                "document_sha256",
                "status",
                "outflow_metric_code",
                "reporting_window_days",
                "closing_inventory_t",
                "average_daily_outflow_t",
                "coverage_days",
                "closing_observation_ids",
                "closing_observation_id_count",
                "closing_observation_ids_truncated",
                "closing_observation_ids_sha256",
                "outflow_observation_ids",
                "outflow_observation_id_count",
                "outflow_observation_ids_truncated",
                "outflow_observation_ids_sha256",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    pair_schema = strict_object(
        {
            "left_observation_id": {"type": "string"},
            "right_observation_id": {"type": "string"},
            "left_observed_at": {"type": "string"},
            "right_observed_at": {"type": "string"},
            "time_gap_seconds": {"type": "number"},
            "left_value": {"type": "number"},
            "right_value_in_left_unit": {"type": "number"},
            "signed_gap": {"type": "number"},
            "relative_gap": {"type": "number"},
            "within_tolerance": {"type": "boolean"},
        },
        required=(
            "left_observation_id",
            "right_observation_id",
            "left_observed_at",
            "right_observed_at",
            "time_gap_seconds",
            "left_value",
            "right_value_in_left_unit",
            "signed_gap",
            "relative_gap",
            "within_tolerance",
        ),
    )
    schemas["compare_metric_series"] = (
        strict_object(
            {
                "draft_id": _ID,
                "left_metric_code": _METRIC,
                "right_metric_code": _METRIC,
                "tolerance_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 3_600,
                },
                "relative_tolerance": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1,
                },
            },
            required=("draft_id", "left_metric_code", "right_metric_code"),
        ),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "revision": {"type": "integer"},
                "document_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "status": {"type": "string"},
                "left_metric_code": {"type": "string"},
                "right_metric_code": {"type": "string"},
                "comparison_unit": {"type": ["string", "null"]},
                "tolerance_seconds": {"type": "integer"},
                "relative_tolerance": {"type": "number"},
                "left_point_count": {"type": "integer"},
                "right_point_count": {"type": "integer"},
                "matched_pair_count": {"type": "integer"},
                "left_unmatched_count": {"type": "integer"},
                "right_unmatched_count": {"type": "integer"},
                "outside_tolerance_count": {"type": "integer"},
                "median_signed_gap": _NULLABLE_NUMBER,
                "median_absolute_relative_gap": _NULLABLE_NUMBER,
                "p95_absolute_relative_gap": _NULLABLE_NUMBER,
                "pairs": {
                    "type": "array",
                    "maxItems": _MAX_DETAILS,
                    "items": pair_schema,
                },
                "pair_count": {"type": "integer"},
                "returned_pair_count": {"type": "integer"},
                "pairs_truncated": {"type": "boolean"},
                "pairs_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "uncertainty": strict_object(
                    {
                        "formula_version": {"type": "string"},
                        "threshold_origin": {"type": "string"},
                        "pairing_rule": {"type": "string"},
                        "business_relation_verified": {"type": "boolean"},
                        "automatic_exact_unit_conversion": {"type": "boolean"},
                        "measurement_uncertainty_included": {"type": "boolean"},
                        "causality_determined": {"type": "boolean"},
                    },
                    required=(
                        "formula_version",
                        "threshold_origin",
                        "pairing_rule",
                        "business_relation_verified",
                        "automatic_exact_unit_conversion",
                        "measurement_uncertainty_included",
                        "causality_determined",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "revision",
                "document_sha256",
                "status",
                "left_metric_code",
                "right_metric_code",
                "comparison_unit",
                "tolerance_seconds",
                "relative_tolerance",
                "left_point_count",
                "right_point_count",
                "matched_pair_count",
                "left_unmatched_count",
                "right_unmatched_count",
                "outside_tolerance_count",
                "median_signed_gap",
                "median_absolute_relative_gap",
                "p95_absolute_relative_gap",
                "pairs",
                "pair_count",
                "returned_pair_count",
                "pairs_truncated",
                "pairs_sha256",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
    trend_point = strict_object(
        {
            "draft_id": {"type": "string"},
            "window_start": {"type": "string"},
            "window_end": {"type": "string"},
            "value": {"type": "number"},
            "current": {"type": "boolean"},
            "observation_ids": _STRING_ARRAY,
            "observation_id_count": {"type": "integer"},
            "observation_ids_truncated": {"type": "boolean"},
            "observation_ids_sha256": {
                "type": "string",
                "pattern": r"[0-9a-f]{64}",
            },
        },
        required=(
            "draft_id",
            "window_start",
            "window_end",
            "value",
            "current",
            "observation_ids",
            "observation_id_count",
            "observation_ids_truncated",
            "observation_ids_sha256",
        ),
    )
    schemas["analyze_historical_trend"] = (
        strict_object(
            {
                "draft_id": _ID,
                "metric_code": {
                    "type": "string",
                    "enum": list(_ADDITIVE_TREND_METRICS),
                },
                "normalization": {
                    "type": "string",
                    "enum": ["total", "per_day"],
                },
            },
            required=("draft_id", "metric_code"),
        ),
        strict_object(
            {
                "draft_id": {"type": "string"},
                "revision": {"type": "integer"},
                "document_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "metric_code": {"type": "string"},
                "status": {"type": "string"},
                "normalization": {"type": "string"},
                "unit": {"type": ["string", "null"]},
                "history_sample_size": {"type": "integer"},
                "minimum_history": {"type": "integer"},
                "point_count": {"type": "integer"},
                "current_value": _NULLABLE_NUMBER,
                "level_median": _NULLABLE_NUMBER,
                "theil_sen_slope_per_day": _NULLABLE_NUMBER,
                "slope_scaled_change_30d": _NULLABLE_NUMBER,
                "relative_slope_scaled_change_30d": _NULLABLE_NUMBER,
                "flat_relative_change_30d": {"type": "number"},
                "direction": {"type": "string"},
                "points": {
                    "type": "array",
                    "maxItems": _MAX_DETAILS,
                    "items": trend_point,
                },
                "returned_point_count": {"type": "integer"},
                "points_truncated": {"type": "boolean"},
                "points_sha256": {
                    "type": "string",
                    "pattern": r"[0-9a-f]{64}",
                },
                "excluded_context_count": {"type": "integer"},
                "excluded_invalid_count": {"type": "integer"},
                "excluded_mixed_unit_count": {"type": "integer"},
                "uncertainty": strict_object(
                    {
                        "formula_version": {"type": "string"},
                        "parameter_source": {"type": "string"},
                        "metric_semantics": {"type": "string"},
                        "future_data_excluded": {"type": "boolean"},
                        "only_succeeded_submissions_in_history": {"type": "boolean"},
                        "context_matched": {"type": "boolean"},
                        "linear_projection_is_forecast": {"type": "boolean"},
                        "seasonality_modeled": {"type": "boolean"},
                        "causality_determined": {"type": "boolean"},
                        "reason": {"type": "string"},
                    },
                    required=(
                        "formula_version",
                        "parameter_source",
                        "metric_semantics",
                        "future_data_excluded",
                        "only_succeeded_submissions_in_history",
                        "context_matched",
                        "linear_projection_is_forecast",
                        "seasonality_modeled",
                        "causality_determined",
                        "reason",
                    ),
                ),
                "disclaimer": _DISCLAIMER,
            },
            required=(
                "draft_id",
                "revision",
                "document_sha256",
                "metric_code",
                "status",
                "normalization",
                "unit",
                "history_sample_size",
                "minimum_history",
                "point_count",
                "current_value",
                "level_median",
                "theil_sen_slope_per_day",
                "slope_scaled_change_30d",
                "relative_slope_scaled_change_30d",
                "flat_relative_change_30d",
                "direction",
                "points",
                "returned_point_count",
                "points_truncated",
                "points_sha256",
                "excluded_context_count",
                "excluded_invalid_count",
                "excluded_mixed_unit_count",
                "uncertainty",
                "disclaimer",
            ),
        ),
    )
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
            data={**result.data, "not_a_regulatory_determination": True},
            summary=result.summary,
            artifacts=result.artifacts,
        )

    return run


def advanced_tool_specs() -> tuple[ToolSpec, ...]:
    schemas = _schemas()
    definitions = (
        (
            "convert_coal_quality_basis",
            "按声明的水分和灰分换算灰分、全硫或挥发分的 ar/ad/d/daf 基准；"
            "涉及 ad 时必须提供空气干燥基水分，不支持发热量及非线性煤质指标。",
            _convert_quality_basis,
        ),
        (
            "evaluate_coal_blend",
            "对用户明确给出的配煤场景和同一煤质基准做质量加权试算，"
            "只核对调用者给出的约束；不代表质量化验、规范符合或配方优化。",
            _evaluate_coal_blend,
        ),
        (
            "calculate_inventory_coverage",
            "从绑定草稿的期末库存和指定出库指标计算静态库存覆盖天数；"
            "不预测未来需求，也不验证库存所有权和盘点截止时点。",
            _inventory_coverage,
        ),
        (
            "compare_metric_series",
            "按显式时间容差一对一匹配草稿内两个指标时序，计算逐对差额、"
            "未匹配数量和稳健差异摘要；指标业务关系和阈值仍需人工确认。",
            _compare_metric_series,
        ),
        (
            "analyze_historical_trend",
            "仅用当前窗口之前、同矿且可选同工况的成功提交历史计算 Theil-Sen "
            "稳健趋势；30 天变化仅作斜率尺度展示，不是预测。",
            _historical_trend,
        ),
    )
    categories = {
        "convert_coal_quality_basis": "coal_quality_scenario",
        "evaluate_coal_blend": "coal_blending_scenario",
        "calculate_inventory_coverage": "inventory_analysis",
        "compare_metric_series": "source_consistency",
        "analyze_historical_trend": "historical_analysis",
    }
    repository_grounded = {
        "calculate_inventory_coverage",
        "compare_metric_series",
        "analyze_historical_trend",
    }
    scenario_only = {
        "convert_coal_quality_basis",
        "evaluate_coal_blend",
    }
    return tuple(
        ToolSpec(
            name=name,
            description=description,
            input_schema=schemas[name][0],
            output_schema=schemas[name][1],
            execute=_governed(executor),
            mutating=False,
            requires_approval=False,
            timeout_seconds={
                "convert_coal_quality_basis": 1.0,
                "evaluate_coal_blend": 2.0,
                "calculate_inventory_coverage": 3.0,
                "compare_metric_series": 5.0,
                "analyze_historical_trend": 5.0,
            }[name],
            category=categories[name],
            evidence_grounding=(
                "repository_grounded"
                if name in repository_grounded
                else "user_supplied"
            ),
            network_access=False,
            scenario_only=name in scenario_only,
        )
        for name, description, executor in definitions
    )


__all__ = ["advanced_tool_specs"]
