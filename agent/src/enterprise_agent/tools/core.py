"""Numerical and repository helpers shared by deterministic coal tools."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from decimal import Decimal
from statistics import median
from typing import Any

from enterprise_agent.util import parse_aware_datetime

from .protocol import ToolContext, ToolProtocolError

MAX_ABS_VALUE = Decimal("1000000000000")
MAX_OBSERVATIONS = 10_000
HEX64 = re.compile(r"^[0-9a-f]{64}$")

MASS_FACTORS_T: dict[str, Decimal] = {
    "g": Decimal("0.000001"),
    "kg": Decimal("0.001"),
    "t": Decimal("1"),
    "tonne": Decimal("1"),
    "吨": Decimal("1"),
    "kt": Decimal("1000"),
}
ENERGY_FACTORS_MJ: dict[str, Decimal] = {
    "kJ": Decimal("0.001"),
    "MJ": Decimal("1"),
    "GJ": Decimal("1000"),
    "kWh": Decimal("3.6"),
    "MWh": Decimal("3600"),
}


def repository(context: ToolContext):
    if context.repository is None:
        raise ToolProtocolError(
            "该工具需要只读草稿仓库",
            code="repository_required",
            path="$",
        )
    return context.repository


def draft(context: ToolContext, draft_id: str) -> dict[str, Any]:
    value = repository(context).get_draft(draft_id)
    observations = value.get("observations")
    if not isinstance(observations, list):
        raise ToolProtocolError(
            "草稿观测结构无效",
            code="invalid_draft",
            path="$.draft_id",
        )
    if len(observations) > min(context.max_observations, MAX_OBSERVATIONS):
        raise ToolProtocolError(
            "草稿观测超过工具处理上限",
            code="too_many_observations",
            path="$.draft_id",
        )
    return value


def finite_decimal(value: Any, path: str, *, nonnegative: bool = False) -> Decimal:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float, Decimal))
        or not math.isfinite(float(value))
    ):
        raise ToolProtocolError(
            "数值必须是有限数字", code="invalid_number", path=path
        )
    number = Decimal(str(value))
    if abs(number) > MAX_ABS_VALUE:
        raise ToolProtocolError(
            "数值绝对值不能超过 1e12", code="number_out_of_range", path=path
        )
    if nonnegative and number < 0:
        raise ToolProtocolError(
            "数值不能为负", code="negative_quantity", path=path
        )
    return number


def json_number(value: Decimal | float | int) -> int | float:
    number = float(value)
    if not math.isfinite(number):
        raise ToolProtocolError(
            "计算结果不是有限数", code="non_finite_result", path="$"
        )
    if number == 0:
        return 0
    if isinstance(value, Decimal) and value == value.to_integral_value():
        integer = int(value)
        if abs(integer) <= 9_007_199_254_740_991:
            return integer
    return number


def conversion_factor(from_unit: str, to_unit: str) -> Decimal:
    if from_unit in MASS_FACTORS_T and to_unit in MASS_FACTORS_T:
        return MASS_FACTORS_T[from_unit] / MASS_FACTORS_T[to_unit]
    if from_unit in ENERGY_FACTORS_MJ and to_unit in ENERGY_FACTORS_MJ:
        return ENERGY_FACTORS_MJ[from_unit] / ENERGY_FACTORS_MJ[to_unit]
    raise ToolProtocolError(
        f"不支持从 {from_unit} 转换到 {to_unit}，或单位维度不一致",
        code="unsupported_unit_conversion",
        path="$.to_unit",
    )


def convert(value: Any, from_unit: str, to_unit: str, path: str) -> Decimal:
    number = finite_decimal(value, path)
    result = number * conversion_factor(from_unit, to_unit)
    if abs(result) > Decimal("1e18"):
        raise ToolProtocolError(
            "换算结果超出安全范围", code="conversion_out_of_range", path=path
        )
    return result


def observation_values(
    value: Mapping[str, Any],
    metric_code: str,
) -> list[tuple[dict[str, Any], Decimal]]:
    results: list[tuple[dict[str, Any], Decimal]] = []
    for index, observation in enumerate(value.get("observations", [])):
        if not isinstance(observation, dict):
            continue
        if observation.get("metric_code") != metric_code:
            continue
        number = finite_decimal(
            observation.get("value"), f"$.draft.observations[{index}].value"
        )
        results.append((observation, number))
    return results


def total_metric(
    value: Mapping[str, Any],
    metric_code: str,
) -> tuple[Decimal | None, str | None, list[str]]:
    rows = observation_values(value, metric_code)
    if not rows:
        return None, None, []
    units = {str(row.get("unit")) for row, _number in rows}
    if len(units) != 1:
        raise ToolProtocolError(
            f"指标 {metric_code} 存在多个单位，不能直接汇总",
            code="mixed_metric_units",
            path="$.metric_code",
        )
    return (
        sum((number for _row, number in rows), Decimal(0)),
        next(iter(units)),
        [str(row.get("observation_id", "")) for row, _number in rows],
    )


def percentile(values: Sequence[Decimal], probability: Decimal) -> Decimal:
    if not values:
        raise ValueError("values must not be empty")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = probability * Decimal(len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - Decimal(lower)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def decimal_median(values: Sequence[Decimal]) -> Decimal:
    return Decimal(str(median(values)))


def mad(values: Sequence[Decimal], center: Decimal | None = None) -> Decimal:
    middle = center if center is not None else decimal_median(values)
    return decimal_median([abs(value - middle) for value in values])


def parsed_time(value: Any, path: str) -> datetime:
    try:
        return parse_aware_datetime(value, path)
    except ValueError as error:
        raise ToolProtocolError(
            str(error), code="invalid_datetime", path=path
        ) from error


def bounded_strings(
    values: Iterable[Any],
    *,
    path: str,
    maximum: int,
    max_length: int = 128,
) -> list[str]:
    result = list(values)
    if len(result) > maximum:
        raise ToolProtocolError(
            "项目超过处理上限", code="too_many_items", path=path
        )
    if any(
        not isinstance(item, str)
        or not item.strip()
        or len(item) > max_length
        for item in result
    ):
        raise ToolProtocolError(
            "项目必须是有长度限制的非空字符串",
            code="invalid_string_list",
            path=path,
        )
    if len(result) != len(set(result)):
        raise ToolProtocolError(
            "项目不能重复", code="duplicate_items", path=path
        )
    return result


def public_document(value: Mapping[str, Any]) -> dict[str, Any]:
    """Drop repository metadata before deterministic validation/hashing."""

    return {
        key: child
        for key, child in value.items()
        if key not in {"_meta", "status", "receipt"}
    }


def disclaimer() -> str:
    return "仅提供确定性核对证据和不确定性，不认定数据正常、合法或可提交。"
