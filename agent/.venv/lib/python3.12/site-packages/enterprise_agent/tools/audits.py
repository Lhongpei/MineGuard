"""Read-only deterministic audits over the current draft schema.

The tools in this module deliberately avoid business-semantic aggregation.
They inspect signed-observation fields, compare same-unit point readings, and
summarize provenance metadata without exposing source signatures or document
content. Missing or incompatible evidence is reported as not evaluated.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from decimal import Decimal
from itertools import combinations
from typing import Any

from enterprise_agent.security import observation_payload
from enterprise_agent.util import sha256_json, utc_text

from .core import (
    HEX64,
    bounded_strings,
    decimal_median,
    disclaimer,
    draft,
    finite_decimal,
    json_number,
    parsed_time,
    public_document,
)
from .protocol import (
    ToolContext,
    ToolResult,
    ToolSpec,
    strict_object,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_ID = {
    "type": "string",
    "minLength": 1,
    "maxLength": 256,
    "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}",
}
_SOURCE_ID = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
}
_METRIC = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
}
_STATUS = {
    "type": "string",
    "enum": ["evaluated", "partial", "not_evaluated"],
}
_NULLABLE_NUMBER = {"type": ["number", "null"]}
_NULLABLE_INTEGER = {"type": ["integer", "null"]}
_NULLABLE_TEXT = {"type": ["string", "null"]}
_COUNT = {"type": "integer", "minimum": 0}
_SHA256 = {"type": "string", "pattern": r"[0-9a-f]{64}"}
_DISCLAIMER = {"type": "string", "minLength": 1, "maxLength": 256}
_GOVERNANCE = {"type": "boolean", "enum": [True]}
_MAX_RETURNED_SERIES = 100
_MAX_RETURNED_EVIDENCE_IDS = 100
_MAX_RETURNED_LINEAGE = 100
_MAX_RETURNED_MATCHES_PER_PAIR = 20
_MAX_COMPARE_SOURCES = 4
_CONTINUITY_ALGORITHM = "observation_continuity_v1"
_CONSISTENCY_ALGORITHM = "ordered_point_consistency_v1"
_LINEAGE_ALGORITHM = "provenance_lineage_v1"
_OBSERVATION_FIELDS = (
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
)


def _bounded(
    values: Sequence[Any],
    maximum: int,
) -> tuple[list[Any], int, bool, str]:
    material = list(values)
    return (
        material[:maximum],
        len(material),
        len(material) > maximum,
        sha256_json(material),
    )


def _id_evidence(
    values: Sequence[str],
    maximum: int = _MAX_RETURNED_EVIDENCE_IDS,
) -> dict[str, Any]:
    material = list(dict.fromkeys(values))
    returned, count, truncated, digest = _bounded(material, maximum)
    return {
        "observation_ids": returned,
        "count": count,
        "returned_count": len(returned),
        "truncated": truncated,
        "sha256": digest,
    }


def _id_collection(
    values: Sequence[str],
    maximum: int = _MAX_RETURNED_EVIDENCE_IDS,
) -> dict[str, Any]:
    material = list(dict.fromkeys(values))
    returned, count, truncated, digest = _bounded(material, maximum)
    return {
        "ids": returned,
        "count": count,
        "returned_count": len(returned),
        "truncated": truncated,
        "sha256": digest,
    }


def _valid_identifier(value: Any, maximum: int) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _IDENTIFIER.fullmatch(value) is None
    ):
        return None
    return value


def _valid_unit(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > 32:
        return None
    return value


def _revision(document: Mapping[str, Any]) -> int:
    metadata = document.get("_meta")
    if not isinstance(metadata, Mapping):
        return 0
    value = metadata.get("revision")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _requested(
    arguments: Mapping[str, Any],
    key: str,
    *,
    maximum: int,
    max_length: int,
) -> list[str] | None:
    raw = arguments.get(key)
    if raw is None:
        return None
    return bounded_strings(
        raw,
        path=f"$.{key}",
        maximum=maximum,
        max_length=max_length,
    )


def _base_output(
    document: Mapping[str, Any],
    *,
    status: str,
    algorithm_version: str,
    evidence_ids: Sequence[str],
) -> dict[str, Any]:
    return {
        "status": status,
        "draft_id": str(document.get("draft_id", "")),
        "revision": _revision(document),
        "window_start": str(document.get("window_start", "")),
        "window_end": str(document.get("window_end", "")),
        "document_sha256": sha256_json(public_document(document)),
        "algorithm_version": algorithm_version,
        "evidence": _id_evidence(evidence_ids),
    }


def _safe_label(value: Any) -> str:
    if (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None
    ):
        return value
    return "invalid_or_unbounded"


def _count_rows(counter: Counter[str]) -> list[dict[str, Any]]:
    return [{"value": key, "count": counter[key]} for key in sorted(counter)]


def _continuity_record(
    source_id: str,
    metric_code: str,
    rows: Sequence[tuple[int, Mapping[str, Any]]],
    *,
    max_gap_seconds: int | None,
    max_receive_delay_seconds: int | None,
) -> dict[str, Any]:
    evidence_ids = [
        observation_id
        for _index, row in rows
        if (observation_id := _valid_identifier(row.get("observation_id"), 256))
        is not None
    ]
    units = sorted(
        {
            unit
            for _index, row in rows
            if (unit := _valid_unit(row.get("unit"))) is not None
        }
    )
    invalid_count = 0
    parsed_rows: list[dict[str, Any]] = []
    for index, row in rows:
        observation_id = _valid_identifier(row.get("observation_id"), 256)
        unit = _valid_unit(row.get("unit"))
        sequence_no = row.get("sequence_no")
        revision = row.get("revision")
        reset_before = row.get("reset_before")
        if (
            observation_id is None
            or unit is None
            or isinstance(sequence_no, bool)
            or not isinstance(sequence_no, int)
            or sequence_no < 0
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 0
            or not isinstance(reset_before, bool)
        ):
            invalid_count += 1
            continue
        try:
            observed_at = parsed_time(
                row.get("observed_at"),
                f"$.draft.observations[{index}].observed_at",
            )
            received_at = parsed_time(
                row.get("received_at"),
                f"$.draft.observations[{index}].received_at",
            )
        except Exception:
            invalid_count += 1
            continue
        if received_at < observed_at:
            invalid_count += 1
            continue
        parsed_rows.append(
            {
                "observation_id": observation_id,
                "unit": unit,
                "sequence_no": sequence_no,
                "revision": revision,
                "reset_before": reset_before,
                "observed_at": observed_at,
                "received_at": received_at,
            }
        )

    reason: str
    if len(rows) < 2:
        reason = "至少需要两条同来源同指标观测"
    elif invalid_count:
        reason = "存在缺失或格式无效的连续性字段，未忽略后强行评价"
    elif len(units) != 1:
        reason = "同来源同指标存在混合单位，未合并为一条序列"
    else:
        reason = ""
    if reason:
        return {
            "source_id": source_id,
            "metric_code": metric_code,
            "status": "not_evaluated",
            "reason": reason,
            "unit": units[0] if len(units) == 1 else None,
            "units": units,
            "point_count": len(rows),
            "invalid_point_count": invalid_count,
            "first_observed_at": None,
            "last_observed_at": None,
            "duplicate_sequence_count": None,
            "sequence_gap_count": None,
            "missing_sequence_number_count": None,
            "sequence_regression_count": None,
            "duplicate_observed_at_count": None,
            "reset_count": None,
            "revision_conflict_count": None,
            "max_observed_gap_seconds": None,
            "time_gap_exceedance_count": None,
            "max_receive_delay_seconds": None,
            "receive_delay_exceedance_count": None,
            "finding_count": None,
            "evidence": _id_evidence(evidence_ids),
            "issue_evidence": _id_evidence([]),
        }

    parsed_rows.sort(
        key=lambda item: (
            item["observed_at"],
            item["sequence_no"],
            item["revision"],
            item["observation_id"],
        )
    )
    duplicate_sequence_count = 0
    sequence_gap_count = 0
    missing_sequence_number_count = 0
    sequence_regression_count = 0
    duplicate_observed_at_count = 0
    revision_conflict_count = 0
    time_gap_exceedance_count = 0
    receive_delay_exceedance_count = 0
    observed_gaps: list[float] = []
    receive_delays: list[float] = []
    issue_ids: list[str] = []
    seen_sequence_revisions: set[tuple[int, int]] = set()

    for position, item in enumerate(parsed_rows):
        key = (item["sequence_no"], item["revision"])
        if key in seen_sequence_revisions:
            revision_conflict_count += 1
            issue_ids.append(item["observation_id"])
        seen_sequence_revisions.add(key)
        delay = (item["received_at"] - item["observed_at"]).total_seconds()
        receive_delays.append(delay)
        if max_receive_delay_seconds is not None and delay > max_receive_delay_seconds:
            receive_delay_exceedance_count += 1
            issue_ids.append(item["observation_id"])
        if position == 0:
            continue
        previous = parsed_rows[position - 1]
        observed_gap = (item["observed_at"] - previous["observed_at"]).total_seconds()
        observed_gaps.append(observed_gap)
        if observed_gap == 0:
            duplicate_observed_at_count += 1
            issue_ids.extend([previous["observation_id"], item["observation_id"]])
        if max_gap_seconds is not None and observed_gap > max_gap_seconds:
            time_gap_exceedance_count += 1
            issue_ids.extend([previous["observation_id"], item["observation_id"]])
        if item["reset_before"]:
            continue
        difference = item["sequence_no"] - previous["sequence_no"]
        if difference == 0:
            duplicate_sequence_count += 1
            issue_ids.extend([previous["observation_id"], item["observation_id"]])
        elif difference < 0:
            sequence_regression_count += 1
            issue_ids.extend([previous["observation_id"], item["observation_id"]])
        elif difference > 1:
            sequence_gap_count += 1
            missing_sequence_number_count += difference - 1
            issue_ids.extend([previous["observation_id"], item["observation_id"]])

    finding_count = (
        duplicate_sequence_count
        + sequence_gap_count
        + sequence_regression_count
        + duplicate_observed_at_count
        + revision_conflict_count
        + time_gap_exceedance_count
        + receive_delay_exceedance_count
    )
    return {
        "source_id": source_id,
        "metric_code": metric_code,
        "status": "evaluated",
        "reason": (
            "已完成描述性连续性核对；发现项不等同于设备故障"
            if finding_count
            else "已完成描述性连续性核对，未发现所列结构性间断"
        ),
        "unit": units[0],
        "units": units,
        "point_count": len(parsed_rows),
        "invalid_point_count": 0,
        "first_observed_at": utc_text(parsed_rows[0]["observed_at"]),
        "last_observed_at": utc_text(parsed_rows[-1]["observed_at"]),
        "duplicate_sequence_count": duplicate_sequence_count,
        "sequence_gap_count": sequence_gap_count,
        "missing_sequence_number_count": missing_sequence_number_count,
        "sequence_regression_count": sequence_regression_count,
        "duplicate_observed_at_count": duplicate_observed_at_count,
        "reset_count": sum(bool(item["reset_before"]) for item in parsed_rows),
        "revision_conflict_count": revision_conflict_count,
        "max_observed_gap_seconds": max(observed_gaps, default=0),
        "time_gap_exceedance_count": (
            time_gap_exceedance_count if max_gap_seconds is not None else None
        ),
        "max_receive_delay_seconds": max(receive_delays, default=0),
        "receive_delay_exceedance_count": (
            receive_delay_exceedance_count
            if max_receive_delay_seconds is not None
            else None
        ),
        "finding_count": finding_count,
        "evidence": _id_evidence(evidence_ids),
        "issue_evidence": _id_evidence(issue_ids),
    }


def _inspect_observation_continuity(
    arguments: Mapping[str, Any],
    context: ToolContext,
) -> ToolResult:
    document = draft(context, str(arguments["draft_id"]))
    requested_sources = _requested(
        arguments,
        "source_ids",
        maximum=64,
        max_length=128,
    )
    requested_metrics = _requested(
        arguments,
        "metric_codes",
        maximum=64,
        max_length=128,
    )
    source_filter = set(requested_sources) if requested_sources is not None else None
    metric_filter = set(requested_metrics) if requested_metrics is not None else None
    max_gap_seconds = arguments.get("max_gap_seconds")
    max_receive_delay_seconds = arguments.get("max_receive_delay_seconds")
    groups: dict[
        tuple[str, str],
        list[tuple[int, Mapping[str, Any]]],
    ] = defaultdict(list)
    all_sources: set[str] = set()
    all_metrics: set[str] = set()
    evidence_ids: list[str] = []
    excluded_observation_count = 0

    for index, raw in enumerate(document["observations"]):
        if not isinstance(raw, Mapping):
            excluded_observation_count += 1
            continue
        source_id = _valid_identifier(raw.get("source_id"), 128)
        metric_code = _valid_identifier(raw.get("metric_code"), 128)
        if source_id is None or metric_code is None:
            excluded_observation_count += 1
            continue
        all_sources.add(source_id)
        all_metrics.add(metric_code)
        if source_filter is not None and source_id not in source_filter:
            continue
        if metric_filter is not None and metric_code not in metric_filter:
            continue
        groups[(source_id, metric_code)].append((index, raw))
        observation_id = _valid_identifier(raw.get("observation_id"), 256)
        if observation_id is not None:
            evidence_ids.append(observation_id)

    records = [
        _continuity_record(
            source_id,
            metric_code,
            rows,
            max_gap_seconds=(
                int(max_gap_seconds) if max_gap_seconds is not None else None
            ),
            max_receive_delay_seconds=(
                int(max_receive_delay_seconds)
                if max_receive_delay_seconds is not None
                else None
            ),
        )
        for (source_id, metric_code), rows in sorted(groups.items())
    ]
    evaluated_count = sum(item["status"] == "evaluated" for item in records)
    not_evaluated_count = len(records) - evaluated_count
    missing_sources = sorted(set(requested_sources or ()) - all_sources)
    missing_metrics = sorted(set(requested_metrics or ()) - all_metrics)
    if not records or evaluated_count == 0:
        status = "not_evaluated"
        reason = "没有足够的同来源同指标观测可执行连续性核对"
    elif (
        not_evaluated_count
        or excluded_observation_count
        or missing_sources
        or missing_metrics
    ):
        status = "partial"
        reason = "部分序列因缺项、混合单位或筛选项不存在而未评价"
    else:
        status = "evaluated"
        reason = "所有选中序列均已完成描述性连续性核对"
    returned, count, truncated, digest = _bounded(
        records,
        _MAX_RETURNED_SERIES,
    )
    data = {
        **_base_output(
            document,
            status=status,
            algorithm_version=_CONTINUITY_ALGORITHM,
            evidence_ids=evidence_ids,
        ),
        "reason": reason,
        "selected_observation_count": sum(len(rows) for rows in groups.values()),
        "excluded_observation_count": excluded_observation_count,
        "evaluated_series_count": evaluated_count,
        "not_evaluated_series_count": not_evaluated_count,
        "series": returned,
        "series_count": count,
        "returned_series_count": len(returned),
        "series_truncated": truncated,
        "series_sha256": digest,
        "missing_requested_source_ids": missing_sources,
        "missing_requested_metric_codes": missing_metrics,
        "thresholds": {
            "max_gap_seconds": max_gap_seconds,
            "max_receive_delay_seconds": max_receive_delay_seconds,
            "origin": (
                "caller_supplied"
                if (
                    max_gap_seconds is not None or max_receive_delay_seconds is not None
                )
                else "none"
            ),
        },
        "uncertainty": {
            "sequence_assignment_policy_verified": False,
            "device_calibration_checked": False,
            "cryptographic_signature_verification_performed": False,
            "causality_determined": False,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"连续性核对状态：{status}；{count} 条序列中 "
            f"{evaluated_count} 条已评价、{not_evaluated_count} 条未评价。"
        ),
    )


def _parsed_comparison_rows(
    rows: Sequence[tuple[int, Mapping[str, Any]]],
) -> tuple[list[dict[str, Any]], list[str], int]:
    parsed: list[dict[str, Any]] = []
    evidence_ids: list[str] = []
    invalid_count = 0
    for index, row in rows:
        observation_id = _valid_identifier(row.get("observation_id"), 256)
        unit = _valid_unit(row.get("unit"))
        if observation_id is not None:
            evidence_ids.append(observation_id)
        if observation_id is None or unit is None:
            invalid_count += 1
            continue
        try:
            observed_at = parsed_time(
                row.get("observed_at"),
                f"$.draft.observations[{index}].observed_at",
            )
            number = finite_decimal(
                row.get("value"),
                f"$.draft.observations[{index}].value",
            )
        except Exception:
            invalid_count += 1
            continue
        parsed.append(
            {
                "observation_id": observation_id,
                "observed_at": observed_at,
                "value": number,
                "unit": unit,
            }
        )
    parsed.sort(key=lambda item: (item["observed_at"], item["observation_id"]))
    return parsed, evidence_ids, invalid_count


def _ordered_matches(
    left: Sequence[dict[str, Any]],
    right: Sequence[dict[str, Any]],
    tolerance_seconds: int,
) -> tuple[list[dict[str, Any]], int, int, int]:
    matches: list[dict[str, Any]] = []
    left_index = 0
    right_index = 0
    unmatched_left = 0
    unmatched_right = 0
    zero_scale_count = 0
    while left_index < len(left) and right_index < len(right):
        left_item = left[left_index]
        right_item = right[right_index]
        signed_time_delta = (
            left_item["observed_at"] - right_item["observed_at"]
        ).total_seconds()
        if abs(signed_time_delta) <= tolerance_seconds:
            signed_difference = left_item["value"] - right_item["value"]
            absolute_difference = abs(signed_difference)
            scale = max(abs(left_item["value"]), abs(right_item["value"]))
            if scale == 0:
                relative_difference = None
                zero_scale_count += 1
            else:
                relative_difference = absolute_difference / scale
            matches.append(
                {
                    "left_observation_id": left_item["observation_id"],
                    "right_observation_id": right_item["observation_id"],
                    "left_observed_at": utc_text(left_item["observed_at"]),
                    "right_observed_at": utc_text(right_item["observed_at"]),
                    "signed_time_delta_seconds": signed_time_delta,
                    "signed_difference": json_number(signed_difference),
                    "absolute_difference": json_number(absolute_difference),
                    "relative_difference": (
                        json_number(relative_difference)
                        if relative_difference is not None
                        else None
                    ),
                }
            )
            left_index += 1
            right_index += 1
        elif signed_time_delta < 0:
            unmatched_left += 1
            left_index += 1
        else:
            unmatched_right += 1
            right_index += 1
    unmatched_left += len(left) - left_index
    unmatched_right += len(right) - right_index
    return matches, unmatched_left, unmatched_right, zero_scale_count


def _source_pair_record(
    left_source_id: str,
    right_source_id: str,
    left_rows: Sequence[dict[str, Any]],
    right_rows: Sequence[dict[str, Any]],
    *,
    left_invalid_count: int,
    right_invalid_count: int,
    time_tolerance_seconds: int,
) -> dict[str, Any]:
    evidence_ids = [
        *(str(item["observation_id"]) for item in left_rows),
        *(str(item["observation_id"]) for item in right_rows),
    ]
    left_units = sorted({str(item["unit"]) for item in left_rows})
    right_units = sorted({str(item["unit"]) for item in right_rows})
    combined_units = sorted(set(left_units) | set(right_units))
    reason = ""
    if left_invalid_count or right_invalid_count:
        reason = "至少一个来源存在无效观测，未忽略后强行比较"
    elif not left_rows or not right_rows:
        reason = "至少一个来源没有可比较观测"
    elif len(left_units) != 1 or len(right_units) != 1:
        reason = "至少一个来源内部存在混合单位"
    elif left_units[0] != right_units[0]:
        reason = "两个来源单位不同，未自动换算或合并"
    if reason:
        return {
            "left_source_id": left_source_id,
            "right_source_id": right_source_id,
            "status": "not_evaluated",
            "reason": reason,
            "unit": None,
            "units": combined_units,
            "left_point_count": len(left_rows) + left_invalid_count,
            "right_point_count": len(right_rows) + right_invalid_count,
            "invalid_point_count": left_invalid_count + right_invalid_count,
            "matched_pair_count": 0,
            "unmatched_left_count": len(left_rows),
            "unmatched_right_count": len(right_rows),
            "zero_scale_pair_count": 0,
            "median_absolute_difference": None,
            "maximum_absolute_difference": None,
            "median_relative_difference": None,
            "maximum_relative_difference": None,
            "matches": [],
            "returned_match_count": 0,
            "matches_truncated": False,
            "matches_sha256": sha256_json([]),
            "evidence": _id_evidence(evidence_ids),
        }
    matches, unmatched_left, unmatched_right, zero_scale_count = _ordered_matches(
        left_rows,
        right_rows,
        time_tolerance_seconds,
    )
    if not matches:
        return {
            "left_source_id": left_source_id,
            "right_source_id": right_source_id,
            "status": "not_evaluated",
            "reason": "所给时间容差内没有一对可比较观测",
            "unit": left_units[0],
            "units": combined_units,
            "left_point_count": len(left_rows),
            "right_point_count": len(right_rows),
            "invalid_point_count": 0,
            "matched_pair_count": 0,
            "unmatched_left_count": unmatched_left,
            "unmatched_right_count": unmatched_right,
            "zero_scale_pair_count": 0,
            "median_absolute_difference": None,
            "maximum_absolute_difference": None,
            "median_relative_difference": None,
            "maximum_relative_difference": None,
            "matches": [],
            "returned_match_count": 0,
            "matches_truncated": False,
            "matches_sha256": sha256_json([]),
            "evidence": _id_evidence(evidence_ids),
        }
    absolute = [Decimal(str(item["absolute_difference"])) for item in matches]
    relative = [
        Decimal(str(item["relative_difference"]))
        for item in matches
        if item["relative_difference"] is not None
    ]
    returned, match_count, truncated, matches_sha256 = _bounded(
        matches,
        _MAX_RETURNED_MATCHES_PER_PAIR,
    )
    return {
        "left_source_id": left_source_id,
        "right_source_id": right_source_id,
        "status": "evaluated",
        "reason": ("完成同指标同单位的有序一对一时间近邻比较；未判定原因或合格性"),
        "unit": left_units[0],
        "units": combined_units,
        "left_point_count": len(left_rows),
        "right_point_count": len(right_rows),
        "invalid_point_count": 0,
        "matched_pair_count": match_count,
        "unmatched_left_count": unmatched_left,
        "unmatched_right_count": unmatched_right,
        "zero_scale_pair_count": zero_scale_count,
        "median_absolute_difference": json_number(decimal_median(absolute)),
        "maximum_absolute_difference": json_number(max(absolute)),
        "median_relative_difference": (
            json_number(decimal_median(relative)) if relative else None
        ),
        "maximum_relative_difference": (
            json_number(max(relative)) if relative else None
        ),
        "matches": returned,
        "returned_match_count": len(returned),
        "matches_truncated": truncated,
        "matches_sha256": matches_sha256,
        "evidence": _id_evidence(evidence_ids),
    }


def _compare_source_consistency(
    arguments: Mapping[str, Any],
    context: ToolContext,
) -> ToolResult:
    document = draft(context, str(arguments["draft_id"]))
    metric_code = str(arguments["metric_code"])
    requested_sources = _requested(
        arguments,
        "source_ids",
        maximum=_MAX_COMPARE_SOURCES,
        max_length=128,
    )
    time_tolerance_seconds = int(arguments.get("time_tolerance_seconds", 300))
    grouped: dict[str, list[tuple[int, Mapping[str, Any]]]] = defaultdict(list)
    all_metric_source_ids: set[str] = set()
    all_metric_evidence_ids: list[str] = []
    excluded_observation_count = 0
    for index, raw in enumerate(document["observations"]):
        if not isinstance(raw, Mapping) or raw.get("metric_code") != metric_code:
            continue
        source_id = _valid_identifier(raw.get("source_id"), 128)
        if source_id is None:
            excluded_observation_count += 1
            continue
        all_metric_source_ids.add(source_id)
        observation_id = _valid_identifier(raw.get("observation_id"), 256)
        if observation_id is not None:
            all_metric_evidence_ids.append(observation_id)
        grouped[source_id].append((index, raw))

    selected_sources = (
        list(requested_sources)
        if requested_sources is not None
        else sorted(all_metric_source_ids)
    )
    too_many_implicit_sources = (
        requested_sources is None and len(selected_sources) > _MAX_COMPARE_SOURCES
    )
    if too_many_implicit_sources:
        selected_sources = []
    missing_sources = sorted(set(requested_sources or ()) - all_metric_source_ids)
    parsed_by_source: dict[str, list[dict[str, Any]]] = {}
    invalid_by_source: dict[str, int] = {}
    evidence_by_source: dict[str, list[str]] = {}
    source_summaries: list[dict[str, Any]] = []
    for source_id in selected_sources:
        parsed, evidence_ids, invalid_count = _parsed_comparison_rows(
            grouped.get(source_id, [])
        )
        parsed_by_source[source_id] = parsed
        invalid_by_source[source_id] = invalid_count
        evidence_by_source[source_id] = evidence_ids
        source_summaries.append(
            {
                "source_id": source_id,
                "point_count": len(grouped.get(source_id, [])),
                "valid_point_count": len(parsed),
                "invalid_point_count": invalid_count,
                "units": sorted({str(item["unit"]) for item in parsed}),
                "evidence": _id_evidence(evidence_ids),
            }
        )

    pairs = [
        _source_pair_record(
            left_source,
            right_source,
            parsed_by_source[left_source],
            parsed_by_source[right_source],
            left_invalid_count=invalid_by_source[left_source],
            right_invalid_count=invalid_by_source[right_source],
            time_tolerance_seconds=time_tolerance_seconds,
        )
        for left_source, right_source in combinations(selected_sources, 2)
    ]
    evaluated_pair_count = sum(item["status"] == "evaluated" for item in pairs)
    not_evaluated_pair_count = len(pairs) - evaluated_pair_count
    selected_evidence = [
        observation_id
        for source_id in selected_sources
        for observation_id in evidence_by_source[source_id]
    ]
    if too_many_implicit_sources:
        status = "not_evaluated"
        reason = (
            f"指标包含超过 {_MAX_COMPARE_SOURCES} 个来源，必须显式选择有限来源后再比较"
        )
    elif len(selected_sources) < 2:
        status = "not_evaluated"
        reason = "同一指标至少需要两个已选来源"
    elif evaluated_pair_count == 0:
        status = "not_evaluated"
        reason = "没有来源对满足同单位且可在时间容差内配对"
    elif not_evaluated_pair_count or missing_sources or excluded_observation_count:
        status = "partial"
        reason = "部分来源对因缺项、混合单位或没有时间配对而未评价"
    else:
        status = "evaluated"
        reason = "所有选中来源对均完成描述性一致性比较"
    data = {
        **_base_output(
            document,
            status=status,
            algorithm_version=_CONSISTENCY_ALGORITHM,
            evidence_ids=(
                selected_evidence if selected_sources else all_metric_evidence_ids
            ),
        ),
        "reason": reason,
        "metric_code": metric_code,
        "time_tolerance_seconds": time_tolerance_seconds,
        "time_tolerance_origin": (
            "caller_supplied"
            if "time_tolerance_seconds" in arguments
            else "tool_default"
        ),
        "selected_source_count": len(selected_sources),
        "available_source_count": len(all_metric_source_ids),
        "excluded_observation_count": excluded_observation_count,
        "missing_requested_source_ids": missing_sources,
        "too_many_implicit_sources": too_many_implicit_sources,
        "sources": source_summaries,
        "source_count": len(source_summaries),
        "pairs": pairs,
        "pair_count": len(pairs),
        "evaluated_pair_count": evaluated_pair_count,
        "not_evaluated_pair_count": not_evaluated_pair_count,
        "uncertainty": {
            "aggregation_performed": False,
            "automatic_unit_conversion": False,
            "metric_code_source_authenticated": False,
            "source_equivalence_verified": False,
            "device_calibration_checked": False,
            "causality_determined": False,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"来源一致性状态：{status}；{len(pairs)} 个来源对中 "
            f"{evaluated_pair_count} 个已评价。"
        ),
    )


def _lineage_record(
    index: int,
    observation: Mapping[str, Any],
    provenance: Mapping[str, Any],
    import_ids_by_hash: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    observation_id = _valid_identifier(observation.get("observation_id"), 256)
    source_id = _valid_identifier(observation.get("source_id"), 128)
    field_count = 0
    provenance_record_count = 0
    invalid_provenance_record_count = 0
    invalid_content_sha256_count = 0
    source_kinds: list[str] = []
    extraction_methods: list[str] = []
    content_hashes: list[str] = []
    for field in _OBSERVATION_FIELDS:
        records = provenance.get(f"/observations/{index}/{field}")
        if not isinstance(records, list) or not records:
            continue
        field_count += 1
        for raw_record in records:
            provenance_record_count += 1
            if not isinstance(raw_record, Mapping):
                invalid_provenance_record_count += 1
                continue
            source_kinds.append(_safe_label(raw_record.get("source_kind")))
            extraction_methods.append(_safe_label(raw_record.get("extraction_method")))
            content_sha256 = raw_record.get("content_sha256")
            if (
                isinstance(content_sha256, str)
                and HEX64.fullmatch(content_sha256) is not None
            ):
                content_hashes.append(content_sha256)
            else:
                invalid_content_sha256_count += 1
    unique_hashes = sorted(set(content_hashes))
    matched_import_ids = sorted(
        {
            import_id
            for content_hash in unique_hashes
            for import_id in import_ids_by_hash.get(content_hash, ())
        }
    )
    unmatched_hashes = sorted(
        content_hash
        for content_hash in unique_hashes
        if content_hash not in import_ids_by_hash
    )
    digest = observation.get("payload_sha256")
    signature = observation.get("signature")
    payload_digest_format_valid = (
        isinstance(digest, str) and HEX64.fullmatch(digest) is not None
    )
    try:
        expected_digest = sha256_json(observation_payload(dict(observation)))
    except (KeyError, TypeError, ValueError):
        expected_digest = None
    payload_digest_matches = (
        payload_digest_format_valid
        and expected_digest is not None
        and digest == expected_digest
    )
    signature_format_valid = (
        isinstance(signature, str) and HEX64.fullmatch(signature) is not None
    )
    if provenance_record_count == 0:
        status = "not_evaluated"
        reason = "没有可汇总的字段来源记录"
    elif (
        observation_id is None
        or source_id is None
        or field_count < len(_OBSERVATION_FIELDS)
        or invalid_provenance_record_count
        or invalid_content_sha256_count
        or not payload_digest_matches
        or not signature_format_valid
    ):
        status = "partial"
        reason = "来源元数据、载荷摘要或签名格式存在缺项，未补写缺失证据"
    else:
        status = "evaluated"
        reason = "已汇总现有字段来源元数据；未执行来源密钥验签"
    source_kind_collection = _id_collection(sorted(set(source_kinds)))
    extraction_method_collection = _id_collection(sorted(set(extraction_methods)))
    content_hash_collection = _id_collection(unique_hashes)
    matched_import_collection = _id_collection(matched_import_ids)
    unmatched_hash_collection = _id_collection(unmatched_hashes)
    return {
        "observation_id": observation_id,
        "source_id": source_id,
        "status": status,
        "reason": reason,
        "provenance_fields_present": field_count,
        "provenance_fields_expected": len(_OBSERVATION_FIELDS),
        "provenance_record_count": provenance_record_count,
        "invalid_provenance_record_count": invalid_provenance_record_count,
        "invalid_content_sha256_count": invalid_content_sha256_count,
        "payload_digest_format_valid": payload_digest_format_valid,
        "payload_digest_matches": payload_digest_matches,
        "signature_format_valid": signature_format_valid,
        "signature_cryptographically_verified": False,
        "source_kinds": source_kind_collection,
        "extraction_methods": extraction_method_collection,
        "content_sha256s": content_hash_collection,
        "matched_import_ids": matched_import_collection,
        "unmatched_content_sha256s": unmatched_hash_collection,
    }


def _summarize_provenance_lineage(
    arguments: Mapping[str, Any],
    context: ToolContext,
) -> ToolResult:
    document = draft(context, str(arguments["draft_id"]))
    requested_ids = _requested(
        arguments,
        "observation_ids",
        maximum=100,
        max_length=256,
    )
    requested_set = set(requested_ids) if requested_ids is not None else None
    provenance = document.get("field_provenance")
    if not isinstance(provenance, Mapping):
        provenance = {}
    imports = document.get("imports")
    if not isinstance(imports, list):
        imports = []
    import_ids_by_hash: dict[str, list[str]] = defaultdict(list)
    valid_manifest_entry_count = 0
    invalid_manifest_entry_count = 0
    for item in imports:
        if not isinstance(item, Mapping):
            invalid_manifest_entry_count += 1
            continue
        import_id = _valid_identifier(item.get("id"), 256)
        content_sha256 = item.get("content_sha256")
        if (
            import_id is None
            or not isinstance(content_sha256, str)
            or HEX64.fullmatch(content_sha256) is None
        ):
            invalid_manifest_entry_count += 1
            continue
        valid_manifest_entry_count += 1
        import_ids_by_hash[content_sha256].append(import_id)

    records: list[dict[str, Any]] = []
    selected_ids: list[str] = []
    seen_ids: set[str] = set()
    invalid_observation_count = 0
    source_kind_counts: Counter[str] = Counter()
    extraction_method_counts: Counter[str] = Counter()
    for index, raw in enumerate(document["observations"]):
        if not isinstance(raw, Mapping):
            invalid_observation_count += 1
            continue
        observation_id = _valid_identifier(raw.get("observation_id"), 256)
        if observation_id is None:
            invalid_observation_count += 1
            continue
        seen_ids.add(observation_id)
        if requested_set is not None and observation_id not in requested_set:
            continue
        selected_ids.append(observation_id)
        record = _lineage_record(
            index,
            raw,
            provenance,
            import_ids_by_hash,
        )
        records.append(record)
        for source_kind in record["source_kinds"]["ids"]:
            source_kind_counts[str(source_kind)] += 1
        for method in record["extraction_methods"]["ids"]:
            extraction_method_counts[str(method)] += 1

    missing_ids = sorted(set(requested_ids or ()) - seen_ids)
    evaluated_count = sum(item["status"] == "evaluated" for item in records)
    partial_count = sum(item["status"] == "partial" for item in records)
    not_evaluated_count = sum(item["status"] == "not_evaluated" for item in records)
    if not records or (evaluated_count == 0 and partial_count == 0):
        status = "not_evaluated"
        reason = "没有可汇总的选中观测来源记录"
    elif (
        partial_count
        or not_evaluated_count
        or missing_ids
        or invalid_observation_count
        or invalid_manifest_entry_count
    ):
        status = "partial"
        reason = "部分来源链存在缺项或格式问题，未补写或推断缺失证据"
    else:
        status = "evaluated"
        reason = "已汇总所有选中观测的现有来源元数据"
    returned, record_count, truncated, records_sha256 = _bounded(
        records,
        _MAX_RETURNED_LINEAGE,
    )
    data = {
        **_base_output(
            document,
            status=status,
            algorithm_version=_LINEAGE_ALGORITHM,
            evidence_ids=selected_ids,
        ),
        "reason": reason,
        "selected_observation_count": len(selected_ids),
        "invalid_observation_count": invalid_observation_count,
        "missing_requested_observation_ids": missing_ids,
        "lineage_records": returned,
        "lineage_record_count": record_count,
        "returned_lineage_record_count": len(returned),
        "lineage_records_truncated": truncated,
        "lineage_records_sha256": records_sha256,
        "evaluated_lineage_count": evaluated_count,
        "partial_lineage_count": partial_count,
        "not_evaluated_lineage_count": not_evaluated_count,
        "manifest_entry_count": len(imports),
        "valid_manifest_entry_count": valid_manifest_entry_count,
        "invalid_manifest_entry_count": invalid_manifest_entry_count,
        "source_kind_counts": _count_rows(source_kind_counts),
        "extraction_method_counts": _count_rows(extraction_method_counts),
        "uncertainty": {
            "cryptographic_signature_verification_performed": False,
            "source_document_content_read": False,
            "metric_code_source_authenticated": False,
            "import_manifest_is_bounded": True,
            "unmatched_hash_proves_missing_source": False,
        },
        "disclaimer": disclaimer(),
    }
    return ToolResult(
        data=data,
        summary=(
            f"来源血缘汇总状态：{status}；{record_count} 条观测中 "
            f"{evaluated_count} 条已完整汇总、{partial_count} 条部分汇总。"
        ),
    )


def _id_evidence_schema() -> dict[str, Any]:
    return strict_object(
        {
            "observation_ids": {
                "type": "array",
                "maxItems": _MAX_RETURNED_EVIDENCE_IDS,
                "uniqueItems": True,
                "items": _ID,
            },
            "count": _COUNT,
            "returned_count": _COUNT,
            "truncated": {"type": "boolean"},
            "sha256": _SHA256,
        },
        required=(
            "observation_ids",
            "count",
            "returned_count",
            "truncated",
            "sha256",
        ),
    )


def _id_collection_schema(
    *,
    maximum: int = _MAX_RETURNED_EVIDENCE_IDS,
    item_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return strict_object(
        {
            "ids": {
                "type": "array",
                "maxItems": maximum,
                "uniqueItems": True,
                "items": item_schema or _ID,
            },
            "count": _COUNT,
            "returned_count": _COUNT,
            "truncated": {"type": "boolean"},
            "sha256": _SHA256,
        },
        required=("ids", "count", "returned_count", "truncated", "sha256"),
    )


def _common_output(properties: Mapping[str, Any]) -> dict[str, Any]:
    common = {
        "status": _STATUS,
        "draft_id": {"type": "string", "minLength": 1, "maxLength": 256},
        "revision": _COUNT,
        "window_start": {"type": "string", "maxLength": 64},
        "window_end": {"type": "string", "maxLength": 64},
        "document_sha256": _SHA256,
        "algorithm_version": {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
        },
        "evidence": _id_evidence_schema(),
        **dict(properties),
        "disclaimer": _DISCLAIMER,
        "not_a_regulatory_determination": _GOVERNANCE,
    }
    return strict_object(common, required=tuple(common))


def _continuity_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    input_schema = strict_object(
        {
            "draft_id": _ID,
            "source_ids": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "uniqueItems": True,
                "items": _SOURCE_ID,
            },
            "metric_codes": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "uniqueItems": True,
                "items": _METRIC,
            },
            "max_gap_seconds": {
                "type": "integer",
                "minimum": 1,
                "maximum": 31_536_000,
            },
            "max_receive_delay_seconds": {
                "type": "integer",
                "minimum": 0,
                "maximum": 31_536_000,
            },
        },
        required=("draft_id",),
    )
    continuity_record = strict_object(
        {
            "source_id": _SOURCE_ID,
            "metric_code": _METRIC,
            "status": {
                "type": "string",
                "enum": ["evaluated", "not_evaluated"],
            },
            "reason": {"type": "string", "minLength": 1, "maxLength": 512},
            "unit": {
                "type": ["string", "null"],
                "maxLength": 32,
            },
            "units": {
                "type": "array",
                "maxItems": 10_000,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 1, "maxLength": 32},
            },
            "point_count": _COUNT,
            "invalid_point_count": _COUNT,
            "first_observed_at": _NULLABLE_TEXT,
            "last_observed_at": _NULLABLE_TEXT,
            "duplicate_sequence_count": _NULLABLE_INTEGER,
            "sequence_gap_count": _NULLABLE_INTEGER,
            "missing_sequence_number_count": _NULLABLE_INTEGER,
            "sequence_regression_count": _NULLABLE_INTEGER,
            "duplicate_observed_at_count": _NULLABLE_INTEGER,
            "reset_count": _NULLABLE_INTEGER,
            "revision_conflict_count": _NULLABLE_INTEGER,
            "max_observed_gap_seconds": _NULLABLE_NUMBER,
            "time_gap_exceedance_count": _NULLABLE_INTEGER,
            "max_receive_delay_seconds": _NULLABLE_NUMBER,
            "receive_delay_exceedance_count": _NULLABLE_INTEGER,
            "finding_count": _NULLABLE_INTEGER,
            "evidence": _id_evidence_schema(),
            "issue_evidence": _id_evidence_schema(),
        },
        required=(
            "source_id",
            "metric_code",
            "status",
            "reason",
            "unit",
            "units",
            "point_count",
            "invalid_point_count",
            "first_observed_at",
            "last_observed_at",
            "duplicate_sequence_count",
            "sequence_gap_count",
            "missing_sequence_number_count",
            "sequence_regression_count",
            "duplicate_observed_at_count",
            "reset_count",
            "revision_conflict_count",
            "max_observed_gap_seconds",
            "time_gap_exceedance_count",
            "max_receive_delay_seconds",
            "receive_delay_exceedance_count",
            "finding_count",
            "evidence",
            "issue_evidence",
        ),
    )
    output_schema = _common_output(
        {
            "reason": {"type": "string", "minLength": 1, "maxLength": 512},
            "selected_observation_count": _COUNT,
            "excluded_observation_count": _COUNT,
            "evaluated_series_count": _COUNT,
            "not_evaluated_series_count": _COUNT,
            "series": {
                "type": "array",
                "maxItems": _MAX_RETURNED_SERIES,
                "items": continuity_record,
            },
            "series_count": _COUNT,
            "returned_series_count": _COUNT,
            "series_truncated": {"type": "boolean"},
            "series_sha256": _SHA256,
            "missing_requested_source_ids": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": True,
                "items": _SOURCE_ID,
            },
            "missing_requested_metric_codes": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": True,
                "items": _METRIC,
            },
            "thresholds": strict_object(
                {
                    "max_gap_seconds": _NULLABLE_INTEGER,
                    "max_receive_delay_seconds": _NULLABLE_INTEGER,
                    "origin": {
                        "type": "string",
                        "enum": ["caller_supplied", "none"],
                    },
                },
                required=(
                    "max_gap_seconds",
                    "max_receive_delay_seconds",
                    "origin",
                ),
            ),
            "uncertainty": strict_object(
                {
                    "sequence_assignment_policy_verified": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "device_calibration_checked": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "cryptographic_signature_verification_performed": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "causality_determined": {
                        "type": "boolean",
                        "enum": [False],
                    },
                },
                required=(
                    "sequence_assignment_policy_verified",
                    "device_calibration_checked",
                    "cryptographic_signature_verification_performed",
                    "causality_determined",
                ),
            ),
        }
    )
    return input_schema, output_schema


def _consistency_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    input_schema = strict_object(
        {
            "draft_id": _ID,
            "metric_code": _METRIC,
            "source_ids": {
                "type": "array",
                "minItems": 2,
                "maxItems": _MAX_COMPARE_SOURCES,
                "uniqueItems": True,
                "items": _SOURCE_ID,
            },
            "time_tolerance_seconds": {
                "type": "integer",
                "minimum": 0,
                "maximum": 86_400,
            },
        },
        required=("draft_id", "metric_code"),
    )
    match = strict_object(
        {
            "left_observation_id": _ID,
            "right_observation_id": _ID,
            "left_observed_at": {"type": "string", "maxLength": 64},
            "right_observed_at": {"type": "string", "maxLength": 64},
            "signed_time_delta_seconds": {"type": "number"},
            "signed_difference": {"type": "number"},
            "absolute_difference": {
                "type": "number",
                "minimum": 0,
            },
            "relative_difference": _NULLABLE_NUMBER,
        },
        required=(
            "left_observation_id",
            "right_observation_id",
            "left_observed_at",
            "right_observed_at",
            "signed_time_delta_seconds",
            "signed_difference",
            "absolute_difference",
            "relative_difference",
        ),
    )
    source = strict_object(
        {
            "source_id": _SOURCE_ID,
            "point_count": _COUNT,
            "valid_point_count": _COUNT,
            "invalid_point_count": _COUNT,
            "units": {
                "type": "array",
                "maxItems": 10_000,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 1, "maxLength": 32},
            },
            "evidence": _id_evidence_schema(),
        },
        required=(
            "source_id",
            "point_count",
            "valid_point_count",
            "invalid_point_count",
            "units",
            "evidence",
        ),
    )
    pair = strict_object(
        {
            "left_source_id": _SOURCE_ID,
            "right_source_id": _SOURCE_ID,
            "status": {
                "type": "string",
                "enum": ["evaluated", "not_evaluated"],
            },
            "reason": {"type": "string", "minLength": 1, "maxLength": 512},
            "unit": {
                "type": ["string", "null"],
                "maxLength": 32,
            },
            "units": {
                "type": "array",
                "maxItems": 10_000,
                "uniqueItems": True,
                "items": {"type": "string", "minLength": 1, "maxLength": 32},
            },
            "left_point_count": _COUNT,
            "right_point_count": _COUNT,
            "invalid_point_count": _COUNT,
            "matched_pair_count": _COUNT,
            "unmatched_left_count": _COUNT,
            "unmatched_right_count": _COUNT,
            "zero_scale_pair_count": _COUNT,
            "median_absolute_difference": _NULLABLE_NUMBER,
            "maximum_absolute_difference": _NULLABLE_NUMBER,
            "median_relative_difference": _NULLABLE_NUMBER,
            "maximum_relative_difference": _NULLABLE_NUMBER,
            "matches": {
                "type": "array",
                "maxItems": _MAX_RETURNED_MATCHES_PER_PAIR,
                "items": match,
            },
            "returned_match_count": _COUNT,
            "matches_truncated": {"type": "boolean"},
            "matches_sha256": _SHA256,
            "evidence": _id_evidence_schema(),
        },
        required=(
            "left_source_id",
            "right_source_id",
            "status",
            "reason",
            "unit",
            "units",
            "left_point_count",
            "right_point_count",
            "invalid_point_count",
            "matched_pair_count",
            "unmatched_left_count",
            "unmatched_right_count",
            "zero_scale_pair_count",
            "median_absolute_difference",
            "maximum_absolute_difference",
            "median_relative_difference",
            "maximum_relative_difference",
            "matches",
            "returned_match_count",
            "matches_truncated",
            "matches_sha256",
            "evidence",
        ),
    )
    output_schema = _common_output(
        {
            "reason": {"type": "string", "minLength": 1, "maxLength": 512},
            "metric_code": _METRIC,
            "time_tolerance_seconds": {
                "type": "integer",
                "minimum": 0,
                "maximum": 86_400,
            },
            "time_tolerance_origin": {
                "type": "string",
                "enum": ["caller_supplied", "tool_default"],
            },
            "selected_source_count": _COUNT,
            "available_source_count": _COUNT,
            "excluded_observation_count": _COUNT,
            "missing_requested_source_ids": {
                "type": "array",
                "maxItems": _MAX_COMPARE_SOURCES,
                "uniqueItems": True,
                "items": _SOURCE_ID,
            },
            "too_many_implicit_sources": {"type": "boolean"},
            "sources": {
                "type": "array",
                "maxItems": _MAX_COMPARE_SOURCES,
                "items": source,
            },
            "source_count": _COUNT,
            "pairs": {
                "type": "array",
                "maxItems": 6,
                "items": pair,
            },
            "pair_count": _COUNT,
            "evaluated_pair_count": _COUNT,
            "not_evaluated_pair_count": _COUNT,
            "uncertainty": strict_object(
                {
                    "aggregation_performed": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "automatic_unit_conversion": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "metric_code_source_authenticated": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "source_equivalence_verified": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "device_calibration_checked": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "causality_determined": {
                        "type": "boolean",
                        "enum": [False],
                    },
                },
                required=(
                    "aggregation_performed",
                    "automatic_unit_conversion",
                    "metric_code_source_authenticated",
                    "source_equivalence_verified",
                    "device_calibration_checked",
                    "causality_determined",
                ),
            ),
        }
    )
    return input_schema, output_schema


def _lineage_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    input_schema = strict_object(
        {
            "draft_id": _ID,
            "observation_ids": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "uniqueItems": True,
                "items": _ID,
            },
        },
        required=("draft_id",),
    )
    label_collection = _id_collection_schema(
        item_schema={
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
        }
    )
    hash_collection = _id_collection_schema(item_schema=_SHA256)
    lineage_record = strict_object(
        {
            "observation_id": {
                "type": ["string", "null"],
                "maxLength": 256,
            },
            "source_id": {
                "type": ["string", "null"],
                "maxLength": 128,
            },
            "status": _STATUS,
            "reason": {"type": "string", "minLength": 1, "maxLength": 512},
            "provenance_fields_present": _COUNT,
            "provenance_fields_expected": _COUNT,
            "provenance_record_count": _COUNT,
            "invalid_provenance_record_count": _COUNT,
            "invalid_content_sha256_count": _COUNT,
            "payload_digest_format_valid": {"type": "boolean"},
            "payload_digest_matches": {"type": "boolean"},
            "signature_format_valid": {"type": "boolean"},
            "signature_cryptographically_verified": {
                "type": "boolean",
                "enum": [False],
            },
            "source_kinds": label_collection,
            "extraction_methods": label_collection,
            "content_sha256s": hash_collection,
            "matched_import_ids": _id_collection_schema(),
            "unmatched_content_sha256s": hash_collection,
        },
        required=(
            "observation_id",
            "source_id",
            "status",
            "reason",
            "provenance_fields_present",
            "provenance_fields_expected",
            "provenance_record_count",
            "invalid_provenance_record_count",
            "invalid_content_sha256_count",
            "payload_digest_format_valid",
            "payload_digest_matches",
            "signature_format_valid",
            "signature_cryptographically_verified",
            "source_kinds",
            "extraction_methods",
            "content_sha256s",
            "matched_import_ids",
            "unmatched_content_sha256s",
        ),
    )
    count_row = strict_object(
        {
            "value": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
            },
            "count": _COUNT,
        },
        required=("value", "count"),
    )
    output_schema = _common_output(
        {
            "reason": {"type": "string", "minLength": 1, "maxLength": 512},
            "selected_observation_count": _COUNT,
            "invalid_observation_count": _COUNT,
            "missing_requested_observation_ids": {
                "type": "array",
                "maxItems": 100,
                "uniqueItems": True,
                "items": _ID,
            },
            "lineage_records": {
                "type": "array",
                "maxItems": _MAX_RETURNED_LINEAGE,
                "items": lineage_record,
            },
            "lineage_record_count": _COUNT,
            "returned_lineage_record_count": _COUNT,
            "lineage_records_truncated": {"type": "boolean"},
            "lineage_records_sha256": _SHA256,
            "evaluated_lineage_count": _COUNT,
            "partial_lineage_count": _COUNT,
            "not_evaluated_lineage_count": _COUNT,
            "manifest_entry_count": _COUNT,
            "valid_manifest_entry_count": _COUNT,
            "invalid_manifest_entry_count": _COUNT,
            "source_kind_counts": {
                "type": "array",
                "maxItems": 129,
                "items": count_row,
            },
            "extraction_method_counts": {
                "type": "array",
                "maxItems": 129,
                "items": count_row,
            },
            "uncertainty": strict_object(
                {
                    "cryptographic_signature_verification_performed": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "source_document_content_read": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "metric_code_source_authenticated": {
                        "type": "boolean",
                        "enum": [False],
                    },
                    "import_manifest_is_bounded": {
                        "type": "boolean",
                        "enum": [True],
                    },
                    "unmatched_hash_proves_missing_source": {
                        "type": "boolean",
                        "enum": [False],
                    },
                },
                required=(
                    "cryptographic_signature_verification_performed",
                    "source_document_content_read",
                    "metric_code_source_authenticated",
                    "import_manifest_is_bounded",
                    "unmatched_hash_proves_missing_source",
                ),
            ),
        }
    )
    return input_schema, output_schema


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


def audit_tool_specs() -> tuple[ToolSpec, ...]:
    """Return the standalone, read-only audit tool definitions."""

    continuity_input, continuity_output = _continuity_schemas()
    consistency_input, consistency_output = _consistency_schemas()
    lineage_input, lineage_output = _lineage_schemas()
    return (
        ToolSpec(
            name="inspect_observation_continuity",
            description=(
                "按来源和指标检查观测序号、时间间隔、重置及接收延迟；"
                "混合单位或关键字段缺失时不评价。"
            ),
            input_schema=continuity_input,
            output_schema=continuity_output,
            execute=_governed(_inspect_observation_continuity),
            mutating=False,
            requires_approval=False,
            timeout_seconds=10.0,
            category="temporal_quality",
            evidence_grounding="repository_grounded",
            network_access=False,
            scenario_only=False,
            allowed_profiles=("standard", "chat_read_only"),
        ),
        ToolSpec(
            name="compare_source_consistency",
            description=(
                "对同一指标的有限来源做同单位、有序一对一时间近邻比较；"
                "不求和、不自动换算，也不判定设备原因。"
            ),
            input_schema=consistency_input,
            output_schema=consistency_output,
            execute=_governed(_compare_source_consistency),
            mutating=False,
            requires_approval=False,
            timeout_seconds=10.0,
            category="source_consistency",
            evidence_grounding="repository_grounded",
            network_access=False,
            scenario_only=False,
            allowed_profiles=("standard", "chat_read_only"),
        ),
        ToolSpec(
            name="summarize_provenance_lineage",
            description=(
                "汇总观测字段来源类型、内容摘要与导入清单关联；"
                "不读取原文、不返回签名值，也不声称完成密钥验签。"
            ),
            input_schema=lineage_input,
            output_schema=lineage_output,
            execute=_governed(_summarize_provenance_lineage),
            mutating=False,
            requires_approval=False,
            timeout_seconds=10.0,
            category="provenance",
            evidence_grounding="repository_grounded",
            network_access=False,
            scenario_only=False,
            allowed_profiles=("standard", "chat_read_only"),
        ),
    )


__all__ = ["audit_tool_specs"]
