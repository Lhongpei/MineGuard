from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal, DecimalException, InvalidOperation
from typing import Any
from zoneinfo import ZoneInfo

from .errors import SourceError
from .models import FieldMapping, NormalizedEvent, PipelineConfig, RawBatch, SourceConfig
from .quantity_catalog import (
    AGGREGATIONS,
    INTEGER_METRICS,
    METRICS,
    TEN_QUANTITY_SOURCE_CONTRACT,
    TEN_QUANTITY_SUBMISSION_CONTRACT,
    UNITS,
)
from .reporting import reporting_cutoff

SCOPES = ("daily_total", "zero_shift", "eight_shift", "four_shift")
_MAX_AGENT_CONTENT_BYTES = 2 * 1024 * 1024
_MAX_MEASUREMENT = Decimal("1000000000000000")
_NUMBER_TEXT = re.compile(
    r"^[+]?(?:(?:\d+)|(?:\d{1,3}(?:,\d{3})+))(?:\.\d+)?(?:[eE]([+-]?\d{1,3}))?$"
)


def canonical_json(value: Any) -> str:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        # json.dumps can preserve lone filesystem surrogate characters in a
        # Python str. Validate the actual wire encoding here so callers always
        # receive a UTF-8-safe canonical document or an operational error.
        text.encode("utf-8", errors="strict")
        return text
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise SourceError(f"数据不能安全序列化为 JSON：{exc}") from exc


def _lookup(record: dict[str, Any], path: str) -> Any:
    current: Any = record
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise KeyError(path)
    return current


def _parse_timestamp(value: Any, zone: ZoneInfo) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, time.min)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            parsed = datetime.fromtimestamp(float(value), UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise SourceError("时间戳超出有效范围") from exc
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise SourceError("时间字段不能为空")
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            try:
                parsed = datetime.combine(date.fromisoformat(text), time.min)
            except ValueError as exc:
                raise SourceError("无法解析来源中的 ISO 8601 时间字段") from exc
    else:
        raise SourceError("时间字段必须是 ISO 8601 字符串或 Unix 秒")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(zone)


def _scope_for(record: dict[str, Any], timestamp: datetime, pipeline: PipelineConfig) -> str:
    if pipeline.scope_field:
        try:
            raw = str(_lookup(record, pipeline.scope_field)).strip()
        except KeyError:
            raise SourceError(f"班次范围字段缺失：{pipeline.scope_field}") from None
        scope = pipeline.scope_values.get(raw, raw)
        if scope not in SCOPES:
            raise SourceError("来源范围值未配置为日报/三班映射")
        return scope
    if pipeline.period_type == "daily":
        return "daily_total"
    minute = timestamp.hour * 60 + timestamp.minute
    selected = pipeline.shifts[-1]
    for shift in pipeline.shifts:
        if minute >= shift.start_minutes:
            selected = shift
        else:
            break
    aliases = {
        "zero": "zero_shift",
        "zero_shift": "zero_shift",
        "eight": "eight_shift",
        "eight_shift": "eight_shift",
        "four": "four_shift",
        "four_shift": "four_shift",
    }
    scope = aliases.get(selected.name)
    if scope is None:
        raise SourceError("shift.name 必须映射为 zero_shift、eight_shift 或 four_shift")
    return scope


def _as_decimal(value: Any, field: str, *, invoice_main: bool = False) -> Decimal:
    if isinstance(value, bool):
        raise SourceError(f"字段 {field} 的布尔值不能转换为数字")
    if not isinstance(value, (str, int, float, Decimal)):
        raise SourceError(f"字段 {field} 必须是十进制数字")
    try:
        text = str(value).strip()
    except (ValueError, OverflowError) as exc:
        raise SourceError(f"字段 {field} 数字文本过大") from exc
    if invoice_main and text.startswith("-"):
        raise SourceError(
            "invoiced_quantity_t 只能映射本期开具的普通/蓝票实物吨数，"
            "必须为非负数；红票、退货或折让是辅助事件，"
            "不得以负数混入十量主字段"
        )
    if not text or len(text) > 128 or _NUMBER_TEXT.fullmatch(text) is None:
        raise SourceError(f"字段 {field} 不是合法十进制数字")
    exponent_match = _NUMBER_TEXT.fullmatch(text)
    assert exponent_match is not None
    exponent = int(exponent_match.group(1) or "0")
    if abs(exponent) > 18 or sum(character.isdigit() for character in text) > 64:
        raise SourceError(f"字段 {field} 数字精度或指数超出上限")
    try:
        result = Decimal(text.replace(",", ""))
    except (InvalidOperation, DecimalException, ValueError, OverflowError) as exc:
        raise SourceError(f"字段 {field} 不能转换为数字") from exc
    if not result.is_finite():
        raise SourceError(f"字段 {field} 必须是有限非负数")
    if result < 0:
        if invoice_main:
            raise SourceError(
                "invoiced_quantity_t 只能映射本期开具的普通/蓝票实物吨数，"
                "必须为非负数；红票、退货或折让是辅助事件，"
                "不得以负数混入十量主字段"
            )
        raise SourceError(f"字段 {field} 必须是有限非负数")
    return result


def _convert(value: Any, mapping: FieldMapping, metric: str) -> int | float:
    try:
        number = _as_decimal(
            value,
            mapping.target,
            invoice_main=metric == "invoiced_quantity_t",
        )
        number = number * Decimal(str(mapping.factor)) + Decimal(str(mapping.offset))
    except SourceError:
        raise
    except (InvalidOperation, DecimalException, ValueError, OverflowError) as exc:
        raise SourceError(f"字段 {mapping.target} 转换运算超出安全范围") from exc
    if not number.is_finite() or number < 0:
        if metric == "invoiced_quantity_t":
            raise SourceError(
                "invoiced_quantity_t 转换后必须为非负数；"
                "红票、退货或折让辅助事件不得净额混入十量主字段"
            )
        raise SourceError(f"字段 {mapping.target} 转换后必须是有限非负数")
    if number > _MAX_MEASUREMENT:
        raise SourceError(f"字段 {mapping.target} 超出十量 V3 数值上限")
    if mapping.value_type == "integer" or metric in INTEGER_METRICS:
        if number != number.to_integral_value():
            raise SourceError(f"字段 {mapping.target} 必须是整数")
        return int(number)
    result = float(number)
    if not math.isfinite(result):
        raise SourceError(f"字段 {mapping.target} 超出十量 V3 数值范围")
    return result


def _target(mapping: FieldMapping, row_scope: str) -> tuple[str, str]:
    parts = mapping.target.split(".", 1)
    if len(parts) == 1:
        return row_scope, parts[0]
    scope = row_scope if parts[0] == "current_shift" else parts[0]
    return scope, parts[1]


def _reduce(values: list[tuple[datetime, int | float]], mapping: FieldMapping) -> int | float:
    ordered = sorted(values, key=lambda item: item[0])
    raw_values = [item[1] for item in ordered]
    if mapping.reduce == "latest":
        values_by_timestamp: dict[datetime, set[Decimal]] = defaultdict(set)
        for observed_at, value in ordered:
            values_by_timestamp[observed_at].add(Decimal(str(value)))
        conflicting_times = [
            observed_at
            for observed_at, timestamp_values in values_by_timestamp.items()
            if len(timestamp_values) > 1
        ]
        if conflicting_times:
            raise SourceError(
                f"映射 {mapping.target} 在相同业务时间出现冲突值："
                f"{min(conflicting_times).isoformat()}；无法确定 latest，需先在来源侧消歧"
            )
        return raw_values[-1]
    if mapping.reduce == "sum":
        result = sum(Decimal(str(value)) for value in raw_values)
        return int(result) if all(isinstance(value, int) for value in raw_values) else float(result)
    if mapping.reduce == "average":
        return float(sum(Decimal(str(value)) for value in raw_values) / len(raw_values))
    distinct = {Decimal(str(value)) for value in raw_values}
    if len(distinct) != 1:
        raise SourceError(
            f"映射 {mapping.target} 在同一日期/范围出现冲突值；"
            "请显式配置 reduce=sum、average 或 latest，不能默认覆盖"
        )
    return raw_values[-1]


def _measurement(metric: str, value: int | float | None, source_ref: str) -> dict[str, Any]:
    return {
        "metric_code": metric,
        "value": value,
        "unit": UNITS[metric],
        "aggregation": AGGREGATIONS[metric],
        "quality_flags": ["reported"] if value is not None else ["missing"],
        "source_refs": [source_ref],
    }


def _set(source_ref: str) -> dict[str, dict[str, Any]]:
    return {metric: _measurement(metric, None, source_ref) for metric in METRICS}


def _shift_window(day: date, scope: str, zone: ZoneInfo) -> tuple[str, str]:
    hour = {"zero_shift": 0, "eight_shift": 8, "four_shift": 16}[scope]
    start = datetime.combine(day, time(hour), tzinfo=zone)
    end = start + timedelta(hours=8)
    return start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds")


def normalize_batches(
    pipeline: PipelineConfig,
    source: SourceConfig,
    batches: tuple[RawBatch, ...],
    *,
    now: datetime | None = None,
) -> tuple[NormalizedEvent, ...]:
    """Create one complete ten-quantity V3 source snapshot per month.

    Every daily total carries all eleven atomic fields. Missing cells stay
    explicit null/missing, including fields absent from a legacy six-column
    source. The Agent merges latest snapshots from different ``source_id``
    values; this connector never overwrites one source with another or
    fabricates a value.
    """

    pipeline = replace(
        pipeline,
        timestamp_field=source.timestamp_field or pipeline.timestamp_field,
        period_type=source.period_type or pipeline.period_type,
        scope_field=source.scope_field or pipeline.scope_field,
        scope_values=(
            source.scope_values if source.scope_values is not None else pipeline.scope_values
        ),
        mappings=source.mappings if source.mappings is not None else pipeline.mappings,
        shifts=source.shifts if source.shifts is not None else pipeline.shifts,
    )

    zone = ZoneInfo(pipeline.timezone)
    collection_time = now or datetime.now(UTC)
    current_local = collection_time.astimezone(zone)
    cutoff = reporting_cutoff(pipeline, collection_time)
    cutoff_month = cutoff.strftime("%Y-%m")
    cells: dict[str, dict[tuple[str, str, str], list[tuple[datetime, int | float]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    dates: dict[str, set[date]] = defaultdict(set)
    filenames: dict[str, set[str]] = defaultdict(set)
    mapping_seen: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    latest_observed_at: dict[str, datetime] = {}
    record_counts: dict[str, int] = defaultdict(int)

    for batch in batches:
        for record in batch.records:
            try:
                timestamp = _parse_timestamp(_lookup(record, pipeline.timestamp_field), zone)
            except KeyError:
                raise SourceError(f"时间字段缺失：{pipeline.timestamp_field}") from None
            month = timestamp.strftime("%Y-%m")
            latest_observed_at[month] = max(latest_observed_at.get(month, timestamp), timestamp)
            record_counts[month] += 1
            day = timestamp.date()
            row_scope = _scope_for(record, timestamp, pipeline)
            dates[month].add(day)
            filenames[month].add(batch.original_filename)
            for mapping in pipeline.mappings:
                try:
                    raw_value = _lookup(record, mapping.source)
                except KeyError:
                    continue
                if raw_value is None or raw_value == "":
                    continue
                scope, metric = _target(mapping, row_scope)
                if scope not in SCOPES or metric not in METRICS:
                    raise SourceError(f"映射目标不是正式十量 V3 单元格：{mapping.target}")
                cells[month][(day.isoformat(), scope, metric)].append(
                    (timestamp, _convert(raw_value, mapping, metric))
                )
                mapping_seen[month][mapping.target] += 1

    events: list[NormalizedEvent] = []
    source_ref = f"CSRC-{hashlib.sha256(source.id.encode()).hexdigest()[:16]}"
    for month in sorted(dates):
        if not any(mapping_seen[month].values()):
            raise SourceError(
                f"月份 {month} 未映射到任何非空规范值；"
                "请检查来源字段是否漂移、mapping.source 是否正确"
            )
        for mapping in pipeline.mappings:
            if mapping.required and not mapping_seen[month][mapping.target]:
                raise SourceError(f"月份 {month} 缺少必填映射来源：{mapping.source}")
        reduced: dict[tuple[str, str, str], int | float] = {}
        for key, values in cells[month].items():
            mapping = next(
                item
                for item in pipeline.mappings
                if _target(item, key[1])[1] == key[2]
                and (
                    len(item.target.split(".", 1)) == 1
                    or item.target.split(".", 1)[0] in {key[1], "current_shift"}
                )
            )
            reduced[key] = _reduce(values, mapping)

        observed_days = sorted(dates[month])
        month_start = date.fromisoformat(f"{month}-01")
        if month > cutoff_month:
            raise SourceError("来源包含企业应报截止日之后的未来月份，拒绝自动建稿")
        if month == cutoff_month:
            expected_end = cutoff
            if observed_days[-1] > expected_end:
                raise SourceError("来源日期晚于当前 pipeline 配置的应报截止日")
        else:
            next_month = (
                date(month_start.year + 1, 1, 1)
                if month_start.month == 12
                else date(month_start.year, month_start.month + 1, 1)
            )
            expected_end = next_month - timedelta(days=1)
        complete_days: list[date] = []
        cursor = month_start
        while cursor <= expected_end:
            complete_days.append(cursor)
            cursor += timedelta(days=1)
        missing_days = sorted(set(complete_days) - set(observed_days))
        day_documents: list[dict[str, Any]] = []
        for day in complete_days:
            daily = _set(source_ref)
            shifts = {scope: _set(source_ref) for scope in SCOPES if scope != "daily_total"}
            for scope in SCOPES:
                target_set = daily if scope == "daily_total" else shifts[scope]
                for metric in METRICS:
                    value = reduced.get((day.isoformat(), scope, metric))
                    target_set[metric] = _measurement(metric, value, source_ref)
            shift_documents: dict[str, Any] = {}
            for scope, code in (
                ("zero_shift", "ZERO"),
                ("eight_shift", "EIGHT"),
                ("four_shift", "FOUR"),
            ):
                start_at, end_at = _shift_window(day, scope, zone)
                shift_documents[scope] = {
                    "shift_code": code,
                    "start_at": start_at,
                    "end_at": end_at,
                    "measurements": shifts[scope],
                }
            day_documents.append(
                {
                    "date": day.isoformat(),
                    # Production volume alone cannot prove whether a mine was
                    # producing, stopped, under maintenance or restarting.
                    "operating_state": "unknown",
                    "reported_quantity": {
                        "daily_total": daily,
                        "shifts": shift_documents,
                    },
                }
            )

        content_document = {
            "contract_version": TEN_QUANTITY_SUBMISSION_CONTRACT,
            "connector_snapshot": {
                "contract_version": TEN_QUANTITY_SOURCE_CONTRACT,
                "pipeline_id": pipeline.id,
                "source_id": source.id,
                "source_system": source.source_system,
                "reporting_month": month,
                "data_watermark": latest_observed_at[month].isoformat(timespec="seconds"),
                "original_filenames": sorted(filenames[month]),
                "coverage": {
                    "period_start": complete_days[0].isoformat(),
                    "period_end": complete_days[-1].isoformat(),
                    "coverage_as_of": expected_end.isoformat(),
                    "reporting_lag_days": pipeline.reporting_lag_days,
                    "observed_date_count": len(observed_days),
                    "expected_date_count": len(complete_days),
                    "observed_dates": [day.isoformat() for day in observed_days],
                    "missing_dates": [day.isoformat() for day in missing_days],
                },
                "source_declaration": source.truth_statement,
                "normalization": (
                    "deterministic-ten-quantity-v3-mapping; no imputation; "
                    "missing cells remain null; conflicting values require an explicit reducer; "
                    "invoiced_quantity_t accepts nonnegative normal/blue-invoice tonnes only"
                ),
            },
            "days": day_documents,
        }
        content = canonical_json(content_document)
        if len(content.encode("utf-8")) > _MAX_AGENT_CONTENT_BYTES:
            raise SourceError("规范化后的月度十量 V3 来源快照超过 Agent 2 MiB 上限")
        content_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        draft_key = f"draft:{pipeline.enterprise_id}:{pipeline.report_type}:monthly:{month}"
        if len(draft_key) > 256:
            raise SourceError("按月 draft_key 超过 Agent 256 字符上限")
        identity = f"{pipeline.id}\n{source.id}\n{draft_key}\n{content_sha}"
        identity_sha = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        event_id = f"cevt_{identity_sha}"
        safe_source = "".join(
            character if character.isalnum() or character in "._-" else "-"
            for character in source.id
        )[:80]
        filename = f"connector-{safe_source}-{month}.json"[:255]
        payload: dict[str, Any] = {
            "contract_version": "enterprise-autofill-ingestion/v1",
            "event_id": event_id,
            "draft_key": draft_key,
            "source": {
                "source_id": source.id,
                "revision": 0,
                "format": "json",
                "content": content,
                "source_name": source.source_name,
                "source_system": source.source_system,
                "original_filename": filename,
                "truth_statement": True,
                "observed_at": current_local.isoformat(timespec="microseconds"),
                "coverage_as_of": expected_end.isoformat(),
            },
            "trigger_workflow": False,
            "workflow_name": "daily_coal_health",
        }
        events.append(
            NormalizedEvent(
                event_id=event_id,
                request_id=f"unused_{identity_sha}",
                pipeline_id=pipeline.id,
                source_id=source.id,
                draft_key=draft_key,
                period_key=month,
                content_sha256=content_sha,
                payload=payload,
                revision_floor=source.revision_seed,
                record_count=record_counts[month],
            )
        )
    return tuple(events)
