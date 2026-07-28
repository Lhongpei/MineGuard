"""Deterministic, mine-scoped analytics for the leadership dashboard.

The calculation in this module is deliberately independent from SQLite and
HTTP.  Callers pass the already-authorized batch, case and event snapshots,
and receive a JSON-ready report.  Aggregate fields are always recomputed from
the visible mine records; persisted portfolio totals are never trusted because
they may include mines outside the caller's scope.

Time windows are inclusive at both ends.  Every accepted timestamp must carry
an explicit UTC offset.  Missing or malformed timestamps are ignored and
reported as scoped data-quality counters instead of being guessed.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AwareDatetime, Field

from .models import StrictModel


_TECHNICAL_STATUSES = (
    "not_received",
    "consistent",
    "inconsistent",
    "inconclusive",
    "solver_error",
)
_OPEN_WORKFLOW_STATUSES = (
    "pending",
    "reviewing",
    "waiting_data",
    "pending_approval",
)
_PRIORITY_ORDER = {"P1": 0, "P2": 1, "DATA": 2, "NONE": 3}
_RISK_ALGORITHM_VERSION = "2.1.0"
_RISK_DECAY_HALF_LIFE_DAYS = 14.0
_RISK_STATUS_SEVERITY = {
    "consistent": 0.0,
    "inconsistent": 0.70,
    "not_received": 0.55,
    "inconclusive": 0.40,
    "solver_error": 0.45,
}
_RISK_PRIORITY_SEVERITY = {
    "P1": 1.0,
    "P2": 0.65,
    "DATA": 0.45,
    "NONE": 0.0,
}
_ANOMALY_LABELS = {
    "production_conflict": "生产数据技术不一致",
    "missing_report": "未按期收到数据",
    "data_insufficient": "数据或计算条件不足",
}
_CLOSURE_BUCKETS = (
    ("0-24小时", 24.0),
    ("1-3天", 72.0),
    ("3-7天", 168.0),
    ("7-15天", 360.0),
    ("15-30天", 720.0),
    ("30天以上", math.inf),
)
_BACKLOG_BUCKETS = (
    ("0-3天", 3.0),
    ("4-7天", 7.0),
    ("8-15天", 15.0),
    ("16-30天", 30.0),
    ("31-60天", 60.0),
    ("60天以上", math.inf),
)
_METRIC_DEFINITIONS = {
    "时间口径": (
        "统计窗口含起止时刻；展示日期按指定时区换算，缺少时区的时间戳不作猜测。"
    ),
    "报送覆盖率": "窗口内已收到矿次 ÷ 应报矿次；同一矿不同批次分别计一次。",
    "重复异常": "同一矿、同一异常类型在窗口内至少出现在指定数量的不同批次。",
    "当前积压": "截至 as_of 已建立且尚未处于 closed 状态的案件，含窗口前转入。",
    "闭环时长": "每个办案周期从案件建立或重新打开起，到下一次关闭止。",
    "首次响应": "案件建立后首个非 created 办案事件的耗时。",
    "风险分": (
        "0—100 分。报送异常按应报次数归一，越近期权重越高（14 天半衰期）；"
        "重复生产冲突、未闭环 P1/P2、待审批和超 30 天积压分别计分并设上限。"
        "只使用统计窗口结束前的数据，缺报作为风险信号，不按正常处理。"
    ),
}


class DailyTrendPoint(StrictModel):
    """One local-calendar-day dashboard point."""

    day: date
    batch_count: int = Field(ge=0)
    expected_reports: int = Field(ge=0)
    received_reports: int = Field(ge=0)
    coverage_rate: float | None = Field(default=None, ge=0, le=1)
    consistent_reports: int = Field(ge=0)
    inconsistent_reports: int = Field(ge=0)
    not_received_reports: int = Field(ge=0)
    inconclusive_reports: int = Field(ge=0)
    solver_error_reports: int = Field(ge=0)
    p1_reports: int = Field(ge=0)
    p2_reports: int = Field(ge=0)
    data_priority_reports: int = Field(ge=0)
    new_cases: int = Field(ge=0)
    closed_cycles: int = Field(ge=0)
    reopened_cycles: int = Field(ge=0)
    backlog_end: int = Field(ge=0)


class RiskScoreBreakdown(StrictModel):
    """Auditable components of the bounded mine risk score."""

    expected_exposure_count: int = Field(default=0, ge=0)
    decay_half_life_days: float = Field(
        default=_RISK_DECAY_HALF_LIFE_DAYS,
        gt=0,
    )
    decayed_exposure: float = Field(default=0, ge=0)
    weighted_abnormal_exposure: float = Field(default=0, ge=0)
    report_signal_score: float = Field(default=0, ge=0, le=50)
    repeated_conflict_score: float = Field(default=0, ge=0, le=10)
    open_p1_score: float = Field(default=0, ge=0, le=18)
    open_p2_score: float = Field(default=0, ge=0, le=7)
    pending_approval_score: float = Field(default=0, ge=0, le=5)
    overdue_backlog_score: float = Field(default=0, ge=0, le=10)
    uncapped_total: float = Field(default=0, ge=0)
    final_score: int = Field(default=0, ge=0, le=100)


class MineRiskRanking(StrictModel):
    """Transparent, sortable risk view for one visible mine."""

    rank: int = Field(ge=1)
    mine_id: str
    risk_level: Literal["high", "medium", "low", "normal"]
    risk_score: int = Field(ge=0, le=100)
    risk_algorithm_version: str = _RISK_ALGORITHM_VERSION
    risk_score_breakdown: RiskScoreBreakdown = Field(
        default_factory=RiskScoreBreakdown,
    )
    expected_reports: int = Field(ge=0)
    received_reports: int = Field(ge=0)
    coverage_rate: float | None = Field(default=None, ge=0, le=1)
    inconsistent_reports: int = Field(ge=0)
    data_issue_reports: int = Field(ge=0)
    p1_reports: int = Field(ge=0)
    p2_reports: int = Field(ge=0)
    consecutive_abnormal_reports: int = Field(ge=0)
    open_cases: int = Field(ge=0)
    open_p1_cases: int = Field(ge=0)
    open_p2_cases: int = Field(ge=0)
    pending_approval_cases: int = Field(ge=0)
    oldest_open_days: float | None = Field(default=None, ge=0)
    latest_technical_status: str | None = None
    latest_review_priority: str | None = None
    latest_observed_at: AwareDatetime | None = None
    reasons: list[str] = Field(default_factory=list)


class RepeatedAnomaly(StrictModel):
    """A repeated anomaly type for a visible mine."""

    mine_id: str
    anomaly_code: str
    anomaly_name: str
    distinct_batch_count: int = Field(ge=2)
    first_seen_at: AwareDatetime
    last_seen_at: AwareDatetime
    highest_priority: str
    current_open_cases: int = Field(ge=0)


class CasePerformance(StrictModel):
    """Case-flow and backlog performance for the requested period."""

    new_case_count: int = Field(ge=0)
    closed_case_count: int = Field(ge=0)
    closed_cycle_count: int = Field(ge=0)
    reopened_case_count: int = Field(ge=0)
    resolved_new_case_count: int = Field(ge=0)
    new_case_resolution_rate: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )
    open_backlog_count: int = Field(ge=0)
    pending_approval_count: int = Field(ge=0)
    backlog_status_counts: dict[str, int]
    oldest_backlog_days: float | None = Field(default=None, ge=0)
    average_closure_hours: float | None = Field(default=None, ge=0)
    median_closure_hours: float | None = Field(default=None, ge=0)
    p90_closure_hours: float | None = Field(default=None, ge=0)
    closure_duration_buckets: dict[str, int]
    average_first_response_hours: float | None = Field(default=None, ge=0)
    median_first_response_hours: float | None = Field(default=None, ge=0)
    responded_within_24h_rate: float | None = Field(
        default=None,
        ge=0,
        le=1,
    )
    cases_without_response: int = Field(ge=0)
    backlog_age_buckets: dict[str, int]


class AnalyticsDataQuality(StrictModel):
    """Only counters for records inside the supplied mine scope."""

    ignored_batches_with_invalid_time: int = Field(ge=0)
    ignored_cases_with_invalid_time: int = Field(ge=0)
    ignored_events_with_invalid_time: int = Field(ge=0)
    inferred_closure_timestamps: int = Field(ge=0)


class LeadershipAnalytics(StrictModel):
    """Complete JSON-ready output for the leadership dashboard."""

    timezone: str
    window_start: AwareDatetime
    window_end: AwareDatetime
    as_of: AwareDatetime
    scoped_mine_ids: list[str]
    expected_report_count: int = Field(ge=0)
    received_report_count: int = Field(ge=0)
    coverage_rate: float | None = Field(default=None, ge=0, le=1)
    daily_trend: list[DailyTrendPoint]
    mine_risk_ranking: list[MineRiskRanking]
    repeated_anomalies: list[RepeatedAnomaly]
    case_performance: CasePerformance
    data_quality: AnalyticsDataQuality
    metric_definitions: dict[str, str]
    summary: str


@dataclass(frozen=True)
class _Observation:
    batch_id: str
    mine_id: str
    observed_at: datetime
    technical_status: str
    review_priority: str


@dataclass(frozen=True)
class _Event:
    case_id: str
    action: str
    happened_at: datetime
    sequence: int
    before_status: str | None
    after_status: str | None


@dataclass(frozen=True)
class _Case:
    case_id: str
    batch_id: str
    mine_id: str
    issue_code: str
    priority: str
    created_at: datetime
    updated_at: datetime | None
    approval_at: datetime | None
    workflow_status: str


@dataclass(frozen=True)
class _Closure:
    case_id: str
    mine_id: str
    happened_at: datetime
    duration_hours: float
    inferred: bool


@dataclass(frozen=True)
class _Reopening:
    case_id: str
    mine_id: str
    happened_at: datetime


@dataclass
class _CaseHistory:
    case: _Case
    events: list[_Event]
    closures: list[_Closure]
    reopenings: list[_Reopening]
    first_response_at: datetime | None
    final_status: str

    def status_at(self, moment: datetime) -> str | None:
        if self.case.created_at > moment:
            return None
        status = "pending"
        saw_event = False
        for event in self.events:
            if event.happened_at > moment:
                break
            if event.after_status:
                status = event.after_status
                saw_event = True
        if (
            not saw_event
            and self.case.updated_at is not None
            and self.case.updated_at <= moment
        ):
            status = self.case.workflow_status
        if any(
            closure.inferred and closure.happened_at <= moment
            for closure in self.closures
        ):
            status = "closed"
        return status


def _mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        result = dump(mode="json")
        return result if isinstance(result, Mapping) else None
    return None


def _sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return value
    return ()


def _timestamp(value: Any) -> datetime | None:
    parsed: datetime
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith(("Z", "z")):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _required_boundary(value: datetime | str | None, name: str) -> datetime | None:
    if value is None:
        return None
    parsed = _timestamp(value)
    if parsed is None:
        raise ValueError(f"{name} must be an ISO 8601 timezone-aware datetime")
    return parsed


def _in_window(moment: datetime, start: datetime, end: datetime) -> bool:
    return start <= moment <= end


def _mine_scope(mine_ids: Collection[str] | None) -> set[str] | None:
    if mine_ids is None:
        return None
    if isinstance(mine_ids, (str, bytes, bytearray)):
        raise ValueError("mine_ids must be a collection of mine id strings")
    normalized: set[str] = set()
    for mine_id in mine_ids:
        if not isinstance(mine_id, str) or not mine_id.strip():
            raise ValueError("mine_ids must contain non-empty strings")
        normalized.add(mine_id.strip())
    return normalized


def _visible(mine_id: str, scope: set[str] | None) -> bool:
    return bool(mine_id) and (scope is None or mine_id in scope)


def _flatten_events(
    events: Sequence[Mapping[str, Any]]
    | Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[Mapping[str, Any]]:
    if not isinstance(events, Mapping):
        return [
            mapped
            for item in _sequence(events)
            if (mapped := _mapping(item)) is not None
        ]
    flattened: list[Mapping[str, Any]] = []
    for case_id in sorted(events):
        for item in _sequence(events[case_id]):
            mapped = _mapping(item)
            if mapped is None:
                continue
            if mapped.get("case_id"):
                flattened.append(mapped)
            else:
                flattened.append({**mapped, "case_id": str(case_id)})
    return flattened


def _batch_records(
    batches: Sequence[Mapping[str, Any]],
    scope: set[str] | None,
) -> tuple[list[_Observation], int, list[datetime]]:
    observations: list[_Observation] = []
    invalid_time = 0
    timestamps: list[datetime] = []

    for raw_value in batches:
        raw = _mapping(raw_value)
        if raw is None:
            continue
        request = _mapping(raw.get("request")) or {}
        response = _mapping(raw.get("response")) or {}
        expected_values = _sequence(request.get("expected_mine_ids"))
        item_values = _sequence(response.get("items"))
        items: dict[str, Mapping[str, Any]] = {}
        for value in item_values:
            item = _mapping(value)
            if item is None:
                continue
            mine_id = str(item.get("mine_id") or "").strip()
            if _visible(mine_id, scope):
                items.setdefault(mine_id, item)

        expected: list[str] = []
        seen: set[str] = set()
        for value in expected_values:
            mine_id = str(value or "").strip()
            if _visible(mine_id, scope) and mine_id not in seen:
                seen.add(mine_id)
                expected.append(mine_id)
        for mine_id in sorted(items):
            if mine_id not in seen:
                seen.add(mine_id)
                expected.append(mine_id)
        if not expected:
            continue

        observed_at = _timestamp(raw.get("created_at"))
        if observed_at is None:
            invalid_time += 1
            continue
        timestamps.append(observed_at)
        batch_id = str(raw.get("batch_id") or request.get("batch_id") or "")
        if not batch_id:
            batch_id = f"anonymous:{observed_at.isoformat()}"
        for mine_id in expected:
            item = items.get(mine_id, {})
            status = str(item.get("technical_status") or "not_received")
            if status not in _TECHNICAL_STATUSES:
                status = "solver_error"
            priority = str(item.get("review_priority") or "")
            if priority not in _PRIORITY_ORDER:
                priority = "NONE" if status == "consistent" else "DATA"
            observations.append(
                _Observation(
                    batch_id=batch_id,
                    mine_id=mine_id,
                    observed_at=observed_at,
                    technical_status=status,
                    review_priority=priority,
                )
            )
    return observations, invalid_time, timestamps


def _case_records(
    cases: Sequence[Mapping[str, Any]],
    scope: set[str] | None,
) -> tuple[list[_Case], int, list[datetime]]:
    records: list[_Case] = []
    invalid_time = 0
    timestamps: list[datetime] = []
    seen_ids: set[str] = set()
    for raw_value in cases:
        raw = _mapping(raw_value)
        if raw is None:
            continue
        mine_id = str(raw.get("mine_id") or "").strip()
        if not _visible(mine_id, scope):
            continue
        case_id = str(raw.get("case_id") or "").strip()
        if not case_id or case_id in seen_ids:
            continue
        created_at = _timestamp(raw.get("created_at"))
        if created_at is None:
            invalid_time += 1
            continue
        seen_ids.add(case_id)
        updated_at = _timestamp(raw.get("updated_at"))
        approval_at = _timestamp(raw.get("approval_at"))
        timestamps.append(created_at)
        if updated_at is not None:
            timestamps.append(updated_at)
        if approval_at is not None:
            timestamps.append(approval_at)
        records.append(
            _Case(
                case_id=case_id,
                batch_id=str(raw.get("batch_id") or ""),
                mine_id=mine_id,
                issue_code=str(raw.get("issue_code") or "unknown"),
                priority=str(raw.get("priority") or "DATA"),
                created_at=created_at,
                updated_at=updated_at,
                approval_at=approval_at,
                workflow_status=str(
                    raw.get("workflow_status") or "pending"
                ),
            )
        )
    records.sort(key=lambda item: (item.created_at, item.case_id))
    return records, invalid_time, timestamps


def _event_records(
    events: Sequence[Mapping[str, Any]]
    | Mapping[str, Sequence[Mapping[str, Any]]],
    cases_by_id: Mapping[str, _Case],
) -> tuple[dict[str, list[_Event]], int, list[datetime]]:
    records: dict[str, list[_Event]] = defaultdict(list)
    invalid_time = 0
    timestamps: list[datetime] = []
    for raw in _flatten_events(events):
        case_id = str(raw.get("case_id") or "").strip()
        if case_id not in cases_by_id:
            # Unknown events might belong to an unauthorized mine, so they are
            # intentionally not counted or exposed.
            continue
        happened_at = _timestamp(raw.get("created_at"))
        if happened_at is None:
            invalid_time += 1
            continue
        before = _mapping(raw.get("before")) or {}
        after = _mapping(raw.get("after")) or {}
        before_status = before.get("workflow_status")
        after_status = after.get("workflow_status")
        try:
            sequence = int(raw.get("sequence") or 0)
        except (TypeError, ValueError):
            sequence = 0
        records[case_id].append(
            _Event(
                case_id=case_id,
                action=str(raw.get("action") or ""),
                happened_at=happened_at,
                sequence=sequence,
                before_status=(
                    str(before_status) if before_status is not None else None
                ),
                after_status=(
                    str(after_status) if after_status is not None else None
                ),
            )
        )
        timestamps.append(happened_at)
    for case_events in records.values():
        case_events.sort(
            key=lambda item: (
                item.happened_at,
                item.sequence,
                item.action,
            )
        )
    return records, invalid_time, timestamps


def _build_history(
    case: _Case,
    events: list[_Event],
    as_of: datetime,
) -> tuple[_CaseHistory, int]:
    relevant = [
        event
        for event in events
        if case.created_at <= event.happened_at <= as_of
    ]
    status = "pending"
    cycle_start = case.created_at
    closures: list[_Closure] = []
    reopenings: list[_Reopening] = []
    first_response: datetime | None = None
    for event in relevant:
        if event.action != "created" and first_response is None:
            first_response = event.happened_at
        after = event.after_status or status
        if status != "closed" and after == "closed":
            duration = max(
                0.0,
                (event.happened_at - cycle_start).total_seconds() / 3600,
            )
            closures.append(
                _Closure(
                    case_id=case.case_id,
                    mine_id=case.mine_id,
                    happened_at=event.happened_at,
                    duration_hours=duration,
                    inferred=False,
                )
            )
        elif status == "closed" and after != "closed":
            reopenings.append(
                _Reopening(
                    case_id=case.case_id,
                    mine_id=case.mine_id,
                    happened_at=event.happened_at,
                )
            )
            cycle_start = event.happened_at
        status = after

    inferred_count = 0
    if case.workflow_status == "closed" and status != "closed":
        candidate = case.approval_at or case.updated_at
        if (
            candidate is not None
            and case.created_at <= candidate <= as_of
            and not any(
                reopening.happened_at > candidate
                for reopening in reopenings
            )
        ):
            closures.append(
                _Closure(
                    case_id=case.case_id,
                    mine_id=case.mine_id,
                    happened_at=candidate,
                    duration_hours=max(
                        0.0,
                        (candidate - cycle_start).total_seconds() / 3600,
                    ),
                    inferred=True,
                )
            )
            status = "closed"
            inferred_count = 1
    elif (
        not relevant
        and case.updated_at is not None
        and case.updated_at <= as_of
    ):
        status = case.workflow_status

    closures.sort(key=lambda item: (item.happened_at, item.case_id))
    return (
        _CaseHistory(
            case=case,
            events=relevant,
            closures=closures,
            reopenings=reopenings,
            first_response_at=first_response,
            final_status=status,
        ),
        inferred_count,
    )


def _bucket_counts(
    values: Sequence[float],
    buckets: Sequence[tuple[str, float]],
) -> dict[str, int]:
    result = {label: 0 for label, _ in buckets}
    for value in values:
        for label, upper_bound in buckets:
            if value <= upper_bound:
                result[label] += 1
                break
    return result


def _rounded_average(values: Sequence[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def _rounded_median(values: Sequence[float]) -> float | None:
    return round(float(statistics.median(values)), 2) if values else None


def _nearest_rank(values: Sequence[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(float(ordered[index]), 2)


def _anomaly_code(status: str) -> str | None:
    if status == "inconsistent":
        return "production_conflict"
    if status == "not_received":
        return "missing_report"
    if status in {"inconclusive", "solver_error"}:
        return "data_insufficient"
    return None


def _history_status_at(history: _CaseHistory, moment: datetime) -> str | None:
    return history.status_at(moment)


def _local_day_end(
    day_value: date,
    timezone: ZoneInfo,
    report_end: datetime,
    as_of: datetime,
) -> datetime:
    next_day = day_value + timedelta(days=1)
    next_midnight = datetime.combine(
        next_day,
        time.min,
        timezone,
    ).astimezone(UTC)
    return min(next_midnight - timedelta(microseconds=1), report_end, as_of)


def _risk_decay_weight(observed_at: datetime, anchor: datetime) -> float:
    """Return a past-only exponential weight anchored at the report end."""

    age_days = max(0.0, (anchor - observed_at).total_seconds() / 86400)
    return math.exp2(-age_days / _RISK_DECAY_HALF_LIFE_DAYS)


def _risk_score(
    observations: Sequence[_Observation],
    *,
    anchor: datetime,
    conflicts: int,
    open_p1: int,
    open_p2: int,
    pending_approval: int,
    overdue: int,
    has_data_issue: bool,
) -> tuple[int, RiskScoreBreakdown]:
    """Compute the frequency-normalized, decayed and bounded risk score."""

    expected = len(observations)
    decayed_exposure = 0.0
    weighted_abnormal = 0.0
    weighted_conflicts = 0.0
    for observation in observations:
        weight = _risk_decay_weight(observation.observed_at, anchor)
        decayed_exposure += weight
        severity = max(
            _RISK_STATUS_SEVERITY[observation.technical_status],
            _RISK_PRIORITY_SEVERITY[observation.review_priority],
        )
        weighted_abnormal += weight * severity
        if observation.technical_status == "inconsistent":
            weighted_conflicts += weight

    # The denominator is the number of expected reports, rather than the
    # number of received or abnormal reports.  This keeps otherwise identical
    # risk rates comparable across daily, weekly and duplicated schedules.
    report_signal = (
        min(50.0, 50.0 * weighted_abnormal / expected)
        if expected
        else 0.0
    )
    repeated_conflict = (
        min(10.0, 10.0 * weighted_conflicts / expected)
        if expected and conflicts >= 2
        else 0.0
    )

    # Workflow contributions are intentionally separate: they measure current
    # control-process exposure, not the reporting rate.  Linear caps make every
    # component easy to reproduce while bounding the total.
    open_p1_score = min(18.0, 12.0 * open_p1)
    open_p2_score = min(7.0, 4.0 * open_p2)
    pending_score = min(5.0, 2.5 * pending_approval)
    overdue_score = min(10.0, 3.0 * overdue)
    components = (
        report_signal,
        repeated_conflict,
        open_p1_score,
        open_p2_score,
        pending_score,
        overdue_score,
    )
    uncapped = sum(components)
    score = min(100, int(round(uncapped)))
    # A very old missing/data-invalid report can decay below half a point, but
    # it must never be represented as "normal".
    if has_data_issue and score == 0:
        score = 1

    breakdown = RiskScoreBreakdown(
        expected_exposure_count=expected,
        decayed_exposure=round(decayed_exposure, 4),
        weighted_abnormal_exposure=round(weighted_abnormal, 4),
        report_signal_score=round(report_signal, 2),
        repeated_conflict_score=round(repeated_conflict, 2),
        open_p1_score=round(open_p1_score, 2),
        open_p2_score=round(open_p2_score, 2),
        pending_approval_score=round(pending_score, 2),
        overdue_backlog_score=round(overdue_score, 2),
        uncapped_total=round(uncapped, 2),
        final_score=score,
    )
    return score, breakdown


def _risk_level(
    score: int,
    p1_reports: int,
    open_p1: int,
    conflicts: int,
) -> str:
    if score >= 60 or p1_reports > 0 or open_p1 > 0 or conflicts >= 2:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "normal"


def _executive_summary(
    *,
    mine_count: int,
    expected: int,
    received: int,
    open_cases: int,
    open_p1: int,
    repeated_count: int,
) -> str:
    coverage = "暂无应报数据" if expected == 0 else f"覆盖率 {received / expected:.1%}"
    return (
        f"本期纳入 {mine_count} 座可见矿井，应报 {expected} 矿次、"
        f"实收 {received} 矿次，{coverage}；当前积压 {open_cases} 件，"
        f"其中 P1 {open_p1} 件；识别重复异常 {repeated_count} 项。"
    )


def calculate_leadership_analytics(
    batches: Sequence[Mapping[str, Any]],
    cases: Sequence[Mapping[str, Any]],
    events: Sequence[Mapping[str, Any]]
    | Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    mine_ids: Collection[str] | None = None,
    start_at: datetime | str | None = None,
    end_at: datetime | str | None = None,
    as_of: datetime | str | None = None,
    timezone: str = "Asia/Shanghai",
    repeat_threshold: int = 2,
) -> LeadershipAnalytics:
    """Calculate a deterministic, leadership-oriented analytics snapshot.

    ``mine_ids`` is a security boundary, not merely a display filter.  Passing
    an empty collection produces an empty report, and no aggregate or quality
    counter is derived from records belonging to other mines.  The caller is
    responsible for supplying the authenticated principal's authorized mine
    ids.

    ``start_at`` and ``end_at`` are inclusive.  If omitted, the start is the
    earliest valid scoped timestamp and the end/as-of time is the latest valid
    scoped timestamp.  Supplying ``as_of`` lets online callers age the backlog
    against the current time while keeping calculations reproducible in tests
    and exports.
    """

    if repeat_threshold < 2:
        raise ValueError("repeat_threshold must be at least 2")
    try:
        reporting_timezone = ZoneInfo(timezone)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone: {timezone}") from exc

    scope = _mine_scope(mine_ids)
    observations, bad_batch_times, batch_times = _batch_records(
        batches,
        scope,
    )
    case_records, bad_case_times, case_times = _case_records(cases, scope)
    cases_by_id = {item.case_id: item for item in case_records}
    events_by_case, bad_event_times, event_times = _event_records(
        events,
        cases_by_id,
    )

    requested_start = _required_boundary(start_at, "start_at")
    requested_end = _required_boundary(end_at, "end_at")
    requested_as_of = _required_boundary(as_of, "as_of")
    available_times = batch_times + case_times + event_times
    effective_as_of = (
        requested_as_of
        or requested_end
        or (max(available_times) if available_times else None)
        or requested_start
        or datetime(1970, 1, 1, tzinfo=UTC)
    )
    effective_end = requested_end or effective_as_of
    if effective_as_of < effective_end:
        raise ValueError("as_of must not be earlier than end_at")
    eligible_starts = [
        timestamp for timestamp in available_times if timestamp <= effective_end
    ]
    effective_start = (
        requested_start
        or (min(eligible_starts) if eligible_starts else effective_end)
    )
    if effective_start > effective_end:
        raise ValueError("start_at must not be later than end_at")

    start_day = effective_start.astimezone(reporting_timezone).date()
    end_day = effective_end.astimezone(reporting_timezone).date()
    day_count = (end_day - start_day).days + 1
    if day_count > 3660:
        raise ValueError("analytics window must not exceed 3660 local days")

    window_observations = [
        item
        for item in observations
        if _in_window(item.observed_at, effective_start, effective_end)
    ]
    histories: list[_CaseHistory] = []
    inferred_closures = 0
    for case in case_records:
        if case.created_at > effective_as_of:
            continue
        history, inferred = _build_history(
            case,
            events_by_case.get(case.case_id, []),
            effective_as_of,
        )
        histories.append(history)
        inferred_closures += inferred

    closures_in_window = [
        closure
        for history in histories
        for closure in history.closures
        if _in_window(
            closure.happened_at,
            effective_start,
            effective_end,
        )
    ]
    reopenings_in_window = [
        reopening
        for history in histories
        for reopening in history.reopenings
        if _in_window(
            reopening.happened_at,
            effective_start,
            effective_end,
        )
    ]
    new_histories = [
        history
        for history in histories
        if _in_window(
            history.case.created_at,
            effective_start,
            effective_end,
        )
    ]
    open_histories = [
        history
        for history in histories
        if _history_status_at(history, effective_as_of) != "closed"
    ]

    daily_trend: list[DailyTrendPoint] = []
    for offset in range(day_count):
        day_value = start_day + timedelta(days=offset)
        day_observations = [
            item
            for item in window_observations
            if item.observed_at.astimezone(reporting_timezone).date()
            == day_value
        ]
        day_batches = {item.batch_id for item in day_observations}
        status_counts = {
            status: sum(
                item.technical_status == status for item in day_observations
            )
            for status in _TECHNICAL_STATUSES
        }
        priority_counts = {
            priority: sum(
                item.review_priority == priority
                for item in day_observations
            )
            for priority in _PRIORITY_ORDER
        }
        received = len(day_observations) - status_counts["not_received"]
        day_end = _local_day_end(
            day_value,
            reporting_timezone,
            effective_end,
            effective_as_of,
        )
        backlog_end = sum(
            history.case.created_at <= day_end
            and _history_status_at(history, day_end) != "closed"
            for history in histories
        )
        daily_trend.append(
            DailyTrendPoint(
                day=day_value,
                batch_count=len(day_batches),
                expected_reports=len(day_observations),
                received_reports=received,
                coverage_rate=(
                    received / len(day_observations)
                    if day_observations
                    else None
                ),
                consistent_reports=status_counts["consistent"],
                inconsistent_reports=status_counts["inconsistent"],
                not_received_reports=status_counts["not_received"],
                inconclusive_reports=status_counts["inconclusive"],
                solver_error_reports=status_counts["solver_error"],
                p1_reports=priority_counts["P1"],
                p2_reports=priority_counts["P2"],
                data_priority_reports=priority_counts["DATA"],
                new_cases=sum(
                    history.case.created_at.astimezone(
                        reporting_timezone
                    ).date()
                    == day_value
                    for history in new_histories
                ),
                closed_cycles=sum(
                    closure.happened_at.astimezone(
                        reporting_timezone
                    ).date()
                    == day_value
                    for closure in closures_in_window
                ),
                reopened_cycles=sum(
                    reopening.happened_at.astimezone(
                        reporting_timezone
                    ).date()
                    == day_value
                    for reopening in reopenings_in_window
                ),
                backlog_end=backlog_end,
            )
        )

    anomaly_occurrences: dict[
        tuple[str, str],
        dict[str, tuple[datetime, str]],
    ] = defaultdict(dict)
    for item in window_observations:
        code = _anomaly_code(item.technical_status)
        if code is None:
            continue
        key = (item.mine_id, code)
        prior = anomaly_occurrences[key].get(item.batch_id)
        candidate = (item.observed_at, item.review_priority)
        if prior is None:
            anomaly_occurrences[key][item.batch_id] = candidate
        else:
            anomaly_occurrences[key][item.batch_id] = (
                min(prior[0], candidate[0]),
                min(
                    (prior[1], candidate[1]),
                    key=lambda value: _PRIORITY_ORDER.get(value, 99),
                ),
            )
    for history in new_histories:
        case = history.case
        if not case.batch_id:
            continue
        key = (case.mine_id, case.issue_code)
        prior = anomaly_occurrences[key].get(case.batch_id)
        candidate = (case.created_at, case.priority)
        if prior is None:
            anomaly_occurrences[key][case.batch_id] = candidate
        else:
            anomaly_occurrences[key][case.batch_id] = (
                min(prior[0], candidate[0]),
                min(
                    (prior[1], candidate[1]),
                    key=lambda value: _PRIORITY_ORDER.get(value, 99),
                ),
            )

    repeated_anomalies: list[RepeatedAnomaly] = []
    for (mine_id, code), per_batch in anomaly_occurrences.items():
        if len(per_batch) < repeat_threshold:
            continue
        values = list(per_batch.values())
        priorities = [priority for _, priority in values]
        highest = min(
            priorities,
            key=lambda value: _PRIORITY_ORDER.get(value, 99),
        )
        repeated_anomalies.append(
            RepeatedAnomaly(
                mine_id=mine_id,
                anomaly_code=code,
                anomaly_name=_ANOMALY_LABELS.get(code, code),
                distinct_batch_count=len(per_batch),
                first_seen_at=min(moment for moment, _ in values),
                last_seen_at=max(moment for moment, _ in values),
                highest_priority=highest,
                current_open_cases=sum(
                    history.case.mine_id == mine_id
                    and history.case.issue_code == code
                    for history in open_histories
                ),
            )
        )
    repeated_anomalies.sort(
        key=lambda item: (
            -item.distinct_batch_count,
            -item.last_seen_at.timestamp(),
            item.mine_id,
            item.anomaly_code,
        )
    )

    mine_names = {
        item.mine_id for item in window_observations
    } | {history.case.mine_id for history in open_histories}
    risk_rows: list[MineRiskRanking] = []
    for mine_id in sorted(mine_names):
        mine_observations = sorted(
            (
                item
                for item in window_observations
                if item.mine_id == mine_id
            ),
            key=lambda item: (item.observed_at, item.batch_id),
        )
        mine_open = [
            history
            for history in open_histories
            if history.case.mine_id == mine_id
        ]
        counts = {
            priority: sum(
                item.review_priority == priority
                for item in mine_observations
            )
            for priority in _PRIORITY_ORDER
        }
        conflicts = sum(
            item.technical_status == "inconsistent"
            for item in mine_observations
        )
        data_issues = sum(
            item.technical_status
            in {"not_received", "inconclusive", "solver_error"}
            for item in mine_observations
        )
        streak = 0
        for item in reversed(mine_observations):
            if item.technical_status == "consistent":
                break
            streak += 1
        open_p1 = sum(
            history.case.priority == "P1" for history in mine_open
        )
        open_p2 = sum(
            history.case.priority == "P2" for history in mine_open
        )
        pending_approval = sum(
            _history_status_at(history, effective_as_of)
            == "pending_approval"
            for history in mine_open
        )
        ages = [
            max(
                0.0,
                (
                    effective_as_of - history.case.created_at
                ).total_seconds()
                / 86400,
            )
            for history in mine_open
        ]
        overdue = sum(age > 30 for age in ages)
        risk_score, score_breakdown = _risk_score(
            mine_observations,
            anchor=effective_end,
            conflicts=conflicts,
            open_p1=open_p1,
            open_p2=open_p2,
            pending_approval=pending_approval,
            overdue=overdue,
            has_data_issue=data_issues > 0,
        )
        reasons: list[str] = []
        if score_breakdown.report_signal_score:
            reasons.append(
                "报送异常贡献 "
                f"{score_breakdown.report_signal_score:g} 分"
                f"（按 {len(mine_observations)} 次应报归一，近期权重更高）"
            )
        if conflicts >= 2:
            reasons.append(
                f"生产数据不一致重复 {conflicts} 次"
                f"（另贡献 {score_breakdown.repeated_conflict_score:g} 分）"
            )
        elif conflicts == 1:
            reasons.append("本期出现生产数据不一致")
        if data_issues:
            missing = sum(
                item.technical_status == "not_received"
                for item in mine_observations
            )
            if missing:
                reasons.append(
                    f"本期缺报 {missing} 次，缺报已计入风险、不会按正常处理"
                )
            insufficient = data_issues - missing
            if insufficient:
                reasons.append(f"数据或计算条件不足 {insufficient} 次")
        if open_p1:
            reasons.append(
                f"有 {open_p1} 件 P1 尚未闭环"
                f"（独立贡献 {score_breakdown.open_p1_score:g} 分）"
            )
        if open_p2:
            reasons.append(
                f"有 {open_p2} 件 P2 尚未闭环"
                f"（独立贡献 {score_breakdown.open_p2_score:g} 分）"
            )
        if pending_approval:
            reasons.append(
                f"有 {pending_approval} 件结论待审批"
                f"（独立贡献 "
                f"{score_breakdown.pending_approval_score:g} 分）"
            )
        if overdue:
            reasons.append(
                f"有 {overdue} 件积压超过 30 天"
                f"（独立贡献 {score_breakdown.overdue_backlog_score:g} 分）"
            )
        latest = mine_observations[-1] if mine_observations else None
        received = len(mine_observations) - sum(
            item.technical_status == "not_received"
            for item in mine_observations
        )
        risk_rows.append(
            MineRiskRanking(
                rank=1,
                mine_id=mine_id,
                risk_level=_risk_level(
                    risk_score,
                    counts["P1"],
                    open_p1,
                    conflicts,
                ),
                risk_score=risk_score,
                risk_algorithm_version=_RISK_ALGORITHM_VERSION,
                risk_score_breakdown=score_breakdown,
                expected_reports=len(mine_observations),
                received_reports=received,
                coverage_rate=(
                    received / len(mine_observations)
                    if mine_observations
                    else None
                ),
                inconsistent_reports=conflicts,
                data_issue_reports=data_issues,
                p1_reports=counts["P1"],
                p2_reports=counts["P2"],
                consecutive_abnormal_reports=streak,
                open_cases=len(mine_open),
                open_p1_cases=open_p1,
                open_p2_cases=open_p2,
                pending_approval_cases=pending_approval,
                oldest_open_days=round(max(ages), 2) if ages else None,
                latest_technical_status=(
                    latest.technical_status if latest else None
                ),
                latest_review_priority=(
                    latest.review_priority if latest else None
                ),
                latest_observed_at=latest.observed_at if latest else None,
                reasons=reasons,
            )
        )
    risk_rows.sort(
        key=lambda item: (
            -item.risk_score,
            -item.open_p1_cases,
            -item.inconsistent_reports,
            item.mine_id,
        )
    )
    risk_ranking = [
        item.model_copy(update={"rank": rank})
        for rank, item in enumerate(risk_rows, start=1)
    ]

    closure_hours = [
        closure.duration_hours for closure in closures_in_window
    ]
    backlog_ages = [
        max(
            0.0,
            (
                effective_as_of - history.case.created_at
            ).total_seconds()
            / 86400,
        )
        for history in open_histories
    ]
    first_response_hours = [
        max(
            0.0,
            (
                history.first_response_at - history.case.created_at
            ).total_seconds()
            / 3600,
        )
        for history in new_histories
        if history.first_response_at is not None
    ]
    status_counts = {
        status: sum(
            _history_status_at(history, effective_as_of) == status
            for history in open_histories
        )
        for status in _OPEN_WORKFLOW_STATUSES
    }
    closed_case_ids = {item.case_id for item in closures_in_window}
    reopened_case_ids = {item.case_id for item in reopenings_in_window}
    resolved_new = sum(
        _history_status_at(history, effective_as_of) == "closed"
        for history in new_histories
    )
    case_performance = CasePerformance(
        new_case_count=len(new_histories),
        closed_case_count=len(closed_case_ids),
        closed_cycle_count=len(closures_in_window),
        reopened_case_count=len(reopened_case_ids),
        resolved_new_case_count=resolved_new,
        new_case_resolution_rate=(
            resolved_new / len(new_histories) if new_histories else None
        ),
        open_backlog_count=len(open_histories),
        pending_approval_count=status_counts["pending_approval"],
        backlog_status_counts=status_counts,
        oldest_backlog_days=(
            round(max(backlog_ages), 2) if backlog_ages else None
        ),
        average_closure_hours=_rounded_average(closure_hours),
        median_closure_hours=_rounded_median(closure_hours),
        p90_closure_hours=_nearest_rank(closure_hours, 0.9),
        closure_duration_buckets=_bucket_counts(
            closure_hours,
            _CLOSURE_BUCKETS,
        ),
        average_first_response_hours=_rounded_average(
            first_response_hours
        ),
        median_first_response_hours=_rounded_median(
            first_response_hours
        ),
        responded_within_24h_rate=(
            sum(value <= 24 for value in first_response_hours)
            / len(new_histories)
            if new_histories
            else None
        ),
        cases_without_response=(
            len(new_histories) - len(first_response_hours)
        ),
        backlog_age_buckets=_bucket_counts(
            backlog_ages,
            _BACKLOG_BUCKETS,
        ),
    )

    expected_total = len(window_observations)
    received_total = expected_total - sum(
        item.technical_status == "not_received"
        for item in window_observations
    )
    scoped_mines = (
        sorted(scope)
        if scope is not None
        else sorted(
            {item.mine_id for item in window_observations}
            | {history.case.mine_id for history in open_histories}
            | {history.case.mine_id for history in new_histories}
        )
    )
    return LeadershipAnalytics(
        timezone=timezone,
        window_start=effective_start,
        window_end=effective_end,
        as_of=effective_as_of,
        scoped_mine_ids=scoped_mines,
        expected_report_count=expected_total,
        received_report_count=received_total,
        coverage_rate=(
            received_total / expected_total if expected_total else None
        ),
        daily_trend=daily_trend,
        mine_risk_ranking=risk_ranking,
        repeated_anomalies=repeated_anomalies,
        case_performance=case_performance,
        data_quality=AnalyticsDataQuality(
            ignored_batches_with_invalid_time=bad_batch_times,
            ignored_cases_with_invalid_time=bad_case_times,
            ignored_events_with_invalid_time=bad_event_times,
            inferred_closure_timestamps=inferred_closures,
        ),
        metric_definitions=dict(_METRIC_DEFINITIONS),
        summary=_executive_summary(
            mine_count=len(scoped_mines),
            expected=expected_total,
            received=received_total,
            open_cases=len(open_histories),
            open_p1=sum(
                history.case.priority == "P1"
                for history in open_histories
            ),
            repeated_count=len(repeated_anomalies),
        ),
    )


__all__ = [
    "AnalyticsDataQuality",
    "CasePerformance",
    "DailyTrendPoint",
    "LeadershipAnalytics",
    "MineRiskRanking",
    "RepeatedAnomaly",
    "RiskScoreBreakdown",
    "calculate_leadership_analytics",
]
