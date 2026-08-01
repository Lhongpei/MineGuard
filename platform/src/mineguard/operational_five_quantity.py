"""State-aware retrospective analysis for operational five-quantity reports.

The workbook called "five quantity" in this module contains ventilation,
labour, total electricity, explosives and production.  It is deliberately
separate from MineGuard's production/transport/wash/sales/inventory physical
five-flow model.

This module turns a strictly imported monthly workbook into explainable
technical review events.  It does not persist the upload, create a case, learn
from the file as governed history, or make a regulatory determination.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, timedelta
from enum import StrEnum
import hashlib
import json
import math
from statistics import fmean, median
from typing import Annotated, Literal, Sequence

from pydantic import Field, model_validator

from .five_quantity import (
    DailyReconciliation,
    FiveQuantityDay,
    FiveQuantityImportRequest,
    FiveQuantityImportResult,
    FiveQuantityQualityFinding,
    FiveQuantityQualitySummary,
    FiveQuantityUnits,
    FiveQuantityValidationParameters,
    ReconciliationStatus,
    ReportMonthSource,
    ShiftNumericValues,
    import_five_quantity_et,
)
from .models import StrictModel


OPERATIONAL_FIVE_QUANTITY_METHOD_VERSION = (
    "operational-five-quantity-state-aware-retrospective-v2"
)
CalendarDate = date


class OperationalState(StrEnum):
    OPEN_PERIOD = "open_period"
    UNKNOWN = "unknown"
    NON_PRODUCTION_CANDIDATE = "non_production_candidate"
    RESTART_RAMP_CANDIDATE = "restart_ramp_candidate"
    PRODUCTION = "production"


class RecordCompleteness(StrEnum):
    OPEN_PERIOD = "open_period"
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


class AttentionLevel(StrEnum):
    PRIORITY_CHECK = "priority_check"
    CHECK = "check"
    OBSERVE = "observe"
    INFORMATION = "information"


class EventCategory(StrEnum):
    DATA_QUALITY = "data_quality"
    OPERATING_STATE = "operating_state"
    CROSS_METRIC = "cross_metric"
    SHIFT_STRUCTURE = "shift_structure"
    CONTEXT_REQUIRED = "context_required"


class EventBasis(StrEnum):
    ARITHMETIC_RECONCILIATION = "arithmetic_reconciliation"
    COMPLETENESS_RULE = "completeness_rule"
    STATE_TRANSITION = "state_transition"
    WITHIN_FILE_ROBUST_BASELINE = "within_file_robust_baseline"
    RETROSPECTIVE_CHANGE_POINT = "retrospective_change_point"
    AGGREGATE_SHIFT_SHARE = "aggregate_shift_share"
    CONTEXT_RULE = "context_rule"


class OverallStatus(StrEnum):
    NEEDS_PRIORITY_REVIEW = "needs_priority_review"
    NEEDS_DATA = "needs_data"
    OBSERVATION_ONLY = "observation_only"
    NO_UNEXPLAINED_LEAD = "no_unexplained_lead"
    INSUFFICIENT_DATA = "insufficient_data"


class AnalysisValueBasis(StrEnum):
    REPORTED_DAILY_RECONCILED = "reported_daily_reconciled"
    SHIFT_RECOMPUTED_DUE_TO_MISMATCH = (
        "shift_recomputed_due_to_mismatch"
    )
    REPORTED_DAILY_UNVERIFIED = "reported_daily_unverified"
    UNAVAILABLE = "unavailable"


class OperationalFiveQuantityParameters(StrictModel):
    minimum_non_production_days_for_restart: Annotated[
        int,
        Field(ge=2, le=31),
    ] = 3
    restart_ramp_positive_days: Annotated[
        int,
        Field(ge=1, le=14),
    ] = 3
    minimum_within_state_reference_days: Annotated[
        int,
        Field(ge=5, le=100),
    ] = 7
    robust_z_threshold: Annotated[float, Field(gt=0.0, le=100.0)] = 3.5
    critical_robust_z_threshold: Annotated[
        float,
        Field(gt=0.0, le=100.0),
    ] = 6.0
    minimum_relative_scale: Annotated[
        float,
        Field(ge=0.001, le=0.5),
    ] = 0.02
    shift_labor_share_threshold: Annotated[
        float,
        Field(gt=0.0, le=1.0),
    ] = 0.30
    shift_production_share_threshold: Annotated[
        float,
        Field(ge=0.0, lt=1.0),
    ] = 0.05
    critical_reconciliation_relative_difference: Annotated[
        float,
        Field(gt=0.0, le=1.0),
    ] = 0.05
    production_change_minimum_relative_shift: Annotated[
        float,
        Field(gt=0.0, le=1.0),
    ] = 0.04
    production_change_minimum_explained_fraction: Annotated[
        float,
        Field(gt=0.0, le=1.0),
    ] = 0.45
    production_change_bic_margin: Annotated[
        float,
        Field(ge=0.0, le=100.0),
    ] = 2.0

    @model_validator(mode="after")
    def validate_thresholds(self) -> "OperationalFiveQuantityParameters":
        if self.critical_robust_z_threshold < self.robust_z_threshold:
            raise ValueError(
                "critical_robust_z_threshold cannot be below "
                "robust_z_threshold"
            )
        if (
            self.shift_production_share_threshold
            >= self.shift_labor_share_threshold
        ):
            raise ValueError(
                "shift production threshold must be below labor threshold"
            )
        return self


class OperationalFiveQuantityFileRequest(FiveQuantityImportRequest):
    analysis_parameters: OperationalFiveQuantityParameters = Field(
        default_factory=OperationalFiveQuantityParameters
    )


class OperationalTrustStatement(StrictModel):
    input_class: Literal["operator_uploaded_untrusted"] = (
        "operator_uploaded_untrusted"
    )
    persisted: Literal[False] = False
    audit_metadata_persisted: bool = False
    persistence_statement: Literal[
        "input_and_analysis_result_not_persisted"
    ] = "input_and_analysis_result_not_persisted"
    audit_metadata_scope: Literal[
        "metadata_only_no_file_or_daily_payload"
    ] = "metadata_only_no_file_or_daily_payload"
    eligible_for_history: Literal[False] = False
    creates_case: Literal[False] = False
    regulatory_effect: Literal["none"] = "none"


class OperationalAnalysisConfiguration(StrictModel):
    method_version: str = OPERATIONAL_FIVE_QUANTITY_METHOD_VERSION
    validation: FiveQuantityValidationParameters
    analysis_parameters: OperationalFiveQuantityParameters
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class OperationalCoverage(StrictModel):
    period_start: date
    period_end: date
    closed_through: date
    row_count: Annotated[int, Field(ge=0)]
    closed_day_count: Annotated[int, Field(ge=0)]
    expected_closed_calendar_day_count: Annotated[int, Field(ge=0)]
    missing_closed_calendar_day_count: Annotated[int, Field(ge=0)]
    core_daily_complete_closed_day_count: Annotated[int, Field(ge=0)]
    core_daily_incomplete_closed_day_count: Annotated[int, Field(ge=0)]
    all_required_fields_complete_closed_day_count: Annotated[
        int,
        Field(ge=0),
    ]
    all_required_fields_incomplete_closed_day_count: Annotated[
        int,
        Field(ge=0),
    ]
    all_shift_totals_reconciled_closed_day_count: Annotated[
        int,
        Field(ge=0),
    ]
    shift_totals_not_fully_reconciled_closed_day_count: Annotated[
        int,
        Field(ge=0),
    ]
    # Backward-compatible aliases for the original UI.  Their exact meaning is
    # now explicitly "core daily values", not all workbook fields.
    complete_closed_day_count: Annotated[int, Field(ge=0)]
    incomplete_closed_day_count: Annotated[int, Field(ge=0)]
    open_day_count: Annotated[int, Field(ge=0)]


class OperationalKpi(StrictModel):
    code: str
    label: str
    value: float | int | None
    unit: str | None = None
    contributing_day_count: Annotated[int, Field(ge=0)] = 0
    expected_day_count: Annotated[int, Field(ge=0)] = 0
    excluded_mismatch_day_count: Annotated[int, Field(ge=0)] = 0
    excluded_incomplete_reconciliation_day_count: Annotated[
        int,
        Field(ge=0),
    ] = 0
    is_partial: bool = False
    value_basis: Literal[
        "reconciled_daily_totals_only",
        "derived_from_reconciled_daily_totals_only",
        "reconciled_state_subset",
    ]
    note: str


class OperationalMetricReconciliation(StrictModel):
    metric: Literal[
        "labor",
        "electricity",
        "detonators",
        "explosives",
        "production",
    ]
    reported_daily_total: float | None
    recomputed_shift_total: float | None
    difference_daily_minus_shifts: float | None
    status: ReconciliationStatus
    analysis_value: float | None
    analysis_basis: AnalysisValueBasis
    eligible_for_robust_baseline: bool


class OperationalMetricReconciliationSummary(StrictModel):
    metric: Literal[
        "labor",
        "electricity",
        "detonators",
        "explosives",
        "production",
    ]
    reported_daily_total: float | None
    recomputed_shift_total: float | None
    reconciled_daily_total: float | None
    reported_day_count: Annotated[int, Field(ge=0)]
    recomputed_shift_day_count: Annotated[int, Field(ge=0)]
    matched_day_count: Annotated[int, Field(ge=0)]
    mismatch_day_count: Annotated[int, Field(ge=0)]
    incomplete_day_count: Annotated[int, Field(ge=0)]
    note: str


class OperationalEventFact(StrictModel):
    date: CalendarDate | None = None
    metric: str
    observed: float | int | str | None = None
    expected: float | int | str | None = None
    difference: float | None = None
    robust_z: float | None = None
    description: str


class OperationalReviewEvent(StrictModel):
    event_id: str
    event_code: str
    category: EventCategory
    attention_level: AttentionLevel
    title: str
    summary: str
    period_start: date
    period_end: date
    metrics: list[str]
    basis: list[EventBasis]
    confidence: Literal["high", "medium", "context_required"]
    merged_point_count: Annotated[int, Field(ge=1)]
    facts: list[OperationalEventFact]
    candidate_explanations: list[str]
    recommended_checks: list[str]
    requires_human_verification: Literal[True] = True
    regulatory_effect: Literal["none"] = "none"


class OperationalRegimeSegment(StrictModel):
    state: OperationalState
    start: date
    end: date
    day_count: Annotated[int, Field(ge=1)]
    explanation: str


class OperationalDayAssessment(StrictModel):
    date: CalendarDate
    is_closed: bool
    completeness: RecordCompleteness
    core_daily_complete: bool
    all_required_fields_complete: bool
    all_shift_totals_reconciled: bool
    operational_state: OperationalState
    ventilation: float | None
    labor: float | None
    electricity: float | None
    production: float | None
    total_electricity_to_production_ratio: float | None
    production_to_labor_ratio: float | None
    ventilation_to_production_ratio: float | None
    metric_reconciliations: list[OperationalMetricReconciliation]
    reason_codes: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)


class OperationalOverall(StrictModel):
    status: OverallStatus
    title: str
    summary: str
    priority_event_count: Annotated[int, Field(ge=0)]
    check_event_count: Annotated[int, Field(ge=0)]
    observation_event_count: Annotated[int, Field(ge=0)]


class OperationalFiveQuantityResult(StrictModel):
    schema_version: Literal[
        "mineguard.operational-five-quantity-monthly.v1"
    ] = "mineguard.operational-five-quantity-monthly.v1"
    method_version: str = OPERATIONAL_FIVE_QUANTITY_METHOD_VERSION
    analysis_mode: Literal["retrospective"] = "retrospective"
    lookahead_used: Literal[True] = True
    mine_id: str
    report_month: Annotated[
        str,
        Field(pattern=r"^\d{4}-(?:0[1-9]|1[0-2])$"),
    ]
    report_month_source: ReportMonthSource
    source_title: str
    source_sha256: str
    configuration: OperationalAnalysisConfiguration
    units: FiveQuantityUnits
    unknown_unit_fields: list[str]
    trust: OperationalTrustStatement
    overall: OperationalOverall
    coverage: OperationalCoverage
    kpis: list[OperationalKpi]
    metric_reconciliation_summaries: list[
        OperationalMetricReconciliationSummary
    ]
    regimes: list[OperationalRegimeSegment]
    events: list[OperationalReviewEvent]
    days: list[OperationalDayAssessment]
    import_quality: FiveQuantityQualitySummary
    limitations: list[str]


def analyze_operational_five_quantity_file(
    request: OperationalFiveQuantityFileRequest,
) -> OperationalFiveQuantityResult:
    imported = import_five_quantity_et(request)
    return analyze_operational_five_quantity(
        imported,
        request.analysis_parameters,
    )


def analyze_operational_five_quantity(
    imported: FiveQuantityImportResult,
    parameters: OperationalFiveQuantityParameters | None = None,
) -> OperationalFiveQuantityResult:
    """Build a deterministic retrospective monthly technical-lead report."""

    parameters = parameters or OperationalFiveQuantityParameters()
    if not imported.days:
        raise ValueError("five-quantity import contains no daily rows")
    configuration = _analysis_configuration(
        imported.validation,
        parameters,
    )

    days = _assess_days(
        imported.days,
        parameters,
        expected_period_start=date.fromisoformat(
            f"{imported.report_month}-01"
        ),
    )
    regimes = _regime_segments(days)
    events: list[OperationalReviewEvent] = []
    events.extend(_quality_events(imported, parameters))
    events.extend(_restart_events(imported, days, regimes))
    events.extend(_robust_ratio_events(imported, days, parameters))
    shift_event = _shift_structure_event(imported, days, parameters)
    if shift_event is not None:
        events.append(shift_event)
    production_change = _production_change_event(
        imported,
        days,
        parameters,
    )
    if production_change is not None:
        events.append(production_change)

    events = _deduplicate_and_sort_events(events)
    events = _bind_configuration_to_event_ids(
        events,
        configuration.sha256,
    )
    days = _attach_event_ids(days, events)
    coverage = _coverage(imported, days)
    kpis = _kpis(imported, days)
    reconciliation_summaries = _reconciliation_summaries(days)
    overall = _overall(events, coverage, imported.quality)

    limitations = [
        "本结果来自操作员临时上传：文件和分析正文未落库、未建案，也不能进入"
        "受治理历史基线；生产 API 可另行保留不含文件及逐日正文的最小审计"
        "元数据，实际是否已写入以 trust.audit_metadata_persisted 为准。",
        "同一工作簿内各指标尚未证明来自相互独立的数据源，只能形成辅助核查线索。",
        "“总电量/产量比”包含通风、排水、压风、提升、洗选等未知干扰负荷，"
        "不是生产分区吨煤电耗。",
        "运行状态和变点来自表内数值模式，属于候选解释；停产、检修、复产等事实"
        "仍需工单、设备记录和现场资料确认。",
        "稳健基线仅由当前文件内同状态日期回顾性形成，不是长期历史基线，不能"
        "用于自动监管定性；该模式使用整月后见信息，不能冒充在线实时预警。",
        "日报与三班合计不一致时，该日比值候选点可明确改用三班重算值，但争议日"
        "不进入稳健参考基线；月度无争议 KPI 同样排除该日，并并列给出日报、"
        "三班重算及已对账累计口径。",
        "所有事件均为技术核查线索，不表示违法事实、责任或处罚结论。",
    ]
    if imported.unknown_unit_fields:
        limitations.append(
            "部分指标单位未声明，派生比值只按原表数值口径展示，禁止直接跨矿比较。"
        )
    if imported.formula_cell_count:
        limitations.append(
            "工作簿含公式缓存；平台未执行公式，已独立重算可核对的班次合计。"
        )

    return OperationalFiveQuantityResult(
        mine_id=imported.mine_id,
        report_month=imported.report_month,
        report_month_source=imported.report_month_source,
        source_title=imported.source_title,
        source_sha256=imported.source_sha256,
        configuration=configuration,
        units=imported.units,
        unknown_unit_fields=imported.unknown_unit_fields,
        trust=OperationalTrustStatement(),
        overall=overall,
        coverage=coverage,
        kpis=kpis,
        metric_reconciliation_summaries=reconciliation_summaries,
        regimes=regimes,
        events=events,
        days=days,
        import_quality=imported.quality,
        limitations=limitations,
    )


def _analysis_configuration(
    validation: FiveQuantityValidationParameters,
    parameters: OperationalFiveQuantityParameters,
) -> OperationalAnalysisConfiguration:
    payload = {
        "method_version": OPERATIONAL_FIVE_QUANTITY_METHOD_VERSION,
        "validation": validation.model_dump(mode="json"),
        "analysis_parameters": parameters.model_dump(mode="json"),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return OperationalAnalysisConfiguration(
        **payload,
        sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )


def _assess_days(
    imported_days: Sequence[FiveQuantityDay],
    parameters: OperationalFiveQuantityParameters,
    *,
    expected_period_start: date | None = None,
) -> list[OperationalDayAssessment]:
    state_by_date: dict[date, OperationalState] = {}
    reason_by_date: dict[date, list[str]] = defaultdict(list)
    non_production_run = 0
    ramp_remaining = 0
    previous_date: date | None = (
        expected_period_start - timedelta(days=1)
        if expected_period_start is not None
        else None
    )

    for day in imported_days:
        production = day.production.daily_total
        production_reconciliation = _reconciliation_for(
            day,
            "production",
        )
        calendar_gap_before = (
            previous_date is not None
            and day.date != previous_date + timedelta(days=1)
        )
        previous_date = day.date
        if not day.is_closed:
            state_by_date[day.date] = OperationalState.OPEN_PERIOD
            reason_by_date[day.date].append("OPEN_ROW_EXCLUDED")
            non_production_run = 0
            ramp_remaining = 0
            continue
        if calendar_gap_before:
            state_by_date[day.date] = OperationalState.UNKNOWN
            reason_by_date[day.date].append("CALENDAR_GAP_BEFORE")
            non_production_run = 0
            ramp_remaining = 0
            continue
        if production is None:
            state_by_date[day.date] = OperationalState.UNKNOWN
            reason_by_date[day.date].append("PRODUCTION_MISSING")
            non_production_run = 0
            ramp_remaining = 0
            continue
        if production_reconciliation.status is not ReconciliationStatus.MATCH:
            state_by_date[day.date] = OperationalState.UNKNOWN
            reason_by_date[day.date].append(
                (
                    "PRODUCTION_DAILY_SHIFT_MISMATCH"
                    if production_reconciliation.status
                    is ReconciliationStatus.MISMATCH
                    else "PRODUCTION_RECONCILIATION_INCOMPLETE"
                )
            )
            non_production_run = 0
            ramp_remaining = 0
            continue
        if production == 0.0:
            state_by_date[day.date] = (
                OperationalState.NON_PRODUCTION_CANDIDATE
            )
            reason_by_date[day.date].append("REPORTED_ZERO_PRODUCTION")
            non_production_run += 1
            ramp_remaining = 0
            continue

        if (
            non_production_run
            >= parameters.minimum_non_production_days_for_restart
        ):
            state_by_date[day.date] = (
                OperationalState.RESTART_RAMP_CANDIDATE
            )
            reason_by_date[day.date].append(
                "POSITIVE_AFTER_CONSECUTIVE_ZERO_PRODUCTION"
            )
            ramp_remaining = parameters.restart_ramp_positive_days - 1
        elif ramp_remaining > 0:
            state_by_date[day.date] = (
                OperationalState.RESTART_RAMP_CANDIDATE
            )
            reason_by_date[day.date].append("RESTART_RAMP_WINDOW")
            ramp_remaining -= 1
        else:
            state_by_date[day.date] = OperationalState.PRODUCTION
        non_production_run = 0

    result: list[OperationalDayAssessment] = []
    for day in imported_days:
        reconciliations = _metric_reconciliations(day)
        reconciliation_by_metric = {
            item.metric: item for item in reconciliations
        }
        core_values = (
            day.ventilation,
            day.labor.daily_total,
            day.electricity.daily_total,
            day.production.daily_total,
        )
        core_daily_complete = all(value is not None for value in core_values)
        all_required_fields_complete = _all_required_fields_complete(day)
        all_shift_totals_reconciled = all(
            item.status is ReconciliationStatus.MATCH
            for item in reconciliations
        )
        if not day.is_closed:
            completeness = RecordCompleteness.OPEN_PERIOD
        elif not core_daily_complete:
            completeness = RecordCompleteness.INCOMPLETE
            reason_by_date[day.date].append("CLOSED_CORE_VALUE_MISSING")
        else:
            completeness = RecordCompleteness.COMPLETE
        for item in reconciliations:
            if item.status is ReconciliationStatus.MISMATCH:
                reason_by_date[day.date].append(
                    f"{item.metric.upper()}_DAILY_SHIFT_MISMATCH"
                )
            elif item.status is ReconciliationStatus.INCOMPLETE:
                reason_by_date[day.date].append(
                    f"{item.metric.upper()}_RECONCILIATION_INCOMPLETE"
                )
        production = day.production.daily_total
        analysis_production = _usable_analysis_value(
            reconciliation_by_metric["production"]
        )
        analysis_electricity = _usable_analysis_value(
            reconciliation_by_metric["electricity"]
        )
        analysis_labor = _usable_analysis_value(
            reconciliation_by_metric["labor"]
        )
        result.append(
            OperationalDayAssessment(
                date=day.date,
                is_closed=day.is_closed,
                completeness=completeness,
                core_daily_complete=core_daily_complete,
                all_required_fields_complete=all_required_fields_complete,
                all_shift_totals_reconciled=all_shift_totals_reconciled,
                operational_state=state_by_date[day.date],
                ventilation=day.ventilation,
                labor=day.labor.daily_total,
                electricity=day.electricity.daily_total,
                production=production,
                total_electricity_to_production_ratio=_safe_ratio(
                    analysis_electricity,
                    analysis_production,
                ),
                production_to_labor_ratio=_safe_ratio(
                    analysis_production,
                    analysis_labor,
                ),
                ventilation_to_production_ratio=_safe_ratio(
                    day.ventilation,
                    analysis_production,
                ),
                metric_reconciliations=reconciliations,
                reason_codes=sorted(set(reason_by_date[day.date])),
            )
        )
    return result


def _metric_reconciliations(
    day: FiveQuantityDay,
) -> list[OperationalMetricReconciliation]:
    result: list[OperationalMetricReconciliation] = []
    for metric in (
        "labor",
        "electricity",
        "detonators",
        "explosives",
        "production",
    ):
        reconciliation = _reconciliation_for(day, metric)
        if reconciliation.status is ReconciliationStatus.MATCH:
            analysis_value = reconciliation.daily_total
            basis = AnalysisValueBasis.REPORTED_DAILY_RECONCILED
            eligible = analysis_value is not None
        elif reconciliation.status is ReconciliationStatus.MISMATCH:
            # A failed reported total is never fed directly to a baseline.
            # Complete shifts provide an explicit alternative calculation while
            # both values remain visible as a data dispute.
            analysis_value = reconciliation.shift_sum
            basis = AnalysisValueBasis.SHIFT_RECOMPUTED_DUE_TO_MISMATCH
            eligible = False
        elif reconciliation.daily_total is not None:
            analysis_value = reconciliation.daily_total
            basis = AnalysisValueBasis.REPORTED_DAILY_UNVERIFIED
            eligible = False
        else:
            analysis_value = None
            basis = AnalysisValueBasis.UNAVAILABLE
            eligible = False
        result.append(
            OperationalMetricReconciliation(
                metric=metric,
                reported_daily_total=reconciliation.daily_total,
                recomputed_shift_total=reconciliation.shift_sum,
                difference_daily_minus_shifts=(
                    reconciliation.difference_daily_minus_shifts
                ),
                status=reconciliation.status,
                analysis_value=analysis_value,
                analysis_basis=basis,
                eligible_for_robust_baseline=eligible,
            )
        )
    return result


def _usable_analysis_value(
    reconciliation: OperationalMetricReconciliation,
) -> float | None:
    if reconciliation.analysis_basis not in {
        AnalysisValueBasis.REPORTED_DAILY_RECONCILED,
        AnalysisValueBasis.SHIFT_RECOMPUTED_DUE_TO_MISMATCH,
    }:
        return None
    return reconciliation.analysis_value


def _reconciliation_for(
    day: FiveQuantityDay,
    metric: Literal[
        "labor",
        "electricity",
        "detonators",
        "explosives",
        "production",
    ],
) -> DailyReconciliation:
    for reconciliation in day.reconciliations:
        if reconciliation.metric == metric:
            return reconciliation

    if metric in {"labor", "electricity", "production"}:
        values = getattr(day, metric)
        shifts = (
            values.zero_shift,
            values.eight_shift,
            values.four_shift,
        )
        daily_total = values.daily_total
    else:
        shifts = tuple(
            getattr(item, metric)
            for item in (
                day.explosives.zero_shift,
                day.explosives.eight_shift,
                day.explosives.four_shift,
            )
        )
        daily_total = getattr(day.explosives.daily_total, metric)
    if daily_total is None or any(value is None for value in shifts):
        return DailyReconciliation(
            metric=metric,
            shift_sum=None,
            daily_total=daily_total,
            difference_daily_minus_shifts=None,
            tolerance=0.0,
            status=ReconciliationStatus.INCOMPLETE,
        )
    shift_sum = math.fsum(float(value) for value in shifts if value is not None)
    difference = float(daily_total) - shift_sum
    return DailyReconciliation(
        metric=metric,
        shift_sum=shift_sum,
        daily_total=daily_total,
        difference_daily_minus_shifts=difference,
        tolerance=1e-9,
        status=(
            ReconciliationStatus.MATCH
            if abs(difference) <= 1e-9
            else ReconciliationStatus.MISMATCH
        ),
    )


def _all_required_fields_complete(day: FiveQuantityDay) -> bool:
    numeric_groups = (day.labor, day.electricity, day.production)
    if day.ventilation is None:
        return False
    if any(
        value is None
        for group in numeric_groups
        for value in (
            group.zero_shift,
            group.eight_shift,
            group.four_shift,
            group.daily_total,
        )
    ):
        return False
    return all(
        getattr(record, metric) is not None
        for record in (
            day.explosives.zero_shift,
            day.explosives.eight_shift,
            day.explosives.four_shift,
            day.explosives.daily_total,
        )
        for metric in ("detonators", "explosives")
    )


def _safe_ratio(
    numerator: float | None,
    denominator: float | None,
) -> float | None:
    if numerator is None or denominator is None or denominator <= 0.0:
        return None
    return numerator / denominator


def _regime_segments(
    days: Sequence[OperationalDayAssessment],
) -> list[OperationalRegimeSegment]:
    if not days:
        return []
    groups: list[list[OperationalDayAssessment]] = [[days[0]]]
    for day in days[1:]:
        previous = groups[-1][-1]
        if (
            day.operational_state == previous.operational_state
            and day.date == previous.date + timedelta(days=1)
        ):
            groups[-1].append(day)
        else:
            groups.append([day])
    explanations = {
        OperationalState.OPEN_PERIOD: "尚未闭账，未参与缺失和异常基线。",
        OperationalState.UNKNOWN: (
            "日期不连续、产量缺失或产量日报与班次无法一致核对，"
            "因此不推断运行状态。"
        ),
        OperationalState.NON_PRODUCTION_CANDIDATE: (
            "表内产量明确为零；是否停产仍需业务记录确认。"
        ),
        OperationalState.RESTART_RAMP_CANDIDATE: (
            "连续零产之后恢复正产量，按复产爬坡候选单独分析。"
        ),
        OperationalState.PRODUCTION: "表内产量为正，作为生产状态候选。",
    }
    return [
        OperationalRegimeSegment(
            state=group[0].operational_state,
            start=group[0].date,
            end=group[-1].date,
            day_count=len(group),
            explanation=explanations[group[0].operational_state],
        )
        for group in groups
    ]


def _quality_events(
    imported: FiveQuantityImportResult,
    parameters: OperationalFiveQuantityParameters,
) -> list[OperationalReviewEvent]:
    events: list[OperationalReviewEvent] = []
    findings = imported.quality.findings

    for finding in findings:
        if finding.code != "SHIFT_TOTAL_MISMATCH" or finding.date is None:
            continue
        relative = _relative_difference(
            finding.difference,
            finding.observed,
            finding.expected,
        )
        attention = (
            AttentionLevel.PRIORITY_CHECK
            if relative
            >= parameters.critical_reconciliation_relative_difference
            else AttentionLevel.CHECK
        )
        metric_label = _metric_label(finding.metric or "unknown")
        events.append(
            _event(
                imported,
                code=f"shift_total_mismatch:{finding.metric}",
                category=EventCategory.DATA_QUALITY,
                attention=attention,
                title=f"{finding.date.isoformat()} {metric_label}班次合计不一致",
                summary=(
                    f"日统计为 {_number_text(finding.observed)}，三个班次合计为"
                    f" {_number_text(finding.expected)}，日统计减班次合计为"
                    f" {_number_text(finding.difference)}。"
                ),
                start=finding.date,
                end=finding.date,
                metrics=[finding.metric or "unknown"],
                basis=[EventBasis.ARITHMETIC_RECONCILIATION],
                confidence="high",
                facts=[
                    OperationalEventFact(
                        date=finding.date,
                        metric=finding.metric or "unknown",
                        observed=finding.observed,
                        expected=finding.expected,
                        difference=finding.difference,
                        description="日统计与三班原始值重新求和后的差额。",
                    )
                ],
                candidate_explanations=[
                    "日报公式缓存或人工录入差异",
                    "抄表时点、日界或班次边界不一致",
                    "某个班次或回路缺采",
                ],
                recommended_checks=[
                    "核对该日三班原始记录、日报公式及签字版本",
                    "按统一日界重新汇总设备明细",
                ],
            )
        )

    missing_calendar_dates = sorted(
        {
            finding.date
            for finding in findings
            if finding.code == "MISSING_CALENDAR_DATE"
            and finding.date is not None
        }
    )
    if missing_calendar_dates:
        events.append(
            _event(
                imported,
                code="closed_calendar_rows_missing",
                category=EventCategory.DATA_QUALITY,
                attention=AttentionLevel.PRIORITY_CHECK,
                title="闭账范围缺少整日数据行",
                summary=(
                    f"闭账范围内缺少 {len(missing_calendar_dates)} 个日期行；"
                    "这些日期不能按数值零处理。"
                ),
                start=missing_calendar_dates[0],
                end=missing_calendar_dates[-1],
                metrics=["calendar_coverage"],
                basis=[EventBasis.COMPLETENESS_RULE],
                confidence="high",
                facts=[
                    OperationalEventFact(
                        date=missing_date,
                        metric="calendar_coverage",
                        observed="missing",
                        expected="one source row",
                        description="闭账范围内该自然日没有来源数据行。",
                    )
                    for missing_date in missing_calendar_dates
                ],
                candidate_explanations=[
                    "来源系统整日未上报",
                    "导出范围或日期筛选遗漏",
                    "文件修订时删除了整行",
                ],
                recommended_checks=[
                    "从来源系统补取该日原始记录并核对导出日志",
                    "不要新增全零行代替缺失数据",
                ],
                merged_point_count=len(missing_calendar_dates),
            )
        )

    missing = [
        finding
        for finding in findings
        if finding.code == "MISSING_REQUIRED_VALUE"
        and finding.date is not None
    ]
    grouped_missing: dict[
        tuple[str, Literal["daily", "shift"]],
        list[FiveQuantityQualityFinding],
    ] = defaultdict(list)
    for finding in missing:
        metric_parts = str(finding.metric or "unknown").split(".", 1)
        base_metric = metric_parts[0]
        position = metric_parts[1] if len(metric_parts) == 2 else "daily"
        granularity: Literal["daily", "shift"] = (
            "daily"
            if position in {"daily", "daily_total"}
            else "shift"
        )
        grouped_missing[(base_metric, granularity)].append(finding)
    for (metric, granularity), items in sorted(grouped_missing.items()):
        dates = sorted({item.date for item in items if item.date is not None})
        if not dates:
            continue
        positions = sorted(
            {
                str(item.metric).split(".", 1)[1]
                for item in items
                if item.metric and "." in item.metric
            }
        )
        daily_missing = granularity == "daily"
        scope_text = "日报总值" if daily_missing else "班次明细"
        events.append(
            _event(
                imported,
                code=(
                    f"closed_daily_value_missing:{metric}"
                    if daily_missing
                    else f"closed_shift_values_missing:{metric}"
                ),
                category=EventCategory.DATA_QUALITY,
                attention=(
                    AttentionLevel.PRIORITY_CHECK
                    if daily_missing
                    else AttentionLevel.CHECK
                ),
                title=f"{_metric_label(metric)}{scope_text}不完整",
                summary=(
                    f"{len(dates)} 个闭账日共缺少 {len(items)} 个{scope_text}；"
                    f"缺失位置：{'、'.join(positions) if positions else '日值'}。"
                ),
                start=dates[0],
                end=dates[-1],
                metrics=[metric],
                basis=[EventBasis.COMPLETENESS_RULE],
                confidence="high",
                facts=[
                    OperationalEventFact(
                        date=missing_date,
                        metric=metric,
                        observed=sum(
                            item.date == missing_date for item in items
                        ),
                        expected=0,
                        description=(
                            f"该闭账日明确为空白的{scope_text}数量。"
                        ),
                    )
                    for missing_date in dates
                ],
                candidate_explanations=[
                    "来源系统未采集",
                    "月报未完成填报",
                    "班次明细未接入但日统计由其他口径形成",
                ],
                recommended_checks=[
                    "补齐原始明细并保留来源、时间戳和修订记录",
                    "不要将空白补成数值零",
                ],
                merged_point_count=len(dates),
            )
        )

    contextual_mapping = {
        "DOCUMENT_TITLE_PLACEHOLDER": (
            "document_identity_placeholder",
            EventCategory.DATA_QUALITY,
            AttentionLevel.CHECK,
            "文件标题仍含占位身份",
            "核对企业、矿井和来源系统身份；平台只采用监管侧显式 mine_id 绑定。",
        ),
        "EXPLOSIVES_ALL_ZERO_WITH_PRODUCTION": (
            "explosives_all_zero_with_production",
            EventCategory.CONTEXT_REQUIRED,
            AttentionLevel.OBSERVE,
            "生产期间火工品持续报零",
            "确认是否为非爆破工艺，并调取火工品领退库和作业方式凭证。",
        ),
        "WIND_STEP_PATTERN": (
            "ventilation_step_pattern",
            EventCategory.CONTEXT_REQUIRED,
            AttentionLevel.OBSERVE,
            "风量呈连续恒定台阶",
            "确认这些值是核定/设定值还是实测日值，并关联设定变更记录。",
        ),
        "UNDECLARED_UNITS": (
            "units_undeclared",
            EventCategory.DATA_QUALITY,
            AttentionLevel.CHECK,
            "指标单位未完整声明",
            "确认各指标单位和统计口径后再进行跨矿、跨月比较。",
        ),
    }
    seen_codes: set[str] = set()
    for finding in findings:
        mapping = contextual_mapping.get(finding.code)
        if mapping is None:
            continue
        code, category, attention, title, action = mapping
        if code in seen_codes:
            continue
        seen_codes.add(code)
        closed_dates = [day.date for day in imported.days if day.is_closed]
        if not closed_dates:
            continue
        events.append(
            _event(
                imported,
                code=code,
                category=category,
                attention=attention,
                title=title,
                summary=finding.message,
                start=closed_dates[0],
                end=closed_dates[-1],
                metrics=[finding.metric or _context_metric(finding.code)],
                basis=[EventBasis.CONTEXT_RULE],
                confidence="context_required",
                facts=[
                    OperationalEventFact(
                        metric=finding.metric
                        or _context_metric(finding.code),
                        observed=finding.observed,
                        expected=finding.expected,
                        difference=finding.difference,
                        description=finding.message,
                    )
                ],
                candidate_explanations=[],
                recommended_checks=[action],
            )
        )
    return events


def _relative_difference(
    difference: float | None,
    observed: float | int | str | None,
    expected: float | int | str | None,
) -> float:
    numeric = [
        abs(float(value))
        for value in (observed, expected)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    denominator = max(numeric, default=0.0)
    if difference is None or denominator <= 0.0:
        return 0.0
    return abs(difference) / denominator


def _restart_events(
    imported: FiveQuantityImportResult,
    days: Sequence[OperationalDayAssessment],
    regimes: Sequence[OperationalRegimeSegment],
) -> list[OperationalReviewEvent]:
    events: list[OperationalReviewEvent] = []
    by_date = {day.date: day for day in days}
    for index, segment in enumerate(regimes):
        if segment.state is not OperationalState.RESTART_RAMP_CANDIDATE:
            continue
        previous = regimes[index - 1] if index else None
        if (
            previous is None
            or previous.state
            is not OperationalState.NON_PRODUCTION_CANDIDATE
        ):
            continue
        non_production_days = [
            day
            for day in days
            if previous.start <= day.date <= previous.end
        ]
        electricity = [
            day.electricity
            for day in non_production_days
            if day.electricity is not None
        ]
        labor = [
            day.labor for day in non_production_days if day.labor is not None
        ]
        first = by_date[segment.start]
        facts = [
            OperationalEventFact(
                metric="production",
                observed=previous.day_count,
                expected=0,
                description="此前连续明确零产的闭账日数量。",
            ),
            OperationalEventFact(
                date=segment.start,
                metric="production",
                observed=first.production,
                description="恢复正产量的第一个闭账日。",
            ),
        ]
        if electricity:
            facts.append(
                OperationalEventFact(
                    metric="electricity",
                    observed=fmean(electricity),
                    description=(
                        "此前零产阶段日报口径的日均总电量；"
                        "其班次对账状态应结合逐日结构化字段查看。"
                    ),
                )
            )
        if labor:
            facts.append(
                OperationalEventFact(
                    metric="labor",
                    observed=fmean(labor),
                    description=(
                        "此前零产阶段日报口径的日均用工；"
                        "其班次对账状态应结合逐日结构化字段查看。"
                    ),
                )
            )
        events.append(
            _event(
                imported,
                code="restart_after_reported_zero_production",
                category=EventCategory.OPERATING_STATE,
                attention=AttentionLevel.OBSERVE,
                title="检测到非生产运行后复产爬坡候选",
                summary=(
                    f"{previous.start.isoformat()} 至 {previous.end.isoformat()}"
                    f"连续 {previous.day_count} 天报零产；"
                    f"{segment.start.isoformat()} 起恢复正产量，后续"
                    f" {segment.day_count} 天按复产爬坡候选单独分析。"
                ),
                start=segment.start,
                end=segment.end,
                metrics=["production", "electricity", "labor"],
                basis=[EventBasis.STATE_TRANSITION],
                confidence="medium",
                facts=facts,
                candidate_explanations=[
                    "经批准的停产检修后复产",
                    "工作面或统计口径切换",
                    "前期产量漏填后恢复填报",
                ],
                recommended_checks=[
                    "核对停复产审批、检修工单和设备启停记录",
                    "复产爬坡期使用独立基线，不与稳产期混算",
                ],
            )
        )
    return events


def _robust_ratio_events(
    imported: FiveQuantityImportResult,
    days: Sequence[OperationalDayAssessment],
    parameters: OperationalFiveQuantityParameters,
) -> list[OperationalReviewEvent]:
    features = {
        "total_electricity_to_production_ratio": (
            "总电量/产量比",
            "total_electricity_to_production_ratio",
        ),
        "production_to_labor_ratio": (
            "产量/用工比",
            "production_to_labor_ratio",
        ),
        "ventilation_to_production_ratio": (
            "风量/产量比",
            "ventilation_to_production_ratio",
        ),
    }
    events: list[OperationalReviewEvent] = []
    for metric, (label, attribute) in features.items():
        candidates = [
            day
            for day in days
            if day.is_closed
            and day.operational_state is OperationalState.PRODUCTION
            and getattr(day, attribute) is not None
        ]
        reference_days = [
            day
            for day in candidates
            if _ratio_baseline_eligible(day, metric)
        ]
        if (
            len(reference_days)
            < parameters.minimum_within_state_reference_days
        ):
            continue
        values = [
            float(getattr(day, attribute)) for day in reference_days
        ]
        centre = float(median(values))
        mad = float(median(abs(value - centre) for value in values))
        scale = max(
            1.4826 * mad,
            abs(centre) * parameters.minimum_relative_scale,
            1e-9,
        )
        anomalies: list[
            tuple[OperationalDayAssessment, float, Literal["high", "low"]]
        ] = []
        for day in candidates:
            value = float(getattr(day, attribute))
            robust_z = (value - centre) / scale
            if abs(robust_z) > parameters.robust_z_threshold:
                anomalies.append(
                    (
                        day,
                        robust_z,
                        "high" if robust_z > 0.0 else "low",
                    )
                )
        for group in _consecutive_anomaly_groups(anomalies):
            maximum_z = max(abs(item[1]) for item in group)
            attention = (
                AttentionLevel.PRIORITY_CHECK
                if maximum_z >= parameters.critical_robust_z_threshold
                and metric == "total_electricity_to_production_ratio"
                else AttentionLevel.CHECK
            )
            direction = group[0][2]
            direction_text = "偏高" if direction == "high" else "偏低"
            start, end = group[0][0].date, group[-1][0].date
            facts = [
                OperationalEventFact(
                    date=day.date,
                    metric=metric,
                    observed=float(getattr(day, attribute)),
                    expected=centre,
                    robust_z=robust_z,
                    description=(
                        f"相对当前文件稳产候选日期的 median/MAD 基线"
                        f"{direction_text}。{_ratio_basis_note(day, metric)}"
                    ),
                )
                for day, robust_z, _ in group
            ]
            events.append(
                _event(
                    imported,
                    code=f"within_state_ratio_{direction}:{metric}",
                    category=EventCategory.CROSS_METRIC,
                    attention=attention,
                    title=f"{start.isoformat()} 至 {end.isoformat()} {label}{direction_text}",
                    summary=(
                        f"连续 {len(group)} 个稳产候选日相对当前文件内同状态"
                        f"基线{direction_text}；基线中位数为 {_number_text(centre)}，"
                        f"最大稳健偏离为 {maximum_z:.2f}。"
                    ),
                    start=start,
                    end=end,
                    metrics=[metric],
                    basis=[EventBasis.WITHIN_FILE_ROBUST_BASELINE],
                    confidence="medium",
                    facts=facts,
                    candidate_explanations=(
                        [
                            "总电表包含的干扰负荷发生变化",
                            "电量或产量采集、归集时点发生变化",
                            "生产组织或设备组合改变",
                        ]
                        if metric
                        == "total_electricity_to_production_ratio"
                        else [
                            "班次组织、工作面或设备效率改变",
                            "分母口径或统计边界改变",
                        ]
                    ),
                    recommended_checks=[
                        "核对同日原始时序、班次边界和运行工况",
                        "与同矿同状态的受治理历史正常样本比较",
                    ],
                )
            )
    return events


def _ratio_baseline_eligible(
    day: OperationalDayAssessment,
    ratio_metric: str,
) -> bool:
    required_metrics = {
        "total_electricity_to_production_ratio": (
            "electricity",
            "production",
        ),
        "production_to_labor_ratio": ("production", "labor"),
        "ventilation_to_production_ratio": ("production",),
    }.get(ratio_metric, ())
    reconciliation_by_metric = {
        item.metric: item for item in day.metric_reconciliations
    }
    return bool(required_metrics) and all(
        reconciliation_by_metric[metric].eligible_for_robust_baseline
        for metric in required_metrics
    )


def _ratio_basis_note(
    day: OperationalDayAssessment,
    ratio_metric: str,
) -> str:
    source_metrics = {
        "total_electricity_to_production_ratio": (
            "electricity",
            "production",
        ),
        "production_to_labor_ratio": ("production", "labor"),
        "ventilation_to_production_ratio": ("production",),
    }.get(ratio_metric, ())
    recomputed = [
        item.metric
        for item in day.metric_reconciliations
        if item.metric in source_metrics
        and item.analysis_basis
        is AnalysisValueBasis.SHIFT_RECOMPUTED_DUE_TO_MISMATCH
    ]
    if not recomputed:
        return "组成指标采用已通过班次对账的日报值。"
    labels = "、".join(_metric_label(metric) for metric in recomputed)
    return (
        f"{labels}日报对账失败，本比值明确改用三班重算值；"
        "原日报值仍作为争议口径保留。"
    )


def _consecutive_anomaly_groups(
    anomalies: Sequence[
        tuple[OperationalDayAssessment, float, Literal["high", "low"]]
    ],
) -> list[
    list[tuple[OperationalDayAssessment, float, Literal["high", "low"]]]
]:
    if not anomalies:
        return []
    groups = [[anomalies[0]]]
    for anomaly in anomalies[1:]:
        previous = groups[-1][-1]
        if (
            anomaly[2] == previous[2]
            and anomaly[0].date == previous[0].date + timedelta(days=1)
        ):
            groups[-1].append(anomaly)
        else:
            groups.append([anomaly])
    return groups


def _shift_structure_event(
    imported: FiveQuantityImportResult,
    days: Sequence[OperationalDayAssessment],
    parameters: OperationalFiveQuantityParameters,
) -> OperationalReviewEvent | None:
    source_days = {
        day.date: day
        for day in imported.days
        if day.is_closed and (day.production.daily_total or 0.0) > 0.0
    }
    eligible_dates = {
        day.date
        for day in days
        if day.is_closed
        and day.operational_state
        in {
            OperationalState.PRODUCTION,
            OperationalState.RESTART_RAMP_CANDIDATE,
        }
    }
    selected = [
        source_days[observed_date]
        for observed_date in sorted(source_days)
        if observed_date in eligible_dates
        and _complete_shifts(source_days[observed_date].labor)
        and _complete_shifts(source_days[observed_date].production)
    ]
    if not selected:
        return None

    shifts = (
        ("zero_shift", "零点班"),
        ("eight_shift", "八点班"),
        ("four_shift", "四点班"),
    )
    labor_sums = {
        code: math.fsum(float(getattr(day.labor, code)) for day in selected)
        for code, _ in shifts
    }
    production_sums = {
        code: math.fsum(
            float(getattr(day.production, code)) for day in selected
        )
        for code, _ in shifts
    }
    labor_total = math.fsum(labor_sums.values())
    production_total = math.fsum(production_sums.values())
    if labor_total <= 0.0 or production_total <= 0.0:
        return None

    mismatches: list[tuple[str, str, float, float]] = []
    for code, label in shifts:
        labor_share = labor_sums[code] / labor_total
        production_share = production_sums[code] / production_total
        if (
            labor_share >= parameters.shift_labor_share_threshold
            and production_share
            <= parameters.shift_production_share_threshold
        ):
            mismatches.append(
                (code, label, labor_share, production_share)
            )
    if not mismatches:
        return None

    facts = [
        OperationalEventFact(
            metric=f"shift_share.{code}",
            observed=production_share,
            expected=labor_share,
            difference=production_share - labor_share,
            description=(
                f"{label}用工占比 {labor_share:.2%}，产量占比"
                f" {production_share:.2%}。"
            ),
        )
        for code, label, labor_share, production_share in mismatches
    ]
    start, end = selected[0].date, selected[-1].date
    labels = "、".join(item[1] for item in mismatches)
    return _event(
        imported,
        code="aggregate_shift_labor_production_mismatch",
        category=EventCategory.SHIFT_STRUCTURE,
        attention=AttentionLevel.CHECK,
        title=f"{labels}用工与产量占比长期错配候选",
        summary=(
            f"在 {len(selected)} 个有产量且班次完整的闭账日中，"
            "一个或多个班次用工占比较高但产量占比很低。"
        ),
        start=start,
        end=end,
        metrics=["labor.shift_share", "production.shift_share"],
        basis=[EventBasis.AGGREGATE_SHIFT_SHARE],
        confidence="context_required",
        facts=facts,
        candidate_explanations=[
            "该班次固定承担检修、交接或辅助作业",
            "产量统计日界与人员班次边界不一致",
            "产量被批量归集到其他班次",
        ],
        recommended_checks=[
            "确认班次功能和统一日界定义",
            "抽取人员定位、设备运行和班次产量原始时间戳核对",
        ],
    )


def _complete_shifts(values: ShiftNumericValues) -> bool:
    return all(
        value is not None
        for value in (
            values.zero_shift,
            values.eight_shift,
            values.four_shift,
        )
    )


def _production_change_event(
    imported: FiveQuantityImportResult,
    days: Sequence[OperationalDayAssessment],
    parameters: OperationalFiveQuantityParameters,
) -> OperationalReviewEvent | None:
    all_eligible = [
        day
        for day in days
        if day.is_closed
        and day.operational_state is OperationalState.PRODUCTION
        and day.production is not None
    ]
    groups: list[list[OperationalDayAssessment]] = []
    for day in all_eligible:
        if groups and day.date == groups[-1][-1].date + timedelta(days=1):
            groups[-1].append(day)
        else:
            groups.append([day])
    eligible = max(groups, key=lambda group: len(group), default=[])
    if len(eligible) < 14:
        return None
    values = [float(day.production) for day in eligible]
    overall_mean = fmean(values)
    total_sse = math.fsum((value - overall_mean) ** 2 for value in values)
    if total_sse <= 1e-12:
        return None
    minimum_segment = max(5, len(values) // 4)
    candidates: list[tuple[float, float, int, float, float]] = []
    for split in range(minimum_segment, len(values) - minimum_segment + 1):
        left = values[:split]
        right = values[split:]
        left_mean, right_mean = fmean(left), fmean(right)
        within = math.fsum((value - left_mean) ** 2 for value in left)
        within += math.fsum((value - right_mean) ** 2 for value in right)
        explained = max(0.0, 1.0 - within / total_sse)
        candidates.append(
            (within, explained, split, left_mean, right_mean)
        )
    if not candidates:
        return None
    step_sse, explained, split, left_mean, right_mean = min(
        candidates,
        key=lambda item: (item[0], item[2]),
    )
    relative_shift = (
        (right_mean - left_mean) / max(abs(left_mean), 1e-9)
    )
    linear_sse = _linear_trend_sse(values)
    step_bic = _bic(
        step_sse,
        observation_count=len(values),
        parameter_count=3,
        reference_sse=total_sse,
    )
    linear_bic = _bic(
        linear_sse,
        observation_count=len(values),
        parameter_count=2,
        reference_sse=total_sse,
    )
    if (
        explained
        < parameters.production_change_minimum_explained_fraction
        or abs(relative_shift)
        < parameters.production_change_minimum_relative_shift
        or step_bic + parameters.production_change_bic_margin >= linear_bic
    ):
        return None
    start = eligible[split].date
    end = eligible[-1].date
    direction = "下降" if relative_shift < 0.0 else "上升"
    return _event(
        imported,
        code=f"retrospective_production_level_{direction}",
        category=EventCategory.OPERATING_STATE,
        attention=AttentionLevel.OBSERVE,
        title=f"{start.isoformat()} 起产量水平{direction}候选",
        summary=(
            f"回顾性两段拟合显示前段日均 {_number_text(left_mean)}、后段日均"
            f" {_number_text(right_mean)}，变化 {relative_shift:.2%}；"
            f"该切分解释月内波动的 {explained:.1%}，且阶跃模型 BIC"
            f" {_number_text(step_bic)} 优于线性趋势"
            f" {_number_text(linear_bic)}。"
        ),
        start=start,
        end=end,
        metrics=["production"],
        basis=[EventBasis.RETROSPECTIVE_CHANGE_POINT],
        confidence="medium",
        facts=[
            OperationalEventFact(
                date=start,
                metric="production",
                observed=right_mean,
                expected=left_mean,
                difference=right_mean - left_mean,
                description=(
                    "当前月连续稳产候选段中最优的单变点两段均值比较；"
                    "仅在线性趋势模型不能更简洁解释数据时保留。"
                ),
            )
        ],
        candidate_explanations=[
            "工作面、设备、煤层条件或排产发生变化",
            "统计口径或班次归集发生变化",
            "短样本随机波动",
        ],
        recommended_checks=[
            "结合运行日志核对候选日期附近的工况变化",
            "用下一统计期数据确认是否持续，不据单月切分定性",
        ],
    )


def _linear_trend_sse(values: Sequence[float]) -> float:
    count = len(values)
    if count < 2:
        return 0.0
    x_mean = (count - 1) / 2.0
    y_mean = fmean(values)
    denominator = math.fsum(
        (index - x_mean) ** 2 for index in range(count)
    )
    if denominator <= 0.0:
        return math.fsum((value - y_mean) ** 2 for value in values)
    slope = math.fsum(
        (index - x_mean) * (value - y_mean)
        for index, value in enumerate(values)
    ) / denominator
    intercept = y_mean - slope * x_mean
    return math.fsum(
        (value - (intercept + slope * index)) ** 2
        for index, value in enumerate(values)
    )


def _bic(
    sse: float,
    *,
    observation_count: int,
    parameter_count: int,
    reference_sse: float,
) -> float:
    # The deterministic floor prevents log(0) while preserving ordering for a
    # perfect linear trend or perfect step.  It scales with the observed month
    # so unit changes do not alter the model comparison.
    floor = max(reference_sse, 1.0) * 1e-12
    variance = max(sse, floor) / observation_count
    return (
        observation_count * math.log(variance)
        + parameter_count * math.log(observation_count)
    )


def _coverage(
    imported: FiveQuantityImportResult,
    days: Sequence[OperationalDayAssessment],
) -> OperationalCoverage:
    closed = [day for day in days if day.is_closed]
    core_complete = [day for day in closed if day.core_daily_complete]
    all_required_complete = [
        day for day in closed if day.all_required_fields_complete
    ]
    all_reconciled = [
        day for day in closed if day.all_shift_totals_reconciled
    ]
    missing_calendar_dates = {
        finding.date
        for finding in imported.quality.findings
        if finding.code == "MISSING_CALENDAR_DATE"
        and finding.date is not None
    }
    missing_calendar_day_count = len(missing_calendar_dates)
    return OperationalCoverage(
        period_start=days[0].date,
        period_end=days[-1].date,
        closed_through=imported.closed_through,
        row_count=len(days),
        closed_day_count=len(closed),
        expected_closed_calendar_day_count=(
            len(closed) + missing_calendar_day_count
        ),
        missing_closed_calendar_day_count=missing_calendar_day_count,
        core_daily_complete_closed_day_count=len(core_complete),
        core_daily_incomplete_closed_day_count=(
            len(closed) - len(core_complete)
        ),
        all_required_fields_complete_closed_day_count=len(
            all_required_complete
        ),
        all_required_fields_incomplete_closed_day_count=(
            len(closed) - len(all_required_complete)
        ),
        all_shift_totals_reconciled_closed_day_count=len(all_reconciled),
        shift_totals_not_fully_reconciled_closed_day_count=(
            len(closed) - len(all_reconciled)
        ),
        complete_closed_day_count=len(core_complete),
        incomplete_closed_day_count=len(closed) - len(core_complete),
        open_day_count=sum(not day.is_closed for day in days),
    )


def _kpis(
    imported: FiveQuantityImportResult,
    days: Sequence[OperationalDayAssessment],
) -> list[OperationalKpi]:
    closed = [day for day in days if day.is_closed]
    units = imported.units

    def total_kpi(
        code: str,
        label: str,
        metric: Literal["labor", "electricity", "production"],
        unit: str | None,
    ) -> OperationalKpi:
        assessments = [_day_reconciliation(day, metric) for day in closed]
        matched = [
            item
            for item in assessments
            if item.status is ReconciliationStatus.MATCH
            and item.reported_daily_total is not None
        ]
        mismatch_count = sum(
            item.status is ReconciliationStatus.MISMATCH
            for item in assessments
        )
        incomplete_count = sum(
            item.status is ReconciliationStatus.INCOMPLETE
            for item in assessments
        )
        return OperationalKpi(
            code=code,
            label=label,
            value=(
                math.fsum(
                    float(item.reported_daily_total) for item in matched
                )
                if matched
                else None
            ),
            unit=unit,
            contributing_day_count=len(matched),
            expected_day_count=len(closed),
            excluded_mismatch_day_count=mismatch_count,
            excluded_incomplete_reconciliation_day_count=incomplete_count,
            is_partial=len(matched) != len(closed),
            value_basis="reconciled_daily_totals_only",
            note=(
                "仅汇总日报与三班重算一致的闭账日；对账不一致和无法"
                "对账的日期均不直接进入该无争议口径，且不把缺失补零。"
            ),
        )

    expected_production_days = [
        day
        for day in closed
        if day.production is not None and day.production > 0.0
    ]
    matched_electricity = [
        day
        for day in expected_production_days
        if _day_reconciliation(day, "production").status
        is ReconciliationStatus.MATCH
        and _day_reconciliation(day, "electricity").status
        is ReconciliationStatus.MATCH
    ]
    matched_labor = [
        day
        for day in expected_production_days
        if _day_reconciliation(day, "production").status
        is ReconciliationStatus.MATCH
        and _day_reconciliation(day, "labor").status
        is ReconciliationStatus.MATCH
        and day.labor > 0.0
    ]
    electricity_exclusions = _pair_reconciliation_exclusions(
        expected_production_days,
        ("production", "electricity"),
    )
    labor_exclusions = _pair_reconciliation_exclusions(
        expected_production_days,
        ("production", "labor"),
    )
    non_production_electricity = [
        day.electricity
        for day in closed
        if day.operational_state
        is OperationalState.NON_PRODUCTION_CANDIDATE
        and day.electricity is not None
        and _day_reconciliation(day, "electricity").status
        is ReconciliationStatus.MATCH
    ]
    expected_non_production = [
        day
        for day in closed
        if day.operational_state
        is OperationalState.NON_PRODUCTION_CANDIDATE
    ]
    non_production_exclusions = _pair_reconciliation_exclusions(
        expected_non_production,
        ("electricity",),
    )
    aggregate_electricity_ratio = (
        math.fsum(float(day.electricity) for day in matched_electricity)
        / math.fsum(float(day.production) for day in matched_electricity)
        if matched_electricity
        else None
    )
    aggregate_labor_ratio = (
        math.fsum(float(day.production) for day in matched_labor)
        / math.fsum(float(day.labor) for day in matched_labor)
        if matched_labor
        else None
    )
    return [
        total_kpi(
            "production_total",
            "已对账闭账日产量合计",
            "production",
            units.production,
        ),
        total_kpi(
            "electricity_total",
            "已对账闭账日总电量合计",
            "electricity",
            units.electricity,
        ),
        total_kpi(
            "labor_total",
            "已对账闭账日用工合计",
            "labor",
            units.labor,
        ),
        OperationalKpi(
            code="aggregate_total_electricity_to_production_ratio",
            label="已对账生产日总电量/产量比",
            value=aggregate_electricity_ratio,
            unit=_ratio_unit(units.electricity, units.production),
            contributing_day_count=len(matched_electricity),
            expected_day_count=len(expected_production_days),
            excluded_mismatch_day_count=electricity_exclusions[0],
            excluded_incomplete_reconciliation_day_count=(
                electricity_exclusions[1]
            ),
            is_partial=(
                len(matched_electricity) != len(expected_production_days)
            ),
            value_basis="derived_from_reconciled_daily_totals_only",
            note=(
                "包含未知干扰负荷，不是生产分区吨煤电耗；只按电量和产量"
                "日报均通过三班对账的生产日计算。"
            ),
        ),
        OperationalKpi(
            code="aggregate_production_to_labor_ratio",
            label="已对账生产日产量/用工比",
            value=aggregate_labor_ratio,
            unit=_ratio_unit(units.production, units.labor),
            contributing_day_count=len(matched_labor),
            expected_day_count=len(expected_production_days),
            excluded_mismatch_day_count=labor_exclusions[0],
            excluded_incomplete_reconciliation_day_count=(
                labor_exclusions[1]
            ),
            is_partial=len(matched_labor) != len(expected_production_days),
            value_basis="derived_from_reconciled_daily_totals_only",
            note="只按产量、用工日报均通过三班对账且用工大于零的生产日计算。",
        ),
        OperationalKpi(
            code="non_production_candidate_electricity_mean",
            label="零产候选期日均总电量",
            value=(
                fmean(non_production_electricity)
                if non_production_electricity
                else None
            ),
            unit=units.electricity,
            contributing_day_count=len(non_production_electricity),
            expected_day_count=sum(
                day.operational_state
                is OperationalState.NON_PRODUCTION_CANDIDATE
                for day in closed
            ),
            excluded_mismatch_day_count=non_production_exclusions[0],
            excluded_incomplete_reconciliation_day_count=(
                non_production_exclusions[1]
            ),
            is_partial=(
                len(non_production_electricity)
                != len(expected_non_production)
            ),
            value_basis="reconciled_state_subset",
            note=(
                "仅使用总电量日报通过三班对账的零产候选日描述固定"
                "基荷线索；是否停产仍需业务记录确认。"
            ),
        ),
    ]


def _day_reconciliation(
    day: OperationalDayAssessment,
    metric: str,
) -> OperationalMetricReconciliation:
    return next(
        item for item in day.metric_reconciliations if item.metric == metric
    )


def _pair_reconciliation_exclusions(
    days: Sequence[OperationalDayAssessment],
    metrics: Sequence[str],
) -> tuple[int, int]:
    mismatch = 0
    incomplete = 0
    for day in days:
        statuses = [
            _day_reconciliation(day, metric).status for metric in metrics
        ]
        if ReconciliationStatus.MISMATCH in statuses:
            mismatch += 1
        elif ReconciliationStatus.INCOMPLETE in statuses:
            incomplete += 1
    return mismatch, incomplete


def _reconciliation_summaries(
    days: Sequence[OperationalDayAssessment],
) -> list[OperationalMetricReconciliationSummary]:
    closed = [day for day in days if day.is_closed]
    summaries: list[OperationalMetricReconciliationSummary] = []
    for metric in (
        "labor",
        "electricity",
        "detonators",
        "explosives",
        "production",
    ):
        assessments = [_day_reconciliation(day, metric) for day in closed]
        reported = [
            float(item.reported_daily_total)
            for item in assessments
            if item.reported_daily_total is not None
        ]
        recomputed = [
            float(item.recomputed_shift_total)
            for item in assessments
            if item.recomputed_shift_total is not None
        ]
        matched = [
            float(item.reported_daily_total)
            for item in assessments
            if item.status is ReconciliationStatus.MATCH
            and item.reported_daily_total is not None
        ]
        summaries.append(
            OperationalMetricReconciliationSummary(
                metric=metric,
                reported_daily_total=(
                    math.fsum(reported) if reported else None
                ),
                recomputed_shift_total=(
                    math.fsum(recomputed) if recomputed else None
                ),
                reconciled_daily_total=(
                    math.fsum(matched) if matched else None
                ),
                reported_day_count=len(reported),
                recomputed_shift_day_count=len(recomputed),
                matched_day_count=sum(
                    item.status is ReconciliationStatus.MATCH
                    for item in assessments
                ),
                mismatch_day_count=sum(
                    item.status is ReconciliationStatus.MISMATCH
                    for item in assessments
                ),
                incomplete_day_count=sum(
                    item.status is ReconciliationStatus.INCOMPLETE
                    for item in assessments
                ),
                note=(
                    "日报累计、三班重算累计和仅对账一致日累计并列展示；"
                    "三者覆盖日数可能不同，不得互相冒充。"
                ),
            )
        )
    return summaries


def _overall(
    events: Sequence[OperationalReviewEvent],
    coverage: OperationalCoverage,
    quality: FiveQuantityQualitySummary,
) -> OperationalOverall:
    counts = Counter(event.attention_level for event in events)
    priority = counts[AttentionLevel.PRIORITY_CHECK]
    checks = counts[AttentionLevel.CHECK]
    observations = (
        counts[AttentionLevel.OBSERVE] + counts[AttentionLevel.INFORMATION]
    )
    if coverage.closed_day_count == 0:
        status = OverallStatus.INSUFFICIENT_DATA
        title = "没有可分析的闭账日"
    elif priority:
        status = OverallStatus.NEEDS_PRIORITY_REVIEW
        title = f"发现 {priority} 项优先核查事件"
    elif quality.error_count or coverage.incomplete_closed_day_count:
        status = OverallStatus.NEEDS_DATA
        title = "数据不完整，需先补数或核对口径"
    elif checks or observations:
        status = OverallStatus.OBSERVATION_ONLY
        title = "形成辅助观察线索"
    else:
        status = OverallStatus.NO_UNEXPLAINED_LEAD
        title = "当前文件未形成未解释技术线索"
    summary = (
        f"共形成 {len(events)} 个合并事件：优先核查 {priority} 个、"
        f"一般核查 {checks} 个、观察提示 {observations} 个。"
        "结果不等于安全、合规或违法认定。"
    )
    return OperationalOverall(
        status=status,
        title=title,
        summary=summary,
        priority_event_count=priority,
        check_event_count=checks,
        observation_event_count=observations,
    )


def _attach_event_ids(
    days: Sequence[OperationalDayAssessment],
    events: Sequence[OperationalReviewEvent],
) -> list[OperationalDayAssessment]:
    result: list[OperationalDayAssessment] = []
    for day in days:
        matching = [
            event.event_id
            for event in events
            if event.period_start <= day.date <= event.period_end
        ]
        result.append(day.model_copy(update={"event_ids": matching}))
    return result


def _deduplicate_and_sort_events(
    events: Sequence[OperationalReviewEvent],
) -> list[OperationalReviewEvent]:
    unique = {event.event_id: event for event in events}
    rank = {
        AttentionLevel.PRIORITY_CHECK: 0,
        AttentionLevel.CHECK: 1,
        AttentionLevel.OBSERVE: 2,
        AttentionLevel.INFORMATION: 3,
    }
    return sorted(
        unique.values(),
        key=lambda event: (
            rank[event.attention_level],
            event.period_start,
            event.event_code,
        ),
    )


def _bind_configuration_to_event_ids(
    events: Sequence[OperationalReviewEvent],
    configuration_sha256: str,
) -> list[OperationalReviewEvent]:
    """Bind stable review-event identifiers to the effective configuration."""

    return [
        event.model_copy(
            update={
                "event_id": "ofq-"
                + hashlib.sha256(
                    (
                        f"{configuration_sha256}|{event.event_id}"
                    ).encode("utf-8")
                ).hexdigest()[:24]
            }
        )
        for event in events
    ]


def _event(
    imported: FiveQuantityImportResult,
    *,
    code: str,
    category: EventCategory,
    attention: AttentionLevel,
    title: str,
    summary: str,
    start: date,
    end: date,
    metrics: list[str],
    basis: list[EventBasis],
    confidence: Literal["high", "medium", "context_required"],
    facts: list[OperationalEventFact],
    candidate_explanations: list[str],
    recommended_checks: list[str],
    merged_point_count: int | None = None,
) -> OperationalReviewEvent:
    event_key = "|".join(
        (
            imported.source_sha256,
            imported.mine_id,
            code,
            start.isoformat(),
            end.isoformat(),
            ",".join(sorted(metrics)),
        )
    )
    event_id = "ofq-" + hashlib.sha256(event_key.encode("utf-8")).hexdigest()[
        :24
    ]
    return OperationalReviewEvent(
        event_id=event_id,
        event_code=code,
        category=category,
        attention_level=attention,
        title=title,
        summary=summary,
        period_start=start,
        period_end=end,
        metrics=sorted(set(metrics)),
        basis=basis,
        confidence=confidence,
        merged_point_count=(
            merged_point_count
            if merged_point_count is not None
            else max(1, (end - start).days + 1)
        ),
        facts=facts,
        candidate_explanations=candidate_explanations,
        recommended_checks=recommended_checks,
    )


def _metric_label(metric: str) -> str:
    return {
        "ventilation": "风量",
        "labor": "用工量",
        "electricity": "用电量",
        "detonators": "雷管量",
        "explosives": "炸药量",
        "production": "产量",
    }.get(metric, metric)


def _context_metric(code: str) -> str:
    return {
        "DOCUMENT_TITLE_PLACEHOLDER": "document_identity",
        "EXPLOSIVES_ALL_ZERO_WITH_PRODUCTION": "explosives",
        "WIND_STEP_PATTERN": "ventilation",
        "UNDECLARED_UNITS": "units",
    }.get(code, "data_quality")


def _number_text(value: float | int | str | None) -> str:
    if value is None:
        return "缺失"
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    return str(value)


def _ratio_unit(
    numerator: str | None,
    denominator: str | None,
) -> str | None:
    if numerator is None or denominator is None:
        return None
    return f"{numerator}/{denominator}"


__all__ = [
    "AnalysisValueBasis",
    "AttentionLevel",
    "EventBasis",
    "EventCategory",
    "OPERATIONAL_FIVE_QUANTITY_METHOD_VERSION",
    "OperationalCoverage",
    "OperationalDayAssessment",
    "OperationalFiveQuantityFileRequest",
    "OperationalFiveQuantityParameters",
    "OperationalFiveQuantityResult",
    "OperationalKpi",
    "OperationalMetricReconciliation",
    "OperationalMetricReconciliationSummary",
    "OperationalOverall",
    "OperationalRegimeSegment",
    "OperationalReviewEvent",
    "OperationalState",
    "OverallStatus",
    "RecordCompleteness",
    "analyze_operational_five_quantity",
    "analyze_operational_five_quantity_file",
]
