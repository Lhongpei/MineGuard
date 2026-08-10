"""Pure ten-quantity V3 analysis core.

This module intentionally has no HTTP, storage, exchange-contract or UI
dependency.  It implements the first governed algorithm boundary for eleven
atomic measurements representing ten business quantities:

* deterministic daily/shift aggregation;
* module-specific coverage instead of one all-or-nothing completeness bit;
* evidence-gated raw-coal and washing balances;
* shipment/sales/invoice cohort reconciliation with invoice lag;
* an elastic window-level flow LP used only for minimum-repair diagnostics;
* past-only robust historical bands whose signals can never create P1.

Sales, transport and invoicing are different credentials for a shipment.  They
are never compiled as three physical outflows in the material-flow equation.
Likewise, extraction is an upstream observation and is not silently equated to
the governed production boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
import hashlib
import json
import math
from statistics import fmean, median
from typing import Annotated, Any, Literal, Mapping, Sequence

from pydantic import Field, model_validator

from .models import StrictModel

try:  # Keep dependency failure explicit at the algorithm boundary.
    from scipy import __version__ as SCIPY_VERSION
    from scipy.optimize import linprog as _linprog
except (ImportError, OSError):  # pragma: no cover - exercised by monkeypatch
    SCIPY_VERSION = "unavailable"
    _linprog = None


REGULATORY_V3_METHOD_VERSION = "regulatory-ten-quantity-v3.1.0"
FLOW_NETWORK_VERSION = "ten-quantity-window-flow-l1-v1"
HISTORICAL_RULE_VERSION = "ten-quantity-past-only-median-mad-v1"

METRICS: tuple[str, ...] = (
    "ventilation_m3_min",
    "electricity_kwh",
    "detonators_count",
    "explosives_kg",
    "mine_entry_persons",
    "production_t",
    "extraction_t",
    "sales_t",
    "transport_t",
    "wash_feed_t",
    "invoiced_quantity_t",
)
TEN_QUANTITY_GROUPS: dict[str, tuple[str, ...]] = {
    "airflow": ("ventilation_m3_min",),
    "electricity": ("electricity_kwh",),
    "blasting_materials": ("detonators_count", "explosives_kg"),
    "mine_entry_personnel": ("mine_entry_persons",),
    "production": ("production_t",),
    "extraction": ("extraction_t",),
    "sales": ("sales_t",),
    "transport": ("transport_t",),
    "coal_washing": ("wash_feed_t",),
    "invoicing": ("invoiced_quantity_t",),
}
COUNT_METRICS = frozenset({"detonators_count", "mine_entry_persons"})
NON_NEGATIVE_METRICS = frozenset(METRICS)
ADDITIVE_METRICS = frozenset(METRICS) - {"ventilation_m3_min"}
SHIFT_OPTIONAL_METRICS = frozenset(
    {"sales_t", "transport_t", "wash_feed_t", "invoiced_quantity_t"}
)
METRIC_UNITS: dict[str, str] = {
    "ventilation_m3_min": "m3/min",
    "electricity_kwh": "kWh",
    "detonators_count": "count",
    "explosives_kg": "kg",
    "mine_entry_persons": "person",
    "production_t": "t",
    "extraction_t": "t",
    "sales_t": "t",
    "transport_t": "t",
    "wash_feed_t": "t",
    "invoiced_quantity_t": "t",
}


class DecisionStatus(StrEnum):
    NORMAL_CANDIDATE = "normal_candidate"
    RISK = "risk"
    INSUFFICIENT_DATA = "insufficient_data"


class ReviewPriority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    DATA = "DATA"
    NONE = "NONE"


class SignalSeverity(StrEnum):
    INFORMATION = "information"
    REVIEW = "review"
    RISK = "risk"


class EvidenceTier(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"


class EvidenceLayer(StrEnum):
    DETERMINISTIC = "deterministic"
    PHYSICAL = "physical"
    CREDENTIAL = "credential"
    HISTORICAL = "historical"


class ModuleStatus(StrEnum):
    EVALUATED = "evaluated"
    INSUFFICIENT = "insufficient"
    SKIPPED = "skipped"


class CheckStatus(StrEnum):
    CONSISTENT = "consistent"
    CONFLICT = "conflict"
    INSUFFICIENT = "insufficient"
    SKIPPED = "skipped"


class SolverStatus(StrEnum):
    OPTIMAL = "optimal"
    FAILED = "failed"
    INSUFFICIENT = "insufficient"
    SKIPPED = "skipped"


class ShiftValues(StrictModel):
    zero_shift: float | None = None
    eight_shift: float | None = None
    four_shift: float | None = None

    @property
    def provided_count(self) -> int:
        return sum(
            value is not None
            for value in (self.zero_shift, self.eight_shift, self.four_shift)
        )

    @property
    def complete(self) -> bool:
        return self.provided_count == 3

    @property
    def values(self) -> tuple[float, float, float] | None:
        if not self.complete:
            return None
        assert self.zero_shift is not None
        assert self.eight_shift is not None
        assert self.four_shift is not None
        return (
            float(self.zero_shift),
            float(self.eight_shift),
            float(self.four_shift),
        )


class ShiftDurations(StrictModel):
    zero_shift: Annotated[float, Field(gt=0.0, le=1_440.0)] = 480.0
    eight_shift: Annotated[float, Field(gt=0.0, le=1_440.0)] = 480.0
    four_shift: Annotated[float, Field(gt=0.0, le=1_440.0)] = 480.0

    @property
    def values(self) -> tuple[float, float, float]:
        return self.zero_shift, self.eight_shift, self.four_shift


class ReportedQuantity(StrictModel):
    daily_total: float | None = None
    daily_aggregation: Literal[
        "time_weighted_average", "sum", "snapshot"
    ] | None = None
    shifts: ShiftValues | None = None


class TenQuantityDay(StrictModel):
    date: date
    ventilation_m3_min: ReportedQuantity
    electricity_kwh: ReportedQuantity
    detonators_count: ReportedQuantity
    explosives_kg: ReportedQuantity
    mine_entry_persons: ReportedQuantity
    production_t: ReportedQuantity
    extraction_t: ReportedQuantity
    sales_t: ReportedQuantity
    transport_t: ReportedQuantity
    wash_feed_t: ReportedQuantity
    invoiced_quantity_t: ReportedQuantity
    shift_durations: ShiftDurations = Field(default_factory=ShiftDurations)

    @model_validator(mode="after")
    def validate_measurements(self) -> "TenQuantityDay":
        for metric, quantity in self.quantities().items():
            expected = (
                {"time_weighted_average", "snapshot"}
                if metric == "ventilation_m3_min"
                else {"sum"}
            )
            if (
                quantity.daily_aggregation is not None
                and quantity.daily_aggregation not in expected
            ):
                raise ValueError(f"{metric} aggregation is not permitted")
            values: list[float | None] = [quantity.daily_total]
            if quantity.shifts is not None:
                values.extend(
                    (
                        quantity.shifts.zero_shift,
                        quantity.shifts.eight_shift,
                        quantity.shifts.four_shift,
                    )
                )
            for value in values:
                if value is None:
                    continue
                numeric = float(value)
                if metric in NON_NEGATIVE_METRICS and numeric < 0.0:
                    raise ValueError(f"{metric} cannot be negative")
                if metric in COUNT_METRICS and not numeric.is_integer():
                    raise ValueError(f"{metric} must be integral")
        return self

    def quantities(self) -> dict[str, ReportedQuantity]:
        return {metric: getattr(self, metric) for metric in METRICS}


class EvidenceProfile(StrictModel):
    source_refs: Annotated[list[str], Field(min_length=1, max_length=64)]
    dependency_domains: Annotated[list[str], Field(min_length=1, max_length=64)]

    @model_validator(mode="after")
    def validate_unique_values(self) -> "EvidenceProfile":
        if len(self.source_refs) != len(set(self.source_refs)):
            raise ValueError("source_refs must be unique")
        if len(self.dependency_domains) != len(set(self.dependency_domains)):
            raise ValueError("dependency_domains must be unique")
        return self

    @property
    def independent(self) -> bool:
        return len(self.source_refs) >= 2 and len(self.dependency_domains) >= 2


class RawCoalBalanceSupport(StrictModel):
    opening_inventory_t: Annotated[float, Field(ge=0.0)]
    closing_inventory_t: Annotated[float, Field(ge=0.0)]
    raw_direct_outbound_t: Annotated[float, Field(ge=0.0)]
    purchases_t: Annotated[float, Field(ge=0.0)] = 0.0
    other_in_t: Annotated[float, Field(ge=0.0)] = 0.0
    other_out_t: Annotated[float, Field(ge=0.0)] = 0.0
    approved_loss_t: Annotated[float, Field(ge=0.0)] = 0.0
    evidence: EvidenceProfile


class WashBalanceSupport(StrictModel):
    opening_wip_t: Annotated[float, Field(ge=0.0)] = 0.0
    closing_wip_t: Annotated[float, Field(ge=0.0)] = 0.0
    washed_product_output_t: Annotated[float, Field(ge=0.0)]
    rejects_t: Annotated[float, Field(ge=0.0)]
    process_loss_t: Annotated[float, Field(ge=0.0)] = 0.0
    evidence: EvidenceProfile


class CredentialCohort(StrictModel):
    cohort_id: Annotated[str, Field(min_length=1, max_length=128)]
    sales_date: date
    sales_t: Annotated[float, Field(ge=0.0)]
    transport_date: date
    transport_t: Annotated[float, Field(ge=0.0)]
    invoiced_at: date | None = None
    # The governed quantity is normal/blue-invoice physical tonnage.  Red
    # invoices and returns are separate support events, never negative values
    # smuggled into this field.
    invoiced_quantity_t: Annotated[float | None, Field(ge=0.0)] = None
    settlement_closed: bool = False
    sales_source_ref: Annotated[str, Field(min_length=1, max_length=256)]
    transport_source_ref: Annotated[str, Field(min_length=1, max_length=256)]
    invoice_source_ref: Annotated[str | None, Field(max_length=256)] = None
    sales_dependency_domain: Annotated[str, Field(min_length=1, max_length=128)]
    transport_dependency_domain: Annotated[str, Field(min_length=1, max_length=128)]
    invoice_dependency_domain: Annotated[str | None, Field(max_length=128)] = None

    @model_validator(mode="after")
    def validate_invoice_pair(self) -> "CredentialCohort":
        if (self.invoiced_at is None) != (self.invoiced_quantity_t is None):
            raise ValueError("invoice date and quantity must be supplied together")
        if self.invoiced_at is not None and self.invoice_source_ref is None:
            raise ValueError("invoice_source_ref is required for an invoice")
        if self.invoiced_at is not None and self.invoice_dependency_domain is None:
            raise ValueError("invoice_dependency_domain is required for an invoice")
        return self


class CredentialSupport(StrictModel):
    cohorts: Annotated[list[CredentialCohort], Field(min_length=1, max_length=100_000)]
    sales_register_complete: bool
    transport_register_complete: bool
    invoice_register_complete: bool

    @model_validator(mode="after")
    def validate_unique_cohorts(self) -> "CredentialSupport":
        identifiers = [item.cohort_id for item in self.cohorts]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("credential cohort identifiers must be unique")
        return self


class ModuleApplicability(StrictModel):
    raw_coal_balance: bool = True
    wash_balance: bool = True
    credential_chain: bool = True


class TenQuantitySubmission(StrictModel):
    contract_version: Literal["enterprise-ten-quantity-submission-v3"] = (
        "enterprise-ten-quantity-submission-v3"
    )
    submission_id: Annotated[str, Field(min_length=8, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    period_start: date
    period_end: date
    coverage_as_of: date | None = None
    operating_regime: Annotated[str, Field(min_length=1, max_length=64)] = "normal"
    days: Annotated[list[TenQuantityDay], Field(min_length=1, max_length=366)]
    applicability: ModuleApplicability = Field(default_factory=ModuleApplicability)
    raw_coal_support: RawCoalBalanceSupport | None = None
    wash_support: WashBalanceSupport | None = None
    credential_support: CredentialSupport | None = None

    @model_validator(mode="after")
    def validate_window(self) -> "TenQuantitySubmission":
        if self.period_end < self.period_start:
            raise ValueError("period_end cannot predate period_start")
        if (self.period_end - self.period_start).days >= 366:
            raise ValueError("analysis window cannot exceed 366 days")
        dates = [item.date for item in self.days]
        if len(dates) != len(set(dates)):
            raise ValueError("daily dates must be unique")
        if any(item < self.period_start or item > self.period_end for item in dates):
            raise ValueError("daily date is outside the analysis window")
        as_of = self.coverage_as_of or self.period_end
        if as_of < self.period_end:
            raise ValueError("coverage_as_of cannot predate period_end")
        if self.credential_support is not None:
            for cohort in self.credential_support.cohorts:
                if not self.period_start <= cohort.sales_date <= self.period_end:
                    raise ValueError("credential sale date must be in the window")
                if cohort.transport_date > as_of:
                    raise ValueError("transport date cannot exceed coverage_as_of")
                if cohort.invoiced_at is not None and cohort.invoiced_at > as_of:
                    raise ValueError("invoice date cannot exceed coverage_as_of")
        return self

    @property
    def effective_coverage_as_of(self) -> date:
        return self.coverage_as_of or self.period_end


class TenQuantityTotals(StrictModel):
    ventilation_m3_min: float | None = None
    electricity_kwh: float | None = None
    detonators_count: float | None = None
    explosives_kg: float | None = None
    mine_entry_persons: float | None = None
    production_t: float | None = None
    extraction_t: float | None = None
    sales_t: float | None = None
    transport_t: float | None = None
    wash_feed_t: float | None = None
    invoiced_quantity_t: float | None = None


class HistoricalReferenceWindow(StrictModel):
    reference_id: Annotated[str, Field(min_length=1, max_length=128)]
    period_end: date
    available_at: date
    operating_regime: Annotated[str, Field(min_length=1, max_length=64)]
    baseline_eligible: bool = True
    totals: TenQuantityTotals


class TenQuantityParameters(StrictModel):
    shift_absolute_tolerance: Annotated[float, Field(ge=0.0)] = 1e-6
    shift_relative_tolerance: Annotated[float, Field(ge=0.0, le=0.5)] = 0.02
    mass_absolute_tolerance_t: Annotated[float, Field(ge=0.0)] = 1.0
    mass_relative_tolerance: Annotated[float, Field(ge=0.0, le=0.5)] = 0.02
    credential_absolute_tolerance_t: Annotated[float, Field(ge=0.0)] = 0.1
    credential_relative_tolerance: Annotated[float, Field(ge=0.0, le=0.5)] = 0.01
    maximum_invoice_lag_days: Annotated[int, Field(ge=0, le=730)] = 90
    flow_slack_penalty: Annotated[float, Field(gt=0.0, le=1e9)] = 100.0
    minimum_history_windows: Annotated[int, Field(ge=3, le=365)] = 7
    historical_robust_z: Annotated[float, Field(gt=1.0, le=10.0)] = 3.5
    historical_minimum_relative_half_width: Annotated[
        float, Field(gt=0.0, le=1.0)
    ] = 0.15


class AnalysisSignal(StrictModel):
    code: str
    layer: EvidenceLayer
    severity: SignalSeverity
    priority: ReviewPriority
    evidence_tier: EvidenceTier
    message: str
    affected_metrics: list[str]
    observed: float | None = None
    expected_lower: float | None = None
    expected_upper: float | None = None
    observed_date: date | None = None
    basis: str


class MetricCoverage(StrictModel):
    metric: str
    expected_day_count: Annotated[int, Field(ge=1)]
    reported_day_count: Annotated[int, Field(ge=0)]
    usable_day_count: Annotated[int, Field(ge=0)]
    ratio: Annotated[float, Field(ge=0.0, le=1.0)]
    shift_reporting_optional: Literal[True] = True


class ModuleAssessment(StrictModel):
    module: str
    status: ModuleStatus
    coverage_ratio: Annotated[float, Field(ge=0.0, le=1.0)]
    reasons: list[str] = Field(default_factory=list)


class BalanceCheck(StrictModel):
    code: str
    status: CheckStatus
    residual: float | None
    tolerance: float | None
    affected_metrics: list[str]
    message: str


class CredentialSummary(StrictModel):
    cohort_count: Annotated[int, Field(ge=0)]
    closed_settlement_count: Annotated[int, Field(ge=0)]
    pending_invoice_count: Annotated[int, Field(ge=0)]
    overdue_invoice_count: Annotated[int, Field(ge=0)]
    cumulative_sales_t: float
    cumulative_transport_t: float
    cumulative_closed_sales_t: float
    cumulative_closed_invoiced_quantity_t: float
    maximum_transport_lag_days: int | None
    maximum_invoice_lag_days: int | None
    checks: list[BalanceCheck]


class L1FlowResult(StrictModel):
    status: SolverStatus
    solver: str
    objective_value: float | None = None
    reconciled_values: dict[str, float] = Field(default_factory=dict)
    signed_adjustments: dict[str, float] = Field(default_factory=dict)
    balance_slacks: dict[str, float] = Field(default_factory=dict)
    message: str | None = None


class HistoricalDiagnostic(StrictModel):
    relationship: str
    numerator_metric: str
    denominator_metric: str
    observed_ratio: float | None
    lower: float | None
    center: float | None
    upper: float | None
    sample_count: Annotated[int, Field(ge=0)]
    status: Literal["within_band", "outside_band", "insufficient"]


class TenQuantityAnalysisResult(StrictModel):
    method_version: str = REGULATORY_V3_METHOD_VERSION
    mine_id: str
    submission_id: str
    decision: DecisionStatus
    review_priority: ReviewPriority
    decision_reasons: list[str]
    totals: TenQuantityTotals
    metric_coverage: list[MetricCoverage]
    modules: list[ModuleAssessment]
    balance_checks: list[BalanceCheck]
    credential_summary: CredentialSummary | None
    reconciliation: L1FlowResult
    historical_diagnostics: list[HistoricalDiagnostic]
    signals: list[AnalysisSignal]
    input_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    configuration_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    runtime_manifest: dict[str, str]


@dataclass(frozen=True)
class _Prepared:
    effective: dict[date, dict[str, float | None]]
    totals: TenQuantityTotals
    metric_coverage: list[MetricCoverage]
    module: ModuleAssessment
    signals: list[AnalysisSignal]


def _shift_aggregate(
    day: TenQuantityDay,
    metric: str,
    quantity: ReportedQuantity,
) -> float | None:
    if quantity.shifts is None or not quantity.shifts.complete:
        return None
    values = quantity.shifts.values
    assert values is not None
    if metric in ADDITIVE_METRICS:
        return math.fsum(values)
    durations = day.shift_durations.values
    total_minutes = math.fsum(durations)
    return math.fsum(
        value * duration
        for value, duration in zip(values, durations, strict=True)
    ) / total_minutes


def effective_reported_value(day: TenQuantityDay, metric: str) -> float | None:
    quantity = getattr(day, metric)
    if quantity.daily_total is not None:
        return float(quantity.daily_total)
    return _shift_aggregate(day, metric, quantity)


def _allowed_difference(
    left: float,
    right: float,
    *,
    absolute: float,
    relative: float,
) -> float:
    return max(absolute, relative * max(abs(left), abs(right), 1.0))


def _prepare_submission(
    submission: TenQuantitySubmission,
    parameters: TenQuantityParameters,
) -> _Prepared:
    effective: dict[date, dict[str, float | None]] = {}
    usable = {metric: 0 for metric in METRICS}
    signals: list[AnalysisSignal] = []
    for day in sorted(submission.days, key=lambda item: item.date):
        values: dict[str, float | None] = {}
        for metric, quantity in day.quantities().items():
            shift_value = _shift_aggregate(day, metric, quantity)
            if (
                quantity.shifts is not None
                and quantity.shifts.provided_count in {1, 2}
                and (
                    metric not in SHIFT_OPTIONAL_METRICS
                    or quantity.daily_total is None
                )
            ):
                signals.append(
                    AnalysisSignal(
                        code="partial_shift_values",
                        layer=EvidenceLayer.DETERMINISTIC,
                        severity=SignalSeverity.REVIEW,
                        priority=ReviewPriority.P2,
                        evidence_tier=EvidenceTier.B,
                        message=(
                            f"{day.date.isoformat()} {metric} 班次值不完整，"
                            "未执行日报—班次确定性核对"
                        ),
                        affected_metrics=[metric],
                        observed_date=day.date,
                        basis="deterministic_shift_completeness",
                    )
                )
            daily = (
                float(quantity.daily_total)
                if quantity.daily_total is not None
                else None
            )
            values[metric] = daily if daily is not None else shift_value
            if values[metric] is not None:
                usable[metric] += 1
            comparable = not (
                metric == "ventilation_m3_min"
                and quantity.daily_aggregation == "snapshot"
            )
            if daily is not None and shift_value is not None and comparable:
                tolerance = _allowed_difference(
                    daily,
                    shift_value,
                    absolute=parameters.shift_absolute_tolerance,
                    relative=parameters.shift_relative_tolerance,
                )
                if abs(daily - shift_value) > tolerance:
                    signals.append(
                        AnalysisSignal(
                            code="daily_shift_arithmetic_mismatch",
                            layer=EvidenceLayer.DETERMINISTIC,
                            severity=SignalSeverity.RISK,
                            priority=ReviewPriority.P2,
                            evidence_tier=EvidenceTier.B,
                            message=(
                                f"{day.date.isoformat()} {metric} 日报值与"
                                "班次聚合不一致"
                            ),
                            affected_metrics=[metric],
                            observed=daily,
                            expected_lower=shift_value - tolerance,
                            expected_upper=shift_value + tolerance,
                            observed_date=day.date,
                            basis="deterministic_daily_shift_aggregation",
                        )
                    )
        effective[day.date] = values

    expected = (submission.period_end - submission.period_start).days + 1
    coverage = [
        MetricCoverage(
            metric=metric,
            expected_day_count=expected,
            reported_day_count=len(submission.days),
            usable_day_count=usable[metric],
            ratio=usable[metric] / expected,
        )
        for metric in METRICS
    ]
    incomplete = [item.metric for item in coverage if item.ratio < 1.0]
    module = ModuleAssessment(
        module="daily_shift_aggregation",
        status=(ModuleStatus.INSUFFICIENT if incomplete else ModuleStatus.EVALUATED),
        coverage_ratio=min(item.ratio for item in coverage),
        reasons=(
            ["缺少完整日报值：" + "、".join(incomplete)] if incomplete else []
        ),
    )

    totals_payload: dict[str, float | None] = {}
    for metric in METRICS:
        metric_values = [
            values[metric]
            for values in effective.values()
            if values[metric] is not None
        ]
        if len(metric_values) != expected:
            totals_payload[metric] = None
        elif metric == "ventilation_m3_min":
            totals_payload[metric] = fmean(float(item) for item in metric_values)
        else:
            totals_payload[metric] = math.fsum(float(item) for item in metric_values)
    return _Prepared(
        effective=effective,
        totals=TenQuantityTotals.model_validate(totals_payload),
        metric_coverage=coverage,
        module=module,
        signals=signals,
    )


def _mass_tolerance(
    values: Sequence[float], parameters: TenQuantityParameters
) -> float:
    return max(
        parameters.mass_absolute_tolerance_t,
        parameters.mass_relative_tolerance
        * max((abs(value) for value in values), default=1.0),
    )


def _check(
    *,
    code: str,
    residual: float,
    tolerance: float,
    metrics: list[str],
    label: str,
) -> BalanceCheck:
    conflict = abs(residual) > tolerance
    return BalanceCheck(
        code=code,
        status=CheckStatus.CONFLICT if conflict else CheckStatus.CONSISTENT,
        residual=residual,
        tolerance=tolerance,
        affected_metrics=metrics,
        message=(
            f"{label}差额 {residual:.3f} t，超出容差 {tolerance:.3f} t"
            if conflict
            else f"{label}落入容差 {tolerance:.3f} t"
        ),
    )


def _not_evaluated_check(
    code: str,
    metrics: list[str],
    message: str,
    *,
    skipped: bool = False,
) -> BalanceCheck:
    return BalanceCheck(
        code=code,
        status=CheckStatus.SKIPPED if skipped else CheckStatus.INSUFFICIENT,
        residual=None,
        tolerance=None,
        affected_metrics=metrics,
        message=message,
    )


def _physical_signal(
    check: BalanceCheck,
    evidence: EvidenceProfile,
) -> AnalysisSignal | None:
    if check.status is not CheckStatus.CONFLICT:
        return None
    independent = evidence.independent
    return AnalysisSignal(
        code=check.code,
        layer=EvidenceLayer.PHYSICAL,
        severity=SignalSeverity.RISK,
        priority=ReviewPriority.P1 if independent else ReviewPriority.P2,
        evidence_tier=EvidenceTier.A if independent else EvidenceTier.B,
        message=check.message,
        affected_metrics=check.affected_metrics,
        observed=check.residual,
        expected_lower=-(check.tolerance or 0.0),
        expected_upper=check.tolerance,
        basis="strict_evidence_gated_material_balance",
    )


def _raw_balance(
    submission: TenQuantitySubmission,
    totals: TenQuantityTotals,
    parameters: TenQuantityParameters,
) -> tuple[ModuleAssessment, BalanceCheck, AnalysisSignal | None]:
    metrics = ["production_t", "wash_feed_t"]
    if not submission.applicability.raw_coal_balance:
        check = _not_evaluated_check(
            "raw_coal_balance", metrics, "本矿受控配置未启用原煤平衡", skipped=True
        )
        return ModuleAssessment(
            module="raw_coal_balance",
            status=ModuleStatus.SKIPPED,
            coverage_ratio=1.0,
            reasons=[check.message],
        ), check, None
    support = submission.raw_coal_support
    if support is None or totals.production_t is None or totals.wash_feed_t is None:
        check = _not_evaluated_check(
            "raw_coal_balance",
            metrics,
            "缺少期初/期末库存、原煤直接出库或完整产量/入洗量，未形成物理冲突",
        )
        return ModuleAssessment(
            module="raw_coal_balance",
            status=ModuleStatus.INSUFFICIENT,
            coverage_ratio=0.0,
            reasons=[check.message],
        ), check, None
    residual = (
        support.opening_inventory_t
        + totals.production_t
        + support.purchases_t
        + support.other_in_t
        - totals.wash_feed_t
        - support.raw_direct_outbound_t
        - support.other_out_t
        - support.approved_loss_t
        - support.closing_inventory_t
    )
    values = (
        support.opening_inventory_t,
        totals.production_t,
        totals.wash_feed_t,
        support.raw_direct_outbound_t,
        support.closing_inventory_t,
    )
    check = _check(
        code="raw_coal_balance",
        residual=residual,
        tolerance=_mass_tolerance(values, parameters),
        metrics=metrics,
        label="原煤收发存平衡",
    )
    return ModuleAssessment(
        module="raw_coal_balance",
        status=ModuleStatus.EVALUATED,
        coverage_ratio=1.0,
    ), check, _physical_signal(check, support.evidence)


def _wash_balance(
    submission: TenQuantitySubmission,
    totals: TenQuantityTotals,
    parameters: TenQuantityParameters,
) -> tuple[ModuleAssessment, BalanceCheck, AnalysisSignal | None]:
    metrics = ["wash_feed_t"]
    if not submission.applicability.wash_balance:
        check = _not_evaluated_check(
            "wash_mass_balance", metrics, "本矿受控配置标记洗选不适用", skipped=True
        )
        return ModuleAssessment(
            module="wash_mass_balance",
            status=ModuleStatus.SKIPPED,
            coverage_ratio=1.0,
            reasons=[check.message],
        ), check, None
    support = submission.wash_support
    if support is None or totals.wash_feed_t is None:
        check = _not_evaluated_check(
            "wash_mass_balance",
            metrics,
            "缺少洗后产品、矸石/煤泥、损耗或在制边界，未形成洗选冲突",
        )
        return ModuleAssessment(
            module="wash_mass_balance",
            status=ModuleStatus.INSUFFICIENT,
            coverage_ratio=0.0,
            reasons=[check.message],
        ), check, None
    residual = (
        support.opening_wip_t
        + totals.wash_feed_t
        - support.washed_product_output_t
        - support.rejects_t
        - support.process_loss_t
        - support.closing_wip_t
    )
    values = (
        totals.wash_feed_t,
        support.washed_product_output_t,
        support.rejects_t,
        support.closing_wip_t,
    )
    check = _check(
        code="wash_mass_balance",
        residual=residual,
        tolerance=_mass_tolerance(values, parameters),
        metrics=metrics,
        label="洗选投入产出平衡",
    )
    return ModuleAssessment(
        module="wash_mass_balance",
        status=ModuleStatus.EVALUATED,
        coverage_ratio=1.0,
    ), check, _physical_signal(check, support.evidence)


def _credential_tolerance(
    left: float, right: float, parameters: TenQuantityParameters
) -> float:
    return _allowed_difference(
        left,
        right,
        absolute=parameters.credential_absolute_tolerance_t,
        relative=parameters.credential_relative_tolerance,
    )


def _credential_analysis(
    submission: TenQuantitySubmission,
    parameters: TenQuantityParameters,
) -> tuple[ModuleAssessment, CredentialSummary | None, list[AnalysisSignal]]:
    if not submission.applicability.credential_chain:
        return ModuleAssessment(
            module="sales_transport_invoice_credentials",
            status=ModuleStatus.SKIPPED,
            coverage_ratio=1.0,
            reasons=["本矿受控配置未启用经营凭证链"],
        ), None, []
    support = submission.credential_support
    complete = bool(
        support is not None
        and support.sales_register_complete
        and support.transport_register_complete
        and support.invoice_register_complete
    )
    if not complete:
        return ModuleAssessment(
            module="sales_transport_invoice_credentials",
            status=ModuleStatus.INSUFFICIENT,
            coverage_ratio=0.0,
            reasons=["销售、运输、开票事件台账未声明完整，未制造凭证冲突"],
        ), None, []
    assert support is not None
    checks: list[BalanceCheck] = []
    signals: list[AnalysisSignal] = []
    closed = 0
    pending = 0
    overdue = 0
    transport_lags: list[int] = []
    invoice_lags: list[int] = []
    sales_total = 0.0
    transport_total = 0.0
    closed_sales = 0.0
    closed_invoices = 0.0
    missing_closed_invoice_count = 0
    evaluable_closed_sales = 0.0

    for cohort in sorted(support.cohorts, key=lambda item: item.cohort_id):
        sales_total += cohort.sales_t
        transport_total += cohort.transport_t
        transport_lags.append((cohort.transport_date - cohort.sales_date).days)
        transport_check = _check(
            code=f"sales_transport_match:{cohort.cohort_id}",
            residual=cohort.sales_t - cohort.transport_t,
            tolerance=_credential_tolerance(
                cohort.sales_t, cohort.transport_t, parameters
            ),
            metrics=["sales_t", "transport_t"],
            label=f"批次 {cohort.cohort_id} 销售—运输凭证",
        )
        checks.append(transport_check)
        if transport_check.status is CheckStatus.CONFLICT:
            independent = (
                cohort.sales_dependency_domain
                != cohort.transport_dependency_domain
            )
            signals.append(
                AnalysisSignal(
                    code="sales_transport_credential_mismatch",
                    layer=EvidenceLayer.CREDENTIAL,
                    severity=SignalSeverity.RISK,
                    # Business-document conflicts remain P2 even when independent.
                    priority=ReviewPriority.P2,
                    evidence_tier=(EvidenceTier.A if independent else EvidenceTier.B),
                    message=transport_check.message,
                    affected_metrics=["sales_t", "transport_t"],
                    observed=transport_check.residual,
                    expected_lower=-(transport_check.tolerance or 0.0),
                    expected_upper=transport_check.tolerance,
                    basis="linked_shipment_credentials_not_physical_outflows",
                )
            )

        if cohort.settlement_closed:
            closed += 1
            closed_sales += cohort.sales_t
            if cohort.invoiced_quantity_t is None or cohort.invoiced_at is None:
                missing_closed_invoice_count += 1
                checks.append(
                    _not_evaluated_check(
                        f"sales_invoice_match:{cohort.cohort_id}",
                        ["sales_t", "invoiced_quantity_t"],
                        f"闭账批次 {cohort.cohort_id} 缺少开票数量或日期",
                    )
                )
                continue
            evaluable_closed_sales += cohort.sales_t
            closed_invoices += cohort.invoiced_quantity_t
            invoice_lag = (cohort.invoiced_at - cohort.sales_date).days
            invoice_lags.append(invoice_lag)
            invoice_check = _check(
                code=f"sales_invoice_match:{cohort.cohort_id}",
                residual=cohort.sales_t - cohort.invoiced_quantity_t,
                tolerance=_credential_tolerance(
                    cohort.sales_t, cohort.invoiced_quantity_t, parameters
                ),
                metrics=["sales_t", "invoiced_quantity_t"],
                label=f"闭账批次 {cohort.cohort_id} 销售—开票凭证",
            )
            checks.append(invoice_check)
            if invoice_check.status is CheckStatus.CONFLICT:
                signals.append(
                    AnalysisSignal(
                        code="sales_invoice_credential_mismatch",
                        layer=EvidenceLayer.CREDENTIAL,
                        severity=SignalSeverity.RISK,
                        priority=ReviewPriority.P2,
                        evidence_tier=EvidenceTier.B,
                        message=invoice_check.message,
                        affected_metrics=["sales_t", "invoiced_quantity_t"],
                        observed=invoice_check.residual,
                        expected_lower=-(invoice_check.tolerance or 0.0),
                        expected_upper=invoice_check.tolerance,
                        basis="closed_settlement_credential_match_not_mass_balance",
                    )
                )
        else:
            pending += 1
            age = (submission.effective_coverage_as_of - cohort.sales_date).days
            if age > parameters.maximum_invoice_lag_days:
                overdue += 1
                signals.append(
                    AnalysisSignal(
                        code="invoice_lag_overdue",
                        layer=EvidenceLayer.CREDENTIAL,
                        severity=SignalSeverity.REVIEW,
                        priority=ReviewPriority.P2,
                        evidence_tier=EvidenceTier.B,
                        message=(
                            f"批次 {cohort.cohort_id} 距销售已 {age} 日仍未闭账，"
                            f"超过治理账期 {parameters.maximum_invoice_lag_days} 日"
                        ),
                        affected_metrics=["sales_t", "invoiced_quantity_t"],
                        observed=float(age),
                        expected_upper=float(parameters.maximum_invoice_lag_days),
                        basis="governed_invoice_ageing_not_daily_equality",
                    )
                )

    cumulative = _check(
        code="sales_transport_cumulative_match",
        residual=sales_total - transport_total,
        tolerance=_credential_tolerance(sales_total, transport_total, parameters),
        metrics=["sales_t", "transport_t"],
        label="窗口累计销售—运输凭证",
    )
    checks.append(cumulative)
    if closed - missing_closed_invoice_count:
        checks.append(
            _check(
                code="sales_invoice_closed_cumulative_match",
                residual=evaluable_closed_sales - closed_invoices,
                tolerance=_credential_tolerance(
                    evaluable_closed_sales, closed_invoices, parameters
                ),
                metrics=["sales_t", "invoiced_quantity_t"],
                label="闭账批次累计销售—开票凭证",
            )
        )

    module_status = (
        ModuleStatus.INSUFFICIENT
        if missing_closed_invoice_count
        else ModuleStatus.EVALUATED
    )
    reasons = (
        [
            f"{missing_closed_invoice_count} 个已闭账批次缺少开票事件，"
            "相关批次未判为冲突"
        ]
        if missing_closed_invoice_count
        else []
    )
    return ModuleAssessment(
        module="sales_transport_invoice_credentials",
        status=module_status,
        coverage_ratio=(
            (closed - missing_closed_invoice_count) / max(closed, 1)
            if closed
            else 1.0
        ),
        reasons=reasons,
    ), CredentialSummary(
        cohort_count=len(support.cohorts),
        closed_settlement_count=closed,
        pending_invoice_count=pending,
        overdue_invoice_count=overdue,
        cumulative_sales_t=sales_total,
        cumulative_transport_t=transport_total,
        cumulative_closed_sales_t=closed_sales,
        cumulative_closed_invoiced_quantity_t=closed_invoices,
        maximum_transport_lag_days=max(transport_lags) if transport_lags else None,
        maximum_invoice_lag_days=max(invoice_lags) if invoice_lags else None,
        checks=checks,
    ), signals


def _flow_reconciliation(
    submission: TenQuantitySubmission,
    totals: TenQuantityTotals,
    parameters: TenQuantityParameters,
) -> tuple[ModuleAssessment, L1FlowResult]:
    flow_applicable = (
        submission.applicability.raw_coal_balance
        or submission.applicability.wash_balance
    )
    if not flow_applicable:
        message = "本矿受控配置未启用原煤或洗选流网络边界"
        return ModuleAssessment(
            module="window_l1_flow_network",
            status=ModuleStatus.SKIPPED,
            coverage_ratio=1.0,
            reasons=[message],
        ), L1FlowResult(
            status=SolverStatus.SKIPPED,
            solver="not_applicable",
            message=message,
        )
    raw = (
        submission.applicability.raw_coal_balance
        and submission.raw_coal_support is not None
        and totals.production_t is not None
        and totals.wash_feed_t is not None
    )
    wash = (
        submission.applicability.wash_balance
        and submission.wash_support is not None
        and totals.wash_feed_t is not None
    )
    if not raw and not wash:
        message = "缺少可编译的库存或洗选边界，未运行流网络求解"
        return ModuleAssessment(
            module="window_l1_flow_network",
            status=ModuleStatus.INSUFFICIENT,
            coverage_ratio=0.0,
            reasons=[message],
        ), L1FlowResult(
            status=SolverStatus.INSUFFICIENT,
            solver="scipy.optimize.linprog/highs",
            message=message,
        )
    if _linprog is None:
        message = "SciPy/HiGHS 不可用，流网络求解已明确跳过"
        return ModuleAssessment(
            module="window_l1_flow_network",
            status=ModuleStatus.SKIPPED,
            coverage_ratio=1.0,
            reasons=[message],
        ), L1FlowResult(
            status=SolverStatus.SKIPPED,
            solver="unavailable",
            message=message,
        )

    observations: dict[str, float] = {}
    equations: list[tuple[str, dict[str, float], float]] = []
    if raw:
        support = submission.raw_coal_support
        assert support is not None
        assert totals.production_t is not None
        assert totals.wash_feed_t is not None
        observations.update(
            {
                "production_t": totals.production_t,
                "wash_feed_t": totals.wash_feed_t,
                "raw_direct_outbound_t": support.raw_direct_outbound_t,
                "closing_raw_inventory_t": support.closing_inventory_t,
            }
        )
        target = (
            -support.opening_inventory_t
            - support.purchases_t
            - support.other_in_t
            + support.other_out_t
            + support.approved_loss_t
        )
        equations.append(
            (
                "raw_coal_balance",
                {
                    "production_t": 1.0,
                    "wash_feed_t": -1.0,
                    "raw_direct_outbound_t": -1.0,
                    "closing_raw_inventory_t": -1.0,
                },
                target,
            )
        )
    if wash:
        support = submission.wash_support
        assert support is not None
        assert totals.wash_feed_t is not None
        observations.setdefault("wash_feed_t", totals.wash_feed_t)
        observations.update(
            {
                "washed_product_output_t": support.washed_product_output_t,
                "wash_rejects_t": support.rejects_t,
                "wash_process_loss_t": support.process_loss_t,
                "closing_wip_t": support.closing_wip_t,
            }
        )
        equations.append(
            (
                "wash_mass_balance",
                {
                    "wash_feed_t": 1.0,
                    "washed_product_output_t": -1.0,
                    "wash_rejects_t": -1.0,
                    "wash_process_loss_t": -1.0,
                    "closing_wip_t": -1.0,
                },
                -support.opening_wip_t,
            )
        )

    names = list(observations)
    metric_count = len(names)
    equation_count = len(equations)
    positive_start = metric_count
    negative_start = positive_start + metric_count
    balance_positive_start = negative_start + metric_count
    balance_negative_start = balance_positive_start + equation_count
    variable_count = balance_negative_start + equation_count

    objective = [0.0] * variable_count
    a_eq: list[list[float]] = []
    b_eq: list[float] = []
    index = {name: position for position, name in enumerate(names)}
    for position, name in enumerate(names):
        value = observations[name]
        tolerance = max(
            parameters.mass_absolute_tolerance_t,
            abs(value) * parameters.mass_relative_tolerance,
            1e-9,
        )
        objective[positive_start + position] = 1.0 / tolerance
        objective[negative_start + position] = 1.0 / tolerance
        row = [0.0] * variable_count
        row[position] = 1.0
        row[positive_start + position] = -1.0
        row[negative_start + position] = 1.0
        a_eq.append(row)
        b_eq.append(value)
    for position, (_, coefficients, target) in enumerate(equations):
        row = [0.0] * variable_count
        for name, coefficient in coefficients.items():
            row[index[name]] = coefficient
        row[balance_positive_start + position] = -1.0
        row[balance_negative_start + position] = 1.0
        scale = max((abs(value) for value in observations.values()), default=1.0)
        coefficient = parameters.flow_slack_penalty / max(scale, 1.0)
        objective[balance_positive_start + position] = coefficient
        objective[balance_negative_start + position] = coefficient
        a_eq.append(row)
        b_eq.append(target)
    try:
        solved = _linprog(
            objective,
            A_eq=a_eq,
            b_eq=b_eq,
            bounds=[(0.0, None)] * variable_count,
            method="highs",
        )
    except Exception as error:  # defensive native-solver boundary
        message = f"{type(error).__name__}: {error}"[:500]
        return ModuleAssessment(
            module="window_l1_flow_network",
            status=ModuleStatus.INSUFFICIENT,
            coverage_ratio=1.0,
            reasons=["流网络求解异常"],
        ), L1FlowResult(
            status=SolverStatus.FAILED,
            solver="scipy.optimize.linprog/highs",
            message=message,
        )
    if not bool(getattr(solved, "success", False)) or solved.x is None:
        message = str(getattr(solved, "message", "solver failed"))[:500]
        return ModuleAssessment(
            module="window_l1_flow_network",
            status=ModuleStatus.INSUFFICIENT,
            coverage_ratio=1.0,
            reasons=["流网络求解未得到最优解"],
        ), L1FlowResult(
            status=SolverStatus.FAILED,
            solver="scipy.optimize.linprog/highs",
            message=message,
        )
    reconciled = {name: float(solved.x[index[name]]) for name in names}
    adjustments = {
        name: reconciled[name] - observations[name]
        for name in names
    }
    slacks = {
        code: float(
            solved.x[balance_positive_start + position]
            + solved.x[balance_negative_start + position]
        )
        for position, (code, _, _) in enumerate(equations)
    }
    return ModuleAssessment(
        module="window_l1_flow_network",
        status=ModuleStatus.EVALUATED,
        coverage_ratio=1.0,
    ), L1FlowResult(
        status=SolverStatus.OPTIMAL,
        solver="scipy.optimize.linprog/highs",
        objective_value=float(solved.fun),
        reconciled_values=reconciled,
        signed_adjustments=adjustments,
        balance_slacks=slacks,
        message=str(getattr(solved, "message", ""))[:500] or None,
    )


_HISTORICAL_RELATIONSHIPS: dict[str, tuple[str, str]] = {
    "electricity_per_production": ("electricity_kwh", "production_t"),
    "detonators_per_extraction": ("detonators_count", "extraction_t"),
    "explosives_per_extraction": ("explosives_kg", "extraction_t"),
    "mine_entry_persons_per_production": (
        "mine_entry_persons",
        "production_t",
    ),
    "production_per_extraction": ("production_t", "extraction_t"),
    "wash_feed_per_production": ("wash_feed_t", "production_t"),
}


def _historical_analysis(
    submission: TenQuantitySubmission,
    totals: TenQuantityTotals,
    history: Sequence[HistoricalReferenceWindow],
    parameters: TenQuantityParameters,
) -> tuple[ModuleAssessment, list[HistoricalDiagnostic], list[AnalysisSignal]]:
    unique_history: dict[str, HistoricalReferenceWindow] = {}
    for item in history:
        unique_history.setdefault(item.reference_id, item)
    eligible = [
        item
        for item in unique_history.values()
        if item.baseline_eligible
        and item.available_at < submission.period_start
        and item.period_end < submission.period_start
        and item.operating_regime == submission.operating_regime
    ]
    diagnostics: list[HistoricalDiagnostic] = []
    signals: list[AnalysisSignal] = []
    evaluated = 0
    for relationship, (numerator, denominator) in _HISTORICAL_RELATIONSHIPS.items():
        ratios: list[float] = []
        for item in eligible:
            numerator_value = getattr(item.totals, numerator)
            denominator_value = getattr(item.totals, denominator)
            if (
                numerator_value is not None
                and denominator_value is not None
                and denominator_value > 1e-9
            ):
                ratios.append(float(numerator_value) / float(denominator_value))
        current_numerator = getattr(totals, numerator)
        current_denominator = getattr(totals, denominator)
        current = (
            float(current_numerator) / float(current_denominator)
            if current_numerator is not None
            and current_denominator is not None
            and current_denominator > 1e-9
            else None
        )
        if len(ratios) < parameters.minimum_history_windows or current is None:
            diagnostics.append(
                HistoricalDiagnostic(
                    relationship=relationship,
                    numerator_metric=numerator,
                    denominator_metric=denominator,
                    observed_ratio=current,
                    lower=None,
                    center=None,
                    upper=None,
                    sample_count=len(ratios),
                    status="insufficient",
                )
            )
            continue
        evaluated += 1
        center = median(ratios)
        mad = median(abs(item - center) for item in ratios)
        half_width = max(
            1.4826 * mad * parameters.historical_robust_z,
            abs(center) * parameters.historical_minimum_relative_half_width,
            1e-9,
        )
        lower = max(0.0, center - half_width)
        upper = center + half_width
        outside = current < lower or current > upper
        diagnostics.append(
            HistoricalDiagnostic(
                relationship=relationship,
                numerator_metric=numerator,
                denominator_metric=denominator,
                observed_ratio=current,
                lower=lower,
                center=center,
                upper=upper,
                sample_count=len(ratios),
                status="outside_band" if outside else "within_band",
            )
        )
        if outside:
            signals.append(
                AnalysisSignal(
                    code="historical_soft_interval_exceeded",
                    layer=EvidenceLayer.HISTORICAL,
                    severity=SignalSeverity.REVIEW,
                    # Explicit invariant: history alone is never P1.
                    priority=ReviewPriority.P2,
                    evidence_tier=EvidenceTier.C,
                    message=f"{relationship} 偏离本矿同工况历史软区间",
                    affected_metrics=[numerator, denominator],
                    observed=current,
                    expected_lower=lower,
                    expected_upper=upper,
                    basis="past_only_median_mad_soft_evidence",
                )
            )
    status = ModuleStatus.EVALUATED if evaluated else ModuleStatus.INSUFFICIENT
    return ModuleAssessment(
        module="historical_soft_baseline",
        status=status,
        coverage_ratio=evaluated / len(_HISTORICAL_RELATIONSHIPS),
        reasons=(
            [] if evaluated else ["没有足够的同工况、过去可用且已准入历史窗口"]
        ),
    ), diagnostics, signals


def _priority(signals: Sequence[AnalysisSignal], required_data_gap: bool) -> ReviewPriority:
    if any(item.priority is ReviewPriority.P1 for item in signals):
        return ReviewPriority.P1
    if any(item.priority is ReviewPriority.P2 for item in signals):
        return ReviewPriority.P2
    if required_data_gap:
        return ReviewPriority.DATA
    return ReviewPriority.NONE


def _stable_signals(signals: Sequence[AnalysisSignal]) -> list[AnalysisSignal]:
    unique: dict[tuple[Any, ...], AnalysisSignal] = {}
    for signal in signals:
        # Guard the fusion boundary even if a future caller constructs a bad
        # historical signal before this function.
        if (
            signal.layer is EvidenceLayer.HISTORICAL
            and signal.priority is ReviewPriority.P1
        ):
            signal = signal.model_copy(update={"priority": ReviewPriority.P2})
        key = (
            signal.code,
            signal.layer,
            signal.observed_date,
            tuple(signal.affected_metrics),
            signal.message,
        )
        unique.setdefault(key, signal)
    rank = {ReviewPriority.P1: 0, ReviewPriority.P2: 1, ReviewPriority.DATA: 2,
            ReviewPriority.NONE: 3}
    return sorted(
        unique.values(),
        key=lambda item: (
            rank[item.priority],
            item.observed_date or date.min,
            item.layer.value,
            item.code,
            tuple(item.affected_metrics),
        ),
    )


def analyze_ten_quantity(
    submission: TenQuantitySubmission | Mapping[str, Any],
    *,
    history: Sequence[HistoricalReferenceWindow | Mapping[str, Any]] = (),
    parameters: TenQuantityParameters | Mapping[str, Any] | None = None,
) -> TenQuantityAnalysisResult:
    """Analyze one governed V3 window without persistence or side effects."""

    validated = (
        submission
        if isinstance(submission, TenQuantitySubmission)
        else TenQuantitySubmission.model_validate(submission)
    )
    policy = (
        parameters
        if isinstance(parameters, TenQuantityParameters)
        else TenQuantityParameters.model_validate(parameters or {})
    )
    references = [
        item
        if isinstance(item, HistoricalReferenceWindow)
        else HistoricalReferenceWindow.model_validate(item)
        for item in history
    ]
    prepared = _prepare_submission(validated, policy)
    raw_module, raw_check, raw_signal = _raw_balance(
        validated, prepared.totals, policy
    )
    wash_module, wash_check, wash_signal = _wash_balance(
        validated, prepared.totals, policy
    )
    credential_module, credential_summary, credential_signals = (
        _credential_analysis(validated, policy)
    )
    flow_module, reconciliation = _flow_reconciliation(
        validated, prepared.totals, policy
    )
    historical_module, historical_diagnostics, historical_signals = (
        _historical_analysis(
            validated, prepared.totals, references, policy
        )
    )
    modules = [
        prepared.module,
        raw_module,
        wash_module,
        credential_module,
        flow_module,
        historical_module,
    ]
    signals = _stable_signals(
        [
            *prepared.signals,
            *([raw_signal] if raw_signal is not None else []),
            *([wash_signal] if wash_signal is not None else []),
            *credential_signals,
            *historical_signals,
        ]
    )
    required_modules = {
        "daily_shift_aggregation",
        *(
            {"raw_coal_balance"}
            if validated.applicability.raw_coal_balance
            else set()
        ),
        *(
            {"wash_mass_balance"}
            if validated.applicability.wash_balance
            else set()
        ),
        *(
            {"sales_transport_invoice_credentials"}
            if validated.applicability.credential_chain
            else set()
        ),
        *(
            {"window_l1_flow_network"}
            if (
                validated.applicability.raw_coal_balance
                or validated.applicability.wash_balance
            )
            else set()
        ),
    }
    required_data_gap = any(
        item.module in required_modules
        and item.status in {ModuleStatus.INSUFFICIENT, ModuleStatus.SKIPPED}
        for item in modules
    )
    priority = _priority(signals, required_data_gap)
    if priority in {ReviewPriority.P1, ReviewPriority.P2}:
        decision = DecisionStatus.RISK
        reasons = list(dict.fromkeys(item.message for item in signals))[:20]
        if required_data_gap:
            reasons.append("同时存在未完成的必需证据模块")
    elif priority is ReviewPriority.DATA:
        decision = DecisionStatus.INSUFFICIENT_DATA
        reasons = [
            reason
            for module in modules
            if module.module in required_modules
            for reason in module.reasons
        ] or ["必需证据模块未完成"]
    else:
        decision = DecisionStatus.NORMAL_CANDIDATE
        reasons = ["已执行的严格证据模块未发现超出治理容差的冲突"]

    runtime_manifest = {
        "solver_backend": "scipy.optimize.linprog/highs",
        "scipy_version": SCIPY_VERSION,
        "flow_network_version": FLOW_NETWORK_VERSION,
        "historical_rule_version": HISTORICAL_RULE_VERSION,
        "sales_transport_invoice_role": "linked_credentials_not_three_outflows",
    }
    input_material = {
        "submission": validated.model_dump(mode="json"),
        "history": [item.model_dump(mode="json") for item in references],
    }
    configuration_material = {
        "method_version": REGULATORY_V3_METHOD_VERSION,
        "parameters": policy.model_dump(mode="json"),
        "runtime_manifest": runtime_manifest,
    }
    return TenQuantityAnalysisResult(
        mine_id=validated.mine_id,
        submission_id=validated.submission_id,
        decision=decision,
        review_priority=priority,
        decision_reasons=reasons,
        totals=prepared.totals,
        metric_coverage=prepared.metric_coverage,
        modules=modules,
        balance_checks=[raw_check, wash_check],
        credential_summary=credential_summary,
        reconciliation=reconciliation,
        historical_diagnostics=historical_diagnostics,
        signals=signals,
        input_sha256=_sha256(input_material),
        configuration_sha256=_sha256(configuration_material),
        runtime_manifest=runtime_manifest,
    )


def _sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda item: item.isoformat()
        if isinstance(item, date)
        else item.value
        if isinstance(item, StrEnum)
        else str(item),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "AnalysisSignal",
    "BalanceCheck",
    "CheckStatus",
    "CredentialCohort",
    "CredentialSummary",
    "CredentialSupport",
    "DecisionStatus",
    "EvidenceLayer",
    "EvidenceProfile",
    "EvidenceTier",
    "HistoricalDiagnostic",
    "HistoricalReferenceWindow",
    "L1FlowResult",
    "METRICS",
    "ModuleApplicability",
    "ModuleAssessment",
    "ModuleStatus",
    "RawCoalBalanceSupport",
    "REGULATORY_V3_METHOD_VERSION",
    "ReportedQuantity",
    "ReviewPriority",
    "ShiftDurations",
    "ShiftValues",
    "SignalSeverity",
    "SolverStatus",
    "TEN_QUANTITY_GROUPS",
    "TenQuantityAnalysisResult",
    "TenQuantityDay",
    "TenQuantityParameters",
    "TenQuantitySubmission",
    "TenQuantityTotals",
    "WashBalanceSupport",
    "analyze_ten_quantity",
    "effective_reported_value",
]
