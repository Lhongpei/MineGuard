from __future__ import annotations

from datetime import date, timedelta
import json

import pytest
from pydantic import ValidationError

import mineguard.regulatory_v3 as v3
from mineguard.regulatory_v3 import (
    CheckStatus,
    CredentialCohort,
    CredentialSupport,
    DecisionStatus,
    EvidenceLayer,
    EvidenceProfile,
    HistoricalReferenceWindow,
    METRICS,
    ModuleApplicability,
    ModuleStatus,
    RawCoalBalanceSupport,
    ReportedQuantity,
    ReviewPriority,
    ShiftValues,
    SolverStatus,
    TEN_QUANTITY_GROUPS,
    TenQuantityDay,
    TenQuantityParameters,
    TenQuantitySubmission,
    TenQuantityTotals,
    WashBalanceSupport,
    analyze_ten_quantity,
)


def _q(value: float | None, shifts: ShiftValues | None = None) -> ReportedQuantity:
    return ReportedQuantity(daily_total=value, shifts=shifts)


def _day(observed: date, **updates: float | None) -> TenQuantityDay:
    values: dict[str, float | None] = {
        "ventilation_m3_min": 3_000.0,
        "electricity_kwh": 2_000.0,
        "detonators_count": 10.0,
        "explosives_kg": 50.0,
        "mine_entry_persons": 100.0,
        "production_t": 100.0,
        "extraction_t": 105.0,
        "sales_t": 30.0,
        "transport_t": 30.0,
        "wash_feed_t": 60.0,
        "invoiced_quantity_t": 30.0,
    }
    values.update(updates)
    return TenQuantityDay(
        date=observed,
        **{metric: _q(values[metric]) for metric in METRICS},
    )


def _evidence(*domains: str) -> EvidenceProfile:
    return EvidenceProfile(
        source_refs=[f"source-{index}" for index in range(len(domains))],
        dependency_domains=list(domains),
    )


def _credentials(start: date, count: int = 3) -> CredentialSupport:
    return CredentialSupport(
        cohorts=[
            CredentialCohort(
                cohort_id=f"shipment-{index}",
                sales_date=start + timedelta(days=index),
                sales_t=30.0,
                transport_date=start + timedelta(days=index),
                transport_t=30.0,
                invoiced_at=start + timedelta(days=index + 5),
                invoiced_quantity_t=30.0,
                settlement_closed=True,
                sales_source_ref=f"sale-{index}",
                transport_source_ref=f"transport-{index}",
                invoice_source_ref=f"invoice-{index}",
                sales_dependency_domain="sales-ledger",
                transport_dependency_domain="weighbridge",
                invoice_dependency_domain="invoice-ledger",
            )
            for index in range(count)
        ],
        sales_register_complete=True,
        transport_register_complete=True,
        invoice_register_complete=True,
    )


def _submission(
    *,
    day_count: int = 3,
    days: list[TenQuantityDay] | None = None,
    raw_support: RawCoalBalanceSupport | None = None,
    wash_support: WashBalanceSupport | None = None,
    credential_support: CredentialSupport | None = None,
    applicability: ModuleApplicability | None = None,
    coverage_as_of: date | None = None,
) -> TenQuantitySubmission:
    start = date(2026, 7, 1)
    report_days = days or [
        _day(start + timedelta(days=index)) for index in range(day_count)
    ]
    raw_support = raw_support or RawCoalBalanceSupport(
        opening_inventory_t=100.0,
        closing_inventory_t=100.0,
        raw_direct_outbound_t=40.0 * day_count,
        evidence=_evidence("inventory-ledger", "belt-scale"),
    )
    wash_support = wash_support or WashBalanceSupport(
        washed_product_output_t=50.0 * day_count,
        rejects_t=10.0 * day_count,
        evidence=_evidence("wash-plc", "laboratory-ledger"),
    )
    return TenQuantitySubmission(
        submission_id="00000000-0000-4000-8000-000000000301",
        mine_id="mine-a",
        period_start=start,
        period_end=start + timedelta(days=day_count - 1),
        coverage_as_of=coverage_as_of
        or start + timedelta(days=day_count + 10),
        operating_regime="normal",
        days=report_days,
        applicability=applicability or ModuleApplicability(),
        raw_coal_support=raw_support,
        wash_support=wash_support,
        credential_support=credential_support or _credentials(start, day_count),
    )


def test_v3_has_ten_business_groups_and_exactly_eleven_atomic_fields() -> None:
    assert list(TEN_QUANTITY_GROUPS) == [
        "airflow",
        "electricity",
        "blasting_materials",
        "mine_entry_personnel",
        "production",
        "extraction",
        "sales",
        "transport",
        "coal_washing",
        "invoicing",
    ]
    assert TEN_QUANTITY_GROUPS["blasting_materials"] == (
        "detonators_count",
        "explosives_kg",
    )
    assert METRICS == (
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


def test_metric_validation_rejects_negative_physical_values_and_fractional_counts() -> None:
    with pytest.raises(ValidationError, match="production_t cannot be negative"):
        _day(date(2026, 7, 1), production_t=-1.0)
    with pytest.raises(ValidationError, match="mine_entry_persons must be integral"):
        _day(date(2026, 7, 1), mine_entry_persons=1.5)

    # The main ten-quantity field is normal/blue-invoice physical tonnage.
    # Red invoices and returns must arrive as separate support events.
    with pytest.raises(
        ValidationError, match="invoiced_quantity_t cannot be negative"
    ):
        _day(date(2026, 7, 1), invoiced_quantity_t=-10.0)


def test_daily_only_values_are_complete_and_invoice_shifts_are_never_required() -> None:
    result = analyze_ten_quantity(_submission())

    assert result.decision is DecisionStatus.NORMAL_CANDIDATE
    assert result.review_priority is ReviewPriority.NONE
    assert all(item.ratio == 1.0 for item in result.metric_coverage)
    assert all(item.shift_reporting_optional for item in result.metric_coverage)
    assert not any(item.code == "partial_shift_values" for item in result.signals)
    assert result.reconciliation.status is SolverStatus.OPTIMAL


def test_partial_optional_commercial_shifts_do_not_override_a_daily_total() -> None:
    observed = date(2026, 7, 1)
    day = _day(observed).model_copy(
        update={
            "sales_t": ReportedQuantity(
                daily_total=30.0,
                shifts=ShiftValues(zero_shift=10.0, four_shift=20.0),
            )
        }
    )

    result = analyze_ten_quantity(_submission(day_count=1, days=[day]))

    assert result.totals.sales_t == 30.0
    assert not any(
        item.code == "partial_shift_values"
        and item.affected_metrics == ["sales_t"]
        for item in result.signals
    )


def test_shift_values_can_supply_daily_value_and_airflow_is_duration_weighted() -> None:
    observed = date(2026, 7, 1)
    day = _day(observed)
    day = day.model_copy(
        update={
            "ventilation_m3_min": ReportedQuantity(
                shifts=ShiftValues(
                    zero_shift=2_000.0,
                    eight_shift=3_000.0,
                    four_shift=4_000.0,
                )
            ),
            "sales_t": ReportedQuantity(
                shifts=ShiftValues(
                    zero_shift=10.0,
                    eight_shift=10.0,
                    four_shift=10.0,
                )
            ),
        }
    )
    submission = _submission(day_count=1, days=[day])

    result = analyze_ten_quantity(submission)

    assert result.totals.ventilation_m3_min == pytest.approx(3_000.0)
    assert result.totals.sales_t == pytest.approx(30.0)


def test_daily_shift_mismatch_is_deterministic_p2_not_physical_p1() -> None:
    start = date(2026, 7, 1)
    day = _day(start)
    day = day.model_copy(
        update={
            "electricity_kwh": ReportedQuantity(
                daily_total=2_000.0,
                shifts=ShiftValues(
                    zero_shift=1_000.0,
                    eight_shift=1_000.0,
                    four_shift=1_000.0,
                ),
            )
        }
    )

    result = analyze_ten_quantity(_submission(day_count=1, days=[day]))

    mismatch = next(
        item for item in result.signals
        if item.code == "daily_shift_arithmetic_mismatch"
    )
    assert mismatch.layer is EvidenceLayer.DETERMINISTIC
    assert mismatch.priority is ReviewPriority.P2


def test_missing_support_returns_insufficient_without_inventing_conflict() -> None:
    submission = _submission().model_copy(
        update={
            "raw_coal_support": None,
            "wash_support": None,
            "credential_support": None,
        }
    )

    result = analyze_ten_quantity(submission)

    assert result.decision is DecisionStatus.INSUFFICIENT_DATA
    assert result.review_priority is ReviewPriority.DATA
    assert {item.status for item in result.balance_checks} == {
        CheckStatus.INSUFFICIENT
    }
    assert not any(item.layer is EvidenceLayer.PHYSICAL for item in result.signals)
    assert result.reconciliation.status is SolverStatus.INSUFFICIENT


def test_raw_balance_conflict_is_p1_only_with_independent_evidence() -> None:
    support = RawCoalBalanceSupport(
        opening_inventory_t=100.0,
        closing_inventory_t=10.0,
        raw_direct_outbound_t=0.0,
        evidence=_evidence("inventory-ledger", "belt-scale"),
    )

    result = analyze_ten_quantity(_submission(raw_support=support))

    signal = next(item for item in result.signals if item.code == "raw_coal_balance")
    assert signal.priority is ReviewPriority.P1
    assert signal.layer is EvidenceLayer.PHYSICAL
    assert result.review_priority is ReviewPriority.P1
    assert result.reconciliation.status is SolverStatus.OPTIMAL
    assert "raw_coal_balance" in result.reconciliation.balance_slacks


def test_single_dependency_physical_conflict_is_conservatively_p2() -> None:
    support = RawCoalBalanceSupport(
        opening_inventory_t=100.0,
        closing_inventory_t=10.0,
        raw_direct_outbound_t=0.0,
        evidence=_evidence("single-erp-domain"),
    )

    result = analyze_ten_quantity(_submission(raw_support=support))

    signal = next(item for item in result.signals if item.code == "raw_coal_balance")
    assert signal.priority is ReviewPriority.P2
    assert result.review_priority is ReviewPriority.P2


def test_two_declared_domains_still_need_two_sources_for_p1() -> None:
    support = RawCoalBalanceSupport(
        opening_inventory_t=100.0,
        closing_inventory_t=10.0,
        raw_direct_outbound_t=0.0,
        evidence=EvidenceProfile(
            source_refs=["one-source"],
            dependency_domains=["domain-a", "domain-b"],
        ),
    )

    result = analyze_ten_quantity(_submission(raw_support=support))

    signal = next(item for item in result.signals if item.code == "raw_coal_balance")
    assert signal.priority is ReviewPriority.P2


def test_sales_transport_and_invoice_are_not_three_material_outflows() -> None:
    start = date(2026, 7, 1)
    days = [
        _day(
            start + timedelta(days=index),
            sales_t=10_000.0,
            transport_t=10_000.0,
            invoiced_quantity_t=10_000.0,
        )
        for index in range(3)
    ]
    credentials = _credentials(start)
    for cohort in credentials.cohorts:
        cohort.sales_t = 10_000.0
        cohort.transport_t = 10_000.0
        cohort.invoiced_quantity_t = 10_000.0

    result = analyze_ten_quantity(
        _submission(days=days, credential_support=credentials)
    )

    raw = next(item for item in result.balance_checks if item.code == "raw_coal_balance")
    assert raw.status is CheckStatus.CONSISTENT
    assert raw.residual == pytest.approx(0.0)
    assert result.runtime_manifest["sales_transport_invoice_role"] == (
        "linked_credentials_not_three_outflows"
    )


def test_wash_support_is_required_but_can_be_governed_not_applicable() -> None:
    missing = _submission().model_copy(update={"wash_support": None})
    missing_result = analyze_ten_quantity(missing)
    wash_missing = next(
        item for item in missing_result.balance_checks
        if item.code == "wash_mass_balance"
    )
    assert wash_missing.status is CheckStatus.INSUFFICIENT

    not_applicable = missing.model_copy(
        update={
            "applicability": ModuleApplicability(
                raw_coal_balance=True,
                wash_balance=False,
                credential_chain=True,
            )
        }
    )
    skipped_result = analyze_ten_quantity(not_applicable)
    wash_skipped = next(
        item for item in skipped_result.balance_checks
        if item.code == "wash_mass_balance"
    )
    assert wash_skipped.status is CheckStatus.SKIPPED
    assert skipped_result.decision is DecisionStatus.NORMAL_CANDIDATE


def test_all_flow_boundaries_can_be_governed_not_applicable() -> None:
    submission = _submission().model_copy(
        update={
            "applicability": ModuleApplicability(
                raw_coal_balance=False,
                wash_balance=False,
                credential_chain=False,
            ),
            "raw_coal_support": None,
            "wash_support": None,
            "credential_support": None,
        }
    )

    result = analyze_ten_quantity(submission)

    flow = next(
        item for item in result.modules if item.module == "window_l1_flow_network"
    )
    assert flow.status is ModuleStatus.SKIPPED
    assert result.reconciliation.status is SolverStatus.SKIPPED
    assert result.decision is DecisionStatus.NORMAL_CANDIDATE


def test_incomplete_credential_register_is_insufficient_not_a_mismatch() -> None:
    support = _credentials(date(2026, 7, 1))
    support.transport_register_complete = False

    result = analyze_ten_quantity(_submission(credential_support=support))

    module = next(
        item for item in result.modules
        if item.module == "sales_transport_invoice_credentials"
    )
    assert module.status is ModuleStatus.INSUFFICIENT
    assert result.credential_summary is None
    assert not any("credential_mismatch" in item.code for item in result.signals)


def test_missing_closed_invoices_have_exact_coverage_and_do_not_pollute_cumulative_check() -> None:
    support = _credentials(date(2026, 7, 1))
    for cohort in support.cohorts[:2]:
        cohort.invoiced_at = None
        cohort.invoiced_quantity_t = None
        cohort.invoice_source_ref = None
        cohort.invoice_dependency_domain = None

    result = analyze_ten_quantity(_submission(credential_support=support))

    module = next(
        item for item in result.modules
        if item.module == "sales_transport_invoice_credentials"
    )
    cumulative = next(
        item for item in result.credential_summary.checks
        if item.code == "sales_invoice_closed_cumulative_match"
    )
    assert module.status is ModuleStatus.INSUFFICIENT
    assert module.coverage_ratio == pytest.approx(1.0 / 3.0)
    assert cumulative.status is CheckStatus.CONSISTENT


def test_linked_sales_transport_mismatch_is_p2_and_never_a_physical_outflow() -> None:
    support = _credentials(date(2026, 7, 1))
    support.cohorts[0].transport_t = 20.0

    result = analyze_ten_quantity(_submission(credential_support=support))

    signal = next(
        item for item in result.signals
        if item.code == "sales_transport_credential_mismatch"
    )
    assert signal.priority is ReviewPriority.P2
    assert signal.layer is EvidenceLayer.CREDENTIAL
    assert result.review_priority is ReviewPriority.P2


def test_open_invoice_within_lag_is_pending_not_daily_mismatch() -> None:
    start = date(2026, 7, 1)
    cohort = CredentialCohort(
        cohort_id="pending-1",
        sales_date=start,
        sales_t=30.0,
        transport_date=start + timedelta(days=1),
        transport_t=30.0,
        settlement_closed=False,
        sales_source_ref="sale-1",
        transport_source_ref="transport-1",
        sales_dependency_domain="erp",
        transport_dependency_domain="weighbridge",
    )
    support = CredentialSupport(
        cohorts=[cohort],
        sales_register_complete=True,
        transport_register_complete=True,
        invoice_register_complete=True,
    )

    result = analyze_ten_quantity(
        _submission(
            day_count=1,
            credential_support=support,
            coverage_as_of=start + timedelta(days=30),
        )
    )

    assert result.credential_summary is not None
    assert result.credential_summary.pending_invoice_count == 1
    assert result.credential_summary.overdue_invoice_count == 0
    assert not any(item.code == "invoice_lag_overdue" for item in result.signals)


def test_invoice_ageing_uses_coverage_as_of_and_not_same_day_equality() -> None:
    start = date(2026, 7, 1)
    cohort = CredentialCohort(
        cohort_id="overdue-1",
        sales_date=start,
        sales_t=30.0,
        transport_date=start,
        transport_t=30.0,
        settlement_closed=False,
        sales_source_ref="sale-1",
        transport_source_ref="transport-1",
        sales_dependency_domain="erp",
        transport_dependency_domain="weighbridge",
    )
    support = CredentialSupport(
        cohorts=[cohort],
        sales_register_complete=True,
        transport_register_complete=True,
        invoice_register_complete=True,
    )

    result = analyze_ten_quantity(
        _submission(
            day_count=1,
            credential_support=support,
            coverage_as_of=start + timedelta(days=100),
        ),
        parameters=TenQuantityParameters(maximum_invoice_lag_days=90),
    )

    signal = next(item for item in result.signals if item.code == "invoice_lag_overdue")
    assert signal.priority is ReviewPriority.P2
    assert signal.observed == 100.0


def _history(start: date, count: int = 7) -> list[HistoricalReferenceWindow]:
    return [
        HistoricalReferenceWindow(
            reference_id=f"history-{index}",
            period_end=start - timedelta(days=20 + index),
            available_at=start - timedelta(days=10 + index),
            operating_regime="normal",
            totals=TenQuantityTotals(
                electricity_kwh=1_000.0,
                detonators_count=100.0,
                explosives_kg=500.0,
                mine_entry_persons=1_000.0,
                production_t=100.0,
                extraction_t=105.0,
                wash_feed_t=60.0,
            ),
        )
        for index in range(count)
    ]


def test_historical_outlier_can_only_create_p2() -> None:
    start = date(2026, 7, 1)
    result = analyze_ten_quantity(_submission(), history=_history(start))

    historical = [
        item for item in result.signals
        if item.layer is EvidenceLayer.HISTORICAL
    ]
    assert historical
    assert all(item.priority is ReviewPriority.P2 for item in historical)
    assert result.review_priority is not ReviewPriority.P1


def test_future_or_not_yet_available_history_is_excluded() -> None:
    start = date(2026, 7, 1)
    future = _history(start)
    future = [
        item.model_copy(update={"available_at": start + timedelta(days=1)})
        for item in future
    ]

    result = analyze_ten_quantity(_submission(), history=future)

    module = next(
        item for item in result.modules if item.module == "historical_soft_baseline"
    )
    assert module.status is ModuleStatus.INSUFFICIENT
    assert not any(item.layer is EvidenceLayer.HISTORICAL for item in result.signals)


def test_duplicate_history_references_do_not_inflate_baseline_sample() -> None:
    start = date(2026, 7, 1)
    one_reference = _history(start, count=1)[0]

    result = analyze_ten_quantity(
        _submission(), history=[one_reference] * 7
    )

    assert all(item.sample_count == 1 for item in result.historical_diagnostics)
    assert not any(item.layer is EvidenceLayer.HISTORICAL for item in result.signals)


def test_extreme_extraction_is_not_silently_equated_to_production() -> None:
    start = date(2026, 7, 1)
    days = [
        _day(start + timedelta(days=index), extraction_t=10_000.0)
        for index in range(3)
    ]

    result = analyze_ten_quantity(_submission(days=days))

    assert not any(
        item.layer is EvidenceLayer.PHYSICAL
        and "extraction_t" in item.affected_metrics
        for item in result.signals
    )
    assert result.decision is DecisionStatus.NORMAL_CANDIDATE


def test_solver_unavailable_is_explicitly_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(v3, "_linprog", None)

    result = analyze_ten_quantity(_submission())

    assert result.reconciliation.status is SolverStatus.SKIPPED
    module = next(
        item for item in result.modules if item.module == "window_l1_flow_network"
    )
    assert module.status is ModuleStatus.SKIPPED
    assert result.decision is DecisionStatus.INSUFFICIENT_DATA


def test_result_is_stably_json_serializable_and_mapping_input_is_supported() -> None:
    submission = _submission()
    first = analyze_ten_quantity(submission.model_dump(mode="json"))
    second = analyze_ten_quantity(submission)

    serialized = json.dumps(
        first.model_dump(mode="json"), ensure_ascii=False, sort_keys=True
    )
    assert "regulatory-ten-quantity-v3.1.0" in serialized
    assert first.input_sha256 == second.input_sha256
    assert first.configuration_sha256 == second.configuration_sha256
    assert first.model_dump(mode="json") == second.model_dump(mode="json")
