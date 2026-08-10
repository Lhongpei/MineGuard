from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
import json

import pytest

import mineguard.regulatory_v2 as regulatory_v2_module
from mineguard.regulatory_v2 import (
    ComparisonContext,
    DecisionStatus,
    FIVE_QUANTITY_GROUPS,
    LEGACY_METRICS,
    METRICS,
    SHIFT_REQUIRED_METRICS,
    TEN_QUANTITY_GROUPS,
    FiveQuantityDay,
    FiveQuantitySubmission,
    HistoricalFiveQuantityDay,
    ReferenceBand,
    RelationshipCode,
    ReportedQuality,
    ReportedQuantity,
    ShiftMetadata,
    ShiftValues,
    ShiftWindowMetadata,
    SubmissionProvenance,
    analyze_five_quantity,
    effective_reported_value,
)


def _quantity(
    value: float | None, shifts: ShiftValues | None = None
) -> ReportedQuantity:
    return ReportedQuantity(daily_total=value, shifts=shifts)


def _submission(
    *,
    submission_id: str = "00000000-0000-4000-8000-000000000001",
    mode: str = "manual_import",
    day_count: int = 14,
    electricity_ratios: list[float] | None = None,
    mismatch_day: int | None = None,
) -> FiveQuantitySubmission:
    start = date(2026, 1, 1)
    ratios = electricity_ratios or [20.0] * day_count
    days: list[FiveQuantityDay] = []
    for index in range(day_count):
        production = 100.0
        electricity = production * ratios[index]
        electricity_shifts = None
        if mismatch_day == index:
            electricity_shifts = ShiftValues(
                zero_shift=electricity,
                eight_shift=electricity,
                four_shift=electricity,
            )
        days.append(
            FiveQuantityDay(
                date=start + timedelta(days=index),
                ventilation_m3_min=_quantity(3_000.0),
                electricity_kwh=_quantity(electricity, electricity_shifts),
                detonators_count=_quantity(10.0),
                explosives_kg=_quantity(50.0),
                mine_entry_persons=_quantity(100.0),
                production_t=_quantity(production),
            )
        )
    return FiveQuantitySubmission(
        submission_id=submission_id,
        mine_id="mine-a",
        mine_name="A Mine",
        period_start=start,
        period_end=start + timedelta(days=day_count - 1),
        comparison_context=ComparisonContext(
            capacity_band="0.9-1.2mtpa",
            mining_method="longwall",
            shift_system="three-shift",
            coal_type="thermal",
            operating_regime="normal",
        ),
        days=days,
        provenance=[
            SubmissionProvenance(
                acquisition_mode=mode,
                source_name="monthly workbook",
                evidence_sha256="a" * 64,
            )
        ],
    )


def _ten_submission(
    *,
    day_count: int = 14,
    invoiced_values: list[float] | None = None,
) -> FiveQuantitySubmission:
    base = _submission(day_count=day_count)
    invoices = invoiced_values or [90.0] * day_count
    days = [
        day.model_copy(
            update={
                "extraction_t": _quantity(110.0),
                "sales_t": _quantity(90.0),
                "transport_t": _quantity(90.0),
                "wash_feed_t": _quantity(70.0),
                "invoiced_quantity_t": _quantity(invoices[index]),
            }
        )
        for index, day in enumerate(base.days)
    ]
    return FiveQuantitySubmission.model_validate(
        {
            **base.model_dump(mode="python"),
            "contract_version": "enterprise-ten-quantity-submission-v3",
            "quantity_scope": "ten_quantity_v3",
            "days": days,
        }
    )


def _ten_history(day_count: int = 30) -> list[HistoricalFiveQuantityDay]:
    return [
        HistoricalFiveQuantityDay(
            date=date(2025, 10, 1) + timedelta(days=index),
            ventilation_m3_min=3_000.0,
            electricity_kwh=2_000.0,
            detonators_count=10.0,
            explosives_kg=50.0,
            mine_entry_persons=100.0,
            production_t=100.0,
            extraction_t=110.0,
            sales_t=90.0,
            transport_t=90.0,
            wash_feed_t=70.0,
            invoiced_quantity_t=90.0,
        )
        for index in range(day_count)
    ]


def test_stable_period_is_normal_candidate_and_acquisition_mode_has_no_weight() -> None:
    manual = analyze_five_quantity(_submission(mode="manual_import"))
    direct = analyze_five_quantity(_submission(mode="direct_collection"))

    assert manual.decision is DecisionStatus.NORMAL_CANDIDATE
    assert direct.decision is DecisionStatus.NORMAL_CANDIDATE
    assert manual.algorithm_input_sha256 == direct.algorithm_input_sha256
    assert manual.reconciliation == direct.reconciliation
    assert manual.configuration_sha256 == direct.configuration_sha256


def test_five_business_quantities_keep_fire_material_units_separate() -> None:
    assert list(FIVE_QUANTITY_GROUPS) == [
        "airflow",
        "electricity",
        "blasting_materials",
        "mine_entry_personnel",
        "production",
    ]
    assert FIVE_QUANTITY_GROUPS["blasting_materials"] == (
        "detonators_count",
        "explosives_kg",
    )


def test_v3_catalog_has_ten_business_quantities_and_eleven_atoms() -> None:
    assert len(TEN_QUANTITY_GROUPS) == 10
    assert len(METRICS) == 11
    assert len(LEGACY_METRICS) == 6
    assert SHIFT_REQUIRED_METRICS == (*LEGACY_METRICS, "extraction_t")
    assert TEN_QUANTITY_GROUPS["blasting_materials"] == (
        "detonators_count",
        "explosives_kg",
    )


def test_legacy_v2_document_remains_readable_under_v3_engine() -> None:
    document = _submission().model_dump(mode="python", exclude_defaults=True)
    restored = FiveQuantitySubmission.model_validate(document)
    result = analyze_five_quantity(restored)

    assert restored.contract_version == "enterprise-five-quantity-submission-v2"
    assert restored.quantity_scope == "five_quantity_v2"
    assert restored.days[0].extraction_t is None
    assert restored.applicable_metrics == LEGACY_METRICS
    assert result.method_version == "regulatory-five-quantity-v2.3.0"
    assert result.runtime_manifest["baseline_admission_rule_version"] == (
        "baseline-admission-v2.2"
    )
    assert result.coverage.complete_day_count == 14
    assert {item.metric for item in result.reconciliation.adjustments} == set(
        LEGACY_METRICS
    )


def test_complete_v3_daily_report_does_not_require_commercial_shift_values() -> None:
    submission = _ten_submission()

    result = analyze_five_quantity(submission)

    assert submission.applicable_metrics == METRICS
    assert result.method_version.startswith("regulatory-ten-quantity-v3.")
    assert result.coverage.complete_day_count == 14
    assert result.coverage.completeness_ratio == 1.0
    assert result.decision is DecisionStatus.NORMAL_CANDIDATE
    assert all(
        item.code != "partial_shift_values"
        for item in result.data_quality_signals
        if item.metric in {"sales_t", "transport_t", "wash_feed_t", "invoiced_quantity_t"}
    )
    assert {item.metric for item in result.reconciliation.adjustments} == set(METRICS)
    assert result.method_version == "regulatory-ten-quantity-v3.2.0"
    assert result.runtime_manifest["advanced_evidence_method_version"] == (
        "regulatory-ten-quantity-v3.1.0"
    )
    advanced_modules = json.loads(
        result.runtime_manifest["advanced_evidence_modules"]
    )
    assert advanced_modules["daily_shift_aggregation"] == "evaluated"
    assert advanced_modules["raw_coal_balance"] == "skipped"
    assert advanced_modules["wash_mass_balance"] == "skipped"
    assert advanced_modules["sales_transport_invoice_credentials"] == "skipped"
    assert result.runtime_manifest["advanced_support_policy"].startswith(
        "base_v3_exchange_has_no_auxiliary"
    )


def test_advanced_evidence_layer_dispatches_only_for_v3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = regulatory_v2_module._run_advanced_v3_evidence_layer
    calls: list[str] = []

    def capture(submission, history):
        calls.append(submission.quantity_scope)
        return original(submission, history)

    monkeypatch.setattr(
        regulatory_v2_module,
        "_run_advanced_v3_evidence_layer",
        capture,
    )

    legacy = analyze_five_quantity(_submission())
    current = analyze_five_quantity(_ten_submission())

    assert calls == ["ten_quantity_v3"]
    assert "advanced_evidence_method_version" not in legacy.runtime_manifest
    assert current.runtime_manifest["advanced_evidence_input_sha256"]


def test_v3_shift_metadata_requires_seven_atoms_but_allows_commercial_subset() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    aggregations = {
        metric: ("time_weighted_average" if metric == "ventilation_m3_min" else "sum")
        for metric in (*SHIFT_REQUIRED_METRICS, "sales_t")
    }

    metadata = ShiftWindowMetadata(
        shift_code="SHIFT-1",
        start_at=start,
        end_at=start + timedelta(hours=8),
        aggregations=aggregations,
    )

    assert set(metadata.aggregations) == set(SHIFT_REQUIRED_METRICS) | {"sales_t"}


def test_provided_commercial_shift_values_are_preserved_and_checked() -> None:
    submission = _ten_submission()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    aggregations = {
        metric: ("time_weighted_average" if metric == "ventilation_m3_min" else "sum")
        for metric in (*SHIFT_REQUIRED_METRICS, "sales_t")
    }
    windows = [
        ShiftWindowMetadata(
            shift_code=f"SHIFT-{index + 1}",
            start_at=start + timedelta(hours=index * 8),
            end_at=start + timedelta(hours=(index + 1) * 8),
            aggregations=aggregations,
        )
        for index in range(3)
    ]
    day = submission.days[0].model_copy(
        update={
            "sales_t": ReportedQuantity(
                daily_total=90.0,
                daily_aggregation="sum",
                shifts=ShiftValues(
                    zero_shift=30.0,
                    eight_shift=30.0,
                    four_shift=30.0,
                ),
            ),
            "shift_metadata": ShiftMetadata(
                zero_shift=windows[0],
                eight_shift=windows[1],
                four_shift=windows[2],
            ),
        }
    )
    submission.days[0] = FiveQuantityDay.model_validate(day.model_dump(mode="python"))

    result = analyze_five_quantity(submission)

    assert submission.days[0].sales_t is not None
    assert submission.days[0].sales_t.shifts is not None
    assert effective_reported_value(submission.days[0], "sales_t") == 90.0
    assert not any(
        signal.code == "daily_shift_arithmetic_mismatch" and signal.metric == "sales_t"
        for signal in result.data_quality_signals
    )


def test_v3_invoice_sales_anomaly_is_a_soft_reference_not_physical_law() -> None:
    result = analyze_five_quantity(
        _ten_submission(invoiced_values=[180.0] * 14),
        history=_ten_history(),
    )

    diagnostic = next(
        item
        for item in result.reconciliation.soft_constraint_diagnostics
        if item.relationship is RelationshipCode.INVOICED_QUANTITY_PER_SALES
    )
    reference = next(
        item
        for item in result.references.accepted_history_bands
        if item.relationship is RelationshipCode.INVOICED_QUANTITY_PER_SALES
    )
    assert reference.numerator_metric == "invoiced_quantity_t"
    assert reference.denominator_metric == "sales_t"
    assert diagnostic.upper_slack > 0.0
    assert result.decision is DecisionStatus.RISK
    assert result.reconciliation.note.endswith("not_physical_laws")
    assert any(
        RelationshipCode.INVOICED_QUANTITY_PER_SALES.value in group
        for conflict in result.reconciliation.minimal_conflict_sets
        for group in conflict.relaxed_groups
    )
    assert {
        "past_only_rolling_mad",
        "past_only_ewma",
        "past_only_cusum",
        "past_only_page_hinkley",
    } <= {
        signal.code
        for signal in result.temporal_signals
        if signal.metric == RelationshipCode.INVOICED_QUANTITY_PER_SALES.value
    }


def test_v3_missing_relationship_denominator_is_skipped_safely() -> None:
    submission = _ten_submission()
    submission.days[0] = submission.days[0].model_copy(
        update={"sales_t": ReportedQuantity(daily_total=None)}
    )

    result = analyze_five_quantity(submission, history=_ten_history())

    assert result.reconciliation.success
    assert result.coverage.complete_day_count == 13
    assert not any(
        item.date == submission.days[0].date
        and item.relationship
        in {
            RelationshipCode.TRANSPORT_PER_SALES,
            RelationshipCode.INVOICED_QUANTITY_PER_SALES,
        }
        for item in result.reconciliation.soft_constraint_diagnostics
    )


def test_v3_l1_solver_uses_eleven_metric_dimensions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = regulatory_v2_module._run_linprog_with_fallback
    objective_sizes: list[int] = []

    def capture_dimension(objective, **kwargs):
        objective_sizes.append(len(objective))
        return original(objective, **kwargs)

    monkeypatch.setattr(
        regulatory_v2_module,
        "_run_linprog_with_fallback",
        capture_dimension,
    )

    result = analyze_five_quantity(_ten_submission())

    # No active prior bands: 11 reconciled values + two L1 error variables for
    # each of the eleven daily observations.
    assert objective_sizes[0] == len(METRICS) * 3
    assert len({item.metric for item in result.reconciliation.adjustments}) == 11


def test_legacy_internal_personnel_records_read_as_canonical_term() -> None:
    document = _submission().days[0].model_dump(mode="python")
    document["labor_persons"] = document.pop("mine_entry_persons")

    restored = FiveQuantityDay.model_validate(document)

    assert restored.mine_entry_persons.daily_total == 100
    assert "mine_entry_persons" in restored.model_dump(mode="python")
    assert RelationshipCode("labor_per_production") is (
        RelationshipCode.MINE_ENTRY_PERSONS_PER_PRODUCTION
    )


def test_missing_values_are_accepted_and_return_insufficient_data() -> None:
    submission = _submission(day_count=3)
    missing = ReportedQuantity(daily_total=None)
    submission.days[0] = submission.days[0].model_copy(
        update={"electricity_kwh": missing}
    )

    result = analyze_five_quantity(submission)

    assert result.decision is DecisionStatus.INSUFFICIENT_DATA
    assert result.coverage.complete_day_count == 2


def test_partial_quality_flags_are_retained_and_reduce_usable_coverage() -> None:
    submission = _submission()
    for index in range(5):
        submission.days[index] = submission.days[index].model_copy(
            update={
                "quality": {
                    "electricity_kwh": ReportedQuality(
                        daily_total=("reported", "partial")
                    )
                }
            }
        )

    result = analyze_five_quantity(submission)

    assert result.decision is DecisionStatus.INSUFFICIENT_DATA
    assert result.coverage.complete_day_count == 9
    assert any(
        signal.code == "qualified_measurement_requires_review"
        for signal in result.data_quality_signals
    )


def test_declared_operating_state_is_compared_but_never_blindly_trusted() -> None:
    submission = _submission()
    submission.days[0] = submission.days[0].model_copy(
        update={"declared_operating_state": "stopped"}
    )

    result = analyze_five_quantity(submission)

    assert any(
        signal.code == "declared_operating_state_mismatch"
        for signal in result.data_quality_signals
    )


def test_daily_shift_mismatch_is_risk_and_has_l1_mcs_diagnosis() -> None:
    result = analyze_five_quantity(_submission(mismatch_day=5))

    assert result.decision is DecisionStatus.RISK
    assert any(
        signal.code == "daily_shift_arithmetic_mismatch"
        for signal in result.data_quality_signals
    )
    assert result.reconciliation.success
    assert result.reconciliation.minimal_conflict_sets
    relaxed = {
        group
        for item in result.reconciliation.minimal_conflict_sets
        for group in item.relaxed_groups
    }
    assert any(group.startswith(("reported:", "shifts:")) for group in relaxed)


def test_explicit_risk_is_not_downgraded_by_short_or_incomplete_reporting() -> None:
    result = analyze_five_quantity(_submission(day_count=3, mismatch_day=1))

    assert result.decision is DecisionStatus.RISK
    assert result.data_sufficiency_reasons
    assert any(
        signal.code == "daily_shift_arithmetic_mismatch"
        for signal in result.data_quality_signals
    )


def test_same_mine_history_is_a_soft_interval_in_weighted_l1() -> None:
    history = [
        HistoricalFiveQuantityDay(
            date=date(2025, 10, 1) + timedelta(days=index),
            ventilation_m3_min=3_000.0,
            electricity_kwh=2_000.0,
            detonators_count=10.0,
            explosives_kg=50.0,
            mine_entry_persons=100.0,
            production_t=100.0,
        )
        for index in range(30)
    ]
    result = analyze_five_quantity(
        _submission(electricity_ratios=[45.0] * 14), history=history
    )

    assert result.decision is DecisionStatus.RISK
    diagnostic = next(
        item
        for item in result.reconciliation.soft_constraint_diagnostics
        if item.relationship is RelationshipCode.ELECTRICITY_PER_PRODUCTION
    )
    assert diagnostic.basis == "same_mine_history"
    assert diagnostic.upper_slack > 0.0
    assert result.reconciliation.note.endswith("not_physical_laws")


def test_peer_band_is_ignored_until_anonymity_threshold_is_met() -> None:
    submission = _submission(electricity_ratios=[35.0] * 14)
    group = submission.comparison_context.group_key
    weak_peer = ReferenceBand(
        relationship=RelationshipCode.ELECTRICITY_PER_PRODUCTION,
        lower=18.0,
        center=20.0,
        upper=22.0,
        sample_count=100,
        mine_count=2,
        basis="anonymous_peer",
        comparison_group=group,
    )
    accepted_peer = weak_peer.model_copy(update={"mine_count": 3})

    ignored = analyze_five_quantity(submission, peer_bands=[weak_peer])
    accepted = analyze_five_quantity(submission, peer_bands=[accepted_peer])

    assert ignored.references.accepted_peer_bands == []
    assert len(accepted.references.accepted_peer_bands) == 1
    assert accepted.decision is DecisionStatus.RISK


def test_temporal_drift_and_bic_change_point_are_retained() -> None:
    result = analyze_five_quantity(
        _submission(electricity_ratios=[20.0] * 10 + [32.0] * 10, day_count=20)
    )

    codes = {signal.code for signal in result.temporal_signals}
    assert "sustained_ratio_drift" in codes
    assert "retrospective_change_point" in codes
    assert result.decision is DecisionStatus.RISK


def test_established_past_only_temporal_detector_suite_is_inside_v2_engine() -> None:
    history = [
        HistoricalFiveQuantityDay(
            date=date(2025, 11, 1) + timedelta(days=index),
            ventilation_m3_min=3_000.0,
            electricity_kwh=2_000.0,
            detonators_count=10.0,
            explosives_kg=50.0,
            mine_entry_persons=100.0,
            production_t=100.0,
        )
        for index in range(30)
    ]

    result = analyze_five_quantity(
        _submission(electricity_ratios=[30.0] * 14),
        history=history,
    )

    codes = {
        signal.code
        for signal in result.temporal_signals
        if signal.metric == RelationshipCode.ELECTRICITY_PER_PRODUCTION.value
    }
    assert {
        "past_only_rolling_mad",
        "past_only_ewma",
        "past_only_cusum",
        "past_only_page_hinkley",
    } <= codes
    assert all(
        "no_future_points" in signal.basis
        for signal in result.temporal_signals
        if signal.code.startswith("past_only_")
    )


def test_highs_fallback_is_auditable_and_keeps_numerical_failure_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = regulatory_v2_module.linprog
    methods: list[str] = []

    def fail_default_then_solve(*args, method: str, **kwargs):
        methods.append(method)
        if method == "highs":
            raise RuntimeError("synthetic primary solver failure")
        return original(*args, method=method, **kwargs)

    monkeypatch.setattr(regulatory_v2_module, "linprog", fail_default_then_solve)
    result = analyze_five_quantity(_submission())

    assert result.reconciliation.success is True
    assert result.reconciliation.solver_status == "optimal"
    assert result.reconciliation.solver_methods_attempted[:2] == [
        "highs",
        "highs-ds",
    ]
    assert methods[:2] == ["highs", "highs-ds"]


def test_time_weighted_ventilation_uses_preserved_shift_durations() -> None:
    submission = _submission()
    start = datetime(2026, 1, 1, tzinfo=UTC)
    durations = (420, 480, 540)
    starts = (start, start + timedelta(minutes=420), start + timedelta(minutes=900))
    values = (1_000.0, 2_000.0, 3_000.0)
    weighted = sum(
        value * minutes for value, minutes in zip(values, durations, strict=True)
    ) / sum(durations)
    aggregations = {
        "ventilation_m3_min": "time_weighted_average",
        "electricity_kwh": "sum",
        "detonators_count": "sum",
        "explosives_kg": "sum",
        "mine_entry_persons": "sum",
        "production_t": "sum",
    }
    windows = [
        ShiftWindowMetadata(
            shift_code=f"SHIFT-{index + 1}",
            start_at=shift_start,
            end_at=shift_start + timedelta(minutes=minutes),
            aggregations=aggregations,
        )
        for index, (shift_start, minutes) in enumerate(
            zip(starts, durations, strict=True)
        )
    ]
    submission.days[0] = submission.days[0].model_copy(
        update={
            "ventilation_m3_min": ReportedQuantity(
                daily_total=weighted,
                shifts=ShiftValues(
                    zero_shift=values[0],
                    eight_shift=values[1],
                    four_shift=values[2],
                ),
            ),
            "shift_metadata": ShiftMetadata(
                zero_shift=windows[0],
                eight_shift=windows[1],
                four_shift=windows[2],
            ),
        }
    )

    result = analyze_five_quantity(submission)

    assert not any(
        signal.code == "daily_shift_arithmetic_mismatch"
        and signal.metric == "ventilation_m3_min"
        for signal in result.data_quality_signals
    )


def test_mine_entry_persons_are_integral_and_sum_aggregated() -> None:
    base = _submission().days[0]
    with pytest.raises(ValueError, match="mine_entry_persons values must be integral"):
        FiveQuantityDay.model_validate(
            {
                **base.model_dump(mode="python"),
                "mine_entry_persons": ReportedQuantity(daily_total=100.5),
            }
        )

    with pytest.raises(ValueError, match="aggregation must be sum"):
        FiveQuantityDay.model_validate(
            {
                **base.model_dump(mode="python"),
                "mine_entry_persons": ReportedQuantity(
                    daily_total=100,
                    daily_aggregation="snapshot",
                ),
            }
        )
