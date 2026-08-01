from __future__ import annotations

import base64
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from mineguard.five_quantity import (
    ExplosiveUsage,
    FiveQuantityDay,
    FiveQuantityImportResult,
    FiveQuantityQualityFinding,
    FiveQuantityQualitySummary,
    FiveQuantityRawCell,
    FiveQuantitySourceMetadata,
    FiveQuantityUnits,
    FindingSeverity,
    RawCellKind,
    ReportMonthSource,
    ShiftExplosiveValues,
    ShiftNumericValues,
)
from mineguard.operational_five_quantity import (
    AnalysisValueBasis,
    AttentionLevel,
    OperationalFiveQuantityParameters,
    OperationalFiveQuantityFileRequest,
    OperationalState,
    OverallStatus,
    analyze_operational_five_quantity,
    analyze_operational_five_quantity_file,
)


ROOT = Path(__file__).resolve().parents[1]
LOCAL_FIXTURES = ROOT.parent / "local _test"
XX_WORKBOOK = LOCAL_FIXTURES / "五量基础数据测试.et"
GENGYANG_WORKBOOK = LOCAL_FIXTURES / "五量基础数据测试（沁源梗阳）.et"


def _empty_raw_cells() -> list[FiveQuantityRawCell]:
    return [
        FiveQuantityRawCell(
            column_index=index,
            cell_kind=RawCellKind.EMPTY,
            raw_value=None,
            is_blank=True,
            is_formula=False,
        )
        for index in range(1, 19)
    ]


def _numeric(value: float | None) -> ShiftNumericValues:
    if value is None:
        return ShiftNumericValues(
            zero_shift=None,
            eight_shift=None,
            four_shift=None,
            daily_total=None,
        )
    return ShiftNumericValues(
        zero_shift=value * 0.4,
        eight_shift=value * 0.2,
        four_shift=value * 0.4,
        daily_total=value,
    )


def _explosives() -> ShiftExplosiveValues:
    usage = ExplosiveUsage(
        detonators=0.0,
        explosives=0.0,
        raw_text="雷管：0\n炸药：0",
        is_blank=False,
    )
    return ShiftExplosiveValues(
        zero_shift=usage,
        eight_shift=usage,
        four_shift=usage,
        daily_total=usage,
    )


def _normalized_import(
    production: list[float | None],
    *,
    closed_count: int,
    ventilation: list[float] | None = None,
) -> FiveQuantityImportResult:
    start = date(2026, 1, 1)
    ventilation = ventilation or [100.0] * len(production)
    days = []
    for index, output in enumerate(production):
        observed_date = start + timedelta(days=index)
        is_closed = index < closed_count
        labor = None if output is None else 20.0
        electricity = None if output is None else 1000.0 + 2.0 * output
        days.append(
            FiveQuantityDay(
                date=observed_date,
                source_row_number=index + 4,
                is_closed=is_closed,
                ventilation=ventilation[index],
                labor=_numeric(labor),
                electricity=_numeric(electricity),
                explosives=_explosives(),
                production=_numeric(output),
                reconciliations=[],
                raw_cells=_empty_raw_cells(),
            )
        )
    return FiveQuantityImportResult(
        mine_id="M-SYNTHETIC",
        source=FiveQuantitySourceMetadata(
            source_id="synthetic",
            filename="synthetic.et",
            received_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        ),
        source_title="合成测试煤矿五量基础数据采集表",
        source_sha256="a" * 64,
        sheet_name="Sheet1",
        report_month="2026-01",
        report_month_source=ReportMonthSource.INFERRED_FROM_WORKBOOK_DATES,
        closed_through=start + timedelta(days=closed_count - 1),
        units=FiveQuantityUnits(),
        unknown_unit_fields=[
            "ventilation",
            "labor",
            "electricity",
            "detonators",
            "explosives",
            "production",
        ],
        formula_cell_count=0,
        days=days,
        quality=FiveQuantityQualitySummary(
            closed_day_count=closed_count,
            open_day_count=len(production) - closed_count,
            error_count=0,
            warning_count=0,
            info_count=0,
            findings=[],
        ),
    )


def _file_request(path: Path, mine_id: str) -> OperationalFiveQuantityFileRequest:
    if not path.is_file():
        pytest.skip(f"local ET fixture is unavailable: {path.name}")
    return OperationalFiveQuantityFileRequest.model_validate(
        {
            "mine_id": mine_id,
            "source": {
                "source_id": "operator-upload",
                "filename": path.name,
                "received_at": "2026-07-31T08:00:00Z",
            },
            "closed_through": "2026-07-30",
            "content_base64": base64.b64encode(path.read_bytes()).decode(
                "ascii"
            ),
        }
    )


def test_state_segmentation_merges_restart_and_excludes_open_day() -> None:
    imported = _normalized_import(
        [0.0, 0.0, 0.0, 40.0, 60.0, 80.0, 100.0, 101.0, 99.0, 100.0, None],
        closed_count=10,
    )

    result = analyze_operational_five_quantity(imported)

    assert [
        (segment.state, segment.day_count)
        for segment in result.regimes
    ] == [
        (OperationalState.NON_PRODUCTION_CANDIDATE, 3),
        (OperationalState.RESTART_RAMP_CANDIDATE, 3),
        (OperationalState.PRODUCTION, 4),
        (OperationalState.OPEN_PERIOD, 1),
    ]
    restart = [
        event
        for event in result.events
        if event.event_code == "restart_after_reported_zero_production"
    ]
    assert len(restart) == 1
    assert restart[0].period_start == date(2026, 1, 4)
    assert restart[0].period_end == date(2026, 1, 6)
    assert result.coverage.open_day_count == 1
    assert result.coverage.incomplete_closed_day_count == 0
    assert result.trust.persisted is False
    assert result.trust.audit_metadata_persisted is False
    assert (
        result.trust.audit_metadata_scope
        == "metadata_only_no_file_or_daily_payload"
    )
    assert result.trust.eligible_for_history is False
    assert result.analysis_mode == "retrospective"
    assert result.lookahead_used is True
    assert result.report_month == "2026-01"
    assert result.configuration.method_version == result.method_version
    assert len(result.configuration.sha256) == 64


def test_calendar_gap_resets_zero_run_and_makes_next_day_unknown() -> None:
    imported = _normalized_import(
        [0.0, 0.0, 0.0, 50.0, 70.0, 90.0, 100.0],
        closed_count=7,
    )
    shifted_days = [
        (
            day.model_copy(update={"date": day.date + timedelta(days=1)})
            if index >= 3
            else day
        )
        for index, day in enumerate(imported.days)
    ]
    imported = imported.model_copy(update={"days": shifted_days})

    result = analyze_operational_five_quantity(imported)

    first_after_gap = next(
        day for day in result.days if day.date == date(2026, 1, 5)
    )
    assert first_after_gap.operational_state is OperationalState.UNKNOWN
    assert "CALENDAR_GAP_BEFORE" in first_after_gap.reason_codes
    assert not any(
        event.event_code == "restart_after_reported_zero_production"
        for event in result.events
    )


def test_report_month_leading_gap_cannot_seed_a_restart() -> None:
    imported = _normalized_import(
        [0.0, 0.0, 0.0, 50.0, 70.0],
        closed_count=5,
    )
    shifted_days = [
        day.model_copy(update={"date": day.date + timedelta(days=2)})
        for day in imported.days
    ]
    imported = imported.model_copy(update={"days": shifted_days})

    result = analyze_operational_five_quantity(imported)

    assert result.days[0].operational_state is OperationalState.UNKNOWN
    assert "CALENDAR_GAP_BEFORE" in result.days[0].reason_codes
    assert not any(
        event.event_code == "restart_after_reported_zero_production"
        for event in result.events
    )


def test_production_reconciliation_failure_blocks_restart() -> None:
    imported = _normalized_import(
        [0.0, 0.0, 0.0, 50.0, 70.0, 90.0, 100.0],
        closed_count=7,
    )
    disputed = imported.days[3]
    disputed_production = disputed.production.model_copy(
        update={"daily_total": 60.0}
    )
    changed_days = list(imported.days)
    changed_days[3] = disputed.model_copy(
        update={"production": disputed_production}
    )
    imported = imported.model_copy(update={"days": changed_days})

    result = analyze_operational_five_quantity(imported)

    disputed_result = result.days[3]
    assert disputed_result.operational_state is OperationalState.UNKNOWN
    assert (
        "PRODUCTION_DAILY_SHIFT_MISMATCH"
        in disputed_result.reason_codes
    )
    assert not any(
        event.event_code == "restart_after_reported_zero_production"
        for event in result.events
    )


def test_relative_scale_prevents_small_constant_step_from_mass_alarm() -> None:
    production = [100.0] * 20
    ventilation = [1000.0] * 10 + [1010.0] * 10
    imported = _normalized_import(
        production,
        closed_count=20,
        ventilation=ventilation,
    )

    result = analyze_operational_five_quantity(imported)

    assert not any(
        event.event_code.startswith(
            "within_state_ratio_"
        )
        and "ventilation_to_production_ratio" in event.event_code
        for event in result.events
    )


def test_disputed_daily_value_uses_shift_recompute_but_not_clean_kpi() -> None:
    imported = _normalized_import([100.0] * 10, closed_count=10)
    disputed = imported.days[4]
    disputed_electricity = disputed.electricity.model_copy(
        update={"daily_total": 2000.0}
    )
    changed_days = list(imported.days)
    changed_days[4] = disputed.model_copy(
        update={"electricity": disputed_electricity}
    )
    imported = imported.model_copy(update={"days": changed_days})

    result = analyze_operational_five_quantity(imported)

    disputed_day = result.days[4]
    electricity = next(
        item
        for item in disputed_day.metric_reconciliations
        if item.metric == "electricity"
    )
    assert electricity.reported_daily_total == 2000.0
    assert electricity.recomputed_shift_total == pytest.approx(1200.0)
    assert electricity.analysis_value == pytest.approx(1200.0)
    assert (
        electricity.analysis_basis
        is AnalysisValueBasis.SHIFT_RECOMPUTED_DUE_TO_MISMATCH
    )
    assert electricity.eligible_for_robust_baseline is False
    assert (
        disputed_day.total_electricity_to_production_ratio
        == pytest.approx(12.0)
    )

    electricity_kpi = next(
        item for item in result.kpis if item.code == "electricity_total"
    )
    assert electricity_kpi.value == pytest.approx(10_800.0)
    assert electricity_kpi.contributing_day_count == 9
    assert electricity_kpi.excluded_mismatch_day_count == 1
    assert electricity_kpi.is_partial is True

    summary = next(
        item
        for item in result.metric_reconciliation_summaries
        if item.metric == "electricity"
    )
    assert summary.reported_daily_total == pytest.approx(12_800.0)
    assert summary.recomputed_shift_total == pytest.approx(12_000.0)
    assert summary.reconciled_daily_total == pytest.approx(10_800.0)
    assert summary.mismatch_day_count == 1


def test_coverage_separates_core_required_and_reconciled_fields() -> None:
    imported = _normalized_import([100.0] * 10, closed_count=10)
    incomplete = imported.days[2]
    incomplete_electricity = incomplete.electricity.model_copy(
        update={"zero_shift": None}
    )
    changed_days = list(imported.days)
    changed_days[2] = incomplete.model_copy(
        update={"electricity": incomplete_electricity}
    )
    imported = imported.model_copy(update={"days": changed_days})

    result = analyze_operational_five_quantity(imported)
    coverage = result.coverage

    assert coverage.core_daily_complete_closed_day_count == 10
    assert coverage.core_daily_incomplete_closed_day_count == 0
    assert coverage.complete_closed_day_count == 10
    assert coverage.all_required_fields_complete_closed_day_count == 9
    assert coverage.all_required_fields_incomplete_closed_day_count == 1
    assert coverage.all_shift_totals_reconciled_closed_day_count == 9
    assert (
        coverage.shift_totals_not_fully_reconciled_closed_day_count == 1
    )


def test_linear_production_trend_is_not_mislabeled_as_a_step() -> None:
    imported = _normalized_import(
        [float(value) for value in range(100, 114)],
        closed_count=14,
    )

    result = analyze_operational_five_quantity(imported)

    assert not any(
        event.event_code.startswith("retrospective_production_level_")
        for event in result.events
    )


def test_true_production_step_beats_linear_trend_model() -> None:
    imported = _normalized_import(
        [100.0] * 7 + [130.0] * 7,
        closed_count=14,
    )

    result = analyze_operational_five_quantity(imported)

    change = next(
        event
        for event in result.events
        if event.event_code == "retrospective_production_level_上升"
    )
    assert change.period_start == date(2026, 1, 8)
    assert "BIC" in change.summary


def test_missing_daily_total_is_not_merged_with_shift_breakdown() -> None:
    imported = _normalized_import([100.0] * 10, closed_count=10)
    first_date = imported.days[0].date
    final_date = imported.days[-1].date
    findings = [
        FiveQuantityQualityFinding(
            code="MISSING_REQUIRED_VALUE",
            severity=FindingSeverity.ERROR,
            message="missing shift",
            date=day.date,
            metric="electricity.zero_shift",
        )
        for day in imported.days
    ]
    findings.append(
        FiveQuantityQualityFinding(
            code="MISSING_REQUIRED_VALUE",
            severity=FindingSeverity.ERROR,
            message="missing daily total",
            date=final_date,
            metric="electricity.daily_total",
        )
    )
    imported = imported.model_copy(
        update={
            "quality": imported.quality.model_copy(
                update={
                    "error_count": len(findings),
                    "findings": findings,
                }
            )
        }
    )

    result = analyze_operational_five_quantity(imported)

    shift_event = next(
        event
        for event in result.events
        if event.event_code == "closed_shift_values_missing:electricity"
    )
    daily_event = next(
        event
        for event in result.events
        if event.event_code == "closed_daily_value_missing:electricity"
    )
    assert shift_event.attention_level is AttentionLevel.CHECK
    assert shift_event.period_start == first_date
    assert shift_event.period_end == final_date
    assert shift_event.merged_point_count == 10
    assert daily_event.attention_level is AttentionLevel.PRIORITY_CHECK
    assert daily_event.period_start == final_date
    assert daily_event.period_end == final_date
    assert daily_event.merged_point_count == 1


def test_missing_calendar_row_becomes_an_explicit_priority_event() -> None:
    imported = _normalized_import([100.0] * 10, closed_count=10)
    missing_date = imported.days[4].date
    finding = FiveQuantityQualityFinding(
        code="MISSING_CALENDAR_DATE",
        severity=FindingSeverity.ERROR,
        message="missing calendar row",
        date=missing_date,
    )
    imported = imported.model_copy(
        update={
            "quality": imported.quality.model_copy(
                update={
                    "error_count": 1,
                    "findings": [finding],
                }
            )
        }
    )

    result = analyze_operational_five_quantity(imported)

    event = next(
        event
        for event in result.events
        if event.event_code == "closed_calendar_rows_missing"
    )
    assert event.attention_level is AttentionLevel.PRIORITY_CHECK
    assert event.period_start == missing_date
    assert event.period_end == missing_date
    assert event.facts[0].observed == "missing"
    assert result.coverage.missing_closed_calendar_day_count == 1
    assert result.coverage.expected_closed_calendar_day_count == 11


def test_xx_file_forms_one_restart_event_not_daily_restart_alarms() -> None:
    result = analyze_operational_five_quantity_file(
        _file_request(XX_WORKBOOK, "M-XX")
    )

    restart = [
        event
        for event in result.events
        if event.event_code == "restart_after_reported_zero_production"
    ]
    assert len(restart) == 1
    assert (restart[0].period_start, restart[0].period_end) == (
        date(2026, 7, 14),
        date(2026, 7, 16),
    )
    assert result.days[-1].operational_state is OperationalState.OPEN_PERIOD
    assert result.days[-1].event_ids == []
    assert result.overall.status is OverallStatus.NEEDS_PRIORITY_REVIEW
    assert any(
        event.event_code == "closed_daily_value_missing:electricity"
        and event.period_start == date(2026, 7, 30)
        and event.merged_point_count == 1
        for event in result.events
    )
    assert any(
        event.event_code == "closed_shift_values_missing:electricity"
        and event.attention_level is AttentionLevel.CHECK
        and event.merged_point_count == 30
        for event in result.events
    )


def test_gengyang_file_prioritizes_reconciliation_and_ratio_episode() -> None:
    result = analyze_operational_five_quantity_file(
        _file_request(GENGYANG_WORKBOOK, "M-GENGYANG")
    )

    mismatch = next(
        event
        for event in result.events
        if event.event_code == "shift_total_mismatch:electricity"
        and event.period_start == date(2026, 7, 13)
    )
    assert mismatch.attention_level is AttentionLevel.PRIORITY_CHECK
    assert mismatch.facts[0].difference == pytest.approx(-10_505)

    low_ratio = next(
        event
        for event in result.events
        if event.event_code
        == "within_state_ratio_low:total_electricity_to_production_ratio"
        and event.period_start == date(2026, 7, 12)
    )
    assert low_ratio.period_end == date(2026, 7, 13)
    assert low_ratio.attention_level is AttentionLevel.PRIORITY_CHECK
    assert low_ratio.merged_point_count == 2
    disputed_fact = next(
        fact for fact in low_ratio.facts if fact.date == date(2026, 7, 13)
    )
    assert "三班重算值" in disputed_fact.description
    assert result.overall.priority_event_count == 2
    assert all(
        "regulatory" not in event.event_code for event in result.events
    )


def test_analysis_is_deterministic_for_same_import_digest() -> None:
    imported = _normalized_import([100.0] * 14, closed_count=14)

    first = analyze_operational_five_quantity(imported)
    second = analyze_operational_five_quantity(imported)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_configuration_fingerprint_and_event_ids_bind_effective_parameters() -> None:
    imported = _normalized_import(
        [100.0] * 7 + [130.0] * 7,
        closed_count=14,
    )

    default = analyze_operational_five_quantity(imported)
    changed = analyze_operational_five_quantity(
        imported,
        OperationalFiveQuantityParameters(robust_z_threshold=4.0),
    )

    assert default.configuration.sha256 != changed.configuration.sha256
    assert default.configuration.analysis_parameters.robust_z_threshold == 3.5
    assert changed.configuration.analysis_parameters.robust_z_threshold == 4.0
    assert [event.event_code for event in default.events] == [
        event.event_code for event in changed.events
    ]
    assert [event.event_id for event in default.events] != [
        event.event_id for event in changed.events
    ]
