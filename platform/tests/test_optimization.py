from __future__ import annotations

import json
from pathlib import Path

import pytest

from mineguard.models import (
    BalanceParameters,
    MetricCode,
    MetricObservation,
    ProductionAnalysisRequest,
)
from mineguard.optimization import analyze_production


ROOT = Path(__file__).resolve().parents[1]


def load_request(name: str) -> ProductionAnalysisRequest:
    payload = json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))
    return ProductionAnalysisRequest.model_validate(payload)


def test_inconsistent_sources_return_mcs_and_production_profile() -> None:
    result = analyze_production(
        load_request("production_inconsistent.json")
    )

    assert result.status == "inconsistent"
    assert result.solver_status == (
        "coordination_optimal;strict_infeasible"
    )
    assert result.mcs_alternatives
    assert result.mcs_alternatives[0].relaxed_source_groups == [
        "production_report"
    ]
    assert result.mcs_alternatives[0].total_reliability_cost == 0.6
    assert result.mcs_alternatives[0].minimum_priority is True
    assert result.mcs_alternatives[0].production_range_bounded is True
    assert result.mcs_alternatives[0].reasonable_production_range == (
        pytest.approx((6993.5, 7206.5))
    )
    assert result.mcs_alternatives[0].minimum_reported_gap == pytest.approx(
        1993.5
    )
    assert (
        result.mcs_alternatives[0].supports_positive_reported_gap is True
    )
    assert result.reasonable_production_range == pytest.approx(
        (6993.5, 7206.5)
    )
    assert result.scenario_union_production_range == pytest.approx(
        (6993.5, 7206.5)
    )
    assert result.minimum_reported_gap == pytest.approx(1993.5)
    assert result.robust_minimum_reported_gap == pytest.approx(1993.5)
    assert result.robust_minimum_reported_gap_ratio == pytest.approx(
        1993.5 / 5000
    )
    assert result.unreported_output_upper == pytest.approx(2206.5)
    assert result.priority_scenario_count == 1
    assert result.all_priority_scenarios_support_positive_gap is True
    assert result.scenario_conclusion_divergent is False
    assert "production_report" not in result.supporting_source_groups
    assert result.independent_evidence_cluster_count == 4
    assert result.evidence_grade == "A"
    assert result.diagnostics_complete is True
    assert result.mcs_search_complete is True
    assert result.priority_scenario_count_complete is True
    assert result.mcs_examined_combination_count > 0
    assert result.recommended_checks


def test_unverified_device_or_clock_quality_cannot_receive_grade_a() -> None:
    request = load_request("production_inconsistent.json")
    first = request.observations[0]
    request.observations[0] = first.model_copy(
        update={
            "quality": first.quality.model_copy(
                update={
                    "unverified_dimensions": [
                        "device_health",
                        "clock",
                    ]
                }
            )
        }
    )

    result = analyze_production(request)

    assert result.status == "inconsistent"
    assert result.evidence_grade != "A"
    assert result.data_quality.unverified_dimensions == [
        f"{first.observation_id}:clock",
        f"{first.observation_id}:device_health",
    ]


def test_consistent_sources_need_no_mcs() -> None:
    result = analyze_production(
        load_request("production_consistent.json")
    )

    assert result.status == "consistent"
    assert result.mcs_alternatives == []
    assert result.minimum_reported_gap == 0
    assert result.reasonable_production_range is not None
    assert (
        result.reasonable_production_range[0]
        <= 7050
        <= result.reasonable_production_range[1]
    )


def test_missing_raw_sales_is_not_silently_treated_as_zero() -> None:
    request = load_request("production_consistent.json")
    request.observations = [
        observation
        for observation in request.observations
        if observation.metric_code != MetricCode.RAW_SALES
    ]

    result = analyze_production(request)

    assert result.status == "inconclusive"
    assert result.solver_status == "not_run_data_quality_blocked"
    assert any(
        MetricCode.RAW_SALES.value in reason
        for reason in result.data_quality.blocking_reasons
    )
    assert result.reconciled_metrics == {}


def test_inventory_decrease_is_a_signed_balance_variable() -> None:
    request = ProductionAnalysisRequest(
        mine_id="M-stock-down",
        window_start="2026-07-20T00:00:00Z",
        window_end="2026-07-21T00:00:00Z",
        observations=[
            MetricObservation(
                observation_id="p",
                metric_code=MetricCode.REPORTED_PRODUCTION,
                value=1000,
                tolerance_abs=10,
                source_group="report",
            ),
            MetricObservation(
                observation_id="t",
                metric_code=MetricCode.MAIN_TRANSPORT,
                value=1000,
                tolerance_abs=10,
                source_group="belt",
            ),
            MetricObservation(
                observation_id="w",
                metric_code=MetricCode.WASH_FEED,
                value=1100,
                tolerance_abs=10,
                source_group="wash",
            ),
            MetricObservation(
                observation_id="s",
                metric_code=MetricCode.RAW_SALES,
                value=100,
                tolerance_abs=10,
                source_group="sales",
            ),
            MetricObservation(
                observation_id="i",
                metric_code=MetricCode.RAW_INVENTORY_CHANGE,
                value=-200,
                tolerance_abs=10,
                source_group="inventory",
            ),
        ],
    )

    result = analyze_production(request)

    assert result.status == "consistent"
    inventory = result.reconciled_metrics[
        MetricCode.RAW_INVENTORY_CHANGE.value
    ]
    assert inventory.inferred_value == pytest.approx(-200)


def test_empirical_p_value_uses_conformal_plus_one_correction() -> None:
    request = load_request("production_inconsistent.json")
    request.calibration_scores = [0.0, 1.0, 100.0]

    result = analyze_production(request)

    assert result.raw_anomaly_statistic is not None
    assert result.empirical_p_value == pytest.approx(0.5)
    assert result.consistency_score == pytest.approx(50.0)
    assert result.calibration_sample_count == 3
    assert result.calibration_method == "empirical_conformal_plus_one"


def test_max_relaxed_groups_can_disable_mcs_without_hiding_conflict() -> None:
    request = load_request("production_inconsistent.json")
    request.parameters = BalanceParameters(max_relaxed_groups=0)

    result = analyze_production(request)

    assert result.status == "inconsistent"
    assert result.mcs_alternatives == []
    assert "mcs_not_found_within_limit" in result.solver_status
    assert result.reasonable_production_range is None
    assert result.minimum_reported_gap is None
    assert result.evidence_grade == "D"
    assert result.diagnostics_complete is False


def test_mcs_search_budget_exhaustion_never_produces_a_robust_claim() -> None:
    request = load_request("production_inconsistent.json")
    request.parameters = BalanceParameters(
        max_relaxed_groups=3,
        max_mcs_search_combinations=1,
    )

    result = analyze_production(request)

    assert result.status == "inconsistent"
    assert result.evidence_grade == "D"
    assert result.diagnostics_complete is False
    assert result.mcs_search_complete is False
    assert result.priority_scenario_count_complete is False
    assert result.mcs_examined_combination_count == 1
    assert result.robust_minimum_reported_gap is None
    assert result.scenario_union_production_range is None
    assert "mcs_search_budget_exhausted" in result.solver_status
    assert result.all_priority_scenarios_support_positive_gap is False


def test_each_minimum_mcs_is_profiled_and_divergence_is_conservative() -> None:
    request = ProductionAnalysisRequest(
        mine_id="M-divergent",
        window_start="2026-07-20T00:00:00Z",
        window_end="2026-07-21T00:00:00Z",
        observations=[
            MetricObservation(
                observation_id="p",
                metric_code=MetricCode.REPORTED_PRODUCTION,
                value=100,
                tolerance_abs=1,
                source_group="report",
            ),
            MetricObservation(
                observation_id="t",
                metric_code=MetricCode.MAIN_TRANSPORT,
                value=200,
                tolerance_abs=1,
                source_group="flow",
            ),
            MetricObservation(
                observation_id="w",
                metric_code=MetricCode.WASH_FEED,
                value=200,
                tolerance_abs=1,
                source_group="flow",
            ),
            MetricObservation(
                observation_id="s",
                metric_code=MetricCode.RAW_SALES,
                value=0,
                tolerance_abs=1,
                source_group="sales",
            ),
            MetricObservation(
                observation_id="i",
                metric_code=MetricCode.RAW_INVENTORY_CHANGE,
                value=0,
                tolerance_abs=1,
                source_group="flow",
            ),
        ],
        parameters=BalanceParameters(max_mcs=1),
    )

    result = analyze_production(request)

    assert result.status == "inconsistent"
    assert result.priority_scenario_count == 2
    assert len(result.mcs_alternatives) == 2
    alternatives = {
        tuple(alternative.relaxed_source_groups): alternative
        for alternative in result.mcs_alternatives
        if alternative.minimum_priority
    }
    assert set(alternatives) == {("flow",), ("report",)}
    assert alternatives[("flow",)].reasonable_production_range == (
        pytest.approx((99, 101))
    )
    assert alternatives[("flow",)].minimum_reported_gap == 0
    assert (
        alternatives[("flow",)].supports_positive_reported_gap is False
    )
    assert alternatives[("report",)].reasonable_production_range == (
        pytest.approx((199, 201))
    )
    assert alternatives[("report",)].minimum_reported_gap == 99
    assert (
        alternatives[("report",)].supports_positive_reported_gap is True
    )
    assert result.scenario_union_production_range == pytest.approx((99, 201))
    assert result.robust_minimum_reported_gap == 0
    assert result.scenario_conclusion_divergent is True
    assert result.all_priority_scenarios_support_positive_gap is False


def test_unbounded_priority_mcs_forces_grade_d_and_no_gap() -> None:
    def observation(
        observation_id: str,
        metric_code: MetricCode,
        value: float,
        source_group: str,
    ) -> MetricObservation:
        return MetricObservation(
            observation_id=observation_id,
            metric_code=metric_code,
            value=value,
            tolerance_abs=1,
            source_group=source_group,
        )

    request = ProductionAnalysisRequest(
        mine_id="M-unbounded",
        window_start="2026-07-20T00:00:00Z",
        window_end="2026-07-21T00:00:00Z",
        observations=[
            observation("p1", MetricCode.REPORTED_PRODUCTION, 100, "p"),
            observation("p2", MetricCode.REPORTED_PRODUCTION, 200, "p"),
            observation("t1", MetricCode.MAIN_TRANSPORT, 100, "t"),
            observation("t2", MetricCode.MAIN_TRANSPORT, 200, "t"),
            observation("w1", MetricCode.WASH_FEED, 100, "w"),
            observation("w2", MetricCode.WASH_FEED, 200, "w"),
            observation("s", MetricCode.RAW_SALES, 0, "s"),
            observation(
                "i",
                MetricCode.RAW_INVENTORY_CHANGE,
                0,
                "i",
            ),
        ],
        parameters=BalanceParameters(max_relaxed_groups=3),
    )

    result = analyze_production(request)

    assert result.status == "inconsistent"
    assert result.priority_scenario_count == 1
    assert result.mcs_alternatives[0].relaxed_source_groups == [
        "p",
        "t",
        "w",
    ]
    assert result.mcs_alternatives[0].production_range_bounded is False
    assert result.mcs_alternatives[0].reasonable_production_range is None
    assert result.reasonable_production_range is None
    assert result.minimum_reported_gap is None
    assert result.robust_minimum_reported_gap is None
    assert result.evidence_grade == "D"
    assert "priority_range_unbounded" in result.solver_status


def test_dependency_domains_deduplicate_independent_evidence() -> None:
    request = load_request("production_inconsistent.json")
    for observation in request.observations:
        if observation.source_group != "production_report":
            observation.dependency_domains = ["shared_operations_database"]

    result = analyze_production(request)

    assert result.status == "inconsistent"
    assert result.independent_evidence_clusters == [
        [
            "main_belt",
            "sales_ledger",
            "stock_survey",
            "wash_meter",
        ]
    ]
    assert result.independent_evidence_cluster_count == 1
    assert result.mcs_alternatives[0].independent_evidence_cluster_count == 1
    assert result.evidence_grade == "C"


def test_undeclared_lineage_is_not_treated_as_independent_evidence() -> None:
    request = load_request("production_inconsistent.json")
    for observation in request.observations:
        observation.dependency_domains = []

    result = analyze_production(request)

    assert result.status == "inconsistent"
    assert result.independent_evidence_clusters == [
        [
            "main_belt",
            "sales_ledger",
            "stock_survey",
            "wash_meter",
        ]
    ]
    assert result.independent_evidence_cluster_count == 1
    assert result.evidence_grade == "C"


def test_dynamic_tolerance_combines_absolute_relative_and_resolution() -> None:
    request = load_request("production_inconsistent.json")
    report = request.observations[0]
    payload = report.model_dump()
    payload["tolerance_relative"] = 0.4
    payload["measurement_resolution"] = 20
    payload.pop("tolerance_rel")
    payload.pop("resolution")
    request.observations[0] = MetricObservation.model_validate(payload)

    result = analyze_production(request)

    assert request.observations[0].tolerance_rel == pytest.approx(0.4)
    assert request.observations[0].tolerance_relative == pytest.approx(0.4)
    assert request.observations[0].resolution == pytest.approx(20)
    adjustment = result.observation_adjustments[
        "production-report-20260720"
    ]
    assert adjustment.effective_tolerance == pytest.approx(
        100 + 5000 * 0.4 + 20 / 2
    )
    assert result.status == "consistent"


def test_observation_repairs_and_business_slacks_are_explained() -> None:
    request = load_request("production_inconsistent.json")
    result = analyze_production(request)

    report_adjustment = result.observation_adjustments[
        "production-report-20260720"
    ]
    assert report_adjustment.signed_adjustment == pytest.approx(2050)
    assert report_adjustment.absolute_adjustment == pytest.approx(2050)
    assert report_adjustment.normalized_residual == pytest.approx(20.5)
    production_metric = result.reconciled_metrics[
        MetricCode.REPORTED_PRODUCTION.value
    ]
    assert production_metric.observation_adjustments == [report_adjustment]
    assert result.business_balance_slacks[
        "production_transport"
    ].absolute_slack == 0

    request.parameters.transport_slack_penalty = 0.00001
    request.parameters.stock_slack_penalty = 0.00001
    slack_result = analyze_production(request)
    assert slack_result.business_balance_slacks[
        "production_transport"
    ].absolute_slack == pytest.approx(2100)
    assert slack_result.business_balance_slacks[
        "stock_flow"
    ].absolute_slack == pytest.approx(2050)
    assert any(
        "至少修复 2100.000 吨" in explanation
        for explanation in slack_result.minimum_repair_explanations
    )
