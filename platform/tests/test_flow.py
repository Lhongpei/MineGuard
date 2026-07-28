from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from scipy.optimize import OptimizeResult

import mineguard.flow as flow_module
from mineguard.flow import (
    FlowAnalysisRequest,
    FlowObservation,
    FlowParameters,
    InitialInTransit,
    InventoryObservation,
    InventoryState,
    MeasurementError,
    NodeKind,
    ObservationPoint,
    PhysicalEdge,
    PhysicalNode,
    TimeWindow,
    analyze_material_flow,
)


UTC = timezone.utc
START = datetime(2026, 7, 20, tzinfo=UTC)
ERROR = MeasurementError(
    absolute=10.0,
    relative=0.0,
    resolution=0.0,
)


def windows(count: int = 2) -> list[TimeWindow]:
    return [
        TimeWindow(
            window_id=f"w{index}",
            start=START + timedelta(days=index),
            end=START + timedelta(days=index + 1),
        )
        for index in range(count)
    ]


def observation(
    observation_id: str,
    edge_id: str,
    window_id: str,
    value: float,
    *,
    source_id: str | None = None,
    point: ObservationPoint = ObservationPoint.DISPATCH,
    reliability: float = 1.0,
    quality: float = 1.0,
) -> FlowObservation:
    return FlowObservation(
        observation_id=observation_id,
        source_id=source_id or observation_id,
        edge_id=edge_id,
        window_id=window_id,
        point=point,
        value=value,
        error=ERROR,
        reliability=reliability,
        quality=quality,
    )


def storage_request(
    *,
    flow_observations: list[FlowObservation],
    initial: float = 0.0,
    terminal: float = 0.0,
    delay: int = 0,
    allow_slack: bool = False,
    inventory_observations: list[InventoryObservation] | None = None,
) -> FlowAnalysisRequest:
    request_windows = windows()
    return FlowAnalysisRequest(
        request_id="flow-test",
        mine_id="M-01",
        windows=request_windows,
        nodes=[
            PhysicalNode(
                node_id="mine",
                name="采煤源",
                kind=NodeKind.SOURCE,
            ),
            PhysicalNode(
                node_id="stock",
                name="原煤仓",
                kind=NodeKind.STORAGE,
            ),
            PhysicalNode(
                node_id="buyer",
                name="销售端",
                kind=NodeKind.SINK,
            ),
        ],
        edges=[
            PhysicalEdge(
                edge_id="production",
                name="入仓",
                from_node_id="mine",
                to_node_id="stock",
            ),
            PhysicalEdge(
                edge_id="sales",
                name="销售",
                from_node_id="stock",
                to_node_id="buyer",
                delay_windows_min=delay,
                delay_windows_max=delay,
            ),
        ],
        inventory_states=[
            InventoryState(
                node_id="stock",
                maximum=1000.0,
                initial_lower=initial,
                initial_upper=initial,
                terminal_lower=terminal,
                terminal_upper=terminal,
            )
        ],
        initial_in_transit=[
            InitialInTransit(
                edge_id="sales",
                arrival_window_id=request_windows[period].window_id,
                received_lower=0.0,
                received_upper=0.0,
            )
            for period in range(min(delay, len(request_windows)))
        ],
        flow_observations=flow_observations,
        inventory_observations=inventory_observations or [],
        parameters=FlowParameters(
            allow_business_slack=allow_slack,
            minimum_observation_quality=0.5,
        ),
    )


def edge_value(
    result: flow_module.FlowAnalysisResult,
    edge_id: str,
    window_id: str,
) -> flow_module.EdgeWindowReconciliation:
    return next(
        item
        for item in result.edge_windows
        if item.edge_id == edge_id and item.window_id == window_id
    )


def test_normal_flow_reconciles_without_repairs_and_is_deterministic() -> None:
    request = storage_request(
        flow_observations=[
            observation("p0", "production", "w0", 100.0),
            observation("p1", "production", "w1", 50.0),
            observation("s0", "sales", "w0", 40.0),
            observation("s1", "sales", "w1", 110.0),
        ]
    )

    first = analyze_material_flow(request)
    second = analyze_material_flow(request)

    assert first.status == "optimal"
    assert first.feasible is True
    assert first.objective_value == pytest.approx(0.0)
    assert first.minimum_repairs == []
    assert [item.value for item in first.inventory_trajectory] == (
        pytest.approx([0.0, 60.0, 0.0])
    )
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_cross_period_sales_delay_and_inventory_continuity() -> None:
    request = storage_request(
        delay=1,
        flow_observations=[
            observation("p0", "production", "w0", 100.0),
            observation("p1", "production", "w1", 0.0),
            observation("s0", "sales", "w0", 40.0),
            observation("s1", "sales", "w1", 60.0),
            observation(
                "arrival-w1",
                "sales",
                "w1",
                40.0,
                point=ObservationPoint.ARRIVAL,
            ),
        ],
    )

    result = analyze_material_flow(request)

    assert result.status == "optimal"
    assert result.objective_value == pytest.approx(0.0)
    assert [item.value for item in result.inventory_trajectory] == (
        pytest.approx([0.0, 60.0, 0.0])
    )
    sales_w0 = edge_value(result, "sales", "w0")
    sales_w1 = edge_value(result, "sales", "w1")
    assert sales_w0.arrived_value == pytest.approx(0.0)
    assert sales_w1.arrived_value == pytest.approx(40.0)
    assert sales_w0.allocations[0].arrival_window_id == "w1"
    assert sales_w1.allocations[0].arrival_window_id is None
    assert sales_w1.terminal_in_transit_identified is True
    assert sales_w1.terminal_in_transit_value == pytest.approx(60.0)


def test_inventory_absorbs_difference_across_windows() -> None:
    request = storage_request(
        terminal=40.0,
        flow_observations=[
            observation("p0", "production", "w0", 100.0),
            observation("p1", "production", "w1", 50.0),
            observation("s0", "sales", "w0", 40.0),
            observation("s1", "sales", "w1", 70.0),
        ],
    )

    result = analyze_material_flow(request)

    assert result.status == "optimal"
    assert result.objective_value == pytest.approx(0.0)
    assert [item.value for item in result.inventory_trajectory] == (
        pytest.approx([0.0, 60.0, 40.0])
    )


def test_anomalous_observation_returns_signed_source_adjustment() -> None:
    request = storage_request(
        flow_observations=[
            observation("p0", "production", "w0", 100.0),
            observation("p1", "production", "w1", 0.0),
            observation(
                "s0",
                "sales",
                "w0",
                130.0,
                source_id="sales-system",
                reliability=0.5,
            ),
            observation("s1", "sales", "w1", 0.0),
        ]
    )

    result = analyze_material_flow(request)

    assert result.status == "optimal"
    adjustment = next(
        item
        for item in result.observation_adjustments
        if item.observation_id == "s0"
    )
    assert adjustment.coordinated_value == pytest.approx(100.0)
    assert adjustment.signed_adjustment == pytest.approx(-30.0)
    assert adjustment.normalized_residual == pytest.approx(-3.0)
    source = next(
        item
        for item in result.source_adjustments
        if item.source_id == "sales-system"
    )
    assert source.signed_adjustment == pytest.approx(-30.0)
    assert result.minimum_repairs[0].target_id == "s0"


def test_missing_flow_is_inferred_from_balance_not_replaced_with_zero() -> None:
    request = storage_request(
        flow_observations=[
            observation("p0", "production", "w0", 100.0),
            # production w1 intentionally absent
            observation("s0", "sales", "w0", 40.0),
            observation("s1", "sales", "w1", 80.0),
        ]
    )

    result = analyze_material_flow(request)

    assert result.status == "optimal"
    inferred = edge_value(result, "production", "w1")
    assert inferred.dispatch_observed is False
    assert inferred.dispatch_identified is True
    assert inferred.dispatched_value == pytest.approx(20.0)
    assert inferred.dispatched_lower_bound == pytest.approx(20.0)
    assert inferred.dispatched_upper_bound == pytest.approx(20.0)
    assert all(
        item.observation_id != "production-w1"
        for item in result.observation_adjustments
    )


def test_hard_inventory_boundary_can_be_infeasible() -> None:
    request = FlowAnalysisRequest(
        request_id="infeasible",
        mine_id="M-02",
        windows=windows(1),
        nodes=[
            PhysicalNode(
                node_id="stock",
                name="孤立库存",
                kind=NodeKind.STORAGE,
            )
        ],
        edges=[],
        inventory_states=[
            InventoryState(
                node_id="stock",
                maximum=20.0,
                initial_lower=0.0,
                initial_upper=0.0,
                terminal_lower=10.0,
                terminal_upper=10.0,
            )
        ],
        inventory_observations=[
            InventoryObservation(
                observation_id="stock-start",
                source_id="inventory-system",
                node_id="stock",
                window_id="w0",
                boundary="start",
                value=0.0,
                error=ERROR,
            )
        ],
        parameters=FlowParameters(allow_business_slack=False),
    )

    result = analyze_material_flow(request)

    assert result.status == "infeasible"
    assert result.feasible is False
    assert result.solver_status == "highs_infeasible"
    assert result.minimum_repairs[0].kind == "hard_constraint_review"


def test_quality_gate_blocks_low_quality_observation() -> None:
    request = storage_request(
        flow_observations=[
            observation(
                "p0",
                "production",
                "w0",
                100.0,
                quality=0.2,
            )
        ]
    )

    result = analyze_material_flow(request)

    assert result.status == "quality_insufficient"
    assert result.feasible is None
    assert result.solver_status == "not_run_quality_gate"
    assert "low_quality_observations:p0" in result.quality_reasons


def test_solver_unbounded_status_is_exposed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = storage_request(
        flow_observations=[
            observation("p0", "production", "w0", 100.0),
        ],
        allow_slack=True,
    )

    def unbounded(*args: object, **kwargs: object) -> OptimizeResult:
        return OptimizeResult(status=3, message="unbounded")

    monkeypatch.setattr(flow_module, "linprog", unbounded)
    result = analyze_material_flow(request)

    assert result.status == "unbounded"
    assert result.feasible is True
    assert result.solver_status == "highs_unbounded"


def test_independent_unobserved_edge_is_reported_as_underdetermined() -> None:
    request = FlowAnalysisRequest(
        request_id="independent-edge",
        mine_id="M-03",
        windows=windows(1),
        nodes=[
            PhysicalNode(
                node_id="source-a",
                name="来源甲",
                kind=NodeKind.SOURCE,
            ),
            PhysicalNode(
                node_id="sink-a",
                name="去向甲",
                kind=NodeKind.SINK,
            ),
            PhysicalNode(
                node_id="source-b",
                name="来源乙",
                kind=NodeKind.SOURCE,
            ),
            PhysicalNode(
                node_id="sink-b",
                name="去向乙",
                kind=NodeKind.SINK,
            ),
        ],
        edges=[
            PhysicalEdge(
                edge_id="observed",
                name="已观测边",
                from_node_id="source-a",
                to_node_id="sink-a",
            ),
            PhysicalEdge(
                edge_id="unobserved",
                name="独立缺测边",
                from_node_id="source-b",
                to_node_id="sink-b",
            ),
        ],
        flow_observations=[
            observation("observed-w0", "observed", "w0", 100.0)
        ],
    )

    result = analyze_material_flow(request)

    assert result.status == "underdetermined"
    assert result.feasible is True
    assert result.identification_complete is False
    missing = edge_value(result, "unobserved", "w0")
    assert missing.dispatch_identified is False
    assert missing.dispatched_value is None
    assert missing.dispatched_lower_bound == pytest.approx(0.0)
    assert missing.dispatched_upper_bound is None
    assert result.unidentified_quantity_count >= 3
    assert any(
        item.kind == "data_gap"
        and item.target_id == "unobserved:dispatch"
        for item in result.minimum_repairs
    )


def test_first_window_arrival_requires_explicit_initial_in_transit() -> None:
    common = {
        "request_id": "initial-transit",
        "mine_id": "M-04",
        "windows": windows(1),
        "nodes": [
            PhysicalNode(
                node_id="source",
                name="发出端",
                kind=NodeKind.SOURCE,
            ),
            PhysicalNode(
                node_id="sink",
                name="接收端",
                kind=NodeKind.SINK,
            ),
        ],
        "edges": [
            PhysicalEdge(
                edge_id="delayed",
                name="跨期运输",
                from_node_id="source",
                to_node_id="sink",
                delay_windows_min=1,
                delay_windows_max=1,
            )
        ],
        "flow_observations": [
            observation("dispatch-w0", "delayed", "w0", 0.0),
            observation(
                "arrival-w0",
                "delayed",
                "w0",
                100.0,
                point=ObservationPoint.ARRIVAL,
            ),
        ],
    }
    with pytest.raises(ValueError, match="initial_in_transit"):
        FlowAnalysisRequest(**common)

    request = FlowAnalysisRequest(
        **common,
        initial_in_transit=[
            InitialInTransit(
                edge_id="delayed",
                arrival_window_id="w0",
                received_lower=100.0,
                received_upper=100.0,
            )
        ],
    )

    result = analyze_material_flow(request)

    assert result.status == "optimal"
    edge = edge_value(result, "delayed", "w0")
    assert edge.arrived_identified is True
    assert edge.arrived_value == pytest.approx(100.0)
    assert edge.initial_in_transit_identified is True
    assert edge.initial_in_transit_value == pytest.approx(100.0)
    assert edge.terminal_in_transit_identified is True
    assert edge.terminal_in_transit_value == pytest.approx(0.0)


def test_flow_problem_complexity_budget_is_enforced() -> None:
    many_edges = [
        PhysicalEdge(
            edge_id=f"edge-{index}",
            name=f"边 {index}",
            from_node_id="source",
            to_node_id="sink",
        )
        for index in range(130)
    ]

    with pytest.raises(ValueError, match="complexity budget"):
        FlowAnalysisRequest(
            request_id="too-many-profile-targets",
            mine_id="M-05",
            windows=windows(1),
            nodes=[
                PhysicalNode(
                    node_id="source",
                    name="来源",
                    kind=NodeKind.SOURCE,
                ),
                PhysicalNode(
                    node_id="sink",
                    name="去向",
                    kind=NodeKind.SINK,
                ),
            ],
            edges=many_edges,
            parameters=FlowParameters(
                minimum_usable_observations=0,
            ),
        )


def test_input_quantity_upper_bound_is_enforced() -> None:
    with pytest.raises(ValueError, match="less than or equal"):
        observation(
            "oversized",
            "edge",
            "w0",
            1_000_000_001.0,
        )


def test_large_bounded_interval_is_not_misreported_as_identified() -> None:
    request = FlowAnalysisRequest(
        request_id="large-interval",
        mine_id="M-06",
        windows=windows(1),
        nodes=[
            PhysicalNode(
                node_id="source",
                name="来源",
                kind=NodeKind.SOURCE,
            ),
            PhysicalNode(
                node_id="sink",
                name="去向",
                kind=NodeKind.SINK,
            ),
        ],
        edges=[
            PhysicalEdge(
                edge_id="bounded",
                name="大数量区间边",
                from_node_id="source",
                to_node_id="sink",
                minimum_dispatch=999_999_950.0,
                maximum_dispatch=1_000_000_000.0,
            )
        ],
        parameters=FlowParameters(
            allow_business_slack=False,
            minimum_usable_observations=0,
        ),
    )

    result = analyze_material_flow(request)

    assert result.status == "underdetermined"
    assert result.identification_complete is False
    edge = edge_value(result, "bounded", "w0")
    assert edge.dispatch_identified is False
    assert edge.dispatched_value is None
    assert edge.dispatched_lower_bound == pytest.approx(999_999_950.0)
    assert edge.dispatched_upper_bound == pytest.approx(1_000_000_000.0)
