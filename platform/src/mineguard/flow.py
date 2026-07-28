"""可配置的时间展开物料流协调模型。

本模块把矿井的物理流程展开到连续时间窗口中，并用加权 L1 线性规划
协调流量、库存和业务平衡。它有几个有意保留的性质：

* 缺失观测不会生成数值为零的伪观测；
* 有时延的边分别建模发出量和到达量，库存按窗口连续；
* 边损耗使用线性上下界，而不是把不确定损耗固定成一个点估计；
* 所有观测调整和业务松弛都可追溯到来源、窗口和物理对象；
* 结果是确定性的技术协调结果，不是违法事实认定。

``MeasurementError`` 的有效误差定义为
``absolute + relative * abs(value) + resolution / 2``。观测目标函数为
``reliability * quality * abs(adjustment) / effective_error``。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import math
from typing import Annotated, Literal

import numpy as np
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)
from scipy.optimize import OptimizeResult, linprog


_MAX_QUANTITY = 1_000_000_000.0
_MAX_RELATIVE_ERROR = 10.0
_MAX_PENALTY = 1_000_000.0
_MIN_EFFECTIVE_ERROR = 1e-9
_MAX_WINDOWS = 366
_MAX_NODES = 200
_MAX_EDGES = 400
_MAX_OBSERVATIONS = 10_000
_MAX_INITIAL_TRANSIT = 10_000
_MAX_VARIABLES = 20_000
_MAX_CONSTRAINTS = 30_000
_MAX_DENSE_CELLS = 5_000_000
_MAX_PROFILE_TARGETS = 512
_PROFILE_IDENTIFICATION_ABSOLUTE_TOLERANCE = 1e-6


class FlowModel(BaseModel):
    """Strict base model for the standalone flow API."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        strict=True,
        frozen=True,
    )


class NodeKind(StrEnum):
    SOURCE = "source"
    JUNCTION = "junction"
    PROCESS = "process"
    STORAGE = "storage"
    SINK = "sink"


class ObservationPoint(StrEnum):
    DISPATCH = "dispatch"
    ARRIVAL = "arrival"


class TimeWindow(FlowModel):
    window_id: Annotated[str, Field(min_length=1)]
    start: AwareDatetime
    end: AwareDatetime

    @model_validator(mode="after")
    def validate_interval(self) -> "TimeWindow":
        if self.end <= self.start:
            raise ValueError("window end must be later than start")
        return self


class PhysicalNode(FlowModel):
    node_id: Annotated[str, Field(min_length=1)]
    name: Annotated[str, Field(min_length=1)]
    kind: NodeKind


class PhysicalEdge(FlowModel):
    edge_id: Annotated[str, Field(min_length=1)]
    name: Annotated[str, Field(min_length=1)]
    from_node_id: Annotated[str, Field(min_length=1)]
    to_node_id: Annotated[str, Field(min_length=1)]
    loss_rate_min: Annotated[float, Field(ge=0.0, lt=1.0)] = 0.0
    loss_rate_max: Annotated[float, Field(ge=0.0, lt=1.0)] = 0.0
    delay_windows_min: Annotated[int, Field(ge=0, le=365)] = 0
    delay_windows_max: Annotated[int, Field(ge=0, le=365)] = 0
    minimum_dispatch: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] = 0.0
    maximum_dispatch: Annotated[
        float,
        Field(gt=0.0, le=_MAX_QUANTITY),
    ] | None = None

    @model_validator(mode="after")
    def validate_ranges(self) -> "PhysicalEdge":
        if self.from_node_id == self.to_node_id:
            raise ValueError("physical edge cannot be a self-loop")
        if self.loss_rate_max < self.loss_rate_min:
            raise ValueError("loss_rate_max must be >= loss_rate_min")
        if self.delay_windows_max < self.delay_windows_min:
            raise ValueError(
                "delay_windows_max must be >= delay_windows_min"
            )
        if (
            self.maximum_dispatch is not None
            and self.maximum_dispatch < self.minimum_dispatch
        ):
            raise ValueError(
                "maximum_dispatch must be >= minimum_dispatch"
            )
        return self


class InventoryState(FlowModel):
    """Hard state bounds for one storage node.

    Missing initial or terminal bounds remain unknown. They are not replaced
    with zero. ``minimum`` and ``maximum`` apply at every boundary.
    """

    node_id: Annotated[str, Field(min_length=1)]
    minimum: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] = 0.0
    maximum: Annotated[
        float,
        Field(gt=0.0, le=_MAX_QUANTITY),
    ] | None = None
    initial_lower: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] | None = None
    initial_upper: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] | None = None
    terminal_lower: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] | None = None
    terminal_upper: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] | None = None

    @model_validator(mode="after")
    def validate_bounds(self) -> "InventoryState":
        pairs = (
            ("initial", self.initial_lower, self.initial_upper),
            ("terminal", self.terminal_lower, self.terminal_upper),
        )
        for label, lower, upper in pairs:
            if lower is not None and upper is not None and upper < lower:
                raise ValueError(f"{label}_upper must be >= {label}_lower")
        for label, value in (
            ("initial_lower", self.initial_lower),
            ("initial_upper", self.initial_upper),
            ("terminal_lower", self.terminal_lower),
            ("terminal_upper", self.terminal_upper),
        ):
            if self.maximum is not None and value is not None:
                if value > self.maximum:
                    raise ValueError(f"{label} exceeds inventory maximum")
            if value is not None and value < self.minimum:
                raise ValueError(f"{label} is below inventory minimum")
        return self


class MeasurementError(FlowModel):
    absolute: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] = 0.0
    relative: Annotated[
        float,
        Field(ge=0.0, le=_MAX_RELATIVE_ERROR),
    ] = 0.0
    resolution: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] = 0.0

    @model_validator(mode="after")
    def validate_nonzero_error(self) -> "MeasurementError":
        if (
            self.absolute == 0.0
            and self.relative == 0.0
            and self.resolution == 0.0
        ):
            raise ValueError("at least one measurement error must be positive")
        return self

    def effective(self, value: float) -> float:
        return (
            self.absolute
            + self.relative * abs(value)
            + self.resolution / 2.0
        )


class _Observation(FlowModel):
    observation_id: Annotated[str, Field(min_length=1)]
    source_id: Annotated[str, Field(min_length=1)]
    value: Annotated[float, Field(ge=0.0, le=_MAX_QUANTITY)]
    error: MeasurementError
    reliability: Annotated[float, Field(gt=0.0, le=1.0)] = 1.0
    quality: Annotated[float, Field(gt=0.0, le=1.0)] = 1.0
    trusted: bool = True

    @model_validator(mode="after")
    def validate_effective_error(self) -> "_Observation":
        effective = self.error.effective(self.value)
        if (
            not math.isfinite(effective)
            or effective < _MIN_EFFECTIVE_ERROR
        ):
            raise ValueError(
                "effective measurement error must be finite and at least "
                f"{_MIN_EFFECTIVE_ERROR:g}"
            )
        return self


class FlowObservation(_Observation):
    edge_id: Annotated[str, Field(min_length=1)]
    window_id: Annotated[str, Field(min_length=1)]
    point: ObservationPoint = ObservationPoint.DISPATCH


class InventoryObservation(_Observation):
    node_id: Annotated[str, Field(min_length=1)]
    window_id: Annotated[str, Field(min_length=1)]
    boundary: Literal["start", "end"]


class InitialInTransit(FlowModel):
    """Received material dispatched before the analysis horizon.

    The value is attached to its arrival window because its departure window is
    outside the modeled horizon. Exact known quantities use equal bounds;
    unknown-but-bounded quantities remain intervals and will make the result
    explicitly underdetermined unless other constraints identify them.
    """

    edge_id: Annotated[str, Field(min_length=1)]
    arrival_window_id: Annotated[str, Field(min_length=1)]
    received_lower: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] = 0.0
    received_upper: Annotated[
        float,
        Field(ge=0.0, le=_MAX_QUANTITY),
    ] | None = None

    @model_validator(mode="after")
    def validate_bounds(self) -> "InitialInTransit":
        if (
            self.received_upper is not None
            and self.received_upper < self.received_lower
        ):
            raise ValueError(
                "received_upper must be greater than or equal to "
                "received_lower"
            )
        return self


class FlowParameters(FlowModel):
    business_slack_penalty: Annotated[
        float,
        Field(gt=0.0, le=_MAX_PENALTY),
    ] = 100.0
    allow_business_slack: bool = True
    minimum_observation_quality: Annotated[
        float, Field(gt=0.0, le=1.0)
    ] = 0.5
    minimum_usable_observations: Annotated[int, Field(ge=0)] = 1
    require_observation_each_window: bool = False
    numerical_tolerance: Annotated[
        float, Field(gt=0.0, le=1e-3)
    ] = 1e-8
    solver_time_limit_seconds: Annotated[
        float,
        Field(ge=0.1, le=60.0),
    ] = 5.0


class FlowAnalysisRequest(FlowModel):
    request_id: Annotated[str, Field(min_length=1)]
    mine_id: Annotated[str, Field(min_length=1)]
    unit: Annotated[str, Field(min_length=1)] = "t"
    windows: Annotated[
        list[TimeWindow],
        Field(min_length=1, max_length=_MAX_WINDOWS),
    ]
    nodes: Annotated[
        list[PhysicalNode],
        Field(min_length=1, max_length=_MAX_NODES),
    ]
    edges: Annotated[
        list[PhysicalEdge],
        Field(max_length=_MAX_EDGES),
    ]
    inventory_states: Annotated[
        list[InventoryState],
        Field(max_length=_MAX_NODES),
    ] = Field(default_factory=list)
    initial_in_transit: Annotated[
        list[InitialInTransit],
        Field(max_length=_MAX_INITIAL_TRANSIT),
    ] = Field(default_factory=list)
    flow_observations: Annotated[
        list[FlowObservation],
        Field(max_length=_MAX_OBSERVATIONS),
    ] = Field(default_factory=list)
    inventory_observations: Annotated[
        list[InventoryObservation],
        Field(max_length=_MAX_OBSERVATIONS),
    ] = Field(default_factory=list)
    parameters: FlowParameters = Field(default_factory=FlowParameters)

    @model_validator(mode="after")
    def validate_graph_and_references(self) -> "FlowAnalysisRequest":
        if not self.windows:
            raise ValueError("at least one time window is required")
        if not self.nodes:
            raise ValueError("at least one physical node is required")

        window_ids = [item.window_id for item in self.windows]
        node_ids = [item.node_id for item in self.nodes]
        edge_ids = [item.edge_id for item in self.edges]
        inventory_ids = [item.node_id for item in self.inventory_states]
        observation_ids = [
            item.observation_id
            for item in (
                *self.flow_observations,
                *self.inventory_observations,
            )
        ]
        initial_transit_keys = [
            (item.edge_id, item.arrival_window_id)
            for item in self.initial_in_transit
        ]
        for label, values in (
            ("window_id", window_ids),
            ("node_id", node_ids),
            ("edge_id", edge_ids),
            ("inventory node_id", inventory_ids),
            ("observation_id", observation_ids),
            ("initial in-transit edge/window", initial_transit_keys),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} values must be unique")

        ordered_windows = sorted(
            self.windows,
            key=lambda item: (item.start, item.end, item.window_id),
        )
        if ordered_windows != self.windows:
            raise ValueError("windows must be in chronological order")
        for previous, current in zip(
            ordered_windows,
            ordered_windows[1:],
            strict=False,
        ):
            if previous.end != current.start:
                raise ValueError("time windows must be contiguous")

        node_by_id = {item.node_id: item for item in self.nodes}
        window_id_set = set(window_ids)
        edge_id_set = set(edge_ids)
        for edge in self.edges:
            if edge.from_node_id not in node_by_id:
                raise ValueError(
                    f"unknown edge from_node_id: {edge.from_node_id}"
                )
            if edge.to_node_id not in node_by_id:
                raise ValueError(
                    f"unknown edge to_node_id: {edge.to_node_id}"
                )
            if node_by_id[edge.from_node_id].kind is NodeKind.SINK:
                raise ValueError("sink nodes cannot have outgoing edges")
            if node_by_id[edge.to_node_id].kind is NodeKind.SOURCE:
                raise ValueError("source nodes cannot have incoming edges")

        inventory_by_node = {
            item.node_id: item for item in self.inventory_states
        }
        storage_ids = {
            item.node_id
            for item in self.nodes
            if item.kind is NodeKind.STORAGE
        }
        if set(inventory_by_node) != storage_ids:
            missing = sorted(storage_ids - set(inventory_by_node))
            extra = sorted(set(inventory_by_node) - storage_ids)
            raise ValueError(
                "inventory_states must match storage nodes exactly; "
                f"missing={missing}, extra={extra}"
            )

        for observation in self.flow_observations:
            if observation.edge_id not in edge_id_set:
                raise ValueError(
                    f"unknown observation edge_id: {observation.edge_id}"
                )
            if observation.window_id not in window_id_set:
                raise ValueError(
                    "unknown observation window_id: "
                    f"{observation.window_id}"
                )
        for observation in self.inventory_observations:
            if observation.node_id not in storage_ids:
                raise ValueError(
                    "inventory observation must reference a storage node: "
                    f"{observation.node_id}"
                )
            if observation.window_id not in window_id_set:
                raise ValueError(
                    "unknown observation window_id: "
                    f"{observation.window_id}"
                )

        provided_initial = set(initial_transit_keys)
        for item in self.initial_in_transit:
            if item.edge_id not in edge_id_set:
                raise ValueError(
                    "unknown initial in-transit edge_id: "
                    f"{item.edge_id}"
                )
            if item.arrival_window_id not in window_id_set:
                raise ValueError(
                    "unknown initial in-transit arrival_window_id: "
                    f"{item.arrival_window_id}"
                )
        required_initial: set[tuple[str, str]] = set()
        for edge in self.edges:
            for period, window in enumerate(self.windows):
                # A delay larger than the current period implies a possible
                # departure before the modeled horizon. Its received material
                # must be declared explicitly, including an exact zero.
                if edge.delay_windows_max > period:
                    required_initial.add((edge.edge_id, window.window_id))
        missing_initial = sorted(required_initial - provided_initial)
        extra_initial = sorted(provided_initial - required_initial)
        if missing_initial:
            raise ValueError(
                "initial_in_transit must explicitly cover every possible "
                "pre-horizon arrival (use equal zero bounds when known empty); "
                f"missing={missing_initial}"
            )
        if extra_initial:
            raise ValueError(
                "initial_in_transit contains edge/window pairs that cannot "
                f"originate before the horizon; extra={extra_initial}"
            )

        window_count = len(self.windows)
        observation_count = len(observation_ids)
        allocation_count = sum(
            window_count
            * (
                edge.delay_windows_max
                - edge.delay_windows_min
                + 1
            )
            for edge in self.edges
        )
        internal_node_count = sum(
            node.kind not in {NodeKind.SOURCE, NodeKind.SINK}
            for node in self.nodes
        )
        storage_count = len(storage_ids)
        capacity_constraint_count = sum(
            window_count
            * (
                int(edge.maximum_dispatch is not None)
                + int(edge.minimum_dispatch > 0.0)
            )
            for edge in self.edges
        )
        variable_count = (
            2 * allocation_count
            + storage_count * (window_count + 1)
            + len(self.initial_in_transit)
            + (
                2 * internal_node_count * window_count
                if self.parameters.allow_business_slack
                else 0
            )
            + 2 * observation_count
        )
        constraint_count = (
            2 * allocation_count
            + capacity_constraint_count
            + internal_node_count * window_count
            + observation_count
        )
        dense_cells = variable_count * constraint_count
        profile_target_count = (
            4 * len(self.edges) * window_count
            + storage_count * (window_count + 1)
            + len(self.initial_in_transit)
        )
        if (
            variable_count > _MAX_VARIABLES
            or constraint_count > _MAX_CONSTRAINTS
            or dense_cells > _MAX_DENSE_CELLS
            or profile_target_count > _MAX_PROFILE_TARGETS
        ):
            raise ValueError(
                "flow problem exceeds complexity budget; split the analysis "
                "window or graph: "
                f"variables={variable_count}/{_MAX_VARIABLES}, "
                f"constraints={constraint_count}/{_MAX_CONSTRAINTS}, "
                f"dense_cells={dense_cells}/{_MAX_DENSE_CELLS}, "
                f"profile_targets={profile_target_count}/"
                f"{_MAX_PROFILE_TARGETS}"
            )
        return self


class DelayAllocation(FlowModel):
    departure_window_id: str
    arrival_window_id: str | None
    delay_windows: int
    dispatched_value: float | None = None
    dispatched_lower_bound: float | None = None
    dispatched_upper_bound: float | None = None
    dispatch_identified: bool = False
    received_value: float | None = None
    received_lower_bound: float | None = None
    received_upper_bound: float | None = None
    received_identified: bool = False


class EdgeWindowReconciliation(FlowModel):
    edge_id: str
    window_id: str
    dispatched_value: float | None = None
    dispatched_lower_bound: float | None = None
    dispatched_upper_bound: float | None = None
    dispatch_identified: bool
    eventual_received_value: float | None = None
    eventual_received_lower_bound: float | None = None
    eventual_received_upper_bound: float | None = None
    eventual_received_identified: bool
    arrived_value: float | None = None
    arrived_lower_bound: float | None = None
    arrived_upper_bound: float | None = None
    arrived_identified: bool
    initial_in_transit_value: float | None = None
    initial_in_transit_lower_bound: float | None = None
    initial_in_transit_upper_bound: float | None = None
    initial_in_transit_identified: bool
    terminal_in_transit_value: float | None = None
    terminal_in_transit_lower_bound: float | None = None
    terminal_in_transit_upper_bound: float | None = None
    terminal_in_transit_identified: bool
    inferred_loss_rate: float | None
    dispatch_observed: bool
    arrival_observed: bool
    allocations: list[DelayAllocation] = Field(default_factory=list)


class InventoryPoint(FlowModel):
    node_id: str
    boundary_index: Annotated[int, Field(ge=0)]
    at: AwareDatetime
    value: float | None = None
    lower_bound: float | None = None
    upper_bound: float | None = None
    identified: bool
    observed: bool


class ObservationAdjustment(FlowModel):
    observation_id: str
    source_id: str
    observation_kind: Literal["flow_dispatch", "flow_arrival", "inventory"]
    target_id: str
    window_id: str
    observed_value: float
    coordinated_value: float
    signed_adjustment: float
    effective_error: Annotated[float, Field(gt=0.0)]
    normalized_residual: float
    objective_contribution: Annotated[float, Field(ge=0.0)]


class SourceAdjustment(FlowModel):
    source_id: str
    observation_count: Annotated[int, Field(ge=1)]
    signed_adjustment: float
    absolute_adjustment: Annotated[float, Field(ge=0.0)]
    signed_normalized_residual: float
    normalized_residual: Annotated[float, Field(ge=0.0)]
    maximum_normalized_residual: Annotated[float, Field(ge=0.0)]


class BusinessSlack(FlowModel):
    node_id: str
    window_id: str
    material_added: Annotated[float, Field(ge=0.0)]
    material_removed: Annotated[float, Field(ge=0.0)]
    signed_slack: float
    objective_contribution: Annotated[float, Field(ge=0.0)]


class MinimumRepair(FlowModel):
    kind: Literal[
        "observation_adjustment",
        "business_slack",
        "hard_constraint_review",
        "quality_review",
        "data_gap",
    ]
    target_id: str
    window_id: str | None = None
    amount: float | None = None
    severity: Annotated[float, Field(ge=0.0)] | None = None
    explanation: str


class FlowAnalysisResult(FlowModel):
    request_id: str
    mine_id: str
    unit: str
    status: Literal[
        "optimal",
        "underdetermined",
        "infeasible",
        "unbounded",
        "quality_insufficient",
        "solver_error",
    ]
    feasible: bool | None
    solver_status: str
    quality_sufficient: bool
    quality_score: Annotated[float, Field(ge=0.0, le=1.0)] | None
    quality_reasons: list[str] = Field(default_factory=list)
    objective_value: float | None = None
    observation_objective: float | None = None
    business_slack_objective: float | None = None
    identification_complete: bool = False
    profiled_quantity_count: Annotated[int, Field(ge=0)] = 0
    unidentified_quantity_count: Annotated[int, Field(ge=0)] = 0
    edge_windows: list[EdgeWindowReconciliation] = Field(
        default_factory=list
    )
    inventory_trajectory: list[InventoryPoint] = Field(
        default_factory=list
    )
    observation_adjustments: list[ObservationAdjustment] = Field(
        default_factory=list
    )
    source_adjustments: list[SourceAdjustment] = Field(
        default_factory=list
    )
    business_slacks: list[BusinessSlack] = Field(default_factory=list)
    minimum_repairs: list[MinimumRepair] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class _ObservationSpec:
    observation_id: str
    source_id: str
    kind: Literal["flow_dispatch", "flow_arrival", "inventory"]
    target_id: str
    window_id: str
    value: float
    effective_error: float
    weight: float
    terms: dict[int, float]


@dataclass(frozen=True)
class _CompiledProblem:
    objective: np.ndarray
    a_ub: np.ndarray | None
    b_ub: np.ndarray | None
    a_eq: np.ndarray | None
    b_eq: np.ndarray | None
    bounds: tuple[tuple[float | None, float | None], ...]
    flow_variables: dict[tuple[str, int, int], tuple[int, int]]
    inventory_variables: dict[tuple[str, int], int]
    initial_transit_variables: dict[tuple[str, int], int]
    residual_variables: dict[str, tuple[int, int]]
    slack_variables: dict[tuple[str, int], tuple[int, int]]
    observation_specs: tuple[_ObservationSpec, ...]


@dataclass(frozen=True)
class _QuantityProfile:
    value: float | None
    lower: float | None
    upper: float | None
    identified: bool


class _ProfileError(RuntimeError):
    """A profile LP failed for a reason other than mathematical unboundedness."""


class _LPBuilder:
    def __init__(self) -> None:
        self.objective: list[float] = []
        self.bounds: list[tuple[float | None, float | None]] = []
        self.eq_rows: list[tuple[dict[int, float], float]] = []
        self.ub_rows: list[tuple[dict[int, float], float]] = []

    def variable(
        self,
        *,
        objective: float = 0.0,
        lower: float | None = 0.0,
        upper: float | None = None,
    ) -> int:
        index = len(self.objective)
        self.objective.append(objective)
        self.bounds.append((lower, upper))
        return index

    def equality(self, terms: dict[int, float], rhs: float) -> None:
        self.eq_rows.append((terms, rhs))

    def upper_bound(self, terms: dict[int, float], rhs: float) -> None:
        self.ub_rows.append((terms, rhs))

    def dense(
        self,
        rows: list[tuple[dict[int, float], float]],
    ) -> tuple[np.ndarray | None, np.ndarray | None]:
        if not rows:
            return None, None
        matrix = np.zeros((len(rows), len(self.objective)), dtype=float)
        rhs = np.empty(len(rows), dtype=float)
        for row_index, (terms, value) in enumerate(rows):
            for variable, coefficient in terms.items():
                matrix[row_index, variable] += coefficient
            rhs[row_index] = value
        return matrix, rhs


def _add_term(terms: dict[int, float], index: int, value: float) -> None:
    terms[index] = terms.get(index, 0.0) + value


def _intersect_bounds(
    lower: float | None,
    upper: float | None,
    special_lower: float | None,
    special_upper: float | None,
) -> tuple[float | None, float | None]:
    if special_lower is not None:
        lower = (
            special_lower
            if lower is None
            else max(lower, special_lower)
        )
    if special_upper is not None:
        upper = (
            special_upper
            if upper is None
            else min(upper, special_upper)
        )
    return lower, upper


def _compile(request: FlowAnalysisRequest) -> _CompiledProblem:
    builder = _LPBuilder()
    windows = request.windows
    window_index = {
        item.window_id: index for index, item in enumerate(windows)
    }
    nodes = sorted(request.nodes, key=lambda item: item.node_id)
    edges = sorted(request.edges, key=lambda item: item.edge_id)
    state_by_node = {
        item.node_id: item for item in request.inventory_states
    }

    flow_variables: dict[tuple[str, int, int], tuple[int, int]] = {}
    for edge in edges:
        for departure in range(len(windows)):
            dispatch_terms: dict[int, float] = {}
            for delay in range(
                edge.delay_windows_min,
                edge.delay_windows_max + 1,
            ):
                sent = builder.variable()
                received = builder.variable()
                flow_variables[(edge.edge_id, departure, delay)] = (
                    sent,
                    received,
                )
                dispatch_terms[sent] = 1.0

                # received <= (1 - loss_min) * sent
                builder.upper_bound(
                    {
                        received: 1.0,
                        sent: -(1.0 - edge.loss_rate_min),
                    },
                    0.0,
                )
                # received >= (1 - loss_max) * sent
                builder.upper_bound(
                    {
                        received: -1.0,
                        sent: 1.0 - edge.loss_rate_max,
                    },
                    0.0,
                )
            if edge.maximum_dispatch is not None:
                builder.upper_bound(
                    dispatch_terms,
                    edge.maximum_dispatch,
                )
            if edge.minimum_dispatch > 0.0:
                builder.upper_bound(
                    {
                        variable: -coefficient
                        for variable, coefficient in dispatch_terms.items()
                    },
                    -edge.minimum_dispatch,
                )

    inventory_variables: dict[tuple[str, int], int] = {}
    for node in nodes:
        if node.kind is not NodeKind.STORAGE:
            continue
        state = state_by_node[node.node_id]
        for boundary in range(len(windows) + 1):
            lower: float | None = state.minimum
            upper = state.maximum
            if boundary == 0:
                lower, upper = _intersect_bounds(
                    lower,
                    upper,
                    state.initial_lower,
                    state.initial_upper,
                )
            if boundary == len(windows):
                lower, upper = _intersect_bounds(
                    lower,
                    upper,
                    state.terminal_lower,
                    state.terminal_upper,
                )
            inventory_variables[(node.node_id, boundary)] = (
                builder.variable(lower=lower, upper=upper)
            )

    initial_transit_variables: dict[tuple[str, int], int] = {}
    for item in sorted(
        request.initial_in_transit,
        key=lambda value: (
            value.edge_id,
            value.arrival_window_id,
        ),
    ):
        period = window_index[item.arrival_window_id]
        initial_transit_variables[(item.edge_id, period)] = (
            builder.variable(
                lower=item.received_lower,
                upper=item.received_upper,
            )
        )

    def dispatch_terms(edge_id: str, period: int) -> dict[int, float]:
        terms: dict[int, float] = {}
        edge = next(item for item in edges if item.edge_id == edge_id)
        for delay in range(
            edge.delay_windows_min,
            edge.delay_windows_max + 1,
        ):
            sent, _ = flow_variables[(edge_id, period, delay)]
            terms[sent] = 1.0
        return terms

    def arrival_terms(edge_id: str, period: int) -> dict[int, float]:
        terms: dict[int, float] = {}
        edge = next(item for item in edges if item.edge_id == edge_id)
        for delay in range(
            edge.delay_windows_min,
            edge.delay_windows_max + 1,
        ):
            departure = period - delay
            if departure < 0:
                continue
            _, received = flow_variables[(edge_id, departure, delay)]
            terms[received] = 1.0
        initial = initial_transit_variables.get((edge_id, period))
        if initial is not None:
            terms[initial] = 1.0
        return terms

    incoming_by_node: dict[str, list[PhysicalEdge]] = {
        node.node_id: [] for node in nodes
    }
    outgoing_by_node: dict[str, list[PhysicalEdge]] = {
        node.node_id: [] for node in nodes
    }
    for edge in edges:
        outgoing_by_node[edge.from_node_id].append(edge)
        incoming_by_node[edge.to_node_id].append(edge)

    slack_variables: dict[tuple[str, int], tuple[int, int]] = {}
    for node in nodes:
        if node.kind in {NodeKind.SOURCE, NodeKind.SINK}:
            continue
        for period in range(len(windows)):
            terms: dict[int, float] = {}
            for edge in incoming_by_node[node.node_id]:
                for variable, coefficient in arrival_terms(
                    edge.edge_id,
                    period,
                ).items():
                    _add_term(terms, variable, coefficient)
            for edge in outgoing_by_node[node.node_id]:
                for variable, coefficient in dispatch_terms(
                    edge.edge_id,
                    period,
                ).items():
                    _add_term(terms, variable, -coefficient)

            if node.kind is NodeKind.STORAGE:
                before = inventory_variables[(node.node_id, period)]
                after = inventory_variables[(node.node_id, period + 1)]
                _add_term(terms, before, 1.0)
                _add_term(terms, after, -1.0)

            if request.parameters.allow_business_slack:
                material_added = builder.variable(
                    objective=request.parameters.business_slack_penalty
                )
                material_removed = builder.variable(
                    objective=request.parameters.business_slack_penalty
                )
                slack_variables[(node.node_id, period)] = (
                    material_added,
                    material_removed,
                )
                _add_term(terms, material_added, 1.0)
                _add_term(terms, material_removed, -1.0)
            builder.equality(terms, 0.0)

    raw_specs: list[
        tuple[
            str,
            str,
            Literal["flow_dispatch", "flow_arrival", "inventory"],
            str,
            str,
            float,
            float,
            float,
            dict[int, float],
        ]
    ] = []
    for observation in sorted(
        request.flow_observations,
        key=lambda item: item.observation_id,
    ):
        period = window_index[observation.window_id]
        if observation.point is ObservationPoint.DISPATCH:
            kind: Literal[
                "flow_dispatch", "flow_arrival", "inventory"
            ] = "flow_dispatch"
            terms = dispatch_terms(observation.edge_id, period)
        else:
            kind = "flow_arrival"
            terms = arrival_terms(observation.edge_id, period)
        effective_error = observation.error.effective(observation.value)
        raw_specs.append(
            (
                observation.observation_id,
                observation.source_id,
                kind,
                observation.edge_id,
                observation.window_id,
                observation.value,
                effective_error,
                observation.reliability * observation.quality
                / effective_error,
                terms,
            )
        )
    for observation in sorted(
        request.inventory_observations,
        key=lambda item: item.observation_id,
    ):
        period = window_index[observation.window_id]
        boundary = period if observation.boundary == "start" else period + 1
        variable = inventory_variables[(observation.node_id, boundary)]
        effective_error = observation.error.effective(observation.value)
        raw_specs.append(
            (
                observation.observation_id,
                observation.source_id,
                "inventory",
                observation.node_id,
                observation.window_id,
                observation.value,
                effective_error,
                observation.reliability * observation.quality
                / effective_error,
                {variable: 1.0},
            )
        )
    raw_specs.sort(key=lambda item: item[0])

    residual_variables: dict[str, tuple[int, int]] = {}
    observation_specs: list[_ObservationSpec] = []
    for (
        observation_id,
        source_id,
        kind,
        target_id,
        window_id,
        value,
        effective_error,
        weight,
        target_terms,
    ) in raw_specs:
        positive = builder.variable(objective=weight)
        negative = builder.variable(objective=weight)
        residual_variables[observation_id] = (positive, negative)
        equation = dict(target_terms)
        _add_term(equation, positive, -1.0)
        _add_term(equation, negative, 1.0)
        builder.equality(equation, value)
        observation_specs.append(
            _ObservationSpec(
                observation_id=observation_id,
                source_id=source_id,
                kind=kind,
                target_id=target_id,
                window_id=window_id,
                value=value,
                effective_error=effective_error,
                weight=weight,
                terms=target_terms,
            )
        )

    a_ub, b_ub = builder.dense(builder.ub_rows)
    a_eq, b_eq = builder.dense(builder.eq_rows)
    return _CompiledProblem(
        objective=np.asarray(builder.objective, dtype=float),
        a_ub=a_ub,
        b_ub=b_ub,
        a_eq=a_eq,
        b_eq=b_eq,
        bounds=tuple(builder.bounds),
        flow_variables=flow_variables,
        inventory_variables=inventory_variables,
        initial_transit_variables=initial_transit_variables,
        residual_variables=residual_variables,
        slack_variables=slack_variables,
        observation_specs=tuple(observation_specs),
    )


def _quality_gate(
    request: FlowAnalysisRequest,
) -> tuple[bool, float | None, list[str]]:
    observations = [
        *request.flow_observations,
        *request.inventory_observations,
    ]
    if not observations:
        score = None
    else:
        score = sum(
            item.quality * item.reliability for item in observations
        ) / len(observations)

    reasons: list[str] = []
    untrusted = sorted(
        item.observation_id for item in observations if not item.trusted
    )
    if untrusted:
        reasons.append("untrusted_observations:" + ",".join(untrusted))
    low_quality = sorted(
        item.observation_id
        for item in observations
        if item.quality < request.parameters.minimum_observation_quality
    )
    if low_quality:
        reasons.append("low_quality_observations:" + ",".join(low_quality))
    usable_count = sum(
        item.trusted
        and item.quality
        >= request.parameters.minimum_observation_quality
        for item in observations
    )
    if usable_count < request.parameters.minimum_usable_observations:
        reasons.append(
            "insufficient_usable_observations:"
            f"{usable_count}<{request.parameters.minimum_usable_observations}"
        )
    if request.parameters.require_observation_each_window:
        observed_windows = {
            item.window_id
            for item in (
                *request.flow_observations,
                *request.inventory_observations,
            )
            if item.trusted
            and item.quality
            >= request.parameters.minimum_observation_quality
        }
        missing_windows = [
            item.window_id
            for item in request.windows
            if item.window_id not in observed_windows
        ]
        if missing_windows:
            reasons.append(
                "windows_without_usable_observation:"
                + ",".join(missing_windows)
            )
    return not reasons, score, reasons


def _clean(value: float, tolerance: float) -> float:
    if abs(value) <= tolerance:
        return 0.0
    return float(value)


def _base_result(
    request: FlowAnalysisRequest,
    *,
    status: Literal[
        "infeasible",
        "unbounded",
        "quality_insufficient",
        "solver_error",
    ],
    feasible: bool | None,
    solver_status: str,
    quality_sufficient: bool,
    quality_score: float | None,
    quality_reasons: list[str],
    repair: MinimumRepair,
) -> FlowAnalysisResult:
    return FlowAnalysisResult(
        request_id=request.request_id,
        mine_id=request.mine_id,
        unit=request.unit,
        status=status,
        feasible=feasible,
        solver_status=solver_status,
        quality_sufficient=quality_sufficient,
        quality_score=quality_score,
        quality_reasons=quality_reasons,
        minimum_repairs=[repair],
        assumptions=_assumptions(request),
    )


def _assumptions(request: FlowAnalysisRequest) -> list[str]:
    assumptions = [
        "损耗仅在边的给定上下界内变化",
        "时延以连续窗口的整数个数计量",
        "缺失观测保持缺失，不作为零值输入",
        "期初在途按到达窗口显式给定边界，期末在途逐边逐窗口披露",
        "监管展示量仅在主目标最优解集合中唯一时报告点值，否则报告区间",
        "观测调整和业务松弛是主目标最优解中的一组确定性协调方案",
        "协调结果仅用于技术核查，不替代人工事实认定",
    ]
    if request.parameters.allow_business_slack:
        assumptions.append("业务平衡允许付费松弛并在结果中逐项披露")
    else:
        assumptions.append("业务平衡为硬约束，不允许未解释物料松弛")
    return assumptions


def _run_linprog(
    problem: _CompiledProblem,
    time_limit_seconds: float,
) -> OptimizeResult:
    return linprog(
        problem.objective,
        A_ub=problem.a_ub,
        b_ub=problem.b_ub,
        A_eq=problem.a_eq,
        b_eq=problem.b_eq,
        bounds=problem.bounds,
        method="highs-ds",
        options={
            "presolve": True,
            "time_limit": time_limit_seconds,
        },
    )


def _deterministic_solution(
    problem: _CompiledProblem,
    primary: OptimizeResult,
    tolerance: float,
    time_limit_seconds: float,
) -> np.ndarray:
    """Resolve alternate primary optima with a stable secondary objective."""

    if len(problem.objective) == 0:
        return np.empty(0, dtype=float)
    optimum = float(primary.fun)
    objective_row = problem.objective.reshape(1, -1)
    objective_rhs = np.asarray(
        [optimum + tolerance * max(1.0, abs(optimum))],
        dtype=float,
    )
    if problem.a_ub is None:
        a_ub = objective_row
        b_ub = objective_rhs
    else:
        a_ub = np.vstack((problem.a_ub, objective_row))
        assert problem.b_ub is not None
        b_ub = np.concatenate((problem.b_ub, objective_rhs))

    count = len(problem.objective)
    secondary = 1.0 + np.arange(count, dtype=float) / max(count, 1) * 1e-6
    # Do not exchange a tiny amount of primary residual/slack for a smaller
    # physical flow merely because the primary-optimum inequality has a
    # numerical feasibility tolerance.
    secondary = np.where(
        problem.objective > 0.0,
        secondary + 1e6,
        secondary,
    )
    polished = linprog(
        secondary,
        A_ub=a_ub,
        b_ub=b_ub,
        A_eq=problem.a_eq,
        b_eq=problem.b_eq,
        bounds=problem.bounds,
        method="highs-ds",
        options={
            "presolve": True,
            "time_limit": time_limit_seconds,
        },
    )
    if polished.status == 0 and polished.x is not None:
        return np.asarray(polished.x, dtype=float)
    return np.asarray(primary.x, dtype=float)


def _profile_expression(
    problem: _CompiledProblem,
    *,
    terms: dict[int, float],
    optimum: float,
    tolerance: float,
    time_limit_seconds: float,
    cache: dict[tuple[tuple[int, float], ...], _QuantityProfile],
) -> _QuantityProfile:
    """Profile one linear quantity over the primary-objective optimal face."""

    key = tuple(
        sorted(
            (index, float(coefficient))
            for index, coefficient in terms.items()
            if coefficient != 0.0
        )
    )
    cached = cache.get(key)
    if cached is not None:
        return cached
    if not key:
        result = _QuantityProfile(
            value=0.0,
            lower=0.0,
            upper=0.0,
            identified=True,
        )
        cache[key] = result
        return result

    variable_count = len(problem.objective)
    expression = np.zeros(variable_count, dtype=float)
    for index, coefficient in key:
        expression[index] = coefficient

    face_row = problem.objective.reshape(1, -1)
    face_rhs = np.asarray(
        [
            optimum
            + tolerance * max(1.0, abs(optimum))
        ],
        dtype=float,
    )
    if problem.a_ub is None:
        a_ub = face_row
        b_ub = face_rhs
    else:
        assert problem.b_ub is not None
        a_ub = np.vstack((problem.a_ub, face_row))
        b_ub = np.concatenate((problem.b_ub, face_rhs))

    options = {
        "presolve": True,
        "time_limit": time_limit_seconds,
    }
    minimum = linprog(
        expression,
        A_ub=a_ub,
        b_ub=b_ub,
        A_eq=problem.a_eq,
        b_eq=problem.b_eq,
        bounds=problem.bounds,
        method="highs-ds",
        options=options,
    )
    maximum = linprog(
        -expression,
        A_ub=a_ub,
        b_ub=b_ub,
        A_eq=problem.a_eq,
        b_eq=problem.b_eq,
        bounds=problem.bounds,
        method="highs-ds",
        options=options,
    )

    def bound(
        solved: OptimizeResult,
        *,
        negate: bool,
    ) -> float | None:
        if solved.status == 3:
            return None
        if (
            solved.status != 0
            or solved.fun is None
            or not math.isfinite(float(solved.fun))
        ):
            raise _ProfileError(
                "quantity profile solver failed with status "
                f"{solved.status}: {solved.message}"
            )
        raw = -float(solved.fun) if negate else float(solved.fun)
        return _clean(raw, tolerance)

    lower = bound(minimum, negate=False)
    upper = bound(maximum, negate=True)
    identified = False
    value: float | None = None
    if lower is not None and upper is not None:
        uniqueness_tolerance = max(
            tolerance,
            _PROFILE_IDENTIFICATION_ABSOLUTE_TOLERANCE,
        )
        identified = upper - lower <= uniqueness_tolerance
        if identified:
            value = _clean((lower + upper) / 2.0, uniqueness_tolerance)
    result = _QuantityProfile(
        value=value,
        lower=lower,
        upper=upper,
        identified=identified,
    )
    cache[key] = result
    return result


def _target_value(spec: _ObservationSpec, solution: np.ndarray) -> float:
    return sum(
        coefficient * solution[index]
        for index, coefficient in spec.terms.items()
    )


def _build_optimal_result(
    request: FlowAnalysisRequest,
    problem: _CompiledProblem,
    primary: OptimizeResult,
    quality_score: float | None,
) -> FlowAnalysisResult:
    tolerance = request.parameters.numerical_tolerance
    time_limit = request.parameters.solver_time_limit_seconds
    solution = _deterministic_solution(
        problem,
        primary,
        tolerance,
        time_limit,
    )
    windows = request.windows
    edge_by_id = {item.edge_id: item for item in request.edges}
    optimum = float(primary.fun)
    profile_cache: dict[
        tuple[tuple[int, float], ...],
        _QuantityProfile,
    ] = {}
    profiled_quantity_count = 0
    unidentified_quantity_count = 0
    profile_repairs: list[MinimumRepair] = []

    def profile(terms: dict[int, float]) -> _QuantityProfile:
        return _profile_expression(
            problem,
            terms=terms,
            optimum=optimum,
            tolerance=tolerance,
            time_limit_seconds=time_limit,
            cache=profile_cache,
        )

    def record_profile(
        quantity: _QuantityProfile,
        *,
        target_id: str,
        window_id: str | None,
        label: str,
    ) -> None:
        nonlocal profiled_quantity_count, unidentified_quantity_count
        profiled_quantity_count += 1
        if quantity.identified:
            return
        unidentified_quantity_count += 1
        lower = (
            "无下界"
            if quantity.lower is None
            else f"{quantity.lower:.6g}"
        )
        upper = (
            "无上界"
            if quantity.upper is None
            else f"{quantity.upper:.6g}"
        )
        severity = (
            quantity.upper - quantity.lower
            if quantity.lower is not None
            and quantity.upper is not None
            else None
        )
        profile_repairs.append(
            MinimumRepair(
                kind="data_gap",
                target_id=target_id,
                window_id=window_id,
                severity=severity,
                explanation=(
                    f"{label}在主目标最优解集合中不唯一，"
                    f"可识别区间为 [{lower}, {upper}] {request.unit}；"
                    "补充独立计量、容量边界或库存边界后重新协调"
                ),
            )
        )

    flow_observed = {
        (item.edge_id, item.window_id, item.point)
        for item in request.flow_observations
    }
    edge_windows: list[EdgeWindowReconciliation] = []
    for edge_id in sorted(edge_by_id):
        edge = edge_by_id[edge_id]
        for period, window in enumerate(windows):
            dispatch_terms: dict[int, float] = {}
            eventual_terms: dict[int, float] = {}
            arrived_terms: dict[int, float] = {}
            terminal_terms: dict[int, float] = {}
            allocations: list[DelayAllocation] = []
            for delay in range(
                edge.delay_windows_min,
                edge.delay_windows_max + 1,
            ):
                sent_index, received_index = problem.flow_variables[
                    (edge_id, period, delay)
                ]
                dispatch_terms[sent_index] = 1.0
                eventual_terms[received_index] = 1.0
                arrival = period + delay
                if arrival >= len(windows):
                    terminal_terms[received_index] = 1.0
            for delay in range(
                edge.delay_windows_min,
                edge.delay_windows_max + 1,
            ):
                departure = period - delay
                if departure < 0:
                    continue
                _, received_index = problem.flow_variables[
                    (edge_id, departure, delay)
                ]
                arrived_terms[received_index] = 1.0
            initial_index = problem.initial_transit_variables.get(
                (edge_id, period)
            )
            initial_terms: dict[int, float] = {}
            if initial_index is not None:
                initial_terms[initial_index] = 1.0
                arrived_terms[initial_index] = 1.0

            dispatch = profile(dispatch_terms)
            eventual = profile(eventual_terms)
            arrived = profile(arrived_terms)
            terminal = profile(terminal_terms)
            initial = profile(initial_terms)
            record_profile(
                dispatch,
                target_id=f"{edge_id}:dispatch",
                window_id=window.window_id,
                label=f"边 {edge_id} 发出量",
            )
            record_profile(
                eventual,
                target_id=f"{edge_id}:eventual_received",
                window_id=window.window_id,
                label=f"边 {edge_id} 最终接收量",
            )
            record_profile(
                arrived,
                target_id=f"{edge_id}:arrived",
                window_id=window.window_id,
                label=f"边 {edge_id} 到达量",
            )
            record_profile(
                terminal,
                target_id=f"{edge_id}:terminal_in_transit",
                window_id=window.window_id,
                label=f"边 {edge_id} 期末在途量",
            )
            if initial_index is not None:
                record_profile(
                    initial,
                    target_id=f"{edge_id}:initial_in_transit",
                    window_id=window.window_id,
                    label=f"边 {edge_id} 期初在途到达量",
                )

            single_delay = (
                edge.delay_windows_min == edge.delay_windows_max
            )
            for delay in range(
                edge.delay_windows_min,
                edge.delay_windows_max + 1,
            ):
                arrival = period + delay
                if single_delay:
                    allocation_dispatch = dispatch
                    allocation_received = eventual
                else:
                    dispatch_is_zero = (
                        dispatch.identified
                        and dispatch.value is not None
                        and dispatch.value <= tolerance
                    )
                    received_is_zero = (
                        eventual.identified
                        and eventual.value is not None
                        and eventual.value <= tolerance
                    )
                    allocation_dispatch = _QuantityProfile(
                        value=0.0 if dispatch_is_zero else None,
                        lower=0.0,
                        upper=(
                            0.0
                            if dispatch_is_zero
                            else dispatch.upper
                        ),
                        identified=dispatch_is_zero,
                    )
                    allocation_received = _QuantityProfile(
                        value=0.0 if received_is_zero else None,
                        lower=0.0,
                        upper=(
                            0.0
                            if received_is_zero
                            else eventual.upper
                        ),
                        identified=received_is_zero,
                    )
                allocations.append(
                    DelayAllocation(
                        departure_window_id=window.window_id,
                        arrival_window_id=(
                            windows[arrival].window_id
                            if arrival < len(windows)
                            else None
                        ),
                        delay_windows=delay,
                        dispatched_value=allocation_dispatch.value,
                        dispatched_lower_bound=(
                            allocation_dispatch.lower
                        ),
                        dispatched_upper_bound=(
                            allocation_dispatch.upper
                        ),
                        dispatch_identified=(
                            allocation_dispatch.identified
                        ),
                        received_value=allocation_received.value,
                        received_lower_bound=allocation_received.lower,
                        received_upper_bound=allocation_received.upper,
                        received_identified=(
                            allocation_received.identified
                        ),
                    )
                )

            inferred_loss = (
                _clean(
                    1.0 - eventual.value / dispatch.value,
                    tolerance,
                )
                if (
                    dispatch.identified
                    and eventual.identified
                    and dispatch.value is not None
                    and eventual.value is not None
                    and dispatch.value > tolerance
                )
                else None
            )
            edge_windows.append(
                EdgeWindowReconciliation(
                    edge_id=edge_id,
                    window_id=window.window_id,
                    dispatched_value=dispatch.value,
                    dispatched_lower_bound=dispatch.lower,
                    dispatched_upper_bound=dispatch.upper,
                    dispatch_identified=dispatch.identified,
                    eventual_received_value=eventual.value,
                    eventual_received_lower_bound=eventual.lower,
                    eventual_received_upper_bound=eventual.upper,
                    eventual_received_identified=eventual.identified,
                    arrived_value=arrived.value,
                    arrived_lower_bound=arrived.lower,
                    arrived_upper_bound=arrived.upper,
                    arrived_identified=arrived.identified,
                    initial_in_transit_value=initial.value,
                    initial_in_transit_lower_bound=initial.lower,
                    initial_in_transit_upper_bound=initial.upper,
                    initial_in_transit_identified=initial.identified,
                    terminal_in_transit_value=terminal.value,
                    terminal_in_transit_lower_bound=terminal.lower,
                    terminal_in_transit_upper_bound=terminal.upper,
                    terminal_in_transit_identified=terminal.identified,
                    inferred_loss_rate=inferred_loss,
                    dispatch_observed=(
                        edge_id,
                        window.window_id,
                        ObservationPoint.DISPATCH,
                    )
                    in flow_observed,
                    arrival_observed=(
                        edge_id,
                        window.window_id,
                        ObservationPoint.ARRIVAL,
                    )
                    in flow_observed,
                    allocations=allocations,
                )
            )

    inventory_observed: set[tuple[str, int]] = set()
    window_index = {
        item.window_id: index for index, item in enumerate(windows)
    }
    for observation in request.inventory_observations:
        period = window_index[observation.window_id]
        boundary = period if observation.boundary == "start" else period + 1
        inventory_observed.add((observation.node_id, boundary))
    inventory_trajectory: list[InventoryPoint] = []
    for node_id, boundary in sorted(problem.inventory_variables):
        variable = problem.inventory_variables[(node_id, boundary)]
        quantity = profile({variable: 1.0})
        record_profile(
            quantity,
            target_id=f"{node_id}:inventory:{boundary}",
            window_id=(
                windows[boundary].window_id
                if boundary < len(windows)
                else None
            ),
            label=f"节点 {node_id} 第 {boundary} 个库存边界",
        )
        at: datetime = (
            windows[0].start
            if boundary == 0
            else windows[boundary - 1].end
        )
        inventory_trajectory.append(
            InventoryPoint(
                node_id=node_id,
                boundary_index=boundary,
                at=at,
                value=quantity.value,
                lower_bound=quantity.lower,
                upper_bound=quantity.upper,
                identified=quantity.identified,
                observed=(node_id, boundary) in inventory_observed,
            )
        )

    adjustments: list[ObservationAdjustment] = []
    observation_objective = 0.0
    for spec in problem.observation_specs:
        coordinated = _clean(_target_value(spec, solution), tolerance)
        signed = _clean(coordinated - spec.value, tolerance)
        normalized = _clean(signed / spec.effective_error, tolerance)
        contribution = abs(signed) * spec.weight
        observation_objective += contribution
        adjustments.append(
            ObservationAdjustment(
                observation_id=spec.observation_id,
                source_id=spec.source_id,
                observation_kind=spec.kind,
                target_id=spec.target_id,
                window_id=spec.window_id,
                observed_value=spec.value,
                coordinated_value=coordinated,
                signed_adjustment=signed,
                effective_error=spec.effective_error,
                normalized_residual=normalized,
                objective_contribution=_clean(
                    contribution,
                    tolerance,
                ),
            )
        )

    by_source: dict[str, list[ObservationAdjustment]] = {}
    for adjustment in adjustments:
        by_source.setdefault(adjustment.source_id, []).append(adjustment)
    source_adjustments: list[SourceAdjustment] = []
    for source_id in sorted(by_source):
        values = by_source[source_id]
        source_adjustments.append(
            SourceAdjustment(
                source_id=source_id,
                observation_count=len(values),
                signed_adjustment=_clean(
                    sum(item.signed_adjustment for item in values),
                    tolerance,
                ),
                absolute_adjustment=_clean(
                    sum(abs(item.signed_adjustment) for item in values),
                    tolerance,
                ),
                signed_normalized_residual=_clean(
                    sum(item.normalized_residual for item in values),
                    tolerance,
                ),
                normalized_residual=_clean(
                    sum(abs(item.normalized_residual) for item in values),
                    tolerance,
                ),
                maximum_normalized_residual=_clean(
                    max(abs(item.normalized_residual) for item in values),
                    tolerance,
                ),
            )
        )

    business_slacks: list[BusinessSlack] = []
    business_objective = 0.0
    for node_id, period in sorted(problem.slack_variables):
        added_index, removed_index = problem.slack_variables[
            (node_id, period)
        ]
        added = _clean(solution[added_index], tolerance)
        removed = _clean(solution[removed_index], tolerance)
        contribution = (
            added + removed
        ) * request.parameters.business_slack_penalty
        business_objective += contribution
        business_slacks.append(
            BusinessSlack(
                node_id=node_id,
                window_id=windows[period].window_id,
                material_added=added,
                material_removed=removed,
                signed_slack=_clean(added - removed, tolerance),
                objective_contribution=_clean(
                    contribution,
                    tolerance,
                ),
            )
        )

    repairs: list[MinimumRepair] = list(profile_repairs)
    for adjustment in adjustments:
        severity = abs(adjustment.normalized_residual)
        if abs(adjustment.signed_adjustment) <= tolerance:
            continue
        direction = "上调" if adjustment.signed_adjustment > 0 else "下调"
        repairs.append(
            MinimumRepair(
                kind="observation_adjustment",
                target_id=adjustment.observation_id,
                window_id=adjustment.window_id,
                amount=adjustment.signed_adjustment,
                severity=severity,
                explanation=(
                    f"将来源 {adjustment.source_id} 的观测"
                    f"{direction} {abs(adjustment.signed_adjustment):.6g} "
                    f"{request.unit}，归一化残差 {severity:.3f}"
                ),
            )
        )
    for slack in business_slacks:
        amount = slack.signed_slack
        if abs(amount) <= tolerance:
            continue
        action = "补入" if amount > 0 else "移出"
        repairs.append(
            MinimumRepair(
                kind="business_slack",
                target_id=slack.node_id,
                window_id=slack.window_id,
                amount=amount,
                severity=abs(amount),
                explanation=(
                    f"节点 {slack.node_id} 需解释业务平衡{action} "
                    f"{abs(amount):.6g} {request.unit}"
                ),
            )
        )
    repairs.sort(
        key=lambda item: (
            -(item.severity or 0.0),
            item.kind,
            item.target_id,
            item.window_id or "",
        )
    )

    observation_objective = _clean(observation_objective, tolerance)
    business_objective = _clean(business_objective, tolerance)
    identification_complete = unidentified_quantity_count == 0
    return FlowAnalysisResult(
        request_id=request.request_id,
        mine_id=request.mine_id,
        unit=request.unit,
        status=(
            "optimal"
            if identification_complete
            else "underdetermined"
        ),
        feasible=True,
        solver_status=(
            "highs_optimal_identified"
            if identification_complete
            else "highs_optimal_underdetermined"
        ),
        quality_sufficient=True,
        quality_score=quality_score,
        objective_value=_clean(optimum, tolerance),
        observation_objective=observation_objective,
        business_slack_objective=business_objective,
        identification_complete=identification_complete,
        profiled_quantity_count=profiled_quantity_count,
        unidentified_quantity_count=unidentified_quantity_count,
        edge_windows=edge_windows,
        inventory_trajectory=inventory_trajectory,
        observation_adjustments=adjustments,
        source_adjustments=source_adjustments,
        business_slacks=business_slacks,
        minimum_repairs=repairs,
        assumptions=_assumptions(request),
    )


def analyze_material_flow(
    request: FlowAnalysisRequest,
) -> FlowAnalysisResult:
    """Run deterministic robust L1 reconciliation for a time-expanded graph."""

    quality_sufficient, quality_score, quality_reasons = _quality_gate(
        request
    )
    if not quality_sufficient:
        return _base_result(
            request,
            status="quality_insufficient",
            feasible=None,
            solver_status="not_run_quality_gate",
            quality_sufficient=False,
            quality_score=quality_score,
            quality_reasons=quality_reasons,
            repair=MinimumRepair(
                kind="quality_review",
                target_id=request.request_id,
                explanation="补齐或修复低质量、未受信观测后重新协调",
            ),
        )

    problem = _compile(request)
    if len(problem.objective) == 0:
        # A graph with no variables can only occur with external nodes and an
        # explicitly disabled minimum-observation gate.
        return FlowAnalysisResult(
            request_id=request.request_id,
            mine_id=request.mine_id,
            unit=request.unit,
            status="optimal",
            feasible=True,
            solver_status="empty_problem_optimal",
            quality_sufficient=True,
            quality_score=quality_score,
            objective_value=0.0,
            observation_objective=0.0,
            business_slack_objective=0.0,
            identification_complete=True,
            assumptions=_assumptions(request),
        )

    solved = _run_linprog(
        problem,
        request.parameters.solver_time_limit_seconds,
    )
    if solved.status == 2:
        return _base_result(
            request,
            status="infeasible",
            feasible=False,
            solver_status="highs_infeasible",
            quality_sufficient=True,
            quality_score=quality_score,
            quality_reasons=[],
            repair=MinimumRepair(
                kind="hard_constraint_review",
                target_id=request.request_id,
                explanation=(
                    "硬库存边界、边容量或禁用业务松弛后的物料平衡"
                    "不可同时满足；核验边界，或经审批启用业务松弛"
                ),
            ),
        )
    if solved.status == 3:
        return _base_result(
            request,
            status="unbounded",
            feasible=True,
            solver_status="highs_unbounded",
            quality_sufficient=True,
            quality_score=quality_score,
            quality_reasons=[],
            repair=MinimumRepair(
                kind="hard_constraint_review",
                target_id=request.request_id,
                explanation="模型无界；补充边容量或库存上下界后重新协调",
            ),
        )
    if solved.status != 0 or solved.x is None or not math.isfinite(
        float(solved.fun)
    ):
        return _base_result(
            request,
            status="solver_error",
            feasible=None,
            solver_status=f"highs_error_{solved.status}",
            quality_sufficient=True,
            quality_score=quality_score,
            quality_reasons=[],
            repair=MinimumRepair(
                kind="hard_constraint_review",
                target_id=request.request_id,
                explanation="求解器未返回可靠最优解，请检查数值尺度和约束",
            ),
        )
    try:
        return _build_optimal_result(
            request,
            problem,
            solved,
            quality_score,
        )
    except _ProfileError:
        return _base_result(
            request,
            status="solver_error",
            feasible=True,
            solver_status="quantity_profile_error",
            quality_sufficient=True,
            quality_score=quality_score,
            quality_reasons=[],
            repair=MinimumRepair(
                kind="data_gap",
                target_id=request.request_id,
                explanation=(
                    "主目标已求得可行最优解，但数量可识别区间求解未可靠"
                    "完成；缩小图或时间范围后重试"
                ),
            ),
        )


__all__ = [
    "BusinessSlack",
    "DelayAllocation",
    "EdgeWindowReconciliation",
    "FlowAnalysisRequest",
    "FlowAnalysisResult",
    "FlowObservation",
    "FlowParameters",
    "InventoryObservation",
    "InventoryPoint",
    "InventoryState",
    "InitialInTransit",
    "MeasurementError",
    "MinimumRepair",
    "NodeKind",
    "ObservationAdjustment",
    "ObservationPoint",
    "PhysicalEdge",
    "PhysicalNode",
    "SourceAdjustment",
    "TimeWindow",
    "analyze_material_flow",
]
