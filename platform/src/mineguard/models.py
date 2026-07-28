from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    AliasChoices,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

MAX_ABSOLUTE_METRIC_VALUE = 1e15
MIN_EFFECTIVE_TOLERANCE = 1e-9
MAX_RELATIVE_TOLERANCE = 10.0
MAX_OPTIMIZATION_PENALTY = 1e12
MAX_ANALYSIS_ITEMS = 100_000


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
    )


class MetricCode(StrEnum):
    REPORTED_PRODUCTION = "coal.reported_output_t"
    MAIN_TRANSPORT = "coal.main_transport_t"
    WASH_FEED = "wash.feed_t"
    RAW_SALES = "sales.raw_shipped_t"
    RAW_INVENTORY_CHANGE = "inventory.raw_change_t"


class QualitySignals(StrictModel):
    completeness: Annotated[float, Field(ge=0, le=1)] = 1.0
    timeliness: Annotated[float, Field(ge=0, le=1)] = 1.0
    device_health: Annotated[float, Field(ge=0, le=1)] = 1.0
    calibration: Annotated[float, Field(ge=0, le=1)] = 1.0
    clock: Annotated[float, Field(ge=0, le=1)] = 1.0
    lineage: Annotated[float, Field(ge=0, le=1)] = 1.0
    uniqueness: Annotated[float, Field(ge=0, le=1)] = 1.0
    signature_valid: bool = True
    blocking_flags: list[str] = Field(default_factory=list)
    unverified_dimensions: list[
        Literal["device_health", "clock"]
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_unverified_dimensions(self) -> "QualitySignals":
        if len(self.unverified_dimensions) != len(
            set(self.unverified_dimensions)
        ):
            raise ValueError("unverified_dimensions values must be unique")
        return self


class MetricObservation(StrictModel):
    observation_id: Annotated[str, Field(min_length=1)]
    metric_code: MetricCode
    value: Annotated[
        float,
        Field(
            ge=-MAX_ABSOLUTE_METRIC_VALUE,
            le=MAX_ABSOLUTE_METRIC_VALUE,
        ),
    ]
    tolerance_abs: Annotated[
        float,
        Field(
            ge=MIN_EFFECTIVE_TOLERANCE,
            le=MAX_ABSOLUTE_METRIC_VALUE,
        ),
    ]
    tolerance_rel: Annotated[
        float,
        Field(
            ge=0,
            le=MAX_RELATIVE_TOLERANCE,
            validation_alias=AliasChoices(
                "tolerance_rel",
                "tolerance_relative",
            ),
        ),
    ] = 0.0
    resolution: Annotated[
        float,
        Field(
            ge=0,
            le=MAX_ABSOLUTE_METRIC_VALUE,
            validation_alias=AliasChoices(
                "resolution",
                "measurement_resolution",
            ),
        ),
    ] = 0.0
    source_group: Annotated[str, Field(min_length=1)]
    dependency_domains: list[Annotated[str, Field(min_length=1)]] = Field(
        default_factory=list
    )
    source_reliability: Annotated[float, Field(gt=0, le=1)] = 1.0
    quality: QualitySignals = Field(default_factory=QualitySignals)

    @model_validator(mode="after")
    def validate_metric_domain(self) -> "MetricObservation":
        if (
            self.metric_code is not MetricCode.RAW_INVENTORY_CHANGE
            and self.value < 0
        ):
            raise ValueError(
                f"{self.metric_code.value} must be non-negative"
            )
        if len(self.dependency_domains) != len(set(self.dependency_domains)):
            raise ValueError("dependency_domains values must be unique")
        return self

    @property
    def tolerance_relative(self) -> float:
        """Readable alias retained for callers using the long field name."""

        return self.tolerance_rel


class BalanceParameters(StrictModel):
    transport_balance_tolerance: Annotated[
        float,
        Field(ge=0, le=MAX_ABSOLUTE_METRIC_VALUE),
    ] = 0.0
    stock_balance_tolerance: Annotated[
        float,
        Field(ge=0, le=MAX_ABSOLUTE_METRIC_VALUE),
    ] = 0.0
    transport_slack_penalty: Annotated[
        float,
        Field(
            ge=MIN_EFFECTIVE_TOLERANCE,
            le=MAX_OPTIMIZATION_PENALTY,
        ),
    ] = 100.0
    stock_slack_penalty: Annotated[
        float,
        Field(
            ge=MIN_EFFECTIVE_TOLERANCE,
            le=MAX_OPTIMIZATION_PENALTY,
        ),
    ] = 100.0
    max_mcs: Annotated[int, Field(ge=1, le=20)] = 5
    max_relaxed_groups: Annotated[int, Field(ge=0, le=10)] = 3
    max_mcs_search_combinations: Annotated[
        int,
        Field(ge=1, le=1_000_000),
    ] = 20_000
    quality_gate: Annotated[float, Field(ge=0, le=100)] = 60.0
    minimum_observation_quality: Annotated[
        float,
        Field(ge=0, le=100),
    ] = 50.0


class ProductionAnalysisRequest(StrictModel):
    mine_id: Annotated[str, Field(min_length=1)]
    window_start: AwareDatetime
    window_end: AwareDatetime
    observations: Annotated[
        list[MetricObservation],
        Field(min_length=1, max_length=MAX_ANALYSIS_ITEMS),
    ]
    parameters: BalanceParameters = Field(default_factory=BalanceParameters)
    calibration_scores: Annotated[
        list[
            Annotated[
                float,
                Field(ge=0, le=MAX_ABSOLUTE_METRIC_VALUE),
            ]
        ],
        Field(max_length=MAX_ANALYSIS_ITEMS),
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_window_and_metrics(self) -> "ProductionAnalysisRequest":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be later than window_start")
        if not self.observations:
            raise ValueError("at least one observation is required")
        observation_ids = [
            observation.observation_id for observation in self.observations
        ]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("observation_id values must be unique")
        return self


class DataQualityResult(StrictModel):
    score: Annotated[float, Field(ge=0, le=100)]
    status: Literal["sufficient", "degraded", "blocked"]
    blocking_reasons: list[str] = Field(default_factory=list)
    observation_scores: dict[str, float] = Field(default_factory=dict)
    minimum_observation_score: Annotated[
        float | None,
        Field(ge=0, le=100),
    ] = None
    quality_gate: Annotated[float, Field(ge=0, le=100)] = 60.0
    minimum_observation_quality: Annotated[
        float,
        Field(ge=0, le=100),
    ] = 50.0
    aggregation_method: str = "mean_with_observation_floor_v2.1"
    unverified_dimensions: list[str] = Field(default_factory=list)


class ObservationAdjustment(StrictModel):
    """Minimum weighted-L1 repair assigned to one raw observation."""

    observation_id: str
    metric_code: MetricCode
    source_group: str
    observed_value: float
    inferred_value: float
    signed_adjustment: float
    absolute_adjustment: Annotated[float, Field(ge=0)]
    effective_tolerance: Annotated[float, Field(gt=0)]
    normalized_residual: Annotated[float, Field(ge=0)]


class BusinessBalanceSlack(StrictModel):
    """Residual of one physical balance after its approved tolerance."""

    balance_code: Literal["production_transport", "stock_flow"]
    signed_balance_residual: float
    approved_tolerance: Annotated[float, Field(ge=0)]
    positive_slack: Annotated[float, Field(ge=0)]
    negative_slack: Annotated[float, Field(ge=0)]
    absolute_slack: Annotated[float, Field(ge=0)]
    minimum_additional_repair: Annotated[float, Field(ge=0)]
    explanation: str


class ReconciledMetric(StrictModel):
    metric_code: MetricCode
    inferred_value: float
    observed_values: list[float]
    reasonable_lower: float | None = None
    reasonable_upper: float | None = None
    normalized_residual: float
    observation_adjustments: list[ObservationAdjustment] = Field(
        default_factory=list
    )


class ConflictAlternative(StrictModel):
    relaxed_source_groups: list[str]
    group_count: int
    total_reliability_cost: float
    minimum_priority: bool = False
    reasonable_production_range: tuple[float, float] | None = None
    production_range_bounded: bool = False
    minimum_reported_gap: float | None = None
    minimum_reported_gap_ratio: float | None = None
    unreported_output_upper: float | None = None
    unreported_output_upper_ratio: float | None = None
    supports_positive_reported_gap: bool | None = None
    supporting_source_groups: list[str] = Field(default_factory=list)
    independent_evidence_clusters: list[list[str]] = Field(
        default_factory=list
    )
    independent_evidence_cluster_count: Annotated[int, Field(ge=0)] = 0


class ProductionAnalysisResult(StrictModel):
    mine_id: str
    status: Literal[
        "consistent",
        "inconsistent",
        "inconclusive",
        "solver_error",
    ]
    data_quality: DataQualityResult
    solver_status: str
    objective_value: float | None = None
    raw_anomaly_statistic: float | None = None
    empirical_p_value: float | None = None
    consistency_score: float | None = None
    calibration_sample_count: Annotated[int, Field(ge=0)] = 0
    calibration_method: str | None = None
    evidence_grade: Literal["A", "B", "C", "D"]
    reconciled_metrics: dict[str, ReconciledMetric] = Field(default_factory=dict)
    mcs_alternatives: list[ConflictAlternative] = Field(default_factory=list)
    reasonable_production_range: tuple[float, float] | None = None
    minimum_reported_gap: float | None = None
    unreported_output_upper: float | None = None
    robust_minimum_reported_gap: float | None = None
    robust_minimum_reported_gap_ratio: float | None = None
    scenario_union_production_range: tuple[float, float] | None = None
    scenario_conclusion_divergent: bool = False
    all_priority_scenarios_support_positive_gap: bool = False
    priority_scenario_count: Annotated[int, Field(ge=0)] = 0
    priority_scenario_count_complete: bool = True
    diagnostics_complete: bool = False
    mcs_search_complete: bool = True
    mcs_examined_combination_count: Annotated[int, Field(ge=0)] = 0
    supporting_source_groups: list[str] = Field(default_factory=list)
    independent_evidence_clusters: list[list[str]] = Field(
        default_factory=list
    )
    independent_evidence_cluster_count: Annotated[int, Field(ge=0)] = 0
    observation_adjustments: dict[str, ObservationAdjustment] = Field(
        default_factory=dict
    )
    business_balance_slacks: dict[str, BusinessBalanceSlack] = Field(
        default_factory=dict
    )
    minimum_repair_explanations: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)


class FaceEvent(StrictModel):
    face_track_id: Annotated[str, Field(min_length=1)]
    event_time: AwareDatetime
    candidate_person_id: Annotated[str, Field(min_length=1)] | None = None
    match_probability: Annotated[float, Field(ge=0, le=1)] = 0.0
    direction: Literal["entry", "exit"] | None = None


class CardEvent(StrictModel):
    card_event_id: Annotated[str, Field(min_length=1)]
    card_id: Annotated[str, Field(min_length=1)]
    bound_person_id: Annotated[str, Field(min_length=1)]
    event_time: AwareDatetime
    direction: Literal["entry", "exit"] | None = None


class PersonnelMatchRequest(StrictModel):
    session_id: Annotated[str, Field(min_length=1)]
    faces: list[FaceEvent]
    cards: list[CardEvent]
    max_time_delta_seconds: Annotated[float, Field(gt=0)] = 30.0
    unmatched_face_cost: Annotated[float, Field(gt=0)] = 1.1
    unmatched_card_cost: Annotated[float, Field(gt=0)] = 1.1
    mismatch_penalty: Annotated[float, Field(gt=0)] = 1.0

    @model_validator(mode="after")
    def validate_unique_event_ids(self) -> "PersonnelMatchRequest":
        face_ids = [face.face_track_id for face in self.faces]
        if len(face_ids) != len(set(face_ids)):
            raise ValueError("face_track_id values must be unique")
        card_event_ids = [card.card_event_id for card in self.cards]
        if len(card_event_ids) != len(set(card_event_ids)):
            raise ValueError("card_event_id values must be unique")
        return self


class PersonnelMatch(StrictModel):
    face_track_id: str
    card_event_id: str
    card_id: str
    face_person_id: str | None
    card_person_id: str
    time_delta_seconds: Annotated[float, Field(ge=0)]
    identity_confidence: Annotated[float, Field(ge=0, le=1)]
    cost: float
    status: Literal[
        "identity_confirmed",
        "temporal_pair_only",
        "identity_conflict",
    ]


class PersonnelIssue(StrictModel):
    code: Literal[
        "identity_conflict",
        "temporal_pair_only",
        "direction_conflict",
        "unmatched_face",
        "unmatched_card",
    ]
    severity: Literal["review", "data"]
    summary: str
    face_track_id: str | None = None
    card_event_id: str | None = None


class PersonnelMatchResult(StrictModel):
    session_id: str
    matches: list[PersonnelMatch] = Field(default_factory=list)
    unmatched_face_tracks: list[str] = Field(default_factory=list)
    unmatched_card_events: list[str] = Field(default_factory=list)
    issues: list[PersonnelIssue] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
