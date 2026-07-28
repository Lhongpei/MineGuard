"""Deterministic safety-monitoring clue engine.

This module deliberately stops at producing traceable *technical warning
clues*.  It never controls ventilation, power, evacuation, production, or
power restoration.  A caller must combine every clue with the applicable
regulation, original device records, and authorised human judgement.

The public contract is:

``build_default_rule_snapshot``
    Return the versioned Qinyuan proposal baseline.  A deployment may replace
    the complete immutable snapshot with an approved local snapshot.

``evaluate_safety``
    Evaluate a batch as-of an explicit decision time.  The caller passes the
    previous states back on the next call, making debounce and recovery
    behaviour deterministic and independent of process memory.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, TypeAlias

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


MAX_MEASUREMENT = 1e12
MAX_DURATION_SECONDS = 31_557_600


class SafetyModel(BaseModel):
    """Strict, immutable base for safety-domain input and output."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        strict=True,
        frozen=True,
        validate_default=True,
    )


class AlertLevel(StrEnum):
    BLUE = "blue"
    YELLOW = "yellow"
    ORANGE = "orange"
    RED = "red"


_LEVEL_RANK = {
    AlertLevel.BLUE: 1,
    AlertLevel.YELLOW: 2,
    AlertLevel.ORANGE: 3,
    AlertLevel.RED: 4,
}


class MineGasCategory(StrEnum):
    LOW = "low_gas"
    HIGH = "high_gas"


class MethaneLocation(StrEnum):
    WORKING_FACE_T1 = "working_face_t1"
    RETURN_AIR_T2 = "return_air_t2"
    RETURN_AIR_MIDDLE = "return_air_middle"
    TOTAL_RETURN_AIR = "total_return_air"


class SafetyMetric(StrEnum):
    PERSONNEL_COUNT = "personnel.count"
    METHANE_CONCENTRATION = "methane.concentration"
    VENTILATION_FLOW = "ventilation.flow"


class MeasurementUnit(StrEnum):
    PERSON = "person"
    PERCENT_CH4 = "%CH4"
    CUBIC_METRE_PER_SECOND = "m3/s"


class SourceChannel(StrEnum):
    AUTOMATIC = "automatic"
    MANUAL = "manual"


class SafetyScope(StrEnum):
    PERSONNEL = "personnel"
    METHANE = "methane"
    VENTILATION = "ventilation"


class StateStatus(StrEnum):
    NORMAL = "normal"
    PENDING = "pending"
    ACTIVE = "active"


class TransitionType(StrEnum):
    OPENED = "opened"
    ESCALATED = "escalated"
    DEESCALATED = "deescalated"
    CLEARED = "cleared"
    METHANE_MAJOR_CHANGE = "methane_major_change"
    RECOVERY_ELIGIBLE = "recovery_eligible"


class DataIssueCode(StrEnum):
    FUTURE_OBSERVATION = "future_observation"
    STALE_OBSERVATION = "stale_observation"
    LOW_QUALITY = "low_quality"
    INVALID_SOURCE = "invalid_source"
    OUT_OF_ORDER = "out_of_order"


class ObservationSource(SafetyModel):
    source_id: Annotated[str, Field(min_length=1, max_length=200)]
    system_name: Annotated[str, Field(min_length=1, max_length=200)]
    channel: SourceChannel
    lineage_ref: Annotated[str, Field(min_length=1, max_length=500)]
    signature_valid: bool = True


class MeasurementQuality(SafetyModel):
    score: Annotated[float, Field(ge=0.0, le=1.0)] = 1.0
    complete: bool = True
    device_healthy: bool = True
    clock_synchronised: bool = True
    blocking_flags: tuple[
        Annotated[str, Field(min_length=1, max_length=200)], ...
    ] = ()

    @model_validator(mode="after")
    def validate_unique_flags(self) -> "MeasurementQuality":
        if len(self.blocking_flags) != len(set(self.blocking_flags)):
            raise ValueError("blocking_flags must be unique")
        return self


class ObservationBase(SafetyModel):
    observation_id: Annotated[str, Field(min_length=1, max_length=200)]
    revision: Annotated[int, Field(ge=0)] = 0
    mine_id: Annotated[str, Field(min_length=1, max_length=200)]
    observed_at: AwareDatetime
    received_at: AwareDatetime
    source: ObservationSource
    quality: MeasurementQuality = Field(default_factory=MeasurementQuality)

    @model_validator(mode="after")
    def validate_source_time(self) -> "ObservationBase":
        if self.observed_at > self.received_at:
            raise ValueError("observed_at must not be later than received_at")
        return self


class PersonnelObservation(ObservationBase):
    metric: Literal[SafetyMetric.PERSONNEL_COUNT] = (
        SafetyMetric.PERSONNEL_COUNT
    )
    value: Annotated[int, Field(ge=0, le=10_000_000)]
    unit: Literal[MeasurementUnit.PERSON] = MeasurementUnit.PERSON


class MethaneObservation(ObservationBase):
    metric: Literal[SafetyMetric.METHANE_CONCENTRATION] = (
        SafetyMetric.METHANE_CONCENTRATION
    )
    point_id: Annotated[str, Field(min_length=1, max_length=200)]
    location: MethaneLocation
    value: Annotated[float, Field(ge=0.0, le=100.0)]
    unit: Literal[MeasurementUnit.PERCENT_CH4] = MeasurementUnit.PERCENT_CH4


class VentilationObservation(ObservationBase):
    metric: Literal[SafetyMetric.VENTILATION_FLOW] = (
        SafetyMetric.VENTILATION_FLOW
    )
    point_id: Annotated[str, Field(min_length=1, max_length=200)]
    value: Annotated[float, Field(ge=0.0, le=MAX_MEASUREMENT)]
    unit: Literal[MeasurementUnit.CUBIC_METRE_PER_SECOND] = (
        MeasurementUnit.CUBIC_METRE_PER_SECOND
    )


SafetyObservation: TypeAlias = (
    PersonnelObservation | MethaneObservation | VentilationObservation
)


class MineSafetyProfile(SafetyModel):
    mine_id: Annotated[str, Field(min_length=1, max_length=200)]
    gas_category: MineGasCategory
    approved_personnel_capacity: Annotated[
        int, Field(gt=0, le=10_000_000)
    ]


class PersonnelThresholds(SafetyModel):
    attention_ratio: Annotated[float, Field(gt=0.0, le=1.0)] = 0.80
    warning_ratio: Annotated[float, Field(gt=0.0, le=1.0)] = 0.90
    overcapacity_ratio: Annotated[float, Field(gt=0.0, le=2.0)] = 1.00

    @model_validator(mode="after")
    def validate_order(self) -> "PersonnelThresholds":
        if not (
            self.attention_ratio
            < self.warning_ratio
            < self.overcapacity_ratio
        ):
            raise ValueError(
                "personnel ratios must satisfy attention < warning "
                "< overcapacity"
            )
        return self


class MethaneThreshold(SafetyModel):
    gas_category: MineGasCategory
    location: MethaneLocation
    alarm_pct: Annotated[float, Field(gt=0.0, le=100.0)]
    cutoff_pct: Annotated[float | None, Field(gt=0.0, le=100.0)] = None
    reset_below_pct: Annotated[
        float | None, Field(gt=0.0, le=100.0)
    ] = None
    trend_pct: Annotated[float | None, Field(gt=0.0, le=100.0)] = None

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "MethaneThreshold":
        if self.trend_pct is not None and self.trend_pct >= self.alarm_pct:
            raise ValueError("trend_pct must be lower than alarm_pct")
        if self.cutoff_pct is not None and self.cutoff_pct < self.alarm_pct:
            raise ValueError("cutoff_pct must not be lower than alarm_pct")
        if (self.cutoff_pct is None) != (self.reset_below_pct is None):
            raise ValueError(
                "cutoff_pct and reset_below_pct must be configured together"
            )
        if (
            self.reset_below_pct is not None
            and self.reset_below_pct > self.alarm_pct
        ):
            raise ValueError(
                "reset_below_pct must not be greater than alarm_pct"
            )
        return self


class VentilationThresholds(SafetyModel):
    # The proposal says "over 15%", therefore equality is intentionally normal.
    sudden_drop_ratio: Annotated[float, Field(gt=0.0, lt=1.0)] = 0.15
    # The proposal does not give a numerical "serious abnormal" boundary.
    # This versioned local parameter must be approved or replaced at deployment.
    severe_drop_ratio: Annotated[float, Field(gt=0.0, lt=1.0)] = 0.30

    @model_validator(mode="after")
    def validate_order(self) -> "VentilationThresholds":
        if self.severe_drop_ratio <= self.sudden_drop_ratio:
            raise ValueError(
                "severe_drop_ratio must be greater than sudden_drop_ratio"
            )
        return self


class MainFanPolicy(SafetyModel):
    """Approved alert levels for discrete main-fan operating signals."""

    stopped_level: AlertLevel = AlertLevel.RED
    fault_level: AlertLevel = AlertLevel.RED
    changeover_level: AlertLevel = AlertLevel.YELLOW


class DebouncePolicy(SafetyModel):
    activate_after_consecutive: Annotated[int, Field(ge=1, le=100)] = 1
    clear_after_consecutive: Annotated[int, Field(ge=1, le=100)] = 2
    methane_red_after_consecutive: Annotated[int, Field(ge=2, le=100)] = 3


class JointRiskPolicy(SafetyModel):
    window_seconds: Annotated[
        int, Field(ge=1, le=MAX_DURATION_SECONDS)
    ] = 300
    methane_minimum_rise_pct_points: Annotated[
        float, Field(ge=0.0, le=100.0)
    ] = 0.0


class DataValidationPolicy(SafetyModel):
    minimum_quality: Annotated[float, Field(ge=0.0, le=1.0)] = 0.70
    maximum_age_seconds: Annotated[
        int, Field(ge=1, le=MAX_DURATION_SECONDS)
    ] = 900


class SafetyRuleSnapshot(SafetyModel):
    version: Annotated[str, Field(min_length=1, max_length=100)]
    effective_from: AwareDatetime
    effective_to: AwareDatetime | None = None
    authority_reference: Annotated[str, Field(min_length=1, max_length=500)]
    personnel: PersonnelThresholds = Field(
        default_factory=PersonnelThresholds
    )
    methane: tuple[MethaneThreshold, ...]
    ventilation: VentilationThresholds = Field(
        default_factory=VentilationThresholds
    )
    main_fan: MainFanPolicy = Field(default_factory=MainFanPolicy)
    debounce: DebouncePolicy = Field(default_factory=DebouncePolicy)
    joint: JointRiskPolicy = Field(default_factory=JointRiskPolicy)
    data_validation: DataValidationPolicy = Field(
        default_factory=DataValidationPolicy
    )
    methane_major_change_pct_points: Annotated[
        float, Field(gt=0.0, le=100.0)
    ] = 0.20

    @model_validator(mode="after")
    def validate_snapshot(self) -> "SafetyRuleSnapshot":
        if (
            self.effective_to is not None
            and self.effective_to <= self.effective_from
        ):
            raise ValueError("effective_to must be later than effective_from")
        keys = [
            (threshold.gas_category, threshold.location)
            for threshold in self.methane
        ]
        if len(keys) != len(set(keys)):
            raise ValueError(
                "methane threshold category/location pairs must be unique"
            )
        expected = {
            (category, location)
            for category in MineGasCategory
            for location in MethaneLocation
            if not (
                category is MineGasCategory.LOW
                and location is MethaneLocation.RETURN_AIR_MIDDLE
            )
        }
        if set(keys) != expected:
            raise ValueError(
                "methane thresholds must cover every supported "
                "category/location pair"
            )
        return self

    @property
    def fingerprint(self) -> str:
        """Content hash used to bind state and results to the exact snapshot."""

        return sha256(self.model_dump_json().encode("utf-8")).hexdigest()

    def threshold_for(
        self,
        category: MineGasCategory,
        location: MethaneLocation,
    ) -> MethaneThreshold:
        for threshold in self.methane:
            if (
                threshold.gas_category is category
                and threshold.location is location
            ):
                return threshold
        raise ValueError(
            f"no methane threshold for {category.value}/{location.value}"
        )


def build_default_rule_snapshot(
    *,
    version: str = "qinyuan-safety-2026.07-v2",
    effective_from: datetime | None = None,
) -> SafetyRuleSnapshot:
    """Build the proposal baseline as an immutable, versioned snapshot.

    ``severe_drop_ratio`` is a transparent local configuration because the
    proposal names serious ventilation abnormality but does not quantify it.
    All other default numeric values below are taken from the proposal.
    """

    effective = effective_from or datetime(2026, 1, 1, tzinfo=UTC)
    common_t1 = {
        "alarm_pct": 1.0,
        "cutoff_pct": 1.5,
        "reset_below_pct": 1.0,
    }
    common_t2 = {
        "alarm_pct": 1.0,
        "cutoff_pct": 1.0,
        "reset_below_pct": 1.0,
    }
    return SafetyRuleSnapshot(
        version=version,
        effective_from=effective,
        authority_reference=(
            "沁源县决策式AI智能体辅助监测平台建设方案，"
            "安全智能预警模块表2；正式部署须经适用规程复核"
        ),
        methane=(
            MethaneThreshold(
                gas_category=MineGasCategory.LOW,
                location=MethaneLocation.WORKING_FACE_T1,
                **common_t1,
            ),
            MethaneThreshold(
                gas_category=MineGasCategory.LOW,
                location=MethaneLocation.RETURN_AIR_T2,
                **common_t2,
            ),
            MethaneThreshold(
                gas_category=MineGasCategory.LOW,
                location=MethaneLocation.TOTAL_RETURN_AIR,
                alarm_pct=0.75,
            ),
            MethaneThreshold(
                gas_category=MineGasCategory.HIGH,
                location=MethaneLocation.WORKING_FACE_T1,
                **common_t1,
            ),
            MethaneThreshold(
                gas_category=MineGasCategory.HIGH,
                location=MethaneLocation.RETURN_AIR_T2,
                trend_pct=0.75,
                **common_t2,
            ),
            MethaneThreshold(
                gas_category=MineGasCategory.HIGH,
                location=MethaneLocation.RETURN_AIR_MIDDLE,
                trend_pct=0.75,
                **common_t2,
            ),
            MethaneThreshold(
                gas_category=MineGasCategory.HIGH,
                location=MethaneLocation.TOTAL_RETURN_AIR,
                alarm_pct=0.75,
            ),
        ),
    )


DEFAULT_RULE_SNAPSHOT = build_default_rule_snapshot()


class SafetyStateCheckpoint(SafetyModel):
    """Dynamic state immediately before the latest observation.

    The checkpoint lets a higher revision of the latest source record replace
    the earlier value instead of being counted as another consecutive sample.
    """

    status: StateStatus = StateStatus.NORMAL
    active_level: AlertLevel | None = None
    candidate_level: AlertLevel | None = None
    candidate_count: Annotated[int, Field(ge=0)] = 0
    clear_count: Annotated[int, Field(ge=0)] = 0
    methane_overlimit_count: Annotated[int, Field(ge=0)] = 0
    recovery_below_count: Annotated[int, Field(ge=0)] = 0
    cutoff_latched: bool = False
    trigger_codes: tuple[
        Annotated[str, Field(min_length=1, max_length=100)], ...
    ] = ()
    last_value: Annotated[
        float | None, Field(ge=0.0, le=MAX_MEASUREMENT)
    ] = None
    last_observed_at: AwareDatetime | None = None
    last_revision: Annotated[int, Field(ge=0)] = 0
    activated_at: AwareDatetime | None = None


class SafetySignalState(SafetyModel):
    state_key: Annotated[str, Field(min_length=1, max_length=500)]
    mine_id: Annotated[str, Field(min_length=1, max_length=200)]
    scope: SafetyScope
    point_id: Annotated[str | None, Field(min_length=1, max_length=200)] = None
    status: StateStatus = StateStatus.NORMAL
    active_level: AlertLevel | None = None
    candidate_level: AlertLevel | None = None
    candidate_count: Annotated[int, Field(ge=0)] = 0
    clear_count: Annotated[int, Field(ge=0)] = 0
    methane_overlimit_count: Annotated[int, Field(ge=0)] = 0
    recovery_below_count: Annotated[int, Field(ge=0)] = 0
    cutoff_latched: bool = False
    trigger_codes: tuple[
        Annotated[str, Field(min_length=1, max_length=100)], ...
    ] = ()
    last_value: Annotated[
        float | None, Field(ge=0.0, le=MAX_MEASUREMENT)
    ] = None
    last_observed_at: AwareDatetime | None = None
    last_revision: Annotated[int, Field(ge=0)] = 0
    activated_at: AwareDatetime | None = None
    prior_checkpoint: SafetyStateCheckpoint | None = None
    evaluated_at: AwareDatetime
    rule_version: Annotated[str, Field(min_length=1, max_length=100)]
    rule_fingerprint: Annotated[
        str, Field(pattern=r"^[0-9a-f]{64}$")
    ]

    @model_validator(mode="after")
    def validate_state(self) -> "SafetySignalState":
        if self.status is StateStatus.ACTIVE and self.active_level is None:
            raise ValueError("active state requires active_level")
        if self.status is not StateStatus.ACTIVE and self.active_level is not None:
            raise ValueError("only active state may contain active_level")
        if self.point_id is None and self.scope is not SafetyScope.PERSONNEL:
            raise ValueError("methane and ventilation states require point_id")
        if self.scope is SafetyScope.PERSONNEL and self.point_id is not None:
            raise ValueError("personnel state must not contain point_id")
        if len(self.trigger_codes) != len(set(self.trigger_codes)):
            raise ValueError("trigger_codes must be unique")
        if (self.last_value is None) != (self.last_observed_at is None):
            raise ValueError(
                "last_value and last_observed_at must be populated together"
            )
        if self.last_value is None and self.last_revision != 0:
            raise ValueError(
                "state without a last value must use revision zero"
            )
        if (
            self.last_observed_at is not None
            and self.last_observed_at > self.evaluated_at
        ):
            raise ValueError(
                "last_observed_at must not be later than evaluated_at"
            )
        if self.status is StateStatus.ACTIVE and self.activated_at is None:
            raise ValueError("active state requires activated_at")
        if (
            self.activated_at is not None
            and self.activated_at > self.evaluated_at
        ):
            raise ValueError("activated_at must not be later than evaluated_at")
        if self.cutoff_latched and self.scope is not SafetyScope.METHANE:
            raise ValueError("cutoff_latched is only valid for methane state")
        return self


def _state_checkpoint(state: SafetySignalState) -> SafetyStateCheckpoint:
    return SafetyStateCheckpoint(
        status=state.status,
        active_level=state.active_level,
        candidate_level=state.candidate_level,
        candidate_count=state.candidate_count,
        clear_count=state.clear_count,
        methane_overlimit_count=state.methane_overlimit_count,
        recovery_below_count=state.recovery_below_count,
        cutoff_latched=state.cutoff_latched,
        trigger_codes=state.trigger_codes,
        last_value=state.last_value,
        last_observed_at=state.last_observed_at,
        last_revision=state.last_revision,
        activated_at=state.activated_at,
    )


def _restore_checkpoint(
    state: SafetySignalState,
    *,
    evaluated_at: datetime,
) -> SafetySignalState:
    checkpoint = state.prior_checkpoint
    if checkpoint is None:
        return state
    return SafetySignalState(
        state_key=state.state_key,
        mine_id=state.mine_id,
        scope=state.scope,
        point_id=state.point_id,
        **checkpoint.model_dump(),
        evaluated_at=evaluated_at,
        rule_version=state.rule_version,
        rule_fingerprint=state.rule_fingerprint,
    )


class SafetyEvaluationRequest(SafetyModel):
    profile: MineSafetyProfile
    decision_time: AwareDatetime
    rules: SafetyRuleSnapshot = Field(
        default_factory=build_default_rule_snapshot
    )
    observations: tuple[SafetyObservation, ...]
    previous_states: tuple[SafetySignalState, ...] = ()

    @model_validator(mode="after")
    def validate_request(self) -> "SafetyEvaluationRequest":
        if self.decision_time < self.rules.effective_from:
            raise ValueError("rules are not effective at decision_time")
        if (
            self.rules.effective_to is not None
            and self.decision_time >= self.rules.effective_to
        ):
            raise ValueError("rules have expired at decision_time")
        observation_ids = [
            observation.observation_id for observation in self.observations
        ]
        if len(observation_ids) != len(set(observation_ids)):
            raise ValueError("observation_id values must be unique")
        state_keys = [state.state_key for state in self.previous_states]
        if len(state_keys) != len(set(state_keys)):
            raise ValueError("previous state_key values must be unique")
        for observation in self.observations:
            if observation.mine_id != self.profile.mine_id:
                raise ValueError(
                    "all observations must belong to profile.mine_id"
                )
            if isinstance(observation, MethaneObservation):
                self.rules.threshold_for(
                    self.profile.gas_category,
                    observation.location,
                )
        for state in self.previous_states:
            if state.mine_id != self.profile.mine_id:
                raise ValueError(
                    "all previous states must belong to profile.mine_id"
                )
            if state.evaluated_at > self.decision_time:
                raise ValueError(
                    "previous state evaluated_at must not be in the future"
                )
            if (
                state.rule_version != self.rules.version
                or state.rule_fingerprint != self.rules.fingerprint
            ):
                raise ValueError(
                    "previous states must use the exact current rule snapshot"
                )
        return self


class SafetyDataIssue(SafetyModel):
    observation_id: Annotated[str, Field(min_length=1, max_length=200)]
    code: DataIssueCode
    explanation: Annotated[str, Field(min_length=1, max_length=1000)]


class SafetyTransitionEvent(SafetyModel):
    event_id: Annotated[str, Field(pattern=r"^safety_[0-9a-f]{24}$")]
    mine_id: Annotated[str, Field(min_length=1, max_length=200)]
    state_key: Annotated[str, Field(min_length=1, max_length=500)]
    point_id: Annotated[str | None, Field(min_length=1, max_length=200)] = None
    scope: SafetyScope
    transition: TransitionType
    previous_level: AlertLevel | None = None
    current_level: AlertLevel | None = None
    event_at: AwareDatetime
    generated_at: AwareDatetime
    trigger_codes: tuple[
        Annotated[str, Field(min_length=1, max_length=100)], ...
    ]
    evidence_observation_ids: tuple[
        Annotated[str, Field(min_length=1, max_length=200)], ...
    ]
    explanation: Annotated[str, Field(min_length=1, max_length=2000)]
    nature: Literal["technical_warning_clue"] = "technical_warning_clue"
    production_control_permitted: Literal[False] = False


class ActiveSafetyLead(SafetyModel):
    state_key: Annotated[str, Field(min_length=1, max_length=500)]
    mine_id: Annotated[str, Field(min_length=1, max_length=200)]
    scope: SafetyScope
    point_id: Annotated[str | None, Field(min_length=1, max_length=200)] = None
    level: AlertLevel
    trigger_codes: tuple[
        Annotated[str, Field(min_length=1, max_length=100)], ...
    ]
    latest_value: Annotated[float, Field(ge=0.0, le=MAX_MEASUREMENT)]
    observed_at: AwareDatetime
    recommended_review: Annotated[str, Field(min_length=1, max_length=1000)]
    advisory_only: Literal[True] = True


class SafetyEvaluationResult(SafetyModel):
    mine_id: Annotated[str, Field(min_length=1, max_length=200)]
    decision_time: AwareDatetime
    rule_version: Annotated[str, Field(min_length=1, max_length=100)]
    rule_fingerprint: Annotated[
        str, Field(pattern=r"^[0-9a-f]{64}$")
    ]
    accepted_observation_ids: tuple[
        Annotated[str, Field(min_length=1, max_length=200)], ...
    ]
    rejected_observations: tuple[SafetyDataIssue, ...]
    states: tuple[SafetySignalState, ...]
    events: tuple[SafetyTransitionEvent, ...]
    active_leads: tuple[ActiveSafetyLead, ...]
    advisory_only: Literal[True] = True
    production_control_actions: Literal[0] = 0


def _state_key(observation: SafetyObservation) -> str:
    if isinstance(observation, PersonnelObservation):
        return "personnel"
    if isinstance(observation, MethaneObservation):
        return f"methane:{observation.point_id}"
    return f"ventilation:{observation.point_id}"


def _scope(observation: SafetyObservation) -> SafetyScope:
    if isinstance(observation, PersonnelObservation):
        return SafetyScope.PERSONNEL
    if isinstance(observation, MethaneObservation):
        return SafetyScope.METHANE
    return SafetyScope.VENTILATION


def _point_id(observation: SafetyObservation) -> str | None:
    if isinstance(observation, PersonnelObservation):
        return None
    return observation.point_id


def _make_initial_state(
    observation: SafetyObservation,
    request: SafetyEvaluationRequest,
) -> SafetySignalState:
    return SafetySignalState(
        state_key=_state_key(observation),
        mine_id=request.profile.mine_id,
        scope=_scope(observation),
        point_id=_point_id(observation),
        evaluated_at=request.decision_time,
        rule_version=request.rules.version,
        rule_fingerprint=request.rules.fingerprint,
    )


def _event(
    *,
    request: SafetyEvaluationRequest,
    state: SafetySignalState,
    observation: SafetyObservation,
    transition: TransitionType,
    previous_level: AlertLevel | None,
    current_level: AlertLevel | None,
    trigger_codes: tuple[str, ...],
    explanation: str,
) -> SafetyTransitionEvent:
    identity = "|".join(
        (
            request.rules.fingerprint,
            state.state_key,
            transition.value,
            observation.observation_id,
            str(observation.revision),
            observation.observed_at.astimezone(UTC).isoformat(),
            current_level.value if current_level else "none",
        )
    )
    event_id = f"safety_{sha256(identity.encode('utf-8')).hexdigest()[:24]}"
    return SafetyTransitionEvent(
        event_id=event_id,
        mine_id=request.profile.mine_id,
        state_key=state.state_key,
        point_id=state.point_id,
        scope=state.scope,
        transition=transition,
        previous_level=previous_level,
        current_level=current_level,
        event_at=observation.observed_at,
        generated_at=request.decision_time,
        trigger_codes=trigger_codes,
        evidence_observation_ids=(observation.observation_id,),
        explanation=explanation,
    )


def _level_max(
    first: AlertLevel | None,
    second: AlertLevel | None,
) -> AlertLevel | None:
    if first is None:
        return second
    if second is None:
        return first
    return first if _LEVEL_RANK[first] >= _LEVEL_RANK[second] else second


def _upgrade(level: AlertLevel) -> AlertLevel:
    if level is AlertLevel.BLUE:
        return AlertLevel.YELLOW
    if level is AlertLevel.YELLOW:
        return AlertLevel.ORANGE
    return AlertLevel.RED


def _personnel_candidate(
    observation: PersonnelObservation,
    request: SafetyEvaluationRequest,
) -> tuple[AlertLevel | None, tuple[str, ...]]:
    ratio = observation.value / request.profile.approved_personnel_capacity
    threshold = request.rules.personnel
    if ratio >= threshold.overcapacity_ratio:
        return AlertLevel.ORANGE, ("personnel_capacity_reached",)
    if ratio >= threshold.warning_ratio:
        return AlertLevel.YELLOW, ("personnel_warning_90pct",)
    if ratio >= threshold.attention_ratio:
        return AlertLevel.BLUE, ("personnel_attention_80pct",)
    return None, ()


def _methane_candidate(
    observation: MethaneObservation,
    state: SafetySignalState,
    request: SafetyEvaluationRequest,
) -> tuple[
    AlertLevel | None,
    tuple[str, ...],
    int,
    bool,
    float | None,
]:
    threshold = request.rules.threshold_for(
        request.profile.gas_category,
        observation.location,
    )
    level: AlertLevel | None = None
    codes: list[str] = []
    if (
        threshold.cutoff_pct is not None
        and observation.value >= threshold.cutoff_pct
    ):
        level = AlertLevel.ORANGE
        codes.append("methane_cutoff_threshold")
    elif observation.value >= threshold.alarm_pct:
        level = AlertLevel.YELLOW
        codes.append("methane_alarm_threshold")
    elif (
        threshold.trend_pct is not None
        and observation.value >= threshold.trend_pct
    ):
        level = AlertLevel.BLUE
        codes.append("methane_trend_threshold")

    overlimit_count = (
        state.methane_overlimit_count + 1
        if observation.value >= threshold.alarm_pct
        else 0
    )
    if overlimit_count >= request.rules.debounce.methane_red_after_consecutive:
        level = AlertLevel.RED
        codes.append("methane_sustained_overlimit")

    delta = (
        observation.value - state.last_value
        if state.last_value is not None
        else None
    )
    major_change = (
        delta is not None
        and abs(delta) > request.rules.methane_major_change_pct_points
    )
    if major_change and delta is not None and delta > 0:
        level = _level_max(level, AlertLevel.ORANGE)
        codes.append("methane_major_increase")

    return level, tuple(dict.fromkeys(codes)), overlimit_count, (
        major_change
    ), delta


def _ventilation_candidate(
    observation: VentilationObservation,
    state: SafetySignalState,
    request: SafetyEvaluationRequest,
    methane_rises: tuple[tuple[datetime, str, float], ...],
) -> tuple[
    AlertLevel | None,
    tuple[str, ...],
    float | None,
]:
    if state.last_value is None or state.last_value <= 0:
        return None, (), None
    drop_ratio = (state.last_value - observation.value) / state.last_value
    if drop_ratio <= request.rules.ventilation.sudden_drop_ratio:
        return None, (), drop_ratio

    if drop_ratio > request.rules.ventilation.severe_drop_ratio:
        level = AlertLevel.RED
        codes = ["ventilation_severe_drop"]
    else:
        level = AlertLevel.YELLOW
        codes = ["ventilation_sudden_drop"]

    joint_window = request.rules.joint.window_seconds
    simultaneous = any(
        abs((observation.observed_at - rise_time).total_seconds())
        <= joint_window
        and rise > request.rules.joint.methane_minimum_rise_pct_points
        for rise_time, _, rise in methane_rises
    )
    if simultaneous:
        level = _upgrade(level)
        codes.append("ventilation_methane_joint")
    return level, tuple(codes), drop_ratio


def _transition_explanation(
    transition: TransitionType,
    level: AlertLevel | None,
    codes: tuple[str, ...],
) -> str:
    level_text = level.value if level is not None else "normal"
    if transition is TransitionType.RECOVERY_ELIGIBLE:
        return (
            "甲烷浓度已连续低于规则快照的复电判据，仅形成具备人工"
            "复核条件的技术线索；系统不执行复电或其他生产控制。"
        )
    if transition is TransitionType.METHANE_MAJOR_CHANGE:
        return (
            "相邻有效甲烷读数变化量超过规则阈值，形成重大变化报告"
            "线索；须核对传感器、原始记录和现场情况。"
        )
    if transition is TransitionType.CLEARED:
        return (
            "指标连续回落并满足去抖清除条件，预警线索状态已清除；"
            "不代表监管结论或自动复产、复电许可。"
        )
    return (
        f"状态变更为 {level_text}，触发依据：{', '.join(codes)}。"
        "这是待人工核查的技术预警线索，不执行断电、停产、撤人、"
        "复电或复产。"
    )


def _advance_state(
    *,
    observation: SafetyObservation,
    state: SafetySignalState,
    candidate_level: AlertLevel | None,
    trigger_codes: tuple[str, ...],
    request: SafetyEvaluationRequest,
    methane_overlimit_count: int = 0,
    cutoff_now: bool = False,
    reset_below: bool = False,
) -> tuple[SafetySignalState, tuple[SafetyTransitionEvent, ...]]:
    policy = request.rules.debounce
    previous_level = state.active_level
    active_level = state.active_level
    activated_at = state.activated_at
    events: list[SafetyTransitionEvent] = []

    if candidate_level is None:
        candidate_count = 0
    elif candidate_level == state.candidate_level:
        candidate_count = state.candidate_count + 1
    else:
        candidate_count = 1

    clear_count = state.clear_count
    transition: TransitionType | None = None
    if active_level is None:
        clear_count = 0
        if (
            candidate_level is not None
            and candidate_count >= policy.activate_after_consecutive
        ):
            active_level = candidate_level
            activated_at = observation.observed_at
            transition = TransitionType.OPENED
    elif candidate_level is None:
        clear_count += 1
        if clear_count >= policy.clear_after_consecutive:
            active_level = None
            activated_at = None
            clear_count = 0
            transition = TransitionType.CLEARED
    elif _LEVEL_RANK[candidate_level] > _LEVEL_RANK[active_level]:
        clear_count = 0
        if candidate_count >= policy.activate_after_consecutive:
            active_level = candidate_level
            transition = TransitionType.ESCALATED
    elif _LEVEL_RANK[candidate_level] < _LEVEL_RANK[active_level]:
        clear_count += 1
        if clear_count >= policy.clear_after_consecutive:
            active_level = candidate_level
            clear_count = 0
            transition = TransitionType.DEESCALATED
    else:
        clear_count = 0

    cutoff_latched = state.cutoff_latched or cutoff_now
    recovery_below_count = state.recovery_below_count
    recovery_eligible = False
    if cutoff_latched:
        if reset_below:
            recovery_below_count += 1
            if recovery_below_count >= policy.clear_after_consecutive:
                cutoff_latched = False
                recovery_below_count = 0
                recovery_eligible = True
        else:
            recovery_below_count = 0

    status = (
        StateStatus.ACTIVE
        if active_level is not None
        else (
            StateStatus.PENDING
            if candidate_level is not None and candidate_count > 0
            else StateStatus.NORMAL
        )
    )
    if active_level is None:
        active_trigger_codes: tuple[str, ...] = ()
    elif (
        transition
        in {
            TransitionType.OPENED,
            TransitionType.ESCALATED,
            TransitionType.DEESCALATED,
        }
        or candidate_level == active_level
    ):
        active_trigger_codes = trigger_codes
    else:
        active_trigger_codes = state.trigger_codes

    new_state = SafetySignalState(
        state_key=state.state_key,
        mine_id=state.mine_id,
        scope=state.scope,
        point_id=state.point_id,
        status=status,
        active_level=active_level,
        candidate_level=candidate_level,
        candidate_count=candidate_count,
        clear_count=clear_count,
        methane_overlimit_count=methane_overlimit_count,
        recovery_below_count=recovery_below_count,
        cutoff_latched=cutoff_latched,
        trigger_codes=active_trigger_codes,
        last_value=float(observation.value),
        last_observed_at=observation.observed_at,
        last_revision=observation.revision,
        activated_at=activated_at,
        prior_checkpoint=_state_checkpoint(state),
        evaluated_at=request.decision_time,
        rule_version=request.rules.version,
        rule_fingerprint=request.rules.fingerprint,
    )
    if transition is not None:
        events.append(
            _event(
                request=request,
                state=new_state,
                observation=observation,
                transition=transition,
                previous_level=previous_level,
                current_level=active_level,
                trigger_codes=trigger_codes,
                explanation=_transition_explanation(
                    transition, active_level, trigger_codes
                ),
            )
        )
    if recovery_eligible:
        events.append(
            _event(
                request=request,
                state=new_state,
                observation=observation,
                transition=TransitionType.RECOVERY_ELIGIBLE,
                previous_level=previous_level,
                current_level=active_level,
                trigger_codes=("methane_below_reset_threshold",),
                explanation=_transition_explanation(
                    TransitionType.RECOVERY_ELIGIBLE,
                    active_level,
                    ("methane_below_reset_threshold",),
                ),
            )
        )
    return new_state, tuple(events)


def _validate_observation(
    observation: SafetyObservation,
    request: SafetyEvaluationRequest,
) -> SafetyDataIssue | None:
    if (
        observation.observed_at > request.decision_time
        or observation.received_at > request.decision_time
    ):
        return SafetyDataIssue(
            observation_id=observation.observation_id,
            code=DataIssueCode.FUTURE_OBSERVATION,
            explanation=(
                "observation or availability time is after decision_time; "
                "excluded to prevent future leakage"
            ),
        )
    age = (request.decision_time - observation.observed_at).total_seconds()
    if age > request.rules.data_validation.maximum_age_seconds:
        return SafetyDataIssue(
            observation_id=observation.observation_id,
            code=DataIssueCode.STALE_OBSERVATION,
            explanation="observation exceeds the configured maximum age",
        )
    quality = observation.quality
    if (
        quality.score < request.rules.data_validation.minimum_quality
        or not quality.complete
        or not quality.device_healthy
        or not quality.clock_synchronised
        or quality.blocking_flags
    ):
        return SafetyDataIssue(
            observation_id=observation.observation_id,
            code=DataIssueCode.LOW_QUALITY,
            explanation=(
                "observation failed the configured quality gate or contains "
                "a blocking quality flag"
            ),
        )
    if not observation.source.signature_valid:
        return SafetyDataIssue(
            observation_id=observation.observation_id,
            code=DataIssueCode.INVALID_SOURCE,
            explanation="source signature is not valid",
        )
    return None


def _recommended_review(level: AlertLevel) -> str:
    if level is AlertLevel.BLUE:
        return "持续观察并核对原始监测记录。"
    if level is AlertLevel.YELLOW:
        return "尽快组织人工核查并记录处置反馈。"
    if level is AlertLevel.ORANGE:
        return "立即组织有权人员核查，并按适用规程人工处置。"
    return "立即升级人工研判和应急核查，并按适用规程处置。"


def evaluate_safety(
    request: SafetyEvaluationRequest,
) -> SafetyEvaluationResult:
    """Evaluate safety observations without hidden state or future leakage."""

    if not isinstance(request, SafetyEvaluationRequest):
        raise TypeError("request must be a SafetyEvaluationRequest")

    states = {state.state_key: state for state in request.previous_states}
    issues: list[SafetyDataIssue] = []
    accepted: list[SafetyObservation] = []
    for observation in request.observations:
        issue = _validate_observation(observation, request)
        if issue is None:
            accepted.append(observation)
        else:
            issues.append(issue)

    # Stable sorting makes output independent of caller batch ordering.
    accepted.sort(
        key=lambda item: (
            item.observed_at.astimezone(UTC),
            item.revision,
            item.received_at.astimezone(UTC),
            item.observation_id,
        )
    )

    usable: list[SafetyObservation] = []
    latest_by_key = {
        key: (state.last_observed_at, state.last_revision)
        for key, state in states.items()
    }
    for observation in accepted:
        key = _state_key(observation)
        last_position = latest_by_key.get(key)
        out_of_order = (
            last_position is not None
            and last_position[0] is not None
            and (
                observation.observed_at < last_position[0]
                or (
                    observation.observed_at == last_position[0]
                    and observation.revision <= last_position[1]
                )
            )
        )
        if out_of_order:
            issues.append(
                SafetyDataIssue(
                    observation_id=observation.observation_id,
                    code=DataIssueCode.OUT_OF_ORDER,
                    explanation=(
                        "observation time/revision is not later than the "
                        "persisted state and was not reprocessed"
                    ),
                )
            )
            continue
        usable.append(observation)
        latest_by_key[key] = (
            observation.observed_at,
            observation.revision,
        )

    # Precompute only as-of-valid methane rises.  This permits correlation
    # whether methane or ventilation arrived first while never seeing data
    # beyond decision_time.
    methane_by_key: dict[str, list[MethaneObservation]] = defaultdict(list)
    for observation in usable:
        if isinstance(observation, MethaneObservation):
            methane_by_key[_state_key(observation)].append(observation)
    methane_rises: list[tuple[datetime, str, float]] = []
    for key, observations in methane_by_key.items():
        persisted_state = states.get(key)
        previous_value = (
            persisted_state.last_value
            if persisted_state is not None
            else None
        )
        if (
            persisted_state is not None
            and observations
            and persisted_state.last_observed_at
            == observations[0].observed_at
            and observations[0].revision > persisted_state.last_revision
            and persisted_state.prior_checkpoint is not None
        ):
            previous_value = persisted_state.prior_checkpoint.last_value
        for observation in observations:
            if previous_value is not None:
                rise = observation.value - previous_value
                if (
                    rise
                    > request.rules.joint.methane_minimum_rise_pct_points
                ):
                    methane_rises.append(
                        (
                            observation.observed_at,
                            observation.observation_id,
                            rise,
                        )
                    )
            previous_value = observation.value
    methane_rise_tuple = tuple(methane_rises)

    events: list[SafetyTransitionEvent] = []
    for observation in usable:
        key = _state_key(observation)
        state = states.get(key) or _make_initial_state(observation, request)
        if (
            state.last_observed_at == observation.observed_at
            and observation.revision > state.last_revision
        ):
            state = _restore_checkpoint(
                state,
                evaluated_at=request.decision_time,
            )
        if isinstance(observation, PersonnelObservation):
            candidate, codes = _personnel_candidate(observation, request)
            state, new_events = _advance_state(
                observation=observation,
                state=state,
                candidate_level=candidate,
                trigger_codes=codes,
                request=request,
            )
        elif isinstance(observation, MethaneObservation):
            (
                candidate,
                codes,
                overlimit_count,
                major_change,
                delta,
            ) = _methane_candidate(observation, state, request)
            threshold = request.rules.threshold_for(
                request.profile.gas_category,
                observation.location,
            )
            cutoff_now = (
                threshold.cutoff_pct is not None
                and observation.value >= threshold.cutoff_pct
            )
            reset_below = (
                threshold.reset_below_pct is not None
                and observation.value < threshold.reset_below_pct
            )
            state, new_events = _advance_state(
                observation=observation,
                state=state,
                candidate_level=candidate,
                trigger_codes=codes,
                request=request,
                methane_overlimit_count=overlimit_count,
                cutoff_now=cutoff_now,
                reset_below=reset_below,
            )
            if major_change:
                direction = "increase" if (delta or 0.0) > 0 else "decrease"
                new_events = (
                    *new_events,
                    _event(
                        request=request,
                        state=state,
                        observation=observation,
                        transition=TransitionType.METHANE_MAJOR_CHANGE,
                        previous_level=state.active_level,
                        current_level=state.active_level,
                        trigger_codes=(
                            f"methane_major_{direction}",
                        ),
                        explanation=_transition_explanation(
                            TransitionType.METHANE_MAJOR_CHANGE,
                            state.active_level,
                            (f"methane_major_{direction}",),
                        ),
                    ),
                )
        else:
            candidate, codes, _ = _ventilation_candidate(
                observation,
                state,
                request,
                methane_rise_tuple,
            )
            state, new_events = _advance_state(
                observation=observation,
                state=state,
                candidate_level=candidate,
                trigger_codes=codes,
                request=request,
            )
        states[key] = state
        events.extend(new_events)

    ordered_states = tuple(states[key] for key in sorted(states))
    active_leads = tuple(
        ActiveSafetyLead(
            state_key=state.state_key,
            mine_id=state.mine_id,
            scope=state.scope,
            point_id=state.point_id,
            level=state.active_level,
            trigger_codes=state.trigger_codes,
            latest_value=state.last_value,
            observed_at=state.last_observed_at,
            recommended_review=_recommended_review(state.active_level),
        )
        for state in ordered_states
        if (
            state.status is StateStatus.ACTIVE
            and state.active_level is not None
            and state.last_value is not None
            and state.last_observed_at is not None
        )
    )
    return SafetyEvaluationResult(
        mine_id=request.profile.mine_id,
        decision_time=request.decision_time,
        rule_version=request.rules.version,
        rule_fingerprint=request.rules.fingerprint,
        accepted_observation_ids=tuple(
            observation.observation_id for observation in usable
        ),
        rejected_observations=tuple(issues),
        states=ordered_states,
        events=tuple(events),
        active_leads=active_leads,
    )


__all__ = [
    "ActiveSafetyLead",
    "AlertLevel",
    "DataIssueCode",
    "DataValidationPolicy",
    "DEFAULT_RULE_SNAPSHOT",
    "DebouncePolicy",
    "JointRiskPolicy",
    "MainFanPolicy",
    "MeasurementQuality",
    "MeasurementUnit",
    "MethaneLocation",
    "MethaneObservation",
    "MethaneThreshold",
    "MineGasCategory",
    "MineSafetyProfile",
    "ObservationSource",
    "PersonnelObservation",
    "PersonnelThresholds",
    "SafetyDataIssue",
    "SafetyEvaluationRequest",
    "SafetyEvaluationResult",
    "SafetyMetric",
    "SafetyRuleSnapshot",
    "SafetyScope",
    "SafetySignalState",
    "SafetyStateCheckpoint",
    "SafetyTransitionEvent",
    "SourceChannel",
    "StateStatus",
    "TransitionType",
    "VentilationObservation",
    "VentilationThresholds",
    "build_default_rule_snapshot",
    "evaluate_safety",
]
