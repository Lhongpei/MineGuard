from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mineguard.safety import (
    DEFAULT_RULE_SNAPSHOT,
    AlertLevel,
    DataIssueCode,
    DebouncePolicy,
    MeasurementQuality,
    MeasurementUnit,
    MethaneLocation,
    MethaneObservation,
    MineGasCategory,
    MineSafetyProfile,
    ObservationSource,
    PersonnelObservation,
    SafetyEvaluationRequest,
    SourceChannel,
    StateStatus,
    TransitionType,
    VentilationObservation,
    build_default_rule_snapshot,
    evaluate_safety,
)


BASE = datetime(2026, 7, 28, 8, 0, tzinfo=UTC)
SOURCE = ObservationSource(
    source_id="system-1",
    system_name="矿井监测系统",
    channel=SourceChannel.AUTOMATIC,
    lineage_ref="raw://system-1/2026-07-28",
)
LOW_PROFILE = MineSafetyProfile(
    mine_id="mine-1",
    gas_category=MineGasCategory.LOW,
    approved_personnel_capacity=100,
)
HIGH_PROFILE = MineSafetyProfile(
    mine_id="mine-1",
    gas_category=MineGasCategory.HIGH,
    approved_personnel_capacity=100,
)


def _personnel(
    observation_id: str,
    value: int,
    *,
    minute: int = 0,
    revision: int = 0,
    quality: MeasurementQuality | None = None,
    source: ObservationSource = SOURCE,
) -> PersonnelObservation:
    timestamp = BASE + timedelta(minutes=minute)
    return PersonnelObservation(
        observation_id=observation_id,
        mine_id="mine-1",
        observed_at=timestamp,
        received_at=timestamp,
        revision=revision,
        source=source,
        quality=quality or MeasurementQuality(),
        value=value,
    )


def _methane(
    observation_id: str,
    value: float,
    *,
    minute: int = 0,
    location: MethaneLocation = MethaneLocation.WORKING_FACE_T1,
    point_id: str = "ch4-1",
) -> MethaneObservation:
    timestamp = BASE + timedelta(minutes=minute)
    return MethaneObservation(
        observation_id=observation_id,
        mine_id="mine-1",
        observed_at=timestamp,
        received_at=timestamp,
        source=SOURCE,
        point_id=point_id,
        location=location,
        value=value,
    )


def _ventilation(
    observation_id: str,
    value: float,
    *,
    minute: int = 0,
    point_id: str = "fan-1",
) -> VentilationObservation:
    timestamp = BASE + timedelta(minutes=minute)
    return VentilationObservation(
        observation_id=observation_id,
        mine_id="mine-1",
        observed_at=timestamp,
        received_at=timestamp,
        source=SOURCE,
        point_id=point_id,
        value=value,
    )


def _evaluate(
    *observations: PersonnelObservation
    | MethaneObservation
    | VentilationObservation,
    profile: MineSafetyProfile = LOW_PROFILE,
    minute: int = 10,
    rules=DEFAULT_RULE_SNAPSHOT,
    previous_states=(),
):
    return evaluate_safety(
        SafetyEvaluationRequest(
            profile=profile,
            decision_time=BASE + timedelta(minutes=minute),
            rules=rules,
            observations=tuple(observations),
            previous_states=tuple(previous_states),
        )
    )


def test_default_snapshot_reproduces_proposal_table_and_is_versioned() -> None:
    rules = DEFAULT_RULE_SNAPSHOT

    low_t1 = rules.threshold_for(
        MineGasCategory.LOW, MethaneLocation.WORKING_FACE_T1
    )
    low_t2 = rules.threshold_for(
        MineGasCategory.LOW, MethaneLocation.RETURN_AIR_T2
    )
    high_t2 = rules.threshold_for(
        MineGasCategory.HIGH, MethaneLocation.RETURN_AIR_T2
    )
    total_return = rules.threshold_for(
        MineGasCategory.HIGH, MethaneLocation.TOTAL_RETURN_AIR
    )

    assert (low_t1.alarm_pct, low_t1.cutoff_pct, low_t1.reset_below_pct) == (
        1.0,
        1.5,
        1.0,
    )
    assert (low_t2.alarm_pct, low_t2.cutoff_pct) == (1.0, 1.0)
    assert high_t2.trend_pct == 0.75
    assert total_return.alarm_pct == 0.75
    assert total_return.cutoff_pct is None
    assert rules.version == "qinyuan-safety-2026.07-v2"
    assert len(rules.fingerprint) == 64
    assert (
        build_default_rule_snapshot(version="approved-v2").fingerprint
        != rules.fingerprint
    )


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (79, None),
        (80, AlertLevel.BLUE),
        (89, AlertLevel.BLUE),
        (90, AlertLevel.YELLOW),
        (99, AlertLevel.YELLOW),
        (100, AlertLevel.ORANGE),
    ],
)
def test_personnel_boundaries_are_inclusive(
    count: int,
    expected: AlertLevel | None,
) -> None:
    result = _evaluate(_personnel(f"p-{count}", count))

    assert result.states[0].active_level == expected
    assert [lead.level for lead in result.active_leads] == (
        [] if expected is None else [expected]
    )


@pytest.mark.parametrize(
    ("profile", "location", "value", "expected"),
    [
        (
            LOW_PROFILE,
            MethaneLocation.WORKING_FACE_T1,
            0.999,
            None,
        ),
        (
            LOW_PROFILE,
            MethaneLocation.WORKING_FACE_T1,
            1.0,
            AlertLevel.YELLOW,
        ),
        (
            LOW_PROFILE,
            MethaneLocation.WORKING_FACE_T1,
            1.5,
            AlertLevel.ORANGE,
        ),
        (
            LOW_PROFILE,
            MethaneLocation.RETURN_AIR_T2,
            1.0,
            AlertLevel.ORANGE,
        ),
        (
            HIGH_PROFILE,
            MethaneLocation.RETURN_AIR_T2,
            0.75,
            AlertLevel.BLUE,
        ),
        (
            HIGH_PROFILE,
            MethaneLocation.TOTAL_RETURN_AIR,
            0.75,
            AlertLevel.YELLOW,
        ),
    ],
)
def test_methane_alarm_cutoff_and_trend_boundaries(
    profile: MineSafetyProfile,
    location: MethaneLocation,
    value: float,
    expected: AlertLevel | None,
) -> None:
    result = _evaluate(
        _methane("gas", value, location=location),
        profile=profile,
    )

    assert result.states[0].active_level == expected


def test_sustained_methane_overlimit_escalates_to_red() -> None:
    result = _evaluate(
        _methane("gas-1", 1.1, minute=1),
        _methane("gas-2", 1.1, minute=2),
        _methane("gas-3", 1.1, minute=3),
        profile=HIGH_PROFILE,
    )

    assert result.states[0].active_level is AlertLevel.RED
    assert [event.transition for event in result.events] == [
        TransitionType.OPENED,
        TransitionType.ESCALATED,
    ]
    assert "methane_sustained_overlimit" in result.active_leads[0].trigger_codes


def test_methane_major_change_is_strictly_over_point_two() -> None:
    result = _evaluate(
        _methane("gas-1", 0.50, minute=1),
        _methane("gas-2", 0.70, minute=2),
        _methane("gas-3", 0.91, minute=3),
        profile=HIGH_PROFILE,
    )

    reports = [
        event
        for event in result.events
        if event.transition is TransitionType.METHANE_MAJOR_CHANGE
    ]
    assert len(reports) == 1
    assert reports[0].evidence_observation_ids == ("gas-3",)
    assert result.states[0].active_level is AlertLevel.ORANGE


def test_ventilation_drop_is_strictly_over_fifteen_percent() -> None:
    exact = _evaluate(
        _ventilation("flow-1", 100.0, minute=1),
        _ventilation("flow-2", 85.0, minute=2),
    )
    over = _evaluate(
        _ventilation("flow-3", 100.0, minute=1),
        _ventilation("flow-4", 84.9, minute=2),
    )

    assert exact.states[0].active_level is None
    assert over.states[0].active_level is AlertLevel.YELLOW
    assert over.active_leads[0].trigger_codes == (
        "ventilation_sudden_drop",
    )


def test_synchronous_methane_rise_upgrades_ventilation_warning() -> None:
    result = _evaluate(
        _methane("gas-1", 0.20, minute=1),
        _ventilation("flow-1", 100.0, minute=1),
        _methane("gas-2", 0.30, minute=2),
        _ventilation("flow-2", 84.0, minute=2),
    )

    ventilation_state = next(
        state
        for state in result.states
        if state.state_key == "ventilation:fan-1"
    )
    assert ventilation_state.active_level is AlertLevel.ORANGE
    assert "ventilation_methane_joint" in ventilation_state.trigger_codes


def test_future_data_is_rejected_and_cannot_change_result() -> None:
    future = _methane("future-gas", 5.0, minute=11)
    result = _evaluate(
        _methane("gas-now", 0.2, minute=1),
        _ventilation("flow-1", 100.0, minute=1),
        _ventilation("flow-2", 84.0, minute=2),
        future,
        minute=10,
    )

    ventilation_state = next(
        state
        for state in result.states
        if state.state_key == "ventilation:fan-1"
    )
    assert ventilation_state.active_level is AlertLevel.YELLOW
    assert "future-gas" not in result.accepted_observation_ids
    assert result.rejected_observations[-1].code is (
        DataIssueCode.FUTURE_OBSERVATION
    )


def test_units_timezone_shape_and_supported_location_are_strict() -> None:
    with pytest.raises(ValidationError):
        PersonnelObservation(
            observation_id="bad-unit",
            mine_id="mine-1",
            observed_at=BASE,
            received_at=BASE,
            source=SOURCE,
            value=1,
            unit=MeasurementUnit.PERCENT_CH4,
        )
    with pytest.raises(ValidationError):
        PersonnelObservation(
            observation_id="naive-time",
            mine_id="mine-1",
            observed_at=datetime(2026, 7, 28, 8, 0),
            received_at=datetime(2026, 7, 28, 8, 0),
            source=SOURCE,
            value=1,
        )
    with pytest.raises(ValidationError, match="observed_at"):
        PersonnelObservation(
            observation_id="reversed-time",
            mine_id="mine-1",
            observed_at=BASE + timedelta(seconds=1),
            received_at=BASE,
            source=SOURCE,
            value=1,
        )
    with pytest.raises(ValidationError):
        PersonnelObservation(
            observation_id="extra",
            mine_id="mine-1",
            observed_at=BASE,
            received_at=BASE,
            source=SOURCE,
            value=1,
            unknown=True,
        )
    with pytest.raises(ValidationError, match="no methane threshold"):
        SafetyEvaluationRequest(
            profile=LOW_PROFILE,
            decision_time=BASE + timedelta(minutes=1),
            observations=(
                _methane(
                    "unsupported",
                    0.1,
                    location=MethaneLocation.RETURN_AIR_MIDDLE,
                ),
            ),
        )


def test_quality_and_source_gates_reject_unreliable_values() -> None:
    unsigned = ObservationSource(
        source_id="unsigned",
        system_name="未验签系统",
        channel=SourceChannel.AUTOMATIC,
        lineage_ref="raw://unsigned",
        signature_valid=False,
    )
    result = _evaluate(
        _personnel(
            "low-quality",
            100,
            quality=MeasurementQuality(score=0.69),
        ),
        _personnel("unsigned", 100, minute=1, source=unsigned),
    )

    assert result.accepted_observation_ids == ()
    assert result.states == ()
    assert [issue.code for issue in result.rejected_observations] == [
        DataIssueCode.LOW_QUALITY,
        DataIssueCode.INVALID_SOURCE,
    ]


def test_cutoff_recovery_requires_two_values_strictly_below_reset() -> None:
    result = _evaluate(
        _methane("gas-cutoff", 1.5, minute=1),
        _methane("gas-equal-reset", 1.0, minute=2),
        _methane("gas-below-1", 0.99, minute=3),
        _methane("gas-below-2", 0.98, minute=4),
    )

    state = result.states[0]
    assert state.status is StateStatus.NORMAL
    assert state.active_level is None
    assert not state.cutoff_latched
    assert [
        event.transition for event in result.events
    ] == [
        TransitionType.OPENED,
        TransitionType.METHANE_MAJOR_CHANGE,
        TransitionType.CLEARED,
        TransitionType.RECOVERY_ELIGIBLE,
    ]
    recovery = result.events[-1]
    assert not recovery.production_control_permitted
    assert "不执行复电" in recovery.explanation


def test_state_round_trip_preserves_clear_debounce_across_calls() -> None:
    opened = _evaluate(
        _personnel("p-high", 90, minute=1),
        minute=1,
    )
    first_normal = _evaluate(
        _personnel("p-normal-1", 50, minute=2),
        minute=2,
        previous_states=opened.states,
    )
    cleared = _evaluate(
        _personnel("p-normal-2", 50, minute=3),
        minute=3,
        previous_states=first_normal.states,
    )

    assert opened.states[0].active_level is AlertLevel.YELLOW
    assert first_normal.states[0].active_level is AlertLevel.YELLOW
    assert first_normal.states[0].clear_count == 1
    assert cleared.states[0].active_level is None
    assert cleared.events[0].transition is TransitionType.CLEARED


def test_custom_debounce_and_snapshot_identity_are_enforced() -> None:
    rules = DEFAULT_RULE_SNAPSHOT.model_copy(
        update={
            "version": "approved-custom-v2",
            "debounce": DebouncePolicy(
                activate_after_consecutive=2,
                clear_after_consecutive=2,
                methane_red_after_consecutive=4,
            ),
        }
    )
    result = _evaluate(
        _personnel("p-1", 80, minute=1),
        _personnel("p-2", 80, minute=2),
        rules=rules,
    )

    assert result.states[0].active_level is AlertLevel.BLUE
    assert len(result.events) == 1
    assert result.rule_version == "approved-custom-v2"
    with pytest.raises(ValidationError, match="exact current rule snapshot"):
        SafetyEvaluationRequest(
            profile=LOW_PROFILE,
            decision_time=BASE + timedelta(minutes=11),
            rules=DEFAULT_RULE_SNAPSHOT,
            observations=(),
            previous_states=result.states,
        )


def test_duplicate_and_replayed_observations_are_not_processed() -> None:
    with pytest.raises(ValidationError, match="observation_id"):
        SafetyEvaluationRequest(
            profile=LOW_PROFILE,
            decision_time=BASE + timedelta(minutes=1),
            observations=(
                _personnel("duplicate", 80),
                _personnel("duplicate", 90),
            ),
        )

    initial = _evaluate(_personnel("first", 80, minute=1), minute=1)
    replay = _evaluate(
        _personnel("different-id-same-time", 100, minute=1),
        minute=2,
        previous_states=initial.states,
    )
    assert replay.accepted_observation_ids == ()
    assert replay.rejected_observations[0].code is DataIssueCode.OUT_OF_ORDER
    assert replay.states == initial.states


def test_higher_revision_replaces_latest_value_without_double_counting() -> None:
    opened = _evaluate(
        _personnel("correctable", 100, minute=1, revision=0),
        minute=1,
    )
    corrected = _evaluate(
        _personnel("correctable", 50, minute=1, revision=1),
        minute=2,
        previous_states=opened.states,
    )
    corrected_again = _evaluate(
        _personnel("correctable", 90, minute=1, revision=2),
        minute=3,
        previous_states=corrected.states,
    )

    assert opened.states[0].active_level is AlertLevel.ORANGE
    assert corrected.states[0].active_level is None
    assert corrected.states[0].candidate_count == 0
    assert corrected.states[0].last_revision == 1
    assert corrected.events == ()
    assert corrected_again.states[0].active_level is AlertLevel.YELLOW
    assert corrected_again.states[0].candidate_count == 1
    assert corrected_again.states[0].last_revision == 2
    assert [event.transition for event in corrected_again.events] == [
        TransitionType.OPENED
    ]


def test_every_output_is_advisory_and_contains_no_control_action() -> None:
    result = _evaluate(_methane("cutoff", 2.0, minute=1))

    assert result.advisory_only
    assert result.production_control_actions == 0
    assert all(lead.advisory_only for lead in result.active_leads)
    assert all(
        event.nature == "technical_warning_clue"
        and not event.production_control_permitted
        for event in result.events
    )
