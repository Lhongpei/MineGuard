from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import ValidationError
import pytest

from mineguard.verification import (
    EnergyDerivationBasis,
    EnergyRatioBand,
    EvidenceDirection,
    ExplosivesReading,
    HistoricalVerificationSample,
    HistoricalRarityBand,
    InterferenceCategory,
    InterferenceReading,
    ManualReviewLabel,
    OperatingCondition,
    ProductionVerificationRequest,
    RobustDeviationBand,
    TechnicalClueLevel,
    VerificationParameters,
    VerificationRequest,
    VerificationResult,
    VerificationStatus,
    analyze_verification,
    derive_net_production_electricity,
    verify_energy_and_explosives,
)
from mineguard.verification import ElectricityReading


CURRENT_START = datetime(2026, 7, 28, tzinfo=UTC)
CONDITION = OperatingCondition(
    regime_code="normal-production",
    mining_method="longwall",
    seam_code="3#",
    face_code="3101",
    shift_code="day",
    geology_zone="zone-a",
)
COMPATIBILITY_KEY = "test-schema-v1"


def _interference(
    *,
    amount: float = 10.0,
) -> list[InterferenceReading]:
    return [
        InterferenceReading(
            category=category,
            identifiable=True,
            electricity_kwh=amount,
            source_id=f"meter-{category.value}",
        )
        for category in InterferenceCategory
    ]


def _sample(
    index: int,
    *,
    energy_intensity: float = 100.0,
    explosives_intensity: float = 0.1,
    production_t: float = 100.0,
    mine_id: str = "M001",
    condition: OperatingCondition = CONDITION,
    window_end: datetime | None = None,
    available_at: datetime | None = None,
    reviewed_at: datetime | None = None,
    label: ManualReviewLabel = ManualReviewLabel.VERIFIED_NORMAL,
    human_reviewed: bool = True,
    review_confidence: float | None = 0.95,
    quality_score: float = 0.95,
    source_hash_valid: bool = True,
    compatibility_key: str = COMPATIBILITY_KEY,
    electricity: ElectricityReading | None = None,
) -> HistoricalVerificationSample:
    end = window_end or CURRENT_START - timedelta(days=100 - index)
    start = end - timedelta(days=1)
    available = available_at or end + timedelta(hours=1)
    reviewed = reviewed_at or end + timedelta(hours=2)
    if not human_reviewed:
        reviewed = None
        review_confidence = None
    return HistoricalVerificationSample(
        sample_id=f"sample-{index:03d}",
        mine_id=mine_id,
        window_start=start,
        window_end=end,
        available_at=available,
        operating_condition=condition,
        reported_production_t=production_t,
        electricity=electricity
        or ElectricityReading(
            source_id=f"energy-{index}",
            production_zone_kwh=energy_intensity * production_t,
        ),
        explosives=ExplosivesReading(
            explosives_used_kg=explosives_intensity * production_t,
            source_id=f"explosives-{index}",
        ),
        quality_score=quality_score,
        source_hash_valid=source_hash_valid,
        compatibility_key=compatibility_key,
        review_label=label,
        human_reviewed=human_reviewed,
        reviewed_by="reviewer" if human_reviewed else None,
        reviewed_at=reviewed,
        review_confidence=review_confidence,
    )


def _request(
    *,
    history: list[HistoricalVerificationSample] | None = None,
    production_t: float = 100.0,
    production_energy_kwh: float = 10_000.0,
    explosives_kg: float = 10.0,
    electricity: ElectricityReading | None = None,
    parameters: VerificationParameters | None = None,
) -> ProductionVerificationRequest:
    return ProductionVerificationRequest(
        request_id="request-001",
        mine_id="M001",
        window_start=CURRENT_START,
        window_end=CURRENT_START + timedelta(days=1),
        decision_time=CURRENT_START + timedelta(days=1, hours=1),
        operating_condition=CONDITION,
        reported_production_t=production_t,
        production_source_id="daily-report",
        electricity=electricity
        or ElectricityReading(
            source_id="current-production-meter",
            production_zone_kwh=production_energy_kwh,
        ),
        explosives=ExplosivesReading(
            explosives_used_kg=explosives_kg,
            source_id="public-security-ledger",
        ),
        history=history or [],
        parameters=parameters
        or VerificationParameters(
            minimum_samples=3,
            maximum_samples=100,
            compatibility_key=COMPATIBILITY_KEY,
        ),
    )


def _normal_history(count: int = 5) -> list[HistoricalVerificationSample]:
    return [_sample(index) for index in range(count)]


def test_models_are_strict_and_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        ExplosivesReading(
            explosives_used_kg="1.0",
            source_id="ledger",
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        OperatingCondition(
            regime_code="normal",
            mining_method="longwall",
            seam_code="3",
            face_code="3101",
            shift_code="day",
            geology_zone="a",
            unknown=True,
        )
    with pytest.raises(ValidationError):
        ProductionVerificationRequest(
            request_id="r",
            mine_id="m",
            window_start=datetime(2026, 1, 1),
            window_end=datetime(2026, 1, 2),
            decision_time=datetime(2026, 1, 3),
            operating_condition=CONDITION,
            reported_production_t=1.0,
            production_source_id="s",
            electricity=ElectricityReading(
                source_id="e",
                production_zone_kwh=1.0,
            ),
            explosives=ExplosivesReading(
                explosives_used_kg=1.0,
                source_id="x",
            ),
        )


def test_partition_meter_has_priority_over_total_and_interference() -> None:
    reading = ElectricityReading(
        source_id="partition-meter",
        production_zone_kwh=600.0,
        total_kwh=9_999.0,
        interference=[
            InterferenceReading(
                category=InterferenceCategory.VENTILATION,
                identifiable=False,
            )
        ],
    )

    result = derive_net_production_electricity(reading)

    assert result.status == "ready"
    assert result.basis is EnergyDerivationBasis.PARTITIONED_PRODUCTION_METER
    assert result.net_production_kwh == pytest.approx(600.0)
    assert result.excluded_kwh == pytest.approx(0.0)


def test_total_meter_requires_and_subtracts_all_interference() -> None:
    reading = ElectricityReading(
        source_id="total-meter",
        total_kwh=1_000.0,
        interference=_interference(amount=10.0),
    )

    result = derive_net_production_electricity(reading)

    assert result.status == "ready"
    assert (
        result.basis
        is EnergyDerivationBasis.TOTAL_LESS_EXPLICIT_INTERFERENCE
    )
    assert result.excluded_kwh == pytest.approx(50.0)
    assert result.net_production_kwh == pytest.approx(950.0)
    assert set(result.excluded_by_category) == set(InterferenceCategory)


def test_total_meter_fails_closed_for_missing_or_unidentifiable_load() -> None:
    incomplete = ElectricityReading(
        source_id="total-meter",
        total_kwh=1_000.0,
        interference=_interference()[:-1],
    )
    blocked_missing = derive_net_production_electricity(incomplete)
    assert blocked_missing.status == "blocked"
    assert blocked_missing.net_production_kwh is None
    assert "缺少干扰项" in blocked_missing.blocking_reasons[0]

    readings = _interference()
    readings[0] = InterferenceReading(
        category=readings[0].category,
        identifiable=False,
    )
    blocked_unknown = derive_net_production_electricity(
        ElectricityReading(
            source_id="total-meter",
            total_kwh=1_000.0,
            interference=readings,
        )
    )
    assert blocked_unknown.status == "blocked"
    assert any("不可识别" in item for item in blocked_unknown.blocking_reasons)


@pytest.mark.parametrize(
    ("ratio", "expected"),
    [
        (0.799, EnergyRatioBand.EXTREME_LOW),
        (0.8, EnergyRatioBand.ATTENTION_LOW),
        (0.899, EnergyRatioBand.ATTENTION_LOW),
        (0.9, EnergyRatioBand.NORMAL),
        (1.0, EnergyRatioBand.NORMAL),
        (1.1, EnergyRatioBand.NORMAL),
        (1.101, EnergyRatioBand.ATTENTION_HIGH),
        (1.3, EnergyRatioBand.ATTENTION_HIGH),
        (1.301, EnergyRatioBand.EXTREME_HIGH),
    ],
)
def test_plan_energy_ratio_boundaries(
    ratio: float,
    expected: EnergyRatioBand,
) -> None:
    result = verify_energy_and_explosives(
        _request(
            history=_normal_history(),
            production_energy_kwh=ratio * 100.0 * 100.0,
        )
    )

    assert result.status is VerificationStatus.READY
    assert result.energy is not None
    assert result.energy.verification_ratio == pytest.approx(ratio)
    assert result.energy.band is expected


def test_robust_baseline_resists_large_outlier() -> None:
    history = [
        _sample(0, energy_intensity=99.0, explosives_intensity=0.099),
        _sample(1, energy_intensity=100.0, explosives_intensity=0.1),
        _sample(2, energy_intensity=101.0, explosives_intensity=0.101),
        _sample(3, energy_intensity=100.0, explosives_intensity=0.1),
        _sample(4, energy_intensity=100_000.0, explosives_intensity=50.0),
    ]

    result = verify_energy_and_explosives(_request(history=history))

    assert result.baselines.energy is not None
    assert result.baselines.explosives is not None
    assert result.baselines.energy.median == pytest.approx(100.0)
    assert result.baselines.explosives.median == pytest.approx(0.1)
    assert result.energy is not None
    assert result.energy.band is EnergyRatioBand.NORMAL


def test_verified_normal_empirical_tail_detects_condition_specific_rarity() -> None:
    history = [
        _sample(index, energy_intensity=99.0 + index * 0.01)
        for index in range(40)
    ]

    result = verify_energy_and_explosives(
        _request(
            history=history,
            production_energy_kwh=101.0 * 100.0,
        )
    )

    assert result.energy is not None
    assert result.energy.band is EnergyRatioBand.NORMAL
    assert result.energy.historical_rarity.band is HistoricalRarityBand.RARE
    assert result.energy.historical_rarity.directional_tail_probability == (
        pytest.approx(1 / 41)
    )
    assert result.energy.direction is EvidenceDirection.HIGH
    assert result.energy.clue_level is TechnicalClueLevel.ELEVATED
    assert "不是违法、瞒报或责任概率" in result.energy.explanation


def test_empirical_tail_plus_one_correction_exposes_small_sample_uncertainty() -> None:
    result = verify_energy_and_explosives(
        _request(
            history=_normal_history(5),
            production_energy_kwh=101.0 * 100.0,
        )
    )

    assert result.energy is not None
    rarity = result.energy.historical_rarity
    assert rarity.directional_tail_probability == pytest.approx(1 / 6)
    assert rarity.band is HistoricalRarityBand.TYPICAL
    assert result.energy.direction is EvidenceDirection.NONE


def test_reference_pool_is_mine_condition_label_and_time_safe() -> None:
    other_condition = CONDITION.model_copy(update={"shift_code": "night"})
    valid = [_sample(index) for index in range(3)]
    rejected = [
        _sample(10, mine_id="M002"),
        _sample(11, condition=other_condition),
        _sample(
            12,
            label=ManualReviewLabel.TECHNICAL_ANOMALY,
        ),
        _sample(13, human_reviewed=False),
        _sample(14, review_confidence=0.85),
        _sample(15, quality_score=0.79),
        _sample(16, source_hash_valid=False),
        _sample(17, compatibility_key="old-schema"),
        _sample(
            18,
            window_end=CURRENT_START + timedelta(seconds=1),
            available_at=CURRENT_START + timedelta(hours=1),
            reviewed_at=CURRENT_START + timedelta(hours=2),
        ),
        _sample(
            19,
            window_end=CURRENT_START - timedelta(days=2),
            available_at=CURRENT_START + timedelta(seconds=1),
            reviewed_at=CURRENT_START + timedelta(hours=1),
        ),
        _sample(
            20,
            window_end=CURRENT_START - timedelta(days=2),
            available_at=CURRENT_START - timedelta(days=1),
            reviewed_at=CURRENT_START + timedelta(seconds=1),
        ),
    ]

    result = verify_energy_and_explosives(_request(history=valid + rejected))

    assert result.status is VerificationStatus.READY
    selection = result.baselines.selection
    assert selection.common_eligible_sample_count == 3
    assert selection.training_cutoff == CURRENT_START
    assert selection.exclusions == {
        "compatibility_mismatch": 1,
        "ineligible_review_label": 1,
        "invalid_source_hash": 1,
        "mine_mismatch": 1,
        "not_human_reviewed": 1,
        "operating_condition_mismatch": 1,
        "overlap_or_future_window": 1,
        "quality_below_floor": 1,
        "review_confidence_below_floor": 1,
        "review_unavailable_at_training_cutoff": 1,
        "unavailable_at_training_cutoff": 1,
    }
    assert result.baselines.energy is not None
    assert result.baselines.energy.selected_sample_ids == [
        "sample-002",
        "sample-001",
        "sample-000",
    ]


def test_cold_start_is_explicit_and_does_not_broaden_context() -> None:
    other_condition = CONDITION.model_copy(update={"shift_code": "night"})
    result = verify_energy_and_explosives(
        _request(
            history=[
                _sample(0),
                _sample(1),
                *[
                    _sample(10 + index, condition=other_condition)
                    for index in range(20)
                ],
            ]
        )
    )

    assert result.status is VerificationStatus.INSUFFICIENT_HISTORY
    assert result.energy is None
    assert result.explosives is None
    assert result.overall_clue_level is TechnicalClueLevel.NORMAL
    assert len(result.baselines.cold_start_reasons) == 2
    assert result.baselines.selection.exclusions[
        "operating_condition_mismatch"
    ] == 20


def test_explosives_use_robust_deviation_thresholds() -> None:
    history = [
        _sample(index, explosives_intensity=0.1 + (index - 2) * 0.001)
        for index in range(5)
    ]
    result = verify_energy_and_explosives(
        _request(history=history, explosives_kg=20.0)
    )

    assert result.explosives is not None
    assert result.explosives.actual_kg_per_t == pytest.approx(0.2)
    assert result.explosives.robust_z > 5.0
    assert result.explosives.band is RobustDeviationBand.EXTREME
    assert result.explosives.direction is EvidenceDirection.HIGH


def test_same_direction_indicators_raise_technical_priority_one_level() -> None:
    history = [
        _sample(index, explosives_intensity=0.1 + (index - 2) * 0.001)
        for index in range(5)
    ]
    result = verify_energy_and_explosives(
        _request(
            history=history,
            production_energy_kwh=14_000.0,
            explosives_kg=20.0,
        )
    )

    assert result.energy is not None
    assert result.explosives is not None
    assert result.energy.direction is EvidenceDirection.HIGH
    assert result.explosives.direction is EvidenceDirection.HIGH
    assert result.same_direction is True
    assert result.jointly_upgraded is True
    assert result.overall_clue_level is TechnicalClueLevel.HIGH
    assert result.legal_determination is False
    assert "不构成" in result.disclaimer
    serialized = result.model_dump_json()
    assert "联合信号仍须经原始凭证和现场核查确认" in serialized


def test_opposite_directions_do_not_raise_joint_priority() -> None:
    history = [
        _sample(index, explosives_intensity=0.1 + (index - 2) * 0.001)
        for index in range(5)
    ]
    result = verify_energy_and_explosives(
        _request(
            history=history,
            production_energy_kwh=7_000.0,
            explosives_kg=20.0,
        )
    )

    assert result.energy is not None
    assert result.explosives is not None
    assert result.energy.direction is EvidenceDirection.LOW
    assert result.explosives.direction is EvidenceDirection.HIGH
    assert result.same_direction is False
    assert result.jointly_upgraded is False
    assert result.overall_clue_level is TechnicalClueLevel.ELEVATED


def test_current_unidentified_interference_blocks_joint_verification() -> None:
    partial = _interference()
    partial[-1] = InterferenceReading(
        category=partial[-1].category,
        identifiable=False,
    )
    result = verify_energy_and_explosives(
        _request(
            history=_normal_history(),
            electricity=ElectricityReading(
                source_id="total-meter",
                total_kwh=11_000.0,
                interference=partial,
            ),
        )
    )

    assert result.status is VerificationStatus.BLOCKED
    assert result.energy is None
    assert result.current_energy_derivation.status == "blocked"
    assert result.blocking_reasons
    assert result.same_direction is False
    assert result.jointly_upgraded is False


def test_invalid_historical_energy_is_excluded_metric_by_metric() -> None:
    invalid_energy = ElectricityReading(
        source_id="incomplete-total",
        total_kwh=12_000.0,
        interference=_interference()[:-1],
    )
    history = [
        _sample(0),
        _sample(1),
        _sample(2, electricity=invalid_energy),
    ]

    result = verify_energy_and_explosives(_request(history=history))

    assert result.status is VerificationStatus.INSUFFICIENT_HISTORY
    assert result.energy is None
    assert result.explosives is not None
    assert result.baselines.selection.invalid_energy_sample_count == 1
    assert result.baselines.selection.invalid_explosives_sample_count == 0


def test_parameters_are_versioned_and_maximum_pool_is_deterministic() -> None:
    parameters = VerificationParameters(
        parameter_version="approved-parameters-v9",
        compatibility_key=COMPATIBILITY_KEY,
        minimum_samples=3,
        maximum_samples=3,
    )
    result = verify_energy_and_explosives(
        _request(
            history=_normal_history(5),
            parameters=parameters,
        )
    )

    assert result.parameter_version == "approved-parameters-v9"
    assert result.baselines.parameters_snapshot == parameters
    assert result.energy is not None
    assert result.energy.threshold_parameter_version == (
        "approved-parameters-v9"
    )
    assert result.energy.baseline.selected_sample_ids == [
        "sample-004",
        "sample-003",
        "sample-002",
    ]
    assert result.baselines.selection.energy_limit_excluded_count == 2
    assert result.baselines.selection.explosives_limit_excluded_count == 2


def test_invalid_threshold_order_and_review_metadata_are_rejected() -> None:
    with pytest.raises(ValidationError, match="strictly ordered"):
        VerificationParameters(
            energy_extreme_low_ratio=0.95,
            energy_attention_low_ratio=0.9,
        )
    with pytest.raises(ValidationError, match="empirical extreme"):
        VerificationParameters(
            empirical_attention_tail_probability=0.05,
            empirical_extreme_tail_probability=0.05,
        )
    with pytest.raises(ValidationError, match="review metadata"):
        _sample(0, human_reviewed=False).model_copy(
            update={"reviewed_by": "forbidden"}
        ).model_validate(
            {
                **_sample(0, human_reviewed=False).model_dump(),
                "reviewed_by": "forbidden",
            }
        )


def test_stable_api_aliases_have_request_and_result_shape() -> None:
    request = _request(history=_normal_history())

    assert isinstance(request, VerificationRequest)
    result = analyze_verification(request)
    assert isinstance(result, VerificationResult)
    assert result == verify_energy_and_explosives(request)
