from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import ValidationError
import pytest

from mineguard.historical import (
    HistoricalLabel,
    HistoricalPolicy,
    HistoricalReferenceSample,
    OperationalContext,
    assess_historical_baseline,
    extract_historical_features,
)
from mineguard.models import (
    DataQualityResult,
    MetricCode,
    MetricObservation,
    ProductionAnalysisRequest,
    ProductionAnalysisResult,
    ReconciledMetric,
)


CURRENT_START = datetime(2026, 7, 27, tzinfo=UTC)
COMPATIBILITY_KEY = "compatibility-v1"


def _request() -> ProductionAnalysisRequest:
    values = {
        MetricCode.REPORTED_PRODUCTION: 100.0,
        MetricCode.MAIN_TRANSPORT: 90.0,
        MetricCode.WASH_FEED: 50.0,
        MetricCode.RAW_SALES: 30.0,
        MetricCode.RAW_INVENTORY_CHANGE: 10.0,
    }
    return ProductionAnalysisRequest(
        mine_id="M001",
        window_start=CURRENT_START,
        window_end=CURRENT_START + timedelta(days=1),
        observations=[
            MetricObservation(
                observation_id=f"observation-{index}",
                metric_code=metric_code,
                value=value,
                tolerance_abs=1.0,
                source_group=f"source-{index}",
                source_reliability=1.0,
            )
            for index, (metric_code, value) in enumerate(values.items())
        ],
    )


def _result(
    *,
    raw_anomaly: float = 2.5,
) -> ProductionAnalysisResult:
    residuals = {
        MetricCode.REPORTED_PRODUCTION: 0.1,
        MetricCode.MAIN_TRANSPORT: 0.2,
        MetricCode.WASH_FEED: 0.3,
        MetricCode.RAW_SALES: 0.4,
        MetricCode.RAW_INVENTORY_CHANGE: 0.5,
    }
    return ProductionAnalysisResult(
        mine_id="M001",
        status="inconsistent",
        data_quality=DataQualityResult(
            score=95.0,
            status="sufficient",
        ),
        solver_status="optimal",
        raw_anomaly_statistic=raw_anomaly,
        evidence_grade="B",
        reconciled_metrics={
            metric_code.value: ReconciledMetric(
                metric_code=metric_code,
                inferred_value=100.0,
                observed_values=[100.0],
                normalized_residual=residual,
            )
            for metric_code, residual in residuals.items()
        },
    )


def _sample(
    index: int,
    *,
    features: dict[str, float] | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    available_at: datetime | None = None,
    mine_id: str = "M001",
    compatibility_key: str = COMPATIBILITY_KEY,
    hash_valid: bool = True,
    quality_score: float = 0.9,
    label: HistoricalLabel = HistoricalLabel.VERIFIED_NORMAL,
    context: OperationalContext | None = None,
) -> HistoricalReferenceSample:
    effective_start = (
        window_start
        or CURRENT_START - timedelta(days=1000 - index)
    )
    return HistoricalReferenceSample(
        sample_id=f"sample-{index:04d}",
        mine_id=mine_id,
        window_start=effective_start,
        window_end=window_end or effective_start + timedelta(hours=12),
        available_at=available_at
        or effective_start + timedelta(hours=13),
        compatibility_key=compatibility_key,
        hash_valid=hash_valid,
        quality_score=quality_score,
        label=label,
        context=context or OperationalContext(),
        features=features or {"feature.a": 0.0, "feature.b": 0.0},
    )


def _assess(
    samples: list[HistoricalReferenceSample],
    *,
    features: dict[str, float] | None = None,
    context: OperationalContext | None = None,
    policy: HistoricalPolicy | None = None,
):
    return assess_historical_baseline(
        current_mine_id="M001",
        current_window_start=CURRENT_START,
        current_context=context,
        current_features=features or {"feature.a": 0.0, "feature.b": 0.0},
        current_compatibility_key=COMPATIBILITY_KEY,
        samples=samples,
        policy=policy,
        current_decision_time=CURRENT_START + timedelta(days=10),
    )


def test_extracts_required_physical_and_residual_features() -> None:
    features = extract_historical_features(_request(), _result())

    assert features["raw_anomaly"] == pytest.approx(2.5)
    assert features["gap_ratio.production_transport"] == pytest.approx(0.1)
    assert features[
        "gap_ratio.production_wash_sales_inventory"
    ] == pytest.approx(0.1)
    for index, metric_code in enumerate(MetricCode, start=1):
        assert features[
            f"normalized_residual.{metric_code.value}"
        ] == pytest.approx(index / 10)
    assert len(features) == 8


def test_extract_rejects_mine_mismatch_and_incomplete_result() -> None:
    mismatched = _result().model_copy(update={"mine_id": "M002"})
    with pytest.raises(ValueError, match="mine_id"):
        extract_historical_features(_request(), mismatched)

    incomplete = _result().model_copy(update={"reconciled_metrics": {}})
    with pytest.raises(ValueError, match="missing reconciled metric"):
        extract_historical_features(_request(), incomplete)


def test_time_leakage_excludes_same_and_future_windows() -> None:
    prior = [_sample(index) for index in range(20)]
    same_window = _sample(100, window_start=CURRENT_START)
    future = _sample(
        101,
        window_start=CURRENT_START + timedelta(microseconds=1),
    )
    overlap = _sample(
        102,
        window_start=CURRENT_START - timedelta(hours=1),
        window_end=CURRENT_START + timedelta(hours=1),
    )

    assessment = _assess([*prior, same_window, future, overlap])

    assert assessment.status == "ready"
    assert assessment.selected_sample_count == 20
    assert assessment.excluded_future_count == 3
    assert same_window.sample_id not in assessment.selected_sample_ids
    assert future.sample_id not in assessment.selected_sample_ids
    assert overlap.sample_id not in assessment.selected_sample_ids


def test_only_governed_normal_labels_are_selected() -> None:
    samples = [
        _sample(index, label=HistoricalLabel.VERIFIED_NORMAL)
        for index in range(20)
    ]
    rejected_labels = [
        HistoricalLabel.LEGITIMATE_EXCEPTION,
        HistoricalLabel.CONFIRMED_DATA_ERROR,
        HistoricalLabel.CONFIRMED_TECHNICAL_ANOMALY,
        HistoricalLabel.ADJUDICATED_VIOLATION,
        HistoricalLabel.UNRESOLVED,
    ]
    samples.extend(
        _sample(100 + index, label=label)
        for index, label in enumerate(rejected_labels)
    )

    assessment = _assess(samples)

    assert assessment.status == "ready"
    assert assessment.selected_sample_count == 20
    assert assessment.excluded_label_count == 5


def test_exact_context_shortage_does_not_fall_back_to_broader_pool() -> None:
    target = OperationalContext(
        regime_code="longwall",
        shift_code="night",
        season_code="wet",
        maintenance=False,
        approved_event_codes=["stocktake"],
        tags=["high-gas"],
    )
    other = target.model_copy(update={"shift_code": "day"})
    samples = [
        _sample(index, context=target)
        for index in range(19)
    ]
    samples.extend(
        _sample(100 + index, context=other)
        for index in range(30)
    )

    assessment = _assess(samples, context=target)

    assert assessment.status == "insufficient_history"
    assert assessment.eligible_sample_count == 19
    assert assessment.excluded_context_count == 30
    assert assessment.overall_p_value is None
    assert assessment.rarity_score is None
    assert assessment.historically_rare is None
    assert "exact operational context" in assessment.explanation


def test_context_collections_are_unique_and_order_canonical() -> None:
    assert OperationalContext() == OperationalContext(
        regime_code="",
        shift_code="",
        season_code="",
        maintenance=None,
        approved_event_codes=[],
        tags=[],
    )
    left = OperationalContext(
        approved_event_codes=["B", "A"],
        tags=["z", "a"],
    )
    right = OperationalContext(
        approved_event_codes=["A", "B"],
        tags=["a", "z"],
    )
    assert left == right

    with pytest.raises(ValidationError, match="must be unique"):
        OperationalContext(approved_event_codes=["A", "A"])
    with pytest.raises(ValidationError, match="must be unique"):
        OperationalContext(tags=["tag", "tag"])
    with pytest.raises(ValidationError):
        OperationalContext(regime_code="x" * 65)


def test_cold_start_is_explicit_and_does_not_claim_normality() -> None:
    assessment = _assess([_sample(index) for index in range(19)])

    assert assessment.status == "insufficient_history"
    assert assessment.selected_sample_count == 19
    assert assessment.dimensions == {}
    assert assessment.historically_rare is None
    assert assessment.physical_status_unchanged is True


def test_normal_and_extreme_windows_are_distinguished() -> None:
    samples = [_sample(index) for index in range(200)]

    normal = _assess(samples)
    extreme = _assess(
        samples,
        features={"feature.a": 100.0, "feature.b": 0.0},
    )

    assert normal.status == "ready"
    assert normal.overall_p_value == pytest.approx(1.0)
    assert normal.rarity_score == pytest.approx(0.0)
    assert normal.historically_rare is False
    assert extreme.overall_p_value == pytest.approx(1 / 201)
    assert extreme.rarity_score == pytest.approx(100 * (1 - 1 / 201))
    assert extreme.historically_rare is True
    assert extreme.physical_status_unchanged is True


def test_unusually_low_anomaly_magnitude_does_not_trigger_review() -> None:
    reference = {"feature.a": 10.0, "feature.b": 5.0}
    samples = [
        _sample(index, features=reference)
        for index in range(30)
    ]

    assessment = _assess(
        samples,
        features={"feature.a": 0.0, "feature.b": 0.0},
    )

    assert assessment.status == "ready"
    assert assessment.historically_rare is False
    assert assessment.overall_p_value == pytest.approx(1.0)
    assert assessment.joint_robust_distance == pytest.approx(0.0)


def test_multidimensional_p_value_uses_joint_max_distance() -> None:
    historical_features = {
        "feature.a": 0.0,
        "feature.b": 0.0,
        "feature.c": 0.0,
    }
    samples = [
        _sample(index, features=historical_features)
        for index in range(100)
    ]
    assessment = _assess(
        samples,
        features={
            "feature.a": 50.0,
            "feature.b": 0.0,
            "feature.c": 0.0,
        },
    )

    assert assessment.status == "ready"
    assert len(assessment.dimensions) == 3
    assert assessment.dimensions[
        "feature.a"
    ].empirical_p_value == pytest.approx(1 / 101)
    assert assessment.overall_p_value == pytest.approx(1 / 101)
    assert assessment.multiplicity_correction == (
        "max_robust_distance_empirical"
    )
    assert assessment.driving_feature_names == ["feature.a"]


def test_selection_is_deterministic_and_capped_at_500() -> None:
    samples = [_sample(index) for index in range(510)]

    forward = _assess(samples)
    reverse = _assess(list(reversed(samples)))

    assert forward == reverse
    assert forward.eligible_sample_count == 510
    assert forward.selected_sample_count == 500
    assert forward.excluded_limit_count == 10
    assert forward.selected_sample_ids == [
        f"sample-{index:04d}" for index in range(10, 510)
    ]


def test_all_selection_exclusions_are_reported() -> None:
    valid = [_sample(index) for index in range(20)]
    invalid = [
        _sample(100, mine_id="M002"),
        _sample(101, compatibility_key="other"),
        _sample(102, hash_valid=False),
        _sample(103, quality_score=0.79),
        _sample(
            104,
            features={"different.dimension": 0.0},
        ),
    ]

    assessment = _assess([*valid, *invalid])

    assert assessment.excluded_mine_count == 1
    assert assessment.excluded_compatibility_count == 1
    assert assessment.excluded_hash_count == 1
    assert assessment.excluded_quality_count == 1
    assert assessment.excluded_feature_count == 1


def test_nan_and_duplicate_sample_ids_are_rejected() -> None:
    with pytest.raises(ValidationError):
        _sample(1, features={"feature.a": float("nan")})

    valid = _sample(1)
    with pytest.raises(ValidationError, match="sample_id values must be unique"):
        _assess([valid, valid])

    with pytest.raises(ValidationError):
        _assess(
            [_sample(index) for index in range(20)],
            features={
                "feature.a": float("nan"),
                "feature.b": 0.0,
            },
        )


def test_policy_enforces_quality_floor_and_coherent_limits() -> None:
    with pytest.raises(ValidationError):
        HistoricalPolicy(minimum_quality_score=0.79)
    with pytest.raises(ValidationError, match="maximum_samples"):
        HistoricalPolicy(minimum_samples=21, maximum_samples=20)
