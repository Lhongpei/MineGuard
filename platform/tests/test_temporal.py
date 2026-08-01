from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from mineguard.temporal import (
    TemporalDetectionParameters,
    TemporalDetectionRequest,
    TemporalDetectorCode,
    TemporalObservation,
    detect_temporal_anomalies,
)


START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def observation(
    index: int,
    value: float | None,
    *,
    mine_id: str = "mine-1",
    source_id: str = "belt-1",
    metric_code: str = "coal.main_transport_t",
    quality: float = 1.0,
    latency_seconds: float = 0.0,
    revision_count: int = 0,
    residual: bool = False,
) -> TemporalObservation:
    return TemporalObservation(
        mine_id=mine_id,
        source_id=source_id,
        metric_code=metric_code,
        timestamp=START + timedelta(hours=index),
        value=None if residual or value is None else value,
        signed_residual=value if residual else None,
        quality=quality,
        missing=value is None,
        latency_seconds=latency_seconds,
        revision_count=revision_count,
    )


def parameters(**overrides: object) -> TemporalDetectionParameters:
    values: dict[str, object] = {
        "baseline_window": 20,
        "min_history": 5,
        "mad_z_threshold": 4.0,
        "ewma_z_threshold": 5.0,
        "cusum_threshold": 4.0,
        "page_hinkley_threshold": 5.0,
    }
    values.update(overrides)
    return TemporalDetectionParameters(**values)


def detect(
    observations: list[TemporalObservation],
    **parameter_overrides: object,
):
    request = TemporalDetectionRequest(
        observations=observations,
        parameters=parameters(**parameter_overrides),
    )
    return detect_temporal_anomalies(request)


def signal_codes(point) -> set[TemporalDetectorCode]:
    return {signal.detector for signal in point.signals}


def test_models_are_strict_and_reject_invalid_measurements() -> None:
    with pytest.raises(ValidationError, match="valid number"):
        TemporalObservation(
            mine_id="mine-1",
            source_id="source-1",
            metric_code="metric-1",
            timestamp=START,
            value="12.5",
        )

    with pytest.raises(ValidationError, match="exactly one"):
        TemporalObservation(
            mine_id="mine-1",
            source_id="source-1",
            metric_code="metric-1",
            timestamp=START,
        )

    with pytest.raises(ValidationError, match="cannot contain"):
        TemporalObservation(
            mine_id="mine-1",
            source_id="source-1",
            metric_code="metric-1",
            timestamp=START,
            value=0.0,
            missing=True,
        )

    with pytest.raises(ValidationError, match="Extra inputs"):
        TemporalObservation(
            mine_id="mine-1",
            source_id="source-1",
            metric_code="metric-1",
            timestamp=START,
            value=1.0,
            unknown=True,
        )

    with pytest.raises(ValidationError):
        TemporalObservation(
            mine_id="mine-1",
            source_id="source-1",
            metric_code="metric-1",
            timestamp=datetime(2026, 1, 1),
            value=1.0,
        )


def test_request_rejects_duplicates_and_mixed_value_kinds() -> None:
    point = observation(0, 1.0)
    with pytest.raises(ValidationError, match="timestamps must be unique"):
        TemporalDetectionRequest(observations=[point, point])

    with pytest.raises(ValidationError, match="cannot be mixed"):
        TemporalDetectionRequest(
            observations=[
                observation(0, 1.0),
                observation(1, 0.1, residual=True),
            ]
        )

    with pytest.raises(
        ValidationError,
        match="min_history cannot be greater",
    ):
        TemporalDetectionParameters(
            baseline_window=5,
            min_history=6,
        )


def test_cold_start_reports_insufficient_history_without_value_alarm() -> None:
    result = detect(
        [observation(index, 10.0 + index / 10) for index in range(4)]
    )
    series = result.series[0]

    assert series.status == "insufficient_history"
    assert series.insufficient_history is True
    assert series.cold_start_point_count == 4
    assert series.anomaly_point_count == 0
    assert series.episodes == []
    assert all(point.insufficient_history for point in series.points)
    assert all(not point.value_anomaly for point in series.points)
    assert all(
        point.baseline_median is None and point.robust_scale is None
        for point in series.points
    )


def test_explicit_missing_is_anomalous_even_during_cold_start() -> None:
    result = detect([observation(0, None)])
    series = result.series[0]

    assert series.insufficient_history is True
    assert series.status == "anomalous"
    assert series.anomaly_point_count == 1
    assert len(series.episodes) == 1
    assert result.anomalous_series_count == 1


def test_extreme_temporal_values_are_rejected_before_numeric_overflow() -> None:
    with pytest.raises(ValidationError):
        TemporalObservation(
            mine_id="mine-1",
            source_id="source-1",
            metric_code="metric-1",
            timestamp=START,
            value=1e308,
        )


def test_subnormal_detector_scale_is_rejected_before_detection() -> None:
    with pytest.raises(ValidationError):
        TemporalDetectionParameters(minimum_scale=5e-324)


def test_rolling_mad_uses_only_prior_points_and_explains_threshold() -> None:
    values = [10.0, 10.2, 9.8, 10.1, 9.9, 13.0]
    series = detect(
        [observation(index, value) for index, value in enumerate(values)],
        cusum_threshold=100.0,
        page_hinkley_threshold=100.0,
        ewma_z_threshold=100.0,
    ).series[0]
    anomaly = series.points[-1]

    assert anomaly.baseline_sample_count == 5
    assert anomaly.baseline_median == pytest.approx(10.0)
    assert anomaly.baseline_mad == pytest.approx(0.1)
    assert anomaly.thresholds.rolling_upper == pytest.approx(10.59304)
    assert TemporalDetectorCode.ROLLING_MAD in signal_codes(anomaly)
    signal = anomaly.signals[0]
    assert signal.direction == "high"
    assert signal.observed_statistic > signal.threshold
    assert signal.contribution > 0
    assert "median/MAD" in signal.explanation
    assert anomaly.accepted_into_baseline is False


def test_zero_mad_uses_scale_floor_and_threshold_is_exclusive() -> None:
    values = [0.0] * 5 + [4e-6, 1e-3]
    series = detect(
        [
            observation(index, value)
            for index, value in enumerate(values)
        ],
        minimum_scale=1e-6,
        ewma_z_threshold=100.0,
        cusum_threshold=100.0,
        page_hinkley_threshold=100.0,
    ).series[0]
    boundary = series.points[-2]
    spike = series.points[-1]

    assert boundary.baseline_mad == 0.0
    assert boundary.robust_scale == 1e-6
    assert boundary.rolling_robust_z == pytest.approx(4.0)
    assert boundary.value_anomaly is False
    assert TemporalDetectorCode.ROLLING_MAD in signal_codes(spike)


def test_relative_scale_floor_is_opt_in_for_constant_level_series() -> None:
    values = [100.0] * 5 + [100.01]
    observations = [
        observation(index, value) for index, value in enumerate(values)
    ]
    default_point = detect(
        observations,
        ewma_z_threshold=1e9,
        cusum_threshold=1e9,
        page_hinkley_threshold=1e9,
    ).series[0].points[-1]
    guarded_point = detect(
        observations,
        minimum_relative_scale=0.01,
        ewma_z_threshold=1e9,
        cusum_threshold=1e9,
        page_hinkley_threshold=1e9,
    ).series[0].points[-1]

    assert TemporalDetectorCode.ROLLING_MAD in signal_codes(default_point)
    assert guarded_point.value_anomaly is False
    assert guarded_point.baseline_mad == 0.0
    assert guarded_point.robust_scale == pytest.approx(1.0)
    assert guarded_point.rolling_robust_z == pytest.approx(0.01)
    assert guarded_point.thresholds.minimum_relative_scale == 0.01
    assert guarded_point.thresholds.effective_scale_floor == pytest.approx(1.0)


def test_relative_floor_near_zero_uses_only_the_absolute_floor() -> None:
    values = [-0.001, 0.0, 0.001, -0.001, 0.001, 0.002]
    point = detect(
        [
            observation(index, value, residual=True)
            for index, value in enumerate(values)
        ],
        minimum_scale=0.01,
        minimum_relative_scale=0.02,
    ).series[0].points[-1]

    assert point.baseline_median == pytest.approx(0.0)
    assert point.robust_scale == pytest.approx(0.01)
    assert point.thresholds.effective_scale_floor == pytest.approx(0.01)


def test_missing_and_low_quality_points_are_not_imputed_or_learned() -> None:
    points = [
        observation(0, 10.0),
        observation(1, 10.1),
        observation(2, None),
        observation(3, 999.0, quality=0.2),
        observation(4, 9.9),
    ]
    series = detect(points).series[0]

    missing = series.points[2]
    low_quality = series.points[3]
    following = series.points[4]
    assert missing.observed_value is None
    assert missing.accepted_into_baseline is False
    assert TemporalDetectorCode.SOURCE_MISSING in signal_codes(missing)
    assert low_quality.accepted_into_baseline is False
    assert (
        TemporalDetectorCode.SOURCE_LOW_QUALITY
        in signal_codes(low_quality)
    )
    assert following.baseline_sample_count == 2
    assert following.ewma_value < 20.0
    assert series.final_baseline_sample_count == 3
    assert series.source_health.missing_count == 1
    assert series.source_health.low_quality_count == 1
    assert series.source_health.baseline_accepted_count == 3
    assert series.source_health.missing_rate == pytest.approx(0.2)


def test_baseline_ineligible_point_is_detected_but_never_learned() -> None:
    baseline = [observation(index, 10.0) for index in range(5)]
    monitored = [
        observation(index, 20.0).model_copy(
            update={"baseline_eligible": False}
        )
        for index in range(5, 8)
    ]
    series = detect(
        baseline + monitored,
        baseline_reset_confirmation_points=3,
    ).series[0]
    point = series.points[-1]

    assert point.value_anomaly is True
    assert point.baseline_eligible is False
    assert point.accepted_into_baseline is False
    assert point.reset_seed_sample_count == 0
    assert series.final_baseline_sample_count == 5
    assert series.baseline_resets == []
    assert series.source_health.baseline_ineligible_count == 3
    assert series.source_health.baseline_accepted_count == 5


def test_persistent_shift_triggers_cusum_ewma_and_page_hinkley() -> None:
    baseline = [10.0, 10.2, 9.8, 10.1, 9.9]
    shifted = [10.7] * 7
    series = detect(
        [
            observation(index, value)
            for index, value in enumerate(baseline + shifted)
        ]
    ).series[0]
    shift_points = series.points[len(baseline) :]
    all_codes = {
        code for point in shift_points for code in signal_codes(point)
    }

    assert TemporalDetectorCode.CUSUM in all_codes
    assert TemporalDetectorCode.EWMA in all_codes
    assert TemporalDetectorCode.PAGE_HINKLEY in all_codes
    assert shift_points[-1].cusum_positive > 4.0
    assert shift_points[-1].page_hinkley_positive > 5.0
    assert shift_points[-1].contributions["cusum"] > 0
    assert series.status == "anomalous"


def test_confirmed_stable_step_resets_baseline_once_and_then_adapts() -> None:
    values = [0.0] * 5 + [1.0] * 10
    series = detect(
        [
            observation(index, value)
            for index, value in enumerate(values)
        ],
        baseline_reset_confirmation_points=3,
    ).series[0]

    assert series.anomaly_point_count == 3
    assert len(series.episodes) == 1
    episode = series.episodes[0]
    assert (episode.start_point_index, episode.end_point_index) == (5, 7)
    assert episode.baseline_reset_count == 1
    assert TemporalDetectorCode.REGIME_CHANGE in episode.detectors

    assert len(series.baseline_resets) == 1
    reset = series.baseline_resets[0]
    assert reset.change_started_at == START + timedelta(hours=5)
    assert reset.confirmed_at == START + timedelta(hours=7)
    assert reset.direction == "high"
    assert reset.confirmation_point_count == 3
    assert reset.previous_baseline_median == 0.0
    assert reset.reset_baseline_median == 1.0
    assert reset.reset_seed_sample_count == 3
    assert reset.new_baseline_epoch == 1

    confirmation = series.points[7]
    assert confirmation.baseline_reset_confirmed is True
    assert confirmation.change_run_length == 3
    assert confirmation.baseline_sample_count_after_update == 3
    assert confirmation.accepted_into_baseline is False
    assert confirmation.reset_seed_sample_count == 3
    assert series.source_health.baseline_accepted_count == 12
    assert series.source_health.reset_seed_sample_count == 3
    assert all(
        not point.anomalous for point in series.points[8:]
    )
    assert all(point.baseline_epoch == 1 for point in series.points[8:])
    assert series.points[10].baseline_median == 1.0
    assert series.final_baseline_sample_count == 10


def test_isolated_spike_does_not_seed_later_regime_reset() -> None:
    values = [0.0] * 5 + [10.0, 0.0] + [1.0] * 8
    series = detect(
        [
            observation(index, value)
            for index, value in enumerate(values)
        ],
        baseline_reset_confirmation_points=3,
        ewma_z_threshold=1e9,
        cusum_threshold=1e9,
        page_hinkley_threshold=1e9,
    ).series[0]

    assert len(series.baseline_resets) == 1
    reset = series.baseline_resets[0]
    assert reset.change_started_at == START + timedelta(hours=7)
    assert reset.confirmed_at == START + timedelta(hours=9)
    assert reset.reset_baseline_median == 1.0
    assert series.points[5].baseline_reset_confirmed is False
    assert series.points[6].change_run_length == 0
    assert [(item.start_point_index, item.end_point_index) for item in series.episodes] == [
        (5, 5),
        (7, 9),
    ]


def test_sparse_same_direction_anomalies_do_not_confirm_a_reset() -> None:
    baseline = [observation(index, 0.0) for index in range(5)]
    sparse = [
        observation(5 + index, 1.0).model_copy(
            update={
                "timestamp": START + timedelta(days=31 * (index + 1))
            }
        )
        for index in range(3)
    ]
    series = detect(
        baseline + sparse,
        baseline_reset_confirmation_points=3,
        baseline_reset_candidate_max_gap_seconds=86_400.0,
        episode_max_gap_seconds=86_400.0,
    ).series[0]

    assert series.baseline_resets == []
    assert [point.change_run_length for point in series.points[-3:]] == [
        1,
        1,
        1,
    ]
    assert len(series.episodes) == 3


def test_negative_signed_residual_shift_preserves_direction() -> None:
    baseline = [0.0, 0.1, -0.1, 0.05, -0.05]
    shifted = [-0.7] * 7
    series = detect(
        [
            observation(index, value, residual=True)
            for index, value in enumerate(baseline + shifted)
        ]
    ).series[0]

    assert series.value_kind == "signed_residual"
    negative_signals = [
        signal
        for point in series.points
        for signal in point.signals
        if signal.detector
        in {
            TemporalDetectorCode.CUSUM,
            TemporalDetectorCode.PAGE_HINKLEY,
        }
    ]
    assert negative_signals
    assert all(signal.direction == "low" for signal in negative_signals)


def test_source_health_latency_revision_and_quality_are_explainable() -> None:
    unhealthy = observation(
        5,
        10.0,
        quality=0.5,
        latency_seconds=901.0,
        revision_count=2,
    )
    series = detect(
        [observation(index, 10.0) for index in range(5)] + [unhealthy]
    ).series[0]
    point = series.points[-1]

    assert point.value_anomaly is False
    assert point.source_health_anomaly is True
    assert point.anomalous is True
    assert signal_codes(point) == {
        TemporalDetectorCode.SOURCE_LATENCY,
        TemporalDetectorCode.SOURCE_REVISION,
        TemporalDetectorCode.SOURCE_LOW_QUALITY,
    }
    assert point.contributions.keys() == {
        "source_latency",
        "source_revision",
        "source_low_quality",
    }
    assert point.accepted_into_baseline is False
    assert series.source_health.late_count == 1
    assert series.source_health.revised_count == 1
    assert series.source_health.low_quality_count == 1


def test_source_health_threshold_boundaries_do_not_trigger() -> None:
    boundary = observation(
        5,
        10.0,
        quality=0.6,
        latency_seconds=900.0,
        revision_count=1,
    )
    point = detect(
        [observation(index, 10.0) for index in range(5)] + [boundary]
    ).series[0].points[-1]

    assert point.source_health_anomaly is False
    assert point.signals == []
    assert point.accepted_into_baseline is True

    almost_perfect = observation(0, 1.0, quality=0.999999999)
    low_quality = detect(
        [almost_perfect],
        min_baseline_quality=1.0,
    ).series[0].points[0]
    assert low_quality.contributions["source_low_quality"] > 0.0


def test_adjacent_anomalies_merge_into_explainable_episodes() -> None:
    baseline = [10.0, 10.2, 9.8, 10.1, 9.9]
    values = baseline + [15.0, 16.0, 10.0, 17.0]
    series = detect(
        [
            observation(index, value)
            for index, value in enumerate(values)
        ],
        ewma_alpha=1.0,
        ewma_z_threshold=4.0,
        cusum_threshold=100.0,
        page_hinkley_threshold=100.0,
    ).series[0]

    assert len(series.episodes) == 2
    first, second = series.episodes
    assert (first.start_point_index, first.end_point_index) == (5, 6)
    assert first.anomaly_point_count == 2
    assert first.spanned_point_count == 2
    assert TemporalDetectorCode.ROLLING_MAD in first.detectors
    assert first.maximum_contribution > 0
    assert "2 个异常时点" in first.explanation
    assert (second.start_point_index, second.end_point_index) == (8, 8)


def test_episode_can_bridge_a_configured_normal_point_but_respects_time() -> None:
    baseline = [10.0, 10.2, 9.8, 10.1, 9.9]
    values = baseline + [15.0, 10.0, 16.0]
    observations = [
        observation(index, value) for index, value in enumerate(values)
    ]
    bridged = detect(
        observations,
        episode_max_normal_points=1,
        episode_max_gap_seconds=10_000.0,
        ewma_alpha=1.0,
        ewma_z_threshold=4.0,
        cusum_threshold=100.0,
        page_hinkley_threshold=100.0,
    ).series[0]
    separated = detect(
        observations,
        episode_max_normal_points=1,
        episode_max_gap_seconds=3_000.0,
        ewma_alpha=1.0,
        ewma_z_threshold=4.0,
        cusum_threshold=100.0,
        page_hinkley_threshold=100.0,
    ).series[0]

    assert len(bridged.episodes) == 1
    assert bridged.episodes[0].spanned_point_count == 3
    assert bridged.episodes[0].anomaly_point_count == 2
    assert len(separated.episodes) == 2


def test_prefix_results_are_unchanged_when_future_points_are_added() -> None:
    values = [
        10.0,
        10.2,
        9.8,
        10.1,
        9.9,
        10.0,
        10.1,
        15.0,
        16.0,
    ]
    observations = [
        observation(index, value) for index, value in enumerate(values)
    ]
    prefix = detect(observations[:7]).series[0]
    complete = detect(observations).series[0]

    assert [
        point.model_dump(mode="json") for point in prefix.points
    ] == [
        point.model_dump(mode="json") for point in complete.points[:7]
    ]


def test_regime_reset_is_past_only_when_future_points_are_added() -> None:
    values = [0.0] * 5 + [1.0] * 10
    observations = [
        observation(index, value) for index, value in enumerate(values)
    ]
    parameter_overrides = {
        "baseline_reset_confirmation_points": 3,
    }
    prefix = detect(
        observations[:10],
        **parameter_overrides,
    ).series[0]
    complete = detect(
        observations,
        **parameter_overrides,
    ).series[0]

    assert [
        point.model_dump(mode="json") for point in prefix.points
    ] == [
        point.model_dump(mode="json")
        for point in complete.points[: len(prefix.points)]
    ]
    assert [
        item.model_dump(mode="json") for item in prefix.baseline_resets
    ] == [
        item.model_dump(mode="json")
        for item in complete.baseline_resets
        if item.confirmed_at <= prefix.points[-1].timestamp
    ]


def test_report_window_uses_prior_warmup_without_exposing_warmup_points() -> None:
    observations = [
        observation(index, 10.0 + index / 100)
        for index in range(8)
    ]
    request = TemporalDetectionRequest(
        observations=observations,
        parameters=parameters(),
        report_start=START + timedelta(hours=5),
        report_end=START + timedelta(hours=8),
    )

    series = detect_temporal_anomalies(request).series[0]

    assert [point.timestamp for point in series.points] == [
        START + timedelta(hours=index) for index in range(5, 8)
    ]
    assert series.points[0].baseline_sample_count == 5
    assert series.points[0].insufficient_history is False
    assert series.status == "normal"


def test_multi_series_output_is_deterministic_and_sorted() -> None:
    observations = [
        observation(1, 20.0, mine_id="mine-b"),
        observation(1, 10.0, mine_id="mine-a"),
        observation(0, 9.9, mine_id="mine-a"),
        observation(0, 19.9, mine_id="mine-b"),
    ]
    result = detect(list(reversed(observations)))

    assert result.series_count == 2
    assert [series.mine_id for series in result.series] == [
        "mine-a",
        "mine-b",
    ]
    assert [
        point.timestamp for point in result.series[0].points
    ] == sorted(point.timestamp for point in result.series[0].points)
    assert result.anomalous_series_count == 0
    assert result.insufficient_history_series_count == 2
