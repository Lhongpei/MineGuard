from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mineguard.aggregation import (
    AggregationRequest,
    MeasurementType,
    SeriesObservation,
    aggregate_measurements,
)


START = datetime(2026, 7, 1, tzinfo=UTC)
END = START + timedelta(hours=1)


def point(
    identifier: str,
    minute: int,
    value: float,
    *,
    reset_before: bool = False,
) -> SeriesObservation:
    return SeriesObservation(
        observation_id=identifier,
        value=value,
        observed_at=START + timedelta(minutes=minute),
        sequence_no=minute,
        reset_before=reset_before,
    )


def interval(
    identifier: str,
    start_minute: int,
    end_minute: int,
    value: float,
) -> SeriesObservation:
    return SeriesObservation(
        observation_id=identifier,
        value=value,
        observed_at=START + timedelta(minutes=end_minute),
        interval_start=START + timedelta(minutes=start_minute),
        interval_end=START + timedelta(minutes=end_minute),
    )


def test_interval_deltas_sum_only_with_complete_non_overlapping_coverage() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="interval_delta",
            window_start=START,
            window_end=END,
            observations=[
                interval("a", 0, 30, 12.5),
                interval("b", 30, 60, 17.5),
            ],
            expected_interval_seconds=1800,
        )
    )

    assert result.status == "sufficient"
    assert result.aggregate_value == pytest.approx(30)
    assert result.coverage_ratio == 1


@pytest.mark.parametrize(
    "field",
    ["expected_interval_seconds", "rate_time_unit_seconds"],
)
def test_subnormal_time_scales_are_rejected_before_aggregation(
    field: str,
) -> None:
    values = {
        "measurement_type": MeasurementType.INSTANTANEOUS_RATE,
        "window_start": START,
        "window_end": END,
        "observations": [point("a", 0, 1.0)],
        field: 5e-324,
    }

    with pytest.raises(ValidationError):
        AggregationRequest(**values)


def test_interval_gap_is_blocked_and_never_filled_with_zero() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type=MeasurementType.INTERVAL_DELTA,
            window_start=START,
            window_end=END,
            observations=[interval("a", 0, 30, 12.5)],
            expected_interval_seconds=1800,
            min_coverage=0.9,
        )
    )

    assert result.status == "blocked"
    assert result.aggregate_value is None
    assert result.partial_value == pytest.approx(12.5)
    assert result.coverage_ratio == pytest.approx(0.5)
    assert "insufficient_coverage" in {
        issue.code for issue in result.issues
    }


def test_high_but_incomplete_interval_coverage_is_still_not_a_total() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type=MeasurementType.INTERVAL_DELTA,
            window_start=START,
            window_end=END,
            observations=[interval("almost", 0, 59, 59.0)],
            min_coverage=0.9,
        )
    )

    assert result.coverage_ratio == pytest.approx(59 / 60)
    assert result.partial_value == pytest.approx(59.0)
    assert result.aggregate_value is None
    assert result.status == "blocked"
    assert "incomplete_additive_window" in {
        issue.code for issue in result.issues
    }


def test_overlapping_deltas_are_rejected() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="interval_delta",
            window_start=START,
            window_end=END,
            observations=[
                interval("a", 0, 40, 10),
                interval("b", 30, 60, 20),
            ],
        )
    )

    assert result.status == "blocked"
    assert result.aggregate_value is None
    assert "overlapping_intervals" in {
        issue.code for issue in result.issues
    }


def test_cumulative_register_handles_only_explicit_reset() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="cumulative_register",
            window_start=START,
            window_end=END,
            observations=[
                point("a", 0, 990),
                point("b", 30, 999),
                point("c", 60, 5, reset_before=True),
            ],
            register_modulus=1000,
            max_boundary_staleness_seconds=0,
            expected_interval_seconds=1800,
        )
    )

    assert result.status == "sufficient"
    assert result.aggregate_value == pytest.approx(15)
    assert result.reset_count == 1

    unmarked = result = aggregate_measurements(
        AggregationRequest(
            measurement_type="cumulative_register",
            window_start=START,
            window_end=END,
            observations=[point("a", 0, 10), point("b", 60, 2)],
        )
    )
    assert unmarked.status == "blocked"
    assert "unexpected_register_decrease" in {
        issue.code for issue in unmarked.issues
    }


def test_snapshot_returns_signed_change_not_sum() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="snapshot",
            window_start=START,
            window_end=END,
            observations=[point("a", 0, 150), point("b", 60, 125)],
        )
    )

    assert result.status == "sufficient"
    assert result.aggregate_value == pytest.approx(-25)


@pytest.mark.parametrize(
    "measurement_type",
    [
        MeasurementType.CUMULATIVE_REGISTER,
        MeasurementType.SNAPSHOT,
    ],
)
def test_point_changes_require_exact_window_boundaries(
    measurement_type: MeasurementType,
) -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type=measurement_type,
            window_start=START,
            window_end=END,
            observations=[
                SeriesObservation(
                    observation_id="before",
                    value=0.0,
                    observed_at=START - timedelta(minutes=10),
                ),
                SeriesObservation(
                    observation_id="after",
                    value=2600.0,
                    observed_at=END + timedelta(minutes=10),
                ),
            ],
            max_boundary_staleness_seconds=600,
        )
    )

    assert result.status == "blocked"
    assert result.aggregate_value is None
    assert result.partial_value == pytest.approx(2600.0)
    assert "exact_boundary_points_required" in {
        issue.code for issue in result.issues
    }


def test_extreme_measurement_is_rejected_before_sum_overflow() -> None:
    with pytest.raises(ValidationError):
        SeriesObservation(
            observation_id="extreme",
            value=1e308,
            observed_at=START,
        )


def test_rate_uses_trapezoidal_integration() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="instantaneous_rate",
            window_start=START,
            window_end=END,
            observations=[point("a", 0, 10), point("b", 60, 20)],
            rate_time_unit_seconds=3600,
        )
    )

    assert result.status == "sufficient"
    assert result.aggregate_value == pytest.approx(15)


def test_rate_clips_approved_stale_boundary_points_to_the_window() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="instantaneous_rate",
            window_start=START,
            window_end=END,
            observations=[
                SeriesObservation(
                    observation_id="before",
                    value=100.0,
                    observed_at=START - timedelta(minutes=10),
                ),
                SeriesObservation(
                    observation_id="after",
                    value=100.0,
                    observed_at=END + timedelta(minutes=10),
                ),
            ],
            max_boundary_staleness_seconds=600,
            rate_time_unit_seconds=3600,
        )
    )

    assert result.status == "degraded"
    assert result.coverage_ratio == 1.0
    assert result.aggregate_value == pytest.approx(100.0)
    assert "boundary_points_approximate" in {
        issue.code for issue in result.issues
    }


def test_partial_rate_integral_is_not_promoted_to_a_window_total() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="instantaneous_rate",
            window_start=START,
            window_end=END,
            observations=[point("a", 1, 10), point("b", 60, 10)],
            max_boundary_staleness_seconds=60,
            min_coverage=0.9,
            rate_time_unit_seconds=3600,
        )
    )

    assert result.coverage_ratio == pytest.approx(59 / 60)
    assert result.partial_value == pytest.approx(59 / 60 * 10)
    assert result.aggregate_value is None
    assert "incomplete_rate_window" in {
        issue.code for issue in result.issues
    }


def test_window_total_rejects_multiple_effective_totals() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="window_total",
            window_start=START,
            window_end=END,
            observations=[point("a", 60, 10), point("b", 60, 11)],
        )
    )

    assert result.status == "blocked"
    assert "ambiguous_window_totals" in {
        issue.code for issue in result.issues
    }


def test_point_series_requires_boundary_coverage() -> None:
    result = aggregate_measurements(
        AggregationRequest(
            measurement_type="snapshot",
            window_start=START,
            window_end=END,
            observations=[point("a", 10, 100), point("b", 50, 120)],
            max_boundary_staleness_seconds=60,
        )
    )

    assert result.status == "blocked"
    assert result.aggregate_value is None
    assert "boundary_points_stale" in {
        issue.code for issue in result.issues
    }
