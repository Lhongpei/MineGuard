"""Measurement-aware aggregation for governed observation series.

Missing coverage is never interpreted as zero.  The module keeps aggregation
deterministic and deliberately refuses ambiguous register resets, overlapping
intervals, and insufficient boundary observations.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
import math
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from .models import StrictModel


MAX_ABSOLUTE_MEASUREMENT_VALUE = 1e15
MIN_TIME_SCALE_SECONDS = 1e-6
MAX_TIME_SCALE_SECONDS = 315_576_000.0


class MeasurementType(StrEnum):
    """How a source value relates to time."""

    WINDOW_TOTAL = "window_total"
    INTERVAL_DELTA = "interval_delta"
    CUMULATIVE_REGISTER = "cumulative_register"
    SNAPSHOT = "snapshot"
    INSTANTANEOUS_RATE = "instantaneous_rate"


class SeriesObservation(StrictModel):
    """One source reading before measurement-aware aggregation."""

    observation_id: Annotated[str, Field(min_length=1, max_length=256)]
    value: Annotated[
        float,
        Field(
            ge=-MAX_ABSOLUTE_MEASUREMENT_VALUE,
            le=MAX_ABSOLUTE_MEASUREMENT_VALUE,
        ),
    ]
    observed_at: AwareDatetime
    interval_start: AwareDatetime | None = None
    interval_end: AwareDatetime | None = None
    sequence_no: Annotated[int, Field(ge=0)] | None = None
    reset_before: bool = False

    @model_validator(mode="after")
    def validate_interval(self) -> "SeriesObservation":
        if (self.interval_start is None) != (self.interval_end is None):
            raise ValueError(
                "interval_start and interval_end must be supplied together"
            )
        if (
            self.interval_start is not None
            and self.interval_end is not None
            and self.interval_end <= self.interval_start
        ):
            raise ValueError("interval_end must be later than interval_start")
        return self


class AggregationRequest(StrictModel):
    """A frozen rule plus the source readings for one analysis window."""

    measurement_type: MeasurementType
    window_start: AwareDatetime
    window_end: AwareDatetime
    observations: Annotated[
        list[SeriesObservation],
        Field(min_length=1, max_length=100_000),
    ]
    min_coverage: Annotated[float, Field(gt=0, le=1)] = 0.9
    expected_interval_seconds: Annotated[
        float,
        Field(
            ge=MIN_TIME_SCALE_SECONDS,
            le=MAX_TIME_SCALE_SECONDS,
        ),
    ] | None = None
    max_boundary_staleness_seconds: Annotated[
        float,
        Field(ge=0, le=MAX_TIME_SCALE_SECONDS),
    ] = 0.0
    register_modulus: Annotated[
        float,
        Field(gt=0, le=MAX_ABSOLUTE_MEASUREMENT_VALUE),
    ] | None = None
    rate_time_unit_seconds: Annotated[
        float,
        Field(
            ge=MIN_TIME_SCALE_SECONDS,
            le=MAX_TIME_SCALE_SECONDS,
        ),
    ] = 3600.0

    @model_validator(mode="after")
    def validate_window(self) -> "AggregationRequest":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be later than window_start")
        identifiers = [
            observation.observation_id
            for observation in self.observations
        ]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("observation_id values must be unique")
        return self


class AggregationIssue(StrictModel):
    code: Annotated[str, Field(min_length=1, max_length=128)]
    severity: Literal["warning", "blocking"]
    message: Annotated[str, Field(min_length=1, max_length=1000)]
    observation_ids: list[str] = Field(default_factory=list)


class AggregationResult(StrictModel):
    measurement_type: MeasurementType
    status: Literal["sufficient", "degraded", "blocked"]
    aggregate_value: float | None
    partial_value: float | None
    coverage_ratio: Annotated[float, Field(ge=0, le=1)]
    expected_points: Annotated[int, Field(ge=0)] | None = None
    observed_points: Annotated[int, Field(ge=0)]
    reset_count: Annotated[int, Field(ge=0)] = 0
    contributing_observation_ids: list[str] = Field(default_factory=list)
    issues: list[AggregationIssue] = Field(default_factory=list)


def _seconds(later: datetime, earlier: datetime) -> float:
    return float((later - earlier).total_seconds())


def _expected_points(request: AggregationRequest) -> int | None:
    interval = request.expected_interval_seconds
    if interval is None:
        return None
    duration = _seconds(request.window_end, request.window_start)
    return max(1, math.ceil(duration / interval))


def _finish(
    request: AggregationRequest,
    *,
    partial_value: float | None,
    coverage: float,
    observations: list[SeriesObservation],
    issues: list[AggregationIssue],
    reset_count: int = 0,
) -> AggregationResult:
    coverage = min(1.0, max(0.0, float(coverage)))
    blocking = any(issue.severity == "blocking" for issue in issues)
    if coverage + 1e-12 < request.min_coverage:
        issues.append(
            AggregationIssue(
                code="insufficient_coverage",
                severity="blocking",
                message=(
                    f"coverage {coverage:.3f} is below required "
                    f"{request.min_coverage:.3f}; missing values were not "
                    "treated as zero"
                ),
                observation_ids=[
                    observation.observation_id
                    for observation in observations
                ],
            )
        )
        blocking = True
    status: Literal["sufficient", "degraded", "blocked"]
    if blocking:
        status = "blocked"
    elif issues:
        status = "degraded"
    else:
        status = "sufficient"
    return AggregationResult(
        measurement_type=request.measurement_type,
        status=status,
        aggregate_value=None if blocking else partial_value,
        partial_value=partial_value,
        coverage_ratio=round(coverage, 6),
        expected_points=_expected_points(request),
        observed_points=len(observations),
        reset_count=reset_count,
        contributing_observation_ids=[
            observation.observation_id for observation in observations
        ],
        issues=issues,
    )


def _window_total(request: AggregationRequest) -> AggregationResult:
    observations = sorted(
        request.observations,
        key=lambda item: (
            item.observed_at,
            item.sequence_no if item.sequence_no is not None else -1,
            item.observation_id,
        ),
    )
    issues: list[AggregationIssue] = []
    if len(observations) != 1:
        issues.append(
            AggregationIssue(
                code="ambiguous_window_totals",
                severity="blocking",
                message=(
                    "a window_total source must provide exactly one effective "
                    "reading per analysis window"
                ),
                observation_ids=[
                    observation.observation_id
                    for observation in observations
                ],
            )
        )
    observation = observations[-1]
    coverage = 1.0
    if (
        observation.interval_start is not None
        and observation.interval_end is not None
    ):
        if (
            observation.interval_start != request.window_start
            or observation.interval_end != request.window_end
        ):
            issues.append(
                AggregationIssue(
                    code="window_mismatch",
                    severity="blocking",
                    message=(
                        "window_total interval does not exactly match the "
                        "analysis window"
                    ),
                    observation_ids=[observation.observation_id],
                )
            )
            overlap_start = max(
                request.window_start,
                observation.interval_start,
            )
            overlap_end = min(request.window_end, observation.interval_end)
            overlap = max(0.0, _seconds(overlap_end, overlap_start))
            coverage = overlap / _seconds(
                request.window_end,
                request.window_start,
            )
    return _finish(
        request,
        partial_value=float(observation.value),
        coverage=coverage,
        observations=observations,
        issues=issues,
    )


def _interval_delta(request: AggregationRequest) -> AggregationResult:
    issues: list[AggregationIssue] = []
    valid: list[SeriesObservation] = []
    for observation in request.observations:
        if (
            observation.interval_start is None
            or observation.interval_end is None
        ):
            issues.append(
                AggregationIssue(
                    code="interval_required",
                    severity="blocking",
                    message=(
                        "interval_delta readings require interval_start and "
                        "interval_end"
                    ),
                    observation_ids=[observation.observation_id],
                )
            )
            continue
        if (
            observation.interval_start < request.window_start
            or observation.interval_end > request.window_end
        ):
            issues.append(
                AggregationIssue(
                    code="partial_interval_outside_window",
                    severity="blocking",
                    message=(
                        "interval_delta readings cannot be silently clipped "
                        "or prorated at an analysis boundary"
                    ),
                    observation_ids=[observation.observation_id],
                )
            )
            continue
        valid.append(observation)
    valid.sort(
        key=lambda item: (
            item.interval_start,
            item.interval_end,
            item.observation_id,
        )
    )
    covered_seconds = 0.0
    previous_end: datetime | None = None
    for observation in valid:
        assert observation.interval_start is not None
        assert observation.interval_end is not None
        if (
            previous_end is not None
            and observation.interval_start < previous_end
        ):
            issues.append(
                AggregationIssue(
                    code="overlapping_intervals",
                    severity="blocking",
                    message=(
                        "overlapping interval deltas would double-count the "
                        "same period"
                    ),
                    observation_ids=[observation.observation_id],
                )
            )
        covered_seconds += _seconds(
            observation.interval_end,
            observation.interval_start,
        )
        previous_end = max(
            previous_end,
            observation.interval_end,
        ) if previous_end is not None else observation.interval_end
    duration = _seconds(request.window_end, request.window_start)
    coverage = covered_seconds / duration
    expected = _expected_points(request)
    if expected is not None:
        coverage = min(coverage, len(valid) / expected)
    if coverage < 1.0 - 1e-12:
        issues.append(
            AggregationIssue(
                code="incomplete_additive_window",
                severity="blocking",
                message=(
                    "interval deltas do not cover the complete analysis "
                    "window; the partial sum cannot be used as a window "
                    "total because that would treat the gap as zero"
                ),
                observation_ids=[
                    observation.observation_id for observation in valid
                ],
            )
        )
    return _finish(
        request,
        partial_value=sum(float(item.value) for item in valid),
        coverage=coverage,
        observations=valid,
        issues=issues,
    )


def _point_series(
    request: AggregationRequest,
) -> tuple[list[SeriesObservation], float, list[AggregationIssue]]:
    observations = sorted(
        request.observations,
        key=lambda item: (
            item.observed_at,
            item.sequence_no if item.sequence_no is not None else -1,
            item.observation_id,
        ),
    )
    issues: list[AggregationIssue] = []
    for left, right in zip(observations, observations[1:]):
        if left.observed_at == right.observed_at:
            issues.append(
                AggregationIssue(
                    code="duplicate_point_time",
                    severity="blocking",
                    message=(
                        "multiple effective readings share the same point time"
                    ),
                    observation_ids=[
                        left.observation_id,
                        right.observation_id,
                    ],
                )
            )
    if len(observations) < 2:
        issues.append(
            AggregationIssue(
                code="boundary_points_missing",
                severity="blocking",
                message="at least two point readings are required",
                observation_ids=[
                    observation.observation_id
                    for observation in observations
                ],
            )
        )
        return observations, 0.0, issues

    first = observations[0]
    last = observations[-1]
    allowed = request.max_boundary_staleness_seconds
    start_error = abs(_seconds(first.observed_at, request.window_start))
    end_error = abs(_seconds(last.observed_at, request.window_end))
    if start_error > allowed or end_error > allowed:
        issues.append(
            AggregationIssue(
                code="boundary_points_stale",
                severity="blocking",
                message=(
                    "point readings are too far from one or both analysis "
                    "window boundaries"
                ),
                observation_ids=[
                    first.observation_id,
                    last.observation_id,
                ],
            )
        )
    elif start_error > 1e-9 or end_error > 1e-9:
        boundary_severity: Literal["warning", "blocking"] = (
            "warning"
            if request.measurement_type
            is MeasurementType.INSTANTANEOUS_RATE
            else "blocking"
        )
        issues.append(
            AggregationIssue(
                code=(
                    "boundary_points_approximate"
                    if boundary_severity == "warning"
                    else "exact_boundary_points_required"
                ),
                severity=boundary_severity,
                message=(
                    "rate readings may be interpolated at approved stale "
                    "boundaries"
                    if boundary_severity == "warning"
                    else "cumulative and snapshot changes require exact "
                    "boundary readings; window-external change cannot be "
                    "silently attributed to the analysis window"
                ),
                observation_ids=[
                    first.observation_id,
                    last.observation_id,
                ],
            )
        )

    duration = _seconds(request.window_end, request.window_start)
    covered_start = max(first.observed_at, request.window_start)
    covered_end = min(last.observed_at, request.window_end)
    span = max(0.0, _seconds(covered_end, covered_start))
    coverage = min(1.0, span / duration)
    expected = _expected_points(request)
    if expected is not None:
        # A point series covering N intervals normally needs N+1 readings.
        coverage = min(coverage, len(observations) / (expected + 1))
        maximum_gap = max(
            _seconds(right.observed_at, left.observed_at)
            for left, right in zip(observations, observations[1:])
        )
        if maximum_gap > request.expected_interval_seconds * 2:
            issues.append(
                AggregationIssue(
                    code="point_series_gap",
                    severity="warning",
                    message=(
                        "point series contains a gap greater than twice the "
                        "expected sampling interval"
                    ),
                )
            )
    return observations, coverage, issues


def _cumulative_register(
    request: AggregationRequest,
) -> AggregationResult:
    observations, coverage, issues = _point_series(request)
    total = 0.0
    resets = 0
    for previous, current in zip(observations, observations[1:]):
        if current.value >= previous.value:
            total += float(current.value - previous.value)
            continue
        if not current.reset_before:
            issues.append(
                AggregationIssue(
                    code="unexpected_register_decrease",
                    severity="blocking",
                    message=(
                        "cumulative register decreased without an explicit "
                        "reset marker"
                    ),
                    observation_ids=[
                        previous.observation_id,
                        current.observation_id,
                    ],
                )
            )
            continue
        resets += 1
        if request.register_modulus is not None:
            if previous.value >= request.register_modulus:
                issues.append(
                    AggregationIssue(
                        code="register_value_exceeds_modulus",
                        severity="blocking",
                        message="register value is outside configured modulus",
                        observation_ids=[previous.observation_id],
                    )
                )
                continue
            total += float(
                request.register_modulus - previous.value + current.value
            )
        else:
            # An explicit replacement/reset marker means the new register
            # restarted at zero; its current value is the post-reset delta.
            total += float(current.value)
    return _finish(
        request,
        partial_value=total,
        coverage=coverage,
        observations=observations,
        issues=issues,
        reset_count=resets,
    )


def _snapshot(request: AggregationRequest) -> AggregationResult:
    observations, coverage, issues = _point_series(request)
    value = (
        float(observations[-1].value - observations[0].value)
        if len(observations) >= 2
        else None
    )
    return _finish(
        request,
        partial_value=value,
        coverage=coverage,
        observations=observations,
        issues=issues,
    )


def _instantaneous_rate(
    request: AggregationRequest,
) -> AggregationResult:
    observations, coverage, issues = _point_series(request)
    integral = 0.0
    for left, right in zip(observations, observations[1:]):
        segment_start = max(left.observed_at, request.window_start)
        segment_end = min(right.observed_at, request.window_end)
        if segment_end <= segment_start:
            continue
        full_elapsed = _seconds(right.observed_at, left.observed_at)
        if full_elapsed <= 0:
            continue
        start_fraction = (
            _seconds(segment_start, left.observed_at) / full_elapsed
        )
        end_fraction = (
            _seconds(segment_end, left.observed_at) / full_elapsed
        )
        start_value = float(left.value) + (
            float(right.value) - float(left.value)
        ) * start_fraction
        end_value = float(left.value) + (
            float(right.value) - float(left.value)
        ) * end_fraction
        elapsed = _seconds(segment_end, segment_start)
        integral += (
            (start_value + end_value)
            * 0.5
            * elapsed
            / request.rate_time_unit_seconds
        )
    if coverage < 1.0 - 1e-12:
        issues.append(
            AggregationIssue(
                code="incomplete_rate_window",
                severity="blocking",
                message=(
                    "rate observations do not bracket the complete analysis "
                    "window; a partial integral cannot be used as a total"
                ),
                observation_ids=[
                    observation.observation_id
                    for observation in observations
                ],
            )
        )
    return _finish(
        request,
        partial_value=integral,
        coverage=coverage,
        observations=observations,
        issues=issues,
    )


def aggregate_measurements(
    request: AggregationRequest,
) -> AggregationResult:
    """Aggregate one trusted source without inventing missing values."""

    if not isinstance(request, AggregationRequest):
        raise TypeError("request must be an AggregationRequest")
    operations = {
        MeasurementType.WINDOW_TOTAL: _window_total,
        MeasurementType.INTERVAL_DELTA: _interval_delta,
        MeasurementType.CUMULATIVE_REGISTER: _cumulative_register,
        MeasurementType.SNAPSHOT: _snapshot,
        MeasurementType.INSTANTANEOUS_RATE: _instantaneous_rate,
    }
    return operations[request.measurement_type](request)


__all__ = [
    "AggregationIssue",
    "AggregationRequest",
    "AggregationResult",
    "MeasurementType",
    "SeriesObservation",
    "aggregate_measurements",
]
