from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from math import sqrt
from typing import Annotated, Literal

import numpy as np
from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from .models import StrictModel


MAX_ABSOLUTE_TEMPORAL_VALUE = 1e15
MIN_TEMPORAL_SCALE = 1e-9
MAX_TEMPORAL_PARAMETER = 1e9
MAX_TEMPORAL_DURATION_SECONDS = 315_576_000.0


class TemporalModel(StrictModel):
    """Strict base model for the public temporal-detection contract."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        strict=True,
    )


class TemporalValueKind(StrEnum):
    VALUE = "value"
    SIGNED_RESIDUAL = "signed_residual"


class TemporalDetectorCode(StrEnum):
    ROLLING_MAD = "rolling_mad"
    EWMA = "ewma"
    CUSUM = "cusum"
    PAGE_HINKLEY = "page_hinkley"
    REGIME_CHANGE = "regime_change"
    SOURCE_MISSING = "source_missing"
    SOURCE_LATENCY = "source_latency"
    SOURCE_REVISION = "source_revision"
    SOURCE_LOW_QUALITY = "source_low_quality"


class TemporalObservation(TemporalModel):
    mine_id: Annotated[str, Field(min_length=1)]
    source_id: Annotated[str, Field(min_length=1)]
    metric_code: Annotated[str, Field(min_length=1)]
    timestamp: AwareDatetime
    value: Annotated[
        float,
        Field(
            ge=-MAX_ABSOLUTE_TEMPORAL_VALUE,
            le=MAX_ABSOLUTE_TEMPORAL_VALUE,
        ),
    ] | None = None
    signed_residual: Annotated[
        float,
        Field(
            ge=-MAX_ABSOLUTE_TEMPORAL_VALUE,
            le=MAX_ABSOLUTE_TEMPORAL_VALUE,
        ),
    ] | None = None
    quality: Annotated[float, Field(ge=0.0, le=1.0)] = 1.0
    missing: bool = False
    latency_seconds: Annotated[
        float,
        Field(ge=0.0, le=MAX_TEMPORAL_DURATION_SECONDS),
    ] = 0.0
    revision_count: Annotated[int, Field(ge=0)] = 0
    baseline_eligible: bool = True

    @model_validator(mode="after")
    def validate_measurement(self) -> "TemporalObservation":
        populated = sum(
            item is not None for item in (self.value, self.signed_residual)
        )
        if self.missing and populated:
            raise ValueError(
                "missing observations cannot contain value or signed_residual"
            )
        if not self.missing and populated != 1:
            raise ValueError(
                "non-missing observations require exactly one of value "
                "or signed_residual"
            )
        return self

    def value_kind(self) -> TemporalValueKind | None:
        if self.value is not None:
            return TemporalValueKind.VALUE
        if self.signed_residual is not None:
            return TemporalValueKind.SIGNED_RESIDUAL
        return None

    def numeric_value(self) -> float | None:
        if self.value is not None:
            return self.value
        return self.signed_residual


class TemporalDetectionParameters(TemporalModel):
    baseline_window: Annotated[int, Field(ge=3, le=10_000)] = 30
    min_history: Annotated[int, Field(ge=3, le=1_000)] = 8
    min_baseline_quality: Annotated[
        float,
        Field(ge=0.0, le=1.0),
    ] = 0.6
    minimum_scale: Annotated[
        float,
        Field(ge=MIN_TEMPORAL_SCALE, le=MAX_ABSOLUTE_TEMPORAL_VALUE),
    ] = 1e-6
    minimum_relative_scale: Annotated[
        float,
        Field(ge=0.0, le=1.0),
    ] = 0.0
    mad_z_threshold: Annotated[
        float,
        Field(ge=MIN_TEMPORAL_SCALE, le=MAX_TEMPORAL_PARAMETER),
    ] = 4.0
    ewma_alpha: Annotated[float, Field(gt=0.0, le=1.0)] = 0.25
    ewma_z_threshold: Annotated[
        float,
        Field(ge=MIN_TEMPORAL_SCALE, le=MAX_TEMPORAL_PARAMETER),
    ] = 3.0
    cusum_drift: Annotated[
        float,
        Field(ge=0.0, le=MAX_TEMPORAL_PARAMETER),
    ] = 0.5
    cusum_threshold: Annotated[
        float,
        Field(ge=MIN_TEMPORAL_SCALE, le=MAX_TEMPORAL_PARAMETER),
    ] = 5.0
    page_hinkley_delta: Annotated[
        float,
        Field(ge=0.0, le=MAX_TEMPORAL_PARAMETER),
    ] = 0.1
    page_hinkley_threshold: Annotated[
        float,
        Field(ge=MIN_TEMPORAL_SCALE, le=MAX_TEMPORAL_PARAMETER),
    ] = 8.0
    max_latency_seconds: Annotated[
        float,
        Field(
            ge=MIN_TEMPORAL_SCALE,
            le=MAX_TEMPORAL_DURATION_SECONDS,
        ),
    ] = 900.0
    max_revision_count: Annotated[int, Field(ge=0)] = 1
    exclude_detected_anomalies_from_baseline: bool = True
    baseline_reset_confirmation_points: Annotated[
        int | None,
        Field(ge=2, le=1_000),
    ] = None
    baseline_reset_candidate_max_gap_seconds: Annotated[
        float | None,
        Field(
            ge=MIN_TEMPORAL_SCALE,
            le=MAX_TEMPORAL_DURATION_SECONDS,
        ),
    ] = None
    episode_max_normal_points: Annotated[int, Field(ge=0, le=100)] = 0
    episode_max_gap_seconds: Annotated[
        float | None,
        Field(
            ge=MIN_TEMPORAL_SCALE,
            le=MAX_TEMPORAL_DURATION_SECONDS,
        ),
    ] = None

    @model_validator(mode="after")
    def validate_history_window(self) -> "TemporalDetectionParameters":
        if self.min_history > self.baseline_window:
            raise ValueError(
                "min_history cannot be greater than baseline_window"
            )
        return self


class DetectorThresholds(TemporalModel):
    rolling_lower: float | None = None
    rolling_upper: float | None = None
    ewma_lower: float | None = None
    ewma_upper: float | None = None
    minimum_scale: Annotated[float, Field(gt=0.0)] = 1e-6
    minimum_relative_scale: Annotated[
        float,
        Field(ge=0.0, le=1.0),
    ] = 0.0
    effective_scale_floor: Annotated[
        float | None,
        Field(gt=0.0),
    ] = None
    cusum: float
    page_hinkley: float
    minimum_quality: Annotated[float, Field(ge=0.0, le=1.0)]
    maximum_latency_seconds: Annotated[float, Field(gt=0.0)]
    maximum_revision_count: Annotated[int, Field(ge=0)]


class TemporalSignal(TemporalModel):
    detector: TemporalDetectorCode
    direction: Literal["high", "low", "none"]
    observed_statistic: Annotated[float, Field(ge=0.0)]
    threshold: Annotated[float, Field(ge=0.0)]
    contribution: Annotated[float, Field(gt=0.0)]
    explanation: Annotated[str, Field(min_length=1)]


class TemporalPointResult(TemporalModel):
    timestamp: AwareDatetime
    observed_value: float | None = None
    quality: Annotated[float, Field(ge=0.0, le=1.0)]
    missing: bool
    baseline_sample_count: Annotated[int, Field(ge=0)]
    baseline_sample_count_after_update: Annotated[
        int | None,
        Field(ge=0),
    ] = None
    baseline_epoch: Annotated[int, Field(ge=0)] = 0
    baseline_median: float | None = None
    baseline_mad: Annotated[float | None, Field(ge=0.0)] = None
    robust_scale: Annotated[float | None, Field(gt=0.0)] = None
    rolling_robust_z: float | None = None
    ewma_value: float | None = None
    ewma_standardized: float | None = None
    cusum_positive: Annotated[float, Field(ge=0.0)] = 0.0
    cusum_negative: Annotated[float, Field(ge=0.0)] = 0.0
    page_hinkley_positive: Annotated[float, Field(ge=0.0)] = 0.0
    page_hinkley_negative: Annotated[float, Field(ge=0.0)] = 0.0
    thresholds: DetectorThresholds
    signals: list[TemporalSignal] = Field(default_factory=list)
    contributions: dict[str, Annotated[float, Field(gt=0.0)]] = Field(
        default_factory=dict
    )
    value_anomaly: bool
    source_health_anomaly: bool
    anomalous: bool
    insufficient_history: bool
    baseline_eligible: bool = True
    accepted_into_baseline: bool
    reset_seed_sample_count: Annotated[int, Field(ge=0)] = 0
    change_direction: Literal["high", "low"] | None = None
    change_run_length: Annotated[int, Field(ge=0)] = 0
    baseline_reset_confirmed: bool = False


class TemporalEpisode(TemporalModel):
    episode_number: Annotated[int, Field(ge=1)]
    start: AwareDatetime
    end: AwareDatetime
    start_point_index: Annotated[int, Field(ge=0)]
    end_point_index: Annotated[int, Field(ge=0)]
    anomaly_point_count: Annotated[int, Field(ge=1)]
    spanned_point_count: Annotated[int, Field(ge=1)]
    detectors: list[TemporalDetectorCode]
    directions: list[Literal["high", "low", "none"]]
    maximum_contribution: Annotated[float, Field(gt=0.0)]
    baseline_reset_count: Annotated[int, Field(ge=0)] = 0
    explanation: Annotated[str, Field(min_length=1)]


class TemporalBaselineReset(TemporalModel):
    """Auditable, unverified statistical adaptation without future data."""

    reset_number: Annotated[int, Field(ge=1)]
    change_started_at: AwareDatetime
    confirmed_at: AwareDatetime
    direction: Literal["high", "low"]
    confirmation_point_count: Annotated[int, Field(ge=2)]
    previous_baseline_sample_count: Annotated[int, Field(ge=0)]
    previous_baseline_median: float
    reset_seed_sample_count: Annotated[int, Field(ge=1)]
    reset_baseline_median: float
    new_baseline_epoch: Annotated[int, Field(ge=1)]
    explanation: Annotated[str, Field(min_length=1)]


class SourceHealthSummary(TemporalModel):
    point_count: Annotated[int, Field(ge=1)]
    missing_count: Annotated[int, Field(ge=0)]
    late_count: Annotated[int, Field(ge=0)]
    revised_count: Annotated[int, Field(ge=0)]
    low_quality_count: Annotated[int, Field(ge=0)]
    baseline_ineligible_count: Annotated[int, Field(ge=0)] = 0
    baseline_accepted_count: Annotated[int, Field(ge=0)]
    reset_seed_sample_count: Annotated[int, Field(ge=0)] = 0
    missing_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    late_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    revision_rate: Annotated[float, Field(ge=0.0, le=1.0)]
    low_quality_rate: Annotated[float, Field(ge=0.0, le=1.0)]


class TemporalSeriesResult(TemporalModel):
    mine_id: str
    source_id: str
    metric_code: str
    value_kind: TemporalValueKind | None
    status: Literal["insufficient_history", "normal", "anomalous"]
    insufficient_history: bool
    final_baseline_sample_count: Annotated[int, Field(ge=0)]
    cold_start_point_count: Annotated[int, Field(ge=0)]
    anomaly_point_count: Annotated[int, Field(ge=0)]
    source_health: SourceHealthSummary
    points: list[TemporalPointResult]
    episodes: list[TemporalEpisode]
    baseline_resets: list[TemporalBaselineReset] = Field(default_factory=list)


class TemporalDetectionRequest(TemporalModel):
    observations: Annotated[
        list[TemporalObservation],
        Field(min_length=1, max_length=100_000),
    ]
    parameters: TemporalDetectionParameters = Field(
        default_factory=TemporalDetectionParameters
    )
    report_start: AwareDatetime | None = None
    report_end: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_series(self) -> "TemporalDetectionRequest":
        if (self.report_start is None) != (self.report_end is None):
            raise ValueError(
                "report_start and report_end must be supplied together"
            )
        if (
            self.report_start is not None
            and self.report_end is not None
        ):
            if self.report_end <= self.report_start:
                raise ValueError("report_end must be later than report_start")
            if not any(
                self.report_start <= item.timestamp < self.report_end
                for item in self.observations
            ):
                raise ValueError(
                    "report window must contain at least one observation"
                )
        seen: set[tuple[str, str, str, datetime]] = set()
        value_kinds: dict[
            tuple[str, str, str],
            TemporalValueKind,
        ] = {}
        for observation in self.observations:
            series_key = (
                observation.mine_id,
                observation.source_id,
                observation.metric_code,
            )
            point_key = (*series_key, observation.timestamp)
            if point_key in seen:
                raise ValueError(
                    "timestamps must be unique within each "
                    "mine/source/metric series"
                )
            seen.add(point_key)
            value_kind = observation.value_kind()
            previous_kind = value_kinds.get(series_key)
            if value_kind is not None and previous_kind not in (
                None,
                value_kind,
            ):
                raise ValueError(
                    "value and signed_residual cannot be mixed within "
                    "one mine/source/metric series"
                )
            if value_kind is not None:
                value_kinds[series_key] = value_kind
        return self


class TemporalDetectionResult(TemporalModel):
    series: list[TemporalSeriesResult]
    series_count: Annotated[int, Field(ge=1)]
    anomalous_series_count: Annotated[int, Field(ge=0)]
    insufficient_history_series_count: Annotated[int, Field(ge=0)]


def _median_and_scale(
    values: Sequence[float],
    minimum_scale: float,
    minimum_relative_scale: float = 0.0,
) -> tuple[float, float, float, float]:
    array = np.asarray(values, dtype=float)
    median = float(np.median(array))
    mad = float(np.median(np.abs(array - median)))
    effective_floor = max(
        minimum_scale,
        abs(median) * minimum_relative_scale,
    )
    return (
        median,
        mad,
        max(1.4826 * mad, effective_floor),
        effective_floor,
    )


def _contribution(statistic: float, threshold: float) -> float:
    return max(round(statistic / threshold - 1.0, 6), 1e-6)


def _signal(
    detector: TemporalDetectorCode,
    direction: Literal["high", "low", "none"],
    statistic: float,
    threshold: float,
    explanation: str,
) -> TemporalSignal:
    return TemporalSignal(
        detector=detector,
        direction=direction,
        observed_statistic=round(statistic, 6),
        threshold=round(threshold, 6),
        contribution=_contribution(statistic, threshold)
        if threshold > 0.0
        else max(round(statistic, 6), 1e-6),
        explanation=explanation,
    )


def _source_health_signals(
    observation: TemporalObservation,
    parameters: TemporalDetectionParameters,
) -> list[TemporalSignal]:
    signals: list[TemporalSignal] = []
    if observation.missing:
        signals.append(
            _signal(
                TemporalDetectorCode.SOURCE_MISSING,
                "none",
                1.0,
                0.0,
                "来源在该时点明确缺失；未将缺失值按 0 补入基线。",
            )
        )
    if observation.latency_seconds > parameters.max_latency_seconds:
        signals.append(
            _signal(
                TemporalDetectorCode.SOURCE_LATENCY,
                "high",
                observation.latency_seconds,
                parameters.max_latency_seconds,
                "接收延迟超过来源健康阈值。",
            )
        )
    if observation.revision_count > parameters.max_revision_count:
        signals.append(
            _signal(
                TemporalDetectorCode.SOURCE_REVISION,
                "high",
                float(observation.revision_count),
                float(parameters.max_revision_count),
                "同一业务时点的修订次数超过来源健康阈值。",
            )
        )
    if observation.quality < parameters.min_baseline_quality:
        signals.append(
            _signal(
                TemporalDetectorCode.SOURCE_LOW_QUALITY,
                "low",
                1.0 - observation.quality,
                1.0 - parameters.min_baseline_quality,
                "质量分低于基线准入阈值；该值不会进入检测基线。",
            )
        )
    return signals


def _episodes(
    points: Sequence[TemporalPointResult],
    parameters: TemporalDetectionParameters,
) -> list[TemporalEpisode]:
    anomalous_indices = [
        index for index, point in enumerate(points) if point.anomalous
    ]
    if not anomalous_indices:
        return []

    groups: list[list[int]] = [[anomalous_indices[0]]]
    for index in anomalous_indices[1:]:
        previous = groups[-1][-1]
        normal_gap = index - previous - 1
        time_gap = (
            points[index].timestamp - points[previous].timestamp
        ).total_seconds()
        within_time = (
            parameters.episode_max_gap_seconds is None
            or time_gap <= parameters.episode_max_gap_seconds
        )
        if (
            normal_gap <= parameters.episode_max_normal_points
            and within_time
        ):
            groups[-1].append(index)
        else:
            groups.append([index])

    episodes: list[TemporalEpisode] = []
    for episode_number, anomaly_indices in enumerate(groups, start=1):
        start_index = anomaly_indices[0]
        end_index = anomaly_indices[-1]
        signals = [
            signal
            for index in anomaly_indices
            for signal in points[index].signals
        ]
        detectors = sorted(
            {signal.detector for signal in signals},
            key=lambda detector: detector.value,
        )
        directions = sorted(
            {signal.direction for signal in signals},
            key=("high", "low", "none").index,
        )
        maximum = max(signal.contribution for signal in signals)
        baseline_reset_count = sum(
            signal.detector is TemporalDetectorCode.REGIME_CHANGE
            for signal in signals
        )
        detector_text = "、".join(detector.value for detector in detectors)
        reset_text = (
            f"其中 {baseline_reset_count} 个时点触发未核实统计基线适配；"
            if baseline_reset_count
            else ""
        )
        episodes.append(
            TemporalEpisode(
                episode_number=episode_number,
                start=points[start_index].timestamp,
                end=points[end_index].timestamp,
                start_point_index=start_index,
                end_point_index=end_index,
                anomaly_point_count=len(anomaly_indices),
                spanned_point_count=end_index - start_index + 1,
                detectors=detectors,
                directions=directions,
                maximum_contribution=maximum,
                baseline_reset_count=baseline_reset_count,
                explanation=(
                    f"连续异常片段，共 {len(anomaly_indices)} 个异常时点；"
                    f"{reset_text}触发检测器：{detector_text}。"
                ),
            )
        )
    return episodes


def _detect_series(
    observations: Sequence[TemporalObservation],
    parameters: TemporalDetectionParameters,
) -> TemporalSeriesResult:
    ordered = sorted(observations, key=lambda observation: observation.timestamp)
    first = ordered[0]
    value_kind = next(
        (
            observation.value_kind()
            for observation in ordered
            if observation.value_kind() is not None
        ),
        None,
    )

    history: list[float] = []
    ewma_state: float | None = None
    cusum_positive = 0.0
    cusum_negative = 0.0
    page_mean: float | None = None
    page_count = 0
    page_cumulative_positive = 0.0
    page_minimum_positive = 0.0
    page_cumulative_negative = 0.0
    page_minimum_negative = 0.0
    points: list[TemporalPointResult] = []
    baseline_epoch = 0
    baseline_resets: list[TemporalBaselineReset] = []
    change_candidate_direction: Literal["high", "low"] | None = None
    change_candidates: list[tuple[datetime, float]] = []

    for observation in ordered:
        numeric_value = observation.numeric_value()
        baseline_count = len(history)
        sufficient = baseline_count >= parameters.min_history
        median: float | None = None
        mad: float | None = None
        scale: float | None = None
        rolling_z: float | None = None
        ewma_standardized: float | None = None
        rolling_lower: float | None = None
        rolling_upper: float | None = None
        ewma_lower: float | None = None
        ewma_upper: float | None = None
        effective_scale_floor: float | None = None
        value_signals: list[TemporalSignal] = []

        usable = (
            numeric_value is not None
            and not observation.missing
            and observation.quality >= parameters.min_baseline_quality
        )

        if sufficient:
            median, mad, scale, effective_scale_floor = _median_and_scale(
                history,
                parameters.minimum_scale,
                parameters.minimum_relative_scale,
            )
            rolling_lower = median - parameters.mad_z_threshold * scale
            rolling_upper = median + parameters.mad_z_threshold * scale
            ewma_factor = sqrt(
                parameters.ewma_alpha / (2.0 - parameters.ewma_alpha)
            )
            ewma_half_width = (
                parameters.ewma_z_threshold * scale * ewma_factor
            )
            ewma_lower = median - ewma_half_width
            ewma_upper = median + ewma_half_width

        ewma_candidate = ewma_state
        if usable and numeric_value is not None:
            if ewma_state is None:
                ewma_candidate = numeric_value
            else:
                ewma_candidate = (
                    parameters.ewma_alpha * numeric_value
                    + (1.0 - parameters.ewma_alpha) * ewma_state
                )

            if sufficient and median is not None and scale is not None:
                rolling_z = (numeric_value - median) / scale
                absolute_rolling_z = abs(rolling_z)
                if absolute_rolling_z > parameters.mad_z_threshold:
                    value_signals.append(
                        _signal(
                            TemporalDetectorCode.ROLLING_MAD,
                            "high" if rolling_z > 0.0 else "low",
                            absolute_rolling_z,
                            parameters.mad_z_threshold,
                            (
                                "当前值相对仅由此前合格样本形成的滚动"
                                " median/MAD 基线发生偏离。"
                            ),
                        )
                    )

                ewma_factor = sqrt(
                    parameters.ewma_alpha
                    / (2.0 - parameters.ewma_alpha)
                )
                ewma_standardized = (
                    (ewma_candidate - median) / (scale * ewma_factor)
                )
                if (
                    abs(ewma_standardized)
                    > parameters.ewma_z_threshold
                ):
                    value_signals.append(
                        _signal(
                            TemporalDetectorCode.EWMA,
                            "high" if ewma_standardized > 0.0 else "low",
                            abs(ewma_standardized),
                            parameters.ewma_z_threshold,
                            "EWMA 水平超过基于历史稳健尺度的控制限。",
                        )
                    )

                cusum_positive = max(
                    0.0,
                    cusum_positive
                    + rolling_z
                    - parameters.cusum_drift,
                )
                cusum_negative = max(
                    0.0,
                    cusum_negative
                    - rolling_z
                    - parameters.cusum_drift,
                )
                if cusum_positive > parameters.cusum_threshold:
                    value_signals.append(
                        _signal(
                            TemporalDetectorCode.CUSUM,
                            "high",
                            cusum_positive,
                            parameters.cusum_threshold,
                            "正向 CUSUM 累积偏移超过持续漂移阈值。",
                        )
                    )
                if cusum_negative > parameters.cusum_threshold:
                    value_signals.append(
                        _signal(
                            TemporalDetectorCode.CUSUM,
                            "low",
                            cusum_negative,
                            parameters.cusum_threshold,
                            "负向 CUSUM 累积偏移超过持续漂移阈值。",
                        )
                    )

                if page_mean is None:
                    page_mean = numeric_value
                    page_count = 1
                else:
                    next_count = page_count + 1
                    next_mean = page_mean + (
                        numeric_value - page_mean
                    ) / next_count
                    page_deviation = (
                        numeric_value - next_mean
                    ) / scale
                    page_cumulative_positive += (
                        page_deviation - parameters.page_hinkley_delta
                    )
                    page_minimum_positive = min(
                        page_minimum_positive,
                        page_cumulative_positive,
                    )
                    page_cumulative_negative += (
                        -page_deviation - parameters.page_hinkley_delta
                    )
                    page_minimum_negative = min(
                        page_minimum_negative,
                        page_cumulative_negative,
                    )
                    page_mean = next_mean
                    page_count = next_count

                page_positive = (
                    page_cumulative_positive - page_minimum_positive
                )
                page_negative = (
                    page_cumulative_negative - page_minimum_negative
                )
                if page_positive > parameters.page_hinkley_threshold:
                    value_signals.append(
                        _signal(
                            TemporalDetectorCode.PAGE_HINKLEY,
                            "high",
                            page_positive,
                            parameters.page_hinkley_threshold,
                            "Page-Hinkley 检测到均值发生持续正向变点。",
                        )
                    )
                if page_negative > parameters.page_hinkley_threshold:
                    value_signals.append(
                        _signal(
                            TemporalDetectorCode.PAGE_HINKLEY,
                            "low",
                            page_negative,
                            parameters.page_hinkley_threshold,
                            "Page-Hinkley 检测到均值发生持续负向变点。",
                        )
                    )
            elif page_mean is None:
                page_mean = numeric_value
                page_count = 1
            else:
                page_count += 1
                page_mean += (numeric_value - page_mean) / page_count

        change_direction: Literal["high", "low"] | None = None
        change_run_length = 0
        reset_event: TemporalBaselineReset | None = None
        reset_seed: list[float] | None = None
        confirmation_points = parameters.baseline_reset_confirmation_points
        if (
            confirmation_points is not None
            and usable
            and observation.baseline_eligible
            and sufficient
            and value_signals
            and numeric_value is not None
            and median is not None
        ):
            deviation = numeric_value - median
            if deviation != 0.0:
                change_direction = "high" if deviation > 0.0 else "low"
                candidate_max_gap = (
                    parameters.baseline_reset_candidate_max_gap_seconds
                )
                if (
                    change_candidates
                    and candidate_max_gap is not None
                    and (
                        observation.timestamp
                        - change_candidates[-1][0]
                    ).total_seconds()
                    > candidate_max_gap
                ):
                    change_candidate_direction = None
                    change_candidates = []
                if change_candidate_direction != change_direction:
                    change_candidate_direction = change_direction
                    change_candidates = []
                change_candidates.append(
                    (observation.timestamp, numeric_value)
                )
                change_run_length = len(change_candidates)
                if change_run_length >= confirmation_points:
                    reset_seed = [
                        value for _, value in change_candidates
                    ][-parameters.baseline_window :]
                    reset_median = float(np.median(reset_seed))
                    value_signals.append(
                        _signal(
                            TemporalDetectorCode.REGIME_CHANGE,
                            change_direction,
                            float(change_run_length),
                            float(confirmation_points),
                            (
                                "连续同方向异常达到确认门槛；当前时点仅使用"
                                "截至本时点的候选值触发未核实统计适配，并将"
                                "在本时点之后重置数值基线；这不是业务状态"
                                "认定。"
                            ),
                        )
                    )
                    reset_event = TemporalBaselineReset(
                        reset_number=len(baseline_resets) + 1,
                        change_started_at=change_candidates[0][0],
                        confirmed_at=observation.timestamp,
                        direction=change_direction,
                        confirmation_point_count=change_run_length,
                        previous_baseline_sample_count=baseline_count,
                        previous_baseline_median=median,
                        reset_seed_sample_count=len(reset_seed),
                        reset_baseline_median=reset_median,
                        new_baseline_epoch=baseline_epoch + 1,
                        explanation=(
                            f"连续 {change_run_length} 个"
                            f"{'正向' if change_direction == 'high' else '负向'}"
                            "异常触发未核实统计基线适配；旧基线保留在此前"
                            "时点的审计结果中，后续检测从候选片段建立的新"
                            "基线继续。该适配不能证明业务状态正常或稳定。"
                        ),
                    )
            else:
                change_candidate_direction = None
                change_candidates = []
        elif confirmation_points is not None:
            change_candidate_direction = None
            change_candidates = []

        source_signals = _source_health_signals(observation, parameters)
        signals = value_signals + source_signals
        value_anomaly = bool(value_signals)
        source_health_anomaly = bool(source_signals)
        accepted = bool(
            usable
            and observation.baseline_eligible
            and (
                not parameters.exclude_detected_anomalies_from_baseline
                or not value_anomaly
            )
        )
        if accepted and numeric_value is not None:
            history.append(numeric_value)
            if len(history) > parameters.baseline_window:
                history.pop(0)

        if usable:
            ewma_state = ewma_candidate

        baseline_count_after_update = len(history)
        if reset_seed is not None:
            baseline_count_after_update = len(reset_seed)

        contributions: dict[str, float] = {}
        for signal in signals:
            name = signal.detector.value
            contributions[name] = max(
                contributions.get(name, 0.0),
                signal.contribution,
            )

        page_positive = (
            page_cumulative_positive - page_minimum_positive
        )
        page_negative = (
            page_cumulative_negative - page_minimum_negative
        )
        points.append(
            TemporalPointResult(
                timestamp=observation.timestamp,
                observed_value=numeric_value,
                quality=observation.quality,
                missing=observation.missing,
                baseline_sample_count=baseline_count,
                baseline_sample_count_after_update=(
                    baseline_count_after_update
                ),
                baseline_epoch=baseline_epoch,
                baseline_median=median,
                baseline_mad=mad,
                robust_scale=scale,
                rolling_robust_z=rolling_z,
                ewma_value=ewma_candidate,
                ewma_standardized=ewma_standardized,
                cusum_positive=round(cusum_positive, 6),
                cusum_negative=round(cusum_negative, 6),
                page_hinkley_positive=round(page_positive, 6),
                page_hinkley_negative=round(page_negative, 6),
                thresholds=DetectorThresholds(
                    rolling_lower=rolling_lower,
                    rolling_upper=rolling_upper,
                    ewma_lower=ewma_lower,
                    ewma_upper=ewma_upper,
                    minimum_scale=parameters.minimum_scale,
                    minimum_relative_scale=(
                        parameters.minimum_relative_scale
                    ),
                    effective_scale_floor=effective_scale_floor,
                    cusum=parameters.cusum_threshold,
                    page_hinkley=parameters.page_hinkley_threshold,
                    minimum_quality=parameters.min_baseline_quality,
                    maximum_latency_seconds=(
                        parameters.max_latency_seconds
                    ),
                    maximum_revision_count=(
                        parameters.max_revision_count
                    ),
                ),
                signals=signals,
                contributions=contributions,
                value_anomaly=value_anomaly,
                source_health_anomaly=source_health_anomaly,
                anomalous=value_anomaly or source_health_anomaly,
                insufficient_history=not sufficient,
                baseline_eligible=observation.baseline_eligible,
                accepted_into_baseline=accepted,
                reset_seed_sample_count=(
                    len(reset_seed) if reset_seed is not None else 0
                ),
                change_direction=change_direction,
                change_run_length=change_run_length,
                baseline_reset_confirmed=reset_event is not None,
            )
        )

        if reset_event is not None and reset_seed is not None:
            history = list(reset_seed)
            ewma_state = reset_seed[0]
            for seed_value in reset_seed[1:]:
                ewma_state = (
                    parameters.ewma_alpha * seed_value
                    + (1.0 - parameters.ewma_alpha) * ewma_state
                )
            cusum_positive = 0.0
            cusum_negative = 0.0
            page_mean = float(np.mean(reset_seed))
            page_count = len(reset_seed)
            page_cumulative_positive = 0.0
            page_minimum_positive = 0.0
            page_cumulative_negative = 0.0
            page_minimum_negative = 0.0
            baseline_epoch += 1
            baseline_resets.append(reset_event)
            change_candidate_direction = None
            change_candidates = []

    episodes = _episodes(points, parameters)
    insufficient_history = len(history) < parameters.min_history
    anomaly_count = sum(point.anomalous for point in points)
    if anomaly_count:
        status: Literal[
            "insufficient_history",
            "normal",
            "anomalous",
        ] = "anomalous"
    elif insufficient_history:
        status = "insufficient_history"
    else:
        status = "normal"
    point_count = len(points)
    missing_count = sum(point.missing for point in points)
    late_count = sum(
        TemporalDetectorCode.SOURCE_LATENCY in signal_codes
        for signal_codes in (
            {signal.detector for signal in point.signals}
            for point in points
        )
    )
    revised_count = sum(
        TemporalDetectorCode.SOURCE_REVISION in signal_codes
        for signal_codes in (
            {signal.detector for signal in point.signals}
            for point in points
        )
    )
    low_quality_count = sum(
        TemporalDetectorCode.SOURCE_LOW_QUALITY in signal_codes
        for signal_codes in (
            {signal.detector for signal in point.signals}
            for point in points
        )
    )
    return TemporalSeriesResult(
        mine_id=first.mine_id,
        source_id=first.source_id,
        metric_code=first.metric_code,
        value_kind=value_kind,
        status=status,
        insufficient_history=insufficient_history,
        final_baseline_sample_count=len(history),
        cold_start_point_count=sum(
            point.insufficient_history for point in points
        ),
        anomaly_point_count=anomaly_count,
        source_health=SourceHealthSummary(
            point_count=point_count,
            missing_count=missing_count,
            late_count=late_count,
            revised_count=revised_count,
            low_quality_count=low_quality_count,
            baseline_ineligible_count=sum(
                not point.baseline_eligible for point in points
            ),
            baseline_accepted_count=sum(
                point.accepted_into_baseline for point in points
            ),
            reset_seed_sample_count=sum(
                point.reset_seed_sample_count for point in points
            ),
            missing_rate=round(missing_count / point_count, 6),
            late_rate=round(late_count / point_count, 6),
            revision_rate=round(revised_count / point_count, 6),
            low_quality_rate=round(
                low_quality_count / point_count,
                6,
            ),
        ),
        points=points,
        episodes=episodes,
        baseline_resets=baseline_resets,
    )


def detect_temporal_anomalies(
    request: TemporalDetectionRequest,
) -> TemporalDetectionResult:
    """Detect temporal anomalies without using future observations.

    Each series is sorted independently. A point is evaluated only against
    earlier baseline-eligible points. Missing and low-quality observations are
    kept as source-health evidence but never imputed or inserted into the
    numeric baseline.
    """

    grouped: dict[
        tuple[str, str, str],
        list[TemporalObservation],
    ] = {}
    for observation in request.observations:
        key = (
            observation.mine_id,
            observation.source_id,
            observation.metric_code,
        )
        grouped.setdefault(key, []).append(observation)

    series = [
        _detect_series(grouped[key], request.parameters)
        for key in sorted(grouped)
    ]
    if request.report_start is not None and request.report_end is not None:
        series = [
            sliced
            for item in series
            if (
                sliced := _slice_series(
                    item,
                    request.parameters,
                    request.report_start,
                    request.report_end,
                )
            )
            is not None
        ]
    return TemporalDetectionResult(
        series=series,
        series_count=len(series),
        anomalous_series_count=sum(
            item.status == "anomalous" for item in series
        ),
        insufficient_history_series_count=sum(
            item.insufficient_history for item in series
        ),
    )


def _slice_series(
    series: TemporalSeriesResult,
    parameters: TemporalDetectionParameters,
    start: datetime,
    end: datetime,
) -> TemporalSeriesResult | None:
    """Keep report-window points while preserving their past-only baselines."""

    points = [
        point for point in series.points if start <= point.timestamp < end
    ]
    if not points:
        return None
    anomaly_count = sum(point.anomalous for point in points)
    insufficient = any(point.insufficient_history for point in points)
    if anomaly_count:
        status: Literal[
            "insufficient_history",
            "normal",
            "anomalous",
        ] = "anomalous"
    elif insufficient:
        status = "insufficient_history"
    else:
        status = "normal"
    missing_count = sum(point.missing for point in points)
    late_count = sum(
        any(
            signal.detector is TemporalDetectorCode.SOURCE_LATENCY
            for signal in point.signals
        )
        for point in points
    )
    revised_count = sum(
        any(
            signal.detector is TemporalDetectorCode.SOURCE_REVISION
            for signal in point.signals
        )
        for point in points
    )
    low_quality_count = sum(
        any(
            signal.detector is TemporalDetectorCode.SOURCE_LOW_QUALITY
            for signal in point.signals
        )
        for point in points
    )
    point_count = len(points)
    final_baseline_count = points[-1].baseline_sample_count_after_update
    if final_baseline_count is None:
        final_baseline_count = min(
            parameters.baseline_window,
            points[-1].baseline_sample_count
            + int(points[-1].accepted_into_baseline),
        )
    return TemporalSeriesResult(
        mine_id=series.mine_id,
        source_id=series.source_id,
        metric_code=series.metric_code,
        value_kind=series.value_kind,
        status=status,
        insufficient_history=insufficient,
        final_baseline_sample_count=final_baseline_count,
        cold_start_point_count=sum(
            point.insufficient_history for point in points
        ),
        anomaly_point_count=anomaly_count,
        source_health=SourceHealthSummary(
            point_count=point_count,
            missing_count=missing_count,
            late_count=late_count,
            revised_count=revised_count,
            low_quality_count=low_quality_count,
            baseline_ineligible_count=sum(
                not point.baseline_eligible for point in points
            ),
            baseline_accepted_count=sum(
                point.accepted_into_baseline for point in points
            ),
            reset_seed_sample_count=sum(
                point.reset_seed_sample_count for point in points
            ),
            missing_rate=round(missing_count / point_count, 6),
            late_rate=round(late_count / point_count, 6),
            revision_rate=round(revised_count / point_count, 6),
            low_quality_rate=round(
                low_quality_count / point_count,
                6,
            ),
        ),
        points=points,
        episodes=_episodes(points, parameters),
        baseline_resets=[
            reset
            for reset in series.baseline_resets
            if start <= reset.confirmed_at < end
        ],
    )
