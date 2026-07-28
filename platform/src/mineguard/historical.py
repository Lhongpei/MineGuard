"""Leakage-safe, explainable conditional historical baseline.

This module deliberately keeps historical evidence separate from the physical
cross-validation result.  It selects governed reference windows, compares a
fixed multidimensional feature vector with robust median/MAD statistics, and
returns a historical assessment only.  It never mutates or reclassifies a
``ProductionAnalysisResult``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
import math
from statistics import median
from typing import Annotated, Literal, Mapping, Sequence

from pydantic import AwareDatetime, ConfigDict, Field, model_validator

from .models import (
    MetricCode,
    ProductionAnalysisRequest,
    ProductionAnalysisResult,
    StrictModel,
)


HISTORICAL_METHOD_VERSION = "conditional-max-score-mad-v2"
MAD_NORMAL_CONSISTENCY_FACTOR = 1.4826
RAW_ANOMALY_FEATURE = "raw_anomaly"
PRODUCTION_TRANSPORT_GAP_FEATURE = "gap_ratio.production_transport"
PRODUCTION_STOCK_FLOW_GAP_FEATURE = (
    "gap_ratio.production_wash_sales_inventory"
)
_RATIO_DENOMINATOR_FLOOR = 1e-9
_RAW_ANOMALY_MINIMUM_EFFECT = 0.05
_GAP_RATIO_MINIMUM_EFFECT = 0.005
_NORMALIZED_RESIDUAL_MINIMUM_EFFECT = 0.05
_ELIGIBLE_LABELS: frozenset["HistoricalLabel"]

_ShortCode = Annotated[str, Field(max_length=64)]
_ContextTag = Annotated[str, Field(max_length=128)]
_FeatureName = Annotated[str, Field(min_length=1, max_length=192)]
_FiniteFeature = Annotated[float, Field(ge=-1e15, le=1e15)]


class HistoricalLabel(StrEnum):
    """Governed outcome label attached to a historical window."""

    VERIFIED_NORMAL = "verified_normal"
    LEGITIMATE_EXCEPTION = "legitimate_exception"
    CONFIRMED_DATA_ERROR = "confirmed_data_error"
    CONFIRMED_TECHNICAL_ANOMALY = "confirmed_technical_anomaly"
    ADJUDICATED_VIOLATION = "adjudicated_violation"
    UNRESOLVED = "unresolved"


_ELIGIBLE_LABELS = frozenset(
    {
        HistoricalLabel.VERIFIED_NORMAL,
    }
)


class OperationalContext(StrictModel):
    """Operational state used for exact conditional-baseline matching.

    Empty defaults preserve compatibility with historical callers that do not
    yet collect contextual fields. Event codes and tags are canonicalized so
    exact matching is set-based rather than dependent on input order.
    """

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        strict=True,
    )

    regime_code: _ShortCode = ""
    shift_code: _ShortCode = ""
    season_code: _ShortCode = ""
    maintenance: bool | None = None
    approved_event_codes: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=64)]],
        Field(max_length=32),
    ] = Field(default_factory=list)
    tags: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(max_length=64),
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_and_canonicalize_sets(self) -> "OperationalContext":
        if len(self.approved_event_codes) != len(
            set(self.approved_event_codes)
        ):
            raise ValueError("approved_event_codes values must be unique")
        if len(self.tags) != len(set(self.tags)):
            raise ValueError("tags values must be unique")
        self.approved_event_codes = sorted(self.approved_event_codes)
        self.tags = sorted(self.tags)
        return self


class HistoricalReferenceSample(StrictModel):
    """One immutable, governed historical reference window."""

    sample_id: Annotated[str, Field(min_length=1, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    window_start: AwareDatetime
    window_end: AwareDatetime
    available_at: AwareDatetime
    compatibility_key: Annotated[str, Field(min_length=1, max_length=256)]
    hash_valid: bool = True
    quality_score: Annotated[float, Field(ge=0.0, le=1.0)]
    label: HistoricalLabel
    context: OperationalContext = Field(default_factory=OperationalContext)
    features: Annotated[
        dict[_FeatureName, _FiniteFeature],
        Field(min_length=1, max_length=256),
    ]

    @model_validator(mode="after")
    def validate_window(self) -> "HistoricalReferenceSample":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be later than window_start")
        return self


class HistoricalPolicy(StrictModel):
    """Selection and robust-scoring policy.

    The default needs 20 eligible windows and consumes at most the most recent
    500. The quality floor cannot be configured below the governed 0.8 floor.
    """

    minimum_samples: Annotated[int, Field(ge=1, le=500)] = 20
    maximum_samples: Annotated[int, Field(ge=1, le=500)] = 500
    minimum_quality_score: Annotated[
        float,
        Field(ge=0.8, le=1.0),
    ] = 0.8
    minimum_scale: Annotated[float, Field(gt=0.0, le=1e12)] = 1e-6
    rare_alpha: Annotated[float, Field(gt=0.0, le=1.0)] = 0.05

    @model_validator(mode="after")
    def validate_sample_limits(self) -> "HistoricalPolicy":
        if self.maximum_samples < self.minimum_samples:
            raise ValueError(
                "maximum_samples must be greater than or equal to "
                "minimum_samples"
            )
        return self


class HistoricalDimensionAssessment(StrictModel):
    """Explainable robust assessment for one feature dimension."""

    feature_name: str
    current_value: float
    reference_median: float
    reference_mad: Annotated[float, Field(ge=0.0)]
    robust_scale: Annotated[float, Field(gt=0.0)]
    robust_distance: Annotated[float, Field(ge=0.0)]
    finite_sample_exceedance_count: Annotated[int, Field(ge=0)]
    empirical_p_value: Annotated[float, Field(gt=0.0, le=1.0)]
    reference_minimum: float
    reference_maximum: float


class HistoricalAssessment(StrictModel):
    """Historical-only evidence returned alongside the physical conclusion."""

    method_version: str = HISTORICAL_METHOD_VERSION
    status: Literal["ready", "insufficient_history"]
    compatibility_key: str
    context_conditioned: bool
    current_context: OperationalContext | None = None
    decision_time: AwareDatetime
    current_features: dict[str, float]
    minimum_required_samples: Annotated[int, Field(ge=1, le=500)]
    maximum_selected_samples: Annotated[int, Field(ge=1, le=500)]
    eligible_sample_count: Annotated[int, Field(ge=0)]
    selected_sample_count: Annotated[int, Field(ge=0)]
    eligible_sample_ids: list[str] = Field(default_factory=list)
    eligible_sample_ids_truncated: bool = False
    selected_sample_ids: list[str] = Field(default_factory=list)
    excluded_mine_count: Annotated[int, Field(ge=0)] = 0
    excluded_future_count: Annotated[int, Field(ge=0)] = 0
    excluded_unavailable_count: Annotated[int, Field(ge=0)] = 0
    excluded_compatibility_count: Annotated[int, Field(ge=0)] = 0
    excluded_hash_count: Annotated[int, Field(ge=0)] = 0
    excluded_quality_count: Annotated[int, Field(ge=0)] = 0
    excluded_label_count: Annotated[int, Field(ge=0)] = 0
    excluded_context_count: Annotated[int, Field(ge=0)] = 0
    excluded_feature_count: Annotated[int, Field(ge=0)] = 0
    excluded_limit_count: Annotated[int, Field(ge=0)] = 0
    dimensions: dict[str, HistoricalDimensionAssessment] = Field(
        default_factory=dict
    )
    multiplicity_correction: Literal[
        "max_robust_distance_empirical"
    ] = (
        "max_robust_distance_empirical"
    )
    joint_robust_distance: Annotated[float, Field(ge=0.0)] | None = None
    joint_exceedance_count: Annotated[int, Field(ge=0)] | None = None
    driving_feature_names: list[str] = Field(default_factory=list)
    overall_p_value: Annotated[float, Field(gt=0.0, le=1.0)] | None = None
    rarity_score: Annotated[float, Field(ge=0.0, le=100.0)] | None = None
    historically_rare: bool | None = None
    physical_status_unchanged: Literal[True] = True
    explanation: str


class _AssessmentInput(StrictModel):
    current_mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    current_window_start: AwareDatetime
    current_decision_time: AwareDatetime
    current_context: OperationalContext | None
    current_features: Annotated[
        dict[_FeatureName, _FiniteFeature],
        Field(min_length=1, max_length=256),
    ]
    current_compatibility_key: Annotated[
        str,
        Field(min_length=1, max_length=256),
    ]
    samples: list[HistoricalReferenceSample]
    policy: HistoricalPolicy

    @model_validator(mode="after")
    def validate_sample_ids(self) -> "_AssessmentInput":
        sample_ids = [sample.sample_id for sample in self.samples]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("sample_id values must be unique")
        return self


def _finite(value: float, *, name: str) -> float:
    converted = float(value)
    if not math.isfinite(converted):
        raise ValueError(f"{name} must be finite")
    return converted


def _weighted_median_observation(
    request: ProductionAnalysisRequest,
    metric_code: MetricCode,
) -> float:
    """Return a deterministic reliability-weighted median raw observation."""

    observations = sorted(
        (
            (
                _finite(observation.value, name=observation.observation_id),
                _finite(
                    observation.source_reliability,
                    name=f"{observation.observation_id}.source_reliability",
                ),
                observation.observation_id,
            )
            for observation in request.observations
            if observation.metric_code is metric_code
        ),
        key=lambda item: (item[0], item[2]),
    )
    if not observations:
        raise ValueError(
            f"missing observation for historical feature {metric_code.value}"
        )
    total_weight = sum(item[1] for item in observations)
    threshold = total_weight / 2.0
    cumulative = 0.0
    for value, weight, _ in observations:
        cumulative += weight
        if cumulative >= threshold:
            return value
    return observations[-1][0]


def _gap_ratio(left: float, right: float) -> float:
    denominator = max(
        abs(left),
        abs(right),
        _RATIO_DENOMINATOR_FLOOR,
    )
    return _finite(abs(left - right) / denominator, name="gap ratio")


def _normalized_residual(
    result: ProductionAnalysisResult,
    metric_code: MetricCode,
) -> float:
    reconciled = result.reconciled_metrics.get(metric_code.value)
    if reconciled is None:
        reconciled = next(
            (
                value
                for value in result.reconciled_metrics.values()
                if value.metric_code is metric_code
            ),
            None,
        )
    if reconciled is None:
        raise ValueError(
            f"missing reconciled metric for historical feature "
            f"{metric_code.value}"
        )
    residual = _finite(
        reconciled.normalized_residual,
        name=f"{metric_code.value}.normalized_residual",
    )
    if residual < 0:
        raise ValueError("normalized_residual must be non-negative")
    return residual


def extract_historical_features(
    request: ProductionAnalysisRequest,
    result: ProductionAnalysisResult,
) -> dict[str, float]:
    """Extract the fixed, explainable feature vector for historical scoring.

    Raw gap ratios use a reliability-weighted median when a metric has several
    source observations. Normalized residuals come from the reconciled physical
    model and remain separate dimensions.
    """

    if result.mine_id != request.mine_id:
        raise ValueError("request and result mine_id values must match")
    if result.raw_anomaly_statistic is None:
        raise ValueError(
            "raw_anomaly_statistic is required for historical assessment"
        )
    raw_anomaly = _finite(
        result.raw_anomaly_statistic,
        name="raw_anomaly_statistic",
    )
    if raw_anomaly < 0:
        raise ValueError("raw_anomaly_statistic must be non-negative")

    production = _weighted_median_observation(
        request,
        MetricCode.REPORTED_PRODUCTION,
    )
    transport = _weighted_median_observation(
        request,
        MetricCode.MAIN_TRANSPORT,
    )
    wash_feed = _weighted_median_observation(
        request,
        MetricCode.WASH_FEED,
    )
    raw_sales = _weighted_median_observation(
        request,
        MetricCode.RAW_SALES,
    )
    inventory_change = _weighted_median_observation(
        request,
        MetricCode.RAW_INVENTORY_CHANGE,
    )
    stock_flow = wash_feed + raw_sales + inventory_change

    features: dict[str, float] = {
        RAW_ANOMALY_FEATURE: raw_anomaly,
        PRODUCTION_TRANSPORT_GAP_FEATURE: _gap_ratio(
            production,
            transport,
        ),
        PRODUCTION_STOCK_FLOW_GAP_FEATURE: _gap_ratio(
            production,
            stock_flow,
        ),
    }
    for metric_code in MetricCode:
        features[f"normalized_residual.{metric_code.value}"] = (
            _normalized_residual(result, metric_code)
        )
    return features


def _same_context(
    left: OperationalContext,
    right: OperationalContext,
) -> bool:
    return left.model_dump(mode="json") == right.model_dump(mode="json")


def _dimension_assessment(
    feature_name: str,
    current_value: float,
    reference_values: list[float],
    *,
    minimum_scale: float,
) -> HistoricalDimensionAssessment:
    center = _finite(median(reference_values), name=f"{feature_name}.median")
    absolute_deviations = [abs(value - center) for value in reference_values]
    mad = _finite(
        median(absolute_deviations),
        name=f"{feature_name}.mad",
    )
    if feature_name == RAW_ANOMALY_FEATURE:
        domain_minimum_effect = _RAW_ANOMALY_MINIMUM_EFFECT
    elif feature_name.startswith("gap_ratio."):
        domain_minimum_effect = _GAP_RATIO_MINIMUM_EFFECT
    elif feature_name.startswith("normalized_residual."):
        domain_minimum_effect = _NORMALIZED_RESIDUAL_MINIMUM_EFFECT
    else:
        domain_minimum_effect = minimum_scale
    scale = max(
        MAD_NORMAL_CONSISTENCY_FACTOR * mad,
        minimum_scale,
        domain_minimum_effect,
    )
    # Every fixed feature is a non-negative anomaly magnitude.  Only an
    # unusually high value is adverse; an unusually low/clean value must not
    # create a shadow review signal.
    current_distance = max(0.0, current_value - center) / scale
    reference_distances = [
        max(0.0, value - center) / scale for value in reference_values
    ]
    exceedances = sum(
        distance >= current_distance for distance in reference_distances
    )
    empirical_p = (1.0 + exceedances) / (len(reference_values) + 1.0)
    return HistoricalDimensionAssessment(
        feature_name=feature_name,
        current_value=current_value,
        reference_median=center,
        reference_mad=mad,
        robust_scale=scale,
        robust_distance=current_distance,
        finite_sample_exceedance_count=exceedances,
        empirical_p_value=empirical_p,
        reference_minimum=min(reference_values),
        reference_maximum=max(reference_values),
    )


def assess_historical_baseline(
    current_mine_id: str,
    current_window_start: datetime,
    current_context: OperationalContext | None,
    current_features: Mapping[str, float],
    current_compatibility_key: str,
    samples: Sequence[HistoricalReferenceSample],
    policy: HistoricalPolicy | None = None,
    current_decision_time: datetime | None = None,
) -> HistoricalAssessment:
    """Assess historical rarity with strict eligibility and no time leakage.

    When ``current_context`` is supplied, all context fields must match exactly.
    A shortage in that exact cohort produces ``insufficient_history``; the
    function never silently falls back to a broader pool.
    """

    validated = _AssessmentInput(
        current_mine_id=current_mine_id,
        current_window_start=current_window_start,
        current_decision_time=(
            current_decision_time or datetime.now(UTC)
        ),
        current_context=current_context,
        current_features=dict(current_features),
        current_compatibility_key=current_compatibility_key,
        samples=list(samples),
        policy=policy or HistoricalPolicy(),
    )
    active_policy = validated.policy
    cutoff = validated.current_window_start.astimezone(UTC)
    decision_time = validated.current_decision_time.astimezone(UTC)
    expected_feature_names = set(validated.current_features)

    excluded_mine = 0
    excluded_future = 0
    excluded_unavailable = 0
    excluded_compatibility = 0
    excluded_hash = 0
    excluded_quality = 0
    excluded_label = 0
    excluded_context = 0
    excluded_feature = 0
    eligible: list[HistoricalReferenceSample] = []

    for sample in validated.samples:
        if sample.mine_id != validated.current_mine_id:
            excluded_mine += 1
            continue
        # A reference window must be fully complete before the current window
        # starts.  Comparing starts alone would admit overlapping data.
        if sample.window_end.astimezone(UTC) > cutoff:
            excluded_future += 1
            continue
        if sample.available_at.astimezone(UTC) > decision_time:
            excluded_unavailable += 1
            continue
        if sample.compatibility_key != validated.current_compatibility_key:
            excluded_compatibility += 1
            continue
        if sample.hash_valid is not True:
            excluded_hash += 1
            continue
        if sample.quality_score < active_policy.minimum_quality_score:
            excluded_quality += 1
            continue
        if sample.label not in _ELIGIBLE_LABELS:
            excluded_label += 1
            continue
        if (
            validated.current_context is not None
            and not _same_context(sample.context, validated.current_context)
        ):
            excluded_context += 1
            continue
        if set(sample.features) != expected_feature_names:
            excluded_feature += 1
            continue
        eligible.append(sample)

    eligible.sort(
        key=lambda sample: (
            sample.window_end.astimezone(UTC),
            sample.sample_id,
        )
    )
    eligible_count = len(eligible)
    selected = eligible[-active_policy.maximum_samples :]
    excluded_limit = eligible_count - len(selected)
    eligible_ids = [
        sample.sample_id
        for sample in eligible[-active_policy.maximum_samples :]
    ]
    selected_ids = [sample.sample_id for sample in selected]

    common = {
        "compatibility_key": validated.current_compatibility_key,
        "context_conditioned": validated.current_context is not None,
        "current_context": validated.current_context,
        "decision_time": decision_time,
        "current_features": validated.current_features,
        "minimum_required_samples": active_policy.minimum_samples,
        "maximum_selected_samples": active_policy.maximum_samples,
        "eligible_sample_count": eligible_count,
        "selected_sample_count": len(selected),
        "eligible_sample_ids": eligible_ids,
        "eligible_sample_ids_truncated": (
            eligible_count > len(eligible_ids)
        ),
        "selected_sample_ids": selected_ids,
        "excluded_mine_count": excluded_mine,
        "excluded_future_count": excluded_future,
        "excluded_unavailable_count": excluded_unavailable,
        "excluded_compatibility_count": excluded_compatibility,
        "excluded_hash_count": excluded_hash,
        "excluded_quality_count": excluded_quality,
        "excluded_label_count": excluded_label,
        "excluded_context_count": excluded_context,
        "excluded_feature_count": excluded_feature,
        "excluded_limit_count": excluded_limit,
    }
    if len(selected) < active_policy.minimum_samples:
        context_note = (
            " for the exact operational context"
            if validated.current_context is not None
            else ""
        )
        return HistoricalAssessment(
            status="insufficient_history",
            **common,
            explanation=(
                f"Only {len(selected)} eligible prior samples{context_note}; "
                f"at least {active_policy.minimum_samples} are required. "
                "No historical rarity conclusion was produced, and the "
                "physical status remains unchanged."
            ),
        )

    dimensions: dict[str, HistoricalDimensionAssessment] = {}
    for feature_name in sorted(expected_feature_names):
        dimensions[feature_name] = _dimension_assessment(
            feature_name,
            validated.current_features[feature_name],
            [sample.features[feature_name] for sample in selected],
            minimum_scale=active_policy.minimum_scale,
        )
    current_joint_distance = max(
        assessment.robust_distance for assessment in dimensions.values()
    )
    driving_features = sorted(
        feature_name
        for feature_name, assessment in dimensions.items()
        if math.isclose(
            assessment.robust_distance,
            current_joint_distance,
            rel_tol=1e-12,
            abs_tol=1e-12,
        )
    )
    reference_joint_distances = [
        max(
            max(
                0.0,
                sample.features[feature_name]
                - dimensions[feature_name].reference_median,
            )
            / dimensions[feature_name].robust_scale
            for feature_name in sorted(expected_feature_names)
        )
        for sample in selected
    ]
    joint_exceedances = sum(
        distance >= current_joint_distance
        for distance in reference_joint_distances
    )
    overall_p = (1.0 + joint_exceedances) / (len(selected) + 1.0)
    rarity_score = min(100.0, max(0.0, 100.0 * (1.0 - overall_p)))
    historically_rare = overall_p <= active_policy.rare_alpha

    return HistoricalAssessment(
        status="ready",
        **common,
        dimensions=dimensions,
        joint_robust_distance=current_joint_distance,
        joint_exceedance_count=joint_exceedances,
        driving_feature_names=driving_features,
        overall_p_value=overall_p,
        rarity_score=rarity_score,
        historically_rare=historically_rare,
        explanation=(
            "Each non-negative anomaly dimension uses an upper-tail median, "
            "1.4826×MAD score with a domain minimum-effect floor and a "
            "finite-sample +1 empirical p-value. The overall "
            "p-value ranks the maximum robust distance across dimensions, "
            "so multiplicity is handled jointly without making a 20-sample "
            "baseline unable to flag any extreme window. This is historical "
            "evidence only; the physical status remains unchanged."
        ),
    )


__all__ = [
    "HISTORICAL_METHOD_VERSION",
    "MAD_NORMAL_CONSISTENCY_FACTOR",
    "HistoricalAssessment",
    "HistoricalDimensionAssessment",
    "HistoricalLabel",
    "HistoricalPolicy",
    "HistoricalReferenceSample",
    "OperationalContext",
    "extract_historical_features",
    "assess_historical_baseline",
]
