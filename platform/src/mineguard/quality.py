from __future__ import annotations

from .models import (
    DataQualityResult,
    MetricObservation,
    ProductionAnalysisRequest,
)


QUALITY_WEIGHTS = {
    "completeness": 0.25,
    "timeliness": 0.15,
    "device_health": 0.15,
    "calibration": 0.15,
    "clock": 0.10,
    "lineage": 0.10,
    "uniqueness": 0.10,
}


def observation_quality_score(observation: MetricObservation) -> float:
    signals = observation.quality
    score = sum(
        weight * float(getattr(signals, field))
        for field, weight in QUALITY_WEIGHTS.items()
    )
    return round(score * 100.0, 3)


def evaluate_data_quality(
    request: ProductionAnalysisRequest,
) -> DataQualityResult:
    scores = {
        observation.observation_id: observation_quality_score(observation)
        for observation in request.observations
    }
    reasons: list[str] = []
    unverified_dimensions = sorted(
        {
            f"{observation.observation_id}:{dimension}"
            for observation in request.observations
            for dimension in observation.quality.unverified_dimensions
        }
    )

    for observation in request.observations:
        if not observation.quality.signature_valid:
            reasons.append(
                f"{observation.observation_id}: signature_invalid"
            )
        reasons.extend(
            f"{observation.observation_id}: {flag}"
            for flag in observation.quality.blocking_flags
        )

    required_codes = {
        "coal.reported_output_t",
        "coal.main_transport_t",
        "wash.feed_t",
        "sales.raw_shipped_t",
        "inventory.raw_change_t",
    }
    available_codes = {
        observation.metric_code.value for observation in request.observations
    }
    missing = sorted(required_codes - available_codes)
    reasons.extend(f"missing_required_metric: {code}" for code in missing)

    minimum_score = min(scores.values()) if scores else None
    for observation_id, observation_score in scores.items():
        if (
            observation_score
            < request.parameters.minimum_observation_quality
        ):
            reasons.append(
                f"{observation_id}: observation_quality_below_floor "
                f"({observation_score:.3f} < "
                f"{request.parameters.minimum_observation_quality:.3f})"
            )

    score = (
        sum(scores.values()) / len(scores)
        if scores
        else 0.0
    )
    if reasons or score < request.parameters.quality_gate:
        status = "blocked"
    elif unverified_dimensions or score < 80:
        status = "degraded"
    else:
        status = "sufficient"

    return DataQualityResult(
        score=round(score, 3),
        status=status,
        blocking_reasons=sorted(set(reasons)),
        observation_scores=scores,
        minimum_observation_score=minimum_score,
        quality_gate=request.parameters.quality_gate,
        minimum_observation_quality=(
            request.parameters.minimum_observation_quality
        ),
        unverified_dimensions=unverified_dimensions,
    )
