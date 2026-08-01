"""Audited orchestration for temporal detector outputs.

Dashboard GET requests remain read-only.  This module is called after a new
analysis batch is committed, then writes immutable model, finding and episode
records.  Detector records use a content-qualified version suffix so a later
source revision creates a new auditable record instead of overwriting an
earlier conclusion.
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Any

from pydantic import ValidationError

from .casework import (
    ALGORITHM_FEATURE_VERSION,
    LocalRepository,
    select_authoritative_algorithm_feature,
    sha256_json,
)
from .temporal import (
    TemporalDetectionParameters,
    TemporalDetectionRequest,
    TemporalObservation,
    detect_temporal_anomalies,
)


TEMPORAL_DETECTOR_VERSION = "2.3.0"
_FEATURE_LIMIT = 100_000
_ACTIVE_MAX_CONTIGUOUS_GAP_SECONDS = 172_800.0


def active_temporal_parameters() -> TemporalDetectionParameters:
    """Return the governed online configuration for this release."""

    return TemporalDetectionParameters(
        # A percentage of a residual median close to zero is not a useful
        # scale floor.  Until feature-specific absolute floors are governed,
        # the active policy reports and uses only the conservative generic
        # absolute floor.
        minimum_relative_scale=0.0,
        # Unreviewed anomalies must never promote themselves into the formal
        # online baseline.  Statistical reset remains an explicit opt-in in
        # the reusable detector, not an active monitoring policy.
        baseline_reset_confirmation_points=None,
        baseline_reset_candidate_max_gap_seconds=(
            _ACTIVE_MAX_CONTIGUOUS_GAP_SECONDS
        ),
        # Consecutive database rows separated by more than two days are not
        # one operational alert episode.
        episode_max_gap_seconds=_ACTIVE_MAX_CONTIGUOUS_GAP_SECONDS,
    )


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _observations(
    features: list[dict[str, Any]],
    *,
    baseline_eligible_run_ids: set[str],
) -> tuple[list[TemporalObservation], int]:
    candidates: dict[
        tuple[str, str, str, datetime],
        list[tuple[dict[str, Any], TemporalObservation]],
    ] = {}
    rejected = 0
    for feature in features:
        event_time = _instant(feature.get("observed_at"))
        mine_id = feature.get("mine_id")
        metric_code = feature.get("feature_code")
        raw_source_key = feature.get("source_key")
        raw_value = feature.get("value")
        raw_quality = feature.get("quality_score")
        if (
            feature.get("hash_valid") is not True
            or event_time is None
            or not isinstance(mine_id, str)
            or not mine_id.strip()
            or not isinstance(metric_code, str)
            or not metric_code.strip()
            or not isinstance(raw_value, (int, float))
            or isinstance(raw_value, bool)
            or not math.isfinite(float(raw_value))
        ):
            rejected += 1
            continue
        compatibility = feature.get("compatibility")
        if (
            not isinstance(compatibility, dict)
            or compatibility.get("trusted_mode") != "governed"
            or compatibility.get("governance_complete") is not True
        ):
            rejected += 1
            continue
        quality = 1.0 if raw_quality is None else raw_quality
        if (
            not isinstance(quality, (int, float))
            or isinstance(quality, bool)
            or not math.isfinite(float(quality))
        ):
            rejected += 1
            continue
        source_id = (
            raw_source_key.strip()
            if isinstance(raw_source_key, str) and raw_source_key.strip()
            else "analysis_engine"
        )
        try:
            observation = TemporalObservation(
                mine_id=mine_id.strip(),
                source_id=source_id,
                metric_code=metric_code.strip(),
                timestamp=event_time,
                signed_residual=float(raw_value),
                quality=float(quality),
            )
        except ValidationError:
            rejected += 1
            continue
        key = (
            observation.mine_id,
            observation.source_id,
            observation.metric_code,
            observation.timestamp,
        )
        candidates.setdefault(key, []).append(
            (feature, observation)
        )

    observations: list[TemporalObservation] = []
    for key in sorted(candidates):
        point_candidates = candidates[key]
        selection = select_authoritative_algorithm_feature(
            [item[0] for item in point_candidates]
        )
        if selection["status"] != "selected":
            rejected += len(point_candidates)
            continue
        selected_feature = selection["selected"]
        selected = next(
            observation
            for feature, observation in point_candidates
            if feature is selected_feature
        )
        authority = selected_feature.get("authority_order")
        revision_count = (
            int(authority.get("source_revision_no") or 0)
            if isinstance(authority, dict)
            else 0
        )
        observations.append(
            selected.model_copy(
                update={
                    "revision_count": revision_count,
                    "baseline_eligible": (
                        str(selected_feature.get("run_id") or "")
                        in baseline_eligible_run_ids
                    ),
                }
            )
        )
    return observations, rejected


def verified_normal_run_ids(
    repository: LocalRepository,
    *,
    mine_ids: set[str] | None,
) -> set[str]:
    """Fail closed to current, integrity-eligible verified-normal labels."""

    labels = repository.list_run_reference_labels(
        labels={"verified_normal"},
        mine_ids=mine_ids,
        include_ineligible=False,
        limit=_FEATURE_LIMIT,
    )
    return {
        str(label["run_id"])
        for label in labels
        if (
            isinstance(label, dict)
            and label.get("run_id")
            and label.get("label") == "verified_normal"
            and label.get("reference_eligible") is True
        )
    }


def initialize_temporal_model_snapshot(
    repository: LocalRepository,
) -> int:
    """Register the immutable detector configuration used by this release."""

    parameters = active_temporal_parameters()
    snapshot_parameters = {
        **parameters.model_dump(mode="json"),
        "baseline_admission_policy": (
            "current_verified_normal_and_reference_eligible"
        ),
    }
    return repository.save_algorithm_model_snapshots(
        [
            {
                "detector_code": "temporal_ensemble",
                "detector_version": TEMPORAL_DETECTOR_VERSION,
                "scope_key": "global",
                "training_start": None,
                "training_end": None,
                "sample_count": 0,
                "activation_status": "active",
                "parameters": snapshot_parameters,
                "method": (
                    "past-only rolling MAD, EWMA, bidirectional CUSUM, "
                    "Page-Hinkley, a generic absolute scale floor, "
                    "verified-normal-only baseline admission, baseline "
                    "reset disabled, bounded alert episodes and "
                    "source-health rules"
                ),
            }
        ]
    )


def _qualified_version(document: dict[str, Any]) -> str:
    return (
        f"{TEMPORAL_DETECTOR_VERSION}+"
        f"{sha256_json(document)[:12]}"
    )


def refresh_temporal_audit(
    repository: LocalRepository,
    *,
    mine_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Run past-only detection and append reproducible audit records."""

    snapshot_inserted = initialize_temporal_model_snapshot(repository)
    features = repository.list_algorithm_features(
        mine_ids=mine_ids,
        feature_version=ALGORITHM_FEATURE_VERSION,
        limit=_FEATURE_LIMIT,
        include_overflow_sentinel=True,
    )
    if len(features) > _FEATURE_LIMIT:
        return {
            "status": "skipped_feature_limit",
            "feature_count": len(features),
            "rejected_feature_count": 0,
            "baseline_eligible_observation_count": 0,
            "baseline_ineligible_observation_count": 0,
            "series_count": 0,
            "finding_count": 0,
            "episode_count": 0,
            "inserted_findings": 0,
            "inserted_episodes": 0,
            "inserted_model_snapshots": snapshot_inserted,
        }

    eligible_run_ids = verified_normal_run_ids(
        repository,
        mine_ids=mine_ids,
    )
    observations, rejected = _observations(
        features,
        baseline_eligible_run_ids=eligible_run_ids,
    )
    baseline_eligible_count = sum(
        observation.baseline_eligible for observation in observations
    )
    baseline_ineligible_count = (
        len(observations) - baseline_eligible_count
    )
    if not observations:
        return {
            "status": "insufficient_history",
            "feature_count": len(features),
            "rejected_feature_count": rejected,
            "baseline_eligible_observation_count": 0,
            "baseline_ineligible_observation_count": 0,
            "series_count": 0,
            "finding_count": 0,
            "episode_count": 0,
            "inserted_findings": 0,
            "inserted_episodes": 0,
            "inserted_model_snapshots": snapshot_inserted,
        }

    parameters = active_temporal_parameters()
    result = detect_temporal_anomalies(
        TemporalDetectionRequest(
            observations=observations,
            parameters=parameters,
        )
    )
    findings: list[dict[str, Any]] = []
    episodes: list[dict[str, Any]] = []
    for series in result.series:
        for point in series.points:
            for signal in point.signals:
                base = {
                    "mine_id": series.mine_id,
                    "observed_at": point.timestamp,
                    "feature_code": series.metric_code,
                    "source_key": series.source_id,
                    "detector_code": signal.detector.value,
                    "status": "anomalous",
                    "score": signal.contribution,
                    "baseline_sample_count": point.baseline_sample_count,
                    "baseline_epoch": point.baseline_epoch,
                    "baseline_reset_confirmed": (
                        point.baseline_reset_confirmed
                    ),
                    "baseline_eligible": point.baseline_eligible,
                    "accepted_into_baseline": (
                        point.accepted_into_baseline
                    ),
                    "reset_seed_sample_count": (
                        point.reset_seed_sample_count
                    ),
                    "direction": signal.direction,
                    "observed_statistic": signal.observed_statistic,
                    "threshold": signal.threshold,
                    "explanation": signal.explanation,
                    "thresholds": point.thresholds,
                    "algorithm_version": TEMPORAL_DETECTOR_VERSION,
                }
                findings.append(
                    {
                        **base,
                        "detector_version": _qualified_version(base),
                    }
                )
        for episode in series.episodes:
            base = {
                "mine_id": series.mine_id,
                "feature_code": series.metric_code,
                "source_key": series.source_id,
                "detector_code": "temporal_ensemble",
                "started_at": episode.start,
                "ended_at": episode.end,
                "peak_score": episode.maximum_contribution,
                "finding_count": episode.anomaly_point_count,
                "detectors": [
                    detector.value for detector in episode.detectors
                ],
                "directions": episode.directions,
                "spanned_point_count": episode.spanned_point_count,
                "explanation": episode.explanation,
                "algorithm_version": TEMPORAL_DETECTOR_VERSION,
            }
            episodes.append(
                {
                    **base,
                    "detector_version": _qualified_version(base),
                }
            )

    inserted_findings = repository.save_detector_findings(findings)
    inserted_episodes = repository.save_alert_episodes(episodes)
    return {
        "status": (
            "anomalous"
            if findings or episodes
            else (
                "insufficient_history"
                if result.insufficient_history_series_count
                else "no_signal"
            )
        ),
        "feature_count": len(features),
        "rejected_feature_count": rejected,
        "baseline_eligible_observation_count": (
            baseline_eligible_count
        ),
        "baseline_ineligible_observation_count": (
            baseline_ineligible_count
        ),
        "series_count": result.series_count,
        "finding_count": len(findings),
        "episode_count": len(episodes),
        "inserted_findings": inserted_findings,
        "inserted_episodes": inserted_episodes,
        "inserted_model_snapshots": snapshot_inserted,
    }


__all__ = [
    "TEMPORAL_DETECTOR_VERSION",
    "active_temporal_parameters",
    "initialize_temporal_model_snapshot",
    "refresh_temporal_audit",
    "verified_normal_run_ids",
]
