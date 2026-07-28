"""Leakage-safe historical calibration for governed production analyses.

Only completed, technically consistent and sufficiently high-quality windows
strictly from the same mine are eligible.  A minimum sample count is required
before the empirical distribution is exposed to the optimizer; cold starts
therefore remain explicit instead of producing unstable pseudo-probabilities.
"""

from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
import math
from typing import Annotated, Any, Protocol

from pydantic import Field

from .casework import (
    ALGORITHM_FEATURE_VERSION,
    algorithm_feature_compatibility_key,
    build_algorithm_feature_compatibility,
    canonical_json,
    select_authoritative_algorithm_feature,
    sha256_json,
)
from .historical import OperationalContext
from .models import ProductionAnalysisRequest, StrictModel


CALIBRATION_POLICY_VERSION = "reviewed-context-compatible-v3"


class HistoricalCalibrationPolicy(StrictModel):
    minimum_samples: Annotated[int, Field(ge=3, le=10_000)] = 20
    maximum_samples: Annotated[int, Field(ge=3, le=10_000)] = 500
    minimum_quality_score: Annotated[
        float,
        Field(ge=0.0, le=1.0),
    ] = 0.8


class CalibrationSelection(StrictModel):
    policy_version: str = CALIBRATION_POLICY_VERSION
    status: str
    compatibility_key: str | None = None
    compatibility_document: dict[str, Any] | None = None
    scores: list[float] = Field(default_factory=list)
    selected_feature_ids: list[str] = Field(default_factory=list)
    selected_feature_hashes: list[str] = Field(default_factory=list)
    selected_run_ids: list[str] = Field(default_factory=list)
    reference_manifest: list[dict[str, Any]] = Field(default_factory=list)
    reference_manifest_sha256: str | None = None
    reference_manifest_as_of: str | None = None
    eligible_sample_count: Annotated[int, Field(ge=0)]
    selected_sample_count: Annotated[int, Field(ge=0)]
    excluded_future_count: Annotated[int, Field(ge=0)] = 0
    excluded_quality_count: Annotated[int, Field(ge=0)] = 0
    excluded_status_count: Annotated[int, Field(ge=0)] = 0
    excluded_label_count: Annotated[int, Field(ge=0)] = 0
    excluded_invalid_count: Annotated[int, Field(ge=0)] = 0
    excluded_incompatible_count: Annotated[int, Field(ge=0)] = 0
    excluded_ambiguous_count: Annotated[int, Field(ge=0)] = 0
    excluded_superseded_count: Annotated[int, Field(ge=0)] = 0
    history_limit_exceeded: bool = False
    reviewed_labels_required: bool = False


class AlgorithmFeatureReader(Protocol):
    def list_algorithm_features(
        self,
        *,
        mine_ids: set[str] | None = None,
        feature_code: str | None = None,
        source_key: str | None = None,
        feature_version: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        limit: int = 10_000,
        include_overflow_sentinel: bool = False,
    ) -> list[dict[str, Any]]: ...


def _context_from_run(
    run: dict[str, Any],
    mine_id: str,
) -> OperationalContext:
    context = run.get("batch_context")
    raw: Any = None
    if isinstance(context, dict):
        raw = context.get("operational_context")
        reports = context.get("mine_reports")
        if isinstance(reports, list):
            report = next(
                (
                    candidate
                    for candidate in reports
                    if isinstance(candidate, dict)
                    and str(candidate.get("mine_id") or "") == mine_id
                ),
                None,
            )
            if report is not None:
                raw = report.get("operational_context")
    return OperationalContext.model_validate(
        raw if isinstance(raw, dict) else {}
    )


def _reviewed_normal_run_ids(
    repository: AlgorithmFeatureReader,
    *,
    mine_id: str,
    operational_context: OperationalContext | None,
) -> set[str]:
    """Return hash-valid, active, explicitly reviewed normal runs.

    A reader without the reviewed-label API fails closed.  Legitimate
    exceptions stay in the parallel historical assessment and do not widen
    the solver's empirical normal calibration distribution.
    """

    list_labels = getattr(repository, "list_run_reference_labels", None)
    if not callable(list_labels):
        return set()
    labels = list_labels(
        labels={"verified_normal"},
        mine_ids={mine_id},
        include_ineligible=False,
        limit=100_000,
    )
    if operational_context is None:
        return {
            str(label["run_id"])
            for label in labels
            if isinstance(label, dict) and label.get("run_id")
        }
    get_run = getattr(repository, "get_run", None)
    if not callable(get_run):
        return set()
    expected = operational_context.model_dump(mode="json")
    selected: set[str] = set()
    for label in labels:
        if not isinstance(label, dict) or not label.get("run_id"):
            continue
        run_id = str(label["run_id"])
        try:
            run_context = _context_from_run(
                get_run(run_id),
                mine_id,
            )
        except (KeyError, TypeError, ValueError):
            continue
        if run_context.model_dump(mode="json") == expected:
            selected.add(run_id)
    return selected


def _context_is_complete(
    context: OperationalContext | None,
) -> bool:
    return bool(
        context is not None
        and context.regime_code
        and context.shift_code
        and context.season_code
        and context.maintenance is not None
    )


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def select_historical_calibration(
    features: list[dict[str, Any]],
    *,
    mine_id: str,
    cutoff: datetime,
    compatibility_key: str | None = None,
    compatibility_document: dict[str, Any] | None = None,
    policy: HistoricalCalibrationPolicy | None = None,
    history_limit_exceeded: bool = False,
    eligible_run_ids: set[str] | None = None,
) -> CalibrationSelection:
    """Select recent normal-reference scores without using future windows."""

    active_policy = policy or HistoricalCalibrationPolicy()
    cutoff_utc = cutoff.astimezone(UTC)
    if compatibility_document is not None:
        calculated_key = algorithm_feature_compatibility_key(compatibility_document)
        if compatibility_key is not None and compatibility_key != calculated_key:
            raise ValueError("compatibility_key does not match compatibility_document")
        compatibility_key = calculated_key
    eligible_candidates: list[tuple[datetime, dict[str, Any]]] = []
    excluded_future = 0
    excluded_quality = 0
    excluded_status = 0
    excluded_label = 0
    excluded_invalid = 0
    excluded_incompatible = 0
    excluded_ambiguous = 0
    excluded_superseded = 0

    for feature in features:
        if (
            feature.get("mine_id") != mine_id
            or feature.get("feature_code") != "balance.raw_anomaly"
        ):
            excluded_invalid += 1
            continue
        run_id = feature.get("run_id")
        if eligible_run_ids is not None and (
            not isinstance(run_id, str) or run_id not in eligible_run_ids
        ):
            excluded_label += 1
            continue
        feature_compatibility = feature.get("compatibility")
        feature_compatibility_key = feature.get("compatibility_key")
        compatible = bool(
            compatibility_key
            and feature.get("feature_version") == ALGORITHM_FEATURE_VERSION
            and isinstance(feature_compatibility, dict)
            and isinstance(feature_compatibility_key, str)
            and algorithm_feature_compatibility_key(feature_compatibility)
            == feature_compatibility_key
            and feature_compatibility_key == compatibility_key
            and feature_compatibility.get("trusted_mode") == "governed"
            and feature_compatibility.get("governance_complete") is True
            and (
                compatibility_document is None
                or canonical_json(feature_compatibility)
                == canonical_json(compatibility_document)
            )
        )
        if not compatible:
            excluded_incompatible += 1
            continue
        observed_at = _instant(feature.get("observed_at"))
        value = feature.get("value")
        feature_id = feature.get("feature_id")
        feature_hash = feature.get("feature_sha256")
        if (
            observed_at is None
            or not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            or float(value) < 0
            or feature.get("hash_valid") is False
            or not isinstance(feature_id, str)
            or not feature_id
            or not isinstance(feature_hash, str)
            or not feature_hash
        ):
            excluded_invalid += 1
            continue
        # A prior window ending exactly when the current window starts is
        # complete and may be used.  Anything later is future information.
        if observed_at > cutoff_utc:
            excluded_future += 1
            continue
        quality = feature.get("quality_score")
        if (
            not isinstance(quality, (int, float))
            or isinstance(quality, bool)
            or not math.isfinite(float(quality))
            or float(quality) < active_policy.minimum_quality_score
        ):
            excluded_quality += 1
            continue
        details = feature.get("details")
        status = details.get("technical_status") if isinstance(details, dict) else None
        if status != "consistent":
            excluded_status += 1
            continue
        eligible_candidates.append((observed_at, feature))

    grouped: dict[
        tuple[str, str, str, str, str],
        list[tuple[datetime, dict[str, Any]]],
    ] = {}
    for observed_at, feature in eligible_candidates:
        key = (
            mine_id,
            observed_at.isoformat(),
            "balance.raw_anomaly",
            str(feature.get("source_key") or ""),
            ALGORITHM_FEATURE_VERSION,
        )
        grouped.setdefault(key, []).append((observed_at, feature))

    eligible: list[tuple[datetime, str, float, str, str, str]] = []
    for group in grouped.values():
        observed_at = group[0][0]
        candidates = [item[1] for item in group]
        if len(candidates) == 1:
            selected_feature = candidates[0]
        else:
            authority = select_authoritative_algorithm_feature(candidates)
            selected_feature = authority.get("selected")
            if authority.get("status") != "selected" or not isinstance(
                selected_feature, dict
            ):
                excluded_ambiguous += len(candidates)
                continue
            excluded_superseded += len(candidates) - 1
        eligible.append(
            (
                observed_at,
                str(selected_feature["feature_id"]),
                float(selected_feature["value"]),
                str(selected_feature["feature_id"]),
                str(selected_feature["feature_sha256"]),
                str(selected_feature["run_id"]),
            )
        )

    eligible.sort(key=lambda item: (item[0], item[1]))
    selected = eligible[-active_policy.maximum_samples :]
    enough = (
        compatibility_key is not None
        and not history_limit_exceeded
        and len(selected) >= active_policy.minimum_samples
    )
    scores = [item[2] for item in selected] if enough else []
    selected_ids = [item[3] for item in selected] if enough else []
    selected_hashes = [item[4] for item in selected] if enough else []
    selected_run_ids = [item[5] for item in selected] if enough else []
    if compatibility_key is None:
        status = "compatibility_required"
    elif history_limit_exceeded:
        status = "history_limit_exceeded"
    elif eligible_run_ids is not None and not eligible_run_ids:
        status = "insufficient_reviewed_history"
    elif enough:
        status = "ready"
    else:
        status = "insufficient_history"
    return CalibrationSelection(
        status=status,
        compatibility_key=compatibility_key,
        compatibility_document=compatibility_document,
        scores=scores,
        selected_feature_ids=selected_ids,
        selected_feature_hashes=selected_hashes,
        selected_run_ids=selected_run_ids,
        eligible_sample_count=len(eligible),
        selected_sample_count=len(scores),
        excluded_future_count=excluded_future,
        excluded_quality_count=excluded_quality,
        excluded_status_count=excluded_status,
        excluded_label_count=excluded_label,
        excluded_invalid_count=excluded_invalid,
        excluded_incompatible_count=excluded_incompatible,
        excluded_ambiguous_count=excluded_ambiguous,
        excluded_superseded_count=excluded_superseded,
        history_limit_exceeded=history_limit_exceeded,
        reviewed_labels_required=eligible_run_ids is not None,
    )


def _calibration_manifest(
    repository: AlgorithmFeatureReader,
    selection: CalibrationSelection,
    *,
    as_of: datetime,
) -> tuple[list[dict[str, Any]], str] | None:
    get_label = getattr(repository, "get_run_reference_label", None)
    get_run = getattr(repository, "get_run", None)
    if not callable(get_label) or not callable(get_run):
        return None
    manifest: list[dict[str, Any]] = []
    for run_id, feature_id, feature_hash in zip(
        selection.selected_run_ids,
        selection.selected_feature_ids,
        selection.selected_feature_hashes,
        strict=True,
    ):
        try:
            label = get_label(run_id)
            run = get_run(run_id)
        except (KeyError, TypeError, ValueError):
            return None
        if (
            not isinstance(label, dict)
            or label.get("label") != "verified_normal"
            or label.get("reference_eligible") is not True
            or not isinstance(run, dict)
            or run.get("batch_reference_integrity_eligible") is not True
        ):
            return None
        manifest.append(
            {
                "run_id": run_id,
                "feature_id": feature_id,
                "feature_sha256": feature_hash,
                "run_input_sha256": str(run.get("input_sha256") or ""),
                "run_result_sha256": str(run.get("result_sha256") or ""),
                "batch_request_sha256": str(
                    run.get("batch_request_sha256") or ""
                ),
                "batch_response_sha256": str(
                    run.get("batch_response_sha256") or ""
                ),
                "batch_context_sha256": str(
                    run.get("batch_context_sha256") or ""
                ),
                "label_sequence": int(label["sequence"]),
                "label_event_hash": str(label["event_hash"]),
                "label_created_at": str(label["created_at"]),
            }
        )
    document = {
        "as_of": as_of.isoformat(),
        "policy_version": selection.policy_version,
        "compatibility_key": selection.compatibility_key,
        "items": manifest,
    }
    return manifest, sha256_json(document)


def _apply_historical_calibration(
    repository: AlgorithmFeatureReader,
    request: ProductionAnalysisRequest,
    *,
    policy: HistoricalCalibrationPolicy | None = None,
    engine_version: str | None = None,
    trusted_mode: str | None = None,
    profile_id: str | None = None,
    profile_version: str | int | None = None,
    registry_snapshot_hash: str | None = None,
    operational_context: OperationalContext | None = None,
) -> tuple[ProductionAnalysisRequest, CalibrationSelection]:
    features = repository.list_algorithm_features(
        mine_ids={request.mine_id},
        feature_code="balance.raw_anomaly",
        feature_version=ALGORITHM_FEATURE_VERSION,
        limit=100_000,
        include_overflow_sentinel=True,
    )
    history_limit_exceeded = len(features) > 100_000
    compatibility_document: dict[str, Any] | None = None
    compatibility_key: str | None = None
    if (
        engine_version
        and trusted_mode == "governed"
        and profile_id
        and profile_version is not None
        and registry_snapshot_hash
    ):
        compatibility_document = build_algorithm_feature_compatibility(
            request,
            engine_version=engine_version,
            trusted_mode=trusted_mode,
            profile_id=profile_id,
            profile_version=str(profile_version),
            registry_snapshot_hash=registry_snapshot_hash,
        )
        compatibility_key = algorithm_feature_compatibility_key(compatibility_document)
    context_complete = _context_is_complete(operational_context)
    reviewed_run_ids = (
        _reviewed_normal_run_ids(
            repository,
            mine_id=request.mine_id,
            operational_context=operational_context,
        )
        if trusted_mode == "governed" and context_complete
        else None
    )
    if trusted_mode == "governed" and not context_complete:
        reviewed_run_ids = set()
    selection = select_historical_calibration(
        features,
        mine_id=request.mine_id,
        cutoff=request.window_start,
        compatibility_key=compatibility_key,
        compatibility_document=compatibility_document,
        policy=policy,
        history_limit_exceeded=history_limit_exceeded,
        eligible_run_ids=reviewed_run_ids,
    )
    if trusted_mode == "governed" and not context_complete:
        selection = selection.model_copy(
            update={
                "status": "operational_context_required",
                "scores": [],
                "selected_feature_ids": [],
                "selected_feature_hashes": [],
                "selected_run_ids": [],
            }
        )
    elif selection.status == "ready":
        as_of = datetime.now(UTC)
        manifest_result = _calibration_manifest(
            repository,
            selection,
            as_of=as_of,
        )
        if manifest_result is None:
            selection = selection.model_copy(
                update={
                    "status": "reference_manifest_invalid",
                    "scores": [],
                    "selected_feature_ids": [],
                    "selected_feature_hashes": [],
                    "selected_run_ids": [],
                }
            )
        else:
            manifest, digest = manifest_result
            selection = selection.model_copy(
                update={
                    "reference_manifest": manifest,
                    "reference_manifest_sha256": digest,
                    "reference_manifest_as_of": as_of.isoformat(),
                }
            )
    return (
        request.model_copy(update={"calibration_scores": selection.scores}),
        selection,
    )


def apply_historical_calibration(
    repository: AlgorithmFeatureReader,
    request: ProductionAnalysisRequest,
    *,
    policy: HistoricalCalibrationPolicy | None = None,
    engine_version: str | None = None,
    trusted_mode: str | None = None,
    profile_id: str | None = None,
    profile_version: str | int | None = None,
    registry_snapshot_hash: str | None = None,
    operational_context: OperationalContext | None = None,
) -> tuple[ProductionAnalysisRequest, CalibrationSelection]:
    """Return a request copy carrying a reviewed, compatible baseline.

    All repository reads are held inside the repository's snapshot boundary
    when available. Missing governance, complete four-axis context, reviewed
    labels or a reproducible reference manifest fails closed to no scores.
    """

    snapshot_factory = getattr(repository, "read_snapshot", None)
    snapshot = (
        snapshot_factory() if callable(snapshot_factory) else nullcontext()
    )
    with snapshot:
        return _apply_historical_calibration(
            repository,
            request,
            policy=policy,
            engine_version=engine_version,
            trusted_mode=trusted_mode,
            profile_id=profile_id,
            profile_version=profile_version,
            registry_snapshot_hash=registry_snapshot_hash,
            operational_context=operational_context,
        )


__all__ = [
    "CALIBRATION_POLICY_VERSION",
    "CalibrationSelection",
    "HistoricalCalibrationPolicy",
    "apply_historical_calibration",
    "select_historical_calibration",
]
