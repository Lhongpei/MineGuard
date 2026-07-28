"""Audited orchestration for historical evidence and conservative fusion.

The physical solver remains unchanged and authoritative.  This module builds
an independent historical assessment from immutable, explicitly reviewed
runs, checks approved legitimate-scenario definitions, and attaches a shadow
fusion result to a portfolio item.  It never rewrites the physical analysis
or its original review priority.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ValidationError

from .casework import (
    LocalRepository,
    algorithm_feature_compatibility_key,
    build_algorithm_feature_compatibility,
    match_legitimate_scenarios,
    sha256_json,
)
from .current_temporal import (
    CURRENT_TEMPORAL_METHOD_VERSION,
    assess_current_temporal,
)
from .fusion import ConservativeFusionInput, fuse_evidence
from .historical import (
    HISTORICAL_METHOD_VERSION,
    HistoricalLabel,
    HistoricalReferenceSample,
    OperationalContext,
    assess_historical_baseline,
    extract_historical_features,
)
from .models import ProductionAnalysisRequest, ProductionAnalysisResult


HISTORICAL_PIPELINE_VERSION = "historical-evidence-pipeline-v1"
_REFERENCE_LABELS = frozenset(
    {
        HistoricalLabel.VERIFIED_NORMAL.value,
    }
)
_REFERENCE_CANDIDATE_LIMIT = 2_000
_SCENARIO_EVALUATION_LIMIT = 1_000


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    return value


def _identity_from_context(
    context: dict[str, Any] | None,
    mine_id: str,
) -> dict[str, Any]:
    if not isinstance(context, dict):
        return {
            "trusted_mode": "direct",
            "profile_id": None,
            "profile_version": None,
            "registry_snapshot_hash": None,
        }
    identity = context
    reports = context.get("mine_reports")
    if isinstance(reports, list):
        identity = next(
            (
                report
                for report in reports
                if isinstance(report, dict)
                and str(report.get("mine_id") or "") == mine_id
            ),
            context,
        )
    kind = str(context.get("kind") or "")
    return {
        "trusted_mode": (
            "governed" if kind.startswith("governed_") else "direct"
        ),
        "profile_id": identity.get("profile_id"),
        "profile_version": identity.get("profile_version"),
        "registry_snapshot_hash": identity.get(
            "registry_snapshot_hash"
        ),
    }


def operational_context_from_batch(
    context: dict[str, Any] | None,
    mine_id: str,
) -> OperationalContext:
    """Read the canonical operational context for one mine.

    Legacy governed batches without a context map to an explicit empty
    context.  That empty cohort never mixes with a non-empty current cohort.
    """

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


def _compatibility_key(
    request: ProductionAnalysisRequest,
    *,
    engine_version: str,
    batch_context: dict[str, Any] | None,
) -> str:
    identity = _identity_from_context(batch_context, request.mine_id)
    compatibility = build_algorithm_feature_compatibility(
        request,
        engine_version=engine_version,
        **identity,
    )
    return algorithm_feature_compatibility_key(compatibility)


def _quality_score(result: ProductionAnalysisResult) -> float:
    return min(1.0, max(0.0, float(result.data_quality.score) / 100.0))


def _context_is_informative(context: OperationalContext) -> bool:
    # These four axes define the minimum exchangeability cohort.  Events and
    # tags refine it, but cannot substitute for an unknown production regime,
    # shift, season or maintenance state.
    return bool(
        context.regime_code
        and context.shift_code
        and context.season_code
        and context.maintenance is not None
    )


def _reference_samples(
    repository: LocalRepository,
    *,
    mine_id: str,
) -> tuple[
    list[HistoricalReferenceSample],
    dict[str, int | bool],
    dict[str, dict[str, Any]],
]:
    labels = repository.list_run_reference_labels(
        labels=_REFERENCE_LABELS,
        mine_ids={mine_id},
        include_ineligible=True,
        limit=_REFERENCE_CANDIDATE_LIMIT + 1,
    )
    candidate_limit_exceeded = len(labels) > _REFERENCE_CANDIDATE_LIMIT
    labels = labels[:_REFERENCE_CANDIDATE_LIMIT]
    samples: list[HistoricalReferenceSample] = []
    manifests: dict[str, dict[str, Any]] = {}
    diagnostics = {
        "labelled_candidate_count": len(labels),
        "candidate_limit": _REFERENCE_CANDIDATE_LIMIT,
        "candidate_limit_exceeded": candidate_limit_exceeded,
        "materialized_sample_count": 0,
        "invalid_snapshot_count": 0,
        "unsupported_snapshot_count": 0,
        "invalid_scenario_reference_count": 0,
    }
    for label in labels:
        try:
            run = repository.get_run(str(label["run_id"]))
            request = ProductionAnalysisRequest.model_validate(run["input"])
            result = ProductionAnalysisResult.model_validate(run["result"])
            features = extract_historical_features(request, result)
            compatibility_key = _compatibility_key(
                request,
                engine_version=str(run["engine_version"]),
                batch_context=run.get("batch_context"),
            )
            context = operational_context_from_batch(
                run.get("batch_context"),
                mine_id,
            )
        except ValidationError:
            diagnostics["unsupported_snapshot_count"] += 1
            continue
        except (KeyError, TypeError, ValueError):
            diagnostics["invalid_snapshot_count"] += 1
            continue
        available_at = max(
            datetime.fromisoformat(
                str(run["created_at"]).replace("Z", "+00:00")
            ).astimezone(UTC),
            datetime.fromisoformat(
                str(label["created_at"]).replace("Z", "+00:00")
            ).astimezone(UTC),
        )
        context_document = context.model_dump(mode="json")
        feature_document = dict(sorted(features.items()))
        sample_id = str(run["run_id"])
        manifests[sample_id] = {
            "sample_id": sample_id,
            "batch_id": str(run["batch_id"]),
            "mine_id": mine_id,
            "window_start": request.window_start.isoformat(),
            "window_end": request.window_end.isoformat(),
            "available_at": available_at.isoformat(),
            "engine_version": str(run["engine_version"]),
            "compatibility_key": compatibility_key,
            "quality_score": _quality_score(result),
            "snapshot_hashes": {
                "run_input_sha256": str(run["input_sha256"]),
                "run_result_sha256": str(run["result_sha256"]),
                "batch_request_sha256": str(
                    run.get("batch_request_sha256") or ""
                ),
                "batch_response_sha256": str(
                    run.get("batch_response_sha256") or ""
                ),
                "batch_context_sha256": str(
                    run.get("batch_context_sha256") or ""
                ),
                "operational_context_sha256": sha256_json(
                    context_document
                ),
                "historical_features_sha256": sha256_json(
                    feature_document
                ),
            },
            "reference_label": {
                "sequence": int(label["sequence"]),
                "label": str(label["label"]),
                "event_hash": str(label["event_hash"]),
                "created_at": str(label["created_at"]),
                "actor": str(label["actor"]),
                "note_sha256": sha256_json(str(label["note"])),
            },
            "integrity_origin": str(
                run.get("batch_integrity_origin") or ""
            ),
        }
        samples.append(
            HistoricalReferenceSample(
                sample_id=sample_id,
                mine_id=mine_id,
                window_start=request.window_start,
                window_end=request.window_end,
                available_at=available_at,
                compatibility_key=compatibility_key,
                hash_valid=bool(
                    label.get("reference_eligible")
                    and run.get("input_hash_valid")
                    and run.get("result_hash_valid")
                    and run.get("batch_integrity_valid")
                    and run.get("batch_reference_integrity_eligible")
                ),
                quality_score=_quality_score(result),
                label=HistoricalLabel(str(label["label"])),
                context=context,
                features=features,
            )
        )
    diagnostics["materialized_sample_count"] = len(samples)
    return samples, diagnostics, manifests


def _physical_diagnostics_complete(
    result: ProductionAnalysisResult,
    original_priority: str,
) -> bool:
    if result.status == "consistent":
        return True
    if result.status != "inconsistent":
        return False
    if original_priority != "P1":
        return bool(result.solver_status)
    return bool(
        result.evidence_grade == "A"
        and result.priority_scenario_count > 0
        and result.all_priority_scenarios_support_positive_gap
        and not result.scenario_conclusion_divergent
        and result.scenario_union_production_range is not None
    )


def _historical_status(assessment: dict[str, Any]) -> str:
    if assessment.get("status") != "ready":
        return "insufficient_history"
    return (
        "historically_rare"
        if assessment.get("historically_rare") is True
        else "within_baseline"
    )


def _unevaluated_evidence(
    *,
    reason: str,
    context: OperationalContext,
) -> dict[str, Any]:
    return {
        "pipeline_version": HISTORICAL_PIPELINE_VERSION,
        "assessment": {
            "status": "not_evaluated",
            "reason": reason,
            "historically_rare": None,
            "rarity_score": None,
            "eligible_sample_count": 0,
            "selected_sample_count": 0,
            "physical_status_unchanged": True,
            "explanation": (
                "历史证据未形成结论；这不表示正常，也不改变物理模型状态。"
            ),
        },
        "operational_context": context.model_dump(mode="json"),
        "reference_build": {
            "labelled_candidate_count": 0,
            "candidate_limit": _REFERENCE_CANDIDATE_LIMIT,
            "candidate_limit_exceeded": False,
            "materialized_sample_count": 0,
            "invalid_snapshot_count": 0,
            "unsupported_snapshot_count": 0,
            "invalid_scenario_reference_count": 0,
        },
        "reference_manifest": {
            "as_of": None,
            "method_version": HISTORICAL_METHOD_VERSION,
            "selected_sample_count": 0,
            "selected_samples": [],
            "sha256": sha256_json([]),
        },
    }


def _unevaluated_temporal(
    *,
    reason: str,
) -> dict[str, Any]:
    return {
        "method_version": CURRENT_TEMPORAL_METHOD_VERSION,
        "status": "insufficient_history",
        "reason_code": reason,
        "physical_status_unchanged": True,
        "selected_feature_ids": [],
        "selected_feature_hashes": [],
        "signals": [],
        "explanation": (
            "当前窗口未形成独立时序结论；这不表示正常，也不改变物理"
            "交叉验证结论。"
        ),
    }


def enrich_portfolio_historical_evidence(
    repository: LocalRepository,
    request_obj: Any,
    result_obj: Any,
    *,
    engine_version: str,
    context_obj: dict[str, Any] | None,
    temporal_status_by_mine: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Attach historical/scenario/fusion evidence to received portfolio items.

    The returned dictionary is suitable for immutable batch persistence.  The
    nested ``analysis`` object and ``review_priority`` are copied verbatim.
    """

    request = _json_value(request_obj)
    result = _json_value(result_obj)
    if not isinstance(request, dict) or not isinstance(result, dict):
        raise TypeError("portfolio request and result must be objects")
    enriched = {
        **result,
        "items": [
            dict(item) if isinstance(item, dict) else item
            for item in result.get("items", [])
        ],
    }
    requests_by_mine = {
        str(item.get("mine_id")): item
        for item in request.get("analyses", [])
        if isinstance(item, dict)
    }
    for item in enriched["items"]:
        if not isinstance(item, dict):
            continue
        mine_id = str(item.get("mine_id") or "")
        raw_request = requests_by_mine.get(mine_id)
        raw_result = item.get("analysis")
        if raw_request is None or not isinstance(raw_result, dict):
            continue
        operational_context = operational_context_from_batch(
            context_obj,
            mine_id,
        )
        identity = _identity_from_context(context_obj, mine_id)
        temporal_evidence = _unevaluated_temporal(
            reason="trusted_governed_input_required",
        )
        if identity["trusted_mode"] != "governed":
            historical_evidence = _unevaluated_evidence(
                reason="trusted_governed_input_required",
                context=operational_context,
            )
            assessment_payload = historical_evidence["assessment"]
            scenario_matches = {
                "mine_id": mine_id,
                "matched_scenarios": [],
                "evaluations": [],
                "status": "not_evaluated",
                "reason": "trusted_governed_input_required",
            }
        elif not _context_is_informative(operational_context):
            temporal_evidence = _unevaluated_temporal(
                reason="operational_context_incomplete",
            )
            historical_evidence = _unevaluated_evidence(
                reason="operational_context_required",
                context=operational_context,
            )
            assessment_payload = historical_evidence["assessment"]
            scenario_matches = {
                "mine_id": mine_id,
                "matched_scenarios": [],
                "evaluations": [],
                "status": "not_evaluated",
                "reason": "operational_context_required",
            }
        else:
            try:
                analysis_request = ProductionAnalysisRequest.model_validate(
                    raw_request
                )
                analysis_result = ProductionAnalysisResult.model_validate(
                    raw_result
                )
                current_features = extract_historical_features(
                    analysis_request,
                    analysis_result,
                )
                compatibility_key = _compatibility_key(
                    analysis_request,
                    engine_version=engine_version,
                    batch_context=context_obj,
                )
                temporal_evidence = assess_current_temporal(
                    repository,
                    analysis_request,
                    analysis_result,
                    compatibility_key,
                    operational_context,
                ).model_dump(mode="json")
                decision_time = datetime.now(UTC)
                with repository.read_snapshot():
                    (
                        samples,
                        build_diagnostics,
                        sample_manifests,
                    ) = _reference_samples(
                        repository,
                        mine_id=mine_id,
                    )
                    scenario_definitions = (
                        repository.list_legitimate_scenarios(
                            mine_id=mine_id,
                            limit=_SCENARIO_EVALUATION_LIMIT + 1,
                        )
                    )
                if build_diagnostics["candidate_limit_exceeded"]:
                    historical_evidence = _unevaluated_evidence(
                        reason="history_candidate_limit_exceeded",
                        context=operational_context,
                    )
                    historical_evidence["reference_build"] = (
                        build_diagnostics
                    )
                    assessment_payload = historical_evidence["assessment"]
                else:
                    assessment = assess_historical_baseline(
                        current_mine_id=mine_id,
                        current_window_start=analysis_request.window_start,
                        current_context=operational_context,
                        current_features=current_features,
                        current_compatibility_key=compatibility_key,
                        samples=samples,
                        current_decision_time=decision_time,
                    )
                    assessment_payload = assessment.model_dump(mode="json")
                    historical_evidence = {
                        "pipeline_version": HISTORICAL_PIPELINE_VERSION,
                        "assessment": assessment_payload,
                        "operational_context": (
                            operational_context.model_dump(mode="json")
                        ),
                        "reference_build": build_diagnostics,
                    }
                selected_manifests = [
                    sample_manifests[sample_id]
                    for sample_id in assessment_payload.get(
                        "selected_sample_ids",
                        [],
                    )
                    if sample_id in sample_manifests
                ]
                manifest_document = {
                    "as_of": decision_time.isoformat(),
                    "method_version": HISTORICAL_METHOD_VERSION,
                    "selected_samples": selected_manifests,
                }
                historical_evidence["reference_manifest"] = {
                    **manifest_document,
                    "selected_sample_count": len(selected_manifests),
                    "sha256": sha256_json(manifest_document),
                }
                if (
                    len(scenario_definitions)
                    > _SCENARIO_EVALUATION_LIMIT
                ):
                    scenario_matches = {
                        "mine_id": mine_id,
                        "matched_scenarios": [],
                        "evaluations": [],
                        "status": "not_evaluated",
                        "reason": "scenario_evaluation_limit_exceeded",
                        "evaluation_limit": _SCENARIO_EVALUATION_LIMIT,
                    }
                else:
                    scenario_matches = match_legitimate_scenarios(
                        scenario_definitions,
                        mine_id=mine_id,
                        operational_context=(
                            operational_context.model_dump(mode="json")
                        ),
                        features=current_features,
                    )
                    scenario_matches["status"] = "evaluated"
            except (ValidationError, TypeError, ValueError):
                temporal_evidence = _unevaluated_temporal(
                    reason="physical_result_not_scorable",
                )
                historical_evidence = _unevaluated_evidence(
                    reason="physical_result_not_scorable",
                    context=operational_context,
                )
                assessment_payload = historical_evidence["assessment"]
                scenario_matches = {
                    "mine_id": mine_id,
                    "matched_scenarios": [],
                    "evaluations": [],
                    "status": "not_evaluated",
                    "reason": "physical_result_not_scorable",
                }

        driving_features = set(
            assessment_payload.get("driving_feature_names") or []
        )
        matched_ids: list[str] = []
        for scenario in scenario_matches.get(
            "matched_scenarios",
            [],
        ):
            if (
                not isinstance(scenario, dict)
                or not scenario.get("scenario_id")
                or not scenario.get("version")
            ):
                continue
            bounded_features = set(
                (scenario.get("feature_bounds") or {}).keys()
            )
            covers_historical_signal = bool(
                driving_features
                and driving_features <= bounded_features
            )
            scenario["covers_historical_driving_features"] = (
                covers_historical_signal
            )
            if covers_historical_signal:
                matched_ids.append(
                    f"{scenario['scenario_id']}@{scenario['version']}"
                )
        scenario_matches["historical_explanation_scenarios"] = (
            matched_ids
        )
        scenario_manifest = [
            {
                "scenario_reference": (
                    f"{scenario['scenario_id']}@{scenario['version']}"
                ),
                "definition_sha256": str(
                    scenario.get("definition_sha256") or ""
                ),
            }
            for scenario in scenario_matches.get("matched_scenarios", [])
            if isinstance(scenario, dict)
            and scenario.get("covers_historical_driving_features") is True
        ]
        historical_evidence["scenario_reference_manifest"] = {
            "items": scenario_manifest,
            "sha256": sha256_json(scenario_manifest),
        }
        analysis_result = ProductionAnalysisResult.model_validate(raw_result)
        original_priority = str(item.get("review_priority") or "DATA")
        temporal_status = (temporal_status_by_mine or {}).get(
            mine_id,
            str(temporal_evidence.get("status") or "insufficient_history"),
        )
        if temporal_status not in {
            "insufficient_history",
            "normal",
            "anomalous",
        }:
            temporal_status = "insufficient_history"
        fusion = fuse_evidence(
            ConservativeFusionInput(
                physical_status=analysis_result.status,
                original_review_priority=original_priority,
                evidence_grade=analysis_result.evidence_grade or "D",
                physical_diagnostics_complete=(
                    _physical_diagnostics_complete(
                        analysis_result,
                        original_priority,
                    )
                ),
                data_quality_status=analysis_result.data_quality.status,
                historical_status=_historical_status(assessment_payload),
                temporal_status=temporal_status,
                legitimate_scenario_matches=matched_ids,
            )
        )
        item["historical_evidence"] = historical_evidence
        item["temporal_evidence"] = temporal_evidence
        item["legitimate_scenario_matches"] = scenario_matches
        item["evidence_fusion"] = fusion.model_dump(mode="json")
    return enriched


__all__ = [
    "HISTORICAL_PIPELINE_VERSION",
    "enrich_portfolio_historical_evidence",
    "operational_context_from_batch",
]
