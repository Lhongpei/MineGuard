"""Conservative fusion of physical, historical and temporal evidence.

The physical analysis remains the authoritative technical result.  This
module only produces a shadow review priority and an explicit description of
whether independent historical or temporal signals corroborate it.

In particular:

* historical evidence can never create a P1 priority;
* a legitimate scenario can explain historical rarity, but cannot erase a
  physical conflict;
* blocked data, an inconclusive physical result or a solver error always
  remains in the DATA queue.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Literal

from pydantic import ConfigDict, Field, field_validator

from .models import StrictModel


PhysicalStatus = Literal[
    "consistent",
    "inconsistent",
    "inconclusive",
    "solver_error",
]
ReviewPriority = Literal["P1", "P2", "DATA", "NONE"]
EvidenceGrade = Literal["A", "B", "C", "D"]
DataQualityStatus = Literal["sufficient", "degraded", "blocked"]
HistoricalStatus = Literal[
    "insufficient_history",
    "within_baseline",
    "historically_rare",
]
TemporalStatus = Literal[
    "insufficient_history",
    "normal",
    "anomalous",
]
Agreement = Literal[
    "corroborated",
    "physical_only",
    "historical_only",
    "no_signal",
    "insufficient",
]

MAX_LEGITIMATE_SCENARIO_MATCHES = 100
MAX_LEGITIMATE_SCENARIO_LENGTH = 256


class FusionModel(StrictModel):
    """Strict public contract for evidence fusion."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        strict=True,
    )


class ConservativeFusionInput(FusionModel):
    """Signals needed by the conservative, side-effect-free fusion rule."""

    physical_status: PhysicalStatus
    original_review_priority: ReviewPriority
    evidence_grade: EvidenceGrade
    physical_diagnostics_complete: bool
    data_quality_status: DataQualityStatus
    historical_status: HistoricalStatus
    temporal_status: TemporalStatus
    legitimate_scenario_matches: Annotated[
        list[
            Annotated[
                str,
                Field(
                    min_length=1,
                    max_length=MAX_LEGITIMATE_SCENARIO_LENGTH,
                ),
            ]
        ],
        Field(max_length=MAX_LEGITIMATE_SCENARIO_MATCHES),
    ] = Field(default_factory=list)

    @field_validator("legitimate_scenario_matches")
    @classmethod
    def validate_legitimate_scenario_matches(
        cls,
        value: list[str],
    ) -> list[str]:
        """Reject ambiguous duplicates and canonicalise input ordering."""

        if len(value) != len(set(value)):
            raise ValueError("legitimate_scenario_matches values must be unique")
        return sorted(value)


class ConservativeFusionResult(FusionModel):
    """Auditable output that cannot mutate the physical conclusion."""

    physical_status: PhysicalStatus
    physical_status_unchanged: Literal[True] = True
    original_review_priority: ReviewPriority
    agreement: Agreement
    shadow_priority: ReviewPriority
    historical_supports_physical: bool
    reasons: list[str]
    safeguards: list[str]


def _agreement(
    request: ConservativeFusionInput,
    *,
    effective_historical_signal: bool,
    temporal_signal: bool,
) -> Agreement:
    if (
        request.physical_status in {"inconclusive", "solver_error"}
        or request.data_quality_status == "blocked"
    ):
        return "insufficient"

    if request.physical_status == "inconsistent":
        if effective_historical_signal or temporal_signal:
            return "corroborated"
        return "physical_only"

    if effective_historical_signal or temporal_signal:
        # The public vocabulary uses historical_only for all non-physical
        # secondary signals, including a temporal-only anomaly.
        return "historical_only"

    secondary_evidence_is_incomplete = (
        request.historical_status == "insufficient_history"
        or request.temporal_status == "insufficient_history"
    )
    if secondary_evidence_is_incomplete:
        return "insufficient"
    return "no_signal"


def _shadow_priority(
    request: ConservativeFusionInput,
    *,
    effective_historical_signal: bool,
    temporal_signal: bool,
) -> ReviewPriority:
    if (
        request.physical_status in {"inconclusive", "solver_error"}
        or request.data_quality_status == "blocked"
    ):
        return "DATA"

    if request.original_review_priority == "DATA":
        return "DATA"

    if request.physical_status == "inconsistent":
        if request.original_review_priority == "P1":
            # Fusion may annotate inconsistent diagnostics, but it is never
            # authorised to lower a priority assigned by the physical layer.
            return "P1"
        # A physical conflict never falls to NONE.  Secondary evidence cannot
        # promote this floor to P1.
        return "P2"

    if (
        request.original_review_priority == "P2"
        or effective_historical_signal
        or temporal_signal
    ):
        return "P2"
    return "NONE"


def _reason_codes(
    request: ConservativeFusionInput,
    *,
    agreement: Agreement,
    shadow_priority: ReviewPriority,
    effective_historical_signal: bool,
    temporal_signal: bool,
    has_legitimate_scenario: bool,
) -> list[str]:
    reasons: list[str] = [
        f"physical_status:{request.physical_status}",
        f"evidence_grade:{request.evidence_grade}",
    ]

    if request.data_quality_status == "blocked":
        reasons.append("data_quality_blocked")
    elif request.data_quality_status == "degraded":
        reasons.append("data_quality_degraded")

    if not request.physical_diagnostics_complete:
        reasons.append("physical_diagnostics_incomplete")

    if request.historical_status == "insufficient_history":
        reasons.append("historical_evidence_insufficient")
    elif request.historical_status == "within_baseline":
        reasons.append("historical_observation_within_baseline")
    elif has_legitimate_scenario:
        reasons.append("historical_rarity_explained_by_legitimate_scenario")
    else:
        reasons.append("historical_observation_rare")

    if request.temporal_status == "insufficient_history":
        reasons.append("temporal_evidence_insufficient")
    elif request.temporal_status == "normal":
        reasons.append("temporal_observation_normal")
    else:
        reasons.append("temporal_observation_anomalous")

    if agreement == "corroborated":
        reasons.append("independent_secondary_signal_corroborates_conflict")
    elif agreement == "physical_only":
        reasons.append("physical_conflict_not_independently_corroborated")
    elif agreement == "historical_only":
        reasons.append("secondary_signal_requires_shadow_review")
    elif agreement == "no_signal":
        reasons.append("no_unexplained_review_signal")
    else:
        reasons.append("evidence_insufficient_for_agreement_assessment")

    if request.original_review_priority == "P1" and shadow_priority == "P1":
        reasons.append("original_physical_p1_preserved_without_rewrite")
    elif request.original_review_priority == "DATA" and shadow_priority == "DATA":
        reasons.append("original_data_priority_preserved")
    elif (
        request.physical_status == "inconsistent"
        and request.original_review_priority == "NONE"
    ):
        reasons.append("physical_conflict_applies_p2_priority_floor")

    if (
        request.physical_status == "inconsistent"
        and (effective_historical_signal or temporal_signal)
        and shadow_priority == "P2"
    ):
        reasons.append("secondary_signal_does_not_promote_p2_to_p1")

    return reasons


def _safeguard_codes(
    request: ConservativeFusionInput,
    *,
    has_legitimate_scenario: bool,
) -> list[str]:
    safeguards = [
        "physical_status_preserved",
        "historical_or_temporal_evidence_cannot_create_p1",
        "legitimate_scenario_cannot_override_physical_conflict",
    ]
    if request.physical_status in {"inconclusive", "solver_error"}:
        safeguards.append("inconclusive_or_solver_error_forces_data_priority")
    if request.data_quality_status == "blocked":
        safeguards.append("blocked_data_forces_data_priority")
    if not request.physical_diagnostics_complete:
        safeguards.append("incomplete_diagnostics_cannot_support_p1")
    if request.historical_status == "insufficient_history":
        safeguards.append("insufficient_history_is_not_treated_as_normal")
    if has_legitimate_scenario:
        safeguards.append("legitimate_scenario_only_explains_historical_signal")
    if request.physical_status == "inconsistent":
        safeguards.append("physical_conflict_has_p2_priority_floor")
    return safeguards


def fuse_evidence(
    request: ConservativeFusionInput | Mapping[str, Any],
    /,
) -> ConservativeFusionResult:
    """Fuse independent signals without altering the physical conclusion.

    A plain mapping is validated using the same strict contract as a model
    instance.  The function is pure and deterministic for equivalent inputs.
    """

    validated = (
        request
        if isinstance(request, ConservativeFusionInput)
        else ConservativeFusionInput.model_validate(request)
    )
    has_legitimate_scenario = bool(validated.legitimate_scenario_matches)
    effective_historical_signal = (
        validated.historical_status == "historically_rare"
        and not has_legitimate_scenario
    )
    temporal_signal = validated.temporal_status == "anomalous"
    agreement = _agreement(
        validated,
        effective_historical_signal=effective_historical_signal,
        temporal_signal=temporal_signal,
    )
    shadow_priority = _shadow_priority(
        validated,
        effective_historical_signal=effective_historical_signal,
        temporal_signal=temporal_signal,
    )
    historical_supports_physical = (
        validated.physical_status == "inconsistent"
        and validated.data_quality_status != "blocked"
        and effective_historical_signal
    )

    return ConservativeFusionResult(
        physical_status=validated.physical_status,
        original_review_priority=validated.original_review_priority,
        agreement=agreement,
        shadow_priority=shadow_priority,
        historical_supports_physical=historical_supports_physical,
        reasons=_reason_codes(
            validated,
            agreement=agreement,
            shadow_priority=shadow_priority,
            effective_historical_signal=effective_historical_signal,
            temporal_signal=temporal_signal,
            has_legitimate_scenario=has_legitimate_scenario,
        ),
        safeguards=_safeguard_codes(
            validated,
            has_legitimate_scenario=has_legitimate_scenario,
        ),
    )


__all__ = [
    "Agreement",
    "ConservativeFusionInput",
    "ConservativeFusionResult",
    "DataQualityStatus",
    "EvidenceGrade",
    "HistoricalStatus",
    "PhysicalStatus",
    "ReviewPriority",
    "TemporalStatus",
    "fuse_evidence",
]
