"""Leakage-safe electricity and explosives production verification.

The module implements the production-verification core described by the
Qinyuan decision-assistant plan while deliberately stopping short of a legal
or regulatory determination.  It:

* builds mine- and operating-condition-specific robust historical baselines;
* admits only sufficiently reliable, manually verified normal reference data;
* prevents time leakage by freezing the reference pool at the current
  window's start;
* prefers partition-metered production electricity and otherwise subtracts
  every required interference category explicitly;
* fails closed when an interference load cannot be identified;
* applies the plan's 0.8/0.9/1.1/1.3 electricity-ratio bands;
* robustly scores explosives intensity with a median/MAD baseline;
* supplements fixed physical bands with finite-sample empirical tail ranks
  learned only from governed, verified-normal historical windows; and
* raises the technical-clue level when both independent indicators point in
  the same direction.

All public inputs and outputs are strict Pydantic models.  The result is an
auditable technical lead for human review, never proof of concealment,
over-reporting, or another violation.
"""

from __future__ import annotations

from collections import Counter
from enum import IntEnum, StrEnum
import math
from typing import Annotated, Literal, Sequence

import numpy as np
from pydantic import (
    AwareDatetime,
    ConfigDict,
    Field,
    model_validator,
)

from .models import StrictModel


VERIFICATION_METHOD_VERSION = "conditional-energy-explosives-empirical-v2"
DEFAULT_PARAMETER_VERSION = "qinyuan-production-verification-2026.07-v2"
MAD_NORMAL_CONSISTENCY_FACTOR = 1.4826
MAX_CONSUMPTION_VALUE = 1e15
MAX_REFERENCE_SAMPLES = 10_000


class VerificationModel(StrictModel):
    """Strict public contract used by this module."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=True,
        strict=True,
    )


class InterferenceCategory(StrEnum):
    """Electric loads that the plan requires removing from mine consumption."""

    VENTILATION = "ventilation"
    DRAINAGE = "drainage"
    COMPRESSED_AIR = "compressed_air"
    HOISTING = "hoisting"
    COAL_PREPARATION = "coal_preparation"


REQUIRED_INTERFERENCE_CATEGORIES = frozenset(InterferenceCategory)


class ManualReviewLabel(StrEnum):
    """Governed result of a completed human review."""

    VERIFIED_NORMAL = "verified_normal"
    LEGITIMATE_EXCEPTION = "legitimate_exception"
    DATA_ERROR = "data_error"
    TECHNICAL_ANOMALY = "technical_anomaly"
    UNRESOLVED = "unresolved"


class EnergyDerivationBasis(StrEnum):
    PARTITIONED_PRODUCTION_METER = "partitioned_production_meter"
    TOTAL_LESS_EXPLICIT_INTERFERENCE = (
        "total_less_explicit_interference"
    )


class EvidenceDirection(StrEnum):
    NONE = "none"
    LOW = "low"
    HIGH = "high"


class EnergyRatioBand(StrEnum):
    EXTREME_LOW = "below_0.8"
    ATTENTION_LOW = "0.8_to_below_0.9"
    NORMAL = "0.9_to_1.1"
    ATTENTION_HIGH = "above_1.1_to_1.3"
    EXTREME_HIGH = "above_1.3"


class RobustDeviationBand(StrEnum):
    NORMAL = "normal"
    ATTENTION = "attention"
    EXTREME = "extreme"


class HistoricalRarityBand(StrEnum):
    """Rarity inside the governed verified-normal reference population."""

    TYPICAL = "typical"
    UNCOMMON = "uncommon"
    RARE = "rare"


class TechnicalClueLevel(IntEnum):
    """Ordinal technical-review priority, not a legal risk classification."""

    NORMAL = 0
    ATTENTION = 1
    ELEVATED = 2
    HIGH = 3


class VerificationStatus(StrEnum):
    READY = "ready"
    INSUFFICIENT_HISTORY = "insufficient_history"
    BLOCKED = "blocked"


class OperatingCondition(VerificationModel):
    """Exact conditioning fields for like-for-like historical comparison."""

    regime_code: Annotated[str, Field(min_length=1, max_length=64)]
    mining_method: Annotated[str, Field(min_length=1, max_length=64)]
    seam_code: Annotated[str, Field(min_length=1, max_length=64)]
    face_code: Annotated[str, Field(min_length=1, max_length=64)]
    shift_code: Annotated[str, Field(min_length=1, max_length=64)]
    geology_zone: Annotated[str, Field(min_length=1, max_length=64)]
    maintenance: bool = False


class InterferenceReading(VerificationModel):
    """One explicitly identified non-production electricity load."""

    category: InterferenceCategory
    identifiable: bool
    electricity_kwh: Annotated[
        float | None,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = None
    source_id: Annotated[str | None, Field(min_length=1, max_length=128)] = (
        None
    )

    @model_validator(mode="after")
    def validate_identification(self) -> "InterferenceReading":
        if self.identifiable:
            if self.electricity_kwh is None or self.source_id is None:
                raise ValueError(
                    "identifiable interference requires electricity_kwh "
                    "and source_id"
                )
        elif self.electricity_kwh is not None or self.source_id is not None:
            raise ValueError(
                "unidentifiable interference cannot carry a value or source"
            )
        return self


class ElectricityReading(VerificationModel):
    """Electricity inputs for a single production window.

    ``production_zone_kwh`` is a net, partition-metered production load and
    always takes precedence.  ``total_kwh`` is used only as a fallback and
    requires a complete, identifiable set of interference readings.
    """

    source_id: Annotated[str, Field(min_length=1, max_length=128)]
    production_zone_kwh: Annotated[
        float | None,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = None
    total_kwh: Annotated[
        float | None,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = None
    interference: Annotated[
        list[InterferenceReading],
        Field(max_length=len(REQUIRED_INTERFERENCE_CATEGORIES)),
    ] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_reading(self) -> "ElectricityReading":
        if self.production_zone_kwh is None and self.total_kwh is None:
            raise ValueError(
                "production_zone_kwh or total_kwh is required"
            )
        categories = [item.category for item in self.interference]
        if len(categories) != len(set(categories)):
            raise ValueError("interference categories must be unique")
        return self


class ExplosivesReading(VerificationModel):
    explosives_used_kg: Annotated[
        float,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    source_id: Annotated[str, Field(min_length=1, max_length=128)]


class HistoricalVerificationSample(VerificationModel):
    """One immutable reference window with a governed human label."""

    sample_id: Annotated[str, Field(min_length=1, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    window_start: AwareDatetime
    window_end: AwareDatetime
    available_at: AwareDatetime
    operating_condition: OperatingCondition
    reported_production_t: Annotated[
        float,
        Field(gt=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    electricity: ElectricityReading
    explosives: ExplosivesReading
    quality_score: Annotated[float, Field(ge=0.0, le=1.0)]
    source_hash_valid: bool
    compatibility_key: Annotated[str, Field(min_length=1, max_length=128)]
    review_label: ManualReviewLabel
    human_reviewed: bool
    reviewed_by: Annotated[
        str | None,
        Field(min_length=1, max_length=128),
    ] = None
    reviewed_at: AwareDatetime | None = None
    review_confidence: Annotated[
        float | None,
        Field(ge=0.0, le=1.0),
    ] = None

    @model_validator(mode="after")
    def validate_window_and_review(self) -> "HistoricalVerificationSample":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be later than window_start")
        if self.available_at < self.window_end:
            raise ValueError("available_at cannot precede window_end")
        review_fields = (
            self.reviewed_by,
            self.reviewed_at,
            self.review_confidence,
        )
        if self.human_reviewed:
            if any(value is None for value in review_fields):
                raise ValueError(
                    "human-reviewed samples require reviewer, reviewed_at, "
                    "and review_confidence"
                )
            assert self.reviewed_at is not None
            if self.reviewed_at < self.available_at:
                raise ValueError(
                    "reviewed_at cannot precede data availability"
                )
        elif any(value is not None for value in review_fields):
            raise ValueError(
                "unreviewed samples cannot carry review metadata"
            )
        return self


class VerificationParameters(VerificationModel):
    """Versioned, replayable selection and scoring policy."""

    parameter_version: Annotated[str, Field(min_length=1, max_length=128)] = (
        DEFAULT_PARAMETER_VERSION
    )
    compatibility_key: Annotated[str, Field(min_length=1, max_length=128)] = (
        "production-verification-schema-v1"
    )
    minimum_samples: Annotated[int, Field(ge=3, le=500)] = 20
    maximum_samples: Annotated[int, Field(ge=3, le=500)] = 500
    minimum_quality_score: Annotated[
        float,
        Field(ge=0.8, le=1.0),
    ] = 0.8
    minimum_review_confidence: Annotated[
        float,
        Field(ge=0.8, le=1.0),
    ] = 0.9
    energy_extreme_low_ratio: Annotated[
        float,
        Field(gt=0.0, lt=1.0),
    ] = 0.8
    energy_attention_low_ratio: Annotated[
        float,
        Field(gt=0.0, lt=1.0),
    ] = 0.9
    energy_attention_high_ratio: Annotated[
        float,
        Field(gt=1.0, le=10.0),
    ] = 1.1
    energy_extreme_high_ratio: Annotated[
        float,
        Field(gt=1.0, le=10.0),
    ] = 1.3
    explosives_attention_robust_z: Annotated[
        float,
        Field(gt=0.0, le=100.0),
    ] = 3.0
    explosives_extreme_robust_z: Annotated[
        float,
        Field(gt=0.0, le=100.0),
    ] = 5.0
    minimum_energy_scale_kwh_per_t: Annotated[
        float,
        Field(gt=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = 0.01
    minimum_explosives_scale_kg_per_t: Annotated[
        float,
        Field(gt=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = 1e-6
    minimum_relative_scale: Annotated[
        float,
        Field(gt=0.0, le=1.0),
    ] = 0.02
    empirical_attention_tail_probability: Annotated[
        float,
        Field(gt=0.0, le=0.25),
    ] = 0.10
    empirical_extreme_tail_probability: Annotated[
        float,
        Field(gt=0.0, le=0.10),
    ] = 0.025

    @model_validator(mode="after")
    def validate_threshold_order(self) -> "VerificationParameters":
        if self.maximum_samples < self.minimum_samples:
            raise ValueError(
                "maximum_samples must be greater than or equal to "
                "minimum_samples"
            )
        if not (
            self.energy_extreme_low_ratio
            < self.energy_attention_low_ratio
            < 1.0
            < self.energy_attention_high_ratio
            < self.energy_extreme_high_ratio
        ):
            raise ValueError(
                "energy ratio thresholds must be strictly ordered around 1"
            )
        if (
            self.explosives_extreme_robust_z
            <= self.explosives_attention_robust_z
        ):
            raise ValueError(
                "explosives extreme threshold must exceed attention threshold"
            )
        if (
            self.empirical_extreme_tail_probability
            >= self.empirical_attention_tail_probability
        ):
            raise ValueError(
                "empirical extreme tail probability must be lower than "
                "the attention tail probability"
            )
        return self


class ProductionVerificationRequest(VerificationModel):
    request_id: Annotated[str, Field(min_length=1, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    window_start: AwareDatetime
    window_end: AwareDatetime
    decision_time: AwareDatetime
    operating_condition: OperatingCondition
    reported_production_t: Annotated[
        float,
        Field(gt=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    production_source_id: Annotated[str, Field(min_length=1, max_length=128)]
    electricity: ElectricityReading
    explosives: ExplosivesReading
    history: Annotated[
        list[HistoricalVerificationSample],
        Field(max_length=MAX_REFERENCE_SAMPLES),
    ] = Field(default_factory=list)
    parameters: VerificationParameters = Field(
        default_factory=VerificationParameters
    )

    @model_validator(mode="after")
    def validate_request(self) -> "ProductionVerificationRequest":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be later than window_start")
        if self.decision_time < self.window_end:
            raise ValueError("decision_time cannot precede window_end")
        sample_ids = [sample.sample_id for sample in self.history]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("historical sample_id values must be unique")
        return self


class EnergyDerivation(VerificationModel):
    status: Literal["ready", "blocked"]
    basis: EnergyDerivationBasis | None = None
    source_id: str
    total_kwh: Annotated[
        float | None,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = None
    excluded_kwh: Annotated[
        float | None,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = None
    net_production_kwh: Annotated[
        float | None,
        Field(gt=0.0, le=MAX_CONSUMPTION_VALUE),
    ] = None
    excluded_by_category: dict[InterferenceCategory, float] = Field(
        default_factory=dict
    )
    blocking_reasons: list[Annotated[str, Field(min_length=1)]] = Field(
        default_factory=list
    )

    @model_validator(mode="after")
    def validate_status_payload(self) -> "EnergyDerivation":
        if self.status == "ready":
            if (
                self.basis is None
                or self.net_production_kwh is None
                or self.blocking_reasons
            ):
                raise ValueError(
                    "ready derivation requires basis and positive net energy"
                )
        elif (
            self.basis is not None
            or self.net_production_kwh is not None
            or not self.blocking_reasons
        ):
            raise ValueError(
                "blocked derivation requires reasons and no derived energy"
            )
        return self


class RobustBaseline(VerificationModel):
    metric: Literal[
        "energy_kwh_per_t",
        "explosives_kg_per_t",
    ]
    median: Annotated[
        float,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    mad: Annotated[
        float,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    robust_scale: Annotated[
        float,
        Field(gt=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    selected_sample_count: Annotated[int, Field(ge=3, le=500)]
    selected_sample_ids: list[str]
    reference_values: Annotated[
        list[float],
        Field(min_length=3, max_length=500),
    ]
    reference_minimum: Annotated[
        float,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    reference_maximum: Annotated[
        float,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    partitioned_meter_sample_count: Annotated[int, Field(ge=0)] = 0
    fallback_meter_sample_count: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def validate_replay_values(self) -> "RobustBaseline":
        if (
            len(self.reference_values) != self.selected_sample_count
            or len(self.selected_sample_ids) != self.selected_sample_count
        ):
            raise ValueError(
                "reference values and sample ids must match sample count"
            )
        if any(
            not math.isfinite(value) or value < 0.0
            for value in self.reference_values
        ):
            raise ValueError(
                "reference values must be finite and non-negative"
            )
        return self


class HistoricalRarityAssessment(VerificationModel):
    """Finite-sample rank evidence; never a probability of misconduct."""

    method: Literal["directional_rank_plus_one"] = (
        "directional_rank_plus_one"
    )
    reference_sample_count: Annotated[int, Field(ge=3, le=500)]
    percentile_rank: Annotated[float, Field(ge=0.0, le=1.0)]
    direction: EvidenceDirection
    directional_tail_probability: Annotated[
        float,
        Field(gt=0.0, le=1.0),
    ]
    band: HistoricalRarityBand
    clue_level: TechnicalClueLevel
    explanation: Annotated[str, Field(min_length=1)]


class ReferenceSelectionAudit(VerificationModel):
    training_cutoff: AwareDatetime
    total_sample_count: Annotated[int, Field(ge=0)]
    common_eligible_sample_count: Annotated[int, Field(ge=0)]
    exclusions: dict[str, Annotated[int, Field(ge=0)]]
    invalid_energy_sample_count: Annotated[int, Field(ge=0)]
    invalid_explosives_sample_count: Annotated[int, Field(ge=0)]
    energy_limit_excluded_count: Annotated[int, Field(ge=0)]
    explosives_limit_excluded_count: Annotated[int, Field(ge=0)]


class VerificationBaselines(VerificationModel):
    status: VerificationStatus
    method_version: Literal[
        "conditional-energy-explosives-empirical-v2"
    ] = VERIFICATION_METHOD_VERSION
    parameter_version: str
    parameters_snapshot: VerificationParameters
    compatibility_key: str
    mine_id: str
    operating_condition: OperatingCondition
    minimum_required_samples: Annotated[int, Field(ge=3, le=500)]
    selection: ReferenceSelectionAudit
    energy: RobustBaseline | None = None
    explosives: RobustBaseline | None = None
    cold_start_reasons: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_baseline_status(self) -> "VerificationBaselines":
        ready = self.energy is not None and self.explosives is not None
        if self.status is VerificationStatus.READY:
            if not ready or self.cold_start_reasons:
                raise ValueError("ready baselines require both metrics")
        elif self.status is VerificationStatus.INSUFFICIENT_HISTORY:
            if ready or not self.cold_start_reasons:
                raise ValueError(
                    "insufficient baselines require a cold-start reason"
                )
        else:
            raise ValueError("baseline status cannot be blocked")
        return self


class EnergyAssessment(VerificationModel):
    derivation: EnergyDerivation
    actual_kwh_per_t: Annotated[
        float,
        Field(gt=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    baseline: RobustBaseline
    verification_ratio: Annotated[float, Field(ge=0.0, le=1e12)]
    historical_rarity: HistoricalRarityAssessment
    band: EnergyRatioBand
    direction: EvidenceDirection
    clue_level: TechnicalClueLevel
    threshold_parameter_version: str
    explanation: Annotated[str, Field(min_length=1)]


class ExplosivesAssessment(VerificationModel):
    actual_kg_per_t: Annotated[
        float,
        Field(ge=0.0, le=MAX_CONSUMPTION_VALUE),
    ]
    baseline: RobustBaseline
    signed_deviation_kg_per_t: float
    signed_relative_deviation: float | None
    robust_z: float
    historical_rarity: HistoricalRarityAssessment
    band: RobustDeviationBand
    direction: EvidenceDirection
    clue_level: TechnicalClueLevel
    threshold_parameter_version: str
    explanation: Annotated[str, Field(min_length=1)]


TECHNICAL_ONLY_DISCLAIMER = (
    "本结果仅为耗电与火工品数据形成的技术核查线索，不构成瞒报、"
    "虚报、违法或责任认定；须核对原始表计、生产日报、火工品台账、"
    "工况变化及现场证据后由有权人员作出结论。"
)


class ProductionVerificationResult(VerificationModel):
    request_id: str
    mine_id: str
    status: VerificationStatus
    method_version: Literal[
        "conditional-energy-explosives-empirical-v2"
    ] = VERIFICATION_METHOD_VERSION
    parameter_version: str
    training_cutoff: AwareDatetime
    baselines: VerificationBaselines
    current_energy_derivation: EnergyDerivation
    energy: EnergyAssessment | None = None
    explosives: ExplosivesAssessment | None = None
    same_direction: bool = False
    jointly_upgraded: bool = False
    overall_clue_level: TechnicalClueLevel
    technical_clues: list[Annotated[str, Field(min_length=1)]] = Field(
        default_factory=list
    )
    blocking_reasons: list[Annotated[str, Field(min_length=1)]] = Field(
        default_factory=list
    )
    legal_determination: Literal[False] = False
    disclaimer: Literal[
        "本结果仅为耗电与火工品数据形成的技术核查线索，不构成瞒报、"
        "虚报、违法或责任认定；须核对原始表计、生产日报、火工品台账、"
        "工况变化及现场证据后由有权人员作出结论。"
    ] = TECHNICAL_ONLY_DISCLAIMER

    @model_validator(mode="after")
    def validate_result_state(self) -> "ProductionVerificationResult":
        if self.status is VerificationStatus.BLOCKED:
            if not self.blocking_reasons or self.energy is not None:
                raise ValueError(
                    "blocked verification requires reasons and no energy "
                    "assessment"
                )
            if self.jointly_upgraded or self.same_direction:
                raise ValueError("blocked verification cannot be joint")
        elif self.blocking_reasons:
            raise ValueError("non-blocked verification cannot have blockers")
        if self.jointly_upgraded and not self.same_direction:
            raise ValueError("joint upgrade requires same-direction evidence")
        return self


def derive_net_production_electricity(
    reading: ElectricityReading,
) -> EnergyDerivation:
    """Derive production electricity, preferring a partition meter.

    The total-meter fallback is intentionally fail-closed.  Every plan-listed
    interference category must be present, identifiable, sourced, and
    subtractable.  A zero or negative remainder is blocked rather than used.
    """

    if reading.production_zone_kwh is not None:
        if reading.production_zone_kwh <= 0.0:
            return EnergyDerivation(
                status="blocked",
                source_id=reading.source_id,
                blocking_reasons=[
                    "分区生产电量必须大于零，当前读数不能用于核验。"
                ],
            )
        return EnergyDerivation(
            status="ready",
            basis=EnergyDerivationBasis.PARTITIONED_PRODUCTION_METER,
            source_id=reading.source_id,
            total_kwh=reading.production_zone_kwh,
            excluded_kwh=0.0,
            net_production_kwh=reading.production_zone_kwh,
        )

    assert reading.total_kwh is not None
    by_category = {item.category: item for item in reading.interference}
    missing = sorted(
        REQUIRED_INTERFERENCE_CATEGORIES - by_category.keys(),
        key=lambda item: item.value,
    )
    unidentified = sorted(
        (
            item.category
            for item in reading.interference
            if not item.identifiable
        ),
        key=lambda item: item.value,
    )
    reasons: list[str] = []
    if missing:
        reasons.append(
            "总表回退缺少干扰项："
            + "、".join(item.value for item in missing)
            + "。"
        )
    if unidentified:
        reasons.append(
            "存在不可识别干扰项："
            + "、".join(item.value for item in unidentified)
            + "。"
        )
    if reasons:
        return EnergyDerivation(
            status="blocked",
            source_id=reading.source_id,
            total_kwh=reading.total_kwh,
            blocking_reasons=reasons,
        )

    excluded = {
        category: float(by_category[category].electricity_kwh)
        for category in sorted(
            REQUIRED_INTERFERENCE_CATEGORIES,
            key=lambda item: item.value,
        )
    }
    excluded_total = math.fsum(excluded.values())
    net = float(reading.total_kwh) - excluded_total
    if net <= 0.0:
        return EnergyDerivation(
            status="blocked",
            source_id=reading.source_id,
            total_kwh=reading.total_kwh,
            excluded_kwh=excluded_total,
            excluded_by_category=excluded,
            blocking_reasons=[
                "干扰项剔除后的生产电量不大于零，需核验表计边界与口径。"
            ],
        )
    return EnergyDerivation(
        status="ready",
        basis=EnergyDerivationBasis.TOTAL_LESS_EXPLICIT_INTERFERENCE,
        source_id=reading.source_id,
        total_kwh=reading.total_kwh,
        excluded_kwh=excluded_total,
        net_production_kwh=net,
        excluded_by_category=excluded,
    )


def _eligible_reference_samples(
    request: ProductionVerificationRequest,
) -> tuple[list[HistoricalVerificationSample], Counter[str]]:
    """Select governed samples using a pre-window, leakage-safe cutoff."""

    eligible: list[HistoricalVerificationSample] = []
    exclusions: Counter[str] = Counter()
    policy = request.parameters
    cutoff = request.window_start

    for sample in request.history:
        if sample.mine_id != request.mine_id:
            exclusions["mine_mismatch"] += 1
        elif sample.operating_condition != request.operating_condition:
            exclusions["operating_condition_mismatch"] += 1
        elif sample.window_end > cutoff:
            exclusions["overlap_or_future_window"] += 1
        elif sample.available_at > cutoff:
            exclusions["unavailable_at_training_cutoff"] += 1
        elif not sample.human_reviewed:
            exclusions["not_human_reviewed"] += 1
        elif sample.reviewed_at is None or sample.reviewed_at > cutoff:
            exclusions["review_unavailable_at_training_cutoff"] += 1
        elif sample.review_label is not ManualReviewLabel.VERIFIED_NORMAL:
            exclusions["ineligible_review_label"] += 1
        elif (
            sample.review_confidence is None
            or sample.review_confidence
            < policy.minimum_review_confidence
        ):
            exclusions["review_confidence_below_floor"] += 1
        elif sample.quality_score < policy.minimum_quality_score:
            exclusions["quality_below_floor"] += 1
        elif not sample.source_hash_valid:
            exclusions["invalid_source_hash"] += 1
        elif sample.compatibility_key != policy.compatibility_key:
            exclusions["compatibility_mismatch"] += 1
        else:
            eligible.append(sample)

    eligible.sort(
        key=lambda item: (item.window_end, item.sample_id),
        reverse=True,
    )
    return eligible, exclusions


def _robust_baseline(
    *,
    metric: Literal["energy_kwh_per_t", "explosives_kg_per_t"],
    values: Sequence[float],
    sample_ids: Sequence[str],
    minimum_absolute_scale: float,
    minimum_relative_scale: float,
    basis_counts: Counter[EnergyDerivationBasis] | None = None,
) -> RobustBaseline:
    array = np.asarray(values, dtype=float)
    center = float(np.median(array))
    mad = float(np.median(np.abs(array - center)))
    robust_scale = max(
        MAD_NORMAL_CONSISTENCY_FACTOR * mad,
        abs(center) * minimum_relative_scale,
        minimum_absolute_scale,
    )
    basis_counts = basis_counts or Counter()
    return RobustBaseline(
        metric=metric,
        median=center,
        mad=mad,
        robust_scale=robust_scale,
        selected_sample_count=len(values),
        selected_sample_ids=list(sample_ids),
        reference_values=[float(value) for value in values],
        reference_minimum=float(np.min(array)),
        reference_maximum=float(np.max(array)),
        partitioned_meter_sample_count=basis_counts[
            EnergyDerivationBasis.PARTITIONED_PRODUCTION_METER
        ],
        fallback_meter_sample_count=basis_counts[
            EnergyDerivationBasis.TOTAL_LESS_EXPLICIT_INTERFERENCE
        ],
    )


def build_verification_baselines(
    request: ProductionVerificationRequest,
) -> VerificationBaselines:
    """Build replayable energy and explosives baselines for a request."""

    eligible, exclusions = _eligible_reference_samples(request)
    policy = request.parameters
    energy_rows: list[
        tuple[HistoricalVerificationSample, float, EnergyDerivationBasis]
    ] = []
    explosives_rows: list[tuple[HistoricalVerificationSample, float]] = []
    invalid_energy_count = 0
    invalid_explosives_count = 0

    for sample in eligible:
        energy = derive_net_production_electricity(sample.electricity)
        if (
            energy.status == "ready"
            and energy.net_production_kwh is not None
            and energy.basis is not None
        ):
            energy_rows.append(
                (
                    sample,
                    energy.net_production_kwh
                    / sample.reported_production_t,
                    energy.basis,
                )
            )
        else:
            invalid_energy_count += 1

        explosives_intensity = (
            sample.explosives.explosives_used_kg
            / sample.reported_production_t
        )
        if math.isfinite(explosives_intensity):
            explosives_rows.append((sample, explosives_intensity))
        else:
            invalid_explosives_count += 1

    energy_limit_excluded = max(
        0, len(energy_rows) - policy.maximum_samples
    )
    explosives_limit_excluded = max(
        0, len(explosives_rows) - policy.maximum_samples
    )
    energy_rows = energy_rows[: policy.maximum_samples]
    explosives_rows = explosives_rows[: policy.maximum_samples]

    energy_baseline: RobustBaseline | None = None
    if len(energy_rows) >= policy.minimum_samples:
        energy_baseline = _robust_baseline(
            metric="energy_kwh_per_t",
            values=[row[1] for row in energy_rows],
            sample_ids=[row[0].sample_id for row in energy_rows],
            minimum_absolute_scale=(
                policy.minimum_energy_scale_kwh_per_t
            ),
            minimum_relative_scale=policy.minimum_relative_scale,
            basis_counts=Counter(row[2] for row in energy_rows),
        )

    explosives_baseline: RobustBaseline | None = None
    if len(explosives_rows) >= policy.minimum_samples:
        explosives_baseline = _robust_baseline(
            metric="explosives_kg_per_t",
            values=[row[1] for row in explosives_rows],
            sample_ids=[row[0].sample_id for row in explosives_rows],
            minimum_absolute_scale=(
                policy.minimum_explosives_scale_kg_per_t
            ),
            minimum_relative_scale=policy.minimum_relative_scale,
        )

    cold_start_reasons: list[str] = []
    if energy_baseline is None:
        cold_start_reasons.append(
            "同矿井、同工况且经人工核查合格的有效电耗样本"
            f"仅 {len(energy_rows)} 条，至少需要 "
            f"{policy.minimum_samples} 条。"
        )
    if explosives_baseline is None:
        cold_start_reasons.append(
            "同矿井、同工况且经人工核查合格的有效炸药样本"
            f"仅 {len(explosives_rows)} 条，至少需要 "
            f"{policy.minimum_samples} 条。"
        )

    return VerificationBaselines(
        status=(
            VerificationStatus.READY
            if not cold_start_reasons
            else VerificationStatus.INSUFFICIENT_HISTORY
        ),
        parameter_version=policy.parameter_version,
        parameters_snapshot=policy,
        compatibility_key=policy.compatibility_key,
        mine_id=request.mine_id,
        operating_condition=request.operating_condition,
        minimum_required_samples=policy.minimum_samples,
        selection=ReferenceSelectionAudit(
            training_cutoff=request.window_start,
            total_sample_count=len(request.history),
            common_eligible_sample_count=len(eligible),
            exclusions=dict(sorted(exclusions.items())),
            invalid_energy_sample_count=invalid_energy_count,
            invalid_explosives_sample_count=invalid_explosives_count,
            energy_limit_excluded_count=energy_limit_excluded,
            explosives_limit_excluded_count=explosives_limit_excluded,
        ),
        energy=energy_baseline,
        explosives=explosives_baseline,
        cold_start_reasons=cold_start_reasons,
    )


def _energy_band(
    ratio: float,
    policy: VerificationParameters,
) -> tuple[EnergyRatioBand, EvidenceDirection, TechnicalClueLevel]:
    if ratio < policy.energy_extreme_low_ratio:
        return (
            EnergyRatioBand.EXTREME_LOW,
            EvidenceDirection.LOW,
            TechnicalClueLevel.ELEVATED,
        )
    if ratio < policy.energy_attention_low_ratio:
        return (
            EnergyRatioBand.ATTENTION_LOW,
            EvidenceDirection.LOW,
            TechnicalClueLevel.ATTENTION,
        )
    if ratio <= policy.energy_attention_high_ratio:
        return (
            EnergyRatioBand.NORMAL,
            EvidenceDirection.NONE,
            TechnicalClueLevel.NORMAL,
        )
    if ratio <= policy.energy_extreme_high_ratio:
        return (
            EnergyRatioBand.ATTENTION_HIGH,
            EvidenceDirection.HIGH,
            TechnicalClueLevel.ATTENTION,
        )
    return (
        EnergyRatioBand.EXTREME_HIGH,
        EvidenceDirection.HIGH,
        TechnicalClueLevel.ELEVATED,
    )


def _historical_rarity(
    *,
    actual: float,
    baseline: RobustBaseline,
    policy: VerificationParameters,
) -> HistoricalRarityAssessment:
    """Score a current value with a leakage-safe finite-sample tail rank.

    The plus-one correction prevents a zero probability and makes small
    reference pools visibly uncertain.  This is the frequency of an equally
    or more extreme value in the selected verified-normal reference
    population, not a probability that a declaration or actor is unlawful.
    """

    values = baseline.reference_values
    count = len(values)
    less = sum(value < actual for value in values)
    equal = sum(value == actual for value in values)
    percentile_rank = (less + 0.5 * equal) / count
    if actual < baseline.median:
        direction = EvidenceDirection.LOW
        extreme_count = sum(value <= actual for value in values)
    elif actual > baseline.median:
        direction = EvidenceDirection.HIGH
        extreme_count = sum(value >= actual for value in values)
    else:
        direction = EvidenceDirection.NONE
        extreme_count = count

    tail_probability = (extreme_count + 1.0) / (count + 1.0)
    if (
        direction is not EvidenceDirection.NONE
        and tail_probability
        <= policy.empirical_extreme_tail_probability
    ):
        band = HistoricalRarityBand.RARE
        clue_level = TechnicalClueLevel.ELEVATED
    elif (
        direction is not EvidenceDirection.NONE
        and tail_probability
        <= policy.empirical_attention_tail_probability
    ):
        band = HistoricalRarityBand.UNCOMMON
        clue_level = TechnicalClueLevel.ATTENTION
    else:
        band = HistoricalRarityBand.TYPICAL
        clue_level = TechnicalClueLevel.NORMAL

    if direction is EvidenceDirection.NONE:
        explanation = (
            "当前值位于已核验正常历史样本中位数；经验尾概率不作为"
            "异常依据。"
        )
    else:
        direction_text = (
            "低侧" if direction is EvidenceDirection.LOW else "高侧"
        )
        explanation = (
            f"在 {count} 条同矿井同工况、已人工核验正常样本中，"
            f"当前值的{direction_text}有限样本经验尾概率为 "
            f"{tail_probability:.4f}（加一校正）；这是参考分布罕见度，"
            "不是违法、瞒报或责任概率。"
        )
    return HistoricalRarityAssessment(
        reference_sample_count=count,
        percentile_rank=percentile_rank,
        direction=direction,
        directional_tail_probability=tail_probability,
        band=band,
        clue_level=clue_level,
        explanation=explanation,
    )


def _assess_energy(
    *,
    derivation: EnergyDerivation,
    production_t: float,
    baseline: RobustBaseline,
    policy: VerificationParameters,
) -> EnergyAssessment:
    assert derivation.net_production_kwh is not None
    actual = derivation.net_production_kwh / production_t
    if baseline.median <= 0.0:
        raise ValueError(
            "historical energy baseline median must be greater than zero"
        )
    ratio = actual / baseline.median
    band, direction, level = _energy_band(ratio, policy)
    historical_rarity = _historical_rarity(
        actual=actual,
        baseline=baseline,
        policy=policy,
    )
    if historical_rarity.clue_level > level:
        level = historical_rarity.clue_level
        direction = historical_rarity.direction
    if direction is EvidenceDirection.NONE:
        explanation = (
            "吨煤生产电耗与同矿井同工况历史基准处于参数版本规定的"
            "正常比值区间。"
        )
    else:
        direction_text = "偏低" if direction is EvidenceDirection.LOW else "偏高"
        explanation = (
            f"吨煤生产电耗相对同矿井同工况历史基准{direction_text}；"
            "应核对生产量分母、分区表计边界、干扰项口径及工况变化，"
            "该偏差本身不能证明申报行为或责任。"
        )
    explanation = f"{explanation}{historical_rarity.explanation}"
    return EnergyAssessment(
        derivation=derivation,
        actual_kwh_per_t=actual,
        baseline=baseline,
        verification_ratio=ratio,
        historical_rarity=historical_rarity,
        band=band,
        direction=direction,
        clue_level=level,
        threshold_parameter_version=policy.parameter_version,
        explanation=explanation,
    )


def _assess_explosives(
    *,
    reading: ExplosivesReading,
    production_t: float,
    baseline: RobustBaseline,
    policy: VerificationParameters,
) -> ExplosivesAssessment:
    actual = reading.explosives_used_kg / production_t
    signed_deviation = actual - baseline.median
    robust_z = signed_deviation / baseline.robust_scale
    historical_rarity = _historical_rarity(
        actual=actual,
        baseline=baseline,
        policy=policy,
    )
    absolute_z = abs(robust_z)
    if absolute_z >= policy.explosives_extreme_robust_z:
        band = RobustDeviationBand.EXTREME
        level = TechnicalClueLevel.ELEVATED
    elif absolute_z >= policy.explosives_attention_robust_z:
        band = RobustDeviationBand.ATTENTION
        level = TechnicalClueLevel.ATTENTION
    else:
        band = RobustDeviationBand.NORMAL
        level = TechnicalClueLevel.NORMAL
    if historical_rarity.clue_level > level:
        level = historical_rarity.clue_level
    if level is TechnicalClueLevel.NORMAL:
        direction = EvidenceDirection.NONE
        explanation = (
            "吨煤炸药消耗与同矿井同工况、人工核查合格历史样本的"
            "稳健基准相符。"
        )
    else:
        direction = (
            EvidenceDirection.LOW
            if signed_deviation < 0.0
            else EvidenceDirection.HIGH
        )
        direction_text = "偏低" if direction is EvidenceDirection.LOW else "偏高"
        explanation = (
            f"吨煤炸药消耗相对稳健历史基准{direction_text}；应核对"
            "爆破作业方式、领退库记录、使用地点、库存和生产量口径，"
            "该偏差仅构成技术核查线索。"
        )
    if (
        direction is EvidenceDirection.NONE
        and historical_rarity.clue_level > TechnicalClueLevel.NORMAL
    ):
        direction = historical_rarity.direction
    explanation = f"{explanation}{historical_rarity.explanation}"
    relative_deviation = (
        signed_deviation / baseline.median
        if baseline.median > 0.0
        else None
    )
    return ExplosivesAssessment(
        actual_kg_per_t=actual,
        baseline=baseline,
        signed_deviation_kg_per_t=signed_deviation,
        signed_relative_deviation=relative_deviation,
        robust_z=robust_z,
        historical_rarity=historical_rarity,
        band=band,
        direction=direction,
        clue_level=level,
        threshold_parameter_version=policy.parameter_version,
        explanation=explanation,
    )


def _maximum_level(
    energy: EnergyAssessment | None,
    explosives: ExplosivesAssessment | None,
) -> TechnicalClueLevel:
    return TechnicalClueLevel(
        max(
            (
                item.clue_level.value
                for item in (energy, explosives)
                if item is not None
            ),
            default=TechnicalClueLevel.NORMAL.value,
        )
    )


def verify_production_consumption(
    request: ProductionVerificationRequest,
) -> ProductionVerificationResult:
    """Create an auditable energy/explosives technical verification result."""

    baselines = build_verification_baselines(request)
    derivation = derive_net_production_electricity(request.electricity)
    policy = request.parameters

    explosives_assessment = (
        _assess_explosives(
            reading=request.explosives,
            production_t=request.reported_production_t,
            baseline=baselines.explosives,
            policy=policy,
        )
        if baselines.explosives is not None
        else None
    )

    if derivation.status == "blocked":
        clues = list(derivation.blocking_reasons)
        if explosives_assessment is not None:
            clues.append(explosives_assessment.explanation)
        return ProductionVerificationResult(
            request_id=request.request_id,
            mine_id=request.mine_id,
            status=VerificationStatus.BLOCKED,
            parameter_version=policy.parameter_version,
            training_cutoff=request.window_start,
            baselines=baselines,
            current_energy_derivation=derivation,
            explosives=explosives_assessment,
            overall_clue_level=_maximum_level(
                None, explosives_assessment
            ),
            technical_clues=clues,
            blocking_reasons=list(derivation.blocking_reasons),
        )

    energy_assessment = (
        _assess_energy(
            derivation=derivation,
            production_t=request.reported_production_t,
            baseline=baselines.energy,
            policy=policy,
        )
        if baselines.energy is not None
        else None
    )
    status = (
        VerificationStatus.READY
        if baselines.status is VerificationStatus.READY
        else VerificationStatus.INSUFFICIENT_HISTORY
    )
    level = _maximum_level(energy_assessment, explosives_assessment)
    same_direction = bool(
        energy_assessment is not None
        and explosives_assessment is not None
        and energy_assessment.direction is not EvidenceDirection.NONE
        and energy_assessment.direction is explosives_assessment.direction
    )
    jointly_upgraded = same_direction
    if jointly_upgraded:
        level = TechnicalClueLevel(
            min(TechnicalClueLevel.HIGH.value, level.value + 1)
        )

    clues: list[str] = []
    if baselines.cold_start_reasons:
        clues.extend(baselines.cold_start_reasons)
    if energy_assessment is not None:
        clues.append(energy_assessment.explanation)
    if explosives_assessment is not None:
        clues.append(explosives_assessment.explanation)
    if jointly_upgraded:
        clues.append(
            "吨煤电耗与吨煤炸药两项独立指标同向偏离，技术核查"
            "优先级上调一级；联合信号仍须经原始凭证和现场核查确认。"
        )

    return ProductionVerificationResult(
        request_id=request.request_id,
        mine_id=request.mine_id,
        status=status,
        parameter_version=policy.parameter_version,
        training_cutoff=request.window_start,
        baselines=baselines,
        current_energy_derivation=derivation,
        energy=energy_assessment,
        explosives=explosives_assessment,
        same_direction=same_direction,
        jointly_upgraded=jointly_upgraded,
        overall_clue_level=level,
        technical_clues=clues,
    )


# Readable alias for callers using the plan's two-indicator terminology.
verify_energy_and_explosives = verify_production_consumption

# Stable, concise API-layer names.  The descriptive class/function names above
# remain canonical for Python callers; these aliases keep HTTP integration
# independent from internal naming preferences.
VerificationRequest = ProductionVerificationRequest
VerificationResult = ProductionVerificationResult
analyze_verification = verify_production_consumption
