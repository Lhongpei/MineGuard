"""The V3 regulatory engine for ten-quantity reports, with V2 read support.

The public product retains :func:`analyze_five_quantity` as its stable business
algorithm.  The implementation is deliberately modular internally: it checks
the deterministic daily/shift arithmetic, identifies operating states, uses
robust same-mine history and anonymous peer aggregates, runs a weighted-L1
linear reconciliation, diagnoses counterfactual minimal conflict sets (MCS),
and evaluates drift/change points.

None of the historical or peer relationships is treated as a law of physics.
Every relationship is an explicit numerator/denominator soft interval in the
elastic optimisation.  The strict solves used
for MCS answer the narrower question "which smallest set of reported/reference
bands would have to be set aside to make this snapshot mutually feasible?".
They are diagnostic and never a finding of cause or misconduct.

``manual_import`` and ``direct_collection`` are equally valid provenance
labels.  Acquisition mode is intentionally absent from every weight,
tolerance, baseline and decision calculation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from itertools import combinations
import hashlib
import json
import math
from statistics import fmean, median
from typing import Annotated, Any, Iterable, Literal, Sequence
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import numpy as np
from pydantic import AliasChoices, AwareDatetime, Field, model_validator
from scipy import __version__ as SCIPY_VERSION
from scipy.optimize import linprog

from . import regulatory_v3 as advanced_v3
from .models import StrictModel
from .temporal import (
    TemporalDetectionParameters,
    TemporalDetectionRequest,
    TemporalDetectorCode,
    TemporalObservation,
    detect_temporal_anomalies,
)


REGULATORY_V2_METHOD_VERSION = "regulatory-ten-quantity-v3.2.0"
AGGREGATION_RULE_VERSION = "ten-quantity-aggregation-v3.0"
BASELINE_ADMISSION_RULE_VERSION = "baseline-admission-v3.0"
BUSINESS_QUANTITY_GROUP_VERSION = "ten-business-quantities-v3.0"
LEGACY_METHOD_VERSION = "regulatory-five-quantity-v2.3.0"
LEGACY_AGGREGATION_RULE_VERSION = "five-quantity-aggregation-v2.2"
LEGACY_BASELINE_ADMISSION_RULE_VERSION = "baseline-admission-v2.2"
LEGACY_BUSINESS_QUANTITY_GROUP_VERSION = "five-business-quantities-v2.3"
LEGACY_CONTRACT_VERSION = "enterprise-five-quantity-submission-v2"
TEN_CONTRACT_VERSION = "enterprise-ten-quantity-submission-v3"
CalendarDate = date


class DecisionStatus(StrEnum):
    NORMAL_CANDIDATE = "normal_candidate"
    RISK = "risk"
    INSUFFICIENT_DATA = "insufficient_data"


class AcquisitionMode(StrEnum):
    """Trace information only; the two modes have identical evidential weight."""

    MANUAL_IMPORT = "manual_import"
    DIRECT_COLLECTION = "direct_collection"


class OperatingState(StrEnum):
    NON_PRODUCTION_CANDIDATE = "non_production_candidate"
    RESTART_RAMP_CANDIDATE = "restart_ramp_candidate"
    PRODUCTION = "production"
    UNKNOWN = "unknown"


class SignalSeverity(StrEnum):
    INFORMATION = "information"
    REVIEW = "review"
    RISK = "risk"


class RelationshipCode(StrEnum):
    VENTILATION_PER_PRODUCTION = "ventilation_per_production"
    ELECTRICITY_PER_PRODUCTION = "electricity_per_production"
    DETONATORS_PER_PRODUCTION = "detonators_per_production"
    EXPLOSIVES_PER_PRODUCTION = "explosives_per_production"
    MINE_ENTRY_PERSONS_PER_PRODUCTION = "mine_entry_persons_per_production"
    VENTILATION_PER_EXTRACTION = "ventilation_per_extraction"
    ELECTRICITY_PER_EXTRACTION = "electricity_per_extraction"
    DETONATORS_PER_EXTRACTION = "detonators_per_extraction"
    EXPLOSIVES_PER_EXTRACTION = "explosives_per_extraction"
    MINE_ENTRY_PERSONS_PER_EXTRACTION = "mine_entry_persons_per_extraction"
    PRODUCTION_PER_EXTRACTION = "production_per_extraction"
    SALES_PER_PRODUCTION = "sales_per_production"
    TRANSPORT_PER_PRODUCTION = "transport_per_production"
    TRANSPORT_PER_SALES = "transport_per_sales"
    WASH_FEED_PER_PRODUCTION = "wash_feed_per_production"
    INVOICED_QUANTITY_PER_SALES = "invoiced_quantity_per_sales"

    @classmethod
    def _missing_(cls, value: object) -> "RelationshipCode | None":
        # Read-only compatibility for analysis records produced before the
        # business term was corrected from generic labour to underground entry.
        if value == "labor_per_production":
            return cls.MINE_ENTRY_PERSONS_PER_PRODUCTION
        return None


LEGACY_METRICS: tuple[str, ...] = (
    "ventilation_m3_min",
    "electricity_kwh",
    "detonators_count",
    "explosives_kg",
    "mine_entry_persons",
    "production_t",
)
METRICS: tuple[str, ...] = (
    *LEGACY_METRICS,
    "extraction_t",
    "sales_t",
    "transport_t",
    "wash_feed_t",
    "invoiced_quantity_t",
)
SHIFT_REQUIRED_METRICS: tuple[str, ...] = (*LEGACY_METRICS, "extraction_t")
COMMERCIAL_DAILY_METRICS = frozenset(
    {"sales_t", "transport_t", "wash_feed_t", "invoiced_quantity_t"}
)
FIVE_QUANTITY_GROUPS: dict[str, tuple[str, ...]] = {
    "airflow": ("ventilation_m3_min",),
    "electricity": ("electricity_kwh",),
    # Fire materials are one business quantity but their unlike units must
    # remain separate atomic measurements rather than being arithmetically added.
    "blasting_materials": ("detonators_count", "explosives_kg"),
    "mine_entry_personnel": ("mine_entry_persons",),
    "production": ("production_t",),
}
TEN_QUANTITY_GROUPS: dict[str, tuple[str, ...]] = {
    **FIVE_QUANTITY_GROUPS,
    "extraction": ("extraction_t",),
    "sales": ("sales_t",),
    "transport": ("transport_t",),
    "coal_washing": ("wash_feed_t",),
    "invoicing": ("invoiced_quantity_t",),
}
ADDITIVE_METRICS = frozenset(METRICS) - {"ventilation_m3_min"}
LEGACY_RELATIONSHIPS: tuple[RelationshipCode, ...] = (
    RelationshipCode.VENTILATION_PER_PRODUCTION,
    RelationshipCode.ELECTRICITY_PER_PRODUCTION,
    RelationshipCode.DETONATORS_PER_PRODUCTION,
    RelationshipCode.EXPLOSIVES_PER_PRODUCTION,
    RelationshipCode.MINE_ENTRY_PERSONS_PER_PRODUCTION,
)
TEN_RELATIONSHIPS: tuple[RelationshipCode, ...] = (
    RelationshipCode.VENTILATION_PER_EXTRACTION,
    RelationshipCode.ELECTRICITY_PER_EXTRACTION,
    RelationshipCode.DETONATORS_PER_EXTRACTION,
    RelationshipCode.EXPLOSIVES_PER_EXTRACTION,
    RelationshipCode.MINE_ENTRY_PERSONS_PER_EXTRACTION,
    RelationshipCode.PRODUCTION_PER_EXTRACTION,
    RelationshipCode.SALES_PER_PRODUCTION,
    RelationshipCode.TRANSPORT_PER_PRODUCTION,
    RelationshipCode.TRANSPORT_PER_SALES,
    RelationshipCode.WASH_FEED_PER_PRODUCTION,
    RelationshipCode.INVOICED_QUANTITY_PER_SALES,
)
RELATIONSHIP_METRICS: dict[RelationshipCode, tuple[str, str]] = {
    RelationshipCode.VENTILATION_PER_PRODUCTION: (
        "ventilation_m3_min",
        "production_t",
    ),
    RelationshipCode.ELECTRICITY_PER_PRODUCTION: (
        "electricity_kwh",
        "production_t",
    ),
    RelationshipCode.DETONATORS_PER_PRODUCTION: (
        "detonators_count",
        "production_t",
    ),
    RelationshipCode.EXPLOSIVES_PER_PRODUCTION: (
        "explosives_kg",
        "production_t",
    ),
    RelationshipCode.MINE_ENTRY_PERSONS_PER_PRODUCTION: (
        "mine_entry_persons",
        "production_t",
    ),
    RelationshipCode.VENTILATION_PER_EXTRACTION: (
        "ventilation_m3_min",
        "extraction_t",
    ),
    RelationshipCode.ELECTRICITY_PER_EXTRACTION: (
        "electricity_kwh",
        "extraction_t",
    ),
    RelationshipCode.DETONATORS_PER_EXTRACTION: (
        "detonators_count",
        "extraction_t",
    ),
    RelationshipCode.EXPLOSIVES_PER_EXTRACTION: (
        "explosives_kg",
        "extraction_t",
    ),
    RelationshipCode.MINE_ENTRY_PERSONS_PER_EXTRACTION: (
        "mine_entry_persons",
        "extraction_t",
    ),
    RelationshipCode.PRODUCTION_PER_EXTRACTION: ("production_t", "extraction_t"),
    RelationshipCode.SALES_PER_PRODUCTION: ("sales_t", "production_t"),
    RelationshipCode.TRANSPORT_PER_PRODUCTION: ("transport_t", "production_t"),
    RelationshipCode.TRANSPORT_PER_SALES: ("transport_t", "sales_t"),
    RelationshipCode.WASH_FEED_PER_PRODUCTION: ("wash_feed_t", "production_t"),
    RelationshipCode.INVOICED_QUANTITY_PER_SALES: (
        "invoiced_quantity_t",
        "sales_t",
    ),
}
# Compatibility export used by read-side presentation code.  New algorithmic
# code must use both columns in ``RELATIONSHIP_METRICS``.
RELATIONSHIP_METRIC: dict[RelationshipCode, str] = {
    relationship: numerator
    for relationship, (numerator, _denominator) in RELATIONSHIP_METRICS.items()
}
RELATIONSHIP_LABELS: dict[RelationshipCode, str] = {
    RelationshipCode.VENTILATION_PER_PRODUCTION: "风量/产量",
    RelationshipCode.ELECTRICITY_PER_PRODUCTION: "电量/产量",
    RelationshipCode.DETONATORS_PER_PRODUCTION: "雷管量/产量",
    RelationshipCode.EXPLOSIVES_PER_PRODUCTION: "炸药量/产量",
    RelationshipCode.MINE_ENTRY_PERSONS_PER_PRODUCTION: "入井人员量/产量",
    RelationshipCode.VENTILATION_PER_EXTRACTION: "风量/开采量",
    RelationshipCode.ELECTRICITY_PER_EXTRACTION: "电量/开采量",
    RelationshipCode.DETONATORS_PER_EXTRACTION: "雷管量/开采量",
    RelationshipCode.EXPLOSIVES_PER_EXTRACTION: "炸药量/开采量",
    RelationshipCode.MINE_ENTRY_PERSONS_PER_EXTRACTION: "入井人员量/开采量",
    RelationshipCode.PRODUCTION_PER_EXTRACTION: "产量/开采量",
    RelationshipCode.SALES_PER_PRODUCTION: "销售量/产量",
    RelationshipCode.TRANSPORT_PER_PRODUCTION: "运输量/产量",
    RelationshipCode.TRANSPORT_PER_SALES: "运输量/销售量",
    RelationshipCode.WASH_FEED_PER_PRODUCTION: "洗煤量/产量",
    RelationshipCode.INVOICED_QUANTITY_PER_SALES: "开票量/销售量",
}
METRIC_LABELS: dict[str, str] = {
    "ventilation_m3_min": "风量",
    "electricity_kwh": "电量",
    "detonators_count": "雷管量",
    "explosives_kg": "炸药量",
    "mine_entry_persons": "入井人员量",
    "production_t": "产量",
    "extraction_t": "开采量",
    "sales_t": "销售量",
    "transport_t": "运输量",
    "wash_feed_t": "洗煤量",
    "invoiced_quantity_t": "开票量",
}
METRIC_UNITS: dict[str, str] = {
    "ventilation_m3_min": "m3/min",
    "electricity_kwh": "kWh",
    "detonators_count": "count",
    "explosives_kg": "kg",
    "mine_entry_persons": "person",
    "production_t": "t",
    "extraction_t": "t",
    "sales_t": "t",
    "transport_t": "t",
    "wash_feed_t": "t",
    "invoiced_quantity_t": "t",
}


def applicable_metrics_for_scope(scope: str) -> tuple[str, ...]:
    if scope == "five_quantity_v2":
        return LEGACY_METRICS
    if scope == "ten_quantity_v3":
        return METRICS
    raise ValueError(f"unknown quantity scope: {scope}")


def shift_required_metrics_for_scope(scope: str) -> tuple[str, ...]:
    if scope == "five_quantity_v2":
        return LEGACY_METRICS
    if scope == "ten_quantity_v3":
        return SHIFT_REQUIRED_METRICS
    raise ValueError(f"unknown quantity scope: {scope}")


def applicable_relationships_for_scope(scope: str) -> tuple[RelationshipCode, ...]:
    if scope == "five_quantity_v2":
        return LEGACY_RELATIONSHIPS
    if scope == "ten_quantity_v3":
        return TEN_RELATIONSHIPS
    raise ValueError(f"unknown quantity scope: {scope}")


class ShiftValues(StrictModel):
    zero_shift: Annotated[float | None, Field(ge=0.0)] = None
    eight_shift: Annotated[float | None, Field(ge=0.0)] = None
    four_shift: Annotated[float | None, Field(ge=0.0)] = None

    @property
    def complete(self) -> bool:
        return all(
            value is not None
            for value in (self.zero_shift, self.eight_shift, self.four_shift)
        )

    @property
    def provided_count(self) -> int:
        return sum(
            value is not None
            for value in (self.zero_shift, self.eight_shift, self.four_shift)
        )

    def aggregate(
        self,
        *,
        additive: bool,
        duration_minutes: tuple[float, float, float] | None = None,
    ) -> float | None:
        values = (self.zero_shift, self.eight_shift, self.four_shift)
        if not self.complete:
            return None
        numeric = [float(value) for value in values if value is not None]
        if additive:
            return math.fsum(numeric)
        if duration_minutes is None:
            return fmean(numeric)
        total_minutes = math.fsum(duration_minutes)
        if total_minutes <= 0:
            return None
        return (
            math.fsum(
                value * minutes
                for value, minutes in zip(numeric, duration_minutes, strict=True)
            )
            / total_minutes
        )


class ShiftWindowMetadata(StrictModel):
    shift_code: Annotated[str, Field(min_length=1, max_length=64)]
    start_at: AwareDatetime
    end_at: AwareDatetime
    aggregations: dict[str, Literal["time_weighted_average", "sum", "snapshot"]]

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_personnel_key(cls, value: Any) -> Any:
        if not isinstance(value, dict) or not isinstance(
            value.get("aggregations"), dict
        ):
            return value
        normalized = dict(value)
        aggregations = dict(value["aggregations"])
        if "mine_entry_persons" not in aggregations and "labor_persons" in aggregations:
            aggregations["mine_entry_persons"] = aggregations.pop("labor_persons")
        normalized["aggregations"] = aggregations
        return normalized

    @model_validator(mode="after")
    def validate_window(self) -> "ShiftWindowMetadata":
        if self.end_at <= self.start_at:
            raise ValueError("shift metadata end_at must follow start_at")
        metric_set = set(self.aggregations)
        is_legacy = metric_set == set(LEGACY_METRICS)
        is_v3 = set(SHIFT_REQUIRED_METRICS) <= metric_set <= set(METRICS)
        if not (is_legacy or is_v3):
            raise ValueError(
                "shift metadata must preserve the six legacy atoms or seven "
                "shift-required V3 atoms plus optional commercial atoms"
            )
        return self

    @property
    def duration_minutes(self) -> float:
        return (self.end_at - self.start_at).total_seconds() / 60.0


class ShiftMetadata(StrictModel):
    zero_shift: ShiftWindowMetadata
    eight_shift: ShiftWindowMetadata
    four_shift: ShiftWindowMetadata

    @property
    def duration_minutes(self) -> tuple[float, float, float]:
        return (
            self.zero_shift.duration_minutes,
            self.eight_shift.duration_minutes,
            self.four_shift.duration_minutes,
        )


class ReportedQuantity(StrictModel):
    daily_total: Annotated[float | None, Field(ge=0.0)] = None
    daily_aggregation: Literal["time_weighted_average", "sum", "snapshot"] | None = None
    shifts: ShiftValues | None = None


class ReportedQuality(StrictModel):
    """Wire quality facts retained for the algorithm instead of being dropped."""

    daily_total: tuple[str, ...] = ()
    zero_shift: tuple[str, ...] = ()
    eight_shift: tuple[str, ...] = ()
    four_shift: tuple[str, ...] = ()

    @property
    def all_flags(self) -> frozenset[str]:
        return frozenset(
            (
                *self.daily_total,
                *self.zero_shift,
                *self.eight_shift,
                *self.four_shift,
            )
        )


class FiveQuantityDay(StrictModel):
    date: CalendarDate = Field(validation_alias=AliasChoices("date", "observed_date"))
    ventilation_m3_min: ReportedQuantity = Field(
        validation_alias=AliasChoices(
            "ventilation_m3_min", "wind_m3_min", "ventilation"
        )
    )
    mine_entry_persons: ReportedQuantity = Field(
        validation_alias=AliasChoices("mine_entry_persons", "labor_persons")
    )
    electricity_kwh: ReportedQuantity
    detonators_count: ReportedQuantity
    explosives_kg: ReportedQuantity
    production_t: ReportedQuantity
    extraction_t: ReportedQuantity | None = None
    sales_t: ReportedQuantity | None = None
    transport_t: ReportedQuantity | None = None
    wash_feed_t: ReportedQuantity | None = None
    invoiced_quantity_t: ReportedQuantity | None = None
    declared_operating_state: (
        Literal["producing", "stopped", "maintenance", "restarting", "unknown"] | None
    ) = None
    quality: dict[str, ReportedQuality] = Field(default_factory=dict)
    shift_metadata: ShiftMetadata | None = None

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_quality_key(cls, value: Any) -> Any:
        if not isinstance(value, dict) or not isinstance(value.get("quality"), dict):
            return value
        normalized = dict(value)
        quality = dict(value["quality"])
        if "mine_entry_persons" not in quality and "labor_persons" in quality:
            quality["mine_entry_persons"] = quality.pop("labor_persons")
        normalized["quality"] = quality
        return normalized

    @model_validator(mode="after")
    def validate_count_metrics(self) -> "FiveQuantityDay":
        for metric in ("detonators_count", "mine_entry_persons"):
            quantity = getattr(self, metric)
            values = [quantity.daily_total]
            if quantity.shifts is not None:
                values.extend(
                    (
                        quantity.shifts.zero_shift,
                        quantity.shifts.eight_shift,
                        quantity.shifts.four_shift,
                    )
                )
            if any(
                value is not None and not float(value).is_integer() for value in values
            ):
                raise ValueError(f"{metric} values must be integral")
        if self.mine_entry_persons.daily_aggregation not in {None, "sum"}:
            raise ValueError("mine_entry_persons aggregation must be sum")
        if self.shift_metadata is not None and any(
            shift.aggregations["mine_entry_persons"] != "sum"
            for shift in (
                self.shift_metadata.zero_shift,
                self.shift_metadata.eight_shift,
                self.shift_metadata.four_shift,
            )
        ):
            raise ValueError("mine_entry_persons shift aggregation must be sum")
        for metric in COMMERCIAL_DAILY_METRICS:
            quantity = getattr(self, metric)
            if quantity is not None and quantity.daily_aggregation not in {None, "sum"}:
                raise ValueError(f"{metric} aggregation must be sum")
        if (
            self.extraction_t is not None
            and self.extraction_t.daily_aggregation
            not in {
                None,
                "sum",
            }
        ):
            raise ValueError("extraction_t aggregation must be sum")
        if self.shift_metadata is not None and self.extraction_t is not None:
            if any(
                shift.aggregations.get("extraction_t") != "sum"
                for shift in (
                    self.shift_metadata.zero_shift,
                    self.shift_metadata.eight_shift,
                    self.shift_metadata.four_shift,
                )
            ):
                raise ValueError("extraction_t shift aggregation must be sum")
        if not set(self.quality) <= set(METRICS):
            raise ValueError("quality contains an unknown metric")
        return self

    def quantities(
        self,
        metrics: Sequence[str] = METRICS,
    ) -> dict[str, ReportedQuantity | None]:
        return {metric: getattr(self, metric) for metric in metrics}


def _shift_aggregate(
    day: FiveQuantityDay,
    metric: str,
    quantity: ReportedQuantity,
) -> tuple[float | None, str]:
    if quantity.shifts is None:
        return None, "not_provided"
    if day.shift_metadata is None:
        aggregation = "sum" if metric in ADDITIVE_METRICS else "time_weighted_average"
    else:
        aggregations = {
            window.aggregations.get(metric)
            for window in (
                day.shift_metadata.zero_shift,
                day.shift_metadata.eight_shift,
                day.shift_metadata.four_shift,
            )
        }
        if None in aggregations:
            # Commercial shift values are cadence-optional.  Preserve any raw
            # values but do not invent an aggregation when metadata says the
            # metric is not applicable to one or more shifts.
            return None, "not_applicable"
        if len(aggregations) != 1:
            return None, "mixed"
        aggregation = aggregations.pop()
    if aggregation == "snapshot":
        # Three point-in-time snapshots do not define a daily snapshot.  They
        # remain in the immutable raw report but are not silently summed or
        # averaged into another business meaning.
        return None, aggregation
    return (
        quantity.shifts.aggregate(
            additive=aggregation == "sum",
            duration_minutes=(
                day.shift_metadata.duration_minutes
                if day.shift_metadata is not None
                and aggregation == "time_weighted_average"
                else None
            ),
        ),
        aggregation,
    )


def effective_reported_value(
    day: FiveQuantityDay,
    metric: str,
) -> float | None:
    """Return the governed daily value without changing aggregation meaning."""

    quantity = getattr(day, metric)
    if quantity is None:
        return None
    if quantity.daily_total is not None:
        return float(quantity.daily_total)
    shift_value, _ = _shift_aggregate(day, metric, quantity)
    return shift_value


class SubmissionProvenance(StrictModel):
    acquisition_mode: AcquisitionMode
    source_name: Annotated[str, Field(min_length=1, max_length=256)]
    evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    source_record_id: Annotated[str | None, Field(min_length=1, max_length=256)] = None


class ComparisonContext(StrictModel):
    """Non-identifying dimensions used to build a comparable peer cohort."""

    capacity_band: Annotated[str, Field(min_length=1, max_length=64)]
    mining_method: Annotated[str, Field(min_length=1, max_length=64)]
    shift_system: Annotated[str, Field(min_length=1, max_length=64)]
    coal_type: Annotated[str, Field(min_length=1, max_length=64)]
    operating_regime: Annotated[str, Field(min_length=1, max_length=64)]

    @property
    def group_key(self) -> str:
        return _sha256(self.model_dump(mode="json"))[:24]


class FiveQuantitySubmission(StrictModel):
    contract_version: Literal[
        "enterprise-five-quantity-submission-v2",
        "enterprise-ten-quantity-submission-v3",
    ] = LEGACY_CONTRACT_VERSION
    quantity_scope: Literal["five_quantity_v2", "ten_quantity_v3"] = "five_quantity_v2"
    submission_id: Annotated[str, Field(min_length=8, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    mine_name: Annotated[str, Field(min_length=1, max_length=256)]
    reporting_timezone: Annotated[str, Field(min_length=1, max_length=64)] = "UTC"
    revision: Annotated[int, Field(ge=1)] = 1
    supersedes_submission_id: Annotated[
        str | None, Field(min_length=8, max_length=128)
    ] = None
    period_start: date
    period_end: date
    comparison_context: ComparisonContext | None = None
    days: Annotated[list[FiveQuantityDay], Field(min_length=1, max_length=366)]
    provenance: Annotated[
        list[SubmissionProvenance], Field(min_length=1, max_length=64)
    ]

    @property
    def comparison_group(self) -> str:
        """Keep history mine-local when optional cohort metadata is absent."""

        if self.comparison_context is not None:
            return self.comparison_context.group_key
        return "mine-local-" + _sha256(self.mine_id)[:24]

    @model_validator(mode="before")
    @classmethod
    def infer_quantity_scope(cls, value: Any) -> Any:
        """Read V2 documents unchanged and infer scope for early V3 producers."""

        if not isinstance(value, dict) or "quantity_scope" in value:
            return value
        normalized = dict(value)
        if normalized.get("contract_version") == TEN_CONTRACT_VERSION:
            normalized["quantity_scope"] = "ten_quantity_v3"
        return normalized

    @model_validator(mode="after")
    def validate_period_and_days(self) -> "FiveQuantitySubmission":
        expected_scope = (
            "ten_quantity_v3"
            if self.contract_version == TEN_CONTRACT_VERSION
            else "five_quantity_v2"
        )
        if self.quantity_scope != expected_scope:
            raise ValueError("contract_version and quantity_scope do not match")
        if self.quantity_scope == "five_quantity_v2" and any(
            getattr(day, metric) is not None or metric in day.quality
            for day in self.days
            for metric in METRICS[len(LEGACY_METRICS) :]
        ):
            raise ValueError("V2 scope cannot silently discard V3 quantity fields")
        if self.period_end < self.period_start:
            raise ValueError("period_end cannot predate period_start")
        expected_span = (self.period_end - self.period_start).days + 1
        if expected_span > 366:
            raise ValueError("submission period cannot exceed 366 days")
        if self.period_start.strftime("%Y-%m") != self.period_end.strftime("%Y-%m"):
            raise ValueError("one five-quantity submission must stay in one month")
        try:
            ZoneInfo(self.reporting_timezone)
        except ZoneInfoNotFoundError as error:
            raise ValueError("reporting_timezone is not an IANA timezone") from error
        dates = [item.date for item in self.days]
        if len(dates) != len(set(dates)):
            raise ValueError("daily dates must be unique")
        outside = [
            item.isoformat()
            for item in dates
            if item < self.period_start or item > self.period_end
        ]
        if outside:
            raise ValueError("daily date outside submission period: " + outside[0])
        return self

    @property
    def applicable_metrics(self) -> tuple[str, ...]:
        return applicable_metrics_for_scope(self.quantity_scope)

    @property
    def applicable_relationships(self) -> tuple[RelationshipCode, ...]:
        return applicable_relationships_for_scope(self.quantity_scope)


class HistoricalFiveQuantityDay(StrictModel):
    """A governed normal-candidate day from the same mine."""

    date: CalendarDate
    ventilation_m3_min: Annotated[float, Field(ge=0.0)]
    mine_entry_persons: Annotated[float, Field(ge=0.0)] = Field(
        validation_alias=AliasChoices("mine_entry_persons", "labor_persons")
    )
    electricity_kwh: Annotated[float, Field(ge=0.0)]
    detonators_count: Annotated[float, Field(ge=0.0)]
    explosives_kg: Annotated[float, Field(ge=0.0)]
    production_t: Annotated[float, Field(ge=0.0)]
    extraction_t: Annotated[float | None, Field(ge=0.0)] = None
    sales_t: Annotated[float | None, Field(ge=0.0)] = None
    transport_t: Annotated[float | None, Field(ge=0.0)] = None
    wash_feed_t: Annotated[float | None, Field(ge=0.0)] = None
    invoiced_quantity_t: Annotated[float | None, Field(ge=0.0)] = None

    @model_validator(mode="after")
    def validate_integral_counts(self) -> "HistoricalFiveQuantityDay":
        if not float(self.mine_entry_persons).is_integer():
            raise ValueError("mine_entry_persons must be integral")
        if not float(self.detonators_count).is_integer():
            raise ValueError("detonators_count must be integral")
        return self

    def values(self) -> dict[str, float | None]:
        return {
            metric: (
                float(value) if (value := getattr(self, metric)) is not None else None
            )
            for metric in METRICS
        }


class ReferenceBand(StrictModel):
    relationship: RelationshipCode
    numerator_metric: Annotated[str | None, Field(min_length=1, max_length=64)] = None
    denominator_metric: Annotated[str | None, Field(min_length=1, max_length=64)] = None
    lower: Annotated[float, Field(ge=0.0)]
    center: Annotated[float, Field(ge=0.0)]
    upper: Annotated[float, Field(ge=0.0)]
    sample_count: Annotated[int, Field(ge=1)]
    mine_count: Annotated[int | None, Field(ge=1)] = None
    basis: Literal["same_mine_history", "anonymous_peer", "within_submission"]
    comparison_group: Annotated[str | None, Field(min_length=1, max_length=128)] = None

    @model_validator(mode="after")
    def validate_bounds(self) -> "ReferenceBand":
        if not self.lower <= self.center <= self.upper:
            raise ValueError("reference band requires lower <= center <= upper")
        canonical_numerator, canonical_denominator = RELATIONSHIP_METRICS[
            self.relationship
        ]
        if self.numerator_metric not in {None, canonical_numerator}:
            raise ValueError("reference numerator does not match relationship")
        if self.denominator_metric not in {None, canonical_denominator}:
            raise ValueError("reference denominator does not match relationship")
        # Populate new V3 semantics while retaining read compatibility for bands
        # written before the two columns existed.
        object.__setattr__(self, "numerator_metric", canonical_numerator)
        object.__setattr__(self, "denominator_metric", canonical_denominator)
        return self


class RegulatoryFiveQuantityParameters(StrictModel):
    minimum_complete_days: Annotated[int, Field(ge=3, le=60)] = 7
    minimum_completeness_ratio: Annotated[float, Field(gt=0.0, le=1.0)] = 0.80
    minimum_reference_samples: Annotated[int, Field(ge=5, le=365)] = 7
    minimum_peer_mines: Annotated[int, Field(ge=3, le=1000)] = 3
    shift_absolute_tolerance: Annotated[float, Field(ge=0.0)] = 1e-6
    shift_relative_tolerance: Annotated[float, Field(ge=0.0, le=0.5)] = 0.02
    observation_absolute_tolerance: Annotated[float, Field(gt=0.0)] = 1e-6
    observation_relative_tolerance: Annotated[float, Field(gt=0.0, le=0.5)] = 0.02
    reference_robust_z: Annotated[float, Field(gt=1.0, le=10.0)] = 3.5
    reference_minimum_relative_half_width: Annotated[float, Field(gt=0.0, le=1.0)] = (
        0.15
    )
    relationship_slack_penalty: Annotated[float, Field(gt=0.0, le=1e9)] = 8.0
    normalized_adjustment_risk_threshold: Annotated[float, Field(gt=0.0, le=100.0)] = (
        3.0
    )
    restart_prior_non_production_days: Annotated[int, Field(ge=2, le=30)] = 3
    restart_ramp_days: Annotated[int, Field(ge=1, le=14)] = 3
    production_epsilon_t: Annotated[float, Field(ge=0.0)] = 1e-6
    drift_minimum_relative_change: Annotated[float, Field(gt=0.0, le=2.0)] = 0.20
    change_point_minimum_relative_shift: Annotated[float, Field(gt=0.0, le=2.0)] = 0.15
    change_point_minimum_explained_fraction: Annotated[float, Field(gt=0.0, le=1.0)] = (
        0.45
    )
    change_point_bic_margin: Annotated[float, Field(ge=0.0, le=100.0)] = 2.0
    temporal_baseline_window: Annotated[int, Field(ge=8, le=365)] = 60
    temporal_min_history: Annotated[int, Field(ge=3, le=365)] = 7
    temporal_minimum_relative_scale: Annotated[float, Field(ge=0.0, le=1.0)] = 0.05
    temporal_mad_z_threshold: Annotated[float, Field(gt=0.0, le=100.0)] = 4.0
    temporal_ewma_alpha: Annotated[float, Field(gt=0.0, le=1.0)] = 0.25
    temporal_ewma_z_threshold: Annotated[float, Field(gt=0.0, le=100.0)] = 3.0
    temporal_cusum_drift: Annotated[float, Field(ge=0.0, le=100.0)] = 0.5
    temporal_cusum_threshold: Annotated[float, Field(gt=0.0, le=100.0)] = 5.0
    temporal_page_hinkley_delta: Annotated[float, Field(ge=0.0, le=100.0)] = 0.1
    temporal_page_hinkley_threshold: Annotated[float, Field(gt=0.0, le=100.0)] = 8.0
    max_mcs: Annotated[int, Field(ge=1, le=20)] = 5
    max_mcs_cardinality: Annotated[int, Field(ge=1, le=3)] = 2
    max_mcs_search_combinations: Annotated[int, Field(ge=1, le=100_000)] = 20_000

    @model_validator(mode="after")
    def validate_temporal_window(self) -> "RegulatoryFiveQuantityParameters":
        if self.temporal_min_history > self.temporal_baseline_window:
            raise ValueError(
                "temporal_min_history cannot exceed temporal_baseline_window"
            )
        return self


class AnalysisSignal(StrictModel):
    code: str
    severity: SignalSeverity
    message: str
    date: CalendarDate | None = None
    metric: str | None = None
    observed: float | None = None
    expected_lower: float | None = None
    expected_upper: float | None = None
    basis: str


class CoverageSummary(StrictModel):
    expected_day_count: Annotated[int, Field(ge=1)]
    reported_day_count: Annotated[int, Field(ge=0)]
    complete_day_count: Annotated[int, Field(ge=0)]
    missing_calendar_day_count: Annotated[int, Field(ge=0)]
    completeness_ratio: Annotated[float, Field(ge=0.0, le=1.0)]


class DayState(StrictModel):
    date: CalendarDate
    state: OperatingState


class L1Adjustment(StrictModel):
    date: CalendarDate
    metric: str
    reported_value: float
    reconciled_value: float
    absolute_adjustment: float
    normalized_adjustment: float
    unit: str


class SoftConstraintDiagnostic(StrictModel):
    date: CalendarDate
    relationship: RelationshipCode
    basis: Literal["same_mine_history", "anonymous_peer", "within_submission"]
    lower: float
    upper: float
    observed_ratio: float | None
    lower_slack: float
    upper_slack: float


class MinimalConflictSet(StrictModel):
    date: CalendarDate
    relaxed_groups: list[str]
    cardinality: Annotated[int, Field(ge=1)]
    statement: Literal["diagnostic_counterfactual_not_cause_or_misconduct"] = (
        "diagnostic_counterfactual_not_cause_or_misconduct"
    )


class ReconciliationSummary(StrictModel):
    solver: Literal["scipy-highs-weighted-l1"] = "scipy-highs-weighted-l1"
    success: bool
    solver_status: Literal[
        "optimal",
        "infeasible",
        "unbounded",
        "iteration_or_time_limit",
        "numerical_failure",
        "solver_error",
    ] = "optimal"
    solver_methods_attempted: list[str] = Field(default_factory=lambda: ["highs"])
    solver_message: str | None = None
    objective_value: float | None
    adjustments: list[L1Adjustment]
    soft_constraint_diagnostics: list[SoftConstraintDiagnostic]
    minimal_conflict_sets: list[MinimalConflictSet]
    mcs_search_complete: bool
    note: Literal[
        "history_and_peer_intervals_are_soft_references_not_physical_laws"
    ] = "history_and_peer_intervals_are_soft_references_not_physical_laws"


class ReferenceSummary(StrictModel):
    same_mine_history_day_count: Annotated[int, Field(ge=0)]
    accepted_history_bands: list[ReferenceBand]
    accepted_peer_bands: list[ReferenceBand]
    within_submission_bands: list[ReferenceBand]
    peer_anonymity_minimum_mines: Annotated[int, Field(ge=3)]


class RegulatoryFiveQuantityResult(StrictModel):
    method_version: str = REGULATORY_V2_METHOD_VERSION
    mine_id: str
    submission_id: str
    decision: DecisionStatus
    decision_reasons: list[str]
    data_sufficiency_reasons: list[str] = Field(default_factory=list)
    coverage: CoverageSummary
    day_states: list[DayState]
    data_quality_signals: list[AnalysisSignal]
    temporal_signals: list[AnalysisSignal]
    relationship_signals: list[AnalysisSignal]
    references: ReferenceSummary
    reconciliation: ReconciliationSummary
    algorithm_input_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    configuration_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    runtime_manifest: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True)
class _Observation:
    group: str
    metric: str
    value: float
    tolerance: float


@dataclass(frozen=True)
class _Relation:
    group: str
    relationship: RelationshipCode
    numerator_metric: str
    denominator_metric: str
    band: ReferenceBand


@dataclass(frozen=True)
class _L1Solve:
    values: dict[str, float] | None
    objective: float | None
    relation_slacks: list[tuple[_Relation, float, float]]
    status: Literal[
        "optimal",
        "infeasible",
        "unbounded",
        "iteration_or_time_limit",
        "numerical_failure",
        "solver_error",
    ]
    methods_attempted: tuple[str, ...]
    message: str | None


def _advanced_v3_quantity(
    quantity: ReportedQuantity | None,
) -> advanced_v3.ReportedQuantity:
    """Losslessly adapt one governed V3 measurement to the evidence engine."""

    if quantity is None:
        return advanced_v3.ReportedQuantity()
    shifts = None
    if quantity.shifts is not None:
        shifts = advanced_v3.ShiftValues(
            zero_shift=quantity.shifts.zero_shift,
            eight_shift=quantity.shifts.eight_shift,
            four_shift=quantity.shifts.four_shift,
        )
    return advanced_v3.ReportedQuantity(
        daily_total=quantity.daily_total,
        daily_aggregation=quantity.daily_aggregation,
        shifts=shifts,
    )


def _run_advanced_v3_evidence_layer(
    submission: FiveQuantitySubmission,
    history: Sequence[HistoricalFiveQuantityDay],
) -> advanced_v3.TenQuantityAnalysisResult:
    """Run the governed V3.1 evidence layer without inventing support facts.

    The base V3 exchange contains the eleven primary atoms but intentionally
    does not claim inventory snapshots, washing outputs or shipment-level
    credential cohorts.  Those evidence modules therefore remain explicitly
    not applicable at this adapter boundary.  A future governed enrichment
    connector may supply them as independent facts; this adapter must never
    synthesize them from aggregate sales, transport or invoice totals.
    """

    days: list[advanced_v3.TenQuantityDay] = []
    for day in sorted(submission.days, key=lambda item: item.date):
        duration_updates: dict[str, float] = {}
        if day.shift_metadata is not None:
            zero, eight, four = day.shift_metadata.duration_minutes
            duration_updates = {
                "zero_shift": zero,
                "eight_shift": eight,
                "four_shift": four,
            }
        days.append(
            advanced_v3.TenQuantityDay(
                date=day.date,
                **{
                    metric: _advanced_v3_quantity(getattr(day, metric))
                    for metric in METRICS
                },
                shift_durations=advanced_v3.ShiftDurations(**duration_updates),
            )
        )

    historical_windows = [
        advanced_v3.HistoricalReferenceWindow(
            reference_id=f"eligible-day:{item.date.isoformat()}",
            period_end=item.date,
            # The store only passes admitted, immutable rows that predate the
            # current window.  Their observation date is a conservative lower
            # bound for availability and cannot leak current-period facts.
            available_at=item.date,
            operating_regime=(
                submission.comparison_context.operating_regime
                if submission.comparison_context is not None
                else "normal"
            ),
            baseline_eligible=True,
            totals=advanced_v3.TenQuantityTotals(**item.values()),
        )
        for item in history
    ]
    adapted = advanced_v3.TenQuantitySubmission(
        submission_id=submission.submission_id,
        mine_id=submission.mine_id,
        period_start=submission.period_start,
        period_end=submission.period_end,
        coverage_as_of=submission.period_end,
        operating_regime=(
            submission.comparison_context.operating_regime
            if submission.comparison_context is not None
            else "normal"
        ),
        days=days,
        applicability=advanced_v3.ModuleApplicability(
            raw_coal_balance=False,
            wash_balance=False,
            credential_chain=False,
        ),
    )
    return advanced_v3.analyze_ten_quantity(adapted, history=historical_windows)


def _legacy_signal_from_advanced(
    signal: advanced_v3.AnalysisSignal,
) -> AnalysisSignal:
    """Project an advanced signal without weakening its review priority."""

    if signal.priority in {
        advanced_v3.ReviewPriority.P1,
        advanced_v3.ReviewPriority.P2,
    }:
        severity = SignalSeverity.RISK
    elif signal.severity is advanced_v3.SignalSeverity.INFORMATION:
        severity = SignalSeverity.INFORMATION
    else:
        severity = SignalSeverity.REVIEW
    return AnalysisSignal(
        code=f"advanced_v3.{signal.code}",
        severity=severity,
        message=signal.message,
        date=signal.observed_date,
        metric=",".join(signal.affected_metrics) or None,
        observed=signal.observed,
        expected_lower=signal.expected_lower,
        expected_upper=signal.expected_upper,
        basis=(
            f"advanced_v3_{signal.layer.value}:"
            f"{signal.basis}"
        ),
    )


def analyze_five_quantity(
    submission: FiveQuantitySubmission,
    *,
    history: Sequence[HistoricalFiveQuantityDay] = (),
    peer_bands: Sequence[ReferenceBand] = (),
    parameters: RegulatoryFiveQuantityParameters | None = None,
) -> RegulatoryFiveQuantityResult:
    """Run the deterministic V3 engine, including its V2 compatibility branch.

    The function is pure: persistence, risk delivery and lifecycle transitions
    are owned by :mod:`mineguard.regulatory_v2_store`.
    """

    parameters = parameters or RegulatoryFiveQuantityParameters()
    applicable_metrics = submission.applicable_metrics
    applicable_relationships = submission.applicable_relationships
    legacy_scope = submission.quantity_scope == "five_quantity_v2"
    method_version = (
        LEGACY_METHOD_VERSION if legacy_scope else REGULATORY_V2_METHOD_VERSION
    )
    ordered_days = sorted(submission.days, key=lambda item: item.date)
    effective, observations, quality_signals, coverage = _prepare_days(
        submission, ordered_days, parameters
    )
    states = _operating_states(effective, parameters)
    quality_signals.extend(_declared_state_signals(ordered_days, states))

    accepted_history = _history_bands(
        history,
        applicable_relationships,
        parameters,
    )
    accepted_peers = [
        item
        for item in peer_bands
        if item.basis == "anonymous_peer"
        and item.mine_count is not None
        and item.mine_count >= parameters.minimum_peer_mines
        and item.sample_count >= parameters.minimum_reference_samples
        and submission.comparison_context is not None
        and item.comparison_group == submission.comparison_group
        and item.relationship in applicable_relationships
    ]
    within = _within_submission_bands(
        effective,
        states,
        applicable_relationships,
        parameters,
    )
    active_bands = [*accepted_history, *accepted_peers]
    # The current period is descriptive only: it must not prove itself normal
    # or let a late-month value alter an early-day reference.  Cold-start
    # reports can still be normal *candidates*, but formal baseline admission
    # requires a governed prior-history or frozen anonymous-peer anchor.

    reconciliation = _reconcile(
        effective,
        observations,
        states,
        active_bands,
        applicable_metrics,
        parameters,
    )
    relationship_signals = _relationship_signals(reconciliation, parameters)
    temporal_signals = _temporal_signals(
        effective,
        states,
        accepted_history,
        accepted_peers,
        applicable_relationships,
        parameters,
    )
    temporal_signals.extend(
        _past_only_detector_signals(
            submission,
            effective,
            states,
            history,
            applicable_relationships,
            parameters,
        )
    )
    temporal_signals = _deduplicate_signals(temporal_signals)

    advanced_result: advanced_v3.TenQuantityAnalysisResult | None = None
    if not legacy_scope:
        advanced_result = _run_advanced_v3_evidence_layer(submission, history)
        for advanced_signal in advanced_result.signals:
            projected = _legacy_signal_from_advanced(advanced_signal)
            if advanced_signal.layer is advanced_v3.EvidenceLayer.DETERMINISTIC:
                quality_signals.append(projected)
            elif advanced_signal.layer is advanced_v3.EvidenceLayer.HISTORICAL:
                temporal_signals.append(projected)
            else:
                relationship_signals.append(projected)
        quality_signals = _deduplicate_signals(quality_signals)
        relationship_signals = _deduplicate_signals(relationship_signals)
        temporal_signals = _deduplicate_signals(temporal_signals)

    insufficient_reasons: list[str] = []
    if coverage.complete_day_count < parameters.minimum_complete_days:
        insufficient_reasons.append(
            "完整十量日不足"
            if submission.quantity_scope == "ten_quantity_v3"
            else "完整五量日不足"
        )
    if coverage.completeness_ratio < parameters.minimum_completeness_ratio:
        insufficient_reasons.append("统计期数据覆盖率不足")
    if not reconciliation.success:
        insufficient_reasons.append("线性协调求解失败")
    if (
        advanced_result is not None
        and advanced_result.decision
        is advanced_v3.DecisionStatus.INSUFFICIENT_DATA
    ):
        insufficient_reasons.extend(
            f"高级十量证据层：{reason}"
            for reason in advanced_result.decision_reasons
            if f"高级十量证据层：{reason}" not in insufficient_reasons
        )

    risk_signals = [
        item
        for item in [
            *quality_signals,
            *relationship_signals,
            *temporal_signals,
        ]
        if item.severity is SignalSeverity.RISK
    ]
    if risk_signals:
        decision = DecisionStatus.RISK
        reasons = list(dict.fromkeys(item.message for item in risk_signals))[:20]
        reasons.extend(
            f"同时存在数据充分性问题：{item}" for item in insufficient_reasons
        )
    elif insufficient_reasons:
        decision = DecisionStatus.INSUFFICIENT_DATA
        reasons = insufficient_reasons
    else:
        decision = DecisionStatus.NORMAL_CANDIDATE
        reasons = ["未发现超过当前数据质量、时序及软参考区间的未解释线索"]

    algorithm_payload = {
        "mine_id": submission.mine_id,
        "contract_version": submission.contract_version,
        "quantity_scope": submission.quantity_scope,
        "period_start": submission.period_start,
        "period_end": submission.period_end,
        "comparison_context": submission.comparison_context,
        "days": ordered_days,
        "history": sorted(history, key=lambda item: item.date),
        "peer_bands": sorted(
            accepted_peers,
            key=lambda item: (item.relationship.value, item.lower, item.upper),
        ),
    }
    runtime_manifest = {
        "numpy_version": np.__version__,
        "scipy_version": SCIPY_VERSION,
        "solver_backend": "HiGHS via scipy.optimize.linprog",
        "aggregation_rule_version": (
            LEGACY_AGGREGATION_RULE_VERSION
            if legacy_scope
            else AGGREGATION_RULE_VERSION
        ),
        "baseline_admission_rule_version": (
            LEGACY_BASELINE_ADMISSION_RULE_VERSION
            if legacy_scope
            else BASELINE_ADMISSION_RULE_VERSION
        ),
        "business_quantity_group_version": (
            LEGACY_BUSINESS_QUANTITY_GROUP_VERSION
            if legacy_scope
            else BUSINESS_QUANTITY_GROUP_VERSION
        ),
        "quantity_scope": submission.quantity_scope,
        "relationship_semantics": "explicit_numerator_denominator_soft_bands",
    }
    if advanced_result is not None:
        runtime_manifest.update(
            {
                "advanced_evidence_method_version": advanced_result.method_version,
                "advanced_evidence_input_sha256": advanced_result.input_sha256,
                "advanced_evidence_configuration_sha256": (
                    advanced_result.configuration_sha256
                ),
                "advanced_evidence_decision": advanced_result.decision.value,
                "advanced_evidence_review_priority": (
                    advanced_result.review_priority.value
                ),
                "advanced_evidence_modules": json.dumps(
                    {
                        item.module: item.status.value
                        for item in advanced_result.modules
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "advanced_support_policy": (
                    "base_v3_exchange_has_no_auxiliary_inventory_wash_output_"
                    "or_credential_cohort_facts"
                ),
            }
        )
    return RegulatoryFiveQuantityResult(
        method_version=method_version,
        mine_id=submission.mine_id,
        submission_id=submission.submission_id,
        decision=decision,
        decision_reasons=reasons,
        data_sufficiency_reasons=insufficient_reasons,
        coverage=coverage,
        day_states=[
            DayState(date=observed_date, state=states[observed_date])
            for observed_date in sorted(states)
        ],
        data_quality_signals=quality_signals,
        temporal_signals=temporal_signals,
        relationship_signals=relationship_signals,
        references=ReferenceSummary(
            same_mine_history_day_count=len(history),
            accepted_history_bands=accepted_history,
            accepted_peer_bands=accepted_peers,
            within_submission_bands=within,
            peer_anonymity_minimum_mines=parameters.minimum_peer_mines,
        ),
        reconciliation=reconciliation,
        algorithm_input_sha256=_sha256(algorithm_payload),
        configuration_sha256=_sha256(
            {
                "method_version": method_version,
                "parameters": parameters,
                "runtime_manifest": runtime_manifest,
            }
        ),
        runtime_manifest=runtime_manifest,
    )


def _prepare_days(
    submission: FiveQuantitySubmission,
    days: Sequence[FiveQuantityDay],
    parameters: RegulatoryFiveQuantityParameters,
) -> tuple[
    dict[date, dict[str, float | None]],
    dict[date, list[_Observation]],
    list[AnalysisSignal],
    CoverageSummary,
]:
    effective: dict[date, dict[str, float | None]] = {}
    observations: dict[date, list[_Observation]] = defaultdict(list)
    signals: list[AnalysisSignal] = []
    complete_count = 0
    applicable_metrics = submission.applicable_metrics
    ten_quantity = submission.quantity_scope == "ten_quantity_v3"

    for day in days:
        values: dict[str, float | None] = {}
        day_quality_complete = True
        for metric, quantity in day.quantities(applicable_metrics).items():
            quality = day.quality.get(metric, ReportedQuality())
            flags = quality.all_flags
            if flags & {"partial", "source_format_warning"}:
                day_quality_complete = False
                signals.append(
                    AnalysisSignal(
                        code="qualified_measurement_requires_review",
                        severity=SignalSeverity.REVIEW,
                        message=(
                            f"{day.date.isoformat()} {METRIC_LABELS[metric]}"
                            "带有部分值或来源格式警告，"
                            "不能作为完整日证明"
                        ),
                        date=day.date,
                        metric=metric,
                        basis="wire_quality_flags",
                    )
                )
            elif flags & {"unit_converted", "corrected"}:
                signals.append(
                    AnalysisSignal(
                        code="measurement_transformation_disclosed",
                        severity=SignalSeverity.INFORMATION,
                        message=(
                            f"{day.date.isoformat()} {METRIC_LABELS[metric]}"
                            "已披露单位换算或更正"
                        ),
                        date=day.date,
                        metric=metric,
                        basis="wire_quality_flags",
                    )
                )
            if quantity is None:
                values[metric] = None
                continue
            shift_value, shift_aggregation = _shift_aggregate(day, metric, quantity)
            if (
                quantity.shifts is not None
                and 0 < quantity.shifts.provided_count < 3
                and (
                    metric not in COMMERCIAL_DAILY_METRICS
                    or quantity.daily_total is None
                )
            ):
                signals.append(
                    AnalysisSignal(
                        code="partial_shift_values",
                        severity=SignalSeverity.REVIEW,
                        message="班次值不完整，不能执行确定性班次汇总核对",
                        date=day.date,
                        metric=metric,
                        basis="deterministic_completeness_rule",
                    )
                )
            daily = (
                float(quantity.daily_total)
                if quantity.daily_total is not None
                else None
            )
            value = daily if daily is not None else shift_value
            values[metric] = value
            if daily is not None:
                tolerance = _observation_tolerance(daily, parameters)
                observations[day.date].append(
                    _Observation(
                        group=f"reported:{day.date.isoformat()}:{metric}",
                        metric=metric,
                        value=daily,
                        tolerance=tolerance,
                    )
                )
            if shift_value is not None:
                tolerance = _observation_tolerance(shift_value, parameters)
                observations[day.date].append(
                    _Observation(
                        group=f"shifts:{day.date.isoformat()}:{metric}",
                        metric=metric,
                        value=shift_value,
                        tolerance=tolerance,
                    )
                )
            comparable = shift_aggregation not in {
                "not_provided",
                "not_applicable",
                "mixed",
                "snapshot",
            } and quantity.daily_aggregation in {None, shift_aggregation}
            if (
                daily is not None
                and quantity.shifts is not None
                and not comparable
                and quantity.shifts.complete
            ):
                signals.append(
                    AnalysisSignal(
                        code="aggregation_semantics_not_comparable",
                        severity=SignalSeverity.REVIEW,
                        message=(
                            f"{day.date.isoformat()} {METRIC_LABELS[metric]}的日报与"
                            "班次聚合语义"
                            "不能直接互推，已保留原值但不执行错误加总"
                        ),
                        date=day.date,
                        metric=metric,
                        basis="governed_aggregation_semantics",
                    )
                )
            if daily is not None and shift_value is not None and comparable:
                allowed = max(
                    parameters.shift_absolute_tolerance,
                    parameters.shift_relative_tolerance
                    * max(abs(daily), abs(shift_value), 1.0),
                )
                difference = abs(daily - shift_value)
                if difference > allowed:
                    aggregation = (
                        "班次合计" if shift_aggregation == "sum" else "班次时长加权均值"
                    )
                    signals.append(
                        AnalysisSignal(
                            code="daily_shift_arithmetic_mismatch",
                            severity=SignalSeverity.RISK,
                            message=(
                                f"{day.date.isoformat()} {METRIC_LABELS[metric]}日报值"
                                f"与{aggregation}"
                                "不一致"
                            ),
                            date=day.date,
                            metric=metric,
                            observed=daily,
                            expected_lower=shift_value - allowed,
                            expected_upper=shift_value + allowed,
                            basis="deterministic_daily_shift_arithmetic",
                        )
                    )
        effective[day.date] = values
        # V3 completeness is the governed eleven-atom *daily* report.  The four
        # commercial quantities have no shift obligation, so their absent shift
        # values never reduce completeness.  V2 retains its original six-atom
        # effective-value rule, including governed shift aggregation fallback.
        complete_values = (
            all(
                (quantity := getattr(day, metric)) is not None
                and quantity.daily_total is not None
                for metric in applicable_metrics
            )
            if ten_quantity
            else all(values[metric] is not None for metric in applicable_metrics)
        )
        if day_quality_complete and complete_values:
            complete_count += 1

    expected = (submission.period_end - submission.period_start).days + 1
    reported_dates = set(effective)
    missing = expected - len(reported_dates)
    ratio = complete_count / expected
    if missing:
        signals.append(
            AnalysisSignal(
                code="missing_calendar_days",
                severity=SignalSeverity.REVIEW,
                message=f"统计期缺少 {missing} 个自然日记录",
                basis="calendar_coverage",
            )
        )
    incomplete = len(days) - complete_count
    if incomplete:
        quantity_name = "十量日报（11个原子指标）" if ten_quantity else "五量值"
        signals.append(
            AnalysisSignal(
                code=(
                    "incomplete_ten_quantity_days"
                    if ten_quantity
                    else "incomplete_five_quantity_days"
                ),
                severity=SignalSeverity.REVIEW,
                message=f"有 {incomplete} 个日期缺少可用的完整{quantity_name}",
                basis="required_metric_completeness",
            )
        )
    return (
        effective,
        observations,
        signals,
        CoverageSummary(
            expected_day_count=expected,
            reported_day_count=len(days),
            complete_day_count=complete_count,
            missing_calendar_day_count=max(0, missing),
            completeness_ratio=ratio,
        ),
    )


def _observation_tolerance(
    value: float, parameters: RegulatoryFiveQuantityParameters
) -> float:
    return max(
        parameters.observation_absolute_tolerance,
        abs(value) * parameters.observation_relative_tolerance,
    )


def _operating_states(
    effective: dict[date, dict[str, float | None]],
    parameters: RegulatoryFiveQuantityParameters,
) -> dict[date, OperatingState]:
    states: dict[date, OperatingState] = {}
    nonproduction_run = 0
    ramp_remaining = 0
    previous_date: date | None = None
    for observed_date in sorted(effective):
        if previous_date is not None and observed_date != previous_date + timedelta(
            days=1
        ):
            nonproduction_run = 0
            ramp_remaining = 0
        activity = _operating_activity_value(effective[observed_date], parameters)
        if activity is None:
            states[observed_date] = OperatingState.UNKNOWN
            nonproduction_run = 0
            ramp_remaining = 0
        elif activity <= parameters.production_epsilon_t:
            states[observed_date] = OperatingState.NON_PRODUCTION_CANDIDATE
            nonproduction_run += 1
            ramp_remaining = 0
        else:
            if nonproduction_run >= parameters.restart_prior_non_production_days:
                ramp_remaining = parameters.restart_ramp_days
            if ramp_remaining > 0:
                states[observed_date] = OperatingState.RESTART_RAMP_CANDIDATE
                ramp_remaining -= 1
            else:
                states[observed_date] = OperatingState.PRODUCTION
            nonproduction_run = 0
        previous_date = observed_date
    return states


def _operating_activity_value(
    values: dict[str, float | None],
    parameters: RegulatoryFiveQuantityParameters,
) -> float | None:
    """Infer activity from production and extraction without hiding either.

    Production remains the primary established signal.  A positive extraction
    value also establishes activity when production is absent or reported as
    zero, avoiding a false stopped-state classification for the V3 scope.
    """

    production = values.get("production_t")
    extraction = values.get("extraction_t")
    available = [float(item) for item in (production, extraction) if item is not None]
    if not available:
        return None
    positive = [item for item in available if item > parameters.production_epsilon_t]
    return max(positive) if positive else 0.0


def _declared_state_signals(
    days: Sequence[FiveQuantityDay],
    inferred: dict[date, OperatingState],
) -> list[AnalysisSignal]:
    expected = {
        "producing": OperatingState.PRODUCTION,
        "stopped": OperatingState.NON_PRODUCTION_CANDIDATE,
        "maintenance": OperatingState.NON_PRODUCTION_CANDIDATE,
        "restarting": OperatingState.RESTART_RAMP_CANDIDATE,
        "unknown": OperatingState.UNKNOWN,
    }
    signals: list[AnalysisSignal] = []
    for day in days:
        declared = day.declared_operating_state
        if declared is None or declared == "unknown":
            continue
        if inferred.get(day.date) is not expected[declared]:
            signals.append(
                AnalysisSignal(
                    code="declared_operating_state_mismatch",
                    severity=SignalSeverity.REVIEW,
                    message=(
                        f"{day.date.isoformat()} 企业申报工况与按产量/开采量序列"
                        "推断的工况不一致"
                    ),
                    date=day.date,
                    metric=(
                        "production_t,extraction_t"
                        if day.extraction_t is not None
                        else "production_t"
                    ),
                    basis="declared_vs_inferred_production_extraction_state",
                )
            )
    return signals


def _history_bands(
    history: Sequence[HistoricalFiveQuantityDay],
    relationships: Sequence[RelationshipCode],
    parameters: RegulatoryFiveQuantityParameters,
) -> list[ReferenceBand]:
    rows = [item.values() for item in history]
    return _bands_from_rows(
        rows,
        basis="same_mine_history",
        relationships=relationships,
        parameters=parameters,
    )


def _within_submission_bands(
    effective: dict[date, dict[str, float | None]],
    states: dict[date, OperatingState],
    relationships: Sequence[RelationshipCode],
    parameters: RegulatoryFiveQuantityParameters,
) -> list[ReferenceBand]:
    rows = [
        {metric: float(value) for metric, value in values.items() if value is not None}
        for observed_date, values in sorted(effective.items())
        if states[observed_date] is OperatingState.PRODUCTION
        and all(value is not None for value in values.values())
    ]
    return _bands_from_rows(
        rows,
        basis="within_submission",
        relationships=relationships,
        parameters=parameters,
    )


def _bands_from_rows(
    rows: Sequence[dict[str, float | None]],
    *,
    basis: Literal["same_mine_history", "within_submission"],
    relationships: Sequence[RelationshipCode],
    parameters: RegulatoryFiveQuantityParameters,
) -> list[ReferenceBand]:
    bands: list[ReferenceBand] = []
    for relationship in relationships:
        numerator, denominator = RELATIONSHIP_METRICS[relationship]
        ratios = [
            float(row[numerator]) / float(row[denominator])
            for row in rows
            if row.get(denominator) is not None
            and float(row[denominator]) > parameters.production_epsilon_t
            and row.get(numerator) is not None
        ]
        if len(ratios) < parameters.minimum_reference_samples:
            continue
        center = median(ratios)
        mad = median(abs(item - center) for item in ratios)
        robust_scale = 1.4826 * mad
        half_width = max(
            robust_scale * parameters.reference_robust_z,
            abs(center) * parameters.reference_minimum_relative_half_width,
            parameters.observation_absolute_tolerance,
        )
        bands.append(
            ReferenceBand(
                relationship=relationship,
                lower=max(0.0, center - half_width),
                center=center,
                upper=center + half_width,
                sample_count=len(ratios),
                basis=basis,
            )
        )
    return bands


def _reconcile(
    effective: dict[date, dict[str, float | None]],
    observations: dict[date, list[_Observation]],
    states: dict[date, OperatingState],
    bands: Sequence[ReferenceBand],
    metrics: Sequence[str],
    parameters: RegulatoryFiveQuantityParameters,
) -> ReconciliationSummary:
    adjustments: list[L1Adjustment] = []
    diagnostics: list[SoftConstraintDiagnostic] = []
    conflict_sets: list[MinimalConflictSet] = []
    objective_total = 0.0
    success = True
    solver_status: Literal[
        "optimal",
        "infeasible",
        "unbounded",
        "iteration_or_time_limit",
        "numerical_failure",
        "solver_error",
    ] = "optimal"
    solver_methods: list[str] = []
    solver_message: str | None = None
    mcs_search_complete = True
    examined = 0

    for observed_date in sorted(effective):
        day_observations = observations.get(observed_date, [])
        if not day_observations:
            continue
        day_relations = (
            [
                _Relation(
                    group=(
                        f"{band.basis}:{observed_date.isoformat()}:"
                        f"{band.relationship.value}"
                    ),
                    relationship=band.relationship,
                    numerator_metric=RELATIONSHIP_METRICS[band.relationship][0],
                    denominator_metric=RELATIONSHIP_METRICS[band.relationship][1],
                    band=band,
                )
                for band in bands
                if effective[observed_date].get(
                    RELATIONSHIP_METRICS[band.relationship][0]
                )
                is not None
                and effective[observed_date].get(
                    RELATIONSHIP_METRICS[band.relationship][1]
                )
                is not None
            ]
            if states[observed_date] is OperatingState.PRODUCTION
            else []
        )
        solved = _solve_day_l1(day_observations, day_relations, metrics, parameters)
        solver_methods.extend(solved.methods_attempted)
        if solved.status != "optimal" or solved.values is None:
            success = False
            if solver_status == "optimal":
                solver_status = solved.status
                solver_message = solved.message
            continue
        values = solved.values
        objective_total += float(solved.objective or 0.0)
        reported = effective[observed_date]
        for metric in metrics:
            if reported[metric] is None:
                continue
            observed = float(reported[metric])
            reconciled = values[metric]
            tolerance = _observation_tolerance(observed, parameters)
            absolute = abs(reconciled - observed)
            adjustments.append(
                L1Adjustment(
                    date=observed_date,
                    metric=metric,
                    reported_value=observed,
                    reconciled_value=_finite(reconciled),
                    absolute_adjustment=_finite(absolute),
                    normalized_adjustment=_finite(absolute / tolerance),
                    unit=METRIC_UNITS[metric],
                )
            )
        for relation, lower_slack, upper_slack in solved.relation_slacks:
            denominator = values[relation.denominator_metric]
            ratio = (
                values[relation.numerator_metric] / denominator
                if denominator > parameters.production_epsilon_t
                else None
            )
            diagnostics.append(
                SoftConstraintDiagnostic(
                    date=observed_date,
                    relationship=relation.relationship,
                    basis=relation.band.basis,
                    lower=relation.band.lower,
                    upper=relation.band.upper,
                    observed_ratio=_finite(ratio) if ratio is not None else None,
                    lower_slack=_finite(lower_slack),
                    upper_slack=_finite(upper_slack),
                )
            )

        if len(conflict_sets) < parameters.max_mcs:
            remaining_budget = parameters.max_mcs_search_combinations - examined
            candidates, used, complete = _day_mcs(
                observed_date,
                day_observations,
                day_relations,
                metrics,
                parameters,
                max(0, remaining_budget),
                parameters.max_mcs - len(conflict_sets),
            )
            examined += used
            conflict_sets.extend(candidates)
            mcs_search_complete = mcs_search_complete and complete
        elif day_relations:
            mcs_search_complete = False

    return ReconciliationSummary(
        success=success,
        solver_status=solver_status,
        solver_methods_attempted=list(dict.fromkeys(solver_methods)),
        solver_message=solver_message,
        objective_value=_finite(objective_total) if success else None,
        adjustments=adjustments,
        soft_constraint_diagnostics=diagnostics,
        minimal_conflict_sets=conflict_sets,
        mcs_search_complete=mcs_search_complete,
    )


def _solve_day_l1(
    observations: Sequence[_Observation],
    relations: Sequence[_Relation],
    metrics: Sequence[str],
    parameters: RegulatoryFiveQuantityParameters,
) -> _L1Solve:
    metric_count = len(metrics)
    observation_count = len(observations)
    relation_count = len(relations)
    positive_start = metric_count
    negative_start = positive_start + observation_count
    lower_slack_start = negative_start + observation_count
    upper_slack_start = lower_slack_start + relation_count
    variable_count = upper_slack_start + relation_count

    objective = np.zeros(variable_count)
    a_eq = np.zeros((observation_count, variable_count))
    b_eq = np.zeros(observation_count)
    metric_index = {metric: index for index, metric in enumerate(metrics)}
    for index, observation in enumerate(observations):
        weight = 1.0 / observation.tolerance
        objective[positive_start + index] = weight
        objective[negative_start + index] = weight
        a_eq[index, metric_index[observation.metric]] = 1.0
        a_eq[index, positive_start + index] = -1.0
        a_eq[index, negative_start + index] = 1.0
        b_eq[index] = observation.value

    a_ub = np.zeros((relation_count * 2, variable_count))
    b_ub = np.zeros(relation_count * 2)
    for index, relation in enumerate(relations):
        numerator = metric_index[relation.numerator_metric]
        denominator = metric_index[relation.denominator_metric]
        lower_row = index * 2
        upper_row = lower_row + 1
        # lower*D - N <= paid lower slack
        a_ub[lower_row, denominator] = relation.band.lower
        a_ub[lower_row, numerator] = -1.0
        a_ub[lower_row, lower_slack_start + index] = -1.0
        # N - upper*D <= paid upper slack
        a_ub[upper_row, numerator] = 1.0
        a_ub[upper_row, denominator] = -relation.band.upper
        a_ub[upper_row, upper_slack_start + index] = -1.0
        reference_scale = max(
            abs(
                relation.band.center
                * median(
                    [
                        item.value
                        for item in observations
                        if item.metric == relation.denominator_metric
                    ]
                    or [1.0]
                )
            ),
            parameters.observation_absolute_tolerance,
        )
        coefficient = parameters.relationship_slack_penalty / reference_scale
        objective[lower_slack_start + index] = coefficient
        objective[upper_slack_start + index] = coefficient

    result, status, methods, message = _run_linprog_with_fallback(
        objective,
        A_ub=a_ub if len(a_ub) else None,
        b_ub=b_ub if len(b_ub) else None,
        A_eq=a_eq,
        b_eq=b_eq,
        bounds=[(0.0, None)] * variable_count,
    )
    if status != "optimal" or result is None or result.x is None or result.fun is None:
        return _L1Solve(
            values=None,
            objective=None,
            relation_slacks=[],
            status=status,
            methods_attempted=methods,
            message=message,
        )
    values = {metric: _finite(result.x[index]) for index, metric in enumerate(metrics)}
    slacks = [
        (
            relation,
            float(result.x[lower_slack_start + index]),
            float(result.x[upper_slack_start + index]),
        )
        for index, relation in enumerate(relations)
    ]
    return _L1Solve(
        values=values,
        objective=float(result.fun),
        relation_slacks=slacks,
        status="optimal",
        methods_attempted=methods,
        message=message,
    )


def _run_linprog_with_fallback(
    objective: np.ndarray,
    **kwargs: Any,
) -> tuple[
    Any | None,
    Literal[
        "optimal",
        "infeasible",
        "unbounded",
        "iteration_or_time_limit",
        "numerical_failure",
        "solver_error",
    ],
    tuple[str, ...],
    str | None,
]:
    """Run HiGHS with explicit fallback and preserve failure semantics."""

    methods: list[str] = []
    last_result: Any | None = None
    last_status: Literal[
        "optimal",
        "infeasible",
        "unbounded",
        "iteration_or_time_limit",
        "numerical_failure",
        "solver_error",
    ] = "solver_error"
    last_message: str | None = None
    for method in ("highs", "highs-ds", "highs-ipm"):
        methods.append(method)
        try:
            result = linprog(objective, method=method, **kwargs)
        except Exception as error:  # defensive native-solver boundary
            last_result = None
            last_status = "solver_error"
            last_message = f"{type(error).__name__}: {error}"[:500]
            continue
        last_result = result
        last_message = str(getattr(result, "message", ""))[:500] or None
        status_code = int(getattr(result, "status", 4))
        status_map: dict[
            int,
            Literal[
                "optimal",
                "infeasible",
                "unbounded",
                "iteration_or_time_limit",
                "numerical_failure",
                "solver_error",
            ],
        ] = {
            0: "optimal",
            1: "iteration_or_time_limit",
            2: "infeasible",
            3: "unbounded",
            4: "numerical_failure",
        }
        last_status = status_map.get(status_code, "solver_error")
        if last_status == "optimal" and bool(getattr(result, "success", False)):
            return result, "optimal", tuple(methods), last_message
        if last_status in {"infeasible", "unbounded"}:
            break
    return last_result, last_status, tuple(methods), last_message


def _day_mcs(
    observed_date: date,
    observations: Sequence[_Observation],
    relations: Sequence[_Relation],
    metrics: Sequence[str],
    parameters: RegulatoryFiveQuantityParameters,
    search_budget: int,
    result_limit: int,
) -> tuple[list[MinimalConflictSet], int, bool]:
    groups = sorted(
        {item.group for item in observations} | {item.group for item in relations}
    )
    examined = 1
    initial = _strict_day_feasible(
        observations, relations, metrics, relaxed=frozenset()
    )
    if initial == "feasible":
        return [], examined, True
    if initial == "indeterminate":
        return [], examined, False
    found: list[MinimalConflictSet] = []
    complete = True
    for cardinality in range(1, parameters.max_mcs_cardinality + 1):
        cardinality_found: list[MinimalConflictSet] = []
        for relaxed_tuple in combinations(groups, cardinality):
            if examined >= search_budget:
                complete = False
                break
            examined += 1
            feasibility = _strict_day_feasible(
                observations,
                relations,
                metrics,
                relaxed=frozenset(relaxed_tuple),
            )
            if feasibility == "indeterminate":
                complete = False
                break
            if feasibility == "feasible":
                cardinality_found.append(
                    MinimalConflictSet(
                        date=observed_date,
                        relaxed_groups=list(relaxed_tuple),
                        cardinality=cardinality,
                    )
                )
                if len(cardinality_found) >= result_limit:
                    # Other same-cardinality alternatives may exist.
                    complete = False
                    break
        if cardinality_found:
            found.extend(cardinality_found[:result_limit])
            break
        if not complete:
            break
    return found, examined, complete


def _strict_day_feasible(
    observations: Sequence[_Observation],
    relations: Sequence[_Relation],
    metrics: Sequence[str],
    *,
    relaxed: frozenset[str],
) -> Literal["feasible", "infeasible", "indeterminate"]:
    metric_index = {metric: index for index, metric in enumerate(metrics)}
    rows: list[np.ndarray] = []
    bounds: list[float] = []
    for observation in observations:
        if observation.group in relaxed:
            continue
        index = metric_index[observation.metric]
        upper = np.zeros(len(metrics))
        upper[index] = 1.0
        rows.append(upper)
        bounds.append(observation.value + observation.tolerance)
        lower = np.zeros(len(metrics))
        lower[index] = -1.0
        rows.append(lower)
        bounds.append(-(max(0.0, observation.value - observation.tolerance)))
    for relation in relations:
        if relation.group in relaxed:
            continue
        numerator = metric_index[relation.numerator_metric]
        denominator = metric_index[relation.denominator_metric]
        lower = np.zeros(len(metrics))
        lower[denominator] = relation.band.lower
        lower[numerator] = -1.0
        rows.append(lower)
        bounds.append(0.0)
        upper = np.zeros(len(metrics))
        upper[numerator] = 1.0
        upper[denominator] = -relation.band.upper
        rows.append(upper)
        bounds.append(0.0)
    result, status, _, _ = _run_linprog_with_fallback(
        np.zeros(len(metrics)),
        A_ub=np.asarray(rows) if rows else None,
        b_ub=np.asarray(bounds) if bounds else None,
        bounds=[(0.0, None)] * len(metrics),
    )
    if status == "optimal" and result is not None:
        return "feasible"
    if status == "infeasible":
        return "infeasible"
    return "indeterminate"


def _relationship_signals(
    reconciliation: ReconciliationSummary,
    parameters: RegulatoryFiveQuantityParameters,
) -> list[AnalysisSignal]:
    signals: list[AnalysisSignal] = []
    for item in reconciliation.soft_constraint_diagnostics:
        if item.lower_slack <= 1e-8 and item.upper_slack <= 1e-8:
            continue
        signals.append(
            AnalysisSignal(
                code="soft_reference_interval_exceeded",
                severity=SignalSeverity.RISK,
                message=(
                    f"{item.date.isoformat()} {RELATIONSHIP_LABELS[item.relationship]}超出"
                    f"{item.basis}软参考区间"
                ),
                date=item.date,
                metric=item.relationship.value,
                observed=item.observed_ratio,
                expected_lower=item.lower,
                expected_upper=item.upper,
                basis=f"weighted_l1:{item.basis}",
            )
        )
    for adjustment in reconciliation.adjustments:
        if (
            adjustment.normalized_adjustment
            <= parameters.normalized_adjustment_risk_threshold
        ):
            continue
        signals.append(
            AnalysisSignal(
                code="large_l1_reconciliation_adjustment",
                severity=SignalSeverity.RISK,
                message=(
                    f"{adjustment.date.isoformat()} "
                    f"{METRIC_LABELS.get(adjustment.metric, adjustment.metric)}需要较大"
                    "L1协调调整才能与其余证据相容"
                ),
                date=adjustment.date,
                metric=adjustment.metric,
                observed=adjustment.reported_value,
                basis="weighted_l1_minimum_adjustment",
            )
        )
    for conflict in reconciliation.minimal_conflict_sets:
        signals.append(
            AnalysisSignal(
                code="strict_counterfactual_conflict_set",
                severity=SignalSeverity.RISK,
                message=(
                    f"{conflict.date.isoformat()} 的日报、班次或软参考带无法在"
                    "各自容差内同时成立，已给出最小放宽组合"
                ),
                date=conflict.date,
                basis="strict_profile_mcs_diagnostic_not_causation",
            )
        )
    return _deduplicate_signals(signals)


def _temporal_signals(
    effective: dict[date, dict[str, float | None]],
    states: dict[date, OperatingState],
    history_bands: Sequence[ReferenceBand],
    peer_bands: Sequence[ReferenceBand],
    relationships: Sequence[RelationshipCode],
    parameters: RegulatoryFiveQuantityParameters,
) -> list[AnalysisSignal]:
    series: dict[RelationshipCode, list[tuple[date, float]]] = defaultdict(list)
    activity_series: list[tuple[date, float]] = []
    has_extraction_scope = any(
        "extraction_t" in values for values in effective.values()
    )
    for observed_date, values in sorted(effective.items()):
        activity = _operating_activity_value(values, parameters)
        if states[observed_date] is OperatingState.PRODUCTION:
            if activity is not None:
                activity_series.append((observed_date, activity))
        if states[observed_date] is not OperatingState.PRODUCTION:
            continue
        for relationship in relationships:
            numerator, denominator = RELATIONSHIP_METRICS[relationship]
            numerator_value = values.get(numerator)
            denominator_value = values.get(denominator)
            if (
                numerator_value is not None
                and denominator_value is not None
                and denominator_value > parameters.production_epsilon_t
            ):
                series[relationship].append(
                    (observed_date, float(numerator_value) / float(denominator_value))
                )

    signals: list[AnalysisSignal] = []
    for observed_date, state in sorted(states.items()):
        if state is not OperatingState.NON_PRODUCTION_CANDIDATE:
            continue
        values = effective[observed_date]
        explosives = float(values.get("explosives_kg") or 0.0)
        detonators = float(values.get("detonators_count") or 0.0)
        zero_basis = "产量及开采量" if has_extraction_scope else "产量"
        if detonators > 0.0:
            signals.append(
                AnalysisSignal(
                    code="detonators_during_nonproduction_candidate",
                    severity=SignalSeverity.RISK,
                    message=(
                        f"{observed_date.isoformat()} {zero_basis}为零但使用雷管 "
                        f"{detonators:g} 枚，需结合掘进、检修或统计边界说明"
                    ),
                    date=observed_date,
                    metric="detonators_count",
                    observed=detonators,
                    basis="state_aware_context_rule_not_physical_violation",
                )
            )
        if explosives > 0.0:
            signals.append(
                AnalysisSignal(
                    code="explosives_during_nonproduction_candidate",
                    severity=SignalSeverity.RISK,
                    message=(
                        f"{observed_date.isoformat()} {zero_basis}为零但使用炸药 "
                        f"{explosives:g} 千克，需结合掘进、检修或统计边界说明"
                    ),
                    date=observed_date,
                    metric="explosives_kg",
                    observed=explosives,
                    basis="state_aware_context_rule_not_physical_violation",
                )
            )
    preferred: dict[RelationshipCode, ReferenceBand] = {}
    for collection in (history_bands, peer_bands):
        for band in collection:
            preferred.setdefault(band.relationship, band)

    for relationship, values in series.items():
        band = preferred.get(relationship)
        if band is not None:
            for observed_date, value in values:
                if value < band.lower or value > band.upper:
                    signals.append(
                        AnalysisSignal(
                            code="robust_temporal_outlier",
                            severity=SignalSeverity.RISK,
                            message=(
                                f"{observed_date.isoformat()} "
                                f"{RELATIONSHIP_LABELS[relationship]}"
                                f"偏离{band.basis}稳健基线"
                            ),
                            date=observed_date,
                            metric=relationship.value,
                            observed=value,
                            expected_lower=band.lower,
                            expected_upper=band.upper,
                            basis=f"median_mad:{band.basis}",
                        )
                    )
        if len(values) >= 10:
            numeric = [item[1] for item in values]
            middle = len(numeric) // 2
            early, late = median(numeric[:middle]), median(numeric[middle:])
            relative = (late - early) / max(abs(early), 1e-9)
            if abs(relative) >= parameters.drift_minimum_relative_change:
                signals.append(
                    AnalysisSignal(
                        code="sustained_ratio_drift",
                        severity=SignalSeverity.RISK,
                        message=(
                            f"{RELATIONSHIP_LABELS[relationship]}统计期后半段相对"
                            "前半段持续"
                            f"变化 {relative:.1%}"
                        ),
                        date=values[middle][0],
                        metric=relationship.value,
                        observed=late,
                        expected_lower=early,
                        expected_upper=early,
                        basis="robust_half_window_median_drift",
                    )
                )
        change = _change_point(values, parameters)
        if change is not None:
            signals.append(
                AnalysisSignal(
                    code="retrospective_change_point",
                    severity=SignalSeverity.RISK,
                    message=(
                        f"{RELATIONSHIP_LABELS[relationship]}自 "
                        f"{change[0].isoformat()} 起出现"
                        f"水平变化候选（{change[1]:.1%}）"
                    ),
                    date=change[0],
                    metric=relationship.value,
                    observed=change[3],
                    expected_lower=change[2],
                    expected_upper=change[2],
                    basis="sse_bic_step_vs_linear",
                )
            )

    activity_change = _change_point(activity_series, parameters)
    if activity_change is not None:
        activity_name = "产量/开采量工况序列" if has_extraction_scope else "产量"
        signals.append(
            AnalysisSignal(
                code=(
                    "production_extraction_change_point_context"
                    if has_extraction_scope
                    else "production_change_point_context"
                ),
                severity=SignalSeverity.REVIEW,
                message=(
                    f"{activity_name}自 {activity_change[0].isoformat()} 起出现"
                    "水平变化候选；"
                    "需结合停复产和生产组织解释"
                ),
                date=activity_change[0],
                metric=(
                    "production_t,extraction_t"
                    if has_extraction_scope
                    else "production_t"
                ),
                observed=activity_change[3],
                expected_lower=activity_change[2],
                expected_upper=activity_change[2],
                basis="sse_bic_step_vs_linear",
            )
        )
    return _deduplicate_signals(signals)


def _past_only_detector_signals(
    submission: FiveQuantitySubmission,
    effective: dict[date, dict[str, float | None]],
    states: dict[date, OperatingState],
    history: Sequence[HistoricalFiveQuantityDay],
    relationships: Sequence[RelationshipCode],
    parameters: RegulatoryFiveQuantityParameters,
) -> list[AnalysisSignal]:
    """Run the established past-only rolling/EWMA/CUSUM/Page-Hinkley suite.

    Eligible governed history is warm-up only.  Points in the current report
    are evaluated in date order and a point can never use a later point.  The
    detector remains an internal module of this sole public regulatory engine.
    """

    observations: list[TemporalObservation] = []
    source_id = f"governed-{submission.quantity_scope}-history"
    history_by_date = {
        item.date: item.values()
        for item in history
        if item.date < submission.period_start
    }
    history_rows = sorted(history_by_date.items())
    current_rows = [
        (observed_date, values)
        for observed_date, values in sorted(effective.items())
        if states[observed_date] is OperatingState.PRODUCTION
    ]
    for relationship in relationships:
        numerator, denominator = RELATIONSHIP_METRICS[relationship]
        series_rows = [*history_rows, *current_rows]
        current_count = 0
        for observed_date, values in series_rows:
            denominator_value = values.get(denominator)
            numerator_value = values.get(numerator)
            if (
                denominator_value is None
                or numerator_value is None
                or float(denominator_value) <= parameters.production_epsilon_t
            ):
                continue
            if observed_date >= submission.period_start:
                current_count += 1
            observations.append(
                TemporalObservation(
                    mine_id=submission.mine_id,
                    source_id=source_id,
                    metric_code=relationship.value,
                    timestamp=datetime.combine(
                        observed_date,
                        datetime.min.time(),
                        tzinfo=UTC,
                    ),
                    value=float(numerator_value) / float(denominator_value),
                    quality=1.0,
                    baseline_eligible=True,
                )
            )
        if current_count == 0:
            observations = [
                item for item in observations if item.metric_code != relationship.value
            ]
    if not observations:
        return []

    detector = detect_temporal_anomalies(
        TemporalDetectionRequest(
            observations=observations,
            parameters=TemporalDetectionParameters(
                baseline_window=parameters.temporal_baseline_window,
                min_history=parameters.temporal_min_history,
                minimum_relative_scale=parameters.temporal_minimum_relative_scale,
                mad_z_threshold=parameters.temporal_mad_z_threshold,
                ewma_alpha=parameters.temporal_ewma_alpha,
                ewma_z_threshold=parameters.temporal_ewma_z_threshold,
                cusum_drift=parameters.temporal_cusum_drift,
                cusum_threshold=parameters.temporal_cusum_threshold,
                page_hinkley_delta=parameters.temporal_page_hinkley_delta,
                page_hinkley_threshold=parameters.temporal_page_hinkley_threshold,
                exclude_detected_anomalies_from_baseline=True,
            ),
            report_start=datetime.combine(
                submission.period_start,
                datetime.min.time(),
                tzinfo=UTC,
            ),
            report_end=datetime.combine(
                submission.period_end + timedelta(days=1),
                datetime.min.time(),
                tzinfo=UTC,
            ),
        )
    )
    source_health = {
        TemporalDetectorCode.SOURCE_MISSING,
        TemporalDetectorCode.SOURCE_LATENCY,
        TemporalDetectorCode.SOURCE_REVISION,
        TemporalDetectorCode.SOURCE_LOW_QUALITY,
    }
    signals: list[AnalysisSignal] = []
    for series in detector.series:
        for point in series.points:
            for item in point.signals:
                severity = (
                    SignalSeverity.REVIEW
                    if item.detector in source_health
                    else SignalSeverity.RISK
                )
                signals.append(
                    AnalysisSignal(
                        code=f"past_only_{item.detector.value}",
                        severity=severity,
                        message=(
                            f"{point.timestamp.date().isoformat()} "
                            f"{RELATIONSHIP_LABELS[RelationshipCode(series.metric_code)]}："
                            f"{item.explanation}"
                        ),
                        date=point.timestamp.date(),
                        metric=series.metric_code,
                        observed=point.observed_value,
                        basis=(
                            "past_only_temporal_detector:"
                            f"{item.detector.value}:no_future_points"
                        ),
                    )
                )
    return _deduplicate_signals(signals)


def _change_point(
    series: Sequence[tuple[date, float]],
    parameters: RegulatoryFiveQuantityParameters,
) -> tuple[date, float, float, float] | None:
    if len(series) < 14:
        return None
    values = [item[1] for item in series]
    overall = fmean(values)
    total_sse = math.fsum((item - overall) ** 2 for item in values)
    if total_sse <= 1e-12:
        return None
    minimum_segment = max(5, len(values) // 4)
    candidates: list[tuple[float, float, int, float, float]] = []
    for split in range(minimum_segment, len(values) - minimum_segment + 1):
        left, right = values[:split], values[split:]
        left_mean, right_mean = fmean(left), fmean(right)
        within = math.fsum((item - left_mean) ** 2 for item in left)
        within += math.fsum((item - right_mean) ** 2 for item in right)
        explained = max(0.0, 1.0 - within / total_sse)
        candidates.append((within, explained, split, left_mean, right_mean))
    if not candidates:
        return None
    step_sse, explained, split, left_mean, right_mean = min(candidates)
    relative = (right_mean - left_mean) / max(abs(left_mean), 1e-9)
    linear_sse = _linear_sse(values)
    if (
        explained < parameters.change_point_minimum_explained_fraction
        or abs(relative) < parameters.change_point_minimum_relative_shift
        or _bic(step_sse, len(values), 3, total_sse)
        + parameters.change_point_bic_margin
        >= _bic(linear_sse, len(values), 2, total_sse)
    ):
        return None
    return series[split][0], relative, left_mean, right_mean


def _linear_sse(values: Sequence[float]) -> float:
    count = len(values)
    x_mean = (count - 1) / 2.0
    y_mean = fmean(values)
    denominator = math.fsum((index - x_mean) ** 2 for index in range(count))
    if denominator <= 0.0:
        return math.fsum((item - y_mean) ** 2 for item in values)
    slope = (
        math.fsum(
            (index - x_mean) * (item - y_mean) for index, item in enumerate(values)
        )
        / denominator
    )
    intercept = y_mean - slope * x_mean
    return math.fsum(
        (item - (intercept + slope * index)) ** 2 for index, item in enumerate(values)
    )


def _bic(sse: float, count: int, parameter_count: int, reference: float) -> float:
    floor = max(reference, 1.0) * 1e-12
    return count * math.log(max(sse, floor) / count) + parameter_count * math.log(count)


def _deduplicate_signals(signals: Iterable[AnalysisSignal]) -> list[AnalysisSignal]:
    unique: dict[tuple[str, date | None, str | None, str], AnalysisSignal] = {}
    for signal in signals:
        unique.setdefault(
            (signal.code, signal.date, signal.metric, signal.basis), signal
        )
    return sorted(
        unique.values(),
        key=lambda item: (
            item.date or date.min,
            item.severity.value,
            item.code,
            item.metric or "",
        ),
    )


def _finite(value: float) -> float:
    return 0.0 if abs(value) < 1e-9 else float(value)


def _json_default(value: object) -> object:
    if isinstance(value, StrictModel):
        return value.model_dump(mode="json")
    if isinstance(value, (date, StrEnum)):
        return value.isoformat() if isinstance(value, date) else value.value
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def _sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "AcquisitionMode",
    "AnalysisSignal",
    "ComparisonContext",
    "DecisionStatus",
    "FIVE_QUANTITY_GROUPS",
    "FiveQuantityDay",
    "FiveQuantitySubmission",
    "HistoricalFiveQuantityDay",
    "LEGACY_METRICS",
    "METRICS",
    "OperatingState",
    "ReferenceBand",
    "RegulatoryFiveQuantityParameters",
    "RegulatoryFiveQuantityResult",
    "RelationshipCode",
    "ReportedQuantity",
    "SHIFT_REQUIRED_METRICS",
    "ShiftValues",
    "SubmissionProvenance",
    "TEN_QUANTITY_GROUPS",
    "analyze_five_quantity",
    "applicable_metrics_for_scope",
    "applicable_relationships_for_scope",
    "shift_required_metrics_for_scope",
]
