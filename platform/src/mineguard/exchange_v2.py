"""Platform-owned implementation of the neutral five-quantity V2 wire contract.

The enterprise product implements the same files independently.  This module
never imports executable code from ``agent/`` or ``contracts/``; conformance is
checked with neutral JSON Schema fixtures instead.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta, timezone as fixed_timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Annotated, Any, Iterable, Literal, Mapping
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BeforeValidator,
    ConfigDict,
    Field,
    PrivateAttr,
    model_validator,
)

from .external_submission import jcs_canonical_json
from .models import StrictModel
from .regulatory_v2 import (
    AcquisitionMode,
    ComparisonContext,
    FiveQuantityDay,
    FiveQuantitySubmission,
    METRICS,
    ReportedQuality,
    ReportedQuantity,
    ShiftMetadata,
    ShiftValues,
    ShiftWindowMetadata,
    SubmissionProvenance,
)
from .regulatory_v2_store import (
    AnalysisReportDeliveryAck,
    EnterpriseFindingResponse,
    EvidenceReference,
)


EXCHANGE_SIGNATURE_VERSION = "hmac-sha256-v2"
EXCHANGE_CANONICALIZATION = "rfc8785-jcs"
EXCHANGE_SIGNATURE_CONTEXT = "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HMAC-SHA256-V2"
EXCHANGE_TRANSPORT_CONTEXT = "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V2"
EXCHANGE_AUTH_WINDOW_SECONDS = 300
EXCHANGE_NONCE_RETENTION_SECONDS = 600
EXCHANGE_CLIENTS_FILE_MAX_BYTES = 4 * 1024 * 1024

SENDER_ID_HEADER = "X-Exchange-Sender-Id"
TIMESTAMP_HEADER = "X-Exchange-Timestamp"
NONCE_HEADER = "X-Exchange-Nonce"
CONTENT_SHA256_HEADER = "X-Exchange-Content-SHA256"
CONTRACT_VERSION_HEADER = "X-Exchange-Contract-Version"
SIGNATURE_VERSION_HEADER = "X-Exchange-Signature-Version"
SIGNATURE_HEADER = "X-Exchange-Signature"
SIGNED_HEADERS = (
    SENDER_ID_HEADER,
    TIMESTAMP_HEADER,
    NONCE_HEADER,
    CONTENT_SHA256_HEADER,
    CONTRACT_VERSION_HEADER,
    SIGNATURE_VERSION_HEADER,
    SIGNATURE_HEADER,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MONTH = re.compile(r"^[0-9]{4}-(?:0[1-9]|1[0-2])$")
_CONTRACT = re.compile(r"^[a-z][a-z0-9-]*-v2$")
_TIMEZONE = re.compile(
    r"^(?:UTC|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9]|"
    r"[A-Za-z][A-Za-z0-9._+-]*(?:/[A-Za-z0-9._+-]+)+)$"
)
_MISSING_FLAGS = frozenset({"missing", "unavailable", "not_applicable"})

MetricCode = Literal[
    "ventilation_m3_min",
    "electricity_kwh",
    "detonators_count",
    "explosives_kg",
    "mine_entry_persons",
    "production_t",
]
QualityFlag = Literal[
    "reported",
    "missing",
    "unavailable",
    "not_applicable",
    "partial",
    "unit_converted",
    "corrected",
    "source_format_warning",
]
OperatingState = Literal[
    "producing",
    "stopped",
    "maintenance",
    "restarting",
    "unknown",
]


def _canonical_uuid(value: str, field_name: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must be a UUID") from error
    if str(parsed) != value.lower():
        raise ValueError(f"{field_name} must use canonical UUID syntax")
    return value.lower()


def _uuid_text(value: str) -> str:
    return _canonical_uuid(value, "value")


def _json_string(value: Any) -> Any:
    if not isinstance(value, str):
        raise ValueError("wire date/time values must be JSON strings")
    return value


def _json_boolean(value: Any) -> Any:
    if type(value) is not bool:
        raise ValueError("wire boolean values must be JSON booleans")
    return value


def _json_integer(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("wire integer values must be JSON integers")
    return value


def _json_number_or_none(value: Any) -> Any:
    if value is not None and (
        isinstance(value, bool) or not isinstance(value, (int, float))
    ):
        raise ValueError("measurement values must be JSON numbers or null")
    return value


def _timezone_text(value: str) -> str:
    if _TIMEZONE.fullmatch(value) is None:
        raise ValueError("timezone does not match the V2 contract")
    if value == "UTC" or value.startswith(("+", "-")):
        return value
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError as error:
        raise ValueError("timezone is not a known IANA timezone") from error
    return value


def _timezone_info(value: str) -> ZoneInfo | fixed_timezone:
    if value == "UTC":
        return fixed_timezone.utc
    if value.startswith(("+", "-")):
        sign = 1 if value[0] == "+" else -1
        hours, minutes = (int(item) for item in value[1:].split(":"))
        return fixed_timezone(sign * timedelta(hours=hours, minutes=minutes))
    return ZoneInfo(value)


Identifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
CanonicalUUID = Annotated[
    str,
    Field(min_length=36, max_length=36),
    AfterValidator(_uuid_text),
]
TimezoneText = Annotated[
    str,
    Field(min_length=1, max_length=64),
    AfterValidator(_timezone_text),
]
WireDate = Annotated[date, BeforeValidator(_json_string)]
WireDateTime = Annotated[AwareDatetime, BeforeValidator(_json_string)]
WireBoolean = Annotated[bool, BeforeValidator(_json_boolean)]
WireTrue = Annotated[Literal[True], BeforeValidator(_json_boolean)]
WireOne = Annotated[Literal[1], BeforeValidator(_json_integer)]
WireSafePositiveInteger = Annotated[
    int,
    BeforeValidator(_json_integer),
    Field(ge=1, le=9_007_199_254_740_991),
]
WireMeasurementValue = Annotated[
    Annotated[float, Field(ge=0.0, le=1e15)] | None,
    BeforeValidator(_json_number_or_none),
]


class WireContractModel(StrictModel):
    """Wire values are validated as sent; no implicit string trimming."""

    model_config = ConfigDict(
        extra="forbid",
        allow_inf_nan=False,
        str_strip_whitespace=False,
    )


class ExchangeParticipant(WireContractModel):
    system_id: Identifier
    party_id: Identifier
    role: Literal["enterprise_agent", "regulatory_platform"]


class ExchangePredecessor(WireContractModel):
    message_id: CanonicalUUID
    payload_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ExchangeSignatureEnvelope(WireContractModel):
    algorithm: Literal["hmac-sha256-v2"] = "hmac-sha256-v2"
    canonicalization: Literal["rfc8785-jcs"] = "rfc8785-jcs"
    key_id: Identifier
    signed_at: WireDateTime
    nonce: Annotated[
        str,
        Field(min_length=22, max_length=86, pattern=r"^[A-Za-z0-9_-]+$"),
    ]
    payload_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class ExchangeMessageBase(WireContractModel):
    contract_version: Annotated[
        str,
        Field(pattern=r"^[a-z][a-z0-9-]*-v2$"),
    ]
    message_type: str
    message_id: CanonicalUUID
    correlation_id: CanonicalUUID
    causation_id: CanonicalUUID | None
    idempotency_key: Annotated[
        str,
        Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"),
    ]
    revision: WireSafePositiveInteger
    predecessor: ExchangePredecessor | None
    created_at: WireDateTime
    sender: ExchangeParticipant
    recipient: ExchangeParticipant
    mine_id: Identifier
    signature_envelope: ExchangeSignatureEnvelope
    _wire_document: dict[str, Any] | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def validate_envelope(self) -> "ExchangeMessageBase":
        if self.revision == 1 and self.predecessor is not None:
            raise ValueError("revision 1 cannot declare a predecessor")
        if self.revision > 1 and self.predecessor is None:
            raise ValueError("later revisions require a predecessor")
        if self.sender.role == self.recipient.role:
            raise ValueError("sender and recipient roles must differ")
        if self.signature_envelope.signed_at < self.created_at:
            raise ValueError("signature cannot predate message creation")
        return self


class WireMine(WireContractModel):
    mine_id: Identifier
    mine_name: Annotated[str, Field(min_length=1, max_length=256)]
    operator_id: Identifier
    operator_name: Annotated[str, Field(min_length=1, max_length=256)]
    unified_social_credit_code: Annotated[
        str | None,
        Field(pattern=r"^[0-9A-HJ-NPQRTUWXY]{18}$"),
    ] = None

    @model_validator(mode="after")
    def reject_explicit_null_credit_code(self) -> "WireMine":
        if (
            "unified_social_credit_code" in self.model_fields_set
            and self.unified_social_credit_code is None
        ):
            raise ValueError("unified_social_credit_code cannot be null")
        return self


class WireMeasurement(WireContractModel):
    metric_code: MetricCode
    value: WireMeasurementValue
    unit: Literal["m3/min", "person", "kWh", "count", "kg", "t"]
    aggregation: Literal["time_weighted_average", "sum", "snapshot"]
    quality_flags: Annotated[
        list[QualityFlag],
        Field(min_length=1, max_length=8),
    ]
    source_refs: Annotated[
        list[Identifier],
        Field(min_length=1, max_length=16),
    ]

    @model_validator(mode="after")
    def validate_value_and_flags(self) -> "WireMeasurement":
        if len(self.quality_flags) != len(set(self.quality_flags)):
            raise ValueError("quality_flags values must be unique")
        if len(self.source_refs) != len(set(self.source_refs)):
            raise ValueError("source_refs values must be unique")
        missing = bool(set(self.quality_flags) & _MISSING_FLAGS)
        if self.value is None and not missing:
            raise ValueError("null measurement requires a missing quality flag")
        if self.value is not None and missing:
            raise ValueError("numeric measurement cannot carry a missing flag")
        if (
            self.metric_code in {"detonators_count", "mine_entry_persons"}
            and self.value is not None
            and not float(self.value).is_integer()
        ):
            raise ValueError(f"{self.metric_code} must be integral")
        return self


class WireMeasurementSet(WireContractModel):
    ventilation_m3_min: WireMeasurement
    electricity_kwh: WireMeasurement
    detonators_count: WireMeasurement
    explosives_kg: WireMeasurement
    mine_entry_persons: WireMeasurement
    production_t: WireMeasurement

    @model_validator(mode="after")
    def validate_codes_and_units(self) -> "WireMeasurementSet":
        expected = {
            "ventilation_m3_min": ("m3/min", {"time_weighted_average", "snapshot"}),
            "electricity_kwh": ("kWh", {"sum"}),
            "detonators_count": ("count", {"sum"}),
            "explosives_kg": ("kg", {"sum"}),
            "mine_entry_persons": ("person", {"sum"}),
            "production_t": ("t", {"sum"}),
        }
        for code, (unit, aggregations) in expected.items():
            measurement = getattr(self, code)
            if measurement.metric_code != code:
                raise ValueError(f"{code} metric_code mismatch")
            if measurement.unit != unit or measurement.aggregation not in aggregations:
                raise ValueError(f"{code} unit or aggregation mismatch")
        return self


class WireShift(WireContractModel):
    shift_code: Annotated[
        str,
        Field(
            min_length=1,
            max_length=64,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        ),
    ]
    start_at: WireDateTime
    end_at: WireDateTime
    measurements: WireMeasurementSet

    @model_validator(mode="after")
    def validate_window(self) -> "WireShift":
        if self.end_at <= self.start_at:
            raise ValueError("shift end_at must be later than start_at")
        return self


class WireShifts(WireContractModel):
    zero_shift: WireShift
    eight_shift: WireShift
    four_shift: WireShift


class WireReportedQuantity(WireContractModel):
    daily_total: WireMeasurementSet
    shifts: WireShifts


class WireDay(WireContractModel):
    date: WireDate
    operating_state: OperatingState
    reported_quantity: WireReportedQuantity


def _validate_three_shift_day(day: WireDay, timezone_name: str) -> None:
    shifts = (
        day.reported_quantity.shifts.zero_shift,
        day.reported_quantity.shifts.eight_shift,
        day.reported_quantity.shifts.four_shift,
    )
    codes = [item.shift_code for item in shifts]
    if len(codes) != len(set(codes)):
        raise ValueError("one day requires three unique shift_code values")

    zone = _timezone_info(timezone_name)
    next_date = day.date + timedelta(days=1)
    boundaries = (
        datetime(day.date.year, day.date.month, day.date.day, 0, tzinfo=zone),
        datetime(day.date.year, day.date.month, day.date.day, 8, tzinfo=zone),
        datetime(day.date.year, day.date.month, day.date.day, 16, tzinfo=zone),
        datetime(next_date.year, next_date.month, next_date.day, 0, tzinfo=zone),
    )
    for index, shift in enumerate(shifts):
        local_start = shift.start_at.astimezone(zone)
        local_end = shift.end_at.astimezone(zone)
        expected_start = boundaries[index]
        expected_end = boundaries[index + 1]
        # Eight hours means eight local wall-clock hours.  On a DST transition
        # the corresponding absolute duration is naturally seven or nine
        # hours; converting both endpoints to the governed zone preserves that
        # distinction without accepting overlaps or gaps.
        if local_start.replace(tzinfo=None) != expected_start.replace(tzinfo=None):
            raise ValueError(
                "shift start does not match its governed local-day boundary"
            )
        if local_end.replace(tzinfo=None) != expected_end.replace(tzinfo=None):
            raise ValueError("shift end does not match its governed local-day boundary")
        if local_end.replace(tzinfo=None) - local_start.replace(
            tzinfo=None
        ) != timedelta(hours=8):
            raise ValueError("each governed shift must span eight local hours")
        expected_absolute = expected_end.astimezone(UTC) - expected_start.astimezone(
            UTC
        )
        actual_absolute = shift.end_at.astimezone(UTC) - shift.start_at.astimezone(UTC)
        if actual_absolute != expected_absolute:
            raise ValueError("shift duration is inconsistent with timezone/DST rules")
        if index and shifts[index - 1].end_at.astimezone(
            UTC
        ) != shift.start_at.astimezone(UTC):
            raise ValueError("three governed shifts must be continuous without gaps")


class WireComparisonContext(WireContractModel):
    capacity_band: Annotated[str, Field(min_length=1, max_length=64)]
    mining_method: Annotated[str, Field(min_length=1, max_length=64)]
    shift_system: Annotated[str, Field(min_length=1, max_length=64)]
    coal_type: Annotated[str, Field(min_length=1, max_length=64)]
    operating_regime: Annotated[str, Field(min_length=1, max_length=64)]


class WireSource(WireContractModel):
    source_id: Identifier
    acquisition_mode: Literal["direct_collection", "manual_import"]
    source_system: Annotated[str, Field(min_length=1, max_length=128)]
    source_record_id: Annotated[str, Field(min_length=1, max_length=256)]
    source_location: Annotated[str | None, Field(min_length=1, max_length=512)] = None
    captured_at: WireDateTime
    media_type: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    normalization: Annotated[str | None, Field(min_length=1, max_length=1000)] = None

    @model_validator(mode="after")
    def reject_explicit_null_optional_strings(self) -> "WireSource":
        for field_name in ("source_location", "media_type", "normalization"):
            if (
                field_name in self.model_fields_set
                and getattr(self, field_name) is None
            ):
                raise ValueError(f"{field_name} cannot be null")
        return self


class WireAgentProcessing(WireContractModel):
    normalization_performed: WireBoolean
    model_assistance_used: WireBoolean
    processing_record_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    model_output_sha256: Annotated[
        str | None,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ] = None

    @model_validator(mode="after")
    def validate_model_disclosure(self) -> "WireAgentProcessing":
        if (
            not self.model_assistance_used
            and "model_output_sha256" in self.model_fields_set
        ):
            raise ValueError(
                "model_output_sha256 must be omitted when model assistance is unused"
            )
        if self.model_assistance_used != (self.model_output_sha256 is not None):
            raise ValueError(
                "model_output_sha256 must exactly match model assistance use"
            )
        return self


class WireHumanConfirmation(WireContractModel):
    confirmed: WireTrue
    confirmer_id: Identifier
    confirmer_name: Annotated[str, Field(min_length=1, max_length=128)]
    role: Annotated[str, Field(min_length=1, max_length=128)]
    confirmed_at: WireDateTime
    content_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class FiveQuantitySubmissionPayload(WireContractModel):
    mine: WireMine
    reporting_month: Annotated[str, Field(pattern=r"^[0-9]{4}-(?:0[1-9]|1[0-2])$")]
    timezone: TimezoneText
    period_start: WireDate
    period_end: WireDate
    closed_at: WireDateTime
    comparison_context: WireComparisonContext
    days: Annotated[list[WireDay], Field(min_length=1, max_length=366)]
    sources: Annotated[list[WireSource], Field(min_length=1, max_length=256)]
    agent_processing: WireAgentProcessing
    human_confirmation: WireHumanConfirmation

    @model_validator(mode="after")
    def validate_reporting_window(self) -> "FiveQuantitySubmissionPayload":
        if self.period_end < self.period_start:
            raise ValueError("period_end cannot predate period_start")
        if (
            self.period_start.strftime("%Y-%m") != self.reporting_month
            or self.period_end.strftime("%Y-%m") != self.reporting_month
        ):
            raise ValueError("period window must stay inside reporting_month")
        dates = [item.date for item in self.days]
        if dates != sorted(dates) or len(dates) != len(set(dates)):
            raise ValueError("days must be unique and chronological")
        if any(
            item < self.period_start
            or item > self.period_end
            or item.strftime("%Y-%m") != self.reporting_month
            for item in dates
        ):
            raise ValueError(
                "daily date is outside the declared reporting month/window"
            )
        source_ids = [item.source_id for item in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source_id values must be unique")
        source_set = set(source_ids)
        for day in self.days:
            _validate_three_shift_day(day, self.timezone)
            sets = [day.reported_quantity.daily_total]
            sets.extend(
                (
                    day.reported_quantity.shifts.zero_shift.measurements,
                    day.reported_quantity.shifts.eight_shift.measurements,
                    day.reported_quantity.shifts.four_shift.measurements,
                )
            )
            for measurements in sets:
                for code in (
                    "ventilation_m3_min",
                    "electricity_kwh",
                    "detonators_count",
                    "explosives_kg",
                    "mine_entry_persons",
                    "production_t",
                ):
                    if not set(getattr(measurements, code).source_refs) <= source_set:
                        raise ValueError("measurement references an unknown source")
        if self.human_confirmation.confirmed_at < self.closed_at:
            raise ValueError("human confirmation cannot predate report closing")
        if any(
            source.captured_at > self.human_confirmation.confirmed_at
            for source in self.sources
        ):
            raise ValueError("human confirmation cannot predate source capture")
        return self


class FiveQuantitySubmissionMessage(ExchangeMessageBase):
    contract_version: Literal["five-quantity-submission-v2"]
    message_type: Literal["five_quantity_submission"]
    payload: FiveQuantitySubmissionPayload

    @model_validator(mode="after")
    def validate_submission_binding(self) -> "FiveQuantitySubmissionMessage":
        if (
            self.sender.role != "enterprise_agent"
            or self.recipient.role != "regulatory_platform"
        ):
            raise ValueError("submission direction is invalid")
        if self.mine_id != self.payload.mine.mine_id:
            raise ValueError("envelope and payload mine_id differ")
        if self.sender.party_id != self.payload.mine.operator_id:
            raise ValueError("sender party must be the mine operator")
        if self.revision == 1:
            if self.correlation_id != self.message_id or self.causation_id is not None:
                raise ValueError("initial submission has invalid correlation/causation")
        elif self.causation_id is None:
            raise ValueError("corrected submission requires causation_id")
        if self.created_at < self.payload.human_confirmation.confirmed_at:
            raise ValueError("message cannot predate human confirmation")
        return self

    def to_regulatory_submission(self) -> FiveQuantitySubmission:
        def shift_metadata(shift: WireShift) -> ShiftWindowMetadata:
            return ShiftWindowMetadata(
                shift_code=shift.shift_code,
                start_at=shift.start_at,
                end_at=shift.end_at,
                aggregations={
                    metric: getattr(shift.measurements, metric).aggregation
                    for metric in METRICS
                },
            )

        def quantity(
            day: WireDay,
            metric: str,
        ) -> ReportedQuantity:
            daily_measurement = getattr(day.reported_quantity.daily_total, metric)
            shifts = day.reported_quantity.shifts
            return ReportedQuantity(
                daily_total=daily_measurement.value,
                daily_aggregation=daily_measurement.aggregation,
                shifts=ShiftValues(
                    zero_shift=getattr(shifts.zero_shift.measurements, metric).value,
                    eight_shift=getattr(shifts.eight_shift.measurements, metric).value,
                    four_shift=getattr(shifts.four_shift.measurements, metric).value,
                ),
            )

        def quality(day: WireDay, metric: str) -> ReportedQuality:
            shifts = day.reported_quantity.shifts
            return ReportedQuality(
                daily_total=tuple(
                    getattr(day.reported_quantity.daily_total, metric).quality_flags
                ),
                zero_shift=tuple(
                    getattr(shifts.zero_shift.measurements, metric).quality_flags
                ),
                eight_shift=tuple(
                    getattr(shifts.eight_shift.measurements, metric).quality_flags
                ),
                four_shift=tuple(
                    getattr(shifts.four_shift.measurements, metric).quality_flags
                ),
            )

        return FiveQuantitySubmission(
            submission_id=self.message_id,
            mine_id=self.mine_id,
            mine_name=self.payload.mine.mine_name,
            reporting_timezone=self.payload.timezone,
            revision=self.revision,
            supersedes_submission_id=(
                self.predecessor.message_id if self.predecessor is not None else None
            ),
            period_start=self.payload.period_start,
            period_end=self.payload.period_end,
            comparison_context=ComparisonContext(
                **self.payload.comparison_context.model_dump()
            ),
            days=[
                FiveQuantityDay(
                    date=day.date,
                    ventilation_m3_min=quantity(day, "ventilation_m3_min"),
                    electricity_kwh=quantity(day, "electricity_kwh"),
                    detonators_count=quantity(day, "detonators_count"),
                    explosives_kg=quantity(day, "explosives_kg"),
                    mine_entry_persons=quantity(day, "mine_entry_persons"),
                    production_t=quantity(day, "production_t"),
                    declared_operating_state=day.operating_state,
                    quality={metric: quality(day, metric) for metric in METRICS},
                    shift_metadata=ShiftMetadata(
                        zero_shift=shift_metadata(
                            day.reported_quantity.shifts.zero_shift
                        ),
                        eight_shift=shift_metadata(
                            day.reported_quantity.shifts.eight_shift
                        ),
                        four_shift=shift_metadata(
                            day.reported_quantity.shifts.four_shift
                        ),
                    ),
                )
                for day in self.payload.days
            ],
            provenance=[
                SubmissionProvenance(
                    acquisition_mode=AcquisitionMode(source.acquisition_mode),
                    source_name=source.source_system,
                    evidence_sha256=source.evidence_sha256,
                    source_record_id=source.source_record_id,
                )
                for source in self.payload.sources
            ],
        )


class DeliveryAckPayload(WireContractModel):
    report_id: CanonicalUUID
    analysis_report_message_id: CanonicalUUID
    delivery_cursor: Annotated[
        str,
        Field(
            min_length=1,
            max_length=256,
            pattern=r"^[A-Za-z0-9._:-]+$",
        ),
    ]
    received_at: WireDateTime
    local_inbox_record_id: Identifier
    delivery_status: Literal["stored", "duplicate"]


class RiskDeliveryAckMessage(ExchangeMessageBase):
    contract_version: Literal["risk-delivery-ack-v2"]
    message_type: Literal["risk_delivery_ack"]
    causation_id: CanonicalUUID
    revision: WireOne
    predecessor: None
    payload: DeliveryAckPayload

    @model_validator(mode="after")
    def validate_ack_binding(self) -> "RiskDeliveryAckMessage":
        if (
            self.sender.role != "enterprise_agent"
            or self.recipient.role != "regulatory_platform"
        ):
            raise ValueError("delivery acknowledgement direction is invalid")
        if self.causation_id != self.payload.analysis_report_message_id:
            raise ValueError("delivery acknowledgement causation mismatch")
        if self.created_at < self.payload.received_at:
            raise ValueError("acknowledgement cannot predate report receipt")
        return self

    def to_store_ack(self) -> AnalysisReportDeliveryAck:
        return AnalysisReportDeliveryAck(
            ack_id=self.message_id,
            report_id=self.payload.report_id,
            mine_id=self.mine_id,
            analysis_report_message_id=self.payload.analysis_report_message_id,
            delivery_cursor=self.payload.delivery_cursor,
            local_inbox_record_id=self.payload.local_inbox_record_id,
            delivery_status=self.payload.delivery_status,
            received_at=self.payload.received_at,
        )


class ResponseAttachment(WireContractModel):
    evidence_id: Identifier
    title: Annotated[str, Field(min_length=1, max_length=256)]
    media_type: Annotated[str, Field(min_length=1, max_length=128)]
    size_bytes: Annotated[
        int,
        BeforeValidator(_json_integer),
        Field(ge=0, le=1_073_741_824),
    ]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    retention_location: Literal["enterprise_local"]


class ResponseAction(WireContractModel):
    action_type: Literal[
        "investigation",
        "data_correction",
        "corrective",
        "preventive",
    ]
    description: Annotated[str, Field(min_length=1, max_length=2000)]
    status: Literal["planned", "in_progress", "completed", "not_applicable"]


class FindingResponseItem(WireContractModel):
    finding_id: CanonicalUUID
    response_kind: Literal[
        "explanation",
        "correction_submitted",
        "clarification_request",
        "unable_to_determine",
    ]
    reason_code: Literal[
        "equipment_maintenance",
        "power_outage",
        "planned_shutdown",
        "restart_transition",
        "geology_change",
        "production_plan_change",
        "shift_arrangement",
        "ventilation_adjustment",
        "blasting_plan_change",
        "meter_or_source_error",
        "transcription_or_mapping_error",
        "other",
        "unknown_under_investigation",
    ]
    facts: Annotated[str, Field(min_length=1, max_length=8000)]
    evidence_refs: Annotated[list[Identifier], Field(max_length=50)]
    actions: Annotated[list[ResponseAction], Field(max_length=50)]
    corrected_submission_message_id: CanonicalUUID | None

    @model_validator(mode="after")
    def validate_correction_reference(self) -> "FindingResponseItem":
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("evidence_refs values must be unique")
        if (self.response_kind == "correction_submitted") != (
            self.corrected_submission_message_id is not None
        ):
            raise ValueError(
                "corrected submission is only valid for correction_submitted"
            )
        return self


class AgentAssistanceDisclosure(WireContractModel):
    used: WireBoolean
    conversation_id: Annotated[str | None, Field(min_length=1, max_length=128)]
    assistance_record_sha256: Annotated[
        str | None,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ]

    @model_validator(mode="after")
    def validate_disclosure(self) -> "AgentAssistanceDisclosure":
        if self.used != (
            self.conversation_id is not None
            and self.assistance_record_sha256 is not None
        ):
            raise ValueError("agent assistance references must match used")
        return self


class EnterpriseRiskResponsePayload(WireContractModel):
    response_id: CanonicalUUID
    report_id: CanonicalUUID
    analysis_report_message_id: CanonicalUUID
    responded_at: WireDateTime
    finding_responses: Annotated[
        list[FindingResponseItem],
        Field(min_length=1, max_length=100),
    ]
    attachments: Annotated[list[ResponseAttachment], Field(max_length=100)]
    agent_assistance: AgentAssistanceDisclosure
    human_confirmation: WireHumanConfirmation

    @model_validator(mode="after")
    def validate_references(self) -> "EnterpriseRiskResponsePayload":
        finding_ids = [item.finding_id for item in self.finding_responses]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("finding_responses cannot repeat a finding_id")
        attachment_ids = [item.evidence_id for item in self.attachments]
        if len(attachment_ids) != len(set(attachment_ids)):
            raise ValueError("attachment evidence_id values must be unique")
        available = set(attachment_ids)
        for item in self.finding_responses:
            if not set(item.evidence_refs) <= available:
                raise ValueError("finding response references unknown evidence")
        if self.responded_at < self.human_confirmation.confirmed_at:
            raise ValueError("responded_at cannot predate human confirmation")
        return self


class EnterpriseRiskResponseMessage(ExchangeMessageBase):
    contract_version: Literal["enterprise-risk-response-v2"]
    message_type: Literal["enterprise_risk_response"]
    causation_id: CanonicalUUID
    payload: EnterpriseRiskResponsePayload

    @model_validator(mode="after")
    def validate_response_binding(self) -> "EnterpriseRiskResponseMessage":
        if (
            self.sender.role != "enterprise_agent"
            or self.recipient.role != "regulatory_platform"
        ):
            raise ValueError("enterprise response direction is invalid")
        if self.causation_id != self.payload.analysis_report_message_id:
            raise ValueError("enterprise response causation mismatch")
        if self.created_at < self.payload.responded_at:
            raise ValueError("message cannot predate the recorded response")
        return self

    def to_store_responses(self) -> list[EnterpriseFindingResponse]:
        """Map every wire item while preserving the signed batch separately."""

        reason_map: dict[
            str,
            Literal[
                "production_arrangement",
                "equipment_or_metering",
                "reporting_scope",
                "maintenance_or_shutdown",
                "geological_condition",
                "data_correction_planned",
                "other",
            ],
        ] = {
            "equipment_maintenance": "equipment_or_metering",
            "meter_or_source_error": "equipment_or_metering",
            "transcription_or_mapping_error": "reporting_scope",
            "planned_shutdown": "maintenance_or_shutdown",
            "power_outage": "maintenance_or_shutdown",
            "restart_transition": "maintenance_or_shutdown",
            "geology_change": "geological_condition",
            "production_plan_change": "production_arrangement",
            "shift_arrangement": "production_arrangement",
            "ventilation_adjustment": "production_arrangement",
            "blasting_plan_change": "production_arrangement",
        }
        attachment_by_id = {item.evidence_id: item for item in self.payload.attachments}
        namespace = UUID(self.payload.response_id)
        result: list[EnterpriseFindingResponse] = []
        for item in self.payload.finding_responses:
            result.append(
                EnterpriseFindingResponse(
                    response_id=str(uuid5(namespace, item.finding_id)),
                    finding_id=item.finding_id,
                    mine_id=self.mine_id,
                    reason_category=reason_map.get(item.reason_code, "other"),
                    explanation=item.facts,
                    corrective_action=(
                        "；".join(action.description for action in item.actions) or None
                    ),
                    corrected_submission_planned=(
                        item.corrected_submission_message_id is not None
                    ),
                    evidence=[
                        EvidenceReference(
                            title=attachment_by_id[evidence_id].title,
                            evidence_sha256=attachment_by_id[evidence_id].sha256,
                            locator="enterprise_local",
                        )
                        for evidence_id in item.evidence_refs
                    ],
                    confirmed_by=self.payload.human_confirmation.confirmer_id,
                    confirmed_at=self.payload.human_confirmation.confirmed_at,
                )
            )
        return result


WireInboundMessage = (
    FiveQuantitySubmissionMessage
    | RiskDeliveryAckMessage
    | EnterpriseRiskResponseMessage
)


@dataclass(frozen=True)
class DecodedInboundMessage:
    """A typed message paired with the exact duplicate-safe decoded document."""

    message: WireInboundMessage
    document: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class ExchangeClient:
    """One independently owned mine bound to one enterprise-agent identity."""

    sender_id: str
    party_id: str
    mine_id: str
    # ``secret`` is the application-message key.  ``transport_secret`` is a
    # separately configured HTTP key; omitting it is retained only as a local
    # compatibility shortcut and the two signature domains still differ.
    secret: bytes = field(repr=False)
    transport_secret: bytes | None = field(default=None, repr=False)
    mine_name: str | None = None
    comparison_context: Mapping[str, str] | None = field(default=None, repr=False)
    previous_secrets: tuple[bytes, ...] = field(default_factory=tuple, repr=False)
    previous_transport_secrets: tuple[bytes, ...] = field(
        default_factory=tuple, repr=False
    )
    # Application keys are addressed by the public key ID carried in the
    # signed envelope.  ``previous_secrets`` remains accepted for constructor
    # compatibility, but every previous secret now needs its parallel ID.
    message_key_id: str = "enterprise-key-2026-01"
    previous_message_key_ids: tuple[str, ...] = field(default_factory=tuple)
    previous_message_keys: Mapping[str, bytes] = field(
        default_factory=dict,
        repr=False,
    )

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.message_key_id) is None:
            raise ValueError("message_key_id is invalid")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValueError("application secret must contain at least 32 bytes")
        if self.transport_secret is not None and (
            not isinstance(self.transport_secret, bytes)
            or len(self.transport_secret) < 32
        ):
            raise ValueError("transport secret must contain at least 32 bytes")
        if any(
            not isinstance(item, bytes) or len(item) < 32
            for item in (*self.previous_secrets, *self.previous_transport_secrets)
        ):
            raise ValueError("previous secrets must contain at least 32 bytes")
        # Materialize once during construction so duplicate/missing key IDs
        # fail at startup instead of during request authentication.
        _ = self.message_verification_keys

    @property
    def verification_secrets(self) -> tuple[bytes, ...]:
        """Compatibility view; signature verification uses the named map."""

        return tuple(self.message_verification_keys.values())

    @property
    def message_verification_keys(self) -> Mapping[str, bytes]:
        if len(self.previous_secrets) != len(self.previous_message_key_ids):
            raise ValueError(
                "each previous application secret requires a previous_message_key_id"
            )
        keys: dict[str, bytes] = {self.message_key_id: self.secret}
        for key_id, secret_value in zip(
            self.previous_message_key_ids,
            self.previous_secrets,
            strict=True,
        ):
            if (
                not isinstance(key_id, str)
                or _IDENTIFIER.fullmatch(key_id) is None
                or key_id in keys
            ):
                raise ValueError(
                    "previous application key IDs must be valid and unique"
                )
            keys[key_id] = secret_value
        for key_id, secret_value in self.previous_message_keys.items():
            if (
                not isinstance(key_id, str)
                or _IDENTIFIER.fullmatch(key_id) is None
                or key_id in keys
            ):
                raise ValueError(
                    "previous application key IDs must be valid and unique"
                )
            if not isinstance(secret_value, bytes) or len(secret_value) < 32:
                raise ValueError(
                    "application key material must contain at least 32 bytes"
                )
            keys[key_id] = secret_value
        return keys

    @property
    def active_transport_secret(self) -> bytes:
        return self.transport_secret or self.secret

    @property
    def transport_verification_secrets(self) -> tuple[bytes, ...]:
        return (self.active_transport_secret, *self.previous_transport_secrets)


class ExchangeAuthenticationError(ValueError):
    """Stable, deliberately non-specific authentication failure."""


class ExchangeLineageError(ValueError):
    """A message does not continue the immutable exchange workflow."""


LineageMessage = ExchangeMessageBase | Mapping[str, Any]


def _lineage_document(value: LineageMessage) -> Mapping[str, Any]:
    if isinstance(value, ExchangeMessageBase):
        return value._wire_document or value.model_dump(mode="json")
    return value


def _lineage_uuid(document: Mapping[str, Any], field_name: str) -> str:
    value = document.get(field_name)
    if not isinstance(value, str):
        raise ExchangeLineageError(f"lineage {field_name} is missing")
    try:
        return _canonical_uuid(value, field_name)
    except ValueError as error:
        raise ExchangeLineageError(str(error)) from error


def _verified_document_payload_hash(document: Mapping[str, Any]) -> str:
    try:
        digest = sha256_bytes(jcs_canonical_json(document["payload"]).encode("utf-8"))
        supplied = document["signature_envelope"]["payload_sha256"]
    except (KeyError, TypeError, ValueError) as error:
        raise ExchangeLineageError(
            "lineage message lacks a valid payload digest"
        ) from error
    if not isinstance(supplied, str) or not hmac.compare_digest(digest, supplied):
        raise ExchangeLineageError("lineage payload digest does not match its document")
    return digest


def validate_exchange_lineage(
    message: ExchangeMessageBase,
    *,
    predecessor: LineageMessage | None = None,
    allowed_causes: Iterable[LineageMessage] = (),
) -> None:
    """Validate immutable revision and direct-cause continuity.

    The HTTP boundary should pass the stored raw predecessor document and all
    permitted direct-cause documents (for example the report that requested a
    correction).  Every matched predecessor/cause is constrained to the same
    mine and correlation workflow; a later revision additionally preserves
    message contract, direction and party identities.
    """

    predecessor_document = (
        _lineage_document(predecessor) if predecessor is not None else None
    )
    if message.revision == 1:
        if predecessor_document is not None or message.predecessor is not None:
            raise ExchangeLineageError("revision 1 cannot have a predecessor")
    else:
        if predecessor_document is None or message.predecessor is None:
            raise ExchangeLineageError("later revision requires its direct predecessor")
        predecessor_id = _lineage_uuid(predecessor_document, "message_id")
        if message.predecessor.message_id != predecessor_id:
            raise ExchangeLineageError(
                "predecessor message_id is not the direct prior message"
            )
        try:
            predecessor_revision = predecessor_document["revision"]
        except KeyError as error:
            raise ExchangeLineageError("predecessor revision is invalid") from error
        if (
            isinstance(predecessor_revision, bool)
            or not isinstance(predecessor_revision, int)
            or predecessor_revision < 1
        ):
            raise ExchangeLineageError("predecessor revision is invalid")
        if message.revision != predecessor_revision + 1:
            raise ExchangeLineageError("revision must increment its predecessor by one")
        if message.predecessor.payload_sha256 != _verified_document_payload_hash(
            predecessor_document
        ):
            raise ExchangeLineageError("predecessor payload_sha256 is not continuous")
        for field_name in ("contract_version", "message_type", "mine_id"):
            if str(predecessor_document.get(field_name, "")) != str(
                getattr(message, field_name)
            ):
                raise ExchangeLineageError(
                    f"predecessor {field_name} differs from the current workflow"
                )
        if (
            _lineage_uuid(predecessor_document, "correlation_id")
            != message.correlation_id
        ):
            raise ExchangeLineageError(
                "predecessor correlation_id differs from the current workflow"
            )
        for participant_name in ("sender", "recipient"):
            previous_participant = predecessor_document.get(participant_name)
            current_participant = getattr(message, participant_name).model_dump(
                mode="json"
            )
            if previous_participant != current_participant:
                raise ExchangeLineageError(
                    f"predecessor {participant_name} identity differs"
                )

    cause_documents = [_lineage_document(item) for item in allowed_causes]
    if predecessor_document is not None:
        cause_documents.append(predecessor_document)
    if message.causation_id is None:
        if cause_documents:
            raise ExchangeLineageError("message lacks the required direct causation_id")
        return
    matched_cause = next(
        (
            item
            for item in cause_documents
            if _lineage_uuid(item, "message_id") == message.causation_id
        ),
        None,
    )
    if matched_cause is None:
        raise ExchangeLineageError(
            "causation_id is not one of the allowed direct causes"
        )
    if str(matched_cause.get("mine_id", "")) != message.mine_id:
        raise ExchangeLineageError("causation message belongs to another mine")
    if _lineage_uuid(matched_cause, "correlation_id") != message.correlation_id:
        raise ExchangeLineageError(
            "causation message belongs to another correlation workflow"
        )


def _encoded_secret(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    encoded = value.encode("utf-8")
    if len(encoded) < 32:
        raise ValueError(f"{label} must contain at least 32 bytes")
    return encoded


def _parse_named_message_keys(entry: Mapping[str, Any]) -> tuple[str, dict[str, bytes]]:
    configured = entry.get("message_keys")
    named: dict[str, bytes] = {}
    if configured is not None:
        if isinstance(configured, dict):
            pairs = list(configured.items())
        elif isinstance(configured, list):
            pairs = []
            for item in configured:
                if not isinstance(item, dict) or set(item) != {"key_id", "secret"}:
                    raise ValueError(
                        "message_keys entries require exactly key_id and secret"
                    )
                pairs.append((item["key_id"], item["secret"]))
        else:
            raise ValueError("message_keys must be an object or an array")
        for raw_key_id, raw_secret in pairs:
            key_id = str(raw_key_id)
            if _IDENTIFIER.fullmatch(key_id) is None or key_id in named:
                raise ValueError("message key IDs must be valid and unique")
            named[key_id] = _encoded_secret(
                raw_secret,
                label=f"message key {key_id}",
            )
        if not named:
            raise ValueError("message_keys cannot be empty")
        if len(named) > 1 and not entry.get("active_message_key_id"):
            raise ValueError(
                "active_message_key_id is required when message_keys rotates keys"
            )
        active_key_id = str(entry.get("active_message_key_id") or next(iter(named)))
    else:
        raw_secrets = entry.get("message_secrets", entry.get("secrets"))
        if raw_secrets is None:
            raw_secrets = [entry.get("message_secret", entry.get("secret"))]
        if not isinstance(raw_secrets, list) or not raw_secrets:
            raise ValueError("message_secrets must be a non-empty array")
        raw_key_ids = entry.get("message_key_ids")
        if raw_key_ids is None:
            if len(raw_secrets) != 1:
                raise ValueError(
                    "rotating legacy message_secrets requires parallel message_key_ids"
                )
            raw_key_ids = [
                entry.get("message_key_id")
                or entry.get("key_id")
                or "demo-exchange-key"
            ]
        if not isinstance(raw_key_ids, list) or len(raw_key_ids) != len(raw_secrets):
            raise ValueError("message_key_ids must parallel message_secrets")
        for raw_key_id, raw_secret in zip(raw_key_ids, raw_secrets, strict=True):
            key_id = str(raw_key_id)
            if _IDENTIFIER.fullmatch(key_id) is None or key_id in named:
                raise ValueError("message key IDs must be valid and unique")
            named[key_id] = _encoded_secret(
                raw_secret,
                label=f"message key {key_id}",
            )
        active_key_id = str(entry.get("active_message_key_id") or raw_key_ids[0])
    if active_key_id not in named:
        raise ValueError("active_message_key_id is not present in message_keys")
    return active_key_id, named


def parse_exchange_clients(value: str | None) -> dict[str, ExchangeClient]:
    if value is None or not value.strip():
        return {}
    try:
        document = json.loads(
            value,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError("MINEGUARD_V2_CLIENTS_JSON must be valid JSON") from error
    entries = document.get("clients") if isinstance(document, dict) else document
    if not isinstance(entries, list):
        raise ValueError("V2 client registry must be an array")
    clients: dict[str, ExchangeClient] = {}
    bound_mines: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("V2 client entry must be an object")
        sender_id = str(entry.get("sender_id") or entry.get("client_id") or "")
        party_id = str(entry.get("party_id") or entry.get("enterprise_id") or "")
        mine_id = str(entry.get("mine_id") or "")
        mine_name_value = entry.get("mine_name")
        mine_name = (
            str(mine_name_value).strip() if mine_name_value is not None else None
        )
        if not mine_id:
            mine_ids = entry.get("mine_ids")
            if isinstance(mine_ids, list) and len(mine_ids) == 1:
                mine_id = str(mine_ids[0])
        active_message_key_id, message_keys = _parse_named_message_keys(entry)
        raw_transport_secrets = entry.get("transport_secrets")
        if raw_transport_secrets is None:
            transport_value = entry.get("transport_secret")
            if transport_value is None:
                raise ValueError(
                    "transport_secret or transport_secrets must be configured explicitly"
                )
            raw_transport_secrets = [transport_value]
        if (
            _IDENTIFIER.fullmatch(sender_id) is None
            or _IDENTIFIER.fullmatch(party_id) is None
            or _IDENTIFIER.fullmatch(mine_id) is None
            or mine_id == "*"
            or not isinstance(raw_transport_secrets, list)
            or not raw_transport_secrets
            or sender_id in clients
            or mine_id in bound_mines
        ):
            raise ValueError("invalid V2 client entry; exactly one mine is required")
        context_value = entry.get("comparison_context")
        context: dict[str, str] | None = None
        if context_value is not None:
            required_context = {
                "capacity_band",
                "mining_method",
                "shift_system",
                "coal_type",
                "operating_regime",
            }
            if (
                not isinstance(context_value, dict)
                or set(context_value) != required_context
            ):
                raise ValueError(
                    "comparison_context must contain the five governed dimensions"
                )
            context = {key: str(value).strip() for key, value in context_value.items()}
            if any(not value or len(value) > 64 for value in context.values()):
                raise ValueError(
                    "comparison_context values must contain 1..64 characters"
                )
        transport_secrets_bytes = tuple(
            item.encode("utf-8") if isinstance(item, str) else b""
            for item in raw_transport_secrets
        )
        if any(len(item) < 32 for item in transport_secrets_bytes):
            raise ValueError("each V2 shared secret must contain at least 32 bytes")
        if set(message_keys.values()) & set(transport_secrets_bytes):
            raise ValueError(
                "application-message and HTTP transport keys must be different"
            )
        active_message_secret = message_keys.pop(active_message_key_id)
        clients[sender_id] = ExchangeClient(
            sender_id=sender_id,
            party_id=party_id,
            mine_id=mine_id,
            mine_name=mine_name,
            comparison_context=context,
            secret=active_message_secret,
            transport_secret=transport_secrets_bytes[0],
            message_key_id=active_message_key_id,
            previous_message_keys=message_keys,
            previous_transport_secrets=transport_secrets_bytes[1:],
        )
        bound_mines.add(mine_id)
    return clients


def _reject_linked_path(path: Path) -> None:
    """Reject symlinks/junction-like reparse points in a secret file path."""

    candidates = [path, *path.parents]
    for candidate in candidates:
        if not candidate.exists() and not candidate.is_symlink():
            continue
        if candidate.is_symlink():
            raise ValueError("MINEGUARD_V2_CLIENTS_FILE must not use symbolic links")
        try:
            attributes = candidate.lstat().st_file_attributes
        except (AttributeError, OSError):
            continue
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if attributes & reparse_flag:
            raise ValueError("MINEGUARD_V2_CLIENTS_FILE must not use reparse points")


def load_exchange_clients(
    inline_value: str | None,
    file_value: str | None,
    *,
    maximum_bytes: int = EXCHANGE_CLIENTS_FILE_MAX_BYTES,
) -> dict[str, ExchangeClient]:
    """Load the V2 client registry from exactly one explicit source.

    A file avoids the Windows environment-block limit for multi-mine
    registries.  It is still parsed by :func:`parse_exchange_clients`, so the
    inline and file forms have identical validation and fail-closed behavior.
    """

    if inline_value is not None and file_value is not None:
        raise ValueError(
            "configure only one of MINEGUARD_V2_CLIENTS_JSON and "
            "MINEGUARD_V2_CLIENTS_FILE"
        )
    if file_value is None:
        return parse_exchange_clients(inline_value)
    if not file_value.strip():
        raise ValueError("MINEGUARD_V2_CLIENTS_FILE must not be empty")
    if maximum_bytes < 1:
        raise ValueError("V2 client registry file size limit must be positive")

    path = Path(file_value.strip()).expanduser()
    if not path.is_absolute():
        raise ValueError("MINEGUARD_V2_CLIENTS_FILE must be an absolute path")
    _reject_linked_path(path)
    try:
        metadata = path.stat()
    except OSError as error:
        raise ValueError(f"MINEGUARD_V2_CLIENTS_FILE cannot be read: {path}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("MINEGUARD_V2_CLIENTS_FILE must be a regular file")
    if metadata.st_size > maximum_bytes:
        raise ValueError("MINEGUARD_V2_CLIENTS_FILE exceeds the 4 MiB safety limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("MINEGUARD_V2_CLIENTS_FILE must be a regular file")
            if (metadata.st_dev, metadata.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise ValueError(
                    "MINEGUARD_V2_CLIENTS_FILE changed while it was opened"
                )
            if opened.st_size > maximum_bytes:
                raise ValueError(
                    "MINEGUARD_V2_CLIENTS_FILE exceeds the 4 MiB safety limit"
                )
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ValueError(
            f"MINEGUARD_V2_CLIENTS_FILE cannot be read safely: {path}"
        ) from error
    if len(payload) > maximum_bytes:
        raise ValueError("MINEGUARD_V2_CLIENTS_FILE exceeds the 4 MiB safety limit")
    try:
        value = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("MINEGUARD_V2_CLIENTS_FILE must contain UTF-8 JSON") from error
    return parse_exchange_clients(value)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exchange_signature_material(message: Mapping[str, Any], payload_hash: str) -> bytes:
    signature = message["signature_envelope"]
    predecessor = message.get("predecessor") or {}
    lines = [
        EXCHANGE_SIGNATURE_CONTEXT,
        str(message["contract_version"]),
        str(message["message_type"]),
        str(message["message_id"]),
        str(message["correlation_id"]),
        str(message.get("causation_id") or ""),
        str(message["idempotency_key"]),
        str(message["revision"]),
        str(predecessor.get("message_id", "")),
        str(predecessor.get("payload_sha256", "")),
        str(message["created_at"]),
        str(message["sender"]["system_id"]),
        str(message["sender"]["party_id"]),
        str(message["sender"]["role"]),
        str(message["recipient"]["system_id"]),
        str(message["recipient"]["party_id"]),
        str(message["recipient"]["role"]),
        str(message["mine_id"]),
        str(signature["algorithm"]),
        str(signature["canonicalization"]),
        str(signature["key_id"]),
        str(signature["signed_at"]),
        str(signature["nonce"]),
        payload_hash,
    ]
    return "\n".join(lines).encode("utf-8")


def verify_exchange_message_signature(
    message: ExchangeMessageBase,
    client: ExchangeClient,
    document: Mapping[str, Any] | None = None,
) -> str:
    """Verify the application signature over the actual decoded wire members.

    Pydantic models intentionally normalize UUID and datetime values.  They are
    therefore used for semantic validation and authorization only, never to
    reconstruct signed material.  ``parse_inbound_message`` retains the raw
    document for compatibility; new HTTP code should use
    ``decode_inbound_message`` and pass ``decoded.document`` explicitly.
    """

    wire = document if document is not None else message._wire_document
    if not isinstance(wire, Mapping):
        raise ExchangeAuthenticationError("exchange authentication failed")
    try:
        validated = _validate_inbound_document(dict(wire))
        if type(validated) is not type(message) or validated.model_dump(
            mode="json"
        ) != message.model_dump(mode="json"):
            raise ValueError("typed message and wire document differ")
        payload_hash = sha256_bytes(jcs_canonical_json(wire["payload"]).encode("utf-8"))
        signature = wire["signature_envelope"]
        supplied_hash = str(signature["payload_sha256"])
        supplied_signature = str(signature["signature"])
        key_id = str(signature["key_id"])
        secret_value = client.message_verification_keys.get(key_id)
        if secret_value is None or not hmac.compare_digest(
            supplied_hash,
            payload_hash,
        ):
            raise ValueError("application key or payload digest mismatch")
        material = exchange_signature_material(wire, payload_hash)
        expected = hmac.new(secret_value, material, hashlib.sha256).hexdigest()
    except (KeyError, TypeError, ValueError) as error:
        raise ExchangeAuthenticationError("exchange authentication failed") from error
    if not hmac.compare_digest(expected, supplied_signature):
        raise ExchangeAuthenticationError("exchange authentication failed")
    return payload_hash


def sign_exchange_message(
    message: dict[str, Any],
    secret: bytes,
) -> dict[str, Any]:
    payload_hash = sha256_bytes(jcs_canonical_json(message["payload"]).encode("utf-8"))
    envelope = message["signature_envelope"]
    envelope["payload_sha256"] = payload_hash
    envelope["signature"] = hmac.new(
        secret,
        exchange_signature_material(message, payload_hash),
        hashlib.sha256,
    ).hexdigest()
    return message


def _validate_inbound_document(document: dict[str, Any]) -> WireInboundMessage:
    message_type = document.get("message_type")
    model: type[WireInboundMessage]
    if message_type == "five_quantity_submission":
        model = FiveQuantitySubmissionMessage
    elif message_type == "risk_delivery_ack":
        model = RiskDeliveryAckMessage
    elif message_type == "enterprise_risk_response":
        model = EnterpriseRiskResponseMessage
    else:
        raise ValueError("unsupported inbound V2 message type")
    return model.model_validate(document)


def decode_inbound_message(body: bytes) -> DecodedInboundMessage:
    try:
        document = json.loads(
            body,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("exchange message must be valid I-JSON") from error
    if not isinstance(document, dict):
        raise ValueError("exchange message must be an object")
    message = _validate_inbound_document(document)
    message._wire_document = document
    return DecodedInboundMessage(message=message, document=document)


def parse_inbound_message(body: bytes) -> WireInboundMessage:
    """Compatibility wrapper returning the typed half of a decoded message."""

    return decode_inbound_message(body).message


def transport_signature(
    secret: bytes,
    *,
    method: str,
    request_target: str,
    sender_id: str,
    timestamp: str,
    nonce: str,
    contract_version: str,
    content_sha256: str,
) -> str:
    material = "\n".join(
        (
            EXCHANGE_TRANSPORT_CONTEXT,
            method.upper(),
            request_target,
            sender_id,
            timestamp,
            nonce,
            contract_version,
            content_sha256,
        )
    )
    return hmac.new(secret, material.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_transport_headers(
    client: ExchangeClient,
    *,
    method: str,
    request_target: str,
    body: bytes = b"",
    contract_version: str,
    timestamp: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    current = (timestamp or datetime.now(UTC)).astimezone(UTC)
    timestamp_text = current.isoformat().replace("+00:00", "Z")
    nonce_text = nonce or base64.urlsafe_b64encode(secrets.token_bytes(16)).decode(
        "ascii"
    ).rstrip("=")
    content_hash = sha256_bytes(body)
    return {
        SENDER_ID_HEADER: client.sender_id,
        TIMESTAMP_HEADER: timestamp_text,
        NONCE_HEADER: nonce_text,
        CONTENT_SHA256_HEADER: content_hash,
        CONTRACT_VERSION_HEADER: contract_version,
        SIGNATURE_VERSION_HEADER: EXCHANGE_SIGNATURE_VERSION,
        SIGNATURE_HEADER: transport_signature(
            client.active_transport_secret,
            method=method,
            request_target=request_target,
            sender_id=client.sender_id,
            timestamp=timestamp_text,
            nonce=nonce_text,
            contract_version=contract_version,
            content_sha256=content_hash,
        ),
    }


def authenticate_transport(
    clients: Mapping[str, ExchangeClient],
    headers: Mapping[str, str],
    *,
    method: str,
    request_target: str,
    body: bytes = b"",
    now: datetime | None = None,
) -> tuple[ExchangeClient, datetime, str, str]:
    try:
        sender_id = _header(headers, SENDER_ID_HEADER)
        timestamp = _header(headers, TIMESTAMP_HEADER)
        nonce = _header(headers, NONCE_HEADER)
        content_hash = _header(headers, CONTENT_SHA256_HEADER)
        contract_version = _header(headers, CONTRACT_VERSION_HEADER)
        signature_version = _header(headers, SIGNATURE_VERSION_HEADER)
        signature = _header(headers, SIGNATURE_HEADER)
        if (
            _IDENTIFIER.fullmatch(sender_id) is None
            or _NONCE.fullmatch(nonce) is None
            or _SHA256.fullmatch(content_hash) is None
            or _SHA256.fullmatch(signature) is None
            or _CONTRACT.fullmatch(contract_version) is None
            or signature_version != EXCHANGE_SIGNATURE_VERSION
            or sha256_bytes(body) != content_hash
        ):
            raise ValueError("malformed transport authentication")
        padding = "=" * (-len(nonce) % 4)
        if len(base64.urlsafe_b64decode(nonce + padding)) < 16:
            raise ValueError("nonce is too short")
        parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
            raise ValueError("transport timestamp lacks timezone")
        parsed_time = parsed_time.astimezone(UTC)
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if abs((current - parsed_time).total_seconds()) > EXCHANGE_AUTH_WINDOW_SECONDS:
            raise ValueError("transport timestamp outside replay window")
        client = clients.get(sender_id)
        if client is None:
            raise ValueError("unknown exchange sender")
        valid = False
        for secret_value in client.transport_verification_secrets:
            expected = transport_signature(
                secret_value,
                method=method,
                request_target=request_target,
                sender_id=sender_id,
                timestamp=timestamp,
                nonce=nonce,
                contract_version=contract_version,
                content_sha256=content_hash,
            )
            valid = hmac.compare_digest(expected, signature) or valid
        if not valid:
            raise ValueError("transport signature mismatch")
        return client, parsed_time, nonce, contract_version
    except ExchangeAuthenticationError:
        raise
    except (ValueError, TypeError, binascii.Error) as error:
        raise ExchangeAuthenticationError("exchange authentication failed") from error


def _header(headers: Mapping[str, str], name: str) -> str:
    lowered = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    value = lowered.get(name.lower())
    if value is None:
        raise ExchangeAuthenticationError("exchange authentication failed")
    return value


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-I-JSON numeric constant: {value}")


def message_nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


__all__ = [
    "CONTRACT_VERSION_HEADER",
    "CONTENT_SHA256_HEADER",
    "DecodedInboundMessage",
    "EnterpriseRiskResponseMessage",
    "ExchangeAuthenticationError",
    "ExchangeClient",
    "ExchangeLineageError",
    "ExchangeMessageBase",
    "FiveQuantitySubmissionMessage",
    "NONCE_HEADER",
    "RiskDeliveryAckMessage",
    "SENDER_ID_HEADER",
    "SIGNED_HEADERS",
    "SIGNATURE_HEADER",
    "SIGNATURE_VERSION_HEADER",
    "TIMESTAMP_HEADER",
    "authenticate_transport",
    "decode_inbound_message",
    "exchange_signature_material",
    "message_nonce",
    "load_exchange_clients",
    "parse_exchange_clients",
    "parse_inbound_message",
    "sha256_bytes",
    "sign_exchange_message",
    "sign_transport_headers",
    "transport_signature",
    "validate_exchange_lineage",
    "verify_exchange_message_signature",
]
