"""Independent enterprise-agent wire contract adapter.

The regulatory platform intentionally owns this implementation.  It imports
neither enterprise-agent code nor executable code from ``contracts/``.  Tests
check it against the neutral contract artifacts instead.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import math
import re
from typing import Annotated, Any, Literal, Mapping
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from .governance import (
    GovernedObservation,
    GovernedProductionRequest,
    GovernanceModel,
)
from .historical import OperationalContext


EXTERNAL_SUBMISSION_CONTRACT_VERSION = "enterprise-submission-v1"
EXTERNAL_RECEIPT_CONTRACT_VERSION = "enterprise-submission-receipt-v1"
EXTERNAL_CAPABILITIES_CONTRACT_VERSION = (
    "enterprise-submission-capabilities-v1"
)
EXTERNAL_SIGNATURE_VERSION = "hmac-sha256-v1"
EXTERNAL_AUTH_CONTEXT = (
    "ENTERPRISE-SUBMISSION-HTTP-HMAC-SHA256-V1"
)
EXTERNAL_AUTH_WINDOW_SECONDS = 300
EXTERNAL_NONCE_RETENTION_SECONDS = 600

CLIENT_ID_HEADER = "X-Enterprise-Client-Id"
TIMESTAMP_HEADER = "X-Enterprise-Timestamp"
NONCE_HEADER = "X-Enterprise-Nonce"
CONTENT_SHA256_HEADER = "X-Enterprise-Content-SHA256"
SIGNATURE_VERSION_HEADER = "X-Enterprise-Signature-Version"
CONTRACT_VERSION_HEADER = "X-Enterprise-Contract-Version"
SIGNATURE_HEADER = "X-Enterprise-Signature"
SIGNED_HEADERS = (
    CLIENT_ID_HEADER,
    TIMESTAMP_HEADER,
    NONCE_HEADER,
    CONTENT_SHA256_HEADER,
    SIGNATURE_VERSION_HEADER,
    CONTRACT_VERSION_HEADER,
    SIGNATURE_HEADER,
)

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_SAFE_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CREDIT_CODE = re.compile(r"^[0-9A-HJ-NPQRTUWXY]{18}$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991

OriginType = Literal[
    "sensor",
    "erp",
    "weighbridge",
    "inventory_system",
    "transport_system",
    "work_order_system",
    "approved_document",
    "manual_record",
    "deterministic_calculation",
    "cryptographic_derivation",
]
AcquisitionMethod = Literal[
    "direct_api",
    "device_gateway",
    "file_import",
    "ocr_extraction",
    "llm_extraction",
    "manual_entry",
    "deterministic_formula",
    "signature_process",
]


class ProvenanceRecord(GovernanceModel):
    origin_type: OriginType
    source_system: Annotated[str, Field(min_length=1, max_length=128)]
    source_record_id: Annotated[str, Field(min_length=1, max_length=256)]
    source_location: Annotated[str | None, Field(min_length=1, max_length=512)] = (
        None
    )
    captured_at: AwareDatetime
    acquisition_method: AcquisitionMethod
    evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    confidence: Annotated[float | None, Field(ge=0.0, le=1.0)] = None
    transformation: Annotated[str | None, Field(min_length=1, max_length=1000)] = (
        None
    )

    @model_validator(mode="after")
    def validate_extraction_evidence(self) -> "ProvenanceRecord":
        if (
            self.acquisition_method in {"ocr_extraction", "llm_extraction"}
            and self.confidence is None
        ):
            raise ValueError(
                "confidence is required for OCR or LLM extraction"
            )
        return self


ProvenanceSet = Annotated[
    list[ProvenanceRecord],
    Field(min_length=1, max_length=16),
]


class EnterpriseFieldProvenance(GovernanceModel):
    enterprise_id: ProvenanceSet
    enterprise_name: ProvenanceSet
    unified_social_credit_code: ProvenanceSet


class EnterpriseIdentity(GovernanceModel):
    enterprise_id: Annotated[str, Field(min_length=1, max_length=128)]
    enterprise_name: Annotated[str, Field(min_length=1, max_length=256)]
    unified_social_credit_code: Annotated[
        str,
        Field(pattern=r"^[0-9A-HJ-NPQRTUWXY]{18}$"),
    ]
    field_provenance: EnterpriseFieldProvenance


class MineFieldProvenance(GovernanceModel):
    mine_id: ProvenanceSet
    mine_name: ProvenanceSet


class MineIdentity(GovernanceModel):
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    mine_name: Annotated[str, Field(min_length=1, max_length=256)]
    field_provenance: MineFieldProvenance


class WindowFieldProvenance(GovernanceModel):
    window_start: ProvenanceSet
    window_end: ProvenanceSet


class SubmissionWindow(GovernanceModel):
    window_start: AwareDatetime
    window_end: AwareDatetime
    field_provenance: WindowFieldProvenance

    @model_validator(mode="after")
    def validate_window(self) -> "SubmissionWindow":
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be later than window_start")
        return self


class ProfileFieldProvenance(GovernanceModel):
    profile_id: ProvenanceSet
    profile_version: ProvenanceSet


class SubmissionProfile(GovernanceModel):
    profile_id: Annotated[str, Field(min_length=1, max_length=128)]
    profile_version: Annotated[str, Field(min_length=1, max_length=64)]
    field_provenance: ProfileFieldProvenance


class OperationalContextFieldProvenance(GovernanceModel):
    regime_code: ProvenanceSet
    shift_code: ProvenanceSet
    season_code: ProvenanceSet
    maintenance: ProvenanceSet
    approved_event_codes: ProvenanceSet
    tags: ProvenanceSet


class SubmissionOperationalContext(GovernanceModel):
    regime_code: Annotated[str, Field(min_length=1, max_length=64)]
    shift_code: Annotated[str, Field(min_length=1, max_length=64)]
    season_code: Annotated[str, Field(min_length=1, max_length=64)]
    maintenance: bool
    approved_event_codes: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=64)]],
        Field(max_length=32),
    ]
    tags: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(max_length=64),
    ]
    field_provenance: OperationalContextFieldProvenance

    @model_validator(mode="after")
    def validate_sets(self) -> "SubmissionOperationalContext":
        if len(self.approved_event_codes) != len(
            set(self.approved_event_codes)
        ):
            raise ValueError("approved_event_codes values must be unique")
        if len(self.tags) != len(set(self.tags)):
            raise ValueError("tags values must be unique")
        return self


class ObservationFieldProvenance(GovernanceModel):
    source_id: ProvenanceSet
    observation_id: ProvenanceSet
    value: ProvenanceSet
    unit: ProvenanceSet
    observed_at: ProvenanceSet
    received_at: ProvenanceSet
    interval_start: ProvenanceSet
    interval_end: ProvenanceSet
    reset_before: ProvenanceSet
    sequence_no: ProvenanceSet
    revision: ProvenanceSet
    payload_sha256: ProvenanceSet
    signature: ProvenanceSet


class SubmissionObservation(GovernanceModel):
    source_id: Annotated[str, Field(min_length=1, max_length=128)]
    observation_id: Annotated[str, Field(min_length=1, max_length=256)]
    value: Annotated[float, Field(ge=-1e15, le=1e15)]
    unit: Annotated[str, Field(min_length=1, max_length=32)]
    observed_at: AwareDatetime
    received_at: AwareDatetime
    interval_start: AwareDatetime | None
    interval_end: AwareDatetime | None
    reset_before: bool
    sequence_no: Annotated[int, Field(ge=0, le=_MAX_SAFE_INTEGER)]
    revision: Annotated[int, Field(ge=0, le=_MAX_SAFE_INTEGER)]
    payload_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    field_provenance: ObservationFieldProvenance

    @model_validator(mode="after")
    def validate_times(self) -> "SubmissionObservation":
        if self.received_at < self.observed_at:
            raise ValueError("received_at cannot predate observed_at")
        if (self.interval_start is None) != (self.interval_end is None):
            raise ValueError(
                "interval_start and interval_end must be supplied together"
            )
        if (
            self.interval_start is not None
            and self.interval_end is not None
            and self.interval_end <= self.interval_start
        ):
            raise ValueError("interval_end must be later than interval_start")
        return self

    def to_governed(self) -> GovernedObservation:
        return GovernedObservation(
            **self.model_dump(
                exclude={"field_provenance"},
            )
        )


class LLMAssistance(GovernanceModel):
    used: bool
    provider: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    model: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    tasks: Annotated[
        list[
            Literal[
                "document_classification",
                "field_extraction",
                "unit_normalization_suggestion",
                "missing_field_question_generation",
                "consistency_explanation",
                "draft_assistance",
            ]
        ]
        | None,
        Field(min_length=1, max_length=16),
    ] = None
    affected_field_paths: Annotated[
        list[Annotated[str, Field(pattern=r"^/")]],
        Field(max_length=512),
    ]
    numeric_values_copied_or_deterministically_calculated: Literal[True]
    approved_events_copied_from_authoritative_source: Literal[True]
    human_reviewed_affected_fields: Literal[True]
    declaration_provenance: ProvenanceSet

    @model_validator(mode="after")
    def validate_disclosure(self) -> "LLMAssistance":
        if len(self.affected_field_paths) != len(
            set(self.affected_field_paths)
        ):
            raise ValueError("affected_field_paths values must be unique")
        if self.tasks is not None and len(self.tasks) != len(set(self.tasks)):
            raise ValueError("tasks values must be unique")
        if self.used:
            if not self.provider or not self.model or not self.tasks:
                raise ValueError(
                    "provider, model and tasks are required when LLM was used"
                )
            if not self.affected_field_paths:
                raise ValueError(
                    "affected_field_paths is required when LLM was used"
                )
        elif self.affected_field_paths:
            raise ValueError(
                "affected_field_paths must be empty when LLM was not used"
            )
        return self


class HumanConfirmation(GovernanceModel):
    confirmed: Literal[True]
    confirmer_id: Annotated[str, Field(min_length=1, max_length=128)]
    confirmer_name: Annotated[str, Field(min_length=1, max_length=128)]
    confirmer_role: Annotated[str, Field(min_length=1, max_length=128)]
    confirmed_at: AwareDatetime
    confirmation_method: Literal[
        "authenticated_click",
        "qualified_electronic_signature",
        "enterprise_seal",
    ]
    confirmation_evidence_sha256: Annotated[
        str,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ]
    evidence_reviewed: Literal[True]
    authorized_to_submit: Literal[True]
    understands_regulator_decides_normality_and_legality: Literal[True]
    declaration_provenance: ProvenanceSet


class EnterpriseSubmissionPayload(GovernanceModel):
    enterprise: EnterpriseIdentity
    mine: MineIdentity
    window: SubmissionWindow
    profile: SubmissionProfile
    operational_context: SubmissionOperationalContext
    observations: Annotated[
        list[SubmissionObservation],
        Field(min_length=1, max_length=10_000),
    ]
    llm_assistance: LLMAssistance
    human_confirmation: HumanConfirmation


class EnterpriseSubmission(GovernanceModel):
    contract_version: Literal["enterprise-submission-v1"]
    submission_id: Annotated[str, Field(min_length=36, max_length=36)]
    idempotency_key: Annotated[
        str,
        Field(min_length=16, max_length=128),
    ]
    submitted_at: AwareDatetime
    payload: EnterpriseSubmissionPayload
    payload_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        # Optional contract fields are absent rather than JSON null. Preserve
        # that wire distinction during a default round trip.
        kwargs.setdefault("exclude_unset", True)
        return super().model_dump(*args, **kwargs)

    @model_validator(mode="after")
    def validate_submission(self) -> "EnterpriseSubmission":
        try:
            parsed_submission_id = UUID(self.submission_id)
        except ValueError as error:
            raise ValueError("submission_id must be a UUID") from error
        if str(parsed_submission_id) != self.submission_id.lower():
            raise ValueError("submission_id must use canonical UUID syntax")
        if _SAFE_IDEMPOTENCY_KEY.fullmatch(self.idempotency_key) is None:
            raise ValueError("idempotency_key contains unsafe characters")
        if (
            self.payload.human_confirmation.confirmed_at
            > self.submitted_at
        ):
            raise ValueError("human confirmation cannot follow submission")
        latest_business_time = max(
            self.payload.window.window_end,
            *(
                max(
                    observation.received_at,
                    observation.interval_end
                    or observation.received_at,
                )
                for observation in self.payload.observations
            ),
        )
        if (
            self.payload.human_confirmation.confirmed_at
            < latest_business_time
        ):
            raise ValueError(
                "human confirmation must follow the reporting window and "
                "all received observations"
            )
        provenance_times = _provenance_times(self.payload)
        if provenance_times and (
            max(provenance_times)
            > self.payload.human_confirmation.confirmed_at
        ):
            raise ValueError(
                "human confirmation must follow all evidence capture"
            )
        llm_paths = _llm_extraction_paths(self.payload)
        declared = set(self.payload.llm_assistance.affected_field_paths)
        if llm_paths - declared:
            raise ValueError(
                "LLM-extracted fields must be declared as affected"
            )
        if llm_paths and not self.payload.llm_assistance.used:
            raise ValueError(
                "LLM extraction provenance requires used=true"
            )
        return self


@dataclass(frozen=True)
class AuthorizedConfirmer:
    confirmer_id: str
    confirmer_name: str
    confirmer_roles: frozenset[str]
    confirmation_methods: frozenset[str] = field(
        default_factory=lambda: frozenset({"authenticated_click"})
    )

    def matches(self, confirmation: HumanConfirmation) -> bool:
        return (
            confirmation.confirmer_id == self.confirmer_id
            and confirmation.confirmer_name == self.confirmer_name
            and confirmation.confirmer_role in self.confirmer_roles
            and confirmation.confirmation_method
            in self.confirmation_methods
        )


@dataclass(frozen=True)
class VerifiedEventSnapshot:
    mine_id: str
    window_start: datetime
    window_end: datetime
    event_codes: tuple[str, ...]
    evidence_sha256: str

    def matches(
        self,
        *,
        mine_id: str,
        window_start: datetime,
        window_end: datetime,
        event_codes: list[str],
        evidence_sha256: set[str],
    ) -> bool:
        return (
            self.mine_id == mine_id
            and self.window_start == window_start
            and self.window_end == window_end
            and self.event_codes == tuple(sorted(event_codes))
            and self.evidence_sha256 in evidence_sha256
        )


@dataclass(frozen=True)
class ExternalClient:
    client_id: str
    enterprise_id: str
    secret: bytes = field(repr=False)
    mine_ids: frozenset[str]
    authorized_confirmers: tuple[AuthorizedConfirmer, ...] = ()
    verified_event_snapshots: tuple[VerifiedEventSnapshot, ...] = ()
    previous_secrets: tuple[bytes, ...] = field(
        default_factory=tuple,
        repr=False,
    )

    def allows_mine(self, mine_id: str) -> bool:
        return "*" in self.mine_ids or mine_id in self.mine_ids

    def allows_confirmation(
        self,
        confirmation: HumanConfirmation,
    ) -> bool:
        return any(
            confirmer.matches(confirmation)
            for confirmer in self.authorized_confirmers
        )

    def has_verified_event_snapshot(
        self,
        *,
        event_codes: list[str],
        mine_id: str,
        window_start: datetime,
        window_end: datetime,
        evidence_sha256: set[str],
    ) -> bool:
        return any(
            snapshot.matches(
                mine_id=mine_id,
                window_start=window_start,
                window_end=window_end,
                event_codes=event_codes,
                evidence_sha256=evidence_sha256,
            )
            for snapshot in self.verified_event_snapshots
        )

    @property
    def verification_secrets(self) -> tuple[bytes, ...]:
        return (self.secret, *self.previous_secrets)


class ExternalAuthenticationError(ValueError):
    """An intentionally non-specific transport authentication failure."""


def _reject_surrogates(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("JCS strings cannot contain Unicode surrogates")


def _jcs_number(value: int | float) -> str:
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError("integer exceeds the interoperable JCS range")
        return str(value)
    if not math.isfinite(value):
        raise ValueError("JCS does not permit non-finite numbers")
    if value == 0:
        return "0"

    rendered = repr(value).lower()
    sign = ""
    if rendered.startswith("-"):
        sign, rendered = "-", rendered[1:]
    if "e" not in rendered:
        if rendered.endswith(".0"):
            rendered = rendered[:-2]
        return sign + rendered

    mantissa, raw_exponent = rendered.split("e", 1)
    exponent = int(raw_exponent)
    whole, dot, fraction = mantissa.partition(".")
    digits = (whole + (fraction if dot else "")).lstrip("0") or "0"
    decimal_position = len(whole) + exponent
    absolute = abs(value)
    if 1e-6 <= absolute < 1e21:
        if decimal_position <= 0:
            number = "0." + ("0" * -decimal_position) + digits
        elif decimal_position >= len(digits):
            number = digits + ("0" * (decimal_position - len(digits)))
        else:
            number = (
                digits[:decimal_position]
                + "."
                + digits[decimal_position:]
            )
        return sign + number

    scientific_exponent = decimal_position - 1
    coefficient = digits[0]
    if len(digits) > 1:
        coefficient += "." + digits[1:]
    exponent_sign = "+" if scientific_exponent >= 0 else ""
    return (
        sign
        + coefficient
        + "e"
        + exponent_sign
        + str(scientific_exponent)
    )


def jcs_canonical_json(value: Any) -> str:
    """Serialize the contract's I-JSON value subset per RFC 8785."""

    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        _reject_surrogates(value)
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    if isinstance(value, int | float):
        return _jcs_number(value)
    if isinstance(value, list | tuple):
        return "[" + ",".join(jcs_canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValueError("JCS object keys must be strings")
            _reject_surrogates(key)
        keys = sorted(value, key=lambda item: item.encode("utf-16be"))
        return (
            "{"
            + ",".join(
                jcs_canonical_json(key)
                + ":"
                + jcs_canonical_json(value[key])
                for key in keys
            )
            + "}"
        )
    raise TypeError(f"{type(value).__name__} is not a JSON value")


def canonical_json(value: Any) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


def enterprise_submission_payload_sha256(
    submission_or_payload: EnterpriseSubmission | Mapping[str, Any],
) -> str:
    if isinstance(submission_or_payload, EnterpriseSubmission):
        payload: Any = submission_or_payload.payload
    elif "payload" in submission_or_payload:
        payload = submission_or_payload["payload"]
    else:
        payload = dict(submission_or_payload)
    return sha256_bytes(jcs_canonical_json(payload).encode("utf-8"))


def validate_enterprise_submission_json(
    body: bytes | str,
) -> EnterpriseSubmission:
    """Validate the exact wire document and its payload-level JCS digest."""

    try:
        document = json.loads(
            body,
            object_pairs_hook=_json_object_without_duplicates,
        )
    except (
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise ValueError(
            "enterprise submission must be valid I-JSON"
        ) from error
    if not isinstance(document, dict):
        raise ValueError("enterprise submission must be a JSON object")
    supplied = document.get("payload_sha256")
    expected = enterprise_submission_payload_sha256(document)
    if not isinstance(supplied, str) or not hmac.compare_digest(
        supplied,
        expected,
    ):
        raise ValueError("payload_sha256 does not match payload")
    return EnterpriseSubmission.model_validate_json(body)


def to_governed_production_request(
    submission: EnterpriseSubmission,
) -> GovernedProductionRequest:
    """Strip enterprise provenance at the regulatory domain boundary."""

    payload = submission.payload
    context = payload.operational_context
    return GovernedProductionRequest(
        mine_id=payload.mine.mine_id,
        window_start=payload.window.window_start,
        window_end=payload.window.window_end,
        profile_id=payload.profile.profile_id,
        profile_version=payload.profile.profile_version,
        operational_context=OperationalContext(
            regime_code=context.regime_code,
            shift_code=context.shift_code,
            season_code=context.season_code,
            maintenance=context.maintenance,
            approved_event_codes=context.approved_event_codes,
            tags=context.tags,
        ),
        observations=[
            observation.to_governed()
            for observation in payload.observations
        ],
    )


def transport_signature(
    secret: bytes,
    *,
    method: str,
    path: str,
    client_id: str,
    timestamp: str,
    nonce: str,
    contract_version: str,
    content_sha256: str,
) -> str:
    material = "\n".join(
        (
            EXTERNAL_AUTH_CONTEXT,
            method.upper(),
            path,
            client_id,
            timestamp,
            nonce,
            contract_version,
            content_sha256,
        )
    )
    return hmac.new(
        secret,
        material.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _utc_rfc3339(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def sign_transport_headers(
    client: ExternalClient,
    body: bytes = b"",
    *,
    method: str,
    path: str,
    timestamp: datetime | str | None = None,
    nonce: str | None = None,
    contract_version: str = EXTERNAL_SUBMISSION_CONTRACT_VERSION,
) -> dict[str, str]:
    timestamp_text = (
        _utc_rfc3339(datetime.now(UTC))
        if timestamp is None
        else (
            _utc_rfc3339(timestamp)
            if isinstance(timestamp, datetime)
            else timestamp
        )
    )
    nonce_text = nonce or base64.urlsafe_b64encode(
        __import__("secrets").token_bytes(16)
    ).decode("ascii").rstrip("=")
    content_sha256 = sha256_bytes(body)
    signature = transport_signature(
        client.secret,
        method=method,
        path=path,
        client_id=client.client_id,
        timestamp=timestamp_text,
        nonce=nonce_text,
        contract_version=contract_version,
        content_sha256=content_sha256,
    )
    return {
        CLIENT_ID_HEADER: client.client_id,
        TIMESTAMP_HEADER: timestamp_text,
        NONCE_HEADER: nonce_text,
        CONTENT_SHA256_HEADER: content_sha256,
        SIGNATURE_VERSION_HEADER: EXTERNAL_SIGNATURE_VERSION,
        CONTRACT_VERSION_HEADER: contract_version,
        SIGNATURE_HEADER: signature,
    }


def _header(headers: Mapping[str, str], name: str) -> str:
    if name in headers:
        return str(headers[name]).strip()
    lowered = {str(key).lower(): value for key, value in headers.items()}
    value = lowered.get(name.lower())
    if value is None:
        raise ExternalAuthenticationError(
            "external request authentication failed"
        )
    return str(value).strip()


def _parse_auth_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ExternalAuthenticationError(
            "external request authentication failed"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExternalAuthenticationError(
            "external request authentication failed"
        )
    if parsed.utcoffset().total_seconds() != 0:
        raise ExternalAuthenticationError(
            "external request authentication failed"
        )
    return parsed.astimezone(UTC)


def authenticate_external_request(
    clients: Mapping[str, ExternalClient],
    headers: Mapping[str, str],
    body: bytes = b"",
    *,
    method: str,
    path: str,
    now: datetime | None = None,
) -> tuple[ExternalClient, datetime, str]:
    """Verify all transport material without exposing the failure reason."""

    try:
        client_id = _header(headers, CLIENT_ID_HEADER)
        timestamp = _header(headers, TIMESTAMP_HEADER)
        nonce = _header(headers, NONCE_HEADER)
        content_sha256 = _header(headers, CONTENT_SHA256_HEADER)
        signature_version = _header(headers, SIGNATURE_VERSION_HEADER)
        contract_version = _header(headers, CONTRACT_VERSION_HEADER)
        signature = _header(headers, SIGNATURE_HEADER)
        content_encoding = str(headers.get("Content-Encoding", "")).strip()
        if content_encoding not in {"", "identity"}:
            raise ValueError("unsupported content encoding")
        if (
            _SAFE_IDENTIFIER.fullmatch(client_id) is None
            or _SAFE_NONCE.fullmatch(nonce) is None
            or _SHA256.fullmatch(content_sha256) is None
            or _SHA256.fullmatch(signature) is None
            or signature_version != EXTERNAL_SIGNATURE_VERSION
            or contract_version != EXTERNAL_SUBMISSION_CONTRACT_VERSION
        ):
            raise ValueError("malformed authentication material")
        padding = "=" * (-len(nonce) % 4)
        if len(base64.urlsafe_b64decode(nonce + padding)) < 16:
            raise ValueError("nonce is too short")
        request_time = _parse_auth_timestamp(timestamp)
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now must be timezone-aware")
        if (
            abs((current.astimezone(UTC) - request_time).total_seconds())
            > EXTERNAL_AUTH_WINDOW_SECONDS
        ):
            raise ValueError("timestamp outside replay window")
        actual_content_hash = sha256_bytes(body)
        if not hmac.compare_digest(content_sha256, actual_content_hash):
            raise ValueError("content hash mismatch")
        client = clients.get(client_id)
        if client is None:
            raise ValueError("unknown client")
        matched = False
        for candidate in client.verification_secrets:
            expected = transport_signature(
                candidate,
                method=method,
                path=path,
                client_id=client_id,
                timestamp=timestamp,
                nonce=nonce,
                contract_version=contract_version,
                content_sha256=content_sha256,
            )
            matched = hmac.compare_digest(signature, expected) or matched
        if not matched:
            raise ValueError("signature mismatch")
        return client, request_time, nonce
    except ExternalAuthenticationError:
        raise
    except (ValueError, TypeError, base64.binascii.Error) as error:
        raise ExternalAuthenticationError(
            "external request authentication failed"
        ) from error


def parse_external_clients(value: str | None) -> dict[str, ExternalClient]:
    """Parse the server-only client registry from one environment value."""

    if value is None or not value.strip():
        return {}
    try:
        document = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(
            "MINEGUARD_EXTERNAL_CLIENTS_JSON must be valid JSON"
        ) from error
    entries = (
        document.get("clients")
        if isinstance(document, dict)
        else document
    )
    if not isinstance(entries, list):
        raise ValueError("external client registry must be a JSON array")
    clients: dict[str, ExternalClient] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("external client entries must be objects")
        client_id = str(entry.get("client_id") or "")
        enterprise_id = str(entry.get("enterprise_id") or "")
        mine_ids_value = entry.get("mine_ids")
        # Confirmers are regulator-owned database records. This optional
        # deployment field remains solely as a one-time compatibility import.
        confirmers_value = entry.get("authorized_confirmers", [])
        # Event snapshots are now registered in the regulator-owned database.
        # This optional field exists only for one-time legacy migration.
        event_snapshots_value = entry.get("verified_event_snapshots", [])
        secret_values = entry.get("secrets")
        if secret_values is None:
            secret_values = [entry.get("secret")]
        if (
            _SAFE_IDENTIFIER.fullmatch(client_id) is None
            or _SAFE_IDENTIFIER.fullmatch(enterprise_id) is None
            or not isinstance(mine_ids_value, list)
            or not mine_ids_value
            or not isinstance(confirmers_value, list)
            or not isinstance(event_snapshots_value, list)
            or not isinstance(secret_values, list)
            or not secret_values
        ):
            raise ValueError("external client entry is invalid")
        mine_ids = frozenset(str(item) for item in mine_ids_value)
        if any(
            item != "*" and _SAFE_IDENTIFIER.fullmatch(item) is None
            for item in mine_ids
        ):
            raise ValueError("external client mine_ids are invalid")
        authorized_confirmers: list[AuthorizedConfirmer] = []
        seen_confirmer_ids: set[str] = set()
        for confirmer in confirmers_value:
            if not isinstance(confirmer, dict):
                raise ValueError(
                    "external client authorized_confirmers are invalid"
                )
            confirmer_id = confirmer.get("confirmer_id")
            confirmer_name = confirmer.get("confirmer_name")
            confirmer_roles_value = confirmer.get("confirmer_roles")
            methods_value = confirmer.get(
                "confirmation_methods",
                ["authenticated_click"],
            )
            if (
                not isinstance(confirmer_id, str)
                or _SAFE_IDENTIFIER.fullmatch(confirmer_id) is None
                or confirmer_id in seen_confirmer_ids
                or not isinstance(confirmer_name, str)
                or not confirmer_name.strip()
                or len(confirmer_name.strip()) > 128
                or not isinstance(confirmer_roles_value, list)
                or not confirmer_roles_value
                or not isinstance(methods_value, list)
                or not methods_value
            ):
                raise ValueError(
                    "external client authorized_confirmers are invalid"
                )
            roles = frozenset(
                str(role).strip() for role in confirmer_roles_value
            )
            methods = frozenset(str(method) for method in methods_value)
            if (
                len(roles) != len(confirmer_roles_value)
                or any(not role or len(role) > 128 for role in roles)
                or methods != {"authenticated_click"}
            ):
                raise ValueError(
                    "only authenticated_click confirmation is supported; "
                    "qualified signatures and seals require a verifier"
                )
            seen_confirmer_ids.add(confirmer_id)
            authorized_confirmers.append(
                AuthorizedConfirmer(
                    confirmer_id=confirmer_id,
                    confirmer_name=confirmer_name.strip(),
                    confirmer_roles=roles,
                    confirmation_methods=methods,
                )
            )

        event_snapshots: list[VerifiedEventSnapshot] = []
        seen_snapshots: set[tuple[str, str, str]] = set()
        for snapshot in event_snapshots_value:
            if not isinstance(snapshot, dict):
                raise ValueError(
                    "external client verified_event_snapshots are invalid"
                )
            event_mine_id = snapshot.get("mine_id")
            event_codes_value = snapshot.get("event_codes")
            evidence_sha256 = snapshot.get("evidence_sha256")
            try:
                window_start = _parse_auth_timestamp(
                    str(snapshot.get("window_start") or "")
                )
                window_end = _parse_auth_timestamp(
                    str(snapshot.get("window_end") or "")
                )
            except ExternalAuthenticationError as error:
                raise ValueError(
                    "external client verified_event_snapshots are invalid"
                ) from error
            event_codes = (
                tuple(sorted(str(code) for code in event_codes_value))
                if isinstance(event_codes_value, list)
                else ()
            )
            key = (
                str(event_mine_id),
                window_start.isoformat(),
                window_end.isoformat(),
            )
            if (
                not isinstance(event_mine_id, str)
                or (
                    "*" not in mine_ids
                    and event_mine_id not in mine_ids
                )
                or _SAFE_IDENTIFIER.fullmatch(event_mine_id) is None
                or not isinstance(event_codes_value, list)
                or len(event_codes_value) > 32
                or any(
                    not isinstance(code, str)
                    for code in event_codes_value
                )
                or len(event_codes) != len(set(event_codes))
                or any(
                    len(code) > 64
                    or _SAFE_IDENTIFIER.fullmatch(code) is None
                    for code in event_codes
                )
                or not isinstance(evidence_sha256, str)
                or _SHA256.fullmatch(evidence_sha256) is None
                or window_end <= window_start
                or key in seen_snapshots
            ):
                raise ValueError(
                    "external client verified_event_snapshots are invalid"
                )
            seen_snapshots.add(key)
            event_snapshots.append(
                VerifiedEventSnapshot(
                    mine_id=event_mine_id,
                    window_start=window_start,
                    window_end=window_end,
                    event_codes=event_codes,
                    evidence_sha256=evidence_sha256,
                )
            )
        secrets = tuple(
            str(secret).encode("utf-8")
            for secret in secret_values
            if isinstance(secret, str)
        )
        if len(secrets) != len(secret_values) or any(
            len(secret) < 32 for secret in secrets
        ):
            raise ValueError(
                "each external client secret must be at least 32 bytes"
            )
        if client_id in clients:
            raise ValueError("external client_id values must be unique")
        clients[client_id] = ExternalClient(
            client_id=client_id,
            enterprise_id=enterprise_id,
            secret=secrets[0],
            previous_secrets=secrets[1:],
            mine_ids=mine_ids,
            authorized_confirmers=tuple(authorized_confirmers),
            verified_event_snapshots=tuple(event_snapshots),
        )
    return clients


def _provenance_times(payload: EnterpriseSubmissionPayload) -> list[datetime]:
    times: list[datetime] = []

    def visit(value: Any) -> None:
        if isinstance(value, ProvenanceRecord):
            times.append(value.captured_at)
            return
        if hasattr(value, "model_dump"):
            for field_name in value.__class__.model_fields:
                visit(getattr(value, field_name))
            return
        if isinstance(value, list | tuple):
            for item in value:
                visit(item)

    visit(payload)
    return times


def _llm_extraction_paths(
    payload: EnterpriseSubmissionPayload,
) -> set[str]:
    paths: set[str] = set()

    def visit(value: Any, path: str) -> None:
        if isinstance(value, ProvenanceRecord):
            if value.acquisition_method == "llm_extraction":
                paths.add(path)
            return
        if hasattr(value, "model_dump"):
            for field_name in value.__class__.model_fields:
                next_path = f"{path}/{field_name}"
                visit(getattr(value, field_name), next_path)
            return
        if isinstance(value, list | tuple):
            for index, item in enumerate(value):
                visit(item, f"{path}/{index}")

    visit(payload, "/payload")
    business_paths: set[str] = set()
    for path in paths:
        if "/field_provenance/" not in path:
            continue
        owner_path, provenance_path = path.split(
            "/field_provenance/",
            1,
        )
        field_name = provenance_path.split("/", 1)[0]
        business_paths.add(f"{owner_path}/{field_name}")
    return business_paths


__all__ = [
    "AuthorizedConfirmer",
    "CLIENT_ID_HEADER",
    "CONTENT_SHA256_HEADER",
    "CONTRACT_VERSION_HEADER",
    "EXTERNAL_AUTH_WINDOW_SECONDS",
    "EXTERNAL_CAPABILITIES_CONTRACT_VERSION",
    "EXTERNAL_NONCE_RETENTION_SECONDS",
    "EXTERNAL_RECEIPT_CONTRACT_VERSION",
    "EXTERNAL_SIGNATURE_VERSION",
    "EXTERNAL_SUBMISSION_CONTRACT_VERSION",
    "EnterpriseSubmission",
    "ExternalAuthenticationError",
    "ExternalClient",
    "NONCE_HEADER",
    "SIGNATURE_HEADER",
    "SIGNATURE_VERSION_HEADER",
    "SIGNED_HEADERS",
    "TIMESTAMP_HEADER",
    "VerifiedEventSnapshot",
    "authenticate_external_request",
    "canonical_json",
    "enterprise_submission_payload_sha256",
    "jcs_canonical_json",
    "parse_external_clients",
    "sha256_bytes",
    "sign_transport_headers",
    "to_governed_production_request",
    "transport_signature",
    "validate_enterprise_submission_json",
]
