"""Regulator-owned adapter for the independent mine edge telemetry wire API.

The edge service and the regulatory platform intentionally do not import each
other.  This module is the platform-side implementation of the neutral JSON
and HMAC contract in ``contracts/``; the contract directory is documentation
and test data, not a runtime dependency.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import re
from typing import Annotated, Any, Literal, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AwareDatetime, Field, ValidationInfo, model_validator

from .models import StrictModel


EDGE_BATCH_CONTRACT_VERSION = "edge-telemetry-batch-v1"
EDGE_RECEIPT_CONTRACT_VERSION = "edge-telemetry-receipt-v1"
EDGE_CAPABILITIES_CONTRACT_VERSION = "edge-telemetry-capabilities-v1"
EDGE_SIGNATURE_VERSION = "hmac-sha256-v1"
EDGE_AUTH_CONTEXT = "MINE-EDGE-TELEMETRY-HTTP-HMAC-SHA256-V1"
EDGE_AUTH_WINDOW_SECONDS = 300
EDGE_NONCE_RETENTION_SECONDS = 600

CLIENT_ID_HEADER = "X-Edge-Client-Id"
TIMESTAMP_HEADER = "X-Edge-Timestamp"
NONCE_HEADER = "X-Edge-Nonce"
CONTENT_SHA256_HEADER = "X-Edge-Content-SHA256"
SIGNATURE_VERSION_HEADER = "X-Edge-Signature-Version"
CONTRACT_VERSION_HEADER = "X-Edge-Contract-Version"
SIGNATURE_HEADER = "X-Edge-Signature"
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
_SAFE_EDGE_CLIENT_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,87}$"
)
_NAMESPACED_BATCH_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,87}--batch_[0-9a-f]{32}$"
)
_SAFE_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,86}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_TIMEZONE_OFFSET = re.compile(r"^[+-](?:[01]\d|2[0-3]):[0-5]\d$")
_TIMEZONE_NAME = re.compile(
    r"^[A-Za-z][A-Za-z0-9._+-]*(?:/[A-Za-z0-9._+-]+)+$"
)

MetricCode = Literal[
    "production.output_t",
    "production.belt_instantaneous_t_h",
    "production.belt_speed_m_s",
    "production.belt_scale_running",
    "production.belt_scale_fault",
    "electricity.total_kwh",
    "electricity.production_kwh",
    "electricity.ventilation_kwh",
    "electricity.drainage_kwh",
    "electricity.compressed_air_kwh",
    "electricity.hoisting_kwh",
    "electricity.wash_plant_kwh",
    "personnel.underground_count",
    "personnel.area_count",
    "personnel.unauthorized_entry_count",
    "personnel.no_card_entry_count",
    "personnel.person_card_mismatch_count",
    "personnel.overtime_count",
    "methane.concentration_percent",
    "ventilation.airflow_m3_min",
    "ventilation.pressure_pa",
    "ventilation.speed_m_s",
    "ventilation.main_fan_running",
    "ventilation.main_fan_fault",
    "ventilation.main_fan_changeover",
    "explosive.issued_kg",
    "explosive.used_kg",
    "explosive.remaining_kg",
    "detonator.issued_count",
    "detonator.used_count",
    "detonator.remaining_count",
    "source.heartbeat_age_seconds",
    "source.consecutive_failures",
    "source.missing_state",
    "coal.use_t",
    "transport.shipped_t",
    "sales.invoice_t",
]


class EdgeIntervalWindow(StrictModel):
    start: AwareDatetime
    end: AwareDatetime
    timezone: Annotated[str, Field(min_length=1, max_length=64)]
    aggregation: Literal[
        "window_total",
        "interval_delta",
        "cumulative_register",
        "snapshot",
        "instantaneous_rate",
    ]
    shift_code: Annotated[
        str,
        Field(
            min_length=1,
            max_length=64,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
        ),
    ] | None = None

    @model_validator(mode="after")
    def validate_window(self) -> "EdgeIntervalWindow":
        if self.end <= self.start:
            raise ValueError("interval.end must be later than interval.start")
        timezone_name = self.timezone
        if not _TIMEZONE_OFFSET.fullmatch(timezone_name):
            if timezone_name != "UTC" and _TIMEZONE_NAME.fullmatch(
                timezone_name
            ) is None:
                raise ValueError(
                    "interval.timezone must be UTC, an offset, or an IANA name"
                )
            try:
                ZoneInfo(timezone_name)
            except ZoneInfoNotFoundError as error:
                raise ValueError("interval.timezone is unknown") from error
        return self


class ObservationQuality(StrictModel):
    valid: bool
    completeness: Annotated[float, Field(ge=0.0, le=1.0)]
    timeliness: Annotated[float, Field(ge=0.0, le=1.0)]
    device_health: Literal["healthy", "degraded", "fault", "unknown"]
    clock_synchronized: bool
    flags: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=128)]],
        Field(max_length=64),
    ]

    @model_validator(mode="after")
    def validate_unique_flags(self) -> "ObservationQuality":
        if len(self.flags) != len(set(self.flags)):
            raise ValueError("quality flags must be unique")
        return self


class ManualAttestation(StrictModel):
    actor_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    actor_name: Annotated[str, Field(min_length=1, max_length=128)]
    recorded_at: AwareDatetime
    reason: Annotated[str, Field(min_length=1, max_length=1000)]


class EdgeObservation(StrictModel):
    source_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    observation_id: Annotated[str, Field(min_length=1, max_length=256)]
    metric_code: MetricCode
    value: Annotated[float, Field(ge=-1e15, le=1e15)]
    unit: Literal[
        "t",
        "kg",
        "kWh",
        "person",
        "count",
        "%",
        "m3/min",
        "Pa",
        "m/s",
        "t/h",
        "s",
    ]
    location_code: Annotated[str, Field(min_length=1, max_length=128)]
    observed_at: AwareDatetime
    received_at: AwareDatetime
    sequence_no: Annotated[int, Field(ge=0, le=_MAX_SAFE_INTEGER)]
    revision: Annotated[int, Field(ge=0, le=_MAX_SAFE_INTEGER)]
    acquisition_mode: Literal[
        "automatic_adapter",
        "file_drop",
        "api_poll",
        "authenticated_manual_entry",
    ]
    source_record_id: Annotated[str, Field(min_length=1, max_length=256)]
    source_record_sha256: Annotated[
        str,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ]
    source_signature: Annotated[
        str | None,
        Field(pattern=r"^[0-9a-f]{64}$"),
    ] = None
    status_code: Annotated[str | None, Field(max_length=64)] = None
    interval: EdgeIntervalWindow | None = None
    quality: ObservationQuality
    manual_attestation: ManualAttestation | None = None

    @model_validator(mode="after")
    def validate_provenance_and_time(self) -> "EdgeObservation":
        if self.received_at < self.observed_at:
            raise ValueError("received_at cannot predate observed_at")
        if self.interval is not None and self.interval.end > self.received_at:
            raise ValueError("interval.end cannot be later than received_at")
        manual = self.acquisition_mode == "authenticated_manual_entry"
        if manual != (self.manual_attestation is not None):
            raise ValueError(
                "manual_attestation is required only for "
                "authenticated_manual_entry"
            )
        exact_units: dict[str, set[str]] = {
            "production.belt_instantaneous_t_h": {"t/h"},
            "production.belt_speed_m_s": {"m/s"},
            "production.belt_scale_running": {"count"},
            "production.belt_scale_fault": {"count"},
            "personnel.area_count": {"person"},
            "personnel.unauthorized_entry_count": {"count"},
            "personnel.no_card_entry_count": {"count"},
            "personnel.person_card_mismatch_count": {"count"},
            "personnel.overtime_count": {"count"},
            "source.heartbeat_age_seconds": {"s"},
            "source.consecutive_failures": {"count"},
            "source.missing_state": {"count"},
        }
        expected_units: dict[str, set[str]] = {
            "production.": {"t"},
            "electricity.": {"kWh"},
            "personnel.": {"person", "count"},
            "methane.": {"%"},
            "ventilation.airflow": {"m3/min"},
            "ventilation.pressure": {"Pa"},
            "ventilation.speed": {"m/s"},
            "ventilation.main_fan": {"count"},
            "explosive.": {"kg"},
            "detonator.": {"count"},
            "coal.": {"t"},
            "transport.": {"t"},
            "sales.": {"t"},
        }
        units = exact_units.get(self.metric_code)
        if units is None:
            units = next(
                (
                    allowed
                    for prefix, allowed in expected_units.items()
                    if self.metric_code.startswith(prefix)
                ),
                None,
            )
        if units is not None and self.unit not in units:
            raise ValueError(
                f"unit {self.unit!r} is invalid for {self.metric_code}"
            )
        if (
            self.metric_code.endswith("_count")
            or self.metric_code.startswith("detonator.")
            or self.metric_code
            in {"source.consecutive_failures", "source.missing_state"}
        ) and not self.value.is_integer():
            raise ValueError("count observations must contain integer values")
        if (
            self.metric_code.startswith("ventilation.main_fan_")
            or self.metric_code.startswith("production.belt_scale_")
            or self.metric_code == "source.missing_state"
        ) and self.value not in {0.0, 1.0}:
            raise ValueError(
                "binary equipment state observations must contain 0 or 1"
            )
        if self.value < 0:
            raise ValueError("telemetry values cannot be negative")
        if (
            self.metric_code.startswith("source.")
            and self.location_code != self.source_id
        ):
            raise ValueError(
                "source.* location_code must equal source_id"
            )
        return self


class EdgeRuleProfileReference(StrictModel):
    profile_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    version: Annotated[int, Field(ge=1, le=2_147_483_647)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class EdgeLocalAlert(StrictModel):
    local_alert_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    rule_code: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    level: Literal["blue", "yellow", "orange", "red"]
    detected_at: AwareDatetime
    location_code: Annotated[str, Field(min_length=1, max_length=128)]
    observation_ids: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=256)]],
        Field(min_length=1, max_length=100),
    ]
    summary: Annotated[str, Field(min_length=1, max_length=1000)]
    advisory_only: Literal[True]

    @model_validator(mode="after")
    def validate_observation_ids(self) -> "EdgeLocalAlert":
        if len(self.observation_ids) != len(set(self.observation_ids)):
            raise ValueError("local alert observation_ids must be unique")
        return self


class EdgeTelemetryBatch(StrictModel):
    schema_version: Literal["edge-telemetry-batch-v1"]
    batch_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    client_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    mine_id: Annotated[
        str,
        Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    ]
    sent_at: AwareDatetime
    sequence_start: Annotated[int, Field(ge=0, le=_MAX_SAFE_INTEGER)]
    sequence_end: Annotated[int, Field(ge=0, le=_MAX_SAFE_INTEGER)]
    rule_profile: EdgeRuleProfileReference
    observations: Annotated[
        list[EdgeObservation],
        Field(min_length=1, max_length=10_000),
    ]
    local_alerts: Annotated[list[EdgeLocalAlert], Field(max_length=1000)]

    @model_validator(mode="after")
    def validate_batch(self, info: ValidationInfo) -> "EdgeTelemetryBatch":
        allow_legacy_batch_id = bool(
            info.context
            and info.context.get("allow_legacy_batch_id", False)
        )
        if (
            not allow_legacy_batch_id
            and not valid_edge_batch_id(self.batch_id, self.client_id)
        ):
            raise ValueError(
                "batch_id must equal "
                "{client_id}--batch_{32 lowercase hex characters}"
            )
        if self.sequence_end < self.sequence_start:
            raise ValueError("sequence_end cannot predate sequence_start")
        sequence_values = [item.sequence_no for item in self.observations]
        if min(sequence_values) != self.sequence_start:
            raise ValueError("sequence_start does not match observations")
        if max(sequence_values) != self.sequence_end:
            raise ValueError("sequence_end does not match observations")
        identities = [
            (item.observation_id, item.revision)
            for item in self.observations
        ]
        if len(identities) != len(set(identities)):
            raise ValueError(
                "observation_id and revision pairs must be unique"
            )
        observation_ids = {item.observation_id for item in self.observations}
        for local_alert in self.local_alerts:
            if not set(local_alert.observation_ids).issubset(observation_ids):
                raise ValueError(
                    "local alerts may only reference batch observations"
                )
        return self


@dataclass(frozen=True)
class EdgeClient:
    client_id: str
    secret: bytes = field(repr=False)
    mine_ids: frozenset[str]
    previous_secrets: tuple[bytes, ...] = field(
        default_factory=tuple,
        repr=False,
    )

    def allows_mine(self, mine_id: str) -> bool:
        return "*" in self.mine_ids or mine_id in self.mine_ids

    @property
    def verification_secrets(self) -> tuple[bytes, ...]:
        return (self.secret, *self.previous_secrets)


class EdgeAuthenticationError(ValueError):
    """Intentionally non-specific transport authentication failure."""


def valid_edge_batch_id(batch_id: str, client_id: str) -> bool:
    """Bind the global batch namespace to the authenticated edge client."""

    prefix = f"{client_id}--batch_"
    return (
        _SAFE_EDGE_CLIENT_ID.fullmatch(client_id) is not None
        and _NAMESPACED_BATCH_ID.fullmatch(batch_id) is not None
        and batch_id.startswith(prefix)
        and len(batch_id) == len(prefix) + 32
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
            EDGE_AUTH_CONTEXT,
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
    client: EdgeClient,
    body: bytes,
    *,
    method: str = "POST",
    path: str = "/v1/edge-telemetry-batches",
    timestamp: datetime | str | None = None,
    nonce: str | None = None,
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
    digest = sha256_bytes(body)
    signature = transport_signature(
        client.secret,
        method=method,
        path=path,
        client_id=client.client_id,
        timestamp=timestamp_text,
        nonce=nonce_text,
        contract_version=EDGE_BATCH_CONTRACT_VERSION,
        content_sha256=digest,
    )
    return {
        CLIENT_ID_HEADER: client.client_id,
        TIMESTAMP_HEADER: timestamp_text,
        NONCE_HEADER: nonce_text,
        CONTENT_SHA256_HEADER: digest,
        SIGNATURE_VERSION_HEADER: EDGE_SIGNATURE_VERSION,
        CONTRACT_VERSION_HEADER: EDGE_BATCH_CONTRACT_VERSION,
        SIGNATURE_HEADER: signature,
    }


def _header(headers: Mapping[str, str], name: str) -> str:
    if name in headers:
        return str(headers[name]).strip()
    lowered = {str(key).lower(): value for key, value in headers.items()}
    value = lowered.get(name.lower())
    if value is None:
        raise EdgeAuthenticationError(
            "edge request authentication failed"
        )
    return str(value).strip()


def _parse_auth_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EdgeAuthenticationError(
            "edge request authentication failed"
        ) from error
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        raise EdgeAuthenticationError(
            "edge request authentication failed"
        )
    return parsed.astimezone(UTC)


def authenticate_edge_request(
    clients: Mapping[str, EdgeClient],
    headers: Mapping[str, str],
    body: bytes,
    *,
    method: str,
    path: str,
    now: datetime | None = None,
) -> tuple[EdgeClient, datetime, str, str]:
    """Verify all raw-body transport material without leaking failure reason."""

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
            _SAFE_EDGE_CLIENT_ID.fullmatch(client_id) is None
            or _SAFE_NONCE.fullmatch(nonce) is None
            or _SHA256.fullmatch(content_sha256) is None
            or _SHA256.fullmatch(signature) is None
            or signature_version != EDGE_SIGNATURE_VERSION
            or contract_version != EDGE_BATCH_CONTRACT_VERSION
        ):
            raise ValueError("malformed authentication material")
        padding = "=" * (-len(nonce) % 4)
        if len(base64.urlsafe_b64decode(nonce + padding)) < 16:
            raise ValueError("nonce is too short")
        request_time = _parse_auth_timestamp(timestamp)
        current = (now or datetime.now(UTC)).astimezone(UTC)
        if abs((current - request_time).total_seconds()) > (
            EDGE_AUTH_WINDOW_SECONDS
        ):
            raise ValueError("timestamp outside replay window")
        if not hmac.compare_digest(content_sha256, sha256_bytes(body)):
            raise ValueError("content hash mismatch")
        client = clients.get(client_id)
        if client is None:
            raise ValueError("unknown client")
        matched = False
        for secret in client.verification_secrets:
            expected = transport_signature(
                secret,
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
        return client, request_time, nonce, content_sha256
    except EdgeAuthenticationError:
        raise
    except (ValueError, TypeError, base64.binascii.Error) as error:
        raise EdgeAuthenticationError(
            "edge request authentication failed"
        ) from error


def parse_edge_clients(value: str | None) -> dict[str, EdgeClient]:
    """Parse the server-only edge client registry from an environment value."""

    if value is None or not value.strip():
        return {}
    try:
        document: Any = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(
            "MINEGUARD_EDGE_CLIENTS_JSON must be valid JSON"
        ) from error
    entries = document.get("clients") if isinstance(document, dict) else document
    if not isinstance(entries, list):
        raise ValueError("edge client registry must be a JSON array")
    clients: dict[str, EdgeClient] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("edge client entries must be objects")
        client_id = str(entry.get("client_id") or "")
        mine_values = entry.get("mine_ids")
        secret_values = entry.get("secrets")
        if secret_values is None:
            secret_values = [entry.get("secret")]
        if (
            _SAFE_EDGE_CLIENT_ID.fullmatch(client_id) is None
            or client_id in clients
            or not isinstance(mine_values, list)
            or not mine_values
            or not isinstance(secret_values, list)
            or not secret_values
        ):
            raise ValueError("edge client entry is invalid")
        mine_ids = frozenset(str(item) for item in mine_values)
        if len(mine_ids) != len(mine_values) or any(
            mine_id != "*" and _SAFE_IDENTIFIER.fullmatch(mine_id) is None
            for mine_id in mine_ids
        ):
            raise ValueError("edge client mine_ids are invalid")
        decoded: list[bytes] = []
        for encoded in secret_values:
            if not isinstance(encoded, str):
                raise ValueError("edge client secrets must be base64 strings")
            try:
                secret = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error) as error:
                raise ValueError(
                    "edge client secrets must be valid base64"
                ) from error
            if len(secret) < 32:
                raise ValueError(
                    "edge client secrets must decode to at least 32 bytes"
                )
            decoded.append(secret)
        if len(set(decoded)) != len(decoded):
            raise ValueError("edge client secrets must be unique")
        clients[client_id] = EdgeClient(
            client_id=client_id,
            secret=decoded[0],
            previous_secrets=tuple(decoded[1:]),
            mine_ids=mine_ids,
        )
    return clients


def validate_edge_batch_json(
    body: bytes | str,
    *,
    allow_legacy_batch_id: bool = False,
) -> EdgeTelemetryBatch:
    """Reject duplicate JSON keys before strict Pydantic validation."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object member: {key}")
            result[key] = value
        return result

    try:
        document = json.loads(body, object_pairs_hook=unique_object)
    except (
        TypeError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        raise ValueError("edge telemetry must be valid I-JSON") from error
    if not isinstance(document, dict):
        raise ValueError("edge telemetry must be a JSON object")
    return EdgeTelemetryBatch.model_validate(
        document,
        context={"allow_legacy_batch_id": allow_legacy_batch_id},
    )
