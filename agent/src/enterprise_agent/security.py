"""Observation canonicalisation and HTTP transport authentication.

Source-observation signing deliberately does not live in the enterprise agent.
Only a source gateway and the regulatory platform may possess that symmetric
key.  This module exposes the canonical payload so the agent can detect stale
payload digests without attempting to authenticate an HMAC.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from typing import Any
from urllib.parse import urlsplit

from .util import (
    parse_aware_datetime,
    sha256_json,
    utc_text,
)

TRANSPORT_SIGNATURE_VERSION = "hmac-sha256-v1"
CONTRACT_VERSION = "enterprise-submission-v1"
MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _secret_bytes(secret: bytes | str) -> bytes:
    if isinstance(secret, str):
        encoded = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        encoded = secret
    else:
        raise TypeError("HMAC secret must be bytes or str")
    if not encoded:
        raise ValueError("HMAC secret must not be empty")
    return encoded


def observation_payload(observation: dict[str, Any]) -> dict[str, Any]:
    normalised = normalize_observation(observation)
    required = (
        "source_id",
        "observation_id",
        "value",
        "unit",
        "observed_at",
        "received_at",
        "sequence_no",
        "revision",
    )
    payload = {key: normalised[key] for key in required}
    for key in ("interval_start", "interval_end", "reset_before"):
        value = normalised.get(key)
        if value is not None:
            payload[key] = value
    # V1 excludes fields retaining their defaults.
    if payload.get("reset_before") is False:
        payload.pop("reset_before")
    return payload


def observation_review_fingerprint(
    observation: dict[str, Any],
) -> str | None:
    """Bind a human review to the exact current observation and credentials.

    ``metric_code`` is enterprise-local display context and is not covered by
    the source HMAC, but changing it can change what a human believes they are
    reviewing.  It is therefore covered here together with the normalised
    source payload and opaque gateway credentials.
    """

    try:
        payload_sha256 = observation.get("payload_sha256")
        signature = observation.get("signature")
        metric_code = observation.get("metric_code")
        if (
            not isinstance(payload_sha256, str)
            or not isinstance(signature, str)
            or not isinstance(metric_code, str)
        ):
            return None
        return sha256_json(
            {
                "source_payload": observation_payload(observation),
                "metric_code": metric_code,
                "gateway_credentials_sha256": sha256_json(
                    {
                        "payload_sha256": payload_sha256,
                        "signature": signature,
                    }
                ),
            }
        )
    except (KeyError, TypeError, ValueError):
        return None


def normalize_observation(
    observation: dict[str, Any],
) -> dict[str, Any]:
    """Normalise the V1 wire types before hashing or transmission.

    In particular, the regulatory model represents ``value`` as binary64. An
    integer-looking JSON number must therefore be signed as ``7100.0``, not
    ``7100``. All timestamps use UTC ``Z`` so equivalent offsets have one
    signature representation.
    """

    def text(field: str, maximum: int) -> str:
        value = observation.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string")
        clean = value.strip()
        if len(clean) > maximum:
            raise ValueError(f"{field} is too long")
        return clean

    raw_value = observation.get("value")
    if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
        raise ValueError("value must be numeric")
    value = float(raw_value)
    if not math.isfinite(value):
        raise ValueError("value must be finite")

    def timestamp(field: str) -> str:
        return utc_text(parse_aware_datetime(observation.get(field), field))

    observed_at = timestamp("observed_at")
    received_at = timestamp("received_at")
    if parse_aware_datetime(received_at, "received_at") < parse_aware_datetime(
        observed_at, "observed_at"
    ):
        raise ValueError("received_at must not be earlier than observed_at")

    interval_start = observation.get("interval_start")
    interval_end = observation.get("interval_end")
    if (interval_start is None) != (interval_end is None):
        raise ValueError("interval_start and interval_end must be paired")
    normalised_start = (
        timestamp("interval_start") if interval_start is not None else None
    )
    normalised_end = timestamp("interval_end") if interval_end is not None else None
    if normalised_start is not None and parse_aware_datetime(
        normalised_end, "interval_end"
    ) <= parse_aware_datetime(normalised_start, "interval_start"):
        raise ValueError("interval_end must be later than interval_start")

    sequence_no = observation.get("sequence_no")
    revision = observation.get("revision")
    if (
        isinstance(sequence_no, bool)
        or not isinstance(sequence_no, int)
        or sequence_no < 0
        or sequence_no > MAX_SAFE_INTEGER
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or revision < 0
        or revision > MAX_SAFE_INTEGER
    ):
        raise ValueError(
            "sequence_no and revision must be non-negative safe integers"
        )
    reset_before = observation.get("reset_before", False)
    if not isinstance(reset_before, bool):
        raise ValueError("reset_before must be boolean")
    return {
        "source_id": text("source_id", 128),
        "observation_id": text("observation_id", 256),
        "value": value,
        "unit": text("unit", 32),
        "observed_at": observed_at,
        "received_at": received_at,
        "interval_start": normalised_start,
        "interval_end": normalised_end,
        "reset_before": reset_before,
        "sequence_no": sequence_no,
        "revision": revision,
    }


def transport_headers(
    *,
    method: str,
    url: str,
    body: bytes,
    secret: bytes | str,
    client_id: str,
    timestamp: str,
    nonce: str,
    contract_version: str = CONTRACT_VERSION,
) -> dict[str, str]:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        raise ValueError("V1 signed endpoints must not contain a query")
    body_hash = hashlib.sha256(body).hexdigest()
    if not client_id or len(client_id) > 128 or not client_id.isascii():
        raise ValueError("transport client_id must be 1-128 ASCII characters")
    components = "\n".join(
        (
            "ENTERPRISE-SUBMISSION-HTTP-HMAC-SHA256-V1",
            method.upper(),
            path,
            client_id,
            timestamp,
            nonce,
            contract_version,
            body_hash,
        )
    ).encode("utf-8")
    signature = hmac.new(
        _secret_bytes(secret),
        components,
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Enterprise-Client-Id": client_id,
        "X-Enterprise-Timestamp": timestamp,
        "X-Enterprise-Nonce": nonce,
        "X-Enterprise-Content-SHA256": body_hash,
        "X-Enterprise-Signature-Version": TRANSPORT_SIGNATURE_VERSION,
        "X-Enterprise-Contract-Version": contract_version,
        "X-Enterprise-Signature": signature,
    }
