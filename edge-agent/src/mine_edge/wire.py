"""Independent edge-telemetry-batch-v1 wire protocol and HMAC signing."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from .models import utc_now

SCHEMA_VERSION = "edge-telemetry-batch-v1"
RECEIPT_SCHEMA_VERSION = "edge-telemetry-receipt-v1"
CONTRACT_VERSION = "edge-telemetry-batch-v1"
SIGNATURE_VERSION = "hmac-sha256-v1"
INGEST_PATH = "/v1/edge-telemetry-batches"
AUTH_CONTEXT = "MINE-EDGE-TELEMETRY-HTTP-HMAC-SHA256-V1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
_URI_REFERENCE = re.compile(
    r"^(?:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*$"
)
_EDGE_CLIENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,87}$")
_LEGACY_IDENTIFIER = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
)
_LEGACY_BATCH_ID = re.compile(r"^batch_[0-9a-f]{32}$")
_NAMESPACED_BATCH_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,87}--batch_[0-9a-f]{32}$"
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class EdgeBatch:
    batch_id: str
    client_id: str
    mine_id: str
    observations: list[dict[str, Any]]
    local_alerts: list[dict[str, Any]]
    sent_at: str
    sequence_start: int
    sequence_end: int
    rule_profile: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "batch_id": self.batch_id,
            "client_id": self.client_id,
            "mine_id": self.mine_id,
            "sent_at": self.sent_at,
            "sequence_start": self.sequence_start,
            "sequence_end": self.sequence_end,
            "rule_profile": self.rule_profile,
            "observations": self.observations,
            "local_alerts": self.local_alerts,
        }

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class EdgeReceipt:
    schema_version: str
    receipt_id: str
    batch_id: str
    client_id: str
    mine_id: str
    status: str
    received_at: str
    body_sha256: str
    accepted_observations: int
    rejected_observations: int
    regulatory_outcome: str
    links: dict[str, str]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON 包含重复字段：{key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON 包含非标准数值：{value}")


def _required_string(
    document: dict[str, Any], name: str, *, maximum: int = 128
) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(f"回执字段 {name} 必须是 1-{maximum} 字符的字符串")
    return value


def _bounded_integer(document: dict[str, Any], name: str) -> int:
    value = document.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10000:
        raise ValueError(f"回执字段 {name} 必须是 0-10000 的整数")
    return value


def _uri_reference(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"回执字段 links.{name} 必须是 URI reference 字符串")
    if _URI_REFERENCE.fullmatch(value) is None:
        raise ValueError(f"回执字段 links.{name} 不是合法 URI reference")
    try:
        urlsplit(value)
    except ValueError as error:
        raise ValueError(f"回执字段 links.{name} 不是合法 URI reference") from error
    return value


def valid_namespaced_batch_id(batch_id: str, client_id: str) -> bool:
    expected_prefix = f"{client_id}--batch_"
    return (
        _EDGE_CLIENT_ID.fullmatch(client_id) is not None
        and _NAMESPACED_BATCH_ID.fullmatch(batch_id) is not None
        and batch_id.startswith(expected_prefix)
        and len(batch_id) == len(expected_prefix) + 32
    )


def valid_legacy_batch_id(batch_id: str, client_id: str) -> bool:
    """Recognize only batch ids emitted by edge-agent releases before namespacing."""

    return (
        _LEGACY_IDENTIFIER.fullmatch(client_id) is not None
        and _LEGACY_BATCH_ID.fullmatch(batch_id) is not None
    )


def parse_edge_receipt(
    raw_body: bytes,
    *,
    allow_legacy_batch_id: bool = False,
) -> EdgeReceipt:
    """Strictly parse the independent ``edge-telemetry-receipt-v1`` contract."""

    try:
        text = raw_body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("监管回执不是有效 UTF-8") from error
    try:
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise ValueError("监管回执不是有效 JSON") from error
    if not isinstance(document, dict):
        raise ValueError("监管回执顶层必须是 JSON 对象")
    required = {
        "schema_version",
        "receipt_id",
        "batch_id",
        "client_id",
        "mine_id",
        "status",
        "received_at",
        "body_sha256",
        "accepted_observations",
        "rejected_observations",
        "regulatory_outcome",
        "links",
    }
    if set(document) != required:
        missing = sorted(required - set(document))
        extra = sorted(set(document) - required)
        raise ValueError(f"监管回执字段不符合合同：missing={missing}, extra={extra}")
    if document["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise ValueError("监管回执 schema_version 不受支持")
    status = document["status"]
    if not isinstance(status, str) or status not in {
        "accepted",
        "duplicate",
        "partially_accepted",
    }:
        raise ValueError("监管回执 status 不受支持")
    received_at = document["received_at"]
    if not isinstance(received_at, str) or _RFC3339.fullmatch(received_at) is None:
        raise ValueError("监管回执 received_at 不是 RFC 3339 date-time")
    try:
        parsed_time = datetime.fromisoformat(
            received_at[:-1] + "+00:00"
            if received_at[-1:].lower() == "z"
            else received_at
        )
        if parsed_time.utcoffset() is None:
            raise ValueError
    except ValueError as error:
        raise ValueError("监管回执 received_at 不是有效日期时间") from error
    body_sha256 = document["body_sha256"]
    if not isinstance(body_sha256, str) or _SHA256.fullmatch(body_sha256) is None:
        raise ValueError("监管回执 body_sha256 不是小写 SHA-256")
    if document["regulatory_outcome"] != "not_determined_at_intake":
        raise ValueError("监管回执 regulatory_outcome 不符合接收阶段合同")
    links = document["links"]
    if not isinstance(links, dict) or set(links) != {"receipt", "alerts"}:
        raise ValueError("监管回执 links 字段不符合合同")
    client_id = _required_string(
        document,
        "client_id",
        maximum=128 if allow_legacy_batch_id else 88,
    )
    batch_id = _required_string(document, "batch_id")
    if allow_legacy_batch_id:
        identifiers_valid = valid_legacy_batch_id(batch_id, client_id)
    else:
        identifiers_valid = valid_namespaced_batch_id(batch_id, client_id)
    if not identifiers_valid:
        raise ValueError("监管回执 batch_id 不属于回执 client_id 命名空间")
    return EdgeReceipt(
        schema_version=RECEIPT_SCHEMA_VERSION,
        receipt_id=_required_string(document, "receipt_id"),
        batch_id=batch_id,
        client_id=client_id,
        mine_id=_required_string(document, "mine_id"),
        status=status,
        received_at=received_at,
        body_sha256=body_sha256,
        accepted_observations=_bounded_integer(document, "accepted_observations"),
        rejected_observations=_bounded_integer(document, "rejected_observations"),
        regulatory_outcome="not_determined_at_intake",
        links={
            "receipt": _uri_reference(links["receipt"], "receipt"),
            "alerts": _uri_reference(links["alerts"], "alerts"),
        },
    )


def signature_headers(
    body: bytes,
    *,
    client_id: str,
    secret: bytes,
    timestamp: str | None = None,
    nonce: str | None = None,
    method: str = "POST",
    path: str = INGEST_PATH,
) -> dict[str, str]:
    """Sign raw body exactly as edge-telemetry-hmac-v1 specifies.

    Canonical form (UTF-8, LF separators):
      MINE-EDGE-TELEMETRY-HTTP-HMAC-SHA256-V1
      METHOD
      PATH
      CLIENT_ID
      TIMESTAMP
      NONCE
      CONTRACT_VERSION
      CONTENT_SHA256
    """

    current_timestamp = timestamp or utc_now()
    current_nonce = nonce or secrets.token_urlsafe(16)
    content_hash = hashlib.sha256(body).hexdigest()
    signature = transport_signature(
        secret,
        client_id=client_id,
        timestamp=current_timestamp,
        nonce=current_nonce,
        content_sha256=content_hash,
        method=method,
        path=path,
    )
    return {
        "X-Edge-Client-Id": client_id,
        "X-Edge-Timestamp": current_timestamp,
        "X-Edge-Nonce": current_nonce,
        "X-Edge-Content-SHA256": content_hash,
        "X-Edge-Signature-Version": SIGNATURE_VERSION,
        "X-Edge-Contract-Version": CONTRACT_VERSION,
        "X-Edge-Signature": signature,
    }


def transport_signature(
    secret: bytes,
    *,
    client_id: str,
    timestamp: str,
    nonce: str,
    content_sha256: str,
    method: str = "POST",
    path: str = INGEST_PATH,
) -> str:
    """Calculate the HMAC from an already computed raw-body digest."""

    canonical = "\n".join(
        (
            AUTH_CONTEXT,
            method.upper(),
            path,
            client_id,
            timestamp,
            nonce,
            CONTRACT_VERSION,
            content_sha256,
        )
    ).encode()
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def verify_signature(
    body: bytes,
    headers: dict[str, str],
    *,
    secret: bytes,
    method: str = "POST",
    path: str = INGEST_PATH,
) -> bool:
    required = (
        "X-Edge-Client-Id",
        "X-Edge-Timestamp",
        "X-Edge-Nonce",
        "X-Edge-Content-SHA256",
        "X-Edge-Signature-Version",
        "X-Edge-Contract-Version",
        "X-Edge-Signature",
    )
    if any(not headers.get(name) for name in required):
        return False
    if headers["X-Edge-Signature-Version"] != SIGNATURE_VERSION:
        return False
    if headers["X-Edge-Contract-Version"] != CONTRACT_VERSION:
        return False
    if not hmac.compare_digest(
        headers["X-Edge-Content-SHA256"], hashlib.sha256(body).hexdigest()
    ):
        return False
    expected = signature_headers(
        body,
        client_id=headers["X-Edge-Client-Id"],
        secret=secret,
        timestamp=headers["X-Edge-Timestamp"],
        nonce=headers["X-Edge-Nonce"],
        method=method,
        path=path,
    )["X-Edge-Signature"]
    return hmac.compare_digest(expected, headers["X-Edge-Signature"])
