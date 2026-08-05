from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .errors import DeliveryError, SourceError
from .net import request_bytes

_ENDPOINT_PATH = "/api/v1/machine/autofill"
_HEALTH_ENDPOINT_PATH = "/api/v1/machine/source-health"
_SIGNATURE_DOMAIN = "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1"
_SAFE_ERROR_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_SAFE_RESPONSE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_AUTOFILL_RESULT_CONTRACT = "enterprise-autofill-ingestion-result/v1"
_HEALTH_RESULT_CONTRACT = "enterprise-source-health-result/v1"


def _safe_error(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    # An Agent error can cross a trust boundary. Keep useful Chinese business
    # text, but never persist control characters or an unbounded response.
    cleaned = " ".join(
        "".join(character if character.isprintable() else " " for character in value).split()
    )
    return cleaned[:maximum] or None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response field")
        result[key] = value
    return result


def _validate_success_response(
    *,
    path: str,
    event_id: str,
    status: int,
    headers: dict[str, str],
    body: bytes,
) -> None:
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    try:
        if content_type != "application/json":
            raise ValueError("response is not application/json")
        parsed = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        if not isinstance(parsed, dict):
            raise ValueError("response root is not an object")
        if parsed.get("event_id") != event_id:
            raise ValueError("response event_id mismatch")
        if not isinstance(parsed.get("idempotent_replay"), bool):
            raise ValueError("idempotent_replay is not boolean")
        if path == _ENDPOINT_PATH:
            if (
                parsed.get("contract_version") != _AUTOFILL_RESULT_CONTRACT
                or parsed.get("status") != "completed"
            ):
                raise ValueError("autofill result contract mismatch")
            for field in ("draft_id", "ingestion_id"):
                value = parsed.get(field)
                if not isinstance(value, str) or _SAFE_RESPONSE_ID.fullmatch(value) is None:
                    raise ValueError(f"invalid {field}")
        elif path == _HEALTH_ENDPOINT_PATH:
            if (
                parsed.get("contract_version") != _HEALTH_RESULT_CONTRACT
                or parsed.get("status") != "recorded"
            ):
                raise ValueError("health result contract mismatch")
        else:
            raise ValueError("unknown success response path")
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise DeliveryError(
            "Agent 2xx 成功响应不符合已版本化 JSON 合同",
            retryable=True,
            status=status,
            code="agent_protocol_error",
        ) from exc


def signature_material(
    timestamp: int,
    request_id: str,
    body: bytes,
    *,
    path: str = _ENDPOINT_PATH,
) -> bytes:
    body_sha = hashlib.sha256(body).hexdigest()
    return (
        f"{_SIGNATURE_DOMAIN}\nPOST\n{path}\n{timestamp}\n{request_id}\n{body_sha}"
    ).encode()


def sign(
    secret: bytes,
    timestamp: int,
    request_id: str,
    body: bytes,
    *,
    path: str = _ENDPOINT_PATH,
) -> str:
    return hmac.new(
        secret,
        signature_material(timestamp, request_id, body, path=path),
        hashlib.sha256,
    ).hexdigest()


class AgentClient:
    def __init__(
        self,
        *,
        agent_url: str,
        client_id: str,
        secret: bytes,
        timeout_seconds: float,
        max_response_bytes: int,
        allowed_hosts: tuple[str, ...],
        allowed_ports: tuple[int, ...],
        allow_private_network: bool,
        ca_bundle: Path | None = None,
    ):
        self.base_url = agent_url.rstrip("/")
        self.client_id = client_id
        self.secret = secret
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.allowed_hosts = allowed_hosts
        self.allowed_ports = allowed_ports
        self.allow_private_network = allow_private_network
        self.ca_bundle = ca_bundle

    def _send(
        self,
        path: str,
        event_id: str,
        body: bytes,
        *,
        timestamp: int | None = None,
    ) -> int:
        request_timestamp = int(time.time()) if timestamp is None else timestamp
        # request_id is a replay nonce for one HTTP attempt. event_id inside the
        # signed body is the durable business-idempotency key across timeouts,
        # restarts and clock-skew windows.
        event_hint = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:8]
        request_id = f"creq_{event_hint}_{uuid.uuid4().hex}"
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "X-Enterprise-Connector-Client": self.client_id,
            "X-Enterprise-Connector-Timestamp": str(request_timestamp),
            "X-Enterprise-Connector-Request-Id": request_id,
            "X-Enterprise-Connector-Signature": sign(
                self.secret,
                request_timestamp,
                request_id,
                body,
                path=path,
            ),
        }
        try:
            result = request_bytes(
                "POST",
                f"{self.base_url}{path}",
                headers=headers,
                body=body,
                timeout=self.timeout_seconds,
                max_response_bytes=self.max_response_bytes,
                allowed_hosts=self.allowed_hosts,
                allowed_ports=self.allowed_ports,
                allow_private_network=self.allow_private_network,
                ca_bundle=self.ca_bundle,
            )
        except SourceError as exc:
            raise DeliveryError(str(exc), retryable=True) from exc
        if 200 <= result.status < 300:
            _validate_success_response(
                path=path,
                event_id=event_id,
                status=result.status,
                headers=result.headers,
                body=result.body,
            )
            return result.status
        error_code: str | None = None
        error_message: str | None = None
        try:
            parsed = json.loads(result.body.decode("utf-8"))
            if isinstance(parsed, dict):
                nested = parsed.get("error")
                raw_code = nested.get("code") if isinstance(nested, dict) else parsed.get("code")
                raw_message = (
                    nested.get("message") if isinstance(nested, dict) else parsed.get("message")
                )
                candidate = _safe_error(raw_code, maximum=64)
                if candidate is not None and _SAFE_ERROR_CODE.fullmatch(candidate):
                    error_code = candidate
                error_message = _safe_error(raw_message, maximum=300)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            pass
        retryable = (
            result.status in {408, 425, 429}
            or result.status >= 500
            or (result.status == 409 and error_code == "connector_ingestion_in_progress")
        )
        detail = f" code={error_code}" if error_code else ""
        if error_message:
            detail = f"{detail}: {error_message}"
        raise DeliveryError(
            f"Agent 返回状态码 {result.status}{detail}",
            retryable=retryable,
            status=result.status,
            code=error_code,
        )

    def send(self, event_id: str, body: bytes, *, timestamp: int | None = None) -> int:
        return self._send(_ENDPOINT_PATH, event_id, body, timestamp=timestamp)

    def send_health(
        self, event_id: str, body: bytes, *, timestamp: int | None = None
    ) -> int:
        return self._send(_HEALTH_ENDPOINT_PATH, event_id, body, timestamp=timestamp)


def validate_agent_base_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.path not in {"", "/"}:
        raise ValueError("agent_url 必须是服务根地址，不能包含路径")
