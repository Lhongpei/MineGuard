"""Authenticated, durable machine-to-agent autofill ingestion.

This module deliberately defines its own wire contract.  Connector processes do
not import enterprise-agent code: they only need the documented HTTP request and
HMAC material.  Machine callers can create/update a reviewable draft and start a
read-only workflow; they can never confirm or submit it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from datetime import date
from http import HTTPStatus
from typing import Any

from .errors import AgentError, ConflictError, ImportContentError
from .util import parse_aware_datetime, utc_text

AUTOFILL_INGESTION_CONTRACT = "enterprise-autofill-ingestion/v1"
AUTOFILL_RESULT_CONTRACT = "enterprise-autofill-ingestion-result/v1"
AUTOFILL_PATH = "/api/v1/machine/autofill"
SOURCE_HEALTH_CONTRACT = "enterprise-source-health/v1"
SOURCE_HEALTH_RESULT_CONTRACT = "enterprise-source-health-result/v1"
SOURCE_HEALTH_PATH = "/api/v1/machine/source-health"
HMAC_DOMAIN = "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1"
_DEFAULT_FRESHNESS_MAX_SECONDS = 60 * 60
_LOWER_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")

_CLIENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_DRAFT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_HEX_64 = re.compile(r"^[0-9A-Fa-f]{64}$")
_SAFE_METADATA_LIMITS = {
    "source_name": 255,
    "source_system": 128,
    "original_filename": 255,
}
_MAX_SOURCE_CONTENT_BYTES = 2 * 1024 * 1024


class ConnectorAuthenticationError(AgentError):
    """One intentionally indistinguishable error for all HMAC failures."""

    code = "connector_authentication_failed"
    status = HTTPStatus.UNAUTHORIZED

    def __init__(self) -> None:
        super().__init__("机器连接器认证失败")


class ConnectorUnavailableError(AgentError):
    code = "connector_unavailable"
    status = HTTPStatus.SERVICE_UNAVAILABLE


class ConnectorAuthorizationError(AgentError):
    code = "connector_source_not_allowed"
    status = HTTPStatus.FORBIDDEN


class ConnectorInProgressError(AgentError):
    code = "connector_ingestion_in_progress"
    status = HTTPStatus.CONFLICT


class ConnectorRejectedError(AgentError):
    """Replay one already persisted, safe machine business rejection."""

    def __init__(self, failure: dict[str, Any], *, replay: bool):
        self.code = str(failure.get("code") or "connector_ingestion_rejected")
        self.status = int(failure.get("http_status") or HTTPStatus.CONFLICT)
        self.details = {
            "ingestion_id": failure.get("ingestion_id"),
            "idempotent_replay": replay,
        }
        super().__init__(str(failure.get("message") or "机器自动填报事件已拒绝"))


@dataclass(frozen=True, slots=True)
class ConnectorSourcePolicy:
    source_id: str
    source_system: str
    required: bool = True
    freshness_max_seconds: int = _DEFAULT_FRESHNESS_MAX_SECONDS

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_id, str)
            or _EVENT_ID.fullmatch(self.source_id) is None
        ):
            raise ValueError("连接器 allowed_sources 的 source_id 非法")
        safe_system = _safe_text(
            self.source_system,
            field="source_system",
            maximum=_SAFE_METADATA_LIMITS["source_system"],
        )
        if not isinstance(self.required, bool):
            raise ValueError("连接器来源 required 必须是布尔值")
        if (
            isinstance(self.freshness_max_seconds, bool)
            or not isinstance(self.freshness_max_seconds, int)
            or not 300 <= self.freshness_max_seconds <= 30 * 24 * 60 * 60
        ):
            raise ValueError(
                "连接器来源 freshness_max_seconds 必须在 300-2592000 秒"
            )
        object.__setattr__(self, "source_system", safe_system)

    def public_policy(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_system": self.source_system,
            "required": self.required,
            "freshness_max_seconds": self.freshness_max_seconds,
        }


@dataclass(frozen=True, slots=True)
class ConnectorClient:
    client_id: str
    secret: str
    permissions: frozenset[str] = frozenset({"autofill"})
    allowed_sources: tuple[ConnectorSourcePolicy | tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.client_id, str) or _CLIENT_ID.fullmatch(
            self.client_id
        ) is None:
            raise ValueError(
                "连接器 client_id 必须是 1-64 位安全标识符"
            )
        if not isinstance(self.secret, str) or len(self.secret.encode("utf-8")) < 32:
            raise ValueError("连接器 secret 必须至少为 32 字节")
        if self.permissions != frozenset({"autofill"}):
            raise ValueError("机器连接器权限只能是 autofill")
        if (
            not isinstance(self.allowed_sources, tuple)
            or not 1 <= len(self.allowed_sources) <= 32
        ):
            raise ValueError("连接器 allowed_sources 必须包含 1-32 个受控来源")
        normalised: list[ConnectorSourcePolicy] = []
        seen: set[str] = set()
        for item in self.allowed_sources:
            if isinstance(item, ConnectorSourcePolicy):
                policy = item
            elif isinstance(item, tuple) and len(item) == 2:
                policy = ConnectorSourcePolicy(
                    source_id=item[0], source_system=item[1]
                )
            else:
                raise ValueError("连接器 allowed_sources 映射非法")
            if policy.source_id in seen:
                raise ValueError("连接器 allowed_sources 的 source_id 非法或重复")
            seen.add(policy.source_id)
            normalised.append(policy)
        object.__setattr__(
            self,
            "allowed_sources",
            tuple(sorted(normalised, key=lambda value: value.source_id)),
        )

    def allows_source(self, source_id: str, source_system: str) -> bool:
        return self.source_policy(source_id, source_system) is not None

    def source_policy(
        self, source_id: str, source_system: str
    ) -> ConnectorSourcePolicy | None:
        return next(
            (
                policy
                for policy in self.allowed_sources
                if policy.source_id == source_id
                and policy.source_system == source_system
            ),
            None,
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedConnector:
    client_id: str
    request_id: str
    timestamp: int
    body_sha256: str

    @property
    def actor_id(self) -> str:
        return f"connector:{self.client_id}"


def parse_connector_clients_json(raw: str | None) -> tuple[ConnectorClient, ...]:
    """Parse a strict secret-bearing environment value without echoing it."""

    if raw is None or not raw.strip():
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(
            "ENTERPRISE_AGENT_CONNECTOR_CLIENTS_JSON 必须是有效 JSON"
        ) from error
    if not isinstance(parsed, list) or len(parsed) > 1:
        raise ValueError(
            "one-mine 模式最多允许配置 1 个权威机器连接器 client"
        )
    clients: list[ConnectorClient] = []
    seen: set[str] = set()
    for index, item in enumerate(parsed):
        if not isinstance(item, dict):
            raise ValueError(f"连接器配置第 {index + 1} 项必须是对象")
        unknown = set(item) - {
            "client_id",
            "secret",
            "permissions",
            "allowed_sources",
        }
        if unknown:
            raise ValueError(f"连接器配置第 {index + 1} 项包含不支持字段")
        permissions = item.get("permissions", ["autofill"])
        if (
            not isinstance(permissions, list)
            or any(not isinstance(value, str) for value in permissions)
        ):
            raise ValueError("连接器 permissions 必须是文本数组")
        allowed_sources = item.get("allowed_sources")
        if not isinstance(allowed_sources, dict):
            raise ValueError("连接器 allowed_sources 必须是 source_id 到系统名的映射")
        policies: list[ConnectorSourcePolicy] = []
        for source_id, policy_value in allowed_sources.items():
            if isinstance(policy_value, str):
                policies.append(
                    ConnectorSourcePolicy(
                        source_id=source_id,
                        source_system=policy_value,
                    )
                )
                continue
            if not isinstance(policy_value, dict):
                raise ValueError(
                    "allowed_sources 的值必须是系统名或受控策略对象"
                )
            unknown_policy = set(policy_value) - {
                "source_system",
                "required",
                "freshness_max_seconds",
            }
            if unknown_policy or "source_system" not in policy_value:
                raise ValueError("allowed_sources 来源策略字段非法")
            policies.append(
                ConnectorSourcePolicy(
                    source_id=source_id,
                    source_system=policy_value["source_system"],
                    required=policy_value.get("required", True),
                    freshness_max_seconds=policy_value.get(
                        "freshness_max_seconds",
                        _DEFAULT_FRESHNESS_MAX_SECONDS,
                    ),
                )
            )
        client = ConnectorClient(
            client_id=item.get("client_id"),
            secret=item.get("secret"),
            permissions=frozenset(permissions),
            allowed_sources=tuple(policies),
        )
        if client.client_id in seen:
            raise ValueError("连接器 client_id 不得重复")
        seen.add(client.client_id)
        clients.append(client)
    return tuple(clients)


def signature_material(
    *,
    timestamp: str,
    request_id: str,
    body_sha256: str,
    path: str = AUTOFILL_PATH,
) -> str:
    """Return the exact, versioned signing material from the public contract."""

    return (
        f"{HMAC_DOMAIN}\nPOST\n{path}\n{timestamp}\n"
        f"{request_id}\n{body_sha256}"
    )


def authenticate_connector_request(
    *,
    clients: tuple[ConnectorClient, ...],
    client_id: str,
    timestamp: str,
    request_id: str,
    signature: str,
    raw_body: bytes,
    maximum_clock_skew_seconds: int,
    path: str = AUTOFILL_PATH,
    now: float | None = None,
) -> AuthenticatedConnector:
    """Authenticate all failures uniformly and compare MACs in constant time."""

    # Always hash the body and calculate one HMAC, including for unknown IDs.
    body_sha256 = hashlib.sha256(raw_body).hexdigest()
    selected = next((item for item in clients if item.client_id == client_id), None)
    dummy_secret = b"\0" * 32
    key = selected.secret.encode("utf-8") if selected is not None else dummy_secret
    material = signature_material(
        timestamp=timestamp,
        request_id=request_id,
        body_sha256=body_sha256,
        path=path,
    ).encode("utf-8")
    expected = hmac.new(key, material, hashlib.sha256).digest()
    supplied = signature if isinstance(signature, str) else ""
    signature_well_formed = _HEX_64.fullmatch(supplied) is not None
    try:
        supplied_digest = (
            bytes.fromhex(supplied) if signature_well_formed else b"\0" * 32
        )
    except ValueError:  # pragma: no cover - guarded by the regular expression
        supplied_digest = b"\0" * 32
        signature_well_formed = False
    signature_matches = hmac.compare_digest(expected, supplied_digest)

    timestamp_value: int | None = None
    if isinstance(timestamp, str) and re.fullmatch(r"[0-9]{10,13}", timestamp):
        try:
            timestamp_value = int(timestamp)
        except ValueError:  # pragma: no cover - guarded by the expression
            timestamp_value = None
    current = time.time() if now is None else float(now)
    timestamp_valid = (
        timestamp_value is not None
        and abs(current - timestamp_value) <= maximum_clock_skew_seconds
    )
    identifiers_valid = (
        isinstance(client_id, str)
        and _CLIENT_ID.fullmatch(client_id) is not None
        and isinstance(request_id, str)
        and _REQUEST_ID.fullmatch(request_id) is not None
    )
    if not (
        clients
        and selected is not None
        and selected.permissions == frozenset({"autofill"})
        and signature_well_formed
        and signature_matches
        and timestamp_valid
        and identifiers_valid
    ):
        raise ConnectorAuthenticationError()
    assert timestamp_value is not None
    return AuthenticatedConnector(
        client_id=selected.client_id,
        request_id=request_id,
        timestamp=timestamp_value,
        body_sha256=body_sha256,
    )


def _safe_text(value: Any, *, field: str, maximum: int, filename: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"source.{field} 必须是文本")
    clean = value.strip()
    try:
        clean.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"source.{field} 必须是有效 UTF-8 文本") from error
    if (
        not clean
        or len(clean) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in clean)
        or (filename and (clean in {".", ".."} or any(c in clean for c in "/\\")))
    ):
        raise ValueError(f"source.{field} 格式非法")
    return clean


def validate_autofill_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalise the complete ingestion contract."""

    allowed = {
        "contract_version",
        "event_id",
        "draft_key",
        "source",
        "trigger_workflow",
        "workflow_name",
    }
    if set(body) != allowed:
        raise ValueError("机器自动填报请求字段不完整或包含未知字段")
    if body.get("contract_version") != AUTOFILL_INGESTION_CONTRACT:
        raise ValueError("不支持的机器自动填报 contract_version")
    event_id = body.get("event_id")
    if not isinstance(event_id, str) or _EVENT_ID.fullmatch(event_id) is None:
        raise ValueError("event_id 格式非法")
    draft_key = body.get("draft_key")
    if not isinstance(draft_key, str) or _DRAFT_KEY.fullmatch(draft_key) is None:
        raise ValueError("draft_key 格式非法")
    trigger_workflow = body.get("trigger_workflow")
    if not isinstance(trigger_workflow, bool):
        raise ValueError("trigger_workflow 必须是布尔值")
    workflow_name = body.get("workflow_name")
    if workflow_name != "daily_coal_health":
        raise ValueError("workflow_name 仅支持 daily_coal_health")
    source = body.get("source")
    required_source = {
        "source_id",
        "revision",
        "format",
        "content",
        "source_name",
        "source_system",
        "original_filename",
        "observed_at",
        "coverage_as_of",
        "truth_statement",
    }
    if not isinstance(source, dict) or set(source) != required_source:
        raise ValueError("source 字段不完整或包含未知字段")
    format_name = source.get("format")
    if format_name not in {"json", "csv"}:
        raise ValueError("source.format 仅支持 json 或 csv")
    source_id = source.get("source_id")
    if not isinstance(source_id, str) or _EVENT_ID.fullmatch(source_id) is None:
        raise ValueError("source.source_id 格式非法")
    source_revision = source.get("revision")
    if (
        isinstance(source_revision, bool)
        or not isinstance(source_revision, int)
        or not 1 <= source_revision <= 2_147_483_647
    ):
        raise ValueError("source.revision 必须是正整数")
    content = source.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("source.content 必须是非空文本且不超过 2 MiB")
    try:
        content_bytes = content.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("source.content 必须是有效 UTF-8 文本") from error
    if len(content_bytes) > _MAX_SOURCE_CONTENT_BYTES:
        raise ValueError("source.content 必须是非空文本且不超过 2 MiB")
    original_filename = source.get("original_filename")
    if original_filename is not None:
        original_filename = _safe_text(
            original_filename,
            field="original_filename",
            maximum=_SAFE_METADATA_LIMITS["original_filename"],
            filename=True,
        )
    if source.get("truth_statement") is not True:
        raise ValueError("source.truth_statement 必须明确为 true")
    observed_at = source.get("observed_at")
    observed_at = utc_text(
        parse_aware_datetime(observed_at, "source.observed_at")
    )
    coverage_as_of = source.get("coverage_as_of")
    if not isinstance(coverage_as_of, str):
        raise ValueError("source.coverage_as_of 必须是 ISO 日期")
    try:
        date.fromisoformat(coverage_as_of)
    except ValueError as error:
        raise ValueError("source.coverage_as_of 必须是 ISO 日期") from error
    return {
        "contract_version": AUTOFILL_INGESTION_CONTRACT,
        "event_id": event_id,
        "draft_key": draft_key,
        "source": {
            "source_id": source_id,
            "revision": source_revision,
            "format": format_name,
            "content": content,
            "source_name": _safe_text(
                source.get("source_name"),
                field="source_name",
                maximum=_SAFE_METADATA_LIMITS["source_name"],
                filename=True,
            ),
            "source_system": _safe_text(
                source.get("source_system"),
                field="source_system",
                maximum=_SAFE_METADATA_LIMITS["source_system"],
            ),
            "original_filename": original_filename,
            "observed_at": observed_at,
            "coverage_as_of": coverage_as_of,
            "truth_statement": True,
        },
        "trigger_workflow": trigger_workflow,
        "workflow_name": workflow_name,
    }


def validate_source_health_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Validate the status-only contract; it can never carry source content."""

    expected = {
        "contract_version",
        "event_id",
        "draft_key",
        "reporting_month",
        "source_id",
        "source_system",
        "outcome",
        "attempted_at",
        "completed_at",
        "record_count",
        "coverage_as_of",
        "error_code",
        "snapshot_sha256",
        "autofill_event_id",
        "source_revision",
    }
    if not isinstance(body, dict) or set(body) != expected:
        raise ValueError("机器来源健康请求字段不完整或包含未知字段")
    if body.get("contract_version") != SOURCE_HEALTH_CONTRACT:
        raise ValueError("不支持的机器来源健康 contract_version")
    event_id = body.get("event_id")
    if not isinstance(event_id, str) or _EVENT_ID.fullmatch(event_id) is None:
        raise ValueError("event_id 格式非法")
    draft_key = body.get("draft_key")
    if not isinstance(draft_key, str) or _DRAFT_KEY.fullmatch(draft_key) is None:
        raise ValueError("draft_key 格式非法")
    reporting_month = body.get("reporting_month")
    if not isinstance(reporting_month, str):
        raise ValueError("reporting_month 格式非法")
    try:
        date.fromisoformat(f"{reporting_month}-01")
    except ValueError as error:
        raise ValueError("reporting_month 格式非法") from error
    if not draft_key.endswith(f":monthly:{reporting_month}"):
        raise ValueError("draft_key 与 reporting_month 不一致")
    source_id = body.get("source_id")
    if not isinstance(source_id, str) or _EVENT_ID.fullmatch(source_id) is None:
        raise ValueError("source_id 格式非法")
    source_system = _safe_text(
        body.get("source_system"),
        field="source_system",
        maximum=_SAFE_METADATA_LIMITS["source_system"],
    )
    outcome = body.get("outcome")
    if outcome not in {
        "success_nonempty",
        "success_empty",
        "error",
        "stability_wait",
    }:
        raise ValueError("outcome 非法")
    attempted = parse_aware_datetime(body.get("attempted_at"), "attempted_at")
    completed = parse_aware_datetime(body.get("completed_at"), "completed_at")
    if completed < attempted:
        raise ValueError("completed_at 不能早于 attempted_at")
    record_count = body.get("record_count")
    if (
        isinstance(record_count, bool)
        or not isinstance(record_count, int)
        or not 0 <= record_count <= 10_000_000
    ):
        raise ValueError("record_count 必须是 0-10000000 的整数")
    if outcome == "success_nonempty" and record_count < 1:
        raise ValueError("success_nonempty 必须包含正的 record_count")
    if outcome != "success_nonempty" and record_count != 0:
        raise ValueError("非 success_nonempty 的 record_count 必须为 0")
    coverage_as_of = body.get("coverage_as_of")
    coverage_date: date | None = None
    if coverage_as_of is not None:
        if not isinstance(coverage_as_of, str):
            raise ValueError("coverage_as_of 必须是 ISO 日期或 null")
        try:
            coverage_date = date.fromisoformat(coverage_as_of)
        except ValueError as error:
            raise ValueError("coverage_as_of 必须是 ISO 日期或 null") from error
        if coverage_date.strftime("%Y-%m") != reporting_month:
            raise ValueError("coverage_as_of 必须属于申报月")
    if outcome == "success_nonempty" and coverage_date is None:
        raise ValueError("success_nonempty 必须声明 coverage_as_of")
    if outcome != "success_nonempty" and coverage_date is not None:
        raise ValueError("非 success_nonempty 的 coverage_as_of 必须为 null")
    error_code = body.get("error_code")
    if outcome == "error":
        if not isinstance(error_code, str) or _ERROR_CODE.fullmatch(error_code) is None:
            raise ValueError("error_code 必须是安全的 ASCII 错误代码")
    elif error_code is not None:
        raise ValueError("只有 error outcome 可以携带 error_code")
    snapshot_sha256 = body.get("snapshot_sha256")
    autofill_event_id = body.get("autofill_event_id")
    source_revision = body.get("source_revision")
    if outcome == "success_nonempty":
        if (
            not isinstance(snapshot_sha256, str)
            or _LOWER_SHA256.fullmatch(snapshot_sha256) is None
        ):
            raise ValueError("success_nonempty.snapshot_sha256 非法")
        if (
            not isinstance(autofill_event_id, str)
            or _EVENT_ID.fullmatch(autofill_event_id) is None
        ):
            raise ValueError("success_nonempty.autofill_event_id 非法")
        if (
            isinstance(source_revision, bool)
            or not isinstance(source_revision, int)
            or not 1 <= source_revision <= 2_147_483_647
        ):
            raise ValueError("success_nonempty.source_revision 非法")
    elif any(
        value is not None
        for value in (snapshot_sha256, autofill_event_id, source_revision)
    ):
        raise ValueError("非 success_nonempty 的快照绑定字段必须为 null")
    return {
        "contract_version": SOURCE_HEALTH_CONTRACT,
        "event_id": event_id,
        "draft_key": draft_key,
        "reporting_month": reporting_month,
        "source_id": source_id,
        "source_system": source_system,
        "outcome": outcome,
        "attempted_at": utc_text(attempted),
        "completed_at": utc_text(completed),
        "record_count": record_count,
        "coverage_as_of": coverage_as_of,
        "error_code": error_code,
        "snapshot_sha256": snapshot_sha256,
        "autofill_event_id": autofill_event_id,
        "source_revision": source_revision,
    }


class MachineAutofillCoordinator:
    """Resume a small SQLite-backed saga without broad machine permissions."""

    def __init__(self, service: Any):
        self.service = service
        self.repository = service.repository

    def ingest(
        self,
        *,
        authenticated: AuthenticatedConnector,
        payload: dict[str, Any],
        source_policy: ConnectorSourcePolicy,
    ) -> tuple[dict[str, Any], bool]:
        actor_id = authenticated.actor_id
        runtime = getattr(self.service, "_five_quantity", None)
        if runtime is None:
            raise ConnectorUnavailableError("十量 V3 正式填报运行时未启用")
        lease_owner = secrets.token_hex(16)
        ingestion, acquired, created = self.repository.claim_connector_ingestion(
            client_id=authenticated.client_id,
            event_id=payload["event_id"],
            request_sha256=authenticated.body_sha256,
            draft_key=payload["draft_key"],
            source=payload["source"],
            trigger_workflow=payload["trigger_workflow"],
            workflow_name=payload["workflow_name"],
            lease_owner=lease_owner,
        )
        if ingestion["status"] == "completed":
            result = dict(ingestion["result"])
            result["idempotent_replay"] = True
            return result, False
        if ingestion["status"] == "rejected":
            raise ConnectorRejectedError(ingestion["failure"], replay=True)
        if not acquired:
            raise ConnectorInProgressError("同一自动填报事件正在处理中，请稍后重试")

        try:
            if ingestion["status"] == "bound":
                try:
                    runtime.ingest_machine_source(
                        ingestion_id=ingestion["ingestion_id"],
                        lease_owner=lease_owner,
                        client_id=authenticated.client_id,
                        draft_key=payload["draft_key"],
                        source_id=payload["source"]["source_id"],
                        source_revision=payload["source"]["revision"],
                        filename=(
                            payload["source"]["original_filename"]
                            or payload["source"]["source_name"]
                        ),
                        source_name=payload["source"]["source_name"],
                        source_system=payload["source"]["source_system"],
                        original_filename=(
                            payload["source"]["original_filename"]
                        ),
                        observed_at=payload["source"]["observed_at"],
                        coverage_as_of=payload["source"]["coverage_as_of"],
                        format_name=payload["source"]["format"],
                        content=payload["source"]["content"].encode("utf-8"),
                        actor_id=actor_id,
                        source_required=source_policy.required,
                        freshness_max_seconds=(
                            source_policy.freshness_max_seconds
                        ),
                    )
                except (ConflictError, ImportContentError, ValueError) as error:
                    failure = self._safe_failure(ingestion, error)
                    self.repository.reject_connector_ingestion(
                        ingestion["ingestion_id"],
                        lease_owner=lease_owner,
                        failure=failure,
                    )
                    raise ConnectorRejectedError(failure, replay=False) from error
                ingestion = self.repository.get_connector_ingestion(
                    ingestion["ingestion_id"]
                )

            preflight = self._public_preflight(ingestion.get("workflow_result"))

            result = {
                "contract_version": AUTOFILL_RESULT_CONTRACT,
                "ingestion_id": ingestion["ingestion_id"],
                "event_id": ingestion["event_id"],
                "draft_key": ingestion["draft_key"],
                "draft_id": ingestion["draft_id"],
                "status": "completed",
                "idempotent_replay": not created,
                "import": ingestion.get("import_summary") or {},
                "autofill_preview": {
                    "source_id": ingestion["source_id"],
                    "source_revision": ingestion["source_revision"],
                    "source_name": ingestion["source_name"],
                    "source_system": ingestion["source_system"],
                    "format": ingestion["format"],
                    "observed_at": ingestion["source_observed_at"],
                    "coverage_as_of": ingestion["source_coverage_as_of"],
                    "request_hash": ingestion["request_sha256"][:12],
                    "draft_revision": ingestion.get("draft_revision"),
                    "merge": (ingestion.get("import_summary") or {}).get(
                        "merge", {}
                    ),
                    "review_required": True,
                    "raw_content_retained": False,
                },
                "workflow": {
                    "triggered": payload["trigger_workflow"],
                    "workflow_name": payload["workflow_name"],
                    "display_name": "十量数据就绪预检",
                    "execution_mode": "v2_data_readiness_preflight",
                    "status": (
                        preflight.get("status") if preflight is not None else None
                    ),
                    "preflight": preflight,
                    "read_only": True,
                    "can_confirm": False,
                    "can_submit": False,
                },
            }
            self.repository.complete_connector_ingestion(
                ingestion["ingestion_id"],
                lease_owner=lease_owner,
                result=result,
            )
            return result, created
        except Exception:
            self.repository.release_connector_ingestion(
                ingestion["ingestion_id"],
                lease_owner=lease_owner,
            )
            raise

    @staticmethod
    def _public_preflight(value: Any) -> dict[str, Any] | None:
        if not isinstance(value, dict):
            return None
        return {
            "status": value.get("status"),
            "bound_revision": value.get("bound_revision"),
            "payload_sha256_prefix": str(value.get("payload_sha256", ""))[:12],
            "missing_count": value.get("missing_count"),
            "missing_day_count": value.get("missing_day_count"),
            "calendar_coverage": value.get("calendar_coverage"),
            "arithmetic_mismatch_count": value.get(
                "arithmetic_mismatch_count"
            ),
            "source_count": value.get("source_count"),
            "checked_at": value.get("checked_at"),
            "warnings": list(value.get("warnings", []))[:20],
        }

    @staticmethod
    def _safe_failure(ingestion: dict[str, Any], error: Exception) -> dict[str, Any]:
        if isinstance(error, ConflictError):
            code = "connector_source_conflict"
            status = HTTPStatus.CONFLICT
        elif isinstance(error, ImportContentError):
            code = "connector_source_invalid"
            status = HTTPStatus.UNPROCESSABLE_ENTITY
        else:
            code = "connector_source_invalid"
            status = HTTPStatus.BAD_REQUEST
        message = "".join(
            character
            for character in str(error)[:500]
            if ord(character) >= 32 and ord(character) != 127
        ) or "机器来源材料未通过校验"
        return {
            "code": code,
            "http_status": int(status),
            "message": message,
            "ingestion_id": ingestion["ingestion_id"],
            "source_id": ingestion["source_id"],
            "source_revision": ingestion["source_revision"],
            "recorded_at": utc_text(),
        }


__all__ = [
    "AUTOFILL_INGESTION_CONTRACT",
    "AUTOFILL_PATH",
    "AUTOFILL_RESULT_CONTRACT",
    "SOURCE_HEALTH_CONTRACT",
    "SOURCE_HEALTH_PATH",
    "SOURCE_HEALTH_RESULT_CONTRACT",
    "AuthenticatedConnector",
    "ConnectorAuthenticationError",
    "ConnectorAuthorizationError",
    "ConnectorClient",
    "ConnectorSourcePolicy",
    "ConnectorInProgressError",
    "ConnectorUnavailableError",
    "MachineAutofillCoordinator",
    "authenticate_connector_request",
    "parse_connector_clients_json",
    "signature_material",
    "validate_autofill_payload",
    "validate_source_health_payload",
]
