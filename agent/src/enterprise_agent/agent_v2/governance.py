"""Governed, proposal-only memory and skill catalogue.

This module deliberately does not register skills with the live harness.  It
stores human-reviewable proposals and immutable, versioned catalogue records;
an approved skill is marked ``approved_inactive`` and needs an explicit,
separate deployment step before any future runtime may use it.

The store expects the four ``agent_*`` governance tables created by
``enterprise_agent.storage.Repository``.  All access to user-scoped material
is constrained to the owning actor, including reviewers.
"""

from __future__ import annotations

import hmac
import json
import math
import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from enterprise_agent.errors import (
    ConflictError,
    NotFoundError,
    ValidationBlockedError,
)
from enterprise_agent.harness.sanitize import has_secret_material
from enterprise_agent.storage import Repository
from enterprise_agent.tools.builtins import builtin_tool_specs
from enterprise_agent.tools.protocol import ToolSpec
from enterprise_agent.util import canonical_json, sha256_json, utc_text

_ZERO_HASH = "0" * 64
_SCOPES = frozenset({"user", "draft", "mine", "enterprise"})
_PROPOSAL_STATUSES = frozenset({"pending", "approved", "rejected"})
_MEMORY_STATUSES = frozenset({"active", "superseded", "revoked"})
_SKILL_STATUSES = frozenset({"active", "superseded", "retired"})
_MEMORY_KEY = re.compile(r"^[^\s/\\\x00-\x1f\x7f]{1,128}$")
_SKILL_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DANGEROUS_CAPABILITY = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:"
    r"confirm|submit|delete|remove|shell|bash|powershell|browser|"
    r"exec(?:ute)?|command|filesystem|file[_-]?(?:write|delete)|"
    r"network|http|fetch|curl|wget|draft[_-]?patch|mutation|"
    r"write[_-]?(?:draft|file|database)"
    r")(?:$|[^a-z0-9])"
)
_DANGEROUS_CJK = (
    "确认提交",
    "自动提交",
    "删除数据",
    "删除文件",
    "命令行",
    "执行脚本",
    "调用浏览器",
    "联网抓取",
    "写入草稿",
    "修改草稿",
)
_SOURCE_TYPES = frozenset(
    {
        "draft",
        "observation",
        "document",
        "user_input",
        "tool_result",
        "submission",
        "public_source",
    }
)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991


@dataclass(frozen=True, slots=True)
class GovernanceAccess:
    """Explicit row-level access supplied by the authenticated service layer.

    ``allow_all_shared`` is intended for a single-tenant deployment or a
    privileged enterprise administrator.  It never grants access to another
    actor's ``user`` scope.  In multi-tenant deployments, keep it false and
    populate the three identifier sets from authoritative tenancy claims.
    """

    actor_id: str
    draft_ids: frozenset[str] = field(default_factory=frozenset)
    mine_ids: frozenset[str] = field(default_factory=frozenset)
    enterprise_ids: frozenset[str] = field(default_factory=frozenset)
    allow_all_shared: bool = False
    can_review: bool = False
    can_manage_skills: bool = False

    def __post_init__(self) -> None:
        _identifier(self.actor_id, "actor_id", maximum=128)
        for name, values in (
            ("draft_ids", self.draft_ids),
            ("mine_ids", self.mine_ids),
            ("enterprise_ids", self.enterprise_ids),
        ):
            if not isinstance(values, (set, frozenset)):
                raise ValueError(f"{name} 必须是集合")
            if len(values) > 10_000:
                raise ValueError(f"{name} 超过访问范围上限")
            for value in values:
                _identifier(value, name, maximum=256)

    @classmethod
    def single_tenant(
        cls,
        actor_id: str,
        *,
        can_review: bool = False,
        can_manage_skills: bool | None = None,
    ) -> GovernanceAccess:
        return cls(
            actor_id=actor_id,
            allow_all_shared=True,
            can_review=can_review,
            can_manage_skills=(
                can_review
                if can_manage_skills is None
                else can_manage_skills
            ),
        )

    def permits(self, scope_type: str, scope_id: str) -> bool:
        if scope_type == "user":
            return scope_id == self.actor_id
        if self.allow_all_shared:
            return scope_type in _SCOPES
        values = {
            "draft": self.draft_ids,
            "mine": self.mine_ids,
            "enterprise": self.enterprise_ids,
        }.get(scope_type)
        return values is not None and scope_id in values


def _identifier(value: Any, field_name: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{field_name} 必须是 1-{maximum} 字符的非空标识")
    return value.strip()


def _text(
    value: Any,
    field_name: str,
    *,
    maximum: int,
    minimum: int = 1,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} 必须是字符串")
    clean = value.strip()
    if not minimum <= len(clean) <= maximum:
        raise ValueError(f"{field_name} 长度必须为 {minimum}-{maximum} 个字符")
    if "\x00" in clean:
        raise ValueError(f"{field_name} 不能包含 NUL")
    if has_secret_material(clean):
        raise ValidationBlockedError(f"{field_name} 疑似包含密钥或口令，禁止保存")
    return clean


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or isinstance(offset, bool)
        or not isinstance(offset, int)
    ):
        raise ValueError("limit 和 offset 必须是整数")
    return min(max(limit, 1), 200), max(offset, 0)


def _validate_json_tree(value: Any, path: str = "$", *, depth: int = 0) -> None:
    if depth > 8:
        raise ValueError(f"{path} 嵌套层级超过 8")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError(f"{path} 整数超出可互操作安全范围")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > _MAX_SAFE_INTEGER:
            raise ValueError(f"{path} 必须是有限且有界的数字")
        return
    if isinstance(value, str):
        if len(value) > 4_096 or "\x00" in value:
            raise ValueError(f"{path} 字符串过长或包含 NUL")
        return
    if isinstance(value, list):
        if len(value) > 200:
            raise ValueError(f"{path} 数组超过 200 项")
        for index, child in enumerate(value):
            _validate_json_tree(child, f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 100:
            raise ValueError(f"{path} 对象超过 100 个字段")
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ValueError(f"{path} JSON 字段名必须是 1-128 字符")
            if any(ord(character) < 32 for character in key):
                raise ValueError(f"{path} JSON 字段名包含控制字符")
            _validate_json_tree(child, f"{path}.{key}", depth=depth + 1)
        return
    raise ValueError(f"{path} 包含非 JSON 类型")


def _validated_json(
    value: Any,
    field_name: str,
    *,
    max_bytes: int,
    require_container: bool = False,
) -> tuple[Any, str]:
    if require_container and not isinstance(value, (dict, list)):
        raise ValueError(f"{field_name} 必须是 JSON 对象或数组")
    _validate_json_tree(value, f"$.{field_name}")
    if has_secret_material(value):
        raise ValidationBlockedError(f"{field_name} 疑似包含密钥或口令，禁止保存")
    encoded = canonical_json(value)
    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} 超过 {max_bytes} 字节上限")
    return json.loads(encoded), encoded


def _source_references(value: Any) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise ValueError("source_refs 必须包含 1-32 条来源引用")
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"source_refs[{index}] 必须是对象")
        unknown = set(item) - {"source_type", "source_id", "sha256", "label"}
        if unknown:
            raise ValueError(
                f"source_refs[{index}] 含未知字段：{', '.join(sorted(unknown))}"
            )
        source_type = item.get("source_type")
        if source_type not in _SOURCE_TYPES:
            raise ValueError(f"source_refs[{index}].source_type 不受支持")
        source_id = _identifier(
            item.get("source_id"),
            f"source_refs[{index}].source_id",
            maximum=256,
        )
        digest = item.get("sha256")
        if digest is not None and (
            not isinstance(digest, str) or _HEX64.fullmatch(digest) is None
        ):
            raise ValueError(f"source_refs[{index}].sha256 必须是 64 位小写十六进制")
        label = item.get("label")
        if label is not None:
            label = _text(
                label,
                f"source_refs[{index}].label",
                maximum=200,
            )
        identity = (str(source_type), source_id)
        if identity in seen:
            raise ValueError("source_refs 不能重复")
        seen.add(identity)
        normalized.append(
            {
                "source_type": source_type,
                "source_id": source_id,
                **({"sha256": digest} if digest is not None else {}),
                **({"label": label} if label is not None else {}),
            }
        )
    return _validated_json(
        normalized,
        "source_refs",
        max_bytes=16_384,
        require_container=True,
    )


def _audit_event(
    events: list[dict[str, Any]],
    *,
    proposal_id: str,
    event_type: str,
    actor_id: str,
    details: dict[str, Any],
    occurred_at: str,
) -> dict[str, Any]:
    sequence = len(events) + 1
    previous_hash = events[-1]["event_hash"] if events else _ZERO_HASH
    envelope = {
        "proposal_id": proposal_id,
        "sequence": sequence,
        "event_type": event_type,
        "actor_id": actor_id,
        "details": details,
        "occurred_at": occurred_at,
        "previous_hash": previous_hash,
    }
    return {**envelope, "event_hash": sha256_json(envelope)}


def _verify_audit(row: Any) -> list[dict[str, Any]]:
    try:
        events = json.loads(row["audit_json"])
    except (json.JSONDecodeError, TypeError) as error:
        raise ConflictError("治理提案审计记录损坏，拒绝读取") from error
    if not isinstance(events, list) or len(events) != int(row["event_count"]):
        raise ConflictError("治理提案审计事件数量不一致，拒绝读取")
    previous_hash = _ZERO_HASH
    for sequence, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ConflictError("治理提案审计事件结构损坏，拒绝读取")
        expected = {
            key: event.get(key)
            for key in (
                "proposal_id",
                "sequence",
                "event_type",
                "actor_id",
                "details",
                "occurred_at",
                "previous_hash",
            )
        }
        if (
            expected["proposal_id"] != row["proposal_id"]
            or expected["sequence"] != sequence
            or expected["previous_hash"] != previous_hash
            or not hmac.compare_digest(
                str(event.get("event_hash", "")), sha256_json(expected)
            )
        ):
            raise ConflictError("治理提案审计哈希链不一致，拒绝读取")
        previous_hash = str(event["event_hash"])
    if not hmac.compare_digest(previous_hash, str(row["event_head_hash"])):
        raise ConflictError("治理提案审计锚点不一致，拒绝读取")
    return events


def _verify_proposal_lifecycle(
    row: Any,
    events: list[dict[str, Any]],
    *,
    prefix: str,
) -> None:
    proposed_type = f"{prefix}_proposed"
    proposed_details = (
        events[0].get("details")
        if events and isinstance(events[0].get("details"), dict)
        else {}
    )
    if (
        not events
        or events[0].get("event_type") != proposed_type
        or events[0].get("actor_id") != row["proposed_by"]
        or events[0].get("occurred_at") != row["created_at"]
        or proposed_details.get("proposal_sha256")
        != row["proposal_sha256"]
    ):
        raise ConflictError("治理提案创建状态与审计记录不一致，拒绝读取")
    status = str(row["status"])
    if status == "pending":
        if (
            len(events) != 1
            or int(row["revision"]) != 1
            or row["reviewed_by"] is not None
            or row["reviewed_at"] is not None
            or row["decision_reason"] is not None
        ):
            raise ConflictError("待审批提案状态与审计记录不一致，拒绝读取")
        return
    if status not in {"approved", "rejected"} or len(events) != 2:
        raise ConflictError("治理提案状态不受支持或审计记录不完整")
    decision_event = events[-1]
    decision_details = (
        decision_event.get("details")
        if isinstance(decision_event.get("details"), dict)
        else {}
    )
    decision = "approve" if status == "approved" else "reject"
    if (
        decision_event.get("event_type") != f"{prefix}_{status}"
        or decision_event.get("actor_id") != row["reviewed_by"]
        or decision_event.get("occurred_at") != row["reviewed_at"]
        or row["reviewed_at"] != row["updated_at"]
        or int(row["revision"]) != 2
        or decision_details.get("decision") != decision
        or not isinstance(row["decision_reason"], str)
        or decision_details.get("reason_sha256")
        != sha256_json(row["decision_reason"])
    ):
        raise ConflictError("治理提案审批状态与审计记录不一致，拒绝读取")


def _append_lifecycle(
    provenance: dict[str, Any],
    *,
    event_type: str,
    actor_id: str,
    occurred_at: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    lifecycle = provenance.get("lifecycle")
    if not isinstance(lifecycle, list):
        lifecycle = []
    previous_hash = (
        str(lifecycle[-1].get("event_hash", _ZERO_HASH))
        if lifecycle
        else _ZERO_HASH
    )
    envelope = {
        "sequence": len(lifecycle) + 1,
        "event_type": event_type,
        "actor_id": actor_id,
        "occurred_at": occurred_at,
        "details": details,
        "previous_hash": previous_hash,
    }
    event = {**envelope, "event_hash": sha256_json(envelope)}
    return {
        **provenance,
        "lifecycle": [*lifecycle, event],
        "lifecycle_head_hash": event["event_hash"],
    }


def _scope_where(access: GovernanceAccess) -> tuple[str, list[Any]]:
    clauses = ["(scope_type = 'user' AND scope_id = ?)"]
    params: list[Any] = [access.actor_id]
    if access.allow_all_shared:
        clauses.append("scope_type IN ('draft', 'mine', 'enterprise')")
    else:
        for scope_type, values in (
            ("draft", access.draft_ids),
            ("mine", access.mine_ids),
            ("enterprise", access.enterprise_ids),
        ):
            ordered = sorted(values)
            if not ordered:
                continue
            clauses.append(
                f"(scope_type = ? AND scope_id IN ({','.join('?' for _ in ordered)}))"
            )
            params.extend([scope_type, *ordered])
    return "(" + " OR ".join(clauses) + ")", params


class GovernanceStore:
    """Persistence and policy boundary for governed memories and skills."""

    def __init__(
        self,
        repository: Repository,
        *,
        public_tool_specs: Iterable[ToolSpec] | None = None,
    ) -> None:
        self.repository = repository
        specs = (
            builtin_tool_specs()
            if public_tool_specs is None
            else tuple(public_tool_specs)
        )
        self._tool_allowlist = frozenset(
            spec.name
            for spec in specs
            if (
                isinstance(spec, ToolSpec)
                and not spec.mutating
                and not spec.requires_approval
                and not spec.network_access
                and _TOOL_NAME.fullmatch(spec.name) is not None
                and not self._dangerous_capability(spec.name)
            )
        )
        if not self._tool_allowlist:
            raise ValueError("治理技能至少需要一个公开只读工具")

    @property
    def readonly_tool_allowlist(self) -> tuple[str, ...]:
        return tuple(sorted(self._tool_allowlist))

    @staticmethod
    def _verified_page(
        db: Any,
        *,
        query: str,
        params: tuple[Any, ...] | list[Any],
        verifier: Any,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        """Paginate verified records while quarantined rows remain invisible."""

        cursor = db.execute(query, params)
        result: list[dict[str, Any]] = []
        verified_seen = 0
        while True:
            rows = cursor.fetchmany(256)
            if not rows:
                return result
            for row in rows:
                try:
                    public = verifier(row)
                except (
                    ConflictError,
                    json.JSONDecodeError,
                    KeyError,
                    TypeError,
                    ValueError,
                ):
                    continue
                if verified_seen < offset:
                    verified_seen += 1
                    continue
                result.append(public)
                verified_seen += 1
                if len(result) >= limit:
                    return result

    @staticmethod
    def _dangerous_capability(value: str) -> bool:
        return bool(_DANGEROUS_CAPABILITY.search(value)) or any(
            token in value for token in _DANGEROUS_CJK
        )

    def _assert_scope(
        self, access: GovernanceAccess, scope_type: Any, scope_id: Any
    ) -> tuple[str, str]:
        if scope_type not in _SCOPES:
            raise ValueError("scope_type 必须是 user、draft、mine 或 enterprise")
        clean_id = _identifier(scope_id, "scope_id", maximum=256)
        if not access.permits(str(scope_type), clean_id):
            raise NotFoundError("治理记录不存在或无权访问")
        if scope_type == "draft":
            self.repository.get_draft(clean_id)
        return str(scope_type), clean_id

    @staticmethod
    def _authorize_row(access: GovernanceAccess, row: Any) -> None:
        if not access.permits(str(row["scope_type"]), str(row["scope_id"])):
            raise NotFoundError("治理记录不存在或无权访问")

    @staticmethod
    def _memory_digest(
        *,
        scope_type: str,
        scope_id: str,
        memory_key: str,
        value: Any,
        source_refs: Any,
        reason: str,
        proposed_by: str,
        created_at: str,
    ) -> str:
        return sha256_json(
            {
                "scope_type": scope_type,
                "scope_id": scope_id,
                "memory_key": memory_key,
                "value": value,
                "source_refs": source_refs,
                "reason": reason,
                "proposed_by": proposed_by,
                "created_at": created_at,
            }
        )

    @staticmethod
    def _skill_digest(
        *,
        skill_name: str,
        description: str,
        procedure: Any,
        allowed_tools: Any,
        source_refs: Any,
        reason: str,
        proposed_by: str,
        created_at: str,
    ) -> str:
        return sha256_json(
            {
                "skill_name": skill_name,
                "description": description,
                "procedure": procedure,
                "allowed_tools": allowed_tools,
                "source_refs": source_refs,
                "reason": reason,
                "proposed_by": proposed_by,
                "created_at": created_at,
            }
        )

    @staticmethod
    def _memory_record_digest(record: Mapping[str, Any]) -> str:
        return sha256_json(
            {
                key: record.get(key)
                for key in (
                    "memory_id",
                    "scope_type",
                    "scope_id",
                    "memory_key",
                    "version",
                    "value",
                    "provenance",
                    "proposal_id",
                    "status",
                    "created_by",
                    "created_at",
                    "updated_at",
                    "revision",
                    "revoked_by",
                    "revoked_at",
                )
            }
        )

    @staticmethod
    def _skill_record_digest(record: Mapping[str, Any]) -> str:
        return sha256_json(
            {
                key: record.get(key)
                for key in (
                    "skill_version_id",
                    "skill_name",
                    "version",
                    "description",
                    "procedure",
                    "allowed_tools",
                    "source_refs",
                    "proposal_id",
                    "status",
                    "runtime_activation",
                    "approved_by",
                    "approved_at",
                    "created_at",
                    "updated_at",
                    "revision",
                    "retired_by",
                    "retired_at",
                    "retirement_reason",
                )
            }
        )

    def create_memory_proposal(
        self,
        access: GovernanceAccess,
        *,
        scope_type: str,
        scope_id: str,
        memory_key: str,
        value: Any,
        source_refs: list[dict[str, Any]],
        reason: str,
    ) -> dict[str, Any]:
        scope_type, scope_id = self._assert_scope(access, scope_type, scope_id)
        key = _identifier(memory_key, "memory_key", maximum=128)
        if _MEMORY_KEY.fullmatch(key) is None:
            raise ValueError("memory_key 不能包含空白、斜杠或控制字符")
        safe_value, value_json = _validated_json(
            value, "value", max_bytes=32_768
        )
        safe_refs, refs_json = _source_references(source_refs)
        clean_reason = _text(reason, "reason", maximum=2_000)
        proposal_id = f"memprop_{uuid.uuid4().hex}"
        now = utc_text()
        digest = self._memory_digest(
            scope_type=scope_type,
            scope_id=scope_id,
            memory_key=key,
            value=safe_value,
            source_refs=safe_refs,
            reason=clean_reason,
            proposed_by=access.actor_id,
            created_at=now,
        )
        event = _audit_event(
            [],
            proposal_id=proposal_id,
            event_type="memory_proposed",
            actor_id=access.actor_id,
            details={"proposal_sha256": digest},
            occurred_at=now,
        )
        with self.repository._transaction() as db:
            duplicates = db.execute(
                """
                SELECT * FROM agent_memory_proposals
                WHERE scope_type = ? AND scope_id = ? AND memory_key = ?
                  AND proposed_by = ? AND status = 'pending'
                ORDER BY created_at, proposal_id
                """,
                (scope_type, scope_id, key, access.actor_id),
            ).fetchall()
            for duplicate in duplicates:
                try:
                    self._public_memory_proposal(duplicate)
                except ConflictError:
                    # Legacy rows without verifiable hashes remain available
                    # for forensic export but cannot block a clean proposal.
                    continue
                raise ConflictError("同一作用域和键已有待审批记忆提案")
            db.execute(
                """
                INSERT INTO agent_memory_proposals (
                    proposal_id, scope_type, scope_id, memory_key, value_json,
                    source_refs_json, reason, status, revision, proposed_by,
                    proposal_sha256, audit_json, event_count, event_head_hash,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    proposal_id,
                    scope_type,
                    scope_id,
                    key,
                    value_json,
                    refs_json,
                    clean_reason,
                    access.actor_id,
                    digest,
                    canonical_json([event]),
                    event["event_hash"],
                    now,
                    now,
                ),
            )
        return self.get_memory_proposal(access, proposal_id)

    def get_memory_proposal(
        self, access: GovernanceAccess, proposal_id: str
    ) -> dict[str, Any]:
        proposal_id = _identifier(proposal_id, "proposal_id", maximum=128)
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM agent_memory_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("记忆提案不存在")
        self._authorize_row(access, row)
        return self._public_memory_proposal(row)

    def list_memory_proposals(
        self,
        access: GovernanceAccess,
        *,
        status: str | None = None,
        scope_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if status is not None and status not in _PROPOSAL_STATUSES:
            raise ValueError("status 不受支持")
        if scope_type is not None and scope_type not in _SCOPES:
            raise ValueError("scope_type 不受支持")
        limit, offset = _bounded_page(limit, offset)
        access_clause, params = _scope_where(access)
        clauses = [access_clause]
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if scope_type is not None:
            clauses.append("scope_type = ?")
            params.append(scope_type)
        with self.repository._read() as db:
            return self._verified_page(
                db,
                query=f"""
                SELECT * FROM agent_memory_proposals
                WHERE {' AND '.join(clauses)}
                ORDER BY updated_at DESC, proposal_id ASC
                """,
                params=params,
                verifier=self._public_memory_proposal,
                limit=limit,
                offset=offset,
            )

    def decide_memory_proposal(
        self,
        access: GovernanceAccess,
        proposal_id: str,
        *,
        decision: str,
        expected_revision: int,
        reason: str,
    ) -> dict[str, Any]:
        if not access.can_review:
            raise NotFoundError("记忆提案不存在或无权审批")
        if decision not in {"approve", "reject"}:
            raise ValueError("decision 必须是 approve 或 reject")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        proposal_id = _identifier(proposal_id, "proposal_id", maximum=128)
        clean_reason = _text(reason, "decision reason", maximum=2_000)
        published_id: str | None = None
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM agent_memory_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("记忆提案不存在")
            self._authorize_row(access, row)
            if row["status"] != "pending":
                raise ConflictError("记忆提案已完成审批")
            if int(row["revision"]) != expected_revision:
                raise ConflictError(f"记忆提案已更新，当前修订号为 {row['revision']}")
            if (
                row["scope_type"] != "user"
                and row["proposed_by"] == access.actor_id
                and decision == "approve"
            ):
                raise ConflictError("共享作用域记忆必须由另一名审批人批准")
            verified = self._public_memory_proposal(row)
            events = list(verified["audit"]["events"])
            now = utc_text()
            next_status = "approved" if decision == "approve" else "rejected"
            details: dict[str, Any] = {
                "decision": decision,
                "reason_sha256": sha256_json(clean_reason),
            }
            if decision == "approve":
                published_id, version = self._publish_memory(
                    db, row=row, actor_id=access.actor_id, now=now
                )
                details.update({"memory_id": published_id, "version": version})
            event = _audit_event(
                events,
                proposal_id=proposal_id,
                event_type=f"memory_{next_status}",
                actor_id=access.actor_id,
                details=details,
                occurred_at=now,
            )
            events.append(event)
            updated = db.execute(
                """
                UPDATE agent_memory_proposals
                SET status = ?, revision = revision + 1, reviewed_by = ?,
                    reviewed_at = ?, decision_reason = ?, audit_json = ?,
                    event_count = ?, event_head_hash = ?, updated_at = ?
                WHERE proposal_id = ? AND revision = ? AND status = 'pending'
                """,
                (
                    next_status,
                    access.actor_id,
                    now,
                    clean_reason,
                    canonical_json(events),
                    len(events),
                    event["event_hash"],
                    now,
                    proposal_id,
                    expected_revision,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("记忆提案已被并发更新")
        proposal = self.get_memory_proposal(access, proposal_id)
        return {
            "proposal": proposal,
            "memory": (
                self.get_memory(access, published_id)
                if published_id is not None
                else None
            ),
        }

    def _publish_memory(
        self, db: Any, *, row: Any, actor_id: str, now: str
    ) -> tuple[str, int]:
        current_rows = db.execute(
            """
            SELECT * FROM agent_memories
            WHERE scope_type = ? AND scope_id = ? AND memory_key = ?
              AND status = 'active'
            """,
            (row["scope_type"], row["scope_id"], row["memory_key"]),
        ).fetchall()
        for current in current_rows:
            try:
                public = self._memory_row(current, db=db)
            except ConflictError:
                continue
            provenance = _append_lifecycle(
                public["provenance"],
                event_type="memory_superseded",
                actor_id=actor_id,
                occurred_at=now,
                details={"superseded_by_proposal_id": row["proposal_id"]},
            )
            public.update(
                {
                    "status": "superseded",
                    "provenance": provenance,
                    "updated_at": now,
                    "revision": int(current["revision"]) + 1,
                }
            )
            db.execute(
                """
                UPDATE agent_memories
                SET status = 'superseded', provenance_json = ?,
                    updated_at = ?, revision = ?, record_sha256 = ?
                WHERE memory_id = ? AND revision = ?
                """,
                (
                    canonical_json(provenance),
                    now,
                    public["revision"],
                    self._memory_record_digest(public),
                    current["memory_id"],
                    current["revision"],
                ),
            )
        version_row = db.execute(
            """
            SELECT COALESCE(MAX(version), 0) AS version
            FROM agent_memories
            WHERE scope_type = ? AND scope_id = ? AND memory_key = ?
            """,
            (row["scope_type"], row["scope_id"], row["memory_key"]),
        ).fetchone()
        version = int(version_row["version"]) + 1
        memory_id = f"memory_{uuid.uuid4().hex}"
        source_refs = json.loads(row["source_refs_json"])
        provenance = _append_lifecycle(
            {
                "proposal_id": row["proposal_id"],
                "proposal_sha256": row["proposal_sha256"],
                "source_refs": source_refs,
            },
            event_type="memory_approved",
            actor_id=actor_id,
            occurred_at=now,
            details={"version": version},
        )
        public = {
            "memory_id": memory_id,
            "scope_type": row["scope_type"],
            "scope_id": row["scope_id"],
            "memory_key": row["memory_key"],
            "version": version,
            "value": json.loads(row["value_json"]),
            "provenance": provenance,
            "proposal_id": row["proposal_id"],
            "status": "active",
            "created_by": actor_id,
            "created_at": now,
            "updated_at": now,
            "revision": 1,
            "revoked_by": None,
            "revoked_at": None,
        }
        db.execute(
            """
            INSERT INTO agent_memories (
                memory_id, scope_type, scope_id, memory_key, version,
                value_json, provenance_json, proposal_id, status, created_by,
                created_at, updated_at, revision, record_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, 1, ?)
            """,
            (
                memory_id,
                row["scope_type"],
                row["scope_id"],
                row["memory_key"],
                version,
                row["value_json"],
                canonical_json(provenance),
                row["proposal_id"],
                actor_id,
                now,
                now,
                self._memory_record_digest(public),
            ),
        )
        return memory_id, version

    def get_memory(
        self, access: GovernanceAccess, memory_id: str
    ) -> dict[str, Any]:
        memory_id = _identifier(memory_id, "memory_id", maximum=128)
        with self.repository._read() as db:
            db.execute("BEGIN")
            try:
                row = db.execute(
                    "SELECT * FROM agent_memories WHERE memory_id = ?",
                    (memory_id,),
                ).fetchone()
                if row is None:
                    raise NotFoundError("受治理记忆不存在")
                self._authorize_row(access, row)
                result = self._memory_row(row, db=db)
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def list_memories(
        self,
        access: GovernanceAccess,
        *,
        status: str | None = "active",
        scope_type: str | None = None,
        memory_key: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if status is not None and status not in _MEMORY_STATUSES:
            raise ValueError("status 不受支持")
        if scope_type is not None and scope_type not in _SCOPES:
            raise ValueError("scope_type 不受支持")
        if memory_key is not None:
            memory_key = _identifier(memory_key, "memory_key", maximum=128)
        limit, offset = _bounded_page(limit, offset)
        access_clause, params = _scope_where(access)
        clauses = [access_clause]
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if scope_type is not None:
            clauses.append("scope_type = ?")
            params.append(scope_type)
        if memory_key is not None:
            clauses.append("memory_key = ?")
            params.append(memory_key)
        with self.repository._read() as db:
            db.execute("BEGIN")
            try:
                result = self._verified_page(
                    db,
                    query=f"""
                    SELECT * FROM agent_memories
                    WHERE {' AND '.join(clauses)}
                    ORDER BY updated_at DESC, memory_id ASC
                    """,
                    params=params,
                    verifier=lambda row: self._memory_row(row, db=db),
                    limit=limit,
                    offset=offset,
                )
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def revoke_memory(
        self,
        access: GovernanceAccess,
        memory_id: str,
        *,
        expected_revision: int,
        reason: str,
    ) -> dict[str, Any]:
        if not access.can_review:
            raise NotFoundError("受治理记忆不存在或无权撤销")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        memory_id = _identifier(memory_id, "memory_id", maximum=128)
        clean_reason = _text(reason, "revoke reason", maximum=2_000)
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM agent_memories WHERE memory_id = ?",
                (memory_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("受治理记忆不存在")
            self._authorize_row(access, row)
            if row["status"] != "active":
                raise ConflictError("只有当前有效记忆可以撤销")
            if int(row["revision"]) != expected_revision:
                raise ConflictError(f"受治理记忆已更新，当前修订号为 {row['revision']}")
            now = utc_text()
            public = self._memory_row(row, db=db)
            provenance = _append_lifecycle(
                public["provenance"],
                event_type="memory_revoked",
                actor_id=access.actor_id,
                occurred_at=now,
                details={"reason_sha256": sha256_json(clean_reason)},
            )
            public.update(
                {
                    "status": "revoked",
                    "provenance": provenance,
                    "updated_at": now,
                    "revision": expected_revision + 1,
                    "revoked_by": access.actor_id,
                    "revoked_at": now,
                }
            )
            updated = db.execute(
                """
                UPDATE agent_memories
                SET status = 'revoked', provenance_json = ?, updated_at = ?,
                    revision = ?, revoked_by = ?, revoked_at = ?,
                    record_sha256 = ?
                WHERE memory_id = ? AND revision = ? AND status = 'active'
                """,
                (
                    canonical_json(provenance),
                    now,
                    public["revision"],
                    access.actor_id,
                    now,
                    self._memory_record_digest(public),
                    memory_id,
                    expected_revision,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("受治理记忆已被并发更新")
        return self.get_memory(access, memory_id)

    def _public_memory_proposal(self, row: Any) -> dict[str, Any]:
        events = _verify_audit(row)
        _verify_proposal_lifecycle(row, events, prefix="memory")
        value = json.loads(row["value_json"])
        refs = json.loads(row["source_refs_json"])
        expected = self._memory_digest(
            scope_type=row["scope_type"],
            scope_id=row["scope_id"],
            memory_key=row["memory_key"],
            value=value,
            source_refs=refs,
            reason=row["reason"],
            proposed_by=row["proposed_by"],
            created_at=row["created_at"],
        )
        if not hmac.compare_digest(expected, str(row["proposal_sha256"])):
            raise ConflictError("记忆提案内容摘要不一致，拒绝读取")
        return {
            "proposal_id": row["proposal_id"],
            "proposal_type": "memory",
            "scope_type": row["scope_type"],
            "scope_id": row["scope_id"],
            "memory_key": row["memory_key"],
            "value": value,
            "source_refs": refs,
            "source_verification": (
                "declared_reference_not_independently_verified"
            ),
            "reason": row["reason"],
            "status": row["status"],
            "revision": int(row["revision"]),
            "proposed_by": row["proposed_by"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "decision_reason": row["decision_reason"],
            "proposal_sha256": row["proposal_sha256"],
            "audit": {
                "valid": True,
                "event_count": len(events),
                "event_head_hash": row["event_head_hash"],
                "events": events,
            },
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _memory_row(
        self,
        row: Any,
        *,
        verify: bool = True,
        db: Any | None = None,
    ) -> dict[str, Any]:
        public = {
            "memory_id": row["memory_id"],
            "scope_type": row["scope_type"],
            "scope_id": row["scope_id"],
            "memory_key": row["memory_key"],
            "version": int(row["version"]),
            "value": json.loads(row["value_json"]),
            "provenance": json.loads(row["provenance_json"]),
            "proposal_id": row["proposal_id"],
            "status": row["status"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "revision": int(row["revision"]),
            "revoked_by": row["revoked_by"],
            "revoked_at": row["revoked_at"],
        }
        valid = hmac.compare_digest(
            self._memory_record_digest(public), str(row["record_sha256"])
        )
        if verify and not valid:
            raise ConflictError("受治理记忆完整性校验失败，拒绝读取")
        if verify:
            if db is None:
                with self.repository._read() as read_db:
                    self._assert_memory_parent(read_db, public)
            else:
                self._assert_memory_parent(db, public)
        return {
            **public,
            "record_sha256": row["record_sha256"],
            "integrity": {"valid": valid},
            "source_verification": (
                "declared_reference_not_independently_verified"
            ),
        }

    def _assert_memory_parent(
        self,
        db: Any,
        memory: Mapping[str, Any],
    ) -> None:
        proposal_row = db.execute(
            """
            SELECT * FROM agent_memory_proposals
            WHERE proposal_id = ?
            """,
            (memory["proposal_id"],),
        ).fetchone()
        if proposal_row is None:
            raise ConflictError("受治理记忆缺少原始审批提案，拒绝读取")
        proposal = self._public_memory_proposal(proposal_row)
        provenance = memory.get("provenance")
        audit_events = proposal.get("audit", {}).get("events", [])
        approval_event = audit_events[-1] if audit_events else {}
        approval_details = approval_event.get("details", {})
        if not isinstance(provenance, Mapping):
            raise ConflictError("受治理记忆来源结构损坏，拒绝读取")
        if (
            proposal["status"] != "approved"
            or approval_event.get("event_type") != "memory_approved"
            or approval_details.get("memory_id") != memory["memory_id"]
            or approval_details.get("version") != memory["version"]
            or proposal["scope_type"] != memory["scope_type"]
            or proposal["scope_id"] != memory["scope_id"]
            or proposal["memory_key"] != memory["memory_key"]
            or proposal["value"] != memory["value"]
            or proposal["source_refs"] != provenance.get("source_refs")
            or proposal["proposal_sha256"]
            != provenance.get("proposal_sha256")
            or proposal["reviewed_by"] != memory["created_by"]
            or proposal["reviewed_at"] != memory["created_at"]
        ):
            raise ConflictError("受治理记忆与审批提案不一致，拒绝读取")

    def _validated_tools(self, allowed_tools: Any) -> tuple[list[str], str]:
        if (
            not isinstance(allowed_tools, list)
            or not 1 <= len(allowed_tools) <= 32
            or any(not isinstance(item, str) for item in allowed_tools)
        ):
            raise ValueError("allowed_tools 必须包含 1-32 个工具名称")
        normalized = [item.strip() for item in allowed_tools]
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed_tools 不能重复")
        for name in normalized:
            if (
                _TOOL_NAME.fullmatch(name) is None
                or self._dangerous_capability(name)
                or name == "draft_patch"
                or name not in self._tool_allowlist
            ):
                raise ValidationBlockedError(
                    f"技能工具 {name or '[空]'} 不在只读白名单"
                )
        normalized.sort()
        return normalized, canonical_json(normalized)

    def _validated_procedure(
        self, procedure: Any, allowed_tools: list[str]
    ) -> tuple[Any, str]:
        safe, encoded = _validated_json(
            procedure,
            "procedure",
            max_bytes=65_536,
            require_container=True,
        )

        def inspect(value: Any, path: str = "$.procedure") -> None:
            if isinstance(value, str):
                if self._dangerous_capability(value):
                    raise ValidationBlockedError(
                        f"{path} 描述了被禁止的写入、提交、网络或执行能力"
                    )
                return
            if isinstance(value, list):
                for index, child in enumerate(value):
                    inspect(child, f"{path}[{index}]")
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    if self._dangerous_capability(key):
                        raise ValidationBlockedError(
                            f"{path}.{key} 使用了危险能力字段"
                        )
                    if key in {"tool", "tool_name"} and (
                        not isinstance(child, str) or child not in allowed_tools
                    ):
                        raise ValidationBlockedError(
                            f"{path}.{key} 必须引用 allowed_tools 中的只读工具"
                        )
                    inspect(child, f"{path}.{key}")

        inspect(safe)
        return safe, encoded

    def create_skill_proposal(
        self,
        access: GovernanceAccess,
        *,
        skill_name: str,
        description: str,
        procedure: Any,
        allowed_tools: list[str],
        source_refs: list[dict[str, Any]],
        reason: str,
    ) -> dict[str, Any]:
        name = _identifier(skill_name, "skill_name", maximum=64)
        if (
            _SKILL_NAME.fullmatch(name) is None
            or self._dangerous_capability(name)
        ):
            raise ValueError("skill_name 仅允许小写字母、数字和连字符")
        clean_description = _text(description, "description", maximum=2_000)
        if self._dangerous_capability(clean_description):
            raise ValidationBlockedError("description 描述了被禁止的危险能力")
        safe_tools, tools_json = self._validated_tools(allowed_tools)
        safe_procedure, procedure_json = self._validated_procedure(
            procedure, safe_tools
        )
        safe_refs, refs_json = _source_references(source_refs)
        clean_reason = _text(reason, "reason", maximum=2_000)
        proposal_id = f"skillprop_{uuid.uuid4().hex}"
        now = utc_text()
        digest = self._skill_digest(
            skill_name=name,
            description=clean_description,
            procedure=safe_procedure,
            allowed_tools=safe_tools,
            source_refs=safe_refs,
            reason=clean_reason,
            proposed_by=access.actor_id,
            created_at=now,
        )
        event = _audit_event(
            [],
            proposal_id=proposal_id,
            event_type="skill_proposed",
            actor_id=access.actor_id,
            details={"proposal_sha256": digest},
            occurred_at=now,
        )
        with self.repository._transaction() as db:
            duplicates = db.execute(
                """
                SELECT * FROM agent_skill_proposals
                WHERE skill_name = ? AND proposed_by = ? AND status = 'pending'
                ORDER BY created_at, proposal_id
                """,
                (name, access.actor_id),
            ).fetchall()
            for duplicate in duplicates:
                try:
                    self._public_skill_proposal(duplicate)
                except ConflictError:
                    continue
                raise ConflictError("同名技能已有待审批提案")
            db.execute(
                """
                INSERT INTO agent_skill_proposals (
                    proposal_id, skill_name, description, procedure_json,
                    allowed_tools_json, source_refs_json, reason, status,
                    revision, proposed_by, proposal_sha256, audit_json,
                    event_count, event_head_hash, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    proposal_id,
                    name,
                    clean_description,
                    procedure_json,
                    tools_json,
                    refs_json,
                    clean_reason,
                    access.actor_id,
                    digest,
                    canonical_json([event]),
                    event["event_hash"],
                    now,
                    now,
                ),
            )
        return self.get_skill_proposal(access, proposal_id)

    def get_skill_proposal(
        self, access: GovernanceAccess, proposal_id: str
    ) -> dict[str, Any]:
        proposal_id = _identifier(proposal_id, "proposal_id", maximum=128)
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM agent_skill_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
        if row is None or (
            not access.can_manage_skills
            and row["proposed_by"] != access.actor_id
        ):
            raise NotFoundError("技能提案不存在或无权访问")
        return self._public_skill_proposal(row)

    def list_skill_proposals(
        self,
        access: GovernanceAccess,
        *,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if status is not None and status not in _PROPOSAL_STATUSES:
            raise ValueError("status 不受支持")
        limit, offset = _bounded_page(limit, offset)
        clauses: list[str] = []
        params: list[Any] = []
        if not access.can_manage_skills:
            clauses.append("proposed_by = ?")
            params.append(access.actor_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        where = " AND ".join(clauses) if clauses else "1 = 1"
        with self.repository._read() as db:
            return self._verified_page(
                db,
                query=f"""
                SELECT * FROM agent_skill_proposals WHERE {where}
                ORDER BY updated_at DESC, proposal_id ASC
                """,
                params=params,
                verifier=self._public_skill_proposal,
                limit=limit,
                offset=offset,
            )

    def decide_skill_proposal(
        self,
        access: GovernanceAccess,
        proposal_id: str,
        *,
        decision: str,
        expected_revision: int,
        reason: str,
    ) -> dict[str, Any]:
        if not access.can_manage_skills:
            raise NotFoundError("技能提案不存在或无权审批")
        if decision not in {"approve", "reject"}:
            raise ValueError("decision 必须是 approve 或 reject")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        proposal_id = _identifier(proposal_id, "proposal_id", maximum=128)
        clean_reason = _text(reason, "decision reason", maximum=2_000)
        version_id: str | None = None
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM agent_skill_proposals WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("技能提案不存在")
            if row["status"] != "pending":
                raise ConflictError("技能提案已完成审批")
            if int(row["revision"]) != expected_revision:
                raise ConflictError(f"技能提案已更新，当前修订号为 {row['revision']}")
            if row["proposed_by"] == access.actor_id and decision == "approve":
                raise ConflictError("技能提案必须由另一名审批人批准")
            verified = self._public_skill_proposal(row)
            safe_tools, _tools_json = self._validated_tools(
                json.loads(row["allowed_tools_json"])
            )
            self._validated_procedure(json.loads(row["procedure_json"]), safe_tools)
            events = list(verified["audit"]["events"])
            now = utc_text()
            next_status = "approved" if decision == "approve" else "rejected"
            details: dict[str, Any] = {
                "decision": decision,
                "reason_sha256": sha256_json(clean_reason),
            }
            if decision == "approve":
                version_id, version = self._publish_skill(
                    db, row=row, actor_id=access.actor_id, now=now
                )
                details.update(
                    {
                        "skill_version_id": version_id,
                        "version": version,
                        "runtime_activation": "approved_inactive",
                    }
                )
            event = _audit_event(
                events,
                proposal_id=proposal_id,
                event_type=f"skill_{next_status}",
                actor_id=access.actor_id,
                details=details,
                occurred_at=now,
            )
            events.append(event)
            updated = db.execute(
                """
                UPDATE agent_skill_proposals
                SET status = ?, revision = revision + 1, reviewed_by = ?,
                    reviewed_at = ?, decision_reason = ?, audit_json = ?,
                    event_count = ?, event_head_hash = ?, updated_at = ?
                WHERE proposal_id = ? AND revision = ? AND status = 'pending'
                """,
                (
                    next_status,
                    access.actor_id,
                    now,
                    clean_reason,
                    canonical_json(events),
                    len(events),
                    event["event_hash"],
                    now,
                    proposal_id,
                    expected_revision,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("技能提案已被并发更新")
        return {
            "proposal": self.get_skill_proposal(access, proposal_id),
            "skill_version": (
                self.get_skill_version(access, version_id)
                if version_id is not None
                else None
            ),
        }

    def _publish_skill(
        self, db: Any, *, row: Any, actor_id: str, now: str
    ) -> tuple[str, int]:
        active_rows = db.execute(
            """
            SELECT * FROM agent_skill_versions
            WHERE skill_name = ? AND status = 'active'
            """,
            (row["skill_name"],),
        ).fetchall()
        for current in active_rows:
            try:
                public = self._skill_row(current, db=db)
            except ConflictError:
                continue
            public.update(
                {
                    "status": "superseded",
                    "updated_at": now,
                    "revision": int(current["revision"]) + 1,
                }
            )
            db.execute(
                """
                UPDATE agent_skill_versions
                SET status = 'superseded', updated_at = ?, revision = ?,
                    record_sha256 = ?
                WHERE skill_version_id = ? AND revision = ?
                """,
                (
                    now,
                    public["revision"],
                    self._skill_record_digest(public),
                    current["skill_version_id"],
                    current["revision"],
                ),
            )
        version_row = db.execute(
            """
            SELECT COALESCE(MAX(version), 0) AS version
            FROM agent_skill_versions WHERE skill_name = ?
            """,
            (row["skill_name"],),
        ).fetchone()
        version = int(version_row["version"]) + 1
        skill_version_id = f"skillver_{uuid.uuid4().hex}"
        public = {
            "skill_version_id": skill_version_id,
            "skill_name": row["skill_name"],
            "version": version,
            "description": row["description"],
            "procedure": json.loads(row["procedure_json"]),
            "allowed_tools": json.loads(row["allowed_tools_json"]),
            "source_refs": json.loads(row["source_refs_json"]),
            "proposal_id": row["proposal_id"],
            "status": "active",
            "runtime_activation": "approved_inactive",
            "approved_by": actor_id,
            "approved_at": now,
            "created_at": now,
            "updated_at": now,
            "revision": 1,
            "retired_by": None,
            "retired_at": None,
            "retirement_reason": None,
        }
        db.execute(
            """
            INSERT INTO agent_skill_versions (
                skill_version_id, skill_name, version, description,
                procedure_json, allowed_tools_json, source_refs_json,
                proposal_id, status, runtime_activation, approved_by,
                approved_at, created_at, updated_at, revision, record_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', 'approved_inactive',
                      ?, ?, ?, ?, 1, ?)
            """,
            (
                skill_version_id,
                row["skill_name"],
                version,
                row["description"],
                row["procedure_json"],
                row["allowed_tools_json"],
                row["source_refs_json"],
                row["proposal_id"],
                actor_id,
                now,
                now,
                now,
                self._skill_record_digest(public),
            ),
        )
        return skill_version_id, version

    def get_skill_version(
        self, access: GovernanceAccess, skill_version_id: str
    ) -> dict[str, Any]:
        _identifier(access.actor_id, "actor_id", maximum=128)
        skill_version_id = _identifier(
            skill_version_id, "skill_version_id", maximum=128
        )
        with self.repository._read() as db:
            db.execute("BEGIN")
            try:
                row = db.execute(
                    """
                    SELECT * FROM agent_skill_versions
                    WHERE skill_version_id = ?
                    """,
                    (skill_version_id,),
                ).fetchone()
                if row is None:
                    raise NotFoundError("技能版本不存在")
                result = self._skill_row(row, db=db)
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def list_skill_versions(
        self,
        access: GovernanceAccess,
        *,
        status: str | None = "active",
        skill_name: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        _identifier(access.actor_id, "actor_id", maximum=128)
        if status is not None and status not in _SKILL_STATUSES:
            raise ValueError("status 不受支持")
        if skill_name is not None:
            skill_name = _identifier(skill_name, "skill_name", maximum=64)
        limit, offset = _bounded_page(limit, offset)
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if skill_name is not None:
            clauses.append("skill_name = ?")
            params.append(skill_name)
        where = " AND ".join(clauses) if clauses else "1 = 1"
        with self.repository._read() as db:
            db.execute("BEGIN")
            try:
                result = self._verified_page(
                    db,
                    query=f"""
                    SELECT * FROM agent_skill_versions WHERE {where}
                    ORDER BY skill_name ASC, version DESC
                    """,
                    params=params,
                    verifier=lambda row: self._skill_row(row, db=db),
                    limit=limit,
                    offset=offset,
                )
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def retire_skill_version(
        self,
        access: GovernanceAccess,
        skill_version_id: str,
        *,
        expected_revision: int,
        reason: str,
    ) -> dict[str, Any]:
        if not access.can_manage_skills:
            raise NotFoundError("技能版本不存在或无权停用")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        skill_version_id = _identifier(
            skill_version_id, "skill_version_id", maximum=128
        )
        clean_reason = _text(reason, "retire reason", maximum=2_000)
        with self.repository._transaction() as db:
            row = db.execute(
                """
                SELECT * FROM agent_skill_versions
                WHERE skill_version_id = ?
                """,
                (skill_version_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("技能版本不存在")
            if row["status"] != "active":
                raise ConflictError("只有当前有效技能版本可以停用")
            if int(row["revision"]) != expected_revision:
                raise ConflictError(f"技能版本已更新，当前修订号为 {row['revision']}")
            now = utc_text()
            public = self._skill_row(row, db=db)
            public.update(
                {
                    "status": "retired",
                    "updated_at": now,
                    "revision": expected_revision + 1,
                    "retired_by": access.actor_id,
                    "retired_at": now,
                    "retirement_reason": clean_reason,
                }
            )
            updated = db.execute(
                """
                UPDATE agent_skill_versions
                SET status = 'retired', updated_at = ?, revision = ?,
                    retired_by = ?, retired_at = ?, retirement_reason = ?,
                    record_sha256 = ?
                WHERE skill_version_id = ? AND revision = ? AND status = 'active'
                """,
                (
                    now,
                    public["revision"],
                    access.actor_id,
                    now,
                    clean_reason,
                    self._skill_record_digest(public),
                    skill_version_id,
                    expected_revision,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("技能版本已被并发更新")
        return self.get_skill_version(access, skill_version_id)

    def _public_skill_proposal(self, row: Any) -> dict[str, Any]:
        events = _verify_audit(row)
        _verify_proposal_lifecycle(row, events, prefix="skill")
        procedure = json.loads(row["procedure_json"])
        tools = json.loads(row["allowed_tools_json"])
        refs = json.loads(row["source_refs_json"])
        expected = self._skill_digest(
            skill_name=row["skill_name"],
            description=row["description"],
            procedure=procedure,
            allowed_tools=tools,
            source_refs=refs,
            reason=row["reason"],
            proposed_by=row["proposed_by"],
            created_at=row["created_at"],
        )
        if not hmac.compare_digest(expected, str(row["proposal_sha256"])):
            raise ConflictError("技能提案内容摘要不一致，拒绝读取")
        return {
            "proposal_id": row["proposal_id"],
            "proposal_type": "skill",
            "skill_name": row["skill_name"],
            "description": row["description"],
            "procedure": procedure,
            "allowed_tools": tools,
            "source_refs": refs,
            "source_verification": (
                "declared_reference_not_independently_verified"
            ),
            "reason": row["reason"],
            "status": row["status"],
            "revision": int(row["revision"]),
            "proposed_by": row["proposed_by"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "decision_reason": row["decision_reason"],
            "proposal_sha256": row["proposal_sha256"],
            "runtime_activation": "proposal_only",
            "audit": {
                "valid": True,
                "event_count": len(events),
                "event_head_hash": row["event_head_hash"],
                "events": events,
            },
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _skill_row(
        self,
        row: Any,
        *,
        verify: bool = True,
        db: Any | None = None,
    ) -> dict[str, Any]:
        public = {
            "skill_version_id": row["skill_version_id"],
            "skill_name": row["skill_name"],
            "version": int(row["version"]),
            "description": row["description"],
            "procedure": json.loads(row["procedure_json"]),
            "allowed_tools": json.loads(row["allowed_tools_json"]),
            "source_refs": json.loads(row["source_refs_json"]),
            "proposal_id": row["proposal_id"],
            "status": row["status"],
            "runtime_activation": row["runtime_activation"],
            "approved_by": row["approved_by"],
            "approved_at": row["approved_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "revision": int(row["revision"]),
            "retired_by": row["retired_by"],
            "retired_at": row["retired_at"],
            "retirement_reason": row["retirement_reason"],
        }
        valid = hmac.compare_digest(
            self._skill_record_digest(public), str(row["record_sha256"])
        )
        if verify and not valid:
            raise ConflictError("技能版本完整性校验失败，拒绝读取")
        if verify:
            if db is None:
                with self.repository._read() as read_db:
                    self._assert_skill_parent(read_db, public)
            else:
                self._assert_skill_parent(db, public)
        return {
            **public,
            "record_sha256": row["record_sha256"],
            "integrity": {"valid": valid},
            "runtime_loaded": False,
            "source_verification": (
                "declared_reference_not_independently_verified"
            ),
        }

    def _assert_skill_parent(
        self,
        db: Any,
        skill: Mapping[str, Any],
    ) -> None:
        proposal_row = db.execute(
            """
            SELECT * FROM agent_skill_proposals
            WHERE proposal_id = ?
            """,
            (skill["proposal_id"],),
        ).fetchone()
        if proposal_row is None:
            raise ConflictError("技能版本缺少原始审批提案，拒绝读取")
        proposal = self._public_skill_proposal(proposal_row)
        audit_events = proposal.get("audit", {}).get("events", [])
        approval_event = audit_events[-1] if audit_events else {}
        approval_details = approval_event.get("details", {})
        if (
            proposal["status"] != "approved"
            or approval_event.get("event_type") != "skill_approved"
            or approval_details.get("skill_version_id")
            != skill["skill_version_id"]
            or approval_details.get("version") != skill["version"]
            or approval_details.get("runtime_activation")
            != skill["runtime_activation"]
            or proposal["skill_name"] != skill["skill_name"]
            or proposal["description"] != skill["description"]
            or proposal["procedure"] != skill["procedure"]
            or proposal["allowed_tools"] != skill["allowed_tools"]
            or proposal["source_refs"] != skill["source_refs"]
            or proposal["reviewed_by"] != skill["approved_by"]
            or proposal["reviewed_at"] != skill["approved_at"]
        ):
            raise ConflictError("技能版本与审批提案不一致，拒绝读取")
