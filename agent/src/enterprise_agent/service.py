"""Application service enforcing the human-confirmation boundary."""

from __future__ import annotations

import re
import threading
import uuid
from typing import Any

from .agent_v2.governance import GovernanceStore
from .agent_v2.models import FlowRuntimeConfig
from .agent_v2.runtime import AgentFlowRuntime
from .agent_v2.scheduler import AgentJobScheduler
from .chat import CoalChatRuntime
from .client import PlatformClient
from .errors import (
    ConfirmationRequiredError,
    ConflictError,
    ImportContentError,
    PlatformError,
    ValidationBlockedError,
)
from .five_quantity_runtime import FiveQuantityRuntime
from .harness import HarnessRuntime
from .importers import import_text, merge_import
from .llm import OpenAICompatibleProvider
from .models import (
    SUBMISSION_SCHEMA_VERSION,
    new_draft,
    provenance_record,
)
from .security import normalize_observation, observation_payload
from .settings import AgentV2Config
from .skills import SkillRegistry, build_skill_registry
from .storage import Repository
from .util import (
    deep_copy_json,
    parse_aware_datetime,
    random_id,
    sha256_jcs,
    sha256_json,
    sha256_text,
    utc_text,
)
from .validation import questions_for_draft, validate_draft

_ACTOR = re.compile(r"^[A-Za-z0-9\u4e00-\u9fff][A-Za-z0-9\u4e00-\u9fff._:@ -]{0,127}$")
_MUTABLE_FIELDS = {
    "enterprise_id",
    "enterprise_name",
    "unified_social_credit_code",
    "mine_id",
    "mine_name",
    "window_start",
    "window_end",
    "profile_id",
    "profile_version",
    "operational_context",
    "observations",
    "notes",
}
_CONFIRMATION_STATEMENT = "enterprise-confirmation-v1"
_CONTEXT_FIELDS = {
    "regime_code",
    "shift_code",
    "season_code",
    "maintenance",
    "approved_event_codes",
    "tags",
}
_SOURCE_CREDENTIAL_FIELDS = {"payload_sha256", "signature"}


def _observation_business_fingerprint(observation: dict[str, Any]) -> str | None:
    """Fingerprint the source-covered payload plus its local metric label."""

    try:
        return sha256_json(
            {
                "source_payload": observation_payload(observation),
                # metric_code is local-only and is not covered by the source
                # HMAC, but changing its business meaning must still discard
                # the credentials attached to the draft row.
                "metric_code": observation.get("metric_code"),
            }
        )
    except (KeyError, TypeError, ValueError):
        return None


def _invalidate_changed_source_credentials(
    previous: Any,
    replacement: Any,
) -> tuple[Any, set[int], dict[int, int]]:
    """Remove source credentials when an existing observation is edited."""

    if not isinstance(replacement, list):
        return replacement, set(), {}
    old_rows = previous if isinstance(previous, list) else []
    rows = deep_copy_json(replacement)
    invalidated: set[int] = set()
    alignment: dict[int, int] = {}

    def unique_rows(
        values: list[Any],
    ) -> dict[str, tuple[int, dict[str, Any]]]:
        result: dict[str, tuple[int, dict[str, Any]]] = {}
        duplicates: set[str] = set()
        for index, row in enumerate(values):
            if not isinstance(row, dict):
                continue
            observation_id = row.get("observation_id")
            if not isinstance(observation_id, str) or not observation_id:
                continue
            if observation_id in result:
                duplicates.add(observation_id)
            result[observation_id] = (index, row)
        for observation_id in duplicates:
            result.pop(observation_id, None)
        return result

    old_by_id = unique_rows(old_rows)
    new_by_id = unique_rows(rows)
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        observation_id = row.get("observation_id")
        old_entry = (
            old_by_id.get(observation_id)
            if isinstance(observation_id, str) and observation_id in new_by_id
            else None
        )
        if old_entry is None:
            continue
        old_index, old = old_entry
        alignment[index] = old_index
        old_has_credentials = any(
            isinstance(old.get(field), str) and bool(old.get(field))
            for field in _SOURCE_CREDENTIAL_FIELDS
        )
        old_fingerprint = _observation_business_fingerprint(old)
        new_fingerprint = _observation_business_fingerprint(row)
        if old_has_credentials and (
            old_fingerprint is None
            or new_fingerprint is None
            or old_fingerprint != new_fingerprint
        ):
            for field in _SOURCE_CREDENTIAL_FIELDS:
                row.pop(field, None)
            invalidated.add(index)
            continue
        if old_fingerprint == new_fingerprint:
            # A form client need not echo opaque credentials on an unchanged
            # row.  Preserve exactly what the gateway issued.
            for field in _SOURCE_CREDENTIAL_FIELDS:
                if field not in row and field in old:
                    row[field] = old[field]
    return rows, invalidated, alignment


def _json_same(left: Any, right: Any) -> bool:
    try:
        return sha256_json(left) == sha256_json(right)
    except (TypeError, ValueError):
        return type(left) is type(right) and left == right


def _effective_patch(
    previous: dict[str, Any],
    merged: dict[str, Any],
    patch: dict[str, Any],
) -> dict[str, Any]:
    effective: dict[str, Any] = {}
    for field in patch:
        if field == "operational_context":
            old_context = previous.get(field)
            new_context = merged.get(field)
            supplied = patch[field]
            if not all(
                isinstance(value, dict)
                for value in (old_context, new_context, supplied)
            ):
                if not _json_same(old_context, new_context):
                    effective[field] = deep_copy_json(new_context)
                continue
            changed_context = {
                key: deep_copy_json(new_context[key])
                for key in supplied
                if (
                    not _json_same(old_context.get(key), new_context.get(key))
                    or not isinstance(
                        previous.get("field_provenance", {}).get(
                            f"/operational_context/{key}"
                        ),
                        list,
                    )
                    or not previous["field_provenance"].get(
                        f"/operational_context/{key}"
                    )
                )
            }
            if changed_context:
                effective[field] = changed_context
        elif not _json_same(previous.get(field), merged.get(field)):
            effective[field] = deep_copy_json(merged.get(field))
    return effective


def _remap_observation_provenance(
    provenance: dict[str, Any],
    alignment: dict[int, int],
) -> dict[str, Any]:
    result = {
        pointer: deep_copy_json(records)
        for pointer, records in provenance.items()
        if not pointer.startswith("/observations/")
    }
    by_old_index: dict[int, list[tuple[str, Any]]] = {}
    for pointer, records in provenance.items():
        match = re.match(r"^/observations/(\d+)(/.*)$", pointer)
        if match is None:
            continue
        by_old_index.setdefault(int(match.group(1)), []).append(
            (match.group(2), records)
        )
    for new_index, old_index in alignment.items():
        for suffix, records in by_old_index.get(old_index, []):
            result[f"/observations/{new_index}{suffix}"] = deep_copy_json(records)
    return result


def _actor(value: Any) -> str:
    if not isinstance(value, str) or not _ACTOR.fullmatch(value.strip()):
        raise ValueError("actor 必须是 1 到 128 字符的有效人员编号")
    return value.strip()


def _document(stored: dict[str, Any]) -> dict[str, Any]:
    return {
        key: deep_copy_json(value)
        for key, value in stored.items()
        if key not in {"_meta", "status", "receipt"}
    }


def _llm_safe_context(document: dict[str, Any]) -> dict[str, Any]:
    """Return only editable business context, never evidence credentials."""

    result = {
        field: deep_copy_json(document[field])
        for field in _MUTABLE_FIELDS
        if field in document and field != "observations"
    }
    observations = document.get("observations")
    if isinstance(observations, list):
        result["observations"] = [
            {
                key: deep_copy_json(value)
                for key, value in observation.items()
                if key not in _SOURCE_CREDENTIAL_FIELDS
            }
            if isinstance(observation, dict)
            else observation
            for observation in observations
        ]
    return result


def _manual_provenance(
    patch: dict[str, Any], *, actor: str
) -> dict[str, list[dict[str, Any]]]:
    digest = sha256_json(patch)
    result: dict[str, list[dict[str, Any]]] = {}

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if not value:
                result[path] = [
                    provenance_record(
                        source_kind="manual",
                        source_name=actor,
                        locator="enterprise-agent-form",
                        content_sha256=digest,
                        confidence=1.0,
                        extraction_method="human_entry",
                    )
                ]
            for key, child in value.items():
                walk(child, f"{path}/{key}")
        elif isinstance(value, list):
            if not value:
                result[path] = [
                    provenance_record(
                        source_kind="manual",
                        source_name=actor,
                        locator="enterprise-agent-form",
                        content_sha256=digest,
                        confidence=1.0,
                        extraction_method="human_entry",
                    )
                ]
            for index, child in enumerate(value):
                walk(child, f"{path}/{index}")
        else:
            result[path] = [
                provenance_record(
                    source_kind="manual",
                    source_name=actor,
                    locator="enterprise-agent-form",
                    content_sha256=digest,
                    confidence=1.0,
                    extraction_method="human_entry",
                )
            ]

    for field, value in patch.items():
        walk(value, f"/{field}")
    return result


def _merge_patch(document: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    unknown = set(patch) - _MUTABLE_FIELDS
    if unknown:
        raise ValueError(
            "不允许修改字段：" + ", ".join(sorted(str(item) for item in unknown))
        )
    merged = deep_copy_json(document)
    for key, value in patch.items():
        if key == "operational_context":
            if not isinstance(value, dict):
                raise ValueError("operational_context 必须是对象")
            unknown_context = set(value) - _CONTEXT_FIELDS
            if unknown_context:
                raise ValueError(
                    "不支持的工况字段："
                    + ", ".join(sorted(str(item) for item in unknown_context))
                )
            merged.setdefault(key, {}).update(deep_copy_json(value))
        else:
            merged[key] = deep_copy_json(value)
    return merged


def _pointer_value(document: dict[str, Any], pointer: str) -> Any:
    current: Any = document
    for raw_segment in pointer.lstrip("/").split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if segment not in current:
                return None
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit():
            index = int(segment)
            if index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def _pointer_touched(patch: dict[str, Any], pointer: str) -> bool:
    first = pointer.lstrip("/").split("/", 1)[0].replace("~1", "/").replace("~0", "~")
    return first in patch


def _contract_pointer(draft_pointer: str) -> str:
    direct = {
        "/enterprise_id": "/payload/enterprise/enterprise_id",
        "/enterprise_name": "/payload/enterprise/enterprise_name",
        "/unified_social_credit_code": (
            "/payload/enterprise/unified_social_credit_code"
        ),
        "/mine_id": "/payload/mine/mine_id",
        "/mine_name": "/payload/mine/mine_name",
        "/window_start": "/payload/window/window_start",
        "/window_end": "/payload/window/window_end",
        "/profile_id": "/payload/profile/profile_id",
        "/profile_version": "/payload/profile/profile_version",
        # Notes are local-only. Their only contract-visible effect is the
        # mandatory disclosure that model assistance occurred.
        "/notes": "/payload/llm_assistance",
    }
    if draft_pointer in direct:
        return direct[draft_pointer]
    for prefix in ("/operational_context/", "/observations/"):
        if draft_pointer.startswith(prefix):
            return "/payload" + draft_pointer
    raise ValidationBlockedError(f"模型影响路径无法映射到提交合同：{draft_pointer}")


def _snapshot_text(
    snapshot: dict[str, Any],
    field: str,
    maximum: int,
) -> str:
    value = snapshot.get(field)
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.strip()) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ImportContentError(f"事件快照 {field} 必须是 1-{maximum} 字符的安全文本")
    return value.strip()


def _validate_event_snapshot(
    snapshot: Any,
    document: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ImportContentError("事件快照必须是 JSON 对象")
    required = {
        "snapshot_id",
        "mine_id",
        "window_start",
        "window_end",
        "event_codes",
        "evidence_sha256",
        "source_system",
        "record_id",
    }
    allowed_metadata = {
        "created_at",
        "created_by",
        "content_sha256",
        "hash_valid",
        "created",
    }
    missing = required - set(snapshot)
    unknown = set(snapshot) - required - allowed_metadata
    if missing:
        raise ImportContentError("事件快照缺少字段：" + ", ".join(sorted(missing)))
    if unknown:
        raise ImportContentError("事件快照包含未知字段：" + ", ".join(sorted(unknown)))
    mine_id = _snapshot_text(snapshot, "mine_id", 128)
    if mine_id != document.get("mine_id"):
        raise ImportContentError("事件快照 mine_id 与当前草稿矿井不一致")
    try:
        snapshot_start = parse_aware_datetime(
            snapshot.get("window_start"),
            "event_snapshot.window_start",
        )
        snapshot_end = parse_aware_datetime(
            snapshot.get("window_end"),
            "event_snapshot.window_end",
        )
        draft_start = parse_aware_datetime(
            document.get("window_start"),
            "window_start",
        )
        draft_end = parse_aware_datetime(
            document.get("window_end"),
            "window_end",
        )
    except ValueError as error:
        raise ImportContentError(str(error)) from error
    if snapshot_start != draft_start or snapshot_end != draft_end:
        raise ImportContentError("事件快照统计窗口与当前草稿不一致")
    event_codes = snapshot.get("event_codes")
    if (
        not isinstance(event_codes, list)
        or len(event_codes) > 32
        or any(
            not isinstance(code, str)
            or not code
            or code != code.strip()
            or len(code) > 64
            or any(ord(character) < 32 or ord(character) == 127 for character in code)
            for code in event_codes
        )
        or len(event_codes) != len(set(event_codes))
    ):
        raise ImportContentError(
            "事件快照 event_codes 必须是最多 32 个不重复安全短文本"
        )
    evidence = snapshot.get("evidence_sha256")
    if not isinstance(evidence, str) or re.fullmatch(r"[0-9a-f]{64}", evidence) is None:
        raise ImportContentError(
            "事件快照 evidence_sha256 必须是 64 位小写十六进制摘要"
        )
    return {
        "snapshot_id": _snapshot_text(snapshot, "snapshot_id", 128),
        "mine_id": mine_id,
        "window_start": utc_text(snapshot_start),
        "window_end": utc_text(snapshot_end),
        "event_codes": sorted(event_codes),
        "evidence_sha256": evidence,
        "source_system": _snapshot_text(snapshot, "source_system", 128),
        "record_id": _snapshot_text(snapshot, "record_id", 256),
    }


class EnterpriseAgentService:
    def __init__(
        self,
        repository: Repository,
        *,
        platform_client: PlatformClient | None = None,
        llm_provider: OpenAICompatibleProvider | None = None,
        skill_registry: SkillRegistry | None = None,
        agent_v2_config: AgentV2Config | None = None,
        five_quantity_runtime: FiveQuantityRuntime | None = None,
        four_eyes_required: bool = False,
        production_mode: bool = False,
    ):
        self.repository = repository
        self.platform_client = platform_client
        self.llm_provider = llm_provider
        self.skills = (
            skill_registry if skill_registry is not None else build_skill_registry()
        )
        self.agent_v2_config = agent_v2_config or AgentV2Config()
        self.governance = GovernanceStore(repository)
        # A single local service process must never race two network attempts
        # for one persisted idempotency record. SQLite remains the durable
        # cross-restart authority; this lock closes the in-process window.
        self._submission_lock = threading.RLock()
        self._integrity_lock = threading.RLock()
        self._production_integrity_snapshot: dict[str, Any] | None = None
        self._harness_lock = threading.RLock()
        self._harness: HarnessRuntime | None = None
        self._chat: CoalChatRuntime | None = None
        self._agent_v2: AgentFlowRuntime | None = None
        self._agent_jobs: AgentJobScheduler | None = None
        self._five_quantity = five_quantity_runtime
        self.four_eyes_required = bool(four_eyes_required)
        self.production_mode = bool(production_mode)

    def _full_integrity_status(self) -> dict[str, Any]:
        """Run the authoritative, linear-history startup verification."""

        generic = self.repository.verify_all_draft_audits()
        five_quantity = (
            self._five_quantity.store.verify_audit()
            if self._five_quantity is not None
            else {"valid": True, "event_count": 0, "not_configured": True}
        )
        return {
            "valid": bool(generic["valid"] and five_quantity["valid"]),
            "generic_drafts": generic,
            "five_quantity_v2": five_quantity,
        }

    def _runtime_integrity_boundary(self) -> dict[str, Any]:
        additional_check = (
            self._five_quantity.store.runtime_integrity_boundary_intact
            if self._five_quantity is not None
            else None
        )
        return self.repository.verify_runtime_integrity_boundary(
            additional_check=additional_check
        )

    def integrity_status(self) -> dict[str, Any]:
        """Return readiness without repeatedly walking production history.

        Non-production diagnostics retain the live full scan.  A production
        process must first pass :meth:`assert_production_integrity`; subsequent
        health probes compare constant-size runtime guards and return counts
        from that trusted full-scan snapshot.
        """

        if not self.production_mode:
            return self._full_integrity_status()
        with self._integrity_lock:
            snapshot = self._production_integrity_snapshot
            if snapshot is None:
                raise ConflictError(
                    "正式模式尚未完成启动全链核验；就绪状态拒绝放行"
                )
            runtime_boundary = self._runtime_integrity_boundary()
            status = deep_copy_json(snapshot["status"])
            completed_at = str(snapshot["completed_at"])
            status["valid"] = True
            status["integrity_mode"] = "runtime_constant_boundary"
            status["runtime_boundary"] = runtime_boundary
            status["full_scan_snapshot"] = {
                "kind": "trusted_startup_full_scan",
                "completed_at": completed_at,
                "counts_are_snapshot": True,
            }
            for key in ("generic_drafts", "five_quantity_v2"):
                component = status.get(key)
                if isinstance(component, dict):
                    component["count_source"] = "trusted_full_scan_snapshot"
                    component["full_scan_completed_at"] = completed_at
            return status

    def assert_production_integrity(self) -> None:
        if not self.production_mode:
            return
        with self._integrity_lock:
            # Never retain an older successful result across an explicit
            # recheck. A failed marker is latched by Repository and cannot be
            # healed by rerunning this scan in the current process.
            self._production_integrity_snapshot = None
            status = self._full_integrity_status()
            if not status["valid"]:
                raise ValueError(
                    "正式模式审计完整性检查失败；服务不会启动、确认、排队或发送，"
                    "请由管理员核验数据库、审计锚点和保护触发器"
                )
            # Bind the cached result to the already armed marker latch and the
            # fixed Generic/FQ trigger + anchor boundary before publication.
            self._runtime_integrity_boundary()
            self._production_integrity_snapshot = {
                "completed_at": utc_text(),
                "status": deep_copy_json(status),
            }

    def _enforce_four_eyes(self, draft_id: str, *, actor: str) -> str:
        last_actor = self.repository.last_content_actor(draft_id)
        if self.four_eyes_required and actor == last_actor:
            raise ValidationBlockedError(
                "四眼复核已启用：当前账号是本修订版的最后创建/编辑人，"
                "请退出并由另一名具备复核权限的具名账号确认或提交"
            )
        return last_actor

    def enable_harness(self) -> HarnessRuntime:
        """Start the long-lived harness only for the HTTP serve process."""

        with self._harness_lock:
            if self._five_quantity is not None:
                self._five_quantity.start()
            if self._harness is None:
                self._harness = HarnessRuntime(
                    self,
                    llm_provider=self.llm_provider,
                )
                self._chat = CoalChatRuntime(
                    self,
                    self._harness,
                    skills=self.skills,
                )
            if self.agent_v2_config.enabled and self._agent_v2 is None:
                self._agent_v2 = AgentFlowRuntime(
                    self,
                    config=FlowRuntimeConfig(
                        worker_count=self.agent_v2_config.worker_count,
                        specialist_worker_count=(
                            self.agent_v2_config.specialist_worker_count
                        ),
                        lease_seconds=(self.agent_v2_config.flow_lease_seconds),
                    ),
                )
                self._agent_jobs = AgentJobScheduler(
                    self.repository,
                    self._agent_v2,
                    poll_seconds=(self.agent_v2_config.scheduler_poll_seconds),
                    auto_start=self.agent_v2_config.scheduler_enabled,
                )
            return self._harness

    @property
    def five_quantity(self) -> FiveQuantityRuntime:
        if self._five_quantity is None:
            raise RuntimeError("十量 V3 运行时未配置")
        return self._five_quantity

    @property
    def harness(self) -> HarnessRuntime:
        if self._harness is None:
            raise RuntimeError("Harness 仅在企业端 serve 进程中启用")
        return self._harness

    @property
    def chat(self) -> CoalChatRuntime:
        if self._chat is None:
            raise RuntimeError("煤炭对话仅在企业端 serve 进程中启用")
        return self._chat

    @property
    def agent_v2(self) -> AgentFlowRuntime:
        if self._agent_v2 is None:
            raise RuntimeError("Agent V2 仅在已启用的企业端 serve 进程中运行")
        return self._agent_v2

    @property
    def agent_jobs(self) -> AgentJobScheduler:
        if self._agent_jobs is None:
            raise RuntimeError("Agent V2 调度器当前不可用")
        return self._agent_jobs

    def disable_harness(self) -> None:
        with self._harness_lock:
            if self._five_quantity is not None:
                self._five_quantity.close()
            if self._agent_jobs is not None:
                self._agent_jobs.close()
                self._agent_jobs = None
            if self._agent_v2 is not None:
                self._agent_v2.close()
                self._agent_v2 = None
            if self._harness is not None:
                self._harness.close()
                self._harness = None
                self._chat = None

    def create_draft(
        self, values: dict[str, Any] | None = None, *, actor: str
    ) -> dict[str, Any]:
        principal = _actor(actor)
        document = new_draft()
        values = values or {}
        if not isinstance(values, dict):
            raise ValueError("草稿内容必须是对象")
        document = _merge_patch(document, values)
        provenance = _manual_provenance(values, actor=principal)
        document["field_provenance"].update(provenance)
        return self.repository.create_draft(document, actor=principal)

    def list_drafts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        return self.repository.draft_summary_page(limit=limit, offset=offset)

    def get_draft(self, draft_id: str) -> dict[str, Any]:
        draft = self.repository.get_draft(draft_id)
        if self.four_eyes_required:
            last_actor = self.repository.last_content_actor(draft_id)
            confirmation = draft["_meta"].get("confirmation")
            reviewer = (
                confirmation.get("confirmer_id")
                if isinstance(confirmation, dict)
                else None
            )
            independently_confirmed = bool(
                draft["_meta"].get("confirmed")
                and isinstance(reviewer, str)
                and reviewer
                and reviewer != last_actor
            )
            draft["_meta"]["four_eyes"] = {
                "required": True,
                "last_content_actor": last_actor,
                "state": (
                    "independent_review_completed"
                    if independently_confirmed
                    else "awaiting_independent_reviewer"
                ),
                "reviewer_actor": reviewer,
                "message": (
                    "已由不同具名账号完成四眼复核"
                    if independently_confirmed
                    else "须由不同于最后创建/编辑人的具名账号复核并报送"
                ),
            }
        else:
            draft["_meta"]["four_eyes"] = {
                "required": False,
                "state": "not_required",
                "message": "当前为演示/调试单人流程，不得据此视为正式报送配置",
            }
        return draft

    def patch_draft(
        self,
        draft_id: str,
        patch: dict[str, Any],
        *,
        actor: str,
        expected_revision: int | None = None,
        audit_details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        principal = _actor(actor)
        if not isinstance(patch, dict) or not patch:
            raise ValueError("patch 必须是非空对象")
        stored = self.repository.get_draft(draft_id)
        document = _document(stored)
        safe_patch = deep_copy_json(patch)
        invalidated_credentials: set[int] = set()
        observation_alignment: dict[int, int] = {}
        if "observations" in safe_patch:
            (
                safe_patch["observations"],
                invalidated_credentials,
                observation_alignment,
            ) = _invalidate_changed_source_credentials(
                document.get("observations"),
                safe_patch["observations"],
            )
        merged = _merge_patch(document, safe_patch)
        effective_patch = _effective_patch(document, merged, safe_patch)
        if (
            expected_revision is not None
            and expected_revision != stored["_meta"]["revision"]
        ):
            raise ConflictError(
                f"草稿已更新，当前修订号为 {stored['_meta']['revision']}"
            )
        if not effective_patch:
            return stored
        if {
            "mine_id",
            "window_start",
            "window_end",
        } & set(effective_patch):
            merged["field_provenance"].pop(
                "/operational_context/approved_event_codes",
                None,
            )
        if "observations" in effective_patch:
            merged["field_provenance"] = _remap_observation_provenance(
                document["field_provenance"],
                observation_alignment,
            )
        manual_records = _manual_provenance(
            effective_patch,
            actor=principal,
        )
        if "observations" in effective_patch:
            old_rows = document.get("observations")
            new_rows = merged.get("observations")
            if isinstance(old_rows, list) and isinstance(new_rows, list):
                for pointer in tuple(manual_records):
                    match = re.match(
                        r"^/observations/(\d+)(/.*)$",
                        pointer,
                    )
                    if match is None:
                        continue
                    new_index = int(match.group(1))
                    old_index = observation_alignment.get(new_index)
                    if old_index is None:
                        continue
                    old_pointer = f"/observations/{old_index}{match.group(2)}"
                    if _json_same(
                        _pointer_value(document, old_pointer),
                        _pointer_value(merged, pointer),
                    ):
                        manual_records.pop(pointer, None)
        merged["field_provenance"].update(manual_records)
        for index in invalidated_credentials:
            for field in _SOURCE_CREDENTIAL_FIELDS:
                merged["field_provenance"].pop(
                    f"/observations/{index}/{field}",
                    None,
                )
        llm = merged.get("llm_assistance")
        accepted_paths: set[str] = set()
        if isinstance(llm, dict):
            accepted_paths.update(llm.get("accepted_field_paths", []))
            for suggestion in llm.get("suggestions", []):
                if not isinstance(suggestion, dict):
                    continue
                path = suggestion.get("path")
                if (
                    not isinstance(path, str)
                    or not _pointer_touched(effective_patch, path)
                    or _pointer_value(merged, path) != suggestion.get("value")
                ):
                    continue
                accepted_paths.add(path)
                merged["field_provenance"].setdefault(path, []).append(
                    provenance_record(
                        source_kind="manual",
                        source_name="llm-assisted-source",
                        locator=str(
                            suggestion.get("source_locator") or "model-source-location"
                        )[:512],
                        content_sha256=str(
                            llm.get("source_content_sha256") or sha256_json(suggestion)
                        ),
                        confidence=float(suggestion["confidence"]),
                        extraction_method="llm_extraction",
                    )
                )
            llm["accepted_field_paths"] = sorted(accepted_paths)
        return self.repository.replace_draft(
            draft_id,
            merged,
            actor=principal,
            event_type="draft_updated",
            details={
                "changed_fields": sorted(effective_patch),
                "invalidated_source_credentials": sorted(invalidated_credentials),
                **(audit_details or {}),
            },
            expected_revision=expected_revision,
        )

    def delete_draft(
        self,
        draft_id: str,
        *,
        actor: str,
        expected_revision: int | None = None,
    ) -> None:
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        self.repository.soft_delete(
            draft_id,
            actor=_actor(actor),
            expected_revision=expected_revision,
        )

    def import_into_draft(
        self,
        draft_id: str,
        *,
        format_name: str,
        content: str,
        source_name: str | None,
        actor: str,
        expected_revision: int | None = None,
        source_system: str | None = None,
        original_filename: str | None = None,
        truth_statement: bool | None = None,
    ) -> dict[str, Any]:
        principal = _actor(actor)
        if source_system is not None:
            if not isinstance(source_system, str):
                raise ImportContentError("source_system 必须是文本")
            source_system = source_system.strip() or None
            if source_system is not None and (
                len(source_system) > 128
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in source_system
                )
            ):
                raise ImportContentError(
                    "source_system 必须是不超过 128 字符的安全文本"
                )
        if original_filename is not None:
            if not isinstance(original_filename, str):
                raise ImportContentError("original_filename 必须是文件名字符串")
            original_filename = original_filename.strip()
            if (
                not original_filename
                or len(original_filename) > 255
                or original_filename in {".", ".."}
                or any(character in original_filename for character in "/\\")
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in original_filename
                )
            ):
                raise ImportContentError(
                    "original_filename 必须是 1-255 字符且不含路径或控制字符"
                )
        if truth_statement is not None and truth_statement is not True:
            raise ImportContentError("导入前必须明确确认来源材料真实性声明")
        imported = import_text(format_name, content, source_name=source_name)
        stored = self.repository.get_draft(draft_id)
        previous_document = _document(stored)
        merged = merge_import(previous_document, imported)
        scope_changed = any(
            not _json_same(previous_document.get(field), merged.get(field))
            for field in ("mine_id", "window_start", "window_end")
        )
        event_pointer = "/operational_context/approved_event_codes"
        previous_codes = previous_document.get("operational_context", {}).get(
            "approved_event_codes"
        )
        merged_codes = merged.get("operational_context", {}).get("approved_event_codes")
        previous_event_provenance = previous_document.get("field_provenance", {}).get(
            event_pointer
        )
        imported_event_provenance = imported["field_provenance"].get(event_pointer)
        same_event_code_set = (
            isinstance(previous_codes, list)
            and isinstance(merged_codes, list)
            and all(isinstance(code, str) for code in previous_codes)
            and all(isinstance(code, str) for code in merged_codes)
            and len(previous_codes) == len(set(previous_codes))
            and len(merged_codes) == len(set(merged_codes))
            and set(previous_codes) == set(merged_codes)
        )
        has_authoritative_snapshot = isinstance(
            previous_event_provenance, list
        ) and any(
            isinstance(record, dict)
            and record.get("source_kind") == "approved_document"
            and record.get("extraction_method") == "regulator_event_snapshot_import"
            for record in previous_event_provenance
        )
        if scope_changed:
            merged["field_provenance"].pop(
                event_pointer,
                None,
            )
        elif (
            imported_event_provenance is not None
            and same_event_code_set
            and has_authoritative_snapshot
        ):
            # A complete business export commonly repeats the event code set.
            # Keep the regulator snapshot credential when that repetition is
            # semantically identical, while retaining the new import lineage.
            combined = deep_copy_json(previous_event_provenance)
            for record in imported_event_provenance:
                if record not in combined:
                    combined.append(deep_copy_json(record))
            merged["field_provenance"][event_pointer] = combined
        content_sha256 = sha256_text(content)
        imported_at = utc_text()
        resolved_source_name = (
            source_name.strip()
            if isinstance(source_name, str)
            else f"pasted.{format_name.lower()}"
        )
        source_manifest = merged.get("imports")
        if not isinstance(source_manifest, list):
            source_manifest = []
        # Complete history remains in the append-only audit table. Keep the
        # operator-facing manifest bounded so repeated imports cannot make
        # every draft read grow without limit.
        source_manifest = deep_copy_json(source_manifest[-499:])
        source_manifest.append(
            {
                "id": random_id("import"),
                "name": resolved_source_name,
                "filename": original_filename,
                "format": format_name.lower(),
                "source_system": source_system,
                "imported_at": imported_at,
                "content_sha256": content_sha256,
                "truth_statement": truth_statement is True,
            }
        )
        merged["imports"] = source_manifest
        updated = self.repository.replace_draft(
            draft_id,
            merged,
            actor=principal,
            event_type="source_imported",
            details={
                "format": format_name.lower(),
                "source_name": source_name or f"pasted.{format_name.lower()}",
                "source_system": source_system,
                "original_filename": original_filename,
                "truth_statement_acknowledged": truth_statement is True,
                "content_sha256": content_sha256,
                "mapped_field_count": len(imported["field_provenance"]),
                "unmapped_fields": imported["unmapped_fields"],
            },
            expected_revision=expected_revision,
        )
        return {
            "draft": updated,
            "import": {
                "mapped_field_count": len(imported["field_provenance"]),
                "unmapped_fields": imported["unmapped_fields"],
                "source_system": source_system,
                "original_filename": original_filename,
                "truth_statement_acknowledged": truth_statement is True,
            },
        }

    def import_event_snapshot(
        self,
        draft_id: str,
        *,
        snapshot: dict[str, Any],
        actor: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        principal = _actor(actor)
        stored = self.repository.get_draft(draft_id)
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        if stored["_meta"]["revision"] != expected_revision:
            raise ConflictError(
                f"草稿已更新，当前修订号为 {stored['_meta']['revision']}"
            )
        document = _document(stored)
        validated = _validate_event_snapshot(snapshot, document)
        merged = deep_copy_json(document)
        merged["operational_context"]["approved_event_codes"] = validated["event_codes"]
        pointer = "/operational_context/approved_event_codes"
        merged["field_provenance"][pointer] = [
            provenance_record(
                source_kind="approved_document",
                source_name=validated["source_system"],
                locator=(
                    f"{validated['record_id']}#snapshot={validated['snapshot_id']}"
                )[:512],
                content_sha256=validated["evidence_sha256"],
                confidence=1.0,
                extraction_method="regulator_event_snapshot_import",
            )
        ]
        updated = self.repository.replace_draft(
            draft_id,
            merged,
            actor=principal,
            event_type="regulator_event_snapshot_imported",
            details={
                "snapshot_id": validated["snapshot_id"],
                "mine_id": validated["mine_id"],
                "window_start": validated["window_start"],
                "window_end": validated["window_end"],
                "event_codes": validated["event_codes"],
                "evidence_sha256": validated["evidence_sha256"],
                "source_system": validated["source_system"],
                "record_id": validated["record_id"],
            },
            expected_revision=expected_revision,
        )
        return {
            "draft": updated,
            "event_snapshot": validated,
        }

    def questions(self, draft_id: str) -> list[dict[str, Any]]:
        return questions_for_draft(_document(self.repository.get_draft(draft_id)))

    def validate(self, draft_id: str) -> dict[str, Any]:
        return validate_draft(_document(self.repository.get_draft(draft_id)))

    def observation_review_state(
        self,
        draft_id: str,
        *,
        actor: str,
    ) -> dict[str, Any]:
        return self.repository.observation_review_state(
            draft_id,
            reviewed_by=_actor(actor),
        )

    def review_observations(
        self,
        draft_id: str,
        *,
        observation_ids: list[str],
        reviewed: bool,
        actor: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        principal = _actor(actor)
        if (
            not isinstance(observation_ids, list)
            or not observation_ids
            or len(observation_ids) > 10_000
            or any(
                not isinstance(item, str) or not item.strip() or len(item.strip()) > 256
                for item in observation_ids
            )
        ):
            raise ValueError("observation_ids 必须是 1-10000 个非空观测编号")
        cleaned = [item.strip() for item in observation_ids]
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("observation_ids 不能重复")
        if not isinstance(reviewed, bool):
            raise ValueError("reviewed 必须是布尔值")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision 必须是正整数")
        return self.repository.record_observation_reviews(
            draft_id,
            observation_ids=cleaned,
            reviewed=reviewed,
            reviewed_by=principal,
            expected_revision=expected_revision,
        )

    def platform_status(self) -> dict[str, Any]:
        if self.platform_client is None:
            return {
                "configured": False,
                "reachable": False,
                "compatible": False,
                "message": "尚未配置监管平台，当前只能保存和预检草稿",
            }
        try:
            self.platform_client.discover_capabilities()
        except PlatformError as error:
            failure_kind = error.details.get("failure_kind")
            result: dict[str, Any] = {
                "configured": True,
                "reachable": failure_kind != "connection",
                "compatible": False,
                "message": str(error),
            }
            if error.details:
                result["error"] = deep_copy_json(error.details)
            return result
        return {
            "configured": True,
            "reachable": True,
            "compatible": True,
            "message": "监管平台在线，enterprise-submission-v1 合同兼容",
        }

    def assist(
        self,
        draft_id: str,
        *,
        content: str = "",
        format_name: str = "text",
        actor: str = "local-operator",
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        current = _document(self.repository.get_draft(draft_id))
        if self.llm_provider is None:
            return {
                "mode": "rules",
                "llm_used": False,
                "suggestion_only": True,
                "questions": questions_for_draft(current),
                "message": "未配置模型密钥，确定性规则模式可完整使用",
            }
        if not isinstance(content, str) or not content.strip():
            raise ValueError("使用模型辅助时 content 不能为空")
        result = self.llm_provider.suggest_fields(
            content=content,
            format_name=format_name,
            current_document=_llm_safe_context(current),
        )
        run_id = random_id("llm")
        suggestion_paths = sorted({item["path"] for item in result["suggestions"]})
        current["llm_assistance"] = {
            "used": True,
            "provider": "openai-compatible",
            "model": self.llm_provider.config.model,
            "run_id": run_id,
            "tasks": ["field_extraction", "draft_assistance"],
            "affected_field_paths": suggestion_paths,
            "accepted_field_paths": [],
            "suggestions": deep_copy_json(result["suggestions"]),
            "source_content_sha256": sha256_text(content),
            "recorded_at": utc_text(),
            "suggestion_only": True,
        }
        updated = self.repository.replace_draft(
            draft_id,
            current,
            actor=_actor(actor),
            event_type="llm_assistance_recorded",
            details={
                "provider": "openai-compatible",
                "model": self.llm_provider.config.model,
                "run_id": run_id,
                "suggestion_count": len(result["suggestions"]),
                "suggestion_paths": suggestion_paths,
                "source_content_sha256": sha256_text(content),
                "suggestion_only": True,
            },
            expected_revision=expected_revision,
        )
        # Suggestions are intentionally not applied. Applying a selected value
        # goes through patch_draft and receives human provenance.
        return {
            "mode": "llm",
            "llm_used": True,
            "provider": "openai-compatible",
            "model": self.llm_provider.config.model,
            "run_id": run_id,
            "suggestion_only": True,
            "draft": updated,
            **result,
        }

    def confirm(
        self,
        draft_id: str,
        *,
        actor: str,
        confirmer_name: str,
        confirmer_role: str,
        accepted: bool,
        attestation: str,
        expected_revision: int,
        confirmation_method: str = "authenticated_click",
    ) -> dict[str, Any]:
        principal = _actor(actor)
        if principal == "demo":
            raise ConfirmationRequiredError("演示账号只能建稿和查看，不能确认或报送")
        if accepted is not True:
            raise ConfirmationRequiredError("必须由填报人员主动勾选确认")
        if (
            not isinstance(confirmer_name, str)
            or not 1 <= len(confirmer_name.strip()) <= 128
            or not isinstance(confirmer_role, str)
            or not 1 <= len(confirmer_role.strip()) <= 128
        ):
            raise ValueError("确认人姓名和岗位不能为空")
        if not isinstance(attestation, str) or len(attestation.strip()) < 10:
            raise ValueError("确认声明至少需要 10 个字符")
        method_map = {
            "account": "authenticated_click",
            "authenticated_click": "authenticated_click",
        }
        normalised_method = method_map.get(confirmation_method)
        if normalised_method is None:
            raise ValueError(
                "仅支持登录账号点击确认；数字签名或企业章须由"
                "具备证据验证能力的外部适配器另行实现"
            )
        stored = self.repository.get_draft(draft_id)
        if stored["_meta"]["revision"] != expected_revision:
            raise ConflictError(
                f"草稿已更新，当前修订号为 {stored['_meta']['revision']}"
            )
        self._enforce_four_eyes(draft_id, actor=principal)
        document = _document(stored)
        validation = validate_draft(document)
        if not validation["valid"]:
            raise ValidationBlockedError(
                f"仍有 {validation['blocking_count']} 个阻断问题"
            )
        return self.repository.confirm(
            draft_id,
            actor=principal,
            confirmer_name=confirmer_name.strip(),
            confirmer_role=confirmer_role.strip(),
            statement_version=_CONFIRMATION_STATEMENT,
            confirmation_method=normalised_method,
            attestation=attestation.strip(),
            expected_revision=expected_revision,
            document_sha256=sha256_json(document),
        )

    def _build_envelope(
        self,
        stored: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        meta = stored["_meta"]
        confirmation = meta["confirmation"]
        if (
            not meta["confirmed"]
            or not isinstance(confirmation, dict)
            or confirmation.get("document_sha256") != sha256_json(_document(stored))
        ):
            raise ConfirmationRequiredError("草稿尚未确认，或确认已因修改失效")
        document = _document(stored)
        validation = validate_draft(document)
        if not validation["valid"]:
            raise ValidationBlockedError(
                f"仍有 {validation['blocking_count']} 个阻断问题"
            )

        def contract_provenance(
            record: dict[str, Any],
        ) -> dict[str, Any]:
            origin_map = {
                "json": "manual_record",
                "csv": "manual_record",
                "manual": "manual_record",
                "sensor": "sensor",
                "erp": "erp",
                "weighbridge": "weighbridge",
                "inventory_system": "inventory_system",
                "transport_system": "transport_system",
                "work_order_system": "work_order_system",
                "approved_document": "approved_document",
                "deterministic": "deterministic_calculation",
                "cryptographic": "cryptographic_derivation",
            }
            method_map = {
                "deterministic_json_key": "file_import",
                "deterministic_csv_header": "file_import",
                "human_entry": "manual_entry",
                "device_gateway": "device_gateway",
                "direct_api": "direct_api",
                "ocr_extraction": "ocr_extraction",
                "llm_extraction": "llm_extraction",
                "regulator_event_snapshot_import": "file_import",
                "deterministic_formula": "deterministic_formula",
                "signature_process": "signature_process",
            }
            source_kind = str(record.get("source_kind", "manual"))
            source_name = str(record.get("source_name") or "enterprise-agent")[:128]
            locator = str(record.get("locator") or "local-record")
            evidence_hash = record.get("content_sha256")
            if (
                not isinstance(evidence_hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", evidence_hash) is None
            ):
                evidence_hash = sha256_json(record)
            converted: dict[str, Any] = {
                "origin_type": origin_map.get(source_kind, "manual_record"),
                "source_system": source_name or "enterprise-agent",
                "source_record_id": locator[:256] or "local-record",
                "source_location": locator[:512] or "local-record",
                "captured_at": record.get("recorded_at")
                or confirmation["confirmed_at"],
                "acquisition_method": method_map.get(
                    str(record.get("extraction_method")), "manual_entry"
                ),
                "evidence_sha256": evidence_hash,
            }
            confidence = record.get("confidence")
            if isinstance(confidence, (int, float)) and not isinstance(
                confidence, bool
            ):
                converted["confidence"] = float(confidence)
            return converted

        def provenance_set(path: str) -> list[dict[str, Any]]:
            records = document["field_provenance"].get(path)
            if not isinstance(records, list) or not records:
                raise ValidationBlockedError(f"字段 {path} 缺少来源记录")
            return [contract_provenance(record) for record in records[:16]]

        signed: list[dict[str, Any]] = []
        for index, observation in enumerate(document["observations"]):
            normalised_observation = normalize_observation(observation)
            base = f"/observations/{index}"
            field_provenance = {
                field: provenance_set(f"{base}/{field}")
                for field in (
                    "source_id",
                    "observation_id",
                    "value",
                    "unit",
                    "observed_at",
                    "received_at",
                    "interval_start",
                    "interval_end",
                    "reset_before",
                    "sequence_no",
                    "revision",
                    "payload_sha256",
                    "signature",
                )
            }
            signed.append(
                {
                    **normalised_observation,
                    "payload_sha256": observation["payload_sha256"],
                    "signature": observation["signature"],
                    "interval_start": normalised_observation["interval_start"],
                    "interval_end": normalised_observation["interval_end"],
                    "reset_before": normalised_observation["reset_before"],
                    "field_provenance": field_provenance,
                }
            )

        llm = document.get("llm_assistance")
        if not isinstance(llm, dict):
            llm = {"used": False}
        accepted_llm_paths = list(llm.get("accepted_field_paths", []))
        contract_llm_paths = (
            sorted({_contract_pointer(path) for path in accepted_llm_paths})
            if accepted_llm_paths
            else ["/payload/llm_assistance"]
        )
        llm_disclosure: dict[str, Any] = {
            "used": bool(llm.get("used", False)),
            "affected_field_paths": (contract_llm_paths if llm.get("used") else []),
            "numeric_values_copied_or_deterministically_calculated": True,
            "approved_events_copied_from_authoritative_source": True,
            "human_reviewed_affected_fields": True,
        }
        if llm_disclosure["used"]:
            llm_disclosure.update(
                {
                    "provider": str(llm.get("provider") or "unknown")[:128],
                    "model": str(llm.get("model") or "unknown")[:128],
                    "tasks": list(
                        llm.get(
                            "tasks",
                            ["field_extraction", "draft_assistance"],
                        )
                    ),
                }
            )
        llm_declaration = deep_copy_json(llm_disclosure)
        llm_disclosure["declaration_provenance"] = [
            {
                "origin_type": "cryptographic_derivation",
                "source_system": "enterprise-reporting-agent",
                "source_record_id": str(
                    llm.get("run_id") or f"no-llm-r{meta['revision']}"
                )[:256],
                "captured_at": confirmation["confirmed_at"],
                "acquisition_method": "signature_process",
                "evidence_sha256": sha256_json(llm_declaration),
            }
        ]
        human_disclosure: dict[str, Any] = {
            "confirmed": True,
            "confirmer_id": confirmation["confirmer_id"],
            "confirmer_name": confirmation["confirmer_name"],
            "confirmer_role": confirmation["confirmer_role"],
            "confirmed_at": confirmation["confirmed_at"],
            "confirmation_method": confirmation["confirmation_method"],
            # Digest the complete immutable confirmation record, including
            # actor, time, revision and exact draft hash.  The regulator can
            # later request that record for an evidence audit; this is not
            # presented as a personal qualified electronic signature.
            "confirmation_evidence_sha256": sha256_json(confirmation),
            "evidence_reviewed": confirmation["evidence_reviewed"],
            "authorized_to_submit": confirmation["authorized_to_submit"],
            "understands_regulator_decides_normality_and_legality": confirmation[
                "understands_regulator_decides_normality_and_legality"
            ],
        }
        human_disclosure["declaration_provenance"] = [
            {
                "origin_type": "manual_record",
                "source_system": "enterprise-reporting-agent",
                "source_record_id": (
                    f"{document['draft_id']}:confirmation:r{meta['revision']}"
                )[:256],
                "captured_at": confirmation["confirmed_at"],
                "acquisition_method": "manual_entry",
                "evidence_sha256": sha256_json(human_disclosure),
            }
        ]

        def nested_provenance(
            names: tuple[str, ...], prefix: str = ""
        ) -> dict[str, list[dict[str, Any]]]:
            return {name: provenance_set(f"{prefix}/{name}") for name in names}

        context = deep_copy_json(document["operational_context"])
        context["field_provenance"] = nested_provenance(
            (
                "regime_code",
                "shift_code",
                "season_code",
                "maintenance",
                "approved_event_codes",
                "tags",
            ),
            "/operational_context",
        )
        payload: dict[str, Any] = {
            "enterprise": {
                "enterprise_id": document["enterprise_id"],
                "enterprise_name": document["enterprise_name"],
                "unified_social_credit_code": document["unified_social_credit_code"],
                "field_provenance": nested_provenance(
                    (
                        "enterprise_id",
                        "enterprise_name",
                        "unified_social_credit_code",
                    )
                ),
            },
            "mine": {
                "mine_id": document["mine_id"],
                "mine_name": document["mine_name"],
                "field_provenance": nested_provenance(("mine_id", "mine_name")),
            },
            "window": {
                "window_start": document["window_start"],
                "window_end": document["window_end"],
                "field_provenance": nested_provenance(("window_start", "window_end")),
            },
            "profile": {
                "profile_id": document["profile_id"],
                "profile_version": document["profile_version"],
                "field_provenance": nested_provenance(
                    ("profile_id", "profile_version")
                ),
            },
            "operational_context": context,
            "observations": signed,
            "llm_assistance": llm_disclosure,
            "human_confirmation": human_disclosure,
        }
        envelope: dict[str, Any] = {
            "contract_version": SUBMISSION_SCHEMA_VERSION,
            "submission_id": str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    (
                        f"enterprise-reporting-agent:{document['draft_id']}:"
                        f"r{meta['revision']}"
                    ),
                )
            ),
            "idempotency_key": idempotency_key,
            # This is transport time, not human-confirmation time. The first
            # envelope is persisted before transport and reused byte-for-byte
            # for every retry of the same idempotency key.
            "submitted_at": utc_text(),
            "payload": payload,
            "payload_sha256": sha256_jcs(payload),
        }
        return envelope

    def submit(
        self,
        draft_id: str,
        *,
        idempotency_key: str | None = None,
        actor: str = "system",
    ) -> dict[str, Any]:
        with self._submission_lock:
            return self._submit_serialized(
                draft_id,
                idempotency_key=idempotency_key,
                actor=actor,
            )

    def _submit_serialized(
        self,
        draft_id: str,
        *,
        idempotency_key: str | None,
        actor: str,
    ) -> dict[str, Any]:
        if self.platform_client is None:
            raise PlatformError("尚未配置监管平台地址")
        submitter = _actor(actor)
        if submitter == "demo":
            raise ConfirmationRequiredError("演示账号只能建稿和查看，不能确认或报送")
        stored = self.repository.get_draft(draft_id)
        meta = stored["_meta"]
        if not meta["confirmed"]:
            raise ConfirmationRequiredError("确认前禁止提交")
        self._enforce_four_eyes(draft_id, actor=submitter)
        key = (
            idempotency_key.strip()
            if isinstance(idempotency_key, str) and idempotency_key.strip()
            else f"{draft_id}-r{meta['revision']}"
        )
        if (
            len(key) < 16
            or len(key) > 128
            or re.fullmatch(r"[A-Za-z0-9._:-]+", key) is None
        ):
            raise ValueError("幂等键须为 16-128 位字母、数字、点、下划线、冒号或连字符")
        envelope = self._build_envelope(stored, idempotency_key=key)
        submission = self.repository.begin_submission(
            draft_id=draft_id,
            confirmed_revision=meta["revision"],
            idempotency_key=key,
            request=envelope,
            actor=submitter,
        )
        if submission["status"] == "succeeded":
            return {**submission, "replayed": True}
        persisted_request = submission["request"]
        try:
            receipt = self.platform_client.submit(
                persisted_request,
                idempotency_key=key,
            )
        except PlatformError as error:
            self.repository.fail_submission(
                key,
                error_code=error.platform_code,
                error_details=(
                    deep_copy_json(error.details)
                    if error.details
                    else {
                        "platform_code": "platform_submission_failed",
                        "retryable": True,
                    }
                ),
                actor=submitter,
            )
            raise
        completed = self.repository.finish_submission(
            key,
            receipt=receipt,
            actor=submitter,
        )
        return {**completed, "replayed": False}
