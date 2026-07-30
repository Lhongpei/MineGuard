"""Build deterministic, review-only autofill proposals.

The module is intentionally a pure boundary between evidence collection and
draft mutation.  It accepts already-collected evidence, labels every candidate
as a raw observation, historical suggestion, or physical inference, and emits
an immutable proposal.  It has no repository, service, confirmation, signature
or submission capability.

Raw signed observations and regulator event snapshots are never converted to a
generic draft patch.  They are routed to their dedicated import paths so their
original credentials and field provenance cannot be laundered into manual
values.  Historical and physical evidence remain suggestions; physical
inferences are analysis-only under the current draft schema.
"""

from __future__ import annotations

import hmac
import math
import re
from collections.abc import Iterable, Mapping
from typing import Any

from enterprise_agent.harness.sanitize import has_secret_material
from enterprise_agent.util import (
    canonical_json,
    deep_copy_json,
    parse_aware_datetime,
    sha256_json,
)

AUTOFILL_PROPOSAL_SCHEMA_VERSION = "enterprise-autofill-proposal/v1"

RAW_OBSERVATION = "raw_observation"
HISTORICAL_SUGGESTION = "historical_suggestion"
PHYSICAL_INFERENCE = "physical_inference"
EVIDENCE_CLASSES = (
    RAW_OBSERVATION,
    HISTORICAL_SUGGESTION,
    PHYSICAL_INFERENCE,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CREDIT_CODE = re.compile(r"^[0-9A-HJ-NPQRTUWXY]{18}$")
_OBSERVATION_PATH = re.compile(
    r"^/observations/(0|[1-9][0-9]*)/([a-z_]+)$"
)
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_OBSERVATION_VALUE = 1_000_000_000_000.0
_MAX_CANDIDATE_BYTES = 64 * 1024
_MAX_SOURCE_REFS = 32

_PATCHABLE_RAW_PATHS = frozenset(
    {
        "/enterprise_id",
        "/enterprise_name",
        "/unified_social_credit_code",
        "/mine_id",
        "/mine_name",
        "/window_start",
        "/window_end",
        "/profile_id",
        "/profile_version",
        "/operational_context/regime_code",
        "/operational_context/shift_code",
        "/operational_context/season_code",
        "/operational_context/maintenance",
        "/operational_context/tags",
    }
)
_PATCHABLE_HISTORICAL_PATHS = frozenset(
    {
        "/operational_context/regime_code",
        "/operational_context/shift_code",
        "/operational_context/season_code",
        "/operational_context/maintenance",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {
        "source_id",
        "observation_id",
        "metric_code",
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
    }
)
_CREDENTIAL_OR_CONTROL_SEGMENTS = frozenset(
    {
        "_meta",
        "confirmation",
        "confirmed",
        "confirmer",
        "field_provenance",
        "hmac",
        "idempotency_key",
        "llm_assistance",
        "password",
        "payload_sha256",
        "receipt",
        "secret",
        "signature",
        "status",
        "submission",
        "submit",
        "token",
    }
)
_CLASS_CAPS = {
    RAW_OBSERVATION: 0.98,
    HISTORICAL_SUGGESTION: 0.75,
    PHYSICAL_INFERENCE: 0.85,
}
_CLASS_LABELS = {
    RAW_OBSERVATION: "原始观测/原始材料",
    HISTORICAL_SUGGESTION: "历史数据建议",
    PHYSICAL_INFERENCE: "物理关系推断",
}
_CLASS_PRIORITY = {
    RAW_OBSERVATION: 0,
    PHYSICAL_INFERENCE: 1,
    HISTORICAL_SUGGESTION: 2,
}
_MODEL_METHOD = re.compile(r"(?:llm|model|ocr|大模型|模型)", re.IGNORECASE)


class AutofillInputError(ValueError):
    """Raised when the proposal cannot be safely bound to its draft."""


def _json_copy(value: Any, field_name: str, *, maximum: int) -> Any:
    try:
        encoded = canonical_json(value)
    except (TypeError, ValueError) as error:
        raise AutofillInputError(f"{field_name} 必须是有限、可序列化的 JSON") from error
    if len(encoded.encode("utf-8")) > maximum:
        raise AutofillInputError(f"{field_name} 超过 {maximum} 字节上限")
    return deep_copy_json(value)


def _public_document(draft: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in draft.items()
        if key not in {"_meta", "status", "receipt"}
    }


def _snapshot_binding(
    draft: dict[str, Any],
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    draft_id = draft.get("draft_id")
    meta = draft.get("_meta")
    if (
        not isinstance(draft_id, str)
        or not draft_id
        or len(draft_id) > 128
        or not isinstance(meta, dict)
        or isinstance(meta.get("revision"), bool)
        or not isinstance(meta.get("revision"), int)
        or meta["revision"] < 1
    ):
        raise AutofillInputError("草稿必须包含有效 draft_id 和 _meta.revision")
    revision = meta["revision"]
    document_sha256 = sha256_json(_public_document(draft))
    if metadata is None:
        return {
            "draft_id": draft_id,
            "draft_revision": revision,
            "document_sha256": document_sha256,
            "history_snapshot_sha256": None,
            "captured_at": None,
            "immutable": False,
        }
    if not isinstance(metadata, Mapping):
        raise AutofillInputError("snapshot_metadata 必须是对象")
    clean = _json_copy(dict(metadata), "snapshot_metadata", maximum=256 * 1024)
    if clean.get("immutable") is not True:
        raise AutofillInputError("自动填报证据快照必须明确标记 immutable=true")
    if clean.get("draft_id") != draft_id:
        raise AutofillInputError("证据快照与草稿编号不一致")
    if clean.get("draft_revision") != revision:
        raise AutofillInputError("证据快照与草稿修订号不一致")
    supplied_digest = clean.get("document_sha256")
    if (
        not isinstance(supplied_digest, str)
        or _HEX64.fullmatch(supplied_digest) is None
        or not hmac.compare_digest(supplied_digest, document_sha256)
    ):
        raise AutofillInputError("证据快照与当前草稿内容摘要不一致")
    history_digest = clean.get("history_snapshot_sha256")
    if history_digest is not None and (
        not isinstance(history_digest, str)
        or _HEX64.fullmatch(history_digest) is None
    ):
        raise AutofillInputError("历史证据快照摘要格式非法")
    captured_at = clean.get("captured_at")
    if captured_at is not None:
        try:
            parse_aware_datetime(captured_at, "snapshot_metadata.captured_at")
        except ValueError as error:
            raise AutofillInputError("证据快照时间格式非法") from error
    return {
        "draft_id": draft_id,
        "draft_revision": revision,
        "document_sha256": document_sha256,
        "history_snapshot_sha256": history_digest,
        "captured_at": captured_at,
        "immutable": True,
    }


def _safe_path_hint(candidate: Any) -> str | None:
    if not isinstance(candidate, Mapping):
        return None
    path = candidate.get("path")
    if (
        isinstance(path, str)
        and path.startswith("/")
        and len(path) <= 256
        and all(ord(character) >= 32 for character in path)
    ):
        return path
    return None


def _blocked_candidate(
    *,
    evidence_class: str,
    index: int,
    path: str | None,
    code: str,
    reason: str,
) -> dict[str, Any]:
    identity = {
        "evidence_class": evidence_class,
        "index": index,
        "path": path,
        "reason_code": code,
    }
    return {
        "candidate_id": f"candidate_{sha256_json(identity)[:24]}",
        "path": path,
        "value_omitted": True,
        "evidence_class": evidence_class,
        "evidence_label": _CLASS_LABELS[evidence_class],
        "method": "unavailable",
        "rationale": "",
        "source_refs": [],
        "basis": {},
        "confidence": {
            "claimed": None,
            "effective": 0.0,
            "cap": _CLASS_CAPS[evidence_class],
            "band": "blocked",
            "adjustments": [code],
        },
        "status": "blocked",
        "reason_code": code,
        "reason": reason,
        "delivery_route": "none",
        "eligible_for_review_patch": False,
        "selected_for_review_patch": False,
        "requires_human_acceptance": True,
    }


def _safe_text(
    value: Any,
    *,
    minimum: int = 1,
    maximum: int,
    identifier: bool = False,
) -> str:
    if not isinstance(value, str):
        raise AutofillInputError("必须是文本")
    clean = value.strip()
    if not minimum <= len(clean) <= maximum:
        raise AutofillInputError(f"文本长度必须为 {minimum}-{maximum}")
    if any(ord(character) < 32 or ord(character) == 127 for character in clean):
        raise AutofillInputError("文本包含控制字符")
    if identifier and _IDENTIFIER.fullmatch(clean) is None:
        raise AutofillInputError("标识符格式非法")
    return clean


def _number(value: Any, field_name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise AutofillInputError(f"{field_name} 必须是有限数字")
    return float(value)


def _validate_candidate_value(path: str, value: Any) -> None:
    text_rules = {
        "/enterprise_id": (128, True),
        "/enterprise_name": (256, False),
        "/mine_id": (128, True),
        "/mine_name": (256, False),
        "/profile_id": (128, True),
        "/profile_version": (64, True),
        "/operational_context/regime_code": (64, False),
        "/operational_context/shift_code": (64, False),
        "/operational_context/season_code": (64, False),
    }
    if path in text_rules:
        maximum, identifier = text_rules[path]
        _safe_text(value, maximum=maximum, identifier=identifier)
        return
    if path == "/unified_social_credit_code":
        if not isinstance(value, str) or _CREDIT_CODE.fullmatch(value) is None:
            raise AutofillInputError("统一社会信用代码格式非法")
        return
    if path in {"/window_start", "/window_end"}:
        parse_aware_datetime(value, path)
        return
    if path == "/operational_context/maintenance":
        if not isinstance(value, bool):
            raise AutofillInputError("检修状态必须是布尔值")
        return
    if path == "/operational_context/tags":
        if (
            not isinstance(value, list)
            or len(value) > 64
            or len(value) != len(set(value))
            or any(
                not isinstance(item, str)
                or not item.strip()
                or len(item) > 128
                for item in value
            )
        ):
            raise AutofillInputError("工况标签必须是不超过 64 项的不重复短文本")
        return
    if path == "/operational_context/approved_event_codes":
        if (
            not isinstance(value, list)
            or len(value) > 32
            or len(value) != len(set(value))
            or any(
                not isinstance(item, str)
                or not item.strip()
                or len(item) > 64
                for item in value
            )
        ):
            raise AutofillInputError("监管事件代码格式非法")
        return
    match = _OBSERVATION_PATH.fullmatch(path)
    if match is None:
        raise AutofillInputError("字段路径不在自动填报建议范围")
    field = match.group(2)
    if field not in _OBSERVATION_FIELDS:
        raise AutofillInputError("观测字段不受支持")
    if field in {"payload_sha256", "signature"}:
        raise AutofillInputError("来源凭证不能进入自动填报提案")
    if field in {"source_id", "observation_id", "metric_code"}:
        _safe_text(value, maximum=128, identifier=True)
    elif field == "unit":
        _safe_text(value, maximum=32)
    elif field in {
        "observed_at",
        "received_at",
        "interval_start",
        "interval_end",
    }:
        if value is not None:
            parse_aware_datetime(value, path)
    elif field == "value":
        number = _number(value, path)
        if abs(number) > _MAX_OBSERVATION_VALUE:
            raise AutofillInputError("观测值超出允许范围")
    elif field == "reset_before":
        if not isinstance(value, bool):
            raise AutofillInputError("reset_before 必须是布尔值")
    elif (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SAFE_INTEGER
    ):
        raise AutofillInputError("观测序号或修订号超出安全整数范围")


def _normalize_source_refs(value: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= _MAX_SOURCE_REFS
    ):
        raise AutofillInputError(
            f"source_refs 必须包含 1-{_MAX_SOURCE_REFS} 条来源引用"
        )
    result: list[dict[str, Any]] = []
    for reference in value:
        if not isinstance(reference, Mapping):
            raise AutofillInputError("每条来源引用必须是对象")
        clean = _json_copy(dict(reference), "source_ref", maximum=8 * 1024)
        if has_secret_material(clean):
            raise AutofillInputError("来源引用疑似包含密钥、签名或口令")
        source_type = clean.get("source_type", clean.get("source_kind"))
        if not isinstance(source_type, str) or not source_type.strip():
            raise AutofillInputError("来源引用必须包含 source_type 或 source_kind")
        handles = (
            clean.get("source_id"),
            clean.get("source_name"),
            clean.get("locator"),
            clean.get("content_sha256"),
            clean.get("tool_call_id"),
        )
        if not any(isinstance(item, str) and item.strip() for item in handles):
            raise AutofillInputError("来源引用必须包含可追溯标识或定位")
        digest = clean.get("content_sha256")
        if digest is not None and (
            not isinstance(digest, str) or _HEX64.fullmatch(digest) is None
        ):
            raise AutofillInputError("来源内容摘要格式非法")
        result.append(clean)
    return sorted(result, key=canonical_json)


def _normalize_basis(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise AutofillInputError("basis 必须是对象")
    clean = _json_copy(dict(value), "basis", maximum=16 * 1024)
    if has_secret_material(clean):
        raise AutofillInputError("推断依据疑似包含密钥、签名或口令")
    return clean


def _confidence(
    *,
    evidence_class: str,
    claimed: float,
    method: str,
    source_refs: list[dict[str, Any]],
    basis: dict[str, Any],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    cap = _CLASS_CAPS[evidence_class]
    adjustments = [f"class_cap:{cap:.2f}"]
    if evidence_class == RAW_OBSERVATION:
        failed = any(
            str(
                reference.get(
                    "verification_status",
                    reference.get("verification", ""),
                )
            ).casefold()
            in {"failed", "invalid", "rejected"}
            for reference in source_refs
        )
        if failed:
            raise AutofillInputError("来源引用明确标记为验证失败")
        verified = any(
            str(
                reference.get(
                    "verification_status",
                    reference.get("verification", ""),
                )
            ).casefold()
            in {"verified", "valid", "passed"}
            or reference.get("verified") is True
            for reference in source_refs
        )
        if not verified:
            cap = min(cap, 0.85)
            adjustments.append("source_not_cryptographically_verified")
        if _MODEL_METHOD.search(method):
            cap = min(cap, 0.70)
            adjustments.append("model_or_ocr_extraction_cap")
    elif evidence_class == HISTORICAL_SUGGESTION:
        if (
            snapshot["immutable"] is not True
            or snapshot["history_snapshot_sha256"] is None
        ):
            raise AutofillInputError("历史建议必须绑定不可变历史证据快照")
        sample_size = basis.get("sample_size")
        support_ratio = basis.get("support_ratio")
        context_match = basis.get("context_match")
        if (
            isinstance(sample_size, bool)
            or not isinstance(sample_size, int)
            or not 1 <= sample_size <= 1_000_000
            or isinstance(support_ratio, bool)
            or not isinstance(support_ratio, (int, float))
            or not math.isfinite(float(support_ratio))
            or not 0 <= float(support_ratio) <= 1
            or not isinstance(context_match, bool)
        ):
            raise AutofillInputError(
                "历史建议 basis 必须包含 sample_size、support_ratio、context_match"
            )
        cap = min(cap, float(support_ratio))
        adjustments.append("historical_support_ratio_cap")
        if sample_size < 5:
            cap = min(cap, 0.50)
            adjustments.append("historical_sample_below_5")
        elif sample_size < 10:
            cap = min(cap, 0.65)
            adjustments.append("historical_sample_below_10")
        if not context_match:
            cap = min(cap, 0.45)
            adjustments.append("historical_context_mismatch")
    else:
        if snapshot["immutable"] is not True:
            raise AutofillInputError("物理推断必须绑定不可变草稿证据快照")
        formula = basis.get("formula")
        input_refs = basis.get("input_refs")
        validated_inputs = basis.get("validated_inputs")
        if (
            not isinstance(formula, str)
            or not formula.strip()
            or len(formula) > 512
            or not isinstance(input_refs, list)
            or not 1 <= len(input_refs) <= 32
            or any(
                not isinstance(item, str)
                or not item.strip()
                or len(item) > 256
                for item in input_refs
            )
            or not isinstance(validated_inputs, bool)
        ):
            raise AutofillInputError(
                "物理推断 basis 必须包含 formula、input_refs、validated_inputs"
            )
        if not validated_inputs:
            cap = min(cap, 0.55)
            adjustments.append("physical_inputs_not_validated")
    effective = round(min(claimed, cap), 4)
    band = "high" if effective >= 0.85 else "medium" if effective >= 0.65 else "low"
    return {
        "claimed": round(claimed, 4),
        "effective": effective,
        "cap": round(cap, 4),
        "band": band,
        "adjustments": adjustments,
    }


def _path_route(path: str, evidence_class: str) -> tuple[str, bool]:
    segments = {segment.casefold() for segment in path.split("/") if segment}
    if segments & _CREDENTIAL_OR_CONTROL_SEGMENTS:
        return "none", False
    if path == "/operational_context/approved_event_codes":
        return (
            "regulator_event_snapshot_import"
            if evidence_class == RAW_OBSERVATION
            else "analysis_only"
        ), False
    if path == "/observations" or _OBSERVATION_PATH.fullmatch(path):
        return (
            "signed_source_import"
            if evidence_class == RAW_OBSERVATION
            else "analysis_only"
        ), False
    if evidence_class == RAW_OBSERVATION and path in _PATCHABLE_RAW_PATHS:
        return "human_review_patch", True
    if (
        evidence_class == HISTORICAL_SUGGESTION
        and path in _PATCHABLE_HISTORICAL_PATHS
    ):
        return "human_review_patch", True
    if evidence_class == PHYSICAL_INFERENCE and path in _PATCHABLE_RAW_PATHS:
        return "analysis_only", False
    return "none", False


def _normalize_candidate(
    candidate: Any,
    *,
    evidence_class: str,
    index: int,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    path_hint = _safe_path_hint(candidate)
    if not isinstance(candidate, Mapping):
        return _blocked_candidate(
            evidence_class=evidence_class,
            index=index,
            path=None,
            code="invalid_candidate",
            reason="候选项必须是对象",
        )
    raw = dict(candidate)
    if has_secret_material(raw):
        return _blocked_candidate(
            evidence_class=evidence_class,
            index=index,
            path=path_hint,
            code="secret_material_rejected",
            reason="候选项疑似包含密钥、签名或口令，已整体丢弃且不回显",
        )
    try:
        encoded = canonical_json(raw)
    except (TypeError, ValueError):
        return _blocked_candidate(
            evidence_class=evidence_class,
            index=index,
            path=path_hint,
            code="invalid_json",
            reason="候选项包含非 JSON 或非有限值",
        )
    if len(encoded.encode("utf-8")) > _MAX_CANDIDATE_BYTES:
        return _blocked_candidate(
            evidence_class=evidence_class,
            index=index,
            path=path_hint,
            code="candidate_too_large",
            reason="候选项超过大小上限",
        )
    try:
        path = _safe_text(raw.get("path"), maximum=256)
        if not path.startswith("/") or "//" in path:
            raise AutofillInputError("path 必须是规范 JSON Pointer")
        route, patchable = _path_route(path, evidence_class)
        if route == "none":
            raise AutofillInputError("字段路径属于控制字段或不在建议范围")
        if "value" not in raw:
            raise AutofillInputError("候选项缺少 value")
        value = _json_copy(raw["value"], "candidate.value", maximum=16 * 1024)
        _validate_candidate_value(path, value)
        claimed = _number(raw.get("confidence"), "confidence")
        if not 0 <= claimed <= 1:
            raise AutofillInputError("confidence 必须在 0 到 1 之间")
        method = _safe_text(raw.get("method"), maximum=128)
        rationale_raw = raw.get("rationale", raw.get("reason", ""))
        rationale = (
            _safe_text(rationale_raw, minimum=0, maximum=1_000)
            if rationale_raw != ""
            else ""
        )
        source_refs = _normalize_source_refs(raw.get("source_refs"))
        basis = _normalize_basis(raw.get("basis"))
        confidence = _confidence(
            evidence_class=evidence_class,
            claimed=claimed,
            method=method,
            source_refs=source_refs,
            basis=basis,
            snapshot=snapshot,
        )
    except (AutofillInputError, ValueError) as error:
        return _blocked_candidate(
            evidence_class=evidence_class,
            index=index,
            path=path_hint,
            code="candidate_validation_failed",
            reason=str(error)[:500],
        )
    identity = {
        "path": path,
        "value": value,
        "evidence_class": evidence_class,
        "method": method,
        "source_refs": source_refs,
        "basis": basis,
    }
    if route == "signed_source_import":
        status = "import_required"
        reason_code = "signed_source_import_required"
        reason = "来源观测必须走签名来源导入接口，不能转成通用草稿补丁"
    elif route == "regulator_event_snapshot_import":
        status = "import_required"
        reason_code = "regulator_event_snapshot_required"
        reason = "监管事件必须走事件快照导入接口，不能由智能体代填"
    elif route == "analysis_only":
        status = "analysis_only"
        reason_code = "derived_evidence_not_observation"
        reason = "历史或物理证据只能辅助判断，不能伪装为原始观测"
    else:
        status = "pending_review"
        reason_code = "human_review_required"
        reason = "候选值尚未写入，需逐字段人工核对后选择"
    return {
        "candidate_id": f"candidate_{sha256_json(identity)[:24]}",
        "path": path,
        "value": value,
        "value_omitted": False,
        "evidence_class": evidence_class,
        "evidence_label": _CLASS_LABELS[evidence_class],
        "method": method,
        "rationale": rationale,
        "source_refs": source_refs,
        "basis": basis,
        "confidence": confidence,
        "status": status,
        "reason_code": reason_code,
        "reason": reason,
        "delivery_route": route,
        "eligible_for_review_patch": patchable,
        "selected_for_review_patch": False,
        "requires_human_acceptance": True,
    }


_MISSING = object()


def _pointer_value(document: Any, path: str) -> Any:
    current = document
    for raw_segment in path.split("/")[1:]:
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if segment not in current:
                return _MISSING
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit():
            index = int(segment)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _same_json(left: Any, right: Any) -> bool:
    if left is _MISSING or right is _MISSING:
        return left is right
    return canonical_json(left) == canonical_json(right)


def _is_blank(value: Any) -> bool:
    return (
        value is _MISSING
        or value is None
        or value == ""
        or value == []
        or value == {}
    )


def _put_patch(patch: dict[str, Any], path: str, value: Any) -> None:
    segments = path.split("/")[1:]
    if len(segments) == 1:
        patch[segments[0]] = deep_copy_json(value)
        return
    if len(segments) == 2 and segments[0] == "operational_context":
        patch.setdefault("operational_context", {})[segments[1]] = deep_copy_json(
            value
        )
        return
    raise AutofillInputError("内部错误：非白名单路径进入 review_patch")


def _candidate_sort_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    return (
        candidate.get("path") or "",
        _CLASS_PRIORITY[candidate["evidence_class"]],
        -float(candidate["confidence"]["effective"]),
        candidate["candidate_id"],
    )


def _apply_review_decisions(
    candidates: list[dict[str, Any]],
    *,
    draft: dict[str, Any],
    minimum_confidence: float,
) -> tuple[dict[str, Any], dict[str, str], list[dict[str, Any]]]:
    patchable = [
        candidate
        for candidate in candidates
        if candidate["eligible_for_review_patch"]
        and candidate["status"] != "blocked"
    ]
    by_path: dict[str, list[dict[str, Any]]] = {}
    for candidate in patchable:
        by_path.setdefault(candidate["path"], []).append(candidate)
    review_patch: dict[str, Any] = {}
    selections: dict[str, str] = {}
    conflicts: list[dict[str, Any]] = []
    for path in sorted(by_path):
        group = sorted(by_path[path], key=_candidate_sort_key)
        values: dict[str, list[dict[str, Any]]] = {}
        for candidate in group:
            values.setdefault(canonical_json(candidate["value"]), []).append(
                candidate
            )
        current = _pointer_value(draft, path)
        current_relation = (
            "blank"
            if _is_blank(current)
            else (
                "same"
                if any(_same_json(current, candidate["value"]) for candidate in group)
                else "different"
            )
        )
        for candidate in group:
            candidate["current_relation"] = current_relation
        if len(values) > 1:
            for candidate in group:
                candidate["status"] = "conflict"
                candidate["reason_code"] = "candidate_values_conflict"
                candidate["reason"] = "同一字段存在互相冲突的证据值，必须人工回查来源"
            conflicts.append(
                {
                    "path": path,
                    "candidate_ids": sorted(
                        candidate["candidate_id"] for candidate in group
                    ),
                    "evidence_classes": sorted(
                        {candidate["evidence_class"] for candidate in group}
                    ),
                    "distinct_value_count": len(values),
                    "resolution": "no_value_selected",
                }
            )
            continue
        selected = group[0]
        for candidate in group[1:]:
            candidate["status"] = "corroborating"
            candidate["reason_code"] = "same_value_corroboration"
            candidate["reason"] = "与优先候选值一致，作为补充证据展示"
        if _same_json(current, selected["value"]):
            selected["status"] = "already_present"
            selected["reason_code"] = "value_already_present"
            selected["reason"] = "草稿中已经存在相同值，无需重复写入"
        elif not _is_blank(current):
            selected["status"] = "would_overwrite"
            selected["reason_code"] = "existing_value_protected"
            selected["reason"] = "草稿已有不同值，提案不会自动覆盖"
        elif selected["confidence"]["effective"] < minimum_confidence:
            selected["status"] = "below_threshold"
            selected["reason_code"] = "confidence_below_review_threshold"
            selected["reason"] = "有效置信度低于进入批量核对补丁的阈值"
        else:
            selected["status"] = "ready_for_review"
            selected["reason_code"] = "ready_for_human_review"
            selected["reason"] = "可进入逐字段人工核对，但尚未写入草稿"
            selected["selected_for_review_patch"] = True
            selections[path] = selected["candidate_id"]
            _put_patch(review_patch, path, selected["value"])
    return review_patch, selections, conflicts


def _candidate_items(
    values: Iterable[Mapping[str, Any]],
    *,
    evidence_class: str,
    remaining: int,
) -> tuple[list[Any], int]:
    if isinstance(values, (str, bytes, Mapping)):
        raise AutofillInputError(f"{evidence_class} 候选集合必须是可迭代对象数组")
    result: list[Any] = []
    for value in values:
        if len(result) >= remaining:
            raise AutofillInputError("自动填报候选总数超过 max_candidates")
        result.append(value)
    return result, remaining - len(result)


def _counts(candidates: list[dict[str, Any]]) -> dict[str, Any]:
    by_class = {evidence_class: 0 for evidence_class in EVIDENCE_CLASSES}
    by_status: dict[str, int] = {}
    for candidate in candidates:
        by_class[candidate["evidence_class"]] += 1
        status = candidate["status"]
        by_status[status] = by_status.get(status, 0) + 1
    return {
        "total": len(candidates),
        "by_evidence_class": by_class,
        "by_status": dict(sorted(by_status.items())),
        "review_patch_field_count": sum(
            bool(candidate["selected_for_review_patch"])
            for candidate in candidates
        ),
    }


def build_autofill_proposal(
    *,
    draft: Mapping[str, Any],
    raw_observations: Iterable[Mapping[str, Any]] = (),
    historical_suggestions: Iterable[Mapping[str, Any]] = (),
    physical_inferences: Iterable[Mapping[str, Any]] = (),
    snapshot_metadata: Mapping[str, Any] | None = None,
    minimum_review_confidence: float = 0.65,
    max_candidates: int = 200,
) -> dict[str, Any]:
    """Return a deterministic proposal that cannot mutate or submit anything.

    Each evidence list uses the same candidate contract: ``path``, ``value``,
    ``confidence``, ``method``, ``source_refs`` and optional ``basis`` and
    ``rationale``.  Historical basis must include ``sample_size``,
    ``support_ratio`` and ``context_match``.  Physical basis must include
    ``formula``, ``input_refs`` and ``validated_inputs``.

    ``snapshot_metadata`` accepts ``FrozenEvidenceRepository.metadata``.
    Historical or physical evidence is blocked unless it is bound to the
    required immutable snapshot.  The returned ``review_patch`` is merely a
    compact review aid: callers must present every selected field to a human,
    re-check the bound draft revision and use the existing audited write gate.
    """

    if not isinstance(draft, Mapping):
        raise AutofillInputError("draft 必须是对象")
    clean_draft = _json_copy(dict(draft), "draft", maximum=32 * 1024 * 1024)
    if (
        isinstance(minimum_review_confidence, bool)
        or not isinstance(minimum_review_confidence, (int, float))
        or not math.isfinite(float(minimum_review_confidence))
        or not 0 <= float(minimum_review_confidence) <= 1
    ):
        raise AutofillInputError("minimum_review_confidence 必须在 0 到 1 之间")
    if (
        isinstance(max_candidates, bool)
        or not isinstance(max_candidates, int)
        or not 1 <= max_candidates <= 1_000
    ):
        raise AutofillInputError("max_candidates 必须是 1 到 1000 的整数")
    snapshot = _snapshot_binding(clean_draft, snapshot_metadata)
    remaining = max_candidates
    groups: list[tuple[str, list[Any]]] = []
    for evidence_class, values in (
        (RAW_OBSERVATION, raw_observations),
        (HISTORICAL_SUGGESTION, historical_suggestions),
        (PHYSICAL_INFERENCE, physical_inferences),
    ):
        materialized, remaining = _candidate_items(
            values,
            evidence_class=evidence_class,
            remaining=remaining,
        )
        groups.append((evidence_class, materialized))
    candidates: list[dict[str, Any]] = []
    global_index = 0
    for evidence_class, values in groups:
        for candidate in values:
            candidates.append(
                _normalize_candidate(
                    candidate,
                    evidence_class=evidence_class,
                    index=global_index,
                    snapshot=snapshot,
                )
            )
            global_index += 1
    review_patch, selections, conflicts = _apply_review_decisions(
        candidates,
        draft=clean_draft,
        minimum_confidence=float(minimum_review_confidence),
    )
    candidates.sort(key=_candidate_sort_key)
    warnings = [
        "本结果只是字段级核对提案，尚未修改、确认或提交任何草稿。",
        "置信度描述证据和提取质量，不代表企业事实真实性或监管认定。",
    ]
    if not snapshot["immutable"]:
        warnings.append(
            "本提案未绑定 Agent V2 不可变快照；历史和物理候选将被阻断。"
        )
    if any(
        candidate["delivery_route"] == "signed_source_import"
        for candidate in candidates
    ):
        warnings.append("来源观测只能通过保留网关签名的专用导入接口落地。")
    if any(
        candidate["delivery_route"] == "regulator_event_snapshot_import"
        for candidate in candidates
    ):
        warnings.append("监管事件代码只能通过匹配统计窗口的事件快照接口落地。")
    if conflicts:
        warnings.append("存在字段级证据冲突；冲突字段未进入核对补丁。")
    payload: dict[str, Any] = {
        "schema_version": AUTOFILL_PROPOSAL_SCHEMA_VERSION,
        "proposal_only": True,
        "applied": False,
        "requires_human_acceptance": True,
        "capabilities": {
            "can_write_draft": False,
            "can_confirm": False,
            "can_sign": False,
            "can_submit": False,
        },
        "snapshot": snapshot,
        "policy": {
            "minimum_review_confidence": round(
                float(minimum_review_confidence), 4
            ),
            "conflict_resolution": "no_value_selected",
            "existing_value_policy": "never_overwrite",
            "raw_observation_route": "signed_source_import",
            "regulator_event_route": "regulator_event_snapshot_import",
            "physical_inference_policy": "analysis_only",
        },
        "review_patch": review_patch,
        "review_patch_sha256": sha256_json(review_patch),
        "review_patch_candidates": dict(sorted(selections.items())),
        "conflicts": conflicts,
        "candidates": candidates,
        "counts": _counts(candidates),
        "warnings": warnings,
    }
    proposal_sha256 = sha256_json(payload)
    return {
        "proposal_id": f"autofill_{proposal_sha256[:24]}",
        **payload,
        "proposal_sha256": proposal_sha256,
    }


__all__ = [
    "AUTOFILL_PROPOSAL_SCHEMA_VERSION",
    "EVIDENCE_CLASSES",
    "HISTORICAL_SUGGESTION",
    "PHYSICAL_INFERENCE",
    "RAW_OBSERVATION",
    "AutofillInputError",
    "build_autofill_proposal",
]
