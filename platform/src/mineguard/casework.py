"""Local trial repository for reproducible runs and review casework.

The hash chain in this module detects accidental or out-of-band changes inside
the local trial database.  It is intentionally not described as WORM storage,
a digital signature, or legally sufficient evidence preservation.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import unicodedata
from contextlib import contextmanager
from datetime import UTC, date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Literal

from pydantic import BaseModel


CaseAction = Literal[
    "assign",
    "add_note",
    "start_review",
    "request_data",
    "submit_conclusion",
    "withdraw_conclusion",
    "approve",
    "reject",
    "close",
    "reopen",
    "archive_case",
    "restore_case",
]
CaseDisposition = Literal[
    "confirmed_technical_issue",
    "excluded",
    "data_insufficient",
    "partially_supported",
]

_DISPOSITIONS = {
    "confirmed_technical_issue",
    "excluded",
    "data_insufficient",
    "partially_supported",
}
ALGORITHM_FEATURE_VERSION = "2.1.0"
ALGORITHM_COMPATIBILITY_VERSION = "algorithm-feature-compatibility-v1"
_PRECOMPATIBILITY_FEATURE_VERSION = "2.1.0-pre-compatibility"


class CaseworkError(RuntimeError):
    """Base exception that API adapters may safely map to a client response."""


class BatchConflictError(CaseworkError):
    """The same batch id was submitted with different canonical input."""


class BatchNotFoundError(CaseworkError):
    """The requested analysis batch does not exist."""


class CaseNotFoundError(CaseworkError):
    """The requested case does not exist."""


class RunNotFoundError(CaseworkError):
    """The requested immutable analysis run does not exist."""


class VersionConflictError(CaseworkError):
    """The caller acted on a stale case version."""


class InvalidCaseActionError(CaseworkError):
    """An action is incomplete or invalid for the current workflow state."""


class AlgorithmRecordConflictError(CaseworkError):
    """One algorithm natural key was reused for different immutable content."""


class AlgorithmRecordIntegrityError(CaseworkError):
    """A stored algorithm record no longer matches its recorded digest."""


class LegitimateScenarioConflictError(CaseworkError):
    """One scenario version was reused for different immutable content."""


class ExternalSubmissionConflictError(CaseworkError):
    """An external idempotency key was reused for different content."""


class ExternalEventSnapshotConflictError(CaseworkError):
    """An external event snapshot id was reused for different content."""


class ExternalConfirmerRegistrationConflictError(CaseworkError):
    """An immutable confirmer registration key was reused or skipped."""


RUN_REFERENCE_LABELS = frozenset(
    {
        "verified_normal",
        "legitimate_exception",
        "confirmed_data_error",
        "confirmed_technical_anomaly",
        "adjudicated_violation",
        "unresolved",
    }
)

_SHORT_ID_LIMIT = 128
_ACTOR_LIMIT = 128
_NOTE_LIMIT = 4_000
_SCENARIO_NAME_LIMIT = 160
_SCENARIO_DESCRIPTION_LIMIT = 8_000
_SCENARIO_LIST_LIMIT = 128
_SCENARIO_FEATURE_LIMIT = 256
_SCENARIO_DEFINITION_BYTES_LIMIT = 256 * 1024
_EXTERNAL_EVENT_CODE_LIMIT = 32
_EXTERNAL_EVENT_SNAPSHOT_BYTES_LIMIT = 64 * 1024
_EXTERNAL_CONFIRMER_REGISTRATION_BYTES_LIMIT = 64 * 1024


def _bounded_text(
    value: Any,
    field: str,
    *,
    maximum: int,
    required: bool = True,
    multiline: bool = False,
) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = unicodedata.normalize("NFKC", value).replace("\r\n", "\n")
    if not multiline and any(character in normalized for character in "\r\n\t"):
        raise ValueError(f"{field} must be a single line")
    normalized = normalized.strip()
    if not normalized:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if len(normalized) > maximum:
        raise ValueError(f"{field} exceeds {maximum} characters")
    for character in normalized:
        if character in "\n\t" and multiline:
            continue
        if not character.isprintable():
            raise ValueError(f"{field} contains control characters")
    return normalized


def _normalized_text_list(
    value: Any,
    field: str,
    *,
    item_limit: int = _SHORT_ID_LIMIT,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"{field} must be an array")
    if len(value) > _SCENARIO_LIST_LIMIT:
        raise ValueError(
            f"{field} exceeds {_SCENARIO_LIST_LIMIT} entries"
        )
    normalized: set[str] = set()
    for index, item in enumerate(value):
        text = _bounded_text(
            item,
            f"{field}[{index}]",
            maximum=item_limit,
        )
        assert text is not None
        normalized.add(text)
    return sorted(normalized)


def _normalize_feature_bounds(value: Any) -> dict[str, dict[str, float | None]]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("feature_bounds must be an object")
    if len(value) > _SCENARIO_FEATURE_LIMIT:
        raise ValueError(
            f"feature_bounds exceeds {_SCENARIO_FEATURE_LIMIT} entries"
        )
    normalized: dict[str, dict[str, float | None]] = {}
    for raw_code, raw_bounds in value.items():
        code = _bounded_text(
            raw_code,
            "feature_bounds key",
            maximum=_SHORT_ID_LIMIT,
        )
        assert code is not None
        if code in normalized:
            raise ValueError("feature_bounds contains duplicate normalized keys")
        if not isinstance(raw_bounds, dict):
            raise ValueError(f"feature_bounds.{code} must be an object")
        unknown = set(raw_bounds) - {"lower", "upper"}
        if unknown:
            raise ValueError(
                f"feature_bounds.{code} contains unsupported fields: "
                + ", ".join(sorted(str(item) for item in unknown))
            )
        lower = _optional_finite_number(
            raw_bounds.get("lower"),
            f"feature_bounds.{code}.lower",
        )
        upper = _optional_finite_number(
            raw_bounds.get("upper"),
            f"feature_bounds.{code}.upper",
        )
        if lower is None and upper is None:
            raise ValueError(
                f"feature_bounds.{code} requires lower or upper"
            )
        if lower is not None and upper is not None and lower > upper:
            raise ValueError(
                f"feature_bounds.{code}.lower must not exceed upper"
            )
        normalized[code] = {"lower": lower, "upper": upper}
    return dict(sorted(normalized.items()))


def _normalize_legitimate_scenario_definition(
    raw: Any,
) -> dict[str, Any]:
    normalized = _json_value(raw)
    if not isinstance(normalized, dict):
        raise ValueError("legitimate scenario must be an object")
    generated_fields = {
        "created",
        "created_at",
        "definition_sha256",
        "definition_json",
        "hash_valid",
        "previous_definition_sha256",
        "version_chain_valid",
    }
    for field in generated_fields:
        normalized.pop(field, None)
    allowed = {
        "scenario_id",
        "version",
        "name",
        "description",
        "mine_ids",
        "regime",
        "shift",
        "season",
        "maintenance",
        "required_event_codes",
        "required_tags",
        "feature_bounds",
        "active",
        "created_by",
    }
    unknown = set(normalized) - allowed
    if unknown:
        raise ValueError(
            "legitimate scenario contains unsupported fields: "
            + ", ".join(sorted(str(item) for item in unknown))
        )

    scenario_id = _bounded_text(
        normalized.get("scenario_id"),
        "scenario_id",
        maximum=_SHORT_ID_LIMIT,
    )
    assert scenario_id is not None
    version = _integer(
        normalized.get("version"),
        "version",
        minimum=1,
    )
    name = _bounded_text(
        normalized.get("name"),
        "name",
        maximum=_SCENARIO_NAME_LIMIT,
    )
    description = _bounded_text(
        normalized.get("description"),
        "description",
        maximum=_SCENARIO_DESCRIPTION_LIMIT,
        multiline=True,
    )
    assert name is not None and description is not None
    raw_mine_ids = normalized.get("mine_ids")
    mine_ids = (
        _normalized_text_list(raw_mine_ids, "mine_ids")
        if raw_mine_ids is not None
        else None
    )
    if mine_ids == []:
        mine_ids = None

    optional_context: dict[str, str | None] = {}
    for field in ("regime", "shift", "season"):
        optional_context[field] = _bounded_text(
            normalized.get(field),
            field,
            maximum=_SHORT_ID_LIMIT,
            required=False,
        )
    maintenance = normalized.get("maintenance")
    if maintenance is not None and not isinstance(maintenance, bool):
        raise ValueError("maintenance must be a boolean or null")
    active = normalized.get("active", True)
    if not isinstance(active, bool):
        raise ValueError("active must be a boolean")
    created_by = _bounded_text(
        normalized.get("created_by"),
        "created_by",
        maximum=_ACTOR_LIMIT,
    )
    assert created_by is not None
    definition = {
        "scenario_id": scenario_id,
        "version": version,
        "name": name,
        "description": description,
        "mine_ids": mine_ids,
        **optional_context,
        "maintenance": maintenance,
        "required_event_codes": _normalized_text_list(
            normalized.get("required_event_codes"),
            "required_event_codes",
        ),
        "required_tags": _normalized_text_list(
            normalized.get("required_tags"),
            "required_tags",
        ),
        "feature_bounds": _normalize_feature_bounds(
            normalized.get("feature_bounds")
        ),
        "active": active,
        "created_by": created_by,
    }
    has_scope_constraint = bool(
        definition["mine_ids"]
        or definition["regime"]
        or definition["shift"]
        or definition["season"]
        or definition["maintenance"] is not None
        or definition["required_event_codes"]
        or definition["required_tags"]
    )
    if not has_scope_constraint:
        raise ValueError(
            "legitimate scenario requires at least one mine, context, "
            "approved event or tag constraint"
        )
    if not definition["feature_bounds"]:
        raise ValueError(
            "legitimate scenario requires at least one feature bound"
        )
    if len(canonical_json(definition).encode("utf-8")) > (
        _SCENARIO_DEFINITION_BYTES_LIMIT
    ):
        raise ValueError("legitimate scenario definition is too large")
    return definition


def _normalize_external_event_snapshot(raw: Any) -> dict[str, Any]:
    """Normalize one regulator-owned, immutable event-query result."""

    normalized = _json_value(raw)
    if not isinstance(normalized, dict):
        raise ValueError("external event snapshot must be an object")
    generated_fields = {
        "created",
        "created_at",
        "content_sha256",
        "content_json",
        "hash_valid",
    }
    for field in generated_fields:
        normalized.pop(field, None)
    allowed = {
        "snapshot_id",
        "mine_id",
        "window_start",
        "window_end",
        "event_codes",
        "evidence_sha256",
        "source_system",
        "record_id",
        "created_by",
    }
    unknown = set(normalized) - allowed
    if unknown:
        raise ValueError(
            "external event snapshot contains unsupported fields: "
            + ", ".join(sorted(str(item) for item in unknown))
        )

    snapshot_id = _bounded_text(
        normalized.get("snapshot_id"),
        "snapshot_id",
        maximum=_SHORT_ID_LIMIT,
    )
    mine_id = _bounded_text(
        normalized.get("mine_id"),
        "mine_id",
        maximum=_SHORT_ID_LIMIT,
    )
    window_start = _timestamp(
        normalized.get("window_start"),
        "window_start",
    )
    window_end = _timestamp(
        normalized.get("window_end"),
        "window_end",
    )
    assert snapshot_id is not None
    assert mine_id is not None
    assert window_start is not None
    assert window_end is not None
    if window_start >= window_end:
        raise ValueError("window_start must be earlier than window_end")

    raw_event_codes = normalized.get("event_codes")
    if not isinstance(raw_event_codes, (list, tuple)):
        raise ValueError("event_codes must be an array")
    if len(raw_event_codes) > _EXTERNAL_EVENT_CODE_LIMIT:
        raise ValueError(
            f"event_codes exceeds {_EXTERNAL_EVENT_CODE_LIMIT} entries"
        )
    event_codes: list[str] = []
    for index, value in enumerate(raw_event_codes):
        event_code = _bounded_text(
            value,
            f"event_codes[{index}]",
            maximum=64,
        )
        assert event_code is not None
        event_codes.append(event_code)
    if len(event_codes) != len(set(event_codes)):
        raise ValueError("event_codes values must be unique")

    evidence_sha256 = _bounded_text(
        normalized.get("evidence_sha256"),
        "evidence_sha256",
        maximum=64,
    )
    if (
        evidence_sha256 is None
        or len(evidence_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in evidence_sha256
        )
    ):
        raise ValueError("evidence_sha256 must be lowercase SHA-256 hex")
    source_system = _bounded_text(
        normalized.get("source_system"),
        "source_system",
        maximum=_SHORT_ID_LIMIT,
    )
    record_id = _bounded_text(
        normalized.get("record_id"),
        "record_id",
        maximum=256,
    )
    created_by = _bounded_text(
        normalized.get("created_by"),
        "created_by",
        maximum=_ACTOR_LIMIT,
    )
    assert source_system is not None
    assert record_id is not None
    assert created_by is not None
    result = {
        "snapshot_id": snapshot_id,
        "mine_id": mine_id,
        "window_start": window_start,
        "window_end": window_end,
        "event_codes": sorted(event_codes),
        "evidence_sha256": evidence_sha256,
        "source_system": source_system,
        "record_id": record_id,
        "created_by": created_by,
    }
    if len(canonical_json(result).encode("utf-8")) > (
        _EXTERNAL_EVENT_SNAPSHOT_BYTES_LIMIT
    ):
        raise ValueError("external event snapshot is too large")
    return result


def _normalize_external_confirmer_registration(
    raw: Any,
) -> dict[str, Any]:
    """Normalize one regulator-owned, immutable confirmer version."""

    normalized = _json_value(raw)
    if not isinstance(normalized, dict):
        raise ValueError(
            "external confirmer registration must be an object"
        )
    generated_fields = {
        "created",
        "created_at",
        "content_sha256",
        "content_json",
        "hash_valid",
        "previous_content_sha256",
        "version_chain_valid",
    }
    for field in generated_fields:
        normalized.pop(field, None)
    allowed = {
        "registration_id",
        "client_id",
        "enterprise_id",
        "confirmer_id",
        "version",
        "confirmer_name",
        "confirmer_roles",
        "confirmation_methods",
        "active",
        "source_system",
        "record_id",
        "created_by",
    }
    unknown = set(normalized) - allowed
    if unknown:
        raise ValueError(
            "external confirmer registration contains unsupported fields: "
            + ", ".join(sorted(str(item) for item in unknown))
        )

    identifiers: dict[str, str] = {}
    for field_name in (
        "registration_id",
        "client_id",
        "enterprise_id",
        "confirmer_id",
    ):
        value = _bounded_text(
            normalized.get(field_name),
            field_name,
            maximum=_SHORT_ID_LIMIT,
        )
        assert value is not None
        identifiers[field_name] = value
    version = _integer(
        normalized.get("version"),
        "version",
        minimum=1,
    )
    confirmer_name = _bounded_text(
        normalized.get("confirmer_name"),
        "confirmer_name",
        maximum=_SHORT_ID_LIMIT,
    )
    assert confirmer_name is not None
    confirmer_roles = _normalized_text_list(
        normalized.get("confirmer_roles"),
        "confirmer_roles",
    )
    if not confirmer_roles:
        raise ValueError("confirmer_roles must contain at least one role")
    confirmation_methods = _normalized_text_list(
        normalized.get("confirmation_methods"),
        "confirmation_methods",
    )
    if confirmation_methods != ["authenticated_click"]:
        raise ValueError(
            "only authenticated_click confirmation is supported; "
            "qualified signatures and seals require a verifier"
        )
    active = normalized.get("active", True)
    if not isinstance(active, bool):
        raise ValueError("active must be a boolean")
    source_system = _bounded_text(
        normalized.get("source_system"),
        "source_system",
        maximum=_SHORT_ID_LIMIT,
    )
    record_id = _bounded_text(
        normalized.get("record_id"),
        "record_id",
        maximum=256,
    )
    created_by = _bounded_text(
        normalized.get("created_by"),
        "created_by",
        maximum=_ACTOR_LIMIT,
    )
    assert source_system is not None
    assert record_id is not None
    assert created_by is not None
    result = {
        **identifiers,
        "version": version,
        "confirmer_name": confirmer_name,
        "confirmer_roles": confirmer_roles,
        "confirmation_methods": confirmation_methods,
        "active": active,
        "source_system": source_system,
        "record_id": record_id,
        "created_by": created_by,
    }
    if len(canonical_json(result).encode("utf-8")) > (
        _EXTERNAL_CONFIRMER_REGISTRATION_BYTES_LIMIT
    ):
        raise ValueError("external confirmer registration is too large")
    return result


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    item = getattr(value, "item", None)
    if callable(item):
        return item()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def _json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    # Normalize dates, enums, tuples and numerical scalar values once so the
    # stored value and its digest are computed from the exact same document.
    return json.loads(canonical_json(value))


def canonical_json(value: Any) -> str:
    """Return the stable UTF-8 JSON representation used for every digest."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def match_legitimate_scenarios(
    scenarios: list[dict[str, Any]],
    *,
    mine_id: str,
    operational_context: dict[str, Any] | None,
    features: dict[str, Any] | None,
) -> dict[str, Any]:
    """Evaluate immutable scenario definitions against one operational window.

    The dictionary contract deliberately stays independent of the historical
    model module.  Required context is matched exactly; feature bounds are
    inclusive.  Every candidate receives machine-readable unmet reasons so a
    caller can explain both matches and near-misses.
    """

    normalized_mine_id = _bounded_text(
        mine_id,
        "mine_id",
        maximum=_SHORT_ID_LIMIT,
    )
    assert normalized_mine_id is not None
    if operational_context is None:
        operational_context = {}
    if not isinstance(operational_context, dict):
        raise ValueError("operational_context must be an object")
    supported_context_fields = {
        "regime",
        "regime_code",
        "shift",
        "shift_code",
        "season",
        "season_code",
        "maintenance",
        "event_codes",
        "approved_event_codes",
        "tags",
    }
    unknown_context_fields = set(operational_context) - (
        supported_context_fields
    )
    if unknown_context_fields:
        raise ValueError(
            "operational_context contains unsupported fields: "
            + ", ".join(
                sorted(str(item) for item in unknown_context_fields)
            )
        )
    if len(canonical_json(operational_context).encode("utf-8")) > 256 * 1024:
        raise ValueError("operational_context is too large")
    if features is None:
        features = {}
    if not isinstance(features, dict):
        raise ValueError("features must be an object")
    if len(features) > 10_000:
        raise ValueError("features exceeds 10000 entries")

    context_values: dict[str, str | bool | None] = {}
    for field in ("regime", "shift", "season"):
        alias = f"{field}_code"
        raw_value = operational_context.get(field)
        raw_alias = operational_context.get(alias)
        if raw_value is not None and raw_alias is not None:
            normalized_value = _bounded_text(
                raw_value,
                f"operational_context.{field}",
                maximum=_SHORT_ID_LIMIT,
                required=False,
            )
            normalized_alias = _bounded_text(
                raw_alias,
                f"operational_context.{alias}",
                maximum=_SHORT_ID_LIMIT,
                required=False,
            )
            if normalized_value != normalized_alias:
                raise ValueError(
                    f"operational_context.{field} and {alias} conflict"
                )
            raw_value = normalized_value
        elif raw_value is None:
            raw_value = raw_alias
        context_values[field] = _bounded_text(
            raw_value,
            f"operational_context.{field}",
            maximum=_SHORT_ID_LIMIT,
            required=False,
        )
    context_maintenance = operational_context.get("maintenance")
    if context_maintenance is not None and not isinstance(
        context_maintenance,
        bool,
    ):
        raise ValueError(
            "operational_context.maintenance must be a boolean or null"
        )
    context_values["maintenance"] = context_maintenance
    raw_event_codes = operational_context.get("event_codes")
    raw_approved_event_codes = operational_context.get(
        "approved_event_codes"
    )
    if raw_event_codes is not None and raw_approved_event_codes is not None:
        normalized_event_codes = _normalized_text_list(
            raw_event_codes,
            "operational_context.event_codes",
        )
        normalized_approved_event_codes = _normalized_text_list(
            raw_approved_event_codes,
            "operational_context.approved_event_codes",
        )
        if normalized_event_codes != normalized_approved_event_codes:
            raise ValueError(
                "operational_context.event_codes and approved_event_codes "
                "conflict"
            )
        raw_event_codes = normalized_event_codes
    elif raw_event_codes is None:
        raw_event_codes = raw_approved_event_codes
    event_codes = set(
        _normalized_text_list(
            raw_event_codes,
            "operational_context.event_codes",
        )
    )
    tags = set(
        _normalized_text_list(
            operational_context.get("tags"),
            "operational_context.tags",
        )
    )
    normalized_features: dict[str, float] = {}
    for raw_code, raw_value in features.items():
        code = _bounded_text(
            raw_code,
            "features key",
            maximum=_SHORT_ID_LIMIT,
        )
        assert code is not None
        if code in normalized_features:
            raise ValueError("features contains duplicate normalized keys")
        value = _optional_finite_number(raw_value, f"features.{code}")
        if value is None:
            raise ValueError(f"features.{code} must not be null")
        normalized_features[code] = value

    evaluations: list[dict[str, Any]] = []
    matched: list[dict[str, Any]] = []
    if len(scenarios) > 10_000:
        raise ValueError("scenarios exceeds 10000 entries")
    for raw_scenario in scenarios:
        if not isinstance(raw_scenario, dict):
            raise ValueError("every scenario must be an object")
        definition = _normalize_legitimate_scenario_definition(raw_scenario)
        scenario_id = definition["scenario_id"]
        version = definition["version"]
        reasons: list[str] = []
        if raw_scenario.get("hash_valid") is False:
            reasons.append("definition_hash_invalid")
        if definition["active"] is not True:
            reasons.append("scenario_inactive")

        scenario_mines = definition["mine_ids"]
        if scenario_mines is not None:
            normalized_mines = set(scenario_mines)
            if normalized_mine_id not in normalized_mines:
                reasons.append("mine_id_not_applicable")

        for field in ("regime", "shift", "season", "maintenance"):
            required_value = definition[field]
            if required_value is None:
                continue
            actual_value = context_values[field]
            if actual_value is None:
                reasons.append(f"missing_context:{field}")
            elif actual_value != required_value:
                reasons.append(f"context_mismatch:{field}")

        required_events = _normalized_text_list(
            definition["required_event_codes"],
            "required_event_codes",
        )
        for event_code in required_events:
            if event_code not in event_codes:
                reasons.append(f"missing_event_code:{event_code}")
        required_tags = _normalized_text_list(
            definition["required_tags"],
            "required_tags",
        )
        for tag in required_tags:
            if tag not in tags:
                reasons.append(f"missing_tag:{tag}")
        bounds = _normalize_feature_bounds(
            definition["feature_bounds"]
        )
        for code, limits in bounds.items():
            value = normalized_features.get(code)
            if value is None:
                reasons.append(f"missing_feature:{code}")
                continue
            lower = limits["lower"]
            upper = limits["upper"]
            if lower is not None and value < lower:
                reasons.append(f"feature_below_lower:{code}")
            if upper is not None and value > upper:
                reasons.append(f"feature_above_upper:{code}")

        evaluation = {
            "scenario_id": scenario_id,
            "version": version,
            "matched": not reasons,
            "unmet_reasons": reasons,
        }
        evaluations.append(evaluation)
        if not reasons:
            matched.append(raw_scenario)
    return {
        "mine_id": normalized_mine_id,
        "operational_context": {
            "regime": context_values["regime"],
            "shift": context_values["shift"],
            "season": context_values["season"],
            "maintenance": context_values["maintenance"],
            "event_codes": sorted(event_codes),
            "tags": sorted(tags),
        },
        "matched_scenarios": matched,
        "evaluations": evaluations,
    }


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(parts)
    return f"{prefix}_{_digest_text(material)[:24]}"


def _required_text(document: dict[str, Any], key: str) -> str:
    value = str(document.get(key, "")).strip()
    if not value:
        raise ValueError(f"{key} is required")
    document[key] = value
    return value


def _timestamp(
    value: Any,
    field: str,
    *,
    required: bool = True,
) -> str | None:
    if value is None or not str(value).strip():
        if required:
            raise ValueError(f"{field} is required")
        return None
    raw = str(value).strip()
    if len(raw) == 10:
        try:
            date.fromisoformat(raw)
        except ValueError:
            pass
        else:
            raw = f"{raw}T00:00:00Z"
    try:
        parsed = datetime.fromisoformat(
            raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
        )
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _time_bounds(
    start_at: str | None,
    end_at: str | None,
) -> tuple[str | None, str | None]:
    start = _timestamp(start_at, "start_at", required=False)
    end = _timestamp(end_at, "end_at", required=False)
    if start is not None and end is not None and start >= end:
        raise ValueError("start_at must be earlier than end_at")
    return start, end


def _integer(
    value: Any,
    field: str,
    *,
    minimum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value < minimum:
        raise ValueError(f"{field} must be at least {minimum}")
    return value


def _optional_finite_number(value: Any, field: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number or null")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field} must be finite")
    return number


def _compatibility_window_seconds(snapshot: dict[str, Any]) -> float | None:
    try:
        start_text = _timestamp(snapshot.get("window_start"), "window_start")
        end_text = _timestamp(snapshot.get("window_end"), "window_end")
    except ValueError:
        return None
    assert start_text is not None and end_text is not None
    start = datetime.fromisoformat(start_text.replace("Z", "+00:00"))
    end = datetime.fromisoformat(end_text.replace("Z", "+00:00"))
    duration = (end - start).total_seconds()
    if not math.isfinite(duration) or duration <= 0:
        return None
    return round(float(duration), 6)


def _compatibility_observation_structure(
    snapshot: dict[str, Any],
) -> list[dict[str, Any]]:
    raw_observations = snapshot.get("observations")
    if not isinstance(raw_observations, list):
        return []
    structure: list[dict[str, Any]] = []
    for raw in raw_observations:
        if not isinstance(raw, dict):
            continue
        raw_domains = raw.get("dependency_domains")
        domains = (
            sorted(str(item) for item in raw_domains)
            if isinstance(raw_domains, list)
            else []
        )
        tolerance_rel = raw.get("tolerance_rel")
        if tolerance_rel is None:
            tolerance_rel = raw.get("tolerance_relative", 0.0)
        resolution = raw.get("resolution")
        if resolution is None:
            resolution = raw.get("measurement_resolution", 0.0)
        structure.append(
            {
                "metric_code": str(raw.get("metric_code") or ""),
                "source_group": str(raw.get("source_group") or ""),
                "tolerance_abs": raw.get("tolerance_abs"),
                "tolerance_rel": tolerance_rel,
                "resolution": resolution,
                "dependency_domains": domains,
                "source_reliability": raw.get(
                    "source_reliability",
                    1.0,
                ),
            }
        )
    return sorted(structure, key=canonical_json)


def build_algorithm_feature_compatibility(
    request_snapshot: Any,
    *,
    engine_version: str,
    trusted_mode: str,
    profile_id: str | None = None,
    profile_version: str | None = None,
    registry_snapshot_hash: str | None = None,
) -> dict[str, Any]:
    """Build the versioned exchangeability contract for one feature window."""

    normalized = _json_value(request_snapshot)
    if not isinstance(normalized, dict):
        raise ValueError("request_snapshot must be an object")
    parameters = normalized.get("parameters")
    if not isinstance(parameters, dict):
        parameters = {}
    structure = _compatibility_observation_structure(normalized)
    normalized_mode = str(trusted_mode or "").strip()
    normalized_profile_id = str(profile_id).strip() if profile_id is not None else None
    normalized_profile_version = (
        str(profile_version).strip() if profile_version is not None else None
    )
    normalized_registry_hash = (
        str(registry_snapshot_hash).strip()
        if registry_snapshot_hash is not None
        else None
    )
    governance_complete = bool(
        normalized_mode == "governed"
        and normalized_profile_id
        and normalized_profile_version
        and normalized_registry_hash
    )
    return {
        "compatibility_version": ALGORITHM_COMPATIBILITY_VERSION,
        "algorithm_feature_version": ALGORITHM_FEATURE_VERSION,
        "engine_version": str(engine_version).strip(),
        "window_duration_seconds": _compatibility_window_seconds(normalized),
        "parameters_sha256": sha256_json(parameters),
        "observation_structure": structure,
        "observation_structure_sha256": sha256_json(structure),
        "trusted_mode": normalized_mode,
        "profile_id": normalized_profile_id,
        "profile_version": normalized_profile_version,
        "registry_snapshot_hash": normalized_registry_hash,
        "governance_complete": governance_complete,
    }


def algorithm_feature_compatibility_key(
    compatibility: dict[str, Any],
) -> str:
    """Hash a complete compatibility document using repository canon rules."""

    return sha256_json(compatibility)


def _algorithm_governance_compatibility(
    context_snapshot: dict[str, Any] | None,
    mine_id: str,
) -> dict[str, Any]:
    if not isinstance(context_snapshot, dict):
        return {
            "trusted_mode": "direct",
            "profile_id": None,
            "profile_version": None,
            "registry_snapshot_hash": None,
        }
    identity: dict[str, Any] = context_snapshot
    reports = context_snapshot.get("mine_reports")
    if isinstance(reports, list):
        for report in reports:
            if isinstance(report, dict) and str(report.get("mine_id") or "") == mine_id:
                identity = report
                break
    kind = str(context_snapshot.get("kind") or "")
    return {
        "trusted_mode": ("governed" if kind.startswith("governed_") else "direct"),
        "profile_id": identity.get("profile_id"),
        "profile_version": identity.get("profile_version"),
        "registry_snapshot_hash": identity.get("registry_snapshot_hash"),
    }


def _algorithm_source_observations(
    input_snapshot: dict[str, Any],
    context_snapshot: dict[str, Any] | None,
    mine_id: str,
) -> list[dict[str, Any]]:
    """Prefer original governed envelopes over reconciled observations."""

    if isinstance(context_snapshot, dict):
        reports = context_snapshot.get("mine_reports")
        if isinstance(reports, list):
            for report in reports:
                if not isinstance(report, dict):
                    continue
                if str(report.get("mine_id") or "") != mine_id:
                    continue
                envelopes = report.get("observation_envelopes")
                if isinstance(envelopes, list):
                    return [item for item in envelopes if isinstance(item, dict)]
        envelopes = context_snapshot.get("observation_envelopes")
        if isinstance(envelopes, list):
            return [item for item in envelopes if isinstance(item, dict)]
    observations = input_snapshot.get("observations")
    if isinstance(observations, list):
        return [item for item in observations if isinstance(item, dict)]
    return []


def _algorithm_feature_authority(
    *,
    input_snapshot: dict[str, Any],
    context_snapshot: dict[str, Any] | None,
    mine_id: str,
    created_at: str,
    feature_id: str,
) -> dict[str, Any]:
    observations = _algorithm_source_observations(
        input_snapshot,
        context_snapshot,
        mine_id,
    )
    revisions: list[int] = []
    sequences: list[int] = []
    received_times: list[str] = []
    for observation in observations:
        raw_revision = observation.get("revision_no")
        if raw_revision is None:
            raw_revision = observation.get("revision")
        if isinstance(raw_revision, int) and not isinstance(raw_revision, bool):
            revisions.append(raw_revision)
        raw_sequence = observation.get("sequence_no")
        if isinstance(raw_sequence, int) and not isinstance(raw_sequence, bool):
            sequences.append(raw_sequence)
        try:
            received_at = _timestamp(
                observation.get("received_at"),
                "received_at",
                required=False,
            )
        except ValueError:
            received_at = None
        if received_at is not None:
            received_times.append(received_at)

    observation_count = len(observations)
    supplied_count = len(revisions) + len(sequences) + len(received_times)
    partial_source_order = bool(
        supplied_count
        and (
            len(revisions) not in {0, observation_count}
            or len(sequences) not in {0, observation_count}
            or len(received_times) not in {0, observation_count}
        )
    )
    return {
        "source_observation_count": observation_count,
        "source_revision_no": max(revisions) if revisions else None,
        "source_revision_complete": bool(
            observation_count and len(revisions) == observation_count
        ),
        "source_sequence_no": max(sequences) if sequences else None,
        "source_sequence_complete": bool(
            observation_count and len(sequences) == observation_count
        ),
        "source_received_at": max(received_times) if received_times else None,
        "source_received_at_complete": bool(
            observation_count and len(received_times) == observation_count
        ),
        "source_order_ambiguous": partial_source_order,
        "repository_created_at": created_at,
        "repository_feature_id": feature_id,
    }


def select_authoritative_algorithm_feature(
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Select one revision without using batch/run identifiers as authority.

    Callers should pass candidates for one event-time feature point.  Source
    revision, sequence and receive time are considered in that order.  When
    source authority is present but incomplete or tied, the result is
    ``ambiguous`` instead of silently falling back to arbitrary identifiers.
    Only records with no source ordering metadata use the repository's actual
    receive order (``created_at``, then stable ``feature_id``).
    """

    feature_ids = [str(candidate.get("feature_id") or "") for candidate in candidates]

    def result(
        status: Literal["empty", "selected", "ambiguous"],
        *,
        selected: dict[str, Any] | None = None,
        basis: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "selected": selected,
            "basis": basis,
            "ambiguity_reason": reason,
            "candidate_count": len(candidates),
            "candidate_feature_ids": feature_ids,
        }

    if not candidates:
        return result("empty", reason="no_candidates")
    point_keys = {
        (
            str(candidate.get("mine_id") or ""),
            str(candidate.get("observed_at") or ""),
            str(candidate.get("feature_code") or ""),
            str(candidate.get("source_key") or ""),
            str(candidate.get("feature_version") or ""),
        )
        for candidate in candidates
    }
    if len(point_keys) != 1:
        return result("ambiguous", reason="mixed_feature_points")
    if any(candidate.get("hash_valid") is False for candidate in candidates):
        return result("ambiguous", reason="hash_verification_failed")

    remaining = list(candidates)
    source_authority_seen = False
    authority_fields = (
        (
            "source_revision_no",
            "source_revision_complete",
            "source_revision_no",
        ),
        (
            "source_sequence_no",
            "source_sequence_complete",
            "source_sequence_no",
        ),
        (
            "source_received_at",
            "source_received_at_complete",
            "source_received_at",
        ),
    )
    if any(
        bool((candidate.get("authority_order") or {}).get("source_order_ambiguous"))
        for candidate in remaining
    ):
        return result("ambiguous", reason="partial_source_order_metadata")

    for value_key, complete_key, basis in authority_fields:
        metadata = [
            candidate.get("authority_order")
            if isinstance(candidate.get("authority_order"), dict)
            else {}
            for candidate in remaining
        ]
        values = [item.get(value_key) for item in metadata]
        if not any(value is not None for value in values):
            continue
        source_authority_seen = True
        if not all(
            value is not None and bool(item.get(complete_key))
            for value, item in zip(values, metadata, strict=True)
        ):
            return result(
                "ambiguous",
                reason=f"incomplete_{value_key}",
            )
        maximum = max(values)
        remaining = [
            candidate
            for candidate, value in zip(remaining, values, strict=True)
            if value == maximum
        ]
        if len(remaining) == 1:
            return result("selected", selected=remaining[0], basis=basis)

    if source_authority_seen:
        return result("ambiguous", reason="source_order_tie")

    receipt_ranks: list[tuple[str, str]] = []
    for candidate in remaining:
        authority = candidate.get("authority_order")
        if not isinstance(authority, dict):
            authority = {}
        created_at = str(
            authority.get("repository_created_at") or candidate.get("created_at") or ""
        )
        feature_id = str(
            authority.get("repository_feature_id") or candidate.get("feature_id") or ""
        )
        try:
            normalized_created_at = _timestamp(
                created_at,
                "repository_created_at",
            )
        except ValueError:
            return result(
                "ambiguous",
                reason="missing_repository_receipt_order",
            )
        assert normalized_created_at is not None
        if not feature_id:
            return result(
                "ambiguous",
                reason="missing_repository_receipt_order",
            )
        receipt_ranks.append((normalized_created_at, feature_id))
    maximum_receipt = max(receipt_ranks)
    winners = [
        candidate
        for candidate, rank in zip(
            remaining,
            receipt_ranks,
            strict=True,
        )
        if rank == maximum_receipt
    ]
    if len(winners) != 1:
        return result("ambiguous", reason="repository_receipt_order_tie")
    return result(
        "selected",
        selected=winners[0],
        basis="repository_receipt_order",
    )


class LocalRepository:
    """Thread-safe SQLite persistence for a single local trial process."""

    def __init__(self, database_path: str | Path = ":memory:") -> None:
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            database_file = Path(self.database_path).expanduser().resolve()
            database_file.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=0o700,
            )
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
            timeout=10,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        if self.database_path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._initialize_schema()
        if self.database_path != ":memory:":
            try:
                Path(self.database_path).chmod(0o600)
            except OSError:
                pass

    def _initialize_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS batches (
            batch_id TEXT PRIMARY KEY,
            portfolio_name TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            request_json TEXT NOT NULL,
            response_sha256 TEXT,
            response_json TEXT NOT NULL,
            context_sha256 TEXT,
            context_json TEXT,
            integrity_origin TEXT,
            created_at TEXT NOT NULL,
            lifecycle_version INTEGER NOT NULL DEFAULT 1,
            invalidated_at TEXT,
            invalidated_by TEXT,
            invalidation_reason TEXT
        );

        CREATE TABLE IF NOT EXISTS batch_lifecycle_events (
            batch_id TEXT NOT NULL REFERENCES batches(batch_id),
            sequence INTEGER NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT,
            before_json TEXT,
            after_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(batch_id, sequence)
        );

        CREATE TABLE IF NOT EXISTS analysis_runs (
            run_id TEXT PRIMARY KEY,
            batch_id TEXT NOT NULL REFERENCES batches(batch_id),
            mine_id TEXT NOT NULL,
            technical_status TEXT NOT NULL,
            input_sha256 TEXT NOT NULL,
            input_json TEXT NOT NULL,
            result_sha256 TEXT NOT NULL,
            result_json TEXT NOT NULL,
            engine_version TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(batch_id, mine_id)
        );

        CREATE TABLE IF NOT EXISTS run_reference_labels (
            run_id TEXT NOT NULL REFERENCES analysis_runs(run_id),
            sequence INTEGER NOT NULL,
            label TEXT NOT NULL,
            scenario_id TEXT,
            actor TEXT NOT NULL,
            note TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(run_id, sequence)
        );

        CREATE INDEX IF NOT EXISTS idx_run_reference_labels_current
            ON run_reference_labels(run_id, sequence DESC);
        CREATE INDEX IF NOT EXISTS idx_run_reference_labels_label
            ON run_reference_labels(label, created_at);

        CREATE TABLE IF NOT EXISTS external_request_nonces (
            client_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            request_timestamp TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(client_id, nonce)
        );

        CREATE INDEX IF NOT EXISTS idx_external_nonces_expiry
            ON external_request_nonces(expires_at);

        CREATE TABLE IF NOT EXISTS external_submission_receipts (
            submission_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            enterprise_id TEXT NOT NULL,
            mine_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            body_sha256 TEXT,
            submission_body BLOB,
            receipt_sha256 TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(client_id, idempotency_key)
        );

        CREATE INDEX IF NOT EXISTS idx_external_receipts_enterprise
            ON external_submission_receipts(
                enterprise_id, mine_id, created_at
            );

        CREATE TABLE IF NOT EXISTS external_event_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            mine_id TEXT NOT NULL,
            window_start TEXT NOT NULL,
            window_end TEXT NOT NULL,
            event_codes_json TEXT NOT NULL,
            evidence_sha256 TEXT NOT NULL,
            source_system TEXT NOT NULL,
            record_id TEXT NOT NULL,
            created_by TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            content_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_external_event_snapshot_lookup
            ON external_event_snapshots(
                mine_id, window_start, window_end, evidence_sha256
            );

        CREATE TABLE IF NOT EXISTS external_confirmer_registrations (
            registration_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            enterprise_id TEXT NOT NULL,
            confirmer_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            confirmer_name TEXT NOT NULL,
            confirmer_roles_json TEXT NOT NULL,
            confirmation_methods_json TEXT NOT NULL,
            active INTEGER NOT NULL,
            source_system TEXT NOT NULL,
            record_id TEXT NOT NULL,
            created_by TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            content_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(client_id, enterprise_id, confirmer_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_external_confirmer_current
            ON external_confirmer_registrations(
                client_id, enterprise_id, confirmer_id, version DESC
            );

        CREATE TABLE IF NOT EXISTS legitimate_scenarios (
            scenario_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            mine_ids_json TEXT,
            regime TEXT,
            shift TEXT,
            season TEXT,
            maintenance INTEGER,
            required_event_codes_json TEXT NOT NULL,
            required_tags_json TEXT NOT NULL,
            feature_bounds_json TEXT NOT NULL,
            active INTEGER NOT NULL,
            created_by TEXT NOT NULL,
            definition_sha256 TEXT NOT NULL,
            definition_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(scenario_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_legitimate_scenarios_current
            ON legitimate_scenarios(scenario_id, version DESC);
        CREATE INDEX IF NOT EXISTS idx_legitimate_scenarios_active
            ON legitimate_scenarios(active, scenario_id, version DESC);

        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            run_id TEXT REFERENCES analysis_runs(run_id),
            batch_id TEXT NOT NULL REFERENCES batches(batch_id),
            mine_id TEXT NOT NULL,
            issue_code TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            priority TEXT NOT NULL,
            technical_status TEXT NOT NULL,
            evidence_grade TEXT,
            workflow_status TEXT NOT NULL,
            disposition TEXT,
            assignee TEXT,
            archived_at TEXT,
            archived_by TEXT,
            archived_reason TEXT,
            version INTEGER NOT NULL,
            recommended_checks_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(batch_id, mine_id)
        );

        CREATE TABLE IF NOT EXISTS case_events (
            case_id TEXT NOT NULL REFERENCES cases(case_id),
            sequence INTEGER NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            note TEXT,
            before_json TEXT,
            after_json TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(case_id, sequence)
        );

        CREATE INDEX IF NOT EXISTS idx_cases_workflow_priority
            ON cases(workflow_status, priority);
        CREATE INDEX IF NOT EXISTS idx_cases_batch_mine
            ON cases(batch_id, mine_id);

        CREATE TABLE IF NOT EXISTS analysis_feature_windows (
            feature_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES analysis_runs(run_id),
            batch_id TEXT NOT NULL REFERENCES batches(batch_id),
            mine_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            feature_code TEXT NOT NULL,
            source_key TEXT NOT NULL,
            feature_version TEXT NOT NULL,
            value REAL NOT NULL,
            quality_score REAL,
            feature_sha256 TEXT NOT NULL,
            feature_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(run_id, feature_code, source_key, feature_version)
        );

        CREATE INDEX IF NOT EXISTS idx_feature_series_time
            ON analysis_feature_windows(
                mine_id, feature_code, source_key, observed_at
            );

        CREATE TABLE IF NOT EXISTS detector_findings (
            finding_id TEXT PRIMARY KEY,
            mine_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            feature_code TEXT NOT NULL,
            source_key TEXT NOT NULL,
            detector_code TEXT NOT NULL,
            detector_version TEXT NOT NULL,
            status TEXT NOT NULL,
            score REAL,
            baseline_sample_count INTEGER NOT NULL,
            finding_sha256 TEXT NOT NULL,
            finding_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(
                mine_id, observed_at, feature_code, source_key,
                detector_code, detector_version
            )
        );

        CREATE INDEX IF NOT EXISTS idx_detector_findings_time
            ON detector_findings(mine_id, observed_at, status);

        CREATE TABLE IF NOT EXISTS algorithm_model_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            detector_code TEXT NOT NULL,
            detector_version TEXT NOT NULL,
            scope_key TEXT NOT NULL,
            training_start TEXT,
            training_end TEXT,
            sample_count INTEGER NOT NULL,
            activation_status TEXT NOT NULL,
            snapshot_sha256 TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(detector_code, detector_version, scope_key)
        );

        CREATE TABLE IF NOT EXISTS alert_episodes (
            episode_id TEXT PRIMARY KEY,
            mine_id TEXT NOT NULL,
            feature_code TEXT NOT NULL,
            source_key TEXT NOT NULL,
            detector_code TEXT NOT NULL,
            detector_version TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT NOT NULL,
            peak_score REAL,
            finding_count INTEGER NOT NULL,
            episode_sha256 TEXT NOT NULL,
            episode_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(
                mine_id, feature_code, source_key, detector_code,
                detector_version, started_at
            )
        );
        """
        with self._lock, self._connection:
            self._connection.executescript(schema)
            external_receipt_columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(external_submission_receipts)"
                ).fetchall()
            }
            for column, column_type in {
                "body_sha256": "TEXT",
                "submission_body": "BLOB",
            }.items():
                if column not in external_receipt_columns:
                    self._connection.execute(
                        "ALTER TABLE external_submission_receipts "
                        f"ADD COLUMN {column} {column_type}"
                    )
            existing_columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(cases)"
                ).fetchall()
            }
            optional_columns = {
                "conclusion_by": "TEXT",
                "conclusion_at": "TEXT",
                "approval_by": "TEXT",
                "approval_at": "TEXT",
                "approval_note": "TEXT",
                "archived_at": "TEXT",
                "archived_by": "TEXT",
                "archived_reason": "TEXT",
            }
            for column, column_type in optional_columns.items():
                if column not in existing_columns:
                    self._connection.execute(
                        f"ALTER TABLE cases ADD COLUMN {column} {column_type}"
                    )
            batch_columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(batches)"
                ).fetchall()
            }
            if "context_json" not in batch_columns:
                self._connection.execute(
                    "ALTER TABLE batches ADD COLUMN context_json TEXT"
                )
            batch_integrity_columns = {
                "response_sha256": "TEXT",
                "context_sha256": "TEXT",
                "integrity_origin": "TEXT",
            }
            for column, column_type in batch_integrity_columns.items():
                if column not in batch_columns:
                    self._connection.execute(
                        f"ALTER TABLE batches ADD COLUMN {column} {column_type}"
                    )
            integrity_rows = self._connection.execute(
                """
                SELECT batch_id, response_json, context_json,
                       response_sha256, context_sha256, integrity_origin
                FROM batches
                WHERE response_sha256 IS NULL OR context_sha256 IS NULL
                   OR integrity_origin IS NULL
                """
            ).fetchall()
            for row in integrity_rows:
                try:
                    response_value = json.loads(row["response_json"])
                    context_value = (
                        json.loads(row["context_json"])
                        if row["context_json"] is not None
                        else None
                    )
                except (TypeError, json.JSONDecodeError):
                    continue
                self._connection.execute(
                    """
                    UPDATE batches
                    SET response_sha256 = COALESCE(response_sha256, ?),
                        context_sha256 = COALESCE(context_sha256, ?),
                        integrity_origin = COALESCE(
                            integrity_origin, 'legacy_backfill'
                        )
                    WHERE batch_id = ?
                    """,
                    (
                        sha256_json(response_value),
                        sha256_json(context_value),
                        str(row["batch_id"]),
                    ),
                )
            batch_optional_columns = {
                "lifecycle_version": "INTEGER NOT NULL DEFAULT 1",
                "invalidated_at": "TEXT",
                "invalidated_by": "TEXT",
                "invalidation_reason": "TEXT",
            }
            for column, column_type in batch_optional_columns.items():
                if column not in batch_columns:
                    self._connection.execute(
                        f"ALTER TABLE batches ADD COLUMN {column} {column_type}"
                    )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS batch_lifecycle_events (
                    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
                    sequence INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT,
                    before_json TEXT,
                    after_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(batch_id, sequence)
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_batches_active_created
                ON batches(invalidated_at, created_at)
                """
            )
            self._backfill_batch_lifecycle_events()
            self._migrate_algorithm_feature_schema()
            self._migrate_precompatibility_features()
            self._migrate_alert_episode_schema()
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_feature_version_series_time
                ON analysis_feature_windows(
                    feature_version, mine_id, feature_code, source_key,
                    observed_at
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_algorithm_model_scope_time
                ON algorithm_model_snapshots(
                    scope_key, training_end, created_at
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_alert_episode_mine_time
                ON alert_episodes(mine_id, started_at, ended_at)
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cases_archived_at
                ON cases(archived_at)
                """
            )
            self._backfill_algorithm_features()

    def _migrate_precompatibility_features(self) -> None:
        """Free the current version key without rewriting legacy evidence."""

        rows = self._connection.execute(
            """
            SELECT feature_id, feature_json
            FROM analysis_feature_windows
            WHERE feature_version = ?
            """,
            (ALGORITHM_FEATURE_VERSION,),
        ).fetchall()
        for row in rows:
            try:
                document = json.loads(row["feature_json"])
            except (TypeError, json.JSONDecodeError):
                document = None
            compatibility = (
                document.get("compatibility") if isinstance(document, dict) else None
            )
            recorded_key = (
                document.get("compatibility_key")
                if isinstance(document, dict)
                else None
            )
            raw_observed_at = (
                document.get("observed_at") if isinstance(document, dict) else None
            )
            try:
                canonical_observed_at = _timestamp(
                    raw_observed_at,
                    "observed_at",
                )
            except ValueError:
                canonical_observed_at = None
            if (
                isinstance(compatibility, dict)
                and isinstance(recorded_key, str)
                and algorithm_feature_compatibility_key(compatibility) == recorded_key
                and compatibility.get("compatibility_version")
                == ALGORITHM_COMPATIBILITY_VERSION
                and compatibility.get("algorithm_feature_version")
                == ALGORITHM_FEATURE_VERSION
                and isinstance(document.get("authority_order"), dict)
                and raw_observed_at == canonical_observed_at
            ):
                continue
            self._connection.execute(
                """
                UPDATE analysis_feature_windows
                SET feature_version = ?
                WHERE feature_id = ? AND feature_version = ?
                """,
                (
                    _PRECOMPATIBILITY_FEATURE_VERSION,
                    str(row["feature_id"]),
                    ALGORITHM_FEATURE_VERSION,
                ),
            )

    def _unique_index_columns(self, table: str) -> set[tuple[str, ...]]:
        result: set[tuple[str, ...]] = set()
        for row in self._connection.execute(f'PRAGMA index_list("{table}")').fetchall():
            if not bool(row["unique"]):
                continue
            name = str(row["name"]).replace('"', '""')
            columns = tuple(
                str(item["name"])
                for item in self._connection.execute(
                    f'PRAGMA index_info("{name}")'
                ).fetchall()
            )
            result.add(columns)
        return result

    def _migrate_algorithm_feature_schema(self) -> None:
        """Upgrade pre-V2 feature tables without rewriting evidence payloads."""

        columns = [
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(analysis_feature_windows)"
            ).fetchall()
        ]
        expected_unique = (
            "run_id",
            "feature_code",
            "source_key",
            "feature_version",
        )
        if (
            "feature_version" in columns
            and expected_unique
            in self._unique_index_columns("analysis_feature_windows")
        ):
            return

        rows = self._connection.execute(
            "SELECT * FROM analysis_feature_windows ORDER BY rowid"
        ).fetchall()
        self._connection.execute("DROP TABLE IF EXISTS analysis_feature_windows_v21")
        extras = [
            column
            for column in columns
            if column
            not in {
                "feature_id",
                "run_id",
                "batch_id",
                "mine_id",
                "observed_at",
                "feature_code",
                "source_key",
                "feature_version",
                "value",
                "quality_score",
                "feature_sha256",
                "feature_json",
                "created_at",
            }
        ]
        extra_definitions = "".join(
            f', "{column.replace(chr(34), chr(34) * 2)}" BLOB' for column in extras
        )
        self._connection.execute(
            f"""
            CREATE TABLE analysis_feature_windows_v21 (
                feature_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES analysis_runs(run_id),
                batch_id TEXT NOT NULL REFERENCES batches(batch_id),
                mine_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                feature_code TEXT NOT NULL,
                source_key TEXT NOT NULL,
                feature_version TEXT NOT NULL,
                value REAL NOT NULL,
                quality_score REAL,
                feature_sha256 TEXT NOT NULL,
                feature_json TEXT NOT NULL,
                created_at TEXT NOT NULL
                {extra_definitions},
                UNIQUE(run_id, feature_code, source_key, feature_version)
            )
            """
        )
        seen_keys: set[tuple[str, str, str, str]] = set()
        known_columns = set(columns)
        for position, row in enumerate(rows):
            raw_json = (
                str(row["feature_json"]) if "feature_json" in known_columns else "{}"
            )
            try:
                payload = json.loads(raw_json)
            except (TypeError, json.JSONDecodeError):
                payload = {}
            raw_version = (
                row["feature_version"] if "feature_version" in known_columns else None
            )
            version = (
                str(
                    raw_version
                    or (
                        payload.get("feature_version")
                        if isinstance(payload, dict)
                        else None
                    )
                    or "legacy"
                ).strip()
                or "legacy"
            )
            run_id = str(row["run_id"])
            feature_code = str(row["feature_code"])
            source_key = str(row["source_key"]) if "source_key" in known_columns else ""
            natural_key = (
                run_id,
                feature_code,
                source_key,
                version,
            )
            if natural_key in seen_keys:
                legacy_id = (
                    str(row["feature_id"])
                    if "feature_id" in known_columns
                    else str(position)
                )
                version = f"{version}+migrated.{_digest_text(legacy_id)[:8]}"
                natural_key = (
                    run_id,
                    feature_code,
                    source_key,
                    version,
                )
            seen_keys.add(natural_key)
            feature_id = (
                str(row["feature_id"])
                if "feature_id" in known_columns
                else _stable_id(
                    "feature",
                    run_id,
                    feature_code,
                    source_key,
                    version,
                )
            )
            standard_values: list[Any] = [
                feature_id,
                run_id,
                str(row["batch_id"]),
                str(row["mine_id"]),
                str(row["observed_at"]),
                feature_code,
                source_key,
                version,
                float(row["value"]),
                (row["quality_score"] if "quality_score" in known_columns else None),
                str(row["feature_sha256"]),
                raw_json,
                str(row["created_at"]),
            ]
            quoted_extras = ", ".join(
                f'"{column.replace(chr(34), chr(34) * 2)}"' for column in extras
            )
            column_suffix = f", {quoted_extras}" if quoted_extras else ""
            placeholders = ", ".join("?" for _ in standard_values + extras)
            self._connection.execute(
                f"""
                INSERT INTO analysis_feature_windows_v21 (
                    feature_id, run_id, batch_id, mine_id, observed_at,
                    feature_code, source_key, feature_version, value,
                    quality_score, feature_sha256, feature_json, created_at
                    {column_suffix}
                ) VALUES ({placeholders})
                """,
                (*standard_values, *(row[column] for column in extras)),
            )

        self._connection.execute("DROP INDEX IF EXISTS idx_feature_series_time")
        self._connection.execute("DROP TABLE analysis_feature_windows")
        self._connection.execute(
            "ALTER TABLE analysis_feature_windows_v21 "
            "RENAME TO analysis_feature_windows"
        )
        self._connection.execute(
            """
            CREATE INDEX idx_feature_series_time
            ON analysis_feature_windows(
                mine_id, feature_code, source_key, observed_at
            )
            """
        )

    def _migrate_alert_episode_schema(self) -> None:
        """Add detector versions to legacy episode natural keys."""

        columns = [
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(alert_episodes)"
            ).fetchall()
        ]
        expected_unique = (
            "mine_id",
            "feature_code",
            "source_key",
            "detector_code",
            "detector_version",
            "started_at",
        )
        if (
            "detector_version" in columns
            and expected_unique in self._unique_index_columns("alert_episodes")
        ):
            return

        rows = self._connection.execute(
            "SELECT * FROM alert_episodes ORDER BY rowid"
        ).fetchall()
        self._connection.execute("DROP TABLE IF EXISTS alert_episodes_v21")
        self._connection.execute(
            """
            CREATE TABLE alert_episodes_v21 (
                episode_id TEXT PRIMARY KEY,
                mine_id TEXT NOT NULL,
                feature_code TEXT NOT NULL,
                source_key TEXT NOT NULL,
                detector_code TEXT NOT NULL,
                detector_version TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT NOT NULL,
                peak_score REAL,
                finding_count INTEGER NOT NULL,
                episode_sha256 TEXT NOT NULL,
                episode_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(
                    mine_id, feature_code, source_key, detector_code,
                    detector_version, started_at
                )
            )
            """
        )
        known_columns = set(columns)
        seen_keys: set[tuple[str, str, str, str, str, str]] = set()
        for position, row in enumerate(rows):
            raw_json = str(row["episode_json"])
            try:
                payload = json.loads(raw_json)
            except (TypeError, json.JSONDecodeError):
                payload = {}
            raw_version = (
                row["detector_version"] if "detector_version" in known_columns else None
            )
            version = (
                str(
                    raw_version
                    or (
                        payload.get("detector_version")
                        if isinstance(payload, dict)
                        else None
                    )
                    or "legacy"
                ).strip()
                or "legacy"
            )
            values = (
                str(row["mine_id"]),
                str(row["feature_code"]),
                str(row["source_key"]),
                str(row["detector_code"]),
                version,
                str(row["started_at"]),
            )
            if values in seen_keys:
                old_id = str(row["episode_id"] or position)
                version = f"{version}+migrated.{_digest_text(old_id)[:8]}"
                values = (*values[:4], version, values[5])
            seen_keys.add(values)
            self._connection.execute(
                """
                INSERT INTO alert_episodes_v21 (
                    episode_id, mine_id, feature_code, source_key,
                    detector_code, detector_version, started_at, ended_at,
                    peak_score, finding_count, episode_sha256, episode_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(row["episode_id"]),
                    *values,
                    str(row["ended_at"]),
                    row["peak_score"],
                    int(row["finding_count"]),
                    str(row["episode_sha256"]),
                    raw_json,
                    str(row["created_at"]),
                ),
            )
        self._connection.execute("DROP INDEX IF EXISTS idx_alert_episode_mine_time")
        self._connection.execute("DROP TABLE alert_episodes")
        self._connection.execute(
            "ALTER TABLE alert_episodes_v21 RENAME TO alert_episodes"
            )

    @staticmethod
    def _batch_lifecycle_state(row: sqlite3.Row) -> dict[str, Any]:
        invalidated_at = row["invalidated_at"]
        return {
            "batch_id": str(row["batch_id"]),
            "active": invalidated_at is None,
            "version": int(row["lifecycle_version"]),
            "invalidated_at": invalidated_at,
            "invalidated_by": row["invalidated_by"],
            "reason": row["invalidation_reason"],
        }

    def _backfill_batch_lifecycle_events(self) -> None:
        """Register pre-lifecycle batches without changing their evidence."""

        rows = self._connection.execute(
            """
            SELECT batches.*
            FROM batches
            LEFT JOIN batch_lifecycle_events USING (batch_id)
            WHERE batch_lifecycle_events.batch_id IS NULL
            ORDER BY batches.created_at, batches.batch_id
            """
        ).fetchall()
        for row in rows:
            self._append_batch_lifecycle_event(
                batch_id=str(row["batch_id"]),
                action="created",
                actor="system:migration",
                reason="legacy_batch_registered",
                before=None,
                after=self._batch_lifecycle_state(row),
                created_at=str(row["created_at"]),
            )

    def _append_batch_lifecycle_event(
        self,
        *,
        batch_id: str,
        action: str,
        actor: str,
        reason: str | None,
        before: dict[str, Any] | None,
        after: dict[str, Any],
        created_at: str,
    ) -> None:
        prior = self._connection.execute(
            """
            SELECT sequence, event_hash
            FROM batch_lifecycle_events
            WHERE batch_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (batch_id,),
        ).fetchone()
        sequence = 1 if prior is None else int(prior["sequence"]) + 1
        previous_hash = "" if prior is None else str(prior["event_hash"])
        payload = {
            "batch_id": batch_id,
            "sequence": sequence,
            "action": action,
            "actor": actor,
            "reason": reason,
            "before": before,
            "after": after,
            "previous_hash": previous_hash,
            "created_at": created_at,
        }
        event_hash = sha256_json(payload)
        self._connection.execute(
            """
            INSERT INTO batch_lifecycle_events (
                batch_id, sequence, action, actor, reason, before_json,
                after_json, previous_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                batch_id,
                sequence,
                action,
                actor,
                reason,
                canonical_json(before) if before is not None else None,
                canonical_json(after),
                previous_hash,
                event_hash,
                created_at,
            ),
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @contextmanager
    def read_snapshot(self) -> Iterator[None]:
        """Hold the repository read boundary across a derived decision.

        All repository mutations use the same re-entrant lock, so callers can
        materialize labels, runs, scenarios and their hashes as one
        single-process snapshot.  This is not a substitute for an external
        database transaction across multiple service instances.
        """

        with self._lock:
            yield

    def claim_external_request_nonce(
        self,
        *,
        client_id: str,
        nonce: str,
        request_timestamp: str,
        expires_at: str,
    ) -> bool:
        """Atomically claim a signed-request nonce.

        ``False`` means the same client already used the nonce. Expired rows
        are housekeeping only; request timestamp validation happens before
        this persistence boundary.
        """

        normalized_client = _bounded_text(
            client_id,
            "client_id",
            maximum=_SHORT_ID_LIMIT,
        )
        normalized_nonce = _bounded_text(
            nonce,
            "nonce",
            maximum=_SHORT_ID_LIMIT,
        )
        normalized_request_time = _timestamp(
            request_timestamp,
            "request_timestamp",
        )
        normalized_expiry = _timestamp(expires_at, "expires_at")
        assert normalized_client is not None
        assert normalized_nonce is not None
        assert normalized_request_time is not None
        assert normalized_expiry is not None
        created_at = _now()
        with self._lock, self._connection:
            self._connection.execute(
                "DELETE FROM external_request_nonces WHERE expires_at < ?",
                (created_at,),
            )
            try:
                self._connection.execute(
                    """
                    INSERT INTO external_request_nonces (
                        client_id, nonce, request_timestamp, expires_at,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_client,
                        normalized_nonce,
                        normalized_request_time,
                        normalized_expiry,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    @staticmethod
    def _external_event_snapshot_row(
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        try:
            content = json.loads(row["content_json"])
            event_codes = json.loads(row["event_codes_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise AlgorithmRecordIntegrityError(
                "stored external event snapshot is not valid JSON"
            ) from error
        if not isinstance(content, dict) or not isinstance(event_codes, list):
            raise AlgorithmRecordIntegrityError(
                "stored external event snapshot has invalid content"
            )
        columns_match = (
            content.get("snapshot_id") == str(row["snapshot_id"])
            and content.get("mine_id") == str(row["mine_id"])
            and content.get("window_start") == str(row["window_start"])
            and content.get("window_end") == str(row["window_end"])
            and content.get("event_codes") == event_codes
            and content.get("evidence_sha256")
            == str(row["evidence_sha256"])
            and content.get("source_system") == str(row["source_system"])
            and content.get("record_id") == str(row["record_id"])
            and content.get("created_by") == str(row["created_by"])
            and canonical_json(content) == str(row["content_json"])
        )
        hash_valid = bool(
            columns_match
            and sha256_json(content) == str(row["content_sha256"])
        )
        return {
            **content,
            "content_sha256": str(row["content_sha256"]),
            "created_at": str(row["created_at"]),
            "hash_valid": hash_valid,
        }

    def save_external_event_snapshot(
        self,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        """Store one immutable query snapshot; exact retries are idempotent."""

        content = _normalize_external_event_snapshot(snapshot)
        content_json = canonical_json(content)
        content_sha256 = sha256_json(content)
        created_at = _now()
        with self._lock, self._connection:
            existing = self._connection.execute(
                """
                SELECT *
                FROM external_event_snapshots
                WHERE snapshot_id = ?
                """,
                (content["snapshot_id"],),
            ).fetchone()
            if existing is not None:
                stored = self._external_event_snapshot_row(existing)
                if not stored["hash_valid"]:
                    raise AlgorithmRecordIntegrityError(
                        "stored external event snapshot failed "
                        "integrity validation"
                    )
                if (
                    existing["content_sha256"] == content_sha256
                    and existing["content_json"] == content_json
                ):
                    return {**stored, "created": False}
                raise ExternalEventSnapshotConflictError(
                    "snapshot_id already exists with different content"
                )
            try:
                self._connection.execute(
                    """
                    INSERT INTO external_event_snapshots (
                        snapshot_id, mine_id, window_start, window_end,
                        event_codes_json, evidence_sha256, source_system,
                        record_id, created_by, content_sha256, content_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        content["snapshot_id"],
                        content["mine_id"],
                        content["window_start"],
                        content["window_end"],
                        canonical_json(content["event_codes"]),
                        content["evidence_sha256"],
                        content["source_system"],
                        content["record_id"],
                        content["created_by"],
                        content_sha256,
                        content_json,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ExternalEventSnapshotConflictError(
                    "external event snapshot changed during immutable insert"
                ) from error
            row = self._connection.execute(
                """
                SELECT *
                FROM external_event_snapshots
                WHERE snapshot_id = ?
                """,
                (content["snapshot_id"],),
            ).fetchone()
            assert row is not None
            stored = self._external_event_snapshot_row(row)
        return {**stored, "created": True}

    def list_external_event_snapshots(
        self,
        *,
        limit: int = 1_000,
    ) -> list[dict[str, Any]]:
        normalized_limit = _integer(limit, "limit", minimum=1)
        if normalized_limit > 10_000:
            raise ValueError("limit must not exceed 10000")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT *
                FROM external_event_snapshots
                ORDER BY created_at DESC, snapshot_id
                LIMIT ?
                """,
                (normalized_limit,),
            ).fetchall()
        return [self._external_event_snapshot_row(row) for row in rows]

    def find_external_event_snapshot(
        self,
        *,
        mine_id: str,
        window_start: Any,
        window_end: Any,
        event_codes: list[str],
        evidence_sha256: set[str],
    ) -> dict[str, Any] | None:
        """Find an integrity-valid exact result for one enterprise report."""

        normalized_mine_id = _bounded_text(
            mine_id,
            "mine_id",
            maximum=_SHORT_ID_LIMIT,
        )
        normalized_start = _timestamp(window_start, "window_start")
        normalized_end = _timestamp(window_end, "window_end")
        assert normalized_mine_id is not None
        assert normalized_start is not None
        assert normalized_end is not None
        if normalized_start >= normalized_end:
            raise ValueError("window_start must be earlier than window_end")
        if not isinstance(event_codes, list):
            raise ValueError("event_codes must be an array")
        normalized_codes: list[str] = []
        for index, code in enumerate(event_codes):
            normalized = _bounded_text(
                code,
                f"event_codes[{index}]",
                maximum=64,
            )
            assert normalized is not None
            normalized_codes.append(normalized)
        if len(normalized_codes) != len(set(normalized_codes)):
            raise ValueError("event_codes values must be unique")
        if (
            not isinstance(evidence_sha256, set)
            or not evidence_sha256
            or any(
                not isinstance(digest, str)
                or len(digest) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in digest
                )
                for digest in evidence_sha256
            )
        ):
            raise ValueError(
                "evidence_sha256 must contain lowercase SHA-256 hex digests"
            )
        codes_json = canonical_json(sorted(normalized_codes))
        placeholders = ",".join("?" for _ in evidence_sha256)
        parameters = [
            normalized_mine_id,
            normalized_start,
            normalized_end,
            codes_json,
            *sorted(evidence_sha256),
        ]
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT *
                FROM external_event_snapshots
                WHERE mine_id = ?
                  AND window_start = ?
                  AND window_end = ?
                  AND event_codes_json = ?
                  AND evidence_sha256 IN ({placeholders})
                ORDER BY created_at, snapshot_id
                """,
                parameters,
            ).fetchall()
        for row in rows:
            stored = self._external_event_snapshot_row(row)
            if not stored["hash_valid"]:
                raise AlgorithmRecordIntegrityError(
                    "stored external event snapshot failed "
                    "integrity validation"
                )
            return stored
        return None

    def _external_confirmer_registration_row(
        self,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        try:
            content = json.loads(row["content_json"])
            confirmer_roles = json.loads(row["confirmer_roles_json"])
            confirmation_methods = json.loads(
                row["confirmation_methods_json"]
            )
            columns_match = (
                isinstance(content, dict)
                and isinstance(confirmer_roles, list)
                and isinstance(confirmation_methods, list)
                and content.get("registration_id")
                == str(row["registration_id"])
                and content.get("client_id") == str(row["client_id"])
                and content.get("enterprise_id")
                == str(row["enterprise_id"])
                and content.get("confirmer_id")
                == str(row["confirmer_id"])
                and content.get("version") == int(row["version"])
                and content.get("confirmer_name")
                == str(row["confirmer_name"])
                and content.get("confirmer_roles") == confirmer_roles
                and content.get("confirmation_methods")
                == confirmation_methods
                and content.get("active") is bool(row["active"])
                and content.get("source_system")
                == str(row["source_system"])
                and content.get("record_id") == str(row["record_id"])
                and content.get("created_by") == str(row["created_by"])
                and canonical_json(content) == str(row["content_json"])
            )
            hash_valid = bool(
                int(row["active"]) in {0, 1}
                and columns_match
                and sha256_json(content) == str(row["content_sha256"])
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            content = {
                "registration_id": str(row["registration_id"]),
                "client_id": str(row["client_id"]),
                "enterprise_id": str(row["enterprise_id"]),
                "confirmer_id": str(row["confirmer_id"]),
                "version": int(row["version"]),
                "confirmer_name": str(row["confirmer_name"]),
                "confirmer_roles": [],
                "confirmation_methods": [],
                "active": bool(row["active"]),
                "source_system": str(row["source_system"]),
                "record_id": str(row["record_id"]),
                "created_by": str(row["created_by"]),
            }
            hash_valid = False

        previous_content_sha256 = ""
        version_chain_valid = int(row["version"]) == 1
        if int(row["version"]) > 1:
            previous = self._connection.execute(
                """
                SELECT *
                FROM external_confirmer_registrations
                WHERE client_id = ?
                  AND enterprise_id = ?
                  AND confirmer_id = ?
                  AND version = ?
                """,
                (
                    str(row["client_id"]),
                    str(row["enterprise_id"]),
                    str(row["confirmer_id"]),
                    int(row["version"]) - 1,
                ),
            ).fetchone()
            if previous is not None:
                previous_stored = (
                    self._external_confirmer_registration_row(previous)
                )
                previous_content_sha256 = str(
                    previous_stored["content_sha256"]
                )
                version_chain_valid = bool(
                    previous_stored["hash_valid"]
                    and previous_stored["version_chain_valid"]
                )
        hash_valid = bool(hash_valid and version_chain_valid)
        return {
            **content,
            "content_sha256": str(row["content_sha256"]),
            "previous_content_sha256": previous_content_sha256,
            "version_chain_valid": version_chain_valid,
            "created_at": str(row["created_at"]),
            "hash_valid": hash_valid,
        }

    def save_external_confirmer_registration(
        self,
        registration: dict[str, Any],
    ) -> dict[str, Any]:
        """Append one immutable confirmer version; exact retries are safe."""

        content = _normalize_external_confirmer_registration(registration)
        content_json = canonical_json(content)
        content_sha256 = sha256_json(content)
        created_at = _now()
        natural_key = (
            content["client_id"],
            content["enterprise_id"],
            content["confirmer_id"],
        )
        version_key = (*natural_key, content["version"])
        with self._lock, self._connection:
            existing_id = self._connection.execute(
                """
                SELECT *
                FROM external_confirmer_registrations
                WHERE registration_id = ?
                """,
                (content["registration_id"],),
            ).fetchone()
            if existing_id is not None:
                stored = self._external_confirmer_registration_row(
                    existing_id
                )
                if not stored["hash_valid"]:
                    raise AlgorithmRecordIntegrityError(
                        "stored external confirmer registration failed "
                        "integrity validation"
                    )
                if (
                    existing_id["content_sha256"] == content_sha256
                    and existing_id["content_json"] == content_json
                ):
                    return {**stored, "created": False}
                raise ExternalConfirmerRegistrationConflictError(
                    "registration_id already exists with different content"
                )

            existing_version = self._connection.execute(
                """
                SELECT *
                FROM external_confirmer_registrations
                WHERE client_id = ?
                  AND enterprise_id = ?
                  AND confirmer_id = ?
                  AND version = ?
                """,
                version_key,
            ).fetchone()
            if existing_version is not None:
                stored = self._external_confirmer_registration_row(
                    existing_version
                )
                if not stored["hash_valid"]:
                    raise AlgorithmRecordIntegrityError(
                        "stored external confirmer registration failed "
                        "integrity validation"
                    )
                raise ExternalConfirmerRegistrationConflictError(
                    "confirmer registration version already exists under "
                    "another registration_id"
                )

            latest = self._connection.execute(
                """
                SELECT *
                FROM external_confirmer_registrations
                WHERE client_id = ?
                  AND enterprise_id = ?
                  AND confirmer_id = ?
                ORDER BY version DESC
                LIMIT 1
                """,
                natural_key,
            ).fetchone()
            expected_version = (
                1 if latest is None else int(latest["version"]) + 1
            )
            if latest is not None:
                latest_stored = self._external_confirmer_registration_row(
                    latest
                )
                if not latest_stored["hash_valid"]:
                    raise AlgorithmRecordIntegrityError(
                        "latest external confirmer registration failed "
                        "integrity validation"
                    )
            if content["version"] != expected_version:
                raise ExternalConfirmerRegistrationConflictError(
                    "confirmer registration versions must be continuous; "
                    f"expected version {expected_version}"
                )

            try:
                self._connection.execute(
                    """
                    INSERT INTO external_confirmer_registrations (
                        registration_id, client_id, enterprise_id,
                        confirmer_id, version, confirmer_name,
                        confirmer_roles_json, confirmation_methods_json,
                        active, source_system, record_id, created_by,
                        content_sha256, content_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        content["registration_id"],
                        content["client_id"],
                        content["enterprise_id"],
                        content["confirmer_id"],
                        content["version"],
                        content["confirmer_name"],
                        canonical_json(content["confirmer_roles"]),
                        canonical_json(content["confirmation_methods"]),
                        int(content["active"]),
                        content["source_system"],
                        content["record_id"],
                        content["created_by"],
                        content_sha256,
                        content_json,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ExternalConfirmerRegistrationConflictError(
                    "confirmer registration changed during immutable insert"
                ) from error
            row = self._connection.execute(
                """
                SELECT *
                FROM external_confirmer_registrations
                WHERE registration_id = ?
                """,
                (content["registration_id"],),
            ).fetchone()
            assert row is not None
            stored = self._external_confirmer_registration_row(row)
        return {**stored, "created": True}

    def list_external_confirmer_registrations(
        self,
        *,
        client_id: str | None = None,
        enterprise_id: str | None = None,
        confirmer_id: str | None = None,
        limit: int = 1_000,
    ) -> list[dict[str, Any]]:
        """Return immutable versions, optionally narrowed by natural key."""

        normalized_limit = _integer(limit, "limit", minimum=1)
        if normalized_limit > 10_000:
            raise ValueError("limit must not exceed 10000")
        filters: list[str] = []
        parameters: list[Any] = []
        for field_name, value in (
            ("client_id", client_id),
            ("enterprise_id", enterprise_id),
            ("confirmer_id", confirmer_id),
        ):
            if value is None:
                continue
            normalized = _bounded_text(
                value,
                field_name,
                maximum=_SHORT_ID_LIMIT,
            )
            assert normalized is not None
            filters.append(f"{field_name} = ?")
            parameters.append(normalized)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        parameters.append(normalized_limit)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT *
                FROM external_confirmer_registrations
                """
                + where
                + """
                ORDER BY client_id, enterprise_id, confirmer_id,
                         version DESC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
            results = [
                self._external_confirmer_registration_row(row)
                for row in rows
            ]
        if any(not item["hash_valid"] for item in results):
            raise AlgorithmRecordIntegrityError(
                "stored external confirmer registration failed "
                "integrity validation"
            )
        return results

    def find_current_external_confirmer_registration(
        self,
        *,
        client_id: str,
        enterprise_id: str,
        confirmer_id: str,
        confirmer_name: str,
        confirmer_role: str,
        confirmation_method: str,
    ) -> dict[str, Any] | None:
        """Match the exact identity against the latest regulator version."""

        normalized_values: dict[str, str] = {}
        for field_name, value in (
            ("client_id", client_id),
            ("enterprise_id", enterprise_id),
            ("confirmer_id", confirmer_id),
            ("confirmer_name", confirmer_name),
            ("confirmer_role", confirmer_role),
            ("confirmation_method", confirmation_method),
        ):
            normalized = _bounded_text(
                value,
                field_name,
                maximum=_SHORT_ID_LIMIT,
            )
            assert normalized is not None
            normalized_values[field_name] = normalized
        with self._lock:
            row = self._connection.execute(
                """
                SELECT *
                FROM external_confirmer_registrations
                WHERE client_id = ?
                  AND enterprise_id = ?
                  AND confirmer_id = ?
                ORDER BY version DESC
                LIMIT 1
                """,
                (
                    normalized_values["client_id"],
                    normalized_values["enterprise_id"],
                    normalized_values["confirmer_id"],
                ),
            ).fetchone()
            if row is None:
                return None
            stored = self._external_confirmer_registration_row(row)
        if not stored["hash_valid"]:
            raise AlgorithmRecordIntegrityError(
                "stored external confirmer registration failed "
                "integrity validation"
            )
        if (
            not stored["active"]
            or stored["confirmer_name"]
            != normalized_values["confirmer_name"]
            or normalized_values["confirmer_role"]
            not in stored["confirmer_roles"]
            or normalized_values["confirmation_method"]
            not in stored["confirmation_methods"]
        ):
            return None
        return stored

    @staticmethod
    def _external_receipt_row(row: sqlite3.Row) -> dict[str, Any]:
        try:
            receipt = json.loads(row["receipt_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise AlgorithmRecordIntegrityError(
                "stored external receipt is not valid JSON"
            ) from error
        if sha256_json(receipt) != str(row["receipt_sha256"]):
            raise AlgorithmRecordIntegrityError(
                "stored external receipt failed integrity validation"
            )
        result = {
            "submission_id": str(row["submission_id"]),
            "client_id": str(row["client_id"]),
            "enterprise_id": str(row["enterprise_id"]),
            "mine_id": str(row["mine_id"]),
            "idempotency_key": str(row["idempotency_key"]),
            "payload_sha256": str(row["payload_sha256"]),
            "receipt": receipt,
            "receipt_sha256": str(row["receipt_sha256"]),
            "created_at": str(row["created_at"]),
        }
        body = row["submission_body"]
        body_sha256 = row["body_sha256"]
        if body is not None or body_sha256 is not None:
            if not isinstance(body, bytes) or not isinstance(
                body_sha256,
                str,
            ):
                raise AlgorithmRecordIntegrityError(
                    "stored external submission is incomplete"
                )
            if hashlib.sha256(body).hexdigest() != body_sha256:
                raise AlgorithmRecordIntegrityError(
                    "stored external submission failed integrity validation"
                )
            try:
                submission = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise AlgorithmRecordIntegrityError(
                    "stored external submission is not valid JSON"
                ) from error
            if not isinstance(submission, dict):
                raise AlgorithmRecordIntegrityError(
                    "stored external submission is not a JSON object"
                )
            result["body_sha256"] = body_sha256
            result["submission"] = submission
        return result

    def get_external_submission_receipt(
        self,
        *,
        client_id: str,
        idempotency_key: str,
    ) -> dict[str, Any] | None:
        normalized_client = _bounded_text(
            client_id,
            "client_id",
            maximum=_SHORT_ID_LIMIT,
        )
        normalized_key = _bounded_text(
            idempotency_key,
            "idempotency_key",
            maximum=_SHORT_ID_LIMIT,
        )
        assert normalized_client is not None
        assert normalized_key is not None
        with self._lock:
            row = self._connection.execute(
                """
                SELECT *
                FROM external_submission_receipts
                WHERE client_id = ? AND idempotency_key = ?
                """,
                (normalized_client, normalized_key),
            ).fetchone()
        return None if row is None else self._external_receipt_row(row)

    def get_external_submission_receipt_by_submission_id(
        self,
        *,
        client_id: str,
        submission_id: str,
    ) -> dict[str, Any] | None:
        normalized_client = _bounded_text(
            client_id,
            "client_id",
            maximum=_SHORT_ID_LIMIT,
        )
        normalized_submission = _bounded_text(
            submission_id,
            "submission_id",
            maximum=_SHORT_ID_LIMIT,
        )
        assert normalized_client is not None
        assert normalized_submission is not None
        with self._lock:
            row = self._connection.execute(
                """
                SELECT *
                FROM external_submission_receipts
                WHERE client_id = ? AND submission_id = ?
                """,
                (normalized_client, normalized_submission),
            ).fetchone()
        return None if row is None else self._external_receipt_row(row)

    def save_external_submission_receipt(
        self,
        *,
        submission_id: str,
        client_id: str,
        enterprise_id: str,
        mine_id: str,
        idempotency_key: str,
        payload_sha256: str,
        receipt: dict[str, Any],
        submission_body: bytes | None = None,
    ) -> dict[str, Any]:
        normalized = {
            name: _bounded_text(
                value,
                name,
                maximum=_SHORT_ID_LIMIT,
            )
            for name, value in (
                ("submission_id", submission_id),
                ("client_id", client_id),
                ("enterprise_id", enterprise_id),
                ("mine_id", mine_id),
                ("idempotency_key", idempotency_key),
            )
        }
        digest = _bounded_text(
            payload_sha256,
            "payload_sha256",
            maximum=64,
        )
        if (
            digest is None
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("payload_sha256 must be lowercase SHA-256 hex")
        receipt_document = _json_value(receipt)
        if not isinstance(receipt_document, dict):
            raise ValueError("receipt must be an object")
        body_sha256: str | None = None
        if submission_body is not None:
            if not isinstance(submission_body, bytes):
                raise ValueError("submission_body must be bytes")
            try:
                submission_document = json.loads(submission_body)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError(
                    "submission_body must contain valid JSON"
                ) from error
            if not isinstance(submission_document, dict):
                raise ValueError(
                    "submission_body must contain a JSON object"
                )
            body_sha256 = hashlib.sha256(submission_body).hexdigest()
        receipt_sha256 = sha256_json(receipt_document)
        created_at = _now()
        with self._lock, self._connection:
            existing = self._connection.execute(
                """
                SELECT *
                FROM external_submission_receipts
                WHERE client_id = ? AND idempotency_key = ?
                """,
                (normalized["client_id"], normalized["idempotency_key"]),
            ).fetchone()
            if existing is not None:
                stored = self._external_receipt_row(existing)
                if (
                    stored["submission_id"] == normalized["submission_id"]
                    and stored["payload_sha256"] == digest
                    and (
                        submission_body is None
                        or stored.get("body_sha256") == body_sha256
                    )
                ):
                    return {**stored, "created": False}
                raise ExternalSubmissionConflictError(
                    "external idempotency key already has different content"
                )
            try:
                self._connection.execute(
                    """
                    INSERT INTO external_submission_receipts (
                        submission_id, client_id, enterprise_id, mine_id,
                        idempotency_key, payload_sha256, body_sha256,
                        submission_body, receipt_sha256, receipt_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized["submission_id"],
                        normalized["client_id"],
                        normalized["enterprise_id"],
                        normalized["mine_id"],
                        normalized["idempotency_key"],
                        digest,
                        body_sha256,
                        submission_body,
                        receipt_sha256,
                        canonical_json(receipt_document),
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ExternalSubmissionConflictError(
                    "external submission identifier already exists"
                ) from error
            row = self._connection.execute(
                """
                SELECT *
                FROM external_submission_receipts
                WHERE submission_id = ?
                """,
                (normalized["submission_id"],),
            ).fetchone()
            assert row is not None
            stored = self._external_receipt_row(row)
        return {**stored, "created": True}

    def save_portfolio_batch(
        self,
        request_obj: Any,
        response_obj: Any,
        engine_version: str,
        *,
        context_obj: Any | None = None,
        created_at: str | datetime | None = None,
    ) -> dict[str, Any]:
        """Atomically persist one idempotent batch, its runs and review cases."""

        request = _json_value(request_obj)
        response = _json_value(response_obj)
        batch_id = str(request["batch_id"])
        request_hash = sha256_json(request)
        context = _json_value(context_obj) if context_obj is not None else None
        response_hash = sha256_json(response)
        context_hash = sha256_json(context)
        created_at_text = (
            _now()
            if created_at is None
            else _timestamp(created_at, "created_at")
        )
        assert created_at_text is not None

        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT * FROM batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if existing is not None:
                if existing["request_sha256"] != request_hash:
                    raise BatchConflictError(
                        "batch_id already exists with different input"
                    )
                stored_response = json.loads(existing["response_json"])
                stored_context = (
                    json.loads(existing["context_json"])
                    if existing["context_json"] is not None
                    else None
                )
                if (
                    existing["response_sha256"] is None
                    or sha256_json(stored_response)
                    != str(existing["response_sha256"])
                    or existing["context_sha256"] is None
                    or sha256_json(stored_context)
                    != str(existing["context_sha256"])
                ):
                    raise AlgorithmRecordIntegrityError(
                        "stored batch response or context hash verification "
                        "failed"
                    )
                return {
                    "created": False,
                    "batch": stored_response,
                }

            self._connection.execute(
                """
                INSERT INTO batches (
                    batch_id, portfolio_name, request_sha256, request_json,
                    response_sha256, response_json, context_sha256,
                    context_json, integrity_origin, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    batch_id,
                    str(request["portfolio_name"]),
                    request_hash,
                    canonical_json(request),
                    response_hash,
                    canonical_json(response),
                    context_hash,
                    canonical_json(context) if context is not None else None,
                    "created",
                    created_at_text,
                ),
            )
            created_row = self._connection.execute(
                "SELECT * FROM batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            assert created_row is not None
            self._append_batch_lifecycle_event(
                batch_id=batch_id,
                action="created",
                actor="system",
                reason=None,
                before=None,
                after=self._batch_lifecycle_state(created_row),
                created_at=created_at_text,
            )

            inputs_by_mine = {
                str(item["mine_id"]): item for item in request.get("analyses", [])
            }
            for item in response.get("items", []):
                mine_id = str(item["mine_id"])
                input_snapshot = inputs_by_mine.get(mine_id)
                run_id: str | None = None
                if input_snapshot is not None:
                    analysis_result = item.get("analysis")
                    if analysis_result is None:
                        analysis_result = {
                            "mine_id": mine_id,
                            "status": item["technical_status"],
                        }
                    input_hash = sha256_json(input_snapshot)
                    result_hash = sha256_json(analysis_result)
                    run_id = _stable_id(
                        "run",
                        batch_id,
                        mine_id,
                        input_hash,
                        result_hash,
                        engine_version,
                    )
                    self._connection.execute(
                        """
                        INSERT INTO analysis_runs (
                            run_id, batch_id, mine_id, technical_status,
                            input_sha256, input_json, result_sha256,
                            result_json, engine_version, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            batch_id,
                            mine_id,
                            str(item["technical_status"]),
                            input_hash,
                            canonical_json(input_snapshot),
                            result_hash,
                            canonical_json(analysis_result),
                            engine_version,
                            created_at_text,
                        ),
                    )
                    self._insert_algorithm_features(
                        run_id=run_id,
                        batch_id=batch_id,
                        mine_id=mine_id,
                        input_snapshot=input_snapshot,
                        analysis_result=analysis_result,
                        context_snapshot=context,
                        engine_version=engine_version,
                        created_at=created_at_text,
                    )

                if item.get("review_priority") == "NONE":
                    continue
                self._insert_case(
                    batch_id=batch_id,
                    item=item,
                    run_id=run_id,
                    created_at=created_at_text,
                )

        return {"created": True, "batch": response}

    def _backfill_algorithm_features(self) -> None:
        rows = self._connection.execute(
            """
            SELECT analysis_runs.run_id, analysis_runs.batch_id,
                   analysis_runs.mine_id, analysis_runs.input_json,
                   analysis_runs.result_json, analysis_runs.created_at,
                   analysis_runs.engine_version,
                   analysis_runs.input_sha256,
                   analysis_runs.result_sha256,
                   batches.context_json
            FROM analysis_runs
            JOIN batches USING (batch_id)
            ORDER BY analysis_runs.created_at, analysis_runs.run_id
            """
        ).fetchall()
        for row in rows:
            try:
                input_snapshot = json.loads(row["input_json"])
                analysis_result = json.loads(row["result_json"])
            except (TypeError, json.JSONDecodeError):
                # Hash verification remains visible through get_run(); never
                # derive fresh algorithm evidence from a damaged snapshot.
                continue
            if sha256_json(input_snapshot) != str(row["input_sha256"]) or sha256_json(
                analysis_result
            ) != str(row["result_sha256"]):
                continue
            self._insert_algorithm_features(
                run_id=str(row["run_id"]),
                batch_id=str(row["batch_id"]),
                mine_id=str(row["mine_id"]),
                input_snapshot=input_snapshot,
                analysis_result=analysis_result,
                context_snapshot=(
                    json.loads(row["context_json"])
                    if row["context_json"] is not None
                    else None
                ),
                engine_version=str(row["engine_version"]),
                created_at=str(row["created_at"]),
            )

    def _insert_algorithm_features(
        self,
        *,
        run_id: str,
        batch_id: str,
        mine_id: str,
        input_snapshot: dict[str, Any],
        analysis_result: dict[str, Any],
        context_snapshot: dict[str, Any] | None,
        engine_version: str,
        created_at: str,
    ) -> None:
        observed_at = _timestamp(
            input_snapshot.get("window_end")
            or input_snapshot.get("window_start")
            or created_at,
            "observed_at",
        )
        assert observed_at is not None
        quality = analysis_result.get("data_quality") or {}
        raw_quality = quality.get("score")
        quality_score = (
            min(1.0, max(0.0, float(raw_quality) / 100.0))
            if isinstance(raw_quality, (int, float))
            else None
        )
        governance_identity = _algorithm_governance_compatibility(
            context_snapshot,
            mine_id,
        )
        compatibility = build_algorithm_feature_compatibility(
            input_snapshot,
            engine_version=engine_version,
            **governance_identity,
        )
        compatibility_key = algorithm_feature_compatibility_key(compatibility)
        candidates: list[tuple[str, str, float, dict[str, Any]]] = []

        for result_key, feature_code in (
            ("raw_anomaly_statistic", "balance.raw_anomaly"),
            ("minimum_reported_gap", "balance.minimum_reported_gap_t"),
            (
                "robust_minimum_reported_gap",
                "balance.robust_minimum_reported_gap_t",
            ),
        ):
            raw_value = analysis_result.get(result_key)
            if isinstance(raw_value, (int, float)) and not isinstance(
                raw_value,
                bool,
            ):
                candidates.append(
                    (
                        feature_code,
                        "",
                        float(raw_value),
                        {
                            "result_field": result_key,
                            "technical_status": analysis_result.get("status"),
                        },
                    )
                )

        metrics = analysis_result.get("reconciled_metrics") or {}
        if isinstance(metrics, dict):
            for metric_code, metric in sorted(metrics.items()):
                if not isinstance(metric, dict):
                    continue
                raw_value = metric.get("normalized_residual")
                if isinstance(raw_value, (int, float)) and not isinstance(
                    raw_value,
                    bool,
                ):
                    candidates.append(
                        (
                            "residual.normalized",
                            str(metric_code),
                            float(raw_value),
                            {
                                "metric_code": str(metric_code),
                                "inferred_value": metric.get("inferred_value"),
                            },
                        )
                    )

        raw_adjustments = analysis_result.get("observation_adjustments") or []
        if isinstance(raw_adjustments, dict):
            adjustments = list(raw_adjustments.values())
        elif isinstance(raw_adjustments, list):
            adjustments = raw_adjustments
        else:
            adjustments = []
        adjustment_groups: dict[
            tuple[str, str],
            list[dict[str, Any]],
        ] = {}
        for adjustment in adjustments:
            if not isinstance(adjustment, dict):
                continue
            raw_value = adjustment.get("normalized_residual")
            if not isinstance(raw_value, (int, float)) or isinstance(
                raw_value,
                bool,
            ):
                continue
            source_group = str(adjustment.get("source_group") or "")
            metric_code = str(adjustment.get("metric_code") or "")
            adjustment_groups.setdefault(
                (source_group, metric_code),
                [],
            ).append(adjustment)
        for (source_group, metric_code), grouped in sorted(adjustment_groups.items()):
            representative = max(
                grouped,
                key=lambda item: (
                    float(item["normalized_residual"]),
                    str(item.get("observation_id") or ""),
                ),
            )
            magnitude = float(representative["normalized_residual"])
            signed_adjustment = representative.get("signed_adjustment")
            signed_value = (
                -magnitude
                if isinstance(signed_adjustment, (int, float)) and signed_adjustment < 0
                else magnitude
            )
            source_key = "|".join(part for part in (source_group, metric_code) if part)
            candidates.append(
                (
                    "source.signed_normalized_residual",
                    source_key,
                    signed_value,
                    {
                        "source_group": source_group,
                        "metric_code": metric_code,
                        "representative_observation_id": (
                            representative.get("observation_id")
                        ),
                        "observation_count": len(grouped),
                        "adjustments": grouped,
                    },
                )
            )

        for feature_code, source_key, value, details in candidates:
            feature_id = _stable_id(
                "feature",
                run_id,
                feature_code,
                source_key,
                ALGORITHM_FEATURE_VERSION,
            )
            id_owner = self._connection.execute(
                """
                SELECT run_id, feature_code, source_key, feature_version
                FROM analysis_feature_windows
                WHERE feature_id = ?
                """,
                (feature_id,),
            ).fetchone()
            expected_key = (
                run_id,
                feature_code,
                source_key,
                ALGORITHM_FEATURE_VERSION,
            )
            if id_owner is not None and tuple(id_owner) != expected_key:
                # Pre-version schemas may already own the legacy stable id.
                # A deterministic suffix preserves that row and still permits
                # the current extractor version to be backfilled.
                feature_id = _stable_id(
                    "feature",
                    *expected_key,
                    "versioned-schema",
                )
            document = {
                "run_id": run_id,
                "batch_id": batch_id,
                "mine_id": mine_id,
                "observed_at": observed_at,
                "feature_code": feature_code,
                "source_key": source_key,
                "feature_version": ALGORITHM_FEATURE_VERSION,
                "value": value,
                "quality_score": quality_score,
                "compatibility": compatibility,
                "compatibility_key": compatibility_key,
                "authority_order": _algorithm_feature_authority(
                    input_snapshot=input_snapshot,
                    context_snapshot=context_snapshot,
                    mine_id=mine_id,
                    created_at=created_at,
                    feature_id=feature_id,
                ),
                "details": details,
            }
            digest = sha256_json(document)
            document_json = canonical_json(document)
            existing = self._connection.execute(
                """
                SELECT feature_id, feature_sha256, feature_json
                FROM analysis_feature_windows
                WHERE run_id = ? AND feature_code = ?
                  AND source_key = ? AND feature_version = ?
                """,
                expected_key,
            ).fetchone()
            if existing is not None:
                self._validate_immutable_retry(
                    existing,
                    digest_column="feature_sha256",
                    json_column="feature_json",
                    expected_digest=digest,
                    expected_json=document_json,
                    legacy_json=document_json,
                    record_label="algorithm feature",
                )
                continue

            id_collision = self._connection.execute(
                """
                SELECT feature_sha256, feature_json
                FROM analysis_feature_windows
                WHERE feature_id = ?
                """,
                (feature_id,),
            ).fetchone()
            if id_collision is not None:
                self._validate_immutable_retry(
                    id_collision,
                    digest_column="feature_sha256",
                    json_column="feature_json",
                    expected_digest=digest,
                    expected_json=document_json,
                    legacy_json=document_json,
                    record_label="algorithm feature id",
                )
                raise AlgorithmRecordIntegrityError(
                    "algorithm feature id exists under different key columns"
                )

            try:
                self._connection.execute(
                    """
                    INSERT INTO analysis_feature_windows (
                        feature_id, run_id, batch_id, mine_id, observed_at,
                        feature_code, source_key, feature_version, value,
                        quality_score,
                        feature_sha256, feature_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        feature_id,
                        run_id,
                        batch_id,
                        mine_id,
                        observed_at,
                        feature_code,
                        source_key,
                        ALGORITHM_FEATURE_VERSION,
                        value,
                        quality_score,
                        digest,
                        document_json,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise AlgorithmRecordConflictError(
                    "algorithm feature key changed during immutable insert"
                ) from exc

    def list_algorithm_features(
        self,
        *,
        mine_ids: set[str] | None = None,
        feature_code: str | None = None,
        source_key: str | None = None,
        feature_version: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        limit: int = 10_000,
        include_overflow_sentinel: bool = False,
        include_invalidated: bool = False,
    ) -> list[dict[str, Any]]:
        """Read immutable features in event/receive order for detector input.

        With ``include_overflow_sentinel=True`` the repository may return one
        extra row.  A caller requesting ``limit=N`` can therefore distinguish
        exactly N rows from a truncated result by checking ``len(rows) > N``.
        The caller-visible limit remains capped at 100,000; only the single
        overflow sentinel can exceed that cap.
        """

        clauses: list[str] = []
        parameters: list[Any] = []
        if not include_invalidated:
            clauses.append(
                "batch_id IN ("
                "SELECT batch_id FROM batches WHERE invalidated_at IS NULL"
                ")"
            )
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            parameters.extend(sorted(mine_ids))
        for column, value in (
            ("feature_code", feature_code),
            ("source_key", source_key),
            ("feature_version", feature_version),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        start_at, end_at = _time_bounds(start_at, end_at)
        if start_at is not None:
            clauses.append("observed_at >= ?")
            parameters.append(start_at)
        if end_at is not None:
            clauses.append("observed_at < ?")
            parameters.append(end_at)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        bounded_limit = max(1, min(limit, 100_000))
        query_limit = bounded_limit + int(include_overflow_sentinel)
        parameters.append(query_limit)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT feature_id, feature_version, feature_json,
                       feature_sha256, created_at
                FROM analysis_feature_windows
                """
                + where
                + " ORDER BY observed_at, created_at, feature_id LIMIT ?",
                parameters,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            document = json.loads(row["feature_json"])
            hash_valid = sha256_json(document) == row["feature_sha256"]
            document["feature_version"] = str(row["feature_version"])
            document["feature_id"] = str(row["feature_id"])
            document["feature_sha256"] = str(row["feature_sha256"])
            document["created_at"] = str(row["created_at"])
            document["hash_valid"] = hash_valid
            result.append(document)
        return result

    @staticmethod
    def _validate_immutable_retry(
        row: sqlite3.Row,
        *,
        digest_column: str,
        json_column: str,
        expected_digest: str,
        expected_json: str,
        legacy_json: str,
        record_label: str,
    ) -> None:
        try:
            stored_document = json.loads(row[json_column])
        except (TypeError, json.JSONDecodeError) as exc:
            raise AlgorithmRecordIntegrityError(
                f"stored {record_label} JSON is invalid"
            ) from exc
        actual_digest = sha256_json(stored_document)
        if actual_digest != str(row[digest_column]):
            raise AlgorithmRecordIntegrityError(
                f"stored {record_label} hash verification failed"
            )
        stored_json = canonical_json(stored_document)
        if (
            actual_digest == expected_digest and stored_json == expected_json
        ) or stored_json == legacy_json:
            return
        raise AlgorithmRecordConflictError(
            f"{record_label} natural key already exists "
            "with different immutable content"
        )

    def save_detector_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> int:
        """Append versioned detector findings; exact retries are idempotent."""

        inserted = 0
        created_at = _now()
        with self._lock, self._connection:
            for raw in findings:
                document = _json_value(raw)
                if not isinstance(document, dict):
                    raise ValueError("detector finding must be an object")
                document.pop("hash_valid", None)
                document.pop("finding_id", None)
                document.pop("created_at", None)
                legacy_json = canonical_json(document)
                mine_id = _required_text(document, "mine_id")
                feature_code = _required_text(document, "feature_code")
                detector_code = _required_text(document, "detector_code")
                detector_version = _required_text(
                    document,
                    "detector_version",
                )
                status = _required_text(document, "status")
                observed_at = _timestamp(
                    document.get("observed_at"),
                    "observed_at",
                )
                assert observed_at is not None
                document["observed_at"] = observed_at
                source_key = str(document.get("source_key") or "").strip()
                document["source_key"] = source_key
                baseline_count = _integer(
                    document.get("baseline_sample_count", 0),
                    "baseline_sample_count",
                    minimum=0,
                )
                document["baseline_sample_count"] = baseline_count
                score = _optional_finite_number(
                    document.get("score"),
                    "score",
                )
                document["score"] = score
                digest = sha256_json(document)
                document_json = canonical_json(document)
                finding_id = _stable_id(
                    "finding",
                    mine_id,
                    observed_at,
                    feature_code,
                    source_key,
                    detector_code,
                    detector_version,
                )
                existing = self._connection.execute(
                    """
                    SELECT finding_sha256, finding_json
                    FROM detector_findings
                    WHERE mine_id = ? AND observed_at = ?
                      AND feature_code = ? AND source_key = ?
                      AND detector_code = ? AND detector_version = ?
                    """,
                    (
                        mine_id,
                        observed_at,
                        feature_code,
                        source_key,
                        detector_code,
                        detector_version,
                    ),
                ).fetchone()
                if existing is not None:
                    self._validate_immutable_retry(
                        existing,
                        digest_column="finding_sha256",
                        json_column="finding_json",
                        expected_digest=digest,
                        expected_json=document_json,
                        legacy_json=legacy_json,
                        record_label="detector finding",
                    )
                    continue
                self._connection.execute(
                    """
                    INSERT INTO detector_findings (
                        finding_id, mine_id, observed_at, feature_code,
                        source_key, detector_code, detector_version, status,
                        score, baseline_sample_count, finding_sha256,
                        finding_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        mine_id,
                        observed_at,
                        feature_code,
                        source_key,
                        detector_code,
                        detector_version,
                        status,
                        score,
                        baseline_count,
                        digest,
                        document_json,
                        created_at,
                    ),
                )
                inserted += 1
        return inserted

    def list_detector_findings(
        self,
        *,
        mine_ids: set[str] | None = None,
        feature_code: str | None = None,
        source_key: str | None = None,
        detector_code: str | None = None,
        detector_version: str | None = None,
        status: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            parameters.extend(sorted(mine_ids))
        for column, value in (
            ("feature_code", feature_code),
            ("source_key", source_key),
            ("detector_code", detector_code),
            ("detector_version", detector_version),
            ("status", status),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        start_at, end_at = _time_bounds(start_at, end_at)
        if start_at is not None:
            clauses.append("observed_at >= ?")
            parameters.append(start_at)
        if end_at is not None:
            clauses.append("observed_at < ?")
            parameters.append(end_at)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 100_000)))
        with self._lock:
            rows = self._connection.execute(
                "SELECT finding_id, finding_json, finding_sha256, created_at "
                "FROM detector_findings "
                + where
                + " ORDER BY observed_at, finding_id LIMIT ?",
                parameters,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            document = json.loads(row["finding_json"])
            hash_valid = sha256_json(document) == row["finding_sha256"]
            document["finding_id"] = str(row["finding_id"])
            document["created_at"] = str(row["created_at"])
            document["hash_valid"] = hash_valid
            result.append(document)
        return result

    def save_algorithm_model_snapshots(
        self,
        snapshots: list[dict[str, Any]],
    ) -> int:
        """Append immutable, versioned detector model/configuration snapshots."""

        inserted = 0
        created_at = _now()
        with self._lock, self._connection:
            for raw in snapshots:
                document = _json_value(raw)
                if not isinstance(document, dict):
                    raise ValueError("algorithm model snapshot must be an object")
                document.pop("hash_valid", None)
                document.pop("snapshot_id", None)
                document.pop("created_at", None)
                legacy_json = canonical_json(document)
                detector_code = _required_text(document, "detector_code")
                detector_version = _required_text(
                    document,
                    "detector_version",
                )
                scope_key = _required_text(document, "scope_key")
                activation_status = _required_text(
                    document,
                    "activation_status",
                )
                training_start = _timestamp(
                    document.get("training_start"),
                    "training_start",
                    required=False,
                )
                training_end = _timestamp(
                    document.get("training_end"),
                    "training_end",
                    required=False,
                )
                if (
                    training_start is not None
                    and training_end is not None
                    and training_start > training_end
                ):
                    raise ValueError(
                        "training_start must not be later than training_end"
                    )
                document["training_start"] = training_start
                document["training_end"] = training_end
                sample_count = _integer(
                    document.get("sample_count", 0),
                    "sample_count",
                    minimum=0,
                )
                document["sample_count"] = sample_count
                snapshot_id = _stable_id(
                    "model",
                    detector_code,
                    detector_version,
                    scope_key,
                )
                digest = sha256_json(document)
                document_json = canonical_json(document)
                existing = self._connection.execute(
                    """
                    SELECT snapshot_sha256, snapshot_json
                    FROM algorithm_model_snapshots
                    WHERE detector_code = ? AND detector_version = ?
                      AND scope_key = ?
                    """,
                    (detector_code, detector_version, scope_key),
                ).fetchone()
                if existing is not None:
                    self._validate_immutable_retry(
                        existing,
                        digest_column="snapshot_sha256",
                        json_column="snapshot_json",
                        expected_digest=digest,
                        expected_json=document_json,
                        legacy_json=legacy_json,
                        record_label="algorithm model snapshot",
                    )
                    continue
                self._connection.execute(
                    """
                    INSERT INTO algorithm_model_snapshots (
                        snapshot_id, detector_code, detector_version,
                        scope_key, training_start, training_end, sample_count,
                        activation_status, snapshot_sha256, snapshot_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        detector_code,
                        detector_version,
                        scope_key,
                        training_start,
                        training_end,
                        sample_count,
                        activation_status,
                        digest,
                        document_json,
                        created_at,
                    ),
                )
                inserted += 1
        return inserted

    def list_algorithm_model_snapshots(
        self,
        *,
        scope_keys: set[str] | None = None,
        detector_code: str | None = None,
        detector_version: str | None = None,
        activation_status: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        """List snapshots by scope and their training/event-time boundary."""

        clauses: list[str] = []
        parameters: list[Any] = []
        if scope_keys is not None:
            if not scope_keys:
                return []
            placeholders = ",".join("?" for _ in scope_keys)
            clauses.append(f"scope_key IN ({placeholders})")
            parameters.extend(sorted(scope_keys))
        for column, value in (
            ("detector_code", detector_code),
            ("detector_version", detector_version),
            ("activation_status", activation_status),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        start_at, end_at = _time_bounds(start_at, end_at)
        event_time = "COALESCE(training_end, training_start, created_at)"
        if start_at is not None:
            clauses.append(f"{event_time} >= ?")
            parameters.append(start_at)
        if end_at is not None:
            clauses.append(f"{event_time} < ?")
            parameters.append(end_at)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 100_000)))
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT snapshot_id, snapshot_json, snapshot_sha256, created_at
                FROM algorithm_model_snapshots
                """
                + where
                + f" ORDER BY {event_time}, snapshot_id LIMIT ?",
                parameters,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            document = json.loads(row["snapshot_json"])
            hash_valid = sha256_json(document) == row["snapshot_sha256"]
            document["snapshot_id"] = str(row["snapshot_id"])
            document["created_at"] = str(row["created_at"])
            document["hash_valid"] = hash_valid
            result.append(document)
        return result

    def save_alert_episodes(
        self,
        episodes: list[dict[str, Any]],
    ) -> int:
        """Append immutable alert episodes; exact retries do not duplicate."""

        inserted = 0
        created_at = _now()
        with self._lock, self._connection:
            for raw in episodes:
                document = _json_value(raw)
                if not isinstance(document, dict):
                    raise ValueError("alert episode must be an object")
                document.pop("hash_valid", None)
                document.pop("episode_id", None)
                document.pop("created_at", None)
                legacy_json = canonical_json(document)
                mine_id = _required_text(document, "mine_id")
                feature_code = _required_text(document, "feature_code")
                detector_code = _required_text(document, "detector_code")
                detector_version = _required_text(
                    document,
                    "detector_version",
                )
                source_key = str(document.get("source_key") or "").strip()
                document["source_key"] = source_key
                started_at = _timestamp(
                    document.get("started_at"),
                    "started_at",
                )
                ended_at = _timestamp(
                    document.get("ended_at"),
                    "ended_at",
                )
                assert started_at is not None and ended_at is not None
                if started_at > ended_at:
                    raise ValueError("started_at must not be later than ended_at")
                document["started_at"] = started_at
                document["ended_at"] = ended_at
                finding_count = _integer(
                    document.get("finding_count"),
                    "finding_count",
                    minimum=1,
                )
                document["finding_count"] = finding_count
                peak_score = _optional_finite_number(
                    document.get("peak_score"),
                    "peak_score",
                )
                document["peak_score"] = peak_score
                episode_id = _stable_id(
                    "episode",
                    mine_id,
                    feature_code,
                    source_key,
                    detector_code,
                    detector_version,
                    started_at,
                )
                digest = sha256_json(document)
                document_json = canonical_json(document)
                existing = self._connection.execute(
                    """
                    SELECT episode_sha256, episode_json
                    FROM alert_episodes
                    WHERE mine_id = ? AND feature_code = ?
                      AND source_key = ? AND detector_code = ?
                      AND detector_version = ? AND started_at = ?
                    """,
                    (
                        mine_id,
                        feature_code,
                        source_key,
                        detector_code,
                        detector_version,
                        started_at,
                    ),
                ).fetchone()
                if existing is not None:
                    self._validate_immutable_retry(
                        existing,
                        digest_column="episode_sha256",
                        json_column="episode_json",
                        expected_digest=digest,
                        expected_json=document_json,
                        legacy_json=legacy_json,
                        record_label="alert episode",
                    )
                    continue
                self._connection.execute(
                    """
                    INSERT INTO alert_episodes (
                        episode_id, mine_id, feature_code, source_key,
                        detector_code, detector_version, started_at, ended_at,
                        peak_score, finding_count, episode_sha256,
                        episode_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        episode_id,
                        mine_id,
                        feature_code,
                        source_key,
                        detector_code,
                        detector_version,
                        started_at,
                        ended_at,
                        peak_score,
                        finding_count,
                        digest,
                        document_json,
                        created_at,
                    ),
                )
                inserted += 1
        return inserted

    def list_alert_episodes(
        self,
        *,
        mine_ids: set[str] | None = None,
        feature_code: str | None = None,
        source_key: str | None = None,
        detector_code: str | None = None,
        detector_version: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        """List episodes intersecting the requested half-open time window."""

        clauses: list[str] = []
        parameters: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            parameters.extend(sorted(mine_ids))
        for column, value in (
            ("feature_code", feature_code),
            ("source_key", source_key),
            ("detector_code", detector_code),
            ("detector_version", detector_version),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        start_at, end_at = _time_bounds(start_at, end_at)
        if start_at is not None:
            clauses.append("ended_at >= ?")
            parameters.append(start_at)
        if end_at is not None:
            clauses.append("started_at < ?")
            parameters.append(end_at)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 100_000)))
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT episode_id, detector_version, episode_json,
                       episode_sha256, created_at
                FROM alert_episodes
                """
                + where
                + " ORDER BY started_at, episode_id LIMIT ?",
                parameters,
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            document = json.loads(row["episode_json"])
            hash_valid = sha256_json(document) == row["episode_sha256"]
            document.setdefault(
                "detector_version",
                str(row["detector_version"]),
            )
            document["episode_id"] = str(row["episode_id"])
            document["created_at"] = str(row["created_at"])
            document["hash_valid"] = hash_valid
            result.append(document)
        return result

    def _insert_case(
        self,
        *,
        batch_id: str,
        item: dict[str, Any],
        run_id: str | None,
        created_at: str,
    ) -> None:
        mine_id = str(item["mine_id"])
        technical_status = str(item["technical_status"])
        if technical_status == "inconsistent":
            issue_code = "production_conflict"
            title = f"{mine_id} 生产数据技术不一致"
        elif technical_status == "not_received":
            issue_code = "missing_report"
            title = f"{mine_id} 未收到分析数据"
        else:
            issue_code = "data_insufficient"
            title = f"{mine_id} 数据或计算条件待处理"

        analysis = item.get("analysis") or {}
        recommended_checks = analysis.get("recommended_checks") or []
        if not recommended_checks:
            if technical_status == "not_received":
                recommended_checks = [
                    "确认该矿本批次是否应报。",
                    "联系数据责任方补齐数据并重新运行分析。",
                ]
            else:
                recommended_checks = [
                    "检查输入完整性、设备状态与时间范围。",
                    "修正数据问题后重新运行分析。",
                ]

        case_id = _stable_id(
            "case",
            batch_id,
            mine_id,
            issue_code,
        )
        case_values = {
            "case_id": case_id,
            "run_id": run_id,
            "batch_id": batch_id,
            "mine_id": mine_id,
            "issue_code": issue_code,
            "title": title,
            "summary": str(item["summary"]),
            "priority": str(item["review_priority"]),
            "technical_status": technical_status,
            "evidence_grade": item.get("evidence_grade"),
            "workflow_status": "pending",
            "disposition": None,
            "assignee": None,
            "conclusion_by": None,
            "conclusion_at": None,
            "approval_by": None,
            "approval_at": None,
            "approval_note": None,
            "archived_at": None,
            "archived_by": None,
            "archived_reason": None,
            "version": 1,
            "recommended_checks": list(recommended_checks),
            "created_at": created_at,
            "updated_at": created_at,
        }
        self._connection.execute(
            """
            INSERT INTO cases (
                case_id, run_id, batch_id, mine_id, issue_code, title,
                summary, priority, technical_status, evidence_grade,
                workflow_status, disposition, assignee, version,
                recommended_checks_json, created_at, updated_at
            ) VALUES (
                :case_id, :run_id, :batch_id, :mine_id, :issue_code, :title,
                :summary, :priority, :technical_status, :evidence_grade,
                :workflow_status, :disposition, :assignee, :version,
                :recommended_checks_json, :created_at, :updated_at
            )
            """,
            {
                **case_values,
                "recommended_checks_json": canonical_json(
                    case_values["recommended_checks"]
                ),
            },
        )
        self._append_event(
            case_id=case_id,
            action="created",
            actor="system",
            note="批次分析自动生成本地试用核查事项。",
            before=None,
            after=case_values,
            created_at=created_at,
        )

    def get_batch(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
        return self._batch_row(row) if row is not None else None

    def get_latest_batch(
        self,
        *,
        include_invalidated: bool = False,
    ) -> dict[str, Any] | None:
        where = "" if include_invalidated else "WHERE invalidated_at IS NULL"
        with self._lock:
            row = self._connection.execute(
                f"SELECT * FROM batches {where} ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
        return self._batch_row(row) if row is not None else None

    def list_batches(
        self,
        *,
        limit: int = 100,
        include_invalidated: bool = False,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 1000))
        where = "" if include_invalidated else "WHERE invalidated_at IS NULL"
        with self._lock:
            rows = self._connection.execute(
                f"SELECT * FROM batches {where} ORDER BY rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._batch_row(row) for row in rows]

    @staticmethod
    def _batch_row(row: sqlite3.Row) -> dict[str, Any]:
        request = json.loads(row["request_json"])
        response = json.loads(row["response_json"])
        context = (
            json.loads(row["context_json"])
            if row["context_json"] is not None
            else None
        )
        request_hash_valid = (
            sha256_json(request) == row["request_sha256"]
        )
        response_hash_valid = bool(
            row["response_sha256"] is not None
            and sha256_json(response) == row["response_sha256"]
        )
        context_hash_valid = bool(
            row["context_sha256"] is not None
            and sha256_json(context) == row["context_sha256"]
        )
        return {
            "batch_id": row["batch_id"],
            "portfolio_name": row["portfolio_name"],
            "request_sha256": row["request_sha256"],
            "request": request,
            "request_hash_valid": request_hash_valid,
            "response_sha256": row["response_sha256"],
            "response": response,
            "response_hash_valid": response_hash_valid,
            "context_sha256": row["context_sha256"],
            "context": context,
            "context_hash_valid": context_hash_valid,
            "integrity_origin": row["integrity_origin"],
            "integrity_valid": bool(
                request_hash_valid
                and response_hash_valid
                and context_hash_valid
            ),
            "created_at": row["created_at"],
            "lifecycle": LocalRepository._batch_lifecycle_state(row),
        }

    def get_batch_lifecycle_events(
        self,
        batch_id: str,
    ) -> list[dict[str, Any]]:
        if self.get_batch(batch_id) is None:
            raise BatchNotFoundError("analysis batch not found")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT *
                FROM batch_lifecycle_events
                WHERE batch_id = ?
                ORDER BY sequence
                """,
                (batch_id,),
            ).fetchall()
        return [self._batch_lifecycle_event_row(row) for row in rows]

    @staticmethod
    def _batch_lifecycle_event_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "batch_id": str(row["batch_id"]),
            "sequence": int(row["sequence"]),
            "action": str(row["action"]),
            "actor": str(row["actor"]),
            "reason": row["reason"],
            "before": (
                json.loads(row["before_json"])
                if row["before_json"] is not None
                else None
            ),
            "after": json.loads(row["after_json"]),
            "previous_hash": str(row["previous_hash"]),
            "event_hash": str(row["event_hash"]),
            "created_at": str(row["created_at"]),
        }

    def verify_batch_lifecycle_chain(self, batch_id: str) -> bool:
        events = self.get_batch_lifecycle_events(batch_id)
        expected_previous = ""
        previous_after: dict[str, Any] | None = None
        for event in events:
            if event["previous_hash"] != expected_previous:
                return False
            payload = {
                key: event[key]
                for key in (
                    "batch_id",
                    "sequence",
                    "action",
                    "actor",
                    "reason",
                    "before",
                    "after",
                    "previous_hash",
                    "created_at",
                )
            }
            if sha256_json(payload) != event["event_hash"]:
                return False
            if previous_after is not None and event["before"] != previous_after:
                return False
            expected_previous = str(event["event_hash"])
            previous_after = event["after"]
        batch = self.get_batch(batch_id)
        return bool(
            events
            and batch is not None
            and events[-1]["after"] == batch["lifecycle"]
        )

    def set_batch_active(
        self,
        batch_id: str,
        *,
        active: bool,
        expected_version: int,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        """Invalidate or restore a batch without deleting immutable evidence."""

        actor = actor.strip()
        reason = reason.strip()
        if not actor:
            raise ValueError("actor is required")
        if not reason:
            raise ValueError("reason is required")
        if expected_version < 1:
            raise ValueError("expected_version must be positive")
        changed_at = _now()
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if row is None:
                raise BatchNotFoundError("analysis batch not found")
            before = self._batch_lifecycle_state(row)
            if before["version"] != expected_version:
                raise VersionConflictError(
                    "batch lifecycle version changed; reload before retrying"
                )
            if before["active"] is active:
                return {
                    "changed": False,
                    "lifecycle": before,
                }

            next_version = expected_version + 1
            if active:
                assignments = (
                    "lifecycle_version = ?, invalidated_at = NULL, "
                    "invalidated_by = NULL, invalidation_reason = NULL"
                )
                parameters: tuple[Any, ...] = (
                    next_version,
                    batch_id,
                    expected_version,
                )
                action = "restored"
            else:
                assignments = (
                    "lifecycle_version = ?, invalidated_at = ?, "
                    "invalidated_by = ?, invalidation_reason = ?"
                )
                parameters = (
                    next_version,
                    changed_at,
                    actor,
                    reason,
                    batch_id,
                    expected_version,
                )
                action = "invalidated"
            cursor = self._connection.execute(
                f"""
                UPDATE batches
                SET {assignments}
                WHERE batch_id = ? AND lifecycle_version = ?
                """,
                parameters,
            )
            if cursor.rowcount != 1:
                raise VersionConflictError(
                    "batch lifecycle version changed; reload before retrying"
                )
            after_row = self._connection.execute(
                "SELECT * FROM batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            assert after_row is not None
            after = self._batch_lifecycle_state(after_row)
            self._append_batch_lifecycle_event(
                batch_id=batch_id,
                action=action,
                actor=actor,
                reason=reason,
                before=before,
                after=after,
                created_at=changed_at,
            )
        return {"changed": True, "lifecycle": after}

    def isolate_legacy_pilot_batches(
        self,
        *,
        actor: str,
        reason: str,
    ) -> list[dict[str, Any]]:
        """Soft-invalidate active legacy batches whose ids start with pilot-."""

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT batch_id, lifecycle_version
                FROM batches
                WHERE invalidated_at IS NULL AND batch_id GLOB 'pilot-*'
                ORDER BY batch_id
                """
            ).fetchall()
            return [
                {
                    "batch_id": str(row["batch_id"]),
                    **self.set_batch_active(
                        str(row["batch_id"]),
                        active=False,
                        expected_version=int(row["lifecycle_version"]),
                        actor=actor,
                        reason=reason,
                    ),
                }
                for row in rows
            ]

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT analysis_runs.*, batches.request_sha256 AS "
                "batch_request_sha256, batches.request_json AS "
                "batch_request_json, batches.response_sha256, "
                "batches.response_json, batches.context_sha256, "
                "batches.context_json, batches.integrity_origin "
                "FROM analysis_runs JOIN batches USING (batch_id) "
                "WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise RunNotFoundError("analysis run not found")
        input_snapshot = json.loads(row["input_json"])
        result = json.loads(row["result_json"])
        batch_request = json.loads(row["batch_request_json"])
        batch_response = json.loads(row["response_json"])
        batch_context = (
            json.loads(row["context_json"])
            if row["context_json"] is not None
            else None
        )
        batch_request_hash_valid = bool(
            sha256_json(batch_request) == row["batch_request_sha256"]
        )
        batch_response_hash_valid = bool(
            row["response_sha256"] is not None
            and sha256_json(batch_response) == row["response_sha256"]
        )
        batch_context_hash_valid = bool(
            row["context_sha256"] is not None
            and sha256_json(batch_context) == row["context_sha256"]
        )
        try:
            batch_lifecycle_chain_valid = (
                self.verify_batch_lifecycle_chain(str(row["batch_id"]))
            )
        except (BatchNotFoundError, TypeError, ValueError):
            batch_lifecycle_chain_valid = False
        return {
            "run_id": row["run_id"],
            "batch_id": row["batch_id"],
            "mine_id": row["mine_id"],
            "technical_status": row["technical_status"],
            "input_sha256": row["input_sha256"],
            "input": input_snapshot,
            "input_hash_valid": (sha256_json(input_snapshot) == row["input_sha256"]),
            "result_sha256": row["result_sha256"],
            "result": result,
            "result_hash_valid": (sha256_json(result) == row["result_sha256"]),
            "engine_version": row["engine_version"],
            "batch_context": batch_context,
            "batch_request_sha256": row["batch_request_sha256"],
            "batch_response_sha256": row["response_sha256"],
            "batch_context_sha256": row["context_sha256"],
            "batch_request_hash_valid": batch_request_hash_valid,
            "batch_response_hash_valid": batch_response_hash_valid,
            "batch_context_hash_valid": batch_context_hash_valid,
            "batch_integrity_origin": row["integrity_origin"],
            "batch_lifecycle_chain_valid": batch_lifecycle_chain_valid,
            "batch_integrity_valid": bool(
                batch_request_hash_valid
                and batch_response_hash_valid
                and batch_context_hash_valid
            ),
            "batch_reference_integrity_eligible": bool(
                batch_request_hash_valid
                and batch_response_hash_valid
                and batch_context_hash_valid
                and row["integrity_origin"] == "created"
                and batch_lifecycle_chain_valid
            ),
            "created_at": row["created_at"],
        }

    def list_runs(self, batch_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT run_id FROM analysis_runs WHERE batch_id = ? ORDER BY mine_id",
                (batch_id,),
            ).fetchall()
        return [self.get_run(str(row["run_id"])) for row in rows]

    @staticmethod
    def _run_reference_label_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": str(row["run_id"]),
            "sequence": int(row["sequence"]),
            "label": str(row["label"]),
            "scenario_id": (
                str(row["scenario_id"])
                if row["scenario_id"] is not None
                else None
            ),
            "actor": str(row["actor"]),
            "note": str(row["note"]),
            "previous_hash": str(row["previous_hash"]),
            "event_hash": str(row["event_hash"]),
            "created_at": str(row["created_at"]),
        }

    def append_run_reference_label(
        self,
        run_id: str,
        *,
        label: str,
        actor: str,
        note: str,
        expected_sequence: int,
        scenario_id: str | None = None,
    ) -> dict[str, Any]:
        """Append one reviewed label using per-run optimistic sequencing."""

        normalized_run_id = _bounded_text(
            run_id,
            "run_id",
            maximum=_SHORT_ID_LIMIT,
        )
        normalized_label = _bounded_text(
            label,
            "label",
            maximum=64,
        )
        normalized_actor = _bounded_text(
            actor,
            "actor",
            maximum=_ACTOR_LIMIT,
        )
        normalized_note = _bounded_text(
            note,
            "note",
            maximum=_NOTE_LIMIT,
            multiline=True,
        )
        normalized_scenario_id = _bounded_text(
            scenario_id,
            "scenario_id",
            maximum=_SHORT_ID_LIMIT,
            required=False,
        )
        expected_sequence = _integer(
            expected_sequence,
            "expected_sequence",
            minimum=0,
        )
        assert normalized_run_id is not None
        assert normalized_label is not None
        assert normalized_actor is not None
        assert normalized_note is not None
        if normalized_label not in RUN_REFERENCE_LABELS:
            raise ValueError("label is not a supported run reference label")
        if (
            normalized_label == "legitimate_exception"
            and normalized_scenario_id is None
        ):
            raise ValueError(
                "legitimate_exception requires a scenario_id"
            )
        if (
            normalized_label != "legitimate_exception"
            and normalized_scenario_id is not None
        ):
            raise ValueError(
                "scenario_id is only valid for legitimate_exception"
            )

        created_at = _now()
        with self._lock, self._connection:
            run = self._connection.execute(
                "SELECT run_id FROM analysis_runs WHERE run_id = ?",
                (normalized_run_id,),
            ).fetchone()
            if run is None:
                raise RunNotFoundError("analysis run not found")
            prior = self._connection.execute(
                """
                SELECT sequence, event_hash
                FROM run_reference_labels
                WHERE run_id = ?
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (normalized_run_id,),
            ).fetchone()
            current_sequence = 0 if prior is None else int(prior["sequence"])
            if current_sequence != expected_sequence:
                raise VersionConflictError(
                    "run reference label sequence changed; reload before retrying"
                )
            sequence = current_sequence + 1
            previous_hash = (
                "" if prior is None else str(prior["event_hash"])
            )
            payload = {
                "run_id": normalized_run_id,
                "sequence": sequence,
                "label": normalized_label,
                "scenario_id": normalized_scenario_id,
                "actor": normalized_actor,
                "note": normalized_note,
                "previous_hash": previous_hash,
                "created_at": created_at,
            }
            event_hash = sha256_json(payload)
            try:
                self._connection.execute(
                    """
                    INSERT INTO run_reference_labels (
                        run_id, sequence, label, scenario_id, actor, note,
                        previous_hash, event_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_run_id,
                        sequence,
                        normalized_label,
                        normalized_scenario_id,
                        normalized_actor,
                        normalized_note,
                        previous_hash,
                        event_hash,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise VersionConflictError(
                    "run reference label sequence changed; reload before retrying"
                ) from exc
        return {**payload, "event_hash": event_hash}

    def get_run_reference_label_history(
        self,
        run_id: str,
    ) -> list[dict[str, Any]]:
        normalized_run_id = _bounded_text(
            run_id,
            "run_id",
            maximum=_SHORT_ID_LIMIT,
        )
        assert normalized_run_id is not None
        with self._lock:
            run = self._connection.execute(
                "SELECT run_id FROM analysis_runs WHERE run_id = ?",
                (normalized_run_id,),
            ).fetchone()
            if run is None:
                raise RunNotFoundError("analysis run not found")
            rows = self._connection.execute(
                """
                SELECT *
                FROM run_reference_labels
                WHERE run_id = ?
                ORDER BY sequence
                """,
                (normalized_run_id,),
            ).fetchall()
        return [self._run_reference_label_row(row) for row in rows]

    def verify_run_reference_label_chain(self, run_id: str) -> bool:
        events = self.get_run_reference_label_history(run_id)
        if not events:
            return False
        expected_previous = ""
        expected_sequence = 1
        for event in events:
            if event["sequence"] != expected_sequence:
                return False
            if event["previous_hash"] != expected_previous:
                return False
            payload = {
                key: event[key]
                for key in (
                    "run_id",
                    "sequence",
                    "label",
                    "scenario_id",
                    "actor",
                    "note",
                    "previous_hash",
                    "created_at",
                )
            }
            if sha256_json(payload) != event["event_hash"]:
                return False
            expected_previous = str(event["event_hash"])
            expected_sequence += 1
        return True

    @staticmethod
    def _stored_run_hashes_valid(row: sqlite3.Row) -> bool:
        try:
            input_snapshot = json.loads(row["input_json"])
            result = json.loads(row["result_json"])
        except (TypeError, json.JSONDecodeError):
            return False
        return bool(
            sha256_json(input_snapshot) == row["input_sha256"]
            and sha256_json(result) == row["result_sha256"]
        )

    def get_run_reference_label(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        """Return the current label plus its reference-eligibility evidence."""

        normalized_run_id = _bounded_text(
            run_id,
            "run_id",
            maximum=_SHORT_ID_LIMIT,
        )
        assert normalized_run_id is not None
        with self._lock:
            run = self._connection.execute(
                """
                SELECT analysis_runs.*, batches.invalidated_at,
                       batches.request_sha256 AS batch_request_sha256,
                       batches.request_json AS batch_request_json,
                       batches.response_sha256, batches.response_json,
                       batches.context_sha256, batches.context_json,
                       batches.integrity_origin
                FROM analysis_runs
                JOIN batches USING (batch_id)
                WHERE run_id = ?
                """,
                (normalized_run_id,),
            ).fetchone()
            if run is None:
                raise RunNotFoundError("analysis run not found")
            row = self._connection.execute(
                """
                SELECT *
                FROM run_reference_labels
                WHERE run_id = ?
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (normalized_run_id,),
            ).fetchone()
            if row is None:
                return None
            event = self._run_reference_label_row(row)
            chain_valid = self.verify_run_reference_label_chain(
                normalized_run_id
            )
            run_hash_valid = self._stored_run_hashes_valid(run)
            try:
                batch_request = json.loads(run["batch_request_json"])
                batch_response = json.loads(run["response_json"])
                batch_context = (
                    json.loads(run["context_json"])
                    if run["context_json"] is not None
                    else None
                )
                batch_integrity_valid = bool(
                    sha256_json(batch_request)
                    == run["batch_request_sha256"]
                    and run["response_sha256"] is not None
                    and sha256_json(batch_response)
                    == run["response_sha256"]
                    and run["context_sha256"] is not None
                    and sha256_json(batch_context)
                    == run["context_sha256"]
                )
            except (TypeError, json.JSONDecodeError):
                batch_integrity_valid = False
            batch_active = run["invalidated_at"] is None
            try:
                batch_lifecycle_chain_valid = (
                    self.verify_batch_lifecycle_chain(
                        str(run["batch_id"])
                    )
                )
            except (BatchNotFoundError, TypeError, ValueError):
                batch_lifecycle_chain_valid = False
        return {
            **event,
            "batch_id": str(run["batch_id"]),
            "mine_id": str(run["mine_id"]),
            "technical_status": str(run["technical_status"]),
            "label_chain_valid": chain_valid,
            "run_hash_valid": run_hash_valid,
            "batch_integrity_valid": batch_integrity_valid,
            "batch_integrity_origin": run["integrity_origin"],
            "batch_active": batch_active,
            "batch_lifecycle_chain_valid": batch_lifecycle_chain_valid,
            "reference_eligible": bool(
                chain_valid
                and run_hash_valid
                and batch_integrity_valid
                and run["integrity_origin"] == "created"
                and batch_active
                and batch_lifecycle_chain_valid
            ),
        }

    def get_current_run_reference_label(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        return self.get_run_reference_label(run_id)

    def list_run_reference_labels(
        self,
        *,
        label: str | None = None,
        labels: set[str] | frozenset[str] | tuple[str, ...] | None = None,
        mine_ids: set[str] | frozenset[str] | tuple[str, ...] | None = None,
        include_ineligible: bool = False,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        """List current labels, excluding unsafe reference runs by default."""

        if not isinstance(include_ineligible, bool):
            raise ValueError("include_ineligible must be a boolean")
        if label is not None and labels is not None:
            raise ValueError("label and labels are mutually exclusive")
        selected_labels = (
            {label}
            if label is not None
            else (set(labels) if labels is not None else None)
        )
        if selected_labels is not None:
            normalized_labels = {
                str(item).strip() for item in selected_labels
            }
            if not normalized_labels <= RUN_REFERENCE_LABELS:
                raise ValueError("labels contains an unsupported label")
            if not normalized_labels:
                return []
        else:
            normalized_labels = None
        normalized_mines = (
            set(
                _normalized_text_list(
                    list(mine_ids),
                    "mine_ids",
                )
            )
            if mine_ids is not None
            else None
        )
        if normalized_mines == set():
            return []
        bounded_limit = _integer(limit, "limit", minimum=1)
        if bounded_limit > 100_000:
            raise ValueError("limit must not exceed 100000")
        clauses: list[str] = []
        parameters: list[Any] = []
        if normalized_labels is not None:
            placeholders = ",".join("?" for _ in normalized_labels)
            clauses.append(f"current.label IN ({placeholders})")
            parameters.extend(sorted(normalized_labels))
        if normalized_mines is not None:
            placeholders = ",".join("?" for _ in normalized_mines)
            clauses.append(f"runs.mine_id IN ({placeholders})")
            parameters.extend(sorted(normalized_mines))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        # Fetch one bounded page.  Callers that need to detect truncation can
        # request ``limit + 1`` and fail closed instead of silently sampling a
        # partial label population.
        parameters.append(bounded_limit)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT current.run_id
                FROM run_reference_labels AS current
                JOIN (
                    SELECT run_id, MAX(sequence) AS sequence
                    FROM run_reference_labels
                    GROUP BY run_id
                ) AS latest
                  ON latest.run_id = current.run_id
                 AND latest.sequence = current.sequence
                JOIN analysis_runs AS runs ON runs.run_id = current.run_id
                """
                + where
                + " ORDER BY current.created_at DESC, current.run_id LIMIT ?"
                ,
                parameters,
            ).fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                current = self.get_run_reference_label(str(row["run_id"]))
                assert current is not None
                if include_ineligible or current["reference_eligible"]:
                    result.append(current)
                    if len(result) >= bounded_limit:
                        break
        return result

    def list_current_run_reference_labels(
        self,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        return self.list_run_reference_labels(**kwargs)

    def _legitimate_scenario_row(
        self,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        try:
            raw_definition = json.loads(row["definition_json"])
            definition = _normalize_legitimate_scenario_definition(
                raw_definition
            )
            mine_ids = (
                json.loads(row["mine_ids_json"])
                if row["mine_ids_json"] is not None
                else None
            )
            columns_match = bool(
                definition["scenario_id"] == row["scenario_id"]
                and definition["version"] == int(row["version"])
                and definition["name"] == row["name"]
                and definition["description"] == row["description"]
                and definition["mine_ids"] == mine_ids
                and definition["regime"] == row["regime"]
                and definition["shift"] == row["shift"]
                and definition["season"] == row["season"]
                and (
                    definition["maintenance"]
                    is (
                        None
                        if row["maintenance"] is None
                        else bool(row["maintenance"])
                    )
                )
                and definition["required_event_codes"]
                == json.loads(row["required_event_codes_json"])
                and definition["required_tags"]
                == json.loads(row["required_tags_json"])
                and definition["feature_bounds"]
                == json.loads(row["feature_bounds_json"])
                and int(row["active"]) in {0, 1}
                and definition["active"] is bool(row["active"])
                and definition["created_by"] == row["created_by"]
                and canonical_json(definition) == row["definition_json"]
            )
            hash_valid = bool(
                columns_match
                and sha256_json(definition) == row["definition_sha256"]
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            definition = {
                "scenario_id": str(row["scenario_id"]),
                "version": int(row["version"]),
                "name": str(row["name"]),
                "description": str(row["description"]),
                "mine_ids": None,
                "regime": row["regime"],
                "shift": row["shift"],
                "season": row["season"],
                "maintenance": (
                    None
                    if row["maintenance"] is None
                    else bool(row["maintenance"])
                ),
                "required_event_codes": [],
                "required_tags": [],
                "feature_bounds": {},
                "active": bool(row["active"]),
                "created_by": str(row["created_by"]),
            }
            hash_valid = False
        previous_definition_sha256 = ""
        version_chain_valid = int(row["version"]) == 1
        if int(row["version"]) > 1:
            previous = self._connection.execute(
                """
                SELECT *
                FROM legitimate_scenarios
                WHERE scenario_id = ? AND version = ?
                """,
                (str(row["scenario_id"]), int(row["version"]) - 1),
            ).fetchone()
            if previous is not None:
                previous_stored = self._legitimate_scenario_row(previous)
                previous_definition_sha256 = str(
                    previous_stored["definition_sha256"]
                )
                version_chain_valid = bool(
                    previous_stored["hash_valid"]
                    and previous_stored["version_chain_valid"]
                )
        hash_valid = bool(hash_valid and version_chain_valid)
        return {
            **definition,
            "definition_sha256": str(row["definition_sha256"]),
            "previous_definition_sha256": previous_definition_sha256,
            "version_chain_valid": version_chain_valid,
            "created_at": str(row["created_at"]),
            "hash_valid": hash_valid,
        }

    def save_legitimate_scenario(
        self,
        scenario: dict[str, Any],
    ) -> dict[str, Any]:
        """Store one immutable scenario version, with exact retries idempotent."""

        definition = _normalize_legitimate_scenario_definition(scenario)
        definition_json = canonical_json(definition)
        digest = sha256_json(definition)
        created_at = _now()
        key = (definition["scenario_id"], definition["version"])
        with self._lock, self._connection:
            existing = self._connection.execute(
                """
                SELECT *
                FROM legitimate_scenarios
                WHERE scenario_id = ? AND version = ?
                """,
                key,
            ).fetchone()
            if existing is not None:
                stored = self._legitimate_scenario_row(existing)
                if not stored["hash_valid"]:
                    raise AlgorithmRecordIntegrityError(
                        "stored legitimate scenario failed integrity validation"
                    )
                if (
                    existing["definition_sha256"] == digest
                    and existing["definition_json"] == definition_json
                ):
                    return {**stored, "created": False}
                raise LegitimateScenarioConflictError(
                    "scenario_id and version already exist with different content"
                )
            latest = self._connection.execute(
                """
                SELECT *
                FROM legitimate_scenarios
                WHERE scenario_id = ?
                ORDER BY version DESC
                LIMIT 1
                """,
                (definition["scenario_id"],),
            ).fetchone()
            expected_version = (
                1 if latest is None else int(latest["version"]) + 1
            )
            if latest is not None:
                latest_stored = self._legitimate_scenario_row(latest)
                if not latest_stored["hash_valid"]:
                    raise AlgorithmRecordIntegrityError(
                        "latest legitimate scenario version failed "
                        "integrity validation"
                    )
            if definition["version"] != expected_version:
                raise LegitimateScenarioConflictError(
                    "scenario versions must be continuous; expected "
                    f"version {expected_version}"
                )
            try:
                self._connection.execute(
                    """
                    INSERT INTO legitimate_scenarios (
                        scenario_id, version, name, description, mine_ids_json,
                        regime, shift, season, maintenance,
                        required_event_codes_json, required_tags_json,
                        feature_bounds_json, active, created_by,
                        definition_sha256, definition_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        definition["scenario_id"],
                        definition["version"],
                        definition["name"],
                        definition["description"],
                        (
                            canonical_json(definition["mine_ids"])
                            if definition["mine_ids"] is not None
                            else None
                        ),
                        definition["regime"],
                        definition["shift"],
                        definition["season"],
                        (
                            None
                            if definition["maintenance"] is None
                            else int(definition["maintenance"])
                        ),
                        canonical_json(definition["required_event_codes"]),
                        canonical_json(definition["required_tags"]),
                        canonical_json(definition["feature_bounds"]),
                        int(definition["active"]),
                        definition["created_by"],
                        digest,
                        definition_json,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise LegitimateScenarioConflictError(
                    "scenario key changed during immutable insert"
                ) from exc
            row = self._connection.execute(
                """
                SELECT *
                FROM legitimate_scenarios
                WHERE scenario_id = ? AND version = ?
                """,
                key,
            ).fetchone()
            assert row is not None
            stored = self._legitimate_scenario_row(row)
        return {**stored, "created": True}

    def get_legitimate_scenario(
        self,
        scenario_id: str,
        *,
        version: int | None = None,
        include_inactive: bool = False,
    ) -> dict[str, Any] | None:
        if not isinstance(include_inactive, bool):
            raise ValueError("include_inactive must be a boolean")
        normalized_scenario_id = _bounded_text(
            scenario_id,
            "scenario_id",
            maximum=_SHORT_ID_LIMIT,
        )
        assert normalized_scenario_id is not None
        parameters: list[Any] = [normalized_scenario_id]
        if version is None:
            version_clause = "ORDER BY version DESC LIMIT 1"
        else:
            normalized_version = _integer(
                version,
                "version",
                minimum=1,
            )
            version_clause = "AND version = ?"
            parameters.append(normalized_version)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT *
                FROM legitimate_scenarios
                WHERE scenario_id = ?
                """
                + version_clause,
                parameters,
            ).fetchone()
        if row is None:
            return None
        result = self._legitimate_scenario_row(row)
        if not include_inactive and not result["active"]:
            return None
        return result

    def list_legitimate_scenarios(
        self,
        *,
        include_inactive: bool = False,
        all_versions: bool = False,
        mine_id: str | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        if not isinstance(include_inactive, bool):
            raise ValueError("include_inactive must be a boolean")
        if not isinstance(all_versions, bool):
            raise ValueError("all_versions must be a boolean")
        normalized_mine_id = _bounded_text(
            mine_id,
            "mine_id",
            maximum=_SHORT_ID_LIMIT,
            required=False,
        )
        if all_versions:
            from_clause = "legitimate_scenarios AS scenario"
        else:
            from_clause = """
                legitimate_scenarios AS scenario
                JOIN (
                    SELECT scenario_id, MAX(version) AS version
                    FROM legitimate_scenarios
                    GROUP BY scenario_id
                ) AS latest
                  ON latest.scenario_id = scenario.scenario_id
                 AND latest.version = scenario.version
            """
        active_clause = "" if include_inactive else "WHERE scenario.active = 1"
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT scenario.*
                FROM {from_clause}
                {active_clause}
                ORDER BY scenario.scenario_id, scenario.version DESC
                """
            ).fetchall()
        bounded_limit = _integer(limit, "limit", minimum=1)
        if bounded_limit > 100_000:
            raise ValueError("limit must not exceed 100000")
        result: list[dict[str, Any]] = []
        for row in rows:
            scenario = self._legitimate_scenario_row(row)
            mine_ids = scenario["mine_ids"]
            if (
                normalized_mine_id is not None
                and mine_ids is not None
                and normalized_mine_id not in mine_ids
            ):
                continue
            result.append(scenario)
            if len(result) >= bounded_limit:
                break
        return result

    def match_legitimate_scenarios(
        self,
        *,
        mine_id: str,
        operational_context: dict[str, Any] | None,
        features: dict[str, Any] | None,
    ) -> dict[str, Any]:
        scenarios = self.list_legitimate_scenarios(mine_id=mine_id)
        return match_legitimate_scenarios(
            scenarios,
            mine_id=mine_id,
            operational_context=operational_context,
            features=features,
        )

    def list_cases(
        self,
        *,
        status: str | None = None,
        priority: str | None = None,
        mine_id: str | None = None,
        batch_id: str | None = None,
        include_archived: bool = False,
        include_invalidated: bool = False,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = [] if include_archived else ["archived_at IS NULL"]
        if not include_invalidated:
            clauses.append(
                "batch_id IN ("
                "SELECT batch_id FROM batches WHERE invalidated_at IS NULL"
                ")"
            )
        parameters: list[str] = []
        for column, value in (
            ("workflow_status", status),
            ("priority", priority),
            ("mine_id", mine_id),
            ("batch_id", batch_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT * FROM cases "
            f"{where} "
            "ORDER BY CASE priority "
            "WHEN 'P1' THEN 0 WHEN 'P2' THEN 1 WHEN 'DATA' THEN 2 ELSE 3 END, "
            "CASE workflow_status WHEN 'closed' THEN 1 ELSE 0 END, updated_at DESC"
        )
        with self._lock:
            rows = self._connection.execute(sql, parameters).fetchall()
        return [self._case_row(row) for row in rows]

    def get_case(self, case_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if row is None:
            raise CaseNotFoundError("case not found")
        return self._case_row(row)

    @staticmethod
    def _case_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "case_id": row["case_id"],
            "run_id": row["run_id"],
            "batch_id": row["batch_id"],
            "mine_id": row["mine_id"],
            "issue_code": row["issue_code"],
            "title": row["title"],
            "summary": row["summary"],
            "priority": row["priority"],
            "technical_status": row["technical_status"],
            "evidence_grade": row["evidence_grade"],
            "workflow_status": row["workflow_status"],
            "disposition": row["disposition"],
            "assignee": row["assignee"],
            "conclusion_by": row["conclusion_by"],
            "conclusion_at": row["conclusion_at"],
            "approval_by": row["approval_by"],
            "approval_at": row["approval_at"],
            "approval_note": row["approval_note"],
            "archived_at": row["archived_at"],
            "archived_by": row["archived_by"],
            "archived_reason": row["archived_reason"],
            "version": row["version"],
            "recommended_checks": json.loads(row["recommended_checks_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_case_events(self, case_id: str) -> list[dict[str, Any]]:
        # Make a missing id distinguishable from a valid case with no events.
        self.get_case(case_id)
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM case_events WHERE case_id = ? ORDER BY sequence",
                (case_id,),
            ).fetchall()
        return [self._event_row(row) for row in rows]

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "case_id": row["case_id"],
            "sequence": row["sequence"],
            "action": row["action"],
            "actor": row["actor"],
            "note": row["note"],
            "before": (
                json.loads(row["before_json"])
                if row["before_json"] is not None
                else None
            ),
            "after": json.loads(row["after_json"]),
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
            "created_at": row["created_at"],
        }

    def apply_case_action(
        self,
        case_id: str,
        *,
        action: CaseAction,
        expected_version: int,
        actor: str,
        note: str | None = None,
        disposition: str | None = None,
        assignee: str | None = None,
        occurred_at: str | datetime | None = None,
    ) -> dict[str, Any]:
        actor = actor.strip()
        if not actor:
            raise InvalidCaseActionError("actor is required")
        if expected_version < 1:
            raise InvalidCaseActionError("expected_version must be positive")
        note = note.strip() if note is not None else None
        assignee = assignee.strip() if assignee is not None else None
        occurred_at_text = (
            _now()
            if occurred_at is None
            else _timestamp(occurred_at, "occurred_at")
        )
        assert occurred_at_text is not None

        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            if row is None:
                raise CaseNotFoundError("case not found")
            before = self._case_row(row)
            if before["version"] != expected_version:
                raise VersionConflictError(
                    "case version changed; reload before applying the action"
                )
            previous_update = _timestamp(
                before["updated_at"],
                "case.updated_at",
            )
            assert previous_update is not None
            if occurred_at_text < previous_update:
                raise InvalidCaseActionError(
                    "occurred_at cannot predate the current case state"
                )

            workflow = str(before["workflow_status"])
            updates: dict[str, Any] = {}
            is_archived = before["archived_at"] is not None
            if is_archived and action != "restore_case":
                raise InvalidCaseActionError(
                    "archived case must be restored before applying another action"
                )
            if action == "archive_case":
                if workflow != "closed":
                    raise InvalidCaseActionError(
                        "archive_case requires closed status"
                    )
                if not note:
                    raise InvalidCaseActionError(
                        "note is required for archive_case"
                    )
                archived_at = occurred_at_text
                updates["archived_at"] = archived_at
                updates["archived_by"] = actor
                updates["archived_reason"] = note
            elif action == "restore_case":
                if not is_archived:
                    raise InvalidCaseActionError(
                        "restore_case requires an archived case"
                    )
                if not note:
                    raise InvalidCaseActionError(
                        "note is required for restore_case"
                    )
                updates["archived_at"] = None
                updates["archived_by"] = None
                updates["archived_reason"] = None
            elif action == "assign":
                if workflow == "closed":
                    raise InvalidCaseActionError(
                        "closed case must be reopened before assignment"
                    )
                if not assignee:
                    raise InvalidCaseActionError("assignee is required for assign")
                updates["assignee"] = assignee
            elif action == "add_note":
                if not note:
                    raise InvalidCaseActionError("note is required for add_note")
            elif action == "start_review":
                if workflow not in {"pending", "waiting_data"}:
                    raise InvalidCaseActionError(
                        "start_review requires pending or waiting_data status"
                    )
                updates["workflow_status"] = "reviewing"
            elif action == "request_data":
                if workflow not in {"pending", "reviewing"}:
                    raise InvalidCaseActionError(
                        "request_data requires pending or reviewing status"
                    )
                if not note:
                    raise InvalidCaseActionError("note is required for request_data")
                updates["workflow_status"] = "waiting_data"
            elif action == "submit_conclusion":
                if workflow not in {
                    "pending",
                    "reviewing",
                    "waiting_data",
                }:
                    raise InvalidCaseActionError(
                        "submit_conclusion requires an open review status"
                    )
                if not note:
                    raise InvalidCaseActionError(
                        "note is required for submit_conclusion"
                    )
                if disposition not in _DISPOSITIONS:
                    raise InvalidCaseActionError(
                        "a supported disposition is required for submit_conclusion"
                    )
                updates["workflow_status"] = "pending_approval"
                updates["disposition"] = disposition
                updates["conclusion_by"] = actor
                updates["conclusion_at"] = occurred_at_text
                updates["approval_by"] = None
                updates["approval_at"] = None
                updates["approval_note"] = None
            elif action == "withdraw_conclusion":
                if workflow != "pending_approval":
                    raise InvalidCaseActionError(
                        "withdraw_conclusion requires pending_approval status"
                    )
                if before["conclusion_by"] != actor:
                    raise InvalidCaseActionError(
                        "only the conclusion author can withdraw the conclusion"
                    )
                if not note:
                    raise InvalidCaseActionError(
                        "note is required for withdraw_conclusion"
                    )
                updates["workflow_status"] = "reviewing"
                updates["disposition"] = None
                updates["conclusion_by"] = None
                updates["conclusion_at"] = None
                updates["approval_by"] = None
                updates["approval_at"] = None
                updates["approval_note"] = None
            elif action in {"approve", "reject"}:
                if workflow != "pending_approval":
                    raise InvalidCaseActionError(
                        f"{action} requires pending_approval status"
                    )
                if not note:
                    raise InvalidCaseActionError(f"note is required for {action}")
                if before["conclusion_by"] == actor:
                    raise InvalidCaseActionError(
                        "conclusion author cannot approve or reject the same conclusion"
                    )
                if action == "approve":
                    updates["workflow_status"] = "closed"
                    updates["approval_by"] = actor
                    updates["approval_at"] = occurred_at_text
                    updates["approval_note"] = note
                else:
                    updates["workflow_status"] = "reviewing"
                    updates["disposition"] = None
                    updates["conclusion_by"] = None
                    updates["conclusion_at"] = None
                    updates["approval_by"] = None
                    updates["approval_at"] = None
                    updates["approval_note"] = note
            elif action == "close":
                if workflow == "closed":
                    raise InvalidCaseActionError("case is already closed")
                if not note:
                    raise InvalidCaseActionError("note is required for close")
                if disposition not in _DISPOSITIONS:
                    raise InvalidCaseActionError(
                        "a supported disposition is required for close"
                    )
                updates["workflow_status"] = "closed"
                updates["disposition"] = disposition
                updates["conclusion_by"] = actor
                updates["conclusion_at"] = occurred_at_text
                updates["approval_by"] = actor
                updates["approval_at"] = occurred_at_text
                updates["approval_note"] = (
                    "兼容模式直接关闭；启用认证时接口禁止该旁路。"
                )
            elif action == "reopen":
                if workflow != "closed":
                    raise InvalidCaseActionError("reopen requires closed status")
                if not note:
                    raise InvalidCaseActionError("note is required for reopen")
                updates["workflow_status"] = "reviewing"
                updates["disposition"] = None
                updates["conclusion_by"] = None
                updates["conclusion_at"] = None
                updates["approval_by"] = None
                updates["approval_at"] = None
                updates["approval_note"] = None
            else:  # pragma: no cover - protected by the public type/API model
                raise InvalidCaseActionError("unsupported action")

            updated_at = occurred_at_text
            updates["version"] = int(before["version"]) + 1
            updates["updated_at"] = updated_at
            assignments = ", ".join(f"{column} = ?" for column in updates)
            values = [*updates.values(), case_id, expected_version]
            cursor = self._connection.execute(
                f"UPDATE cases SET {assignments} WHERE case_id = ? AND version = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise VersionConflictError(
                    "case version changed; reload before applying the action"
                )
            after_row = self._connection.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            assert after_row is not None
            after = self._case_row(after_row)
            self._append_event(
                case_id=case_id,
                action=action,
                actor=actor,
                note=note,
                before=before,
                after=after,
                created_at=updated_at,
            )
        return after

    def _append_event(
        self,
        *,
        case_id: str,
        action: str,
        actor: str,
        note: str | None,
        before: dict[str, Any] | None,
        after: dict[str, Any],
        created_at: str,
    ) -> None:
        prior = self._connection.execute(
            "SELECT sequence, event_hash FROM case_events "
            "WHERE case_id = ? ORDER BY sequence DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        sequence = 1 if prior is None else int(prior["sequence"]) + 1
        previous_hash = "" if prior is None else str(prior["event_hash"])
        event_payload = {
            "case_id": case_id,
            "sequence": sequence,
            "action": action,
            "actor": actor,
            "note": note,
            "before": before,
            "after": after,
            "previous_hash": previous_hash,
            "created_at": created_at,
        }
        event_hash = sha256_json(event_payload)
        self._connection.execute(
            """
            INSERT INTO case_events (
                case_id, sequence, action, actor, note, before_json,
                after_json, previous_hash, event_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                sequence,
                action,
                actor,
                note,
                canonical_json(before) if before is not None else None,
                canonical_json(after),
                previous_hash,
                event_hash,
                created_at,
            ),
        )

    def verify_case_chain(self, case_id: str) -> bool:
        events = self.get_case_events(case_id)
        expected_previous = ""
        previous_after: dict[str, Any] | None = None
        for event in events:
            if event["previous_hash"] != expected_previous:
                return False
            payload = {
                key: event[key]
                for key in (
                    "case_id",
                    "sequence",
                    "action",
                    "actor",
                    "note",
                    "before",
                    "after",
                    "previous_hash",
                    "created_at",
                )
            }
            if sha256_json(payload) != event["event_hash"]:
                return False
            if previous_after is not None and self._normalized_case_state(
                event["before"]
            ) != self._normalized_case_state(previous_after):
                return False
            expected_previous = event["event_hash"]
            previous_after = event["after"]
        if not events:
            return False
        # The event chain is only useful if its final recorded state is also
        # the state currently exposed from the mutable case table.
        return self._normalized_case_state(
            events[-1]["after"]
        ) == self._normalized_case_state(self.get_case(case_id))

    @staticmethod
    def _normalized_case_state(
        state: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        if state is None:
            return None
        normalized = dict(state)
        for key in (
            "conclusion_by",
            "conclusion_at",
            "approval_by",
            "approval_at",
            "approval_note",
            "archived_at",
            "archived_by",
            "archived_reason",
        ):
            normalized.setdefault(key, None)
        return normalized

    def verify_run_hashes(self, run_id: str) -> bool:
        run = self.get_run(run_id)
        return bool(run["input_hash_valid"] and run["result_hash_valid"])

    def count_open_cases(
        self,
        *,
        batch_id: str | None = None,
        batch_ids: tuple[str, ...] | None = None,
        mine_ids: tuple[str, ...] | None = None,
    ) -> int:
        if batch_id is not None and batch_ids is not None:
            raise ValueError("batch_id and batch_ids are mutually exclusive")
        parameters: list[str] = []
        clauses = [
            "workflow_status != 'closed'",
            "archived_at IS NULL",
            "batch_id IN ("
            "SELECT batch_id FROM batches WHERE invalidated_at IS NULL"
            ")",
        ]
        if batch_id is not None:
            clauses.append("batch_id = ?")
            parameters.append(batch_id)
        if batch_ids is not None:
            if not batch_ids:
                return 0
            placeholders = ",".join("?" for _ in batch_ids)
            clauses.append(f"batch_id IN ({placeholders})")
            parameters.extend(batch_ids)
        if mine_ids is not None:
            if not mine_ids:
                return 0
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            parameters.extend(mine_ids)
        with self._lock:
            row = self._connection.execute(
                f"SELECT COUNT(*) AS count FROM cases WHERE {' AND '.join(clauses)}",
                parameters,
            ).fetchone()
        assert row is not None
        return int(row["count"])


__all__ = [
    "ALGORITHM_COMPATIBILITY_VERSION",
    "ALGORITHM_FEATURE_VERSION",
    "AlgorithmRecordConflictError",
    "AlgorithmRecordIntegrityError",
    "BatchConflictError",
    "BatchNotFoundError",
    "CaseNotFoundError",
    "CaseworkError",
    "ExternalConfirmerRegistrationConflictError",
    "ExternalEventSnapshotConflictError",
    "ExternalSubmissionConflictError",
    "InvalidCaseActionError",
    "LegitimateScenarioConflictError",
    "LocalRepository",
    "RUN_REFERENCE_LABELS",
    "RunNotFoundError",
    "VersionConflictError",
    "algorithm_feature_compatibility_key",
    "build_algorithm_feature_compatibility",
    "canonical_json",
    "match_legitimate_scenarios",
    "select_authoritative_algorithm_feature",
    "sha256_json",
]
