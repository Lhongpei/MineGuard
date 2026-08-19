"""SQLite persistence with optimistic revisions and append-only audit hashes."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import timedelta
from pathlib import Path
from typing import Any

from .errors import (
    ConflictError,
    ConnectorQuotaExceededError,
    NotFoundError,
    ValidationBlockedError,
)
from .security import observation_review_fingerprint
from .util import canonical_json, parse_aware_datetime, sha256_json, utc_now, utc_text

_SCHEMA_VERSION = 9
_CONNECTOR_EVENTS_PER_TEN_MINUTES = 240
_CONNECTOR_EVENTS_PER_DAY = 5_000
_CONNECTOR_MAX_MONTH_BINDINGS = 240
_CONNECTOR_MAX_SOURCES_PER_DRAFT = 32
_CONNECTOR_HEALTH_EVENTS_PER_TEN_MINUTES = 1_000
_CONNECTOR_HEALTH_EVENTS_PER_DAY = 20_000
_CONNECTOR_HEALTH_EVENT_RETENTION_DAYS = 90


_CONNECTOR_BINDING_COLUMNS = frozenset(
    {
        "client_id",
        "draft_key",
        "draft_id",
        "reporting_month",
        "last_machine_revision",
        "last_machine_payload_sha256",
        "created_at",
    }
)
_CONNECTOR_INGESTION_COLUMNS = frozenset(
    {
        "ingestion_id",
        "client_id",
        "event_id",
        "request_sha256",
        "draft_key",
        "draft_id",
        "source_id",
        "source_revision",
        "source_name",
        "source_system",
        "source_format",
        "original_filename",
        "source_observed_at",
        "source_coverage_as_of",
        "truth_statement",
        "trigger_workflow",
        "workflow_name",
        "status",
        "import_summary_json",
        "draft_revision",
        "draft_payload_sha256",
        "workflow_result_json",
        "failure_json",
        "result_json",
        "lease_owner",
        "lease_expires_at",
        "created_at",
        "updated_at",
        "completed_at",
    }
)


def _sqlite_table_exists(db: sqlite3.Connection, table: str) -> bool:
    return (
        db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        is not None
    )


def _sqlite_columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row["name"])
        for row in db.execute(f'PRAGMA table_info("{table}")').fetchall()
    }


def _connector_legacy_tables(
    db: sqlite3.Connection, prefix: str
) -> list[str]:
    rows = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ? "
        "ORDER BY name",
        (f"{prefix}_v5_legacy%",),
    ).fetchall()
    return [
        str(row["name"])
        for row in rows
        if str(row["name"]).replace("_", "").isalnum()
    ]


def _next_connector_legacy_table(db: sqlite3.Connection, prefix: str) -> str:
    base = f"{prefix}_v5_legacy"
    candidate = base
    suffix = 1
    while _sqlite_table_exists(db, candidate):
        suffix += 1
        candidate = f"{base}_{suffix}"
    return candidate


def _create_connector_v6_tables(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS connector_draft_bindings (
            client_id TEXT NOT NULL,
            draft_key TEXT NOT NULL,
            draft_id TEXT NOT NULL UNIQUE,
            reporting_month TEXT NOT NULL,
            last_machine_revision INTEGER NOT NULL CHECK (
                last_machine_revision >= 1
            ),
            last_machine_payload_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (client_id, draft_key)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS connector_ingestions (
            ingestion_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            draft_key TEXT NOT NULL,
            draft_id TEXT,
            source_id TEXT NOT NULL,
            source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
            source_name TEXT NOT NULL,
            source_system TEXT NOT NULL,
            source_format TEXT NOT NULL CHECK (source_format IN ('json', 'csv')),
            original_filename TEXT,
            source_observed_at TEXT NOT NULL,
            source_coverage_as_of TEXT,
            truth_statement INTEGER NOT NULL CHECK (truth_statement = 1),
            trigger_workflow INTEGER NOT NULL CHECK (trigger_workflow IN (0, 1)),
            workflow_name TEXT NOT NULL CHECK (
                workflow_name = 'daily_coal_health'
            ),
            status TEXT NOT NULL CHECK (
                status IN ('bound', 'imported', 'completed', 'rejected')
            ),
            import_summary_json TEXT,
            draft_revision INTEGER,
            draft_payload_sha256 TEXT,
            workflow_result_json TEXT,
            failure_json TEXT,
            result_json TEXT,
            lease_owner TEXT,
            lease_expires_at REAL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT,
            UNIQUE (client_id, event_id)
        )
        """
    )
    db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_connector_ingestions_draft
            ON connector_ingestions(draft_id, created_at DESC)
        """
    )
    db.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_connector_binding_month
            ON connector_draft_bindings(reporting_month)
        """
    )


def _create_connector_health_tables(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS connector_source_health_events (
            client_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            draft_key TEXT NOT NULL,
            reporting_month TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_system TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK(outcome IN (
                'success_nonempty','success_empty','error','stability_wait'
            )),
            attempted_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            coverage_as_of TEXT,
            error_code TEXT,
            snapshot_sha256 TEXT,
            autofill_event_id TEXT,
            source_revision INTEGER,
            applied INTEGER NOT NULL CHECK(applied IN (0,1)),
            result_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(client_id,event_id)
        )
        """
    )
    db.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_connector_health_events_created
            ON connector_source_health_events(client_id,created_at)
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS connector_source_health (
            client_id TEXT NOT NULL,
            draft_key TEXT NOT NULL,
            reporting_month TEXT NOT NULL,
            source_id TEXT NOT NULL,
            source_system TEXT NOT NULL,
            required INTEGER NOT NULL CHECK(required IN (0,1)),
            freshness_max_seconds INTEGER NOT NULL CHECK(
                freshness_max_seconds BETWEEN 300 AND 2592000
            ),
            outcome TEXT NOT NULL CHECK(outcome IN (
                'success_nonempty','success_empty','error','stability_wait'
            )),
            attempted_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            last_success_at TEXT,
            last_nonempty_at TEXT,
            record_count INTEGER NOT NULL CHECK(record_count >= 0),
            coverage_as_of TEXT,
            error_code TEXT,
            snapshot_sha256 TEXT,
            autofill_event_id TEXT,
            source_revision INTEGER,
            last_event_id TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(client_id,draft_key,source_id)
        )
        """
    )


def _apply_connector_source_health(
    db: sqlite3.Connection,
    *,
    client_id: str,
    draft_key: str,
    reporting_month: str,
    source_id: str,
    source_system: str,
    required: bool,
    freshness_max_seconds: int,
    outcome: str,
    attempted_at: str,
    completed_at: str,
    record_count: int,
    coverage_as_of: str | None,
    error_code: str | None,
    snapshot_sha256: str | None,
    autofill_event_id: str | None,
    source_revision: int | None,
    event_id: str,
    updated_at: str,
) -> bool:
    current = db.execute(
        """
        SELECT * FROM connector_source_health
        WHERE client_id=? AND draft_key=? AND source_id=?
        """,
        (client_id, draft_key, source_id),
    ).fetchone()
    if current is not None and str(current["completed_at"]) >= completed_at:
        return False
    last_success_at = (
        completed_at
        if outcome in {"success_nonempty", "success_empty"}
        else current["last_success_at"]
        if current is not None
        else None
    )
    last_nonempty_at = (
        completed_at
        if outcome == "success_nonempty"
        else current["last_nonempty_at"]
        if current is not None
        else None
    )
    db.execute(
        """
        INSERT INTO connector_source_health(
            client_id,draft_key,reporting_month,source_id,source_system,
            required,freshness_max_seconds,outcome,attempted_at,completed_at,
            last_success_at,last_nonempty_at,record_count,coverage_as_of,
            error_code,snapshot_sha256,autofill_event_id,source_revision,
            last_event_id,updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(client_id,draft_key,source_id) DO UPDATE SET
            reporting_month=excluded.reporting_month,
            source_system=excluded.source_system,
            required=excluded.required,
            freshness_max_seconds=excluded.freshness_max_seconds,
            outcome=excluded.outcome,
            attempted_at=excluded.attempted_at,
            completed_at=excluded.completed_at,
            last_success_at=excluded.last_success_at,
            last_nonempty_at=excluded.last_nonempty_at,
            record_count=excluded.record_count,
            coverage_as_of=excluded.coverage_as_of,
            error_code=excluded.error_code,
            snapshot_sha256=excluded.snapshot_sha256,
            autofill_event_id=excluded.autofill_event_id,
            source_revision=excluded.source_revision,
            last_event_id=excluded.last_event_id,
            updated_at=excluded.updated_at
        """,
        (
            client_id,
            draft_key,
            reporting_month,
            source_id,
            source_system,
            int(required),
            freshness_max_seconds,
            outcome,
            attempted_at,
            completed_at,
            last_success_at,
            last_nonempty_at,
            record_count,
            coverage_as_of,
            error_code,
            snapshot_sha256,
            autofill_event_id,
            source_revision,
            event_id,
            updated_at,
        ),
    )
    return True


def _evaluate_connector_source_health(
    *,
    draft_payload_json: str,
    rows: list[sqlite3.Row],
    contribution_rows: list[sqlite3.Row],
    policies: tuple[dict[str, Any], ...],
    current_epoch: float,
) -> dict[str, Any]:
    """Build the dynamic source-health view from one database snapshot."""

    row_by_source = {str(row["source_id"]): row for row in rows}
    contribution_by_source = {
        str(row["source_id"]): row for row in contribution_rows
    }
    active_policy_configured = bool(policies)
    effective_policies = policies
    if effective_policies:
        configured_source_ids = {
            str(policy["source_id"]) for policy in effective_policies
        }
        missing_contributions = tuple(
            row
            for row in contribution_rows
            if str(row["source_id"]) not in configured_source_ids
        )
        effective_policies = effective_policies + tuple(
            {
                "source_id": str(row["source_id"]),
                "source_system": str(
                    row["ingestion_source_system"] or "unknown"
                ),
                "required": True,
                "freshness_max_seconds": int(
                    row_by_source[str(row["source_id"])][
                        "freshness_max_seconds"
                    ]
                    if str(row["source_id"]) in row_by_source
                    else 3600
                ),
                "_policy_missing": True,
            }
            for row in missing_contributions
        )
    if not effective_policies and contribution_rows:
        effective_policies = tuple(
            {
                "source_id": str(row["source_id"]),
                "source_system": str(
                    row["ingestion_source_system"] or "unknown"
                ),
                "required": True,
                "freshness_max_seconds": int(
                    row_by_source.get(str(row["source_id"]))[
                        "freshness_max_seconds"
                    ]
                    if row_by_source.get(str(row["source_id"])) is not None
                    else 3600
                ),
            }
            for row in contribution_rows
        )
    if not effective_policies:
        effective_policies = tuple(
            {
                "source_id": str(row["source_id"]),
                "source_system": str(row["source_system"]),
                "required": True,
                "freshness_max_seconds": int(row["freshness_max_seconds"]),
            }
            for row in rows
        )
    period_end = str(json.loads(draft_payload_json)["period_end"])
    items: list[dict[str, Any]] = []
    stale_required: list[str] = []
    for policy in sorted(
        effective_policies, key=lambda value: value["source_id"]
    ):
        source_id = str(policy["source_id"])
        row = row_by_source.get(source_id)
        contribution = contribution_by_source.get(source_id)
        source_name = (
            str(contribution["ingestion_source_name"])
            if contribution is not None
            and contribution["ingestion_source_name"] is not None
            else None
        )
        required = bool(policy["required"])
        maximum_age = int(policy["freshness_max_seconds"])
        age_seconds: int | None = None
        if row is None or row["source_system"] != policy["source_system"]:
            state = "unknown"
            outcome = None
            completed_at = None
            last_nonempty_at = None
            last_success_at = None
            coverage_as_of = None
            error_code = None
        else:
            outcome = str(row["outcome"])
            completed_at = str(row["completed_at"])
            completed_epoch = parse_aware_datetime(
                completed_at, "completed_at"
            ).timestamp()
            age_seconds = max(0, int(current_epoch - completed_epoch))
            last_nonempty_at = row["last_nonempty_at"]
            last_success_at = row["last_success_at"]
            coverage_as_of = row["coverage_as_of"]
            error_code = row["error_code"]
            snapshot_matches = bool(
                contribution is not None
                and row["snapshot_sha256"] == contribution["content_sha256"]
                and row["autofill_event_id"] == contribution["event_id"]
                and row["source_revision"]
                == contribution["source_revision"]
                and contribution["ingestion_status"] == "completed"
            )
            if outcome == "error":
                state = "error"
            elif (
                outcome in {"success_empty", "stability_wait"}
                or not snapshot_matches
                or coverage_as_of is None
                or str(coverage_as_of) < period_end
            ):
                state = "waiting"
            elif age_seconds >= maximum_age:
                state = "stale"
            else:
                state = "fresh"
        if not active_policy_configured or policy.get("_policy_missing"):
            state = "unknown"
            error_code = "policy_missing"
        if required and state != "fresh":
            stale_required.append(source_id)
        items.append(
            {
                "source_id": source_id,
                "source_system": str(policy["source_system"]),
                "source_name": source_name,
                "required": required,
                "outcome": outcome,
                "completed_at": completed_at,
                "last_nonempty_at": last_nonempty_at,
                "last_success_at": last_success_at,
                "coverage_as_of": coverage_as_of,
                "freshness_max_seconds": maximum_age,
                "age_seconds": age_seconds,
                "freshness_state": state,
                "error_code": error_code,
            }
        )
    return {
        "source_health": items,
        "freshness": {
            "overall_state": "fresh" if not stale_required else "stale",
            "stale_required_source_ids": sorted(stale_required),
        },
    }


def _valid_json_text(value: Any, *, object_only: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    if object_only and not isinstance(parsed, dict):
        return None
    return canonical_json(parsed)


def _recover_machine_baseline(
    db: sqlite3.Connection,
    *,
    draft_id: str,
    ingestion_tables: list[str],
) -> tuple[int, str] | None:
    """Recover the last trusted machine revision, not the current human state."""

    if _sqlite_table_exists(db, "fq_audit"):
        rows = db.execute(
            "SELECT details_json FROM fq_audit "
            "WHERE event_type='five_quantity_machine_autofilled' "
            "ORDER BY sequence DESC"
        ).fetchall()
        for row in rows:
            try:
                details = json.loads(row["details_json"])
                revision = int(details.get("draft_revision"))
                payload_hash = str(details.get("payload_sha256"))
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                continue
            if (
                details.get("draft_id") == draft_id
                and revision >= 1
                and len(payload_hash) == 64
                and all(character in "0123456789abcdef" for character in payload_hash)
            ):
                return revision, payload_hash
    for table in ingestion_tables:
        columns = _sqlite_columns(db, table)
        required = {
            "draft_id",
            "draft_revision",
            "draft_payload_sha256",
        }
        if not required.issubset(columns):
            continue
        rows = db.execute(
            f'SELECT draft_revision,draft_payload_sha256 FROM "{table}" '
            "WHERE draft_id=? AND draft_revision IS NOT NULL "
            "AND draft_payload_sha256 IS NOT NULL ORDER BY rowid DESC",
            (draft_id,),
        ).fetchall()
        for row in rows:
            try:
                revision = int(row["draft_revision"])
                payload_hash = str(row["draft_payload_sha256"])
            except (TypeError, ValueError):
                continue
            if (
                revision >= 1
                and len(payload_hash) == 64
                and all(character in "0123456789abcdef" for character in payload_hash)
            ):
                return revision, payload_hash
    return None


def _migrate_connector_bindings(
    db: sqlite3.Connection,
    *,
    binding_tables: list[str],
    ingestion_tables: list[str],
) -> None:
    """Restore only bindings whose complete V2 source state is recoverable."""

    required_v2_tables = {
        "fq_drafts",
        "fq_machine_source_contributions",
    }
    if not all(_sqlite_table_exists(db, table) for table in required_v2_tables):
        return
    for table in binding_tables:
        columns = _sqlite_columns(db, table)
        if not {"client_id", "draft_key", "draft_id"}.issubset(columns):
            continue
        rows = db.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
        for legacy in rows:
            client_id = str(legacy["client_id"] or "")
            draft_key = str(legacy["draft_key"] or "")
            draft_id = str(legacy["draft_id"] or "")
            if not client_id or not draft_key or not draft_id:
                continue
            draft = db.execute(
                "SELECT revision,payload_json,created_at FROM fq_drafts "
                "WHERE draft_id=?",
                (draft_id,),
            ).fetchone()
            if draft is None:
                continue
            contribution = db.execute(
                "SELECT 1 FROM fq_machine_source_contributions "
                "WHERE client_id=? AND draft_key=? AND draft_id=? LIMIT 1",
                (client_id, draft_key, draft_id),
            ).fetchone()
            if contribution is None:
                continue
            try:
                payload = json.loads(draft["payload_json"])
                reporting_month = str(payload["reporting_month"])
            except (KeyError, TypeError, json.JSONDecodeError):
                continue
            if (
                len(reporting_month) != 7
                or reporting_month[4] != "-"
                or not reporting_month.replace("-", "").isdigit()
            ):
                continue
            baseline = _recover_machine_baseline(
                db,
                draft_id=draft_id,
                ingestion_tables=ingestion_tables,
            )
            if baseline is None or baseline[0] > int(draft["revision"]):
                continue
            created_at = (
                str(legacy["created_at"])
                if "created_at" in columns and legacy["created_at"]
                else str(draft["created_at"])
            )
            db.execute(
                """
                INSERT OR IGNORE INTO connector_draft_bindings(
                    client_id,draft_key,draft_id,reporting_month,
                    last_machine_revision,last_machine_payload_sha256,created_at
                ) VALUES (?,?,?,?,?,?,?)
                """,
                (
                    client_id,
                    draft_key,
                    draft_id,
                    reporting_month,
                    baseline[0],
                    baseline[1],
                    created_at,
                ),
            )


def _migrate_connector_ingestions(
    db: sqlite3.Connection, ingestion_tables: list[str]
) -> None:
    """Preserve event idempotency; fail closed when V1 state cannot resume."""

    migration_time = utc_text()
    for table in ingestion_tables:
        columns = _sqlite_columns(db, table)
        essentials = {
            "ingestion_id",
            "client_id",
            "event_id",
            "request_sha256",
            "draft_key",
        }
        if not essentials.issubset(columns):
            continue
        rows = db.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
        for row in rows:
            row_keys = row.keys()
            legacy = {key: row[key] for key in row_keys}
            identifiers = [
                str(legacy.get(key) or "")
                for key in (
                    "ingestion_id",
                    "client_id",
                    "event_id",
                    "request_sha256",
                    "draft_key",
                )
            ]
            if not all(identifiers):
                continue
            ingestion_id, client_id, event_id, request_hash, draft_key = identifiers
            legacy_draft_id = str(legacy.get("draft_id") or "")
            binding = db.execute(
                "SELECT draft_id FROM connector_draft_bindings "
                "WHERE client_id=? AND draft_key=?",
                (client_id, draft_key),
            ).fetchone()
            compatible = (
                binding is not None
                and legacy_draft_id
                and str(binding["draft_id"]) == legacy_draft_id
            )
            raw_revision = legacy.get("source_revision", 1)
            try:
                source_revision = max(1, int(raw_revision))
            except (TypeError, ValueError):
                source_revision = 1
            source_id = str(legacy.get("source_id") or "")
            if not source_id:
                source_id = "legacy-" + sha256_json(
                    {"client_id": client_id, "event_id": event_id}
                )[:24]
            source_format = str(legacy.get("source_format") or "json")
            if source_format not in {"json", "csv"}:
                source_format = "json"
            source_name = str(
                legacy.get("source_name") or f"{source_id}.{source_format}"
            )[:255]
            source_system = str(
                legacy.get("source_system") or "legacy-connector-migration"
            )[:128]
            original_filename = legacy.get("original_filename")
            if original_filename is not None:
                original_filename = str(original_filename)[:255]

            legacy_status = str(legacy.get("status") or "")
            result_json = _valid_json_text(
                legacy.get("result_json"), object_only=True
            )
            failure_json = _valid_json_text(
                legacy.get("failure_json"), object_only=True
            )
            resumable = compatible and {
                "source_id",
                "source_revision",
            }.issubset(columns)
            if legacy_status == "completed" and result_json is not None:
                status = "completed"
            elif legacy_status == "rejected" and failure_json is not None:
                status = "rejected"
            elif legacy_status in {"bound", "imported"} and resumable:
                status = legacy_status
            else:
                status = "rejected"
                result_json = None
                failure_json = canonical_json(
                    {
                        "code": "connector_migration_review_required",
                        "http_status": 409,
                        "message": (
                            "旧版机器填报事件缺少可安全恢复的 V2 来源状态；"
                            "已保留幂等记录，请使用新的 event_id 重新采集"
                        ),
                        "ingestion_id": ingestion_id,
                        "source_id": source_id,
                        "source_revision": source_revision,
                        "recorded_at": migration_time,
                    }
                )
            created_at = str(legacy.get("created_at") or migration_time)
            updated_at = str(legacy.get("updated_at") or created_at)
            completed_at = legacy.get("completed_at")
            if status in {"completed", "rejected"} and completed_at is None:
                completed_at = updated_at
            db.execute(
                """
                INSERT OR IGNORE INTO connector_ingestions(
                    ingestion_id,client_id,event_id,request_sha256,draft_key,
                    draft_id,source_id,source_revision,source_name,source_system,
                    source_format,original_filename,source_observed_at,
                    source_coverage_as_of,truth_statement,
                    trigger_workflow,workflow_name,status,import_summary_json,
                    draft_revision,draft_payload_sha256,workflow_result_json,
                    failure_json,result_json,lease_owner,lease_expires_at,
                    created_at,updated_at,completed_at
                ) VALUES (
                    ?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,
                    NULL,NULL,?,?,?
                )
                """,
                (
                    ingestion_id,
                    client_id,
                    event_id,
                    request_hash,
                    draft_key,
                    legacy_draft_id if compatible else None,
                    source_id,
                    source_revision,
                    source_name,
                    source_system,
                    source_format,
                    original_filename,
                    str(legacy.get("source_observed_at") or created_at),
                    legacy.get("source_coverage_as_of"),
                    int(bool(legacy.get("trigger_workflow", 0))),
                    "daily_coal_health",
                    status,
                    _valid_json_text(
                        legacy.get("import_summary_json"), object_only=True
                    ),
                    legacy.get("draft_revision") if compatible else None,
                    (
                        legacy.get("draft_payload_sha256")
                        if compatible
                        else None
                    ),
                    _valid_json_text(
                        legacy.get("workflow_result_json"), object_only=True
                    ),
                    failure_json,
                    result_json,
                    created_at,
                    updated_at,
                    completed_at,
                ),
            )


def _migrate_connector_schema_v6(db: sqlite3.Connection) -> None:
    """Upgrade V5 safely while retaining source rows for manual recovery."""

    ingestion_columns = _sqlite_columns(db, "connector_ingestions")
    binding_columns = _sqlite_columns(db, "connector_draft_bindings")
    ingestion_sql_row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' "
        "AND name='connector_ingestions'"
    ).fetchone()
    ingestion_sql = str(ingestion_sql_row["sql"] or "")
    ingestion_complete = (
        _CONNECTOR_INGESTION_COLUMNS.issubset(ingestion_columns)
        and "'rejected'" in ingestion_sql
    )
    binding_complete = _CONNECTOR_BINDING_COLUMNS.issubset(binding_columns)

    if not ingestion_complete:
        db.execute("DROP INDEX IF EXISTS idx_connector_ingestions_draft")
        legacy_name = _next_connector_legacy_table(
            db, "connector_ingestions"
        )
        db.execute(
            f'ALTER TABLE connector_ingestions RENAME TO "{legacy_name}"'
        )
    if not binding_complete:
        legacy_name = _next_connector_legacy_table(
            db, "connector_draft_bindings"
        )
        db.execute(
            f'ALTER TABLE connector_draft_bindings RENAME TO "{legacy_name}"'
        )
    _create_connector_v6_tables(db)
    _create_connector_health_tables(db)

    ingestion_tables = _connector_legacy_tables(db, "connector_ingestions")
    binding_tables = _connector_legacy_tables(
        db, "connector_draft_bindings"
    )
    if not ingestion_tables and not binding_tables:
        return
    _migrate_connector_bindings(
        db,
        binding_tables=binding_tables,
        ingestion_tables=ingestion_tables,
    )
    _migrate_connector_ingestions(db, ingestion_tables)


def _install_schema_guards(db: sqlite3.Connection) -> None:
    """Give upgraded SQLite tables the same future-write guards as fresh ones."""

    guards = {
        "agent_flows": (
            "NEW.status NOT IN "
            "('queued','running','blocked','succeeded','failed','cancelled') "
            "OR NEW.attempt < 1 OR NEW.revision < 1 "
            "OR NEW.dispatch_ready NOT IN (0,1) "
            "OR NEW.cancel_requested NOT IN (0,1)"
        ),
        "agent_jobs": (
            "NEW.schedule_kind NOT IN ('daily','interval','event') "
            "OR NEW.enabled NOT IN (0,1) OR NEW.revision < 1 "
            "OR NEW.event_count < 0"
        ),
        "agent_trigger_events": "NEW.progress_revision < 0",
        "agent_memory_proposals": (
            "NEW.scope_type NOT IN ('user','draft','mine','enterprise') "
            "OR NEW.status NOT IN ('pending','approved','rejected') "
            "OR NEW.revision < 1 OR NEW.event_count < 0"
        ),
        "agent_memories": (
            "NEW.scope_type NOT IN ('user','draft','mine','enterprise') "
            "OR NEW.status NOT IN ('active','revoked','superseded') "
            "OR NEW.version < 1 OR NEW.revision < 1 "
            "OR NOT EXISTS ("
            "SELECT 1 FROM agent_memory_proposals AS proposal "
            "WHERE proposal.proposal_id = NEW.proposal_id"
            ") OR EXISTS ("
            "SELECT 1 FROM agent_memories AS other "
            "WHERE other.memory_id <> NEW.memory_id "
            "AND (other.proposal_id = NEW.proposal_id OR ("
            "other.scope_type = NEW.scope_type "
            "AND other.scope_id = NEW.scope_id "
            "AND other.memory_key = NEW.memory_key "
            "AND other.version = NEW.version))"
            ")"
        ),
        "agent_skill_proposals": (
            "NEW.status NOT IN ('pending','approved','rejected') "
            "OR NEW.revision < 1 OR NEW.event_count < 0"
        ),
        "agent_skill_versions": (
            "NEW.status NOT IN ('active','retired','superseded') "
            "OR NEW.runtime_activation NOT IN "
            "('proposal_only','approved_inactive') "
            "OR NEW.version < 1 OR NEW.revision < 1 "
            "OR NOT EXISTS ("
            "SELECT 1 FROM agent_skill_proposals AS proposal "
            "WHERE proposal.proposal_id = NEW.proposal_id"
            ") OR EXISTS ("
            "SELECT 1 FROM agent_skill_versions AS other "
            "WHERE other.skill_version_id <> NEW.skill_version_id "
            "AND (other.proposal_id = NEW.proposal_id OR ("
            "other.skill_name = NEW.skill_name "
            "AND other.version = NEW.version))"
            ")"
        ),
    }
    for table, invalid_when in guards.items():
        for operation in ("INSERT", "UPDATE"):
            trigger_name = (
                f"guard_{table}_{operation.casefold()}_v4"
            )
            db.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS {trigger_name}
                BEFORE {operation} ON {table}
                WHEN {invalid_when}
                BEGIN
                    SELECT RAISE(ABORT, '{table} constraint violation');
                END
                """
            )
    for operation in ("UPDATE", "DELETE"):
        trigger_name = f"guard_draft_audit_{operation.casefold()}_v4"
        db.execute(
            f"""
            CREATE TRIGGER IF NOT EXISTS {trigger_name}
            BEFORE {operation} ON draft_audit
            BEGIN
                SELECT RAISE(ABORT, 'draft_audit is append-only');
            END
            """
        )


def _normalise_managed_schema_sql(value: str) -> str:
    """Return a stable representation of SQL authored by this application.

    SQLite stores the trigger body supplied at creation time.  Collapsing
    whitespace is deliberately the *only* normalisation: accepting a trigger
    merely because its header looks right would also accept a same-name no-op
    body and defeat the append-only boundary.
    """

    return " ".join(value.split())


def _expected_draft_audit_triggers() -> dict[str, str]:
    return {
        f"guard_draft_audit_{operation.casefold()}_v4": (
            _normalise_managed_schema_sql(
                f"""
                CREATE TRIGGER guard_draft_audit_{operation.casefold()}_v4
                BEFORE {operation} ON draft_audit
                BEGIN
                    SELECT RAISE(ABORT, 'draft_audit is append-only');
                END
                """
            )
        )
        for operation in ("UPDATE", "DELETE")
    }


def _draft_audit_triggers_intact(db: sqlite3.Connection) -> bool:
    """Require the exact two governed triggers and reject side-effect extras."""

    expected = _expected_draft_audit_triggers()
    rows = db.execute(
        "SELECT name,sql FROM sqlite_master "
        "WHERE type='trigger' AND tbl_name='draft_audit'"
    ).fetchall()
    actual: dict[str, str] = {}
    for row in rows:
        name = str(row["name"])
        sql = row["sql"]
        if name not in expected or not isinstance(sql, str):
            return False
        actual[name] = _normalise_managed_schema_sql(sql)
    return actual == expected


class Repository:
    def __init__(self, path: str | Path):
        raw_path = str(path)
        self.path = (
            raw_path
            if raw_path == ":memory:"
            else str(Path(raw_path).expanduser().resolve())
        )
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        self._lock = threading.RLock()
        self._memory_connection: sqlite3.Connection | None = None
        self._runtime_connection: sqlite3.Connection | None = None
        self._runtime_data_version: int | None = None
        self._runtime_schema_version: int | None = None
        self._runtime_integrity_failed = False
        # Development and migration utilities may legitimately open a second
        # Repository for the same file.  Production startup enables the latch
        # only after the complete audit verification succeeds; from that point
        # on any commit through another SQLite connection is terminal for this
        # process.
        self._runtime_integrity_latching_enabled = False
        if self.path == ":memory:":
            self._memory_connection = self._connect()
        try:
            self._initialize()
            self._ensure_wal()
            # All post-initialisation reads and writes share one connection.
            # PRAGMA data_version changes on this connection only when another
            # SQLite connection commits, which gives the running Agent a
            # constant-size, process-local external-write latch.  The RLock
            # already serialised the former short-lived connections, so this
            # does not reduce application concurrency.
            self._runtime_connection = self._memory_connection or self._connect()
            self._refresh_runtime_integrity_checkpoint_locked()
        except sqlite3.Error as error:
            raise ValueError(
                f"无法打开企业端数据库 {self.path}；请检查路径、权限或数据库完整性"
            ) from error
        if self.path != ":memory:":
            # Some non-POSIX/network filesystems do not expose chmod.
            with suppress(OSError):
                os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
            check_same_thread=False,
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=10000")
            if self.path != ":memory:":
                connection.execute("PRAGMA synchronous=FULL")
            return connection
        except Exception:
            connection.close()
            raise

    def _ensure_wal(self) -> None:
        """Enable WAL once, retrying only the cross-process bootstrap race."""

        if self.path == ":memory:":
            return
        deadline = time.monotonic() + 10.0
        delay = 0.01
        last_error: sqlite3.OperationalError | None = None
        while time.monotonic() < deadline:
            connection: sqlite3.Connection | None = None
            try:
                connection = self._connect()
                current = connection.execute(
                    "PRAGMA journal_mode"
                ).fetchone()
                if current is not None and str(current[0]).lower() == "wal":
                    return
                selected = connection.execute(
                    "PRAGMA journal_mode=WAL"
                ).fetchone()
                if (
                    selected is not None
                    and str(selected[0]).lower() == "wal"
                ):
                    return
                raise sqlite3.OperationalError(
                    "数据库文件系统不支持 WAL 日志模式"
                )
            except sqlite3.OperationalError as error:
                last_error = error
                if "locked" not in str(error).lower() and "busy" not in str(
                    error
                ).lower():
                    raise
            finally:
                if connection is not None:
                    connection.close()
            time.sleep(delay)
            delay = min(delay * 2, 0.25)
        raise last_error or sqlite3.OperationalError(
            "启用 WAL 日志模式超时"
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._runtime_connection or self._memory_connection
            if connection is None:  # pragma: no cover - construction invariant
                raise RuntimeError("企业端数据库运行连接尚未初始化")
            if connection.in_transaction:
                yield connection
                return
            self._assert_runtime_database_unchanged_locked(connection)
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                # Capture the schema marker while the reserved write lock still
                # excludes an external writer.  Our own commit does not change
                # this connection's data_version.
                expected_schema_version = int(
                    connection.execute("PRAGMA schema_version").fetchone()[0]
                )
                connection.execute("COMMIT")
                self._accept_controlled_commit_locked(
                    connection,
                    expected_schema_version=expected_schema_version,
                )
            except BaseException:
                # KeyboardInterrupt, cancellation and SystemExit must not leave
                # the shared in-memory connection inside an open transaction.
                with suppress(sqlite3.Error):
                    connection.execute("ROLLBACK")
                raise

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._runtime_connection or self._memory_connection
            if connection is None:  # pragma: no cover - construction invariant
                raise RuntimeError("企业端数据库运行连接尚未初始化")
            if connection.in_transaction:
                yield connection
                return
            self._assert_runtime_database_unchanged_locked(connection)
            try:
                yield connection
                self._assert_runtime_database_unchanged_locked(connection)
            except BaseException:
                # A few governance projections deliberately open their own
                # snapshot on the yielded connection. Never leave that manual
                # read transaction active after an exception.
                if connection.in_transaction:
                    with suppress(sqlite3.Error):
                        connection.execute("ROLLBACK")
                raise

    def _refresh_runtime_integrity_checkpoint_locked(self) -> None:
        connection = self._runtime_connection or self._memory_connection
        if connection is None:  # pragma: no cover - construction invariant
            raise RuntimeError("企业端数据库运行连接尚未初始化")
        self._runtime_data_version = int(
            connection.execute("PRAGMA data_version").fetchone()[0]
        )
        self._runtime_schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )

    def _latch_runtime_integrity_failure(self) -> None:
        self._runtime_integrity_failed = True

    def _assert_runtime_database_unchanged_locked(
        self, connection: sqlite3.Connection
    ) -> None:
        if self._runtime_integrity_failed:
            raise ConflictError(
                "运行期数据库完整性已锁死；拒绝继续读写，请保全现场并重启核验"
            )
        data_version = int(connection.execute("PRAGMA data_version").fetchone()[0])
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        if (
            self._runtime_data_version is None
            or self._runtime_schema_version is None
        ):
            self._runtime_data_version = data_version
            self._runtime_schema_version = schema_version
            return
        if (
            data_version != self._runtime_data_version
            or schema_version != self._runtime_schema_version
        ):
            if not self._runtime_integrity_latching_enabled:
                self._runtime_data_version = data_version
                self._runtime_schema_version = schema_version
                return
            self._latch_runtime_integrity_failure()
            raise ConflictError(
                "检测到运行期外部数据库写入或 schema 变化；"
                "当前进程已锁死，请保全数据库并重启核验"
            )

    def _accept_controlled_commit_locked(
        self,
        connection: sqlite3.Connection,
        *,
        expected_schema_version: int,
    ) -> None:
        data_version = int(connection.execute("PRAGMA data_version").fetchone()[0])
        schema_version = int(
            connection.execute("PRAGMA schema_version").fetchone()[0]
        )
        if (
            self._runtime_data_version is None
            or data_version != self._runtime_data_version
            or schema_version != expected_schema_version
        ):
            if not self._runtime_integrity_latching_enabled:
                self._runtime_data_version = data_version
                self._runtime_schema_version = schema_version
                return
            self._latch_runtime_integrity_failure()
            raise ConflictError(
                "受控提交完成时检测到并发外部数据库变化；"
                "当前进程已锁死，请重启核验"
            )
        self._runtime_schema_version = schema_version

    def verify_runtime_integrity_boundary(
        self,
        *,
        additional_check: Callable[[sqlite3.Connection], bool] | None = None,
    ) -> dict[str, Any]:
        """Run the constant-size production readiness boundary.

        A complete audit scan must have armed the latch first.  Thereafter the
        persistent connection's data/schema markers make every external commit
        terminal.  The fixed trigger/version checks below protect the trusted
        schema boundary without walking historical audit rows.  A caller may
        add another constant-size check (the five-quantity singleton anchor and
        its two exact triggers) while the same lock and marker window are held.

        This method never attempts a full rescan or refreshes a mismatched
        checkpoint: a runtime mismatch is recoverable only by process restart
        followed by the normal startup full verification.
        """

        with self._lock:
            connection = self._runtime_connection or self._memory_connection
            if connection is None:  # pragma: no cover - construction invariant
                raise RuntimeError("企业端数据库运行连接尚未初始化")
            if self._runtime_integrity_failed:
                raise ConflictError(
                    "运行期数据库完整性已锁死；拒绝继续服务，请保全现场并重启核验"
                )
            if not self._runtime_integrity_latching_enabled:
                raise ConflictError(
                    "正式模式尚未完成启动全链核验；运行期就绪检查拒绝放行"
                )
            self._assert_runtime_database_unchanged_locked(connection)
            try:
                version = connection.execute(
                    "SELECT version FROM app_schema_versions "
                    "WHERE component='enterprise_agent'"
                ).fetchone()
                anchor_table = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='draft_audit_anchors'"
                ).fetchone()
                generic_valid = bool(
                    version is not None
                    and int(version["version"]) == _SCHEMA_VERSION
                    and anchor_table is not None
                    and _draft_audit_triggers_intact(connection)
                )
                additional_valid = (
                    True
                    if additional_check is None
                    else bool(additional_check(connection))
                )
            except (
                sqlite3.Error,
                IndexError,
                KeyError,
                TypeError,
                ValueError,
            ) as error:
                self._latch_runtime_integrity_failure()
                raise ConflictError(
                    "运行期固定完整性边界无法核验；当前进程已锁死，请重启核验"
                ) from error
            if not generic_valid or not additional_valid:
                self._latch_runtime_integrity_failure()
                raise ConflictError(
                    "运行期审计触发器、版本或必要锚点异常；"
                    "当前进程已锁死，请保全现场并重启核验"
                )
            # Detect an external commit that raced any of the constant queries.
            self._assert_runtime_database_unchanged_locked(connection)
            return {
                "valid": True,
                "mode": "runtime_constant_boundary",
                "generic_triggers_exact": True,
                "generic_anchor_table_present": True,
                "additional_boundary_valid": additional_valid,
            }

    def close(self) -> None:
        """Close the shared file connection when an embedding runtime can."""

        with self._lock:
            connection = self._runtime_connection
            self._runtime_connection = None
            if connection is not None and connection is not self._memory_connection:
                connection.close()
            if self._memory_connection is not None:
                self._memory_connection.close()
                self._memory_connection = None

    def _initialize(self) -> None:
        with self._lock:
            db = self._memory_connection or self._connect()
            try:
                opening_schema_version = 0
                version_table = db.execute(
                    """
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'app_schema_versions'
                    """
                ).fetchone()
                if version_table is not None:
                    current_version = db.execute(
                        """
                        SELECT version FROM app_schema_versions
                        WHERE component = 'enterprise_agent'
                        """
                    ).fetchone()
                    if current_version is not None:
                        opening_schema_version = int(current_version["version"])
                    if (
                        current_version is not None
                        and int(current_version["version"]) > _SCHEMA_VERSION
                    ):
                        raise ValueError(
                            "数据库 schema 版本高于当前程序支持版本；"
                            "拒绝由旧程序降级打开"
                        )
                # ``executescript`` commits any transaction that existed before
                # it starts.  Begin the exclusive migration *inside* the script
                # so every CREATE/ALTER/version write below is serialized across
                # Repository instances and processes.
                db.executescript(
                    """
                    BEGIN EXCLUSIVE;

                    CREATE TABLE IF NOT EXISTS app_schema_versions (
                        component TEXT PRIMARY KEY,
                        version INTEGER NOT NULL CHECK (version >= 1),
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS drafts (
                        draft_id TEXT PRIMARY KEY,
                        document_json TEXT NOT NULL,
                        revision INTEGER NOT NULL CHECK (revision >= 1),
                        confirmed_revision INTEGER,
                        confirmation_json TEXT,
                        deleted_at TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS draft_audit (
                        draft_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        event_type TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        PRIMARY KEY (draft_id, sequence),
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE TABLE IF NOT EXISTS draft_audit_anchors (
                        draft_id TEXT PRIMARY KEY,
                        event_count INTEGER NOT NULL CHECK (event_count >= 1),
                        head_hash TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE TABLE IF NOT EXISTS submissions (
                        idempotency_key TEXT PRIMARY KEY,
                        draft_id TEXT NOT NULL,
                        confirmed_revision INTEGER NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        request_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        receipt_json TEXT,
                        error_code TEXT,
                        error_json TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_drafts_updated
                        ON drafts(updated_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_submissions_draft
                        ON submissions(draft_id, created_at DESC);

                    CREATE TABLE IF NOT EXISTS observation_reviews (
                        review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        draft_id TEXT NOT NULL,
                        observation_id TEXT NOT NULL,
                        observation_fingerprint_sha256 TEXT NOT NULL,
                        reviewed_by TEXT NOT NULL,
                        reviewed_at TEXT NOT NULL,
                        revoked_at TEXT,
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_observation_reviews_active
                        ON observation_reviews (
                            draft_id, reviewed_by, observation_id, revoked_at
                        );

                    CREATE TABLE IF NOT EXISTS agent_runs (
                        run_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        draft_id TEXT,
                        task_text TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        status TEXT NOT NULL,
                        budgets_json TEXT NOT NULL,
                        checkpoint_json TEXT NOT NULL,
                        summary TEXT,
                        answer TEXT,
                        error_code TEXT,
                        error_message TEXT,
                        cancel_requested INTEGER NOT NULL DEFAULT 0,
                        active_duration_ms INTEGER NOT NULL DEFAULT 0,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        event_head_hash TEXT NOT NULL DEFAULT
                            '0000000000000000000000000000000000000000000000000000000000000000',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        completed_at TEXT
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_runs_actor_updated
                        ON agent_runs(actor_id, updated_at DESC);

                    CREATE TABLE IF NOT EXISTS agent_tool_calls (
                        call_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        provider_call_id TEXT,
                        tool_name TEXT NOT NULL,
                        tool_spec_sha256 TEXT NOT NULL,
                        evidence_grounding TEXT NOT NULL,
                        arguments_json TEXT NOT NULL,
                        arguments_sha256 TEXT NOT NULL,
                        draft_revision INTEGER,
                        status TEXT NOT NULL,
                        result_json TEXT,
                        result_sha256 TEXT,
                        result_bytes INTEGER NOT NULL DEFAULT 0,
                        summary TEXT,
                        approval_id TEXT,
                        error_code TEXT,
                        error_message TEXT,
                        created_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        UNIQUE(run_id, sequence),
                        FOREIGN KEY (run_id) REFERENCES agent_runs(run_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_tool_calls_run
                        ON agent_tool_calls(run_id, sequence);

                    CREATE TABLE IF NOT EXISTS agent_approvals (
                        approval_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        call_id TEXT NOT NULL UNIQUE,
                        arguments_sha256 TEXT NOT NULL,
                        draft_revision INTEGER,
                        tool_spec_sha256 TEXT NOT NULL,
                        harness_version TEXT NOT NULL,
                        status TEXT NOT NULL,
                        requested_by TEXT NOT NULL,
                        requested_at TEXT NOT NULL,
                        decided_by TEXT,
                        decided_at TEXT,
                        decision TEXT,
                        FOREIGN KEY (run_id) REFERENCES agent_runs(run_id),
                        FOREIGN KEY (call_id) REFERENCES agent_tool_calls(call_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_approvals_run
                        ON agent_approvals(run_id, requested_at);

                    CREATE TABLE IF NOT EXISTS agent_run_steps (
                        run_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        kind TEXT NOT NULL,
                        status TEXT NOT NULL,
                        title TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        evidence_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (run_id, sequence),
                        FOREIGN KEY (run_id) REFERENCES agent_runs(run_id)
                    );

                    CREATE TABLE IF NOT EXISTS agent_run_events (
                        run_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        PRIMARY KEY (run_id, sequence),
                        FOREIGN KEY (run_id) REFERENCES agent_runs(run_id)
                    );

                    CREATE TABLE IF NOT EXISTS chat_sessions (
                        session_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        client_request_id TEXT,
                        title TEXT NOT NULL,
                        draft_id TEXT,
                        context_draft_id TEXT,
                        deleted_at TEXT,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        event_head_hash TEXT NOT NULL DEFAULT
                            '0000000000000000000000000000000000000000000000000000000000000000',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_chat_sessions_actor_updated
                        ON chat_sessions(actor_id, updated_at DESC);

                    CREATE TABLE IF NOT EXISTS chat_messages (
                        message_id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        role TEXT NOT NULL CHECK (
                            role IN ('user', 'assistant')
                        ),
                        client_message_id TEXT,
                        content TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN (
                                'queued', 'completed', 'failed', 'refused'
                            )
                        ),
                        run_id TEXT UNIQUE,
                        domain_allowed INTEGER NOT NULL CHECK (
                            domain_allowed IN (0, 1)
                        ),
                        domain_reason TEXT NOT NULL,
                        evidence_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE(session_id, sequence),
                        FOREIGN KEY (session_id)
                            REFERENCES chat_sessions(session_id),
                        FOREIGN KEY (run_id) REFERENCES agent_runs(run_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_chat_messages_session_sequence
                        ON chat_messages(session_id, sequence);

                    CREATE TABLE IF NOT EXISTS chat_session_events (
                        session_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        event_type TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        PRIMARY KEY (session_id, sequence),
                        FOREIGN KEY (session_id)
                            REFERENCES chat_sessions(session_id)
                    );

                    CREATE TABLE IF NOT EXISTS agent_flows (
                        flow_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        workflow_name TEXT NOT NULL,
                        workflow_version TEXT NOT NULL,
                        draft_id TEXT,
                        goal_text TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL CHECK (
                            status IN (
                                'queued', 'running', 'blocked', 'succeeded',
                                'failed', 'cancelled'
                            )
                        ),
                        trigger_type TEXT NOT NULL DEFAULT 'manual',
                        trigger_ref TEXT,
                        client_request_id TEXT,
                        state_json TEXT NOT NULL DEFAULT '{}',
                        current_step TEXT,
                        attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt >= 1),
                        dispatch_ready INTEGER NOT NULL DEFAULT 1 CHECK (
                            dispatch_ready IN (0, 1)
                        ),
                        run_owner TEXT,
                        lease_expires_at TEXT,
                        revision INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1),
                        cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (
                            cancel_requested IN (0, 1)
                        ),
                        summary TEXT,
                        error_code TEXT,
                        error_message TEXT,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        event_head_hash TEXT NOT NULL DEFAULT
                            '0000000000000000000000000000000000000000000000000000000000000000',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        UNIQUE(actor_id, client_request_id),
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_flows_actor_status
                        ON agent_flows(actor_id, status, updated_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_agent_flows_status_updated
                        ON agent_flows(status, updated_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_agent_flows_draft_updated
                        ON agent_flows(draft_id, updated_at DESC);

                    CREATE TABLE IF NOT EXISTS agent_flow_steps (
                        flow_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        attempt INTEGER NOT NULL CHECK (attempt >= 1),
                        step_key TEXT NOT NULL,
                        specialist TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN (
                                'running', 'succeeded', 'failed', 'cancelled'
                            )
                        ),
                        input_json TEXT NOT NULL DEFAULT '{}',
                        result_json TEXT,
                        result_sha256 TEXT,
                        error_code TEXT,
                        error_message TEXT,
                        started_at TEXT NOT NULL,
                        completed_at TEXT,
                        PRIMARY KEY (flow_id, sequence),
                        UNIQUE(flow_id, attempt, step_key),
                        FOREIGN KEY (flow_id) REFERENCES agent_flows(flow_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_flow_steps_attempt
                        ON agent_flow_steps(flow_id, attempt, sequence);

                    CREATE TABLE IF NOT EXISTS agent_flow_events (
                        flow_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        event_type TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        PRIMARY KEY (flow_id, sequence),
                        FOREIGN KEY (flow_id) REFERENCES agent_flows(flow_id)
                    );

                    CREATE TABLE IF NOT EXISTS agent_memory_proposals (
                        proposal_id TEXT PRIMARY KEY,
                        scope_type TEXT NOT NULL CHECK (
                            scope_type IN ('user', 'draft', 'mine', 'enterprise')
                        ),
                        scope_id TEXT NOT NULL,
                        memory_key TEXT NOT NULL,
                        value_json TEXT NOT NULL,
                        source_refs_json TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN ('pending', 'approved', 'rejected')
                        ),
                        revision INTEGER NOT NULL CHECK (revision >= 1),
                        proposed_by TEXT NOT NULL,
                        reviewed_by TEXT,
                        reviewed_at TEXT,
                        decision_reason TEXT,
                        proposal_sha256 TEXT NOT NULL,
                        audit_json TEXT NOT NULL,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        event_head_hash TEXT NOT NULL DEFAULT
                            '0000000000000000000000000000000000000000000000000000000000000000',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS agent_memories (
                        memory_id TEXT PRIMARY KEY,
                        scope_type TEXT NOT NULL CHECK (
                            scope_type IN ('user', 'draft', 'mine', 'enterprise')
                        ),
                        scope_id TEXT NOT NULL,
                        memory_key TEXT NOT NULL,
                        version INTEGER NOT NULL CHECK (version >= 1),
                        value_json TEXT NOT NULL,
                        provenance_json TEXT NOT NULL,
                        proposal_id TEXT NOT NULL UNIQUE,
                        status TEXT NOT NULL CHECK (
                            status IN ('active', 'revoked', 'superseded')
                        ),
                        created_by TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        revision INTEGER NOT NULL CHECK (revision >= 1),
                        revoked_by TEXT,
                        revoked_at TEXT,
                        record_sha256 TEXT NOT NULL,
                        UNIQUE(scope_type, scope_id, memory_key, version),
                        FOREIGN KEY (proposal_id)
                            REFERENCES agent_memory_proposals(proposal_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_memories_active_scope
                        ON agent_memories (
                            scope_type, scope_id, memory_key, status, version DESC
                        );

                    CREATE TABLE IF NOT EXISTS agent_skill_proposals (
                        proposal_id TEXT PRIMARY KEY,
                        skill_name TEXT NOT NULL,
                        description TEXT NOT NULL,
                        procedure_json TEXT NOT NULL,
                        allowed_tools_json TEXT NOT NULL,
                        source_refs_json TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN ('pending', 'approved', 'rejected')
                        ),
                        revision INTEGER NOT NULL CHECK (revision >= 1),
                        proposed_by TEXT NOT NULL,
                        reviewed_by TEXT,
                        reviewed_at TEXT,
                        decision_reason TEXT,
                        proposal_sha256 TEXT NOT NULL,
                        audit_json TEXT NOT NULL,
                        event_count INTEGER NOT NULL DEFAULT 0,
                        event_head_hash TEXT NOT NULL DEFAULT
                            '0000000000000000000000000000000000000000000000000000000000000000',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS agent_skill_versions (
                        skill_version_id TEXT PRIMARY KEY,
                        skill_name TEXT NOT NULL,
                        version INTEGER NOT NULL CHECK (version >= 1),
                        description TEXT NOT NULL,
                        procedure_json TEXT NOT NULL,
                        allowed_tools_json TEXT NOT NULL,
                        source_refs_json TEXT NOT NULL,
                        proposal_id TEXT NOT NULL UNIQUE,
                        status TEXT NOT NULL CHECK (
                            status IN ('active', 'retired', 'superseded')
                        ),
                        runtime_activation TEXT NOT NULL CHECK (
                            runtime_activation IN (
                                'proposal_only', 'approved_inactive'
                            )
                        ),
                        approved_by TEXT NOT NULL,
                        approved_at TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        revision INTEGER NOT NULL CHECK (revision >= 1),
                        retired_by TEXT,
                        retired_at TEXT,
                        retirement_reason TEXT,
                        record_sha256 TEXT NOT NULL,
                        UNIQUE(skill_name, version),
                        FOREIGN KEY (proposal_id)
                            REFERENCES agent_skill_proposals(proposal_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_skill_versions_active
                        ON agent_skill_versions (
                            skill_name, status, version DESC
                        );

                    CREATE TABLE IF NOT EXISTS agent_jobs (
                        job_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        client_request_id TEXT,
                        name TEXT NOT NULL,
                        workflow_name TEXT NOT NULL,
                        draft_id TEXT,
                        goal_text TEXT NOT NULL,
                        schedule_kind TEXT NOT NULL CHECK (
                            schedule_kind IN ('daily', 'interval', 'event')
                        ),
                        schedule_json TEXT NOT NULL,
                        enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                        next_run_at TEXT,
                        pending_run_at TEXT,
                        last_run_at TEXT,
                        last_flow_id TEXT,
                        last_error TEXT,
                        revision INTEGER NOT NULL CHECK (revision >= 1),
                        event_count INTEGER NOT NULL DEFAULT 0,
                        event_head_hash TEXT NOT NULL DEFAULT
                            '0000000000000000000000000000000000000000000000000000000000000000',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        deleted_at TEXT,
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_jobs_actor_updated
                        ON agent_jobs(actor_id, updated_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_agent_jobs_due
                        ON agent_jobs(enabled, next_run_at)
                        WHERE deleted_at IS NULL;
                    CREATE UNIQUE INDEX IF NOT EXISTS
                        idx_agent_jobs_client_request
                    ON agent_jobs(actor_id, client_request_id)
                    WHERE client_request_id IS NOT NULL;

                    CREATE TABLE IF NOT EXISTS agent_job_events (
                        job_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL CHECK (sequence >= 1),
                        event_type TEXT NOT NULL,
                        actor_id TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        event_hash TEXT NOT NULL,
                        PRIMARY KEY (job_id, sequence),
                        FOREIGN KEY (job_id) REFERENCES agent_jobs(job_id)
                    );

                    CREATE TABLE IF NOT EXISTS agent_trigger_events (
                        event_id TEXT PRIMARY KEY,
                        actor_id TEXT NOT NULL,
                        client_event_id TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        draft_id TEXT,
                        payload_json TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        matched_jobs_json TEXT,
                        triggered_jobs_json TEXT NOT NULL,
                        record_sha256 TEXT,
                        progress_revision INTEGER NOT NULL DEFAULT 0,
                        progress_sha256 TEXT,
                        occurred_at TEXT NOT NULL,
                        UNIQUE(actor_id, client_event_id),
                        FOREIGN KEY (draft_id) REFERENCES drafts(draft_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_agent_trigger_events_actor_time
                        ON agent_trigger_events(actor_id, occurred_at DESC);

                    CREATE TABLE IF NOT EXISTS agent_trigger_claims (
                        event_id TEXT PRIMARY KEY,
                        owner_id TEXT NOT NULL,
                        lease_expires_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        FOREIGN KEY (event_id)
                            REFERENCES agent_trigger_events(event_id)
                    );

                    CREATE TABLE IF NOT EXISTS connector_request_nonces (
                        client_id TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        request_timestamp INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (client_id, request_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_connector_nonces_created
                        ON connector_request_nonces(created_at);

                    CREATE TABLE IF NOT EXISTS connector_draft_bindings (
                        client_id TEXT NOT NULL,
                        draft_key TEXT NOT NULL,
                        draft_id TEXT NOT NULL UNIQUE,
                        reporting_month TEXT NOT NULL,
                        last_machine_revision INTEGER NOT NULL CHECK (
                            last_machine_revision >= 1
                        ),
                        last_machine_payload_sha256 TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        PRIMARY KEY (client_id, draft_key)
                    );

                    CREATE TABLE IF NOT EXISTS connector_ingestions (
                        ingestion_id TEXT PRIMARY KEY,
                        client_id TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        draft_key TEXT NOT NULL,
                        draft_id TEXT,
                        source_id TEXT NOT NULL,
                        source_revision INTEGER NOT NULL CHECK (
                            source_revision >= 1
                        ),
                        source_name TEXT NOT NULL,
                        source_system TEXT NOT NULL,
                        source_format TEXT NOT NULL CHECK (
                            source_format IN ('json', 'csv')
                        ),
                        original_filename TEXT,
                        source_observed_at TEXT NOT NULL,
                        source_coverage_as_of TEXT,
                        truth_statement INTEGER NOT NULL CHECK (
                            truth_statement = 1
                        ),
                        trigger_workflow INTEGER NOT NULL CHECK (
                            trigger_workflow IN (0, 1)
                        ),
                        workflow_name TEXT NOT NULL CHECK (
                            workflow_name = 'daily_coal_health'
                        ),
                        status TEXT NOT NULL CHECK (
                            status IN ('bound', 'imported', 'completed', 'rejected')
                        ),
                        import_summary_json TEXT,
                        draft_revision INTEGER,
                        draft_payload_sha256 TEXT,
                        workflow_result_json TEXT,
                        failure_json TEXT,
                        result_json TEXT,
                        lease_owner TEXT,
                        lease_expires_at REAL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        completed_at TEXT,
                        UNIQUE (client_id, event_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_connector_ingestions_draft
                        ON connector_ingestions(draft_id, created_at DESC);

                    """
                )
                # Re-check while holding the cross-process migration lock.  A
                # newer binary may have upgraded the file after the optimistic
                # pre-check but before this process acquired the lock.
                current_version = db.execute(
                    """
                    SELECT version FROM app_schema_versions
                    WHERE component = 'enterprise_agent'
                    """
                ).fetchone()
                if (
                    current_version is not None
                    and int(current_version["version"]) > _SCHEMA_VERSION
                ):
                    raise ValueError(
                        "数据库 schema 版本高于当前程序支持版本；"
                        "拒绝由旧程序降级打开"
                    )
                _migrate_connector_schema_v6(db)
                submission_columns = {
                    str(row["name"])
                    for row in db.execute("PRAGMA table_info(submissions)").fetchall()
                }
                if "error_json" not in submission_columns:
                    db.execute("ALTER TABLE submissions ADD COLUMN error_json TEXT")
                run_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(agent_runs)"
                    ).fetchall()
                }
                anchor_added = (
                    "event_count" not in run_columns
                    or "event_head_hash" not in run_columns
                )
                if "event_count" not in run_columns:
                    db.execute(
                        "ALTER TABLE agent_runs ADD COLUMN "
                        "event_count INTEGER NOT NULL DEFAULT 0"
                    )
                if "event_head_hash" not in run_columns:
                    db.execute(
                        "ALTER TABLE agent_runs ADD COLUMN event_head_hash "
                        "TEXT NOT NULL DEFAULT "
                        "'0000000000000000000000000000000000000000000000000000000000000000'"
                    )
                if anchor_added:
                    db.execute(
                        """
                        UPDATE agent_runs
                        SET event_count = (
                            SELECT COUNT(*) FROM agent_run_events AS e
                            WHERE e.run_id = agent_runs.run_id
                        ),
                        event_head_hash = COALESCE((
                            SELECT e.event_hash
                            FROM agent_run_events AS e
                            WHERE e.run_id = agent_runs.run_id
                            ORDER BY e.sequence DESC LIMIT 1
                        ), ?)
                        """,
                        ("0" * 64,),
                    )
                call_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(agent_tool_calls)"
                    ).fetchall()
                }
                if "tool_spec_sha256" not in call_columns:
                    db.execute(
                        "ALTER TABLE agent_tool_calls ADD COLUMN "
                        "tool_spec_sha256 TEXT NOT NULL DEFAULT ''"
                    )
                if "evidence_grounding" not in call_columns:
                    db.execute(
                        "ALTER TABLE agent_tool_calls ADD COLUMN "
                        "evidence_grounding TEXT NOT NULL DEFAULT 'user_supplied'"
                    )
                approval_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(agent_approvals)"
                    ).fetchall()
                }
                if "tool_spec_sha256" not in approval_columns:
                    db.execute(
                        "ALTER TABLE agent_approvals ADD COLUMN "
                        "tool_spec_sha256 TEXT NOT NULL DEFAULT ''"
                    )
                if "harness_version" not in approval_columns:
                    db.execute(
                        "ALTER TABLE agent_approvals ADD COLUMN "
                        "harness_version TEXT NOT NULL DEFAULT ''"
                    )
                chat_session_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(chat_sessions)"
                    ).fetchall()
                }
                if "deleted_at" not in chat_session_columns:
                    db.execute(
                        "ALTER TABLE chat_sessions ADD COLUMN deleted_at TEXT"
                    )
                if "event_count" not in chat_session_columns:
                    db.execute(
                        "ALTER TABLE chat_sessions ADD COLUMN "
                        "event_count INTEGER NOT NULL DEFAULT 0"
                    )
                if "event_head_hash" not in chat_session_columns:
                    db.execute(
                        "ALTER TABLE chat_sessions ADD COLUMN event_head_hash "
                        "TEXT NOT NULL DEFAULT "
                        "'0000000000000000000000000000000000000000000000000000000000000000'"
                    )
                if "client_request_id" not in chat_session_columns:
                    db.execute(
                        "ALTER TABLE chat_sessions "
                        "ADD COLUMN client_request_id TEXT"
                    )
                if "context_draft_id" not in chat_session_columns:
                    db.execute(
                        "ALTER TABLE chat_sessions "
                        "ADD COLUMN context_draft_id TEXT"
                    )
                db.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                        idx_chat_sessions_client_request
                    ON chat_sessions(actor_id, client_request_id)
                    WHERE client_request_id IS NOT NULL
                    """
                )
                chat_message_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(chat_messages)"
                    ).fetchall()
                }
                if "client_message_id" not in chat_message_columns:
                    db.execute(
                        "ALTER TABLE chat_messages "
                        "ADD COLUMN client_message_id TEXT"
                    )
                db.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS
                        idx_chat_messages_client_id
                    ON chat_messages(session_id, client_message_id)
                    WHERE client_message_id IS NOT NULL
                    """
                )
                job_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(agent_jobs)"
                    ).fetchall()
                }
                if "pending_run_at" not in job_columns:
                    db.execute(
                        "ALTER TABLE agent_jobs "
                        "ADD COLUMN pending_run_at TEXT"
                    )
                trigger_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(agent_trigger_events)"
                    ).fetchall()
                }
                if "matched_jobs_json" not in trigger_columns:
                    db.execute(
                        "ALTER TABLE agent_trigger_events "
                        "ADD COLUMN matched_jobs_json TEXT"
                    )
                if "record_sha256" not in trigger_columns:
                    db.execute(
                        "ALTER TABLE agent_trigger_events "
                        "ADD COLUMN record_sha256 TEXT"
                    )
                if "progress_revision" not in trigger_columns:
                    db.execute(
                        "ALTER TABLE agent_trigger_events "
                        "ADD COLUMN progress_revision INTEGER "
                        "NOT NULL DEFAULT 0"
                    )
                if "progress_sha256" not in trigger_columns:
                    db.execute(
                        "ALTER TABLE agent_trigger_events "
                        "ADD COLUMN progress_sha256 TEXT"
                    )
                flow_columns = {
                    str(row["name"])
                    for row in db.execute(
                        "PRAGMA table_info(agent_flows)"
                    ).fetchall()
                }
                if "run_owner" not in flow_columns:
                    db.execute(
                        "ALTER TABLE agent_flows ADD COLUMN run_owner TEXT"
                    )
                if "lease_expires_at" not in flow_columns:
                    db.execute(
                        "ALTER TABLE agent_flows "
                        "ADD COLUMN lease_expires_at TEXT"
                    )
                if "dispatch_ready" not in flow_columns:
                    db.execute(
                        "ALTER TABLE agent_flows ADD COLUMN dispatch_ready "
                        "INTEGER NOT NULL DEFAULT 1"
                    )
                governance_columns: dict[str, dict[str, str]] = {
                    "agent_memory_proposals": {
                        "reviewed_by": "TEXT",
                        "reviewed_at": "TEXT",
                        "decision_reason": "TEXT",
                        "proposal_sha256": "TEXT NOT NULL DEFAULT ''",
                        "audit_json": "TEXT NOT NULL DEFAULT '[]'",
                        "event_count": "INTEGER NOT NULL DEFAULT 0",
                        "event_head_hash": (
                            "TEXT NOT NULL DEFAULT '" + ("0" * 64) + "'"
                        ),
                        "updated_at": "TEXT NOT NULL DEFAULT ''",
                    },
                    "agent_memories": {
                        "provenance_json": "TEXT NOT NULL DEFAULT '{}'",
                        "revision": "INTEGER NOT NULL DEFAULT 1",
                        "revoked_by": "TEXT",
                        "revoked_at": "TEXT",
                        "record_sha256": "TEXT NOT NULL DEFAULT ''",
                        "updated_at": "TEXT NOT NULL DEFAULT ''",
                    },
                    "agent_skill_proposals": {
                        "reviewed_by": "TEXT",
                        "reviewed_at": "TEXT",
                        "decision_reason": "TEXT",
                        "proposal_sha256": "TEXT NOT NULL DEFAULT ''",
                        "audit_json": "TEXT NOT NULL DEFAULT '[]'",
                        "event_count": "INTEGER NOT NULL DEFAULT 0",
                        "event_head_hash": (
                            "TEXT NOT NULL DEFAULT '" + ("0" * 64) + "'"
                        ),
                        "updated_at": "TEXT NOT NULL DEFAULT ''",
                    },
                    "agent_skill_versions": {
                        "runtime_activation": (
                            "TEXT NOT NULL DEFAULT 'approved_inactive'"
                        ),
                        "revision": "INTEGER NOT NULL DEFAULT 1",
                        "retired_by": "TEXT",
                        "retired_at": "TEXT",
                        "retirement_reason": "TEXT",
                        "record_sha256": "TEXT NOT NULL DEFAULT ''",
                        "updated_at": "TEXT NOT NULL DEFAULT ''",
                    },
                }
                for table, expected_columns in governance_columns.items():
                    existing = {
                        str(row["name"])
                        for row in db.execute(
                            f"PRAGMA table_info({table})"
                        ).fetchall()
                    }
                    for column, definition in expected_columns.items():
                        if column not in existing:
                            db.execute(
                                f"ALTER TABLE {table} "
                                f"ADD COLUMN {column} {definition}"
                            )
                if (
                    opening_schema_version >= 4
                    and not _draft_audit_triggers_intact(db)
                ):
                    raise ValueError(
                        "草稿审计防篡改触发器缺失或被替换，拒绝启动"
                    )
                _install_schema_guards(db)
                if not _draft_audit_triggers_intact(db):
                    # CREATE TRIGGER IF NOT EXISTS must never turn a same-name
                    # no-op/replacement trigger into an accepted migration.
                    raise ValueError(
                        "草稿审计防篡改触发器缺失、被替换或存在额外副作用，拒绝启动"
                    )
                if opening_schema_version < 9:
                    # Anchor each already validated complete chain exactly once
                    # so deleting a valid tail can no longer look valid.
                    draft_ids = db.execute(
                        "SELECT draft_id FROM drafts ORDER BY draft_id"
                    ).fetchall()
                    for draft_row in draft_ids:
                        integrity = self._draft_audit_integrity_in_transaction(
                            db,
                            str(draft_row["draft_id"]),
                            require_anchor=False,
                        )
                        if not integrity["valid"]:
                            raise ValueError(
                                "历史草稿审计链不完整，拒绝建立正式审计锚点"
                            )
                        db.execute(
                            "INSERT OR REPLACE INTO draft_audit_anchors("
                            "draft_id,event_count,head_hash,updated_at) "
                            "VALUES (?,?,?,?)",
                            (
                                draft_row["draft_id"],
                                integrity["event_count"],
                                integrity["head_hash"],
                                utc_text(),
                            ),
                        )
                # These indexes reference columns introduced by the migration,
                # so they must be created only after the ALTER statements.
                db.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                        idx_agent_memory_proposals_scope
                    ON agent_memory_proposals (
                        scope_type, scope_id, updated_at DESC
                    )
                    """
                )
                db.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                        idx_agent_memory_proposals_actor
                    ON agent_memory_proposals (
                        proposed_by, status, updated_at DESC
                    )
                    """
                )
                db.execute(
                    """
                    CREATE INDEX IF NOT EXISTS
                        idx_agent_skill_proposals_actor
                    ON agent_skill_proposals (
                        proposed_by, status, updated_at DESC
                    )
                    """
                )
                db.execute(
                    """
                    INSERT INTO app_schema_versions (
                        component, version, updated_at
                    ) VALUES ('enterprise_agent', ?, ?)
                    ON CONFLICT(component) DO UPDATE SET
                        version = excluded.version,
                        updated_at = excluded.updated_at
                    WHERE app_schema_versions.version < excluded.version
                    """,
                    (_SCHEMA_VERSION, utc_text()),
                )
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    with suppress(sqlite3.Error):
                        db.execute("ROLLBACK")
                raise
            finally:
                if self._memory_connection is None:
                    db.close()

    @staticmethod
    def _row(
        row: sqlite3.Row,
        submission: sqlite3.Row | None = None,
    ) -> dict[str, Any]:
        document = json.loads(row["document_json"])
        confirmation = (
            json.loads(row["confirmation_json"])
            if row["confirmation_json"] is not None
            else None
        )
        submitted = submission is not None and submission["status"] == "succeeded"
        receipt = (
            json.loads(submission["receipt_json"])
            if submitted and submission["receipt_json"] is not None
            else None
        )
        confirmed = (
            row["confirmed_revision"] == row["revision"] and confirmation is not None
        )
        status = "submitted" if submitted else ("confirmed" if confirmed else "draft")
        return {
            **document,
            "status": status,
            "receipt": receipt,
            "_meta": {
                "revision": row["revision"],
                "confirmed_revision": row["confirmed_revision"],
                "confirmed": confirmed,
                "confirmation": confirmation,
                "submitted": submitted,
                "latest_submission": (
                    {
                        "idempotency_key": submission["idempotency_key"],
                        "status": submission["status"],
                        "request_sha256": submission["request_sha256"],
                        "updated_at": submission["updated_at"],
                    }
                    if submission is not None
                    else None
                ),
                "deleted": row["deleted_at"] is not None,
                "deleted_at": row["deleted_at"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            },
        }

    @staticmethod
    def _append_audit(
        db: sqlite3.Connection,
        *,
        draft_id: str,
        event_type: str,
        actor: str,
        details: dict[str, Any],
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        last = db.execute(
            """
            SELECT sequence, event_hash
            FROM draft_audit
            WHERE draft_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (draft_id,),
        ).fetchone()
        anchor = db.execute(
            "SELECT 1 FROM draft_audit_anchors WHERE draft_id=?", (draft_id,)
        ).fetchone()
        if last is not None or anchor is not None:
            integrity = Repository._draft_audit_integrity_in_transaction(db, draft_id)
            if not integrity["valid"]:
                raise ConflictError(
                    "草稿审计链或防篡改锚点异常，已拒绝追加事件"
                )
        sequence = int(last["sequence"]) + 1 if last else 1
        previous_hash = str(last["event_hash"]) if last else "0" * 64
        timestamp = occurred_at or utc_text()
        event = {
            "draft_id": draft_id,
            "sequence": sequence,
            "event_type": event_type,
            "actor": actor,
            "occurred_at": timestamp,
            "details": details,
            "previous_hash": previous_hash,
        }
        event_hash = sha256_json(event)
        db.execute(
            """
            INSERT INTO draft_audit (
                draft_id, sequence, event_type, actor, occurred_at,
                details_json, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                draft_id,
                sequence,
                event_type,
                actor,
                timestamp,
                canonical_json(details),
                previous_hash,
                event_hash,
            ),
        )
        db.execute(
            """
            INSERT INTO draft_audit_anchors(
                draft_id,event_count,head_hash,updated_at
            ) VALUES (?,?,?,?)
            ON CONFLICT(draft_id) DO UPDATE SET
                event_count=excluded.event_count,
                head_hash=excluded.head_hash,
                updated_at=excluded.updated_at
            """,
            (draft_id, sequence, event_hash, timestamp),
        )
        return {**event, "event_hash": event_hash}

    def create_draft(self, document: dict[str, Any], *, actor: str) -> dict[str, Any]:
        now = utc_text()
        draft_id = document["draft_id"]
        with self._transaction() as db:
            try:
                db.execute(
                    """
                    INSERT INTO drafts (
                        draft_id, document_json, revision,
                        created_at, updated_at
                    ) VALUES (?, ?, 1, ?, ?)
                    """,
                    (draft_id, canonical_json(document), now, now),
                )
            except sqlite3.IntegrityError as error:
                raise ConflictError("草稿编号已存在") from error
            self._append_audit(
                db,
                draft_id=draft_id,
                event_type="draft_created",
                actor=actor,
                details={"document_sha256": sha256_json(document), "revision": 1},
                occurred_at=now,
            )
            row = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
        assert row is not None
        return self._row(row)

    def register_connector_request(
        self,
        *,
        client_id: str,
        request_id: str,
        request_sha256: str,
        request_timestamp: int,
    ) -> None:
        """Persist replay protection before interpreting connector payloads.

        ``request_id`` is a per-attempt nonce, while the payload ``event_id`` is
        the durable business idempotency key. Even byte-identical HTTP replays
        are rejected; a lost-response retry uses a fresh signed request ID.
        """

        now = utc_text()
        retention_cutoff = utc_text(utc_now() - timedelta(days=30))
        with self._transaction() as db:
            # Replay checks need to outlive the largest accepted clock window,
            # while bounded retention prevents an authenticated noisy client
            # from growing this narrow security table forever. Event IDs remain
            # durable without expiry in connector_ingestions.
            db.execute(
                "DELETE FROM connector_request_nonces WHERE created_at < ?",
                (retention_cutoff,),
            )
            previous = db.execute(
                """
                SELECT request_sha256, request_timestamp
                FROM connector_request_nonces
                WHERE client_id = ? AND request_id = ?
                """,
                (client_id, request_id),
            ).fetchone()
            if previous is not None:
                raise ConflictError("机器请求编号已使用，请以新 request_id 重试")
            db.execute(
                """
                INSERT INTO connector_request_nonces (
                    client_id, request_id, request_sha256,
                    request_timestamp, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    request_id,
                    request_sha256,
                    request_timestamp,
                    now,
                ),
            )

    def record_connector_source_health(
        self,
        *,
        client_id: str,
        request_sha256: str,
        payload: dict[str, Any],
        source_required: bool,
        freshness_max_seconds: int,
    ) -> tuple[dict[str, Any], bool]:
        """Persist one status-only event and monotonically update current health."""

        now = utc_text()
        retention_cutoff = utc_text(
            utc_now() - timedelta(days=_CONNECTOR_HEALTH_EVENT_RETENTION_DAYS)
        )
        ten_minute_cutoff = utc_text(utc_now() - timedelta(minutes=10))
        day_cutoff = utc_text(utc_now() - timedelta(days=1))
        with self._transaction() as db:
            existing = db.execute(
                """
                SELECT request_sha256,result_json
                FROM connector_source_health_events
                WHERE client_id=? AND event_id=?
                """,
                (client_id, payload["event_id"]),
            ).fetchone()
            if existing is not None:
                if str(existing["request_sha256"]) != request_sha256:
                    raise ConflictError("health event_id 已用于不同请求")
                result = json.loads(existing["result_json"])
                result["idempotent_replay"] = True
                return result, False
            recent = db.execute(
                """
                SELECT
                    SUM(CASE WHEN created_at>=? THEN 1 ELSE 0 END)
                        AS ten_minute_count,
                    COUNT(*) AS day_count
                FROM connector_source_health_events
                WHERE client_id=? AND created_at>=?
                """,
                (ten_minute_cutoff, client_id, day_cutoff),
            ).fetchone()
            if (
                int(recent["ten_minute_count"] or 0)
                >= _CONNECTOR_HEALTH_EVENTS_PER_TEN_MINUTES
                or int(recent["day_count"] or 0)
                >= _CONNECTOR_HEALTH_EVENTS_PER_DAY
            ):
                raise ConnectorQuotaExceededError(
                    "机器来源健康事件速率超过受控配额，请稍后重试"
                )
            current_key = db.execute(
                """
                SELECT 1 FROM connector_source_health
                WHERE client_id=? AND draft_key=? AND source_id=?
                """,
                (client_id, payload["draft_key"], payload["source_id"]),
            ).fetchone()
            if current_key is None:
                key_count = db.execute(
                    """
                    SELECT COUNT(DISTINCT draft_key) AS value
                    FROM connector_source_health WHERE client_id=?
                    """,
                    (client_id,),
                ).fetchone()
                if int(key_count["value"] or 0) >= _CONNECTOR_MAX_MONTH_BINDINGS:
                    raise ConnectorQuotaExceededError(
                        "机器来源健康历史月份数量超过受控配额"
                    )
            applied = _apply_connector_source_health(
                db,
                client_id=client_id,
                draft_key=payload["draft_key"],
                reporting_month=payload["reporting_month"],
                source_id=payload["source_id"],
                source_system=payload["source_system"],
                required=source_required,
                freshness_max_seconds=freshness_max_seconds,
                outcome=payload["outcome"],
                attempted_at=payload["attempted_at"],
                completed_at=payload["completed_at"],
                record_count=payload["record_count"],
                coverage_as_of=payload["coverage_as_of"],
                error_code=payload["error_code"],
                snapshot_sha256=payload["snapshot_sha256"],
                autofill_event_id=payload["autofill_event_id"],
                source_revision=payload["source_revision"],
                event_id=payload["event_id"],
                updated_at=now,
            )
            result = {
                "contract_version": "enterprise-source-health-result/v1",
                "event_id": payload["event_id"],
                "source_id": payload["source_id"],
                "outcome": payload["outcome"],
                "completed_at": payload["completed_at"],
                "status": "recorded",
                "applied": applied,
                "idempotent_replay": False,
            }
            db.execute(
                """
                INSERT INTO connector_source_health_events(
                    client_id,event_id,request_sha256,draft_key,
                    reporting_month,source_id,source_system,outcome,
                    attempted_at,completed_at,record_count,coverage_as_of,
                    error_code,snapshot_sha256,autofill_event_id,
                    source_revision,applied,result_json,created_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    client_id,
                    payload["event_id"],
                    request_sha256,
                    payload["draft_key"],
                    payload["reporting_month"],
                    payload["source_id"],
                    payload["source_system"],
                    payload["outcome"],
                    payload["attempted_at"],
                    payload["completed_at"],
                    payload["record_count"],
                    payload["coverage_as_of"],
                    payload["error_code"],
                    payload["snapshot_sha256"],
                    payload["autofill_event_id"],
                    payload["source_revision"],
                    int(applied),
                    canonical_json(result),
                    now,
                ),
            )
            db.execute(
                "DELETE FROM connector_source_health_events "
                "WHERE created_at<? AND NOT (client_id=? AND event_id=?)",
                (retention_cutoff, client_id, payload["event_id"]),
            )
        return result, True

    @staticmethod
    def apply_connector_snapshot_health_in_transaction(
        db: sqlite3.Connection,
        *,
        client_id: str,
        draft_key: str,
        reporting_month: str,
        source_id: str,
        source_system: str,
        source_required: bool,
        freshness_max_seconds: int,
        completed_at: str,
        record_count: int,
        coverage_as_of: str,
        snapshot_sha256: str,
        autofill_event_id: str,
        source_revision: int,
        ingestion_id: str,
        received_at: str,
    ) -> bool:
        return _apply_connector_source_health(
            db,
            client_id=client_id,
            draft_key=draft_key,
            reporting_month=reporting_month,
            source_id=source_id,
            source_system=source_system,
            required=source_required,
            freshness_max_seconds=freshness_max_seconds,
            outcome="success_nonempty",
            attempted_at=completed_at,
            completed_at=completed_at,
            record_count=record_count,
            coverage_as_of=coverage_as_of,
            error_code=None,
            snapshot_sha256=snapshot_sha256,
            autofill_event_id=autofill_event_id,
            source_revision=source_revision,
            event_id=f"autofill:{ingestion_id}",
            updated_at=received_at,
        )

    def connector_source_health_for_draft(
        self,
        draft_id: str,
        *,
        policies: tuple[dict[str, Any], ...],
        now_epoch: float | None = None,
    ) -> dict[str, Any]:
        """Calculate dynamic freshness from controlled TTLs at read time."""

        current_epoch = time.time() if now_epoch is None else float(now_epoch)
        with self._read() as db:
            return self.connector_source_health_for_draft_in_transaction(
                db,
                draft_id,
                policies=policies,
                now_epoch=current_epoch,
            )

    @staticmethod
    def connector_source_health_for_draft_in_transaction(
        db: sqlite3.Connection,
        draft_id: str,
        *,
        policies: tuple[dict[str, Any], ...],
        now_epoch: float,
    ) -> dict[str, Any]:
        """Evaluate source health inside an existing consistency boundary."""

        draft = db.execute(
            "SELECT payload_json FROM fq_drafts WHERE draft_id=?",
            (draft_id,),
        ).fetchone()
        if draft is None:
            raise NotFoundError("报送草稿不存在")
        binding = db.execute(
            "SELECT * FROM connector_draft_bindings WHERE draft_id=?",
            (draft_id,),
        ).fetchone()
        if binding is None:
            return {
                "source_health": [],
                "freshness": {
                    "overall_state": "not_applicable",
                    "stale_required_source_ids": [],
                },
            }
        rows = db.execute(
            """
            SELECT * FROM connector_source_health
            WHERE client_id=? AND draft_key=?
            """,
            (binding["client_id"], binding["draft_key"]),
        ).fetchall()
        contribution_rows = db.execute(
            """
            SELECT contribution.*,ingestion.status AS ingestion_status,
                ingestion.source_system AS ingestion_source_system,
                ingestion.source_name AS ingestion_source_name
            FROM fq_machine_source_contributions AS contribution
            LEFT JOIN connector_ingestions AS ingestion
                ON ingestion.ingestion_id=contribution.ingestion_id
            WHERE contribution.client_id=?
                AND contribution.draft_key=?
                AND contribution.draft_id=?
            """,
            (binding["client_id"], binding["draft_key"], draft_id),
        ).fetchall()
        return _evaluate_connector_source_health(
            draft_payload_json=str(draft["payload_json"]),
            rows=rows,
            contribution_rows=contribution_rows,
            policies=policies,
            current_epoch=now_epoch,
        )

    @staticmethod
    def _connector_ingestion_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "ingestion_id": str(row["ingestion_id"]),
            "client_id": str(row["client_id"]),
            "event_id": str(row["event_id"]),
            "request_sha256": str(row["request_sha256"]),
            "draft_key": str(row["draft_key"]),
            "draft_id": str(row["draft_id"]) if row["draft_id"] else None,
            "source_id": str(row["source_id"]),
            "source_revision": int(row["source_revision"]),
            "source_name": str(row["source_name"]),
            "source_system": str(row["source_system"]),
            "format": str(row["source_format"]),
            "original_filename": row["original_filename"],
            "source_observed_at": str(row["source_observed_at"]),
            "source_coverage_as_of": row["source_coverage_as_of"],
            "truth_statement": bool(row["truth_statement"]),
            "trigger_workflow": bool(row["trigger_workflow"]),
            "workflow_name": str(row["workflow_name"]),
            "status": str(row["status"]),
            "import_summary": (
                json.loads(row["import_summary_json"])
                if row["import_summary_json"] is not None
                else None
            ),
            "draft_revision": row["draft_revision"],
            "draft_payload_sha256": row["draft_payload_sha256"],
            "workflow_result": (
                json.loads(row["workflow_result_json"])
                if row["workflow_result_json"] is not None
                else None
            ),
            "failure": (
                json.loads(row["failure_json"])
                if row["failure_json"] is not None
                else None
            ),
            "result": (
                json.loads(row["result_json"])
                if row["result_json"] is not None
                else None
            ),
            "lease_owner": row["lease_owner"],
            "lease_expires_at": row["lease_expires_at"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "completed_at": row["completed_at"],
        }

    def claim_connector_ingestion(
        self,
        *,
        client_id: str,
        event_id: str,
        request_sha256: str,
        draft_key: str,
        source: dict[str, Any],
        trigger_workflow: bool,
        workflow_name: str,
        lease_owner: str,
        lease_seconds: int = 120,
    ) -> tuple[dict[str, Any], bool, bool]:
        """Create/bind once and lease one ingestion stage across processes."""

        now_text = utc_text()
        now_epoch = time.time()
        expires_at = now_epoch + lease_seconds
        ingestion_id = str(uuid.uuid4())
        created = False
        acquired = False
        with self._transaction() as db:
            row = db.execute(
                """
                SELECT * FROM connector_ingestions
                WHERE client_id = ? AND event_id = ?
                """,
                (client_id, event_id),
            ).fetchone()
            if row is not None:
                if str(row["request_sha256"]) != request_sha256:
                    raise ConflictError("event_id 已用于不同自动填报请求")
                if str(row["status"]) in {"completed", "rejected"}:
                    return self._connector_ingestion_row(row), False, False
                lease_expired = (
                    row["lease_owner"] is None
                    or row["lease_expires_at"] is None
                    or float(row["lease_expires_at"]) <= now_epoch
                )
                if lease_expired:
                    db.execute(
                        """
                        UPDATE connector_ingestions
                        SET lease_owner = ?, lease_expires_at = ?, updated_at = ?
                        WHERE ingestion_id = ?
                        """,
                        (lease_owner, expires_at, now_text, row["ingestion_id"]),
                    )
                    acquired = True
            else:
                ten_minute_cutoff = utc_text(
                    utc_now() - timedelta(minutes=10)
                )
                day_cutoff = utc_text(utc_now() - timedelta(days=1))
                recent = db.execute(
                    """
                    SELECT
                        SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END)
                            AS ten_minute_count,
                        COUNT(*) AS day_count
                    FROM connector_ingestions
                    WHERE client_id = ? AND created_at >= ?
                    """,
                    (ten_minute_cutoff, client_id, day_cutoff),
                ).fetchone()
                if (
                    int(recent["ten_minute_count"] or 0)
                    >= _CONNECTOR_EVENTS_PER_TEN_MINUTES
                    or int(recent["day_count"] or 0)
                    >= _CONNECTOR_EVENTS_PER_DAY
                ):
                    raise ConnectorQuotaExceededError(
                        "机器连接器新事件速率超过受控配额，请稍后重试"
                    )
                binding = db.execute(
                    """
                    SELECT 1 FROM connector_draft_bindings
                    WHERE client_id = ? AND draft_key = ?
                    """,
                    (client_id, draft_key),
                ).fetchone()
                if binding is None:
                    binding_count = db.execute(
                        "SELECT COUNT(*) AS value "
                        "FROM connector_draft_bindings WHERE client_id = ?",
                        (client_id,),
                    ).fetchone()
                    if (
                        int(binding_count["value"])
                        >= _CONNECTOR_MAX_MONTH_BINDINGS
                    ):
                        raise ConnectorQuotaExceededError(
                            "机器连接器历史月份草稿数量超过受控配额"
                        )
                if _sqlite_table_exists(
                    db, "fq_machine_source_contributions"
                ):
                    existing_source = db.execute(
                        """
                        SELECT 1 FROM fq_machine_source_contributions
                        WHERE client_id = ? AND draft_key = ? AND source_id = ?
                        """,
                        (client_id, draft_key, source["source_id"]),
                    ).fetchone()
                    if existing_source is None:
                        source_count = db.execute(
                            """
                            SELECT COUNT(*) AS value
                            FROM fq_machine_source_contributions
                            WHERE client_id = ? AND draft_key = ?
                            """,
                            (client_id, draft_key),
                        ).fetchone()
                        if (
                            int(source_count["value"])
                            >= _CONNECTOR_MAX_SOURCES_PER_DRAFT
                        ):
                            raise ConnectorQuotaExceededError(
                                "该月机器草稿的唯一来源数量超过受控配额"
                            )
                db.execute(
                    """
                    INSERT INTO connector_ingestions (
                        ingestion_id, client_id, event_id, request_sha256,
                        draft_key, source_id, source_revision,
                        source_name, source_system, source_format,
                        original_filename, source_observed_at,
                        source_coverage_as_of, truth_statement,
                        trigger_workflow, workflow_name, status,
                        lease_owner, lease_expires_at, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'bound',
                        ?, ?, ?, ?
                    )
                    """,
                    (
                        ingestion_id,
                        client_id,
                        event_id,
                        request_sha256,
                        draft_key,
                        source["source_id"],
                        source["revision"],
                        source["source_name"],
                        source["source_system"],
                        source["format"],
                        source["original_filename"],
                        source["observed_at"],
                        source["coverage_as_of"],
                        int(trigger_workflow),
                        workflow_name,
                        lease_owner,
                        expires_at,
                        now_text,
                        now_text,
                    ),
                )
                created = True
                acquired = True
            selected = db.execute(
                """
                SELECT * FROM connector_ingestions
                WHERE client_id = ? AND event_id = ?
                """,
                (client_id, event_id),
            ).fetchone()
        assert selected is not None
        return self._connector_ingestion_row(selected), acquired, created

    def get_connector_ingestion(self, ingestion_id: str) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute(
                "SELECT * FROM connector_ingestions WHERE ingestion_id = ?",
                (ingestion_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("机器自动填报事件不存在")
        return self._connector_ingestion_row(row)

    def complete_connector_ingestion(
        self,
        ingestion_id: str,
        *,
        lease_owner: str,
        result: dict[str, Any],
    ) -> None:
        now = utc_text()
        with self._transaction() as db:
            updated = db.execute(
                """
                UPDATE connector_ingestions
                SET status = 'completed', result_json = ?,
                    lease_owner = NULL, lease_expires_at = NULL,
                    updated_at = ?, completed_at = ?
                WHERE ingestion_id = ? AND status = 'imported'
                    AND lease_owner = ?
                """,
                (
                    canonical_json(result),
                    now,
                    now,
                    ingestion_id,
                    lease_owner,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("机器自动填报租约已失效，请重试")

    def release_connector_ingestion(
        self,
        ingestion_id: str,
        *,
        lease_owner: str,
    ) -> None:
        with self._transaction() as db:
            db.execute(
                """
                UPDATE connector_ingestions
                SET lease_owner = NULL, lease_expires_at = NULL, updated_at = ?
                WHERE ingestion_id = ? AND lease_owner = ?
                    AND status != 'completed'
                """,
                (utc_text(), ingestion_id, lease_owner),
            )

    def reject_connector_ingestion(
        self,
        ingestion_id: str,
        *,
        lease_owner: str,
        failure: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist a safe terminal business rejection without changing a draft."""

        now = utc_text()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM connector_ingestions WHERE ingestion_id = ?",
                (ingestion_id,),
            ).fetchone()
            if row is None or row["lease_owner"] != lease_owner:
                raise ConflictError("机器自动填报租约已失效")
            binding = db.execute(
                """
                SELECT draft_id FROM connector_draft_bindings
                WHERE client_id = ? AND draft_key = ?
                """,
                (row["client_id"], row["draft_key"]),
            ).fetchone()
            draft_id = str(binding["draft_id"]) if binding is not None else None
            updated = db.execute(
                """
                UPDATE connector_ingestions
                SET status = 'rejected', draft_id = ?, failure_json = ?,
                    lease_owner = NULL, lease_expires_at = NULL,
                    updated_at = ?, completed_at = ?
                WHERE ingestion_id = ? AND lease_owner = ?
                    AND status IN ('bound', 'imported')
                """,
                (
                    draft_id,
                    canonical_json(failure),
                    now,
                    now,
                    ingestion_id,
                    lease_owner,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("机器自动填报状态已变化")
            selected = db.execute(
                "SELECT * FROM connector_ingestions WHERE ingestion_id = ?",
                (ingestion_id,),
            ).fetchone()
        assert selected is not None
        return self._connector_ingestion_row(selected)

    def connector_ingestions_for_draft(
        self,
        draft_id: str,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        bounded = min(max(int(limit), 1), 200)
        with self._read() as db:
            draft = db.execute(
                "SELECT 1 FROM fq_drafts WHERE draft_id = ?",
                (draft_id,),
            ).fetchone()
            if draft is None:
                raise NotFoundError("报送草稿不存在")
            rows = db.execute(
                """
                SELECT * FROM connector_ingestions
                WHERE draft_id = ?
                ORDER BY created_at DESC, ingestion_id DESC
                LIMIT ?
                """,
                (draft_id, bounded),
            ).fetchall()
        return [
            {
                "ingestion_id": str(row["ingestion_id"]),
                "client_id": str(row["client_id"]),
                "event_id": str(row["event_id"]),
                "source_id": str(row["source_id"]),
                "source_revision": int(row["source_revision"]),
                "source_name": str(row["source_name"]),
                "source_system": str(row["source_system"]),
                "format": str(row["source_format"]),
                "original_filename": row["original_filename"],
                "observed_at": str(row["source_observed_at"]),
                "coverage_as_of": row["source_coverage_as_of"],
                "status": str(row["status"]),
                "request_sha256_prefix": str(row["request_sha256"])[:12],
                "request_hash": str(row["request_sha256"])[:12],
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "imported_at": str(row["updated_at"]),
                "completed_at": row["completed_at"],
                "processed_at": row["completed_at"],
                "trigger_workflow": bool(row["trigger_workflow"]),
                "workflow_name": str(row["workflow_name"]),
                "draft_revision": row["draft_revision"],
                "preflight": (
                    self._public_connector_preflight(row["workflow_result_json"])
                ),
                "rejection": (
                    self._public_connector_failure(row["failure_json"])
                ),
            }
            for row in rows
        ]

    @staticmethod
    def _public_connector_preflight(raw: str | None) -> dict[str, Any] | None:
        if raw is None:
            return None
        value = json.loads(raw)
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
    def _public_connector_failure(raw: str | None) -> dict[str, Any] | None:
        if raw is None:
            return None
        value = json.loads(raw)
        if not isinstance(value, dict):
            return None
        return {
            "code": value.get("code"),
            "message": value.get("message"),
            "http_status": value.get("http_status"),
            "source_id": value.get("source_id"),
            "source_revision": value.get("source_revision"),
            "recorded_at": value.get("recorded_at"),
        }

    def list_drafts(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        bounded = min(max(int(limit), 1), 1000)
        start = max(int(offset), 0)
        where = "" if include_deleted else "WHERE deleted_at IS NULL"
        with self._read() as db:
            rows = db.execute(
                f"""
                SELECT * FROM drafts
                {where}
                ORDER BY updated_at DESC, draft_id ASC
                LIMIT ? OFFSET ?
                """,
                (bounded, start),
            ).fetchall()
            results: list[dict[str, Any]] = []
            for row in rows:
                submission = db.execute(
                    """
                    SELECT * FROM submissions
                    WHERE draft_id = ?
                    ORDER BY
                        CASE status WHEN 'succeeded' THEN 0 ELSE 1 END,
                        created_at DESC
                    LIMIT 1
                    """,
                    (row["draft_id"],),
                ).fetchone()
                results.append(self._row(row, submission))
        return results

    @staticmethod
    def _draft_summary(
        row: sqlite3.Row,
        submission: sqlite3.Row | None,
    ) -> dict[str, Any]:
        full = Repository._row(row, submission)
        receipt = full.get("receipt")
        receipt_summary = (
            {
                key: receipt[key]
                for key in (
                    "receipt_id",
                    "received_at",
                    "status",
                    "regulatory_outcome",
                )
                if key in receipt
            }
            if isinstance(receipt, dict)
            else None
        )
        observations = full.get("observations")
        meta = full["_meta"]
        return {
            "draft_id": full["draft_id"],
            "status": full["status"],
            "enterprise_id": full.get("enterprise_id"),
            "enterprise_name": full.get("enterprise_name"),
            "mine_id": full.get("mine_id"),
            "mine_name": full.get("mine_name"),
            "window_start": full.get("window_start"),
            "window_end": full.get("window_end"),
            "observation_count": (
                len(observations) if isinstance(observations, list) else 0
            ),
            "receipt": receipt_summary,
            "_meta": {
                "revision": meta["revision"],
                "confirmed_revision": meta["confirmed_revision"],
                "confirmed": meta["confirmed"],
                "submitted": meta["submitted"],
                "latest_submission": meta["latest_submission"],
                "created_at": meta["created_at"],
                "updated_at": meta["updated_at"],
            },
        }

    def draft_summary_page(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        bounded = min(max(int(limit), 1), 200)
        start = max(int(offset), 0)
        where = "" if include_deleted else "WHERE deleted_at IS NULL"
        with self._read() as db:
            total = int(
                db.execute(
                    f"SELECT COUNT(*) FROM drafts {where}"
                ).fetchone()[0]
            )
            rows = db.execute(
                f"""
                SELECT * FROM drafts
                {where}
                ORDER BY updated_at DESC, draft_id ASC
                LIMIT ? OFFSET ?
                """,
                (bounded, start),
            ).fetchall()
            results: list[dict[str, Any]] = []
            for row in rows:
                submission = db.execute(
                    """
                    SELECT * FROM submissions
                    WHERE draft_id = ?
                    ORDER BY
                        CASE status WHEN 'succeeded' THEN 0 ELSE 1 END,
                        created_at DESC
                    LIMIT 1
                    """,
                    (row["draft_id"],),
                ).fetchone()
                results.append(self._draft_summary(row, submission))
        return results, total

    def get_draft(
        self, draft_id: str, *, include_deleted: bool = False
    ) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            submission = db.execute(
                """
                SELECT * FROM submissions
                WHERE draft_id = ?
                ORDER BY
                    CASE status WHEN 'succeeded' THEN 0 ELSE 1 END,
                    created_at DESC
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
        if row is None or (row["deleted_at"] is not None and not include_deleted):
            raise NotFoundError("草稿不存在")
        return self._row(row, submission)

    @staticmethod
    def _assert_active_draft_in_transaction(
        db: sqlite3.Connection,
        draft_id: str,
    ) -> sqlite3.Row:
        """Resolve a live draft while sharing the caller's write transaction.

        Agent task/job creation first performs a friendly read-side check, but
        that alone leaves a time-of-check/time-of-use window with soft deletion.
        Callers that create or reactivate draft-bound work use this second check
        under ``BEGIN IMMEDIATE`` so deletion and task creation are serialized.
        """

        row = db.execute(
            "SELECT * FROM drafts WHERE draft_id = ?",
            (draft_id,),
        ).fetchone()
        if row is None or row["deleted_at"] is not None:
            raise NotFoundError("草稿不存在")
        return row

    @staticmethod
    def _draft_audit_integrity_in_transaction(
        db: sqlite3.Connection,
        draft_id: str,
        *,
        require_anchor: bool = True,
    ) -> dict[str, Any]:
        """Verify the complete draft audit chain in the current transaction."""

        if not _draft_audit_triggers_intact(db):
            return {
                "valid": False,
                "event_count": 0,
                "failed_sequence": None,
                "failure": "audit_trigger_missing",
                "creator": None,
            }

        rows = db.execute(
            """
            SELECT * FROM draft_audit
            WHERE draft_id = ?
            ORDER BY sequence
            """,
            (draft_id,),
        ).fetchall()
        expected_previous = "0" * 64
        creator: str | None = None
        for expected_sequence, row in enumerate(rows, start=1):
            try:
                details = json.loads(row["details_json"])
                event = {
                    "draft_id": str(row["draft_id"]),
                    "sequence": int(row["sequence"]),
                    "event_type": str(row["event_type"]),
                    "actor": str(row["actor"]),
                    "occurred_at": str(row["occurred_at"]),
                    "details": details,
                    "previous_hash": str(row["previous_hash"]),
                }
                calculated_hash = sha256_json(event)
            except (
                json.JSONDecodeError,
                OverflowError,
                RecursionError,
                TypeError,
                UnicodeError,
                ValueError,
            ):
                return {
                    "valid": False,
                    "event_count": len(rows),
                    "failed_sequence": expected_sequence,
                    "creator": creator,
                }
            if expected_sequence == 1:
                if event["event_type"] != "draft_created":
                    return {
                        "valid": False,
                        "event_count": len(rows),
                        "failed_sequence": 1,
                        "creator": None,
                    }
                creator = event["actor"]
            if (
                event["sequence"] != expected_sequence
                or event["previous_hash"] != expected_previous
                or calculated_hash != str(row["event_hash"])
            ):
                return {
                    "valid": False,
                    "event_count": len(rows),
                    "failed_sequence": event["sequence"],
                    "creator": creator,
                }
            expected_previous = str(row["event_hash"])
        result = {
            "valid": bool(rows) and creator is not None,
            "event_count": len(rows),
            "head_hash": expected_previous,
            "creator": creator,
        }
        if not result["valid"] or not require_anchor:
            return result
        anchor = db.execute(
            "SELECT event_count,head_hash FROM draft_audit_anchors "
            "WHERE draft_id=?",
            (draft_id,),
        ).fetchone()
        if (
            anchor is None
            or int(anchor["event_count"]) != len(rows)
            or str(anchor["head_hash"]) != expected_previous
        ):
            return {
                **result,
                "valid": False,
                "failure": "audit_tail_or_anchor_mismatch",
            }
        return result

    def replace_draft(
        self,
        draft_id: str,
        document: dict[str, Any],
        *,
        actor: str,
        event_type: str,
        details: dict[str, Any] | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        now = utc_text()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            if row is None or row["deleted_at"] is not None:
                raise NotFoundError("草稿不存在")
            audit_integrity = self._draft_audit_integrity_in_transaction(
                db, draft_id
            )
            if not audit_integrity["valid"]:
                raise ConflictError("草稿审计链或防篡改锚点异常，拒绝修改")
            succeeded = db.execute(
                """
                SELECT 1 FROM submissions
                WHERE draft_id = ? AND status = 'succeeded'
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if succeeded is not None:
                raise ConflictError("已成功提交的草稿不可修改")
            pending = db.execute(
                """
                SELECT 1 FROM submissions
                WHERE draft_id = ? AND status = 'pending'
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if pending is not None:
                raise ConflictError("草稿正在提交，暂时不能修改；请等待或重试提交")
            current_revision = int(row["revision"])
            if expected_revision is not None and expected_revision != current_revision:
                raise ConflictError(f"草稿已更新，当前修订号为 {current_revision}")
            revision = current_revision + 1
            previous_document = json.loads(row["document_json"])
            invalidated_reviews = self._revoke_changed_reviews(
                db,
                draft_id=draft_id,
                previous_document=previous_document,
                replacement_document=document,
                revoked_at=now,
            )
            db.execute(
                """
                UPDATE drafts
                SET document_json = ?, revision = ?,
                    confirmed_revision = NULL, confirmation_json = NULL,
                    updated_at = ?
                WHERE draft_id = ?
                """,
                (canonical_json(document), revision, now, draft_id),
            )
            audit_details = {
                "revision": revision,
                "previous_revision": current_revision,
                "document_sha256": sha256_json(document),
                "confirmation_invalidated": row["confirmed_revision"] is not None,
                "invalidated_observation_reviews": invalidated_reviews,
                **(details or {}),
            }
            self._append_audit(
                db,
                draft_id=draft_id,
                event_type=event_type,
                actor=actor,
                details=audit_details,
                occurred_at=now,
            )
            updated = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
        assert updated is not None
        return self._row(updated)

    def confirm(
        self,
        draft_id: str,
        *,
        actor: str,
        attestation: str,
        confirmer_name: str,
        confirmer_role: str,
        statement_version: str,
        confirmation_method: str,
        expected_revision: int,
        document_sha256: str,
    ) -> dict[str, Any]:
        now = utc_text()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
            if row is None or row["deleted_at"] is not None:
                raise NotFoundError("草稿不存在")
            audit_integrity = self._draft_audit_integrity_in_transaction(
                db, draft_id
            )
            if not audit_integrity["valid"]:
                raise ConflictError("草稿审计链或防篡改锚点异常，拒绝确认")
            succeeded = db.execute(
                """
                SELECT 1 FROM submissions
                WHERE draft_id = ? AND status = 'succeeded'
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if succeeded is not None:
                raise ConflictError("已成功提交的草稿不可重复确认")
            pending = db.execute(
                """
                SELECT 1 FROM submissions
                WHERE draft_id = ? AND status = 'pending'
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if pending is not None:
                raise ConflictError("草稿正在提交，暂时不能重复确认")
            if int(row["revision"]) != expected_revision:
                raise ConflictError(f"草稿已更新，当前修订号为 {row['revision']}")
            document = json.loads(row["document_json"])
            current_hash = sha256_json(document)
            if current_hash != document_sha256:
                raise ConflictError("草稿内容摘要不匹配，请重新核对")
            review_records = self._current_review_records(
                db,
                draft_id=draft_id,
                document=document,
                reviewed_by=actor,
            )
            observation_count = len(document.get("observations", []))
            if len(review_records) != observation_count:
                raise ValidationBlockedError(
                    "当前确认人尚未逐条核对全部来源观测"
                )
            review_evidence_sha256 = sha256_json(review_records)
            confirmation = {
                "confirmed_by": actor,
                "confirmer_id": actor,
                "confirmer_name": confirmer_name,
                "confirmer_role": confirmer_role,
                "confirmed_at": now,
                "attestation": attestation,
                "statement_version": statement_version,
                "confirmation_method": confirmation_method,
                "evidence_reviewed": True,
                "authorized_to_submit": True,
                "understands_regulator_decides_normality_and_legality": True,
                "document_sha256": current_hash,
                "revision": expected_revision,
                "observation_review_count": len(review_records),
                "observation_reviews_sha256": review_evidence_sha256,
            }
            db.execute(
                """
                UPDATE drafts
                SET confirmed_revision = ?, confirmation_json = ?,
                    updated_at = ?
                WHERE draft_id = ?
                """,
                (
                    expected_revision,
                    canonical_json(confirmation),
                    now,
                    draft_id,
                ),
            )
            self._append_audit(
                db,
                draft_id=draft_id,
                event_type="human_confirmed",
                actor=actor,
                details={
                    "revision": expected_revision,
                    "document_sha256": current_hash,
                    "attestation_sha256": sha256_json(attestation),
                    "observation_review_count": len(review_records),
                    "observation_reviews_sha256": review_evidence_sha256,
                },
                occurred_at=now,
            )
            updated = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?", (draft_id,)
            ).fetchone()
        assert updated is not None
        return self._row(updated)

    def soft_delete(
        self,
        draft_id: str,
        *,
        actor: str,
        expected_revision: int,
    ) -> None:
        now = utc_text()
        with self._transaction() as db:
            row = self._assert_active_draft_in_transaction(db, draft_id)
            # Authentication and ``write`` authorization belong to the HTTP
            # boundary.  One deployment/database is one enterprise tenant, so
            # another authorised writer may take over a colleague's draft.
            # The audit event below records the actual deleting principal.
            audit_integrity = self._draft_audit_integrity_in_transaction(
                db,
                draft_id,
            )
            if not audit_integrity["valid"]:
                raise ConflictError("草稿审计完整性校验失败，拒绝删除")
            if int(row["revision"]) != expected_revision:
                raise ConflictError(f"草稿已更新，当前修订号为 {row['revision']}")
            succeeded = db.execute(
                """
                SELECT 1 FROM submissions
                WHERE draft_id = ? AND status = 'succeeded'
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if succeeded is not None:
                raise ConflictError("已成功提交的草稿不可删除")
            pending = db.execute(
                """
                SELECT 1 FROM submissions
                WHERE draft_id = ? AND status = 'pending'
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if pending is not None:
                raise ConflictError("草稿正在提交，暂时不能删除")
            if (
                row["confirmed_revision"] is not None
                or row["confirmation_json"] is not None
            ):
                raise ConflictError(
                    "草稿已经人工确认，不可直接删除；"
                    "如需废弃，请先修改草稿使原确认失效并重新核对"
                )
            active_flow = db.execute(
                """
                SELECT 1 FROM agent_flows
                WHERE draft_id = ? AND status IN ('queued', 'running')
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if active_flow is not None:
                raise ConflictError(
                    "草稿仍有排队或运行中的煤炭智能体任务，"
                    "请先等待任务结束或取消任务"
                )
            enabled_job = db.execute(
                """
                SELECT 1 FROM agent_jobs
                WHERE draft_id = ? AND enabled = 1 AND deleted_at IS NULL
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if enabled_job is not None:
                raise ConflictError(
                    "草稿仍绑定启用的智能体计划，请先停用或删除计划"
                )
            active_harness_run = db.execute(
                """
                SELECT 1 FROM agent_runs
                WHERE draft_id = ?
                  AND status IN ('queued', 'running', 'waiting_approval')
                LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if active_harness_run is not None:
                raise ConflictError(
                    "草稿仍有未结束的智能体运行，请先等待完成或取消运行"
                )
            next_revision = int(row["revision"]) + 1
            db.execute(
                """
                UPDATE drafts
                SET deleted_at = ?, revision = ?,
                    confirmed_revision = NULL, confirmation_json = NULL,
                    updated_at = ?
                WHERE draft_id = ?
                """,
                (now, next_revision, now, draft_id),
            )
            revoked_reviews = db.execute(
                """
                UPDATE observation_reviews
                SET revoked_at = ?
                WHERE draft_id = ? AND revoked_at IS NULL
                """,
                (now, draft_id),
            ).rowcount
            document = json.loads(row["document_json"])
            self._append_audit(
                db,
                draft_id=draft_id,
                event_type="draft_deleted",
                actor=actor,
                details={
                    "deletion_kind": "soft_delete",
                    "previous_revision": int(row["revision"]),
                    "revision": next_revision,
                    "document_sha256": sha256_json(document),
                    "invalidated_observation_reviews": revoked_reviews,
                },
                occurred_at=now,
            )

    def audit_events(self, draft_id: str) -> list[dict[str, Any]]:
        self.get_draft(draft_id, include_deleted=True)
        with self._read() as db:
            rows = db.execute(
                """
                SELECT * FROM draft_audit
                WHERE draft_id = ?
                ORDER BY sequence
                """,
                (draft_id,),
            ).fetchall()
        return [
            {
                "draft_id": row["draft_id"],
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "occurred_at": row["occurred_at"],
                "details": json.loads(row["details_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in rows
        ]

    def last_content_actor(self, draft_id: str) -> str:
        """Return the principal responsible for the current draft revision.

        This is derived from the append-only audit chain so databases created
        by older releases require no destructive migration or guessed owner.
        """

        self.get_draft(draft_id)
        with self._read() as db:
            row = db.execute(
                """
                SELECT actor FROM draft_audit
                WHERE draft_id = ? AND event_type IN (
                    'draft_created',
                    'draft_updated',
                    'source_imported',
                    'regulator_event_snapshot_imported',
                    'llm_assistance_recorded'
                )
                ORDER BY sequence DESC LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
        if row is None:
            raise ConflictError(
                "草稿缺少可核验的创建/编辑人审计记录，不能执行四眼复核"
            )
        return str(row["actor"])

    def verify_audit(self, draft_id: str) -> dict[str, Any]:
        self.get_draft(draft_id, include_deleted=True)
        with self._read() as db:
            return self._draft_audit_integrity_in_transaction(db, draft_id)

    def verify_all_draft_audits(self) -> dict[str, Any]:
        """Verify every complete chain, trigger and tail anchor.

        The first successful production check also arms the process-local
        external-write latch.  That transition must be based on one explicit
        SQLite read snapshot.  Otherwise an external connection could commit
        halfway through the scan and have its new ``data_version`` accepted as
        the checkpoint immediately before the latch becomes active.
        """

        with self._lock:
            db = self._runtime_connection or self._memory_connection
            if db is None:  # pragma: no cover - construction invariant
                raise RuntimeError("企业端数据库运行连接尚未初始化")
            if db.in_transaction:
                raise RuntimeError("完整审计扫描不能在业务事务中启用")
            # Before the first successful full scan there is no trusted marker
            # to refresh.  Sample the candidate snapshot below and publish its
            # markers only if every database/audit check succeeds.  Once armed
            # (or failed), the existing latch must be enforced before any rescan.
            if (
                self._runtime_integrity_latching_enabled
                or self._runtime_integrity_failed
            ):
                self._assert_runtime_database_unchanged_locked(db)
            starting_data_version = int(
                db.execute("PRAGMA data_version").fetchone()[0]
            )
            starting_schema_version = int(
                db.execute("PRAGMA schema_version").fetchone()[0]
            )
            db.execute("BEGIN")
            try:
                result = self._verify_all_draft_audits_in_snapshot(db)
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    with suppress(sqlite3.Error):
                        db.execute("ROLLBACK")
                raise

            ending_data_version = int(
                db.execute("PRAGMA data_version").fetchone()[0]
            )
            ending_schema_version = int(
                db.execute("PRAGMA schema_version").fetchone()[0]
            )
            if (
                ending_data_version != starting_data_version
                or ending_schema_version != starting_schema_version
            ):
                self._latch_runtime_integrity_failure()
                raise ConflictError(
                    "完整审计扫描期间检测到外部数据库提交；"
                    "当前进程已锁死，请保全现场并重启核验"
                )
            if result["valid"]:
                # Store the values already compared above.  Do not issue a
                # fresh checkpoint query here: a commit racing after the
                # comparison must remain visible to the next guarded access.
                self._runtime_data_version = ending_data_version
                self._runtime_schema_version = ending_schema_version
                self._runtime_integrity_latching_enabled = True
            return result

    def _verify_all_draft_audits_in_snapshot(
        self, db: sqlite3.Connection
    ) -> dict[str, Any]:
        """Scan SQLite and the audit boundary in one caller-owned snapshot."""

        # quick_check deliberately runs only during the authoritative startup
        # scan, never on the high-frequency health path.  SQLite's quick_check
        # does not report foreign-key violations, so both results are required
        # before this snapshot may arm the runtime marker latch.
        quick_check_rows = db.execute("PRAGMA quick_check").fetchall()
        quick_check_ok = bool(
            len(quick_check_rows) == 1
            and str(quick_check_rows[0][0]) == "ok"
        )
        foreign_key_violation = db.execute(
            "PRAGMA foreign_key_check"
        ).fetchone()
        foreign_keys_ok = foreign_key_violation is None

        rows = db.execute(
            "SELECT draft_id FROM drafts ORDER BY draft_id"
        ).fetchall()
        failures = []
        if not quick_check_ok:
            failures.append(
                {
                    "draft_id": None,
                    "integrity": {
                        "valid": False,
                        "event_count": 0,
                        "failed_sequence": None,
                        "failure": "sqlite_quick_check_failed",
                        "creator": None,
                    },
                }
            )
        if not foreign_keys_ok:
            failures.append(
                {
                    "draft_id": None,
                    "integrity": {
                        "valid": False,
                        "event_count": 0,
                        "failed_sequence": None,
                        "failure": "sqlite_foreign_key_violation",
                        "creator": None,
                    },
                }
            )
        if not _draft_audit_triggers_intact(db):
            failures.append(
                {
                    "draft_id": None,
                    "integrity": {
                        "valid": False,
                        "event_count": 0,
                        "failed_sequence": None,
                        "failure": "audit_trigger_missing",
                        "creator": None,
                    },
                }
            )
        total_events = 0
        for row in rows:
            draft_id = str(row["draft_id"])
            integrity = self._draft_audit_integrity_in_transaction(db, draft_id)
            total_events += int(integrity.get("event_count") or 0)
            if not integrity["valid"]:
                failures.append(
                    {"draft_id": draft_id, "integrity": integrity}
                )
        return {
            "valid": not failures,
            "draft_count": len(rows),
            "event_count": total_events,
            "failures": failures[:20],
            "database_checks": {
                "quick_check": "ok" if quick_check_ok else "failed",
                "foreign_keys": "ok" if foreign_keys_ok else "failed",
            },
        }

    def begin_submission(
        self,
        *,
        draft_id: str,
        confirmed_revision: int,
        idempotency_key: str,
        request: dict[str, Any],
        actor: str = "system",
    ) -> dict[str, Any]:
        request_hash = sha256_json(request)
        now = utc_text()
        with self._transaction() as db:
            draft = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?",
                (draft_id,),
            ).fetchone()
            if draft is None or draft["deleted_at"] is not None:
                raise NotFoundError("草稿不存在")
            audit_integrity = self._draft_audit_integrity_in_transaction(
                db, draft_id
            )
            if not audit_integrity["valid"]:
                raise ConflictError("草稿审计链或防篡改锚点异常，拒绝提交")
            if (
                int(draft["revision"]) != confirmed_revision
                or draft["confirmed_revision"] != confirmed_revision
                or draft["confirmation_json"] is None
            ):
                raise ConflictError("草稿已更新或确认失效，请刷新后重新核对")
            row = db.execute(
                "SELECT * FROM submissions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is not None:
                if (
                    row["draft_id"] != draft_id
                    or int(row["confirmed_revision"]) != confirmed_revision
                ):
                    raise ConflictError("幂等键已用于不同的草稿内容")
                # The first request is authoritative for this idempotency key.
                # In particular, transport timestamps must not change across
                # retries after an ambiguous or failed network attempt.
                if row["status"] == "failed":
                    db.execute(
                        """
                        UPDATE submissions
                        SET status = 'pending', error_code = NULL,
                            error_json = NULL, updated_at = ?
                        WHERE idempotency_key = ?
                        """,
                        (now, idempotency_key),
                    )
                    self._append_audit(
                        db,
                        draft_id=draft_id,
                        event_type="submission_retry_started",
                        actor=actor,
                        details={
                            "idempotency_key_sha256": sha256_json(
                                idempotency_key
                            ),
                            "request_sha256": row["request_sha256"],
                            "confirmed_revision": confirmed_revision,
                        },
                        occurred_at=now,
                    )
                    row = db.execute(
                        "SELECT * FROM submissions WHERE idempotency_key = ?",
                        (idempotency_key,),
                    ).fetchone()
                    assert row is not None
                return self._submission_row(row)
            db.execute(
                """
                INSERT INTO submissions (
                    idempotency_key, draft_id, confirmed_revision,
                    request_sha256, request_json, status,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    idempotency_key,
                    draft_id,
                    confirmed_revision,
                    request_hash,
                    canonical_json(request),
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                draft_id=draft_id,
                event_type="submission_started",
                actor=actor,
                details={
                    "idempotency_key_sha256": sha256_json(idempotency_key),
                    "request_sha256": request_hash,
                    "confirmed_revision": confirmed_revision,
                },
                occurred_at=now,
            )
            created = db.execute(
                "SELECT * FROM submissions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        assert created is not None
        return self._submission_row(created)

    @staticmethod
    def _submission_row(row: sqlite3.Row) -> dict[str, Any]:
        request = json.loads(row["request_json"])
        return {
            "idempotency_key": row["idempotency_key"],
            "draft_id": row["draft_id"],
            "confirmed_revision": row["confirmed_revision"],
            "request_sha256": row["request_sha256"],
            "submitted_at": request.get("submitted_at"),
            "request": request,
            "status": row["status"],
            "receipt": (
                json.loads(row["receipt_json"])
                if row["receipt_json"] is not None
                else None
            ),
            "error_code": row["error_code"],
            "error": (
                json.loads(row["error_json"])
                if row["error_json"] is not None
                else None
            ),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def finish_submission(
        self,
        idempotency_key: str,
        *,
        receipt: dict[str, Any],
        actor: str = "system",
    ) -> dict[str, Any]:
        now = utc_text()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM submissions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is None:
                raise NotFoundError("提交记录不存在")
            if row["status"] == "succeeded":
                return self._submission_row(row)
            db.execute(
                """
                UPDATE submissions
                SET status = 'succeeded', receipt_json = ?,
                    error_code = NULL, error_json = NULL, updated_at = ?
                WHERE idempotency_key = ?
                """,
                (canonical_json(receipt), now, idempotency_key),
            )
            self._append_audit(
                db,
                draft_id=row["draft_id"],
                event_type="submission_succeeded",
                actor=actor,
                details={
                    "request_sha256": row["request_sha256"],
                    "receipt_sha256": sha256_json(receipt),
                },
                occurred_at=now,
            )
            updated = db.execute(
                "SELECT * FROM submissions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
        assert updated is not None
        return self._submission_row(updated)

    def fail_submission(
        self,
        idempotency_key: str,
        *,
        error_code: str,
        error_details: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> None:
        now = utc_text()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM submissions WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if row is None or row["status"] == "succeeded":
                return
            db.execute(
                """
                UPDATE submissions
                SET status = 'failed', error_code = ?, error_json = ?,
                    updated_at = ?
                WHERE idempotency_key = ?
                """,
                (
                    error_code[:128],
                    (
                        canonical_json(error_details)
                        if error_details is not None
                        else None
                    ),
                    now,
                    idempotency_key,
                ),
            )
            self._append_audit(
                db,
                draft_id=row["draft_id"],
                event_type="submission_failed",
                actor=actor,
                details={
                    "request_sha256": row["request_sha256"],
                    "error_code": error_code[:128],
                    "error_details": error_details or {},
                },
                occurred_at=now,
            )

    def submissions_for_draft(self, draft_id: str) -> list[dict[str, Any]]:
        self.get_draft(draft_id, include_deleted=True)
        with self._read() as db:
            rows = db.execute(
                """
                SELECT * FROM submissions
                WHERE draft_id = ?
                ORDER BY created_at DESC
                """,
                (draft_id,),
            ).fetchall()
        return [self._submission_row(row) for row in rows]

    def submission_summaries_for_draft(
        self, draft_id: str
    ) -> list[dict[str, Any]]:
        """Return browser-safe history without persisted submission payloads."""

        return [
            {key: value for key, value in item.items() if key != "request"}
            for item in self.submissions_for_draft(draft_id)
        ]

    def recent_audit_events(
        self,
        draft_id: str,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        self.get_draft(draft_id, include_deleted=True)
        bounded = min(max(int(limit), 1), 500)
        with self._read() as db:
            rows = db.execute(
                """
                SELECT * FROM draft_audit
                WHERE draft_id = ?
                ORDER BY sequence DESC
                LIMIT ?
                """,
                (draft_id, bounded),
            ).fetchall()
        return [
            {
                "draft_id": row["draft_id"],
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "occurred_at": row["occurred_at"],
                "details": json.loads(row["details_json"]),
                "previous_hash": row["previous_hash"],
                "event_hash": row["event_hash"],
            }
            for row in reversed(rows)
        ]

    @staticmethod
    def _observation_fingerprints(
        document: dict[str, Any],
    ) -> dict[str, str]:
        result: dict[str, str] = {}
        duplicates: set[str] = set()
        observations = document.get("observations")
        if not isinstance(observations, list):
            return result
        for observation in observations:
            if not isinstance(observation, dict):
                continue
            observation_id = observation.get("observation_id")
            fingerprint = observation_review_fingerprint(observation)
            if (
                not isinstance(observation_id, str)
                or not observation_id
                or fingerprint is None
            ):
                continue
            if observation_id in result:
                duplicates.add(observation_id)
            result[observation_id] = fingerprint
        for observation_id in duplicates:
            result.pop(observation_id, None)
        return result

    @classmethod
    def _revoke_changed_reviews(
        cls,
        db: sqlite3.Connection,
        *,
        draft_id: str,
        previous_document: dict[str, Any],
        replacement_document: dict[str, Any],
        revoked_at: str,
    ) -> int:
        previous = cls._observation_fingerprints(previous_document)
        replacement = cls._observation_fingerprints(replacement_document)
        changed_ids = sorted(
            observation_id
            for observation_id in set(previous) | set(replacement)
            if previous.get(observation_id) != replacement.get(observation_id)
        )
        if not changed_ids:
            return 0
        placeholders = ",".join("?" for _ in changed_ids)
        cursor = db.execute(
            f"""
            UPDATE observation_reviews
            SET revoked_at = ?
            WHERE draft_id = ? AND revoked_at IS NULL
              AND observation_id IN ({placeholders})
            """,
            (revoked_at, draft_id, *changed_ids),
        )
        return max(int(cursor.rowcount), 0)

    @classmethod
    def _current_review_records(
        cls,
        db: sqlite3.Connection,
        *,
        draft_id: str,
        document: dict[str, Any],
        reviewed_by: str,
    ) -> list[dict[str, Any]]:
        fingerprints = cls._observation_fingerprints(document)
        rows = db.execute(
            """
            SELECT observation_id, observation_fingerprint_sha256,
                   reviewed_by, reviewed_at
            FROM observation_reviews
            WHERE draft_id = ? AND reviewed_by = ? AND revoked_at IS NULL
            ORDER BY observation_id, reviewed_at DESC, review_id DESC
            """,
            (draft_id, reviewed_by),
        ).fetchall()
        latest: dict[str, sqlite3.Row] = {}
        for row in rows:
            latest.setdefault(str(row["observation_id"]), row)
        records: list[dict[str, Any]] = []
        for observation_id in sorted(fingerprints):
            row = latest.get(observation_id)
            if (
                row is None
                or row["observation_fingerprint_sha256"]
                != fingerprints[observation_id]
            ):
                continue
            records.append(
                {
                    "observation_id": observation_id,
                    "observation_fingerprint_sha256": fingerprints[
                        observation_id
                    ],
                    "reviewed_by": row["reviewed_by"],
                    "reviewed_at": row["reviewed_at"],
                    "statement_version": "observation-review-v1",
                }
            )
        return records

    def observation_review_state(
        self,
        draft_id: str,
        *,
        reviewed_by: str,
    ) -> dict[str, Any]:
        with self._read() as db:
            row = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?",
                (draft_id,),
            ).fetchone()
            if row is None or row["deleted_at"] is not None:
                raise NotFoundError("草稿不存在")
            document = json.loads(row["document_json"])
            records = self._current_review_records(
                db,
                draft_id=draft_id,
                document=document,
                reviewed_by=reviewed_by,
            )
        by_id = {record["observation_id"]: record for record in records}
        fingerprints = self._observation_fingerprints(document)
        observations = [
            (
                {
                    "observation_id": observation_id,
                    "reviewed": True,
                    "reviewed_by": by_id[observation_id]["reviewed_by"],
                    "reviewed_at": by_id[observation_id]["reviewed_at"],
                }
                if observation_id in by_id
                else {
                    "observation_id": observation_id,
                    "reviewed": False,
                    "reviewed_by": None,
                    "reviewed_at": None,
                }
            )
            for observation_id in sorted(fingerprints)
        ]
        return {
            "revision": int(row["revision"]),
            "reviewer_id": reviewed_by,
            "total": len(fingerprints),
            "reviewed_count": len(records),
            "all_reviewed": bool(fingerprints)
            and len(records) == len(fingerprints),
            "observations": observations,
        }

    def record_observation_reviews(
        self,
        draft_id: str,
        *,
        observation_ids: list[str],
        reviewed: bool,
        reviewed_by: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        now = utc_text()
        with self._transaction() as db:
            row = db.execute(
                "SELECT * FROM drafts WHERE draft_id = ?",
                (draft_id,),
            ).fetchone()
            if row is None or row["deleted_at"] is not None:
                raise NotFoundError("草稿不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError(f"草稿已更新，当前修订号为 {row['revision']}")
            locked = db.execute(
                """
                SELECT status FROM submissions
                WHERE draft_id = ? AND status IN ('pending', 'succeeded')
                ORDER BY created_at DESC LIMIT 1
                """,
                (draft_id,),
            ).fetchone()
            if locked is not None:
                raise ConflictError(
                    "草稿正在提交或已经提交，不能变更逐条核对状态"
                )
            document = json.loads(row["document_json"])
            fingerprints = self._observation_fingerprints(document)
            missing = sorted(set(observation_ids) - set(fingerprints))
            if missing:
                raise ValidationBlockedError(
                    "以下观测不存在、编号重复或内容尚不完整："
                    + ", ".join(missing[:10])
                )
            changed: list[str] = []
            for observation_id in observation_ids:
                current = db.execute(
                    """
                    SELECT * FROM observation_reviews
                    WHERE draft_id = ? AND observation_id = ?
                      AND reviewed_by = ? AND revoked_at IS NULL
                    ORDER BY reviewed_at DESC, review_id DESC
                    LIMIT 1
                    """,
                    (draft_id, observation_id, reviewed_by),
                ).fetchone()
                is_current = (
                    current is not None
                    and current["observation_fingerprint_sha256"]
                    == fingerprints[observation_id]
                )
                if reviewed and is_current:
                    continue
                if current is not None:
                    db.execute(
                        """
                        UPDATE observation_reviews
                        SET revoked_at = ?
                        WHERE review_id = ?
                        """,
                        (now, current["review_id"]),
                    )
                if reviewed:
                    db.execute(
                        """
                        INSERT INTO observation_reviews (
                            draft_id, observation_id,
                            observation_fingerprint_sha256,
                            reviewed_by, reviewed_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            draft_id,
                            observation_id,
                            fingerprints[observation_id],
                            reviewed_by,
                            now,
                        ),
                    )
                if current is not None or reviewed:
                    changed.append(observation_id)
            if changed:
                confirmation = (
                    json.loads(row["confirmation_json"])
                    if row["confirmation_json"] is not None
                    else None
                )
                confirmation_invalidated = bool(
                    not reviewed
                    and isinstance(confirmation, dict)
                    and confirmation.get("confirmed_by") == reviewed_by
                )
                if confirmation_invalidated:
                    db.execute(
                        """
                        UPDATE drafts
                        SET confirmed_revision = NULL,
                            confirmation_json = NULL, updated_at = ?
                        WHERE draft_id = ?
                        """,
                        (now, draft_id),
                    )
                self._append_audit(
                    db,
                    draft_id=draft_id,
                    event_type=(
                        "observations_reviewed"
                        if reviewed
                        else "observation_reviews_revoked"
                    ),
                    actor=reviewed_by,
                    details={
                        "revision": expected_revision,
                        "observation_ids": changed,
                        "reviewed": reviewed,
                        "confirmation_invalidated": confirmation_invalidated,
                    },
                    occurred_at=now,
                )
        return self.observation_review_state(
            draft_id,
            reviewed_by=reviewed_by,
        )

    def historical_observations(
        self,
        *,
        mine_id: str,
        metric_code: str,
        exclude_draft_id: str | None = None,
        before_window_start: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Expose a small succeeded-submission history surface to tools."""

        if not isinstance(mine_id, str) or not mine_id or len(mine_id) > 128:
            raise ValueError("mine_id 必须是 1 到 128 字符")
        if (
            not isinstance(metric_code, str)
            or not metric_code
            or len(metric_code) > 128
        ):
            raise ValueError("metric_code 必须是 1 到 128 字符")
        bounded = min(max(int(limit), 1), 500)
        before = (
            utc_text(
                parse_aware_datetime(
                    before_window_start,
                    "before_window_start",
                )
            )
            if before_window_start is not None
            else None
        )
        with self._read() as db:
            rows = db.execute(
                """
                WITH eligible AS (
                    SELECT d.draft_id, d.document_json, d.updated_at
                    FROM drafts AS d
                    WHERE (? IS NULL OR d.draft_id <> ?)
                      AND json_extract(
                          d.document_json, '$.mine_id'
                      ) = ?
                      AND (
                        ? IS NULL
                        OR julianday(json_extract(
                            d.document_json, '$.window_end'
                        )) < julianday(?)
                      )
                      AND EXISTS (
                        SELECT 1 FROM submissions AS s
                        WHERE s.draft_id = d.draft_id
                          AND s.status = 'succeeded'
                      )
                    ORDER BY d.updated_at DESC
                    LIMIT 500
                )
                SELECT
                    e.draft_id,
                    json_extract(
                        e.document_json, '$.window_start'
                    ) AS window_start,
                    json_extract(
                        e.document_json, '$.window_end'
                    ) AS window_end,
                    json_extract(
                        e.document_json, '$.profile_id'
                    ) AS profile_id,
                    json_extract(
                        e.document_json, '$.profile_version'
                    ) AS profile_version,
                    json_extract(
                        e.document_json,
                        '$.operational_context.regime_code'
                    ) AS regime_code,
                    json_extract(
                        e.document_json,
                        '$.operational_context.shift_code'
                    ) AS shift_code,
                    json_extract(
                        e.document_json,
                        '$.operational_context.season_code'
                    ) AS season_code,
                    json_extract(
                        e.document_json,
                        '$.operational_context.maintenance'
                    ) AS maintenance,
                    json_extract(o.value, '$.observed_at') AS observed_at,
                    json_extract(o.value, '$.value') AS value,
                    json_extract(o.value, '$.unit') AS unit,
                    json_extract(
                        o.value, '$.observation_id'
                    ) AS observation_id,
                    json_extract(o.value, '$.source_id') AS source_id
                FROM eligible AS e
                JOIN json_each(
                    e.document_json, '$.observations'
                ) AS o
                WHERE json_extract(
                    o.value, '$.metric_code'
                ) = ?
                ORDER BY e.updated_at DESC, o.key
                LIMIT ?
                """,
                (
                    exclude_draft_id,
                    exclude_draft_id,
                    mine_id,
                    before,
                    before,
                    metric_code,
                    bounded,
                ),
            ).fetchall()
        return [
            {
                "draft_id": row["draft_id"],
                "window_start": row["window_start"],
                "window_end": row["window_end"],
                "observed_at": row["observed_at"],
                "value": row["value"],
                "unit": row["unit"],
                "observation_id": row["observation_id"],
                "source_id": row["source_id"],
                "profile_id": row["profile_id"],
                "profile_version": row["profile_version"],
                "operational_context": {
                    "regime_code": row["regime_code"],
                    "shift_code": row["shift_code"],
                    "season_code": row["season_code"],
                    "maintenance": (
                        bool(row["maintenance"])
                        if row["maintenance"] is not None
                        else None
                    ),
                },
            }
            for row in rows
        ]
