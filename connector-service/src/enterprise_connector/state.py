from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from .errors import ConnectorError
from .models import DeliveryRecord, HealthDeliveryRecord, NormalizedEvent, PipelineConfig
from .normalize import canonical_json

_SCHEMA_VERSION = 2
_HEALTH_DELIVERY_RETENTION_SECONDS = 90 * 24 * 60 * 60


class StateStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            path.parent.chmod(0o700)
        self.path = path
        self.connection = sqlite3.connect(path, timeout=15, isolation_level=None)
        with suppress(OSError):
            path.chmod(0o600)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA synchronous = FULL")
        self.connection.execute("PRAGMA busy_timeout = 15000")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def close(self) -> None:
        self.connection.close()

    def _migrate(self) -> None:
        self.connection.execute("BEGIN EXCLUSIVE")
        try:
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = self.connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            version = int(row["value"]) if row else 0
            if version > _SCHEMA_VERSION:
                raise ConnectorError(f"状态库 schema {version} 高于程序支持版本 {_SCHEMA_VERSION}")
            if version == 0:
                self.connection.executescript(
                    """
                    CREATE TABLE observations (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        request_id TEXT NOT NULL UNIQUE,
                        pipeline_id TEXT NOT NULL,
                        source_id TEXT NOT NULL,
                        draft_key TEXT NOT NULL,
                        period_key TEXT NOT NULL,
                        source_revision INTEGER NOT NULL CHECK (source_revision >= 1),
                        content_sha256 TEXT NOT NULL,
                        delivered_content_sha256 TEXT,
                        payload_json TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'delivered', 'dead')),
                        trigger_workflow INTEGER NOT NULL DEFAULT 0
                            CHECK (trigger_workflow IN (0, 1)),
                        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                        next_attempt_at REAL NOT NULL DEFAULT 0,
                        response_status INTEGER,
                        last_error TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        delivered_at REAL,
                        UNIQUE (pipeline_id, source_id, draft_key, source_revision)
                    );
                    CREATE INDEX observations_pending
                        ON observations(status, next_attempt_at, sequence);
                    CREATE INDEX observations_latest
                        ON observations(pipeline_id, draft_key, source_id, sequence DESC);
                    CREATE TABLE workflow_generations (
                        draft_key TEXT NOT NULL,
                        generation_hash TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('assigned', 'completed', 'failed')),
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        PRIMARY KEY (draft_key, generation_hash),
                        FOREIGN KEY (event_id) REFERENCES observations(event_id)
                    );
                    CREATE INDEX workflow_generation_assigned
                        ON workflow_generations(draft_key, status);
                    CREATE TABLE leases (
                        name TEXT PRIMARY KEY,
                        owner TEXT NOT NULL,
                        expires_at REAL NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """
                )
                self.connection.execute(
                    "INSERT INTO metadata(key, value) VALUES ('schema_version', ?)",
                    (str(_SCHEMA_VERSION),),
                )
            elif version == 1:
                old_health = self.connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_health'"
                ).fetchone()
                if old_health:
                    self.connection.executescript(
                        """
                        CREATE TABLE source_health_v2 (
                            pipeline_id TEXT NOT NULL,
                            source_id TEXT NOT NULL,
                            status TEXT NOT NULL CHECK (
                                status IN ('ok','empty','stability_wait','error')
                            ),
                            record_count INTEGER NOT NULL CHECK (record_count >= 0),
                            last_poll_at REAL NOT NULL,
                            last_success_at REAL,
                            last_nonempty_at REAL,
                            last_error TEXT,
                            PRIMARY KEY (pipeline_id, source_id)
                        );
                        INSERT INTO source_health_v2
                        SELECT pipeline_id,source_id,
                               CASE WHEN status='waiting_or_empty' THEN 'empty' ELSE status END,
                               record_count,last_poll_at,last_success_at,last_nonempty_at,last_error
                        FROM source_health;
                        DROP TABLE source_health;
                        ALTER TABLE source_health_v2 RENAME TO source_health;
                        """
                    )
                self.connection.execute(
                    "UPDATE metadata SET value = ? WHERE key = 'schema_version'",
                    (str(_SCHEMA_VERSION),),
                )
            # Additive operational tables are deliberately safe for an
            # existing v1 state database; no queued observation is rewritten.
            observation_columns = {
                str(row["name"])
                for row in self.connection.execute("PRAGMA table_info(observations)")
            }
            if "delivered_content_sha256" not in observation_columns:
                self.connection.execute(
                    "ALTER TABLE observations ADD COLUMN delivered_content_sha256 TEXT"
                )
            for observation in self.connection.execute(
                """
                SELECT event_id,payload_json FROM observations
                WHERE delivered_content_sha256 IS NULL
                """
            ).fetchall():
                payload = json.loads(observation["payload_json"])
                delivered_hash = hashlib.sha256(
                    payload["source"]["content"].encode("utf-8")
                ).hexdigest()
                self.connection.execute(
                    "UPDATE observations SET delivered_content_sha256=? WHERE event_id=?",
                    (delivered_hash, observation["event_id"]),
                )
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS source_health (
                    pipeline_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status IN ('ok', 'empty', 'stability_wait', 'error')),
                    record_count INTEGER NOT NULL CHECK (record_count >= 0),
                    last_poll_at REAL NOT NULL,
                    last_success_at REAL,
                    last_nonempty_at REAL,
                    last_error TEXT,
                    PRIMARY KEY (pipeline_id, source_id)
                );
                CREATE TABLE IF NOT EXISTS recovery_actions (
                    action_id TEXT PRIMARY KEY,
                    action_type TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS source_snapshot_health (
                    pipeline_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    draft_key TEXT NOT NULL,
                    period_key TEXT NOT NULL,
                    record_count INTEGER NOT NULL CHECK (record_count > 0),
                    last_success_at REAL NOT NULL,
                    last_nonempty_at REAL NOT NULL,
                    PRIMARY KEY (pipeline_id, source_id, draft_key)
                );
                CREATE TABLE IF NOT EXISTS health_deliveries (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    pipeline_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    draft_key TEXT NOT NULL,
                    period_key TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (outcome IN (
                        'success_nonempty','success_empty','error','stability_wait'
                    )),
                    semantic_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    completed_epoch REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','delivered','dead')),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    response_status INTEGER,
                    last_error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    delivered_at REAL
                );
                CREATE INDEX IF NOT EXISTS health_deliveries_pending
                    ON health_deliveries(status,next_attempt_at,sequence);
                CREATE INDEX IF NOT EXISTS health_deliveries_latest
                    ON health_deliveries(pipeline_id,source_id,draft_key,sequence DESC);
                CREATE INDEX IF NOT EXISTS health_deliveries_retention
                    ON health_deliveries(status,delivered_at,sequence);
                """
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def acquire_lease(self, owner: str, lease_seconds: int, *, now: float | None = None) -> bool:
        timestamp = time.time() if now is None else now
        expires = timestamp + lease_seconds
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT owner, expires_at FROM leases WHERE name = 'service'"
            ).fetchone()
            if row and row["owner"] != owner and row["expires_at"] > timestamp:
                self.connection.rollback()
                return False
            self.connection.execute(
                """
                INSERT INTO leases(name, owner, expires_at, updated_at)
                VALUES ('service', ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    owner = excluded.owner,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at
                """,
                (owner, expires, timestamp),
            )
            self.connection.commit()
            return True
        except BaseException:
            self.connection.rollback()
            raise

    def renew_lease(self, owner: str, lease_seconds: int, *, now: float | None = None) -> bool:
        timestamp = time.time() if now is None else now
        cursor = self.connection.execute(
            """
            UPDATE leases SET expires_at = ?, updated_at = ?
            WHERE name = 'service' AND owner = ? AND expires_at > ?
            """,
            (timestamp + lease_seconds, timestamp, owner, timestamp),
        )
        return cursor.rowcount == 1

    def release_lease(self, owner: str) -> None:
        self.connection.execute("DELETE FROM leases WHERE name = 'service' AND owner = ?", (owner,))

    def record_collection_health(
        self,
        pipeline_id: str,
        source_id: str,
        *,
        status: str,
        record_count: int,
        error: str | None = None,
        now: float | None = None,
    ) -> None:
        """Persist bounded collection metadata, never source records or credentials."""

        if status not in {"ok", "empty", "stability_wait", "error"}:
            raise ValueError("非法来源健康状态")
        if record_count < 0:
            raise ValueError("record_count 不能为负数")
        timestamp = time.time() if now is None else now
        self.connection.execute(
            """
            INSERT INTO source_health(
                pipeline_id,source_id,status,record_count,last_poll_at,
                last_success_at,last_nonempty_at,last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pipeline_id,source_id) DO UPDATE SET
                status=excluded.status,
                record_count=excluded.record_count,
                last_poll_at=excluded.last_poll_at,
                last_success_at=CASE
                    WHEN excluded.status='ok' THEN excluded.last_poll_at
                    ELSE source_health.last_success_at END,
                last_nonempty_at=CASE
                    WHEN excluded.status='ok' AND excluded.record_count > 0
                    THEN excluded.last_poll_at ELSE source_health.last_nonempty_at END,
                last_error=excluded.last_error
            """,
            (
                pipeline_id,
                source_id,
                status,
                record_count,
                timestamp,
                timestamp if status == "ok" else None,
                timestamp if status == "ok" and record_count > 0 else None,
                error[:500] if error else None,
            ),
        )

    def record_snapshot_health(
        self,
        pipeline_id: str,
        source_id: str,
        draft_key: str,
        period_key: str,
        *,
        record_count: int,
        now: float | None = None,
    ) -> None:
        if record_count <= 0:
            raise ValueError("snapshot record_count 必须为正数")
        timestamp = time.time() if now is None else now
        self.connection.execute(
            """
            INSERT INTO source_snapshot_health(
                pipeline_id,source_id,draft_key,period_key,record_count,
                last_success_at,last_nonempty_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(pipeline_id,source_id,draft_key) DO UPDATE SET
                period_key=excluded.period_key,
                record_count=excluded.record_count,
                last_success_at=excluded.last_success_at,
                last_nonempty_at=excluded.last_nonempty_at
            """,
            (
                pipeline_id,
                source_id,
                draft_key,
                period_key,
                record_count,
                timestamp,
                timestamp,
            ),
        )

    def source_snapshot_is_fresh(
        self,
        pipeline_id: str,
        source_id: str,
        draft_key: str,
        maximum_age: float,
        *,
        now: float | None = None,
    ) -> bool:
        timestamp = time.time() if now is None else now
        health = self.connection.execute(
            """
            SELECT status,last_success_at FROM source_health
            WHERE pipeline_id = ? AND source_id = ?
            """,
            (pipeline_id, source_id),
        ).fetchone()
        snapshot = self.connection.execute(
            """
            SELECT last_success_at FROM source_snapshot_health
            WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
            """,
            (pipeline_id, source_id, draft_key),
        ).fetchone()
        return bool(
            health is not None
            and health["status"] == "ok"
            and health["last_success_at"] is not None
            and timestamp - float(health["last_success_at"]) < maximum_age
            and snapshot is not None
            and timestamp - float(snapshot["last_success_at"]) < maximum_age
        )

    def register_health(
        self,
        pipeline_id: str,
        payload: dict[str, object],
        *,
        heartbeat_seconds: float,
        completed_epoch: float,
        now: float | None = None,
    ) -> str | None:
        """Queue one state transition or bounded heartbeat as a durable body."""

        timestamp = time.time() if now is None else now
        source_id = str(payload["source_id"])
        draft_key = str(payload["draft_key"])
        period_key = str(payload["reporting_month"])
        outcome = str(payload["outcome"])
        semantic = {
            key: value
            for key, value in payload.items()
            if key not in {"event_id", "attempted_at", "completed_at"}
        }
        semantic_json = canonical_json(semantic)
        semantic_sha = hashlib.sha256(semantic_json.encode("utf-8")).hexdigest()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            # Bound heartbeat history without weakening recovery or audit:
            # pending/dead rows are never removed, nor is the latest state for
            # any pipeline/source/draft. Observations and recovery_actions are
            # outside this retention policy and remain untouched.
            self.connection.execute(
                """
                DELETE FROM health_deliveries
                WHERE status = 'delivered'
                  AND delivered_at IS NOT NULL
                  AND delivered_at < ?
                  AND EXISTS (
                    SELECT 1 FROM health_deliveries AS newer
                    WHERE newer.pipeline_id = health_deliveries.pipeline_id
                      AND newer.source_id = health_deliveries.source_id
                      AND newer.draft_key = health_deliveries.draft_key
                      AND newer.sequence > health_deliveries.sequence
                  )
                """,
                (timestamp - _HEALTH_DELIVERY_RETENTION_SECONDS,),
            )
            latest = self.connection.execute(
                """
                SELECT status,semantic_sha256,created_at FROM health_deliveries
                WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (pipeline_id, source_id, draft_key),
            ).fetchone()
            if (
                latest
                and latest["semantic_sha256"] == semantic_sha
                and (
                    latest["status"] == "pending"
                    or timestamp - float(latest["created_at"]) < heartbeat_seconds
                )
            ):
                self.connection.commit()
                return None
            nonce = uuid.uuid4().hex
            material = (
                f"{pipeline_id}\n{source_id}\n{draft_key}\n{semantic_sha}\n"
                f"{completed_epoch:.6f}\n{nonce}"
            )
            event_id = f"chlt_{hashlib.sha256(material.encode()).hexdigest()}"
            body = dict(payload)
            body["event_id"] = event_id
            self.connection.execute(
                """
                INSERT INTO health_deliveries(
                    event_id,pipeline_id,source_id,draft_key,period_key,outcome,
                    semantic_sha256,payload_json,completed_epoch,created_at,updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    pipeline_id,
                    source_id,
                    draft_key,
                    period_key,
                    outcome,
                    semantic_sha,
                    canonical_json(body),
                    completed_epoch,
                    timestamp,
                    timestamp,
                ),
            )
            self.connection.commit()
            return event_id
        except BaseException:
            self.connection.rollback()
            raise

    def pending_health(
        self, *, now: float | None = None, limit: int = 100
    ) -> tuple[HealthDeliveryRecord, ...]:
        timestamp = time.time() if now is None else now
        rows = self.connection.execute(
            """
            SELECT * FROM health_deliveries
            WHERE status='pending' AND next_attempt_at <= ?
            ORDER BY next_attempt_at,sequence LIMIT ?
            """,
            (timestamp, limit),
        ).fetchall()
        return tuple(
            HealthDeliveryRecord(
                event_id=row["event_id"],
                pipeline_id=row["pipeline_id"],
                source_id=row["source_id"],
                draft_key=row["draft_key"],
                payload_json=row["payload_json"],
                attempts=row["attempts"],
            )
            for row in rows
        )

    def mark_health_delivered(
        self, event_id: str, response_status: int, *, now: float | None = None
    ) -> None:
        timestamp = time.time() if now is None else now
        self.connection.execute(
            """
            UPDATE health_deliveries SET status='delivered',attempts=attempts+1,
                response_status=?,last_error=NULL,delivered_at=?,updated_at=?
            WHERE event_id=? AND status='pending'
            """,
            (response_status, timestamp, timestamp, event_id),
        )

    def mark_health_retry(
        self,
        event_id: str,
        error: str,
        delay_seconds: float,
        response_status: int | None,
        *,
        now: float | None = None,
    ) -> None:
        timestamp = time.time() if now is None else now
        self.connection.execute(
            """
            UPDATE health_deliveries SET attempts=attempts+1,next_attempt_at=?,
                response_status=?,last_error=?,updated_at=?
            WHERE event_id=? AND status='pending'
            """,
            (timestamp + delay_seconds, response_status, error[:500], timestamp, event_id),
        )

    def mark_health_dead(
        self,
        event_id: str,
        error: str,
        response_status: int | None,
        *,
        now: float | None = None,
    ) -> None:
        timestamp = time.time() if now is None else now
        self.connection.execute(
            """
            UPDATE health_deliveries SET status='dead',attempts=attempts+1,
                response_status=?,last_error=?,updated_at=?
            WHERE event_id=? AND status='pending'
            """,
            (response_status, error[:500], timestamp, event_id),
        )

    def register(
        self,
        event: NormalizedEvent,
        *,
        now: float | None = None,
    ) -> str | None:
        """Register a source transition and preserve A→B→A as three revisions."""

        timestamp = time.time() if now is None else now
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            latest = self.connection.execute(
                """
                SELECT content_sha256, source_revision FROM observations
                WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                ORDER BY sequence DESC LIMIT 1
                """,
                (event.pipeline_id, event.source_id, event.draft_key),
            ).fetchone()
            if latest and latest["content_sha256"] == event.content_sha256:
                self.connection.commit()
                return None
            revision = int(latest["source_revision"]) + 1 if latest else event.revision_floor + 1
            identity = (
                f"{event.pipeline_id}\n{event.source_id}\n{event.draft_key}\n"
                f"{revision}\n{event.content_sha256}"
            )
            identity_sha = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            event_id = f"cevt_{identity_sha}"
            payload = json.loads(canonical_json(event.payload))
            payload["event_id"] = event_id
            payload["source"]["revision"] = revision
            source_content = json.loads(payload["source"]["content"])
            source_content["connector_snapshot"]["source_revision"] = revision
            payload["source"]["content"] = canonical_json(source_content)
            delivered_content_sha = hashlib.sha256(
                payload["source"]["content"].encode("utf-8")
            ).hexdigest()
            request_id = f"stored_{identity_sha}"
            self.connection.execute(
                """
                INSERT INTO observations(
                    event_id, request_id, pipeline_id, source_id, draft_key, period_key,
                    source_revision, content_sha256, delivered_content_sha256,
                    payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    request_id,
                    event.pipeline_id,
                    event.source_id,
                    event.draft_key,
                    event.period_key,
                    revision,
                    event.content_sha256,
                    delivered_content_sha,
                    canonical_json(payload),
                    timestamp,
                    timestamp,
                ),
            )
            self.connection.commit()
            return event_id
        except BaseException:
            self.connection.rollback()
            raise

    def latest_observation_metadata(
        self, pipeline_id: str, source_id: str, draft_key: str
    ) -> dict[str, object] | None:
        row = self.connection.execute(
            """
            SELECT event_id,source_revision,content_sha256,
                   delivered_content_sha256,status
            FROM observations
            WHERE pipeline_id=? AND source_id=? AND draft_key=?
            ORDER BY sequence DESC LIMIT 1
            """,
            (pipeline_id, source_id, draft_key),
        ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _to_delivery(row: sqlite3.Row) -> DeliveryRecord:
        return DeliveryRecord(
            event_id=row["event_id"],
            pipeline_id=row["pipeline_id"],
            source_id=row["source_id"],
            draft_key=row["draft_key"],
            payload_json=row["payload_json"],
            attempts=row["attempts"],
            trigger_workflow=bool(row["trigger_workflow"]),
        )

    @staticmethod
    def _health_matches_observation(
        health: sqlite3.Row | None, observation: sqlite3.Row
    ) -> bool:
        if health is None:
            return False
        try:
            payload = json.loads(health["payload_json"])
            return bool(
                payload.get("autofill_event_id") == observation["event_id"]
                and payload.get("source_revision") == observation["source_revision"]
                and payload.get("snapshot_sha256")
                == observation["delivered_content_sha256"]
            )
        except (json.JSONDecodeError, TypeError, KeyError):
            return False

    def pending(self, *, now: float | None = None, limit: int = 100) -> tuple[DeliveryRecord, ...]:
        timestamp = time.time() if now is None else now
        rows = self.connection.execute(
            """
            SELECT * FROM observations
            WHERE status = 'pending' AND next_attempt_at <= ?
            ORDER BY next_attempt_at, sequence LIMIT ?
            """,
            (timestamp, limit),
        ).fetchall()
        return tuple(self._to_delivery(row) for row in rows)

    def prepare_delivery(
        self,
        event_id: str,
        required_sources: tuple[str, ...],
        *,
        max_staleness_by_source: dict[str, float] | None = None,
        now: float | None = None,
    ) -> DeliveryRecord | None:
        """Reserve a generation trigger, or defer while an older generation is in flight."""

        timestamp = time.time() if now is None else now
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.connection.execute(
                "SELECT * FROM observations WHERE event_id = ? AND status = 'pending'",
                (event_id,),
            ).fetchone()
            if current is None:
                self.connection.rollback()
                return None
            if current["trigger_workflow"]:
                self.connection.commit()
                return self._to_delivery(current)
            assigned = self.connection.execute(
                """
                SELECT 1 FROM workflow_generations
                WHERE draft_key = ? AND status = 'assigned' LIMIT 1
                """,
                (current["draft_key"],),
            ).fetchone()
            if assigned:
                self.connection.rollback()
                return None
            if max_staleness_by_source is not None:
                current_maximum_age = max_staleness_by_source.get(str(current["source_id"]))
                current_health = self.connection.execute(
                    """
                    SELECT outcome,status,completed_epoch,payload_json
                    FROM health_deliveries
                    WHERE pipeline_id=? AND source_id=? AND draft_key=?
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (current["pipeline_id"], current["source_id"], current["draft_key"]),
                ).fetchone()
                # The health body is the cross-process freshness authority. An
                # exact success binding must reach the Agent before its
                # observation, even when that health event was durably
                # rejected. A newer empty/error/unrelated binding describes a
                # different health transition; it must not strand an older
                # observation that is still safe to deliver without workflow.
                exact_success_binding = bool(
                    current_health is not None
                    and current_health["outcome"] == "success_nonempty"
                    and self._health_matches_observation(current_health, current)
                )
                if current_health is None or (
                    exact_success_binding and current_health["status"] != "delivered"
                ):
                    self.connection.rollback()
                    return None
                current_health_ready = bool(
                    current_maximum_age is not None
                    and current_health["status"] == "delivered"
                    and exact_success_binding
                    and timestamp - float(current_health["completed_epoch"])
                    < current_maximum_age
                )
                if not current_health_ready:
                    self.connection.commit()
                    return self._to_delivery(current)
            required_latest: dict[str, sqlite3.Row] = {}
            for source_id in required_sources:
                row = self.connection.execute(
                    """
                    SELECT * FROM observations
                    WHERE pipeline_id = ? AND draft_key = ? AND source_id = ?
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (current["pipeline_id"], current["draft_key"], source_id),
                ).fetchone()
                if row is None:
                    self.connection.commit()
                    return self._to_delivery(current)
                required_latest[source_id] = row
                if max_staleness_by_source is not None:
                    health = self.connection.execute(
                        """
                        SELECT status,last_success_at FROM source_health
                        WHERE pipeline_id = ? AND source_id = ?
                        """,
                        (current["pipeline_id"], source_id),
                    ).fetchone()
                    snapshot_health = self.connection.execute(
                        """
                        SELECT last_success_at FROM source_snapshot_health
                        WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                        """,
                        (current["pipeline_id"], source_id, current["draft_key"]),
                    ).fetchone()
                    remote_health = self.connection.execute(
                        """
                        SELECT outcome,status,completed_epoch,payload_json
                        FROM health_deliveries
                        WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                        ORDER BY sequence DESC LIMIT 1
                        """,
                        (current["pipeline_id"], source_id, current["draft_key"]),
                    ).fetchone()
                    maximum_age = max_staleness_by_source[source_id]
                    if (
                        health is None
                        or health["status"] != "ok"
                        or health["last_success_at"] is None
                        or timestamp - float(health["last_success_at"]) >= maximum_age
                        or snapshot_health is None
                        or timestamp - float(snapshot_health["last_success_at"])
                        >= maximum_age
                        or remote_health is None
                        or remote_health["outcome"] != "success_nonempty"
                        or remote_health["status"] != "delivered"
                        or timestamp - float(remote_health["completed_epoch"])
                        >= maximum_age
                        or not self._health_matches_observation(
                            remote_health, required_latest[source_id]
                        )
                    ):
                        self.connection.commit()
                        return self._to_delivery(current)
            latest_rows = self.connection.execute(
                """
                SELECT candidate.* FROM observations AS candidate
                WHERE candidate.pipeline_id = ? AND candidate.draft_key = ?
                  AND NOT EXISTS (
                    SELECT 1 FROM observations AS newer
                    WHERE newer.pipeline_id = candidate.pipeline_id
                      AND newer.draft_key = candidate.draft_key
                      AND newer.source_id = candidate.source_id
                      AND newer.sequence > candidate.sequence
                  )
                """,
                (current["pipeline_id"], current["draft_key"]),
            ).fetchall()
            latest = {str(row["source_id"]): row for row in latest_rows}
            current_latest = latest.get(str(current["source_id"]))
            if current_latest is None or current_latest["event_id"] != current["event_id"]:
                self.connection.commit()
                return self._to_delivery(current)
            # Only required sources form the readiness gate. An optional
            # source with a newer dead/pending revision must not silently turn
            # into a required dependency for later required-source updates.
            for source_id, row in required_latest.items():
                if source_id != current["source_id"] and row["status"] != "delivered":
                    self.connection.commit()
                    return self._to_delivery(current)
            delivered_rows = self.connection.execute(
                """
                SELECT candidate.* FROM observations AS candidate
                WHERE candidate.pipeline_id = ? AND candidate.draft_key = ?
                  AND candidate.status = 'delivered'
                  AND NOT EXISTS (
                    SELECT 1 FROM observations AS newer
                    WHERE newer.pipeline_id = candidate.pipeline_id
                      AND newer.draft_key = candidate.draft_key
                      AND newer.source_id = candidate.source_id
                      AND newer.status = 'delivered'
                      AND newer.sequence > candidate.sequence
                  )
                """,
                (current["pipeline_id"], current["draft_key"]),
            ).fetchall()
            generation_rows = {
                str(row["source_id"]): row for row in delivered_rows
            }
            # The event about to be sent is the proposed contribution even
            # though it is not delivered yet. Once an optional event succeeds,
            # it therefore creates a new generation as expected.
            generation_rows[str(current["source_id"])] = current
            generation_material = "\n".join(
                f"{source_id}:{generation_rows[source_id]['event_id']}"
                for source_id in sorted(generation_rows)
            )
            generation_hash = hashlib.sha256(generation_material.encode("utf-8")).hexdigest()
            prior = self.connection.execute(
                """
                SELECT status FROM workflow_generations
                WHERE draft_key = ? AND generation_hash = ?
                """,
                (current["draft_key"], generation_hash),
            ).fetchone()
            if prior:
                self.connection.commit()
                return self._to_delivery(current)
            payload = json.loads(current["payload_json"])
            payload["trigger_workflow"] = True
            payload_json = canonical_json(payload)
            self.connection.execute(
                """
                UPDATE observations
                SET payload_json = ?, trigger_workflow = 1, updated_at = ?
                WHERE event_id = ?
                """,
                (payload_json, timestamp, event_id),
            )
            self.connection.execute(
                """
                INSERT INTO workflow_generations(
                    draft_key, generation_hash, event_id, status, created_at, updated_at
                ) VALUES (?, ?, ?, 'assigned', ?, ?)
                """,
                (current["draft_key"], generation_hash, event_id, timestamp, timestamp),
            )
            updated = self.connection.execute(
                "SELECT * FROM observations WHERE event_id = ?", (event_id,)
            ).fetchone()
            self.connection.commit()
            return self._to_delivery(updated)
        except BaseException:
            self.connection.rollback()
            raise

    def mark_delivered(
        self, event_id: str, response_status: int, *, now: float | None = None
    ) -> None:
        timestamp = time.time() if now is None else now
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                """
                UPDATE observations SET status = 'delivered', attempts = attempts + 1,
                    response_status = ?, last_error = NULL, delivered_at = ?, updated_at = ?
                WHERE event_id = ? AND status = 'pending'
                """,
                (response_status, timestamp, timestamp, event_id),
            )
            self.connection.execute(
                """
                UPDATE workflow_generations SET status = 'completed', updated_at = ?
                WHERE event_id = ? AND status = 'assigned'
                """,
                (timestamp, event_id),
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def mark_retry(
        self,
        event_id: str,
        error: str,
        delay_seconds: float,
        response_status: int | None,
        *,
        now: float | None = None,
    ) -> None:
        timestamp = time.time() if now is None else now
        self.connection.execute(
            """
            UPDATE observations SET attempts = attempts + 1, next_attempt_at = ?,
                response_status = ?, last_error = ?, updated_at = ?
            WHERE event_id = ? AND status = 'pending'
            """,
            (timestamp + delay_seconds, response_status, error[:1000], timestamp, event_id),
        )

    def mark_dead(
        self,
        event_id: str,
        error: str,
        response_status: int | None,
        *,
        now: float | None = None,
    ) -> None:
        timestamp = time.time() if now is None else now
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                """
                UPDATE observations SET status = 'dead', attempts = attempts + 1,
                    response_status = ?, last_error = ?, updated_at = ?
                WHERE event_id = ? AND status = 'pending'
                """,
                (response_status, error[:1000], timestamp, event_id),
            )
            self.connection.execute(
                """
                UPDATE workflow_generations SET status = 'failed', updated_at = ?
                WHERE event_id = ? AND status = 'assigned'
                """,
                (timestamp, event_id),
            )
            self.connection.commit()
        except BaseException:
            self.connection.rollback()
            raise

    def retry_dead(self, event_id: str | None = None, *, now: float | None = None) -> int:
        """Retry one event, or only latest dead revisions when no ID is supplied."""

        timestamp = time.time() if now is None else now
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if event_id is not None:
                rows = self.connection.execute(
                    """
                    SELECT event_id,response_status FROM observations
                    WHERE status = 'dead' AND event_id = ?
                    """,
                    (event_id,),
                ).fetchall()
                if rows and rows[0]["response_status"] is not None and 400 <= int(
                    rows[0]["response_status"]
                ) < 500:
                    raise ConnectorError(
                        "Agent 4xx 已可能持久记录该 event_id 的拒绝结果；"
                        "请核对原因后使用 supersede-dead 生成新修订"
                    )
            else:
                rows = self.connection.execute(
                    """
                    SELECT current.event_id FROM observations AS current
                    WHERE current.status = 'dead'
                      AND (current.response_status IS NULL
                           OR current.response_status < 400
                           OR current.response_status >= 500)
                      AND NOT EXISTS (
                        SELECT 1 FROM observations AS newer
                        WHERE newer.pipeline_id = current.pipeline_id
                            AND newer.source_id = current.source_id
                            AND newer.draft_key = current.draft_key
                            AND newer.sequence > current.sequence
                    )
                    """
                ).fetchall()
            event_ids = [row["event_id"] for row in rows]
            if event_ids:
                placeholders = ",".join("?" for _ in event_ids)
                self.connection.execute(
                    f"DELETE FROM workflow_generations WHERE status = 'failed' "
                    f"AND event_id IN ({placeholders})",
                    event_ids,
                )
                self.connection.execute(
                    f"UPDATE observations SET status = 'pending', next_attempt_at = 0, "
                    f"trigger_workflow = 0, last_error = NULL, updated_at = ? "
                    f"WHERE event_id IN ({placeholders})",
                    (timestamp, *event_ids),
                )
                for event_id in event_ids:
                    row = self.connection.execute(
                        "SELECT payload_json FROM observations WHERE event_id = ?", (event_id,)
                    ).fetchone()
                    payload = json.loads(row["payload_json"])
                    payload["trigger_workflow"] = False
                    self.connection.execute(
                        "UPDATE observations SET payload_json = ? WHERE event_id = ?",
                        (canonical_json(payload), event_id),
                    )
            self.connection.commit()
            return len(event_ids)
        except BaseException:
            self.connection.rollback()
            raise

    def supersede_dead(
        self,
        event_id: str,
        *,
        reason: str,
        now: float | None = None,
    ) -> dict[str, object]:
        """Clone one latest dead snapshot as a new auditable source revision."""

        clean_reason = " ".join(reason.split())
        if not 10 <= len(clean_reason) <= 500:
            raise ValueError("reason 必须是 10-500 个字符的可审计说明")
        timestamp = time.time() if now is None else now
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(
                "SELECT * FROM observations WHERE event_id=? AND status='dead'",
                (event_id,),
            ).fetchone()
            if row is None:
                raise ConnectorError("指定事件不是 dead，不能 supersede")
            newer = self.connection.execute(
                """
                SELECT 1 FROM observations
                WHERE pipeline_id=? AND source_id=? AND draft_key=? AND sequence>?
                LIMIT 1
                """,
                (row["pipeline_id"], row["source_id"], row["draft_key"], row["sequence"]),
            ).fetchone()
            if newer:
                raise ConnectorError("该 dead 事件已有更新修订，拒绝回退覆盖")
            revision = int(row["source_revision"]) + 1
            if revision > 2_147_483_647:
                raise ConnectorError("来源修订号已达上限")
            payload = json.loads(row["payload_json"])
            payload["trigger_workflow"] = False
            payload["source"]["revision"] = revision
            content = json.loads(payload["source"]["content"])
            content["connector_snapshot"]["source_revision"] = revision
            payload["source"]["content"] = canonical_json(content)
            delivered_content_sha = hashlib.sha256(
                payload["source"]["content"].encode("utf-8")
            ).hexdigest()
            material = (
                f"supersede\n{event_id}\n{revision}\n{row['content_sha256']}"
            )
            digest = hashlib.sha256(material.encode()).hexdigest()
            new_event_id = f"cevt_{digest}"
            payload["event_id"] = new_event_id
            self.connection.execute(
                """
                INSERT INTO observations(
                    event_id,request_id,pipeline_id,source_id,draft_key,period_key,
                    source_revision,content_sha256,delivered_content_sha256,
                    payload_json,created_at,updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_event_id,
                    f"stored_{digest}",
                    row["pipeline_id"],
                    row["source_id"],
                    row["draft_key"],
                    row["period_key"],
                    revision,
                    row["content_sha256"],
                    delivered_content_sha,
                    canonical_json(payload),
                    timestamp,
                    timestamp,
                ),
            )
            action_id = f"recovery_{uuid.uuid4().hex}"
            self.connection.execute(
                """
                INSERT INTO recovery_actions(action_id,action_type,details_json,created_at)
                VALUES (?, 'supersede_dead', ?, ?)
                """,
                (
                    action_id,
                    canonical_json(
                        {
                            "old_event_id": event_id,
                            "new_event_id": new_event_id,
                            "source_revision": revision,
                            "reason": clean_reason,
                        }
                    ),
                    timestamp,
                ),
            )
            self.connection.commit()
            return {
                "action_id": action_id,
                "old_event_id": event_id,
                "new_event_id": new_event_id,
                "source_revision": revision,
            }
        except BaseException:
            self.connection.rollback()
            raise

    def replay_delivered(
        self,
        event_id: str | None = None,
        *,
        latest: bool = False,
        now: float | None = None,
    ) -> int:
        """Requeue an exact delivered body for controlled Agent disaster recovery."""

        if (event_id is None) == (not latest):
            raise ValueError("必须且只能指定 event_id 或 latest=True")
        timestamp = time.time() if now is None else now
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if event_id is not None:
                rows = self.connection.execute(
                    "SELECT event_id FROM observations WHERE status='delivered' AND event_id=?",
                    (event_id,),
                ).fetchall()
            else:
                rows = self.connection.execute(
                    """
                    SELECT current.event_id FROM observations AS current
                    WHERE current.status='delivered' AND NOT EXISTS (
                        SELECT 1 FROM observations AS newer
                        WHERE newer.pipeline_id=current.pipeline_id
                          AND newer.source_id=current.source_id
                          AND newer.draft_key=current.draft_key
                          AND newer.sequence>current.sequence
                    )
                    """
                ).fetchall()
            event_ids = [str(row["event_id"]) for row in rows]
            if event_ids:
                placeholders = ",".join("?" for _ in event_ids)
                self.connection.execute(
                    f"UPDATE observations SET status='pending', next_attempt_at=0, "
                    f"last_error=NULL, updated_at=? WHERE event_id IN ({placeholders})",
                    (timestamp, *event_ids),
                )
                self.connection.execute(
                    """
                    INSERT INTO recovery_actions(action_id,action_type,details_json,created_at)
                    VALUES (?, 'replay_delivered', ?, ?)
                    """,
                    (
                        f"recovery_{uuid.uuid4().hex}",
                        canonical_json(
                            {
                                "mode": "event_id" if event_id is not None else "latest",
                                "event_ids": event_ids,
                                "count": len(event_ids),
                            }
                        ),
                        timestamp,
                    ),
                )
            self.connection.commit()
            return len(event_ids)
        except BaseException:
            self.connection.rollback()
            raise

    def status(self) -> dict[str, object]:
        counts = {
            row["status"]: row["count"]
            for row in self.connection.execute(
                "SELECT status, COUNT(*) AS count FROM observations GROUP BY status"
            )
        }
        generation_counts = {
            row["status"]: row["count"]
            for row in self.connection.execute(
                "SELECT status, COUNT(*) AS count FROM workflow_generations GROUP BY status"
            )
        }
        health_counts = {
            row["status"]: row["count"]
            for row in self.connection.execute(
                "SELECT status,COUNT(*) AS count FROM health_deliveries GROUP BY status"
            )
        }
        last_error = self.connection.execute(
            """
            SELECT event_id, last_error, response_status, updated_at
            FROM observations WHERE last_error IS NOT NULL
            ORDER BY updated_at DESC LIMIT 1
            """
        ).fetchone()
        recovery = self.connection.execute(
            """
            SELECT action_id,action_type,created_at FROM recovery_actions
            ORDER BY created_at DESC LIMIT 1
            """
        ).fetchone()
        return {
            "schema_version": _SCHEMA_VERSION,
            "database": str(self.path),
            "observations": {
                "pending": counts.get("pending", 0),
                "delivered": counts.get("delivered", 0),
                "dead": counts.get("dead", 0),
                "total": sum(counts.values()),
            },
            "workflow_generations": {
                "assigned": generation_counts.get("assigned", 0),
                "completed": generation_counts.get("completed", 0),
                "failed": generation_counts.get("failed", 0),
            },
            "health_deliveries": {
                "pending": health_counts.get("pending", 0),
                "delivered": health_counts.get("delivered", 0),
                "dead": health_counts.get("dead", 0),
                "total": sum(health_counts.values()),
            },
            "last_error": dict(last_error) if last_error else None,
            "recovery_actions": {
                "total": self.connection.execute(
                    "SELECT COUNT(*) FROM recovery_actions"
                ).fetchone()[0],
                "latest": dict(recovery) if recovery else None,
            },
        }

    def pipeline_status(self, pipelines: tuple[PipelineConfig, ...]) -> list[dict[str, object]]:
        """Return bounded metadata-only readiness details for operators."""

        result: list[dict[str, object]] = []
        timestamp = time.time()
        for pipeline in pipelines:
            source_items: list[dict[str, object]] = []
            for source in pipeline.sources:
                row = self.connection.execute(
                    """
                    SELECT event_id,draft_key,period_key,source_revision,status,
                           created_at,delivered_at,last_error
                    FROM observations
                    WHERE pipeline_id = ? AND source_id = ?
                    ORDER BY period_key DESC, sequence DESC LIMIT 1
                    """,
                    (pipeline.id, source.id),
                ).fetchone()
                health = self.connection.execute(
                    """
                    SELECT status,record_count,last_poll_at,last_success_at,
                           last_nonempty_at,last_error
                    FROM source_health WHERE pipeline_id = ? AND source_id = ?
                    """,
                    (pipeline.id, source.id),
                ).fetchone()
                snapshot_health = (
                    self.connection.execute(
                        """
                        SELECT last_success_at,last_nonempty_at,record_count
                        FROM source_snapshot_health
                        WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                        """,
                        (pipeline.id, source.id, row["draft_key"]),
                    ).fetchone()
                    if row
                    else None
                )
                remote_health = (
                    self.connection.execute(
                        """
                        SELECT outcome,status,completed_epoch,payload_json
                        FROM health_deliveries
                        WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                        ORDER BY sequence DESC LIMIT 1
                        """,
                        (pipeline.id, source.id, row["draft_key"]),
                    ).fetchone()
                    if row
                    else None
                )
                latest_reported_health = self.connection.execute(
                    """
                    SELECT period_key,outcome,status,completed_epoch
                    FROM health_deliveries
                    WHERE pipeline_id=? AND source_id=?
                    ORDER BY period_key DESC,sequence DESC LIMIT 1
                    """,
                    (pipeline.id, source.id),
                ).fetchone()
                stale = (
                    health is None
                    or health["status"] != "ok"
                    or health["last_success_at"] is None
                    or timestamp - float(health["last_success_at"])
                    >= source.max_staleness_seconds
                    or snapshot_health is None
                    or timestamp - float(snapshot_health["last_success_at"])
                    >= source.max_staleness_seconds
                    or remote_health is None
                    or remote_health["outcome"] != "success_nonempty"
                    or remote_health["status"] != "delivered"
                    or timestamp - float(remote_health["completed_epoch"])
                    >= source.max_staleness_seconds
                    or not self._health_matches_observation(remote_health, row)
                )
                source_items.append(
                    {
                        "source_id": source.id,
                        "adapter": source.adapter,
                        "required": source.id in pipeline.required_sources,
                        "seen": row is not None,
                        "latest_event_id": row["event_id"] if row else None,
                        "latest_revision": int(row["source_revision"]) if row else None,
                        "latest_period": row["period_key"] if row else None,
                        "latest_status": row["status"] if row else None,
                        "revision_seed": source.revision_seed,
                        "disaster_recovery_seed_active": source.revision_seed > 0,
                        "max_staleness_seconds": source.max_staleness_seconds,
                        "collection_status": health["status"] if health else "never_polled",
                        "collection_record_count": int(health["record_count"]) if health else 0,
                        "collection_stale": stale,
                        "agent_health_status": (
                            remote_health["status"] if remote_health else "never_sent"
                        ),
                        "agent_health_outcome": (
                            remote_health["outcome"] if remote_health else None
                        ),
                        "latest_reported_health_period": (
                            latest_reported_health["period_key"]
                            if latest_reported_health
                            else None
                        ),
                        "latest_reported_health_outcome": (
                            latest_reported_health["outcome"]
                            if latest_reported_health
                            else None
                        ),
                        "last_poll_at": (
                            datetime.fromtimestamp(health["last_poll_at"], UTC).isoformat()
                            if health
                            else None
                        ),
                        "last_collection_success_at": (
                            datetime.fromtimestamp(health["last_success_at"], UTC).isoformat()
                            if health and health["last_success_at"] is not None
                            else None
                        ),
                        "last_nonempty_at": (
                            datetime.fromtimestamp(
                                snapshot_health["last_nonempty_at"], UTC
                            ).isoformat()
                            if snapshot_health
                            and snapshot_health["last_nonempty_at"] is not None
                            else None
                        ),
                        "last_seen_at": (
                            datetime.fromtimestamp(row["created_at"], UTC).isoformat()
                            if row
                            else None
                        ),
                        "last_delivered_at": (
                            datetime.fromtimestamp(row["delivered_at"], UTC).isoformat()
                            if row and row["delivered_at"] is not None
                            else None
                        ),
                        "last_error": (
                            health["last_error"]
                            if health and health["last_error"]
                            else (row["last_error"] if row else None)
                        ),
                    }
                )
            latest_draft = self.connection.execute(
                """
                SELECT draft_key,period_key FROM (
                    SELECT draft_key,period_key,sequence * 2 AS ordering
                    FROM observations WHERE pipeline_id = ?
                    UNION ALL
                    SELECT draft_key,period_key,sequence * 2 + 1 AS ordering
                    FROM health_deliveries WHERE pipeline_id = ?
                ) ORDER BY period_key DESC,ordering DESC LIMIT 1
                """,
                (pipeline.id, pipeline.id),
            ).fetchone()
            ready_sources: set[str] = set()
            if latest_draft:
                rows = self.connection.execute(
                    """
                    SELECT current.* FROM observations AS current
                    WHERE pipeline_id = ? AND draft_key = ? AND NOT EXISTS (
                        SELECT 1 FROM observations AS newer
                        WHERE newer.pipeline_id = current.pipeline_id
                          AND newer.draft_key = current.draft_key
                          AND newer.source_id = current.source_id
                          AND newer.sequence > current.sequence
                    )
                    """,
                    (pipeline.id, latest_draft["draft_key"]),
                ).fetchall()
                delivered_sources = {
                    str(row["source_id"]) for row in rows if row["status"] == "delivered"
                }
                source_by_id = {source.id: source for source in pipeline.sources}
                for source_id in delivered_sources:
                    source = source_by_id.get(source_id)
                    if source is None:
                        continue
                    health = self.connection.execute(
                        """
                        SELECT status,last_success_at FROM source_health
                        WHERE pipeline_id = ? AND source_id = ?
                        """,
                        (pipeline.id, source_id),
                    ).fetchone()
                    snapshot_health = self.connection.execute(
                        """
                        SELECT last_success_at FROM source_snapshot_health
                        WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                        """,
                        (pipeline.id, source_id, latest_draft["draft_key"]),
                    ).fetchone()
                    remote_health = self.connection.execute(
                        """
                        SELECT outcome,status,completed_epoch,payload_json FROM health_deliveries
                        WHERE pipeline_id = ? AND source_id = ? AND draft_key = ?
                        ORDER BY sequence DESC LIMIT 1
                        """,
                        (pipeline.id, source_id, latest_draft["draft_key"]),
                    ).fetchone()
                    if (
                        health is not None
                        and health["status"] == "ok"
                        and health["last_success_at"] is not None
                        and timestamp - float(health["last_success_at"])
                        < source.max_staleness_seconds
                        and snapshot_health is not None
                        and timestamp - float(snapshot_health["last_success_at"])
                        < source.max_staleness_seconds
                        and remote_health is not None
                        and remote_health["outcome"] == "success_nonempty"
                        and remote_health["status"] == "delivered"
                        and timestamp - float(remote_health["completed_epoch"])
                        < source.max_staleness_seconds
                        and self._health_matches_observation(
                            remote_health,
                            next(
                                row
                                for row in rows
                                if str(row["source_id"]) == source_id
                            ),
                        )
                    ):
                        ready_sources.add(source_id)
            missing = sorted(set(pipeline.required_sources) - ready_sources)
            result.append(
                {
                    "pipeline_id": pipeline.id,
                    "latest_period": latest_draft["period_key"] if latest_draft else None,
                    "required_sources": list(pipeline.required_sources),
                    "required_sources_not_ready": missing,
                    "ready_for_workflow": not missing,
                    "sources": source_items,
                }
            )
        return result
