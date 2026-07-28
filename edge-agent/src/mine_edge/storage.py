"""SQLite persistence, idempotency and durable store-and-forward queue."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .models import Alert, Observation, utc_now

_BATCH_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclasses.dataclass(frozen=True, slots=True)
class OutboxRecord:
    row_id: int
    event_id: str
    event_type: str
    payload: dict[str, Any]
    attempts: int


@dataclasses.dataclass(frozen=True, slots=True)
class ClaimedBatch:
    batch_id: str
    records: list[OutboxRecord]


class Repository:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    observation_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    mine_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    metric TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (observation_id, revision)
                );
                CREATE INDEX IF NOT EXISTS idx_observations_time
                    ON observations(observed_at DESC);

                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    observation_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    mine_id TEXT NOT NULL,
                    level TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    triggered_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_time
                    ON alerts(triggered_at DESC);

                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL
                        CHECK (event_type IN ('observation', 'local_alert')),
                    mine_id TEXT NOT NULL,
                    group_id TEXT,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'delivered')),
                    batch_id TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    delivered_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_outbox_due
                    ON outbox(status, next_attempt_at, id);
                CREATE INDEX IF NOT EXISTS idx_outbox_batch
                    ON outbox(batch_id);

                CREATE TABLE IF NOT EXISTS runtime_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS source_scheduler_state (
                    source_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS source_scheduler_events (
                    event_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_source_scheduler_events
                    ON source_scheduler_events(source_id, occurred_at DESC);
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(outbox)").fetchall()
            }
            if "group_id" not in columns:
                connection.execute("ALTER TABLE outbox ADD COLUMN group_id TEXT")
                connection.execute(
                    "UPDATE outbox SET group_id=event_id WHERE group_id IS NULL"
                )

    def record(
        self, observation: Observation, alerts: list[Alert]
    ) -> tuple[bool, list[Alert]]:
        payload = observation.to_dict()
        wire_payload = (
            observation.to_wire_dict() if observation.wire_supported() else None
        )
        now = utc_now()
        inserted_alerts: list[Alert] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT revision, payload_json FROM observations
                WHERE observation_id=? ORDER BY revision DESC LIMIT 1
                """,
                (observation.observation_id,),
            ).fetchone()
            if existing and int(existing["revision"]) > observation.revision:
                raise ValidationError(
                    f"拒绝过期修订：当前最高 revision={existing['revision']}，"
                    f"收到 revision={observation.revision}"
                )
            if existing and int(existing["revision"]) == observation.revision:
                existing_payload = json.loads(existing["payload_json"])
                if (
                    existing_payload.get("source_record_sha256")
                    != observation.source_record_sha256
                ):
                    raise ValidationError(
                        "同一 observation_id/revision 的内容发生变化；"
                        "源系统必须增加 revision"
                    )
                return False, []
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO observations(
                    observation_id, revision, mine_id, kind, metric,
                    observed_at, received_at, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation.observation_id,
                    observation.revision,
                    observation.mine_id,
                    observation.kind.value,
                    observation.metric,
                    observation.observed_at,
                    observation.received_at,
                    _json(payload),
                    now,
                ),
            )
            inserted = cursor.rowcount == 1
            if not inserted:
                return False, []
            if wire_payload is not None:
                connection.execute(
                    """
                    INSERT INTO outbox(
                        event_id, event_type, mine_id, group_id,
                        payload_json, created_at
                    ) VALUES (?, 'observation', ?, ?, ?, ?)
                    """,
                    (
                        f"{observation.observation_id}:r{observation.revision}",
                        observation.mine_id,
                        observation.observation_id,
                        _json(wire_payload),
                        now,
                    ),
                )
            for alert in alerts:
                alert_cursor = connection.execute(
                    """
                    INSERT OR IGNORE INTO alerts(
                        alert_id, observation_id, revision, mine_id, level,
                        rule_id, triggered_at, payload_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.alert_id,
                        observation.observation_id,
                        observation.revision,
                        alert.mine_id,
                        alert.level.value,
                        alert.rule_id,
                        alert.triggered_at,
                        _json(alert.to_dict()),
                        now,
                    ),
                )
                if alert_cursor.rowcount == 1:
                    inserted_alerts.append(alert)
                    if wire_payload is not None:
                        connection.execute(
                            """
                            INSERT INTO outbox(
                                event_id, event_type, mine_id, group_id,
                                payload_json, created_at
                            ) VALUES (?, 'local_alert', ?, ?, ?, ?)
                            """,
                            (
                                alert.alert_id,
                                alert.mine_id,
                                observation.observation_id,
                                _json(alert.to_wire_dict()),
                                now,
                            ),
                        )
        return True, inserted_alerts

    def list_observations(
        self, *, limit: int = 100, kind: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            parameters.append(kind)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(_safe_limit(limit))
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT payload_json FROM observations
                {where}
                ORDER BY observed_at DESC, rowid DESC LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def list_alerts(
        self, *, limit: int = 100, level: str | None = None
    ) -> list[dict[str, Any]]:
        where = "WHERE level = ?" if level else ""
        parameters: list[Any] = [level] if level else []
        parameters.append(_safe_limit(limit))
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT payload_json FROM alerts
                {where}
                ORDER BY triggered_at DESC, rowid DESC LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def list_outbox(
        self, *, limit: int = 100, status: str | None = None
    ) -> list[dict[str, Any]]:
        where = "WHERE status = ?" if status else ""
        parameters: list[Any] = [status] if status else []
        parameters.append(_safe_limit(limit))
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT id, event_id, event_type, mine_id, status, batch_id,
                       attempts, next_attempt_at, last_error, created_at, delivered_at
                FROM outbox
                {where}
                ORDER BY id DESC LIMIT ?
                """,
                parameters,
            ).fetchall()
        return [dict(row) for row in rows]

    def claim_batch(self, *, limit: int, client_id: str) -> ClaimedBatch | None:
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT batch_id FROM outbox
                WHERE status='pending' AND next_attempt_at <= ?
                      AND batch_id IS NOT NULL
                ORDER BY id LIMIT 1
                """,
                (now,),
            ).fetchone()
            if existing:
                batch_id = str(existing["batch_id"])
            else:
                groups = connection.execute(
                    """
                    SELECT group_id, MIN(id) AS first_id FROM outbox
                    WHERE status='pending' AND next_attempt_at <= ?
                          AND batch_id IS NULL AND group_id IS NOT NULL
                    GROUP BY group_id
                    ORDER BY first_id LIMIT ?
                    """,
                    (now, _safe_limit(limit)),
                ).fetchall()
                if not groups:
                    return None
                group_ids = [str(row["group_id"]) for row in groups]
                group_placeholders = ",".join("?" for _ in group_ids)
                rows = connection.execute(
                    f"""
                    SELECT id, event_id FROM outbox
                    WHERE status='pending' AND next_attempt_at <= ?
                          AND batch_id IS NULL
                          AND group_id IN ({group_placeholders})
                    ORDER BY id
                    """,
                    (now, *group_ids),
                ).fetchall()
                digest = hashlib.sha256(
                    (client_id + "\n" + "\n".join(row["event_id"] for row in rows)).encode()
                ).hexdigest()[:32]
                batch_id = f"{client_id}--batch_{digest}"
                if _BATCH_IDENTIFIER.fullmatch(batch_id) is None:
                    raise ValidationError(
                        "client_id 无法生成合法的客户端命名空间 batch_id"
                    )
                placeholders = ",".join("?" for _ in rows)
                connection.execute(
                    f"UPDATE outbox SET batch_id=? WHERE id IN ({placeholders})",
                    [batch_id, *(row["id"] for row in rows)],
                )
            selected = connection.execute(
                """
                SELECT id, event_id, event_type, payload_json, attempts
                FROM outbox WHERE batch_id=? AND status='pending' ORDER BY id
                """,
                (batch_id,),
            ).fetchall()
        if not selected:
            return None
        return ClaimedBatch(
            batch_id=batch_id,
            records=[
                OutboxRecord(
                    row_id=row["id"],
                    event_id=row["event_id"],
                    event_type=row["event_type"],
                    payload=json.loads(row["payload_json"]),
                    attempts=row["attempts"],
                )
                for row in selected
            ],
        )

    def mark_batch_delivered(self, batch_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE outbox
                SET status='delivered', attempts=attempts+1, delivered_at=?,
                    last_error=NULL
                WHERE batch_id=? AND status='pending'
                """,
                (utc_now(), batch_id),
            )
            self._set_state(connection, "last_forward_success_at", utc_now())
            self._set_state(connection, "last_forward_error", "")

    def mark_batch_failed(
        self,
        batch_id: str,
        *,
        error: str,
        base_delay_seconds: int,
        max_delay_seconds: int,
    ) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT MAX(attempts) AS attempts FROM outbox WHERE batch_id=?",
                (batch_id,),
            ).fetchone()
            attempts = int(row["attempts"] or 0) + 1
            delay = min(max_delay_seconds, base_delay_seconds * (2 ** (attempts - 1)))
            connection.execute(
                """
                UPDATE outbox
                SET attempts=attempts+1, next_attempt_at=?, last_error=?
                WHERE batch_id=? AND status='pending'
                """,
                (time.time() + delay, error[:1000], batch_id),
            )
            self._set_state(connection, "last_forward_attempt_at", utc_now())
            self._set_state(connection, "last_forward_error", error[:1000])
        return delay

    def stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM outbox GROUP BY status"
                )
            }
            observation_count = connection.execute(
                "SELECT COUNT(*) FROM observations"
            ).fetchone()[0]
            alert_count = connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            state = {
                row["key"]: row["value"]
                for row in connection.execute("SELECT key, value FROM runtime_state")
            }
        return {
            "observations": observation_count,
            "alerts": alert_count,
            "outbox_pending": counts.get("pending", 0),
            "outbox_delivered": counts.get("delivered", 0),
            **state,
        }

    def health(self) -> dict[str, Any]:
        try:
            with self._connect() as connection:
                result = connection.execute("PRAGMA quick_check").fetchone()[0]
            return {"ok": result == "ok", "sqlite": result}
        except sqlite3.Error as error:
            return {"ok": False, "sqlite": str(error)}

    def load_source_scheduler_state(
        self,
        source_id: str,
    ) -> dict[str, Any] | None:
        if _BATCH_IDENTIFIER.fullmatch(source_id) is None:
            raise ValidationError("source_id 不是安全标识符")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT state_json
                FROM source_scheduler_state
                WHERE source_id = ?
                """,
                (source_id,),
            ).fetchone()
        if row is None:
            return None
        value = json.loads(row["state_json"])
        if not isinstance(value, dict):
            raise ValidationError("持久化来源调度状态不是对象")
        return value

    def save_source_scheduler_state(
        self,
        source_id: str,
        state: dict[str, Any],
    ) -> None:
        if _BATCH_IDENTIFIER.fullmatch(source_id) is None:
            raise ValidationError("source_id 不是安全标识符")
        event_id = state.get("event_id")
        event_type = state.get("event_type")
        occurred_at = state.get("triggered_at")
        if not all(
            isinstance(item, str) and item
            for item in (event_id, event_type, occurred_at)
        ):
            raise ValidationError("来源调度状态缺少审计事件身份或时间")
        assert isinstance(event_id, str)
        assert isinstance(event_type, str)
        assert isinstance(occurred_at, str)
        if _BATCH_IDENTIFIER.fullmatch(event_id) is None:
            raise ValidationError("来源调度审计 event_id 不是安全标识符")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO source_scheduler_state(
                    source_id, state_json, updated_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(source_id) DO UPDATE
                    SET state_json=excluded.state_json,
                        updated_at=excluded.updated_at
                """,
                (source_id, _json(state), utc_now()),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO source_scheduler_events(
                    event_id, source_id, event_type, occurred_at,
                    payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    source_id,
                    event_type,
                    occurred_at,
                    _json(state),
                    utc_now(),
                ),
            )

    def list_source_scheduler_events(
        self,
        source_id: str,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if _BATCH_IDENTIFIER.fullmatch(source_id) is None:
            raise ValidationError("source_id 不是安全标识符")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json
                FROM source_scheduler_events
                WHERE source_id = ?
                ORDER BY occurred_at DESC, rowid DESC
                LIMIT ?
                """,
                (source_id, _safe_limit(limit)),
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    @staticmethod
    def _set_state(connection: sqlite3.Connection, key: str, value: str) -> None:
        connection.execute(
            """
            INSERT INTO runtime_state(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE
                SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, value, utc_now()),
        )


def _safe_limit(value: int) -> int:
    return max(1, min(int(value), 1000))


def _json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
