"""Durable intake, alert ledger and dashboard read model for mine telemetry."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator, Literal
from uuid import uuid4

from .edge_ingest import (
    EDGE_NONCE_RETENTION_SECONDS,
    EdgeTelemetryBatch,
)
from .safety_attachments import (
    ALLOWED_SAFETY_ATTACHMENT_TYPES,
    MAX_SAFETY_ATTACHMENT_BYTES,
)


AlertLevel = Literal["blue", "yellow", "orange", "red"]
AlertStatus = Literal[
    "open",
    "acknowledged",
    "in_progress",
    "resolved",
    "closed",
]

_LEVEL_RANK = {"blue": 1, "yellow": 2, "orange": 3, "red": 4}
_OPEN_STATUSES = frozenset({"open", "acknowledged", "in_progress"})
_REQUIRED_VERIFICATION_REFERENCE_DIGESTS = frozenset(
    {"production", "electricity", "explosives"}
)


class EdgeBatchConflictError(ValueError):
    pass


class EdgeNonceReplayError(ValueError):
    pass


class AlertNotFoundError(ValueError):
    pass


class AlertVersionConflictError(ValueError):
    pass


class InvalidAlertActionError(ValueError):
    pass


class VerificationRunConflictError(ValueError):
    pass


class VerificationReferenceConflictError(ValueError):
    pass


class VerificationReferenceNotFoundError(ValueError):
    pass


class InvalidVerificationReferenceActionError(ValueError):
    pass


class SafetyRuleConflictError(ValueError):
    pass


class SafetyAttachmentConflictError(ValueError):
    pass


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _approval_status(rule_profile: Any) -> str:
    """Return the persisted governance status without inventing approval."""
    profile = rule_profile
    if isinstance(profile, str):
        try:
            profile = json.loads(profile)
        except (TypeError, ValueError, json.JSONDecodeError):
            return "unknown"
    if not isinstance(profile, dict):
        return "unknown"
    status = profile.get("approval_status")
    if not isinstance(status, str):
        return "unknown"
    normalized = status.strip()
    if not normalized or len(normalized) > 128:
        return "unknown"
    return normalized


class EdgeTelemetryRepository:
    """SQLite repository sharing the main backup boundary, not object state."""

    def __init__(self, database_path: str | Path = ":memory:") -> None:
        self.database_path = str(database_path)
        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 5000")
            if self.database_path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
                self._connection.execute("PRAGMA synchronous = FULL")
            self._migrate()

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS edge_nonces (
                client_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                request_time TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (client_id, nonce)
            );
            CREATE INDEX IF NOT EXISTS idx_edge_nonces_expiry
                ON edge_nonces(expires_at);

            CREATE TABLE IF NOT EXISTS edge_batches (
                receipt_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                mine_id TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                received_at TEXT NOT NULL,
                accepted_observations INTEGER NOT NULL,
                rejected_observations INTEGER NOT NULL,
                sequence_start INTEGER NOT NULL,
                sequence_end INTEGER NOT NULL,
                edge_rule_profile_json TEXT NOT NULL,
                raw_batch_json TEXT NOT NULL,
                rejection_details_json TEXT NOT NULL,
                safety_evaluation_status TEXT NOT NULL DEFAULT 'pending',
                safety_evaluation_attempts INTEGER NOT NULL DEFAULT 0,
                safety_evaluation_result_status TEXT,
                safety_evaluation_error_code TEXT,
                safety_evaluation_updated_at TEXT,
                safety_evaluation_next_attempt_at TEXT,
                safety_evaluation_lease_token TEXT,
                safety_evaluation_lease_expires_at TEXT,
                safety_evaluation_trigger TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_edge_batches_mine_received
                ON edge_batches(mine_id, received_at DESC);

            CREATE TABLE IF NOT EXISTS edge_observations (
                mine_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                source_id TEXT NOT NULL,
                metric_code TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT NOT NULL,
                location_code TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                sequence_no INTEGER NOT NULL,
                source_record_id TEXT NOT NULL,
                source_record_sha256 TEXT NOT NULL,
                acquisition_mode TEXT NOT NULL,
                quality_json TEXT NOT NULL,
                interval_json TEXT,
                manual_attestation_json TEXT,
                source_signature TEXT,
                status_code TEXT,
                first_batch_id TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                analytic_accepted INTEGER NOT NULL,
                rejection_reason TEXT,
                payload_sha256 TEXT NOT NULL,
                PRIMARY KEY (mine_id, observation_id, revision),
                FOREIGN KEY (first_batch_id)
                    REFERENCES edge_batches(batch_id)
            );
            CREATE INDEX IF NOT EXISTS idx_edge_observations_metric_time
                ON edge_observations(
                    mine_id, metric_code, observed_at DESC
                );
            CREATE INDEX IF NOT EXISTS idx_edge_observations_source_sequence
                ON edge_observations(
                    mine_id, source_id, sequence_no DESC, revision DESC
                );

            CREATE TABLE IF NOT EXISTS edge_batch_observations (
                batch_id TEXT NOT NULL,
                mine_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                disposition TEXT NOT NULL,
                reason TEXT,
                PRIMARY KEY (
                    batch_id, mine_id, observation_id, revision
                ),
                FOREIGN KEY (batch_id) REFERENCES edge_batches(batch_id)
            );

            CREATE TABLE IF NOT EXISTS edge_local_alert_hints (
                batch_id TEXT NOT NULL,
                local_alert_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (batch_id, local_alert_id),
                FOREIGN KEY (batch_id) REFERENCES edge_batches(batch_id)
            );

            CREATE TABLE IF NOT EXISTS mine_registry (
                mine_id TEXT PRIMARY KEY,
                mine_name TEXT NOT NULL,
                gas_category TEXT,
                longitude REAL,
                latitude REAL,
                approved_capacity_tpy REAL,
                approved_underground_personnel INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS safety_alerts (
                alert_id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                mine_id TEXT NOT NULL,
                category TEXT NOT NULL,
                rule_code TEXT NOT NULL,
                operational INTEGER NOT NULL DEFAULT 1,
                level TEXT NOT NULL,
                status TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                location_code TEXT NOT NULL,
                detected_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                due_at TEXT,
                assignee TEXT,
                occurrence_count INTEGER NOT NULL,
                version INTEGER NOT NULL,
                observation_ids_json TEXT NOT NULL,
                details_json TEXT NOT NULL,
                rule_profile_json TEXT NOT NULL,
                source TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_safety_alerts_mine_status
                ON safety_alerts(mine_id, status, last_seen_at DESC);
            CREATE INDEX IF NOT EXISTS idx_safety_alerts_level_status
                ON safety_alerts(level, status, last_seen_at DESC);

            CREATE TABLE IF NOT EXISTS safety_alert_events (
                event_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT,
                note TEXT,
                payload_json TEXT NOT NULL,
                previous_hash TEXT,
                event_hash TEXT NOT NULL UNIQUE,
                FOREIGN KEY (alert_id) REFERENCES safety_alerts(alert_id)
            );
            CREATE INDEX IF NOT EXISTS idx_safety_alert_events_alert
                ON safety_alert_events(alert_id, occurred_at, event_id);

            CREATE TABLE IF NOT EXISTS safety_alert_attachments (
                attachment_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                mine_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                media_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL
                    CHECK(size_bytes > 0 AND size_bytes <= 5242880),
                sha256 TEXT NOT NULL,
                content BLOB NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                UNIQUE(alert_id, sha256),
                FOREIGN KEY (alert_id) REFERENCES safety_alerts(alert_id)
                    ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_safety_attachments_alert
                ON safety_alert_attachments(
                    alert_id, created_at, attachment_id
                );

            CREATE TABLE IF NOT EXISTS safety_responsibility_routes (
                route_id TEXT PRIMARY KEY,
                mine_id TEXT,
                category TEXT,
                minimum_level TEXT NOT NULL,
                primary_user_id TEXT NOT NULL,
                primary_username TEXT NOT NULL,
                backup_user_id TEXT,
                backup_username TEXT,
                escalation_minutes INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_safety_routes_match
                ON safety_responsibility_routes(
                    enabled, mine_id, category, minimum_level
                );

            CREATE TABLE IF NOT EXISTS safety_alert_recipients (
                recipient_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                recipient_role TEXT NOT NULL,
                route_id TEXT,
                assigned_at TEXT NOT NULL,
                read_at TEXT,
                escalated_at TEXT,
                UNIQUE (alert_id, route_id, recipient_role),
                FOREIGN KEY (alert_id) REFERENCES safety_alerts(alert_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (route_id)
                    REFERENCES safety_responsibility_routes(route_id)
                    ON DELETE SET NULL
            );
            CREATE INDEX IF NOT EXISTS idx_safety_recipients_unread
                ON safety_alert_recipients(
                    recipient_role, read_at, assigned_at
                );

            CREATE TABLE IF NOT EXISTS safety_signal_states (
                mine_id TEXT NOT NULL,
                state_key TEXT NOT NULL,
                state_json TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                rule_fingerprint TEXT NOT NULL,
                evaluated_at TEXT NOT NULL,
                PRIMARY KEY (mine_id, state_key)
            );

            CREATE TABLE IF NOT EXISTS safety_evaluation_runs (
                run_id TEXT PRIMARY KEY,
                batch_id TEXT,
                mine_id TEXT NOT NULL,
                decision_time TEXT NOT NULL,
                rule_version TEXT NOT NULL,
                rule_fingerprint TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_safety_runs_mine_time
                ON safety_evaluation_runs(mine_id, decision_time DESC);

            CREATE TABLE IF NOT EXISTS safety_notification_outbox (
                notification_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                alert_version INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                level TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL,
                delivered_at TEXT,
                UNIQUE (alert_id, alert_version),
                FOREIGN KEY (alert_id) REFERENCES safety_alerts(alert_id)
            );
            CREATE INDEX IF NOT EXISTS idx_safety_notification_pending
                ON safety_notification_outbox(status, next_attempt_at);

            CREATE TABLE IF NOT EXISTS safety_notification_deliveries (
                notification_id TEXT NOT NULL,
                webhook_id TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                attempt_cycle INTEGER NOT NULL DEFAULT 0,
                manual_retry_count INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                created_at TEXT NOT NULL,
                last_attempt_at TEXT,
                delivered_at TEXT,
                PRIMARY KEY (notification_id, webhook_id),
                FOREIGN KEY (notification_id)
                    REFERENCES safety_notification_outbox(notification_id)
                    ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_safety_delivery_pending
                ON safety_notification_deliveries(
                    status, next_attempt_at, notification_id, webhook_id
                );

            CREATE TABLE IF NOT EXISTS production_verification_runs (
                run_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL UNIQUE,
                request_sha256 TEXT NOT NULL,
                mine_id TEXT NOT NULL,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                status TEXT NOT NULL,
                overall_clue_level INTEGER NOT NULL,
                request_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_verification_runs_mine_window
                ON production_verification_runs(
                    mine_id, window_end DESC, created_at DESC
                );

            CREATE TABLE IF NOT EXISTS verification_reference_samples (
                sample_id TEXT PRIMARY KEY,
                mine_id TEXT NOT NULL,
                sample_json TEXT NOT NULL,
                sample_sha256 TEXT NOT NULL,
                source_digests_json TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                registration_sha256 TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK(status IN ('draft', 'approved', 'rejected')),
                registered_at TEXT NOT NULL,
                registered_by TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT,
                decision_note TEXT,
                FOREIGN KEY (mine_id)
                    REFERENCES mine_registry(mine_id)
                    ON DELETE RESTRICT
            );
            CREATE INDEX IF NOT EXISTS idx_verification_reference_scope
                ON verification_reference_samples(
                    mine_id, status, registered_at DESC
                );

            CREATE TABLE IF NOT EXISTS verification_reference_events (
                event_id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                from_status TEXT,
                to_status TEXT,
                note TEXT,
                payload_json TEXT NOT NULL,
                previous_hash TEXT,
                event_hash TEXT NOT NULL UNIQUE,
                FOREIGN KEY (sample_id)
                    REFERENCES verification_reference_samples(sample_id)
                    ON DELETE RESTRICT
            );
            CREATE INDEX IF NOT EXISTS idx_verification_reference_events
                ON verification_reference_events(
                    sample_id, occurred_at, event_id
                );
            CREATE TRIGGER IF NOT EXISTS
                verification_reference_content_immutable
            BEFORE UPDATE OF
                sample_id, mine_id, sample_json, sample_sha256,
                source_digests_json, evidence_refs_json,
                registration_sha256, registered_at, registered_by
            ON verification_reference_samples
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'verification reference content is immutable'
                );
            END;
            CREATE TRIGGER IF NOT EXISTS
                verification_reference_delete_forbidden
            BEFORE DELETE ON verification_reference_samples
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'verification reference deletion is forbidden'
                );
            END;
            CREATE TRIGGER IF NOT EXISTS
                verification_reference_event_update_forbidden
            BEFORE UPDATE ON verification_reference_events
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'verification reference events are append-only'
                );
            END;
            CREATE TRIGGER IF NOT EXISTS
                verification_reference_event_delete_forbidden
            BEFORE DELETE ON verification_reference_events
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'verification reference events are append-only'
                );
            END;

            CREATE TABLE IF NOT EXISTS safety_rule_profiles (
                rule_version TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                snapshot_json TEXT NOT NULL,
                status TEXT NOT NULL,
                effective_from TEXT NOT NULL,
                effective_to TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                approved_at TEXT,
                approved_by TEXT,
                decision_note TEXT,
                approval_note TEXT,
                retired_at TEXT,
                retired_by TEXT,
                retirement_note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_safety_rule_status_effective
                ON safety_rule_profiles(
                    status, effective_from, effective_to
                );
            """
        )
        columns = {
            row["name"]
            for row in self._connection.execute(
                "PRAGMA table_info(mine_registry)"
            ).fetchall()
        }
        if "gas_category" not in columns:
            self._connection.execute(
                "ALTER TABLE mine_registry ADD COLUMN gas_category TEXT"
            )
        observation_columns = {
            row["name"]
            for row in self._connection.execute(
                "PRAGMA table_info(edge_observations)"
            ).fetchall()
        }
        if "interval_json" not in observation_columns:
            self._connection.execute(
                "ALTER TABLE edge_observations "
                "ADD COLUMN interval_json TEXT"
            )
        batch_columns = {
            row["name"]
            for row in self._connection.execute(
                "PRAGMA table_info(edge_batches)"
            ).fetchall()
        }
        batch_migrations = {
            "safety_evaluation_status": (
                "TEXT NOT NULL DEFAULT 'pending'"
            ),
            "safety_evaluation_attempts": (
                "INTEGER NOT NULL DEFAULT 0"
            ),
            "safety_evaluation_result_status": "TEXT",
            "safety_evaluation_error_code": "TEXT",
            "safety_evaluation_updated_at": "TEXT",
            "safety_evaluation_next_attempt_at": "TEXT",
            "safety_evaluation_lease_token": "TEXT",
            "safety_evaluation_lease_expires_at": "TEXT",
            "safety_evaluation_trigger": "TEXT",
        }
        for column, declaration in batch_migrations.items():
            if column not in batch_columns:
                self._connection.execute(
                    f"ALTER TABLE edge_batches ADD COLUMN "
                    f"{column} {declaration}"
                )
        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_edge_batches_evaluation_queue
            ON edge_batches(
                safety_evaluation_status,
                safety_evaluation_next_attempt_at,
                received_at
            )
            """
        )
        alert_columns = {
            row["name"]
            for row in self._connection.execute(
                "PRAGMA table_info(safety_alerts)"
            ).fetchall()
        }
        if "operational" not in alert_columns:
            self._connection.execute(
                "ALTER TABLE safety_alerts ADD COLUMN "
                "operational INTEGER NOT NULL DEFAULT 1"
            )
            legacy_rows = self._connection.execute(
                """
                SELECT alert_id, rule_code, rule_profile_json
                FROM safety_alerts
                """
            ).fetchall()
            for row in legacy_rows:
                try:
                    profile = json.loads(
                        row["rule_profile_json"]
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                approval_status = (
                    profile.get("approval_status")
                    if isinstance(profile, dict)
                    else None
                )
                if (
                    approval_status == "not_approved"
                    and row["rule_code"]
                    != "safety_rule_approval_required"
                ):
                    self._connection.execute(
                        """
                        UPDATE safety_alerts
                        SET operational = 0, due_at = NULL
                        WHERE alert_id = ?
                        """,
                        (row["alert_id"],),
                    )
                    self._connection.execute(
                        """
                        UPDATE safety_notification_outbox
                        SET status = 'dead',
                            last_error =
                                'shadow_alert_migration_suppressed'
                        WHERE alert_id = ? AND status != 'delivered'
                        """,
                        (row["alert_id"],),
                    )
                    self._connection.execute(
                        """
                        UPDATE safety_notification_deliveries
                        SET status = 'dead',
                            last_error =
                                'shadow_alert_migration_suppressed'
                        WHERE notification_id IN (
                            SELECT notification_id
                            FROM safety_notification_outbox
                            WHERE alert_id = ?
                        ) AND status != 'delivered'
                        """,
                        (row["alert_id"],),
                    )
        recipient_columns = {
            row["name"]
            for row in self._connection.execute(
                "PRAGMA table_info(safety_alert_recipients)"
            ).fetchall()
        }
        if "recipient_id" not in recipient_columns:
            self._connection.executescript(
                """
                DROP INDEX IF EXISTS idx_safety_recipients_unread;
                CREATE TABLE safety_alert_recipients_v2 (
                    recipient_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    recipient_role TEXT NOT NULL,
                    route_id TEXT,
                    assigned_at TEXT NOT NULL,
                    read_at TEXT,
                    escalated_at TEXT,
                    UNIQUE (alert_id, route_id, recipient_role),
                    FOREIGN KEY (alert_id)
                        REFERENCES safety_alerts(alert_id)
                        ON DELETE CASCADE,
                    FOREIGN KEY (route_id)
                        REFERENCES safety_responsibility_routes(route_id)
                        ON DELETE SET NULL
                );
                INSERT INTO safety_alert_recipients_v2(
                    recipient_id, alert_id, user_id, username,
                    recipient_role, route_id, assigned_at, read_at,
                    escalated_at
                )
                SELECT
                    'recipient-legacy-' || printf('%016x', source.rowid),
                    source.alert_id, source.user_id, source.username,
                    source.recipient_role, source.route_id,
                    source.assigned_at, source.read_at,
                    source.escalated_at
                FROM safety_alert_recipients source
                WHERE source.route_id IS NULL
                   OR source.rowid = (
                        SELECT candidate.rowid
                        FROM safety_alert_recipients candidate
                        WHERE candidate.alert_id = source.alert_id
                          AND candidate.route_id = source.route_id
                          AND candidate.recipient_role =
                              source.recipient_role
                        ORDER BY candidate.assigned_at DESC,
                                 candidate.rowid DESC
                        LIMIT 1
                   );
                DROP TABLE safety_alert_recipients;
                ALTER TABLE safety_alert_recipients_v2
                    RENAME TO safety_alert_recipients;
                CREATE INDEX idx_safety_recipients_unread
                    ON safety_alert_recipients(
                        recipient_role, read_at, assigned_at
                    );
                """
            )
        stale_route_recipients = self._connection.execute(
            """
            SELECT alert_id, username
            FROM safety_alert_recipients
            WHERE route_id IS NULL AND recipient_role = 'primary'
            """
        ).fetchall()
        for recipient in stale_route_recipients:
            self._connection.execute(
                """
                UPDATE safety_alerts
                SET assignee = NULL
                WHERE alert_id = ? AND assignee = ?
                """,
                (recipient["alert_id"], recipient["username"]),
            )
        self._connection.execute(
            """
            DELETE FROM safety_alert_recipients
            WHERE route_id IS NULL
              AND recipient_role IN ('primary', 'backup')
            """
        )
        rule_columns = {
            row["name"]
            for row in self._connection.execute(
                "PRAGMA table_info(safety_rule_profiles)"
            ).fetchall()
        }
        for column in (
            "approval_note",
            "retired_at",
            "retired_by",
            "retirement_note",
        ):
            if column not in rule_columns:
                self._connection.execute(
                    f"ALTER TABLE safety_rule_profiles ADD COLUMN {column} TEXT"
                )
        self._connection.execute(
            """
            UPDATE safety_notification_outbox
            SET status = 'retry', next_attempt_at = ?
            WHERE status = 'sending'
            """,
            (_format_time(_utc_now()),),
        )
        self._connection.execute(
            """
            UPDATE safety_notification_deliveries
            SET status = 'retry', next_attempt_at = ?,
                last_error = COALESCE(
                    last_error,
                    'worker_restarted_during_delivery'
                )
            WHERE status = 'sending'
            """,
            (_format_time(_utc_now()),),
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def ready(self) -> bool:
        with self._lock:
            self._connection.execute(
                "SELECT receipt_id FROM edge_batches LIMIT 1"
            ).fetchone()
        return True

    def record_nonce(
        self,
        client_id: str,
        nonce: str,
        request_time: datetime,
        *,
        now: datetime | None = None,
    ) -> None:
        current = now or _utc_now()
        expires = current + timedelta(seconds=EDGE_NONCE_RETENTION_SECONDS)
        with self._transaction() as connection:
            connection.execute(
                "DELETE FROM edge_nonces WHERE expires_at < ?",
                (_format_time(current),),
            )
            try:
                connection.execute(
                    """
                    INSERT INTO edge_nonces(
                        client_id, nonce, request_time, expires_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        client_id,
                        nonce,
                        _format_time(request_time),
                        _format_time(expires),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise EdgeNonceReplayError(
                    "edge request authentication failed"
                ) from error

    def ingest_batch(
        self,
        batch: EdgeTelemetryBatch,
        *,
        body_sha256: str,
        raw_body: bytes,
        received_at: datetime | None = None,
    ) -> dict[str, Any]:
        now = received_at or _utc_now()
        raw_text = raw_body.decode("utf-8")
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM edge_batches WHERE batch_id = ?",
                (batch.batch_id,),
            ).fetchone()
            if existing is not None:
                if existing["body_sha256"] != body_sha256:
                    raise EdgeBatchConflictError(
                        "batch_id is already bound to different content"
                    )
                receipt = self._receipt_from_row(existing)
                receipt["status"] = "duplicate"
                return receipt

            receipt_id = f"edge-receipt-{uuid4()}"
            provisional = (
                "accepted"
                if all(item.quality.valid for item in batch.observations)
                else "partially_accepted"
            )
            connection.execute(
                """
                INSERT INTO edge_batches(
                    receipt_id, batch_id, client_id, mine_id,
                    body_sha256, status, received_at,
                    accepted_observations, rejected_observations,
                    sequence_start, sequence_end, edge_rule_profile_json,
                    raw_batch_json, rejection_details_json,
                    safety_evaluation_next_attempt_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, '[]', ?
                )
                """,
                (
                    receipt_id,
                    batch.batch_id,
                    batch.client_id,
                    batch.mine_id,
                    body_sha256,
                    provisional,
                    _format_time(now),
                    batch.sequence_start,
                    batch.sequence_end,
                    _json(batch.rule_profile.model_dump(mode="json")),
                    raw_text,
                    _format_time(now + timedelta(seconds=1)),
                ),
            )

            accepted = 0
            rejected = 0
            rejection_details: list[dict[str, Any]] = []
            for observation in batch.observations:
                payload = observation.model_dump(mode="json")
                if observation.interval is None:
                    # Preserve pre-extension observation hashes exactly.
                    payload.pop("interval", None)
                payload_sha256 = hashlib.sha256(
                    _json(payload).encode("utf-8")
                ).hexdigest()
                identity = (
                    batch.mine_id,
                    observation.observation_id,
                    observation.revision,
                )
                previous = connection.execute(
                    """
                    SELECT payload_sha256, analytic_accepted,
                           rejection_reason
                    FROM edge_observations
                    WHERE mine_id = ? AND observation_id = ?
                          AND revision = ?
                    """,
                    identity,
                ).fetchone()
                disposition = "accepted"
                reason: str | None = None
                if previous is not None:
                    if previous["payload_sha256"] != payload_sha256:
                        disposition = "rejected"
                        reason = "observation_identity_conflict"
                    elif previous["analytic_accepted"]:
                        disposition = "duplicate"
                    else:
                        disposition = "rejected"
                        reason = previous["rejection_reason"]
                elif not observation.quality.valid:
                    disposition = "rejected"
                    reason = "source_marked_invalid"
                elif observation.quality.completeness < 0.5:
                    disposition = "rejected"
                    reason = "insufficient_completeness"
                elif not observation.quality.clock_synchronized:
                    disposition = "rejected"
                    reason = "clock_not_synchronized"

                analytic_accepted = disposition in {"accepted", "duplicate"}
                if analytic_accepted:
                    accepted += 1
                else:
                    rejected += 1
                    rejection_details.append(
                        {
                            "observation_id": observation.observation_id,
                            "revision": observation.revision,
                            "reason": reason,
                        }
                    )

                if previous is None:
                    connection.execute(
                        """
                        INSERT INTO edge_observations(
                            mine_id, observation_id, revision, source_id,
                            metric_code, value, unit, location_code,
                            observed_at, received_at, sequence_no,
                            source_record_id, source_record_sha256,
                            acquisition_mode, quality_json, interval_json,
                            manual_attestation_json, source_signature,
                            status_code, first_batch_id, ingested_at,
                            analytic_accepted, rejection_reason,
                            payload_sha256
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                            ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            batch.mine_id,
                            observation.observation_id,
                            observation.revision,
                            observation.source_id,
                            observation.metric_code,
                            observation.value,
                            observation.unit,
                            observation.location_code,
                            _format_time(observation.observed_at),
                            _format_time(observation.received_at),
                            observation.sequence_no,
                            observation.source_record_id,
                            observation.source_record_sha256,
                            observation.acquisition_mode,
                            _json(
                                observation.quality.model_dump(mode="json")
                            ),
                            (
                                None
                                if observation.interval is None
                                else _json(
                                    observation.interval.model_dump(
                                        mode="json"
                                    )
                                )
                            ),
                            (
                                None
                                if observation.manual_attestation is None
                                else _json(
                                    observation.manual_attestation.model_dump(
                                        mode="json"
                                    )
                                )
                            ),
                            observation.source_signature,
                            observation.status_code,
                            batch.batch_id,
                            _format_time(now),
                            int(analytic_accepted),
                            reason,
                            payload_sha256,
                        ),
                    )
                connection.execute(
                    """
                    INSERT INTO edge_batch_observations(
                        batch_id, mine_id, observation_id, revision,
                        disposition, reason
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        batch.batch_id,
                        batch.mine_id,
                        observation.observation_id,
                        observation.revision,
                        disposition,
                        reason,
                    ),
                )

            for alert in batch.local_alerts:
                connection.execute(
                    """
                    INSERT INTO edge_local_alert_hints(
                        batch_id, local_alert_id, payload_json
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        batch.batch_id,
                        alert.local_alert_id,
                        _json(alert.model_dump(mode="json")),
                    ),
                )
            status = "accepted" if rejected == 0 else "partially_accepted"
            connection.execute(
                """
                UPDATE edge_batches
                SET status = ?, accepted_observations = ?,
                    rejected_observations = ?,
                    rejection_details_json = ?
                WHERE batch_id = ?
                """,
                (
                    status,
                    accepted,
                    rejected,
                    _json(rejection_details),
                    batch.batch_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM edge_batches WHERE batch_id = ?",
                (batch.batch_id,),
            ).fetchone()
            assert row is not None
            return self._receipt_from_row(row)

    @staticmethod
    def _receipt_from_row(row: sqlite3.Row) -> dict[str, Any]:
        mine_id = row["mine_id"]
        batch_id = row["batch_id"]
        return {
            "schema_version": "edge-telemetry-receipt-v1",
            "receipt_id": row["receipt_id"],
            "batch_id": batch_id,
            "client_id": row["client_id"],
            "mine_id": mine_id,
            "status": row["status"],
            "received_at": row["received_at"],
            "body_sha256": row["body_sha256"],
            "accepted_observations": row["accepted_observations"],
            "rejected_observations": row["rejected_observations"],
            "regulatory_outcome": "not_determined_at_intake",
            "links": {
                "receipt": (
                    f"/v1/edge-telemetry-batches/{batch_id}/receipt"
                ),
                "alerts": f"/v1/safety/alerts?mine_id={mine_id}",
            },
        }

    def get_receipt(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM edge_batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
        return None if row is None else self._receipt_from_row(row)

    def get_batch_document(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT raw_batch_json FROM edge_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        return (
            None
            if row is None
            else json.loads(row["raw_batch_json"])
        )

    def batch_evaluation_observation_keys(
        self,
        batch_id: str,
    ) -> set[tuple[str, int]]:
        """Return only observations newly accepted in this exact batch."""

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT observation_id, revision
                FROM edge_batch_observations
                WHERE batch_id = ? AND disposition = 'accepted'
                """,
                (batch_id,),
            ).fetchall()
        return {
            (str(row["observation_id"]), int(row["revision"]))
            for row in rows
        }

    def get_batch_evaluation(
        self,
        batch_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT safety_evaluation_status,
                       safety_evaluation_attempts,
                       safety_evaluation_result_status,
                       safety_evaluation_error_code,
                       safety_evaluation_updated_at,
                       safety_evaluation_next_attempt_at,
                       safety_evaluation_lease_expires_at,
                       safety_evaluation_trigger
                FROM edge_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        if row is None:
            return None
        return self._evaluation_status_from_row(row)

    @staticmethod
    def _evaluation_status_from_row(
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        fields = (
            "safety_evaluation_status",
            "safety_evaluation_attempts",
            "safety_evaluation_result_status",
            "safety_evaluation_error_code",
            "safety_evaluation_updated_at",
            "safety_evaluation_next_attempt_at",
            "safety_evaluation_lease_expires_at",
            "safety_evaluation_trigger",
        )
        return {
            key.removeprefix("safety_evaluation_"): row[key]
            for key in fields
        }

    @staticmethod
    def _evaluation_claim_from_row(
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        return {
            "batch_id": row["batch_id"],
            "mine_id": row["mine_id"],
            "document": json.loads(row["raw_batch_json"]),
            "attempts": int(row["safety_evaluation_attempts"]),
            "lease_token": row["safety_evaluation_lease_token"],
            "lease_expires_at": row[
                "safety_evaluation_lease_expires_at"
            ],
            "trigger": row["safety_evaluation_trigger"],
        }

    @staticmethod
    def _expire_evaluation_leases(
        connection: sqlite3.Connection,
        *,
        now_text: str,
        maximum_attempts: int,
    ) -> None:
        connection.execute(
            """
            UPDATE edge_batches
            SET safety_evaluation_status = CASE
                    WHEN safety_evaluation_attempts >= ? THEN 'dead'
                    ELSE 'failed'
                END,
                safety_evaluation_error_code =
                    COALESCE(
                        safety_evaluation_error_code,
                        'worker_lease_expired'
                    ),
                safety_evaluation_next_attempt_at = CASE
                    WHEN safety_evaluation_attempts >= ? THEN NULL
                    ELSE ?
                END,
                safety_evaluation_lease_token = NULL,
                safety_evaluation_lease_expires_at = NULL,
                safety_evaluation_updated_at = ?
            WHERE safety_evaluation_status = 'running'
              AND safety_evaluation_lease_expires_at IS NOT NULL
              AND safety_evaluation_lease_expires_at <= ?
            """,
            (
                maximum_attempts,
                maximum_attempts,
                now_text,
                now_text,
                now_text,
            ),
        )
        connection.execute(
            """
            UPDATE edge_batches
            SET safety_evaluation_status = 'dead',
                safety_evaluation_next_attempt_at = NULL,
                safety_evaluation_lease_token = NULL,
                safety_evaluation_lease_expires_at = NULL,
                safety_evaluation_updated_at = ?
            WHERE safety_evaluation_status = 'failed'
              AND safety_evaluation_attempts >= ?
            """,
            (now_text, maximum_attempts),
        )

    def _claim_evaluation_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        trigger: str,
        maximum_attempts: int,
        lease_seconds: float,
        now: datetime,
        force: bool,
        reset_terminal: bool,
    ) -> dict[str, Any] | None:
        status = str(row["safety_evaluation_status"])
        attempts = int(row["safety_evaluation_attempts"])
        now_text = _format_time(now)
        next_attempt_at = row["safety_evaluation_next_attempt_at"]
        if status == "failed" and not force and (
            next_attempt_at is not None and next_attempt_at > now_text
        ):
            return None
        if status in {"completed", "dead"}:
            if not reset_terminal:
                return None
            attempts = 0
        elif status not in {"pending", "failed"}:
            return None
        if attempts >= maximum_attempts and not reset_terminal:
            connection.execute(
                """
                UPDATE edge_batches
                SET safety_evaluation_status = 'dead',
                    safety_evaluation_next_attempt_at = NULL,
                    safety_evaluation_updated_at = ?
                WHERE batch_id = ?
                """,
                (now_text, row["batch_id"]),
            )
            return None
        running = connection.execute(
            """
            SELECT 1
            FROM edge_batches
            WHERE mine_id = ?
              AND batch_id != ?
              AND safety_evaluation_status = 'running'
              AND safety_evaluation_lease_expires_at > ?
            LIMIT 1
            """,
            (row["mine_id"], row["batch_id"], now_text),
        ).fetchone()
        if running is not None:
            return None
        token = str(uuid4())
        lease_expires_at = _format_time(
            now + timedelta(seconds=lease_seconds)
        )
        connection.execute(
            """
            UPDATE edge_batches
            SET safety_evaluation_status = 'running',
                safety_evaluation_attempts = ?,
                safety_evaluation_result_status = NULL,
                safety_evaluation_error_code = NULL,
                safety_evaluation_updated_at = ?,
                safety_evaluation_next_attempt_at = NULL,
                safety_evaluation_lease_token = ?,
                safety_evaluation_lease_expires_at = ?,
                safety_evaluation_trigger = ?
            WHERE batch_id = ?
            """,
            (
                attempts + 1,
                now_text,
                token,
                lease_expires_at,
                trigger,
                row["batch_id"],
            ),
        )
        claimed = connection.execute(
            "SELECT * FROM edge_batches WHERE batch_id = ?",
            (row["batch_id"],),
        ).fetchone()
        assert claimed is not None
        return self._evaluation_claim_from_row(claimed)

    def claim_batch_evaluation(
        self,
        batch_id: str,
        *,
        trigger: Literal["intake", "manual"],
        maximum_attempts: int,
        lease_seconds: float,
        force: bool = False,
        reset_terminal: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        current = (now or _utc_now()).astimezone(UTC)
        now_text = _format_time(current)
        with self._transaction() as connection:
            self._expire_evaluation_leases(
                connection,
                now_text=now_text,
                maximum_attempts=maximum_attempts,
            )
            row = connection.execute(
                "SELECT * FROM edge_batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if row is None:
                raise KeyError(batch_id)
            return self._claim_evaluation_row(
                connection,
                row,
                trigger=trigger,
                maximum_attempts=maximum_attempts,
                lease_seconds=lease_seconds,
                now=current,
                force=force,
                reset_terminal=reset_terminal,
            )

    def claim_next_batch_evaluation(
        self,
        *,
        maximum_attempts: int,
        lease_seconds: float,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        current = (now or _utc_now()).astimezone(UTC)
        now_text = _format_time(current)
        with self._transaction() as connection:
            self._expire_evaluation_leases(
                connection,
                now_text=now_text,
                maximum_attempts=maximum_attempts,
            )
            row = connection.execute(
                """
                SELECT candidate.*
                FROM edge_batches candidate
                WHERE (
                    (
                        candidate.safety_evaluation_status = 'pending'
                        AND (
                            candidate.safety_evaluation_next_attempt_at
                                IS NULL
                            OR candidate.safety_evaluation_next_attempt_at
                                <= ?
                        )
                    )
                    OR (
                        candidate.safety_evaluation_status = 'failed'
                        AND (
                            candidate.safety_evaluation_next_attempt_at
                                IS NULL
                            OR candidate.safety_evaluation_next_attempt_at
                                <= ?
                        )
                    )
                )
                  AND candidate.safety_evaluation_attempts < ?
                  AND NOT EXISTS (
                      SELECT 1
                      FROM edge_batches running
                      WHERE running.mine_id = candidate.mine_id
                        AND running.batch_id != candidate.batch_id
                        AND running.safety_evaluation_status = 'running'
                        AND running.safety_evaluation_lease_expires_at > ?
                  )
                ORDER BY
                    CASE candidate.safety_evaluation_status
                        WHEN 'failed' THEN 0
                        ELSE 1
                    END,
                    COALESCE(
                        candidate.safety_evaluation_next_attempt_at,
                        candidate.received_at
                    ),
                    candidate.received_at,
                    candidate.batch_id
                LIMIT 1
                """,
                (now_text, now_text, maximum_attempts, now_text),
            ).fetchone()
            if row is None:
                return None
            return self._claim_evaluation_row(
                connection,
                row,
                trigger="worker",
                maximum_attempts=maximum_attempts,
                lease_seconds=lease_seconds,
                now=current,
                force=False,
                reset_terminal=False,
            )

    def renew_batch_evaluation_lease(
        self,
        batch_id: str,
        lease_token: str,
        *,
        lease_seconds: float,
        now: datetime | None = None,
    ) -> bool:
        current = (now or _utc_now()).astimezone(UTC)
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE edge_batches
                SET safety_evaluation_lease_expires_at = ?,
                    safety_evaluation_updated_at = ?
                WHERE batch_id = ?
                  AND safety_evaluation_status = 'running'
                  AND safety_evaluation_lease_token = ?
                """,
                (
                    _format_time(
                        current + timedelta(seconds=lease_seconds)
                    ),
                    _format_time(current),
                    batch_id,
                    lease_token,
                ),
            )
        return cursor.rowcount == 1

    def finish_batch_evaluation(
        self,
        batch_id: str,
        lease_token: str,
        *,
        succeeded: bool,
        maximum_attempts: int,
        result_status: str | None = None,
        error_code: str | None = None,
        retry_at: datetime | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        if succeeded and (error_code is not None or result_status is None):
            raise ValueError(
                "successful evaluation requires only result_status"
            )
        if not succeeded and (
            not error_code or result_status is not None
        ):
            raise ValueError(
                "failed evaluation requires only a stable error_code"
            )
        current = (now or _utc_now()).astimezone(UTC)
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT safety_evaluation_attempts
                FROM edge_batches
                WHERE batch_id = ?
                  AND safety_evaluation_status = 'running'
                  AND safety_evaluation_lease_token = ?
                """,
                (batch_id, lease_token),
            ).fetchone()
            if row is None:
                return None
            terminal = (
                not succeeded
                and int(row["safety_evaluation_attempts"])
                >= maximum_attempts
            )
            status = (
                "completed"
                if succeeded
                else "dead"
                if terminal
                else "failed"
            )
            connection.execute(
                """
                UPDATE edge_batches
                SET safety_evaluation_status = ?,
                    safety_evaluation_result_status = ?,
                    safety_evaluation_error_code = ?,
                    safety_evaluation_updated_at = ?,
                    safety_evaluation_next_attempt_at = ?,
                    safety_evaluation_lease_token = NULL,
                    safety_evaluation_lease_expires_at = NULL
                WHERE batch_id = ?
                  AND safety_evaluation_status = 'running'
                  AND safety_evaluation_lease_token = ?
                """,
                (
                    status,
                    result_status,
                    error_code,
                    _format_time(current),
                    (
                        _format_time(retry_at)
                        if not succeeded
                        and not terminal
                        and retry_at is not None
                        else None
                    ),
                    batch_id,
                    lease_token,
                ),
            )
            current_row = connection.execute(
                "SELECT * FROM edge_batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            assert current_row is not None
            result = self._evaluation_status_from_row(current_row)
        return result

    def mark_batch_evaluation(
        self,
        batch_id: str,
        *,
        status: Literal["completed", "failed"],
        result_status: str | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        if status == "completed" and error_code is not None:
            raise ValueError("completed evaluation cannot contain error_code")
        if status == "failed" and (
            not error_code or result_status is not None
        ):
            raise ValueError(
                "failed evaluation requires only a stable error_code"
            )
        now = _format_time(_utc_now())
        with self._transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE edge_batches
                SET safety_evaluation_status = ?,
                    safety_evaluation_attempts =
                        safety_evaluation_attempts + 1,
                    safety_evaluation_result_status = ?,
                    safety_evaluation_error_code = ?,
                    safety_evaluation_updated_at = ?
                WHERE batch_id = ?
                """,
                (
                    status,
                    result_status,
                    error_code,
                    now,
                    batch_id,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError(batch_id)
        result = self.get_batch_evaluation(batch_id)
        assert result is not None
        return result

    def evaluation_health(
        self,
        mine_ids: set[str] | None = None,
    ) -> dict[str, int]:
        clauses: list[str] = []
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return {
                    "pending": 0,
                    "failed": 0,
                    "running": 0,
                    "dead": 0,
                    "completed": 0,
                    "backlog": 0,
                }
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            arguments.extend(sorted(mine_ids))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT safety_evaluation_status, COUNT(*) AS total
                FROM edge_batches
                {where}
                GROUP BY safety_evaluation_status
                """,
                tuple(arguments),
            ).fetchall()
        counts = {
            str(row["safety_evaluation_status"]): int(row["total"])
            for row in rows
        }
        pending = counts.get("pending", 0)
        failed = counts.get("failed", 0)
        return {
            "pending": pending,
            "failed": failed,
            "running": counts.get("running", 0),
            "dead": counts.get("dead", 0),
            "completed": counts.get("completed", 0),
            "backlog": pending + failed,
        }

    def list_batch_evaluations(
        self,
        *,
        mine_ids: set[str] | None = None,
        status: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        allowed_statuses = {
            "pending",
            "failed",
            "running",
            "dead",
            "completed",
        }
        if status is not None and status not in allowed_statuses:
            raise ValueError("unsupported edge evaluation status")
        clauses: list[str] = []
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            arguments.extend(sorted(mine_ids))
        if status is not None:
            clauses.append("safety_evaluation_status = ?")
            arguments.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        arguments.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT *
                FROM edge_batches
                {where}
                ORDER BY
                    CASE safety_evaluation_status
                        WHEN 'dead' THEN 0
                        WHEN 'failed' THEN 1
                        WHEN 'running' THEN 2
                        WHEN 'pending' THEN 3
                        ELSE 4
                    END,
                    COALESCE(
                        safety_evaluation_updated_at,
                        received_at
                    ) DESC,
                    batch_id
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(
                {
                    "batch_id": str(row["batch_id"]),
                    "mine_id": str(row["mine_id"]),
                    "client_id": str(row["client_id"]),
                    "received_at": str(row["received_at"]),
                    "intake_status": str(row["status"]),
                    "accepted_observations": int(
                        row["accepted_observations"]
                    ),
                    "rejected_observations": int(
                        row["rejected_observations"]
                    ),
                    **self._evaluation_status_from_row(row),
                }
            )
        return result

    def list_batch_documents(
        self,
        *,
        mine_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        where = "WHERE mine_id = ?" if mine_id else ""
        arguments: list[Any] = [mine_id] if mine_id else []
        arguments.append(max(1, min(limit, 1000)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT batch_id, received_at, raw_batch_json
                FROM edge_batches
                {where}
                ORDER BY received_at DESC
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
        return [
            {
                "batch_id": row["batch_id"],
                "received_at": row["received_at"],
                "document": json.loads(row["raw_batch_json"]),
            }
            for row in rows
        ]

    def recent_observations(
        self,
        mine_id: str,
        *,
        metric_codes: set[str] | None = None,
        since: datetime | None = None,
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        clauses = ["mine_id = ?", "analytic_accepted = 1"]
        arguments: list[Any] = [mine_id]
        if metric_codes:
            placeholders = ",".join("?" for _ in metric_codes)
            clauses.append(f"metric_code IN ({placeholders})")
            arguments.extend(sorted(metric_codes))
        if since is not None:
            clauses.append("observed_at >= ?")
            arguments.append(_format_time(since))
        arguments.append(max(1, min(limit, 10_000)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM edge_observations
                WHERE {' AND '.join(clauses)}
                ORDER BY observed_at ASC, sequence_no ASC, revision ASC
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = _row_dict(row)
            item["quality"] = json.loads(item.pop("quality_json"))
            interval = item.pop("interval_json")
            item["interval"] = (
                None if interval is None else json.loads(interval)
            )
            manual = item.pop("manual_attestation_json")
            item["manual_attestation"] = (
                None if manual is None else json.loads(manual)
            )
            item["analytic_accepted"] = bool(item["analytic_accepted"])
            result.append(item)
        return result

    def load_safety_states(
        self,
        mine_id: str,
        *,
        rule_version: str,
        rule_fingerprint: str,
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT state_json FROM safety_signal_states
                WHERE mine_id = ? AND rule_version = ?
                      AND rule_fingerprint = ?
                ORDER BY state_key
                """,
                (mine_id, rule_version, rule_fingerprint),
            ).fetchall()
        return [json.loads(row["state_json"]) for row in rows]

    def save_safety_evaluation(
        self,
        *,
        batch_id: str | None,
        result: dict[str, Any],
    ) -> str:
        run_id = f"safety-run-{uuid4()}"
        created_at = _format_time(_utc_now())
        with self._transaction() as connection:
            for state in result.get("states", []):
                connection.execute(
                    """
                    INSERT INTO safety_signal_states(
                        mine_id, state_key, state_json, rule_version,
                        rule_fingerprint, evaluated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mine_id, state_key) DO UPDATE SET
                        state_json = excluded.state_json,
                        rule_version = excluded.rule_version,
                        rule_fingerprint = excluded.rule_fingerprint,
                        evaluated_at = excluded.evaluated_at
                    """,
                    (
                        result["mine_id"],
                        state["state_key"],
                        _json(state),
                        result["rule_version"],
                        result["rule_fingerprint"],
                        result["decision_time"],
                    ),
                )
            connection.execute(
                """
                INSERT INTO safety_evaluation_runs(
                    run_id, batch_id, mine_id, decision_time,
                    rule_version, rule_fingerprint, result_json,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    batch_id,
                    result["mine_id"],
                    result["decision_time"],
                    result["rule_version"],
                    result["rule_fingerprint"],
                    _json(result),
                    created_at,
                ),
            )
        return run_id

    def list_safety_runs(
        self,
        *,
        mine_ids: set[str] | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        where = ""
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            where = f"WHERE mine_id IN ({placeholders})"
            arguments.extend(sorted(mine_ids))
        arguments.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM safety_evaluation_runs
                {where}
                ORDER BY decision_time DESC
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
        return [
            {
                **{
                    key: row[key]
                    for key in row.keys()
                    if key != "result_json"
                },
                "result": json.loads(row["result_json"]),
            }
            for row in rows
        ]

    def list_latest_metrics(
        self,
        mine_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["o.analytic_accepted = 1"]
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"o.mine_id IN ({placeholders})")
            arguments.extend(sorted(mine_ids))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT o.*
                FROM edge_observations o
                WHERE {' AND '.join(clauses)}
                  AND NOT EXISTS (
                      SELECT 1
                      FROM edge_observations newer
                      WHERE newer.analytic_accepted = 1
                        AND newer.mine_id = o.mine_id
                        AND newer.metric_code = o.metric_code
                        AND newer.location_code = o.location_code
                        AND (
                            newer.observed_at > o.observed_at
                            OR (
                                newer.observed_at = o.observed_at
                                AND newer.revision > o.revision
                            )
                            OR (
                                newer.observed_at = o.observed_at
                                AND newer.revision = o.revision
                                AND newer.sequence_no > o.sequence_no
                            )
                            OR (
                                newer.observed_at = o.observed_at
                                AND newer.revision = o.revision
                                AND newer.sequence_no = o.sequence_no
                                AND newer.ingested_at > o.ingested_at
                            )
                            OR (
                                newer.observed_at = o.observed_at
                                AND newer.revision = o.revision
                                AND newer.sequence_no = o.sequence_no
                                AND newer.ingested_at = o.ingested_at
                                AND newer.observation_id > o.observation_id
                            )
                        )
                  )
                ORDER BY o.mine_id, o.metric_code, o.location_code
                """,
                tuple(arguments),
            ).fetchall()
        return [_row_dict(row) for row in rows]

    def upsert_mine(
        self,
        profile: dict[str, Any],
        *,
        actor_id: str,
    ) -> dict[str, Any]:
        mine_id = str(profile["mine_id"])
        mine_name = str(profile.get("mine_name") or mine_id).strip()
        if not mine_name:
            raise ValueError("mine_name is required")
        longitude = profile.get("longitude")
        latitude = profile.get("latitude")
        if longitude is not None and not -180 <= float(longitude) <= 180:
            raise ValueError("longitude must be between -180 and 180")
        if latitude is not None and not -90 <= float(latitude) <= 90:
            raise ValueError("latitude must be between -90 and 90")
        now = _format_time(_utc_now())
        with self._transaction() as connection:
            connection.execute(
                """
                INSERT INTO mine_registry(
                    mine_id, mine_name, gas_category, longitude, latitude,
                    approved_capacity_tpy,
                    approved_underground_personnel,
                    enabled, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mine_id) DO UPDATE SET
                    mine_name = excluded.mine_name,
                    gas_category = excluded.gas_category,
                    longitude = excluded.longitude,
                    latitude = excluded.latitude,
                    approved_capacity_tpy = excluded.approved_capacity_tpy,
                    approved_underground_personnel =
                        excluded.approved_underground_personnel,
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (
                    mine_id,
                    mine_name,
                    profile.get("gas_category"),
                    longitude,
                    latitude,
                    profile.get("approved_capacity_tpy"),
                    profile.get("approved_underground_personnel"),
                    int(bool(profile.get("enabled", True))),
                    now,
                    actor_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM mine_registry WHERE mine_id = ?",
                (mine_id,),
            ).fetchone()
            assert row is not None
            return self._mine_from_row(row)

    @staticmethod
    def _mine_from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = _row_dict(row)
        item["enabled"] = bool(item["enabled"])
        return item

    def list_mines(
        self,
        mine_ids: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        where = ""
        arguments: tuple[Any, ...] = ()
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            where = f"WHERE mine_id IN ({placeholders})"
            arguments = tuple(sorted(mine_ids))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM mine_registry
                {where}
                ORDER BY mine_name, mine_id
                """,
                arguments,
            ).fetchall()
        return [self._mine_from_row(row) for row in rows]

    def register_safety_rule(
        self,
        *,
        snapshot: dict[str, Any],
        fingerprint: str,
        actor_id: str,
        status: str = "draft",
    ) -> tuple[dict[str, Any], bool]:
        if status not in {"proposal", "draft"}:
            raise ValueError("new safety rule status must be proposal or draft")
        version = str(snapshot["version"])
        snapshot_text = _json(snapshot)
        now = _format_time(_utc_now())
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT * FROM safety_rule_profiles
                WHERE rule_version = ?
                """,
                (version,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["fingerprint"] != fingerprint
                    or existing["snapshot_json"] != snapshot_text
                ):
                    raise SafetyRuleConflictError(
                        "rule version is already bound to different content"
                    )
                return self._safety_rule_from_row(existing), False
            by_fingerprint = connection.execute(
                """
                SELECT rule_version FROM safety_rule_profiles
                WHERE fingerprint = ?
                """,
                (fingerprint,),
            ).fetchone()
            if by_fingerprint is not None:
                raise SafetyRuleConflictError(
                    "identical rule content already has another version"
                )
            connection.execute(
                """
                INSERT INTO safety_rule_profiles(
                    rule_version, fingerprint, snapshot_json, status,
                    effective_from, effective_to, created_at, created_by,
                    approved_at, approved_by, decision_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)
                """,
                (
                    version,
                    fingerprint,
                    snapshot_text,
                    status,
                    snapshot["effective_from"],
                    snapshot.get("effective_to"),
                    now,
                    actor_id,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM safety_rule_profiles
                WHERE rule_version = ?
                """,
                (version,),
            ).fetchone()
            assert row is not None
            return self._safety_rule_from_row(row), True

    @staticmethod
    def _safety_rule_from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = _row_dict(row)
        item["snapshot"] = json.loads(item.pop("snapshot_json"))
        return item

    def list_safety_rules(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM safety_rule_profiles
                ORDER BY effective_from DESC, created_at DESC
                """
            ).fetchall()
        return [self._safety_rule_from_row(row) for row in rows]

    def effective_safety_rule(
        self,
        decision_time: datetime,
    ) -> dict[str, Any] | None:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM safety_rule_profiles
                WHERE status = 'approved'
                """,
            ).fetchall()
        current = decision_time.astimezone(UTC)
        eligible = [
            row
            for row in rows
            if (
                _parse_time(row["effective_from"]) <= current
                and (
                    row["effective_to"] is None
                    or current < _parse_time(row["effective_to"])
                )
            )
        ]
        if not eligible:
            return None
        row = max(
            eligible,
            key=lambda item: (
                _parse_time(item["approved_at"] or item["created_at"]),
                _parse_time(item["created_at"]),
            ),
        )
        return self._safety_rule_from_row(row)

    def change_safety_rule_status(
        self,
        rule_version: str,
        *,
        action: str,
        expected_fingerprint: str,
        actor_id: str,
        note: str,
    ) -> dict[str, Any]:
        if action not in {"approve", "retire"}:
            raise ValueError("unsupported safety rule action")
        now = _format_time(_utc_now())
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM safety_rule_profiles
                WHERE rule_version = ?
                """,
                (rule_version,),
            ).fetchone()
            if row is None:
                raise KeyError(rule_version)
            if row["fingerprint"] != expected_fingerprint:
                raise SafetyRuleConflictError(
                    "safety rule fingerprint has changed"
                )
            if action == "retire":
                if row["status"] != "approved":
                    raise SafetyRuleConflictError(
                        "only an approved rule can be retired"
                    )
                target_status = "retired"
            else:
                if row["status"] == "approved":
                    return self._safety_rule_from_row(row)
                if row["created_by"] == actor_id:
                    raise SafetyRuleConflictError(
                        "rule author cannot approve the same rule version"
                    )
                approved_rows = connection.execute(
                    """
                    SELECT * FROM safety_rule_profiles
                    WHERE status = 'approved'
                          AND rule_version != ?
                    """,
                    (rule_version,),
                ).fetchall()
                start = _parse_time(row["effective_from"])
                end = (
                    None
                    if row["effective_to"] is None
                    else _parse_time(row["effective_to"])
                )
                overlap = any(
                    (
                        existing["effective_to"] is None
                        or _parse_time(existing["effective_to"]) > start
                    )
                    and (
                        end is None
                        or _parse_time(existing["effective_from"]) < end
                    )
                    for existing in approved_rows
                )
                if overlap:
                    raise SafetyRuleConflictError(
                        "another approved rule overlaps this effective window"
                    )
                target_status = "approved"
            if action == "approve":
                connection.execute(
                    """
                    UPDATE safety_rule_profiles
                    SET status = ?, approved_at = ?, approved_by = ?,
                        approval_note = ?, decision_note = ?
                    WHERE rule_version = ?
                    """,
                    (
                        target_status,
                        now,
                        actor_id,
                        note.strip(),
                        note.strip(),
                        rule_version,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE safety_rule_profiles
                    SET status = ?, retired_at = ?, retired_by = ?,
                        retirement_note = ?, decision_note = ?
                    WHERE rule_version = ?
                    """,
                    (
                        target_status,
                        now,
                        actor_id,
                        note.strip(),
                        note.strip(),
                        rule_version,
                    ),
                )
            current = connection.execute(
                """
                SELECT * FROM safety_rule_profiles
                WHERE rule_version = ?
                """,
                (rule_version,),
            ).fetchone()
            assert current is not None
            return self._safety_rule_from_row(current)

    @staticmethod
    def _responsibility_route_from_row(
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        item = _row_dict(row)
        item["enabled"] = bool(item["enabled"])
        return item

    def upsert_responsibility_route(
        self,
        *,
        route_id: str,
        mine_id: str | None,
        category: str | None,
        minimum_level: AlertLevel,
        primary_user_id: str,
        primary_username: str,
        backup_user_id: str | None,
        backup_username: str | None,
        escalation_minutes: int,
        enabled: bool,
        actor_id: str,
    ) -> dict[str, Any]:
        route_id = route_id.strip()
        mine_id = mine_id.strip() if mine_id else None
        category = category.strip() if category else None
        primary_user_id = primary_user_id.strip()
        primary_username = primary_username.strip()
        backup_user_id = backup_user_id.strip() if backup_user_id else None
        backup_username = (
            backup_username.strip() if backup_username else None
        )
        if (
            not route_id
            or len(route_id) > 128
            or not primary_user_id
            or not primary_username
        ):
            raise ValueError("route and primary user are required")
        if (backup_user_id is None) != (backup_username is None):
            raise ValueError("backup user id and username must be paired")
        if backup_user_id == primary_user_id:
            raise ValueError("primary and backup users must differ")
        if not 1 <= escalation_minutes <= 10_080:
            raise ValueError(
                "escalation_minutes must be between 1 and 10080"
            )
        now = _format_time(_utc_now())
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT created_at, created_by
                FROM safety_responsibility_routes
                WHERE route_id = ?
                """,
                (route_id,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO safety_responsibility_routes(
                    route_id, mine_id, category, minimum_level,
                    primary_user_id, primary_username,
                    backup_user_id, backup_username,
                    escalation_minutes, enabled,
                    created_at, created_by, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(route_id) DO UPDATE SET
                    mine_id = excluded.mine_id,
                    category = excluded.category,
                    minimum_level = excluded.minimum_level,
                    primary_user_id = excluded.primary_user_id,
                    primary_username = excluded.primary_username,
                    backup_user_id = excluded.backup_user_id,
                    backup_username = excluded.backup_username,
                    escalation_minutes = excluded.escalation_minutes,
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (
                    route_id,
                    mine_id,
                    category,
                    minimum_level,
                    primary_user_id,
                    primary_username,
                    backup_user_id,
                    backup_username,
                    escalation_minutes,
                    int(enabled),
                    (
                        existing["created_at"]
                        if existing is not None
                        else now
                    ),
                    (
                        existing["created_by"]
                        if existing is not None
                        else actor_id
                    ),
                    now,
                    actor_id,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM safety_responsibility_routes
                WHERE route_id = ?
                """,
                (route_id,),
            ).fetchone()
            assert row is not None
            return self._responsibility_route_from_row(row)

    def list_responsibility_routes(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM safety_responsibility_routes
                ORDER BY enabled DESC, mine_id, category, route_id
                """
            ).fetchall()
        return [
            self._responsibility_route_from_row(row) for row in rows
        ]

    def delete_responsibility_route(self, route_id: str) -> bool:
        with self._transaction() as connection:
            accountable = connection.execute(
                """
                SELECT recipient.alert_id, recipient.username
                FROM safety_alert_recipients recipient
                WHERE recipient.route_id = ?
                  AND recipient.recipient_role = 'primary'
                """,
                (route_id,),
            ).fetchall()
            connection.execute(
                """
                DELETE FROM safety_alert_recipients
                WHERE route_id = ?
                """,
                (route_id,),
            )
            for recipient in accountable:
                connection.execute(
                    """
                    UPDATE safety_alerts
                    SET assignee = NULL
                    WHERE alert_id = ? AND assignee = ?
                    """,
                    (recipient["alert_id"], recipient["username"]),
                )
            cursor = connection.execute(
                """
                DELETE FROM safety_responsibility_routes
                WHERE route_id = ?
                """,
                (route_id,),
            )
        return cursor.rowcount == 1

    @staticmethod
    def _apply_responsibility_route(
        connection: sqlite3.Connection,
        *,
        alert_id: str,
        mine_id: str,
        category: str,
        level: str,
        assigned_at: datetime,
    ) -> dict[str, Any] | None:
        rows = connection.execute(
            """
            SELECT *
            FROM safety_responsibility_routes
            WHERE enabled = 1
              AND (mine_id IS NULL OR mine_id = ?)
              AND (category IS NULL OR category = ?)
            """,
            (mine_id, category),
        ).fetchall()
        eligible = [
            row
            for row in rows
            if _LEVEL_RANK[str(row["minimum_level"])]
            <= _LEVEL_RANK[level]
        ]
        eligible.sort(
            key=lambda row: (
                int(row["mine_id"] is not None),
                int(row["category"] is not None),
                _LEVEL_RANK[str(row["minimum_level"])],
                str(row["updated_at"]),
                str(row["route_id"]),
            ),
            reverse=True,
        )
        stale_route_recipients = connection.execute(
            """
            SELECT *
            FROM safety_alert_recipients
            WHERE alert_id = ? AND route_id IS NULL
              AND recipient_role IN ('primary', 'backup')
            """,
            (alert_id,),
        ).fetchall()
        for recipient in stale_route_recipients:
            if recipient["recipient_role"] == "primary":
                connection.execute(
                    """
                    UPDATE safety_alerts
                    SET assignee = NULL
                    WHERE alert_id = ? AND assignee = ?
                    """,
                    (alert_id, recipient["username"]),
                )
        if stale_route_recipients:
            connection.execute(
                """
                DELETE FROM safety_alert_recipients
                WHERE alert_id = ? AND route_id IS NULL
                  AND recipient_role IN ('primary', 'backup')
                """,
                (alert_id,),
            )
        existing_rows = connection.execute(
            """
            SELECT *
            FROM safety_alert_recipients
            WHERE alert_id = ?
              AND route_id IS NOT NULL
              AND recipient_role IN ('primary', 'observer')
            ORDER BY route_id, recipient_role, recipient_id
            """,
            (alert_id,),
        ).fetchall()
        existing_by_route: dict[str, list[sqlite3.Row]] = {}
        for recipient in existing_rows:
            existing_by_route.setdefault(
                str(recipient["route_id"]), []
            ).append(recipient)
        desired_route_ids = {str(route["route_id"]) for route in eligible}
        changed = bool(stale_route_recipients)
        assigned_text = _format_time(assigned_at)
        for index, route in enumerate(eligible):
            route_id = str(route["route_id"])
            desired_role = "primary" if index == 0 else "observer"
            current = existing_by_route.get(route_id, [])
            exact = (
                len(current) == 1
                and current[0]["recipient_role"] == desired_role
                and current[0]["user_id"] == route["primary_user_id"]
                and current[0]["username"] == route["primary_username"]
            )
            if exact:
                continue
            preserved = next(
                (
                    item
                    for item in current
                    if item["user_id"] == route["primary_user_id"]
                ),
                None,
            )
            user_changed = bool(current) and preserved is None
            connection.execute(
                """
                DELETE FROM safety_alert_recipients
                WHERE alert_id = ? AND route_id = ?
                  AND recipient_role IN ('primary', 'observer')
                """,
                (alert_id, route_id),
            )
            if user_changed:
                connection.execute(
                    """
                    DELETE FROM safety_alert_recipients
                    WHERE alert_id = ? AND route_id = ?
                      AND recipient_role = 'backup'
                    """,
                    (alert_id, route_id),
                )
            connection.execute(
                """
                INSERT INTO safety_alert_recipients(
                    recipient_id, alert_id, user_id, username,
                    recipient_role, route_id, assigned_at, read_at,
                    escalated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        preserved["recipient_id"]
                        if preserved is not None
                        else f"recipient-{uuid4()}"
                    ),
                    alert_id,
                    route["primary_user_id"],
                    route["primary_username"],
                    desired_role,
                    route_id,
                    (
                        preserved["assigned_at"]
                        if preserved is not None
                        else assigned_text
                    ),
                    (
                        preserved["read_at"]
                        if preserved is not None
                        else None
                    ),
                    (
                        preserved["escalated_at"]
                        if preserved is not None
                        else None
                    ),
                ),
            )
            changed = True
        removed_route_ids = sorted(
            set(existing_by_route) - desired_route_ids
        )
        for route_id in removed_route_ids:
            connection.execute(
                """
                DELETE FROM safety_alert_recipients
                WHERE alert_id = ? AND route_id = ?
                """,
                (alert_id, route_id),
            )
            changed = True

        previous_primary = next(
            (
                row
                for row in existing_rows
                if row["recipient_role"] == "primary"
            ),
            None,
        )
        primary_route = eligible[0] if eligible else None
        primary_changed = (
            (previous_primary is None) != (primary_route is None)
            or (
                previous_primary is not None
                and primary_route is not None
                and (
                    previous_primary["route_id"]
                    != primary_route["route_id"]
                    or previous_primary["user_id"]
                    != primary_route["primary_user_id"]
                    or previous_primary["username"]
                    != primary_route["primary_username"]
                )
            )
        )
        if primary_changed:
            alert = connection.execute(
                "SELECT assignee FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            assert alert is not None
            next_assignee = (
                str(primary_route["primary_username"])
                if primary_route is not None
                else (
                    None
                    if previous_primary is not None
                    and alert["assignee"] == previous_primary["username"]
                    else alert["assignee"]
                )
            )
            connection.execute(
                """
                UPDATE safety_alerts
                SET assignee = ?
                WHERE alert_id = ?
                """,
                (next_assignee, alert_id),
            )
            changed = True
        if primary_route is None:
            if not changed:
                return None
            return {
                "changed": True,
                "route_id": None,
                "primary_user_id": None,
                "primary_username": None,
                "backup_user_id": None,
                "backup_username": None,
                "escalation_minutes": None,
                "observers": [],
                "removed_route_ids": removed_route_ids,
            }
        return {
            "changed": changed,
            "route_id": primary_route["route_id"],
            "primary_user_id": primary_route["primary_user_id"],
            "primary_username": primary_route["primary_username"],
            "backup_user_id": primary_route["backup_user_id"],
            "backup_username": primary_route["backup_username"],
            "escalation_minutes": int(
                primary_route["escalation_minutes"]
            ),
            "observers": [
                {
                    "route_id": route["route_id"],
                    "user_id": route["primary_user_id"],
                    "username": route["primary_username"],
                    "backup_user_id": route["backup_user_id"],
                    "backup_username": route["backup_username"],
                    "escalation_minutes": int(
                        route["escalation_minutes"]
                    ),
                }
                for route in eligible[1:]
            ],
            "removed_route_ids": removed_route_ids,
        }

    def route_unassigned_alerts(
        self,
        *,
        actor_id: str = "platform:responsibility-router",
    ) -> int:
        now = _utc_now()
        routed = 0
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT a.*
                FROM safety_alerts a
                WHERE a.operational = 1
                  AND a.status IN ('open', 'acknowledged', 'in_progress')
                """
            ).fetchall()
            for row in rows:
                assignment = self._apply_responsibility_route(
                    connection,
                    alert_id=row["alert_id"],
                    mine_id=row["mine_id"],
                    category=row["category"],
                    level=row["level"],
                    assigned_at=now,
                )
                if assignment is None or not assignment["changed"]:
                    continue
                connection.execute(
                    """
                    UPDATE safety_alerts
                    SET version = version + 1, updated_at = ?,
                        updated_by = ?
                    WHERE alert_id = ?
                    """,
                    (
                        _format_time(now),
                        actor_id,
                        row["alert_id"],
                    ),
                )
                self._append_event(
                    connection,
                    alert_id=row["alert_id"],
                    event_type="auto_assigned",
                    actor_id=actor_id,
                    from_status=row["status"],
                    to_status=row["status"],
                    note=None,
                    payload=assignment,
                    occurred_at=now,
                )
                self._enqueue_notification(
                    connection,
                    alert_id=row["alert_id"],
                    alert_version=int(row["version"]) + 1,
                    event_type="auto_assigned",
                    level=row["level"],
                    payload={
                        "mine_id": row["mine_id"],
                        "category": row["category"],
                        "rule_code": row["rule_code"],
                        "level": row["level"],
                        "status": row["status"],
                        "title": row["title"],
                        "summary": (
                            "正式预警责任路由已更新，主责唯一，"
                            "其余匹配部门同步知会。"
                        ),
                        "location_code": row["location_code"],
                        "detected_at": row["detected_at"],
                        "assignee": assignment["primary_username"],
                        "observer_usernames": [
                            item["username"]
                            for item in assignment["observers"]
                        ],
                        "approval_status": _approval_status(
                            row["rule_profile_json"]
                        ),
                        "operational": True,
                        "advisory_only": True,
                    },
                    occurred_at=now,
                )
                routed += 1
        return routed

    def upsert_platform_alert(
        self,
        *,
        mine_id: str,
        category: str,
        rule_code: str,
        level: AlertLevel,
        title: str,
        summary: str,
        location_code: str,
        detected_at: datetime,
        observation_ids: list[str],
        details: dict[str, Any],
        rule_profile: dict[str, Any],
        operational: bool = True,
        actor_id: str = "platform:safety-engine",
    ) -> dict[str, Any]:
        fingerprint = hashlib.sha256(
            f"{mine_id}\n{category}\n{rule_code}\n{location_code}".encode()
        ).hexdigest()
        now = _utc_now()
        due_hours = {"red": 1, "orange": 4, "yellow": 12, "blue": 24}
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM safety_alerts WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None:
                alert_id = f"alert-{uuid4()}"
                due_at = now + timedelta(hours=due_hours[level])
                connection.execute(
                    """
                    INSERT INTO safety_alerts(
                        alert_id, fingerprint, mine_id, category,
                        rule_code, operational, level, status, title, summary,
                        location_code, detected_at, last_seen_at,
                        due_at, assignee, occurrence_count, version,
                        observation_ids_json, details_json,
                        rule_profile_json, source, updated_at, updated_by
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?,
                        NULL, 1, 1, ?, ?, ?, 'platform_recalculation',
                        ?, ?
                    )
                    """,
                    (
                        alert_id,
                        fingerprint,
                        mine_id,
                        category,
                        rule_code,
                        int(operational),
                        level,
                        title,
                        summary,
                        location_code,
                        _format_time(detected_at),
                        _format_time(detected_at),
                        _format_time(due_at) if operational else None,
                        _json(sorted(set(observation_ids))),
                        _json(details),
                        _json(rule_profile),
                        _format_time(now),
                        actor_id,
                    ),
                )
                self._append_event(
                    connection,
                    alert_id=alert_id,
                    event_type="created",
                    actor_id=actor_id,
                    from_status=None,
                    to_status="open",
                    note=None,
                    payload={"level": level, "rule_code": rule_code},
                    occurred_at=now,
                )
                assignment = (
                    self._apply_responsibility_route(
                        connection,
                        alert_id=alert_id,
                        mine_id=mine_id,
                        category=category,
                        level=level,
                        assigned_at=now,
                    )
                    if operational
                    else None
                )
                if assignment is not None and assignment["changed"]:
                    self._append_event(
                        connection,
                        alert_id=alert_id,
                        event_type="auto_assigned",
                        actor_id="platform:responsibility-router",
                        from_status="open",
                        to_status="open",
                        note=None,
                        payload=assignment,
                        occurred_at=now,
                    )
                if operational:
                    self._enqueue_notification(
                        connection,
                        alert_id=alert_id,
                        alert_version=1,
                        event_type="created",
                        level=level,
                        payload={
                            "mine_id": mine_id,
                            "category": category,
                            "rule_code": rule_code,
                            "level": level,
                            "status": "open",
                            "title": title,
                            "summary": summary,
                            "location_code": location_code,
                            "detected_at": _format_time(detected_at),
                            "assignee": (
                                assignment["primary_username"]
                                if assignment is not None
                                else None
                            ),
                            "approval_status": _approval_status(
                                rule_profile
                            ),
                            "operational": True,
                            "advisory_only": True,
                        },
                        occurred_at=now,
                    )
            else:
                alert_id = row["alert_id"]
                was_operational = bool(row["operational"])
                if was_operational and not operational:
                    # Never let an unapproved shadow evaluation mutate,
                    # reopen or downgrade an existing formal alert.
                    return self._alert_from_row(row)
                old_status = row["status"]
                old_level = row["level"]
                status = (
                    "open"
                    if old_status in {"resolved", "closed"}
                    else old_status
                )
                reopened = status != old_status
                current_level = level
                promoted = operational and not was_operational
                if promoted:
                    status = "open"
                deadline_candidate = now + timedelta(
                    hours=due_hours[current_level]
                )
                if not operational:
                    next_due_at = None
                elif promoted or reopened or row["due_at"] is None:
                    next_due_at = _format_time(deadline_candidate)
                elif (
                    _LEVEL_RANK[current_level] > _LEVEL_RANK[old_level]
                    and _parse_time(row["due_at"]) > deadline_candidate
                ):
                    next_due_at = _format_time(deadline_candidate)
                else:
                    next_due_at = row["due_at"]
                ids = sorted(
                    set(json.loads(row["observation_ids_json"]))
                    | set(observation_ids)
                )[-500:]
                connection.execute(
                    """
                    UPDATE safety_alerts
                    SET operational = ?, level = ?, status = ?, summary = ?,
                        last_seen_at = ?, occurrence_count =
                            occurrence_count + 1,
                        version = version + 1,
                        due_at = ?,
                        observation_ids_json = ?, details_json = ?,
                        rule_profile_json = ?, updated_at = ?,
                        updated_by = ?
                    WHERE alert_id = ?
                    """,
                    (
                        int(operational),
                        current_level,
                        status,
                        summary,
                        _format_time(detected_at),
                        next_due_at,
                        _json(ids),
                        _json(details),
                        _json(rule_profile),
                        _format_time(now),
                        actor_id,
                        alert_id,
                    ),
                )
                if reopened:
                    connection.execute(
                        """
                        UPDATE safety_alert_recipients
                        SET assigned_at = ?, read_at = NULL,
                            escalated_at = NULL
                        WHERE alert_id = ?
                          AND recipient_role IN ('primary', 'observer')
                          AND route_id IS NOT NULL
                        """,
                        (_format_time(now), alert_id),
                    )
                    connection.execute(
                        """
                        DELETE FROM safety_alert_recipients
                        WHERE alert_id = ? AND recipient_role = 'backup'
                        """,
                        (alert_id,),
                    )
                event_type = (
                    "promoted_from_shadow"
                    if promoted
                    else (
                    "reopened"
                    if reopened
                    else (
                        (
                            "escalated"
                            if _LEVEL_RANK[current_level]
                            > _LEVEL_RANK[old_level]
                            else "deescalated"
                        )
                        if current_level != old_level
                        else "observed_again"
                    )
                    )
                )
                self._append_event(
                    connection,
                    alert_id=alert_id,
                    event_type=event_type,
                    actor_id=actor_id,
                    from_status=old_status,
                    to_status=status,
                    note=None,
                    payload={
                        "previous_level": old_level,
                        "level": current_level,
                        "operational": operational,
                    },
                    occurred_at=now,
                )
                assignment = (
                    self._apply_responsibility_route(
                        connection,
                        alert_id=alert_id,
                        mine_id=mine_id,
                        category=category,
                        level=current_level,
                        assigned_at=now,
                    )
                    if operational and status in _OPEN_STATUSES
                    else None
                )
                if assignment is not None and assignment["changed"]:
                    self._append_event(
                        connection,
                        alert_id=alert_id,
                        event_type="auto_assigned",
                        actor_id="platform:responsibility-router",
                        from_status=status,
                        to_status=status,
                        note=None,
                        payload=assignment,
                        occurred_at=now,
                    )
                if operational and event_type in {
                    "promoted_from_shadow",
                    "reopened",
                    "escalated",
                    "deescalated",
                }:
                    self._enqueue_notification(
                        connection,
                        alert_id=alert_id,
                        alert_version=int(row["version"]) + 1,
                        event_type=event_type,
                        level=current_level,
                        payload={
                            "mine_id": mine_id,
                            "category": category,
                            "rule_code": rule_code,
                            "level": current_level,
                            "status": status,
                            "title": title,
                            "summary": summary,
                            "location_code": location_code,
                            "detected_at": _format_time(detected_at),
                            "assignee": (
                                assignment["primary_username"]
                                if assignment is not None
                                else row["assignee"]
                            ),
                            "approval_status": _approval_status(
                                rule_profile
                            ),
                            "operational": True,
                            "advisory_only": True,
                        },
                        occurred_at=now,
                    )
            current = connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            assert current is not None
            return self._alert_from_row(current)

    def auto_resolve_platform_alert(
        self,
        *,
        mine_id: str,
        category: str,
        rule_code: str,
        location_code: str,
        operational: bool = True,
        actor_id: str = "platform:safety-engine",
        note: str = "规则复算已满足清除条件，转为待人工关闭。",
    ) -> dict[str, Any] | None:
        fingerprint = hashlib.sha256(
            f"{mine_id}\n{category}\n{rule_code}\n{location_code}".encode()
        ).hexdigest()
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM safety_alerts WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if row is None or row["status"] not in _OPEN_STATUSES:
                return None
            if bool(row["operational"]) != operational:
                return None
            connection.execute(
                """
                UPDATE safety_alerts
                SET status = 'resolved', version = version + 1,
                    updated_at = ?, updated_by = ?
                WHERE alert_id = ?
                """,
                (_format_time(now), actor_id, row["alert_id"]),
            )
            self._append_event(
                connection,
                alert_id=row["alert_id"],
                event_type="auto_resolved",
                actor_id=actor_id,
                from_status=row["status"],
                to_status="resolved",
                note=note,
                payload={"rule_code": rule_code},
                occurred_at=now,
            )
            if operational:
                self._enqueue_notification(
                    connection,
                    alert_id=row["alert_id"],
                    alert_version=int(row["version"]) + 1,
                    event_type="auto_resolved",
                    level=row["level"],
                    payload={
                        "mine_id": row["mine_id"],
                        "category": row["category"],
                        "rule_code": row["rule_code"],
                        "level": row["level"],
                        "status": "resolved",
                        "title": row["title"],
                        "summary": note,
                        "location_code": row["location_code"],
                        "detected_at": row["detected_at"],
                        "approval_status": _approval_status(
                            row["rule_profile_json"]
                        ),
                        "operational": True,
                        "advisory_only": True,
                    },
                    occurred_at=now,
                )
            current = connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (row["alert_id"],),
            ).fetchone()
            assert current is not None
            return self._alert_from_row(current)

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        alert_id: str,
        event_type: str,
        actor_id: str,
        from_status: str | None,
        to_status: str | None,
        note: str | None,
        payload: dict[str, Any],
        occurred_at: datetime,
    ) -> None:
        previous = connection.execute(
            """
            SELECT event_hash FROM safety_alert_events
            WHERE alert_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (alert_id,),
        ).fetchone()
        previous_hash = None if previous is None else previous["event_hash"]
        event_id = f"alert-event-{uuid4()}"
        event_document = {
            "event_id": event_id,
            "alert_id": alert_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "occurred_at": _format_time(occurred_at),
            "from_status": from_status,
            "to_status": to_status,
            "note": note,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(
            _json(event_document).encode("utf-8")
        ).hexdigest()
        connection.execute(
            """
            INSERT INTO safety_alert_events(
                event_id, alert_id, event_type, actor_id, occurred_at,
                from_status, to_status, note, payload_json,
                previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                alert_id,
                event_type,
                actor_id,
                _format_time(occurred_at),
                from_status,
                to_status,
                note,
                _json(payload),
                previous_hash,
                event_hash,
            ),
        )

    @staticmethod
    def _enqueue_notification(
        connection: sqlite3.Connection,
        *,
        alert_id: str,
        alert_version: int,
        event_type: str,
        level: str,
        payload: dict[str, Any],
        occurred_at: datetime,
    ) -> None:
        notification_id = f"safety-notification-{uuid4()}"
        envelope = {
            "schema_version": "mineguard-safety-notification-v1",
            "notification_id": notification_id,
            "event_type": event_type,
            "occurred_at": _format_time(occurred_at),
            "alert_id": alert_id,
            "alert_version": alert_version,
            "technical_warning": payload,
            "regulatory_outcome": "not_determined",
        }
        connection.execute(
            """
            INSERT OR IGNORE INTO safety_notification_outbox(
                notification_id, alert_id, alert_version, event_type,
                level, payload_json, status, attempts,
                next_attempt_at, last_error, created_at, delivered_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, NULL, ?, NULL)
            """,
            (
                notification_id,
                alert_id,
                alert_version,
                event_type,
                level,
                _json(envelope),
                _format_time(occurred_at),
                _format_time(occurred_at),
            ),
        )

    @staticmethod
    def _alert_from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = _row_dict(row)
        item.pop("fingerprint", None)
        item["operational"] = bool(item["operational"])
        item["mode"] = (
            "operational" if item["operational"] else "shadow"
        )
        item["observation_ids"] = json.loads(
            item.pop("observation_ids_json")
        )
        item["details"] = json.loads(item.pop("details_json"))
        item["rule_profile"] = json.loads(
            item.pop("rule_profile_json")
        )
        due = item.get("due_at")
        item["overdue"] = bool(
            due
            and item["operational"]
            and item["status"] in _OPEN_STATUSES
            and _parse_time(due) < _utc_now()
        )
        return item

    def list_alerts(
        self,
        *,
        mine_ids: set[str] | None = None,
        status: str | None = None,
        level: str | None = None,
        operational: bool | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            arguments.extend(sorted(mine_ids))
        if status:
            clauses.append("status = ?")
            arguments.append(status)
        if level:
            clauses.append("level = ?")
            arguments.append(level)
        if operational is not None:
            clauses.append("operational = ?")
            arguments.append(int(operational))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        arguments.append(max(1, min(limit, 1000)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM safety_alerts
                {where}
                ORDER BY
                    CASE level
                        WHEN 'red' THEN 4
                        WHEN 'orange' THEN 3
                        WHEN 'yellow' THEN 2
                        ELSE 1
                    END DESC,
                    last_seen_at DESC
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
            alert_ids = [str(row["alert_id"]) for row in rows]
            recipient_rows: list[sqlite3.Row] = []
            for offset in range(0, len(alert_ids), 500):
                selected_ids = alert_ids[offset : offset + 500]
                placeholders = ",".join("?" for _ in selected_ids)
                recipient_rows.extend(
                    self._connection.execute(
                        f"""
                        SELECT *
                        FROM safety_alert_recipients
                        WHERE alert_id IN ({placeholders})
                        ORDER BY assigned_at, recipient_role, username
                        """,
                        tuple(selected_ids),
                    ).fetchall()
                )
        recipients_by_alert: dict[str, list[dict[str, Any]]] = {
            alert_id: [] for alert_id in alert_ids
        }
        for recipient in recipient_rows:
            recipients_by_alert[str(recipient["alert_id"])].append(
                _row_dict(recipient)
            )
        items = [self._alert_from_row(row) for row in rows]
        for item in items:
            item["recipients"] = recipients_by_alert[item["alert_id"]]
        return items

    def list_alert_recipients(
        self,
        alert_id: str,
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT *
                FROM safety_alert_recipients
                WHERE alert_id = ?
                ORDER BY assigned_at, recipient_role, username
                """,
                (alert_id,),
            ).fetchall()
        return [_row_dict(row) for row in rows]

    def mark_alert_read(
        self,
        alert_id: str,
        *,
        user_id: str,
        username: str,
    ) -> dict[str, Any]:
        now = _utc_now()
        now_text = _format_time(now)
        with self._transaction() as connection:
            alert = connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            if alert is None:
                raise AlertNotFoundError("alert not found")
            if not bool(alert["operational"]):
                raise InvalidAlertActionError(
                    "shadow alerts do not require formal read receipts"
                )
            existing = connection.execute(
                """
                SELECT 1
                FROM safety_alert_recipients
                WHERE alert_id = ? AND user_id = ? AND read_at IS NOT NULL
                LIMIT 1
                """,
                (alert_id, user_id),
            ).fetchone()
            if existing is not None:
                current = connection.execute(
                    "SELECT * FROM safety_alerts WHERE alert_id = ?",
                    (alert_id,),
                ).fetchone()
                assert current is not None
                return self._alert_from_row(current)
            matched = connection.execute(
                """
                UPDATE safety_alert_recipients
                SET read_at = ?
                WHERE alert_id = ? AND user_id = ? AND read_at IS NULL
                """,
                (now_text, alert_id, user_id),
            )
            if matched.rowcount == 0:
                connection.execute(
                    """
                    INSERT INTO safety_alert_recipients(
                        recipient_id, alert_id, user_id, username,
                        recipient_role, route_id, assigned_at, read_at,
                        escalated_at
                    ) VALUES (?, ?, ?, ?, 'observer', NULL, ?, ?, NULL)
                    """,
                    (
                        f"recipient-{uuid4()}",
                        alert_id,
                        user_id,
                        username,
                        now_text,
                        now_text,
                    ),
                )
            connection.execute(
                """
                UPDATE safety_alerts
                SET version = version + 1, updated_at = ?, updated_by = ?
                WHERE alert_id = ?
                """,
                (now_text, user_id, alert_id),
            )
            self._append_event(
                connection,
                alert_id=alert_id,
                event_type="read_receipt",
                actor_id=user_id,
                from_status=alert["status"],
                to_status=alert["status"],
                note=None,
                payload={"username": username},
                occurred_at=now,
            )
            current = connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            assert current is not None
            return self._alert_from_row(current)

    def escalate_responsibilities(
        self,
        *,
        now: datetime | None = None,
        actor_id: str = "platform:responsibility-escalator",
    ) -> int:
        current_time = (now or _utc_now()).astimezone(UTC)
        current_text = _format_time(current_time)
        escalated = 0
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT
                    a.*, recipient.assigned_at,
                    recipient.recipient_role,
                    recipient.user_id AS responsible_user_id,
                    recipient.username AS responsible_username,
                    route.route_id, route.escalation_minutes,
                    route.backup_user_id, route.backup_username
                FROM safety_alerts a
                JOIN safety_alert_recipients recipient
                  ON recipient.alert_id = a.alert_id
                 AND recipient.recipient_role IN ('primary', 'observer')
                 AND recipient.route_id IS NOT NULL
                JOIN safety_responsibility_routes route
                  ON route.route_id = recipient.route_id
                WHERE a.operational = 1
                  AND a.status IN ('open', 'acknowledged', 'in_progress')
                  AND recipient.read_at IS NULL
                  AND route.enabled = 1
                  AND route.backup_user_id IS NOT NULL
                """
            ).fetchall()
            for row in rows:
                due = _parse_time(row["assigned_at"]) + timedelta(
                    minutes=int(row["escalation_minutes"])
                )
                if due > current_time:
                    continue
                exists = connection.execute(
                    """
                    SELECT 1
                    FROM safety_alert_recipients
                    WHERE alert_id = ? AND route_id = ?
                      AND recipient_role = 'backup'
                    """,
                    (row["alert_id"], row["route_id"]),
                ).fetchone()
                if exists is not None:
                    continue
                connection.execute(
                    """
                    INSERT INTO safety_alert_recipients(
                        recipient_id, alert_id, user_id, username,
                        recipient_role, route_id, assigned_at, read_at,
                        escalated_at
                    ) VALUES (?, ?, ?, ?, 'backup', ?, ?, NULL, ?)
                    """,
                    (
                        f"recipient-{uuid4()}",
                        row["alert_id"],
                        row["backup_user_id"],
                        row["backup_username"],
                        row["route_id"],
                        current_text,
                        current_text,
                    ),
                )
                connection.execute(
                    """
                    UPDATE safety_alert_recipients
                    SET escalated_at = ?
                    WHERE alert_id = ? AND route_id = ?
                      AND recipient_role = ?
                    """,
                    (
                        current_text,
                        row["alert_id"],
                        row["route_id"],
                        row["recipient_role"],
                    ),
                )
                version_row = connection.execute(
                    "SELECT version FROM safety_alerts WHERE alert_id = ?",
                    (row["alert_id"],),
                ).fetchone()
                assert version_row is not None
                next_version = int(version_row["version"]) + 1
                connection.execute(
                    """
                    UPDATE safety_alerts
                    SET version = version + 1,
                        updated_at = ?, updated_by = ?
                    WHERE alert_id = ?
                    """,
                    (current_text, actor_id, row["alert_id"]),
                )
                self._append_event(
                    connection,
                    alert_id=row["alert_id"],
                    event_type="responsibility_escalated",
                    actor_id=actor_id,
                    from_status=row["status"],
                    to_status=row["status"],
                    note=None,
                    payload={
                        "route_id": row["route_id"],
                        "recipient_role": row["recipient_role"],
                        "responsible_user_id": row["responsible_user_id"],
                        "responsible_username": row["responsible_username"],
                        "backup_user_id": row["backup_user_id"],
                        "backup_username": row["backup_username"],
                        "reason": "route_read_receipt_overdue",
                    },
                    occurred_at=current_time,
                )
                self._enqueue_notification(
                    connection,
                    alert_id=row["alert_id"],
                    alert_version=next_version,
                    event_type="responsibility_escalated",
                    level=row["level"],
                    payload={
                        "mine_id": row["mine_id"],
                        "category": row["category"],
                        "rule_code": row["rule_code"],
                        "level": row["level"],
                        "status": row["status"],
                        "title": row["title"],
                        "summary": (
                            "责任路由接收人未在规定时间内回执，"
                            "已按该路由独立升级通知备岗人员。"
                        ),
                        "location_code": row["location_code"],
                        "detected_at": row["detected_at"],
                        "assignee": row["assignee"],
                        "route_id": row["route_id"],
                        "responsible_username": row[
                            "responsible_username"
                        ],
                        "recipient_role": row["recipient_role"],
                        "backup_assignee": row["backup_username"],
                        "approval_status": _approval_status(
                            row["rule_profile_json"]
                        ),
                        "operational": True,
                        "advisory_only": True,
                    },
                    occurred_at=current_time,
                )
                escalated += 1
        return escalated

    def escalate_overdue_alerts(
        self,
        *,
        now: datetime | None = None,
        actor_id: str = "platform:sla-escalator",
    ) -> int:
        """Emit one durable escalation when a formal alert exceeds due_at."""
        current_time = (now or _utc_now()).astimezone(UTC)
        current_text = _format_time(current_time)
        escalated = 0
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM safety_alerts
                WHERE operational = 1
                  AND status IN ('open', 'acknowledged', 'in_progress')
                  AND due_at IS NOT NULL
                ORDER BY due_at, alert_id
                """
            ).fetchall()
            for row in rows:
                if _parse_time(row["due_at"]) > current_time:
                    continue
                recorded_events = connection.execute(
                    """
                    SELECT payload_json
                    FROM safety_alert_events
                    WHERE alert_id = ?
                      AND event_type = 'sla_overdue_escalated'
                    """,
                    (row["alert_id"],),
                ).fetchall()
                already_recorded = False
                for event in recorded_events:
                    try:
                        payload = json.loads(event["payload_json"])
                    except (
                        TypeError,
                        ValueError,
                        json.JSONDecodeError,
                    ):
                        continue
                    if (
                        isinstance(payload, dict)
                        and payload.get("due_at") == row["due_at"]
                    ):
                        already_recorded = True
                        break
                if already_recorded:
                    continue

                primary = connection.execute(
                    """
                    SELECT recipient.route_id
                    FROM safety_alert_recipients recipient
                    WHERE recipient.alert_id = ?
                      AND recipient.recipient_role = 'primary'
                    ORDER BY recipient.assigned_at, recipient.user_id
                    LIMIT 1
                    """,
                    (row["alert_id"],),
                ).fetchone()
                backup_username: str | None = None
                backup_added = False
                if primary is not None and primary["route_id"] is not None:
                    route = connection.execute(
                        """
                        SELECT route_id, backup_user_id, backup_username
                        FROM safety_responsibility_routes
                        WHERE route_id = ?
                        """,
                        (primary["route_id"],),
                    ).fetchone()
                    if (
                        route is not None
                        and route["backup_user_id"] is not None
                        and route["backup_username"] is not None
                    ):
                        inserted = connection.execute(
                            """
                            INSERT OR IGNORE INTO safety_alert_recipients(
                                recipient_id, alert_id, user_id, username,
                                recipient_role, route_id, assigned_at,
                                read_at, escalated_at
                            ) VALUES (?, ?, ?, ?, 'backup', ?, ?, NULL, ?)
                            """,
                            (
                                f"recipient-{uuid4()}",
                                row["alert_id"],
                                route["backup_user_id"],
                                route["backup_username"],
                                route["route_id"],
                                current_text,
                                current_text,
                            ),
                        )
                        backup_added = inserted.rowcount == 1
                        backup_username = str(route["backup_username"])

                connection.execute(
                    """
                    UPDATE safety_alerts
                    SET version = version + 1,
                        updated_at = ?, updated_by = ?
                    WHERE alert_id = ?
                    """,
                    (current_text, actor_id, row["alert_id"]),
                )
                next_version = int(row["version"]) + 1
                event_payload = {
                    "due_at": row["due_at"],
                    "escalated_at": current_text,
                    "assignee": row["assignee"],
                    "backup_assignee": backup_username,
                    "backup_recipient_added": backup_added,
                    "reason": "formal_alert_due_at_exceeded",
                }
                self._append_event(
                    connection,
                    alert_id=row["alert_id"],
                    event_type="sla_overdue_escalated",
                    actor_id=actor_id,
                    from_status=row["status"],
                    to_status=row["status"],
                    note=None,
                    payload=event_payload,
                    occurred_at=current_time,
                )
                self._enqueue_notification(
                    connection,
                    alert_id=row["alert_id"],
                    alert_version=next_version,
                    event_type="sla_overdue_escalated",
                    level=row["level"],
                    payload={
                        "mine_id": row["mine_id"],
                        "category": row["category"],
                        "rule_code": row["rule_code"],
                        "level": row["level"],
                        "status": row["status"],
                        "title": row["title"],
                        "summary": (
                            "正式预警已超过办理时限，系统已触发一次性"
                            "超时升级通知；监管结论仍需人工复核。"
                        ),
                        "location_code": row["location_code"],
                        "detected_at": row["detected_at"],
                        "due_at": row["due_at"],
                        "assignee": row["assignee"],
                        "backup_assignee": backup_username,
                        "approval_status": _approval_status(
                            row["rule_profile_json"]
                        ),
                        "operational": True,
                        "advisory_only": True,
                    },
                    occurred_at=current_time,
                )
                escalated += 1
        return escalated

    def responsibility_health(
        self,
        mine_ids: set[str] | None = None,
    ) -> dict[str, int]:
        clauses = [
            "a.operational = 1",
            "a.status IN ('open', 'acknowledged', 'in_progress')",
        ]
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return {
                    "unrouted": 0,
                    "unread_primary": 0,
                    "unread_observer": 0,
                    "escalated": 0,
                    "sla_overdue_escalated": 0,
                }
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"a.mine_id IN ({placeholders})")
            arguments.extend(sorted(mine_ids))
        where = " AND ".join(clauses)
        with self._lock:
            unrouted = self._connection.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM safety_alerts a
                WHERE {where}
                  AND NOT EXISTS (
                      SELECT 1 FROM safety_alert_recipients r
                      WHERE r.alert_id = a.alert_id
                        AND r.recipient_role = 'primary'
                        AND r.route_id IS NOT NULL
                  )
                """,
                tuple(arguments),
            ).fetchone()
            unread = self._connection.execute(
                f"""
                SELECT COUNT(DISTINCT a.alert_id) AS total
                FROM safety_alerts a
                JOIN safety_alert_recipients r
                  ON r.alert_id = a.alert_id
                 AND r.recipient_role = 'primary'
                 AND r.route_id IS NOT NULL
                WHERE {where} AND r.read_at IS NULL
                """,
                tuple(arguments),
            ).fetchone()
            unread_observer = self._connection.execute(
                f"""
                SELECT COUNT(*) AS total
                FROM safety_alerts a
                JOIN safety_alert_recipients r
                  ON r.alert_id = a.alert_id
                 AND r.recipient_role = 'observer'
                 AND r.route_id IS NOT NULL
                WHERE {where} AND r.read_at IS NULL
                """,
                tuple(arguments),
            ).fetchone()
            escalated = self._connection.execute(
                f"""
                SELECT COUNT(DISTINCT a.alert_id) AS total
                FROM safety_alerts a
                JOIN safety_alert_recipients r
                  ON r.alert_id = a.alert_id
                 AND r.recipient_role = 'backup'
                 AND r.route_id IS NOT NULL
                WHERE {where}
                """,
                tuple(arguments),
            ).fetchone()
            sla_overdue = self._connection.execute(
                f"""
                SELECT COUNT(DISTINCT a.alert_id) AS total
                FROM safety_alerts a
                JOIN safety_alert_events event
                  ON event.alert_id = a.alert_id
                 AND event.event_type = 'sla_overdue_escalated'
                WHERE {where}
                """,
                tuple(arguments),
            ).fetchone()
        return {
            "unrouted": int(unrouted["total"]),
            "unread_primary": int(unread["total"]),
            "unread_observer": int(unread_observer["total"]),
            "escalated": int(escalated["total"]),
            "sla_overdue_escalated": int(sla_overdue["total"]),
        }

    @staticmethod
    def _refresh_notification_aggregate(
        connection: sqlite3.Connection,
        notification_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        """Project target delivery state onto the legacy event-level outbox."""
        deliveries = connection.execute(
            """
            SELECT status, attempts, next_attempt_at, last_error,
                   delivered_at, last_attempt_at, webhook_id
            FROM safety_notification_deliveries
            WHERE notification_id = ?
            ORDER BY
                COALESCE(last_attempt_at, next_attempt_at) DESC,
                webhook_id
            """,
            (notification_id,),
        ).fetchall()
        if not deliveries:
            return
        statuses = {str(row["status"]) for row in deliveries}
        if statuses == {"delivered"}:
            aggregate_status = "delivered"
        elif "sending" in statuses:
            aggregate_status = "sending"
        elif "retry" in statuses:
            aggregate_status = "retry"
        elif "pending" in statuses:
            aggregate_status = "pending"
        elif "dead" in statuses:
            aggregate_status = "dead"
        else:  # Defensive fail-closed branch for a corrupt status.
            aggregate_status = "dead"
        active_times = [
            str(row["next_attempt_at"])
            for row in deliveries
            if row["status"] in {"pending", "retry", "sending"}
        ]
        failed = next(
            (
                row
                for row in deliveries
                if row["status"] in {"retry", "dead"}
                and row["last_error"]
            ),
            None,
        )
        delivered_times = [
            str(row["delivered_at"])
            for row in deliveries
            if row["delivered_at"]
        ]
        current = _format_time(now or _utc_now())
        connection.execute(
            """
            UPDATE safety_notification_outbox
            SET status = ?, attempts = ?, next_attempt_at = ?,
                last_error = ?, delivered_at = ?
            WHERE notification_id = ?
            """,
            (
                aggregate_status,
                max(int(row["attempts"]) for row in deliveries),
                min(active_times) if active_times else current,
                str(failed["last_error"]) if failed is not None else None,
                (
                    max(delivered_times)
                    if aggregate_status == "delivered" and delivered_times
                    else None
                ),
                notification_id,
            ),
        )

    def materialize_notification_deliveries(
        self,
        targets: dict[str, str],
        *,
        now: datetime | None = None,
    ) -> int:
        """Create one durable delivery per eligible configured webhook.

        Previously delivered legacy rows are intentionally not expanded: the
        old schema cannot prove which target received them, so replaying them
        would risk duplicate downstream actions.
        """
        current = now or _utc_now()
        current_text = _format_time(current)
        automatically_completed = 0
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT notification_id, level, attempts
                FROM safety_notification_outbox
                WHERE status IN ('pending', 'retry')
                ORDER BY created_at, notification_id
                """
            ).fetchall()
            for row in rows:
                notification_id = str(row["notification_id"])
                existing_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) AS delivery_count
                        FROM safety_notification_deliveries
                        WHERE notification_id = ?
                        """,
                        (notification_id,),
                    ).fetchone()["delivery_count"]
                )
                inherited_attempts = (
                    int(row["attempts"]) if existing_count == 0 else 0
                )
                selected = [
                    webhook_id
                    for webhook_id, minimum_level in sorted(targets.items())
                    if (
                        minimum_level in _LEVEL_RANK
                        and _LEVEL_RANK[str(row["level"])]
                        >= _LEVEL_RANK[minimum_level]
                    )
                ]
                for webhook_id in selected:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO
                            safety_notification_deliveries(
                                notification_id, webhook_id, status,
                                attempts, attempt_cycle, manual_retry_count,
                                next_attempt_at, last_error, created_at,
                                last_attempt_at, delivered_at
                            )
                        VALUES (?, ?, 'pending', ?, ?, 0, ?, NULL, ?,
                                NULL, NULL)
                        """,
                        (
                            notification_id,
                            webhook_id,
                            inherited_attempts,
                            inherited_attempts,
                            current_text,
                            current_text,
                        ),
                    )
                count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) AS delivery_count
                        FROM safety_notification_deliveries
                        WHERE notification_id = ?
                        """,
                        (notification_id,),
                    ).fetchone()["delivery_count"]
                )
                if count:
                    self._refresh_notification_aggregate(
                        connection,
                        notification_id,
                        now=current,
                    )
                elif not selected:
                    connection.execute(
                        """
                        UPDATE safety_notification_outbox
                        SET status = 'delivered', delivered_at = ?,
                            last_error = NULL
                        WHERE notification_id = ?
                        """,
                        (current_text, notification_id),
                    )
                    automatically_completed += 1
        return automatically_completed

    def fail_unconfigured_notification_deliveries(
        self,
        configured_webhook_ids: set[str],
        *,
        now: datetime | None = None,
    ) -> int:
        """Make removed targets explicit instead of leaving hidden retries."""
        if not configured_webhook_ids:
            return 0
        placeholders = ",".join("?" for _ in configured_webhook_ids)
        with self._transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT notification_id, webhook_id
                FROM safety_notification_deliveries
                WHERE status IN ('pending', 'retry')
                  AND webhook_id NOT IN ({placeholders})
                """,
                tuple(sorted(configured_webhook_ids)),
            ).fetchall()
            if not rows:
                return 0
            current_text = _format_time(now or _utc_now())
            for row in rows:
                connection.execute(
                    """
                    UPDATE safety_notification_deliveries
                    SET status = 'dead',
                        next_attempt_at = ?,
                        last_error = 'webhook_not_configured'
                    WHERE notification_id = ? AND webhook_id = ?
                      AND status IN ('pending', 'retry')
                    """,
                    (
                        current_text,
                        row["notification_id"],
                        row["webhook_id"],
                    ),
                )
            for notification_id in {
                str(row["notification_id"]) for row in rows
            }:
                self._refresh_notification_aggregate(
                    connection,
                    notification_id,
                    now=now,
                )
            return len(rows)

    def claim_notification_deliveries(
        self,
        webhook_ids: set[str],
        *,
        limit: int = 20,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        if not webhook_ids:
            return []
        current = now or _utc_now()
        current_text = _format_time(current)
        placeholders = ",".join("?" for _ in webhook_ids)
        arguments: list[Any] = [
            *sorted(webhook_ids),
            current_text,
            max(1, min(limit, 100)),
        ]
        with self._transaction() as connection:
            rows = connection.execute(
                f"""
                SELECT
                    d.notification_id, d.webhook_id,
                    d.status AS delivery_status,
                    d.attempts AS delivery_attempts,
                    d.attempt_cycle, d.manual_retry_count,
                    d.next_attempt_at AS delivery_next_attempt_at,
                    d.last_error AS delivery_last_error,
                    d.created_at AS delivery_created_at,
                    d.last_attempt_at, d.delivered_at AS delivery_delivered_at,
                    n.alert_id, n.alert_version, n.event_type, n.level,
                    n.payload_json, n.created_at AS notification_created_at
                FROM safety_notification_deliveries d
                JOIN safety_notification_outbox n
                  ON n.notification_id = d.notification_id
                WHERE d.webhook_id IN ({placeholders})
                  AND d.status IN ('pending', 'retry')
                  AND d.next_attempt_at <= ?
                ORDER BY
                    d.next_attempt_at, n.created_at,
                    d.notification_id, d.webhook_id
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
            for row in rows:
                connection.execute(
                    """
                    UPDATE safety_notification_deliveries
                    SET status = 'sending',
                        attempts = attempts + 1,
                        attempt_cycle = attempt_cycle + 1,
                        last_attempt_at = ?
                    WHERE notification_id = ? AND webhook_id = ?
                      AND status IN ('pending', 'retry')
                    """,
                    (
                        current_text,
                        row["notification_id"],
                        row["webhook_id"],
                    ),
                )
            for notification_id in {
                str(row["notification_id"]) for row in rows
            }:
                self._refresh_notification_aggregate(
                    connection,
                    notification_id,
                    now=current,
                )
        return [
            {
                **_row_dict(row),
                "payload": json.loads(row["payload_json"]),
                "delivery_status": "sending",
                "delivery_attempts": int(row["delivery_attempts"]) + 1,
                "attempt_cycle": int(row["attempt_cycle"]) + 1,
            }
            for row in rows
        ]

    def mark_notification_delivery_delivered(
        self,
        notification_id: str,
        webhook_id: str,
    ) -> None:
        now = _utc_now()
        now_text = _format_time(now)
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE safety_notification_deliveries
                SET status = 'delivered', delivered_at = ?,
                    last_error = NULL, next_attempt_at = ?
                WHERE notification_id = ? AND webhook_id = ?
                  AND status = 'sending'
                """,
                (now_text, now_text, notification_id, webhook_id),
            )
            self._refresh_notification_aggregate(
                connection,
                notification_id,
                now=now,
            )

    def mark_notification_delivery_failed(
        self,
        notification_id: str,
        webhook_id: str,
        *,
        error_code: str,
        maximum_attempts: int = 12,
    ) -> None:
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT attempt_cycle
                FROM safety_notification_deliveries
                WHERE notification_id = ? AND webhook_id = ?
                  AND status = 'sending'
                """,
                (notification_id, webhook_id),
            ).fetchone()
            if row is None:
                return
            attempt_cycle = int(row["attempt_cycle"])
            status = (
                "dead"
                if attempt_cycle >= max(1, maximum_attempts)
                else "retry"
            )
            delay = min(
                3600,
                max(5, 5 * (2 ** max(0, attempt_cycle - 1))),
            )
            connection.execute(
                """
                UPDATE safety_notification_deliveries
                SET status = ?, next_attempt_at = ?, last_error = ?
                WHERE notification_id = ? AND webhook_id = ?
                  AND status = 'sending'
                """,
                (
                    status,
                    _format_time(now + timedelta(seconds=delay)),
                    error_code[:200],
                    notification_id,
                    webhook_id,
                ),
            )
            self._refresh_notification_aggregate(
                connection,
                notification_id,
                now=now,
            )

    def retry_notification_deliveries(
        self,
        notification_id: str,
        *,
        webhook_id: str | None = None,
        now: datetime | None = None,
    ) -> int:
        """Requeue dead targets while preserving successful target receipts."""
        current = now or _utc_now()
        current_text = _format_time(current)
        with self._transaction() as connection:
            parent = connection.execute(
                """
                SELECT notification_id, status
                FROM safety_notification_outbox
                WHERE notification_id = ?
                """,
                (notification_id,),
            ).fetchone()
            if parent is None:
                raise KeyError(notification_id)
            clauses = ["notification_id = ?", "status = 'dead'"]
            arguments: list[Any] = [notification_id]
            if webhook_id is not None:
                clauses.append("webhook_id = ?")
                arguments.append(webhook_id)
            cursor = connection.execute(
                f"""
                UPDATE safety_notification_deliveries
                SET status = 'retry', attempt_cycle = 0,
                    manual_retry_count = manual_retry_count + 1,
                    next_attempt_at = ?, last_error = NULL,
                    delivered_at = NULL
                WHERE {' AND '.join(clauses)}
                """,
                (current_text, *arguments),
            )
            changed = int(cursor.rowcount)
            if changed:
                self._refresh_notification_aggregate(
                    connection,
                    notification_id,
                    now=current,
                )
                return changed
            delivery_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) AS delivery_count
                    FROM safety_notification_deliveries
                    WHERE notification_id = ?
                    """,
                    (notification_id,),
                ).fetchone()["delivery_count"]
            )
            if (
                delivery_count == 0
                and webhook_id is None
                and parent["status"] == "dead"
            ):
                connection.execute(
                    """
                    UPDATE safety_notification_outbox
                    SET status = 'retry', attempts = 0,
                        next_attempt_at = ?, last_error = NULL,
                        delivered_at = NULL
                    WHERE notification_id = ?
                    """,
                    (current_text, notification_id),
                )
                return 1
            return 0

    def claim_notifications(
        self,
        *,
        limit: int = 20,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        current = now or _utc_now()
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM safety_notification_outbox
                WHERE status IN ('pending', 'retry')
                      AND next_attempt_at <= ?
                ORDER BY created_at, notification_id
                LIMIT ?
                """,
                (
                    _format_time(current),
                    max(1, min(limit, 100)),
                ),
            ).fetchall()
            if rows:
                placeholders = ",".join("?" for _ in rows)
                connection.execute(
                    f"""
                    UPDATE safety_notification_outbox
                    SET status = 'sending', attempts = attempts + 1
                    WHERE notification_id IN ({placeholders})
                    """,
                    tuple(row["notification_id"] for row in rows),
                )
        return [
            {
                **_row_dict(row),
                "payload": json.loads(row["payload_json"]),
                "attempts": int(row["attempts"]) + 1,
            }
            for row in rows
        ]

    def mark_notification_delivered(
        self,
        notification_id: str,
    ) -> None:
        now = _format_time(_utc_now())
        with self._transaction() as connection:
            connection.execute(
                """
                UPDATE safety_notification_outbox
                SET status = 'delivered', delivered_at = ?,
                    last_error = NULL
                WHERE notification_id = ? AND status = 'sending'
                """,
                (now, notification_id),
            )

    def mark_notification_failed(
        self,
        notification_id: str,
        *,
        error_code: str,
        maximum_attempts: int = 12,
    ) -> None:
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT attempts FROM safety_notification_outbox
                WHERE notification_id = ?
                """,
                (notification_id,),
            ).fetchone()
            if row is None:
                return
            attempts = int(row["attempts"])
            status = "dead" if attempts >= maximum_attempts else "retry"
            delay = min(3600, max(5, 5 * (2 ** max(0, attempts - 1))))
            connection.execute(
                """
                UPDATE safety_notification_outbox
                SET status = ?, next_attempt_at = ?, last_error = ?
                WHERE notification_id = ?
                """,
                (
                    status,
                    _format_time(_utc_now() + timedelta(seconds=delay)),
                    error_code[:200],
                    notification_id,
                ),
            )

    def list_notifications(
        self,
        *,
        mine_ids: set[str] | None = None,
        status: str | None = None,
        webhook_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"a.mine_id IN ({placeholders})")
            arguments.extend(sorted(mine_ids))
        if status:
            clauses.append("n.status = ?")
            arguments.append(status)
        if webhook_id:
            clauses.append(
                """
                EXISTS (
                    SELECT 1
                    FROM safety_notification_deliveries selected_delivery
                    WHERE selected_delivery.notification_id =
                          n.notification_id
                      AND selected_delivery.webhook_id = ?
                )
                """
            )
            arguments.append(webhook_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        arguments.append(max(1, min(limit, 1000)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT n.*, a.mine_id, a.title
                FROM safety_notification_outbox n
                JOIN safety_alerts a ON a.alert_id = n.alert_id
                {where}
                ORDER BY n.created_at DESC
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
            notification_ids = [
                str(row["notification_id"]) for row in rows
            ]
            deliveries: list[sqlite3.Row] = []
            if notification_ids:
                delivery_placeholders = ",".join(
                    "?" for _ in notification_ids
                )
                delivery_arguments: list[Any] = [*notification_ids]
                delivery_filter = ""
                if webhook_id:
                    delivery_filter = "AND webhook_id = ?"
                    delivery_arguments.append(webhook_id)
                deliveries = self._connection.execute(
                    f"""
                    SELECT *
                    FROM safety_notification_deliveries
                    WHERE notification_id IN ({delivery_placeholders})
                    {delivery_filter}
                    ORDER BY notification_id, webhook_id
                    """,
                    tuple(delivery_arguments),
                ).fetchall()
        by_notification: dict[str, list[dict[str, Any]]] = {
            notification_id: [] for notification_id in notification_ids
        }
        for delivery in deliveries:
            item = _row_dict(delivery)
            for integer_field in (
                "attempts",
                "attempt_cycle",
                "manual_retry_count",
            ):
                item[integer_field] = int(item[integer_field])
            by_notification[str(delivery["notification_id"])].append(item)
        result: list[dict[str, Any]] = []
        for row in rows:
            notification_id = str(row["notification_id"])
            target_deliveries = by_notification[notification_id]
            status_counts: dict[str, int] = {}
            for delivery in target_deliveries:
                delivery_status = str(delivery["status"])
                status_counts[delivery_status] = (
                    status_counts.get(delivery_status, 0) + 1
                )
            result.append(
                {
                    **{
                        key: row[key]
                        for key in row.keys()
                        if key != "payload_json"
                    },
                    "payload": json.loads(row["payload_json"]),
                    "deliveries": target_deliveries,
                    "delivery_summary": {
                        "target_count": len(target_deliveries),
                        "status_counts": status_counts,
                        "all_delivered": bool(target_deliveries)
                        and status_counts.get("delivered", 0)
                        == len(target_deliveries),
                    },
                }
            )
        return result

    def get_notification(
        self,
        notification_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT n.*, a.mine_id, a.title
                FROM safety_notification_outbox n
                JOIN safety_alerts a ON a.alert_id = n.alert_id
                WHERE n.notification_id = ?
                """,
                (notification_id,),
            ).fetchone()
            if row is None:
                return None
            deliveries = self._connection.execute(
                """
                SELECT *
                FROM safety_notification_deliveries
                WHERE notification_id = ?
                ORDER BY webhook_id
                """,
                (notification_id,),
            ).fetchall()
        target_deliveries = [_row_dict(item) for item in deliveries]
        status_counts: dict[str, int] = {}
        for delivery in target_deliveries:
            for integer_field in (
                "attempts",
                "attempt_cycle",
                "manual_retry_count",
            ):
                delivery[integer_field] = int(delivery[integer_field])
            delivery_status = str(delivery["status"])
            status_counts[delivery_status] = (
                status_counts.get(delivery_status, 0) + 1
            )
        return {
            **{
                key: row[key]
                for key in row.keys()
                if key != "payload_json"
            },
            "payload": json.loads(row["payload_json"]),
            "deliveries": target_deliveries,
            "delivery_summary": {
                "target_count": len(target_deliveries),
                "status_counts": status_counts,
                "all_delivered": bool(target_deliveries)
                and status_counts.get("delivered", 0)
                == len(target_deliveries),
            },
        }

    def notification_delivery_health(self) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT status, COUNT(*) AS item_count
                FROM safety_notification_deliveries
                GROUP BY status
                """
            ).fetchall()
        counts = {
            "pending": 0,
            "sending": 0,
            "retry": 0,
            "delivered": 0,
            "dead": 0,
        }
        for row in rows:
            status = str(row["status"])
            if status in counts:
                counts[status] = int(row["item_count"])
        counts["unfinished"] = sum(
            counts[status]
            for status in ("pending", "sending", "retry", "dead")
        )
        counts["total"] = sum(
            counts[status]
            for status in (
                "pending",
                "sending",
                "retry",
                "delivered",
                "dead",
            )
        )
        return counts

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            events = self._connection.execute(
                """
                SELECT rowid AS event_sequence, *
                FROM safety_alert_events
                WHERE alert_id = ?
                ORDER BY rowid
                """,
                (alert_id,),
            ).fetchall()
            recipients = self._connection.execute(
                """
                SELECT *
                FROM safety_alert_recipients
                WHERE alert_id = ?
                ORDER BY assigned_at, recipient_role, username
                """,
                (alert_id,),
            ).fetchall()
            attachments = self._connection.execute(
                """
                SELECT
                    attachment_id, alert_id, mine_id, filename,
                    media_type, size_bytes, sha256, note,
                    created_at, created_by
                FROM safety_alert_attachments
                WHERE alert_id = ?
                ORDER BY created_at, attachment_id
                """,
                (alert_id,),
            ).fetchall()
        if row is None:
            return None
        result = self._alert_from_row(row)
        result["events"] = [
            {
                **{
                    key: event[key]
                    for key in event.keys()
                    if key != "payload_json"
                },
                "payload": json.loads(event["payload_json"]),
            }
            for event in events
        ]
        result["audit_chain_valid"] = self._verify_event_chain(events)
        result["recipients"] = [_row_dict(item) for item in recipients]
        result["attachments"] = [_row_dict(item) for item in attachments]
        result["attachment_count"] = len(attachments)
        return result

    def add_alert_attachment(
        self,
        alert_id: str,
        *,
        filename: str,
        media_type: str,
        content: bytes,
        content_sha256: str,
        actor_id: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        if (
            not content
            or len(content) > MAX_SAFETY_ATTACHMENT_BYTES
            or hashlib.sha256(content).hexdigest() != content_sha256
            or media_type not in ALLOWED_SAFETY_ATTACHMENT_TYPES
            or not filename
            or len(filename) > 160
            or "/" in filename
            or "\\" in filename
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in filename
            )
        ):
            raise ValueError("invalid attachment content")
        attachment_id = f"safety-attachment-{uuid4()}"
        now = _utc_now()
        normalized_note = note.strip() if note and note.strip() else None
        with self._transaction() as connection:
            alert = connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            if alert is None:
                raise AlertNotFoundError("alert not found")
            try:
                connection.execute(
                    """
                    INSERT INTO safety_alert_attachments(
                        attachment_id, alert_id, mine_id, filename,
                        media_type, size_bytes, sha256, content, note,
                        created_at, created_by
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attachment_id,
                        alert_id,
                        alert["mine_id"],
                        filename,
                        media_type,
                        len(content),
                        content_sha256,
                        sqlite3.Binary(content),
                        normalized_note,
                        _format_time(now),
                        actor_id,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise SafetyAttachmentConflictError(
                    "the same attachment content already exists"
                ) from error
            connection.execute(
                """
                UPDATE safety_alerts
                SET version = version + 1,
                    updated_at = ?, updated_by = ?
                WHERE alert_id = ?
                """,
                (_format_time(now), actor_id, alert_id),
            )
            self._append_event(
                connection,
                alert_id=alert_id,
                event_type="attachment_added",
                actor_id=actor_id,
                from_status=alert["status"],
                to_status=alert["status"],
                note=normalized_note,
                payload={
                    "attachment_id": attachment_id,
                    "filename": filename,
                    "media_type": media_type,
                    "size_bytes": len(content),
                    "sha256": content_sha256,
                },
                occurred_at=now,
            )
            row = connection.execute(
                """
                SELECT
                    attachment_id, alert_id, mine_id, filename,
                    media_type, size_bytes, sha256, note,
                    created_at, created_by
                FROM safety_alert_attachments
                WHERE attachment_id = ?
                """,
                (attachment_id,),
            ).fetchone()
            version = int(alert["version"]) + 1
        assert row is not None
        return {**_row_dict(row), "alert_version": version}

    def list_alert_attachments(
        self,
        alert_id: str,
    ) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                    attachment_id, alert_id, mine_id, filename,
                    media_type, size_bytes, sha256, note,
                    created_at, created_by
                FROM safety_alert_attachments
                WHERE alert_id = ?
                ORDER BY created_at, attachment_id
                """,
                (alert_id,),
            ).fetchall()
        return [_row_dict(row) for row in rows]

    def get_alert_attachment(
        self,
        alert_id: str,
        attachment_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT *
                FROM safety_alert_attachments
                WHERE alert_id = ? AND attachment_id = ?
                """,
                (alert_id, attachment_id),
            ).fetchone()
        if row is None:
            return None
        item = _row_dict(row)
        item["content"] = bytes(item["content"])
        return item

    @staticmethod
    def _verify_event_chain(events: list[sqlite3.Row]) -> bool:
        previous_hash: str | None = None
        for row in events:
            document = {
                "event_id": row["event_id"],
                "alert_id": row["alert_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "occurred_at": row["occurred_at"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "note": row["note"],
                "payload": json.loads(row["payload_json"]),
                "previous_hash": row["previous_hash"],
            }
            expected = hashlib.sha256(
                _json(document).encode("utf-8")
            ).hexdigest()
            if (
                row["previous_hash"] != previous_hash
                or row["event_hash"] != expected
            ):
                return False
            previous_hash = row["event_hash"]
        return True

    def apply_alert_action(
        self,
        alert_id: str,
        *,
        action: str,
        expected_version: int,
        actor_id: str,
        actor_username: str | None = None,
        note: str | None = None,
        assignee: str | None = None,
    ) -> dict[str, Any]:
        transitions: dict[str, tuple[set[str], str]] = {
            "acknowledge": ({"open"}, "acknowledged"),
            "start": ({"open", "acknowledged"}, "in_progress"),
            "resolve": (
                {"open", "acknowledged", "in_progress"},
                "resolved",
            ),
            "close": ({"resolved"}, "closed"),
            "reopen": ({"resolved", "closed"}, "open"),
        }
        if action not in {
            *transitions,
            "assign",
            "add_note",
        }:
            raise InvalidAlertActionError("unsupported alert action")
        if action in {"resolve", "close", "reopen", "add_note"} and not (
            note and note.strip()
        ):
            raise InvalidAlertActionError(
                "this alert action requires a note"
            )
        if action == "assign" and not (assignee and assignee.strip()):
            raise InvalidAlertActionError("assign requires assignee")
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            if row is None:
                raise AlertNotFoundError("alert not found")
            if not bool(row["operational"]) and action != "add_note":
                raise InvalidAlertActionError(
                    "shadow alerts do not enter the formal workflow"
                )
            if row["version"] != expected_version:
                raise AlertVersionConflictError(
                    "alert version has changed"
                )
            if action == "close":
                resolver = connection.execute(
                    """
                    SELECT actor_id
                    FROM safety_alert_events
                    WHERE alert_id = ? AND event_type IN (
                        'resolve', 'auto_resolved'
                    )
                    ORDER BY occurred_at DESC, event_id DESC
                    LIMIT 1
                    """,
                    (alert_id,),
                ).fetchone()
                if (
                    resolver is not None
                    and resolver["actor_id"] == actor_id
                ):
                    raise InvalidAlertActionError(
                        "the same reviewer cannot both resolve and close "
                        "an alert"
                    )
            old_status = row["status"]
            new_status = old_status
            new_assignee = row["assignee"]
            if action in transitions:
                allowed, new_status = transitions[action]
                if old_status not in allowed:
                    raise InvalidAlertActionError(
                        f"cannot {action} alert from {old_status}"
                    )
            elif action == "assign":
                new_assignee = assignee.strip() if assignee else None
            next_due_at = row["due_at"]
            if action == "reopen":
                response_hours = {
                    "red": 1,
                    "orange": 4,
                    "yellow": 12,
                    "blue": 24,
                }
                next_due_at = _format_time(
                    now + timedelta(hours=response_hours[row["level"]])
                )
            connection.execute(
                """
                UPDATE safety_alerts
                SET status = ?, assignee = ?, version = version + 1,
                    due_at = ?, updated_at = ?, updated_by = ?
                WHERE alert_id = ?
                """,
                (
                    new_status,
                    new_assignee,
                    next_due_at,
                    _format_time(now),
                    actor_id,
                    alert_id,
                ),
            )
            if action == "reopen":
                connection.execute(
                    """
                    UPDATE safety_alert_recipients
                    SET assigned_at = ?, read_at = NULL,
                        escalated_at = NULL
                    WHERE alert_id = ?
                      AND recipient_role IN ('primary', 'observer')
                      AND route_id IS NOT NULL
                    """,
                    (_format_time(now), alert_id),
                )
                connection.execute(
                    """
                    DELETE FROM safety_alert_recipients
                    WHERE alert_id = ? AND recipient_role = 'backup'
                    """,
                    (alert_id,),
                )
            if action == "acknowledge":
                read_at = _format_time(now)
                matched = connection.execute(
                    """
                    UPDATE safety_alert_recipients
                    SET read_at = COALESCE(read_at, ?)
                    WHERE alert_id = ? AND user_id = ?
                    """,
                    (read_at, alert_id, actor_id),
                )
                if matched.rowcount == 0:
                    connection.execute(
                        """
                        INSERT INTO safety_alert_recipients(
                            recipient_id, alert_id, user_id, username,
                            recipient_role, route_id, assigned_at, read_at,
                            escalated_at
                        ) VALUES (
                            ?, ?, ?, ?, 'observer', NULL, ?, ?, NULL
                        )
                        """,
                        (
                            f"recipient-{uuid4()}",
                            alert_id,
                            actor_id,
                            actor_username or actor_id,
                            read_at,
                            read_at,
                        ),
                    )
            self._append_event(
                connection,
                alert_id=alert_id,
                event_type=action,
                actor_id=actor_id,
                from_status=old_status,
                to_status=new_status,
                note=note.strip() if note else None,
                payload=(
                    {"assignee": new_assignee}
                    if action == "assign"
                    else {}
                ),
                occurred_at=now,
            )
            if bool(row["operational"]):
                self._enqueue_notification(
                    connection,
                    alert_id=alert_id,
                    alert_version=int(row["version"]) + 1,
                    event_type=action,
                    level=row["level"],
                    payload={
                        "mine_id": row["mine_id"],
                        "category": row["category"],
                        "rule_code": row["rule_code"],
                        "level": row["level"],
                        "status": new_status,
                        "title": row["title"],
                        "summary": note or row["summary"],
                        "location_code": row["location_code"],
                        "detected_at": row["detected_at"],
                        "assignee": new_assignee,
                        "approval_status": _approval_status(
                            row["rule_profile_json"]
                        ),
                        "operational": True,
                        "advisory_only": True,
                    },
                    occurred_at=now,
                )
            current = connection.execute(
                "SELECT * FROM safety_alerts WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
            assert current is not None
            return self._alert_from_row(current)

    @staticmethod
    def verification_reference_sample_sha256(
        sample: dict[str, Any],
    ) -> str:
        return hashlib.sha256(_json(sample).encode("utf-8")).hexdigest()

    @staticmethod
    def _verification_reference_registration_sha256(
        *,
        sample_sha256: str,
        source_digests: dict[str, str],
        evidence_refs: list[str],
    ) -> str:
        return hashlib.sha256(
            _json(
                {
                    "sample_sha256": sample_sha256,
                    "source_digests": source_digests,
                    "evidence_refs": evidence_refs,
                }
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _validate_verification_reference_evidence(
        source_digests: dict[str, str],
        evidence_refs: list[str],
    ) -> tuple[dict[str, str], list[str]]:
        normalized_digests = {
            str(name).strip(): str(digest).strip().lower()
            for name, digest in source_digests.items()
        }
        if not _REQUIRED_VERIFICATION_REFERENCE_DIGESTS.issubset(
            normalized_digests
        ):
            raise ValueError(
                "production, electricity and explosives source digests "
                "are required"
            )
        for name, digest in normalized_digests.items():
            if (
                not name
                or len(name) > 128
                or len(digest) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in digest
                )
            ):
                raise ValueError("source digests must be named lowercase SHA-256")
        normalized_refs = [str(value).strip() for value in evidence_refs]
        if (
            not normalized_refs
            or len(normalized_refs) > 100
            or any(not value or len(value) > 1000 for value in normalized_refs)
            or len(normalized_refs) != len(set(normalized_refs))
        ):
            raise ValueError(
                "evidence_refs must contain unique non-empty references"
            )
        return (
            dict(sorted(normalized_digests.items())),
            sorted(normalized_refs),
        )

    def _append_verification_reference_event(
        self,
        connection: sqlite3.Connection,
        *,
        sample_id: str,
        event_type: str,
        actor_id: str,
        from_status: str | None,
        to_status: str,
        note: str | None,
        payload: dict[str, Any],
        occurred_at: datetime,
    ) -> None:
        previous = connection.execute(
            """
            SELECT event_hash
            FROM verification_reference_events
            WHERE sample_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (sample_id,),
        ).fetchone()
        previous_hash = None if previous is None else previous["event_hash"]
        event_id = f"verification-reference-event-{uuid4()}"
        document = {
            "event_id": event_id,
            "sample_id": sample_id,
            "event_type": event_type,
            "actor_id": actor_id,
            "occurred_at": _format_time(occurred_at),
            "from_status": from_status,
            "to_status": to_status,
            "note": note,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        event_hash = hashlib.sha256(
            _json(document).encode("utf-8")
        ).hexdigest()
        connection.execute(
            """
            INSERT INTO verification_reference_events(
                event_id, sample_id, event_type, actor_id, occurred_at,
                from_status, to_status, note, payload_json,
                previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                sample_id,
                event_type,
                actor_id,
                _format_time(occurred_at),
                from_status,
                to_status,
                note,
                _json(payload),
                previous_hash,
                event_hash,
            ),
        )

    @staticmethod
    def _verification_reference_event_chain_valid(
        events: list[sqlite3.Row],
    ) -> bool:
        previous_hash: str | None = None
        for row in events:
            document = {
                "event_id": row["event_id"],
                "sample_id": row["sample_id"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "occurred_at": row["occurred_at"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "note": row["note"],
                "payload": json.loads(row["payload_json"]),
                "previous_hash": row["previous_hash"],
            }
            expected = hashlib.sha256(
                _json(document).encode("utf-8")
            ).hexdigest()
            if (
                row["previous_hash"] != previous_hash
                or row["event_hash"] != expected
            ):
                return False
            previous_hash = row["event_hash"]
        return True

    def _verification_reference_row_integrity_valid(
        self,
        row: sqlite3.Row,
        events: list[sqlite3.Row],
    ) -> bool:
        try:
            sample = json.loads(row["sample_json"])
            source_digests = json.loads(row["source_digests_json"])
            evidence_refs = json.loads(row["evidence_refs_json"])
        except (TypeError, ValueError):
            return False
        if (
            not events
            or not self._verification_reference_event_chain_valid(events)
            or sample.get("sample_id") != row["sample_id"]
            or sample.get("mine_id") != row["mine_id"]
            or self.verification_reference_sample_sha256(sample)
            != row["sample_sha256"]
            or self._verification_reference_registration_sha256(
                sample_sha256=row["sample_sha256"],
                source_digests=source_digests,
                evidence_refs=evidence_refs,
            )
            != row["registration_sha256"]
        ):
            return False
        first = events[0]
        if (
            first["event_type"] != "registered"
            or first["actor_id"] != row["registered_by"]
            or first["occurred_at"] != row["registered_at"]
            or first["from_status"] is not None
            or first["to_status"] != "draft"
        ):
            return False
        first_payload = json.loads(first["payload_json"])
        if (
            first_payload.get("sample_sha256") != row["sample_sha256"]
            or first_payload.get("registration_sha256")
            != row["registration_sha256"]
        ):
            return False
        last = events[-1]
        if last["to_status"] != row["status"]:
            return False
        if row["status"] == "draft":
            return (
                len(events) == 1
                and row["decided_at"] is None
                and row["decided_by"] is None
                and row["decision_note"] is None
            )
        expected_event = (
            "approve" if row["status"] == "approved" else "reject"
        )
        if (
            len(events) != 2
            or last["event_type"] != expected_event
            or last["from_status"] != "draft"
            or last["actor_id"] != row["decided_by"]
            or last["occurred_at"] != row["decided_at"]
            or last["note"] != row["decision_note"]
            or row["registered_by"] == row["decided_by"]
        ):
            return False
        last_payload = json.loads(last["payload_json"])
        return (
            last_payload.get("expected_sample_sha256")
            == row["sample_sha256"]
            and last_payload.get("registration_sha256")
            == row["registration_sha256"]
        )

    def _verification_reference_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        events = connection.execute(
            """
            SELECT rowid AS event_sequence, *
            FROM verification_reference_events
            WHERE sample_id = ?
            ORDER BY rowid
            """,
            (row["sample_id"],),
        ).fetchall()
        item = {
            key: row[key]
            for key in row.keys()
            if key
            not in {
                "sample_json",
                "source_digests_json",
                "evidence_refs_json",
            }
        }
        item["sample"] = json.loads(row["sample_json"])
        item["source_digests"] = json.loads(row["source_digests_json"])
        item["evidence_refs"] = json.loads(row["evidence_refs_json"])
        item["events"] = [
            {
                **{
                    key: event[key]
                    for key in event.keys()
                    if key != "payload_json"
                },
                "payload": json.loads(event["payload_json"]),
            }
            for event in events
        ]
        integrity_valid = self._verification_reference_row_integrity_valid(
            row,
            events,
        )
        item["audit_chain_valid"] = integrity_valid
        item["registry_integrity_valid"] = integrity_valid
        return item

    def register_verification_reference(
        self,
        *,
        sample: dict[str, Any],
        source_digests: dict[str, str],
        evidence_refs: list[str],
        actor_id: str,
    ) -> tuple[dict[str, Any], bool]:
        sample_id = str(sample.get("sample_id") or "").strip()
        mine_id = str(sample.get("mine_id") or "").strip()
        actor_id = actor_id.strip()
        if (
            not sample_id
            or sample.get("sample_id") != sample_id
            or len(sample_id) > 128
            or not mine_id
            or sample.get("mine_id") != mine_id
            or len(mine_id) > 128
            or not actor_id
        ):
            raise ValueError("sample_id, mine_id and actor_id are required")
        normalized_digests, normalized_refs = (
            self._validate_verification_reference_evidence(
                source_digests,
                evidence_refs,
            )
        )
        sample_text = _json(sample)
        sample_sha256 = hashlib.sha256(
            sample_text.encode("utf-8")
        ).hexdigest()
        source_text = _json(normalized_digests)
        evidence_text = _json(normalized_refs)
        registration_sha256 = (
            self._verification_reference_registration_sha256(
                sample_sha256=sample_sha256,
                source_digests=normalized_digests,
                evidence_refs=normalized_refs,
            )
        )
        now = _utc_now()
        with self._transaction() as connection:
            mine = connection.execute(
                "SELECT 1 FROM mine_registry WHERE mine_id = ?",
                (mine_id,),
            ).fetchone()
            if mine is None:
                raise ValueError(
                    "verification reference mine is not registered"
                )
            existing = connection.execute(
                """
                SELECT *
                FROM verification_reference_samples
                WHERE sample_id = ?
                """,
                (sample_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["sample_sha256"] != sample_sha256
                    or existing["sample_json"] != sample_text
                    or existing["source_digests_json"] != source_text
                    or existing["evidence_refs_json"] != evidence_text
                    or existing["registration_sha256"]
                    != registration_sha256
                ):
                    raise VerificationReferenceConflictError(
                        "sample_id is already bound to different immutable "
                        "content or evidence"
                    )
                return (
                    self._verification_reference_from_row(
                        connection,
                        existing,
                    ),
                    False,
                )
            connection.execute(
                """
                INSERT INTO verification_reference_samples(
                    sample_id, mine_id, sample_json, sample_sha256,
                    source_digests_json, evidence_refs_json,
                    registration_sha256, status, registered_at,
                    registered_by, decided_at, decided_by, decision_note
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, NULL, NULL, NULL
                )
                """,
                (
                    sample_id,
                    mine_id,
                    sample_text,
                    sample_sha256,
                    source_text,
                    evidence_text,
                    registration_sha256,
                    _format_time(now),
                    actor_id,
                ),
            )
            self._append_verification_reference_event(
                connection,
                sample_id=sample_id,
                event_type="registered",
                actor_id=actor_id,
                from_status=None,
                to_status="draft",
                note=None,
                payload={
                    "sample_sha256": sample_sha256,
                    "registration_sha256": registration_sha256,
                    "source_digest_names": sorted(normalized_digests),
                    "evidence_ref_count": len(normalized_refs),
                },
                occurred_at=now,
            )
            row = connection.execute(
                """
                SELECT *
                FROM verification_reference_samples
                WHERE sample_id = ?
                """,
                (sample_id,),
            ).fetchone()
            assert row is not None
            return (
                self._verification_reference_from_row(connection, row),
                True,
            )

    def list_verification_references(
        self,
        *,
        mine_ids: set[str] | None = None,
        status: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        if status is not None and status not in {
            "draft",
            "approved",
            "rejected",
        }:
            raise ValueError("invalid verification reference status")
        clauses: list[str] = []
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            clauses.append(f"mine_id IN ({placeholders})")
            arguments.extend(sorted(mine_ids))
        if status is not None:
            clauses.append("status = ?")
            arguments.append(status)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        arguments.append(max(1, min(int(limit), 1000)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT *
                FROM verification_reference_samples
                {where}
                ORDER BY registered_at DESC, sample_id
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
            return [
                self._verification_reference_from_row(
                    self._connection,
                    row,
                )
                for row in rows
            ]

    def get_verification_reference(
        self,
        sample_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT *
                FROM verification_reference_samples
                WHERE sample_id = ?
                """,
                (sample_id,),
            ).fetchone()
            if row is None:
                return None
            return self._verification_reference_from_row(
                self._connection,
                row,
            )

    def decide_verification_reference(
        self,
        sample_id: str,
        *,
        action: Literal["approve", "reject"],
        expected_sample_sha256: str,
        note: str,
        actor_id: str,
    ) -> tuple[dict[str, Any], bool]:
        sample_id = sample_id.strip()
        actor_id = actor_id.strip()
        note = note.strip()
        if (
            not sample_id
            or action not in {"approve", "reject"}
            or len(expected_sample_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_sample_sha256
            )
            or not actor_id
            or not 10 <= len(note) <= 4000
        ):
            raise ValueError("invalid verification reference decision")
        target_status = "approved" if action == "approve" else "rejected"
        now = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM verification_reference_samples
                WHERE sample_id = ?
                """,
                (sample_id,),
            ).fetchone()
            if row is None:
                raise VerificationReferenceNotFoundError(
                    "verification reference not found"
                )
            if row["sample_sha256"] != expected_sample_sha256:
                raise VerificationReferenceConflictError(
                    "expected_sample_sha256 does not match immutable sample"
                )
            if row["status"] == target_status:
                if (
                    row["decided_by"] != actor_id
                    or row["decision_note"] != note
                ):
                    raise InvalidVerificationReferenceActionError(
                        "verification reference decision is already bound "
                        "to another immutable approval request"
                    )
                return (
                    self._verification_reference_from_row(connection, row),
                    False,
                )
            if row["status"] != "draft":
                raise InvalidVerificationReferenceActionError(
                    "verification reference decision is immutable"
                )
            if row["registered_by"] == actor_id:
                raise InvalidVerificationReferenceActionError(
                    "the registrant cannot approve or reject the same sample"
                )
            events = connection.execute(
                """
                SELECT *
                FROM verification_reference_events
                WHERE sample_id = ?
                ORDER BY rowid
                """,
                (sample_id,),
            ).fetchall()
            if not self._verification_reference_row_integrity_valid(
                row,
                events,
            ):
                raise VerificationReferenceConflictError(
                    "verification reference integrity check failed"
                )
            connection.execute(
                """
                UPDATE verification_reference_samples
                SET status = ?, decided_at = ?, decided_by = ?,
                    decision_note = ?
                WHERE sample_id = ?
                """,
                (
                    target_status,
                    _format_time(now),
                    actor_id,
                    note,
                    sample_id,
                ),
            )
            self._append_verification_reference_event(
                connection,
                sample_id=sample_id,
                event_type=action,
                actor_id=actor_id,
                from_status="draft",
                to_status=target_status,
                note=note,
                payload={
                    "expected_sample_sha256": expected_sample_sha256,
                    "registration_sha256": row["registration_sha256"],
                },
                occurred_at=now,
            )
            current = connection.execute(
                """
                SELECT *
                FROM verification_reference_samples
                WHERE sample_id = ?
                """,
                (sample_id,),
            ).fetchone()
            assert current is not None
            return (
                self._verification_reference_from_row(connection, current),
                True,
            )

    def validate_verification_reference_history(
        self,
        samples: list[dict[str, Any]],
        *,
        expected_mine_id: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        approved: list[dict[str, Any]] = []
        failures: list[dict[str, Any]] = []
        with self._lock:
            for sample in samples:
                sample_id = str(sample.get("sample_id") or "")
                if (
                    expected_mine_id is not None
                    and sample.get("mine_id") != expected_mine_id
                ):
                    failures.append(
                        {
                            "sample_id": sample_id,
                            "code": "reference_mine_mismatch",
                            "sample_mine_id": sample.get("mine_id"),
                            "expected_mine_id": expected_mine_id,
                        }
                    )
                    continue
                sample_sha256 = self.verification_reference_sample_sha256(
                    sample
                )
                row = self._connection.execute(
                    """
                    SELECT *
                    FROM verification_reference_samples
                    WHERE sample_id = ?
                    """,
                    (sample_id,),
                ).fetchone()
                if row is None:
                    failures.append(
                        {
                            "sample_id": sample_id,
                            "code": "reference_not_registered",
                        }
                    )
                    continue
                if (
                    row["sample_sha256"] != sample_sha256
                    or row["sample_json"] != _json(sample)
                ):
                    failures.append(
                        {
                            "sample_id": sample_id,
                            "code": "reference_hash_mismatch",
                            "submitted_sample_sha256": sample_sha256,
                            "registered_sample_sha256": row["sample_sha256"],
                        }
                    )
                    continue
                stored_digests = json.loads(row["source_digests_json"])
                stored_refs = json.loads(row["evidence_refs_json"])
                registration_sha256 = (
                    self._verification_reference_registration_sha256(
                        sample_sha256=row["sample_sha256"],
                        source_digests=stored_digests,
                        evidence_refs=stored_refs,
                    )
                )
                events = self._connection.execute(
                    """
                    SELECT *
                    FROM verification_reference_events
                    WHERE sample_id = ?
                    ORDER BY rowid
                    """,
                    (sample_id,),
                ).fetchall()
                if (
                    registration_sha256 != row["registration_sha256"]
                    or not self._verification_reference_row_integrity_valid(
                        row,
                        events,
                    )
                ):
                    failures.append(
                        {
                            "sample_id": sample_id,
                            "code": "reference_registry_integrity_failed",
                        }
                    )
                    continue
                if row["status"] != "approved":
                    failures.append(
                        {
                            "sample_id": sample_id,
                            "code": "reference_not_approved",
                            "status": row["status"],
                        }
                    )
                    continue
                approved.append(
                    {
                        "sample_id": sample_id,
                        "sample_sha256": row["sample_sha256"],
                        "registration_sha256": row["registration_sha256"],
                        "approved_at": row["decided_at"],
                        "approved_by": row["decided_by"],
                        "evidence_ref_count": len(stored_refs),
                        "source_digest_names": sorted(stored_digests),
                    }
                )
        return approved, failures

    def save_verification_run(
        self,
        *,
        request: dict[str, Any],
        result: dict[str, Any],
        actor_id: str,
    ) -> tuple[dict[str, Any], bool]:
        request_text = _json(request)
        result_text = _json(result)
        request_sha256 = hashlib.sha256(
            request_text.encode("utf-8")
        ).hexdigest()
        result_sha256 = hashlib.sha256(
            result_text.encode("utf-8")
        ).hexdigest()
        request_id = str(request["request_id"])
        now = _format_time(_utc_now())
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT * FROM production_verification_runs
                WHERE request_id = ?
                """,
                (request_id,),
            ).fetchone()
            if existing is not None:
                if existing["request_sha256"] != request_sha256:
                    raise VerificationRunConflictError(
                        "request_id is already bound to different content"
                    )
                return self._verification_from_row(existing), False
            run_id = f"verification-run-{uuid4()}"
            connection.execute(
                """
                INSERT INTO production_verification_runs(
                    run_id, request_id, request_sha256, mine_id,
                    window_start, window_end, status,
                    overall_clue_level, request_json, result_json,
                    result_sha256, created_at, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    request_id,
                    request_sha256,
                    request["mine_id"],
                    request["window_start"],
                    request["window_end"],
                    result["status"],
                    int(result["overall_clue_level"]),
                    request_text,
                    result_text,
                    result_sha256,
                    now,
                    actor_id,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM production_verification_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            assert row is not None
            return self._verification_from_row(row), True

    @staticmethod
    def _verification_from_row(row: sqlite3.Row) -> dict[str, Any]:
        item = _row_dict(row)
        item["request"] = json.loads(item.pop("request_json"))
        item["result"] = json.loads(item.pop("result_json"))
        return item

    def list_verification_runs(
        self,
        *,
        mine_ids: set[str] | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        where = ""
        arguments: list[Any] = []
        if mine_ids is not None:
            if not mine_ids:
                return []
            placeholders = ",".join("?" for _ in mine_ids)
            where = f"WHERE mine_id IN ({placeholders})"
            arguments.extend(sorted(mine_ids))
        arguments.append(max(1, min(limit, 1000)))
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM production_verification_runs
                {where}
                ORDER BY window_end DESC, created_at DESC
                LIMIT ?
                """,
                tuple(arguments),
            ).fetchall()
        return [self._verification_from_row(row) for row in rows]

    def dashboard(self, mine_ids: set[str] | None = None) -> dict[str, Any]:
        mines = {item["mine_id"]: item for item in self.list_mines(mine_ids)}
        latest = self.list_latest_metrics(mine_ids)
        for item in latest:
            mine = mines.setdefault(
                item["mine_id"],
                {
                    "mine_id": item["mine_id"],
                    "mine_name": item["mine_id"],
                    "gas_category": None,
                    "longitude": None,
                    "latitude": None,
                    "approved_capacity_tpy": None,
                    "approved_underground_personnel": None,
                    "enabled": True,
                },
            )
            mine.setdefault("latest_metrics", {})
            mine["latest_metrics"][
                f"{item['metric_code']}@{item['location_code']}"
            ] = {
                "metric_code": item["metric_code"],
                "value": item["value"],
                "unit": item["unit"],
                "location_code": item["location_code"],
                "observed_at": item["observed_at"],
                "received_at": item["received_at"],
                "observation_id": item["observation_id"],
                "revision": int(item["revision"]),
                "source_id": item["source_id"],
                "status_code": item["status_code"],
                "quality": json.loads(item["quality_json"]),
                "interval": (
                    None
                    if item["interval_json"] is None
                    else json.loads(item["interval_json"])
                ),
            }
        all_alerts = self.list_alerts(mine_ids=mine_ids, limit=1000)
        disabled_mine_ids = {
            mine_id
            for mine_id, mine in mines.items()
            if not bool(mine.get("enabled", True))
        }
        alerts = [
            alert
            for alert in all_alerts
            if alert["mine_id"] not in disabled_mine_ids
        ]
        counts = {
            "total_open": 0,
            "overdue": 0,
            "blue": 0,
            "yellow": 0,
            "orange": 0,
            "red": 0,
        }
        shadow_summary = {
            "total_open": 0,
            "blue": 0,
            "yellow": 0,
            "orange": 0,
            "red": 0,
        }
        for alert in alerts:
            mine = mines.setdefault(
                alert["mine_id"],
                {
                    "mine_id": alert["mine_id"],
                    "mine_name": alert["mine_id"],
                    "gas_category": None,
                    "latest_metrics": {},
                    "enabled": True,
                },
            )
            mine.setdefault("open_alerts", [])
            mine.setdefault("shadow_alerts", [])
            if (
                alert["status"] in _OPEN_STATUSES
                and not alert["operational"]
            ):
                shadow_summary["total_open"] += 1
                shadow_summary[alert["level"]] += 1
                mine["shadow_alerts"].append(
                    {
                        key: alert[key]
                        for key in (
                            "alert_id",
                            "level",
                            "status",
                            "title",
                            "location_code",
                            "last_seen_at",
                            "operational",
                            "mode",
                        )
                    }
                )
            elif alert["status"] in _OPEN_STATUSES:
                counts["total_open"] += 1
                counts[alert["level"]] += 1
                counts["overdue"] += int(alert["overdue"])
                mine["open_alerts"].append(
                    {
                        key: alert[key]
                        for key in (
                            "alert_id",
                            "level",
                            "status",
                            "title",
                            "location_code",
                            "last_seen_at",
                            "overdue",
                            "operational",
                            "mode",
                        )
                    }
                )
        verification_summary = {
            "ready": 0,
            "insufficient_history": 0,
            "blocked": 0,
            "attention_or_higher": 0,
        }
        seen_verification_mines: set[str] = set()
        for run in self.list_verification_runs(
            mine_ids=mine_ids,
            limit=1000,
        ):
            if run["mine_id"] in disabled_mine_ids:
                continue
            if run["mine_id"] in seen_verification_mines:
                continue
            seen_verification_mines.add(run["mine_id"])
            status = run["status"]
            if status in verification_summary:
                verification_summary[status] += 1
            if int(run["overall_clue_level"]) >= 1:
                verification_summary["attention_or_higher"] += 1
            mine = mines.setdefault(
                run["mine_id"],
                {
                    "mine_id": run["mine_id"],
                    "mine_name": run["mine_id"],
                    "gas_category": None,
                    "latest_metrics": {},
                    "enabled": True,
                },
            )
            result = run["result"]
            energy = result.get("energy")
            explosives = result.get("explosives")
            mine["production_verification"] = {
                "run_id": run["run_id"],
                "request_id": run["request_id"],
                "window_start": run["window_start"],
                "window_end": run["window_end"],
                "status": status,
                "overall_clue_level": run["overall_clue_level"],
                "jointly_upgraded": bool(
                    result.get("jointly_upgraded")
                ),
                "energy": (
                    None
                    if energy is None
                    else {
                        "band": energy.get("band"),
                        "verification_ratio": energy.get(
                            "verification_ratio"
                        ),
                        "direction": energy.get("direction"),
                        "historical_rarity": energy.get(
                            "historical_rarity"
                        ),
                    }
                ),
                "explosives": (
                    None
                    if explosives is None
                    else {
                        "band": explosives.get("band"),
                        "robust_z": explosives.get("robust_z"),
                        "direction": explosives.get("direction"),
                        "historical_rarity": explosives.get(
                            "historical_rarity"
                        ),
                    }
                ),
                "technical_clues": result.get("technical_clues", [])[:5],
                "disclaimer": result.get("disclaimer"),
            }
        mine_items = list(mines.values())
        for mine in mine_items:
            mine.setdefault("latest_metrics", {})
            mine.setdefault("open_alerts", [])
            mine.setdefault("shadow_alerts", [])
            if not bool(mine.get("enabled", True)):
                mine["open_alerts"] = []
                mine["shadow_alerts"] = []
                mine["risk_level"] = "monitoring_disabled"
                continue
            levels = [
                item["level"] for item in mine["open_alerts"]
            ]
            mine["risk_level"] = (
                max(levels, key=_LEVEL_RANK.__getitem__)
                if levels
                else "normal"
            )
        mine_items.sort(key=lambda item: item["mine_name"])
        verification_heatmap = [
            {
                "mine_id": mine["mine_id"],
                "mine_name": mine["mine_name"],
                **mine["production_verification"],
            }
            for mine in mine_items
            if mine.get("enabled", True)
            and mine.get("production_verification") is not None
        ]
        verification_heatmap.sort(
            key=lambda item: (
                -int(item["overall_clue_level"]),
                str(item["mine_name"]),
            )
        )
        return {
            "generated_at": _format_time(_utc_now()),
            "summary": counts,
            "shadow_summary": shadow_summary,
            "responsibility_health": self.responsibility_health(mine_ids),
            "evaluation_health": self.evaluation_health(mine_ids),
            "verification_summary": verification_summary,
            "verification_heatmap": verification_heatmap,
            "mines": mine_items,
            "alerts": alerts[:100],
            "disclaimer": (
                "预警为辅助监管线索，不替代法定监测、现场处置或行政认定。"
            ),
        }
