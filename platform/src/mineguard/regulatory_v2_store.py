"""Append-only persistence and automated lifecycle for regulatory V2.

Business users consume read-only projections from this store.  The only write
paths are machine-to-machine submission intake and enterprise response intake;
neither offers an operator method for changing an algorithm conclusion.

The schema uses new ``v2_*`` tables and therefore leaves every legacy table
and hash chain untouched.  Base records are immutable.  Lifecycle changes are
new events, never updates: an enterprise explanation is recorded as
``explanation_recorded`` and only a later, normal-candidate revision can append
``resolved_by_revision``.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, date, datetime
import hashlib
import json
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Annotated, Any, Callable, Iterator, Literal, Sequence
from uuid import NAMESPACE_URL, uuid4, uuid5
from zoneinfo import ZoneInfo

from pydantic import AwareDatetime, Field, model_validator

from .models import StrictModel
from .regulatory_v2 import (
    BASELINE_ADMISSION_RULE_VERSION,
    DecisionStatus,
    FiveQuantitySubmission,
    HistoricalFiveQuantityDay,
    ReferenceBand,
    RegulatoryFiveQuantityParameters,
    RegulatoryFiveQuantityResult,
    RelationshipCode,
    analyze_five_quantity,
    effective_reported_value,
)


class RegulatoryV2ConflictError(ValueError):
    """An idempotency, revision or immutable-identity conflict."""


class _DurableIdempotencyConflict(RegulatoryV2ConflictError):
    """Conflict whose security audit must commit before it is returned."""


class RegulatoryV2NotFoundError(LookupError):
    """A requested V2 object does not exist in the caller's scope."""


class EvidenceReference(StrictModel):
    title: Annotated[str, Field(min_length=1, max_length=256)]
    evidence_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    locator: Annotated[str | None, Field(min_length=1, max_length=512)] = None


class EnterpriseFindingResponse(StrictModel):
    contract_version: Literal["enterprise-finding-response-v2"] = (
        "enterprise-finding-response-v2"
    )
    response_id: Annotated[str, Field(min_length=8, max_length=128)]
    finding_id: Annotated[str, Field(min_length=8, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    reason_category: Literal[
        "production_arrangement",
        "equipment_or_metering",
        "reporting_scope",
        "maintenance_or_shutdown",
        "geological_condition",
        "data_correction_planned",
        "other",
    ]
    explanation: Annotated[str, Field(min_length=1, max_length=10_000)]
    corrective_action: Annotated[str | None, Field(min_length=1, max_length=5_000)] = (
        None
    )
    corrected_submission_planned: bool = False
    evidence: Annotated[list[EvidenceReference], Field(max_length=64)] = Field(
        default_factory=list
    )
    confirmed_by: Annotated[str, Field(min_length=1, max_length=128)]
    confirmed_at: AwareDatetime


class RiskFindingReport(StrictModel):
    contract_version: Literal["government-finding-report-v2"] = (
        "government-finding-report-v2"
    )
    finding_id: str
    mine_id: str
    submission_id: str
    run_id: str
    finding_type: Literal["risk", "data_insufficient"]
    category: Literal[
        "data_quality",
        "relationship_consistency",
        "temporal_pattern",
        "data_completeness",
    ]
    title: str
    summary: str
    decision_reasons: list[str]
    result: RegulatoryFiveQuantityResult
    issued_at: AwareDatetime
    lifecycle_statement: Literal[
        "enterprise_explanation_is_recorded_but_does_not_clear_finding"
    ] = "enterprise_explanation_is_recorded_but_does_not_clear_finding"


class AnalysisReport(StrictModel):
    contract_version: Literal["government-analysis-report-v2"] = (
        "government-analysis-report-v2"
    )
    report_id: str
    run_id: str
    submission_id: str
    mine_id: str
    outcome: DecisionStatus
    finding_ids: list[str]
    response_required: bool
    delivery_cursor: Annotated[
        str, Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    result: RegulatoryFiveQuantityResult
    issued_at: AwareDatetime

    @model_validator(mode="after")
    def validate_outcome(self) -> "AnalysisReport":
        expected = self.outcome is not DecisionStatus.NORMAL_CANDIDATE
        if self.response_required != expected:
            raise ValueError("response_required must match the analysis outcome")
        if expected != bool(self.finding_ids):
            raise ValueError("non-normal report requires at least one finding")
        return self


class SubmissionReceipt(StrictModel):
    contract_version: Literal["government-submission-receipt-v2"] = (
        "government-submission-receipt-v2"
    )
    submission_id: str
    run_id: str
    mine_id: str
    decision: DecisionStatus
    finding_id: str | None
    received_at: AwareDatetime
    payload_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    idempotent_replay: bool = False


class ResponseReceipt(StrictModel):
    contract_version: Literal["government-response-receipt-v2"] = (
        "government-response-receipt-v2"
    )
    response_id: str
    finding_id: str
    mine_id: str
    recorded_at: AwareDatetime
    finding_state: Literal["explanation_recorded"] = "explanation_recorded"
    risk_cleared: Literal[False] = False
    idempotent_replay: bool = False


class ResponseBatchReceipt(StrictModel):
    contract_version: Literal["government-response-receipt-v2"] = (
        "government-response-receipt-v2"
    )
    wire_response_id: str
    report_id: str
    mine_id: str
    child_response_ids: list[str]
    finding_ids: list[str]
    recorded_at: AwareDatetime
    finding_state: Literal["explanation_recorded"] = "explanation_recorded"
    risk_cleared: Literal[False] = False
    idempotent_replay: bool = False


class AnalysisReportDeliveryAck(StrictModel):
    contract_version: Literal["risk-delivery-ack-v2"] = "risk-delivery-ack-v2"
    ack_id: Annotated[str, Field(min_length=8, max_length=128)]
    report_id: Annotated[str, Field(min_length=8, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    analysis_report_message_id: Annotated[str, Field(min_length=8, max_length=128)]
    delivery_cursor: Annotated[
        str, Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    local_inbox_record_id: Annotated[str, Field(min_length=1, max_length=128)]
    delivery_status: Literal["stored", "duplicate"]
    received_at: AwareDatetime


class DeliveryAckReceipt(StrictModel):
    ack_id: str
    report_id: str
    mine_id: str
    recorded_at: AwareDatetime
    idempotent_replay: bool = False


class OutboxItem(StrictModel):
    sequence: Annotated[int, Field(ge=1)]
    message_id: str
    audience_mine_id: str
    kind: Literal[
        "analysis_report_available",
        "finding_issued",
        "response_recorded",
        "finding_resolved",
    ]
    aggregate_id: str
    payload: dict[str, Any]
    created_at: AwareDatetime


class OutboxPage(StrictModel):
    items: list[OutboxItem]
    next_cursor: Annotated[int, Field(ge=0)]
    has_more: bool


class ExchangeMessageInput(StrictModel):
    """Lossless storage wrapper for a signed neutral-contract message."""

    message_id: Annotated[str, Field(min_length=8, max_length=128)]
    direction: Literal["inbound", "outbound"]
    message_type: Annotated[str, Field(min_length=1, max_length=128)]
    mine_id: Annotated[str, Field(min_length=1, max_length=128)]
    agent_id: Annotated[str | None, Field(min_length=1, max_length=128)] = None
    body: dict[str, Any]
    exchanged_at: AwareDatetime


class ExchangeMessageProjection(ExchangeMessageInput):
    sequence: Annotated[int, Field(ge=1)]
    body_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class FindingProjection(StrictModel):
    finding: RiskFindingReport
    state: Literal["open", "explanation_recorded", "cleared_by_reanalysis"]
    responses: list[EnterpriseFindingResponse]
    resolved_by_submission_id: str | None = None
    event_count: Annotated[int, Field(ge=1)]


class MineOverview(StrictModel):
    mine_id: str
    mine_name: str
    latest_submission_id: str | None
    latest_period_end: date | None
    latest_decision: DecisionStatus | None
    open_finding_count: Annotated[int, Field(ge=0)]
    explanation_recorded_finding_count: Annotated[int, Field(ge=0)]
    cleared_finding_count: Annotated[int, Field(ge=0)]
    latest_audit_at: AwareDatetime | None


class AuditProjection(StrictModel):
    sequence: Annotated[int, Field(ge=1)]
    event_id: str
    event_type: str
    aggregate_type: str
    aggregate_id: str
    mine_id: str | None
    payload: dict[str, Any]
    occurred_at: AwareDatetime
    previous_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    event_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class AuditPage(StrictModel):
    """One stable, newest-first page from the immutable audit ledger."""

    items: list[AuditProjection]
    snapshot_sequence: Annotated[int, Field(ge=0)]
    matched_count: Annotated[int, Field(ge=0)]
    has_more: bool
    next_before_sequence: Annotated[int | None, Field(ge=1)] = None


class MineDetailProjection(StrictModel):
    overview: MineOverview
    submissions: list[dict[str, Any]]
    runs: list[dict[str, Any]]
    analysis_reports: list[AnalysisReport]
    findings: list[FindingProjection]
    daily_facts: list[dict[str, Any]]
    audit_events: list[AuditProjection]


class RegulatoryV2Store:
    """SQLite-backed V2 service boundary.

    A single instance is safe for concurrent threads.  Processes coordinate
    through ``BEGIN IMMEDIATE`` and SQLite's busy timeout.  ``now`` is
    injectable for deterministic tests.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = str(path)
        self._now = now or (lambda: datetime.now(UTC))
        self._lock = RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=15.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 15000")
        if self.path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._create_schema()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "RegulatoryV2Store":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except _DurableIdempotencyConflict:
                # The conflicting business command is never applied, but the
                # attempted idempotency-key reuse is itself immutable evidence.
                self._connection.commit()
                raise
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _create_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS v2_agent_mine_bindings (
            agent_id TEXT PRIMARY KEY,
            mine_id TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_transport_nonces (
            sender_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            request_time TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (sender_id, nonce)
        );
        CREATE INDEX IF NOT EXISTS idx_v2_transport_nonce_expiry
            ON v2_transport_nonces(expires_at);

        CREATE TABLE IF NOT EXISTS v2_inbox_commands (
            sender_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            message_id TEXT NOT NULL,
            message_type TEXT NOT NULL,
            mine_id TEXT NOT NULL,
            body_sha256 TEXT NOT NULL,
            result_kind TEXT NOT NULL,
            result_id TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (sender_id, idempotency_key),
            UNIQUE (message_id)
        );
        CREATE INDEX IF NOT EXISTS idx_v2_inbox_result
            ON v2_inbox_commands(result_kind, result_id);

        CREATE TABLE IF NOT EXISTS v2_submissions (
            submission_id TEXT PRIMARY KEY,
            mine_id TEXT NOT NULL,
            mine_name TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK (revision >= 1),
            supersedes_submission_id TEXT REFERENCES v2_submissions(submission_id),
            reporting_month TEXT NOT NULL,
            root_workflow_id TEXT NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            comparison_group TEXT NOT NULL,
            idempotency_key TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            received_at TEXT NOT NULL,
            UNIQUE (mine_id, period_start, period_end, revision),
            UNIQUE (mine_id, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS v2_daily_facts (
            submission_id TEXT NOT NULL REFERENCES v2_submissions(submission_id),
            observed_date TEXT NOT NULL,
            normalized_json TEXT NOT NULL,
            normalized_sha256 TEXT NOT NULL,
            PRIMARY KEY (submission_id, observed_date)
        );

        CREATE TABLE IF NOT EXISTS v2_analysis_runs (
            run_id TEXT PRIMARY KEY,
            submission_id TEXT NOT NULL REFERENCES v2_submissions(submission_id),
            mine_id TEXT NOT NULL,
            method_version TEXT NOT NULL,
            decision TEXT NOT NULL CHECK (
                decision IN ('normal_candidate', 'risk', 'insufficient_data')
            ),
            result_json TEXT NOT NULL,
            result_sha256 TEXT NOT NULL,
            algorithm_input_sha256 TEXT NOT NULL,
            configuration_sha256 TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            UNIQUE (submission_id, method_version)
        );

        CREATE TABLE IF NOT EXISTS v2_baseline_admissions (
            admission_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL UNIQUE REFERENCES v2_analysis_runs(run_id),
            submission_id TEXT NOT NULL REFERENCES v2_submissions(submission_id),
            mine_id TEXT NOT NULL,
            eligible INTEGER NOT NULL CHECK (eligible IN (0, 1)),
            reference_candidate INTEGER NOT NULL CHECK (
                reference_candidate IN (0, 1)
            ),
            rule_version TEXT NOT NULL,
            reasons_json TEXT NOT NULL,
            reasons_sha256 TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_peer_reference_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            comparison_group TEXT NOT NULL,
            cutoff_date TEXT NOT NULL,
            cohort_json TEXT NOT NULL,
            cohort_sha256 TEXT NOT NULL,
            mine_count INTEGER NOT NULL CHECK (mine_count >= 0),
            created_at TEXT NOT NULL,
            UNIQUE (comparison_group, cutoff_date)
        );

        CREATE TABLE IF NOT EXISTS v2_findings (
            finding_id TEXT PRIMARY KEY,
            submission_id TEXT NOT NULL REFERENCES v2_submissions(submission_id),
            run_id TEXT NOT NULL REFERENCES v2_analysis_runs(run_id),
            mine_id TEXT NOT NULL,
            finding_type TEXT NOT NULL CHECK (
                finding_type IN ('risk', 'data_insufficient')
            ),
            category TEXT NOT NULL CHECK (
                category IN (
                    'data_quality', 'relationship_consistency',
                    'temporal_pattern', 'data_completeness'
                )
            ),
            report_json TEXT NOT NULL,
            report_sha256 TEXT NOT NULL,
            issued_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_analysis_reports (
            report_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES v2_analysis_runs(run_id),
            submission_id TEXT NOT NULL REFERENCES v2_submissions(submission_id),
            mine_id TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK (
                outcome IN ('normal_candidate', 'risk', 'insufficient_data')
            ),
            report_json TEXT NOT NULL,
            report_sha256 TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            UNIQUE (run_id)
        );

        CREATE TABLE IF NOT EXISTS v2_finding_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            finding_id TEXT NOT NULL REFERENCES v2_findings(finding_id),
            event_type TEXT NOT NULL CHECK (
                event_type IN (
                    'issued', 'delivery_acknowledged',
                    'explanation_recorded', 'resolved_by_revision'
                )
            ),
            payload_json TEXT NOT NULL,
            occurred_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_response_batches (
            wire_response_id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL REFERENCES v2_analysis_reports(report_id),
            mine_id TEXT NOT NULL,
            request_json TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_responses (
            response_id TEXT PRIMARY KEY,
            finding_id TEXT NOT NULL REFERENCES v2_findings(finding_id),
            mine_id TEXT NOT NULL,
            wire_response_id TEXT REFERENCES v2_response_batches(wire_response_id),
            response_json TEXT NOT NULL,
            response_sha256 TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE (wire_response_id, finding_id)
        );

        CREATE TABLE IF NOT EXISTS v2_delivery_acks (
            ack_id TEXT PRIMARY KEY,
            report_id TEXT NOT NULL REFERENCES v2_analysis_reports(report_id),
            mine_id TEXT NOT NULL,
            analysis_report_message_id TEXT NOT NULL REFERENCES v2_outbox(message_id),
            ack_json TEXT NOT NULL,
            ack_sha256 TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_outbox (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL UNIQUE,
            audience_mine_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (
                kind IN (
                    'analysis_report_available', 'finding_issued',
                    'response_recorded', 'finding_resolved'
                )
            ),
            aggregate_id TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_exchange_messages (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL UNIQUE,
            direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
            message_type TEXT NOT NULL,
            mine_id TEXT NOT NULL,
            agent_id TEXT,
            body_json TEXT NOT NULL,
            body_sha256 TEXT NOT NULL,
            exchanged_at TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS v2_audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            event_type TEXT NOT NULL,
            aggregate_type TEXT NOT NULL,
            aggregate_id TEXT NOT NULL,
            mine_id TEXT,
            payload_json TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_v2_audit_mine_sequence
            ON v2_audit_events(mine_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_v2_audit_event_sequence
            ON v2_audit_events(event_type, sequence);
        CREATE INDEX IF NOT EXISTS idx_v2_audit_occurred_sequence
            ON v2_audit_events(occurred_at, sequence);

        CREATE INDEX IF NOT EXISTS idx_v2_submissions_mine_period
            ON v2_submissions(mine_id, period_start, period_end, revision);
        CREATE INDEX IF NOT EXISTS idx_v2_runs_mine_completed
            ON v2_analysis_runs(mine_id, completed_at);
        CREATE INDEX IF NOT EXISTS idx_v2_findings_mine_issued
            ON v2_findings(mine_id, issued_at);
        CREATE INDEX IF NOT EXISTS idx_v2_outbox_mine_sequence
            ON v2_outbox(audience_mine_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_v2_exchange_mine_sequence
            ON v2_exchange_messages(mine_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_v2_daily_date
            ON v2_daily_facts(observed_date);
        """
        with self._lock:
            self._connection.executescript(schema)
            run_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(v2_analysis_runs)"
                ).fetchall()
            }
            if "started_at" not in run_columns:
                # Forward-only compatibility for early V2 preview databases.
                # Existing rows retain NULL and projections fall back to their
                # completed_at; no historical record is rewritten.
                self._connection.execute(
                    "ALTER TABLE v2_analysis_runs ADD COLUMN started_at TEXT"
                )
            admission_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(v2_baseline_admissions)"
                ).fetchall()
            }
            if "reference_candidate" not in admission_columns:
                self._connection.execute(
                    "ALTER TABLE v2_baseline_admissions ADD COLUMN "
                    "reference_candidate INTEGER NOT NULL DEFAULT 0 "
                    "CHECK (reference_candidate IN (0, 1))"
                )
            submission_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(v2_submissions)"
                ).fetchall()
            }
            if "reporting_month" not in submission_columns:
                self._connection.execute(
                    "ALTER TABLE v2_submissions ADD COLUMN reporting_month TEXT"
                )
            if "root_workflow_id" not in submission_columns:
                self._connection.execute(
                    "ALTER TABLE v2_submissions ADD COLUMN root_workflow_id TEXT"
                )
            self._connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_v2_one_monthly_root
                ON v2_submissions(mine_id, reporting_month)
                WHERE revision = 1 AND reporting_month IS NOT NULL
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_v2_submission_workflow
                ON v2_submissions(root_workflow_id, revision)
                """
            )
            immutable_tables = (
                "v2_agent_mine_bindings",
                "v2_inbox_commands",
                "v2_submissions",
                "v2_daily_facts",
                "v2_analysis_runs",
                "v2_baseline_admissions",
                "v2_peer_reference_snapshots",
                "v2_findings",
                "v2_analysis_reports",
                "v2_finding_events",
                "v2_response_batches",
                "v2_responses",
                "v2_delivery_acks",
                "v2_outbox",
                "v2_exchange_messages",
                "v2_audit_events",
            )
            for table in immutable_tables:
                self._connection.executescript(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_update
                    BEFORE UPDATE ON {table}
                    BEGIN
                        SELECT RAISE(ABORT, '{table} is append-only');
                    END;
                    CREATE TRIGGER IF NOT EXISTS {table}_no_delete
                    BEFORE DELETE ON {table}
                    BEGIN
                        SELECT RAISE(ABORT, '{table} is append-only');
                    END;
                    """
                )

    # ------------------------------------------------------------------
    # Machine write paths

    def claim_transport_nonce(
        self,
        sender_id: str,
        nonce: str,
        *,
        request_time: datetime,
        expires_at: datetime,
    ) -> bool:
        """Atomically persist an HTTP nonce; return ``False`` on replay."""

        if not sender_id.strip() or not nonce.strip():
            raise ValueError("sender_id and nonce are required")
        requested = _as_utc(request_time)
        expiry = _as_utc(expires_at)
        current = _as_utc(self._now())
        if expiry <= requested or expiry <= current:
            raise ValueError("nonce expiry must be after request time and current time")
        with self._transaction() as connection:
            connection.execute(
                "DELETE FROM v2_transport_nonces WHERE expires_at <= ?",
                (current.isoformat(),),
            )
            try:
                connection.execute(
                    """
                    INSERT INTO v2_transport_nonces(
                        sender_id, nonce, request_time, expires_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        sender_id,
                        nonce,
                        requested.isoformat(),
                        expiry.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def bind_agent_to_mine(self, agent_id: str, mine_id: str) -> None:
        """Permanently bind one enterprise-agent identity to one mine."""

        if not agent_id.strip() or not mine_id.strip():
            raise ValueError("agent_id and mine_id are required")
        timestamp = self._timestamp()
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT mine_id FROM v2_agent_mine_bindings WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if existing is not None:
                if existing["mine_id"] != mine_id:
                    raise RegulatoryV2ConflictError(
                        "one enterprise agent cannot submit for multiple mines"
                    )
                return
            try:
                connection.execute(
                    """
                    INSERT INTO v2_agent_mine_bindings(agent_id, mine_id, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (agent_id, mine_id, timestamp),
                )
            except sqlite3.IntegrityError as error:
                raise RegulatoryV2ConflictError(
                    "one mine can be bound to only one enterprise agent"
                ) from error
            self._append_audit(
                connection,
                event_type="agent_mine_bound",
                aggregate_type="agent_binding",
                aggregate_id=agent_id,
                mine_id=mine_id,
                payload={"agent_id": agent_id, "mine_id": mine_id},
                occurred_at=timestamp,
            )

    def record_exchange_message(
        self,
        message: ExchangeMessageInput,
    ) -> ExchangeMessageProjection:
        """Record the complete signed wire body without interpreting it.

        The raw envelope is retained alongside, rather than replaced by, the
        normalized algorithm payload.  Replaying the same ID and bytes is
        idempotent; reusing an ID for different bytes is rejected.
        """

        recorded_at = self._timestamp()
        with self._transaction() as connection:
            projection, replay = self._insert_exchange_message(
                connection, message, recorded_at=recorded_at
            )
            if not replay:
                self._append_audit(
                    connection,
                    event_type=f"exchange_{message.direction}_recorded",
                    aggregate_type="exchange_message",
                    aggregate_id=message.message_id,
                    mine_id=message.mine_id,
                    payload={
                        "message_type": message.message_type,
                        "direction": message.direction,
                        "body_sha256": projection.body_sha256,
                    },
                    occurred_at=recorded_at,
                )
            return projection

    def submit_and_analyze(
        self,
        submission: FiveQuantitySubmission,
        *,
        agent_id: str | None = None,
        idempotency_key: str | None = None,
        exchange_message: ExchangeMessageInput | None = None,
        parameters: RegulatoryFiveQuantityParameters | None = None,
    ) -> SubmissionReceipt:
        """Persist, automatically analyse, issue a finding, and audit atomically."""

        parameters = parameters or RegulatoryFiveQuantityParameters()
        payload = submission.model_dump(mode="json")
        payload_json = _canonical_json(payload)
        payload_sha256 = _hash_text(payload_json)
        idempotency_key = idempotency_key or submission.submission_id
        received_instant = _as_utc(self._now())
        if submission.period_end > received_instant.astimezone(
            ZoneInfo(submission.reporting_timezone)
        ).date():
            raise RegulatoryV2ConflictError(
                "future reporting periods cannot enter regulatory history"
            )
        timestamp = received_instant.isoformat()

        with self._transaction() as connection:
            if agent_id is not None:
                self._assert_agent_mine(connection, agent_id, submission.mine_id)
            command_body_sha256: str | None = None
            if agent_id is not None and exchange_message is not None:
                command_body_sha256 = _hash_text(
                    _canonical_json(exchange_message.body)
                )
                claimed = self._find_inbox_command(
                    connection,
                    sender_id=agent_id,
                    idempotency_key=idempotency_key,
                    message_id=exchange_message.message_id,
                    message_type=exchange_message.message_type,
                    mine_id=submission.mine_id,
                    body_sha256=command_body_sha256,
                    occurred_at=timestamp,
                )
                if claimed is not None:
                    if claimed["result_kind"] != "submission":
                        raise RegulatoryV2ConflictError(
                            "idempotency key belongs to another command type"
                        )
                    return self._receipt_for_submission(
                        connection, claimed["result_id"], replay=True
                    )
            if exchange_message is not None:
                if exchange_message.direction != "inbound":
                    raise ValueError("submission exchange message must be inbound")
                if exchange_message.mine_id != submission.mine_id:
                    raise RegulatoryV2ConflictError(
                        "exchange envelope mine_id differs from normalized payload"
                    )
                if (
                    agent_id is not None
                    and exchange_message.agent_id is not None
                    and exchange_message.agent_id != agent_id
                ):
                    raise RegulatoryV2ConflictError(
                        "exchange envelope agent_id differs from authenticated agent"
                    )
                exchange_projection, exchange_replay = self._insert_exchange_message(
                    connection, exchange_message, recorded_at=timestamp
                )
                if not exchange_replay:
                    self._append_audit(
                        connection,
                        event_type="exchange_inbound_recorded",
                        aggregate_type="exchange_message",
                        aggregate_id=exchange_message.message_id,
                        mine_id=exchange_message.mine_id,
                        payload={
                            "message_type": exchange_message.message_type,
                            "body_sha256": exchange_projection.body_sha256,
                        },
                        occurred_at=timestamp,
                    )
            existing = connection.execute(
                """
                SELECT submission_id, payload_sha256
                FROM v2_submissions
                WHERE submission_id = ? OR (mine_id = ? AND idempotency_key = ?)
                """,
                (submission.submission_id, submission.mine_id, idempotency_key),
            ).fetchone()
            if existing is not None:
                if (
                    existing["submission_id"] != submission.submission_id
                    or existing["payload_sha256"] != payload_sha256
                ):
                    raise RegulatoryV2ConflictError(
                        "submission/idempotency key was already used with another payload"
                    )
                if command_body_sha256 is not None and agent_id is not None:
                    self._insert_inbox_command(
                        connection,
                        sender_id=agent_id,
                        idempotency_key=idempotency_key,
                        message_id=exchange_message.message_id,
                        message_type=exchange_message.message_type,
                        mine_id=submission.mine_id,
                        body_sha256=command_body_sha256,
                        result_kind="submission",
                        result_id=submission.submission_id,
                        recorded_at=timestamp,
                    )
                return self._receipt_for_submission(
                    connection, submission.submission_id, replay=True
                )

            predecessor = self._validate_revision(connection, submission)
            reporting_month = submission.period_start.strftime("%Y-%m")
            root_workflow_id = (
                submission.submission_id
                if predecessor is None
                else (
                    predecessor["root_workflow_id"]
                    or predecessor["submission_id"]
                )
            )
            try:
                connection.execute(
                    """
                    INSERT INTO v2_submissions(
                        submission_id, mine_id, mine_name, revision,
                        supersedes_submission_id, reporting_month,
                        root_workflow_id, period_start, period_end,
                        comparison_group, idempotency_key, payload_json,
                        payload_sha256, received_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        submission.submission_id,
                        submission.mine_id,
                        submission.mine_name,
                        submission.revision,
                        submission.supersedes_submission_id,
                        reporting_month,
                        root_workflow_id,
                        submission.period_start.isoformat(),
                        submission.period_end.isoformat(),
                        submission.comparison_context.group_key,
                        idempotency_key,
                        payload_json,
                        payload_sha256,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise RegulatoryV2ConflictError(str(error)) from error

            normalized_days = _normalized_days(submission)
            for item in normalized_days:
                normalized_json = _canonical_json(item)
                connection.execute(
                    """
                    INSERT INTO v2_daily_facts(
                        submission_id, observed_date, normalized_json,
                        normalized_sha256
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        submission.submission_id,
                        item["date"],
                        normalized_json,
                        _hash_text(normalized_json),
                    ),
                )
            self._append_audit(
                connection,
                event_type="submission_received",
                aggregate_type="submission",
                aggregate_id=submission.submission_id,
                mine_id=submission.mine_id,
                payload={
                    "payload_sha256": payload_sha256,
                    "revision": submission.revision,
                    "supersedes_submission_id": submission.supersedes_submission_id,
                },
                occurred_at=timestamp,
            )

            analysis_started_at = self._timestamp()
            history = self._same_mine_history(
                connection,
                submission.mine_id,
                before=submission.period_start,
                excluded_submission_id=submission.submission_id,
                comparison_group=submission.comparison_context.group_key,
            )
            peer_bands = self._anonymous_peer_bands(
                connection,
                submission,
                parameters,
            )
            result = analyze_five_quantity(
                submission,
                history=history,
                peer_bands=peer_bands,
                parameters=parameters,
            )
            analysis_completed_at = self._timestamp()
            run_id = str(uuid4())
            result_json = _canonical_json(result.model_dump(mode="json"))
            connection.execute(
                """
                INSERT INTO v2_analysis_runs(
                    run_id, submission_id, mine_id, method_version, decision,
                    result_json, result_sha256, algorithm_input_sha256,
                    configuration_sha256, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    submission.submission_id,
                    submission.mine_id,
                    result.method_version,
                    result.decision.value,
                    result_json,
                    _hash_text(result_json),
                    result.algorithm_input_sha256,
                    result.configuration_sha256,
                    analysis_started_at,
                    analysis_completed_at,
                ),
            )
            self._append_audit(
                connection,
                event_type="analysis_completed",
                aggregate_type="analysis_run",
                aggregate_id=run_id,
                mine_id=submission.mine_id,
                payload={
                    "submission_id": submission.submission_id,
                    "decision": result.decision.value,
                    "result_sha256": _hash_text(result_json),
                    "algorithm_input_sha256": result.algorithm_input_sha256,
                    "configuration_sha256": result.configuration_sha256,
                },
                occurred_at=analysis_completed_at,
            )
            self._record_baseline_admission(
                connection,
                submission=submission,
                run_id=run_id,
                result=result,
                recorded_at=analysis_completed_at,
            )

            finding_ids: list[str] = []
            if result.decision is not DecisionStatus.NORMAL_CANDIDATE:
                for category, reasons in _finding_groups(result):
                    finding_ids.append(
                        self._issue_finding(
                            connection,
                            submission=submission,
                            run_id=run_id,
                            result=result,
                            category=category,
                            reasons=reasons,
                            issued_at=analysis_completed_at,
                        )
                    )
            elif predecessor is not None:
                self._resolve_predecessor_findings(
                    connection,
                    predecessor_submission_id=predecessor["submission_id"],
                    resolving_submission_id=submission.submission_id,
                    mine_id=submission.mine_id,
                    occurred_at=analysis_completed_at,
                )
            self._issue_analysis_report(
                connection,
                submission=submission,
                run_id=run_id,
                result=result,
                finding_ids=finding_ids,
                issued_at=analysis_completed_at,
            )

            if command_body_sha256 is not None and agent_id is not None:
                self._insert_inbox_command(
                    connection,
                    sender_id=agent_id,
                    idempotency_key=idempotency_key,
                    message_id=exchange_message.message_id,
                    message_type=exchange_message.message_type,
                    mine_id=submission.mine_id,
                    body_sha256=command_body_sha256,
                    result_kind="submission",
                    result_id=submission.submission_id,
                    recorded_at=timestamp,
                )

            return SubmissionReceipt(
                submission_id=submission.submission_id,
                run_id=run_id,
                mine_id=submission.mine_id,
                decision=result.decision,
                finding_id=finding_ids[0] if finding_ids else None,
                received_at=_parse_datetime(timestamp),
                payload_sha256=payload_sha256,
            )

    def record_enterprise_response(
        self,
        response: EnterpriseFindingResponse,
    ) -> ResponseReceipt:
        """Append an explanation without clearing or replacing the finding."""

        response_json = _canonical_json(response.model_dump(mode="json"))
        response_sha256 = _hash_text(response_json)
        timestamp = self._timestamp()
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT response_sha256, recorded_at
                FROM v2_responses WHERE response_id = ?
                """,
                (response.response_id,),
            ).fetchone()
            if existing is not None:
                if existing["response_sha256"] != response_sha256:
                    raise RegulatoryV2ConflictError(
                        "response_id was already used with another payload"
                    )
                return ResponseReceipt(
                    response_id=response.response_id,
                    finding_id=response.finding_id,
                    mine_id=response.mine_id,
                    recorded_at=_parse_datetime(existing["recorded_at"]),
                    idempotent_replay=True,
                )
            finding = connection.execute(
                "SELECT mine_id FROM v2_findings WHERE finding_id = ?",
                (response.finding_id,),
            ).fetchone()
            if finding is None:
                raise RegulatoryV2NotFoundError("finding not found")
            if finding["mine_id"] != response.mine_id:
                raise RegulatoryV2NotFoundError("finding not found in mine scope")
            connection.execute(
                """
                INSERT INTO v2_responses(
                    response_id, finding_id, mine_id, response_json,
                    response_sha256, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    response.response_id,
                    response.finding_id,
                    response.mine_id,
                    response_json,
                    response_sha256,
                    timestamp,
                ),
            )
            self._append_finding_event(
                connection,
                finding_id=response.finding_id,
                event_type="explanation_recorded",
                payload={
                    "response_id": response.response_id,
                    "response_sha256": response_sha256,
                    "risk_cleared": False,
                },
                occurred_at=timestamp,
            )
            self._append_outbox(
                connection,
                audience_mine_id=response.mine_id,
                kind="response_recorded",
                aggregate_id=response.response_id,
                payload={
                    "response_id": response.response_id,
                    "finding_id": response.finding_id,
                    "recorded_at": timestamp,
                    "finding_state": "explanation_recorded",
                    "risk_cleared": False,
                },
                created_at=timestamp,
            )
            self._append_audit(
                connection,
                event_type="enterprise_explanation_recorded",
                aggregate_type="finding_response",
                aggregate_id=response.response_id,
                mine_id=response.mine_id,
                payload={
                    "finding_id": response.finding_id,
                    "response_sha256": response_sha256,
                    "risk_cleared": False,
                },
                occurred_at=timestamp,
            )
            return ResponseReceipt(
                response_id=response.response_id,
                finding_id=response.finding_id,
                mine_id=response.mine_id,
                recorded_at=_parse_datetime(timestamp),
            )

    def record_enterprise_response_batch(
        self,
        wire_response_id: str,
        report_id: str,
        mine_id: str,
        responses: Sequence[EnterpriseFindingResponse],
        *,
        exchange_message: ExchangeMessageInput | None = None,
        sender_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> ResponseBatchReceipt:
        """Atomically record every per-finding item from one wire response."""

        if not 1 <= len(responses) <= 100:
            raise ValueError("responses must contain between 1 and 100 items")
        finding_ids = [item.finding_id for item in responses]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("a response batch cannot repeat a finding_id")
        if any(item.mine_id != mine_id for item in responses):
            raise RegulatoryV2ConflictError(
                "response batch cannot cross mine boundaries"
            )
        request_payload = {
            "wire_response_id": wire_response_id,
            "report_id": report_id,
            "mine_id": mine_id,
            "responses": [
                item.model_dump(mode="json", exclude={"response_id"})
                for item in responses
            ],
        }
        request_json = _canonical_json(request_payload)
        request_sha256 = _hash_text(request_json)
        timestamp = self._timestamp()
        idempotency_key = idempotency_key or wire_response_id

        with self._transaction() as connection:
            if sender_id is not None:
                self._assert_agent_mine(connection, sender_id, mine_id)
            command_body_sha256: str | None = None
            if sender_id is not None and exchange_message is not None:
                command_body_sha256 = _hash_text(
                    _canonical_json(exchange_message.body)
                )
                claimed = self._find_inbox_command(
                    connection,
                    sender_id=sender_id,
                    idempotency_key=idempotency_key,
                    message_id=exchange_message.message_id,
                    message_type=exchange_message.message_type,
                    mine_id=mine_id,
                    body_sha256=command_body_sha256,
                    occurred_at=timestamp,
                )
                if claimed is not None:
                    if claimed["result_kind"] != "response_batch":
                        raise RegulatoryV2ConflictError(
                            "idempotency key belongs to another command type"
                        )
                    return self._response_batch_receipt(
                        connection, claimed["result_id"], replay=True
                    )
            if exchange_message is not None:
                if (
                    exchange_message.direction != "inbound"
                    or exchange_message.mine_id != mine_id
                ):
                    raise RegulatoryV2ConflictError(
                        "response exchange envelope scope is invalid"
                    )
                projection, replay = self._insert_exchange_message(
                    connection, exchange_message, recorded_at=timestamp
                )
                if not replay:
                    self._append_audit(
                        connection,
                        event_type="exchange_inbound_recorded",
                        aggregate_type="exchange_message",
                        aggregate_id=exchange_message.message_id,
                        mine_id=mine_id,
                        payload={
                            "message_type": exchange_message.message_type,
                            "body_sha256": projection.body_sha256,
                        },
                        occurred_at=timestamp,
                    )
            existing = connection.execute(
                """
                SELECT * FROM v2_response_batches WHERE wire_response_id = ?
                """,
                (wire_response_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["request_sha256"] != request_sha256
                    or existing["report_id"] != report_id
                    or existing["mine_id"] != mine_id
                ):
                    raise RegulatoryV2ConflictError(
                        "wire response ID was already used with another batch"
                    )
                if command_body_sha256 is not None and sender_id is not None:
                    self._insert_inbox_command(
                        connection,
                        sender_id=sender_id,
                        idempotency_key=idempotency_key,
                        message_id=exchange_message.message_id,
                        message_type=exchange_message.message_type,
                        mine_id=mine_id,
                        body_sha256=command_body_sha256,
                        result_kind="response_batch",
                        result_id=wire_response_id,
                        recorded_at=timestamp,
                    )
                return self._response_batch_receipt(
                    connection, wire_response_id, replay=True
                )

            report_row = connection.execute(
                """
                SELECT mine_id, report_json FROM v2_analysis_reports
                WHERE report_id = ?
                """,
                (report_id,),
            ).fetchone()
            if report_row is None or report_row["mine_id"] != mine_id:
                raise RegulatoryV2NotFoundError(
                    "analysis report not found in mine scope"
                )
            report_finding_ids = set(
                json.loads(report_row["report_json"])["finding_ids"]
            )
            if not set(finding_ids) <= report_finding_ids:
                raise RegulatoryV2ConflictError(
                    "one or more findings do not belong to the analysis report"
                )
            connection.execute(
                """
                INSERT INTO v2_response_batches(
                    wire_response_id, report_id, mine_id, request_json,
                    request_sha256, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    wire_response_id,
                    report_id,
                    mine_id,
                    request_json,
                    request_sha256,
                    timestamp,
                ),
            )
            child_ids: list[str] = []
            for response in responses:
                finding = connection.execute(
                    "SELECT mine_id FROM v2_findings WHERE finding_id = ?",
                    (response.finding_id,),
                ).fetchone()
                if finding is None or finding["mine_id"] != mine_id:
                    raise RegulatoryV2NotFoundError(
                        "finding not found in report/mine scope"
                    )
                child_id = str(
                    uuid5(
                        NAMESPACE_URL,
                        f"mineguard:v2:{wire_response_id}:{response.finding_id}",
                    )
                )
                child = response.model_copy(update={"response_id": child_id})
                child_json = _canonical_json(child.model_dump(mode="json"))
                child_sha256 = _hash_text(child_json)
                connection.execute(
                    """
                    INSERT INTO v2_responses(
                        response_id, finding_id, mine_id, wire_response_id,
                        response_json, response_sha256, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        child_id,
                        child.finding_id,
                        mine_id,
                        wire_response_id,
                        child_json,
                        child_sha256,
                        timestamp,
                    ),
                )
                self._append_finding_event(
                    connection,
                    finding_id=child.finding_id,
                    event_type="explanation_recorded",
                    payload={
                        "wire_response_id": wire_response_id,
                        "child_response_id": child_id,
                        "response_sha256": child_sha256,
                        "risk_cleared": False,
                    },
                    occurred_at=timestamp,
                )
                child_ids.append(child_id)

            self._append_outbox(
                connection,
                audience_mine_id=mine_id,
                kind="response_recorded",
                aggregate_id=wire_response_id,
                payload={
                    "wire_response_id": wire_response_id,
                    "report_id": report_id,
                    "finding_ids": finding_ids,
                    "child_response_ids": child_ids,
                    "recorded_at": timestamp,
                    "finding_state": "explanation_recorded",
                    "risk_cleared": False,
                },
                created_at=timestamp,
            )
            self._append_audit(
                connection,
                event_type="enterprise_response_batch_recorded",
                aggregate_type="response_batch",
                aggregate_id=wire_response_id,
                mine_id=mine_id,
                payload={
                    "report_id": report_id,
                    "finding_ids": finding_ids,
                    "child_response_ids": child_ids,
                    "request_sha256": request_sha256,
                    "risk_cleared": False,
                },
                occurred_at=timestamp,
            )
            if command_body_sha256 is not None and sender_id is not None:
                self._insert_inbox_command(
                    connection,
                    sender_id=sender_id,
                    idempotency_key=idempotency_key,
                    message_id=exchange_message.message_id,
                    message_type=exchange_message.message_type,
                    mine_id=mine_id,
                    body_sha256=command_body_sha256,
                    result_kind="response_batch",
                    result_id=wire_response_id,
                    recorded_at=timestamp,
                )
            return ResponseBatchReceipt(
                wire_response_id=wire_response_id,
                report_id=report_id,
                mine_id=mine_id,
                child_response_ids=child_ids,
                finding_ids=finding_ids,
                recorded_at=_parse_datetime(timestamp),
            )

    def record_delivery_ack(
        self,
        ack: AnalysisReportDeliveryAck,
        *,
        exchange_message: ExchangeMessageInput | None = None,
        sender_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> DeliveryAckReceipt:
        """Append an enterprise acknowledgement; it has no decision effect."""

        ack_json = _canonical_json(ack.model_dump(mode="json"))
        ack_sha256 = _hash_text(ack_json)
        timestamp = self._timestamp()
        idempotency_key = idempotency_key or ack.ack_id
        with self._transaction() as connection:
            if sender_id is not None:
                self._assert_agent_mine(connection, sender_id, ack.mine_id)
            command_body_sha256: str | None = None
            if sender_id is not None and exchange_message is not None:
                command_body_sha256 = _hash_text(
                    _canonical_json(exchange_message.body)
                )
                claimed = self._find_inbox_command(
                    connection,
                    sender_id=sender_id,
                    idempotency_key=idempotency_key,
                    message_id=exchange_message.message_id,
                    message_type=exchange_message.message_type,
                    mine_id=ack.mine_id,
                    body_sha256=command_body_sha256,
                    occurred_at=timestamp,
                )
                if claimed is not None:
                    if claimed["result_kind"] != "delivery_ack":
                        raise RegulatoryV2ConflictError(
                            "idempotency key belongs to another command type"
                        )
                    return self._delivery_ack_receipt(
                        connection, claimed["result_id"], replay=True
                    )
            if exchange_message is not None:
                if (
                    exchange_message.direction != "inbound"
                    or exchange_message.mine_id != ack.mine_id
                    or (
                        sender_id is not None
                        and exchange_message.agent_id is not None
                        and exchange_message.agent_id != sender_id
                    )
                ):
                    raise RegulatoryV2ConflictError(
                        "ack exchange envelope scope is invalid"
                    )
                projection, replay = self._insert_exchange_message(
                    connection, exchange_message, recorded_at=timestamp
                )
                if not replay:
                    self._append_audit(
                        connection,
                        event_type="exchange_inbound_recorded",
                        aggregate_type="exchange_message",
                        aggregate_id=exchange_message.message_id,
                        mine_id=ack.mine_id,
                        payload={
                            "message_type": exchange_message.message_type,
                            "body_sha256": projection.body_sha256,
                        },
                        occurred_at=timestamp,
                    )
            existing = connection.execute(
                "SELECT ack_sha256, recorded_at FROM v2_delivery_acks WHERE ack_id = ?",
                (ack.ack_id,),
            ).fetchone()
            if existing is not None:
                if existing["ack_sha256"] != ack_sha256:
                    raise RegulatoryV2ConflictError(
                        "ack_id was already used with another payload"
                    )
                if command_body_sha256 is not None and sender_id is not None:
                    self._insert_inbox_command(
                        connection,
                        sender_id=sender_id,
                        idempotency_key=idempotency_key,
                        message_id=exchange_message.message_id,
                        message_type=exchange_message.message_type,
                        mine_id=ack.mine_id,
                        body_sha256=command_body_sha256,
                        result_kind="delivery_ack",
                        result_id=ack.ack_id,
                        recorded_at=timestamp,
                    )
                return self._delivery_ack_receipt(
                    connection, ack.ack_id, replay=True
                )
            report = connection.execute(
                """
                SELECT mine_id, report_json FROM v2_analysis_reports
                WHERE report_id = ?
                """,
                (ack.report_id,),
            ).fetchone()
            outbox = connection.execute(
                """
                SELECT sequence, audience_mine_id, kind, aggregate_id
                FROM v2_outbox WHERE message_id = ?
                """,
                (ack.analysis_report_message_id,),
            ).fetchone()
            if (
                report is None
                or outbox is None
                or report["mine_id"] != ack.mine_id
                or outbox["audience_mine_id"] != ack.mine_id
                or outbox["kind"] != "analysis_report_available"
                or outbox["aggregate_id"] != ack.report_id
                or (
                    report is not None
                    and json.loads(report["report_json"])["delivery_cursor"]
                    != ack.delivery_cursor
                )
            ):
                raise RegulatoryV2NotFoundError(
                    "analysis report delivery message not found in mine scope"
                )
            connection.execute(
                """
                INSERT INTO v2_delivery_acks(
                    ack_id, report_id, mine_id, analysis_report_message_id,
                    ack_json, ack_sha256, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ack.ack_id,
                    ack.report_id,
                    ack.mine_id,
                    ack.analysis_report_message_id,
                    ack_json,
                    ack_sha256,
                    timestamp,
                ),
            )
            self._append_audit(
                connection,
                event_type="analysis_report_delivery_acknowledged",
                aggregate_type="analysis_report",
                aggregate_id=ack.report_id,
                mine_id=ack.mine_id,
                payload={
                    "ack_id": ack.ack_id,
                    "analysis_report_message_id": ack.analysis_report_message_id,
                    "delivery_cursor": ack.delivery_cursor,
                    "delivery_status": ack.delivery_status,
                    "ack_sha256": ack_sha256,
                },
                occurred_at=timestamp,
            )
            if command_body_sha256 is not None and sender_id is not None:
                self._insert_inbox_command(
                    connection,
                    sender_id=sender_id,
                    idempotency_key=idempotency_key,
                    message_id=exchange_message.message_id,
                    message_type=exchange_message.message_type,
                    mine_id=ack.mine_id,
                    body_sha256=command_body_sha256,
                    result_kind="delivery_ack",
                    result_id=ack.ack_id,
                    recorded_at=timestamp,
                )
            return DeliveryAckReceipt(
                ack_id=ack.ack_id,
                report_id=ack.report_id,
                mine_id=ack.mine_id,
                recorded_at=_parse_datetime(timestamp),
            )

    # ------------------------------------------------------------------
    # Read-only business projections

    def get_submission(self, submission_id: str) -> FiveQuantitySubmission:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM v2_submissions WHERE submission_id = ?",
                (submission_id,),
            ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError("submission not found")
        return FiveQuantitySubmission.model_validate_json(row["payload_json"])

    def get_submission_receipt(
        self,
        submission_id: str,
        *,
        mine_id: str | None = None,
    ) -> SubmissionReceipt:
        with self._lock:
            if mine_id is not None:
                scoped = self._connection.execute(
                    """
                    SELECT 1 FROM v2_submissions
                    WHERE submission_id = ? AND mine_id = ?
                    """,
                    (submission_id, mine_id),
                ).fetchone()
                if scoped is None:
                    raise RegulatoryV2NotFoundError(
                        "submission receipt not found in mine scope"
                    )
            return self._receipt_for_submission(
                self._connection, submission_id, replay=False
            )

    def get_response_receipt(
        self,
        response_id: str,
        *,
        mine_id: str | None = None,
    ) -> ResponseReceipt:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT response_id, finding_id, mine_id, recorded_at
                FROM v2_responses WHERE response_id = ?
                """,
                (response_id,),
            ).fetchone()
        if row is None or (mine_id is not None and row["mine_id"] != mine_id):
            raise RegulatoryV2NotFoundError("response receipt not found in mine scope")
        return ResponseReceipt(
            response_id=row["response_id"],
            finding_id=row["finding_id"],
            mine_id=row["mine_id"],
            recorded_at=_parse_datetime(row["recorded_at"]),
        )

    def get_response_batch_receipt(
        self,
        wire_response_id: str,
        *,
        mine_id: str | None = None,
    ) -> ResponseBatchReceipt:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM v2_response_batches WHERE wire_response_id = ?
                """,
                (wire_response_id,),
            ).fetchone()
            if row is None or (mine_id is not None and row["mine_id"] != mine_id):
                raise RegulatoryV2NotFoundError(
                    "response batch receipt not found in mine scope"
                )
            children = self._connection.execute(
                """
                SELECT response_id, finding_id FROM v2_responses
                WHERE wire_response_id = ? ORDER BY response_id
                """,
                (wire_response_id,),
            ).fetchall()
        return ResponseBatchReceipt(
            wire_response_id=row["wire_response_id"],
            report_id=row["report_id"],
            mine_id=row["mine_id"],
            child_response_ids=[item["response_id"] for item in children],
            finding_ids=[item["finding_id"] for item in children],
            recorded_at=_parse_datetime(row["recorded_at"]),
        )

    def get_delivery_ack_receipt(
        self,
        ack_id: str,
        *,
        mine_id: str | None = None,
    ) -> DeliveryAckReceipt:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT ack_id, report_id, mine_id, recorded_at
                FROM v2_delivery_acks WHERE ack_id = ?
                """,
                (ack_id,),
            ).fetchone()
        if row is None or (mine_id is not None and row["mine_id"] != mine_id):
            raise RegulatoryV2NotFoundError("delivery ack not found in mine scope")
        return DeliveryAckReceipt(
            ack_id=row["ack_id"],
            report_id=row["report_id"],
            mine_id=row["mine_id"],
            recorded_at=_parse_datetime(row["recorded_at"]),
        )

    def list_submissions(
        self,
        *,
        mine_id: str | None = None,
        before_received_at: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        limit = _validated_limit(limit)
        clauses: list[str] = []
        values: list[Any] = []
        if mine_id is not None:
            clauses.append("mine_id = ?")
            values.append(mine_id)
        if before_received_at is not None:
            clauses.append("received_at < ?")
            values.append(_as_utc(before_received_at).isoformat())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT submission_id, mine_id, mine_name, revision,
                       supersedes_submission_id, period_start, period_end,
                       payload_sha256, received_at
                FROM v2_submissions{where}
                ORDER BY period_end DESC, period_start DESC, revision DESC,
                         received_at DESC, submission_id DESC LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> RegulatoryFiveQuantityResult:
        with self._lock:
            row = self._connection.execute(
                "SELECT result_json FROM v2_analysis_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError("analysis run not found")
        return RegulatoryFiveQuantityResult.model_validate_json(row["result_json"])

    def get_run_metadata(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT run_id, submission_id, mine_id, method_version, decision,
                       result_sha256, algorithm_input_sha256,
                       configuration_sha256, started_at, completed_at
                FROM v2_analysis_runs WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError("analysis run not found")
        value = dict(row)
        value["started_at"] = value["started_at"] or value["completed_at"]
        return value

    def get_analysis_report(
        self,
        report_id: str,
        *,
        mine_id: str | None = None,
    ) -> AnalysisReport:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT mine_id, report_json FROM v2_analysis_reports
                WHERE report_id = ?
                """,
                (report_id,),
            ).fetchone()
        if row is None or (mine_id is not None and row["mine_id"] != mine_id):
            raise RegulatoryV2NotFoundError("analysis report not found in mine scope")
        return AnalysisReport.model_validate_json(row["report_json"])

    def list_analysis_reports(
        self,
        *,
        mine_id: str | None = None,
        limit: int = 100,
    ) -> list[AnalysisReport]:
        limit = _validated_limit(limit)
        where = " WHERE mine_id = ?" if mine_id is not None else ""
        values: tuple[Any, ...] = (mine_id, limit) if mine_id is not None else (limit,)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT report_json FROM v2_analysis_reports{where}
                ORDER BY issued_at DESC, report_id DESC LIMIT ?
                """,
                values,
            ).fetchall()
        return [AnalysisReport.model_validate_json(row["report_json"]) for row in rows]

    def list_runs(
        self,
        *,
        mine_id: str | None = None,
        decision: DecisionStatus | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        limit = _validated_limit(limit)
        clauses: list[str] = []
        values: list[Any] = []
        if mine_id is not None:
            clauses.append("r.mine_id = ?")
            values.append(mine_id)
        if decision is not None:
            clauses.append("r.decision = ?")
            values.append(decision.value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT r.run_id, r.submission_id, r.mine_id, r.method_version,
                       r.decision, r.result_sha256, r.algorithm_input_sha256,
                       r.configuration_sha256, r.started_at, r.completed_at,
                       b.eligible AS baseline_eligible,
                       b.reference_candidate AS baseline_reference_candidate,
                       b.rule_version AS baseline_rule_version,
                       b.reasons_sha256 AS baseline_reasons_sha256
                FROM v2_analysis_runs r
                LEFT JOIN v2_baseline_admissions b ON b.run_id = r.run_id
                {where}
                ORDER BY r.completed_at DESC, r.run_id DESC LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_finding(
        self,
        finding_id: str,
        *,
        mine_id: str | None = None,
    ) -> FindingProjection:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM v2_findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if row is None or (mine_id is not None and row["mine_id"] != mine_id):
                raise RegulatoryV2NotFoundError("finding not found")
            event_rows = self._connection.execute(
                """
                SELECT event_type, payload_json FROM v2_finding_events
                WHERE finding_id = ? ORDER BY sequence
                """,
                (finding_id,),
            ).fetchall()
            response_rows = self._connection.execute(
                """
                SELECT response_json FROM v2_responses
                WHERE finding_id = ? ORDER BY recorded_at, response_id
                """,
                (finding_id,),
            ).fetchall()
        state: Literal["open", "explanation_recorded", "cleared_by_reanalysis"] = "open"
        resolved_by: str | None = None
        for event in event_rows:
            if event["event_type"] == "explanation_recorded" and state == "open":
                state = "explanation_recorded"
            elif event["event_type"] == "resolved_by_revision":
                state = "cleared_by_reanalysis"
                resolved_by = json.loads(event["payload_json"])[
                    "resolving_submission_id"
                ]
        return FindingProjection(
            finding=RiskFindingReport.model_validate_json(row["report_json"]),
            state=state,
            responses=[
                EnterpriseFindingResponse.model_validate_json(item["response_json"])
                for item in response_rows
            ],
            resolved_by_submission_id=resolved_by,
            event_count=len(event_rows),
        )

    def list_findings(
        self,
        *,
        mine_id: str | None = None,
        include_resolved: bool = True,
        limit: int = 100,
    ) -> list[FindingProjection]:
        limit = _validated_limit(limit)
        where = " WHERE mine_id = ?" if mine_id is not None else ""
        values: tuple[Any, ...] = (mine_id, limit) if mine_id is not None else (limit,)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT finding_id FROM v2_findings{where}
                ORDER BY issued_at DESC, finding_id DESC LIMIT ?
                """,
                values,
            ).fetchall()
        projections = [
            self.get_finding(row["finding_id"], mine_id=mine_id) for row in rows
        ]
        if include_resolved:
            return projections
        return [item for item in projections if item.state != "cleared_by_reanalysis"]

    def list_responses(
        self,
        *,
        mine_id: str | None = None,
        finding_id: str | None = None,
        limit: int = 100,
    ) -> list[EnterpriseFindingResponse]:
        limit = _validated_limit(limit)
        clauses: list[str] = []
        values: list[Any] = []
        if mine_id is not None:
            clauses.append("mine_id = ?")
            values.append(mine_id)
        if finding_id is not None:
            clauses.append("finding_id = ?")
            values.append(finding_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT response_json FROM v2_responses{where}
                ORDER BY recorded_at DESC, response_id DESC LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [
            EnterpriseFindingResponse.model_validate_json(row["response_json"])
            for row in rows
        ]

    def list_daily_facts(
        self,
        mine_id: str,
        *,
        date_from: date | None = None,
        date_to: date | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        limit = _validated_limit(limit)
        clauses = ["s.mine_id = ?"]
        values: list[Any] = [mine_id]
        if date_from is not None:
            clauses.append("d.observed_date >= ?")
            values.append(date_from.isoformat())
        if date_to is not None:
            clauses.append("d.observed_date <= ?")
            values.append(date_to.isoformat())
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT d.submission_id, d.observed_date, d.normalized_json,
                       d.normalized_sha256, s.revision, r.decision
                FROM v2_daily_facts d
                JOIN v2_submissions s ON s.submission_id = d.submission_id
                JOIN v2_analysis_runs r ON r.submission_id = s.submission_id
                WHERE {" AND ".join(clauses)}
                  AND NOT EXISTS (
                      SELECT 1 FROM v2_submissions newer
                      WHERE newer.supersedes_submission_id = s.submission_id
                  )
                ORDER BY d.observed_date DESC, s.revision DESC LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [
            {
                "submission_id": row["submission_id"],
                "date": row["observed_date"],
                "revision": row["revision"],
                "decision": row["decision"],
                "normalized_sha256": row["normalized_sha256"],
                **_canonical_daily_payload(json.loads(row["normalized_json"])),
            }
            for row in rows
        ]

    def list_exchange_messages(
        self,
        *,
        mine_id: str | None = None,
        direction: Literal["inbound", "outbound"] | None = None,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> list[ExchangeMessageProjection]:
        limit = _validated_limit(limit)
        clauses = ["sequence > ?"]
        values: list[Any] = [after_sequence]
        if mine_id is not None:
            clauses.append("mine_id = ?")
            values.append(mine_id)
        if direction is not None:
            clauses.append("direction = ?")
            values.append(direction)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM v2_exchange_messages
                WHERE {" AND ".join(clauses)}
                ORDER BY sequence LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [_exchange_from_row(row) for row in rows]

    def get_exchange_message(
        self,
        message_id: str,
        *,
        mine_id: str | None = None,
        direction: Literal["inbound", "outbound"] | None = None,
    ) -> ExchangeMessageProjection:
        clauses = ["message_id = ?"]
        values: list[Any] = [message_id]
        if mine_id is not None:
            clauses.append("mine_id = ?")
            values.append(mine_id)
        if direction is not None:
            clauses.append("direction = ?")
            values.append(direction)
        with self._lock:
            row = self._connection.execute(
                f"SELECT * FROM v2_exchange_messages WHERE {' AND '.join(clauses)}",
                values,
            ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError(
                "signed exchange message not found in mine scope"
            )
        return _exchange_from_row(row)

    def is_strict_submission_descendant(
        self,
        candidate_submission_id: str,
        ancestor_submission_id: str,
        *,
        mine_id: str,
    ) -> bool:
        """Return whether candidate is a higher-revision descendant of ancestor."""

        if candidate_submission_id == ancestor_submission_id:
            return False
        with self._lock:
            candidate = self._connection.execute(
                """
                SELECT submission_id, mine_id, revision, supersedes_submission_id
                FROM v2_submissions WHERE submission_id = ? AND mine_id = ?
                """,
                (candidate_submission_id, mine_id),
            ).fetchone()
            ancestor = self._connection.execute(
                """
                SELECT submission_id, revision FROM v2_submissions
                WHERE submission_id = ? AND mine_id = ?
                """,
                (ancestor_submission_id, mine_id),
            ).fetchone()
            if candidate is None or ancestor is None:
                return False
            if candidate["revision"] <= ancestor["revision"]:
                return False
            current = candidate
            visited: set[str] = set()
            while current["supersedes_submission_id"] is not None:
                predecessor_id = current["supersedes_submission_id"]
                if predecessor_id == ancestor_submission_id:
                    return True
                if predecessor_id in visited:
                    return False
                visited.add(predecessor_id)
                current = self._connection.execute(
                    """
                    SELECT submission_id, mine_id, revision,
                           supersedes_submission_id
                    FROM v2_submissions
                    WHERE submission_id = ? AND mine_id = ?
                    """,
                    (predecessor_id, mine_id),
                ).fetchone()
                if current is None:
                    return False
        return False

    def list_mine_overviews(self) -> list[MineOverview]:
        with self._lock:
            mine_rows = self._connection.execute(
                """
                SELECT mines.mine_id,
                       (
                           SELECT s.mine_name FROM v2_submissions s
                           WHERE s.mine_id = mines.mine_id
                           ORDER BY s.period_end DESC, s.revision DESC,
                                    s.received_at DESC LIMIT 1
                       ) AS mine_name
                FROM (SELECT DISTINCT mine_id FROM v2_submissions) mines
                ORDER BY mine_name, mine_id
                """
            ).fetchall()
        overviews: list[MineOverview] = []
        for mine in mine_rows:
            mine_id = mine["mine_id"]
            submissions = self.list_submissions(mine_id=mine_id, limit=1)
            latest_submission = submissions[0] if submissions else None
            with self._lock:
                latest_run_row = (
                    self._connection.execute(
                        """
                        SELECT run_id, submission_id, mine_id, method_version,
                               decision, result_sha256, algorithm_input_sha256,
                               configuration_sha256, completed_at
                        FROM v2_analysis_runs WHERE submission_id = ?
                        ORDER BY completed_at DESC, run_id DESC LIMIT 1
                        """,
                        (latest_submission["submission_id"],),
                    ).fetchone()
                    if latest_submission is not None
                    else None
                )
                latest_audit_row = self._connection.execute(
                    """
                    SELECT occurred_at FROM v2_audit_events
                    WHERE mine_id = ? ORDER BY sequence DESC LIMIT 1
                    """,
                    (mine_id,),
                ).fetchone()
                state_rows = self._connection.execute(
                    """
                    SELECT
                      EXISTS(
                        SELECT 1 FROM v2_finding_events e
                        WHERE e.finding_id = f.finding_id
                          AND e.event_type = 'resolved_by_revision'
                      ) AS cleared,
                      EXISTS(
                        SELECT 1 FROM v2_finding_events e
                        WHERE e.finding_id = f.finding_id
                          AND e.event_type = 'explanation_recorded'
                      ) AS explained
                    FROM v2_findings f WHERE f.mine_id = ?
                    """,
                    (mine_id,),
                ).fetchall()
            counts = {
                "open": sum(
                    not row["cleared"] and not row["explained"] for row in state_rows
                ),
                "explanation": sum(
                    not row["cleared"] and row["explained"] for row in state_rows
                ),
                "cleared": sum(bool(row["cleared"]) for row in state_rows),
            }
            latest_run = dict(latest_run_row) if latest_run_row is not None else None
            overviews.append(
                MineOverview(
                    mine_id=mine_id,
                    mine_name=mine["mine_name"],
                    latest_submission_id=(
                        latest_submission["submission_id"]
                        if latest_submission is not None
                        else None
                    ),
                    latest_period_end=(
                        date.fromisoformat(latest_submission["period_end"])
                        if latest_submission is not None
                        else None
                    ),
                    latest_decision=(
                        DecisionStatus(latest_run["decision"])
                        if latest_run is not None
                        else None
                    ),
                    open_finding_count=counts["open"],
                    explanation_recorded_finding_count=counts["explanation"],
                    cleared_finding_count=counts["cleared"],
                    latest_audit_at=(
                        _parse_datetime(latest_audit_row["occurred_at"])
                        if latest_audit_row is not None
                        else None
                    ),
                )
            )
        return overviews

    def mine_detail_projection(
        self,
        mine_id: str,
        *,
        limit: int = 100,
    ) -> MineDetailProjection:
        overview = next(
            (item for item in self.list_mine_overviews() if item.mine_id == mine_id),
            None,
        )
        if overview is None:
            raise RegulatoryV2NotFoundError("mine has no V2 submissions")
        return MineDetailProjection(
            overview=overview,
            submissions=self.list_submissions(mine_id=mine_id, limit=limit),
            runs=self.list_runs(mine_id=mine_id, limit=limit),
            analysis_reports=self.list_analysis_reports(mine_id=mine_id, limit=limit),
            findings=self.list_findings(mine_id=mine_id, limit=limit),
            daily_facts=self.list_daily_facts(mine_id, limit=min(limit * 31, 1000)),
            audit_events=self.list_audit_events(mine_id=mine_id, limit=limit),
        )

    def poll_outbox(
        self,
        mine_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> OutboxPage:
        if after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        limit = _validated_limit(limit)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT sequence, message_id, audience_mine_id, kind,
                       aggregate_id, payload_json, created_at
                FROM v2_outbox
                WHERE audience_mine_id = ? AND sequence > ?
                ORDER BY sequence LIMIT ?
                """,
                (mine_id, after_sequence, limit + 1),
            ).fetchall()
        selected = rows[:limit]
        items = [
            OutboxItem(
                sequence=row["sequence"],
                message_id=row["message_id"],
                audience_mine_id=row["audience_mine_id"],
                kind=row["kind"],
                aggregate_id=row["aggregate_id"],
                payload=json.loads(row["payload_json"]),
                created_at=_parse_datetime(row["created_at"]),
            )
            for row in selected
        ]
        return OutboxPage(
            items=items,
            next_cursor=items[-1].sequence if items else after_sequence,
            has_more=len(rows) > limit,
        )

    def poll_analysis_reports(
        self,
        mine_id: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> OutboxPage:
        """Enterprise pull projection containing only completed analysis reports."""

        if after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        limit = _validated_limit(limit)
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT sequence, message_id, audience_mine_id, kind,
                       aggregate_id, payload_json, created_at
                FROM v2_outbox
                WHERE audience_mine_id = ? AND sequence > ?
                  AND kind = 'analysis_report_available'
                ORDER BY sequence LIMIT ?
                """,
                (mine_id, after_sequence, limit + 1),
            ).fetchall()
        selected = rows[:limit]
        items = [
            OutboxItem(
                sequence=row["sequence"],
                message_id=row["message_id"],
                audience_mine_id=row["audience_mine_id"],
                kind=row["kind"],
                aggregate_id=row["aggregate_id"],
                payload=json.loads(row["payload_json"]),
                created_at=_parse_datetime(row["created_at"]),
            )
            for row in selected
        ]
        return OutboxPage(
            items=items,
            next_cursor=items[-1].sequence if items else after_sequence,
            has_more=len(rows) > limit,
        )

    def list_audit_events(
        self,
        *,
        after_sequence: int = 0,
        mine_id: str | None = None,
        limit: int = 100,
        newest_first: bool = False,
    ) -> list[AuditProjection]:
        limit = _validated_limit(limit)
        clauses = ["sequence > ?"]
        values: list[Any] = [after_sequence]
        if mine_id is not None:
            clauses.append("mine_id = ?")
            values.append(mine_id)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT * FROM v2_audit_events
                WHERE {" AND ".join(clauses)}
                ORDER BY sequence {"DESC" if newest_first else "ASC"} LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [
            AuditProjection(
                sequence=row["sequence"],
                event_id=row["event_id"],
                event_type=row["event_type"],
                aggregate_type=row["aggregate_type"],
                aggregate_id=row["aggregate_id"],
                mine_id=row["mine_id"],
                payload=json.loads(row["payload_json"]),
                occurred_at=_parse_datetime(row["occurred_at"]),
                previous_hash=row["previous_hash"],
                event_hash=row["event_hash"],
            )
            for row in rows
        ]

    def list_audit_events_page(
        self,
        *,
        mine_ids: Sequence[str] | None = None,
        event_types: Sequence[str] | None = None,
        occurred_from: datetime | None = None,
        occurred_before: datetime | None = None,
        snapshot_sequence: int | None = None,
        before_sequence: int | None = None,
        limit: int = 100,
    ) -> AuditPage:
        """Return a stable newest-first audit page for a filtered snapshot.

        The first call captures the ledger's current maximum sequence.  Pass
        the returned ``snapshot_sequence`` and ``next_before_sequence`` to the
        next call so events appended during browsing cannot move, duplicate or
        hide rows in the original result set.  The time range is half-open:
        ``[occurred_from, occurred_before)``.
        """

        limit = _validated_limit(limit)
        if snapshot_sequence is not None and snapshot_sequence < 0:
            raise ValueError("snapshot_sequence must be non-negative")
        if before_sequence is not None and before_sequence < 0:
            raise ValueError("before_sequence must be non-negative")

        occurred_from_utc = (
            _as_utc(occurred_from) if occurred_from is not None else None
        )
        occurred_before_utc = (
            _as_utc(occurred_before) if occurred_before is not None else None
        )
        if (
            occurred_from_utc is not None
            and occurred_before_utc is not None
            and occurred_from_utc >= occurred_before_utc
        ):
            raise ValueError("occurred_from must be before occurred_before")

        scoped_mines = None if mine_ids is None else tuple(dict.fromkeys(mine_ids))
        scoped_event_types = (
            None if event_types is None else tuple(dict.fromkeys(event_types))
        )

        with self._lock:
            if snapshot_sequence is None:
                snapshot_row = self._connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) AS sequence FROM v2_audit_events"
                ).fetchone()
                snapshot_sequence = int(snapshot_row["sequence"])

            # Empty permission/event scopes deliberately match nothing.  The
            # snapshot is still captured above so the response is complete and
            # can be handled exactly like any other first page.
            if scoped_mines == () or scoped_event_types == ():
                return AuditPage(
                    items=[],
                    snapshot_sequence=snapshot_sequence,
                    matched_count=0,
                    has_more=False,
                    next_before_sequence=None,
                )

            clauses = ["sequence <= ?"]
            values: list[Any] = [snapshot_sequence]
            if scoped_mines is not None:
                placeholders = ",".join("?" for _ in scoped_mines)
                clauses.append(f"mine_id IN ({placeholders})")
                values.extend(scoped_mines)
            if scoped_event_types is not None:
                placeholders = ",".join("?" for _ in scoped_event_types)
                clauses.append(f"event_type IN ({placeholders})")
                values.extend(scoped_event_types)
            if occurred_from_utc is not None:
                clauses.append("occurred_at >= ?")
                values.append(occurred_from_utc.isoformat())
            if occurred_before_utc is not None:
                clauses.append("occurred_at < ?")
                values.append(occurred_before_utc.isoformat())

            page_where = ""
            if before_sequence is not None:
                page_where = "WHERE sequence < ?"
                values.append(before_sequence)
            values.append(limit + 1)

            # The count and page share one filtered CTE and one SQLite
            # statement.  This keeps matched_count tied to the same immutable
            # snapshot even while another connection appends newer events.
            rows = self._connection.execute(
                f"""
                WITH filtered AS (
                    SELECT * FROM v2_audit_events
                    WHERE {" AND ".join(clauses)}
                ),
                matched AS (
                    SELECT COUNT(*) AS matched_count FROM filtered
                ),
                paged AS (
                    SELECT * FROM filtered
                    {page_where}
                    ORDER BY sequence DESC
                    LIMIT ?
                )
                SELECT
                    paged.sequence,
                    paged.event_id,
                    paged.event_type,
                    paged.aggregate_type,
                    paged.aggregate_id,
                    paged.mine_id,
                    paged.payload_json,
                    paged.occurred_at,
                    paged.previous_hash,
                    paged.event_hash,
                    matched.matched_count
                FROM matched
                LEFT JOIN paged ON 1 = 1
                ORDER BY paged.sequence DESC
                """,
                values,
            ).fetchall()

        matched_count = int(rows[0]["matched_count"]) if rows else 0
        item_rows = [row for row in rows if row["sequence"] is not None]
        has_more = len(item_rows) > limit
        selected = item_rows[:limit]
        items = [
            AuditProjection(
                sequence=row["sequence"],
                event_id=row["event_id"],
                event_type=row["event_type"],
                aggregate_type=row["aggregate_type"],
                aggregate_id=row["aggregate_id"],
                mine_id=row["mine_id"],
                payload=json.loads(row["payload_json"]),
                occurred_at=_parse_datetime(row["occurred_at"]),
                previous_hash=row["previous_hash"],
                event_hash=row["event_hash"],
            )
            for row in selected
        ]
        return AuditPage(
            items=items,
            snapshot_sequence=snapshot_sequence,
            matched_count=matched_count,
            has_more=has_more,
            next_before_sequence=(items[-1].sequence if has_more and items else None),
        )

    def finding_summary_counts(
        self,
        *,
        mine_ids: Sequence[str] | None = None,
    ) -> dict[str, int]:
        """Compute uncapped dashboard counts inside SQL and within mine scope."""

        if mine_ids is not None and not mine_ids:
            return {
                "open": 0,
                "explanation_recorded": 0,
                "cleared_by_reanalysis": 0,
                "risk": 0,
                "data_insufficient": 0,
            }
        values: list[Any] = []
        where = ""
        if mine_ids is not None:
            placeholders = ",".join("?" for _ in mine_ids)
            where = f"WHERE f.mine_id IN ({placeholders})"
            values.extend(mine_ids)
        with self._lock:
            row = self._connection.execute(
                f"""
                SELECT
                    SUM(CASE WHEN NOT EXISTS (
                        SELECT 1 FROM v2_finding_events e
                        WHERE e.finding_id = f.finding_id
                          AND e.event_type IN (
                              'explanation_recorded', 'resolved_by_revision'
                          )
                    ) THEN 1 ELSE 0 END) AS open_count,
                    SUM(CASE WHEN EXISTS (
                        SELECT 1 FROM v2_finding_events e
                        WHERE e.finding_id = f.finding_id
                          AND e.event_type = 'explanation_recorded'
                    ) AND NOT EXISTS (
                        SELECT 1 FROM v2_finding_events e
                        WHERE e.finding_id = f.finding_id
                          AND e.event_type = 'resolved_by_revision'
                    ) THEN 1 ELSE 0 END) AS explanation_count,
                    SUM(CASE WHEN EXISTS (
                        SELECT 1 FROM v2_finding_events e
                        WHERE e.finding_id = f.finding_id
                          AND e.event_type = 'resolved_by_revision'
                    ) THEN 1 ELSE 0 END) AS cleared_count,
                    SUM(CASE WHEN f.finding_type = 'risk' AND NOT EXISTS (
                        SELECT 1 FROM v2_finding_events e
                        WHERE e.finding_id = f.finding_id
                          AND e.event_type = 'resolved_by_revision'
                    ) THEN 1 ELSE 0 END)
                        AS risk_count,
                    SUM(CASE WHEN f.finding_type = 'data_insufficient'
                        AND NOT EXISTS (
                            SELECT 1 FROM v2_finding_events e
                            WHERE e.finding_id = f.finding_id
                              AND e.event_type = 'resolved_by_revision'
                        ) THEN 1 ELSE 0 END) AS insufficient_count
                FROM v2_findings f {where}
                """,
                values,
            ).fetchone()
        assert row is not None
        return {
            "open": int(row["open_count"] or 0),
            "explanation_recorded": int(row["explanation_count"] or 0),
            "cleared_by_reanalysis": int(row["cleared_count"] or 0),
            "risk": int(row["risk_count"] or 0),
            "data_insufficient": int(row["insufficient_count"] or 0),
        }

    def verify_audit_chain(self) -> bool:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM v2_audit_events ORDER BY sequence"
            ).fetchall()
        previous = "0" * 64
        for row in rows:
            material = _audit_hash_material(
                event_id=row["event_id"],
                event_type=row["event_type"],
                aggregate_type=row["aggregate_type"],
                aggregate_id=row["aggregate_id"],
                mine_id=row["mine_id"],
                payload_json=row["payload_json"],
                occurred_at=row["occurred_at"],
                previous_hash=previous,
            )
            if row["previous_hash"] != previous or row["event_hash"] != _hash_text(
                material
            ):
                return False
            previous = row["event_hash"]
        return True

    def verify_integrity(self) -> bool:
        """Verify all immutable JSON/hash bindings and the audit hash chain."""

        checks = (
            ("v2_submissions", "payload_json", "payload_sha256"),
            ("v2_daily_facts", "normalized_json", "normalized_sha256"),
            ("v2_analysis_runs", "result_json", "result_sha256"),
            ("v2_baseline_admissions", "reasons_json", "reasons_sha256"),
            ("v2_peer_reference_snapshots", "cohort_json", "cohort_sha256"),
            ("v2_findings", "report_json", "report_sha256"),
            ("v2_analysis_reports", "report_json", "report_sha256"),
            ("v2_response_batches", "request_json", "request_sha256"),
            ("v2_responses", "response_json", "response_sha256"),
            ("v2_delivery_acks", "ack_json", "ack_sha256"),
            ("v2_outbox", "payload_json", "payload_sha256"),
            ("v2_exchange_messages", "body_json", "body_sha256"),
        )
        with self._lock:
            for table, payload_column, hash_column in checks:
                rows = self._connection.execute(
                    f"SELECT {payload_column}, {hash_column} FROM {table}"
                ).fetchall()
                if any(
                    _hash_text(row[payload_column]) != row[hash_column] for row in rows
                ):
                    return False
        return self.verify_audit_chain()

    # ------------------------------------------------------------------
    # Internal transaction helpers

    def _find_inbox_command(
        self,
        connection: sqlite3.Connection,
        *,
        sender_id: str,
        idempotency_key: str,
        message_id: str,
        message_type: str,
        mine_id: str,
        body_sha256: str,
        occurred_at: str,
    ) -> sqlite3.Row | None:
        row = connection.execute(
            """
            SELECT * FROM v2_inbox_commands
            WHERE sender_id = ? AND idempotency_key = ?
            """,
            (sender_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if (
            row["message_id"] == message_id
            and row["message_type"] == message_type
            and row["mine_id"] == mine_id
            and row["body_sha256"] == body_sha256
        ):
            return row
        self._append_audit(
            connection,
            event_type="inbox_idempotency_conflict_rejected",
            aggregate_type="exchange_security",
            aggregate_id=idempotency_key,
            mine_id=mine_id,
            payload={
                "sender_id": sender_id,
                "message_type": message_type,
                "attempted_message_id": message_id,
                "attempted_body_sha256": body_sha256,
                "original_message_id": row["message_id"],
                "original_body_sha256": row["body_sha256"],
            },
            occurred_at=occurred_at,
        )
        raise _DurableIdempotencyConflict(
            "idempotency key was already used with another authenticated body"
        )

    @staticmethod
    def _insert_inbox_command(
        connection: sqlite3.Connection,
        *,
        sender_id: str,
        idempotency_key: str,
        message_id: str,
        message_type: str,
        mine_id: str,
        body_sha256: str,
        result_kind: str,
        result_id: str,
        recorded_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO v2_inbox_commands(
                sender_id, idempotency_key, message_id, message_type, mine_id,
                body_sha256, result_kind, result_id, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sender_id,
                idempotency_key,
                message_id,
                message_type,
                mine_id,
                body_sha256,
                result_kind,
                result_id,
                recorded_at,
            ),
        )

    @staticmethod
    def _delivery_ack_receipt(
        connection: sqlite3.Connection,
        ack_id: str,
        *,
        replay: bool,
    ) -> DeliveryAckReceipt:
        row = connection.execute(
            """
            SELECT ack_id, report_id, mine_id, recorded_at
            FROM v2_delivery_acks WHERE ack_id = ?
            """,
            (ack_id,),
        ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError("delivery ack not found")
        return DeliveryAckReceipt(
            ack_id=row["ack_id"],
            report_id=row["report_id"],
            mine_id=row["mine_id"],
            recorded_at=_parse_datetime(row["recorded_at"]),
            idempotent_replay=replay,
        )

    @staticmethod
    def _response_batch_receipt(
        connection: sqlite3.Connection,
        wire_response_id: str,
        *,
        replay: bool,
    ) -> ResponseBatchReceipt:
        row = connection.execute(
            "SELECT * FROM v2_response_batches WHERE wire_response_id = ?",
            (wire_response_id,),
        ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError("response batch not found")
        children = connection.execute(
            """
            SELECT response_id, finding_id FROM v2_responses
            WHERE wire_response_id = ? ORDER BY response_id
            """,
            (wire_response_id,),
        ).fetchall()
        return ResponseBatchReceipt(
            wire_response_id=row["wire_response_id"],
            report_id=row["report_id"],
            mine_id=row["mine_id"],
            child_response_ids=[item["response_id"] for item in children],
            finding_ids=[item["finding_id"] for item in children],
            recorded_at=_parse_datetime(row["recorded_at"]),
            idempotent_replay=replay,
        )

    @staticmethod
    def _insert_exchange_message(
        connection: sqlite3.Connection,
        message: ExchangeMessageInput,
        *,
        recorded_at: str,
    ) -> tuple[ExchangeMessageProjection, bool]:
        payload = message.model_dump(mode="json")
        body_json = _canonical_json(payload["body"])
        body_sha256 = _hash_text(body_json)
        existing = connection.execute(
            "SELECT * FROM v2_exchange_messages WHERE message_id = ?",
            (message.message_id,),
        ).fetchone()
        if existing is not None:
            if (
                existing["body_sha256"] != body_sha256
                or existing["direction"] != message.direction
                or existing["message_type"] != message.message_type
                or existing["mine_id"] != message.mine_id
                or existing["agent_id"] != message.agent_id
                or existing["exchanged_at"] != _as_utc(message.exchanged_at).isoformat()
            ):
                raise RegulatoryV2ConflictError(
                    "exchange message_id was already used with another envelope"
                )
            return _exchange_from_row(existing), True
        connection.execute(
            """
            INSERT INTO v2_exchange_messages(
                message_id, direction, message_type, mine_id, agent_id,
                body_json, body_sha256, exchanged_at, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message.message_id,
                message.direction,
                message.message_type,
                message.mine_id,
                message.agent_id,
                body_json,
                body_sha256,
                _as_utc(message.exchanged_at).isoformat(),
                recorded_at,
            ),
        )
        row = connection.execute(
            "SELECT * FROM v2_exchange_messages WHERE message_id = ?",
            (message.message_id,),
        ).fetchone()
        assert row is not None
        return _exchange_from_row(row), False

    @staticmethod
    def _assert_agent_mine(
        connection: sqlite3.Connection, agent_id: str, mine_id: str
    ) -> None:
        row = connection.execute(
            "SELECT mine_id FROM v2_agent_mine_bindings WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError("enterprise agent is not registered")
        if row["mine_id"] != mine_id:
            raise RegulatoryV2ConflictError(
                "one enterprise agent cannot submit for multiple mines"
            )

    @staticmethod
    def _validate_revision(
        connection: sqlite3.Connection,
        submission: FiveQuantitySubmission,
    ) -> sqlite3.Row | None:
        if submission.supersedes_submission_id is None:
            if submission.revision != 1:
                raise RegulatoryV2ConflictError(
                    "revision greater than one requires supersedes_submission_id"
                )
            reporting_month = submission.period_start.strftime("%Y-%m")
            existing_root = connection.execute(
                """
                SELECT submission_id FROM v2_submissions
                WHERE mine_id = ? AND revision = 1
                  AND COALESCE(reporting_month, substr(period_start, 1, 7)) = ?
                """,
                (submission.mine_id, reporting_month),
            ).fetchone()
            if existing_root is not None:
                raise RegulatoryV2ConflictError(
                    "one mine may have only one root workflow per reporting month; "
                    "submit a direct revision of the current leaf"
                )
            return None
        predecessor = connection.execute(
            "SELECT * FROM v2_submissions WHERE submission_id = ?",
            (submission.supersedes_submission_id,),
        ).fetchone()
        if predecessor is None:
            raise RegulatoryV2ConflictError("superseded submission does not exist")
        if predecessor["mine_id"] != submission.mine_id:
            raise RegulatoryV2ConflictError("revision cannot cross mine boundaries")
        if (
            predecessor["period_start"] != submission.period_start.isoformat()
            or predecessor["period_end"] != submission.period_end.isoformat()
        ):
            raise RegulatoryV2ConflictError("revision must preserve reporting period")
        if predecessor["revision"] + 1 != submission.revision:
            raise RegulatoryV2ConflictError(
                "revision must increment predecessor by one"
            )
        existing_successor = connection.execute(
            """
            SELECT 1 FROM v2_submissions WHERE supersedes_submission_id = ?
            """,
            (submission.supersedes_submission_id,),
        ).fetchone()
        if existing_successor is not None:
            raise RegulatoryV2ConflictError("predecessor already has a revision")
        return predecessor

    def _receipt_for_submission(
        self,
        connection: sqlite3.Connection,
        submission_id: str,
        *,
        replay: bool,
    ) -> SubmissionReceipt:
        row = connection.execute(
            """
            SELECT s.submission_id, s.mine_id, s.received_at, s.payload_sha256,
                   r.run_id, r.decision,
                   (
                       SELECT f.finding_id FROM v2_findings f
                       WHERE f.run_id = r.run_id
                       ORDER BY f.issued_at, f.finding_id LIMIT 1
                   ) AS finding_id
            FROM v2_submissions s
            JOIN v2_analysis_runs r ON r.submission_id = s.submission_id
            WHERE s.submission_id = ?
            """,
            (submission_id,),
        ).fetchone()
        if row is None:
            raise RegulatoryV2NotFoundError("submission receipt not found")
        return SubmissionReceipt(
            submission_id=row["submission_id"],
            run_id=row["run_id"],
            mine_id=row["mine_id"],
            decision=DecisionStatus(row["decision"]),
            finding_id=row["finding_id"],
            received_at=_parse_datetime(row["received_at"]),
            payload_sha256=row["payload_sha256"],
            idempotent_replay=replay,
        )

    def _same_mine_history(
        self,
        connection: sqlite3.Connection,
        mine_id: str,
        *,
        before: date,
        excluded_submission_id: str,
        comparison_group: str,
        limit: int = 365,
    ) -> list[HistoricalFiveQuantityDay]:
        rows = connection.execute(
            """
            SELECT DISTINCT d.observed_date, d.normalized_json
            FROM v2_daily_facts d
            JOIN v2_submissions s ON s.submission_id = d.submission_id
            JOIN v2_analysis_runs r ON r.submission_id = s.submission_id
            JOIN v2_baseline_admissions b ON b.run_id = r.run_id
            WHERE s.mine_id = ?
              AND s.comparison_group = ?
              AND d.observed_date < ?
              AND d.submission_id != ?
              AND r.decision = 'normal_candidate'
              AND b.eligible = 1
              AND NOT EXISTS (
                  SELECT 1 FROM v2_submissions newer
                  WHERE newer.supersedes_submission_id = s.submission_id
              )
            ORDER BY d.observed_date DESC LIMIT ?
            """,
            (
                mine_id,
                comparison_group,
                before.isoformat(),
                excluded_submission_id,
                limit,
            ),
        ).fetchall()
        result: list[HistoricalFiveQuantityDay] = []
        for row in reversed(rows):
            payload = _canonical_daily_payload(json.loads(row["normalized_json"]))
            if any(payload.get(metric) is None for metric in _METRICS):
                continue
            result.append(HistoricalFiveQuantityDay.model_validate(payload))
        return result

    def _anonymous_peer_bands(
        self,
        connection: sqlite3.Connection,
        submission: FiveQuantitySubmission,
        parameters: RegulatoryFiveQuantityParameters,
    ) -> list[ReferenceBand]:
        comparison_group = submission.comparison_context.group_key
        cutoff_date = submission.period_start.isoformat()
        frozen = connection.execute(
            """
            SELECT cohort_json FROM v2_peer_reference_snapshots
            WHERE comparison_group = ? AND cutoff_date = ?
            """,
            (comparison_group, cutoff_date),
        ).fetchone()
        if frozen is None:
            rows = connection.execute(
                """
                WITH ranked AS (
                    SELECT s.mine_id, d.normalized_json,
                           ROW_NUMBER() OVER (
                               PARTITION BY s.mine_id
                               ORDER BY d.observed_date DESC
                           ) AS recency_rank
                    FROM v2_daily_facts d
                    JOIN v2_submissions s
                      ON s.submission_id = d.submission_id
                    JOIN v2_analysis_runs r
                      ON r.submission_id = s.submission_id
                    JOIN v2_baseline_admissions b ON b.run_id = r.run_id
                    WHERE s.comparison_group = ?
                      -- Freeze one group-wide, lagged snapshot.  All mines in
                      -- this report period see exactly the same as-of cohort.
                      AND d.observed_date < ?
                      AND r.decision = 'normal_candidate'
                      AND b.reference_candidate = 1
                      AND NOT EXISTS (
                          SELECT 1 FROM v2_submissions newer
                          WHERE newer.supersedes_submission_id = s.submission_id
                      )
                )
                SELECT mine_id, normalized_json FROM ranked
                WHERE recency_rank <= 365
                ORDER BY mine_id, recency_rank
                """,
                (comparison_group, cutoff_date),
            ).fetchall()
            ratios_by_mine: dict[RelationshipCode, dict[str, list[float]]] = {
                relationship: {} for relationship in _RELATIONSHIP_METRIC
            }
            for row in rows:
                payload = _canonical_daily_payload(
                    json.loads(row["normalized_json"])
                )
                production = payload.get("production_t")
                if (
                    production is None
                    or production <= parameters.production_epsilon_t
                ):
                    continue
                for relationship, metric in _RELATIONSHIP_METRIC.items():
                    value = payload.get(metric)
                    if value is not None:
                        ratios_by_mine[relationship].setdefault(
                            row["mine_id"], []
                        ).append(float(value) / float(production))
            mine_ids = sorted({row["mine_id"] for row in rows})
            members: list[dict[str, Any]] = []
            for mine_id in mine_ids:
                ratios: dict[str, dict[str, float | int]] = {}
                for relationship, mine_values in ratios_by_mine.items():
                    values = mine_values.get(mine_id, [])
                    if values:
                        ratios[relationship.value] = {
                            "center": _median(values),
                            "sample_count": len(values),
                        }
                members.append(
                    {
                        "mine_token": _hash_text("peer-member:" + mine_id),
                        "ratios": ratios,
                    }
                )
            cohort = {
                "schema_version": "anonymous-peer-cohort-snapshot-v1",
                "comparison_group": comparison_group,
                "cutoff_date": cutoff_date,
                "members": members,
            }
            cohort_json = _canonical_json(cohort)
            snapshot_id = str(
                uuid5(
                    NAMESPACE_URL,
                    "mineguard:v2:peer-snapshot:"
                    f"{comparison_group}:{cutoff_date}",
                )
            )
            created_at = self._timestamp()
            connection.execute(
                """
                INSERT INTO v2_peer_reference_snapshots(
                    snapshot_id, comparison_group, cutoff_date,
                    cohort_json, cohort_sha256, mine_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    comparison_group,
                    cutoff_date,
                    cohort_json,
                    _hash_text(cohort_json),
                    len(members),
                    created_at,
                ),
            )
            self._append_audit(
                connection,
                event_type="anonymous_peer_snapshot_frozen",
                aggregate_type="peer_reference_snapshot",
                aggregate_id=snapshot_id,
                mine_id=None,
                payload={
                    "comparison_group": comparison_group,
                    "cutoff_date": cutoff_date,
                    "cohort_sha256": _hash_text(cohort_json),
                    "mine_count": len(members),
                    "minimum_anonymity": parameters.minimum_peer_mines,
                },
                occurred_at=created_at,
            )
        else:
            cohort = json.loads(frozen["cohort_json"])

        target_token = _hash_text("peer-member:" + submission.mine_id)
        peer_members = [
            member
            for member in cohort["members"]
            if member["mine_token"] != target_token
        ]
        result: list[ReferenceBand] = []
        for relationship in _RELATIONSHIP_METRIC:
            relationship_keys = (relationship.value,)
            if relationship is RelationshipCode.MINE_ENTRY_PERSONS_PER_PRODUCTION:
                relationship_keys += ("labor_per_production",)
            samples = [
                next(
                    member["ratios"][key]
                    for key in relationship_keys
                    if key in member["ratios"]
                )
                for member in peer_members
                if any(key in member["ratios"] for key in relationship_keys)
            ]
            if len(samples) < parameters.minimum_peer_mines:
                continue
            sample_count = sum(int(item["sample_count"]) for item in samples)
            if sample_count < parameters.minimum_reference_samples:
                continue
            cohort_values = [float(item["center"]) for item in samples]
            center = _median(cohort_values)
            mad = _median([abs(item - center) for item in cohort_values])
            half = max(
                1.4826 * mad * parameters.reference_robust_z,
                abs(center) * parameters.reference_minimum_relative_half_width,
                parameters.observation_absolute_tolerance,
            )
            result.append(
                ReferenceBand(
                    relationship=relationship,
                    lower=max(0.0, center - half),
                    center=center,
                    upper=center + half,
                    sample_count=sample_count,
                    mine_count=len(cohort_values),
                    basis="anonymous_peer",
                    comparison_group=comparison_group,
                )
            )
        return result

    def _issue_finding(
        self,
        connection: sqlite3.Connection,
        *,
        submission: FiveQuantitySubmission,
        run_id: str,
        result: RegulatoryFiveQuantityResult,
        category: Literal[
            "data_quality",
            "relationship_consistency",
            "temporal_pattern",
            "data_completeness",
        ],
        reasons: list[str],
        issued_at: str,
    ) -> str:
        finding_id = str(uuid4())
        finding_type: Literal["risk", "data_insufficient"] = (
            "risk" if result.decision is DecisionStatus.RISK else "data_insufficient"
        )
        title_by_category = {
            "data_quality": "五量数据质量风险",
            "relationship_consistency": "五量关系协调风险",
            "temporal_pattern": "五量时序变化风险",
            "data_completeness": "五量数据补充要求",
        }
        title = title_by_category[category]
        report = RiskFindingReport(
            finding_id=finding_id,
            mine_id=submission.mine_id,
            submission_id=submission.submission_id,
            run_id=run_id,
            finding_type=finding_type,
            category=category,
            title=title,
            summary="；".join(reasons[:5]),
            decision_reasons=reasons,
            result=result,
            issued_at=_parse_datetime(issued_at),
        )
        report_json = _canonical_json(report.model_dump(mode="json"))
        connection.execute(
            """
            INSERT INTO v2_findings(
                finding_id, submission_id, run_id, mine_id, finding_type,
                category, report_json, report_sha256, issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                submission.submission_id,
                run_id,
                submission.mine_id,
                finding_type,
                category,
                report_json,
                _hash_text(report_json),
                issued_at,
            ),
        )
        self._append_finding_event(
            connection,
            finding_id=finding_id,
            event_type="issued",
            payload={
                "run_id": run_id,
                "submission_id": submission.submission_id,
                "finding_type": finding_type,
                "category": category,
            },
            occurred_at=issued_at,
        )
        self._append_audit(
            connection,
            event_type="finding_automatically_issued",
            aggregate_type="finding",
            aggregate_id=finding_id,
            mine_id=submission.mine_id,
            payload={
                "submission_id": submission.submission_id,
                "run_id": run_id,
                "finding_type": finding_type,
                "category": category,
                "report_sha256": _hash_text(report_json),
            },
            occurred_at=issued_at,
        )
        return finding_id

    def _issue_analysis_report(
        self,
        connection: sqlite3.Connection,
        *,
        submission: FiveQuantitySubmission,
        run_id: str,
        result: RegulatoryFiveQuantityResult,
        finding_ids: list[str],
        issued_at: str,
    ) -> str:
        """Create exactly one enterprise-visible report for every run."""

        report_id = str(uuid4())
        next_row = connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 AS value FROM v2_outbox"
        ).fetchone()
        outbox_sequence = int(next_row["value"])
        delivery_cursor = _opaque_delivery_cursor(submission.mine_id, outbox_sequence)
        report = AnalysisReport(
            report_id=report_id,
            run_id=run_id,
            submission_id=submission.submission_id,
            mine_id=submission.mine_id,
            outcome=result.decision,
            finding_ids=finding_ids,
            response_required=result.decision is not DecisionStatus.NORMAL_CANDIDATE,
            delivery_cursor=delivery_cursor,
            result=result,
            issued_at=_parse_datetime(issued_at),
        )
        report_json = _canonical_json(report.model_dump(mode="json"))
        connection.execute(
            """
            INSERT INTO v2_analysis_reports(
                report_id, run_id, submission_id, mine_id, outcome,
                report_json, report_sha256, issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                run_id,
                submission.submission_id,
                submission.mine_id,
                result.decision.value,
                report_json,
                _hash_text(report_json),
                issued_at,
            ),
        )
        self._append_outbox(
            connection,
            audience_mine_id=submission.mine_id,
            kind="analysis_report_available",
            aggregate_id=report_id,
            payload=report.model_dump(mode="json"),
            created_at=issued_at,
            sequence=outbox_sequence,
        )
        self._append_audit(
            connection,
            event_type="analysis_report_automatically_issued",
            aggregate_type="analysis_report",
            aggregate_id=report_id,
            mine_id=submission.mine_id,
            payload={
                "run_id": run_id,
                "submission_id": submission.submission_id,
                "outcome": result.decision.value,
                "finding_ids": finding_ids,
                "report_sha256": _hash_text(report_json),
                "delivery_cursor": delivery_cursor,
            },
            occurred_at=issued_at,
        )
        return report_id

    def _resolve_predecessor_findings(
        self,
        connection: sqlite3.Connection,
        *,
        predecessor_submission_id: str,
        resolving_submission_id: str,
        mine_id: str,
        occurred_at: str,
    ) -> None:
        rows = connection.execute(
            """
            WITH RECURSIVE ancestor_submissions(submission_id) AS (
                SELECT ?
                UNION ALL
                SELECT s.supersedes_submission_id
                FROM v2_submissions s
                JOIN ancestor_submissions a ON s.submission_id = a.submission_id
                WHERE s.supersedes_submission_id IS NOT NULL
            )
            SELECT f.finding_id
            FROM v2_findings f
            WHERE f.submission_id IN (
                SELECT submission_id FROM ancestor_submissions
            )
              AND NOT EXISTS (
                  SELECT 1 FROM v2_finding_events e
                  WHERE e.finding_id = f.finding_id
                    AND e.event_type = 'resolved_by_revision'
              )
            """,
            (predecessor_submission_id,),
        ).fetchall()
        for row in rows:
            finding_id = row["finding_id"]
            payload = {
                "resolving_submission_id": resolving_submission_id,
                "rule": "normal_candidate_revision_reanalysis_only",
            }
            self._append_finding_event(
                connection,
                finding_id=finding_id,
                event_type="resolved_by_revision",
                payload=payload,
                occurred_at=occurred_at,
            )
            self._append_outbox(
                connection,
                audience_mine_id=mine_id,
                kind="finding_resolved",
                aggregate_id=finding_id,
                payload={"finding_id": finding_id, **payload},
                created_at=occurred_at,
            )
            self._append_audit(
                connection,
                event_type="finding_resolved_by_revision_reanalysis",
                aggregate_type="finding",
                aggregate_id=finding_id,
                mine_id=mine_id,
                payload=payload,
                occurred_at=occurred_at,
            )

    def _record_baseline_admission(
        self,
        connection: sqlite3.Connection,
        *,
        submission: FiveQuantitySubmission,
        run_id: str,
        result: RegulatoryFiveQuantityResult,
        recorded_at: str,
    ) -> None:
        review_or_risk = [
            signal.code
            for signal in (
                *result.data_quality_signals,
                *result.relationship_signals,
                *result.temporal_signals,
            )
            if signal.severity.value in {"review", "risk"}
        ]
        maximum_adjustment = max(
            (
                item.normalized_adjustment
                for item in result.reconciliation.adjustments
            ),
            default=0.0,
        )
        intrinsic_failures: list[str] = []
        if result.decision is not DecisionStatus.NORMAL_CANDIDATE:
            intrinsic_failures.append("decision_not_normal_candidate")
        if result.coverage.completeness_ratio < 0.999999:
            intrinsic_failures.append("calendar_or_metric_coverage_incomplete")
        if result.coverage.complete_day_count < 14:
            intrinsic_failures.append("fewer_than_14_complete_days")
        if not result.reconciliation.success:
            intrinsic_failures.append("l1_solver_unsuccessful")
        if not result.reconciliation.mcs_search_complete:
            intrinsic_failures.append("mcs_search_incomplete")
        if maximum_adjustment > 0.10:
            intrinsic_failures.append("large_normalized_reconciliation_adjustment")
        if review_or_risk:
            intrinsic_failures.append("review_or_risk_signal_present")
        reference_candidate = not intrinsic_failures
        has_independent_anchor = bool(
            result.references.accepted_history_bands
            or result.references.accepted_peer_bands
        )
        failed = list(intrinsic_failures)
        if reference_candidate and not has_independent_anchor:
            failed.append("no_independent_history_or_anonymous_peer_anchor")
        eligible = reference_candidate and has_independent_anchor
        reasons = {
            "eligible": eligible,
            "reference_candidate": reference_candidate,
            "has_independent_anchor": has_independent_anchor,
            "failed_rules": failed,
            "intrinsic_failed_rules": intrinsic_failures,
            "review_or_risk_signal_codes": sorted(set(review_or_risk)),
            "complete_day_count": result.coverage.complete_day_count,
            "completeness_ratio": result.coverage.completeness_ratio,
            "maximum_normalized_adjustment": maximum_adjustment,
            "rule_statement": (
                "normal outcome is retained independently from baseline eligibility"
            ),
        }
        reasons_json = _canonical_json(reasons)
        admission_id = str(uuid4())
        connection.execute(
            """
            INSERT INTO v2_baseline_admissions(
                admission_id, run_id, submission_id, mine_id, eligible,
                reference_candidate, rule_version, reasons_json,
                reasons_sha256, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                admission_id,
                run_id,
                submission.submission_id,
                submission.mine_id,
                int(eligible),
                int(reference_candidate),
                BASELINE_ADMISSION_RULE_VERSION,
                reasons_json,
                _hash_text(reasons_json),
                recorded_at,
            ),
        )
        self._append_audit(
            connection,
            event_type=(
                "baseline_candidate_admitted"
                if eligible
                else "baseline_candidate_rejected"
            ),
            aggregate_type="baseline_admission",
            aggregate_id=admission_id,
            mine_id=submission.mine_id,
            payload={
                "run_id": run_id,
                "submission_id": submission.submission_id,
                "eligible": eligible,
                "reference_candidate": reference_candidate,
                "reasons_sha256": _hash_text(reasons_json),
                "rule_version": BASELINE_ADMISSION_RULE_VERSION,
            },
            occurred_at=recorded_at,
        )

    @staticmethod
    def _append_finding_event(
        connection: sqlite3.Connection,
        *,
        finding_id: str,
        event_type: Literal[
            "issued",
            "delivery_acknowledged",
            "explanation_recorded",
            "resolved_by_revision",
        ],
        payload: dict[str, Any],
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO v2_finding_events(
                event_id, finding_id, event_type, payload_json, occurred_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                finding_id,
                event_type,
                _canonical_json(payload),
                occurred_at,
            ),
        )

    @staticmethod
    def _append_outbox(
        connection: sqlite3.Connection,
        *,
        audience_mine_id: str,
        kind: Literal[
            "analysis_report_available",
            "finding_issued",
            "response_recorded",
            "finding_resolved",
        ],
        aggregate_id: str,
        payload: dict[str, Any],
        created_at: str,
        sequence: int | None = None,
    ) -> None:
        payload_json = _canonical_json(payload)
        message_id = str(uuid4())
        if sequence is None:
            connection.execute(
                """
                INSERT INTO v2_outbox(
                    message_id, audience_mine_id, kind, aggregate_id,
                    payload_json, payload_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    audience_mine_id,
                    kind,
                    aggregate_id,
                    payload_json,
                    _hash_text(payload_json),
                    created_at,
                ),
            )
        else:
            connection.execute(
                """
                INSERT INTO v2_outbox(
                    sequence, message_id, audience_mine_id, kind, aggregate_id,
                    payload_json, payload_sha256, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    message_id,
                    audience_mine_id,
                    kind,
                    aggregate_id,
                    payload_json,
                    _hash_text(payload_json),
                    created_at,
                ),
            )

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        mine_id: str | None,
        payload: dict[str, Any],
        occurred_at: str,
    ) -> None:
        previous_row = connection.execute(
            "SELECT event_hash FROM v2_audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous_row["event_hash"] if previous_row else "0" * 64
        event_id = str(uuid4())
        payload_json = _canonical_json(payload)
        material = _audit_hash_material(
            event_id=event_id,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            mine_id=mine_id,
            payload_json=payload_json,
            occurred_at=occurred_at,
            previous_hash=previous_hash,
        )
        connection.execute(
            """
            INSERT INTO v2_audit_events(
                event_id, event_type, aggregate_type, aggregate_id, mine_id,
                payload_json, occurred_at, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                event_type,
                aggregate_type,
                aggregate_id,
                mine_id,
                payload_json,
                occurred_at,
                previous_hash,
                _hash_text(material),
            ),
        )

    def _timestamp(self) -> str:
        return _as_utc(self._now()).isoformat()


_METRICS = (
    "ventilation_m3_min",
    "electricity_kwh",
    "detonators_count",
    "explosives_kg",
    "mine_entry_persons",
    "production_t",
)
_RELATIONSHIP_METRIC = {
    RelationshipCode.VENTILATION_PER_PRODUCTION: "ventilation_m3_min",
    RelationshipCode.ELECTRICITY_PER_PRODUCTION: "electricity_kwh",
    RelationshipCode.DETONATORS_PER_PRODUCTION: "detonators_count",
    RelationshipCode.EXPLOSIVES_PER_PRODUCTION: "explosives_kg",
    RelationshipCode.MINE_ENTRY_PERSONS_PER_PRODUCTION: "mine_entry_persons",
}


def _canonical_daily_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Expose the corrected personnel term while preserving legacy V2 records."""

    normalized = dict(payload)
    if "mine_entry_persons" not in normalized and "labor_persons" in normalized:
        normalized["mine_entry_persons"] = normalized.pop("labor_persons")
    return normalized


def _finding_groups(
    result: RegulatoryFiveQuantityResult,
) -> list[
    tuple[
        Literal[
            "data_quality",
            "relationship_consistency",
            "temporal_pattern",
            "data_completeness",
        ],
        list[str],
    ]
]:
    if result.decision is DecisionStatus.INSUFFICIENT_DATA:
        return [("data_completeness", result.decision_reasons)]
    groups: list[tuple[Any, list[str]]] = []
    for category, signals in (
        ("data_quality", result.data_quality_signals),
        ("relationship_consistency", result.relationship_signals),
        ("temporal_pattern", result.temporal_signals),
    ):
        reasons = list(
            dict.fromkeys(
                item.message for item in signals if item.severity.value == "risk"
            )
        )
        if reasons:
            groups.append((category, reasons))
    if result.data_sufficiency_reasons:
        groups.append(("data_completeness", result.data_sufficiency_reasons))
    if not groups:
        groups.append(("relationship_consistency", result.decision_reasons))
    return groups


def _normalized_days(submission: FiveQuantitySubmission) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for day in sorted(submission.days, key=lambda item: item.date):
        payload: dict[str, Any] = {"date": day.date.isoformat()}
        for metric in day.quantities():
            payload[metric] = effective_reported_value(day, metric)
        result.append(payload)
    return result


def _exchange_from_row(row: sqlite3.Row) -> ExchangeMessageProjection:
    return ExchangeMessageProjection(
        sequence=row["sequence"],
        message_id=row["message_id"],
        direction=row["direction"],
        message_type=row["message_type"],
        mine_id=row["mine_id"],
        agent_id=row["agent_id"],
        body=json.loads(row["body_json"]),
        body_sha256=row["body_sha256"],
        exchanged_at=_parse_datetime(row["exchanged_at"]),
    )


def _audit_hash_material(
    *,
    event_id: str,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    mine_id: str | None,
    payload_json: str,
    occurred_at: str,
    previous_hash: str,
) -> str:
    return _canonical_json(
        {
            "event_id": event_id,
            "event_type": event_type,
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "mine_id": mine_id,
            "payload": json.loads(payload_json),
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _opaque_delivery_cursor(mine_id: str, sequence: int) -> str:
    mine_token = hashlib.sha256(mine_id.encode("utf-8")).hexdigest()[:12]
    return f"v2.{mine_token}.{sequence:020d}"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return _as_utc(parsed)


def _validated_limit(value: int) -> int:
    if not 1 <= value <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    return value


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return float((ordered[middle - 1] + ordered[middle]) / 2.0)


__all__ = [
    "AnalysisReport",
    "AnalysisReportDeliveryAck",
    "AuditPage",
    "AuditProjection",
    "DeliveryAckReceipt",
    "EnterpriseFindingResponse",
    "EvidenceReference",
    "ExchangeMessageInput",
    "ExchangeMessageProjection",
    "FindingProjection",
    "MineDetailProjection",
    "MineOverview",
    "OutboxItem",
    "OutboxPage",
    "RegulatoryV2ConflictError",
    "RegulatoryV2NotFoundError",
    "RegulatoryV2Store",
    "ResponseBatchReceipt",
    "ResponseReceipt",
    "RiskFindingReport",
    "SubmissionReceipt",
]
