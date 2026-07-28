"""Persistent, restart-safe background analysis jobs for the local service."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Callable, Literal

from pydantic import Field, model_validator

from .casework import canonical_json, sha256_json
from .models import StrictModel


JobStatus = Literal[
    "queued",
    "running",
    "succeeded",
    "partial_failed",
    "failed",
    "cancelled",
]
TERMINAL_JOB_STATUSES = frozenset(
    {"succeeded", "partial_failed", "failed", "cancelled"}
)
WindowStatus = Literal[
    "queued",
    "running",
    "succeeded",
    "failed",
    "cancelled",
]


class JobError(RuntimeError):
    pass


class JobConflictError(JobError):
    pass


class JobNotFoundError(JobError):
    pass


class JobCapacityError(JobError):
    pass


class JobStateError(JobError):
    pass


class PublicJobError(RuntimeError):
    """An operation failure whose stable code and summary may be persisted."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code
        self.summary = summary


class AnalysisWindow(StrictModel):
    window_id: Annotated[str, Field(min_length=1)]
    mine_id: Annotated[str, Field(min_length=1)]
    payload: dict[str, Any]


class AnalysisJobRequest(StrictModel):
    idempotency_key: Annotated[str, Field(min_length=1, max_length=200)]
    requested_by: Annotated[str, Field(min_length=1)]
    windows: Annotated[list[AnalysisWindow], Field(min_length=1, max_length=5000)]
    parent_job_id: str | None = None

    @model_validator(mode="after")
    def validate_window_ids(self) -> "AnalysisJobRequest":
        window_ids = [window.window_id for window in self.windows]
        if len(window_ids) != len(set(window_ids)):
            raise ValueError("window_id values must be unique within a job")
        return self


class WindowOutcome(StrictModel):
    window_id: str
    mine_id: str
    status: WindowStatus
    attempt: int
    payload_sha256: str
    result_sha256: str | None = None
    result: dict[str, Any] | None = None
    error_code: str | None = None
    error_summary: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


class JobRecord(StrictModel):
    job_id: str
    idempotency_key: str
    requested_by: str
    parent_job_id: str | None = None
    status: JobStatus
    request_sha256: str
    total_windows: int
    completed_windows: int
    succeeded_windows: int
    failed_windows: int
    cancelled_windows: int
    attempt: int
    cancellation_requested: bool
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str
    archived_at: str | None = None
    archived_by: str | None = None
    archived_reason: str | None = None
    outcomes: list[WindowOutcome] = Field(default_factory=list)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _job_id(idempotency_key: str, request_hash: str) -> str:
    material = f"{idempotency_key}\x1f{request_hash}".encode("utf-8")
    return f"job_{hashlib.sha256(material).hexdigest()[:24]}"


class JobRepository:
    """SQLite storage. One instance is safe for all server worker threads."""

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
        self._initialize()
        if self.database_path != ":memory:":
            try:
                Path(self.database_path).chmod(0o600)
            except OSError:
                pass

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS analysis_jobs (
            job_id TEXT PRIMARY KEY,
            idempotency_key TEXT NOT NULL UNIQUE,
            requested_by TEXT NOT NULL,
            parent_job_id TEXT,
            status TEXT NOT NULL,
            request_sha256 TEXT NOT NULL,
            request_json TEXT NOT NULL,
            total_windows INTEGER NOT NULL,
            completed_windows INTEGER NOT NULL DEFAULT 0,
            succeeded_windows INTEGER NOT NULL DEFAULT 0,
            failed_windows INTEGER NOT NULL DEFAULT 0,
            cancelled_windows INTEGER NOT NULL DEFAULT 0,
            attempt INTEGER NOT NULL DEFAULT 0,
            cancellation_requested INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            updated_at TEXT NOT NULL,
            archived_at TEXT,
            archived_by TEXT,
            archived_reason TEXT
        );

        CREATE TABLE IF NOT EXISTS analysis_job_windows (
            job_id TEXT NOT NULL REFERENCES analysis_jobs(job_id),
            window_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            mine_id TEXT NOT NULL,
            status TEXT NOT NULL,
            attempt INTEGER NOT NULL DEFAULT 0,
            payload_sha256 TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            result_sha256 TEXT,
            result_json TEXT,
            error_code TEXT,
            error_summary TEXT,
            started_at TEXT,
            finished_at TEXT,
            PRIMARY KEY(job_id, window_id)
        );

        CREATE INDEX IF NOT EXISTS idx_jobs_status_created
            ON analysis_jobs(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_job_windows_status
            ON analysis_job_windows(job_id, status, position);
        """
        with self._lock, self._connection:
            self._connection.executescript(schema)
            columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(analysis_jobs)"
                ).fetchall()
            }
            for column in ("archived_at", "archived_by", "archived_reason"):
                if column not in columns:
                    self._connection.execute(
                        f"ALTER TABLE analysis_jobs ADD COLUMN {column} TEXT"
                    )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_jobs_archived_created
                ON analysis_jobs(archived_at, created_at)
                """
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def recover_interrupted(self) -> int:
        """Return interrupted work to the durable queue after a process crash."""

        now = _now()
        with self._lock, self._connection:
            rows = self._connection.execute(
                "SELECT job_id FROM analysis_jobs WHERE status = 'running'"
            ).fetchall()
            job_ids = [str(row["job_id"]) for row in rows]
            for job_id in job_ids:
                self._connection.execute(
                    """
                    UPDATE analysis_job_windows
                    SET status = 'queued', started_at = NULL
                    WHERE job_id = ? AND status = 'running'
                    """,
                    (job_id,),
                )
                self._connection.execute(
                    """
                    UPDATE analysis_jobs
                    SET status = 'queued', started_at = NULL, updated_at = ?
                    WHERE job_id = ?
                    """,
                    (now, job_id),
                )
        return len(job_ids)

    def submit(
        self,
        request: AnalysisJobRequest,
        *,
        max_pending_jobs: int,
    ) -> tuple[JobRecord, bool]:
        request_data = request.model_dump(mode="json")
        request_hash = sha256_json(request_data)
        job_id = _job_id(request.idempotency_key, request_hash)
        now = _now()
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT job_id, request_sha256 FROM analysis_jobs "
                "WHERE idempotency_key = ?",
                (request.idempotency_key,),
            ).fetchone()
            if existing is not None:
                if str(existing["request_sha256"]) != request_hash:
                    raise JobConflictError(
                        "idempotency_key already exists with different input"
                    )
                return self.get(str(existing["job_id"])), False

            pending = self._connection.execute(
                "SELECT COUNT(*) AS count FROM analysis_jobs "
                "WHERE status IN ('queued', 'running')"
            ).fetchone()
            assert pending is not None
            if int(pending["count"]) >= max_pending_jobs:
                raise JobCapacityError("background job capacity is full")

            self._connection.execute(
                """
                INSERT INTO analysis_jobs (
                    job_id, idempotency_key, requested_by, parent_job_id,
                    status, request_sha256, request_json, total_windows,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)
                """,
                (
                    job_id,
                    request.idempotency_key,
                    request.requested_by,
                    request.parent_job_id,
                    request_hash,
                    canonical_json(request_data),
                    len(request.windows),
                    now,
                    now,
                ),
            )
            for position, window in enumerate(request.windows):
                payload = window.payload
                self._connection.execute(
                    """
                    INSERT INTO analysis_job_windows (
                        job_id, window_id, position, mine_id, status,
                        payload_sha256, payload_json
                    ) VALUES (?, ?, ?, ?, 'queued', ?, ?)
                    """,
                    (
                        job_id,
                        window.window_id,
                        position,
                        window.mine_id,
                        sha256_json(payload),
                        canonical_json(payload),
                    ),
                )
        return self.get(job_id), True

    def get_request(self, job_id: str) -> AnalysisJobRequest:
        with self._lock:
            row = self._connection.execute(
                "SELECT request_json FROM analysis_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            raise JobNotFoundError("analysis job not found")
        return AnalysisJobRequest.model_validate_json(row["request_json"])

    def get(self, job_id: str) -> JobRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobNotFoundError("analysis job not found")
            window_rows = self._connection.execute(
                "SELECT * FROM analysis_job_windows WHERE job_id = ? "
                "ORDER BY position",
                (job_id,),
            ).fetchall()
        return self._record(row, window_rows)

    def list(
        self,
        *,
        limit: int = 100,
        include_archived: bool = False,
    ) -> list[JobRecord]:
        limit = max(1, min(limit, 500))
        archive_filter = "" if include_archived else "WHERE archived_at IS NULL "
        with self._lock:
            rows = self._connection.execute(
                "SELECT job_id FROM analysis_jobs "
                f"{archive_filter}ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self.get(str(row["job_id"])) for row in rows]

    def archive(
        self,
        job_id: str,
        *,
        archived: bool,
        archived_by: str,
        reason: str,
    ) -> JobRecord:
        """Soft-archive or restore a terminal job without deleting evidence."""

        actor = archived_by.strip()
        normalized_reason = reason.strip()
        if not actor or len(actor) > 100:
            raise ValueError("archived_by must be 1 to 100 characters")
        if not normalized_reason or len(normalized_reason) > 500:
            raise ValueError("reason must be 1 to 500 characters")
        now = _now()
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT status, archived_at FROM analysis_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobNotFoundError("analysis job not found")
            if str(row["status"]) not in TERMINAL_JOB_STATUSES:
                raise JobStateError("only terminal jobs can be archived")
            is_archived = row["archived_at"] is not None
            if archived == is_archived:
                state = "archived" if archived else "active"
                raise JobStateError(f"analysis job is already {state}")
            if archived:
                self._connection.execute(
                    """
                    UPDATE analysis_jobs
                    SET archived_at = ?, archived_by = ?, archived_reason = ?,
                        updated_at = ?
                    WHERE job_id = ?
                    """,
                    (now, actor, normalized_reason, now, job_id),
                )
            else:
                self._connection.execute(
                    """
                    UPDATE analysis_jobs
                    SET archived_at = NULL, archived_by = NULL,
                        archived_reason = NULL, updated_at = ?
                    WHERE job_id = ?
                    """,
                    (now, job_id),
                )
        return self.get(job_id)

    @staticmethod
    def _record(
        row: sqlite3.Row,
        window_rows: list[sqlite3.Row],
    ) -> JobRecord:
        outcomes = []
        for window in window_rows:
            result = (
                json.loads(window["result_json"])
                if window["result_json"] is not None
                else None
            )
            outcomes.append(
                WindowOutcome(
                    window_id=window["window_id"],
                    mine_id=window["mine_id"],
                    status=window["status"],
                    attempt=window["attempt"],
                    payload_sha256=window["payload_sha256"],
                    result_sha256=window["result_sha256"],
                    result=result,
                    error_code=window["error_code"],
                    error_summary=window["error_summary"],
                    started_at=window["started_at"],
                    finished_at=window["finished_at"],
                )
            )
        return JobRecord(
            job_id=row["job_id"],
            idempotency_key=row["idempotency_key"],
            requested_by=row["requested_by"],
            parent_job_id=row["parent_job_id"],
            status=row["status"],
            request_sha256=row["request_sha256"],
            total_windows=row["total_windows"],
            completed_windows=row["completed_windows"],
            succeeded_windows=row["succeeded_windows"],
            failed_windows=row["failed_windows"],
            cancelled_windows=row["cancelled_windows"],
            attempt=row["attempt"],
            cancellation_requested=bool(row["cancellation_requested"]),
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            updated_at=row["updated_at"],
            archived_at=row["archived_at"],
            archived_by=row["archived_by"],
            archived_reason=row["archived_reason"],
            outcomes=outcomes,
        )

    def claim_next(self) -> str | None:
        now = _now()
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT job_id FROM analysis_jobs "
                "WHERE status = 'queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            job_id = str(row["job_id"])
            cursor = self._connection.execute(
                """
                UPDATE analysis_jobs
                SET status = 'running', attempt = attempt + 1,
                    started_at = COALESCE(started_at, ?), updated_at = ?
                WHERE job_id = ? AND status = 'queued'
                """,
                (now, now, job_id),
            )
            if cursor.rowcount != 1:
                return None
        return job_id

    def next_queued_window(
        self,
        job_id: str,
    ) -> tuple[str, dict[str, Any]] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT window_id, payload_json
                FROM analysis_job_windows
                WHERE job_id = ? AND status = 'queued'
                ORDER BY position LIMIT 1
                """,
                (job_id,),
            ).fetchone()
        if row is None:
            return None
        return str(row["window_id"]), json.loads(row["payload_json"])

    def start_window(self, job_id: str, window_id: str) -> None:
        now = _now()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE analysis_job_windows
                SET status = 'running', attempt = attempt + 1,
                    started_at = ?, finished_at = NULL,
                    error_code = NULL, error_summary = NULL
                WHERE job_id = ? AND window_id = ? AND status = 'queued'
                """,
                (now, job_id, window_id),
            )
            if cursor.rowcount != 1:
                raise JobStateError("window is not queued")

    def finish_window_success(
        self,
        job_id: str,
        window_id: str,
        result: dict[str, Any],
    ) -> None:
        now = _now()
        result_hash = sha256_json(result)
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE analysis_job_windows
                SET status = 'succeeded', result_sha256 = ?,
                    result_json = ?, finished_at = ?
                WHERE job_id = ? AND window_id = ? AND status = 'running'
                """,
                (
                    result_hash,
                    canonical_json(result),
                    now,
                    job_id,
                    window_id,
                ),
            )
            if cursor.rowcount != 1:
                raise JobStateError("window is not running")
            self._refresh_counts(job_id, now)

    def finish_window_failure(
        self,
        job_id: str,
        window_id: str,
        *,
        error_code: str,
        error_summary: str,
    ) -> None:
        now = _now()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE analysis_job_windows
                SET status = 'failed', error_code = ?, error_summary = ?,
                    finished_at = ?
                WHERE job_id = ? AND window_id = ? AND status = 'running'
                """,
                (
                    error_code[:100],
                    error_summary[:500],
                    now,
                    job_id,
                    window_id,
                ),
            )
            if cursor.rowcount != 1:
                raise JobStateError("window is not running")
            self._refresh_counts(job_id, now)

    def _refresh_counts(self, job_id: str, now: str) -> None:
        counts = self._connection.execute(
            """
            SELECT
                SUM(CASE WHEN status IN ('succeeded','failed','cancelled')
                    THEN 1 ELSE 0 END) AS completed,
                SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END)
                    AS succeeded,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
                    AS failed,
                SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END)
                    AS cancelled
            FROM analysis_job_windows WHERE job_id = ?
            """,
            (job_id,),
        ).fetchone()
        assert counts is not None
        self._connection.execute(
            """
            UPDATE analysis_jobs
            SET completed_windows = ?, succeeded_windows = ?,
                failed_windows = ?, cancelled_windows = ?, updated_at = ?
            WHERE job_id = ?
            """,
            (
                int(counts["completed"] or 0),
                int(counts["succeeded"] or 0),
                int(counts["failed"] or 0),
                int(counts["cancelled"] or 0),
                now,
                job_id,
            ),
        )

    def cancellation_requested(self, job_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT cancellation_requested FROM analysis_jobs "
                "WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        if row is None:
            raise JobNotFoundError("analysis job not found")
        return bool(row["cancellation_requested"])

    def cancel(self, job_id: str) -> JobRecord:
        now = _now()
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT status FROM analysis_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobNotFoundError("analysis job not found")
            status = str(row["status"])
            if status not in {"queued", "running"}:
                raise JobStateError("only queued or running jobs can be cancelled")
            self._connection.execute(
                "UPDATE analysis_jobs SET cancellation_requested = 1, "
                "updated_at = ? WHERE job_id = ?",
                (now, job_id),
            )
            if status == "queued":
                self._cancel_remaining(job_id, now)
        return self.get(job_id)

    def _cancel_remaining(self, job_id: str, now: str) -> None:
        self._connection.execute(
            """
            UPDATE analysis_job_windows
            SET status = 'cancelled', finished_at = ?
            WHERE job_id = ? AND status IN ('queued', 'running')
            """,
            (now, job_id),
        )
        self._refresh_counts(job_id, now)
        self._connection.execute(
            """
            UPDATE analysis_jobs
            SET status = 'cancelled', finished_at = ?, updated_at = ?
            WHERE job_id = ?
            """,
            (now, now, job_id),
        )

    def cancel_remaining(self, job_id: str) -> None:
        now = _now()
        with self._lock, self._connection:
            self._cancel_remaining(job_id, now)

    def finalize(self, job_id: str) -> JobRecord:
        now = _now()
        with self._lock, self._connection:
            row = self._connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobNotFoundError("analysis job not found")
            if bool(row["cancellation_requested"]):
                self._cancel_remaining(job_id, now)
                return self.get(job_id)
            total = int(row["total_windows"])
            succeeded = int(row["succeeded_windows"])
            failed = int(row["failed_windows"])
            completed = int(row["completed_windows"])
            if completed != total:
                raise JobStateError("job still has unfinished windows")
            if failed == 0 and succeeded == total:
                status = "succeeded"
            elif succeeded == 0:
                status = "failed"
            else:
                status = "partial_failed"
            self._connection.execute(
                """
                UPDATE analysis_jobs
                SET status = ?, finished_at = ?, updated_at = ?
                WHERE job_id = ? AND status = 'running'
                """,
                (status, now, now, job_id),
            )
        return self.get(job_id)

    def requeue_running(self, job_id: str) -> None:
        now = _now()
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE analysis_job_windows SET status = 'queued', "
                "started_at = NULL WHERE job_id = ? AND status = 'running'",
                (job_id,),
            )
            self._connection.execute(
                "UPDATE analysis_jobs SET status = 'queued', "
                "started_at = NULL, updated_at = ? "
                "WHERE job_id = ? AND status = 'running'",
                (now, job_id),
            )


class JobManager:
    """A small durable worker suitable for one MineGuard server process."""

    def __init__(
        self,
        repository: JobRepository,
        operation: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        max_pending_jobs: int = 100,
        poll_seconds: float = 0.2,
    ) -> None:
        if max_pending_jobs < 1:
            raise ValueError("max_pending_jobs must be positive")
        self.repository = repository
        self.operation = operation
        self.max_pending_jobs = max_pending_jobs
        self.poll_seconds = max(0.02, poll_seconds)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self.repository.recover_interrupted()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._worker,
            name="mineguard-analysis-worker",
            daemon=True,
        )
        self._thread.start()

    def stop(self, *, timeout: float = 10) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                raise TimeoutError("analysis worker did not stop in time")
        self._thread = None

    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def submit(
        self,
        request: AnalysisJobRequest,
    ) -> tuple[JobRecord, bool]:
        record, created = self.repository.submit(
            request,
            max_pending_jobs=self.max_pending_jobs,
        )
        self._wake.set()
        return record, created

    def get(self, job_id: str) -> JobRecord:
        return self.repository.get(job_id)

    def list(
        self,
        *,
        limit: int = 100,
        include_archived: bool = False,
    ) -> list[JobRecord]:
        return self.repository.list(
            limit=limit,
            include_archived=include_archived,
        )

    def archive(
        self,
        job_id: str,
        *,
        archived: bool,
        archived_by: str,
        reason: str,
    ) -> JobRecord:
        return self.repository.archive(
            job_id,
            archived=archived,
            archived_by=archived_by,
            reason=reason,
        )

    def cancel(self, job_id: str) -> JobRecord:
        record = self.repository.cancel(job_id)
        self._wake.set()
        return record

    def replay(
        self,
        job_id: str,
        *,
        idempotency_key: str,
        requested_by: str,
    ) -> tuple[JobRecord, bool]:
        original = self.repository.get_request(job_id)
        replay = AnalysisJobRequest(
            idempotency_key=idempotency_key,
            requested_by=requested_by,
            parent_job_id=job_id,
            windows=original.windows,
        )
        return self.submit(replay)

    def _worker(self) -> None:
        while not self._stop.is_set():
            job_id = self.repository.claim_next()
            if job_id is None:
                self._wake.wait(self.poll_seconds)
                self._wake.clear()
                continue
            self._run_job(job_id)

    def _run_job(self, job_id: str) -> None:
        try:
            while not self._stop.is_set():
                if self.repository.cancellation_requested(job_id):
                    self.repository.cancel_remaining(job_id)
                    return
                queued = self.repository.next_queued_window(job_id)
                if queued is None:
                    self.repository.finalize(job_id)
                    return
                window_id, payload = queued
                self.repository.start_window(job_id, window_id)
                try:
                    result = self.operation(payload)
                    if not isinstance(result, dict):
                        raise PublicJobError(
                            "invalid_result",
                            "analysis operation returned an invalid result",
                        )
                    self.repository.finish_window_success(
                        job_id,
                        window_id,
                        result,
                    )
                except PublicJobError as error:
                    self.repository.finish_window_failure(
                        job_id,
                        window_id,
                        error_code=error.code,
                        error_summary=error.summary,
                    )
                except Exception:
                    self.repository.finish_window_failure(
                        job_id,
                        window_id,
                        error_code="analysis_failed",
                        error_summary="analysis window failed",
                    )
            self.repository.requeue_running(job_id)
        except Exception:
            # Keep durable work retryable even if repository/finalization code
            # itself raises. Operational details belong in server logs.
            self.repository.requeue_running(job_id)


__all__ = [
    "AnalysisJobRequest",
    "AnalysisWindow",
    "JobCapacityError",
    "JobConflictError",
    "JobManager",
    "JobNotFoundError",
    "JobRecord",
    "JobRepository",
    "JobStateError",
    "PublicJobError",
    "TERMINAL_JOB_STATUSES",
    "WindowOutcome",
]
