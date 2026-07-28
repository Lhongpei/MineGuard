from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from mineguard.jobs import (
    AnalysisJobRequest,
    AnalysisWindow,
    JobConflictError,
    JobManager,
    JobRepository,
    JobStateError,
    PublicJobError,
)


def _request(
    key: str = "job-key",
    *,
    values: tuple[int, ...] = (1, 2),
) -> AnalysisJobRequest:
    return AnalysisJobRequest(
        idempotency_key=key,
        requested_by="reviewer",
        windows=[
            AnalysisWindow(
                window_id=f"window-{index}",
                mine_id=f"M{index:03d}",
                payload={"value": value},
            )
            for index, value in enumerate(values, start=1)
        ],
    )


def _wait_terminal(
    manager: JobManager,
    job_id: str,
    timeout: float = 5,
):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        record = manager.get(job_id)
        if record.status in {
            "succeeded",
            "partial_failed",
            "failed",
            "cancelled",
        }:
            return record
        time.sleep(0.02)
    raise AssertionError("job did not reach a terminal state")


def test_job_runs_every_window_and_is_idempotent(tmp_path: Path) -> None:
    repository = JobRepository(tmp_path / "jobs.sqlite3")
    manager = JobManager(
        repository,
        lambda payload: {"doubled": payload["value"] * 2},
    )
    manager.start()
    try:
        record, created = manager.submit(_request())
        assert created
        finished = _wait_terminal(manager, record.job_id)
        assert finished.status == "succeeded"
        assert finished.succeeded_windows == 2
        assert [outcome.result for outcome in finished.outcomes] == [
            {"doubled": 2},
            {"doubled": 4},
        ]
        same, created_again = manager.submit(_request())
        assert not created_again
        assert same.job_id == record.job_id
    finally:
        manager.stop()
        repository.close()


def test_idempotency_key_rejects_different_payload(tmp_path: Path) -> None:
    repository = JobRepository(tmp_path / "conflict.sqlite3")
    try:
        repository.submit(_request(), max_pending_jobs=10)
        with pytest.raises(JobConflictError):
            repository.submit(
                _request(values=(9,)),
                max_pending_jobs=10,
            )
    finally:
        repository.close()


def test_window_failures_are_isolated_and_public_errors_are_stable(
    tmp_path: Path,
) -> None:
    def operation(payload):
        if payload["value"] == 2:
            raise PublicJobError("bad_window", "该窗口输入不可用")
        return {"value": payload["value"]}

    repository = JobRepository(tmp_path / "partial.sqlite3")
    manager = JobManager(repository, operation)
    manager.start()
    try:
        submitted, _ = manager.submit(_request(values=(1, 2, 3)))
        finished = _wait_terminal(manager, submitted.job_id)
        assert finished.status == "partial_failed"
        assert finished.succeeded_windows == 2
        assert finished.failed_windows == 1
        failed = next(
            outcome
            for outcome in finished.outcomes
            if outcome.status == "failed"
        )
        assert failed.error_code == "bad_window"
        assert failed.error_summary == "该窗口输入不可用"
    finally:
        manager.stop()
        repository.close()


def test_queued_job_can_be_cancelled_without_losing_outcomes(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "cancel.sqlite3")
    manager = JobManager(repository, lambda payload: payload)
    try:
        submitted, _ = manager.submit(_request())
        cancelled = manager.cancel(submitted.job_id)
        assert cancelled.status == "cancelled"
        assert cancelled.cancelled_windows == 2
        assert all(
            outcome.status == "cancelled"
            for outcome in cancelled.outcomes
        )
    finally:
        repository.close()


def test_interrupted_running_job_is_recovered_after_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "recover.sqlite3"
    first = JobRepository(database)
    submitted, _ = first.submit(_request(), max_pending_jobs=10)
    assert first.claim_next() == submitted.job_id
    queued = first.next_queued_window(submitted.job_id)
    assert queued is not None
    first.start_window(submitted.job_id, queued[0])
    first.close()

    reopened = JobRepository(database)
    manager = JobManager(
        reopened,
        lambda payload: {"value": payload["value"]},
    )
    manager.start()
    try:
        finished = _wait_terminal(manager, submitted.job_id)
        assert finished.status == "succeeded"
        assert finished.attempt == 2
        assert finished.outcomes[0].attempt == 2
    finally:
        manager.stop()
        reopened.close()


def test_replay_creates_linked_job_with_new_idempotency_key(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "replay.sqlite3")
    manager = JobManager(repository, lambda payload: dict(payload))
    manager.start()
    try:
        original, _ = manager.submit(_request())
        _wait_terminal(manager, original.job_id)
        replay, created = manager.replay(
            original.job_id,
            idempotency_key="replay-key",
            requested_by="supervisor",
        )
        assert created
        assert replay.parent_job_id == original.job_id
        finished = _wait_terminal(manager, replay.job_id)
        assert finished.status == "succeeded"
        assert finished.requested_by == "supervisor"
    finally:
        manager.stop()
        repository.close()


def test_terminal_jobs_can_be_soft_archived_and_restored(
    tmp_path: Path,
) -> None:
    repository = JobRepository(tmp_path / "archive.sqlite3")
    try:
        submitted, _ = repository.submit(_request(), max_pending_jobs=10)
        with pytest.raises(JobStateError, match="only terminal"):
            repository.archive(
                submitted.job_id,
                archived=True,
                archived_by="supervisor",
                reason="季度任务清理",
            )

        repository.cancel(submitted.job_id)
        archived = repository.archive(
            submitted.job_id,
            archived=True,
            archived_by=" supervisor ",
            reason=" 季度任务清理 ",
        )
        assert archived.archived_at is not None
        assert archived.archived_by == "supervisor"
        assert archived.archived_reason == "季度任务清理"
        assert repository.get(submitted.job_id).job_id == submitted.job_id
        assert repository.list() == []
        assert [item.job_id for item in repository.list(
            include_archived=True
        )] == [submitted.job_id]

        with pytest.raises(JobStateError, match="already archived"):
            repository.archive(
                submitted.job_id,
                archived=True,
                archived_by="supervisor",
                reason="重复操作",
            )

        restored = repository.archive(
            submitted.job_id,
            archived=False,
            archived_by="supervisor",
            reason="恢复复核",
        )
        assert restored.archived_at is None
        assert restored.archived_by is None
        assert restored.archived_reason is None
        assert [item.job_id for item in repository.list()] == [
            submitted.job_id
        ]
    finally:
        repository.close()


def test_existing_job_database_is_migrated_for_soft_archive(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE analysis_jobs (
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
            updated_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    connection.close()

    repository = JobRepository(database)
    repository.close()
    reopened = sqlite3.connect(database)
    try:
        columns = {
            str(row[1])
            for row in reopened.execute(
                "PRAGMA table_info(analysis_jobs)"
            ).fetchall()
        }
        assert {"archived_at", "archived_by", "archived_reason"} <= columns
    finally:
        reopened.close()
