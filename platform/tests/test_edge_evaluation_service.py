from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any
from uuid import uuid4

import pytest

import mineguard.api as api_module
from mineguard.api import create_server
from mineguard.edge_evaluation import (
    EdgeEvaluationBusyError,
    EdgeEvaluationClaimLostError,
    EdgeEvaluationFailedError,
    EdgeSafetyEvaluationService,
)
from mineguard.edge_ingest import EdgeTelemetryBatch
from mineguard.edge_store import EdgeTelemetryRepository


WEB_APP = Path(__file__).resolve().parents[1] / "src/mineguard/web/app.js"
WEB_INDEX = Path(__file__).resolve().parents[1] / "src/mineguard/web/index.html"


def _document(
    *,
    mine_id: str = "M001",
    batch_id: str | None = None,
) -> dict[str, Any]:
    client_id = f"client-{mine_id}"
    batch_seed = batch_id or f"evaluation-{uuid4()}"
    selected_batch_id = (
        f"{client_id}--batch_"
        f"{hashlib.sha256(batch_seed.encode()).hexdigest()[:32]}"
    )
    now = datetime.now(UTC).isoformat()
    return {
        "schema_version": "edge-telemetry-batch-v1",
        "batch_id": selected_batch_id,
        "client_id": client_id,
        "mine_id": mine_id,
        "sent_at": now,
        "sequence_start": 1,
        "sequence_end": 1,
        "rule_profile": {
            "profile_id": "evaluation-test",
            "version": 1,
            "sha256": "a" * 64,
        },
        "observations": [
            {
                "source_id": "personnel-total",
                "observation_id": f"{selected_batch_id}-observation",
                "metric_code": "personnel.underground_count",
                "value": 50,
                "unit": "person",
                "location_code": "underground-total",
                "observed_at": now,
                "received_at": now,
                "sequence_no": 1,
                "revision": 0,
                "acquisition_mode": "api_poll",
                "source_record_id": f"source-{selected_batch_id}",
                "source_record_sha256": "b" * 64,
                "source_signature": None,
                "status_code": "online",
                "quality": {
                    "valid": True,
                    "completeness": 1.0,
                    "timeliness": 1.0,
                    "device_health": "healthy",
                    "clock_synchronized": True,
                    "flags": [],
                },
                "manual_attestation": None,
            }
        ],
        "local_alerts": [],
    }


def _ingest(
    repository: EdgeTelemetryRepository,
    document: dict[str, Any],
) -> None:
    raw = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    repository.ingest_batch(
        EdgeTelemetryBatch.model_validate(document),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        raw_body=raw,
    )


def _wait_for(
    predicate: Any,
    *,
    timeout: float = 3.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition was not reached before timeout")


def _failure_alert(
    repository: EdgeTelemetryRepository,
) -> dict[str, Any]:
    return next(
        item
        for item in repository.list_alerts(limit=100)
        if item["rule_code"] == "platform_safety_recalculation_failed"
    )


def test_existing_edge_database_is_migrated_to_durable_queue(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """
            CREATE TABLE edge_batches (
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
                rejection_details_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO edge_batches VALUES (
                'receipt-legacy', 'batch-legacy', 'client-legacy',
                'M001', ?, 'accepted', ?, 1, 0, 1, 1, '{}', '{}', '[]'
            )
            """,
            (
                "a" * 64,
                datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    repository = EdgeTelemetryRepository(database)
    try:
        evaluation = repository.get_batch_evaluation("batch-legacy")
        assert evaluation is not None
        assert evaluation["status"] == "pending"
        assert evaluation["attempts"] == 0
        assert repository.evaluation_health()["backlog"] == 1
    finally:
        repository.close()


def test_leadership_dashboard_distinguishes_retry_and_dead_letter() -> None:
    script = WEB_APP.read_text(encoding="utf-8")
    page = WEB_INDEX.read_text(encoding="utf-8")

    assert "evaluationHealth.dead" in script
    assert "evaluationHealth.backlog" in script
    assert "正在按退避策略自动重试" in script
    assert "平台安全复算已进入死信" in script
    assert "失败预警保持开放" in script
    assert 'edgeEvaluations: "/v1/edge-evaluation-batches"' in script
    assert "handleEdgeEvaluationAction" in script
    assert "受控重算" in script
    assert 'id="edge-evaluation-body"' in page


def test_background_worker_retries_with_backoff_and_resolves_alert(
    tmp_path: Path,
) -> None:
    repository = EdgeTelemetryRepository(tmp_path / "edge.db")
    document = _document()
    _ingest(repository, document)
    calls = 0

    def evaluator(
        _repository: EdgeTelemetryRepository,
        batch: EdgeTelemetryBatch,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("transient")
        return {
            "status": "evaluated",
            "mine_id": batch.mine_id,
            "alert_ids": [],
        }

    service = EdgeSafetyEvaluationService(
        repository,
        evaluator,
        maximum_attempts=3,
        base_retry_seconds=0.02,
        maximum_retry_seconds=0.04,
        poll_seconds=0.005,
        lease_seconds=0.5,
    )
    try:
        with pytest.raises(EdgeEvaluationFailedError):
            service.evaluate_batch(
                document["batch_id"],
                trigger="intake",
            )
        failed = repository.get_batch_evaluation(document["batch_id"])
        assert failed is not None
        assert failed["status"] == "failed"
        assert failed["attempts"] == 1
        assert failed["next_attempt_at"] is not None
        assert _failure_alert(repository)["status"] == "open"

        service.start()
        _wait_for(
            lambda: repository.get_batch_evaluation(
                document["batch_id"]
            )["status"]
            == "completed"
        )
        completed = repository.get_batch_evaluation(document["batch_id"])
        assert completed is not None
        assert completed["attempts"] == 2
        assert calls == 2
        assert _failure_alert(repository)["status"] == "resolved"
    finally:
        service.stop()
        repository.close()


def test_worker_honours_exponential_backoff_and_attempt_cap(
    tmp_path: Path,
) -> None:
    repository = EdgeTelemetryRepository(tmp_path / "edge.db")
    document = _document()
    _ingest(repository, document)
    current = [datetime(2026, 7, 28, 12, 0, tzinfo=UTC)]
    calls = 0

    def evaluator(*_args: Any) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        raise RuntimeError("retry")

    service = EdgeSafetyEvaluationService(
        repository,
        evaluator,
        maximum_attempts=3,
        base_retry_seconds=10,
        maximum_retry_seconds=15,
        poll_seconds=1,
        lease_seconds=120,
        clock=lambda: current[0],
    )
    try:
        with pytest.raises(EdgeEvaluationFailedError):
            service.evaluate_batch(
                document["batch_id"],
                trigger="intake",
            )
        first = repository.get_batch_evaluation(document["batch_id"])
        assert first is not None
        assert first["next_attempt_at"] == (
            current[0] + timedelta(seconds=10)
        ).isoformat().replace("+00:00", "Z")
        assert service.process_once() is False
        assert calls == 1

        current[0] += timedelta(seconds=10)
        assert service.process_once() is True
        second = repository.get_batch_evaluation(document["batch_id"])
        assert second is not None
        assert second["attempts"] == 2
        assert second["next_attempt_at"] == (
            current[0] + timedelta(seconds=15)
        ).isoformat().replace("+00:00", "Z")
        assert service.process_once() is False

        current[0] += timedelta(seconds=15)
        assert service.process_once() is True
        dead = repository.get_batch_evaluation(document["batch_id"])
        assert dead is not None
        assert dead["status"] == "dead"
        assert dead["attempts"] == 3
        assert dead["next_attempt_at"] is None
        assert calls == 3
    finally:
        repository.close()


def test_maximum_attempts_becomes_dead_and_manual_retry_recovers(
    tmp_path: Path,
) -> None:
    repository = EdgeTelemetryRepository(tmp_path / "edge.db")
    document = _document()
    _ingest(repository, document)
    should_fail = True
    calls = 0

    def evaluator(
        _repository: EdgeTelemetryRepository,
        batch: EdgeTelemetryBatch,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if should_fail:
            raise OSError("persistent")
        return {
            "status": "evaluated",
            "mine_id": batch.mine_id,
            "alert_ids": [],
        }

    service = EdgeSafetyEvaluationService(
        repository,
        evaluator,
        maximum_attempts=3,
        base_retry_seconds=0.01,
        maximum_retry_seconds=0.02,
        poll_seconds=0.005,
        lease_seconds=0.5,
    )
    try:
        service.start()
        with pytest.raises(EdgeEvaluationFailedError):
            service.evaluate_batch(
                document["batch_id"],
                trigger="intake",
            )
        _wait_for(
            lambda: repository.get_batch_evaluation(
                document["batch_id"]
            )["status"]
            == "dead"
        )
        dead = repository.get_batch_evaluation(document["batch_id"])
        assert dead is not None
        assert dead["attempts"] == 3
        assert calls == 3
        assert repository.evaluation_health()["dead"] == 1
        assert repository.evaluation_health()["backlog"] == 0
        assert _failure_alert(repository)["status"] == "open"

        should_fail = False
        result = service.evaluate_batch(
            document["batch_id"],
            trigger="manual",
        )
        assert result is not None
        assert result["status"] == "evaluated"
        recovered = repository.get_batch_evaluation(document["batch_id"])
        assert recovered is not None
        assert recovered["status"] == "completed"
        assert recovered["attempts"] == 1
        assert _failure_alert(repository)["status"] == "resolved"
    finally:
        service.stop()
        repository.close()


def test_expired_lease_is_recovered_after_process_restart(
    tmp_path: Path,
) -> None:
    database = tmp_path / "edge.db"
    document = _document()
    first = EdgeTelemetryRepository(database)
    _ingest(first, document)
    claim = first.claim_batch_evaluation(
        document["batch_id"],
        trigger="intake",
        maximum_attempts=3,
        lease_seconds=0.05,
        force=True,
    )
    assert claim is not None
    assert claim["attempts"] == 1
    contender = EdgeTelemetryRepository(database)
    try:
        assert (
            contender.claim_batch_evaluation(
                document["batch_id"],
                trigger="intake",
                maximum_attempts=3,
                lease_seconds=0.05,
                force=True,
            )
            is None
        )
    finally:
        contender.close()
    first.close()

    time.sleep(0.07)
    second = EdgeTelemetryRepository(database)
    calls = 0

    def evaluator(
        _repository: EdgeTelemetryRepository,
        batch: EdgeTelemetryBatch,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {
            "status": "evaluated",
            "mine_id": batch.mine_id,
            "alert_ids": [],
        }

    service = EdgeSafetyEvaluationService(
        second,
        evaluator,
        maximum_attempts=3,
        base_retry_seconds=0.01,
        maximum_retry_seconds=0.02,
        poll_seconds=0.005,
        lease_seconds=0.5,
    )
    try:
        service.start()
        _wait_for(
            lambda: second.get_batch_evaluation(
                document["batch_id"]
            )["status"]
            == "completed"
        )
        completed = second.get_batch_evaluation(document["batch_id"])
        assert completed is not None
        assert completed["attempts"] == 2
        assert calls == 1
    finally:
        service.stop()
        second.close()


def test_concurrent_manual_evaluation_is_serialized_per_mine(
    tmp_path: Path,
) -> None:
    repository = EdgeTelemetryRepository(tmp_path / "edge.db")
    first = _document(batch_id="concurrent-first")
    second = _document(batch_id="concurrent-second")
    _ingest(repository, first)
    _ingest(repository, second)
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def evaluator(
        _repository: EdgeTelemetryRepository,
        batch: EdgeTelemetryBatch,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        entered.set()
        assert release.wait(timeout=2)
        return {
            "status": "evaluated",
            "mine_id": batch.mine_id,
            "alert_ids": [],
        }

    service = EdgeSafetyEvaluationService(
        repository,
        evaluator,
        poll_seconds=0.01,
        lease_seconds=0.3,
    )
    errors: list[BaseException] = []

    def run_first() -> None:
        try:
            service.evaluate_batch(
                first["batch_id"],
                trigger="manual",
            )
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run_first)
    thread.start()
    try:
        assert entered.wait(timeout=2)
        with pytest.raises(EdgeEvaluationBusyError):
            service.evaluate_batch(
                first["batch_id"],
                trigger="manual",
            )
        with pytest.raises(EdgeEvaluationBusyError):
            service.evaluate_batch(
                second["batch_id"],
                trigger="manual",
            )
        assert calls == 1
    finally:
        release.set()
        thread.join(timeout=2)
        repository.close()
    assert not thread.is_alive()
    assert errors == []


def test_lost_success_claim_does_not_resolve_failure_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = EdgeTelemetryRepository(tmp_path / "edge.db")
    document = _document()
    _ingest(repository, document)

    failing = EdgeSafetyEvaluationService(
        repository,
        lambda *_args: (_ for _ in ()).throw(RuntimeError("failure")),
        maximum_attempts=3,
        base_retry_seconds=0.01,
        maximum_retry_seconds=0.02,
        poll_seconds=0.01,
        lease_seconds=0.5,
    )
    with pytest.raises(EdgeEvaluationFailedError):
        failing.evaluate_batch(document["batch_id"], trigger="intake")
    assert _failure_alert(repository)["status"] == "open"

    original_finish = repository.finish_batch_evaluation

    def lose_success(*args: Any, **kwargs: Any) -> Any:
        if kwargs.get("succeeded"):
            return None
        return original_finish(*args, **kwargs)

    monkeypatch.setattr(
        repository,
        "finish_batch_evaluation",
        lose_success,
    )
    succeeding = EdgeSafetyEvaluationService(
        repository,
        lambda _repository, batch: {
            "status": "evaluated",
            "mine_id": batch.mine_id,
            "alert_ids": [],
        },
        maximum_attempts=3,
        base_retry_seconds=0.01,
        maximum_retry_seconds=0.02,
        poll_seconds=0.01,
        lease_seconds=0.5,
    )
    try:
        with pytest.raises(EdgeEvaluationClaimLostError):
            succeeding.evaluate_batch(
                document["batch_id"],
                trigger="manual",
            )
        assert _failure_alert(repository)["status"] == "open"
    finally:
        repository.close()


def test_server_lifecycle_and_readiness_distinguish_backlog_and_dead(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        api_module,
        "evaluate_edge_batch_safety",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("dead-letter-test")
        ),
    )
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        edge_evaluation_maximum_attempts=1,
        edge_evaluation_base_retry_seconds=0.01,
        edge_evaluation_maximum_retry_seconds=0.02,
        edge_evaluation_poll_seconds=0.01,
        edge_evaluation_lease_seconds=0.5,
    )
    service = server.edge_evaluation_service
    try:
        assert service.is_running()
        document = _document()
        _ingest(server.edge_repository, document)
        readiness = server.readiness.readiness()
        evaluation_check = next(
            item
            for item in readiness["checks"]
            if item["name"] == "edge_safety_evaluation"
        )
        assert evaluation_check["status"] == "degraded"
        assert "等待安全复算" in evaluation_check["message"]

        with pytest.raises(EdgeEvaluationFailedError):
            service.evaluate_batch(
                document["batch_id"],
                trigger="intake",
            )
        readiness = server.readiness.readiness()
        evaluation_check = next(
            item
            for item in readiness["checks"]
            if item["name"] == "edge_safety_evaluation"
        )
        assert evaluation_check["status"] == "degraded"
        assert "死信" in evaluation_check["message"]
        assert _failure_alert(server.edge_repository)["status"] == "open"
    finally:
        server.server_close()
    assert not service.is_running()


def test_stop_is_bounded_and_readiness_exposes_stuck_worker(
    tmp_path: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocking_evaluator(
        _repository: EdgeTelemetryRepository,
        batch: EdgeTelemetryBatch,
    ) -> dict[str, Any]:
        entered.set()
        release.wait()
        return {
            "status": "evaluated",
            "mine_id": batch.mine_id,
            "alert_ids": [],
        }

    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "bounded-stop.db",
    )
    service = server.edge_evaluation_service
    service._evaluator = blocking_evaluator
    try:
        document = _document()
        _ingest(server.edge_repository, document)
        service.notify()
        assert entered.wait(timeout=2)

        started = time.monotonic()
        assert service.stop(timeout_seconds=0.03) is False
        elapsed = time.monotonic() - started

        assert elapsed < 0.5
        assert service.is_running()
        assert service.shutdown_timed_out is True
        assert service.last_worker_error == "EdgeEvaluationStopTimeout"
        readiness = server.readiness.readiness()
        evaluation_check = next(
            item
            for item in readiness["checks"]
            if item["name"] == "edge_safety_evaluation"
        )
        assert evaluation_check["status"] == "degraded"
        assert "线程仍在运行" in evaluation_check["message"]
    finally:
        release.set()
        _wait_for(lambda: not service.is_running())
        assert service.stop(timeout_seconds=0.2) is True
        server.server_close()


def test_blocked_lease_heartbeat_exit_is_bounded_and_claim_not_completed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = EdgeTelemetryRepository(tmp_path / "heartbeat-stop.db")
    document = _document()
    _ingest(repository, document)
    renew_entered = threading.Event()
    release_renewal = threading.Event()

    def blocked_renewal(*_args: Any, **_kwargs: Any) -> bool:
        renew_entered.set()
        release_renewal.wait()
        return True

    monkeypatch.setattr(
        repository,
        "renew_batch_evaluation_lease",
        blocked_renewal,
    )

    def evaluator(
        _repository: EdgeTelemetryRepository,
        batch: EdgeTelemetryBatch,
    ) -> dict[str, Any]:
        assert renew_entered.wait(timeout=1)
        return {
            "status": "evaluated",
            "mine_id": batch.mine_id,
            "alert_ids": [],
        }

    service = EdgeSafetyEvaluationService(
        repository,
        evaluator,
        lease_seconds=0.06,
        stop_timeout_seconds=0.02,
    )
    try:
        started = time.monotonic()
        with pytest.raises(EdgeEvaluationClaimLostError):
            service.evaluate_batch(
                document["batch_id"],
                trigger="intake",
            )
        elapsed = time.monotonic() - started
        evaluation = repository.get_batch_evaluation(
            document["batch_id"]
        )

        assert elapsed < 0.5
        assert service.last_worker_error == (
            "EdgeEvaluationLeaseHeartbeatStopTimeout"
        )
        assert evaluation is not None
        assert evaluation["status"] == "running"
    finally:
        release_renewal.set()
        time.sleep(0.03)
        repository.close()
