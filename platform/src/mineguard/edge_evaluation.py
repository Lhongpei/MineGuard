"""Durable execution service for regulator-side edge safety evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import threading
from typing import Any, Callable

from pydantic import ValidationError

from .edge_ingest import EdgeTelemetryBatch, validate_edge_batch_json
from .edge_store import EdgeTelemetryRepository
from .safety_service import evaluate_edge_batch_safety


EdgeEvaluator = Callable[
    [EdgeTelemetryRepository, EdgeTelemetryBatch],
    dict[str, Any],
]


class EdgeEvaluationError(RuntimeError):
    """Base class for controlled evaluation execution failures."""


class EdgeEvaluationBatchNotFoundError(EdgeEvaluationError):
    pass


class EdgeEvaluationBusyError(EdgeEvaluationError):
    pass


class EdgeEvaluationClaimLostError(EdgeEvaluationError):
    pass


class EdgeEvaluationFailedError(EdgeEvaluationError):
    def __init__(self, error_code: str) -> None:
        super().__init__("edge safety evaluation failed")
        self.error_code = error_code


class _LeaseHeartbeat:
    def __init__(
        self,
        repository: EdgeTelemetryRepository,
        *,
        batch_id: str,
        lease_token: str,
        lease_seconds: float,
        join_timeout_seconds: float,
    ) -> None:
        self._repository = repository
        self._batch_id = batch_id
        self._lease_token = lease_token
        self._lease_seconds = lease_seconds
        self._join_timeout_seconds = join_timeout_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.lost = False
        self.stop_timed_out = False

    def __enter__(self) -> "_LeaseHeartbeat":
        self._thread = threading.Thread(
            target=self._run,
            name=f"edge-evaluation-lease-{self._batch_id[:24]}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(
        self,
        _error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: Any,
    ) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._join_timeout_seconds)
            if self._thread.is_alive():
                # Never complete a claim while its lease-renewal thread may
                # still be stuck in an external repository call.
                self.stop_timed_out = True
                self.lost = True

    def _run(self) -> None:
        interval = max(0.05, self._lease_seconds / 3.0)
        while not self._stop.wait(interval):
            try:
                renewed = self._repository.renew_batch_evaluation_lease(
                    self._batch_id,
                    self._lease_token,
                    lease_seconds=self._lease_seconds,
                )
            except Exception:
                renewed = False
            if not renewed:
                self.lost = True
                return


class EdgeSafetyEvaluationService:
    """Evaluate stored batches now and retry unfinished work in background."""

    def __init__(
        self,
        repository: EdgeTelemetryRepository,
        evaluator: EdgeEvaluator = evaluate_edge_batch_safety,
        *,
        maximum_attempts: int = 5,
        base_retry_seconds: float = 5.0,
        maximum_retry_seconds: float = 300.0,
        poll_seconds: float = 1.0,
        lease_seconds: float = 120.0,
        stop_timeout_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
        error_reporter: Callable[[str], None] | None = None,
    ) -> None:
        if maximum_attempts < 1:
            raise ValueError("maximum_attempts must be positive")
        if base_retry_seconds <= 0:
            raise ValueError("base_retry_seconds must be positive")
        if maximum_retry_seconds < base_retry_seconds:
            raise ValueError(
                "maximum_retry_seconds cannot be below base_retry_seconds"
            )
        if (
            poll_seconds <= 0
            or lease_seconds <= 0
            or stop_timeout_seconds <= 0
        ):
            raise ValueError(
                "poll_seconds, lease_seconds and stop_timeout_seconds "
                "must be positive"
            )
        self.repository = repository
        self._evaluator = evaluator
        self.maximum_attempts = maximum_attempts
        self.base_retry_seconds = base_retry_seconds
        self.maximum_retry_seconds = maximum_retry_seconds
        self.poll_seconds = poll_seconds
        self.lease_seconds = lease_seconds
        self.stop_timeout_seconds = stop_timeout_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._error_reporter = error_reporter
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._state_lock = threading.RLock()
        self._last_worker_error: str | None = None
        self._lifecycle_error: str | None = None

    @property
    def last_worker_error(self) -> str | None:
        with self._state_lock:
            return self._lifecycle_error or self._last_worker_error

    @property
    def shutdown_timed_out(self) -> bool:
        with self._state_lock:
            return (
                self._lifecycle_error == "EdgeEvaluationStopTimeout"
                and self.is_running()
            )

    def is_running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        with self._state_lock:
            if self.is_running():
                return
            self._stop.clear()
            self._wake.clear()
            self._lifecycle_error = None
            self._last_worker_error = None
            self._thread = threading.Thread(
                target=self._run,
                name="mineguard-edge-safety-evaluation",
                daemon=True,
            )
            self._thread.start()

    def stop(self, *, timeout_seconds: float | None = None) -> bool:
        selected_timeout = (
            self.stop_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        if selected_timeout <= 0:
            raise ValueError("stop timeout_seconds must be positive")
        with self._state_lock:
            thread = self._thread
            if thread is None:
                return True
            self._stop.set()
            self._wake.set()
            if thread is threading.current_thread():
                self._lifecycle_error = "EdgeEvaluationSelfStopRejected"
                return False
        thread.join(timeout=selected_timeout)
        with self._state_lock:
            if thread.is_alive():
                # Keep the live thread reference.  is_running() and the
                # existing readiness callback will therefore report a running
                # but degraded service instead of a false clean shutdown.
                self._lifecycle_error = "EdgeEvaluationStopTimeout"
                return False
            if self._thread is thread:
                self._thread = None
        return True

    def notify(self) -> None:
        self._wake.set()

    def evaluate_batch(
        self,
        batch_id: str,
        *,
        trigger: str,
    ) -> dict[str, Any] | None:
        if trigger not in {"intake", "manual"}:
            raise ValueError("unsupported evaluation trigger")
        try:
            claim = self.repository.claim_batch_evaluation(
                batch_id,
                trigger=trigger,
                maximum_attempts=self.maximum_attempts,
                lease_seconds=self.lease_seconds,
                force=True,
                reset_terminal=trigger == "manual",
                now=self._now(),
            )
        except KeyError as error:
            raise EdgeEvaluationBatchNotFoundError(batch_id) from error
        if claim is None:
            current = self.repository.get_batch_evaluation(batch_id)
            if trigger == "manual" or (
                current is not None and current["status"] == "running"
            ):
                raise EdgeEvaluationBusyError(
                    "edge safety evaluation is already running"
                )
            return None
        try:
            return self._execute_claim(claim)
        finally:
            self.notify()

    def process_once(self) -> bool:
        claim = self.repository.claim_next_batch_evaluation(
            maximum_attempts=self.maximum_attempts,
            lease_seconds=self.lease_seconds,
            now=self._now(),
        )
        if claim is None:
            return False
        try:
            self._execute_claim(claim)
        except (EdgeEvaluationFailedError, EdgeEvaluationClaimLostError):
            pass
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                processed = self.process_once()
                with self._state_lock:
                    self._last_worker_error = None
            except Exception as error:
                processed = False
                error_code = type(error).__name__[:128]
                with self._state_lock:
                    self._last_worker_error = error_code
                self._report_error(
                    "edge safety evaluation worker queue processing failed"
                )
            if processed:
                continue
            self._wake.wait(self.poll_seconds)
            self._wake.clear()

    def _execute_claim(
        self,
        claim: dict[str, Any],
    ) -> dict[str, Any]:
        batch_id = str(claim["batch_id"])
        lease_token = str(claim["lease_token"])
        heartbeat = _LeaseHeartbeat(
            self.repository,
            batch_id=batch_id,
            lease_token=lease_token,
            lease_seconds=self.lease_seconds,
            join_timeout_seconds=min(
                self.stop_timeout_seconds,
                1.0,
            ),
        )
        try:
            with heartbeat:
                batch = self._validated_batch(claim["document"])
                observations = self._accepted_latest_observations(batch)
                if not observations:
                    result: dict[str, Any] = {
                        "status": "no_new_accepted_observations",
                        "mine_id": batch.mine_id,
                        "alert_ids": [],
                    }
                else:
                    evaluation_batch = batch.model_copy(
                        update={
                            "observations": observations,
                            "local_alerts": [],
                            "sequence_start": min(
                                item.sequence_no for item in observations
                            ),
                            "sequence_end": max(
                                item.sequence_no for item in observations
                            ),
                        }
                    )
                    result = self._evaluator(
                        self.repository,
                        evaluation_batch,
                    )
                    if not isinstance(result, dict):
                        raise TypeError(
                            "edge evaluator must return a dictionary"
                        )
        except EdgeEvaluationClaimLostError:
            raise
        except Exception as error:
            if heartbeat.stop_timed_out:
                self._record_lifecycle_error(
                    "EdgeEvaluationLeaseHeartbeatStopTimeout"
                )
            if heartbeat.lost:
                raise EdgeEvaluationClaimLostError(
                    "edge evaluation lease was lost"
                ) from error
            self._finish_failure(claim, error)
            raise EdgeEvaluationFailedError(
                type(error).__name__[:128]
            ) from error
        if heartbeat.stop_timed_out:
            self._record_lifecycle_error(
                "EdgeEvaluationLeaseHeartbeatStopTimeout"
            )
        if heartbeat.lost:
            raise EdgeEvaluationClaimLostError(
                "edge evaluation lease was lost"
            )
        result_status = str(result.get("status") or "unknown")[:128]
        completed = self.repository.finish_batch_evaluation(
            batch_id,
            lease_token,
            succeeded=True,
            maximum_attempts=self.maximum_attempts,
            result_status=result_status,
            now=self._now(),
        )
        if completed is None or completed["status"] != "completed":
            raise EdgeEvaluationClaimLostError(
                "edge evaluation completion claim was lost"
            )
        try:
            self.repository.auto_resolve_platform_alert(
                mine_id=str(claim["mine_id"]),
                category="data_quality",
                rule_code="platform_safety_recalculation_failed",
                location_code=batch_id,
                note="该批次平台安全复算已成功完成。",
            )
        except Exception:
            self._report_error(
                "completed edge evaluation failure alert reconciliation failed"
            )
        return result

    def _finish_failure(
        self,
        claim: dict[str, Any],
        error: Exception,
    ) -> None:
        batch_id = str(claim["batch_id"])
        attempts = int(claim["attempts"])
        error_code = type(error).__name__[:128]
        delay = min(
            self.maximum_retry_seconds,
            self.base_retry_seconds
            * (2 ** min(30, max(0, attempts - 1))),
        )
        retry_at = self._now() + timedelta(seconds=delay)
        failed = self.repository.finish_batch_evaluation(
            batch_id,
            str(claim["lease_token"]),
            succeeded=False,
            maximum_attempts=self.maximum_attempts,
            error_code=error_code,
            retry_at=retry_at,
            now=self._now(),
        )
        if failed is None:
            raise EdgeEvaluationClaimLostError(
                "edge evaluation failure claim was lost"
            ) from error
        observation_ids = self._raw_observation_ids(claim["document"])
        try:
            self.repository.upsert_platform_alert(
                mine_id=str(claim["mine_id"]),
                category="data_quality",
                rule_code="platform_safety_recalculation_failed",
                level="blue",
                title="平台安全复算失败",
                summary=(
                    "原始批次已留存，但本批平台独立复算未完成。"
                    "平台将按退避策略自动重试；死信需人工受控重算，"
                    "不能显示为正常。"
                ),
                location_code=batch_id,
                detected_at=self._now(),
                observation_ids=observation_ids,
                details={
                    "batch_id": batch_id,
                    "error_code": error_code,
                    "attempts": failed["attempts"],
                    "maximum_attempts": self.maximum_attempts,
                    "evaluation_status": failed["status"],
                    "next_attempt_at": failed["next_attempt_at"],
                    "advisory_only": True,
                    "production_control_permitted": False,
                },
                rule_profile={
                    "version": "platform-evaluation-runtime-v2",
                    "fingerprint": hashlib.sha256(
                        b"platform-evaluation-runtime-v2"
                    ).hexdigest(),
                },
            )
        except Exception:
            self._report_error(
                "failed to persist edge safety evaluation failure alert"
            )

    def _accepted_latest_observations(
        self,
        batch: EdgeTelemetryBatch,
    ) -> list[Any]:
        keys = self.repository.batch_evaluation_observation_keys(
            batch.batch_id
        )
        latest: dict[str, Any] = {}
        for item in batch.observations:
            if (item.observation_id, item.revision) not in keys:
                continue
            previous = latest.get(item.observation_id)
            if previous is None or item.revision > previous.revision:
                latest[item.observation_id] = item
        return list(latest.values())

    @staticmethod
    def _validated_batch(document: dict[str, Any]) -> EdgeTelemetryBatch:
        try:
            return validate_edge_batch_json(
                json.dumps(
                    document,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                allow_legacy_batch_id=True,
            )
        except (ValueError, ValidationError) as error:
            raise ValueError("stored edge batch is invalid") from error

    @staticmethod
    def _raw_observation_ids(document: Any) -> list[str]:
        if not isinstance(document, dict):
            return []
        observations = document.get("observations")
        if not isinstance(observations, list):
            return []
        result: list[str] = []
        for item in observations:
            if not isinstance(item, dict):
                continue
            observation_id = item.get("observation_id")
            if isinstance(observation_id, str) and observation_id:
                result.append(observation_id)
        return sorted(set(result))[:10_000]

    def _now(self) -> datetime:
        return self._clock().astimezone(UTC)

    def _report_error(self, message: str) -> None:
        if self._error_reporter is None:
            return
        try:
            self._error_reporter(message)
        except Exception:
            pass

    def _record_lifecycle_error(self, error_code: str) -> None:
        with self._state_lock:
            self._lifecycle_error = error_code[:128]
