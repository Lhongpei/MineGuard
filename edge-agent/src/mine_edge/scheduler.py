"""Independent multi-source scheduling and health isolation.

Each configured source owns one scheduler thread. A slow or failing source can
therefore change only its own state; it cannot block another source or the
separate store-and-forward loop.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import random
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from .adapters import (
    FileDropAdapter,
    HttpPollAdapter,
    JsonlAdapter,
    RawRecord,
    ReadOnlyAdapter,
)
from .errors import AdapterError, ValidationError
from .models import utc_now
from .service import EdgeService
from .settings import SourceSettings

AdapterFactory = Callable[[SourceSettings], ReadOnlyAdapter]


@dataclasses.dataclass(slots=True)
class _RuntimeState:
    enabled: bool
    in_flight: bool = False
    last_heartbeat_at: str | None = None
    last_attempt_at: str | None = None
    last_success_at: str | None = None
    last_data_at: str | None = None
    last_error: str | None = None
    next_run_at: str | None = None
    consecutive_failures: int = 0
    attempts: int = 0
    successful_polls: int = 0
    records_received: int = 0
    records_inserted: int = 0
    records_duplicate: int = 0
    records_rejected: int = 0
    alerts_created: int = 0
    last_record_count: int = 0
    last_duration_ms: int | None = None
    partial_failure: bool = False
    health_telemetry_last_emitted_at: str | None = None
    health_telemetry_last_error: str | None = None
    health_telemetry_consecutive_failures: int = 0
    health_observations_inserted: int = 0
    health_observations_duplicate: int = 0
    methane_sampling_accelerated_until: str | None = None
    methane_sampling_last_trigger_at: str | None = None
    methane_sampling_last_trigger_reason: str | None = None
    methane_sampling_last_value_percent: float | None = None
    methane_sampling_trigger_threshold_percent: float | None = None
    methane_sampling_trigger_count: int = 0
    methane_sampling_restored_after_restart: bool = False
    methane_sampling_state_error: str | None = None


class _UnavailableAdapter(ReadOnlyAdapter):
    def __init__(self, message: str) -> None:
        self.message = message

    def poll(self) -> list[RawRecord]:
        raise AdapterError(self.message)


class _AllRecordsRejected(AdapterError):
    def __init__(self, message: str, count: int) -> None:
        super().__init__(message)
        self.count = count


def build_adapter(config: SourceSettings) -> ReadOnlyAdapter:
    if config.adapter == "jsonl":
        return JsonlAdapter(config.location, source_id=config.source_id)
    if config.adapter == "file-drop":
        return FileDropAdapter(config.location, source_id=config.source_id)
    token = None
    if config.token_env:
        token = os.environ.get(config.token_env)
        if not token:
            raise AdapterError(
                f"来源 {config.source_id} 所需环境变量 {config.token_env} 未配置"
            )
    return HttpPollAdapter(
        config.location,
        source_id=config.source_id,
        token=token,
        timeout_seconds=config.timeout_seconds,
        ca_file=config.ca_file,
    )


class SourceWorker:
    def __init__(
        self,
        config: SourceSettings,
        adapter: ReadOnlyAdapter,
        service: EdgeService,
        *,
        jitter: Callable[[float, float], float] | None = None,
    ) -> None:
        if not adapter.read_only:
            raise ValidationError(f"来源 {config.source_id} 的适配器未声明只读")
        self.config = config
        self.adapter = adapter
        self.service = service
        self._jitter = jitter or random.SystemRandom().uniform
        self._condition = threading.Condition()
        self._state = _RuntimeState(enabled=config.enabled)
        self._stopping = False
        self._worker_started = False
        self._trigger_now = config.enabled
        self._started_monotonic = time.monotonic()
        self._last_data_monotonic: float | None = None
        self._methane_accelerated_until_monotonic: float | None = None
        self._restore_methane_sampling_window()
        self._next_due_monotonic: float | None = (
            self._started_monotonic + self._initial_jitter()
            if config.enabled
            else None
        )
        self._late_poll: tuple[threading.Thread, dict[str, Any]] | None = None
        self._thread = threading.Thread(
            target=self._run,
            name=f"mine-edge-source-{config.source_id}",
            daemon=True,
        )

    def start_worker(self) -> None:
        with self._condition:
            self._worker_started = True
        try:
            self._thread.start()
        except Exception:
            with self._condition:
                self._worker_started = False
            raise

    def request_stop(self) -> None:
        with self._condition:
            self._stopping = True
            self._condition.notify_all()

    def join(self, timeout: float) -> None:
        if self._thread.is_alive():
            self._thread.join(timeout=max(0, timeout))

    def enable(self) -> None:
        with self._condition:
            self._state.enabled = True
            self._state.last_error = None
            self._state.partial_failure = False
            self._trigger_now = True
            self._next_due_monotonic = time.monotonic()
            self._state.next_run_at = utc_now()
            self._condition.notify_all()

    def disable(self) -> None:
        with self._condition:
            self._state.enabled = False
            self._trigger_now = False
            self._next_due_monotonic = None
            self._state.next_run_at = None
            self._condition.notify_all()

    def run_now(self) -> None:
        with self._condition:
            if not self._state.enabled:
                raise ValidationError(
                    f"来源 {self.config.source_id} 已暂停；请先启用采集"
                )
            self._trigger_now = True
            self._next_due_monotonic = time.monotonic()
            self._state.next_run_at = utc_now()
            self._condition.notify_all()

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            late_running = (
                self._late_poll is not None and self._late_poll[0].is_alive()
            )
            if self._late_poll is not None and not late_running:
                self._late_poll = None
                self._state.in_flight = False
            enabled = self._state.enabled
            elapsed_without_data = time.monotonic() - (
                self._last_data_monotonic or self._started_monotonic
            )
            heartbeat_age_seconds = max(0.0, elapsed_without_data)
            missing = enabled and (
                elapsed_without_data >= self.config.missing_after_seconds
            )
            worker_stopped = (
                enabled
                and self._worker_started
                and not self._thread.is_alive()
                and not self._stopping
            )
            adaptive = self.config.methane_adaptive_sampling
            adaptive_available = (
                adaptive.enabled
                and adaptive.accelerated_interval_seconds
                < self.config.interval_seconds
            )
            accelerated = (
                enabled
                and adaptive_available
                and self._methane_accelerated_until_monotonic is not None
                and time.monotonic()
                < self._methane_accelerated_until_monotonic
            )
            accelerated_remaining_seconds = (
                max(
                    0.0,
                    self._methane_accelerated_until_monotonic
                    - time.monotonic(),
                )
                if accelerated
                and self._methane_accelerated_until_monotonic is not None
                else 0.0
            )
            effective_interval_seconds = (
                adaptive.accelerated_interval_seconds
                if accelerated
                else self.config.interval_seconds
            )
            if not enabled:
                health, signal = "disabled", "disabled"
            elif worker_stopped:
                health, signal = "failed", "worker_stopped"
            elif self._state.consecutive_failures >= 3:
                health, signal = "failed", "source_failure"
            elif self._state.consecutive_failures > 0:
                health, signal = "degraded", "source_failure"
            elif self._state.partial_failure:
                health, signal = "degraded", "partial_records_rejected"
            elif missing:
                health, signal = "degraded", "missing_data"
            elif self._state.last_data_at is None:
                health, signal = "starting", "awaiting_first_data"
            elif self._state.health_telemetry_consecutive_failures:
                health, signal = (
                    "degraded",
                    "health_telemetry_persistence_failed",
                )
            elif self._state.methane_sampling_state_error:
                health, signal = (
                    "degraded",
                    "methane_sampling_state_persistence_failed",
                )
            else:
                health, signal = "healthy", "ok"
            return {
                "source_id": self.config.source_id,
                "adapter": self.config.adapter,
                "enabled": enabled,
                "read_only": True,
                "health": health,
                "signal": signal,
                "missing_data": missing,
                "in_flight": bool(self._state.in_flight or late_running),
                "worker_alive": self._thread.is_alive(),
                "interval_seconds": self.config.interval_seconds,
                "jitter_seconds": self.config.jitter_seconds,
                "timeout_seconds": self.config.timeout_seconds,
                "missing_after_seconds": self.config.missing_after_seconds,
                "heartbeat_age_seconds": round(heartbeat_age_seconds, 3),
                "last_heartbeat_at": self._state.last_heartbeat_at,
                "last_attempt_at": self._state.last_attempt_at,
                "last_success_at": self._state.last_success_at,
                "last_data_at": self._state.last_data_at,
                "last_error": self._state.last_error,
                "next_run_at": self._state.next_run_at,
                "consecutive_failures": self._state.consecutive_failures,
                "attempts": self._state.attempts,
                "successful_polls": self._state.successful_polls,
                "records_received": self._state.records_received,
                "records_inserted": self._state.records_inserted,
                "records_duplicate": self._state.records_duplicate,
                "records_rejected": self._state.records_rejected,
                "alerts_created": self._state.alerts_created,
                "last_record_count": self._state.last_record_count,
                "last_duration_ms": self._state.last_duration_ms,
                "health_telemetry_last_emitted_at": (
                    self._state.health_telemetry_last_emitted_at
                ),
                "health_telemetry_last_error": (
                    self._state.health_telemetry_last_error
                ),
                "health_telemetry_consecutive_failures": (
                    self._state.health_telemetry_consecutive_failures
                ),
                "health_observations_inserted": (
                    self._state.health_observations_inserted
                ),
                "health_observations_duplicate": (
                    self._state.health_observations_duplicate
                ),
                "methane_adaptive_sampling": {
                    "enabled": adaptive.enabled,
                    "effective": adaptive_available,
                    "mode": (
                        "accelerated" if accelerated else "regular"
                    ),
                    "regular_interval_seconds": (
                        self.config.interval_seconds
                    ),
                    "accelerated_interval_seconds": (
                        adaptive.accelerated_interval_seconds
                    ),
                    "effective_interval_seconds": (
                        effective_interval_seconds
                    ),
                    "trigger_ratio": adaptive.trigger_ratio,
                    "window_seconds": adaptive.window_seconds,
                    "accelerated_until": (
                        self._state.methane_sampling_accelerated_until
                    ),
                    "accelerated_remaining_seconds": round(
                        accelerated_remaining_seconds,
                        3,
                    ),
                    "last_trigger_at": (
                        self._state.methane_sampling_last_trigger_at
                    ),
                    "last_trigger_reason": (
                        self._state.methane_sampling_last_trigger_reason
                    ),
                    "last_value_percent": (
                        self._state.methane_sampling_last_value_percent
                    ),
                    "trigger_threshold_percent": (
                        self._state.methane_sampling_trigger_threshold_percent
                    ),
                    "trigger_count": (
                        self._state.methane_sampling_trigger_count
                    ),
                    "restored_after_restart": (
                        self._state.methane_sampling_restored_after_restart
                    ),
                    "state_error": (
                        self._state.methane_sampling_state_error
                    ),
                    "restart_behavior": (
                        "restore_unexpired_bounded_window"
                    ),
                    "poll_schedule_only": True,
                    "device_write_capability": False,
                },
            }

    def record_health_telemetry_success(
        self,
        *,
        emitted_at: str,
        inserted: int,
        duplicate: int,
    ) -> None:
        with self._condition:
            self._state.health_telemetry_last_emitted_at = emitted_at
            self._state.health_telemetry_last_error = None
            self._state.health_telemetry_consecutive_failures = 0
            self._state.health_observations_inserted += inserted
            self._state.health_observations_duplicate += duplicate

    def record_health_telemetry_failure(self, error: Exception) -> None:
        with self._condition:
            self._state.health_telemetry_last_error = str(error)[:1000]
            self._state.health_telemetry_consecutive_failures += 1

    def _restore_methane_sampling_window(self) -> None:
        adaptive = self.config.methane_adaptive_sampling
        if (
            not adaptive.enabled
            or adaptive.accelerated_interval_seconds
            >= self.config.interval_seconds
        ):
            return
        repository = getattr(self.service, "repository", None)
        load = getattr(repository, "load_source_scheduler_state", None)
        if not callable(load):
            return
        try:
            state = load(self.config.source_id)
            if not state or state.get("schema_version") != (
                "methane-adaptive-sampling-v1"
            ):
                return
            active_until_raw = state.get("active_until")
            if not isinstance(active_until_raw, str):
                return
            active_until = datetime.fromisoformat(
                active_until_raw.replace("Z", "+00:00")
            )
            if active_until.tzinfo is None:
                return
            remaining = (
                active_until.astimezone(UTC) - datetime.now(UTC)
            ).total_seconds()
            if remaining <= 0:
                return
            # Never trust persisted state to exceed the currently configured
            # bounded window.
            remaining = min(remaining, adaptive.window_seconds)
            self._methane_accelerated_until_monotonic = (
                time.monotonic() + remaining
            )
            self._state.methane_sampling_accelerated_until = (
                self._future_time(remaining)
            )
            self._state.methane_sampling_last_trigger_at = (
                str(state.get("triggered_at") or "") or None
            )
            self._state.methane_sampling_last_trigger_reason = (
                str(state.get("reason") or "") or None
            )
            value = state.get("methane_value_percent")
            if isinstance(value, (int, float)) and not isinstance(
                value,
                bool,
            ):
                self._state.methane_sampling_last_value_percent = float(
                    value
                )
            threshold = state.get("trigger_threshold_percent")
            if isinstance(threshold, (int, float)) and not isinstance(
                threshold,
                bool,
            ):
                self._state.methane_sampling_trigger_threshold_percent = (
                    float(threshold)
                )
            count = state.get("trigger_count")
            if isinstance(count, int) and not isinstance(count, bool):
                self._state.methane_sampling_trigger_count = max(0, count)
            self._state.methane_sampling_restored_after_restart = True
        except Exception as error:
            # State restoration must never prevent read-only acquisition.
            self._state.methane_sampling_state_error = str(error)[:1000]

    def _methane_sampling_trigger(
        self,
        outcome: dict[str, Any],
    ) -> dict[str, Any] | None:
        adaptive = self.config.methane_adaptive_sampling
        if (
            not adaptive.enabled
            or adaptive.accelerated_interval_seconds
            >= self.config.interval_seconds
        ):
            return None
        threshold_settings = getattr(
            getattr(self.service, "settings", None),
            "thresholds",
            None,
        )
        methane_thresholds = getattr(
            threshold_settings,
            "methane_percent",
            None,
        )
        if not isinstance(methane_thresholds, dict):
            return None
        try:
            blue_threshold = float(methane_thresholds["blue"])
        except (KeyError, TypeError, ValueError):
            return None
        trigger_threshold = blue_threshold * adaptive.trigger_ratio
        alert_evidence = outcome.get("methane_local_alert_evidence")
        if alert_evidence is not None:
            return {
                "reason": "methane_local_alert",
                "value_percent": float(alert_evidence.value_percent),
                "trigger_threshold_percent": trigger_threshold,
            }
        evidence = outcome.get("latest_valid_methane_evidence")
        if (
            evidence is not None
            and float(evidence.value_percent) >= trigger_threshold
        ):
            return {
                "reason": "methane_warning_ratio",
                "value_percent": float(evidence.value_percent),
                "trigger_threshold_percent": trigger_threshold,
            }
        return None

    def _activate_methane_sampling_locked(
        self,
        trigger: dict[str, Any],
    ) -> dict[str, Any]:
        adaptive = self.config.methane_adaptive_sampling
        triggered_at = utc_now()
        self._methane_accelerated_until_monotonic = (
            time.monotonic() + adaptive.window_seconds
        )
        active_until = self._future_time(adaptive.window_seconds)
        self._state.methane_sampling_accelerated_until = active_until
        self._state.methane_sampling_last_trigger_at = triggered_at
        self._state.methane_sampling_last_trigger_reason = str(
            trigger["reason"]
        )
        self._state.methane_sampling_last_value_percent = float(
            trigger["value_percent"]
        )
        self._state.methane_sampling_trigger_threshold_percent = float(
            trigger["trigger_threshold_percent"]
        )
        self._state.methane_sampling_trigger_count += 1
        self._state.methane_sampling_restored_after_restart = False
        event_id = "sampling_" + hashlib.sha256(
            (
                f"{self.config.source_id}\n{triggered_at}\n"
                f"{self._state.methane_sampling_trigger_count}\n"
                f"{self._state.methane_sampling_last_trigger_reason}\n"
                f"{self._state.methane_sampling_last_value_percent}"
            ).encode()
        ).hexdigest()[:32]
        return {
            "schema_version": "methane-adaptive-sampling-v1",
            "event_id": event_id,
            "event_type": "methane_sampling_accelerated",
            "source_id": self.config.source_id,
            "triggered_at": triggered_at,
            "active_until": active_until,
            "reason": self._state.methane_sampling_last_trigger_reason,
            "methane_value_percent": (
                self._state.methane_sampling_last_value_percent
            ),
            "trigger_threshold_percent": (
                self._state.methane_sampling_trigger_threshold_percent
            ),
            "trigger_count": self._state.methane_sampling_trigger_count,
            "poll_schedule_only": True,
            "device_write_capability": False,
        }

    def _persist_methane_sampling_state(
        self,
        state: dict[str, Any],
    ) -> None:
        repository = getattr(self.service, "repository", None)
        save = getattr(repository, "save_source_scheduler_state", None)
        if not callable(save):
            return
        try:
            save(self.config.source_id, state)
        except Exception as error:
            with self._condition:
                self._state.methane_sampling_state_error = str(error)[:1000]
        else:
            with self._condition:
                self._state.methane_sampling_state_error = None

    def _initial_jitter(self) -> float:
        if self.config.jitter_seconds <= 0:
            return 0
        return max(0, self._jitter(0, self.config.jitter_seconds))

    def _next_delay(self) -> float:
        adaptive = self.config.methane_adaptive_sampling
        accelerated = (
            adaptive.enabled
            and adaptive.accelerated_interval_seconds
            < self.config.interval_seconds
            and self._methane_accelerated_until_monotonic is not None
            and time.monotonic()
            < self._methane_accelerated_until_monotonic
        )
        base_interval = (
            adaptive.accelerated_interval_seconds
            if accelerated
            else self.config.interval_seconds
        )
        jitter_limit = self.config.jitter_seconds
        if accelerated:
            # Preserve a strictly shorter accelerated schedule even when the
            # regular schedule has a large anti-herd jitter.
            jitter_limit = min(
                jitter_limit,
                max(
                    0.0,
                    (
                        self.config.interval_seconds
                        - base_interval
                    )
                    / 2,
                ),
            )
        jitter = (
            self._jitter(0, jitter_limit)
            if jitter_limit > 0
            else 0
        )
        return max(0.01, base_interval + jitter)

    @staticmethod
    def _future_time(seconds: float) -> str:
        return (
            (datetime.now(UTC) + timedelta(seconds=seconds))
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

    def _run(self) -> None:
        while True:
            with self._condition:
                while True:
                    self._state.last_heartbeat_at = utc_now()
                    if self._stopping:
                        return
                    if not self._state.enabled:
                        self._condition.wait()
                        continue
                    now = time.monotonic()
                    due = self._next_due_monotonic or now
                    if self._trigger_now or now >= due:
                        self._trigger_now = False
                        self._state.in_flight = True
                        self._state.last_attempt_at = utc_now()
                        self._state.attempts += 1
                        break
                    self._condition.wait(timeout=min(max(0, due - now), 1.0))
            started = time.monotonic()
            try:
                records = self._poll_with_timeout()
                outcome = self._ingest_records(records)
            except _AllRecordsRejected as error:
                self._record_failure(
                    error,
                    started,
                    records_received=error.count,
                    records_rejected=error.count,
                )
            except Exception as error:
                self._record_failure(error, started)
            else:
                self._record_success(records, outcome, started)
            with self._condition:
                if self._stopping:
                    return
                if self._state.enabled:
                    delay = self._next_delay()
                    self._next_due_monotonic = time.monotonic() + delay
                    self._state.next_run_at = self._future_time(delay)

    def _poll_with_timeout(self) -> list[RawRecord]:
        with self._condition:
            late_poll = self._late_poll
            if late_poll is not None:
                thread, _box = late_poll
                if thread.is_alive():
                    raise AdapterError(
                        "上一次采集超过 timeout 且尚未结束；"
                        "本周期未启动重叠采集"
                    )
                self._late_poll = None
        box: dict[str, Any] = {}

        def poll() -> None:
            try:
                box["records"] = self.adapter.poll()
            except Exception as error:
                box["error"] = error

        thread = threading.Thread(
            target=poll,
            name=f"mine-edge-poll-{self.config.source_id}",
            daemon=True,
        )
        thread.start()
        thread.join(timeout=self.config.timeout_seconds)
        if thread.is_alive():
            with self._condition:
                self._late_poll = (thread, box)
            raise AdapterError(
                f"采集超过 timeout_seconds={self.config.timeout_seconds:g}"
            )
        if "error" in box:
            error = box["error"]
            if isinstance(error, Exception):
                raise error
            raise AdapterError(str(error))
        records = box.get("records")
        if not isinstance(records, list) or any(
            not isinstance(record, RawRecord) for record in records
        ):
            raise AdapterError("适配器返回值不符合只读 RawRecord 列表接口")
        return records

    def _ingest_records(self, records: list[RawRecord]) -> dict[str, Any]:
        inserted = duplicate = rejected = alerts = 0
        errors: list[str] = []
        latest_valid_methane_evidence: Any | None = None
        methane_local_alert_evidence: Any | None = None
        for record in records:
            try:
                result = self.service.ingest(
                    record.data,
                    channel=record.channel,
                    source_id=record.source_id,
                )
            except Exception as error:
                rejected += 1
                errors.append(str(error))
                continue
            inserted += int(result.inserted)
            duplicate += int(result.duplicate)
            alerts += len(result.alert_ids)
            evidence = getattr(
                result,
                "methane_sampling_evidence",
                None,
            )
            if evidence is None:
                continue
            rank = (
                evidence.observed_at,
                evidence.revision,
                evidence.sequence_no,
            )
            if evidence.local_alert_generated and (
                methane_local_alert_evidence is None
                or rank
                > (
                    methane_local_alert_evidence.observed_at,
                    methane_local_alert_evidence.revision,
                    methane_local_alert_evidence.sequence_no,
                )
            ):
                methane_local_alert_evidence = evidence
            if (
                result.inserted
                and evidence.quality_valid
                and (
                    latest_valid_methane_evidence is None
                    or rank
                    > (
                        latest_valid_methane_evidence.observed_at,
                        latest_valid_methane_evidence.revision,
                        latest_valid_methane_evidence.sequence_no,
                    )
                )
            ):
                latest_valid_methane_evidence = evidence
        if records and rejected == len(records):
            raise _AllRecordsRejected(
                (
                    f"本次 {rejected} 条记录全部被拒绝："
                    + "; ".join(errors[:3])
                ),
                rejected,
            )
        return {
            "inserted": inserted,
            "duplicate": duplicate,
            "rejected": rejected,
            "alerts": alerts,
            "errors": errors,
            "latest_valid_methane_evidence": (
                latest_valid_methane_evidence
            ),
            "methane_local_alert_evidence": (
                methane_local_alert_evidence
            ),
        }

    def _record_failure(
        self,
        error: Exception,
        started: float,
        *,
        records_received: int = 0,
        records_rejected: int = 0,
    ) -> None:
        with self._condition:
            late_running = (
                self._late_poll is not None and self._late_poll[0].is_alive()
            )
            self._state.in_flight = late_running
            self._state.last_heartbeat_at = utc_now()
            self._state.last_error = str(error)[:1000]
            self._state.consecutive_failures += 1
            self._state.partial_failure = False
            self._state.records_received += records_received
            self._state.records_rejected += records_rejected
            self._state.last_record_count = records_received
            self._state.last_duration_ms = round(
                (time.monotonic() - started) * 1000
            )

    def _record_success(
        self,
        records: list[RawRecord],
        outcome: dict[str, Any],
        started: float,
    ) -> None:
        now_text = utc_now()
        sampling_state: dict[str, Any] | None = None
        sampling_trigger = self._methane_sampling_trigger(outcome)
        with self._condition:
            self._state.in_flight = False
            self._state.last_heartbeat_at = now_text
            self._state.last_success_at = now_text
            self._state.consecutive_failures = 0
            self._state.successful_polls += 1
            self._state.records_received += len(records)
            self._state.records_inserted += int(outcome["inserted"])
            self._state.records_duplicate += int(outcome["duplicate"])
            self._state.records_rejected += int(outcome["rejected"])
            self._state.alerts_created += int(outcome["alerts"])
            self._state.last_record_count = len(records)
            self._state.last_duration_ms = round(
                (time.monotonic() - started) * 1000
            )
            self._state.partial_failure = bool(outcome["rejected"])
            self._state.last_error = (
                "; ".join(outcome["errors"][:3])
                if outcome["errors"]
                else None
            )
            if outcome["inserted"] or outcome["duplicate"]:
                self._state.last_data_at = now_text
                self._last_data_monotonic = time.monotonic()
            if sampling_trigger is not None:
                sampling_state = self._activate_methane_sampling_locked(
                    sampling_trigger
                )
        if sampling_state is not None:
            self._persist_methane_sampling_state(sampling_state)


class SourceManager:
    def __init__(
        self,
        configs: tuple[SourceSettings, ...],
        service: EdgeService,
        *,
        adapter_factory: AdapterFactory = build_adapter,
        jitter: Callable[[float, float], float] | None = None,
        health_interval_seconds: float | None = None,
    ) -> None:
        self._service = service
        self._workers: dict[str, SourceWorker] = {}
        for config in configs:
            try:
                adapter = adapter_factory(config)
            except Exception as error:
                adapter = _UnavailableAdapter(str(error))
            self._workers[config.source_id] = SourceWorker(
                config,
                adapter,
                service,
                jitter=jitter,
            )
        self._started = False
        self._stopped = False
        if health_interval_seconds is not None:
            if health_interval_seconds <= 0:
                raise ValidationError("来源健康遥测周期必须大于零")
            self._health_interval_seconds = health_interval_seconds
        elif configs:
            self._health_interval_seconds = min(
                10.0,
                max(
                    1.0,
                    min(
                        min(item.interval_seconds for item in configs),
                        min(
                            item.missing_after_seconds
                            for item in configs
                        )
                        / 10,
                    ),
                ),
            )
        else:
            self._health_interval_seconds = 10.0
        self._health_stop = threading.Event()
        self._health_thread = threading.Thread(
            target=self._run_health_telemetry,
            name="mine-edge-source-health",
            daemon=True,
        )

    def start(self) -> None:
        if self._started:
            return
        if self._stopped:
            raise ValidationError("采集调度器停止后不可在同一进程内重新启动")
        self._started = True
        for worker in self._workers.values():
            worker.start_worker()
        if self._workers:
            self._health_thread.start()

    def stop(self) -> None:
        if not self._started:
            return
        self._health_stop.set()
        for worker in self._workers.values():
            worker.request_stop()
        deadline = time.monotonic() + 5
        if self._health_thread.is_alive():
            self._health_thread.join(max(0, deadline - time.monotonic()))
        for worker in self._workers.values():
            worker.join(max(0, deadline - time.monotonic()))
        self._started = False
        self._stopped = True

    def enable(self, source_id: str) -> dict[str, Any]:
        worker = self._worker(source_id)
        worker.enable()
        return worker.snapshot()

    def disable(self, source_id: str) -> dict[str, Any]:
        worker = self._worker(source_id)
        worker.disable()
        return worker.snapshot()

    def run_now(self, source_id: str) -> dict[str, Any]:
        worker = self._worker(source_id)
        worker.run_now()
        return worker.snapshot()

    def snapshot(self) -> dict[str, Any]:
        items = [
            worker.snapshot()
            for worker in self._workers.values()
        ]
        summary = {
            "total": len(items),
            "enabled": sum(item["enabled"] for item in items),
            "healthy": sum(item["health"] == "healthy" for item in items),
            "starting": sum(item["health"] == "starting" for item in items),
            "degraded": sum(item["health"] == "degraded" for item in items),
            "failed": sum(item["health"] == "failed" for item in items),
            "disabled": sum(item["health"] == "disabled" for item in items),
            "missing": sum(item["missing_data"] for item in items),
            "in_flight": sum(item["in_flight"] for item in items),
            "methane_accelerated": sum(
                item["methane_adaptive_sampling"]["mode"]
                == "accelerated"
                for item in items
            ),
        }
        summary["attention"] = (
            summary["degraded"] + summary["failed"]
        )
        heartbeat_values = [
            item["last_heartbeat_at"]
            for item in items
            if item["enabled"] and item["last_heartbeat_at"] is not None
        ]
        return {
            "summary": summary,
            "items": items,
            "heartbeat": {
                "generated_at": utc_now(),
                "latest_source_heartbeat_at": (
                    max(heartbeat_values) if heartbeat_values else None
                ),
                "signal": "attention" if summary["attention"] else "ok",
            },
        }

    def configured_sources(self) -> list[dict[str, Any]]:
        return [
            worker.config.public_dict()
            for worker in self._workers.values()
        ]

    def _run_health_telemetry(self) -> None:
        emit = getattr(self._service, "ingest_source_health", None)
        if not callable(emit):
            return
        while not self._health_stop.wait(self._health_interval_seconds):
            emitted_at = utc_now()
            for worker in self._workers.values():
                if self._health_stop.is_set():
                    return
                item = worker.snapshot()
                try:
                    results = emit(
                        source_id=item["source_id"],
                        heartbeat_age_seconds=item[
                            "heartbeat_age_seconds"
                        ],
                        consecutive_failures=item[
                            "consecutive_failures"
                        ],
                        missing_state=item["missing_data"],
                        status_code=item["signal"],
                        emitted_at=emitted_at,
                    )
                except Exception as error:
                    worker.record_health_telemetry_failure(error)
                    continue
                worker.record_health_telemetry_success(
                    emitted_at=emitted_at,
                    inserted=sum(
                        int(result.inserted) for result in results
                    ),
                    duplicate=sum(
                        int(result.duplicate) for result in results
                    ),
                )

    def _worker(self, source_id: str) -> SourceWorker:
        worker = self._workers.get(source_id)
        if worker is None:
            raise ValidationError(f"采集来源不存在：{source_id}")
        return worker
