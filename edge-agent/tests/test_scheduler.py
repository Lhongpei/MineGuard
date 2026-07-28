from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

from mine_edge.adapters import RawRecord, ReadOnlyAdapter
from mine_edge.errors import AdapterError, ValidationError
from mine_edge.http_api import ForwardLoop
from mine_edge.models import utc_now
from mine_edge.scheduler import SourceManager
from mine_edge.service import EdgeService
from mine_edge.settings import (
    MethaneAdaptiveSamplingSettings,
    SourceSettings,
)
from mine_edge.storage import Repository


def _source(
    source_id: str,
    *,
    enabled: bool = True,
    timeout: float = 0.03,
    missing_after: float = 1.0,
) -> SourceSettings:
    # Direct construction permits short periods so the concurrency tests stay
    # fast. Environment parsing intentionally enforces production-safe minima.
    return SourceSettings(
        source_id=source_id,
        adapter="jsonl",
        location="/read-only/test",
        interval_seconds=0.02,
        jitter_seconds=0,
        timeout_seconds=timeout,
        missing_after_seconds=missing_after,
        enabled=enabled,
    )


def _wait_until(predicate, *, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate(), "condition did not become true before timeout"


class _GoodAdapter(ReadOnlyAdapter):
    def __init__(self, source_id: str) -> None:
        self.source_id = source_id
        self.polls = 0

    def poll(self) -> list[RawRecord]:
        self.polls += 1
        return [
            RawRecord(
                {"poll": self.polls},
                "test",
                self.source_id,
            )
        ]


class _FailingAdapter(ReadOnlyAdapter):
    def poll(self) -> list[RawRecord]:
        raise AdapterError("source unavailable")


class _SlowAdapter(ReadOnlyAdapter):
    def poll(self) -> list[RawRecord]:
        time.sleep(0.35)
        return []


class _EmptyAdapter(ReadOnlyAdapter):
    def poll(self) -> list[RawRecord]:
        return []


class _PartialAdapter(ReadOnlyAdapter):
    def poll(self) -> list[RawRecord]:
        return [
            RawRecord({"value": 1}, "test", "partial"),
            RawRecord({"reject": True}, "test", "partial"),
        ]


class _RejectedAdapter(ReadOnlyAdapter):
    def poll(self) -> list[RawRecord]:
        return [RawRecord({"reject": True}, "test", "rejected")]


class _TimedMethaneAdapter(ReadOnlyAdapter):
    def __init__(
        self,
        values: list[float | None | Exception],
        *,
        quality_valid: bool = True,
    ) -> None:
        self.values = values
        self.quality_valid = quality_valid
        self.poll_times: list[float] = []
        self.polls = 0

    def poll(self) -> list[RawRecord]:
        self.poll_times.append(time.monotonic())
        self.polls += 1
        selected = self.values[
            min(self.polls - 1, len(self.values) - 1)
        ]
        if isinstance(selected, Exception):
            raise selected
        if selected is None:
            return []
        return [
            RawRecord(
                {
                    "event_id": f"adaptive-methane-{self.polls}",
                    "kind": "methane",
                    "metric": "methane_concentration",
                    "value": selected,
                    "unit": "%",
                    "location_code": "working-face-t1",
                    "observed_at": utc_now(),
                    "quality": {
                        "valid": self.quality_valid,
                        "completeness": 1.0,
                        "timeliness": 1.0,
                        "device_health": "healthy",
                        "clock_synchronized": True,
                        "flags": [],
                    },
                },
                "http_poll",
                "gas-adaptive",
            )
        ]


def _adaptive_source(
    *,
    interval: float = 0.14,
    accelerated_interval: float = 0.02,
    window: float = 0.11,
    enabled: bool = True,
) -> SourceSettings:
    return SourceSettings(
        source_id="gas-adaptive",
        adapter="http-poll",
        location="https://source.example/read-only/gas",
        interval_seconds=interval,
        jitter_seconds=0,
        timeout_seconds=0.05,
        missing_after_seconds=2,
        methane_adaptive_sampling=MethaneAdaptiveSamplingSettings(
            enabled=enabled,
            trigger_ratio=0.8,
            accelerated_interval_seconds=accelerated_interval,
            window_seconds=window,
        ),
    )


class _FakeService:
    def __init__(self) -> None:
        self.ingested: list[dict[str, object]] = []
        self._lock = threading.Lock()

    def ingest(self, raw, *, channel, source_id):
        if raw.get("reject"):
            raise ValidationError("invalid test record")
        with self._lock:
            self.ingested.append(
                {"raw": raw, "channel": channel, "source_id": source_id}
            )
        return SimpleNamespace(inserted=True, duplicate=False, alert_ids=[])


class _FakeForwarder:
    def __init__(self) -> None:
        self.calls = 0

    def flush(self, *, max_batches):
        self.calls += 1
        return []


def _item(manager: SourceManager, source_id: str) -> dict[str, object]:
    return next(
        item
        for item in manager.snapshot()["items"]
        if item["source_id"] == source_id
    )


def test_failing_source_does_not_block_healthy_source() -> None:
    service = _FakeService()
    adapters = {
        "good": _GoodAdapter("good"),
        "bad": _FailingAdapter(),
    }
    manager = SourceManager(
        (_source("good"), _source("bad")),
        service,
        adapter_factory=lambda config: adapters[config.source_id],
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(
            lambda: (
                _item(manager, "good")["successful_polls"] >= 3
                and _item(manager, "bad")["consecutive_failures"] >= 3
            )
        )
        assert _item(manager, "good")["health"] == "healthy"
        assert _item(manager, "bad")["health"] == "failed"
        assert len(service.ingested) >= 3
    finally:
        manager.stop()


def test_adapter_construction_failure_is_local_to_one_source() -> None:
    service = _FakeService()

    def factory(config):
        if config.source_id == "missing-token":
            raise AdapterError("required token environment variable is missing")
        return _GoodAdapter(config.source_id)

    manager = SourceManager(
        (_source("missing-token"), _source("ready")),
        service,
        adapter_factory=factory,
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(
            lambda: (
                _item(manager, "missing-token")["consecutive_failures"] >= 1
                and _item(manager, "ready")["successful_polls"] >= 1
            )
        )
        assert "token" in str(_item(manager, "missing-token")["last_error"])
        assert _item(manager, "ready")["health"] == "healthy"
    finally:
        manager.stop()


def test_timeout_isolated_from_other_sources_and_forwarder() -> None:
    service = _FakeService()
    service.settings = SimpleNamespace(upstream_url="https://regulator.example")
    service.forwarder = _FakeForwarder()
    adapters = {
        "slow": _SlowAdapter(),
        "fast": _GoodAdapter("fast"),
    }
    manager = SourceManager(
        (_source("slow", timeout=0.02), _source("fast")),
        service,
        adapter_factory=lambda config: adapters[config.source_id],
        jitter=lambda _start, _end: 0,
    )
    forward_loop = ForwardLoop(service, interval_seconds=0.01)
    manager.start()
    forward_loop.start()
    try:
        _wait_until(
            lambda: (
                _item(manager, "slow")["consecutive_failures"] >= 1
                and _item(manager, "fast")["successful_polls"] >= 2
                and service.forwarder.calls >= 3
            )
        )
        assert _item(manager, "slow")["health"] == "degraded"
        assert _item(manager, "slow")["in_flight"] is True
        assert _item(manager, "fast")["health"] == "healthy"
    finally:
        manager.stop()
        forward_loop.stop()


def test_empty_success_becomes_standard_missing_data_signal() -> None:
    service = _FakeService()
    manager = SourceManager(
        (_source("empty", missing_after=0.08),),
        service,
        adapter_factory=lambda _config: _EmptyAdapter(),
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(lambda: _item(manager, "empty")["successful_polls"] >= 1)
        _wait_until(lambda: _item(manager, "empty")["signal"] == "missing_data")
        item = _item(manager, "empty")
        assert item["health"] == "degraded"
        assert item["last_success_at"] is not None
        assert item["last_data_at"] is None
        assert manager.snapshot()["summary"]["missing"] == 1
    finally:
        manager.stop()


def test_partial_records_are_counted_without_losing_valid_record() -> None:
    service = _FakeService()
    manager = SourceManager(
        (_source("partial"),),
        service,
        adapter_factory=lambda _config: _PartialAdapter(),
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(lambda: _item(manager, "partial")["successful_polls"] >= 1)
        item = _item(manager, "partial")
        assert item["health"] == "degraded"
        assert item["signal"] == "partial_records_rejected"
        assert item["records_received"] >= 2
        assert item["records_inserted"] >= 1
        assert item["records_rejected"] >= 1
    finally:
        manager.stop()


def test_all_rejected_records_are_visible_as_source_failure_counters() -> None:
    service = _FakeService()
    manager = SourceManager(
        (_source("rejected"),),
        service,
        adapter_factory=lambda _config: _RejectedAdapter(),
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(lambda: _item(manager, "rejected")["records_rejected"] >= 1)
        item = _item(manager, "rejected")
        assert item["health"] == "degraded"
        assert item["signal"] == "source_failure"
        assert item["records_received"] >= 1
        assert item["last_record_count"] == 1
    finally:
        manager.stop()


def test_runtime_enable_disable_and_run_now_control_connector_only() -> None:
    service = _FakeService()
    manager = SourceManager(
        (_source("paused", enabled=False),),
        service,
        adapter_factory=lambda _config: _GoodAdapter("paused"),
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        assert _item(manager, "paused")["health"] == "disabled"
        manager.enable("paused")
        _wait_until(lambda: _item(manager, "paused")["successful_polls"] >= 1)
        attempts = int(_item(manager, "paused")["attempts"])
        manager.run_now("paused")
        _wait_until(lambda: int(_item(manager, "paused")["attempts"]) > attempts)
        manager.disable("paused")
        item = _item(manager, "paused")
        assert item["health"] == "disabled"
        assert item["next_run_at"] is None
    finally:
        manager.stop()


def test_continuous_jsonl_source_integrates_with_real_store(
    settings, methane_raw, tmp_path
) -> None:
    path = tmp_path / "readings.jsonl"
    path.write_text(json.dumps(methane_raw) + "\n", encoding="utf-8")
    source = SourceSettings(
        source_id="continuous",
        adapter="jsonl",
        location=str(path),
        interval_seconds=0.02,
        jitter_seconds=0,
        timeout_seconds=0.1,
        missing_after_seconds=1,
    )
    service = EdgeService(Repository(settings.database_path), settings)
    manager = SourceManager((source,), service, jitter=lambda _start, _end: 0)
    manager.start()
    try:
        _wait_until(lambda: service.repository.stats()["observations"] == 1)
        _wait_until(lambda: _item(manager, "continuous")["records_duplicate"] >= 1)
        item = _item(manager, "continuous")
        assert item["health"] == "healthy"
        assert item["records_inserted"] == 1
        assert service.repository.stats()["outbox_pending"] == 2
    finally:
        manager.stop()


def test_internal_source_health_cycle_is_idempotent_durable_and_outboxed(
    settings,
) -> None:
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    emitted_at = utc_now()

    first = service.ingest_source_health(
        source_id="personnel-gateway",
        heartbeat_age_seconds=72.25,
        consecutive_failures=3,
        missing_state=True,
        status_code="missing_data",
        emitted_at=emitted_at,
        cycle_id="stable-cycle-001",
    )
    replay = service.ingest_source_health(
        source_id="personnel-gateway",
        heartbeat_age_seconds=72.25,
        consecutive_failures=3,
        missing_state=True,
        status_code="missing_data",
        emitted_at=emitted_at,
        cycle_id="stable-cycle-001",
    )

    observations = repository.list_observations(
        kind="source_health",
        limit=10,
    )
    claimed = repository.claim_batch(
        limit=100,
        client_id=settings.client_id,
    )
    assert len(first) == 3
    assert all(item.inserted for item in first)
    assert len(replay) == 3
    assert all(item.duplicate for item in replay)
    assert len(observations) == 3
    assert {
        item["metric"] for item in observations
    } == {
        "source.heartbeat_age_seconds",
        "source.consecutive_failures",
        "source.missing_state",
    }
    assert all(
        item["kind"] == "source_health"
        and item["provenance"]["source_id"] == "personnel-gateway"
        for item in observations
    )
    assert repository.stats()["alerts"] == 0
    assert repository.stats()["outbox_pending"] == 3
    assert claimed is not None
    assert {
        item.payload["metric_code"] for item in claimed.records
    } == {
        "source.heartbeat_age_seconds",
        "source.consecutive_failures",
        "source.missing_state",
    }


def test_scheduler_persists_periodic_missing_health_without_business_counts(
    settings,
) -> None:
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    manager = SourceManager(
        (_source("empty-health", missing_after=0.06),),
        service,
        adapter_factory=lambda _config: _EmptyAdapter(),
        jitter=lambda _start, _end: 0,
        health_interval_seconds=0.02,
    )
    manager.start()
    try:
        _wait_until(
            lambda: any(
                item["metric"] == "source.missing_state"
                and item["value"] is True
                for item in repository.list_observations(
                    kind="source_health",
                    limit=100,
                )
            )
        )
        item = _item(manager, "empty-health")
        health_observations = repository.list_observations(
            kind="source_health",
            limit=100,
        )
        assert item["signal"] == "missing_data"
        assert item["records_received"] == 0
        assert item["records_inserted"] == 0
        assert item["records_duplicate"] == 0
        assert item["health_observations_inserted"] >= 3
        assert item["health_telemetry_last_error"] is None
        assert len(health_observations) >= 3
        assert repository.stats()["outbox_pending"] == len(
            health_observations
        )
    finally:
        manager.stop()


def test_methane_ratio_switches_to_fast_polling_then_bounded_window_expires(
    settings,
) -> None:
    adapter = _TimedMethaneAdapter([0.45, 0.1])
    repository = Repository(settings.database_path)
    service = EdgeService(repository, settings)
    manager = SourceManager(
        (_adaptive_source(),),
        service,
        adapter_factory=lambda _config: adapter,
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(lambda: adapter.polls >= 2)
        active = _item(manager, "gas-adaptive")
        adaptive = active["methane_adaptive_sampling"]
        assert adaptive["mode"] == "accelerated"
        assert adaptive["effective_interval_seconds"] == 0.02
        assert adaptive["last_trigger_reason"] == (
            "methane_warning_ratio"
        )
        assert adaptive["last_value_percent"] == 0.45
        assert adaptive["trigger_threshold_percent"] == 0.4
        assert adaptive["poll_schedule_only"] is True
        assert adaptive["device_write_capability"] is False
        assert manager.snapshot()["summary"]["methane_accelerated"] == 1
        _wait_until(
            lambda: bool(
                repository.list_source_scheduler_events(
                    "gas-adaptive"
                )
            )
        )
        events = repository.list_source_scheduler_events(
            "gas-adaptive"
        )
        assert len(events) == 1
        assert events[0]["event_type"] == (
            "methane_sampling_accelerated"
        )
        assert events[0]["reason"] == "methane_warning_ratio"
        assert events[0]["methane_value_percent"] == 0.45
        assert events[0]["trigger_threshold_percent"] == 0.4
        assert events[0]["device_write_capability"] is False

        _wait_until(lambda: adapter.polls >= 8)
        expired = _item(manager, "gas-adaptive")[
            "methane_adaptive_sampling"
        ]
        assert expired["mode"] == "regular"
        assert expired["effective_interval_seconds"] == 0.14
        assert adapter.poll_times[-1] - adapter.poll_times[-2] >= 0.1
    finally:
        manager.stop()


def test_failure_and_empty_poll_do_not_cancel_active_methane_window(
    settings,
) -> None:
    adapter = _TimedMethaneAdapter(
        [0.45, None, AdapterError("gas source temporarily unavailable")]
    )
    service = EdgeService(Repository(settings.database_path), settings)
    manager = SourceManager(
        (_adaptive_source(window=0.3),),
        service,
        adapter_factory=lambda _config: adapter,
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(
            lambda: (
                adapter.polls >= 3
                and _item(manager, "gas-adaptive")[
                    "consecutive_failures"
                ]
                >= 1
            )
        )
        item = _item(manager, "gas-adaptive")
        assert item["signal"] == "source_failure"
        assert item["last_record_count"] == 0
        assert item["methane_adaptive_sampling"]["mode"] == (
            "accelerated"
        )
        assert item["methane_adaptive_sampling"]["trigger_count"] == 1
        assert adapter.poll_times[2] - adapter.poll_times[1] < 0.08
    finally:
        manager.stop()


def test_local_methane_alert_accelerates_even_when_quality_flag_is_invalid(
    settings,
) -> None:
    adapter = _TimedMethaneAdapter([0.6, 0.1], quality_valid=False)
    service = EdgeService(Repository(settings.database_path), settings)
    manager = SourceManager(
        (_adaptive_source(window=0.3),),
        service,
        adapter_factory=lambda _config: adapter,
        jitter=lambda _start, _end: 0,
    )
    manager.start()
    try:
        _wait_until(lambda: adapter.polls >= 2)
        adaptive = _item(manager, "gas-adaptive")[
            "methane_adaptive_sampling"
        ]
        assert adaptive["mode"] == "accelerated"
        assert adaptive["last_trigger_reason"] == "methane_local_alert"
        assert adaptive["last_value_percent"] == 0.6
    finally:
        manager.stop()


def test_unexpired_methane_window_is_restored_and_capped_after_restart(
    settings,
) -> None:
    repository = Repository(settings.database_path)
    source = _adaptive_source(window=0.8)
    first_adapter = _TimedMethaneAdapter([0.45, 0.1])
    first = SourceManager(
        (source,),
        EdgeService(repository, settings),
        adapter_factory=lambda _config: first_adapter,
        jitter=lambda _start, _end: 0,
    )
    first.start()
    try:
        _wait_until(
            lambda: repository.load_source_scheduler_state(
                "gas-adaptive"
            )
            is not None
        )
        assert _item(first, "gas-adaptive")[
            "methane_adaptive_sampling"
        ]["mode"] == "accelerated"
    finally:
        first.stop()

    restored_source = _adaptive_source(window=0.2)
    restored = SourceManager(
        (restored_source,),
        EdgeService(repository, settings),
        adapter_factory=lambda _config: _EmptyAdapter(),
        jitter=lambda _start, _end: 0,
    )
    state = _item(restored, "gas-adaptive")[
        "methane_adaptive_sampling"
    ]
    assert state["mode"] == "accelerated"
    assert state["restored_after_restart"] is True
    assert 0 < state["accelerated_remaining_seconds"] <= 0.2
    assert state["restart_behavior"] == (
        "restore_unexpired_bounded_window"
    )
