from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .adapters import collect_file_drop, collect_http_poll, collect_sqlite_query
from .client import AgentClient
from .config import require_secret
from .errors import ConnectorError, DeliveryError
from .models import PipelineConfig, ServiceConfig, SourceConfig
from .normalize import normalize_batches
from .reporting import reporting_target
from .state import StateStore

logger = logging.getLogger("enterprise_connector")


@dataclass
class CycleResult:
    discovered: int = 0
    duplicate: int = 0
    delivered: int = 0
    retried: int = 0
    dead: int = 0
    source_errors: int = 0
    health_queued: int = 0
    health_delivered: int = 0
    health_retried: int = 0
    health_dead: int = 0

    @property
    def errors(self) -> int:
        return (
            self.retried
            + self.dead
            + self.source_errors
            + self.health_retried
            + self.health_dead
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "discovered": self.discovered,
            "duplicate": self.duplicate,
            "delivered": self.delivered,
            "retried": self.retried,
            "dead": self.dead,
            "source_errors": self.source_errors,
            "health_queued": self.health_queued,
            "health_delivered": self.health_delivered,
            "health_retried": self.health_retried,
            "health_dead": self.health_dead,
        }


def _log(event: str, **fields: Any) -> None:
    logger.info(json.dumps({"event": event, **fields}, ensure_ascii=False, sort_keys=True))


def _collect(source: SourceConfig):
    if source.adapter == "file-drop":
        return collect_file_drop(source)
    if source.adapter == "http-poll":
        return collect_http_poll(source)
    return collect_sqlite_query(source)


def _file_drop_has_candidate(source: SourceConfig) -> bool:
    if source.adapter != "file-drop" or source.path is None:
        return False
    try:
        return any(
            path.is_file() and not path.is_symlink()
            for path in source.path.resolve().glob(source.glob)
        )
    except OSError:
        return False


def _retry_delay(config: ServiceConfig, event_id: str, attempts: int) -> float:
    base = min(config.retry_max_seconds, config.retry_base_seconds * (2 ** min(attempts, 16)))
    digest = hashlib.sha256(f"{event_id}:{attempts}".encode()).digest()
    jitter = 0.8 + (int.from_bytes(digest[:2], "big") / 65535) * 0.4
    return min(config.retry_max_seconds, base * jitter)


def _utc_text(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _current_reporting_target(
    pipeline: PipelineConfig, timestamp: float
) -> tuple[str, str, str]:
    return reporting_target(pipeline, timestamp)


class ConnectorService:
    def __init__(self, config: ServiceConfig):
        self.config = config
        self.owner = f"connector-{uuid.uuid4()}"
        self.store = StateStore(config.state_db)
        secret = require_secret(config)
        self.client = AgentClient(
            agent_url=config.agent_url,
            client_id=config.client_id,
            secret=secret,
            timeout_seconds=config.agent_timeout_seconds,
            max_response_bytes=config.agent_max_response_bytes,
            allowed_hosts=config.agent_allowed_hosts,
            allowed_ports=config.agent_allowed_ports,
            allow_private_network=config.agent_allow_private_network,
            ca_bundle=config.agent_ca_bundle,
        )
        self._pipelines = {pipeline.id: pipeline for pipeline in config.pipelines}
        self._has_lease = False

    def acquire(self) -> None:
        if not self.store.acquire_lease(self.owner, self.config.lease_seconds):
            raise ConnectorError("已有另一个 connector-service 实例持有运行租约")
        self._has_lease = True

    def close(self) -> None:
        if self._has_lease:
            self.store.release_lease(self.owner)
            self._has_lease = False
        self.store.close()

    def _renew(self) -> None:
        if not self.store.renew_lease(self.owner, self.config.lease_seconds):
            raise ConnectorError("运行租约已丢失，停止处理以避免双实例重复")

    def _queue_health(
        self,
        result: CycleResult,
        pipeline: PipelineConfig,
        source: SourceConfig,
        *,
        draft_key: str,
        reporting_month: str,
        outcome: str,
        attempted_at: float,
        completed_at: float,
        record_count: int,
        coverage_as_of: str | None,
        error_code: str | None,
        snapshot_sha256: str | None,
        autofill_event_id: str | None,
        source_revision: int | None,
    ) -> None:
        heartbeat = min(900.0, max(60.0, source.max_staleness_seconds / 2))
        event_id = self.store.register_health(
            pipeline.id,
            {
                "contract_version": "enterprise-source-health/v1",
                "draft_key": draft_key,
                "reporting_month": reporting_month,
                "source_id": source.id,
                "source_system": source.source_system,
                "outcome": outcome,
                "attempted_at": _utc_text(attempted_at),
                "completed_at": _utc_text(completed_at),
                "record_count": record_count,
                "coverage_as_of": coverage_as_of,
                "error_code": error_code,
                "snapshot_sha256": snapshot_sha256,
                "autofill_event_id": autofill_event_id,
                "source_revision": source_revision,
            },
            heartbeat_seconds=heartbeat,
            completed_epoch=completed_at,
        )
        if event_id is not None:
            result.health_queued += 1
            _log(
                "source_health_queued",
                pipeline_id=pipeline.id,
                source_id=source.id,
                draft_key=draft_key,
                outcome=outcome,
                event_id=event_id,
            )

    def collect(self, result: CycleResult) -> None:
        for pipeline in self.config.pipelines:
            for source in pipeline.sources:
                self._renew()
                attempted_at = time.time()
                try:
                    batches = _collect(source)
                    completed_at = time.time()
                    record_count = sum(len(batch.records) for batch in batches)
                    if record_count == 0:
                        health_status = (
                            "stability_wait"
                            if not batches and _file_drop_has_candidate(source)
                            else "empty"
                        )
                        self.store.record_collection_health(
                            pipeline.id,
                            source.id,
                            status=health_status,
                            record_count=0,
                        )
                        draft_key, month, _coverage = _current_reporting_target(
                            pipeline, completed_at
                        )
                        self._queue_health(
                            result,
                            pipeline,
                            source,
                            draft_key=draft_key,
                            reporting_month=month,
                            outcome=(
                                "stability_wait"
                                if health_status == "stability_wait"
                                else "success_empty"
                            ),
                            attempted_at=attempted_at,
                            completed_at=completed_at,
                            record_count=0,
                            coverage_as_of=None,
                            error_code=None,
                            snapshot_sha256=None,
                            autofill_event_id=None,
                            source_revision=None,
                        )
                        _log(
                            "source_collection_empty",
                            pipeline_id=pipeline.id,
                            source_id=source.id,
                            collection_status=health_status,
                        )
                        continue
                    events = normalize_batches(pipeline, source, batches)
                    completed_at = time.time()
                    self.store.record_collection_health(
                        pipeline.id,
                        source.id,
                        status="ok",
                        record_count=record_count,
                    )
                    health_drafts: set[str] = set()
                    for event in events:
                        self.store.record_snapshot_health(
                            pipeline.id,
                            source.id,
                            event.draft_key,
                            event.period_key,
                            record_count=record_count,
                        )
                        registered_event_id = self.store.register(event)
                        if registered_event_id is not None:
                            result.discovered += 1
                            _log(
                                "observation_discovered",
                                pipeline_id=pipeline.id,
                                source_id=source.id,
                                event_id=registered_event_id,
                                draft_key=event.draft_key,
                            )
                        else:
                            result.duplicate += 1
                        metadata = self.store.latest_observation_metadata(
                            pipeline.id, source.id, event.draft_key
                        )
                        assert metadata is not None
                        source_payload = event.payload["source"]
                        assert isinstance(source_payload, dict)
                        self._queue_health(
                            result,
                            pipeline,
                            source,
                            draft_key=event.draft_key,
                            reporting_month=event.period_key,
                            outcome="success_nonempty",
                            attempted_at=attempted_at,
                            completed_at=completed_at,
                            record_count=event.record_count,
                            coverage_as_of=str(source_payload["coverage_as_of"]),
                            error_code=None,
                            snapshot_sha256=str(metadata["delivered_content_sha256"]),
                            autofill_event_id=str(metadata["event_id"]),
                            source_revision=int(metadata["source_revision"]),
                        )
                        health_drafts.add(event.draft_key)
                    current_draft, current_month, _current_coverage = _current_reporting_target(
                        pipeline, completed_at
                    )
                    if current_draft not in health_drafts:
                        self._queue_health(
                            result,
                            pipeline,
                            source,
                            draft_key=current_draft,
                            reporting_month=current_month,
                            outcome="success_empty",
                            attempted_at=attempted_at,
                            completed_at=completed_at,
                            record_count=0,
                            coverage_as_of=None,
                            error_code=None,
                            snapshot_sha256=None,
                            autofill_event_id=None,
                            source_revision=None,
                        )
                except ConnectorError as exc:
                    completed_at = time.time()
                    self.store.record_collection_health(
                        pipeline.id,
                        source.id,
                        status="error",
                        record_count=0,
                        error=str(exc),
                    )
                    draft_key, month, _coverage = _current_reporting_target(
                        pipeline, completed_at
                    )
                    self._queue_health(
                        result,
                        pipeline,
                        source,
                        draft_key=draft_key,
                        reporting_month=month,
                        outcome="error",
                        attempted_at=attempted_at,
                        completed_at=completed_at,
                        record_count=0,
                        coverage_as_of=None,
                        error_code="source_collection_error",
                        snapshot_sha256=None,
                        autofill_event_id=None,
                        source_revision=None,
                    )
                    result.source_errors += 1
                    _log(
                        "source_collection_failed",
                        pipeline_id=pipeline.id,
                        source_id=source.id,
                        error=str(exc),
                    )
                except Exception as exc:
                    # A malformed adapter/plugin result must not terminate the
                    # daemon or prevent independent sources from being polled.
                    # Persist and log only the exception class across this
                    # unexpected boundary; exception text may contain source
                    # rows, credentials or an unsafe filesystem name.
                    completed_at = time.time()
                    exception_type = type(exc).__name__
                    self.store.record_collection_health(
                        pipeline.id,
                        source.id,
                        status="error",
                        record_count=0,
                        error=f"internal:{exception_type}",
                    )
                    draft_key, month, _coverage = _current_reporting_target(
                        pipeline, completed_at
                    )
                    self._queue_health(
                        result,
                        pipeline,
                        source,
                        draft_key=draft_key,
                        reporting_month=month,
                        outcome="error",
                        attempted_at=attempted_at,
                        completed_at=completed_at,
                        record_count=0,
                        coverage_as_of=None,
                        error_code="source_internal_error",
                        snapshot_sha256=None,
                        autofill_event_id=None,
                        source_revision=None,
                    )
                    result.source_errors += 1
                    _log(
                        "source_collection_internal_error",
                        pipeline_id=pipeline.id,
                        source_id=source.id,
                        exception_type=exception_type,
                    )

    def dispatch_health(self, result: CycleResult) -> None:
        for pending in self.store.pending_health(limit=1000):
            self._renew()
            body = pending.payload_json.encode("utf-8")
            try:
                status = self.client.send_health(pending.event_id, body)
                self.store.mark_health_delivered(pending.event_id, status)
                result.health_delivered += 1
                _log(
                    "source_health_delivered",
                    event_id=pending.event_id,
                    draft_key=pending.draft_key,
                    response_status=status,
                )
            except DeliveryError as exc:
                if exc.retryable:
                    delay = _retry_delay(self.config, pending.event_id, pending.attempts)
                    self.store.mark_health_retry(
                        pending.event_id,
                        str(exc),
                        delay,
                        exc.status,
                    )
                    result.health_retried += 1
                    _log(
                        "source_health_retry_scheduled",
                        event_id=pending.event_id,
                        response_status=exc.status,
                        error_code=exc.code,
                        delay_seconds=round(delay, 3),
                    )
                else:
                    self.store.mark_health_dead(pending.event_id, str(exc), exc.status)
                    result.health_dead += 1
                    _log(
                        "source_health_permanently_rejected",
                        event_id=pending.event_id,
                        response_status=exc.status,
                        error_code=exc.code,
                    )

    def dispatch(self, result: CycleResult) -> None:
        for pending in self.store.pending(limit=1000):
            self._renew()
            pipeline: PipelineConfig | None = self._pipelines.get(pending.pipeline_id)
            if pipeline is None:
                self.store.mark_dead(pending.event_id, "pipeline 已从配置中移除", None)
                result.dead += 1
                continue
            prepared = self.store.prepare_delivery(
                pending.event_id,
                pipeline.required_sources,
                max_staleness_by_source={
                    source.id: source.max_staleness_seconds
                    for source in pipeline.sources
                },
            )
            if prepared is None:
                continue
            body = prepared.payload_json.encode("utf-8")
            try:
                status = self.client.send(
                    prepared.event_id,
                    body,
                )
                self.store.mark_delivered(prepared.event_id, status)
                result.delivered += 1
                _log(
                    "observation_delivered",
                    event_id=prepared.event_id,
                    draft_key=prepared.draft_key,
                    trigger_workflow=prepared.trigger_workflow,
                    response_status=status,
                )
            except DeliveryError as exc:
                if exc.retryable:
                    delay = _retry_delay(self.config, prepared.event_id, prepared.attempts)
                    self.store.mark_retry(
                        prepared.event_id,
                        str(exc),
                        delay,
                        exc.status,
                    )
                    result.retried += 1
                    _log(
                        "delivery_retry_scheduled",
                        event_id=prepared.event_id,
                        response_status=exc.status,
                        error_code=exc.code,
                        delay_seconds=round(delay, 3),
                    )
                else:
                    self.store.mark_dead(prepared.event_id, str(exc), exc.status)
                    result.dead += 1
                    _log(
                        "delivery_permanently_rejected",
                        event_id=prepared.event_id,
                        response_status=exc.status,
                        error_code=exc.code,
                    )

    def run_cycle(self) -> CycleResult:
        result = CycleResult()
        self.collect(result)
        self.dispatch_health(result)
        self.dispatch(result)
        _log("cycle_completed", **result.as_dict())
        return result

    def run_forever(self, should_stop: Any) -> None:
        while not should_stop():
            started = time.monotonic()
            # Source and delivery failures are already converted into durable
            # per-source/per-event state. A ConnectorError here means the
            # singleton lease or state store failed and must terminate the
            # process rather than spin beside another instance.
            self.run_cycle()
            elapsed = time.monotonic() - started
            remaining = max(0.1, self.config.poll_interval_seconds - elapsed)
            deadline = time.monotonic() + remaining
            while not should_stop() and time.monotonic() < deadline:
                time.sleep(min(0.5, deadline - time.monotonic()))
