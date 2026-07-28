"""Application service coordinating normalization, rules and persistence."""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

from .adapters import ReadOnlyAdapter
from .errors import ValidationError
from .forwarder import Forwarder
from .models import ObservationKind, utc_now
from .normalization import normalize_observation
from .rules import SafetyRuleEngine
from .settings import Settings
from .storage import Repository


@dataclasses.dataclass(frozen=True, slots=True)
class MethaneSamplingEvidence:
    metric_code: str
    value_percent: float
    observed_at: str
    revision: int
    sequence_no: int
    quality_valid: bool
    local_alert_generated: bool


@dataclasses.dataclass(frozen=True, slots=True)
class IngestResult:
    observation_id: str
    revision: int
    inserted: bool
    duplicate: bool
    alert_ids: list[str]
    methane_sampling_evidence: MethaneSamplingEvidence | None = (
        dataclasses.field(default=None, repr=False, compare=False)
    )

    def to_dict(self) -> dict[str, Any]:
        # Sampling evidence is internal scheduler input, not part of the
        # external ingestion response contract.
        return {
            "observation_id": self.observation_id,
            "revision": self.revision,
            "inserted": self.inserted,
            "duplicate": self.duplicate,
            "alert_ids": self.alert_ids,
        }


class EdgeService:
    def __init__(
        self,
        repository: Repository,
        settings: Settings,
        *,
        forwarder: Forwarder | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.rule_engine = SafetyRuleEngine(settings.thresholds)
        self.forwarder = forwarder or Forwarder(repository, settings)

    def ingest(
        self,
        raw: dict[str, Any],
        *,
        channel: str,
        source_id: str,
    ) -> IngestResult:
        observation = normalize_observation(
            raw,
            default_mine_id=self.settings.mine_id,
            default_timezone=self.settings.local_timezone,
            forced_channel=channel,
            forced_source_id=source_id,
        )
        if observation.mine_id != self.settings.mine_id:
            raise ValidationError(
                f"拒绝跨矿数据：配置矿井 {self.settings.mine_id}，"
                f"收到 {observation.mine_id}"
            )
        alerts = self.rule_engine.evaluate(observation)
        inserted, stored_alerts = self.repository.record(observation, alerts)
        methane_sampling_evidence = None
        if observation.kind is ObservationKind.METHANE:
            wire = observation.to_wire_dict()
            if wire["metric_code"] == "methane.concentration_percent":
                methane_sampling_evidence = MethaneSamplingEvidence(
                    metric_code=wire["metric_code"],
                    value_percent=float(wire["value"]),
                    observed_at=observation.observed_at,
                    revision=observation.revision,
                    sequence_no=observation.sequence_no,
                    quality_valid=bool(
                        observation.quality_detail.get("valid", False)
                    ),
                    local_alert_generated=any(
                        item.rule_id == "methane-concentration-v1"
                        for item in alerts
                    ),
                )
        return IngestResult(
            observation_id=observation.observation_id,
            revision=observation.revision,
            inserted=inserted,
            duplicate=not inserted,
            alert_ids=[item.alert_id for item in stored_alerts],
            methane_sampling_evidence=methane_sampling_evidence,
        )

    def ingest_many(
        self,
        values: list[dict[str, Any]],
        *,
        channel: str,
        source_id: str,
    ) -> list[IngestResult]:
        return [
            self.ingest(value, channel=channel, source_id=source_id)
            for value in values
        ]

    def ingest_source_health(
        self,
        *,
        source_id: str,
        heartbeat_age_seconds: float,
        consecutive_failures: int,
        missing_state: bool,
        status_code: str,
        emitted_at: str | None = None,
        cycle_id: str | None = None,
    ) -> list[IngestResult]:
        """Persist one auditable, idempotent source-health telemetry cycle.

        Source health is intentionally kept out of adapter business-record
        counters.  It still travels through the same durable observation and
        outbox path, so the regulator can independently see missing data even
        when the source itself has no business records to send.
        """

        observed_at = emitted_at or utc_now()
        cycle_token = cycle_id or hashlib.sha256(
            (
                f"{self.settings.client_id}\n{source_id}\n"
                f"{observed_at}"
            ).encode()
        ).hexdigest()[:32]
        failures = int(consecutive_failures)
        if failures < 0:
            raise ValidationError("source health 连续失败次数不得小于零")
        heartbeat_age = float(heartbeat_age_seconds)
        if heartbeat_age < 0:
            raise ValidationError("source health 心跳时延不得小于零")
        if len(status_code) > 64:
            raise ValidationError("source health status_code 最长 64 字符")

        if missing_state or failures >= 3:
            device_health = "fault"
        elif failures > 0 or status_code not in {
            "ok",
            "partial_records_rejected",
        }:
            device_health = "degraded"
        else:
            device_health = "healthy"
        flags: list[str] = ["edge_agent_generated_source_health"]
        if missing_state:
            flags.append("source_data_missing")
        if failures:
            flags.append("source_poll_failure")
        if status_code in {
            "awaiting_first_poll",
            "awaiting_first_data",
        }:
            flags.append("source_state_unconfirmed")

        measurements: tuple[tuple[str, float | int | bool, str], ...] = (
            (
                "source.heartbeat_age_seconds",
                round(heartbeat_age, 3),
                "s",
            ),
            ("source.consecutive_failures", failures, "count"),
            ("source.missing_state", bool(missing_state), "count"),
        )
        values: list[dict[str, Any]] = []
        for metric, value, unit in measurements:
            metric_token = metric.removeprefix("source.").replace(".", "-")
            event_id = (
                f"source-health:{source_id}:{cycle_token}:{metric_token}"
            )
            values.append(
                {
                    "kind": "source_health",
                    "metric": metric,
                    "value": value,
                    "unit": unit,
                    "observed_at": observed_at,
                    "location_code": source_id,
                    "event_id": event_id,
                    "source_record_id": event_id,
                    "status_code": status_code,
                    "quality": {
                        "valid": True,
                        "completeness": 1.0,
                        "timeliness": 1.0,
                        "device_health": device_health,
                        "clock_synchronized": True,
                        "flags": flags,
                    },
                    "provenance": {
                        "channel": "edge_internal",
                        "source_id": source_id,
                        "source_event_id": event_id,
                        "acquired_at": observed_at,
                    },
                }
            )
        return self.ingest_many(
            values,
            channel="edge_internal",
            source_id=source_id,
        )

    def ingest_manual(self, raw: dict[str, Any]) -> IngestResult:
        provenance = raw.get("provenance")
        if not isinstance(provenance, dict):
            raise ValidationError("人工补录必须包含 provenance 对象")
        source_id = str(provenance.get("source_id") or "manual-entry").strip()
        return self.ingest(raw, channel="manual", source_id=source_id)

    def run_adapter(self, adapter: ReadOnlyAdapter) -> list[IngestResult]:
        if not adapter.read_only:
            raise ValidationError("拒绝执行未声明只读的采集适配器")
        return [
            self.ingest(
                record.data,
                channel=record.channel,
                source_id=record.source_id,
            )
            for record in adapter.poll()
        ]

    def health(self) -> dict[str, Any]:
        database = self.repository.health()
        return {
            "status": "ok" if database["ok"] else "degraded",
            "mine_id": self.settings.mine_id,
            "client_id": self.settings.client_id,
            "database": database,
            "upstream_configured": bool(self.settings.upstream_url),
            "thresholds_calibrated": self.settings.thresholds_calibrated,
            "production_control_api": False,
            "stats": self.repository.stats(),
        }
