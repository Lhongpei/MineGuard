from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


@dataclass(frozen=True)
class FieldMapping:
    target: str
    source: str
    value_type: Literal["preserve", "integer", "number"] = "number"
    factor: float = 1.0
    offset: float = 0.0
    required: bool = False
    reduce: Literal["single", "sum", "average", "latest"] = "single"


@dataclass(frozen=True)
class Shift:
    name: str
    start_minutes: int


@dataclass(frozen=True)
class SourceConfig:
    id: str
    adapter: Literal["file-drop", "http-poll", "sqlite-query"]
    source_name: str
    source_system: str
    truth_statement: str
    format: Literal["json", "csv"] = "json"
    records_path: str | None = None
    path: Path | None = None
    glob: str = "*.json"
    url: str | None = None
    allowed_hosts: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    allow_private_network: bool = False
    allow_insecure_http: bool = False
    headers: dict[str, str] = field(default_factory=dict)
    ca_bundle: Path | None = None
    database: Path | None = None
    query: str | None = None
    timeout_seconds: float = 10.0
    stable_seconds: float = 2.0
    max_bytes: int = 5_000_000
    max_records: int = 10_000
    revision_seed: int = 0
    max_staleness_seconds: int = 3600
    max_files_per_poll: int = 100
    max_total_bytes: int = 20_000_000
    max_total_records: int = 50_000
    # Heterogeneous upstream systems may override the pipeline's canonical
    # parsing defaults without introducing a code dependency on that system.
    timestamp_field: str | None = None
    period_type: Literal["daily", "shift"] | None = None
    scope_field: str | None = None
    scope_values: dict[str, str] | None = None
    mappings: tuple[FieldMapping, ...] | None = None
    shifts: tuple[Shift, ...] | None = None


@dataclass(frozen=True)
class PipelineConfig:
    id: str
    enterprise_id: str
    report_type: str
    period_type: Literal["daily", "shift"]
    timezone: str
    timestamp_field: str
    scope_field: str | None
    scope_values: dict[str, str]
    reporting_lag_days: int
    workflow_name: str
    required_sources: tuple[str, ...]
    sources: tuple[SourceConfig, ...]
    mappings: tuple[FieldMapping, ...]
    shifts: tuple[Shift, ...] = ()


@dataclass(frozen=True)
class ServiceConfig:
    config_path: Path
    state_db: Path
    poll_interval_seconds: float
    agent_url: str
    client_id: str
    secret_env: str
    agent_timeout_seconds: float
    agent_max_response_bytes: int
    agent_allowed_hosts: tuple[str, ...]
    agent_allowed_ports: tuple[int, ...]
    agent_allow_private_network: bool
    agent_allow_insecure_http: bool
    agent_ca_bundle: Path | None
    retry_base_seconds: float
    retry_max_seconds: float
    lease_seconds: int
    pipelines: tuple[PipelineConfig, ...]


@dataclass(frozen=True)
class RawBatch:
    source_id: str
    original_filename: str
    records: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    request_id: str
    pipeline_id: str
    source_id: str
    draft_key: str
    period_key: str
    content_sha256: str
    payload: dict[str, Any]
    revision_floor: int = 0
    record_count: int = 0


@dataclass(frozen=True)
class DeliveryRecord:
    event_id: str
    pipeline_id: str
    source_id: str
    draft_key: str
    payload_json: str
    attempts: int
    trigger_workflow: bool


@dataclass(frozen=True)
class HealthDeliveryRecord:
    event_id: str
    pipeline_id: str
    source_id: str
    draft_key: str
    payload_json: str
    attempts: int
