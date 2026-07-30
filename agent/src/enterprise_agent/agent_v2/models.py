"""Domain constants for durable, read-only enterprise agent flows."""

from __future__ import annotations

import re
from dataclasses import dataclass

FLOW_STATUSES = frozenset(
    {"queued", "running", "blocked", "succeeded", "failed", "cancelled"}
)
TERMINAL_FLOW_STATUSES = frozenset(
    {"blocked", "succeeded", "failed", "cancelled"}
)
RETRYABLE_FLOW_STATUSES = frozenset({"blocked", "failed"})
STEP_STATUSES = frozenset({"running", "succeeded", "failed", "cancelled"})
TRIGGER_TYPES = frozenset({"manual", "schedule", "event"})

DAILY_COAL_HEALTH_WORKFLOW = "daily_coal_health"
DAILY_COAL_HEALTH_VERSION = "2.0"
SUPPORTED_WORKFLOWS = frozenset({DAILY_COAL_HEALTH_WORKFLOW})

ACTOR_PATTERN = re.compile(
    r"^[A-Za-z0-9\u4e00-\u9fff]"
    r"[A-Za-z0-9\u4e00-\u9fff._:@ -]{0,127}$"
)
DRAFT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CLIENT_REQUEST_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"
)


@dataclass(frozen=True, slots=True)
class FlowRuntimeConfig:
    """Small bounds that prevent a background workflow from exhausting a host."""

    worker_count: int = 2
    specialist_worker_count: int = 4
    queue_capacity: int = 200
    actor_active_limit: int = 20
    global_active_limit: int = 200
    lease_seconds: int = 120

    def __post_init__(self) -> None:
        if not 1 <= self.worker_count <= 8:
            raise ValueError("worker_count 必须在 1 到 8 之间")
        if not 1 <= self.specialist_worker_count <= 8:
            raise ValueError("specialist_worker_count 必须在 1 到 8 之间")
        if not 1 <= self.queue_capacity <= 2_000:
            raise ValueError("queue_capacity 必须在 1 到 2000 之间")
        if not 1 <= self.actor_active_limit <= 200:
            raise ValueError("actor_active_limit 必须在 1 到 200 之间")
        if not 1 <= self.global_active_limit <= 2_000:
            raise ValueError("global_active_limit 必须在 1 到 2000 之间")
        if not 30 <= self.lease_seconds <= 600:
            raise ValueError("lease_seconds 必须在 30 到 600 之间")


def workflow_version(workflow_name: str) -> str:
    if workflow_name == DAILY_COAL_HEALTH_WORKFLOW:
        return DAILY_COAL_HEALTH_VERSION
    raise ValueError("不支持的智能体工作流")


__all__ = [
    "ACTOR_PATTERN",
    "CLIENT_REQUEST_ID_PATTERN",
    "DAILY_COAL_HEALTH_VERSION",
    "DAILY_COAL_HEALTH_WORKFLOW",
    "DRAFT_ID_PATTERN",
    "FLOW_STATUSES",
    "FlowRuntimeConfig",
    "RETRYABLE_FLOW_STATUSES",
    "STEP_STATUSES",
    "SUPPORTED_WORKFLOWS",
    "TERMINAL_FLOW_STATUSES",
    "TRIGGER_TYPES",
    "workflow_version",
]
