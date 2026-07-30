"""Small dependency-free types shared by the harness."""

from __future__ import annotations

from dataclasses import asdict, dataclass

RUN_STATUSES = frozenset(
    {
        "queued",
        "running",
        "waiting_approval",
        "completed",
        "failed",
        "cancelled",
    }
)
TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled"})
RUN_MODES = frozenset({"auto", "deterministic"})


@dataclass(frozen=True, slots=True)
class HarnessBudgets:
    """Server-owned limits; callers cannot raise them through the API."""

    max_steps: int = 8
    max_tool_calls: int = 12
    max_duration_seconds: float = 60.0
    max_result_bytes: int = 128 * 1024
    max_single_result_bytes: int = 64 * 1024

    def public_dict(self) -> dict[str, int | float]:
        return asdict(self)
