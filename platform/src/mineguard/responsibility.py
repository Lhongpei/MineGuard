"""Background routing and read-receipt escalation for safety alerts."""

from __future__ import annotations

import threading

from .edge_store import EdgeTelemetryRepository


class SafetyResponsibilityDispatcher:
    """Small restart-safe worker backed entirely by repository state."""

    def __init__(
        self,
        repository: EdgeTelemetryRepository,
        *,
        poll_seconds: float = 5.0,
    ) -> None:
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        self._repository = repository
        self._poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._last_error: str | None = None

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._wake.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="mineguard-safety-responsibility",
                daemon=True,
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=max(2.0, self._poll_seconds + 1.0))

    def wake(self) -> None:
        self._wake.set()

    def is_running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def run_once(self) -> dict[str, int]:
        routed = self._repository.route_unassigned_alerts()
        escalated = self._repository.escalate_responsibilities()
        sla_escalated = self._repository.escalate_overdue_alerts()
        with self._lock:
            self._last_error = None
        return {
            "routed": routed,
            "escalated": escalated,
            "sla_escalated": sla_escalated,
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as error:  # pragma: no cover - fail-safe loop
                with self._lock:
                    self._last_error = type(error).__name__[:128]
            self._wake.wait(self._poll_seconds)
            self._wake.clear()


__all__ = ["SafetyResponsibilityDispatcher"]
