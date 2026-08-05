"""Domain error types safe to expose through the local API."""

from __future__ import annotations

from typing import Any


class AgentError(RuntimeError):
    code = "agent_error"
    status = 400


class NotFoundError(AgentError):
    code = "not_found"
    status = 404


class ConflictError(AgentError):
    code = "conflict"
    status = 409


class ValidationBlockedError(AgentError):
    code = "validation_blocked"
    status = 422


class ConfirmationRequiredError(AgentError):
    code = "confirmation_required"
    status = 409


class ImportContentError(AgentError):
    code = "invalid_import"
    status = 422


class RequestTooLargeError(AgentError):
    code = "request_too_large"
    status = 413


class ConnectorQuotaExceededError(AgentError):
    code = "connector_quota_exceeded"
    status = 429


class ProviderError(AgentError):
    code = "llm_provider_failed"
    status = 502


class PlatformError(AgentError):
    code = "platform_submission_failed"
    status = 502

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.details = details or {}

    @property
    def platform_code(self) -> str:
        value = self.details.get("platform_code")
        return value if isinstance(value, str) else self.code
