class ConnectorError(Exception):
    """Expected operational or validation failure."""


class ConfigurationError(ConnectorError):
    """Configuration is invalid."""


class SourceError(ConnectorError):
    """A read-only source could not be collected safely."""


class DeliveryError(ConnectorError):
    """The Agent endpoint could not accept an event."""

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = True,
        status: int | None = None,
        code: str | None = None,
    ):
        super().__init__(message)
        self.retryable = retryable
        self.status = status
        self.code = code
