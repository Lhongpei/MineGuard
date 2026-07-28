"""Domain errors exposed consistently by the CLI and HTTP API."""


class EdgeAgentError(Exception):
    """Base class for expected edge-agent failures."""


class ValidationError(EdgeAgentError):
    """Input data did not satisfy the edge wire contract."""


class ConfigurationError(EdgeAgentError):
    """Runtime configuration is unsafe or inconsistent."""


class AdapterError(EdgeAgentError):
    """A read-only source adapter could not acquire or parse data."""


class ForwardError(EdgeAgentError):
    """An upstream delivery attempt failed."""

