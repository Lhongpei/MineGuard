"""Secret redaction for persisted traces and model-visible task text."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_SECRET_KEY = re.compile(
    r"(?:^|.*_)(?:api_?key|secret|password|passwd|authorization|cookie|"
    r"session_?token|access_?token|refresh_?token|private_?key(?:_pem)?|"
    r"hmac(?:_secret)?|signature)$",
    re.IGNORECASE,
)
_STRING_SECRETS = (
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
        r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(
        r"(?i)\b(api[_-]?key|password|secret|token)\s*[:=]\s*"
        r"([\"']?)[^\s,;\"']{4,}\2"
    ),
)
_REDACTED = "[REDACTED]"


def redact_text(value: str, *, maximum: int = 16_000) -> str:
    clean = value[:maximum]
    for pattern in _STRING_SECRETS:
        clean = pattern.sub(_REDACTED, clean)
    return clean


def sanitize(value: Any, *, depth: int = 0) -> Any:
    if depth > 12:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact_text(value, maximum=64_000)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, child in list(value.items())[:1_000]:
            key = str(raw_key)[:256]
            result[key] = (
                _REDACTED
                if _SECRET_KEY.search(key)
                else sanitize(child, depth=depth + 1)
            )
        return result
    if isinstance(value, (list, tuple)):
        return [sanitize(child, depth=depth + 1) for child in value[:10_000]]
    return redact_text(str(value), maximum=1_000)


def has_secret_material(value: Any) -> bool:
    """Return true when sanitizing would remove credential-like material."""

    return sanitize(value) != value
