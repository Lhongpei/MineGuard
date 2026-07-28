"""Small deterministic and security-sensitive helpers."""

from __future__ import annotations

import hashlib
import json
import math
import secrets
from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


def utc_text(value: datetime | None = None) -> str:
    current = value or utc_now()
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("datetime must include a timezone")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_aware_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as error:
        raise ValueError(f"{field} must be a valid ISO-8601 datetime") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON numbers are forbidden")
    if isinstance(value, dict):
        for child in value.values():
            _reject_non_finite(child)
    elif isinstance(value, list):
        for child in value:
            _reject_non_finite(child)


def canonical_json(value: Any) -> str:
    _reject_non_finite(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _jcs_number(value: int | float) -> str:
    """Render an interoperable RFC 8785/ECMAScript JSON number.

    Python and ECMAScript use the same shortest-round-trip binary64 digits but
    choose different plain/scientific notation around the edges.  This
    normalises those notation choices and rejects integers outside the exact
    binary64 interoperability range required by I-JSON.
    """

    if isinstance(value, bool):
        raise TypeError("boolean is not a JCS number")
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise ValueError("JCS integer exceeds the exact binary64 range")
        return str(value)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON numbers are forbidden")
    if value == 0:
        return "0"
    negative = value < 0
    absolute = -value if negative else value
    rendered = repr(absolute).lower()
    if "e" not in rendered:
        if rendered.endswith(".0"):
            rendered = rendered[:-2]
        return ("-" if negative else "") + rendered

    mantissa, exponent_text = rendered.split("e", 1)
    exponent = int(exponent_text)
    integer_part, _dot, fraction_part = mantissa.partition(".")
    digits = (integer_part + fraction_part).lstrip("0") or "0"
    decimal_position = len(integer_part) + exponent
    if 1e-6 <= absolute < 1e21:
        if decimal_position <= 0:
            result = "0." + ("0" * -decimal_position) + digits
        elif decimal_position >= len(digits):
            result = digits + ("0" * (decimal_position - len(digits)))
        else:
            result = digits[:decimal_position] + "." + digits[decimal_position:]
    else:
        scientific_exponent = decimal_position - 1
        result = digits[0]
        if len(digits) > 1:
            result += "." + digits[1:]
        result += ("e+" if scientific_exponent >= 0 else "e-") + str(
            abs(scientific_exponent)
        )
    return ("-" if negative else "") + result


def jcs_json(value: Any) -> str:
    """Return RFC 8785 canonical JSON for the contract's I-JSON domain."""

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        # U+2028/U+2029 are valid JSON and RFC 8785 leaves them unescaped.
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, list):
        return "[" + ",".join(jcs_json(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JCS object keys must be strings")
        # RFC 8785 sorts object names by UTF-16 code units.
        keys = sorted(value, key=lambda item: item.encode("utf-16be"))
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                + ":"
                + jcs_json(value[key])
                for key in keys
            )
            + "}"
        )
    raise TypeError(f"{type(value).__name__} is not a JSON value")


def sha256_jcs(value: Any) -> str:
    return hashlib.sha256(jcs_json(value).encode("utf-8")).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def deep_copy_json(value: Any) -> Any:
    return json.loads(canonical_json(value))
