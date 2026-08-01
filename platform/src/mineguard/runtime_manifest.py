"""Deterministic runtime-version metadata for reproducible analysis records.

The manifest deliberately contains no host name, filesystem path, account or
other machine identifier.  Callers can attach it to an analysis context,
evidence trace or diagnostic export without leaking deployment-specific data.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version
import platform
from typing import Final

from . import __version__


RUNTIME_DISTRIBUTIONS: Final[tuple[str, ...]] = (
    "numpy",
    "scipy",
    "pydantic",
    "PyYAML",
    "olefile",
    "xlrd",
)


def _distribution_version(distribution: str) -> str:
    try:
        return version(distribution)
    except PackageNotFoundError:
        return "not-installed"


def build_runtime_manifest() -> dict[str, object]:
    """Return stable application, Python and numerical dependency versions."""

    return {
        "schema_version": "mineguard.runtime.v1",
        "application": {
            "name": "mineguard-mvp",
            "version": __version__,
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "dependencies": {
            distribution: _distribution_version(distribution)
            for distribution in RUNTIME_DISTRIBUTIONS
        },
    }


__all__ = ["RUNTIME_DISTRIBUTIONS", "build_runtime_manifest"]
