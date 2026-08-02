"""Read bundled MineGuard assets without assuming a source checkout layout.

``__file__`` happens to point at package data in an editable installation, but
that is not a packaging contract.  In particular, frozen/standalone runtimes
may materialise resources in a runtime-specific package location.  The
``importlib.resources`` Traversable API works in both installations.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import PurePosixPath


_RESOURCE_DIRECTORIES = frozenset({"regulatory_web", "web"})


def read_package_resource(directory: str, filename: str) -> bytes:
    """Return one allowlisted package asset as bytes.

    The HTTP layers already map URLs through explicit allowlists.  This second
    check keeps the lower-level helper safe if it is reused by a self-check or
    another delivery boundary in the future.
    """

    if directory not in _RESOURCE_DIRECTORIES:
        raise ValueError("unsupported MineGuard resource directory")
    candidate = PurePosixPath(filename)
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or candidate.name != filename
        or candidate.is_absolute()
        or "\x00" in filename
    ):
        raise ValueError("resource filename must be a plain file name")
    return files("mineguard").joinpath(directory, filename).read_bytes()


__all__ = ["read_package_resource"]
