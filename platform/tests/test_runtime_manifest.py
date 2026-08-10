from __future__ import annotations

from importlib.metadata import version
import json
from pathlib import Path
import platform

from mineguard import __version__
from mineguard.runtime_manifest import (
    RUNTIME_DISTRIBUTIONS,
    build_runtime_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


def _constraints() -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in (ROOT / "constraints.txt").read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, pinned_version = line.split("==", 1)
        result[name.casefold()] = pinned_version
    return result


def test_runtime_manifest_matches_release_environment_and_constraints() -> None:
    manifest = build_runtime_manifest()

    assert manifest["schema_version"] == "mineguard.runtime.v1"
    assert manifest["application"] == {
        "name": "mineguard-platform",
        "version": __version__,
    }
    assert manifest["python"] == {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
    }

    dependencies = manifest["dependencies"]
    assert isinstance(dependencies, dict)
    constraints = _constraints()
    for distribution in RUNTIME_DISTRIBUTIONS:
        installed = version(distribution)
        assert dependencies[distribution] == installed
        assert constraints[distribution.casefold()] == installed

    # The structure is safe to attach directly to canonical JSON evidence.
    json.dumps(manifest, sort_keys=True)
