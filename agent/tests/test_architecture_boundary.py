from __future__ import annotations

import ast
from pathlib import Path

import enterprise_agent.security as security

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
FORBIDDEN_ROOTS = {"mineguard", "platform", "contracts"}


def test_agent_has_no_regulatory_platform_runtime_imports() -> None:
    violations: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".", 1)[0] in FORBIDDEN_ROOTS:
                    violations.append(f"{path.relative_to(SOURCE_ROOT)}: {name}")
    assert violations == []


def test_production_agent_has_no_source_observation_signer() -> None:
    assert not hasattr(security, "sign_observation")
    assert not hasattr(security, "verify_observation")
    service_source = (
        SOURCE_ROOT / "enterprise_agent" / "service.py"
    ).read_text(encoding="utf-8")
    assert "sign_observation" not in service_source
    assert "OBSERVATION_SIGNING_CONTEXT" not in service_source
