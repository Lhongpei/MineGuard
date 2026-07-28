from __future__ import annotations

import ast
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
FORBIDDEN_ROOTS = {"enterprise_agent", "agent", "contracts"}


def test_platform_has_no_enterprise_agent_runtime_imports() -> None:
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
