from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_edge_pipeline_black_box() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_edge_pipeline.py"),
            "--timeout",
            "30",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["status"] == "passed"
    assert result["edge"]["local_personnel_level"] == "red"
    assert result["platform"]["personnel_level"] == "orange"
    assert result["platform"]["alert_source"] == "platform_recalculation"
    assert result["platform"]["accepted_observations"] == 3
