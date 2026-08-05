from __future__ import annotations

import json
from pathlib import Path

from conftest import write_config

from enterprise_connector.cli import main
from enterprise_connector.config import load_config
from enterprise_connector.state import StateStore


def test_validate_exposes_required_ttl_and_disaster_seed_warning(
    tmp_path: Path, source_db: Path, capsys
) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "max_staleness_seconds = 3600",
            "max_staleness_seconds = 3600\nrevision_seed = 7",
            1,
        ),
        encoding="utf-8",
    )
    assert main(["validate", "--config", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["source_policies"] == [
        {
            "pipeline_id": "mine-one-five-quantity",
            "source_id": "ledger",
            "source_system": "mes-ledger",
            "required": True,
            "freshness_max_seconds": 3600,
            "revision_seed": 7,
        }
    ]
    assert result["warnings"] and "revision_seed" in result["warnings"][0]


def test_check_is_machine_readable_and_maintenance_refuses_live_lease(
    tmp_path: Path, source_db: Path, capsys
) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    config = load_config(path)
    assert main(["check", "--config", str(path)]) == 1
    status = json.loads(capsys.readouterr().out)
    assert status["overall_status"] == "unhealthy"

    store = StateStore(config.state_db)
    try:
        assert store.acquire_lease("running-daemon", 60)
        assert main(["retry-dead", "--config", str(path)]) == 2
        assert "先停止服务" in capsys.readouterr().err
    finally:
        store.release_lease("running-daemon")
        store.close()
