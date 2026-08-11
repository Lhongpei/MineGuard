from __future__ import annotations

import json
from pathlib import Path

from conftest import write_config

from enterprise_connector.cli import main
from enterprise_connector.config import load_config
from enterprise_connector.quantity_catalog import (
    METRICS,
    OPTIONAL_SHIFT_METRICS,
    REQUIRED_SHIFT_METRICS,
)
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
    assert result["data_contract"] == "ten-quantity-submission-v3"
    assert result["mapping_coverage_version"] == 2
    assert result["mapping_coverage_compatibility"] == {
        "mapped_metrics": "daily_total.mapped_metrics",
        "unmapped_metrics": "daily_total.unmapped_metrics",
    }
    assert result["atomic_metrics"] == [
        "ventilation_m3_min",
        "electricity_kwh",
        "detonators_count",
        "explosives_kg",
        "mine_entry_persons",
        "production_t",
        "extraction_t",
        "sales_t",
        "transport_t",
        "wash_feed_t",
        "invoiced_quantity_t",
    ]
    coverage = result["mapping_coverage"][0]
    assert coverage["pipeline_id"] == "mine-one-five-quantity"
    assert coverage["mapped_metrics"] == result["atomic_metrics"]
    assert coverage["unmapped_metrics"] == []
    assert coverage["daily_total"] == {
        "required_metrics": result["atomic_metrics"],
        "mapped_metrics": result["atomic_metrics"],
        "unmapped_metrics": [],
    }
    for shift in coverage["shifts"].values():
        assert shift["mapped_required_metrics"] == [
            metric for metric in METRICS if metric in REQUIRED_SHIFT_METRICS
        ]
        assert shift["unmapped_required_metrics"] == []
        assert shift["mapped_optional_metrics"] == [
            metric for metric in METRICS if metric in OPTIONAL_SHIFT_METRICS
        ]
        assert shift["unmapped_optional_metrics"] == []
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


def test_validate_warns_when_legacy_mapping_leaves_new_v3_atoms_missing(
    tmp_path: Path, source_db: Path, capsys
) -> None:
    path = write_config(tmp_path / "legacy-six.toml", source_db)
    text = path.read_text(encoding="utf-8")
    for metric in (
        "extraction_t",
        "sales_t",
        "transport_t",
        "wash_feed_t",
        "invoiced_quantity_t",
    ):
        text = "\n".join(
            line for line in text.splitlines() if not line.startswith(f"{metric} =")
        )
    path.write_text(f"{text}\n", encoding="utf-8")
    assert main(["validate", "--config", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["mapping_coverage"][0]["unmapped_metrics"] == [
        "extraction_t",
        "sales_t",
        "transport_t",
        "wash_feed_t",
        "invoiced_quantity_t",
    ]
    assert any("null + missing" in warning for warning in result["warnings"])


def test_validate_does_not_count_explicit_zero_shift_mapping_as_daily_coverage(
    tmp_path: Path, source_db: Path, capsys
) -> None:
    path = write_config(tmp_path / "zero-shift-only.toml", source_db)
    metric_names = set(METRICS)
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        target = line.split("=", 1)[0].strip()
        if target in metric_names:
            line = line.replace(target, f'"zero_shift.{target}"', 1)
        lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["validate", "--config", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    coverage = result["mapping_coverage"][0]
    assert coverage["mapped_metrics"] == []
    assert coverage["unmapped_metrics"] == list(METRICS)
    assert coverage["daily_total"]["mapped_metrics"] == []
    assert coverage["shifts"]["zero_shift"]["unmapped_required_metrics"] == []
    assert coverage["shifts"]["zero_shift"]["unmapped_optional_metrics"] == []
    for scope in ("eight_shift", "four_shift"):
        assert coverage["shifts"][scope]["mapped_required_metrics"] == []
        assert coverage["shifts"][scope]["mapped_optional_metrics"] == []


def test_validate_unscoped_mapping_follows_declared_dynamic_scopes(
    tmp_path: Path, source_db: Path, capsys
) -> None:
    path = write_config(tmp_path / "daily-dynamic.toml", source_db)
    text = path.read_text(encoding="utf-8")
    for identity_mapping in (
        'zero_shift = "zero_shift"\n',
        'eight_shift = "eight_shift"\n',
        'four_shift = "four_shift"\n',
    ):
        text = text.replace(identity_mapping, "")
    path.write_text(text, encoding="utf-8")

    assert main(["validate", "--config", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    coverage = result["mapping_coverage"][0]
    assert coverage["daily_total"]["unmapped_metrics"] == []
    for shift in coverage["shifts"].values():
        assert shift["mapped_required_metrics"] == []
        assert shift["mapped_optional_metrics"] == []


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
