from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import write_config

from enterprise_connector.adapters.sqlite_query import collect_sqlite_query
from enterprise_connector.config import load_config
from enterprise_connector.normalize import normalize_batches


def test_normalized_content_is_consumed_by_real_agent_v2_importer(
    tmp_path: Path, source_db: Path
) -> None:
    repository = Path(__file__).resolve().parents[2]
    agent_src = repository / "agent" / "src"
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    pipeline = config.pipelines[0]
    source = pipeline.sources[0]
    event = normalize_batches(pipeline, source, collect_sqlite_query(source))[0]
    script = r"""
import json, sys
from enterprise_agent.five_quantity_exchange import MineIdentity
from enterprise_agent.five_quantity_import import import_five_quantity_bytes
from enterprise_agent.five_quantity_runtime import validate_five_quantity_payload

identity = MineIdentity(
    mine_id="MINE-TEST-001", mine_name="测试煤矿",
    operator_id="operator-qy-001", operator_name="测试煤业",
    system_id="agent-mine-test-001", regulator_system_id="mineguard-qinyuan",
    regulator_party_id="regulator-qinyuan", key_id="enterprise-key",
    regulator_key_id="regulator-key",
    message_hmac_secret="message-secret-at-least-thirty-two-bytes",
    timezone="Asia/Shanghai",
)
content = sys.stdin.buffer.read()
imported = import_five_quantity_bytes(
    filename="connector-ledger-2026-07.json", content=content,
    acquisition_mode="direct_collection", identity=identity,
    captured_at="2026-08-01T00:00:00Z",
)
validate_five_quantity_payload(imported["payload"], identity=identity, confirmed=False)
day = next(item for item in imported["payload"]["days"] if item["date"] == "2026-07-29")
print(json.dumps({
    "month": imported["payload"]["reporting_month"],
    "days": len(imported["payload"]["days"]),
    "production": day["reported_quantity"]["daily_total"]["production_t"]["value"],
    "zero_production": (
        day["reported_quantity"]["shifts"]["zero_shift"]
        ["measurements"]["production_t"]["value"]
    ),
}))
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(agent_src)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        input=event.payload["source"]["content"].encode(),
        capture_output=True,
        env=environment,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode()
    result = json.loads(completed.stdout)
    assert result == {
        "month": "2026-07",
        "days": 31,
        "production": 350.0,
        "zero_production": 100.0,
    }
