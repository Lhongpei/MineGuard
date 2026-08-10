from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest


@pytest.fixture
def source_db(tmp_path: Path) -> Path:
    path = tmp_path / "source.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE five_quantity (
            observed_at TEXT NOT NULL,
            scope TEXT NOT NULL,
            production REAL,
            electricity REAL,
            ventilation REAL,
            detonators INTEGER,
            explosives REAL,
            persons INTEGER,
            extraction REAL,
            sales REAL,
            transport REAL,
            wash_feed REAL,
            invoiced_quantity REAL
        )
        """
    )
    rows = []
    for day in ("2026-07-29", "2026-07-30"):
        rows.extend(
            [
                (
                    f"{day}T00:00:00+08:00",
                    "zero_shift",
                    100.0,
                    30.0,
                    8000.0,
                    3,
                    1.5,
                    10,
                    102.0,
                    90.0,
                    88.0,
                    45.0,
                    85.0,
                ),
                (
                    f"{day}T08:00:00+08:00",
                    "eight_shift",
                    120.0,
                    35.0,
                    8100.0,
                    4,
                    2.0,
                    12,
                    121.0,
                    100.0,
                    98.0,
                    50.0,
                    95.0,
                ),
                (
                    f"{day}T16:00:00+08:00",
                    "four_shift",
                    130.0,
                    40.0,
                    8200.0,
                    5,
                    2.5,
                    13,
                    132.0,
                    110.0,
                    109.0,
                    55.0,
                    105.0,
                ),
                (
                    f"{day}T23:59:00+08:00",
                    "daily_total",
                    350.0,
                    105.0,
                    8100.0,
                    12,
                    6.0,
                    35,
                    355.0,
                    300.0,
                    295.0,
                    150.0,
                    285.0,
                ),
            ]
        )
    connection.executemany(
        "INSERT INTO five_quantity VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
    )
    connection.commit()
    connection.close()
    return path


def write_config(
    path: Path,
    source_db: Path,
    *,
    agent_port: int = 18091,
    second_source_db: Path | None = None,
) -> Path:
    sources = f'''\n[[pipelines.sources]]
id = "ledger"
adapter = "sqlite-query"
source_name = "production-ledger"
source_system = "mes-ledger"
truth_statement = "只读来源数据，仍须经办人核对"
max_staleness_seconds = 3600
database = "{source_db.as_posix()}"
query = "SELECT * FROM five_quantity"
timeout_seconds = 1
'''
    required = '["ledger"]'
    if second_source_db is not None:
        required = '["ledger", "scale"]'
        sources += f'''\n[[pipelines.sources]]
id = "scale"
adapter = "sqlite-query"
source_name = "scale-ledger"
source_system = "scale-system"
truth_statement = "地磅读取数据，仍须经办人核对"
max_staleness_seconds = 3600
database = "{second_source_db.as_posix()}"
query = "SELECT * FROM five_quantity"
timeout_seconds = 1
'''
    path.write_text(
        f"""[service]
state_db = "./state.sqlite3"
poll_interval_seconds = 1
agent_url = "http://127.0.0.1:{agent_port}"
client_id = "test-connector"
secret_env = "TEST_CONNECTOR_SECRET"
agent_timeout_seconds = 1
agent_max_response_bytes = 100000
agent_allowed_hosts = ["127.0.0.1"]
agent_allowed_ports = [{agent_port}]
agent_allow_private_network = true
retry_base_seconds = 0.01
retry_max_seconds = 1
lease_seconds = 5

[[pipelines]]
id = "mine-one-five-quantity"
enterprise_id = "operator-qy-001"
report_type = "five-quantity"
period_type = "daily"
timezone = "Asia/Shanghai"
timestamp_field = "observed_at"
scope_field = "scope"
required_sources = {required}
workflow_name = "daily_coal_health"

[pipelines.scope_values]
daily = "daily_total"

[pipelines.mapping]
production_t = {{ source = "production", type = "number" }}
extraction_t = {{ source = "extraction", type = "number" }}
sales_t = {{ source = "sales", type = "number" }}
transport_t = {{ source = "transport", type = "number" }}
wash_feed_t = {{ source = "wash_feed", type = "number" }}
invoiced_quantity_t = {{ source = "invoiced_quantity", type = "number" }}
electricity_kwh = {{ source = "electricity", type = "number" }}
ventilation_m3_min = {{ source = "ventilation", type = "number" }}
detonators_count = {{ source = "detonators", type = "integer" }}
explosives_kg = {{ source = "explosives", type = "number" }}
mine_entry_persons = {{ source = "persons", type = "integer" }}
{sources}
""",
        encoding="utf-8",
    )
    return path
