from __future__ import annotations

from pathlib import Path

import pytest
from conftest import write_config

from enterprise_connector.config import load_config, require_secret
from enterprise_connector.errors import ConfigurationError


def test_loads_strict_config(
    tmp_path: Path, source_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    assert config.client_id == "test-connector"
    assert config.pipelines[0].required_sources == ("ledger",)
    assert len(config.pipelines[0].mappings) == 6
    monkeypatch.setenv("TEST_CONNECTOR_SECRET", "x" * 32)
    assert require_secret(config) == b"x" * 32


def test_boolean_string_cannot_open_private_network(tmp_path: Path, source_db: Path) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    text = path.read_text(encoding="utf-8").replace(
        "agent_allow_private_network = true",
        'agent_allow_private_network = "false"',
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="必须是 true 或 false"):
        load_config(path)


def test_plaintext_remote_http_requires_explicit_risk_switch(
    tmp_path: Path, source_db: Path
) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    text = (
        path.read_text(encoding="utf-8")
        .replace("http://127.0.0.1:18091", "http://agent.internal:18091")
        .replace('["127.0.0.1"]', '["agent.internal"]')
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="明文传输"):
        load_config(path)


def test_unknown_metric_mapping_is_rejected(tmp_path: Path, source_db: Path) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    text = path.read_text(encoding="utf-8").replace("production_t =", "made_up_metric =", 1)
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="六个五量原子字段"):
        load_config(path)


@pytest.mark.parametrize(
    ("anchor", "replacement", "unknown_key"),
    [
        (
            "lease_seconds = 5",
            "lease_seconds = 5\nlease_second = 5",
            "lease_second",
        ),
        (
            'workflow_name = "daily_coal_health"',
            'workflow_name = "daily_coal_health"\nreporting_lag_day = 1',
            "reporting_lag_day",
        ),
        (
            "timeout_seconds = 1",
            "timeout_seconds = 1\nmax_record = 10",
            "max_record",
        ),
    ],
)
def test_unknown_service_pipeline_and_source_keys_are_rejected(
    tmp_path: Path,
    source_db: Path,
    anchor: str,
    replacement: str,
    unknown_key: str,
) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    path.write_text(
        path.read_text(encoding="utf-8").replace(anchor, replacement, 1),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match=rf"未知配置项.*{unknown_key}"):
        load_config(path)


def test_unknown_mapping_option_is_rejected(tmp_path: Path, source_db: Path) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            '{ source = "production", type = "number" }',
            '{ source = "production", type = "number", reduct = "latest" }',
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match=r"未知配置项.*reduct"):
        load_config(path)


def test_secret_never_allowed_short(
    tmp_path: Path, source_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = load_config(write_config(tmp_path / "connector.toml", source_db))
    monkeypatch.setenv("TEST_CONNECTOR_SECRET", "short")
    with pytest.raises(ConfigurationError, match="至少需要 32"):
        require_secret(config)


def test_agent_private_ca_bundle_is_resolved(tmp_path: Path, source_db: Path) -> None:
    bundle = tmp_path / "ca.pem"
    bundle.write_text("test-ca", encoding="utf-8")
    path = write_config(tmp_path / "connector.toml", source_db)
    text = path.read_text(encoding="utf-8").replace(
        'secret_env = "TEST_CONNECTOR_SECRET"',
        'secret_env = "TEST_CONNECTOR_SECRET"\nagent_ca_bundle = "./ca.pem"',
    )
    path.write_text(text, encoding="utf-8")
    assert load_config(path).agent_ca_bundle == bundle


def test_source_level_schema_overrides_are_parsed(tmp_path: Path, source_db: Path) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            """
timestamp_field = "business_time"
period_type = "daily"
scope_field = "bucket_code"

[pipelines.sources.scope_values]
D = "daily_total"

[pipelines.sources.mapping]
production_t = { source = "net_tons", type = "number", reduce = "latest" }
"""
        )
    source = load_config(path).pipelines[0].sources[0]
    assert source.timestamp_field == "business_time"
    assert source.scope_values == {"D": "daily_total"}
    assert source.mappings is not None and source.mappings[0].source == "net_tons"
    assert source.max_staleness_seconds == 3600


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('report_type = "five-quantity"', 'report_type = "other"', "five-quantity"),
        (
            'workflow_name = "daily_coal_health"',
            'workflow_name = "other_workflow"',
            "daily_coal_health",
        ),
    ],
)
def test_wire_contract_names_cannot_drift(
    tmp_path: Path, source_db: Path, old: str, new: str, message: str
) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    path.write_text(path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")
    with pytest.raises(ConfigurationError, match=message):
        load_config(path)


def test_v1_rejects_multiple_pipelines_for_one_mine_policy_scope(
    tmp_path: Path, source_db: Path
) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            f"""

[[pipelines]]
id = "second"
enterprise_id = "operator-qy-002"
report_type = "five-quantity"
period_type = "daily"
timezone = "Asia/Shanghai"
timestamp_field = "observed_at"
scope_field = "scope"
required_sources = ["other"]
workflow_name = "daily_coal_health"

[pipelines.mapping]
production_t = {{ source = "production", type = "number" }}

[[pipelines.sources]]
id = "other"
adapter = "sqlite-query"
source_name = "other-ledger"
source_system = "other-mes"
truth_statement = "read only"
database = "{source_db.as_posix()}"
query = "SELECT * FROM five_quantity"
"""
        )
    with pytest.raises(ConfigurationError, match="只允许一个"):
        load_config(path)


@pytest.mark.parametrize("value", [299, 3600.5])
def test_source_freshness_ttl_is_agent_compatible_integer(
    tmp_path: Path, source_db: Path, value: object
) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    text = path.read_text(encoding="utf-8").replace(
        "max_staleness_seconds = 3600",
        f"max_staleness_seconds = {value}",
        1,
    )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigurationError, match="max_staleness_seconds"):
        load_config(path)


def test_source_freshness_ttl_minimum_is_accepted(tmp_path: Path, source_db: Path) -> None:
    path = write_config(tmp_path / "connector.toml", source_db)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "max_staleness_seconds = 3600",
            "max_staleness_seconds = 300",
            1,
        ),
        encoding="utf-8",
    )
    assert load_config(path).pipelines[0].sources[0].max_staleness_seconds == 300
