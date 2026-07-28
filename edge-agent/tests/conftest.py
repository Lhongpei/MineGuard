from __future__ import annotations

from pathlib import Path

import pytest

from mine_edge.settings import Settings, ThresholdSettings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        mine_id="mine-001",
        client_id="edge-001",
        database_path=tmp_path / "edge.sqlite3",
        host="127.0.0.1",
        port=8091,
        api_token=None,
        upstream_url=None,
        upstream_hmac_secret=None,
        local_timezone="+08:00",
        forward_batch_size=100,
        forward_base_delay_seconds=5,
        forward_max_delay_seconds=3600,
        request_timeout_seconds=2,
        body_limit_bytes=2 * 1024 * 1024,
        thresholds=ThresholdSettings(
            personnel_capacity={"underground": 100, "face-101": 40},
            airflow_minimum={"face-101": 20.0},
        ),
        thresholds_calibrated=False,
        rule_profile_id="qinyuan-safety-default",
        rule_profile_version=1,
        rule_profile_sha256="a" * 64,
    )


@pytest.fixture
def methane_raw() -> dict[str, object]:
    return {
        "event_id": "gas-001",
        "kind": "methane",
        "metric": "methane_concentration",
        "value": 0.82,
        "unit": "%",
        "location_code": "face-101",
        "observed_at": "2026-07-28T08:00:00+08:00",
    }
