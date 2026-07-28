from __future__ import annotations

import base64
import json

import pytest

from mine_edge.errors import ConfigurationError
from mine_edge.settings import Settings, ThresholdSettings


@pytest.mark.parametrize(
    "mapping",
    [
        {
            "methane_percent": {
                "blue": 1.0,
                "yellow": 0.8,
                "orange": 1.2,
                "red": 1.5,
            }
        },
        {
            "airflow_ratio": {
                "blue": 0.7,
                "yellow": 0.9,
                "orange": 0.8,
                "red": 0.6,
            }
        },
        {"airflow_minimum": {"face-1": -2}},
    ],
)
def test_unsafe_threshold_order_is_rejected(mapping) -> None:
    with pytest.raises(ConfigurationError):
        ThresholdSettings.from_mapping(mapping)


def test_base64_transport_secret_is_decoded(monkeypatch, tmp_path) -> None:
    secret = b"edge-shared-secret-with-at-least-32-bytes"
    monkeypatch.setenv(
        "MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64",
        base64.b64encode(secret).decode(),
    )
    monkeypatch.setenv("MINE_EDGE_UPSTREAM_URL", "https://platform.example")
    monkeypatch.setenv("MINE_EDGE_DB", str(tmp_path / "edge.db"))
    settings = Settings.from_env()
    assert settings.upstream_hmac_secret == secret


def test_short_transport_secret_is_rejected(monkeypatch) -> None:
    monkeypatch.setenv(
        "MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64",
        base64.b64encode(b"short").decode(),
    )
    with pytest.raises(ConfigurationError, match="至少需要 32"):
        Settings.from_env()


@pytest.mark.parametrize(
    "url",
    [
        "http://regulator.example",
        "https://user:pass@regulator.example",
        "https://regulator.example/base",
        "https://regulator.example?tenant=mine-1",
        "https://regulator.example#fragment",
        " https://regulator.example",
    ],
)
def test_unsafe_upstream_url_is_rejected(monkeypatch, url) -> None:
    monkeypatch.setenv("MINE_EDGE_UPSTREAM_URL", url)
    with pytest.raises(ConfigurationError):
        Settings.from_env()


@pytest.mark.parametrize(
    ("url", "normalized"),
    [
        ("https://regulator.example", "https://regulator.example"),
        ("https://regulator.example:8443/", "https://regulator.example:8443"),
        ("http://localhost:8080", "http://localhost:8080"),
        ("http://127.0.0.2:8080/", "http://127.0.0.2:8080"),
        ("http://[::1]:8080", "http://[::1]:8080"),
    ],
)
def test_secure_upstream_origin_is_normalized(monkeypatch, url, normalized) -> None:
    monkeypatch.setenv("MINE_EDGE_UPSTREAM_URL", url)
    settings = Settings.from_env()
    assert settings.upstream_url == normalized


def test_client_id_length_preserves_batch_identifier_limit(monkeypatch) -> None:
    monkeypatch.setenv("MINE_EDGE_CLIENT_ID", "x" * 89)
    with pytest.raises(ConfigurationError, match="最长 88"):
        Settings.from_env()


def test_multiple_source_configuration_is_parsed_and_secrets_are_not_exposed(
    monkeypatch,
) -> None:
    monkeypatch.setenv("MINE_SOURCE_TOKEN", "do-not-return-this-secret")
    monkeypatch.setenv(
        "MINE_EDGE_SOURCES_JSON",
        json.dumps(
            [
                {
                    "source_id": "gas:file",
                    "adapter": "jsonl",
                    "path": "/data/gas.jsonl",
                    "interval_seconds": 10,
                    "jitter_seconds": 2,
                    "timeout_seconds": 3,
                    "missing_after_seconds": 60,
                },
                {
                    "source_id": "safety-api",
                    "adapter": "http-poll",
                    "url": "https://source.example/readings?access_token=hidden",
                    "interval_seconds": 15,
                    "timeout_seconds": 5,
                    "missing_after_seconds": 90,
                    "token_env": "MINE_SOURCE_TOKEN",
                },
            ]
        ),
    )
    settings = Settings.from_env()
    assert [source.source_id for source in settings.sources] == [
        "gas:file",
        "safety-api",
    ]
    public = settings.public_dict()["sources"][1]
    assert public["location"] == "https://source.example/readings"
    assert public["query_configured"] is True
    assert public["token_env"] == "MINE_SOURCE_TOKEN"
    assert "do-not-return-this-secret" not in json.dumps(
        settings.public_dict(), ensure_ascii=False
    )


def test_methane_adaptive_sampling_defaults_and_overrides_are_public(
    monkeypatch,
) -> None:
    monkeypatch.setenv(
        "MINE_EDGE_SOURCES_JSON",
        json.dumps(
            [
                {
                    "source_id": "gas-default",
                    "adapter": "jsonl",
                    "path": "/data/gas-default.jsonl",
                    "interval_seconds": 12,
                },
                {
                    "source_id": "gas-custom",
                    "adapter": "http-poll",
                    "url": "https://source.example/gas",
                    "interval_seconds": 15,
                    "methane_adaptive_sampling": {
                        "enabled": True,
                        "trigger_ratio": 0.7,
                        "accelerated_interval_seconds": 1.5,
                        "window_seconds": 180,
                    },
                },
            ]
        ),
    )
    settings = Settings.from_env()

    defaults = settings.sources[0].methane_adaptive_sampling
    assert defaults.enabled is True
    assert defaults.trigger_ratio == 0.8
    assert defaults.accelerated_interval_seconds == 2
    assert defaults.window_seconds == 300
    public = settings.public_dict()["sources"][1][
        "methane_adaptive_sampling"
    ]
    assert public == {
        "enabled": True,
        "trigger_ratio": 0.7,
        "accelerated_interval_seconds": 1.5,
        "window_seconds": 180.0,
        "effective": True,
        "restart_behavior": "restore_unexpired_bounded_window",
        "device_write_capability": False,
    }


def test_duplicate_source_ids_are_rejected(monkeypatch) -> None:
    source = {
        "source_id": "duplicate",
        "adapter": "jsonl",
        "path": "/data/readings.jsonl",
    }
    monkeypatch.setenv("MINE_EDGE_SOURCES_JSON", json.dumps([source, source]))
    with pytest.raises(ConfigurationError, match="不得重复"):
        Settings.from_env()


@pytest.mark.parametrize(
    "source",
    [
        {
            "source_id": "bad-jitter",
            "adapter": "jsonl",
            "path": "/data/readings.jsonl",
            "interval_seconds": 2,
            "jitter_seconds": 3,
        },
        {
            "source_id": "bad-window",
            "adapter": "jsonl",
            "path": "/data/readings.jsonl",
            "interval_seconds": 10,
            "missing_after_seconds": 5,
        },
        {
            "source_id": "bad-token-env",
            "adapter": "http-poll",
            "url": "https://source.example/readings",
            "token_env": "lower-case-name",
        },
        {
            "source_id": "ambiguous-location",
            "adapter": "http-poll",
            "url": "https://source.example/readings",
            "path": "/data/readings.jsonl",
        },
        {
            "source_id": "bad-enabled",
            "adapter": "jsonl",
            "path": "/data/readings.jsonl",
            "enabled": "yes",
        },
        {
            "source_id": "bad-adaptive-ratio",
            "adapter": "jsonl",
            "path": "/data/readings.jsonl",
            "interval_seconds": 10,
            "methane_adaptive_sampling": {"trigger_ratio": 1.1},
        },
        {
            "source_id": "bad-adaptive-interval",
            "adapter": "jsonl",
            "path": "/data/readings.jsonl",
            "interval_seconds": 10,
            "methane_adaptive_sampling": {
                "accelerated_interval_seconds": 10
            },
        },
        {
            "source_id": "unbounded-adaptive-window",
            "adapter": "jsonl",
            "path": "/data/readings.jsonl",
            "interval_seconds": 10,
            "methane_adaptive_sampling": {"window_seconds": 3601},
        },
        {
            "source_id": "unknown-adaptive-key",
            "adapter": "jsonl",
            "path": "/data/readings.jsonl",
            "interval_seconds": 10,
            "methane_adaptive_sampling": {"write_device": True},
        },
    ],
)
def test_unsafe_source_configuration_is_rejected(monkeypatch, source) -> None:
    monkeypatch.setenv("MINE_EDGE_SOURCES_JSON", json.dumps([source]))
    with pytest.raises(ConfigurationError):
        Settings.from_env()
