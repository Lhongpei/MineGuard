from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from enterprise_agent import settings as settings_module
from enterprise_agent.auth import hash_password
from enterprise_agent.cli import main
from enterprise_agent.settings import Settings

_PLATFORM_ENV = (
    "PLATFORM_BASE_URL",
    "PLATFORM_CLIENT_ID",
    "PLATFORM_TRANSPORT_HMAC_SECRET",
    "PLATFORM_BEARER_TOKEN",
    "PLATFORM_SUBMISSION_PATH",
    "PLATFORM_CAPABILITIES_PATH",
)
_MODEL_ENV = (
    "MINEGUARD_AGENT_API_KEY",
    "MINEGUARD_AGENT_BASE_URL",
    "MINEGUARD_AGENT_MODEL",
    "MINEGUARD_AGENT_TIMEOUT_SECONDS",
    "MINEGUARD_AGENT_MAX_RETRIES",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "DEEPSEEK_MODEL",
    "DEEPSEEK_TIMEOUT_SECONDS",
    "DEEPSEEK_MAX_RETRIES",
)


def _clear_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PLATFORM_ENV:
        monkeypatch.delenv(name, raising=False)


def _clear_model(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _MODEL_ENV:
        monkeypatch.delenv(name, raising=False)


def test_provider_neutral_model_configuration_is_canonical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_model(monkeypatch)
    monkeypatch.setenv("MINEGUARD_AGENT_API_KEY", "gateway-enterprise-key")
    monkeypatch.setenv("MINEGUARD_AGENT_BASE_URL", "https://llm.internal.example")
    monkeypatch.setenv("MINEGUARD_AGENT_MODEL", "approved-coal-model")
    monkeypatch.setenv("MINEGUARD_AGENT_TIMEOUT_SECONDS", "17.5")
    monkeypatch.setenv("MINEGUARD_AGENT_MAX_RETRIES", "4")

    llm = Settings.from_environment().llm

    assert llm is not None
    assert llm.api_key == "gateway-enterprise-key"
    assert llm.base_url == "https://llm.internal.example"
    assert llm.model == "approved-coal-model"
    assert llm.timeout_seconds == 17.5
    assert llm.max_retries == 4


def test_legacy_deepseek_model_configuration_remains_a_migration_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_model(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "legacy-enterprise-key")

    llm = Settings.from_environment().llm

    assert llm is not None
    assert llm.api_key == "legacy-enterprise-key"
    assert llm.base_url == "https://api.deepseek.com"
    assert llm.model == "deepseek-v4-flash"


def test_model_configuration_rejects_mixed_new_and_legacy_namespaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_model(monkeypatch)
    monkeypatch.setenv("MINEGUARD_AGENT_API_KEY", "new-key")
    monkeypatch.setenv("MINEGUARD_AGENT_BASE_URL", "https://llm.internal.example")
    monkeypatch.setenv("MINEGUARD_AGENT_MODEL", "approved-model")
    monkeypatch.setenv("DEEPSEEK_MODEL", "legacy-model")

    with pytest.raises(ValueError, match="不能与已弃用的 DEEPSEEK"):
        Settings.from_environment()


def test_model_configuration_conflict_does_not_disclose_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_model(monkeypatch)
    current_secret = "current-model-secret-must-not-leak"
    legacy_secret = "legacy-model-secret-must-not-leak"
    monkeypatch.setenv("MINEGUARD_AGENT_API_KEY", current_secret)
    monkeypatch.setenv("MINEGUARD_AGENT_BASE_URL", "https://llm.internal.example")
    monkeypatch.setenv("MINEGUARD_AGENT_MODEL", "approved-model")
    monkeypatch.setenv("DEEPSEEK_API_KEY", legacy_secret)

    with pytest.raises(ValueError) as captured:
        Settings.from_environment()

    message = str(captured.value)
    assert current_secret not in message
    assert legacy_secret not in message
    assert "MINEGUARD_AGENT" in message
    assert "DEEPSEEK" in message


def test_unavailable_managed_model_disables_egress_without_blocking_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_model(monkeypatch)
    monkeypatch.setenv(
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE",
        "/var/lib/enterprise-agent/model.lock.json",
    )
    monkeypatch.setenv(
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE",
        "/var/lib/enterprise-agent/model.secret.json",
    )

    def fail_closed(**_kwargs):
        raise settings_module.ModelCredentialError("expired secret must not leak")

    monkeypatch.setattr(
        settings_module,
        "load_model_credential_from_environment",
        fail_closed,
    )
    llm, status = settings_module._managed_model_config(
        provisioning_status=SimpleNamespace(
            managed=True,
            pair_id="11111111-1111-4111-8111-111111111111",
        ),
        identity=SimpleNamespace(
            mine_id="MINE-QY-001",
            system_id="agent-mine-qy-001",
            operator_id="operator-qy-001",
        ),
    )

    assert llm is None
    assert status.managed is True
    assert status.state == "unavailable"
    assert status.failure_code == "credential_invalid_or_unavailable"
    assert status.source == "managed-model-credential-unavailable"
    assert "expired secret" not in str(status.as_dict())


@pytest.mark.parametrize(
    "missing_name",
    ["MINEGUARD_AGENT_BASE_URL", "MINEGUARD_AGENT_MODEL"],
)
def test_provider_neutral_key_requires_explicit_destination_and_model(
    monkeypatch: pytest.MonkeyPatch,
    missing_name: str,
) -> None:
    _clear_model(monkeypatch)
    monkeypatch.setenv("MINEGUARD_AGENT_API_KEY", "new-key")
    monkeypatch.setenv("MINEGUARD_AGENT_BASE_URL", "https://llm.internal.example")
    monkeypatch.setenv("MINEGUARD_AGENT_MODEL", "approved-model")
    monkeypatch.delenv(missing_name)

    with pytest.raises(ValueError, match=missing_name):
        Settings.from_environment()


def test_no_platform_configuration_keeps_offline_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_platform(monkeypatch)
    settings = Settings.from_environment()
    assert settings.platform is None


@pytest.mark.parametrize(
    "partial",
    [
        {"PLATFORM_BASE_URL": "https://regulator.example"},
        {
            "PLATFORM_BASE_URL": "https://regulator.example",
            "PLATFORM_BEARER_TOKEN": "legacy-bearer-only",
        },
        {
            "PLATFORM_BASE_URL": "https://regulator.example",
            "PLATFORM_CLIENT_ID": "enterprise-001",
        },
    ],
)
def test_partial_platform_identity_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
    partial: dict[str, str],
) -> None:
    _clear_platform(monkeypatch)
    for name, value in partial.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="must be configured together"):
        Settings.from_environment()


def test_contract_hmac_identity_may_include_optional_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_platform(monkeypatch)
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://regulator.example")
    monkeypatch.setenv("PLATFORM_CLIENT_ID", "enterprise-001")
    monkeypatch.setenv(
        "PLATFORM_TRANSPORT_HMAC_SECRET",
        "transport-hmac-secret-at-least-32-bytes",
    )
    monkeypatch.setenv("PLATFORM_BEARER_TOKEN", "legacy-bearer")
    settings = Settings.from_environment()
    assert settings.platform is not None
    assert settings.platform.client_id == "enterprise-001"
    assert settings.platform.transport_hmac_secret == (
        "transport-hmac-secret-at-least-32-bytes"
    )
    assert settings.platform.bearer_token == "legacy-bearer"


def test_enterprise_users_and_session_security_are_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded = hash_password(
        "operator-password",
        iterations=100_000,
        salt=b"0123456789abcdef",
    )
    monkeypatch.setenv(
        "ENTERPRISE_AGENT_USERS_JSON",
        (
            '[{"actor_id":"operator-1","name":"张三","role":"经办人",'
            f'"password_hash":"{encoded}",'
            '"permissions":["read","write"]}]'
        ),
    )
    monkeypatch.setenv("ENTERPRISE_AGENT_SESSION_TTL_SECONDS", "900")
    monkeypatch.setenv("ENTERPRISE_AGENT_SECURE_COOKIE", "true")
    settings = Settings.from_environment()
    assert settings.users[0].actor_id == "operator-1"
    assert settings.users[0].permissions == frozenset({"read", "write"})
    assert settings.session_ttl_seconds == 900
    assert settings.secure_cookie is True


def test_short_platform_transport_secret_fails_during_settings_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_platform(monkeypatch)
    monkeypatch.setenv("PLATFORM_BASE_URL", "https://regulator.example")
    monkeypatch.setenv("PLATFORM_CLIENT_ID", "enterprise-001")
    monkeypatch.setenv("PLATFORM_TRANSPORT_HMAC_SECRET", "too-short")
    with pytest.raises(ValueError, match="at least 32 bytes"):
        Settings.from_environment()


def test_v2_requires_explicit_distinct_application_and_transport_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PLATFORM_V2_BASE_URL", "https://regulator.example")
    monkeypatch.setenv("PLATFORM_V2_SENDER_ID", "agent-demo-mine-001")
    monkeypatch.setenv(
        "PLATFORM_V2_TRANSPORT_HMAC_SECRET",
        "transport-secret-at-least-thirty-two-bytes",
    )
    monkeypatch.delenv("ENTERPRISE_EXCHANGE_HMAC_SECRET", raising=False)
    with pytest.raises(ValueError, match="显式配置"):
        Settings.from_environment()

    shared = "shared-secret-is-long-enough-but-forbidden"
    monkeypatch.setenv("ENTERPRISE_EXCHANGE_HMAC_SECRET", shared)
    monkeypatch.setenv("PLATFORM_V2_TRANSPORT_HMAC_SECRET", shared)
    with pytest.raises(ValueError, match="不得相同"):
        Settings.from_environment()

    monkeypatch.setenv(
        "ENTERPRISE_EXCHANGE_HMAC_SECRET",
        "application-secret-at-least-thirty-two-bytes",
    )
    monkeypatch.setenv(
        "PLATFORM_V2_TRANSPORT_HMAC_SECRET",
        "different-transport-secret-at-least-32-bytes",
    )
    settings = Settings.from_environment()
    assert settings.five_quantity_platform is not None
    assert settings.five_quantity_demo_secret is False


def test_v3_platform_environment_selects_ten_quantity_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENTERPRISE_SYSTEM_ID", "agent-ten-001")
    monkeypatch.setenv("PLATFORM_V3_BASE_URL", "https://regulator.example")
    monkeypatch.setenv("PLATFORM_V3_SENDER_ID", "agent-ten-001")
    monkeypatch.setenv(
        "ENTERPRISE_EXCHANGE_HMAC_SECRET",
        "application-secret-at-least-thirty-two-bytes",
    )
    monkeypatch.setenv(
        "PLATFORM_V3_TRANSPORT_HMAC_SECRET",
        "different-transport-secret-at-least-32-bytes",
    )

    settings = Settings.from_environment()

    assert settings.five_quantity_platform is not None
    assert settings.five_quantity_platform.submission_path == (
        "/v3/ten-quantity-submissions"
    )
    assert settings.five_quantity_platform.next_report_path == (
        "/v3/analysis-reports/next"
    )


def test_historical_enterprise_signing_keyring_is_strictly_loaded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
        json.dumps(
            [
                {
                    "key_id": "enterprise-key-2026-06",
                    "secret": (
                        "enterprise-retired-secret-2026-06-abcdefghijklmnopqrstuvwxyz"
                    ),
                },
                {
                    "key_id": "enterprise-key-2026-07",
                    "secret": (
                        "enterprise-retired-secret-2026-07-abcdefghijklmnopqrstuvwxyz"
                    ),
                },
            ]
        ),
    )

    identity = Settings.from_environment().five_quantity_identity

    assert [item.key_id for item in identity.historical_enterprise_signing_keys] == [
        "enterprise-key-2026-06",
        "enterprise-key-2026-07",
    ]
    assert identity.key_id not in {
        item.key_id for item in identity.historical_enterprise_signing_keys
    }


@pytest.mark.parametrize(
    "value",
    [
        "{}",
        '[{"key_id":"enterprise-key-old","secret":"too-short"}]',
        (
            '[{"key_id":"enterprise-key-old",'
            '"secret":"retired-enterprise-secret-abcdefghijklmnopqrstuvwxyz",'
            '"enabled":true}]'
        ),
        (
            '[{"key_id":"enterprise-key-old",'
            '"secret":"retired-enterprise-secret-one-abcdefghijklmnopqrstuvwxyz"},'
            '{"key_id":"enterprise-key-old",'
            '"secret":"retired-enterprise-secret-two-abcdefghijklmnopqrstuvwxyz"}]'
        ),
    ],
    ids=("not-array", "short-secret", "extra-field", "duplicate-key-id"),
)
def test_invalid_historical_enterprise_signing_keyring_fails_at_startup(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON", value)

    with pytest.raises(ValueError, match="历史|HISTORICAL"):
        Settings.from_environment()


def test_historical_enterprise_keyring_rejects_current_key_or_secret_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_key_id = "enterprise-key-current-2026-08"
    current_secret = "enterprise-current-secret-2026-08-abcdefghijklmnopqrstuvwxyz"
    monkeypatch.setenv("ENTERPRISE_EXCHANGE_KEY_ID", current_key_id)
    monkeypatch.setenv("ENTERPRISE_EXCHANGE_HMAC_SECRET", current_secret)
    monkeypatch.setenv(
        "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
        json.dumps([{"key_id": current_key_id, "secret": current_secret}]),
    )

    with pytest.raises(ValueError, match="历史.*不得"):
        Settings.from_environment()


def test_config_check_lists_enterprise_key_ids_without_exposing_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    historical_secret = (
        "enterprise-retired-secret-for-config-check-abcdefghijklmnopqrstuvwxyz"
    )
    monkeypatch.setenv(
        "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
        json.dumps(
            [
                {
                    "key_id": "enterprise-key-retired-config-check",
                    "secret": historical_secret,
                }
            ]
        ),
    )

    assert main(["config-check"]) == 0
    output = capsys.readouterr().out
    document = json.loads(output)
    assert document["enterprise_signing_key_id"] == "demo-exchange-key"
    assert document["historical_enterprise_verification_key_ids"] == [
        "enterprise-key-retired-config-check"
    ]
    assert historical_secret not in output


def test_config_check_warns_about_legacy_model_names_without_exposing_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _clear_model(monkeypatch)
    legacy_secret = "legacy-model-key-must-not-leak"
    monkeypatch.setenv("DEEPSEEK_API_KEY", legacy_secret)

    assert main(["config-check"]) == 0

    output = capsys.readouterr().out
    document = json.loads(output)
    assert any("DEEPSEEK_*" in warning for warning in document["warnings"])
    assert legacy_secret not in output


def test_public_origin_is_strictly_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ENTERPRISE_AGENT_PUBLIC_ORIGIN",
        "https://REPORT.Example.com:8443/",
    )
    assert Settings.from_environment().public_origin == (
        "https://report.example.com:8443"
    )

    for invalid in (
        "report.example.com",
        "ftp://report.example.com",
        "https://user:password@report.example.com",
        "https://report.example.com/app",
        "https://report.example.com?secret=value",
        "https://report.example.com:bad",
        " https://report.example.com",
        "https://report%2eexample.com",
    ):
        monkeypatch.setenv("ENTERPRISE_AGENT_PUBLIC_ORIGIN", invalid)
        with pytest.raises(ValueError, match="PUBLIC_ORIGIN"):
            Settings.from_environment()
    monkeypatch.setenv(
        "ENTERPRISE_AGENT_PUBLIC_ORIGIN",
        "https://REPORT.Example.com:443",
    )
    assert Settings.from_environment().public_origin == ("https://report.example.com")


def test_empty_database_and_host_configuration_fail_early(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", " ")
    with pytest.raises(ValueError, match="DB"):
        Settings.from_environment()
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", "./test.db")
    monkeypatch.setenv("ENTERPRISE_AGENT_HOST", " ")
    with pytest.raises(ValueError, match="HOST"):
        Settings.from_environment()


def test_coal_news_search_defaults_and_bounded_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "COAL_NEWS_SEARCH_ENABLED",
        "COAL_NEWS_SEARCH_TIMEOUT_SECONDS",
        "COAL_NEWS_BAIDU_TIMEOUT_SECONDS",
        "COAL_NEWS_DEEPSEEK_TIMEOUT_SECONDS",
        "COAL_NEWS_SEARCH_CACHE_TTL_SECONDS",
        "COAL_NEWS_SEARCH_MAX_RESULTS",
        "COAL_NEWS_SEARCH_MAX_RESPONSE_BYTES",
        "COAL_NEWS_SEARCH_MAX_CONCURRENCY",
        "COAL_NEWS_BAIDU_ENABLED",
        "COAL_NEWS_DEEPSEEK_WEB_SEARCH_ENABLED",
        "COAL_NEWS_BING_FALLBACK_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)
    defaults = Settings.from_environment().coal_news
    assert defaults.enabled is True
    assert defaults.timeout_seconds == 25.0
    assert defaults.baidu_timeout_seconds == 3.0
    assert defaults.deepseek_timeout_seconds == 24.0
    assert defaults.cache_ttl_seconds == 300
    assert defaults.max_results == 8
    assert defaults.baidu_enabled is True
    assert defaults.deepseek_web_search_enabled is True
    assert defaults.bing_fallback_enabled is False

    monkeypatch.setenv("COAL_NEWS_SEARCH_ENABLED", "false")
    monkeypatch.setenv("COAL_NEWS_SEARCH_TIMEOUT_SECONDS", "8")
    monkeypatch.setenv("COAL_NEWS_BAIDU_TIMEOUT_SECONDS", "2")
    monkeypatch.setenv("COAL_NEWS_DEEPSEEK_TIMEOUT_SECONDS", "7")
    monkeypatch.setenv("COAL_NEWS_SEARCH_CACHE_TTL_SECONDS", "600")
    monkeypatch.setenv("COAL_NEWS_SEARCH_MAX_RESULTS", "12")
    monkeypatch.setenv("COAL_NEWS_SEARCH_MAX_RESPONSE_BYTES", "65536")
    monkeypatch.setenv("COAL_NEWS_SEARCH_MAX_CONCURRENCY", "2")
    monkeypatch.setenv("COAL_NEWS_BAIDU_ENABLED", "false")
    monkeypatch.setenv("COAL_NEWS_DEEPSEEK_WEB_SEARCH_ENABLED", "false")
    monkeypatch.setenv("COAL_NEWS_BING_FALLBACK_ENABLED", "true")
    configured = Settings.from_environment().coal_news
    assert configured.enabled is False
    assert configured.timeout_seconds == 8.0
    assert configured.baidu_timeout_seconds == 2.0
    assert configured.deepseek_timeout_seconds == 7.0
    assert configured.cache_ttl_seconds == 600
    assert configured.max_results == 12
    assert configured.max_response_bytes == 65536
    assert configured.max_concurrency == 2
    assert configured.baidu_enabled is False
    assert configured.deepseek_web_search_enabled is False
    assert configured.bing_fallback_enabled is True

    monkeypatch.setenv("COAL_NEWS_SEARCH_MAX_RESULTS", "99")
    with pytest.raises(ValueError, match="MAX_RESULTS"):
        Settings.from_environment()


def test_agent_v2_defaults_and_bounded_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "AGENT_V2_ENABLED",
        "AGENT_V2_SCHEDULER_ENABLED",
        "AGENT_V2_SCHEDULER_POLL_SECONDS",
        "AGENT_V2_WORKER_COUNT",
        "AGENT_V2_SPECIALIST_WORKER_COUNT",
        "AGENT_V2_FLOW_LEASE_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)
    defaults = Settings.from_environment().agent_v2
    assert defaults.enabled is True
    assert defaults.scheduler_enabled is True
    assert defaults.scheduler_poll_seconds == 5.0
    assert defaults.worker_count == 2
    assert defaults.specialist_worker_count == 4
    assert defaults.flow_lease_seconds == 120

    monkeypatch.setenv("AGENT_V2_ENABLED", "false")
    monkeypatch.setenv("AGENT_V2_SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("AGENT_V2_SCHEDULER_POLL_SECONDS", "0.5")
    monkeypatch.setenv("AGENT_V2_WORKER_COUNT", "3")
    monkeypatch.setenv("AGENT_V2_SPECIALIST_WORKER_COUNT", "6")
    monkeypatch.setenv("AGENT_V2_FLOW_LEASE_SECONDS", "180")
    configured = Settings.from_environment().agent_v2
    assert configured.enabled is False
    assert configured.scheduler_enabled is False
    assert configured.scheduler_poll_seconds == 0.5
    assert configured.worker_count == 3
    assert configured.specialist_worker_count == 6
    assert configured.flow_lease_seconds == 180

    monkeypatch.setenv("AGENT_V2_WORKER_COUNT", "99")
    with pytest.raises(ValueError, match="AGENT_V2_WORKER_COUNT"):
        Settings.from_environment()
