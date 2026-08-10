from __future__ import annotations

import pytest

from enterprise_agent.auth import hash_password
from enterprise_agent.settings import Settings

_PLATFORM_ENV = (
    "PLATFORM_BASE_URL",
    "PLATFORM_CLIENT_ID",
    "PLATFORM_TRANSPORT_HMAC_SECRET",
    "PLATFORM_BEARER_TOKEN",
    "PLATFORM_SUBMISSION_PATH",
    "PLATFORM_CAPABILITIES_PATH",
)


def _clear_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PLATFORM_ENV:
        monkeypatch.delenv(name, raising=False)


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
