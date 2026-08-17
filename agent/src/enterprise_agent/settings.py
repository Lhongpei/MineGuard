"""Environment-based configuration.

Secrets are read only when constructing runtime services and are never
serialised into drafts or logs.
"""

from __future__ import annotations

import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .auth import UserAccount, parse_users_json
from .client import PlatformClientConfig
from .five_quantity_exchange import (
    EnterpriseSigningVerificationKey,
    FiveQuantityPlatformConfig,
    MineIdentity,
)
from .llm import LLMConfig
from .machine_ingestion import ConnectorClient, parse_connector_clients_json
from .model_api_config import ModelApiConfigError, load_model_api_config
from .model_credentials import (
    ModelCredentialStatus,
    plaintext_model_environment_names,
)
from .provisioning import (
    ProvisioningStatus,
    verify_provisioning_lock_from_environment,
)
from .skills import CoalNewsConfig


def split_path_list(raw: str, *, separator: str | None = None) -> tuple[str, ...]:
    """Split an OS path list, including Windows' semicolon-separated form."""

    selected_separator = os.pathsep if separator is None else separator
    if len(selected_separator) != 1:
        raise ValueError("path list separator must be one character")
    return tuple(part.strip() for part in raw.split(selected_separator) if part.strip())


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    return _integer_value(name, os.environ.get(name), default, minimum, maximum)


def _integer_value(
    name: str,
    raw: str | None,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _float(name: str, default: float, minimum: float, maximum: float) -> float:
    return _float_value(name, os.environ.get(name), default, minimum, maximum)


def _float_value(
    name: str,
    raw: str | None,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    if raw is None:
        return default
    try:
        parsed = float(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be numeric") from error
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _boolean(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalised = raw.strip().lower()
    if normalised in {"1", "true", "yes", "on"}:
        return True
    if normalised in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


_MODEL_ENVIRONMENT = {
    "api_key": "MINEGUARD_AGENT_API_KEY",
    "base_url": "MINEGUARD_AGENT_BASE_URL",
    "model": "MINEGUARD_AGENT_MODEL",
    "timeout": "MINEGUARD_AGENT_TIMEOUT_SECONDS",
    "max_retries": "MINEGUARD_AGENT_MAX_RETRIES",
}
_REMOVED_LEGACY_MODEL_ENVIRONMENT = frozenset(
    {
        "DEEPSEEK_API_KEY",
        "DEEPSEEK_BASE_URL",
        "DEEPSEEK_MODEL",
        "DEEPSEEK_TIMEOUT_SECONDS",
        "DEEPSEEK_MAX_RETRIES",
    }
)
_REMOVED_MODEL_CREDENTIAL_ENVIRONMENT = {
    "lock": "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE",
    "secret_store": "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE",
}


def _model_config_from_environment() -> LLMConfig | None:
    """Read the provider-neutral development-only model namespace."""

    current = {
        field: os.environ.get(name) for field, name in _MODEL_ENVIRONMENT.items()
    }
    removed_legacy_names = sorted(
        name
        for name in _REMOVED_LEGACY_MODEL_ENVIRONMENT
        if os.environ.get(name, "").strip()
    )
    if removed_legacy_names:
        raise ValueError(
            "DEEPSEEK_* 模型配置已移除；请删除："
            + "、".join(removed_legacy_names)
        )
    api_key = (current["api_key"] or "").strip()
    if not api_key:
        return None

    missing = [
        _MODEL_ENVIRONMENT[field]
        for field in ("base_url", "model")
        if not (current[field] or "").strip()
    ]
    if missing:
        raise ValueError(
            "使用 MINEGUARD_AGENT_API_KEY 时必须显式配置 " + "、".join(missing)
        )

    return LLMConfig(
        api_key=api_key,
        base_url=(current["base_url"] or "").strip(),
        model=(current["model"] or "").strip(),
        timeout_seconds=_float_value(
            _MODEL_ENVIRONMENT["timeout"],
            current["timeout"],
            20.0,
            1.0,
            120.0,
        ),
        max_retries=_integer_value(
            _MODEL_ENVIRONMENT["max_retries"],
            current["max_retries"],
            2,
            0,
            5,
        ),
    )


def _plaintext_model_environment_present() -> bool:
    return bool(plaintext_model_environment_names())


def _managed_model_config(
    *,
    provisioning_status: ProvisioningStatus,
    identity: MineIdentity,
) -> tuple[LLMConfig | None, ModelCredentialStatus]:
    local_path = os.environ.get("ENTERPRISE_AGENT_MODEL_CONFIG_FILE", "").strip()
    removed_pointers = {
        field: os.environ.get(name, "").strip()
        for field, name in _REMOVED_MODEL_CREDENTIAL_ENVIRONMENT.items()
    }
    if any(removed_pointers.values()):
        raise ValueError(
            "旧 .mgllm 模型凭据流程已移除；请删除旧 lock/store 指针，"
            "并由 api_admin 在企业端页面配置模型 API"
        )
    if local_path:
        if _plaintext_model_environment_present():
            raise ValueError("api_admin 模型配置不能与明文模型环境变量混用")
        if not provisioning_status.managed:
            raise ValueError("api_admin 模型配置必须绑定已验签的企业接入身份")
        try:
            config, status = load_model_api_config(local_path)
        except (ModelApiConfigError, OSError):
            return None, ModelCredentialStatus(
                managed=True,
                mine_id=identity.mine_id,
                system_id=identity.system_id,
                party_id=identity.operator_id,
                pair_id=provisioning_status.pair_id,
                source="api_admin",
                state="unavailable",
                failure_code="local_model_config_invalid",
            )
        return config, ModelCredentialStatus(
            managed=True,
            mine_id=identity.mine_id,
            system_id=identity.system_id,
            party_id=identity.operator_id,
            pair_id=provisioning_status.pair_id,
            base_url=(config.base_url if config is not None else None),
            model=(config.model if config is not None else None),
            capabilities=("chat", "extraction", "coal-news-search"),
            secret_protection=status.get("secret_protection"),
            source="api_admin",
            state=str(status.get("state") or "not_configured"),
        )
    config = _model_config_from_environment()
    return config, ModelCredentialStatus(
        managed=False,
        source=("development-environment" if config is not None else "not_configured"),
    )


def _historical_enterprise_signing_keys(
    raw: str | None,
) -> tuple[EnterpriseSigningVerificationKey, ...]:
    """Parse the bounded, explicit keyring used for immutable predecessors."""

    if raw is None or not raw.strip():
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(
            "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON must be valid JSON"
        ) from error
    if not isinstance(parsed, list):
        raise ValueError(
            "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON must be a JSON array"
        )
    if len(parsed) > 64:
        raise ValueError(
            "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON may contain at most 64 keys"
        )
    result: list[EnterpriseSigningVerificationKey] = []
    for index, item in enumerate(parsed):
        if not isinstance(item, dict) or set(item) != {"key_id", "secret"}:
            raise ValueError(
                "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON entry "
                f"{index + 1} must contain exactly key_id and secret"
            )
        key_id = item.get("key_id")
        secret = item.get("secret")
        if not isinstance(key_id, str) or not isinstance(secret, str):
            raise ValueError(
                "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON entry "
                f"{index + 1} key_id and secret must be strings"
            )
        try:
            result.append(
                EnterpriseSigningVerificationKey(key_id=key_id, secret=secret)
            )
        except ValueError as error:
            raise ValueError(
                "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON entry "
                f"{index + 1} is invalid: {error}"
            ) from error
    return tuple(result)


@dataclass(frozen=True)
class AgentV2Config:
    """Bounded runtime configuration for durable read-only workflows."""

    enabled: bool = True
    scheduler_enabled: bool = True
    scheduler_poll_seconds: float = 5.0
    worker_count: int = 2
    specialist_worker_count: int = 4
    flow_lease_seconds: int = 120

    def __post_init__(self) -> None:
        if not 0.25 <= self.scheduler_poll_seconds <= 60:
            raise ValueError(
                "AGENT_V2_SCHEDULER_POLL_SECONDS must be between 0.25 and 60"
            )
        if not 1 <= self.worker_count <= 8:
            raise ValueError("AGENT_V2_WORKER_COUNT must be between 1 and 8")
        if not 1 <= self.specialist_worker_count <= 8:
            raise ValueError("AGENT_V2_SPECIALIST_WORKER_COUNT must be between 1 and 8")
        if not 30 <= self.flow_lease_seconds <= 600:
            raise ValueError("AGENT_V2_FLOW_LEASE_SECONDS must be between 30 and 600")


@dataclass(frozen=True)
class Settings:
    database_path: str
    host: str
    port: int
    production_mode: bool
    four_eyes_required: bool
    users: tuple[UserAccount, ...]
    allow_anonymous_local: bool
    session_ttl_seconds: int
    secure_cookie: bool
    public_origin: str | None
    platform: PlatformClientConfig | None
    llm: LLMConfig | None
    model_credential_status: ModelCredentialStatus
    model_config_path: str | None
    coal_news: CoalNewsConfig
    agent_v2: AgentV2Config
    five_quantity_identity: MineIdentity
    five_quantity_platform: FiveQuantityPlatformConfig | None
    five_quantity_watch_directories: tuple[str, ...]
    five_quantity_quarantine_directory: str
    five_quantity_poll_seconds: float
    five_quantity_stable_seconds: float
    five_quantity_demo_secret: bool
    connector_clients: tuple[ConnectorClient, ...]
    connector_max_clock_skew_seconds: int
    provisioning_status: ProvisioningStatus

    @classmethod
    def from_environment(cls) -> Settings:
        # A configured provisioning lock is an authority boundary, not an
        # informational marker.  Verify it before interpreting any current
        # environment value so an inherited/UI override fails closed.
        provisioning_status = verify_provisioning_lock_from_environment()
        database_path = os.environ.get(
            "ENTERPRISE_AGENT_DB",
            "./data/enterprise-agent.db",
        )
        if not database_path.strip():
            raise ValueError("ENTERPRISE_AGENT_DB 不能为空")
        host = os.environ.get("ENTERPRISE_AGENT_HOST", "127.0.0.1").strip()
        if not host:
            raise ValueError("ENTERPRISE_AGENT_HOST 不能为空")
        untrimmed_public_origin = os.environ.get(
            "ENTERPRISE_AGENT_PUBLIC_ORIGIN",
            "",
        )
        raw_public_origin = untrimmed_public_origin.strip()
        public_origin = None
        if raw_public_origin:
            if (
                raw_public_origin != untrimmed_public_origin
                or any(character.isspace() for character in raw_public_origin)
                or "%" in raw_public_origin
            ):
                raise ValueError(
                    "ENTERPRISE_AGENT_PUBLIC_ORIGIN 不能包含空白或百分号编码"
                )
            parsed_origin = urlsplit(raw_public_origin)
            try:
                _ = parsed_origin.port
            except ValueError as error:
                raise ValueError("ENTERPRISE_AGENT_PUBLIC_ORIGIN 端口非法") from error
            if (
                parsed_origin.scheme not in {"http", "https"}
                or not parsed_origin.hostname
                or parsed_origin.username is not None
                or parsed_origin.password is not None
                or parsed_origin.query
                or parsed_origin.fragment
                or parsed_origin.path not in {"", "/"}
            ):
                raise ValueError(
                    "ENTERPRISE_AGENT_PUBLIC_ORIGIN 必须是无路径、查询和账号信息的 "
                    "HTTP(S) origin，例如 https://report.example.com"
                )
            hostname = parsed_origin.hostname.lower()
            host_text = f"[{hostname}]" if ":" in hostname else hostname
            port = parsed_origin.port
            default_port = 443 if parsed_origin.scheme == "https" else 80
            authority = (
                host_text
                if port is None or port == default_port
                else f"{host_text}:{port}"
            )
            public_origin = f"{parsed_origin.scheme}://{authority}"
        platform_base = os.environ.get("PLATFORM_BASE_URL", "").strip()
        platform_client_id = os.environ.get("PLATFORM_CLIENT_ID", "").strip()
        platform_hmac_secret = os.environ.get("PLATFORM_TRANSPORT_HMAC_SECRET", "")
        platform_bearer = os.environ.get("PLATFORM_BEARER_TOKEN", "")
        platform_requested = any(
            (
                platform_base,
                platform_client_id,
                platform_hmac_secret,
                platform_bearer,
            )
        )
        if platform_requested and not all(
            (platform_base, platform_client_id, platform_hmac_secret)
        ):
            raise ValueError(
                "PLATFORM_BASE_URL, PLATFORM_CLIENT_ID and "
                "PLATFORM_TRANSPORT_HMAC_SECRET must be configured together; "
                "a Bearer token cannot replace contract HMAC authentication"
            )
        if platform_hmac_secret and len(platform_hmac_secret.encode("utf-8")) < 32:
            raise ValueError("PLATFORM_TRANSPORT_HMAC_SECRET must be at least 32 bytes")
        platform = None
        if platform_requested:
            platform = PlatformClientConfig(
                base_url=platform_base,
                submission_path=os.environ.get(
                    "PLATFORM_SUBMISSION_PATH",
                    "/v1/enterprise-submissions",
                ),
                capabilities_path=os.environ.get(
                    "PLATFORM_CAPABILITIES_PATH",
                    "/v1/enterprise-submission-capabilities",
                ),
                bearer_token=platform_bearer or None,
                client_id=platform_client_id,
                transport_hmac_secret=platform_hmac_secret,
                timeout_seconds=_float("PLATFORM_TIMEOUT_SECONDS", 20.0, 1.0, 120.0),
            )

        # V1 and the governed V2/V3 exchange are independent products.  Keep
        # the V2 variable names as deployment aliases, but all new reporting
        # uses the V3 routes and signing domains.
        v2_base = (
            os.environ.get("PLATFORM_V3_BASE_URL", "").strip()
            or os.environ.get("PLATFORM_V2_BASE_URL", "").strip()
        )
        v2_sender_id = (
            os.environ.get("PLATFORM_V3_SENDER_ID", "").strip()
            or os.environ.get("PLATFORM_V2_SENDER_ID", "").strip()
            or os.environ.get("ENTERPRISE_SYSTEM_ID", "agent-demo-mine-001").strip()
        )
        v2_transport_secret = os.environ.get(
            "PLATFORM_V3_TRANSPORT_HMAC_SECRET", ""
        ) or os.environ.get("PLATFORM_V2_TRANSPORT_HMAC_SECRET", "")
        explicit_message_secret = os.environ.get("ENTERPRISE_EXCHANGE_HMAC_SECRET", "")
        demo_message_secret = (
            "DEMO_ONLY_five_quantity_exchange_secret_change_before_production"
        )
        message_secret = explicit_message_secret or demo_message_secret
        five_quantity_demo_secret = not bool(explicit_message_secret)
        five_quantity_identity = MineIdentity(
            mine_id=os.environ.get("ENTERPRISE_MINE_ID", "demo-mine-001").strip(),
            mine_name=os.environ.get("ENTERPRISE_MINE_NAME", "演示煤矿").strip(),
            operator_id=os.environ.get(
                "ENTERPRISE_OPERATOR_ID", "demo-operator-001"
            ).strip(),
            operator_name=os.environ.get(
                "ENTERPRISE_OPERATOR_NAME", "演示煤矿经营主体"
            ).strip(),
            system_id=os.environ.get(
                "ENTERPRISE_SYSTEM_ID", "agent-demo-mine-001"
            ).strip(),
            regulator_system_id=os.environ.get(
                "REGULATORY_SYSTEM_ID", "mineguard-qinyuan"
            ).strip(),
            regulator_party_id=os.environ.get(
                "REGULATORY_PARTY_ID", "regulator-qinyuan"
            ).strip(),
            key_id=os.environ.get(
                "ENTERPRISE_EXCHANGE_KEY_ID", "demo-exchange-key"
            ).strip(),
            regulator_key_id=os.environ.get(
                "REGULATORY_EXCHANGE_KEY_ID", "regulator-key-v2"
            ).strip(),
            message_hmac_secret=message_secret,
            historical_enterprise_signing_keys=(
                _historical_enterprise_signing_keys(
                    os.environ.get("ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON")
                )
            ),
            previous_regulator_key_id=(
                os.environ.get("REGULATORY_PREVIOUS_EXCHANGE_KEY_ID", "").strip()
                or None
            ),
            previous_message_hmac_secret=(
                os.environ.get("REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET", "") or None
            ),
            timezone=os.environ.get(
                "ENTERPRISE_REPORTING_TIMEZONE", "Asia/Shanghai"
            ).strip(),
            capacity_band=os.environ.get(
                "ENTERPRISE_CAPACITY_BAND", "unclassified"
            ).strip(),
            mining_method=os.environ.get(
                "ENTERPRISE_MINING_METHOD", "unclassified"
            ).strip(),
            shift_system=os.environ.get(
                "ENTERPRISE_SHIFT_SYSTEM", "three-shift-eight-hour"
            ).strip(),
            coal_type=os.environ.get("ENTERPRISE_COAL_TYPE", "unclassified").strip(),
            operating_regime=os.environ.get(
                "ENTERPRISE_OPERATING_REGIME", "normal-production"
            ).strip(),
        )
        five_quantity_platform = None
        if v2_base:
            if (
                not v2_sender_id
                or not v2_transport_secret
                or not explicit_message_secret
            ):
                raise ValueError(
                    "配置 V3 监管地址时必须显式配置 PLATFORM_V3_SENDER_ID"
                    "（或兼容的 V2 名称）、"
                    "ENTERPRISE_EXCHANGE_HMAC_SECRET 和 "
                    "PLATFORM_V3_TRANSPORT_HMAC_SECRET（或兼容的 V2 名称）"
                )
            if hmac.compare_digest(
                explicit_message_secret.encode("utf-8"),
                v2_transport_secret.encode("utf-8"),
            ):
                raise ValueError("应用消息 HMAC 密钥与运输 HMAC 密钥不得相同")
            if v2_sender_id != five_quantity_identity.system_id:
                raise ValueError(
                    "PLATFORM_V3_SENDER_ID 必须与 ENTERPRISE_SYSTEM_ID 相同；"
                    "一个智能体实例只能绑定一个已登记发送系统"
                )
            five_quantity_platform = FiveQuantityPlatformConfig(
                base_url=v2_base,
                sender_id=v2_sender_id,
                transport_hmac_secret=v2_transport_secret,
                timeout_seconds=_float(
                    (
                        "PLATFORM_V3_TIMEOUT_SECONDS"
                        if "PLATFORM_V3_TIMEOUT_SECONDS" in os.environ
                        else "PLATFORM_V2_TIMEOUT_SECONDS"
                    ),
                    20.0,
                    1.0,
                    120.0,
                ),
                submission_path=os.environ.get(
                    "PLATFORM_V3_SUBMISSION_PATH",
                    "/v3/ten-quantity-submissions",
                ).strip(),
                next_report_path=os.environ.get(
                    "PLATFORM_V3_NEXT_REPORT_PATH",
                    "/v3/analysis-reports/next",
                ).strip(),
                legacy_submission_path=os.environ.get(
                    "PLATFORM_V2_SUBMISSION_PATH",
                    "/v2/five-quantity-submissions",
                ).strip(),
                analysis_path=os.environ.get(
                    "PLATFORM_V3_ANALYSIS_PATH",
                    "/v3/analysis-reports",
                ).strip(),
                ca_bundle_path=(
                    os.environ.get("PLATFORM_V3_CA_BUNDLE", "").strip()
                    or os.environ.get("PLATFORM_V2_CA_BUNDLE", "").strip()
                    or None
                ),
            )
        watched_raw = os.environ.get("ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS", "")
        five_quantity_watch_directories = split_path_list(watched_raw)
        database_state_directory = (
            Path("./data").resolve()
            if database_path == ":memory:"
            else Path(database_path).expanduser().resolve().parent
        )
        five_quantity_quarantine_directory = str(
            database_state_directory / "five-quantity-quarantine"
        )

        llm, model_credential_status = _managed_model_config(
            provisioning_status=provisioning_status,
            identity=five_quantity_identity,
        )
        return cls(
            database_path=database_path,
            host=host,
            port=_integer("ENTERPRISE_AGENT_PORT", 8090, 1, 65535),
            production_mode=_boolean(
                "ENTERPRISE_AGENT_PRODUCTION_MODE",
                False,
            ),
            four_eyes_required=_boolean(
                "ENTERPRISE_AGENT_FOUR_EYES_REQUIRED",
                False,
            ),
            users=parse_users_json(os.environ.get("ENTERPRISE_AGENT_USERS_JSON")),
            allow_anonymous_local=_boolean(
                "ENTERPRISE_AGENT_ALLOW_ANONYMOUS_LOCAL",
                False,
            ),
            session_ttl_seconds=_integer(
                "ENTERPRISE_AGENT_SESSION_TTL_SECONDS",
                8 * 60 * 60,
                300,
                7 * 24 * 60 * 60,
            ),
            secure_cookie=_boolean("ENTERPRISE_AGENT_SECURE_COOKIE", False),
            public_origin=public_origin,
            platform=platform,
            llm=llm,
            model_credential_status=model_credential_status,
            model_config_path=(
                os.environ.get("ENTERPRISE_AGENT_MODEL_CONFIG_FILE", "").strip()
                or None
            ),
            coal_news=CoalNewsConfig(
                enabled=_boolean("COAL_NEWS_SEARCH_ENABLED", True),
                timeout_seconds=_float(
                    "COAL_NEWS_SEARCH_TIMEOUT_SECONDS",
                    25.0,
                    3.0,
                    60.0,
                ),
                baidu_timeout_seconds=_float(
                    "COAL_NEWS_BAIDU_TIMEOUT_SECONDS",
                    3.0,
                    1.0,
                    10.0,
                ),
                deepseek_timeout_seconds=_float(
                    "COAL_NEWS_DEEPSEEK_TIMEOUT_SECONDS",
                    24.0,
                    3.0,
                    60.0,
                ),
                cache_ttl_seconds=_integer(
                    "COAL_NEWS_SEARCH_CACHE_TTL_SECONDS",
                    300,
                    30,
                    3_600,
                ),
                max_results=_integer(
                    "COAL_NEWS_SEARCH_MAX_RESULTS",
                    8,
                    1,
                    20,
                ),
                max_response_bytes=_integer(
                    "COAL_NEWS_SEARCH_MAX_RESPONSE_BYTES",
                    1024 * 1024,
                    64 * 1024,
                    2 * 1024 * 1024,
                ),
                max_concurrency=_integer(
                    "COAL_NEWS_SEARCH_MAX_CONCURRENCY",
                    4,
                    1,
                    8,
                ),
                baidu_enabled=_boolean(
                    "COAL_NEWS_BAIDU_ENABLED",
                    True,
                ),
                deepseek_web_search_enabled=_boolean(
                    "COAL_NEWS_DEEPSEEK_WEB_SEARCH_ENABLED",
                    True,
                ),
                bing_fallback_enabled=_boolean(
                    "COAL_NEWS_BING_FALLBACK_ENABLED",
                    False,
                ),
            ),
            agent_v2=AgentV2Config(
                enabled=_boolean("AGENT_V2_ENABLED", True),
                scheduler_enabled=_boolean(
                    "AGENT_V2_SCHEDULER_ENABLED",
                    True,
                ),
                scheduler_poll_seconds=_float(
                    "AGENT_V2_SCHEDULER_POLL_SECONDS",
                    5.0,
                    0.25,
                    60.0,
                ),
                worker_count=_integer(
                    "AGENT_V2_WORKER_COUNT",
                    2,
                    1,
                    8,
                ),
                specialist_worker_count=_integer(
                    "AGENT_V2_SPECIALIST_WORKER_COUNT",
                    4,
                    1,
                    8,
                ),
                flow_lease_seconds=_integer(
                    "AGENT_V2_FLOW_LEASE_SECONDS",
                    120,
                    30,
                    600,
                ),
            ),
            five_quantity_identity=five_quantity_identity,
            five_quantity_platform=five_quantity_platform,
            five_quantity_watch_directories=five_quantity_watch_directories,
            five_quantity_quarantine_directory=five_quantity_quarantine_directory,
            five_quantity_poll_seconds=_float(
                "ENTERPRISE_FIVE_QUANTITY_POLL_SECONDS", 5.0, 0.5, 60.0
            ),
            five_quantity_stable_seconds=_float(
                "ENTERPRISE_FIVE_QUANTITY_STABLE_SECONDS", 2.0, 0.5, 60.0
            ),
            five_quantity_demo_secret=five_quantity_demo_secret,
            connector_clients=parse_connector_clients_json(
                os.environ.get("ENTERPRISE_AGENT_CONNECTOR_CLIENTS_JSON")
            ),
            connector_max_clock_skew_seconds=_integer(
                "ENTERPRISE_AGENT_CONNECTOR_MAX_CLOCK_SKEW_SECONDS",
                300,
                30,
                900,
            ),
            provisioning_status=provisioning_status,
        )
