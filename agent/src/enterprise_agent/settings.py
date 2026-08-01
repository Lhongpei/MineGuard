"""Environment-based configuration.

Secrets are read only when constructing runtime services and are never
serialised into drafts or logs.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .auth import UserAccount, parse_users_json
from .client import PlatformClientConfig
from .five_quantity_exchange import FiveQuantityPlatformConfig, MineIdentity
from .llm import LLMConfig
from .skills import CoalNewsConfig


def _integer(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
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
    raw = os.environ.get(name)
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
    users: tuple[UserAccount, ...]
    allow_anonymous_local: bool
    session_ttl_seconds: int
    secure_cookie: bool
    public_origin: str | None
    platform: PlatformClientConfig | None
    llm: LLMConfig | None
    coal_news: CoalNewsConfig
    agent_v2: AgentV2Config
    five_quantity_identity: MineIdentity
    five_quantity_platform: FiveQuantityPlatformConfig | None
    five_quantity_watch_directories: tuple[str, ...]
    five_quantity_quarantine_directory: str
    five_quantity_poll_seconds: float
    five_quantity_stable_seconds: float
    five_quantity_demo_secret: bool

    @classmethod
    def from_environment(cls) -> Settings:
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

        # V1 and V2 are independent products/contracts.  A legacy V1 endpoint
        # must never silently enable the V2 exchange client.
        v2_base = os.environ.get("PLATFORM_V2_BASE_URL", "").strip()
        v2_sender_id = (
            os.environ.get("PLATFORM_V2_SENDER_ID", "").strip()
            or os.environ.get("ENTERPRISE_SYSTEM_ID", "agent-demo-mine-001").strip()
        )
        v2_transport_secret = os.environ.get("PLATFORM_V2_TRANSPORT_HMAC_SECRET", "")
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
                    "配置 V2 监管地址时必须显式配置 PLATFORM_V2_SENDER_ID、"
                    "ENTERPRISE_EXCHANGE_HMAC_SECRET 和 "
                    "PLATFORM_V2_TRANSPORT_HMAC_SECRET"
                )
            if hmac.compare_digest(
                explicit_message_secret.encode("utf-8"),
                v2_transport_secret.encode("utf-8"),
            ):
                raise ValueError("V2 应用消息 HMAC 密钥与运输 HMAC 密钥不得相同")
            if v2_sender_id != five_quantity_identity.system_id:
                raise ValueError(
                    "PLATFORM_V2_SENDER_ID 必须与 ENTERPRISE_SYSTEM_ID 相同；"
                    "一个智能体实例只能绑定一个已登记发送系统"
                )
            five_quantity_platform = FiveQuantityPlatformConfig(
                base_url=v2_base,
                sender_id=v2_sender_id,
                transport_hmac_secret=v2_transport_secret,
                timeout_seconds=_float(
                    "PLATFORM_V2_TIMEOUT_SECONDS",
                    20.0,
                    1.0,
                    120.0,
                ),
                submission_path=os.environ.get(
                    "PLATFORM_V2_SUBMISSION_PATH",
                    "/v2/five-quantity-submissions",
                ).strip(),
                next_report_path=os.environ.get(
                    "PLATFORM_V2_NEXT_REPORT_PATH",
                    "/v2/analysis-reports/next",
                ).strip(),
                ca_bundle_path=(
                    os.environ.get("PLATFORM_V2_CA_BUNDLE", "").strip() or None
                ),
            )
        watched_raw = os.environ.get("ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS", "")
        five_quantity_watch_directories = tuple(
            part.strip() for part in watched_raw.split(os.pathsep) if part.strip()
        )
        database_state_directory = (
            Path("./data").resolve()
            if database_path == ":memory:"
            else Path(database_path).expanduser().resolve().parent
        )
        five_quantity_quarantine_directory = str(
            database_state_directory / "five-quantity-quarantine"
        )

        api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
        llm = None
        if api_key:
            llm = LLMConfig(
                api_key=api_key,
                base_url=os.environ.get(
                    "DEEPSEEK_BASE_URL", "https://api.deepseek.com"
                ).strip(),
                model=os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-flash").strip(),
                timeout_seconds=_float("DEEPSEEK_TIMEOUT_SECONDS", 20.0, 1.0, 120.0),
                max_retries=_integer("DEEPSEEK_MAX_RETRIES", 2, 0, 5),
            )
        return cls(
            database_path=database_path,
            host=host,
            port=_integer("ENTERPRISE_AGENT_PORT", 8090, 1, 65535),
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
        )
