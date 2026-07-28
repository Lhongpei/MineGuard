"""Environment-based configuration.

Secrets are read only when constructing runtime services and are never
serialised into drafts or logs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from .auth import UserAccount, parse_users_json
from .client import PlatformClientConfig
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
        )
