"""Environment based runtime configuration."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import ipaddress
import json
import math
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .errors import ConfigurationError

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
# A generated batch id is ``{client_id}--batch_{32 hex chars}`` and the neutral
# contract caps identifiers at 128 characters.
_MAX_BATCH_CLIENT_ID_LENGTH = 128 - len("--batch_") - 32


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"布尔配置值无效：{value!r}")


def _int(value: str | None, default: int, *, minimum: int = 0) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ConfigurationError(f"整数配置值无效：{value!r}") from error
    if parsed < minimum:
        raise ConfigurationError(f"配置值不得小于 {minimum}")
    return parsed


def _finite_float(value: Any, name: str, *, minimum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"{name} 必须是数值") from error
    if not math.isfinite(parsed) or parsed < minimum:
        raise ConfigurationError(f"{name} 必须是不小于 {minimum:g} 的有限数")
    return parsed


def _json_object(value: str | None, name: str) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ConfigurationError(f"{name} 必须是有效 JSON") from error
    if not isinstance(parsed, dict):
        raise ConfigurationError(f"{name} 顶层必须是对象")
    return parsed


def _upstream_secret() -> bytes | None:
    encoded = os.environ.get("MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64")
    text = os.environ.get("MINE_EDGE_UPSTREAM_HMAC_SECRET")
    if encoded and text:
        raise ConfigurationError(
            "上行 HMAC 密钥的 BASE64 与 UTF-8 配置不能同时设置"
        )
    if encoded:
        try:
            result = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ConfigurationError(
                "MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64 不是有效 base64"
            ) from error
    elif text:
        result = text.encode("utf-8")
    else:
        return None
    if len(result) < 32:
        raise ConfigurationError("上行 HMAC 密钥解码后至少需要 32 字节")
    return result


def validate_upstream_url(value: str | None) -> str | None:
    """Validate and normalize the regulator origin used for signed uploads.

    The HMAC contract signs a fixed root path.  Rejecting userinfo, URL
    decorations and base paths prevents credentials or signed headers from
    being sent somewhere other than the configured regulator origin.
    """

    if value is None:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate != value or any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in candidate
    ):
        raise ConfigurationError(
            "MINE_EDGE_UPSTREAM_URL 不得包含首尾空白或控制字符"
        )
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError("MINE_EDGE_UPSTREAM_URL 不是有效 URL") from error
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError("MINE_EDGE_UPSTREAM_URL 必须是 HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("MINE_EDGE_UPSTREAM_URL 禁止包含 userinfo")
    if "?" in candidate or "#" in candidate or parsed.query or parsed.fragment:
        raise ConfigurationError("MINE_EDGE_UPSTREAM_URL 禁止包含 query 或 fragment")
    if parsed.path not in {"", "/"}:
        raise ConfigurationError(
            "MINE_EDGE_UPSTREAM_URL 只能填写协议、主机和端口，禁止 base path"
        )
    if parsed.hostname is None or parsed.netloc.endswith(":"):
        raise ConfigurationError("MINE_EDGE_UPSTREAM_URL 缺少有效主机或端口")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigurationError("MINE_EDGE_UPSTREAM_URL 端口必须在 1-65535 范围内")
    if parsed.scheme == "http":
        hostname = parsed.hostname.lower()
        loopback = hostname == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                loopback = False
        if not loopback:
            raise ConfigurationError(
                "监管上行必须使用 HTTPS；仅 localhost 或回环 IP 可使用 HTTP"
            )
    return candidate.rstrip("/")


@dataclasses.dataclass(frozen=True, slots=True)
class ThresholdSettings:
    methane_percent: dict[str, float] = dataclasses.field(
        default_factory=lambda: {
            "blue": 0.5,
            "yellow": 0.8,
            "orange": 1.0,
            "red": 1.5,
        }
    )
    personnel_capacity: dict[str, int] = dataclasses.field(default_factory=dict)
    personnel_ratio: dict[str, float] = dataclasses.field(
        default_factory=lambda: {
            "blue": 0.8,
            "yellow": 0.9,
            "orange": 1.0,
            "red": 1.1,
        }
    )
    airflow_minimum: dict[str, float] = dataclasses.field(default_factory=dict)
    airflow_ratio: dict[str, float] = dataclasses.field(
        default_factory=lambda: {
            "blue": 0.95,
            "yellow": 0.9,
            "orange": 0.8,
            "red": 0.7,
        }
    )

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> ThresholdSettings:
        defaults = cls()

        def numeric_map(name: str, default: dict[str, float]) -> dict[str, float]:
            raw = value.get(name, default)
            if not isinstance(raw, dict):
                raise ConfigurationError(f"thresholds.{name} 必须是对象")
            try:
                parsed = {str(key): float(item) for key, item in raw.items()}
            except (TypeError, ValueError) as error:
                raise ConfigurationError(f"thresholds.{name} 只能包含数值") from error
            if any(not math.isfinite(item) for item in parsed.values()):
                raise ConfigurationError(f"thresholds.{name} 必须是有限数")
            return parsed

        def integer_map(name: str, default: dict[str, int]) -> dict[str, int]:
            raw = value.get(name, default)
            if not isinstance(raw, dict):
                raise ConfigurationError(f"thresholds.{name} 必须是对象")
            try:
                parsed = {str(key): int(item) for key, item in raw.items()}
            except (TypeError, ValueError) as error:
                raise ConfigurationError(f"thresholds.{name} 只能包含整数") from error
            if any(item <= 0 for item in parsed.values()):
                raise ConfigurationError(f"thresholds.{name} 必须大于零")
            return parsed

        result = cls(
            methane_percent=numeric_map(
                "methane_percent", defaults.methane_percent
            ),
            personnel_capacity=integer_map(
                "personnel_capacity", defaults.personnel_capacity
            ),
            personnel_ratio=numeric_map(
                "personnel_ratio", defaults.personnel_ratio
            ),
            airflow_minimum=numeric_map(
                "airflow_minimum", defaults.airflow_minimum
            ),
            airflow_ratio=numeric_map("airflow_ratio", defaults.airflow_ratio),
        )
        expected = {"blue", "yellow", "orange", "red"}
        for name in ("methane_percent", "personnel_ratio", "airflow_ratio"):
            if set(getattr(result, name)) != expected:
                raise ConfigurationError(f"thresholds.{name} 必须包含四色阈值")
        for name in ("methane_percent", "personnel_ratio"):
            mapping = getattr(result, name)
            ordered = [mapping[level] for level in ("blue", "yellow", "orange", "red")]
            if not all(
                left < right for left, right in zip(ordered, ordered[1:], strict=False)
            ) or (
                ordered[0] < 0
            ):
                raise ConfigurationError(
                    f"thresholds.{name} 必须满足 0 <= 蓝 < 黄 < 橙 < 红"
                )
        airflow = result.airflow_ratio
        airflow_ordered = [
            airflow[level] for level in ("blue", "yellow", "orange", "red")
        ]
        if not all(
            left > right
            for left, right in zip(
                airflow_ordered, airflow_ordered[1:], strict=False
            )
        ) or airflow_ordered[-1] < 0:
            raise ConfigurationError(
                "thresholds.airflow_ratio 必须满足 蓝 > 黄 > 橙 > 红 >= 0"
            )
        if any(value <= 0 for value in result.airflow_minimum.values()):
            raise ConfigurationError("thresholds.airflow_minimum 必须大于零")
        return result

    def public_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True, slots=True)
class MethaneAdaptiveSamplingSettings:
    """Read-only polling acceleration near a methane warning threshold."""

    enabled: bool = True
    trigger_ratio: float = 0.8
    accelerated_interval_seconds: float = 2.0
    window_seconds: float = 300.0

    def public_dict(self, *, regular_interval_seconds: float) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "trigger_ratio": self.trigger_ratio,
            "accelerated_interval_seconds": (
                self.accelerated_interval_seconds
            ),
            "window_seconds": self.window_seconds,
            "effective": (
                self.enabled
                and self.accelerated_interval_seconds
                < regular_interval_seconds
            ),
            "restart_behavior": "restore_unexpired_bounded_window",
            "device_write_capability": False,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class SourceSettings:
    """One independently scheduled, read-only acquisition source."""

    source_id: str
    adapter: str
    location: str
    interval_seconds: float
    jitter_seconds: float
    timeout_seconds: float
    missing_after_seconds: float
    enabled: bool = True
    token_env: str | None = None
    ca_file: Path | None = None
    methane_adaptive_sampling: MethaneAdaptiveSamplingSettings = (
        dataclasses.field(
            default_factory=MethaneAdaptiveSamplingSettings
        )
    )

    @classmethod
    def from_mapping(cls, value: dict[str, Any], index: int) -> SourceSettings:
        if not isinstance(value, dict):
            raise ConfigurationError(f"MINE_EDGE_SOURCES_JSON[{index}] 必须是对象")
        allowed = {
            "source_id",
            "adapter",
            "path",
            "url",
            "interval_seconds",
            "jitter_seconds",
            "timeout_seconds",
            "missing_after_seconds",
            "enabled",
            "token_env",
            "ca_file",
            "methane_adaptive_sampling",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}] 含未知字段："
                + ", ".join(sorted(unknown))
            )
        source_id = str(value.get("source_id") or "").strip()
        if _IDENTIFIER.fullmatch(source_id) is None:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}].source_id 不是安全标识符"
            )
        adapter = str(value.get("adapter") or "").strip()
        if adapter not in {"jsonl", "file-drop", "http-poll"}:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}].adapter 必须为 "
                "jsonl、file-drop 或 http-poll"
            )
        if adapter == "http-poll" and "path" in value:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}] 的 http-poll 只能配置 url"
            )
        if adapter != "http-poll" and "url" in value:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}] 的 {adapter} 只能配置 path"
            )
        location_key = "url" if adapter == "http-poll" else "path"
        location = str(value.get(location_key) or "").strip()
        if not location:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}].{location_key} 不能为空"
            )
        if adapter == "http-poll":
            try:
                parsed_url = urlsplit(location)
                port = parsed_url.port
            except ValueError as error:
                raise ConfigurationError(
                    f"MINE_EDGE_SOURCES_JSON[{index}].url 无效"
                ) from error
            if (
                parsed_url.scheme not in {"http", "https"}
                or not parsed_url.netloc
                or parsed_url.username is not None
                or parsed_url.password is not None
                or parsed_url.fragment
                or (port is not None and not 1 <= port <= 65535)
            ):
                raise ConfigurationError(
                    f"MINE_EDGE_SOURCES_JSON[{index}].url 必须是无 userinfo/fragment "
                    "的 HTTP(S) URL"
                )
        interval = _finite_float(
            value.get("interval_seconds", 30),
            f"MINE_EDGE_SOURCES_JSON[{index}].interval_seconds",
            minimum=0.1,
        )
        jitter = _finite_float(
            value.get("jitter_seconds", 0),
            f"MINE_EDGE_SOURCES_JSON[{index}].jitter_seconds",
            minimum=0,
        )
        if jitter > interval:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}].jitter_seconds "
                "不得大于 interval_seconds"
            )
        timeout = _finite_float(
            value.get("timeout_seconds", min(interval, 10)),
            f"MINE_EDGE_SOURCES_JSON[{index}].timeout_seconds",
            minimum=0.1,
        )
        missing_after = _finite_float(
            value.get("missing_after_seconds", max(interval * 3, 60)),
            f"MINE_EDGE_SOURCES_JSON[{index}].missing_after_seconds",
            minimum=interval,
        )
        adaptive_raw = value.get("methane_adaptive_sampling", {})
        if not isinstance(adaptive_raw, dict):
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling 必须是对象"
            )
        adaptive_unknown = set(adaptive_raw) - {
            "enabled",
            "trigger_ratio",
            "accelerated_interval_seconds",
            "window_seconds",
        }
        if adaptive_unknown:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling 含未知字段："
                + ", ".join(sorted(adaptive_unknown))
            )
        adaptive_enabled = adaptive_raw.get("enabled", True)
        if not isinstance(adaptive_enabled, bool):
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling.enabled 必须是布尔值"
            )
        trigger_ratio = _finite_float(
            adaptive_raw.get("trigger_ratio", 0.8),
            (
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling.trigger_ratio"
            ),
            minimum=0.1,
        )
        if trigger_ratio > 1:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling.trigger_ratio 必须不大于 1"
            )
        default_accelerated_interval = max(
            0.05,
            min(2.0, interval / 3),
        )
        accelerated_interval = _finite_float(
            adaptive_raw.get(
                "accelerated_interval_seconds",
                default_accelerated_interval,
            ),
            (
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling."
                "accelerated_interval_seconds"
            ),
            minimum=0.05,
        )
        if adaptive_enabled and accelerated_interval >= interval:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling."
                "accelerated_interval_seconds 必须小于 interval_seconds"
            )
        window_seconds = _finite_float(
            adaptive_raw.get("window_seconds", 300),
            (
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling.window_seconds"
            ),
            minimum=accelerated_interval,
        )
        if window_seconds > 3600:
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}]."
                "methane_adaptive_sampling.window_seconds 不得超过 3600"
            )
        methane_adaptive_sampling = MethaneAdaptiveSamplingSettings(
            enabled=adaptive_enabled,
            trigger_ratio=trigger_ratio,
            accelerated_interval_seconds=accelerated_interval,
            window_seconds=window_seconds,
        )
        enabled_value = value.get("enabled", True)
        if not isinstance(enabled_value, bool):
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}].enabled 必须是布尔值"
            )
        token_env_value = value.get("token_env")
        token_env = (
            str(token_env_value).strip() if token_env_value is not None else None
        )
        if token_env is not None and (
            adapter != "http-poll"
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", token_env) is None
        ):
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}].token_env 必须是大写环境变量名，"
                "且仅用于 http-poll"
            )
        ca_value = value.get("ca_file")
        ca_file = Path(str(ca_value)).expanduser() if ca_value else None
        if ca_file is not None and adapter != "http-poll":
            raise ConfigurationError(
                f"MINE_EDGE_SOURCES_JSON[{index}].ca_file 仅用于 http-poll"
            )
        return cls(
            source_id=source_id,
            adapter=adapter,
            location=location,
            interval_seconds=interval,
            jitter_seconds=jitter,
            timeout_seconds=timeout,
            missing_after_seconds=missing_after,
            enabled=enabled_value,
            token_env=token_env,
            ca_file=ca_file,
            methane_adaptive_sampling=methane_adaptive_sampling,
        )

    def public_dict(self) -> dict[str, Any]:
        public_location = self.location
        query_configured = False
        if self.adapter == "http-poll":
            parsed = urlsplit(self.location)
            query_configured = bool(parsed.query)
            public_location = urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, "", "")
            )
        return {
            "source_id": self.source_id,
            "adapter": self.adapter,
            # Query values can contain credentials even when operators should
            # use token_env. Never echo them through the API or browser.
            "location": public_location,
            "query_configured": query_configured,
            "interval_seconds": self.interval_seconds,
            "jitter_seconds": self.jitter_seconds,
            "timeout_seconds": self.timeout_seconds,
            "missing_after_seconds": self.missing_after_seconds,
            "enabled": self.enabled,
            "token_env": self.token_env,
            "ca_file": str(self.ca_file) if self.ca_file else None,
            "methane_adaptive_sampling": (
                self.methane_adaptive_sampling.public_dict(
                    regular_interval_seconds=self.interval_seconds,
                )
            ),
            "read_only": True,
        }


def _sources_from_env() -> tuple[SourceSettings, ...]:
    raw = os.environ.get("MINE_EDGE_SOURCES_JSON")
    if raw is None or not raw.strip():
        return ()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ConfigurationError(
            "MINE_EDGE_SOURCES_JSON 必须是有效 JSON"
        ) from error
    if not isinstance(document, list):
        raise ConfigurationError("MINE_EDGE_SOURCES_JSON 顶层必须是数组")
    if len(document) > 64:
        raise ConfigurationError("MINE_EDGE_SOURCES_JSON 最多配置 64 个来源")
    sources = tuple(
        SourceSettings.from_mapping(value, index)
        for index, value in enumerate(document)
    )
    ids = [source.source_id for source in sources]
    if len(ids) != len(set(ids)):
        raise ConfigurationError("MINE_EDGE_SOURCES_JSON source_id 不得重复")
    return sources


@dataclasses.dataclass(frozen=True, slots=True)
class Settings:
    mine_id: str
    client_id: str
    database_path: Path
    host: str
    port: int
    api_token: str | None
    upstream_url: str | None
    upstream_hmac_secret: bytes | None
    local_timezone: str
    forward_batch_size: int
    forward_base_delay_seconds: int
    forward_max_delay_seconds: int
    request_timeout_seconds: int
    body_limit_bytes: int
    thresholds: ThresholdSettings
    thresholds_calibrated: bool
    rule_profile_id: str
    rule_profile_version: int
    rule_profile_sha256: str
    sources: tuple[SourceSettings, ...] = ()

    @classmethod
    def from_env(cls) -> Settings:
        threshold_json = _json_object(
            os.environ.get("MINE_EDGE_THRESHOLDS_JSON"),
            "MINE_EDGE_THRESHOLDS_JSON",
        )
        upstream = validate_upstream_url(
            os.environ.get("MINE_EDGE_UPSTREAM_URL") or None
        )
        port = _int(os.environ.get("MINE_EDGE_PORT"), 8091, minimum=1)
        if port > 65535:
            raise ConfigurationError("MINE_EDGE_PORT 必须在 1-65535 范围内")
        base = _int(
            os.environ.get("MINE_EDGE_FORWARD_BASE_DELAY_SECONDS"), 5, minimum=1
        )
        maximum = _int(
            os.environ.get("MINE_EDGE_FORWARD_MAX_DELAY_SECONDS"), 3600, minimum=base
        )
        thresholds = ThresholdSettings.from_mapping(threshold_json)
        profile_id = os.environ.get(
            "MINE_EDGE_RULE_PROFILE_ID", "qinyuan-safety-default"
        ).strip()
        if _IDENTIFIER.fullmatch(profile_id) is None:
            raise ConfigurationError("MINE_EDGE_RULE_PROFILE_ID 不是安全标识符")
        profile_version = _int(
            os.environ.get("MINE_EDGE_RULE_PROFILE_VERSION"), 1, minimum=1
        )
        profile_sha256 = (
            os.environ.get("MINE_EDGE_RULE_PROFILE_SHA256") or ""
        ).strip().lower()
        if not profile_sha256:
            profile_sha256 = hashlib.sha256(
                json.dumps(
                    thresholds.public_dict(),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
        if _SHA256.fullmatch(profile_sha256) is None:
            raise ConfigurationError(
                "MINE_EDGE_RULE_PROFILE_SHA256 必须是 64 位小写 SHA-256"
            )
        result = cls(
            mine_id=os.environ.get("MINE_EDGE_MINE_ID", "demo-mine").strip(),
            client_id=os.environ.get(
                "MINE_EDGE_CLIENT_ID",
                os.environ.get("MINE_EDGE_MINE_ID", "demo-edge-client"),
            ).strip(),
            database_path=Path(
                os.environ.get("MINE_EDGE_DB", "./data/mine-edge.sqlite3")
            ).expanduser(),
            host=os.environ.get("MINE_EDGE_HOST", "127.0.0.1"),
            port=port,
            api_token=os.environ.get("MINE_EDGE_API_TOKEN") or None,
            upstream_url=upstream,
            upstream_hmac_secret=_upstream_secret(),
            local_timezone=os.environ.get("MINE_EDGE_LOCAL_TIMEZONE", "+08:00"),
            forward_batch_size=_int(
                os.environ.get("MINE_EDGE_FORWARD_BATCH_SIZE"), 100, minimum=1
            ),
            forward_base_delay_seconds=base,
            forward_max_delay_seconds=maximum,
            request_timeout_seconds=_int(
                os.environ.get("MINE_EDGE_REQUEST_TIMEOUT_SECONDS"), 10, minimum=1
            ),
            body_limit_bytes=_int(
                os.environ.get("MINE_EDGE_BODY_LIMIT_BYTES"),
                2 * 1024 * 1024,
                minimum=1024,
            ),
            thresholds=thresholds,
            thresholds_calibrated=_bool(
                os.environ.get("MINE_EDGE_THRESHOLDS_CALIBRATED"), False
            ),
            rule_profile_id=profile_id,
            rule_profile_version=profile_version,
            rule_profile_sha256=profile_sha256,
            sources=_sources_from_env(),
        )
        result.validate_contract_identity()
        return result

    def validate_contract_identity(self) -> None:
        if not self.mine_id:
            raise ConfigurationError("MINE_EDGE_MINE_ID 不能为空")
        if not self.client_id:
            raise ConfigurationError("MINE_EDGE_CLIENT_ID 不能为空")
        if _IDENTIFIER.fullmatch(self.mine_id) is None:
            raise ConfigurationError("MINE_EDGE_MINE_ID 不是安全合同标识符")
        if _IDENTIFIER.fullmatch(self.client_id) is None:
            raise ConfigurationError("MINE_EDGE_CLIENT_ID 不是安全合同标识符")
        if len(self.client_id) > _MAX_BATCH_CLIENT_ID_LENGTH:
            raise ConfigurationError(
                "MINE_EDGE_CLIENT_ID 最长 88 个字符，以确保带客户端前缀的 "
                "batch_id 不超过合同上限"
            )

    def validate_server_binding(self) -> None:
        self.validate_contract_identity()
        if self.upstream_url and not self.upstream_hmac_secret:
            raise ConfigurationError(
                "配置上行地址时必须设置 "
                "MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64（推荐）"
                "或 MINE_EDGE_UPSTREAM_HMAC_SECRET"
            )
        loopback = self.host in {"127.0.0.1", "::1", "localhost"}
        if not loopback and not self.api_token:
            raise ConfigurationError(
                "监听非本机地址时必须设置 MINE_EDGE_API_TOKEN；"
                "生产环境还应通过 HTTPS 反向代理访问"
            )

    def public_dict(self) -> dict[str, Any]:
        host = None
        if self.upstream_url:
            parsed = urlsplit(self.upstream_url)
            host = parsed.hostname
        return {
            "mine_id": self.mine_id,
            "client_id": self.client_id,
            "local_timezone": self.local_timezone,
            "upstream_configured": bool(self.upstream_url),
            "upstream_host": host,
            "api_auth_enabled": bool(self.api_token),
            "thresholds": self.thresholds.public_dict(),
            "thresholds_calibrated": self.thresholds_calibrated,
            "rule_profile": {
                "profile_id": self.rule_profile_id,
                "version": self.rule_profile_version,
                "sha256": self.rule_profile_sha256,
            },
            "sources": [source.public_dict() for source in self.sources],
            "operating_mode": "read-only-acquisition",
            "production_control_api": False,
        }
