"""Minimal, configurable HTTP client for the external platform contract."""

from __future__ import annotations

import json
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from .errors import PlatformError
from .security import transport_headers
from .util import canonical_json, utc_text

_MAX_ERROR_BODY = 128 * 1024
_MAX_PUBLIC_VIOLATIONS = 8
_PLATFORM_ERROR_HINTS = {
    "EXTERNAL_INTAKE_NOT_CONFIGURED": "监管端尚未启用企业报送入口，请联系监管管理员",
    "AUTHENTICATION_FAILED": (
        "运输身份验证失败，请核对监管端签发的客户端编号和 HMAC 凭证"
    ),
    "SUBMISSION_SCOPE_DENIED": "当前企业客户端无权报送该企业或矿井",
    "CONFIRMER_NOT_AUTHORIZED": "确认人姓名、岗位或确认方式未在监管端有效备案",
    "EVENT_SNAPSHOT_NOT_VERIFIED": "本统计窗口的事件代码集合尚未在监管端完成快照登记",
    "PROFILE_NOT_AVAILABLE": "监管端未登记或未启用当前分析配置版本",
    "SOURCE_NOT_REGISTERED": "至少一个观测来源尚未在监管端登记",
    "SOURCE_SIGNATURE_INVALID": (
        "来源网关签名未通过监管端验证，请从来源网关重新获取数据"
    ),
    "GOVERNANCE_REJECTED": (
        "监管端治理配置未接受本次来源、配置版本或数据范围，请按字段提示处理"
    ),
    "GOVERNANCE_CONFIGURATION_REJECTED": (
        "监管端治理配置不完整，请联系监管管理员核对来源和分析配置"
    ),
    "SUBMISSION_TIME_INVALID": (
        "报送时间顺序不合法，请核对统计窗口、接收时间和人工确认时间"
    ),
    "SUBMISSION_VALIDATION_FAILED": "报送内容不符合共享合同，请按字段路径修正",
    "PAYLOAD_INTEGRITY_FAILED": "报送载荷摘要校验失败，请勿手工修改已确认报送包",
    "IDEMPOTENCY_CONFLICT": "该幂等键已绑定其他内容，请刷新草稿状态后处理",
    "SUBMISSION_ID_CONFLICT": "该提交编号已被其他内容使用，请联系系统管理员",
}


def _clean_public_text(value: Any, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        character if character >= " " and character != "\x7f" else " "
        for character in value
    ).strip()
    return cleaned[:maximum] or None


def _platform_http_error(error: HTTPError) -> PlatformError:
    status = int(error.code)
    try:
        raw = error.read(_MAX_ERROR_BODY + 1)
    except (OSError, ValueError):
        raw = b""
    if len(raw) > _MAX_ERROR_BODY:
        raw = b""
    parsed: Any = None
    try:
        parsed = json.loads(raw) if raw else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = None
    if not isinstance(parsed, dict) or parsed.get("contract_version") != (
        "enterprise-submission-error-v1"
    ):
        return PlatformError(
            f"监管平台拒绝请求（HTTP {status}）",
            details={
                "http_status": status,
                "retryable": status == 429 or status >= 500,
            },
        )
    code = parsed.get("code")
    retryable = parsed.get("retryable")
    if (
        not isinstance(code, str)
        or re.fullmatch(r"[A-Z][A-Z0-9_]{2,127}", code) is None
        or not isinstance(retryable, bool)
        or parsed.get("http_status") != status
    ):
        return PlatformError(
            f"监管平台拒绝请求（HTTP {status}）",
            details={
                "http_status": status,
                "retryable": status == 429 or status >= 500,
            },
        )
    violations: list[dict[str, str]] = []
    raw_violations = parsed.get("violations")
    if isinstance(raw_violations, list):
        for item in raw_violations[:_MAX_PUBLIC_VIOLATIONS]:
            if not isinstance(item, dict):
                continue
            pointer = _clean_public_text(item.get("json_pointer"), 512)
            rule = _clean_public_text(item.get("rule"), 128)
            message = _clean_public_text(item.get("message"), 500)
            if pointer is None or not pointer.startswith("/") or message is None:
                continue
            violation = {"json_pointer": pointer, "message": message}
            if rule is not None:
                violation["rule"] = rule
            violations.append(violation)
    remote_message = _clean_public_text(parsed.get("message"), 500)
    hint = _PLATFORM_ERROR_HINTS.get(code)
    summary = hint or remote_message or "监管平台拒绝了报送内容"
    message = f"{summary}（{code}，HTTP {status}）"
    if violations:
        first = violations[0]
        message += f"；{first['json_pointer']}：{first['message']}"
    details: dict[str, Any] = {
        "http_status": status,
        "platform_code": code,
        "retryable": retryable,
        "violations": violations,
    }
    error_id = _clean_public_text(parsed.get("error_id"), 64)
    if error_id is not None:
        details["error_id"] = error_id
    return PlatformError(message, details=details)


@dataclass(frozen=True)
class PlatformClientConfig:
    base_url: str
    submission_path: str = "/v1/enterprise-submissions"
    capabilities_path: str = "/v1/enterprise-submission-capabilities"
    bearer_token: str | None = None
    client_id: str | None = None
    transport_hmac_secret: str | None = None
    timeout_seconds: float = 20.0


class PlatformClient:
    def __init__(
        self,
        config: PlatformClientConfig,
        *,
        opener: Callable[..., Any] = urlopen,
    ):
        if not config.base_url.strip():
            raise ValueError("platform base_url must not be empty")
        if not config.client_id or not config.transport_hmac_secret:
            raise ValueError(
                "platform client_id and transport HMAC secret are required"
            )
        if len(config.transport_hmac_secret.encode("utf-8")) < 32:
            raise ValueError("platform transport HMAC secret must be at least 32 bytes")
        parsed = urlsplit(config.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("platform base_url must be an absolute HTTP URL")
        if parsed.scheme != "https" and parsed.hostname not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            raise ValueError("remote platform connections require HTTPS")
        for label, path in (
            ("submission_path", config.submission_path),
            ("capabilities_path", config.capabilities_path),
        ):
            parsed_path = urlsplit(path)
            if (
                not path.startswith("/")
                or parsed_path.scheme
                or parsed_path.netloc
                or parsed_path.query
                or parsed_path.fragment
                or ".." in parsed_path.path.split("/")
            ):
                raise ValueError(f"platform {label} must be an absolute URL path")
        self.config = config
        self._opener = opener
        self._capabilities_lock = threading.Lock()
        self._capabilities_checked = False
        self._max_body_bytes: int | None = None

    def _headers(
        self,
        *,
        method: str,
        url: str,
        body: bytes,
        idempotency_key: str | None = None,
    ) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "enterprise-reporting-agent/0.1",
        }
        if body:
            headers["Content-Type"] = "application/json; charset=utf-8"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"
        if self.config.transport_hmac_secret:
            if not self.config.client_id:
                raise PlatformError("配置运输 HMAC 时必须同时配置平台客户端编号")
            headers.update(
                transport_headers(
                    method=method,
                    url=url,
                    body=body,
                    secret=self.config.transport_hmac_secret,
                    client_id=self.config.client_id,
                    timestamp=utc_text(),
                    nonce=secrets.token_urlsafe(18),
                )
            )
        return headers

    def _send_json(
        self,
        *,
        method: str,
        url: str,
        body: bytes = b"",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        request = Request(
            url,
            data=body if body else None,
            headers=self._headers(
                method=method,
                url=url,
                body=body,
                idempotency_key=idempotency_key,
            ),
            method=method,
        )
        try:
            with self._opener(request, timeout=self.config.timeout_seconds) as response:
                response_body = response.read(2 * 1024 * 1024 + 1)
                if len(response_body) > 2 * 1024 * 1024:
                    raise PlatformError("监管平台响应超过 2 MiB")
                status = int(getattr(response, "status", 200))
        except HTTPError as error:
            raise _platform_http_error(error) from error
        except (URLError, TimeoutError, OSError) as error:
            raise PlatformError(
                "无法连接监管平台",
                details={
                    "failure_kind": "connection",
                    "retryable": True,
                },
            ) from error
        if status < 200 or status >= 300:
            raise PlatformError(f"监管平台拒绝请求（HTTP {status}）")
        try:
            parsed = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PlatformError(
                "监管平台返回了非法 JSON",
                details={"failure_kind": "protocol", "retryable": False},
            ) from error
        if not isinstance(parsed, dict):
            raise PlatformError(
                "监管平台响应必须是 JSON 对象",
                details={"failure_kind": "protocol", "retryable": False},
            )
        return parsed

    def discover_capabilities(self) -> dict[str, Any]:
        url = urljoin(
            self.config.base_url.rstrip("/") + "/",
            self.config.capabilities_path.lstrip("/"),
        )
        result = self._send_json(method="GET", url=url)
        supported = result.get("supported_submission_contracts")
        selected = None
        if isinstance(supported, list):
            selected = next(
                (
                    item
                    for item in supported
                    if isinstance(item, dict)
                    and item.get("version") == "enterprise-submission-v1"
                    and item.get("status") in {"current", "supported"}
                ),
                None,
            )
        if (
            result.get("contract_version") != "enterprise-submission-capabilities-v1"
            or selected is None
        ):
            raise PlatformError(
                "监管平台未声明支持 enterprise-submission-v1",
                details={"failure_kind": "incompatible", "retryable": False},
            )
        advertised_path = selected.get("submission_path")
        if advertised_path != self.config.submission_path:
            raise PlatformError(
                "监管平台声明的提交路径与企业端配置不一致",
                details={"failure_kind": "incompatible", "retryable": False},
            )
        authentication = result.get("authentication")
        if not isinstance(authentication, dict) or (
            authentication.get("scheme"),
            authentication.get("signature_version"),
        ) != ("hmac-sha256", "hmac-sha256-v1"):
            raise PlatformError(
                "监管平台未声明兼容的运输 HMAC 认证",
                details={"failure_kind": "incompatible", "retryable": False},
            )
        integrity = result.get("integrity_algorithms")
        if not isinstance(integrity, dict) or any(
            integrity.get(name) != expected
            for name, expected in {
                "submission_payload": "sha-256+rfc8785-jcs",
                "transport_body": "sha-256+raw-http-body",
                "observation_signature": (
                    "mineguard-governed-observation-hmac-sha256-v1"
                ),
            }.items()
        ):
            raise PlatformError(
                "监管平台未声明兼容的完整性算法",
                details={"failure_kind": "incompatible", "retryable": False},
            )
        limits = result.get("limits")
        max_body_bytes = (
            limits.get("max_body_bytes") if isinstance(limits, dict) else None
        )
        if (
            not isinstance(max_body_bytes, int)
            or isinstance(max_body_bytes, bool)
            or max_body_bytes < 1024
        ):
            raise PlatformError(
                "监管平台未声明有效的请求体大小限制",
                details={"failure_kind": "incompatible", "retryable": False},
            )
        self._max_body_bytes = max_body_bytes
        return result

    def _ensure_capabilities(self) -> None:
        if self._capabilities_checked:
            return
        with self._capabilities_lock:
            if self._capabilities_checked:
                return
            self.discover_capabilities()
            self._capabilities_checked = True

    def submit(
        self, payload: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        self._ensure_capabilities()
        url = urljoin(
            self.config.base_url.rstrip("/") + "/",
            self.config.submission_path.lstrip("/"),
        )
        body = canonical_json(payload).encode("utf-8")
        if self._max_body_bytes is None:
            raise PlatformError("监管平台能力信息尚未初始化")
        if len(body) > self._max_body_bytes:
            raise PlatformError(
                f"报送包超过监管平台限制（{len(body)} > "
                f"{self._max_body_bytes} 字节）"
            )
        parsed = self._send_json(
            method="POST",
            url=url,
            body=body,
            idempotency_key=idempotency_key,
        )
        checks = {
            "contract_version": "enterprise-submission-receipt-v1",
            "submission_contract_version": "enterprise-submission-v1",
            "submission_id": payload.get("submission_id"),
            "idempotency_key": idempotency_key,
            "payload_sha256": payload.get("payload_sha256"),
            "regulatory_outcome": "not_determined_at_intake",
        }
        if any(parsed.get(key) != value for key, value in checks.items()):
            raise PlatformError("监管平台回执与提交内容不匹配")
        if parsed.get("status") not in {"accepted", "duplicate"}:
            raise PlatformError("监管平台回执状态非法")
        if not isinstance(parsed.get("warnings"), list) or not isinstance(
            parsed.get("links"), dict
        ):
            raise PlatformError("监管平台回执缺少警告或链接字段")
        return parsed
