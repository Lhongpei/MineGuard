"""Independent V2/V3 exchange signing and HTTP transport.

This module deliberately duplicates the neutral wire rules.  It never imports
``contracts`` or regulatory-platform code, so either product can be deployed
and upgraded independently.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import ssl
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .errors import PlatformError
from .util import jcs_json, parse_aware_datetime, sha256_jcs, utc_now, utc_text

MESSAGE_SIGNING_CONTEXT = "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HMAC-SHA256-V2"
MESSAGE_SIGNING_CONTEXT_V3 = "MINEGUARD-TEN-QUANTITY-EXCHANGE-HMAC-SHA256-V3"
HTTP_SIGNING_CONTEXT = "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V2"
HTTP_SIGNING_CONTEXT_V3 = "MINEGUARD-TEN-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V3"
HTTP_SIGNATURE_VERSION = "hmac-sha256-v2"
HTTP_SIGNATURE_VERSION_V3 = "hmac-sha256-v3"
GENERIC_GET_CONTRACT = "five-quantity-exchange-v2"
GENERIC_GET_CONTRACT_V3 = "ten-quantity-exchange-v3"
EMPTY_BODY_SHA256 = hashlib.sha256(b"").hexdigest()
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CURSOR = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


_V3_MESSAGE_CONTRACTS = frozenset(
    {"ten-quantity-submission-v3", "analysis-report-v3"}
)
_V2_MESSAGE_CONTRACTS = frozenset(
    {
        "five-quantity-submission-v2",
        "analysis-report-v2",
        "intake-receipt-v2",
        "risk-delivery-ack-v2",
        "enterprise-risk-response-v2",
        "response-receipt-v2",
    }
)
_V3_HTTP_CONTRACTS = frozenset(
    {"ten-quantity-submission-v3", GENERIC_GET_CONTRACT_V3}
)
_V2_HTTP_CONTRACTS = frozenset(
    {
        "five-quantity-submission-v2",
        "risk-delivery-ack-v2",
        "enterprise-risk-response-v2",
        GENERIC_GET_CONTRACT,
    }
)


def _message_signing_context(contract_version: str) -> str:
    if contract_version in _V3_MESSAGE_CONTRACTS:
        return MESSAGE_SIGNING_CONTEXT_V3
    if contract_version in _V2_MESSAGE_CONTRACTS:
        return MESSAGE_SIGNING_CONTEXT
    raise ValueError("不支持的应用消息签名契约")


def _is_v3_target(request_target: str) -> bool:
    path = request_target.split("?", 1)[0]
    return path == "/v3" or path.startswith("/v3/")


def _http_signing_context(contract_version: str, request_target: str) -> str:
    if _is_v3_target(request_target) and contract_version in (
        _V3_HTTP_CONTRACTS
        | {"risk-delivery-ack-v2", "enterprise-risk-response-v2"}
    ):
        return HTTP_SIGNING_CONTEXT_V3
    if not _is_v3_target(request_target) and contract_version in _V2_HTTP_CONTRACTS:
        return HTTP_SIGNING_CONTEXT
    raise ValueError("不支持的 HTTP 运输签名契约")


def _message_signature_version(contract_version: str) -> str:
    if contract_version in _V3_MESSAGE_CONTRACTS:
        return HTTP_SIGNATURE_VERSION_V3
    if contract_version in _V2_MESSAGE_CONTRACTS:
        return HTTP_SIGNATURE_VERSION
    raise ValueError("不支持的应用消息签名契约")


def _http_signature_version(contract_version: str, request_target: str) -> str:
    if _is_v3_target(request_target) and contract_version in (
        _V3_HTTP_CONTRACTS
        | {"risk-delivery-ack-v2", "enterprise-risk-response-v2"}
    ):
        return HTTP_SIGNATURE_VERSION_V3
    if not _is_v3_target(request_target) and contract_version in _V2_HTTP_CONTRACTS:
        return HTTP_SIGNATURE_VERSION
    raise ValueError("不支持的 HTTP 运输签名契约")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value.strip()) is None:
        raise ValueError(f"{label} 必须是安全的 1-128 字符标识")
    return value.strip()


def _secret(value: str, label: str) -> bytes:
    if not isinstance(value, str) or len(value.encode("utf-8")) < 32:
        raise ValueError(f"{label} 必须至少 32 字节")
    return value.encode("utf-8")


@dataclass(frozen=True)
class MineIdentity:
    mine_id: str
    mine_name: str
    operator_id: str
    operator_name: str
    system_id: str
    regulator_system_id: str
    regulator_party_id: str
    key_id: str
    regulator_key_id: str
    message_hmac_secret: str
    previous_regulator_key_id: str | None = None
    previous_message_hmac_secret: str | None = None
    timezone: str = "Asia/Shanghai"
    capacity_band: str = "unclassified"
    mining_method: str = "unclassified"
    shift_system: str = "three-shift-eight-hour"
    coal_type: str = "unclassified"
    operating_regime: str = "normal-production"

    def __post_init__(self) -> None:
        for field in (
            "mine_id",
            "operator_id",
            "system_id",
            "regulator_system_id",
            "regulator_party_id",
            "key_id",
            "regulator_key_id",
        ):
            _identifier(getattr(self, field), field)
        for field in ("mine_name", "operator_name"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{field} 必须是 1-256 字符")
        _secret(self.message_hmac_secret, "message_hmac_secret")
        if (self.previous_regulator_key_id is None) != (
            self.previous_message_hmac_secret is None
        ):
            raise ValueError("上一把政府验签 key_id 和 secret 必须同时配置")
        if self.previous_regulator_key_id is not None:
            _identifier(self.previous_regulator_key_id, "previous_regulator_key_id")
            assert self.previous_message_hmac_secret is not None
            _secret(
                self.previous_message_hmac_secret,
                "previous_message_hmac_secret",
            )
        if not isinstance(self.timezone, str) or not self.timezone.strip():
            raise ValueError("timezone 不能为空")
        for field in (
            "capacity_band",
            "mining_method",
            "shift_system",
            "coal_type",
            "operating_regime",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip() or len(value) > 64:
                raise ValueError(f"{field} 必须是 1-64 字符")

    @property
    def comparison_context(self) -> dict[str, str]:
        return {
            "capacity_band": self.capacity_band,
            "mining_method": self.mining_method,
            "shift_system": self.shift_system,
            "coal_type": self.coal_type,
            "operating_regime": self.operating_regime,
        }

    @property
    def mine(self) -> dict[str, str]:
        return {
            "mine_id": self.mine_id,
            "mine_name": self.mine_name,
            "operator_id": self.operator_id,
            "operator_name": self.operator_name,
        }


@dataclass(frozen=True)
class FiveQuantityPlatformConfig:
    base_url: str
    sender_id: str
    transport_hmac_secret: str
    timeout_seconds: float = 20.0
    submission_path: str = "/v3/ten-quantity-submissions"
    next_report_path: str = "/v3/analysis-reports/next"
    legacy_submission_path: str = "/v2/five-quantity-submissions"
    legacy_analysis_path: str = "/v2/analysis-reports"
    analysis_path: str = "/v3/analysis-reports"
    ca_bundle_path: str | None = None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        try:
            _ = parsed.port
        except ValueError as error:
            raise ValueError("V2 platform base_url 端口非法") from error
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("V2 platform base_url 必须是绝对 HTTP(S) URL")
        if parsed.scheme != "https" and parsed.hostname not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            raise ValueError("远程监管平台必须使用 HTTPS")
        _identifier(self.sender_id, "sender_id")
        _secret(self.transport_hmac_secret, "transport_hmac_secret")
        if not 1 <= self.timeout_seconds <= 120:
            raise ValueError("timeout_seconds 必须在 1-120 秒")
        for name in (
            "submission_path",
            "next_report_path",
            "legacy_submission_path",
            "legacy_analysis_path",
            "analysis_path",
        ):
            path = getattr(self, name)
            parsed_path = urlsplit(path)
            if (
                not path.startswith("/")
                or parsed_path.scheme
                or parsed_path.netloc
                or parsed_path.query
                or parsed_path.fragment
                or ".." in parsed_path.path.split("/")
            ):
                raise ValueError(f"{name} 必须是安全的绝对 URL path")
        if self.ca_bundle_path is not None:
            bundle = Path(self.ca_bundle_path).expanduser()
            if bundle.is_symlink() or not bundle.is_file():
                raise ValueError(
                    "PLATFORM_V2_CA_BUNDLE 必须是普通 CA 文件且不能是符号链接"
                )
            if parsed.scheme != "https":
                raise ValueError("自定义 CA 只适用于 HTTPS 监管地址")


class _RejectRedirects(HTTPRedirectHandler):
    """Never replay a signed request at a redirect-selected target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _message_material(message: dict[str, Any], payload_hash: str) -> bytes:
    signature = message["signature_envelope"]
    predecessor = message.get("predecessor") or {}
    lines = [
        _message_signing_context(str(message["contract_version"])),
        str(message["contract_version"]),
        str(message["message_type"]),
        str(message["message_id"]),
        str(message["correlation_id"]),
        str(message.get("causation_id") or ""),
        str(message["idempotency_key"]),
        str(message["revision"]),
        str(predecessor.get("message_id", "")),
        str(predecessor.get("payload_sha256", "")),
        str(message["created_at"]),
        str(message["sender"]["system_id"]),
        str(message["sender"]["party_id"]),
        str(message["sender"]["role"]),
        str(message["recipient"]["system_id"]),
        str(message["recipient"]["party_id"]),
        str(message["recipient"]["role"]),
        str(message["mine_id"]),
        str(signature["algorithm"]),
        str(signature["canonicalization"]),
        str(signature["key_id"]),
        str(signature["signed_at"]),
        str(signature["nonce"]),
        payload_hash,
    ]
    return "\n".join(lines).encode("utf-8")


def sign_message(message: dict[str, Any], *, secret: str) -> dict[str, Any]:
    """Fill the payload digest and HMAC in the contract's exact signing domain."""

    contract_version = str(message.get("contract_version", ""))
    expected_algorithm = _message_signature_version(contract_version)
    envelope = message["signature_envelope"]
    if envelope.get("algorithm") != expected_algorithm:
        raise ValueError("应用消息签名算法与 contract_version 不匹配")
    payload_hash = sha256_jcs(message["payload"])
    envelope["payload_sha256"] = payload_hash
    envelope["signature"] = hmac.new(
        _secret(secret, "message secret"),
        _message_material(message, payload_hash),
        hashlib.sha256,
    ).hexdigest()
    return message


def verify_message(
    message: dict[str, Any],
    *,
    secret: str,
    identity: MineIdentity,
    expected_contract: str,
    expected_type: str,
    maximum_clock_skew_seconds: int = 600,
) -> None:
    """Fail closed on application signature, identity and recipient binding."""

    if not isinstance(message, dict):
        raise PlatformError("监管平台消息必须是 JSON 对象")
    required = {
        "contract_version",
        "message_type",
        "message_id",
        "correlation_id",
        "causation_id",
        "idempotency_key",
        "revision",
        "predecessor",
        "created_at",
        "sender",
        "recipient",
        "mine_id",
        "payload",
        "signature_envelope",
    }
    if set(message) != required:
        raise PlatformError("监管平台消息信封字段不完整或包含未知字段")
    if (
        message.get("contract_version") != expected_contract
        or message.get("message_type") != expected_type
    ):
        raise PlatformError("监管平台消息契约或类型不匹配")
    if message.get("mine_id") != identity.mine_id:
        raise PlatformError("监管平台消息不属于本煤矿")
    sender = message.get("sender")
    recipient = message.get("recipient")
    if not isinstance(sender, dict) or not isinstance(recipient, dict):
        raise PlatformError("监管平台消息参与方非法")
    if (
        sender.get("system_id") != identity.regulator_system_id
        or sender.get("party_id") != identity.regulator_party_id
        or sender.get("role") != "regulatory_platform"
        or recipient.get("system_id") != identity.system_id
        or recipient.get("party_id") != identity.operator_id
        or recipient.get("role") != "enterprise_agent"
    ):
        raise PlatformError("监管平台消息参与方与启动配置不匹配")
    signature = message.get("signature_envelope")
    if not isinstance(signature, dict) or set(signature) != {
        "algorithm",
        "canonicalization",
        "key_id",
        "signed_at",
        "nonce",
        "payload_sha256",
        "signature",
    }:
        raise PlatformError("监管平台消息签名信封非法")
    try:
        expected_signature_version = _message_signature_version(expected_contract)
    except ValueError as error:
        raise PlatformError("监管平台消息契约没有已登记签名域") from error
    if (
        signature.get("algorithm") != expected_signature_version
        or signature.get("canonicalization") != "rfc8785-jcs"
    ):
        raise PlatformError("监管平台消息签名算法或密钥编号不匹配")
    declared_hash = signature.get("payload_sha256")
    if not isinstance(declared_hash, str) or _HEX_64.fullmatch(declared_hash) is None:
        raise PlatformError("监管平台消息 payload 摘要非法")
    actual_hash = sha256_jcs(message.get("payload"))
    if not hmac.compare_digest(declared_hash, actual_hash):
        raise PlatformError("监管平台消息 payload 摘要不匹配")
    provided = signature.get("signature")
    candidates: list[str] = []
    if signature.get("key_id") == identity.regulator_key_id:
        candidates.append(secret)
    if (
        identity.previous_regulator_key_id is not None
        and signature.get("key_id") == identity.previous_regulator_key_id
    ):
        assert identity.previous_message_hmac_secret is not None
        candidates.append(identity.previous_message_hmac_secret)
    material = _message_material(message, actual_hash)
    verified = isinstance(provided, str) and any(
        hmac.compare_digest(
            provided,
            hmac.new(
                _secret(candidate, "message secret"), material, hashlib.sha256
            ).hexdigest(),
        )
        for candidate in candidates
    )
    if not verified:
        raise PlatformError("监管平台消息应用签名验证失败")
    signed_at = parse_aware_datetime(signature.get("signed_at"), "signed_at")
    # A signed report can legitimately wait in the government outbox longer
    # than the HTTP anti-replay window.  Reject impossible future timestamps;
    # transport HMAC independently enforces freshness of the current request.
    if signed_at > utc_now() + timedelta(seconds=maximum_clock_skew_seconds):
        raise PlatformError("监管平台消息签名时间来自未来")


def http_transport_headers(
    *,
    method: str,
    url: str,
    body: bytes,
    sender_id: str,
    secret: str,
    contract_version: str,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    parsed = urlsplit(url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    body_hash = hashlib.sha256(body).hexdigest()
    signed_at = timestamp or utc_text()
    token = nonce or secrets.token_urlsafe(18)
    lines = [
        _http_signing_context(contract_version, target),
        method.upper(),
        target,
        _identifier(sender_id, "sender_id"),
        signed_at,
        token,
        contract_version,
        body_hash,
    ]
    signature = hmac.new(
        _secret(secret, "transport secret"),
        "\n".join(lines).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Exchange-Sender-Id": sender_id,
        "X-Exchange-Timestamp": signed_at,
        "X-Exchange-Nonce": token,
        "X-Exchange-Contract-Version": contract_version,
        "X-Exchange-Signature-Version": _http_signature_version(
            contract_version, target
        ),
        "X-Exchange-Content-SHA256": body_hash,
        "X-Exchange-Signature": signature,
    }


class FiveQuantityPlatformClient:
    def __init__(self, config: FiveQuantityPlatformConfig, *, opener=None):
        self.config = config
        if opener is None:
            context = ssl.create_default_context(cafile=config.ca_bundle_path)
            self._opener = build_opener(
                _RejectRedirects(),
                HTTPSHandler(context=context),
            ).open
        else:
            self._opener = opener

    def _url(self, path: str, query: dict[str, str] | None = None) -> str:
        url = urljoin(self.config.base_url.rstrip("/") + "/", path.lstrip("/"))
        if query:
            url += "?" + urlencode(query, safe=".:-")
        return url

    def _request(
        self,
        *,
        method: str,
        path: str,
        contract_version: str,
        message: dict[str, Any] | None = None,
        query: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        url = self._url(path, query)
        body = jcs_json(message).encode("utf-8") if message is not None else b""
        headers = {
            "Accept": "application/json",
            "User-Agent": "enterprise-reporting-agent/0.3",
            **http_transport_headers(
                method=method,
                url=url,
                body=body,
                sender_id=self.config.sender_id,
                secret=self.config.transport_hmac_secret,
                contract_version=contract_version,
            ),
        }
        if body:
            headers["Content-Type"] = "application/json; charset=utf-8"
        request = Request(
            url,
            data=body if body else None,
            headers=headers,
            method=method,
        )
        try:
            with self._opener(request, timeout=self.config.timeout_seconds) as response:
                status = int(getattr(response, "status", 200))
                final_url = response.geturl() if hasattr(response, "geturl") else url
                if final_url != url:
                    raise PlatformError("监管平台 V2 响应发生重定向，已拒绝")
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            retryable = error.code in {408, 425, 429, 500, 502, 503, 504}
            raise PlatformError(
                f"监管平台拒绝 V2 请求（HTTP {error.code}）",
                details={"retryable": retryable, "http_status": error.code},
            ) from error
        except (URLError, TimeoutError, OSError) as error:
            raise PlatformError(
                "无法连接监管平台 V2 接口",
                details={"retryable": True, "failure_kind": "connection"},
            ) from error
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise PlatformError("监管平台 V2 响应超过 4 MiB")
        if status == 204:
            if raw:
                raise PlatformError("HTTP 204 不得包含响应体")
            return None
        if not 200 <= status < 300:
            raise PlatformError(f"监管平台拒绝 V2 请求（HTTP {status}）")
        try:
            parsed = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PlatformError("监管平台 V2 返回非法 JSON") from error
        if not isinstance(parsed, dict):
            raise PlatformError("监管平台 V2 响应必须是 JSON 对象")
        return parsed

    def submit(self, message: dict[str, Any]) -> dict[str, Any]:
        contract_version = str(message.get("contract_version", ""))
        if contract_version == "ten-quantity-submission-v3":
            path = self.config.submission_path
        elif contract_version == "five-quantity-submission-v2":
            # Only already-queued, immutable V2 messages use this compatibility
            # route. New Agent drafts are always V3.
            path = self.config.legacy_submission_path
        else:
            raise PlatformError("待发送报送消息契约不受支持")
        result = self._request(
            method="POST",
            path=path,
            contract_version=contract_version,
            message=message,
        )
        if result is None:
            raise PlatformError("监管平台提交接口未返回接收回执")
        return result

    def submission_receipt(
        self,
        message_id: str,
        *,
        submission_contract: str = "ten-quantity-submission-v3",
    ) -> dict[str, Any]:
        """Read a previously-issued intake receipt without changing state."""

        message_id = _identifier(message_id, "message_id")
        if submission_contract == "ten-quantity-submission-v3":
            base_path = self.config.submission_path
            transport_contract = GENERIC_GET_CONTRACT_V3
        elif submission_contract == "five-quantity-submission-v2":
            base_path = self.config.legacy_submission_path
            transport_contract = GENERIC_GET_CONTRACT
        else:
            raise ValueError("submission_contract 不受支持")
        result = self._request(
            method="GET",
            path=f"{base_path.rstrip('/')}/{message_id}/receipt",
            contract_version=transport_contract,
        )
        if result is None:
            raise PlatformError("监管平台未找到报送接收回执")
        return result

    def pull_next(
        self,
        *,
        after_cursor: str | None = None,
        legacy: bool = False,
    ) -> dict[str, Any] | None:
        query = None
        if after_cursor is not None:
            if _SAFE_CURSOR.fullmatch(after_cursor) is None:
                raise ValueError("风险游标格式非法")
            query = {"after_cursor": after_cursor}
        return self._request(
            method="GET",
            path=(
                f"{self.config.legacy_analysis_path.rstrip('/')}/next"
                if legacy
                else self.config.next_report_path
            ),
            contract_version=(
                GENERIC_GET_CONTRACT if legacy else GENERIC_GET_CONTRACT_V3
            ),
            query=query,
        )

    def analysis_report(
        self, report_id: str, *, legacy: bool = False
    ) -> dict[str, Any]:
        """Read one analysis report by its logical report identifier."""

        report_id = _identifier(report_id, "report_id")
        result = self._request(
            method="GET",
            path=(
                f"{self.config.legacy_analysis_path.rstrip('/')}/{report_id}"
                if legacy
                else f"{self.config.analysis_path.rstrip('/')}/{report_id}"
            ),
            contract_version=(
                GENERIC_GET_CONTRACT if legacy else GENERIC_GET_CONTRACT_V3
            ),
        )
        if result is None:
            raise PlatformError("监管平台未找到算法报告")
        return result

    def acknowledge(
        self,
        report_id: str,
        message: dict[str, Any],
        *,
        legacy: bool = False,
    ) -> None:
        if not isinstance(report_id, str) or _IDENTIFIER.fullmatch(report_id) is None:
            raise ValueError("report_id 格式非法")
        result = self._request(
            method="POST",
            path=(
                f"{self.config.legacy_analysis_path.rstrip('/')}/{report_id}/delivery-ack"
                if legacy
                else f"{self.config.analysis_path.rstrip('/')}/{report_id}/delivery-ack"
            ),
            # POST transport binding follows the signed body contract.  The
            # V3 URL namespace does not turn a V2 lifecycle acknowledgement
            # into a different application message.
            contract_version=str(message.get("contract_version", "")),
            message=message,
        )
        if result is not None:
            raise PlatformError("风险投递确认接口应返回 HTTP 204")

    def respond(
        self,
        report_id: str,
        message: dict[str, Any],
        *,
        legacy: bool = False,
    ) -> dict[str, Any]:
        result = self._request(
            method="POST",
            path=(
                f"{self.config.legacy_analysis_path.rstrip('/')}/{report_id}/responses"
                if legacy
                else f"{self.config.analysis_path.rstrip('/')}/{report_id}/responses"
            ),
            contract_version=str(message.get("contract_version", "")),
            message=message,
        )
        if result is None:
            raise PlatformError("监管平台回复接口未返回回执")
        return result

    def response_receipt(
        self, response_id: str, *, legacy: bool = False
    ) -> dict[str, Any]:
        """Read a previously-issued enterprise-response receipt."""

        response_id = _identifier(response_id, "response_id")
        result = self._request(
            method="GET",
            path=(
                f"/v2/risk-responses/{response_id}/receipt"
                if legacy
                else f"/v3/risk-responses/{response_id}/receipt"
            ),
            contract_version=(
                GENERIC_GET_CONTRACT if legacy else GENERIC_GET_CONTRACT_V3
            ),
        )
        if result is None:
            raise PlatformError("监管平台未找到风险回复回执")
        return result
