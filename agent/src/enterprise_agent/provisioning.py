"""Agent-side import and runtime enforcement for signed per-mine bundles.

This module implements the V1 protocol published in ``contracts`` without
importing Platform code.  The generic Agent executable receives one opaque
``.mgprov`` file.  Import binds the embedded Ed25519 issuer key metadata,
verifies the signature before
decrypting, validates the sealed enterprise identity and government HTTPS
endpoint, and moves HMAC material into a protected local secret store.  The
generated ``agent.env`` contains no bilateral secret.  The enterprise UI
remains loopback-only and outbound HTTPS uses the operating system trust store.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import sys
import threading
import unicodedata
from collections.abc import Mapping, MutableMapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .auth import parse_users_json, production_credential_errors
from .environment import parse_environment_file
from .util import canonical_json, utc_text

CONTRACT_VERSION = "mineguard-provisioning-bundle-v1"
ACCESS_PACKAGE_FORMAT = "mineguard-enterprise-access-package-v1"
BUNDLE_KIND = "enterprise-agent-provisioning"
LOCK_FORMAT = "mineguard-enterprise-provisioning-lock-v1"
SECRET_STORE_FORMAT = "mineguard-enterprise-secret-store-v1"
DPAPI_PROTECTION = "dpapi-local-machine-v1"
POSIX_PROTECTION = "posix-mode-0600-plaintext-json-v1"

_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_PROFILE_VERSION = 2_147_483_647
_SCRYPT_N = 16_384
_SCRYPT_R = 8
_SCRYPT_P = 1
_LOCK_MAC_CONTEXT = b"MINEGUARD-ENTERPRISE-PROVISIONING-LOCK-V1\x00"
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/](?![\\/]).+")
_ACTIVATION_CODE = re.compile(rb"[A-Za-z0-9_-]{43}\Z")
_SECRET_PLACEHOLDERS = (
    "demo",
    "example",
    "sample",
    "placeholder",
    "replace",
    "replace-me",
    "replace_me",
    "change-me",
    "change-",
    "change_before",
    "not-configured",
    "not_configured",
    "default-secret",
    "default_secret",
    "test-only",
    "test_only",
    "待替换",
    "示例",
    "演示",
    "测试",
)
_PLACEHOLDER_TOKENS = frozenset(
    {
        "change",
        "demo",
        "example",
        "placeholder",
        "replace",
        "sample",
        "synthetic",
        "test",
        "unknown",
        "unclassified",
        "待填写",
        "待配置",
        "未分类",
        "未知",
        "示例",
        "测试",
    }
)

_ENVELOPE_FIELDS = {"protected", "ciphertext", "signature"}
_ACCESS_PACKAGE_FIELDS = {
    "format",
    "agent_bundle",
    "activation_code",
    "issuer_public_key_pem",
    "issuer_public_key_sha256",
    "issuer_key_id",
}
_PROTECTED_FIELDS = {
    "contract_version",
    "bundle_kind",
    "bundle_id",
    "pair_id",
    "profile_version",
    "issued_at",
    "expires_at",
    "issuer_id",
    "issuer_key_id",
    "subject",
    "payload_sha256",
    "locked_config_sha256",
    "locked_keys",
    "encryption",
}
_ENCRYPTION_FIELDS = {"algorithm", "kdf", "salt", "n", "r", "p", "nonce"}
_SUBJECT_FIELDS = {"mine_id", "system_id", "party_id"}
_PAYLOAD_FIELDS = {
    "kind",
    "bundle_id",
    "pair_id",
    "profile_version",
    "config",
    "locked_keys",
}
_REQUIRED_CONFIG_KEYS = {
    "ENTERPRISE_AGENT_FOUR_EYES_REQUIRED",
    "ENTERPRISE_AGENT_PRODUCTION_MODE",
    "ENTERPRISE_AGENT_SECURE_COOKIE",
    "ENTERPRISE_CAPACITY_BAND",
    "ENTERPRISE_COAL_TYPE",
    "ENTERPRISE_EXCHANGE_HMAC_SECRET",
    "ENTERPRISE_EXCHANGE_KEY_ID",
    "ENTERPRISE_MINE_ID",
    "ENTERPRISE_MINE_NAME",
    "ENTERPRISE_MINING_METHOD",
    "ENTERPRISE_OPERATING_REGIME",
    "ENTERPRISE_OPERATOR_ID",
    "ENTERPRISE_OPERATOR_NAME",
    "ENTERPRISE_REPORTING_TIMEZONE",
    "ENTERPRISE_SHIFT_SYSTEM",
    "ENTERPRISE_SYSTEM_ID",
    "PLATFORM_V3_BASE_URL",
    "PLATFORM_V3_SENDER_ID",
    "PLATFORM_V3_TRANSPORT_HMAC_SECRET",
    "REGULATORY_EXCHANGE_KEY_ID",
    "REGULATORY_PARTY_ID",
    "REGULATORY_SYSTEM_ID",
}
_OPTIONAL_CONFIG_KEYS = {
    "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
    "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET",
    "REGULATORY_PREVIOUS_EXCHANGE_KEY_ID",
}
_ALLOWED_CONFIG_KEYS = _REQUIRED_CONFIG_KEYS | _OPTIONAL_CONFIG_KEYS
_SECRET_CONFIG_KEYS = {
    "ENTERPRISE_EXCHANGE_HMAC_SECRET",
    "PLATFORM_V3_TRANSPORT_HMAC_SECRET",
    "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
    "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET",
}
_DERIVED_LOCKED_ENVIRONMENT = {
    "ENTERPRISE_AGENT_HOST": "127.0.0.1",
    "ENTERPRISE_AGENT_ALLOW_ANONYMOUS_LOCAL": "false",
    "ENTERPRISE_PROVISIONING_MANAGED_REQUIRED": "true",
    "PLATFORM_V3_SUBMISSION_PATH": "/v3/ten-quantity-submissions",
    "PLATFORM_V3_NEXT_REPORT_PATH": "/v3/analysis-reports/next",
    "PLATFORM_V3_ANALYSIS_PATH": "/v3/analysis-reports",
}
_FORBIDDEN_PROVISIONED_ENDPOINT_ALIASES = {
    "PLATFORM_BASE_URL",
    "PLATFORM_CLIENT_ID",
    "PLATFORM_TRANSPORT_HMAC_SECRET",
    "PLATFORM_BEARER_TOKEN",
    "PLATFORM_SUBMISSION_PATH",
    "PLATFORM_CAPABILITIES_PATH",
    "PLATFORM_V2_BASE_URL",
    "PLATFORM_V2_SENDER_ID",
    "PLATFORM_V2_TRANSPORT_HMAC_SECRET",
    "PLATFORM_V2_SUBMISSION_PATH",
    "PLATFORM_V2_CA_BUNDLE",
}
_PROCESS_OVERLAY_LOCK = threading.Lock()
_PROCESS_APPLIED_SECRETS: dict[str, str] = {}


class ProvisioningError(ValueError):
    """Non-secret-bearing provisioning failure."""


@dataclass(frozen=True)
class VerifiedBundle:
    envelope: dict[str, Any]
    payload: dict[str, Any]
    config: dict[str, str]
    public_key_pem: str
    public_key_sha256: str


@dataclass(frozen=True)
class ProvisioningResult:
    summary: dict[str, Any]


@dataclass(frozen=True)
class ProvisioningStatus:
    managed: bool
    bundle_id: str | None = None
    pair_id: str | None = None
    profile_version: int | None = None
    mine_id: str | None = None
    public_key_sha256: str | None = None
    secret_protection: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "managed": self.managed,
            "bundle_id": self.bundle_id,
            "pair_id": self.pair_id,
            "profile_version": self.profile_version,
            "mine_id": self.mine_id,
            "public_key_sha256": self.public_key_sha256,
            "secret_protection": self.secret_protection,
        }


def _canonical_bytes(value: Any) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as error:
        raise ProvisioningError("provisioning JSON 无法规范化") from error


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ProvisioningError(f"{label} 字段不完整或包含未知字段")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProvisioningError(f"{label} 不是有效标识")
    return value


def _contains_control(value: str) -> bool:
    return any(
        ord(character) < 32
        or 127 <= ord(character) <= 159
        or unicodedata.category(character) in {"Cc", "Cs"}
        for character in value
    )


def _looks_placeholder(value: str) -> bool:
    folded = value.strip().casefold()
    ascii_tokens = {token for token in re.split(r"[^a-z0-9]+", folded) if token}
    if ascii_tokens & {token for token in _PLACEHOLDER_TOKENS if token.isascii()}:
        return True
    return any(
        marker in folded for marker in _PLACEHOLDER_TOKENS if not marker.isascii()
    )


def _production_identifier(value: Any, label: str) -> str:
    selected = _identifier(value, label)
    if _looks_placeholder(selected):
        raise ProvisioningError(f"{label} 不得使用生产占位标识")
    return selected


def _display(value: Any, label: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or _contains_control(value)
    ):
        raise ProvisioningError(f"{label} 必须是 1-{maximum} 个有效字符")
    return value


def _production_display(value: Any, label: str, maximum: int = 256) -> str:
    selected = _display(value, label, maximum)
    if _looks_placeholder(selected):
        raise ProvisioningError(f"{label} 不得使用生产占位值")
    return selected


def _canonical_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProvisioningError(f"{label} 必须是 UUID")
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise ProvisioningError(f"{label} 必须是 UUID") from error
    if str(parsed) != value:
        raise ProvisioningError(f"{label} 必须是小写连字符规范 UUID")
    return value


def _parse_time(value: Any, label: str) -> datetime:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
            r"[0-9]{2}(?:\.[0-9]{1,6})?Z",
            value,
        )
        is None
    ):
        raise ProvisioningError(f"{label} 必须是 UTC RFC3339 Z 时间")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProvisioningError(f"{label} 必须是 UTC RFC3339 Z 时间") from error
    return parsed.astimezone(UTC)


def _https_origin(value: Any, label: str) -> str:
    selected = _display(value, label, maximum=2048)
    if "%" in selected or any(character.isspace() for character in selected):
        raise ProvisioningError(f"{label} 不能包含空白或百分号编码")
    try:
        parsed = urlsplit(selected)
        port = parsed.port
    except ValueError as error:
        raise ProvisioningError(f"{label} 端口或主机格式非法") from error
    if port is not None and not 1 <= port <= 65_535:
        raise ProvisioningError(f"{label} 端口必须为 1-65535")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ProvisioningError(f"{label} 必须是无路径和账号信息的 HTTPS origin")
    hostname = parsed.hostname.lower()
    if hostname in {
        "localhost",
        "example",
        "invalid",
        "test",
        "example.com",
        "example.net",
        "example.org",
    } or hostname.endswith(
        (
            ".localhost",
            ".example",
            ".invalid",
            ".test",
            ".example.com",
            ".example.net",
            ".example.org",
        )
    ):
        raise ProvisioningError(f"{label} 不能使用回环、保留或示例主机")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        if (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
        ):
            raise ProvisioningError(f"{label} 不能使用回环或不可路由特殊地址")
    host = f"[{hostname}]" if ":" in hostname else hostname
    normalized = f"https://{host}" if port in {None, 443} else f"https://{host}:{port}"
    if selected.rstrip("/") != normalized:
        raise ProvisioningError(f"{label} 必须使用规范 HTTPS origin")
    return normalized


def _absolute_path(value: Any, label: str, *, maximum: int = 4096) -> str:
    selected = _display(value, label, maximum=maximum)
    if (
        not Path(selected).is_absolute()
        and _WINDOWS_ABSOLUTE.fullmatch(selected) is None
    ):
        raise ProvisioningError(f"{label} 必须是绝对路径")
    if any(part in {".", ".."} for part in re.split(r"[\\/]", selected)):
        raise ProvisioningError(f"{label} 包含不安全路径片段")
    return selected


def _b64url(value: Any, label: str, length: int | None = None) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise ProvisioningError(f"{label} 必须是无 padding 的 Base64URL")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ProvisioningError(f"{label} 必须是无 padding 的 Base64URL") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ProvisioningError(f"{label} 不是规范 Base64URL")
    if length is not None and len(decoded) != length:
        raise ProvisioningError(f"{label} 长度非法")
    return decoded


def _json_bytes(encoded: bytes, label: str) -> dict[str, Any]:
    if len(encoded) > _MAX_JSON_BYTES:
        raise ProvisioningError(f"{label} 超过 4 MiB")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ProvisioningError(f"{label} 包含重复字段 {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            encoded.decode("utf-8-sig"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ProvisioningError(f"{label} 包含非有限数值 {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisioningError(f"{label} 必须是 UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ProvisioningError(f"{label} 顶层必须是对象")
    return value


def _is_link_or_reparse(path: Path) -> bool:
    metadata = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    is_junction = getattr(path, "is_junction", None)
    return bool(
        path.is_symlink()
        or (callable(is_junction) and is_junction())
        or (reparse_flag and attributes & reparse_flag)
    )


def _read_regular(path: str | Path, label: str) -> tuple[Path, bytes]:
    requested = Path(path).expanduser()
    if not requested.is_absolute():
        raise ProvisioningError(f"{label} 必须使用绝对路径")
    for candidate in (requested, *requested.parents):
        if candidate.exists() and _is_link_or_reparse(candidate):
            raise ProvisioningError(f"{label} 路径不能包含链接或重解析点")
    try:
        before = requested.lstat()
    except OSError as error:
        raise ProvisioningError(f"{label} 无法读取：{requested}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_JSON_BYTES:
        raise ProvisioningError(f"{label} 必须是小于 4 MiB 的普通文件")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(requested, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size > _MAX_JSON_BYTES
        ):
            raise ProvisioningError(f"{label} 在读取前发生变化")
        chunks: list[bytes] = []
        remaining = _MAX_JSON_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > _MAX_JSON_BYTES:
            raise ProvisioningError(f"{label} 超过 4 MiB")
        return requested.resolve(), content
    finally:
        os.close(descriptor)


def _public_key(encoded: bytes) -> tuple[Ed25519PublicKey, str, str]:
    try:
        key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError) as error:
        raise ProvisioningError("签发公钥不是有效 PEM") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ProvisioningError("签发公钥必须是 Ed25519")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return key, pem, _sha256(der)


def _validate_envelope(
    document: Any,
    public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    envelope = _strict_object(document, _ENVELOPE_FIELDS, "接入包")
    protected = _strict_object(
        envelope["protected"], _PROTECTED_FIELDS, "接入包 protected"
    )
    if protected["contract_version"] != CONTRACT_VERSION:
        raise ProvisioningError("接入包 contract_version 不受支持")
    if protected["bundle_kind"] != BUNDLE_KIND:
        raise ProvisioningError("接入包不是企业 Agent 接入包")
    _canonical_uuid(protected["bundle_id"], "protected.bundle_id")
    _canonical_uuid(protected["pair_id"], "protected.pair_id")
    version = protected["profile_version"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or not 1 <= version <= _MAX_PROFILE_VERSION
    ):
        raise ProvisioningError("protected.profile_version 非法")
    issued_at = _parse_time(protected["issued_at"], "protected.issued_at")
    expires_at = _parse_time(protected["expires_at"], "protected.expires_at")
    if issued_at >= expires_at:
        raise ProvisioningError("接入包签发时间与安装截止时间顺序非法")
    _production_identifier(protected["issuer_id"], "protected.issuer_id")
    _production_identifier(protected["issuer_key_id"], "protected.issuer_key_id")
    subject = _strict_object(protected["subject"], _SUBJECT_FIELDS, "protected.subject")
    for name, value in subject.items():
        _production_identifier(value, f"protected.subject.{name}")
    for name in ("payload_sha256", "locked_config_sha256"):
        if (
            not isinstance(protected[name], str)
            or _HEX_64.fullmatch(protected[name]) is None
        ):
            raise ProvisioningError(f"protected.{name} 必须是小写 SHA-256")
    locked_keys = protected["locked_keys"]
    if not isinstance(locked_keys, list) or any(
        not isinstance(key, str) for key in locked_keys
    ):
        raise ProvisioningError("protected.locked_keys 非法")
    if locked_keys != sorted(set(locked_keys)):
        raise ProvisioningError("protected.locked_keys 非法")
    if any(key not in _ALLOWED_CONFIG_KEYS for key in locked_keys):
        raise ProvisioningError("protected.locked_keys 包含未知字段")
    encryption = _strict_object(
        protected["encryption"], _ENCRYPTION_FIELDS, "protected.encryption"
    )
    if (
        encryption["algorithm"] != "aes-256-gcm"
        or encryption["kdf"] != "scrypt"
        or type(encryption["n"]) is not int
        or type(encryption["r"]) is not int
        or type(encryption["p"]) is not int
        or encryption["n"] != _SCRYPT_N
        or encryption["r"] != _SCRYPT_R
        or encryption["p"] != _SCRYPT_P
    ):
        raise ProvisioningError("接入包加密参数不受支持")
    _b64url(encryption["salt"], "encryption.salt", 16)
    _b64url(encryption["nonce"], "encryption.nonce", 12)
    if len(_b64url(envelope["ciphertext"], "ciphertext")) < 17:
        raise ProvisioningError("接入包 ciphertext 长度非法")
    signature = _b64url(envelope["signature"], "signature", 64)
    signed = {"protected": protected, "ciphertext": envelope["ciphertext"]}
    try:
        public_key.verify(signature, _canonical_bytes(signed))
    except InvalidSignature as error:
        raise ProvisioningError("接入包 Ed25519 签名验证失败") from error
    return envelope


def _validate_historical_keyring(raw: str) -> list[tuple[str, str]]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ProvisioningError("历史企业验签密钥环包含重复字段")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ProvisioningError(f"历史企业验签密钥环包含非有限数值 {token}")
            ),
        )
    except json.JSONDecodeError as error:
        raise ProvisioningError("历史企业验签密钥环不是有效 JSON") from error
    if not isinstance(parsed, list) or len(parsed) > 64:
        raise ProvisioningError("历史企业验签密钥环必须是最多 64 项的数组")
    seen_ids: set[str] = set()
    seen_secrets: set[str] = set()
    result: list[tuple[str, str]] = []
    for item in parsed:
        if not isinstance(item, dict) or set(item) != {"key_id", "secret"}:
            raise ProvisioningError("历史企业验签密钥环条目非法")
        key_id = _production_identifier(item["key_id"], "历史 key_id")
        secret = _display(item["secret"], "历史 secret", 512)
        if (
            len(secret.encode()) < 32
            or key_id in seen_ids
            or secret in seen_secrets
            or any(marker in secret.casefold() for marker in _SECRET_PLACEHOLDERS)
        ):
            raise ProvisioningError("历史企业验签密钥环存在短密钥、占位值或重复项")
        seen_ids.add(key_id)
        seen_secrets.add(secret)
        result.append((key_id, secret))
    return result


def _validate_config(config: Any, protected: Mapping[str, Any]) -> dict[str, str]:
    if (
        not isinstance(config, dict)
        or not _REQUIRED_CONFIG_KEYS.issubset(config)
        or not set(config).issubset(_ALLOWED_CONFIG_KEYS)
        or any(not isinstance(value, str) or not value for value in config.values())
    ):
        raise ProvisioningError("接入包 config 字段不完整或包含未知字段")
    selected = dict(config)
    for name in selected:
        if len(selected[name]) > 16_384 or any(
            ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F
            for character in selected[name]
        ):
            raise ProvisioningError(f"接入包 config {name} 值非法")
    if selected["ENTERPRISE_AGENT_PRODUCTION_MODE"] != "true":
        raise ProvisioningError("接入包必须锁定正式生产模式")
    if selected["ENTERPRISE_AGENT_FOUR_EYES_REQUIRED"] != "false":
        raise ProvisioningError("简化接入包必须关闭四眼复核")
    if selected["ENTERPRISE_AGENT_SECURE_COOKIE"] != "false":
        raise ProvisioningError("回环企业界面必须关闭 Secure Cookie")
    _https_origin(selected["PLATFORM_V3_BASE_URL"], "PLATFORM_V3_BASE_URL")
    identity_names = (
        "ENTERPRISE_MINE_ID",
        "ENTERPRISE_OPERATOR_ID",
        "ENTERPRISE_SYSTEM_ID",
        "PLATFORM_V3_SENDER_ID",
        "REGULATORY_SYSTEM_ID",
        "REGULATORY_PARTY_ID",
        "ENTERPRISE_EXCHANGE_KEY_ID",
        "REGULATORY_EXCHANGE_KEY_ID",
    )
    for name in identity_names:
        _production_identifier(selected[name], name)
    _production_display(selected["ENTERPRISE_MINE_NAME"], "ENTERPRISE_MINE_NAME")
    _production_display(
        selected["ENTERPRISE_OPERATOR_NAME"], "ENTERPRISE_OPERATOR_NAME"
    )
    for name in (
        "ENTERPRISE_CAPACITY_BAND",
        "ENTERPRISE_MINING_METHOD",
        "ENTERPRISE_SHIFT_SYSTEM",
        "ENTERPRISE_COAL_TYPE",
        "ENTERPRISE_OPERATING_REGIME",
    ):
        _production_display(selected[name], name, 64)
    if selected["ENTERPRISE_REPORTING_TIMEZONE"] != "Asia/Shanghai":
        raise ProvisioningError("V1 接入包时区必须是 Asia/Shanghai")
    if selected["PLATFORM_V3_SENDER_ID"] != selected["ENTERPRISE_SYSTEM_ID"]:
        raise ProvisioningError("PLATFORM_V3_SENDER_ID 必须等于 ENTERPRISE_SYSTEM_ID")
    subject = protected["subject"]
    bindings = {
        "ENTERPRISE_MINE_ID": "mine_id",
        "ENTERPRISE_SYSTEM_ID": "system_id",
        "ENTERPRISE_OPERATOR_ID": "party_id",
    }
    for config_name, subject_name in bindings.items():
        if selected[config_name] != subject[subject_name]:
            raise ProvisioningError(f"{config_name} 与接入包 subject 不一致")
    message_secret = selected["ENTERPRISE_EXCHANGE_HMAC_SECRET"]
    transport_secret = selected["PLATFORM_V3_TRANSPORT_HMAC_SECRET"]
    if (
        len(message_secret.encode()) < 32
        or len(transport_secret.encode()) < 32
        or len(message_secret) > 512
        or len(transport_secret) > 512
    ):
        raise ProvisioningError("接入包 HMAC 密钥必须为 32-512 字符且至少 32 字节")
    for label, secret in (
        ("应用消息 HMAC", message_secret),
        ("运输 HMAC", transport_secret),
    ):
        if any(marker in secret.casefold() for marker in _SECRET_PLACEHOLDERS):
            raise ProvisioningError(f"{label} 密钥仍是示例或占位值")
    if hmac.compare_digest(message_secret.encode(), transport_secret.encode()):
        raise ProvisioningError("应用消息与运输 HMAC 密钥不得相同")
    historical = selected.get("ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON")
    if historical is not None:
        historical_items = _validate_historical_keyring(historical)
        if any(
            key_id == selected["ENTERPRISE_EXCHANGE_KEY_ID"]
            or hmac.compare_digest(secret.encode(), message_secret.encode())
            for key_id, secret in historical_items
        ):
            raise ProvisioningError("历史企业验签密钥不得复用当前企业 key_id 或 secret")
    previous_id = selected.get("REGULATORY_PREVIOUS_EXCHANGE_KEY_ID")
    previous_secret = selected.get("REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET")
    if (previous_id is None) != (previous_secret is None):
        raise ProvisioningError("政府上一把 key_id 与 secret 必须同时配置")
    if previous_id is not None:
        _production_identifier(previous_id, "REGULATORY_PREVIOUS_EXCHANGE_KEY_ID")
        assert previous_secret is not None
        if len(previous_secret.encode()) < 32 or len(previous_secret) > 512:
            raise ProvisioningError(
                "政府上一把应用密钥必须为 32-512 字符且至少 32 字节"
            )
        if any(marker in previous_secret.casefold() for marker in _SECRET_PLACEHOLDERS):
            raise ProvisioningError("政府上一把应用密钥仍是示例或占位值")
        if hmac.compare_digest(previous_secret.encode(), message_secret.encode()):
            raise ProvisioningError("政府上一把应用密钥不得复用当前应用密钥")
    return selected


def verify_and_decrypt_bundle(
    document: Any,
    *,
    activation_code: bytes,
    issuer_public_key_pem: bytes,
    expected_public_key_sha256: str | None,
    allow_unanchored_test_key: bool = False,
    now: datetime | None = None,
    check_install_window: bool = True,
) -> VerifiedBundle:
    key, normalized_pem, fingerprint = _public_key(issuer_public_key_pem)
    if expected_public_key_sha256 is None:
        if not allow_unanchored_test_key:
            raise ProvisioningError("正式导入必须提供介质外审批的签发公钥 SHA-256")
    else:
        if _HEX_64.fullmatch(expected_public_key_sha256) is None:
            raise ProvisioningError("签发公钥 SHA-256 必须是 64 位小写十六进制")
        if not hmac.compare_digest(expected_public_key_sha256, fingerprint):
            raise ProvisioningError("签发公钥与介质外审批 SHA-256 不匹配")
    envelope = _validate_envelope(document, key)
    protected = envelope["protected"]
    current = (now or datetime.now(UTC)).astimezone(UTC)
    issued_at = _parse_time(protected["issued_at"], "protected.issued_at")
    expires_at = _parse_time(protected["expires_at"], "protected.expires_at")
    if check_install_window:
        if issued_at > current + timedelta(minutes=5):
            raise ProvisioningError("接入包签发时间来自未来")
        if current >= expires_at:
            raise ProvisioningError("接入包已过安装有效期")
    selected_activation_code = normalize_activation_code(activation_code)
    encryption = protected["encryption"]
    key_material = Scrypt(
        salt=_b64url(encryption["salt"], "encryption.salt", 16),
        length=32,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    ).derive(selected_activation_code)
    try:
        plaintext = AESGCM(key_material).decrypt(
            _b64url(encryption["nonce"], "encryption.nonce", 12),
            _b64url(envelope["ciphertext"], "ciphertext"),
            _canonical_bytes(protected),
        )
    except Exception as error:
        raise ProvisioningError("接入包激活或认证解密失败") from error
    payload = _strict_object(
        _json_bytes(plaintext, "接入包 payload"),
        _PAYLOAD_FIELDS,
        "payload",
    )
    expected_fields = {
        "kind": BUNDLE_KIND,
        "bundle_id": protected["bundle_id"],
        "pair_id": protected["pair_id"],
        "profile_version": protected["profile_version"],
    }
    for name, expected in expected_fields.items():
        if payload[name] != expected:
            raise ProvisioningError(f"payload.{name} 与 protected 不一致")
    if _sha256(_canonical_bytes(payload)) != protected["payload_sha256"]:
        raise ProvisioningError("接入包 payload 摘要不匹配")
    config = _validate_config(payload["config"], protected)
    if payload["locked_keys"] != protected["locked_keys"]:
        raise ProvisioningError("payload.locked_keys 与 protected 不一致")
    if protected["locked_keys"] != sorted(config):
        raise ProvisioningError("接入包必须锁定全部 config 字段")
    locked = {name: config[name] for name in protected["locked_keys"]}
    if _sha256(_canonical_bytes(locked)) != protected["locked_config_sha256"]:
        raise ProvisioningError("接入包 locked config 摘要不匹配")
    return VerifiedBundle(
        envelope=envelope,
        payload=payload,
        config=config,
        public_key_pem=normalized_pem,
        public_key_sha256=fingerprint,
    )


def normalize_activation_code(value: bytes) -> bytes:
    """Accept exactly one generated 32-byte base64url activation credential.

    Files and stdin may contribute one conventional terminal LF or CRLF. No
    other leading/trailing whitespace or Unicode normalization is permitted.
    """

    if not isinstance(value, bytes):
        raise ProvisioningError("接入包激活码必须是原始 ASCII bytes")
    selected = value
    if selected.endswith(b"\r\n"):
        selected = selected[:-2]
    elif selected.endswith(b"\n"):
        selected = selected[:-1]
    if _ACTIVATION_CODE.fullmatch(selected) is None:
        raise ProvisioningError("接入包激活码必须是生成器产生的 43 字符 Base64URL")
    return selected


def read_activation_code_file(path: str | Path) -> bytes:
    """Read a file-delivered activation code without returning path contents."""

    _, encoded = _read_regular(path, "接入包激活码")
    return normalize_activation_code(encoded)


def _validate_base_accounts(raw: str | None) -> None:
    users = parse_users_json(raw)
    if len(users) != 2:
        raise ProvisioningError("基础环境必须配置企业管理员和固定 api_admin 两个账号")
    business_admins = []
    api_admins = []
    for account in users:
        defects = production_credential_errors(account)
        if defects:
            raise ProvisioningError(f"账号 {account.actor_id} 正式凭据不合格")
        if account.actor_id == "api_admin":
            if account.permissions != frozenset({"model_api_admin"}):
                raise ProvisioningError("api_admin 只能拥有 model_api_admin 权限")
            api_admins.append(account.actor_id)
        elif account.permissions == frozenset(
            {"read", "write", "confirm", "submit"}
        ):
            business_admins.append(account.actor_id)
    if len(business_admins) != 1 or api_admins != ["api_admin"]:
        raise ProvisioningError("基础环境必须包含一个业务管理员和固定 api_admin")


def _encode_environment(values: Mapping[str, str]) -> bytes:
    lines = [
        "# Generated from a verified MineGuard enterprise provisioning bundle.",
        "# Sealed identity and endpoint fields must not be edited.",
    ]
    for name in sorted(values):
        value = values[name]
        if _ENVIRONMENT_NAME.fullmatch(name) is None:
            raise ProvisioningError(f"环境变量名非法：{name}")
        if (
            not isinstance(value, str)
            or value != value.strip()
            or value.startswith(("'", '"'))
            or any(character in value for character in ("\x00", "\r", "\n"))
        ):
            raise ProvisioningError(f"环境变量 {name} 不能安全写入严格环境文件")
        lines.append(f"{name}={value}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _dpapi_protect(plaintext: bytes, entropy: bytes) -> bytes:
    return _dpapi(plaintext, entropy, protect=True)


def _dpapi_unprotect(ciphertext: bytes, entropy: bytes) -> bytes:
    return _dpapi(ciphertext, entropy, protect=False)


def _dpapi(value: bytes, entropy: bytes, *, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise ProvisioningError("Windows DPAPI 只能在 Windows 上使用")

    class DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint32),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    def make_blob(data: bytes) -> tuple[DataBlob, Any]:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return (
            DataBlob(
                len(data),
                ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)),
            ),
            buffer,
        )

    source, source_buffer = make_blob(value)
    optional_entropy, entropy_buffer = make_blob(entropy)
    output = DataBlob()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if protect:
        function = crypt32.CryptProtectData
        function.argtypes = [
            ctypes.POINTER(DataBlob),
            ctypes.c_wchar_p,
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(DataBlob),
        ]
        function.restype = ctypes.c_bool
        succeeded = function(
            ctypes.byref(source),
            "MineGuard enterprise provisioning secrets",
            ctypes.byref(optional_entropy),
            None,
            None,
            0x4,
            ctypes.byref(output),
        )
        description = None
    else:
        function = crypt32.CryptUnprotectData
        function.argtypes = [
            ctypes.POINTER(DataBlob),
            ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.POINTER(DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(DataBlob),
        ]
        function.restype = ctypes.c_bool
        description = ctypes.c_wchar_p()
        succeeded = function(
            ctypes.byref(source),
            ctypes.byref(description),
            ctypes.byref(optional_entropy),
            None,
            None,
            0,
            ctypes.byref(output),
        )
    if not succeeded:
        raise OSError(ctypes.get_last_error(), "Windows DPAPI 操作失败")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
        if description:
            kernel32.LocalFree(description)
        _ = source_buffer, entropy_buffer


def _secret_store(
    verified: VerifiedBundle,
    *,
    protection: str,
) -> tuple[dict[str, Any], str, dict[str, str]]:
    secrets = {
        name: verified.config[name]
        for name in sorted(_SECRET_CONFIG_KEYS & set(verified.config))
    }
    plaintext = _canonical_bytes(secrets)
    selected = protection
    if selected == "auto":
        selected = "dpapi-local-machine" if sys.platform == "win32" else "posix-0600"
    protected = verified.envelope["protected"]
    base = {
        "format": SECRET_STORE_FORMAT,
        "bundle_id": protected["bundle_id"],
        "pair_id": protected["pair_id"],
        "profile_version": protected["profile_version"],
    }
    entropy = bytes.fromhex(protected["payload_sha256"])
    if selected == "dpapi-local-machine":
        blob = _dpapi_protect(plaintext, entropy)
        document = {
            **base,
            "protection": DPAPI_PROTECTION,
            "payload_b64": base64.b64encode(blob).decode("ascii"),
        }
        return document, DPAPI_PROTECTION, secrets
    if selected == "posix-0600":
        if os.name == "nt":
            raise ProvisioningError("Windows 正式导入不得使用 POSIX 明文 secret store")
        document = {**base, "protection": POSIX_PROTECTION, "secrets": secrets}
        return document, POSIX_PROTECTION, secrets
    raise ProvisioningError("secret protection 取值非法")


def _write_new(path: Path, content: bytes) -> None:
    if not path.is_absolute() or not path.parent.is_dir():
        raise ProvisioningError(f"输出路径必须是现有目录下的绝对路径：{path}")
    for candidate in (path.parent, *path.parent.parents):
        if candidate.exists() and _is_link_or_reparse(candidate):
            raise ProvisioningError(f"输出路径不能包含链接或重解析点：{path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("配置文件写入失败")
            view = view[count:]
        os.fsync(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def _assert_upgrade(current_lock_path: str | Path, verified: VerifiedBundle) -> None:
    current = _load_lock(current_lock_path)
    public_value = current["issuer_public_key_pem"]
    if not isinstance(public_value, str):
        raise ProvisioningError("当前 provisioning lock 签发公钥非法")
    try:
        current_key, _pem, current_fingerprint = _public_key(
            public_value.encode("ascii")
        )
    except UnicodeEncodeError as error:
        raise ProvisioningError("当前 provisioning lock 签发公钥非法") from error
    if (
        current["trust_anchor_mode"] != "embedded-package"
        or current_fingerprint != current["issuer_public_key_sha256"]
    ):
        raise ProvisioningError("当前 provisioning lock 未绑定接入包签发公钥")
    before = _validate_envelope(current["envelope"], current_key)["protected"]
    after = verified.envelope["protected"]
    if before["issuer_key_id"] != current["expected_issuer_key_id"]:
        raise ProvisioningError("当前 provisioning lock issuer_key_id 持久绑定不匹配")
    if before.get("subject") != after["subject"]:
        raise ProvisioningError("接入包升级不得改变 mine/party/system 身份")
    if before.get("pair_id") != after["pair_id"]:
        raise ProvisioningError("接入包升级不得改变 pair_id")
    if before.get("issuer_key_id") != after["issuer_key_id"]:
        raise ProvisioningError("接入包升级不得改变 issuer_key_id")
    if before.get("issuer_id") != after["issuer_id"]:
        raise ProvisioningError("接入包升级不得改变 issuer_id")
    if current_fingerprint != verified.public_key_sha256:
        raise ProvisioningError("接入包升级不得切换已审批签发公钥")
    previous_version = before.get("profile_version")
    if (
        not isinstance(previous_version, int)
        or after["profile_version"] != previous_version + 1
    ):
        raise ProvisioningError("接入包升级 profile_version 必须精确递增 1")

    before_config, _before_secrets = _reconstruct_locked_config(current, before)
    after_config = verified.config
    if (
        after_config["REGULATORY_EXCHANGE_KEY_ID"]
        != before_config["REGULATORY_EXCHANGE_KEY_ID"]
    ):
        raise ProvisioningError("接入包升级不得改变政府全局应用 key_id")
    if after_config["ENTERPRISE_EXCHANGE_KEY_ID"] == before_config[
        "ENTERPRISE_EXCHANGE_KEY_ID"
    ] or hmac.compare_digest(
        after_config["ENTERPRISE_EXCHANGE_HMAC_SECRET"].encode(),
        before_config["ENTERPRISE_EXCHANGE_HMAC_SECRET"].encode(),
    ):
        raise ProvisioningError("接入包升级必须轮换企业当前应用 key_id 和 secret")
    if hmac.compare_digest(
        after_config["PLATFORM_V3_TRANSPORT_HMAC_SECRET"].encode(),
        before_config["PLATFORM_V3_TRANSPORT_HMAC_SECRET"].encode(),
    ):
        raise ProvisioningError("接入包升级必须轮换运输 HMAC secret")
    historical_raw = after_config.get("ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON")
    historical = (
        _validate_historical_keyring(historical_raw)
        if historical_raw is not None
        else []
    )
    prior_enterprise_key = (
        before_config["ENTERPRISE_EXCHANGE_KEY_ID"],
        before_config["ENTERPRISE_EXCHANGE_HMAC_SECRET"],
    )
    if prior_enterprise_key not in historical:
        raise ProvisioningError("接入包升级必须保留紧邻上一版企业应用密钥")
    if after_config.get("REGULATORY_PREVIOUS_EXCHANGE_KEY_ID") != before_config[
        "REGULATORY_EXCHANGE_KEY_ID"
    ] or not hmac.compare_digest(
        after_config.get("REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET", "").encode(),
        before_config["ENTERPRISE_EXCHANGE_HMAC_SECRET"].encode(),
    ):
        raise ProvisioningError("接入包升级必须保留紧邻上一版政府应用验签密钥")


def install_provisioning_bundle(
    *,
    bundle_path: str | Path,
    base_environment_path: str | Path,
    output_environment_path: str | Path,
    lock_output_path: str | Path,
    lock_environment_path: str | Path,
    secret_store_output_path: str | Path,
    secret_store_environment_path: str | Path,
    secret_protection: str = "auto",
    expected_mine_id: str | None = None,
    expected_system_id: str | None = None,
    current_lock_path: str | Path | None = None,
    now: datetime | None = None,
) -> ProvisioningResult:
    _, bundle_bytes = _read_regular(bundle_path, "企业接入包")
    package = _strict_object(
        _json_bytes(bundle_bytes, "企业接入包"),
        _ACCESS_PACKAGE_FIELDS,
        "企业接入包",
    )
    if package["format"] != ACCESS_PACKAGE_FORMAT:
        raise ProvisioningError("企业接入包格式不受支持")
    if not isinstance(package["activation_code"], str):
        raise ProvisioningError("企业接入包内置激活凭据格式非法")
    if not isinstance(package["issuer_public_key_pem"], str):
        raise ProvisioningError("企业接入包内置签发公钥格式非法")
    embedded_fingerprint = package["issuer_public_key_sha256"]
    if not isinstance(embedded_fingerprint, str) or _HEX_64.fullmatch(
        embedded_fingerprint
    ) is None:
        raise ProvisioningError("企业接入包内置签发公钥摘要格式非法")
    embedded_issuer_key_id = _production_identifier(
        package["issuer_key_id"], "企业接入包 issuer_key_id"
    )
    try:
        embedded_activation = package["activation_code"].encode("ascii", "strict")
        embedded_public_key = package["issuer_public_key_pem"].encode(
            "ascii", "strict"
        )
    except UnicodeEncodeError as error:
        raise ProvisioningError("企业接入包内置凭据编码非法") from error
    verified = verify_and_decrypt_bundle(
        package["agent_bundle"],
        activation_code=embedded_activation,
        issuer_public_key_pem=embedded_public_key,
        expected_public_key_sha256=embedded_fingerprint,
        now=now,
    )
    protected = verified.envelope["protected"]
    if protected["issuer_key_id"] != embedded_issuer_key_id:
        raise ProvisioningError("企业接入包 issuer_key_id 绑定不一致")
    subject = protected["subject"]
    if expected_mine_id is not None and subject["mine_id"] != expected_mine_id:
        raise ProvisioningError("接入包 mine_id 与安装目标不一致")
    if expected_system_id is not None and subject["system_id"] != expected_system_id:
        raise ProvisioningError("接入包 system_id 与安装目标不一致")
    if current_lock_path is not None:
        _assert_upgrade(current_lock_path, verified)

    base = parse_environment_file(base_environment_path)
    _validate_base_accounts(base.get("ENTERPRISE_AGENT_USERS_JSON"))
    inherited_secrets = sorted(name for name in _SECRET_CONFIG_KEYS if base.get(name))
    if inherited_secrets:
        raise ProvisioningError(
            "基础环境文件不得携带接入密钥：" + ", ".join(inherited_secrets)
        )
    for name in _FORBIDDEN_PROVISIONED_ENDPOINT_ALIASES:
        base.pop(name, None)
    output_env = Path(output_environment_path).expanduser()
    lock_output = Path(lock_output_path).expanduser()
    lock_env = Path(lock_environment_path).expanduser()
    store_output = Path(secret_store_output_path).expanduser()
    store_env = Path(secret_store_environment_path).expanduser()
    for label, path in (
        ("output-env", output_env),
        ("lock-output", lock_output),
        ("lock-env-path", lock_env),
        ("secret-store", store_output),
        ("secret-store-env-path", store_env),
    ):
        if not path.is_absolute():
            raise ProvisioningError(f"{label} 必须使用绝对路径")
    distinct_outputs = {
        os.path.normcase(str(path)) for path in (output_env, lock_output, store_output)
    }
    if len(distinct_outputs) != 3:
        raise ProvisioningError("env、lock、secret store 输出路径必须不同")

    secret_document, selected_protection, secret_values = _secret_store(
        verified, protection=secret_protection
    )
    public_config = {
        name: value
        for name, value in verified.config.items()
        if name not in _SECRET_CONFIG_KEYS
    }
    managed = {
        **public_config,
        **_DERIVED_LOCKED_ENVIRONMENT,
        "ENTERPRISE_PROVISIONING_LOCK_FILE": str(lock_env),
        "ENTERPRISE_PROVISIONING_SECRET_STORE": str(store_env),
    }
    for name in _SECRET_CONFIG_KEYS:
        base.pop(name, None)
    base.update(managed)
    env_bytes = _encode_environment(base)
    imported_at = utc_text(now or datetime.now(UTC))
    lock_body = {
        "format": LOCK_FORMAT,
        "envelope": verified.envelope,
        "issuer_public_key_pem": verified.public_key_pem,
        "issuer_public_key_sha256": verified.public_key_sha256,
        "expected_issuer_key_id": protected["issuer_key_id"],
        "trust_anchor_mode": "embedded-package",
        "public_payload": {
            "kind": verified.payload["kind"],
            "bundle_id": verified.payload["bundle_id"],
            "pair_id": verified.payload["pair_id"],
            "profile_version": verified.payload["profile_version"],
            "config": public_config,
            "locked_keys": verified.payload["locked_keys"],
        },
        "managed_environment": managed,
        "secret_names": sorted(secret_values),
        "secret_store": {"path": str(store_env), "protection": selected_protection},
        "imported_at": imported_at,
        "lock_hmac_algorithm": "hmac-sha256-v1",
    }
    lock_mac = hmac.new(
        secret_values["ENTERPRISE_EXCHANGE_HMAC_SECRET"].encode(),
        _LOCK_MAC_CONTEXT + _canonical_bytes(lock_body),
        hashlib.sha256,
    ).hexdigest()
    lock_document = {**lock_body, "lock_hmac": lock_mac}
    created: list[Path] = []
    try:
        for path, content in (
            (store_output, _canonical_bytes(secret_document) + b"\n"),
            (lock_output, _canonical_bytes(lock_document) + b"\n"),
            (output_env, env_bytes),
        ):
            _write_new(path, content)
            created.append(path)
    except Exception:
        for path in reversed(created):
            with suppress(OSError):
                path.unlink()
        raise
    finally:
        secret_values.clear()

    return ProvisioningResult(
        summary={
            "valid": True,
            "production_ready": True,
            "bundle_id": protected["bundle_id"],
            "pair_id": protected["pair_id"],
            "profile_version": protected["profile_version"],
            "mine_id": subject["mine_id"],
            "system_id": subject["system_id"],
            "party_id": subject["party_id"],
            "platform_origin": verified.config["PLATFORM_V3_BASE_URL"],
            "tls_trust": "operating-system",
            "install_before": protected["expires_at"],
            "public_key_sha256": verified.public_key_sha256,
            "secret_protection": selected_protection,
            "environment_path": str(output_env),
            "lock_path": str(lock_output),
            "secret_store_path": str(store_output),
        }
    )


def _load_lock(path: str | Path) -> dict[str, Any]:
    _, encoded = _read_regular(path, "provisioning lock")
    document = _json_bytes(encoded, "provisioning lock")
    expected = {
        "format",
        "envelope",
        "issuer_public_key_pem",
        "issuer_public_key_sha256",
        "expected_issuer_key_id",
        "trust_anchor_mode",
        "public_payload",
        "managed_environment",
        "secret_names",
        "secret_store",
        "imported_at",
        "lock_hmac_algorithm",
        "lock_hmac",
    }
    _strict_object(document, expected, "provisioning lock")
    if document["format"] != LOCK_FORMAT:
        raise ProvisioningError("provisioning lock format 不受支持")
    return document


def _load_secret_store(
    path: str | Path,
    *,
    protected: Mapping[str, Any],
    expected_names: list[str],
    expected_protection: str,
) -> dict[str, str]:
    resolved, encoded = _read_regular(path, "provisioning secret store")
    store = _json_bytes(encoded, "provisioning secret store")
    common = {"format", "bundle_id", "pair_id", "profile_version", "protection"}
    if store.get("protection") == DPAPI_PROTECTION:
        _strict_object(store, common | {"payload_b64"}, "secret store")
    elif store.get("protection") == POSIX_PROTECTION:
        _strict_object(store, common | {"secrets"}, "secret store")
    else:
        raise ProvisioningError("secret store protection 不受支持")
    if (
        store["format"] != SECRET_STORE_FORMAT
        or store["bundle_id"] != protected["bundle_id"]
        or store["pair_id"] != protected["pair_id"]
        or store["profile_version"] != protected["profile_version"]
        or store["protection"] != expected_protection
    ):
        raise ProvisioningError("secret store 与接入包身份不绑定")
    if store["protection"] == DPAPI_PROTECTION:
        try:
            ciphertext = base64.b64decode(store["payload_b64"], validate=True)
        except (TypeError, ValueError, binascii.Error) as error:
            raise ProvisioningError("DPAPI secret store payload 非法") from error
        plaintext = _dpapi_unprotect(
            ciphertext, bytes.fromhex(protected["payload_sha256"])
        )
        secrets = _json_bytes(plaintext, "DPAPI secrets")
    else:
        metadata = resolved.stat()
        if os.name == "nt" or metadata.st_mode & 0o077:
            raise ProvisioningError("POSIX secret store 必须以 0600 独占")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ProvisioningError("POSIX secret store 所有者不是当前服务身份")
        secrets = store["secrets"]
    if not isinstance(secrets, dict) or set(secrets) != set(expected_names):
        raise ProvisioningError("secret store 字段与接入包不一致")
    if any(not isinstance(value, str) or not value for value in secrets.values()):
        raise ProvisioningError("secret store 包含非法 secret")
    return dict(secrets)


def _reconstruct_locked_config(
    lock: Mapping[str, Any],
    protected: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    """Authenticate local lock state and reconstruct its exact signed config."""

    secret_names = lock["secret_names"]
    if (
        not isinstance(secret_names, list)
        or any(not isinstance(name, str) for name in secret_names)
        or secret_names != sorted(set(secret_names))
        or any(name not in _SECRET_CONFIG_KEYS for name in secret_names)
    ):
        raise ProvisioningError("provisioning lock secret_names 非法")
    store = _strict_object(
        lock["secret_store"],
        {"path", "protection"},
        "lock.secret_store",
    )
    secrets = _load_secret_store(
        store["path"],
        protected=protected,
        expected_names=secret_names,
        expected_protection=store["protection"],
    )
    if "ENTERPRISE_EXCHANGE_HMAC_SECRET" not in secrets:
        raise ProvisioningError("provisioning secret store 缺少 lock HMAC 密钥")
    lock_body = {name: value for name, value in lock.items() if name != "lock_hmac"}
    expected_mac = hmac.new(
        secrets["ENTERPRISE_EXCHANGE_HMAC_SECRET"].encode(),
        _LOCK_MAC_CONTEXT + _canonical_bytes(lock_body),
        hashlib.sha256,
    ).hexdigest()
    if (
        lock["lock_hmac_algorithm"] != "hmac-sha256-v1"
        or not isinstance(lock["lock_hmac"], str)
        or not hmac.compare_digest(lock["lock_hmac"], expected_mac)
    ):
        raise ProvisioningError("provisioning lock 完整性校验失败")
    public_payload = _strict_object(
        lock["public_payload"],
        _PAYLOAD_FIELDS,
        "provisioning lock public_payload",
    )
    if not isinstance(public_payload["config"], dict):
        raise ProvisioningError("provisioning lock public_payload config 非法")
    reconstructed = {
        **public_payload,
        "config": {**public_payload["config"], **secrets},
    }
    if _sha256(_canonical_bytes(reconstructed)) != protected["payload_sha256"]:
        raise ProvisioningError("provisioning lock 无法重建签名 payload")
    config = _validate_config(reconstructed["config"], protected)
    if reconstructed["locked_keys"] != protected["locked_keys"]:
        raise ProvisioningError("provisioning lock locked_keys 不匹配")
    locked = {name: config[name] for name in protected["locked_keys"]}
    if _sha256(_canonical_bytes(locked)) != protected["locked_config_sha256"]:
        raise ProvisioningError("provisioning lock locked config 摘要不匹配")
    return config, secrets


def apply_provisioning_lock(
    environment: MutableMapping[str, str] | None = None,
) -> ProvisioningStatus:
    """Fail closed on any override, then overlay protected secrets in memory."""

    target = os.environ if environment is None else environment
    raw_managed_required = target.get(
        "ENTERPRISE_PROVISIONING_MANAGED_REQUIRED", "false"
    ).strip()
    if raw_managed_required not in {"true", "false"}:
        raise ProvisioningError(
            "ENTERPRISE_PROVISIONING_MANAGED_REQUIRED 只能严格设置为 true 或 false"
        )
    managed_required = raw_managed_required == "true"
    lock_path = target.get("ENTERPRISE_PROVISIONING_LOCK_FILE", "").strip()
    if not lock_path:
        if target is os.environ:
            with _PROCESS_OVERLAY_LOCK:
                for name, expected in tuple(_PROCESS_APPLIED_SECRETS.items()):
                    if target.get(name) == expected:
                        target.pop(name, None)
                _PROCESS_APPLIED_SECRETS.clear()
        if managed_required:
            raise ProvisioningError("受管必需策略已启用，但 provisioning lock 缺失")
        return ProvisioningStatus(managed=False)
    lock = _load_lock(lock_path)
    public_value = lock["issuer_public_key_pem"]
    if (
        not isinstance(public_value, str)
        or not public_value
        or len(public_value) > 16_384
        or "PRIVATE KEY" in public_value
        or "\x00" in public_value
        or "\r" in public_value
    ):
        raise ProvisioningError("provisioning lock 签发公钥 PEM 非法")
    try:
        public_encoded = public_value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ProvisioningError("provisioning lock 签发公钥 PEM 非法") from error
    key, normalized_pem, fingerprint = _public_key(public_encoded)
    if (
        normalized_pem != lock["issuer_public_key_pem"]
        or fingerprint != lock["issuer_public_key_sha256"]
    ):
        raise ProvisioningError("provisioning lock 签发公钥摘要不匹配")
    envelope = _validate_envelope(lock["envelope"], key)
    protected = envelope["protected"]
    if protected["issuer_key_id"] != lock["expected_issuer_key_id"]:
        raise ProvisioningError("provisioning lock issuer_key_id 持久绑定不匹配")
    imported_at = _parse_time(lock["imported_at"], "lock.imported_at")
    issued_at = _parse_time(protected["issued_at"], "protected.issued_at")
    expires_at = _parse_time(protected["expires_at"], "protected.expires_at")
    # expires_at is an import window, not a runtime kill switch.
    if imported_at + timedelta(minutes=5) < issued_at or imported_at >= expires_at:
        raise ProvisioningError("provisioning lock 导入时间不在签发窗口内")
    if lock["trust_anchor_mode"] != "embedded-package":
        raise ProvisioningError("provisioning lock 信任模式非法")
    if _HEX_64.fullmatch(lock["issuer_public_key_sha256"]) is None:
        raise ProvisioningError("provisioning lock 公钥指纹非法")

    managed = lock["managed_environment"]
    if not isinstance(managed, dict) or not managed:
        raise ProvisioningError("provisioning lock managed_environment 非法")
    for name, expected in managed.items():
        if (
            not isinstance(name, str)
            or not isinstance(expected, str)
            or target.get(name) != expected
        ):
            raise ProvisioningError(f"封存配置 {name} 被删除或覆盖")
    unexpected_aliases = sorted(
        name for name in _FORBIDDEN_PROVISIONED_ENDPOINT_ALIASES if target.get(name)
    )
    if unexpected_aliases:
        raise ProvisioningError(
            "封存实例禁止启用未签名的旧版监管端点别名：" + ", ".join(unexpected_aliases)
        )
    store = _strict_object(
        lock["secret_store"],
        {"path", "protection"},
        "lock.secret_store",
    )
    if target.get("ENTERPRISE_PROVISIONING_SECRET_STORE") != store["path"]:
        raise ProvisioningError("封存 secret store 路径被覆盖")
    config, secrets = _reconstruct_locked_config(lock, protected)
    inherited_secrets = {name: target.get(name) for name in secrets if target.get(name)}
    for name, inherited in inherited_secrets.items():
        if not hmac.compare_digest(str(inherited).encode(), secrets[name].encode()):
            raise ProvisioningError(f"封存实例的 secret {name} 被环境变量覆盖")
    target.update(secrets)
    if target is os.environ:
        with _PROCESS_OVERLAY_LOCK:
            _PROCESS_APPLIED_SECRETS.clear()
            _PROCESS_APPLIED_SECRETS.update(secrets)
    return ProvisioningStatus(
        managed=True,
        bundle_id=protected["bundle_id"],
        pair_id=protected["pair_id"],
        profile_version=protected["profile_version"],
        mine_id=protected["subject"]["mine_id"],
        public_key_sha256=fingerprint,
        secret_protection=store["protection"],
    )


def verify_provisioning_lock_from_environment() -> ProvisioningStatus:
    """Compatibility entry point used by :mod:`enterprise_agent.settings`."""

    return apply_provisioning_lock(os.environ)


__all__ = [
    "BUNDLE_KIND",
    "CONTRACT_VERSION",
    "DPAPI_PROTECTION",
    "POSIX_PROTECTION",
    "ProvisioningError",
    "ProvisioningResult",
    "ProvisioningStatus",
    "VerifiedBundle",
    "apply_provisioning_lock",
    "install_provisioning_bundle",
    "normalize_activation_code",
    "read_activation_code_file",
    "verify_and_decrypt_bundle",
    "verify_provisioning_lock_from_environment",
]
