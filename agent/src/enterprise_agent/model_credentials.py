"""Signed, encrypted and locally protected model credentials.

``.mgllm`` is deliberately independent from the regulatory ``.mgprov`` /
``.mgreg`` exchange.  The government Platform never imports this bundle and
never receives the upstream model API key.  A bundle fixes one enterprise's
provider URL, model and key under an Ed25519 issuer selected from a release
trust store.  Import moves the key into DPAPI LocalMachine storage on Windows
(or an explicitly labelled POSIX 0600 compatibility store) and runtime never
copies it into ``os.environ``.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import stat
import sys
import threading
import unicodedata
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .llm import LLMConfig
from .util import canonical_json, utc_text

CONTRACT_VERSION = "mineguard-model-credential-bundle-v1"
BUNDLE_KIND = "enterprise-agent-model-credential"
PAYLOAD_KIND = BUNDLE_KIND
TRUST_STORE_FORMAT = "mineguard-model-issuer-trust-store-v1"
LOCK_FORMAT = "mineguard-model-credential-lock-v1"
SECRET_STORE_FORMAT = "mineguard-model-credential-secret-store-v1"
STATE_FORMAT = "mineguard-model-credential-state-v1"
DPAPI_PROTECTION = "dpapi-local-machine-v1"
POSIX_PROTECTION = "posix-mode-0600-plaintext-json-v1"
PROTOCOL = "openai-compatible-chat-completions"

LOCK_ENVIRONMENT = "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE"
SECRET_STORE_ENVIRONMENT = "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE"
TRUST_STORE_ENVIRONMENT = "MINEGUARD_AGENT_MODEL_TRUST_STORE"

_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES = 2 * 1024 * 1024
_MAX_PAYLOAD_BYTES = 1 * 1024 * 1024
_MAX_VERSION = 2_147_483_647
_MAX_ISSUER_KEY_EPOCH = 2_147_483_647
_SCRYPT_N = 16_384
_SCRYPT_R = 8
_SCRYPT_P = 1
_LOCK_MAC_CONTEXT = b"MINEGUARD-MODEL-CREDENTIAL-LOCK-V1\x00"
_STATE_MAC_CONTEXT = b"MINEGUARD-MODEL-CREDENTIAL-STATE-V1\x00"
_ACTIVATION_CODE = re.compile(rb"[A-Za-z0-9_-]{43}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_UTC_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)
_UTC_SECOND = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/](?![\\/]).+")

_ENVELOPE_FIELDS = {"protected", "ciphertext", "signature"}
_PROTECTED_FIELDS = {
    "contract_version",
    "bundle_kind",
    "bundle_id",
    "credential_id",
    "credential_version",
    "issued_at",
    "install_before",
    "runtime_not_after",
    "issuer_id",
    "issuer_key_id",
    "issuer_key_epoch",
    "subject",
    "payload_sha256",
    "provider_config_sha256",
    "encryption",
}
_SUBJECT_FIELDS = {"mine_id", "system_id", "party_id", "pair_id"}
_ENCRYPTION_FIELDS = {"algorithm", "kdf", "salt", "n", "r", "p", "nonce"}
_PAYLOAD_FIELDS = {
    "kind",
    "bundle_id",
    "credential_id",
    "credential_version",
    "subject",
    "provider",
    "api_key",
}
_PROVIDER_FIELDS = {
    "provider_id",
    "protocol",
    "base_url",
    "model",
    "capabilities",
    "timeout_seconds",
    "max_retries",
}
SUPPORTED_MODEL_CAPABILITIES = frozenset({"chat", "extraction", "coal-news-search"})
_TRUST_STORE_FIELDS = {"format", "issuers"}
_TRUST_ENTRY_FIELDS = {
    "issuer_id",
    "issuer_key_id",
    "issuer_key_epoch",
    "public_key_pem",
    "public_key_sha256",
}

_PLAINTEXT_MODEL_NAMES = frozenset(
    {
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
    }
)

_LOAD_LOCK = threading.RLock()


class ModelCredentialError(ValueError):
    """Safe failure that must never include a model API key or activation."""


@dataclass(frozen=True)
class TrustedModelIssuer:
    issuer_id: str
    issuer_key_id: str
    issuer_key_epoch: int
    public_key: Ed25519PublicKey
    public_key_pem: str
    public_key_sha256: str


@dataclass(frozen=True, repr=False)
class VerifiedModelBundle:
    envelope: dict[str, Any]
    payload: dict[str, Any]
    config: LLMConfig
    issuer: TrustedModelIssuer

    def __repr__(self) -> str:
        protected = self.envelope.get("protected", {})
        return (
            "VerifiedModelBundle("
            f"bundle_id={protected.get('bundle_id')!r}, "
            f"credential_id={protected.get('credential_id')!r}, "
            f"credential_version={protected.get('credential_version')!r}, "
            f"issuer_id={self.issuer.issuer_id!r})"
        )


@dataclass(frozen=True)
class ModelCredentialResult:
    summary: dict[str, Any]


@dataclass(frozen=True)
class ModelCredentialSubject:
    mine_id: str
    system_id: str
    party_id: str
    pair_id: str

    def as_dict(self) -> dict[str, str]:
        return {
            "mine_id": self.mine_id,
            "system_id": self.system_id,
            "party_id": self.party_id,
            "pair_id": self.pair_id,
        }


@dataclass(frozen=True)
class ModelProviderPolicy:
    provider_id: str
    base_url: str
    model: str
    capabilities: tuple[str, ...]
    timeout_seconds: float = 20.0
    max_retries: int = 2

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "protocol": PROTOCOL,
            "base_url": self.base_url,
            "model": self.model,
            "capabilities": list(self.capabilities),
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
        }


@dataclass(frozen=True)
class ModelCredentialStatus:
    managed: bool
    bundle_id: str | None = None
    credential_id: str | None = None
    credential_version: int | None = None
    mine_id: str | None = None
    system_id: str | None = None
    party_id: str | None = None
    pair_id: str | None = None
    issuer_id: str | None = None
    issuer_key_id: str | None = None
    issuer_key_epoch: int | None = None
    issuer_public_key_sha256: str | None = None
    provider_id: str | None = None
    base_url: str | None = None
    model: str | None = None
    capabilities: tuple[str, ...] = ()
    runtime_not_after: str | None = None
    secret_protection: str | None = None
    source: str = "not_configured"
    state: str = "not_configured"
    failure_code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "managed": self.managed,
            "bundle_id": self.bundle_id,
            "credential_id": self.credential_id,
            "credential_version": self.credential_version,
            "mine_id": self.mine_id,
            "system_id": self.system_id,
            "party_id": self.party_id,
            "pair_id": self.pair_id,
            "issuer_id": self.issuer_id,
            "issuer_key_id": self.issuer_key_id,
            "issuer_key_epoch": self.issuer_key_epoch,
            "issuer_public_key_sha256": self.issuer_public_key_sha256,
            "provider_id": self.provider_id,
            "base_url": self.base_url,
            "model": self.model,
            "capabilities": list(self.capabilities),
            "runtime_not_after": self.runtime_not_after,
            "secret_protection": self.secret_protection,
            "source": self.source,
            "failure_code": self.failure_code,
        }


@dataclass(frozen=True, repr=False)
class ManagedModelCredential:
    config: LLMConfig
    status: ModelCredentialStatus

    def __repr__(self) -> str:
        return f"ManagedModelCredential(status={self.status!r})"


def _canonical_bytes(value: Any) -> bytes:
    try:
        return canonical_json(value).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as error:
        raise ModelCredentialError("模型凭据 JSON 无法规范化") from error


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ModelCredentialError(f"{label} 字段不完整或包含未知字段")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ModelCredentialError(f"{label} 不是有效标识")
    return value


def _issuer_key_epoch(value: Any, label: str = "issuer_key_epoch") -> int:
    """Return a strict, bounded key generation number (booleans are invalid)."""

    if type(value) is not int or not 1 <= value <= _MAX_ISSUER_KEY_EPOCH:
        raise ModelCredentialError(f"{label} 必须是严格正整数")
    return value


def _canonical_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ModelCredentialError(f"{label} 必须是 UUID")
    try:
        selected = UUID(value)
    except ValueError as error:
        raise ModelCredentialError(f"{label} 必须是 UUID") from error
    if str(selected) != value:
        raise ModelCredentialError(f"{label} 必须是小写连字符规范 UUID")
    return value


def _canonical_uuid4(value: Any, label: str) -> str:
    selected = _canonical_uuid(value, label)
    if UUID(selected).version != 4:
        raise ModelCredentialError(f"{label} 必须是 UUIDv4")
    return selected


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_TIME.fullmatch(value) is None:
        raise ModelCredentialError(f"{label} 必须是 UTC RFC3339 Z 时间")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
    except ValueError as error:
        raise ModelCredentialError(f"{label} 必须是 UTC RFC3339 Z 时间") from error


def _parse_second_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_SECOND.fullmatch(value) is None:
        raise ModelCredentialError(f"{label} 必须是精确到秒的 UTC RFC3339 Z 时间")
    return _parse_time(value, label)


def _contains_control(value: str) -> bool:
    return any(
        ord(character) < 32
        or 127 <= ord(character) <= 159
        or unicodedata.category(character) in {"Cc", "Cs"}
        for character in value
    )


def _b64url(value: Any, label: str, length: int | None = None) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or "=" in value
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise ModelCredentialError(f"{label} 必须是无 padding 的 Base64URL")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ModelCredentialError(f"{label} 必须是无 padding 的 Base64URL") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ModelCredentialError(f"{label} 不是规范 Base64URL")
    if length is not None and len(decoded) != length:
        raise ModelCredentialError(f"{label} 长度非法")
    return decoded


def _json_bytes(encoded: bytes, label: str) -> dict[str, Any]:
    if len(encoded) > _MAX_JSON_BYTES:
        raise ModelCredentialError(f"{label} 超过 4 MiB")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ModelCredentialError(f"{label} 包含重复字段 {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            encoded.decode("utf-8-sig"),
            object_pairs_hook=pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ModelCredentialError(f"{label} 包含非有限数值 {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ModelCredentialError(f"{label} 必须是 UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ModelCredentialError(f"{label} 顶层必须是对象")
    return value


def _is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    is_junction = getattr(path, "is_junction", None)
    return bool(
        path.is_symlink()
        or (callable(is_junction) and is_junction())
        or (reparse_flag and attributes & reparse_flag)
    )


def _read_regular(path: str | Path, label: str) -> tuple[Path, bytes]:
    requested = Path(path).expanduser()
    if not requested.is_absolute():
        raise ModelCredentialError(f"{label} 必须使用绝对路径")
    for candidate in (requested, *requested.parents):
        if candidate.exists() and _is_link_or_reparse(candidate):
            raise ModelCredentialError(f"{label} 路径不能包含链接或重解析点")
    try:
        before = requested.lstat()
    except OSError as error:
        raise ModelCredentialError(f"{label} 无法读取") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > _MAX_JSON_BYTES
    ):
        raise ModelCredentialError(f"{label} 必须是小于 4 MiB 的独占普通文件")
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
            raise ModelCredentialError(f"{label} 在读取前发生变化")
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
            raise ModelCredentialError(f"{label} 超过 4 MiB")
        return requested.resolve(), content
    finally:
        os.close(descriptor)


def _write_new(path: Path, content: bytes) -> None:
    if not path.is_absolute() or not path.parent.is_dir():
        raise ModelCredentialError("模型凭据输出必须位于现有目录的绝对路径")
    for candidate in (path.parent, *path.parent.parents):
        if candidate.exists() and _is_link_or_reparse(candidate):
            raise ModelCredentialError("模型凭据输出路径不能包含链接或重解析点")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    completed = False
    try:
        view = memoryview(content)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise OSError("模型凭据文件写入失败")
            view = view[count:]
        os.fsync(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        completed = True
    finally:
        os.close(descriptor)
        if not completed:
            with suppress(OSError):
                path.unlink()


def _absolute_path(value: str | Path, label: str) -> Path:
    text = str(value)
    if (
        not text
        or text != text.strip()
        or _contains_control(text)
        or (not Path(text).is_absolute() and _WINDOWS_ABSOLUTE.fullmatch(text) is None)
        or any(part in {".", ".."} for part in re.split(r"[\\/]", text))
    ):
        raise ModelCredentialError(f"{label} 必须是安全绝对路径")
    return Path(text)


def _public_key(encoded: bytes) -> tuple[Ed25519PublicKey, str, str]:
    try:
        key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError) as error:
        raise ModelCredentialError("模型签发公钥不是有效 PEM") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ModelCredentialError("模型签发公钥必须是 Ed25519")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pem = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return key, pem, _sha256(der)


def _parse_trusted_issuers(
    encoded: bytes,
) -> dict[tuple[str, str], TrustedModelIssuer]:
    document = _strict_object(
        _json_bytes(encoded, "模型 issuer trust store"),
        _TRUST_STORE_FIELDS,
        "模型 issuer trust store",
    )
    if document["format"] != TRUST_STORE_FORMAT:
        raise ModelCredentialError("模型 issuer trust store format 不受支持")
    entries = document["issuers"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise ModelCredentialError("模型 issuer trust store 必须含 1-32 个签发方")
    result: dict[tuple[str, str], TrustedModelIssuer] = {}
    fingerprints: set[str] = set()
    key_ids: set[str] = set()
    issuer_epochs: set[tuple[str, int]] = set()
    ordered_key_ids: list[str] = []
    for index, raw in enumerate(entries):
        item = _strict_object(raw, _TRUST_ENTRY_FIELDS, f"issuer[{index}]")
        issuer_id = _identifier(item["issuer_id"], f"issuer[{index}].issuer_id")
        key_id = _identifier(item["issuer_key_id"], f"issuer[{index}].issuer_key_id")
        key_epoch = _issuer_key_epoch(
            item["issuer_key_epoch"], f"issuer[{index}].issuer_key_epoch"
        )
        pem_value = item["public_key_pem"]
        if (
            not isinstance(pem_value, str)
            or not pem_value
            or len(pem_value) > 16_384
            or "PRIVATE KEY" in pem_value
            or "\r" in pem_value
            or "\x00" in pem_value
        ):
            raise ModelCredentialError("模型 issuer trust store 公钥非法")
        try:
            key, pem, fingerprint = _public_key(pem_value.encode("ascii"))
        except UnicodeEncodeError as error:
            raise ModelCredentialError("模型 issuer trust store 公钥非法") from error
        expected = item["public_key_sha256"]
        if (
            not isinstance(expected, str)
            or _HEX_64.fullmatch(expected) is None
            or not hmac.compare_digest(expected, fingerprint)
            or pem != pem_value
        ):
            raise ModelCredentialError("模型 issuer trust store 公钥摘要不匹配")
        identity = (issuer_id, key_id)
        issuer_epoch = (issuer_id, key_epoch)
        if issuer_epoch in issuer_epochs:
            raise ModelCredentialError(
                "模型 issuer trust store 同一 issuer 的 key epoch 必须唯一"
            )
        if identity in result or key_id in key_ids or fingerprint in fingerprints:
            raise ModelCredentialError("模型 issuer trust store 存在重复签发方")
        result[identity] = TrustedModelIssuer(
            issuer_id=issuer_id,
            issuer_key_id=key_id,
            issuer_key_epoch=key_epoch,
            public_key=key,
            public_key_pem=pem,
            public_key_sha256=fingerprint,
        )
        fingerprints.add(fingerprint)
        key_ids.add(key_id)
        issuer_epochs.add(issuer_epoch)
        ordered_key_ids.append(key_id)
    if ordered_key_ids != sorted(ordered_key_ids):
        raise ModelCredentialError("模型 issuer trust store 必须按 issuer_key_id 排序")
    return result


def _trusted_issuers(path: str | Path) -> dict[tuple[str, str], TrustedModelIssuer]:
    _, encoded = _read_regular(path, "模型 issuer trust store")
    return _parse_trusted_issuers(encoded)


def validate_model_trust_store(path: str | Path) -> dict[str, Any]:
    """Return a non-secret semantic summary for build and CLI checks."""

    resolved, encoded = _read_regular(path, "模型 issuer trust store")
    issuers = _parse_trusted_issuers(encoded)
    ordered = sorted(issuers.values(), key=lambda item: item.issuer_key_id)
    return {
        "valid": True,
        "format": TRUST_STORE_FORMAT,
        "issuer_count": len(ordered),
        "issuer_ids": [item.issuer_id for item in ordered],
        "issuer_key_ids": [item.issuer_key_id for item in ordered],
        "issuer_key_epochs": [item.issuer_key_epoch for item in ordered],
        "issuer_keys": [
            {
                "issuer_id": item.issuer_id,
                "issuer_key_id": item.issuer_key_id,
                "issuer_key_epoch": item.issuer_key_epoch,
                "public_key_sha256": item.public_key_sha256,
            }
            for item in ordered
        ],
        "sha256": _sha256(encoded),
        "path": str(resolved),
    }


def release_model_trust_store_path() -> Path:
    """Return the trust-store path fixed by the installed release layout."""

    binary_directory = Path(sys.executable).resolve().parent
    release_root = (
        binary_directory.parent
        if binary_directory.name.casefold() == "runtime"
        else binary_directory
    )
    return release_root / "release-metadata" / "model-credential-trust.json"


def default_model_trust_store_path() -> Path:
    """Return release trust, with an explicit override for source/dev tools."""

    configured = os.environ.get(TRUST_STORE_ENVIRONMENT, "").strip()
    if configured:
        return _absolute_path(configured, TRUST_STORE_ENVIRONMENT)
    return release_model_trust_store_path()


def plaintext_model_environment_names(
    environment: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    selected = os.environ if environment is None else environment
    found = {
        name.upper()
        for name, value in selected.items()
        if name.upper() in _PLAINTEXT_MODEL_NAMES and str(value).strip()
    }
    return tuple(sorted(found))


def _provider_config(value: Any) -> tuple[dict[str, Any], LLMConfig]:
    provider = _strict_object(value, _PROVIDER_FIELDS, "payload.provider")
    provider_id = _identifier(provider["provider_id"], "payload.provider.provider_id")
    if provider["protocol"] != PROTOCOL:
        raise ModelCredentialError("模型凭据 provider.protocol 不受支持")
    base_url = provider["base_url"]
    if (
        not isinstance(base_url, str)
        or not base_url
        or base_url != base_url.strip()
        or len(base_url) > 2048
        or _contains_control(base_url)
        or any(character.isspace() for character in base_url)
        or "%" in base_url
    ):
        raise ModelCredentialError("模型凭据 provider.base_url 非法")
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError as error:
        raise ModelCredentialError("模型凭据 provider.base_url 非法") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "//" in parsed.path
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise ModelCredentialError("受管模型地址必须是无账号/查询的 HTTPS URL")
    if port is not None and not 1 <= port <= 65_535:
        raise ModelCredentialError("模型凭据 provider.base_url 端口非法")
    hostname = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname.encode("ascii")
        except UnicodeEncodeError as error:
            raise ModelCredentialError(
                "模型凭据 provider.base_url 主机名非法"
            ) from error
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None
            for label in hostname.split(".")
        ):
            raise ModelCredentialError(
                "模型凭据 provider.base_url 主机名非法"
            ) from None
    else:
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ModelCredentialError("模型凭据 provider.base_url 主机不可用")
        hostname = address.compressed
    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host if port in {None, 443} else f"{host}:{port}"
    normalized_path = parsed.path.rstrip("/")
    normalized = urlunsplit(("https", authority, normalized_path, "", ""))
    if base_url != normalized:
        raise ModelCredentialError("模型凭据 provider.base_url 必须使用规范形式")
    model = provider["model"]
    if not isinstance(model, str) or _MODEL.fullmatch(model) is None:
        raise ModelCredentialError("模型凭据 provider.model 非法")
    capabilities = provider["capabilities"]
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or capabilities != sorted(set(capabilities))
        or any(
            not isinstance(capability, str)
            or capability not in SUPPORTED_MODEL_CAPABILITIES
            for capability in capabilities
        )
    ):
        raise ModelCredentialError("模型凭据 provider.capabilities 非法")
    timeout = provider["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 1.0 <= float(timeout) <= 120.0
    ):
        raise ModelCredentialError("模型凭据 provider.timeout_seconds 非法")
    retries = provider["max_retries"]
    if (
        isinstance(retries, bool)
        or not isinstance(retries, int)
        or not 0 <= retries <= 5
    ):
        raise ModelCredentialError("模型凭据 provider.max_retries 非法")
    canonical = {
        "provider_id": provider_id,
        "protocol": PROTOCOL,
        "base_url": normalized,
        "model": model,
        "capabilities": capabilities,
        # JSON integers and floating-point values have different canonical
        # bytes (``20`` versus ``20.0``).  Preserve the signed representation
        # for provider_config_sha256 while the runtime config below safely
        # converts either schema-valid number to float.
        "timeout_seconds": timeout,
        "max_retries": retries,
    }
    return canonical, LLMConfig(
        api_key="placeholder-only",
        base_url=normalized,
        model=model,
        timeout_seconds=float(timeout),
        max_retries=retries,
    )


def _api_key(value: Any) -> str:
    if not isinstance(value, str):
        raise ModelCredentialError("模型凭据 API key 格式非法")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ModelCredentialError("模型凭据 API key 格式非法") from error
    if (
        value != value.strip()
        or not 16 <= len(encoded) <= 4096
        or any(byte < 0x21 or byte > 0x7E for byte in encoded)
    ):
        raise ModelCredentialError("模型凭据 API key 格式非法")
    return value


def _validate_envelope_header(document: Any) -> dict[str, Any]:
    envelope = _strict_object(document, _ENVELOPE_FIELDS, "模型凭据包")
    protected = _strict_object(
        envelope["protected"], _PROTECTED_FIELDS, "模型凭据 protected"
    )
    if protected["contract_version"] != CONTRACT_VERSION:
        raise ModelCredentialError("模型凭据 contract_version 不受支持")
    if protected["bundle_kind"] != BUNDLE_KIND:
        raise ModelCredentialError("文件不是企业模型凭据包")
    _canonical_uuid4(protected["bundle_id"], "protected.bundle_id")
    _canonical_uuid4(protected["credential_id"], "protected.credential_id")
    version = protected["credential_version"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or not 1 <= version <= _MAX_VERSION
    ):
        raise ModelCredentialError("protected.credential_version 非法")
    issued_at = _parse_second_time(protected["issued_at"], "protected.issued_at")
    install_before = _parse_second_time(
        protected["install_before"], "protected.install_before"
    )
    runtime_not_after = _parse_second_time(
        protected["runtime_not_after"], "protected.runtime_not_after"
    )
    if not issued_at < install_before <= runtime_not_after:
        raise ModelCredentialError("模型凭据签发、安装和运行时间顺序非法")
    _identifier(protected["issuer_id"], "protected.issuer_id")
    _identifier(protected["issuer_key_id"], "protected.issuer_key_id")
    _issuer_key_epoch(protected["issuer_key_epoch"], "protected.issuer_key_epoch")
    subject = _strict_object(protected["subject"], _SUBJECT_FIELDS, "protected.subject")
    for name, value in subject.items():
        if name == "pair_id":
            _canonical_uuid4(value, "protected.subject.pair_id")
        else:
            _identifier(value, f"protected.subject.{name}")
    for name in ("payload_sha256", "provider_config_sha256"):
        if (
            not isinstance(protected[name], str)
            or _HEX_64.fullmatch(protected[name]) is None
        ):
            raise ModelCredentialError(f"protected.{name} 必须是小写 SHA-256")
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
        raise ModelCredentialError("模型凭据加密参数不受支持")
    _b64url(encryption["salt"], "encryption.salt", 16)
    _b64url(encryption["nonce"], "encryption.nonce", 12)
    if len(_b64url(envelope["ciphertext"], "ciphertext")) < 17:
        raise ModelCredentialError("模型凭据 ciphertext 长度非法")
    _b64url(envelope["signature"], "signature", 64)
    return envelope


def _verify_envelope(
    document: Any,
    issuers: Mapping[tuple[str, str], TrustedModelIssuer],
) -> tuple[dict[str, Any], TrustedModelIssuer]:
    envelope = _validate_envelope_header(document)
    protected = envelope["protected"]
    identity = (protected["issuer_id"], protected["issuer_key_id"])
    issuer = issuers.get(identity)
    if issuer is None:
        raise ModelCredentialError("模型凭据签发方不在发行版受信列表")
    if protected["issuer_key_epoch"] != issuer.issuer_key_epoch:
        raise ModelCredentialError("模型凭据签发 key epoch 与发行信任不匹配")
    signed = {"protected": protected, "ciphertext": envelope["ciphertext"]}
    try:
        issuer.public_key.verify(
            _b64url(envelope["signature"], "signature", 64),
            _canonical_bytes(signed),
        )
    except InvalidSignature as error:
        raise ModelCredentialError("模型凭据 Ed25519 签名验证失败") from error
    return envelope, issuer


def normalize_activation_code(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) > 128:
        raise ModelCredentialError("模型凭据激活码格式非法")
    selected = value
    if selected.endswith(b"\r\n"):
        selected = selected[:-2]
    elif selected.endswith(b"\n"):
        selected = selected[:-1]
    if _ACTIVATION_CODE.fullmatch(selected) is None:
        raise ModelCredentialError("模型凭据激活码格式非法")
    return selected


def read_activation_code_file(path: str | Path) -> bytes:
    resolved, encoded = _read_regular(path, "模型凭据激活码文件")
    if os.name != "nt":
        metadata = resolved.stat()
        if metadata.st_mode & 0o077:
            raise ModelCredentialError("模型凭据激活码文件必须由属主以 0600 独占")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ModelCredentialError("模型凭据激活码文件所有者不正确")
    return normalize_activation_code(encoded)


def _validate_expected_subject(
    subject: Mapping[str, Any], expected_subject: Mapping[str, str] | None
) -> None:
    if expected_subject is None:
        return
    unknown = set(expected_subject) - _SUBJECT_FIELDS
    if unknown:
        raise ModelCredentialError("模型凭据预期企业身份包含未知字段")
    for name, expected in expected_subject.items():
        selected = (
            _canonical_uuid4(expected, "expected_subject.pair_id")
            if name == "pair_id"
            else _identifier(expected, f"expected_subject.{name}")
        )
        if not hmac.compare_digest(str(subject.get(name)), selected):
            raise ModelCredentialError(f"模型凭据与本实例 {name} 不匹配")


def verify_and_decrypt_model_bundle(
    *,
    bundle_path: str | Path,
    activation_code: bytes,
    trust_store_path: str | Path,
    expected_subject: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> VerifiedModelBundle:
    """Verify the release trust anchor and signature before decrypting."""

    _, encoded = _read_regular(bundle_path, "模型凭据包")
    if len(encoded) > _MAX_BUNDLE_BYTES:
        raise ModelCredentialError("模型凭据包超过 2 MiB")
    document = _json_bytes(encoded, "模型凭据包")
    envelope, issuer = _verify_envelope(document, _trusted_issuers(trust_store_path))
    protected = envelope["protected"]
    _validate_expected_subject(protected["subject"], expected_subject)
    selected_now = (now or datetime.now(UTC)).astimezone(UTC)
    issued_at = _parse_time(protected["issued_at"], "protected.issued_at")
    if issued_at > selected_now + timedelta(minutes=5):
        raise ModelCredentialError("模型凭据签发时间晚于本机允许偏差")
    if selected_now >= _parse_time(
        protected["install_before"], "protected.install_before"
    ):
        raise ModelCredentialError("模型凭据已超过允许安装时间")
    if selected_now >= _parse_time(
        protected["runtime_not_after"], "protected.runtime_not_after"
    ):
        raise ModelCredentialError("模型凭据已过运行有效期")
    activation = normalize_activation_code(activation_code)
    encryption = protected["encryption"]
    try:
        key = Scrypt(
            salt=_b64url(encryption["salt"], "encryption.salt", 16),
            length=32,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        ).derive(activation)
        plaintext = AESGCM(key).decrypt(
            _b64url(encryption["nonce"], "encryption.nonce", 12),
            _b64url(envelope["ciphertext"], "ciphertext"),
            _canonical_bytes(protected),
        )
    except (ValueError, InvalidTag) as error:
        raise ModelCredentialError("模型凭据激活或认证解密失败") from error
    if len(plaintext) > _MAX_PAYLOAD_BYTES:
        raise ModelCredentialError("模型凭据 payload 超过 1 MiB")
    payload = _strict_object(
        _json_bytes(plaintext, "模型凭据 payload"),
        _PAYLOAD_FIELDS,
        "模型凭据 payload",
    )
    if _sha256(_canonical_bytes(payload)) != protected["payload_sha256"]:
        raise ModelCredentialError("模型凭据 payload 摘要不匹配")
    for name in ("bundle_id", "credential_id", "credential_version", "subject"):
        if payload[name] != protected[name]:
            raise ModelCredentialError(f"模型凭据 payload.{name} 与签名头不一致")
    if payload["kind"] != PAYLOAD_KIND:
        raise ModelCredentialError("模型凭据 payload.kind 不受支持")
    provider, template = _provider_config(payload["provider"])
    if _sha256(_canonical_bytes(provider)) != protected["provider_config_sha256"]:
        raise ModelCredentialError("模型凭据 provider 配置摘要不匹配")
    api_key = _api_key(payload["api_key"])
    return VerifiedModelBundle(
        envelope=envelope,
        payload=payload,
        config=LLMConfig(
            api_key=api_key,
            base_url=template.base_url,
            model=template.model,
            timeout_seconds=template.timeout_seconds,
            max_retries=template.max_retries,
        ),
        issuer=issuer,
    )


def _dpapi(value: bytes, entropy: bytes, *, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise ModelCredentialError("Windows DPAPI 只能在 Windows 上使用")

    class DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.c_uint32),
            ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    def make_blob(data: bytes) -> tuple[DataBlob, Any]:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return DataBlob(
            len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        ), buffer

    source, source_buffer = make_blob(value)
    entropy_blob, entropy_buffer = make_blob(entropy)
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
        description = None
        arguments = (
            ctypes.byref(source),
            "MineGuard managed model credential",
            ctypes.byref(entropy_blob),
            None,
            None,
            0x4,
            ctypes.byref(output),
        )
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
        description = ctypes.c_wchar_p()
        arguments = (
            ctypes.byref(source),
            ctypes.byref(description),
            ctypes.byref(entropy_blob),
            None,
            None,
            0,
            ctypes.byref(output),
        )
    function.restype = ctypes.c_bool
    if not function(*arguments):
        raise OSError(ctypes.get_last_error(), "Windows DPAPI 操作失败")
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        kernel32.LocalFree(output.pbData)
        if description:
            kernel32.LocalFree(description)
        _ = source_buffer, entropy_buffer


def _entropy(protected: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(
        b"MINEGUARD-MODEL-DPAPI-V1\x00"
        + str(protected["credential_id"]).encode("ascii")
        + b"\x00"
        + str(protected["bundle_id"]).encode("ascii")
        + b"\x00"
        + bytes.fromhex(protected["payload_sha256"])
    ).digest()


def _make_secret_store(
    verified: VerifiedModelBundle, protection: str
) -> tuple[dict[str, Any], str]:
    selected = protection
    if selected == "auto":
        selected = "dpapi-local-machine" if sys.platform == "win32" else "posix-0600"
    protected = verified.envelope["protected"]
    base = {
        "format": SECRET_STORE_FORMAT,
        "bundle_id": protected["bundle_id"],
        "credential_id": protected["credential_id"],
        "credential_version": protected["credential_version"],
    }
    secret = _canonical_bytes({"api_key": verified.config.api_key})
    if selected == "dpapi-local-machine":
        ciphertext = _dpapi(secret, _entropy(protected), protect=True)
        return {
            **base,
            "protection": DPAPI_PROTECTION,
            "payload_b64": base64.b64encode(ciphertext).decode("ascii"),
        }, DPAPI_PROTECTION
    if selected == "posix-0600":
        if os.name == "nt":
            raise ModelCredentialError("Windows 正式导入不得使用 POSIX 明文凭据库")
        return {
            **base,
            "protection": POSIX_PROTECTION,
            "secrets": {"api_key": verified.config.api_key},
        }, POSIX_PROTECTION
    raise ModelCredentialError("模型凭据 secret protection 取值非法")


def _load_secret_store(
    path: str | Path,
    protected: Mapping[str, Any],
    expected_protection: str,
) -> str:
    resolved, encoded = _read_regular(path, "模型凭据 secret store")
    store = _json_bytes(encoded, "模型凭据 secret store")
    common = {
        "format",
        "bundle_id",
        "credential_id",
        "credential_version",
        "protection",
    }
    if store.get("protection") == DPAPI_PROTECTION:
        _strict_object(store, common | {"payload_b64"}, "模型凭据 secret store")
    elif store.get("protection") == POSIX_PROTECTION:
        _strict_object(store, common | {"secrets"}, "模型凭据 secret store")
    else:
        raise ModelCredentialError("模型凭据 secret store protection 不受支持")
    if (
        store["format"] != SECRET_STORE_FORMAT
        or store["bundle_id"] != protected["bundle_id"]
        or store["credential_id"] != protected["credential_id"]
        or store["credential_version"] != protected["credential_version"]
        or store["protection"] != expected_protection
    ):
        raise ModelCredentialError("模型凭据 secret store 与签名包不绑定")
    if store["protection"] == DPAPI_PROTECTION:
        try:
            ciphertext = base64.b64decode(store["payload_b64"], validate=True)
        except (TypeError, ValueError, binascii.Error) as error:
            raise ModelCredentialError("模型凭据 DPAPI payload 非法") from error
        plaintext = _dpapi(ciphertext, _entropy(protected), protect=False)
        secrets = _json_bytes(plaintext, "模型凭据 DPAPI secrets")
    else:
        metadata = resolved.stat()
        if os.name == "nt" or metadata.st_mode & 0o077:
            raise ModelCredentialError("POSIX 模型凭据库必须由属主以 0600 独占")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise ModelCredentialError("POSIX 模型凭据库所有者不是当前服务身份")
        secrets = store["secrets"]
    if not isinstance(secrets, dict) or set(secrets) != {"api_key"}:
        raise ModelCredentialError("模型凭据 secret store 字段非法")
    return _api_key(secrets["api_key"])


def _load_lock(path: str | Path) -> dict[str, Any]:
    _, encoded = _read_regular(path, "模型凭据 lock")
    lock = _json_bytes(encoded, "模型凭据 lock")
    fields = {
        "format",
        "envelope",
        "issuer",
        "public_payload",
        "secret_store",
        "imported_at",
        "lock_hmac_algorithm",
        "lock_hmac",
    }
    _strict_object(lock, fields, "模型凭据 lock")
    if lock["format"] != LOCK_FORMAT:
        raise ModelCredentialError("模型凭据 lock format 不受支持")
    return lock


def model_credential_state_path(lock_path: str | Path) -> Path:
    """Derive the fixed anti-rollback state beside a credential lock."""

    selected = _absolute_path(lock_path, "模型凭据 lock")
    if selected.suffix:
        return selected.with_suffix(".state.json")
    return selected.with_name(selected.name + ".state.json")


def _state_document(
    envelope: Mapping[str, Any],
    *,
    accepted_at: str,
    api_key: str,
) -> dict[str, Any]:
    protected = envelope["protected"]
    state: dict[str, Any] = {
        "format": STATE_FORMAT,
        "credential_id": protected["credential_id"],
        "highest_credential_version": protected["credential_version"],
        "accepted_bundle_id": protected["bundle_id"],
        "accepted_envelope_sha256": _sha256(
            _canonical_bytes(envelope)
        ),
        "accepted_payload_sha256": protected["payload_sha256"],
        "issuer_id": protected["issuer_id"],
        "issuer_key_epoch": protected["issuer_key_epoch"],
        "accepted_at": accepted_at,
        "state_hmac_algorithm": "hmac-sha256-v1",
    }
    state["state_hmac"] = hmac.new(
        api_key.encode("utf-8"),
        _STATE_MAC_CONTEXT + _canonical_bytes(state),
        hashlib.sha256,
    ).hexdigest()
    return state


def _verify_state_document(
    path: Path,
    *,
    envelope: Mapping[str, Any],
    api_key: str,
    imported_at: str,
) -> None:
    _, encoded = _read_regular(path, "模型凭据防回退状态")
    state = _strict_object(
        _json_bytes(encoded, "模型凭据防回退状态"),
        {
            "format",
            "credential_id",
            "highest_credential_version",
            "accepted_bundle_id",
            "accepted_envelope_sha256",
            "accepted_payload_sha256",
            "issuer_id",
            "issuer_key_epoch",
            "accepted_at",
            "state_hmac_algorithm",
            "state_hmac",
        },
        "模型凭据防回退状态",
    )
    supplied_mac = state.pop("state_hmac")
    expected_mac = hmac.new(
        api_key.encode("utf-8"),
        _STATE_MAC_CONTEXT + _canonical_bytes(state),
        hashlib.sha256,
    ).hexdigest()
    if (
        state["state_hmac_algorithm"] != "hmac-sha256-v1"
        or not isinstance(supplied_mac, str)
        or not hmac.compare_digest(supplied_mac, expected_mac)
    ):
        raise ModelCredentialError("模型凭据防回退状态完整性校验失败")
    protected = envelope["protected"]
    expected = {
        "format": STATE_FORMAT,
        "credential_id": protected["credential_id"],
        "highest_credential_version": protected["credential_version"],
        "accepted_bundle_id": protected["bundle_id"],
        "accepted_envelope_sha256": _sha256(
            _canonical_bytes(envelope)
        ),
        "accepted_payload_sha256": protected["payload_sha256"],
        "issuer_id": protected["issuer_id"],
        "issuer_key_epoch": protected["issuer_key_epoch"],
        "accepted_at": imported_at,
        "state_hmac_algorithm": "hmac-sha256-v1",
    }
    if state != expected:
        raise ModelCredentialError("模型凭据版本或包摘要发生回退")


def _status(
    protected: Mapping[str, Any],
    issuer: TrustedModelIssuer,
    protection: str,
    provider: Mapping[str, Any],
) -> ModelCredentialStatus:
    subject = protected["subject"]
    return ModelCredentialStatus(
        managed=True,
        bundle_id=protected["bundle_id"],
        credential_id=protected["credential_id"],
        credential_version=protected["credential_version"],
        mine_id=subject["mine_id"],
        system_id=subject["system_id"],
        party_id=subject["party_id"],
        pair_id=subject["pair_id"],
        issuer_id=issuer.issuer_id,
        issuer_key_id=issuer.issuer_key_id,
        issuer_key_epoch=issuer.issuer_key_epoch,
        issuer_public_key_sha256=issuer.public_key_sha256,
        provider_id=provider["provider_id"],
        base_url=provider["base_url"],
        model=provider["model"],
        capabilities=tuple(provider["capabilities"]),
        runtime_not_after=protected["runtime_not_after"],
        secret_protection=protection,
        source="signed-managed-model-credential",
        state="managed",
    )


def load_model_credential_lock(
    *,
    lock_path: str | Path,
    secret_store_path: str | Path | None = None,
    trust_store_path: str | Path | None = None,
    expected_subject: Mapping[str, str] | None = None,
    now: datetime | None = None,
    require_runtime_valid: bool = True,
) -> tuple[LLMConfig, ModelCredentialStatus]:
    with _LOAD_LOCK:
        resolved_lock_path = _absolute_path(lock_path, "模型凭据 lock")
        lock = _load_lock(lock_path)
        issuers = _trusted_issuers(trust_store_path or default_model_trust_store_path())
        envelope, issuer = _verify_envelope(lock["envelope"], issuers)
        protected = envelope["protected"]
        issuer_lock = _strict_object(
            lock["issuer"],
            {
                "issuer_id",
                "issuer_key_id",
                "issuer_key_epoch",
                "public_key_sha256",
            },
            "模型凭据 lock.issuer",
        )
        if issuer_lock != {
            "issuer_id": issuer.issuer_id,
            "issuer_key_id": issuer.issuer_key_id,
            "issuer_key_epoch": issuer.issuer_key_epoch,
            "public_key_sha256": issuer.public_key_sha256,
        }:
            raise ModelCredentialError("模型凭据 lock 签发信任绑定不匹配")
        _validate_expected_subject(protected["subject"], expected_subject)
        imported_at = _parse_time(lock["imported_at"], "lock.imported_at")
        issued_at = _parse_time(protected["issued_at"], "protected.issued_at")
        install_before = _parse_time(
            protected["install_before"], "protected.install_before"
        )
        if (
            imported_at + timedelta(minutes=5) < issued_at
            or imported_at >= install_before
        ):
            raise ModelCredentialError("模型凭据 lock 导入时间不在签发安装窗口")
        runtime_not_after = _parse_time(
            protected["runtime_not_after"], "protected.runtime_not_after"
        )
        if (
            require_runtime_valid
            and (now or datetime.now(UTC)).astimezone(UTC) >= runtime_not_after
        ):
            raise ModelCredentialError("模型凭据已过运行有效期")
        store = _strict_object(
            lock["secret_store"], {"path", "protection"}, "模型凭据 lock.secret_store"
        )
        locked_store_path = _absolute_path(store["path"], "lock.secret_store.path")
        if secret_store_path is not None:
            supplied = _absolute_path(secret_store_path, "模型凭据 secret store")
            if os.path.normcase(str(supplied)) != os.path.normcase(
                str(locked_store_path)
            ):
                raise ModelCredentialError("模型凭据 secret store 路径被覆盖")
        api_key = _load_secret_store(
            locked_store_path, protected, str(store["protection"])
        )
        body = {name: value for name, value in lock.items() if name != "lock_hmac"}
        expected_mac = hmac.new(
            api_key.encode("utf-8"),
            _LOCK_MAC_CONTEXT + _canonical_bytes(body),
            hashlib.sha256,
        ).hexdigest()
        if (
            lock["lock_hmac_algorithm"] != "hmac-sha256-v1"
            or not isinstance(lock["lock_hmac"], str)
            or not hmac.compare_digest(lock["lock_hmac"], expected_mac)
        ):
            raise ModelCredentialError("模型凭据 lock 完整性校验失败")
        _verify_state_document(
            model_credential_state_path(resolved_lock_path),
            envelope=envelope,
            api_key=api_key,
            imported_at=lock["imported_at"],
        )
        public_payload = _strict_object(
            lock["public_payload"], _PAYLOAD_FIELDS - {"api_key"}, "lock.public_payload"
        )
        payload = {**public_payload, "api_key": api_key}
        if _sha256(_canonical_bytes(payload)) != protected["payload_sha256"]:
            raise ModelCredentialError("模型凭据 lock 无法重建签名 payload")
        if payload["kind"] != PAYLOAD_KIND:
            raise ModelCredentialError("模型凭据 lock payload.kind 不受支持")
        for name in ("bundle_id", "credential_id", "credential_version", "subject"):
            if payload[name] != protected[name]:
                raise ModelCredentialError("模型凭据 lock 与签名身份不一致")
        provider, template = _provider_config(payload["provider"])
        if _sha256(_canonical_bytes(provider)) != protected["provider_config_sha256"]:
            raise ModelCredentialError("模型凭据 lock provider 摘要不匹配")
        config = LLMConfig(
            api_key=api_key,
            base_url=template.base_url,
            model=template.model,
            timeout_seconds=template.timeout_seconds,
            max_retries=template.max_retries,
        )
        return config, _status(protected, issuer, str(store["protection"]), provider)


def _assert_upgrade(
    current_lock_path: str | Path,
    verified: VerifiedModelBundle,
    trust_store_path: str | Path,
) -> None:
    current_config, current_status = load_model_credential_lock(
        lock_path=current_lock_path,
        trust_store_path=trust_store_path,
        require_runtime_valid=False,
    )
    protected = verified.envelope["protected"]
    if (
        current_status.credential_id != protected["credential_id"]
        or current_status.issuer_id != protected["issuer_id"]
        or current_status.mine_id != protected["subject"]["mine_id"]
        or current_status.system_id != protected["subject"]["system_id"]
        or current_status.party_id != protected["subject"]["party_id"]
        or current_status.pair_id != protected["subject"]["pair_id"]
    ):
        raise ModelCredentialError("模型凭据更新与现有授权身份或签发链不一致")
    if protected["credential_version"] != (current_status.credential_version or 0) + 1:
        raise ModelCredentialError("模型凭据更新必须严格递增一个版本")
    if protected["issuer_key_epoch"] < (current_status.issuer_key_epoch or 0):
        raise ModelCredentialError("模型凭据更新禁止回退 issuer key epoch")
    if hmac.compare_digest(
        current_config.api_key.encode("utf-8"), verified.config.api_key.encode("utf-8")
    ):
        raise ModelCredentialError("模型凭据更新必须轮换 API key")


def install_model_credential_bundle(
    *,
    bundle_path: str | Path,
    activation_code: bytes,
    trust_store_path: str | Path,
    lock_output_path: str | Path,
    lock_environment_path: str | Path,
    secret_store_output_path: str | Path,
    secret_store_environment_path: str | Path,
    secret_protection: str = "auto",
    expected_subject: Mapping[str, str] | None = None,
    current_lock_path: str | Path | None = None,
    now: datetime | None = None,
) -> ModelCredentialResult:
    if expected_subject is None or set(expected_subject) != _SUBJECT_FIELDS:
        raise ModelCredentialError(
            "模型凭据正式导入必须提供完整 mine/system/party/pair 身份"
        )
    selected_now = (now or datetime.now(UTC)).astimezone(UTC)
    verified = verify_and_decrypt_model_bundle(
        bundle_path=bundle_path,
        activation_code=activation_code,
        trust_store_path=trust_store_path,
        expected_subject=expected_subject,
        now=selected_now,
    )
    protected = verified.envelope["protected"]
    if current_lock_path is None:
        if protected["credential_version"] != 1:
            raise ModelCredentialError("首次模型凭据安装必须从版本 1 开始")
    else:
        _assert_upgrade(current_lock_path, verified, trust_store_path)
    lock_output = _absolute_path(lock_output_path, "模型凭据 lock 输出")
    store_output = _absolute_path(secret_store_output_path, "模型凭据库输出")
    lock_environment = _absolute_path(lock_environment_path, "模型凭据 lock 正式路径")
    store_environment = _absolute_path(
        secret_store_environment_path, "模型凭据库正式路径"
    )
    state_output = model_credential_state_path(lock_output)
    state_environment = model_credential_state_path(lock_environment)
    if len({lock_output, store_output, state_output}) != 3 or len(
        {lock_environment, store_environment, state_environment}
    ) != 3:
        raise ModelCredentialError(
            "模型凭据 lock、secret store 与防回退状态路径必须不同"
        )
    store, protection = _make_secret_store(verified, secret_protection)
    public_payload = {
        name: value for name, value in verified.payload.items() if name != "api_key"
    }
    lock: dict[str, Any] = {
        "format": LOCK_FORMAT,
        "envelope": verified.envelope,
        "issuer": {
            "issuer_id": verified.issuer.issuer_id,
            "issuer_key_id": verified.issuer.issuer_key_id,
            "issuer_key_epoch": verified.issuer.issuer_key_epoch,
            "public_key_sha256": verified.issuer.public_key_sha256,
        },
        "public_payload": public_payload,
        "secret_store": {"path": str(store_environment), "protection": protection},
        "imported_at": utc_text(selected_now),
        "lock_hmac_algorithm": "hmac-sha256-v1",
    }
    lock["lock_hmac"] = hmac.new(
        verified.config.api_key.encode("utf-8"),
        _LOCK_MAC_CONTEXT + _canonical_bytes(lock),
        hashlib.sha256,
    ).hexdigest()
    state = _state_document(
        verified.envelope,
        accepted_at=lock["imported_at"],
        api_key=verified.config.api_key,
    )
    created: list[Path] = []
    try:
        _write_new(store_output, _canonical_bytes(store) + b"\n")
        created.append(store_output)
        _write_new(state_output, _canonical_bytes(state) + b"\n")
        created.append(state_output)
        _write_new(lock_output, _canonical_bytes(lock) + b"\n")
        created.append(lock_output)
    except BaseException:
        for created_path in reversed(created):
            with suppress(OSError):
                created_path.unlink()
        raise
    status = _status(
        protected, verified.issuer, protection, verified.payload["provider"]
    )
    return ModelCredentialResult(
        summary={
            **status.as_dict(),
            "lock_path": str(lock_output),
            "secret_store_path": str(store_output),
            "anti_rollback_state_path": str(state_output),
        }
    )


def load_model_credential_from_environment(
    *,
    expected_subject: Mapping[str, str] | None = None,
    now: datetime | None = None,
    environment: Mapping[str, str] | None = None,
) -> tuple[LLMConfig | None, ModelCredentialStatus]:
    selected = os.environ if environment is None else environment
    lock_path = str(selected.get(LOCK_ENVIRONMENT, "")).strip()
    store_path = str(selected.get(SECRET_STORE_ENVIRONMENT, "")).strip()
    if not lock_path and not store_path:
        return None, ModelCredentialStatus(managed=False)
    if not lock_path or not store_path:
        raise ModelCredentialError("模型凭据 lock 与 secret store 指针必须同时配置")
    plaintext = plaintext_model_environment_names(selected)
    if plaintext:
        raise ModelCredentialError("受管模型凭据禁止任何明文模型环境变量覆盖")
    trust_path = str(selected.get(TRUST_STORE_ENVIRONMENT, "")).strip()
    return load_model_credential_lock(
        lock_path=lock_path,
        secret_store_path=store_path,
        trust_store_path=(trust_path or default_model_trust_store_path()),
        expected_subject=expected_subject,
        now=now,
    )


def verify_model_credential_from_environment(
    *,
    expected_subject: Mapping[str, str] | None = None,
    expected_status: ModelCredentialStatus | None = None,
    now: datetime | None = None,
) -> ModelCredentialStatus:
    _config, status = load_model_credential_from_environment(
        expected_subject=expected_subject, now=now
    )
    if not status.managed:
        raise ModelCredentialError("受管模型凭据不存在")
    if expected_status is not None:
        fixed = (
            "bundle_id",
            "credential_id",
            "credential_version",
            "issuer_id",
            "issuer_key_id",
            "issuer_key_epoch",
            "issuer_public_key_sha256",
            "mine_id",
            "system_id",
            "party_id",
            "pair_id",
            "provider_id",
            "base_url",
            "model",
            "capabilities",
            "runtime_not_after",
            "secret_protection",
        )
        if any(
            getattr(status, name) != getattr(expected_status, name) for name in fixed
        ):
            raise ModelCredentialError("模型凭据运行期间已变化，请重启服务完成轮换")
    return status


def load_managed_model_credential(
    lock_path: str | Path,
    *,
    secret_store_path: str | Path | None = None,
    trust_store_path: str | Path | None = None,
    expected_subject: ModelCredentialSubject | Mapping[str, str] | None = None,
    now: datetime | None = None,
    check_runtime_validity: bool = True,
) -> ManagedModelCredential:
    """Load a managed credential without modifying process environment."""

    subject = (
        expected_subject.as_dict()
        if isinstance(expected_subject, ModelCredentialSubject)
        else expected_subject
    )
    config, status = load_model_credential_lock(
        lock_path=lock_path,
        secret_store_path=secret_store_path,
        trust_store_path=trust_store_path,
        expected_subject=subject,
        now=now,
        require_runtime_valid=check_runtime_validity,
    )
    return ManagedModelCredential(config=config, status=status)


read_model_activation_code_file = read_activation_code_file


__all__ = [
    "BUNDLE_KIND",
    "CONTRACT_VERSION",
    "DPAPI_PROTECTION",
    "LOCK_ENVIRONMENT",
    "ManagedModelCredential",
    "ModelCredentialError",
    "ModelCredentialResult",
    "ModelCredentialStatus",
    "ModelCredentialSubject",
    "ModelProviderPolicy",
    "POSIX_PROTECTION",
    "PROTOCOL",
    "SECRET_STORE_ENVIRONMENT",
    "STATE_FORMAT",
    "SUPPORTED_MODEL_CAPABILITIES",
    "TRUST_STORE_ENVIRONMENT",
    "TRUST_STORE_FORMAT",
    "VerifiedModelBundle",
    "default_model_trust_store_path",
    "install_model_credential_bundle",
    "load_model_credential_from_environment",
    "load_managed_model_credential",
    "load_model_credential_lock",
    "model_credential_state_path",
    "normalize_activation_code",
    "plaintext_model_environment_names",
    "read_activation_code_file",
    "read_model_activation_code_file",
    "release_model_trust_store_path",
    "validate_model_trust_store",
    "verify_and_decrypt_model_bundle",
    "verify_model_credential_from_environment",
]
