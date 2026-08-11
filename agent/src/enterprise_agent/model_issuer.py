"""Offline issuer for signed, enterprise-bound ``.mgllm`` bundles.

The API key is supplied separately from the non-secret profile and is never
returned.  This module is intended for the commercial operator's signing
workstation; the government Platform does not import it or its output secrets.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import model_credentials as credentials

_PROFILE_FIELDS = {
    "credential_id",
    "credential_version",
    "subject",
    "provider",
    "install_before",
    "runtime_not_after",
    "issuer_id",
    "issuer_key_id",
    "issuer_key_epoch",
}
_SUBJECT_FIELDS = {"mine_id", "system_id", "party_id", "pair_id"}
_PAYLOAD_FIELDS = {
    "kind",
    "bundle_id",
    "credential_id",
    "credential_version",
    "subject",
    "provider",
    "api_key",
}


@dataclass(frozen=True)
class ModelIssuerResult:
    summary: dict[str, Any]


@dataclass(frozen=True)
class ModelCredentialBundleResult:
    summary: dict[str, Any]


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _secret_bytes(
    value: bytes | str,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> bytes:
    if isinstance(value, str):
        try:
            selected = value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise credentials.ModelCredentialError(f"{label}格式非法") from error
    elif isinstance(value, bytes):
        selected = value
    else:
        raise credentials.ModelCredentialError(f"{label}格式非法")
    if (
        not minimum <= len(selected) <= maximum
        or b"\x00" in selected
        or selected.endswith((b"\r", b"\n"))
    ):
        raise credentials.ModelCredentialError(f"{label}格式非法")
    return selected


def _secret_file(path: str | Path, label: str) -> bytes:
    resolved, encoded = credentials._read_regular(path, label)  # noqa: SLF001
    if os.name != "nt":
        metadata = resolved.stat()
        if metadata.st_mode & 0o077:
            raise credentials.ModelCredentialError(f"{label}必须由属主以 0600 独占")
        if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
            raise credentials.ModelCredentialError(f"{label}所有者不是当前签发账号")
    if encoded.endswith(b"\r\n"):
        selected = encoded[:-2]
    elif encoded.endswith(b"\n"):
        selected = encoded[:-1]
    else:
        selected = encoded
    if selected.endswith((b"\r", b"\n")):
        raise credentials.ModelCredentialError(f"{label}只能包含一个末尾换行")
    return selected


def read_model_api_key_file(path: str | Path) -> bytes:
    selected = _secret_bytes(
        _secret_file(path, "模型 API key 文件"),
        "模型 API key",
        minimum=16,
        maximum=4096,
    )
    try:
        credentials._api_key(selected.decode("ascii"))  # noqa: SLF001
    except (UnicodeDecodeError, credentials.ModelCredentialError) as error:
        raise credentials.ModelCredentialError("模型 API key 格式非法") from error
    return selected


def read_model_issuer_passphrase_file(path: str | Path) -> bytes:
    return _secret_bytes(
        _secret_file(path, "模型签发私钥口令文件"),
        "模型签发私钥口令",
        minimum=12,
        maximum=1024,
    )


def _api_key(value: bytes | str) -> str:
    selected = _secret_bytes(
        value,
        "模型 API key",
        minimum=16,
        maximum=4096,
    )
    try:
        return credentials._api_key(selected.decode("ascii"))  # noqa: SLF001
    except (UnicodeDecodeError, credentials.ModelCredentialError) as error:
        raise credentials.ModelCredentialError("模型 API key 格式非法") from error


def _passphrase(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise credentials.ModelCredentialError("模型签发私钥口令格式非法")
    return _secret_bytes(
        value,
        "模型签发私钥口令",
        minimum=12,
        maximum=1024,
    )


def _fingerprint(public_key: Any) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(encoded).hexdigest()


def _distinct_paths(values: list[str | Path], label: str) -> list[Path]:
    selected = [Path(value).expanduser() for value in values]
    if any(not path.is_absolute() for path in selected):
        raise credentials.ModelCredentialError(f"{label}必须使用绝对路径")
    if len({os.path.normcase(str(path)) for path in selected}) != len(selected):
        raise credentials.ModelCredentialError(f"{label}必须彼此不同")
    return selected


def issuer_init(
    private_key_path: str | Path,
    public_key_path: str | Path,
    trust_store_path: str | Path,
    issuer_id: str,
    issuer_key_id: str,
    passphrase: bytes,
    *,
    issuer_key_epoch: int,
) -> ModelIssuerResult:
    """Create an encrypted Ed25519 key pair and one-entry trust store."""

    private_path, public_path, trust_path = _distinct_paths(
        [private_key_path, public_key_path, trust_store_path],
        "模型签发材料输出路径",
    )
    selected_issuer = credentials._identifier(issuer_id, "issuer_id")  # noqa: SLF001
    selected_key_id = credentials._identifier(  # noqa: SLF001
        issuer_key_id, "issuer_key_id"
    )
    selected_key_epoch = credentials._issuer_key_epoch(  # noqa: SLF001
        issuer_key_epoch
    )
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(_passphrase(passphrase)),
    )
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = _fingerprint(public_key)
    trust_store = {
        "format": credentials.TRUST_STORE_FORMAT,
        "issuers": [
            {
                "issuer_id": selected_issuer,
                "issuer_key_id": selected_key_id,
                "issuer_key_epoch": selected_key_epoch,
                "public_key_pem": public_pem.decode("ascii"),
                "public_key_sha256": fingerprint,
            }
        ],
    }
    created: list[Path] = []
    try:
        for path, content in (
            (private_path, private_pem),
            (public_path, public_pem),
            (trust_path, credentials._canonical_bytes(trust_store) + b"\n"),  # noqa: SLF001
        ):
            credentials._write_new(path, content)  # noqa: SLF001
            created.append(path)
    except BaseException:
        for path in reversed(created):
            with suppress(OSError):
                path.unlink()
        raise
    return ModelIssuerResult(
        summary={
            "valid": True,
            "algorithm": "Ed25519",
            "issuer_id": selected_issuer,
            "issuer_key_id": selected_key_id,
            "issuer_key_epoch": selected_key_epoch,
            "public_key_sha256": fingerprint,
            "private_key_path": str(private_path),
            "public_key_path": str(public_path),
            "trust_store_path": str(trust_path),
            "secrets_disclosed": False,
        }
    )


def compose_model_trust_store_create_new(
    input_paths: list[str | Path], output_path: str | Path
) -> ModelIssuerResult:
    """Merge independently generated trust stores for safe key rollover."""

    if not isinstance(input_paths, list) or not 2 <= len(input_paths) <= 32:
        raise credentials.ModelCredentialError(
            "trust store 合并必须提供 2-32 个输入文件"
        )
    output = Path(output_path).expanduser()
    if not output.is_absolute():
        raise credentials.ModelCredentialError("trust store 输出必须使用绝对路径")
    normalized_inputs = [Path(value).expanduser() for value in input_paths]
    if any(not path.is_absolute() for path in normalized_inputs):
        raise credentials.ModelCredentialError("trust store 输入必须使用绝对路径")
    if os.path.normcase(str(output)) in {
        os.path.normcase(str(path)) for path in normalized_inputs
    }:
        raise credentials.ModelCredentialError("trust store 输出不得覆盖任一输入")

    by_key_id: dict[str, credentials.TrustedModelIssuer] = {}
    by_identity: dict[tuple[str, str], credentials.TrustedModelIssuer] = {}
    by_fingerprint: dict[str, credentials.TrustedModelIssuer] = {}
    by_issuer_epoch: dict[tuple[str, int], credentials.TrustedModelIssuer] = {}
    for path in normalized_inputs:
        for issuer in credentials._trusted_issuers(path).values():  # noqa: SLF001
            identity = (issuer.issuer_id, issuer.issuer_key_id)
            existing_key = by_key_id.get(issuer.issuer_key_id)
            existing_identity = by_identity.get(identity)
            existing_fingerprint = by_fingerprint.get(issuer.public_key_sha256)
            existing_epoch = by_issuer_epoch.get(
                (issuer.issuer_id, issuer.issuer_key_epoch)
            )
            candidates = tuple(
                item
                for item in (
                    existing_key,
                    existing_identity,
                    existing_fingerprint,
                    existing_epoch,
                )
                if item is not None
            )
            if candidates and any(
                item.issuer_id != issuer.issuer_id
                or item.issuer_key_id != issuer.issuer_key_id
                or item.issuer_key_epoch != issuer.issuer_key_epoch
                or item.public_key_sha256 != issuer.public_key_sha256
                for item in candidates
            ):
                raise credentials.ModelCredentialError(
                    "trust store 合并发现 issuer/key/fingerprint 冲突"
                )
            by_key_id[issuer.issuer_key_id] = issuer
            by_identity[identity] = issuer
            by_fingerprint[issuer.public_key_sha256] = issuer
            by_issuer_epoch[(issuer.issuer_id, issuer.issuer_key_epoch)] = issuer
    if not 1 <= len(by_key_id) <= 32:
        raise credentials.ModelCredentialError(
            "合并后的 trust store 必须含 1-32 把公钥"
        )
    ordered = [by_key_id[key_id] for key_id in sorted(by_key_id)]
    document = {
        "format": credentials.TRUST_STORE_FORMAT,
        "issuers": [
            {
                "issuer_id": issuer.issuer_id,
                "issuer_key_id": issuer.issuer_key_id,
                "issuer_key_epoch": issuer.issuer_key_epoch,
                "public_key_pem": issuer.public_key_pem,
                "public_key_sha256": issuer.public_key_sha256,
            }
            for issuer in ordered
        ],
    }
    encoded = credentials._canonical_bytes(document) + b"\n"  # noqa: SLF001
    # Validate the exact bytes before the create-new write.
    credentials._parse_trusted_issuers(encoded)  # noqa: SLF001
    credentials._write_new(output, encoded)  # noqa: SLF001
    return ModelIssuerResult(
        summary={
            "valid": True,
            "trust_store_path": str(output),
            "issuer_count": len(ordered),
            "issuer_ids": [issuer.issuer_id for issuer in ordered],
            "issuer_key_ids": [issuer.issuer_key_id for issuer in ordered],
            "issuer_key_epochs": [issuer.issuer_key_epoch for issuer in ordered],
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "secrets_disclosed": False,
        }
    )


def _load_private_key(path: str | Path, passphrase: bytes) -> Ed25519PrivateKey:
    encoded = _secret_file(path, "模型签发私钥")
    try:
        key = serialization.load_pem_private_key(
            encoded,
            password=_passphrase(passphrase),
        )
    except (TypeError, ValueError) as error:
        raise credentials.ModelCredentialError("模型签发私钥或口令无效") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise credentials.ModelCredentialError("模型签发私钥必须是 Ed25519")
    return key


def _second_time(value: Any, label: str) -> tuple[str, datetime]:
    selected = credentials._parse_time(value, label)  # noqa: SLF001
    rendered = selected.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if value != rendered:
        raise credentials.ModelCredentialError(f"{label} 必须精确到 UTC 秒")
    return rendered, selected


def _now(value: datetime | None) -> datetime:
    selected = value or datetime.now(UTC)
    if selected.tzinfo is None or selected.utcoffset() is None:
        raise credentials.ModelCredentialError("now 必须包含时区")
    return selected.astimezone(UTC).replace(microsecond=0)


def _validate_profile_document(value: Any, issued_at: datetime) -> dict[str, Any]:
    document = credentials._strict_object(  # noqa: SLF001
        value,
        _PROFILE_FIELDS,
        "模型凭据签发 profile",
    )
    version = document["credential_version"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or not 1 <= version <= 2_147_483_647
    ):
        raise credentials.ModelCredentialError("profile.credential_version 非法")
    subject = credentials._strict_object(  # noqa: SLF001
        document["subject"], _SUBJECT_FIELDS, "profile.subject"
    )
    canonical_subject = {
        name: credentials._identifier(subject[name], f"profile.subject.{name}")  # noqa: SLF001
        for name in ("mine_id", "system_id", "party_id")
    }
    canonical_subject["pair_id"] = credentials._canonical_uuid4(  # noqa: SLF001
        subject["pair_id"], "profile.subject.pair_id"
    )
    provider, _template = credentials._provider_config(document["provider"])  # noqa: SLF001
    if provider != document["provider"]:
        raise credentials.ModelCredentialError("profile.provider 必须使用规范形式")
    install_text, install_before = _second_time(
        document["install_before"], "profile.install_before"
    )
    runtime_text, runtime_not_after = _second_time(
        document["runtime_not_after"], "profile.runtime_not_after"
    )
    if not issued_at < install_before <= runtime_not_after:
        raise credentials.ModelCredentialError("模型凭据签发、安装和运行时间顺序非法")
    return {
        "credential_id": credentials._canonical_uuid4(  # noqa: SLF001
            document["credential_id"], "profile.credential_id"
        ),
        "credential_version": version,
        "subject": canonical_subject,
        "provider": provider,
        "install_before": install_text,
        "runtime_not_after": runtime_text,
        "issuer_id": credentials._identifier(  # noqa: SLF001
            document["issuer_id"], "profile.issuer_id"
        ),
        "issuer_key_id": credentials._identifier(  # noqa: SLF001
            document["issuer_key_id"], "profile.issuer_key_id"
        ),
        "issuer_key_epoch": credentials._issuer_key_epoch(  # noqa: SLF001
            document["issuer_key_epoch"], "profile.issuer_key_epoch"
        ),
    }


def _profile(path: str | Path, issued_at: datetime) -> dict[str, Any]:
    _, encoded = credentials._read_regular(path, "模型凭据签发 profile")  # noqa: SLF001
    return _validate_profile_document(
        credentials._json_bytes(encoded, "模型凭据签发 profile"),  # noqa: SLF001
        issued_at,
    )


def load_model_credential_profile(
    path: str | Path, *, now: datetime | None = None
) -> dict[str, Any]:
    """Load and strictly normalize a non-secret signing profile."""

    return _profile(path, _now(now))


def write_model_credential_profile_create_new(
    path: str | Path,
    profile: dict[str, Any],
    *,
    now: datetime | None = None,
) -> Path:
    """Validate and create one non-secret profile without overwriting."""

    output = Path(path).expanduser()
    if not output.is_absolute():
        raise credentials.ModelCredentialError("模型凭据 profile 输出必须使用绝对路径")
    normalized = _validate_profile_document(profile, _now(now))
    credentials._write_new(  # noqa: SLF001
        output,
        credentials._canonical_bytes(normalized) + b"\n",  # noqa: SLF001
    )
    return output


def write_model_activation_file_create_new(
    path: str | Path, activation_code: bytes
) -> Path:
    """Create one separately delivered activation file without overwriting."""

    output = Path(path).expanduser()
    if not output.is_absolute():
        raise credentials.ModelCredentialError("模型凭据激活码输出必须使用绝对路径")
    selected = credentials.normalize_activation_code(activation_code)
    credentials._write_new(output, selected + b"\n")  # noqa: SLF001
    return output


def _decode_previous(
    path: str | Path,
    activation_code: bytes | str,
    private_key: Ed25519PrivateKey,
    profile: dict[str, Any],
    trust_store_path: str | Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _, encoded = credentials._read_regular(path, "上一版模型凭据包")  # noqa: SLF001
    if len(encoded) > 2 * 1024 * 1024:
        raise credentials.ModelCredentialError("上一版模型凭据包超过 2 MiB")
    document = credentials._json_bytes(encoded, "上一版模型凭据包")  # noqa: SLF001
    if trust_store_path is not None:
        trusted = credentials._trusted_issuers(trust_store_path)  # noqa: SLF001
    else:
        public_key = private_key.public_key()
        issuer = credentials.TrustedModelIssuer(
            issuer_id=profile["issuer_id"],
            issuer_key_id=profile["issuer_key_id"],
            issuer_key_epoch=profile["issuer_key_epoch"],
            public_key=public_key,
            public_key_pem=public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("ascii"),
            public_key_sha256=_fingerprint(public_key),
        )
        trusted = {(profile["issuer_id"], profile["issuer_key_id"]): issuer}
    envelope, selected_issuer = credentials._verify_envelope(  # noqa: SLF001
        document, trusted
    )
    protected = envelope["protected"]
    if selected_issuer.issuer_id != profile["issuer_id"]:
        raise credentials.ModelCredentialError("上一版模型凭据与当前 issuer_id 不一致")
    activation = credentials.normalize_activation_code(
        _secret_bytes(
            activation_code,
            "上一版模型凭据激活码",
            minimum=43,
            maximum=43,
        )
    )
    encryption = protected["encryption"]
    try:
        derived = Scrypt(
            salt=credentials._b64url(  # noqa: SLF001
                encryption["salt"], "encryption.salt", 16
            ),
            length=32,
            n=16_384,
            r=8,
            p=1,
        ).derive(activation)
        plaintext = AESGCM(derived).decrypt(
            credentials._b64url(  # noqa: SLF001
                encryption["nonce"], "encryption.nonce", 12
            ),
            credentials._b64url(envelope["ciphertext"], "ciphertext"),  # noqa: SLF001
            credentials._canonical_bytes(protected),  # noqa: SLF001
        )
    except (ValueError, InvalidTag) as error:
        raise credentials.ModelCredentialError(
            "上一版模型凭据激活或认证解密失败"
        ) from error
    if len(plaintext) > 1024 * 1024:
        raise credentials.ModelCredentialError("上一版模型凭据 payload 超过 1 MiB")
    payload = credentials._strict_object(  # noqa: SLF001
        credentials._json_bytes(plaintext, "上一版模型凭据 payload"),  # noqa: SLF001
        _PAYLOAD_FIELDS,
        "上一版模型凭据 payload",
    )
    if (
        credentials._sha256(  # noqa: SLF001
            credentials._canonical_bytes(payload)  # noqa: SLF001
        )
        != protected["payload_sha256"]
    ):
        raise credentials.ModelCredentialError("上一版模型凭据 payload 摘要不匹配")
    for name in ("bundle_id", "credential_id", "credential_version", "subject"):
        if payload[name] != protected[name]:
            raise credentials.ModelCredentialError("上一版模型凭据签名身份不一致")
    if payload["kind"] != credentials.PAYLOAD_KIND:
        raise credentials.ModelCredentialError("上一版模型凭据 kind 不受支持")
    provider, _template = credentials._provider_config(payload["provider"])  # noqa: SLF001
    if (
        credentials._sha256(  # noqa: SLF001
            credentials._canonical_bytes(provider)  # noqa: SLF001
        )
        != protected["provider_config_sha256"]
    ):
        raise credentials.ModelCredentialError("上一版模型 provider 摘要不匹配")
    payload["api_key"] = credentials._api_key(payload["api_key"])  # noqa: SLF001
    return payload, protected


def create_model_credential_bundle(
    profile_path: str | Path,
    api_key: bytes | str,
    issuer_private_key_path: str | Path,
    issuer_passphrase: bytes,
    bundle_output_path: str | Path,
    activation_output_path: str | Path,
    *,
    issuer_trust_store_path: str | Path,
    previous_bundle_path: str | Path | None = None,
    previous_activation_code: bytes | str | None = None,
    previous_trust_store_path: str | Path | None = None,
    now: datetime | None = None,
) -> ModelCredentialBundleResult:
    """Create one bundle and a separate 256-bit activation-code file."""

    issued_at = _now(now)
    profile = _profile(profile_path, issued_at)
    selected_api_key = _api_key(api_key)
    private_key = _load_private_key(issuer_private_key_path, issuer_passphrase)
    trusted = credentials._trusted_issuers(  # noqa: SLF001
        issuer_trust_store_path
    )
    selected_issuer = trusted.get((profile["issuer_id"], profile["issuer_key_id"]))
    if (
        selected_issuer is None
        or selected_issuer.issuer_key_epoch != profile["issuer_key_epoch"]
        or not hmac.compare_digest(
            selected_issuer.public_key_sha256,
            _fingerprint(private_key.public_key()),
        )
    ):
        raise credentials.ModelCredentialError(
            "模型签发 profile、私钥与发行 trust store 的 issuer key 不匹配"
        )
    previous_requested = (
        previous_bundle_path is not None
        or previous_activation_code is not None
        or previous_trust_store_path is not None
    )
    if previous_requested and (
        previous_bundle_path is None or previous_activation_code is None
    ):
        raise credentials.ModelCredentialError(
            "模型凭据轮换必须同时提供上一版包和激活码"
        )
    if previous_requested:
        assert previous_bundle_path is not None
        assert previous_activation_code is not None
        previous, previous_protected = _decode_previous(
            previous_bundle_path,
            previous_activation_code,
            private_key,
            profile,
            previous_trust_store_path,
        )
        if (
            previous["credential_id"] != profile["credential_id"]
            or previous["subject"] != profile["subject"]
        ):
            raise credentials.ModelCredentialError(
                "模型凭据轮换不得改变 credential_id 或企业实例身份"
            )
        if profile["credential_version"] != previous["credential_version"] + 1:
            raise credentials.ModelCredentialError("模型凭据轮换版本必须精确递增 1")
        if profile["issuer_key_epoch"] < previous_protected["issuer_key_epoch"]:
            raise credentials.ModelCredentialError(
                "模型凭据轮换禁止回退 issuer key epoch"
            )
        if hmac.compare_digest(
            previous["api_key"].encode("ascii"), selected_api_key.encode("ascii")
        ):
            raise credentials.ModelCredentialError("模型凭据轮换必须更换 API key")
    elif profile["credential_version"] != 1:
        raise credentials.ModelCredentialError("首次模型凭据签发必须从版本 1 开始")

    bundle_path, activation_path = _distinct_paths(
        [bundle_output_path, activation_output_path],
        "模型凭据包与激活码输出路径",
    )
    bundle_id = str(uuid4())
    activation = credentials.normalize_activation_code(
        _b64url(secrets.token_bytes(32)).encode("ascii")
    )
    payload = {
        "kind": credentials.PAYLOAD_KIND,
        "bundle_id": bundle_id,
        "credential_id": profile["credential_id"],
        "credential_version": profile["credential_version"],
        "subject": profile["subject"],
        "provider": profile["provider"],
        "api_key": selected_api_key,
    }
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    protected = {
        "contract_version": credentials.CONTRACT_VERSION,
        "bundle_kind": credentials.BUNDLE_KIND,
        "bundle_id": bundle_id,
        "credential_id": profile["credential_id"],
        "credential_version": profile["credential_version"],
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "install_before": profile["install_before"],
        "runtime_not_after": profile["runtime_not_after"],
        "issuer_id": profile["issuer_id"],
        "issuer_key_id": profile["issuer_key_id"],
        "issuer_key_epoch": profile["issuer_key_epoch"],
        "subject": profile["subject"],
        "payload_sha256": credentials._sha256(  # noqa: SLF001
            credentials._canonical_bytes(payload)  # noqa: SLF001
        ),
        "provider_config_sha256": credentials._sha256(  # noqa: SLF001
            credentials._canonical_bytes(profile["provider"])  # noqa: SLF001
        ),
        "encryption": {
            "algorithm": "aes-256-gcm",
            "kdf": "scrypt",
            "salt": _b64url(salt),
            "n": 16_384,
            "r": 8,
            "p": 1,
            "nonce": _b64url(nonce),
        },
    }
    key = Scrypt(salt=salt, length=32, n=16_384, r=8, p=1).derive(activation)
    ciphertext = _b64url(
        AESGCM(key).encrypt(
            nonce,
            credentials._canonical_bytes(payload),  # noqa: SLF001
            credentials._canonical_bytes(protected),  # noqa: SLF001
        )
    )
    signed = {"protected": protected, "ciphertext": ciphertext}
    envelope = {
        **signed,
        "signature": _b64url(
            private_key.sign(credentials._canonical_bytes(signed))  # noqa: SLF001
        ),
    }
    created: list[Path] = []
    try:
        credentials._write_new(  # noqa: SLF001
            bundle_path,
            credentials._canonical_bytes(envelope) + b"\n",  # noqa: SLF001
        )
        created.append(bundle_path)
        credentials._write_new(activation_path, activation + b"\n")  # noqa: SLF001
        created.append(activation_path)
    except BaseException:
        for path in reversed(created):
            with suppress(OSError):
                path.unlink()
        raise
    return ModelCredentialBundleResult(
        summary={
            "valid": True,
            "bundle_id": bundle_id,
            "credential_id": profile["credential_id"],
            "credential_version": profile["credential_version"],
            **profile["subject"],
            "issuer_id": profile["issuer_id"],
            "issuer_key_id": profile["issuer_key_id"],
            "issuer_key_epoch": profile["issuer_key_epoch"],
            "public_key_sha256": _fingerprint(private_key.public_key()),
            "provider_id": profile["provider"]["provider_id"],
            "base_url": profile["provider"]["base_url"],
            "model": profile["provider"]["model"],
            "capabilities": list(profile["provider"]["capabilities"]),
            "install_before": profile["install_before"],
            "runtime_not_after": profile["runtime_not_after"],
            "bundle_path": str(bundle_path),
            "activation_file": str(activation_path),
            "activation_codes_disclosed": False,
            "secrets_disclosed": False,
        }
    )


__all__ = [
    "ModelCredentialBundleResult",
    "ModelIssuerResult",
    "compose_model_trust_store_create_new",
    "create_model_credential_bundle",
    "issuer_init",
    "load_model_credential_profile",
    "read_model_api_key_file",
    "read_model_issuer_passphrase_file",
    "write_model_activation_file_create_new",
    "write_model_credential_profile_create_new",
]
