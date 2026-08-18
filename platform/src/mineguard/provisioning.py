"""Signed, activation-code encrypted per-mine provisioning bundles.

The provisioning protocol is deliberately independent from both product
runtimes.  Platform creates a pair of opaque files from one approved profile:
an Agent profile (``.mgprov``) and the matching Platform registration
(``.mgreg``).  The Agent activation material and issuer public key are embedded
in its single enterprise delivery file; protected government-side copies of
the two distinct activation codes remain available for recovery and audit.
Activation values are never returned in the result object.

Registry locks are checked whenever ``clients.json`` is loaded.  A legacy
manual registry remains readable, while any registry that declares a
``provisioning_lock`` fails closed if its signed client material was changed.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import tempfile
import time
import unicodedata
import uuid
from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

CONTRACT_VERSION = "mineguard-provisioning-bundle-v1"
ENTERPRISE_ACCESS_PACKAGE_FORMAT = "mineguard-enterprise-access-package-v1"
AGENT_BUNDLE_KIND = "enterprise-agent-provisioning"
REGISTRATION_BUNDLE_KIND = "platform-client-registration"
REGISTRY_LOCK_VERSION = "mineguard-platform-registry-lock-v1"
SCRYPT_N = 16_384
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PROFILE_VERSION = 2_147_483_647
REGISTRY_LOCK_TIMEOUT_SECONDS = 30.0

MANAGED_REQUIRED_ENV = "MINEGUARD_PROVISIONING_MANAGED_REQUIRED"
TRUSTED_PUBLIC_KEY_FILE_ENV = "MINEGUARD_PROVISIONING_TRUSTED_PUBLIC_KEY_FILE"
EXPECTED_PUBLIC_KEY_SHA256_ENV = (
    "MINEGUARD_PROVISIONING_EXPECTED_PUBLIC_KEY_SHA256"
)
EXPECTED_ISSUER_KEY_ID_ENV = "MINEGUARD_PROVISIONING_EXPECTED_ISSUER_KEY_ID"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_DATETIME = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}(?:\.[0-9]{1,6})?Z$"
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
        "待填",
        "待配置",
        "待补充",
        "未分类",
        "未知",
        "占位",
        "部署时",
        "示例",
        "示例值",
        "测试",
        "测试值",
    }
)
_CONTEXT_KEYS = frozenset(
    {
        "capacity_band",
        "mining_method",
        "shift_system",
        "coal_type",
        "operating_regime",
    }
)
_SUBJECT_KEYS = frozenset({"mine_id", "system_id", "party_id"})
_PROFILE_KEYS = frozenset(
    {
        "profile_version",
        "expires_at",
        "issuer_id",
        "issuer_key_id",
        "subject",
        "comparison_context",
        "agent",
        "platform_identity",
    }
)
_AGENT_PROFILE_KEYS = frozenset(
    {
        "platform_base_url",
        "reporting_timezone",
    }
)
_PLATFORM_IDENTITY_KEYS = frozenset({"system_id", "party_id", "key_id"})
_PROTECTED_KEYS = frozenset(
    {
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
)
_ENCRYPTION_KEYS = frozenset(
    {"algorithm", "kdf", "salt", "n", "r", "p", "nonce"}
)
_ENVELOPE_KEYS = frozenset({"protected", "ciphertext", "signature"})
_AGENT_PAYLOAD_KEYS = frozenset(
    {"kind", "bundle_id", "pair_id", "profile_version", "config", "locked_keys"}
)
_REGISTRATION_PAYLOAD_KEYS = frozenset(
    {
        "kind",
        "bundle_id",
        "pair_id",
        "profile_version",
        "client",
        "platform_identity",
    }
)

_REGISTRATION_LOCK_KEYS = frozenset(
    {
        "bundle_id",
        "pair_id",
        "profile_version",
        "subject",
        "client_sha256",
        "platform_identity",
        "envelope",
        "issuer_key_id",
        "issuer_public_key_sha256",
    }
)


class ProvisioningError(ValueError):
    """Safe provisioning error that never includes activation or HMAC values."""


def canonical_json(value: object) -> bytes:
    """Return the protocol's single canonical JSON representation."""

    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ProvisioningError("provisioning document is not canonical JSON") from error


def _b64url_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: object, *, label: str, length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ProvisioningError(f"{label} must be unpadded base64url")
    if re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ProvisioningError(f"{label} must be unpadded base64url")
    try:
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise ProvisioningError(f"{label} must be unpadded base64url") from error
    if _b64url_encode(decoded) != value:
        raise ProvisioningError(f"{label} is not canonical base64url")
    if length is not None and len(decoded) != length:
        raise ProvisioningError(f"{label} has an invalid length")
    return decoded


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvisioningError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ProvisioningError(f"non-finite JSON number is forbidden: {value}")


def _load_json_bytes(payload: bytes, *, label: str) -> Any:
    if len(payload) > MAX_JSON_BYTES:
        raise ProvisioningError(f"{label} exceeds the 4 MiB safety limit")
    try:
        text = payload.decode("utf-8-sig")
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisioningError(f"{label} must contain UTF-8 JSON") from error


def _reject_linked_path(path: Path, *, label: str, allow_missing_leaf: bool = False) -> None:
    """Reject symlink/reparse traversal for every existing path component."""

    absolute = path.expanduser().absolute()
    candidates = [absolute, *absolute.parents]
    for index, candidate in enumerate(candidates):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            if index == 0 and allow_missing_leaf:
                continue
            continue
        except OSError as error:
            raise ProvisioningError(f"{label} path cannot be inspected") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ProvisioningError(f"{label} must not traverse symbolic links")
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        attributes = getattr(metadata, "st_file_attributes", 0)
        if attributes & reparse_flag:
            raise ProvisioningError(f"{label} must not traverse reparse points")


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        # Windows cannot open/fsync a directory. Windows deployments must rely
        # on the installer-created, service-only ACL on the containing tree.
        pass


def _read_regular_file(path_value: str | os.PathLike[str], *, label: str) -> bytes:
    path = Path(path_value).expanduser().absolute()
    _reject_linked_path(path, label=label)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProvisioningError(f"{label} cannot be read: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ProvisioningError(f"{label} must be a regular non-linked file")
    if metadata.st_size > MAX_JSON_BYTES:
        raise ProvisioningError(f"{label} exceeds the 4 MiB safety limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProvisioningError(f"{label} cannot be read: {path}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise ProvisioningError(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_JSON_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_JSON_BYTES:
                raise ProvisioningError(f"{label} exceeds the 4 MiB safety limit")
        payload = b"".join(chunks)
        closed = os.fstat(descriptor)
        if (
            (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (closed.st_dev, closed.st_ino, closed.st_size, closed.st_mtime_ns)
        ):
            raise ProvisioningError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    if len(payload) > MAX_JSON_BYTES:
        raise ProvisioningError(f"{label} exceeds the 4 MiB safety limit")
    return payload


def _load_json_file(path: str | os.PathLike[str], *, label: str) -> Any:
    return _load_json_bytes(_read_regular_file(path, label=label), label=label)


def read_secret_file(path: str | os.PathLike[str], *, label: str) -> bytes:
    """Read one newline-terminated local credential without exposing it."""

    raw = _read_regular_file(path, label=label)
    # Accept at most one conventional line terminator. Do not silently change
    # the activation/passphrase bytes beyond that transport newline.
    if raw.endswith(b"\r\n"):
        value = raw[:-2]
    elif raw.endswith(b"\n"):
        value = raw[:-1]
    else:
        value = raw
    if not value:
        raise ProvisioningError(f"{label} must not be empty")
    if b"\x00" in value or b"\r" in value or b"\n" in value:
        raise ProvisioningError(f"{label} must contain exactly one secret line")
    return value


def _write_new_private(path: Path, payload: bytes) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_path(path.parent, label="output directory")
    _reject_linked_path(path, label="output file", allow_missing_leaf=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _paths_share_tree(first: Path, second: Path) -> bool:
    """Return whether two resolved paths are equal or one contains the other."""

    try:
        first.relative_to(second)
        return True
    except ValueError:
        try:
            second.relative_to(first)
            return True
        except ValueError:
            return False


def _prepare_delivery_directories(
    *,
    output_directory: str | os.PathLike[str] | None,
    activation_directory: str | os.PathLike[str] | None,
    enterprise_bundle_directory: str | os.PathLike[str] | None,
    platform_registration_directory: str | os.PathLike[str] | None,
    enterprise_activation_directory: str | os.PathLike[str] | None,
    platform_activation_directory: str | os.PathLike[str] | None,
) -> tuple[Path, Path, Path, Path, bool]:
    """Resolve either the four-tree delivery layout or the legacy two-tree layout."""

    legacy_values = (output_directory, activation_directory)
    split_values = (
        enterprise_bundle_directory,
        platform_registration_directory,
        enterprise_activation_directory,
        platform_activation_directory,
    )
    legacy_requested = any(value is not None for value in legacy_values)
    split_requested = any(value is not None for value in split_values)
    if legacy_requested and split_requested:
        raise ProvisioningError(
            "legacy output directories cannot be mixed with split delivery directories"
        )
    if split_requested:
        if any(value is None for value in split_values):
            raise ProvisioningError(
                "split delivery requires enterprise bundle, Platform registration, "
                "enterprise activation, and Platform activation directories"
            )
        raw_directories = {
            "enterprise bundle output directory": enterprise_bundle_directory,
            "Platform registration output directory": platform_registration_directory,
            "enterprise activation output directory": enterprise_activation_directory,
            "Platform activation output directory": platform_activation_directory,
        }
        legacy_layout = False
    elif legacy_requested:
        if output_directory is None or activation_directory is None:
            raise ProvisioningError(
                "legacy delivery requires both output_directory and activation_directory"
            )
        raw_directories = {
            "bundle output directory": output_directory,
            "activation output directory": activation_directory,
        }
        legacy_layout = True
    else:
        raise ProvisioningError(
            "four split delivery directories are required; the legacy two-directory "
            "layout is accepted only for compatibility"
        )

    directories: dict[str, Path] = {}
    for label, value in raw_directories.items():
        assert value is not None
        directory = Path(value).expanduser().absolute()
        _reject_linked_path(directory, label=label, allow_missing_leaf=True)
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise ProvisioningError(f"{label} cannot be created") from error
        _reject_linked_path(directory, label=label)
        if not directory.is_dir():
            raise ProvisioningError(f"{label} must be a directory")
        try:
            os.chmod(directory, 0o700)
        except OSError:
            if os.name != "nt":
                raise
        directories[label] = directory.resolve(strict=True)

    resolved = list(directories.items())
    for index, (first_label, first) in enumerate(resolved):
        for second_label, second in resolved[index + 1 :]:
            if _paths_share_tree(first, second):
                raise ProvisioningError(
                    f"{first_label} and {second_label} must be separate directory trees"
                )

    if legacy_layout:
        bundle = directories["bundle output directory"]
        activation = directories["activation output directory"]
        return bundle, bundle, activation, activation, True
    return (
        directories["enterprise bundle output directory"],
        directories["Platform registration output directory"],
        directories["enterprise activation output directory"],
        directories["Platform activation output directory"],
        False,
    )


def _atomic_write_private(path: Path, payload: bytes) -> None:
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_path(path.parent, label="client registry directory")
    _reject_linked_path(path, label="client registry", allow_missing_leaf=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


@contextmanager
def _registry_transaction_lock(path: Path):
    """Serialize the full read/validate/replace transaction across processes."""

    registry_path = path.expanduser().absolute()
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    _reject_linked_path(registry_path.parent, label="client registry directory")
    lock_path = registry_path.with_name(registry_path.name + ".provisioning.lock")
    _reject_linked_path(lock_path, label="client registry lock", allow_missing_leaf=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    acquired = False
    deadline = time.monotonic() + REGISTRY_LOCK_TIMEOUT_SECONDS
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ProvisioningError("client registry lock must be a private regular file")
        if opened.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        while not acquired:
            try:
                if os.name == "nt":  # pragma: no cover - exercised by Windows CI
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError as error:
                if time.monotonic() >= deadline:
                    raise ProvisioningError(
                        "timed out waiting for the client registry transaction lock"
                    ) from error
                time.sleep(0.05)
        yield
    finally:
        if acquired:
            try:
                if os.name == "nt":  # pragma: no cover - exercised by Windows CI
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(descriptor)


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProvisioningError(f"{label} must be a valid identifier")
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
    ascii_tokens = {
        token for token in re.split(r"[^a-z0-9]+", folded) if token
    }
    if ascii_tokens & {token for token in _PLACEHOLDER_TOKENS if token.isascii()}:
        return True
    return any(
        marker in folded
        for marker in _PLACEHOLDER_TOKENS
        if not marker.isascii()
    )


def _production_identifier(value: object, *, label: str) -> str:
    identifier = _identifier(value, label=label)
    if _looks_placeholder(identifier):
        raise ProvisioningError(f"{label} must not be a placeholder identifier")
    return identifier


def _display_name(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 128:
        raise ProvisioningError(f"{label} must contain 1..128 characters")
    if _contains_control(value):
        raise ProvisioningError(f"{label} contains forbidden control characters")
    normalized = value.strip()
    if _looks_placeholder(normalized):
        raise ProvisioningError(f"{label} must not be a placeholder value")
    return normalized


def _strict_object(
    value: object, *, keys: frozenset[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ProvisioningError(f"{label} fields are incomplete or unsupported")
    return value


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or _UTC_DATETIME.fullmatch(value) is None:
        raise ProvisioningError(f"{label} must be RFC3339 UTC ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProvisioningError(f"{label} must be RFC3339 UTC ending in Z") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ProvisioningError(f"{label} must be RFC3339 UTC ending in Z")
    canonical = parsed.astimezone(UTC)
    return canonical


def _format_time(value: datetime) -> str:
    canonical = value.astimezone(UTC)
    timespec = "microseconds" if canonical.microsecond else "seconds"
    return canonical.isoformat(timespec=timespec).replace("+00:00", "Z")


def _https_origin(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or _contains_control(value)
        or len(value) > 2048
        or "%" in value
        or any(character.isspace() for character in value)
    ):
        raise ProvisioningError(f"{label} must be an HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ProvisioningError(f"{label} contains an invalid port") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ProvisioningError(
            f"{label} must be a path-free HTTPS origin without credentials"
        )
    if port is not None and not 1 <= port <= 65535:
        raise ProvisioningError(f"{label} contains an invalid port")
    hostname = parsed.hostname.lower()
    reserved_hosts = {
        "localhost",
        "example",
        "invalid",
        "test",
        "example.com",
        "example.net",
        "example.org",
    }
    reserved_suffixes = (
        ".localhost",
        ".example",
        ".invalid",
        ".test",
        ".example.com",
        ".example.net",
        ".example.org",
    )
    if hostname in reserved_hosts or hostname.endswith(reserved_suffixes):
        raise ProvisioningError(f"{label} must not use a reserved or example host")
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
            raise ProvisioningError(
                f"{label} must not use a loopback or unroutable special address"
            )
    host = f"[{hostname}]" if ":" in hostname else hostname
    normalized = f"https://{host}" if port in {None, 443} else f"https://{host}:{port}"
    if value.rstrip("/") != normalized:
        raise ProvisioningError(f"{label} must use canonical HTTPS origin syntax")
    return normalized


def _canonical_uuid(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise ProvisioningError(f"{label} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise ProvisioningError(f"{label} must be a canonical UUID") from error
    if str(parsed) != value:
        raise ProvisioningError(f"{label} must be a canonical UUID")
    return value


def _profile(document: object, *, now: datetime) -> dict[str, Any]:
    profile = _strict_object(document, keys=_PROFILE_KEYS, label="profile")
    version = profile["profile_version"]
    if type(version) is not int or not 1 <= version <= MAX_PROFILE_VERSION:
        raise ProvisioningError(
            f"profile_version must be an integer in 1..{MAX_PROFILE_VERSION}"
        )
    expires_at = _parse_time(profile["expires_at"], label="expires_at")
    if expires_at <= now.astimezone(UTC):
        raise ProvisioningError("profile expires_at must be in the future")
    issuer_id = _production_identifier(profile["issuer_id"], label="issuer_id")
    issuer_key_id = _production_identifier(
        profile["issuer_key_id"], label="issuer_key_id"
    )

    subject_source = profile["subject"]
    if not isinstance(subject_source, dict) or not _SUBJECT_KEYS.issubset(subject_source):
        raise ProvisioningError("subject must include mine_id, system_id, and party_id")
    if set(subject_source) != {
        "mine_id",
        "mine_name",
        "party_id",
        "party_name",
        "system_id",
    }:
        raise ProvisioningError("profile subject fields are incomplete or unsupported")
    subject = {
        "mine_id": _production_identifier(
            subject_source["mine_id"], label="subject.mine_id"
        ),
        "system_id": _production_identifier(
            subject_source["system_id"], label="subject.system_id"
        ),
        "party_id": _production_identifier(
            subject_source["party_id"], label="subject.party_id"
        ),
    }
    if len(set(subject.values())) != len(subject):
        raise ProvisioningError("profile subject identifiers must be distinct")
    mine_name = _display_name(subject_source["mine_name"], label="subject.mine_name")
    party_name = _display_name(
        subject_source["party_name"], label="subject.party_name"
    )

    comparison = _strict_object(
        profile["comparison_context"], keys=_CONTEXT_KEYS, label="comparison_context"
    )
    normalized_comparison: dict[str, str] = {}
    for key in sorted(_CONTEXT_KEYS):
        value = comparison[key]
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value.strip()) > 64
            or _contains_control(value)
            or _looks_placeholder(value)
        ):
            raise ProvisioningError(
                f"comparison_context.{key} must be a governed non-placeholder value"
            )
        normalized_comparison[key] = value.strip()

    agent = _strict_object(profile["agent"], keys=_AGENT_PROFILE_KEYS, label="agent")
    timezone = agent["reporting_timezone"]
    if not isinstance(timezone, str) or timezone != "Asia/Shanghai":
        raise ProvisioningError("agent.reporting_timezone must be Asia/Shanghai")
    normalized_agent = {
        "platform_base_url": _https_origin(
            agent["platform_base_url"],
            label="agent.platform_base_url",
        ),
        "reporting_timezone": timezone,
    }

    platform_identity = _strict_object(
        profile["platform_identity"],
        keys=_PLATFORM_IDENTITY_KEYS,
        label="platform_identity",
    )
    normalized_platform = {
        "system_id": _production_identifier(
            platform_identity["system_id"], label="platform_identity.system_id"
        ),
        "party_id": _production_identifier(
            platform_identity["party_id"], label="platform_identity.party_id"
        ),
        "key_id": _production_identifier(
            platform_identity["key_id"], label="platform_identity.key_id"
        ),
    }
    if normalized_platform["system_id"] == normalized_platform["party_id"]:
        raise ProvisioningError("Platform system_id and party_id must be distinct")
    return {
        "profile_version": version,
        "expires_at": _format_time(expires_at),
        "issuer_id": issuer_id,
        "issuer_key_id": issuer_key_id,
        "subject": subject,
        "mine_name": mine_name,
        "party_name": party_name,
        "comparison_context": normalized_comparison,
        "agent": normalized_agent,
        "platform_identity": normalized_platform,
    }


def _load_private_key(payload: bytes, passphrase: bytes) -> Ed25519PrivateKey:
    if not passphrase:
        raise ProvisioningError("issuer private-key passphrase must not be empty")
    try:
        key = serialization.load_pem_private_key(payload, password=passphrase)
    except (TypeError, ValueError) as error:
        raise ProvisioningError("issuer private key or passphrase is invalid") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ProvisioningError("issuer private key must be Ed25519")
    return key


def load_public_key(payload: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as error:
        raise ProvisioningError("issuer public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ProvisioningError("issuer public key must be Ed25519")
    return key


def public_key_spki_sha256(key: Ed25519PublicKey) -> str:
    """Return the externally approved Ed25519 SPKI-DER fingerprint."""

    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(der).hexdigest()


def _expected_fingerprint(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _HEX_SHA256.fullmatch(value) is None:
        raise ProvisioningError(f"{label} must be 64 lowercase SHA-256 hex characters")
    return value


def _verify_issuer_trust(
    *,
    envelope: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    expected_public_key_sha256: str,
    expected_issuer_key_id: str,
) -> None:
    expected_fingerprint = _expected_fingerprint(
        expected_public_key_sha256,
        label="expected issuer public-key fingerprint",
    )
    actual_fingerprint = public_key_spki_sha256(public_key)
    if not hmac.compare_digest(actual_fingerprint, expected_fingerprint):
        raise ProvisioningError(
            "issuer public key does not match the independently approved fingerprint"
        )
    expected_key_id = _production_identifier(
        expected_issuer_key_id,
        label="expected issuer key ID",
    )
    if not hmac.compare_digest(
        str(envelope["protected"]["issuer_key_id"]), expected_key_id
    ):
        raise ProvisioningError("bundle issuer_key_id does not match the trusted key ID")


def _environment_flag(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    folded = raw.strip().casefold()
    if folded == "true":
        return True
    if folded == "false":
        return False
    raise ProvisioningError(f"{name} must be true or false")


def issuer_init(
    *,
    private_key_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    passphrase: bytes,
) -> dict[str, object]:
    """Create a password-encrypted Ed25519 issuer key pair without overwriting."""

    if len(passphrase) < 12:
        raise ProvisioningError("issuer private-key passphrase must contain >= 12 bytes")
    private_path = Path(private_key_path).expanduser().absolute()
    public_path = Path(public_key_path).expanduser().absolute()
    if private_path == public_path:
        raise ProvisioningError("issuer private and public key paths must differ")
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    public_pem = public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_new_private(private_path, private_pem)
    try:
        _write_new_private(public_path, public_pem)
    except BaseException:
        try:
            private_path.unlink()
        except OSError:
            pass
        raise
    fingerprint = public_key_spki_sha256(public)
    return {
        "status": "created",
        "algorithm": "Ed25519",
        "private_key": str(private_path),
        "public_key": str(public_path),
        "public_key_sha256": fingerprint,
        "public_key_fingerprint_format": "sha256-spki-der",
    }


def _derive_key(activation_code: bytes, encryption: Mapping[str, Any]) -> bytes:
    if not activation_code:
        raise ProvisioningError("activation code must not be empty")
    salt = _b64url_decode(encryption.get("salt"), label="encryption.salt", length=16)
    try:
        return Scrypt(
            salt=salt,
            length=KEY_LENGTH,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
        ).derive(activation_code)
    except (TypeError, ValueError) as error:
        raise ProvisioningError("activation code could not derive the bundle key") from error


def _new_envelope(
    *,
    kind: str,
    pair_id: str,
    bundle_id: str,
    profile: Mapping[str, Any],
    payload: Mapping[str, Any],
    locked_document: Mapping[str, Any],
    locked_keys: list[str],
    activation_code: bytes,
    private_key: Ed25519PrivateKey,
    issued_at: datetime,
) -> dict[str, object]:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    payload_bytes = canonical_json(payload)
    protected: dict[str, object] = {
        "contract_version": CONTRACT_VERSION,
        "bundle_kind": kind,
        "bundle_id": bundle_id,
        "pair_id": pair_id,
        "profile_version": profile["profile_version"],
        "issued_at": _format_time(issued_at),
        "expires_at": profile["expires_at"],
        "issuer_id": profile["issuer_id"],
        "issuer_key_id": profile["issuer_key_id"],
        "subject": profile["subject"],
        "payload_sha256": sha256(payload_bytes).hexdigest(),
        "locked_config_sha256": sha256(canonical_json(locked_document)).hexdigest(),
        "locked_keys": locked_keys,
        "encryption": {
            "algorithm": "aes-256-gcm",
            "kdf": "scrypt",
            "salt": _b64url_encode(salt),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "nonce": _b64url_encode(nonce),
        },
    }
    key = Scrypt(
        salt=salt, length=KEY_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    ).derive(activation_code)
    ciphertext = _b64url_encode(
        AESGCM(key).encrypt(nonce, payload_bytes, canonical_json(protected))
    )
    signed = {"protected": protected, "ciphertext": ciphertext}
    return {
        **signed,
        "signature": _b64url_encode(private_key.sign(canonical_json(signed))),
    }


def create_pair(
    *,
    profile_path: str | os.PathLike[str],
    issuer_private_key_path: str | os.PathLike[str],
    issuer_passphrase: bytes,
    output_directory: str | os.PathLike[str] | None = None,
    activation_directory: str | os.PathLike[str] | None = None,
    enterprise_bundle_directory: str | os.PathLike[str] | None = None,
    platform_registration_directory: str | os.PathLike[str] | None = None,
    enterprise_activation_directory: str | os.PathLike[str] | None = None,
    platform_activation_directory: str | os.PathLike[str] | None = None,
    previous_registration_bundle_path: str | os.PathLike[str] | None = None,
    previous_registration_activation_code_path: str | os.PathLike[str] | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Generate matching Agent and Platform materials in isolated delivery trees."""

    current = (now or datetime.now(UTC)).astimezone(UTC)
    issued_at = current.replace(microsecond=0)
    profile = _profile(_load_json_file(profile_path, label="profile"), now=current)
    private_key = _load_private_key(
        _read_regular_file(issuer_private_key_path, label="issuer private key"),
        issuer_passphrase,
    )
    previous_requested = (
        previous_registration_bundle_path is not None
        or previous_registration_activation_code_path is not None
    )
    if previous_requested and (
        previous_registration_bundle_path is None
        or previous_registration_activation_code_path is None
    ):
        raise ProvisioningError(
            "an update requires both previous registration bundle and activation code"
        )
    previous_envelope: dict[str, Any] | None = None
    previous_client: dict[str, Any] | None = None
    previous_platform_identity: dict[str, str] | None = None
    if previous_requested:
        assert previous_registration_bundle_path is not None
        assert previous_registration_activation_code_path is not None
        previous_document = _load_json_file(
            previous_registration_bundle_path,
            label="previous Platform registration bundle",
        )
        previous_envelope, previous_payload = decrypt_bundle(
            previous_document,
            activation_code=read_secret_file(
                previous_registration_activation_code_path,
                label="previous Platform activation code",
            ),
            issuer_public_key=private_key.public_key(),
            expected_kind=REGISTRATION_BUNDLE_KIND,
            check_expiry=False,
            now=current,
        )
        previous_client, previous_platform_identity = _validate_registration_payload(
            previous_envelope, previous_payload
        )
        previous_protected = previous_envelope["protected"]
        if profile["issuer_key_id"] != previous_protected["issuer_key_id"]:
            raise ProvisioningError("update issuer_key_id differs from the prior bundle")
        if profile["subject"] != previous_protected["subject"]:
            raise ProvisioningError("update subject identity differs from the prior bundle")
        if profile["profile_version"] != previous_protected["profile_version"] + 1:
            raise ProvisioningError(
                "update profile_version must increment the prior version by exactly one"
            )
        if profile["platform_identity"] != previous_platform_identity:
            raise ProvisioningError(
                "update Platform identity differs from the prior bundle"
            )
        pair_id = previous_protected["pair_id"]
    else:
        if profile["profile_version"] != 1:
            raise ProvisioningError(
                "an initial provisioning pair must use profile_version 1"
            )
        pair_id = str(uuid.uuid4())
    agent_bundle_id = str(uuid.uuid4())
    registration_bundle_id = str(uuid.uuid4())
    activation_agent = _b64url_encode(secrets.token_bytes(32)).encode("ascii")
    activation_platform = _b64url_encode(secrets.token_bytes(32)).encode("ascii")
    message_secret = _b64url_encode(secrets.token_bytes(48))
    transport_secret = _b64url_encode(secrets.token_bytes(48))
    key_prefix = re.sub(r"[^A-Za-z0-9]+", "-", profile["subject"]["mine_id"]).strip("-")
    enterprise_key_id = (
        f"{key_prefix[:48]}-msg-v{profile['profile_version']}-{agent_bundle_id[:8]}"
    )

    subject = profile["subject"]
    context = profile["comparison_context"]
    agent_settings = profile["agent"]
    platform_identity = profile["platform_identity"]
    config = {
        "ENTERPRISE_AGENT_PRODUCTION_MODE": "true",
        "ENTERPRISE_AGENT_FOUR_EYES_REQUIRED": "false",
        # The enterprise UI is intentionally loopback-only.  Government-to-
        # enterprise delivery is pulled over PLATFORM_V3_BASE_URL, so the
        # Agent does not need an inbound HTTPS endpoint or a public origin.
        "ENTERPRISE_AGENT_SECURE_COOKIE": "false",
        "ENTERPRISE_MINE_ID": subject["mine_id"],
        "ENTERPRISE_MINE_NAME": profile["mine_name"],
        "ENTERPRISE_OPERATOR_ID": subject["party_id"],
        "ENTERPRISE_OPERATOR_NAME": profile["party_name"],
        "ENTERPRISE_SYSTEM_ID": subject["system_id"],
        "ENTERPRISE_REPORTING_TIMEZONE": agent_settings["reporting_timezone"],
        "ENTERPRISE_CAPACITY_BAND": context["capacity_band"],
        "ENTERPRISE_MINING_METHOD": context["mining_method"],
        "ENTERPRISE_SHIFT_SYSTEM": context["shift_system"],
        "ENTERPRISE_COAL_TYPE": context["coal_type"],
        "ENTERPRISE_OPERATING_REGIME": context["operating_regime"],
        "PLATFORM_V3_BASE_URL": agent_settings["platform_base_url"],
        "PLATFORM_V3_SENDER_ID": subject["system_id"],
        "REGULATORY_SYSTEM_ID": platform_identity["system_id"],
        "REGULATORY_PARTY_ID": platform_identity["party_id"],
        "ENTERPRISE_EXCHANGE_KEY_ID": enterprise_key_id,
        "REGULATORY_EXCHANGE_KEY_ID": platform_identity["key_id"],
        "ENTERPRISE_EXCHANGE_HMAC_SECRET": message_secret,
        "PLATFORM_V3_TRANSPORT_HMAC_SECRET": transport_secret,
    }
    if previous_client is not None and previous_platform_identity is not None:
        previous_message_key_id = str(previous_client["active_message_key_id"])
        previous_message_secret = str(
            previous_client["message_keys"][previous_message_key_id]
        )
        config.update(
            {
                "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON": canonical_json(
                    [
                        {
                            "key_id": previous_message_key_id,
                            "secret": previous_message_secret,
                        }
                    ]
                ).decode("utf-8"),
                "REGULATORY_PREVIOUS_EXCHANGE_KEY_ID": previous_platform_identity[
                    "key_id"
                ],
                "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET": previous_message_secret,
            }
        )
    locked_keys = sorted(config)
    agent_payload = {
        "kind": AGENT_BUNDLE_KIND,
        "bundle_id": agent_bundle_id,
        "pair_id": pair_id,
        "profile_version": profile["profile_version"],
        "config": config,
        "locked_keys": locked_keys,
    }
    client = {
        "sender_id": subject["system_id"],
        "party_id": subject["party_id"],
        "mine_id": subject["mine_id"],
        "mine_name": profile["mine_name"],
        "active_message_key_id": enterprise_key_id,
        "message_keys": {enterprise_key_id: message_secret},
        "transport_secrets": [transport_secret],
        "comparison_context": dict(context),
    }
    if previous_client is not None:
        previous_message_key_id = str(previous_client["active_message_key_id"])
        client["message_keys"][previous_message_key_id] = previous_client[
            "message_keys"
        ][previous_message_key_id]
        client["transport_secrets"].append(previous_client["transport_secrets"][0])
    registration_payload = {
        "kind": REGISTRATION_BUNDLE_KIND,
        "bundle_id": registration_bundle_id,
        "pair_id": pair_id,
        "profile_version": profile["profile_version"],
        "client": client,
        "platform_identity": dict(platform_identity),
    }
    agent_envelope = _new_envelope(
        kind=AGENT_BUNDLE_KIND,
        pair_id=pair_id,
        bundle_id=agent_bundle_id,
        profile=profile,
        payload=agent_payload,
        locked_document={key: config[key] for key in locked_keys},
        locked_keys=locked_keys,
        activation_code=activation_agent,
        private_key=private_key,
        issued_at=issued_at,
    )
    registration_locked_document = {
        "client": client,
        "platform_identity": dict(platform_identity),
    }
    # Only Agent environment keys participate in the cross-product
    # ``locked_keys`` contract.  The Platform registration binds its complete
    # client + Platform identity through ``locked_config_sha256`` instead.
    registration_locked_keys: list[str] = []
    registration_envelope = _new_envelope(
        kind=REGISTRATION_BUNDLE_KIND,
        pair_id=pair_id,
        bundle_id=registration_bundle_id,
        profile=profile,
        payload=registration_payload,
        locked_document=registration_locked_document,
        locked_keys=registration_locked_keys,
        activation_code=activation_platform,
        private_key=private_key,
        issued_at=issued_at,
    )

    (
        enterprise_bundle_output,
        platform_registration_output,
        enterprise_activation_output,
        platform_activation_output,
        legacy_shared_layout,
    ) = _prepare_delivery_directories(
        output_directory=output_directory,
        activation_directory=activation_directory,
        enterprise_bundle_directory=enterprise_bundle_directory,
        platform_registration_directory=platform_registration_directory,
        enterprise_activation_directory=enterprise_activation_directory,
        platform_activation_directory=platform_activation_directory,
    )
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", subject["mine_id"]).strip("-")
    filename_stem = f"{stem}-v{profile['profile_version']}"
    agent_path = enterprise_bundle_output / f"{filename_stem}.mgprov"
    registration_path = platform_registration_output / f"{filename_stem}.mgreg"
    issuer_public_key_path = (
        platform_registration_output / f"{filename_stem}.issuer-public.pem"
    )
    manifest_path = (
        platform_registration_output
        / f"{filename_stem}.provisioning-manifest.json"
    )
    agent_activation_path = (
        enterprise_activation_output / f"{filename_stem}-agent.activation"
    )
    platform_activation_path = (
        platform_activation_output / f"{filename_stem}-platform.activation"
    )
    registration_bundle_bytes = canonical_json(registration_envelope) + b"\n"
    issuer_public_key = private_key.public_key()
    issuer_public_key_bytes = issuer_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    issuer_fingerprint = public_key_spki_sha256(issuer_public_key)
    enterprise_access_package = {
        "format": ENTERPRISE_ACCESS_PACKAGE_FORMAT,
        "agent_bundle": agent_envelope,
        "activation_code": activation_agent.decode("ascii"),
        "issuer_public_key_pem": issuer_public_key_bytes.decode("ascii"),
        "issuer_public_key_sha256": issuer_fingerprint,
        "issuer_key_id": profile["issuer_key_id"],
    }
    agent_bundle_bytes = canonical_json(enterprise_access_package) + b"\n"
    issuer_public_key_artifact = {
        "filename": issuer_public_key_path.name,
        "sha256": sha256(issuer_public_key_bytes).hexdigest(),
        "spki_sha256": issuer_fingerprint,
        "spki_fingerprint_format": "sha256-spki-der",
    }
    issuer_manifest = {
        "issuer_id": profile["issuer_id"],
        "issuer_key_id": profile["issuer_key_id"],
        "public_key_fingerprint_format": "sha256-spki-der",
        "public_key_sha256": issuer_fingerprint,
    }
    manifest = {
        "schema_version": "mineguard-provisioning-manifest-v1",
        "pair_id": pair_id,
        "profile_version": profile["profile_version"],
        "issued_at": _format_time(issued_at),
        "expires_at": profile["expires_at"],
        "subject": dict(subject),
        "platform_identity": dict(platform_identity),
        "issuer": issuer_manifest,
        "artifacts": {
            "agent_bundle": {
                "bundle_id": agent_bundle_id,
                "filename": agent_path.name,
                "sha256": sha256(agent_bundle_bytes).hexdigest(),
            },
            "platform_registration_bundle": {
                "bundle_id": registration_bundle_id,
                "filename": registration_path.name,
                "sha256": sha256(registration_bundle_bytes).hexdigest(),
            },
            "issuer_public_key": issuer_public_key_artifact,
        },
    }
    manifest_bytes = canonical_json(manifest) + b"\n"
    targets = (
        agent_path,
        registration_path,
        issuer_public_key_path,
        manifest_path,
        agent_activation_path,
        platform_activation_path,
    )
    if any(path.exists() or path.is_symlink() for path in targets):
        raise ProvisioningError("provisioning output already exists; no file was overwritten")
    written: list[Path] = []
    try:
        for path, payload in (
            (agent_path, agent_bundle_bytes),
            (issuer_public_key_path, issuer_public_key_bytes),
            (registration_path, registration_bundle_bytes),
            (manifest_path, manifest_bytes),
            (agent_activation_path, activation_agent + b"\n"),
            (platform_activation_path, activation_platform + b"\n"),
        ):
            _write_new_private(path, payload)
            written.append(path)
    except BaseException:
        for path in written:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return {
        "status": "created",
        "pair_id": pair_id,
        "profile_version": profile["profile_version"],
        "subject": dict(subject),
        "platform_identity": dict(platform_identity),
        "agent_bundle": str(agent_path),
        "platform_registration_bundle": str(registration_path),
        "provisioning_manifest": str(manifest_path),
        "issuer_public_key_file": str(issuer_public_key_path),
        "agent_activation_file": str(agent_activation_path),
        "platform_activation_file": str(platform_activation_path),
        "issuer_public_key_sha256": issuer_fingerprint,
        "issuer_public_key_fingerprint_format": "sha256-spki-der",
        "layout": (
            "legacy-shared-v1" if legacy_shared_layout else "split-delivery-v1"
        ),
        "legacy_shared_layout": legacy_shared_layout,
        "enterprise_package_format": ENTERPRISE_ACCESS_PACKAGE_FORMAT,
        "activation_codes_disclosed": False,
        "secrets_disclosed": False,
    }


def _validate_envelope(document: object, *, expected_kind: str) -> dict[str, Any]:
    envelope = _strict_object(document, keys=_ENVELOPE_KEYS, label="bundle envelope")
    protected = _strict_object(
        envelope["protected"], keys=_PROTECTED_KEYS, label="bundle protected header"
    )
    if protected["contract_version"] != CONTRACT_VERSION:
        raise ProvisioningError("unsupported provisioning contract_version")
    if protected["bundle_kind"] != expected_kind:
        raise ProvisioningError("provisioning bundle kind does not match this operation")
    for label in ("bundle_id", "pair_id"):
        _canonical_uuid(protected[label], label=f"protected.{label}")
    version = protected["profile_version"]
    if type(version) is not int or not 1 <= version <= MAX_PROFILE_VERSION:
        raise ProvisioningError(
            "protected.profile_version must be an integer in "
            f"1..{MAX_PROFILE_VERSION}"
        )
    issued_at = _parse_time(protected["issued_at"], label="protected.issued_at")
    expires_at = _parse_time(protected["expires_at"], label="protected.expires_at")
    if expires_at <= issued_at:
        raise ProvisioningError("protected.expires_at must be later than issued_at")
    _production_identifier(protected["issuer_id"], label="protected.issuer_id")
    _production_identifier(protected["issuer_key_id"], label="protected.issuer_key_id")
    subject = _strict_object(
        protected["subject"], keys=_SUBJECT_KEYS, label="protected.subject"
    )
    for key in sorted(_SUBJECT_KEYS):
        _production_identifier(subject[key], label=f"protected.subject.{key}")
    for label in ("payload_sha256", "locked_config_sha256"):
        if not isinstance(protected[label], str) or _HEX_SHA256.fullmatch(protected[label]) is None:
            raise ProvisioningError(f"protected.{label} must be lowercase SHA-256")
    locked_keys = protected["locked_keys"]
    if (
        not isinstance(locked_keys, list)
        or len(locked_keys) > 64
        or any(not isinstance(item, str) or not item for item in locked_keys)
        or locked_keys != sorted(set(locked_keys))
    ):
        raise ProvisioningError("protected.locked_keys must be a sorted unique string array")
    encryption = _strict_object(
        protected["encryption"], keys=_ENCRYPTION_KEYS, label="protected.encryption"
    )
    numeric_parameters = {"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
    if (
        encryption["algorithm"] != "aes-256-gcm"
        or encryption["kdf"] != "scrypt"
        or any(
            type(encryption[name]) is not int or encryption[name] != expected
            for name, expected in numeric_parameters.items()
        )
    ):
        raise ProvisioningError("unsupported provisioning encryption parameters")
    _b64url_decode(encryption["salt"], label="encryption.salt", length=16)
    _b64url_decode(encryption["nonce"], label="encryption.nonce", length=12)
    if len(_b64url_decode(envelope["ciphertext"], label="ciphertext")) < 17:
        raise ProvisioningError("ciphertext must include plaintext and a 16-byte tag")
    _b64url_decode(envelope["signature"], label="signature", length=64)
    return envelope


def _verify_signature(envelope: Mapping[str, Any], key: Ed25519PublicKey) -> None:
    signed = {
        "protected": envelope["protected"],
        "ciphertext": envelope["ciphertext"],
    }
    signature = _b64url_decode(envelope["signature"], label="signature", length=64)
    try:
        key.verify(signature, canonical_json(signed))
    except InvalidSignature as error:
        raise ProvisioningError("provisioning signature verification failed") from error


def decrypt_bundle(
    document: object,
    *,
    activation_code: bytes,
    issuer_public_key: Ed25519PublicKey,
    expected_kind: str,
    check_expiry: bool = True,
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify then decrypt one envelope; used by Platform and Agent importers."""

    envelope = _validate_envelope(document, expected_kind=expected_kind)
    _verify_signature(envelope, issuer_public_key)
    protected = envelope["protected"]
    if check_expiry:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        issued_at = _parse_time(
            protected["issued_at"], label="protected.issued_at"
        )
        expires_at = _parse_time(
            protected["expires_at"], label="protected.expires_at"
        )
        if issued_at > current + timedelta(minutes=5):
            raise ProvisioningError("provisioning bundle is not yet valid")
        if expires_at <= current:
            raise ProvisioningError("provisioning bundle has expired")
    encryption = protected["encryption"]
    if re.fullmatch(rb"[A-Za-z0-9_-]{43}", activation_code) is None:
        raise ProvisioningError("activation code format is invalid")
    key = _derive_key(activation_code, encryption)
    nonce = _b64url_decode(encryption["nonce"], label="encryption.nonce", length=12)
    ciphertext = _b64url_decode(envelope["ciphertext"], label="ciphertext")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, canonical_json(protected))
    except Exception as error:
        # InvalidTag deliberately becomes the same non-secret-bearing error as a
        # wrong activation code; callers cannot use the message as an oracle.
        raise ProvisioningError("bundle activation or authenticated decryption failed") from error
    payload = _load_json_bytes(plaintext, label="decrypted provisioning payload")
    if not isinstance(payload, dict):
        raise ProvisioningError("decrypted provisioning payload must be an object")
    if sha256(canonical_json(payload)).hexdigest() != protected["payload_sha256"]:
        raise ProvisioningError("decrypted provisioning payload digest mismatch")
    return envelope, payload


def _validate_registration_payload(
    envelope: Mapping[str, Any], payload: object
) -> tuple[dict[str, Any], dict[str, str]]:
    value = _strict_object(
        payload, keys=_REGISTRATION_PAYLOAD_KEYS, label="registration payload"
    )
    protected = envelope["protected"]
    for field in ("kind", "bundle_id", "pair_id", "profile_version"):
        expected = (
            REGISTRATION_BUNDLE_KIND if field == "kind" else protected[field]
        )
        if value[field] != expected:
            raise ProvisioningError(f"registration payload {field} mismatch")
    client = value["client"]
    if not isinstance(client, dict):
        raise ProvisioningError("registration payload client must be an object")
    platform_identity = _strict_object(
        value["platform_identity"],
        keys=_PLATFORM_IDENTITY_KEYS,
        label="registration platform_identity",
    )
    normalized_identity = {
        key: _identifier(platform_identity[key], label=f"platform_identity.{key}")
        for key in sorted(_PLATFORM_IDENTITY_KEYS)
    }
    subject = protected["subject"]
    if (
        client.get("mine_id") != subject["mine_id"]
        or client.get("sender_id") != subject["system_id"]
        or client.get("party_id") != subject["party_id"]
    ):
        raise ProvisioningError("registration client identity does not match subject")
    locked_document = {
        "client": client,
        "platform_identity": normalized_identity,
    }
    if protected["locked_keys"] != []:
        raise ProvisioningError("registration client locked_keys mismatch")
    digest = sha256(canonical_json(locked_document)).hexdigest()
    if digest != protected["locked_config_sha256"]:
        raise ProvisioningError("registration client digest mismatch")
    return client, normalized_identity


def registry_lock_status(
    document: object,
    *,
    trusted_public_key: Ed25519PublicKey | None = None,
    expected_public_key_sha256: str | None = None,
    expected_issuer_key_id: str | None = None,
    managed_required: bool = False,
) -> dict[str, object]:
    """Verify managed clients against an external trust anchor.

    The trusted key is deliberately not read from ``clients.json``. A registry
    writer must not be able to replace both a client and the key that purports
    to authenticate that client.
    """

    if not isinstance(document, dict):
        return {"managed": False, "locked_client_count": 0}
    lock = document.get("provisioning_lock")
    if lock is None:
        if managed_required:
            raise ProvisioningError(
                "managed provisioning is required but provisioning_lock is missing"
            )
        return {"managed": False, "locked_client_count": 0}
    if (
        trusted_public_key is None
        or expected_public_key_sha256 is None
        or expected_issuer_key_id is None
    ):
        raise ProvisioningError(
            "managed registry verification requires an external trusted issuer key, "
            "fingerprint, and key ID"
        )
    trusted_fingerprint = _expected_fingerprint(
        expected_public_key_sha256,
        label="expected issuer public-key fingerprint",
    )
    actual_trusted_fingerprint = public_key_spki_sha256(trusted_public_key)
    if not hmac.compare_digest(trusted_fingerprint, actual_trusted_fingerprint):
        raise ProvisioningError(
            "trusted issuer public key does not match the approved fingerprint"
        )
    trusted_key_id = _production_identifier(
        expected_issuer_key_id,
        label="expected issuer key ID",
    )
    if not isinstance(lock, dict) or set(lock) != {"schema_version", "registrations"}:
        raise ProvisioningError("provisioning_lock fields are invalid")
    if lock["schema_version"] != REGISTRY_LOCK_VERSION:
        raise ProvisioningError("unsupported provisioning_lock schema_version")
    registrations = lock["registrations"]
    clients = document.get("clients")
    if (
        not isinstance(registrations, list)
        or not registrations
        or not isinstance(clients, list)
    ):
        raise ProvisioningError("provisioning_lock registrations and clients must be arrays")
    by_sender: dict[str, Mapping[str, Any]] = {}
    for client in clients:
        if isinstance(client, dict) and isinstance(client.get("sender_id"), str):
            if client["sender_id"] in by_sender:
                raise ProvisioningError("client registry contains duplicate sender_id")
            by_sender[client["sender_id"]] = client
    seen_bundles: set[str] = set()
    seen_pairs: set[str] = set()
    seen_senders: set[str] = set()
    governed_platform_identity: dict[str, str] | None = None
    for registration in registrations:
        if not isinstance(registration, dict) or set(registration) != set(
            _REGISTRATION_LOCK_KEYS
        ):
            raise ProvisioningError("provisioning_lock registration fields are invalid")
        envelope = _validate_envelope(
            registration["envelope"], expected_kind=REGISTRATION_BUNDLE_KIND
        )
        protected = envelope["protected"]
        for field in ("bundle_id", "pair_id", "profile_version", "subject"):
            if registration[field] != protected[field]:
                raise ProvisioningError(f"provisioning_lock {field} mismatch")
        bundle_id = protected["bundle_id"]
        if bundle_id in seen_bundles:
            raise ProvisioningError("provisioning_lock contains duplicate bundle_id")
        seen_bundles.add(bundle_id)
        pair_id = protected["pair_id"]
        if pair_id in seen_pairs:
            raise ProvisioningError("provisioning_lock reuses pair_id across clients")
        seen_pairs.add(pair_id)
        if (
            registration["issuer_key_id"] != trusted_key_id
            or protected["issuer_key_id"] != trusted_key_id
            or registration["issuer_public_key_sha256"] != trusted_fingerprint
        ):
            raise ProvisioningError("provisioning_lock issuer trust binding mismatch")
        _verify_issuer_trust(
            envelope=envelope,
            public_key=trusted_public_key,
            expected_public_key_sha256=trusted_fingerprint,
            expected_issuer_key_id=trusted_key_id,
        )
        _verify_signature(envelope, trusted_public_key)
        subject = protected["subject"]
        sender_id = subject["system_id"]
        if sender_id in seen_senders:
            raise ProvisioningError("provisioning_lock binds a sender more than once")
        seen_senders.add(sender_id)
        client = by_sender.get(sender_id)
        if client is None:
            raise ProvisioningError("provisioning_lock client is missing from registry")
        if (
            client.get("mine_id") != subject["mine_id"]
            or client.get("party_id") != subject["party_id"]
        ):
            raise ProvisioningError("provisioning_lock client identity mismatch")
        platform_identity = _strict_object(
            registration["platform_identity"],
            keys=_PLATFORM_IDENTITY_KEYS,
            label="provisioning_lock platform_identity",
        )
        normalized_platform_identity = {
            key: _identifier(
                platform_identity[key],
                label=f"provisioning_lock platform_identity.{key}",
            )
            for key in sorted(_PLATFORM_IDENTITY_KEYS)
        }
        if governed_platform_identity is None:
            governed_platform_identity = normalized_platform_identity
        elif governed_platform_identity != normalized_platform_identity:
            raise ProvisioningError(
                "provisioning_lock contains inconsistent Platform identities"
            )
        digest = sha256(
            canonical_json(
                {
                    "client": client,
                    "platform_identity": normalized_platform_identity,
                }
            )
        ).hexdigest()
        client_digest = sha256(canonical_json(client)).hexdigest()
        if (
            registration["client_sha256"] != client_digest
            or protected["locked_config_sha256"] != digest
            or protected["locked_keys"] != []
        ):
            raise ProvisioningError("provisioning_lock client digest verification failed")
    unmanaged_client_count = len(clients) - len(registrations)
    if managed_required and unmanaged_client_count != 0:
        raise ProvisioningError(
            "managed provisioning requires every client to have a signed lock"
        )
    return {
        "managed": True,
        "locked_client_count": len(registrations),
        "unmanaged_client_count": unmanaged_client_count,
        "platform_identity": governed_platform_identity,
        "issuer_key_id": trusted_key_id,
        "issuer_public_key_sha256": trusted_fingerprint,
    }


def registry_lock_status_from_environment(document: object) -> dict[str, object]:
    """Apply the service's external managed-mode and issuer trust policy."""

    managed_required = _environment_flag(MANAGED_REQUIRED_ENV)
    has_lock = isinstance(document, dict) and document.get("provisioning_lock") is not None
    if not has_lock and not managed_required:
        return {
            "managed": False,
            "managed_required_external": False,
            "locked_client_count": 0,
        }
    public_key_file = os.environ.get(TRUSTED_PUBLIC_KEY_FILE_ENV, "").strip()
    fingerprint = os.environ.get(EXPECTED_PUBLIC_KEY_SHA256_ENV, "").strip()
    key_id = os.environ.get(EXPECTED_ISSUER_KEY_ID_ENV, "").strip()
    if not public_key_file or not fingerprint or not key_id:
        raise ProvisioningError(
            "managed registry requires trusted public-key file, expected SPKI "
            "fingerprint, and expected issuer key ID environment settings"
        )
    if not Path(public_key_file).expanduser().is_absolute():
        raise ProvisioningError(
            f"{TRUSTED_PUBLIC_KEY_FILE_ENV} must be an absolute path"
        )
    public_key = load_public_key(
        _read_regular_file(public_key_file, label="trusted issuer public key")
    )
    status = registry_lock_status(
        document,
        trusted_public_key=public_key,
        expected_public_key_sha256=fingerprint,
        expected_issuer_key_id=key_id,
        # A registry that contains any signed lock can never mix in unsigned
        # clients. The external flag additionally survives complete lock removal.
        managed_required=True,
    )
    status["managed_required_external"] = managed_required
    return status


def registry_lock_status_file(path: str | os.PathLike[str]) -> dict[str, object]:
    return registry_lock_status_from_environment(
        _load_json_file(path, label="client registry")
    )


def import_registration(
    *,
    bundle_path: str | os.PathLike[str],
    activation_code_path: str | os.PathLike[str],
    issuer_public_key_path: str | os.PathLike[str],
    expected_public_key_sha256: str,
    expected_issuer_key_id: str,
    clients_file_path: str | os.PathLike[str],
    allow_update: bool = False,
    now: datetime | None = None,
) -> dict[str, object]:
    """Verify, decrypt, validate and atomically merge one Platform registration."""

    document = _load_json_file(bundle_path, label="Platform registration bundle")
    public_key = load_public_key(
        _read_regular_file(issuer_public_key_path, label="issuer public key")
    )
    validated_envelope = _validate_envelope(
        document, expected_kind=REGISTRATION_BUNDLE_KIND
    )
    _verify_issuer_trust(
        envelope=validated_envelope,
        public_key=public_key,
        expected_public_key_sha256=expected_public_key_sha256,
        expected_issuer_key_id=expected_issuer_key_id,
    )
    activation_code = read_secret_file(
        activation_code_path, label="Platform activation code"
    )
    envelope, payload = decrypt_bundle(
        document,
        activation_code=activation_code,
        issuer_public_key=public_key,
        expected_kind=REGISTRATION_BUNDLE_KIND,
        check_expiry=True,
        now=now,
    )
    client, platform_identity = _validate_registration_payload(envelope, payload)
    from .exchange_v2 import (
        parse_exchange_clients,
        validate_production_exchange_clients,
        validate_production_platform_identity,
    )

    imported_clients = parse_exchange_clients(
        canonical_json({"clients": [client]}).decode(),
        enforce_provisioning_policy=False,
    )
    validate_production_exchange_clients(imported_clients)
    validate_production_platform_identity(
        platform_identity["system_id"],
        platform_identity["party_id"],
        platform_identity["key_id"],
        clients=imported_clients,
    )

    clients_path = Path(clients_file_path).expanduser().absolute()
    protected = envelope["protected"]
    bundle_id = protected["bundle_id"]
    trusted_fingerprint = public_key_spki_sha256(public_key)
    with _registry_transaction_lock(clients_path):
        original_registry_bytes: bytes | None
        if clients_path.exists() or clients_path.is_symlink():
            original_registry_bytes = _read_regular_file(
                clients_path, label="client registry"
            )
            registry = _load_json_bytes(
                original_registry_bytes, label="client registry"
            )
            if not isinstance(registry, dict) or not isinstance(
                registry.get("clients"), list
            ):
                raise ProvisioningError(
                    "client registry must be an object with clients array"
                )
        else:
            original_registry_bytes = None
            registry = {"clients": []}
        clients: list[Any] = list(registry["clients"])
        lock = registry.get("provisioning_lock")
        if lock is None:
            if clients:
                raise ProvisioningError(
                    "cannot mix managed registration with existing unmanaged clients"
                )
            lock = {"schema_version": REGISTRY_LOCK_VERSION, "registrations": []}
        else:
            registry_lock_status(
                registry,
                trusted_public_key=public_key,
                expected_public_key_sha256=expected_public_key_sha256,
                expected_issuer_key_id=expected_issuer_key_id,
                managed_required=True,
            )
        registrations: list[Any] = list(lock["registrations"])
        if registrations:
            existing_platform_identity = registrations[0]["platform_identity"]
            if existing_platform_identity != platform_identity:
                raise ProvisioningError(
                    "registration Platform identity differs from managed registry"
                )
        for registration in registrations:
            if registration["bundle_id"] == bundle_id:
                if (
                    canonical_json(registration["envelope"])
                    != canonical_json(envelope)
                    or registration["issuer_key_id"] != expected_issuer_key_id
                    or registration["issuer_public_key_sha256"]
                    != trusted_fingerprint
                ):
                    raise ProvisioningError(
                        "bundle_id already exists with different signed material"
                    )
                return {
                    "status": "unchanged",
                    "idempotent": True,
                    "bundle_id": bundle_id,
                    "pair_id": protected["pair_id"],
                    "profile_version": protected["profile_version"],
                    "subject": dict(protected["subject"]),
                    "platform_identity": dict(platform_identity),
                    "client_count": len(clients),
                    "clients_file": str(clients_path),
                }
            if (
                registration["pair_id"] == protected["pair_id"]
                and registration["subject"] != protected["subject"]
            ):
                raise ProvisioningError("pair_id is already bound to another subject")

        sender_matches = [
            index
            for index, item in enumerate(clients)
            if isinstance(item, dict) and item.get("sender_id") == client["sender_id"]
        ]
        mine_matches = [
            index
            for index, item in enumerate(clients)
            if isinstance(item, dict) and item.get("mine_id") == client["mine_id"]
        ]
        collision_indexes = sorted(set(sender_matches + mine_matches))
        action = "created"
        if collision_indexes:
            if len(collision_indexes) != 1 or sender_matches != mine_matches:
                raise ProvisioningError(
                    "registration collides with a different mine or sender"
                )
            index = collision_indexes[0]
            existing_registration = next(
                (
                    item
                    for item in registrations
                    if item["subject"]["system_id"] == client["sender_id"]
                    and item["subject"]["mine_id"] == client["mine_id"]
                ),
                None,
            )
            if existing_registration is None:
                raise ProvisioningError("cannot replace an unmanaged client registration")
            if not allow_update:
                raise ProvisioningError("existing mine requires explicit --allow-update")
            if protected["subject"] != existing_registration["subject"]:
                raise ProvisioningError("update subject identity must remain unchanged")
            if protected["pair_id"] != existing_registration["pair_id"]:
                raise ProvisioningError("update pair_id must remain unchanged")
            if (
                protected["profile_version"]
                != existing_registration["profile_version"] + 1
            ):
                raise ProvisioningError(
                    "update profile_version must increment by exactly one"
                )
            existing_client = clients[index]
            old_message_key_id = existing_client["active_message_key_id"]
            old_message_secret = existing_client["message_keys"][old_message_key_id]
            if (
                client["active_message_key_id"] == old_message_key_id
                or client["message_keys"].get(old_message_key_id)
                != old_message_secret
                or existing_client["transport_secrets"][0]
                not in client["transport_secrets"][1:]
            ):
                raise ProvisioningError(
                    "update must rotate current keys and retain the immediately prior keys"
                )
            clients[index] = client
            registrations.remove(existing_registration)
            action = "updated"
        else:
            if protected["profile_version"] != 1:
                raise ProvisioningError(
                    "a new managed mine must start at profile_version 1"
                )
            if registrations and registrations[0]["platform_identity"] != platform_identity:
                raise ProvisioningError(
                    "new mine Platform identity differs from the managed registry"
                )
            clients.append(client)

        registration_lock = {
            "bundle_id": bundle_id,
            "pair_id": protected["pair_id"],
            "profile_version": protected["profile_version"],
            "subject": dict(protected["subject"]),
            "client_sha256": sha256(canonical_json(client)).hexdigest(),
            "platform_identity": dict(platform_identity),
            "envelope": envelope,
            "issuer_key_id": expected_issuer_key_id,
            "issuer_public_key_sha256": trusted_fingerprint,
        }
        registrations.append(registration_lock)
        registrations.sort(
            key=lambda item: (item["subject"]["mine_id"], item["bundle_id"])
        )
        clients.sort(key=lambda item: str(item.get("sender_id", "")))
        registry["clients"] = clients
        registry["provisioning_lock"] = {
            "schema_version": REGISTRY_LOCK_VERSION,
            "registrations": registrations,
        }

        # Re-parse and validate the complete prospective registry before publish.
        registry_lock_status(
            registry,
            trusted_public_key=public_key,
            expected_public_key_sha256=expected_public_key_sha256,
            expected_issuer_key_id=expected_issuer_key_id,
            managed_required=True,
        )
        all_clients = parse_exchange_clients(
            canonical_json(registry).decode(), enforce_provisioning_policy=False
        )
        validate_production_exchange_clients(all_clients)
        validate_production_platform_identity(
            platform_identity["system_id"],
            platform_identity["party_id"],
            platform_identity["key_id"],
            clients=all_clients,
        )
        # The advisory lock serializes cooperating importers; this digest check
        # also refuses a non-cooperating writer that changed the file mid-flight.
        if original_registry_bytes is None:
            if clients_path.exists() or clients_path.is_symlink():
                raise ProvisioningError("client registry appeared during import")
        else:
            current_bytes = _read_regular_file(clients_path, label="client registry")
            if not hmac.compare_digest(
                sha256(current_bytes).digest(), sha256(original_registry_bytes).digest()
            ):
                raise ProvisioningError("client registry changed during import")
        _atomic_write_private(clients_path, canonical_json(registry) + b"\n")
        return {
            "status": action,
            "idempotent": False,
            "bundle_id": bundle_id,
            "pair_id": protected["pair_id"],
            "profile_version": protected["profile_version"],
            "subject": dict(protected["subject"]),
            "platform_identity": dict(platform_identity),
            "client_count": len(clients),
            "clients_file": str(clients_path),
        }


__all__ = [
    "AGENT_BUNDLE_KIND",
    "CONTRACT_VERSION",
    "ENTERPRISE_ACCESS_PACKAGE_FORMAT",
    "EXPECTED_ISSUER_KEY_ID_ENV",
    "EXPECTED_PUBLIC_KEY_SHA256_ENV",
    "MANAGED_REQUIRED_ENV",
    "REGISTRATION_BUNDLE_KIND",
    "REGISTRY_LOCK_VERSION",
    "TRUSTED_PUBLIC_KEY_FILE_ENV",
    "ProvisioningError",
    "canonical_json",
    "create_pair",
    "decrypt_bundle",
    "import_registration",
    "issuer_init",
    "load_public_key",
    "public_key_spki_sha256",
    "read_secret_file",
    "registry_lock_status",
    "registry_lock_status_file",
    "registry_lock_status_from_environment",
]
