"""Locally managed model API settings owned by the fixed ``api_admin``.

The API key is never written as plaintext on Windows.  The small public
configuration and the DPAPI ciphertext are authenticated together so a
partial or hand-edited file fails closed.  POSIX support exists for tests and
source deployments and requires a private 0600 file.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .llm import LLMConfig, OpenAICompatibleProvider
from .provisioning import _dpapi_protect, _dpapi_unprotect
from .util import canonical_json

FORMAT = "mineguard-local-model-api-v1"
DPAPI_PROTECTION = "dpapi-local-machine-v1"
POSIX_PROTECTION = "posix-mode-0600-v1"
_ENTROPY = b"MINEGUARD-LOCAL-MODEL-API-V1\x00"
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")


class ModelApiConfigError(ValueError):
    """Safe configuration failure that never contains the API key."""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _path(value: str | Path) -> Path:
    selected = Path(value).expanduser()
    if not selected.is_absolute():
        raise ModelApiConfigError("模型 API 配置路径必须是绝对路径")
    return selected


def validate_model_api_config(
    api_key: str,
    base_url: str,
    model: str,
) -> LLMConfig:
    """Validate and normalize settings before any credential-bearing request."""

    if not all(isinstance(value, str) for value in (api_key, base_url, model)):
        raise ModelApiConfigError("模型 API 配置必须是文本")
    key = api_key.strip()
    endpoint = base_url.strip().rstrip("/")
    selected_model = model.strip()
    if (
        not key
        or len(key) > 4096
        or any(character in key for character in "\x00\r\n")
    ):
        raise ModelApiConfigError("API Key 不能为空或包含非法字符")
    if _MODEL.fullmatch(selected_model) is None:
        raise ModelApiConfigError("模型名称格式非法")
    if (
        not endpoint
        or len(endpoint) > 2048
        or any(ord(character) < 32 or ord(character) == 127 for character in endpoint)
    ):
        raise ModelApiConfigError("模型 API 地址格式非法")
    try:
        parsed = urlsplit(endpoint)
        _port = parsed.port
    except ValueError as error:
        raise ModelApiConfigError("模型 API 地址格式非法") from error
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ModelApiConfigError("模型 API 地址不能包含账号、查询参数或片段")
    try:
        config = LLMConfig(
            api_key=key,
            base_url=endpoint,
            model=selected_model,
            timeout_seconds=20.0,
            max_retries=2,
        )
        OpenAICompatibleProvider(config)
    except ValueError as error:
        raise ModelApiConfigError("模型 API 地址或模型名称无效") from error
    return config


def save_model_api_config(
    path: str | Path,
    *,
    api_key: str,
    base_url: str,
    model: str,
    actor_id: str,
) -> LLMConfig:
    if actor_id != "api_admin":
        raise ModelApiConfigError("只有固定账号 api_admin 可以保存模型 API")
    config = validate_model_api_config(api_key, base_url, model)
    target = _path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.is_symlink():
        raise ModelApiConfigError("模型 API 配置文件不能是链接")
    protection = DPAPI_PROTECTION if os.name == "nt" else POSIX_PROTECTION
    key_bytes = config.api_key.encode("utf-8")
    protected = (
        _dpapi_protect(key_bytes, _ENTROPY)
        if protection == DPAPI_PROTECTION
        else key_bytes
    )
    public = {
        "format": FORMAT,
        "base_url": config.base_url,
        "model": config.model,
        "protection": protection,
        "updated_at": _timestamp(),
        "updated_by": actor_id,
    }
    integrity = hmac.new(
        hashlib.sha256(key_bytes).digest(),
        canonical_json(public).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    document = {
        **public,
        "api_key_protected_b64": base64.b64encode(protected).decode("ascii"),
        "integrity_hmac": integrity,
    }
    encoded = (canonical_json(document) + "\n").encode("utf-8")
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        if os.name != "nt":
            os.chmod(target, 0o600)
    finally:
        with suppress(OSError):
            temporary.unlink()
    return config


def load_model_api_config(
    path: str | Path,
) -> tuple[LLMConfig | None, dict[str, Any]]:
    target = _path(path)
    if not target.exists():
        return None, {
            "managed": True,
            "state": "not_configured",
            "source": "api_admin",
        }
    if target.is_symlink() or not target.is_file():
        raise ModelApiConfigError("模型 API 配置文件类型不安全")
    metadata = target.stat()
    if metadata.st_size <= 0 or metadata.st_size > 64 * 1024:
        raise ModelApiConfigError("模型 API 配置文件大小非法")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise ModelApiConfigError("模型 API 配置文件必须使用 0600 权限")
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ModelApiConfigError("模型 API 配置文件无法读取") from error
    fields = {
        "format",
        "base_url",
        "model",
        "protection",
        "updated_at",
        "updated_by",
        "api_key_protected_b64",
        "integrity_hmac",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise ModelApiConfigError("模型 API 配置字段非法")
    if document["format"] != FORMAT or document["updated_by"] != "api_admin":
        raise ModelApiConfigError("模型 API 配置来源非法")
    expected_protection = DPAPI_PROTECTION if os.name == "nt" else POSIX_PROTECTION
    if document["protection"] != expected_protection:
        raise ModelApiConfigError("模型 API 配置保护方式与当前系统不匹配")
    try:
        protected = base64.b64decode(document["api_key_protected_b64"], validate=True)
        key_bytes = (
            _dpapi_unprotect(protected, _ENTROPY)
            if expected_protection == DPAPI_PROTECTION
            else protected
        )
        api_key = key_bytes.decode("utf-8")
    except (TypeError, ValueError, UnicodeError, OSError) as error:
        raise ModelApiConfigError("模型 API Key 无法解密") from error
    for name in ("base_url", "model", "updated_at", "updated_by"):
        if not isinstance(document[name], str):
            raise ModelApiConfigError("模型 API 配置字段类型非法")
    public = {
        name: document[name]
        for name in fields - {"api_key_protected_b64", "integrity_hmac"}
    }
    expected_hmac = hmac.new(
        hashlib.sha256(key_bytes).digest(),
        canonical_json(public).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(document["integrity_hmac"], str) or not hmac.compare_digest(
        document["integrity_hmac"], expected_hmac
    ):
        raise ModelApiConfigError("模型 API 配置完整性校验失败")
    config = validate_model_api_config(
        api_key,
        document["base_url"],
        document["model"],
    )
    return config, {
        "managed": True,
        "state": "configured",
        "source": "api_admin",
        "model": config.model,
        "base_url": config.base_url,
        "updated_at": document["updated_at"],
        "updated_by": "api_admin",
        "secret_protection": expected_protection,
    }


def verify_model_api_config(path: str | Path, expected: LLMConfig) -> None:
    current, _status = load_model_api_config(path)
    if current is None or not (
        hmac.compare_digest(current.api_key.encode(), expected.api_key.encode())
        and current.base_url == expected.base_url
        and current.model == expected.model
    ):
        raise ModelApiConfigError("模型 API 配置在运行期间被改变")


__all__ = [
    "ModelApiConfigError",
    "load_model_api_config",
    "save_model_api_config",
    "validate_model_api_config",
    "verify_model_api_config",
]
