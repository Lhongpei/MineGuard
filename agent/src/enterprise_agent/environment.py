"""Strict, non-executable environment-file loading.

The Windows service wrapper cannot safely dot-source a PowerShell script that
contains credentials.  This module accepts only ``KEY=VALUE`` records and
places them in the current process environment before ``Settings`` is built.
It intentionally implements no variable expansion or command substitution.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import MutableMapping
from pathlib import Path

_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_MAX_ENVIRONMENT_FILE_BYTES = 1024 * 1024


def _is_reparse_point(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    is_junction = getattr(path, "is_junction", None)
    return bool(
        path.is_symlink()
        or (callable(is_junction) and is_junction())
        or (reparse_flag and attributes & reparse_flag)
    )


def _read_environment_bytes(path: str | Path) -> tuple[Path, bytes]:
    requested = Path(path).expanduser()
    if not requested.is_absolute():
        raise ValueError("环境文件必须使用绝对路径")
    # The file and every existing parent must be real paths rather than a
    # symlink, Windows junction or other reparse point.  This keeps an
    # ACL-protected service configuration from being redirected elsewhere.
    for candidate in (requested, *requested.parents):
        if candidate.exists() and _is_reparse_point(candidate):
            raise ValueError(f"环境文件路径不能包含链接或重解析点：{requested}")
    try:
        before = requested.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"环境文件不存在：{requested}") from error
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"环境文件必须是普通文件：{requested}")
    if before.st_size > _MAX_ENVIRONMENT_FILE_BYTES:
        raise ValueError("环境文件不得超过 1 MiB")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(requested, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError(f"环境文件必须是普通文件：{requested}")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("环境文件在读取前发生变化")
        if opened.st_size > _MAX_ENVIRONMENT_FILE_BYTES:
            raise ValueError("环境文件不得超过 1 MiB")
        chunks: list[bytes] = []
        remaining = _MAX_ENVIRONMENT_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > _MAX_ENVIRONMENT_FILE_BYTES:
            raise ValueError("环境文件不得超过 1 MiB")
        return requested.resolve(), content
    finally:
        os.close(descriptor)


def parse_environment_file(path: str | Path) -> dict[str, str]:
    """Parse a UTF-8/BOM ``KEY=VALUE`` file without executing its contents."""

    resolved, encoded = _read_environment_bytes(path)
    try:
        content = encoded.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError(f"环境文件必须是 UTF-8 编码：{resolved}") from error

    values: dict[str, str] = {}
    for line_number, original in enumerate(content.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(
                f"环境文件第 {line_number} 行必须使用 KEY=VALUE：{resolved}"
            )
        name, raw_value = line.split("=", 1)
        name = name.strip()
        if not _ENVIRONMENT_NAME.fullmatch(name):
            raise ValueError(f"环境文件第 {line_number} 行变量名非法：{resolved}")
        if name in values:
            raise ValueError(f"环境文件第 {line_number} 行重复定义 {name}：{resolved}")
        value = raw_value.strip()
        if value.startswith(("'", '"')):
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise ValueError(f"环境文件第 {line_number} 行引号不完整：{resolved}")
            value = value[1:-1]
        if "\x00" in value or "\r" in value or "\n" in value:
            raise ValueError(f"环境文件第 {line_number} 行包含非法控制字符：{resolved}")
        values[name] = value
    return values


def load_environment_file(
    path: str | Path,
    *,
    environment: MutableMapping[str, str] | None = None,
    override: bool = False,
) -> tuple[str, ...]:
    """Load a strict environment file and return the names that were applied.

    Inherited service/process variables win by default.  This permits a secret
    manager or an emergency service-level override without changing the ACL-
    protected instance file.
    """

    target = os.environ if environment is None else environment
    loaded: list[str] = []
    for name, value in parse_environment_file(path).items():
        if override or name not in target:
            target[name] = value
            loaded.append(name)
    return tuple(loaded)
