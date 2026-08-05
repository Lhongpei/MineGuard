from __future__ import annotations

import os
import stat
import time
import unicodedata
from pathlib import Path

from ..errors import SourceError
from ..models import RawBatch, SourceConfig
from .parsing import parse_records

_STABILITY: dict[tuple[str, str], tuple[int, int, float]] = {}


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _has_symlink_parent(candidate: Path, root: Path) -> bool:
    current = candidate
    while current != root:
        if current.is_symlink():
            return True
        current = current.parent
    return False


def _validate_relative_filename(candidate: Path, root: Path) -> None:
    try:
        parts = candidate.relative_to(root).parts
    except ValueError as exc:
        raise SourceError("file-drop 文件逃逸配置目录") from exc
    for part in parts:
        try:
            part.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise SourceError("file-drop 文件名必须是有效 UTF-8 文本") from exc
        if any(unicodedata.category(character) in {"Cc", "Cf"} for character in part):
            raise SourceError("file-drop 文件名不得包含控制或格式控制字符")


def _read_stable_file(path: Path, expected: os.stat_result, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SourceError(f"无法安全打开文件 {path.name}：{exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SourceError("file-drop 目标不是普通文件")
        if (
            before.st_dev != expected.st_dev
            or before.st_ino != expected.st_ino
            or before.st_size != expected.st_size
            or before.st_mtime_ns != expected.st_mtime_ns
        ):
            raise SourceError("file-drop 文件在打开前发生变化，延后处理")
        if before.st_size <= 0 or before.st_size > maximum:
            raise SourceError(f"文件为空或超过大小上限：{path.name}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        content = b"".join(chunks)
        if (
            len(content) != before.st_size
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise SourceError("file-drop 文件在读取期间发生变化，延后处理")
        return content
    finally:
        os.close(descriptor)


def collect_file_drop(config: SourceConfig) -> tuple[RawBatch, ...]:
    assert config.path is not None
    root = config.path.resolve()
    if not root.is_dir():
        raise SourceError(f"file-drop 目录不存在：{root}")
    batches: list[RawBatch] = []
    now = time.monotonic()
    try:
        candidates: list[Path] = []
        for candidate in root.glob(config.glob):
            _validate_relative_filename(candidate, root)
            candidates.append(candidate)
            if len(candidates) > config.max_files_per_poll:
                raise SourceError("file-drop 候选文件数超过 max_files_per_poll")
        candidates.sort(key=lambda path: path.as_posix())
    except (OSError, ValueError) as exc:
        raise SourceError(f"无法扫描 file-drop：{exc}") from exc
    active_keys: set[tuple[str, str]] = set()
    total_bytes = 0
    total_records = 0
    for candidate in candidates:
        if candidate.is_symlink() or _has_symlink_parent(candidate, root):
            continue
        resolved = candidate.resolve()
        if not _inside(resolved, root):
            raise SourceError("file-drop 文件逃逸配置目录")
        key = (config.id, str(resolved))
        active_keys.add(key)
        try:
            info = candidate.stat(follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        total_bytes += info.st_size
        if total_bytes > config.max_total_bytes:
            raise SourceError("file-drop 单轮文件总大小超过 max_total_bytes")
        fingerprint = (info.st_size, info.st_mtime_ns)
        prior = _STABILITY.get(key)
        if prior is None or prior[:2] != fingerprint:
            _STABILITY[key] = (*fingerprint, now)
            continue
        if now - prior[2] < config.stable_seconds:
            continue
        content = _read_stable_file(candidate, info, config.max_bytes)
        records = parse_records(
            content,
            data_format=config.format,
            records_path=config.records_path,
            max_records=config.max_records,
        )
        total_records += len(records)
        if total_records > config.max_total_records:
            raise SourceError("file-drop 单轮记录总数超过 max_total_records")
        batches.append(
            RawBatch(
                source_id=config.id,
                original_filename=candidate.name,
                records=records,
            )
        )
    root_prefix = f"{root}{os.sep}"
    for stale_key in tuple(_STABILITY):
        source_id, path = stale_key
        if source_id == config.id and path.startswith(root_prefix) and stale_key not in active_keys:
            _STABILITY.pop(stale_key, None)
    return tuple(batches)
