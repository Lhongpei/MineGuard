"""Safe SQLite backup and offline restore primitives.

Backups use SQLite's online backup API so a running WAL database is captured as
one consistent file.  Restore remains an offline operation and always creates a
rollback snapshot of an existing database before replacing it.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .storage import _SCHEMA_VERSION
from .util import canonical_json

_MANIFEST_SUFFIX = ".manifest.json"


def _resolved_database(path: str | Path, *, label: str) -> Path:
    if str(path) == ":memory:":
        raise ValueError(f"{label}不能使用内存数据库")
    resolved = Path(path).expanduser().resolve()
    if resolved == Path(resolved.anchor):
        raise ValueError(f"{label}不能是文件系统根目录")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_agent_database(path: Path) -> int:
    try:
        connection = sqlite3.connect(str(path), timeout=10)
        try:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or str(result[0]).lower() != "ok":
                raise ValueError("SQLite 完整性检查未通过")
            version = connection.execute(
                """
                SELECT version FROM app_schema_versions
                WHERE component = 'enterprise_agent'
                """
            ).fetchone()
            if version is None or int(version[0]) < 1:
                raise ValueError("不是可识别的企业智能体状态库")
            parsed_version = int(version[0])
            if parsed_version > _SCHEMA_VERSION:
                raise ValueError("备份 schema 版本高于当前程序支持版本")
            return parsed_version
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise ValueError(f"数据库校验失败：{path}") from error


def _copy_sqlite(source: Path, destination: Path) -> int:
    source_connection = sqlite3.connect(str(source), timeout=30)
    destination_connection = sqlite3.connect(str(destination), timeout=30)
    try:
        source_connection.execute("PRAGMA query_only=ON")
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()
    return _validate_agent_database(destination)


def _atomic_text(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        with suppress(OSError):
            temporary.unlink()
        raise


def backup_database(
    database_path: str | Path,
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create one consistent SQLite backup and a SHA-256 manifest."""

    source = _resolved_database(database_path, label="源数据库")
    destination = _resolved_database(output_path, label="备份文件")
    if not source.is_file():
        raise ValueError(f"源数据库不存在：{source}")
    if source == destination:
        raise ValueError("备份文件不能覆盖正在使用的源数据库")
    manifest_path = Path(f"{destination}{_MANIFEST_SUFFIX}")
    if not overwrite and (destination.exists() or manifest_path.exists()):
        raise ValueError(f"备份目标已存在：{destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.unlink()
        schema_version = _copy_sqlite(source, temporary)
        # Windows' CRT rejects fsync/_commit on a read-only descriptor even
        # though POSIX accepts it.  Open the completed SQLite copy read/write
        # solely for the durability barrier before the atomic replace.
        with temporary.open("r+b") as stream:
            os.fsync(stream.fileno())
        size = temporary.stat().st_size
        digest = _sha256(temporary)
        os.replace(temporary, destination)
        with suppress(OSError):
            os.chmod(destination, 0o600)
        manifest = {
            "format": "enterprise-agent-sqlite-backup-v1",
            "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "database_file": destination.name,
            "bytes": size,
            "sha256": digest,
            "schema_version": schema_version,
        }
        _atomic_text(
            manifest_path,
            canonical_json(manifest) + "\n",
        )
        with suppress(OSError):
            os.chmod(manifest_path, 0o600)
        return {
            "backup_path": str(destination),
            "manifest_path": str(manifest_path),
            **manifest,
        }
    except BaseException:
        with suppress(OSError):
            temporary.unlink()
        raise


def _verify_manifest(backup: Path) -> None:
    manifest_path = Path(f"{backup}{_MANIFEST_SUFFIX}")
    if not manifest_path.exists():
        raise ValueError(f"备份清单不存在：{manifest_path}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"备份清单无法读取：{manifest_path}") from error
    if not isinstance(manifest, dict) or manifest.get("format") != (
        "enterprise-agent-sqlite-backup-v1"
    ):
        raise ValueError("备份清单格式不受支持")
    if manifest.get("database_file") != backup.name:
        raise ValueError("备份清单与数据库文件名不匹配")
    expected_size = manifest.get("bytes")
    if not isinstance(expected_size, int) or expected_size != backup.stat().st_size:
        raise ValueError("备份文件大小与清单不一致")
    expected_digest = manifest.get("sha256")
    if not isinstance(expected_digest, str) or expected_digest != _sha256(backup):
        raise ValueError("备份 SHA-256 与清单不一致")


def restore_database(
    database_path: str | Path,
    backup_path: str | Path,
    *,
    rollback_directory: str | Path,
) -> dict[str, Any]:
    """Restore a verified backup after the service has been stopped.

    The caller is responsible for stopping the Windows service.  Open SQLite
    handles normally make ``os.replace`` fail on Windows, which also prevents a
    live process from being silently overwritten.
    """

    destination = _resolved_database(database_path, label="目标数据库")
    backup = _resolved_database(backup_path, label="备份文件")
    if not backup.is_file():
        raise ValueError(f"备份文件不存在：{backup}")
    if destination == backup:
        raise ValueError("目标数据库与备份文件不能相同")
    _verify_manifest(backup)
    restored_schema_version = _validate_agent_database(backup)

    rollback_root = Path(rollback_directory).expanduser().resolve()
    if rollback_root == Path(rollback_root.anchor):
        raise ValueError("回滚目录不能是文件系统根目录")
    rollback_root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rollback_path: Path | None = None
    rollback_mode: str | None = None
    if destination.exists():
        rollback_path = rollback_root / f"pre-restore-{timestamp}.db"
        suffix = 1
        while rollback_path.exists():
            rollback_path = rollback_root / f"pre-restore-{timestamp}-{suffix}.db"
            suffix += 1
        try:
            backup_database(destination, rollback_path)
            rollback_mode = "consistent_sqlite_backup"
        except (ValueError, sqlite3.Error):
            # A corrupt live database is one of the main reasons to restore.
            # Preserve its exact stopped bytes (and any sidecars) for forensic
            # recovery instead of making corruption prevent restoration.
            rollback_path = rollback_root / f"pre-restore-{timestamp}-corrupt.db"
            suffix = 1
            while rollback_path.exists():
                rollback_path = rollback_root / (
                    f"pre-restore-{timestamp}-corrupt-{suffix}.db"
                )
                suffix += 1
            shutil.copy2(destination, rollback_path)
            for sidecar_suffix in ("-wal", "-shm"):
                source_sidecar = Path(f"{destination}{sidecar_suffix}")
                if source_sidecar.is_file():
                    shutil.copy2(
                        source_sidecar,
                        Path(f"{rollback_path}{sidecar_suffix}"),
                    )
            _atomic_text(
                Path(f"{rollback_path}.notice.txt"),
                "Unverified raw pre-restore database preserved because SQLite "
                "integrity validation failed.\n",
            )
            rollback_mode = "unverified_raw_corrupt_database"

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".restore",
        dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.unlink()
        _copy_sqlite(backup, temporary)
        # A stopped WAL database can leave empty sidecars.  They belong to the
        # old database generation and must not be attached to the restored one.
        for suffix in ("-wal", "-shm"):
            with suppress(FileNotFoundError):
                Path(f"{destination}{suffix}").unlink()
        os.replace(temporary, destination)
        with suppress(OSError):
            os.chmod(destination, 0o600)
    except BaseException:
        with suppress(OSError):
            temporary.unlink()
        raise

    return {
        "database_path": str(destination),
        "restored_from": str(backup),
        "schema_version": restored_schema_version,
        "rollback_backup": str(rollback_path) if rollback_path is not None else None,
        "rollback_mode": rollback_mode,
    }
