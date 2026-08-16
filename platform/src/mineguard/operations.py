"""Operational building blocks for a single-node or intranet deployment.

The module deliberately depends only on the Python standard library.  Backup
manifests are authenticated with HMAC (integrity and origin authentication);
they are not digital signatures and do not provide non-repudiation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, TextIO


ReadinessStatus = Literal["ready", "degraded", "not_ready"]

_BACKUP_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MANIFEST_FILENAME = "manifest.json"
_AUTH_FILENAME = "manifest.hmac"
_RESERVED_FILENAMES = {_MANIFEST_FILENAME, _AUTH_FILENAME}
_REDACTED = "[REDACTED]"
_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "signature",
    "cookie",
    "authorization",
    "csrf",
    "person_id",
)


class OperationsError(RuntimeError):
    """Base class for errors safe to map to an operational failure."""


class UnsafePathError(OperationsError):
    """A caller supplied an ambiguous or escaping path."""


class BackupExistsError(OperationsError):
    """A backup identifier has already been used."""


class BackupNotFoundError(OperationsError):
    """The requested backup does not exist."""


class BackupVerificationError(OperationsError):
    """The authenticated manifest or one of its files is invalid."""


class RestoreTargetError(OperationsError):
    """The restore destination is unsafe or would overwrite data."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _canonical_json(value: Any) -> bytes:
    try:
        document = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not valid canonical JSON") from exc
    return document.encode("utf-8")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _fsync_file(path: Path) -> None:
    # Windows' CRT rejects fsync/_commit on a read-only descriptor.  The file
    # is already complete; open it read/write only to issue the durability
    # barrier before publishing the backup generation.
    with path.open("r+b") as stream:
        os.fsync(stream.fileno())


def _fsync_directory(path: Path) -> None:
    """Best-effort directory fsync (not supported by every platform)."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _write_new_file(path: Path, payload: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _validate_component(value: str, *, label: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or Path(value).name != value
    ):
        raise UnsafePathError(f"{label} must be a single safe path component")
    return value


def _validate_backup_id(backup_id: str) -> str:
    if not isinstance(backup_id, str) or not _BACKUP_ID_PATTERN.fullmatch(
        backup_id
    ):
        raise UnsafePathError("backup_id contains unsafe characters")
    return backup_id


def _sqlite_integrity_check(database: Path) -> None:
    try:
        uri = f"{database.resolve().as_uri()}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, timeout=10)
        try:
            rows = connection.execute("PRAGMA integrity_check").fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise BackupVerificationError(
            f"SQLite integrity check could not run for {database.name}"
        ) from exc
    if rows != [("ok",)]:
        raise BackupVerificationError(
            f"SQLite integrity check failed for {database.name}"
        )


class BackupManager:
    """Create, authenticate, verify, and restore consistent SQLite backups.

    Each backup is a directory below ``backup_directory``.  ``databases`` may
    be a path, an iterable of paths, or a mapping from safe destination
    filename to source path.  Mapping names are useful when source databases
    in different directories have the same basename.
    """

    def __init__(
        self,
        backup_directory: str | os.PathLike[str],
        hmac_key: bytes | str,
        key_id: str,
        app_version: str,
    ) -> None:
        raw_directory = os.fspath(backup_directory)
        if not raw_directory.strip():
            raise UnsafePathError("backup_directory must be explicit")
        self.backup_directory = Path(raw_directory).expanduser().resolve()
        if self.backup_directory == Path(self.backup_directory.anchor):
            raise UnsafePathError("filesystem root cannot be a backup directory")
        if self.backup_directory.exists() and not self.backup_directory.is_dir():
            raise UnsafePathError("backup_directory is not a directory")
        self.backup_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.backup_directory.chmod(0o700)
        except OSError:
            pass

        if isinstance(hmac_key, str):
            hmac_key = hmac_key.encode("utf-8")
        if not isinstance(hmac_key, bytes) or not hmac_key:
            raise ValueError("hmac_key must be non-empty bytes or text")
        self._hmac_key = hmac_key
        self.key_id = _validate_component(str(key_id), label="key_id")
        self.app_version = str(app_version)
        if not self.app_version:
            raise ValueError("app_version must not be empty")
        self._lock = threading.RLock()

    def _backup_path(self, backup_id: str) -> Path:
        safe_id = _validate_backup_id(backup_id)
        candidate = self.backup_directory / safe_id
        # The id validation is the primary boundary; this check is defense in
        # depth for platforms with unusual path semantics.
        if candidate.parent.resolve() != self.backup_directory:
            raise UnsafePathError("backup path escapes backup_directory")
        return candidate

    @staticmethod
    def _normalise_databases(
        databases: (
            str
            | os.PathLike[str]
            | Iterable[str | os.PathLike[str]]
            | Mapping[str, str | os.PathLike[str]]
        ),
    ) -> list[tuple[str, Path]]:
        if isinstance(databases, Mapping):
            candidates = [
                (str(filename), Path(source).expanduser().resolve())
                for filename, source in databases.items()
            ]
        elif isinstance(databases, (str, os.PathLike)):
            source = Path(databases).expanduser().resolve()
            candidates = [(source.name, source)]
        else:
            candidates = []
            for item in databases:
                source = Path(item).expanduser().resolve()
                candidates.append((source.name, source))

        if not candidates:
            raise ValueError("at least one SQLite database is required")
        normalised: list[tuple[str, Path]] = []
        seen: set[str] = set()
        for filename, source in candidates:
            _validate_component(filename, label="backup filename")
            if filename in _RESERVED_FILENAMES:
                raise UnsafePathError("backup filename is reserved")
            if filename in seen:
                raise ValueError(f"duplicate backup filename: {filename}")
            if not source.exists() or not source.is_file():
                raise FileNotFoundError(f"SQLite database not found: {source}")
            seen.add(filename)
            normalised.append((filename, source))
        return sorted(normalised, key=lambda item: item[0])

    @staticmethod
    def _copy_sqlite_consistently(source: Path, destination: Path) -> None:
        source_uri = f"{source.as_uri()}?mode=ro"
        try:
            source_connection = sqlite3.connect(
                source_uri, uri=True, timeout=10
            )
            destination_connection = sqlite3.connect(destination, timeout=10)
            try:
                source_connection.backup(destination_connection)
                # A backup can copy the source's WAL journal-mode setting.
                # Standalone backup files must not create unmanifested
                # ``-wal``/``-shm`` sidecars during later verification.
                destination_connection.execute("PRAGMA journal_mode=DELETE")
            finally:
                destination_connection.close()
                source_connection.close()
        except sqlite3.Error as exc:
            raise OperationsError(
                f"SQLite backup failed for {source.name}"
            ) from exc
        _sqlite_integrity_check(destination)
        try:
            destination.chmod(0o600)
        except OSError:
            pass
        _fsync_file(destination)

    def create_backup(
        self,
        backup_id: str,
        databases: (
            str
            | os.PathLike[str]
            | Iterable[str | os.PathLike[str]]
            | Mapping[str, str | os.PathLike[str]]
        ),
    ) -> dict[str, Any]:
        """Create one immutable backup directory and return its manifest."""

        destination = self._backup_path(backup_id)
        sources = self._normalise_databases(databases)
        reservation = self.backup_directory / f".reserve-{backup_id}"
        stage: Path | None = None

        with self._lock:
            if destination.exists() or destination.is_symlink():
                raise BackupExistsError(f"backup already exists: {backup_id}")
            try:
                reserve_descriptor = os.open(
                    reservation,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                os.close(reserve_descriptor)
            except FileExistsError as exc:
                raise BackupExistsError(
                    f"backup is already being created: {backup_id}"
                ) from exc

            try:
                stage = Path(
                    tempfile.mkdtemp(
                        prefix=f".{backup_id}.",
                        suffix=".tmp",
                        dir=self.backup_directory,
                    )
                )
                file_records: list[dict[str, Any]] = []
                for filename, source in sources:
                    backup_file = stage / filename
                    self._copy_sqlite_consistently(source, backup_file)
                    digest, size = _sha256_file(backup_file)
                    file_records.append(
                        {
                            "filename": filename,
                            "sha256": digest,
                            "size": size,
                        }
                    )

                manifest: dict[str, Any] = {
                    "schema_version": 1,
                    "backup_id": backup_id,
                    "created_at": _utc_now(),
                    "app_version": self.app_version,
                    "key_id": self.key_id,
                    "files": file_records,
                }
                manifest_bytes = _canonical_json(manifest)
                signature = hmac.new(
                    self._hmac_key, manifest_bytes, hashlib.sha256
                ).hexdigest()
                auth = {
                    "algorithm": "HMAC-SHA256",
                    "key_id": self.key_id,
                    "signature": signature,
                }
                _write_new_file(stage / _MANIFEST_FILENAME, manifest_bytes)
                _write_new_file(
                    stage / _AUTH_FILENAME, _canonical_json(auth)
                )
                _fsync_directory(stage)

                # The reservation prevents a cooperating second process from
                # racing this existence check and rename.
                if destination.exists() or destination.is_symlink():
                    raise BackupExistsError(
                        f"backup already exists: {backup_id}"
                    )
                os.rename(stage, destination)
                stage = None
                _fsync_directory(self.backup_directory)
                return manifest
            finally:
                if stage is not None:
                    shutil.rmtree(stage, ignore_errors=True)
                try:
                    reservation.unlink()
                except FileNotFoundError:
                    pass

    def backup(
        self,
        databases: (
            str
            | os.PathLike[str]
            | Iterable[str | os.PathLike[str]]
            | Mapping[str, str | os.PathLike[str]]
        ),
        *,
        backup_id: str,
    ) -> dict[str, Any]:
        """Keyword-friendly alias for :meth:`create_backup`."""

        return self.create_backup(backup_id, databases)

    def _verified_manifest(self, backup_id: str) -> dict[str, Any]:
        backup_path = self._backup_path(backup_id)
        if not backup_path.exists() or not backup_path.is_dir():
            raise BackupNotFoundError(f"backup not found: {backup_id}")
        if backup_path.is_symlink():
            raise BackupVerificationError("backup directory must not be a link")

        manifest_path = backup_path / _MANIFEST_FILENAME
        auth_path = backup_path / _AUTH_FILENAME
        try:
            manifest_bytes = manifest_path.read_bytes()
            auth_bytes = auth_path.read_bytes()
        except (FileNotFoundError, OSError) as exc:
            raise BackupVerificationError(
                "backup manifest or authentication record is missing"
            ) from exc

        try:
            manifest = json.loads(manifest_bytes)
            auth = json.loads(auth_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BackupVerificationError("backup metadata is not valid JSON") from exc
        if not isinstance(manifest, dict) or not isinstance(auth, dict):
            raise BackupVerificationError("backup metadata has an invalid shape")
        try:
            if manifest_bytes != _canonical_json(manifest):
                raise BackupVerificationError("manifest is not canonical JSON")
            if auth_bytes != _canonical_json(auth):
                raise BackupVerificationError(
                    "authentication record is not canonical JSON"
                )
        except ValueError as exc:
            raise BackupVerificationError("backup metadata is invalid") from exc

        if (
            manifest.get("schema_version") != 1
            or manifest.get("backup_id") != backup_id
            or manifest.get("key_id") != self.key_id
            or auth.get("algorithm") != "HMAC-SHA256"
            or auth.get("key_id") != self.key_id
            or not isinstance(auth.get("signature"), str)
        ):
            raise BackupVerificationError(
                "backup metadata or key identifier does not match"
            )
        expected_signature = hmac.new(
            self._hmac_key, manifest_bytes, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(auth["signature"], expected_signature):
            raise BackupVerificationError("manifest authentication failed")

        files = manifest.get("files")
        if not isinstance(files, list) or not files:
            raise BackupVerificationError("manifest has no database files")
        expected_names = {_MANIFEST_FILENAME, _AUTH_FILENAME}
        seen: set[str] = set()
        for record in files:
            if not isinstance(record, dict):
                raise BackupVerificationError("manifest file record is invalid")
            filename = record.get("filename")
            try:
                _validate_component(filename, label="backup filename")
            except (TypeError, UnsafePathError) as exc:
                raise BackupVerificationError(
                    "manifest contains an unsafe filename"
                ) from exc
            if filename in _RESERVED_FILENAMES or filename in seen:
                raise BackupVerificationError(
                    "manifest contains a duplicate or reserved filename"
                )
            if (
                not isinstance(record.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                or not isinstance(record.get("size"), int)
                or isinstance(record.get("size"), bool)
                or record["size"] < 0
            ):
                raise BackupVerificationError("manifest file metadata is invalid")
            seen.add(filename)
            expected_names.add(filename)
            file_path = backup_path / filename
            if file_path.is_symlink() or not file_path.is_file():
                raise BackupVerificationError(
                    f"backup file is missing or unsafe: {filename}"
                )
            digest, size = _sha256_file(file_path)
            if (
                not hmac.compare_digest(digest, record["sha256"])
                or size != record["size"]
            ):
                raise BackupVerificationError(
                    f"backup file verification failed: {filename}"
                )

        actual_names = {item.name for item in backup_path.iterdir()}
        if actual_names != expected_names:
            raise BackupVerificationError(
                "backup directory contains unmanifested files"
            )
        return manifest

    def verify(self, backup_id: str) -> dict[str, Any]:
        """Verify HMAC, hashes, sizes, names, and directory membership."""

        return self._verified_manifest(backup_id)

    def verify_backup(self, backup_id: str) -> bool:
        """Boolean convenience wrapper; verification failures still raise."""

        self._verified_manifest(backup_id)
        return True

    def list_backups(self) -> list[dict[str, Any]]:
        """List candidate backups and report verification without leaking paths."""

        items: list[dict[str, Any]] = []
        with self._lock:
            candidates = sorted(
                (
                    path
                    for path in self.backup_directory.iterdir()
                    if path.is_dir()
                    and not path.is_symlink()
                    and _BACKUP_ID_PATTERN.fullmatch(path.name)
                ),
                key=lambda path: path.name,
                reverse=True,
            )
            for path in candidates:
                try:
                    manifest = self._verified_manifest(path.name)
                except OperationsError:
                    items.append(
                        {
                            "backup_id": path.name,
                            "verification": "invalid",
                        }
                    )
                else:
                    items.append(
                        {
                            "backup_id": path.name,
                            "verification": "valid",
                            "created_at": manifest["created_at"],
                            "app_version": manifest["app_version"],
                            "files": manifest["files"],
                        }
                    )
        return items

    @staticmethod
    def _validate_restore_target(
        target_directory: str | os.PathLike[str],
    ) -> tuple[Path, bool]:
        raw_target = os.fspath(target_directory)
        if not raw_target.strip() or raw_target.strip() in {".", ".."}:
            raise RestoreTargetError("restore target must be explicit")
        expanded = Path(raw_target).expanduser()
        if expanded.is_symlink():
            raise RestoreTargetError("restore target must not be a link")
        target = expanded.resolve()
        if target == Path(target.anchor):
            raise RestoreTargetError("filesystem root cannot be restored into")
        existed = target.exists()
        if existed:
            if not target.is_dir():
                raise RestoreTargetError(
                    "restore target exists and is not a directory"
                )
            try:
                next(target.iterdir())
            except StopIteration:
                pass
            else:
                raise RestoreTargetError(
                    "restore target must be empty or nonexistent"
                )
        return target, existed

    def restore(
        self,
        backup_id: str,
        target_directory: str | os.PathLike[str],
    ) -> Path:
        """Restore into an explicitly empty or nonexistent directory.

        Files are copied and checked in a sibling staging directory.  The
        destination is made visible only after all hashes and SQLite integrity
        checks pass.
        """

        manifest = self._verified_manifest(backup_id)
        backup_path = self._backup_path(backup_id)
        target, target_existed = self._validate_restore_target(target_directory)
        if target == self.backup_directory or self.backup_directory in target.parents:
            raise RestoreTargetError(
                "restore target must be outside the backup directory"
            )

        parent = target.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        reservation = parent / f".restore-{target.name}.lock"
        stage: Path | None = None
        installed = False

        with self._lock:
            # Revalidate under the in-process lock before reserving the name.
            current_target, current_existed = self._validate_restore_target(
                target
            )
            if current_target != target or current_existed != target_existed:
                raise RestoreTargetError("restore target changed during validation")
            try:
                descriptor = os.open(
                    reservation,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                os.close(descriptor)
            except FileExistsError as exc:
                raise RestoreTargetError(
                    "another restore is already using this destination"
                ) from exc

            try:
                stage = Path(
                    tempfile.mkdtemp(
                        prefix=f".{target.name}.restore-",
                        dir=parent,
                    )
                )
                for record in manifest["files"]:
                    filename = record["filename"]
                    source = backup_path / filename
                    if source.is_symlink() or not source.is_file():
                        raise BackupVerificationError(
                            f"backup file changed during restore: {filename}"
                        )
                    destination = stage / filename
                    with source.open("rb") as source_stream:
                        with destination.open("xb") as destination_stream:
                            shutil.copyfileobj(
                                source_stream,
                                destination_stream,
                                length=1024 * 1024,
                            )
                            destination_stream.flush()
                            os.fsync(destination_stream.fileno())
                    try:
                        destination.chmod(0o600)
                    except OSError:
                        pass
                    digest, size = _sha256_file(destination)
                    if (
                        not hmac.compare_digest(digest, record["sha256"])
                        or size != record["size"]
                    ):
                        raise BackupVerificationError(
                            f"restored copy verification failed: {filename}"
                        )
                    _sqlite_integrity_check(destination)
                _fsync_directory(stage)

                if target_existed:
                    target.rmdir()
                os.rename(stage, target)
                stage = None
                installed = True
                _fsync_directory(parent)

                # Check the files at their final paths as well.  If this check
                # fails, the entire just-restored directory is removed.
                for record in manifest["files"]:
                    _sqlite_integrity_check(target / record["filename"])
                return target
            except BaseException:
                if installed:
                    shutil.rmtree(target, ignore_errors=True)
                    installed = False
                if target_existed and not target.exists():
                    try:
                        target.mkdir(mode=0o700)
                    except OSError:
                        pass
                raise
            finally:
                if stage is not None:
                    shutil.rmtree(stage, ignore_errors=True)
                try:
                    reservation.unlink()
                except FileNotFoundError:
                    pass


@dataclass(frozen=True)
class ReadinessCheckResult:
    """A normalized result returned by a readiness callback."""

    status: ReadinessStatus = "ready"
    message: str = "正常"

    def __post_init__(self) -> None:
        if self.status not in {"ready", "degraded", "not_ready"}:
            raise ValueError("invalid readiness status")


@dataclass(frozen=True)
class _RegisteredCheck:
    callback: Callable[[], Any]
    required: bool
    public_error_message: str


class ReadinessChecker:
    """Run isolated dependency checks without exposing exception details."""

    def __init__(self, service: str = "mineguard") -> None:
        self.service = service
        self._checks: dict[str, _RegisteredCheck] = {}
        self._lock = threading.RLock()

    def register(
        self,
        name: str,
        callback: Callable[[], Any],
        *,
        required: bool = True,
        public_error_message: str = "检查执行失败",
        replace: bool = False,
    ) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("check name must not be empty")
        if not callable(callback):
            raise TypeError("check callback must be callable")
        if not isinstance(public_error_message, str):
            raise TypeError("public_error_message must be text")
        with self._lock:
            if name in self._checks and not replace:
                raise ValueError(f"readiness check already registered: {name}")
            self._checks[name] = _RegisteredCheck(
                callback=callback,
                required=required,
                public_error_message=public_error_message,
            )

    def unregister(self, name: str) -> None:
        with self._lock:
            self._checks.pop(name, None)

    @staticmethod
    def _normalise_result(value: Any) -> ReadinessCheckResult:
        if isinstance(value, ReadinessCheckResult):
            return value
        if value is None or value is True:
            return ReadinessCheckResult()
        if value is False:
            return ReadinessCheckResult("not_ready", "检查未通过")
        if isinstance(value, str):
            if value in {"ready", "degraded", "not_ready"}:
                return ReadinessCheckResult(value, value)
            raise ValueError("callback returned an invalid status")
        if isinstance(value, Mapping):
            return ReadinessCheckResult(
                status=value.get("status", "ready"),
                message=str(value.get("message", "正常")),
            )
        if (
            isinstance(value, (tuple, list))
            and len(value) == 2
        ):
            return ReadinessCheckResult(
                status=value[0],
                message=str(value[1]),
            )
        raise ValueError("callback returned an unsupported result")

    def readiness(self) -> dict[str, Any]:
        with self._lock:
            registered = list(self._checks.items())

        checks: list[dict[str, Any]] = []
        overall: ReadinessStatus = "ready"
        for name, registration in registered:
            started = time.perf_counter()
            try:
                result = self._normalise_result(registration.callback())
            except Exception:
                # Neither exception type nor message is returned.  The caller
                # controls the only externally visible failure text.
                result = ReadinessCheckResult(
                    "not_ready" if registration.required else "degraded",
                    registration.public_error_message,
                )
            duration_ms = round(
                max(0.0, (time.perf_counter() - started) * 1000), 3
            )
            checks.append(
                {
                    "name": name,
                    "status": result.status,
                    "message": result.message,
                    "duration_ms": duration_ms,
                }
            )
            if result.status == "not_ready":
                overall = "not_ready"
            elif result.status == "degraded" and overall == "ready":
                overall = "degraded"

        return {
            "status": overall,
            "service": self.service,
            "timestamp": _utc_now(),
            "checks": checks,
        }

    def check(self) -> dict[str, Any]:
        """Alias used by simple HTTP adapters."""

        return self.readiness()

    def liveness(self) -> dict[str, str]:
        """Process liveness; intentionally does not execute dependencies."""

        return {
            "status": "alive",
            "service": self.service,
            "timestamp": _utc_now(),
        }

    def health(self) -> dict[str, str]:
        """Lightweight process health, separate from readiness."""

        return {
            "status": "ok",
            "service": self.service,
            "timestamp": _utc_now(),
        }


def _normalise_sensitive_key(key: Any) -> str:
    text = str(key)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _is_sensitive_key(key: Any) -> bool:
    normalized = _normalise_sensitive_key(key)
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            redacted[key_text] = (
                _REDACTED if _is_sensitive_key(key_text) else _redact(item)
            )
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [_redact(item) for item in sorted(value, key=repr)]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("audit record must not contain NaN or infinity")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(
        f"audit value of type {type(value).__name__} is not JSON serializable"
    )


class JsonAuditLogger:
    """Write one canonical, recursively redacted JSON object per line."""

    def __init__(self, stream: TextIO) -> None:
        if not hasattr(stream, "write"):
            raise TypeError("stream must be a text writer")
        self.stream = stream
        self._lock = threading.RLock()

    def log(
        self,
        action: str,
        outcome: str,
        *,
        request_id: str | None = None,
        actor: str | None = None,
        details: Mapping[str, Any] | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        record: dict[str, Any] = {
            "timestamp": _utc_now(),
            "action": str(action),
            "outcome": str(outcome),
            "request_id": request_id,
            "actor": actor,
        }
        if details is not None:
            record["details"] = details
        for key, value in fields.items():
            if key in record:
                raise ValueError(f"reserved audit field: {key}")
            record[key] = value
        safe_record = _redact(record)
        payload = _canonical_json(safe_record).decode("utf-8")
        with self._lock:
            self.stream.write(payload)
            self.stream.write("\n")
            flush = getattr(self.stream, "flush", None)
            if callable(flush):
                flush()
        return safe_record
