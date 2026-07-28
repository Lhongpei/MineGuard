"""Filesystem-backed source HMAC keys for a controlled intranet trial.

Keys are never addressed by caller-controlled path components.  The filename
is a SHA-256 digest of the source identifier and files are created with mode
0600.  This is intentionally a small single-node key store; production
deployments should replace it with the organisation's KMS/HSM.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import threading


class SourceKeyError(RuntimeError):
    """Base class for source-key persistence errors."""


class SourceKeyConflictError(SourceKeyError):
    """A source already has a different immutable trial key."""


class SourceKeyStore:
    def __init__(self, directory: str | Path) -> None:
        raw = os.fspath(directory)
        if not raw.strip():
            raise ValueError("source key directory must be explicit")
        self.directory = Path(raw).expanduser().resolve()
        if self.directory == Path(self.directory.anchor):
            raise ValueError("filesystem root cannot be a source key directory")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass
        self.database_path = self.directory / "source-keys.db"
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
            timeout=10,
        )
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS source_keys (
                    source_id TEXT PRIMARY KEY,
                    secret BLOB NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS system_secrets (
                    name TEXT PRIMARY KEY,
                    secret BLOB NOT NULL
                )
                """
            )
        try:
            self.database_path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @staticmethod
    def _validate_source_id(source_id: str) -> str:
        if (
            not isinstance(source_id, str)
            or not source_id.strip()
            or len(source_id) > 128
            or "\x00" in source_id
        ):
            raise ValueError("source_id must be non-empty safe text")
        return source_id

    def _path(self, source_id: str) -> Path:
        normalized = self._validate_source_id(source_id)
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.key"

    def put(self, source_id: str, secret: bytes | str) -> bool:
        """Create an immutable key; return ``False`` for an exact retry."""

        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError("source HMAC secret must contain at least 16 bytes")
        path = self._path(source_id)
        with self._lock:
            existing = self.get(source_id)
            if existing is not None:
                if hmac.compare_digest(existing, secret):
                    return False
                raise SourceKeyConflictError(
                    "source already has a different key; "
                    "register a new source id"
                )

            file_created = False
            try:
                try:
                    descriptor = os.open(
                        path,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                except FileExistsError:
                    file_secret = path.read_bytes()
                    if not hmac.compare_digest(file_secret, secret):
                        raise SourceKeyConflictError(
                            "source key file contains different content"
                        )
                else:
                    file_created = True
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(secret)
                        stream.flush()
                        os.fsync(stream.fileno())
                with self._connection:
                    self._connection.execute(
                        "INSERT INTO source_keys(source_id, secret) "
                        "VALUES (?, ?)",
                        (source_id, secret),
                    )
            except BaseException:
                if file_created:
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                raise
        return True

    def get(self, source_id: str) -> bytes | None:
        path = self._path(source_id)
        with self._lock:
            row = self._connection.execute(
                "SELECT secret FROM source_keys WHERE source_id = ?",
                (source_id,),
            ).fetchone()
            if row is not None:
                secret = bytes(row[0])
                return secret if len(secret) >= 16 else None
            try:
                secret = path.read_bytes()
            except FileNotFoundError:
                return None
            if len(secret) < 16:
                return None
            # Migrate a legacy per-file key into the backupable SQLite store.
            with self._connection:
                self._connection.execute(
                    "INSERT OR IGNORE INTO source_keys(source_id, secret) "
                    "VALUES (?, ?)",
                    (source_id, secret),
                )
            return secret

    def exists(self, source_id: str) -> bool:
        return self.get(source_id) is not None

    def put_system(self, name: str, secret: bytes) -> bool:
        """Store an immutable system recovery secret in the backupable DB."""

        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 128
            or "\x00" in name
        ):
            raise ValueError("system secret name must be safe non-empty text")
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("system secret must contain at least 32 bytes")
        with self._lock:
            row = self._connection.execute(
                "SELECT secret FROM system_secrets WHERE name = ?",
                (name,),
            ).fetchone()
            if row is not None:
                if hmac.compare_digest(bytes(row[0]), secret):
                    return False
                raise SourceKeyConflictError(
                    "system recovery secret already has different content"
                )
            with self._connection:
                self._connection.execute(
                    "INSERT INTO system_secrets(name, secret) VALUES (?, ?)",
                    (name, secret),
                )
        return True

    def get_system(self, name: str) -> bytes | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT secret FROM system_secrets WHERE name = ?",
                (name,),
            ).fetchone()
        return bytes(row[0]) if row is not None else None


__all__ = [
    "SourceKeyConflictError",
    "SourceKeyError",
    "SourceKeyStore",
]
