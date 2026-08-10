"""Local authentication and authorization for controlled MineGuard trials.

This module deliberately uses only the Python standard library and SQLite.  It
is suitable for a single-node, local trial behind TLS, not as a replacement for
an organisation's SSO/IAM service.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import threading
from typing import Any, Iterator
from urllib.parse import quote
from uuid import uuid4


class Role(StrEnum):
    ADMIN = "admin"
    SUPERVISOR = "supervisor"
    REVIEWER = "reviewer"
    VIEWER = "viewer"


class Permission(StrEnum):
    # Compact names are convenient for API middleware.  The domain-specific
    # names below allow finer-grained policy without changing this interface.
    READ = "read"
    ASSIGN = "assign"
    HANDLE = "handle"
    APPROVE = "approve"
    MANAGE_CONFIG = "manage_config"
    MANAGE_USERS = "manage_users"
    DATA_READ = "data.read"
    ANALYSIS_READ = "analysis.read"
    ANALYSIS_RUN = "analysis.run"
    CASE_READ = "case.read"
    CASE_ASSIGN = "case.assign"
    CASE_REVIEW = "case.review"
    CASE_APPROVE = "case.approve"
    CONFIG_MANAGE = "config.manage"
    USER_MANAGE = "user.manage"
    AUDIT_READ = "audit.read"


_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMIN: frozenset(Permission),
    Role.SUPERVISOR: frozenset(
        {
            Permission.READ,
            Permission.ASSIGN,
            Permission.HANDLE,
            Permission.APPROVE,
            Permission.DATA_READ,
            Permission.ANALYSIS_READ,
            Permission.ANALYSIS_RUN,
            Permission.CASE_READ,
            Permission.CASE_ASSIGN,
            Permission.CASE_REVIEW,
            Permission.CASE_APPROVE,
            Permission.AUDIT_READ,
        }
    ),
    Role.REVIEWER: frozenset(
        {
            Permission.READ,
            Permission.HANDLE,
            Permission.DATA_READ,
            Permission.ANALYSIS_READ,
            Permission.CASE_READ,
            Permission.CASE_REVIEW,
        }
    ),
    Role.VIEWER: frozenset(
        {
            Permission.READ,
            Permission.DATA_READ,
            Permission.ANALYSIS_READ,
            Permission.CASE_READ,
        }
    ),
}

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_PASSWORD_BYTES = 32
_KNOWN_DEMO_PASSWORDS = ("123123123",)
_MIN_STRONG_PASSWORD_LENGTH = 12
CURRENT_CREDENTIAL_POLICY_VERSION = 1
_COMMON_WEAK_PASSWORDS = frozenset(
    {
        "12345678",
        "123456789",
        "123123123",
        "admin123",
        "admin123456",
        "password",
        "password123",
        "qwerty123",
    }
)
_PLACEHOLDER_PASSWORD = re.compile(
    r"(?i)(?:replace(?:[_ -]|\b)|change[_ -]?me|demo[_ -]?only|"
    r"not[_ -]?for[_ -]?production)"
)


class AuthError(Exception):
    """Base class for stable authentication errors."""


class BootstrapConflictError(AuthError):
    pass


class UserConflictError(AuthError):
    pass


class UserNotFoundError(AuthError):
    pass


class LastActiveAdminError(AuthError):
    """Raised when a mutation would leave no enabled administrator."""


class InvalidCredentialsError(AuthError):
    pass


class LoginRateLimitedError(AuthError):
    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__(
            f"login temporarily locked; retry after "
            f"{self.retry_after_seconds} seconds"
        )


class InvalidSessionError(AuthError):
    pass


class SessionExpiredError(InvalidSessionError):
    pass


class CsrfValidationError(AuthError):
    pass


class UnknownPermissionError(AuthError):
    pass


class PermissionDeniedError(AuthError):
    pass


@dataclass(frozen=True)
class User:
    user_id: str
    username: str
    role: Role
    mine_scopes: tuple[str, ...]
    active: bool
    created_at: datetime
    updated_at: datetime
    must_change_password: bool = False
    temporary_demo: bool = False
    credential_policy_version: int = 0

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.value,
            "mine_scopes": list(self.mine_scopes),
            "active": self.active,
            "must_change_password": self.must_change_password,
            "temporary_demo": self.temporary_demo,
            "credential_policy_version": self.credential_policy_version,
            "created_at": _format_datetime(self.created_at),
            "updated_at": _format_datetime(self.updated_at),
        }


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    role: Role
    mine_scopes: tuple[str, ...]
    session_id: str
    active: bool = True
    must_change_password: bool = False
    temporary_demo: bool = False
    credential_policy_version: int = CURRENT_CREDENTIAL_POLICY_VERSION


@dataclass(frozen=True)
class LoginResult:
    """Credentials returned exactly once after a successful login."""

    session_token: str
    csrf_token: str
    principal: Principal
    absolute_expires_at: datetime
    idle_expires_at: datetime


@dataclass(frozen=True)
class Session:
    """Safe session metadata; token and CSRF digests are intentionally absent."""

    session_id: str
    user_id: str
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    idle_expires_at: datetime
    revoked_at: datetime | None

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "created_at": _format_datetime(self.created_at),
            "last_seen_at": _format_datetime(self.last_seen_at),
            "absolute_expires_at": _format_datetime(self.absolute_expires_at),
            "idle_expires_at": _format_datetime(self.idle_expires_at),
            "revoked_at": (
                None
                if self.revoked_at is None
                else _format_datetime(self.revoked_at)
            ),
        }


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _format_datetime(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("stored timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _normalise_username(username: str) -> tuple[str, str]:
    display = username.strip()
    if not display:
        raise ValueError("username is required")
    return display, display.casefold()


def _normalise_scopes(
    mine_scopes: Iterable[str],
    *,
    role: Role,
) -> tuple[str, ...]:
    scopes = tuple(sorted({scope.strip() for scope in mine_scopes if scope.strip()}))
    if role is not Role.ADMIN and not scopes:
        raise ValueError("non-admin users require at least one mine scope")
    return scopes


def _password_digest(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("password is required")
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_PASSWORD_BYTES,
    )


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _credential_flags(
    password: str,
    *,
    must_change_password: bool,
    temporary_demo: bool,
) -> tuple[bool, bool]:
    """Normalize durable credential-purpose flags.

    The built-in demonstration password is always classified as temporary and
    pending replacement, even when an older caller does not pass the newer
    keyword arguments.  This keeps the compatibility defaults safe.
    """

    known_demo = any(
        secrets.compare_digest(password, candidate)
        for candidate in _KNOWN_DEMO_PASSWORDS
    )
    is_temporary_demo = bool(temporary_demo or known_demo)
    return bool(must_change_password or is_temporary_demo), is_temporary_demo


def validate_strong_password(password: str) -> None:
    """Validate a production/self-service password without storing it."""

    if not isinstance(password, str) or not password:
        raise ValueError("password is required")
    if len(password) < _MIN_STRONG_PASSWORD_LENGTH:
        raise ValueError("password must contain at least 12 characters")
    if password.casefold() in _COMMON_WEAK_PASSWORDS:
        raise ValueError("password is a known weak or demonstration password")
    if _PLACEHOLDER_PASSWORD.search(password):
        raise ValueError("password must not contain example or placeholder text")
    categories = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if categories < 3:
        raise ValueError(
            "password must use at least three of lowercase, uppercase, digits, symbols"
        )


def _credential_policy_version_for_password(password: str) -> int:
    """Classify a newly written credential without weakening legacy writers."""

    try:
        validate_strong_password(password)
    except ValueError:
        return 0
    return CURRENT_CREDENTIAL_POLICY_VERSION


def _validated_credential_policy_version(value: object) -> int:
    """Read a durable policy marker, rejecting downgrade/future ambiguity."""

    if type(value) is not int or value not in {
        0,
        CURRENT_CREDENTIAL_POLICY_VERSION,
    }:
        raise AuthError("credential policy version is invalid or unsupported")
    return value


def _credential_status_from_rows(
    rows: Iterable[sqlite3.Row],
    *,
    forbidden_passwords: Iterable[str],
) -> dict[str, Any]:
    candidates = tuple(dict.fromkeys(forbidden_passwords))
    materialized = list(rows)
    blocked: list[dict[str, Any]] = []
    active_admin_count = 0
    active_ready_admin_count = 0
    pending_password_change_user_count = 0
    outdated_credential_policy_user_count = 0
    for row in materialized:
        if row["must_change_password"] not in (0, 1) or row[
            "temporary_demo"
        ] not in (0, 1):
            raise AuthError("credential-purpose flags are invalid")
        active = bool(row["active"])
        credential_policy_version = _validated_credential_policy_version(
            row["credential_policy_version"]
        )
        if active and row["role"] == Role.ADMIN.value:
            active_admin_count += 1
        reasons: list[str] = []
        if bool(row["must_change_password"]):
            reasons.append("must_change_password")
        if bool(row["temporary_demo"]):
            reasons.append("temporary_demo")
        if credential_policy_version != CURRENT_CREDENTIAL_POLICY_VERSION:
            reasons.append("credential_policy_outdated")
        for candidate in candidates:
            digest = _password_digest(candidate, row["password_salt"])
            if hmac.compare_digest(digest, row["password_hash"]):
                reasons.append("forbidden_weak_password")
                break
        if active and bool(row["must_change_password"]):
            pending_password_change_user_count += 1
        if active and credential_policy_version != CURRENT_CREDENTIAL_POLICY_VERSION:
            outdated_credential_policy_user_count += 1
        globally_blocking = active and any(
            reason in {
                "credential_policy_outdated",
                "temporary_demo",
                "forbidden_weak_password",
            }
            for reason in reasons
        )
        if globally_blocking:
            blocked.append(
                {
                    "username": str(row["username"]),
                    "reasons": sorted(set(reasons)),
                }
            )
        if (
            active
            and row["role"] == Role.ADMIN.value
            and not reasons
        ):
            active_ready_admin_count += 1
    return {
        "user_count": len(materialized),
        "active_admin_count": active_admin_count,
        "active_ready_admin_count": active_ready_admin_count,
        "production_ready": not blocked and active_ready_admin_count > 0,
        "blocked_user_count": len(blocked),
        "blocked_users": blocked,
        "pending_password_change_user_count": (
            pending_password_change_user_count
        ),
        "outdated_credential_policy_user_count": (
            outdated_credential_policy_user_count
        ),
    }


def inspect_auth_database(
    database: str | Path,
    *,
    forbidden_passwords: Iterable[str] = _COMMON_WEAK_PASSWORDS,
) -> dict[str, Any]:
    """Inspect a file-backed auth database without mutating or migrating it."""

    path = Path(database).expanduser().resolve()
    if not path.is_file():
        raise AuthError(f"authentication database does not exist: {path}")
    try:
        with sqlite3.connect(
            f"{path.as_uri()}?mode=ro", uri=True, timeout=5.0
        ) as connection:
            connection.row_factory = sqlite3.Row
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(users)")
            }
            required = {
                "username",
                "role",
                "active",
                "password_salt",
                "password_hash",
            }
            if not required.issubset(columns):
                raise AuthError("authentication database has an invalid users table")
            must_change = (
                "must_change_password"
                if "must_change_password" in columns
                else "0 AS must_change_password"
            )
            temporary_demo = (
                "temporary_demo"
                if "temporary_demo" in columns
                else "0 AS temporary_demo"
            )
            credential_policy_version = (
                "credential_policy_version"
                if "credential_policy_version" in columns
                else "0 AS credential_policy_version"
            )
            rows = connection.execute(
                "SELECT username,role,active,password_salt,password_hash,"
                f"{must_change},{temporary_demo},{credential_policy_version} "
                "FROM users ORDER BY username"
            ).fetchall()
    except sqlite3.Error as error:
        raise AuthError("authentication database could not be inspected") from error
    return _credential_status_from_rows(
        rows, forbidden_passwords=forbidden_passwords
    )


def authorize(
    principal: Principal,
    permission: Permission | str,
    mine_id: str | None = None,
) -> None:
    """Raise a stable exception unless ``principal`` may perform the action."""

    if not principal.active:
        raise PermissionDeniedError("inactive user")
    try:
        requested = (
            permission
            if isinstance(permission, Permission)
            else Permission(permission)
        )
    except ValueError as error:
        raise UnknownPermissionError(f"unknown permission: {permission}") from error

    if requested not in _ROLE_PERMISSIONS[principal.role]:
        raise PermissionDeniedError(
            f"role {principal.role.value} lacks {requested.value}"
        )

    if principal.role is Role.ADMIN:
        return
    if mine_id is None or not mine_id.strip():
        raise PermissionDeniedError("a mine scope is required")
    if mine_id not in principal.mine_scopes:
        raise PermissionDeniedError("mine is outside the user's scope")


def session_cookie_header(
    session_token: str,
    *,
    max_age_seconds: int,
    secure: bool = True,
    cookie_name: str = "mineguard_session",
) -> str:
    """Build the hardened session ``Set-Cookie`` value."""

    if max_age_seconds < 0:
        raise ValueError("max_age_seconds must be non-negative")
    parts = [
        f"{cookie_name}={quote(session_token, safe='-_~.')}",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        f"Max-Age={int(max_age_seconds)}",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def clear_session_cookie_header(
    *,
    secure: bool = True,
    cookie_name: str = "mineguard_session",
) -> str:
    return session_cookie_header(
        "",
        max_age_seconds=0,
        secure=secure,
        cookie_name=cookie_name,
    )


class LocalAuthStore:
    """SQLite-backed local authentication store.

    Connections are never shared between operations or threads.  File-backed
    stores use WAL and ``BEGIN IMMEDIATE`` for writes.  ``:memory:`` uses a
    shared-cache URI with a private anchor connection.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        absolute_timeout_seconds: int = 8 * 60 * 60,
        idle_timeout_seconds: int = 30 * 60,
        max_login_failures: int = 5,
        login_window_seconds: int = 5 * 60,
        lockout_seconds: int = 5 * 60,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        for name, value in {
            "absolute_timeout_seconds": absolute_timeout_seconds,
            "idle_timeout_seconds": idle_timeout_seconds,
            "max_login_failures": max_login_failures,
            "login_window_seconds": login_window_seconds,
            "lockout_seconds": lockout_seconds,
        }.items():
            if value <= 0:
                raise ValueError(f"{name} must be positive")

        self.absolute_timeout_seconds = int(absolute_timeout_seconds)
        self.idle_timeout_seconds = int(idle_timeout_seconds)
        self.max_login_failures = int(max_login_failures)
        self.login_window_seconds = int(login_window_seconds)
        self.lockout_seconds = int(lockout_seconds)
        self._clock = clock
        self._rate_lock = threading.Lock()
        self._failures: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._locked_until: dict[tuple[str, str], float] = {}
        self._dummy_salt = secrets.token_bytes(16)
        self._dummy_hash = _password_digest(
            secrets.token_urlsafe(24),
            self._dummy_salt,
        )
        self._anchor: sqlite3.Connection | None = None

        database_text = str(database)
        if database_text == ":memory:":
            self.database = (
                f"file:mineguard-auth-{uuid4().hex}?mode=memory&cache=shared"
            )
            self._uri = True
            self._anchor = self._new_connection()
        else:
            database_path = Path(database_text)
            database_path.parent.mkdir(
                parents=True,
                exist_ok=True,
                mode=0o700,
            )
            self.database = str(database_path)
            self._uri = False
        self._initialise()
        if not self._uri:
            try:
                Path(self.database).chmod(0o600)
            except OSError:
                pass

    def close(self) -> None:
        if self._anchor is not None:
            self._anchor.close()
            self._anchor = None

    def __enter__(self) -> "LocalAuthStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _new_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database,
            uri=self._uri,
            timeout=5.0,
            check_same_thread=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = self._new_connection()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._new_connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialise(self) -> None:
        with self._read() as connection:
            if not self._uri:
                connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    username_key TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL CHECK (
                        role IN ('admin','supervisor','reviewer','viewer')
                    ),
                    mine_scopes_json TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK (active IN (0,1)),
                    password_salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (
                        must_change_password IN (0,1)
                    ),
                    temporary_demo INTEGER NOT NULL DEFAULT 0 CHECK (
                        temporary_demo IN (0,1)
                    ),
                    credential_policy_version INTEGER NOT NULL DEFAULT 0 CHECK (
                        credential_policy_version IN (0,1)
                    ),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id),
                    token_sha256 TEXT NOT NULL UNIQUE,
                    csrf_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    absolute_expires_at TEXT NOT NULL,
                    idle_expires_at TEXT NOT NULL,
                    revoked_at TEXT
                );

                CREATE INDEX IF NOT EXISTS sessions_user_idx
                    ON sessions(user_id, revoked_at);

                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    user_id TEXT,
                    username TEXT,
                    client_id TEXT,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            # Databases created by releases before credential-purpose tracking
            # are upgraded in place.  SQLite cannot add a table CHECK during a
            # compatible ALTER, so every read also validates these flags.
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(users)")
            }
            if "must_change_password" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN "
                    "must_change_password INTEGER NOT NULL DEFAULT 0"
                )
            if "temporary_demo" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN "
                    "temporary_demo INTEGER NOT NULL DEFAULT 0"
                )
            if "credential_policy_version" not in columns:
                # Existing hashes cannot prove which historical password
                # policy accepted them.  They deliberately remain at zero
                # until the owner verifies the old password and rotates it.
                connection.execute(
                    "ALTER TABLE users ADD COLUMN "
                    "credential_policy_version INTEGER NOT NULL DEFAULT 0"
                )
            connection.commit()

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        return User(
            user_id=row["user_id"],
            username=row["username"],
            role=Role(row["role"]),
            mine_scopes=tuple(json.loads(row["mine_scopes_json"])),
            active=bool(row["active"]),
            created_at=_parse_datetime(row["created_at"]),
            updated_at=_parse_datetime(row["updated_at"]),
            must_change_password=bool(row["must_change_password"]),
            temporary_demo=bool(row["temporary_demo"]),
            credential_policy_version=_validated_credential_policy_version(
                row["credential_policy_version"]
            ),
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        action: str,
        now: datetime,
        *,
        user_id: str | None = None,
        username: str | None = None,
        client_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_events(
                action,user_id,username,client_id,detail_json,created_at
            ) VALUES (?,?,?,?,?,?)
            """,
            (
                action,
                user_id,
                username,
                client_id,
                json.dumps(
                    detail or {},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                _format_datetime(now),
            ),
        )

    def bootstrap_admin(
        self,
        username: str,
        password: str,
        *,
        must_change_password: bool = False,
        temporary_demo: bool = False,
    ) -> User:
        display, username_key = _normalise_username(username)
        must_change_password, temporary_demo = _credential_flags(
            password,
            must_change_password=must_change_password,
            temporary_demo=temporary_demo,
        )
        credential_policy_version = _credential_policy_version_for_password(
            password
        )
        now = self._now()
        with self._write() as connection:
            rows = connection.execute("SELECT * FROM users").fetchall()
            bootstrap = connection.execute(
                """
                SELECT value FROM auth_metadata
                WHERE key = 'bootstrap_admin_user_id'
                """
            ).fetchone()
            if bootstrap is not None:
                matching = connection.execute(
                    "SELECT * FROM users WHERE user_id = ?",
                    (bootstrap["value"],),
                ).fetchone()
                if (
                    matching is None
                    or matching["username_key"] != username_key
                ):
                    raise BootstrapConflictError(
                        "bootstrap admin does not match the existing bootstrap"
                    )
                candidate = _password_digest(password, matching["password_salt"])
                credentials_match = hmac.compare_digest(
                    candidate,
                    matching["password_hash"],
                )
                if (
                    not credentials_match
                    or matching["role"] != Role.ADMIN.value
                    or not bool(matching["active"])
                ):
                    raise BootstrapConflictError(
                        "bootstrap username already exists with different credentials"
                    )
                return self._row_to_user(matching)
            if rows:
                raise BootstrapConflictError(
                    "bootstrap is only allowed for an empty user store"
                )

            salt = secrets.token_bytes(16)
            password_hash = _password_digest(password, salt)
            user_id = f"usr_{secrets.token_urlsafe(16)}"
            timestamp = _format_datetime(now)
            connection.execute(
                """
                INSERT INTO users(
                    user_id,username,username_key,role,mine_scopes_json,active,
                    password_salt,password_hash,must_change_password,
                    temporary_demo,credential_policy_version,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    user_id,
                    display,
                    username_key,
                    Role.ADMIN.value,
                    "[]",
                    1,
                    salt,
                    password_hash,
                    int(must_change_password),
                    int(temporary_demo),
                    credential_policy_version,
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO auth_metadata(key,value)
                VALUES ('bootstrap_admin_user_id',?)
                """,
                (user_id,),
            )
            self._audit(
                connection,
                "bootstrap_admin",
                now,
                user_id=user_id,
                username=display,
            )
            row = connection.execute(
                "SELECT * FROM users WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            assert row is not None
            return self._row_to_user(row)

    def create_user(
        self,
        username: str,
        password: str,
        role: Role | str,
        mine_scopes: Iterable[str] = (),
        *,
        active: bool = True,
        must_change_password: bool = False,
        temporary_demo: bool = False,
    ) -> User:
        display, username_key = _normalise_username(username)
        must_change_password, temporary_demo = _credential_flags(
            password,
            must_change_password=must_change_password,
            temporary_demo=temporary_demo,
        )
        credential_policy_version = _credential_policy_version_for_password(
            password
        )
        selected_role = role if isinstance(role, Role) else Role(role)
        scopes = _normalise_scopes(mine_scopes, role=selected_role)
        now = self._now()
        salt = secrets.token_bytes(16)
        password_hash = _password_digest(password, salt)
        user_id = f"usr_{secrets.token_urlsafe(16)}"
        timestamp = _format_datetime(now)
        try:
            with self._write() as connection:
                connection.execute(
                    """
                    INSERT INTO users(
                        user_id,username,username_key,role,mine_scopes_json,
                        active,password_salt,password_hash,must_change_password,
                        temporary_demo,credential_policy_version,created_at,updated_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        user_id,
                        display,
                        username_key,
                        selected_role.value,
                        json.dumps(scopes, ensure_ascii=False),
                        int(active),
                        salt,
                        password_hash,
                        int(must_change_password),
                        int(temporary_demo),
                        credential_policy_version,
                        timestamp,
                        timestamp,
                    ),
                )
                self._audit(
                    connection,
                    "user_created",
                    now,
                    user_id=user_id,
                    username=display,
                    detail={
                        "role": selected_role.value,
                        "mine_scopes": list(scopes),
                        "active": active,
                        "must_change_password": must_change_password,
                        "temporary_demo": temporary_demo,
                        "credential_policy_version": credential_policy_version,
                    },
                )
                row = connection.execute(
                    "SELECT * FROM users WHERE user_id = ?",
                    (user_id,),
                ).fetchone()
                assert row is not None
                return self._row_to_user(row)
        except sqlite3.IntegrityError as error:
            raise UserConflictError("username already exists") from error

    def get_user(self, username: str) -> User | None:
        _, username_key = _normalise_username(username)
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()
        return None if row is None else self._row_to_user(row)

    def list_users(self) -> list[dict[str, Any]]:
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM users ORDER BY username_key"
            ).fetchall()
        return [self._row_to_user(row).to_audit_dict() for row in rows]

    def production_credential_status(
        self,
        *,
        forbidden_passwords: Iterable[str] = _COMMON_WEAK_PASSWORDS,
    ) -> dict[str, Any]:
        """Return a secret-free, fail-closed production credential audit.

        Flags cover credentials deliberately issued for demonstrations or
        pending replacement.  Digest comparison also catches legacy databases
        that predate those flags and therefore cannot truthfully identify the
        original credential purpose.
        """

        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM users ORDER BY username_key"
            ).fetchall()
        return _credential_status_from_rows(
            rows, forbidden_passwords=forbidden_passwords
        )

    @staticmethod
    def _ensure_active_admin_remains(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        next_active: bool,
        next_role: Role,
    ) -> None:
        removes_active_admin = (
            bool(row["active"])
            and row["role"] == Role.ADMIN.value
            and (not next_active or next_role is not Role.ADMIN)
        )
        if not removes_active_admin:
            return
        replacement = connection.execute(
            """
            SELECT 1 FROM users
            WHERE active = 1 AND role = ? AND user_id <> ?
            LIMIT 1
            """,
            (Role.ADMIN.value, row["user_id"]),
        ).fetchone()
        if replacement is None:
            raise LastActiveAdminError(
                "at least one active administrator is required"
            )

    def set_user_active(self, username: str, active: bool) -> User:
        _, username_key = _normalise_username(username)
        now = self._now()
        timestamp = _format_datetime(now)
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()
            if row is None:
                raise UserNotFoundError(username)
            self._ensure_active_admin_remains(
                connection,
                row,
                next_active=active,
                next_role=Role(row["role"]),
            )
            connection.execute(
                "UPDATE users SET active = ?, updated_at = ? WHERE user_id = ?",
                (int(active), timestamp, row["user_id"]),
            )
            if not active:
                connection.execute(
                    """
                    UPDATE sessions SET revoked_at = ?
                    WHERE user_id = ? AND revoked_at IS NULL
                    """,
                    (timestamp, row["user_id"]),
                )
            self._audit(
                connection,
                "user_enabled" if active else "user_disabled",
                now,
                user_id=row["user_id"],
                username=row["username"],
            )
            updated = connection.execute(
                "SELECT * FROM users WHERE user_id = ?",
                (row["user_id"],),
            ).fetchone()
            assert updated is not None
            return self._row_to_user(updated)

    def update_user_access(
        self,
        username: str,
        role: Role | str,
        mine_scopes: Iterable[str] = (),
    ) -> User:
        """Replace a user's role and mine scopes, revoking active sessions."""

        _, username_key = _normalise_username(username)
        selected_role = role if isinstance(role, Role) else Role(role)
        scopes = _normalise_scopes(mine_scopes, role=selected_role)
        now = self._now()
        timestamp = _format_datetime(now)
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()
            if row is None:
                raise UserNotFoundError(username)
            self._ensure_active_admin_remains(
                connection,
                row,
                next_active=bool(row["active"]),
                next_role=selected_role,
            )
            previous_scopes = tuple(json.loads(row["mine_scopes_json"]))
            connection.execute(
                """
                UPDATE users
                SET role = ?, mine_scopes_json = ?, updated_at = ?
                WHERE user_id = ?
                """,
                (
                    selected_role.value,
                    json.dumps(scopes, ensure_ascii=False),
                    timestamp,
                    row["user_id"],
                ),
            )
            revoked = connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (timestamp, row["user_id"]),
            )
            self._audit(
                connection,
                "user_access_changed",
                now,
                user_id=row["user_id"],
                username=row["username"],
                detail={
                    "previous_role": row["role"],
                    "role": selected_role.value,
                    "previous_mine_scopes": list(previous_scopes),
                    "mine_scopes": list(scopes),
                    "sessions_revoked": int(revoked.rowcount),
                },
            )
            updated = connection.execute(
                "SELECT * FROM users WHERE user_id = ?",
                (row["user_id"],),
            ).fetchone()
            assert updated is not None
            return self._row_to_user(updated)

    def change_password(
        self,
        username: str,
        current_password: str,
        new_password: str,
    ) -> None:
        """Change a user's own password and revoke every active session."""

        _, username_key = _normalise_username(username)
        if not isinstance(new_password, str) or not new_password:
            raise ValueError("new password is required")
        validate_strong_password(new_password)
        must_change_password, temporary_demo = _credential_flags(
            new_password,
            must_change_password=False,
            temporary_demo=False,
        )
        credential_policy_version = _credential_policy_version_for_password(
            new_password
        )
        now = self._now()
        timestamp = _format_datetime(now)
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()
            if row is None or not bool(row["active"]):
                raise InvalidCredentialsError("invalid username or password")
            candidate = _password_digest(
                current_password,
                row["password_salt"],
            )
            if not hmac.compare_digest(candidate, row["password_hash"]):
                raise InvalidCredentialsError("invalid username or password")
            salt = secrets.token_bytes(16)
            password_hash = _password_digest(new_password, salt)
            connection.execute(
                "UPDATE users SET password_salt = ?, password_hash = ?, "
                "must_change_password = ?, temporary_demo = ?, "
                "credential_policy_version = ?, updated_at = ? WHERE user_id = ?",
                (
                    salt,
                    password_hash,
                    int(must_change_password),
                    int(temporary_demo),
                    credential_policy_version,
                    timestamp,
                    row["user_id"],
                ),
            )
            connection.execute(
                "UPDATE sessions SET revoked_at = ? "
                "WHERE user_id = ? AND revoked_at IS NULL",
                (timestamp, row["user_id"]),
            )
            self._audit(
                connection,
                "password_changed",
                now,
                user_id=row["user_id"],
                username=row["username"],
            )

    def reset_password(
        self,
        username: str,
        new_password: str,
        *,
        must_change_password: bool = True,
        temporary_demo: bool = False,
        strict: bool = False,
    ) -> None:
        """Set a new password administratively and revoke active sessions."""

        _, username_key = _normalise_username(username)
        if not isinstance(new_password, str) or not new_password:
            raise ValueError("new password is required")
        if strict:
            validate_strong_password(new_password)
        must_change_password, temporary_demo = _credential_flags(
            new_password,
            must_change_password=must_change_password,
            temporary_demo=temporary_demo,
        )
        credential_policy_version = _credential_policy_version_for_password(
            new_password
        )
        now = self._now()
        timestamp = _format_datetime(now)
        salt = secrets.token_bytes(16)
        password_hash = _password_digest(new_password, salt)
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()
            if row is None:
                raise UserNotFoundError(username)
            connection.execute(
                "UPDATE users SET password_salt = ?, password_hash = ?, "
                "must_change_password = ?, temporary_demo = ?, "
                "credential_policy_version = ?, updated_at = ? WHERE user_id = ?",
                (
                    salt,
                    password_hash,
                    int(must_change_password),
                    int(temporary_demo),
                    credential_policy_version,
                    timestamp,
                    row["user_id"],
                ),
            )
            connection.execute(
                "UPDATE sessions SET revoked_at = ? "
                "WHERE user_id = ? AND revoked_at IS NULL",
                (timestamp, row["user_id"]),
            )
            self._audit(
                connection,
                "password_reset",
                now,
                user_id=row["user_id"],
                username=row["username"],
            )

    def _rate_key(self, username_key: str, client_id: str) -> tuple[str, str]:
        client = client_id.strip()
        if not client:
            raise ValueError("client_id is required")
        return username_key, client

    def _check_rate_limit(
        self,
        key: tuple[str, str],
        now_seconds: float,
    ) -> None:
        with self._rate_lock:
            locked_until = self._locked_until.get(key)
            if locked_until is not None:
                if locked_until > now_seconds:
                    raise LoginRateLimitedError(
                        int(locked_until - now_seconds + 0.999)
                    )
                self._locked_until.pop(key, None)
                self._failures.pop(key, None)

            failures = self._failures[key]
            cutoff = now_seconds - self.login_window_seconds
            while failures and failures[0] <= cutoff:
                failures.popleft()

    def _record_failure(
        self,
        key: tuple[str, str],
        now_seconds: float,
    ) -> None:
        with self._rate_lock:
            failures = self._failures[key]
            cutoff = now_seconds - self.login_window_seconds
            while failures and failures[0] <= cutoff:
                failures.popleft()
            failures.append(now_seconds)
            if len(failures) >= self.max_login_failures:
                self._locked_until[key] = now_seconds + self.lockout_seconds

    def _clear_failures(self, key: tuple[str, str]) -> None:
        with self._rate_lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def login(
        self,
        username: str,
        password: str,
        *,
        client_id: str,
    ) -> LoginResult:
        display, username_key = _normalise_username(username)
        now = self._now()
        now_seconds = now.timestamp()
        key = self._rate_key(username_key, client_id)
        self._check_rate_limit(key, now_seconds)

        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()

        if row is None:
            candidate = _password_digest(password, self._dummy_salt)
            hmac.compare_digest(candidate, self._dummy_hash)
            valid = False
        else:
            candidate = _password_digest(password, row["password_salt"])
            valid = hmac.compare_digest(candidate, row["password_hash"])
            valid = valid and bool(row["active"])

        if not valid:
            self._record_failure(key, now_seconds)
            with self._write() as connection:
                self._audit(
                    connection,
                    "login_failed",
                    now,
                    username=display,
                    client_id=client_id,
                )
            raise InvalidCredentialsError("invalid username or password")

        self._clear_failures(key)
        assert row is not None
        absolute_expires = now + timedelta(
            seconds=self.absolute_timeout_seconds
        )
        idle_expires = min(
            absolute_expires,
            now + timedelta(seconds=self.idle_timeout_seconds),
        )
        session_id = f"ses_{secrets.token_urlsafe(16)}"
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        timestamp = _format_datetime(now)
        with self._write() as connection:
            # Re-check active state inside the write transaction so disabling a
            # user cannot race a successful login.
            active_row = connection.execute(
                "SELECT active FROM users WHERE user_id = ?",
                (row["user_id"],),
            ).fetchone()
            if active_row is None or not bool(active_row["active"]):
                raise InvalidCredentialsError("invalid username or password")
            connection.execute(
                """
                INSERT INTO sessions(
                    session_id,user_id,token_sha256,csrf_sha256,created_at,
                    last_seen_at,absolute_expires_at,idle_expires_at,revoked_at
                ) VALUES (?,?,?,?,?,?,?,?,NULL)
                """,
                (
                    session_id,
                    row["user_id"],
                    _token_digest(session_token),
                    _token_digest(csrf_token),
                    timestamp,
                    timestamp,
                    _format_datetime(absolute_expires),
                    _format_datetime(idle_expires),
                ),
            )
            self._audit(
                connection,
                "login_succeeded",
                now,
                user_id=row["user_id"],
                username=row["username"],
                client_id=client_id,
                detail={"session_id": session_id},
            )

        principal = Principal(
            user_id=row["user_id"],
            username=row["username"],
            role=Role(row["role"]),
            mine_scopes=tuple(json.loads(row["mine_scopes_json"])),
            session_id=session_id,
            must_change_password=bool(row["must_change_password"]),
            temporary_demo=bool(row["temporary_demo"]),
            credential_policy_version=_validated_credential_policy_version(
                row["credential_policy_version"]
            ),
        )
        return LoginResult(
            session_token=session_token,
            csrf_token=csrf_token,
            principal=principal,
            absolute_expires_at=absolute_expires,
            idle_expires_at=idle_expires,
        )

    def _authenticate_in_transaction(
        self,
        connection: sqlite3.Connection,
        session_token: str,
        *,
        touch: bool,
    ) -> tuple[Principal, sqlite3.Row]:
        token_sha256 = _token_digest(session_token)
        row = connection.execute(
            """
            SELECT
                s.*, u.username, u.role, u.mine_scopes_json, u.active,
                u.must_change_password, u.temporary_demo,
                u.credential_policy_version
            FROM sessions s
            JOIN users u ON u.user_id = s.user_id
            WHERE s.token_sha256 = ?
            """,
            (token_sha256,),
        ).fetchone()
        if row is None or row["revoked_at"] is not None:
            raise InvalidSessionError("invalid or revoked session")
        if not bool(row["active"]):
            raise InvalidSessionError("user is inactive")

        now = self._now()
        absolute_expires = _parse_datetime(row["absolute_expires_at"])
        idle_expires = _parse_datetime(row["idle_expires_at"])
        if now >= absolute_expires or now >= idle_expires:
            connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE session_id = ? AND revoked_at IS NULL
                """,
                (_format_datetime(now), row["session_id"]),
            )
            raise SessionExpiredError("session expired")

        if touch:
            next_idle = min(
                absolute_expires,
                now + timedelta(seconds=self.idle_timeout_seconds),
            )
            connection.execute(
                """
                UPDATE sessions
                SET last_seen_at = ?, idle_expires_at = ?
                WHERE session_id = ?
                """,
                (
                    _format_datetime(now),
                    _format_datetime(next_idle),
                    row["session_id"],
                ),
            )

        principal = Principal(
            user_id=row["user_id"],
            username=row["username"],
            role=Role(row["role"]),
            mine_scopes=tuple(json.loads(row["mine_scopes_json"])),
            session_id=row["session_id"],
            must_change_password=bool(row["must_change_password"]),
            temporary_demo=bool(row["temporary_demo"]),
            credential_policy_version=_validated_credential_policy_version(
                row["credential_policy_version"]
            ),
        )
        return principal, row

    def authenticate(
        self,
        session_token: str,
        *,
        touch: bool = True,
    ) -> Principal:
        if not session_token:
            raise InvalidSessionError("session token is required")
        with self._write() as connection:
            principal, _ = self._authenticate_in_transaction(
                connection,
                session_token,
                touch=touch,
            )
            return principal

    def touch_session(self, session_token: str) -> Principal:
        return self.authenticate(session_token, touch=True)

    def issue_csrf(self, session_token: str) -> tuple[Principal, str]:
        """Rotate and return a CSRF token after same-origin session recovery."""

        csrf_token = secrets.token_urlsafe(32)
        with self._write() as connection:
            principal, row = self._authenticate_in_transaction(
                connection,
                session_token,
                touch=True,
            )
            connection.execute(
                "UPDATE sessions SET csrf_sha256 = ? WHERE session_id = ?",
                (_token_digest(csrf_token), row["session_id"]),
            )
            self._audit(
                connection,
                "csrf_rotated",
                self._now(),
                user_id=principal.user_id,
                username=principal.username,
                detail={"session_id": principal.session_id},
            )
        return principal, csrf_token

    def validate_csrf(
        self,
        session_token: str,
        header_token: str | None,
        *,
        method: str,
    ) -> Principal:
        if method.upper() in _SAFE_METHODS:
            return self.authenticate(session_token)
        if not header_token:
            raise CsrfValidationError("CSRF header is required")
        with self._write() as connection:
            principal, row = self._authenticate_in_transaction(
                connection,
                session_token,
                touch=True,
            )
            candidate = _token_digest(header_token)
            if not hmac.compare_digest(row["csrf_sha256"], candidate):
                raise CsrfValidationError("invalid CSRF token")
            return principal

    def logout(self, session_token: str) -> None:
        token_sha256 = _token_digest(session_token)
        now = self._now()
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT s.session_id,s.user_id,u.username
                FROM sessions s JOIN users u ON u.user_id=s.user_id
                WHERE s.token_sha256 = ?
                """,
                (token_sha256,),
            ).fetchone()
            if row is None:
                return
            connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE session_id = ? AND revoked_at IS NULL
                """,
                (_format_datetime(now), row["session_id"]),
            )
            self._audit(
                connection,
                "logout",
                now,
                user_id=row["user_id"],
                username=row["username"],
                detail={"session_id": row["session_id"]},
            )

    def revoke_all(self, username: str) -> int:
        _, username_key = _normalise_username(username)
        now = self._now()
        with self._write() as connection:
            row = connection.execute(
                "SELECT user_id,username FROM users WHERE username_key = ?",
                (username_key,),
            ).fetchone()
            if row is None:
                raise UserNotFoundError(username)
            cursor = connection.execute(
                """
                UPDATE sessions SET revoked_at = ?
                WHERE user_id = ? AND revoked_at IS NULL
                """,
                (_format_datetime(now), row["user_id"]),
            )
            self._audit(
                connection,
                "sessions_revoked",
                now,
                user_id=row["user_id"],
                username=row["username"],
                detail={"count": cursor.rowcount},
            )
            return int(cursor.rowcount)

    def list_sessions(self, username: str) -> list[dict[str, Any]]:
        _, username_key = _normalise_username(username)
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT
                    s.session_id,s.user_id,s.created_at,s.last_seen_at,
                    s.absolute_expires_at,s.idle_expires_at,s.revoked_at
                FROM sessions s JOIN users u ON u.user_id=s.user_id
                WHERE u.username_key = ?
                ORDER BY s.created_at DESC
                """,
                (username_key,),
            ).fetchall()
        sessions = [
            Session(
                session_id=row["session_id"],
                user_id=row["user_id"],
                created_at=_parse_datetime(row["created_at"]),
                last_seen_at=_parse_datetime(row["last_seen_at"]),
                absolute_expires_at=_parse_datetime(
                    row["absolute_expires_at"]
                ),
                idle_expires_at=_parse_datetime(row["idle_expires_at"]),
                revoked_at=(
                    None
                    if row["revoked_at"] is None
                    else _parse_datetime(row["revoked_at"])
                ),
            )
            for row in rows
        ]
        return [session.to_audit_dict() for session in sessions]

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT seq,action,user_id,username,client_id,detail_json,created_at
                FROM audit_events ORDER BY seq DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "seq": row["seq"],
                "action": row["action"],
                "user_id": row["user_id"],
                "username": row["username"],
                "client_id": row["client_id"],
                "detail": json.loads(row["detail_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def record_audit_event(
        self,
        action: str,
        *,
        principal: Principal | None = None,
        client_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Append a non-authentication domain event to the shared audit log."""

        normalized_action = action.strip()
        if not normalized_action or len(normalized_action) > 200:
            raise ValueError("audit action must be non-empty text")
        # Validate serializability and reject NaN before opening a write
        # transaction.  Callers must not place credentials or raw secrets here.
        json.dumps(
            detail or {},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        with self._write() as connection:
            self._audit(
                connection,
                normalized_action,
                self._now(),
                user_id=principal.user_id if principal else None,
                username=principal.username if principal else None,
                client_id=client_id,
                detail=detail,
            )


# A shorter name for callers that treat this as their auth service.
LocalAuth = LocalAuthStore
AuthRepository = LocalAuthStore


__all__ = [
    "AuthError",
    "AuthRepository",
    "BootstrapConflictError",
    "CsrfValidationError",
    "CURRENT_CREDENTIAL_POLICY_VERSION",
    "InvalidCredentialsError",
    "InvalidSessionError",
    "LastActiveAdminError",
    "LocalAuth",
    "LocalAuthStore",
    "LoginRateLimitedError",
    "LoginResult",
    "Permission",
    "PermissionDeniedError",
    "Principal",
    "Role",
    "Session",
    "SessionExpiredError",
    "UnknownPermissionError",
    "User",
    "UserConflictError",
    "UserNotFoundError",
    "authorize",
    "clear_session_cookie_header",
    "inspect_auth_database",
    "session_cookie_header",
    "validate_strong_password",
]
