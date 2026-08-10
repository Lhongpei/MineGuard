"""Enterprise-side accounts, principals and server-side browser sessions.

The regulatory platform never participates in this authentication boundary.
Accounts are supplied by the enterprise deployment and an authenticated
``Principal`` is the only identity accepted by the HTTP layer.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

PASSWORD_SCHEME = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 600_000
SESSION_COOKIE_NAME = "enterprise_agent_session"
PRODUCTION_CREDENTIAL_PROVENANCES = frozenset(
    {
        "production_hash_command",
        "secret_manager_generated",
        "verified_migration",
    }
)
_KNOWN_INSECURE_PASSWORDS = (
    "123123123",
    "12345678",
    "password",
    "admin123",
)
KNOWN_PERMISSIONS = frozenset(
    {
        "read",
        "write",
        "confirm",
        "submit",
        "governance_review",
        "skill_admin",
    }
)
ALL_PERMISSIONS = KNOWN_PERMISSIONS
_ACTOR_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_MAX_SESSIONS = 2_000
_LOGIN_WINDOW_SECONDS = 60
_MAX_LOGIN_FAILURES = 8
_MAX_REMOTE_LOGIN_FAILURES = 1_000
_MAX_FAILURE_BUCKETS = 10_000


class AuthenticationFailed(RuntimeError):
    """A deliberately generic login/authentication failure."""


class LoginThrottled(RuntimeError):
    """Too many failed login attempts from one remote endpoint."""


@dataclass(frozen=True)
class Principal:
    actor_id: str
    name: str
    role: str
    permissions: frozenset[str]
    authentication_method: str
    must_change_password: bool = False
    temporary_demo: bool = False

    def allows(self, permission: str) -> bool:
        return permission in self.permissions

    def public_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "role": self.role,
            "permissions": sorted(self.permissions),
            "authentication_method": self.authentication_method,
            "must_change_password": self.must_change_password,
            "temporary_demo": self.temporary_demo,
        }


@dataclass(frozen=True)
class UserAccount:
    actor_id: str
    name: str
    role: str
    password_hash: str
    permissions: frozenset[str]
    must_change_password: bool = False
    temporary_demo: bool = False
    # Password hashes cannot prove how the original password was selected.
    # Production therefore requires an explicit, auditable provenance claim.
    # ``unspecified`` preserves compatibility with existing development JSON,
    # while the production config gate rejects it.
    credential_provenance: str = "unspecified"

    def principal(self) -> Principal:
        return Principal(
            actor_id=self.actor_id,
            name=self.name,
            role=self.role,
            permissions=self.permissions,
            authentication_method="password_session",
            must_change_password=self.must_change_password,
            temporary_demo=self.temporary_demo,
        )


@dataclass(frozen=True)
class AuthContext:
    principal: Principal
    csrf_token: str
    session_token: str | None
    expires_at: int | None

    @property
    def is_session(self) -> bool:
        return self.session_token is not None


@dataclass(frozen=True)
class LoginResult:
    context: AuthContext
    max_age: int


@dataclass
class _StoredSession:
    principal: Principal
    csrf_token: str
    expires_at: float


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.b64decode(
        value + padding,
        altchars=b"-_",
        validate=True,
    )


def hash_password(
    password: str,
    *,
    iterations: int = PASSWORD_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Hash a password for ``ENTERPRISE_AGENT_USERS_JSON``.

    PBKDF2 is used because it is available in the Python standard library.
    The encoded value is self-describing so the work factor can be raised for
    newly generated hashes without invalidating existing accounts.
    """

    if not isinstance(password, str) or not 8 <= len(password) <= 1_024:
        raise ValueError("密码长度必须为 8-1024 个字符")
    if "\x00" in password:
        raise ValueError("密码不能包含 NUL 字符")
    if not 100_000 <= iterations <= 10_000_000:
        raise ValueError("PBKDF2 迭代次数超出安全范围")
    selected_salt = salt if salt is not None else secrets.token_bytes(18)
    if len(selected_salt) < 16:
        raise ValueError("密码盐至少需要 16 字节")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        selected_salt,
        iterations,
    )
    return (
        f"{PASSWORD_SCHEME}${iterations}$"
        f"{_b64encode(selected_salt)}${_b64encode(digest)}"
    )


def verify_password(password: str, encoded: str) -> bool:
    """Verify a configured password hash without leaking parse failures."""

    try:
        scheme, raw_iterations, raw_salt, raw_digest = encoded.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        iterations = int(raw_iterations)
        if not 100_000 <= iterations <= 10_000_000:
            return False
        salt = _b64decode(raw_salt)
        expected = _b64decode(raw_digest)
        if len(salt) < 16 or len(expected) != hashlib.sha256().digest_size:
            return False
        if not isinstance(password, str) or len(password) > 1_024:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual, expected)
    except (binascii.Error, UnicodeError, ValueError):
        return False


def validate_production_password(password: str) -> None:
    """Reject passwords unsuitable for a newly provisioned formal account."""

    if isinstance(password, str) and password.casefold() in {
        value.casefold() for value in _KNOWN_INSECURE_PASSWORDS
    }:
        raise ValueError("正式账号密码不得使用演示或常见默认密码")
    if not isinstance(password, str) or not 12 <= len(password) <= 1_024:
        raise ValueError("正式账号密码长度必须为 12-1024 个字符")
    categories = sum(
        (
            any(character.islower() for character in password),
            any(character.isupper() for character in password),
            any(character.isdigit() for character in password),
            any(not character.isalnum() for character in password),
        )
    )
    if categories < 3:
        raise ValueError("正式账号密码至少应包含大小写字母、数字、符号中的三类")


def production_credential_errors(account: UserAccount) -> tuple[str, ...]:
    """Return account-local credential defects detectable from configuration."""

    errors: list[str] = []
    if account.must_change_password:
        errors.append("仍标记为必须换密")
    if account.temporary_demo:
        errors.append("仍标记为演示账号")
    if account.credential_provenance not in PRODUCTION_CREDENTIAL_PROVENANCES:
        errors.append(
            "未声明可信 credential_provenance（应使用 production_hash_command、"
            "secret_manager_generated 或 verified_migration）"
        )
    try:
        iterations = int(account.password_hash.split("$", 3)[1])
    except (IndexError, ValueError):
        iterations = 0
    if iterations < PASSWORD_ITERATIONS:
        errors.append(f"PBKDF2 迭代次数低于正式基线 {PASSWORD_ITERATIONS}")
    if any(
        verify_password(candidate, account.password_hash)
        for candidate in _KNOWN_INSECURE_PASSWORDS
    ):
        errors.append("使用了演示或已知常见默认密码")
    return tuple(errors)


def _text(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 128:
        raise ValueError(f"企业用户 {field} 必须是 1-128 字符的非空字符串")
    return value.strip()


def parse_users_json(raw: str | None) -> tuple[UserAccount, ...]:
    """Parse enterprise-owned accounts from an environment JSON value.

    A list is canonical. An object keyed by ``actor_id`` is also accepted for
    operators who prefer mapping-shaped secret-manager values.
    """

    if raw is None or not raw.strip():
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("ENTERPRISE_AGENT_USERS_JSON 必须是有效 JSON") from error
    records: list[Any]
    if isinstance(parsed, list):
        records = parsed
    elif isinstance(parsed, dict):
        records = []
        for actor_id, value in parsed.items():
            if not isinstance(value, dict):
                raise ValueError("ENTERPRISE_AGENT_USERS_JSON 用户记录必须是对象")
            records.append({"actor_id": actor_id, **value})
    else:
        raise ValueError("ENTERPRISE_AGENT_USERS_JSON 顶层必须是数组或对象")

    accounts: list[UserAccount] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("ENTERPRISE_AGENT_USERS_JSON 用户记录必须是对象")
        actor_id = _text(record, "actor_id")
        if _ACTOR_ID.fullmatch(actor_id) is None:
            raise ValueError(
                "企业用户 actor_id 仅允许字母、数字、点、下划线、冒号、@ 和连字符"
            )
        if actor_id in seen:
            raise ValueError(f"企业用户 actor_id 重复：{actor_id}")
        password_hash = record.get("password_hash")
        if not isinstance(password_hash, str) or not password_hash:
            raise ValueError(f"企业用户 {actor_id} 必须配置 password_hash")
        # Reject malformed/weak encoded values before the service starts.
        parts = password_hash.split("$", 3)
        if (
            len(parts) != 4
            or parts[0] != PASSWORD_SCHEME
            or not parts[1].isdigit()
            or not 100_000 <= int(parts[1]) <= 10_000_000
        ):
            raise ValueError(f"企业用户 {actor_id} 的 password_hash 格式不受支持")
        try:
            salt = _b64decode(parts[2])
            digest = _b64decode(parts[3])
        except (binascii.Error, ValueError) as error:
            raise ValueError(
                f"企业用户 {actor_id} 的 password_hash 格式不受支持"
            ) from error
        if len(salt) < 16 or len(digest) != hashlib.sha256().digest_size:
            raise ValueError(f"企业用户 {actor_id} 的 password_hash 格式不受支持")
        permissions = record.get("permissions")
        if (
            not isinstance(permissions, list)
            or not permissions
            or any(not isinstance(item, str) for item in permissions)
        ):
            raise ValueError(f"企业用户 {actor_id} 必须配置非空 permissions 数组")
        permission_set = frozenset(permissions)
        unknown = permission_set - KNOWN_PERMISSIONS
        if unknown:
            raise ValueError(
                f"企业用户 {actor_id} 含未知权限：{', '.join(sorted(unknown))}"
            )
        must_change = record.get("must_change_password", False)
        if not isinstance(must_change, bool):
            raise ValueError("must_change_password 必须是布尔值")
        credential_provenance = record.get(
            "credential_provenance",
            "unspecified",
        )
        if (
            not isinstance(credential_provenance, str)
            or credential_provenance
            not in PRODUCTION_CREDENTIAL_PROVENANCES | {"unspecified"}
        ):
            raise ValueError(
                "credential_provenance 必须是 unspecified、"
                "production_hash_command、secret_manager_generated 或 "
                "verified_migration"
            )
        accounts.append(
            UserAccount(
                actor_id=actor_id,
                name=_text(record, "name"),
                role=_text(record, "role"),
                password_hash=password_hash,
                permissions=permission_set,
                must_change_password=must_change,
                credential_provenance=credential_provenance,
            )
        )
        seen.add(actor_id)
    return tuple(accounts)


def is_loopback(value: str) -> bool:
    host = value.strip().strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def demo_account() -> UserAccount:
    """Return the conspicuously temporary loopback-only demonstration user."""

    return UserAccount(
        actor_id="demo",
        name="本机演示用户",
        role="企业填报演示管理员",
        password_hash=hash_password("123123123"),
        # Expose only effective capabilities to the browser.  The HTTP layer
        # still independently blocks confirm/submit for every
        # must_change_password principal, even if an administrator
        # accidentally grants those permissions to another temporary account.
        permissions=frozenset({"read", "write"}),
        must_change_password=True,
        temporary_demo=True,
        credential_provenance="unspecified",
    )


class AuthManager:
    """Thread-safe account authentication and in-memory session storage."""

    def __init__(
        self,
        accounts: tuple[UserAccount, ...] = (),
        *,
        allow_anonymous_local: bool = False,
        session_ttl_seconds: int = 8 * 60 * 60,
    ):
        if not 300 <= session_ttl_seconds <= 7 * 24 * 60 * 60:
            raise ValueError("会话有效期必须为 300-604800 秒")
        self._accounts = {account.actor_id: account for account in accounts}
        self.allow_anonymous_local = allow_anonymous_local
        self.session_ttl_seconds = session_ttl_seconds
        self._sessions: dict[str, _StoredSession] = {}
        self._login_failures: dict[tuple[str, str], list[float]] = {}
        self._remote_login_failures: dict[str, list[float]] = {}
        self._lock = threading.RLock()
        self._local_context = AuthContext(
            principal=Principal(
                actor_id="local-development",
                name="本机开发人员",
                role="本机开发模式",
                permissions=ALL_PERMISSIONS,
                authentication_method="loopback_development",
            ),
            csrf_token=secrets.token_urlsafe(32),
            session_token=None,
            expires_at=None,
        )

    @property
    def account_count(self) -> int:
        return len(self._accounts)

    @property
    def has_temporary_accounts(self) -> bool:
        return any(account.temporary_demo for account in self._accounts.values())

    @staticmethod
    def _session_key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _purge(self, now: float) -> None:
        for key, session in tuple(self._sessions.items()):
            if session.expires_at <= now:
                self._sessions.pop(key, None)
        if len(self._sessions) >= _MAX_SESSIONS:
            oldest = sorted(
                self._sessions.items(),
                key=lambda item: item[1].expires_at,
            )
            for key, _ in oldest[: len(self._sessions) - _MAX_SESSIONS + 1]:
                self._sessions.pop(key, None)

    @staticmethod
    def _actor_bucket(actor_id: str) -> str:
        return hashlib.sha256(actor_id.encode("utf-8")).hexdigest()

    def _purge_login_failures(self, now: float) -> None:
        cutoff = now - _LOGIN_WINDOW_SECONDS
        for key, attempts in tuple(self._login_failures.items()):
            active = [value for value in attempts if value > cutoff]
            if active:
                self._login_failures[key] = active
            else:
                self._login_failures.pop(key, None)
        for key, attempts in tuple(self._remote_login_failures.items()):
            active = [value for value in attempts if value > cutoff]
            if active:
                self._remote_login_failures[key] = active
            else:
                self._remote_login_failures.pop(key, None)
        if len(self._login_failures) > _MAX_FAILURE_BUCKETS:
            oldest = sorted(
                self._login_failures,
                key=lambda key: max(self._login_failures[key]),
            )
            for key in oldest[: len(self._login_failures) - _MAX_FAILURE_BUCKETS]:
                self._login_failures.pop(key, None)

    def _record_failure(
        self,
        remote_address: str,
        actor_bucket: str,
        now: float,
    ) -> None:
        key = (remote_address, actor_bucket)
        attempts = [
            value
            for value in self._login_failures.get(key, [])
            if value > now - _LOGIN_WINDOW_SECONDS
        ]
        attempts.append(now)
        self._login_failures[key] = attempts
        remote_attempts = [
            value
            for value in self._remote_login_failures.get(remote_address, [])
            if value > now - _LOGIN_WINDOW_SECONDS
        ]
        remote_attempts.append(now)
        self._remote_login_failures[remote_address] = remote_attempts

    def _check_throttle(
        self,
        remote_address: str,
        actor_bucket: str,
        now: float,
    ) -> None:
        self._purge_login_failures(now)
        if len(self._remote_login_failures.get(remote_address, [])) >= (
            _MAX_REMOTE_LOGIN_FAILURES
        ):
            raise LoginThrottled("登录失败次数过多，请稍后重试")
        if len(self._login_failures.get((remote_address, actor_bucket), [])) >= (
            _MAX_LOGIN_FAILURES
        ):
            raise LoginThrottled("登录失败次数过多，请稍后重试")

    def login(
        self,
        actor_id: str,
        password: str,
        *,
        remote_address: str,
    ) -> LoginResult:
        now = time.time()
        actor = actor_id.strip() if isinstance(actor_id, str) else ""
        secret = password if isinstance(password, str) else ""
        actor_bucket = self._actor_bucket(actor)
        with self._lock:
            self._check_throttle(remote_address, actor_bucket, now)
            account = self._accounts.get(actor)
            if account is None:
                # Perform the same expensive primitive for an unknown account.
                hashlib.pbkdf2_hmac(
                    "sha256",
                    secret[:1_024].encode("utf-8", errors="ignore"),
                    b"enterprise-agent-unknown-account",
                    PASSWORD_ITERATIONS,
                )
                self._record_failure(remote_address, actor_bucket, now)
                raise AuthenticationFailed("账号或密码错误")
            if not verify_password(secret, account.password_hash):
                self._record_failure(remote_address, actor_bucket, now)
                raise AuthenticationFailed("账号或密码错误")
            self._login_failures.pop((remote_address, actor_bucket), None)
            self._purge(now)
            token = secrets.token_urlsafe(40)
            csrf_token = secrets.token_urlsafe(32)
            expires_at = now + self.session_ttl_seconds
            principal = account.principal()
            self._sessions[self._session_key(token)] = _StoredSession(
                principal=principal,
                csrf_token=csrf_token,
                expires_at=expires_at,
            )
            return LoginResult(
                context=AuthContext(
                    principal=principal,
                    csrf_token=csrf_token,
                    session_token=token,
                    expires_at=int(expires_at),
                ),
                max_age=self.session_ttl_seconds,
            )

    def authenticate(
        self,
        session_token: str | None,
        *,
        remote_address: str,
    ) -> AuthContext | None:
        now = time.time()
        with self._lock:
            self._purge(now)
            if session_token:
                stored = self._sessions.get(self._session_key(session_token))
                if stored is not None and stored.expires_at > now:
                    return AuthContext(
                        principal=stored.principal,
                        csrf_token=stored.csrf_token,
                        session_token=session_token,
                        expires_at=int(stored.expires_at),
                    )
            if self.allow_anonymous_local and is_loopback(remote_address):
                return self._local_context
            return None

    def logout(self, session_token: str | None) -> None:
        if not session_token:
            return
        with self._lock:
            self._sessions.pop(self._session_key(session_token), None)


def build_auth_manager(
    *,
    accounts: tuple[UserAccount, ...],
    bind_host: str,
    allow_anonymous_local: bool,
    session_ttl_seconds: int,
    enable_loopback_demo: bool = True,
    public_origin_exposed: bool = False,
) -> AuthManager:
    """Create a deployment auth boundary and enforce remote-safe defaults."""

    loopback_bind = is_loopback(bind_host)
    if allow_anonymous_local and not loopback_bind:
        raise ValueError("匿名本机身份只能在回环地址监听时启用")
    if public_origin_exposed and allow_anonymous_local:
        raise ValueError("配置 PUBLIC_ORIGIN 时禁止匿名本机身份")
    if public_origin_exposed and not accounts:
        raise ValueError(
            "配置 PUBLIC_ORIGIN 时必须通过 ENTERPRISE_AGENT_USERS_JSON "
            "配置正式企业账号，不能启用演示账号"
        )
    selected = accounts
    if not selected and loopback_bind and enable_loopback_demo:
        selected = (demo_account(),)
    if not selected and not (loopback_bind and allow_anonymous_local):
        raise ValueError(
            "非回环监听必须通过 ENTERPRISE_AGENT_USERS_JSON 配置逐用户账号"
        )
    return AuthManager(
        selected,
        allow_anonymous_local=allow_anonymous_local,
        session_ttl_seconds=session_ttl_seconds,
    )
