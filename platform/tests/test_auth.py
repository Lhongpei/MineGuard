from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import json
import sqlite3

import pytest

from mineguard.auth import (
    AuthError,
    BootstrapConflictError,
    CURRENT_CREDENTIAL_POLICY_VERSION,
    CsrfValidationError,
    InvalidCredentialsError,
    InvalidSessionError,
    LastActiveAdminError,
    LocalAuth,
    LoginRateLimitedError,
    Permission,
    PermissionDeniedError,
    Principal,
    Role,
    SessionExpiredError,
    UnknownPermissionError,
    authorize,
    inspect_auth_database,
    session_cookie_header,
)


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def test_passwords_are_salted_and_bootstrap_is_idempotent(
    tmp_path,
) -> None:
    database = tmp_path / "auth.sqlite3"
    store = LocalAuth(database)

    first = store.bootstrap_admin("Admin", "correct horse battery staple")
    second = store.bootstrap_admin("admin", "correct horse battery staple")
    assert first.user_id == second.user_id

    with pytest.raises(BootstrapConflictError):
        store.bootstrap_admin("admin", "different password")

    store.create_user(
        "reviewer-a",
        "same password",
        Role.REVIEWER,
        ["M001"],
    )
    store.create_user(
        "reviewer-b",
        "same password",
        Role.REVIEWER,
        ["M002"],
    )
    login = store.login(
        "reviewer-a",
        "same password",
        client_id="127.0.0.1",
    )

    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            """
            SELECT password_salt,password_hash FROM users
            WHERE username IN ('reviewer-a','reviewer-b')
            ORDER BY username
            """
        ).fetchall()
        session_row = connection.execute(
            "SELECT token_sha256,csrf_sha256 FROM sessions"
        ).fetchone()
        dump = "\n".join(connection.iterdump())
    finally:
        connection.close()

    assert rows[0][0] != rows[1][0]
    assert rows[0][1] != rows[1][1]
    assert session_row is not None
    assert len(session_row[0]) == len(session_row[1]) == 64
    assert "same password" not in dump
    assert login.session_token not in dump
    assert login.csrf_token not in dump


def test_bootstrap_only_creates_the_first_user(tmp_path) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    store.bootstrap_admin("root", "admin password")

    with pytest.raises(BootstrapConflictError):
        store.bootstrap_admin("another-admin", "admin password")


def test_idle_touch_and_absolute_expiration(tmp_path) -> None:
    clock = MutableClock(datetime(2026, 7, 26, tzinfo=UTC))
    store = LocalAuth(
        tmp_path / "auth.sqlite3",
        absolute_timeout_seconds=25,
        idle_timeout_seconds=10,
        clock=clock,
    )
    store.bootstrap_admin("admin", "admin password")

    session = store.login(
        "admin",
        "admin password",
        client_id="browser-a",
    )
    clock.advance(9)
    store.touch_session(session.session_token)
    clock.advance(9)
    assert (
        store.authenticate(session.session_token, touch=False).username
        == "admin"
    )
    clock.advance(8)
    with pytest.raises(SessionExpiredError):
        store.authenticate(session.session_token)

    idle_session = store.login(
        "admin",
        "admin password",
        client_id="browser-b",
    )
    clock.advance(11)
    with pytest.raises(SessionExpiredError):
        store.authenticate(idle_session.session_token)


def test_disable_logout_and_revoke_all_invalidate_sessions(tmp_path) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    store.bootstrap_admin("admin", "admin password")
    store.create_user("alice", "alice password", Role.REVIEWER, ["M001"])
    first = store.login("alice", "alice password", client_id="one")
    second = store.login("alice", "alice password", client_id="two")

    store.set_user_active("alice", False)
    for token in (first.session_token, second.session_token):
        with pytest.raises(InvalidSessionError):
            store.authenticate(token)

    with pytest.raises(InvalidCredentialsError):
        store.login("alice", "alice password", client_id="three")

    store.set_user_active("alice", True)
    third = store.login("alice", "alice password", client_id="three")
    fourth = store.login("alice", "alice password", client_id="four")
    assert store.revoke_all("alice") == 2
    for token in (third.session_token, fourth.session_token):
        with pytest.raises(InvalidSessionError):
            store.authenticate(token)

    fifth = store.login("alice", "alice password", client_id="five")
    store.logout(fifth.session_token)
    with pytest.raises(InvalidSessionError):
        store.authenticate(fifth.session_token)


def test_last_active_admin_is_preserved_and_access_changes_revoke_sessions(
    tmp_path,
) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    root = store.bootstrap_admin("root", "root password")

    with pytest.raises(LastActiveAdminError):
        store.set_user_active("root", False)
    with pytest.raises(LastActiveAdminError):
        store.update_user_access("root", Role.REVIEWER, ["M001"])
    assert store.get_user("root") == root

    store.create_user("backup-admin", "backup password", Role.ADMIN)
    root_session = store.login(
        "root",
        "root password",
        client_id="root-browser",
    )
    updated = store.update_user_access(
        "root",
        Role.SUPERVISOR,
        ["M002", "M001", "M001"],
    )
    assert updated.role is Role.SUPERVISOR
    assert updated.mine_scopes == ("M001", "M002")
    with pytest.raises(InvalidSessionError):
        store.authenticate(root_session.session_token)

    with pytest.raises(LastActiveAdminError):
        store.set_user_active("backup-admin", False)
    with pytest.raises(LastActiveAdminError):
        store.update_user_access(
            "backup-admin",
            Role.VIEWER,
            ["M001"],
        )

    access_event = next(
        event
        for event in store.list_audit_events()
        if event["action"] == "user_access_changed"
    )
    assert access_event["username"] == "root"
    assert access_event["detail"] == {
        "previous_role": "admin",
        "role": "supervisor",
        "previous_mine_scopes": [],
        "mine_scopes": ["M001", "M002"],
        "sessions_revoked": 1,
    }


def test_password_change_and_admin_reset_revoke_sessions(tmp_path) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    store.bootstrap_admin("admin", "admin password")
    store.create_user("alice", "alice password", Role.REVIEWER, ["M001"])

    first = store.login("alice", "alice password", client_id="one")
    with pytest.raises(InvalidCredentialsError):
        store.change_password(
            "alice", "wrong", "New-Alice-Password-2026!"
        )
    store.change_password(
        "alice",
        "alice password",
        "New-Alice-Password-2026!",
    )
    with pytest.raises(InvalidSessionError):
        store.authenticate(first.session_token)
    with pytest.raises(InvalidCredentialsError):
        store.login("alice", "alice password", client_id="two")

    second = store.login(
        "alice", "New-Alice-Password-2026!", client_id="two"
    )
    store.reset_password("alice", "reset alice password")
    pending = store.get_user("alice")
    assert pending is not None and pending.must_change_password is True
    with pytest.raises(InvalidSessionError):
        store.authenticate(second.session_token)
    reset_login = store.login(
        "alice",
        "reset alice password",
        client_id="three",
    )
    assert reset_login.principal.must_change_password is True
    store.change_password(
        "alice", "reset alice password", "Self-Service-Password-2026!"
    )
    ready = store.get_user("alice")
    assert ready is not None and ready.must_change_password is False
    assert ready.temporary_demo is False
    assert ready.credential_policy_version == CURRENT_CREDENTIAL_POLICY_VERSION


def test_demo_credentials_are_durable_and_fail_closed_for_production(
    tmp_path,
) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    demo = store.bootstrap_admin("admin", "123123123")
    assert demo.must_change_password is True
    assert demo.temporary_demo is True
    status = store.production_credential_status()
    assert status["production_ready"] is False
    assert status["blocked_users"] == [
        {
            "username": "admin",
            "reasons": [
                "credential_policy_outdated",
                "forbidden_weak_password",
                "must_change_password",
                "temporary_demo",
            ],
        }
    ]

def test_pending_strong_non_admin_keeps_production_ready_but_requires_change(
    tmp_path,
) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    store.bootstrap_admin("admin", "Production-Admin-2026!")
    store.create_user(
        "leader",
        "Leader-Initial-2026!",
        Role.VIEWER,
        ["M001"],
        must_change_password=True,
    )
    status = store.production_credential_status()
    assert status["production_ready"] is True
    assert status["active_ready_admin_count"] == 1
    assert status["pending_password_change_user_count"] == 1
    assert status["blocked_user_count"] == 0
    assert status["blocked_users"] == []

    login = store.login("leader", "Leader-Initial-2026!", client_id="browser")
    assert login.principal.must_change_password is True


def test_inactive_demo_account_does_not_block_a_ready_administrator(
    tmp_path,
) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    store.bootstrap_admin("admin", "Production-Admin-2026!")
    store.create_user("old-demo", "123123123", Role.VIEWER, ["M001"])
    store.set_user_active("old-demo", False)
    status = store.production_credential_status()
    assert status["production_ready"] is True
    assert status["blocked_user_count"] == 0


@pytest.mark.parametrize(
    "weak_password",
    ("password", "password123", "admin123", "admin123456", "qwerty123"),
)
def test_unflagged_legacy_common_password_is_detected_by_digest(
    tmp_path,
    weak_password: str,
) -> None:
    store = LocalAuth(tmp_path / f"legacy-{weak_password}.sqlite3")
    # These values are not marked temporary_demo by the legacy-compatible
    # writer.  Production readiness must therefore identify them from their
    # salted digest, not rely on the new purpose columns.
    user = store.bootstrap_admin("admin", weak_password)
    assert user.must_change_password is False
    assert user.temporary_demo is False
    status = store.production_credential_status()
    assert status["production_ready"] is False
    assert status["active_ready_admin_count"] == 0
    assert status["blocked_users"] == [
        {
            "username": "admin",
            "reasons": [
                "credential_policy_outdated",
                "forbidden_weak_password",
            ],
        }
    ]


def test_legacy_auth_schema_is_migrated_without_reclassifying_passwords(
    tmp_path,
) -> None:
    database = tmp_path / "legacy-auth.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE users (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                username_key TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                mine_scopes_json TEXT NOT NULL,
                active INTEGER NOT NULL,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
    with LocalAuth(database) as store:
        user = store.bootstrap_admin("admin", "Production-Admin-2026!")
        assert user.must_change_password is False
        assert user.temporary_demo is False
    with sqlite3.connect(database) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(users)")
        }
    assert {
        "must_change_password",
        "temporary_demo",
        "credential_policy_version",
    }.issubset(columns)


def test_unclassified_password_outside_weak_dictionary_blocks_production(
    tmp_path,
) -> None:
    store = LocalAuth(tmp_path / "unclassified.sqlite3")
    user = store.bootstrap_admin("admin", "admin password")
    assert user.credential_policy_version == 0
    status = store.production_credential_status()
    assert status["production_ready"] is False
    assert status["outdated_credential_policy_user_count"] == 1
    assert status["blocked_users"] == [
        {"username": "admin", "reasons": ["credential_policy_outdated"]}
    ]


def test_legacy_row_stays_unclassified_until_verified_password_rotation(
    tmp_path,
) -> None:
    database = tmp_path / "legacy-policy.sqlite3"
    original_password = "Legacy-Strong-Password-2025!"
    with LocalAuth(database) as store:
        store.bootstrap_admin("admin", original_password)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "ALTER TABLE users DROP COLUMN credential_policy_version"
        )

    # Read-only deployment checks must fail closed before opening/migrating.
    inspected = inspect_auth_database(database)
    assert inspected["production_ready"] is False
    assert inspected["blocked_users"] == [
        {"username": "admin", "reasons": ["credential_policy_outdated"]}
    ]

    with LocalAuth(database) as migrated:
        legacy = migrated.get_user("admin")
        assert legacy is not None
        assert legacy.credential_policy_version == 0
        migrated.change_password(
            "admin",
            original_password,
            "Rotated-Strong-Password-2026!",
        )
        upgraded = migrated.get_user("admin")
        assert upgraded is not None
        assert upgraded.credential_policy_version == (
            CURRENT_CREDENTIAL_POLICY_VERSION
        )
        assert upgraded.must_change_password is False
        assert migrated.production_credential_status()["production_ready"] is True


@pytest.mark.parametrize("invalid_version", (-1, 2, "future"))
def test_invalid_or_future_credential_policy_versions_fail_closed(
    tmp_path,
    invalid_version: object,
) -> None:
    database = tmp_path / f"invalid-policy-{invalid_version}.sqlite3"
    with LocalAuth(database) as store:
        store.bootstrap_admin("admin", "Ready-Admin-Password-2026!")
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE users SET credential_policy_version = ?",
            (invalid_version,),
        )
    with pytest.raises(AuthError, match="invalid or unsupported"):
        inspect_auth_database(database)
    with LocalAuth(database) as store:
        with pytest.raises(AuthError, match="invalid or unsupported"):
            store.production_credential_status()


def test_login_failures_are_limited_by_username_and_client(tmp_path) -> None:
    clock = MutableClock(datetime(2026, 7, 26, tzinfo=UTC))
    store = LocalAuth(
        tmp_path / "auth.sqlite3",
        max_login_failures=2,
        login_window_seconds=10,
        lockout_seconds=20,
        clock=clock,
    )
    store.bootstrap_admin("admin", "admin password")

    for _ in range(2):
        with pytest.raises(InvalidCredentialsError):
            store.login("admin", "wrong password", client_id="10.0.0.1")
    with pytest.raises(LoginRateLimitedError) as limited:
        store.login("admin", "admin password", client_id="10.0.0.1")
    assert limited.value.retry_after_seconds == 20

    # A different client identifier has an independent bucket.
    assert store.login(
        "admin",
        "admin password",
        client_id="10.0.0.2",
    ).principal.role is Role.ADMIN

    clock.advance(21)
    assert store.login(
        "admin",
        "admin password",
        client_id="10.0.0.1",
    ).principal.username == "admin"


def _principal(role: Role, scopes: tuple[str, ...]) -> Principal:
    return Principal(
        user_id=f"user-{role.value}",
        username=role.value,
        role=role,
        mine_scopes=scopes,
        session_id=f"session-{role.value}",
    )


def test_authorization_matrix_and_mine_scopes() -> None:
    admin = _principal(Role.ADMIN, ())
    supervisor = _principal(Role.SUPERVISOR, ("M001", "M002"))
    reviewer = _principal(Role.REVIEWER, ("M001",))
    viewer = _principal(Role.VIEWER, ("M001",))

    for permission in Permission:
        authorize(admin, permission)

    for permission in (
        Permission.DATA_READ,
        Permission.CASE_ASSIGN,
        Permission.CASE_APPROVE,
        Permission.AUDIT_READ,
    ):
        authorize(supervisor, permission, "M001")

    authorize(reviewer, Permission.CASE_REVIEW, "M001")
    authorize(viewer, Permission.CASE_READ, "M001")

    for principal, permission in (
        (supervisor, Permission.CONFIG_MANAGE),
        (supervisor, Permission.USER_MANAGE),
        (reviewer, Permission.CASE_APPROVE),
        (reviewer, Permission.CASE_ASSIGN),
        (viewer, Permission.CASE_REVIEW),
        (viewer, Permission.ANALYSIS_RUN),
    ):
        with pytest.raises(PermissionDeniedError):
            authorize(principal, permission, "M001")

    with pytest.raises(PermissionDeniedError):
        authorize(supervisor, Permission.CASE_READ)
    with pytest.raises(PermissionDeniedError):
        authorize(supervisor, Permission.CASE_READ, "M999")
    with pytest.raises(PermissionDeniedError):
        authorize(
            Principal(
                user_id="disabled",
                username="disabled",
                role=Role.ADMIN,
                mine_scopes=(),
                session_id="disabled",
                active=False,
            ),
            Permission.DATA_READ,
        )
    with pytest.raises(UnknownPermissionError):
        authorize(admin, "case.typo")


def test_csrf_checks_state_changes_and_cookie_attributes(tmp_path) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    store.bootstrap_admin("admin", "admin password")
    login = store.login("admin", "admin password", client_id="browser")

    assert store.validate_csrf(
        login.session_token,
        None,
        method="GET",
    ).username == "admin"
    with pytest.raises(CsrfValidationError):
        store.validate_csrf(login.session_token, None, method="POST")
    with pytest.raises(CsrfValidationError):
        store.validate_csrf(login.session_token, "wrong", method="DELETE")
    assert store.validate_csrf(
        login.session_token,
        login.csrf_token,
        method="PATCH",
    ).username == "admin"
    principal, rotated = store.issue_csrf(login.session_token)
    assert principal.username == "admin"
    with pytest.raises(CsrfValidationError):
        store.validate_csrf(
            login.session_token,
            login.csrf_token,
            method="POST",
        )
    assert store.validate_csrf(
        login.session_token,
        rotated,
        method="POST",
    ).username == "admin"

    secure_cookie = session_cookie_header(
        login.session_token,
        max_age_seconds=3600,
    )
    for attribute in (
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=3600",
        "Secure",
    ):
        assert attribute in secure_cookie
    assert "Secure" not in session_cookie_header(
        login.session_token,
        max_age_seconds=60,
        secure=False,
    )


def test_sessions_and_users_survive_database_reopen(tmp_path) -> None:
    database = tmp_path / "auth.sqlite3"
    first_store = LocalAuth(database)
    user = first_store.bootstrap_admin("admin", "admin password")
    login = first_store.login("admin", "admin password", client_id="browser")
    first_store.close()

    second_store = LocalAuth(database)
    assert second_store.get_user("admin") == user
    assert (
        second_store.authenticate(login.session_token, touch=False).user_id
        == user.user_id
    )


def test_audit_and_listing_views_never_return_secret_material(tmp_path) -> None:
    store = LocalAuth(tmp_path / "auth.sqlite3")
    store.bootstrap_admin("admin", "admin password")
    login = store.login("admin", "admin password", client_id="browser")

    returned = {
        "users": store.list_users(),
        "sessions": store.list_sessions("admin"),
        "audit": store.list_audit_events(),
    }
    encoded = json.dumps(returned, ensure_ascii=False)
    for forbidden in (
        "password_hash",
        "password_salt",
        "token_sha256",
        "csrf_sha256",
        login.session_token,
        login.csrf_token,
        "admin password",
    ):
        assert forbidden not in encoded
