from __future__ import annotations

import pytest

import enterprise_agent.auth as auth_module
from enterprise_agent.auth import (
    AuthenticationFailed,
    AuthManager,
    LoginThrottled,
    UserAccount,
    build_auth_manager,
    hash_password,
    parse_users_json,
    verify_password,
)


def test_password_hash_round_trip_and_plaintext_is_rejected() -> None:
    encoded = hash_password(
        "correct-horse-battery",
        iterations=100_000,
        salt=b"0123456789abcdef",
    )
    assert encoded.startswith("pbkdf2_sha256$100000$")
    assert verify_password("correct-horse-battery", encoded) is True
    assert verify_password("wrong-password", encoded) is False

    with pytest.raises(ValueError, match="password_hash"):
        parse_users_json(
            """
            [{
              "actor_id": "operator-1",
              "name": "张三",
              "role": "经办人",
              "password": "plaintext-is-not-accepted",
              "permissions": ["read"]
            }]
            """
        )


def test_user_configuration_supports_mapping_and_rejects_unknown_permission() -> None:
    encoded = hash_password(
        "a-safe-password",
        iterations=100_000,
        salt=b"0123456789abcdef",
    )
    accounts = parse_users_json(
        f"""
        {{
          "operator-1": {{
            "name": "张三",
            "role": "企业经办人",
            "password_hash": "{encoded}",
            "permissions": ["read", "write"]
          }}
        }}
        """
    )
    assert accounts[0].actor_id == "operator-1"
    assert accounts[0].permissions == frozenset({"read", "write"})

    with pytest.raises(ValueError, match="未知权限"):
        parse_users_json(
            f"""
            [{{
              "actor_id": "operator-1",
              "name": "张三",
              "role": "企业经办人",
              "password_hash": "{encoded}",
              "permissions": ["admin"]
            }}]
            """
        )


def test_demo_account_is_loopback_only_and_marked_for_password_change() -> None:
    manager = build_auth_manager(
        accounts=(),
        bind_host="127.0.0.1",
        allow_anonymous_local=False,
        session_ttl_seconds=300,
    )
    login = manager.login(
        "demo",
        "123123123",
        remote_address="127.0.0.1",
    )
    assert login.context.principal.permissions == frozenset({"read", "write"})
    assert login.context.principal.must_change_password is True
    assert login.context.principal.temporary_demo is True

    with pytest.raises(AuthenticationFailed):
        manager.login(
            "demo",
            "123123124",
            remote_address="127.0.0.2",
        )
    with pytest.raises(ValueError, match="逐用户账号"):
        build_auth_manager(
            accounts=(),
            bind_host="0.0.0.0",
            allow_anonymous_local=False,
            session_ttl_seconds=300,
        )
    with pytest.raises(ValueError, match="回环地址"):
        build_auth_manager(
            accounts=(),
            bind_host="0.0.0.0",
            allow_anonymous_local=True,
            session_ttl_seconds=300,
        )


def test_login_throttling_is_per_account_with_higher_remote_ceiling() -> None:
    def account(actor_id: str, password: str) -> UserAccount:
        return UserAccount(
            actor_id=actor_id,
            name=actor_id,
            role="企业用户",
            password_hash=hash_password(
                password,
                iterations=100_000,
                salt=(actor_id.encode() + b"0" * 16)[:16],
            ),
            permissions=frozenset({"read"}),
        )

    manager = AuthManager(
        (
            account("operator-a", "operator-a-password"),
            account("operator-b", "operator-b-password"),
        ),
        session_ttl_seconds=300,
    )
    for _ in range(8):
        with pytest.raises(AuthenticationFailed):
            manager.login(
                "operator-a",
                "wrong-password",
                remote_address="127.0.0.1",
            )
    # A shared loopback reverse proxy must not let one user's mistakes lock
    # every other enterprise user.
    assert manager.login(
        "operator-b",
        "operator-b-password",
        remote_address="127.0.0.1",
    ).context.principal.actor_id == "operator-b"
    with pytest.raises(LoginThrottled):
        manager.login(
            "operator-a",
            "operator-a-password",
            remote_address="127.0.0.1",
        )


def test_remote_wide_login_ceiling_still_blocks_username_spraying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(auth_module, "_MAX_REMOTE_LOGIN_FAILURES", 3)
    monkeypatch.setattr(auth_module, "PASSWORD_ITERATIONS", 100_000)
    account = UserAccount(
        actor_id="real-user",
        name="真实用户",
        role="企业用户",
        password_hash=hash_password(
            "real-user-password",
            iterations=100_000,
            salt=b"0123456789abcdef",
        ),
        permissions=frozenset({"read"}),
    )
    manager = AuthManager((account,), session_ttl_seconds=300)
    for index in range(3):
        with pytest.raises(AuthenticationFailed):
            manager.login(
                f"unknown-{index}",
                "wrong-password",
                remote_address="127.0.0.1",
            )
    with pytest.raises(LoginThrottled):
        manager.login(
            "real-user",
            "real-user-password",
            remote_address="127.0.0.1",
        )


def test_public_origin_never_enables_demo_or_anonymous_identity() -> None:
    with pytest.raises(ValueError, match="正式企业账号"):
        build_auth_manager(
            accounts=(),
            bind_host="127.0.0.1",
            allow_anonymous_local=False,
            session_ttl_seconds=300,
            public_origin_exposed=True,
        )
    with pytest.raises(ValueError, match="禁止匿名"):
        build_auth_manager(
            accounts=(),
            bind_host="127.0.0.1",
            allow_anonymous_local=True,
            session_ttl_seconds=300,
            public_origin_exposed=True,
        )
