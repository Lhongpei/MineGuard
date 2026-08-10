from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from mineguard import product_cli
from mineguard.auth import LocalAuthStore


ADMIN_PASSWORD = "Formal-Admin-2026!"
MESSAGE_SECRET = "message-secret-material-that-is-long-enough"
TRANSPORT_SECRET = "transport-secret-material-that-is-long-enough"


def _clients_file(tmp_path: Path) -> Path:
    path = tmp_path / "clients.json"
    path.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "sender_id": "agent-mine-001",
                        "party_id": "operator-mine-001",
                        "mine_id": "MINE-001",
                        "mine_name": "沁源一号煤矿",
                        "active_message_key_id": "mine001-msg-2026q3-a7f4",
                        "message_keys": {
                            "mine001-msg-2026q3-a7f4": MESSAGE_SECRET,
                        },
                        "transport_secrets": [TRANSPORT_SECRET],
                        "comparison_context": {
                            "capacity_band": "0.9-1.2Mtpa",
                            "mining_method": "underground-longwall",
                            "shift_system": "three-shift-eight-hour",
                            "coal_type": "thermal-coal",
                            "operating_regime": "normal-production",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def test_demo_seeds_and_starts_without_a_client_registry(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "demo"
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setenv("MINEGUARD_V2_CLIENTS_JSON", "not-json")
    monkeypatch.setenv("MINEGUARD_V2_CLIENTS_FILE", "missing.json")
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", "unrelated secret")

    def fake_serve(*args: Any, **kwargs: Any) -> None:
        assert "MINEGUARD_V2_CLIENTS_JSON" not in os.environ
        assert "MINEGUARD_V2_CLIENTS_FILE" not in os.environ
        assert "MINEGUARD_ADMIN_PASSWORD" not in os.environ
        calls.append((args, kwargs))

    monkeypatch.setattr(product_cli, "serve", fake_serve)

    assert (
        product_cli.main(
            [
                "demo",
                "--state-directory",
                str(state),
                "--through-month",
                "2026-07-31",
                "--port",
                "18080",
            ]
        )
        == 0
    )

    assert (state / "mineguard.db").is_file()
    assert (state / "auth.db").is_file()
    assert calls[0][0][:2] == ("127.0.0.1", 18080)
    assert calls[0][1]["auth_required"] is True
    assert "http://127.0.0.1:18080/" in capsys.readouterr().err
    assert os.environ["MINEGUARD_V2_CLIENTS_JSON"] == "not-json"
    assert os.environ["MINEGUARD_V2_CLIENTS_FILE"] == "missing.json"
    assert "MINEGUARD_ADMIN_PASSWORD" not in os.environ


def test_setup_wizard_keeps_secrets_out_of_settings_and_start_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "formal-state"
    clients_file = _clients_file(tmp_path)
    answers = iter([f'"{clients_file}"', "y", "formal-admin"])
    passwords = iter([ADMIN_PASSWORD, ADMIN_PASSWORD])
    monkeypatch.setattr("builtins.input", lambda _label: next(answers))
    monkeypatch.setattr(product_cli.getpass, "getpass", lambda _label: next(passwords))

    assert (
        product_cli.main(["setup", "--state-directory", str(state)])
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "configured"
    assert result["client_count"] == 1
    assert result["administrator_created"] == "formal-admin"
    assert result["password_stored_in_settings"] is False
    rendered_result = json.dumps(result, ensure_ascii=False)
    assert ADMIN_PASSWORD not in rendered_result
    assert MESSAGE_SECRET not in rendered_result
    assert TRANSPORT_SECRET not in rendered_result

    settings_path = state / ".mineguard-start.json"
    settings_text = settings_path.read_text(encoding="utf-8")
    settings = json.loads(settings_text)
    assert settings == {
        "schema_version": 1,
        "kind": "mineguard-platform-start",
        "host": "127.0.0.1",
        "port": 8080,
        "secure_cookie": True,
        "clients_file": str(clients_file),
    }
    assert ADMIN_PASSWORD not in settings_text
    assert MESSAGE_SECRET not in settings_text
    assert TRANSPORT_SECRET not in settings_text
    with LocalAuthStore(state / "auth.db") as auth:
        login = auth.login("formal-admin", ADMIN_PASSWORD, client_id="test")
        assert login.principal.username == "formal-admin"

    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake_serve(*args: Any, **kwargs: Any) -> None:
        assert "MINEGUARD_V2_CLIENTS_JSON" not in os.environ
        assert os.environ["MINEGUARD_V2_CLIENTS_FILE"] == str(clients_file)
        calls.append((args, kwargs))

    monkeypatch.setattr(product_cli, "serve", fake_serve)
    assert (
        product_cli.main(["start", "--state-directory", str(state)])
        == 0
    )
    assert calls[0][0][:2] == ("127.0.0.1", 8080)
    assert calls[0][1]["auth_required"] is True
    assert calls[0][1]["production_mode"] is True
    assert "MINEGUARD_V2_CLIENTS_FILE" not in os.environ


def test_formal_quickstart_never_falls_back_to_demo_credentials(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "formal-state"
    clients_file = _clients_file(tmp_path)
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", "123123123")

    assert (
        product_cli.main(
            [
                "setup",
                "--state-directory",
                str(state),
                "--clients-file",
                str(clients_file),
                "--non-interactive",
                "--secure-cookie",
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "不允许使用演示默认密码" in error["error"]["message"]
    assert not (state / ".mineguard-start.json").exists()

    missing = tmp_path / "not-configured"
    assert (
        product_cli.main(["start", "--state-directory", str(missing)])
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "mineguard setup" in error["error"]["message"]


def test_formal_quickstart_rejects_template_secrets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients_file = _clients_file(tmp_path)
    state = tmp_path / "formal-state"
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", "CHANGE_ME_formal_password")
    assert (
        product_cli.main(
            [
                "setup",
                "--state-directory",
                str(state),
                "--clients-file",
                str(clients_file),
                "--non-interactive",
                "--secure-cookie",
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "占位密码" in error["error"]["message"]
    assert not (state / ".mineguard-start.json").exists()


def test_setup_refuses_to_mix_formal_configuration_into_demo_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "demo"
    clients_file = _clients_file(tmp_path)
    assert (
        product_cli.main(
            [
                "seed-v2-demo",
                "--state-directory",
                str(state),
                "--through-month",
                "2026-07-31",
            ]
        )
        == 0
    )
    capsys.readouterr()
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", ADMIN_PASSWORD)

    assert (
        product_cli.main(
            [
                "setup",
                "--state-directory",
                str(state),
                "--clients-file",
                str(clients_file),
                "--non-interactive",
                "--secure-cookie",
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "不能转为正式状态目录" in error["error"]["message"]


def test_formal_start_allows_pending_strong_user_but_blocks_active_demo_user(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "formal-state"
    clients_file = _clients_file(tmp_path)
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", ADMIN_PASSWORD)
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(state),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 0
    capsys.readouterr()

    with LocalAuthStore(state / "auth.db") as auth:
        auth.create_user(
            "pending-leader",
            "Leader-Initial-2026!",
            "viewer",
            ["MINE-001"],
            must_change_password=True,
        )
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    monkeypatch.setattr(
        product_cli,
        "serve",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    assert product_cli.main(
        ["start", "--state-directory", str(state)]
    ) == 0
    assert calls[-1][1]["production_mode"] is True

    with LocalAuthStore(state / "auth.db") as auth:
        auth.create_user(
            "active-demo",
            "123123123",
            "viewer",
            ["MINE-001"],
        )
    assert product_cli.main(
        ["start", "--state-directory", str(state)]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "弱口令" in error["error"]["message"]

    with LocalAuthStore(state / "auth.db") as auth:
        auth.set_user_active("active-demo", False)
    assert product_cli.main(
        ["start", "--state-directory", str(state)]
    ) == 0


def test_formal_setup_detects_demo_database_even_if_marker_was_removed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "demo"
    clients_file = _clients_file(tmp_path)
    assert product_cli.main(
        [
            "seed-v2-demo",
            "--state-directory",
            str(state),
            "--through-month",
            "2026-07-31",
        ]
    ) == 0
    capsys.readouterr()
    (state / ".mineguard-v2-synthetic-owner.json").unlink()
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", ADMIN_PASSWORD)
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(state),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "演示或合成数据目录" in error["error"]["message"]


def test_formal_setup_rejects_an_existing_default_password_auth_database(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "formal-state"
    state.mkdir()
    clients_file = _clients_file(tmp_path)
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "123123123")
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(state),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "当前密码策略" in error["error"]["message"]
    assert not (state / ".mineguard-start.json").exists()


@pytest.mark.parametrize(
    "weak_password",
    ("password123", "admin123456", "qwerty123"),
)
def test_production_config_check_rejects_unflagged_legacy_weak_admin(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    weak_password: str,
) -> None:
    auth_database = tmp_path / f"legacy-{weak_password}.db"
    with LocalAuthStore(auth_database) as auth:
        user = auth.bootstrap_admin("admin", weak_password)
        assert user.must_change_password is False
        assert user.temporary_demo is False
    assert product_cli.main(
        [
            "config-check",
            "--auth-database",
            str(auth_database),
            "--production",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "弱口令" in error["error"]["message"]


def test_production_registry_gate_is_shared_by_config_check_and_serve(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients_file = tmp_path / "compatibility-clients.json"
    clients_file.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "sender_id": "agent-mine-001",
                        "party_id": "operator-mine-001",
                        "mine_id": "MINE-001",
                        "mine_name": "沁源一号煤矿",
                        "message_key_id": "test-key",
                        "message_secret": "a" * 32,
                        "transport_secret": TRANSPORT_SECRET,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    # Generic validation deliberately remains compatible for isolated tests.
    assert product_cli.main(
        ["config-check", "--clients-file", str(clients_file)]
    ) == 0
    assert json.loads(capsys.readouterr().out)["client_count"] == 1

    assert product_cli.main(
        [
            "config-check",
            "--clients-file",
            str(clients_file),
            "--production",
        ]
    ) == 2
    config_error = json.loads(capsys.readouterr().out)
    assert "comparison_context" in config_error["error"]["message"]

    monkeypatch.setenv("MINEGUARD_V2_CLIENTS_FILE", str(clients_file))
    monkeypatch.delenv("MINEGUARD_V2_CLIENTS_JSON", raising=False)
    monkeypatch.setattr(
        product_cli,
        "serve",
        lambda *_args, **_kwargs: pytest.fail("invalid production registry started"),
    )
    assert product_cli.main(
        [
            "serve",
            "--state-directory",
            str(tmp_path / "formal-state"),
            "--secure-cookie",
            "--production",
        ]
    ) == 2
    serve_error = json.loads(capsys.readouterr().out)
    assert "comparison_context" in serve_error["error"]["message"]


def test_production_serve_rejects_placeholder_or_colliding_platform_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients_file = _clients_file(tmp_path)
    monkeypatch.setenv("MINEGUARD_V2_CLIENTS_FILE", str(clients_file))
    monkeypatch.delenv("MINEGUARD_V2_CLIENTS_JSON", raising=False)
    assert product_cli.main(
        [
            "config-check",
            "--clients-file",
            str(clients_file),
            "--production",
            "--platform-system-id",
            "mineguard-qinyuan",
            "--platform-party-id",
            "regulator-qinyuan",
            "--platform-key-id",
            "mine001-msg-2026q3-a7f4",
        ]
    ) == 2
    config_collision = json.loads(capsys.readouterr().out)
    assert "must not reuse" in config_collision["error"]["message"]

    monkeypatch.setattr(
        product_cli,
        "serve",
        lambda *_args, **_kwargs: pytest.fail("invalid platform identity started"),
    )
    common = [
        "serve",
        "--state-directory",
        str(tmp_path / "formal-state"),
        "--secure-cookie",
        "--production",
    ]

    monkeypatch.setenv("MINEGUARD_V2_PLATFORM_SYSTEM_ID", "demo-platform")
    assert product_cli.main(common) == 2
    placeholder = json.loads(capsys.readouterr().out)
    assert "platform_system_id" in placeholder["error"]["message"]
    assert "placeholder" in placeholder["error"]["message"]

    monkeypatch.setenv("MINEGUARD_V2_PLATFORM_SYSTEM_ID", "mineguard-qinyuan")
    monkeypatch.setenv(
        "MINEGUARD_V2_PLATFORM_KEY_ID", "mine001-msg-2026q3-a7f4"
    )
    assert product_cli.main(common) == 2
    collision = json.loads(capsys.readouterr().out)
    assert "must not reuse" in collision["error"]["message"]


def test_formal_setup_start_and_config_check_reject_unclassified_credentials(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This intentionally weak historical value is not in the finite weak-word
    # dictionary.  The durable policy marker, not password guessing, must block it.
    standalone_auth = tmp_path / "legacy-unclassified.db"
    with LocalAuthStore(standalone_auth) as auth:
        auth.bootstrap_admin("admin", "admin password")
    assert product_cli.main(
        [
            "config-check",
            "--auth-database",
            str(standalone_auth),
            "--production",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "旧策略" in error["error"]["message"]
    assert "change-password" in error["error"]["message"]

    clients_file = _clients_file(tmp_path)
    legacy_state = tmp_path / "legacy-state"
    legacy_state.mkdir()
    with LocalAuthStore(legacy_state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "admin password")
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(legacy_state),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "change-password" in error["error"]["message"]
    assert not (legacy_state / ".mineguard-start.json").exists()

    ready_state = tmp_path / "ready-state"
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", ADMIN_PASSWORD)
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(ready_state),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 0
    capsys.readouterr()
    with sqlite3.connect(ready_state / "auth.db") as connection:
        connection.execute(
            "UPDATE users SET credential_policy_version = 0 WHERE username = 'admin'"
        )
    monkeypatch.setattr(
        product_cli,
        "serve",
        lambda *_args, **_kwargs: pytest.fail("production server must not start"),
    )
    assert product_cli.main(
        ["start", "--state-directory", str(ready_state)]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "change-password" in error["error"]["message"]


def test_formal_start_rejects_legacy_common_weak_admin_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "formal-state"
    clients_file = _clients_file(tmp_path)
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", ADMIN_PASSWORD)
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(state),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 0
    capsys.readouterr()
    with LocalAuthStore(state / "auth.db") as auth:
        auth.reset_password(
            "admin",
            "password123",
            must_change_password=False,
            temporary_demo=False,
            strict=False,
        )
    assert product_cli.main(
        ["start", "--state-directory", str(state)]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "当前密码策略" in error["error"]["message"]


def test_formal_setup_rejects_legacy_common_weak_admin_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "formal-state"
    state.mkdir()
    clients_file = _clients_file(tmp_path)
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "admin123456")
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(state),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "当前密码策略" in error["error"]["message"]
    assert not (state / ".mineguard-start.json").exists()


def test_formal_setup_requires_https_and_strong_password_classes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clients_file = _clients_file(tmp_path)
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", "alllowercasepassword1")
    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(tmp_path / "no-https"),
            "--clients-file",
            str(clients_file),
            "--non-interactive",
        ]
    ) == 2
    assert "--secure-cookie" in json.loads(capsys.readouterr().out)["error"][
        "message"
    ]

    assert product_cli.main(
        [
            "setup",
            "--state-directory",
            str(tmp_path / "weak"),
            "--clients-file",
            str(clients_file),
            "--secure-cookie",
            "--non-interactive",
        ]
    ) == 2
    assert "至少三类" in json.loads(capsys.readouterr().out)["error"]["message"]
