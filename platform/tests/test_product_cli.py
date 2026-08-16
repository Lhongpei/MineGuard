from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from mineguard.auth import LocalAuthStore
from mineguard import product_cli


def test_product_cli_exposes_only_v2_runtime_and_operations() -> None:
    parser = product_cli._parser()  # noqa: SLF001 - product surface regression
    subparsers = next(
        action
        for action in parser._actions  # noqa: SLF001
        if action.__class__.__name__ == "_SubParsersAction"
    )
    assert set(subparsers.choices) == {
        "serve",
        "demo",
        "setup",
        "start",
        "bootstrap-admin",
        "seed-v2-demo",
        "backup",
        "verify-backup",
        "restore-backup",
        "config-check",
        "self-check",
        "provision",
        "user",
    }
    user_parser = subparsers.choices["user"]
    user_subparsers = next(
        action
        for action in user_parser._actions  # noqa: SLF001
        if action.__class__.__name__ == "_SubParsersAction"
    )
    assert set(user_subparsers.choices) == {
        "list",
        "mines",
        "add",
        "set-access",
        "enable",
        "disable",
        "reset-password",
        "change-password",
    }
    source = inspect.getsource(product_cli)
    assert "from .api" not in source
    assert "from .edge_store" not in source
    with pytest.raises(SystemExit):
        parser.parse_args(["production", "{}"])


def test_product_cli_self_check_covers_both_frontends_timezone_and_solver(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert product_cli.main(["self-check"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok"
    assert result["timezone"] == "Asia/Shanghai"
    assert result["solver"] == "scipy.optimize.linprog/highs"
    assert result["solver_objective"] == pytest.approx(1.0)
    assert result["provisioning_crypto"] == "ed25519+aes-256-gcm+scrypt"
    assert {
        "regulatory_web/index.html",
        "regulatory_web/app.js",
        "regulatory_web/styles.css",
        "web/index.html",
        "web/app.js",
        "web/styles.css",
        "demo_samples/taiyue-2026-07.et",
        "demo_samples/gengyang-2026-07.et",
    } == set(result["assets"])
    assert all(item["bytes"] > 0 for item in result["assets"].values())
    assert all(
        value != "not-installed"
        for value in result["runtime"]["dependencies"].values()
    )


def test_product_cli_config_check_is_read_only_and_machine_parseable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    auth_database = tmp_path / "auth.db"
    with LocalAuthStore(auth_database) as auth:
        auth.bootstrap_admin("admin", "Ready-Admin-Password-2026!")

    assert (
        product_cli.main(
            ["config-check", "--auth-database", str(auth_database)]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "ok"
    assert result["auth_user_count"] == 1
    assert result["auth_ready_admin_count"] == 1
    assert result["auth_production_ready"] is True
    assert result["auth_blocked_user_count"] == 0
    assert result["auth_outdated_credential_policy_user_count"] == 0
    assert result["auth_current_credential_policy_version"] == 1

    assert product_cli.main(["config-check"]) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["error"]["code"] == "operation_failed"


def test_short_bootstrap_uses_fixed_file_and_writes_only_password_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "formal-state"
    password = "Bootstrap-Admin-Password-2026!"
    password_file = tmp_path / "bootstrap-admin-password.txt"
    password_file.write_text(password, encoding="utf-8")
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", "must-not-be-used")
    assert product_cli.main(
        [
            "bootstrap-admin",
            "--state-directory",
            str(state),
            "--admin-username",
            "formal-admin",
            "--password-file",
            str(password_file),
            "--production",
        ]
    ) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["status"] == "administrator_bootstrapped"
    assert result["production_ready"] is True
    assert result["password_stored"] is False
    assert result["credential_policy_version"] == 1
    assert password not in output
    assert "MINEGUARD_ADMIN_PASSWORD" not in os.environ
    assert not password_file.exists()
    assert not (state / ".mineguard-start.json").exists()
    with LocalAuthStore(state / "auth.db") as auth:
        assert auth.login(
            "formal-admin", password, client_id="bootstrap-test"
        ).principal.username == "formal-admin"


def test_short_bootstrap_is_formal_empty_store_only_and_retains_failed_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "existing-state"
    state.mkdir()
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("existing-admin", "Existing-Admin-Password-2026!")
    password_file = tmp_path / "bootstrap-admin-password.txt"
    password_file.write_text(
        "Second-Admin-Password-2026!", encoding="utf-8"
    )
    assert product_cli.main(
        [
            "bootstrap-admin",
            "--state-directory",
            str(state),
            "--password-file",
            str(password_file),
            "--production",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "空 auth.db" in error["error"]["message"]
    assert password_file.is_file()

    assert product_cli.main(
        [
            "bootstrap-admin",
            "--state-directory",
            str(tmp_path / "unsafe"),
            "--password-file",
            str(password_file),
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "--production" in error["error"]["message"]
    assert password_file.is_file()


def test_short_bootstrap_rejects_password_file_symlink(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "secret-target.txt"
    target.write_text("Symlink-Admin-Password-2026!", encoding="utf-8")
    password_file = tmp_path / "bootstrap-admin-password.txt"
    try:
        password_file.symlink_to(target)
    except OSError as error:
        if os.name == "nt" and error.winerror == 1314:
            pytest.skip("Windows symbolic-link privilege is unavailable")
        raise
    assert product_cli.main(
        [
            "bootstrap-admin",
            "--state-directory",
            str(tmp_path / "formal-state"),
            "--password-file",
            str(password_file),
            "--production",
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "符号链接" in error["error"]["message"]
    assert password_file.is_symlink()
    assert target.is_file()


def test_loopback_first_start_uses_requested_demo_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    calls: list[tuple[object, ...]] = []
    monkeypatch.delenv("MINEGUARD_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(
        product_cli,
        "serve",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert (
        product_cli.main(
            ["serve", "--state-directory", str(state), "--port", "18080"]
        )
        == 0
    )
    assert calls
    with LocalAuthStore(state / "auth.db") as auth:
        login = auth.login("admin", "123123123", client_id="test")
        assert login.principal.username == "admin"


def test_loopback_gui_control_token_is_consumed_and_passed_in_memory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "controlled-state"
    token = "a" * 64
    calls: list[dict[str, object]] = []
    monkeypatch.setenv("MINEGUARD_LOCAL_CONTROL_TOKEN", token)
    monkeypatch.setattr(
        product_cli,
        "serve",
        lambda *args, **kwargs: calls.append(kwargs),
    )

    assert (
        product_cli.main(
            ["serve", "--state-directory", str(state), "--port", "18081"]
        )
        == 0
    )
    assert calls[0]["local_control_token"] == token
    assert "MINEGUARD_LOCAL_CONTROL_TOKEN" not in os.environ


def test_loopback_gui_control_token_rejects_malformed_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MINEGUARD_LOCAL_CONTROL_TOKEN", "not-a-token")
    monkeypatch.setattr(
        product_cli,
        "serve",
        lambda *args, **kwargs: pytest.fail("server must not start"),
    )

    assert (
        product_cli.main(
            ["serve", "--state-directory", str(tmp_path / "bad-control")]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "本机控制令牌格式无效" in error["error"]["message"]
    assert "MINEGUARD_LOCAL_CONTROL_TOKEN" not in os.environ


def test_user_cli_manages_accounts_in_the_selected_live_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "admin password")
    with sqlite3.connect(state / "mineguard.db") as connection:
        connection.execute(
            """
            CREATE TABLE v2_agent_mine_bindings(
                agent_id TEXT PRIMARY KEY,
                mine_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO v2_agent_mine_bindings VALUES (?,?,?)",
            [
                ("agent-001", "MINE-QY-001", "2026-08-01T00:00:00+00:00"),
                ("agent-002", "MINE-QY-002", "2026-08-01T00:00:00+00:00"),
            ],
        )

    monkeypatch.setenv("MINEGUARD_NEW_USER_PASSWORD", "initial password")
    assert (
        product_cli.main(
            [
                "user",
                "add",
                "领导甲",
                "--role",
                "viewer",
                "--mine-id",
                "MINE-QY-001",
                "--state-directory",
                str(state),
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["status"] == "created"
    assert created["restart_required"] is False
    assert created["user"]["mine_scopes"] == ["MINE-QY-001"]
    assert "password" not in created["user"]

    with LocalAuthStore(state / "auth.db") as auth:
        login = auth.login("领导甲", "initial password", client_id="test")
        assert login.principal.mine_scopes == ("MINE-QY-001",)
    assert "MINEGUARD_NEW_USER_PASSWORD" not in os.environ

    assert (
        product_cli.main(
            ["user", "list", "--state-directory", str(state)]
        )
        == 0
    )
    listed = json.loads(capsys.readouterr().out)
    assert listed["count"] == 2
    assert {item["username"] for item in listed["users"]} == {"admin", "领导甲"}

    assert (
        product_cli.main(
            [
                "user",
                "set-access",
                "领导甲",
                "--role",
                "reviewer",
                "--all-mines",
                "--state-directory",
                str(state),
            ]
        )
        == 0
    )
    changed = json.loads(capsys.readouterr().out)
    assert changed["sessions_revoked"] is True
    assert changed["user"]["role"] == "reviewer"
    assert changed["user"]["mine_scopes"] == ["MINE-QY-001", "MINE-QY-002"]

    assert (
        product_cli.main(
            ["user", "disable", "领导甲", "--state-directory", str(state)]
        )
        == 0
    )
    disabled = json.loads(capsys.readouterr().out)
    assert disabled["status"] == "disabled"
    assert disabled["user"]["active"] is False

    assert (
        product_cli.main(
            ["user", "enable", "领导甲", "--state-directory", str(state)]
        )
        == 0
    )
    enabled = json.loads(capsys.readouterr().out)
    assert enabled["user"]["active"] is True

    assert (
        product_cli.main(
            [
                "user",
                "reset-password",
                "领导甲",
                "--demo-default-password",
                "--state-directory",
                str(state),
            ]
        )
        == 0
    )
    reset = json.loads(capsys.readouterr().out)
    assert reset["status"] == "password_reset"
    assert reset["warnings"]
    with LocalAuthStore(state / "auth.db") as auth:
        login = auth.login("领导甲", "123123123", client_id="test-after-reset")
        assert login.principal.role.value == "reviewer"


@pytest.mark.parametrize(
    "formal_marker",
    (".mineguard-start.json", ".mineguard-platform-state.json"),
)
def test_formal_user_add_rejects_and_clears_environment_password(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    formal_marker: str,
) -> None:
    state = tmp_path / "formal-state"
    state.mkdir()
    (state / formal_marker).write_text("{}", encoding="utf-8")
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "Formal-Admin-2026!")
    monkeypatch.setenv(
        "MINEGUARD_NEW_USER_PASSWORD", "Leader-Initial-2026!"
    )

    assert product_cli.main(
        [
            "user",
            "add",
            "leader-a",
            "--role",
            "viewer",
            "--mine-id",
            "MINE-QY-001",
            "--state-directory",
            str(state),
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "不接受 MINEGUARD_NEW_USER_PASSWORD" in error["error"]["message"]
    assert "MINEGUARD_NEW_USER_PASSWORD" not in os.environ
    with LocalAuthStore(state / "auth.db") as auth:
        assert auth.get_user("leader-a") is None


def test_formal_user_add_requires_an_attached_local_terminal(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "formal-state"
    state.mkdir()
    (state / ".mineguard-start.json").write_text("{}", encoding="utf-8")
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "Formal-Admin-2026!")

    assert product_cli.main(
        [
            "user",
            "add",
            "leader-a",
            "--role",
            "viewer",
            "--mine-id",
            "MINE-QY-001",
            "--state-directory",
            str(state),
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "服务器本机交互终端" in error["error"]["message"]


def test_user_cli_rejects_wrong_state_directory_and_missing_mine_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing"
    assert (
        product_cli.main(
            ["user", "list", "--state-directory", str(missing)]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "同一 --state-directory" in error["error"]["message"]

    state = tmp_path / "state"
    state.mkdir()
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "admin password")
    assert (
        product_cli.main(
            [
                "user",
                "add",
                "scope-less",
                "--demo-default-password",
                "--state-directory",
                str(state),
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "至少需要一个 --mine-id 或 --all-mines" in error["error"]["message"]


def test_local_interactive_password_rotation_upgrades_legacy_policy_without_leak(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "legacy-state"
    state.mkdir()
    old_password = "admin password"
    new_password = "Rotated-Admin-Password-2026!"
    with LocalAuthStore(state / "auth.db") as auth:
        legacy = auth.bootstrap_admin("admin", old_password)
        assert legacy.credential_policy_version == 0

    monkeypatch.setattr(
        product_cli.sys,
        "stdin",
        SimpleNamespace(isatty=lambda: True),
    )
    entered = iter([old_password, new_password, new_password])
    monkeypatch.setattr(product_cli.getpass, "getpass", lambda _label: next(entered))
    assert product_cli.main(
        [
            "user",
            "change-password",
            "admin",
            "--state-directory",
            str(state),
        ]
    ) == 0
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result == {
        "credential_policy_version": 1,
        "password_stored": False,
        "restart_required": False,
        "sessions_revoked": True,
        "state_directory": str(state.resolve()),
        "status": "password_changed",
        "username": "admin",
    }
    assert old_password not in output
    assert new_password not in output
    with LocalAuthStore(state / "auth.db") as auth:
        upgraded = auth.get_user("admin")
        assert upgraded is not None
        assert upgraded.credential_policy_version == 1
        assert upgraded.must_change_password is False
        assert auth.production_credential_status()["production_ready"] is True


def test_password_rotation_refuses_noninteractive_secret_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "legacy-state"
    state.mkdir()
    with LocalAuthStore(state / "auth.db") as auth:
        auth.bootstrap_admin("admin", "admin password")
    monkeypatch.setattr(
        product_cli.sys,
        "stdin",
        SimpleNamespace(isatty=lambda: False),
    )
    monkeypatch.setattr(
        product_cli.getpass,
        "getpass",
        lambda _label: pytest.fail("must not read a password without a local TTY"),
    )
    assert product_cli.main(
        [
            "user",
            "change-password",
            "admin",
            "--state-directory",
            str(state),
        ]
    ) == 2
    error = json.loads(capsys.readouterr().out)
    assert "本机交互终端" in error["error"]["message"]
    assert "环境变量" in error["error"]["message"]


def test_seed_v2_demo_command_creates_isolated_dashboard_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "demo"
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
    raw_output = capsys.readouterr().out
    # This command is parsed by the Windows PowerShell 5.1 control center.
    # Keep its transport ASCII-only so a legacy console code page cannot
    # corrupt Chinese values or the JSON syntax around them.
    assert raw_output.isascii()
    payload = json.loads(raw_output)
    assert payload["synthetic_demo"] is True
    assert payload["demo_dataset"] is True
    assert payload["contains_workbook_examples"] is True
    assert payload["mine_count"] == 10
    assert payload["submission_count"] == 26
    assert payload["decision_counts"] == {
        "insufficient_data": 1,
        "normal_candidate": 20,
        "risk": 5,
    }
    mine_names = {scenario["mine_name"] for scenario in payload["scenarios"]}
    assert {"太岳矿", "梗阳矿"} <= mine_names
    assert (state / "mineguard.db").is_file()

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
    resume_output = capsys.readouterr().out
    assert resume_output.isascii()
    resumed = json.loads(resume_output)
    assert resumed["status"] == "already_seeded"
    assert resumed["created_submission_count"] == 0
    assert resumed["replayed_submission_count"] == 26
    resumed_names = {
        scenario["mine_name"] for scenario in resumed["scenarios"]
    }
    assert {"太岳矿", "梗阳矿"} <= resumed_names


def test_v2_backup_verify_and_restore_round_trip(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    for name in ("mineguard.db", "auth.db"):
        with sqlite3.connect(state / name) as connection:
            connection.execute("CREATE TABLE sample(value TEXT)")
            connection.execute("INSERT INTO sample VALUES ('kept')")

    assert (
        product_cli.main(
            ["backup", "snapshot-001", "--state-directory", str(state)]
        )
        == 0
    )
    assert (
        product_cli.main(
            ["verify-backup", "snapshot-001", "--state-directory", str(state)]
        )
        == 0
    )

    restored = tmp_path / "restored"
    assert (
        product_cli.main(
            [
                "restore-backup",
                "snapshot-001",
                "--state-directory",
                str(restored),
                "--backup-directory",
                str(state / "backups"),
                "--key-file",
                str(state / "backup.key"),
            ]
        )
        == 0
    )
    with sqlite3.connect(restored / "mineguard.db") as connection:
        assert connection.execute("SELECT value FROM sample").fetchone() == ("kept",)
    assert (restored / "backup.key").is_file()
