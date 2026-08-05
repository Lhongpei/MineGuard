from __future__ import annotations

import inspect
import json
from pathlib import Path
import sqlite3

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
        "seed-v2-demo",
        "backup",
        "verify-backup",
        "restore-backup",
        "config-check",
        "self-check",
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
        auth.bootstrap_admin("admin", "admin password")

    assert (
        product_cli.main(
            ["config-check", "--auth-database", str(auth_database)]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result == {"status": "ok", "auth_user_count": 1}

    assert product_cli.main(["config-check"]) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["error"]["code"] == "operation_failed"


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

    monkeypatch.delenv("MINEGUARD_NEW_USER_PASSWORD")
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
    payload = json.loads(capsys.readouterr().out)
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
    assert (state / "mineguard.db").is_file()


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
