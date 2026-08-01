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
    }
    source = inspect.getsource(product_cli)
    assert "from .api" not in source
    assert "from .edge_store" not in source
    with pytest.raises(SystemExit):
        parser.parse_args(["production", "{}"])


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
    assert payload["mine_count"] == 8
    assert payload["submission_count"] == 24
    assert payload["decision_counts"] == {
        "insufficient_data": 1,
        "normal_candidate": 19,
        "risk": 4,
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
