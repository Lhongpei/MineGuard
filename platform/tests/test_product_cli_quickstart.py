from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from mineguard import product_cli
from mineguard.auth import LocalAuthStore


ADMIN_PASSWORD = "formal admin password"
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
                        "message_secret": MESSAGE_SECRET,
                        "transport_secret": TRANSPORT_SECRET,
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
    assert os.environ["MINEGUARD_ADMIN_PASSWORD"] == "unrelated secret"


def test_setup_wizard_keeps_secrets_out_of_settings_and_start_command(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "formal-state"
    clients_file = _clients_file(tmp_path)
    answers = iter([f'"{clients_file}"', "n", "formal-admin"])
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
        "secure_cookie": False,
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
            ]
        )
        == 2
    )
    error = json.loads(capsys.readouterr().out)
    assert "演示数据目录不能转为正式" in error["error"]["message"]
