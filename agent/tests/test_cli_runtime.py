from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from conftest import complete_values, ensure_event_snapshot

from enterprise_agent.cli import main
from enterprise_agent.model_credentials import model_credential_state_path
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_model_rotation_accepts_sanitized_authoritative_environment(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    """Windows removes old model pointers before validating a replacement."""

    pair_id = str(uuid4())
    settings = SimpleNamespace(
        production_mode=False,
        provisioning_status=SimpleNamespace(managed=True, pair_id=pair_id),
        five_quantity_identity=SimpleNamespace(
            mine_id="MINE-QY-001",
            system_id="agent-mine-qy-001",
            operator_id="operator-qy-001",
        ),
        # A sanitized import environment intentionally reports no active
        # runtime credential even though predecessor files remain on disk.
        model_credential_status=SimpleNamespace(managed=False),
    )
    monkeypatch.setattr(
        "enterprise_agent.cli.Settings.from_environment", lambda: settings
    )
    captured: dict[str, object] = {}

    def fake_install(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            summary={
                "managed": True,
                "mine_id": "MINE-QY-001",
                "system_id": "agent-mine-qy-001",
                "credential_version": 2,
            }
        )

    monkeypatch.setattr(
        "enterprise_agent.cli.install_model_credential_bundle", fake_install
    )
    bundle = tmp_path / "rotation.mgllm"
    bundle.write_text("{}\n", encoding="utf-8")
    activation = tmp_path / "rotation.activation"
    activation.write_text("A" * 43 + "\n", encoding="ascii")
    if os.name != "nt":
        activation.chmod(0o600)
    trust = tmp_path / "trust.json"
    trust.write_text("{}\n", encoding="utf-8")
    final_lock = tmp_path / "model-credential-lock.json"
    final_lock.write_text("old-lock\n", encoding="utf-8")
    model_credential_state_path(final_lock).write_text(
        "old-state\n", encoding="utf-8"
    )
    final_store = tmp_path / "model-credentials.dpapi"
    final_store.write_text("old-store\n", encoding="utf-8")

    assert (
        main(
            [
                "model-credential-import",
                "--bundle",
                str(bundle),
                "--activation-code-file",
                str(activation),
                "--trust-store",
                str(trust),
                "--lock-output",
                str(tmp_path / "new-lock.json"),
                "--lock-env-path",
                str(final_lock),
                "--secret-store",
                str(tmp_path / "new-store.dpapi"),
                "--secret-store-env-path",
                str(final_store),
                "--current-lock",
                str(final_lock),
            ]
        )
        == 0
    )
    assert captured["current_lock_path"] == final_lock
    assert captured["expected_subject"] == {
        "mine_id": "MINE-QY-001",
        "system_id": "agent-mine-qy-001",
        "party_id": "operator-qy-001",
        "pair_id": pair_id,
    }
    assert json.loads(capsys.readouterr().out)["credential_version"] == 2


def test_model_rotation_accepts_new_versioned_linux_final_paths(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    pair_id = str(uuid4())
    settings = SimpleNamespace(
        production_mode=False,
        provisioning_status=SimpleNamespace(managed=True, pair_id=pair_id),
        five_quantity_identity=SimpleNamespace(
            mine_id="MINE-QY-001",
            system_id="agent-mine-qy-001",
            operator_id="operator-qy-001",
        ),
        model_credential_status=SimpleNamespace(managed=False),
    )
    monkeypatch.setattr(
        "enterprise_agent.cli.Settings.from_environment", lambda: settings
    )
    captured: dict[str, object] = {}

    def fake_install(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            summary={
                "managed": True,
                "mine_id": "MINE-QY-001",
                "system_id": "agent-mine-qy-001",
                "credential_version": 2,
            }
        )

    monkeypatch.setattr(
        "enterprise_agent.cli.install_model_credential_bundle", fake_install
    )
    bundle = tmp_path / "rotation-v2.mgllm"
    bundle.write_text("{}\n", encoding="utf-8")
    activation = tmp_path / "rotation-v2.activation"
    activation.write_text("A" * 43 + "\n", encoding="ascii")
    if os.name != "nt":
        activation.chmod(0o600)
    trust = tmp_path / "trust.json"
    trust.write_text("{}\n", encoding="utf-8")
    current_lock = tmp_path / "model-credential-v1.lock.json"
    current_lock.write_text("old-lock\n", encoding="utf-8")
    current_store = tmp_path / "model-credential-v1.secret.json"
    current_store.write_text("old-store\n", encoding="utf-8")
    monkeypatch.setenv(
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE", str(current_lock)
    )
    monkeypatch.setenv(
        "MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE", str(current_store)
    )
    new_lock = tmp_path / "model-credential-v2.lock.json"
    new_store = tmp_path / "model-credential-v2.secret.json"

    assert (
        main(
            [
                "model-credential-import",
                "--bundle",
                str(bundle),
                "--activation-code-file",
                str(activation),
                "--trust-store",
                str(trust),
                "--lock-output",
                str(new_lock),
                "--lock-env-path",
                str(new_lock),
                "--secret-store",
                str(new_store),
                "--secret-store-env-path",
                str(new_store),
                "--current-lock",
                str(current_lock),
            ]
        )
        == 0
    )
    assert captured["current_lock_path"] == current_lock
    assert captured["lock_environment_path"] == new_lock
    assert os.environ["MINEGUARD_AGENT_MODEL_CREDENTIAL_LOCK_FILE"] == str(
        current_lock
    )
    assert os.environ["MINEGUARD_AGENT_MODEL_CREDENTIAL_SECRET_STORE"] == str(
        current_store
    )
    assert json.loads(capsys.readouterr().out)["credential_version"] == 2


def test_self_check_exercises_provisioning_crypto_without_loading_settings(
    monkeypatch,
    capsys,
) -> None:
    def fail_if_settings_are_loaded():
        raise AssertionError("self-check must not load instance settings")

    monkeypatch.setattr(
        "enterprise_agent.cli.Settings.from_environment",
        fail_if_settings_are_loaded,
    )

    assert main(["self-check"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "status": "ok",
        "provisioning_crypto": "ed25519+aes-256-gcm+scrypt",
    }


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_foreground_server_prints_actionable_banner_and_ctrl_c_is_clean(
    tmp_path: Path,
) -> None:
    port = _free_port()
    environment = {
        **os.environ,
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
        "ENTERPRISE_AGENT_DB": str(tmp_path / "runtime.db"),
    }
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "enterprise_agent",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            if process.poll() is not None:
                break
            time.sleep(0.05)
    assert process.poll() is None
    process.send_signal(signal.SIGINT)
    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0
    assert "企业可信数据填报智能体已启动" in stdout
    assert f"http://127.0.0.1:{port}/" in stdout
    assert "ssh -N -L" in stdout
    assert "按 Ctrl+C 可安全停止" in stdout
    assert str((tmp_path / "runtime.db").resolve()) in stdout
    assert "Traceback" not in stderr
    assert "KeyboardInterrupt" not in stderr


def test_port_conflict_and_corrupt_database_fail_without_traceback(
    tmp_path: Path,
    capsys,
) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = int(listener.getsockname()[1])
        result = main(
            [
                "--db",
                str(tmp_path / "port.db"),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ]
        )
    assert result == 1
    error = capsys.readouterr().err
    assert f"端口 {port} 已被占用" in error
    assert "Traceback" not in error

    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not a sqlite database")
    result = main(["--db", str(corrupt), "list"])
    assert result == 1
    error = capsys.readouterr().err
    assert "数据库" in error
    assert "完整性" in error
    assert "Traceback" not in error
    assert corrupt.read_bytes() == b"not a sqlite database"


def test_wheel_contains_single_frontend_source_as_installable_data(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(tmp_path),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    wheels = list(tmp_path.glob("enterprise_reporting_agent-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        for asset in ("index.html", "app.js", "styles.css"):
            matches = [
                name
                for name in names
                if name.endswith(
                    f"share/enterprise-reporting-agent/web/{asset}"
                )
            ]
            assert len(matches) == 1


def test_cli_review_explicit_all_unblocks_cli_confirmation(
    tmp_path: Path,
    capsys,
) -> None:
    database = tmp_path / "review.db"
    service = EnterpriseAgentService(Repository(database))
    draft = ensure_event_snapshot(
        service,
        service.create_draft(complete_values(), actor="operator-1"),
    )

    result = main(
        [
            "--db",
            str(database),
            "review",
            draft["draft_id"],
            "--actor",
            "operator-1",
            "--revision",
            str(draft["_meta"]["revision"]),
            "--all",
        ]
    )
    assert result == 0
    assert '"all_reviewed": true' in capsys.readouterr().out

    result = main(
        [
            "--db",
            str(database),
            "confirm",
            draft["draft_id"],
            "--actor",
            "operator-1",
            "--name",
            "张三",
            "--role",
            "企业报送负责人",
            "--attestation",
            "本人已逐条核对全部来源观测和原始记录。",
            "--yes-i-confirm",
            "--revision",
            str(draft["_meta"]["revision"]),
        ]
    )
    assert result == 0
    assert '"confirmed": true' in capsys.readouterr().out
