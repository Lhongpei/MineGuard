from __future__ import annotations

import io
import json
from pathlib import Path
import re
import sqlite3
from typing import Any
import zipfile

import pytest

from mineguard import cli
from mineguard.api import create_server
from mineguard.auth import LocalAuthStore
from mineguard.evidence import EvidenceBundleService
from mineguard.source_keys import SourceKeyStore


def _initialise_complete_state(state: Path) -> None:
    layout = cli._state_layout(state)
    server = create_server(
        "127.0.0.1",
        0,
        database_path=layout.database,
        auth_required=True,
        auth_database_path=layout.auth_database,
        bootstrap_admin=("existing-admin", "existing-password"),
        job_database_path=layout.job_database,
        evidence_database_path=layout.evidence_database,
        evidence_directory=layout.evidence_directory,
        governance_database_path=layout.governance_database,
        source_key_directory=layout.source_key_directory,
    )
    server.server_close()


def _sqlite_is_valid(path: Path) -> bool:
    connection = sqlite3.connect(path)
    try:
        return connection.execute("PRAGMA integrity_check").fetchone() == (
            "ok",
        )
    finally:
        connection.close()


def test_serve_creates_and_displays_generated_admin_only_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def fake_serve(*args: Any, **kwargs: Any) -> None:
        calls.append((args, kwargs))

    monkeypatch.setattr(cli, "serve", fake_serve)
    monkeypatch.delenv("MINEGUARD_ADMIN_PASSWORD", raising=False)

    assert (
        cli.main(
            [
                "serve",
                "--state-directory",
                str(state),
                "--port",
                "0",
                "--secure-cookie",
            ]
        )
        == 0
    )
    first_stderr = capsys.readouterr().err
    match = re.search(
        r"一次性显示的管理员密码: (?P<password>\S+)",
        first_stderr,
    )
    assert match is not None
    generated_password = match.group("password")
    assert first_stderr.count(generated_password) == 1
    assert "只显示这一次" in first_stderr
    assert "必须外部保留" in first_stderr

    with LocalAuthStore(state / "auth.db") as auth:
        session = auth.login(
            "admin",
            generated_password,
            client_id="cli-test",
        )
        assert session.principal.username == "admin"
    assert generated_password.encode() not in (state / "auth.db").read_bytes()
    assert (state / "backup.key").stat().st_size >= 32

    assert cli.main(["serve", "--state-directory", str(state)]) == 0
    second_stderr = capsys.readouterr().err
    assert generated_password not in second_stderr
    assert "一次性显示的管理员密码" not in second_stderr

    assert len(calls) == 2
    _, first_kwargs = calls[0]
    assert first_kwargs["auth_required"] is True
    assert first_kwargs["secure_cookie"] is True
    assert first_kwargs["database_path"] == state.resolve() / "mineguard.db"
    assert first_kwargs["auth_database_path"] == state.resolve() / "auth.db"
    assert first_kwargs["source_key_directory"] == (
        state.resolve() / "source-keys"
    )


def test_serve_uses_environment_admin_password_without_echoing_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    password = "Unique-env-password-2026!"
    monkeypatch.setenv("MINEGUARD_ADMIN_PASSWORD", password)
    monkeypatch.setattr(cli, "serve", lambda *_args, **_kwargs: None)

    assert cli.main(["serve", "--state-directory", str(state)]) == 0
    stderr = capsys.readouterr().err
    assert password not in stderr
    assert "为避免泄露不回显" in stderr

    with LocalAuthStore(state / "auth.db") as auth:
        session = auth.login("admin", password, client_id="env-test")
        assert session.principal.username == "admin"


def test_serve_no_auth_preserves_legacy_database_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    legacy_database = tmp_path / "legacy.db"
    captured: dict[str, Any] = {}

    def fake_serve(*_args: Any, **kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(cli, "serve", fake_serve)
    assert (
        cli.main(
            [
                "serve",
                "--state-directory",
                str(state),
                "--database",
                str(legacy_database),
                "--no-auth",
            ]
        )
        == 0
    )

    assert captured["auth_required"] is False
    assert captured["database_path"] == legacy_database.resolve()
    assert not (state / "auth.db").exists()
    assert "身份认证已关闭" in capsys.readouterr().err


def test_backup_verify_restore_produces_directly_runnable_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_state = tmp_path / "source-state"
    _initialise_complete_state(source_state)
    source_keys = SourceKeyStore(source_state / "source-keys")
    try:
        original_evidence_key = source_keys.get_system(
            "evidence-signing-key"
        )
    finally:
        source_keys.close()
    assert original_evidence_key is not None

    assert (
        cli.main(
            [
                "backup",
                "nightly-001",
                "--state-directory",
                str(source_state),
            ]
        )
        == 0
    )
    backup_output = json.loads(capsys.readouterr().out)
    assert backup_output["status"] == "created"
    assert {
        record["filename"]
        for record in backup_output["backup"]["files"]
    } == {
        "mineguard.db",
        "auth.db",
        "jobs.db",
        "evidence.db",
        "governance.db",
        "source-keys.db",
    }
    assert "必须" in backup_output["key_retention_required"]

    assert (
        cli.main(
            [
                "verify-backup",
                "nightly-001",
                "--state-directory",
                str(source_state),
            ]
        )
        == 0
    )
    verification = json.loads(capsys.readouterr().out)
    assert verification["status"] == "valid"

    restored_state = tmp_path / "restored-state"
    assert (
        cli.main(
            [
                "restore-backup",
                "nightly-001",
                "--backup-directory",
                str(source_state / "backups"),
                "--key-file",
                str(source_state / "backup.key"),
                "--state-directory",
                str(restored_state),
            ]
        )
        == 0
    )
    restored_output = json.loads(capsys.readouterr().out)
    assert restored_output["status"] == "restored"
    restored_layout = cli._state_layout(restored_state)
    assert all(
        _sqlite_is_valid(path)
        for path in cli._state_databases(restored_layout).values()
    )
    assert not (restored_state / "source-keys.db").exists()
    assert restored_layout.evidence_directory.is_dir()
    assert restored_layout.backup_directory.is_dir()
    assert (
        restored_layout.backup_key.read_bytes()
        == (source_state / "backup.key").read_bytes()
    )
    source_keys = SourceKeyStore(restored_layout.source_key_directory)
    try:
        assert (
            source_keys.get_system("evidence-signing-key")
            == original_evidence_key
        )
    finally:
        source_keys.close()

    # The restored databases open without another bootstrap credential.
    server = create_server(
        "127.0.0.1",
        0,
        database_path=restored_layout.database,
        auth_required=True,
        auth_database_path=restored_layout.auth_database,
        job_database_path=restored_layout.job_database,
        evidence_database_path=restored_layout.evidence_database,
        evidence_directory=restored_layout.evidence_directory,
        governance_database_path=restored_layout.governance_database,
        source_key_directory=restored_layout.source_key_directory,
    )
    server.server_close()


def test_verify_rejects_tampered_backup_and_never_creates_missing_key(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _initialise_complete_state(state)
    assert (
        cli.main(
            ["backup", "signed", "--state-directory", str(state)]
        )
        == 0
    )
    capsys.readouterr()

    (state / "backups" / "signed" / "jobs.db").write_bytes(b"tampered")
    assert (
        cli.main(
            ["verify-backup", "signed", "--state-directory", str(state)]
        )
        == 1
    )
    error = json.loads(capsys.readouterr().err)
    assert error["error"]["code"] == "operation_error"

    missing_key = tmp_path / "missing.key"
    assert (
        cli.main(
            [
                "verify-backup",
                "signed",
                "--state-directory",
                str(state),
                "--key-file",
                str(missing_key),
            ]
        )
        == 2
    )
    assert not missing_key.exists()


def test_restore_refuses_to_overwrite_existing_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _initialise_complete_state(state)
    assert (
        cli.main(["backup", "safe", "--state-directory", str(state)]) == 0
    )
    capsys.readouterr()
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    marker = occupied / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    assert (
        cli.main(
            [
                "restore-backup",
                "safe",
                "--backup-directory",
                str(state / "backups"),
                "--key-file",
                str(state / "backup.key"),
                "--state-directory",
                str(occupied),
            ]
        )
        == 1
    )
    assert marker.read_text(encoding="utf-8") == "keep"


def test_production_and_demo_commands_remain_compatible(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["production", json.dumps(cli._DEMO_PRODUCTION)]) == 0
    production = json.loads(capsys.readouterr().out)
    assert production["mine_id"] == "M001"

    assert cli.main(["demo"]) == 0
    demo = json.loads(capsys.readouterr().out)
    assert set(demo) == {"production", "personnel"}


def test_global_version_flag_reports_application_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["--version"])

    assert raised.value.code == 0
    assert capsys.readouterr().out == f"mineguard {cli.__version__}\n"


@pytest.mark.parametrize(
    "command",
    ["production", "flow", "aggregate", "temporal", "personnel"],
)
def test_json_command_help_explains_all_input_forms(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main([command, "--help"])

    assert raised.value.code == 0
    help_text = capsys.readouterr().out
    assert "内联 JSON 文本" in help_text
    assert "@文件路径" in help_text
    assert "标准输入" in help_text


def test_flow_command_parses_time_expanded_examples(
    capsys: pytest.CaptureFixture[str],
) -> None:
    examples = Path(__file__).resolve().parents[1] / "examples"

    assert cli.main(["flow", str(examples / "flow_normal.json")]) == 0
    normal = json.loads(capsys.readouterr().out)
    assert normal["status"] == "optimal"
    assert normal["objective_value"] == pytest.approx(0.0)
    assert normal["minimum_repairs"] == []
    assert [
        point["value"] for point in normal["inventory_trajectory"]
    ] == pytest.approx([0.0, 60.0, 40.0, 0.0, 0.0])
    delayed = next(
        edge
        for edge in normal["edge_windows"]
        if edge["edge_id"] == "stock-to-buyer"
        and edge["window_id"] == "2026-07-20"
    )
    assert delayed["arrived_value"] == pytest.approx(0.0)
    assert (
        delayed["allocations"][0]["arrival_window_id"] == "2026-07-21"
    )

    assert (
        cli.main(["flow", f"@{examples / 'flow_anomalous.json'}"]) == 0
    )
    anomalous = json.loads(capsys.readouterr().out)
    assert anomalous["status"] == "optimal"
    repair = anomalous["minimum_repairs"][0]
    assert repair["kind"] == "observation_adjustment"
    assert repair["target_id"] == "dispatch-sales-21"
    assert repair["amount"] == pytest.approx(-70.0)
    adjustment = next(
        item
        for item in anomalous["observation_adjustments"]
        if item["observation_id"] == "dispatch-sales-21"
    )
    assert adjustment["observed_value"] == pytest.approx(170.0)
    assert adjustment["coordinated_value"] == pytest.approx(100.0)
    assert adjustment["normalized_residual"] < -6.9


def test_aggregate_and_temporal_commands_are_directly_runnable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    aggregation_request = {
        "measurement_type": "interval_delta",
        "window_start": "2026-07-20T00:00:00Z",
        "window_end": "2026-07-21T00:00:00Z",
        "observations": [
            {
                "observation_id": "first",
                "value": 40.0,
                "observed_at": "2026-07-20T12:00:00Z",
                "interval_start": "2026-07-20T00:00:00Z",
                "interval_end": "2026-07-20T12:00:00Z",
            },
            {
                "observation_id": "second",
                "value": 60.0,
                "observed_at": "2026-07-21T00:00:00Z",
                "interval_start": "2026-07-20T12:00:00Z",
                "interval_end": "2026-07-21T00:00:00Z",
            },
        ],
        "expected_interval_seconds": 43200.0,
    }
    assert cli.main(["aggregate", json.dumps(aggregation_request)]) == 0
    aggregation = json.loads(capsys.readouterr().out)
    assert aggregation["status"] == "sufficient"
    assert aggregation["aggregate_value"] == pytest.approx(100.0)

    temporal_request = {
        "observations": [
            {
                "mine_id": "M001",
                "source_id": "belt",
                "metric_code": "source.residual",
                "timestamp": (
                    f"2026-07-20T{index:02d}:00:00Z"
                ),
                "signed_residual": value,
            }
            for index, value in enumerate(
                [10.0, 10.2, 9.8, 10.1, 9.9, 25.0]
            )
        ],
        "parameters": {
            "baseline_window": 20,
            "min_history": 5,
        },
    }
    assert cli.main(["temporal", json.dumps(temporal_request)]) == 0
    temporal = json.loads(capsys.readouterr().out)
    assert temporal["series_count"] == 1
    assert temporal["series"][0]["status"] == "anomalous"
    assert temporal["series"][0]["episodes"]


def test_verify_evidence_works_offline_and_detects_tampering(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    layout = cli._state_layout(state)
    key_store = SourceKeyStore(layout.source_key_directory)
    secret = b"offline-evidence-verification-key!!"
    key_store.put_system("evidence-signing-key", secret)
    key_store.close()
    service = EvidenceBundleService(
        lambda key_id: (
            secret if key_id == "local-evidence-key" else None
        ),
        signing_key_id="local-evidence-key",
    )
    bundle, _ = service.build(
        case={
            "case_id": "case-offline",
            "version": 1,
            "mine_id": "M001",
            "workflow_status": "closed",
        },
        events=[{"sequence": 1, "action": "created"}],
        run=None,
        engine_version="0.3.0",
        generated_at="2026-07-26T00:00:00Z",
    )
    bundle_path = tmp_path / "evidence.zip"
    bundle_path.write_bytes(bundle)

    assert (
        cli.main(
            [
                "verify-evidence",
                str(bundle_path),
                "--state-directory",
                str(state),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "valid"

    source = zipfile.ZipFile(io.BytesIO(bundle), "r")
    tampered = io.BytesIO()
    with source, zipfile.ZipFile(tampered, "w") as target:
        for entry in source.infolist():
            content = source.read(entry)
            if entry.filename == "case.json":
                content = b'{"tampered":true}'
            target.writestr(entry.filename, content)
    bundle_path.write_bytes(tampered.getvalue())
    assert (
        cli.main(
            [
                "verify-evidence",
                str(bundle_path),
                "--state-directory",
                str(state),
            ]
        )
        == 1
    )
    assert json.loads(capsys.readouterr().out)["status"] == "invalid"
