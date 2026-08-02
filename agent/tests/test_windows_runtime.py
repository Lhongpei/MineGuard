from __future__ import annotations

import json
from pathlib import Path

import pytest

from enterprise_agent.cli import _configuration_errors, main
from enterprise_agent.environment import (
    load_environment_file,
    parse_environment_file,
)
from enterprise_agent.instance_lock import lock_for_database
from enterprise_agent.maintenance import backup_database, restore_database
from enterprise_agent.settings import Settings, split_path_list
from enterprise_agent.storage import Repository


def test_strict_environment_file_supports_bom_unicode_and_process_precedence(
    tmp_path: Path,
) -> None:
    config = tmp_path / "agent.env"
    config.write_bytes(
        (
            "\ufeff# comment\r\nENTERPRISE_MINE_NAME=示例煤矿\r\n"
            'ENTERPRISE_AGENT_USERS_JSON=\'[{"name":"张三"}]\'\r\n'
            "EMPTY=\r\n"
        ).encode()
    )
    parsed = parse_environment_file(config)
    assert parsed == {
        "ENTERPRISE_MINE_NAME": "示例煤矿",
        "ENTERPRISE_AGENT_USERS_JSON": '[{"name":"张三"}]',
        "EMPTY": "",
    }

    environment = {"ENTERPRISE_MINE_NAME": "inherited"}
    loaded = load_environment_file(config, environment=environment)
    assert "ENTERPRISE_MINE_NAME" not in loaded
    assert environment["ENTERPRISE_MINE_NAME"] == "inherited"
    assert environment["EMPTY"] == ""


def test_environment_file_rejects_relative_link_duplicate_and_oversize(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="绝对路径"):
        parse_environment_file("relative.env")

    duplicate = tmp_path / "duplicate.env"
    duplicate.write_text("A=1\nA=2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="重复定义"):
        parse_environment_file(duplicate)

    oversized = tmp_path / "oversized.env"
    oversized.write_bytes(b"A=" + (b"x" * (1024 * 1024)))
    with pytest.raises(ValueError, match="1 MiB"):
        parse_environment_file(oversized)

    target = tmp_path / "target.env"
    target.write_text("A=1\n", encoding="utf-8")
    link = tmp_path / "link.env"
    try:
        link.symlink_to(target)
    except OSError:
        return
    with pytest.raises(ValueError, match="链接|重解析点"):
        parse_environment_file(link)


def test_windows_semicolon_watch_path_list_keeps_drive_colons() -> None:
    assert split_path_list(
        r"C:\MineGuard\Inbox;D:\煤矿 数据\收件箱",
        separator=";",
    ) == (r"C:\MineGuard\Inbox", r"D:\煤矿 数据\收件箱")


def test_production_config_rejects_loopback_http_platform(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", str(tmp_path / "agent.db"))
    monkeypatch.setenv("PLATFORM_V2_BASE_URL", "http://127.0.0.1:8080")
    monkeypatch.setenv("PLATFORM_V2_SENDER_ID", "agent-demo-mine-001")
    monkeypatch.setenv(
        "ENTERPRISE_EXCHANGE_HMAC_SECRET",
        "application-secret-at-least-thirty-two-bytes",
    )
    monkeypatch.setenv(
        "PLATFORM_V2_TRANSPORT_HMAC_SECRET",
        "different-transport-secret-at-least-32-bytes",
    )
    errors = _configuration_errors(Settings.from_environment(), production=True)
    assert "正式服务连接政府 V2 平台必须使用 HTTPS" in errors


def test_windows_deployment_assets_keep_secrets_out_of_service_xml() -> None:
    root = Path(__file__).resolve().parents[1] / "deploy" / "windows"
    expected = {
        "Install-EnterpriseAgent.ps1",
        "New-EnterpriseAgentInstance.ps1",
        "Start-EnterpriseAgent.ps1",
        "Test-EnterpriseAgentHealth.ps1",
        "Install-EnterpriseAgentService.ps1",
        "Uninstall-EnterpriseAgentService.ps1",
        "Backup-EnterpriseAgent.ps1",
        "Restore-EnterpriseAgent.ps1",
    }
    assert expected.issubset({path.name for path in root.glob("*.ps1")})
    for script in root.glob("*.ps1"):
        encoded = script.read_bytes()
        assert encoded.startswith(b"\xef\xbb\xbf") or encoded.isascii()
        lowered = encoded.lower()
        assert b"invoke-expression" not in lowered
        assert b"downloadfile" not in lowered
    service_xml = (root / "enterprise-agent-service.xml.template").read_text(
        encoding="utf-8"
    )
    assert "__ENV_FILE__" in service_xml
    assert "HMAC_SECRET" not in service_xml
    assert "DEEPSEEK_API_KEY" not in service_xml
    installer = (root / "Install-EnterpriseAgentService.ps1").read_text(
        encoding="utf-8"
    )
    assert "WinSWExpectedSha256" in installer
    assert '"--production"' in installer
    backup = (root / "Backup-EnterpriseAgent.ps1").read_text(encoding="utf-8")
    assert '"five-quantity-quarantine"' in backup
    assert '"snapshot.json"' in backup


def test_database_backup_restore_manifest_rollback_and_instance_lock(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state" / "enterprise-agent.db"
    repository = Repository(database)
    original = repository.create_draft(
        {"draft_id": "draft-backup-001", "mine_name": "备份煤矿"},
        actor="tester",
    )

    backup = tmp_path / "backup" / "enterprise-agent.db"
    result = backup_database(database, backup)
    assert result["format"] == "enterprise-agent-sqlite-backup-v1"
    manifest_path = Path(result["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["database_file"] == backup.name
    assert len(manifest["sha256"]) == 64

    repository.create_draft(
        {"draft_id": "draft-later-002", "mine_name": "later"},
        actor="tester",
    )
    restored = restore_database(
        database,
        backup,
        rollback_directory=tmp_path / "rollback",
    )
    assert restored["rollback_backup"] is not None
    drafts = Repository(database).list_drafts(limit=20)
    assert len(drafts) == 1
    assert drafts[0]["draft_id"] == original["draft_id"]

    with (
        lock_for_database(database),
        pytest.raises(ValueError, match="已有企业 Agent"),
        lock_for_database(database),
    ):
        pass


def test_cli_restore_refuses_when_service_lock_is_held(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "state.db"
    Repository(database)
    backup = tmp_path / "backup.db"
    backup_database(database, backup)

    with lock_for_database(database):
        result = main(
            [
                "--db",
                str(database),
                "database-restore",
                "--input",
                str(backup),
                "--rollback-directory",
                str(tmp_path / "rollback"),
                "--yes-service-stopped",
            ]
        )
    assert result == 1
    assert "必须先停止服务" in capsys.readouterr().err


def test_restore_preserves_corrupt_current_database_as_raw_evidence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state.db"
    Repository(database)
    backup = tmp_path / "backup.db"
    backup_database(database, backup)
    database.write_bytes(b"corrupt live database")

    restored = restore_database(
        database,
        backup,
        rollback_directory=tmp_path / "rollback",
    )
    assert restored["rollback_mode"] == "unverified_raw_corrupt_database"
    raw = Path(str(restored["rollback_backup"]))
    assert raw.read_bytes() == b"corrupt live database"
    assert Path(f"{raw}.notice.txt").is_file()
    Repository(database)
