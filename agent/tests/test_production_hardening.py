from __future__ import annotations

import sqlite3
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest

from enterprise_agent.auth import (
    UserAccount,
    hash_password,
    parse_users_json,
    production_credential_errors,
    validate_production_password,
)
from enterprise_agent.cli import _configuration_errors, main
from enterprise_agent.errors import ConflictError, ValidationBlockedError
from enterprise_agent.five_quantity_exchange import (
    EnterpriseSigningVerificationKey,
    FiveQuantityPlatformConfig,
    MineIdentity,
)
from enterprise_agent.five_quantity_runtime import FiveQuantityRuntime
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.settings import Settings
from enterprise_agent.storage import Repository


def _account(
    actor_id: str,
    name: str,
    permissions: frozenset[str],
    *,
    password: str,
) -> UserAccount:
    return UserAccount(
        actor_id=actor_id,
        name=name,
        role="经办人" if "write" in permissions else "复核负责人",
        password_hash=hash_password(
            password,
            salt=(actor_id.encode("utf-8") + b"0123456789abcdef")[:18],
        ),
        permissions=permissions,
        credential_provenance="production_hash_command",
    )


def _identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-PROD-001",
        mine_name="正式化测试煤矿",
        operator_id="operator-prod-001",
        operator_name="正式化测试煤业有限公司",
        system_id="agent-prod-001",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-prod-key",
        regulator_key_id="regulator-prod-key",
        message_hmac_secret="message-secret-for-production-tests-123456789",
        capacity_band="medium",
        mining_method="underground",
        shift_system="three-shift-eight-hour",
        coal_type="bituminous",
        operating_regime="normal-production",
    )


def _csv() -> bytes:
    return (
        b"date,ventilation_m3_min,mine_entry_persons,electricity_kwh,"
        b"detonators_count,explosives_kg,production_t\n"
        b"2026-08-01,4800,320,96000,120,240,2600\n"
    )


def _mark_as_real_v1_fq_schema(db: sqlite3.Connection) -> None:
    """Remove objects that did not exist in v1 before changing its marker."""

    for trigger in (
        "fq_outbox_archive_no_update",
        "fq_outbox_archive_no_delete",
        "fq_draft_submission_archive_no_update",
        "fq_draft_submission_archive_no_delete",
    ):
        db.execute(f"DROP TRIGGER {trigger}")
    db.execute("DROP INDEX idx_fq_draft_predecessor_unique")
    db.execute(
        "UPDATE fq_schema_versions SET version=1 "
        "WHERE component='five_quantity_v2'"
    )


def test_production_password_and_json_output_are_safe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(ValueError, match="默认密码"):
        validate_production_password("123123123")
    with pytest.raises(ValueError, match="三类"):
        validate_production_password("alllowercasepassword")

    monkeypatch.setattr(
        "sys.stdin",
        StringIO("MineGuard!Generated2026\n"),
    )
    assert main(
        ["hash-password", "--password-stdin", "--production", "--json"]
    ) == 0
    output = capsys.readouterr().out
    assert '"password_hash"' in output
    assert '"credential_provenance": "production_hash_command"' in output
    assert "MineGuard!Generated2026" not in output


def test_formal_account_requires_provenance_and_rejects_demo_hash() -> None:
    encoded = hash_password("123123123", salt=b"0123456789abcdef")
    account = parse_users_json(
        "[{"
        '"actor_id":"operator-1","name":"张三","role":"经办人",'
        f'"password_hash":"{encoded}",'
        '"permissions":["read","write"]'
        "}]"
    )[0]
    defects = production_credential_errors(account)
    assert any("credential_provenance" in item for item in defects)
    assert any("默认密码" in item for item in defects)


def test_production_config_requires_business_admin_and_api_admin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", str(tmp_path / "agent.db"))
    base = Settings.from_environment()
    all_powerful = _account(
        "admin-1",
        "张三",
        frozenset({"read", "write", "confirm", "submit"}),
        password="MineGuard!Admin2026",
    )
    unsafe = replace(
        base,
        production_mode=True,
        four_eyes_required=False,
        users=(all_powerful,),
    )
    errors = _configuration_errors(unsafe, production=True)
    assert any("必须且只能配置业务管理员和 api_admin" in item for item in errors)
    assert any("固定且独立的 api_admin" in item for item in errors)

    business_admin = _account(
        "admin-1",
        "张三",
        frozenset({"read", "write", "confirm", "submit"}),
        password="MineGuard!Business2026",
    )
    api_admin = _account(
        "api_admin",
        "API 配置管理员",
        frozenset({"model_api_admin"}),
        password="MineGuard!ApiAdmin2026",
    )
    separated = replace(unsafe, users=(business_admin, api_admin))
    separated_errors = _configuration_errors(separated, production=True)
    assert not any("api_admin" in item for item in separated_errors)
    assert not any("业务管理员" in item for item in separated_errors)
    assert not any("凭据不合格" in item for item in separated_errors)


def test_legacy_four_eyes_rejects_last_editor_before_confirmation() -> None:
    service = EnterpriseAgentService(
        Repository(":memory:"),
        four_eyes_required=True,
    )
    draft = service.create_draft(actor="preparer-1")
    assert draft["draft_id"]
    visible = service.get_draft(draft["draft_id"])
    assert visible["_meta"]["four_eyes"]["state"] == (
        "awaiting_independent_reviewer"
    )
    with pytest.raises(ValidationBlockedError, match="四眼复核"):
        service.confirm(
            draft["draft_id"],
            actor="preparer-1",
            confirmer_name="张三",
            confirmer_role="经办人",
            accepted=True,
            attestation="本人已经逐项核对来源材料并确认。",
            expected_revision=draft["_meta"]["revision"],
        )


def test_v2_four_eyes_blocks_creator_and_allows_independent_reviewer(
    tmp_path: Path,
) -> None:
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "agent.db"),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine",
        four_eyes_required=True,
        human_preparer_actor_ids=frozenset({"preparer-1"}),
    )
    draft = runtime.ingest_bytes(
        filename="august.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="preparer-1",
    )["draft"]
    assert draft["review_gate"]["state"] == "awaiting_independent_reviewer"
    with pytest.raises(ValidationBlockedError, match="四眼复核"):
        runtime.confirm_draft(
            draft["draft_id"],
            expected_revision=draft["revision"],
            actor_id="preparer-1",
            confirmer_name="张三",
            confirmer_role="经办人",
            attestation="本人已逐项核对日报及原始记录。",
            accepted=True,
        )
    confirmed = runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="reviewer-1",
        confirmer_name="李四",
        confirmer_role="复核负责人",
        attestation="本人已独立逐项核对日报及原始记录。",
        accepted=True,
    )
    assert confirmed["status"] == "queued"


def test_v2_frontend_explains_four_eyes_before_button_click() -> None:
    script = (
        Path(__file__).resolve().parents[1] / "web" / "v2-app.js"
    ).read_text(encoding="utf-8")
    assert "review_gate" in script
    assert "待另一账号接手" in script
    assert "你是本修订版最后创建/编辑人" in script
    assert "currentIsLastEditor" in script


def test_existing_single_person_unsent_queue_is_reopened_on_upgrade(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-queue.db"
    original = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    draft = original.ingest_bytes(
        filename="legacy.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="operator-legacy",
    )["draft"]
    original.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="operator-legacy",
        confirmer_name="历史经办人",
        confirmer_role="历史管理员",
        attestation="旧版本中本人已经核对并形成尚未发送队列。",
        accepted=True,
    )
    with sqlite3.connect(database) as db:
        _mark_as_real_v1_fq_schema(db)

    hardened = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine",
        four_eyes_required=True,
        human_preparer_actor_ids=frozenset({"operator-legacy"}),
    )
    reopened = hardened.store.get_draft(draft["draft_id"])
    assert reopened["status"] == "ready_review"
    assert reopened["confirmation"] is None
    assert hardened.store.due_outbox() == []
    assert any(
        item["event_type"]
        == "five_quantity_legacy_queue_reopened_for_four_eyes"
        for item in hardened.store.audit()["events"]
    )
    first_event_count = hardened.store.verify_audit()["event_count"]
    restarted = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine",
        four_eyes_required=True,
        human_preparer_actor_ids=frozenset({"operator-legacy"}),
    )
    assert restarted.store.verify_audit()["event_count"] == first_event_count


def test_legacy_connector_draft_with_different_reviewer_is_reopened(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-connector-queue.db"
    original = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine-original",
    )
    draft = original.ingest_bytes(
        filename="connector.csv",
        content=_csv(),
        acquisition_mode="direct_collection",
        actor="connector-client-1",
    )["draft"]
    queued = original.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="reviewer-1",
        confirmer_name="李四",
        confirmer_role="复核负责人",
        attestation="旧版本中已核对连接器自动草稿。",
        accepted=True,
    )
    assert queued["status"] == "queued"
    assert queued["last_content_actor"] == "connector-client-1"
    assert queued["human_preparer_actor"] is None
    with sqlite3.connect(database) as db:
        _mark_as_real_v1_fq_schema(db)

    hardened = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine-hardened",
        four_eyes_required=True,
        human_preparer_actor_ids=frozenset({"preparer-1"}),
    )
    reopened = hardened.store.get_draft(draft["draft_id"])
    assert reopened["status"] == "ready_review"
    assert reopened["confirmation"] is None
    assert reopened["submission_message_id"] is None
    with hardened.store.repository._read() as db:
        cancelled = db.execute(
            "SELECT status,last_error FROM fq_outbox WHERE aggregate_id=?",
            (draft["draft_id"],),
        ).fetchone()
    assert cancelled["status"] == "cancelled"
    assert cancelled["last_error"] == (
        "submission_human_preparer_missing_or_unconfigured"
    )
    migration_events = [
        event
        for event in hardened.store.audit()["events"]
        if event["event_type"]
        == "five_quantity_legacy_queue_reopened_for_four_eyes"
    ]
    assert len(migration_events) == 1
    assert migration_events[0]["details"]["reason"] == (
        "submission_human_preparer_missing_or_unconfigured"
    )
    restarted = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine-restarted",
        four_eyes_required=True,
        human_preparer_actor_ids=frozenset({"preparer-1"}),
    )
    assert len(
        [
            event
            for event in restarted.store.audit()["events"]
            if event["event_type"]
            == "five_quantity_legacy_queue_reopened_for_four_eyes"
        ]
    ) == 1


def test_outbox_rechecks_persisted_human_preparer_before_network_send(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RecordingPlatform:
        def __init__(self) -> None:
            self.submit_calls = 0

        def submit(self, _message: dict[str, object]) -> dict[str, object]:
            self.submit_calls += 1
            raise AssertionError("invalid queue must not reach network")

    database = tmp_path / "send-gate.db"
    platform = RecordingPlatform()
    runtime = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        platform_client=platform,  # type: ignore[arg-type]
        quarantine_directory=tmp_path / "quarantine",
        four_eyes_required=True,
        human_preparer_actor_ids=frozenset({"preparer-1"}),
    )
    draft = runtime.ingest_bytes(
        filename="prepared.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="preparer-1",
    )["draft"]
    queued = runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="reviewer-1",
        confirmer_name="李四",
        confirmer_role="复核负责人",
        attestation="本人已独立核对经办人保存的当前修订版。",
        accepted=True,
    )
    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE fq_drafts SET human_preparer_actor=NULL WHERE draft_id=?",
            (draft["draft_id"],),
        )
    with pytest.raises(ConflictError, match="持久化四眼复核条件"):
        runtime.store.due_outbox()

    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE fq_drafts SET human_preparer_actor='preparer-1',"
            "human_prepared_revision=revision WHERE draft_id=?",
            (draft["draft_id"],),
        )
    claimed = runtime.store.due_outbox()
    assert len(claimed) == 1
    with sqlite3.connect(database) as db:
        db.execute(
            "UPDATE fq_drafts SET human_preparer_actor=NULL WHERE draft_id=?",
            (draft["draft_id"],),
        )
    monkeypatch.setattr(runtime.store, "due_outbox", lambda: claimed)
    delivered = runtime.process_outbox_once()
    assert delivered == [
        {"message_id": queued["submission_message_id"], "status": "failed"}
    ]
    assert platform.submit_calls == 0
    with runtime.store.repository._read() as db:
        outbox = db.execute(
            "SELECT status,last_error FROM fq_outbox WHERE message_id=?",
            (queued["submission_message_id"],),
        ).fetchone()
    assert outbox["status"] == "failed"
    assert "持久化四眼复核条件" in outbox["last_error"]


def test_five_quantity_full_audit_detects_tail_tampering_beyond_200(
    tmp_path: Path,
) -> None:
    database = tmp_path / "fq-audit.db"
    runtime = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    runtime.ingest_bytes(
        filename="audit.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="operator-1",
    )
    with runtime.store.repository._transaction() as db:
        for index in range(205):
            runtime.store._append_audit(
                db,
                "test_full_chain_event",
                "operator-1",
                {"index": index},
            )
    visible = runtime.store.audit(limit=200)
    assert visible["valid"] is True
    assert visible["event_count"] == 206
    assert visible["displayed_count"] == 200
    assert visible["truncated"] is True

    with sqlite3.connect(database) as db:
        db.execute("DROP TRIGGER fq_audit_no_delete")
        db.execute(
            "DELETE FROM fq_audit WHERE sequence=(SELECT MAX(sequence) FROM fq_audit)"
        )
        db.execute(
            "CREATE TRIGGER fq_audit_no_delete BEFORE DELETE ON fq_audit BEGIN "
            "SELECT RAISE(ABORT, 'fq_audit is append-only'); END"
        )
    integrity = runtime.store.verify_audit()
    assert integrity["valid"] is False
    assert integrity["failure"] == "audit_tail_or_anchor_mismatch"
    with pytest.raises(ConflictError, match="发送队列已停止"):
        runtime.store.due_outbox()
    with pytest.raises(ValueError, match="审计链或审计锚点"):
        FiveQuantityRuntime(
            Repository(database),
            identity=_identity(),
            quarantine_directory=tmp_path / "quarantine-restart",
        )


def test_generic_full_audit_and_production_readiness_detect_tail_tampering(
    tmp_path: Path,
) -> None:
    database = tmp_path / "generic-audit.db"
    repository = Repository(database)
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(actor="operator-1")
    with repository._transaction() as db:
        for index in range(205):
            repository._append_audit(
                db,
                draft_id=draft["draft_id"],
                event_type="test_full_chain_event",
                actor="operator-1",
                details={"index": index},
            )
    assert repository.verify_audit(draft["draft_id"])["event_count"] == 206

    with sqlite3.connect(database) as db:
        db.execute("DROP TRIGGER guard_draft_audit_delete_v4")
        db.execute(
            "DELETE FROM draft_audit WHERE draft_id=? AND sequence=("
            "SELECT MAX(sequence) FROM draft_audit WHERE draft_id=?)",
            (draft["draft_id"], draft["draft_id"]),
        )
        db.execute(
            "CREATE TRIGGER guard_draft_audit_delete_v4 "
            "BEFORE DELETE ON draft_audit BEGIN "
            "SELECT RAISE(ABORT, 'draft_audit rows are append-only'); END"
        )
    assert repository.verify_audit(draft["draft_id"])["valid"] is False
    hardened = EnterpriseAgentService(repository, production_mode=True)
    with pytest.raises(ValueError, match="审计完整性"):
        hardened.assert_production_integrity()
    with pytest.raises(ConflictError, match="审计链"):
        repository.replace_draft(
            draft["draft_id"],
            service.get_draft(draft["draft_id"]),
            actor="operator-1",
            event_type="draft_patched",
        )


def test_generic_audit_trigger_requires_exact_body_and_no_extras(
    tmp_path: Path,
) -> None:
    noop_database = tmp_path / "generic-noop-trigger.db"
    repository = Repository(noop_database)
    repository.close()
    with sqlite3.connect(noop_database) as db:
        db.execute("DROP TRIGGER guard_draft_audit_delete_v4")
        db.execute(
            "CREATE TRIGGER guard_draft_audit_delete_v4 "
            "BEFORE DELETE ON draft_audit BEGIN SELECT 1; END"
        )
    with pytest.raises(ValueError, match="触发器.*替换"):
        Repository(noop_database)

    extra_database = tmp_path / "generic-extra-trigger.db"
    repository = Repository(extra_database)
    with repository._transaction() as db:
        db.execute(
            "CREATE TRIGGER injected_draft_audit_side_effect "
            "AFTER INSERT ON draft_audit BEGIN SELECT 1; END"
        )
    assert repository.verify_all_draft_audits()["valid"] is False
    repository.close()
    with pytest.raises(ValueError, match="触发器.*替换|额外"):
        Repository(extra_database)


def test_five_quantity_audit_trigger_rejects_extra_side_effect_trigger(
    tmp_path: Path,
) -> None:
    database = tmp_path / "fq-extra-trigger.db"
    repository = Repository(database)
    runtime = FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=tmp_path / "fq-extra-quarantine",
    )
    with repository._transaction() as db:
        db.execute(
            "CREATE TRIGGER injected_fq_audit_side_effect "
            "AFTER INSERT ON fq_audit BEGIN SELECT 1; END"
        )
    integrity = runtime.store.verify_audit()
    assert integrity["valid"] is False
    assert integrity["failure"] == "audit_trigger_missing_or_replaced"
    repository.close()

    with pytest.raises(ValueError, match="五量审计保护触发器"):
        FiveQuantityRuntime(
            Repository(database),
            identity=_identity(),
            quarantine_directory=tmp_path / "fq-extra-restart",
        )


def test_production_repository_latches_external_connection_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "external-write-latch.db"
    repository = Repository(database)
    service = EnterpriseAgentService(repository, production_mode=True)
    with repository._transaction() as db:
        db.execute(
            "CREATE TABLE runtime_external_probe(value TEXT NOT NULL)"
        )
    service.assert_production_integrity()

    monkeypatch.setattr(
        repository,
        "verify_all_draft_audits",
        lambda: pytest.fail("runtime readiness must not rescan generic history"),
    )

    # Normal writes through the controlled repository connection remain valid.
    service.create_draft(actor="operator-1")
    assert service.list_drafts()[1] == 1

    with sqlite3.connect(database) as external:
        external.execute(
            "INSERT INTO runtime_external_probe(value) VALUES ('tampered')"
        )
    with pytest.raises(ConflictError, match="外部数据库写入|锁死"):
        service.integrity_status()
    # The fault is terminal for this process even if the external row is later
    # removed; a restart and complete verification are required.
    with sqlite3.connect(database) as external:
        external.execute("DELETE FROM runtime_external_probe")
    with pytest.raises(ConflictError, match="锁死"):
        service.list_drafts()


def test_production_integrity_health_uses_trusted_full_scan_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "constant-health-integrity.db"
    repository = Repository(database)
    runtime = FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=tmp_path / "constant-health-quarantine",
    )
    service = EnterpriseAgentService(
        repository,
        five_quantity_runtime=runtime,
        production_mode=True,
    )
    service.create_draft(actor="operator-1")
    runtime.ingest_bytes(
        filename="health-snapshot.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="operator-1",
    )

    generic_full_scan = repository.verify_all_draft_audits
    fq_full_scan = runtime.store.verify_audit
    calls = {"generic": 0, "five_quantity": 0}

    def counted_generic_scan() -> dict[str, object]:
        calls["generic"] += 1
        return generic_full_scan()

    def counted_fq_scan() -> dict[str, object]:
        calls["five_quantity"] += 1
        return fq_full_scan()

    monkeypatch.setattr(repository, "verify_all_draft_audits", counted_generic_scan)
    monkeypatch.setattr(runtime.store, "verify_audit", counted_fq_scan)

    service.assert_production_integrity()
    assert calls == {"generic": 1, "five_quantity": 1}

    first = service.integrity_status()
    second = service.integrity_status()
    assert calls == {"generic": 1, "five_quantity": 1}
    assert first["integrity_mode"] == "runtime_constant_boundary"
    assert first["runtime_boundary"]["valid"] is True
    assert first["full_scan_snapshot"]["counts_are_snapshot"] is True
    assert first["generic_drafts"]["event_count"] == 1
    assert first["five_quantity_v2"]["event_count"] == 1
    assert first["generic_drafts"]["count_source"] == (
        "trusted_full_scan_snapshot"
    )
    assert second["full_scan_snapshot"] == first["full_scan_snapshot"]


def test_production_full_scan_rejects_orphan_audit_foreign_key(
    tmp_path: Path,
) -> None:
    database = tmp_path / "orphan-audit.db"
    repository = Repository(database)
    initial_markers = (
        repository._runtime_data_version,
        repository._runtime_schema_version,
    )
    with sqlite3.connect(database) as external:
        assert external.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        external.execute(
            """
            INSERT INTO draft_audit(
                draft_id,sequence,event_type,actor,occurred_at,
                details_json,previous_hash,event_hash
            ) VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                "orphan-draft",
                1,
                "forged_orphan_event",
                "external-writer",
                "2026-08-09T00:00:00Z",
                "{}",
                "0" * 64,
                "1" * 64,
            ),
        )

    integrity = repository.verify_all_draft_audits()
    assert integrity["valid"] is False
    assert integrity["draft_count"] == 0
    assert integrity["event_count"] == 0
    assert integrity["database_checks"] == {
        "quick_check": "ok",
        "foreign_keys": "failed",
    }
    assert any(
        failure["integrity"]["failure"] == "sqlite_foreign_key_violation"
        for failure in integrity["failures"]
    )
    assert repository._runtime_integrity_latching_enabled is False
    assert repository._runtime_integrity_failed is False
    assert (
        repository._runtime_data_version,
        repository._runtime_schema_version,
    ) == initial_markers

    service = EnterpriseAgentService(repository, production_mode=True)
    with pytest.raises(ValueError, match="审计完整性"):
        service.assert_production_integrity()
    assert service._production_integrity_snapshot is None
    assert repository._runtime_integrity_latching_enabled is False


def test_production_integrity_scan_rejects_external_commit_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "startup-integrity-race.db"
    repository = Repository(database)
    service = EnterpriseAgentService(repository, production_mode=True)
    service.create_draft(actor="operator-1")
    with repository._transaction() as db:
        db.execute("CREATE TABLE startup_external_probe(value TEXT NOT NULL)")

    original = repository._draft_audit_integrity_in_transaction
    injected = False

    def verify_then_commit_externally(
        db: sqlite3.Connection,
        draft_id: str,
        **kwargs: object,
    ) -> dict[str, object]:
        nonlocal injected
        result = original(db, draft_id, **kwargs)
        if not injected:
            injected = True
            # WAL permits this separate writer to commit while the guarded
            # connection retains its explicit read snapshot.
            with sqlite3.connect(database, timeout=5) as external:
                external.execute(
                    "INSERT INTO startup_external_probe(value) VALUES ('tampered')"
                )
        return result

    monkeypatch.setattr(
        repository,
        "_draft_audit_integrity_in_transaction",
        verify_then_commit_externally,
    )
    with pytest.raises(ConflictError, match="扫描期间.*外部数据库提交"):
        service.assert_production_integrity()
    assert injected is True
    with pytest.raises(ConflictError, match="锁死"):
        service.list_drafts()


def test_machine_or_watcher_draft_requires_named_human_preparer(
    tmp_path: Path,
) -> None:
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "machine-human-gate.db"),
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine",
        four_eyes_required=True,
        human_preparer_actor_ids=frozenset({"preparer-1"}),
    )
    draft = runtime.ingest_bytes(
        filename="watcher.csv",
        content=_csv(),
        acquisition_mode="direct_collection",
        actor="system-watcher",
    )["draft"]
    assert draft["review_gate"]["state"] == "awaiting_human_preparer"
    with pytest.raises(ValidationBlockedError, match="具名经办账号"):
        runtime.confirm_draft(
            draft["draft_id"],
            expected_revision=draft["revision"],
            actor_id="reviewer-1",
            confirmer_name="李四",
            confirmer_role="复核负责人",
            attestation="本人已独立核对草稿。",
            accepted=True,
        )
    prepared = runtime.save_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        payload=draft["payload"],
        actor="preparer-1",
    )
    assert prepared["review_gate"]["state"] == "awaiting_independent_reviewer"
    assert prepared["human_preparer_actor"] == "preparer-1"
    confirmed = runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=prepared["revision"],
        actor_id="reviewer-1",
        confirmer_name="李四",
        confirmer_role="复核负责人",
        attestation="本人已独立核对经办人保存的当前修订版。",
        accepted=True,
    )
    assert confirmed["status"] == "queued"


def test_five_quantity_rejects_future_schema_and_missing_audit_trigger(
    tmp_path: Path,
) -> None:
    future_database = tmp_path / "future.db"
    FiveQuantityRuntime(
        Repository(future_database),
        identity=_identity(),
        quarantine_directory=tmp_path / "future-quarantine",
    )
    with sqlite3.connect(future_database) as db:
        db.execute(
            "UPDATE fq_schema_versions SET version=999 "
            "WHERE component='five_quantity_v2'"
        )
    with pytest.raises(ValueError, match="高于当前程序支持"):
        FiveQuantityRuntime(
            Repository(future_database),
            identity=_identity(),
            quarantine_directory=tmp_path / "future-quarantine-2",
        )

    trigger_database = tmp_path / "trigger.db"
    FiveQuantityRuntime(
        Repository(trigger_database),
        identity=_identity(),
        quarantine_directory=tmp_path / "trigger-quarantine",
    )
    with sqlite3.connect(trigger_database) as db:
        db.execute("DROP TRIGGER fq_audit_no_update")
    with pytest.raises(ValueError, match="触发器缺失或被替换"):
        FiveQuantityRuntime(
            Repository(trigger_database),
            identity=_identity(),
            quarantine_directory=tmp_path / "trigger-quarantine-2",
        )


def test_production_cli_rejects_self_reported_actor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_PRODUCTION_MODE", "true")
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", str(tmp_path / "agent.db"))
    assert main(["create", "--actor", "claimed-user"]) == 1
    assert "禁止使用可自行填写 --actor" in capsys.readouterr().err


def test_production_config_rejects_placeholder_and_reused_secrets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", str(tmp_path / "agent.db"))
    base = Settings.from_environment()
    shared = "A9-shared-secret-with-enough-entropy-2026-Zx7!"
    identity = replace(
        _identity(),
        key_id="current-key",
        message_hmac_secret=shared,
    )
    platform = FiveQuantityPlatformConfig(
        base_url="https://regulator.example.cn",
        sender_id=identity.system_id,
        transport_hmac_secret=shared,
    )
    configured = replace(
        base,
        production_mode=True,
        four_eyes_required=True,
        five_quantity_identity=identity,
        five_quantity_platform=platform,
    )
    errors = _configuration_errors(configured, production=True)
    assert any("低质量标识" in item for item in errors)
    assert any("应用消息密钥" in item and "运输密钥" in item for item in errors)

    placeholder_identity = replace(
        identity,
        key_id="enterprise-prod-key-2026",
        message_hmac_secret="replace-me-before-production-1234567890-ABC!",
    )
    placeholder_errors = _configuration_errors(
        replace(
            configured,
            five_quantity_identity=placeholder_identity,
            five_quantity_platform=None,
        ),
        production=True,
    )
    assert any("示例、占位或测试值" in item for item in placeholder_errors)


def test_production_config_validates_enterprise_historical_keyring_separately(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", str(tmp_path / "agent.db"))
    base = Settings.from_environment()
    historical_secret = (
        "Q7-enterprise-retired-signing-secret-2026-07-Zx9-abcdefghijklmnopqrstuvwxyz"
    )
    identity = replace(
        _identity(),
        historical_enterprise_signing_keys=(
            EnterpriseSigningVerificationKey(
                # Deliberately collides with the regulator namespace.  The
                # CLI must report it rather than treating both keyrings alike.
                key_id="regulator-prod-key",
                secret=historical_secret,
            ),
        ),
    )
    configured = replace(
        base,
        production_mode=True,
        four_eyes_required=True,
        five_quantity_identity=identity,
        five_quantity_platform=FiveQuantityPlatformConfig(
            base_url="https://regulator.example.cn",
            sender_id=identity.system_id,
            transport_hmac_secret=historical_secret,
        ),
    )

    errors = _configuration_errors(configured, production=True)

    assert any(
        "企业历史应用验签 key ID" in item
        and "政府当前应用验签 key ID" in item
        and "不得复用" in item
        for item in errors
    )
    assert any(
        "企业历史应用验签密钥" in item
        and "十量运输密钥" in item
        and "不得复用" in item
        for item in errors
    )


def test_production_config_allows_bilateral_retired_application_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("ENTERPRISE_AGENT_DB", str(tmp_path / "agent.db"))
    base = Settings.from_environment()
    retired_secret = (
        "Q7-bilateral-retired-application-secret-2026-07-Zx9-abcdefghijklmnopqrstuvwxyz"
    )
    identity = replace(
        _identity(),
        regulator_key_id="regulator-prod-key-2026-08",
        historical_enterprise_signing_keys=(
            EnterpriseSigningVerificationKey(
                key_id="enterprise-prod-key-2026-07",
                secret=retired_secret,
            ),
        ),
        # The regulator key ID is a stable global verification slot; only its
        # secret rotates during the bounded current/previous overlap.
        previous_regulator_key_id="regulator-prod-key-2026-08",
        previous_message_hmac_secret=retired_secret,
    )
    configured = replace(
        base,
        production_mode=True,
        four_eyes_required=True,
        five_quantity_identity=identity,
        five_quantity_platform=FiveQuantityPlatformConfig(
            base_url="https://regulator.example.cn",
            sender_id=identity.system_id,
            transport_hmac_secret=(
                "T8-distinct-current-transport-secret-2026-08-"
                "abcdefghijklmnopqrstuvwxyz"
            ),
        ),
    )

    errors = _configuration_errors(configured, production=True)

    assert not any(
        "企业历史应用验签密钥" in item
        and "政府上一把应用验签密钥" in item
        and "不得复用" in item
        for item in errors
    )
    assert not any(
        "政府当前应用验签 key ID" in item
        and "政府上一把应用验签 key ID" in item
        and "不得复用" in item
        for item in errors
    )
