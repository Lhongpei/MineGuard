from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from enterprise_agent.errors import ConflictError
from enterprise_agent.five_quantity_exchange import MineIdentity, sign_message
from enterprise_agent.five_quantity_runtime import (
    FiveQuantityRuntime,
    FiveQuantityStore,
)
from enterprise_agent.storage import Repository
from enterprise_agent.util import jcs_json, utc_text


def _identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-ARCHIVE-001",
        mine_name="十量归档测试煤矿",
        operator_id="operator-archive-001",
        operator_name="十量归档测试有限公司",
        system_id="agent-archive-001",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-archive-key",
        regulator_key_id="regulator-archive-key",
        message_hmac_secret="archive-message-secret-abcdefghijklmnopqrstuvwxyz",
    )


def _csv() -> bytes:
    return (
        "日期,风量,电量,雷管,炸药,入井人员量,产量,开采量,"
        "销售量,运输量,洗煤量,开票量\n"
        "2026-07-01,4800,96000,120,240,320,2600,2660,"
        "2500,2480,2550,2440\n"
    ).encode()


def _signed_receipt(
    submission: dict[str, Any],
    *,
    mine: MineIdentity | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    mine = mine or _identity()
    timestamp = timestamp or utc_text()
    receipt = {
        "contract_version": "intake-receipt-v2",
        "message_type": "intake_receipt",
        "message_id": str(uuid4()),
        "correlation_id": submission["correlation_id"],
        "causation_id": submission["message_id"],
        "idempotency_key": f"intake.{submission['message_id']}",
        "revision": 1,
        "predecessor": None,
        "created_at": timestamp,
        "sender": {
            "system_id": mine.regulator_system_id,
            "party_id": mine.regulator_party_id,
            "role": "regulatory_platform",
        },
        "recipient": {
            "system_id": mine.system_id,
            "party_id": mine.operator_id,
            "role": "enterprise_agent",
        },
        "mine_id": mine.mine_id,
        "payload": {
            "receipt_id": str(uuid4()),
            "submission_message_id": submission["message_id"],
            "submission_revision": submission["revision"],
            "received_payload_sha256": submission["signature_envelope"][
                "payload_sha256"
            ],
            "received_at": timestamp,
            "intake_status": "accepted",
            "analysis_state": "queued",
            "regulatory_outcome": "not_determined_at_intake",
            "analysis_run_id": str(uuid4()),
        },
        "signature_envelope": {
            "algorithm": "hmac-sha256-v2",
            "canonicalization": "rfc8785-jcs",
            "key_id": mine.regulator_key_id,
            "signed_at": timestamp,
            "nonce": uuid4().hex,
            "payload_sha256": "0" * 64,
            "signature": "0" * 64,
        },
    }
    return sign_message(receipt, secret=mine.message_hmac_secret)


def _queued_submission(
    tmp_path: Path, filename: str
) -> tuple[Repository, FiveQuantityRuntime, dict[str, Any], dict[str, Any]]:
    repository = Repository(tmp_path / filename)
    runtime = FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=tmp_path / f"{filename}-quarantine",
    )
    draft = runtime.ingest_bytes(
        filename="十量归档.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="preparer-1",
    )["draft"]
    runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="reviewer-1",
        confirmer_name="归档复核员",
        confirmer_role="企业复核员",
        attestation="已按原始凭证核对十量报送。",
        accepted=True,
    )
    outbox = runtime.store.due_outbox()[0]
    return repository, runtime, draft, outbox["body"]


@pytest.mark.parametrize(
    "mutation,resign,expected",
    (
        ("signature", False, "应用签名"),
        ("revision", True, "版本或 payload"),
        ("payload_hash", True, "版本或 payload"),
        ("causation", True, "版本或 payload"),
    ),
)
def test_fake_or_misbound_intake_receipt_is_never_archived(
    tmp_path: Path,
    mutation: str,
    resign: bool,
    expected: str,
) -> None:
    repository, runtime, draft, message = _queued_submission(
        tmp_path, f"bad-{mutation}.db"
    )
    receipt = _signed_receipt(message)
    if mutation == "signature":
        receipt["signature_envelope"]["signature"] = "f" * 64
    elif mutation == "revision":
        receipt["payload"]["submission_revision"] += 1
    elif mutation == "payload_hash":
        receipt["payload"]["received_payload_sha256"] = "a" * 64
    else:
        receipt["causation_id"] = str(uuid4())
    if resign:
        sign_message(receipt, secret=_identity().message_hmac_secret)

    with pytest.raises(ConflictError, match=expected):
        runtime.store.outbox_succeeded(message["message_id"], receipt=receipt)
    with repository._read() as db:
        outbox = db.execute(
            "SELECT status,receipt_json FROM fq_outbox WHERE message_id=?",
            (message["message_id"],),
        ).fetchone()
        source = db.execute(
            "SELECT status,receipt_json FROM fq_drafts WHERE draft_id=?",
            (draft["draft_id"],),
        ).fetchone()
    assert (outbox["status"], outbox["receipt_json"]) == ("sending", None)
    assert (source["status"], source["receipt_json"]) == ("queued", None)


def test_queued_and_delivered_submission_projection_is_immutable(
    tmp_path: Path,
) -> None:
    repository, runtime, draft, message = _queued_submission(tmp_path, "locked.db")

    with (
        pytest.raises(sqlite3.IntegrityError, match="projection is immutable"),
        repository._transaction() as db,
    ):
        db.execute(
            "UPDATE fq_drafts SET payload_json='{}' WHERE draft_id=?",
            (draft["draft_id"],),
        )
    with (
        pytest.raises(sqlite3.IntegrityError, match="projection is immutable"),
        repository._transaction() as db,
    ):
        db.execute("DELETE FROM fq_drafts WHERE draft_id=?", (draft["draft_id"],))
    with (
        pytest.raises(sqlite3.IntegrityError, match="signed archive is immutable"),
        repository._transaction() as db,
    ):
        db.execute(
            "UPDATE fq_outbox SET body_json='{}' WHERE message_id=?",
            (message["message_id"],),
        )
    with (
        pytest.raises(sqlite3.IntegrityError, match="signed archive is immutable"),
        repository._transaction() as db,
    ):
        db.execute(
            "DELETE FROM fq_outbox WHERE message_id=?", (message["message_id"],)
        )

    receipt = _signed_receipt(message)
    runtime.store.outbox_succeeded(message["message_id"], receipt=receipt)
    with repository._transaction() as db:
        db.execute(
            "UPDATE fq_outbox SET attempts=attempts+1,last_error=?,updated_at=? "
            "WHERE message_id=?",
            ("archived-diagnostic-note", utc_text(), message["message_id"]),
        )

    forbidden = (
        (
            "UPDATE fq_outbox SET body_json='{}' WHERE message_id=?",
            message["message_id"],
        ),
        (
            "UPDATE fq_outbox SET receipt_json='{}' WHERE message_id=?",
            message["message_id"],
        ),
        (
            "UPDATE fq_outbox SET status='failed' WHERE message_id=?",
            message["message_id"],
        ),
        ("DELETE FROM fq_outbox WHERE message_id=?", message["message_id"]),
        (
            "UPDATE fq_drafts SET status='ready_review' WHERE draft_id=?",
            draft["draft_id"],
        ),
        ("UPDATE fq_drafts SET receipt_json='{}' WHERE draft_id=?", draft["draft_id"]),
        ("DELETE FROM fq_drafts WHERE draft_id=?", draft["draft_id"]),
    )
    for statement, identifier in forbidden:
        with (
            pytest.raises(sqlite3.IntegrityError, match="immutable"),
            repository._transaction() as db,
        ):
            db.execute(statement, (identifier,))


def test_old_signed_receipt_remains_valid_for_later_correction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, runtime, draft, message = _queued_submission(tmp_path, "old-receipt.db")
    receipt = _signed_receipt(message, timestamp=message["created_at"])
    runtime.store.outbox_succeeded(message["message_id"], receipt=receipt)
    submitted = runtime.store.get_draft(draft["draft_id"])

    monkeypatch.setattr(
        "enterprise_agent.five_quantity_exchange.utc_now",
        lambda: datetime(2027, 2, 1, tzinfo=UTC),
    )
    correction = runtime.create_correction_draft(
        submitted["draft_id"],
        expected_revision=submitted["revision"],
        expected_submission_revision=1,
        accepted=True,
        actor="preparer-2",
    )
    assert correction["draft"]["submission_revision"] == 2


def test_correction_rejects_source_and_outbox_receipt_divergence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "receipt-divergence.db"
    repository, runtime, draft, message = _queued_submission(
        tmp_path, database.name
    )
    receipt = _signed_receipt(message)
    runtime.store.outbox_succeeded(message["message_id"], receipt=receipt)
    repository.close()

    divergent = copy.deepcopy(receipt)
    divergent["message_id"] = str(uuid4())
    divergent["payload"]["receipt_id"] = str(uuid4())
    sign_message(divergent, secret=_identity().message_hmac_secret)
    trigger_sql = FiveQuantityStore._archive_guard_definitions()[0][
        "fq_draft_submission_archive_no_update"
    ]
    with sqlite3.connect(database) as db:
        db.row_factory = sqlite3.Row
        db.execute("DROP TRIGGER fq_draft_submission_archive_no_update")
        db.execute(
            "UPDATE fq_drafts SET receipt_json=? WHERE draft_id=?",
            (jcs_json(divergent), draft["draft_id"]),
        )
        db.execute(trigger_sql)
        source = db.execute(
            "SELECT * FROM fq_drafts WHERE draft_id=?", (draft["draft_id"],)
        ).fetchone()
        assert source is not None
        with pytest.raises(ConflictError, match="政府回执不一致"):
            runtime.store._verify_archived_submission(db, source)

    with pytest.raises(ValueError, match="归档投影不一致"):
        FiveQuantityRuntime(
            Repository(database),
            identity=_identity(),
            quarantine_directory=tmp_path / "receipt-divergence-restart",
        )


def test_v3_to_v4_migration_installs_exact_guards_and_preserves_message(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v3-to-v4.db"
    repository, _, _, message = _queued_submission(tmp_path, database.name)
    with repository._read() as db:
        original_body = db.execute(
            "SELECT body_json FROM fq_outbox WHERE message_id=?",
            (message["message_id"],),
        ).fetchone()[0]
    repository.close()
    with sqlite3.connect(database) as db:
        for trigger in FiveQuantityStore._archive_guard_definitions()[0]:
            db.execute(f"DROP TRIGGER {trigger}")
        db.execute(
            "UPDATE fq_schema_versions SET version=3 "
            "WHERE component='five_quantity_v2'"
        )

    migrated = FiveQuantityRuntime(
        Repository(database),
        identity=_identity(),
        quarantine_directory=tmp_path / "v3-to-v4-restart",
    )
    with migrated.store.repository._read() as db:
        version = db.execute(
            "SELECT version FROM fq_schema_versions "
            "WHERE component='five_quantity_v2'"
        ).fetchone()[0]
        migrated_body = db.execute(
            "SELECT body_json FROM fq_outbox WHERE message_id=?",
            (message["message_id"],),
        ).fetchone()[0]
        assert migrated.store._archive_guards_intact(db)
    assert version == 4
    assert migrated_body == original_body


@pytest.mark.parametrize("object_kind", ("trigger", "index"))
def test_v4_refuses_replaced_archive_guard(
    tmp_path: Path, object_kind: str
) -> None:
    database = tmp_path / f"replaced-{object_kind}.db"
    repository = Repository(database)
    FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=tmp_path / f"replaced-{object_kind}-quarantine",
    )
    repository.close()
    with sqlite3.connect(database) as db:
        if object_kind == "trigger":
            db.execute("DROP TRIGGER fq_outbox_archive_no_delete")
            db.execute(
                "CREATE TRIGGER fq_outbox_archive_no_delete "
                "BEFORE DELETE ON fq_outbox BEGIN SELECT 1; END"
            )
        else:
            db.execute("DROP INDEX idx_fq_draft_predecessor_unique")
            db.execute(
                "CREATE INDEX idx_fq_draft_predecessor_unique "
                "ON fq_drafts(predecessor_message_id)"
            )
    with pytest.raises(ValueError, match="归档保护索引或触发器"):
        FiveQuantityRuntime(
            Repository(database),
            identity=_identity(),
            quarantine_directory=tmp_path / f"replaced-{object_kind}-restart",
        )


def test_restart_rejects_offline_deleted_delivered_projection(tmp_path: Path) -> None:
    database = tmp_path / "offline-delete.db"
    repository, runtime, draft, message = _queued_submission(tmp_path, database.name)
    runtime.store.outbox_succeeded(
        message["message_id"], receipt=_signed_receipt(message)
    )
    repository.close()
    triggers, _ = FiveQuantityStore._archive_guard_definitions()
    with sqlite3.connect(database) as db:
        for name in triggers:
            db.execute(f"DROP TRIGGER {name}")
        db.execute("DELETE FROM fq_outbox WHERE message_id=?", (message["message_id"],))
        db.execute("DELETE FROM fq_drafts WHERE draft_id=?", (draft["draft_id"],))
        for sql in triggers.values():
            db.execute(sql)

    with pytest.raises(ValueError, match="审计与本地签名归档投影不一致"):
        FiveQuantityRuntime(
            Repository(database),
            identity=_identity(),
            quarantine_directory=tmp_path / "offline-delete-restart",
        )


def test_restart_rejects_tampered_confirmed_v3_signature(tmp_path: Path) -> None:
    database = tmp_path / "offline-signature.db"
    repository, _, _, message = _queued_submission(tmp_path, database.name)
    repository.close()
    trigger_sql = FiveQuantityStore._archive_guard_definitions()[0][
        "fq_outbox_archive_no_update"
    ]
    with sqlite3.connect(database) as db:
        db.execute("DROP TRIGGER fq_outbox_archive_no_update")
        body = json.loads(
            db.execute(
                "SELECT body_json FROM fq_outbox WHERE message_id=?",
                (message["message_id"],),
            ).fetchone()[0]
        )
        body["signature_envelope"]["signature"] = "f" * 64
        body_json = jcs_json(body)
        db.execute(
            "UPDATE fq_outbox SET body_json=?,body_sha256=? WHERE message_id=?",
            (
                body_json,
                hashlib.sha256(body_json.encode()).hexdigest(),
                message["message_id"],
            ),
        )
        db.execute(trigger_sql)

    with pytest.raises(ValueError, match="审计与本地签名归档投影不一致"):
        FiveQuantityRuntime(
            Repository(database),
            identity=_identity(),
            quarantine_directory=tmp_path / "offline-signature-restart",
        )
