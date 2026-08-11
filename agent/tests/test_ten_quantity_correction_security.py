from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any
from uuid import uuid4

import pytest

from enterprise_agent.errors import ConflictError
from enterprise_agent.five_quantity_exchange import MineIdentity, sign_message
from enterprise_agent.five_quantity_runtime import FiveQuantityRuntime
from enterprise_agent.storage import Repository
from enterprise_agent.util import jcs_json, utc_text


def _identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-CORRECTION-SECURITY",
        mine_name="更正安全测试煤矿",
        operator_id="operator-correction-security",
        operator_name="更正安全测试煤业有限公司",
        system_id="agent-correction-security",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-correction-security-key",
        regulator_key_id="regulator-correction-security-key",
        message_hmac_secret=(
            "ten-quantity-correction-security-message-secret-abcdefghijklmnopqrstuvwxyz"
        ),
        capacity_band="medium",
        mining_method="underground",
        shift_system="three-shift-eight-hour",
        coal_type="bituminous",
        operating_regime="normal-production",
    )


def _csv() -> bytes:
    return (
        "日期,风量,电量,雷管,炸药,入井人员量,企业报表产量,开采量,"
        "销售量,运输量,洗煤量,开票量\n"
        "2026-07-01,4800,96000,120,240,320,2600,2660,"
        "2500,2480,2550,2440\n"
    ).encode()


def _signed_receipt(
    submission: dict[str, Any],
    *,
    identity: MineIdentity,
) -> dict[str, Any]:
    now = utc_text()
    message = {
        "contract_version": "intake-receipt-v2",
        "message_type": "intake_receipt",
        "message_id": str(uuid4()),
        "correlation_id": submission["correlation_id"],
        "causation_id": submission["message_id"],
        "idempotency_key": f"intake.{submission['message_id']}",
        "revision": 1,
        "predecessor": None,
        "created_at": now,
        "sender": {
            "system_id": identity.regulator_system_id,
            "party_id": identity.regulator_party_id,
            "role": "regulatory_platform",
        },
        "recipient": {
            "system_id": identity.system_id,
            "party_id": identity.operator_id,
            "role": "enterprise_agent",
        },
        "mine_id": identity.mine_id,
        "payload": {
            "receipt_id": str(uuid4()),
            "submission_message_id": submission["message_id"],
            "submission_revision": submission["revision"],
            "received_payload_sha256": submission["signature_envelope"][
                "payload_sha256"
            ],
            "received_at": now,
            "intake_status": "accepted",
            "analysis_state": "queued",
            "regulatory_outcome": "not_determined_at_intake",
            "analysis_run_id": str(uuid4()),
        },
        "signature_envelope": {
            "algorithm": "hmac-sha256-v2",
            "canonicalization": "rfc8785-jcs",
            "key_id": identity.regulator_key_id,
            "signed_at": now,
            "nonce": uuid4().hex,
            "payload_sha256": "0" * 64,
            "signature": "0" * 64,
        },
    }
    return sign_message(message, secret=identity.message_hmac_secret)


def _runtime(tmp_path: Path, name: str) -> FiveQuantityRuntime:
    return FiveQuantityRuntime(
        Repository(tmp_path / f"{name}.db"),
        identity=_identity(),
        quarantine_directory=tmp_path / f"quarantine-{name}",
    )


def _submitted_first_report(
    runtime: FiveQuantityRuntime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    draft = runtime.ingest_bytes(
        filename="十量首报.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="preparer-r1",
    )["draft"]
    runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="reviewer-r1",
        confirmer_name="首报复核员",
        confirmer_role="企业复核员",
        attestation="已按原始凭证核对首报。",
        accepted=True,
    )
    message = runtime.store.due_outbox()[0]["body"]
    runtime.store.outbox_succeeded(
        message["message_id"],
        receipt=_signed_receipt(message, identity=runtime.identity),
    )
    return runtime.store.get_draft(draft["draft_id"]), message


def _correction(
    runtime: FiveQuantityRuntime,
    source: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    return runtime.create_correction_draft(
        source["draft_id"],
        expected_revision=source["revision"],
        expected_submission_revision=source["submission_revision"],
        accepted=True,
        actor=actor,
    )["draft"]


def _move_payload_to_august(payload: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(payload)
    changed["reporting_month"] = "2026-08"
    changed["period_start"] = "2026-08-01"
    changed["period_end"] = "2026-08-01"
    changed["days"][0]["date"] = "2026-08-01"
    return changed


def test_correction_cannot_be_discarded_or_change_reporting_window(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "immutable-window")
    submitted, _message = _submitted_first_report(runtime)
    correction = _correction(runtime, submitted, actor="preparer-r2")

    with pytest.raises(ConflictError, match="唯一后继"):
        runtime.discard_draft(
            correction["draft_id"],
            expected_revision=correction["revision"],
            actor="preparer-r2",
            reason="不应允许放弃正式更正",
        )

    with pytest.raises(ConflictError, match="沿用直接前序"):
        runtime.save_draft(
            correction["draft_id"],
            expected_revision=correction["revision"],
            payload=_move_payload_to_august(correction["payload"]),
            actor="preparer-r2",
        )

    unchanged = runtime.store.get_draft(correction["draft_id"])
    assert unchanged["status"] == "ready_review"
    assert unchanged["revision"] == correction["revision"]
    assert unchanged["payload"]["reporting_month"] == "2026-07"


def test_confirm_rechecks_predecessor_window_after_direct_row_tamper(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "confirm-window")
    submitted, _message = _submitted_first_report(runtime)
    correction = _correction(runtime, submitted, actor="preparer-r2")
    changed = _move_payload_to_august(correction["payload"])
    with runtime.store.repository._transaction() as db:
        db.execute(
            "UPDATE fq_drafts SET payload_json=? WHERE draft_id=?",
            (jcs_json(changed), correction["draft_id"]),
        )

    with pytest.raises(ConflictError, match="改变了直接前序"):
        runtime.confirm_draft(
            correction["draft_id"],
            expected_revision=correction["revision"],
            actor_id="reviewer-r2",
            confirmer_name="更正复核员",
            confirmer_role="企业复核员",
            attestation="已核对更正。",
            accepted=True,
        )
    assert runtime.store.get_draft(correction["draft_id"])["status"] == (
        "ready_review"
    )


def test_store_binds_signed_payload_and_confirmation_to_current_draft(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path, "store-binding")
    draft = runtime.ingest_bytes(
        filename="十量首报.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="preparer-r1",
    )["draft"]
    captured: dict[str, Any] = {}
    original = runtime.store.confirm_and_enqueue

    def capture(draft_id: str, **kwargs: Any) -> dict[str, Any]:
        captured["draft_id"] = draft_id
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(runtime.store, "confirm_and_enqueue", capture)
    runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="reviewer-r1",
        confirmer_name="首报复核员",
        confirmer_role="企业复核员",
        attestation="已核对首报。",
        accepted=True,
    )
    monkeypatch.setattr(runtime.store, "confirm_and_enqueue", original)

    changed = copy.deepcopy(draft["payload"])
    changed["days"][0]["reported_quantity"]["daily_total"]["sales_t"][
        "value"
    ] = 2499
    with runtime.store.repository._transaction() as db:
        db.execute(
            "UPDATE fq_drafts SET payload_json=? WHERE draft_id=?",
            (jcs_json(changed), draft["draft_id"]),
        )
    with pytest.raises(ConflictError, match="未精确绑定"):
        original(
            captured.pop("draft_id"),
            **captured,
        )

    with runtime.store.repository._transaction() as db:
        db.execute(
            "UPDATE fq_drafts SET payload_json=? WHERE draft_id=?",
            (jcs_json(draft["payload"]), draft["draft_id"]),
        )
    wrong_confirmation = copy.deepcopy(captured["confirmation"])
    wrong_confirmation["actor_id"] = "different-reviewer"
    with pytest.raises(ConflictError, match="未精确绑定"):
        original(
            draft["draft_id"],
            **{**captured, "confirmation": wrong_confirmation},
        )


def test_parallel_correction_requests_share_one_unique_successor(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "parallel-successor")
    submitted, _message = _submitted_first_report(runtime)
    barrier = Barrier(2)

    def create() -> dict[str, Any]:
        barrier.wait(timeout=5)
        return runtime.create_correction_draft(
            submitted["draft_id"],
            expected_revision=submitted["revision"],
            expected_submission_revision=1,
            accepted=True,
            actor="preparer-r2",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: create(), range(2)))

    assert {result["created"] for result in results} == {False, True}
    assert len({result["draft"]["draft_id"] for result in results}) == 1
    assert all(result["draft"]["submission_revision"] == 2 for result in results)


def test_three_revision_chain_uses_direct_predecessor_and_one_correlation(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path, "three-revisions")
    submitted_r1, message_r1 = _submitted_first_report(runtime)
    draft_r2 = _correction(runtime, submitted_r1, actor="preparer-r2")
    runtime.confirm_draft(
        draft_r2["draft_id"],
        expected_revision=draft_r2["revision"],
        actor_id="reviewer-r2",
        confirmer_name="第 2 版复核员",
        confirmer_role="企业复核员",
        attestation="已核对第 2 版。",
        accepted=True,
    )
    message_r2 = runtime.store.due_outbox()[0]["body"]
    runtime.store.outbox_succeeded(
        message_r2["message_id"],
        receipt=_signed_receipt(message_r2, identity=runtime.identity),
    )
    submitted_r2 = runtime.store.get_draft(draft_r2["draft_id"])
    draft_r3 = _correction(runtime, submitted_r2, actor="preparer-r3")
    runtime.confirm_draft(
        draft_r3["draft_id"],
        expected_revision=draft_r3["revision"],
        actor_id="reviewer-r3",
        confirmer_name="第 3 版复核员",
        confirmer_role="企业复核员",
        attestation="已核对第 3 版。",
        accepted=True,
    )
    message_r3 = runtime.store.due_outbox()[0]["body"]

    assert message_r3["revision"] == 3
    assert message_r3["correlation_id"] == message_r1["message_id"]
    assert message_r3["causation_id"] == message_r2["message_id"]
    assert message_r3["predecessor"] == {
        "message_id": message_r2["message_id"],
        "payload_sha256": message_r2["signature_envelope"]["payload_sha256"],
    }
    assert message_r2["predecessor"]["message_id"] == message_r1["message_id"]


def test_acknowledged_status_is_server_side_immutable(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "acknowledged-lock")
    draft = runtime.ingest_bytes(
        filename="十量首报.csv",
        content=_csv(),
        acquisition_mode="manual_import",
        actor="preparer-r1",
    )["draft"]
    with runtime.store.repository._transaction() as db:
        db.execute(
            "UPDATE fq_drafts SET status='acknowledged' WHERE draft_id=?",
            (draft["draft_id"],),
        )

    with pytest.raises(ConflictError, match="不可覆盖"):
        runtime.save_draft(
            draft["draft_id"],
            expected_revision=draft["revision"],
            payload=copy.deepcopy(draft["payload"]),
            actor="preparer-r1",
        )
