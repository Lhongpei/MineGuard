from __future__ import annotations

import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from enterprise_agent.five_quantity_exchange import MineIdentity, sign_message
from enterprise_agent.five_quantity_runtime import (
    FiveQuantityRuntime,
    validate_five_quantity_payload,
)
from enterprise_agent.storage import Repository
from enterprise_agent.util import utc_text

MESSAGE_SECRET = "current-message-secret-abcdefghijklmnopqrstuvwxyz"


def identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-TEST-001",
        mine_name="测试煤矿",
        operator_id="operator-test-001",
        operator_name="测试煤业有限公司",
        system_id="agent-mine-test-001",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-key-current",
        regulator_key_id="regulator-key-current",
        message_hmac_secret=MESSAGE_SECRET,
        capacity_band="medium",
        mining_method="underground",
        shift_system="three-shift-eight-hour",
        coal_type="bituminous",
        operating_regime="normal-production",
    )


def csv_bytes() -> bytes:
    return (
        b"date,ventilation_m3_min,mine_entry_persons,electricity_kwh,"
        b"detonators_count,explosives_kg,production_t\n"
        b"2026-07-01,4800,320,96000,120,240,2600\n"
        b"2026-07-02,4900,322,97000,121,242,2700\n"
    )


def test_mine_entry_persons_requires_integer_sum_aggregation(tmp_path: Path) -> None:
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "aggregation.db"),
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    draft = runtime.ingest_bytes(
        filename="aggregation.csv",
        content=csv_bytes(),
        acquisition_mode="manual_import",
        actor="operator-1",
    )["draft"]
    measurement = draft["payload"]["days"][0]["reported_quantity"][
        "daily_total"
    ]["mine_entry_persons"]
    measurement["aggregation"] = "snapshot"
    with pytest.raises(ValueError, match="mine_entry_persons.aggregation"):
        validate_five_quantity_payload(
            draft["payload"],
            identity=identity(),
            confirmed=False,
        )

    measurement["aggregation"] = "sum"
    measurement["value"] = 320.5
    with pytest.raises(ValueError, match="mine_entry_persons 非空时必须是整数"):
        validate_five_quantity_payload(
            draft["payload"],
            identity=identity(),
            confirmed=False,
        )


class FakeGovernment:
    def __init__(self, mine: MineIdentity):
        self.identity = mine
        self.submission: dict[str, Any] | None = None
        self.report: dict[str, Any] | None = None
        self.acks: list[dict[str, Any]] = []
        self.responses: list[dict[str, Any]] = []

    def _message(
        self,
        contract: str,
        message_type: str,
        payload: dict[str, Any],
        *,
        correlation_id: str,
        causation_id: str,
    ) -> dict[str, Any]:
        message_id = str(uuid4())
        timestamp = utc_text()
        return sign_message(
            {
                "contract_version": contract,
                "message_type": message_type,
                "message_id": message_id,
                "correlation_id": correlation_id,
                "causation_id": causation_id,
                "idempotency_key": f"gov.{message_type}.{message_id}",
                "revision": 1,
                "predecessor": None,
                "created_at": timestamp,
                "sender": {
                    "system_id": self.identity.regulator_system_id,
                    "party_id": self.identity.regulator_party_id,
                    "role": "regulatory_platform",
                },
                "recipient": {
                    "system_id": self.identity.system_id,
                    "party_id": self.identity.operator_id,
                    "role": "enterprise_agent",
                },
                "mine_id": self.identity.mine_id,
                "payload": payload,
                "signature_envelope": {
                    "algorithm": "hmac-sha256-v2",
                    "canonicalization": "rfc8785-jcs",
                    "key_id": self.identity.regulator_key_id,
                    "signed_at": timestamp,
                    "nonce": uuid4().hex,
                    "payload_sha256": "0" * 64,
                    "signature": "0" * 64,
                },
            },
            secret=MESSAGE_SECRET,
        )

    def submit(self, message: dict[str, Any]) -> dict[str, Any]:
        self.submission = message
        payload = {
            "receipt_id": str(uuid4()),
            "submission_message_id": message["message_id"],
            "received_at": utc_text(),
            "accepted_revision": message["revision"],
            "received_payload_sha256": message["signature_envelope"]["payload_sha256"],
            "queue_state": "queued_for_analysis",
            "regulatory_outcome": "not_determined_at_intake",
            "analysis_report_id": None,
            "warnings": [],
        }
        return self._message(
            "intake-receipt-v2",
            "intake_receipt",
            payload,
            correlation_id=message["correlation_id"],
            causation_id=message["message_id"],
        )

    def pull_next(self, *, after_cursor: str | None = None) -> dict[str, Any] | None:
        if self.submission is None or self.report is not None:
            return None
        report_id = str(uuid4())
        finding_id = str(uuid4())
        submission_payload = self.submission["payload"]
        payload = {
            "report_id": report_id,
            "submission_message_id": self.submission["message_id"],
            "submission_revision": 1,
            "mine": self.identity.mine,
            "reporting_month": submission_payload["reporting_month"],
            "period_start": submission_payload["period_start"],
            "period_end": submission_payload["period_end"],
            "issued_at": utc_text(),
            "algorithm": {
                "engine_id": "mineguard-five-quantity-engine",
                "engine_version": "2.0.0",
                "algorithm_run_id": str(uuid4()),
                "config_sha256": "1" * 64,
                "input_snapshot_sha256": "2" * 64,
                "own_history_snapshot_sha256": "3" * 64,
                "peer_snapshot_sha256": "4" * 64,
                "started_at": utc_text(),
                "completed_at": utc_text(),
                "modules": [
                    "l1_reconciliation",
                    "robust_temporal_baseline",
                    "past_only_page_hinkley",
                ],
            },
            "outcome": "risk",
            "summary": "产量与用电联合关系需要企业核对。",
            "findings": [
                {
                    "finding_id": finding_id,
                    "category": "combined_evidence",
                    "severity": "high",
                    "title": "产量与用电关系异常",
                    "summary": "联合约束和本矿历史基线同时偏离。",
                    "affected_dates": ["2026-07-02"],
                    "affected_shifts": [],
                    "affected_metrics": ["electricity_kwh", "production_t"],
                    "evidence": [
                        {
                            "evidence_id": "EV-L1-001",
                            "method": "l1_reconciliation",
                            "summary": "最小调整超过阈值。",
                            "observed_value": 36.0,
                            "expected_min": 20.0,
                            "expected_max": 30.0,
                            "score": 3.0,
                            "evidence_sha256": "5" * 64,
                        },
                        {
                            "evidence_id": "EV-TEMP-001",
                            "method": "past_only_page_hinkley",
                            "summary": "只使用此前历史检测到累积变化。",
                            "observed_value": None,
                            "expected_min": None,
                            "expected_max": None,
                            "score": None,
                            "evidence_sha256": "6" * 64,
                        }
                    ],
                    "requires_response": True,
                }
            ],
            "response_required": True,
            "response_due_at": utc_text(),
            "delivery_cursor": "opaque.mine.cursor:00000001",
        }
        self.report = self._message(
            "analysis-report-v2",
            "analysis_report",
            payload,
            correlation_id=self.submission["correlation_id"],
            causation_id=self.submission["message_id"],
        )
        return self.report

    def acknowledge(self, report_id: str, message: dict[str, Any]) -> None:
        assert self.report is not None
        assert report_id == self.report["payload"]["report_id"]
        self.acks.append(message)

    def respond(self, report_id: str, message: dict[str, Any]) -> dict[str, Any]:
        assert self.report is not None
        assert report_id == self.report["payload"]["report_id"]
        self.responses.append(message)
        payload = {
            "receipt_id": str(uuid4()),
            "enterprise_response_message_id": message["message_id"],
            "response_id": message["payload"]["response_id"],
            "analysis_report_id": report_id,
            "received_at": utc_text(),
            "record_state": "recorded",
            "risk_status": "not_cleared_by_receipt",
            "reanalysis_triggered": False,
            "reanalysis_report_id": None,
        }
        return self._message(
            "response-receipt-v2",
            "response_receipt",
            payload,
            correlation_id=message["correlation_id"],
            causation_id=message["message_id"],
        )


def test_durable_full_workflow_and_agent_assistance_trace(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "agent.db")
    first = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "state" / "quarantine",
    )
    imported = first.ingest_bytes(
        filename="july.csv",
        content=csv_bytes(),
        acquisition_mode="manual_import",
        actor="operator-1",
    )
    duplicate = first.ingest_bytes(
        filename="same-content.csv",
        content=csv_bytes(),
        acquisition_mode="direct_collection",
        actor="device-api",
    )
    assert duplicate["duplicate"] is True
    draft = imported["draft"]
    first.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="operator-1",
        confirmer_name="张三",
        confirmer_role="企业填报员",
        attestation="本人已逐项核对日报和三个班次原始记录。",
        accepted=True,
    )
    claimed = first.store.due_outbox()
    assert claimed[0]["message_kind"] == "submission"

    government = FakeGovernment(identity())
    restarted = FiveQuantityRuntime(
        Repository(tmp_path / "agent.db"),
        identity=identity(),
        platform_client=government,  # type: ignore[arg-type]
        quarantine_directory=tmp_path / "state" / "quarantine",
    )
    assert restarted.process_outbox_once()[0]["status"] == "succeeded"
    assert restarted.poll_analysis_once()["duplicate"] is False  # type: ignore[index]
    report = restarted.store.list_reports()[0]
    assert report["report"]["payload"]["delivery_cursor"] == (
        "opaque.mine.cursor:00000001"
    )
    assert restarted.store.last_cursor() is None
    restarted.process_outbox_once()
    assert restarted.store.last_cursor() == "opaque.mine.cursor:00000001"

    chat = restarted.risk_explanation(
        report["report_id"],
        "L1 求解器和历史基线为什么同时提示风险？",
        actor="operator-1",
    )
    assert "evidence_method_explainer" in chat["tools"]
    assert "L1 求解器" in chat["answer"]
    assert "Page-Hinkley" in chat["answer"]
    assert "涉及指标：电量、产量" in chat["answer"]
    assert "electricity_kwh" not in chat["answer"]
    response = restarted.store.create_response(report["report_id"], actor="operator-1")
    document = response["document"]
    document["finding_responses"][0].update(
        response_kind="explanation",
        reason_code="planned_shutdown",
        facts="企业核对后确认当日存在计划检修，日报与三个班次记录一致。",
        actions=[
            {
                "action_type": "investigation",
                "description": "复核日报、班次记录与检修计划。",
                "status": "completed",
            }
        ],
    )
    response = restarted.save_response(
        response["response_id"],
        expected_revision=response["revision"],
        document=document,
        actor="operator-1",
    )
    restarted.confirm_response(
        response["response_id"],
        expected_revision=response["revision"],
        actor_id="operator-1",
        confirmer_name="李四",
        confirmer_role="企业负责人",
        attestation="本人确认事实、证据引用和措施已经企业核实。",
        accepted=True,
    )
    assert restarted.process_outbox_once()[0]["status"] == "succeeded"
    sent = government.responses[0]
    assert sent["payload"]["agent_assistance"]["used"] is True
    assert len(sent["payload"]["agent_assistance"]["assistance_record_sha256"]) == 64
    assert restarted.store.get_response(response["response_id"])["status"] == (
        "submitted"
    )
    assert restarted.store.audit()["valid"] is True


def test_watcher_quarantines_in_agent_state_not_read_only_source(
    tmp_path: Path,
) -> None:
    watched = tmp_path / "source-inbox"
    watched.mkdir()
    quarantine = tmp_path / "agent-state" / "quarantine"
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "agent-state" / "agent.db"),
        identity=identity(),
        watched_directories=(str(watched),),
        quarantine_directory=quarantine,
        stable_seconds=0.5,
    )
    source = watched / "broken.csv"
    source.write_text("not,a,five-quantity-table\n1,2,3\n")
    assert runtime.scan_watched_directories() == []
    time.sleep(0.55)
    result = runtime.scan_watched_directories()
    assert result[0]["status"] == "quarantined"
    assert source.exists()
    assert not (watched / ".five-quantity-quarantine").exists()
    quarantined = list(quarantine.iterdir())
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == source.read_bytes()


def test_quarantine_directory_cannot_be_inside_a_watched_source(tmp_path: Path) -> None:
    watched = tmp_path / "source"
    watched.mkdir()
    try:
        FiveQuantityRuntime(
            Repository(tmp_path / "agent.db"),
            identity=identity(),
            watched_directories=(str(watched),),
            quarantine_directory=watched / "quarantine",
        )
    except ValueError as error:
        assert "不能放在来源目录" in str(error)
    else:
        raise AssertionError("source-contained quarantine must be rejected")
