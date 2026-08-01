from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
import sqlite3
from uuid import uuid4

import pytest

from mineguard.regulatory_v2 import (
    ComparisonContext,
    DecisionStatus,
    FiveQuantityDay,
    FiveQuantitySubmission,
    ReportedQuantity,
    ShiftValues,
    SubmissionProvenance,
)
from mineguard.regulatory_v2_store import (
    AnalysisReportDeliveryAck,
    EnterpriseFindingResponse,
    ExchangeMessageInput,
    RegulatoryV2ConflictError,
    RegulatoryV2NotFoundError,
    RegulatoryV2Store,
)


NOW = datetime(2026, 2, 1, tzinfo=UTC)


def _q(value: float, shifts: ShiftValues | None = None) -> ReportedQuantity:
    return ReportedQuantity(daily_total=value, shifts=shifts)


def _submission(
    submission_id: str,
    *,
    mine_id: str = "mine-a",
    revision: int = 1,
    predecessor: str | None = None,
    mismatch: bool = False,
    start: date = date(2026, 1, 1),
    electricity_ratio: float = 20.0,
) -> FiveQuantitySubmission:
    days: list[FiveQuantityDay] = []
    for index in range(14):
        shifts = (
            ShiftValues(zero_shift=2_000, eight_shift=2_000, four_shift=2_000)
            if mismatch and index == 5
            else None
        )
        days.append(
            FiveQuantityDay(
                date=start + timedelta(days=index),
                ventilation_m3_min=_q(3_000),
                electricity_kwh=_q(100 * electricity_ratio, shifts),
                detonators_count=_q(10),
                explosives_kg=_q(50),
                mine_entry_persons=_q(100),
                production_t=_q(100),
            )
        )
    return FiveQuantitySubmission(
        submission_id=submission_id,
        mine_id=mine_id,
        mine_name=f"{mine_id} name",
        revision=revision,
        supersedes_submission_id=predecessor,
        period_start=start,
        period_end=start + timedelta(days=13),
        comparison_context=ComparisonContext(
            capacity_band="0.9-1.2mtpa",
            mining_method="longwall",
            shift_system="three-shift",
            coal_type="thermal",
            operating_regime="normal",
        ),
        days=days,
        provenance=[
            SubmissionProvenance(
                acquisition_mode="manual_import",
                source_name="file",
                evidence_sha256="b" * 64,
            )
        ],
    )


def test_every_run_has_one_analysis_report_outbox_and_delivery_ack() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        store.bind_agent_to_mine("agent-a", "mine-a")
        receipt = store.submit_and_analyze(
            _submission(str(uuid4())), agent_id="agent-a"
        )

        assert receipt.decision is DecisionStatus.NORMAL_CANDIDATE
        page = store.poll_analysis_reports("mine-a")
        assert len(page.items) == 1
        item = page.items[0]
        assert item.kind == "analysis_report_available"
        report = store.get_analysis_report(item.aggregate_id, mine_id="mine-a")
        assert report.response_required is False
        assert report.finding_ids == []
        assert report.delivery_cursor.endswith(f"{item.sequence:020d}")
        latest_run = store.list_runs(mine_id="mine-a")[0]
        assert latest_run["baseline_eligible"] == 0
        assert latest_run["baseline_reference_candidate"] == 1
        assert latest_run["baseline_rule_version"] == "baseline-admission-v2.2"

        ack = AnalysisReportDeliveryAck(
            ack_id=str(uuid4()),
            report_id=report.report_id,
            mine_id="mine-a",
            analysis_report_message_id=item.message_id,
            delivery_cursor=report.delivery_cursor,
            local_inbox_record_id="local-inbox-1",
            delivery_status="stored",
            received_at=NOW,
        )
        first = store.record_delivery_ack(ack)
        replay = store.record_delivery_ack(ack)
        assert first.idempotent_replay is False
        assert replay.idempotent_replay is True
        assert store.get_delivery_ack_receipt(ack.ack_id).report_id == report.report_id


def test_explanation_does_not_clear_and_normal_revision_reanalysis_does() -> None:
    first_id = str(uuid4())
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        store.bind_agent_to_mine("agent-a", "mine-a")
        first = store.submit_and_analyze(
            _submission(first_id, mismatch=True), agent_id="agent-a"
        )
        assert first.decision is DecisionStatus.RISK
        assert first.finding_id is not None
        assert store.list_runs(mine_id="mine-a")[0]["baseline_eligible"] == 0

        response = EnterpriseFindingResponse(
            response_id=str(uuid4()),
            finding_id=first.finding_id,
            mine_id="mine-a",
            reason_category="equipment_or_metering",
            explanation="日报与班次表的归集口径不一致，原始电表已完成复核。",
            corrected_submission_planned=True,
            confirmed_by="mine-operator",
            confirmed_at=NOW,
        )
        response_receipt = store.record_enterprise_response(response)
        assert response_receipt.risk_cleared is False
        assert store.get_response_receipt(response.response_id).risk_cleared is False
        assert store.get_finding(first.finding_id).state == "explanation_recorded"

        revision = store.submit_and_analyze(
            _submission(str(uuid4()), revision=2, predecessor=first_id, mismatch=False),
            agent_id="agent-a",
        )
        assert revision.decision is DecisionStatus.NORMAL_CANDIDATE
        finding = store.get_finding(first.finding_id)
        assert finding.state == "cleared_by_reanalysis"
        assert finding.resolved_by_submission_id == revision.submission_id
        assert store.verify_audit_chain()


def test_multi_finding_wire_response_is_recorded_as_one_atomic_batch() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        store.submit_and_analyze(_submission(str(uuid4()), mismatch=True))
        report_item = store.poll_analysis_reports("mine-a").items[0]
        report = store.get_analysis_report(report_item.aggregate_id)
        assert len(report.finding_ids) >= 2
        outer_response_id = str(uuid4())
        responses = [
            EnterpriseFindingResponse(
                response_id=outer_response_id,
                finding_id=finding_id,
                mine_id="mine-a",
                reason_category="equipment_or_metering",
                explanation=f"对风险项 {index} 的人工确认说明",
                confirmed_by="operator",
                confirmed_at=NOW,
            )
            for index, finding_id in enumerate(report.finding_ids)
        ]

        first = store.record_enterprise_response_batch(
            outer_response_id,
            report.report_id,
            "mine-a",
            responses,
        )
        replay = store.record_enterprise_response_batch(
            outer_response_id,
            report.report_id,
            "mine-a",
            responses,
        )

        assert first.idempotent_replay is False
        assert replay.idempotent_replay is True
        assert len(first.child_response_ids) == len(report.finding_ids)
        assert len(store.list_responses(mine_id="mine-a")) == len(report.finding_ids)
        assert all(
            store.get_finding(finding_id).state == "explanation_recorded"
            for finding_id in report.finding_ids
        )
        assert set(
            store.get_response_batch_receipt(outer_response_id).finding_ids
        ) == set(report.finding_ids)


def test_one_agent_is_permanently_bound_to_one_mine() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        store.bind_agent_to_mine("agent-a", "mine-a")
        store.bind_agent_to_mine("agent-a", "mine-a")
        with pytest.raises(RegulatoryV2ConflictError):
            store.bind_agent_to_mine("agent-a", "mine-b")
        with pytest.raises(RegulatoryV2ConflictError):
            store.bind_agent_to_mine("agent-b", "mine-a")
        with pytest.raises(RegulatoryV2ConflictError):
            store.submit_and_analyze(
                _submission(str(uuid4()), mine_id="mine-b"),
                agent_id="agent-a",
            )


def test_future_reporting_period_is_rejected_before_baseline_admission() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        with pytest.raises(RegulatoryV2ConflictError, match="future reporting"):
            store.submit_and_analyze(
                _submission(
                    str(uuid4()),
                    start=date(2030, 1, 1),
                )
            )
        assert store.list_submissions() == []


def test_one_mine_cannot_create_parallel_or_overlapping_monthly_roots() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        first = store.submit_and_analyze(
            _submission(str(uuid4()), start=date(2026, 1, 1))
        )
        with pytest.raises(RegulatoryV2ConflictError, match="one root workflow"):
            store.submit_and_analyze(
                _submission(str(uuid4()), start=date(2026, 1, 2))
            )
        assert len(store.list_submissions(mine_id="mine-a")) == 1
        assert store.get_submission_receipt(first.submission_id).run_id == first.run_id


def test_store_builds_anonymous_equal_mine_peer_reference() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        for index in range(3):
            mine_id = f"peer-{index + 1}"
            receipt = store.submit_and_analyze(
                _submission(
                    str(uuid4()),
                    mine_id=mine_id,
                    start=date(2025, 12, 1),
                    electricity_ratio=20.0 + index,
                )
            )
            assert receipt.decision is DecisionStatus.NORMAL_CANDIDATE

        target = store.submit_and_analyze(
            _submission(
                str(uuid4()),
                mine_id="target-mine",
                electricity_ratio=38.0,
            )
        )
        result = store.get_run(target.run_id)

        electricity_band = next(
            band
            for band in result.references.accepted_peer_bands
            if band.relationship.value == "electricity_per_production"
        )
        assert electricity_band.mine_count == 3
        assert electricity_band.basis == "anonymous_peer"
        assert target.decision is DecisionStatus.RISK
        serialized = result.model_dump_json()
        assert "peer-1" not in serialized
        assert "peer-2" not in serialized
        assert "peer-3" not in serialized


def test_same_period_peer_arrival_order_cannot_change_analysis() -> None:
    target_id = "00000000-0000-4000-8000-000000000099"

    def run(*, target_first: bool) -> tuple[DecisionStatus, str, list[object]]:
        with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
            def submit_target() -> tuple[DecisionStatus, str, list[object]]:
                receipt = store.submit_and_analyze(
                    _submission(
                        target_id,
                        mine_id="target-mine",
                        electricity_ratio=38.0,
                    )
                )
                result = store.get_run(receipt.run_id)
                return (
                    result.decision,
                    result.algorithm_input_sha256,
                    list(result.references.accepted_peer_bands),
                )

            if target_first:
                target = submit_target()
            for index in range(3):
                store.submit_and_analyze(
                    _submission(
                        str(uuid4()),
                        mine_id=f"same-period-peer-{index}",
                        electricity_ratio=20.0 + index,
                    )
                )
            if not target_first:
                target = submit_target()
            return target

    before_peers = run(target_first=True)
    after_peers = run(target_first=False)
    assert before_peers == after_peers
    assert before_peers[2] == []


def test_group_peer_snapshot_is_frozen_for_all_mines_in_reporting_period() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        for index in range(3):
            store.submit_and_analyze(
                _submission(
                    str(uuid4()),
                    mine_id=f"prior-peer-{index}",
                    start=date(2025, 12, 1),
                    electricity_ratio=20.0 + index,
                )
            )

        first = store.submit_and_analyze(
            _submission(str(uuid4()), mine_id="current-a")
        )
        first_bands = store.get_run(first.run_id).references.accepted_peer_bands
        assert first_bands
        assert {item.mine_count for item in first_bands} == {3}

        # This late prior-period report is valid but cannot rewrite the already
        # frozen January cohort or give a later January mine more information.
        store.submit_and_analyze(
            _submission(
                str(uuid4()),
                mine_id="late-prior-peer",
                start=date(2025, 12, 1),
                electricity_ratio=28.0,
            )
        )
        second = store.submit_and_analyze(
            _submission(str(uuid4()), mine_id="current-b")
        )
        second_bands = store.get_run(second.run_id).references.accepted_peer_bands
        assert second_bands == first_bands
        january_freezes = [
            event
            for event in store.list_audit_events(limit=1_000)
            if event.event_type == "anonymous_peer_snapshot_frozen"
            and event.payload["cutoff_date"] == "2026-01-01"
        ]
        assert len(january_freezes) == 1


def test_raw_exchange_envelope_is_retained_and_hash_idempotent() -> None:
    submission = _submission(str(uuid4()))
    exchange = ExchangeMessageInput(
        message_id=str(uuid4()),
        direction="inbound",
        message_type="five_quantity_submission",
        mine_id="mine-a",
        agent_id="agent-a",
        body={
            "enterprise_id": "independent-enterprise-a",
            "human_confirmation": {"confirmed_by": "operator-a"},
            "signature_envelope": {"algorithm": "hmac-sha256"},
        },
        exchanged_at=NOW,
    )
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        store.bind_agent_to_mine("agent-a", "mine-a")
        store.submit_and_analyze(
            submission,
            agent_id="agent-a",
            exchange_message=exchange,
        )
        messages = store.list_exchange_messages(mine_id="mine-a")
        assert messages[0].body["enterprise_id"] == "independent-enterprise-a"
        assert (
            store.record_exchange_message(exchange).body_sha256
            == messages[0].body_sha256
        )

        changed = exchange.model_copy(update={"body": {"tampered": True}})
        with pytest.raises(RegulatoryV2ConflictError):
            store.record_exchange_message(changed)


def test_sender_idempotency_is_atomic_and_conflict_is_durably_audited() -> None:
    first_id = str(uuid4())
    first_exchange = ExchangeMessageInput(
        message_id=first_id,
        direction="inbound",
        message_type="five_quantity_submission",
        mine_id="mine-a",
        agent_id="agent-a",
        body={"message_id": first_id, "payload": {"version": 1}},
        exchanged_at=NOW,
    )
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        store.bind_agent_to_mine("agent-a", "mine-a")
        first = store.submit_and_analyze(
            _submission(first_id),
            agent_id="agent-a",
            idempotency_key="monthly-2026-01",
            exchange_message=first_exchange,
        )
        replay = store.submit_and_analyze(
            _submission(first_id),
            agent_id="agent-a",
            idempotency_key="monthly-2026-01",
            exchange_message=first_exchange,
        )
        assert replay.run_id == first.run_id
        assert replay.idempotent_replay is True

        second_id = str(uuid4())
        conflicting_exchange = first_exchange.model_copy(
            update={
                "message_id": second_id,
                "body": {"message_id": second_id, "payload": {"version": 2}},
            }
        )
        with pytest.raises(RegulatoryV2ConflictError, match="idempotency"):
            store.submit_and_analyze(
                _submission(second_id),
                agent_id="agent-a",
                idempotency_key="monthly-2026-01",
                exchange_message=conflicting_exchange,
            )

        assert len(store.list_submissions(mine_id="mine-a")) == 1
        with pytest.raises(RegulatoryV2NotFoundError):
            store.get_exchange_message(
                second_id, mine_id="mine-a", direction="inbound"
            )
        assert any(
            item.event_type == "inbox_idempotency_conflict_rejected"
            for item in store.list_audit_events(limit=100)
        )


def test_nonce_replay_survives_store_and_core_tables_are_append_only() -> None:
    with RegulatoryV2Store(":memory:", now=lambda: NOW) as store:
        expiry = NOW + timedelta(minutes=10)
        assert store.claim_transport_nonce(
            "agent-a", "nonce-1", request_time=NOW, expires_at=expiry
        )
        assert not store.claim_transport_nonce(
            "agent-a", "nonce-1", request_time=NOW, expires_at=expiry
        )
        receipt = store.submit_and_analyze(_submission(str(uuid4())))
        assert (
            store.get_submission_receipt(receipt.submission_id).run_id == receipt.run_id
        )
        assert store.list_mine_overviews()[0].mine_id == "mine-a"
        assert store.mine_detail_projection("mine-a").daily_facts
        assert store.verify_integrity()

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._connection.execute(  # noqa: SLF001 - verifies DB enforcement
                "UPDATE v2_analysis_runs SET decision = 'risk' WHERE run_id = ?",
                (receipt.run_id,),
            )
