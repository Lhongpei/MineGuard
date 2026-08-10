from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
import sqlite3
from typing import Literal
from uuid import uuid4

import pytest

import mineguard.regulatory_v2_store as regulatory_store_module
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
    RegulatoryV2IntegrityError,
    RegulatoryV2NotFoundError,
    RegulatoryV2SchemaVersionError,
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


def _record_exchange_audit(
    store: RegulatoryV2Store,
    *,
    mine_id: str,
    direction: Literal["inbound", "outbound"],
    marker: str,
) -> None:
    store.record_exchange_message(
        ExchangeMessageInput(
            message_id=str(uuid4()),
            direction=direction,
            message_type="test_exchange",
            mine_id=mine_id,
            body={"marker": marker},
            exchanged_at=NOW,
        )
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
            store.submit_and_analyze(_submission(str(uuid4()), start=date(2026, 1, 2)))
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

        first = store.submit_and_analyze(_submission(str(uuid4()), mine_id="current-a"))
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
            store.get_exchange_message(second_id, mine_id="mine-a", direction="inbound")
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


def test_transport_nonce_rows_have_a_strict_per_sender_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        regulatory_store_module,
        "_MAX_ACTIVE_TRANSPORT_NONCES_PER_SENDER",
        2,
    )
    with RegulatoryV2Store(tmp_path / "bounded-nonces.sqlite3", now=lambda: NOW) as store:
        expiry = NOW + timedelta(minutes=10)
        assert store.claim_transport_nonce(
            "agent-a", "bounded-nonce-1", request_time=NOW, expires_at=expiry
        )
        assert store.claim_transport_nonce(
            "agent-a", "bounded-nonce-2", request_time=NOW, expires_at=expiry
        )
        assert not store.claim_transport_nonce(
            "agent-a", "bounded-nonce-3", request_time=NOW, expires_at=expiry
        )
        assert store.claim_transport_nonce(
            "agent-b", "bounded-nonce-1", request_time=NOW, expires_at=expiry
        )
        assert (
            store._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM v2_transport_nonces WHERE sender_id='agent-a'"
            ).fetchone()[0]
            == 2
        )


def test_schema_migration_ledger_is_explicit_and_append_only(tmp_path: Path) -> None:
    database = tmp_path / "schema-ledger.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW) as store:
        status = store.schema_status()
        assert status["current_version"] == status["supported_version"] == 1
        assert [item["version"] for item in status["migrations"]] == [1]
        assert len(status["migrations"][0]["checksum"]) == 64
        assert store._connection.execute("PRAGMA user_version").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store._connection.execute(
                "UPDATE v2_schema_migrations SET checksum = ? WHERE version = 1",
                ("0" * 64,),
            )


def test_pre_ledger_v2_database_requires_explicit_offline_exact_adoption(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-v2.sqlite3"
    submission_id = str(uuid4())
    with RegulatoryV2Store(database, now=lambda: NOW) as store:
        store.submit_and_analyze(_submission(submission_id))
        store._connection.execute("DROP TRIGGER v2_schema_migrations_no_update")
        store._connection.execute("DROP TRIGGER v2_schema_migrations_no_delete")
        store._connection.execute("DROP TABLE v2_schema_migrations")
        store._connection.execute("PRAGMA user_version = 0")

    with pytest.raises(RegulatoryV2SchemaVersionError, match="ledger is missing"):
        RegulatoryV2Store(database, now=lambda: NOW)
    with pytest.raises(RegulatoryV2SchemaVersionError, match="forbidden"):
        RegulatoryV2Store(
            database,
            now=lambda: NOW,
            production_mode=True,
            allow_legacy_schema_adoption=True,
        )

    # Adoption is a deliberate offline step.  Only the exact pre-ledger V2
    # fingerprint is accepted; production can open it only after that step.
    with RegulatoryV2Store(
        database,
        now=lambda: NOW,
        allow_legacy_schema_adoption=True,
    ) as adopted:
        assert adopted.get_submission(submission_id).submission_id == submission_id

    with RegulatoryV2Store(database, now=lambda: NOW, production_mode=True) as upgraded:
        assert upgraded.schema_status()["current_version"] == 1
        assert upgraded.get_submission(submission_id).submission_id == submission_id
        assert upgraded.verify_integrity() is True


def test_missing_ledger_on_any_other_nonempty_database_fails_without_writes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "unrelated-nonempty.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.execute("INSERT INTO unrelated VALUES ('keep-me')")

    with pytest.raises(RegulatoryV2SchemaVersionError, match="ledger is missing"):
        RegulatoryV2Store(database, now=lambda: NOW)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT value FROM unrelated").fetchone()[0] == "keep-me"
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name GLOB 'v2_*'"
            ).fetchone()[0]
            == 0
        )


def test_managed_schema_rejects_noop_trigger_extra_or_weakened_index(
    tmp_path: Path,
) -> None:
    noop_database = tmp_path / "noop-trigger.sqlite3"
    with RegulatoryV2Store(noop_database, now=lambda: NOW) as store:
        store._connection.execute("DROP TRIGGER v2_audit_events_no_update")
        store._connection.execute(
            """
            CREATE TRIGGER v2_audit_events_no_update
            BEFORE UPDATE ON v2_audit_events BEGIN SELECT 1; END
            """
        )
    with pytest.raises(RegulatoryV2IntegrityError, match="trigger integrity"):
        RegulatoryV2Store(noop_database, now=lambda: NOW)

    extra_database = tmp_path / "extra-index.sqlite3"
    with RegulatoryV2Store(extra_database, now=lambda: NOW) as store:
        store._connection.execute(
            "CREATE INDEX injected_v2_submission_index "
            "ON v2_submissions(received_at)"
        )
    with pytest.raises(RegulatoryV2SchemaVersionError, match="schema contract"):
        RegulatoryV2Store(extra_database, now=lambda: NOW)

    weak_database = tmp_path / "weak-index.sqlite3"
    with RegulatoryV2Store(weak_database, now=lambda: NOW) as store:
        store._connection.execute("DROP INDEX idx_v2_submissions_mine_period")
        store._connection.execute(
            "CREATE INDEX idx_v2_submissions_mine_period "
            "ON v2_submissions(mine_id)"
        )
    with pytest.raises(RegulatoryV2SchemaVersionError, match="schema contract"):
        RegulatoryV2Store(weak_database, now=lambda: NOW)


def test_managed_schema_rejects_weakened_check_constraint(tmp_path: Path) -> None:
    database = tmp_path / "weak-check.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW):
        pass
    with sqlite3.connect(database) as connection:
        original = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='v2_submissions'"
        ).fetchone()[0]
        weakened = original.replace(
            "revision INTEGER NOT NULL CHECK (revision >= 1)",
            "revision INTEGER NOT NULL",
        )
        assert weakened != original
        schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
        connection.execute("PRAGMA writable_schema=ON")
        connection.execute(
            "UPDATE sqlite_master SET sql=? "
            "WHERE type='table' AND name='v2_submissions'",
            (weakened,),
        )
        connection.commit()
        connection.execute(f"PRAGMA schema_version={schema_version + 1}")
        connection.execute("PRAGMA writable_schema=OFF")

    with pytest.raises(RegulatoryV2SchemaVersionError, match="schema contract"):
        RegulatoryV2Store(database, now=lambda: NOW)


def test_unknown_future_schema_is_rejected_before_current_schema_changes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "future-v2.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW) as store:
        store._connection.execute(
            """
            INSERT INTO v2_schema_migrations(
                version, migration_id, checksum, applied_at
            ) VALUES (2, 'future-migration', ?, ?)
            """,
            ("f" * 64, NOW.isoformat()),
        )
        store._connection.execute("PRAGMA user_version = 2")

    with pytest.raises(RegulatoryV2SchemaVersionError, match="newer"):
        RegulatoryV2Store(database, now=lambda: NOW)
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert (
            connection.execute(
                "SELECT migration_id FROM v2_schema_migrations WHERE version = 2"
            ).fetchone()[0]
            == "future-migration"
        )


def test_production_write_rejects_runtime_future_schema_marker(tmp_path: Path) -> None:
    database = tmp_path / "runtime-future-v2.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW, production_mode=True) as store:
        store._connection.execute(
            """
            INSERT INTO v2_schema_migrations(
                version, migration_id, checksum, applied_at
            ) VALUES (2, 'future-runtime-migration', ?, ?)
            """,
            ("e" * 64, NOW.isoformat()),
        )
        store._connection.execute("PRAGMA user_version = 2")
        with pytest.raises(RegulatoryV2SchemaVersionError, match="newer"):
            store.claim_transport_nonce(
                "agent-a",
                "nonce-after-future-upgrade",
                request_time=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM v2_transport_nonces"
            ).fetchone()[0]
            == 0
        )


def test_production_start_and_subsequent_writes_fail_closed_on_broken_audit_chain(
    tmp_path: Path,
) -> None:
    database = tmp_path / "production-integrity.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW) as store:
        store.record_security_event(
            event_type="machine_authentication_failed",
            request_method="POST",
            request_path="/v2/five-quantity-submissions",
            remote_address="127.0.0.1",
        )
        store._connection.execute("DROP TRIGGER v2_audit_events_no_update")
        store._connection.execute(
            "UPDATE v2_audit_events SET event_hash = ? WHERE sequence = 1",
            ("f" * 64,),
        )

    with pytest.raises(RegulatoryV2IntegrityError, match="audit chain"):
        RegulatoryV2Store(database, now=lambda: NOW, production_mode=True)

    # A production process which was healthy at startup also rechecks before
    # every transaction, so post-start tampering cannot admit even a nonce.
    runtime_database = tmp_path / "production-runtime.sqlite3"
    with RegulatoryV2Store(
        runtime_database, now=lambda: NOW, production_mode=True
    ) as store:
        store.record_security_event(
            event_type="machine_authentication_failed",
            request_method="GET",
            request_path="/v2/analysis-reports/next",
            remote_address="127.0.0.1",
        )
        store._connection.execute("DROP TRIGGER v2_audit_events_no_update")
        store._connection.execute(
            "UPDATE v2_audit_events SET event_hash = ? WHERE sequence = 1",
            ("e" * 64,),
        )
        with pytest.raises(RegulatoryV2IntegrityError, match="write refused"):
            store.claim_transport_nonce(
                "agent-a",
                "nonce-after-tamper",
                request_time=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
        assert (
            store._connection.execute(
                "SELECT COUNT(*) FROM v2_transport_nonces"
            ).fetchone()[0]
            == 0
        )


def test_production_full_integrity_rejects_orphaned_foreign_keys(
    tmp_path: Path,
) -> None:
    startup_database = tmp_path / "orphan-at-startup.sqlite3"
    with RegulatoryV2Store(startup_database, now=lambda: NOW):
        pass
    with sqlite3.connect(startup_database) as external:
        external.execute("PRAGMA foreign_keys = OFF")
        external.execute(
            """
            INSERT INTO v2_finding_events(
                event_id, finding_id, event_type, payload_json, occurred_at
            ) VALUES ('orphan-startup-event', 'missing-finding', 'issued', '{}', ?)
            """,
            (NOW.isoformat(),),
        )
        assert external.execute("PRAGMA foreign_key_check").fetchone() is not None

    with pytest.raises(RegulatoryV2IntegrityError, match="integrity check failed"):
        RegulatoryV2Store(
            startup_database,
            now=lambda: NOW,
            production_mode=True,
        )

    runtime_database = tmp_path / "orphan-at-runtime.sqlite3"
    with RegulatoryV2Store(
        runtime_database,
        now=lambda: NOW,
        production_mode=True,
    ) as store:
        trusted_checkpoint = store._integrity_checkpoint  # noqa: SLF001
        assert trusted_checkpoint is not None
        with sqlite3.connect(runtime_database) as external:
            external.execute("PRAGMA foreign_keys = OFF")
            external.execute(
                """
                INSERT INTO v2_finding_events(
                    event_id, finding_id, event_type, payload_json, occurred_at
                ) VALUES (
                    'orphan-runtime-event', 'missing-finding', 'issued', '{}', ?
                )
                """,
                (NOW.isoformat(),),
            )

        assert store.verify_integrity() is False
        assert store._integrity_failed is True  # noqa: SLF001
        assert store._integrity_checkpoint == trusted_checkpoint  # noqa: SLF001
        assert store.verify_runtime_integrity() is False


def test_production_startup_rejects_sqlite_quick_check_failure(
    tmp_path: Path,
) -> None:
    database = tmp_path / "sqlite-structure-damage.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW):
        pass

    image = bytearray(database.read_bytes())
    assert image[:16] == b"SQLite format 3\x00"
    freelist_count = int.from_bytes(image[36:40], "big")
    image[36:40] = (freelist_count + 1).to_bytes(4, "big")
    database.write_bytes(image)

    with sqlite3.connect(database) as probe:
        quick_check = [tuple(row) for row in probe.execute("PRAGMA quick_check")]
    assert quick_check != [("ok",)]

    with pytest.raises(RegulatoryV2IntegrityError, match="integrity check failed"):
        RegulatoryV2Store(database, now=lambda: NOW, production_mode=True)


def test_production_integrity_fast_path_does_not_rescan_large_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "large-production-history.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW) as seed:
        for index in range(750):
            seed.record_security_event(
                event_type="machine_authentication_failed",
                request_method="POST",
                request_path="/v2/five-quantity-submissions",
                remote_address=f"10.0.{index // 256}.{index % 256}",
            )

    with RegulatoryV2Store(database, now=lambda: NOW, production_mode=True) as store:
        full_scan_count = 0
        original = store._run_full_integrity_check_locked  # noqa: SLF001

        def counted_full_scan() -> bool:
            nonlocal full_scan_count
            full_scan_count += 1
            return original()

        monkeypatch.setattr(
            store,
            "_run_full_integrity_check_locked",
            counted_full_scan,
        )
        for index in range(100):
            assert store.verify_runtime_integrity() is True
            assert store.claim_transport_nonce(
                "agent-a",
                f"large-history-nonce-{index}",
                request_time=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
        for _ in range(25):
            store.record_security_event(
                event_type="machine_authentication_failed",
                request_method="GET",
                request_path="/v2/analysis-reports/next",
                remote_address="127.0.0.1",
            )

        assert full_scan_count == 0
        assert store.verify_audit_chain() is True


def test_production_runtime_detects_external_tamper_even_after_trigger_recreated(
    tmp_path: Path,
) -> None:
    database = tmp_path / "external-tamper.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW, production_mode=True) as store:
        store.record_security_event(
            event_type="machine_authentication_failed",
            request_method="POST",
            request_path="/v2/five-quantity-submissions",
            remote_address="127.0.0.1",
        )
        with sqlite3.connect(database) as external:
            external.execute("DROP TRIGGER v2_audit_events_no_update")
            external.execute(
                "UPDATE v2_audit_events SET event_hash=? WHERE sequence=1",
                ("d" * 64,),
            )
            external.execute(
                """
                CREATE TRIGGER v2_audit_events_no_update
                BEFORE UPDATE ON v2_audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'v2_audit_events is append-only');
                END
                """
            )

        assert store.verify_runtime_integrity() is False
        # Integrity failure is deliberately latched; a later marker match or
        # repair cannot make this process resume writes without a restart.
        assert store.verify_runtime_integrity() is False
        with pytest.raises(RegulatoryV2IntegrityError, match="write refused"):
            store.claim_transport_nonce(
                "agent-a",
                "external-tamper-nonce",
                request_time=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )


def test_production_runtime_rejects_every_external_append_after_checkpoint(
    tmp_path: Path,
) -> None:
    binding_database = tmp_path / "external-binding-append.sqlite3"
    with RegulatoryV2Store(
        binding_database, now=lambda: NOW, production_mode=True
    ) as store:
        with sqlite3.connect(binding_database) as external:
            external.execute(
                """
                INSERT INTO v2_agent_mine_bindings(agent_id, mine_id, created_at)
                VALUES ('forged-agent', 'forged-mine', ?)
                """,
                (NOW.isoformat(),),
            )
        assert store.verify_runtime_integrity() is False
        assert store._integrity_failed is True  # noqa: SLF001
        assert store.verify_runtime_integrity() is False

    audit_database = tmp_path / "external-audit-append.sqlite3"
    with RegulatoryV2Store(
        audit_database, now=lambda: NOW, production_mode=True
    ) as store:
        # A second, internally self-consistent store represents an out-of-band
        # writer capable of producing a perfectly valid public SHA-256 chain.
        with RegulatoryV2Store(audit_database, now=lambda: NOW) as external:
            external.record_security_event(
                event_type="machine_authentication_failed",
                request_method="GET",
                request_path="/v2/analysis-reports/next",
                remote_address="127.0.0.2",
            )
        assert store.verify_runtime_integrity() is False
        assert store._integrity_failed is True  # noqa: SLF001


def test_production_runtime_latches_external_migration_ledger_deletion(
    tmp_path: Path,
) -> None:
    database = tmp_path / "external-ledger-delete.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW, production_mode=True) as store:
        with sqlite3.connect(database) as external:
            external.executescript(
                """
                DROP TRIGGER v2_schema_migrations_no_update;
                DROP TRIGGER v2_schema_migrations_no_delete;
                DELETE FROM v2_schema_migrations;
                CREATE TRIGGER v2_schema_migrations_no_update
                BEFORE UPDATE ON v2_schema_migrations
                BEGIN
                    SELECT RAISE(ABORT, 'v2_schema_migrations is append-only');
                END;
                CREATE TRIGGER v2_schema_migrations_no_delete
                BEFORE DELETE ON v2_schema_migrations
                BEGIN
                    SELECT RAISE(ABORT, 'v2_schema_migrations is append-only');
                END;
                """
            )
        assert store.verify_runtime_integrity() is False
        assert store._integrity_failed is True  # noqa: SLF001
        with pytest.raises(RegulatoryV2IntegrityError, match="write refused"):
            store.claim_transport_nonce(
                "agent-a",
                "nonce-after-ledger-delete",
                request_time=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )

    with pytest.raises(RegulatoryV2SchemaVersionError, match="migration|ledger"):
        RegulatoryV2Store(database, now=lambda: NOW, production_mode=True)


def test_production_rejects_unexpected_trigger_before_it_can_run(
    tmp_path: Path,
) -> None:
    database = tmp_path / "unexpected-trigger.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW, production_mode=True) as store:
        store._connection.execute(  # noqa: SLF001 - simulate injected schema
            """
            CREATE TRIGGER injected_binding_side_effect
            AFTER INSERT ON v2_audit_events
            BEGIN
                INSERT OR IGNORE INTO v2_agent_mine_bindings(
                    agent_id, mine_id, created_at
                ) VALUES ('injected-agent', 'injected-mine',
                          '2026-01-01T00:00:00+00:00');
            END
            """
        )
        with pytest.raises(RegulatoryV2IntegrityError, match="write refused"):
            store.record_security_event(
                event_type="machine_authentication_failed",
                request_method="GET",
                request_path="/v2/analysis-reports/next",
                remote_address="127.0.0.1",
            )
        assert (
            store._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM v2_agent_mine_bindings "
                "WHERE agent_id = 'injected-agent'"
            ).fetchone()[0]
            == 0
        )


def test_production_runtime_and_restart_reject_deleted_append_only_trigger(
    tmp_path: Path,
) -> None:
    database = tmp_path / "deleted-trigger.sqlite3"
    with RegulatoryV2Store(database, now=lambda: NOW, production_mode=True) as store:
        with sqlite3.connect(database) as external:
            external.execute("DROP TRIGGER v2_submissions_no_delete")
        assert store.verify_runtime_integrity() is False

    with pytest.raises(RegulatoryV2IntegrityError, match="trigger integrity"):
        RegulatoryV2Store(database, now=lambda: NOW, production_mode=True)


def test_audit_page_snapshot_has_no_duplicates_or_gaps_after_concurrent_append(
    tmp_path: Path,
) -> None:
    clock = [NOW]
    database = tmp_path / "audit-page.sqlite3"
    with (
        RegulatoryV2Store(database, now=lambda: clock[0]) as reader,
        RegulatoryV2Store(database, now=lambda: clock[0]) as writer,
    ):
        for index in range(7):
            clock[0] = NOW + timedelta(minutes=index)
            _record_exchange_audit(
                writer,
                mine_id="mine-a",
                direction="inbound",
                marker=f"original-{index}",
            )

        first = reader.list_audit_events_page(limit=3)
        assert [item.sequence for item in first.items] == [7, 6, 5]
        assert first.snapshot_sequence == 7
        assert first.matched_count == 7
        assert first.has_more is True
        assert first.next_before_sequence == 5

        # This append represents an event arriving while a user is browsing.
        clock[0] = NOW + timedelta(minutes=8)
        _record_exchange_audit(
            writer,
            mine_id="mine-a",
            direction="inbound",
            marker="new-after-snapshot",
        )

        second = reader.list_audit_events_page(
            snapshot_sequence=first.snapshot_sequence,
            before_sequence=first.next_before_sequence,
            limit=3,
        )
        third = reader.list_audit_events_page(
            snapshot_sequence=second.snapshot_sequence,
            before_sequence=second.next_before_sequence,
            limit=3,
        )

        combined = [*first.items, *second.items, *third.items]
        assert [item.sequence for item in combined] == list(range(7, 0, -1))
        assert len({item.event_id for item in combined}) == 7
        assert second.matched_count == third.matched_count == 7
        assert second.next_before_sequence == 2
        assert third.has_more is False
        assert third.next_before_sequence is None
        assert reader.list_audit_events_page(limit=1).items[0].sequence == 8


def test_audit_page_combines_scope_event_and_half_open_time_filters() -> None:
    clock = [NOW]
    fixtures: list[tuple[str, Literal["inbound", "outbound"]]] = [
        ("mine-a", "inbound"),
        ("mine-a", "outbound"),
        ("mine-b", "inbound"),
        ("mine-a", "inbound"),
        ("mine-b", "outbound"),
    ]
    with RegulatoryV2Store(":memory:", now=lambda: clock[0]) as store:
        for index, (mine_id, direction) in enumerate(fixtures):
            clock[0] = NOW + timedelta(hours=index)
            _record_exchange_audit(
                store,
                mine_id=mine_id,
                direction=direction,
                marker=f"event-{index}",
            )

        page = store.list_audit_events_page(
            mine_ids=["mine-a", "mine-a"],
            event_types=["exchange_inbound_recorded"],
            occurred_from=NOW,
            occurred_before=NOW + timedelta(hours=3),
        )
        assert page.snapshot_sequence == 5
        assert page.matched_count == 1
        assert [item.sequence for item in page.items] == [1]
        assert page.items[0].occurred_at == NOW

        boundary_page = store.list_audit_events_page(
            event_types=["exchange_inbound_recorded"],
            occurred_from=NOW + timedelta(hours=2),
            occurred_before=NOW + timedelta(hours=4),
        )
        assert [item.sequence for item in boundary_page.items] == [4, 3]

        empty_scope = store.list_audit_events_page(mine_ids=[])
        assert empty_scope.snapshot_sequence == 5
        assert empty_scope.matched_count == 0
        assert empty_scope.items == []
        assert empty_scope.has_more is False
        assert empty_scope.next_before_sequence is None

        assert store.list_audit_events_page(event_types=[]).matched_count == 0
        assert store.list_audit_events_page(mine_ids=None).matched_count == 5

        with pytest.raises(ValueError, match="timezone-aware"):
            store.list_audit_events_page(occurred_from=datetime(2026, 1, 1))
        with pytest.raises(ValueError, match="must be before"):
            store.list_audit_events_page(
                occurred_from=NOW + timedelta(days=1),
                occurred_before=NOW,
            )


def test_audit_page_query_indexes_exist() -> None:
    with RegulatoryV2Store(":memory:") as store:
        rows = store._connection.execute(  # noqa: SLF001 - schema assertion
            "PRAGMA index_list(v2_audit_events)"
        ).fetchall()
        names = {row["name"] for row in rows}

        expected = {
            "idx_v2_audit_mine_sequence": ["mine_id", "sequence"],
            "idx_v2_audit_event_sequence": ["event_type", "sequence"],
            "idx_v2_audit_occurred_sequence": ["occurred_at", "sequence"],
        }
        columns = {
            name: [
                row["name"]
                for row in store._connection.execute(  # noqa: SLF001
                    f"PRAGMA index_info({name})"
                ).fetchall()
            ]
            for name in expected
        }

    assert expected.keys() <= names
    assert columns == expected
