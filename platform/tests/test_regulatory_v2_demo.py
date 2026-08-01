from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from mineguard.regulatory_v2 import DecisionStatus
from mineguard.regulatory_v2_demo import (
    SYNTHETIC_DEMO_DISCLAIMER,
    V2_DEMO_MINES,
    V2_DEMO_STATE_MARKER,
    V2DemoSeedResult,
    V2DemoStateOwnershipError,
    claim_v2_demo_state_directory,
    seed_v2_demo,
    v2_demo_status,
)
from mineguard.regulatory_v2_store import RegulatoryV2Store


THROUGH_MONTH = date(2026, 7, 31)


@pytest.fixture(scope="module")
def seeded_demo(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, V2DemoSeedResult]:
    database = tmp_path_factory.mktemp("regulatory-v2-demo") / "mineguard.db"
    with RegulatoryV2Store(database) as store:
        result = seed_v2_demo(store, through_month=THROUGH_MONTH)
    return database, result


def _latest_result(store: RegulatoryV2Store, mine_id: str):
    latest = store.list_submissions(mine_id=mine_id, limit=1)[0]
    run = next(
        item
        for item in store.list_runs(mine_id=mine_id, limit=10)
        if item["submission_id"] == latest["submission_id"]
    )
    return store.get_run(run["run_id"])


def test_seed_has_eight_explicitly_synthetic_mines_and_monthly_daily_rows(
    seeded_demo: tuple[Path, V2DemoSeedResult],
) -> None:
    database, result = seeded_demo
    assert result.status == "seeded"
    assert result.synthetic_demo is True
    assert result.disclaimer == SYNTHETIC_DEMO_DISCLAIMER
    assert result.mine_count == 8
    assert result.submission_count == 24
    assert result.period_start == date(2026, 5, 1)
    assert result.period_end == date(2026, 7, 31)

    with RegulatoryV2Store(database) as store:
        overviews = store.list_mine_overviews()
        assert len(overviews) == 8
        assert all(item.mine_name.startswith("【合成演示】") for item in overviews)
        for mine in V2_DEMO_MINES:
            submissions = store.list_submissions(mine_id=mine.mine_id, limit=10)
            facts = store.list_daily_facts(mine.mine_id, limit=1_000)
            assert len(submissions) == 3
            assert [
                (item["period_start"], item["period_end"])
                for item in reversed(submissions)
            ] == [
                ("2026-05-01", "2026-05-31"),
                ("2026-06-01", "2026-06-30"),
                ("2026-07-01", "2026-07-31"),
            ]
            assert len(facts) == 92

        exchanges = store.list_exchange_messages(limit=1_000)
        assert len(exchanges) == 24
        assert all(item.body["synthetic_demo"] is True for item in exchanges)
        assert all(item.body["not_enterprise_signed"] is True for item in exchanges)
        assert all(
            item.body["disclaimer"] == SYNTHETIC_DEMO_DISCLAIMER for item in exchanges
        )
        assert store.verify_audit_chain()


def test_real_engine_produces_each_teaching_scenario(
    seeded_demo: tuple[Path, V2DemoSeedResult],
) -> None:
    database, _ = seeded_demo
    with RegulatoryV2Store(database) as store:
        for mine_id in (
            "SYNTH-DEMO-REF-001",
            "SYNTH-DEMO-REF-002",
            "SYNTH-DEMO-REF-003",
        ):
            assert (
                _latest_result(store, mine_id).decision
                is DecisionStatus.NORMAL_CANDIDATE
            )

        mismatch = _latest_result(store, "SYNTH-DEMO-SHIFT-004")
        assert mismatch.decision is DecisionStatus.RISK
        assert "daily_shift_arithmetic_mismatch" in {
            item.code for item in mismatch.data_quality_signals
        }
        assert mismatch.reconciliation.minimal_conflict_sets

        drift = _latest_result(store, "SYNTH-DEMO-DRIFT-005")
        assert drift.decision is DecisionStatus.RISK
        drift_codes = {item.code for item in drift.temporal_signals}
        assert "sustained_ratio_drift" in drift_codes
        assert "retrospective_change_point" in drift_codes
        # The cold-start month remains quarantined; only independently
        # anchored prior periods may enter formal same-mine history.
        assert drift.references.same_mine_history_day_count >= 28

        peer = _latest_result(store, "SYNTH-DEMO-PEER-006")
        assert peer.decision is DecisionStatus.RISK
        assert peer.references.same_mine_history_day_count == 0
        assert peer.references.accepted_peer_bands
        assert (
            min(item.mine_count or 0 for item in peer.references.accepted_peer_bands)
            >= 3
        )
        assert all(
            item.basis == "anonymous_peer"
            for item in peer.references.accepted_peer_bands
        )

        missing = _latest_result(store, "SYNTH-DEMO-MISSING-007")
        assert missing.decision is DecisionStatus.INSUFFICIENT_DATA
        assert missing.coverage.expected_day_count == 31
        assert missing.coverage.complete_day_count == 21
        assert "qualified_measurement_requires_review" in {
            item.code for item in missing.data_quality_signals
        }
        missing_facts = store.list_daily_facts(
            "SYNTH-DEMO-MISSING-007",
            date_from=date(2026, 7, 5),
            date_to=date(2026, 7, 14),
            limit=100,
        )
        assert len(missing_facts) == 10
        assert all(fact["production_t"] is None for fact in missing_facts)
        assert all(fact["electricity_kwh"] is None for fact in missing_facts)

        restart = _latest_result(store, "SYNTH-DEMO-RESTART-008")
        assert restart.decision is DecisionStatus.NORMAL_CANDIDATE
        states = {item.state.value for item in restart.day_states}
        assert "non_production_candidate" in states
        assert "restart_ramp_candidate" in states
        assert "production" in states


def test_repeated_seed_is_idempotent_and_does_not_extend_audit_chain(
    seeded_demo: tuple[Path, V2DemoSeedResult],
) -> None:
    database, _ = seeded_demo
    with RegulatoryV2Store(database) as store:
        audit_count = len(store.list_audit_events(limit=1_000))
        exchange_count = len(store.list_exchange_messages(limit=1_000))
        replay = seed_v2_demo(store, through_month=THROUGH_MONTH)
        assert replay.status == "already_seeded"
        assert replay.created_submission_count == 0
        assert replay.replayed_submission_count == 24
        assert len(store.list_submissions(limit=1_000)) == 24
        assert len(store.list_exchange_messages(limit=1_000)) == exchange_count
        assert len(store.list_audit_events(limit=1_000)) == audit_count
        assert store.verify_audit_chain()
        status = v2_demo_status(store, through_month=THROUGH_MONTH)
        assert status.status == "complete"
        assert status.recorded_submission_count == 24
        assert status.remaining_submission_count == 0
        assert status.audit_chain_valid is True


def test_demo_state_marker_refuses_non_owned_or_different_month(
    tmp_path: Path,
) -> None:
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "real-data.db").write_text("do not touch", encoding="utf-8")
    with pytest.raises(V2DemoStateOwnershipError, match="非空"):
        claim_v2_demo_state_directory(occupied, through_month=THROUGH_MONTH)
    assert (occupied / "real-data.db").read_text(encoding="utf-8") == "do not touch"

    owned = claim_v2_demo_state_directory(
        tmp_path / "owned",
        through_month=THROUGH_MONTH,
    )
    assert (owned / V2_DEMO_STATE_MARKER).is_file()
    assert claim_v2_demo_state_directory(owned, through_month=THROUGH_MONTH) == owned
    with pytest.raises(V2DemoStateOwnershipError, match="另一数据月份"):
        claim_v2_demo_state_directory(owned, through_month=date(2026, 8, 31))
