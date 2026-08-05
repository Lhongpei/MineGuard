from __future__ import annotations

from datetime import date
from http.client import HTTPConnection
import json
from pathlib import Path
from threading import Thread

import pytest

from mineguard.regulatory_v2 import DecisionStatus
from mineguard.regulatory_v2_demo import (
    SYNTHETIC_ONLY_DISCLAIMER,
    SYNTHETIC_ONLY_SCHEMA_VERSION,
    SYNTHETIC_DEMO_DISCLAIMER,
    V2_DEMO_MINES,
    V2_DEMO_SCHEMA_VERSION,
    V2_DEMO_STATE_MARKER,
    V2_WORKBOOK_DEMO_MINES,
    V2DemoSeedError,
    V2DemoSeedResult,
    V2DemoStateOwnershipError,
    _build_day,
    _build_plan,
    _build_workbook_example_plan,
    _load_workbook_example,
    claim_v2_demo_state_directory,
    seed_v2_demo,
    seed_v2_demo_state,
    v2_demo_status,
)
from mineguard.regulatory_v2_store import RegulatoryV2Store
from mineguard.regulatory_v2_http import create_server


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


def test_seed_has_eight_synthetic_mines_plus_two_one_month_workbook_mines(
    seeded_demo: tuple[Path, V2DemoSeedResult],
) -> None:
    database, result = seeded_demo
    assert result.status == "seeded"
    assert result.synthetic_demo is True
    assert result.disclaimer == SYNTHETIC_DEMO_DISCLAIMER
    assert result.demo_dataset is True
    assert result.contains_workbook_examples is True
    assert result.mine_count == 10
    assert result.submission_count == 26
    assert result.decision_counts == {
        "insufficient_data": 1,
        "normal_candidate": 20,
        "risk": 5,
    }
    assert result.period_start == date(2026, 5, 1)
    assert result.period_end == date(2026, 7, 31)

    with RegulatoryV2Store(database) as store:
        overviews = store.list_mine_overviews()
        assert len(overviews) == 10
        overview_names = {item.mine_id: item.mine_name for item in overviews}
        assert all(
            overview_names[mine.mine_id].startswith("【合成演示】")
            for mine in V2_DEMO_MINES
        )
        assert {
            mine.mine_id: overview_names[mine.mine_id]
            for mine in V2_WORKBOOK_DEMO_MINES
        } == {
            "DEMO-WORKBOOK-TAIYUE-001": "太岳矿",
            "DEMO-WORKBOOK-GENGYANG-002": "梗阳矿",
        }
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
        for mine in V2_WORKBOOK_DEMO_MINES:
            submissions = store.list_submissions(mine_id=mine.mine_id, limit=10)
            facts = store.list_daily_facts(mine.mine_id, limit=1_000)
            assert len(submissions) == 1
            assert submissions[0]["mine_name"] == mine.mine_name
            assert (
                submissions[0]["period_start"],
                submissions[0]["period_end"],
            ) == ("2026-07-01", "2026-07-31")
            assert len(facts) == 31
            assert (facts[0]["date"], facts[-1]["date"]) == (
                "2026-07-31",
                "2026-07-01",
            )

        exchanges = store.list_exchange_messages(limit=1_000)
        assert len(exchanges) == 26
        synthetic = [item for item in exchanges if item.body["synthetic_demo"]]
        workbook = [
            item for item in exchanges if item.body.get("workbook_example") is True
        ]
        assert len(synthetic) == 24
        assert len(workbook) == 2
        assert all(item.body["not_enterprise_signed"] is True for item in exchanges)
        assert all(
            item.body["disclaimer"] == SYNTHETIC_ONLY_DISCLAIMER
            for item in synthetic
        )
        assert all(
            item.body["disclaimer"] == SYNTHETIC_DEMO_DISCLAIMER
            for item in workbook
        )
        assert {
            item.body["mine_display_name"]: item.body["source_sha256"]
            for item in workbook
        } == {
            "太岳矿": (
                "a83ca156886c4ee8443825e14126f0dad"
                "731898951447f5a951e2570787530a9"
            ),
            "梗阳矿": (
                "5c1a0dde50965f9b3f8605676bc792fa"
                "3b74d28ec90bba23182f759cfb1341f6"
            ),
        }
        assert all(
            item.body["source_value_policy"]
            == "source_cells_only_no_fill_interpolation_or_date_shift"
            for item in workbook
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


def test_workbook_values_are_exact_one_month_source_mappings(
    seeded_demo: tuple[Path, V2DemoSeedResult],
) -> None:
    root = Path(__file__).resolve().parents[2]
    source_files = {
        "taiyue-2026-07.et": root / "local _test" / "五量基础数据测试.et",
        "gengyang-2026-07.et": (
            root / "local _test" / "五量基础数据测试（沁源梗阳）.et"
        ),
    }
    bundled_root = root / "platform" / "src" / "mineguard" / "demo_samples"
    for bundled_name, source in source_files.items():
        assert (bundled_root / bundled_name).read_bytes() == source.read_bytes()

    plan = {item.mine.mine_name: item for item in _build_workbook_example_plan()}
    assert set(plan) == {"太岳矿", "梗阳矿"}
    for mine in V2_WORKBOOK_DEMO_MINES:
        imported = _load_workbook_example(mine)
        submission = plan[mine.mine_name].submission
        assert [item.date for item in submission.days] == [
            item.date for item in imported.days
        ] == [date(2026, 7, day) for day in range(1, 32)]
        for source_day, mapped_day in zip(
            imported.days,
            submission.days,
            strict=True,
        ):
            assert mapped_day.ventilation_m3_min.daily_total == source_day.ventilation
            for mapped, source in (
                (mapped_day.mine_entry_persons, source_day.labor),
                (mapped_day.electricity_kwh, source_day.electricity),
                (mapped_day.production_t, source_day.production),
            ):
                assert mapped.shifts is not None
                assert (
                    mapped.shifts.zero_shift,
                    mapped.shifts.eight_shift,
                    mapped.shifts.four_shift,
                    mapped.daily_total,
                ) == (
                    source.zero_shift,
                    source.eight_shift,
                    source.four_shift,
                    source.daily_total,
                )
            for field, mapped in (
                ("detonators", mapped_day.detonators_count),
                ("explosives", mapped_day.explosives_kg),
            ):
                assert mapped.shifts is not None
                assert (
                    mapped.shifts.zero_shift,
                    mapped.shifts.eight_shift,
                    mapped.shifts.four_shift,
                    mapped.daily_total,
                ) == tuple(
                    getattr(value, field)
                    for value in (
                        source_day.explosives.zero_shift,
                        source_day.explosives.eight_shift,
                        source_day.explosives.four_shift,
                        source_day.explosives.daily_total,
                    )
                )

    taiyue = plan["太岳矿"].submission
    gengyang = plan["梗阳矿"].submission
    assert all(item.declared_operating_state == "unknown" for item in taiyue.days)
    assert all(item.declared_operating_state == "unknown" for item in gengyang.days)
    assert all(item.ventilation_m3_min.shifts is None for item in taiyue.days)
    assert all(item.ventilation_m3_min.shifts is None for item in gengyang.days)

    taiyue_first = taiyue.days[0]
    assert taiyue_first.ventilation_m3_min.daily_total == 15_522
    assert taiyue_first.mine_entry_persons.daily_total == 527
    assert taiyue_first.electricity_kwh.daily_total == pytest.approx(133_418.73)
    assert taiyue_first.electricity_kwh.shifts is not None
    assert taiyue_first.electricity_kwh.shifts.provided_count == 0
    assert taiyue_first.production_t.daily_total == 0
    assert taiyue_first.detonators_count.daily_total == 0
    assert taiyue_first.explosives_kg.daily_total == 0
    taiyue_30 = taiyue.days[29]
    assert taiyue_30.electricity_kwh.daily_total is None
    assert taiyue_30.production_t.daily_total == pytest.approx(7_349.8)
    assert taiyue_30.production_t.shifts is not None
    assert (
        taiyue_30.production_t.shifts.zero_shift,
        taiyue_30.production_t.shifts.eight_shift,
        taiyue_30.production_t.shifts.four_shift,
    ) == pytest.approx((3_653.6, 80.5, 3_615.7))
    assert all(
        value is None
        for quantity in taiyue.days[30].quantities().values()
        for value in (
            quantity.daily_total,
            *(
                ()
                if quantity.shifts is None
                else (
                    quantity.shifts.zero_shift,
                    quantity.shifts.eight_shift,
                    quantity.shifts.four_shift,
                )
            ),
        )
    )
    assert sum(
        "formula_cached_value"
        in day.quality["production_t"].daily_total
        for day in taiyue.days
    ) == 30

    gengyang_first = gengyang.days[0]
    assert gengyang_first.ventilation_m3_min.daily_total == 8_017
    assert gengyang_first.mine_entry_persons.daily_total == 576
    assert gengyang_first.electricity_kwh.daily_total == pytest.approx(89_053.8)
    assert gengyang_first.electricity_kwh.shifts is not None
    assert (
        gengyang_first.electricity_kwh.shifts.zero_shift,
        gengyang_first.electricity_kwh.shifts.eight_shift,
        gengyang_first.electricity_kwh.shifts.four_shift,
    ) == pytest.approx((35_872.3, 15_348.6, 37_832.9))
    assert gengyang_first.production_t.daily_total == 4_504
    gengyang_13 = gengyang.days[12]
    assert gengyang_13.electricity_kwh.daily_total == 45_707
    assert gengyang_13.electricity_kwh.shifts is not None
    assert sum(
        value
        for value in (
            gengyang_13.electricity_kwh.shifts.zero_shift,
            gengyang_13.electricity_kwh.shifts.eight_shift,
            gengyang_13.electricity_kwh.shifts.four_shift,
        )
        if value is not None
    ) == pytest.approx(56_212)
    gengyang_last = gengyang.days[30]
    assert gengyang_last.ventilation_m3_min.daily_total == 8_068
    assert gengyang_last.detonators_count.daily_total == 0
    assert gengyang_last.explosives_kg.daily_total == 0
    assert gengyang_last.mine_entry_persons.daily_total is None
    assert gengyang_last.electricity_kwh.daily_total is None
    assert gengyang_last.production_t.daily_total is None

    database, _ = seeded_demo
    with RegulatoryV2Store(database) as store:
        taiyue_result = _latest_result(store, taiyue.mine_id)
        gengyang_result = _latest_result(store, gengyang.mine_id)
        assert taiyue_result.coverage.complete_day_count == 29
        assert taiyue_result.decision is DecisionStatus.NORMAL_CANDIDATE
        assert gengyang_result.coverage.complete_day_count == 30
        assert gengyang_result.decision is DecisionStatus.RISK
        mismatch = [
            signal
            for signal in gengyang_result.data_quality_signals
            if signal.code == "daily_shift_arithmetic_mismatch"
        ]
        assert [(item.date, item.metric) for item in mismatch] == [
            (date(2026, 7, 13), "electricity_kwh")
        ]
        for mine in (taiyue, gengyang):
            run = store.list_runs(mine_id=mine.mine_id, limit=1)[0]
            assert not run["baseline_eligible"]
            assert not run["baseline_reference_candidate"]
            result = _latest_result(store, mine.mine_id)
            assert result.references.same_mine_history_day_count == 0
            assert result.references.accepted_peer_bands == []


def test_leadership_api_exposes_both_workbook_mines_and_null_gaps(
    seeded_demo: tuple[Path, V2DemoSeedResult],
    tmp_path: Path,
) -> None:
    database, _ = seeded_demo
    server = create_server(
        "127.0.0.1",
        0,
        database_path=database,
        auth_database_path=tmp_path / "auth.db",
        auth_required=False,
        clients={},
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request("GET", "/v2/regulatory/mines")
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == 200
        rows = {item["mine_id"]: item for item in payload["items"]}
        assert len(rows) == 10
        assert rows["DEMO-WORKBOOK-TAIYUE-001"]["mine_name"] == "太岳矿"
        assert rows["DEMO-WORKBOOK-GENGYANG-002"]["mine_name"] == "梗阳矿"

        for mine_id, mine_name in (
            ("DEMO-WORKBOOK-TAIYUE-001", "太岳矿"),
            ("DEMO-WORKBOOK-GENGYANG-002", "梗阳矿"),
        ):
            connection.request("GET", f"/v2/regulatory/mines/{mine_id}")
            detail_response = connection.getresponse()
            detail = json.loads(detail_response.read())
            assert detail_response.status == 200
            assert detail["mine"]["mine_name"] == mine_name
            assert detail["latest_submission"]["report_month"] == "2026-07"
            disclosure = detail["latest_submission"]["source_disclosure"]
            assert disclosure["data_origin"] == "bundled_workbook_values"
            assert disclosure["label"] == "ET样表原值（未企业签名）"
            assert disclosure["source_value_policy"] == (
                "source_cells_only_no_fill_interpolation_or_date_shift"
            )
            assert disclosure["units_verified"] is False
            assert disclosure["identity_verified"] is False
            assert len(detail["daily_series"]) == 31
            assert detail["daily_series"][0]["date"] == "2026-07-01"
            assert detail["daily_series"][-1]["date"] == "2026-07-31"

        connection.request(
            "GET", "/v2/regulatory/mines/DEMO-WORKBOOK-TAIYUE-001"
        )
        taiyue = json.loads(connection.getresponse().read())
        assert taiyue["daily_series"][-1]["production_t"] is None
        assert taiyue["daily_series"][-1]["electricity_kwh"] is None

        connection.request(
            "GET", "/v2/regulatory/mines/DEMO-WORKBOOK-GENGYANG-002"
        )
        gengyang = json.loads(connection.getresponse().read())
        assert gengyang["daily_series"][12]["electricity_kwh"] == 45_707
        assert gengyang["daily_series"][-1]["ventilation_m3_min"] == 8_068
        assert gengyang["daily_series"][-1]["production_t"] is None
        assert gengyang["daily_series"][-1]["detonators_count"] == 0
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_normal_demo_has_six_distinct_nonconstant_daily_trajectories() -> None:
    """The normalised chart must not hide fixed-ratio series behind output."""

    mine = V2_DEMO_MINES[1]
    rows = [
        _build_day(
            mine,
            date(2026, 7, day),
            month_index=2,
            day_index=day - 1,
            mine_index=1,
        )
        for day in range(1, 32)
    ]
    metric_series = {
        metric: [float(getattr(row, metric).daily_total) for row in rows]
        for metric in (
            "ventilation_m3_min",
            "electricity_kwh",
            "detonators_count",
            "explosives_kg",
            "mine_entry_persons",
            "production_t",
        )
    }
    normalised: dict[str, tuple[float, ...]] = {}
    for metric, values in metric_series.items():
        lower, upper = min(values), max(values)
        assert upper > lower, metric
        assert len(set(values)) >= (4 if metric == "detonators_count" else 8)
        normalised[metric] = tuple(
            round((value - lower) / (upper - lower), 6) for value in values
        )

    assert len(set(normalised.values())) == len(normalised)
    for left_index, left in enumerate(normalised):
        for right in tuple(normalised)[left_index + 1 :]:
            mean_absolute_distance = sum(
                abs(a - b)
                for a, b in zip(normalised[left], normalised[right], strict=True)
            ) / len(rows)
            assert mean_absolute_distance >= 0.10, (left, right)


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
        assert replay.replayed_submission_count == 26
        assert len(store.list_submissions(limit=1_000)) == 26
        assert len(store.list_exchange_messages(limit=1_000)) == exchange_count
        assert len(store.list_audit_events(limit=1_000)) == audit_count
        assert store.verify_audit_chain()
        status = v2_demo_status(store, through_month=THROUGH_MONTH)
        assert status.status == "complete"
        assert status.recorded_submission_count == 26
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
    with pytest.raises(V2DemoSeedError, match="不能早于 2026-07"):
        claim_v2_demo_state_directory(
            tmp_path / "too-early",
            through_month=date(2026, 6, 30),
        )

    owned = claim_v2_demo_state_directory(
        tmp_path / "owned",
        through_month=THROUGH_MONTH,
    )
    assert (owned / V2_DEMO_STATE_MARKER).is_file()
    assert claim_v2_demo_state_directory(owned, through_month=THROUGH_MONTH) == owned
    with pytest.raises(V2DemoStateOwnershipError, match="另一数据月份"):
        claim_v2_demo_state_directory(owned, through_month=date(2026, 8, 31))

    legacy = tmp_path / "legacy-v1"
    legacy.mkdir()
    (legacy / V2_DEMO_STATE_MARKER).write_text(
        json.dumps(
            {
                "schema_version": "mineguard-regulatory-v2-synthetic-demo-v1",
                "synthetic_demo": True,
                "through_month": THROUGH_MONTH.isoformat(),
                "database": "mineguard.db",
                "disclaimer": SYNTHETIC_DEMO_DISCLAIMER,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    with pytest.raises(V2DemoStateOwnershipError, match="标记版本"):
        claim_v2_demo_state_directory(legacy, through_month=THROUGH_MONTH)


def test_demo_seed_claims_only_an_empty_platform_owned_state(
    tmp_path: Path,
) -> None:
    install_root = tmp_path / "MineGuard" / "Platform"
    state = install_root / "state" / "local-demo"
    state.mkdir(parents=True)
    platform_marker = state / ".mineguard-platform-state.json"
    platform_marker.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "product": "MineGuard Platform State",
                "initializedFor": str(install_root),
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    result = seed_v2_demo_state(state, through_month=THROUGH_MONTH)

    assert Path(result.state_directory) == state.resolve()
    assert Path(result.database_path).is_file()
    assert platform_marker.is_file()
    assert (state / V2_DEMO_STATE_MARKER).is_file()


@pytest.mark.parametrize("extra_name", ["mineguard.db", "other.txt"])
def test_demo_seed_rejects_platform_marker_beside_existing_content(
    tmp_path: Path,
    extra_name: str,
) -> None:
    install_root = tmp_path / "MineGuard" / "Platform"
    state = install_root / "state" / "local-demo"
    state.mkdir(parents=True)
    (state / ".mineguard-platform-state.json").write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "product": "MineGuard Platform State",
                "initializedFor": str(install_root),
            }
        ),
        encoding="utf-8",
    )
    existing = state / extra_name
    existing.write_text("do not overwrite", encoding="utf-8")

    with pytest.raises(V2DemoStateOwnershipError, match="拒绝写入"):
        claim_v2_demo_state_directory(state, through_month=THROUGH_MONTH)

    assert existing.read_text(encoding="utf-8") == "do not overwrite"
    assert not (state / V2_DEMO_STATE_MARKER).exists()


def test_owned_legacy_24_submission_state_resumes_with_only_two_samples(
    tmp_path: Path,
) -> None:
    state = tmp_path / "legacy-owned"
    state.mkdir()
    legacy_marker = {
        "schema_version": SYNTHETIC_ONLY_SCHEMA_VERSION,
        "synthetic_demo": True,
        "through_month": THROUGH_MONTH.isoformat(),
        "database": "mineguard.db",
        "disclaimer": SYNTHETIC_ONLY_DISCLAIMER,
    }
    (state / V2_DEMO_STATE_MARKER).write_text(
        json.dumps(legacy_marker, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with RegulatoryV2Store(state / "mineguard.db") as store:
        for item in _build_plan(THROUGH_MONTH)[:24]:
            store.bind_agent_to_mine(item.agent_id, item.mine.mine_id)
            store.submit_and_analyze(
                item.submission,
                agent_id=item.agent_id,
                idempotency_key=item.submission.submission_id,
                exchange_message=item.exchange,
            )
        assert len(store.list_submissions(limit=1_000)) == 24

    resumed = seed_v2_demo_state(state, through_month=THROUGH_MONTH)
    assert resumed.status == "resumed"
    assert resumed.created_submission_count == 2
    assert resumed.replayed_submission_count == 24
    assert json.loads(
        (state / V2_DEMO_STATE_MARKER).read_text(encoding="utf-8")
    )["schema_version"] == V2_DEMO_SCHEMA_VERSION
    with RegulatoryV2Store(state / "mineguard.db") as store:
        assert len(store.list_submissions(limit=1_000)) == 26
        assert store.verify_audit_chain()
