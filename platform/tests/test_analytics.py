from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mineguard.analytics import (
    MineRiskRanking,
    calculate_leadership_analytics,
)


def _batch(
    batch_id: str,
    created_at: str,
    items: list[tuple[str, str, str]],
) -> dict[str, object]:
    return {
        "batch_id": batch_id,
        "created_at": created_at,
        "request": {
            "batch_id": batch_id,
            "expected_mine_ids": [mine_id for mine_id, _, _ in items],
        },
        # Deliberately bogus persisted totals: analytics must recompute them.
        "response": {
            "expected_mine_count": 999,
            "received_mine_count": 999,
            "items": [
                {
                    "mine_id": mine_id,
                    "technical_status": status,
                    "review_priority": priority,
                }
                for mine_id, status, priority in items
            ],
        },
    }


def _case(
    case_id: str,
    mine_id: str,
    batch_id: str,
    created_at: str,
    *,
    status: str = "pending",
    priority: str = "P1",
    issue_code: str = "production_conflict",
    updated_at: str | None = None,
    approval_at: str | None = None,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "mine_id": mine_id,
        "batch_id": batch_id,
        "created_at": created_at,
        "updated_at": updated_at or created_at,
        "approval_at": approval_at,
        "workflow_status": status,
        "priority": priority,
        "issue_code": issue_code,
    }


def _event(
    case_id: str,
    sequence: int,
    action: str,
    created_at: str,
    before: str,
    after: str,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "sequence": sequence,
        "action": action,
        "created_at": created_at,
        "before": {"workflow_status": before},
        "after": {"workflow_status": after},
    }


def test_scope_is_a_security_boundary_and_totals_are_recomputed() -> None:
    batches = [
        _batch(
            "B1",
            "2026-07-01T16:30:00Z",
            [
                ("M001", "inconsistent", "P1"),
                ("M002", "not_received", "DATA"),
            ],
        )
    ]
    cases = [
        _case("C1", "M001", "B1", "2026-07-01T16:31:00Z"),
        _case("C2", "M002", "B1", "not-a-time"),
    ]
    events = [
        _event(
            "C1",
            1,
            "created",
            "2026-07-01T16:31:00Z",
            "pending",
            "pending",
        ),
        # The unauthorized malformed event must not affect quality counters.
        {
            "case_id": "C2",
            "sequence": 1,
            "action": "created",
            "created_at": "not-a-time",
        },
    ]

    report = calculate_leadership_analytics(
        batches,
        cases,
        events,
        mine_ids={"M001"},
        start_at="2026-07-01T00:00:00Z",
        end_at="2026-07-02T23:59:59Z",
        as_of="2026-07-02T23:59:59Z",
    )

    assert report.scoped_mine_ids == ["M001"]
    assert report.expected_report_count == 1
    assert report.received_report_count == 1
    assert report.coverage_rate == 1
    assert [point.day.isoformat() for point in report.daily_trend] == [
        "2026-07-01",
        "2026-07-02",
        "2026-07-03",
    ]
    july_second = report.daily_trend[1]
    assert july_second.batch_count == 1
    assert july_second.inconsistent_reports == 1
    assert july_second.not_received_reports == 0
    assert {item.mine_id for item in report.mine_risk_ranking} == {"M001"}
    assert report.data_quality.ignored_cases_with_invalid_time == 0
    assert report.data_quality.ignored_events_with_invalid_time == 0
    assert "M002" not in report.model_dump_json()


def test_repeated_anomalies_and_ranking_are_order_independent() -> None:
    batches = [
        _batch(
            "B1",
            "2026-07-01T00:00:00Z",
            [
                ("M001", "inconsistent", "P1"),
                ("M002", "consistent", "NONE"),
            ],
        ),
        _batch(
            "B2",
            "2026-07-02T00:00:00Z",
            [
                ("M001", "inconsistent", "P2"),
                ("M002", "inconclusive", "DATA"),
            ],
        ),
        _batch(
            "B3",
            "2026-07-03T00:00:00Z",
            [
                ("M001", "consistent", "NONE"),
                ("M002", "consistent", "NONE"),
            ],
        ),
    ]
    cases = [
        _case("C1", "M001", "B1", "2026-07-01T01:00:00Z"),
        _case(
            "C2",
            "M001",
            "B2",
            "2026-07-02T01:00:00Z",
            priority="P2",
        ),
    ]
    arguments = {
        "start_at": "2026-07-01T00:00:00Z",
        "end_at": "2026-07-04T00:00:00Z",
        "as_of": "2026-07-04T00:00:00Z",
        "timezone": "UTC",
    }

    forward = calculate_leadership_analytics(
        batches,
        cases,
        [],
        **arguments,
    )
    reversed_input = calculate_leadership_analytics(
        list(reversed(batches)),
        list(reversed(cases)),
        [],
        **arguments,
    )

    assert forward.model_dump() == reversed_input.model_dump()
    repeated = forward.repeated_anomalies
    assert len(repeated) == 1
    assert repeated[0].mine_id == "M001"
    assert repeated[0].anomaly_code == "production_conflict"
    assert repeated[0].distinct_batch_count == 2
    assert forward.mine_risk_ranking[0].mine_id == "M001"
    assert forward.mine_risk_ranking[0].risk_level == "high"
    assert (
        forward.mine_risk_ranking[0].consecutive_abnormal_reports == 0
    )


def test_case_cycles_response_and_backlog_performance() -> None:
    cases = [
        _case(
            "C1",
            "M001",
            "B1",
            "2026-07-01T00:00:00Z",
            status="closed",
            updated_at="2026-07-10T00:00:00Z",
            approval_at="2026-07-10T00:00:00Z",
        ),
        _case(
            "C2",
            "M001",
            "B0",
            "2026-05-20T00:00:00Z",
            status="waiting_data",
            priority="P2",
            issue_code="data_insufficient",
            updated_at="2026-05-21T00:00:00Z",
        ),
        _case(
            "C3",
            "M002",
            "B2",
            "2026-07-02T00:00:00Z",
            status="pending_approval",
            updated_at="2026-07-03T00:00:00Z",
        ),
    ]
    events = {
        "C1": [
            _event(
                "C1",
                1,
                "created",
                "2026-07-01T00:00:00Z",
                "pending",
                "pending",
            ),
            _event(
                "C1",
                2,
                "start_review",
                "2026-07-02T00:00:00Z",
                "pending",
                "reviewing",
            ),
            _event(
                "C1",
                3,
                "approve",
                "2026-07-04T00:00:00Z",
                "reviewing",
                "closed",
            ),
            _event(
                "C1",
                4,
                "reopen",
                "2026-07-05T00:00:00Z",
                "closed",
                "reviewing",
            ),
            _event(
                "C1",
                5,
                "approve",
                "2026-07-10T00:00:00Z",
                "reviewing",
                "closed",
            ),
        ],
        "C2": [
            _event(
                "C2",
                1,
                "created",
                "2026-05-20T00:00:00Z",
                "pending",
                "pending",
            ),
            _event(
                "C2",
                2,
                "request_data",
                "2026-05-21T00:00:00Z",
                "pending",
                "waiting_data",
            ),
        ],
        "C3": [
            _event(
                "C3",
                1,
                "created",
                "2026-07-02T00:00:00Z",
                "pending",
                "pending",
            ),
            _event(
                "C3",
                2,
                "submit_conclusion",
                "2026-07-03T00:00:00Z",
                "pending",
                "pending_approval",
            ),
        ],
    }

    report = calculate_leadership_analytics(
        [],
        cases,
        events,
        start_at="2026-07-01T00:00:00Z",
        end_at="2026-07-12T00:00:00Z",
        as_of="2026-07-12T00:00:00Z",
        timezone="UTC",
    )
    performance = report.case_performance

    assert performance.new_case_count == 2
    assert performance.closed_case_count == 1
    assert performance.closed_cycle_count == 2
    assert performance.reopened_case_count == 1
    assert performance.resolved_new_case_count == 1
    assert performance.new_case_resolution_rate == 0.5
    assert performance.open_backlog_count == 2
    assert performance.pending_approval_count == 1
    assert performance.backlog_status_counts == {
        "pending": 0,
        "reviewing": 0,
        "waiting_data": 1,
        "pending_approval": 1,
    }
    assert performance.average_closure_hours == 96
    assert performance.median_closure_hours == 96
    assert performance.p90_closure_hours == 120
    assert performance.closure_duration_buckets["1-3天"] == 1
    assert performance.closure_duration_buckets["3-7天"] == 1
    assert performance.average_first_response_hours == 24
    assert performance.responded_within_24h_rate == 1
    assert performance.oldest_backlog_days == 53
    assert performance.backlog_age_buckets["31-60天"] == 1
    assert performance.backlog_age_buckets["8-15天"] == 1
    assert report.data_quality.inferred_closure_timestamps == 0


def test_missing_times_are_counted_only_inside_scope_and_closure_can_infer() -> None:
    batches = [
        _batch("bad-visible", "naive-or-invalid", [("M001", "consistent", "NONE")]),
        _batch("bad-hidden", "naive-or-invalid", [("M002", "consistent", "NONE")]),
    ]
    cases = [
        _case(
            "C1",
            "M001",
            "B1",
            "2026-07-01T00:00:00Z",
            status="closed",
            updated_at="2026-07-02T00:00:00Z",
            approval_at="2026-07-02T00:00:00Z",
        ),
        _case("bad", "M001", "B2", "2026-07-01T00:00:00"),
        _case("hidden", "M002", "B3", "invalid"),
    ]
    events = [
        {
            "case_id": "C1",
            "sequence": 1,
            "action": "created",
            "created_at": "invalid",
        },
        {
            "case_id": "hidden",
            "sequence": 1,
            "action": "created",
            "created_at": "invalid",
        },
    ]

    report = calculate_leadership_analytics(
        batches,
        cases,
        events,
        mine_ids={"M001"},
        start_at="2026-07-01T00:00:00Z",
        end_at="2026-07-03T00:00:00Z",
        as_of="2026-07-03T00:00:00Z",
        timezone="UTC",
    )

    assert report.data_quality.ignored_batches_with_invalid_time == 1
    assert report.data_quality.ignored_cases_with_invalid_time == 1
    assert report.data_quality.ignored_events_with_invalid_time == 1
    assert report.data_quality.inferred_closure_timestamps == 1
    assert report.case_performance.closed_cycle_count == 1
    assert report.case_performance.open_backlog_count == 0


def test_empty_scope_and_validation_do_not_leak_records() -> None:
    report = calculate_leadership_analytics(
        [_batch("B1", "invalid", [("M001", "inconsistent", "P1")])],
        [_case("C1", "M001", "B1", "invalid")],
        [],
        mine_ids=set(),
        start_at=datetime(2026, 7, 1, tzinfo=UTC),
        end_at=datetime(2026, 7, 2, tzinfo=UTC),
        timezone="UTC",
    )

    assert report.scoped_mine_ids == []
    assert report.expected_report_count == 0
    assert report.mine_risk_ranking == []
    assert report.data_quality.ignored_batches_with_invalid_time == 0
    assert report.data_quality.ignored_cases_with_invalid_time == 0

    with pytest.raises(ValueError, match="timezone-aware"):
        calculate_leadership_analytics(
            [],
            [],
            [],
            start_at=datetime(2026, 7, 1),
        )
    with pytest.raises(ValueError, match="unknown timezone"):
        calculate_leadership_analytics([], [], [], timezone="Mars/Olympus")
    with pytest.raises(ValueError, match="repeat_threshold"):
        calculate_leadership_analytics(
            [],
            [],
            [],
            repeat_threshold=1,
        )


def test_risk_score_is_normalized_by_expected_report_exposure() -> None:
    sparse = [
        _batch(
            "S1",
            "2026-07-31T00:00:00Z",
            [("M001", "solver_error", "DATA")],
        ),
        _batch(
            "S2",
            "2026-07-31T00:00:00Z",
            [("M001", "consistent", "NONE")],
        ),
    ]
    frequent = [
        _batch(
            f"F{copy}-{kind}",
            "2026-07-31T00:00:00Z",
            [
                (
                    "M001",
                    "solver_error" if kind == "bad" else "consistent",
                    "DATA" if kind == "bad" else "NONE",
                )
            ],
        )
        for copy in range(5)
        for kind in ("bad", "good")
    ]
    arguments = {
        "start_at": "2026-07-01T00:00:00Z",
        "end_at": "2026-08-01T00:00:00Z",
        "as_of": "2026-08-01T00:00:00Z",
        "timezone": "UTC",
    }

    sparse_risk = calculate_leadership_analytics(
        sparse,
        [],
        [],
        **arguments,
    ).mine_risk_ranking[0]
    frequent_risk = calculate_leadership_analytics(
        frequent,
        [],
        [],
        **arguments,
    ).mine_risk_ranking[0]

    assert sparse_risk.expected_reports == 2
    assert frequent_risk.expected_reports == 10
    assert sparse_risk.risk_score == frequent_risk.risk_score
    assert (
        sparse_risk.risk_score_breakdown.report_signal_score
        == frequent_risk.risk_score_breakdown.report_signal_score
    )


def test_recent_report_risk_has_more_weight_than_old_report_risk() -> None:
    arguments = {
        "start_at": "2026-07-01T00:00:00Z",
        "end_at": "2026-08-01T00:00:00Z",
        "as_of": "2026-08-01T00:00:00Z",
        "timezone": "UTC",
    }
    old = calculate_leadership_analytics(
        [
            _batch(
                "old",
                "2026-07-04T00:00:00Z",
                [("M001", "solver_error", "DATA")],
            )
        ],
        [],
        [],
        **arguments,
    ).mine_risk_ranking[0]
    recent = calculate_leadership_analytics(
        [
            _batch(
                "recent",
                "2026-08-01T00:00:00Z",
                [("M001", "solver_error", "DATA")],
            )
        ],
        [],
        [],
        **arguments,
    ).mine_risk_ranking[0]

    assert recent.risk_score > old.risk_score
    assert (
        recent.risk_score_breakdown.report_signal_score
        > old.risk_score_breakdown.report_signal_score
    )


def test_risk_score_is_capped_at_100_with_separate_case_contributions() -> None:
    batches = [
        _batch(
            f"B{index}",
            "2026-08-01T00:00:00Z",
            [("M001", "inconsistent", "P1")],
        )
        for index in range(10)
    ]
    cases = [
        _case(
            f"P1-{index}",
            "M001",
            f"BP1-{index}",
            "2026-06-01T00:00:00Z",
            status="pending_approval",
            priority="P1",
        )
        for index in range(10)
    ] + [
        _case(
            f"P2-{index}",
            "M001",
            f"BP2-{index}",
            "2026-06-01T00:00:00Z",
            status="pending_approval",
            priority="P2",
        )
        for index in range(10)
    ]

    risk = calculate_leadership_analytics(
        batches,
        cases,
        [],
        start_at="2026-06-01T00:00:00Z",
        end_at="2026-08-01T00:00:00Z",
        as_of="2026-08-01T00:00:00Z",
        timezone="UTC",
    ).mine_risk_ranking[0]

    assert risk.risk_score == 100
    assert risk.risk_score_breakdown.final_score == 100
    assert risk.risk_score_breakdown.uncapped_total == 100
    assert risk.risk_score_breakdown.open_p1_score == 18
    assert risk.risk_score_breakdown.open_p2_score == 7
    assert risk.risk_score_breakdown.pending_approval_score == 5
    assert risk.risk_score_breakdown.overdue_backlog_score == 10


def test_missing_report_never_becomes_normal_even_after_long_decay() -> None:
    risk = calculate_leadership_analytics(
        [
            _batch(
                "missing",
                "2020-01-01T00:00:00Z",
                [("M001", "not_received", "DATA")],
            )
        ],
        [],
        [],
        start_at="2020-01-01T00:00:00Z",
        end_at="2026-08-01T00:00:00Z",
        as_of="2026-08-01T00:00:00Z",
        timezone="UTC",
    ).mine_risk_ranking[0]

    assert risk.received_reports == 0
    assert risk.risk_score == 1
    assert risk.risk_level == "low"
    assert any("不会按正常处理" in reason for reason in risk.reasons)


def test_future_records_do_not_leak_into_risk_and_new_fields_default() -> None:
    report = calculate_leadership_analytics(
        [
            _batch(
                "current",
                "2026-07-01T00:00:00Z",
                [("M001", "consistent", "NONE")],
            ),
            _batch(
                "future",
                "2026-07-03T00:00:00Z",
                [("M001", "inconsistent", "P1")],
            ),
        ],
        [],
        [],
        start_at="2026-07-01T00:00:00Z",
        end_at="2026-07-02T00:00:00Z",
        as_of="2026-07-04T00:00:00Z",
        timezone="UTC",
    )
    risk = report.mine_risk_ranking[0]

    assert risk.expected_reports == 1
    assert risk.risk_score == 0
    assert risk.risk_level == "normal"
    assert risk.risk_algorithm_version == "2.1.0"

    legacy_payload = risk.model_dump(
        exclude={"risk_algorithm_version", "risk_score_breakdown"}
    )
    restored = MineRiskRanking.model_validate(legacy_payload)
    assert restored.risk_algorithm_version == "2.1.0"
    assert restored.risk_score_breakdown.final_score == 0
