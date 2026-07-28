from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import mineguard.portfolio as portfolio_module
from mineguard.models import DataQualityResult
from mineguard.models import ProductionAnalysisRequest
from mineguard.models import ProductionAnalysisResult
from mineguard.portfolio import PortfolioAnalysisRequest
from mineguard.portfolio import analyze_production_portfolio


ROOT = Path(__file__).resolve().parents[1]


def load_request(name: str, mine_id: str) -> ProductionAnalysisRequest:
    payload = json.loads((ROOT / "examples" / name).read_text())
    payload["mine_id"] = mine_id
    return ProductionAnalysisRequest.model_validate(payload)


def result_for(
    request: ProductionAnalysisRequest,
    *,
    status: str,
    grade: str,
    gap: float | None = None,
) -> ProductionAnalysisResult:
    quality_status = (
        "blocked" if status in {"inconclusive", "solver_error"} else "sufficient"
    )
    is_inconsistent = status == "inconsistent"
    supports_positive_gap = (
        is_inconsistent and gap is not None and gap > 0
    )
    return ProductionAnalysisResult(
        mine_id=request.mine_id,
        status=status,
        data_quality=DataQualityResult(
            score=0 if quality_status == "blocked" else 100,
            status=quality_status,
        ),
        solver_status=f"test_{status}",
        evidence_grade=grade,
        minimum_reported_gap=gap,
        robust_minimum_reported_gap=gap,
        priority_scenario_count=1 if is_inconsistent else 0,
        all_priority_scenarios_support_positive_gap=(
            supports_positive_gap
        ),
        scenario_union_production_range=(
            (gap or 0.0, gap or 0.0)
            if is_inconsistent and gap is not None
            else None
        ),
    )


def test_portfolio_keeps_missing_mines_and_sorts_by_priority() -> None:
    request = PortfolioAnalysisRequest(
        batch_id="batch-20260726",
        portfolio_name="北部辖区",
        expected_mine_ids=["M001", "M002", "M003"],
        analyses=[
            load_request("production_consistent.json", "M002"),
            load_request("production_inconsistent.json", "M001"),
        ],
    )

    result = analyze_production_portfolio(request)

    assert result.expected_mine_count == 3
    assert result.received_mine_count == 2
    assert result.coverage_rate == pytest.approx(2 / 3)
    assert [item.mine_id for item in result.items] == [
        "M001",
        "M003",
        "M002",
    ]
    assert [item.review_priority for item in result.items] == [
        "P1",
        "DATA",
        "NONE",
    ]

    p1 = result.items[0]
    assert p1.technical_status == "inconsistent"
    assert p1.evidence_grade == "A"
    assert p1.minimum_required_gap == pytest.approx(1993.5)
    assert p1.analysis is not None
    assert p1.window_start == request.analyses[1].window_start
    assert p1.window_end == request.analyses[1].window_end

    missing = result.items[1]
    assert missing.technical_status == "not_received"
    assert missing.analysis is None
    assert missing.evidence_grade is None
    assert missing.window_start is None
    assert missing.window_end is None

    assert result.technical_status_counts == {
        "not_received": 1,
        "consistent": 1,
        "inconsistent": 1,
        "inconclusive": 0,
        "solver_error": 0,
    }
    assert result.review_priority_counts == {
        "P1": 1,
        "P2": 0,
        "DATA": 1,
        "NONE": 1,
    }
    assert "覆盖率 66.7%" in result.summary
    assert "P1 1 座" in result.summary


def test_priority_rules_cover_every_technical_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_mines = [
        "p1",
        "p2-zero-gap",
        "p2-grade-b",
        "inconclusive",
        "solver-error",
        "consistent",
        "not-received",
    ]
    analyses = [
        load_request("production_consistent.json", mine_id)
        for mine_id in expected_mines[:-1]
    ]
    specifications = {
        "p1": ("inconsistent", "A", 10.0),
        "p2-zero-gap": ("inconsistent", "A", 0.0),
        "p2-grade-b": ("inconsistent", "B", 10.0),
        "inconclusive": ("inconclusive", "D", None),
        "solver-error": ("solver_error", "D", None),
        "consistent": ("consistent", "C", 0.0),
    }

    def fake_analysis(
        analysis_request: ProductionAnalysisRequest,
    ) -> ProductionAnalysisResult:
        status, grade, gap = specifications[analysis_request.mine_id]
        return result_for(
            analysis_request,
            status=status,
            grade=grade,
            gap=gap,
        )

    monkeypatch.setattr(
        portfolio_module,
        "analyze_production",
        fake_analysis,
    )

    result = analyze_production_portfolio(
        PortfolioAnalysisRequest(
            batch_id="priority-rules",
            portfolio_name="规则测试",
            expected_mine_ids=expected_mines,
            analyses=analyses,
        )
    )

    assert [
        (item.mine_id, item.technical_status, item.review_priority)
        for item in result.items
    ] == [
        ("p1", "inconsistent", "P1"),
        ("p2-zero-gap", "inconsistent", "P2"),
        ("p2-grade-b", "inconsistent", "P2"),
        ("inconclusive", "inconclusive", "DATA"),
        ("solver-error", "solver_error", "DATA"),
        ("not-received", "not_received", "DATA"),
        ("consistent", "consistent", "NONE"),
    ]
    assert result.technical_status_counts == {
        "not_received": 1,
        "consistent": 1,
        "inconsistent": 3,
        "inconclusive": 1,
        "solver_error": 1,
    }
    assert result.review_priority_counts == {
        "P1": 1,
        "P2": 2,
        "DATA": 3,
        "NONE": 1,
    }


def test_consistent_result_requires_verified_sufficient_quality_for_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mine_ids = ["degraded", "unverified", "verified"]
    analyses = [
        load_request("production_consistent.json", mine_id)
        for mine_id in mine_ids
    ]
    results = {
        mine_id: result_for(
            analysis,
            status="consistent",
            grade="C",
            gap=0.0,
        )
        for mine_id, analysis in zip(mine_ids, analyses, strict=True)
    }
    results["degraded"].data_quality = DataQualityResult(
        score=79,
        status="degraded",
    )
    results["unverified"].data_quality = DataQualityResult(
        score=95,
        status="degraded",
        unverified_dimensions=[
            "obs-1:device_health",
            "obs-1:clock",
        ],
    )

    monkeypatch.setattr(
        portfolio_module,
        "analyze_production",
        lambda analysis_request: results[analysis_request.mine_id],
    )

    result = analyze_production_portfolio(
        PortfolioAnalysisRequest(
            batch_id="quality-review-closure",
            portfolio_name="质量复核闭环",
            expected_mine_ids=mine_ids,
            analyses=analyses,
        )
    )
    items = {item.mine_id: item for item in result.items}

    assert items["degraded"].review_priority == "DATA"
    assert "技术模型一致" in items["degraded"].summary
    assert "数据质量处于降级状态" in items["degraded"].summary
    assert "抽查" in items["degraded"].summary
    assert "无需" not in items["degraded"].summary

    assert items["unverified"].review_priority == "DATA"
    assert "技术模型一致" in items["unverified"].summary
    assert "设备健康、时钟同步未验证" in items["unverified"].summary
    assert "补充验证证据" in items["unverified"].summary
    assert "抽查" in items["unverified"].summary
    assert "无需" not in items["unverified"].summary

    assert items["verified"].review_priority == "NONE"
    assert "无需进入人工复核队列" in items["verified"].summary
    assert result.review_priority_counts == {
        "P1": 0,
        "P2": 0,
        "DATA": 2,
        "NONE": 1,
    }


def test_p1_requires_complete_consensus_across_priority_scenarios(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyses = [
        load_request("production_consistent.json", mine_id)
        for mine_id in ("consensus", "divergent", "unbounded", "no-mcs")
    ]

    results = {
        "consensus": result_for(
            analyses[0],
            status="inconsistent",
            grade="A",
            gap=10,
        ),
        "divergent": result_for(
            analyses[1],
            status="inconsistent",
            grade="A",
            gap=10,
        ),
        "unbounded": result_for(
            analyses[2],
            status="inconsistent",
            grade="D",
            gap=None,
        ),
        "no-mcs": result_for(
            analyses[3],
            status="inconsistent",
            grade="D",
            gap=None,
        ),
    }
    results["divergent"].priority_scenario_count = 2
    results["divergent"].scenario_conclusion_divergent = True
    results["divergent"].all_priority_scenarios_support_positive_gap = False
    results["unbounded"].priority_scenario_count = 1
    results["unbounded"].scenario_union_production_range = None
    results["no-mcs"].priority_scenario_count = 0

    monkeypatch.setattr(
        portfolio_module,
        "analyze_production",
        lambda analysis_request: results[analysis_request.mine_id],
    )

    result = analyze_production_portfolio(
        PortfolioAnalysisRequest(
            batch_id="robust-priority",
            portfolio_name="稳健优先级",
            expected_mine_ids=[
                "consensus",
                "divergent",
                "unbounded",
                "no-mcs",
            ],
            analyses=analyses,
        )
    )

    priorities = {
        item.mine_id: item.review_priority for item in result.items
    }
    assert priorities == {
        "consensus": "P1",
        "divergent": "P2",
        "unbounded": "P2",
        "no-mcs": "P2",
    }


def test_empty_received_batch_marks_every_expected_mine_as_data() -> None:
    result = analyze_production_portfolio(
        PortfolioAnalysisRequest(
            batch_id="empty-batch",
            portfolio_name="空批次",
            expected_mine_ids=["M001", "M002"],
            analyses=[],
        )
    )

    assert result.coverage_rate == 0
    assert [item.mine_id for item in result.items] == ["M001", "M002"]
    assert all(
        item.technical_status == "not_received"
        and item.review_priority == "DATA"
        for item in result.items
    )
    assert result.review_priority_counts["DATA"] == 2
    assert "覆盖率 0.0%" in result.summary


@pytest.mark.parametrize(
    ("expected_mines", "analyses", "message"),
    [
        (
            ["M001", "M001"],
            [],
            "expected_mine_ids values must be unique",
        ),
        (
            ["M001"],
            [
                load_request("production_consistent.json", "M001"),
                load_request("production_inconsistent.json", "M001"),
            ],
            "analysis mine_id values must be unique",
        ),
        (
            ["M001"],
            [load_request("production_consistent.json", "M999")],
            "must belong to expected_mine_ids",
        ),
    ],
)
def test_request_rejects_invalid_mine_rosters(
    expected_mines: list[str],
    analyses: list[ProductionAnalysisRequest],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        PortfolioAnalysisRequest(
            batch_id="bad-roster",
            portfolio_name="错误名单",
            expected_mine_ids=expected_mines,
            analyses=analyses,
        )


def test_request_requires_at_least_one_expected_mine() -> None:
    with pytest.raises(ValidationError):
        PortfolioAnalysisRequest(
            batch_id="no-mines",
            portfolio_name="空辖区",
            expected_mine_ids=[],
        )


def test_analyzer_requires_validated_request_model() -> None:
    with pytest.raises(
        TypeError,
        match="request must be a PortfolioAnalysisRequest",
    ):
        analyze_production_portfolio({})  # type: ignore[arg-type]
