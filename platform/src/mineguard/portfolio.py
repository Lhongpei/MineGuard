"""多矿辖区生产分析汇总。

本模块只编排现有的单矿生产分析纯函数，不改变单矿算法结论。技术状态与
人工复核优先级分开表达，未收到数据的预期矿井也会保留在批次结果中。
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field, model_validator

from .models import (
    ProductionAnalysisRequest,
    ProductionAnalysisResult,
    StrictModel,
)
from .optimization import analyze_production


TechnicalStatus = Literal[
    "not_received",
    "consistent",
    "inconsistent",
    "inconclusive",
    "solver_error",
]
ReviewPriority = Literal["P1", "P2", "DATA", "NONE"]

_TECHNICAL_STATUSES = (
    "not_received",
    "consistent",
    "inconsistent",
    "inconclusive",
    "solver_error",
)
_REVIEW_PRIORITIES = ("P1", "P2", "DATA", "NONE")
_PRIORITY_ORDER = {
    priority: index for index, priority in enumerate(_REVIEW_PRIORITIES)
}


class PortfolioAnalysisRequest(StrictModel):
    """A complete expected-mine roster plus the analyses received so far."""

    batch_id: Annotated[str, Field(min_length=1)]
    portfolio_name: Annotated[str, Field(min_length=1)]
    expected_mine_ids: Annotated[
        list[Annotated[str, Field(min_length=1)]],
        Field(min_length=1),
    ]
    analyses: list[ProductionAnalysisRequest] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_mine_roster(self) -> "PortfolioAnalysisRequest":
        if len(self.expected_mine_ids) != len(set(self.expected_mine_ids)):
            raise ValueError("expected_mine_ids values must be unique")

        actual_mine_ids = [analysis.mine_id for analysis in self.analyses]
        if len(actual_mine_ids) != len(set(actual_mine_ids)):
            raise ValueError("analysis mine_id values must be unique")

        expected = set(self.expected_mine_ids)
        unexpected = sorted(set(actual_mine_ids) - expected)
        if unexpected:
            raise ValueError(
                "analysis mine_id values must belong to expected_mine_ids: "
                + ", ".join(unexpected)
            )
        return self


class PortfolioItem(StrictModel):
    """One expected mine's technical result and independent review priority."""

    mine_id: str
    window_start: AwareDatetime | None = None
    window_end: AwareDatetime | None = None
    technical_status: TechnicalStatus
    review_priority: ReviewPriority
    evidence_grade: Literal["A", "B", "C", "D"] | None = None
    minimum_required_gap: float | None = None
    summary: str
    analysis: ProductionAnalysisResult | None = None


class PortfolioAnalysisResult(StrictModel):
    """Deterministic jurisdiction-level view of one production batch."""

    batch_id: str
    portfolio_name: str
    expected_mine_count: Annotated[int, Field(ge=1)]
    received_mine_count: Annotated[int, Field(ge=0)]
    coverage_rate: Annotated[float, Field(ge=0, le=1)]
    technical_status_counts: dict[str, Annotated[int, Field(ge=0)]]
    review_priority_counts: dict[str, Annotated[int, Field(ge=0)]]
    items: list[PortfolioItem]
    summary: str


def _review_priority(
    result: ProductionAnalysisResult,
) -> ReviewPriority:
    if result.status == "inconsistent":
        gap = result.minimum_reported_gap
        if (
            result.evidence_grade == "A"
            and gap is not None
            and gap > 0
            and result.priority_scenario_count > 0
            and result.all_priority_scenarios_support_positive_gap
            and not result.scenario_conclusion_divergent
            and result.scenario_union_production_range is not None
        ):
            return "P1"
        return "P2"
    if result.status in {"inconclusive", "solver_error"}:
        return "DATA"
    if (
        result.status == "consistent"
        and (
            result.data_quality.status != "sufficient"
            or result.data_quality.unverified_dimensions
        )
    ):
        return "DATA"
    return "NONE"


def _item_summary(
    technical_status: TechnicalStatus,
    priority: ReviewPriority,
    result: ProductionAnalysisResult | None,
) -> str:
    if technical_status == "not_received":
        return "未收到该矿分析数据，需补齐数据后重新运行。"
    if technical_status == "consistent":
        assert result is not None
        unverified_dimensions = {
            value.rsplit(":", maxsplit=1)[-1]
            for value in result.data_quality.unverified_dimensions
        }
        labels = {
            "device_health": "设备健康",
            "clock": "时钟同步",
        }
        dimension_order = {
            "device_health": 0,
            "clock": 1,
        }
        unverified_labels = [
            labels.get(dimension, dimension)
            for dimension in sorted(
                unverified_dimensions,
                key=lambda dimension: (
                    dimension_order.get(dimension, len(dimension_order)),
                    dimension,
                ),
            )
        ]
        if unverified_labels:
            return (
                "现有报送指标技术模型一致，但"
                f"{'、'.join(unverified_labels)}未验证，"
                "需补充验证证据并安排抽查。"
            )
        if priority == "DATA":
            return (
                "现有报送指标技术模型一致，但数据质量处于降级状态，"
                "需补充质量证据并安排抽查。"
            )
        return "现有报送指标技术模型一致，当前无需进入人工复核队列。"
    if technical_status == "inconclusive":
        return "数据质量未达到分析门槛，需先处理数据问题。"
    if technical_status == "solver_error":
        return "分析求解失败，需检查输入、配置和求解器运行状态。"

    assert result is not None
    gap = result.minimum_reported_gap
    if priority == "P1" and gap is not None:
        return (
            f"A级技术证据且各最小修正情景共同支持至少 {gap:.3f} 吨差额，"
            "建议优先开展人工核查。"
        )
    if gap is not None and gap > 0:
        return (
            f"发现全局不一致，最小技术差额为 {gap:.3f} 吨，"
            "建议进入常规人工复核。"
        )
    return "发现全局不一致，建议结合原始证据开展常规人工复核。"


def _received_item(
    request: ProductionAnalysisRequest,
    result: ProductionAnalysisResult,
) -> PortfolioItem:
    priority = _review_priority(result)
    return PortfolioItem(
        mine_id=result.mine_id,
        window_start=request.window_start,
        window_end=request.window_end,
        technical_status=result.status,
        review_priority=priority,
        evidence_grade=result.evidence_grade,
        minimum_required_gap=result.minimum_reported_gap,
        summary=_item_summary(result.status, priority, result),
        analysis=result,
    )


def _not_received_item(mine_id: str) -> PortfolioItem:
    return PortfolioItem(
        mine_id=mine_id,
        technical_status="not_received",
        review_priority="DATA",
        summary=_item_summary("not_received", "DATA", None),
    )


def _empty_counts(values: tuple[str, ...]) -> dict[str, int]:
    return {value: 0 for value in values}


def _portfolio_summary(
    request: PortfolioAnalysisRequest,
    received_count: int,
    coverage_rate: float,
    priority_counts: dict[str, int],
) -> str:
    return (
        f"{request.portfolio_name}批次共预期 {len(request.expected_mine_ids)} 座矿，"
        f"已收到 {received_count} 座，覆盖率 {coverage_rate:.1%}；"
        f"P1 {priority_counts['P1']} 座，"
        f"P2 {priority_counts['P2']} 座，"
        f"数据待处理 {priority_counts['DATA']} 座，"
        f"无需复核 {priority_counts['NONE']} 座。"
    )


def analyze_production_portfolio(
    request: PortfolioAnalysisRequest,
) -> PortfolioAnalysisResult:
    """Analyze received mines and retain every mine on the expected roster."""

    if not isinstance(request, PortfolioAnalysisRequest):
        raise TypeError("request must be a PortfolioAnalysisRequest")

    analysis_by_mine = {
        analysis.mine_id: analysis for analysis in request.analyses
    }
    roster_order = {
        mine_id: index
        for index, mine_id in enumerate(request.expected_mine_ids)
    }

    items: list[PortfolioItem] = []
    for mine_id in request.expected_mine_ids:
        analysis_request = analysis_by_mine.get(mine_id)
        if analysis_request is None:
            items.append(_not_received_item(mine_id))
            continue
        items.append(
            _received_item(
                analysis_request,
                analyze_production(analysis_request),
            )
        )

    items.sort(
        key=lambda item: (
            _PRIORITY_ORDER[item.review_priority],
            roster_order[item.mine_id],
        )
    )

    technical_counts = _empty_counts(_TECHNICAL_STATUSES)
    priority_counts = _empty_counts(_REVIEW_PRIORITIES)
    for item in items:
        technical_counts[item.technical_status] += 1
        priority_counts[item.review_priority] += 1

    received_count = len(request.analyses)
    coverage_rate = received_count / len(request.expected_mine_ids)
    return PortfolioAnalysisResult(
        batch_id=request.batch_id,
        portfolio_name=request.portfolio_name,
        expected_mine_count=len(request.expected_mine_ids),
        received_mine_count=received_count,
        coverage_rate=coverage_rate,
        technical_status_counts=technical_counts,
        review_priority_counts=priority_counts,
        items=items,
        summary=_portfolio_summary(
            request,
            received_count,
            coverage_rate,
            priority_counts,
        ),
    )


__all__ = [
    "PortfolioAnalysisRequest",
    "PortfolioAnalysisResult",
    "PortfolioItem",
    "analyze_production_portfolio",
]
