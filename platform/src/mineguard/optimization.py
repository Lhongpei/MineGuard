"""产运储洗全局协调与冲突诊断。

这一版刻意只使用线性模型：

* 弹性模型以加权 L1 残差协调多源观测；
* 严格模型只接受观测自身容差和业务平衡容差；
* 严格模型不可行时，按 ``source_group`` 枚举最小修正集（MCS）；
* 每个 MCS 都对产量做上下界剖面，并在全部最小基数情景上汇总稳健差额；
* 共享 ``dependency_domains`` 的来源按连通簇折算为一份独立证据。

这里的区间和差额都是确定性技术结果，不是违法事实认定或统计置信区间。
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
import math
from typing import Collection, Iterable, Sequence

import numpy as np
from scipy.optimize import OptimizeResult, linprog

from .models import (
    BusinessBalanceSlack,
    ConflictAlternative,
    DataQualityResult,
    MetricCode,
    MetricObservation,
    ObservationAdjustment,
    ProductionAnalysisRequest,
    ProductionAnalysisResult,
    ReconciledMetric,
)
from .quality import evaluate_data_quality


_METRICS: tuple[MetricCode, ...] = tuple(MetricCode)
_METRIC_INDEX = {metric: index for index, metric in enumerate(_METRICS)}
_PRODUCTION_INDEX = _METRIC_INDEX[MetricCode.REPORTED_PRODUCTION]


@dataclass(frozen=True)
class _StrictProblem:
    """A strict LP ready for repeated feasibility/profile solves."""

    a_ub: np.ndarray
    b_ub: np.ndarray
    bounds: tuple[tuple[float | None, float | None], ...]
    impossible_reason: str | None = None


@dataclass(frozen=True)
class _MCSCandidate:
    groups: tuple[str, ...]
    reliability_cost: float


@dataclass(frozen=True)
class _MCSEnumeration:
    candidates: tuple[_MCSCandidate, ...]
    examined_combination_count: int
    priority_scenario_count_complete: bool


@dataclass(frozen=True)
class _CoordinationLayout:
    positive_residual_start: int
    negative_residual_start: int
    transport_positive: int
    transport_negative: int
    stock_positive: int
    stock_negative: int
    variable_count: int


def _coordination_layout(observation_count: int) -> _CoordinationLayout:
    metric_count = len(_METRICS)
    positive_residual_start = metric_count
    negative_residual_start = positive_residual_start + observation_count
    transport_positive = negative_residual_start + observation_count
    transport_negative = transport_positive + 1
    stock_positive = transport_negative + 1
    stock_negative = stock_positive + 1
    return _CoordinationLayout(
        positive_residual_start=positive_residual_start,
        negative_residual_start=negative_residual_start,
        transport_positive=transport_positive,
        transport_negative=transport_negative,
        stock_positive=stock_positive,
        stock_negative=stock_negative,
        variable_count=stock_negative + 1,
    )


def _finite(value: float) -> float:
    """Remove harmless HiGHS signed zero/noise from values exposed by the API."""

    if abs(value) < 1e-9:
        return 0.0
    return float(value)


def _effective_tolerance(observation: MetricObservation) -> float:
    """Combine fixed, proportional and quantisation uncertainty.

    ``resolution / 2`` is the maximum rounding error when a source reports to
    the nearest resolution step.  Existing requests retain their exact
    behaviour because both new terms default to zero.
    """

    return float(
        observation.tolerance_abs
        + abs(observation.value) * observation.tolerance_rel
        + observation.resolution / 2.0
    )


def _required_quality(
    request: ProductionAnalysisRequest,
) -> DataQualityResult:
    """Apply the common gate and require an explicit raw-sales observation.

    ``quality.evaluate_data_quality`` owns the general gate.  Raw sales is also
    required by this five-quantity balance: treating an absent value as zero
    would silently manufacture evidence.
    """

    quality = evaluate_data_quality(request)
    codes = {observation.metric_code for observation in request.observations}
    if MetricCode.RAW_SALES in codes:
        return quality

    reason = (
        f"missing_required_metric: {MetricCode.RAW_SALES.value}"
    )
    reasons = sorted(set([*quality.blocking_reasons, reason]))
    return quality.model_copy(
        update={
            "status": "blocked",
            "blocking_reasons": reasons,
        }
    )


def _quality_recommendations(
    quality: DataQualityResult,
) -> list[str]:
    recommendations: list[str] = []
    missing = [
        reason.split(": ", 1)[1]
        for reason in quality.blocking_reasons
        if reason.startswith("missing_required_metric: ")
    ]
    if missing:
        recommendations.append(
            "补齐必需指标并明确上报零值，不得以缺失值代替零值："
            + "、".join(missing)
        )
    if any("signature_invalid" in reason for reason in quality.blocking_reasons):
        recommendations.append("核验无效签名数据的来源、传输链路和原始记录")
    if quality.score < 80:
        recommendations.append("修复低质量数据源后重新执行交叉验证")
    if not recommendations:
        recommendations.append("处理数据质量阻断项后重新执行交叉验证")
    return recommendations


def _coordination_problem(
    request: ProductionAnalysisRequest,
) -> tuple[
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    np.ndarray,
    tuple[tuple[float | None, float | None], ...],
]:
    """Compile the elastic weighted-L1 coordination LP.

    Observation terms are exactly ``source_reliability * abs(x-y)`` divided by
    the combined fixed, proportional and resolution tolerance.  Data quality
    is used only by the gate, so it is not multiplied into the objective a
    second time. Business slack is the amount *beyond* the approved normal
    tolerance.
    """

    observations = request.observations
    observation_count = len(observations)
    layout = _coordination_layout(observation_count)

    objective = np.zeros(layout.variable_count, dtype=float)
    for index, observation in enumerate(observations):
        coefficient = (
            observation.source_reliability
            / _effective_tolerance(observation)
        )
        objective[layout.positive_residual_start + index] = coefficient
        objective[layout.negative_residual_start + index] = coefficient

    parameters = request.parameters
    objective[layout.transport_positive] = (
        parameters.transport_slack_penalty
    )
    objective[layout.transport_negative] = (
        parameters.transport_slack_penalty
    )
    objective[layout.stock_positive] = parameters.stock_slack_penalty
    objective[layout.stock_negative] = parameters.stock_slack_penalty

    # x_metric - d+ + d- = observed_value
    a_eq = np.zeros(
        (observation_count, layout.variable_count),
        dtype=float,
    )
    b_eq = np.empty(observation_count, dtype=float)
    for index, observation in enumerate(observations):
        a_eq[index, _METRIC_INDEX[observation.metric_code]] = 1.0
        a_eq[index, layout.positive_residual_start + index] = -1.0
        a_eq[index, layout.negative_residual_start + index] = 1.0
        b_eq[index] = observation.value

    production = _METRIC_INDEX[MetricCode.REPORTED_PRODUCTION]
    transport = _METRIC_INDEX[MetricCode.MAIN_TRANSPORT]
    wash_feed = _METRIC_INDEX[MetricCode.WASH_FEED]
    raw_sales = _METRIC_INDEX[MetricCode.RAW_SALES]
    inventory_change = _METRIC_INDEX[MetricCode.RAW_INVENTORY_CHANGE]

    # |P-T| <= normal tolerance + paid slack.
    # |P-W-S-dI| <= normal tolerance + paid slack.
    a_ub = np.zeros((4, layout.variable_count), dtype=float)
    b_ub = np.array(
        [
            parameters.transport_balance_tolerance,
            parameters.transport_balance_tolerance,
            parameters.stock_balance_tolerance,
            parameters.stock_balance_tolerance,
        ],
        dtype=float,
    )
    a_ub[0, production] = 1.0
    a_ub[0, transport] = -1.0
    a_ub[0, layout.transport_positive] = -1.0
    a_ub[1, production] = -1.0
    a_ub[1, transport] = 1.0
    a_ub[1, layout.transport_negative] = -1.0

    stock_row = np.zeros(layout.variable_count, dtype=float)
    stock_row[production] = 1.0
    stock_row[wash_feed] = -1.0
    stock_row[raw_sales] = -1.0
    stock_row[inventory_change] = -1.0
    a_ub[2] = stock_row
    a_ub[2, layout.stock_positive] = -1.0
    a_ub[3] = -stock_row
    a_ub[3, layout.stock_negative] = -1.0

    bounds_list: list[tuple[float | None, float | None]] = [
        (0.0, None) for _ in range(layout.variable_count)
    ]
    # 库存变化是有符号的状态差：正数为库存增加，负数为库存下降。
    bounds_list[inventory_change] = (None, None)
    bounds = tuple(bounds_list)
    return objective, a_ub, b_ub, a_eq, b_eq, bounds


def _solve_coordination(
    request: ProductionAnalysisRequest,
) -> OptimizeResult:
    objective, a_ub, b_ub, a_eq, b_eq, bounds = (
        _coordination_problem(request)
    )
    return linprog(
        objective,
        A_ub=a_ub,
        b_ub=b_ub,
        A_eq=a_eq,
        b_eq=b_eq,
        bounds=bounds,
        method="highs",
    )


def _strict_problem(
    request: ProductionAnalysisRequest,
    relaxed_groups: Collection[str] = (),
) -> _StrictProblem:
    """Compile observation bands and physical relationships without slack."""

    relaxed = set(relaxed_groups)
    lower = np.zeros(len(_METRICS), dtype=float)
    upper = np.full(len(_METRICS), np.inf, dtype=float)
    inventory_change = _METRIC_INDEX[MetricCode.RAW_INVENTORY_CHANGE]
    lower[inventory_change] = -np.inf

    for observation in request.observations:
        if observation.source_group in relaxed:
            continue
        index = _METRIC_INDEX[observation.metric_code]
        tolerance = _effective_tolerance(observation)
        observation_lower = observation.value - tolerance
        if observation.metric_code != MetricCode.RAW_INVENTORY_CHANGE:
            observation_lower = max(observation_lower, 0.0)
        lower[index] = max(lower[index], observation_lower)
        upper[index] = min(
            upper[index],
            observation.value + tolerance,
        )

    for metric, index in _METRIC_INDEX.items():
        if lower[index] > upper[index] + 1e-9:
            return _StrictProblem(
                a_ub=np.empty((0, len(_METRICS)), dtype=float),
                b_ub=np.empty(0, dtype=float),
                bounds=tuple(
                    (
                        None if math.isinf(lo) else float(lo),
                        None if math.isinf(hi) else float(hi),
                    )
                    for lo, hi in zip(lower, upper, strict=True)
                ),
                impossible_reason=(
                    f"observation bands do not intersect for {metric.value}"
                ),
            )

    production = _METRIC_INDEX[MetricCode.REPORTED_PRODUCTION]
    transport = _METRIC_INDEX[MetricCode.MAIN_TRANSPORT]
    wash_feed = _METRIC_INDEX[MetricCode.WASH_FEED]
    raw_sales = _METRIC_INDEX[MetricCode.RAW_SALES]
    inventory_change = _METRIC_INDEX[MetricCode.RAW_INVENTORY_CHANGE]

    a_ub = np.zeros((4, len(_METRICS)), dtype=float)
    a_ub[0, production] = 1.0
    a_ub[0, transport] = -1.0
    a_ub[1] = -a_ub[0]

    stock_row = np.zeros(len(_METRICS), dtype=float)
    stock_row[production] = 1.0
    stock_row[wash_feed] = -1.0
    stock_row[raw_sales] = -1.0
    stock_row[inventory_change] = -1.0
    a_ub[2] = stock_row
    a_ub[3] = -stock_row

    b_ub = np.array(
        [
            request.parameters.transport_balance_tolerance,
            request.parameters.transport_balance_tolerance,
            request.parameters.stock_balance_tolerance,
            request.parameters.stock_balance_tolerance,
        ],
        dtype=float,
    )
    bounds = tuple(
        (
            None if math.isinf(lo) else float(lo),
            None if math.isinf(hi) else float(hi),
        )
        for lo, hi in zip(lower, upper, strict=True)
    )
    return _StrictProblem(a_ub=a_ub, b_ub=b_ub, bounds=bounds)


def _solve_strict(
    problem: _StrictProblem,
    objective: np.ndarray | None = None,
) -> OptimizeResult | None:
    if problem.impossible_reason is not None:
        return None
    if objective is None:
        objective = np.zeros(len(_METRICS), dtype=float)
    return linprog(
        objective,
        A_ub=problem.a_ub,
        b_ub=problem.b_ub,
        bounds=problem.bounds,
        method="highs",
    )


def _strict_feasible(
    request: ProductionAnalysisRequest,
    relaxed_groups: Collection[str] = (),
) -> bool:
    result = _solve_strict(_strict_problem(request, relaxed_groups))
    return result is not None and result.status == 0


def _group_reliability_costs(
    observations: Sequence[MetricObservation],
) -> dict[str, float]:
    """Assign one conservative reliability cost per independent source group."""

    costs: dict[str, float] = {}
    for observation in observations:
        costs[observation.source_group] = max(
            costs.get(observation.source_group, 0.0),
            observation.source_reliability,
        )
    return costs


def _enumerate_mcs(
    request: ProductionAnalysisRequest,
) -> _MCSEnumeration:
    """Enumerate every feasible relaxation at the minimum cardinality.

    Higher-cardinality repairs cannot affect the robust minimum-cardinality
    conclusion, so the search stops after completing the first feasible
    cardinality.  A configured combination budget prevents pathological
    source counts from creating an unbounded request-time search; exhausting
    that budget is surfaced as incomplete diagnostics and therefore cannot
    produce strong evidence.
    """

    groups = tuple(
        sorted({observation.source_group for observation in request.observations})
    )
    group_costs = _group_reliability_costs(request.observations)
    examined = 0
    budget = request.parameters.max_mcs_search_combinations

    max_groups = min(request.parameters.max_relaxed_groups, len(groups))
    for group_count in range(1, max_groups + 1):
        feasible_sets: list[frozenset[str]] = []
        for candidate_tuple in combinations(groups, group_count):
            if examined >= budget:
                candidates = [
                    _MCSCandidate(
                        groups=tuple(sorted(candidate)),
                        reliability_cost=sum(
                            group_costs[group] for group in candidate
                        ),
                    )
                    for candidate in feasible_sets
                ]
                candidates.sort(
                    key=lambda candidate: (
                        candidate.reliability_cost,
                        candidate.groups,
                    )
                )
                return _MCSEnumeration(
                    candidates=tuple(candidates),
                    examined_combination_count=examined,
                    priority_scenario_count_complete=False,
                )
            examined += 1
            candidate = frozenset(candidate_tuple)
            if _strict_feasible(request, candidate):
                feasible_sets.append(candidate)
        if feasible_sets:
            candidates = [
                _MCSCandidate(
                    groups=tuple(sorted(candidate)),
                    reliability_cost=sum(
                        group_costs[group] for group in candidate
                    ),
                )
                for candidate in feasible_sets
            ]
            candidates.sort(
                key=lambda candidate: (
                    candidate.reliability_cost,
                    candidate.groups,
                )
            )
            return _MCSEnumeration(
                candidates=tuple(candidates),
                examined_combination_count=examined,
                priority_scenario_count_complete=True,
            )
    return _MCSEnumeration(
        candidates=(),
        examined_combination_count=examined,
        priority_scenario_count_complete=True,
    )


def _production_range(
    request: ProductionAnalysisRequest,
    relaxed_groups: Collection[str],
) -> tuple[float, float] | None:
    problem = _strict_problem(request, relaxed_groups)
    minimum_objective = np.zeros(len(_METRICS), dtype=float)
    minimum_objective[_PRODUCTION_INDEX] = 1.0
    maximum_objective = -minimum_objective

    minimum = _solve_strict(problem, minimum_objective)
    maximum = _solve_strict(problem, maximum_objective)
    if (
        minimum is None
        or maximum is None
        or minimum.status != 0
        or maximum.status != 0
    ):
        return None

    return (
        _finite(float(minimum.fun)),
        _finite(float(-maximum.fun)),
    )


def _reported_value(request: ProductionAnalysisRequest) -> float:
    """Return a conservative nominal report when redundant reports exist."""

    reported = [
        observation.value
        for observation in request.observations
        if observation.metric_code == MetricCode.REPORTED_PRODUCTION
    ]
    # The quality gate guarantees this list is non-empty.  Using the largest
    # redundant report makes the derived unexplained gap conservative.
    return float(max(reported))


def _reported_gap_ratio(gap: float, reported_value: float) -> float | None:
    if reported_value > 1e-9:
        return _finite(gap / reported_value)
    if gap <= 1e-9:
        return 0.0
    return None


def _independent_evidence_clusters(
    request: ProductionAnalysisRequest,
    supporting_groups: Collection[str],
) -> list[list[str]]:
    """Return connected source clusters induced by shared dependencies.

    Declared domains join all source groups that depend on the same PLC,
    database, manual ledger or other upstream evidence domain.  An undeclared
    dependency is unknown, not proof of independence: all groups lacking
    lineage metadata are conservatively joined into one unknown cluster.
    """

    groups = sorted(set(supporting_groups))
    neighbours = {group: {group} for group in groups}
    groups_by_domain: dict[str, set[str]] = {}
    for observation in request.observations:
        if observation.source_group not in neighbours:
            continue
        domains = (
            observation.dependency_domains
            if observation.dependency_domains
            else ["__undeclared_dependency__"]
        )
        for domain in domains:
            groups_by_domain.setdefault(domain, set()).add(
                observation.source_group
            )

    for domain_groups in groups_by_domain.values():
        for group in domain_groups:
            neighbours[group].update(domain_groups)

    clusters: list[list[str]] = []
    unvisited = set(groups)
    while unvisited:
        start = min(unvisited)
        pending = [start]
        component: set[str] = set()
        while pending:
            group = pending.pop()
            if group in component:
                continue
            component.add(group)
            pending.extend(sorted(neighbours[group] - component))
        unvisited.difference_update(component)
        clusters.append(sorted(component))
    clusters.sort(key=lambda cluster: tuple(cluster))
    return clusters


def _raw_anomaly_statistic(
    request: ProductionAnalysisRequest,
    objective_value: float,
) -> float:
    denominator = sum(
        observation.source_reliability
        for observation in request.observations
    )
    return float(objective_value / max(denominator, 1e-12))


def _empirical_calibration(
    raw_statistic: float,
    calibration_scores: Iterable[float],
) -> tuple[float | None, float | None]:
    finite_scores = [
        float(score) for score in calibration_scores if math.isfinite(score)
    ]
    if not finite_scores:
        return None, None
    exceedances = sum(score >= raw_statistic for score in finite_scores)
    p_value = (1.0 + exceedances) / (len(finite_scores) + 1.0)
    return p_value, 100.0 * p_value


def _reconciled_metrics(
    request: ProductionAnalysisRequest,
    inferred: np.ndarray,
    production_range: tuple[float, float] | None,
    adjustments: dict[str, ObservationAdjustment],
) -> dict[str, ReconciledMetric]:
    result: dict[str, ReconciledMetric] = {}
    for metric in _METRICS:
        observations = [
            observation
            for observation in request.observations
            if observation.metric_code == metric
        ]
        if not observations:
            continue

        metric_value = _finite(float(inferred[_METRIC_INDEX[metric]]))
        reliability_total = sum(
            observation.source_reliability for observation in observations
        )
        normalized_residual = sum(
            observation.source_reliability
            * abs(metric_value - observation.value)
            / _effective_tolerance(observation)
            for observation in observations
        ) / max(reliability_total, 1e-12)

        lower: float | None = None
        upper: float | None = None
        if (
            metric == MetricCode.REPORTED_PRODUCTION
            and production_range is not None
        ):
            lower, upper = production_range

        result[metric.value] = ReconciledMetric(
            metric_code=metric,
            inferred_value=metric_value,
            observed_values=[
                float(observation.value) for observation in observations
            ],
            reasonable_lower=lower,
            reasonable_upper=upper,
            normalized_residual=_finite(float(normalized_residual)),
            observation_adjustments=[
                adjustments[observation.observation_id]
                for observation in observations
            ],
        )
    return result


def _observation_adjustments(
    request: ProductionAnalysisRequest,
    inferred: np.ndarray,
) -> dict[str, ObservationAdjustment]:
    adjustments: dict[str, ObservationAdjustment] = {}
    for observation in request.observations:
        inferred_value = _finite(
            float(inferred[_METRIC_INDEX[observation.metric_code]])
        )
        signed = _finite(inferred_value - observation.value)
        absolute = _finite(abs(signed))
        tolerance = _effective_tolerance(observation)
        adjustments[observation.observation_id] = ObservationAdjustment(
            observation_id=observation.observation_id,
            metric_code=observation.metric_code,
            source_group=observation.source_group,
            observed_value=float(observation.value),
            inferred_value=inferred_value,
            signed_adjustment=signed,
            absolute_adjustment=absolute,
            effective_tolerance=tolerance,
            normalized_residual=_finite(absolute / tolerance),
        )
    return adjustments


def _business_balance_slacks(
    request: ProductionAnalysisRequest,
    coordination_values: np.ndarray,
) -> dict[str, BusinessBalanceSlack]:
    layout = _coordination_layout(len(request.observations))
    production = float(coordination_values[_PRODUCTION_INDEX])
    transport = float(
        coordination_values[_METRIC_INDEX[MetricCode.MAIN_TRANSPORT]]
    )
    wash_feed = float(
        coordination_values[_METRIC_INDEX[MetricCode.WASH_FEED]]
    )
    raw_sales = float(
        coordination_values[_METRIC_INDEX[MetricCode.RAW_SALES]]
    )
    inventory_change = float(
        coordination_values[
            _METRIC_INDEX[MetricCode.RAW_INVENTORY_CHANGE]
        ]
    )

    def build(
        *,
        code: str,
        signed_residual: float,
        tolerance: float,
        positive_index: int,
        negative_index: int,
        label: str,
    ) -> BusinessBalanceSlack:
        positive = _finite(
            max(0.0, float(coordination_values[positive_index]))
        )
        negative = _finite(
            max(0.0, float(coordination_values[negative_index]))
        )
        absolute = _finite(positive + negative)
        if absolute > 1e-9:
            explanation = (
                f"{label}在批准容差外仍需至少修复 {absolute:.3f} 吨；"
                "该值是当前加权L1协调解的业务平衡松弛量。"
            )
        else:
            explanation = f"{label}已落入批准的业务平衡容差。"
        return BusinessBalanceSlack(
            balance_code=code,
            signed_balance_residual=_finite(signed_residual),
            approved_tolerance=float(tolerance),
            positive_slack=positive,
            negative_slack=negative,
            absolute_slack=absolute,
            minimum_additional_repair=absolute,
            explanation=explanation,
        )

    return {
        "production_transport": build(
            code="production_transport",
            signed_residual=production - transport,
            tolerance=request.parameters.transport_balance_tolerance,
            positive_index=layout.transport_positive,
            negative_index=layout.transport_negative,
            label="产量—主运输平衡",
        ),
        "stock_flow": build(
            code="stock_flow",
            signed_residual=(
                production - wash_feed - raw_sales - inventory_change
            ),
            tolerance=request.parameters.stock_balance_tolerance,
            positive_index=layout.stock_positive,
            negative_index=layout.stock_negative,
            label="产量—入洗—销售—库存平衡",
        ),
    }


def _minimum_repair_explanations(
    adjustments: dict[str, ObservationAdjustment],
    balance_slacks: dict[str, BusinessBalanceSlack],
) -> list[str]:
    explanations = [
        (
            f"观测 {adjustment.observation_id} 建议"
            f"{'上调' if adjustment.signed_adjustment > 0 else '下调'}"
            f"至少 {adjustment.absolute_adjustment:.3f} 吨"
            f"（{adjustment.normalized_residual:.3f} 倍动态容差）。"
        )
        for adjustment in sorted(
            adjustments.values(),
            key=lambda item: (
                -item.normalized_residual,
                item.observation_id,
            ),
        )
        if adjustment.absolute_adjustment > 1e-9
    ]
    explanations.extend(
        slack.explanation
        for slack in balance_slacks.values()
        if slack.absolute_slack > 1e-9
    )
    if not explanations:
        explanations.append(
            "加权L1协调解无需修改观测，且业务平衡均在批准容差内。"
        )
    return explanations


def _metric_labels_for_groups(
    request: ProductionAnalysisRequest,
    groups: Collection[str],
) -> list[str]:
    labels = {
        MetricCode.REPORTED_PRODUCTION: "上报产量",
        MetricCode.MAIN_TRANSPORT: "主运输皮带",
        MetricCode.WASH_FEED: "洗选投料",
        MetricCode.RAW_SALES: "原煤销售",
        MetricCode.RAW_INVENTORY_CHANGE: "原煤库存变化",
    }
    selected = {
        labels[observation.metric_code]
        for observation in request.observations
        if observation.source_group in groups
    }
    return sorted(selected)


def _recommended_checks(
    request: ProductionAnalysisRequest,
    preferred_groups: Collection[str],
    minimum_gap: float | None,
) -> list[str]:
    if not preferred_groups:
        return []

    group_text = "、".join(sorted(preferred_groups))
    metric_text = "、".join(
        _metric_labels_for_groups(request, preferred_groups)
    )
    checks = [
        f"优先核查来源组 {group_text} 的{metric_text}原始记录、口径及修订日志",
        f"核验来源组 {group_text} 对应设备的检定、校准、时钟和断点续传记录",
    ]
    if minimum_gap is not None and minimum_gap > 1e-9:
        checks.append(
            f"围绕至少 {minimum_gap:.3f} 吨的上报技术差额，"
            "复核运输、入洗、销售和库存原始凭证"
        )
    checks.append("保全相关时段原始表底、设备日志、视频和业务凭证后开展人工复核")
    return checks


def _evidence_grade(
    *,
    inconsistent: bool,
    quality: DataQualityResult,
    diagnostics_complete: bool,
    independent_cluster_count: int,
) -> str:
    if not inconsistent:
        return "C"
    if not diagnostics_complete:
        return "D"
    if (
        quality.status == "sufficient"
        and independent_cluster_count >= 3
        and not quality.unverified_dimensions
    ):
        return "A"
    if independent_cluster_count >= 2:
        return "B"
    return "C"


def analyze_production(
    request: ProductionAnalysisRequest,
) -> ProductionAnalysisResult:
    """Run data coordination, strict conflict diagnosis and profiling."""

    quality = _required_quality(request)
    base_assumptions = [
        "全部指标已统一为同一分析窗口和吨单位",
        "库存变化为正表示期末库存较期初增加",
        "严格模型仅使用观测容差及已配置的产运、库存平衡容差",
        "合理区间和差额仅为技术核查线索，不构成违法事实认定",
    ]
    if quality.status == "blocked":
        return ProductionAnalysisResult(
            mine_id=request.mine_id,
            status="inconclusive",
            data_quality=quality,
            solver_status="not_run_data_quality_blocked",
            evidence_grade="D",
            assumptions=base_assumptions,
            recommended_checks=_quality_recommendations(quality),
        )

    try:
        coordination = _solve_coordination(request)
    except (TypeError, ValueError, FloatingPointError) as error:
        return ProductionAnalysisResult(
            mine_id=request.mine_id,
            status="solver_error",
            data_quality=quality,
            solver_status=f"coordination_error: {error}",
            evidence_grade="D",
            assumptions=base_assumptions,
            recommended_checks=["检查输入数值、容差和求解器运行环境后重试"],
        )

    if coordination.status != 0 or coordination.x is None:
        return ProductionAnalysisResult(
            mine_id=request.mine_id,
            status="solver_error",
            data_quality=quality,
            solver_status=(
                f"coordination_{coordination.status}: {coordination.message}"
            ),
            evidence_grade="D",
            assumptions=base_assumptions,
            recommended_checks=["检查模型参数和求解器日志后重试"],
        )

    strict_problem = _strict_problem(request)
    strict = _solve_strict(strict_problem)
    strict_is_feasible = strict is not None and strict.status == 0
    strict_is_infeasible = (
        strict_problem.impossible_reason is not None
        or (strict is not None and strict.status == 2)
    )
    if not strict_is_feasible and not strict_is_infeasible:
        status_code = "not_run" if strict is None else str(strict.status)
        message = (
            strict_problem.impossible_reason
            if strict is None
            else strict.message
        )
        return ProductionAnalysisResult(
            mine_id=request.mine_id,
            status="solver_error",
            data_quality=quality,
            solver_status=f"strict_{status_code}: {message}",
            objective_value=float(coordination.fun),
            evidence_grade="D",
            assumptions=base_assumptions,
            recommended_checks=["检查严格诊断模型和求解器日志后重试"],
        )

    reported_value = _reported_value(request)
    all_groups = {
        observation.source_group for observation in request.observations
    }
    mcs_enumeration = (
        _enumerate_mcs(request)
        if not strict_is_feasible
        else _MCSEnumeration(
            candidates=(),
            examined_combination_count=0,
            priority_scenario_count_complete=True,
        )
    )
    mcs_candidates = list(mcs_enumeration.candidates)
    minimum_group_count = (
        min(len(candidate.groups) for candidate in mcs_candidates)
        if mcs_candidates
        else None
    )
    priority_candidates = [
        candidate
        for candidate in mcs_candidates
        if len(candidate.groups) == minimum_group_count
    ]

    scenario_details: dict[
        tuple[str, ...],
        tuple[
            tuple[float, float] | None,
            float | None,
            float | None,
            bool | None,
            list[str],
            list[list[str]],
        ],
    ] = {}
    for candidate in mcs_candidates:
        candidate_range = _production_range(request, candidate.groups)
        candidate_minimum_gap: float | None = None
        candidate_upper_gap: float | None = None
        supports_positive_gap: bool | None = None
        if candidate_range is not None:
            candidate_minimum_gap = _finite(
                max(0.0, candidate_range[0] - reported_value)
            )
            candidate_upper_gap = _finite(
                max(0.0, candidate_range[1] - reported_value)
            )
            supports_positive_gap = candidate_minimum_gap > 1e-9
        scenario_supporting_groups = sorted(
            all_groups - set(candidate.groups)
        )
        clusters = _independent_evidence_clusters(
            request,
            scenario_supporting_groups,
        )
        scenario_details[candidate.groups] = (
            candidate_range,
            candidate_minimum_gap,
            candidate_upper_gap,
            supports_positive_gap,
            scenario_supporting_groups,
            clusters,
        )

    priority_details = [
        scenario_details[candidate.groups]
        for candidate in priority_candidates
    ]
    all_priority_ranges_bounded = bool(priority_details) and all(
        detail[0] is not None for detail in priority_details
    )
    robust_minimum_gap: float | None = None
    unreported_upper: float | None = None
    scenario_union_range: tuple[float, float] | None = None
    if all_priority_ranges_bounded:
        bounded_ranges = [
            detail[0]
            for detail in priority_details
            if detail[0] is not None
        ]
        robust_minimum_gap = _finite(
            min(
                detail[1]
                for detail in priority_details
                if detail[1] is not None
            )
        )
        unreported_upper = _finite(
            max(
                detail[2]
                for detail in priority_details
                if detail[2] is not None
            )
        )
        scenario_union_range = (
            _finite(min(item[0] for item in bounded_ranges)),
            _finite(max(item[1] for item in bounded_ranges)),
        )

    scenario_conclusions = {
        detail[3] for detail in priority_details
    }
    scenario_conclusion_divergent = len(scenario_conclusions) > 1
    all_priority_support_positive = bool(priority_details) and all(
        detail[3] is True for detail in priority_details
    )
    if not mcs_enumeration.priority_scenario_count_complete:
        # Partial scenario ranges may be useful for debugging but are not a
        # robust union and must not be exposed as a minimum supported gap.
        robust_minimum_gap = None
        unreported_upper = None
        scenario_union_range = None
        all_priority_support_positive = False

    if priority_candidates:
        weakest_candidate = min(
            priority_candidates,
            key=lambda candidate: (
                len(scenario_details[candidate.groups][5]),
                candidate.groups,
            ),
        )
        weakest_detail = scenario_details[weakest_candidate.groups]
        supporting_groups = weakest_detail[4]
        evidence_clusters = weakest_detail[5]
    else:
        supporting_groups = sorted(all_groups) if strict_is_feasible else []
        evidence_clusters = _independent_evidence_clusters(
            request,
            supporting_groups,
        )

    if strict_is_feasible:
        scenario_union_range = _production_range(request, ())
        if scenario_union_range is not None:
            robust_minimum_gap = _finite(
                max(0.0, scenario_union_range[0] - reported_value)
            )
            unreported_upper = _finite(
                max(0.0, scenario_union_range[1] - reported_value)
            )

    priority_group_sets = {candidate.groups for candidate in priority_candidates}
    displayed_candidates = [
        candidate
        for candidate in mcs_candidates
        if candidate.groups in priority_group_sets
    ]
    remaining_capacity = max(
        0,
        request.parameters.max_mcs - len(displayed_candidates),
    )
    displayed_candidates.extend(
        candidate
        for candidate in mcs_candidates
        if candidate.groups not in priority_group_sets
    )
    displayed_candidates = displayed_candidates[
        : len(priority_candidates) + remaining_capacity
    ]

    mcs_alternatives: list[ConflictAlternative] = []
    for candidate in displayed_candidates:
        (
            candidate_range,
            candidate_minimum_gap,
            candidate_upper_gap,
            supports_positive_gap,
            scenario_supporting_groups,
            clusters,
        ) = scenario_details[candidate.groups]
        mcs_alternatives.append(
            ConflictAlternative(
                relaxed_source_groups=list(candidate.groups),
                group_count=len(candidate.groups),
                total_reliability_cost=float(candidate.reliability_cost),
                minimum_priority=(
                    candidate.groups in priority_group_sets
                ),
                reasonable_production_range=candidate_range,
                production_range_bounded=candidate_range is not None,
                minimum_reported_gap=candidate_minimum_gap,
                minimum_reported_gap_ratio=(
                    _reported_gap_ratio(
                        candidate_minimum_gap,
                        reported_value,
                    )
                    if candidate_minimum_gap is not None
                    else None
                ),
                unreported_output_upper=candidate_upper_gap,
                unreported_output_upper_ratio=(
                    _reported_gap_ratio(
                        candidate_upper_gap,
                        reported_value,
                    )
                    if candidate_upper_gap is not None
                    else None
                ),
                supports_positive_reported_gap=supports_positive_gap,
                supporting_source_groups=scenario_supporting_groups,
                independent_evidence_clusters=clusters,
                independent_evidence_cluster_count=len(clusters),
            )
        )

    objective_value = _finite(float(coordination.fun))
    raw_statistic = _raw_anomaly_statistic(request, objective_value)
    empirical_p, consistency_score = _empirical_calibration(
        raw_statistic,
        request.calibration_scores,
    )

    observation_adjustments = _observation_adjustments(
        request,
        coordination.x[: len(_METRICS)],
    )
    balance_slacks = _business_balance_slacks(
        request,
        coordination.x,
    )

    assumptions = list(base_assumptions)
    assumptions.append(
        "观测动态容差=绝对容差+|观测值|×相对容差+分辨率/2"
    )
    assumptions.append(
        "共享 dependency_domains 的来源组按连通簇计为一份独立证据；"
        "未声明依赖域不视为独立，统一归入未知依赖簇"
    )
    if not mcs_candidates and not strict_is_feasible:
        assumptions.append(
            "在 max_relaxed_groups 限制内未找到可恢复可行性的来源组组合"
        )
    if not mcs_enumeration.priority_scenario_count_complete:
        assumptions.append(
            "最小修正情景搜索达到组合预算，情景集合不完整，"
            "因此不输出稳健差额并强制证据降级"
        )
    if priority_candidates and not all_priority_ranges_bounded:
        assumptions.append(
            "至少一个最小来源组修正情景下产量无法得到有限的上下界"
        )
    if scenario_conclusion_divergent:
        assumptions.append(
            "最小来源组修正情景对是否存在正向上报差额的结论不一致"
        )
    if len(priority_candidates) > request.parameters.max_mcs:
        assumptions.append(
            "为避免遗漏稳健性风险，输出的最小优先情景数超过 max_mcs"
        )
    if not request.calibration_scores:
        assumptions.append("未提供独立正常校准分数，因此不输出经验p值")
    else:
        assumptions.append(
            "经验p值采用同矿历史正常窗口的有限样本+1校准，"
            f"样本数为 {len(request.calibration_scores)}"
        )

    inconsistent = not strict_is_feasible
    solver_status = (
        "coordination_optimal;strict_feasible"
        if strict_is_feasible
        else "coordination_optimal;strict_infeasible"
    )
    if inconsistent and not mcs_candidates:
        solver_status += ";mcs_not_found_within_limit"
    if not mcs_enumeration.priority_scenario_count_complete:
        solver_status += ";mcs_search_budget_exhausted"
    if inconsistent and priority_candidates and not all_priority_ranges_bounded:
        solver_status += ";priority_range_unbounded"
    if scenario_conclusion_divergent:
        solver_status += ";scenario_conclusions_diverge"

    diagnostics_complete = (
        bool(priority_candidates)
        and all_priority_ranges_bounded
        and mcs_enumeration.priority_scenario_count_complete
        if inconsistent
        else True
    )
    preferred_groups = sorted(
        {
            group
            for candidate in priority_candidates
            for group in candidate.groups
        }
    )

    return ProductionAnalysisResult(
        mine_id=request.mine_id,
        status="inconsistent" if inconsistent else "consistent",
        data_quality=quality,
        solver_status=solver_status,
        objective_value=objective_value,
        raw_anomaly_statistic=_finite(raw_statistic),
        empirical_p_value=empirical_p,
        consistency_score=consistency_score,
        calibration_sample_count=len(request.calibration_scores),
        calibration_method=(
            "empirical_conformal_plus_one"
            if request.calibration_scores
            else None
        ),
        evidence_grade=_evidence_grade(
            inconsistent=inconsistent,
            quality=quality,
            diagnostics_complete=diagnostics_complete,
            independent_cluster_count=len(evidence_clusters),
        ),
        reconciled_metrics=_reconciled_metrics(
            request,
            coordination.x[: len(_METRICS)],
            scenario_union_range,
            observation_adjustments,
        ),
        mcs_alternatives=mcs_alternatives,
        reasonable_production_range=scenario_union_range,
        minimum_reported_gap=robust_minimum_gap,
        unreported_output_upper=unreported_upper,
        robust_minimum_reported_gap=robust_minimum_gap,
        robust_minimum_reported_gap_ratio=(
            _reported_gap_ratio(
                robust_minimum_gap,
                reported_value,
            )
            if robust_minimum_gap is not None
            else None
        ),
        scenario_union_production_range=scenario_union_range,
        scenario_conclusion_divergent=scenario_conclusion_divergent,
        all_priority_scenarios_support_positive_gap=(
            all_priority_support_positive
        ),
        priority_scenario_count=len(priority_candidates),
        priority_scenario_count_complete=(
            mcs_enumeration.priority_scenario_count_complete
        ),
        diagnostics_complete=diagnostics_complete,
        mcs_search_complete=(
            mcs_enumeration.priority_scenario_count_complete
        ),
        mcs_examined_combination_count=(
            mcs_enumeration.examined_combination_count
        ),
        supporting_source_groups=supporting_groups,
        independent_evidence_clusters=evidence_clusters,
        independent_evidence_cluster_count=len(evidence_clusters),
        observation_adjustments=observation_adjustments,
        business_balance_slacks=balance_slacks,
        minimum_repair_explanations=_minimum_repair_explanations(
            observation_adjustments,
            balance_slacks,
        ),
        assumptions=assumptions,
        recommended_checks=_recommended_checks(
            request,
            preferred_groups,
            robust_minimum_gap,
        ),
    )
