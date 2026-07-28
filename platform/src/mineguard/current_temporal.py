"""Past-only temporal evidence for the current governed analysis window.

This module deliberately remains independent from both reviewed historical
labels and the physical solver.  It reconstructs a strictly compatible,
same-context series of immutable ``balance.raw_anomaly`` features, appends the
current value as the final point, and delegates detection to the platform's
existing past-only temporal detector.

The returned assessment is shadow evidence only.  It never changes the
``ProductionAnalysisResult`` supplied by the caller.
"""

from __future__ import annotations

from datetime import UTC, datetime
import math
from typing import Annotated, Any, Literal, Protocol

from pydantic import AwareDatetime, Field

from .casework import (
    ALGORITHM_FEATURE_VERSION,
    algorithm_feature_compatibility_key,
    select_authoritative_algorithm_feature,
)
from .historical import OperationalContext
from .models import (
    ProductionAnalysisRequest,
    ProductionAnalysisResult,
    StrictModel,
)
from .temporal import (
    TemporalDetectionParameters,
    TemporalDetectionRequest,
    TemporalObservation,
    TemporalSignal,
    detect_temporal_anomalies,
)


CURRENT_TEMPORAL_METHOD_VERSION = "current-raw-anomaly-past-only-v1"
_FEATURE_CODE = "balance.raw_anomaly"
_SOURCE_KEY = ""
_REPOSITORY_CANDIDATE_LIMIT = 100_000


class CurrentTemporalPolicy(StrictModel):
    """Selection limits for the independent current-window time series."""

    minimum_samples: Annotated[int, Field(ge=3, le=500)] = 20
    maximum_samples: Annotated[int, Field(ge=3, le=500)] = 500
    minimum_quality_score: Annotated[
        float,
        Field(ge=0.8, le=1.0),
    ] = 0.8

    def model_post_init(self, __context: Any) -> None:
        if self.maximum_samples < self.minimum_samples:
            raise ValueError(
                "maximum_samples must be greater than or equal to "
                "minimum_samples"
            )


class CurrentTemporalAssessment(StrictModel):
    """Auditable shadow assessment for the current raw-anomaly point."""

    method_version: str = CURRENT_TEMPORAL_METHOD_VERSION
    status: Literal["insufficient_history", "normal", "anomalous"]
    reason_code: str
    compatibility_key: str
    feature_code: Literal["balance.raw_anomaly"] = _FEATURE_CODE
    feature_version: str = ALGORITHM_FEATURE_VERSION
    current_timestamp: AwareDatetime
    current_raw_anomaly: float | None = None
    current_data_quality: Annotated[
        float | None,
        Field(ge=0.0, le=1.0),
    ] = None
    candidate_count: Annotated[int, Field(ge=0)] = 0
    eligible_sample_count: Annotated[int, Field(ge=0)] = 0
    sample_count: Annotated[int, Field(ge=0)] = 0
    baseline_sample_count: Annotated[int, Field(ge=0)] = 0
    selected_feature_ids: list[str] = Field(default_factory=list)
    selected_feature_hashes: list[str] = Field(default_factory=list)
    rejected_invalid_count: Annotated[int, Field(ge=0)] = 0
    rejected_future_count: Annotated[int, Field(ge=0)] = 0
    rejected_compatibility_count: Annotated[int, Field(ge=0)] = 0
    rejected_governance_count: Annotated[int, Field(ge=0)] = 0
    rejected_quality_count: Annotated[int, Field(ge=0)] = 0
    rejected_integrity_count: Annotated[int, Field(ge=0)] = 0
    rejected_context_count: Annotated[int, Field(ge=0)] = 0
    rejected_ambiguous_count: Annotated[int, Field(ge=0)] = 0
    rejected_superseded_count: Annotated[int, Field(ge=0)] = 0
    rejected_limit_count: Annotated[int, Field(ge=0)] = 0
    repository_error_count: Annotated[int, Field(ge=0)] = 0
    detector_error_count: Annotated[int, Field(ge=0)] = 0
    history_limit_exceeded: bool = False
    current_value_anomaly: bool | None = None
    current_source_health_anomaly: bool | None = None
    rolling_robust_z: float | None = None
    ewma_standardized: float | None = None
    signals: list[TemporalSignal] = Field(default_factory=list)
    physical_status_unchanged: Literal[True] = True
    explanation: str


class CurrentTemporalRepository(Protocol):
    """Minimal repository contract needed by the current-window detector."""

    def list_algorithm_features(
        self,
        *,
        mine_ids: set[str] | None = None,
        feature_code: str | None = None,
        source_key: str | None = None,
        feature_version: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        limit: int = 10_000,
        include_overflow_sentinel: bool = False,
    ) -> list[dict[str, Any]]: ...

    def get_run(self, run_id: str) -> dict[str, Any]: ...


def _instant(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(
                value.strip().replace("Z", "+00:00")
            )
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _finite_number(value: Any, *, nonnegative: bool = False) -> float | None:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
    ):
        return None
    converted = float(value)
    if nonnegative and converted < 0.0:
        return None
    return converted


def _context_axes(
    context: OperationalContext,
) -> tuple[str, str, str, bool] | None:
    """Return the four mandatory exchangeability axes, if complete."""

    if (
        not context.regime_code
        or not context.shift_code
        or not context.season_code
        or context.maintenance is None
    ):
        return None
    return (
        context.regime_code,
        context.shift_code,
        context.season_code,
        context.maintenance,
    )


def _run_context(
    run: dict[str, Any],
    mine_id: str,
) -> tuple[OperationalContext | None, bool]:
    """Extract context and independently verify the governed batch kind."""

    batch_context = run.get("batch_context")
    if not isinstance(batch_context, dict):
        return None, False
    if not str(batch_context.get("kind") or "").startswith("governed_"):
        return None, False
    raw_context: Any = batch_context.get("operational_context")
    reports = batch_context.get("mine_reports")
    if isinstance(reports, list):
        report = next(
            (
                item
                for item in reports
                if isinstance(item, dict)
                and str(item.get("mine_id") or "") == mine_id
            ),
            None,
        )
        if report is None:
            return None, True
        raw_context = report.get("operational_context")
    try:
        return (
            OperationalContext.model_validate(
                raw_context if isinstance(raw_context, dict) else {}
            ),
            True,
        )
    except (TypeError, ValueError):
        return None, True


def _assessment(
    *,
    request: ProductionAnalysisRequest,
    compatibility_key: str,
    status: Literal["insufficient_history", "normal", "anomalous"],
    reason_code: str,
    explanation: str,
    current_raw_anomaly: float | None,
    current_data_quality: float | None,
    **counts_and_details: Any,
) -> CurrentTemporalAssessment:
    return CurrentTemporalAssessment(
        status=status,
        reason_code=reason_code,
        compatibility_key=compatibility_key,
        current_timestamp=request.window_end,
        current_raw_anomaly=current_raw_anomaly,
        current_data_quality=current_data_quality,
        explanation=explanation,
        **counts_and_details,
    )


def assess_current_temporal(
    repository: CurrentTemporalRepository,
    request: ProductionAnalysisRequest,
    result: ProductionAnalysisResult,
    compatibility_key: str,
    operational_context: OperationalContext,
    policy: CurrentTemporalPolicy | None = None,
) -> CurrentTemporalAssessment:
    """Assess the current raw-anomaly value against compatible prior windows.

    Selection is deliberately fail-closed:

    * the event time must be at or before ``request.window_start``;
    * feature and batch hashes must be valid and created in this repository;
    * the compatibility document must be governed and hash to the supplied
      compatibility key;
    * production regime, shift, season and maintenance state must all be
      present and exactly equal;
    * duplicate event-time revisions require an unambiguous authority winner.

    Reviewed labels are intentionally not queried.  This is independent
    temporal/drift evidence, not a learned normality or legality judgement.
    """

    active_policy = policy or CurrentTemporalPolicy()
    raw_current_value = _finite_number(
        result.raw_anomaly_statistic,
        nonnegative=True,
    )
    raw_current_quality = _finite_number(result.data_quality.score)
    current_quality = (
        min(1.0, max(0.0, raw_current_quality / 100.0))
        if raw_current_quality is not None
        else None
    )
    if (
        request.mine_id != result.mine_id
        or raw_current_value is None
        or current_quality is None
        or not isinstance(compatibility_key, str)
        or not compatibility_key.strip()
    ):
        return _assessment(
            request=request,
            compatibility_key=str(compatibility_key or ""),
            status="insufficient_history",
            reason_code="invalid_current_analysis",
            explanation=(
                "当前请求、物理结果或兼容性标识不完整，未生成时序结论。"
            ),
            current_raw_anomaly=raw_current_value,
            current_data_quality=current_quality,
        )

    expected_axes = _context_axes(operational_context)
    if expected_axes is None:
        return _assessment(
            request=request,
            compatibility_key=compatibility_key,
            status="insufficient_history",
            reason_code="operational_context_incomplete",
            explanation=(
                "生产工况、班次、季节或检修状态不完整；为避免混合不可比"
                "窗口，时序证据保持“历史不足”。"
            ),
            current_raw_anomaly=raw_current_value,
            current_data_quality=current_quality,
        )

    try:
        raw_features = repository.list_algorithm_features(
            mine_ids={request.mine_id},
            feature_code=_FEATURE_CODE,
            source_key=_SOURCE_KEY,
            feature_version=ALGORITHM_FEATURE_VERSION,
            limit=_REPOSITORY_CANDIDATE_LIMIT,
            include_overflow_sentinel=True,
        )
    except Exception:
        return _assessment(
            request=request,
            compatibility_key=compatibility_key,
            status="insufficient_history",
            reason_code="repository_read_error",
            explanation="读取不可变历史特征失败，已按失败关闭处理。",
            current_raw_anomaly=raw_current_value,
            current_data_quality=current_quality,
            repository_error_count=1,
        )

    candidate_count = len(raw_features)
    history_limit_exceeded = (
        candidate_count > _REPOSITORY_CANDIDATE_LIMIT
    )
    if history_limit_exceeded:
        return _assessment(
            request=request,
            compatibility_key=compatibility_key,
            status="insufficient_history",
            reason_code="history_limit_exceeded",
            explanation=(
                "候选历史超过可证明完整的读取上限，未对不完整截断样本"
                "作出时序判断。"
            ),
            current_raw_anomaly=raw_current_value,
            current_data_quality=current_quality,
            candidate_count=candidate_count,
            history_limit_exceeded=True,
        )

    rejected = {
        "rejected_invalid_count": 0,
        "rejected_future_count": 0,
        "rejected_compatibility_count": 0,
        "rejected_governance_count": 0,
        "rejected_quality_count": 0,
        "rejected_integrity_count": 0,
        "rejected_context_count": 0,
        "rejected_ambiguous_count": 0,
        "rejected_superseded_count": 0,
        "rejected_limit_count": 0,
    }
    cutoff = request.window_start.astimezone(UTC)
    run_cache: dict[str, dict[str, Any] | None] = {}
    candidates: list[tuple[datetime, dict[str, Any]]] = []

    for feature in raw_features:
        if not isinstance(feature, dict):
            rejected["rejected_invalid_count"] += 1
            continue
        if (
            feature.get("mine_id") != request.mine_id
            or feature.get("feature_code") != _FEATURE_CODE
            or str(feature.get("source_key") or "") != _SOURCE_KEY
            or feature.get("feature_version")
            != ALGORITHM_FEATURE_VERSION
            or feature.get("hash_valid") is not True
        ):
            rejected["rejected_invalid_count"] += 1
            continue
        observed_at = _instant(feature.get("observed_at"))
        feature_value = _finite_number(
            feature.get("value"),
            nonnegative=True,
        )
        feature_id = feature.get("feature_id")
        feature_hash = feature.get("feature_sha256")
        run_id = feature.get("run_id")
        if (
            observed_at is None
            or feature_value is None
            or not isinstance(feature_id, str)
            or not feature_id
            or not isinstance(feature_hash, str)
            or not feature_hash
            or not isinstance(run_id, str)
            or not run_id
        ):
            rejected["rejected_invalid_count"] += 1
            continue
        if observed_at > cutoff:
            rejected["rejected_future_count"] += 1
            continue

        feature_compatibility = feature.get("compatibility")
        feature_compatibility_key = feature.get("compatibility_key")
        if (
            not isinstance(feature_compatibility, dict)
            or feature_compatibility_key != compatibility_key
        ):
            rejected["rejected_compatibility_count"] += 1
            continue
        try:
            calculated_key = algorithm_feature_compatibility_key(
                feature_compatibility
            )
        except (TypeError, ValueError):
            calculated_key = None
        if calculated_key != compatibility_key:
            rejected["rejected_compatibility_count"] += 1
            continue
        if (
            feature_compatibility.get("trusted_mode") != "governed"
            or feature_compatibility.get("governance_complete") is not True
        ):
            rejected["rejected_governance_count"] += 1
            continue

        quality = _finite_number(feature.get("quality_score"))
        if (
            quality is None
            or quality < active_policy.minimum_quality_score
            or quality > 1.0
        ):
            rejected["rejected_quality_count"] += 1
            continue

        if run_id not in run_cache:
            try:
                loaded = repository.get_run(run_id)
                run_cache[run_id] = (
                    loaded if isinstance(loaded, dict) else None
                )
            except Exception:
                run_cache[run_id] = None
        run = run_cache[run_id]
        if (
            run is None
            or str(run.get("run_id") or "") != run_id
            or str(run.get("mine_id") or "") != request.mine_id
            or run.get("input_hash_valid") is not True
            or run.get("result_hash_valid") is not True
            or run.get("batch_integrity_valid") is not True
            or run.get("batch_reference_integrity_eligible") is not True
            or run.get("batch_integrity_origin") != "created"
        ):
            rejected["rejected_integrity_count"] += 1
            continue
        raw_input = run.get("input")
        run_window_end = (
            _instant(raw_input.get("window_end"))
            if isinstance(raw_input, dict)
            else None
        )
        if run_window_end is None:
            rejected["rejected_integrity_count"] += 1
            continue
        if run_window_end > cutoff:
            rejected["rejected_future_count"] += 1
            continue

        run_context, governed_batch = _run_context(
            run,
            request.mine_id,
        )
        if not governed_batch:
            rejected["rejected_governance_count"] += 1
            continue
        if (
            run_context is None
            or _context_axes(run_context) != expected_axes
        ):
            rejected["rejected_context_count"] += 1
            continue

        # Store the normalized value used by the detector without modifying
        # the immutable repository document used for authority selection.
        normalized = dict(feature)
        normalized["value"] = feature_value
        normalized["quality_score"] = quality
        candidates.append((observed_at, normalized))

    grouped: dict[datetime, list[dict[str, Any]]] = {}
    for observed_at, feature in candidates:
        grouped.setdefault(observed_at, []).append(feature)

    authoritative: list[tuple[datetime, dict[str, Any]]] = []
    for observed_at in sorted(grouped):
        group = grouped[observed_at]
        try:
            authority = select_authoritative_algorithm_feature(group)
        except (TypeError, ValueError):
            authority = {"status": "ambiguous", "selected": None}
        selected = authority.get("selected")
        if (
            authority.get("status") != "selected"
            or not isinstance(selected, dict)
        ):
            rejected["rejected_ambiguous_count"] += len(group)
            continue
        rejected["rejected_superseded_count"] += len(group) - 1
        authoritative.append((observed_at, selected))

    authoritative.sort(
        key=lambda item: (
            item[0],
            str(item[1].get("feature_id") or ""),
        )
    )
    eligible_sample_count = len(authoritative)
    selected_history = authoritative[-active_policy.maximum_samples :]
    rejected["rejected_limit_count"] = (
        eligible_sample_count - len(selected_history)
    )
    sample_count = len(selected_history)
    common = {
        "candidate_count": candidate_count,
        "eligible_sample_count": eligible_sample_count,
        "sample_count": sample_count,
        "selected_feature_ids": [
            str(feature["feature_id"])
            for _, feature in selected_history
        ],
        "selected_feature_hashes": [
            str(feature["feature_sha256"])
            for _, feature in selected_history
        ],
        **rejected,
    }
    if sample_count < active_policy.minimum_samples:
        return _assessment(
            request=request,
            compatibility_key=compatibility_key,
            status="insufficient_history",
            reason_code="insufficient_compatible_history",
            explanation=(
                f"仅找到 {sample_count} 个同矿、同模型、同四轴工况且完整"
                f"可信的先前窗口，少于最低 {active_policy.minimum_samples} 个。"
            ),
            current_raw_anomaly=raw_current_value,
            current_data_quality=current_quality,
            **common,
        )

    observations = [
        TemporalObservation(
            mine_id=request.mine_id,
            source_id="governed-history",
            metric_code=_FEATURE_CODE,
            timestamp=observed_at,
            value=float(feature["value"]),
            quality=float(feature["quality_score"]),
        )
        for observed_at, feature in selected_history
    ]
    observations.append(
        TemporalObservation(
            mine_id=request.mine_id,
            source_id="governed-history",
            metric_code=_FEATURE_CODE,
            timestamp=request.window_end,
            value=raw_current_value,
            quality=current_quality,
        )
    )
    try:
        detected = detect_temporal_anomalies(
            TemporalDetectionRequest(
                observations=observations,
                parameters=TemporalDetectionParameters(
                    baseline_window=active_policy.maximum_samples,
                    min_history=active_policy.minimum_samples,
                    min_baseline_quality=(
                        active_policy.minimum_quality_score
                    ),
                ),
            )
        )
        series = detected.series[0]
        current_point = series.points[-1]
    except Exception:
        return _assessment(
            request=request,
            compatibility_key=compatibility_key,
            status="insufficient_history",
            reason_code="temporal_detector_error",
            explanation="过去时点序列检测失败，已按失败关闭处理。",
            current_raw_anomaly=raw_current_value,
            current_data_quality=current_quality,
            detector_error_count=1,
            **common,
        )

    detail = {
        **common,
        "baseline_sample_count": current_point.baseline_sample_count,
        "current_value_anomaly": current_point.value_anomaly,
        "current_source_health_anomaly": (
            current_point.source_health_anomaly
        ),
        "rolling_robust_z": current_point.rolling_robust_z,
        "ewma_standardized": current_point.ewma_standardized,
        "signals": current_point.signals,
    }
    if current_point.insufficient_history:
        status: Literal[
            "insufficient_history",
            "normal",
            "anomalous",
        ] = "insufficient_history"
        reason_code = "detector_baseline_insufficient"
        explanation = (
            "候选窗口数量达到门槛，但异常隔离后的有效过去基线仍不足；"
            "未强行给出正常或异常结论。"
        )
    elif current_point.anomalous:
        status = "anomalous"
        reason_code = "past_only_temporal_anomaly"
        explanation = (
            "当前原始异常统计量被仅使用此前合格窗口的时序检测器标记；"
            "该结果只作并行证据，不改变物理求解结论。"
        )
    else:
        status = "normal"
        reason_code = "within_past_only_control_limits"
        explanation = (
            "当前原始异常统计量处于同矿、同模型、同四轴工况的过去"
            "时序控制范围内；该结果不替代物理交叉验证。"
        )
    return _assessment(
        request=request,
        compatibility_key=compatibility_key,
        status=status,
        reason_code=reason_code,
        explanation=explanation,
        current_raw_anomaly=raw_current_value,
        current_data_quality=current_quality,
        **detail,
    )


__all__ = [
    "CURRENT_TEMPORAL_METHOD_VERSION",
    "CurrentTemporalAssessment",
    "CurrentTemporalPolicy",
    "CurrentTemporalRepository",
    "assess_current_temporal",
]
