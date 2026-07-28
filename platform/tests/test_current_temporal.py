from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mineguard.casework import (
    ALGORITHM_FEATURE_VERSION,
    algorithm_feature_compatibility_key,
)
from mineguard.current_temporal import (
    CURRENT_TEMPORAL_METHOD_VERSION,
    CurrentTemporalPolicy,
    assess_current_temporal,
)
from mineguard.historical import OperationalContext
from mineguard.models import (
    DataQualityResult,
    MetricCode,
    MetricObservation,
    ProductionAnalysisRequest,
    ProductionAnalysisResult,
)
from mineguard.temporal import TemporalDetectorCode


CURRENT_START = datetime(2026, 7, 27, tzinfo=UTC)
CURRENT_END = CURRENT_START + timedelta(days=1)
CONTEXT = OperationalContext(
    regime_code="longwall",
    shift_code="night",
    season_code="wet",
    maintenance=False,
    approved_event_codes=["stocktake"],
    tags=["high-gas"],
)
COMPATIBILITY = {
    "compatibility_version": "test-v1",
    "algorithm_feature_version": ALGORITHM_FEATURE_VERSION,
    "trusted_mode": "governed",
    "governance_complete": True,
}
COMPATIBILITY_KEY = algorithm_feature_compatibility_key(COMPATIBILITY)


def _request() -> ProductionAnalysisRequest:
    return ProductionAnalysisRequest(
        mine_id="M001",
        window_start=CURRENT_START,
        window_end=CURRENT_END,
        observations=[
            MetricObservation(
                observation_id="reported",
                metric_code=MetricCode.REPORTED_PRODUCTION,
                value=100.0,
                tolerance_abs=1.0,
                source_group="reporting",
            )
        ],
    )


def _result(
    raw_anomaly: float | None = 1.0,
    *,
    quality: float = 95.0,
) -> ProductionAnalysisResult:
    return ProductionAnalysisResult(
        mine_id="M001",
        status="consistent",
        data_quality=DataQualityResult(
            score=quality,
            status="sufficient",
        ),
        solver_status="optimal",
        raw_anomaly_statistic=raw_anomaly,
        evidence_grade="B",
    )


def _feature(
    index: int,
    *,
    observed_at: datetime | None = None,
    value: float = 1.0,
    quality: float = 0.95,
    context: OperationalContext = CONTEXT,
    compatibility: dict[str, Any] = COMPATIBILITY,
    compatibility_key: str | None = None,
    hash_valid: bool = True,
    integrity_valid: bool = True,
    reference_eligible: bool = True,
    origin: str = "created",
    authority: dict[str, Any] | None = None,
    raw_observed_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    event_time = observed_at or (
        CURRENT_START - timedelta(days=40 - index)
    )
    run_id = f"run-{index:04d}"
    feature_id = f"feature-{index:04d}"
    created_at = event_time + timedelta(minutes=1)
    feature = {
        "run_id": run_id,
        "feature_id": feature_id,
        "feature_sha256": f"sha-{feature_id}",
        "mine_id": "M001",
        "observed_at": raw_observed_at or event_time.isoformat(),
        "created_at": created_at.isoformat(),
        "feature_code": "balance.raw_anomaly",
        "source_key": "",
        "feature_version": ALGORITHM_FEATURE_VERSION,
        "value": value,
        "quality_score": quality,
        "compatibility": compatibility,
        "compatibility_key": (
            compatibility_key
            if compatibility_key is not None
            else algorithm_feature_compatibility_key(compatibility)
        ),
        "authority_order": authority
        or {
            "source_revision_no": None,
            "source_revision_complete": False,
            "source_sequence_no": None,
            "source_sequence_complete": False,
            "source_received_at": None,
            "source_received_at_complete": False,
            "source_order_ambiguous": False,
            "repository_created_at": created_at.isoformat(),
            "repository_feature_id": feature_id,
        },
        "hash_valid": hash_valid,
    }
    run = {
        "run_id": run_id,
        "mine_id": "M001",
        "input": {
            "window_start": (
                event_time - timedelta(days=1)
            ).isoformat(),
            "window_end": event_time.isoformat(),
        },
        "input_hash_valid": True,
        "result_hash_valid": True,
        "batch_integrity_valid": integrity_valid,
        "batch_reference_integrity_eligible": reference_eligible,
        "batch_integrity_origin": origin,
        "batch_context": {
            "kind": "governed_production",
            "operational_context": context.model_dump(mode="json"),
        },
    }
    return feature, run


class _Repository:
    def __init__(
        self,
        items: list[tuple[dict[str, Any], dict[str, Any]]],
        *,
        fail_read: bool = False,
    ) -> None:
        self.rows = [item[0] for item in items]
        self.runs = {item[1]["run_id"]: item[1] for item in items}
        self.fail_read = fail_read
        self.calls: list[dict[str, Any]] = []
        self.run_calls: list[str] = []

    def list_algorithm_features(
        self,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        self.calls.append(kwargs)
        if self.fail_read:
            raise RuntimeError("database unavailable")
        return self.rows

    def get_run(self, run_id: str) -> dict[str, Any]:
        self.run_calls.append(run_id)
        return self.runs[run_id]

    def list_run_reference_labels(self, **_: Any) -> list[dict[str, Any]]:
        raise AssertionError("current temporal evidence must not read labels")


def _items(
    count: int,
    *,
    value: float = 1.0,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    return [_feature(index, value=value) for index in range(count)]


def test_normal_current_point_uses_only_compatible_past_windows() -> None:
    repository = _Repository(_items(20))
    request = _request()
    physical = _result(1.0)
    before = physical.model_dump(mode="json")

    assessment = assess_current_temporal(
        repository,
        request,
        physical,
        COMPATIBILITY_KEY,
        CONTEXT,
    )

    assert assessment.method_version == CURRENT_TEMPORAL_METHOD_VERSION
    assert assessment.status == "normal"
    assert assessment.reason_code == "within_past_only_control_limits"
    assert assessment.sample_count == 20
    assert assessment.baseline_sample_count == 20
    assert assessment.signals == []
    assert assessment.physical_status_unchanged is True
    assert physical.model_dump(mode="json") == before
    assert repository.calls == [
        {
            "mine_ids": {"M001"},
            "feature_code": "balance.raw_anomaly",
            "source_key": "",
            "feature_version": ALGORITHM_FEATURE_VERSION,
            "limit": 100_000,
            "include_overflow_sentinel": True,
        }
    ]


def test_large_current_jump_is_reported_as_shadow_temporal_anomaly() -> None:
    assessment = assess_current_temporal(
        _Repository(_items(20)),
        _request(),
        _result(100.0),
        COMPATIBILITY_KEY,
        CONTEXT,
    )

    assert assessment.status == "anomalous"
    assert assessment.reason_code == "past_only_temporal_anomaly"
    assert assessment.current_value_anomaly is True
    assert assessment.rolling_robust_z is not None
    assert assessment.rolling_robust_z > 1_000_000
    assert TemporalDetectorCode.ROLLING_MAD in {
        signal.detector for signal in assessment.signals
    }
    assert assessment.physical_status_unchanged is True


def test_filters_future_invalid_incompatible_low_quality_and_bad_runs() -> None:
    items = _items(20)
    rejected_event_time = CURRENT_START - timedelta(hours=1)
    items.extend(
        [
            _feature(
                100,
                observed_at=CURRENT_START + timedelta(seconds=1),
                value=9999.0,
            ),
            _feature(
                101,
                observed_at=rejected_event_time,
                hash_valid=False,
            ),
            _feature(
                102,
                observed_at=rejected_event_time,
                compatibility_key="wrong-key",
            ),
            _feature(
                103,
                observed_at=rejected_event_time,
                quality=0.79,
            ),
            _feature(
                104,
                observed_at=rejected_event_time,
                integrity_valid=False,
            ),
            _feature(
                105,
                observed_at=rejected_event_time,
                context=CONTEXT.model_copy(
                    update={"shift_code": "day"}
                ),
            ),
        ]
    )
    assessment = assess_current_temporal(
        _Repository(items),
        _request(),
        _result(1.0),
        COMPATIBILITY_KEY,
        CONTEXT,
    )

    assert assessment.status == "normal"
    assert assessment.candidate_count == 26
    assert assessment.sample_count == 20
    assert assessment.rejected_future_count == 1
    assert assessment.rejected_invalid_count == 1
    assert assessment.rejected_compatibility_count == 1
    assert assessment.rejected_quality_count == 1
    assert assessment.rejected_integrity_count == 1
    assert assessment.rejected_context_count == 1


def test_cutoff_is_inclusive_but_future_point_never_leaks() -> None:
    items = _items(19)
    items.append(_feature(50, observed_at=CURRENT_START))
    items.append(
        _feature(
            51,
            observed_at=CURRENT_START + timedelta(microseconds=1),
            value=1_000_000.0,
        )
    )

    assessment = assess_current_temporal(
        _Repository(items),
        _request(),
        _result(1.0),
        COMPATIBILITY_KEY,
        CONTEXT,
    )

    assert assessment.status == "normal"
    assert assessment.sample_count == 20
    assert assessment.rejected_future_count == 1
    assert "feature-0050" in assessment.selected_feature_ids
    assert "feature-0051" not in assessment.selected_feature_ids


def test_authority_deduplicates_revisions_before_recent_limit() -> None:
    items = _items(19)
    event_time = CURRENT_START - timedelta(days=1)
    old_feature, old_run = _feature(
        100,
        observed_at=event_time,
        value=1.0,
        authority={
            "source_revision_no": 1,
            "source_revision_complete": True,
            "source_sequence_no": None,
            "source_sequence_complete": False,
            "source_received_at": None,
            "source_received_at_complete": False,
            "source_order_ambiguous": False,
        },
    )
    new_feature, new_run = _feature(
        101,
        observed_at=event_time,
        value=1.0,
        authority={
            "source_revision_no": 2,
            "source_revision_complete": True,
            "source_sequence_no": None,
            "source_sequence_complete": False,
            "source_received_at": None,
            "source_received_at_complete": False,
            "source_order_ambiguous": False,
        },
    )
    # Both revisions must describe the exact same authority point.
    new_feature["observed_at"] = old_feature["observed_at"]
    new_run["input"]["window_end"] = old_run["input"]["window_end"]
    items.extend([(old_feature, old_run), (new_feature, new_run)])

    assessment = assess_current_temporal(
        _Repository(items),
        _request(),
        _result(1.0),
        COMPATIBILITY_KEY,
        CONTEXT,
    )

    assert assessment.status == "normal"
    assert assessment.eligible_sample_count == 20
    assert assessment.sample_count == 20
    assert assessment.rejected_superseded_count == 1
    assert "feature-0101" in assessment.selected_feature_ids
    assert "feature-0100" not in assessment.selected_feature_ids


def test_only_most_recent_policy_window_is_sent_to_detector() -> None:
    assessment = assess_current_temporal(
        _Repository(_items(8)),
        _request(),
        _result(1.0),
        COMPATIBILITY_KEY,
        CONTEXT,
        CurrentTemporalPolicy(
            minimum_samples=3,
            maximum_samples=5,
        ),
    )

    assert assessment.status == "normal"
    assert assessment.eligible_sample_count == 8
    assert assessment.sample_count == 5
    assert assessment.rejected_limit_count == 3
    assert assessment.selected_feature_ids == [
        "feature-0003",
        "feature-0004",
        "feature-0005",
        "feature-0006",
        "feature-0007",
    ]


@pytest.mark.parametrize(
    ("context", "reason"),
    [
        (
            OperationalContext(
                regime_code="",
                shift_code="night",
                season_code="wet",
                maintenance=False,
            ),
            "operational_context_incomplete",
        ),
        (
            CONTEXT,
            "invalid_current_analysis",
        ),
    ],
)
def test_incomplete_inputs_fail_closed(
    context: OperationalContext,
    reason: str,
) -> None:
    result = _result(None) if reason == "invalid_current_analysis" else _result()
    assessment = assess_current_temporal(
        _Repository(_items(20)),
        _request(),
        result,
        COMPATIBILITY_KEY,
        context,
    )

    assert assessment.status == "insufficient_history"
    assert assessment.reason_code == reason
    assert assessment.physical_status_unchanged is True


def test_repository_failure_is_explicit_and_fail_closed() -> None:
    assessment = assess_current_temporal(
        _Repository([], fail_read=True),
        _request(),
        _result(),
        COMPATIBILITY_KEY,
        CONTEXT,
    )

    assert assessment.status == "insufficient_history"
    assert assessment.reason_code == "repository_read_error"
    assert assessment.repository_error_count == 1
