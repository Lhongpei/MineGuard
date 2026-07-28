from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mineguard.calibration import (
    HistoricalCalibrationPolicy,
    apply_historical_calibration,
    select_historical_calibration,
)
from mineguard.casework import (
    ALGORITHM_FEATURE_VERSION,
    algorithm_feature_compatibility_key,
    build_algorithm_feature_compatibility,
    sha256_json,
)
from mineguard.historical import OperationalContext
from mineguard.models import (
    BalanceParameters,
    MetricCode,
    MetricObservation,
    ProductionAnalysisRequest,
)


START = datetime(2026, 7, 21, tzinfo=UTC)
ENGINE_VERSION = "0.4.0"
PROFILE_ID = "coal-balance"
PROFILE_VERSION = "7"
REGISTRY_HASH = "a" * 64
_UNSET = object()
OPERATIONAL_CONTEXT = OperationalContext(
    regime_code="normal-production",
    shift_code="daily",
    season_code="summer",
    maintenance=False,
)


def analysis_request(
    *,
    window_days: int = 1,
    quality_gate: float = 60.0,
    metric_code: MetricCode = MetricCode.RAW_SALES,
    source_group: str = "sales",
    tolerance_abs: float = 1.0,
    dependency_domains: list[str] | None = None,
) -> ProductionAnalysisRequest:
    return ProductionAnalysisRequest(
        mine_id="M001",
        window_start=START,
        window_end=START + timedelta(days=window_days),
        parameters=BalanceParameters(quality_gate=quality_gate),
        observations=[
            MetricObservation(
                observation_id="raw-sales",
                metric_code=metric_code,
                value=10.0,
                tolerance_abs=tolerance_abs,
                source_group=source_group,
                dependency_domains=dependency_domains or [],
            )
        ],
    )


def compatibility(
    request: ProductionAnalysisRequest | None = None,
    *,
    engine_version: str = ENGINE_VERSION,
    trusted_mode: str = "governed",
    profile_id: str = PROFILE_ID,
    profile_version: str = PROFILE_VERSION,
    registry_snapshot_hash: str = REGISTRY_HASH,
) -> dict[str, Any]:
    return build_algorithm_feature_compatibility(
        request or analysis_request(),
        engine_version=engine_version,
        trusted_mode=trusted_mode,
        profile_id=profile_id,
        profile_version=profile_version,
        registry_snapshot_hash=registry_snapshot_hash,
    )


DEFAULT_COMPATIBILITY = compatibility()
DEFAULT_COMPATIBILITY_KEY = algorithm_feature_compatibility_key(DEFAULT_COMPATIBILITY)


def feature(
    index: int,
    *,
    mine_id: str = "M001",
    observed_at: datetime | None = None,
    quality: float | None = 0.9,
    status: str = "consistent",
    value: float | str = 1.0,
    hash_valid: bool = True,
    feature_version: str = ALGORITHM_FEATURE_VERSION,
    compatibility_document: dict[str, Any] | None | object = _UNSET,
) -> dict[str, Any]:
    event_time = observed_at or START - timedelta(days=30 - index)
    feature_id = f"feature-{index:03d}"
    document: dict[str, Any] = {
        "run_id": f"run-{index:03d}",
        "feature_id": feature_id,
        "feature_sha256": sha256_json({"feature_id": feature_id}),
        "mine_id": mine_id,
        "observed_at": event_time.isoformat(),
        "created_at": (event_time + timedelta(minutes=1)).isoformat(),
        "feature_code": "balance.raw_anomaly",
        "feature_version": feature_version,
        "source_key": "",
        "value": value,
        "quality_score": quality,
        "details": {"technical_status": status},
        "authority_order": {
            "source_observation_count": 0,
            "source_revision_no": None,
            "source_revision_complete": False,
            "source_sequence_no": None,
            "source_sequence_complete": False,
            "source_received_at": None,
            "source_received_at_complete": False,
            "source_order_ambiguous": False,
            "repository_created_at": (event_time + timedelta(minutes=1)).isoformat(),
            "repository_feature_id": feature_id,
        },
        "hash_valid": hash_valid,
    }
    active_compatibility = (
        DEFAULT_COMPATIBILITY
        if compatibility_document is _UNSET
        else compatibility_document
    )
    if isinstance(active_compatibility, dict):
        document["compatibility"] = active_compatibility
        document["compatibility_key"] = algorithm_feature_compatibility_key(
            active_compatibility
        )
    return document


def selection(
    rows: list[dict[str, Any]],
    *,
    policy: HistoricalCalibrationPolicy | None = None,
):
    return select_historical_calibration(
        rows,
        mine_id="M001",
        cutoff=START,
        compatibility_key=DEFAULT_COMPATIBILITY_KEY,
        compatibility_document=DEFAULT_COMPATIBILITY,
        policy=policy,
    )


def test_calibration_requires_enough_clean_prior_windows() -> None:
    cold = selection([feature(index, value=float(index)) for index in range(19)])
    assert cold.status == "insufficient_history"
    assert cold.eligible_sample_count == 19
    assert cold.scores == []
    assert cold.selected_feature_ids == []

    ready = selection([feature(index, value=float(index)) for index in range(20)])
    assert ready.status == "ready"
    assert ready.selected_sample_count == 20
    assert ready.scores == [float(index) for index in range(20)]
    assert ready.selected_feature_ids == [f"feature-{index:03d}" for index in range(20)]
    assert ready.selected_feature_hashes == [
        sha256_json({"feature_id": f"feature-{index:03d}"}) for index in range(20)
    ]


def test_calibration_excludes_future_low_quality_abnormal_and_invalid_rows() -> None:
    rows = [feature(index, value=float(index)) for index in range(20)]
    rows.extend(
        [
            feature(
                101,
                observed_at=START + timedelta(seconds=1),
                value=999.0,
            ),
            feature(
                102,
                observed_at=START - timedelta(days=1),
                quality=0.5,
                value=998.0,
            ),
            feature(
                103,
                observed_at=START - timedelta(days=1),
                status="inconsistent",
                value=997.0,
            ),
            feature(
                104,
                observed_at=START - timedelta(days=1),
                value="bad",
            ),
            feature(
                105,
                observed_at=START - timedelta(days=1),
                hash_valid=False,
                value=996.0,
            ),
            feature(
                106,
                mine_id="M002",
                observed_at=START - timedelta(days=1),
                value=995.0,
            ),
        ]
    )

    result = selection(rows)

    assert result.status == "ready"
    assert 999.0 not in result.scores
    assert 998.0 not in result.scores
    assert 997.0 not in result.scores
    assert result.excluded_future_count == 1
    assert result.excluded_quality_count == 1
    assert result.excluded_status_count == 1
    assert result.excluded_invalid_count == 3


def test_calibration_keeps_only_the_most_recent_bounded_history() -> None:
    rows = [
        feature(
            index,
            observed_at=START - timedelta(days=100 - index),
            value=float(index),
        )
        for index in range(100)
    ]
    result = selection(
        list(reversed(rows)),
        policy=HistoricalCalibrationPolicy(
            minimum_samples=10,
            maximum_samples=25,
        ),
    )

    assert result.eligible_sample_count == 100
    assert result.selected_sample_count == 25
    assert result.scores == [float(index) for index in range(75, 100)]


def test_incompatible_engine_governance_window_and_model_are_excluded() -> None:
    rows = [feature(index, value=float(index)) for index in range(20)]
    incompatible_documents = [
        compatibility(engine_version="0.5.0"),
        compatibility(profile_id="other-profile"),
        compatibility(profile_version="8"),
        compatibility(registry_snapshot_hash="b" * 64),
        compatibility(trusted_mode="direct"),
        compatibility(analysis_request(window_days=2)),
        compatibility(analysis_request(quality_gate=75.0)),
        compatibility(
            analysis_request(
                source_group="weighbridge",
                tolerance_abs=2.0,
                dependency_domains=["erp", "weighbridge"],
            )
        ),
    ]
    rows.extend(
        feature(
            200 + index,
            observed_at=START - timedelta(hours=index + 1),
            value=900.0 + index,
            compatibility_document=document,
        )
        for index, document in enumerate(incompatible_documents)
    )
    rows.extend(
        [
            feature(
                300,
                observed_at=START - timedelta(hours=20),
                compatibility_document=None,
            ),
            feature(
                301,
                observed_at=START - timedelta(hours=21),
                feature_version="legacy",
            ),
        ]
    )

    result = selection(rows)

    assert result.status == "ready"
    assert result.excluded_incompatible_count == 10
    assert result.eligible_sample_count == 20
    assert max(result.scores) == 19.0


def test_compatibility_document_locks_every_required_dimension() -> None:
    document = DEFAULT_COMPATIBILITY
    assert document["algorithm_feature_version"] == "2.1.0"
    assert document["engine_version"] == ENGINE_VERSION
    assert document["window_duration_seconds"] == 86_400.0
    assert len(document["parameters_sha256"]) == 64
    assert len(document["observation_structure_sha256"]) == 64
    assert document["observation_structure"] == [
        {
            "metric_code": "sales.raw_shipped_t",
            "source_group": "sales",
            "tolerance_abs": 1.0,
            "tolerance_rel": 0.0,
            "resolution": 0.0,
            "dependency_domains": [],
            "source_reliability": 1.0,
        }
    ]
    assert document["trusted_mode"] == "governed"
    assert document["profile_id"] == PROFILE_ID
    assert document["profile_version"] == PROFILE_VERSION
    assert document["registry_snapshot_hash"] == REGISTRY_HASH
    assert document["governance_complete"] is True


class _Reader:
    def __init__(
        self,
        rows: list[dict[str, Any]],
        *,
        reviewed: bool = True,
    ) -> None:
        self.rows = rows
        self.reviewed = reviewed
        self.calls: list[dict[str, Any]] = []

    def list_algorithm_features(self, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls.append(kwargs)
        return self.rows

    def list_run_reference_labels(
        self,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        assert kwargs["labels"] == {"verified_normal"}
        if not self.reviewed:
            return []
        return [
            {"run_id": row["run_id"]}
            for row in self.rows
            if isinstance(row.get("run_id"), str)
        ]

    def get_run(self, run_id: str) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "input_sha256": f"input-{run_id}",
            "result_sha256": f"result-{run_id}",
            "batch_request_sha256": f"request-{run_id}",
            "batch_response_sha256": f"response-{run_id}",
            "batch_context_sha256": f"context-{run_id}",
            "batch_reference_integrity_eligible": True,
            "batch_context": {
                "kind": "governed_production",
                "operational_context": OPERATIONAL_CONTEXT.model_dump(
                    mode="json"
                ),
            },
        }

    def get_run_reference_label(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        if not self.reviewed:
            return None
        return {
            "run_id": run_id,
            "sequence": 1,
            "label": "verified_normal",
            "event_hash": f"label-{run_id}",
            "created_at": "2026-07-20T00:00:00Z",
            "reference_eligible": True,
        }


def test_apply_requires_explicit_governance_and_never_mutates_request() -> None:
    request = analysis_request()
    rows = [feature(index, value=float(index)) for index in range(20)]

    missing_reader = _Reader(rows)
    unchanged, missing = apply_historical_calibration(
        missing_reader,
        request,
    )
    assert missing.status == "compatibility_required"
    assert missing.excluded_incompatible_count == 20
    assert unchanged.calibration_scores == []
    assert request.calibration_scores == []

    contextless, contextless_selection = apply_historical_calibration(
        _Reader(rows),
        request,
        engine_version=ENGINE_VERSION,
        trusted_mode="governed",
        profile_id=PROFILE_ID,
        profile_version=PROFILE_VERSION,
        registry_snapshot_hash=REGISTRY_HASH,
    )
    assert contextless_selection.status == "operational_context_required"
    assert contextless.calibration_scores == []

    reader = _Reader(rows)
    calibrated, selected = apply_historical_calibration(
        reader,
        request,
        engine_version=ENGINE_VERSION,
        trusted_mode="governed",
        profile_id=PROFILE_ID,
        profile_version=PROFILE_VERSION,
        registry_snapshot_hash=REGISTRY_HASH,
        operational_context=OPERATIONAL_CONTEXT,
    )

    assert selected.status == "ready"
    assert calibrated is not request
    assert calibrated.calibration_scores == selected.scores
    assert len(selected.reference_manifest) == 20
    assert selected.reference_manifest_sha256 is not None
    assert len(selected.reference_manifest_sha256) == 64
    assert request.calibration_scores == []
    assert reader.calls == [
        {
            "mine_ids": {"M001"},
            "feature_code": "balance.raw_anomaly",
            "feature_version": ALGORITHM_FEATURE_VERSION,
            "limit": 100_000,
            "include_overflow_sentinel": True,
        }
    ]

    unreviewed, unreviewed_selection = apply_historical_calibration(
        _Reader(rows, reviewed=False),
        request,
        engine_version=ENGINE_VERSION,
        trusted_mode="governed",
        profile_id=PROFILE_ID,
        profile_version=PROFILE_VERSION,
        registry_snapshot_hash=REGISTRY_HASH,
        operational_context=OPERATIONAL_CONTEXT,
    )
    assert unreviewed.calibration_scores == []
    assert (
        unreviewed_selection.status
        == "insufficient_reviewed_history"
    )
    assert unreviewed_selection.reviewed_labels_required is True
    assert unreviewed_selection.excluded_label_count == 20


def test_mismatched_compatibility_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="does not match"):
        select_historical_calibration(
            [feature(1)],
            mine_id="M001",
            cutoff=START,
            compatibility_key="0" * 64,
            compatibility_document=DEFAULT_COMPATIBILITY,
        )
