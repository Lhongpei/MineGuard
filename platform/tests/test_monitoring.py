from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mineguard.casework import LocalRepository
from mineguard.monitoring import (
    TEMPORAL_DETECTOR_VERSION,
    active_temporal_parameters,
    refresh_temporal_audit,
)


def _persist_score(
    repository: LocalRepository,
    *,
    index: int,
    score: float,
) -> str:
    end = datetime(2026, 7, 1, tzinfo=UTC) + timedelta(days=index)
    repository.save_portfolio_batch(
        {
            "batch_id": f"B-{index:02d}",
            "portfolio_name": "时序审计测试",
            "expected_mine_ids": ["M001"],
            "analyses": [
                {
                    "mine_id": "M001",
                    "window_start": (
                        end - timedelta(days=1)
                    ).isoformat(),
                    "window_end": end.isoformat(),
                    "observations": [],
                }
            ],
        },
        {
            "items": [
                {
                    "mine_id": "M001",
                    "technical_status": "consistent",
                    "review_priority": "NONE",
                    "summary": "test",
                    "analysis": {
                        "mine_id": "M001",
                        "status": "consistent",
                        "raw_anomaly_statistic": score,
                        "data_quality": {"score": 95.0},
                    },
                }
            ]
        },
        "0.4.0",
        context_obj={
            "kind": "governed_production_ingest",
            "profile_id": "test-profile",
            "profile_version": "1",
            "registry_snapshot_hash": "a" * 64,
            "observation_envelopes": [],
        },
    )
    runs = repository.list_runs(f"B-{index:02d}")
    assert len(runs) == 1
    return str(runs[0]["run_id"])


def test_refresh_persists_model_findings_and_episodes_idempotently() -> None:
    repository = LocalRepository()
    try:
        baseline_run_ids = []
        for index, score in enumerate(
            [0.1, -0.1, 0.0, 0.2, -0.2, 0.1, 0.0, -0.1, 5.0]
        ):
            run_id = _persist_score(
                repository,
                index=index,
                score=score,
            )
            if index < 8:
                baseline_run_ids.append(run_id)
        for run_id in baseline_run_ids:
            repository.append_run_reference_label(
                run_id,
                label="verified_normal",
                actor="supervisor",
                note="原始凭证与现场记录复核一致",
                expected_sequence=0,
            )

        first = refresh_temporal_audit(
            repository,
            mine_ids={"M001"},
        )
        assert first["status"] == "anomalous"
        assert first["series_count"] == 1
        assert first["finding_count"] > 0
        assert first["episode_count"] == 1
        assert first["inserted_findings"] == first["finding_count"]
        assert first["inserted_episodes"] == 1
        assert first["inserted_model_snapshots"] == 1
        assert first["baseline_eligible_observation_count"] == 8
        assert first["baseline_ineligible_observation_count"] == 1

        findings = repository.list_detector_findings(
            mine_ids={"M001"}
        )
        episodes = repository.list_alert_episodes(mine_ids={"M001"})
        snapshots = repository.list_algorithm_model_snapshots(
            detector_code="temporal_ensemble"
        )
        assert findings and all(item["hash_valid"] for item in findings)
        assert all(
            item["baseline_eligible"] is False
            and item["accepted_into_baseline"] is False
            and item["reset_seed_sample_count"] == 0
            for item in findings
        )
        assert episodes and all(item["hash_valid"] for item in episodes)
        assert len(snapshots) == 1
        assert snapshots[0]["hash_valid"] is True
        assert snapshots[0]["detector_version"] == (
            TEMPORAL_DETECTOR_VERSION
        )
        assert snapshots[0]["parameters"]["minimum_relative_scale"] == 0.0
        assert (
            snapshots[0]["parameters"][
                "baseline_reset_confirmation_points"
            ]
            is None
        )
        assert snapshots[0]["parameters"][
            "baseline_reset_candidate_max_gap_seconds"
        ] == 172_800.0
        assert snapshots[0]["parameters"][
            "episode_max_gap_seconds"
        ] == 172_800.0
        assert snapshots[0]["parameters"][
            "baseline_admission_policy"
        ] == "current_verified_normal_and_reference_eligible"

        second = refresh_temporal_audit(
            repository,
            mine_ids={"M001"},
        )
        assert second["finding_count"] == first["finding_count"]
        assert second["episode_count"] == first["episode_count"]
        assert second["inserted_findings"] == 0
        assert second["inserted_episodes"] == 0
        assert second["inserted_model_snapshots"] == 0
    finally:
        repository.close()


def test_unreviewed_history_remains_cold_start_and_is_not_normal() -> None:
    repository = LocalRepository()
    try:
        for index, score in enumerate(
            [0.1, -0.1, 0.0, 0.2, -0.2, 0.1, 0.0, -0.1, 0.1]
        ):
            _persist_score(repository, index=index, score=score)

        summary = refresh_temporal_audit(
            repository,
            mine_ids={"M001"},
        )

        assert summary["status"] == "insufficient_history"
        assert summary["finding_count"] == 0
        assert summary["episode_count"] == 0
        assert summary["baseline_eligible_observation_count"] == 0
        assert summary["baseline_ineligible_observation_count"] == 9
    finally:
        repository.close()


def test_active_policy_disables_self_learning_and_bounds_time_gaps() -> None:
    parameters = active_temporal_parameters()

    assert parameters.minimum_relative_scale == 0.0
    assert parameters.baseline_reset_confirmation_points is None
    assert (
        parameters.baseline_reset_candidate_max_gap_seconds
        == 172_800.0
    )
    assert parameters.episode_max_gap_seconds == 172_800.0


def test_refresh_cold_start_still_records_detector_configuration() -> None:
    repository = LocalRepository()
    try:
        summary = refresh_temporal_audit(
            repository,
            mine_ids={"M-COLD"},
        )

        assert summary["status"] == "insufficient_history"
        assert summary["finding_count"] == 0
        assert summary["episode_count"] == 0
        assert summary["inserted_model_snapshots"] == 1
        assert repository.list_detector_findings() == []
        assert repository.list_alert_episodes() == []
        assert len(repository.list_algorithm_model_snapshots()) == 1
    finally:
        repository.close()
