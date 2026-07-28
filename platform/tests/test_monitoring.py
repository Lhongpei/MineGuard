from __future__ import annotations

from datetime import UTC, datetime, timedelta

from mineguard.casework import LocalRepository
from mineguard.monitoring import (
    TEMPORAL_DETECTOR_VERSION,
    refresh_temporal_audit,
)


def _persist_score(
    repository: LocalRepository,
    *,
    index: int,
    score: float,
) -> None:
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


def test_refresh_persists_model_findings_and_episodes_idempotently() -> None:
    repository = LocalRepository()
    try:
        for index, score in enumerate(
            [0.1, -0.1, 0.0, 0.2, -0.2, 0.1, 0.0, -0.1, 5.0]
        ):
            _persist_score(repository, index=index, score=score)

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

        findings = repository.list_detector_findings(
            mine_ids={"M001"}
        )
        episodes = repository.list_alert_episodes(mine_ids={"M001"})
        snapshots = repository.list_algorithm_model_snapshots(
            detector_code="temporal_ensemble"
        )
        assert findings and all(item["hash_valid"] for item in findings)
        assert episodes and all(item["hash_valid"] for item in episodes)
        assert len(snapshots) == 1
        assert snapshots[0]["hash_valid"] is True
        assert snapshots[0]["detector_version"] == (
            TEMPORAL_DETECTOR_VERSION
        )

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
