from __future__ import annotations

import json
import sqlite3

import pytest
import mineguard.casework as casework

from mineguard.casework import (
    ALGORITHM_FEATURE_VERSION,
    AlgorithmRecordConflictError,
    AlgorithmRecordIntegrityError,
    LocalRepository,
    canonical_json,
    select_authoritative_algorithm_feature,
    sha256_json,
)


def batch_request(batch_id: str, window_end: str) -> dict:
    return {
        "batch_id": batch_id,
        "portfolio_name": "算法特征测试",
        "expected_mine_ids": ["M001"],
        "analyses": [
            {
                "mine_id": "M001",
                "window_start": "2026-07-01T00:00:00Z",
                "window_end": window_end,
                "observations": [],
            }
        ],
    }


def batch_result(raw_score: float) -> dict:
    return {
        "items": [
            {
                "mine_id": "M001",
                "technical_status": "consistent",
                "review_priority": "NONE",
                "summary": "test",
                "analysis": {
                    "mine_id": "M001",
                    "status": "consistent",
                    "raw_anomaly_statistic": raw_score,
                    "minimum_reported_gap": 0.0,
                    "data_quality": {"score": 80.0},
                    "reconciled_metrics": {
                        "coal.reported_output_t": {
                            "inferred_value": 10.0,
                            "normalized_residual": raw_score / 2,
                        }
                    },
                    "observation_adjustments": [
                        {
                            "observation_id": "belt-window",
                            "metric_code": "coal.main_transport_t",
                            "source_group": "belt",
                            "normalized_residual": raw_score / 3,
                        }
                    ],
                },
            }
        ]
    }


def test_batch_persistence_derives_immutable_temporal_features() -> None:
    repository = LocalRepository()
    try:
        repository.save_portfolio_batch(
            batch_request("B1", "2026-07-02T00:00:00Z"),
            batch_result(3.0),
            "0.4.0",
        )

        features = repository.list_algorithm_features(mine_ids={"M001"})
        assert {(item["feature_code"], item["source_key"]) for item in features} == {
            ("balance.raw_anomaly", ""),
            ("balance.minimum_reported_gap_t", ""),
            ("residual.normalized", "coal.reported_output_t"),
            (
                "source.signed_normalized_residual",
                "belt|coal.main_transport_t",
            ),
        }
        assert all(item["hash_valid"] for item in features)
        assert all(item["quality_score"] == 0.8 for item in features)
        assert all(
            item["feature_version"] == ALGORITHM_FEATURE_VERSION for item in features
        )
        assert all(
            item["authority_order"]["repository_created_at"] == item["created_at"]
            for item in features
        )
        assert all(
            item["authority_order"]["repository_feature_id"] == item["feature_id"]
            for item in features
        )
        assert all(
            item["compatibility"]["trusted_mode"] == "direct" for item in features
        )
        assert all(
            item["compatibility"]["governance_complete"] is False for item in features
        )
        assert all(
            item["compatibility_key"] == sha256_json(item["compatibility"])
            for item in features
        )

        before = repository.list_algorithm_features(end_at="2026-07-02T00:00:00Z")
        assert before == []
        through = repository.list_algorithm_features(end_at="2026-07-03T00:00:00Z")
        assert len(through) == 4
        assert (
            len(
                repository.list_algorithm_features(
                    feature_version=ALGORITHM_FEATURE_VERSION,
                    limit=2,
                )
            )
            == 2
        )
        assert (
            len(
                repository.list_algorithm_features(
                    feature_version=ALGORITHM_FEATURE_VERSION,
                    limit=2,
                    include_overflow_sentinel=True,
                )
            )
            == 3
        )
    finally:
        repository.close()


def test_feature_insert_is_exactly_idempotent_and_detects_conflicts() -> None:
    repository = LocalRepository()
    try:
        repository.save_portfolio_batch(
            batch_request("B1", "2026-07-02T00:00:00Z"),
            batch_result(3.0),
            "0.4.0",
        )
        run = repository.list_runs("B1")[0]
        arguments = {
            "run_id": run["run_id"],
            "batch_id": run["batch_id"],
            "mine_id": run["mine_id"],
            "input_snapshot": run["input"],
            "analysis_result": run["result"],
            "context_snapshot": run["batch_context"],
            "engine_version": run["engine_version"],
            "created_at": run["created_at"],
        }
        repository._insert_algorithm_features(**arguments)
        assert len(repository.list_algorithm_features()) == 4

        changed_result = json.loads(canonical_json(run["result"]))
        changed_result["raw_anomaly_statistic"] = 99.0
        with pytest.raises(
            AlgorithmRecordConflictError,
            match="natural key",
        ):
            repository._insert_algorithm_features(
                **{**arguments, "analysis_result": changed_result}
            )

        repository._connection.execute(
            """
            UPDATE analysis_feature_windows
            SET feature_sha256 = ?
            WHERE feature_code = ?
            """,
            ("0" * 64, "balance.raw_anomaly"),
        )
        repository._connection.commit()
        with pytest.raises(
            AlgorithmRecordIntegrityError,
            match="hash verification",
        ):
            repository._insert_algorithm_features(**arguments)
    finally:
        repository.close()


def test_feature_event_time_is_normalized_to_utc_for_range_ordering() -> None:
    repository = LocalRepository()
    try:
        repository.save_portfolio_batch(
            batch_request("B-offset", "2026-07-02T08:00:00+08:00"),
            batch_result(3.0),
            "0.4.0",
        )
        features = repository.list_algorithm_features()
        assert features
        assert {item["observed_at"] for item in features} == {"2026-07-02T00:00:00Z"}
        stored_times = {
            str(row["observed_at"])
            for row in repository._connection.execute(
                "SELECT observed_at FROM analysis_feature_windows"
            ).fetchall()
        }
        assert stored_times == {"2026-07-02T00:00:00Z"}
        assert repository.list_algorithm_features(
            start_at="2026-07-02T00:00:00Z",
            end_at="2026-07-03T00:00:00Z",
        )
        assert repository.list_algorithm_features(end_at="2026-07-02T00:00:00Z") == []
    finally:
        repository.close()


def test_precompatibility_feature_is_preserved_under_legacy_version(
    tmp_path,
) -> None:
    database = tmp_path / "precompat.db"
    first = LocalRepository(database)
    first.save_portfolio_batch(
        batch_request("B1", "2026-07-02T00:00:00Z"),
        batch_result(3.0),
        "0.4.0",
    )
    first.close()

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            """
            SELECT feature_id, feature_json
            FROM analysis_feature_windows
            WHERE feature_code = ?
            """,
            ("balance.raw_anomaly",),
        ).fetchone()
        assert row is not None
        document = json.loads(row["feature_json"])
        document.pop("compatibility")
        document.pop("compatibility_key")
        connection.execute(
            """
            UPDATE analysis_feature_windows
            SET feature_json = ?, feature_sha256 = ?
            WHERE feature_id = ?
            """,
            (
                canonical_json(document),
                sha256_json(document),
                str(row["feature_id"]),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    migrated = LocalRepository(database)
    try:
        assert (
            len(
                migrated.list_algorithm_features(
                    feature_version=ALGORITHM_FEATURE_VERSION
                )
            )
            == 4
        )
        legacy = migrated.list_algorithm_features(
            feature_version="2.1.0-pre-compatibility"
        )
        assert len(legacy) == 1
        assert legacy[0]["hash_valid"] is True
        assert "compatibility" not in legacy[0]
    finally:
        migrated.close()


def test_authoritative_selection_uses_receive_order_not_batch_id(
    monkeypatch,
) -> None:
    received = iter(
        (
            "2026-07-02T00:00:00Z",
            "2026-07-02T00:00:01Z",
        )
    )
    monkeypatch.setattr(casework, "_now", lambda: next(received))
    repository = LocalRepository()
    try:
        repository.save_portfolio_batch(
            batch_request("Z-older", "2026-07-02T00:00:00Z"),
            batch_result(1.0),
            "0.4.0",
        )
        repository.save_portfolio_batch(
            batch_request("A-newer", "2026-07-02T00:00:00Z"),
            batch_result(9.0),
            "0.4.0",
        )
        candidates = repository.list_algorithm_features(
            feature_code="balance.raw_anomaly",
            feature_version=ALGORITHM_FEATURE_VERSION,
        )
        assert [item["batch_id"] for item in candidates] == [
            "Z-older",
            "A-newer",
        ]
        selection = select_authoritative_algorithm_feature(candidates)
        assert selection["status"] == "selected"
        assert selection["basis"] == "repository_receipt_order"
        assert selection["selected"]["batch_id"] == "A-newer"
        assert selection["selected"]["value"] == 9.0
    finally:
        repository.close()


def _context_with_source_order(
    observation_id: str,
    *,
    revision_no: int,
    sequence_no: int,
    received_at: str,
) -> dict:
    return {
        "kind": "governed_production_ingest",
        "profile_id": "coal-balance",
        "profile_version": "7",
        "registry_snapshot_hash": "a" * 64,
        "observation_envelopes": [
            {
                "observation_id": observation_id,
                "source_id": "belt",
                "revision": revision_no,
                "revision_no": revision_no,
                "sequence_no": sequence_no,
                "received_at": received_at,
            }
        ],
    }


def _save_with_source_order(
    repository: LocalRepository,
    batch_id: str,
    *,
    revision_no: int,
    sequence_no: int,
    received_at: str,
    score: float,
) -> None:
    repository.save_portfolio_batch(
        batch_request(batch_id, "2026-07-02T00:00:00Z"),
        batch_result(score),
        "0.4.0",
        context_obj=_context_with_source_order(
            f"{batch_id}-source",
            revision_no=revision_no,
            sequence_no=sequence_no,
            received_at=received_at,
        ),
    )


def test_source_revision_precedes_receipt_and_ties_are_ambiguous(
    monkeypatch,
) -> None:
    received = iter(
        (
            "2026-07-02T00:00:00Z",
            "2026-07-02T00:00:01Z",
            "2026-07-02T00:00:02Z",
        )
    )
    monkeypatch.setattr(casework, "_now", lambda: next(received))
    repository = LocalRepository()
    try:
        _save_with_source_order(
            repository,
            "revision-2-first",
            revision_no=2,
            sequence_no=10,
            received_at="2026-07-01T10:00:00Z",
            score=8.0,
        )
        _save_with_source_order(
            repository,
            "revision-1-later",
            revision_no=1,
            sequence_no=99,
            received_at="2026-07-01T11:00:00Z",
            score=3.0,
        )
        candidates = repository.list_algorithm_features(
            feature_code="balance.raw_anomaly",
            feature_version=ALGORITHM_FEATURE_VERSION,
        )
        assert all(
            item["compatibility"]["trusted_mode"] == "governed"
            and item["compatibility"]["profile_id"] == "coal-balance"
            and item["compatibility"]["profile_version"] == "7"
            and item["compatibility"]["registry_snapshot_hash"] == "a" * 64
            and item["compatibility"]["governance_complete"] is True
            for item in candidates
        )
        selection = select_authoritative_algorithm_feature(candidates)
        assert selection["status"] == "selected"
        assert selection["basis"] == "source_revision_no"
        assert selection["selected"]["batch_id"] == "revision-2-first"

        _save_with_source_order(
            repository,
            "revision-2-tie",
            revision_no=2,
            sequence_no=10,
            received_at="2026-07-01T10:00:00Z",
            score=9.0,
        )
        tied = repository.list_algorithm_features(
            feature_code="balance.raw_anomaly",
            feature_version=ALGORITHM_FEATURE_VERSION,
        )
        ambiguous = select_authoritative_algorithm_feature(tied)
        assert ambiguous["status"] == "ambiguous"
        assert ambiguous["selected"] is None
        assert ambiguous["ambiguity_reason"] == "source_order_tie"
    finally:
        repository.close()


def test_feature_backfill_and_detector_findings_are_idempotent(
    tmp_path,
) -> None:
    database = tmp_path / "state.db"
    first = LocalRepository(database)
    first.save_portfolio_batch(
        batch_request("B1", "2026-07-02T00:00:00Z"),
        batch_result(2.0),
        "0.4.0",
    )
    first.close()

    second = LocalRepository(database)
    try:
        assert len(second.list_algorithm_features()) == 4
        finding = {
            "mine_id": "M001",
            "observed_at": "2026-07-02T00:00:00Z",
            "feature_code": "balance.raw_anomaly",
            "source_key": "",
            "detector_code": "rolling_mad",
            "detector_version": "1",
            "status": "normal",
            "score": 0.2,
            "baseline_sample_count": 20,
        }
        assert second.save_detector_findings([finding]) == 1
        assert second.save_detector_findings([finding]) == 0
        stored = second.list_detector_findings(mine_ids={"M001"})
        assert len(stored) == 1
        assert stored[0]["hash_valid"] is True
    finally:
        second.close()


def detector_finding(
    *,
    mine_id: str = "M001",
    observed_at: str = "2026-07-02T00:00:00Z",
    status: str = "normal",
) -> dict:
    return {
        "mine_id": mine_id,
        "observed_at": observed_at,
        "feature_code": "balance.raw_anomaly",
        "source_key": "",
        "detector_code": "rolling_mad",
        "detector_version": "2.1",
        "status": status,
        "score": 0.2,
        "baseline_sample_count": 20,
        "explanation": "within threshold",
    }


def test_detector_finding_retry_conflict_and_transaction_rollback() -> None:
    repository = LocalRepository()
    try:
        finding = detector_finding()
        assert repository.save_detector_findings([finding]) == 1
        assert repository.save_detector_findings([finding]) == 0
        stored = repository.list_detector_findings()
        assert repository.save_detector_findings(stored) == 0
        assert stored[0]["finding_id"].startswith("finding_")

        conflict = {**finding, "status": "anomalous"}
        with pytest.raises(
            AlgorithmRecordConflictError,
            match="natural key",
        ):
            repository.save_detector_findings([conflict])

        new_finding = detector_finding(
            mine_id="M002",
            observed_at="2026-07-03T00:00:00Z",
        )
        with pytest.raises(AlgorithmRecordConflictError):
            repository.save_detector_findings([new_finding, conflict])
        assert repository.list_detector_findings(mine_ids={"M002"}) == []
    finally:
        repository.close()


def test_detector_finding_hash_integrity_and_filters() -> None:
    repository = LocalRepository()
    try:
        first = detector_finding()
        second = detector_finding(
            mine_id="M002",
            observed_at="2026-07-04T00:00:00+00:00",
        )
        assert repository.save_detector_findings([first, second]) == 2
        assert (
            len(
                repository.list_detector_findings(
                    mine_ids={"M001"},
                    detector_version="2.1",
                    start_at="2026-07-01T00:00:00Z",
                    end_at="2026-07-03T00:00:00Z",
                )
            )
            == 1
        )
        assert repository.list_detector_findings(mine_ids=set()) == []

        repository._connection.execute(
            "UPDATE detector_findings SET finding_sha256 = ? WHERE mine_id = ?",
            ("0" * 64, "M001"),
        )
        repository._connection.commit()
        damaged = repository.list_detector_findings(mine_ids={"M001"})
        assert damaged[0]["hash_valid"] is False
        with pytest.raises(
            AlgorithmRecordIntegrityError,
            match="hash verification",
        ):
            repository.save_detector_findings([first])

        with pytest.raises(ValueError, match="earlier"):
            repository.list_detector_findings(
                start_at="2026-07-03T00:00:00Z",
                end_at="2026-07-02T00:00:00Z",
            )
    finally:
        repository.close()


def model_snapshot(
    *,
    scope_key: str = "mine:M001|balance.raw_anomaly",
    version: str = "2.1",
) -> dict:
    return {
        "detector_code": "rolling_mad",
        "detector_version": version,
        "scope_key": scope_key,
        "training_start": "2026-06-01T00:00:00Z",
        "training_end": "2026-07-01T00:00:00Z",
        "sample_count": 30,
        "activation_status": "active",
        "parameters": {"window": 30, "threshold": 4.0},
        "training_feature_sha256": "a" * 64,
    }


def test_model_snapshots_are_versioned_hash_checked_and_scoped() -> None:
    repository = LocalRepository()
    try:
        snapshot = model_snapshot()
        assert repository.save_algorithm_model_snapshots([snapshot]) == 1
        assert repository.save_algorithm_model_snapshots([snapshot]) == 0
        listed = repository.list_algorithm_model_snapshots(
            scope_keys={"mine:M001|balance.raw_anomaly"},
            detector_code="rolling_mad",
            start_at="2026-07-01T00:00:00Z",
            end_at="2026-07-02T00:00:00Z",
        )
        assert len(listed) == 1
        assert listed[0]["snapshot_id"].startswith("model_")
        assert listed[0]["hash_valid"] is True
        assert repository.save_algorithm_model_snapshots(listed) == 0
        assert repository.list_algorithm_model_snapshots(scope_keys=set()) == []
        assert (
            repository.list_algorithm_model_snapshots(end_at="2026-07-01T00:00:00Z")
            == []
        )

        with pytest.raises(
            AlgorithmRecordConflictError,
            match="natural key",
        ):
            repository.save_algorithm_model_snapshots(
                [{**snapshot, "sample_count": 31}]
            )
        assert (
            repository.save_algorithm_model_snapshots([model_snapshot(version="2.2")])
            == 1
        )

        with pytest.raises(ValueError, match="training_start"):
            repository.save_algorithm_model_snapshots(
                [
                    {
                        **model_snapshot(version="invalid"),
                        "training_start": "2026-08-01T00:00:00Z",
                    }
                ]
            )

        repository._connection.execute(
            "UPDATE algorithm_model_snapshots SET snapshot_json = ? "
            "WHERE detector_version = ?",
            ("{}", "2.1"),
        )
        repository._connection.commit()
        damaged = repository.list_algorithm_model_snapshots(detector_version="2.1")
        assert damaged[0]["hash_valid"] is False
        with pytest.raises(AlgorithmRecordIntegrityError):
            repository.save_algorithm_model_snapshots([snapshot])
    finally:
        repository.close()


def alert_episode(
    *,
    mine_id: str = "M001",
    version: str = "2.1",
    started_at: str = "2026-07-02T01:00:00Z",
    ended_at: str = "2026-07-02T03:00:00Z",
) -> dict:
    return {
        "mine_id": mine_id,
        "feature_code": "source.signed_normalized_residual",
        "source_key": "belt|coal.main_transport_t",
        "detector_code": "temporal_ensemble",
        "detector_version": version,
        "started_at": started_at,
        "ended_at": ended_at,
        "peak_score": 6.2,
        "finding_count": 3,
        "detectors": ["rolling_mad", "cusum"],
        "explanation": "persistent positive shift",
    }


def test_alert_episodes_are_idempotent_versioned_and_time_scoped() -> None:
    repository = LocalRepository()
    try:
        episode = alert_episode()
        assert repository.save_alert_episodes([episode]) == 1
        assert repository.save_alert_episodes([episode]) == 0
        assert repository.save_alert_episodes([alert_episode(version="2.2")]) == 1
        assert (
            repository.save_alert_episodes(
                [
                    alert_episode(
                        mine_id="M002",
                        started_at="2026-07-05T01:00:00Z",
                        ended_at="2026-07-05T03:00:00Z",
                    )
                ]
            )
            == 1
        )

        listed = repository.list_alert_episodes(
            mine_ids={"M001"},
            detector_version="2.1",
            start_at="2026-07-02T02:00:00Z",
            end_at="2026-07-02T02:30:00Z",
        )
        assert len(listed) == 1
        assert listed[0]["episode_id"].startswith("episode_")
        assert listed[0]["hash_valid"] is True
        assert repository.save_alert_episodes(listed) == 0
        assert repository.list_alert_episodes(mine_ids=set()) == []
        assert repository.list_alert_episodes(end_at="2026-07-02T01:00:00Z") == []

        with pytest.raises(AlgorithmRecordConflictError):
            repository.save_alert_episodes(
                [{**episode, "ended_at": "2026-07-02T04:00:00Z"}]
            )
        with pytest.raises(ValueError, match="started_at"):
            repository.save_alert_episodes(
                [
                    alert_episode(
                        version="invalid-time",
                        started_at="2026-07-03T00:00:00Z",
                        ended_at="2026-07-02T00:00:00Z",
                    )
                ]
            )
        with pytest.raises(ValueError, match="at least 1"):
            repository.save_alert_episodes(
                [
                    {
                        **alert_episode(version="invalid-count"),
                        "finding_count": 0,
                    }
                ]
            )
    finally:
        repository.close()


def _replace_feature_table_with_legacy_schema(database) -> None:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("DROP INDEX idx_feature_series_time")
        connection.execute(
            "ALTER TABLE analysis_feature_windows RENAME TO feature_windows_current"
        )
        connection.execute(
            """
            CREATE TABLE analysis_feature_windows (
                feature_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES analysis_runs(run_id),
                batch_id TEXT NOT NULL REFERENCES batches(batch_id),
                mine_id TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                feature_code TEXT NOT NULL,
                source_key TEXT NOT NULL,
                value REAL NOT NULL,
                quality_score REAL,
                feature_sha256 TEXT NOT NULL,
                feature_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                legacy_note TEXT,
                UNIQUE(run_id, feature_code, source_key)
            )
            """
        )
        rows = connection.execute(
            "SELECT * FROM feature_windows_current ORDER BY feature_id"
        ).fetchall()
        for index, row in enumerate(rows):
            document = json.loads(row["feature_json"])
            if index == 0:
                document.pop("feature_version")
            connection.execute(
                """
                INSERT INTO analysis_feature_windows (
                    feature_id, run_id, batch_id, mine_id, observed_at,
                    feature_code, source_key, value, quality_score,
                    feature_sha256, feature_json, created_at, legacy_note
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["feature_id"],
                    row["run_id"],
                    row["batch_id"],
                    row["mine_id"],
                    row["observed_at"],
                    row["feature_code"],
                    row["source_key"],
                    row["value"],
                    row["quality_score"],
                    sha256_json(document),
                    canonical_json(document),
                    row["created_at"],
                    f"preserved-{index}",
                ),
            )
        connection.execute("DROP TABLE feature_windows_current")
        connection.commit()
    finally:
        connection.close()


def test_legacy_feature_schema_migrates_without_losing_payloads(
    tmp_path,
) -> None:
    database = tmp_path / "legacy.db"
    first = LocalRepository(database)
    first.save_portfolio_batch(
        batch_request("B1", "2026-07-02T00:00:00Z"),
        batch_result(2.0),
        "0.4.0",
    )
    first.close()
    _replace_feature_table_with_legacy_schema(database)

    migrated = LocalRepository(database)
    try:
        features = migrated.list_algorithm_features()
        assert len(features) == 5
        assert all(item["hash_valid"] for item in features)
        assert {item["feature_version"] for item in features} == {
            "legacy",
            ALGORITHM_FEATURE_VERSION,
        }
        assert (
            len(
                migrated.list_algorithm_features(
                    feature_version=ALGORITHM_FEATURE_VERSION
                )
            )
            == 4
        )
        assert len(migrated.list_algorithm_features(feature_version="legacy")) == 1
        notes = {
            row["legacy_note"]
            for row in migrated._connection.execute(
                "SELECT legacy_note FROM analysis_feature_windows "
                "WHERE legacy_note IS NOT NULL"
            ).fetchall()
        }
        assert notes == {f"preserved-{index}" for index in range(4)}
        unique_indexes = migrated._unique_index_columns("analysis_feature_windows")
        assert (
            "run_id",
            "feature_code",
            "source_key",
            "feature_version",
        ) in unique_indexes
        assert (
            "run_id",
            "feature_code",
            "source_key",
        ) not in unique_indexes
    finally:
        migrated.close()
