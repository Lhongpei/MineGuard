from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator

import pytest

from mineguard import cli
from mineguard.api import MineGuardRequestHandler
from mineguard.casework import LocalRepository
from mineguard.demo_seed import (
    DEMO_BATCH_PREFIX,
    DEMO_DATASET_ID,
    DEMO_MINES,
    DEMO_STATE_MARKER,
    DemoSeedError,
    DemoStateOwnershipError,
    claim_demo_state_directory,
    clear_demo_data,
    demo_seed_status,
    seed_demo_data,
)
from mineguard.edge_store import EdgeTelemetryRepository


@contextmanager
def repositories(
    path: Path,
) -> Iterator[tuple[LocalRepository, EdgeTelemetryRepository]]:
    repository = LocalRepository(path)
    edge_repository = EdgeTelemetryRepository(path)
    try:
        yield repository, edge_repository
    finally:
        edge_repository.close()
        repository.close()


@pytest.fixture(scope="module")
def seeded_database(
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    database = tmp_path_factory.mktemp("demo-seed") / "mineguard.db"
    with repositories(database) as (repository, edge_repository):
        seeded = seed_demo_data(
            repository,
            edge_repository,
            days=21,
            anchor_date=datetime.now(UTC).date(),
        )
        assert seeded["created"] is True
    return database


def test_seed_builds_real_multimine_series_and_is_idempotent(
    seeded_database: Path,
) -> None:
    with repositories(seeded_database) as (repository, edge_repository):
        status = demo_seed_status(repository, edge_repository)
        assert status["active"] is True
        assert status["manifest"]["days"] == 21
        assert status["counts"]["batches"] == 21
        assert status["counts"]["mines"] == len(DEMO_MINES)
        assert status["counts"]["features"] > 1_000
        assert status["counts"]["alerts"] == 5
        assert status["counts"]["verification_runs"] == len(DEMO_MINES)
        assert status["integrity"] == {
            "all_batch_hashes_valid": True,
            "all_batch_lifecycle_chains_valid": True,
        }

        repeated = seed_demo_data(
            repository,
            edge_repository,
            days=21,
            anchor_date=status["manifest"]["anchor_date"],
        )
        assert repeated["created"] is False
        assert repeated["reused"] is True
        assert repeated["counts"] == status["counts"]


def test_demo_history_contains_missing_anomaly_and_historical_casework(
    seeded_database: Path,
) -> None:
    with repositories(seeded_database) as (repository, edge_repository):
        batches = repository.list_batches(limit=100)
        assert len(batches) == 21
        assert all(
            str(item["batch_id"]).startswith(DEMO_BATCH_PREFIX)
            for item in batches
        )
        assert all(item["context"]["demo_seed"] is True for item in batches)
        assert all(
            item["context"]["demo_dataset"]["regulatory_use"]
            == "prohibited"
            for item in batches
        )
        assert any(
            row["technical_status"] == "not_received"
            for batch in batches
            for row in batch["response"]["items"]
        )
        assert any(
            row["technical_status"] == "inconsistent"
            for batch in batches
            for row in batch["response"]["items"]
        )

        cases = repository.list_cases(include_archived=True)
        assert any(item["workflow_status"] == "closed" for item in cases)
        closed = next(
            item for item in cases if item["workflow_status"] == "closed"
        )
        events = repository.get_case_events(closed["case_id"])
        assert [item["created_at"] for item in events] == sorted(
            item["created_at"] for item in events
        )
        assert events[-1]["created_at"] < datetime.now(UTC).isoformat()
        assert repository.verify_case_chain(closed["case_id"]) is True
        assert any(
            event["action"] == "reopen"
            for item in cases
            for event in repository.get_case_events(item["case_id"])
        )

        alerts = edge_repository.list_alerts(
            mine_ids={mine.mine_id for mine in DEMO_MINES},
            limit=100,
        )
        assert {item["category"] for item in alerts} >= {
            "methane",
            "personnel",
            "source_health",
        }
        assert all(item["operational"] is False for item in alerts)
        assert all(item["mode"] == "shadow" for item in alerts)
        runs = edge_repository.list_verification_runs(limit=100)
        by_mine = {item["mine_id"]: item for item in runs}
        assert by_mine["DEMO-M005"]["status"] == "insufficient_history"
        assert any(
            int(item["overall_clue_level"]) >= 1 for item in runs
        )


def test_api_classifies_demo_as_local_trial_not_formal_governed(
    seeded_database: Path,
) -> None:
    with repositories(seeded_database) as (repository, _edge_repository):
        latest = repository.get_latest_batch()
        assert latest is not None
        dataset = MineGuardRequestHandler._demo_dataset_from_batch(latest)
        assert dataset is not None
        assert dataset["active"] is True
        assert dataset["dataset_id"] == DEMO_DATASET_ID
        assert dataset["regulatory_use"] == "prohibited"
        assert MineGuardRequestHandler._is_governed_batch(latest) is False
        handler = object.__new__(MineGuardRequestHandler)
        handler.server = SimpleNamespace(repository=repository)
        assert handler._active_demo_dataset(None) == dataset
        assert (
            latest["response"]["received_mine_count"]
            == len(DEMO_MINES) - 1
        )
        source_report = {"report_reference": "demo-report"}
        decorated = (
            MineGuardRequestHandler._report_payload_with_demo_notice(
                source_report,
                dataset,
            )
        )
        assert decorated["demo_dataset"] == dataset
        assert "严禁用于监管认定" in decorated["demo_disclaimer"]
        assert source_report == {"report_reference": "demo-report"}


def test_clear_is_scoped_and_seed_refuses_a_mixed_store(
    tmp_path: Path,
) -> None:
    database = tmp_path / "mixed.db"
    with repositories(database) as (repository, edge_repository):
        edge_repository.upsert_mine(
            {
                "mine_id": "REAL-M001",
                "mine_name": "真实数据占位矿",
            },
            actor_id="test",
        )
        with pytest.raises(DemoSeedError, match="dedicated"):
            seed_demo_data(
                repository,
                edge_repository,
                days=21,
                anchor_date="2026-07-28",
            )
        cleared = clear_demo_data(repository, edge_repository)
        assert cleared["cleared"] is True
        assert edge_repository.list_mines()[0]["mine_id"] == "REAL-M001"


def test_cli_state_marker_refuses_an_unowned_nonempty_directory(
    tmp_path: Path,
) -> None:
    owned = tmp_path / "owned"
    claimed = claim_demo_state_directory(owned, create=True)
    assert claimed == owned.resolve()
    assert (owned / DEMO_STATE_MARKER).is_file()
    assert claim_demo_state_directory(owned, create=False) == claimed

    unowned = tmp_path / "unowned"
    unowned.mkdir()
    (unowned / "keep.txt").write_text("formal state", encoding="utf-8")
    with pytest.raises(DemoStateOwnershipError, match="non-empty"):
        claim_demo_state_directory(unowned, create=True)


def test_cli_seed_status_and_clear_round_trip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "cli-demo"
    arguments = [
        "--state-directory",
        str(state),
    ]
    assert (
        cli.main(
            [
                "seed-demo",
                *arguments,
                "--days",
                "21",
                "--anchor-date",
                "2026-07-28",
            ]
        )
        == 0
    )
    seeded = json.loads(capsys.readouterr().out)
    assert seeded["active"] is True
    assert seeded["counts"]["batches"] == 21

    assert cli.main(["demo-status", *arguments]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["active"] is True

    assert cli.main(["clear-demo", *arguments]) == 0
    cleared = json.loads(capsys.readouterr().out)
    assert cleared["cleared"] is True
