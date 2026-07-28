from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from mineguard.casework import (
    BatchConflictError,
    InvalidCaseActionError,
    LocalRepository,
    VersionConflictError,
)
from mineguard.portfolio import (
    PortfolioAnalysisRequest,
    analyze_production_portfolio,
)


ROOT = Path(__file__).resolve().parents[1]


def _trial_batch() -> tuple[PortfolioAnalysisRequest, object]:
    inconsistent = json.loads(
        (ROOT / "examples" / "production_inconsistent.json").read_text()
    )
    inconsistent["mine_id"] = "M001"
    request = PortfolioAnalysisRequest(
        batch_id="casework-batch",
        portfolio_name="本地试点",
        expected_mine_ids=["M001", "M002"],
        analyses=[inconsistent],
    )
    return request, analyze_production_portfolio(request)


def test_batch_is_idempotent_and_conflict_safe(tmp_path: Path) -> None:
    database = tmp_path / "casework.sqlite3"
    request, result = _trial_batch()
    repository = LocalRepository(database)
    try:
        assert repository.save_portfolio_batch(
            request, result, "0.2.0"
        )["created"]
        assert not repository.save_portfolio_batch(
            request, result, "0.2.0"
        )["created"]
        assert len(repository.list_cases()) == 2
        assert len(repository.list_runs(request.batch_id)) == 1

        changed = request.model_copy(
            update={"portfolio_name": "相同ID不同内容"}
        )
        with pytest.raises(BatchConflictError):
            repository.save_portfolio_batch(changed, result, "0.2.0")
    finally:
        repository.close()


def test_case_state_machine_uses_optimistic_versions(tmp_path: Path) -> None:
    request, result = _trial_batch()
    repository = LocalRepository(tmp_path / "state.sqlite3")
    try:
        repository.save_portfolio_batch(request, result, "0.2.0")
        case = repository.list_cases(priority="P1")[0]
        case_id = case["case_id"]

        reviewing = repository.apply_case_action(
            case_id,
            action="start_review",
            expected_version=case["version"],
            actor="reviewer",
        )
        assert reviewing["workflow_status"] == "reviewing"

        with pytest.raises(VersionConflictError):
            repository.apply_case_action(
                case_id,
                action="add_note",
                expected_version=case["version"],
                actor="reviewer",
                note="过期版本",
            )
        with pytest.raises(InvalidCaseActionError):
            repository.apply_case_action(
                case_id,
                action="close",
                expected_version=reviewing["version"],
                actor="reviewer",
            )

        closed = repository.apply_case_action(
            case_id,
            action="close",
            expected_version=reviewing["version"],
            actor="reviewer",
            note="已调阅原始记录，作为技术问题关闭。",
            disposition="confirmed_technical_issue",
        )
        assert closed["workflow_status"] == "closed"
        assert repository.verify_case_chain(case_id)
        assert len(repository.get_case_events(case_id)) == 3
    finally:
        repository.close()


def test_closed_case_can_be_archived_and_restored_without_reopening(
    tmp_path: Path,
) -> None:
    request, result = _trial_batch()
    repository = LocalRepository(tmp_path / "case-archive.sqlite3")
    try:
        repository.save_portfolio_batch(request, result, "0.4.0")
        case = repository.list_cases(priority="P1")[0]

        with pytest.raises(InvalidCaseActionError, match="closed"):
            repository.apply_case_action(
                case["case_id"],
                action="archive_case",
                expected_version=case["version"],
                actor="supervisor",
                note="归档已完成事项。",
            )

        closed = repository.apply_case_action(
            case["case_id"],
            action="close",
            expected_version=case["version"],
            actor="supervisor",
            note="现场原始记录已复核。",
            disposition="confirmed_technical_issue",
        )
        with pytest.raises(InvalidCaseActionError, match="note is required"):
            repository.apply_case_action(
                case["case_id"],
                action="archive_case",
                expected_version=closed["version"],
                actor="supervisor",
            )

        archived = repository.apply_case_action(
            case["case_id"],
            action="archive_case",
            expected_version=closed["version"],
            actor="supervisor",
            note="事项已办结，移出日常列表。",
        )
        assert archived["workflow_status"] == "closed"
        assert archived["version"] == closed["version"] + 1
        assert archived["archived_at"] is not None
        assert archived["archived_by"] == "supervisor"
        assert archived["archived_reason"] == "事项已办结，移出日常列表。"
        assert repository.list_cases(priority="P1") == []
        assert repository.list_cases(
            priority="P1",
            include_archived=True,
        )[0]["case_id"] == case["case_id"]
        assert repository.get_case(case["case_id"]) == archived
        assert repository.verify_case_chain(case["case_id"])

        with pytest.raises(InvalidCaseActionError, match="must be restored"):
            repository.apply_case_action(
                case["case_id"],
                action="reopen",
                expected_version=archived["version"],
                actor="supervisor",
                note="归档状态不能直接重开。",
            )

        with pytest.raises(InvalidCaseActionError, match="note is required"):
            repository.apply_case_action(
                case["case_id"],
                action="restore_case",
                expected_version=archived["version"],
                actor="supervisor",
            )

        restored = repository.apply_case_action(
            case["case_id"],
            action="restore_case",
            expected_version=archived["version"],
            actor="supervisor",
            note="需要重新显示以便复查。",
        )
        assert restored["workflow_status"] == "closed"
        assert restored["version"] == archived["version"] + 1
        assert restored["archived_at"] is None
        assert restored["archived_by"] is None
        assert restored["archived_reason"] is None
        assert repository.list_cases(priority="P1")[0]["case_id"] == case["case_id"]
        events = repository.get_case_events(case["case_id"])
        assert events[-2]["action"] == "archive_case"
        assert events[-1]["action"] == "restore_case"
        assert repository.verify_case_chain(case["case_id"])
    finally:
        repository.close()


def test_case_archive_columns_are_added_to_an_existing_database(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-cases.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY,
                run_id TEXT,
                batch_id TEXT NOT NULL,
                mine_id TEXT NOT NULL,
                issue_code TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                priority TEXT NOT NULL,
                technical_status TEXT NOT NULL,
                evidence_grade TEXT,
                workflow_status TEXT NOT NULL,
                disposition TEXT,
                assignee TEXT,
                version INTEGER NOT NULL,
                recommended_checks_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(batch_id, mine_id)
            )
            """
        )

    repository = LocalRepository(database)
    repository.close()
    with sqlite3.connect(database) as connection:
        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(cases)")
        }
        assert {"archived_at", "archived_by", "archived_reason"} <= columns


def test_hash_chain_detects_event_tampering_and_survives_reopen(
    tmp_path: Path,
) -> None:
    database = tmp_path / "audit.sqlite3"
    request, result = _trial_batch()
    repository = LocalRepository(database)
    repository.save_portfolio_batch(request, result, "0.2.0")
    case_id = repository.list_cases(priority="P1")[0]["case_id"]
    assert repository.verify_case_chain(case_id)
    repository.close()

    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE case_events SET note = ? "
            "WHERE case_id = ? AND sequence = 1",
            ("被外部修改", case_id),
        )
        connection.commit()
    finally:
        connection.close()

    reopened = LocalRepository(database)
    try:
        assert reopened.get_case(case_id)["case_id"] == case_id
        assert not reopened.verify_case_chain(case_id)
    finally:
        reopened.close()


def test_integrity_checks_detect_case_state_and_run_snapshot_changes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "integrity.sqlite3"
    request, result = _trial_batch()
    repository = LocalRepository(database)
    repository.save_portfolio_batch(request, result, "0.2.0")
    case = repository.list_cases(priority="P1")[0]
    case_id = case["case_id"]
    run_id = case["run_id"]
    assert run_id is not None
    assert repository.verify_case_chain(case_id)
    assert repository.verify_run_hashes(run_id)
    repository.close()

    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "UPDATE cases SET summary = ? WHERE case_id = ?",
            ("被外部修改的摘要", case_id),
        )
        connection.execute(
            "UPDATE analysis_runs SET input_json = ? WHERE run_id = ?",
            ('{"tampered":true}', run_id),
        )
        connection.commit()
    finally:
        connection.close()

    reopened = LocalRepository(database)
    try:
        assert not reopened.verify_case_chain(case_id)
        assert not reopened.verify_run_hashes(run_id)
    finally:
        reopened.close()


def test_conclusion_requires_a_different_approver(tmp_path: Path) -> None:
    request, result = _trial_batch()
    repository = LocalRepository(tmp_path / "approval.sqlite3")
    try:
        repository.save_portfolio_batch(request, result, "0.3.0")
        case = repository.list_cases(priority="P1")[0]
        submitted = repository.apply_case_action(
            case["case_id"],
            action="submit_conclusion",
            expected_version=case["version"],
            actor="reviewer-a",
            note="原始记录支持部分技术线索，提交审批。",
            disposition="partially_supported",
        )
        assert submitted["workflow_status"] == "pending_approval"
        assert submitted["conclusion_by"] == "reviewer-a"

        with pytest.raises(InvalidCaseActionError):
            repository.apply_case_action(
                case["case_id"],
                action="approve",
                expected_version=submitted["version"],
                actor="reviewer-a",
                note="试图自行批准",
            )

        approved = repository.apply_case_action(
            case["case_id"],
            action="approve",
            expected_version=submitted["version"],
            actor="supervisor-b",
            note="已复核原始依据，同意关闭。",
        )
        assert approved["workflow_status"] == "closed"
        assert approved["approval_by"] == "supervisor-b"
        assert approved["disposition"] == "partially_supported"
        assert repository.verify_case_chain(case["case_id"])
    finally:
        repository.close()


def test_rejected_conclusion_returns_to_review(tmp_path: Path) -> None:
    request, result = _trial_batch()
    repository = LocalRepository(tmp_path / "rejection.sqlite3")
    try:
        repository.save_portfolio_batch(request, result, "0.3.0")
        case = repository.list_cases(priority="P1")[0]
        submitted = repository.apply_case_action(
            case["case_id"],
            action="submit_conclusion",
            expected_version=case["version"],
            actor="reviewer-a",
            note="提交排除结论。",
            disposition="excluded",
        )
        rejected = repository.apply_case_action(
            case["case_id"],
            action="reject",
            expected_version=submitted["version"],
            actor="supervisor-b",
            note="原始设备日志尚未核对，请继续复核。",
        )

        assert rejected["workflow_status"] == "reviewing"
        assert rejected["disposition"] is None
        assert rejected["conclusion_by"] is None
        assert rejected["approval_note"] == (
            "原始设备日志尚未核对，请继续复核。"
        )
        assert repository.verify_case_chain(case["case_id"])
    finally:
        repository.close()


def test_conclusion_author_can_withdraw_pending_conclusion(
    tmp_path: Path,
) -> None:
    request, result = _trial_batch()
    repository = LocalRepository(tmp_path / "withdrawal.sqlite3")
    try:
        repository.save_portfolio_batch(request, result, "0.4.0")
        case = repository.list_cases(priority="P1")[0]
        submitted = repository.apply_case_action(
            case["case_id"],
            action="submit_conclusion",
            expected_version=case["version"],
            actor="reviewer-a",
            note="提交技术问题结论。",
            disposition="confirmed_technical_issue",
        )

        with pytest.raises(
            InvalidCaseActionError,
            match="only the conclusion author",
        ):
            repository.apply_case_action(
                case["case_id"],
                action="withdraw_conclusion",
                expected_version=submitted["version"],
                actor="reviewer-b",
                note="试图撤回他人的结论。",
            )
        with pytest.raises(
            InvalidCaseActionError,
            match="note is required",
        ):
            repository.apply_case_action(
                case["case_id"],
                action="withdraw_conclusion",
                expected_version=submitted["version"],
                actor="reviewer-a",
            )

        withdrawn = repository.apply_case_action(
            case["case_id"],
            action="withdraw_conclusion",
            expected_version=submitted["version"],
            actor="reviewer-a",
            note="发现设备时钟记录尚未核对，撤回后继续复核。",
        )

        assert withdrawn["workflow_status"] == "reviewing"
        assert withdrawn["disposition"] is None
        assert withdrawn["conclusion_by"] is None
        assert withdrawn["conclusion_at"] is None
        assert withdrawn["approval_by"] is None
        assert withdrawn["approval_at"] is None
        assert withdrawn["approval_note"] is None

        events = repository.get_case_events(case["case_id"])
        assert events[-2]["action"] == "submit_conclusion"
        assert events[-2]["after"]["conclusion_by"] == "reviewer-a"
        assert events[-1]["action"] == "withdraw_conclusion"
        assert events[-1]["note"] == (
            "发现设备时钟记录尚未核对，撤回后继续复核。"
        )
        assert events[-1]["before"]["disposition"] == (
            "confirmed_technical_issue"
        )
        assert events[-1]["after"]["disposition"] is None
        assert repository.verify_case_chain(case["case_id"])

        with pytest.raises(
            InvalidCaseActionError,
            match="requires pending_approval",
        ):
            repository.apply_case_action(
                case["case_id"],
                action="withdraw_conclusion",
                expected_version=withdrawn["version"],
                actor="reviewer-a",
                note="不能重复撤回。",
            )
    finally:
        repository.close()
