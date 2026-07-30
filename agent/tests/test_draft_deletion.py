from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from enterprise_agent.agent_v2.runtime import AgentFlowRuntime
from enterprise_agent.agent_v2.scheduler import AgentJobScheduler
from enterprise_agent.errors import ConflictError, NotFoundError
from enterprise_agent.harness.models import HarnessBudgets
from enterprise_agent.harness.store import HarnessStore
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.util import canonical_json


def test_soft_delete_allows_writer_handover_and_records_actual_actor() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(actor="creator-1")
    draft_id = draft["draft_id"]

    service.delete_draft(
        draft_id,
        actor="successor-writer",
        expected_revision=1,
    )

    with pytest.raises(NotFoundError, match="草稿不存在"):
        service.get_draft(draft_id)
    deleted = repository.get_draft(draft_id, include_deleted=True)
    assert deleted["_meta"]["deleted"] is True
    assert deleted["_meta"]["deleted_at"]
    assert deleted["_meta"]["revision"] == 2
    assert repository.list_drafts() == []

    events = repository.audit_events(draft_id)
    assert [event["event_type"] for event in events] == [
        "draft_created",
        "draft_deleted",
    ]
    deletion = events[-1]
    assert deletion["actor"] == "successor-writer"
    assert deletion["details"]["deletion_kind"] == "soft_delete"
    assert deletion["details"]["previous_revision"] == 1
    assert deletion["details"]["revision"] == 2
    assert len(deletion["details"]["document_sha256"]) == 64
    assert repository.verify_audit(draft_id)["valid"] is True


@pytest.mark.parametrize("revision", [None, True, False, 0, -1, "1"])
def test_delete_requires_a_positive_integer_revision(revision: object) -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(actor="creator-1")

    with pytest.raises(ValueError, match="expected_revision 必须是正整数"):
        service.delete_draft(
            draft["draft_id"],
            actor="creator-1",
            expected_revision=revision,  # type: ignore[arg-type]
        )

    assert service.get_draft(draft["draft_id"])["_meta"]["revision"] == 1


def test_delete_rejects_stale_revision_and_corrupt_audit_without_partial_write(
) -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(actor="creator-1")
    draft_id = draft["draft_id"]

    with pytest.raises(ConflictError, match="当前修订号为 1"):
        service.delete_draft(
            draft_id,
            actor="creator-1",
            expected_revision=2,
        )

    with (
        pytest.raises(sqlite3.IntegrityError, match="append-only"),
        repository._transaction() as db,
    ):
        db.execute(
            """
            UPDATE draft_audit
            SET details_json = ?
            WHERE draft_id = ? AND sequence = 1
            """,
            (canonical_json({"tampered": True}), draft_id),
        )

    # Simulate an offline/legacy database that was altered before the
    # append-only guard was installed. Runtime verification must still fail
    # closed without partially deleting the draft.
    with repository._transaction() as db:
        db.execute("DROP TRIGGER guard_draft_audit_update_v4")
        db.execute(
            """
            UPDATE draft_audit
            SET details_json = ?
            WHERE draft_id = ? AND sequence = 1
            """,
            (canonical_json({"tampered": True}), draft_id),
        )

    with pytest.raises(ConflictError, match="审计完整性"):
        service.delete_draft(
            draft_id,
            actor="creator-1",
            expected_revision=1,
        )

    stored = service.get_draft(draft_id)
    assert stored["_meta"]["deleted"] is False
    assert stored["_meta"]["revision"] == 1
    assert len(repository.audit_events(draft_id)) == 1


def test_legacy_draft_without_creation_audit_fails_closed() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(actor="legacy-import")

    # Model a pre-guard/offline legacy database with an incomplete chain.
    with repository._transaction() as db:
        db.execute("DROP TRIGGER guard_draft_audit_delete_v4")
        db.execute(
            "DELETE FROM draft_audit WHERE draft_id = ?",
            (draft["draft_id"],),
        )

    with pytest.raises(ConflictError, match="审计完整性"):
        service.delete_draft(
            draft["draft_id"],
            actor="successor-writer",
            expected_revision=1,
        )
    assert service.get_draft(draft["draft_id"])["_meta"]["deleted"] is False


def test_delete_rejects_confirmed_pending_and_succeeded_states() -> None:
    for state in ("confirmed", "pending", "succeeded"):
        repository = Repository(":memory:")
        service = EnterpriseAgentService(repository)
        draft = service.create_draft(actor="creator-1")
        draft_id = draft["draft_id"]
        with repository._transaction() as db:
            if state == "confirmed":
                db.execute(
                    """
                    UPDATE drafts
                    SET confirmed_revision = 1, confirmation_json = '{}'
                    WHERE draft_id = ?
                    """,
                    (draft_id,),
                )
            else:
                db.execute(
                    """
                    INSERT INTO submissions (
                        idempotency_key, draft_id, confirmed_revision,
                        request_sha256, request_json, status,
                        created_at, updated_at
                    ) VALUES (?, ?, 1, ?, '{}', ?, ?, ?)
                    """,
                    (
                        f"delete-state-{state}",
                        draft_id,
                        "a" * 64,
                        state,
                        "2026-07-30T00:00:00Z",
                        "2026-07-30T00:00:00Z",
                    ),
                )

        expected_message = {
            "confirmed": "已经人工确认",
            "pending": "正在提交",
            "succeeded": "已成功提交",
        }[state]
        with pytest.raises(ConflictError, match=expected_message):
            service.delete_draft(
                draft_id,
                actor="creator-1",
                expected_revision=1,
            )
        assert service.get_draft(draft_id)["draft_id"] == draft_id


def test_delete_blocks_active_v2_flow_enabled_job_and_harness_run() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(actor="creator-1")
    draft_id = draft["draft_id"]
    runtime = AgentFlowRuntime(service, auto_start=False)
    scheduler = AgentJobScheduler(
        repository,
        runtime,
        auto_start=False,
    )
    try:
        flow = runtime.create(
            actor_id="creator-1",
            draft_id=draft_id,
        )
        with pytest.raises(ConflictError, match="排队或运行中"):
            service.delete_draft(
                draft_id,
                actor="creator-1",
                expected_revision=1,
            )
        cancelled = runtime.cancel(
            flow["flow_id"],
            actor_id="creator-1",
            expected_revision=flow["revision"],
        )
        assert cancelled["status"] == "cancelled"

        job = scheduler.create_job(
            actor_id="creator-1",
            name="草稿删除边界",
            draft_id=draft_id,
            schedule_kind="interval",
            schedule={"interval_seconds": 3_600},
        )
        with pytest.raises(ConflictError, match="绑定启用"):
            service.delete_draft(
                draft_id,
                actor="creator-1",
                expected_revision=1,
            )
        disabled = scheduler.update_job(
            job["job_id"],
            actor_id="creator-1",
            expected_revision=job["revision"],
            patch={"enabled": False},
        )
        assert disabled["enabled"] is False

        harness = HarnessStore(repository)
        run = harness.create_run(
            actor_id="creator-1",
            task="只读检查草稿",
            draft_id=draft_id,
            mode="deterministic",
            budgets=HarnessBudgets(),
            allow_mutations=False,
        )
        with pytest.raises(ConflictError, match="未结束的智能体运行"):
            service.delete_draft(
                draft_id,
                actor="creator-1",
                expected_revision=1,
            )
        harness.cancel(run["run_id"], actor_id="creator-1")

        service.delete_draft(
            draft_id,
            actor="creator-1",
            expected_revision=1,
        )
    finally:
        scheduler.close()
        runtime.close()


def test_concurrent_delete_commits_once_and_keeps_a_valid_chain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent-delete.db"
    creator = EnterpriseAgentService(Repository(path))
    draft = creator.create_draft(actor="creator-1")

    def remove() -> str:
        service = EnterpriseAgentService(Repository(path))
        try:
            service.delete_draft(
                draft["draft_id"],
                actor="creator-1",
                expected_revision=1,
            )
        except NotFoundError:
            return "not_found"
        return "deleted"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = sorted(pool.map(lambda _: remove(), range(2)))

    assert outcomes == ["deleted", "not_found"]
    repository = Repository(path)
    deleted = repository.get_draft(draft["draft_id"], include_deleted=True)
    assert deleted["_meta"]["revision"] == 2
    assert repository.verify_audit(draft["draft_id"])["valid"] is True
    assert [
        event["event_type"]
        for event in repository.audit_events(draft["draft_id"])
    ] == ["draft_created", "draft_deleted"]
