from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from enterprise_agent.agent_v2 import AgentFlowRuntime
from enterprise_agent.agent_v2.scheduler import AgentJobScheduler
from enterprise_agent.errors import ConflictError, NotFoundError
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.util import canonical_json


class FakeFlowRuntime:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._by_request: dict[str, dict[str, Any]] = {}
        self.store = self

    def create(self, **values: Any) -> dict[str, Any]:
        self.calls.append(values)
        request_id = str(values.get("client_request_id") or "")
        if request_id and request_id in self._by_request:
            return {
                **self._by_request[request_id],
                "idempotent_replay": True,
            }
        result = {
            "flow_id": f"flow-{len(self.calls)}",
            "status": "queued",
            "dispatch_ready": not bool(values.get("defer_dispatch")),
            **values,
        }
        if request_id:
            self._by_request[request_id] = result
        return result

    def authorize_dispatch_in_transaction(
        self,
        _db: Any,
        flow_id: str,
        *,
        actor_id: str,
    ) -> bool:
        del actor_id
        flow = next(
            item
            for item in self._by_request.values()
            if item["flow_id"] == flow_id
        )
        changed = not bool(flow["dispatch_ready"])
        flow["dispatch_ready"] = True
        return changed

    def schedule_existing(self, flow_id: str) -> None:
        self.get(flow_id)

    def abandon_deferred(
        self,
        flow_id: str,
        *,
        actor_id: str,
        reason_code: str,
    ) -> bool:
        del actor_id, reason_code
        flow = next(
            item
            for item in self._by_request.values()
            if item["flow_id"] == flow_id
        )
        if flow["status"] != "queued" or flow["dispatch_ready"]:
            return False
        flow["status"] = "cancelled"
        return True

    def get(self, flow_id: str) -> dict[str, Any]:
        for flow in self._by_request.values():
            if flow["flow_id"] == flow_id:
                return dict(flow)
        raise AssertionError(f"unknown fake flow {flow_id}")

    def get_in_transaction(
        self,
        _db: Any,
        flow_id: str,
    ) -> dict[str, Any]:
        return {**self.get(flow_id), "integrity": {"valid": True}}

    def find_by_client_request(
        self,
        *,
        actor_id: str,
        client_request_id: str,
    ) -> dict[str, Any] | None:
        flow = self._by_request.get(client_request_id)
        if flow is None or flow.get("actor_id") != actor_id:
            return None
        return {**flow, "integrity": {"valid": True}}


def _subject() -> tuple[Repository, AgentJobScheduler, FakeFlowRuntime, str]:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(
        {
            "enterprise_id": "enterprise-1",
            "mine_id": "mine-1",
        },
        actor="operator-1",
    )
    runtime = FakeFlowRuntime()
    scheduler = AgentJobScheduler(
        repository,
        runtime,
        auto_start=False,
    )
    return repository, scheduler, runtime, draft["draft_id"]


def test_job_crud_is_actor_scoped_revisioned_and_audited() -> None:
    _repository, scheduler, _runtime, draft_id = _subject()
    try:
        created = scheduler.create_job(
            actor_id="operator-1",
            name="每天九点煤炭体检",
            draft_id=draft_id,
            schedule_kind="daily",
            schedule={"time": "09:00", "timezone": "Asia/Shanghai"},
            client_request_id="create-job-1",
        )
        replay = scheduler.create_job(
            actor_id="operator-1",
            name="每天九点煤炭体检",
            draft_id=draft_id,
            schedule_kind="daily",
            schedule={"time": "09:00", "timezone": "Asia/Shanghai"},
            client_request_id="create-job-1",
        )
        assert replay["job_id"] == created["job_id"]
        assert replay["schedule_kind"] == "daily"
        assert created["next_run_at"] is not None
        with pytest.raises(ConflictError, match="不同"):
            scheduler.create_job(
                actor_id="operator-1",
                name="不会覆盖原任务",
                draft_id=draft_id,
                schedule_kind="interval",
                schedule={"interval_seconds": 3600},
                client_request_id="create-job-1",
            )

        items, total = scheduler.list_jobs(actor_id="operator-1")
        assert total == 1
        assert items[0]["job_id"] == created["job_id"]
        with pytest.raises(NotFoundError):
            scheduler.get_job(created["job_id"], actor_id="operator-2")

        updated = scheduler.update_job(
            created["job_id"],
            actor_id="operator-1",
            expected_revision=created["revision"],
            patch={"enabled": False, "name": "暂停的每日体检"},
        )
        assert updated["enabled"] is False
        assert updated["next_run_at"] is None
        with pytest.raises(ConflictError):
            scheduler.update_job(
                created["job_id"],
                actor_id="operator-1",
                expected_revision=created["revision"],
                patch={"enabled": True},
            )
        detail = scheduler.get_job(
            created["job_id"],
            actor_id="operator-1",
        )
        assert detail["integrity"]["valid"] is True
        assert [item["event_type"] for item in detail["events"]] == [
            "job_created",
            "job_updated",
        ]

        deleted = scheduler.delete_job(
            created["job_id"],
            actor_id="operator-1",
            expected_revision=updated["revision"],
        )
        assert deleted["deleted"] is True
        assert scheduler.list_jobs(actor_id="operator-1")[1] == 0
    finally:
        scheduler.close()


def test_manual_due_and_event_triggers_only_launch_read_only_workflow() -> None:
    repository, scheduler, runtime, draft_id = _subject()
    try:
        interval = scheduler.create_job(
            actor_id="operator-1",
            name="五分钟体检",
            draft_id=draft_id,
            schedule_kind="interval",
            schedule={"interval_seconds": 300},
        )
        manual = scheduler.run_now(
            interval["job_id"],
            actor_id="operator-1",
        )
        assert manual["flow_id"] == "flow-1"
        assert runtime.calls[-1]["workflow_name"] == "daily_coal_health"
        assert runtime.calls[-1]["trigger_type"] == "manual"

        scheduled_for = datetime.fromisoformat(
            str(interval["next_run_at"]).replace("Z", "+00:00")
        )
        launched = scheduler.run_due_once(
            now=scheduled_for + timedelta(seconds=1)
        )
        assert launched == ["flow-2"]
        assert runtime.calls[-1]["trigger_type"] == "schedule"

        event_job = scheduler.create_job(
            actor_id="operator-1",
            name="新数据到达后体检",
            draft_id=draft_id,
            schedule_kind="event",
            schedule={"event_type": "coal.data_arrived"},
        )
        event = scheduler.emit_event(
            actor_id="operator-1",
            event_type="coal.data_arrived",
            client_event_id="source-event-1",
            draft_id=draft_id,
            payload={"source_id": "scale-1", "record_count": 10},
        )
        assert event["triggered"]["succeeded"] == [
            {"job_id": event_job["job_id"], "flow_id": "flow-3"}
        ]
        assert runtime.calls[-1]["trigger_type"] == "event"
        assert runtime.calls[-1]["trigger_ref"] == event["event_id"]

        replay = scheduler.emit_event(
            actor_id="operator-1",
            event_type="coal.data_arrived",
            client_event_id="source-event-1",
            draft_id=draft_id,
            payload={"source_id": "scale-1", "record_count": 10},
        )
        assert replay["replayed"] is True
        assert len(runtime.calls) == 3
        with pytest.raises(ConflictError, match="不同"):
            scheduler.emit_event(
                actor_id="operator-1",
                event_type="coal.data_arrived",
                client_event_id="source-event-1",
                draft_id=draft_id,
                payload={"source_id": "different"},
            )
    finally:
        scheduler.close()


def test_concurrent_duplicate_business_event_creates_one_audited_flow() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(
        {"enterprise_id": "enterprise-1", "mine_id": "mine-1"},
        actor="operator-1",
    )
    runtime = AgentFlowRuntime(service, auto_start=False)
    first = AgentJobScheduler(repository, runtime, auto_start=False)
    second = AgentJobScheduler(repository, runtime, auto_start=False)
    event_job = first.create_job(
        actor_id="operator-1",
        name="并发数据到达体检",
        draft_id=draft["draft_id"],
        schedule_kind="event",
        schedule={"event_type": "coal.concurrent_arrived"},
    )
    entered = threading.Event()
    release = threading.Event()
    original_create = runtime.create

    def create_with_gate(**values: Any) -> dict[str, Any]:
        result = original_create(**values)
        entered.set()
        assert release.wait(timeout=5)
        return result

    runtime.create = create_with_gate  # type: ignore[method-assign]

    def emit(scheduler: AgentJobScheduler) -> dict[str, Any]:
        return scheduler.emit_event(
            actor_id="operator-1",
            event_type="coal.concurrent_arrived",
            client_event_id="same-concurrent-event",
            draft_id=draft["draft_id"],
            payload={"records": 8},
        )

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_result = pool.submit(emit, first)
            assert entered.wait(timeout=5)
            in_progress = emit(second)
            release.set()
            completed = first_result.result(timeout=5)
        replay = emit(second)
        results = [completed, replay]
        with repository._read() as db:
            flow_count = int(
                db.execute(
                    "SELECT COUNT(*) AS amount FROM agent_flows"
                ).fetchone()["amount"]
            )
            created_events = int(
                db.execute(
                    """
                    SELECT COUNT(*) AS amount FROM agent_job_events
                    WHERE job_id = ? AND event_type = 'job_flow_created'
                    """,
                    (event_job["job_id"],),
                ).fetchone()["amount"]
            )
        detail = first.get_job(
            event_job["job_id"],
            actor_id="operator-1",
        )
    finally:
        runtime.create = original_create  # type: ignore[method-assign]
        first.close()
        second.close()
        runtime.close()

    assert flow_count == 1
    assert created_events == 1
    assert detail["last_error"] is None
    assert in_progress["triggered"]["completed"] is False
    assert all(item["integrity"]["valid"] for item in results)
    flow_ids = {
        item["triggered"]["succeeded"][0]["flow_id"] for item in results
    }
    assert len(flow_ids) == 1


def test_manual_client_request_replays_after_job_configuration_changes() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(
        {"enterprise_id": "enterprise-1", "mine_id": "mine-1"},
        actor="operator-1",
    )
    runtime = AgentFlowRuntime(service, auto_start=False)
    scheduler = AgentJobScheduler(repository, runtime, auto_start=False)
    try:
        job = scheduler.create_job(
            actor_id="operator-1",
            name="幂等人工体检",
            draft_id=draft["draft_id"],
            schedule_kind="interval",
            schedule={"interval_seconds": 300},
            goal_text="检查原始配置",
        )
        first = scheduler.run_now(
            job["job_id"],
            actor_id="operator-1",
            client_request_id="stable-manual-run-1",
        )
        current = scheduler.get_job(job["job_id"], actor_id="operator-1")
        scheduler.update_job(
            job["job_id"],
            actor_id="operator-1",
            expected_revision=current["revision"],
            patch={"goal_text": "后来更新的配置"},
        )
        replay = scheduler.run_now(
            job["job_id"],
            actor_id="operator-1",
            client_request_id="stable-manual-run-1",
        )
        with repository._read() as db:
            flow_count = int(
                db.execute(
                    "SELECT COUNT(*) AS amount FROM agent_flows"
                ).fetchone()["amount"]
            )
            link_count = int(
                db.execute(
                    """
                    SELECT COUNT(*) AS amount FROM agent_job_events
                    WHERE job_id = ? AND event_type = 'job_flow_created'
                    """,
                    (job["job_id"],),
                ).fetchone()["amount"]
            )
    finally:
        scheduler.close()
        runtime.close()

    assert replay["flow_id"] == first["flow_id"]
    assert replay["goal"] == "检查原始配置"
    assert flow_count == 1
    assert link_count == 1


def test_manual_client_request_recovers_after_attach_transaction_failure() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(
        {"enterprise_id": "enterprise-1", "mine_id": "mine-1"},
        actor="operator-1",
    )
    runtime = AgentFlowRuntime(service, auto_start=False)
    scheduler = AgentJobScheduler(repository, runtime, auto_start=False)
    job = scheduler.create_job(
        actor_id="operator-1",
        name="可恢复人工体检",
        draft_id=draft["draft_id"],
        schedule_kind="interval",
        schedule={"interval_seconds": 300},
        goal_text="故障前的原始目标",
    )
    original_append = scheduler._append_event
    failed_once = False

    def fail_link_once(*args: Any, **values: Any) -> None:
        nonlocal failed_once
        if values.get("event_type") == "job_flow_created" and not failed_once:
            failed_once = True
            raise RuntimeError("simulated attach failure")
        original_append(*args, **values)

    scheduler._append_event = fail_link_once  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="attach"):
            scheduler.run_now(
                job["job_id"],
                actor_id="operator-1",
                client_request_id="recoverable-manual-run-1",
            )
        with repository._read() as db:
            deferred_row = db.execute(
                """
                SELECT created_at FROM agent_flows
                WHERE actor_id = 'operator-1'
                """
            ).fetchone()
        created_at = datetime.fromisoformat(
            str(deferred_row["created_at"]).replace("Z", "+00:00")
        )
        runtime.store.recover_interrupted(
            now=created_at + timedelta(seconds=121)
        )
        current = scheduler.get_job(job["job_id"], actor_id="operator-1")
        scheduler.update_job(
            job["job_id"],
            actor_id="operator-1",
            expected_revision=current["revision"],
            patch={"goal_text": "故障后更新的目标"},
        )
        scheduler._append_event = original_append  # type: ignore[method-assign]
        recovered = scheduler.run_now(
            job["job_id"],
            actor_id="operator-1",
            client_request_id="recoverable-manual-run-1",
        )
        with repository._read() as db:
            rows = db.execute(
                """
                SELECT status, dispatch_ready FROM agent_flows
                WHERE actor_id = 'operator-1'
                """
            ).fetchall()
            link = db.execute(
                """
                SELECT details_json FROM agent_job_events
                WHERE job_id = ? AND event_type = 'job_flow_created'
                """,
                (job["job_id"],),
            ).fetchone()
    finally:
        scheduler._append_event = original_append  # type: ignore[method-assign]
        scheduler.close()
        runtime.close()

    assert recovered["status"] == "queued"
    assert recovered["dispatch_ready"] is True
    assert recovered["goal"] == "故障前的原始目标"
    assert [(row["status"], row["dispatch_ready"]) for row in rows] == [
        ("queued", 1)
    ]
    details = canonical_json({})
    details = str(link["details_json"])
    assert '"execution_configuration_source":"existing_idempotent_flow"' in details
    assert '"launch_config_sha256"' not in details


def test_event_replay_after_progress_checkpoint_crash_is_idempotent() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(
        {"enterprise_id": "enterprise-1", "mine_id": "mine-1"},
        actor="operator-1",
    )
    runtime = AgentFlowRuntime(service, auto_start=False)
    scheduler = AgentJobScheduler(repository, runtime, auto_start=False)
    event_job = scheduler.create_job(
        actor_id="operator-1",
        name="断点恢复事件体检",
        draft_id=draft["draft_id"],
        schedule_kind="event",
        schedule={"event_type": "coal.checkpoint_arrived"},
    )
    original_persist = scheduler._persist_trigger_progress
    failed_once = False

    def fail_first_checkpoint(**values: Any) -> tuple[int, str, dict[str, Any]]:
        nonlocal failed_once
        if not failed_once:
            failed_once = True
            raise RuntimeError("simulated checkpoint crash")
        return original_persist(**values)

    scheduler._persist_trigger_progress = fail_first_checkpoint  # type: ignore[method-assign]
    try:
        with pytest.raises(RuntimeError, match="checkpoint"):
            scheduler.emit_event(
                actor_id="operator-1",
                event_type="coal.checkpoint_arrived",
                client_event_id="checkpoint-event",
                draft_id=draft["draft_id"],
                payload={"records": 1},
            )
        scheduler._persist_trigger_progress = original_persist  # type: ignore[method-assign]
        replay = scheduler.emit_event(
            actor_id="operator-1",
            event_type="coal.checkpoint_arrived",
            client_event_id="checkpoint-event",
            draft_id=draft["draft_id"],
            payload={"records": 1},
        )
        with repository._read() as db:
            flow_count = int(
                db.execute(
                    "SELECT COUNT(*) AS amount FROM agent_flows"
                ).fetchone()["amount"]
            )
            created_events = int(
                db.execute(
                    """
                    SELECT COUNT(*) AS amount FROM agent_job_events
                    WHERE job_id = ? AND event_type = 'job_flow_created'
                    """,
                    (event_job["job_id"],),
                ).fetchone()["amount"]
            )
    finally:
        scheduler._persist_trigger_progress = original_persist  # type: ignore[method-assign]
        scheduler.close()
        runtime.close()

    assert replay["replayed"] is True
    assert replay["triggered"]["completed"] is True
    assert replay["integrity"]["valid"] is True
    assert flow_count == 1
    assert created_events == 1


def test_scheduler_tick_resumes_event_interrupted_before_job_attachment() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(
        {"enterprise_id": "enterprise-1", "mine_id": "mine-1"},
        actor="operator-1",
    )
    runtime = AgentFlowRuntime(service, auto_start=False)
    scheduler = AgentJobScheduler(repository, runtime, auto_start=False)
    event_job = scheduler.create_job(
        actor_id="operator-1",
        name="进程中断恢复事件",
        draft_id=draft["draft_id"],
        schedule_kind="event",
        schedule={"event_type": "coal.crash_arrived"},
        goal_text="事件中断前的目标",
    )
    original_append = scheduler._append_event
    interrupted = False

    def interrupt_link(*args: Any, **values: Any) -> None:
        nonlocal interrupted
        if values.get("event_type") == "job_flow_created" and not interrupted:
            interrupted = True
            raise KeyboardInterrupt()
        original_append(*args, **values)

    scheduler._append_event = interrupt_link  # type: ignore[method-assign]
    try:
        with pytest.raises(KeyboardInterrupt):
            scheduler.emit_event(
                actor_id="operator-1",
                event_type="coal.crash_arrived",
                client_event_id="crash-before-attach",
                draft_id=draft["draft_id"],
                payload={"records": 3},
            )
        scheduler._append_event = original_append  # type: ignore[method-assign]
        with repository._read() as db:
            deferred = db.execute(
                "SELECT flow_id, created_at FROM agent_flows"
            ).fetchone()
            original_event = db.execute(
                """
                SELECT * FROM agent_trigger_events
                WHERE client_event_id = 'crash-before-attach'
                """
            ).fetchone()
        with repository._transaction() as db:
            db.executemany(
                """
                INSERT INTO agent_trigger_events (
                    event_id, actor_id, client_event_id, event_type,
                    draft_id, payload_json, payload_sha256,
                    matched_jobs_json, triggered_jobs_json, record_sha256,
                    progress_revision, progress_sha256, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f"poison-{index:03d}",
                        original_event["actor_id"],
                        f"poison-client-{index:03d}",
                        original_event["event_type"],
                        original_event["draft_id"],
                        original_event["payload_json"],
                        original_event["payload_sha256"],
                        original_event["matched_jobs_json"],
                        original_event["triggered_jobs_json"],
                        "tampered-record-sha256",
                        original_event["progress_revision"],
                        original_event["progress_sha256"],
                        f"2000-01-01T00:00:{index % 60:02d}Z",
                    )
                    for index in range(120)
                ],
            )
        created_at = datetime.fromisoformat(
            str(deferred["created_at"]).replace("Z", "+00:00")
        )
        runtime.store.recover_interrupted(
            now=created_at + timedelta(hours=25)
        )
        assert runtime.get(
            str(deferred["flow_id"]),
            actor_id="operator-1",
        )["status"] == "cancelled"
        current = scheduler.get_job(
            event_job["job_id"],
            actor_id="operator-1",
        )
        scheduler.update_job(
            event_job["job_id"],
            actor_id="operator-1",
            expected_revision=current["revision"],
            patch={"goal_text": "事件中断后更新的目标"},
        )
        resumed = AgentJobScheduler(
            repository,
            runtime,
            auto_start=False,
        )
        try:
            resumed.run_due_once()
            events = resumed.list_trigger_events(actor_id="operator-1")
            job = resumed.get_job(
                event_job["job_id"],
                actor_id="operator-1",
            )
            flow = runtime.get(
                events[0]["triggered"]["succeeded"][0]["flow_id"],
                actor_id="operator-1",
            )
            with repository._read() as db:
                link = db.execute(
                    """
                    SELECT details_json FROM agent_job_events
                    WHERE job_id = ? AND event_type = 'job_flow_created'
                    """,
                    (event_job["job_id"],),
                ).fetchone()
        finally:
            resumed.close()
    finally:
        scheduler._append_event = original_append  # type: ignore[method-assign]
        scheduler.close()
        runtime.close()

    assert events[0]["triggered"]["completed"] is True
    assert len(events[0]["triggered"]["succeeded"]) == 1
    assert job["last_flow_id"] == events[0]["triggered"]["succeeded"][0]["flow_id"]
    assert flow["goal"] == "事件中断前的目标"
    assert '"execution_configuration_source":"existing_idempotent_flow"' in str(
        link["details_json"]
    )
    assert '"launch_config_sha256"' not in str(link["details_json"])


def test_closed_scheduler_rejects_launches_before_any_persistence() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(
        {"enterprise_id": "enterprise-1", "mine_id": "mine-1"},
        actor="operator-1",
    )
    runtime = AgentFlowRuntime(service, auto_start=False)
    scheduler = AgentJobScheduler(repository, runtime, auto_start=False)
    job = scheduler.create_job(
        actor_id="operator-1",
        name="关闭边界",
        draft_id=draft["draft_id"],
        schedule_kind="event",
        schedule={"event_type": "coal.closed_arrived"},
    )
    scheduler.close()
    try:
        for operation in (
            lambda: scheduler.create_job(
                actor_id="operator-1",
                name="关闭后新建",
                draft_id=draft["draft_id"],
                schedule_kind="event",
                schedule={"event_type": "coal.closed_create"},
            ),
            lambda: scheduler.update_job(
                job["job_id"],
                actor_id="operator-1",
                expected_revision=job["revision"],
                patch={"name": "关闭后更新"},
            ),
            lambda: scheduler.delete_job(
                job["job_id"],
                actor_id="operator-1",
                expected_revision=job["revision"],
            ),
        ):
            with pytest.raises(RuntimeError, match="已经关闭"):
                operation()
        with pytest.raises(RuntimeError, match="已经关闭"):
            scheduler.run_now(
                job["job_id"],
                actor_id="operator-1",
                client_request_id="after-scheduler-close",
            )
        with pytest.raises(RuntimeError, match="已经关闭"):
            scheduler.emit_event(
                actor_id="operator-1",
                event_type="coal.closed_arrived",
                client_event_id="after-close-event",
                draft_id=draft["draft_id"],
                payload={},
            )
        with repository._read() as db:
            flow_count = int(
                db.execute(
                    "SELECT COUNT(*) AS amount FROM agent_flows"
                ).fetchone()["amount"]
            )
            trigger_count = int(
                db.execute(
                    "SELECT COUNT(*) AS amount FROM agent_trigger_events"
                ).fetchone()["amount"]
            )
            stored_job = db.execute(
                "SELECT name, revision, deleted_at FROM agent_jobs WHERE job_id = ?",
                (job["job_id"],),
            ).fetchone()
    finally:
        runtime.close()

    assert flow_count == 0
    assert trigger_count == 0
    assert stored_job["name"] == "关闭边界"
    assert stored_job["revision"] == job["revision"]
    assert stored_job["deleted_at"] is None


def test_scheduler_resumes_claimed_occurrence_and_incomplete_event() -> None:
    repository, scheduler, runtime, draft_id = _subject()
    try:
        interval = scheduler.create_job(
            actor_id="operator-1",
            name="可恢复定时体检",
            draft_id=draft_id,
            schedule_kind="interval",
            schedule={"interval_seconds": 300},
        )
        scheduled_for = str(interval["next_run_at"])
        due_at = datetime.fromisoformat(
            scheduled_for.replace("Z", "+00:00")
        ) + timedelta(seconds=1)
        claimed = scheduler._claim_due(
            interval["job_id"],
            actor_id="operator-1",
            now=due_at,
        )
        assert claimed is not None
        assert scheduler.get_job(
            interval["job_id"],
            actor_id="operator-1",
        )["pending_run_at"] == scheduled_for

        resumed = AgentJobScheduler(
            repository,
            runtime,
            auto_start=False,
        )
        try:
            flow_ids = resumed.run_due_once(
                now=due_at,
            )
            assert flow_ids == ["flow-1"]
            assert resumed.get_job(
                interval["job_id"],
                actor_id="operator-1",
            )["pending_run_at"] is None
        finally:
            resumed.close()

        event_job = scheduler.create_job(
            actor_id="operator-1",
            name="可恢复事件体检",
            draft_id=draft_id,
            schedule_kind="event",
            schedule={"event_type": "coal.data_arrived"},
        )
        event = scheduler.emit_event(
            actor_id="operator-1",
            event_type="coal.data_arrived",
            client_event_id="recoverable-event",
            draft_id=draft_id,
            payload={"record_count": 1},
        )
        original_flow = event["triggered"]["succeeded"][0]["flow_id"]
        incomplete_progress = {
            "completed": False,
            "failed": [],
            "matched_job_ids": [event_job["job_id"]],
            "succeeded": [],
        }
        checkpoint_revision = (
            int(event["integrity"]["progress_revision"]) + 1
        )
        checkpoint_hash = scheduler._trigger_progress_sha256(
            event_id=event["event_id"],
            record_sha256=event["integrity"]["record_sha256"],
            revision=checkpoint_revision,
            progress=incomplete_progress,
        )
        with repository._transaction() as db:
            db.execute(
                """
                UPDATE agent_trigger_events
                SET triggered_jobs_json = ?, progress_revision = ?,
                    progress_sha256 = ?
                WHERE event_id = ?
                """,
                (
                    canonical_json(incomplete_progress),
                    checkpoint_revision,
                    checkpoint_hash,
                    event["event_id"],
                ),
            )
        replay = scheduler.emit_event(
            actor_id="operator-1",
            event_type="coal.data_arrived",
            client_event_id="recoverable-event",
            draft_id=draft_id,
            payload={"record_count": 1},
        )
        assert replay["replayed"] is True
        assert replay["triggered"]["completed"] is True
        assert replay["triggered"]["succeeded"][0]["flow_id"] == original_flow
    finally:
        scheduler.close()


def test_failed_scheduled_occurrence_is_closed_without_retry_storm() -> None:
    repository, scheduler, runtime, draft_id = _subject()
    try:
        interval = scheduler.create_job(
            actor_id="operator-1",
            name="失败后等待下一周期",
            draft_id=draft_id,
            schedule_kind="interval",
            schedule={"interval_seconds": 300},
        )
        due_at = datetime.fromisoformat(
            str(interval["next_run_at"]).replace("Z", "+00:00")
        ) + timedelta(seconds=1)

        def fail_create(**_values: Any) -> dict[str, Any]:
            runtime.calls.append({"failed": True})
            raise RuntimeError("simulated launch failure")

        runtime.create = fail_create  # type: ignore[method-assign]
        first = scheduler.run_due_once(now=due_at)
        second = scheduler.run_due_once(
            now=due_at + timedelta(seconds=60)
        )
        detail = scheduler.get_job(
            interval["job_id"],
            actor_id="operator-1",
        )

        assert first == []
        assert second == []
        assert runtime.calls == [{"failed": True}]
        assert detail["pending_run_at"] is None
        assert detail["last_error"] == "RuntimeError"
        assert datetime.fromisoformat(
            str(detail["next_run_at"]).replace("Z", "+00:00")
        ) == due_at + timedelta(seconds=300)
        assert detail["events"][-1]["details"]["occurrence_closed"] is True
    finally:
        scheduler.close()


def test_job_state_tampering_cannot_trigger_or_be_laundered_by_update() -> None:
    repository, scheduler, runtime, draft_id = _subject()
    try:
        job = scheduler.create_job(
            actor_id="operator-1",
            name="防篡改调度",
            draft_id=draft_id,
            schedule_kind="interval",
            schedule={"interval_seconds": 300},
        )
        with repository._transaction() as db:
            db.execute(
                "UPDATE agent_jobs SET next_run_at = ? WHERE job_id = ?",
                ("2020-01-01T00:00:00Z", job["job_id"]),
            )
        detail = scheduler.get_job(
            job["job_id"],
            actor_id="operator-1",
        )
        launched = scheduler.run_due_once(
            now=datetime(2026, 7, 30, tzinfo=UTC)
        )
        with pytest.raises(ConflictError, match="完整性"):
            scheduler.update_job(
                job["job_id"],
                actor_id="operator-1",
                expected_revision=job["revision"],
                patch={"name": "不得洗白"},
            )
        with pytest.raises(ConflictError, match="完整性"):
            scheduler.run_now(
                job["job_id"],
                actor_id="operator-1",
            )

        assert detail["integrity"]["valid"] is False
        assert launched == []
        assert runtime.calls == []
    finally:
        scheduler.close()


def test_trigger_event_tampering_cannot_change_matched_jobs() -> None:
    repository, scheduler, runtime, draft_id = _subject()
    try:
        unrelated = scheduler.create_job(
            actor_id="operator-1",
            name="只监听其他事件",
            draft_id=draft_id,
            schedule_kind="event",
            schedule={"event_type": "coal.other"},
        )
        event = scheduler.emit_event(
            actor_id="operator-1",
            event_type="coal.data_arrived",
            client_event_id="tamper-event",
            draft_id=draft_id,
            payload={"record_count": 1},
        )
        assert event["triggered"]["matched_job_ids"] == []
        with repository._transaction() as db:
            db.execute(
                """
                UPDATE agent_trigger_events
                SET triggered_jobs_json = ?
                WHERE event_id = ?
                """,
                (
                    canonical_json(
                        {
                            "matched_job_ids": [unrelated["job_id"]],
                            "succeeded": [],
                            "failed": [],
                            "completed": False,
                        }
                    ),
                    event["event_id"],
                ),
            )
        with pytest.raises(ConflictError, match="完整性"):
            scheduler.emit_event(
                actor_id="operator-1",
                event_type="coal.data_arrived",
                client_event_id="tamper-event",
                draft_id=draft_id,
                payload={"record_count": 1},
            )
        listed = scheduler.list_trigger_events(actor_id="operator-1")

        assert runtime.calls == []
        assert listed[0]["integrity"]["valid"] is False
        assert listed[0]["triggered"]["matched_job_ids"] == []
    finally:
        scheduler.close()


def test_scheduler_rejects_unsafe_or_unbounded_configuration() -> None:
    _repository, scheduler, _runtime, draft_id = _subject()
    try:
        with pytest.raises(ValueError, match="300"):
            scheduler.create_job(
                actor_id="operator-1",
                name="过密任务",
                draft_id=draft_id,
                schedule_kind="interval",
                schedule={"interval_seconds": 1},
            )
        with pytest.raises(ValueError, match="不受支持"):
            scheduler.create_job(
                actor_id="operator-1",
                name="越权任务",
                workflow_name="submit",
                draft_id=draft_id,
                schedule_kind="interval",
                schedule={"interval_seconds": 300},
            )
        with pytest.raises(ValueError, match="API 密钥"):
            scheduler.emit_event(
                actor_id="operator-1",
                event_type="coal.data_arrived",
                client_event_id="secret-event",
                draft_id=draft_id,
                payload={"api_key": "sk-secret-value"},
            )
    finally:
        scheduler.close()
