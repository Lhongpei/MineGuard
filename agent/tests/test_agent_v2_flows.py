from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from conftest import complete_values, gateway_sign_observation

from enterprise_agent.agent_v2 import AgentFlowRuntime, FlowRuntimeConfig
from enterprise_agent.agent_v2.governance import GovernanceAccess
from enterprise_agent.agent_v2.snapshot import FrozenEvidenceRepository
from enterprise_agent.agent_v2.workflows import (
    SPECIALIST_NAMES,
    build_critic,
    build_executive_brief,
    prepare_daily_health,
)
from enterprise_agent.errors import ConflictError, NotFoundError
from enterprise_agent.harness.readonly import ReadOnlyRepository
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.tools import ToolContext, ToolRegistry, builtin_tool_specs
from enterprise_agent.util import canonical_json, sha256_json, utc_now


def _service() -> EnterpriseAgentService:
    return EnterpriseAgentService(Repository(":memory:"))


def _draft(service: EnterpriseAgentService) -> dict:
    return service.create_draft(complete_values(), actor="operator-1")


def test_daily_coal_health_is_durable_read_only_and_critic_grounded() -> None:
    service = _service()
    draft = _draft(service)
    before = service.get_draft(draft["draft_id"])
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        created = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
            client_request_id="daily-health-20260730",
        )
        result = runtime.run(
            created["flow_id"],
            actor_id="operator-1",
        )
    finally:
        runtime.close()

    after = service.get_draft(draft["draft_id"])
    assert result["status"] == "succeeded"
    assert result["integrity"]["valid"] is True
    assert [step["step_key"] for step in result["steps"]] == [
        "prepare_evidence",
        "specialist_source",
        "specialist_temporal",
        "specialist_physical",
        "specialist_historical",
        "critic_and_executive_brief",
    ]
    assert all(step["status"] == "succeeded" for step in result["steps"])
    state = result["state"]
    assert state["read_only"] is True
    assert state["network_access"] is False
    assert state["confirmed"] is False
    assert state["submitted"] is False
    assert state["not_a_regulatory_determination"] is True
    assert state["critic"]["independent_specialist_count"] == 4
    assert len(state["executive_brief"]["key_points"]) == 5
    assert state["executive_brief"]["metric_coverage"]["complete"] is True
    assert "不是监管认定" in state["executive_brief"]["disclaimer"]
    source_tools = {
        item["tool_name"] for item in state["specialists"]["source"]["tools"]
    }
    historical_tools = {
        item["tool_name"]
        for item in state["specialists"]["historical"]["tools"]
    }
    assert "compare_source_consistency" in source_tools
    assert "analyze_historical_trend" in historical_tools
    assert before["_meta"]["revision"] == after["_meta"]["revision"]
    assert before["_meta"]["confirmed"] is after["_meta"]["confirmed"] is False


def test_metric_budget_is_risk_prioritized_and_never_silently_truncated() -> None:
    service = _service()
    values = complete_values()
    base = values["observations"][0]
    observations = []
    for index in range(70):
        observations.append(
            gateway_sign_observation(
                {
                    **base,
                    "observation_id": f"obs-aux-{index:03d}",
                    "metric_code": f"zz_aux.metric_{index:03d}",
                    "sequence_no": 202607280000 + index,
                }
            )
        )
    observations.append(
        gateway_sign_observation(
            {
                **base,
                "observation_id": "obs-critical-production",
                "metric_code": "coal.production_t",
                "sequence_no": 202607289999,
            }
        )
    )
    values["observations"] = observations
    draft = service.create_draft(values, actor="operator-1")
    snapshot = FrozenEvidenceRepository.capture(
        service.repository,
        draft_id=draft["draft_id"],
    )
    metadata = snapshot.metadata
    registry = ToolRegistry(
        builtin_tool_specs(),
        context=ToolContext(repository=snapshot),
    )
    prepared = prepare_daily_health(
        registry,
        draft_id=draft["draft_id"],
        selected_metric_codes=metadata["history_metric_codes"],
        metric_coverage=metadata["metric_coverage"],
    )
    prepared["preflight"] = {
        "data": {"blocking_count": 0, "warning_count": 0}
    }
    specialists = {
        name: {
            "specialist": name,
            "status": "completed",
            "tools": [],
            "errors": [],
        }
        for name in SPECIALIST_NAMES
    }
    critic = build_critic(prepared, specialists)
    brief = build_executive_brief(prepared, specialists, critic)

    coverage = metadata["metric_coverage"]
    assert coverage["total_metric_count"] == 71
    assert coverage["analyzed_metric_count"] == 64
    assert coverage["omitted_metric_count"] == 7
    assert coverage["complete"] is False
    assert "coal.production_t" in coverage["analyzed_metric_codes"]
    assert critic["priority"] == "medium"
    assert any(
        item["code"] == "metric_coverage_limited"
        for item in critic["evidence_conflicts"]
    )
    assert brief["evidence_confidence"] == "limited"
    assert any(
        point["dimension"] == "分析覆盖"
        for point in brief["key_points"]
    )


def test_daily_health_uses_only_approved_memory_as_explanatory_context() -> None:
    service = _service()
    draft = _draft(service)
    access = GovernanceAccess.single_tenant(
        "operator-1",
        can_review=True,
    )
    proposal = service.governance.create_memory_proposal(
        access,
        scope_type="user",
        scope_id="operator-1",
        memory_key="night-shift-scale-note",
        value={"note": "夜班交接时优先复核皮带秤维护记录"},
        source_refs=[
            {
                "source_type": "user_input",
                "source_id": "operator-1",
                "label": "人工复核说明",
            }
        ],
        reason="为日常煤炭体检提供已审批的解释背景",
    )
    service.governance.decide_memory_proposal(
        access,
        proposal["proposal_id"],
        decision="approve",
        expected_revision=proposal["revision"],
        reason="本人私有作用域记忆，已核对内容",
    )
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        created = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        result = runtime.run(created["flow_id"], actor_id="operator-1")
    finally:
        runtime.close()

    context = result["state"]["governed_context"]
    assert context["status"] == "loaded"
    assert context["memory_count"] == 1
    assert context["items"][0]["memory_key"] == "night-shift-scale-note"
    assert context["usage"] == "context_only_never_overrides_evidence"
    brief = result["state"]["executive_brief"]
    assert brief["approved_context_notes"][0]["memory_key"] == (
        "night-shift-scale-note"
    )
    assert any(
        point["dimension"] == "受治理业务记忆"
        for point in brief["key_points"]
    )
    assert result["state"]["critic"]["evidence_snapshot"][
        "approved_memory_count"
    ] == 1


def test_flow_uses_one_immutable_snapshot_for_tools_and_memory_scope() -> None:
    service = _service()
    draft = _draft(service)
    foreign_mine = "mine-after-snapshot"
    proposer = GovernanceAccess(
        actor_id="memory-author",
        mine_ids=frozenset({foreign_mine}),
    )
    reviewer = GovernanceAccess(
        actor_id="memory-reviewer",
        mine_ids=frozenset({foreign_mine}),
        can_review=True,
    )
    proposal = service.governance.create_memory_proposal(
        proposer,
        scope_type="mine",
        scope_id=foreign_mine,
        memory_key="foreign-mine-note",
        value={"note": "不得混入旧快照"},
        source_refs=[
            {
                "source_type": "user_input",
                "source_id": "memory-author",
            }
        ],
        reason="验证快照作用域隔离",
    )
    service.governance.decide_memory_proposal(
        reviewer,
        proposal["proposal_id"],
        decision="approve",
        expected_revision=proposal["revision"],
        reason="仅用于测试快照作用域",
    )

    mutated = False
    specs = []
    for spec in builtin_tool_specs():
        if spec.name != "deterministic_preflight":
            specs.append(spec)
            continue
        original_execute = spec.execute

        def mutate_live_draft(
            arguments,
            context,
            _execute=original_execute,
        ):
            nonlocal mutated
            if not mutated:
                mutated = True
                service.patch_draft(
                    draft["draft_id"],
                    {"mine_id": foreign_mine},
                    actor="operator-1",
                    expected_revision=draft["_meta"]["revision"],
                )
            return _execute(arguments, context)

        specs.append(replace(spec, execute=mutate_live_draft))
    registry = ToolRegistry(
        specs,
        context=ToolContext(
            repository=ReadOnlyRepository(service.repository)
        ),
    )
    runtime = AgentFlowRuntime(
        service,
        registry=registry,
        auto_start=False,
    )
    try:
        created = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        result = runtime.run(created["flow_id"], actor_id="operator-1")
    finally:
        runtime.close()

    assert mutated is True
    assert result["status"] == "succeeded"
    assert result["integrity"]["valid"] is True
    assert result["state"]["draft_revision"] == draft["_meta"]["revision"]
    assert result["state"]["preflight"]["data"]["revision"] == (
        draft["_meta"]["revision"]
    )
    assert result["state"]["executive_brief"]["mine_id"] == draft["mine_id"]
    assert result["state"]["evidence_snapshot"]["immutable"] is True
    assert result["state"]["governed_context"]["memory_count"] == 0
    live = service.get_draft(draft["draft_id"])
    assert live["_meta"]["revision"] == draft["_meta"]["revision"] + 1
    assert live["mine_id"] == foreign_mine


def test_specialists_are_dispatched_before_results_are_committed() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        created = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        result = runtime.run(created["flow_id"], actor_id="operator-1")
    finally:
        runtime.close()

    events = result["events"]
    specialist_starts = [
        index
        for index, event in enumerate(events)
        if event["event_type"] == "flow_step_started"
        and str(event["details"].get("step_key", "")).startswith(
            "specialist_"
        )
    ]
    expert_sequences = {
        step["sequence"]
        for step in result["steps"]
        if step["step_key"].startswith("specialist_")
    }
    specialist_finishes = [
        index
        for index, event in enumerate(events)
        if event["event_type"]
        in {"flow_step_succeeded", "flow_step_failed"}
        and event["details"].get("sequence") in expert_sequences
    ]
    assert len(specialist_starts) == 4
    assert len(specialist_finishes) == 4
    assert max(specialist_starts) < min(specialist_finishes)


def test_client_request_id_is_idempotent_and_conflicting_reuse_is_rejected() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        first = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
            goal="执行煤炭日检",
            client_request_id="request-001",
        )
        replay = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
            goal="执行煤炭日检",
            client_request_id="request-001",
        )
        with pytest.raises(ConflictError):
            runtime.create(
                actor_id="operator-1",
                draft_id=draft["draft_id"],
                goal="换一个任务",
                client_request_id="request-001",
            )
    finally:
        runtime.close()

    assert replay["flow_id"] == first["flow_id"]
    assert first["idempotent_replay"] is False
    assert replay["idempotent_replay"] is True


def test_cancel_is_sticky_and_uses_optimistic_revision() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        with pytest.raises(ConflictError):
            runtime.cancel(
                flow["flow_id"],
                actor_id="operator-1",
                expected_revision=flow["revision"] + 1,
            )
        cancelled = runtime.cancel(
            flow["flow_id"],
            actor_id="operator-1",
            expected_revision=flow["revision"],
        )
        replay = runtime.cancel(
            flow["flow_id"],
            actor_id="operator-1",
            expected_revision=cancelled["revision"],
        )
    finally:
        runtime.close()

    assert cancelled["status"] == "cancelled"
    assert cancelled["cancel_requested"] is True
    assert replay["status"] == "cancelled"


def test_running_cancellation_cannot_be_overwritten_by_success() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        assert runtime.store.claim(
            flow["flow_id"],
            owner_id=runtime.runtime_id,
        ) is True
        running = runtime.get(flow["flow_id"], actor_id="operator-1")
        requested = runtime.cancel(
            flow["flow_id"],
            actor_id="operator-1",
            expected_revision=running["revision"],
        )
        assert requested["status"] == "running"
        terminal = runtime.store.complete(
            flow["flow_id"],
            status="succeeded",
            state={"would_have_succeeded": True},
            summary="不应覆盖取消",
            owner_id=runtime.runtime_id,
            attempt=1,
        )
    finally:
        runtime.close()

    assert terminal["status"] == "cancelled"
    assert terminal["summary"] == "任务已按用户要求取消"


def test_cancellation_between_parallel_dispatches_closes_started_steps() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    flow = runtime.create(
        actor_id="operator-1",
        draft_id=draft["draft_id"],
    )
    original_start_step = runtime.store.start_step

    def cancel_after_first_specialist(*args, **kwargs):
        sequence = original_start_step(*args, **kwargs)
        if kwargs.get("step_key") == "specialist_source":
            runtime.store.request_cancel(
                flow["flow_id"],
                actor_id="operator-1",
            )
        return sequence

    runtime.store.start_step = cancel_after_first_specialist  # type: ignore[method-assign]
    try:
        result = runtime.run(flow["flow_id"], actor_id="operator-1")
    finally:
        runtime.close()

    assert result["status"] == "cancelled"
    assert all(step["status"] != "running" for step in result["steps"])
    source_step = next(
        step
        for step in result["steps"]
        if step["step_key"] == "specialist_source"
    )
    assert source_step["status"] == "cancelled"


def test_failed_flow_can_retry_with_new_attempt() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        assert runtime.store.claim(
            flow["flow_id"],
            owner_id=runtime.runtime_id,
        ) is True
        failed = runtime.store.complete(
            flow["flow_id"],
            status="failed",
            state={"read_only": True},
            summary="测试失败",
            error_code="test_failure",
            error_message="可重试",
            owner_id=runtime.runtime_id,
            attempt=1,
        )
        retried = runtime.retry(
            flow["flow_id"],
            actor_id="operator-1",
            expected_revision=failed["revision"],
        )
        completed = runtime.run(
            flow["flow_id"],
            actor_id="operator-1",
        )
    finally:
        runtime.close()

    assert retried["status"] == "queued"
    assert retried["attempt"] == 2
    assert completed["status"] == "succeeded"
    assert completed["attempt"] == 2


def test_durable_retry_is_accepted_when_wake_queue_is_full() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    flow = runtime.create(
        actor_id="operator-1",
        draft_id=draft["draft_id"],
    )
    assert runtime.store.claim(
        flow["flow_id"],
        owner_id=runtime.runtime_id,
    )
    failed = runtime.store.complete(
        flow["flow_id"],
        status="failed",
        state={"read_only": True},
        summary="测试失败",
        owner_id=runtime.runtime_id,
        attempt=1,
    )
    original_schedule = runtime._schedule

    def queue_full(_flow_id: str) -> None:
        raise ConflictError("simulated wake queue full")

    runtime._schedule = queue_full  # type: ignore[method-assign]
    runtime._started = True
    try:
        retried = runtime.retry(
            flow["flow_id"],
            actor_id="operator-1",
            expected_revision=failed["revision"],
        )
    finally:
        runtime._started = False
        runtime._schedule = original_schedule  # type: ignore[method-assign]
        runtime.close()

    assert retried["status"] == "queued"
    assert retried["attempt"] == 2
    assert retried["integrity"]["valid"] is True


@pytest.mark.parametrize(
    ("config", "blocker_actor", "message"),
    [
        (
            FlowRuntimeConfig(actor_active_limit=1, global_active_limit=10),
            "operator-1",
            "任务过多",
        ),
        (
            FlowRuntimeConfig(actor_active_limit=10, global_active_limit=1),
            "operator-2",
            "队列已满",
        ),
    ],
)
def test_retry_cannot_bypass_active_capacity(
    config: FlowRuntimeConfig,
    blocker_actor: str,
    message: str,
) -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, config=config, auto_start=False)
    try:
        failed_flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        assert runtime.store.claim(
            failed_flow["flow_id"],
            owner_id=runtime.runtime_id,
        )
        failed = runtime.store.complete(
            failed_flow["flow_id"],
            status="failed",
            state={"read_only": True},
            summary="测试失败",
            owner_id=runtime.runtime_id,
            attempt=1,
        )
        runtime.create(
            actor_id=blocker_actor,
            draft_id=draft["draft_id"],
        )
        with pytest.raises(ConflictError, match=message):
            runtime.retry(
                failed_flow["flow_id"],
                actor_id="operator-1",
                expected_revision=failed["revision"],
            )
    finally:
        runtime.close()


def test_reopen_cannot_bypass_active_capacity() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(
        service,
        config=FlowRuntimeConfig(
            actor_active_limit=1,
            global_active_limit=2,
            lease_seconds=30,
        ),
        auto_start=False,
    )
    try:
        deferred = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
            client_request_id="capacity-reopen",
            trigger_type="event",
            trigger_ref="event-capacity",
            defer_dispatch=True,
        )
        created_at = datetime.fromisoformat(
            deferred["created_at"].replace("Z", "+00:00")
        )
        runtime.store.recover_interrupted(
            now=created_at + timedelta(days=2)
        )
        runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        with pytest.raises(
            ConflictError, match="任务过多"
        ), service.repository._transaction() as db:
            runtime.store.reopen_abandoned_deferred_in_transaction(
                db,
                deferred["flow_id"],
                actor_id="operator-1",
            )
        still_cancelled = runtime.get(
            deferred["flow_id"],
            actor_id="operator-1",
        )
    finally:
        runtime.close()

    assert still_cancelled["status"] == "cancelled"
    assert still_cancelled["integrity"]["valid"] is True


def test_restart_recovers_only_read_work_and_preserves_old_attempt() -> None:
    service = _service()
    draft = _draft(service)
    first_runtime = AgentFlowRuntime(service, auto_start=False)
    flow = first_runtime.create(
        actor_id="operator-1",
        draft_id=draft["draft_id"],
    )
    assert first_runtime.store.claim(
        flow["flow_id"],
        owner_id=first_runtime.runtime_id,
    ) is True
    first_runtime.store.start_step(
        flow["flow_id"],
        step_key="prepare_evidence",
        specialist="orchestrator",
        step_input={"draft_id": draft["draft_id"]},
        owner_id=first_runtime.runtime_id,
        attempt=1,
    )
    first_runtime.close()

    recovered_runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        recovered_ids = recovered_runtime.store.recover_interrupted(
            now=utc_now() + timedelta(minutes=10)
        )
        recovered = recovered_runtime.get(
            flow["flow_id"],
            actor_id="operator-1",
        )
        completed = recovered_runtime.run(
            flow["flow_id"],
            actor_id="operator-1",
        )
    finally:
        recovered_runtime.close()

    assert recovered_ids == [flow["flow_id"]]
    assert recovered["status"] == "queued"
    assert recovered["attempt"] == 2
    old_step = recovered["steps"][0]
    assert old_step["attempt"] == 1
    assert old_step["status"] == "failed"
    assert old_step["error"]["code"] == "flow_interrupted"
    assert completed["status"] == "succeeded"
    assert {step["attempt"] for step in completed["steps"]} == {1, 2}


def test_active_bound_flow_must_be_cancelled_before_draft_delete() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        with pytest.raises(ConflictError, match="排队或运行中"):
            service.delete_draft(
                draft["draft_id"],
                actor="operator-1",
                expected_revision=draft["_meta"]["revision"],
            )
        cancelled = runtime.cancel(
            flow["flow_id"],
            actor_id="operator-1",
            expected_revision=flow["revision"],
        )
        service.delete_draft(
            draft["draft_id"],
            actor="operator-1",
            expected_revision=draft["_meta"]["revision"],
        )
    finally:
        runtime.close()

    assert cancelled["status"] == "cancelled"
    with pytest.raises(NotFoundError, match="草稿不存在"):
        service.get_draft(draft["draft_id"])


def test_flow_content_is_private_to_actor_and_event_tampering_is_detected() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        with pytest.raises(NotFoundError):
            runtime.get(flow["flow_id"], actor_id="operator-2")
        with service.repository._transaction() as db:
            db.execute(
                """
                UPDATE agent_flow_events
                SET details_json = '{"tampered":true}'
                WHERE flow_id = ? AND sequence = 1
                """,
                (flow["flow_id"],),
            )
        tampered = runtime.get(flow["flow_id"], actor_id="operator-1")
    finally:
        runtime.close()

    assert tampered["integrity"]["valid"] is False
    assert tampered["integrity"]["failed_sequence"] == 1


def test_legacy_flow_without_control_anchor_is_quarantined() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        with service.repository._transaction() as db:
            event = db.execute(
                """
                SELECT * FROM agent_flow_events
                WHERE flow_id = ? AND sequence = 1
                """,
                (flow["flow_id"],),
            ).fetchone()
            details = json.loads(event["details_json"])
            details.pop("flow_control_sha256")
            details.pop("initial_dispatch_ready")
            envelope = {
                "flow_id": event["flow_id"],
                "sequence": int(event["sequence"]),
                "event_type": event["event_type"],
                "actor_id": event["actor_id"],
                "details": details,
                "occurred_at": event["occurred_at"],
                "previous_hash": event["previous_hash"],
            }
            legacy_hash = sha256_json(envelope)
            db.execute(
                """
                UPDATE agent_flow_events
                SET details_json = ?, event_hash = ?
                WHERE flow_id = ? AND sequence = 1
                """,
                (canonical_json(details), legacy_hash, flow["flow_id"]),
            )
            db.execute(
                """
                UPDATE agent_flows
                SET event_head_hash = ?, current_step = 'FORGED',
                    revision = 999, updated_at = ?
                WHERE flow_id = ?
                """,
                (legacy_hash, "2099-01-01T00:00:00Z", flow["flow_id"]),
            )

        quarantined = runtime.get(
            flow["flow_id"],
            actor_id="operator-1",
        )
        with pytest.raises(ConflictError, match="完整性"):
            runtime.run(flow["flow_id"], actor_id="operator-1")
    finally:
        runtime.close()

    assert quarantined["status"] == "queued"
    assert quarantined["integrity"]["valid"] is False
    assert quarantined["integrity"]["failed_component"] == (
        "flow_control_state"
    )
    assert quarantined["steps"] == []


def test_deferred_flows_are_bounded_and_expire_without_execution() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(
        service,
        config=FlowRuntimeConfig(
            actor_active_limit=1,
            global_active_limit=2,
            lease_seconds=30,
        ),
        auto_start=False,
    )
    try:
        deferred = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
            client_request_id="deferred-one",
            defer_dispatch=True,
        )
        with pytest.raises(ConflictError, match="未结束"):
            runtime.create(
                actor_id="operator-1",
                draft_id=draft["draft_id"],
                client_request_id="deferred-two",
                defer_dispatch=True,
            )
        created_at = datetime.fromisoformat(
            deferred["created_at"].replace("Z", "+00:00")
        )
        assert runtime.store.recover_interrupted(
            now=created_at + timedelta(seconds=31)
        ) == []
        expired = runtime.get(
            deferred["flow_id"],
            actor_id="operator-1",
        )
    finally:
        runtime.close()

    assert expired["status"] == "cancelled"
    assert expired["dispatch_ready"] is False
    assert expired["integrity"]["valid"] is True
    assert expired["steps"] == []


def test_closed_runtime_rejects_new_durable_flows() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    runtime.close()

    with pytest.raises(RuntimeError, match="已经关闭"):
        runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
            client_request_id="after-close",
        )
    with service.repository._read() as db:
        count = int(
            db.execute(
                "SELECT COUNT(*) AS amount FROM agent_flows"
            ).fetchone()["amount"]
        )
    assert count == 0


def test_closed_runtime_rejects_cancel_and_retry_without_state_change() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    queued = runtime.create(
        actor_id="operator-1",
        draft_id=draft["draft_id"],
    )
    failed_flow = runtime.create(
        actor_id="operator-1",
        draft_id=draft["draft_id"],
    )
    assert runtime.store.claim(
        failed_flow["flow_id"],
        owner_id=runtime.runtime_id,
    )
    failed = runtime.store.complete(
        failed_flow["flow_id"],
        status="failed",
        state={"read_only": True},
        summary="测试失败",
        owner_id=runtime.runtime_id,
        attempt=1,
    )
    runtime.close()

    with pytest.raises(RuntimeError, match="已经关闭"):
        runtime.cancel(
            queued["flow_id"],
            actor_id="operator-1",
            expected_revision=queued["revision"],
        )
    with pytest.raises(RuntimeError, match="已经关闭"):
        runtime.retry(
            failed_flow["flow_id"],
            actor_id="operator-1",
            expected_revision=failed["revision"],
        )
    unchanged_queued = runtime.get(
        queued["flow_id"],
        actor_id="operator-1",
    )
    unchanged_failed = runtime.get(
        failed_flow["flow_id"],
        actor_id="operator-1",
    )
    assert unchanged_queued["status"] == "queued"
    assert unchanged_queued["revision"] == queued["revision"]
    assert unchanged_failed["status"] == "failed"
    assert unchanged_failed["revision"] == failed["revision"]


@pytest.mark.parametrize(
    ("column", "replacement", "component"),
    [
        ("state_json", '{"forged":true}', "flow_state"),
        ("attempt", 999, "flow_attempt"),
        ("error_message", "伪造错误", "flow_error"),
    ],
)
def test_flow_row_content_tampering_is_detected(
    column: str,
    replacement: object,
    component: str,
) -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        created = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        completed = runtime.run(
            created["flow_id"],
            actor_id="operator-1",
        )
        assert completed["integrity"]["valid"] is True
        with service.repository._transaction() as db:
            db.execute(
                f"UPDATE agent_flows SET {column} = ? WHERE flow_id = ?",
                (replacement, created["flow_id"]),
            )
        tampered = runtime.get(
            created["flow_id"],
            actor_id="operator-1",
        )
    finally:
        runtime.close()

    assert tampered["integrity"]["valid"] is False
    assert tampered["integrity"]["failed_component"] in {
        component,
        "flow_control_state",
    }


def test_flow_identity_and_step_tampering_cannot_retarget_execution() -> None:
    service = _service()
    first = _draft(service)
    second_values = complete_values()
    second_values["mine_id"] = "mine-002"
    second = service.create_draft(second_values, actor="operator-1")
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        created = runtime.create(
            actor_id="operator-1",
            draft_id=first["draft_id"],
        )
        with service.repository._transaction() as db:
            db.execute(
                "UPDATE agent_flows SET draft_id = ? WHERE flow_id = ?",
                (second["draft_id"], created["flow_id"]),
            )
        with pytest.raises(ConflictError, match="完整性"):
            runtime.run(
                created["flow_id"],
                actor_id="operator-1",
            )
        retargeted = runtime.get(
            created["flow_id"],
            actor_id="operator-1",
        )

        clean = runtime.create(
            actor_id="operator-1",
            draft_id=first["draft_id"],
        )
        completed = runtime.run(clean["flow_id"], actor_id="operator-1")
        with service.repository._transaction() as db:
            db.execute(
                """
                UPDATE agent_flow_steps
                SET status = 'failed', error_code = 'flow_interrupted',
                    error_message = 'forged', completed_at = ?
                WHERE flow_id = ? AND sequence = 1
                """,
                ("1900-01-01T00:00:00Z", clean["flow_id"]),
            )
        step_tampered = runtime.get(
            clean["flow_id"],
            actor_id="operator-1",
        )
    finally:
        runtime.close()

    assert retargeted["status"] == "queued"
    assert retargeted["integrity"]["valid"] is False
    assert retargeted["steps"] == []
    assert completed["status"] == "succeeded"
    assert step_tampered["integrity"]["valid"] is False
    assert str(step_tampered["integrity"]["failed_component"]).startswith(
        "step:1:"
    )


def test_integrity_failure_prevents_all_business_tool_execution() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(service, auto_start=False)
    try:
        flow = runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        with service.repository._transaction() as db:
            db.execute(
                """
                UPDATE agent_flow_events
                SET details_json = '{"tampered":true}'
                WHERE flow_id = ? AND sequence = 1
                """,
                (flow["flow_id"],),
            )
        with pytest.raises(ConflictError, match="完整性"):
            runtime.run(flow["flow_id"], actor_id="operator-1")
        result = runtime.get(flow["flow_id"], actor_id="operator-1")
    finally:
        runtime.close()

    assert result["status"] == "queued"
    assert result["error"] is None
    assert result["steps"] == []
    assert result["integrity"]["valid"] is False


def test_registry_fails_closed_on_network_capability() -> None:
    service = _service()
    specs = [
        (
            replace(spec, network_access=True)
            if spec.name == "source_evidence_check"
            else spec
        )
        for spec in builtin_tool_specs()
    ]
    registry = ToolRegistry(
        specs,
        context=ToolContext(
            repository=ReadOnlyRepository(service.repository)
        ),
    )
    with pytest.raises(ValueError, match="只允许本地只读"):
        AgentFlowRuntime(
            service,
            registry=registry,
            auto_start=False,
        )


def test_active_flow_limit_is_enforced_before_queue_growth() -> None:
    service = _service()
    draft = _draft(service)
    runtime = AgentFlowRuntime(
        service,
        config=FlowRuntimeConfig(actor_active_limit=1),
        auto_start=False,
    )
    try:
        runtime.create(
            actor_id="operator-1",
            draft_id=draft["draft_id"],
        )
        with pytest.raises(ConflictError, match="任务过多"):
            runtime.create(
                actor_id="operator-1",
                draft_id=draft["draft_id"],
            )
    finally:
        runtime.close()
