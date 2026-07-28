from __future__ import annotations

import json
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from conftest import complete_values

from enterprise_agent.errors import ConflictError, NotFoundError, ProviderError
from enterprise_agent.harness import HarnessBudgets, HarnessRuntime
from enterprise_agent.harness.store import HarnessStore
from enterprise_agent.models import new_draft
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.tools import (
    ToolContext,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)


def _wait(
    harness: HarnessRuntime,
    run_id: str,
    *,
    actor: str = "operator-1",
    statuses: set[str] | None = None,
) -> dict[str, Any]:
    wanted = statuses or {
        "waiting_approval",
        "completed",
        "failed",
        "cancelled",
    }
    for _ in range(500):
        run = harness.get(run_id, actor_id=actor)
        if run["status"] in wanted:
            return run
        time.sleep(0.01)
    raise AssertionError("harness run did not settle")


def _service() -> tuple[EnterpriseAgentService, HarnessRuntime]:
    service = EnterpriseAgentService(Repository(":memory:"))
    return service, service.enable_harness()


class SequenceProvider:
    def __init__(self, messages: list[dict[str, Any] | Exception]):
        self.responses = list(messages)
        self.requests: list[dict[str, Any]] = []

    def complete_with_tools(self, **request: Any) -> dict[str, Any]:
        self.requests.append(deepcopy(request))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _tool_call(
    name: str, arguments: dict[str, Any], *, call_id: str = "call-1"
) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": "",
        "reasoning_content": "选择确定性工具核查，不作监管结论。",
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments, ensure_ascii=False),
                },
            }
        ],
    }


def test_deterministic_coal_check_runs_seven_evidence_tools() -> None:
    service, harness = _service()
    draft = service.create_draft(complete_values(), actor="operator-1")

    created = harness.create(
        actor_id="operator-1",
        task="全面检查这份煤炭填报草稿",
        draft_id=draft["draft_id"],
        mode="deterministic",
    )
    run = _wait(harness, created["run_id"])

    assert run["status"] == "completed"
    assert run["integrity"]["valid"] is True
    assert run["budgets"]["steps_used"] == 7
    assert {
        call["tool_name"] for call in run["tool_calls"]
    } == {
        "draft_summary",
        "deterministic_preflight",
        "source_evidence_check",
        "align_observation_time",
        "inspect_observation_continuity",
        "calculate_coal_flow_balance",
        "explain_cross_validation",
    }
    assert all(call["status"] == "succeeded" for call in run["tool_calls"])
    assert all(
        step["evidence"]["deterministic"] is True for step in run["steps"]
    )
    assert "不是监管认定" in run["answer"]
    assert "未执行确认或提交" in run["answer"]


def test_ten_thousand_observation_check_stays_within_total_result_budget() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    document = new_draft()
    values = complete_values()
    base = values["observations"][0]
    values["observations"] = [
        {
            **base,
            "observation_id": f"obs-large-{index:05d}",
            "sequence_no": index,
        }
        for index in range(10_000)
    ]
    document.update(values)
    draft = repository.create_draft(document, actor="operator-1")
    harness = service.enable_harness()

    created = harness.create(
        actor_id="operator-1",
        task="一万条观测完整体检",
        draft_id=draft["draft_id"],
        mode="deterministic",
    )
    run = _wait(harness, created["run_id"])

    assert run["status"] == "completed"
    assert len(run["tool_calls"]) == 7
    assert run["budgets"]["result_bytes_used"] <= (
        run["budgets"]["max_result_bytes"]
    )
    assert all(
        call["result_bytes"] <= run["budgets"]["max_single_result_bytes"]
        for call in run["tool_calls"]
    )


def test_llm_tool_loop_preserves_reasoning_and_uses_local_tool_evidence() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    provider = SequenceProvider(
        [
            _tool_call("draft_summary", {"draft_id": draft["draft_id"]}),
            {"role": "assistant", "content": "已完成辅助汇总，证据见工具结果。"},
        ]
    )
    harness = HarnessRuntime(service, llm_provider=provider)

    created = harness.create(
        actor_id="operator-1",
        task="概括草稿",
        draft_id=draft["draft_id"],
    )
    run = _wait(harness, created["run_id"])

    assert run["status"] == "completed"
    assert [step["kind"] for step in run["steps"]] == [
        "model",
        "tool",
        "model",
    ]
    second_messages = provider.requests[1]["messages"]
    assistant = next(
        message
        for message in second_messages
        if message["role"] == "assistant"
    )
    assert assistant["reasoning_content"].startswith("选择确定性工具")
    assert assistant["content"] == ""
    assert second_messages[-1]["role"] == "tool"
    assert run["steps"][1]["evidence"]["result_sha256"]


def test_write_tool_waits_for_bound_idempotent_approval() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(actor="operator-1")
    provider = SequenceProvider(
        [
            _tool_call(
                "draft_patch",
                {
                    "draft_id": draft["draft_id"],
                    "expected_revision": 1,
                    "patch": {"enterprise_name": "批准后的名称"},
                },
            ),
            {"role": "assistant", "content": "写入动作已按批准范围处理。"},
        ]
    )
    harness = HarnessRuntime(service, llm_provider=provider)
    created = harness.create(
        actor_id="operator-1",
        task="修改企业名称",
        draft_id=draft["draft_id"],
        allow_mutations=True,
    )
    waiting = _wait(harness, created["run_id"])

    assert waiting["status"] == "waiting_approval"
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == ""
    approval = waiting["approvals"][0]
    call = waiting["tool_calls"][0]
    assert approval["arguments_sha256"] == call["arguments_sha256"]
    assert approval["draft_revision"] == 1
    with service.repository._read() as db:
        checkpoint = db.execute(
            "SELECT checkpoint_json FROM agent_runs WHERE run_id = ?",
            (created["run_id"],),
        ).fetchone()["checkpoint_json"]
    assert "reasoning_content" not in checkpoint
    assert "选择确定性工具" not in checkpoint

    harness.approve(
        created["run_id"],
        approval_id=approval["approval_id"],
        decision="approve",
        actor_id="operator-1",
    )
    run = _wait(harness, created["run_id"])
    assert run["status"] == "completed"
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == (
        "批准后的名称"
    )
    same = harness.approve(
        created["run_id"],
        approval_id=approval["approval_id"],
        decision="approve",
        actor_id="operator-1",
    )
    assert same["approvals"][0]["status"] == "approved"
    with pytest.raises(ConflictError):
        harness.approve(
            created["run_id"],
            approval_id=approval["approval_id"],
            decision="reject",
            actor_id="operator-1",
        )


def test_reject_cancel_and_stale_revision_never_apply_patch() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(actor="operator-1")
    reject_provider = SequenceProvider(
        [
            _tool_call(
                "draft_patch",
                {
                    "draft_id": draft["draft_id"],
                    "expected_revision": 1,
                    "patch": {"enterprise_name": "不能写入"},
                },
            ),
            {"role": "assistant", "content": "人工拒绝，未修改。"},
        ]
    )
    reject_harness = HarnessRuntime(service, llm_provider=reject_provider)
    created = reject_harness.create(
        actor_id="operator-1",
        task="建议修改",
        draft_id=draft["draft_id"],
        allow_mutations=True,
    )
    waiting = _wait(reject_harness, created["run_id"])
    reject_harness.approve(
        created["run_id"],
        approval_id=waiting["approvals"][0]["approval_id"],
        decision="reject",
        actor_id="operator-1",
    )
    rejected = _wait(reject_harness, created["run_id"])
    assert rejected["tool_calls"][0]["status"] == "rejected"
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == ""

    stale_provider = SequenceProvider(
        [
            _tool_call(
                "draft_patch",
                {
                    "draft_id": draft["draft_id"],
                    "expected_revision": 1,
                    "patch": {"enterprise_name": "过期写入"},
                },
            )
        ]
    )
    stale_harness = HarnessRuntime(service, llm_provider=stale_provider)
    created = stale_harness.create(
        actor_id="operator-1",
        task="修改",
        draft_id=draft["draft_id"],
        allow_mutations=True,
    )
    waiting = _wait(stale_harness, created["run_id"])
    service.patch_draft(
        draft["draft_id"],
        {"enterprise_name": "人工并发修改"},
        actor="operator-1",
        expected_revision=1,
    )
    stale_harness.approve(
        created["run_id"],
        approval_id=waiting["approvals"][0]["approval_id"],
        decision="approve",
        actor_id="operator-1",
    )
    stale = _wait(stale_harness, created["run_id"])
    assert stale["status"] == "failed"
    assert stale["tool_calls"][0]["error"]["code"] == (
        "draft_revision_changed"
    )
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == (
        "人工并发修改"
    )

    cancel_provider = SequenceProvider(
        [
            _tool_call(
                "draft_patch",
                {
                    "draft_id": draft["draft_id"],
                    "expected_revision": 2,
                    "patch": {"enterprise_name": "取消写入"},
                },
            )
        ]
    )
    cancel_harness = HarnessRuntime(service, llm_provider=cancel_provider)
    created = cancel_harness.create(
        actor_id="operator-1",
        task="修改后取消",
        draft_id=draft["draft_id"],
        allow_mutations=True,
    )
    _wait(cancel_harness, created["run_id"])
    cancelled = cancel_harness.cancel(
        created["run_id"], actor_id="operator-1"
    )
    assert cancelled["status"] == "cancelled"
    assert cancelled["tool_calls"][0]["status"] == "failed"
    assert cancelled["tool_calls"][0]["error"]["code"] == "run_cancelled"
    assert cancelled["approvals"][0]["status"] == "rejected"
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == (
        "人工并发修改"
    )


def test_owner_isolation_for_get_approve_and_cancel() -> None:
    service, harness = _service()
    created = harness.create(
        actor_id="owner-1", task="列出能力", mode="deterministic"
    )
    _wait(harness, created["run_id"], actor="owner-1")
    with pytest.raises(NotFoundError):
        harness.get(created["run_id"], actor_id="other-2")
    with pytest.raises(NotFoundError):
        harness.cancel(created["run_id"], actor_id="other-2")


def test_cancel_during_model_call_cannot_append_post_cancel_trace() -> None:
    started = threading.Event()
    release = threading.Event()

    class BlockingProvider:
        def complete_with_tools(self, **_request: Any) -> dict[str, Any]:
            started.set()
            release.wait(timeout=2)
            return {"role": "assistant", "content": "ignored"}

    service = EnterpriseAgentService(Repository(":memory:"))
    harness = HarnessRuntime(service, llm_provider=BlockingProvider())
    created = harness.create(actor_id="operator-1", task="等待后取消")
    assert started.wait(timeout=1)
    cancelled = harness.cancel(
        created["run_id"], actor_id="operator-1"
    )
    release.set()
    time.sleep(0.1)
    final = harness.get(created["run_id"], actor_id="operator-1")

    assert cancelled["status"] == "cancelled"
    assert final["status"] == "cancelled"
    assert final["steps"] == []
    assert final["tool_calls"] == []
    assert final["integrity"]["valid"] is True


def test_active_run_limit_is_atomic_and_worker_queue_is_bounded() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    harness = HarnessRuntime(service)
    # Stop workers so queued rows stay active while exercising the Store's
    # transaction-local count-and-insert guard.
    harness.close()
    successes = 0
    for index in range(21):
        try:
            harness.store.create_run(
                actor_id="same-actor",
                task=f"queued-{index}",
                draft_id=None,
                mode="deterministic",
                budgets=HarnessBudgets(),
                allow_mutations=False,
            )
            successes += 1
        except ConflictError:
            pass

    assert successes == 20
    assert harness._run_queue.maxsize == 200
    assert len(harness._workers) == 4
    assert all(worker.daemon for worker in harness._workers)


def test_secrets_and_forbidden_submit_are_never_persisted() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    secret = "sk-super-secret-value-123456"
    provider = SequenceProvider(
        [_tool_call("submit", {}, call_id="forbidden-1")]
    )
    harness = HarnessRuntime(service, llm_provider=provider)
    created = harness.create(
        actor_id="operator-1",
        task=f"api_key={secret} 请提交",
    )
    run = _wait(harness, created["run_id"])

    assert run["status"] == "failed"
    assert run["error"]["code"] == "forbidden_tool"
    assert secret not in run["task"]
    with service.repository._read() as db:
        dump = "\n".join(db.iterdump())
    assert secret not in dump
    assert all(
        "confirm" not in item["name"] and "submit" not in item["name"]
        for item in harness.public_tools()
    )


def test_read_only_run_cannot_plan_write_and_model_claims_are_blocked() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(actor="operator-1")
    provider = SequenceProvider(
        [
            _tool_call(
                "draft_patch",
                {
                    "draft_id": draft["draft_id"],
                    "expected_revision": 1,
                    "patch": {"enterprise_name": "越权"},
                },
            )
        ]
    )
    harness = HarnessRuntime(service, llm_provider=provider)
    created = harness.create(
        actor_id="operator-1",
        task="尝试修改",
        draft_id=draft["draft_id"],
        allow_mutations=False,
    )
    run = _wait(harness, created["run_id"])
    assert run["status"] == "failed"
    assert run["error"]["code"] == "write_tool_not_allowed"
    assert run["approvals"] == []
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == ""
    advertised = provider.requests[0]["tools"]
    assert not any(
        item["function"]["name"] == "draft_patch" for item in advertised
    )
    advertised_by_name = {
        item["function"]["name"]: item["function"] for item in advertised
    }
    assert {
        "convert_coal_quality_basis",
        "evaluate_coal_blend",
        "calculate_inventory_coverage",
        "compare_metric_series",
        "analyze_historical_trend",
        "inspect_observation_continuity",
        "compare_source_consistency",
        "summarize_provenance_lineage",
    } <= set(advertised_by_name)
    assert "caller-supplied scenario" in advertised_by_name[
        "evaluate_coal_blend"
    ]["description"]

    unsafe = HarnessRuntime(
        service,
        llm_provider=SequenceProvider(
            [{"role": "assistant", "content": "数据合规、无异常，可以提交。"}]
        ),
    )
    created = unsafe.create(actor_id="operator-1", task="给结论")
    run = _wait(unsafe, created["run_id"])
    assert run["status"] == "completed"
    assert "数据合规" not in run["answer"]
    assert "可以提交" not in run["answer"]
    assert "未绑定草稿" in run["answer"]

    warning = HarnessRuntime(
        service,
        llm_provider=SequenceProvider(
            [{"role": "assistant", "content": "数据不合规，不可提交。"}]
        ),
    )
    created = warning.create(actor_id="operator-1", task="给风险提示")
    run = _wait(warning, created["run_id"])
    assert run["status"] == "completed"
    assert "数据不合规" not in run["answer"]


def test_model_cannot_publish_ungrounded_draft_numbers() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    provider = SequenceProvider(
        [
            {
                "role": "assistant",
                "content": "产量999999吨，没有问题，建议直接上报。",
            }
        ]
    )
    harness = HarnessRuntime(service, llm_provider=provider)
    created = harness.create(
        actor_id="operator-1",
        task="判断产量",
        draft_id=draft["draft_id"],
    )
    run = _wait(harness, created["run_id"])

    assert run["status"] == "completed"
    assert "999999" not in run["answer"]
    assert "直接上报" not in run["answer"]
    assert any(
        call["status"] == "succeeded"
        and call["evidence_grounding"] == "repository_grounded"
        for call in run["tool_calls"]
    )
    assert all(
        "产量999999" not in step["summary"] for step in run["steps"]
    )


def test_duplicate_provider_tool_call_ids_fail_before_execution() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    duplicate = _tool_call(
        "draft_summary", {"draft_id": draft["draft_id"]}
    )
    duplicate["tool_calls"].append(
        {
            "id": "call-1",
            "type": "function",
            "function": {
                "name": "draft_summary",
                "arguments": json.dumps({"draft_id": draft["draft_id"]}),
            },
        }
    )
    harness = HarnessRuntime(
        service, llm_provider=SequenceProvider([duplicate])
    )
    created = harness.create(
        actor_id="operator-1",
        task="重复调用",
        draft_id=draft["draft_id"],
    )
    run = _wait(harness, created["run_id"])
    assert run["status"] == "failed"
    assert run["error"]["code"] == "duplicate_tool_call_id"
    assert run["tool_calls"] == []


def test_step_and_result_budgets_fail_closed() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    provider = SequenceProvider(
        [
            _tool_call("draft_summary", {"draft_id": draft["draft_id"]}),
            _tool_call(
                "draft_summary",
                {"draft_id": draft["draft_id"]},
                call_id="call-2",
            ),
        ]
    )
    harness = HarnessRuntime(
        service,
        llm_provider=provider,
        budgets=HarnessBudgets(max_steps=2),
    )
    created = harness.create(
        actor_id="operator-1",
        task="反复调用",
        draft_id=draft["draft_id"],
    )
    run = _wait(harness, created["run_id"])
    assert run["status"] == "failed"
    assert run["error"]["code"] == "budget_exceeded"

    small = HarnessRuntime(
        service,
        budgets=HarnessBudgets(max_single_result_bytes=100),
    )
    created = small.create(
        actor_id="operator-1",
        task="体检",
        draft_id=draft["draft_id"],
        mode="deterministic",
    )
    run = _wait(small, created["run_id"])
    assert run["status"] == "failed"
    assert run["error"]["code"] == "budget_exceeded"
    assert run["tool_calls"][0]["result"] is None

    def blob(_arguments: Any, _context: Any) -> ToolResult:
        return ToolResult(data={"blob": "x" * 30_000}, summary="bounded blob")

    blob_registry = ToolRegistry(
        (
            ToolSpec(
                name="bounded_blob",
                description="budget fixture",
                input_schema={
                    "type": "object",
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["blob"],
                    "properties": {
                        "blob": {
                            "type": "string",
                            "maxLength": 40_000,
                        }
                    },
                },
                execute=blob,
            ),
        )
    )
    blob_provider = SequenceProvider(
        [
            _tool_call("bounded_blob", {}, call_id=f"blob-{index}")
            for index in range(4)
        ]
    )
    cumulative = HarnessRuntime(
        service,
        registry=blob_registry,
        llm_provider=blob_provider,
        budgets=HarnessBudgets(
            max_steps=8,
            max_result_bytes=100_000,
            max_single_result_bytes=40_000,
        ),
    )
    created = cumulative.create(actor_id="operator-1", task="累计结果预算")
    run = _wait(cumulative, created["run_id"])
    assert run["status"] == "failed"
    assert run["error"]["code"] == "budget_exceeded"
    assert run["budgets"]["result_bytes_used"] < 100_000
    assert run["tool_calls"][-1]["result"] is None
    assert run["tool_calls"][-1]["status"] == "failed"


def test_tool_timeout_and_provider_failure_fallback() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")

    def slow(_arguments: Any, _context: Any) -> ToolResult:
        time.sleep(0.2)
        return ToolResult(data={"ok": True}, summary="late")

    registry = ToolRegistry(
        (
            ToolSpec(
                name="slow_read",
                description="slow",
                input_schema={
                    "type": "object",
                    "additionalProperties": False,
                },
                output_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ok"],
                    "properties": {"ok": {"type": "boolean"}},
                },
                execute=slow,
                timeout_seconds=0.01,
            ),
        ),
        context=ToolContext(repository=service.repository),
    )
    provider = SequenceProvider([_tool_call("slow_read", {})])
    harness = HarnessRuntime(
        service, registry=registry, llm_provider=provider
    )
    created = harness.create(actor_id="operator-1", task="慢工具")
    run = _wait(harness, created["run_id"])
    assert run["status"] == "failed"
    assert run["tool_calls"][0]["error"]["code"] == "tool_timeout"

    fallback = HarnessRuntime(
        service,
        llm_provider=SequenceProvider([ProviderError("temporary")]),
    )
    created = fallback.create(
        actor_id="operator-1",
        task="模型失败也要体检",
        draft_id=draft["draft_id"],
    )
    run = _wait(fallback, created["run_id"])
    assert run["status"] == "completed"
    assert any("确定性模式" in step["title"] for step in run["steps"])
def test_interrupted_running_run_is_failed_without_replay(
    tmp_path: Path,
) -> None:
    path = tmp_path / "agent.db"
    repository = Repository(path)
    store = HarnessStore(repository)
    created = store.create_run(
        actor_id="operator-1",
        task="中断任务",
        draft_id=None,
        mode="deterministic",
        budgets=HarnessBudgets(),
        allow_mutations=False,
    )
    assert store.claim(created["run_id"]) is True

    service = EnterpriseAgentService(Repository(path))
    service.enable_harness()
    recovered = HarnessStore(service.repository).get(created["run_id"])
    assert recovered["status"] == "failed"
    assert recovered["error"]["code"] == "run_interrupted"
    assert recovered["integrity"]["valid"] is True
