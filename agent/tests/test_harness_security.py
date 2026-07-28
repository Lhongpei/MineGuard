from __future__ import annotations

import json
import time
from dataclasses import replace
from typing import Any

import pytest
from conftest import complete_values

from enterprise_agent.errors import ConflictError
from enterprise_agent.harness import HarnessRuntime
from enterprise_agent.harness.models import HarnessBudgets
from enterprise_agent.harness.sanitize import sanitize
from enterprise_agent.harness.store import HarnessStore
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.tools import ToolRegistry, ToolResult, ToolSpec
from enterprise_agent.util import canonical_json, sha256_json


class Provider:
    def __init__(self, responses: list[dict[str, Any]]):
        self.responses = list(responses)

    def complete_with_tools(self, **_request: Any) -> dict[str, Any]:
        return self.responses.pop(0)


def tool_call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": "",
        "reasoning_content": "private provider reasoning",
        "tool_calls": [
            {
                "id": "call-security",
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments),
                },
            }
        ],
    }


def wait_for(
    harness: HarnessRuntime,
    run_id: str,
    status: str,
    *,
    actor: str = "operator-1",
) -> dict[str, Any]:
    for _ in range(500):
        run = harness.get(run_id, actor_id=actor)
        if run["status"] == status:
            return run
        if run["status"] in {"completed", "failed", "cancelled"}:
            return run
        time.sleep(0.01)
    raise AssertionError("run did not settle")


def test_secret_redaction_is_precise_and_covers_common_credentials() -> None:
    value = {
        "signature": "raw-signature",
        "transport_hmac_secret": "secret-value",
        "signature_format_valid_count": 17,
        "signature_verification_status": "valid",
        "text": (
            "Authorization: Basic dXNlcjpwYXNzd29yZA== "
            "AWS AKIAABCDEFGHIJKLMNOP "
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
        ),
    }
    clean = sanitize(value)

    assert clean["signature"] == "[REDACTED]"
    assert clean["transport_hmac_secret"] == "[REDACTED]"
    assert clean["signature_format_valid_count"] == 17
    assert clean["signature_verification_status"] == "valid"
    assert "dXNlcjpwYXNzd29yZA" not in clean["text"]
    assert "AKIAABCDEFGHIJKLMNOP" not in clean["text"]
    assert "BEGIN PRIVATE KEY" not in clean["text"]


def test_tool_context_is_a_copying_read_only_capability() -> None:
    repository = Repository(":memory:")
    service = EnterpriseAgentService(repository)
    draft = service.create_draft(complete_values(), actor="operator-1")

    def probe(arguments: Any, context: Any) -> ToolResult:
        exposed = hasattr(context.repository, "soft_delete")
        copied = context.repository.get_draft(arguments["draft_id"])
        copied["enterprise_name"] = "工具尝试篡改"
        return ToolResult(
            data={
                "soft_delete_exposed": exposed,
                "copied_name": copied["enterprise_name"],
            },
            summary="只读能力探测完成",
        )

    spec = ToolSpec(
        name="draft_summary",
        description="security probe",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["draft_id"],
            "properties": {"draft_id": {"type": "string"}},
        },
        output_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["soft_delete_exposed", "copied_name"],
            "properties": {
                "soft_delete_exposed": {"type": "boolean"},
                "copied_name": {"type": "string"},
            },
        },
        execute=probe,
    )
    provider = Provider(
        [
            tool_call("draft_summary", {"draft_id": draft["draft_id"]}),
            {"role": "assistant", "content": "done"},
        ]
    )
    harness = HarnessRuntime(
        service,
        registry=ToolRegistry((spec,)),
        llm_provider=provider,
    )
    created = harness.create(
        actor_id="operator-1",
        task="probe",
        draft_id=draft["draft_id"],
    )
    run = wait_for(harness, created["run_id"], "completed")

    assert run["status"] == "completed"
    result = run["tool_calls"][0]["result"]["data"]
    assert result["soft_delete_exposed"] is False
    assert service.get_draft(draft["draft_id"])["enterprise_name"] != (
        "工具尝试篡改"
    )


def test_untrusted_generic_mutating_tool_is_rejected() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    spec = ToolSpec(
        name="evil_write",
        description="write",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        execute=lambda _arguments, _context: ToolResult(
            data={}, summary="bad"
        ),
        mutating=True,
        requires_approval=True,
    )
    with pytest.raises(ValueError, match="draft_patch"):
        HarnessRuntime(service, registry=ToolRegistry((spec,)))


def _waiting_patch() -> tuple[
    EnterpriseAgentService, HarnessRuntime, dict[str, Any], dict[str, Any]
]:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(actor="operator-1")
    provider = Provider(
        [
            tool_call(
                "draft_patch",
                {
                    "draft_id": draft["draft_id"],
                    "expected_revision": 1,
                    "patch": {"enterprise_name": "原批准值"},
                },
            )
        ]
    )
    harness = HarnessRuntime(service, llm_provider=provider)
    created = harness.create(
        actor_id="operator-1",
        task="patch",
        draft_id=draft["draft_id"],
        allow_mutations=True,
    )
    waiting = wait_for(harness, created["run_id"], "waiting_approval")
    assert waiting["status"] == "waiting_approval"
    return service, harness, draft, waiting


def test_multicolumn_argument_tamper_is_detected_against_audit_event() -> None:
    service, harness, draft, waiting = _waiting_patch()
    call = waiting["tool_calls"][0]
    approval = waiting["approvals"][0]
    tampered = {
        **call["arguments"],
        "patch": {"enterprise_name": "篡改后的值"},
    }
    digest = sha256_json(tampered)
    with service.repository._transaction() as db:
        db.execute(
            """
            UPDATE agent_tool_calls
            SET arguments_json = ?, arguments_sha256 = ?
            WHERE call_id = ?
            """,
            (canonical_json(tampered), digest, call["call_id"]),
        )
        db.execute(
            """
            UPDATE agent_approvals SET arguments_sha256 = ?
            WHERE approval_id = ?
            """,
            (digest, approval["approval_id"]),
        )

    assert harness.get(
        waiting["run_id"], actor_id="operator-1"
    )["integrity"]["valid"] is False
    with pytest.raises(ConflictError):
        harness.approve(
            waiting["run_id"],
            approval_id=approval["approval_id"],
            decision="approve",
            actor_id="operator-1",
        )
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == ""


def test_result_and_event_tail_tamper_make_integrity_false() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    harness = HarnessRuntime(service)
    created = harness.create(
        actor_id="operator-1",
        task="check",
        draft_id=draft["draft_id"],
        mode="deterministic",
    )
    run = wait_for(harness, created["run_id"], "completed")
    assert run["integrity"]["valid"] is True
    call_id = run["tool_calls"][0]["call_id"]
    with service.repository._transaction() as db:
        db.execute(
            "UPDATE agent_tool_calls SET result_json = ? WHERE call_id = ?",
            ('{"tampered":true}', call_id),
        )
    assert harness.get(
        run["run_id"], actor_id="operator-1"
    )["integrity"]["valid"] is False

    with service.repository._transaction() as db:
        db.execute(
            """
            DELETE FROM agent_run_events
            WHERE run_id = ? AND sequence = (
                SELECT MAX(sequence) FROM agent_run_events WHERE run_id = ?
            )
            """,
            (run["run_id"], run["run_id"]),
        )
    integrity = harness.get(
        run["run_id"], actor_id="operator-1"
    )["integrity"]
    assert integrity["valid"] is False
    assert integrity["anchored_event_count"] > integrity["event_count"]


@pytest.mark.parametrize(
    "target",
    ("result_and_digest", "step_projection", "run_answer"),
)
def test_projection_tamper_is_checked_against_events_and_hidden(
    target: str,
) -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    harness = HarnessRuntime(service)
    created = harness.create(
        actor_id="operator-1",
        task="projection-integrity",
        draft_id=draft["draft_id"],
        mode="deterministic",
    )
    run = wait_for(harness, created["run_id"], "completed")
    assert run["integrity"]["valid"] is True

    with service.repository._transaction() as db:
        if target == "result_and_digest":
            forged = {"forged": True}
            db.execute(
                """
                UPDATE agent_tool_calls
                SET result_json = ?, result_sha256 = ?
                WHERE call_id = ?
                """,
                (
                    canonical_json(forged),
                    sha256_json(forged),
                    run["tool_calls"][0]["call_id"],
                ),
            )
        elif target == "step_projection":
            forged_evidence = {"forged": True}
            db.execute(
                """
                UPDATE agent_run_steps
                SET summary = ?, evidence_json = ?
                WHERE run_id = ? AND sequence = 1
                """,
                (
                    "FORGED STEP",
                    canonical_json(forged_evidence),
                    run["run_id"],
                ),
            )
        else:
            db.execute(
                """
                UPDATE agent_runs SET summary = ?, answer = ?
                WHERE run_id = ?
                """,
                ("FORGED SUMMARY", "FORGED ANSWER", run["run_id"]),
            )

    hidden = harness.get(run["run_id"], actor_id="operator-1")
    assert hidden["integrity"]["valid"] is False
    assert hidden["actionable"] is False
    assert hidden["answer"] is None
    assert hidden["tool_calls"] == []
    assert hidden["steps"] == []
    assert "FORGED" not in canonical_json(hidden)


def test_database_status_cannot_forge_human_approval() -> None:
    service, harness, draft, waiting = _waiting_patch()
    approval = waiting["approvals"][0]
    decided_at = "2026-07-27T00:00:00Z"
    with service.repository._transaction() as db:
        db.execute(
            """
            UPDATE agent_approvals
            SET status = 'approved', decision = 'approve',
                decided_by = 'attacker', decided_at = ?
            WHERE approval_id = ?
            """,
            (decided_at, approval["approval_id"]),
        )
        db.execute(
            """
            UPDATE agent_runs SET status = 'queued'
            WHERE run_id = ?
            """,
            (waiting["run_id"],),
        )

    forged = harness.get(waiting["run_id"], actor_id="operator-1")
    assert forged["integrity"]["valid"] is False
    assert forged["actionable"] is False
    harness._schedule(waiting["run_id"])
    final = wait_for(harness, waiting["run_id"], "failed")
    assert final["integrity"]["valid"] is False
    assert service.get_draft(draft["draft_id"])["enterprise_name"] == ""


@pytest.mark.parametrize(
    ("table", "column", "selector"),
    [
        ("agent_runs", "budgets_json", "run_id"),
        ("agent_tool_calls", "arguments_json", "call_id"),
        ("agent_tool_calls", "result_json", "call_id"),
    ],
)
def test_malformed_persisted_json_fails_closed_without_projection_error(
    table: str,
    column: str,
    selector: str,
) -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    harness = HarnessRuntime(service)
    created = harness.create(
        actor_id="operator-1",
        task="check",
        draft_id=draft["draft_id"],
        mode="deterministic",
    )
    run = wait_for(harness, created["run_id"], "completed")
    selector_value = (
        run["run_id"]
        if selector == "run_id"
        else run["tool_calls"][0]["call_id"]
    )
    with service.repository._transaction() as db:
        db.execute(
            f"UPDATE {table} SET {column} = ? WHERE {selector} = ?",
            ("{malformed", selector_value),
        )

    hidden = harness.get(run["run_id"], actor_id="operator-1")
    assert hidden["integrity"]["valid"] is False
    assert hidden["actionable"] is False
    assert hidden["tool_calls"] == []
    assert hidden["budgets"] == {}
    items, total = harness.list(actor_id="operator-1")
    assert total == 1
    assert items[0]["integrity"]["valid"] is False
    assert items[0]["task"].startswith("[审计完整性失败")


def test_tool_definition_change_and_restart_invalidate_approval() -> None:
    service, harness, _draft, waiting = _waiting_patch()
    approval = waiting["approvals"][0]
    original = harness.registry.get("draft_patch")
    harness.registry._specs["draft_patch"] = replace(
        original, description=original.description + " changed"
    )
    with pytest.raises(ConflictError, match="版本|定义"):
        harness.approve(
            waiting["run_id"],
            approval_id=approval["approval_id"],
            decision="approve",
            actor_id="operator-1",
        )

    service2, harness2, _draft2, waiting2 = _waiting_patch()
    restarted = HarnessRuntime(service2)
    invalidated = restarted.get(
        waiting2["run_id"], actor_id="operator-1"
    )
    assert invalidated["status"] == "failed"
    assert invalidated["error"]["code"] == (
        "approval_invalidated_by_restart"
    )
    assert invalidated["approvals"][0]["status"] == "rejected"


def test_restart_marks_inflight_write_outcome_unknown() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(actor="operator-1")
    store = HarnessStore(service.repository)
    created = store.create_run(
        actor_id="operator-1",
        task="write",
        draft_id=draft["draft_id"],
        mode="auto",
        budgets=HarnessBudgets(),
        allow_mutations=True,
    )
    assert store.claim(created["run_id"])
    call = store.create_tool_call(
        created["run_id"],
        provider_call_id="write-1",
        tool_name="draft_patch",
        tool_spec_sha256="a" * 64,
        evidence_grounding="user_supplied",
        arguments={
            "draft_id": draft["draft_id"],
            "expected_revision": 1,
            "patch": {"enterprise_name": "unknown"},
        },
        draft_revision=1,
        requires_approval=True,
        harness_version="agent-harness-v1",
    )
    store.update_checkpoint(
        created["run_id"],
        {
            "messages": [],
            "pending_batch": [call["call_id"]],
            "allow_mutations": True,
        },
        status="waiting_approval",
    )
    waiting = store.get(created["run_id"])
    store.decide_approval(
        created["run_id"],
        approval_id=waiting["approvals"][0]["approval_id"],
        decision="approve",
        actor_id="operator-1",
    )
    assert store.claim(created["run_id"])
    assert store.mark_tool_running(call["call_id"])

    restarted = HarnessRuntime(service)
    run = restarted.get(created["run_id"], actor_id="operator-1")
    assert run["status"] == "failed"
    assert run["error"]["code"] == "mutation_outcome_unknown"
    assert run["tool_calls"][0]["error"]["code"] == (
        "mutation_outcome_unknown"
    )
    assert "未执行" not in run["error"]["message"]
