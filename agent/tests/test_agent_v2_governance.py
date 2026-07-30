from __future__ import annotations

import json

import pytest

from enterprise_agent.agent_v2.governance import (
    GovernanceAccess,
    GovernanceStore,
)
from enterprise_agent.errors import (
    ConflictError,
    NotFoundError,
    ValidationBlockedError,
)
from enterprise_agent.storage import Repository


def source_refs(source_id: str = "operator-note-1") -> list[dict[str, str]]:
    return [
        {
            "source_type": "document",
            "source_id": source_id,
            "sha256": "a" * 64,
            "label": "经人工核对的煤炭业务依据",
        }
    ]


@pytest.fixture
def governance() -> GovernanceStore:
    return GovernanceStore(Repository(":memory:"))


def test_readonly_allowlist_and_payload_validation(
    governance: GovernanceStore,
) -> None:
    assert "draft_summary" in governance.readonly_tool_allowlist
    assert "draft_patch" not in governance.readonly_tool_allowlist
    access = GovernanceAccess.single_tenant("alice")

    with pytest.raises(ValidationBlockedError, match="密钥|口令"):
        governance.create_memory_proposal(
            access,
            scope_type="user",
            scope_id="alice",
            memory_key="coal.preference",
            value={"api_key": "sk-not-allowed-12345678"},
            source_refs=source_refs(),
            reason="记录用户偏好",
        )
    with pytest.raises(ValueError, match="source_refs"):
        governance.create_memory_proposal(
            access,
            scope_type="user",
            scope_id="alice",
            memory_key="coal.preference",
            value={"unit": "t"},
            source_refs=[],
            reason="记录用户偏好",
        )
    with pytest.raises(ValueError, match="安全范围"):
        governance.create_memory_proposal(
            access,
            scope_type="user",
            scope_id="alice",
            memory_key="coal.preference",
            value={"unsafe_integer": 9_007_199_254_740_992},
            source_refs=source_refs(),
            reason="记录用户偏好",
        )


def test_user_scope_never_crosses_actor_and_can_be_explicitly_reviewed(
    governance: GovernanceStore,
) -> None:
    alice = GovernanceAccess.single_tenant("alice", can_review=True)
    bob = GovernanceAccess.single_tenant("bob", can_review=True)
    proposal = governance.create_memory_proposal(
        alice,
        scope_type="user",
        scope_id="alice",
        memory_key="display.default-unit",
        value={"unit": "t", "basis": "received"},
        source_refs=source_refs(),
        reason="保存用户本人确认的显示偏好",
    )

    with pytest.raises(NotFoundError):
        governance.get_memory_proposal(bob, proposal["proposal_id"])
    assert governance.list_memory_proposals(bob) == []

    result = governance.decide_memory_proposal(
        alice,
        proposal["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="用户明确确认，仅作用于本人",
    )
    assert result["proposal"]["status"] == "approved"
    assert result["proposal"]["audit"]["valid"] is True
    assert result["proposal"]["audit"]["event_count"] == 2
    assert result["memory"]["version"] == 1
    assert result["memory"]["status"] == "active"
    assert result["memory"]["integrity"]["valid"] is True
    assert result["memory"]["provenance"]["source_refs"] == source_refs()

    with pytest.raises(NotFoundError):
        governance.get_memory(bob, result["memory"]["memory_id"])

    revoked = governance.revoke_memory(
        alice,
        result["memory"]["memory_id"],
        expected_revision=1,
        reason="用户撤回该偏好",
    )
    assert revoked["status"] == "revoked"
    assert revoked["revision"] == 2
    assert revoked["provenance"]["lifecycle"][-1]["event_type"] == "memory_revoked"


def test_shared_memory_requires_four_eyes_and_is_versioned(
    governance: GovernanceStore,
) -> None:
    alice = GovernanceAccess(
        "alice",
        mine_ids=frozenset({"mine-001"}),
        can_review=True,
    )
    bob = GovernanceAccess(
        "bob",
        mine_ids=frozenset({"mine-001"}),
        can_review=True,
    )
    first = governance.create_memory_proposal(
        alice,
        scope_type="mine",
        scope_id="mine-001",
        memory_key="quality.received-ash-baseline",
        value={"median": 12.4, "unit": "%", "basis": "received"},
        source_refs=source_refs("lab-batch-202607"),
        reason="固化已复核的历史基线口径",
    )
    with pytest.raises(ConflictError, match="另一名审批人"):
        governance.decide_memory_proposal(
            alice,
            first["proposal_id"],
            decision="approve",
            expected_revision=1,
            reason="本人批准",
        )
    approved_first = governance.decide_memory_proposal(
        bob,
        first["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="已复核化验批次与口径",
    )["memory"]
    assert approved_first["version"] == 1

    second = governance.create_memory_proposal(
        alice,
        scope_type="mine",
        scope_id="mine-001",
        memory_key="quality.received-ash-baseline",
        value={"median": 12.1, "unit": "%", "basis": "received"},
        source_refs=source_refs("lab-batch-202608"),
        reason="以新审批周期数据更新基线",
    )
    approved_second = governance.decide_memory_proposal(
        bob,
        second["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="新周期数据已复核",
    )["memory"]
    assert approved_second["version"] == 2
    assert governance.get_memory(alice, approved_first["memory_id"])["status"] == (
        "superseded"
    )
    assert governance.list_memories(alice)[0]["memory_id"] == approved_second[
        "memory_id"
    ]


def test_draft_scope_checks_both_row_access_and_draft_existence(
    service,
    values,
) -> None:
    draft = service.create_draft(values, actor="alice")
    governance = GovernanceStore(service.repository)
    allowed = GovernanceAccess(
        "alice", draft_ids=frozenset({draft["draft_id"]})
    )
    denied = GovernanceAccess("bob")
    proposal = governance.create_memory_proposal(
        allowed,
        scope_type="draft",
        scope_id=draft["draft_id"],
        memory_key="review.window-note",
        value={"note": "该窗口包含经批准的检修事件"},
        source_refs=source_refs("maintenance-record-42"),
        reason="保留本草稿的人工复核上下文",
    )
    assert proposal["scope_id"] == draft["draft_id"]
    with pytest.raises(NotFoundError):
        governance.get_memory_proposal(denied, proposal["proposal_id"])
    with pytest.raises(NotFoundError):
        governance.create_memory_proposal(
            GovernanceAccess(
                "alice", draft_ids=frozenset({"missing-draft"})
            ),
            scope_type="draft",
            scope_id="missing-draft",
            memory_key="review.note",
            value={"note": "不存在"},
            source_refs=source_refs(),
            reason="应被拒绝",
        )


def test_proposal_revision_and_hash_chain_are_enforced(
    governance: GovernanceStore,
) -> None:
    access = GovernanceAccess.single_tenant("alice", can_review=True)
    proposal = governance.create_memory_proposal(
        access,
        scope_type="user",
        scope_id="alice",
        memory_key="display.metric-order",
        value=["coal.production_t", "coal.inventory_t"],
        source_refs=source_refs(),
        reason="保存本人确认的指标顺序",
    )
    with pytest.raises(ConflictError, match="修订号"):
        governance.decide_memory_proposal(
            access,
            proposal["proposal_id"],
            decision="reject",
            expected_revision=2,
            reason="错误修订号",
        )

    with governance.repository._transaction() as db:
        row = db.execute(
            """
            SELECT audit_json FROM agent_memory_proposals
            WHERE proposal_id = ?
            """,
            (proposal["proposal_id"],),
        ).fetchone()
        audit = json.loads(row["audit_json"])
        audit[0]["details"]["proposal_sha256"] = "0" * 64
        db.execute(
            """
            UPDATE agent_memory_proposals SET audit_json = ?
            WHERE proposal_id = ?
            """,
            (json.dumps(audit), proposal["proposal_id"]),
        )
    with pytest.raises(ConflictError, match="哈希链"):
        governance.get_memory_proposal(access, proposal["proposal_id"])


def test_tampered_proposal_cannot_be_published(
    governance: GovernanceStore,
) -> None:
    access = GovernanceAccess.single_tenant("alice", can_review=True)
    proposal = governance.create_memory_proposal(
        access,
        scope_type="user",
        scope_id="alice",
        memory_key="display.default-metric",
        value={"metric_code": "coal.production_t"},
        source_refs=source_refs(),
        reason="记录本人确认的默认指标",
    )
    with governance.repository._transaction() as db:
        db.execute(
            """
            UPDATE agent_memory_proposals SET value_json = ?
            WHERE proposal_id = ?
            """,
            (
                json.dumps({"metric_code": "tampered.metric"}),
                proposal["proposal_id"],
            ),
        )
    with pytest.raises(ConflictError, match="内容摘要"):
        governance.decide_memory_proposal(
            access,
            proposal["proposal_id"],
            decision="approve",
            expected_revision=1,
            reason="尝试批准",
        )
    assert governance.list_memories(access) == []


def test_skill_proposal_is_readonly_and_approval_does_not_hot_load(
    governance: GovernanceStore,
) -> None:
    proposer = GovernanceAccess.single_tenant("analyst", can_review=True)
    reviewer = GovernanceAccess.single_tenant("reviewer", can_review=True)
    proposal = governance.create_skill_proposal(
        proposer,
        skill_name="coal-draft-brief",
        description="基于草稿证据生成确定性煤炭数据摘要",
        procedure={
            "steps": [
                {
                    "id": "summary",
                    "tool": "draft_summary",
                    "instruction": "汇总草稿中的指标和证据范围",
                },
                {
                    "id": "evidence",
                    "tool": "source_evidence_check",
                    "instruction": "核对来源摘要和字段来源完整度",
                },
            ]
        },
        allowed_tools=["source_evidence_check", "draft_summary"],
        source_refs=source_refs("skill-design-202607"),
        reason="将已验证的人工核对流程沉淀为候选技能",
    )
    assert proposal["runtime_activation"] == "proposal_only"
    assert proposal["allowed_tools"] == [
        "draft_summary",
        "source_evidence_check",
    ]

    with pytest.raises(ConflictError, match="另一名审批人"):
        governance.decide_skill_proposal(
            proposer,
            proposal["proposal_id"],
            decision="approve",
            expected_revision=1,
            reason="本人批准",
        )

    result = governance.decide_skill_proposal(
        reviewer,
        proposal["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="工具均为只读，流程及来源已复核",
    )
    version = result["skill_version"]
    assert result["proposal"]["status"] == "approved"
    assert version["version"] == 1
    assert version["status"] == "active"
    assert version["runtime_activation"] == "approved_inactive"
    assert version["runtime_loaded"] is False
    assert version["integrity"]["valid"] is True


@pytest.mark.parametrize(
    ("allowed_tools", "procedure"),
    [
        (
            ["draft_patch"],
            {"steps": [{"tool": "draft_patch", "instruction": "修改草稿"}]},
        ),
        (
            ["draft_summary"],
            {"steps": [{"tool": "draft_summary", "shell": "bash -c whoami"}]},
        ),
        (
            ["draft_summary"],
            {"steps": [{"tool": "draft_summary", "instruction": "自动提交数据"}]},
        ),
        (
            ["draft_summary"],
            {"steps": [{"tool": "source_evidence_check"}]},
        ),
    ],
)
def test_skill_proposal_rejects_dangerous_or_unlisted_capabilities(
    governance: GovernanceStore,
    allowed_tools: list[str],
    procedure: dict,
) -> None:
    with pytest.raises(ValidationBlockedError):
        governance.create_skill_proposal(
            GovernanceAccess.single_tenant("analyst"),
            skill_name="unsafe-coal-skill",
            description="不安全技能测试",
            procedure=procedure,
            allowed_tools=allowed_tools,
            source_refs=source_refs(),
            reason="验证安全门禁",
        )


def test_skill_versions_supersede_and_can_be_retired(
    governance: GovernanceStore,
) -> None:
    proposer = GovernanceAccess.single_tenant("analyst")
    reviewer = GovernanceAccess.single_tenant("reviewer", can_review=True)

    def propose(source_id: str) -> dict:
        return governance.create_skill_proposal(
            proposer,
            skill_name="coal-summary",
            description="形成只读煤炭草稿摘要",
            procedure={
                "steps": [
                    {
                        "tool": "draft_summary",
                        "instruction": "汇总煤炭草稿",
                    }
                ]
            },
            allowed_tools=["draft_summary"],
            source_refs=source_refs(source_id),
            reason="更新已验证的摘要流程",
        )

    first_proposal = propose("design-v1")
    first = governance.decide_skill_proposal(
        reviewer,
        first_proposal["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="批准第一版",
    )["skill_version"]
    second_proposal = propose("design-v2")
    second = governance.decide_skill_proposal(
        reviewer,
        second_proposal["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="批准第二版",
    )["skill_version"]

    assert second["version"] == 2
    assert governance.get_skill_version(
        reviewer, first["skill_version_id"]
    )["status"] == "superseded"
    retired = governance.retire_skill_version(
        reviewer,
        second["skill_version_id"],
        expected_revision=1,
        reason="流程依据已过期",
    )
    assert retired["status"] == "retired"
    assert retired["retirement_reason"] == "流程依据已过期"
    assert retired["runtime_loaded"] is False
    assert governance.list_skill_versions(reviewer, status="active") == []


def test_proposal_status_cannot_be_forged_without_lifecycle_event(
    governance: GovernanceStore,
) -> None:
    access = GovernanceAccess.single_tenant("alice", can_review=True)
    memory = governance.create_memory_proposal(
        access,
        scope_type="user",
        scope_id="alice",
        memory_key="tamper-check",
        value={"note": "pending"},
        source_refs=source_refs(),
        reason="验证审批状态完整性",
    )
    skill = governance.create_skill_proposal(
        GovernanceAccess.single_tenant("analyst"),
        skill_name="tamper-check",
        description="验证技能审批状态完整性",
        procedure={
            "steps": [
                {
                    "tool": "draft_summary",
                    "instruction": "只读汇总",
                }
            ]
        },
        allowed_tools=["draft_summary"],
        source_refs=source_refs("skill-tamper"),
        reason="验证审批状态完整性",
    )
    with governance.repository._transaction() as db:
        db.execute(
            """
            UPDATE agent_memory_proposals
            SET status = 'approved', reviewed_by = 'mallory',
                reviewed_at = ?, decision_reason = 'forged'
            WHERE proposal_id = ?
            """,
            ("2026-07-30T00:00:00Z", memory["proposal_id"]),
        )
        db.execute(
            """
            UPDATE agent_skill_proposals
            SET status = 'approved', reviewed_by = 'mallory',
                reviewed_at = ?, decision_reason = 'forged'
            WHERE proposal_id = ?
            """,
            ("2026-07-30T00:00:00Z", skill["proposal_id"]),
        )

    with pytest.raises(ConflictError, match="状态|审计"):
        governance.get_memory_proposal(access, memory["proposal_id"])
    with pytest.raises(ConflictError, match="状态|审计"):
        governance.get_skill_proposal(access, skill["proposal_id"])


def test_published_records_fail_closed_when_parent_approval_is_corrupt(
    governance: GovernanceStore,
) -> None:
    proposer = GovernanceAccess.single_tenant("analyst", can_review=True)
    reviewer = GovernanceAccess.single_tenant("reviewer", can_review=True)
    memory_proposal = governance.create_memory_proposal(
        proposer,
        scope_type="mine",
        scope_id="mine-1",
        memory_key="verified-baseline",
        value={"note": "仅用于解释"},
        source_refs=source_refs("memory-parent"),
        reason="验证发布记录与审批链绑定",
    )
    memory = governance.decide_memory_proposal(
        reviewer,
        memory_proposal["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="复核通过",
    )["memory"]
    skill_proposal = governance.create_skill_proposal(
        proposer,
        skill_name="verified-summary",
        description="只读汇总已核验煤炭草稿",
        procedure={
            "steps": [
                {
                    "tool": "draft_summary",
                    "instruction": "只读汇总",
                }
            ]
        },
        allowed_tools=["draft_summary"],
        source_refs=source_refs("skill-parent"),
        reason="验证技能与审批链绑定",
    )
    skill = governance.decide_skill_proposal(
        reviewer,
        skill_proposal["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="复核通过",
    )["skill_version"]

    with governance.repository._transaction() as db:
        db.execute(
            """
            UPDATE agent_memory_proposals
            SET event_head_hash = ?
            WHERE proposal_id = ?
            """,
            ("f" * 64, memory_proposal["proposal_id"]),
        )
        db.execute(
            """
            UPDATE agent_skill_proposals
            SET event_head_hash = ?
            WHERE proposal_id = ?
            """,
            ("f" * 64, skill_proposal["proposal_id"]),
        )

    with pytest.raises(ConflictError, match="审批|审计"):
        governance.get_memory(reviewer, memory["memory_id"])
    with pytest.raises(ConflictError, match="审批|审计"):
        governance.get_skill_version(reviewer, skill["skill_version_id"])
