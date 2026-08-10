from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from enterprise_agent.agent_v2.governance import (
    GovernanceAccess,
    GovernanceStore,
)
from enterprise_agent.errors import ConflictError
from enterprise_agent.storage import Repository


def _legacy_governance_schema(path: Path) -> None:
    db = sqlite3.connect(path)
    try:
        db.executescript(
            """
            CREATE TABLE agent_memory_proposals (
                proposal_id TEXT PRIMARY KEY,
                scope_type TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                memory_key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                source_refs_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                revision INTEGER NOT NULL,
                proposed_by TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at TEXT,
                decision_reason TEXT,
                proposal_sha256 TEXT NOT NULL,
                audit_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE agent_memories (
                memory_id TEXT PRIMARY KEY,
                scope_type TEXT NOT NULL,
                scope_id TEXT NOT NULL,
                memory_key TEXT NOT NULL,
                version INTEGER NOT NULL,
                value_json TEXT NOT NULL,
                proposal_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE agent_skill_proposals (
                proposal_id TEXT PRIMARY KEY,
                skill_name TEXT NOT NULL,
                description TEXT NOT NULL,
                procedure_json TEXT NOT NULL,
                allowed_tools_json TEXT NOT NULL,
                source_refs_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                revision INTEGER NOT NULL,
                proposed_by TEXT NOT NULL,
                reviewed_by TEXT,
                reviewed_at TEXT,
                decision_reason TEXT,
                proposal_sha256 TEXT NOT NULL,
                audit_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE agent_skill_versions (
                skill_version_id TEXT PRIMARY KEY,
                skill_name TEXT NOT NULL,
                version INTEGER NOT NULL,
                description TEXT NOT NULL,
                procedure_json TEXT NOT NULL,
                allowed_tools_json TEXT NOT NULL,
                source_refs_json TEXT NOT NULL,
                proposal_id TEXT NOT NULL,
                status TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT INTO agent_memory_proposals (
                proposal_id, scope_type, scope_id, memory_key, value_json,
                source_refs_json, reason, status, revision, proposed_by,
                proposal_sha256, audit_json, created_at, updated_at
            ) VALUES (
                'legacy-proposal', 'user', 'alice', 'legacy-key', '{}',
                '[]', 'legacy', 'pending', 1, 'alice', '', '[]',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            );
            INSERT INTO agent_memories (
                memory_id, scope_type, scope_id, memory_key, version,
                value_json, proposal_id, status, created_by, created_at,
                updated_at
            ) VALUES (
                'legacy-memory', 'user', 'alice', 'legacy-active', 1,
                '{}', 'legacy-proposal', 'active', 'legacy-reviewer',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            );
            INSERT INTO agent_skill_proposals (
                proposal_id, skill_name, description, procedure_json,
                allowed_tools_json, source_refs_json, reason, status,
                revision, proposed_by, proposal_sha256, audit_json,
                created_at, updated_at
            ) VALUES (
                'legacy-skill-proposal', 'legacy-skill', 'legacy',
                '{"steps":[{"tool":"draft_summary","instruction":"legacy"}]}',
                '["draft_summary"]', '[]', 'legacy', 'pending', 1, 'alice',
                '', '[]', '2026-01-01T00:00:00Z',
                '2026-01-01T00:00:00Z'
            );
            INSERT INTO agent_skill_versions (
                skill_version_id, skill_name, version, description,
                procedure_json, allowed_tools_json, source_refs_json,
                proposal_id, status, approved_by, approved_at, created_at,
                updated_at
            ) VALUES (
                'legacy-skill-version', 'legacy-skill', 1, 'legacy',
                '{"steps":[{"tool":"draft_summary","instruction":"legacy"}]}',
                '["draft_summary"]', '[]', 'legacy-skill-proposal',
                'active', 'legacy-reviewer', '2026-01-01T00:00:00Z',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            );
            """
        )
        db.commit()
    finally:
        db.close()


def test_governance_schema_migrates_and_legacy_rows_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-governance.db"
    _legacy_governance_schema(path)

    repository = Repository(path)
    governance = GovernanceStore(repository)
    access = GovernanceAccess.single_tenant("alice", can_review=True)

    with repository._read() as db:
        version = db.execute(
            """
            SELECT version FROM app_schema_versions
            WHERE component = 'enterprise_agent'
            """
        ).fetchone()
        skill_columns = {
            row["name"]
            for row in db.execute(
                "PRAGMA table_info(agent_skill_versions)"
            ).fetchall()
        }
    assert version["version"] == 9
    assert {
        "runtime_activation",
        "revision",
        "retired_by",
        "retired_at",
        "retirement_reason",
        "record_sha256",
    } <= skill_columns

    with pytest.raises(ConflictError, match="审计|状态"):
        governance.get_memory_proposal(access, "legacy-proposal")

    created = governance.create_memory_proposal(
        access,
        scope_type="mine",
        scope_id="mine-migration",
        memory_key="post-migration",
        value={"note": "new rows use the complete schema"},
        source_refs=[
            {
                "source_type": "document",
                "source_id": "migration-evidence",
                "sha256": "a" * 64,
                "label": "迁移测试来源",
            }
        ],
        reason="验证升级后可正常写入",
    )
    approved = governance.decide_memory_proposal(
        GovernanceAccess.single_tenant("reviewer", can_review=True),
        created["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="复核通过",
    )
    assert approved["memory"]["status"] == "active"

    replacement = governance.create_memory_proposal(
        access,
        scope_type="user",
        scope_id="alice",
        memory_key="legacy-active",
        value={"note": "replace quarantined legacy row"},
        source_refs=[
            {
                "source_type": "document",
                "source_id": "replacement-evidence",
                "sha256": "b" * 64,
                "label": "替换依据",
            }
        ],
        reason="以可核验提案替代旧记录",
    )
    replacement_memory = governance.decide_memory_proposal(
        access,
        replacement["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="复核通过",
    )["memory"]
    assert replacement_memory["version"] == 2
    visible_memories = governance.list_memories(access)
    assert replacement_memory["memory_id"] in {
        item["memory_id"] for item in visible_memories
    }
    assert "legacy-memory" not in {
        item["memory_id"] for item in visible_memories
    }

    replacement_skill = governance.create_skill_proposal(
        access,
        skill_name="legacy-skill",
        description="以受治理只读技能替代旧记录",
        procedure={
            "steps": [
                {
                    "tool": "draft_summary",
                    "instruction": "只读汇总",
                }
            ]
        },
        allowed_tools=["draft_summary"],
        source_refs=[
            {
                "source_type": "document",
                "source_id": "skill-replacement-evidence",
                "sha256": "c" * 64,
                "label": "技能替换依据",
            }
        ],
        reason="旧技能记录无法验证",
    )
    replacement_version = governance.decide_skill_proposal(
        GovernanceAccess.single_tenant("skill-reviewer", can_review=True),
        replacement_skill["proposal_id"],
        decision="approve",
        expected_revision=1,
        reason="复核通过",
    )["skill_version"]
    assert replacement_version["version"] == 2
    assert governance.list_skill_versions(access) == [replacement_version]
    with pytest.raises(
        sqlite3.IntegrityError
    ), repository._transaction() as db:
        db.execute(
            """
            UPDATE agent_skill_versions
            SET runtime_activation = 'hot_loaded'
            WHERE skill_version_id = ?
            """,
            (replacement_version["skill_version_id"],),
        )
    with pytest.raises(
        sqlite3.IntegrityError
    ), repository._transaction() as db:
        db.execute(
            """
            UPDATE agent_memories SET revision = 0
            WHERE memory_id = ?
            """,
            (replacement_memory["memory_id"],),
        )


def test_schema_migration_is_serialized_between_repository_instances(
    tmp_path: Path,
) -> None:
    path = tmp_path / "concurrent-migration.db"
    _legacy_governance_schema(path)

    def open_repository(_index: int) -> int:
        repository = Repository(path)
        with repository._read() as db:
            return int(
                db.execute(
                    """
                    SELECT version FROM app_schema_versions
                    WHERE component = 'enterprise_agent'
                    """
                ).fetchone()["version"]
            )

    with ThreadPoolExecutor(max_workers=12) as pool:
        versions = list(pool.map(open_repository, range(24)))
    assert versions == [9] * 24


def test_future_schema_version_refuses_downgrade(tmp_path: Path) -> None:
    path = tmp_path / "future-schema.db"
    repository = Repository(path)
    with repository._transaction() as db:
        db.execute(
            """
            UPDATE app_schema_versions
            SET version = 999
            WHERE component = 'enterprise_agent'
            """
        )

    with pytest.raises(ValueError, match="高于当前程序"):
        Repository(path)
def test_memory_transaction_rolls_back_base_exception() -> None:
    repository = Repository(":memory:")
    with pytest.raises(KeyboardInterrupt), repository._transaction() as db:
        db.execute(
            """
            INSERT INTO app_schema_versions (component, version, updated_at)
            VALUES ('interrupt-test', 1, '2026-07-30T00:00:00Z')
            """
        )
        raise KeyboardInterrupt()

    with repository._transaction() as db:
        db.execute(
            """
            INSERT INTO app_schema_versions (component, version, updated_at)
            VALUES ('after-interrupt', 1, '2026-07-30T00:00:00Z')
            """
        )
    with repository._read() as db:
        rows = db.execute(
            """
            SELECT component FROM app_schema_versions
            WHERE component IN ('interrupt-test', 'after-interrupt')
            ORDER BY component
            """
        ).fetchall()
    assert [row["component"] for row in rows] == ["after-interrupt"]
