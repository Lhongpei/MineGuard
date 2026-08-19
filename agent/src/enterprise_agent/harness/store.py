"""SQLite-backed harness state and append-only hash-chain audit."""

from __future__ import annotations

import hmac
import json
import uuid
from typing import Any

from enterprise_agent.errors import ConflictError, NotFoundError
from enterprise_agent.storage import Repository
from enterprise_agent.util import canonical_json, sha256_json, utc_text

from .models import TERMINAL_STATUSES, HarnessBudgets
from .sanitize import redact_text, sanitize


class HarnessStore:
    def __init__(self, repository: Repository):
        self.repository = repository

    @staticmethod
    def _append_event(
        db: Any,
        *,
        run_id: str,
        event_type: str,
        actor_id: str,
        details: dict[str, Any],
        occurred_at: str | None = None,
    ) -> None:
        now = occurred_at or utc_text()
        previous = db.execute(
            """
            SELECT sequence, event_hash FROM agent_run_events
            WHERE run_id = ? ORDER BY sequence DESC LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = str(previous["event_hash"]) if previous else "0" * 64
        anchor = db.execute(
            """
            SELECT event_count, event_head_hash FROM agent_runs
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if (
            anchor is None
            or int(anchor["event_count"]) != sequence - 1
            or not hmac.compare_digest(
                str(anchor["event_head_hash"]), previous_hash
            )
        ):
            raise ConflictError("智能体运行审计锚点不一致，拒绝继续写入")
        safe_details = sanitize(details)
        envelope = {
            "run_id": run_id,
            "sequence": sequence,
            "event_type": event_type,
            "actor_id": actor_id,
            "details": safe_details,
            "occurred_at": now,
            "previous_hash": previous_hash,
        }
        db.execute(
            """
            INSERT INTO agent_run_events (
                run_id, sequence, event_type, actor_id, details_json,
                occurred_at, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                sequence,
                event_type,
                actor_id,
                canonical_json(safe_details),
                now,
                previous_hash,
                sha256_json(envelope),
            ),
        )
        db.execute(
            """
            UPDATE agent_runs SET event_count = ?, event_head_hash = ?
            WHERE run_id = ?
            """,
            (sequence, sha256_json(envelope), run_id),
        )

    def create_run(
        self,
        *,
        actor_id: str,
        task: str,
        draft_id: str | None,
        mode: str,
        budgets: HarnessBudgets,
        allow_mutations: bool,
        tool_profile: str = "standard",
    ) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        now = utc_text()
        checkpoint = {
            "messages": [],
            "pending_batch": [],
            "allow_mutations": allow_mutations,
            "tool_profile": tool_profile,
        }
        with self.repository._transaction() as db:
            if draft_id is not None:
                try:
                    self.repository._assert_active_draft_in_transaction(
                        db,
                        draft_id,
                    )
                except NotFoundError:
                    production_draft = db.execute(
                        "SELECT status FROM fq_drafts WHERE draft_id = ?",
                        (draft_id,),
                    ).fetchone()
                    if (
                        production_draft is None
                        or production_draft["status"] == "discarded"
                        or tool_profile != "chat_read_only"
                        or allow_mutations
                    ):
                        raise
            actor_active = db.execute(
                """
                SELECT COUNT(*) AS amount FROM agent_runs
                WHERE actor_id = ?
                  AND status IN ('queued', 'running', 'waiting_approval')
                """,
                (actor_id,),
            ).fetchone()
            global_active = db.execute(
                """
                SELECT COUNT(*) AS amount FROM agent_runs
                WHERE status IN ('queued', 'running', 'waiting_approval')
                """
            ).fetchone()
            if int(actor_active["amount"]) >= 20:
                raise ConflictError(
                    "当前账号未结束的智能体任务过多，请先处理或取消"
                )
            if int(global_active["amount"]) >= 200:
                raise ConflictError(
                    "服务当前智能体任务已满，请稍后再试"
                )
            db.execute(
                """
                INSERT INTO agent_runs (
                    run_id, actor_id, draft_id, task_text, mode, status,
                    budgets_json, checkpoint_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)
                """,
                (
                    run_id,
                    actor_id,
                    draft_id,
                    redact_text(task, maximum=4_000),
                    mode,
                    canonical_json(budgets.public_dict()),
                    canonical_json(checkpoint),
                    now,
                    now,
                ),
            )
            self._append_event(
                db,
                run_id=run_id,
                event_type="run_created",
                actor_id=actor_id,
                details={
                    "mode": mode,
                    "draft_id": draft_id,
                    "task_sha256": sha256_json(task),
                    "budgets": budgets.public_dict(),
                    "allow_mutations": allow_mutations,
                    "tool_profile": tool_profile,
                },
                occurred_at=now,
            )
        return self.get(run_id)

    def recover_interrupted(self) -> list[str]:
        """Fail ambiguous in-flight work and return safe queued work to resume."""

        now = utc_text()
        with self.repository._transaction() as db:
            running = db.execute(
                """
                SELECT run_id, actor_id FROM agent_runs
                WHERE status = 'running'
                """
            ).fetchall()
            for row in running:
                ambiguous = db.execute(
                    """
                    SELECT call_id FROM agent_tool_calls
                    WHERE run_id = ? AND status = 'running'
                      AND approval_id IS NOT NULL
                    LIMIT 1
                    """,
                    (row["run_id"],),
                ).fetchone()
                error_code = (
                    "mutation_outcome_unknown"
                    if ambiguous is not None
                    else "run_interrupted"
                )
                summary = (
                    "写操作执行期间进程中断，结果待人工核对"
                    if ambiguous is not None
                    else "进程中断，未自动重放"
                )
                error_message = (
                    "写操作开始后进程中断；执行结果未知，请核对草稿修订和审计"
                    if ambiguous is not None
                    else "上次进程执行期间中断；未自动重放"
                )
                db.execute(
                    """
                    UPDATE agent_runs
                    SET status = 'failed', summary = ?,
                        error_code = ?, error_message = ?,
                        updated_at = ?, completed_at = ?
                    WHERE run_id = ?
                    """,
                    (
                        summary,
                        error_code,
                        error_message,
                        now,
                        now,
                        row["run_id"],
                    ),
                )
                db.execute(
                    """
                    UPDATE agent_tool_calls
                    SET status = 'failed',
                        error_code = CASE
                            WHEN approval_id IS NOT NULL
                            THEN 'mutation_outcome_unknown'
                            ELSE 'run_interrupted'
                        END,
                        error_message = CASE
                            WHEN approval_id IS NOT NULL
                            THEN '写操作结果未知，需人工核对'
                            ELSE '进程中断，工具未自动重放'
                        END,
                        completed_at = ?
                    WHERE run_id = ?
                      AND status IN ('planned', 'running')
                    """,
                    (now, row["run_id"]),
                )
                self._append_event(
                    db,
                    run_id=row["run_id"],
                    event_type="run_interrupted",
                    actor_id="system",
                    details={
                        "previous_actor_id": row["actor_id"],
                        "status": "failed",
                        "summary_sha256": sha256_json(summary),
                        "answer_sha256": None,
                        "error_code": error_code,
                        "error_message_sha256": sha256_json(error_message),
                    },
                    occurred_at=now,
                )
            waiting = db.execute(
                """
                SELECT run_id, actor_id FROM agent_runs
                WHERE status = 'waiting_approval'
                """
            ).fetchall()
            for row in waiting:
                db.execute(
                    """
                    UPDATE agent_runs
                    SET status = 'failed',
                        summary = '服务重启后旧批准已失效',
                        error_code = 'approval_invalidated_by_restart',
                        error_message = '请重新发起任务并重新核对待批准动作',
                        updated_at = ?, completed_at = ?
                    WHERE run_id = ?
                    """,
                    (now, now, row["run_id"]),
                )
                db.execute(
                    """
                    UPDATE agent_tool_calls
                    SET status = 'failed',
                        error_code = 'approval_invalidated_by_restart',
                        error_message = '服务重启后待批准动作失效',
                        completed_at = ?
                    WHERE run_id = ? AND status = 'waiting_approval'
                    """,
                    (now, row["run_id"]),
                )
                db.execute(
                    """
                    UPDATE agent_approvals
                    SET status = 'rejected', decision = 'reject',
                        decided_by = 'system', decided_at = ?
                    WHERE run_id = ? AND status = 'pending'
                    """,
                    (now, row["run_id"]),
                )
                self._append_event(
                    db,
                    run_id=row["run_id"],
                    event_type="approval_invalidated_by_restart",
                    actor_id="system",
                    details={
                        "previous_actor_id": row["actor_id"],
                        "status": "failed",
                        "summary_sha256": sha256_json(
                            "服务重启后旧批准已失效"
                        ),
                        "answer_sha256": None,
                        "error_code": "approval_invalidated_by_restart",
                        "error_message_sha256": sha256_json(
                            "请重新发起任务并重新核对待批准动作"
                        ),
                    },
                    occurred_at=now,
                )
            queued = db.execute(
                """
                SELECT run_id FROM agent_runs
                WHERE status = 'queued' AND cancel_requested = 0
                """
            ).fetchall()
        return [str(row["run_id"]) for row in queued]

    def count_active_for_actor(self, actor_id: str) -> int:
        with self.repository._read() as db:
            row = db.execute(
                """
                SELECT COUNT(*) AS amount FROM agent_runs
                WHERE actor_id = ?
                  AND status IN ('queued', 'running', 'waiting_approval')
                """,
                (actor_id,),
            ).fetchone()
        return int(row["amount"])

    def claim(self, run_id: str) -> bool:
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None or row["status"] != "queued":
                return False
            if row["cancel_requested"]:
                return False
            changed = db.execute(
                """
                UPDATE agent_runs SET status = 'running', updated_at = ?
                WHERE run_id = ? AND status = 'queued'
                  AND cancel_requested = 0
                """,
                (now, run_id),
            )
            if changed.rowcount != 1:
                return False
            self._append_event(
                db,
                run_id=run_id,
                event_type="run_started",
                actor_id=row["actor_id"],
                details={},
                occurred_at=now,
            )
        return True

    def update_checkpoint(
        self,
        run_id: str,
        checkpoint: dict[str, Any],
        *,
        status: str | None = None,
        summary: str | None = None,
        answer: str | None = None,
    ) -> None:
        with self.repository._transaction() as db:
            previous = db.execute(
                """
                SELECT actor_id, status, checkpoint_json
                FROM agent_runs WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            if previous is None:
                raise NotFoundError("智能体运行不存在")
            if previous["status"] in TERMINAL_STATUSES:
                raise ConflictError("智能体运行已经结束")
            stored_checkpoint = json.loads(previous["checkpoint_json"])
            safe_checkpoint = sanitize(checkpoint)
            if not isinstance(safe_checkpoint, dict):
                raise ValueError("运行检查点必须是对象")
            for protected in ("allow_mutations", "tool_profile"):
                stored_value = stored_checkpoint.get(protected)
                if (
                    protected in safe_checkpoint
                    and safe_checkpoint[protected] != stored_value
                ):
                    raise ConflictError("运行工具安全配置不能在执行中修改")
                safe_checkpoint[protected] = stored_value
            assignments = ["checkpoint_json = ?", "updated_at = ?"]
            values: list[Any] = [
                canonical_json(safe_checkpoint),
                utc_text(),
            ]
            if status is not None:
                assignments.append("status = ?")
                values.append(status)
            if summary is not None:
                assignments.append("summary = ?")
                values.append(redact_text(summary, maximum=2_000))
            if answer is not None:
                assignments.append("answer = ?")
                values.append(redact_text(answer, maximum=16_000))
            values.append(run_id)
            db.execute(
                f"UPDATE agent_runs SET {', '.join(assignments)} WHERE run_id = ?",
                values,
            )
            if (
                previous is not None
                and status is not None
                and previous["status"] != status
            ):
                self._append_event(
                    db,
                    run_id=run_id,
                    event_type=f"run_{status}",
                    actor_id=previous["actor_id"],
                    details={},
                )

    def add_active_duration(self, run_id: str, milliseconds: int) -> None:
        if milliseconds <= 0:
            return
        with self.repository._transaction() as db:
            db.execute(
                """
                UPDATE agent_runs
                SET active_duration_ms = active_duration_ms + ?, updated_at = ?
                WHERE run_id = ?
                """,
                (milliseconds, utc_text(), run_id),
            )

    def add_step(
        self,
        run_id: str,
        *,
        kind: str,
        status: str,
        title: str,
        summary: str,
        evidence: dict[str, Any] | None = None,
    ) -> None:
        now = utc_text()
        safe_evidence = sanitize(evidence or {})
        with self.repository._transaction() as db:
            run = db.execute(
                "SELECT actor_id, status FROM agent_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise NotFoundError("智能体运行不存在")
            if run["status"] in TERMINAL_STATUSES:
                raise ConflictError("智能体运行已经结束")
            row = db.execute(
                """
                SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence
                FROM agent_run_steps WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            sequence = int(row["sequence"])
            db.execute(
                """
                INSERT INTO agent_run_steps (
                    run_id, sequence, kind, status, title, summary,
                    evidence_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    sequence,
                    kind,
                    status,
                    redact_text(title, maximum=200),
                    redact_text(summary, maximum=2_000),
                    canonical_json(safe_evidence),
                    now,
                ),
            )
            self._append_event(
                db,
                run_id=run_id,
                event_type="step_recorded",
                actor_id=run["actor_id"],
                details={
                    "sequence": sequence,
                    "kind": kind,
                    "status": status,
                    "title_sha256": sha256_json(
                        redact_text(title, maximum=200)
                    ),
                    "summary_sha256": sha256_json(
                        redact_text(summary, maximum=2_000)
                    ),
                    "evidence_sha256": sha256_json(safe_evidence),
                },
                occurred_at=now,
            )

    def create_tool_call(
        self,
        run_id: str,
        *,
        provider_call_id: str,
        tool_name: str,
        tool_spec_sha256: str,
        evidence_grounding: str,
        arguments: dict[str, Any],
        draft_revision: int | None,
        requires_approval: bool,
        harness_version: str,
    ) -> dict[str, Any]:
        call_id = str(uuid.uuid4())
        approval_id = str(uuid.uuid4()) if requires_approval else None
        safe_arguments = sanitize(arguments)
        arguments_hash = sha256_json(safe_arguments)
        now = utc_text()
        with self.repository._transaction() as db:
            run = db.execute(
                "SELECT actor_id, status FROM agent_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise NotFoundError("智能体运行不存在")
            if run["status"] != "running":
                raise ConflictError("智能体运行当前不能创建工具调用")
            sequence_row = db.execute(
                """
                SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence
                FROM agent_tool_calls WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            sequence = int(sequence_row["sequence"])
            db.execute(
                """
                INSERT INTO agent_tool_calls (
                    call_id, run_id, sequence, provider_call_id, tool_name,
                    tool_spec_sha256, evidence_grounding, arguments_json,
                    arguments_sha256, draft_revision, status, approval_id,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    call_id,
                    run_id,
                    sequence,
                    redact_text(provider_call_id, maximum=256),
                    tool_name,
                    tool_spec_sha256,
                    evidence_grounding,
                    canonical_json(safe_arguments),
                    arguments_hash,
                    draft_revision,
                    "waiting_approval" if requires_approval else "planned",
                    approval_id,
                    now,
                ),
            )
            if approval_id is not None:
                db.execute(
                    """
                    INSERT INTO agent_approvals (
                        approval_id, run_id, call_id, arguments_sha256,
                        draft_revision, tool_spec_sha256, harness_version,
                        status, requested_by, requested_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        approval_id,
                        run_id,
                        call_id,
                        arguments_hash,
                        draft_revision,
                        tool_spec_sha256,
                        harness_version,
                        run["actor_id"],
                        now,
                    ),
                )
            self._append_event(
                db,
                run_id=run_id,
                event_type=(
                    "tool_approval_requested"
                    if requires_approval
                    else "tool_call_planned"
                ),
                actor_id=run["actor_id"],
                details={
                    "call_id": call_id,
                    "approval_id": approval_id,
                    "tool_name": tool_name,
                    "tool_spec_sha256": tool_spec_sha256,
                    "evidence_grounding": evidence_grounding,
                    "arguments_sha256": arguments_hash,
                    "draft_revision": draft_revision,
                },
                occurred_at=now,
            )
        return self.tool_call(call_id)

    def tool_call(self, call_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM agent_tool_calls WHERE call_id = ?", (call_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("工具调用不存在")
        return self._tool_call_row(row)

    def mark_tool_running(self, call_id: str) -> bool:
        with self.repository._transaction() as db:
            call = db.execute(
                "SELECT * FROM agent_tool_calls WHERE call_id = ?", (call_id,)
            ).fetchone()
            if call is None or call["status"] not in {"planned", "waiting_approval"}:
                return False
            if call["approval_id"]:
                approval = db.execute(
                    "SELECT status FROM agent_approvals WHERE approval_id = ?",
                    (call["approval_id"],),
                ).fetchone()
                if approval is None or approval["status"] != "approved":
                    return False
            run = db.execute(
                "SELECT * FROM agent_runs WHERE run_id = ?", (call["run_id"],)
            ).fetchone()
            if run["cancel_requested"] or run["status"] != "running":
                return False
            now = utc_text()
            db.execute(
                """
                UPDATE agent_tool_calls SET status = 'running', started_at = ?
                WHERE call_id = ?
                """,
                (now, call_id),
            )
            self._append_event(
                db,
                run_id=call["run_id"],
                event_type="tool_call_started",
                actor_id=run["actor_id"],
                details={
                    "call_id": call_id,
                    "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                },
                occurred_at=now,
            )
        return True

    def finish_tool(
        self,
        call_id: str,
        *,
        result: dict[str, Any] | None = None,
        summary: str = "",
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        now = utc_text()
        safe_result = sanitize(result) if result is not None else None
        encoded = canonical_json(safe_result) if safe_result is not None else None
        status = "succeeded" if error_code is None else "failed"
        with self.repository._transaction() as db:
            call = db.execute(
                "SELECT * FROM agent_tool_calls WHERE call_id = ?", (call_id,)
            ).fetchone()
            if call is None:
                raise NotFoundError("工具调用不存在")
            run = db.execute(
                "SELECT actor_id, status FROM agent_runs WHERE run_id = ?",
                (call["run_id"],),
            ).fetchone()
            if run is None or run["status"] != "running":
                return
            db.execute(
                """
                UPDATE agent_tool_calls
                SET status = ?, result_json = ?, result_sha256 = ?,
                    result_bytes = ?, summary = ?, error_code = ?,
                    error_message = ?, completed_at = ?
                WHERE call_id = ?
                """,
                (
                    status,
                    encoded,
                    sha256_json(safe_result) if safe_result is not None else None,
                    len(encoded.encode("utf-8")) if encoded is not None else 0,
                    redact_text(summary, maximum=2_000) or None,
                    error_code[:128] if error_code else None,
                    (
                        redact_text(error_message, maximum=1_000)
                        if error_message
                        else None
                    ),
                    now,
                    call_id,
                ),
            )
            self._append_event(
                db,
                run_id=call["run_id"],
                event_type=f"tool_call_{status}",
                actor_id=run["actor_id"],
                details={
                    "call_id": call_id,
                    "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                    "result_sha256": (
                        sha256_json(safe_result)
                        if safe_result is not None
                        else None
                    ),
                    "summary_sha256": sha256_json(
                        redact_text(summary, maximum=2_000)
                    ),
                    "error_code": error_code,
                    "error_message_sha256": (
                        sha256_json(
                            redact_text(error_message, maximum=1_000)
                        )
                        if error_message
                        else None
                    ),
                },
                occurred_at=now,
            )

    def reject_tool(self, call_id: str) -> None:
        with self.repository._transaction() as db:
            db.execute(
                """
                UPDATE agent_tool_calls
                SET status = 'rejected', error_code = 'approval_rejected',
                    error_message = '人工拒绝执行该工具', completed_at = ?
                WHERE call_id = ? AND status = 'waiting_approval'
                """,
                (utc_text(), call_id),
            )

    def decide_approval(
        self,
        run_id: str,
        *,
        approval_id: str,
        decision: str,
        actor_id: str,
    ) -> tuple[dict[str, Any], bool]:
        now = utc_text()
        desired = "approved" if decision == "approve" else "rejected"
        with self.repository._transaction() as db:
            row = db.execute(
                """
                SELECT a.*, c.arguments_sha256 AS live_arguments_sha256,
                       c.arguments_json AS live_arguments_json,
                       c.tool_spec_sha256 AS live_tool_spec_sha256,
                       c.draft_revision AS live_draft_revision,
                       r.actor_id AS run_actor, r.status AS run_status
                FROM agent_approvals AS a
                JOIN agent_tool_calls AS c ON c.call_id = a.call_id
                JOIN agent_runs AS r ON r.run_id = a.run_id
                WHERE a.approval_id = ? AND a.run_id = ?
                """,
                (approval_id, run_id),
            ).fetchone()
            if row is None:
                raise NotFoundError("待批准动作不存在")
            try:
                material_hash = sha256_json(
                    json.loads(row["live_arguments_json"])
                )
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise ConflictError("待批准工具参数存储已损坏") from error
            if (
                not hmac.compare_digest(
                    row["arguments_sha256"], material_hash
                )
                or not hmac.compare_digest(
                    row["arguments_sha256"],
                    row["live_arguments_sha256"],
                )
                or not hmac.compare_digest(
                    row["tool_spec_sha256"],
                    row["live_tool_spec_sha256"],
                )
            ):
                raise ConflictError("待批准动作绑定摘要不一致，拒绝执行")
            event_rows = db.execute(
                """
                SELECT details_json FROM agent_run_events
                WHERE run_id = ? AND event_type = 'tool_approval_requested'
                ORDER BY sequence DESC
                """,
                (run_id,),
            ).fetchall()
            binding = next(
                (
                    json.loads(event["details_json"])
                    for event in event_rows
                    if json.loads(event["details_json"]).get("call_id")
                    == row["call_id"]
                ),
                None,
            )
            if (
                binding is None
                or binding.get("approval_id") != approval_id
                or binding.get("arguments_sha256")
                != row["arguments_sha256"]
                or binding.get("tool_spec_sha256")
                != row["tool_spec_sha256"]
                or binding.get("draft_revision") != row["draft_revision"]
            ):
                raise ConflictError("待批准动作与审计事件不一致，拒绝执行")
            if row["status"] != "pending":
                if row["status"] == desired and row["decision"] == decision:
                    return self.get(run_id), False
                raise ConflictError("该动作已经作出不同决定，不能覆盖")
            if row["run_status"] != "waiting_approval":
                raise ConflictError("运行当前不处于待批准状态")
            if (
                row["arguments_sha256"] != row["live_arguments_sha256"]
                or row["draft_revision"] != row["live_draft_revision"]
            ):
                raise ConflictError("待批准动作绑定信息已变化，拒绝执行")
            db.execute(
                """
                UPDATE agent_approvals
                SET status = ?, decision = ?, decided_by = ?, decided_at = ?
                WHERE approval_id = ? AND status = 'pending'
                """,
                (desired, decision, actor_id, now, approval_id),
            )
            if desired == "rejected":
                db.execute(
                    """
                    UPDATE agent_tool_calls
                    SET status = 'rejected', error_code = 'approval_rejected',
                        error_message = '人工拒绝执行该工具',
                        completed_at = ?
                    WHERE call_id = ? AND status = 'waiting_approval'
                    """,
                    (now, row["call_id"]),
                )
            pending = db.execute(
                """
                SELECT COUNT(*) AS amount FROM agent_approvals
                WHERE run_id = ? AND status = 'pending'
                """,
                (run_id,),
            ).fetchone()
            ready = int(pending["amount"]) == 0
            if ready:
                db.execute(
                    """
                    UPDATE agent_runs SET status = 'queued', updated_at = ?
                    WHERE run_id = ? AND status = 'waiting_approval'
                    """,
                    (now, run_id),
                )
            self._append_event(
                db,
                run_id=run_id,
                event_type=f"tool_approval_{desired}",
                actor_id=actor_id,
                details={
                    "approval_id": approval_id,
                    "call_id": row["call_id"],
                    "arguments_sha256": row["arguments_sha256"],
                    "draft_revision": row["draft_revision"],
                    "tool_spec_sha256": row["tool_spec_sha256"],
                    "harness_version": row["harness_version"],
                    "decision": decision,
                    "decided_by": actor_id,
                    "decided_at": now,
                },
                occurred_at=now,
            )
        return self.get(run_id), ready

    def complete(self, run_id: str, *, summary: str, answer: str) -> None:
        self._finish_run(
            run_id,
            status="completed",
            summary=summary,
            answer=answer,
            event_type="run_completed",
        )

    def fail(self, run_id: str, *, code: str, message: str) -> None:
        self._finish_run(
            run_id,
            status="failed",
            summary="任务执行未完成",
            error_code=code,
            error_message=message,
            event_type="run_failed",
        )

    def _finish_run(
        self,
        run_id: str,
        *,
        status: str,
        summary: str,
        event_type: str,
        answer: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        now = utc_text()
        with self.repository._transaction() as db:
            run = db.execute(
                "SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None or run["status"] in TERMINAL_STATUSES:
                return
            db.execute(
                """
                UPDATE agent_runs
                SET status = ?, summary = ?, answer = ?, error_code = ?,
                    error_message = ?, updated_at = ?, completed_at = ?
                WHERE run_id = ?
                """,
                (
                    status,
                    redact_text(summary, maximum=2_000),
                    redact_text(answer, maximum=16_000) if answer else None,
                    error_code[:128] if error_code else None,
                    (
                        redact_text(error_message, maximum=1_000)
                        if error_message
                        else None
                    ),
                    now,
                    now,
                    run_id,
                ),
            )
            self._append_event(
                db,
                run_id=run_id,
                event_type=event_type,
                actor_id=run["actor_id"],
                details={
                    "status": status,
                    "summary_sha256": sha256_json(
                        redact_text(summary, maximum=2_000)
                    ),
                    "answer_sha256": (
                        sha256_json(
                            redact_text(answer, maximum=16_000)
                        )
                        if answer
                        else None
                    ),
                    "error_code": error_code,
                    "error_message_sha256": (
                        sha256_json(
                            redact_text(error_message, maximum=1_000)
                        )
                        if error_message
                        else None
                    ),
                },
                occurred_at=now,
            )

    def cancel(self, run_id: str, *, actor_id: str) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            run = db.execute(
                "SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise NotFoundError("智能体运行不存在")
            if run["status"] in TERMINAL_STATUSES:
                raise ConflictError("已结束的运行不能取消")
            active_calls = db.execute(
                """
                SELECT * FROM agent_tool_calls
                WHERE run_id = ?
                  AND status IN (
                    'planned', 'waiting_approval', 'running'
                  )
                """,
                (run_id,),
            ).fetchall()
            pending_approvals = db.execute(
                """
                SELECT * FROM agent_approvals
                WHERE run_id = ? AND status = 'pending'
                """,
                (run_id,),
            ).fetchall()
            db.execute(
                """
                UPDATE agent_runs
                SET cancel_requested = 1, status = 'cancelled',
                    summary = '已由用户取消', updated_at = ?, completed_at = ?
                WHERE run_id = ?
                """,
                (now, now, run_id),
            )
            closed_calls = db.execute(
                """
                UPDATE agent_tool_calls
                SET status = 'failed', error_code = 'run_cancelled',
                    error_message = '运行已取消，工具结果不再接收',
                    completed_at = ?
                WHERE run_id = ?
                  AND status IN (
                    'planned', 'waiting_approval', 'running'
                  )
                """,
                (now, run_id),
            )
            closed_approvals = db.execute(
                """
                UPDATE agent_approvals
                SET status = 'rejected', decision = 'reject',
                    decided_by = ?, decided_at = ?
                WHERE run_id = ? AND status = 'pending'
                """,
                (actor_id, now, run_id),
            )
            self._append_event(
                db,
                run_id=run_id,
                event_type="run_cancelled",
                actor_id=actor_id,
                details={
                    "status": "cancelled",
                    "summary_sha256": sha256_json("已由用户取消"),
                    "answer_sha256": None,
                    "closed_tool_calls": max(int(closed_calls.rowcount), 0),
                    "closed_approvals": max(
                        int(closed_approvals.rowcount), 0
                    ),
                },
                occurred_at=now,
            )
            for call in active_calls:
                self._append_event(
                    db,
                    run_id=run_id,
                    event_type="tool_call_cancelled",
                    actor_id=actor_id,
                    details={
                        "call_id": call["call_id"],
                        "arguments_sha256": call["arguments_sha256"],
                        "error_code": "run_cancelled",
                    },
                    occurred_at=now,
                )
            for approval in pending_approvals:
                self._append_event(
                    db,
                    run_id=run_id,
                    event_type="tool_approval_rejected",
                    actor_id=actor_id,
                    details={
                        "approval_id": approval["approval_id"],
                        "call_id": approval["call_id"],
                        "arguments_sha256": approval["arguments_sha256"],
                        "draft_revision": approval["draft_revision"],
                        "tool_spec_sha256": approval["tool_spec_sha256"],
                        "harness_version": approval["harness_version"],
                        "decision": "reject",
                        "decided_by": actor_id,
                        "decided_at": now,
                    },
                    occurred_at=now,
                )
        return self.get(run_id)

    def get(self, run_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            run = db.execute(
                "SELECT * FROM agent_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if run is None:
                raise NotFoundError("智能体运行不存在")
            calls = db.execute(
                """
                SELECT * FROM agent_tool_calls
                WHERE run_id = ? ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
            approvals = db.execute(
                """
                SELECT * FROM agent_approvals
                WHERE run_id = ? ORDER BY requested_at, approval_id
                """,
                (run_id,),
            ).fetchall()
            steps = db.execute(
                """
                SELECT * FROM agent_run_steps
                WHERE run_id = ? ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
        return self._public_run(run, calls, approvals, steps)

    def list(
        self, *, actor_id: str, limit: int, offset: int
    ) -> tuple[list[dict[str, Any]], int]:
        with self.repository._read() as db:
            total_row = db.execute(
                "SELECT COUNT(*) AS amount FROM agent_runs WHERE actor_id = ?",
                (actor_id,),
            ).fetchone()
            rows = db.execute(
                """
                SELECT r.*,
                    (
                        SELECT COUNT(*) FROM agent_run_steps AS st
                        WHERE st.run_id = r.run_id
                    ) AS steps_used,
                    (
                        SELECT COUNT(*) FROM agent_tool_calls AS tc
                        WHERE tc.run_id = r.run_id
                    ) AS tool_calls_used,
                    (
                        SELECT COALESCE(SUM(tc.result_bytes), 0)
                        FROM agent_tool_calls AS tc
                        WHERE tc.run_id = r.run_id
                    ) AS result_bytes_used
                FROM agent_runs AS r WHERE r.actor_id = ?
                ORDER BY updated_at DESC, run_id DESC LIMIT ? OFFSET ?
                """,
                (actor_id, limit, offset),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            detail = self.get(str(row["run_id"]))
            items.append(
                {
                    key: value
                    for key, value in detail.items()
                    if key
                    not in {
                        "answer",
                        "steps",
                        "tool_calls",
                        "approvals",
                    }
                }
                | {
                    "answer": None,
                    "steps": [],
                    "tool_calls": [],
                    "approvals": [],
                }
            )
        return items, int(total_row["amount"])

    def checkpoint(self, run_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT checkpoint_json FROM agent_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("智能体运行不存在")
        return json.loads(row["checkpoint_json"])

    def pending_batch_calls(self, run_id: str) -> list[dict[str, Any]]:
        checkpoint = self.checkpoint(run_id)
        call_ids = checkpoint.get("pending_batch", [])
        return [self.tool_call(value) for value in call_ids]

    def integrity(self, run_id: str) -> dict[str, Any]:
        """Verify persisted run evidence and fail closed on malformed data."""

        try:
            return self._integrity_unchecked(run_id)
        except (
            AttributeError,
            IndexError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ):
            return {
                "valid": False,
                "event_count": 0,
                "head_hash": None,
                "anchored_event_count": 0,
                "anchored_head_hash": None,
            }

    def _integrity_unchecked(self, run_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            run = db.execute(
                """
                SELECT * FROM agent_runs
                WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
            rows = db.execute(
                """
                SELECT * FROM agent_run_events
                WHERE run_id = ? ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
            calls = db.execute(
                """
                SELECT call_id, approval_id, tool_name, tool_spec_sha256,
                       evidence_grounding,
                       draft_revision, arguments_json, arguments_sha256,
                       result_json, result_sha256, status, summary,
                       error_code, error_message
                FROM agent_tool_calls WHERE run_id = ?
                """,
                (run_id,),
            ).fetchall()
            approvals = db.execute(
                """
                SELECT * FROM agent_approvals WHERE run_id = ?
                """,
                (run_id,),
            ).fetchall()
            steps = db.execute(
                """
                SELECT * FROM agent_run_steps WHERE run_id = ?
                ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
        previous_hash = "0" * 64
        valid = run is not None and bool(rows)
        for expected, row in enumerate(rows, 1):
            details = json.loads(row["details_json"])
            envelope = {
                "run_id": row["run_id"],
                "sequence": row["sequence"],
                "event_type": row["event_type"],
                "actor_id": row["actor_id"],
                "details": details,
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            if (
                row["sequence"] != expected
                or row["previous_hash"] != previous_hash
                or row["event_hash"] != sha256_json(envelope)
            ):
                valid = False
                break
            previous_hash = row["event_hash"]

        def event_details(
            event_type: str,
            *,
            call_id: str | None = None,
            approval_id: str | None = None,
            sequence: int | None = None,
        ) -> dict[str, Any] | None:
            for event in rows:
                if event["event_type"] != event_type:
                    continue
                details = json.loads(event["details_json"])
                if call_id is not None and details.get("call_id") != call_id:
                    continue
                if (
                    approval_id is not None
                    and details.get("approval_id") != approval_id
                ):
                    continue
                if sequence is not None and details.get("sequence") != sequence:
                    continue
                return details
            return None

        created = event_details("run_created")
        try:
            checkpoint = json.loads(run["checkpoint_json"])
        except (TypeError, json.JSONDecodeError):
            checkpoint = None
        if (
            created is None
            or created.get("mode") != run["mode"]
            or created.get("draft_id") != run["draft_id"]
            or created.get("task_sha256") != sha256_json(run["task_text"])
            or created.get("budgets") != json.loads(run["budgets_json"])
            or not isinstance(checkpoint, dict)
            or (
                "tool_profile" in created
                and created.get("tool_profile")
                != checkpoint.get("tool_profile")
            )
            or (
                "allow_mutations" in created
                and created.get("allow_mutations")
                != checkpoint.get("allow_mutations")
            )
        ):
            valid = False

        for call in calls:
            try:
                arguments_hash = sha256_json(
                    json.loads(call["arguments_json"])
                )
                result_hash = (
                    sha256_json(json.loads(call["result_json"]))
                    if call["result_json"] is not None
                    else None
                )
            except (TypeError, ValueError, json.JSONDecodeError):
                valid = False
                break
            if not hmac.compare_digest(
                str(call["arguments_sha256"]), arguments_hash
            ):
                valid = False
                break
            if (
                call["result_json"] is None
                and call["result_sha256"] is not None
            ) or (
                call["result_json"] is not None
                and (
                    call["result_sha256"] is None
                    or not hmac.compare_digest(
                        str(call["result_sha256"]), str(result_hash)
                    )
                )
            ):
                valid = False
                break
            expected_event_type = (
                "tool_approval_requested"
                if call["approval_id"] is not None
                else "tool_call_planned"
            )
            binding = next(
                (
                    json.loads(event["details_json"])
                    for event in rows
                    if event["event_type"] == expected_event_type
                    and json.loads(event["details_json"]).get("call_id")
                    == call["call_id"]
                ),
                None,
            )
            if (
                binding is None
                or binding.get("arguments_sha256")
                != call["arguments_sha256"]
                or binding.get("tool_spec_sha256")
                != call["tool_spec_sha256"]
                or binding.get("evidence_grounding")
                != call["evidence_grounding"]
                or binding.get("draft_revision") != call["draft_revision"]
            ):
                valid = False
                break
            started = event_details(
                "tool_call_started", call_id=str(call["call_id"])
            )
            if call["status"] in {"running", "succeeded"} and (
                started is None
                or started.get("arguments_sha256")
                != call["arguments_sha256"]
                or started.get("tool_name") != call["tool_name"]
            ):
                valid = False
                break
            if call["status"] in {"succeeded", "failed"}:
                terminal = event_details(
                    f"tool_call_{call['status']}",
                    call_id=str(call["call_id"]),
                )
                cancellation = event_details(
                    "tool_call_cancelled",
                    call_id=str(call["call_id"]),
                )
                closed_by_recovery = any(
                    event_details(kind) is not None
                    for kind in (
                        "run_interrupted",
                        "approval_invalidated_by_restart",
                    )
                )
                if (
                    terminal is None
                    and cancellation is None
                    and not closed_by_recovery
                ):
                    valid = False
                    break
                if cancellation is not None and (
                    cancellation.get("arguments_sha256")
                    != call["arguments_sha256"]
                    or cancellation.get("error_code") != call["error_code"]
                ):
                    valid = False
                    break
                if terminal is not None and (
                    terminal.get("arguments_sha256")
                    != call["arguments_sha256"]
                    or terminal.get("result_sha256")
                    != call["result_sha256"]
                    or terminal.get("summary_sha256")
                    != sha256_json(call["summary"] or "")
                    or terminal.get("error_code") != call["error_code"]
                    or terminal.get("error_message_sha256")
                    != (
                        sha256_json(call["error_message"])
                        if call["error_message"]
                        else None
                    )
                ):
                    valid = False
                    break

        calls_by_id = {str(call["call_id"]): call for call in calls}
        for approval in approvals:
            call = calls_by_id.get(str(approval["call_id"]))
            if (
                call is None
                or call["approval_id"] != approval["approval_id"]
                or approval["arguments_sha256"]
                != call["arguments_sha256"]
                or approval["tool_spec_sha256"]
                != call["tool_spec_sha256"]
                or approval["draft_revision"] != call["draft_revision"]
            ):
                valid = False
                break
            if approval["status"] in {"approved", "rejected"}:
                decision_event = event_details(
                    f"tool_approval_{approval['status']}",
                    call_id=str(approval["call_id"]),
                    approval_id=str(approval["approval_id"]),
                )
                closed_by_restart = event_details(
                    "approval_invalidated_by_restart"
                ) is not None
                if decision_event is None and not closed_by_restart:
                    valid = False
                    break
                if decision_event is not None and (
                    decision_event.get("decision") != approval["decision"]
                    or decision_event.get("decided_by")
                    != approval["decided_by"]
                    or decision_event.get("decided_at")
                    != approval["decided_at"]
                    or decision_event.get("arguments_sha256")
                    != approval["arguments_sha256"]
                    or decision_event.get("tool_spec_sha256")
                    != approval["tool_spec_sha256"]
                    or decision_event.get("draft_revision")
                    != approval["draft_revision"]
                ):
                    valid = False
                    break

        for step in steps:
            recorded = event_details(
                "step_recorded", sequence=int(step["sequence"])
            )
            if (
                recorded is None
                or recorded.get("kind") != step["kind"]
                or recorded.get("status") != step["status"]
                or recorded.get("title_sha256")
                != sha256_json(step["title"])
                or recorded.get("summary_sha256")
                != sha256_json(step["summary"])
                or recorded.get("evidence_sha256")
                != sha256_json(json.loads(step["evidence_json"]))
            ):
                valid = False
                break

        if run["status"] in {"completed", "failed"}:
            terminal_type = (
                "run_completed"
                if run["status"] == "completed"
                else "run_failed"
            )
            terminal = event_details(terminal_type)
            if terminal is None and run["status"] == "failed":
                terminal = event_details("run_interrupted")
            if terminal is None and run["status"] == "failed":
                terminal = event_details("approval_invalidated_by_restart")
            if terminal is None or (
                terminal.get("status") != run["status"]
                or terminal.get("summary_sha256")
                != sha256_json(run["summary"] or "")
                or terminal.get("answer_sha256")
                != (
                    sha256_json(run["answer"]) if run["answer"] else None
                )
                or terminal.get("error_code") != run["error_code"]
                or terminal.get("error_message_sha256")
                != (
                    sha256_json(run["error_message"])
                    if run["error_message"]
                    else None
                )
            ):
                valid = False
        elif run["status"] == "cancelled":
            cancelled = event_details("run_cancelled")
            if (
                cancelled is None
                or cancelled.get("status") != "cancelled"
                or cancelled.get("summary_sha256")
                != sha256_json(run["summary"] or "")
                or run["answer"] is not None
            ):
                valid = False
        elif run["status"] == "waiting_approval":
            waiting_sequences = [
                int(event["sequence"])
                for event in rows
                if event["event_type"] == "run_waiting_approval"
            ]
            started_sequences = [
                int(event["sequence"])
                for event in rows
                if event["event_type"] == "run_started"
            ]
            if (
                not waiting_sequences
                or (
                    started_sequences
                    and max(waiting_sequences) < max(started_sequences)
                )
                or not any(
                    approval["status"] == "pending"
                    for approval in approvals
                )
            ):
                valid = False
        elif run["status"] == "running":
            waiting_sequences = [
                int(event["sequence"])
                for event in rows
                if event["event_type"] == "run_waiting_approval"
            ]
            started_sequences = [
                int(event["sequence"])
                for event in rows
                if event["event_type"] == "run_started"
            ]
            if (
                not started_sequences
                or (
                    waiting_sequences
                    and max(started_sequences) < max(waiting_sequences)
                )
            ):
                valid = False
        elif run["status"] == "queued":
            if approvals and (
                any(approval["status"] == "pending" for approval in approvals)
                or not any(
                    event["event_type"]
                    in {
                        "tool_approval_approved",
                        "tool_approval_rejected",
                    }
                    for event in rows
                )
            ):
                valid = False
        anchored_count = int(run["event_count"]) if run is not None else 0
        anchored_head = str(run["event_head_hash"]) if run is not None else ""
        if (
            anchored_count != len(rows)
            or not hmac.compare_digest(anchored_head, previous_hash)
        ):
            valid = False
        return {
            "valid": valid,
            "event_count": len(rows),
            "head_hash": previous_hash if rows else None,
            "anchored_event_count": anchored_count,
            "anchored_head_hash": anchored_head or None,
        }

    @staticmethod
    def _tool_call_row(row: Any) -> dict[str, Any]:
        return {
            "call_id": row["call_id"],
            "sequence": row["sequence"],
            "provider_call_id": row["provider_call_id"],
            "tool_name": row["tool_name"],
            "tool_spec_sha256": row["tool_spec_sha256"],
            "evidence_grounding": row["evidence_grounding"],
            "arguments": json.loads(row["arguments_json"]),
            "arguments_sha256": row["arguments_sha256"],
            "draft_revision": row["draft_revision"],
            "status": row["status"],
            "result": (
                json.loads(row["result_json"])
                if row["result_json"] is not None
                else None
            ),
            "result_sha256": row["result_sha256"],
            "result_bytes": row["result_bytes"],
            "summary": row["summary"],
            "approval_id": row["approval_id"],
            "error": (
                {
                    "code": row["error_code"],
                    "message": row["error_message"],
                }
                if row["error_code"]
                else None
            ),
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }

    def _public_run(
        self, run: Any, calls: list[Any], approvals: list[Any], steps: list[Any]
    ) -> dict[str, Any]:
        integrity = self.integrity(str(run["run_id"]))
        if not integrity["valid"]:
            return {
                "run_id": run["run_id"],
                "actor_id": run["actor_id"],
                "draft_id": run["draft_id"],
                "task": "[审计完整性失败，内容已隐藏]",
                "mode": run["mode"],
                "status": run["status"],
                "summary": "运行审计完整性校验失败，所有业务内容均不可采信",
                "answer": None,
                "error": {
                    "code": "run_integrity_failed",
                    "message": "检测到运行记录或证据被修改，已隐藏内容并禁止操作",
                },
                "budgets": {},
                "steps": [],
                "tool_calls": [],
                "approvals": [],
                "integrity": integrity,
                "actionable": False,
                "created_at": run["created_at"],
                "updated_at": run["updated_at"],
                "completed_at": run["completed_at"],
            }
        budgets = json.loads(run["budgets_json"])
        call_items = [self._tool_call_row(row) for row in calls]
        budgets.update(
            {
                "steps_used": len(steps),
                "tool_calls_used": len(calls),
                "result_bytes_used": sum(row["result_bytes"] for row in calls),
                "active_duration_seconds": round(
                    int(run["active_duration_ms"]) / 1000, 3
                ),
            }
        )
        return {
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "draft_id": run["draft_id"],
            "task": run["task_text"],
            "mode": run["mode"],
            "status": run["status"],
            "summary": run["summary"],
            "answer": run["answer"],
            "error": (
                {
                    "code": run["error_code"],
                    "message": run["error_message"],
                }
                if run["error_code"]
                else None
            ),
            "budgets": budgets,
            "steps": [
                {
                    "sequence": row["sequence"],
                    "kind": row["kind"],
                    "status": row["status"],
                    "title": row["title"],
                    "summary": row["summary"],
                    "evidence": json.loads(row["evidence_json"]),
                    "created_at": row["created_at"],
                }
                for row in steps
            ],
            "tool_calls": call_items,
            "approvals": [
                {
                    "approval_id": row["approval_id"],
                    "call_id": row["call_id"],
                    "arguments_sha256": row["arguments_sha256"],
                    "draft_revision": row["draft_revision"],
                    "tool_spec_sha256": row["tool_spec_sha256"],
                    "harness_version": row["harness_version"],
                    "status": row["status"],
                    "requested_by": row["requested_by"],
                    "requested_at": row["requested_at"],
                    "decision": row["decision"],
                    "decided_by": row["decided_by"],
                    "decided_at": row["decided_at"],
                }
                for row in approvals
            ],
            "integrity": integrity,
            "actionable": True,
            "created_at": run["created_at"],
            "updated_at": run["updated_at"],
            "completed_at": run["completed_at"],
        }

    @staticmethod
    def _summary_row(run: Any) -> dict[str, Any]:
        budgets = json.loads(run["budgets_json"])
        budgets.update(
            {
                "steps_used": int(run["steps_used"]),
                "tool_calls_used": int(run["tool_calls_used"]),
                "result_bytes_used": int(run["result_bytes_used"]),
                "active_duration_seconds": round(
                    int(run["active_duration_ms"]) / 1000, 3
                ),
            }
        )
        return {
            "run_id": run["run_id"],
            "actor_id": run["actor_id"],
            "draft_id": run["draft_id"],
            "task": run["task_text"],
            "mode": run["mode"],
            "status": run["status"],
            "summary": run["summary"],
            "answer": None,
            "error": (
                {
                    "code": run["error_code"],
                    "message": run["error_message"],
                }
                if run["error_code"]
                else None
            ),
            "budgets": budgets,
            "steps": [],
            "tool_calls": [],
            "approvals": [],
            "created_at": run["created_at"],
            "updated_at": run["updated_at"],
            "completed_at": run["completed_at"],
        }
