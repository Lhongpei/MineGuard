"""Durable SQLite state and tamper-evident events for Agent V2 flows."""

from __future__ import annotations

import hmac
import json
import uuid
from datetime import datetime, timedelta
from typing import Any

from enterprise_agent.errors import ConflictError, NotFoundError
from enterprise_agent.harness.sanitize import redact_text, sanitize
from enterprise_agent.storage import Repository
from enterprise_agent.util import (
    canonical_json,
    sha256_json,
    utc_now,
    utc_text,
)

from .models import (
    RETRYABLE_FLOW_STATUSES,
    TERMINAL_FLOW_STATUSES,
    FlowRuntimeConfig,
)

_ZERO_HASH = "0" * 64
_MAX_STEP_JSON_BYTES = 512 * 1024
_MAX_STATE_JSON_BYTES = 2 * 1024 * 1024


def _json_or(value: Any, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        return fallback


def _lease_text(seconds: int) -> str:
    return utc_text(utc_now() + timedelta(seconds=seconds))


def _flow_control_payload(flow: Any) -> dict[str, Any]:
    """Fields controlled by transitions, excluding the event-chain anchors."""

    return {
        name: flow[name]
        for name in (
            "flow_id",
            "actor_id",
            "workflow_name",
            "workflow_version",
            "draft_id",
            "goal_text",
            "status",
            "trigger_type",
            "trigger_ref",
            "client_request_id",
            "state_json",
            "current_step",
            "attempt",
            "dispatch_ready",
            "run_owner",
            "lease_expires_at",
            "revision",
            "cancel_requested",
            "summary",
            "error_code",
            "error_message",
            "created_at",
            "updated_at",
            "started_at",
            "completed_at",
        )
    }


def _safe_json(
    value: Any,
    *,
    name: str,
    maximum_bytes: int,
) -> tuple[Any, str]:
    material = sanitize(value)
    encoded = canonical_json(material)
    if len(encoded.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{name} 超过持久化大小上限")
    return material, encoded


class AgentFlowStore:
    """Persistence boundary shared by HTTP, workers and the scheduler."""

    def __init__(
        self,
        repository: Repository,
        *,
        config: FlowRuntimeConfig | None = None,
    ):
        self.repository = repository
        self.config = config or FlowRuntimeConfig()

    def _assert_integrity_in_transaction(
        self,
        db: Any,
        flow: Any,
    ) -> None:
        steps = db.execute(
            """
            SELECT * FROM agent_flow_steps
            WHERE flow_id = ?
            ORDER BY sequence
            """,
            (flow["flow_id"],),
        ).fetchall()
        events = db.execute(
            """
            SELECT * FROM agent_flow_events
            WHERE flow_id = ?
            ORDER BY sequence
            """,
            (flow["flow_id"],),
        ).fetchall()
        integrity = self._verify_integrity(flow, steps, events)
        if not integrity["valid"]:
            raise ConflictError(
                "智能体任务完整性校验失败，拒绝改变任务状态"
            )

    def _verified_active_count_in_transaction(
        self,
        db: Any,
        *,
        actor_id: str | None = None,
    ) -> int:
        where = "status IN ('queued', 'running')"
        params: tuple[Any, ...] = ()
        if actor_id is not None:
            where += " AND actor_id = ?"
            params = (actor_id,)
        rows = db.execute(
            f"SELECT * FROM agent_flows WHERE {where}",
            params,
        ).fetchall()
        verified = 0
        for row in rows:
            try:
                self._assert_integrity_in_transaction(db, row)
            except ConflictError:
                continue
            verified += 1
        return verified

    def _assert_active_capacity_in_transaction(
        self,
        db: Any,
        *,
        actor_id: str,
    ) -> None:
        actor_active = self._verified_active_count_in_transaction(
            db,
            actor_id=actor_id,
        )
        if actor_active >= self.config.actor_active_limit:
            raise ConflictError(
                "当前账号未结束的智能体任务过多，请先处理或取消"
            )
        global_active = self._verified_active_count_in_transaction(db)
        if global_active >= self.config.global_active_limit:
            raise ConflictError("智能体任务队列已满，请稍后再试")

    @staticmethod
    def _append_event(
        db: Any,
        *,
        flow_id: str,
        event_type: str,
        actor_id: str,
        details: dict[str, Any],
        occurred_at: str | None = None,
    ) -> None:
        now = occurred_at or utc_text()
        previous = db.execute(
            """
            SELECT sequence, event_hash
            FROM agent_flow_events
            WHERE flow_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (flow_id,),
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = str(previous["event_hash"]) if previous else _ZERO_HASH
        anchor = db.execute(
            """
            SELECT event_count, event_head_hash
            FROM agent_flows
            WHERE flow_id = ?
            """,
            (flow_id,),
        ).fetchone()
        if (
            anchor is None
            or int(anchor["event_count"]) != sequence - 1
            or not hmac.compare_digest(
                str(anchor["event_head_hash"]), previous_hash
            )
        ):
            raise ConflictError("智能体任务审计锚点不一致，拒绝继续写入")
        flow = db.execute(
            "SELECT * FROM agent_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
        if flow is None:
            raise NotFoundError("智能体任务不存在")
        details = {
            **details,
            "flow_control_sha256": sha256_json(_flow_control_payload(flow)),
        }
        safe_details, details_json = _safe_json(
            details,
            name="事件详情",
            maximum_bytes=128 * 1024,
        )
        envelope = {
            "flow_id": flow_id,
            "sequence": sequence,
            "event_type": event_type,
            "actor_id": actor_id,
            "details": safe_details,
            "occurred_at": now,
            "previous_hash": previous_hash,
        }
        event_hash = sha256_json(envelope)
        db.execute(
            """
            INSERT INTO agent_flow_events (
                flow_id, sequence, event_type, actor_id, details_json,
                occurred_at, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                flow_id,
                sequence,
                event_type,
                actor_id,
                details_json,
                now,
                previous_hash,
                event_hash,
            ),
        )
        db.execute(
            """
            UPDATE agent_flows
            SET event_count = ?, event_head_hash = ?
            WHERE flow_id = ?
            """,
            (sequence, event_hash, flow_id),
        )

    def create_flow(
        self,
        *,
        actor_id: str,
        workflow_name: str,
        workflow_version: str,
        draft_id: str,
        goal_text: str,
        trigger_type: str,
        trigger_ref: str | None,
        client_request_id: str | None,
        dispatch_ready: bool = True,
    ) -> tuple[dict[str, Any], bool]:
        """Create once per actor/client request and detect conflicting reuse."""

        flow_id = str(uuid.uuid4())
        now = utc_text()
        safe_goal = redact_text(goal_text, maximum=4_000)
        safe_trigger_ref = (
            redact_text(trigger_ref, maximum=256)
            if trigger_ref is not None
            else None
        )
        with self.repository._transaction() as db:
            self.repository._assert_active_draft_in_transaction(
                db,
                draft_id,
            )
            if client_request_id is not None:
                previous = db.execute(
                    """
                    SELECT * FROM agent_flows
                    WHERE actor_id = ? AND client_request_id = ?
                    """,
                    (actor_id, client_request_id),
                ).fetchone()
                if previous is not None:
                    self._assert_integrity_in_transaction(db, previous)
                    expected = (
                        workflow_name,
                        workflow_version,
                        draft_id,
                        safe_goal,
                        trigger_type,
                        safe_trigger_ref,
                    )
                    actual = tuple(
                        previous[name]
                        for name in (
                            "workflow_name",
                            "workflow_version",
                            "draft_id",
                            "goal_text",
                            "trigger_type",
                            "trigger_ref",
                        )
                    )
                    if actual != expected:
                        raise ConflictError(
                            "client_request_id 已用于不同的智能体任务"
                        )
                    existing_id = str(previous["flow_id"])
                    created = False
                else:
                    existing_id = ""
                    created = True
            else:
                existing_id = ""
                created = True

            if created:
                self._assert_active_capacity_in_transaction(
                    db,
                    actor_id=actor_id,
                )
                db.execute(
                    """
                    INSERT INTO agent_flows (
                        flow_id, actor_id, workflow_name, workflow_version,
                        draft_id, goal_text, status, trigger_type, trigger_ref,
                        client_request_id, state_json, current_step, attempt,
                        dispatch_ready, revision, cancel_requested,
                        summary, error_code,
                        error_message, event_count, event_head_hash,
                        created_at, updated_at, started_at, completed_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, '{}', NULL, 1,
                        ?, 1, 0, NULL, NULL, NULL, 0, ?, ?, ?, NULL, NULL
                    )
                    """,
                    (
                        flow_id,
                        actor_id,
                        workflow_name,
                        workflow_version,
                        draft_id,
                        safe_goal,
                        trigger_type,
                        safe_trigger_ref,
                        client_request_id,
                        int(dispatch_ready),
                        _ZERO_HASH,
                        now,
                        now,
                    ),
                )
                self._append_event(
                    db,
                    flow_id=flow_id,
                    event_type="flow_created",
                    actor_id=actor_id,
                    details={
                        "workflow_name": workflow_name,
                        "workflow_version": workflow_version,
                        "draft_id": draft_id,
                        "goal_sha256": sha256_json(safe_goal),
                        "trigger_type": trigger_type,
                        "trigger_ref": safe_trigger_ref,
                        "client_request_id": client_request_id,
                        "initial_dispatch_ready": dispatch_ready,
                        "state_sha256": sha256_json({}),
                    },
                    occurred_at=now,
                )
                existing_id = flow_id
        return self.get(existing_id), created

    def find_by_client_request(
        self,
        *,
        actor_id: str,
        client_request_id: str,
    ) -> dict[str, Any] | None:
        """Resolve one integrity-verified idempotent request without re-creating it."""

        with self.repository._read() as db:
            db.execute("BEGIN")
            try:
                row = db.execute(
                    """
                    SELECT flow_id FROM agent_flows
                    WHERE actor_id = ? AND client_request_id = ?
                    """,
                    (actor_id, client_request_id),
                ).fetchone()
                if row is None:
                    db.execute("COMMIT")
                    return None
                result = self._get_in_transaction(db, str(row["flow_id"]))
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def claim(
        self,
        flow_id: str,
        *,
        owner_id: str,
    ) -> bool:
        now = utc_text()
        lease_expires_at = _lease_text(self.config.lease_seconds)
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if (
                row is None
                or row["status"] != "queued"
                or bool(row["cancel_requested"])
                or not bool(row["dispatch_ready"])
            ):
                return False
            self._assert_integrity_in_transaction(db, row)
            changed = db.execute(
                """
                UPDATE agent_flows
                SET status = 'running',
                    started_at = COALESCE(started_at, ?),
                    run_owner = ?, lease_expires_at = ?,
                    updated_at = ?,
                    revision = revision + 1
                WHERE flow_id = ? AND status = 'queued'
                  AND cancel_requested = 0 AND dispatch_ready = 1
                """,
                (
                    now,
                    owner_id,
                    lease_expires_at,
                    now,
                    flow_id,
                ),
            )
            if changed.rowcount != 1:
                return False
            self._append_event(
                db,
                flow_id=flow_id,
                event_type="flow_started",
                actor_id=str(row["actor_id"]),
                details={
                    "attempt": int(row["attempt"]),
                    "owner_id": owner_id,
                    "lease_expires_at": lease_expires_at,
                },
                occurred_at=now,
            )
        return True

    def authorize_dispatch_in_transaction(
        self,
        db: Any,
        flow_id: str,
        *,
        actor_id: str,
    ) -> bool:
        """Atomically make a deferred scheduler flow eligible for workers."""

        flow = db.execute(
            "SELECT * FROM agent_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
        if flow is None:
            raise NotFoundError("智能体任务不存在")
        self._assert_integrity_in_transaction(db, flow)
        if bool(flow["dispatch_ready"]):
            return False
        if flow["status"] != "queued" or bool(flow["cancel_requested"]):
            raise ConflictError("延迟派发任务当前不能授权执行")
        now = utc_text()
        changed = db.execute(
            """
            UPDATE agent_flows
            SET dispatch_ready = 1, revision = revision + 1,
                updated_at = ?
            WHERE flow_id = ? AND status = 'queued'
              AND dispatch_ready = 0 AND cancel_requested = 0
            """,
            (now, flow_id),
        )
        if changed.rowcount != 1:
            raise ConflictError("延迟派发任务状态已经变化")
        self._append_event(
            db,
            flow_id=flow_id,
            event_type="flow_dispatch_authorized",
            actor_id=actor_id,
            details={"dispatch_ready": True},
            occurred_at=now,
        )
        return True

    def abandon_deferred(
        self,
        flow_id: str,
        *,
        actor_id: str,
        reason_code: str = "dispatch_aborted",
    ) -> bool:
        """Safely terminate a scheduler flow that was never dispatchable.

        This is intentionally narrower than ordinary cancellation: an already
        authorized or claimed flow is never touched, so a losing scheduler
        process cannot cancel the winner's idempotent launch.
        """

        with self.repository._transaction() as db:
            flow = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if flow is None:
                return False
            if str(flow["actor_id"]) != actor_id:
                raise NotFoundError("智能体任务不存在")
            self._assert_integrity_in_transaction(db, flow)
            return self._abandon_deferred_in_transaction(
                db,
                flow,
                actor_id=actor_id,
                reason_code=reason_code,
                occurred_at=utc_text(),
            )

    def reopen_abandoned_deferred_in_transaction(
        self,
        db: Any,
        flow_id: str,
        *,
        actor_id: str,
    ) -> bool:
        """Reopen only a never-dispatched scheduler/event orphan for exact replay."""

        flow = db.execute(
            "SELECT * FROM agent_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
        if flow is None or str(flow["actor_id"]) != actor_id:
            raise NotFoundError("智能体任务不存在")
        self._assert_integrity_in_transaction(db, flow)
        if (
            str(flow["status"]) != "cancelled"
            or bool(flow["dispatch_ready"])
            or not bool(flow["cancel_requested"])
            or flow["started_at"] is not None
            or str(flow["error_code"])
            not in {
                "dispatch_authorization_expired",
                "scheduler_launch_aborted",
            }
        ):
            return False
        step_count = int(
            db.execute(
                """
                SELECT COUNT(*) AS amount FROM agent_flow_steps
                WHERE flow_id = ?
                """,
                (flow_id,),
            ).fetchone()["amount"]
        )
        if step_count:
            return False
        self._assert_active_capacity_in_transaction(
            db,
            actor_id=actor_id,
        )
        now = utc_text()
        changed = db.execute(
            """
            UPDATE agent_flows
            SET status = 'queued', cancel_requested = 0,
                summary = NULL, error_code = NULL, error_message = NULL,
                run_owner = NULL, lease_expires_at = NULL,
                started_at = NULL, completed_at = NULL,
                updated_at = ?, revision = revision + 1
            WHERE flow_id = ? AND status = 'cancelled'
              AND dispatch_ready = 0 AND cancel_requested = 1
            """,
            (now, flow_id),
        )
        if changed.rowcount != 1:
            return False
        self._append_event(
            db,
            flow_id=flow_id,
            event_type="flow_dispatch_reopened",
            actor_id=actor_id,
            details={
                "previous_error_code": str(flow["error_code"]),
                "dispatch_ready": False,
                "state_sha256": sha256_json({}),
                "owner_id": None,
                "lease_expires_at": None,
            },
            occurred_at=now,
        )
        return True

    def _abandon_deferred_in_transaction(
        self,
        db: Any,
        flow: Any,
        *,
        actor_id: str,
        reason_code: str,
        occurred_at: str,
    ) -> bool:
        if (
            str(flow["status"]) != "queued"
            or bool(flow["dispatch_ready"])
            or bool(flow["cancel_requested"])
        ):
            return False
        safe_reason = redact_text(reason_code, maximum=128)
        summary = "任务在派发前安全终止，未执行任何业务工具"
        changed = db.execute(
            """
            UPDATE agent_flows
            SET status = 'cancelled', cancel_requested = 1,
                summary = ?, error_code = ?, error_message = NULL,
                run_owner = NULL, lease_expires_at = NULL,
                updated_at = ?, completed_at = ?, revision = revision + 1
            WHERE flow_id = ? AND status = 'queued'
              AND dispatch_ready = 0 AND cancel_requested = 0
            """,
            (
                summary,
                safe_reason,
                occurred_at,
                occurred_at,
                flow["flow_id"],
            ),
        )
        if changed.rowcount != 1:
            return False
        self._append_event(
            db,
            flow_id=str(flow["flow_id"]),
            event_type="flow_cancelled",
            actor_id=actor_id,
            details={
                "immediate": True,
                "dispatch_aborted": True,
                "reason_code": safe_reason,
                "state_sha256": sha256_json(
                    _json_or(flow["state_json"], {})
                ),
                "summary_sha256": sha256_json(summary),
                "error_code": safe_reason,
                "error_message_sha256": None,
                "owner_id": None,
                "lease_expires_at": None,
            },
            occurred_at=occurred_at,
        )
        return True

    @staticmethod
    def _deferred_has_pending_parent(
        db: Any,
        flow: Any,
        *,
        event_parent_cutoff: str,
    ) -> bool:
        trigger_type = str(flow["trigger_type"])
        trigger_ref = flow["trigger_ref"]
        if trigger_type == "schedule" and trigger_ref:
            parent = db.execute(
                """
                SELECT 1 FROM agent_jobs
                WHERE job_id = ? AND actor_id = ?
                  AND deleted_at IS NULL AND pending_run_at IS NOT NULL
                """,
                (trigger_ref, flow["actor_id"]),
            ).fetchone()
            return parent is not None
        if trigger_type == "event" and trigger_ref:
            if str(flow["created_at"]) <= event_parent_cutoff:
                # Incomplete event parents are normally resumed by the
                # scheduler. A corrupt or permanently unreachable parent must
                # not reserve actor capacity forever.
                return False
            parent = db.execute(
                """
                SELECT triggered_jobs_json
                FROM agent_trigger_events
                WHERE event_id = ? AND actor_id = ?
                """,
                (trigger_ref, flow["actor_id"]),
            ).fetchone()
            if parent is None:
                return False
            progress = _json_or(parent["triggered_jobs_json"], {})
            return (
                isinstance(progress, dict)
                and progress.get("completed") is False
            )
        return False

    def start_step(
        self,
        flow_id: str,
        *,
        step_key: str,
        specialist: str,
        step_input: dict[str, Any],
        owner_id: str,
        attempt: int,
    ) -> int:
        now = utc_text()
        lease_expires_at = _lease_text(self.config.lease_seconds)
        _safe_input, input_json = _safe_json(
            step_input,
            name="步骤输入",
            maximum_bytes=_MAX_STEP_JSON_BYTES,
        )
        with self.repository._transaction() as db:
            flow = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if flow is None:
                raise NotFoundError("智能体任务不存在")
            self._assert_integrity_in_transaction(db, flow)
            if (
                flow["status"] != "running"
                or bool(flow["cancel_requested"])
                or flow["run_owner"] != owner_id
                or int(flow["attempt"]) != int(attempt)
            ):
                raise ConflictError("智能体任务当前不能开始新步骤")
            sequence = int(
                db.execute(
                    """
                    SELECT COALESCE(MAX(sequence), 0) + 1 AS sequence
                    FROM agent_flow_steps
                    WHERE flow_id = ?
                    """,
                    (flow_id,),
                ).fetchone()["sequence"]
            )
            try:
                db.execute(
                    """
                    INSERT INTO agent_flow_steps (
                        flow_id, sequence, attempt, step_key, specialist,
                        status, input_json, result_json, result_sha256,
                        error_code, error_message, started_at, completed_at
                    ) VALUES (?, ?, ?, ?, ?, 'running', ?, NULL, NULL,
                              NULL, NULL, ?, NULL)
                    """,
                    (
                        flow_id,
                        sequence,
                        int(attempt),
                        step_key,
                        specialist,
                        input_json,
                        now,
                    ),
                )
            except Exception as error:
                # The uniqueness constraint is a safety invariant, not a signal
                # to silently reuse an ambiguous in-flight execution.
                if "UNIQUE constraint failed" in str(error):
                    raise ConflictError("当前步骤在本次尝试中已经执行") from error
                raise
            changed = db.execute(
                """
                UPDATE agent_flows
                SET current_step = ?, updated_at = ?, lease_expires_at = ?,
                    revision = revision + 1
                WHERE flow_id = ? AND run_owner = ? AND attempt = ?
                """,
                (
                    step_key,
                    now,
                    lease_expires_at,
                    flow_id,
                    owner_id,
                    int(attempt),
                ),
            )
            if changed.rowcount != 1:
                raise ConflictError("智能体任务执行租约已经变化")
            self._append_event(
                db,
                flow_id=flow_id,
                event_type="flow_step_started",
                actor_id=str(flow["actor_id"]),
                details={
                    "sequence": sequence,
                    "attempt": int(attempt),
                    "step_key": step_key,
                    "specialist": specialist,
                    "input_sha256": sha256_json(_safe_input),
                    "owner_id": owner_id,
                    "lease_expires_at": lease_expires_at,
                },
                occurred_at=now,
            )
        return sequence

    def finish_step(
        self,
        flow_id: str,
        sequence: int,
        *,
        status: str,
        result: dict[str, Any] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        owner_id: str,
        attempt: int,
    ) -> None:
        if status not in {"succeeded", "failed", "cancelled"}:
            raise ValueError("步骤完成状态不受支持")
        safe_result: Any | None = None
        result_json: str | None = None
        result_hash: str | None = None
        if result is not None:
            safe_result, result_json = _safe_json(
                result,
                name="步骤结果",
                maximum_bytes=_MAX_STEP_JSON_BYTES,
            )
            result_hash = sha256_json(safe_result)
        now = utc_text()
        lease_expires_at = _lease_text(self.config.lease_seconds)
        safe_error = (
            redact_text(error_message, maximum=2_000)
            if error_message is not None
            else None
        )
        with self.repository._transaction() as db:
            flow = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if flow is None:
                raise NotFoundError("智能体任务不存在")
            self._assert_integrity_in_transaction(db, flow)
            if (
                flow["status"] != "running"
                or flow["run_owner"] != owner_id
                or int(flow["attempt"]) != int(attempt)
            ):
                raise ConflictError("智能体任务执行租约已经变化")
            changed = db.execute(
                """
                UPDATE agent_flow_steps
                SET status = ?, result_json = ?, result_sha256 = ?,
                    error_code = ?, error_message = ?, completed_at = ?
                WHERE flow_id = ? AND sequence = ? AND attempt = ?
                  AND status = 'running'
                """,
                (
                    status,
                    result_json,
                    result_hash,
                    error_code,
                    safe_error,
                    now,
                    flow_id,
                    int(sequence),
                    int(attempt),
                ),
            )
            if changed.rowcount != 1:
                raise ConflictError("智能体步骤不存在或已经结束")
            lease_changed = db.execute(
                """
                UPDATE agent_flows
                SET updated_at = ?, lease_expires_at = ?,
                    revision = revision + 1
                WHERE flow_id = ? AND status = 'running'
                  AND run_owner = ? AND attempt = ?
                """,
                (
                    now,
                    lease_expires_at,
                    flow_id,
                    owner_id,
                    int(attempt),
                ),
            )
            if lease_changed.rowcount != 1:
                raise ConflictError("智能体任务执行租约已经变化")
            self._append_event(
                db,
                flow_id=flow_id,
                event_type=f"flow_step_{status}",
                actor_id=str(flow["actor_id"]),
                details={
                    "sequence": int(sequence),
                    "attempt": int(attempt),
                    "result_sha256": result_hash,
                    "error_code": error_code,
                    "error_message_sha256": (
                        sha256_json(safe_error) if safe_error else None
                    ),
                    "owner_id": owner_id,
                    "lease_expires_at": lease_expires_at,
                },
                occurred_at=now,
            )

    def complete(
        self,
        flow_id: str,
        *,
        status: str,
        state: dict[str, Any],
        summary: str,
        error_code: str | None = None,
        error_message: str | None = None,
        actor_id: str | None = None,
        owner_id: str,
        attempt: int,
    ) -> dict[str, Any]:
        if status not in TERMINAL_FLOW_STATUSES:
            raise ValueError("任务完成状态不受支持")
        _safe_state, state_json = _safe_json(
            state,
            name="任务状态",
            maximum_bytes=_MAX_STATE_JSON_BYTES,
        )
        safe_summary = redact_text(summary, maximum=4_000)
        safe_error = (
            redact_text(error_message, maximum=2_000)
            if error_message is not None
            else None
        )
        now = utc_text()
        with self.repository._transaction() as db:
            flow = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if flow is None:
                raise NotFoundError("智能体任务不存在")
            self._assert_integrity_in_transaction(db, flow)
            if flow["status"] in TERMINAL_FLOW_STATUSES:
                if flow["status"] == status:
                    return self._get_in_transaction(db, flow_id)
                raise ConflictError("智能体任务已经结束")
            if flow["status"] != "running":
                raise ConflictError("智能体任务当前不能结束")
            if (
                flow["run_owner"] != owner_id
                or int(flow["attempt"]) != int(attempt)
            ):
                raise ConflictError("智能体任务执行租约已经变化")
            actual_status = (
                "cancelled" if bool(flow["cancel_requested"]) else status
            )
            actual_summary = (
                "任务已按用户要求取消"
                if actual_status == "cancelled"
                else safe_summary
            )
            actual_error_code = (
                None if actual_status == "cancelled" else error_code
            )
            actual_error = None if actual_status == "cancelled" else safe_error
            db.execute(
                """
                UPDATE agent_flows
                SET status = ?, state_json = ?, current_step = NULL,
                    summary = ?, error_code = ?, error_message = ?,
                    run_owner = NULL, lease_expires_at = NULL,
                    updated_at = ?, completed_at = ?, revision = revision + 1
                WHERE flow_id = ? AND status = 'running'
                  AND run_owner = ? AND attempt = ?
                """,
                (
                    actual_status,
                    state_json,
                    actual_summary,
                    actual_error_code,
                    actual_error,
                    now,
                    now,
                    flow_id,
                    owner_id,
                    int(attempt),
                ),
            )
            if db.execute("SELECT changes() AS amount").fetchone()["amount"] != 1:
                raise ConflictError("智能体任务执行租约已经变化")
            self._append_event(
                db,
                flow_id=flow_id,
                event_type=f"flow_{actual_status}",
                actor_id=actor_id or str(flow["actor_id"]),
                details={
                    "attempt": int(attempt),
                    "summary_sha256": sha256_json(actual_summary),
                    "state_sha256": sha256_json(_safe_state),
                    "error_code": actual_error_code,
                    "error_message_sha256": (
                        sha256_json(actual_error) if actual_error else None
                    ),
                    "owner_id": owner_id,
                    "lease_expires_at": None,
                },
                occurred_at=now,
            )
        return self.get(flow_id)

    def request_cancel(
        self,
        flow_id: str,
        *,
        actor_id: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            flow = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if flow is None or flow["actor_id"] != actor_id:
                raise NotFoundError("智能体任务不存在")
            self._assert_integrity_in_transaction(db, flow)
            if flow["status"] == "cancelled" or (
                flow["status"] == "running"
                and bool(flow["cancel_requested"])
            ):
                return self._get_in_transaction(db, flow_id)
            if (
                expected_revision is not None
                and int(flow["revision"]) != int(expected_revision)
            ):
                raise ConflictError("智能体任务版本已变化，请刷新后重试")
            if flow["status"] in TERMINAL_FLOW_STATUSES:
                raise ConflictError("已经结束的智能体任务不能取消")
            immediate = flow["status"] == "queued"
            db.execute(
                """
                UPDATE agent_flows
                SET cancel_requested = 1,
                    status = CASE WHEN status = 'queued'
                                  THEN 'cancelled' ELSE status END,
                    summary = CASE WHEN status = 'queued'
                                   THEN '任务在执行前已取消' ELSE summary END,
                    completed_at = CASE WHEN status = 'queued'
                                        THEN ? ELSE completed_at END,
                    run_owner = CASE WHEN status = 'queued'
                                     THEN NULL ELSE run_owner END,
                    lease_expires_at = CASE WHEN status = 'queued'
                                            THEN NULL
                                            ELSE lease_expires_at END,
                    updated_at = ?, revision = revision + 1
                WHERE flow_id = ?
                """,
                (now, now, flow_id),
            )
            self._append_event(
                db,
                flow_id=flow_id,
                event_type=(
                    "flow_cancelled" if immediate else "flow_cancel_requested"
                ),
                actor_id=actor_id,
                details={
                    "immediate": immediate,
                    "state_sha256": (
                        sha256_json(_json_or(flow["state_json"], {}))
                        if immediate
                        else None
                    ),
                    "summary_sha256": (
                        sha256_json("任务在执行前已取消")
                        if immediate
                        else None
                    ),
                    "owner_id": None if immediate else flow["run_owner"],
                    "lease_expires_at": (
                        None if immediate else flow["lease_expires_at"]
                    ),
                },
                occurred_at=now,
            )
            return self._get_in_transaction(db, flow_id)

    def retry(
        self,
        flow_id: str,
        *,
        actor_id: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            flow = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if flow is None or flow["actor_id"] != actor_id:
                raise NotFoundError("智能体任务不存在")
            self._assert_integrity_in_transaction(db, flow)
            if (
                expected_revision is not None
                and int(flow["revision"]) != int(expected_revision)
            ):
                raise ConflictError("智能体任务版本已变化，请刷新后重试")
            if flow["status"] not in RETRYABLE_FLOW_STATUSES:
                raise ConflictError("只有失败或受阻任务可以重试")
            self.repository._assert_active_draft_in_transaction(
                db,
                str(flow["draft_id"]),
            )
            self._assert_active_capacity_in_transaction(
                db,
                actor_id=actor_id,
            )
            db.execute(
                """
                UPDATE agent_flows
                SET status = 'queued', state_json = '{}', current_step = NULL,
                    attempt = attempt + 1, revision = revision + 1,
                    cancel_requested = 0, summary = NULL, error_code = NULL,
                    error_message = NULL, updated_at = ?,
                    started_at = NULL, completed_at = NULL,
                    run_owner = NULL, lease_expires_at = NULL
                WHERE flow_id = ?
                """,
                (now, flow_id),
            )
            self._append_event(
                db,
                flow_id=flow_id,
                event_type="flow_retry_queued",
                actor_id=actor_id,
                details={
                    "previous_attempt": int(flow["attempt"]),
                    "new_attempt": int(flow["attempt"]) + 1,
                    "state_sha256": sha256_json({}),
                    "owner_id": None,
                    "lease_expires_at": None,
                },
                occurred_at=now,
            )
            return self._get_in_transaction(db, flow_id)

    def renew_lease(
        self,
        flow_id: str,
        *,
        owner_id: str,
        attempt: int,
    ) -> bool:
        """Renew one live execution lease with an auditable CAS transition."""

        now = utc_text()
        lease_expires_at = _lease_text(self.config.lease_seconds)
        with self.repository._transaction() as db:
            flow = db.execute(
                "SELECT * FROM agent_flows WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
            if flow is None:
                raise NotFoundError("智能体任务不存在")
            self._assert_integrity_in_transaction(db, flow)
            if (
                flow["status"] != "running"
                or flow["run_owner"] != owner_id
                or int(flow["attempt"]) != int(attempt)
            ):
                return False
            changed = db.execute(
                """
                UPDATE agent_flows
                SET lease_expires_at = ?, updated_at = ?,
                    revision = revision + 1
                WHERE flow_id = ? AND status = 'running'
                  AND run_owner = ? AND attempt = ?
                """,
                (
                    lease_expires_at,
                    now,
                    flow_id,
                    owner_id,
                    int(attempt),
                ),
            )
            if changed.rowcount != 1:
                return False
            self._append_event(
                db,
                flow_id=flow_id,
                event_type="flow_lease_renewed",
                actor_id="system",
                details={
                    "attempt": int(attempt),
                    "owner_id": owner_id,
                    "lease_expires_at": lease_expires_at,
                },
                occurred_at=now,
            )
        return True

    def recover_interrupted(
        self,
        *,
        now: datetime | None = None,
    ) -> list[str]:
        """Replay only work whose durable execution lease has expired."""

        current = now or utc_now()
        cutoff = utc_text(current)
        deferred_cutoff = utc_text(
            current - timedelta(seconds=self.config.lease_seconds)
        )
        event_parent_cutoff = utc_text(current - timedelta(days=1))
        occurred_at = utc_text()
        with self.repository._transaction() as db:
            deferred = db.execute(
                """
                SELECT * FROM agent_flows
                WHERE status = 'queued' AND dispatch_ready = 0
                  AND cancel_requested = 0 AND created_at <= ?
                ORDER BY created_at ASC
                """,
                (deferred_cutoff,),
            ).fetchall()
            for flow in deferred:
                try:
                    self._assert_integrity_in_transaction(db, flow)
                except ConflictError:
                    continue
                if self._deferred_has_pending_parent(
                    db,
                    flow,
                    event_parent_cutoff=event_parent_cutoff,
                ):
                    continue
                self._abandon_deferred_in_transaction(
                    db,
                    flow,
                    actor_id="system",
                    reason_code="dispatch_authorization_expired",
                    occurred_at=occurred_at,
                )
            running = db.execute(
                """
                SELECT * FROM agent_flows
                WHERE status = 'running'
                  AND (
                      lease_expires_at IS NULL
                      OR lease_expires_at <= ?
                  )
                ORDER BY created_at ASC
                """,
                (cutoff,),
            ).fetchall()
            for flow in running:
                try:
                    self._assert_integrity_in_transaction(db, flow)
                except ConflictError:
                    # Corrupt state is deliberately left untouched for an
                    # operator to inspect; recovery must never launder it.
                    continue
                interrupted_steps = db.execute(
                    """
                    SELECT sequence
                    FROM agent_flow_steps
                    WHERE flow_id = ? AND status = 'running'
                    ORDER BY sequence
                    """,
                    (flow["flow_id"],),
                ).fetchall()
                db.execute(
                    """
                    UPDATE agent_flow_steps
                    SET status = 'failed',
                        error_code = 'flow_interrupted',
                        error_message = '服务重启中断了只读步骤；新尝试将重新计算',
                        completed_at = ?
                    WHERE flow_id = ? AND status = 'running'
                    """,
                    (occurred_at, flow["flow_id"]),
                )
                for step in interrupted_steps:
                    self._append_event(
                        db,
                        flow_id=str(flow["flow_id"]),
                        event_type="flow_step_failed",
                        actor_id="system",
                        details={
                            "sequence": int(step["sequence"]),
                            "attempt": int(flow["attempt"]),
                            "result_sha256": None,
                            "error_code": "flow_interrupted",
                            "error_message_sha256": sha256_json(
                                "服务重启中断了只读步骤；新尝试将重新计算"
                            ),
                            "owner_id": flow["run_owner"],
                            "lease_expires_at": flow["lease_expires_at"],
                        },
                        occurred_at=occurred_at,
                    )
                cancelled = bool(flow["cancel_requested"])
                recovery_summary = (
                    "服务重启时完成取消"
                    if cancelled
                    else "服务重启后恢复只读任务"
                )
                db.execute(
                    """
                    UPDATE agent_flows
                    SET status = ?, current_step = NULL,
                        attempt = CASE WHEN ? THEN attempt
                                       ELSE attempt + 1 END,
                        revision = revision + 1,
                        summary = ?, error_code = NULL, error_message = NULL,
                        run_owner = NULL, lease_expires_at = NULL,
                        updated_at = ?,
                        started_at = CASE WHEN ? THEN started_at ELSE NULL END,
                        completed_at = CASE WHEN ? THEN ? ELSE NULL END
                    WHERE flow_id = ?
                    """,
                    (
                        "cancelled" if cancelled else "queued",
                        cancelled,
                        recovery_summary,
                        occurred_at,
                        cancelled,
                        cancelled,
                        occurred_at,
                        flow["flow_id"],
                    ),
                )
                self._append_event(
                    db,
                    flow_id=str(flow["flow_id"]),
                    event_type=(
                        "flow_cancelled"
                        if cancelled
                        else "flow_recovered"
                    ),
                    actor_id="system",
                    details={
                        "previous_attempt": int(flow["attempt"]),
                        "new_attempt": (
                            int(flow["attempt"])
                            if cancelled
                            else int(flow["attempt"]) + 1
                        ),
                        "read_only_replay": not cancelled,
                        "state_sha256": sha256_json(
                            _json_or(flow["state_json"], {})
                        ),
                        "summary_sha256": (
                            sha256_json(recovery_summary)
                            if cancelled
                            else None
                        ),
                        "owner_id": None,
                        "lease_expires_at": None,
                    },
                    occurred_at=occurred_at,
                )
            queued = db.execute(
                """
                SELECT *
                FROM agent_flows
                WHERE status = 'queued' AND cancel_requested = 0
                  AND dispatch_ready = 1
                ORDER BY created_at ASC
                """
            ).fetchall()
            recoverable = []
            for row in queued:
                try:
                    self._assert_integrity_in_transaction(db, row)
                except ConflictError:
                    continue
                recoverable.append(str(row["flow_id"]))
        return recoverable

    def is_cancel_requested(
        self,
        flow_id: str,
        *,
        owner_id: str | None = None,
        attempt: int | None = None,
    ) -> bool:
        with self.repository._read() as db:
            row = db.execute(
                """
                SELECT cancel_requested, status, run_owner, attempt
                FROM agent_flows
                WHERE flow_id = ?
                """,
                (flow_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("智能体任务不存在")
        if owner_id is not None and (
            row["status"] != "running"
            or row["run_owner"] != owner_id
            or (
                attempt is not None
                and int(row["attempt"]) != int(attempt)
            )
        ):
            raise ConflictError("智能体任务执行租约已经变化")
        return bool(row["cancel_requested"])

    def get(self, flow_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            db.execute("BEGIN")
            try:
                result = self._get_in_transaction(db, flow_id)
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def get_in_transaction(
        self,
        db: Any,
        flow_id: str,
    ) -> dict[str, Any]:
        """Read and verify a flow using the caller's SQLite snapshot."""

        return self._get_in_transaction(db, flow_id)

    def list(
        self,
        *,
        actor_id: str,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        bounded = min(max(int(limit), 1), 100)
        start = max(int(offset), 0)
        where = "WHERE actor_id = ?"
        values: list[Any] = [actor_id]
        if status is not None:
            where += " AND status = ?"
            values.append(status)
        with self.repository._read() as db:
            db.execute("BEGIN")
            try:
                total = int(
                    db.execute(
                        f"SELECT COUNT(*) AS amount FROM agent_flows {where}",
                        values,
                    ).fetchone()["amount"]
                )
                rows = db.execute(
                    f"""
                    SELECT *
                    FROM agent_flows
                    {where}
                    ORDER BY updated_at DESC, flow_id ASC
                    LIMIT ? OFFSET ?
                    """,
                    [*values, bounded, start],
                ).fetchall()
                items = []
                for row in rows:
                    steps = db.execute(
                        """
                        SELECT * FROM agent_flow_steps
                        WHERE flow_id = ? ORDER BY sequence
                        """,
                        (row["flow_id"],),
                    ).fetchall()
                    events = db.execute(
                        """
                        SELECT * FROM agent_flow_events
                        WHERE flow_id = ? ORDER BY sequence
                        """,
                        (row["flow_id"],),
                    ).fetchall()
                    item = self._flow_row(row, include_state=False)
                    item["integrity"] = self._verify_integrity(
                        row,
                        steps,
                        events,
                    )
                    items.append(item)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return items, total

    def _get_in_transaction(self, db: Any, flow_id: str) -> dict[str, Any]:
        row = db.execute(
            "SELECT * FROM agent_flows WHERE flow_id = ?",
            (flow_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("智能体任务不存在")
        steps = db.execute(
            """
            SELECT *
            FROM agent_flow_steps
            WHERE flow_id = ?
            ORDER BY sequence ASC
            """,
            (flow_id,),
        ).fetchall()
        events = db.execute(
            """
            SELECT *
            FROM agent_flow_events
            WHERE flow_id = ?
            ORDER BY sequence ASC
            """,
            (flow_id,),
        ).fetchall()
        result = self._flow_row(row)
        result["steps"] = [self._step_row(item) for item in steps]
        result["events"] = [self._event_row(item) for item in events]
        result["integrity"] = self._verify_integrity(row, steps, events)
        return result

    @staticmethod
    def _flow_row(
        row: Any,
        *,
        include_state: bool = True,
    ) -> dict[str, Any]:
        result = {
            "flow_id": str(row["flow_id"]),
            "actor_id": str(row["actor_id"]),
            "workflow_name": str(row["workflow_name"]),
            "workflow_version": str(row["workflow_version"]),
            "draft_id": row["draft_id"],
            "goal": str(row["goal_text"]),
            "status": str(row["status"]),
            "trigger": {
                "type": str(row["trigger_type"]),
                "ref": row["trigger_ref"],
            },
            "client_request_id": row["client_request_id"],
            "current_step": row["current_step"],
            "attempt": int(row["attempt"]),
            "dispatch_ready": bool(row["dispatch_ready"]),
            "run_owner": row["run_owner"],
            "lease_expires_at": row["lease_expires_at"],
            "revision": int(row["revision"]),
            "cancel_requested": bool(row["cancel_requested"]),
            "summary": row["summary"],
            "error": (
                {
                    "code": row["error_code"],
                    "message": row["error_message"],
                }
                if row["error_code"] or row["error_message"]
                else None
            ),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "started_at": row["started_at"],
            "completed_at": row["completed_at"],
        }
        if include_state:
            result["state"] = _json_or(row["state_json"], {})
        return result

    @staticmethod
    def _step_row(row: Any) -> dict[str, Any]:
        return {
            "sequence": int(row["sequence"]),
            "attempt": int(row["attempt"]),
            "step_key": str(row["step_key"]),
            "specialist": str(row["specialist"]),
            "status": str(row["status"]),
            "input": _json_or(row["input_json"], {}),
            "result": (
                _json_or(row["result_json"], None)
                if row["result_json"] is not None
                else None
            ),
            "result_sha256": row["result_sha256"],
            "error": (
                {
                    "code": row["error_code"],
                    "message": row["error_message"],
                }
                if row["error_code"] or row["error_message"]
                else None
            ),
            "started_at": str(row["started_at"]),
            "completed_at": row["completed_at"],
        }

    @staticmethod
    def _event_row(row: Any) -> dict[str, Any]:
        return {
            "sequence": int(row["sequence"]),
            "event_type": str(row["event_type"]),
            "actor_id": str(row["actor_id"]),
            "details": _json_or(row["details_json"], {}),
            "occurred_at": str(row["occurred_at"]),
            "previous_hash": str(row["previous_hash"]),
            "event_hash": str(row["event_hash"]),
        }

    @staticmethod
    def _verify_integrity(
        flow: Any,
        steps: list[Any],
        events: list[Any],
    ) -> dict[str, Any]:
        previous_hash = _ZERO_HASH
        valid = True
        failed_sequence: int | None = None
        failed_component: str | None = None
        parsed_events: list[tuple[Any, dict[str, Any]]] = []
        for expected_sequence, row in enumerate(events, start=1):
            try:
                details = json.loads(row["details_json"])
            except (json.JSONDecodeError, TypeError, ValueError):
                valid = False
                failed_sequence = expected_sequence
                failed_component = "event_details"
                break
            if not isinstance(details, dict):
                valid = False
                failed_sequence = expected_sequence
                failed_component = "event_details"
                break
            envelope = {
                "flow_id": str(row["flow_id"]),
                "sequence": int(row["sequence"]),
                "event_type": str(row["event_type"]),
                "actor_id": str(row["actor_id"]),
                "details": details,
                "occurred_at": str(row["occurred_at"]),
                "previous_hash": str(row["previous_hash"]),
            }
            if (
                int(row["sequence"]) != expected_sequence
                or not hmac.compare_digest(
                    str(row["previous_hash"]), previous_hash
                )
                or not hmac.compare_digest(
                    str(row["event_hash"]), sha256_json(envelope)
                )
            ):
                valid = False
                failed_sequence = expected_sequence
                failed_component = "event_chain"
                break
            previous_hash = str(row["event_hash"])
            parsed_events.append((row, details))
        if valid and (
            int(flow["event_count"]) != len(events)
            or not hmac.compare_digest(
                str(flow["event_head_hash"]), previous_hash
            )
        ):
            valid = False
            failed_sequence = len(events) + 1
            failed_component = "event_anchor"
        if valid and parsed_events:
            latest_control_hash = parsed_events[-1][1].get(
                "flow_control_sha256"
            )
            if (
                not isinstance(latest_control_hash, str)
                or latest_control_hash
                != sha256_json(_flow_control_payload(flow))
            ):
                valid = False
                failed_sequence = len(events)
                failed_component = "flow_control_state"
        if valid:
            created = (
                parsed_events[0]
                if parsed_events
                and str(parsed_events[0][0]["event_type"]) == "flow_created"
                else None
            )
            if created is None:
                valid = False
                failed_component = "flow_created_event"
            else:
                created_row, created_details = created
                immutable_matches = (
                    str(created_row["actor_id"]) == str(flow["actor_id"])
                    and created_details.get("workflow_name")
                    == str(flow["workflow_name"])
                    and created_details.get("workflow_version")
                    == str(flow["workflow_version"])
                    and created_details.get("draft_id")
                    == str(flow["draft_id"])
                    and created_details.get("goal_sha256")
                    == sha256_json(str(flow["goal_text"]))
                    and created_details.get("trigger_type")
                    == str(flow["trigger_type"])
                    and created_details.get("trigger_ref")
                    == flow["trigger_ref"]
                    and created_details.get("client_request_id")
                    == flow["client_request_id"]
                    and str(created_row["occurred_at"])
                    == str(flow["created_at"])
                )
                if not immutable_matches:
                    valid = False
                    failed_component = "flow_identity"
        if valid:
            derived_status = "queued"
            derived_cancel_requested = False
            derived_attempt = 1
            initial_dispatch_ready = parsed_events[0][1].get(
                "initial_dispatch_ready"
            )
            if not isinstance(initial_dispatch_ready, bool):
                valid = False
                failed_component = "flow_dispatch"
            derived_dispatch_ready = bool(initial_dispatch_ready)
            derived_owner: str | None = None
            derived_lease: str | None = None
            latest_started_at: str | None = None
            latest_terminal: tuple[Any, dict[str, Any]] | None = None
            for event_row, details in parsed_events[1:] if valid else ():
                event_type = str(event_row["event_type"])
                if event_type == "flow_dispatch_authorized":
                    if (
                        derived_status != "queued"
                        or derived_dispatch_ready
                        or details.get("dispatch_ready") is not True
                    ):
                        valid = False
                        failed_component = "flow_dispatch"
                        break
                    derived_dispatch_ready = True
                elif event_type == "flow_started":
                    owner = details.get("owner_id")
                    lease = details.get("lease_expires_at")
                    if (
                        derived_status != "queued"
                        or derived_cancel_requested
                        or details.get("attempt") != derived_attempt
                        or (owner is not None and not isinstance(owner, str))
                        or (lease is not None and not isinstance(lease, str))
                    ):
                        valid = False
                        failed_component = "flow_transition"
                        break
                    derived_status = "running"
                    derived_owner = owner
                    derived_lease = lease
                    latest_started_at = str(event_row["occurred_at"])
                elif event_type == "flow_dispatch_reopened":
                    if (
                        derived_status != "cancelled"
                        or not derived_cancel_requested
                        or derived_dispatch_ready
                        or latest_terminal is None
                        or details.get("previous_error_code")
                        not in {
                            "dispatch_authorization_expired",
                            "scheduler_launch_aborted",
                        }
                        or details.get("dispatch_ready") is not False
                    ):
                        valid = False
                        failed_component = "flow_dispatch"
                        break
                    derived_status = "queued"
                    derived_cancel_requested = False
                    derived_owner = None
                    derived_lease = None
                    latest_started_at = None
                    latest_terminal = None
                elif event_type == "flow_cancel_requested":
                    if derived_status != "running" or derived_cancel_requested:
                        valid = False
                        failed_component = "flow_transition"
                        break
                    if (
                        details.get("owner_id") is not None
                        and details.get("owner_id") != derived_owner
                    ):
                        valid = False
                        failed_component = "flow_lease"
                        break
                    derived_cancel_requested = True
                elif event_type == "flow_lease_renewed":
                    if (
                        derived_status != "running"
                        or details.get("attempt") != derived_attempt
                        or details.get("owner_id") != derived_owner
                        or not isinstance(details.get("lease_expires_at"), str)
                    ):
                        valid = False
                        failed_component = "flow_lease"
                        break
                    derived_lease = details["lease_expires_at"]
                elif event_type.startswith("flow_step_"):
                    if derived_status != "running":
                        valid = False
                        failed_component = "flow_transition"
                        break
                    event_attempt = details.get("attempt")
                    if event_attempt is not None and event_attempt != derived_attempt:
                        valid = False
                        failed_component = "flow_attempt"
                        break
                    event_owner = details.get("owner_id")
                    if event_owner is not None and event_owner != derived_owner:
                        valid = False
                        failed_component = "flow_lease"
                        break
                    event_lease = details.get("lease_expires_at")
                    if event_lease is not None:
                        if not isinstance(event_lease, str):
                            valid = False
                            failed_component = "flow_lease"
                            break
                        derived_lease = event_lease
                elif event_type == "flow_retry_queued":
                    new_attempt = details.get("new_attempt")
                    if (
                        derived_status not in RETRYABLE_FLOW_STATUSES
                        or details.get("previous_attempt") != derived_attempt
                        or isinstance(new_attempt, bool)
                        or not isinstance(new_attempt, int)
                        or new_attempt != derived_attempt + 1
                    ):
                        valid = False
                        failed_component = "flow_transition"
                        break
                    derived_attempt = new_attempt
                    derived_status = "queued"
                    derived_cancel_requested = False
                    derived_owner = None
                    derived_lease = None
                    latest_started_at = None
                    latest_terminal = None
                elif event_type == "flow_recovered":
                    new_attempt = details.get("new_attempt")
                    if (
                        derived_status != "running"
                        or details.get("previous_attempt") != derived_attempt
                        or isinstance(new_attempt, bool)
                        or not isinstance(new_attempt, int)
                        or new_attempt != derived_attempt + 1
                    ):
                        valid = False
                        failed_component = "flow_transition"
                        break
                    derived_attempt = new_attempt
                    derived_status = "queued"
                    derived_cancel_requested = False
                    derived_owner = None
                    derived_lease = None
                    latest_started_at = None
                    latest_terminal = None
                elif event_type.startswith("flow_") and event_type[5:] in (
                    TERMINAL_FLOW_STATUSES
                ):
                    terminal_status = event_type[5:]
                    immediate_cancel = (
                        terminal_status == "cancelled"
                        and details.get("immediate") is True
                    )
                    if (
                        immediate_cancel
                        and derived_status != "queued"
                    ) or (
                        not immediate_cancel
                        and derived_status != "running"
                    ):
                        valid = False
                        failed_component = "flow_transition"
                        break
                    derived_status = event_type[5:]
                    derived_owner = None
                    derived_lease = None
                    latest_terminal = (event_row, details)
                    if derived_status == "cancelled":
                        derived_cancel_requested = True
                else:
                    valid = False
                    failed_component = "flow_event_type"
                    break
            if valid and (
                str(flow["status"]) != derived_status
                or bool(flow["cancel_requested"])
                != derived_cancel_requested
            ):
                valid = False
                failed_component = "flow_status"
            if valid and int(flow["attempt"]) != derived_attempt:
                valid = False
                failed_component = "flow_attempt"
            if valid and bool(flow["dispatch_ready"]) != derived_dispatch_ready:
                valid = False
                failed_component = "flow_dispatch"
            if valid and (
                flow["run_owner"] != derived_owner
                or flow["lease_expires_at"] != derived_lease
            ):
                valid = False
                failed_component = "flow_lease"
            if valid:
                started_at = flow["started_at"]
                completed_at = flow["completed_at"]
                if derived_status == "queued":
                    timestamps_match = (
                        started_at is None and completed_at is None
                    )
                elif derived_status == "running":
                    timestamps_match = (
                        started_at == latest_started_at
                        and completed_at is None
                    )
                else:
                    timestamps_match = (
                        latest_terminal is not None
                        and started_at == latest_started_at
                        and completed_at
                        == str(latest_terminal[0]["occurred_at"])
                    )
                if not timestamps_match:
                    valid = False
                    failed_component = "flow_timestamps"
        if valid:
            try:
                state = json.loads(flow["state_json"])
            except (json.JSONDecodeError, TypeError, ValueError):
                valid = False
                failed_component = "flow_state"
                state = None
            if valid and not isinstance(state, dict):
                valid = False
                failed_component = "flow_state"
            if (
                valid
                and str(flow["status"]) not in TERMINAL_FLOW_STATUSES
                and state != {}
            ):
                valid = False
                failed_component = "flow_state"
            if valid and str(flow["status"]) in TERMINAL_FLOW_STATUSES:
                terminal_type = f"flow_{flow['status']}"
                terminal_details = (
                    latest_terminal[1]
                    if latest_terminal is not None
                    and str(latest_terminal[0]["event_type"])
                    == terminal_type
                    else None
                )
                if terminal_details is None:
                    valid = False
                    failed_component = "flow_terminal_event"
                elif terminal_details.get("state_sha256") != sha256_json(state):
                    valid = False
                    failed_component = "flow_state"
                elif terminal_details.get("summary_sha256") != sha256_json(
                    flow["summary"]
                ):
                    valid = False
                    failed_component = "flow_summary"
                elif (
                    terminal_details.get("error_code") != flow["error_code"]
                    or terminal_details.get("error_message_sha256")
                    != (
                        sha256_json(flow["error_message"])
                        if flow["error_message"] is not None
                        else None
                    )
                ):
                    valid = False
                    failed_component = "flow_error"
        if valid:
            for step in steps:
                sequence = int(step["sequence"])
                try:
                    step_input = json.loads(step["input_json"])
                    step_result = (
                        json.loads(step["result_json"])
                        if step["result_json"] is not None
                        else None
                    )
                except (json.JSONDecodeError, TypeError, ValueError):
                    valid = False
                    failed_component = f"step:{sequence}:json"
                    break
                expected_result_hash = (
                    sha256_json(step_result)
                    if step["result_json"] is not None
                    else None
                )
                if step["result_sha256"] != expected_result_hash:
                    valid = False
                    failed_component = f"step:{sequence}:result"
                    break
                started = [
                    (row, details)
                    for row, details in parsed_events
                    if str(row["event_type"]) == "flow_step_started"
                    and details.get("sequence") == sequence
                ]
                if len(started) != 1:
                    valid = False
                    failed_component = f"step:{sequence}:start_event"
                    break
                started_row, started_details = started[0]
                if (
                    started_details.get("attempt") != int(step["attempt"])
                    or started_details.get("step_key") != str(step["step_key"])
                    or started_details.get("specialist")
                    != str(step["specialist"])
                    or started_details.get("input_sha256")
                    != sha256_json(step_input)
                    or str(step["started_at"])
                    != str(started_row["occurred_at"])
                ):
                    valid = False
                    failed_component = f"step:{sequence}:input"
                    break
                if str(step["status"]) == "running":
                    if (
                        step["completed_at"] is not None
                        or step["error_code"] is not None
                        or step["error_message"] is not None
                    ):
                        valid = False
                        failed_component = f"step:{sequence}:running_state"
                        break
                    continue
                completed = [
                    (row, details)
                    for row, details in parsed_events
                    if str(row["event_type"])
                    == f"flow_step_{step['status']}"
                    and details.get("sequence") == sequence
                ]
                if len(completed) != 1:
                    valid = False
                    failed_component = f"step:{sequence}:completion_event"
                    break
                completed_row, completed_details = completed[0]
                if (
                    completed_details.get("result_sha256")
                    != expected_result_hash
                    or completed_details.get("error_code")
                    != step["error_code"]
                    or completed_details.get("error_message_sha256")
                    != (
                        sha256_json(step["error_message"])
                        if step["error_message"] is not None
                        else None
                    )
                    or step["completed_at"]
                    != str(completed_row["occurred_at"])
                ):
                    valid = False
                    failed_component = f"step:{sequence}:completion_event"
                    break
        return {
            "valid": valid,
            "event_count": len(events),
            "head_hash": previous_hash,
            "failed_sequence": failed_sequence,
            "failed_component": failed_component,
        }


__all__ = ["AgentFlowStore"]
