"""Worker runtime for durable, replay-safe coal health flows."""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import replace
from queue import Empty, Full, Queue
from typing import Any

from enterprise_agent.errors import ConflictError, NotFoundError
from enterprise_agent.harness.readonly import ReadOnlyRepository
from enterprise_agent.harness.sanitize import redact_text
from enterprise_agent.tools import ToolContext, ToolRegistry
from enterprise_agent.tools.builtins import builtin_tool_specs
from enterprise_agent.util import canonical_json, random_id

from .governance import GovernanceAccess
from .models import (
    ACTOR_PATTERN,
    CLIENT_REQUEST_ID_PATTERN,
    DAILY_COAL_HEALTH_WORKFLOW,
    DRAFT_ID_PATTERN,
    FLOW_STATUSES,
    SUPPORTED_WORKFLOWS,
    TRIGGER_TYPES,
    FlowRuntimeConfig,
    workflow_version,
)
from .snapshot import FrozenEvidenceRepository
from .store import AgentFlowStore
from .workflows import (
    SPECIALIST_NAMES,
    assemble_daily_health_result,
    execute_specialist,
    prepare_daily_health,
    validate_read_only_registry,
)


class AgentFlowRuntime:
    """Runs bounded, local-only workflows while persisting every transition."""

    version = "enterprise-agent-flow-v2"

    def __init__(
        self,
        service: Any,
        *,
        registry: ToolRegistry | None = None,
        worker_count: int | None = None,
        config: FlowRuntimeConfig | None = None,
        auto_start: bool = True,
    ):
        self.service = service
        self.repository = service.repository
        runtime_config = config or FlowRuntimeConfig()
        if worker_count is not None:
            runtime_config = replace(runtime_config, worker_count=worker_count)
        self.config = runtime_config
        self.store = AgentFlowStore(
            self.repository,
            config=runtime_config,
        )
        self.readonly_repository = ReadOnlyRepository(self.repository)
        self.registry = registry or ToolRegistry(
            builtin_tool_specs(),
            context=ToolContext(repository=self.readonly_repository),
        )
        validate_read_only_registry(self.registry)

        self._queue: Queue[str | None] = Queue(
            maxsize=runtime_config.queue_capacity
        )
        self._specialist_pool = ThreadPoolExecutor(
            max_workers=runtime_config.specialist_worker_count,
            thread_name_prefix="coal-flow-specialist",
        )
        self._lifecycle_lock = threading.RLock()
        self._schedule_lock = threading.Lock()
        self._scheduled: set[str] = set()
        self._workers: tuple[threading.Thread, ...] = ()
        self._recovery_stop = threading.Event()
        self._recovery_thread: threading.Thread | None = None
        self._heartbeat_stops: set[threading.Event] = set()
        self.runtime_id = random_id("flow-worker")
        self._started = False
        self._closed = False
        if auto_start:
            self.start()

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("智能体任务运行器已经关闭")
            if self._started:
                return
            recoverable = self.store.recover_interrupted()
            self._workers = tuple(
                threading.Thread(
                    target=self._worker_loop,
                    name=f"enterprise-agent-flow-{index + 1}",
                    daemon=True,
                )
                for index in range(self.config.worker_count)
            )
            self._recovery_thread = threading.Thread(
                target=self._recovery_loop,
                name="enterprise-agent-flow-recovery",
                daemon=True,
            )
            self._started = True
            for worker in self._workers:
                worker.start()
            self._recovery_thread.start()
            for flow_id in recoverable:
                try:
                    self._schedule(flow_id)
                except ConflictError:
                    # Durable queued rows remain discoverable by recovery.
                    break

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            workers = self._workers
            recovery_thread = self._recovery_thread
            self._recovery_stop.set()
            heartbeat_stops = tuple(self._heartbeat_stops)
        for stop in heartbeat_stops:
            stop.set()
        if recovery_thread is not None:
            recovery_thread.join(timeout=2.0)
        sentinels = 0
        shutdown_deadline = time.monotonic() + 5.0
        while sentinels < len(workers):
            remaining = shutdown_deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                self._queue.put(None, timeout=min(0.25, remaining))
            except Full:
                if all(not worker.is_alive() for worker in workers):
                    break
                continue
            sentinels += 1
        for worker in workers:
            worker.join(timeout=max(0.0, shutdown_deadline - time.monotonic()))
        self._specialist_pool.shutdown(wait=False, cancel_futures=True)

    def public_workflows(self) -> list[dict[str, Any]]:
        return [
            {
                "name": DAILY_COAL_HEALTH_WORKFLOW,
                "version": workflow_version(DAILY_COAL_HEALTH_WORKFLOW),
                "title": "每日煤炭数据体检",
                "description": (
                    "并行核对来源凭证、时序质量、物理平衡和历史交叉证据，"
                    "再由确定性反方核验器生成领导摘要。"
                ),
                "read_only": True,
                "network_access": False,
                "can_confirm": False,
                "can_submit": False,
            }
        ]

    def create(
        self,
        *,
        actor_id: str,
        draft_id: str,
        workflow_name: str = DAILY_COAL_HEALTH_WORKFLOW,
        goal: str = "",
        client_request_id: str | None = None,
        trigger_type: str = "manual",
        trigger_ref: str | None = None,
        defer_dispatch: bool = False,
    ) -> dict[str, Any]:
        actor = self._actor(actor_id)
        draft = self._draft_id(draft_id)
        workflow = self._workflow(workflow_name)
        if not isinstance(goal, str) or len(goal) > 4_000:
            raise ValueError("goal 必须是不超过 4000 字符的文本")
        safe_goal = goal.strip() or "对当前煤炭填报草稿执行每日只读体检"
        if trigger_type not in TRIGGER_TYPES:
            raise ValueError("trigger_type 只能是 manual、schedule 或 event")
        if trigger_ref is not None and (
            not isinstance(trigger_ref, str)
            or not trigger_ref.strip()
            or len(trigger_ref) > 256
        ):
            raise ValueError("trigger_ref 必须是 1 到 256 字符的文本")
        request_id = self._client_request_id(client_request_id)
        if not isinstance(defer_dispatch, bool):
            raise ValueError("defer_dispatch 必须是布尔值")

        # The lifecycle lock makes "closed" a hard API boundary: close() cannot
        # return and then race with a late durable create.
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("智能体任务运行器已经关闭")
            # Resolve through the narrow read capability before allocating work.
            self.readonly_repository.get_draft(draft)
            flow, created = self.store.create_flow(
                actor_id=actor,
                workflow_name=workflow,
                workflow_version=workflow_version(workflow),
                draft_id=draft,
                goal_text=safe_goal,
                trigger_type=trigger_type,
                trigger_ref=trigger_ref.strip() if trigger_ref else None,
                client_request_id=request_id,
                dispatch_ready=not defer_dispatch,
            )
            if (
                self._started
                and flow["status"] == "queued"
                and flow["dispatch_ready"]
            ):
                with suppress(ConflictError):
                    # Persistence is the durable queue. A full in-memory wake
                    # queue must not turn an accepted idempotent request into
                    # an apparent failure; recovery will enqueue it later.
                    self._schedule(flow["flow_id"])
        # Keep the same public representation for first and idempotent calls.
        flow["idempotent_replay"] = not created
        return flow

    def authorize_dispatch_in_transaction(
        self,
        db: Any,
        flow_id: str,
        *,
        actor_id: str,
    ) -> bool:
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("智能体任务运行器已经关闭")
            return self.store.authorize_dispatch_in_transaction(
                db,
                self._flow_id(flow_id),
                actor_id=self._actor(actor_id),
            )

    def abandon_deferred(
        self,
        flow_id: str,
        *,
        actor_id: str,
        reason_code: str = "dispatch_aborted",
    ) -> bool:
        return self.store.abandon_deferred(
            self._flow_id(flow_id),
            actor_id=self._actor(actor_id),
            reason_code=reason_code,
        )

    def schedule_existing(self, flow_id: str) -> None:
        flow = self.store.get(self._flow_id(flow_id))
        if (
            self._started
            and flow["status"] == "queued"
            and flow["dispatch_ready"]
            and flow["integrity"]["valid"]
        ):
            self._schedule(flow["flow_id"])

    def list(
        self,
        *,
        actor_id: str,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        actor = self._actor(actor_id)
        if status is not None and status not in FLOW_STATUSES:
            raise ValueError("status 不受支持")
        return self.store.list(
            actor_id=actor,
            limit=limit,
            offset=offset,
            status=status,
        )

    def get(self, flow_id: str, *, actor_id: str) -> dict[str, Any]:
        flow = self.store.get(self._flow_id(flow_id))
        if flow["actor_id"] != self._actor(actor_id):
            raise NotFoundError("智能体任务不存在")
        return flow

    def cancel(
        self,
        flow_id: str,
        *,
        actor_id: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        revision = self._revision(expected_revision)
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("智能体任务运行器已经关闭")
            return self.store.request_cancel(
                self._flow_id(flow_id),
                actor_id=self._actor(actor_id),
                expected_revision=revision,
            )

    def retry(
        self,
        flow_id: str,
        *,
        actor_id: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        revision = self._revision(expected_revision)
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("智能体任务运行器已经关闭")
            flow = self.store.retry(
                self._flow_id(flow_id),
                actor_id=self._actor(actor_id),
                expected_revision=revision,
            )
            if self._started:
                with suppress(ConflictError):
                    # SQLite is the durable queue; a saturated in-memory wake
                    # queue must not turn an accepted retry into an apparent
                    # API failure.
                    self._schedule(flow["flow_id"])
            return flow

    def run(
        self,
        flow_id: str,
        *,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        """Claim and execute synchronously; schedulers may omit actor_id."""

        normalized = self._flow_id(flow_id)
        if actor_id is not None:
            self.get(normalized, actor_id=actor_id)
        heartbeat_stop: threading.Event | None = None
        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("智能体任务运行器已经关闭")
            claimed_by_runtime = self.store.claim(
                normalized,
                owner_id=self.runtime_id,
            )
            if claimed_by_runtime:
                claimed = self.store.get(normalized)
                attempt = int(claimed["attempt"])
                heartbeat_stop = threading.Event()
                self._heartbeat_stops.add(heartbeat_stop)
        if claimed_by_runtime and heartbeat_stop is not None:
            heartbeat = threading.Thread(
                target=self._heartbeat_loop,
                args=(normalized, attempt, heartbeat_stop),
                name=f"flow-heartbeat-{normalized[:8]}",
                daemon=True,
            )
            heartbeat.start()
            try:
                self._execute_claimed(normalized, attempt=attempt)
            finally:
                heartbeat_stop.set()
                heartbeat.join(timeout=2.0)
                with self._lifecycle_lock:
                    self._heartbeat_stops.discard(heartbeat_stop)
        result = self.store.get(normalized)
        if actor_id is not None and result["actor_id"] != self._actor(actor_id):
            raise NotFoundError("智能体任务不存在")
        return result

    def recover(self) -> list[str]:
        """Startup hook for hosts that construct with ``auto_start=False``."""

        with self._lifecycle_lock:
            if self._closed:
                raise RuntimeError("智能体任务运行器已经关闭")
            recovered = self.store.recover_interrupted()
            if self._started:
                for flow_id in recovered:
                    try:
                        self._schedule(flow_id)
                    except ConflictError:
                        break
            return recovered

    def _schedule(self, flow_id: str) -> None:
        with self._schedule_lock:
            if self._closed or flow_id in self._scheduled:
                return
            self._scheduled.add(flow_id)
        try:
            self._queue.put_nowait(flow_id)
        except Full as error:
            with self._schedule_lock:
                self._scheduled.discard(flow_id)
            raise ConflictError(
                "智能体任务队列已满；任务已安全保留，可稍后重试"
            ) from error

    def _worker_loop(self) -> None:
        while True:
            try:
                flow_id = self._queue.get(timeout=0.5)
            except Empty:
                if self._closed:
                    return
                continue
            if flow_id is None:
                self._queue.task_done()
                return
            try:
                # Shutdown leaves unclaimed durable work queued for the next
                # process instead of silently starting more background work.
                if self._closed:
                    continue
                try:
                    self.run(flow_id)
                except Exception as error:
                    # A corrupt row or unexpected persistence error must not
                    # permanently kill one of the bounded worker threads.
                    self._complete_after_error(
                        flow_id,
                        status="failed",
                        state={"read_only": True},
                        summary="智能体后台任务异常终止，可在排查后重试",
                        error_code="worker_boundary_failed",
                        error_message=redact_text(str(error), maximum=2_000),
                    )
            finally:
                with self._schedule_lock:
                    self._scheduled.discard(flow_id)
                self._queue.task_done()
                if not self._closed:
                    try:
                        persisted = self.store.get(flow_id)
                        if (
                            persisted["status"] == "queued"
                            and persisted["integrity"]["valid"]
                        ):
                            self._schedule(flow_id)
                    except (ConflictError, NotFoundError):
                        pass

    def _recovery_loop(self) -> None:
        interval = min(30.0, max(5.0, self.config.lease_seconds / 3))
        while not self._recovery_stop.wait(interval):
            try:
                recovered = self.store.recover_interrupted()
            except Exception:
                continue
            for flow_id in recovered:
                try:
                    self._schedule(flow_id)
                except ConflictError:
                    break

    def _heartbeat_loop(
        self,
        flow_id: str,
        attempt: int,
        stop: threading.Event,
    ) -> None:
        interval = min(30.0, max(5.0, self.config.lease_seconds / 3))
        while not stop.wait(interval):
            try:
                if not self.store.renew_lease(
                    flow_id,
                    owner_id=self.runtime_id,
                    attempt=attempt,
                ):
                    return
            except (ConflictError, NotFoundError):
                return

    def _execute_claimed(self, flow_id: str, *, attempt: int) -> None:
        partial_state: dict[str, Any] = {
            "workflow": DAILY_COAL_HEALTH_WORKFLOW,
            "read_only": True,
            "confirmed": False,
            "submitted": False,
        }
        active_step: int | None = None
        inflight_steps: set[int] = set()
        try:
            flow = self.store.get(flow_id)
            if not flow["integrity"]["valid"]:
                self.store.complete(
                    flow_id,
                    status="failed",
                    state=partial_state,
                    summary="任务审计完整性校验失败，未执行任何业务工具",
                    error_code="flow_integrity_failed",
                    error_message="智能体任务事件链与持久化锚点不一致",
                    owner_id=self.runtime_id,
                    attempt=attempt,
                )
                return
            if flow["workflow_name"] != DAILY_COAL_HEALTH_WORKFLOW:
                raise ValueError("工作流实现不存在")
            self._raise_if_cancelled(flow_id, attempt)
            active_step = self.store.start_step(
                flow_id,
                step_key="prepare_evidence",
                specialist="orchestrator",
                step_input={"draft_id": flow["draft_id"]},
                owner_id=self.runtime_id,
                attempt=attempt,
            )
            evidence_repository = FrozenEvidenceRepository.capture(
                self.repository,
                draft_id=str(flow["draft_id"]),
            )
            evidence_metadata = evidence_repository.metadata
            flow_registry = ToolRegistry(
                self.registry.list_specs(),
                context=ToolContext(repository=evidence_repository),
            )
            validate_read_only_registry(flow_registry)
            prepared = prepare_daily_health(
                flow_registry,
                draft_id=str(flow["draft_id"]),
                selected_metric_codes=evidence_metadata.get(
                    "history_metric_codes",
                    [],
                ),
                metric_coverage=evidence_metadata.get("metric_coverage"),
            )
            prepared["evidence_snapshot"] = evidence_metadata
            prepared["governed_context"] = self._load_governed_context(
                flow,
                evidence_repository=evidence_repository,
            )
            partial_state["prepared"] = {
                key: prepared.get(key)
                for key in (
                    "draft_id",
                    "draft_revision",
                    "document_sha256",
                    "mine_id",
                    "metric_codes",
                    "metric_coverage",
                    "evidence_snapshot",
                    "governed_context",
                )
            }
            self._raise_if_cancelled(flow_id, attempt)
            self.store.finish_step(
                flow_id,
                active_step,
                status="succeeded",
                result={
                    "draft_id": prepared["draft_id"],
                    "draft_revision": prepared.get("draft_revision"),
                    "document_sha256": prepared.get("document_sha256"),
                    "metric_codes": prepared.get("metric_codes", []),
                    "metric_coverage": prepared.get("metric_coverage"),
                    "governed_context": prepared["governed_context"],
                    "summary": prepared["summary"],
                    "preflight": prepared["preflight"],
                },
                owner_id=self.runtime_id,
                attempt=attempt,
            )
            active_step = None
            self._raise_if_cancelled(flow_id, attempt)

            step_sequences: dict[str, int] = {}
            futures: dict[Future[dict[str, Any]], str] = {}
            for specialist in SPECIALIST_NAMES:
                self._raise_if_cancelled(flow_id, attempt)
                sequence = self.store.start_step(
                    flow_id,
                    step_key=f"specialist_{specialist}",
                    specialist=specialist,
                    step_input={
                        "draft_id": prepared["draft_id"],
                        "draft_revision": prepared.get("draft_revision"),
                        "metric_codes": prepared.get("metric_codes", []),
                    },
                    owner_id=self.runtime_id,
                    attempt=attempt,
                )
                step_sequences[specialist] = sequence
                inflight_steps.add(sequence)
                futures[
                    self._specialist_pool.submit(
                        execute_specialist,
                        flow_registry,
                        specialist,
                        prepared,
                    )
                ] = specialist

            specialists: dict[str, dict[str, Any]] = {}
            for future in as_completed(futures):
                self._raise_if_cancelled(flow_id, attempt)
                specialist = futures[future]
                sequence = step_sequences[specialist]
                try:
                    result = future.result()
                except Exception as error:
                    message = redact_text(str(error), maximum=1_000)
                    result = {
                        "specialist": specialist,
                        "status": "failed",
                        "tool_count": 0,
                        "succeeded_tool_count": 0,
                        "tools": [],
                        "errors": [
                            {
                                "code": type(error).__name__,
                                "message": message,
                            }
                        ],
                        "read_only": True,
                        "network_access": False,
                    }
                    self.store.finish_step(
                        flow_id,
                        sequence,
                        status="failed",
                        result=result,
                        error_code="specialist_failed",
                        error_message=message,
                        owner_id=self.runtime_id,
                        attempt=attempt,
                    )
                else:
                    if result.get("status") == "failed":
                        errors = result.get("errors", [])
                        message = (
                            str(errors[0].get("message"))
                            if errors and isinstance(errors[0], dict)
                            else "专家所需只读工具全部执行失败"
                        )
                        self.store.finish_step(
                            flow_id,
                            sequence,
                            status="failed",
                            result=result,
                            error_code="specialist_failed",
                            error_message=message,
                            owner_id=self.runtime_id,
                            attempt=attempt,
                        )
                    else:
                        self.store.finish_step(
                            flow_id,
                            sequence,
                            status="succeeded",
                            result=result,
                            owner_id=self.runtime_id,
                            attempt=attempt,
                        )
                inflight_steps.discard(sequence)
                specialists[specialist] = result
            partial_state["specialists"] = specialists
            self._raise_if_cancelled(flow_id, attempt)

            active_step = self.store.start_step(
                flow_id,
                step_key="critic_and_executive_brief",
                specialist="dissenting_critic",
                step_input={
                    "draft_id": prepared["draft_id"],
                    "specialists": list(SPECIALIST_NAMES),
                },
                owner_id=self.runtime_id,
                attempt=attempt,
            )
            result = assemble_daily_health_result(prepared, specialists)
            self.store.finish_step(
                flow_id,
                active_step,
                status="succeeded",
                result={
                    "critic": result["critic"],
                    "executive_brief": result["executive_brief"],
                },
                owner_id=self.runtime_id,
                attempt=attempt,
            )
            active_step = None
            partial_state = result
            self._raise_if_cancelled(flow_id, attempt)
            failed_count = sum(
                item.get("status") == "failed"
                for item in specialists.values()
            )
            if failed_count == len(SPECIALIST_NAMES):
                self.store.complete(
                    flow_id,
                    status="failed",
                    state=result,
                    summary="四个只读专家均未能完成，请检查草稿和本地工具",
                    error_code="all_specialists_failed",
                    error_message="所有独立专家执行失败，可在修复后重试",
                    owner_id=self.runtime_id,
                    attempt=attempt,
                )
            else:
                brief = result["executive_brief"]
                self.store.complete(
                    flow_id,
                    status="succeeded",
                    state=result,
                    summary=str(brief["headline"]),
                    owner_id=self.runtime_id,
                    attempt=attempt,
                )
        except _RuntimeClosing:
            # Leave the durable lease-owned attempt untouched. Heartbeat stops
            # in ``run`` and the next process recovers it only after expiry.
            return
        except _FlowCancelled:
            if active_step is not None:
                with suppress(ConflictError):
                    self.store.finish_step(
                        flow_id,
                        active_step,
                        status="cancelled",
                        error_code="flow_cancelled",
                        error_message="用户请求取消",
                        owner_id=self.runtime_id,
                        attempt=attempt,
                    )
            self._finish_inflight_steps(
                flow_id,
                inflight_steps,
                status="cancelled",
                error_code="flow_cancelled",
                error_message="用户请求取消",
                attempt=attempt,
            )
            self._complete_after_error(
                flow_id,
                status="cancelled",
                state=partial_state,
                summary="任务已按用户要求取消",
                attempt=attempt,
            )
        except NotFoundError as error:
            if active_step is not None:
                self._finish_failed_step(flow_id, active_step, error, attempt)
            self._finish_inflight_steps(
                flow_id,
                inflight_steps,
                status="failed",
                error_code="draft_unavailable",
                error_message=str(error),
                attempt=attempt,
            )
            self._complete_after_error(
                flow_id,
                status="blocked",
                state=partial_state,
                summary="绑定草稿不可用，任务暂时受阻",
                error_code="draft_unavailable",
                error_message=str(error),
                attempt=attempt,
            )
        except Exception as error:
            if active_step is not None:
                self._finish_failed_step(flow_id, active_step, error, attempt)
            self._finish_inflight_steps(
                flow_id,
                inflight_steps,
                status="failed",
                error_code=type(error).__name__,
                error_message=str(error),
                attempt=attempt,
            )
            self._complete_after_error(
                flow_id,
                status="failed",
                state=partial_state,
                summary="每日煤炭体检执行失败，可在排查后重试",
                error_code="flow_execution_failed",
                error_message=redact_text(str(error), maximum=2_000),
                attempt=attempt,
            )

    def _complete_after_error(
        self,
        flow_id: str,
        *,
        status: str,
        state: dict[str, Any],
        summary: str,
        error_code: str | None = None,
        error_message: str | None = None,
        attempt: int | None = None,
    ) -> None:
        try:
            flow = self.store.get(flow_id)
            owned_attempt = (
                int(attempt) if attempt is not None else int(flow["attempt"])
            )
            if (
                flow["status"] != "running"
                or flow.get("run_owner") != self.runtime_id
                or int(flow["attempt"]) != owned_attempt
            ):
                return
            self.store.complete(
                flow_id,
                status=status,
                state=state,
                summary=summary,
                error_code=error_code,
                error_message=error_message,
                owner_id=self.runtime_id,
                attempt=owned_attempt,
            )
        except (ConflictError, NotFoundError):
            return

    def _finish_failed_step(
        self,
        flow_id: str,
        sequence: int,
        error: Exception,
        attempt: int,
    ) -> None:
        try:
            self.store.finish_step(
                flow_id,
                sequence,
                status="failed",
                error_code=type(error).__name__,
                error_message=redact_text(str(error), maximum=1_000),
                owner_id=self.runtime_id,
                attempt=attempt,
            )
        except ConflictError:
            return

    def _finish_inflight_steps(
        self,
        flow_id: str,
        sequences: set[int],
        *,
        status: str,
        error_code: str,
        error_message: str,
        attempt: int,
    ) -> None:
        for sequence in sorted(sequences):
            with suppress(ConflictError, NotFoundError):
                self.store.finish_step(
                    flow_id,
                    sequence,
                    status=status,
                    error_code=error_code,
                    error_message=redact_text(error_message, maximum=1_000),
                    owner_id=self.runtime_id,
                    attempt=attempt,
                )
        sequences.clear()

    def _raise_if_cancelled(self, flow_id: str, attempt: int) -> None:
        if self._closed:
            raise _RuntimeClosing()
        if self.store.is_cancel_requested(
            flow_id,
            owner_id=self.runtime_id,
            attempt=attempt,
        ):
            raise _FlowCancelled()

    def _load_governed_context(
        self,
        flow: dict[str, Any],
        *,
        evidence_repository: FrozenEvidenceRepository,
    ) -> dict[str, Any]:
        """Load approved memories only as bounded explanatory context."""

        governance = getattr(self.service, "governance", None)
        if governance is None:
            return {
                "status": "unavailable",
                "memory_count": 0,
                "items": [],
                "usage": "context_only_never_overrides_evidence",
            }
        document = evidence_repository.get_draft(str(flow["draft_id"]))
        mine_id = document.get("mine_id")
        enterprise_id = document.get("enterprise_id")
        access = GovernanceAccess(
            actor_id=str(flow["actor_id"]),
            draft_ids=frozenset({str(flow["draft_id"])}),
            mine_ids=(
                frozenset({mine_id})
                if isinstance(mine_id, str) and mine_id
                else frozenset()
            ),
            enterprise_ids=(
                frozenset({enterprise_id})
                if isinstance(enterprise_id, str) and enterprise_id
                else frozenset()
            ),
        )
        try:
            memories = governance.list_memories(
                access,
                status="active",
                limit=20,
            )
        except Exception as error:
            return {
                "status": "unavailable",
                "memory_count": 0,
                "items": [],
                "error_code": type(error).__name__,
                "usage": "context_only_never_overrides_evidence",
            }
        items = []
        for memory in memories:
            items.append(
                {
                    "memory_id": memory.get("memory_id"),
                    "scope_type": memory.get("scope_type"),
                    "scope_id": memory.get("scope_id"),
                    "memory_key": memory.get("memory_key"),
                    "version": memory.get("version"),
                    "value_preview": redact_text(
                        canonical_json(memory.get("value")),
                        maximum=1_000,
                    ),
                    "record_sha256": memory.get("record_sha256"),
                }
            )
        return {
            "status": "loaded",
            "memory_count": len(items),
            "items": items,
            "usage": "context_only_never_overrides_evidence",
        }

    @staticmethod
    def _actor(value: Any) -> str:
        if not isinstance(value, str) or ACTOR_PATTERN.fullmatch(value) is None:
            raise ValueError("actor_id 格式非法")
        return value

    @staticmethod
    def _draft_id(value: Any) -> str:
        if (
            not isinstance(value, str)
            or DRAFT_ID_PATTERN.fullmatch(value) is None
        ):
            raise ValueError("draft_id 格式非法")
        return value

    @staticmethod
    def _workflow(value: Any) -> str:
        if not isinstance(value, str) or value not in SUPPORTED_WORKFLOWS:
            raise ValueError("不支持的智能体工作流")
        return value

    @staticmethod
    def _client_request_id(value: Any) -> str | None:
        if value is None:
            return None
        if (
            not isinstance(value, str)
            or CLIENT_REQUEST_ID_PATTERN.fullmatch(value) is None
        ):
            raise ValueError("client_request_id 格式非法")
        return value

    @staticmethod
    def _flow_id(value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("flow_id 格式非法")
        try:
            import uuid

            parsed = uuid.UUID(value)
        except (ValueError, AttributeError) as error:
            raise ValueError("flow_id 格式非法") from error
        return str(parsed)

    @staticmethod
    def _revision(value: Any) -> int | None:
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("expected_revision 必须是正整数")
        return value


class _FlowCancelled(RuntimeError):
    pass


class _RuntimeClosing(RuntimeError):
    pass


__all__ = ["AgentFlowRuntime"]
