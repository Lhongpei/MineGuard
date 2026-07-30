"""Built-in deterministic workflows for coal reporting health checks.

The workflow is deliberately composed from existing governed, read-only tools.
It has no model, shell, browser, network, draft-write, confirmation or
submission capability.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from queue import Empty, Queue
from threading import BoundedSemaphore, Thread
from typing import Any

from enterprise_agent.harness.sanitize import redact_text, sanitize
from enterprise_agent.tools import ToolProtocolError, ToolRegistry
from enterprise_agent.util import sha256_json, utc_text

from .models import DAILY_COAL_HEALTH_VERSION, DAILY_COAL_HEALTH_WORKFLOW
from .snapshot import prioritize_metric_codes

SPECIALIST_NAMES = ("source", "temporal", "physical", "historical")
REQUIRED_TOOL_NAMES = frozenset(
    {
        "draft_summary",
        "deterministic_preflight",
        "source_evidence_check",
        "compare_source_consistency",
        "summarize_provenance_lineage",
        "align_observation_time",
        "inspect_observation_continuity",
        "calculate_coal_flow_balance",
        "analyze_historical_trend",
        "explain_cross_validation",
    }
)
_MAX_ARRAY_DETAILS = 20
_SOURCE_DETAIL_METRICS = 12
_CROSS_VALIDATION_BATCH = 8
_TREND_DETAIL_METRICS = 12
_MAX_STRANDED_TOOL_THREADS = 64
_TOOL_THREAD_CAPACITY = BoundedSemaphore(_MAX_STRANDED_TOOL_THREADS)
_TREND_METRICS = frozenset(
    {
        "coal.reported_output_t",
        "coal.production_t",
        "coal.main_transport_t",
        "coal.purchase_in_t",
        "sales.raw_shipped_t",
        "coal.sale_out_t",
        "wash.feed_t",
        "coal.processing_input_t",
    }
)


def _compact(value: Any, *, depth: int = 0) -> Any:
    """Bound persisted evidence while retaining counts and content hashes."""

    if depth > 10:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        return {
            str(key)[:256]: _compact(child, depth=depth + 1)
            for key, child in list(value.items())[:500]
        }
    if isinstance(value, (list, tuple)):
        items = list(value)
        kept = [
            _compact(child, depth=depth + 1)
            for child in items[:_MAX_ARRAY_DETAILS]
        ]
        if len(items) <= _MAX_ARRAY_DETAILS:
            return kept
        return {
            "items": kept,
            "item_count": len(items),
            "items_truncated": True,
            "items_sha256": sha256_json(sanitize(items)),
        }
    if isinstance(value, str):
        return redact_text(value, maximum=8_000)
    return sanitize(value)


def _tool(
    registry: ToolRegistry,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    spec = registry.get(name)
    raw_timeout = 10.0 if spec.timeout_seconds is None else spec.timeout_seconds
    if (
        isinstance(raw_timeout, bool)
        or not isinstance(raw_timeout, (int, float))
        or not math.isfinite(float(raw_timeout))
        or float(raw_timeout) <= 0
    ):
        raise ToolProtocolError(
            "确定性煤炭工具超时配置非法",
            code="invalid_tool_timeout",
            path=f"$.tools.{name}",
        )
    timeout = min(float(raw_timeout), 30.0)
    if not _TOOL_THREAD_CAPACITY.acquire(blocking=False):
        raise ToolProtocolError(
            "确定性煤炭工具隔离容量已满",
            code="tool_capacity_exhausted",
            path=f"$.tools.{name}",
        )
    outcome: Queue[tuple[bool, Any]] = Queue(maxsize=1)

    def execute() -> None:
        try:
            outcome.put((True, registry.execute(name, arguments)))
        except BaseException as error:
            outcome.put((False, error))
        finally:
            _TOOL_THREAD_CAPACITY.release()

    # A Python thread cannot be forcibly killed safely. A bounded daemon thread
    # gives the workflow a hard deadline and, unlike ThreadPoolExecutor, cannot
    # keep interpreter shutdown blocked if a defective read-only tool never
    # returns. The semaphore prevents unbounded accumulation.
    worker = Thread(
        target=execute,
        name=f"coal-tool-{name[:24]}",
        daemon=True,
    )
    worker.start()
    try:
        succeeded, value = outcome.get(timeout=timeout)
    except Empty as error:
        raise ToolProtocolError(
            "确定性煤炭工具执行超时",
            code="tool_timeout",
            path=f"$.tools.{name}",
        ) from error
    if not succeeded:
        if isinstance(value, Exception):
            raise value
        raise ToolProtocolError(
            "确定性煤炭工具异常终止",
            code="tool_aborted",
            path=f"$.tools.{name}",
        )
    result = value
    return {
        "tool_name": name,
        "summary": redact_text(result.summary, maximum=1_000),
        "data": _compact(result.data),
        "artifacts": _compact(list(result.artifacts)),
        "evidence_grounding": registry.get(name).evidence_grounding,
    }


def validate_read_only_registry(registry: ToolRegistry) -> None:
    available = {spec.name: spec for spec in registry.list_specs()}
    missing = sorted(REQUIRED_TOOL_NAMES - set(available))
    if missing:
        raise ValueError("每日煤炭体检缺少只读工具：" + "、".join(missing))
    unsafe = sorted(
        name
        for name in REQUIRED_TOOL_NAMES
        if (
            available[name].mutating
            or available[name].requires_approval
            or available[name].network_access
        )
    )
    if unsafe:
        raise ValueError(
            "每日煤炭体检只允许本地只读、非联网工具：" + "、".join(unsafe)
        )


def prepare_daily_health(
    registry: ToolRegistry,
    *,
    draft_id: str,
    selected_metric_codes: list[str] | None = None,
    metric_coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Load one immutable evidence snapshot and determine metric scope."""

    summary = _tool(registry, "draft_summary", {"draft_id": draft_id})
    preflight = _tool(
        registry,
        "deterministic_preflight",
        {"draft_id": draft_id},
    )
    metric_groups = summary["data"].get("metric_groups", [])
    if isinstance(metric_groups, dict):
        metric_groups = metric_groups.get("items", [])
    summary_metric_codes = prioritize_metric_codes(
        {
            str(item["metric_code"])
            for item in metric_groups
            if isinstance(item, dict)
            and isinstance(item.get("metric_code"), str)
            and item["metric_code"]
        }
    )
    metric_codes = (
        prioritize_metric_codes(selected_metric_codes)
        if selected_metric_codes is not None
        else summary_metric_codes
    )
    coverage = (
        dict(metric_coverage)
        if isinstance(metric_coverage, dict)
        else {
            "strategy": "coal_regulatory_priority_then_code",
            "total_metric_count": len(summary_metric_codes),
            "analyzed_metric_count": len(metric_codes),
            "omitted_metric_count": max(
                0,
                len(summary_metric_codes) - len(metric_codes),
            ),
            "complete": len(metric_codes) >= len(summary_metric_codes),
            "analyzed_metric_codes": metric_codes,
            "omitted_metric_codes": [],
            "omitted_metric_codes_truncated": False,
            "omitted_metric_codes_sha256": sha256_json([]),
        }
    )
    return {
        "draft_id": draft_id,
        "draft_revision": summary["data"].get("revision"),
        "document_sha256": summary["data"].get("document_sha256"),
        "mine_id": summary["data"].get("mine_id"),
        "metric_codes": metric_codes,
        "metric_coverage": coverage,
        "summary": summary,
        "preflight": preflight,
    }


def _source_specialist(
    registry: ToolRegistry,
    prepared: dict[str, Any],
) -> dict[str, Any]:
    draft_id = str(prepared["draft_id"])
    metric_codes = list(prepared.get("metric_codes") or [])
    plan: list[tuple[str, dict[str, Any]]] = [
        ("source_evidence_check", {"draft_id": draft_id}),
        ("summarize_provenance_lineage", {"draft_id": draft_id}),
    ]
    # Detailed pairwise comparison is risk-prioritized and explicitly bounded;
    # the global source evidence tool still covers every observation.
    plan.extend(
        (
            "compare_source_consistency",
            {"draft_id": draft_id, "metric_code": metric_code},
        )
        for metric_code in metric_codes[:_SOURCE_DETAIL_METRICS]
    )
    return _run_tool_group(
        registry,
        specialist="source",
        plan=tuple(plan),
    )


def _temporal_specialist(
    registry: ToolRegistry,
    prepared: dict[str, Any],
) -> dict[str, Any]:
    draft_id = str(prepared["draft_id"])
    metric_codes = list(prepared.get("metric_codes") or [])
    align_args: dict[str, Any] = {"draft_id": draft_id}
    continuity_args: dict[str, Any] = {"draft_id": draft_id}
    if metric_codes:
        align_args["metric_codes"] = metric_codes
        continuity_args["metric_codes"] = metric_codes
    return _run_tool_group(
        registry,
        specialist="temporal",
        plan=(
            ("align_observation_time", align_args),
            ("inspect_observation_continuity", continuity_args),
        ),
    )


def _physical_specialist(
    registry: ToolRegistry,
    prepared: dict[str, Any],
) -> dict[str, Any]:
    return _run_tool_group(
        registry,
        specialist="physical",
        plan=(
            (
                "calculate_coal_flow_balance",
                {"draft_id": str(prepared["draft_id"])},
            ),
        ),
    )


def _historical_specialist(
    registry: ToolRegistry,
    prepared: dict[str, Any],
) -> dict[str, Any]:
    metric_codes = list(prepared.get("metric_codes") or [])
    if not metric_codes:
        return {
            "specialist": "historical",
            "status": "incomplete",
            "tool_count": 0,
            "succeeded_tool_count": 0,
            "tools": [],
            "errors": [
                {
                    "code": "no_metric",
                    "message": "草稿没有可用于历史交叉核验的指标",
                }
            ],
            "read_only": True,
            "network_access": False,
        }
    plan: list[tuple[str, dict[str, Any]]] = []
    for offset in range(0, len(metric_codes), _CROSS_VALIDATION_BATCH):
        plan.append(
            (
                "explain_cross_validation",
                {
                    "draft_id": str(prepared["draft_id"]),
                    "metric_codes": metric_codes[
                        offset : offset + _CROSS_VALIDATION_BATCH
                    ],
                },
            )
        )
    plan.extend(
        (
            "analyze_historical_trend",
            {
                "draft_id": str(prepared["draft_id"]),
                "metric_code": metric_code,
            },
        )
        for metric_code in [
            code for code in metric_codes if code in _TREND_METRICS
        ][:_TREND_DETAIL_METRICS]
    )
    return _run_tool_group(
        registry,
        specialist="historical",
        plan=tuple(plan),
    )


def _run_tool_group(
    registry: ToolRegistry,
    *,
    specialist: str,
    plan: tuple[tuple[str, dict[str, Any]], ...],
) -> dict[str, Any]:
    tools: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for name, arguments in plan:
        try:
            tools.append(_tool(registry, name, arguments))
        except Exception as error:
            errors.append(
                {
                    "tool_name": name,
                    "code": str(
                        getattr(error, "code", type(error).__name__)
                    ),
                    "message": redact_text(str(error), maximum=1_000),
                }
            )
    status = (
        "completed"
        if not errors
        else ("failed" if not tools else "partial")
    )
    return {
        "specialist": specialist,
        "status": status,
        "tool_count": len(plan),
        "succeeded_tool_count": len(tools),
        "tools": tools,
        "errors": errors,
        "read_only": True,
        "network_access": False,
    }


def execute_specialist(
    registry: ToolRegistry,
    specialist: str,
    prepared: dict[str, Any],
) -> dict[str, Any]:
    dispatch = {
        "source": _source_specialist,
        "temporal": _temporal_specialist,
        "physical": _physical_specialist,
        "historical": _historical_specialist,
    }
    try:
        executor = dispatch[specialist]
    except KeyError as error:
        raise ValueError("未知煤炭核验专家") from error
    return executor(registry, prepared)


def _tool_data(
    specialists: Mapping[str, Any],
    specialist: str,
    tool_name: str,
) -> dict[str, Any]:
    result = specialists.get(specialist, {})
    for tool in result.get("tools", []) if isinstance(result, dict) else []:
        if isinstance(tool, dict) and tool.get("tool_name") == tool_name:
            data = tool.get("data")
            return data if isinstance(data, dict) else {}
    return {}


def _tool_data_all(
    specialists: Mapping[str, Any],
    specialist: str,
    tool_name: str,
) -> list[dict[str, Any]]:
    result = specialists.get(specialist, {})
    return [
        data
        for tool in result.get("tools", []) if isinstance(result, dict)
        if isinstance(tool, dict) and tool.get("tool_name") == tool_name
        if isinstance((data := tool.get("data")), dict)
    ]


def _integer(data: Mapping[str, Any], name: str) -> int:
    value = data.get(name, 0)
    return (
        int(value)
        if isinstance(value, int) and not isinstance(value, bool)
        else 0
    )


def build_critic(
    prepared: dict[str, Any],
    specialists: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    """Act as a deterministic dissenting reviewer over independent evidence."""

    preflight = prepared["preflight"]["data"]
    source = _tool_data(
        specialists, "source", "source_evidence_check"
    )
    temporal = _tool_data(
        specialists, "temporal", "align_observation_time"
    )
    continuity = _tool_data(
        specialists, "temporal", "inspect_observation_continuity"
    )
    physical = _tool_data(
        specialists, "physical", "calculate_coal_flow_balance"
    )
    historical_batches = _tool_data_all(
        specialists,
        "historical",
        "explain_cross_validation",
    )
    governed_context = prepared.get("governed_context")
    if not isinstance(governed_context, dict):
        governed_context = {}

    conflicts: list[dict[str, Any]] = []
    blocking_count = _integer(preflight, "blocking_count")
    warning_count = _integer(preflight, "warning_count")
    if blocking_count:
        conflicts.append(
            {
                "code": "preflight_blocking",
                "severity": "critical",
                "count": blocking_count,
                "message": "确定性预检存在阻断项",
            }
        )
    observation_count = _integer(source, "observation_count")
    digest_match_count = _integer(source, "payload_digest_match_count")
    if observation_count > digest_match_count:
        conflicts.append(
            {
                "code": "source_digest_mismatch",
                "severity": "high",
                "count": observation_count - digest_match_count,
                "message": "部分来源载荷摘要缺失或不匹配",
            }
        )
    outside_balance = _integer(physical, "outside_tolerance_count")
    if outside_balance:
        conflicts.append(
            {
                "code": "physical_balance_outside_tolerance",
                "severity": "high",
                "count": outside_balance,
                "message": "煤流平衡存在超出预检容差的方程",
            }
        )
    delayed = _integer(temporal, "delayed_count")
    outside_window = _integer(temporal, "outside_window_count")
    continuity_findings = _integer(continuity, "finding_count")
    temporal_count = delayed + outside_window + continuity_findings
    if temporal_count:
        conflicts.append(
            {
                "code": "temporal_quality_finding",
                "severity": "medium",
                "count": temporal_count,
                "message": "时间对齐或连续性存在需复核记录",
            }
        )
    historical_blocking = sum(
        _integer(item, "blocking_count") for item in historical_batches
    )
    historical_warning = sum(
        _integer(item, "warning_count") for item in historical_batches
    )
    historical_incomplete = sum(
        _integer(item, "incomplete_component_count")
        for item in historical_batches
    )
    if historical_blocking or historical_warning or historical_incomplete:
        conflicts.append(
            {
                "code": "cross_validation_attention",
                "severity": (
                    "high" if historical_blocking else "medium"
                ),
                "count": (
                    historical_blocking
                    + historical_warning
                    + historical_incomplete
                ),
                "message": "历史与交叉凭证核验存在异常或证据不足",
            }
        )
    if governed_context.get("status") == "unavailable":
        conflicts.append(
            {
                "code": "governed_context_unavailable",
                "severity": "medium",
                "count": 1,
                "message": "受治理业务记忆未能读取，本次未将其用于解释",
            }
        )
    metric_coverage = prepared.get("metric_coverage")
    if not isinstance(metric_coverage, dict):
        metric_coverage = {}
    omitted_metric_count = _integer(
        metric_coverage,
        "omitted_metric_count",
    )
    if omitted_metric_count:
        conflicts.append(
            {
                "code": "metric_coverage_limited",
                "severity": "medium",
                "count": omitted_metric_count,
                "message": (
                    f"本次按监管重要度分析了 "
                    f"{_integer(metric_coverage, 'analyzed_metric_count')}/"
                    f"{_integer(metric_coverage, 'total_metric_count')} 个指标；"
                    "其余指标未静默忽略，已列入覆盖范围说明"
                ),
            }
        )

    failed = sorted(
        name
        for name in SPECIALIST_NAMES
        if specialists.get(name, {}).get("status") in {"failed", "partial"}
    )
    incomplete = sorted(
        name
        for name in SPECIALIST_NAMES
        if specialists.get(name, {}).get("status") == "incomplete"
    )
    if failed:
        conflicts.append(
            {
                "code": "specialist_execution_incomplete",
                "severity": "high",
                "count": len(failed),
                "message": "部分独立专家未完整执行",
            }
        )
    severities = {item["severity"] for item in conflicts}
    priority = (
        "critical"
        if "critical" in severities
        else (
            "high"
            if "high" in severities
            else (
                "medium"
                if "medium" in severities or warning_count or incomplete
                else "low"
            )
        )
    )
    return {
        "reviewer": "deterministic_dissenting_critic",
        "priority": priority,
        "independent_specialist_count": len(SPECIALIST_NAMES),
        "completed_specialists": sorted(
            name
            for name in SPECIALIST_NAMES
            if specialists.get(name, {}).get("status") == "completed"
        ),
        "failed_or_partial_specialists": failed,
        "incomplete_specialists": incomplete,
        "evidence_conflicts": conflicts,
        "conflict_count": len(conflicts),
        "evidence_snapshot": {
            "draft_revision": prepared.get("draft_revision"),
            "document_sha256": prepared.get("document_sha256"),
            "history_snapshot_sha256": (
                prepared.get("evidence_snapshot", {}).get(
                    "history_snapshot_sha256"
                )
                if isinstance(prepared.get("evidence_snapshot"), dict)
                else None
            ),
            "immutable": True,
            "metric_codes": list(prepared.get("metric_codes") or []),
            "metric_coverage": metric_coverage,
            "approved_memory_count": _integer(
                governed_context,
                "memory_count",
            ),
        },
        "limitations": [
            "结果只来自草稿、已成功提交历史和本地确定性规则",
            "人工批准的业务记忆仅作解释上下文，不能覆盖观测或计算证据",
            "来源签名格式检查不等于持密钥完成密码学验签",
            "统计异常不能单独证明原因、责任或违法事实",
            "本流程不修改、确认或提交企业草稿",
            "本次结论固定在任务启动时的证据快照，后续修改需重新体检",
            (
                "指标超过单次安全预算时按煤炭监管重要度优先分析，"
                "覆盖不足会降低结论等级并显式列出"
            ),
        ],
        "not_a_regulatory_determination": True,
    }


def _specialist_summary(
    specialists: Mapping[str, dict[str, Any]],
    specialist: str,
) -> str:
    result = specialists.get(specialist, {})
    tools = result.get("tools", []) if isinstance(result, dict) else []
    summaries = [
        str(tool["summary"])
        for tool in tools
        if isinstance(tool, dict) and isinstance(tool.get("summary"), str)
    ]
    if summaries:
        return "；".join(summaries)[:1_000]
    errors = result.get("errors", []) if isinstance(result, dict) else []
    if errors:
        return "证据不足或工具未完成，需人工查看任务详情"
    return "本维度没有可评价证据"


def build_executive_brief(
    prepared: dict[str, Any],
    specialists: Mapping[str, dict[str, Any]],
    critic: Mapping[str, Any],
) -> dict[str, Any]:
    priority = str(critic["priority"])
    headline = {
        "critical": "发现阻断项，请优先组织人工复核",
        "high": "发现高关注证据，请尽快核对原始凭证",
        "medium": "存在需关注的数据质量或证据完整性问题",
        "low": "未发现显著交叉核验冲突，仍需按流程人工复核",
    }[priority]
    conflicts = critic.get("evidence_conflicts", [])
    actions: list[str] = []
    codes = {
        item.get("code")
        for item in conflicts
        if isinstance(item, dict)
    }
    if "preflight_blocking" in codes:
        actions.append("先处理预检阻断项，再考虑确认或提交")
    if "source_digest_mismatch" in codes:
        actions.append("回看来源载荷、导入清单和原始凭证")
    if "physical_balance_outside_tolerance" in codes:
        actions.append("复核产量、主运、库存收发存和原煤去向口径")
    if "temporal_quality_finding" in codes:
        actions.append("核对观测时间、接收延迟、序号重置和缺测")
    if "cross_validation_attention" in codes:
        actions.append("对照同矿历史合法数据并解释工况变化")
    if "governed_context_unavailable" in codes:
        actions.append("核查受治理业务记忆的完整性和访问范围")
    if "metric_coverage_limited" in codes:
        actions.append("对覆盖范围中尚未分析的指标另行发起专项体检")
    if not actions:
        actions.append("按企业内部复核流程查看原始凭证并由人员确认")
    governed_context = prepared.get("governed_context")
    if not isinstance(governed_context, dict):
        governed_context = {}
    context_items = governed_context.get("items")
    if not isinstance(context_items, list):
        context_items = []
    context_notes = [
        {
            "memory_id": item.get("memory_id"),
            "memory_key": item.get("memory_key"),
            "scope_type": item.get("scope_type"),
            "version": item.get("version"),
            "value_preview": item.get("value_preview"),
        }
        for item in context_items[:10]
        if isinstance(item, dict)
    ]
    key_points = [
        {
            "dimension": "来源凭证",
            "summary": _specialist_summary(specialists, "source"),
        },
        {
            "dimension": "时序质量",
            "summary": _specialist_summary(specialists, "temporal"),
        },
        {
            "dimension": "物理平衡",
            "summary": _specialist_summary(specialists, "physical"),
        },
        {
            "dimension": "历史与交叉验证",
            "summary": _specialist_summary(specialists, "historical"),
        },
    ]
    metric_coverage = prepared.get("metric_coverage")
    if isinstance(metric_coverage, dict):
        key_points.append(
            {
                "dimension": "分析覆盖",
                "summary": (
                    f"本次分析 "
                    f"{_integer(metric_coverage, 'analyzed_metric_count')}/"
                    f"{_integer(metric_coverage, 'total_metric_count')} 个指标；"
                    + (
                        "已完整覆盖当前草稿指标。"
                        if metric_coverage.get("complete")
                        else "其余指标已显式列入未覆盖清单，结论置信范围已降级。"
                    )
                ),
            }
        )
    if context_notes:
        key_points.append(
            {
                "dimension": "受治理业务记忆",
                "summary": (
                    f"已读取 {len(context_notes)} 条人工批准的背景说明；"
                    "仅用于解释，不参与替代观测或计算。"
                ),
            }
        )
    return {
        "headline": headline,
        "priority": priority,
        "mine_id": prepared.get("mine_id"),
        "draft_revision": prepared.get("draft_revision"),
        "metric_coverage": prepared.get("metric_coverage"),
        "evidence_confidence": (
            "limited"
            if isinstance(prepared.get("metric_coverage"), dict)
            and not prepared["metric_coverage"].get("complete", True)
            else "full_scope"
        ),
        "key_points": key_points,
        "approved_context_notes": context_notes,
        "approved_context_usage": governed_context.get(
            "usage",
            "context_only_never_overrides_evidence",
        ),
        "next_actions": actions[:5],
        "disclaimer": (
            "以上为煤炭业务智能辅助体检，不是监管认定、法律意见或"
            "提交指令；请结合原始凭证和现场情况人工复核。"
            "智能体未执行确认或提交。"
        ),
    }


def assemble_daily_health_result(
    prepared: dict[str, Any],
    specialists: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    critic = build_critic(prepared, specialists)
    brief = build_executive_brief(prepared, specialists, critic)
    return {
        "workflow": DAILY_COAL_HEALTH_WORKFLOW,
        "workflow_version": DAILY_COAL_HEALTH_VERSION,
        "generated_at": utc_text(),
        "draft_id": prepared["draft_id"],
        "draft_revision": prepared.get("draft_revision"),
        "document_sha256": prepared.get("document_sha256"),
        "evidence_snapshot": prepared.get("evidence_snapshot"),
        "governed_context": prepared.get(
            "governed_context",
            {
                "status": "unavailable",
                "memory_count": 0,
                "items": [],
                "usage": "context_only_never_overrides_evidence",
            },
        ),
        "preflight": prepared["preflight"],
        "specialists": {
            name: specialists[name]
            for name in SPECIALIST_NAMES
            if name in specialists
        },
        "critic": critic,
        "executive_brief": brief,
        "read_only": True,
        "network_access": False,
        "confirmed": False,
        "submitted": False,
        "not_a_regulatory_determination": True,
    }


__all__ = [
    "REQUIRED_TOOL_NAMES",
    "SPECIALIST_NAMES",
    "assemble_daily_health_result",
    "build_critic",
    "build_executive_brief",
    "execute_specialist",
    "prepare_daily_health",
    "validate_read_only_registry",
]
