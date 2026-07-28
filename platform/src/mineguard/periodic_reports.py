"""Deterministic monthly and quarterly regulatory report composition.

The report is deliberately a read-only projection over already-authorized
records.  It does not call an LLM, infer a legal conclusion, send messages, or
persist a new regulatory finding.  Missing reports, unavailable verification,
blocked verification and truncated source reads are represented explicitly.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from zoneinfo import ZoneInfo


ReportKind = Literal["monthly", "quarterly"]

_MONTH_PATTERN = re.compile(r"^(20[2-9][0-9]|2100)-(0[1-9]|1[0-2])$")
_QUARTER_PATTERN = re.compile(r"^(20[2-9][0-9]|2100)-Q([1-4])$")
_SUPPORTED_TIMEZONES = frozenset({"Asia/Shanghai"})
_OPEN_ALERT_STATUSES = frozenset(
    {"open", "acknowledged", "in_progress", "resolved"}
)
_LEVEL_RANK = {"blue": 1, "yellow": 2, "orange": 3, "red": 4}


@dataclass(frozen=True)
class ReportingPeriod:
    """One validated, fixed calendar reporting period."""

    kind: ReportKind
    key: str
    label: str
    timezone: str
    start_at: datetime
    end_at: datetime
    data_end_at: datetime
    complete: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "key": self.key,
            "label": self.label,
            "timezone": self.timezone,
            "start_at": self.start_at.isoformat(),
            "end_at": self.end_at.isoformat(),
            "data_end_at": self.data_end_at.isoformat(),
            "complete": self.complete,
        }


def resolve_reporting_period(
    kind: str,
    key: str,
    timezone: str,
    *,
    now: datetime | None = None,
) -> ReportingPeriod:
    """Resolve a strict month or quarter key to an explicit local-time window."""

    if kind not in {"monthly", "quarterly"}:
        raise ValueError("kind must be monthly or quarterly")
    if timezone not in _SUPPORTED_TIMEZONES:
        raise ValueError("timezone must be Asia/Shanghai")
    current = now or datetime.now(UTC)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must include an explicit UTC offset")
    local_zone = ZoneInfo(timezone)
    local_now = current.astimezone(local_zone)

    if kind == "monthly":
        match = _MONTH_PATTERN.fullmatch(key)
        if match is None:
            raise ValueError("monthly period must use YYYY-MM from 2020 to 2100")
        year, month = (int(value) for value in match.groups())
        start = datetime(year, month, 1, tzinfo=local_zone)
        if month == 12:
            next_start = datetime(year + 1, 1, 1, tzinfo=local_zone)
        else:
            next_start = datetime(year, month + 1, 1, tzinfo=local_zone)
        label = f"{year}年{month}月监管分析报告"
    else:
        match = _QUARTER_PATTERN.fullmatch(key)
        if match is None:
            raise ValueError(
                "quarterly period must use YYYY-Q1 through YYYY-Q4 "
                "from 2020 to 2100"
            )
        year, quarter = (int(value) for value in match.groups())
        month = 1 + (quarter - 1) * 3
        start = datetime(year, month, 1, tzinfo=local_zone)
        if quarter == 4:
            next_start = datetime(year + 1, 1, 1, tzinfo=local_zone)
        else:
            next_start = datetime(year, month + 3, 1, tzinfo=local_zone)
        label = f"{year}年第{quarter}季度监管分析报告"

    if start > local_now:
        raise ValueError("future reporting periods are not available")
    end = next_start - timedelta(microseconds=1)
    complete = local_now > end
    return ReportingPeriod(
        kind=kind,
        key=key,
        label=label,
        timezone=timezone,
        start_at=start,
        end_at=end,
        data_end_at=end if complete else local_now,
        complete=complete,
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        result = model_dump(mode="json")
        if isinstance(result, Mapping):
            return result
    raise TypeError("analytics must be a mapping or a Pydantic model")


def _parse_aware(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _integer(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _float_or_none(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if result == result else None


def _short_text(value: Any, maximum: int = 500) -> str:
    return str(value or "").strip()[:maximum]


def _reporting_state(row: Mapping[str, Any] | None) -> tuple[str, str]:
    if row is None or _integer(row.get("expected_reports")) == 0:
        return (
            "no_report_records",
            "本期没有可统计的应报记录；未覆盖部分不能判断为正常。",
        )
    expected = _integer(row.get("expected_reports"))
    received = _integer(row.get("received_reports"))
    if received < expected:
        return (
            "missing_report",
            f"应报 {expected} 矿次、实收 {received} 矿次，存在缺报。",
        )
    if _integer(row.get("data_issue_reports")):
        return (
            "data_incomplete",
            "本期记录已接收，但存在数据或计算条件不足。",
        )
    return (
        "received",
        f"已记录 {received} 矿次；“已接收”不等于数据真实或合规。",
    )


def _verification_state(
    run: Mapping[str, Any] | None,
) -> tuple[str, str]:
    if run is None:
        return (
            "not_run",
            "本期没有生产交叉核验结果，不能据此判断正常。",
        )
    status = str(run.get("status") or "")
    if status == "blocked":
        return (
            "blocked",
            "核验被数据质量或必要条件阻断，必须先补数或修复来源。",
        )
    if status == "insufficient_history":
        return (
            "insufficient_history",
            "合法历史样本不足；历史不足不能解释为正常。",
        )
    if status == "ready":
        level = _integer(run.get("overall_clue_level"))
        if level:
            return (
                "ready",
                f"核验已完成，技术线索等级为 {level}；需人工复核。",
            )
        return (
            "ready",
            "核验已完成且未记录关注级线索；这不是合规认定。",
        )
    return (
        "unknown",
        "核验状态无法识别，不能据此判断正常。",
    )


def _latest_period_verifications(
    runs: Sequence[Mapping[str, Any]],
    mine_ids: set[str],
    period: ReportingPeriod,
) -> tuple[dict[str, Mapping[str, Any]], int]:
    selected: dict[str, tuple[datetime, datetime, str, Mapping[str, Any]]] = {}
    invalid_times = 0
    start = period.start_at.astimezone(UTC)
    end = period.data_end_at.astimezone(UTC)
    for run in runs:
        mine_id = str(run.get("mine_id") or "")
        if mine_id not in mine_ids:
            continue
        window_end = _parse_aware(run.get("window_end"))
        if window_end is None:
            invalid_times += 1
            continue
        if not start <= window_end <= end:
            continue
        created_at = _parse_aware(run.get("created_at")) or window_end
        candidate = (
            window_end,
            created_at,
            str(run.get("run_id") or ""),
            run,
        )
        prior = selected.get(mine_id)
        if prior is None or candidate[:3] > prior[:3]:
            selected[mine_id] = candidate
    return ({mine_id: value[3] for mine_id, value in selected.items()}, invalid_times)


def _period_alerts(
    alerts: Sequence[Mapping[str, Any]],
    mine_ids: set[str],
    period: ReportingPeriod,
) -> tuple[dict[str, list[Mapping[str, Any]]], int]:
    selected = {mine_id: [] for mine_id in mine_ids}
    invalid_times = 0
    start = period.start_at.astimezone(UTC)
    end = period.data_end_at.astimezone(UTC)
    for alert in alerts:
        mine_id = str(alert.get("mine_id") or "")
        if mine_id not in mine_ids:
            continue
        detected = _parse_aware(alert.get("detected_at"))
        last_seen = _parse_aware(alert.get("last_seen_at"))
        if detected is None or last_seen is None:
            invalid_times += 1
            continue
        if detected <= end and last_seen >= start:
            selected[mine_id].append(alert)
    for values in selected.values():
        values.sort(
            key=lambda item: (
                -_LEVEL_RANK.get(str(item.get("level")), 0),
                str(item.get("alert_id") or ""),
            )
        )
    return selected, invalid_times


def _verification_excerpt(run: Mapping[str, Any] | None) -> dict[str, Any]:
    if run is None:
        return {
            "run_id": None,
            "status": "not_run",
            "overall_clue_level": None,
            "jointly_upgraded": False,
            "energy": None,
            "explosives": None,
            "technical_clues": [],
        }
    result = run.get("result")
    result_map = result if isinstance(result, Mapping) else {}
    clues = result_map.get("technical_clues")
    clue_items = clues if isinstance(clues, list) else []
    return {
        "run_id": _short_text(run.get("run_id"), 200) or None,
        "status": _short_text(run.get("status"), 50) or "unknown",
        "overall_clue_level": _integer(run.get("overall_clue_level")),
        "jointly_upgraded": bool(result_map.get("jointly_upgraded")),
        "energy": (
            dict(result_map["energy"])
            if isinstance(result_map.get("energy"), Mapping)
            else None
        ),
        "explosives": (
            dict(result_map["explosives"])
            if isinstance(result_map.get("explosives"), Mapping)
            else None
        ),
        "technical_clues": [
            _short_text(item) for item in clue_items[:5] if _short_text(item)
        ],
    }


def build_periodic_regulatory_report(
    *,
    period: ReportingPeriod,
    mine_ids: Collection[str],
    analytics: Any,
    alerts: Sequence[Mapping[str, Any]],
    verification_runs: Sequence[Mapping[str, Any]],
    mine_catalog: Sequence[Mapping[str, Any]],
    safety_dashboard: Mapping[str, Any],
    generated_at: datetime,
    governed_mode: bool,
    integrity_blocked: bool = False,
    source_limits: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    """Compose one mine-scoped, JSON-ready report without legal inference."""

    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must include an explicit UTC offset")
    scoped_ids = sorted({str(value) for value in mine_ids if str(value)})
    scoped_set = set(scoped_ids)
    analytics_map = _mapping(analytics)
    rankings = analytics_map.get("mine_risk_ranking")
    ranking_items = rankings if isinstance(rankings, list) else []
    ranking_by_mine = {
        str(item.get("mine_id")): item
        for item in ranking_items
        if isinstance(item, Mapping)
        and str(item.get("mine_id")) in scoped_set
    }
    catalog_by_mine = {
        str(item.get("mine_id")): item
        for item in mine_catalog
        if str(item.get("mine_id")) in scoped_set
    }
    verifications, invalid_verification_times = (
        _latest_period_verifications(
            verification_runs,
            scoped_set,
            period,
        )
    )
    alerts_by_mine, invalid_alert_times = _period_alerts(
        alerts,
        scoped_set,
        period,
    )

    mine_rows: list[dict[str, Any]] = []
    reporting_counts = {
        "received": 0,
        "missing_report": 0,
        "data_incomplete": 0,
        "no_report_records": 0,
    }
    verification_counts = {
        "ready": 0,
        "insufficient_history": 0,
        "blocked": 0,
        "not_run": 0,
        "unknown": 0,
    }
    alert_counts = {
        "operational_total": 0,
        "operational_open": 0,
        "shadow_total": 0,
        "blue": 0,
        "yellow": 0,
        "orange": 0,
        "red": 0,
    }
    attention_mines = 0

    for mine_id in scoped_ids:
        ranking = ranking_by_mine.get(mine_id)
        reporting_status, reporting_note = _reporting_state(ranking)
        reporting_counts[reporting_status] += 1
        verification = verifications.get(mine_id)
        verification_status, verification_note = _verification_state(
            verification
        )
        verification_counts[verification_status] += 1
        mine_alerts = alerts_by_mine.get(mine_id, [])
        operational = [
            item for item in mine_alerts if bool(item.get("operational", True))
        ]
        shadow = [
            item
            for item in mine_alerts
            if not bool(item.get("operational", True))
        ]
        for alert in operational:
            level = str(alert.get("level") or "")
            alert_counts["operational_total"] += 1
            if str(alert.get("status")) in _OPEN_ALERT_STATUSES:
                alert_counts["operational_open"] += 1
            if level in _LEVEL_RANK:
                alert_counts[level] += 1
        alert_counts["shadow_total"] += len(shadow)
        verification_level = (
            _integer(verification.get("overall_clue_level"))
            if verification is not None
            else 0
        )
        if operational or verification_level > 0:
            attention_mines += 1

        if reporting_status in {"no_report_records", "missing_report"}:
            overall_status = "blocked"
            overall_note = "报送缺口阻止完整研判，未覆盖部分不能判断正常。"
        elif verification_status == "blocked":
            overall_status = "blocked"
            overall_note = "生产核验被阻断，应先处理数据质量或必要条件。"
        elif operational or verification_level > 0:
            overall_status = "attention"
            overall_note = "存在技术线索，建议按原始凭证和现场情况人工复核。"
        elif verification_status in {
            "not_run",
            "insufficient_history",
            "unknown",
        }:
            overall_status = "incomplete"
            overall_note = "核验覆盖或历史样本不足，不能写成正常。"
        else:
            overall_status = "observed_without_attention"
            overall_note = (
                "本期已覆盖记录中未汇总出关注级线索；"
                "这不是安全、合规或责任认定。"
            )

        catalog = catalog_by_mine.get(mine_id, {})
        verification_excerpt = _verification_excerpt(verification)
        mine_rows.append(
            {
                "mine_id": mine_id,
                "mine_name": _short_text(
                    catalog.get("mine_name") or mine_id,
                    256,
                ),
                "enabled": bool(catalog.get("enabled", True)),
                "overall_status": overall_status,
                "overall_note": overall_note,
                "reporting": {
                    "status": reporting_status,
                    "note": reporting_note,
                    "expected_reports": (
                        _integer(ranking.get("expected_reports"))
                        if ranking is not None
                        else 0
                    ),
                    "received_reports": (
                        _integer(ranking.get("received_reports"))
                        if ranking is not None
                        else 0
                    ),
                    "coverage_rate": (
                        _float_or_none(ranking.get("coverage_rate"))
                        if ranking is not None
                        else None
                    ),
                    "data_issue_reports": (
                        _integer(ranking.get("data_issue_reports"))
                        if ranking is not None
                        else 0
                    ),
                },
                "casework": {
                    "open_cases": (
                        _integer(ranking.get("open_cases"))
                        if ranking is not None
                        else 0
                    ),
                    "open_p1_cases": (
                        _integer(ranking.get("open_p1_cases"))
                        if ranking is not None
                        else 0
                    ),
                    "open_p2_cases": (
                        _integer(ranking.get("open_p2_cases"))
                        if ranking is not None
                        else 0
                    ),
                    "pending_approval_cases": (
                        _integer(ranking.get("pending_approval_cases"))
                        if ranking is not None
                        else 0
                    ),
                },
                "safety_alerts": {
                    "operational_count": len(operational),
                    "shadow_count": len(shadow),
                    "open_operational_count": sum(
                        str(item.get("status")) in _OPEN_ALERT_STATUSES
                        for item in operational
                    ),
                    "highest_level": (
                        max(
                            (
                                str(item.get("level"))
                                for item in operational
                                if str(item.get("level")) in _LEVEL_RANK
                            ),
                            key=_LEVEL_RANK.__getitem__,
                            default=None,
                        )
                    ),
                    "items": [
                        {
                            "alert_id": _short_text(
                                item.get("alert_id"),
                                200,
                            ),
                            "level": _short_text(item.get("level"), 20),
                            "status": _short_text(item.get("status"), 30),
                            "title": _short_text(item.get("title"), 300),
                            "last_seen_at": item.get("last_seen_at"),
                        }
                        for item in operational[:5]
                    ],
                },
                "verification": {
                    **verification_excerpt,
                    "status": verification_status,
                    "note": verification_note,
                },
            }
        )

    limits = {
        str(name): bool(value)
        for name, value in (source_limits or {}).items()
    }
    quality_issues: list[str] = []
    if not period.complete:
        quality_issues.append("本报告期尚未结束，仅统计到 data_end_at。")
    if not governed_mode:
        quality_issues.append(
            "当前范围没有可信治理批次，领导统计来自历史或直接分析通道。"
        )
    if integrity_blocked:
        quality_issues.append(
            "至少一个范围内批次未通过完整性校验，相关批次未参与统计。"
        )
    if any(limits.values()):
        quality_issues.append(
            "至少一个数据源达到单次读取上限，报告可能不完整。"
        )
    if invalid_alert_times or invalid_verification_times:
        quality_issues.append(
            "部分安全预警或生产核验时间无效，已排除且未按正常处理。"
        )
    if reporting_counts["no_report_records"]:
        quality_issues.append(
            f"{reporting_counts['no_report_records']} 座矿井本期没有可统计应报记录。"
        )
    if reporting_counts["missing_report"]:
        quality_issues.append(
            f"{reporting_counts['missing_report']} 座矿井存在缺报。"
        )
    if verification_counts["not_run"]:
        quality_issues.append(
            f"{verification_counts['not_run']} 座矿井本期未运行生产交叉核验。"
        )
    if verification_counts["insufficient_history"]:
        quality_issues.append(
            f"{verification_counts['insufficient_history']} 座矿井历史样本不足。"
        )
    if verification_counts["blocked"]:
        quality_issues.append(
            f"{verification_counts['blocked']} 座矿井生产核验被阻断。"
        )

    hard_block = bool(
        integrity_blocked
        or any(limits.values())
        or verification_counts["blocked"]
        or reporting_counts["no_report_records"]
        or reporting_counts["missing_report"]
    )
    incomplete = bool(
        hard_block
        or not period.complete
        or not governed_mode
        or invalid_alert_times
        or invalid_verification_times
        or verification_counts["not_run"]
        or verification_counts["insufficient_history"]
        or verification_counts["unknown"]
    )
    quality_status = (
        "blocked"
        if hard_block
        else ("incomplete" if incomplete else "complete_for_review")
    )
    case_performance = analytics_map.get("case_performance")
    case_map = (
        dict(case_performance)
        if isinstance(case_performance, Mapping)
        else {}
    )
    current_summary = safety_dashboard.get("summary")
    current_shadow = safety_dashboard.get("shadow_summary")
    current_snapshot = {
        "generated_at": safety_dashboard.get("generated_at"),
        "summary": (
            dict(current_summary)
            if isinstance(current_summary, Mapping)
            else {}
        ),
        "shadow_summary": (
            dict(current_shadow)
            if isinstance(current_shadow, Mapping)
            else {}
        ),
        "evaluation_health": safety_dashboard.get("evaluation_health"),
        "responsibility_health": safety_dashboard.get(
            "responsibility_health"
        ),
        "note": (
            "这是生成时刻的安全驾驶舱快照，不等同于报告期末历史快照。"
        ),
    }
    reference_payload = {
        "period": period.as_dict(),
        "mine_ids": scoped_ids,
        "analytics_window": {
            "start": analytics_map.get("window_start"),
            "end": analytics_map.get("window_end"),
        },
        "alert_ids": sorted(
            _short_text(item.get("alert_id"), 200)
            for values in alerts_by_mine.values()
            for item in values
        ),
        "verification_run_ids": sorted(
            _short_text(item.get("run_id"), 200)
            for item in verifications.values()
        ),
    }
    reference = hashlib.sha256(
        json.dumps(
            reference_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:20]
    if not scoped_ids:
        summary_text = "当前账号没有可用矿井范围，报告不包含监管对象。"
    else:
        summary_text = (
            f"本期覆盖 {len(scoped_ids)} 座授权矿井；"
            f"{reporting_counts['missing_report']} 座存在缺报，"
            f"{reporting_counts['no_report_records']} 座无可统计应报记录，"
            f"{verification_counts['blocked']} 座核验被阻断，"
            f"{verification_counts['insufficient_history']} 座历史不足，"
            f"{attention_mines} 座汇总出需关注技术线索。"
        )

    return {
        "schema_version": "regulatory-periodic-report-v1",
        "report_reference": reference,
        "title": period.label,
        "period": period.as_dict(),
        "generated_at": generated_at.astimezone(UTC).isoformat(),
        "scope": {
            "basis": "authenticated_principal_mine_scope",
            "mine_ids": scoped_ids,
            "mine_count": len(scoped_ids),
        },
        "delivery": {
            "mode": "preview_only",
            "automatically_sent": False,
            "note": "报告仅供页面预览和本地打印，系统不会自动外发。",
        },
        "data_quality": {
            "status": quality_status,
            "issues": quality_issues,
            "governed_batch_mode": governed_mode,
            "integrity_blocked": integrity_blocked,
            "source_limits": limits,
            "invalid_alert_times": invalid_alert_times,
            "invalid_verification_times": invalid_verification_times,
        },
        "executive_summary": summary_text,
        "summary": {
            "mine_count": len(scoped_ids),
            "expected_report_count": _integer(
                analytics_map.get("expected_report_count")
            ),
            "received_report_count": _integer(
                analytics_map.get("received_report_count")
            ),
            "coverage_rate": _float_or_none(
                analytics_map.get("coverage_rate")
            ),
            "reporting": reporting_counts,
            "verification": verification_counts,
            "safety_alerts": alert_counts,
            "attention_mines": attention_mines,
            "casework": {
                "new_case_count": _integer(
                    case_map.get("new_case_count")
                ),
                "closed_case_count": _integer(
                    case_map.get("closed_case_count")
                ),
                "open_backlog_count": _integer(
                    case_map.get("open_backlog_count")
                ),
                "pending_approval_count": _integer(
                    case_map.get("pending_approval_count")
                ),
            },
        },
        "mines": mine_rows,
        "repeated_anomalies": (
            analytics_map.get("repeated_anomalies")
            if isinstance(analytics_map.get("repeated_anomalies"), list)
            else []
        ),
        "current_safety_snapshot": current_snapshot,
        "methodology": {
            "leadership_analytics_reused": True,
            "production_verification_reused": True,
            "safety_dashboard_reused": True,
            "period_alert_rule": (
                "纳入首次发现不晚于 data_end_at 且最后出现不早于 start_at "
                "的当前预警记录。"
            ),
            "verification_rule": (
                "每矿取 window_end 落在报告期内的最新一条生产核验结果。"
            ),
            "metric_definitions": (
                dict(analytics_map["metric_definitions"])
                if isinstance(
                    analytics_map.get("metric_definitions"),
                    Mapping,
                )
                else {}
            ),
        },
        "limitations": [
            "报告是生成时刻的确定性只读汇总，不还原报告期末历史数据库状态。",
            "无预警记录、核验 ready 或线索等级为 0 均不等于安全或合规。",
            "影子预警单独计数，不进入正式预警数量。",
            "报告不会自动发送、签批、立案或改变任何办理状态。",
        ],
        "disclaimer": (
            "本报告仅形成煤矿监管辅助技术线索，不是安全、违法、责任或处罚认定；"
            "应结合原始凭证、适用规程和现场情况由有权人员人工复核。"
        ),
    }


__all__ = [
    "ReportingPeriod",
    "build_periodic_regulatory_report",
    "resolve_reporting_period",
]
