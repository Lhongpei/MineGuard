"""Deterministic, explicitly non-production data for leadership demos.

The generator deliberately exercises the real portfolio solver, immutable
feature extraction, temporal detector, edge dashboard and production
verification read models.  It does not invent a second "demo algorithm".

Two safety boundaries are kept separate:

* service functions only create or delete records in the ``pilot-demo90-`` /
  ``DEMO-`` namespaces and mark every batch context as ``demo_seed``;
* CLI callers must use a state directory carrying the ownership marker
  created by :func:`claim_demo_state_directory`.

This lets an embedded test server use the pure service functions while the
operator-facing CLI defaults to an isolated ``.mineguard-demo`` state tree.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from . import __version__
from .casework import LocalRepository, canonical_json, sha256_json
from .edge_ingest import EdgeTelemetryBatch
from .edge_store import EdgeTelemetryRepository
from .models import ProductionAnalysisRequest
from .monitoring import refresh_temporal_audit
from .portfolio import (
    PortfolioAnalysisRequest,
    analyze_production_portfolio,
)
from .verification import (
    HistoricalVerificationSample,
    ManualReviewLabel,
    ProductionVerificationRequest,
    analyze_verification,
)


DEMO_DATASET_ID = "qinyuan-leadership-90d-v1"
DEMO_SCHEMA_VERSION = "mineguard-demo-seed-v1"
DEMO_BATCH_PREFIX = "pilot-demo90-"
DEMO_MINE_PREFIX = "DEMO-M"
DEMO_EDGE_CLIENT_PREFIX = "demo-edge-"
DEMO_ACTOR = "system:demo-seed"
DEFAULT_DEMO_STATE_DIRECTORY = ".mineguard-demo"
DEMO_STATE_MARKER = ".mineguard-demo-owner.json"
MIN_DEMO_DAYS = 21
MAX_DEMO_DAYS = 365


class DemoSeedError(RuntimeError):
    """A safe, operator-readable demo seed error."""


class DemoStateOwnershipError(DemoSeedError):
    """The selected state directory is not owned by the demo generator."""


@dataclass(frozen=True)
class DemoMine:
    mine_id: str
    name: str
    scenario: str
    scenario_label: str
    base_output_t: float
    longitude: float
    latitude: float
    gas_category: str


DEMO_MINES: tuple[DemoMine, ...] = (
    DemoMine(
        "DEMO-M001",
        "演示一矿（稳定生产）",
        "normal",
        "稳定正常基线",
        5_200.0,
        112.319,
        36.514,
        "低瓦斯",
    ),
    DemoMine(
        "DEMO-M002",
        "演示二矿（缓慢漂移）",
        "slow_drift",
        "上报量缓慢漂移",
        5_750.0,
        112.367,
        36.488,
        "高瓦斯",
    ),
    DemoMine(
        "DEMO-M003",
        "演示三矿（变化点）",
        "change_point",
        "中后段突发变化点",
        4_850.0,
        112.412,
        36.535,
        "高瓦斯",
    ),
    DemoMine(
        "DEMO-M004",
        "演示四矿（重复异常）",
        "repeated_anomaly",
        "周期性重复异常",
        6_100.0,
        112.458,
        36.472,
        "低瓦斯",
    ),
    DemoMine(
        "DEMO-M005",
        "演示五矿（间歇缺报）",
        "missing_reports",
        "间歇缺报与数据待补",
        4_350.0,
        112.287,
        36.445,
        "低瓦斯",
    ),
    DemoMine(
        "DEMO-M006",
        "演示六矿（安全与来源健康）",
        "source_and_safety",
        "来源健康和安全预警",
        5_450.0,
        112.505,
        36.518,
        "煤与瓦斯突出",
    ),
)


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _anchor_date(value: date | datetime | str | None) -> date:
    if value is None:
        return datetime.now(UTC).date()
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise DemoSeedError("anchor datetime must include a timezone")
        return value.astimezone(UTC).date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError as error:
        raise DemoSeedError("anchor_date must use YYYY-MM-DD") from error


def _validate_days(days: int) -> int:
    if isinstance(days, bool) or not isinstance(days, int):
        raise DemoSeedError("days must be an integer")
    if not MIN_DEMO_DAYS <= days <= MAX_DEMO_DAYS:
        raise DemoSeedError(
            f"days must be between {MIN_DEMO_DAYS} and {MAX_DEMO_DAYS}"
        )
    return days


def _demo_dataset(anchor: date, days: int) -> dict[str, Any]:
    return {
        "active": True,
        "dataset_id": DEMO_DATASET_ID,
        "schema_version": DEMO_SCHEMA_VERSION,
        "anchor_date": anchor.isoformat(),
        "days": days,
        "mine_count": len(DEMO_MINES),
        "classification": "synthetic_demo_only",
        "regulatory_use": "prohibited",
    }


def _manifest_table(repository: LocalRepository) -> None:
    with repository._lock, repository._connection:  # noqa: SLF001
        repository._connection.execute(  # noqa: SLF001
            """
            CREATE TABLE IF NOT EXISTS demo_seed_manifests (
                dataset_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                anchor_date TEXT NOT NULL,
                days INTEGER NOT NULL,
                mine_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                summary_json TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            )
            """
        )


def _manifest(repository: LocalRepository) -> dict[str, Any] | None:
    _manifest_table(repository)
    with repository._lock:  # noqa: SLF001
        row = repository._connection.execute(  # noqa: SLF001
            """
            SELECT * FROM demo_seed_manifests
            WHERE dataset_id = ?
            """,
            (DEMO_DATASET_ID,),
        ).fetchone()
    if row is None:
        return None
    result = {key: row[key] for key in row.keys()}
    result["summary"] = (
        json.loads(result.pop("summary_json"))
        if result["summary_json"] is not None
        else None
    )
    return result


def _set_manifest(
    repository: LocalRepository,
    *,
    anchor: date,
    days: int,
    status: str,
    summary: dict[str, Any] | None,
) -> None:
    now = _utc_text(datetime.now(UTC))
    with repository._lock, repository._connection:  # noqa: SLF001
        repository._connection.execute(  # noqa: SLF001
            """
            INSERT INTO demo_seed_manifests(
                dataset_id, schema_version, anchor_date, days, mine_count,
                status, summary_json, created_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(dataset_id) DO UPDATE SET
                schema_version = excluded.schema_version,
                anchor_date = excluded.anchor_date,
                days = excluded.days,
                mine_count = excluded.mine_count,
                status = excluded.status,
                summary_json = excluded.summary_json,
                completed_at = excluded.completed_at
            """,
            (
                DEMO_DATASET_ID,
                DEMO_SCHEMA_VERSION,
                anchor.isoformat(),
                days,
                len(DEMO_MINES),
                status,
                canonical_json(summary) if summary is not None else None,
                now,
                now if status == "ready" else None,
            ),
        )


def _batch_id(window_end: datetime) -> str:
    return f"{DEMO_BATCH_PREFIX}{window_end:%Y%m%d}"


def _season_code(day: date) -> str:
    return {
        12: "winter",
        1: "winter",
        2: "winter",
        3: "spring",
        4: "spring",
        5: "spring",
        6: "summer",
        7: "summer",
        8: "summer",
        9: "autumn",
        10: "autumn",
        11: "autumn",
    }[day.month]


def _reported_gap_ratio(mine: DemoMine, index: int, days: int) -> float:
    if mine.scenario == "slow_drift":
        start = max(20, days // 3)
        if index < start:
            return 0.0
        progress = (index - start + 1) / max(1, days - start)
        return 0.02 + 0.17 * progress
    if mine.scenario == "change_point":
        change = max(20, (days * 2) // 3)
        return 0.19 if index >= change else 0.0
    if mine.scenario == "repeated_anomaly":
        # Three-point episodes separated by normal recovery windows.
        return 0.22 if index >= 20 and index % 14 in {7, 8, 9} else 0.0
    return 0.0


def _is_missing(mine: DemoMine, index: int, days: int) -> bool:
    return (
        mine.scenario == "missing_reports"
        and (
            index == days - 1
            or (index >= 8 and index % 7 in {0, 1})
        )
    )


def _quality(
    *,
    completeness: float = 1.0,
    timeliness: float = 1.0,
    device_health: float = 1.0,
    blocking_flags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "completeness": completeness,
        "timeliness": timeliness,
        "device_health": device_health,
        "calibration": 0.98,
        "clock": 1.0,
        "lineage": 1.0,
        "uniqueness": 1.0,
        "signature_valid": True,
        "blocking_flags": blocking_flags or [],
        "unverified_dimensions": [],
    }


def _production_request(
    mine: DemoMine,
    *,
    index: int,
    days: int,
    window_start: datetime,
    window_end: datetime,
) -> ProductionAnalysisRequest:
    weekly = math.sin(index * 2.0 * math.pi / 7.0)
    monthly = math.sin(index * 2.0 * math.pi / 30.0)
    actual = mine.base_output_t * (1.0 + 0.035 * weekly + 0.02 * monthly)
    gap_ratio = _reported_gap_ratio(mine, index, days)
    normal_report_noise = 18.0 * math.sin(index * 1.71)
    reported = actual * (1.0 - gap_ratio) + normal_report_noise
    wash_feed = actual * (0.78 + 0.012 * math.sin(index / 5.0))
    raw_sales = actual * (0.13 + 0.008 * math.cos(index / 4.0))
    inventory_change = actual - wash_feed - raw_sales
    date_code = window_end.strftime("%Y%m%d")
    quality = _quality()
    observations = [
        {
            "observation_id": f"{mine.mine_id}-{date_code}-report",
            "metric_code": "coal.reported_output_t",
            "value": round(reported, 3),
            "tolerance_abs": 65.0,
            "tolerance_rel": 0.004,
            "resolution": 1.0,
            "source_group": "enterprise_report",
            "dependency_domains": ["enterprise_reporting"],
            "source_reliability": 0.72,
            "quality": quality,
        },
        {
            "observation_id": f"{mine.mine_id}-{date_code}-belt",
            "metric_code": "coal.main_transport_t",
            "value": round(actual, 3),
            "tolerance_abs": 55.0,
            "tolerance_rel": 0.003,
            "resolution": 0.5,
            "source_group": "main_belt",
            "dependency_domains": ["belt_plc"],
            "source_reliability": 0.98,
            "quality": quality,
        },
        {
            "observation_id": f"{mine.mine_id}-{date_code}-wash",
            "metric_code": "wash.feed_t",
            "value": round(wash_feed, 3),
            "tolerance_abs": 55.0,
            "tolerance_rel": 0.004,
            "resolution": 0.5,
            "source_group": "wash_meter",
            "dependency_domains": ["wash_plant_plc"],
            "source_reliability": 0.96,
            "quality": quality,
        },
        {
            "observation_id": f"{mine.mine_id}-{date_code}-sales",
            "metric_code": "sales.raw_shipped_t",
            "value": round(raw_sales, 3),
            "tolerance_abs": 30.0,
            "tolerance_rel": 0.006,
            "resolution": 0.5,
            "source_group": "sales_ledger",
            "dependency_domains": ["sales_system"],
            "source_reliability": 0.94,
            "quality": quality,
        },
        {
            "observation_id": f"{mine.mine_id}-{date_code}-stock",
            "metric_code": "inventory.raw_change_t",
            "value": round(inventory_change, 3),
            "tolerance_abs": 45.0,
            "tolerance_rel": 0.005,
            "resolution": 1.0,
            "source_group": "stock_survey",
            "dependency_domains": ["stock_survey"],
            "source_reliability": 0.9,
            "quality": quality,
        },
    ]
    return ProductionAnalysisRequest.model_validate(
        {
            "mine_id": mine.mine_id,
            "window_start": window_start,
            "window_end": window_end,
            "observations": observations,
            "parameters": {
                "transport_balance_tolerance": 30.0,
                "stock_balance_tolerance": 45.0,
                "quality_gate": 60.0,
                "minimum_observation_quality": 50.0,
            },
        }
    )


def _context(
    *,
    anchor: date,
    days: int,
    window_end: datetime,
    analyses: list[ProductionAnalysisRequest],
) -> dict[str, Any]:
    dataset = _demo_dataset(anchor, days)
    by_mine = {request.mine_id: request for request in analyses}
    reports: list[dict[str, Any]] = []
    for mine in DEMO_MINES:
        request = by_mine.get(mine.mine_id)
        received_at = window_end + timedelta(minutes=5)
        envelopes = []
        if request is not None:
            envelopes = [
                {
                    "observation_id": item.observation_id,
                    "revision_no": 0,
                    "sequence_no": (
                        int(window_end.strftime("%Y%m%d")) * 10 + offset
                    ),
                    "received_at": _utc_text(received_at),
                    "demo_seed": True,
                }
                for offset, item in enumerate(request.observations)
            ]
        registry_hash = hashlib.sha256(
            f"{DEMO_DATASET_ID}:{mine.mine_id}".encode()
        ).hexdigest()
        reports.append(
            {
                "mine_id": mine.mine_id,
                "accepted": request is not None,
                "ingested_by": DEMO_ACTOR,
                "profile_id": "demo-governance-profile",
                "profile_version": "1",
                "registry_snapshot_hash": registry_hash,
                "operational_context": {
                    "regime_code": "normal-production",
                    "shift_code": "daily",
                    "season_code": _season_code(window_end.date()),
                    "maintenance": False,
                    "approved_event_codes": [],
                    "tags": ["synthetic-demo", mine.scenario],
                },
                "observation_envelopes": envelopes,
                "demo_seed": True,
                "scenario": mine.scenario,
            }
        )
    return {
        # ``governed_`` is required only so the real past-only detector accepts
        # complete compatibility metadata.  ``demo_seed`` overrides every
        # public trust envelope and keeps this out of formal governed totals.
        "kind": "governed_demo_seed",
        "demo_seed": True,
        "demo_dataset": dataset,
        "ingested_by": DEMO_ACTOR,
        "governed_request_sha256": sha256_json(
            {
                "dataset": dataset,
                "window_end": _utc_text(window_end),
                "received_mine_ids": sorted(by_mine),
            }
        ),
        "partial": len(analyses) != len(DEMO_MINES),
        "accepted_mine_count": len(analyses),
        "rejected_submission_count": len(DEMO_MINES) - len(analyses),
        "mine_reports": reports,
    }


def _seed_portfolio_history(
    repository: LocalRepository,
    *,
    anchor: date,
    days: int,
) -> dict[str, int]:
    first_day = anchor - timedelta(days=days - 1)
    counters = {
        "batches": 0,
        "received_reports": 0,
        "missing_reports": 0,
        "inconsistent_reports": 0,
        "cases": 0,
    }
    expected_ids = [mine.mine_id for mine in DEMO_MINES]
    for index in range(days):
        window_end = datetime.combine(
            first_day + timedelta(days=index),
            time.min,
            tzinfo=UTC,
        )
        window_start = window_end - timedelta(days=1)
        analyses = [
            _production_request(
                mine,
                index=index,
                days=days,
                window_start=window_start,
                window_end=window_end,
            )
            for mine in DEMO_MINES
            if not _is_missing(mine, index, days)
        ]
        request = PortfolioAnalysisRequest(
            batch_id=_batch_id(window_end),
            portfolio_name="沁源县脱敏演示辖区（严禁用于监管认定）",
            expected_mine_ids=expected_ids,
            analyses=analyses,
        )
        result = analyze_production_portfolio(request)
        context = _context(
            anchor=anchor,
            days=days,
            window_end=window_end,
            analyses=analyses,
        )
        stored = repository.save_portfolio_batch(
            request,
            result,
            __version__,
            context_obj=context,
            created_at=window_end + timedelta(minutes=10),
        )
        counters["batches"] += int(stored["created"])
        counters["received_reports"] += len(analyses)
        counters["missing_reports"] += len(DEMO_MINES) - len(analyses)
        counters["inconsistent_reports"] += sum(
            item.technical_status == "inconsistent"
            for item in result.items
        )
        counters["cases"] += sum(
            item.review_priority != "NONE" for item in result.items
        )
    return counters


def _seed_casework_history(
    repository: LocalRepository,
    *,
    anchor: date,
) -> dict[str, int]:
    """Create deterministic historical handling paths for older demo cases."""

    anchor_end = datetime.combine(
        anchor + timedelta(days=1),
        time.min,
        tzinfo=UTC,
    )
    counters = {
        "closed": 0,
        "reviewing": 0,
        "waiting_data": 0,
        "pending_approval": 0,
        "reopened": 0,
    }
    cases = [
        item
        for item in repository.list_cases(include_archived=True)
        if item["mine_id"] in _demo_ids()
        and str(item["batch_id"]).startswith(DEMO_BATCH_PREFIX)
    ]
    for case in cases:
        created = datetime.fromisoformat(
            str(case["created_at"]).replace("Z", "+00:00")
        ).astimezone(UTC)
        age_days = (anchor_end - created).days
        selector = int(
            hashlib.sha256(str(case["case_id"]).encode()).hexdigest()[:8],
            16,
        )
        current = case
        if age_days >= 10 and selector % 5 in {0, 1, 2}:
            current = repository.apply_case_action(
                str(current["case_id"]),
                action="assign",
                expected_version=int(current["version"]),
                actor="demo-dispatcher",
                assignee=(
                    "演示数据专员"
                    if current["issue_code"] == "missing_report"
                    else "演示核查员"
                ),
                occurred_at=created + timedelta(hours=1),
            )
            if current["issue_code"] == "missing_report":
                current = repository.apply_case_action(
                    str(current["case_id"]),
                    action="request_data",
                    expected_version=int(current["version"]),
                    actor="demo-reviewer-a",
                    note="演示流程：已向企业端发出补报请求。",
                    occurred_at=created + timedelta(hours=8),
                )
                disposition = "data_insufficient"
            else:
                current = repository.apply_case_action(
                    str(current["case_id"]),
                    action="start_review",
                    expected_version=int(current["version"]),
                    actor="demo-reviewer-a",
                    occurred_at=created + timedelta(hours=6),
                )
                disposition = (
                    "confirmed_technical_issue"
                    if selector % 2
                    else "excluded"
                )
            current = repository.apply_case_action(
                str(current["case_id"]),
                action="submit_conclusion",
                expected_version=int(current["version"]),
                actor="demo-reviewer-a",
                note="演示结论：已核对模拟凭证并提交复核。",
                disposition=disposition,
                occurred_at=created + timedelta(hours=30),
            )
            repository.apply_case_action(
                str(current["case_id"]),
                action="approve",
                expected_version=int(current["version"]),
                actor="demo-approver-b",
                note="演示审批：双人复核通过，仅用于功能展示。",
                occurred_at=created + timedelta(hours=48),
            )
            counters["closed"] += 1
        elif age_days >= 5 and selector % 5 == 3:
            current = repository.apply_case_action(
                str(current["case_id"]),
                action="assign",
                expected_version=int(current["version"]),
                actor="demo-dispatcher",
                assignee="演示核查员",
                occurred_at=created + timedelta(hours=2),
            )
            repository.apply_case_action(
                str(current["case_id"]),
                action="start_review",
                expected_version=int(current["version"]),
                actor="demo-reviewer-a",
                occurred_at=created + timedelta(hours=12),
            )
            counters["reviewing"] += 1
        elif (
            age_days >= 5
            and current["issue_code"] == "missing_report"
        ):
            current = repository.apply_case_action(
                str(current["case_id"]),
                action="assign",
                expected_version=int(current["version"]),
                actor="demo-dispatcher",
                assignee="演示数据专员",
                occurred_at=created + timedelta(hours=2),
            )
            repository.apply_case_action(
                str(current["case_id"]),
                action="request_data",
                expected_version=int(current["version"]),
                actor="demo-reviewer-a",
                note="演示流程：等待企业补齐缺报窗口。",
                occurred_at=created + timedelta(hours=10),
            )
            counters["waiting_data"] += 1

    # The hash-based distribution above gives variety without hard-coding a
    # particular case.  Calendar-dependent case identifiers can nevertheless
    # make a small demo window land in buckets with no completed example.  A
    # usable demo must deterministically contain at least one full two-person
    # closure path, so promote the oldest still-pending historical case only
    # when the distribution did not already create one.
    if counters["closed"] == 0:
        candidates_for_closure = [
            item
            for item in repository.list_cases(include_archived=True)
            if item["mine_id"] in _demo_ids()
            and str(item["batch_id"]).startswith(DEMO_BATCH_PREFIX)
            and item["workflow_status"]
            in {
                "pending",
                "assigned",
                "reviewing",
                "waiting_data",
                "pending_approval",
            }
            and (
                anchor_end
                - datetime.fromisoformat(
                    str(item["created_at"]).replace("Z", "+00:00")
                ).astimezone(UTC)
            ).days
            >= 3
        ]
        if candidates_for_closure:
            current = min(
                candidates_for_closure,
                key=lambda item: str(item["created_at"]),
            )
            created = datetime.fromisoformat(
                str(current["created_at"]).replace("Z", "+00:00")
            ).astimezone(UTC)
            if current["workflow_status"] == "pending":
                current = repository.apply_case_action(
                    str(current["case_id"]),
                    action="assign",
                    expected_version=int(current["version"]),
                    actor="demo-dispatcher",
                    assignee=(
                        "演示数据专员"
                        if current["issue_code"] == "missing_report"
                        else "演示核查员"
                    ),
                    occurred_at=created + timedelta(hours=1),
                )
            if current["workflow_status"] == "assigned":
                if current["issue_code"] == "missing_report":
                    current = repository.apply_case_action(
                        str(current["case_id"]),
                        action="request_data",
                        expected_version=int(current["version"]),
                        actor="demo-reviewer-a",
                        note="演示流程：已向企业端发出补报请求。",
                        occurred_at=created + timedelta(hours=8),
                    )
                else:
                    current = repository.apply_case_action(
                        str(current["case_id"]),
                        action="start_review",
                        expected_version=int(current["version"]),
                        actor="demo-reviewer-a",
                        occurred_at=created + timedelta(hours=6),
                    )
            if current["issue_code"] == "missing_report":
                disposition = "data_insufficient"
            else:
                disposition = "confirmed_technical_issue"
            if current["workflow_status"] != "pending_approval":
                current = repository.apply_case_action(
                    str(current["case_id"]),
                    action="submit_conclusion",
                    expected_version=int(current["version"]),
                    actor="demo-reviewer-a",
                    note="演示结论：保证至少展示一条完整双人闭环。",
                    disposition=disposition,
                    occurred_at=created + timedelta(hours=30),
                )
            repository.apply_case_action(
                str(current["case_id"]),
                action="approve",
                expected_version=int(current["version"]),
                actor="demo-approver-b",
                note="演示审批：双人复核通过，仅用于功能展示。",
                occurred_at=created + timedelta(hours=48),
            )
            counters["closed"] = 1

    refreshed = [
        item
        for item in repository.list_cases(include_archived=True)
        if item["mine_id"] in _demo_ids()
        and str(item["batch_id"]).startswith(DEMO_BATCH_PREFIX)
    ]
    pending = [
        item
        for item in refreshed
        if item["workflow_status"] == "pending"
    ]
    if pending:
        current = min(pending, key=lambda item: str(item["created_at"]))
        created = datetime.fromisoformat(
            str(current["created_at"]).replace("Z", "+00:00")
        ).astimezone(UTC)
        current = repository.apply_case_action(
            str(current["case_id"]),
            action="assign",
            expected_version=int(current["version"]),
            actor="demo-dispatcher",
            assignee="演示核查员",
            occurred_at=created + timedelta(hours=1),
        )
        current = repository.apply_case_action(
            str(current["case_id"]),
            action="start_review",
            expected_version=int(current["version"]),
            actor="demo-reviewer-a",
            occurred_at=created + timedelta(hours=6),
        )
        repository.apply_case_action(
            str(current["case_id"]),
            action="submit_conclusion",
            expected_version=int(current["version"]),
            actor="demo-reviewer-a",
            note="演示流程：此事项特意停留在待审批状态。",
            disposition="partially_supported",
            occurred_at=created + timedelta(hours=30),
        )
        counters["pending_approval"] = 1

    closed = [
        item
        for item in repository.list_cases(include_archived=True)
        if item["mine_id"] in _demo_ids()
        and item["workflow_status"] == "closed"
    ]
    if closed:
        current = max(closed, key=lambda item: str(item["created_at"]))
        created = datetime.fromisoformat(
            str(current["created_at"]).replace("Z", "+00:00")
        ).astimezone(UTC)
        current = repository.apply_case_action(
            str(current["case_id"]),
            action="reopen",
            expected_version=int(current["version"]),
            actor="demo-approver-b",
            note="演示复开：收到新的模拟凭证，重新进入核查。",
            occurred_at=created + timedelta(hours=60),
        )
        current = repository.apply_case_action(
            str(current["case_id"]),
            action="submit_conclusion",
            expected_version=int(current["version"]),
            actor="demo-reviewer-a",
            note="演示复开后重新提交结论。",
            disposition="confirmed_technical_issue",
            occurred_at=created + timedelta(hours=72),
        )
        repository.apply_case_action(
            str(current["case_id"]),
            action="approve",
            expected_version=int(current["version"]),
            actor="demo-approver-b",
            note="演示复开事项完成第二轮双人审批。",
            occurred_at=created + timedelta(hours=84),
        )
        counters["reopened"] = 1
    return counters


def _edge_quality(
    *,
    health: str = "healthy",
    completeness: float = 1.0,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "valid": True,
        "completeness": completeness,
        "timeliness": 0.98,
        "device_health": health,
        "clock_synchronized": True,
        "flags": flags or [],
    }


def _edge_observation(
    mine: DemoMine,
    *,
    metric_code: str,
    value: float,
    unit: str,
    location_code: str,
    source_id: str,
    observed_at: datetime,
    sequence_no: int,
    quality: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = (
        f"{DEMO_DATASET_ID}:{mine.mine_id}:{metric_code}:"
        f"{location_code}:{_utc_text(observed_at)}"
    )
    return {
        "source_id": source_id,
        "observation_id": hashlib.sha256(record.encode()).hexdigest()[:32],
        "metric_code": metric_code,
        "value": value,
        "unit": unit,
        "location_code": location_code,
        "observed_at": observed_at,
        "received_at": observed_at + timedelta(minutes=2),
        "sequence_no": sequence_no,
        "revision": 0,
        "acquisition_mode": "automatic_adapter",
        "source_record_id": f"demo-record-{sequence_no}",
        "source_record_sha256": hashlib.sha256(record.encode()).hexdigest(),
        "source_signature": None,
        "status_code": "DEMO",
        "quality": quality or _edge_quality(),
    }


def _seed_edge_dashboard(
    edge_repository: EdgeTelemetryRepository,
    *,
    anchor: date,
) -> dict[str, int]:
    observed_at = datetime.combine(anchor, time.min, tzinfo=UTC)
    counters = {"mines": 0, "edge_batches": 0, "edge_observations": 0}
    for mine_index, mine in enumerate(DEMO_MINES, start=1):
        edge_repository.upsert_mine(
            {
                "mine_id": mine.mine_id,
                "mine_name": mine.name,
                "gas_category": mine.gas_category,
                "longitude": mine.longitude,
                "latitude": mine.latitude,
                "approved_capacity_tpy": mine.base_output_t * 330,
                "approved_underground_personnel": 180 + mine_index * 15,
                "enabled": True,
            },
            actor_id=DEMO_ACTOR,
        )
        counters["mines"] += 1
        sequence = mine_index * 100
        methane = 1.18 if mine.scenario == "source_and_safety" else (
            0.92 if mine.scenario == "change_point" else 0.42
        )
        observations = [
            _edge_observation(
                mine,
                metric_code="production.output_t",
                value=round(mine.base_output_t, 2),
                unit="t",
                location_code="daily-total",
                source_id=f"{DEMO_EDGE_CLIENT_PREFIX}production",
                observed_at=observed_at,
                sequence_no=sequence,
            ),
            _edge_observation(
                mine,
                metric_code="electricity.production_kwh",
                value=round(mine.base_output_t * 22.5, 2),
                unit="kWh",
                location_code="production-zone",
                source_id=f"{DEMO_EDGE_CLIENT_PREFIX}electricity",
                observed_at=observed_at,
                sequence_no=sequence + 1,
            ),
            _edge_observation(
                mine,
                metric_code="personnel.underground_count",
                value=float(96 + mine_index * 7),
                unit="person",
                location_code="whole-mine",
                source_id=f"{DEMO_EDGE_CLIENT_PREFIX}personnel",
                observed_at=observed_at,
                sequence_no=sequence + 2,
            ),
            _edge_observation(
                mine,
                metric_code="methane.concentration_percent",
                value=methane,
                unit="%",
                location_code="working-face-A",
                source_id=f"{DEMO_EDGE_CLIENT_PREFIX}methane",
                observed_at=observed_at,
                sequence_no=sequence + 3,
            ),
            _edge_observation(
                mine,
                metric_code="ventilation.airflow_m3_min",
                value=825.0 - mine_index * 12,
                unit="m3/min",
                location_code="working-face-A",
                source_id=f"{DEMO_EDGE_CLIENT_PREFIX}ventilation",
                observed_at=observed_at,
                sequence_no=sequence + 4,
            ),
        ]
        if mine.scenario == "source_and_safety":
            observations.extend(
                [
                    _edge_observation(
                        mine,
                        metric_code="source.heartbeat_age_seconds",
                        value=1_260.0,
                        unit="s",
                        location_code=f"{DEMO_EDGE_CLIENT_PREFIX}methane",
                        source_id=f"{DEMO_EDGE_CLIENT_PREFIX}methane",
                        observed_at=observed_at,
                        sequence_no=sequence + 5,
                        quality=_edge_quality(
                            health="degraded",
                            completeness=0.72,
                            flags=["demo_source_delay"],
                        ),
                    ),
                    _edge_observation(
                        mine,
                        metric_code="source.consecutive_failures",
                        value=4.0,
                        unit="count",
                        location_code=f"{DEMO_EDGE_CLIENT_PREFIX}methane",
                        source_id=f"{DEMO_EDGE_CLIENT_PREFIX}methane",
                        observed_at=observed_at,
                        sequence_no=sequence + 6,
                        quality=_edge_quality(
                            health="degraded",
                            completeness=0.72,
                            flags=["demo_source_failures"],
                        ),
                    ),
                    _edge_observation(
                        mine,
                        metric_code="source.missing_state",
                        value=1.0,
                        unit="count",
                        location_code=f"{DEMO_EDGE_CLIENT_PREFIX}methane",
                        source_id=f"{DEMO_EDGE_CLIENT_PREFIX}methane",
                        observed_at=observed_at,
                        sequence_no=sequence + 7,
                        quality=_edge_quality(
                            health="degraded",
                            completeness=0.72,
                            flags=["demo_source_missing"],
                        ),
                    ),
                ]
            )
        client_id = f"{DEMO_EDGE_CLIENT_PREFIX}m{mine_index:02d}"
        batch_digest = hashlib.sha256(
            f"{DEMO_DATASET_ID}:{anchor}:{mine.mine_id}".encode()
        ).hexdigest()[:32]
        batch = EdgeTelemetryBatch.model_validate(
            {
                "schema_version": "edge-telemetry-batch-v1",
                "batch_id": f"{client_id}--batch_{batch_digest}",
                "client_id": client_id,
                "mine_id": mine.mine_id,
                "sent_at": observed_at + timedelta(minutes=3),
                "sequence_start": observations[0]["sequence_no"],
                "sequence_end": observations[-1]["sequence_no"],
                "rule_profile": {
                    "profile_id": "demo-safety-profile",
                    "version": 1,
                    "sha256": hashlib.sha256(
                        b"mineguard-demo-safety-profile"
                    ).hexdigest(),
                },
                "observations": observations,
                "local_alerts": [],
            }
        )
        raw_body = canonical_json(batch.model_dump(mode="json")).encode()
        receipt = edge_repository.ingest_batch(
            batch,
            body_sha256=hashlib.sha256(raw_body).hexdigest(),
            raw_body=raw_body,
            received_at=observed_at + timedelta(minutes=3),
        )
        if receipt["status"] != "duplicate":
            counters["edge_batches"] += 1
            counters["edge_observations"] += len(observations)
            edge_repository.mark_batch_evaluation(
                batch.batch_id,
                status="completed",
                result_status="demo_seed_precomputed",
            )
    return counters


def _seed_shadow_alerts(
    edge_repository: EdgeTelemetryRepository,
    *,
    anchor: date,
) -> int:
    detected_at = datetime.combine(anchor, time.min, tzinfo=UTC)
    definitions = (
        (
            "DEMO-M002",
            "production",
            "DEMO_SLOW_DRIFT",
            "yellow",
            "演示：生产交叉凭证出现缓慢漂移",
            "连续窗口偏离逐步扩大，建议查看时序曲线和原始凭证。",
            "whole-mine",
            2,
        ),
        (
            "DEMO-M003",
            "methane",
            "DEMO_METHANE_ATTENTION",
            "orange",
            "演示：工作面甲烷浓度接近处置阈值",
            "这是脱敏模拟预警，用于演示领导端分级、详情和闭环。",
            "working-face-A",
            1,
        ),
        (
            "DEMO-M004",
            "personnel",
            "DEMO_PERSON_CARD_MISMATCH",
            "orange",
            "演示：人员与定位卡信息不一致",
            "模拟重复出现的人卡不一致信号，需调阅门禁和定位记录。",
            "main-entry",
            3,
        ),
        (
            "DEMO-M006",
            "source_health",
            "DEMO_SOURCE_MISSING",
            "yellow",
            "演示：甲烷数据源连续采集失败",
            "心跳超时且连续失败，平台保持缺数状态，未将缺报按零处理。",
            f"{DEMO_EDGE_CLIENT_PREFIX}methane",
            4,
        ),
        (
            "DEMO-M006",
            "ventilation",
            "DEMO_AIRFLOW_LOW",
            "red",
            "演示：工作面风量显著偏低",
            "模拟安全高优先级线索；只用于界面和处置闭环演练。",
            "working-face-A",
            1,
        ),
    )
    total = 0
    for (
        mine_id,
        category,
        rule_code,
        level,
        title,
        summary,
        location,
        occurrences,
    ) in definitions:
        for occurrence in range(occurrences):
            edge_repository.upsert_platform_alert(
                mine_id=mine_id,
                category=category,
                rule_code=rule_code,
                level=level,  # type: ignore[arg-type]
                title=title,
                summary=summary,
                location_code=location,
                detected_at=detected_at
                - timedelta(hours=occurrences - occurrence - 1),
                observation_ids=[
                    f"demo-alert-observation-{mine_id}-{rule_code}"
                ],
                details={
                    "demo_seed": True,
                    "dataset_id": DEMO_DATASET_ID,
                    "scenario": category,
                },
                rule_profile={
                    "version": "demo-only-v1",
                    "approval_status": "demo_only",
                    "demo_seed": True,
                },
                operational=False,
                actor_id=DEMO_ACTOR,
            )
        total += 1
    return total


def _historical_verification_samples(
    mine: DemoMine,
    *,
    window_start: datetime,
    sample_count: int,
) -> list[HistoricalVerificationSample]:
    samples: list[HistoricalVerificationSample] = []
    for index in range(sample_count):
        end_at = window_start - timedelta(days=sample_count - index)
        start_at = end_at - timedelta(days=1)
        production = mine.base_output_t * (
            1.0 + 0.025 * math.sin(index * 0.87)
        )
        energy_intensity = 22.5 * (
            1.0 + 0.025 * math.sin(index * 1.13)
        )
        explosive_intensity = 0.118 * (
            1.0 + 0.03 * math.cos(index * 0.79)
        )
        available_at = end_at + timedelta(hours=1)
        samples.append(
            HistoricalVerificationSample.model_validate(
                {
                    "sample_id": (
                        f"demo-verification-{mine.mine_id}-{index:03d}"
                    ),
                    "mine_id": mine.mine_id,
                    "window_start": start_at,
                    "window_end": end_at,
                    "available_at": available_at,
                    "operating_condition": {
                        "regime_code": "normal-production",
                        "mining_method": "longwall",
                        "seam_code": "demo-seam",
                        "face_code": "working-face-A",
                        "shift_code": "daily",
                        "geology_zone": "demo-zone",
                        "maintenance": False,
                    },
                    "reported_production_t": production,
                    "electricity": {
                        "source_id": "demo-partition-meter",
                        "production_zone_kwh": (
                            production * energy_intensity
                        ),
                    },
                    "explosives": {
                        "explosives_used_kg": (
                            production * explosive_intensity
                        ),
                        "source_id": "demo-explosives-ledger",
                    },
                    "quality_score": 0.98,
                    "source_hash_valid": True,
                    "compatibility_key": (
                        "production-verification-schema-v1"
                    ),
                    "review_label": ManualReviewLabel.VERIFIED_NORMAL,
                    "human_reviewed": True,
                    "reviewed_by": "demo-reviewer",
                    "reviewed_at": available_at + timedelta(hours=1),
                    "review_confidence": 0.98,
                }
            )
        )
    return samples


def _verification_ratios(mine: DemoMine) -> tuple[float, float]:
    return {
        "normal": (1.02, 1.01),
        "slow_drift": (0.84, 0.83),
        "change_point": (0.76, 0.74),
        "repeated_anomaly": (1.34, 1.31),
        "missing_reports": (1.0, 1.0),
        "source_and_safety": (1.08, 1.06),
    }[mine.scenario]


def _seed_verification_runs(
    edge_repository: EdgeTelemetryRepository,
    *,
    anchor: date,
) -> int:
    window_end = datetime.combine(anchor, time.min, tzinfo=UTC)
    window_start = window_end - timedelta(days=1)
    created = 0
    for mine in DEMO_MINES:
        sample_count = 6 if mine.scenario == "missing_reports" else 25
        history = _historical_verification_samples(
            mine,
            window_start=window_start,
            sample_count=sample_count,
        )
        energy_ratio, explosive_ratio = _verification_ratios(mine)
        production = mine.base_output_t
        request = ProductionVerificationRequest(
            request_id=f"demo90-verification-{mine.mine_id}-{anchor:%Y%m%d}",
            mine_id=mine.mine_id,
            window_start=window_start,
            window_end=window_end,
            decision_time=window_end + timedelta(hours=2),
            operating_condition={
                "regime_code": "normal-production",
                "mining_method": "longwall",
                "seam_code": "demo-seam",
                "face_code": "working-face-A",
                "shift_code": "daily",
                "geology_zone": "demo-zone",
                "maintenance": False,
            },
            reported_production_t=production,
            production_source_id="demo-production-report",
            electricity={
                "source_id": "demo-partition-meter",
                "production_zone_kwh": (
                    production * 22.5 * energy_ratio
                ),
            },
            explosives={
                "explosives_used_kg": (
                    production * 0.118 * explosive_ratio
                ),
                "source_id": "demo-explosives-ledger",
            },
            history=history,
        )
        result = analyze_verification(request)
        _, inserted = edge_repository.save_verification_run(
            request=request.model_dump(mode="json"),
            result=result.model_dump(mode="json"),
            actor_id=DEMO_ACTOR,
        )
        created += int(inserted)
    return created


def _demo_ids() -> set[str]:
    return {mine.mine_id for mine in DEMO_MINES}


def _assert_dedicated_demo_store(
    repository: LocalRepository,
    edge_repository: EdgeTelemetryRepository,
) -> None:
    foreign_batches = [
        str(item["batch_id"])
        for item in repository.list_batches(
            limit=1_000,
            include_invalidated=True,
        )
        if not str(item["batch_id"]).startswith(DEMO_BATCH_PREFIX)
    ]
    foreign_mines = [
        str(item["mine_id"])
        for item in edge_repository.list_mines()
        if str(item["mine_id"]) not in _demo_ids()
    ]
    if foreign_batches or foreign_mines:
        raise DemoSeedError(
            "demo seeding requires a dedicated state database; "
            "non-demo batches or mines are already present"
        )


def _clear_casework(repository: LocalRepository) -> dict[str, int]:
    mine_ids = sorted(_demo_ids())
    placeholders = ",".join("?" for _ in mine_ids)
    batch_pattern = f"{DEMO_BATCH_PREFIX}%"
    counts: dict[str, int] = {}
    with repository._lock, repository._connection:  # noqa: SLF001
        connection = repository._connection  # noqa: SLF001
        for table, where, parameters in (
            (
                "run_reference_labels",
                "run_id IN (SELECT run_id FROM analysis_runs "
                "WHERE batch_id LIKE ?)",
                (batch_pattern,),
            ),
            (
                "case_events",
                "case_id IN (SELECT case_id FROM cases "
                "WHERE batch_id LIKE ?)",
                (batch_pattern,),
            ),
            ("cases", "batch_id LIKE ?", (batch_pattern,)),
            (
                "analysis_feature_windows",
                "batch_id LIKE ?",
                (batch_pattern,),
            ),
            (
                "detector_findings",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            (
                "alert_episodes",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            ("analysis_runs", "batch_id LIKE ?", (batch_pattern,)),
            (
                "batch_lifecycle_events",
                "batch_id LIKE ?",
                (batch_pattern,),
            ),
            ("batches", "batch_id LIKE ?", (batch_pattern,)),
        ):
            cursor = connection.execute(
                f"DELETE FROM {table} WHERE {where}",
                parameters,
            )
            counts[table] = max(0, cursor.rowcount)
    return counts


def _clear_edge(edge_repository: EdgeTelemetryRepository) -> dict[str, int]:
    mine_ids = sorted(_demo_ids())
    placeholders = ",".join("?" for _ in mine_ids)
    counts: dict[str, int] = {}
    with edge_repository._transaction() as connection:  # noqa: SLF001
        alert_selector = (
            f"SELECT alert_id FROM safety_alerts "
            f"WHERE mine_id IN ({placeholders})"
        )
        for table, where, parameters in (
            (
                "safety_notification_deliveries",
                "notification_id IN (SELECT notification_id FROM "
                "safety_notification_outbox WHERE alert_id IN "
                f"({alert_selector}))",
                tuple(mine_ids),
            ),
            (
                "safety_notification_outbox",
                f"alert_id IN ({alert_selector})",
                tuple(mine_ids),
            ),
            (
                "safety_alert_attachments",
                f"alert_id IN ({alert_selector})",
                tuple(mine_ids),
            ),
            (
                "safety_alert_recipients",
                f"alert_id IN ({alert_selector})",
                tuple(mine_ids),
            ),
            (
                "safety_alert_events",
                f"alert_id IN ({alert_selector})",
                tuple(mine_ids),
            ),
            (
                "safety_alerts",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            (
                "safety_signal_states",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            (
                "safety_evaluation_runs",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            (
                "production_verification_runs",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            (
                "edge_batch_observations",
                "batch_id IN (SELECT batch_id FROM edge_batches "
                f"WHERE mine_id IN ({placeholders}))",
                tuple(mine_ids),
            ),
            (
                "edge_local_alert_hints",
                "batch_id IN (SELECT batch_id FROM edge_batches "
                f"WHERE mine_id IN ({placeholders}))",
                tuple(mine_ids),
            ),
            (
                "edge_observations",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            (
                "edge_batches",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
            (
                "safety_responsibility_routes",
                "route_id LIKE 'demo90-%'",
                (),
            ),
            (
                "mine_registry",
                f"mine_id IN ({placeholders})",
                tuple(mine_ids),
            ),
        ):
            cursor = connection.execute(
                f"DELETE FROM {table} WHERE {where}",
                parameters,
            )
            counts[table] = max(0, cursor.rowcount)
    return counts


def clear_demo_data(
    repository: LocalRepository,
    edge_repository: EdgeTelemetryRepository,
) -> dict[str, Any]:
    """Delete only records owned by this synthetic dataset namespace."""

    casework = _clear_casework(repository)
    edge = _clear_edge(edge_repository)
    _manifest_table(repository)
    with repository._lock, repository._connection:  # noqa: SLF001
        repository._connection.execute(  # noqa: SLF001
            "DELETE FROM demo_seed_manifests WHERE dataset_id = ?",
            (DEMO_DATASET_ID,),
        )
    return {
        "cleared": True,
        "dataset_id": DEMO_DATASET_ID,
        "deleted_records": {
            **{f"casework.{key}": value for key, value in casework.items()},
            **{f"edge.{key}": value for key, value in edge.items()},
        },
    }


def demo_seed_status(
    repository: LocalRepository,
    edge_repository: EdgeTelemetryRepository,
) -> dict[str, Any]:
    """Return a compact integrity/status envelope for UI and CLI callers."""

    manifest = _manifest(repository)
    mine_ids = _demo_ids()
    batches = [
        batch
        for batch in repository.list_batches(
            limit=MAX_DEMO_DAYS + 10,
            include_invalidated=True,
        )
        if str(batch["batch_id"]).startswith(DEMO_BATCH_PREFIX)
    ]
    features = repository.list_algorithm_features(
        mine_ids=mine_ids,
        limit=100_000,
        include_invalidated=True,
    )
    cases = [
        case
        for case in repository.list_cases(include_archived=True)
        if case["mine_id"] in mine_ids
    ]
    alerts = edge_repository.list_alerts(
        mine_ids=mine_ids,
        limit=1000,
    )
    verifications = edge_repository.list_verification_runs(
        mine_ids=mine_ids,
        limit=1000,
    )
    expected_batches = int(manifest["days"]) if manifest else 0
    ready = bool(
        manifest is not None
        and manifest["status"] == "ready"
        and len(batches) == expected_batches
        and all(batch["integrity_valid"] for batch in batches)
    )
    return {
        "active": ready,
        "dataset_id": DEMO_DATASET_ID,
        "schema_version": DEMO_SCHEMA_VERSION,
        "manifest": manifest,
        "counts": {
            "batches": len(batches),
            "mines": len(edge_repository.list_mines(mine_ids)),
            "features": len(features),
            "cases": len(cases),
            "alerts": len(alerts),
            "verification_runs": len(verifications),
        },
        "integrity": {
            "all_batch_hashes_valid": all(
                batch["integrity_valid"] for batch in batches
            ),
            "all_batch_lifecycle_chains_valid": all(
                repository.verify_batch_lifecycle_chain(batch["batch_id"])
                for batch in batches
            ),
        },
        "scenarios": [
            {
                "mine_id": mine.mine_id,
                "mine_name": mine.name,
                "scenario": mine.scenario,
                "label": mine.scenario_label,
            }
            for mine in DEMO_MINES
        ],
    }


def seed_demo_data(
    repository: LocalRepository,
    edge_repository: EdgeTelemetryRepository,
    *,
    days: int = 90,
    anchor_date: date | datetime | str | None = None,
    reset: bool = False,
) -> dict[str, Any]:
    """Build or idempotently reuse one deterministic multi-mine dataset."""

    bounded_days = _validate_days(days)
    anchor = _anchor_date(anchor_date)
    existing = _manifest(repository)
    requested_identity = (
        DEMO_SCHEMA_VERSION,
        anchor.isoformat(),
        bounded_days,
        len(DEMO_MINES),
    )
    if existing is not None:
        existing_identity = (
            existing["schema_version"],
            existing["anchor_date"],
            int(existing["days"]),
            int(existing["mine_count"]),
        )
        if (
            not reset
            and existing["status"] == "ready"
            and existing_identity == requested_identity
        ):
            return {
                "created": False,
                "reused": True,
                **demo_seed_status(repository, edge_repository),
            }
        if not reset and existing["status"] == "ready":
            raise DemoSeedError(
                "another demo configuration already exists; use reset to "
                "rebuild it"
            )
        clear_demo_data(repository, edge_repository)
    elif reset:
        clear_demo_data(repository, edge_repository)

    _assert_dedicated_demo_store(repository, edge_repository)
    _set_manifest(
        repository,
        anchor=anchor,
        days=bounded_days,
        status="building",
        summary=None,
    )
    try:
        portfolio = _seed_portfolio_history(
            repository,
            anchor=anchor,
            days=bounded_days,
        )
        casework = _seed_casework_history(
            repository,
            anchor=anchor,
        )
        edge = _seed_edge_dashboard(
            edge_repository,
            anchor=anchor,
        )
        alert_count = _seed_shadow_alerts(
            edge_repository,
            anchor=anchor,
        )
        verification_count = _seed_verification_runs(
            edge_repository,
            anchor=anchor,
        )
        temporal = refresh_temporal_audit(
            repository,
            mine_ids=_demo_ids(),
        )
        summary = {
            "dataset": _demo_dataset(anchor, bounded_days),
            "portfolio": portfolio,
            "casework": casework,
            "edge": edge,
            "alerts": alert_count,
            "verification_runs": verification_count,
            "temporal_audit": temporal,
        }
        _set_manifest(
            repository,
            anchor=anchor,
            days=bounded_days,
            status="ready",
            summary=summary,
        )
    except Exception:
        _set_manifest(
            repository,
            anchor=anchor,
            days=bounded_days,
            status="failed",
            summary=None,
        )
        raise
    return {
        "created": True,
        "reused": False,
        **demo_seed_status(repository, edge_repository),
    }


def claim_demo_state_directory(
    state_directory: str | Path,
    *,
    create: bool,
) -> Path:
    """Validate/create the CLI ownership marker for an isolated demo state."""

    root = Path(state_directory).expanduser().resolve()
    if root == Path(root.anchor):
        raise DemoStateOwnershipError(
            "filesystem root cannot be used as a demo state directory"
        )
    marker = root / DEMO_STATE_MARKER
    if not root.exists():
        if not create:
            raise DemoStateOwnershipError(
                "demo state directory does not exist"
            )
        root.mkdir(parents=True, mode=0o700)
    if not root.is_dir():
        raise DemoStateOwnershipError(
            "demo state path must be a directory"
        )
    if marker.exists():
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise DemoStateOwnershipError(
                "demo state ownership marker is invalid"
            ) from error
        if payload != {
            "owner": "mineguard-demo-seed",
            "schema_version": DEMO_SCHEMA_VERSION,
        }:
            raise DemoStateOwnershipError(
                "demo state ownership marker does not match this generator"
            )
        return root
    existing = [item for item in root.iterdir()]
    if existing:
        raise DemoStateOwnershipError(
            "refusing to use a non-empty state directory without the "
            f"{DEMO_STATE_MARKER} ownership marker"
        )
    if not create:
        raise DemoStateOwnershipError(
            "demo state ownership marker is missing"
        )
    marker.write_text(
        json.dumps(
            {
                "owner": "mineguard-demo-seed",
                "schema_version": DEMO_SCHEMA_VERSION,
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        marker.chmod(0o600)
    except OSError:
        pass
    return root


__all__ = [
    "DEFAULT_DEMO_STATE_DIRECTORY",
    "DEMO_BATCH_PREFIX",
    "DEMO_DATASET_ID",
    "DEMO_MINES",
    "DEMO_SCHEMA_VERSION",
    "DEMO_STATE_MARKER",
    "DemoSeedError",
    "DemoStateOwnershipError",
    "claim_demo_state_directory",
    "clear_demo_data",
    "demo_seed_status",
    "seed_demo_data",
]
