"""Explicitly synthetic data for the read-only regulatory V2 dashboard.

The demo seed is deliberately routed through :class:`RegulatoryV2Store` and
therefore through the same :func:`analyze_five_quantity` entry point as an
authenticated enterprise submission.  It never inserts analysis rows or
findings directly.

Every mine, source record and retained exchange envelope says that it is
synthetic.  ``manual_import`` and ``direct_collection`` are both represented
as provenance facts; the demo does not turn either mode into a trust grade.
The default filesystem wrapper owns only ``.mineguard-v2-demo`` and refuses to
reuse an unmarked, non-empty directory.
"""

from __future__ import annotations

from calendar import monthrange
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import shlex
from typing import Annotated, Any, Literal, Sequence
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field

from .models import StrictModel
from .regulatory_v2 import (
    AcquisitionMode,
    ComparisonContext,
    DecisionStatus,
    FiveQuantityDay,
    FiveQuantitySubmission,
    METRICS,
    ReportedQuality,
    ReportedQuantity,
    RegulatoryFiveQuantityResult,
    ShiftValues,
    SubmissionProvenance,
)
from .regulatory_v2_store import (
    ExchangeMessageInput,
    RegulatoryV2Store,
)


V2_DEMO_SCHEMA_VERSION = "mineguard-regulatory-v2-synthetic-demo-v1"
DEFAULT_V2_DEMO_STATE_DIRECTORY = ".mineguard-v2-demo"
V2_DEMO_DATABASE_FILENAME = "mineguard.db"
V2_DEMO_STATE_MARKER = ".mineguard-v2-synthetic-owner.json"
V2_DEMO_AGENT_PREFIX = "synthetic-demo-agent-"
SYNTHETIC_DEMO_DISCLAIMER = (
    "本数据集完全由程序合成，仅用于功能演示和培训；不是企业实际报送、"
    "不是设备实采记录，也不得作为监管认定或执法依据。"
)


class V2DemoSeedError(ValueError):
    """A safe, operator-readable demo seed failure."""


class V2DemoStateOwnershipError(V2DemoSeedError):
    """The selected directory is not owned by this synthetic seed."""


@dataclass(frozen=True)
class V2DemoMine:
    mine_id: str
    mine_name: str
    scenario_code: str
    scenario_label: str
    base_production_t: float
    electricity_ratio: float
    acquisition_mode: AcquisitionMode


V2_DEMO_MINES: tuple[V2DemoMine, ...] = (
    V2DemoMine(
        "SYNTH-DEMO-REF-001",
        "【合成演示】同类基线一矿（人工导入）",
        "normal_reference_manual",
        "稳定正常基线 / 人工导入",
        920.0,
        19.6,
        AcquisitionMode.MANUAL_IMPORT,
    ),
    V2DemoMine(
        "SYNTH-DEMO-REF-002",
        "【合成演示】同类基线二矿（直采）",
        "normal_reference_direct",
        "稳定正常基线 / 直采",
        1_000.0,
        20.0,
        AcquisitionMode.DIRECT_COLLECTION,
    ),
    V2DemoMine(
        "SYNTH-DEMO-REF-003",
        "【合成演示】同类基线三矿（直采）",
        "normal_reference_direct",
        "稳定正常基线 / 直采",
        1_080.0,
        20.4,
        AcquisitionMode.DIRECT_COLLECTION,
    ),
    V2DemoMine(
        "SYNTH-DEMO-SHIFT-004",
        "【合成演示】日报班次不一致矿",
        "daily_shift_mismatch",
        "日报与三班合计不一致",
        980.0,
        20.0,
        AcquisitionMode.MANUAL_IMPORT,
    ),
    V2DemoMine(
        "SYNTH-DEMO-DRIFT-005",
        "【合成演示】历史漂移与变化点矿",
        "history_drift_change_point",
        "本矿历史比例漂移与变化点",
        1_020.0,
        20.0,
        AcquisitionMode.DIRECT_COLLECTION,
    ),
    V2DemoMine(
        "SYNTH-DEMO-PEER-006",
        "【合成演示】匿名同类矿偏离矿",
        "anonymous_peer_deviation",
        "相对匿名同类矿软参考带偏离",
        950.0,
        34.0,
        AcquisitionMode.MANUAL_IMPORT,
    ),
    V2DemoMine(
        "SYNTH-DEMO-MISSING-007",
        "【合成演示】缺失数据待补矿",
        "missing_values",
        "缺失值以 null 和 missing 标志表达",
        1_000.0,
        20.0,
        AcquisitionMode.DIRECT_COLLECTION,
    ),
    V2DemoMine(
        "SYNTH-DEMO-RESTART-008",
        "【合成演示】停产复产工况矿",
        "shutdown_restart",
        "连续停产后复产爬坡",
        1_050.0,
        20.0,
        AcquisitionMode.MANUAL_IMPORT,
    ),
)


DEMO_COMPARISON_CONTEXT = ComparisonContext(
    capacity_band="synthetic-0.9-1.2mtpa",
    mining_method="synthetic-underground-longwall",
    shift_system="synthetic-three-shift-eight-hour",
    coal_type="synthetic-thermal-coal",
    operating_regime="synthetic-normal-production",
)


class V2DemoScenarioSummary(StrictModel):
    mine_id: str
    mine_name: str
    scenario_code: str
    scenario_label: str
    acquisition_mode: AcquisitionMode
    submission_count: Annotated[int, Field(ge=1)]
    decisions: dict[str, Annotated[int, Field(ge=0)]]
    latest_decision: DecisionStatus
    signal_codes: list[str]
    reference_bases: list[str]
    operating_states: list[str]


class V2DemoSeedResult(StrictModel):
    schema_version: Literal["mineguard-regulatory-v2-synthetic-demo-v1"] = (
        V2_DEMO_SCHEMA_VERSION
    )
    status: Literal["seeded", "resumed", "already_seeded"]
    synthetic_demo: Literal[True] = True
    disclaimer: Literal[
        "本数据集完全由程序合成，仅用于功能演示和培训；不是企业实际报送、"
        "不是设备实采记录，也不得作为监管认定或执法依据。"
    ] = SYNTHETIC_DEMO_DISCLAIMER
    dataset_id: str
    through_month: date
    period_start: date
    period_end: date
    mine_count: Annotated[int, Field(ge=6)]
    submission_count: Annotated[int, Field(ge=1)]
    created_submission_count: Annotated[int, Field(ge=0)]
    replayed_submission_count: Annotated[int, Field(ge=0)]
    decision_counts: dict[str, Annotated[int, Field(ge=0)]]
    scenarios: list[V2DemoScenarioSummary]
    database_path: str | None = None
    state_directory: str | None = None
    serve_command: str | None = None


class V2DemoStatusResult(StrictModel):
    schema_version: Literal["mineguard-regulatory-v2-synthetic-demo-v1"] = (
        V2_DEMO_SCHEMA_VERSION
    )
    status: Literal["empty", "partial", "complete"]
    synthetic_demo: Literal[True] = True
    disclaimer: Literal[
        "本数据集完全由程序合成，仅用于功能演示和培训；不是企业实际报送、"
        "不是设备实采记录，也不得作为监管认定或执法依据。"
    ] = SYNTHETIC_DEMO_DISCLAIMER
    dataset_id: str
    through_month: date
    expected_submission_count: Annotated[int, Field(ge=1)]
    recorded_submission_count: Annotated[int, Field(ge=0)]
    remaining_submission_count: Annotated[int, Field(ge=0)]
    recorded_mine_count: Annotated[int, Field(ge=0)]
    decision_counts: dict[str, Annotated[int, Field(ge=0)]]
    audit_chain_valid: bool


@dataclass(frozen=True)
class _PlannedSubmission:
    mine: V2DemoMine
    month_index: int
    submission: FiveQuantitySubmission
    exchange: ExchangeMessageInput
    agent_id: str


def seed_v2_demo(
    store: RegulatoryV2Store,
    *,
    through_month: date | None = None,
) -> V2DemoSeedResult:
    """Seed three full calendar months through the real V2 store and engine.

    Replaying the exact dataset is idempotent.  A partially written prefix is
    resumed, while any unrelated or differently anchored submission causes an
    explicit refusal so that a real regulatory database cannot be polluted by
    this convenience function.
    """

    month_end = _normalise_through_month(through_month)
    plan = _build_plan(month_end)
    _validated_existing_prefix(store, plan)

    created = 0
    replayed = 0
    decisions: Counter[str] = Counter()
    scenario_runs: dict[
        str, list[tuple[DecisionStatus, RegulatoryFiveQuantityResult]]
    ] = {mine.mine_id: [] for mine in V2_DEMO_MINES}
    for item in plan:
        store.bind_agent_to_mine(item.agent_id, item.mine.mine_id)
        receipt = store.submit_and_analyze(
            item.submission,
            agent_id=item.agent_id,
            idempotency_key=item.submission.submission_id,
            exchange_message=item.exchange,
        )
        result = store.get_run(receipt.run_id)
        replayed += int(receipt.idempotent_replay)
        created += int(not receipt.idempotent_replay)
        decisions[receipt.decision.value] += 1
        scenario_runs[item.mine.mine_id].append((receipt.decision, result))

    scenario_summaries: list[V2DemoScenarioSummary] = []
    for mine in V2_DEMO_MINES:
        runs = scenario_runs[mine.mine_id]
        mine_decisions = Counter(decision.value for decision, _ in runs)
        results = [result for _, result in runs]
        scenario_summaries.append(
            V2DemoScenarioSummary(
                mine_id=mine.mine_id,
                mine_name=mine.mine_name,
                scenario_code=mine.scenario_code,
                scenario_label=mine.scenario_label,
                acquisition_mode=mine.acquisition_mode,
                submission_count=len(runs),
                decisions=dict(sorted(mine_decisions.items())),
                latest_decision=runs[-1][0],
                signal_codes=sorted(
                    {
                        signal.code
                        for result in results
                        for signal in (
                            *result.data_quality_signals,
                            *result.relationship_signals,
                            *result.temporal_signals,
                        )
                    }
                ),
                reference_bases=sorted(
                    {
                        band.basis
                        for result in results
                        for band in (
                            *result.references.accepted_history_bands,
                            *result.references.accepted_peer_bands,
                            *result.references.within_submission_bands,
                        )
                    }
                ),
                operating_states=sorted(
                    {
                        state.state.value
                        for result in results
                        for state in result.day_states
                    }
                ),
            )
        )

    first_period = plan[0].submission.period_start
    state = "already_seeded" if created == 0 else "resumed" if replayed else "seeded"
    database_path = (
        None if store.path == ":memory:" else str(Path(store.path).resolve())
    )
    return V2DemoSeedResult(
        status=state,
        dataset_id=f"regulatory-v2-synthetic-demo-{month_end:%Y-%m}",
        through_month=month_end,
        period_start=first_period,
        period_end=month_end,
        mine_count=len(V2_DEMO_MINES),
        submission_count=len(plan),
        created_submission_count=created,
        replayed_submission_count=replayed,
        decision_counts=dict(sorted(decisions.items())),
        scenarios=scenario_summaries,
        database_path=database_path,
    )


def v2_demo_status(
    store: RegulatoryV2Store,
    *,
    through_month: date | None = None,
) -> V2DemoStatusResult:
    """Inspect one expected synthetic dataset without adding a submission."""

    month_end = _normalise_through_month(through_month)
    plan = _build_plan(month_end)
    existing = _validated_existing_prefix(store, plan)
    runs = store.list_runs(limit=1_000)
    decisions = Counter(str(item["decision"]) for item in runs)
    mine_ids = {str(item["mine_id"]) for item in existing}
    recorded = len(existing)
    return V2DemoStatusResult(
        status=(
            "empty"
            if recorded == 0
            else "complete"
            if recorded == len(plan)
            else "partial"
        ),
        dataset_id=f"regulatory-v2-synthetic-demo-{month_end:%Y-%m}",
        through_month=month_end,
        expected_submission_count=len(plan),
        recorded_submission_count=recorded,
        remaining_submission_count=len(plan) - recorded,
        recorded_mine_count=len(mine_ids),
        decision_counts=dict(sorted(decisions.items())),
        audit_chain_valid=store.verify_audit_chain(),
    )


def seed_v2_demo_state(
    state_directory: str | os.PathLike[str] = DEFAULT_V2_DEMO_STATE_DIRECTORY,
    *,
    through_month: date | None = None,
) -> V2DemoSeedResult:
    """Create/use an owned standalone demo state tree and seed its V2 DB."""

    month_end = _normalise_through_month(through_month)
    root = claim_v2_demo_state_directory(
        state_directory,
        through_month=month_end,
    )
    database = root / V2_DEMO_DATABASE_FILENAME
    with RegulatoryV2Store(database) as store:
        result = seed_v2_demo(store, through_month=month_end)
    try:
        database.chmod(0o600)
    except OSError:
        pass
    return result.model_copy(
        update={
            "database_path": str(database),
            "state_directory": str(root),
            "serve_command": (
                "mineguard serve --state-directory " + shlex.quote(str(root))
            ),
        }
    )


def claim_v2_demo_state_directory(
    value: str | os.PathLike[str] = DEFAULT_V2_DEMO_STATE_DIRECTORY,
    *,
    through_month: date | None = None,
) -> Path:
    """Claim a non-root directory with a durable synthetic-demo marker."""

    raw = os.fspath(value)
    if not raw.strip():
        raise V2DemoStateOwnershipError("合成演示状态目录不能为空")
    root = Path(raw).expanduser().resolve()
    if root == Path(root.anchor):
        raise V2DemoStateOwnershipError("文件系统根目录不能作为合成演示状态目录")
    month_end = _normalise_through_month(through_month)
    marker = root / V2_DEMO_STATE_MARKER
    expected = {
        "schema_version": V2_DEMO_SCHEMA_VERSION,
        "synthetic_demo": True,
        "through_month": month_end.isoformat(),
        "database": V2_DEMO_DATABASE_FILENAME,
        "disclaimer": SYNTHETIC_DEMO_DISCLAIMER,
    }
    if marker.is_file():
        try:
            actual = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise V2DemoStateOwnershipError("合成演示目录所有权标记损坏") from error
        if actual != expected:
            raise V2DemoStateOwnershipError(
                "合成演示目录属于另一数据月份或标记版本，已拒绝混写"
            )
        return root
    if root.exists() and any(root.iterdir()):
        raise V2DemoStateOwnershipError(
            "目标目录非空且没有合成演示所有权标记，已拒绝写入"
        )
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    marker_text = json.dumps(expected, ensure_ascii=False, indent=2) + "\n"
    try:
        descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(marker_text)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return claim_v2_demo_state_directory(root, through_month=month_end)
    return root


def _normalise_through_month(value: date | None) -> date:
    if value is None:
        today = datetime.now(UTC).date()
        first_this_month = today.replace(day=1)
        value = first_this_month - timedelta(days=1)
    return value.replace(day=monthrange(value.year, value.month)[1])


def _validated_existing_prefix(
    store: RegulatoryV2Store,
    plan: Sequence[_PlannedSubmission],
) -> list[dict[str, Any]]:
    expected_ids = [item.submission.submission_id for item in plan]
    expected_mine_ids = {item.mine.mine_id for item in plan}
    existing = store.list_submissions(limit=1_000)
    existing_ids = {str(item["submission_id"]) for item in existing}
    expected_prefix = set(expected_ids[: len(existing_ids)])
    audits = store.list_audit_events(limit=1_000)
    exchanges = store.list_exchange_messages(limit=1_000)
    foreign_audit = any(
        item.mine_id not in expected_mine_ids
        and not (
            item.mine_id is None
            and item.event_type == "anonymous_peer_snapshot_frozen"
            and item.aggregate_type == "peer_reference_snapshot"
        )
        for item in audits
    )
    foreign_exchange = any(
        item.mine_id not in expected_mine_ids
        or item.body.get("synthetic_demo") is not True
        for item in exchanges
    )
    if existing_ids != expected_prefix or foreign_audit or foreign_exchange:
        raise V2DemoSeedError(
            "目标数据库包含非本批次合成演示报送，已拒绝写入；"
            "请使用独立的 .mineguard-v2-demo 状态目录。"
        )
    return existing


def _build_plan(through_month: date) -> list[_PlannedSubmission]:
    periods = _three_month_periods(through_month)
    plan: list[_PlannedSubmission] = []
    # Period-major order mirrors the reporting calendar and ensures that the
    # first period's quarantined candidates exist before the next period's
    # frozen anonymous peer snapshot is built.  Conclusions must not depend on
    # the order of mines inside one period.
    for month_index, (period_start, period_end) in enumerate(periods):
        for mine_index, mine in enumerate(V2_DEMO_MINES):
            agent_id = V2_DEMO_AGENT_PREFIX + mine.mine_id.lower()
            submission_id = str(
                uuid5(
                    NAMESPACE_URL,
                    f"mineguard:v2:synthetic-demo:{through_month}:{mine.mine_id}:"
                    f"{period_start}",
                )
            )
            days = [
                _build_day(
                    mine,
                    observed_date,
                    month_index=month_index,
                    day_index=(observed_date - period_start).days,
                    mine_index=mine_index,
                )
                for observed_date in _date_range(period_start, period_end)
            ]
            provenance_seed = {
                "synthetic_demo": True,
                "mine_id": mine.mine_id,
                "period_start": period_start.isoformat(),
                "period_end": period_end.isoformat(),
                "scenario": mine.scenario_code,
                "acquisition_mode": mine.acquisition_mode.value,
            }
            evidence_sha256 = hashlib.sha256(
                json.dumps(
                    provenance_seed,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            submission = FiveQuantitySubmission(
                submission_id=submission_id,
                mine_id=mine.mine_id,
                mine_name=mine.mine_name,
                reporting_timezone="Asia/Shanghai",
                revision=1,
                period_start=period_start,
                period_end=period_end,
                comparison_context=DEMO_COMPARISON_CONTEXT,
                days=days,
                provenance=[
                    SubmissionProvenance(
                        acquisition_mode=mine.acquisition_mode,
                        source_name=(
                            "【合成演示，非真实报送】人工导入生成器"
                            if mine.acquisition_mode is AcquisitionMode.MANUAL_IMPORT
                            else "【合成演示，非设备实采】直采接口生成器"
                        ),
                        evidence_sha256=evidence_sha256,
                        source_record_id=(
                            f"SYNTHETIC-DEMO-ONLY/{mine.scenario_code}/"
                            f"{period_start:%Y-%m}"
                        ),
                    )
                ],
            )
            message_id = str(
                uuid5(
                    NAMESPACE_URL,
                    "mineguard:v2:synthetic-demo-exchange:" + submission_id,
                )
            )
            exchange = ExchangeMessageInput(
                message_id=message_id,
                direction="inbound",
                message_type="synthetic_demo_five_quantity_submission_v2",
                mine_id=mine.mine_id,
                agent_id=agent_id,
                body={
                    "schema_version": V2_DEMO_SCHEMA_VERSION,
                    "synthetic_demo": True,
                    "not_enterprise_signed": True,
                    "offline_seed": True,
                    "disclaimer": SYNTHETIC_DEMO_DISCLAIMER,
                    "scenario_code": mine.scenario_code,
                    "missing_encoding": "null_with_missing_quality_flags",
                    "submission_id": submission_id,
                    "payload_sha256": hashlib.sha256(
                        submission.model_dump_json().encode("utf-8")
                    ).hexdigest(),
                },
                exchanged_at=datetime.combine(
                    period_end + timedelta(days=1),
                    datetime.min.time(),
                    tzinfo=UTC,
                ),
            )
            plan.append(
                _PlannedSubmission(
                    mine=mine,
                    month_index=month_index,
                    submission=submission,
                    exchange=exchange,
                    agent_id=agent_id,
                )
            )
    return plan


def _three_month_periods(through_month: date) -> tuple[tuple[date, date], ...]:
    starts: list[date] = []
    cursor = through_month.replace(day=1)
    for _ in range(3):
        starts.append(cursor)
        cursor = (cursor - timedelta(days=1)).replace(day=1)
    starts.reverse()
    return tuple(
        (
            start,
            start.replace(day=monthrange(start.year, start.month)[1]),
        )
        for start in starts
    )


def _date_range(start: date, end: date) -> Sequence[date]:
    return tuple(
        start + timedelta(days=index) for index in range((end - start).days + 1)
    )


def _build_day(
    mine: V2DemoMine,
    observed_date: date,
    *,
    month_index: int,
    day_index: int,
    mine_index: int,
) -> FiveQuantityDay:
    if (
        mine.scenario_code == "missing_values"
        and month_index == 2
        and 4 <= day_index < 14
    ):
        missing_quality = ReportedQuality(
            daily_total=("missing", "partial"),
            zero_shift=("missing", "partial"),
            eight_shift=("missing", "partial"),
            four_shift=("missing", "partial"),
        )
        return FiveQuantityDay(
            date=observed_date,
            declared_operating_state="unknown",
            quality={metric: missing_quality for metric in METRICS},
            **{metric: ReportedQuantity(shifts=ShiftValues()) for metric in METRICS},
        )

    variation = (((observed_date.toordinal() + mine_index * 3) % 9) - 4) * 0.006
    production = mine.base_production_t * (1.0 + variation)
    declared: Literal["producing", "stopped", "restarting"] = "producing"
    if mine.scenario_code == "shutdown_restart" and month_index == 2:
        if 8 <= day_index < 13:
            declared = "stopped"
            values = {
                "ventilation_m3_min": 850.0,
                "mine_entry_persons": 18.0,
                "electricity_kwh": 1_800.0,
                "detonators_count": 0.0,
                "explosives_kg": 0.0,
                "production_t": 0.0,
            }
            return _complete_day(observed_date, values, declared=declared)
        if 13 <= day_index < 16:
            declared = "restarting"
            production *= (0.35, 0.65, 0.85)[day_index - 13]

    electricity_ratio = mine.electricity_ratio
    if (
        mine.scenario_code == "history_drift_change_point"
        and month_index == 2
        and day_index >= 15
    ):
        electricity_ratio = 31.0
    values = {
        "ventilation_m3_min": 3.0 * production,
        "mine_entry_persons": round(0.10 * production),
        "electricity_kwh": electricity_ratio * production,
        "detonators_count": float(round(0.010 * production)),
        "explosives_kg": 0.050 * production,
        "production_t": production,
    }
    mismatch_metric = (
        "electricity_kwh"
        if mine.scenario_code == "daily_shift_mismatch"
        and month_index == 2
        and day_index == 10
        else None
    )
    return _complete_day(
        observed_date,
        values,
        declared=declared,
        mismatch_metric=mismatch_metric,
    )


def _complete_day(
    observed_date: date,
    values: dict[str, float],
    *,
    declared: Literal["producing", "stopped", "restarting"],
    mismatch_metric: str | None = None,
) -> FiveQuantityDay:
    quantities: dict[str, ReportedQuantity] = {}
    for metric, raw_value in values.items():
        value = float(raw_value)
        if metric == "ventilation_m3_min":
            shifts = ShiftValues(
                zero_shift=value * 0.99,
                eight_shift=value,
                four_shift=value * 1.01,
            )
        elif metric in {"detonators_count", "mine_entry_persons"}:
            shifts = _integral_shifts(int(round(value)))
        else:
            shifts = _additive_shifts(value)
        if metric == mismatch_metric:
            shifts = _additive_shifts(value * 1.80)
        quantities[metric] = ReportedQuantity(daily_total=value, shifts=shifts)
    return FiveQuantityDay(
        date=observed_date,
        declared_operating_state=declared,
        **quantities,
    )


def _additive_shifts(value: float) -> ShiftValues:
    zero = value * 0.34
    eight = value * 0.33
    return ShiftValues(
        zero_shift=zero,
        eight_shift=eight,
        four_shift=value - zero - eight,
    )


def _integral_shifts(value: int) -> ShiftValues:
    zero = round(value * 0.34)
    eight = round(value * 0.33)
    return ShiftValues(
        zero_shift=float(zero),
        eight_shift=float(eight),
        four_shift=float(value - zero - eight),
    )


__all__ = [
    "DEFAULT_V2_DEMO_STATE_DIRECTORY",
    "SYNTHETIC_DEMO_DISCLAIMER",
    "V2_DEMO_DATABASE_FILENAME",
    "V2_DEMO_MINES",
    "V2DemoSeedError",
    "V2DemoSeedResult",
    "V2DemoStatusResult",
    "V2DemoStateOwnershipError",
    "claim_v2_demo_state_directory",
    "seed_v2_demo",
    "seed_v2_demo_state",
    "v2_demo_status",
]
