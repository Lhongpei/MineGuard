"""Isolated teaching data for the read-only regulatory V2 dashboard.

The demo seed is deliberately routed through :class:`RegulatoryV2Store` and
therefore through the same :func:`analyze_five_quantity` entry point as an
authenticated enterprise submission.  It never inserts analysis rows or
findings directly.

Eight generated mines retain the synthetic teaching scenarios.  Two additional
mines are mapped cell-for-cell from the bundled July 2026 WPS ``.et`` examples:
their values are never shifted, interpolated, backfilled or randomised.  Every
retained exchange envelope identifies which origin applies.  ``manual_import``
and ``direct_collection`` remain provenance facts, not trust grades.

The default filesystem wrapper owns only ``.mineguard-v2-demo-v2`` and refuses
to reuse an unmarked, non-empty directory.
"""

from __future__ import annotations

from calendar import monthrange
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
import hashlib
from importlib.resources import files
import json
import math
import os
from pathlib import Path
import shlex
from typing import Annotated, Any, Literal, Sequence
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field

from .five_quantity import (
    FiveQuantityDay as ImportedFiveQuantityDay,
    FiveQuantityImportRequest,
    FiveQuantityImportResult,
    import_five_quantity_et,
)
from .models import StrictModel
from .regulatory_v2 import (
    AcquisitionMode,
    ComparisonContext,
    DecisionStatus,
    FiveQuantityDay,
    FiveQuantitySubmission,
    LEGACY_METRICS,
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


V2_DEMO_SCHEMA_VERSION = "mineguard-regulatory-v2-demo-v3"
DEFAULT_V2_DEMO_STATE_DIRECTORY = ".mineguard-v2-demo-v2"
V2_DEMO_DATABASE_FILENAME = "mineguard.db"
V2_DEMO_STATE_MARKER = ".mineguard-v2-synthetic-owner.json"
PLATFORM_STATE_MARKER = ".mineguard-platform-state.json"
PLATFORM_STATE_PRODUCT = "MineGuard Platform State"
V2_DEMO_AGENT_PREFIX = "synthetic-demo-agent-"
V2_WORKBOOK_DEMO_AGENT_PREFIX = "workbook-demo-agent-"
SYNTHETIC_ONLY_SCHEMA_VERSION = "mineguard-regulatory-v2-synthetic-demo-v2"
SYNTHETIC_ONLY_DISCLAIMER = (
    "本数据集完全由程序合成，仅用于功能演示和培训；不是企业实际报送、"
    "不是设备实采记录，也不得作为监管认定或执法依据。"
)
V2_DEMO_DISCLAIMER = (
    "本演示库包含程序合成教学场景，以及从随项目提供的两份2026年7月ET样表"
    "逐格映射的太岳矿、梗阳矿示例；样表值未补数、未插值、未平移日期。"
    "全部记录均非企业签名报送，样表单位和身份未经监管核验，不得作为监管认定"
    "或执法依据。"
)
# Kept as a source-level compatibility alias for callers that used the old
# constant name.  The value now truthfully describes the mixed demo dataset.
SYNTHETIC_DEMO_DISCLAIMER = V2_DEMO_DISCLAIMER
WORKBOOK_DEMO_PERIOD_START = date(2026, 7, 1)
WORKBOOK_DEMO_PERIOD_END = date(2026, 7, 31)
WORKBOOK_DEMO_VALUE_POLICY = "source_cells_only_no_fill_interpolation_or_date_shift"


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
    data_origin: Literal["synthetic_generated", "bundled_workbook_values"] = (
        "synthetic_generated"
    )
    bundled_filename: str | None = None
    original_filename: str | None = None
    expected_source_sha256: str | None = None


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


V2_WORKBOOK_DEMO_MINES: tuple[V2DemoMine, ...] = (
    V2DemoMine(
        "DEMO-WORKBOOK-TAIYUE-001",
        "太岳矿",
        "bundled_workbook_taiyue_2026_07",
        "2026年7月ET样表原值 / 太岳矿",
        0.0,
        0.0,
        AcquisitionMode.MANUAL_IMPORT,
        data_origin="bundled_workbook_values",
        bundled_filename="taiyue-2026-07.et",
        original_filename="五量基础数据测试.et",
        expected_source_sha256=(
            "a83ca156886c4ee8443825e14126f0dad"
            "731898951447f5a951e2570787530a9"
        ),
    ),
    V2DemoMine(
        "DEMO-WORKBOOK-GENGYANG-002",
        "梗阳矿",
        "bundled_workbook_gengyang_2026_07",
        "2026年7月ET样表原值 / 梗阳矿",
        0.0,
        0.0,
        AcquisitionMode.MANUAL_IMPORT,
        data_origin="bundled_workbook_values",
        bundled_filename="gengyang-2026-07.et",
        original_filename="五量基础数据测试（沁源梗阳）.et",
        expected_source_sha256=(
            "5c1a0dde50965f9b3f8605676bc792fa"
            "3b74d28ec90bba23182f759cfb1341f6"
        ),
    ),
)
V2_ALL_DEMO_MINES = (*V2_DEMO_MINES, *V2_WORKBOOK_DEMO_MINES)


DEMO_COMPARISON_CONTEXT = ComparisonContext(
    capacity_band="synthetic-0.9-1.2mtpa",
    mining_method="synthetic-underground-longwall",
    shift_system="synthetic-three-shift-eight-hour",
    coal_type="synthetic-thermal-coal",
    operating_regime="synthetic-normal-production",
)

WORKBOOK_DEMO_COMPARISON_CONTEXT = ComparisonContext(
    capacity_band="demo-source-not-verified",
    mining_method="demo-source-not-verified",
    shift_system="source-workbook-three-shift",
    coal_type="demo-source-not-verified",
    operating_regime="source-workbook-unverified",
)


class V2DemoScenarioSummary(StrictModel):
    mine_id: str
    mine_name: str
    scenario_code: str
    scenario_label: str
    acquisition_mode: AcquisitionMode
    data_origin: Literal["synthetic_generated", "bundled_workbook_values"]
    source_filename: str | None = None
    source_sha256: str | None = None
    source_value_policy: str | None = None
    submission_count: Annotated[int, Field(ge=1)]
    decisions: dict[str, Annotated[int, Field(ge=0)]]
    latest_decision: DecisionStatus
    signal_codes: list[str]
    reference_bases: list[str]
    operating_states: list[str]


class V2DemoSeedResult(StrictModel):
    schema_version: Literal["mineguard-regulatory-v2-demo-v3"] = (
        V2_DEMO_SCHEMA_VERSION
    )
    status: Literal["seeded", "resumed", "already_seeded"]
    demo_dataset: Literal[True] = True
    synthetic_demo: Literal[True] = True
    contains_workbook_examples: Literal[True] = True
    disclaimer: Literal[
        "本演示库包含程序合成教学场景，以及从随项目提供的两份2026年7月ET样表"
        "逐格映射的太岳矿、梗阳矿示例；样表值未补数、未插值、未平移日期。"
        "全部记录均非企业签名报送，样表单位和身份未经监管核验，不得作为监管认定"
        "或执法依据。"
    ] = V2_DEMO_DISCLAIMER
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
    schema_version: Literal["mineguard-regulatory-v2-demo-v3"] = (
        V2_DEMO_SCHEMA_VERSION
    )
    status: Literal["empty", "partial", "complete"]
    demo_dataset: Literal[True] = True
    synthetic_demo: Literal[True] = True
    contains_workbook_examples: Literal[True] = True
    disclaimer: Literal[
        "本演示库包含程序合成教学场景，以及从随项目提供的两份2026年7月ET样表"
        "逐格映射的太岳矿、梗阳矿示例；样表值未补数、未插值、未平移日期。"
        "全部记录均非企业签名报送，样表单位和身份未经监管核验，不得作为监管认定"
        "或执法依据。"
    ] = V2_DEMO_DISCLAIMER
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
    ] = {mine.mine_id: [] for mine in V2_ALL_DEMO_MINES}
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
    for mine in V2_ALL_DEMO_MINES:
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
                data_origin=mine.data_origin,
                source_filename=mine.original_filename,
                source_sha256=mine.expected_source_sha256,
                source_value_policy=(
                    WORKBOOK_DEMO_VALUE_POLICY
                    if mine.data_origin == "bundled_workbook_values"
                    else None
                ),
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

    first_period = min(item.submission.period_start for item in plan)
    last_period = max(item.submission.period_end for item in plan)
    state = "already_seeded" if created == 0 else "resumed" if replayed else "seeded"
    database_path = (
        None if store.path == ":memory:" else str(Path(store.path).resolve())
    )
    return V2DemoSeedResult(
        status=state,
        dataset_id=f"regulatory-v2-demo-series-v3-{month_end:%Y-%m}",
        through_month=month_end,
        period_start=first_period,
        period_end=last_period,
        mine_count=len(V2_ALL_DEMO_MINES),
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
        dataset_id=f"regulatory-v2-demo-series-v3-{month_end:%Y-%m}",
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
    _upgrade_demo_state_marker(root, through_month=month_end)
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
    """Claim a non-root directory with a durable mixed-demo marker."""

    raw = os.fspath(value)
    if not raw.strip():
        raise V2DemoStateOwnershipError("演示状态目录不能为空")
    root = Path(raw).expanduser().resolve()
    if root == Path(root.anchor):
        raise V2DemoStateOwnershipError("文件系统根目录不能作为演示状态目录")
    month_end = _normalise_through_month(through_month)
    marker = root / V2_DEMO_STATE_MARKER
    expected = {
        "schema_version": V2_DEMO_SCHEMA_VERSION,
        "demo_dataset": True,
        "synthetic_demo": True,
        "contains_workbook_examples": True,
        "through_month": month_end.isoformat(),
        "database": V2_DEMO_DATABASE_FILENAME,
        "disclaimer": V2_DEMO_DISCLAIMER,
    }
    if marker.is_file():
        try:
            actual = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise V2DemoStateOwnershipError("演示目录所有权标记损坏") from error
        legacy = {
            "schema_version": SYNTHETIC_ONLY_SCHEMA_VERSION,
            "synthetic_demo": True,
            "through_month": month_end.isoformat(),
            "database": V2_DEMO_DATABASE_FILENAME,
            "disclaimer": SYNTHETIC_ONLY_DISCLAIMER,
        }
        if actual not in (expected, legacy):
            raise V2DemoStateOwnershipError(
                "合成演示目录属于另一数据月份或标记版本，已拒绝混写"
            )
        return root
    if root.exists() and any(root.iterdir()):
        if not _is_empty_platform_owned_state(root):
            raise V2DemoStateOwnershipError(
                "目标目录非空且没有可验证的演示或空 Platform "
                "状态所有权标记，已拒绝写入"
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


def _is_empty_platform_owned_state(root: Path) -> bool:
    """Accept only the exact empty state tree prepared by the Windows wizard."""

    try:
        entries = tuple(root.iterdir())
    except OSError:
        return False
    if len(entries) != 1:
        return False
    marker = entries[0]
    if (
        marker.name != PLATFORM_STATE_MARKER
        or marker.is_symlink()
        or not marker.is_file()
    ):
        return False
    try:
        payload = json.loads(marker.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict) or set(payload) != {
        "schemaVersion",
        "product",
        "initializedFor",
    }:
        return False
    if (
        type(payload["schemaVersion"]) is not int
        or payload["schemaVersion"] != 1
        or payload["product"] != PLATFORM_STATE_PRODUCT
        or not isinstance(payload["initializedFor"], str)
        or not payload["initializedFor"].strip()
    ):
        return False
    try:
        raw_install_root = Path(payload["initializedFor"]).expanduser()
        if not raw_install_root.is_absolute():
            return False
        install_root = raw_install_root.resolve()
        platform_state_root = (install_root / "state").resolve()
        root.relative_to(platform_state_root)
    except (OSError, RuntimeError, ValueError):
        return False
    return True


def _demo_state_marker_payload(through_month: date) -> dict[str, Any]:
    return {
        "schema_version": V2_DEMO_SCHEMA_VERSION,
        "demo_dataset": True,
        "synthetic_demo": True,
        "contains_workbook_examples": True,
        "through_month": through_month.isoformat(),
        "database": V2_DEMO_DATABASE_FILENAME,
        "disclaimer": V2_DEMO_DISCLAIMER,
    }


def _upgrade_demo_state_marker(root: Path, *, through_month: date) -> None:
    """Atomically migrate only the exact legacy owned marker after seeding.

    ``seed_v2_demo`` has already verified that every database record is the
    expected plan prefix before this runs.  An arbitrary marker or mixed store
    therefore never reaches this replacement path.
    """

    marker = root / V2_DEMO_STATE_MARKER
    expected = _demo_state_marker_payload(through_month)
    try:
        actual = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise V2DemoStateOwnershipError("演示目录所有权标记损坏") from error
    if actual == expected:
        return
    legacy = {
        "schema_version": SYNTHETIC_ONLY_SCHEMA_VERSION,
        "synthetic_demo": True,
        "through_month": through_month.isoformat(),
        "database": V2_DEMO_DATABASE_FILENAME,
        "disclaimer": SYNTHETIC_ONLY_DISCLAIMER,
    }
    if actual != legacy:
        raise V2DemoStateOwnershipError(
            "演示目录所有权标记不属于可迁移的旧版数据集"
        )
    marker_text = json.dumps(expected, ensure_ascii=False, indent=2) + "\n"
    temporary = root / f".{V2_DEMO_STATE_MARKER}.{os.getpid()}.upgrade"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(marker_text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, marker)
        try:
            directory_descriptor = os.open(root, os.O_RDONLY)
        except OSError:
            # Windows does not expose a portable directory fsync handle.
            directory_descriptor = None
        if directory_descriptor is not None:
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _normalise_through_month(value: date | None) -> date:
    if value is None:
        today = datetime.now(UTC).date()
        first_this_month = today.replace(day=1)
        value = first_this_month - timedelta(days=1)
    normalized = value.replace(day=monthrange(value.year, value.month)[1])
    if normalized < WORKBOOK_DEMO_PERIOD_END:
        raise V2DemoSeedError(
            "演示库包含固定的2026年7月太岳矿、梗阳矿样表，"
            "--through-month 不能早于 2026-07"
        )
    return normalized


def _validated_existing_prefix(
    store: RegulatoryV2Store,
    plan: Sequence[_PlannedSubmission],
) -> list[dict[str, Any]]:
    expected_ids = [item.submission.submission_id for item in plan]
    expected_mine_ids = {item.mine.mine_id for item in plan}
    expected_exchange_ids = {item.exchange.message_id for item in plan}
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
        or item.message_id not in expected_exchange_ids
        for item in exchanges
    )
    if existing_ids != expected_prefix or foreign_audit or foreign_exchange:
        raise V2DemoSeedError(
            "目标数据库包含非本批次演示报送，已拒绝写入；"
            "请使用独立的 .mineguard-v2-demo-v2 状态目录。"
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
                    f"mineguard:v2:synthetic-demo-v2:{through_month}:{mine.mine_id}:"
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
                    # Keep the original synthetic envelope byte-for-byte
                    # stable so an owned 24-submission V2 demo can safely
                    # resume by appending only the two workbook examples.
                    "schema_version": SYNTHETIC_ONLY_SCHEMA_VERSION,
                    "synthetic_demo": True,
                    "not_enterprise_signed": True,
                    "offline_seed": True,
                    "disclaimer": SYNTHETIC_ONLY_DISCLAIMER,
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
    plan.extend(_build_workbook_example_plan())
    return plan


def _build_workbook_example_plan() -> list[_PlannedSubmission]:
    """Map the two bundled July workbooks without manufacturing any value.

    The display identities are an explicit demo mapping supplied by the user;
    in particular, the Taiyue workbook still contains an ``XX煤矿`` title and
    that title is retained in the exchange evidence rather than treated as an
    identity source.  The files declare neither units nor operating state, so
    those limitations are also retained instead of guessed.
    """

    plan: list[_PlannedSubmission] = []
    for mine in V2_WORKBOOK_DEMO_MINES:
        imported = _load_workbook_example(mine)
        days = [_map_imported_workbook_day(day) for day in imported.days]
        source_digest = imported.source_sha256
        submission_id = str(
            uuid5(
                NAMESPACE_URL,
                "mineguard:v2:workbook-demo-v1:"
                f"{mine.mine_id}:{WORKBOOK_DEMO_PERIOD_START}:{source_digest}",
            )
        )
        submission = FiveQuantitySubmission(
            submission_id=submission_id,
            mine_id=mine.mine_id,
            mine_name=mine.mine_name,
            reporting_timezone="Asia/Shanghai",
            revision=1,
            period_start=WORKBOOK_DEMO_PERIOD_START,
            period_end=WORKBOOK_DEMO_PERIOD_END,
            comparison_context=WORKBOOK_DEMO_COMPARISON_CONTEXT,
            days=days,
            provenance=[
                SubmissionProvenance(
                    acquisition_mode=AcquisitionMode.MANUAL_IMPORT,
                    source_name=f"演示样表人工导入：{mine.original_filename}",
                    evidence_sha256=source_digest,
                    source_record_id=(
                        f"BUNDLED-ET-DEMO/2026-07/{mine.mine_id}"
                    ),
                )
            ],
        )
        agent_id = V2_WORKBOOK_DEMO_AGENT_PREFIX + mine.mine_id.lower()
        message_id = str(
            uuid5(
                NAMESPACE_URL,
                "mineguard:v2:workbook-demo-exchange-v1:" + submission_id,
            )
        )
        finding_counts = Counter(
            finding.code for finding in imported.quality.findings
        )
        exchange = ExchangeMessageInput(
            message_id=message_id,
            direction="inbound",
            message_type="provided_sample_demo_import_v1",
            mine_id=mine.mine_id,
            agent_id=agent_id,
            body={
                "schema_version": V2_DEMO_SCHEMA_VERSION,
                "demo_dataset": True,
                "synthetic_demo": False,
                "workbook_example": True,
                "data_origin": "bundled_workbook_values",
                "not_enterprise_signed": True,
                "offline_seed": True,
                "regulatory_use": "prohibited",
                "disclaimer": V2_DEMO_DISCLAIMER,
                "mine_display_name": mine.mine_name,
                "identity_binding": "user_supplied_demo_mapping_not_workbook_title",
                "original_filename": mine.original_filename,
                "original_workbook_title": imported.source_title,
                "source_sha256": source_digest,
                "source_report_month": imported.report_month,
                "source_value_policy": WORKBOOK_DEMO_VALUE_POLICY,
                "formula_policy": "stored_biff8_cached_value_only_no_execution",
                "formula_cell_count": imported.formula_cell_count,
                "closed_through": imported.closed_through.isoformat(),
                "open_row_count": imported.quality.open_day_count,
                "source_quality_finding_counts": dict(
                    sorted(finding_counts.items())
                ),
                "unit_binding": "configured_demo_mapping_not_declared_in_workbook",
                "personnel_binding": (
                    "source_用工量_mapped_to_mine_entry_persons_"
                    "for_demo_requires_business_confirmation"
                ),
                "comparison_context_policy": (
                    "source_dimensions_unverified_excluded_from_synthetic_peer_group"
                ),
                "submission_id": submission_id,
                "payload_sha256": hashlib.sha256(
                    submission.model_dump_json().encode("utf-8")
                ).hexdigest(),
            },
            exchanged_at=datetime(2026, 8, 1, tzinfo=UTC),
        )
        plan.append(
            _PlannedSubmission(
                mine=mine,
                month_index=0,
                submission=submission,
                exchange=exchange,
                agent_id=agent_id,
            )
        )
    return plan


def _load_workbook_example(mine: V2DemoMine) -> FiveQuantityImportResult:
    if (
        mine.data_origin != "bundled_workbook_values"
        or mine.bundled_filename is None
        or mine.original_filename is None
        or mine.expected_source_sha256 is None
    ):
        raise V2DemoSeedError("演示样表清单不完整")
    try:
        content = (
            files("mineguard")
            .joinpath("demo_samples", mine.bundled_filename)
            .read_bytes()
        )
    except (FileNotFoundError, OSError) as error:
        raise V2DemoSeedError(
            f"演示样表资源缺失：{mine.bundled_filename}"
        ) from error
    digest = hashlib.sha256(content).hexdigest()
    if digest != mine.expected_source_sha256:
        raise V2DemoSeedError(
            f"演示样表完整性校验失败：{mine.bundled_filename}"
        )
    request = FiveQuantityImportRequest.model_validate(
        {
            "mine_id": mine.mine_id,
            "source": {
                "source_id": f"bundled-demo:{mine.mine_id}:2026-07",
                "filename": mine.original_filename,
                "received_at": "2026-08-01T00:00:00Z",
                "origin_system": "bundled-user-provided-demo-workbook",
                "expected_sha256": digest,
            },
            "closed_through": "2026-07-30",
            "report_month": "2026-07",
            "content_bytes": content,
        }
    )
    try:
        imported = import_five_quantity_et(request)
    except ValueError as error:
        raise V2DemoSeedError(
            f"演示样表解析失败：{mine.bundled_filename}"
        ) from error
    if (
        imported.source_sha256 != digest
        or imported.report_month != "2026-07"
        or len(imported.days) != 31
        or imported.days[0].date != WORKBOOK_DEMO_PERIOD_START
        or imported.days[-1].date != WORKBOOK_DEMO_PERIOD_END
    ):
        raise V2DemoSeedError(
            f"演示样表月份或内容清单不匹配：{mine.bundled_filename}"
        )
    return imported


def _map_imported_workbook_day(day: ImportedFiveQuantityDay) -> FiveQuantityDay:
    personnel, personnel_quality = _map_numeric_quantity(
        day,
        day.labor,
        columns=(3, 4, 5, 6),
        personnel_semantics=True,
    )
    electricity, electricity_quality = _map_numeric_quantity(
        day,
        day.electricity,
        columns=(7, 8, 9, 10),
    )
    production, production_quality = _map_numeric_quantity(
        day,
        day.production,
        columns=(15, 16, 17, 18),
    )
    detonators, detonator_quality = _map_explosive_quantity(
        day,
        field="detonators",
    )
    explosives, explosive_quality = _map_explosive_quantity(
        day,
        field="explosives",
    )
    ventilation_flags = _source_cell_flags(
        day,
        column=2,
        value=day.ventilation,
        partial_when_missing=True,
    )
    ventilation = ReportedQuantity(
        daily_total=day.ventilation,
        # The workbook contains one daily ventilation column and does not
        # disclose whether it is an average or a snapshot.  Leaving the
        # aggregation unset is more faithful than inventing either meaning.
        daily_aggregation=None,
        shifts=None,
    )
    return FiveQuantityDay(
        date=day.date,
        ventilation_m3_min=ventilation,
        mine_entry_persons=personnel,
        electricity_kwh=electricity,
        detonators_count=detonators,
        explosives_kg=explosives,
        production_t=production,
        declared_operating_state="unknown",
        shift_metadata=None,
        quality={
            "ventilation_m3_min": ReportedQuality(
                daily_total=ventilation_flags
            ),
            "mine_entry_persons": personnel_quality,
            "electricity_kwh": electricity_quality,
            "detonators_count": detonator_quality,
            "explosives_kg": explosive_quality,
            "production_t": production_quality,
        },
    )


def _map_numeric_quantity(
    day: ImportedFiveQuantityDay,
    values: Any,
    *,
    columns: tuple[int, int, int, int],
    personnel_semantics: bool = False,
) -> tuple[ReportedQuantity, ReportedQuality]:
    raw_values = (
        values.zero_shift,
        values.eight_shift,
        values.four_shift,
        values.daily_total,
    )
    provided_shift_count = sum(value is not None for value in raw_values[:3])
    flags = tuple(
        _source_cell_flags(
            day,
            column=column,
            value=value,
            personnel_semantics=personnel_semantics,
            partial_when_missing=(
                index == 3
                or 0 < provided_shift_count < 3
                or values.daily_total is None
            ),
        )
        for index, (column, value) in enumerate(
            zip(columns, raw_values, strict=True)
        )
    )
    return (
        ReportedQuantity(
            daily_total=values.daily_total,
            daily_aggregation="sum",
            shifts=ShiftValues(
                zero_shift=values.zero_shift,
                eight_shift=values.eight_shift,
                four_shift=values.four_shift,
            ),
        ),
        ReportedQuality(
            zero_shift=flags[0],
            eight_shift=flags[1],
            four_shift=flags[2],
            daily_total=flags[3],
        ),
    )


def _map_explosive_quantity(
    day: ImportedFiveQuantityDay,
    *,
    field: Literal["detonators", "explosives"],
) -> tuple[ReportedQuantity, ReportedQuality]:
    usages = (
        day.explosives.zero_shift,
        day.explosives.eight_shift,
        day.explosives.four_shift,
        day.explosives.daily_total,
    )
    values = tuple(getattr(item, field) for item in usages)
    columns = (11, 12, 13, 14)
    provided_shift_count = sum(value is not None for value in values[:3])
    flags = tuple(
        _source_cell_flags(
            day,
            column=column,
            value=value,
            partial_when_missing=(
                index == 3
                or 0 < provided_shift_count < 3
                or values[3] is None
            ),
        )
        for index, (column, value) in enumerate(
            zip(columns, values, strict=True)
        )
    )
    return (
        ReportedQuantity(
            daily_total=values[3],
            daily_aggregation="sum",
            shifts=ShiftValues(
                zero_shift=values[0],
                eight_shift=values[1],
                four_shift=values[2],
            ),
        ),
        ReportedQuality(
            zero_shift=flags[0],
            eight_shift=flags[1],
            four_shift=flags[2],
            daily_total=flags[3],
        ),
    )


def _source_cell_flags(
    day: ImportedFiveQuantityDay,
    *,
    column: int,
    value: float | None,
    personnel_semantics: bool = False,
    partial_when_missing: bool = False,
) -> tuple[str, ...]:
    flags = ["unit_mapping_not_declared_in_source"]
    if personnel_semantics:
        flags.append("source_business_semantics_requires_confirmation")
    if value is None:
        flags.append("missing")
        if partial_when_missing:
            flags.append("partial")
    if not day.is_closed:
        flags.extend(("open_period_unclosed", "partial"))
    raw_cell = day.raw_cells[column - 1]
    if raw_cell.is_formula:
        flags.append("formula_cached_value")
    return tuple(dict.fromkeys(flags))


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
            quality={metric: missing_quality for metric in LEGACY_METRICS},
            **{
                metric: ReportedQuantity(shifts=ShiftValues())
                for metric in LEGACY_METRICS
            },
        )

    # Do not derive every quantity from one daily multiplier.  The dashboard
    # normalises each metric to its own visible range, so fixed metric-to-output
    # ratios make otherwise different units collapse onto the same line.  The
    # deterministic cycles below model distinct operational drivers while
    # keeping each relationship inside a plausible, stable envelope:
    #
    # * production follows the face/haulage organisation cycle;
    # * ventilation is mostly a continuous safety load;
    # * electricity combines a fixed auxiliary load and a production load;
    # * mine entries mostly follow staffing rather than daily tonnage;
    # * blasting-material subitems follow their own work schedule.
    #
    # Absolute calendar ordinals make adjacent months continuous and replaying
    # a seed byte-for-byte deterministic.  Mine-specific phases avoid making
    # all eight synthetic mines move in lockstep.
    ordinal = observed_date.toordinal()
    production_factor = 1.0 + _wave(
        ordinal,
        mine_index,
        primary_period=9,
        primary_amplitude=0.036,
        secondary_period=17,
        secondary_amplitude=0.018,
        phase=1,
    )
    production = mine.base_production_t * production_factor
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
    ventilation_factor = (
        0.82
        + 0.18 * production_factor
        + _wave(
            ordinal,
            mine_index,
            primary_period=13,
            primary_amplitude=0.026,
            secondary_period=7,
            secondary_amplitude=0.012,
            phase=3,
        )
    )
    electricity_factor = (
        0.25
        + 0.75 * production_factor
        + _wave(
            ordinal,
            mine_index,
            primary_period=11,
            primary_amplitude=0.036,
            secondary_period=5,
            secondary_amplitude=0.014,
            phase=7,
        )
    )
    mine_entry_factor = (
        0.50
        + 0.50 * production_factor
        + _wave(
            ordinal,
            mine_index,
            primary_period=8,
            primary_amplitude=0.035,
            secondary_period=19,
            secondary_amplitude=0.012,
            phase=11,
        )
    )
    detonator_factor = production_factor * (
        1.0
        + _wave(
            ordinal,
            mine_index,
            primary_period=5,
            primary_amplitude=0.075,
            secondary_period=12,
            secondary_amplitude=0.030,
            phase=13,
        )
    )
    explosives_factor = production_factor * (
        1.0
        + _wave(
            ordinal,
            mine_index,
            primary_period=6,
            primary_amplitude=0.065,
            secondary_period=14,
            secondary_amplitude=0.025,
            phase=17,
        )
    )
    values = {
        "ventilation_m3_min": 3.0 * mine.base_production_t * ventilation_factor,
        "electricity_kwh": (
            electricity_ratio * mine.base_production_t * electricity_factor
        ),
        # Daily mine entries and detonators are counts.  A slightly larger
        # blasting baseline avoids quantisation turning the detonator series
        # into a constant ten-count line in the 0.9--1.2 kt/day demo band.
        "detonators_count": float(
            round(0.022 * mine.base_production_t * detonator_factor)
        ),
        "explosives_kg": 0.050 * mine.base_production_t * explosives_factor,
        "mine_entry_persons": round(
            0.10 * mine.base_production_t * mine_entry_factor
        ),
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


def _wave(
    ordinal: int,
    mine_index: int,
    *,
    primary_period: int,
    primary_amplitude: float,
    secondary_period: int,
    secondary_amplitude: float,
    phase: int,
) -> float:
    """Return one bounded, deterministic operational variation component."""

    primary_angle = math.tau * (
        ordinal + phase + mine_index * (phase % 5 + 1)
    ) / primary_period
    secondary_angle = math.tau * (
        ordinal + phase * 2 + mine_index * (phase % 7 + 1)
    ) / secondary_period
    return (
        primary_amplitude * math.sin(primary_angle)
        + secondary_amplitude * math.cos(secondary_angle)
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
    "SYNTHETIC_ONLY_DISCLAIMER",
    "SYNTHETIC_DEMO_DISCLAIMER",
    "V2_ALL_DEMO_MINES",
    "V2_DEMO_DATABASE_FILENAME",
    "V2_DEMO_DISCLAIMER",
    "V2_DEMO_MINES",
    "V2_WORKBOOK_DEMO_MINES",
    "V2DemoSeedError",
    "V2DemoSeedResult",
    "V2DemoStatusResult",
    "V2DemoStateOwnershipError",
    "claim_v2_demo_state_directory",
    "seed_v2_demo",
    "seed_v2_demo_state",
    "v2_demo_status",
]
