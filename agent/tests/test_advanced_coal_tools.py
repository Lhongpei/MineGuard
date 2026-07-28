from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from enterprise_agent.models import new_draft
from enterprise_agent.tools import ToolContext, ToolProtocolError, ToolRegistry
from enterprise_agent.tools.advanced import advanced_tool_specs
from enterprise_agent.util import canonical_json


def observation(
    observation_id: str,
    metric_code: str,
    value: float,
    unit: str,
    observed_at: datetime,
) -> dict[str, Any]:
    return {
        "source_id": f"source-{metric_code}",
        "observation_id": observation_id,
        "metric_code": metric_code,
        "value": value,
        "unit": unit,
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "received_at": (observed_at + timedelta(seconds=2))
        .isoformat()
        .replace("+00:00", "Z"),
        "interval_start": None,
        "interval_end": None,
        "reset_before": False,
        "sequence_no": 1,
        "revision": 0,
        "payload_sha256": "a" * 64,
        "signature": "b" * 64,
    }


def draft_document(
    *,
    draft_id: str = "draft-current",
    start: datetime | None = None,
    duration_days: int = 1,
    observations: list[dict[str, Any]] | None = None,
    status: str = "draft",
    profile_id: str = "coal-balance-default",
    profile_version: str = "2026.07",
    shift_code: str = "A",
    mine_id: str = "mine-001",
) -> dict[str, Any]:
    window_start = start or datetime(2026, 7, 20, tzinfo=UTC)
    window_end = window_start + timedelta(days=duration_days)
    value = new_draft()
    value.update(
        {
            "draft_id": draft_id,
            "enterprise_id": "enterprise-001",
            "enterprise_name": "示例能源有限公司",
            "unified_social_credit_code": "91110000ABCDEFGH1X",
            "mine_id": mine_id,
            "mine_name": "示例一号矿",
            "window_start": window_start.isoformat().replace("+00:00", "Z"),
            "window_end": window_end.isoformat().replace("+00:00", "Z"),
            "profile_id": profile_id,
            "profile_version": profile_version,
            "operational_context": {
                "regime_code": "NORMAL_PRODUCTION",
                "shift_code": shift_code,
                "season_code": "SUMMER",
                "maintenance": False,
                "approved_event_codes": [],
                "tags": [],
            },
            "observations": observations or [],
            "status": status,
            "receipt": None,
            "_meta": {
                "revision": 3,
                "confirmed_revision": None,
                "confirmed": False,
                "confirmation": None,
                "submitted": status == "submitted",
                "latest_submission": None,
                "deleted": False,
                "deleted_at": None,
                "created_at": window_start.isoformat().replace("+00:00", "Z"),
                "updated_at": window_end.isoformat().replace("+00:00", "Z"),
            },
        }
    )
    return value


class FakeRepository:
    """Expose the same bounded, succeeded-only history surface as Repository."""

    def __init__(
        self,
        current: dict[str, Any],
        history: list[dict[str, Any]] | None = None,
    ):
        self.current = current
        self.history = history or []
        self.history_query: dict[str, Any] | None = None
        self.filtered_non_succeeded = 0
        self.filtered_not_past = 0

    def get_draft(
        self,
        draft_id: str,
        *,
        include_deleted: bool = False,
    ) -> dict[str, Any]:
        assert include_deleted is False
        if draft_id != self.current["draft_id"]:
            raise KeyError(draft_id)
        return deepcopy(self.current)

    def list_drafts(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        raise AssertionError("高级历史工具不得读取通用草稿列表")

    def historical_observations(
        self,
        *,
        mine_id: str,
        metric_code: str,
        exclude_draft_id: str | None = None,
        before_window_start: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        self.history_query = {
            "mine_id": mine_id,
            "metric_code": metric_code,
            "exclude_draft_id": exclude_draft_id,
            "before_window_start": before_window_start,
            "limit": limit,
        }
        assert before_window_start is not None
        before = datetime.fromisoformat(before_window_start.replace("Z", "+00:00"))
        rows: list[dict[str, Any]] = []
        for candidate in self.history:
            if candidate.get("_submission_status") != "succeeded":
                self.filtered_non_succeeded += 1
                continue
            end = datetime.fromisoformat(
                str(candidate["window_end"]).replace("Z", "+00:00")
            )
            if end >= before:
                self.filtered_not_past += 1
                continue
            if (
                candidate["mine_id"] != mine_id
                or candidate["draft_id"] == exclude_draft_id
            ):
                continue
            for item in candidate["observations"]:
                if item["metric_code"] != metric_code:
                    continue
                rows.append(
                    {
                        "draft_id": candidate["draft_id"],
                        "window_start": candidate["window_start"],
                        "window_end": candidate["window_end"],
                        "observed_at": item["observed_at"],
                        "value": item["value"],
                        "unit": item["unit"],
                        "observation_id": item["observation_id"],
                        "source_id": item["source_id"],
                        "profile_id": candidate["profile_id"],
                        "profile_version": candidate["profile_version"],
                        "operational_context": deepcopy(
                            candidate["operational_context"]
                        ),
                    }
                )
        return rows[:limit]


def registry(
    current: dict[str, Any] | None = None,
    history: list[dict[str, Any]] | None = None,
) -> tuple[ToolRegistry, FakeRepository | None]:
    if current is None:
        return ToolRegistry(advanced_tool_specs()), None
    repo = FakeRepository(current, history)
    return (
        ToolRegistry(
            advanced_tool_specs(),
            context=ToolContext(repository=repo),
        ),
        repo,
    )


def assert_json_safe(value: Any) -> None:
    encoded = canonical_json(value)
    assert "NaN" not in encoded
    assert "Infinity" not in encoded


def test_advanced_tool_metadata_distinguishes_scenarios_and_repository() -> None:
    specs = {item.name: item for item in advanced_tool_specs()}
    assert set(specs) == {
        "convert_coal_quality_basis",
        "evaluate_coal_blend",
        "calculate_inventory_coverage",
        "compare_metric_series",
        "analyze_historical_trend",
    }
    for name in ("convert_coal_quality_basis", "evaluate_coal_blend"):
        assert specs[name].evidence_grounding == "user_supplied"
        assert specs[name].scenario_only is True
    for name in (
        "calculate_inventory_coverage",
        "compare_metric_series",
        "analyze_historical_trend",
    ):
        assert specs[name].evidence_grounding == "repository_grounded"
        assert specs[name].scenario_only is False
    assert all(
        not item.mutating
        and not item.requires_approval
        and not item.network_access
        and item.input_schema["additionalProperties"] is False
        for item in specs.values()
    )


def test_quality_basis_conversion_and_input_consistency() -> None:
    tools, _ = registry()
    result = tools.execute(
        "convert_coal_quality_basis",
        {
            "property_code": "total_sulfur",
            "value_percent": 1,
            "from_basis": "ar",
            "to_basis": "d",
            "total_moisture_ar_percent": 10,
            "ash_ar_percent": 20,
        },
    )
    assert result.data["converted_value_percent"] == pytest.approx(1 / 0.9)
    assert result.data["conversion_factor"] == pytest.approx(1 / 0.9)
    assert result.data["input_origin"] == "caller_supplied_scenario"
    assert result.data["uncertainty"]["laboratory_method_verified"] is False
    assert_json_safe(result.as_dict())

    ash = tools.execute(
        "convert_coal_quality_basis",
        {
            "property_code": "ash",
            "value_percent": 20 / 0.9,
            "from_basis": "d",
            "to_basis": "ar",
            "total_moisture_ar_percent": 10,
            "ash_ar_percent": 20,
        },
    )
    assert ash.data["converted_value_percent"] == pytest.approx(20)
    assert ash.data["input_consistency_checked"] is True

    air_dried = tools.execute(
        "convert_coal_quality_basis",
        {
            "property_code": "total_sulfur",
            "value_percent": 1,
            "from_basis": "ar",
            "to_basis": "ad",
            "total_moisture_ar_percent": 10,
            "moisture_ad_percent": 2,
            "ash_ar_percent": 20,
        },
    )
    assert air_dried.data["converted_value_percent"] == pytest.approx(98 / 90)
    assert air_dried.data["moisture_ad_percent"] == 2


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"property_code": "ash", "to_basis": "daf"}, "ash_daf_undefined"),
        (
            {
                "total_moisture_ar_percent": 80,
                "ash_ar_percent": 20,
            },
            "invalid_quality_denominator",
        ),
        (
            {
                "property_code": "ash",
                "value_percent": 21,
            },
            "inconsistent_ash_input",
        ),
        (
            {
                "to_basis": "ad",
            },
            "moisture_ad_required",
        ),
    ],
)
def test_quality_basis_rejects_undefined_or_inconsistent_inputs(
    overrides: dict[str, Any],
    code: str,
) -> None:
    tools, _ = registry()
    arguments = {
        "property_code": "total_sulfur",
        "value_percent": 1,
        "from_basis": "ar",
        "to_basis": "d",
        "total_moisture_ar_percent": 10,
        "ash_ar_percent": 20,
        **overrides,
    }
    with pytest.raises(ToolProtocolError) as captured:
        tools.execute("convert_coal_quality_basis", arguments)
    assert captured.value.code == code


def blend_components() -> list[dict[str, Any]]:
    return [
        {
            "component_id": "coal-a",
            "mass_value": 60,
            "mass_unit": "t",
            "quality_basis": "ar",
            "quality": {
                "ash_percent": 10,
                "total_sulfur_percent": 1,
                "total_moisture_percent": 8,
                "gross_calorific_value_mj_kg": 25,
            },
        },
        {
            "component_id": "coal-b",
            "mass_value": 40_000,
            "mass_unit": "kg",
            "quality_basis": "ar",
            "quality": {
                "ash_percent": 20,
                "total_sulfur_percent": 2,
                "total_moisture_percent": 12,
                "gross_calorific_value_mj_kg": 20,
            },
        },
    ]


def test_blend_is_mass_weighted_and_only_checks_caller_constraints() -> None:
    tools, _ = registry()
    result = tools.execute(
        "evaluate_coal_blend",
        {
            "components": blend_components(),
            "constraints": {
                "max_ash_percent": 14,
                "max_total_sulfur_percent": 1.39,
                "min_gross_calorific_value_mj_kg": 23,
            },
        },
    )
    properties = {item["property_code"]: item for item in result.data["properties"]}
    assert result.data["total_mass_t"] == 100
    assert properties["ash_percent"]["value"] == pytest.approx(14)
    assert properties["total_sulfur_percent"]["value"] == pytest.approx(1.4)
    assert properties["total_moisture_percent"]["value"] == pytest.approx(9.6)
    assert properties["gross_calorific_value_mj_kg"]["value"] == pytest.approx(23)
    evaluations = {
        item["constraint_code"]: item for item in result.data["constraint_evaluations"]
    }
    assert evaluations["max_ash_percent"]["status"] == "meets_supplied_constraint"
    assert (
        evaluations["max_total_sulfur_percent"]["status"]
        == "does_not_meet_supplied_constraint"
    )
    assert (
        result.data["overall_constraint_status"]
        == "one_or_more_supplied_constraints_not_met"
    )
    assert result.data["uncertainty"]["recipe_optimized"] is False
    assert "未执行配方优化" in result.summary
    assert_json_safe(result.as_dict())


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (
            lambda items: items[1].update({"quality_basis": "d"}),
            "mixed_quality_basis",
        ),
        (
            lambda items: [item.update({"quality_basis": "d"}) for item in items],
            "invalid_moisture_basis",
        ),
    ],
)
def test_blend_rejects_mixed_basis_and_moisture_on_non_ar_basis(
    mutator,
    code: str,
) -> None:
    tools, _ = registry()
    components = blend_components()
    mutator(components)
    with pytest.raises(ToolProtocolError) as captured:
        tools.execute("evaluate_coal_blend", {"components": components})
    assert captured.value.code == code


def test_blend_does_not_impute_a_missing_component_quality() -> None:
    tools, _ = registry()
    components = blend_components()
    components[0]["quality"] = {"ash_percent": 10}
    components[1]["quality"] = {"total_sulfur_percent": 2}
    result = tools.execute(
        "evaluate_coal_blend",
        {
            "components": components,
            "constraints": {"max_ash_percent": 15},
        },
    )
    properties = {item["property_code"]: item for item in result.data["properties"]}
    assert properties["ash_percent"]["status"] == "incomplete"
    assert properties["ash_percent"]["value"] is None
    assert properties["ash_percent"]["missing_component_ids"] == ["coal-b"]
    assert result.data["constraint_evaluations"][0]["status"] == "not_evaluated"
    assert result.data["overall_constraint_status"] == "not_evaluated"


@pytest.mark.parametrize("duration_days", [7, 10])
def test_inventory_coverage_uses_window_average_rate(
    duration_days: int,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = start + timedelta(days=duration_days)
    current = draft_document(
        start=start,
        duration_days=duration_days,
        observations=[
            observation(
                "closing-1",
                "coal.closing_inventory_t",
                140,
                "t",
                end - timedelta(seconds=1),
            ),
            observation(
                "outflow-1",
                "sales.raw_shipped_t",
                duration_days * 10,
                "t",
                end - timedelta(seconds=2),
            ),
        ],
    )
    tools, _ = registry(current)
    result = tools.execute(
        "calculate_inventory_coverage",
        {"draft_id": "draft-current"},
    )
    assert result.data["status"] == "evaluated"
    assert result.data["reporting_window_days"] == duration_days
    assert result.data["average_daily_outflow_t"] == 10
    assert result.data["coverage_days"] == 14
    assert result.data["uncertainty"]["future_demand_forecast"] is False


def test_inventory_multiple_closing_snapshots_are_not_summed() -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    current = draft_document(
        start=start,
        duration_days=7,
        observations=[
            observation(
                "closing-1",
                "coal.closing_inventory_t",
                100,
                "t",
                start + timedelta(days=6),
            ),
            observation(
                "closing-2",
                "coal.closing_inventory_t",
                140,
                "t",
                start + timedelta(days=7, seconds=-1),
            ),
            observation(
                "outflow-1",
                "sales.raw_shipped_t",
                70,
                "t",
                start + timedelta(days=7, seconds=-2),
            ),
        ],
    )
    tools, _ = registry(current)
    result = tools.execute(
        "calculate_inventory_coverage",
        {"draft_id": "draft-current"},
    )
    assert result.data["status"] == "ambiguous_closing_inventory_snapshots"
    assert result.data["closing_observation_id_count"] == 2
    assert result.data["closing_inventory_t"] is None
    assert result.data["average_daily_outflow_t"] is None
    assert result.data["coverage_days"] is None


@pytest.mark.parametrize(
    ("outflow", "expected_status"),
    [(None, "outflow_missing"), (0, "zero_outflow")],
)
def test_inventory_missing_or_zero_outflow_is_not_evaluated(
    outflow: float | None,
    expected_status: str,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    observations = [
        observation(
            "closing-1",
            "coal.closing_inventory_t",
            140,
            "t",
            start + timedelta(days=7, seconds=-1),
        )
    ]
    if outflow is not None:
        observations.append(
            observation(
                "outflow-1",
                "sales.raw_shipped_t",
                outflow,
                "t",
                start + timedelta(days=7, seconds=-2),
            )
        )
    current = draft_document(
        start=start,
        duration_days=7,
        observations=observations,
    )
    tools, _ = registry(current)
    result = tools.execute(
        "calculate_inventory_coverage",
        {"draft_id": "draft-current"},
    )
    assert result.data["status"] == expected_status
    assert result.data["coverage_days"] is None


def test_metric_series_matches_once_converts_units_and_includes_boundaries() -> None:
    start = datetime(2026, 7, 20, tzinfo=UTC)
    current = draft_document(
        start=start,
        observations=[
            observation("left-1", "coal.production_t", 1, "t", start),
            observation(
                "left-2",
                "coal.production_t",
                2,
                "t",
                start + timedelta(minutes=10),
            ),
            observation(
                "right-1",
                "coal.main_transport_t",
                1_000,
                "kg",
                start + timedelta(seconds=60),
            ),
            observation(
                "right-2",
                "coal.main_transport_t",
                1_800,
                "kg",
                start + timedelta(minutes=11),
            ),
            observation(
                "right-unmatched",
                "coal.main_transport_t",
                5_000,
                "kg",
                start + timedelta(hours=1),
            ),
        ],
    )
    tools, _ = registry(current)
    result = tools.execute(
        "compare_metric_series",
        {
            "draft_id": "draft-current",
            "left_metric_code": "coal.production_t",
            "right_metric_code": "coal.main_transport_t",
            "tolerance_seconds": 60,
            "relative_tolerance": 0.1,
        },
    )
    assert result.data["status"] == "evaluated"
    assert result.data["comparison_unit"] == "t"
    assert result.data["matched_pair_count"] == 2
    assert result.data["right_unmatched_count"] == 1
    assert result.data["outside_tolerance_count"] == 0
    assert [item["time_gap_seconds"] for item in result.data["pairs"]] == [
        60,
        60,
    ]
    assert result.data["pairs"][1]["relative_gap"] == pytest.approx(0.1)
    assert result.data["pairs"][1]["within_tolerance"] is True
    assert result.data["uncertainty"]["automatic_exact_unit_conversion"] is True
    assert result.data["uncertainty"]["causality_determined"] is False


def test_metric_series_rejects_an_excessive_time_tolerance() -> None:
    tools, _ = registry()
    with pytest.raises(ToolProtocolError) as captured:
        tools.execute(
            "compare_metric_series",
            {
                "draft_id": "draft-current",
                "left_metric_code": "coal.production_t",
                "right_metric_code": "coal.main_transport_t",
                "tolerance_seconds": 3_601,
            },
        )
    assert captured.value.code == "schema_maximum"
    assert captured.value.path == "$.tolerance_seconds"


def test_metric_series_output_is_bounded_and_hashes_the_full_result() -> None:
    start = datetime(2026, 7, 20, tzinfo=UTC)
    observations: list[dict[str, Any]] = []
    for index in range(105):
        when = start + timedelta(minutes=index)
        observations.extend(
            [
                observation(
                    f"left-{index:03d}",
                    "coal.production_t",
                    index + 1,
                    "t",
                    when,
                ),
                observation(
                    f"right-{index:03d}",
                    "coal.main_transport_t",
                    index + 1,
                    "t",
                    when,
                ),
            ]
        )
    current = draft_document(
        start=start,
        duration_days=1,
        observations=observations,
    )
    tools, _ = registry(current)
    result = tools.execute(
        "compare_metric_series",
        {
            "draft_id": "draft-current",
            "left_metric_code": "coal.production_t",
            "right_metric_code": "coal.main_transport_t",
            "tolerance_seconds": 0,
        },
    )
    assert result.data["pair_count"] == 105
    assert result.data["returned_pair_count"] == 100
    assert len(result.data["pairs"]) == 100
    assert result.data["pairs_truncated"] is True
    assert len(result.data["pairs_sha256"]) == 64
    assert_json_safe(result.as_dict())


def historical_document(
    *,
    draft_id: str,
    start: datetime,
    value: float,
    submission_status: str = "succeeded",
    profile_id: str = "coal-balance-default",
    shift_code: str = "A",
) -> dict[str, Any]:
    document = draft_document(
        draft_id=draft_id,
        start=start,
        observations=[
            observation(
                f"obs-{draft_id}",
                "coal.production_t",
                value,
                "t",
                start + timedelta(hours=23),
            )
        ],
        status="submitted",
        profile_id=profile_id,
        shift_code=shift_code,
    )
    document["_submission_status"] = submission_status
    return document


def test_historical_trend_uses_only_past_succeeded_same_context_history() -> None:
    current_start = datetime(2026, 7, 20, tzinfo=UTC)
    current = draft_document(
        start=current_start,
        observations=[
            observation(
                "obs-current",
                "coal.production_t",
                160,
                "t",
                current_start + timedelta(hours=23),
            )
        ],
    )
    history = [
        historical_document(
            draft_id=f"history-{index}",
            start=datetime(2026, 7, index, tzinfo=UTC),
            value=90 + index * 10,
        )
        for index in range(1, 6)
    ]
    history.extend(
        [
            historical_document(
                draft_id="wrong-shift",
                start=datetime(2026, 7, 7, tzinfo=UTC),
                value=999_999,
                shift_code="B",
            ),
            historical_document(
                draft_id="wrong-profile",
                start=datetime(2026, 7, 8, tzinfo=UTC),
                value=999_999,
                profile_id="other-profile",
            ),
            historical_document(
                draft_id="not-succeeded",
                start=datetime(2026, 7, 9, tzinfo=UTC),
                value=999_999,
                submission_status="failed",
            ),
            historical_document(
                draft_id="future-succeeded",
                start=datetime(2026, 7, 21, tzinfo=UTC),
                value=999_999,
            ),
        ]
    )
    tools, repo = registry(current, history)
    assert repo is not None
    result = tools.execute(
        "analyze_historical_trend",
        {
            "draft_id": "draft-current",
            "metric_code": "coal.production_t",
            "normalization": "per_day",
        },
    )
    assert result.data["status"] == "evaluated"
    assert result.data["history_sample_size"] == 5
    assert result.data["minimum_history"] == 5
    assert result.data["unit"] == "t/day"
    assert result.data["direction"] == "increasing"
    assert result.data["theil_sen_slope_per_day"] > 0
    assert result.data["excluded_context_count"] == 2
    assert sum(item["current"] for item in result.data["points"]) == 1
    assert {item["draft_id"] for item in result.data["points"]}.isdisjoint(
        {
            "wrong-shift",
            "wrong-profile",
            "not-succeeded",
            "future-succeeded",
        }
    )
    assert repo.filtered_non_succeeded == 1
    assert repo.filtered_not_past == 1
    assert repo.history_query == {
        "mine_id": "mine-001",
        "metric_code": "coal.production_t",
        "exclude_draft_id": "draft-current",
        "before_window_start": "2026-07-20T00:00:00Z",
        "limit": 500,
    }
    uncertainty = result.data["uncertainty"]
    assert uncertainty["future_data_excluded"] is True
    assert uncertainty["only_succeeded_submissions_in_history"] is True
    assert uncertainty["context_matched"] is True
    assert uncertainty["linear_projection_is_forecast"] is False
    assert "forecast_value" not in result.data
    assert "projected_value" not in result.data
    assert_json_safe(result.as_dict())


def test_historical_trend_has_fixed_minimum_and_additive_metric_allowlist() -> None:
    trend = {item.name: item for item in advanced_tool_specs()}[
        "analyze_historical_trend"
    ]
    assert trend.input_schema["properties"]["metric_code"]["enum"] == [
        "coal.reported_output_t",
        "coal.production_t",
        "coal.main_transport_t",
        "coal.purchase_in_t",
        "sales.raw_shipped_t",
        "coal.sale_out_t",
        "wash.feed_t",
        "coal.processing_input_t",
    ]
    assert "min_history" not in trend.input_schema["properties"]
    assert "context_match" not in trend.input_schema["properties"]

    tools, _ = registry()
    with pytest.raises(ToolProtocolError) as captured:
        tools.execute(
            "analyze_historical_trend",
            {
                "draft_id": "draft-current",
                "metric_code": "coal.closing_inventory_t",
            },
        )
    assert captured.value.code == "schema_enum"

    with pytest.raises(ToolProtocolError) as captured:
        tools.execute(
            "analyze_historical_trend",
            {
                "draft_id": "draft-current",
                "metric_code": "coal.production_t",
                "min_history": 2,
            },
        )
    assert captured.value.code == "schema_additional_property"


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        (
            "convert_coal_quality_basis",
            {
                "property_code": "total_sulfur",
                "value_percent": 1,
                "from_basis": "ar",
                "to_basis": "d",
                "total_moisture_ar_percent": 10,
                "ash_ar_percent": 20,
            },
        ),
        (
            "evaluate_coal_blend",
            {"components": blend_components()},
        ),
        (
            "calculate_inventory_coverage",
            {"draft_id": "draft-current"},
        ),
        (
            "compare_metric_series",
            {
                "draft_id": "draft-current",
                "left_metric_code": "coal.production_t",
                "right_metric_code": "coal.main_transport_t",
            },
        ),
        (
            "analyze_historical_trend",
            {
                "draft_id": "draft-current",
                "metric_code": "coal.production_t",
            },
        ),
    ],
)
def test_all_advanced_tools_reject_extra_input_fields(
    name: str,
    arguments: dict[str, Any],
) -> None:
    tools, _ = registry()
    with pytest.raises(ToolProtocolError) as captured:
        tools.execute(name, {**arguments, "ignore_previous_rules": True})
    assert captured.value.code == "schema_additional_property"
    assert captured.value.path == "$.ignore_previous_rules"
