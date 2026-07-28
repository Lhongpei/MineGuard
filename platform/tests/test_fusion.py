from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from mineguard.fusion import (
    ConservativeFusionInput,
    fuse_evidence,
)


def _input(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "physical_status": "consistent",
        "original_review_priority": "NONE",
        "evidence_grade": "C",
        "physical_diagnostics_complete": True,
        "data_quality_status": "sufficient",
        "historical_status": "within_baseline",
        "temporal_status": "normal",
        "legitimate_scenario_matches": [],
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    (
        "overrides",
        "expected_agreement",
        "expected_priority",
        "expected_historical_support",
    ),
    [
        ({}, "no_signal", "NONE", False),
        (
            {
                "physical_status": "inconsistent",
                "original_review_priority": "P1",
                "evidence_grade": "A",
            },
            "physical_only",
            "P1",
            False,
        ),
        (
            {
                "physical_status": "inconsistent",
                "original_review_priority": "P1",
                "evidence_grade": "A",
                "historical_status": "historically_rare",
            },
            "corroborated",
            "P1",
            True,
        ),
        (
            {
                "physical_status": "inconsistent",
                "original_review_priority": "P2",
                "evidence_grade": "B",
                "historical_status": "historically_rare",
            },
            "corroborated",
            "P2",
            True,
        ),
        (
            {
                "physical_status": "inconsistent",
                "original_review_priority": "P2",
                "evidence_grade": "B",
                "temporal_status": "anomalous",
            },
            "corroborated",
            "P2",
            False,
        ),
        (
            {
                "physical_status": "inconsistent",
                "original_review_priority": "NONE",
                "evidence_grade": "C",
            },
            "physical_only",
            "P2",
            False,
        ),
        (
            {
                "physical_status": "consistent",
                "historical_status": "historically_rare",
            },
            "historical_only",
            "P2",
            False,
        ),
        (
            {
                "physical_status": "consistent",
                "temporal_status": "anomalous",
            },
            "historical_only",
            "P2",
            False,
        ),
        (
            {
                "physical_status": "consistent",
                "original_review_priority": "DATA",
                "historical_status": "historically_rare",
            },
            "historical_only",
            "DATA",
            False,
        ),
        (
            {
                "physical_status": "consistent",
                "original_review_priority": "P2",
            },
            "no_signal",
            "P2",
            False,
        ),
        (
            {
                "historical_status": "insufficient_history",
            },
            "insufficient",
            "NONE",
            False,
        ),
        (
            {
                "temporal_status": "insufficient_history",
            },
            "insufficient",
            "NONE",
            False,
        ),
    ],
)
def test_conservative_fusion_rule_table(
    overrides: dict[str, Any],
    expected_agreement: str,
    expected_priority: str,
    expected_historical_support: bool,
) -> None:
    result = fuse_evidence(_input(**overrides))

    assert result.physical_status == overrides.get(
        "physical_status",
        "consistent",
    )
    assert result.physical_status_unchanged is True
    assert result.agreement == expected_agreement
    assert result.shadow_priority == expected_priority
    assert result.historical_supports_physical is expected_historical_support


@pytest.mark.parametrize("physical_status", ["inconclusive", "solver_error"])
@pytest.mark.parametrize(
    "historical_status",
    ["within_baseline", "historically_rare"],
)
@pytest.mark.parametrize("temporal_status", ["normal", "anomalous"])
def test_unresolved_physical_status_always_forces_data(
    physical_status: str,
    historical_status: str,
    temporal_status: str,
) -> None:
    result = fuse_evidence(
        _input(
            physical_status=physical_status,
            original_review_priority="P1",
            evidence_grade="D",
            physical_diagnostics_complete=False,
            historical_status=historical_status,
            temporal_status=temporal_status,
        )
    )

    assert result.agreement == "insufficient"
    assert result.shadow_priority == "DATA"
    assert result.physical_status == physical_status
    assert result.physical_status_unchanged is True
    assert "inconclusive_or_solver_error_forces_data_priority" in result.safeguards


def test_blocked_data_overrides_every_signal_and_priority() -> None:
    result = fuse_evidence(
        _input(
            physical_status="inconsistent",
            original_review_priority="P1",
            evidence_grade="A",
            data_quality_status="blocked",
            historical_status="historically_rare",
            temporal_status="anomalous",
        )
    )

    assert result.agreement == "insufficient"
    assert result.shadow_priority == "DATA"
    assert result.historical_supports_physical is False
    assert "blocked_data_forces_data_priority" in result.safeguards


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "physical_diagnostics_complete": False,
        },
        {
            "evidence_grade": "B",
        },
        {
            "data_quality_status": "degraded",
        },
    ],
)
def test_fusion_never_downgrades_an_existing_physical_p1(
    overrides: dict[str, Any],
) -> None:
    values = {
        "physical_status": "inconsistent",
        "original_review_priority": "P1",
        "evidence_grade": "A",
        "historical_status": "historically_rare",
        "temporal_status": "anomalous",
        **overrides,
    }
    result = fuse_evidence(_input(**values))

    assert result.shadow_priority == "P1"
    assert (
        "original_physical_p1_preserved_without_rewrite"
        in result.reasons
    )


def test_history_or_time_never_upgrades_p2_to_p1() -> None:
    result = fuse_evidence(
        _input(
            physical_status="inconsistent",
            original_review_priority="P2",
            evidence_grade="A",
            historical_status="historically_rare",
            temporal_status="anomalous",
        )
    )

    assert result.agreement == "corroborated"
    assert result.shadow_priority == "P2"
    assert "secondary_signal_does_not_promote_p2_to_p1" in result.reasons
    assert "historical_or_temporal_evidence_cannot_create_p1" in result.safeguards


def test_normal_history_cannot_reduce_a_physical_conflict_to_none() -> None:
    result = fuse_evidence(
        _input(
            physical_status="inconsistent",
            original_review_priority="P2",
            evidence_grade="B",
            historical_status="within_baseline",
            temporal_status="normal",
        )
    )

    assert result.agreement == "physical_only"
    assert result.shadow_priority == "P2"
    assert "physical_conflict_has_p2_priority_floor" in result.safeguards


def test_legitimate_scenario_only_explains_historical_rarity() -> None:
    consistent = fuse_evidence(
        _input(
            historical_status="historically_rare",
            legitimate_scenario_matches=["approved_maintenance"],
        )
    )
    inconsistent = fuse_evidence(
        _input(
            physical_status="inconsistent",
            original_review_priority="P1",
            evidence_grade="A",
            historical_status="historically_rare",
            legitimate_scenario_matches=["approved_maintenance"],
        )
    )

    assert consistent.agreement == "no_signal"
    assert consistent.shadow_priority == "NONE"
    assert inconsistent.agreement == "physical_only"
    assert inconsistent.shadow_priority == "P1"
    assert inconsistent.historical_supports_physical is False
    assert "historical_rarity_explained_by_legitimate_scenario" in inconsistent.reasons
    assert (
        "legitimate_scenario_only_explains_historical_signal" in inconsistent.safeguards
    )


def test_legitimate_scenario_does_not_suppress_temporal_anomaly() -> None:
    result = fuse_evidence(
        _input(
            historical_status="historically_rare",
            temporal_status="anomalous",
            legitimate_scenario_matches=["stocktake"],
        )
    )

    assert result.agreement == "historical_only"
    assert result.shadow_priority == "P2"
    assert result.historical_supports_physical is False


def test_mapping_and_model_inputs_are_deterministic() -> None:
    first_input = _input(
        physical_status="inconsistent",
        original_review_priority="P2",
        evidence_grade="B",
        historical_status="historically_rare",
        temporal_status="anomalous",
        legitimate_scenario_matches=["stocktake", "maintenance"],
    )
    second_input = {
        **first_input,
        "legitimate_scenario_matches": ["maintenance", "stocktake"],
    }

    first = fuse_evidence(first_input)
    second = fuse_evidence(ConservativeFusionInput(**second_input))

    assert first == second
    assert first.reasons == fuse_evidence(first_input).reasons
    assert first.safeguards == fuse_evidence(first_input).safeguards


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("physical_status", "unknown"),
        ("original_review_priority", "URGENT"),
        ("evidence_grade", "E"),
        ("data_quality_status", "unknown"),
        ("historical_status", "normal"),
        ("temporal_status", "rare"),
        ("physical_diagnostics_complete", "true"),
    ],
)
def test_bad_enum_and_non_strict_inputs_are_rejected(
    field: str,
    value: Any,
) -> None:
    with pytest.raises(ValidationError):
        fuse_evidence(_input(**{field: value}))


@pytest.mark.parametrize(
    "scenarios",
    [
        [""],
        ["   "],
        ["stocktake", "stocktake"],
        [" stocktake", "stocktake "],
        ["x" * 257],
        [f"scenario-{index}" for index in range(101)],
    ],
)
def test_bad_legitimate_scenario_lists_are_rejected(
    scenarios: list[str],
) -> None:
    with pytest.raises(ValidationError):
        fuse_evidence(_input(legitimate_scenario_matches=scenarios))


def test_extra_input_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        fuse_evidence({**_input(), "unexpected": True})
