from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mineguard.models import MetricObservation
from mineguard.models import ProductionAnalysisRequest
from mineguard.quality import evaluate_data_quality


ROOT = Path(__file__).resolve().parents[1]


def load_request(name: str) -> ProductionAnalysisRequest:
    payload = json.loads((ROOT / "examples" / name).read_text(encoding="utf-8"))
    return ProductionAnalysisRequest.model_validate(payload)


def test_complete_example_passes_quality_gate() -> None:
    result = evaluate_data_quality(
        load_request("production_inconsistent.json")
    )
    assert result.status == "sufficient"
    assert result.score == 100.0
    assert result.blocking_reasons == []


def test_missing_required_metric_blocks_analysis() -> None:
    request = load_request("production_consistent.json")
    request.observations = request.observations[:-1]

    result = evaluate_data_quality(request)

    assert result.status == "blocked"
    assert any(
        "inventory.raw_change_t" in reason
        for reason in result.blocking_reasons
    )


def test_invalid_signature_blocks_analysis() -> None:
    request = load_request("production_consistent.json")
    request.observations[0].quality.signature_valid = False

    result = evaluate_data_quality(request)

    assert result.status == "blocked"
    assert any("signature_invalid" in reason for reason in result.blocking_reasons)


def test_one_bad_required_source_cannot_hide_inside_a_high_average() -> None:
    request = load_request("production_consistent.json")
    request.observations[0].quality.completeness = 0.0
    request.observations[0].quality.timeliness = 0.0
    request.observations[0].quality.device_health = 0.0
    request.observations[0].quality.calibration = 0.0
    request.observations[0].quality.clock = 0.0
    request.observations[0].quality.lineage = 0.0
    request.observations[0].quality.uniqueness = 0.0

    result = evaluate_data_quality(request)

    assert result.score == 80.0
    assert result.minimum_observation_score == 0.0
    assert result.status == "blocked"
    assert any(
        "observation_quality_below_floor" in reason
        for reason in result.blocking_reasons
    )


def test_inventory_change_may_be_negative() -> None:
    observation = MetricObservation(
        observation_id="stock-down",
        metric_code="inventory.raw_change_t",
        value=-250,
        tolerance_abs=20,
        source_group="stock_survey",
    )
    assert observation.value == -250


def test_physical_flow_may_not_be_negative() -> None:
    with pytest.raises(ValidationError):
        MetricObservation(
            observation_id="bad-production",
            metric_code="coal.reported_output_t",
            value=-1,
            tolerance_abs=1,
            source_group="production_report",
        )
