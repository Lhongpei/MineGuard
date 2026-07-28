from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re

import pytest
from pydantic import ValidationError

from mineguard.api import SourceRegistrationRequest
from mineguard.models import PersonnelMatchRequest, ProductionAnalysisRequest


ROOT = Path(__file__).resolve().parents[1]


def production_payload() -> dict[str, object]:
    return json.loads(
        (ROOT / "examples" / "production_consistent.json").read_text()
    )


def personnel_payload() -> dict[str, object]:
    return json.loads(
        (ROOT / "examples" / "personnel_session.json").read_text()
    )


def test_production_window_requires_explicit_timezone() -> None:
    payload = production_payload()
    payload["window_start"] = "2026-07-20T00:00:00"

    with pytest.raises(ValidationError, match="timezone"):
        ProductionAnalysisRequest.model_validate(payload)


def test_observation_ids_must_be_unique() -> None:
    payload = production_payload()
    observations = payload["observations"]
    assert isinstance(observations, list)
    duplicate = deepcopy(observations[0])
    observations.append(duplicate)

    with pytest.raises(ValidationError, match="observation_id"):
        ProductionAnalysisRequest.model_validate(payload)


def test_non_finite_values_are_rejected_before_solver() -> None:
    payload = production_payload()
    observations = payload["observations"]
    assert isinstance(observations, list)
    observations[0]["value"] = float("nan")

    with pytest.raises(ValidationError, match="finite"):
        ProductionAnalysisRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("observations", 0, "tolerance_abs"), 5e-324),
        (("parameters", "transport_slack_penalty"), 5e-324),
    ],
)
def test_numerically_unsafe_solver_scales_are_rejected(
    path: tuple[str | int, ...],
    value: float,
) -> None:
    payload = production_payload()
    if "parameters" not in payload:
        payload["parameters"] = {}
    target: object = payload
    for key in path[:-1]:
        assert isinstance(target, (dict, list))
        target = target[key]
    assert isinstance(target, (dict, list))
    target[path[-1]] = value

    with pytest.raises(ValidationError):
        ProductionAnalysisRequest.model_validate(payload)


def test_documented_source_registration_example_is_executable() -> None:
    document = (ROOT / "docs" / "可信数据接入说明.md").read_text()
    section = document.split("### 3.1 来源", maxsplit=1)[1]
    match = re.search(r"```json\n(.*?)\n```", section, re.DOTALL)

    assert match is not None
    SourceRegistrationRequest.model_validate_json(match.group(1))


@pytest.mark.parametrize("field", ["face_track_id", "card_event_id"])
def test_personnel_event_ids_must_be_unique(field: str) -> None:
    payload = personnel_payload()
    collection_name = "faces" if field == "face_track_id" else "cards"
    events = payload[collection_name]
    assert isinstance(events, list)
    events.append(deepcopy(events[0]))

    with pytest.raises(ValidationError, match=field):
        PersonnelMatchRequest.model_validate(payload)
