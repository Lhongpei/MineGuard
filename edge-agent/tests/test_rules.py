from __future__ import annotations

import pytest

from mine_edge.models import AlertLevel
from mine_edge.normalization import normalize_observation
from mine_edge.rules import SafetyRuleEngine
from mine_edge.settings import ThresholdSettings


def observation(
    *,
    kind: str,
    metric: str,
    value: object,
    unit: str,
    location: str = "face-101",
):
    return normalize_observation(
        {
            "event_id": f"{kind}-{metric}-{value}",
            "kind": kind,
            "metric": metric,
            "value": value,
            "unit": unit,
            "location_code": location,
            "observed_at": "2026-07-28T00:00:00Z",
        },
        default_mine_id="mine-001",
        default_timezone="+08:00",
        forced_channel="http_poll",
        forced_source_id="source-1",
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.49, None),
        (0.5, AlertLevel.BLUE),
        (0.8, AlertLevel.YELLOW),
        (1.0, AlertLevel.ORANGE),
        (1.5, AlertLevel.RED),
        (3.0, AlertLevel.RED),
    ],
)
def test_methane_four_colors(value: float, expected: AlertLevel | None) -> None:
    alerts = SafetyRuleEngine(ThresholdSettings()).evaluate(
        observation(
            kind="methane",
            metric="methane_concentration",
            value=value,
            unit="%",
        )
    )
    assert (alerts[0].level if alerts else None) is expected


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (79, None),
        (80, AlertLevel.BLUE),
        (90, AlertLevel.YELLOW),
        (100, AlertLevel.ORANGE),
        (110, AlertLevel.RED),
    ],
)
def test_personnel_capacity(count: int, expected: AlertLevel | None) -> None:
    engine = SafetyRuleEngine(
        ThresholdSettings(personnel_capacity={"underground": 100})
    )
    alerts = engine.evaluate(
        observation(
            kind="personnel",
            metric="underground_count",
            value=count,
            unit="人",
            location="underground",
        )
    )
    assert (alerts[0].level if alerts else None) is expected


@pytest.mark.parametrize(
    ("ratio", "expected"),
    [
        (0.96, None),
        (0.95, AlertLevel.BLUE),
        (0.9, AlertLevel.YELLOW),
        (0.8, AlertLevel.ORANGE),
        (0.7, AlertLevel.RED),
    ],
)
def test_airflow_ratio(ratio: float, expected: AlertLevel | None) -> None:
    alerts = SafetyRuleEngine(ThresholdSettings()).evaluate(
        observation(
            kind="ventilation",
            metric="airflow_ratio",
            value=ratio,
            unit="ratio",
        )
    )
    assert (alerts[0].level if alerts else None) is expected


def test_stopped_main_fan_is_red() -> None:
    alerts = SafetyRuleEngine(ThresholdSettings()).evaluate(
        observation(
            kind="ventilation",
            metric="main_fan_running",
            value=False,
            unit="bool",
        )
    )
    assert alerts[0].level is AlertLevel.RED


def test_main_fan_fault_and_changeover_are_local_hints() -> None:
    engine = SafetyRuleEngine(ThresholdSettings())
    fault = engine.evaluate(
        observation(
            kind="ventilation",
            metric="main_fan_fault",
            value=True,
            unit="bool",
        )
    )
    changeover = engine.evaluate(
        observation(
            kind="ventilation",
            metric="main_fan_changeover",
            value=True,
            unit="bool",
        )
    )
    assert fault[0].level is AlertLevel.RED
    assert changeover[0].level is AlertLevel.YELLOW


def test_no_capacity_means_no_invented_personnel_threshold() -> None:
    alerts = SafetyRuleEngine(ThresholdSettings()).evaluate(
        observation(
            kind="personnel",
            metric="underground_count",
            value=999,
            unit="人",
            location="not-configured",
        )
    )
    assert alerts == []


def test_absolute_airflow_uses_location_minimum() -> None:
    alerts = SafetyRuleEngine(
        ThresholdSettings(airflow_minimum={"face-101": 20})
    ).evaluate(
        observation(
            kind="ventilation",
            metric="airflow",
            value=14,
            unit="m3/s",
        )
    )
    assert alerts[0].level is AlertLevel.RED
