"""Deterministic local safety warning rules.

These rules only produce advisory warning events.  They never issue commands to
mine equipment.  Defaults are examples and are deliberately marked uncalibrated
by Settings until an operator confirms the applicable mine/regulation profile.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .models import Alert, AlertLevel, Observation, ObservationKind, utc_now
from .settings import ThresholdSettings


class SafetyRuleEngine:
    def __init__(self, thresholds: ThresholdSettings) -> None:
        self.thresholds = thresholds

    def evaluate(self, observation: Observation) -> list[Alert]:
        if observation.kind is ObservationKind.METHANE:
            return self._methane(observation)
        if observation.kind is ObservationKind.PERSONNEL:
            return self._personnel(observation)
        if observation.kind is ObservationKind.VENTILATION:
            return self._ventilation(observation)
        return []

    def _methane(self, observation: Observation) -> list[Alert]:
        if observation.unit != "%" or not isinstance(observation.value, (int, float)):
            return []
        selected = _ascending_level(
            float(observation.value), self.thresholds.methane_percent
        )
        if selected is None:
            return []
        level, threshold = selected
        return [
            self._alert(
                observation,
                rule_id="methane-concentration-v1",
                level=level,
                title=f"甲烷浓度{_level_cn(level)}预警",
                message=(
                    f"{observation.location_code} 甲烷浓度 "
                    f"{observation.value:g}% 达到 {level.value} 阈值 {threshold:g}%"
                ),
                threshold=threshold,
            )
        ]

    def _personnel(self, observation: Observation) -> list[Alert]:
        if observation.unit != "person" or not isinstance(observation.value, int):
            return []
        capacity = _location_setting(
            self.thresholds.personnel_capacity,
            observation.location_code,
            observation.metric,
        )
        if capacity is None:
            return []
        ratio = observation.value / capacity
        selected = _ascending_level(ratio, self.thresholds.personnel_ratio)
        if selected is None:
            return []
        level, threshold = selected
        return [
            self._alert(
                observation,
                rule_id="personnel-overcapacity-v1",
                level=level,
                title=f"井下人员容量{_level_cn(level)}预警",
                message=(
                    f"{observation.location_code} 当前 {observation.value} 人，"
                    f"核定 {capacity} 人，占比 {ratio:.1%}"
                ),
                threshold={"capacity": capacity, "ratio": threshold},
            )
        ]

    def _ventilation(self, observation: Observation) -> list[Alert]:
        if observation.metric in {"main_fan_running", "fan_running"}:
            if observation.value is False:
                return [
                    self._alert(
                        observation,
                        rule_id="main-fan-stopped-v1",
                        level=AlertLevel.RED,
                        title="主通风机红色预警",
                        message=f"{observation.location_code} 主通风机报告停止",
                        threshold=True,
                    )
                ]
            return []
        if observation.metric == "main_fan_fault":
            if observation.value is True:
                return [
                    self._alert(
                        observation,
                        rule_id="main-fan-fault-v1",
                        level=AlertLevel.RED,
                        title="主通风机故障红色预警",
                        message=f"{observation.location_code} 主通风机报告故障",
                        threshold=False,
                    )
                ]
            return []
        if observation.metric == "main_fan_changeover":
            if observation.value is True:
                return [
                    self._alert(
                        observation,
                        rule_id="main-fan-changeover-v1",
                        level=AlertLevel.YELLOW,
                        title="主通风机倒机黄色提示",
                        message=(
                            f"{observation.location_code} 主通风机报告倒机，"
                            "请核对备用机启停和风量恢复情况"
                        ),
                        threshold=False,
                    )
                ]
            return []
        ratio: float | None = None
        threshold_context: Any
        if observation.metric == "airflow_ratio" and isinstance(
            observation.value, (int, float)
        ):
            ratio = float(observation.value)
            threshold_context = self.thresholds.airflow_ratio
        elif observation.unit == "m3/s" and isinstance(observation.value, (int, float)):
            minimum = _location_setting(
                self.thresholds.airflow_minimum,
                observation.location_code,
                observation.metric,
            )
            if minimum:
                ratio = float(observation.value) / minimum
                threshold_context = {"minimum_m3_s": minimum}
        if ratio is None:
            return []
        selected = _descending_level(ratio, self.thresholds.airflow_ratio)
        if selected is None:
            return []
        level, threshold = selected
        return [
            self._alert(
                observation,
                rule_id="insufficient-airflow-v1",
                level=level,
                title=f"通风不足{_level_cn(level)}预警",
                message=(
                    f"{observation.location_code} 实际/最低风量比 {ratio:.1%}，"
                    f"触及 {threshold:.0%} 阈值"
                ),
                threshold={
                    "ratio": threshold,
                    "context": threshold_context,
                },
            )
        ]

    @staticmethod
    def _alert(
        observation: Observation,
        *,
        rule_id: str,
        level: AlertLevel,
        title: str,
        message: str,
        threshold: Any,
    ) -> Alert:
        identity = json.dumps(
            {
                "observation_id": observation.observation_id,
                "revision": observation.revision,
                "rule_id": rule_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        alert_id = "alert_" + hashlib.sha256(identity).hexdigest()[:32]
        return Alert(
            alert_id=alert_id,
            mine_id=observation.mine_id,
            observation_id=observation.observation_id,
            rule_id=rule_id,
            level=level,
            title=title,
            message=message,
            triggered_at=utc_now(),
            measured_value=observation.value,
            threshold=threshold,
            unit=observation.unit,
            location_code=observation.location_code,
        )


def _ascending_level(
    value: float, thresholds: Mapping[str, float]
) -> tuple[AlertLevel, float] | None:
    for level in (
        AlertLevel.RED,
        AlertLevel.ORANGE,
        AlertLevel.YELLOW,
        AlertLevel.BLUE,
    ):
        threshold = float(thresholds[level.value])
        if value >= threshold:
            return level, threshold
    return None


def _descending_level(
    value: float, thresholds: Mapping[str, float]
) -> tuple[AlertLevel, float] | None:
    for level in (
        AlertLevel.RED,
        AlertLevel.ORANGE,
        AlertLevel.YELLOW,
        AlertLevel.BLUE,
    ):
        threshold = float(thresholds[level.value])
        if value <= threshold:
            return level, threshold
    return None


def _location_setting(
    mapping: Mapping[str, Any], location: str, metric: str
) -> Any | None:
    for key in (location, metric, "*"):
        if key in mapping:
            return mapping[key]
    return None


def _level_cn(level: AlertLevel) -> str:
    return {
        AlertLevel.BLUE: "蓝色",
        AlertLevel.YELLOW: "黄色",
        AlertLevel.ORANGE: "橙色",
        AlertLevel.RED: "红色",
    }[level]
