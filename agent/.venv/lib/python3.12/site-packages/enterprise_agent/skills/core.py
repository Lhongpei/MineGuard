"""Small, explicit registry for read-only enterprise-agent skills."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol


class Skill(Protocol):
    """Runtime contract implemented by locally installed skills."""

    name: str

    def public_definition(self) -> dict[str, Any]:
        """Return non-secret metadata suitable for the HTTP API."""

    def invoke(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        """Run the skill and return a JSON-compatible result."""


class SkillRegistry:
    """Name-addressed skill registry with a deliberately narrow call surface."""

    def __init__(self) -> None:
        self._skills: dict[str, Skill] = {}

    def register(self, skill: Skill) -> None:
        name = getattr(skill, "name", None)
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 64
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789-"
                for character in name
            )
        ):
            raise ValueError("技能名称格式非法")
        if name in self._skills:
            raise ValueError(f"技能已注册：{name}")
        self._skills[name] = skill

    def list_public(self) -> list[dict[str, Any]]:
        return [self._skills[name].public_definition() for name in sorted(self._skills)]

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def available(self, name: str) -> bool:
        skill = self.get(name)
        if skill is None:
            return False
        definition = skill.public_definition()
        return bool(definition.get("enabled"))

    def call(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        skill = self.get(name)
        if skill is None:
            raise KeyError(f"未知技能：{name}")
        if not isinstance(arguments, Mapping):
            raise ValueError("技能参数必须是对象")
        return skill.invoke(arguments)
