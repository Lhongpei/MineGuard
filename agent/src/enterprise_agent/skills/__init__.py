"""Installed enterprise-agent skills."""

from __future__ import annotations

from ..llm import LLMConfig
from .coal_news import CoalNewsConfig, CoalNewsSearchSkill
from .core import SkillRegistry


def build_skill_registry(
    coal_news_config: CoalNewsConfig | None = None,
    *,
    llm_config: LLMConfig | None = None,
) -> SkillRegistry:
    registry = SkillRegistry()
    registry.register(
        CoalNewsSearchSkill(
            coal_news_config,
            llm_config=llm_config,
        )
    )
    return registry


__all__ = [
    "CoalNewsConfig",
    "CoalNewsSearchSkill",
    "SkillRegistry",
    "build_skill_registry",
]
