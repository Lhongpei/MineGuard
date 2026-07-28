"""Narrow read capability exposed to deterministic in-process tools."""

from __future__ import annotations

from typing import Any

from enterprise_agent.util import deep_copy_json


class ReadOnlyRepository:
    """Expose copied reads through a deliberately tiny capability surface."""

    __slots__ = ("__get", "__history", "__list")

    def __init__(self, repository: Any):
        self.__get = repository.get_draft
        self.__list = repository.list_drafts
        self.__history = repository.historical_observations

    def get_draft(
        self, draft_id: str, *, include_deleted: bool = False
    ) -> dict[str, Any]:
        return deep_copy_json(
            self.__get(draft_id, include_deleted=include_deleted)
        )

    def list_drafts(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return deep_copy_json(
            self.__list(
                include_deleted=include_deleted,
                limit=limit,
                offset=offset,
            )
        )

    def historical_observations(
        self,
        *,
        mine_id: str,
        metric_code: str,
        exclude_draft_id: str | None = None,
        before_window_start: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return deep_copy_json(
            self.__history(
                mine_id=mine_id,
                metric_code=metric_code,
                exclude_draft_id=exclude_draft_id,
                before_window_start=before_window_start,
                limit=limit,
            )
        )
