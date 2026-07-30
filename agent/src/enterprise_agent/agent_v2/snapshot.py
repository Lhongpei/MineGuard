"""Immutable repository view for one Agent V2 evidence run."""

from __future__ import annotations

from typing import Any

from enterprise_agent.errors import NotFoundError
from enterprise_agent.util import deep_copy_json, sha256_json, utc_text

_DEFAULT_MAX_METRIC_CODES = 64
_HIGH_VALUE_METRICS = (
    "coal.production_t",
    "coal.reported_output_t",
    "coal.main_transport_t",
    "coal.inventory_opening_t",
    "coal.inventory_closing_t",
    "coal.purchase_in_t",
    "coal.sale_out_t",
    "sales.raw_shipped_t",
    "wash.feed_t",
    "coal.processing_input_t",
    "quality.calorific_value",
    "quality.ash",
    "quality.moisture",
    "quality.sulfur",
)
_HIGH_VALUE_TOKENS = (
    ("production", "output", "产量"),
    ("transport", "belt", "scale", "运量"),
    ("inventory", "stock", "库存"),
    ("purchase", "inbound", "购入"),
    ("sale", "sales", "shipped", "outbound", "销量"),
    ("wash", "processing", "yield", "洗选"),
    ("calorific", "heat", "热值"),
    ("ash", "moisture", "sulfur", "quality", "煤质"),
    ("methane", "gas", "瓦斯"),
)


def prioritize_metric_codes(metric_codes: list[str] | set[str]) -> list[str]:
    """Order metrics by coal-regulatory value, then deterministically by code."""

    exact = {code: index for index, code in enumerate(_HIGH_VALUE_METRICS)}

    def key(code: str) -> tuple[int, int, str]:
        lowered = code.casefold()
        if lowered in exact:
            return (0, exact[lowered], lowered)
        for index, tokens in enumerate(_HIGH_VALUE_TOKENS):
            if any(token in lowered for token in tokens):
                return (1, index, lowered)
        return (2, 0, lowered)

    return sorted(set(metric_codes), key=key)


def _public_document(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: child
        for key, child in value.items()
        if key not in {"_meta", "status", "receipt"}
    }


class FrozenEvidenceRepository:
    """Serve one draft and its bounded history from a captured read snapshot.

    The capture runs under the repository's short SQLite write transaction so
    concurrent edits cannot interleave between the draft and history queries.
    The transaction is released before any specialist computation starts.
    """

    __slots__ = (
        "_draft",
        "_draft_id",
        "_history",
        "_history_errors",
        "_metadata",
    )

    def __init__(
        self,
        *,
        draft: dict[str, Any],
        history: dict[str, list[dict[str, Any]]],
        history_errors: dict[str, str],
        all_metric_codes: list[str],
        captured_at: str,
    ):
        self._draft = deep_copy_json(draft)
        self._draft_id = str(draft["draft_id"])
        self._history = deep_copy_json(history)
        self._history_errors = dict(history_errors)
        selected_metric_codes = list(history)
        omitted_metric_codes = [
            code for code in all_metric_codes if code not in history
        ]
        public = _public_document(draft)
        self._metadata = {
            "captured_at": captured_at,
            "draft_id": self._draft_id,
            "draft_revision": int(draft["_meta"]["revision"]),
            "document_sha256": sha256_json(public),
            "history_metric_codes": selected_metric_codes,
            "metric_coverage": {
                "strategy": "coal_regulatory_priority_then_code",
                "total_metric_count": len(all_metric_codes),
                "analyzed_metric_count": len(selected_metric_codes),
                "omitted_metric_count": len(omitted_metric_codes),
                "complete": not omitted_metric_codes,
                "analyzed_metric_codes": selected_metric_codes,
                "omitted_metric_codes": omitted_metric_codes[:64],
                "omitted_metric_codes_truncated": len(omitted_metric_codes) > 64,
                "omitted_metric_codes_sha256": sha256_json(
                    omitted_metric_codes
                ),
            },
            "history_snapshot_sha256": sha256_json(
                {
                    "history": history,
                    "errors": history_errors,
                }
            ),
            "immutable": True,
        }

    @classmethod
    def capture(
        cls,
        repository: Any,
        *,
        draft_id: str,
        max_metric_codes: int = _DEFAULT_MAX_METRIC_CODES,
    ) -> FrozenEvidenceRepository:
        """Capture current evidence without retaining a long database lock."""

        with repository._transaction():
            draft = repository.get_draft(draft_id)
            observations = draft.get("observations")
            all_metric_codes = prioritize_metric_codes(
                {
                    str(item["metric_code"])
                    for item in observations
                    if isinstance(item, dict)
                    and isinstance(item.get("metric_code"), str)
                    and item["metric_code"]
                }
            ) if isinstance(observations, list) else []
            metric_codes = all_metric_codes[:max_metric_codes]
            history: dict[str, list[dict[str, Any]]] = {}
            history_errors: dict[str, str] = {}
            for metric_code in metric_codes:
                try:
                    history[metric_code] = repository.historical_observations(
                        mine_id=str(draft.get("mine_id", "")),
                        metric_code=metric_code,
                        exclude_draft_id=draft_id,
                        before_window_start=str(
                            draft.get("window_start", "")
                        ),
                        limit=500,
                    )
                except (TypeError, ValueError) as error:
                    # Incomplete drafts remain analyzable; the historical
                    # specialist receives a deterministic unavailable error.
                    history[metric_code] = []
                    history_errors[metric_code] = type(error).__name__
            captured_at = utc_text()
        return cls(
            draft=draft,
            history=history,
            history_errors=history_errors,
            all_metric_codes=all_metric_codes,
            captured_at=captured_at,
        )

    @property
    def metadata(self) -> dict[str, Any]:
        return deep_copy_json(self._metadata)

    def get_draft(
        self,
        draft_id: str,
        *,
        include_deleted: bool = False,
    ) -> dict[str, Any]:
        if draft_id != self._draft_id:
            raise NotFoundError("证据快照中不存在该草稿")
        if not include_deleted and self._draft.get("_meta", {}).get("deleted_at"):
            raise NotFoundError("证据快照中的草稿已删除")
        return deep_copy_json(self._draft)

    def list_drafts(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if offset > 0 or limit < 1:
            return []
        try:
            return [
                self.get_draft(
                    self._draft_id,
                    include_deleted=include_deleted,
                )
            ]
        except NotFoundError:
            return []

    def historical_observations(
        self,
        *,
        mine_id: str,
        metric_code: str,
        exclude_draft_id: str | None = None,
        before_window_start: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        if (
            mine_id != str(self._draft.get("mine_id", ""))
            or exclude_draft_id not in {None, self._draft_id}
            or before_window_start
            not in {None, str(self._draft.get("window_start", ""))}
        ):
            raise ValueError("历史查询超出本次不可变证据快照范围")
        if metric_code in self._history_errors:
            raise ValueError("该指标的历史快照因草稿口径不完整而不可用")
        bounded = min(max(int(limit), 1), 500)
        return deep_copy_json(self._history.get(metric_code, [])[:bounded])


__all__ = ["FrozenEvidenceRepository", "prioritize_metric_codes"]
