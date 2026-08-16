from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from mineguard import __version__
from mineguard.casework import LocalRepository
from mineguard.historical_pipeline import (
    enrich_portfolio_historical_evidence,
)
from mineguard.models import ProductionAnalysisRequest
from mineguard.portfolio import (
    PortfolioAnalysisRequest,
    analyze_production_portfolio,
)


ROOT = Path(__file__).resolve().parents[1]


def _request(day_offset: int) -> ProductionAnalysisRequest:
    raw = json.loads(
        (ROOT / "examples" / "production_consistent.json").read_text(
            encoding="utf-8"
        )
    )
    raw["mine_id"] = "M001"
    request = ProductionAnalysisRequest.model_validate(raw)
    return request.model_copy(
        update={
            "window_start": request.window_start
            + timedelta(days=day_offset),
            "window_end": request.window_end + timedelta(days=day_offset),
        }
    )


def _context() -> dict[str, object]:
    return {
        "kind": "governed_production_ingest",
        "profile_id": "production-default",
        "profile_version": "1",
        "registry_snapshot_hash": "a" * 64,
        "operational_context": {
            "regime_code": "normal-production",
            "shift_code": "daily",
            "season_code": "summer",
            "maintenance": False,
            "approved_event_codes": [],
            "tags": ["raw-coal"],
        },
    }


def _portfolio(
    request: ProductionAnalysisRequest,
    batch_id: str,
) -> tuple[PortfolioAnalysisRequest, object]:
    portfolio = PortfolioAnalysisRequest(
        batch_id=batch_id,
        portfolio_name="历史证据集成测试",
        expected_mine_ids=["M001"],
        analyses=[request],
    )
    return portfolio, analyze_production_portfolio(portfolio)


def test_governed_pipeline_uses_only_explicitly_labelled_prior_runs() -> None:
    repository = LocalRepository()
    try:
        for index in range(20):
            request = _request(index)
            portfolio, result = _portfolio(
                request,
                f"history-{index:02d}",
            )
            repository.save_portfolio_batch(
                portfolio,
                result,
                __version__,
                context_obj=_context(),
            )
            run = repository.list_runs(portfolio.batch_id)[0]
            repository.append_run_reference_label(
                str(run["run_id"]),
                label="verified_normal",
                actor="supervisor",
                note="原始凭证与现场记录复核一致",
                expected_sequence=0,
            )

        current_request = _request(21)
        current_portfolio, current_result = _portfolio(
            current_request,
            "current",
        )
        enriched = enrich_portfolio_historical_evidence(
            repository,
            current_portfolio,
            current_result,
            engine_version=__version__,
            context_obj=_context(),
        )
        item = enriched["items"][0]
        assessment = item["historical_evidence"]["assessment"]

        assert assessment["status"] == "ready"
        assert assessment["eligible_sample_count"] == 20
        assert assessment["selected_sample_count"] == 20
        assert assessment["historically_rare"] is False
        assert assessment["physical_status_unchanged"] is True
        manifest = item["historical_evidence"]["reference_manifest"]
        assert manifest["selected_sample_count"] == 20
        assert len(manifest["selected_samples"]) == 20
        assert len(manifest["sha256"]) == 64
        assert all(
            sample["reference_label"]["label"] == "verified_normal"
            for sample in manifest["selected_samples"]
        )
        assert item["temporal_evidence"]["status"] == "normal"
        assert item["temporal_evidence"]["sample_count"] == 20
        assert item["analysis"] == current_result.model_dump(
            mode="json"
        )["items"][0]["analysis"]
        assert (
            item["review_priority"]
            == current_result.items[0].review_priority
        )
        assert (
            item["evidence_fusion"]["physical_status_unchanged"] is True
        )
    finally:
        repository.close()


def test_pipeline_reports_cold_start_and_does_not_treat_it_as_normal() -> None:
    repository = LocalRepository()
    try:
        request = _request(30)
        portfolio, result = _portfolio(request, "cold-start")
        enriched = enrich_portfolio_historical_evidence(
            repository,
            portfolio,
            result,
            engine_version=__version__,
            context_obj=_context(),
        )
        item = enriched["items"][0]
        assessment = item["historical_evidence"]["assessment"]

        assert assessment["status"] == "insufficient_history"
        assert assessment["historically_rare"] is None
        assert item["evidence_fusion"]["agreement"] == "insufficient"
        assert (
            item["evidence_fusion"]["physical_status"]
            == item["technical_status"]
        )
    finally:
        repository.close()


def test_direct_caller_data_is_not_used_for_governed_history() -> None:
    repository = LocalRepository()
    try:
        request = _request(30)
        portfolio, result = _portfolio(request, "direct")
        enriched = enrich_portfolio_historical_evidence(
            repository,
            portfolio,
            result,
            engine_version=__version__,
            context_obj=None,
        )

        evidence = enriched["items"][0]["historical_evidence"]
        assert evidence["assessment"]["status"] == "not_evaluated"
        assert (
            evidence["assessment"]["reason"]
            == "trusted_governed_input_required"
        )
    finally:
        repository.close()
