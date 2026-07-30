from __future__ import annotations

import copy

import pytest

from enterprise_agent.agent_v2.autofill import (
    HISTORICAL_SUGGESTION,
    PHYSICAL_INFERENCE,
    RAW_OBSERVATION,
    AutofillInputError,
    build_autofill_proposal,
)
from enterprise_agent.util import sha256_json


def _draft() -> dict:
    return {
        "schema_version": "enterprise-submission-draft/v1",
        "draft_id": "draft-autofill-1",
        "enterprise_id": "enterprise-001",
        "enterprise_name": "",
        "unified_social_credit_code": "",
        "mine_id": "mine-001",
        "mine_name": "沁源一号矿",
        "window_start": "2026-07-29T00:00:00+08:00",
        "window_end": "2026-07-30T00:00:00+08:00",
        "profile_id": "coal-daily",
        "profile_version": "v1",
        "operational_context": {
            "regime_code": "",
            "shift_code": "",
            "season_code": "",
            "maintenance": None,
            "approved_event_codes": [],
            "tags": [],
        },
        "observations": [
            {
                "source_id": "belt-scale-01",
                "observation_id": "obs-001",
                "metric_code": "coal.main_transport_t",
                "value": 100.0,
                "unit": "t",
                "observed_at": "2026-07-29T23:59:00+08:00",
                "received_at": "2026-07-29T23:59:10+08:00",
                "interval_start": "2026-07-29T00:00:00+08:00",
                "interval_end": "2026-07-30T00:00:00+08:00",
                "reset_before": False,
                "sequence_no": 1,
                "revision": 0,
                "payload_sha256": "1" * 64,
                "signature": "2" * 64,
            }
        ],
        "imports": [],
        "field_provenance": {},
        "llm_assistance": {
            "used": False,
            "provider": None,
            "model": None,
            "run_id": None,
            "suggestion_only": True,
        },
        "notes": "",
        "status": "draft",
        "_meta": {
            "revision": 7,
            "confirmed": False,
        },
    }


def _snapshot(draft: dict) -> dict:
    public = {
        key: value
        for key, value in draft.items()
        if key not in {"_meta", "status", "receipt"}
    }
    return {
        "captured_at": "2026-07-30T01:00:00Z",
        "draft_id": draft["draft_id"],
        "draft_revision": draft["_meta"]["revision"],
        "document_sha256": sha256_json(public),
        "history_snapshot_sha256": sha256_json(
            {"history": {"coal.main_transport_t": []}, "errors": {}}
        ),
        "immutable": True,
    }


def _raw(
    path: str,
    value: object,
    *,
    confidence: float = 0.96,
    method: str = "deterministic_json_key",
    verified: bool = True,
) -> dict:
    return {
        "path": path,
        "value": value,
        "confidence": confidence,
        "method": method,
        "rationale": "来自原始台账的明确字段",
        "source_refs": [
            {
                "source_type": "document",
                "source_id": "source-ledger-001",
                "locator": "$.field",
                "content_sha256": "a" * 64,
                "verified": verified,
            }
        ],
    }


def _history(
    path: str,
    value: object,
    *,
    confidence: float = 0.9,
    sample_size: int = 20,
    support_ratio: float = 0.8,
    context_match: bool = True,
) -> dict:
    return {
        "path": path,
        "value": value,
        "confidence": confidence,
        "method": "historical_context_mode",
        "rationale": "同矿同班次历史样本的众数",
        "source_refs": [
            {
                "source_type": "tool_result",
                "tool_call_id": "history-tool-call-1",
                "locator": "$.mode",
            }
        ],
        "basis": {
            "sample_size": sample_size,
            "support_ratio": support_ratio,
            "context_match": context_match,
        },
    }


def _physical(
    path: str,
    value: object,
    *,
    confidence: float = 0.92,
    validated_inputs: bool = True,
) -> dict:
    return {
        "path": path,
        "value": value,
        "confidence": confidence,
        "method": "deterministic_mass_balance",
        "rationale": "由煤流守恒关系计算",
        "source_refs": [
            {
                "source_type": "tool_result",
                "tool_call_id": "balance-tool-call-1",
                "locator": "$.derived_value",
            }
        ],
        "basis": {
            "formula": "production = transport + inventory_change",
            "input_refs": [
                "/observations/0/value",
                "tool:inventory-change",
            ],
            "validated_inputs": validated_inputs,
        },
    }


def _by_path(proposal: dict, path: str, evidence_class: str) -> dict:
    return next(
        item
        for item in proposal["candidates"]
        if item["path"] == path and item["evidence_class"] == evidence_class
    )


def test_proposal_separates_evidence_and_is_deterministic_and_pure() -> None:
    draft = _draft()
    before = copy.deepcopy(draft)
    raw = [_raw("/enterprise_name", "沁源煤业有限公司")]
    historical = [_history("/operational_context/maintenance", False)]
    physical = [_physical("/observations/0/value", 98.5)]

    proposal = build_autofill_proposal(
        draft=draft,
        raw_observations=raw,
        historical_suggestions=historical,
        physical_inferences=physical,
        snapshot_metadata=_snapshot(draft),
    )
    replay = build_autofill_proposal(
        draft=draft,
        raw_observations=raw,
        historical_suggestions=historical,
        physical_inferences=physical,
        snapshot_metadata=_snapshot(draft),
    )

    assert draft == before
    assert proposal == replay
    assert proposal["proposal_only"] is True
    assert proposal["applied"] is False
    assert proposal["capabilities"] == {
        "can_write_draft": False,
        "can_confirm": False,
        "can_sign": False,
        "can_submit": False,
    }
    assert proposal["review_patch"] == {
        "enterprise_name": "沁源煤业有限公司",
        "operational_context": {"maintenance": False},
    }
    assert set(proposal["counts"]["by_evidence_class"]) == {
        RAW_OBSERVATION,
        HISTORICAL_SUGGESTION,
        PHYSICAL_INFERENCE,
    }
    assert (
        _by_path(
            proposal,
            "/observations/0/value",
            PHYSICAL_INFERENCE,
        )["status"]
        == "analysis_only"
    )
    digest_payload = {
        key: value
        for key, value in proposal.items()
        if key not in {"proposal_id", "proposal_sha256"}
    }
    assert sha256_json(digest_payload) == proposal["proposal_sha256"]


def test_conflicting_evidence_never_selects_a_value_even_when_raw_is_stronger() -> None:
    draft = _draft()
    proposal = build_autofill_proposal(
        draft=draft,
        raw_observations=[
            _raw("/operational_context/regime_code", "normal")
        ],
        historical_suggestions=[
            _history("/operational_context/regime_code", "maintenance")
        ],
        snapshot_metadata=_snapshot(draft),
    )

    assert "operational_context" not in proposal["review_patch"]
    assert proposal["review_patch_candidates"] == {}
    assert proposal["conflicts"] == [
        {
            "path": "/operational_context/regime_code",
            "candidate_ids": sorted(
                item["candidate_id"] for item in proposal["candidates"]
            ),
            "evidence_classes": [
                HISTORICAL_SUGGESTION,
                RAW_OBSERVATION,
            ],
            "distinct_value_count": 2,
            "resolution": "no_value_selected",
        }
    ]
    assert {item["status"] for item in proposal["candidates"]} == {"conflict"}


def test_existing_values_are_never_overwritten_and_same_values_are_noops() -> None:
    draft = _draft()
    proposal = build_autofill_proposal(
        draft=draft,
        raw_observations=[
            _raw("/mine_name", "另一个矿"),
            _raw("/mine_id", "mine-001"),
        ],
        snapshot_metadata=_snapshot(draft),
    )

    assert proposal["review_patch"] == {}
    assert (
        _by_path(proposal, "/mine_name", RAW_OBSERVATION)["status"]
        == "would_overwrite"
    )
    assert (
        _by_path(proposal, "/mine_id", RAW_OBSERVATION)["status"]
        == "already_present"
    )


def test_observations_and_regulator_events_are_routed_to_credentialed_imports() -> None:
    draft = _draft()
    proposal = build_autofill_proposal(
        draft=draft,
        raw_observations=[
            _raw("/observations/0/value", 101.5),
            _raw(
                "/operational_context/approved_event_codes",
                ["EVENT-001"],
            ),
        ],
        physical_inferences=[
            _physical("/operational_context/maintenance", True)
        ],
        snapshot_metadata=_snapshot(draft),
    )

    observation = _by_path(
        proposal,
        "/observations/0/value",
        RAW_OBSERVATION,
    )
    event = _by_path(
        proposal,
        "/operational_context/approved_event_codes",
        RAW_OBSERVATION,
    )
    inferred = _by_path(
        proposal,
        "/operational_context/maintenance",
        PHYSICAL_INFERENCE,
    )
    assert observation["delivery_route"] == "signed_source_import"
    assert observation["status"] == "import_required"
    assert event["delivery_route"] == "regulator_event_snapshot_import"
    assert event["status"] == "import_required"
    assert inferred["delivery_route"] == "analysis_only"
    assert inferred["eligible_for_review_patch"] is False
    assert proposal["review_patch"] == {}


def test_confidence_caps_are_explicit_and_do_not_upgrade_evidence() -> None:
    draft = _draft()
    proposal = build_autofill_proposal(
        draft=draft,
        raw_observations=[
            _raw(
                "/enterprise_name",
                "沁源煤业有限公司",
                confidence=0.99,
                method="llm_extraction",
                verified=True,
            ),
            _raw(
                "/unified_social_credit_code",
                "91140000123456789X",
                confidence=0.99,
                verified=False,
            ),
        ],
        historical_suggestions=[
            _history(
                "/operational_context/shift_code",
                "night",
                confidence=0.99,
                sample_size=3,
                support_ratio=0.99,
            )
        ],
        physical_inferences=[
            _physical(
                "/observations/0/value",
                99.0,
                confidence=0.99,
                validated_inputs=False,
            )
        ],
        snapshot_metadata=_snapshot(draft),
    )

    assert (
        _by_path(
            proposal,
            "/enterprise_name",
            RAW_OBSERVATION,
        )["confidence"]["effective"]
        == 0.7
    )
    assert (
        _by_path(
            proposal,
            "/unified_social_credit_code",
            RAW_OBSERVATION,
        )["confidence"]["effective"]
        == 0.85
    )
    historical = _by_path(
        proposal,
        "/operational_context/shift_code",
        HISTORICAL_SUGGESTION,
    )
    assert historical["confidence"]["effective"] == 0.5
    assert historical["status"] == "below_threshold"
    assert (
        _by_path(
            proposal,
            "/observations/0/value",
            PHYSICAL_INFERENCE,
        )["confidence"]["effective"]
        == 0.55
    )


def test_credentials_control_fields_and_secret_material_are_never_echoed() -> None:
    draft = _draft()
    leaked = "sk-this-must-never-appear"
    proposal = build_autofill_proposal(
        draft=draft,
        raw_observations=[
            _raw("/observations/0/signature", "f" * 64),
            _raw("/status", "submitted"),
            {
                **_raw("/enterprise_name", "沁源煤业有限公司"),
                "reason": f"api_key={leaked}",
            },
        ],
        snapshot_metadata=_snapshot(draft),
    )

    assert proposal["review_patch"] == {}
    assert all(item["status"] == "blocked" for item in proposal["candidates"])
    assert all(item["value_omitted"] is True for item in proposal["candidates"])
    rendered = str(proposal)
    assert leaked not in rendered
    assert "f" * 64 not in rendered
    assert "submitted" not in rendered


def test_history_and_physical_candidates_require_the_right_snapshot_binding() -> None:
    draft = _draft()
    proposal = build_autofill_proposal(
        draft=draft,
        raw_observations=[
            _raw("/enterprise_name", "沁源煤业有限公司")
        ],
        historical_suggestions=[
            _history("/operational_context/shift_code", "day")
        ],
        physical_inferences=[
            _physical("/observations/0/value", 99.0)
        ],
    )

    assert proposal["snapshot"]["immutable"] is False
    assert (
        _by_path(
            proposal,
            "/enterprise_name",
            RAW_OBSERVATION,
        )["status"]
        == "ready_for_review"
    )
    assert (
        _by_path(
            proposal,
            "/operational_context/shift_code",
            HISTORICAL_SUGGESTION,
        )["status"]
        == "blocked"
    )
    assert (
        _by_path(
            proposal,
            "/observations/0/value",
            PHYSICAL_INFERENCE,
        )["status"]
        == "blocked"
    )


def test_snapshot_mismatch_and_unbounded_input_fail_closed() -> None:
    draft = _draft()
    snapshot = _snapshot(draft)
    snapshot["draft_revision"] += 1
    with pytest.raises(AutofillInputError, match="修订号"):
        build_autofill_proposal(
            draft=draft,
            snapshot_metadata=snapshot,
        )

    with pytest.raises(AutofillInputError, match="超过 max_candidates"):
        build_autofill_proposal(
            draft=draft,
            raw_observations=[
                _raw("/enterprise_name", f"企业-{index}")
                for index in range(3)
            ],
            max_candidates=2,
        )
