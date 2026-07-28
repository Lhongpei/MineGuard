from __future__ import annotations

import re
import threading
import time
from copy import deepcopy
from types import SimpleNamespace

import pytest
from conftest import ensure_event_snapshot, gateway_sign_observation

from enterprise_agent.errors import (
    ConfirmationRequiredError,
    ConflictError,
    PlatformError,
    ValidationBlockedError,
)
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.util import sha256_jcs, sha256_json


class FakePlatform:
    def __init__(self) -> None:
        self.calls: list[tuple[dict, str]] = []

    def submit(self, payload: dict, *, idempotency_key: str) -> dict:
        self.calls.append((payload, idempotency_key))
        return {
            "contract_version": "enterprise-submission-receipt-v1",
            "receipt_id": "receipt-1",
            "status": "accepted",
            "regulatory_outcome": "not_determined_at_intake",
        }


class FailOncePlatform(FakePlatform):
    def submit(self, payload: dict, *, idempotency_key: str) -> dict:
        self.calls.append((deepcopy(payload), idempotency_key))
        if len(self.calls) == 1:
            raise PlatformError("simulated ambiguous transport failure")
        return {
            "contract_version": "enterprise-submission-receipt-v1",
            "receipt_id": "receipt-after-retry",
            "status": "accepted",
            "regulatory_outcome": "not_determined_at_intake",
        }


class BlockingPlatform(FakePlatform):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def submit(self, payload: dict, *, idempotency_key: str) -> dict:
        self.calls.append((deepcopy(payload), idempotency_key))
        self.entered.set()
        assert self.release.wait(timeout=3)
        return {
            "contract_version": "enterprise-submission-receipt-v1",
            "receipt_id": "receipt-blocking",
            "status": "accepted",
            "regulatory_outcome": "not_determined_at_intake",
        }


class RejectingPlatform(FakePlatform):
    def submit(self, payload: dict, *, idempotency_key: str) -> dict:
        self.calls.append((deepcopy(payload), idempotency_key))
        raise PlatformError(
            "确认人未备案",
            details={
                "http_status": 403,
                "platform_code": "CONFIRMER_NOT_AUTHORIZED",
                "retryable": False,
                "violations": [
                    {
                        "json_pointer": (
                            "/payload/human_confirmation/confirmer_id"
                        ),
                        "message": "No active registration.",
                    }
                ],
            },
        )


class CompatiblePlatform(FakePlatform):
    def discover_capabilities(self) -> dict:
        return {"contract_version": "enterprise-submission-capabilities-v1"}


class UnreachablePlatform(FakePlatform):
    def discover_capabilities(self) -> dict:
        raise PlatformError(
            "无法连接监管平台",
            details={"failure_kind": "connection", "retryable": True},
        )


class FakeLLM:
    config = SimpleNamespace(model="test-model")

    def suggest_fields(self, **_kwargs):
        return {
            "suggestions": [
                {
                    "path": "/mine_name",
                    "value": "模型定位到的矿名",
                    "confidence": 0.9,
                    "reason": "原文明确给出",
                    "source_locator": "第2页矿井名称",
                    "advisory_only": True,
                }
            ],
            "advisory_only": True,
        }


class CapturingLLM(FakeLLM):
    def __init__(self) -> None:
        self.current_document = None

    def suggest_fields(self, **kwargs):
        self.current_document = deepcopy(kwargs["current_document"])
        return super().suggest_fields(**kwargs)


def _confirm(service, draft):
    draft = ensure_event_snapshot(service, draft)
    observation_ids = [
        item["observation_id"]
        for item in draft.get("observations", [])
        if isinstance(item, dict) and isinstance(item.get("observation_id"), str)
    ]
    if observation_ids:
        service.review_observations(
            draft["draft_id"],
            observation_ids=observation_ids,
            reviewed=True,
            actor="operator-1",
            expected_revision=draft["_meta"]["revision"],
        )
    return service.confirm(
        draft["draft_id"],
        actor="operator-1",
        confirmer_name="张三",
        confirmer_role="企业报送负责人",
        accepted=True,
        attestation="本人已逐项核对原始记录并确认有权提交。",
        expected_revision=draft["_meta"]["revision"],
    )


def test_confirmation_is_required_and_invalidated_by_change(service, values) -> None:
    draft = service.create_draft(values, actor="operator-1")
    with pytest.raises(ConfirmationRequiredError):
        service.confirm(
            draft["draft_id"],
            actor="operator-1",
            confirmer_name="张三",
            confirmer_role="负责人",
            accepted=False,
            attestation="本人已逐项核对原始记录并确认有权提交。",
            expected_revision=1,
        )
    confirmed = _confirm(service, draft)
    assert confirmed["_meta"]["confirmed"] is True
    changed = service.patch_draft(
        draft["draft_id"],
        {"notes": "补充说明"},
        actor="operator-1",
        expected_revision=confirmed["_meta"]["revision"],
    )
    assert changed["_meta"]["confirmed"] is False


def test_llm_suggestion_never_applies_itself_and_acceptance_is_traced(
    values,
) -> None:
    service = EnterpriseAgentService(
        Repository(":memory:"),
        llm_provider=FakeLLM(),  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    confirmed_before_assist = _confirm(service, draft)
    assisted = service.assist(
        draft["draft_id"],
        content="矿井名称：模型定位到的矿名",
        actor="operator-1",
        expected_revision=confirmed_before_assist["_meta"]["revision"],
    )
    assert assisted["draft"]["mine_name"] == "示例一号矿"
    assert assisted["draft"]["_meta"]["confirmed"] is False
    adopted = service.patch_draft(
        draft["draft_id"],
        {"mine_name": "模型定位到的矿名"},
        actor="operator-1",
        expected_revision=assisted["draft"]["_meta"]["revision"],
    )
    records = adopted["field_provenance"]["/mine_name"]
    assert any(record["extraction_method"] == "llm_extraction" for record in records)
    assert adopted["llm_assistance"]["accepted_field_paths"] == ["/mine_name"]
    confirmed = _confirm(service, adopted)
    envelope = service._build_envelope(
        confirmed,
        idempotency_key="enterprise-001-llm-mapped-v1",
    )
    assert envelope["payload"]["llm_assistance"]["affected_field_paths"] == [
        "/payload/mine/mine_name"
    ]
    mine_provenance = envelope["payload"]["mine"]["field_provenance"]["mine_name"]
    assert any(
        record["acquisition_method"] == "llm_extraction" for record in mine_provenance
    )


def test_llm_never_receives_gateway_credentials_or_internal_evidence(values) -> None:
    marker_signature = values["observations"][0]["signature"]
    marker_digest = values["observations"][0]["payload_sha256"]
    provider = CapturingLLM()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        llm_provider=provider,  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    service.assist(
        draft["draft_id"],
        content="矿井名称：模型定位到的矿名",
        actor="operator-1",
        expected_revision=1,
    )
    context = provider.current_document
    assert isinstance(context, dict)
    serialized = str(context)
    assert marker_signature not in serialized
    assert marker_digest not in serialized
    assert "payload_sha256" not in serialized
    assert "signature" not in serialized
    assert "field_provenance" not in context
    assert "llm_assistance" not in context
    assert "draft_id" not in context


def test_incomplete_draft_cannot_be_confirmed(service) -> None:
    draft = service.create_draft(actor="operator-1")
    with pytest.raises(ValidationBlockedError):
        _confirm(service, draft)


def test_service_does_not_accept_unverified_signature_or_seal_claims(
    service,
    values,
) -> None:
    draft = service.create_draft(values, actor="operator-1")
    with pytest.raises(ValueError, match="外部适配器"):
        service.confirm(
            draft["draft_id"],
            actor="operator-1",
            confirmer_name="张三",
            confirmer_role="企业报送负责人",
            accepted=True,
            attestation="本人已逐项核对原始记录并确认有权提交。",
            expected_revision=draft["_meta"]["revision"],
            confirmation_method="qualified_electronic_signature",
        )


def test_submission_matches_v1_shape_and_is_idempotent(values) -> None:
    platform = FakePlatform()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=platform,  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    _confirm(service, draft)
    first = service.submit(
        draft["draft_id"],
        idempotency_key="enterprise-001-20260727-a",
    )
    second = service.submit(
        draft["draft_id"],
        idempotency_key="enterprise-001-20260727-a",
    )
    assert first["replayed"] is False
    assert second["replayed"] is True
    assert len(platform.calls) == 1
    envelope = platform.calls[0][0]
    assert set(envelope) == {
        "contract_version",
        "submission_id",
        "idempotency_key",
        "submitted_at",
        "payload",
        "payload_sha256",
    }
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12}",
        envelope["submission_id"],
    )
    assert envelope["payload_sha256"] == sha256_jcs(envelope["payload"])
    payload = envelope["payload"]
    assert payload["human_confirmation"]["confirmed"] is True
    assert payload["human_confirmation"][
        "understands_regulator_decides_normality_and_legality"
    ]
    confirmation = service.get_draft(draft["draft_id"])["_meta"][
        "confirmation"
    ]
    assert payload["human_confirmation"][
        "confirmation_evidence_sha256"
    ] == sha256_json(confirmation)
    assert confirmation["document_sha256"]
    assert confirmation["revision"] == service.get_draft(
        draft["draft_id"]
    )["_meta"]["revision"]
    assert payload["llm_assistance"]["used"] is False
    observation = payload["observations"][0]
    assert "metric_code" not in observation
    assert len(observation["signature"]) == 64
    assert set(observation["field_provenance"]) >= {
        "value",
        "payload_sha256",
        "signature",
    }


def test_submission_uses_transport_time_not_old_confirmation_time(
    values,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform = FakePlatform()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=platform,  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    confirmed = _confirm(service, draft)
    confirmed_at = confirmed["_meta"]["confirmation"]["confirmed_at"]
    monkeypatch.setattr(
        "enterprise_agent.service.utc_text",
        lambda: "2026-07-27T12:00:00Z",
    )

    service.submit(
        draft["draft_id"],
        idempotency_key="enterprise-001-delayed-submit-v1",
    )

    envelope = platform.calls[0][0]
    assert envelope["submitted_at"] == "2026-07-27T12:00:00Z"
    assert envelope["submitted_at"] != confirmed_at


def test_failed_retry_reuses_first_persisted_request_and_transport_time(
    values,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform = FailOncePlatform()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=platform,  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    _confirm(service, draft)
    transport_times = iter(
        (
            "2026-07-27T10:00:00Z",
            "2026-07-27T14:00:00Z",
        )
    )
    monkeypatch.setattr(
        "enterprise_agent.service.utc_text",
        lambda: next(transport_times),
    )
    key = "enterprise-001-retry-same-request-v1"

    with pytest.raises(PlatformError):
        service.submit(draft["draft_id"], idempotency_key=key)
    completed = service.submit(draft["draft_id"], idempotency_key=key)

    assert completed["status"] == "succeeded"
    assert len(platform.calls) == 2
    assert platform.calls[0] == platform.calls[1]
    assert platform.calls[0][0]["submitted_at"] == "2026-07-27T10:00:00Z"
    stored = service.repository.submissions_for_draft(draft["draft_id"])[0]
    assert stored["request"] == platform.calls[0][0]


def test_submission_uses_normalised_signed_observation_without_overwrite(
    values,
) -> None:
    values["observations"][0].update(
        {
            "value": 7100,
            "observed_at": "2026-07-27T08:00:00+08:00",
            "received_at": "2026-07-27T08:00:05+08:00",
            "interval_start": "2026-07-27T07:00:00+08:00",
            "interval_end": "2026-07-27T08:00:00+08:00",
        }
    )
    values["observations"][0] = gateway_sign_observation(
        values["observations"][0]
    )
    platform = FakePlatform()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=platform,  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    _confirm(service, draft)
    service.submit(
        draft["draft_id"],
        idempotency_key="enterprise-001-normalized-v1",
    )
    observation = platform.calls[0][0]["payload"]["observations"][0]
    assert observation["value"] == 7100.0
    assert isinstance(observation["value"], float)
    assert observation["observed_at"] == "2026-07-27T00:00:00Z"
    assert observation["received_at"] == "2026-07-27T00:00:05Z"
    assert observation["interval_start"] == "2026-07-26T23:00:00Z"
    assert observation["interval_end"] == "2026-07-27T00:00:00Z"


def test_idempotency_key_has_contract_constraints(service, values) -> None:
    service.platform_client = FakePlatform()  # type: ignore[assignment]
    draft = service.create_draft(values, actor="operator-1")
    _confirm(service, draft)
    with pytest.raises(ValueError):
        service.submit(draft["draft_id"], idempotency_key="short")


def test_manual_observation_without_gateway_signature_fails_closed(values) -> None:
    observation = values["observations"][0]
    observation["payload_sha256"] = ""
    observation["signature"] = ""
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=FakePlatform(),  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    with pytest.raises(ValidationBlockedError):
        _confirm(service, draft)
    result = service.validate(draft["draft_id"])
    assert result["valid"] is False
    assert {
        issue["code"] for issue in result["issues"]
    } >= {
        "source_payload_digest_required",
        "source_signature_required",
    }
    # Even the empty credential fields received ordinary manual provenance;
    # provenance alone must never make hand-entered values submittable.
    assert "/observations/0/payload_sha256" in draft["field_provenance"]
    assert "/observations/0/signature" in draft["field_provenance"]


def test_editing_signed_observation_discards_source_credentials(values) -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(values, actor="operator-1")
    edited_observation = {
        **draft["observations"][0],
        "value": 1001.25,
    }
    changed = service.patch_draft(
        draft["draft_id"],
        {"observations": [edited_observation]},
        actor="operator-1",
        expected_revision=draft["_meta"]["revision"],
    )
    observation = changed["observations"][0]
    assert "payload_sha256" not in observation
    assert "signature" not in observation
    assert "/observations/0/payload_sha256" not in changed["field_provenance"]
    assert "/observations/0/signature" not in changed["field_provenance"]
    result = service.validate(draft["draft_id"])
    assert result["valid"] is False
    assert any(
        issue["code"] == "source_signature_required"
        for issue in result["issues"]
    )


def test_deleting_or_reordering_observations_preserves_unchanged_gateway_evidence(
    values,
) -> None:
    second = gateway_sign_observation(
        {
            **values["observations"][0],
            "source_id": "mine-001-secondary-transport",
            "observation_id": "obs-20260727-0002",
            "sequence_no": 202607270002,
            "value": 500.5,
        }
    )
    values["observations"].append(second)

    delete_service = EnterpriseAgentService(Repository(":memory:"))
    delete_draft = delete_service.create_draft(values, actor="operator-1")
    old_provenance = deepcopy(
        delete_draft["field_provenance"]["/observations/1/signature"]
    )
    after_delete = delete_service.patch_draft(
        delete_draft["draft_id"],
        {"observations": [deepcopy(delete_draft["observations"][1])]},
        actor="operator-1",
        expected_revision=1,
    )
    assert after_delete["observations"][0]["signature"] == second["signature"]
    assert after_delete["field_provenance"][
        "/observations/0/signature"
    ] == old_provenance

    reorder_service = EnterpriseAgentService(Repository(":memory:"))
    reorder_draft = reorder_service.create_draft(values, actor="operator-1")
    reordered = reorder_service.patch_draft(
        reorder_draft["draft_id"],
        {
            "observations": [
                deepcopy(reorder_draft["observations"][1]),
                deepcopy(reorder_draft["observations"][0]),
            ]
        },
        actor="operator-1",
        expected_revision=1,
    )
    assert [row["observation_id"] for row in reordered["observations"]] == [
        "obs-20260727-0002",
        "obs-20260727-0001",
    ]
    assert [row["signature"] for row in reordered["observations"]] == [
        second["signature"],
        values["observations"][0]["signature"],
    ]
    assert reordered["field_provenance"]["/observations/0/signature"] == (
        reorder_draft["field_provenance"]["/observations/1/signature"]
    )


def test_stale_gateway_digest_is_blocked_before_confirmation(values) -> None:
    # Simulate an out-of-band mutation that bypasses the ordinary edit helper:
    # the preflight digest comparison remains a second fail-closed boundary.
    values["observations"][0]["value"] = 1001.25
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(values, actor="operator-1")
    result = service.validate(draft["draft_id"])
    assert result["valid"] is False
    assert any(
        issue["code"] == "source_payload_digest_mismatch"
        for issue in result["issues"]
    )
    with pytest.raises(ValidationBlockedError):
        _confirm(service, draft)


def test_optimistic_revision_and_audit_chain(service, values) -> None:
    draft = service.create_draft(values, actor="operator-1")
    service.patch_draft(
        draft["draft_id"],
        {"notes": "first"},
        actor="operator-1",
        expected_revision=1,
    )
    with pytest.raises(ConflictError):
        service.patch_draft(
            draft["draft_id"],
            {"notes": "stale"},
            actor="operator-2",
            expected_revision=1,
        )
    integrity = service.repository.verify_audit(draft["draft_id"])
    assert integrity["valid"] is True
    assert integrity["event_count"] == 2


def test_concurrent_submit_is_serialized_and_draft_is_locked_while_pending(
    values,
) -> None:
    platform = BlockingPlatform()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=platform,  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    confirmed = _confirm(service, draft)
    key = "enterprise-001-concurrent-submit-v1"
    results: list[dict] = []

    def submit() -> None:
        results.append(
            service.submit(
                draft["draft_id"],
                idempotency_key=key,
                actor="operator-1",
            )
        )

    first = threading.Thread(target=submit)
    second = threading.Thread(target=submit)
    first.start()
    assert platform.entered.wait(timeout=3)
    second.start()
    time.sleep(0.05)
    assert len(platform.calls) == 1
    with pytest.raises(ConflictError, match="正在提交"):
        service.patch_draft(
            draft["draft_id"],
            {"notes": "不能与网络提交并发"},
            actor="operator-1",
            expected_revision=confirmed["_meta"]["revision"],
        )
    platform.release.set()
    first.join(timeout=3)
    second.join(timeout=3)

    assert len(results) == 2
    assert len(platform.calls) == 1
    assert {result["replayed"] for result in results} == {False, True}


def test_structured_platform_failure_is_durable_and_actionable(values) -> None:
    platform = RejectingPlatform()
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=platform,  # type: ignore[arg-type]
    )
    draft = service.create_draft(values, actor="operator-1")
    _confirm(service, draft)
    with pytest.raises(PlatformError, match="确认人未备案"):
        service.submit(
            draft["draft_id"],
            idempotency_key="enterprise-001-rejected-submit-v1",
            actor="operator-1",
        )
    stored = service.repository.submissions_for_draft(draft["draft_id"])[0]
    assert stored["status"] == "failed"
    assert stored["error_code"] == "CONFIRMER_NOT_AUTHORIZED"
    assert stored["error"]["retryable"] is False
    assert stored["error"]["violations"][0]["json_pointer"].endswith(
        "/confirmer_id"
    )


def test_platform_status_distinguishes_offline_reachable_and_compatible() -> None:
    offline = EnterpriseAgentService(Repository(":memory:"))
    assert offline.platform_status()["configured"] is False

    compatible = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=CompatiblePlatform(),  # type: ignore[arg-type]
    )
    assert compatible.platform_status() == {
        "configured": True,
        "reachable": True,
        "compatible": True,
        "message": "监管平台在线，enterprise-submission-v1 合同兼容",
    }

    unreachable = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=UnreachablePlatform(),  # type: ignore[arg-type]
    )
    status = unreachable.platform_status()
    assert status["configured"] is True
    assert status["reachable"] is False
    assert status["compatible"] is False
    assert status["error"]["retryable"] is True
