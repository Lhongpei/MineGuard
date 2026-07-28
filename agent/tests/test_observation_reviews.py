from __future__ import annotations

import threading
from copy import deepcopy

import pytest
from conftest import complete_values, ensure_event_snapshot

from enterprise_agent.errors import ConflictError, ValidationBlockedError
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository


def _confirm(
    service: EnterpriseAgentService,
    draft: dict,
    *,
    actor: str,
) -> dict:
    return service.confirm(
        draft["draft_id"],
        actor=actor,
        confirmer_name="企业确认人",
        confirmer_role="企业报送负责人",
        accepted=True,
        attestation="本人已逐条核对来源观测和原始记录并确认有权提交。",
        expected_revision=draft["_meta"]["revision"],
    )


def test_confirmation_requires_current_principal_to_review_every_observation() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = ensure_event_snapshot(
        service,
        service.create_draft(complete_values(), actor="editor-1"),
        actor="editor-1",
    )
    observation_id = draft["observations"][0]["observation_id"]

    with pytest.raises(ValidationBlockedError, match="当前确认人"):
        _confirm(service, draft, actor="confirmer-1")

    reviewed = service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=True,
        actor="confirmer-1",
        expected_revision=draft["_meta"]["revision"],
    )
    assert reviewed["all_reviewed"] is True
    assert reviewed["reviewed_count"] == 1
    assert service.observation_review_state(
        draft["draft_id"],
        actor="confirmer-2",
    )["all_reviewed"] is False
    with pytest.raises(ValidationBlockedError, match="当前确认人"):
        _confirm(service, draft, actor="confirmer-2")

    confirmed = _confirm(service, draft, actor="confirmer-1")
    evidence = confirmed["_meta"]["confirmation"]
    assert evidence["observation_review_count"] == 1
    assert len(evidence["observation_reviews_sha256"]) == 64


def test_observation_change_permanently_revokes_review_even_if_value_is_restored(
) -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = ensure_event_snapshot(
        service,
        service.create_draft(complete_values(), actor="editor-1"),
        actor="editor-1",
    )
    original = deepcopy(draft["observations"][0])
    observation_id = original["observation_id"]
    service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=True,
        actor="confirmer-1",
        expected_revision=draft["_meta"]["revision"],
    )

    edited = {**original, "value": original["value"] + 1}
    changed = service.patch_draft(
        draft["draft_id"],
        {"observations": [edited]},
        actor="editor-1",
        expected_revision=draft["_meta"]["revision"],
    )
    assert service.observation_review_state(
        draft["draft_id"],
        actor="confirmer-1",
    )["all_reviewed"] is False

    restored = service.patch_draft(
        draft["draft_id"],
        {"observations": [original]},
        actor="editor-1",
        expected_revision=changed["_meta"]["revision"],
    )
    assert restored["observations"][0] == original
    assert service.observation_review_state(
        draft["draft_id"],
        actor="confirmer-1",
    )["all_reviewed"] is False
    audit = service.repository.audit_events(draft["draft_id"])
    changed_event = next(
        event
        for event in audit
        if event["event_type"] == "draft_updated"
        and event["details"]["invalidated_observation_reviews"] == 1
    )
    assert changed_event["details"]["invalidated_observation_reviews"] == 1


def test_review_is_idempotent_and_revocation_invalidates_confirmation() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = ensure_event_snapshot(
        service,
        service.create_draft(complete_values(), actor="editor-1"),
        actor="editor-1",
    )
    observation_id = draft["observations"][0]["observation_id"]
    first = service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=True,
        actor="confirmer-1",
        expected_revision=draft["_meta"]["revision"],
    )
    second = service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=True,
        actor="confirmer-1",
        expected_revision=draft["_meta"]["revision"],
    )
    assert first == second
    assert len(service.repository.audit_events(draft["draft_id"])) == 3

    confirmed = _confirm(service, draft, actor="confirmer-1")
    assert confirmed["_meta"]["confirmed"] is True
    revoked = service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=False,
        actor="confirmer-1",
        expected_revision=draft["_meta"]["revision"],
    )
    assert revoked["all_reviewed"] is False
    assert service.get_draft(draft["draft_id"])["_meta"]["confirmed"] is False


def test_concurrent_observation_change_cannot_leave_a_stale_review_active() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = ensure_event_snapshot(
        service,
        service.create_draft(complete_values(), actor="editor-1"),
        actor="editor-1",
    )
    observation = deepcopy(draft["observations"][0])
    observation_id = observation["observation_id"]
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def review() -> None:
        barrier.wait()
        try:
            service.review_observations(
                draft["draft_id"],
                observation_ids=[observation_id],
                reviewed=True,
                actor="confirmer-1",
                expected_revision=draft["_meta"]["revision"],
            )
            outcomes.append("reviewed")
        except ConflictError:
            outcomes.append("review_conflict")

    def change() -> None:
        barrier.wait()
        service.patch_draft(
            draft["draft_id"],
            {"observations": [{**observation, "value": 999.5}]},
            actor="editor-1",
            expected_revision=draft["_meta"]["revision"],
        )
        outcomes.append("changed")

    threads = [threading.Thread(target=review), threading.Thread(target=change)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)

    assert "changed" in outcomes
    assert service.observation_review_state(
        draft["draft_id"],
        actor="confirmer-1",
    )["all_reviewed"] is False


def test_another_reviewers_actions_do_not_invalidate_existing_confirmation() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = ensure_event_snapshot(
        service,
        service.create_draft(complete_values(), actor="editor-1"),
        actor="editor-1",
    )
    observation_id = draft["observations"][0]["observation_id"]
    service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=True,
        actor="confirmer-1",
        expected_revision=draft["_meta"]["revision"],
    )
    _confirm(service, draft, actor="confirmer-1")

    service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=True,
        actor="confirmer-2",
        expected_revision=draft["_meta"]["revision"],
    )
    assert service.get_draft(draft["draft_id"])["_meta"]["confirmed"] is True
    service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=False,
        actor="confirmer-2",
        expected_revision=draft["_meta"]["revision"],
    )
    assert service.get_draft(draft["draft_id"])["_meta"]["confirmed"] is True

    service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=False,
        actor="confirmer-1",
        expected_revision=draft["_meta"]["revision"],
    )
    assert service.get_draft(draft["draft_id"])["_meta"]["confirmed"] is False
