from __future__ import annotations

import json
from copy import deepcopy

import pytest
from conftest import complete_values, event_snapshot_for

from enterprise_agent.errors import ImportContentError
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository


def test_empty_event_set_still_requires_regulator_snapshot_and_import_passes() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    before = service.validate(draft["draft_id"])
    assert before["valid"] is False
    assert any(
        issue["code"] == "regulator_event_snapshot_required"
        for issue in before["issues"]
    )

    result = service.import_event_snapshot(
        draft["draft_id"],
        snapshot=event_snapshot_for(draft),
        actor="operator-1",
        expected_revision=1,
    )
    imported = result["draft"]
    assert imported["_meta"]["revision"] == 2
    assert service.validate(draft["draft_id"])["valid"] is True
    record = imported["field_provenance"][
        "/operational_context/approved_event_codes"
    ][0]
    assert record["source_kind"] == "approved_document"
    assert record["extraction_method"] == "regulator_event_snapshot_import"
    assert record["content_sha256"] == "e" * 64


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("mine_id", "other-mine", "矿井"),
        ("window_start", "2026-07-27T00:00:01Z", "统计窗口"),
        ("window_end", "2026-07-27T08:00:01Z", "统计窗口"),
        ("evidence_sha256", "not-a-digest", "64 位"),
    ],
)
def test_event_snapshot_rejects_mismatched_scope_or_invalid_digest(
    field: str,
    value: str,
    message: str,
) -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    snapshot = event_snapshot_for(draft)
    snapshot[field] = value
    with pytest.raises(ImportContentError, match=message):
        service.import_event_snapshot(
            draft["draft_id"],
            snapshot=snapshot,
            actor="operator-1",
            expected_revision=1,
        )
    assert service.get_draft(draft["draft_id"])["_meta"]["revision"] == 1


def test_same_value_autosave_preserves_snapshot_provenance_and_confirmation() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    imported = service.import_event_snapshot(
        draft["draft_id"],
        snapshot=event_snapshot_for(draft),
        actor="operator-1",
        expected_revision=1,
    )["draft"]
    pointer = "/operational_context/approved_event_codes"
    snapshot_provenance = deepcopy(imported["field_provenance"][pointer])

    no_op = service.patch_draft(
        draft["draft_id"],
        {
            "enterprise_name": imported["enterprise_name"],
            "operational_context": deepcopy(imported["operational_context"]),
        },
        actor="operator-1",
        expected_revision=2,
    )
    assert no_op["_meta"]["revision"] == 2
    assert no_op["field_provenance"][pointer] == snapshot_provenance

    observation_id = imported["observations"][0]["observation_id"]
    service.review_observations(
        draft["draft_id"],
        observation_ids=[observation_id],
        reviewed=True,
        actor="operator-1",
        expected_revision=2,
    )
    confirmed = service.confirm(
        draft["draft_id"],
        actor="operator-1",
        confirmer_name="张三",
        confirmer_role="企业报送负责人",
        accepted=True,
        attestation="本人已逐条核对来源观测和全部原始材料。",
        expected_revision=2,
    )
    assert confirmed["_meta"]["confirmed"] is True
    still_no_op = service.patch_draft(
        draft["draft_id"],
        {"operational_context": deepcopy(imported["operational_context"])},
        actor="operator-1",
        expected_revision=2,
    )
    assert still_no_op["_meta"]["confirmed"] is True
    assert still_no_op["_meta"]["revision"] == 2


def test_same_event_codes_in_later_business_json_keep_snapshot_authority() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    values = complete_values()
    values["operational_context"]["approved_event_codes"] = [
        "MAINTENANCE",
        "APPROVED_STOP",
    ]
    draft = service.create_draft(values, actor="operator-1")
    snapshot = event_snapshot_for(draft)
    snapshot["event_codes"] = ["APPROVED_STOP", "MAINTENANCE"]
    imported = service.import_event_snapshot(
        draft["draft_id"],
        snapshot=snapshot,
        actor="operator-1",
        expected_revision=1,
    )["draft"]

    # Full exports often repeat the same set in a different order.
    values["operational_context"]["approved_event_codes"] = [
        "MAINTENANCE",
        "APPROVED_STOP",
    ]
    later = service.import_into_draft(
        draft["draft_id"],
        format_name="json",
        content=json.dumps(values, ensure_ascii=False),
        source_name="complete-export.json",
        actor="operator-1",
        expected_revision=imported["_meta"]["revision"],
    )["draft"]

    records = later["field_provenance"][
        "/operational_context/approved_event_codes"
    ]
    assert any(
        record["extraction_method"] == "regulator_event_snapshot_import"
        for record in records
    )
    assert any(record["source_kind"] == "json" for record in records)
    assert service.validate(draft["draft_id"])["valid"] is True


def test_changing_snapshot_scope_invalidates_authoritative_provenance() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(complete_values(), actor="operator-1")
    imported = service.import_event_snapshot(
        draft["draft_id"],
        snapshot=event_snapshot_for(draft),
        actor="operator-1",
        expected_revision=1,
    )["draft"]
    changed = service.patch_draft(
        draft["draft_id"],
        {"window_end": "2026-07-27T09:00:00Z"},
        actor="operator-1",
        expected_revision=imported["_meta"]["revision"],
    )
    assert (
        "/operational_context/approved_event_codes"
        not in changed["field_provenance"]
    )
    result = service.validate(draft["draft_id"])
    assert any(
        issue["code"] == "regulator_event_snapshot_required"
        for issue in result["issues"]
    )
