from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import complete_values, gateway_sign_observation

from enterprise_agent.models import new_draft
from enterprise_agent.tools.audits import audit_tool_specs
from enterprise_agent.tools.protocol import (
    ToolContext,
    ToolProtocolError,
    ToolRegistry,
)
from enterprise_agent.util import canonical_json, sha256_json


class FakeRepository:
    def __init__(self, document: dict[str, Any]):
        self.document = document

    def get_draft(
        self,
        draft_id: str,
        *,
        include_deleted: bool = False,
    ) -> dict[str, Any]:
        assert not include_deleted
        assert draft_id == self.document["draft_id"]
        return deepcopy(self.document)

    def list_drafts(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        assert not include_deleted
        return []


def observation(
    source_id: str,
    index: int,
    value: float,
    *,
    unit: str = "t",
    minute: int | None = None,
    sequence_no: int | None = None,
) -> dict[str, Any]:
    observed_at = datetime(2026, 7, 27, tzinfo=UTC) + timedelta(
        minutes=index if minute is None else minute
    )
    return gateway_sign_observation(
        {
            "source_id": source_id,
            "observation_id": f"{source_id}-obs-{index:04d}",
            "metric_code": "coal.main_transport_t",
            "value": value,
            "unit": unit,
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "received_at": (observed_at + timedelta(seconds=5))
            .isoformat()
            .replace("+00:00", "Z"),
            "interval_start": None,
            "interval_end": None,
            "reset_before": False,
            "sequence_no": index if sequence_no is None else sequence_no,
            "revision": 0,
        }
    )


def draft_document(observations: list[dict[str, Any]]) -> dict[str, Any]:
    document = new_draft()
    document.update(complete_values())
    document["draft_id"] = "draft-audit"
    document["observations"] = observations
    document.update(
        {
            "status": "draft",
            "receipt": None,
            "_meta": {
                "revision": 7,
                "confirmed_revision": None,
                "confirmed": False,
                "confirmation": None,
                "submitted": False,
                "latest_submission": None,
                "deleted": False,
                "deleted_at": None,
                "created_at": document["window_start"],
                "updated_at": document["window_end"],
            },
        }
    )
    return document


def registry_for(document: dict[str, Any]) -> ToolRegistry:
    return ToolRegistry(
        audit_tool_specs(),
        context=ToolContext(repository=FakeRepository(document)),
    )


def attach_complete_lineage(
    document: dict[str, Any],
    *,
    sensitive_text: str = "TOP-SECRET-SOURCE-MATERIAL",
) -> None:
    content_sha256 = "a" * 64
    document["imports"] = [
        {
            "id": "import-audit-1",
            "name": sensitive_text,
            "filename": "source.json",
            "format": "json",
            "source_system": sensitive_text,
            "imported_at": "2026-07-27T08:01:00Z",
            "content_sha256": content_sha256,
            "truth_statement": True,
        }
    ]
    record = {
        "source_kind": "json",
        "source_name": sensitive_text,
        "locator": f"secret://{sensitive_text}",
        "content_sha256": content_sha256,
        "confidence": 1.0,
        "extraction_method": "deterministic_json_key",
        "recorded_at": "2026-07-27T08:01:00Z",
    }
    document["field_provenance"] = {}
    for index, item in enumerate(document["observations"]):
        for field in item:
            document["field_provenance"][f"/observations/{index}/{field}"] = [
                deepcopy(record)
            ]


def test_audit_specs_are_strict_read_only_and_repository_grounded() -> None:
    specs = audit_tool_specs()
    assert [item.name for item in specs] == [
        "inspect_observation_continuity",
        "compare_source_consistency",
        "summarize_provenance_lineage",
    ]
    assert [item.category for item in specs] == [
        "temporal_quality",
        "source_consistency",
        "provenance",
    ]
    assert all(not item.mutating and not item.requires_approval for item in specs)
    assert all(item.evidence_grounding == "repository_grounded" for item in specs)
    assert all(item.network_access is False for item in specs)
    assert all(item.scenario_only is False for item in specs)
    assert all(
        item.allowed_profiles == ("standard", "chat_read_only") for item in specs
    )
    assert all(item.input_schema["additionalProperties"] is False for item in specs)
    assert all(item.output_schema["additionalProperties"] is False for item in specs)
    assert all(
        item.output_schema["properties"]["not_a_regulatory_determination"]
        == {"type": "boolean", "enum": [True]}
        for item in specs
    )


@pytest.mark.parametrize(
    ("tool_name", "arguments"),
    [
        ("inspect_observation_continuity", {"draft_id": "draft-audit"}),
        (
            "compare_source_consistency",
            {
                "draft_id": "draft-audit",
                "metric_code": "coal.main_transport_t",
            },
        ),
        ("summarize_provenance_lineage", {"draft_id": "draft-audit"}),
    ],
)
def test_audit_inputs_reject_unknown_fields(
    tool_name: str,
    arguments: dict[str, Any],
) -> None:
    document = draft_document(
        [
            observation("source-a", 0, 100),
            observation("source-a", 1, 101),
        ]
    )
    registry = registry_for(document)
    with pytest.raises(ToolProtocolError, match="不支持字段"):
        registry.execute(
            tool_name,
            {**arguments, "ignore_previous_rules": True},
        )


def test_continuity_reports_sequence_gap_without_claiming_device_failure() -> None:
    document = draft_document(
        [
            observation("source-a", 0, 100, sequence_no=10),
            observation("source-a", 1, 101, sequence_no=12),
        ]
    )
    result = registry_for(document).execute(
        "inspect_observation_continuity",
        {
            "draft_id": document["draft_id"],
            "max_gap_seconds": 120,
            "max_receive_delay_seconds": 10,
        },
    )
    series = result.data["series"][0]
    assert result.data["status"] == "evaluated"
    assert result.data["not_a_regulatory_determination"] is True
    assert series["status"] == "evaluated"
    assert series["sequence_gap_count"] == 1
    assert series["missing_sequence_number_count"] == 1
    assert series["finding_count"] == 1
    assert series["issue_evidence"]["count"] == 2
    assert result.data["uncertainty"]["device_calibration_checked"] is False
    assert result.data["uncertainty"]["causality_determined"] is False


def test_continuity_does_not_merge_mixed_units_or_single_points() -> None:
    mixed = draft_document(
        [
            observation("source-a", 0, 100, unit="t"),
            observation("source-a", 1, 101, unit="kg"),
            observation("source-b", 2, 102, unit="t"),
        ]
    )
    result = registry_for(mixed).execute(
        "inspect_observation_continuity",
        {"draft_id": mixed["draft_id"]},
    )
    records = {item["source_id"]: item for item in result.data["series"]}
    assert result.data["status"] == "not_evaluated"
    assert records["source-a"]["status"] == "not_evaluated"
    assert records["source-a"]["unit"] is None
    assert records["source-a"]["units"] == ["kg", "t"]
    assert records["source-a"]["sequence_gap_count"] is None
    assert records["source-b"]["status"] == "not_evaluated"
    assert "至少需要两条" in records["source-b"]["reason"]


def test_continuity_bounds_evidence_and_hashes_the_complete_id_set() -> None:
    observations = [
        observation("source-a", index, float(index)) for index in range(105)
    ]
    document = draft_document(observations)
    result = registry_for(document).execute(
        "inspect_observation_continuity",
        {"draft_id": document["draft_id"]},
    )
    expected_ids = [item["observation_id"] for item in observations]
    evidence = result.data["evidence"]
    series_evidence = result.data["series"][0]["evidence"]
    assert evidence["count"] == 105
    assert evidence["returned_count"] == 100
    assert evidence["truncated"] is True
    assert evidence["sha256"] == sha256_json(expected_ids)
    assert series_evidence == evidence


def test_source_consistency_compares_same_unit_points_without_aggregation() -> None:
    document = draft_document(
        [
            observation("source-a", 0, 100, minute=0),
            observation("source-a", 1, 102, minute=10),
            observation("source-b", 2, 101, minute=1),
            observation("source-b", 3, 104, minute=11),
        ]
    )
    result = registry_for(document).execute(
        "compare_source_consistency",
        {
            "draft_id": document["draft_id"],
            "metric_code": "coal.main_transport_t",
            "source_ids": ["source-a", "source-b"],
            "time_tolerance_seconds": 120,
        },
    )
    pair = result.data["pairs"][0]
    assert result.data["status"] == "evaluated"
    assert pair["status"] == "evaluated"
    assert pair["matched_pair_count"] == 2
    assert pair["median_absolute_difference"] == 1.5
    assert pair["maximum_absolute_difference"] == 2
    assert pair["matches_sha256"] == sha256_json(pair["matches"])
    assert result.data["uncertainty"]["aggregation_performed"] is False
    assert result.data["uncertainty"]["automatic_unit_conversion"] is False
    assert result.data["uncertainty"]["source_equivalence_verified"] is False


def test_source_consistency_returns_not_evaluated_for_mixed_units() -> None:
    document = draft_document(
        [
            observation("source-a", 0, 100, unit="t"),
            observation("source-b", 1, 100_000, unit="kg"),
        ]
    )
    result = registry_for(document).execute(
        "compare_source_consistency",
        {
            "draft_id": document["draft_id"],
            "metric_code": "coal.main_transport_t",
            "source_ids": ["source-a", "source-b"],
        },
    )
    pair = result.data["pairs"][0]
    assert result.data["status"] == "not_evaluated"
    assert pair["status"] == "not_evaluated"
    assert pair["unit"] is None
    assert pair["matched_pair_count"] == 0
    assert pair["median_absolute_difference"] is None
    assert pair["matches"] == []
    assert "单位不同" in pair["reason"]


def test_provenance_lineage_is_grounded_and_does_not_expose_sensitive_text() -> None:
    sensitive_text = "TOP-SECRET-SOURCE-MATERIAL"
    document = draft_document([observation("source-a", 0, 100)])
    attach_complete_lineage(document, sensitive_text=sensitive_text)
    source_signature = document["observations"][0]["signature"]
    payload_digest = document["observations"][0]["payload_sha256"]
    result = registry_for(document).execute(
        "summarize_provenance_lineage",
        {"draft_id": document["draft_id"]},
    )
    record = result.data["lineage_records"][0]
    encoded = canonical_json(result.data)
    assert result.data["status"] == "evaluated"
    assert record["status"] == "evaluated"
    assert record["payload_digest_matches"] is True
    assert record["signature_format_valid"] is True
    assert record["signature_cryptographically_verified"] is False
    assert record["matched_import_ids"]["ids"] == ["import-audit-1"]
    assert record["unmatched_content_sha256s"]["count"] == 0
    assert sensitive_text not in encoded
    assert source_signature not in encoded
    assert payload_digest not in encoded
    assert result.data["uncertainty"]["source_document_content_read"] is False


def test_provenance_lineage_missing_records_is_not_evaluated() -> None:
    document = draft_document([observation("source-a", 0, 100)])
    document["field_provenance"] = {}
    document["imports"] = []
    result = registry_for(document).execute(
        "summarize_provenance_lineage",
        {"draft_id": document["draft_id"]},
    )
    record = result.data["lineage_records"][0]
    assert result.data["status"] == "not_evaluated"
    assert record["status"] == "not_evaluated"
    assert record["provenance_fields_present"] == 0
    assert record["provenance_record_count"] == 0
    assert record["content_sha256s"]["count"] == 0
    assert result.data["not_a_regulatory_determination"] is True
