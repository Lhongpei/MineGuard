from __future__ import annotations

from dataclasses import replace

import pytest

from enterprise_agent.tools import (
    ToolProtocolError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)


def spec() -> ToolSpec:
    return ToolSpec(
        name="metadata_probe",
        description="metadata probe",
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "maxProperties": 1,
            "properties": {"value": {"type": "number"}},
        },
        output_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["ok"],
            "properties": {"ok": {"type": "boolean"}},
        },
        execute=lambda _arguments, _context: ToolResult(
            data={"ok": True},
            summary="ok",
        ),
        category="protocol_test",
        evidence_grounding="user_supplied",
        network_access=False,
        scenario_only=True,
        allowed_profiles=("standard",),
    )


def test_tool_metadata_is_public_and_stable() -> None:
    definition = spec().public_definition()
    assert definition["category"] == "protocol_test"
    assert definition["evidence_grounding"] == "user_supplied"
    assert definition["network_access"] is False
    assert definition["scenario_only"] is True
    assert definition["allowed_profiles"] == ["standard"]


def test_registry_rejects_unsupported_schema_keywords() -> None:
    invalid = replace(
        spec(),
        input_schema={
            "type": "object",
            "unevaluatedProperties": False,
        },
    )
    with pytest.raises(ToolProtocolError) as captured:
        ToolRegistry((invalid,))
    assert captured.value.code == "unsupported_schema_keyword"


def test_max_properties_is_enforced_instead_of_silently_ignored() -> None:
    registry = ToolRegistry((spec(),))
    with pytest.raises(ToolProtocolError) as captured:
        registry.execute("metadata_probe", {"value": 1, "extra": 2})
    assert captured.value.code == "schema_max_properties"


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"category": "Bad Category"}, "invalid_tool_category"),
        ({"evidence_grounding": "model_memory"}, "invalid_evidence_grounding"),
        ({"allowed_profiles": ()}, "invalid_tool_profiles"),
        (
            {"allowed_profiles": ("standard", "standard")},
            "invalid_tool_profiles",
        ),
    ],
)
def test_registry_rejects_invalid_governance_metadata(
    change: dict[str, object],
    code: str,
) -> None:
    with pytest.raises(ToolProtocolError) as captured:
        ToolRegistry((replace(spec(), **change),))
    assert captured.value.code == code
