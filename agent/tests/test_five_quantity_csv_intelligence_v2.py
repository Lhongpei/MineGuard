from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from enterprise_agent.errors import ConflictError, ImportContentError
from enterprise_agent.five_quantity_exchange import MineIdentity
from enterprise_agent.five_quantity_mapping import MAPPING_TOOL_NAME
from enterprise_agent.five_quantity_runtime import FiveQuantityRuntime
from enterprise_agent.storage import Repository


class MappingProvider:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def complete_with_tools(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        self.calls.append({"messages": messages, "tools": tools})
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "csv-map-call-1",
                    "type": "function",
                    "function": {
                        "name": MAPPING_TOOL_NAME,
                        "arguments": json.dumps(
                            {
                                "mappings": [
                                    {
                                        "source_column": 1,
                                        "source_header": "原煤完成量",
                                        "metric": "production_t",
                                        "scope": "daily_total",
                                        "shift": None,
                                        "unit": "t",
                                        "confidence": 0.92,
                                        "reason": "表头语义指向原煤日产量",
                                    },
                                    {
                                        "source_column": 2,
                                        "source_header": "当日总电耗",
                                        "metric": "electricity_kwh",
                                        "scope": "daily_total",
                                        "shift": None,
                                        "unit": "kWh",
                                        "confidence": 0.91,
                                        "reason": "表头语义指向日累计耗电量",
                                    },
                                ]
                            },
                            ensure_ascii=False,
                        ),
                    },
                }
            ],
        }


def identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-CSV-AI-001",
        mine_name="CSV 智能映射测试矿",
        operator_id="operator-csv-ai",
        operator_name="CSV 智能映射测试企业",
        system_id="agent-csv-ai",
        regulator_system_id="regulator-csv-ai",
        regulator_party_id="regulator-party-csv-ai",
        key_id="enterprise-key-csv-ai",
        regulator_key_id="regulator-key-csv-ai",
        message_hmac_secret="csv-ai-message-secret-abcdefghijklmnopqrstuvwxyz",
    )


def test_model_maps_only_headers_and_materializes_human_selected_values(
    tmp_path: Path,
) -> None:
    repository = Repository(tmp_path / "agent.db")
    provider = MappingProvider()
    runtime = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
        csv_preview_directory=tmp_path / "csv-preview-evidence",
        llm_provider=provider,
    )
    content = (
        "业务日,原煤完成量,当日总电耗,内部备注\n"
        "2026-08-01,2600,96000,SECRET-RAW-COAL-VALUE\n"
    ).encode()

    preview = runtime.preview_csv(
        filename="erp.csv",
        content=content,
        actor="operator-1",
    )

    assert preview["mapping_assistant"]["attempted"] is True
    assert preview["mapping_assistant"]["succeeded"] is True
    columns = {item["source_index"]: item for item in preview["columns"]}
    assert columns[1]["source"] == "llm"
    assert columns[1]["target_metric"] == "production_t"
    assert columns[2]["target_metric"] == "electricity_kwh"
    assert columns[3]["status"] == "unmapped"
    sent_to_model = json.dumps(provider.calls, ensure_ascii=False)
    assert "2600" not in sent_to_model
    assert "96000" not in sent_to_model
    assert "SECRET-RAW-COAL-VALUE" not in sent_to_model

    with repository._read() as db:
        row = db.execute(
            "SELECT inspection_json,mapping_advice_json FROM fq_csv_previews"
        ).fetchone()
        assert row is not None
        persisted_metadata = str(row["inspection_json"]) + str(
            row["mapping_advice_json"]
        )
        assert "2600" not in persisted_metadata
        assert "SECRET-RAW-COAL-VALUE" not in persisted_metadata

    result = runtime.materialize_csv_preview(
        preview_id=preview["preview_id"],
        mappings=[
            {
                "source_index": 1,
                "target_metric": "production_t",
                "target_period": "daily_total",
            },
            {
                "source_index": 2,
                "target_metric": "electricity_kwh",
                "target_period": "daily_total",
            },
        ],
        save_profile=False,
        actor="operator-1",
    )

    assert result["status"] == "ready_review"
    assert result["model_assistance_used"] is True
    payload = result["draft"]["payload"]
    assert payload["agent_processing"]["model_assistance_used"] is True
    daily = payload["days"][0]["reported_quantity"]["daily_total"]
    assert daily["production_t"]["value"] == 2600
    assert daily["electricity_kwh"]["value"] == 96000
    with repository._read() as db:
        assert db.execute("SELECT COUNT(*) FROM fq_outbox").fetchone()[0] == 0
        preview_row = db.execute(
            "SELECT status,resulting_draft_id FROM fq_csv_previews"
        ).fetchone()
        assert preview_row is not None
        assert preview_row["status"] == "consumed"
        assert preview_row["resulting_draft_id"] == result["draft_id"]


def test_headerless_csv_is_rejected_before_any_model_call(tmp_path: Path) -> None:
    provider = MappingProvider()
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "agent.db"),
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
        csv_preview_directory=tmp_path / "csv-preview-evidence",
        llm_provider=provider,
    )

    with pytest.raises(ImportContentError, match="日期列"):
        runtime.preview_csv(
            filename="无表头.csv",
            content=(
                b"2026-08-01,2600,96000\n"
                b"2026-08-02,2700,97000\n"
            ),
            actor="operator-1",
        )

    assert provider.calls == []


def test_observation_like_declared_headers_are_rejected_before_model(
    tmp_path: Path,
) -> None:
    provider = MappingProvider()
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "agent.db"),
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
        csv_preview_directory=tmp_path / "csv-preview-evidence",
        llm_provider=provider,
    )

    with pytest.raises(ImportContentError, match="日期列"):
        runtime.preview_csv(
            filename="伪造表头.csv",
            content=(
                b"date,2600,SECRET-RAW-VALUE\n"
                b"2026-08-01,2700,other\n"
            ),
            actor="operator-1",
        )

    assert provider.calls == []


def test_observation_like_detail_headers_are_rejected_before_model(
    tmp_path: Path,
) -> None:
    provider = MappingProvider()
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "agent.db"),
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
        csv_preview_directory=tmp_path / "csv-preview-evidence",
        llm_provider=provider,
    )

    with pytest.raises(ImportContentError, match="表头明细行"):
        runtime.preview_csv(
            filename="伪造多层表头.csv",
            content=(
                "date,业务字段,内部备注\n"
                ",产量,2600\n"
                "2026-08-01,2700,SECRET\n"
            ).encode(),
            actor="operator-1",
        )

    assert provider.calls == []


def test_same_csv_with_different_confirmed_mapping_is_not_silently_reused(
    tmp_path: Path,
) -> None:
    repository = Repository(tmp_path / "agent.db")
    runtime = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
        csv_preview_directory=tmp_path / "csv-preview-evidence",
    )
    content = b"date,production_t\n2026-08-01,2600\n"
    original = runtime.ingest_bytes(
        filename="same.csv",
        content=content,
        acquisition_mode="manual_import",
        actor="operator-1",
    )
    preview = runtime.preview_csv(
        filename="same.csv",
        content=content,
        actor="operator-1",
    )

    with pytest.raises(ConflictError, match="另一套字段映射"):
        runtime.materialize_csv_preview(
            preview_id=preview["preview_id"],
            mappings=[
                {
                    "source_index": 1,
                    "target_metric": "electricity_kwh",
                    "target_period": "daily_total",
                }
            ],
            save_profile=False,
            actor="operator-1",
        )

    old_draft = runtime.store.get_draft(original["draft_id"])
    daily = old_draft["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert daily["production_t"]["value"] == 2600
    assert daily["electricity_kwh"]["value"] is None
    assert runtime.csv_persistence.get_preview(
        preview["preview_id"], actor="operator-1"
    )["status"] == "active"

    matching_preview = runtime.preview_csv(
        filename="same.csv",
        content=content,
        actor="operator-1",
    )
    matching = runtime.materialize_csv_preview(
        preview_id=matching_preview["preview_id"],
        mappings=[
            {
                "source_index": 1,
                "target_metric": "production_t",
                "target_period": "daily_total",
            }
        ],
        save_profile=False,
        actor="operator-1",
    )
    assert matching["duplicate"] is True
    assert matching["draft_id"] == original["draft_id"]
    assert runtime.csv_persistence.get_preview(
        matching_preview["preview_id"],
        actor="operator-1",
        include_terminal=True,
    )["status"] == "consumed"
