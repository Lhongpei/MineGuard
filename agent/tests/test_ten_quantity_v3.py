from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from enterprise_agent.errors import (
    ConflictError,
    ImportContentError,
    ValidationBlockedError,
)
from enterprise_agent.five_quantity_exchange import (
    HTTP_SIGNING_CONTEXT_V3,
    MineIdentity,
    http_transport_headers,
)
from enterprise_agent.five_quantity_import import (
    SHIFT_KEYS,
    import_five_quantity_bytes,
    inspect_five_quantity_csv,
)
from enterprise_agent.five_quantity_mapping import (
    MAPPING_TOOL_NAME,
    map_csv_columns,
)
from enterprise_agent.five_quantity_runtime import (
    CURRENT_SUBMISSION_CONTRACT,
    FiveQuantityRuntime,
    _v2_machine_preflight,
    validate_five_quantity_payload,
)
from enterprise_agent.quantity_catalog import (
    METRICS,
    OPTIONAL_SHIFT_METRICS,
    REQUIRED_SHIFT_METRICS,
)
from enterprise_agent.storage import Repository


def identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-TEN-001",
        mine_name="十量测试煤矿",
        operator_id="operator-ten-001",
        operator_name="十量测试煤业有限公司",
        system_id="agent-mine-ten-001",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-key-current",
        regulator_key_id="regulator-key-current",
        message_hmac_secret="ten-quantity-message-secret-abcdefghijklmnopqrstuvwxyz",
        capacity_band="medium",
        mining_method="underground",
        shift_system="three-shift-eight-hour",
        coal_type="bituminous",
        operating_regime="normal-production",
    )


def canonical_csv(*, invoiced: str = "2440") -> bytes:
    return (
        "日期,风量,电量,雷管,炸药,入井人员量,企业报表产量,开采量,"
        "销售量,出矿运输量,入洗原煤量,开票吨数\n"
        f"2026-07-01,4800,96000,120,240,320,2600,2660,2500,2480,2550,{invoiced}\n"
    ).encode()


def imported_payload(*, invoiced: str = "2440") -> dict[str, Any]:
    return import_five_quantity_bytes(
        filename="十量日报.csv",
        content=canonical_csv(invoiced=invoiced),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )["payload"]


class EmptyMappingProvider:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    def complete_with_tools(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> dict[str, Any]:
        self.messages = messages
        return {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call-map-empty",
                    "type": "function",
                    "function": {
                        "name": MAPPING_TOOL_NAME,
                        "arguments": json.dumps({"mappings": []}),
                    },
                }
            ],
        }


def test_v3_import_has_exact_eleven_atomic_metrics_and_no_wire_catalog_marker() -> None:
    imported = import_five_quantity_bytes(
        filename="十量日报.csv",
        content=canonical_csv(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )

    assert imported["contract_version"] == CURRENT_SUBMISSION_CONTRACT
    payload = imported["payload"]
    assert "quantity_catalog_version" not in payload
    daily = payload["days"][0]["reported_quantity"]["daily_total"]
    assert tuple(daily) == METRICS
    assert daily["production_t"]["value"] == 2600
    assert daily["extraction_t"]["value"] == 2660
    assert daily["sales_t"]["value"] == 2500
    assert daily["transport_t"]["value"] == 2480
    assert daily["wash_feed_t"]["value"] == 2550
    assert daily["invoiced_quantity_t"]["value"] == 2440

    for shift_key in SHIFT_KEYS:
        measurements = payload["days"][0]["reported_quantity"]["shifts"][
            shift_key
        ]["measurements"]
        assert set(measurements) == set(METRICS)
        assert all(
            measurements[metric]["quality_flags"] == ["not_applicable"]
            for metric in OPTIONAL_SHIFT_METRICS
        )


def test_user_facing_chinese_quantity_names_import_without_manual_remapping() -> None:
    imported = import_five_quantity_bytes(
        filename="十量标准中文表头.csv",
        content=(
            "日期,风量,电量,雷管量,炸药量,入井人员量,产量,开采量,"
            "销售量,运输量,洗煤量,开票量\n"
            "2026-07-01,4800,96000,120,240,320,2600,2660,"
            "2500,2480,2550,2440\n"
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )

    daily = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert {metric: daily[metric]["value"] for metric in METRICS} == {
        "ventilation_m3_min": 4800.0,
        "electricity_kwh": 96000.0,
        "detonators_count": 120.0,
        "explosives_kg": 240.0,
        "mine_entry_persons": 320.0,
        "production_t": 2600.0,
        "extraction_t": 2660.0,
        "sales_t": 2500.0,
        "transport_t": 2480.0,
        "wash_feed_t": 2550.0,
        "invoiced_quantity_t": 2440.0,
    }


def test_v3_shift_optional_fields_may_be_omitted_but_extraction_is_required() -> None:
    payload = imported_payload()
    for shift_key in SHIFT_KEYS:
        measurements = payload["days"][0]["reported_quantity"]["shifts"][
            shift_key
        ]["measurements"]
        for metric in OPTIONAL_SHIFT_METRICS:
            measurements.pop(metric)

    validate_five_quantity_payload(
        payload,
        identity=identity(),
        confirmed=False,
        contract_version=CURRENT_SUBMISSION_CONTRACT,
    )

    payload["days"][0]["reported_quantity"]["shifts"]["zero_shift"][
        "measurements"
    ].pop("extraction_t")
    with pytest.raises(ValueError, match="前 7 项"):
        validate_five_quantity_payload(
            payload,
            identity=identity(),
            confirmed=False,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )


def test_all_primary_quantities_including_invoiced_tonnage_are_nonnegative() -> None:
    payload = imported_payload(invoiced="-10")
    invoice = payload["days"][0]["reported_quantity"]["daily_total"][
        "invoiced_quantity_t"
    ]
    assert invoice["value"] is None
    assert "source_format_warning" in invoice["quality_flags"]

    invoice["value"] = -10
    invoice["quality_flags"] = ["reported"]
    with pytest.raises(ValueError, match="invoiced_quantity_t.value 超出范围"):
        validate_five_quantity_payload(
            payload,
            identity=identity(),
            confirmed=False,
            contract_version=CURRENT_SUBMISSION_CONTRACT,
        )


def test_standard_business_headers_map_and_true_conflicts_stay_blocked() -> None:
    provider = EmptyMappingProvider()
    headers = [
        "日期",
        "产量",
        "开票金额",
        "洗煤量",
        "运输量",
        "净开票量",
        "开采量",
        "开票量",
        "未知ERP列",
    ]
    result = map_csv_columns(headers, llm_provider=provider)

    assert set(result["blocked_columns"]) == {2, 5}
    mapped = {
        item["source_header"]: item["target"]["metric"]
        for item in result["candidates"]
    }
    assert mapped == {
        "产量": "production_t",
        "洗煤量": "wash_feed_t",
        "运输量": "transport_t",
        "开采量": "extraction_t",
        "开票量": "invoiced_quantity_t",
    }
    prompt = provider.messages[-1]["content"]
    assert "未知ERP列" in prompt
    assert all(header not in prompt for header in headers[1:8])


def test_csv_inspection_accepts_standard_names_but_blocks_invoice_amount() -> None:
    inspection = inspect_five_quantity_csv(
        filename="歧义字段.csv",
        content=(
            "日期,产量,开票金额,洗煤量,运输量\n"
            "2026-07-01,2600,1000000,2500,2480\n"
        ).encode(),
    )
    statuses = {
        item["source_header"]: item["status"] for item in inspection["columns"]
    }
    assert statuses == {
        "产量": "mapped",
        "开票金额": "blocked",
        "洗煤量": "mapped",
        "运输量": "mapped",
    }
    assert next(
        item for item in inspection["columns"]
        if item["source_header"] == "开票金额"
    )["target_metric"] is None


def test_preflight_does_not_count_optional_shift_fields_as_missing() -> None:
    payload = imported_payload()
    preflight = _v2_machine_preflight(
        payload,
        revision=1,
        contract_version=CURRENT_SUBMISSION_CONTRACT,
    )
    assert len(REQUIRED_SHIFT_METRICS) == 7
    assert preflight["missing_count"] == len(REQUIRED_SHIFT_METRICS) * 3


def test_confirmed_draft_uses_v3_message_contract_and_signing_algorithm(
    tmp_path: Path,
) -> None:
    runtime = FiveQuantityRuntime(
        Repository(tmp_path / "ten-v3.db"),
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    draft = runtime.ingest_bytes(
        filename="十量日报.csv",
        content=canonical_csv(),
        acquisition_mode="manual_import",
        actor="operator-1",
    )["draft"]
    runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="operator-1",
        confirmer_name="张三",
        confirmer_role="企业填报员",
        attestation="本人已按原始凭证逐项核对十量日报。",
        accepted=True,
    )
    message = runtime.store.due_outbox()[0]["body"]
    assert message["contract_version"] == "ten-quantity-submission-v3"
    assert message["message_type"] == "ten_quantity_submission"
    assert message["idempotency_key"].startswith("tq3.")
    assert message["signature_envelope"]["algorithm"] == "hmac-sha256-v3"
    assert "quantity_catalog_version" not in message["payload"]


def test_v3_route_uses_v3_transport_domain_for_reused_v2_application_message() -> None:
    headers = http_transport_headers(
        method="POST",
        url="https://regulator.example/v3/analysis-reports/report-1/delivery-ack",
        body=b"{}",
        sender_id="agent-mine-ten-001",
        secret="ten-quantity-transport-secret-abcdefghijklmnopqrstuvwxyz",
        contract_version="risk-delivery-ack-v2",
        timestamp="2026-08-01T00:05:00Z",
        nonce="VGVuUXVhbnRpdHlIVFRQVmVjdG9yMQ",
    )
    assert headers["X-Exchange-Contract-Version"] == "risk-delivery-ack-v2"
    assert headers["X-Exchange-Signature-Version"] == "hmac-sha256-v3"

    with pytest.raises(ValueError, match="HTTP"):
        http_transport_headers(
            method="POST",
            url="https://regulator.example/v2/five-quantity-submissions",
            body=b"{}",
            sender_id="agent-mine-ten-001",
            secret="ten-quantity-transport-secret-abcdefghijklmnopqrstuvwxyz",
            contract_version="ten-quantity-submission-v3",
        )

    assert HTTP_SIGNING_CONTEXT_V3 == (
        "MINEGUARD-TEN-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V3"
    )


def test_legacy_v2_draft_is_read_only_without_audit_or_revision_mutation(
    tmp_path: Path,
) -> None:
    repository = Repository(tmp_path / "legacy-read-only.db")
    runtime = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    draft = runtime.ingest_bytes(
        filename="十量日报.csv",
        content=canonical_csv(),
        acquisition_mode="manual_import",
        actor="operator-1",
    )["draft"]
    with repository._transaction() as db:
        db.execute(
            "UPDATE fq_drafts SET contract_version='five-quantity-submission-v2' "
            "WHERE draft_id=?",
            (draft["draft_id"],),
        )

    legacy = runtime.store.get_draft(draft["draft_id"])
    assert legacy["read_only"] is True
    before_audit = runtime.store.audit()["event_count"]
    before_revision = legacy["revision"]

    with pytest.raises(ConflictError, match="仅供读取"):
        runtime.save_draft(
            legacy["draft_id"],
            expected_revision=before_revision,
            payload=copy.deepcopy(legacy["payload"]),
            actor="operator-1",
        )
    with pytest.raises(ConflictError, match="仅供读取"):
        runtime.discard_draft(
            legacy["draft_id"],
            expected_revision=before_revision,
            actor="operator-1",
            reason="测试只读保护",
        )
    with pytest.raises(ValidationBlockedError, match="仅供读取"):
        runtime.confirm_draft(
            legacy["draft_id"],
            expected_revision=before_revision,
            actor_id="operator-2",
            confirmer_name="李四",
            confirmer_role="复核员",
            attestation="仅验证历史草稿只读保护。",
            accepted=True,
        )

    after = runtime.store.get_draft(legacy["draft_id"])
    assert after["revision"] == before_revision
    assert runtime.store.audit()["event_count"] == before_audit


def test_signed_v2_json_cannot_be_silently_upgraded_to_v3() -> None:
    document = {
        "contract_version": "five-quantity-submission-v2",
        "payload": imported_payload(),
    }
    with pytest.raises(ImportContentError, match="不能补字段升级"):
        import_five_quantity_bytes(
            filename="历史五量报文.json",
            content=json.dumps(document, ensure_ascii=False).encode(),
            acquisition_mode="manual_import",
            identity=identity(),
            captured_at="2026-08-01T00:00:00Z",
        )
