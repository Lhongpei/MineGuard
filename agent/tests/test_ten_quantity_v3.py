from __future__ import annotations

import copy
import hashlib
import hmac
import json
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from enterprise_agent.errors import (
    ConflictError,
    ImportContentError,
    ValidationBlockedError,
)
from enterprise_agent.five_quantity_exchange import (
    HTTP_SIGNING_CONTEXT_V3,
    EnterpriseSigningVerificationKey,
    MineIdentity,
    _message_material,
    http_transport_headers,
    sign_message,
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
from enterprise_agent.util import jcs_json, utc_text


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


def signed_intake_receipt(
    submission: dict[str, Any],
    *,
    mine: MineIdentity | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    mine = mine or identity()
    timestamp = timestamp or utc_text()
    receipt_message_id = str(uuid4())
    receipt = {
        "contract_version": "intake-receipt-v2",
        "message_type": "intake_receipt",
        "message_id": receipt_message_id,
        "correlation_id": submission["correlation_id"],
        "causation_id": submission["message_id"],
        "idempotency_key": f"intake.{submission['message_id']}",
        "revision": 1,
        "predecessor": None,
        "created_at": timestamp,
        "sender": {
            "system_id": mine.regulator_system_id,
            "party_id": mine.regulator_party_id,
            "role": "regulatory_platform",
        },
        "recipient": {
            "system_id": mine.system_id,
            "party_id": mine.operator_id,
            "role": "enterprise_agent",
        },
        "mine_id": mine.mine_id,
        "payload": {
            "receipt_id": str(uuid4()),
            "submission_message_id": submission["message_id"],
            "submission_revision": submission["revision"],
            "received_payload_sha256": submission["signature_envelope"][
                "payload_sha256"
            ],
            "received_at": timestamp,
            "intake_status": "accepted",
            "analysis_state": "queued",
            "regulatory_outcome": "not_determined_at_intake",
            "analysis_run_id": str(uuid4()),
        },
        "signature_envelope": {
            "algorithm": "hmac-sha256-v2",
            "canonicalization": "rfc8785-jcs",
            "key_id": mine.regulator_key_id,
            "signed_at": timestamp,
            "nonce": uuid4().hex,
            "payload_sha256": "0" * 64,
            "signature": "0" * 64,
        },
    }
    return sign_message(receipt, secret=mine.message_hmac_secret)


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


def test_csv_inspection_blocks_unapproved_scaled_or_wrong_units() -> None:
    inspection = inspect_five_quantity_csv(
        filename="危险单位.csv",
        content=(
            "日期,电量(万kWh),电量（万千瓦时）,炸药量(g),"
            "煤炭产量(kt),开票量(万t),产量(foo)\n"
            "2026-07-01,9.6,9.6,240000,2.6,0.244,2600\n"
        ).encode(),
    )

    assert len(inspection["columns"]) == 6
    assert {item["status"] for item in inspection["columns"]} == {"blocked"}
    assert all("不会静默换算" in item["reason"] for item in inspection["columns"])


def test_csv_inspection_accepts_approved_units_and_semantic_qualifiers() -> None:
    inspection = inspect_five_quantity_csv(
        filename="批准口径.csv",
        content=(
            "日期,电量(kWh),炸药量(kg),产量（企业报表）,"
            "开采量（采掘计量）,运输量（出矿/外运）,"
            "洗煤量（入洗原煤）,开票量（正常/蓝票实物吨数）\n"
            "2026-07-01,96000,240,2600,2660,2480,2550,2440\n"
        ).encode(),
    )

    assert {item["status"] for item in inspection["columns"]} == {"mapped"}


_SAFE_CSV_UNIT_HEADERS = (
    ("风量（日合计）（m3/min）", "ventilation_m3_min"),
    ("电量（日合计）（kWh）", "electricity_kwh"),
    ("雷管量（火工品雷管）（发）", "detonators_count"),
    ("雷管量", "detonators_count"),
    ("炸药量（火工品炸药）（千克）", "explosives_kg"),
    ("炸药量", "explosives_kg"),
    ("炸药量公斤", "explosives_kg"),
    ("炸药量kg", "explosives_kg"),
    ("入井人员量（日合计）（人次）", "mine_entry_persons"),
    ("产量（企业报表）（t）", "production_t"),
    ("开采量（采掘计量）（吨）", "extraction_t"),
    ("销售量（日合计）（t）", "sales_t"),
    ("运输量（出矿/外运）（吨）", "transport_t"),
    ("洗煤量（入洗原煤）（t）", "wash_feed_t"),
    ("开票量（正常/蓝票实物吨数）（吨）", "invoiced_quantity_t"),
    ("开票吨数", "invoiced_quantity_t"),
    *((metric, metric) for metric in METRICS),
)


@pytest.mark.parametrize("header,metric", _SAFE_CSV_UNIT_HEADERS)
def test_safe_csv_unit_headers_work_in_inspect_auto_and_override(
    header: str,
    metric: str,
) -> None:
    content = f"日期,{header}\n2026-07-01,123\n".encode()
    inspection = inspect_five_quantity_csv(filename="规范单位.csv", content=content)
    column = inspection["columns"][0]
    assert column["status"] == "mapped"
    assert column["target_metric"] == metric

    automatic = import_five_quantity_bytes(
        filename="规范单位.csv",
        content=content,
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    forced = import_five_quantity_bytes(
        filename="规范单位.csv",
        content=content,
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
        column_mappings=[
            {
                "source_index": 1,
                "target_metric": metric,
                "target_period": "daily_total",
            }
        ],
    )
    for imported in (automatic, forced):
        daily = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
        assert daily[metric]["value"] == 123


_DANGEROUS_CSV_UNIT_HEADERS = (
    ("风量(m3/s)", "ventilation_m3_min"),
    ("风量m3/h", "ventilation_m3_min"),
    ("风量m³／s", "ventilation_m3_min"),
    ("风量m³·s⁻¹", "ventilation_m3_min"),
    ("电量(万kWh)", "electricity_kwh"),
    ("电量（万千瓦时）", "electricity_kwh"),
    ("电量(MWh)", "electricity_kwh"),
    ("电量(Wh)", "electricity_kwh"),
    ("电量Wh", "electricity_kwh"),
    ("电量[Wh]", "electricity_kwh"),
    ("电量(Wh", "electricity_kwh"),
    ("电量千kWh", "electricity_kwh"),
    ("电量ＭＷｈ", "electricity_kwh"),
    ("电量MW·h", "electricity_kwh"),
    ("雷管量(kg)", "detonators_count"),
    ("雷管量kg", "detonators_count"),
    ("雷管量万发", "detonators_count"),
    ("炸药量(g)", "explosives_kg"),
    ("炸药量(mg)", "explosives_kg"),
    ("炸药量(t)", "explosives_kg"),
    ("炸药量g", "explosives_kg"),
    ("炸药量mg", "explosives_kg"),
    ("炸药量t", "explosives_kg"),
    ("入井人员量(万人)", "mine_entry_persons"),
    ("入井人员量万人", "mine_entry_persons"),
    ("入井人员量kg", "mine_entry_persons"),
    ("企业报表产量(kt)", "production_t"),
    ("企业报表产量kt", "production_t"),
    ("企业报表产量kg", "production_t"),
    ("企业报表产量g", "production_t"),
    ("企业报表产量[万吨]", "production_t"),
    ("企业报表产量万ｔ", "production_t"),
    ("开采量(千吨)", "extraction_t"),
    ("销售量(万吨)", "sales_t"),
    ("销售量[foo]", "sales_t"),
    ("销售量【kg】", "sales_t"),
    ("出矿运输量(万t)", "transport_t"),
    ("入洗原煤量(kg)", "wash_feed_t"),
    ("开票量(万元)", "invoiced_quantity_t"),
)


@pytest.mark.parametrize("header,metric", _DANGEROUS_CSV_UNIT_HEADERS)
def test_dangerous_csv_unit_headers_never_map_or_write(
    header: str,
    metric: str,
) -> None:
    content = f"日期,{header}\n2026-07-01,123\n".encode()
    inspection = inspect_five_quantity_csv(filename="危险单位.csv", content=content)
    column = inspection["columns"][0]
    assert column["status"] == "blocked"
    assert column["target_metric"] is None

    with pytest.raises(ImportContentError):
        import_five_quantity_bytes(
            filename="危险单位.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
        )
    with pytest.raises(ImportContentError):
        import_five_quantity_bytes(
            filename="危险单位.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
            column_mappings=[
                {
                    "source_index": 1,
                    "target_metric": metric,
                    "target_period": "daily_total",
                }
            ],
        )


_UNKNOWN_BARE_SUFFIX_HEADERS = (
    ("风量斤", "ventilation_m3_min"),
    ("电量斤", "electricity_kwh"),
    ("雷管量斤", "detonators_count"),
    ("炸药量斤", "explosives_kg"),
    ("入井人员量斤", "mine_entry_persons"),
    ("企业报表产量斤", "production_t"),
    ("开采量斤", "extraction_t"),
    ("销售量斤", "sales_t"),
    ("出矿运输量斤", "transport_t"),
    ("入洗原煤量斤", "wash_feed_t"),
    ("开票吨数斤", "invoiced_quantity_t"),
)


@pytest.mark.parametrize("header,metric", _UNKNOWN_BARE_SUFFIX_HEADERS)
def test_unknown_bare_suffix_is_closed_for_all_eleven_metrics(
    header: str,
    metric: str,
) -> None:
    content = f"日期,{header}\n2026-07-01,1000\n".encode()
    inspection = inspect_five_quantity_csv(filename="未知裸单位.csv", content=content)
    assert inspection["columns"][0]["status"] == "blocked"
    assert inspection["columns"][0]["target_metric"] is None

    with pytest.raises(ImportContentError):
        import_five_quantity_bytes(
            filename="未知裸单位.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
        )
    with pytest.raises(ImportContentError):
        import_five_quantity_bytes(
            filename="未知裸单位.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
            column_mappings=[
                {
                    "source_index": 1,
                    "target_metric": metric,
                    "target_period": "daily_total",
                }
            ],
        )


_UNKNOWN_BARE_PREFIX_HEADERS = (
    ("斤风量", "ventilation_m3_min"),
    ("斤电量", "electricity_kwh"),
    ("斤雷管量", "detonators_count"),
    ("斤炸药量", "explosives_kg"),
    ("斤入井人员量", "mine_entry_persons"),
    ("斤企业报表产量", "production_t"),
    ("斤开采量", "extraction_t"),
    ("斤销售量", "sales_t"),
    ("斤出矿运输量", "transport_t"),
    ("斤入洗原煤量", "wash_feed_t"),
    ("斤开票吨数", "invoiced_quantity_t"),
)


@pytest.mark.parametrize("header,metric", _UNKNOWN_BARE_PREFIX_HEADERS)
def test_unknown_bare_prefix_is_closed_for_all_eleven_metrics(
    header: str,
    metric: str,
) -> None:
    content = f"日期,{header}\n2026-07-01,1000\n".encode()
    inspection = inspect_five_quantity_csv(filename="未知裸前缀.csv", content=content)
    assert inspection["columns"][0]["status"] == "blocked"
    assert inspection["columns"][0]["target_metric"] is None

    with pytest.raises(ImportContentError):
        import_five_quantity_bytes(
            filename="未知裸前缀.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
        )
    with pytest.raises(ImportContentError):
        import_five_quantity_bytes(
            filename="未知裸前缀.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
            column_mappings=[
                {
                    "source_index": 1,
                    "target_metric": metric,
                    "target_period": "daily_total",
                }
            ],
        )


@pytest.mark.parametrize(
    "header,targets",
    (
        ("运输量销售量", ("transport_t", "sales_t")),
        ("产量开采量", ("production_t", "extraction_t")),
        ("销售量开票量", ("sales_t", "invoiced_quantity_t")),
        ("电量风量", ("electricity_kwh", "ventilation_m3_min")),
    ),
)
def test_combined_metric_headers_never_map_or_write(
    header: str,
    targets: tuple[str, str],
) -> None:
    content = f"日期,{header}\n2026-07-01,1000\n".encode()
    inspection = inspect_five_quantity_csv(filename="组合字段.csv", content=content)
    assert inspection["columns"][0]["status"] == "blocked"
    assert inspection["columns"][0]["target_metric"] is None
    with pytest.raises(ImportContentError):
        import_five_quantity_bytes(
            filename="组合字段.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
        )
    for metric in targets:
        with pytest.raises(ImportContentError):
            import_five_quantity_bytes(
                filename="组合字段.csv",
                content=content,
                acquisition_mode="manual_import",
                identity=identity(),
                column_mappings=[
                    {
                        "source_index": 1,
                        "target_metric": metric,
                        "target_period": "daily_total",
                    }
                ],
            )


@pytest.mark.parametrize(
    "unit,status",
    (
        ("kWh", "mapped"),
        ("Wh", "blocked"),
        ("MWh", "blocked"),
        ("万kWh", "blocked"),
        ("foo", "blocked"),
    ),
)
def test_second_header_unit_row_is_merged_and_enforced(
    unit: str,
    status: str,
) -> None:
    content = f"日期,电量\n,{unit}\n2026-07-01,123\n".encode()
    inspection = inspect_five_quantity_csv(filename="单位行.csv", content=content)
    assert inspection["data_start_row"] == 3
    column = inspection["columns"][0]
    assert column["source_header"] == f"电量 / {unit}"
    assert column["status"] == status

    mapping = [
        {
            "source_index": 1,
            "target_metric": "electricity_kwh",
            "target_period": "daily_total",
        }
    ]
    if status == "blocked":
        with pytest.raises(ImportContentError):
            import_five_quantity_bytes(
                filename="单位行.csv",
                content=content,
                acquisition_mode="manual_import",
                identity=identity(),
            )
        with pytest.raises(ImportContentError):
            import_five_quantity_bytes(
                filename="单位行.csv",
                content=content,
                acquisition_mode="manual_import",
                identity=identity(),
                column_mappings=mapping,
            )
        return

    for mappings in (None, mapping):
        imported = import_five_quantity_bytes(
            filename="单位行.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
            column_mappings=mappings,
        )
        daily = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
        assert daily["electricity_kwh"]["value"] == 123


def test_generic_fire_material_is_blocked_for_auto_and_override() -> None:
    content = ("日期,火工品量\n2026-07-01,雷管:120kg;炸药:240发\n").encode()
    inspection = inspect_five_quantity_csv(filename="火工品总栏.csv", content=content)
    assert inspection["columns"][0]["status"] == "blocked"

    with pytest.raises(ImportContentError, match="必须拆为雷管和炸药"):
        import_five_quantity_bytes(
            filename="火工品总栏.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
        )
    with pytest.raises(ImportContentError, match="白名单"):
        import_five_quantity_bytes(
            filename="火工品总栏.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
            column_mappings=[
                {
                    "source_index": 1,
                    "target_metric": "fire_material",
                    "target_period": "daily_total",
                }
            ],
        )


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


def test_acknowledged_v3_submission_creates_one_signed_correction_chain(
    tmp_path: Path,
) -> None:
    repository = Repository(tmp_path / "ten-v3-correction.db")
    runtime = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    first_draft = runtime.ingest_bytes(
        filename="十量首报.csv",
        content=canonical_csv(),
        acquisition_mode="manual_import",
        actor="preparer-1",
    )["draft"]
    runtime.confirm_draft(
        first_draft["draft_id"],
        expected_revision=first_draft["revision"],
        actor_id="reviewer-1",
        confirmer_name="首报复核员",
        confirmer_role="企业复核员",
        attestation="已核对十量首报原始凭证。",
        accepted=True,
    )
    first_outbox = runtime.store.due_outbox()[0]
    first_message = first_outbox["body"]
    runtime.store.outbox_succeeded(
        first_message["message_id"],
        receipt=signed_intake_receipt(first_message),
    )
    with repository._read() as db:
        first_body_bytes = str(
            db.execute(
                "SELECT body_json FROM fq_outbox WHERE message_id=?",
                (first_message["message_id"],),
            ).fetchone()[0]
        ).encode()
    submitted = runtime.store.get_draft(first_draft["draft_id"])
    assert submitted["status"] == "submitted"

    created = runtime.create_correction_draft(
        submitted["draft_id"],
        expected_revision=submitted["revision"],
        expected_submission_revision=1,
        accepted=True,
        actor="preparer-2",
    )
    correction = created["draft"]
    assert created["created"] is True
    assert correction["submission_revision"] == 2
    assert correction["correlation_id"] == first_message["message_id"]
    assert correction["predecessor"] == {
        "message_id": first_message["message_id"],
        "payload_sha256": first_message["signature_envelope"]["payload_sha256"],
    }
    assert "human_confirmation" not in correction["payload"]

    replay = runtime.create_correction_draft(
        submitted["draft_id"],
        expected_revision=submitted["revision"],
        expected_submission_revision=1,
        accepted=True,
        actor="preparer-2",
    )
    assert replay["duplicate"] is True
    assert replay["draft"]["draft_id"] == correction["draft_id"]
    assert [event["event_type"] for event in runtime.store.audit()["events"]].count(
        "ten_quantity_correction_draft_created"
    ) == 1

    with pytest.raises(ConflictError, match="已送达"):
        runtime.create_correction_draft(
            correction["draft_id"],
            expected_revision=correction["revision"],
            expected_submission_revision=2,
            accepted=True,
            actor="preparer-2",
        )

    revised_payload = copy.deepcopy(correction["payload"])
    revised_sales = revised_payload["days"][0]["reported_quantity"]["daily_total"][
        "sales_t"
    ]
    revised_sales["value"] = 2490
    revised_sales["quality_flags"] = ["reported", "corrected"]
    correction = runtime.save_draft(
        correction["draft_id"],
        expected_revision=correction["revision"],
        payload=revised_payload,
        actor="preparer-2",
    )
    runtime.confirm_draft(
        correction["draft_id"],
        expected_revision=correction["revision"],
        actor_id="reviewer-2",
        confirmer_name="更正复核员",
        confirmer_role="企业复核员",
        attestation="已核对第 2 版更正内容及直接前序。",
        accepted=True,
    )
    second_outbox = runtime.store.due_outbox()[0]
    second_message = second_outbox["body"]
    assert second_message["revision"] == 2
    assert second_message["correlation_id"] == first_message["message_id"]
    assert second_message["causation_id"] == first_message["message_id"]
    assert second_message["predecessor"] == {
        "message_id": first_message["message_id"],
        "payload_sha256": first_message["signature_envelope"]["payload_sha256"],
    }
    for message in (first_message, second_message):
        payload_hash = hashlib.sha256(jcs_json(message["payload"]).encode()).hexdigest()
        expected_signature = hmac.new(
            identity().message_hmac_secret.encode(),
            _message_material(message, payload_hash),
            hashlib.sha256,
        ).hexdigest()
        assert hmac.compare_digest(
            expected_signature,
            message["signature_envelope"]["signature"],
        )

    with repository._read() as db:
        persisted_first = db.execute(
            "SELECT body_json FROM fq_outbox WHERE message_id=?",
            (first_message["message_id"],),
        ).fetchone()[0]
        chain_size = db.execute(
            "SELECT COUNT(*) FROM fq_drafts WHERE correlation_id=?",
            (first_message["message_id"],),
        ).fetchone()[0]
    assert str(persisted_first).encode() == first_body_bytes
    assert json.loads(persisted_first) == first_message
    assert chain_size == 2


def test_enterprise_key_rotation_verifies_old_predecessor_and_signs_r2_current(
    tmp_path: Path,
) -> None:
    old_key_id = "enterprise-key-retired-2026-07"
    old_secret = "retired-enterprise-message-secret-2026-07-abcdefghijklmnopqrstuvwxyz"
    current_key_id = "enterprise-key-current-2026-08"
    current_secret = (
        "current-enterprise-message-secret-2026-08-abcdefghijklmnopqrstuvwxyz"
    )
    old_identity = replace(
        identity(),
        key_id=old_key_id,
        regulator_key_id="regulator-key-retired-2026-07",
        message_hmac_secret=old_secret,
    )
    repository = Repository(tmp_path / "ten-v3-enterprise-key-rotation.db")
    old_runtime = FiveQuantityRuntime(
        repository,
        identity=old_identity,
        quarantine_directory=tmp_path / "quarantine-old",
    )
    first_draft = old_runtime.ingest_bytes(
        filename="十量轮换前首报.csv",
        content=canonical_csv(),
        acquisition_mode="manual_import",
        actor="preparer-old",
    )["draft"]
    old_runtime.confirm_draft(
        first_draft["draft_id"],
        expected_revision=first_draft["revision"],
        actor_id="reviewer-old",
        confirmer_name="轮换前复核员",
        confirmer_role="企业复核员",
        attestation="已核对轮换前十量首报原始凭证。",
        accepted=True,
    )
    first_message = old_runtime.store.due_outbox()[0]["body"]
    assert first_message["signature_envelope"]["key_id"] == old_key_id
    old_runtime.store.outbox_succeeded(
        first_message["message_id"],
        receipt=signed_intake_receipt(first_message, mine=old_identity),
    )
    submitted = old_runtime.store.get_draft(first_draft["draft_id"])

    rotated_identity = replace(
        old_identity,
        key_id=current_key_id,
        regulator_key_id="regulator-key-current-2026-08",
        message_hmac_secret=current_secret,
        historical_enterprise_signing_keys=(
            EnterpriseSigningVerificationKey(
                key_id=old_key_id,
                secret=old_secret,
            ),
        ),
        previous_regulator_key_id=old_identity.regulator_key_id,
        previous_message_hmac_secret=old_secret,
    )
    rotated_runtime = FiveQuantityRuntime(
        repository,
        identity=rotated_identity,
        quarantine_directory=tmp_path / "quarantine-current",
    )
    correction = rotated_runtime.create_correction_draft(
        submitted["draft_id"],
        expected_revision=submitted["revision"],
        expected_submission_revision=1,
        accepted=True,
        actor="preparer-current",
    )["draft"]
    rotated_runtime.confirm_draft(
        correction["draft_id"],
        expected_revision=correction["revision"],
        actor_id="reviewer-current",
        confirmer_name="轮换后复核员",
        confirmer_role="企业复核员",
        attestation="已核对轮换后的第 2 版更正及其旧密钥前序。",
        accepted=True,
    )
    second_message = rotated_runtime.store.due_outbox()[0]["body"]
    assert second_message["revision"] == 2
    assert second_message["predecessor"]["message_id"] == first_message["message_id"]
    assert second_message["signature_envelope"]["key_id"] == current_key_id
    second_payload_hash = hashlib.sha256(
        jcs_json(second_message["payload"]).encode()
    ).hexdigest()
    expected_current_signature = hmac.new(
        current_secret.encode(),
        _message_material(second_message, second_payload_hash),
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(
        expected_current_signature,
        second_message["signature_envelope"]["signature"],
    )
    old_key_signature = hmac.new(
        old_secret.encode(),
        _message_material(second_message, second_payload_hash),
        hashlib.sha256,
    ).hexdigest()
    assert not hmac.compare_digest(
        old_key_signature,
        second_message["signature_envelope"]["signature"],
    )


@pytest.mark.parametrize(
    "historical_keys",
    [
        (),
        (
            EnterpriseSigningVerificationKey(
                key_id="enterprise-key-retired-2026-07",
                secret=(
                    "incorrect-retired-message-secret-2026-07-"
                    "abcdefghijklmnopqrstuvwxyz"
                ),
            ),
        ),
    ],
    ids=("unknown-old-key-id", "incorrect-old-secret"),
)
def test_enterprise_key_rotation_rejects_unverifiable_v3_predecessor(
    tmp_path: Path,
    historical_keys: tuple[EnterpriseSigningVerificationKey, ...],
) -> None:
    old_key_id = "enterprise-key-retired-2026-07"
    old_secret = "retired-enterprise-message-secret-2026-07-abcdefghijklmnopqrstuvwxyz"
    old_identity = replace(
        identity(),
        key_id=old_key_id,
        regulator_key_id="regulator-key-retired-2026-07",
        message_hmac_secret=old_secret,
    )
    repository = Repository(tmp_path / "ten-v3-bad-enterprise-keyring.db")
    old_runtime = FiveQuantityRuntime(
        repository,
        identity=old_identity,
        quarantine_directory=tmp_path / "quarantine-old",
    )
    draft = old_runtime.ingest_bytes(
        filename="十量轮换前首报.csv",
        content=canonical_csv(),
        acquisition_mode="manual_import",
        actor="preparer-old",
    )["draft"]
    old_runtime.confirm_draft(
        draft["draft_id"],
        expected_revision=draft["revision"],
        actor_id="reviewer-old",
        confirmer_name="轮换前复核员",
        confirmer_role="企业复核员",
        attestation="已核对轮换前十量首报原始凭证。",
        accepted=True,
    )
    first_message = old_runtime.store.due_outbox()[0]["body"]
    old_runtime.store.outbox_succeeded(
        first_message["message_id"],
        receipt=signed_intake_receipt(first_message, mine=old_identity),
    )
    with pytest.raises(ValueError, match="签名归档投影不一致"):
        FiveQuantityRuntime(
            repository,
            identity=replace(
                old_identity,
                key_id="enterprise-key-current-2026-08",
                message_hmac_secret=(
                    "current-enterprise-message-secret-2026-08-"
                    "abcdefghijklmnopqrstuvwxyz"
                ),
                historical_enterprise_signing_keys=historical_keys,
                # A regulator inbound overlap with the same ID/secret must never
                # be reused to verify an enterprise-authored predecessor.
                previous_regulator_key_id=old_identity.regulator_key_id,
                previous_message_hmac_secret=old_secret,
            ),
            quarantine_directory=tmp_path / "quarantine-current",
        )


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
    with pytest.raises(ConflictError, match="不能升级"):
        runtime.create_correction_draft(
            legacy["draft_id"],
            expected_revision=before_revision,
            expected_submission_revision=legacy["submission_revision"],
            accepted=True,
            actor="operator-1",
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
