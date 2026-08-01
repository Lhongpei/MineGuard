from __future__ import annotations

import json
import zipfile
from io import BytesIO

import pytest
from openpyxl import Workbook

from enterprise_agent.errors import ImportContentError
from enterprise_agent.five_quantity_exchange import MineIdentity
from enterprise_agent.five_quantity_import import (
    METRICS,
    SHIFT_KEYS,
    import_five_quantity_bytes,
)


def identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-TEST-001",
        mine_name="测试煤矿",
        operator_id="operator-test-001",
        operator_name="测试煤业有限公司",
        system_id="agent-mine-test-001",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-key-current",
        regulator_key_id="regulator-key-current",
        message_hmac_secret="current-message-secret-abcdefghijklmnopqrstuvwxyz",
        timezone="Asia/Shanghai",
        capacity_band="medium",
        mining_method="underground",
        shift_system="three-shift-eight-hour",
        coal_type="bituminous",
        operating_regime="normal-production",
    )


def csv_bytes() -> bytes:
    return (
        b"date,daily_ventilation_m3_min,daily_mine_entry_persons,"
        b"daily_electricity_kwh,daily_detonators_count,"
        b"daily_explosives_kg,daily_production_t,zero_production_t\n"
        b"2026-07-01,4800,320,96000,120,240,2600,850\n"
        b"2026-07-02,4900,322,97000,121,242,,860\n"
    )


def test_csv_normalisation_never_invents_missing_values_or_trust_tiers() -> None:
    imported = import_five_quantity_bytes(
        filename="五量.csv",
        content=csv_bytes(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    payload = imported["payload"]
    assert payload["mine"] == identity().mine
    assert payload["reporting_month"] == "2026-07"
    assert len(payload["days"]) == 2
    assert (
        payload["days"][1]["reported_quantity"]["daily_total"]["production_t"]["value"]
        is None
    )
    assert payload["days"][1]["reported_quantity"]["daily_total"]["production_t"][
        "quality_flags"
    ] == ["missing"]
    assert (
        payload["days"][0]["reported_quantity"]["shifts"]["zero_shift"]["measurements"][
            "production_t"
        ]["value"]
        == 850
    )
    for source in payload["sources"]:
        assert source["acquisition_mode"] == "manual_import"
        assert not {"trust_level", "trust_score", "reliability_weight"} & set(source)
    for day in payload["days"]:
        for shift in SHIFT_KEYS:
            measurements = day["reported_quantity"]["shifts"][shift]["measurements"]
            assert set(measurements) == set(METRICS)


def test_preferred_chinese_five_quantity_header_keeps_first_and_only_day() -> None:
    content = (
        "日期,风量,电量,雷管,炸药,入井人员量,产量\n"
        "2026-07-01,4800,96000,120,240,320,2600\n"
    ).encode()
    imported = import_five_quantity_bytes(
        filename="中文五量.csv",
        content=content,
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    assert [item["date"] for item in imported["payload"]["days"]] == [
        "2026-07-01"
    ]
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert {metric: item["value"] for metric, item in values.items()} == {
        "ventilation_m3_min": 4800,
        "electricity_kwh": 96000,
        "detonators_count": 120,
        "explosives_kg": 240,
        "mine_entry_persons": 320,
        "production_t": 2600,
    }


def test_separate_columns_accept_unambiguous_business_unit_suffixes() -> None:
    imported = import_five_quantity_bytes(
        filename="带单位五量.csv",
        content=(
            "日期,风量,电量,雷管,炸药,入井人员量,产量\n"
            "2026-07-01,4800m3/min,96000kWh,120发,240kg,320人次,2600吨\n"
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["ventilation_m3_min"]["value"] == 4800
    assert values["electricity_kwh"]["value"] == 96000
    assert values["detonators_count"]["value"] == 120
    assert values["explosives_kg"]["value"] == 240
    assert values["mine_entry_persons"]["value"] == 320
    assert values["production_t"]["value"] == 2600


def test_legacy_labor_header_is_accepted_but_output_is_canonical() -> None:
    imported = import_five_quantity_bytes(
        filename="旧模板.csv",
        content=(
            "日期,风量,电量,雷管,炸药,用工量,产量\n"
            "2026-07-01,4800,96000,120,240,320,2600\n"
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert "labor_persons" not in values
    assert values["mine_entry_persons"]["value"] == 320
    assert any(
        item["kind"] == "legacy_mine_entry_alias"
        for item in imported["suggestions"]
    )


def test_generic_numeric_fire_material_is_missing_with_review_warning() -> None:
    imported = import_five_quantity_bytes(
        filename="火工品总栏.csv",
        content=(
            "日期,风量,电量,火工品量,入井人数,产量\n"
            "2026-07-01,4800,96000,240,320,2600\n"
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["detonators_count"]["value"] is None
    assert values["explosives_kg"]["value"] is None
    assert any(
        item["kind"] == "ambiguous_fire_material_value"
        and "无法判断" in item["reason"]
        for item in imported["suggestions"]
    )


def test_generic_fire_material_with_explicit_children_is_parsed() -> None:
    imported = import_five_quantity_bytes(
        filename="火工品明细.csv",
        content=(
            "日期,火工品量\n"
            '2026-07-01,"电子雷管:120发、乳化炸药:240kg"\n'
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["detonators_count"]["value"] == 120
    assert values["explosives_kg"]["value"] == 240
    assert not any(
        item["kind"] == "ambiguous_fire_material_value"
        for item in imported["suggestions"]
    )


def test_duplicate_fire_child_columns_do_not_overwrite_or_guess_total() -> None:
    imported = import_five_quantity_bytes(
        filename="重复雷管列.csv",
        content=(
            "日期,工业雷管,电子雷管,炸药\n"
            "2026-07-01,100,20,240\n"
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["detonators_count"]["value"] is None
    assert values["explosives_kg"]["value"] == 240
    assert any(
        item["kind"] == "duplicate_column_mapping"
        and item["metric"] == "detonators_count"
        for item in imported["suggestions"]
    )


def test_unapproved_fire_component_is_not_folded_into_known_children() -> None:
    imported = import_five_quantity_bytes(
        filename="其他火工品.csv",
        content=(
            "日期,雷管,炸药,导爆索,产量\n"
            "2026-07-01,120,240,30,2600\n"
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["detonators_count"]["value"] == 120
    assert values["explosives_kg"]["value"] == 240
    assert any(
        item["kind"] == "unsupported_fire_material_component"
        and "导爆索" in item["reason"]
        for item in imported["suggestions"]
    )


def test_two_level_fire_material_header_maps_children_without_overwrite() -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["日期", "风量", "电量", "火工品量", None, "入井人次", "产量"])
    sheet.append([None, "日合计", "日合计", "雷管", "炸药", "日合计", "日合计"])
    sheet.append(["2026-07-01", 4800, 96000, 120, 240, 320, 2600])
    buffer = BytesIO()
    workbook.save(buffer)
    imported = import_five_quantity_bytes(
        filename="二层表头.xlsx",
        content=buffer.getvalue(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["detonators_count"]["value"] == 120
    assert values["explosives_kg"]["value"] == 240
    assert values["mine_entry_persons"]["value"] == 320


def test_xlsx_bytes_are_accepted_with_et_extension() -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["date", "production_t", "electricity_kwh"])
    sheet.append(["2026-07-01", 2600, 96000])
    buffer = BytesIO()
    workbook.save(buffer)
    imported = import_five_quantity_bytes(
        filename="设备导出.et",
        content=buffer.getvalue(),
        acquisition_mode="direct_collection",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    assert (
        imported["payload"]["days"][0]["reported_quantity"]["daily_total"][
            "production_t"
        ]["value"]
        == 2600
    )
    assert imported["payload"]["sources"][0]["acquisition_mode"] == (
        "direct_collection"
    )


def test_structured_json_rebuilds_identity_and_provenance() -> None:
    base = import_five_quantity_bytes(
        filename="base.csv",
        content=csv_bytes(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )["payload"]
    hostile = {
        **base,
        "mine": {"mine_id": "OTHER-MINE"},
        "sources": [{"source_id": "forged", "trust_level": "high"}],
        "human_confirmation": {"confirmed": True},
    }
    imported = import_five_quantity_bytes(
        filename="structured.json",
        content=json.dumps(hostile, ensure_ascii=False).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )["payload"]
    assert imported["mine"] == identity().mine
    assert "human_confirmation" not in imported
    assert len(imported["sources"]) == 1
    assert imported["sources"][0]["source_id"].startswith("SRC-")
    assert "trust_level" not in imported["sources"][0]


def test_structured_json_legacy_person_key_is_canonicalised() -> None:
    base = import_five_quantity_bytes(
        filename="base.csv",
        content=csv_bytes(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )["payload"]
    for day in base["days"]:
        measurement_sets = [day["reported_quantity"]["daily_total"]] + [
            day["reported_quantity"]["shifts"][shift]["measurements"]
            for shift in SHIFT_KEYS
        ]
        for measurements in measurement_sets:
            legacy = measurements.pop("mine_entry_persons")
            legacy["metric_code"] = "labor_persons"
            measurements["labor_persons"] = legacy
    imported = import_five_quantity_bytes(
        filename="legacy.json",
        content=json.dumps(base, ensure_ascii=False).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )["payload"]
    for day in imported["days"]:
        assert "labor_persons" not in day["reported_quantity"]["daily_total"]
        assert (
            day["reported_quantity"]["daily_total"]["mine_entry_persons"][
                "metric_code"
            ]
            == "mine_entry_persons"
        )


def test_jsonl_accepts_one_day_per_line() -> None:
    payload = import_five_quantity_bytes(
        filename="base.csv",
        content=csv_bytes(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )["payload"]
    content = "\n".join(
        json.dumps(day, ensure_ascii=False) for day in payload["days"]
    ).encode()
    imported = import_five_quantity_bytes(
        filename="device.jsonl",
        content=content,
        acquisition_mode="direct_collection",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    assert len(imported["payload"]["days"]) == 2
    assert imported["payload"]["sources"][0]["media_type"] == ("application/x-ndjson")


def test_zip_path_traversal_is_rejected_before_workbook_parsing() -> None:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../outside.xml", "forbidden")
    with pytest.raises(ImportContentError, match="路径|压缩"):
        import_five_quantity_bytes(
            filename="unsafe.xlsx",
            content=buffer.getvalue(),
            acquisition_mode="manual_import",
            identity=identity(),
        )
