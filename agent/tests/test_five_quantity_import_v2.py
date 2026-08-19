from __future__ import annotations

import json
import zipfile
from io import BytesIO

import pytest
from openpyxl import Workbook

from enterprise_agent.errors import ImportContentError
from enterprise_agent.five_quantity_exchange import MineIdentity
from enterprise_agent.five_quantity_import import (
    SHIFT_KEYS,
    import_five_quantity_bytes,
    inspect_five_quantity_csv,
)
from enterprise_agent.quantity_catalog import LEGACY_V2_METRICS, METRICS


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
    assert payload["period_start"] == "2026-07-01"
    assert payload["period_end"] == "2026-07-02"
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


def test_production_batch_can_cross_months_and_skip_dates() -> None:
    imported = import_five_quantity_bytes(
        filename="跨月生产数据.csv",
        content=(
            b"date,daily_production_t\n"
            b"2026-07-31,100\n"
            b"2026-08-02,120\n"
        ),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-03T00:00:00Z",
    )

    payload = imported["payload"]
    assert payload["period_start"] == "2026-07-31"
    assert payload["period_end"] == "2026-08-02"
    assert [day["date"] for day in payload["days"]] == [
        "2026-07-31",
        "2026-08-02",
    ]
    assert "reporting_month" not in payload


def test_preferred_chinese_five_quantity_header_keeps_first_and_only_day() -> None:
    content = (
        "日期,风量,电量,雷管,炸药,入井人员量,企业报表产量\n"
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
    assert {metric: values[metric]["value"] for metric in LEGACY_V2_METRICS} == {
        "ventilation_m3_min": 4800,
        "electricity_kwh": 96000,
        "detonators_count": 120,
        "explosives_kg": 240,
        "mine_entry_persons": 320,
        "production_t": 2600,
    }
    assert all(
        values[metric]["value"] is None
        for metric in METRICS
        if metric not in LEGACY_V2_METRICS
    )


def test_csv_accepts_gb18030_and_semicolon_delimiter() -> None:
    imported = import_five_quantity_bytes(
        filename="业务系统导出.csv",
        content=(
            "日期;风量(m3/min);电量(kWh);雷管(发);炸药(kg);入井人员量(人次);企业报表产量(t)\n"
            "2026-07-01;4800;96000;120;240;320;2600\n"
        ).encode("gb18030"),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["ventilation_m3_min"]["value"] == 4800
    assert values["production_t"]["value"] == 2600


def test_complete_three_shift_csv_template_maps_every_scope() -> None:
    scopes = ("日合计", "零点班", "八点班", "四点班")
    metrics = (
        "风量(m3/min)",
        "电量(kWh)",
        "雷管(发)",
        "炸药(kg)",
        "入井人员量(人次)",
        "企业报表产量(t)",
    )
    header = ["日期"] + [
        f"{scope}_{metric}" for scope in scopes for metric in metrics
    ]
    values = ["2026-07-01"] + [str(index) for index in range(1, 25)]
    imported = import_five_quantity_bytes(
        filename="五量填报标准模板.csv",
        content=(",".join(header) + "\n" + ",".join(values) + "\n").encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    reported = imported["payload"]["days"][0]["reported_quantity"]
    assert [
        reported["daily_total"][metric]["value"]
        for metric in LEGACY_V2_METRICS
    ] == [
        1,
        2,
        3,
        4,
        5,
        6,
    ]
    assert [
        reported["shifts"]["zero_shift"]["measurements"][metric]["value"]
        for metric in LEGACY_V2_METRICS
    ] == [7, 8, 9, 10, 11, 12]
    assert [
        reported["shifts"]["eight_shift"]["measurements"][metric]["value"]
        for metric in LEGACY_V2_METRICS
    ] == [13, 14, 15, 16, 17, 18]
    assert [
        reported["shifts"]["four_shift"]["measurements"][metric]["value"]
        for metric in LEGACY_V2_METRICS
    ] == [19, 20, 21, 22, 23, 24]
    for metric in METRICS:
        if metric in LEGACY_V2_METRICS:
            continue
        assert reported["daily_total"][metric]["value"] is None


def test_csv_reports_unmapped_and_unsafe_numeric_cells_without_executing() -> None:
    imported = import_five_quantity_bytes(
        filename="待核对.csv",
        content=(
            '日期,企业报表产量,电量,企业备注\n'
            '2026-07-01,=1+1,"1,2",不得自动采用\n'
        ).encode(),
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
    )
    values = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert values["production_t"]["value"] is None
    assert values["electricity_kwh"]["value"] is None
    assert "source_format_warning" in values["production_t"]["quality_flags"]
    assert "source_format_warning" in values["electricity_kwh"]["quality_flags"]
    kinds = {item["kind"] for item in imported["suggestions"]}
    assert {"formula_like_cell", "invalid_numeric_cell", "unmapped_column"} <= kinds


def test_csv_rejects_malformed_quotes_nul_and_excessive_cells() -> None:
    for content, message in (
        (b'date,production_t\n"2026-07-01,2600\n', "CSV"),
        (b"date,production_t\n2026-07-01,26\x000\n", "NUL"),
    ):
        with pytest.raises(ImportContentError, match=message):
            import_five_quantity_bytes(
                filename="unsafe.csv",
                content=content,
                acquisition_mode="manual_import",
                identity=identity(),
            )

    oversized_row = ",".join(["x"] * 256)
    excessive_cells = (oversized_row + "\n") * 1954
    with pytest.raises(ImportContentError, match="单元格"):
        import_five_quantity_bytes(
            filename="too-many-cells.csv",
            content=excessive_cells.encode(),
            acquisition_mode="manual_import",
            identity=identity(),
        )


def test_csv_preview_masks_values_and_infers_an_opaque_date_header() -> None:
    content = (
        "业务日,原煤完成量,当日总电耗,内部备注\n"
        "2026-07-01,2600,96000,仅内部可见\n"
        "2026-07-02,2610,97000,继续生产\n"
    ).encode()
    preview = inspect_five_quantity_csv(filename="ERP导出.csv", content=content)

    assert preview["date_column"] == {
        "source_index": 0,
        "source_header": "业务日",
        "inferred": True,
        "confidence": 0.85,
    }
    assert preview["valid_day_count"] == 2
    assert preview["detected_months"] == ["2026-07"]
    assert preview["encoding"] == "utf-8"
    assert preview["delimiter"] == ","
    assert preview["columns"][0]["sample_types"] == {"integer": 2}
    serialized = json.dumps(preview, ensure_ascii=False)
    assert "2600" not in serialized
    assert "仅内部可见" not in serialized


def test_headerless_csv_fails_closed_instead_of_exposing_first_data_row() -> None:
    content = (
        b"2026-08-01,2600,96000\n"
        b"2026-08-02,2700,97000\n"
    )

    with pytest.raises(ImportContentError, match="日期列"):
        inspect_five_quantity_csv(filename="无表头.csv", content=content)
    with pytest.raises(ImportContentError, match="日期列"):
        import_five_quantity_bytes(
            filename="无表头.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
        )


def test_headerless_unit_values_cannot_masquerade_as_safe_headers() -> None:
    content = (
        b"08/01/2026,2600t,96000kWh\n"
        b"2026-08-02,2700t,97000kWh\n"
        b"2026-08-03,2800t,98000kWh\n"
    )

    with pytest.raises(ImportContentError, match="日期列"):
        inspect_five_quantity_csv(filename="伪表头.csv", content=content)


@pytest.mark.parametrize(
    "content",
    (
        b"date,2600,SECRET-RAW-VALUE\n2026-08-01,2700,other\n",
        b"date,=HYPERLINK('https://invalid'),production_t\n"
        b"2026-08-01,2700,2800\n",
    ),
)
def test_declared_date_header_rejects_observation_or_formula_cells(
    content: bytes,
) -> None:
    with pytest.raises(ImportContentError, match="日期列"):
        inspect_five_quantity_csv(filename="伪造显式表头.csv", content=content)


@pytest.mark.parametrize("detail", ("产量,2600", "产量,=CMD()"))
def test_multilevel_header_rejects_observation_or_formula_detail(
    detail: str,
) -> None:
    content = (
        "date,业务字段,内部备注\n"
        f",{detail}\n"
        "2026-08-01,2700,SECRET\n"
    ).encode()

    with pytest.raises(ImportContentError, match="表头明细行"):
        inspect_five_quantity_csv(filename="伪造多层表头.csv", content=content)


def test_opaque_date_inference_accepts_real_erp_field_codes() -> None:
    preview = inspect_five_quantity_csv(
        filename="ERP字段码.csv",
        content=(
            "业务日,A17,ERP_COL_01,风量(m3/min)\n"
            "2026-08-01,2600,96000,4800\n"
            "2026-08-02,2700,97000,4900\n"
        ).encode(),
    )

    assert preview["date_column"]["inferred"] is True
    assert [item["source_header"] for item in preview["columns"]] == [
        "A17",
        "ERP_COL_01",
        "风量(m3/min)",
    ]


def test_reviewed_csv_mapping_materializes_values_without_model_editing() -> None:
    content = (
        "业务日,原煤完成量,当日总电耗,内部备注\n"
        "2026-07-01,2600,96000,不得写入报表\n"
    ).encode()
    imported = import_five_quantity_bytes(
        filename="ERP导出.csv",
        content=content,
        acquisition_mode="manual_import",
        identity=identity(),
        captured_at="2026-08-01T00:00:00Z",
        column_mappings=[
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
        model_assistance_used=True,
        model_output_sha256="a" * 64,
    )

    daily = imported["payload"]["days"][0]["reported_quantity"]["daily_total"]
    assert daily["production_t"]["value"] == 2600
    assert daily["electricity_kwh"]["value"] == 96000
    assert imported["payload"]["agent_processing"]["model_assistance_used"] is True
    assert any(
        item["kind"] == "explicitly_unmapped_column"
        and item["source_column"] == 3
        for item in imported["suggestions"]
    )


def test_reviewed_csv_mapping_rejects_duplicate_or_unknown_targets() -> None:
    content = "日期,A,B\n2026-07-01,1,2\n".encode()
    invalid_mappings = (
        [
            {
                "source_index": 1,
                "target_metric": "production_t",
                "target_period": "daily_total",
            },
            {
                "source_index": 2,
                "target_metric": "production_t",
                "target_period": "daily_total",
            },
        ],
        [
            {
                "source_index": 1,
                "target_metric": "arbitrary_python_expression",
                "target_period": "daily_total",
            }
        ],
    )
    for mappings in invalid_mappings:
        with pytest.raises(ImportContentError, match="同一规范字段|白名单"):
            import_five_quantity_bytes(
                filename="unsafe.csv",
                content=content,
                acquisition_mode="manual_import",
                identity=identity(),
                column_mappings=mappings,
            )


def test_csv_mapping_never_silently_treats_incompatible_units_as_canonical() -> None:
    content = "日期,企业报表产量(kg),风量(m3/s)\n2026-07-01,2600000,80\n".encode()
    preview = inspect_five_quantity_csv(filename="wrong-units.csv", content=content)
    assert {item["status"] for item in preview["columns"]} == {"blocked"}
    assert all("不会静默换算" in item["reason"] for item in preview["columns"])

    with pytest.raises(ImportContentError, match="不会静默换算"):
        import_five_quantity_bytes(
            filename="wrong-units.csv",
            content=content,
            acquisition_mode="manual_import",
            identity=identity(),
            column_mappings=[
                {
                    "source_index": 1,
                    "target_metric": "production_t",
                    "target_period": "daily_total",
                },
                {
                    "source_index": 2,
                    "target_metric": "ventilation_m3_min",
                    "target_period": "daily_total",
                },
            ],
        )


def test_separate_columns_accept_unambiguous_business_unit_suffixes() -> None:
    imported = import_five_quantity_bytes(
        filename="带单位五量.csv",
        content=(
            "日期,风量,电量,雷管,炸药,入井人员量,企业报表产量\n"
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


def test_generic_fire_material_is_never_mapped_into_v3_atomic_fields() -> None:
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
        item["kind"] == "generic_fire_material_requires_atomic_columns"
        and "必须拆" in item["reason"]
        for item in imported["suggestions"]
    )


def test_generic_fire_material_with_embedded_children_is_rejected() -> None:
    with pytest.raises(ImportContentError, match="必须拆为雷管和炸药"):
        import_five_quantity_bytes(
            filename="火工品明细.csv",
            content=(
                "日期,火工品量\n"
                '2026-07-01,"电子雷管:120发、乳化炸药:240kg"\n'
            ).encode(),
            acquisition_mode="manual_import",
            identity=identity(),
            captured_at="2026-08-01T00:00:00Z",
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
