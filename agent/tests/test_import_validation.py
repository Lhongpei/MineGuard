from __future__ import annotations

import json
from hashlib import sha256

import pytest
from conftest import ensure_event_snapshot, gateway_sign_observation

from enterprise_agent.errors import ImportContentError
from enterprise_agent.importers import import_text


def test_json_import_preserves_field_level_provenance(service, values) -> None:
    draft = service.create_draft(actor="operator-1")
    result = service.import_into_draft(
        draft["draft_id"],
        format_name="json",
        content=json.dumps(values, ensure_ascii=False),
        source_name="production.json",
        actor="operator-1",
        expected_revision=1,
    )
    imported = result["draft"]
    provenance = imported["field_provenance"]
    assert provenance["/enterprise_id"][0]["source_kind"] == "json"
    assert provenance["/observations/0/value"][0]["locator"].endswith(".value")
    # Defaulted signing fields still have provenance for contract completeness.
    assert provenance["/observations/0/reset_before"]
    imported = ensure_event_snapshot(service, imported)
    assert service.validate(draft["draft_id"])["valid"] is True


def test_import_digest_matches_original_file_bytes_and_audit(service) -> None:
    draft = service.create_draft(actor="operator-1")
    content = '\ufeff{"企业编号":"enterprise-1"}'
    result = service.import_into_draft(
        draft["draft_id"],
        format_name="json",
        content=content,
        source_name="bom.json",
        actor="operator-1",
        expected_revision=1,
    )
    expected = sha256(content.encode("utf-8")).hexdigest()
    record = result["draft"]["field_provenance"]["/enterprise_id"][0]
    event = service.repository.audit_events(draft["draft_id"])[-1]
    assert record["content_sha256"] == expected
    assert event["details"]["content_sha256"] == expected


def test_import_metadata_is_validated_returned_and_audited(service) -> None:
    draft = service.create_draft(actor="operator-1")
    result = service.import_into_draft(
        draft["draft_id"],
        format_name="json",
        content='{"企业编号":"enterprise-1"}',
        source_name="display-name.json",
        source_system="ERP 生产系统",
        original_filename="export-20260727.json",
        truth_statement=True,
        actor="operator-1",
        expected_revision=1,
    )
    metadata = result["import"]
    assert metadata["source_system"] == "ERP 生产系统"
    assert metadata["original_filename"] == "export-20260727.json"
    assert metadata["truth_statement_acknowledged"] is True
    source_manifest = result["draft"]["imports"]
    assert len(source_manifest) == 1
    assert source_manifest[0]["name"] == "display-name.json"
    assert source_manifest[0]["filename"] == "export-20260727.json"
    assert source_manifest[0]["source_system"] == "ERP 生产系统"
    assert source_manifest[0]["truth_statement"] is True
    assert source_manifest[0]["content_sha256"] == sha256(
        '{"企业编号":"enterprise-1"}'.encode()
    ).hexdigest()
    details = service.repository.audit_events(draft["draft_id"])[-1]["details"]
    assert details["source_system"] == "ERP 生产系统"
    assert details["original_filename"] == "export-20260727.json"
    assert details["truth_statement_acknowledged"] is True

    with pytest.raises(ImportContentError, match="真实性"):
        service.import_into_draft(
            draft["draft_id"],
            format_name="json",
            content='{"企业编号":"enterprise-1"}',
            source_name="display-name.json",
            truth_statement=False,
            actor="operator-1",
            expected_revision=2,
        )


def test_utf8_bom_json_and_csv_are_imported_once_only() -> None:
    json_result = import_text("json", '\ufeff{"企业编号":"enterprise-1"}')
    assert json_result["patch"]["enterprise_id"] == "enterprise-1"
    csv_result = import_text("csv", "\ufeff企业编号\nenterprise-1\n")
    assert csv_result["patch"]["enterprise_id"] == "enterprise-1"
    with pytest.raises(ImportContentError, match="JSON 格式错误"):
        import_text("json", '\ufeff\ufeff{"企业编号":"enterprise-1"}')


def test_chinese_json_container_locators_match_original_paths(service) -> None:
    draft = service.create_draft(actor="operator-1")
    result = service.import_into_draft(
        draft["draft_id"],
        format_name="json",
        content=json.dumps(
            {
                "企业编号": "enterprise-1",
                "工况信息": {"工况": "NORMAL"},
                "观测": [
                    {
                        "观测编号": "obs-1",
                        "数值": 12.5,
                    }
                ],
            },
            ensure_ascii=False,
        ),
        source_name="中文导出.json",
        actor="operator-1",
        expected_revision=1,
    )
    provenance = result["draft"]["field_provenance"]
    assert provenance["/operational_context/regime_code"][0]["locator"] == (
        "$.工况信息.工况"
    )
    assert provenance["/observations/0/value"][0]["locator"] == (
        "$.观测[0].数值"
    )


@pytest.mark.parametrize(
    "content",
    [
        '{"企业编号":"one","enterprise_id":"two"}',
        '{"工况信息":{"工况":"A","regime_code":"B"}}',
        '{"观测":[{"数值":1,"value":2}]}',
        '{"operational_context":{},"工况信息":{}}',
        '{"observations":[],"观测":[]}',
    ],
)
def test_json_rejects_semantically_duplicate_aliases(content: str) -> None:
    with pytest.raises(ImportContentError, match="含义重复"):
        import_text("json", content)


def test_csv_alias_import_and_unmapped_columns(service) -> None:
    draft = service.create_draft(actor="operator-1")
    signed = gateway_sign_observation(
        {
            "source_id": "mine-001-main-transport",
            "observation_id": "obs-1",
            "metric_code": "coal.main_transport_t",
            "value": 1000.25,
            "unit": "t",
            "observed_at": "2026-07-27T08:00:00Z",
            "received_at": "2026-07-27T08:00:05Z",
            "interval_start": None,
            "interval_end": None,
            "reset_before": False,
            "sequence_no": 1,
            "revision": 0,
        }
    )
    csv_text = (
        "企业编号,企业名称,统一社会信用代码,矿井编号,矿井名称,"
        "统计开始,统计结束,配置编号,配置版本,工况,班次,季节,"
        "是否检修,来源编号,观测编号,观测值,单位,观测时间,"
        "接收时间,序号,修订号,payload_sha256,signature,备注列\n"
        "enterprise-001,示例能源有限公司,91110000ABCDEFGH1X,"
        "mine-001,示例一号矿,2026-07-27T00:00:00Z,"
        "2026-07-27T08:00:00Z,coal-balance-default,2026.07,"
        "NORMAL_PRODUCTION,A,SUMMER,否,mine-001-main-transport,"
        "obs-1,1000.25,t,2026-07-27T08:00:00Z,"
        "2026-07-27T08:00:05Z,1,0,"
        f"{signed['payload_sha256']},{signed['signature']},ignored\n"
    )
    result = service.import_into_draft(
        draft["draft_id"],
        format_name="csv",
        content=csv_text,
        source_name="production.csv",
        actor="operator-1",
    )
    assert result["draft"]["observations"][0]["value"] == 1000.25
    assert result["draft"]["observations"][0]["signature"] == signed["signature"]
    assert result["draft"]["field_provenance"]["/observations/0/signature"]
    assert result["import"]["unmapped_fields"] == ["备注列"]


def test_csv_observations_without_gateway_credentials_are_rejected(service) -> None:
    draft = service.create_draft(actor="operator-1")
    with pytest.raises(ImportContentError, match="填报智能体不会代签"):
        service.import_into_draft(
            draft["draft_id"],
            format_name="csv",
            content=(
                "来源编号,观测编号,观测值,单位,观测时间,接收时间,序号,修订号\n"
                "source-1,obs-1,12.5,t,2026-07-27T08:00:00Z,"
                "2026-07-27T08:00:01Z,1,0\n"
            ),
            source_name="manual.csv",
            actor="operator-1",
        )


def test_unknown_import_format_is_rejected() -> None:
    with pytest.raises(ImportContentError):
        import_text("xlsx", "not-empty")


@pytest.mark.parametrize(
    "source_name",
    [
        "x" * 256,
        "../secret.json",
        "folder/report.json",
        "bad\x00name.json",
        "",
        123,
    ],
)
def test_import_source_name_is_bounded_display_filename(source_name) -> None:
    with pytest.raises(ImportContentError, match="source_name"):
        import_text(
            "json",
            '{"enterprise_id":"enterprise-1"}',
            source_name=source_name,  # type: ignore[arg-type]
        )


def test_csv_rejects_duplicate_semantic_headers_and_handles_missing_cells() -> None:
    with pytest.raises(ImportContentError, match="冲突"):
        import_text(
            "csv",
            "企业编号,enterprise_id\nenterprise-1,enterprise-2\n",
            source_name="duplicate.csv",
        )
    result = import_text(
        "csv",
        "企业编号,企业名称\nenterprise-1\n",
        source_name="short-row.csv",
    )
    assert result["patch"]["enterprise_id"] == "enterprise-1"


def test_questions_are_deterministic_and_actionable(service) -> None:
    draft = service.create_draft(actor="operator-1")
    first = service.questions(draft["draft_id"])
    second = service.questions(draft["draft_id"])
    assert first == second
    assert any(item["path"] == "/mine_id" for item in first)
    assert all(item["question"] for item in first)


def test_business_precheck_warns_without_claiming_regulatory_result(
    service, values
) -> None:
    values["observations"].append(
        gateway_sign_observation(
            {
            **values["observations"][0],
            "source_id": "production-report",
            "observation_id": "production-1",
            "metric_code": "coal.production_t",
            "value": 2000,
            }
        )
    )
    draft = service.create_draft(values, actor="operator-1")
    ensure_event_snapshot(service, draft)
    result = service.validate(draft["draft_id"])
    assert result["valid"] is True
    check = next(
        item
        for item in result["business_checks"]
        if item["code"] == "production_transport_gap"
    )
    assert check["status"] == "warning"
    assert "不替代监管平台核验" in check["message"]
