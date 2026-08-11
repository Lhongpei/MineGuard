from __future__ import annotations

import base64
import http.client
import json
import threading
from pathlib import Path
from typing import Any
from uuid import uuid4

from enterprise_agent.auth import AuthManager, UserAccount, hash_password
from enterprise_agent.five_quantity_exchange import MineIdentity, sign_message
from enterprise_agent.five_quantity_runtime import FiveQuantityRuntime
from enterprise_agent.http_api import EnterpriseAgentHTTPServer
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.util import utc_text

ROOT = Path(__file__).resolve().parents[1]


def identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-HTTP-001",
        mine_name="HTTP 测试煤矿",
        operator_id="operator-http-001",
        operator_name="HTTP 测试煤业有限公司",
        system_id="agent-mine-http-001",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-key-http",
        regulator_key_id="regulator-key-v2",
        message_hmac_secret="http-message-secret-abcdefghijklmnopqrstuvwxyz",
    )


def signed_intake_receipt(submission: dict[str, Any]) -> dict[str, Any]:
    mine = identity()
    timestamp = utc_text()
    receipt = {
        "contract_version": "intake-receipt-v2",
        "message_type": "intake_receipt",
        "message_id": str(uuid4()),
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


def request_json(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    encoded = json.dumps(body).encode() if body is not None else None
    request_headers = {"Content-Type": "application/json"} if encoded else {}
    request_headers.update(headers or {})
    connection.request(method, path, body=encoded, headers=request_headers)
    response = connection.getresponse()
    raw = response.read()
    return response.status, json.loads(raw) if raw else {}


def test_enterprise_v2_http_import_review_confirm_and_audit(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "agent.db")
    runtime = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    service = EnterpriseAgentService(repository, five_quantity_runtime=runtime)
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,
        web_root=ROOT / "web",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=5
    )
    try:
        status, runtime_status = request_json(connection, "GET", "/api/v2/status")
        assert status == 200
        assert runtime_status["mine_id"] == "MINE-HTTP-001"
        assert runtime_status["acquisition_trust_tiering"] is False

        csv = (
            b"date,ventilation_m3_min,mine_entry_persons,electricity_kwh,"
            b"detonators_count,explosives_kg,production_t\n"
            b"2026-07-01,4800,320,96000,120,240,2600\n"
        )
        status, imported = request_json(
            connection,
            "POST",
            "/api/v2/imports",
            {
                "filename": "july.csv",
                "content_base64": base64.b64encode(csv).decode(),
            },
        )
        assert status == 201
        draft_id = imported["draft_id"]
        assert imported["draft"]["payload"]["sources"][0]["acquisition_mode"] == (
            "manual_import"
        )

        status, drafts = request_json(connection, "GET", "/api/v2/drafts")
        assert status == 200
        draft = drafts["items"][0]
        assert draft["draft_id"] == draft_id
        status, confirmed = request_json(
            connection,
            "POST",
            f"/api/v2/drafts/{draft_id}/confirm",
            {
                "expected_revision": draft["revision"],
                "confirmer_name": "本机测试员",
                "confirmer_role": "企业填报员",
                "attestation": "本人已逐项核对原始日报与三个班次记录。",
                "accepted": True,
            },
        )
        assert status == 202
        assert confirmed["status"] == "queued"

        status, error = request_json(
            connection,
            "DELETE",
            f"/api/v2/drafts/{draft_id}",
            {
                "expected_revision": confirmed["revision"],
                "reason": "不能放弃已确认草稿",
            },
        )
        assert status == 409
        assert "不能放弃" in error["error"]["message"]

        status, audit = request_json(connection, "GET", "/api/v2/audit")
        assert status == 200
        assert audit["valid"] is True
        assert [event["event_type"] for event in audit["events"]] == [
            "five_quantity_imported",
            "five_quantity_confirmed_and_queued",
        ]

        outbound = runtime.store.due_outbox()[0]
        runtime.store.outbox_succeeded(
            outbound["message_id"],
            receipt=signed_intake_receipt(outbound["body"]),
        )
        submitted = runtime.store.get_draft(draft_id)
        status, correction_result = request_json(
            connection,
            "POST",
            f"/api/v2/drafts/{draft_id}/correction",
            {
                "expected_revision": submitted["revision"],
                "expected_submission_revision": submitted[
                    "submission_revision"
                ],
                "accepted": True,
            },
        )
        assert status == 201
        assert correction_result["draft"]["submission_revision"] == 2
        assert correction_result["draft"]["predecessor"]["message_id"] == (
            outbound["message_id"]
        )
        status, correction_replay = request_json(
            connection,
            "POST",
            f"/api/v2/drafts/{draft_id}/correction",
            {
                "expected_revision": submitted["revision"],
                "expected_submission_revision": 1,
                "accepted": True,
            },
        )
        assert status == 200
        assert correction_replay["duplicate"] is True
        assert correction_replay["draft"]["draft_id"] == correction_result[
            "draft"
        ]["draft_id"]

        second_csv = csv.replace(b"2026-07-01", b"2026-07-02")
        status, second_import = request_json(
            connection,
            "POST",
            "/api/v2/imports",
            {
                "filename": "july-correction.csv",
                "content_base64": base64.b64encode(second_csv).decode(),
            },
        )
        assert status == 201
        second_draft = second_import["draft"]
        status, duplicate_month = request_json(
            connection,
            "POST",
            f"/api/v2/drafts/{second_draft['draft_id']}/confirm",
            {
                "expected_revision": second_draft["revision"],
                "confirmer_name": "本机测试员",
                "confirmer_role": "企业填报员",
                "attestation": "同月第二份首报必须得到清晰冲突提示。",
                "accepted": True,
            },
        )
        assert status == 409
        assert "该月份" in duplicate_month["error"]["message"]
        assert runtime.store.get_draft(second_draft["draft_id"])["status"] == (
            "ready_review"
        )
        status, discarded = request_json(
            connection,
            "DELETE",
            f"/api/v2/drafts/{second_draft['draft_id']}",
            {
                "expected_revision": second_draft["revision"],
                "reason": "重复导入，保留原始记录供审计",
            },
        )
        assert status == 200
        assert discarded["discarded"] is True
        assert discarded["draft"]["status"] == "discarded"

        status, imports = request_json(connection, "GET", "/api/v2/imports")
        assert status == 200
        assert all(item["status"] != "discarded" for item in imports["items"])
        status, all_imports = request_json(
            connection,
            "GET",
            "/api/v2/imports?include_discarded=true",
        )
        assert status == 200
        assert any(item["status"] == "discarded" for item in all_imports["items"])

        status, drafts = request_json(connection, "GET", "/api/v2/drafts")
        assert status == 200
        assert all(item["status"] != "discarded" for item in drafts["items"])
        status, all_drafts = request_json(
            connection,
            "GET",
            "/api/v2/drafts?include_discarded=true",
        )
        assert status == 200
        discarded_draft = next(
            item for item in all_drafts["items"] if item["status"] == "discarded"
        )
        assert discarded_draft["payload"] == second_draft["payload"]

        status, _ = request_json(
            connection,
            "PATCH",
            f"/api/v2/drafts/{second_draft['draft_id']}",
            {
                "expected_revision": discarded_draft["revision"],
                "payload": discarded_draft["payload"],
            },
        )
        assert status == 409
        status, _ = request_json(
            connection,
            "POST",
            f"/api/v2/drafts/{second_draft['draft_id']}/confirm",
            {
                "expected_revision": discarded_draft["revision"],
                "confirmer_name": "本机测试员",
                "confirmer_role": "企业填报员",
                "attestation": "不得重新确认已放弃草稿。",
                "accepted": True,
            },
        )
        assert status == 409

        status, audit = request_json(connection, "GET", "/api/v2/audit")
        assert status == 200
        assert audit["valid"] is True
        assert audit["events"][-1]["event_type"] == "five_quantity_draft_discarded"
        assert audit["events"][-1]["details"]["reason"] == (
            "重复导入，保留原始记录供审计"
        )

        status, _ = request_json(
            connection,
            "GET",
            "/api/v2/imports?include_discarded=invalid",
        )
        assert status == 400
        status, _ = request_json(connection, "DELETE", "/api/v2/risks/report-1", {})
        assert status == 405
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_csv_preview_mapping_profile_and_materialize_http_flow(
    tmp_path: Path,
) -> None:
    repository = Repository(tmp_path / "agent.db")
    runtime = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
        csv_preview_directory=tmp_path / "csv-preview-evidence",
    )
    service = EnterpriseAgentService(repository, five_quantity_runtime=runtime)
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,
        web_root=ROOT / "web",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=5
    )
    csv = (
        "业务日,原煤完成量,当日总电耗,内部备注\n"
        "2026-08-01,2600,96000,不得发送给模型\n"
    ).encode()
    try:
        status, preview = request_json(
            connection,
            "POST",
            "/api/v2/imports/preview",
            {
                "filename": "erp-august.csv",
                "content_base64": base64.b64encode(csv).decode(),
            },
        )
        assert status == 201
        assert preview["status"] == "active"
        assert preview["date_column"]["source_index"] == 0
        assert preview["date_column"]["inferred"] is True
        assert preview["detected_months"] == ["2026-08"]
        assert preview["valid_day_count"] == 1
        assert preview["mapping_assistant"]["attempted"] is False
        assert {item["status"] for item in preview["columns"]} == {"unmapped"}
        assert "2600" not in json.dumps(preview, ensure_ascii=False)
        assert "不得发送给模型" not in json.dumps(preview, ensure_ascii=False)

        status, invalid = request_json(
            connection,
            "POST",
            f"/api/v2/imports/{preview['preview_id']}/materialize",
            {
                "mappings": [
                    {
                        "source_index": 99,
                        "target_metric": "production_t",
                        "target_period": "daily_total",
                    }
                ],
                "save_profile": False,
            },
        )
        assert status == 422
        assert "不存在" in invalid["error"]["message"]

        mappings = [
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
        ]
        status, materialized = request_json(
            connection,
            "POST",
            f"/api/v2/imports/{preview['preview_id']}/materialize",
            {"mappings": mappings, "save_profile": True},
        )
        assert status == 201
        assert materialized["status"] == "ready_review"
        assert materialized["mapping_profile"]["status"] == "active"
        assert materialized["model_assistance_used"] is False
        daily = materialized["draft"]["payload"]["days"][0][
            "reported_quantity"
        ]["daily_total"]
        assert daily["production_t"]["value"] == 2600
        assert daily["electricity_kwh"]["value"] == 96000

        second_csv = csv.replace(b"2026-08-01", b"2026-08-02").replace(
            b"2600", b"2610"
        )
        status, reused = request_json(
            connection,
            "POST",
            "/api/v2/imports/preview",
            {
                "filename": "erp-august-next.csv",
                "content_base64": base64.b64encode(second_csv).decode(),
            },
        )
        assert status == 201
        assert reused["mapping_profile_applied"] == materialized["mapping_profile"][
            "profile_id"
        ]
        reused_by_index = {
            item["source_index"]: item for item in reused["columns"]
        }
        assert reused_by_index[1]["source"] == "approved_profile"
        assert reused_by_index[1]["target_metric"] == "production_t"
        assert reused_by_index[2]["target_metric"] == "electricity_kwh"

        status, audit = request_json(connection, "GET", "/api/v2/audit")
        assert status == 200
        assert audit["valid"] is True
        preview_events = [
            item
            for item in audit["events"]
            if item["event_type"].startswith("five_quantity_csv_")
        ]
        assert preview_events
        assert all(
            item["details"].get("submission_enqueued") is not True
            for item in preview_events
        )
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_enterprise_v2_discard_requires_write_permission(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "agent.db")
    runtime = FiveQuantityRuntime(
        repository,
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    imported = runtime.ingest_bytes(
        filename="permission.csv",
        content=(
            b"date,ventilation_m3_min,mine_entry_persons,electricity_kwh,"
            b"detonators_count,explosives_kg,production_t\n"
            b"2026-07-03,4800,320,96000,120,240,2600\n"
        ),
        acquisition_mode="manual_import",
        actor="system-test",
    )
    account = UserAccount(
        actor_id="auditor-1",
        name="只读审计员",
        role="审计员",
        password_hash=hash_password(
            "read-only-password",
            iterations=100_000,
            salt=b"auditor-1-000000",
        ),
        permissions=frozenset({"read"}),
    )
    service = EnterpriseAgentService(repository, five_quantity_runtime=runtime)
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,
        auth_manager=AuthManager((account,), session_ttl_seconds=300),
        web_root=ROOT / "web",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=5
    )
    try:
        login_body = json.dumps(
            {"actor_id": "auditor-1", "password": "read-only-password"}
        ).encode()
        connection.request(
            "POST",
            "/api/v1/auth/login",
            body=login_body,
            headers={"Content-Type": "application/json"},
        )
        login_response = connection.getresponse()
        login_payload = json.loads(login_response.read())
        assert login_response.status == 200
        cookie = login_response.getheader("Set-Cookie").split(";", 1)[0]

        draft = imported["draft"]
        status, error = request_json(
            connection,
            "DELETE",
            f"/api/v2/drafts/{draft['draft_id']}",
            {
                "expected_revision": draft["revision"],
                "reason": "只读账号无权放弃",
            },
            headers={
                "Cookie": cookie,
                "X-CSRF-Token": login_payload["csrf_token"],
            },
        )
        assert status == 403
        assert error["error"]["code"] == "permission_denied"
        assert runtime.store.get_draft(draft["draft_id"])["status"] == ("ready_review")

        status, error = request_json(
            connection,
            "POST",
            f"/api/v2/drafts/{draft['draft_id']}/correction",
            {
                "expected_revision": draft["revision"],
                "expected_submission_revision": 1,
                "accepted": True,
            },
            headers={"Cookie": cookie},
        )
        assert status == 403
        assert error["error"]["code"] == "csrf_token_invalid"
        status, error = request_json(
            connection,
            "POST",
            f"/api/v2/drafts/{draft['draft_id']}/correction",
            {
                "expected_revision": draft["revision"],
                "expected_submission_revision": 1,
                "accepted": True,
            },
            headers={
                "Cookie": cookie,
                "X-CSRF-Token": login_payload["csrf_token"],
            },
        )
        assert status == 403
        assert error["error"]["code"] == "permission_denied"
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_frontend_exposes_only_the_four_step_v2_mainline() -> None:
    html = (ROOT / "web" / "index.html").read_text()
    script = (ROOT / "web" / "v2-app.js").read_text()
    for label in (
        "数据收件箱",
        "规范化复核与报送",
        "风险解读与回复",
        "留痕与设置",
    ):
        assert label in html
    assert 'class="app-shell legacy-workspace" hidden' in html
    assert 'id="agentTaskButton" type="button" disabled hidden' in html
    assert 'id="coalChatButton" type="button" disabled hidden' in html
    assert "/api/v2/imports" in script
    assert "/api/v2/drafts/" in script
    assert "/api/v2/risks/" in script
    assert "/api/v2/audit" in script
    assert "include_discarded=true" in script
    assert "放弃草稿" in script
    assert "创建更正草稿" in script
    assert "/correction" in script
    assert "系统没有创建分叉" in script
    assert "直接前序消息" in script
    assert "人工导入和直采均进入同一复核与报送流程" in script
    assert "上传 CSV，自动生成填报草稿" in html
    assert 'id="fqDownloadCsvTemplate"' in html
    assert 'id="fqSelectedFileSummary" role="status"' in html
    assert 'id="fqUploadResult" role="status"' in html
    assert "只生成草稿，不会自动报送" in html
    assert "让 Agent 读取并生成草稿" in html
    assert "CSV_TEMPLATE_HEADER" in script
    assert "零点班" in script and "八点班" in script and "四点班" in script
    assert "日期 + 11 个原子字段" in html
    assert "十量日汇总 CSV 模板" in script
    assert "syncImportCapability" in script
    assert "当前尚未报送" in script
    assert "可信度分层" not in script
    assert "入井人员量" in html
    assert "入井人员量" in script
    assert "火工品量" in script
    assert "mine_entry_persons" in script
    for metric, label in (
        ("extraction_t", "开采量（采掘计量）"),
        ("sales_t", "销售量"),
        ("transport_t", "运输量"),
        ("wash_feed_t", "洗煤量（入洗原煤）"),
        ("invoiced_quantity_t", "开票量（吨）"),
    ):
        assert metric in script
        assert label in script
    assert "旧版 V2 五量数据：已到 5/10" in script
    assert "班次高级明细" in script
    assert "销售量、运输量、洗煤量和开票量不强制填班次" in script
    assert '{ code: "transport", label: "运输量", shiftRequired: false' in script
    assert (
        '{ code: "washing", label: "洗煤量（入洗原煤）", shiftRequired: false'
        in script
    )
    assert '["transport_t", "运输量", "t", true]' in script
    assert '["wash_feed_t", "洗煤量（入洗原煤）", "t", true]' in script
    assert "逐日核对六项" not in html
    assert '["labor_persons", "用工量"' not in script


def test_frontend_v2_autofill_evidence_behavior_in_jsdom() -> None:
    import subprocess

    script = ROOT / "tests" / "frontend_five_quantity_autofill_dom.test.js"
    completed = subprocess.run(
        ["node", str(script)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (
        "JSDOM five-quantity autofill evidence checks passed"
        in completed.stdout
    )


def test_frontend_v2_csv_upload_behavior_in_jsdom() -> None:
    import subprocess

    script = ROOT / "tests" / "frontend_five_quantity_csv_upload_dom.test.js"
    completed = subprocess.run(
        ["node", str(script)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "JSDOM five-quantity CSV upload checks passed" in completed.stdout


def test_frontend_ten_quantity_correction_behavior_in_jsdom() -> None:
    import subprocess

    script = ROOT / "tests" / "frontend_ten_quantity_correction_dom.test.js"
    completed = subprocess.run(
        ["node", str(script)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "JSDOM ten-quantity correction flow checks passed" in completed.stdout
