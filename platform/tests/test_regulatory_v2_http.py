from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import hmac
from http.client import HTTPConnection
import json
from pathlib import Path
from threading import Thread
from typing import Any
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker
import pytest
from referencing import Registry, Resource

from mineguard.exchange_v2 import (
    ExchangeClient,
    exchange_signature_material,
    sign_exchange_message,
    sign_transport_headers,
)
from mineguard.external_submission import jcs_canonical_json
from mineguard.regulatory_v2_http import RegulatoryV2RequestHandler, create_server


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
EXAMPLE_SECRET = b"example-v2-exchange-secret-not-for-production"
FIXED_NOW = datetime(2026, 8, 1, 0, 20, tzinfo=UTC)


def _schema_registry() -> Registry:
    resources = []
    for path in (CONTRACTS / "schemas").glob("*.json"):
        schema = json.loads(path.read_text())
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _assert_contract(document: dict[str, Any], schema_name: str) -> None:
    schema = json.loads((CONTRACTS / "schemas" / schema_name).read_text())
    errors = list(
        Draft202012Validator(
            schema,
            registry=_schema_registry(),
            format_checker=FormatChecker(),
        ).iter_errors(document)
    )
    assert not errors, [error.message for error in errors]


def _assert_problem(document: dict[str, Any]) -> None:
    openapi = json.loads(
        (CONTRACTS / "openapi" / "five-quantity-exchange-v2.openapi.json").read_text()
    )
    Draft202012Validator(openapi["components"]["schemas"]["Problem"]).validate(
        document
    )


def _assert_application_signature(document: dict[str, Any]) -> None:
    digest = hashlib.sha256(
        jcs_canonical_json(document["payload"]).encode("utf-8")
    ).hexdigest()
    assert digest == document["signature_envelope"]["payload_sha256"]
    expected = hmac.new(
        EXAMPLE_SECRET,
        exchange_signature_material(document, digest),
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(expected, document["signature_envelope"]["signature"])


def _signed_enterprise_message(document: dict[str, Any]) -> bytes:
    document["signature_envelope"]["payload_sha256"] = "0" * 64
    document["signature_envelope"]["signature"] = "0" * 64
    sign_exchange_message(document, EXAMPLE_SECRET)
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("past_only_rolling_mad", "past_only_rolling_mad"),
        ("past_only_ewma", "past_only_ewma"),
        ("past_only_cusum", "past_only_cusum"),
        ("past_only_page_hinkley", "past_only_page_hinkley"),
    ],
)
def test_v2_report_preserves_specific_temporal_evidence_method(
    code: str, expected: str
) -> None:
    assert RegulatoryV2RequestHandler._evidence_method(
        code, f"past_only_temporal_detector:{code}"
    ) == expected


def test_complete_two_product_exchange_and_read_only_dashboard(tmp_path: Path) -> None:
    submission_body = (
        CONTRACTS / "examples" / "five-quantity-submission-v2.json"
    ).read_bytes()
    submission = json.loads(submission_body)
    client = ExchangeClient(
        sender_id="agent-mine-qy-001",
        party_id="operator-qy-001",
        mine_id="MINE-QY-001",
        secret=EXAMPLE_SECRET,
        mine_name="示例一号煤矿",
        comparison_context=submission["payload"]["comparison_context"],
    )
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "regulatory.db",
        auth_database_path=tmp_path / "auth.db",
        auth_required=False,
        clients={client.sender_id: client},
        clock=lambda: FIXED_NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    nonce_counter = 0

    def exchange_request(
        method: str,
        target: str,
        *,
        body: bytes = b"",
        contract_version: str,
    ) -> tuple[int, dict[str, Any] | None]:
        nonlocal nonce_counter
        nonce_counter += 1
        nonce = nonce_counter.to_bytes(16, "big")
        import base64

        nonce_text = base64.urlsafe_b64encode(nonce).decode().rstrip("=")
        headers = sign_transport_headers(
            client,
            method=method,
            request_target=target,
            body=body,
            contract_version=contract_version,
            timestamp=FIXED_NOW,
            nonce=nonce_text,
        )
        if body:
            headers["Content-Type"] = "application/json"
        connection.request(method, target, body=body or None, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        payload = json.loads(raw) if raw else None
        return response.status, payload

    try:
        future_envelope = deepcopy(submission)
        future_envelope["created_at"] = "2030-01-01T00:00:00Z"
        future_envelope["signature_envelope"]["signed_at"] = (
            "2030-01-01T00:00:00Z"
        )
        future_status, future_problem = exchange_request(
            "POST",
            "/v2/five-quantity-submissions",
            body=_signed_enterprise_message(future_envelope),
            contract_version="five-quantity-submission-v2",
        )
        assert future_status == 400
        assert future_problem is not None
        assert "future application timestamp" in future_problem["detail"]

        status, intake = exchange_request(
            "POST",
            "/v2/five-quantity-submissions",
            body=submission_body,
            contract_version="five-quantity-submission-v2",
        )
        assert status == 202
        assert intake is not None
        _assert_contract(intake, "intake-receipt-v2.schema.json")
        _assert_application_signature(intake)
        assert intake["payload"]["regulatory_outcome"] == "not_determined_at_intake"

        status, report = exchange_request(
            "GET",
            "/v2/analysis-reports/next",
            contract_version="five-quantity-exchange-v2",
        )
        assert status == 200
        assert report is not None
        _assert_contract(report, "analysis-report-v2.schema.json")
        _assert_application_signature(report)
        assert report["payload"]["outcome"] == "data_insufficient"
        assert report["payload"]["response_required"] is True
        assert report["payload"]["algorithm"]["engine_id"] == (
            "mineguard-five-quantity-engine"
        )
        assert "l1_reconciliation" in report["payload"]["algorithm"]["modules"]
        assert "robust_temporal_baseline" in report["payload"]["algorithm"]["modules"]

        broken_revision = deepcopy(submission)
        broken_revision["message_id"] = str(uuid4())
        broken_revision["correlation_id"] = submission["message_id"]
        broken_revision["causation_id"] = report["message_id"]
        broken_revision["idempotency_key"] = f"revision.{broken_revision['message_id']}"
        broken_revision["revision"] = 2
        broken_revision["predecessor"] = {
            "message_id": submission["message_id"],
            "payload_sha256": "0" * 64,
        }
        broken_revision["created_at"] = "2026-08-01T00:20:30Z"
        broken_revision["signature_envelope"]["signed_at"] = broken_revision[
            "created_at"
        ]
        broken_revision["signature_envelope"]["nonce"] = (
            "BQUFBQUFBQUFBQUFBQUFBQ"
        )
        status, lineage_problem = exchange_request(
            "POST",
            "/v2/five-quantity-submissions",
            body=_signed_enterprise_message(broken_revision),
            contract_version="five-quantity-submission-v2",
        )
        assert status == 409
        assert lineage_problem is not None
        assert lineage_problem["code"] == "LINEAGE_CONFLICT"
        _assert_problem(lineage_problem)

        ack = deepcopy(
            json.loads(
                (CONTRACTS / "examples" / "risk-delivery-ack-v2.json").read_text()
            )
        )
        ack["message_id"] = str(uuid4())
        ack["correlation_id"] = report["correlation_id"]
        ack["causation_id"] = report["message_id"]
        ack["idempotency_key"] = f"ack.{ack['message_id']}"
        ack["created_at"] = "2026-08-01T00:21:00Z"
        ack["payload"].update(
            {
                "report_id": report["payload"]["report_id"],
                "analysis_report_message_id": report["message_id"],
                "delivery_cursor": report["payload"]["delivery_cursor"],
                "received_at": "2026-08-01T00:20:59Z",
                "local_inbox_record_id": "inbox-test-001",
            }
        )
        ack["signature_envelope"]["signed_at"] = ack["created_at"]
        ack["signature_envelope"]["nonce"] = "AQEBAQEBAQEBAQEBAQEBAQ"
        ack_body = _signed_enterprise_message(ack)
        status, payload = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/delivery-ack",
            body=ack_body,
            contract_version="risk-delivery-ack-v2",
        )
        assert status == 204
        assert payload is None

        conflicting_ack = deepcopy(ack)
        conflicting_ack["message_id"] = str(uuid4())
        conflicting_ack["created_at"] = "2026-08-01T00:21:10Z"
        conflicting_ack["payload"]["local_inbox_record_id"] = "inbox-tampered"
        conflicting_ack["signature_envelope"]["signed_at"] = conflicting_ack[
            "created_at"
        ]
        conflicting_ack["signature_envelope"]["nonce"] = (
            "AwMDAwMDAwMDAwMDAwMDAw"
        )
        status, problem = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/delivery-ack",
            body=_signed_enterprise_message(conflicting_ack),
            contract_version="risk-delivery-ack-v2",
        )
        assert status == 409
        assert problem is not None
        assert problem["status"] == 409
        assert problem["code"] == "IMMUTABLE_CONFLICT"
        assert problem["type"].startswith("/problems/")
        _assert_problem(problem)

        response_message = deepcopy(
            json.loads(
                (
                    CONTRACTS / "examples" / "enterprise-risk-response-v2.json"
                ).read_text()
            )
        )
        response_message["message_id"] = str(uuid4())
        response_message["correlation_id"] = report["correlation_id"]
        response_message["causation_id"] = report["message_id"]
        response_message["idempotency_key"] = (
            f"response.{response_message['message_id']}"
        )
        response_message["created_at"] = "2026-08-01T00:23:00Z"
        response_message["payload"]["response_id"] = str(uuid4())
        response_message["payload"]["report_id"] = report["payload"]["report_id"]
        response_message["payload"]["analysis_report_message_id"] = report["message_id"]
        response_message["payload"]["responded_at"] = "2026-08-01T00:22:59Z"
        response_message["payload"]["finding_responses"] = [
            {
                "finding_id": report["payload"]["findings"][0]["finding_id"],
                "response_kind": "explanation",
                "reason_code": "planned_shutdown",
                "facts": "企业已核对停产检修记录；本说明只作留痕，不申请直接消除风险。",
                "evidence_refs": [],
                "actions": [
                    {
                        "action_type": "investigation",
                        "description": "复核日报与三个班次原始记录。",
                        "status": "completed",
                    }
                ],
                "corrected_submission_message_id": None,
            }
        ]
        response_message["payload"]["attachments"] = []
        response_message["payload"]["agent_assistance"] = {
            "used": False,
            "conversation_id": None,
            "assistance_record_sha256": None,
        }
        response_message["payload"]["human_confirmation"].update(
            {
                "confirmed_at": "2026-08-01T00:22:58Z",
                "content_sha256": "9" * 64,
            }
        )
        response_message["signature_envelope"]["signed_at"] = response_message[
            "created_at"
        ]
        response_message["signature_envelope"]["nonce"] = "AgICAgICAgICAgICAgICAg"

        invalid_correction = deepcopy(response_message)
        invalid_correction["message_id"] = str(uuid4())
        invalid_correction["idempotency_key"] = (
            f"response.{invalid_correction['message_id']}"
        )
        invalid_correction["payload"]["response_id"] = str(uuid4())
        invalid_correction["payload"]["finding_responses"][0][
            "corrected_submission_message_id"
        ] = submission["message_id"]
        invalid_correction["payload"]["finding_responses"][0][
            "response_kind"
        ] = "correction_submitted"
        invalid_correction["signature_envelope"]["nonce"] = (
            "BAQEBAQEBAQEBAQEBAQEBA"
        )
        status, correction_problem = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/responses",
            body=_signed_enterprise_message(invalid_correction),
            contract_version="enterprise-risk-response-v2",
        )
        assert status == 409
        assert correction_problem is not None
        assert "higher-revision descendant" in correction_problem["detail"]
        _assert_problem(correction_problem)

        response_body = _signed_enterprise_message(response_message)
        status, response_receipt = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/responses",
            body=response_body,
            contract_version="enterprise-risk-response-v2",
        )
        assert status == 202
        assert response_receipt is not None
        _assert_contract(response_receipt, "response-receipt-v2.schema.json")
        _assert_application_signature(response_receipt)
        assert response_receipt["payload"]["risk_status"] == ("not_cleared_by_receipt")

        connection.request("GET", "/v2/regulatory/overview")
        overview_response = connection.getresponse()
        overview = json.loads(overview_response.read())
        assert overview_response.status == 200
        assert overview["counts"]["configured_mines"] == 1
        assert overview["counts"]["insufficient_data"] == 1
        assert overview["counts"]["awaiting_response"] == 0
        assert "notice" not in overview

        connection.request("GET", "/v2/regulatory/mines/MINE-QY-001")
        detail_response = connection.getresponse()
        detail = json.loads(detail_response.read())
        assert detail_response.status == 200
        assert detail["mine"]["mine_id"] == "MINE-QY-001"
        assert detail["latest_analysis"]["algorithm_version"].startswith(
            "regulatory-five-quantity-v2"
        )
        assert detail["findings"][0]["state"] == "explanation_recorded"

        connection.request(
            "HEAD",
            f"/v2/analysis-reports/{report['payload']['report_id']}",
        )
        head_response = connection.getresponse()
        head_response.read()
        assert head_response.status == 405

        connection.request("POST", "/v2/regulatory/mines", body=b"{}")
        read_only_response = connection.getresponse()
        read_only_response.read()
        assert read_only_response.status == 404
        assert server.store.verify_audit_chain() is True
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
