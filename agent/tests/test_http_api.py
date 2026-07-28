from __future__ import annotations

import http.client
import json
import threading
from typing import Any

from conftest import complete_values

from enterprise_agent.http_api import EnterpriseAgentHTTPServer
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository


class FakePlatform:
    def submit(
        self, payload: dict[str, Any], *, idempotency_key: str
    ) -> dict[str, Any]:
        return {
            "contract_version": "enterprise-submission-receipt-v1",
            "submission_contract_version": "enterprise-submission-v1",
            "receipt_id": "018f7b4d-3367-71b0-98d8-84ac388c2e20",
            "submission_id": payload["submission_id"],
            "idempotency_key": idempotency_key,
            "received_at": "2026-07-27T08:05:01Z",
            "status": "accepted",
            "payload_sha256": payload["payload_sha256"],
            "regulatory_outcome": "not_determined_at_intake",
            "warnings": [],
            "links": {},
        }


def _request(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    encoded = (
        json.dumps(body, ensure_ascii=False).encode("utf-8")
        if body is not None
        else None
    )
    headers = {"Content-Type": "application/json"} if encoded else {}
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    parsed = json.loads(response.read())
    return response.status, parsed


def test_api_complete_draft_confirm_submit_reload_and_delete_guard() -> None:
    service = EnterpriseAgentService(
        Repository(":memory:"),
        platform_client=FakePlatform(),  # type: ignore[arg-type]
    )
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=3
    )
    try:
        status, created = _request(connection, "POST", "/api/v1/drafts", {})
        assert status == 201
        draft_id = created["draft"]["draft_id"]

        status, patched = _request(
            connection,
            "PATCH",
            f"/api/v1/drafts/{draft_id}",
            {
                "actor": "operator-1",
                "expected_revision": 1,
                "patch": complete_values(),
            },
        )
        assert status == 200
        assert patched["draft"]["enterprise_name"] == "示例能源有限公司"
        assert patched["draft"]["unified_social_credit_code"] == ("91110000ABCDEFGH1X")
        assert patched["draft"]["mine_name"] == "示例一号矿"

        status, validation = _request(
            connection,
            "POST",
            f"/api/v1/drafts/{draft_id}/validate",
            {},
        )
        assert status == 200
        assert validation["valid"] is False
        assert any(
            issue["code"] == "regulator_event_snapshot_required"
            for issue in validation["issues"]
        )

        status, snapshot = _request(
            connection,
            "POST",
            f"/api/v1/drafts/{draft_id}/event-snapshot",
            {
                "snapshot": {
                    "snapshot_id": "mine-001-event-snapshot",
                    "mine_id": "mine-001",
                    "window_start": "2026-07-27T00:00:00Z",
                    "window_end": "2026-07-27T08:00:00Z",
                    "event_codes": [],
                    "evidence_sha256": "e" * 64,
                    "source_system": "regulator-event-ledger",
                    "record_id": "query-result:mine-001",
                },
                "expected_revision": 2,
            },
        )
        assert status == 200
        assert snapshot["draft"]["_meta"]["revision"] == 3

        status, validation = _request(
            connection,
            "POST",
            f"/api/v1/drafts/{draft_id}/validate",
            {},
        )
        assert status == 200
        assert validation["valid"] is True

        status, reviewed = _request(
            connection,
            "POST",
            f"/api/v1/drafts/{draft_id}/reviews",
            {
                "observation_ids": ["obs-20260727-0001"],
                "reviewed": True,
                "expected_revision": 3,
            },
        )
        assert status == 200
        assert reviewed["review_state"]["all_reviewed"] is True

        status, confirmed = _request(
            connection,
            "POST",
            f"/api/v1/drafts/{draft_id}/confirm",
            {
                "actor": "operator-1",
                "confirmer_name": "张三",
                "confirmer_role": "企业报送负责人",
                "accepted": True,
                "attestation": "本人已逐项核对原始记录并确认有权提交。",
                "expected_revision": 3,
            },
        )
        assert status == 200
        assert confirmed["draft"]["_meta"]["confirmed"] is True

        status, submitted = _request(
            connection,
            "POST",
            f"/api/v1/drafts/{draft_id}/submit",
            {},
        )
        assert status == 200
        assert submitted["submission"]["status"] == "succeeded"
        assert "request" not in submitted["submission"]
        assert submitted["submission"]["submitted_at"]

        status, reloaded = _request(connection, "GET", f"/api/v1/drafts/{draft_id}")
        assert status == 200
        assert reloaded["draft"]["status"] == "submitted"
        assert reloaded["draft"]["_meta"]["submitted"] is True
        assert reloaded["draft"]["receipt"]["status"] == "accepted"

        status, submissions = _request(
            connection,
            "GET",
            f"/api/v1/drafts/{draft_id}/submissions",
        )
        assert status == 200
        assert submissions["count"] == 1
        assert "request" not in submissions["submissions"][0]
        assert submissions["submissions"][0]["request_sha256"]

        status, audit = _request(
            connection,
            "GET",
            f"/api/v1/drafts/{draft_id}/audit?limit=2",
        )
        assert status == 200
        assert audit["count"] == 2
        assert audit["truncated"] is True
        assert audit["integrity"]["valid"] is True
        assert audit["total"] == audit["integrity"]["event_count"]

        status, error = _request(
            connection,
            "DELETE",
            f"/api/v1/drafts/{draft_id}",
            {"expected_revision": 3},
        )
        assert status == 409
        assert error["error"]["code"] == "conflict"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_head_health_is_probe_friendly_and_has_no_body() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    server = EnterpriseAgentHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=3,
    )
    try:
        connection.request("HEAD", "/api/v1/health")
        response = connection.getresponse()
        assert response.status == 200
        assert int(response.getheader("Content-Length", "0")) > 0
        assert response.getheader("Permissions-Policy") == (
            "camera=(), microphone=(), geolocation=()"
        )
        assert "default-src 'none'" in response.getheader(
            "Content-Security-Policy", ""
        )
        assert response.getheader("Server", "").startswith(
            "EnterpriseReportingAgent/0.1"
        )
        assert response.read() == b""
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_draft_list_is_bounded_paginated_summary() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    for index in range(3):
        service.create_draft(
            {
                "enterprise_id": f"enterprise-{index}",
                "enterprise_name": f"企业 {index}",
                "observations": [
                    {
                        "observation_id": f"secret-observation-{index}",
                        "signature": "secret-signature",
                    }
                ],
            },
            actor="operator-1",
        )
    server = EnterpriseAgentHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=3
    )
    try:
        status, first = _request(
            connection,
            "GET",
            "/api/v1/drafts?limit=2&offset=0",
        )
        assert status == 200
        assert first["count"] == 2
        assert first["total"] == 3
        assert first["has_more"] is True
        assert first["next_offset"] == 2
        assert all("observations" not in item for item in first["items"])
        assert all("field_provenance" not in item for item in first["items"])
        assert all(item["observation_count"] == 1 for item in first["items"])

        status, second = _request(
            connection,
            "GET",
            "/api/v1/drafts?limit=2&offset=2",
        )
        assert status == 200
        assert second["count"] == 1
        assert second["has_more"] is False
        assert second["next_offset"] is None

        status, invalid = _request(
            connection,
            "GET",
            "/api/v1/drafts?limit=201",
        )
        assert status == 400
        assert invalid["error"]["code"] == "invalid_request"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_platform_status_endpoint_is_safe_in_offline_mode() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    server = EnterpriseAgentHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=3,
    )
    try:
        status, result = _request(
            connection,
            "GET",
            "/api/v1/platform-status",
        )
        assert status == 200
        assert result == {
            "configured": False,
            "reachable": False,
            "compatible": False,
            "message": "尚未配置监管平台，当前只能保存和预检草稿",
        }
        assert "url" not in json.dumps(result).lower()
        assert "secret" not in json.dumps(result).lower()
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
