from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import UTC, datetime
import hashlib
import http.client
import json
from pathlib import Path
import threading
from typing import Any, Iterator

from mineguard.api import create_server
from mineguard.auth import Role
from mineguard.edge_ingest import EdgeTelemetryBatch


ADMIN_PASSWORD = "correct admin password"
USER_PASSWORD = "scoped user password"
REVIEW_ACTIONS = {
    "acknowledge",
    "start",
    "resolve",
    "add_note",
}
ALL_ACTIONS = {
    "assign",
    *REVIEW_ACTIONS,
    "close",
    "reopen",
}


def _authorization_batch_id(mine_id: str) -> str:
    client_id = f"client-{mine_id}"
    suffix = hashlib.sha256(f"authorization-{mine_id}".encode()).hexdigest()[:32]
    return f"{client_id}--batch_{suffix}"


def _seed_alert(
    server: Any,
    *,
    mine_id: str,
    rule_code: str,
) -> dict[str, Any]:
    return server.edge_repository.upsert_platform_alert(
        mine_id=mine_id,
        category="authorization-test",
        rule_code=rule_code,
        level="yellow",
        title=f"{mine_id} 授权测试预警",
        summary="仅用于授权回归",
        location_code="test-location",
        detected_at=datetime.now(UTC),
        observation_ids=[f"observation-{rule_code}"],
        details={"advisory_only": True},
        rule_profile={"version": "test-v1", "fingerprint": "a" * 64},
    )


def _seed_edge_batch(server: Any, *, mine_id: str) -> str:
    now = datetime.now(UTC).isoformat()
    batch_id = _authorization_batch_id(mine_id)
    document = {
        "schema_version": "edge-telemetry-batch-v1",
        "batch_id": batch_id,
        "client_id": f"client-{mine_id}",
        "mine_id": mine_id,
        "sent_at": now,
        "sequence_start": 1,
        "sequence_end": 1,
        "rule_profile": {
            "profile_id": "authorization-test",
            "version": 1,
            "sha256": "a" * 64,
        },
        "observations": [
            {
                "source_id": "personnel-total",
                "observation_id": f"{batch_id}-observation",
                "metric_code": "personnel.underground_count",
                "value": 50,
                "unit": "person",
                "location_code": "underground-total",
                "observed_at": now,
                "received_at": now,
                "sequence_no": 1,
                "revision": 0,
                "acquisition_mode": "api_poll",
                "source_record_id": f"source-{batch_id}",
                "source_record_sha256": "b" * 64,
                "source_signature": None,
                "status_code": "online",
                "quality": {
                    "valid": True,
                    "completeness": 1.0,
                    "timeliness": 1.0,
                    "device_health": "healthy",
                    "clock_synchronized": True,
                    "flags": [],
                },
                "manual_attestation": None,
            }
        ],
        "local_alerts": [],
    }
    raw = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    server.edge_repository.ingest_batch(
        EdgeTelemetryBatch.model_validate(document),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        raw_body=raw,
    )
    return batch_id


@contextmanager
def _server(
    tmp_path: Path,
) -> Iterator[tuple[Any, dict[str, dict[str, Any]]]]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=True,
        auth_database_path=tmp_path / "auth.db",
        bootstrap_admin=("admin", ADMIN_PASSWORD),
        job_database_path=tmp_path / "jobs.db",
        secure_cookie=False,
    )
    for mine_id in ("M001", "M002"):
        server.edge_repository.upsert_mine(
            {
                "mine_id": mine_id,
                "mine_name": f"测试矿井 {mine_id}",
                "gas_category": "high_gas",
                "approved_underground_personnel": 100,
            },
            actor_id="test",
        )
        now = datetime.now(UTC).isoformat()
        server.edge_repository.save_safety_evaluation(
            batch_id=None,
            result={
                "mine_id": mine_id,
                "decision_time": now,
                "rule_version": "test-v1",
                "rule_fingerprint": "a" * 64,
                "states": [],
            },
        )
        server.edge_repository.save_verification_run(
            request={
                "request_id": f"verification-{mine_id}",
                "mine_id": mine_id,
                "window_start": now,
                "window_end": now,
            },
            result={
                "status": "ready",
                "overall_clue_level": 0,
            },
            actor_id="test",
        )
    alerts = {
        mine_id: _seed_alert(
            server,
            mine_id=mine_id,
            rule_code=f"collection-{mine_id}",
        )
        for mine_id in ("M001", "M002")
    }
    for mine_id in ("M001", "M002"):
        _seed_edge_batch(server, mine_id=mine_id)
    for role in (Role.SUPERVISOR, Role.REVIEWER, Role.VIEWER):
        server.auth_store.create_user(
            role.value,
            USER_PASSWORD,
            role,
            ["M001"],
        )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, alerts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _raw_request(
    server: Any,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    host, port = server.server_address[:2]
    connection = http.client.HTTPConnection(host, port, timeout=5)
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = dict(headers or {})
    if encoded is not None:
        request_headers["Content-Type"] = "application/json"
    try:
        connection.request(
            method,
            path,
            body=encoded,
            headers=request_headers,
        )
        response = connection.getresponse()
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        return response.status, response.read(), response_headers
    finally:
        connection.close()


def _json_request(
    server: Any,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    status, raw, _ = _raw_request(
        server,
        method,
        path,
        body,
        headers=headers,
    )
    return status, json.loads(raw)


def _login(server: Any, role: str) -> tuple[str, str]:
    username = "admin" if role == "admin" else role
    password = ADMIN_PASSWORD if role == "admin" else USER_PASSWORD
    status, raw, response_headers = _raw_request(
        server,
        "POST",
        "/v1/auth/login",
        {"username": username, "password": password},
    )
    assert status == 200
    payload = json.loads(raw)
    cookie = response_headers["set-cookie"].split(";", 1)[0]
    return cookie, payload["csrf_token"]


def _headers(cookie: str, csrf: str | None = None) -> dict[str, str]:
    result = {"Cookie": cookie}
    if csrf is not None:
        result["X-CSRF-Token"] = csrf
    return result


def _mine_ids(items: list[dict[str, Any]]) -> set[str]:
    return {str(item["mine_id"]) for item in items}


def test_safety_collections_and_resources_apply_role_mine_scopes(
    tmp_path: Path,
) -> None:
    with _server(tmp_path) as (server, alerts):
        for role in ("admin", "supervisor", "reviewer", "viewer"):
            cookie, _ = _login(server, role)
            headers = _headers(cookie)
            expected_mines = (
                {"M001", "M002"} if role == "admin" else {"M001"}
            )

            status, dashboard = _json_request(
                server,
                "GET",
                "/v1/dashboard/safety",
                headers=headers,
            )
            assert status == 200
            assert _mine_ids(dashboard["mines"]) == expected_mines
            assert _mine_ids(dashboard["alerts"]) == expected_mines

            for path in (
                "/v1/safety/alerts",
                "/v1/safety/runs",
                "/v1/safety/notifications",
                "/v1/verification/runs",
                "/v1/edge-evaluation-batches",
            ):
                status, payload = _json_request(
                    server,
                    "GET",
                    path,
                    headers=headers,
                )
                assert status == 200, (role, path, payload)
                assert _mine_ids(payload["items"]) == expected_mines

            status, csv_body, _ = _raw_request(
                server,
                "GET",
                "/v1/reports/safety-alerts.csv",
                headers=headers,
            )
            assert status == 200
            csv_text = csv_body.decode("utf-8-sig")
            assert "M001" in csv_text
            assert ("M002" in csv_text) is (role == "admin")

            for mine_id in ("M001", "M002"):
                status, payload = _json_request(
                    server,
                    "GET",
                    f"/v1/safety/alerts/{alerts[mine_id]['alert_id']}",
                    headers=headers,
                )
                expected_status = (
                    200
                    if role == "admin" or mine_id == "M001"
                    else 403
                )
                assert status == expected_status, (role, mine_id, payload)

                status, payload = _json_request(
                    server,
                    "GET",
                    (
                        f"/v1/edge-telemetry-batches/"
                        f"{_authorization_batch_id(mine_id)}/receipt"
                    ),
                    headers=headers,
                )
                assert status == expected_status, (role, mine_id, payload)

            if role != "admin":
                for path in (
                    "/v1/safety/alerts?mine_id=M002",
                    "/v1/safety/runs?mine_id=M002",
                    "/v1/verification/runs?mine_id=M002",
                    "/v1/edge-evaluation-batches?mine_id=M002",
                    "/v1/reports/safety-alerts.csv?mine_id=M002",
                ):
                    status, payload = _json_request(
                        server,
                        "GET",
                        path,
                        headers=headers,
                    )
                    assert status == 403, (role, path, payload)


def test_edge_recalculation_checks_action_permission_and_batch_mine(
    tmp_path: Path,
) -> None:
    with _server(tmp_path) as (server, _):
        supervisor_cookie, supervisor_csrf = _login(
            server,
            "supervisor",
        )
        supervisor_headers = _headers(
            supervisor_cookie,
            supervisor_csrf,
        )
        status, payload = _json_request(
            server,
            "POST",
            (
                "/v1/edge-telemetry-batches/"
                f"{_authorization_batch_id('M001')}/recalculate"
            ),
            {},
            headers=supervisor_headers,
        )
        assert status == 200, payload

        status, payload = _json_request(
            server,
            "POST",
            (
                "/v1/edge-telemetry-batches/"
                f"{_authorization_batch_id('M002')}/recalculate"
            ),
            {},
            headers=supervisor_headers,
        )
        assert status == 403, payload

        reviewer_cookie, reviewer_csrf = _login(server, "reviewer")
        status, payload = _json_request(
            server,
            "POST",
            (
                "/v1/edge-telemetry-batches/"
                f"{_authorization_batch_id('M001')}/recalculate"
            ),
            {},
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403, payload


def test_only_admin_can_retry_dead_webhook_delivery(
    tmp_path: Path,
) -> None:
    with _server(tmp_path) as (server, _):
        notification = server.edge_repository.list_notifications(
            mine_ids={"M001"}
        )[0]
        notification_id = notification["notification_id"]
        server.edge_repository.materialize_notification_deliveries(
            {"county-command": "blue"}
        )
        delivery = next(
            item
            for item in server.edge_repository.claim_notification_deliveries(
                {"county-command"}
            )
            if item["notification_id"] == notification_id
        )
        server.edge_repository.mark_notification_delivery_failed(
            notification_id,
            delivery["webhook_id"],
            error_code="webhook_http_5xx",
            maximum_attempts=1,
        )

        supervisor_cookie, supervisor_csrf = _login(
            server,
            "supervisor",
        )
        status, payload = _json_request(
            server,
            "POST",
            f"/v1/safety/notifications/{notification_id}/retry",
            {"webhook_id": "county-command"},
            headers=_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 403, payload

        admin_cookie, admin_csrf = _login(server, "admin")
        status, payload = _json_request(
            server,
            "POST",
            f"/v1/safety/notifications/{notification_id}/retry",
            {"webhook_id": "county-command"},
            headers=_headers(admin_cookie),
        )
        assert status == 403, payload

        status, payload = _json_request(
            server,
            "POST",
            f"/v1/safety/notifications/{notification_id}/retry",
            {"webhook_id": "county-command"},
            headers=_headers(admin_cookie, admin_csrf),
        )
        assert status == 200, payload
        assert payload["requeued_delivery_count"] == 1
        retried = payload["notification"]["deliveries"][0]
        assert retried["status"] == "retry"
        assert retried["manual_retry_count"] == 1

        status, payload = _json_request(
            server,
            "POST",
            f"/v1/safety/notifications/{notification_id}/retry",
            {"webhook_id": "county-command"},
            headers=_headers(admin_cookie, admin_csrf),
        )
        assert status == 409, payload

        status, payload = _json_request(
            server,
            "GET",
            "/v1/safety/notifications?webhook_id=county-command",
            headers=_headers(admin_cookie),
        )
        assert status == 200, payload
        selected = next(
            item
            for item in payload["items"]
            if item["notification_id"] == notification_id
        )
        assert selected["deliveries"][0]["webhook_id"] == "county-command"


def _action_body(action: str, version: int) -> dict[str, Any]:
    body: dict[str, Any] = {
        "action": action,
        "expected_version": version,
    }
    if action == "assign":
        body["assignee"] = "reviewer"
    if action in {"resolve", "close", "reopen", "add_note"}:
        body["note"] = "授权回归测试说明"
    return body


def _prepare_action_alert(
    server: Any,
    *,
    mine_id: str,
    role: str,
    action: str,
    scope: str,
) -> dict[str, Any]:
    alert = _seed_alert(
        server,
        mine_id=mine_id,
        rule_code=f"action-{scope}-{role}-{action}",
    )
    if action in {"close", "reopen"}:
        alert = server.edge_repository.apply_alert_action(
            alert["alert_id"],
            action="resolve",
            expected_version=alert["version"],
            actor_id="test-setup",
            note="准备审批动作的状态",
        )
    return alert


def test_safety_action_permissions_and_mine_scopes(
    tmp_path: Path,
) -> None:
    allowed_by_role = {
        "admin": ALL_ACTIONS,
        "supervisor": ALL_ACTIONS,
        "reviewer": REVIEW_ACTIONS,
        "viewer": set(),
    }
    with _server(tmp_path) as (server, _):
        for role, allowed_actions in allowed_by_role.items():
            cookie, csrf = _login(server, role)
            headers = _headers(cookie, csrf)
            for action in sorted(ALL_ACTIONS):
                alert = _prepare_action_alert(
                    server,
                    mine_id="M001",
                    role=role,
                    action=action,
                    scope="inside",
                )
                status, payload = _json_request(
                    server,
                    "POST",
                    f"/v1/safety/alerts/{alert['alert_id']}/actions",
                    _action_body(action, alert["version"]),
                    headers=headers,
                )
                expected_status = 200 if action in allowed_actions else 403
                assert status == expected_status, (role, action, payload)

                if role != "admin":
                    outside = _prepare_action_alert(
                        server,
                        mine_id="M002",
                        role=role,
                        action=action,
                        scope="outside",
                    )
                    status, payload = _json_request(
                        server,
                        "POST",
                        (
                            f"/v1/safety/alerts/"
                            f"{outside['alert_id']}/actions"
                        ),
                        _action_body(action, outside["version"]),
                        headers=headers,
                    )
                    assert status == 403, (role, action, payload)


def test_responsibility_route_read_receipt_and_delete_are_authorized(
    tmp_path: Path,
) -> None:
    with _server(tmp_path) as (server, _):
        admin_cookie, admin_csrf = _login(server, "admin")
        status, created = _json_request(
            server,
            "POST",
            "/v1/admin/safety-responsibility-routes",
            {
                "route_id": "m001-all-yellow",
                "mine_id": "M001",
                "category": None,
                "minimum_level": "yellow",
                "primary_username": "reviewer",
                "backup_username": "supervisor",
                "escalation_minutes": 5,
                "enabled": True,
            },
            headers=_headers(admin_cookie, admin_csrf),
        )
        assert status == 200, created
        assert created["route"]["primary_username"] == "reviewer"
        assert created["newly_routed_alerts"] >= 1

        status, listed = _json_request(
            server,
            "GET",
            "/v1/admin/safety-responsibility-routes",
            headers=_headers(admin_cookie),
        )
        assert status == 200, listed
        assert [item["route_id"] for item in listed["items"]] == [
            "m001-all-yellow"
        ]

        alert = _seed_alert(
            server,
            mine_id="M001",
            rule_code="responsibility-read",
        )
        detail = server.edge_repository.get_alert(alert["alert_id"])
        assert detail is not None
        assert detail["assignee"] == "reviewer"
        assert detail["recipients"][0]["recipient_role"] == "primary"

        reviewer_cookie, reviewer_csrf = _login(server, "reviewer")
        status, read = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert['alert_id']}/read",
            {"expected_version": detail["version"]},
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 200, read
        primary = next(
            item
            for item in read["recipients"]
            if item["recipient_role"] == "primary"
        )
        assert primary["username"] == "reviewer"
        assert primary["read_at"] is not None

        parallel_route = {
            "route_id": "m001-authorization-yellow",
            "mine_id": "M001",
            "category": "authorization-test",
            "minimum_level": "yellow",
            "primary_username": "supervisor",
            "backup_username": "admin",
            "escalation_minutes": 5,
            "enabled": True,
        }
        status, denied = _json_request(
            server,
            "POST",
            "/v1/admin/safety-responsibility-routes",
            parallel_route,
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403, denied

        status, parallel = _json_request(
            server,
            "POST",
            "/v1/admin/safety-responsibility-routes",
            parallel_route,
            headers=_headers(admin_cookie, admin_csrf),
        )
        assert status == 200, parallel
        assert parallel["reconciled_alerts"] >= 1
        reconciled = server.edge_repository.get_alert(alert["alert_id"])
        assert reconciled is not None
        assert reconciled["assignee"] == "supervisor"
        routed = {
            item["route_id"]: item
            for item in reconciled["recipients"]
            if item["route_id"] is not None
        }
        assert routed["m001-authorization-yellow"]["recipient_role"] == (
            "primary"
        )
        assert routed["m001-all-yellow"]["recipient_role"] == "observer"
        assert routed["m001-all-yellow"]["read_at"] is not None

        status, duplicate = _json_request(
            server,
            "POST",
            "/v1/admin/safety-responsibility-routes",
            parallel_route,
            headers=_headers(admin_cookie, admin_csrf),
        )
        assert status == 200, duplicate
        assert duplicate["reconciled_alerts"] == 0

        outside = _seed_alert(
            server,
            mine_id="M002",
            rule_code="responsibility-outside",
        )
        status, denied = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{outside['alert_id']}/read",
            {"expected_version": outside["version"]},
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403, denied

        status, deleted = _json_request(
            server,
            "POST",
            (
                "/v1/admin/safety-responsibility-routes/"
                "m001-all-yellow/actions"
            ),
            {"action": "delete"},
            headers=_headers(admin_cookie, admin_csrf),
        )
        assert status == 200, deleted
        assert deleted["deleted"] is True


def test_safety_attachment_permissions_integrity_and_forced_download(
    tmp_path: Path,
) -> None:
    with _server(tmp_path) as (server, alerts):
        alert = alerts["M001"]
        alert_id = alert["alert_id"]
        content = b"%PDF-1.4\nattachment evidence\n%%EOF\n"

        def upload_body(
            payload: bytes = content,
            *,
            digest: str | None = None,
            media_type: str = "application/pdf",
        ) -> dict[str, Any]:
            return {
                "filename": "../../现场核查\r\n.exe",
                "media_type": media_type,
                "content_base64": base64.b64encode(payload).decode(),
                "sha256": digest or hashlib.sha256(payload).hexdigest(),
                "note": "现场核查材料",
            }

        viewer_cookie, viewer_csrf = _login(server, "viewer")
        status, denied = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert_id}/attachments",
            upload_body(),
            headers=_headers(viewer_cookie, viewer_csrf),
        )
        assert status == 403, denied

        reviewer_cookie, reviewer_csrf = _login(server, "reviewer")
        status, denied = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert_id}/attachments",
            upload_body(),
            headers=_headers(reviewer_cookie),
        )
        assert status == 403, denied

        status, mismatch = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert_id}/attachments",
            upload_body(digest="0" * 64),
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 400, mismatch
        assert mismatch["error"]["code"] == "attachment_sha256_mismatch"

        status, disguised = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert_id}/attachments",
            upload_body(b"MZ executable"),
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 400, disguised
        assert disguised["error"]["code"] == (
            "attachment_content_type_mismatch"
        )

        oversized = b"A" * (5 * 1024 * 1024 + 1)
        status, too_large = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert_id}/attachments",
            upload_body(oversized, media_type="text/plain"),
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 400, too_large
        assert too_large["error"]["code"] == "attachment_too_large"

        status, created = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert_id}/attachments",
            upload_body(),
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 201, created
        attachment = created["attachment"]
        assert attachment["filename"].endswith(".pdf")
        assert "/" not in attachment["filename"]
        assert "\r" not in attachment["filename"]
        assert "\n" not in attachment["filename"]
        assert attachment["sha256"] == hashlib.sha256(content).hexdigest()
        assert attachment["size_bytes"] == len(content)

        status, duplicate = _json_request(
            server,
            "POST",
            f"/v1/safety/alerts/{alert_id}/attachments",
            upload_body(),
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 409, duplicate
        assert duplicate["error"]["code"] == "safety_attachment_duplicate"

        status, listed = _json_request(
            server,
            "GET",
            f"/v1/safety/alerts/{alert_id}/attachments",
            headers=_headers(viewer_cookie),
        )
        assert status == 200, listed
        assert listed["count"] == 1
        assert "content" not in listed["items"][0]
        assert listed["items"][0]["sha256"] == attachment["sha256"]

        status, outside = _json_request(
            server,
            "GET",
            (
                f"/v1/safety/alerts/{alerts['M002']['alert_id']}/"
                "attachments"
            ),
            headers=_headers(viewer_cookie),
        )
        assert status == 403, outside

        status, outside_upload = _json_request(
            server,
            "POST",
            (
                f"/v1/safety/alerts/{alerts['M002']['alert_id']}/"
                "attachments"
            ),
            upload_body(),
            headers=_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403, outside_upload

        download_path = attachment["download_url"]
        status, downloaded, headers = _raw_request(
            server,
            "GET",
            download_path,
            headers=_headers(viewer_cookie),
        )
        assert status == 200
        assert downloaded == content
        assert headers["content-type"] == "application/octet-stream"
        assert headers["content-disposition"].startswith("attachment;")
        assert "inline" not in headers["content-disposition"]
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-download-options"] == "noopen"
        assert headers["cross-origin-resource-policy"] == "same-origin"
        assert headers["content-security-policy"] == (
            "sandbox; default-src 'none'"
        )

        detail = server.edge_repository.get_alert(alert_id)
        assert detail is not None
        assert detail["audit_chain_valid"] is True
        assert detail["events"][-1]["event_type"] == "attachment_added"
        audit_actions = {
            item["action"] for item in server.auth_store.list_audit_events()
        }
        assert "safety_alert_attachment_added" in audit_actions
        assert "safety_alert_attachment_downloaded" in audit_actions

        with server.edge_repository._lock:
            server.edge_repository._connection.execute(
                """
                UPDATE safety_alert_attachments
                SET content = ?
                WHERE attachment_id = ?
                """,
                (b"tampered", attachment["attachment_id"]),
            )
        status, integrity = _json_request(
            server,
            "GET",
            download_path,
            headers=_headers(viewer_cookie),
        )
        assert status == 409, integrity
        assert integrity["error"]["code"] == (
            "safety_attachment_integrity_failed"
        )
