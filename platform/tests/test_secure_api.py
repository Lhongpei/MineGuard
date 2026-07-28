from __future__ import annotations

import http.client
import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

import mineguard.api as api_module
from mineguard.api import create_server
from mineguard.governance import (
    GovernedObservation,
    GovernedProductionRequest,
    sha256_json as governance_sha256_json,
)


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def secure_server(tmp_path: Path) -> Iterator[tuple[str, int]]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=True,
        auth_database_path=tmp_path / "auth.db",
        bootstrap_admin=("admin", "correct admin password"),
        secure_cookie=False,
        job_database_path=tmp_path / "jobs.db",
        evidence_database_path=tmp_path / "evidence.db",
        evidence_directory=tmp_path / "evidence",
        evidence_secret=b"test-evidence-secret-with-32-bytes!",
        governance_database_path=tmp_path / "governance.db",
        source_key_directory=tmp_path / "source-keys",
        backup_directory=tmp_path / "backups",
        backup_secret=b"test-backup-secret-with-32-bytes!!",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def raw_request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: Any | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
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


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: Any | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    status, raw, response_headers = raw_request(
        host,
        port,
        method,
        path,
        body,
        headers=headers,
    )
    return status, json.loads(raw), response_headers


def login(
    host: str,
    port: int,
    username: str,
    password: str,
) -> tuple[str, str, dict[str, Any]]:
    status, payload, headers = request(
        host,
        port,
        "POST",
        "/v1/auth/login",
        {"username": username, "password": password},
    )
    assert status == 200
    cookie = headers["set-cookie"].split(";", 1)[0]
    return cookie, payload["csrf_token"], payload["principal"]


def auth_headers(cookie: str, csrf: str | None = None) -> dict[str, str]:
    headers = {"Cookie": cookie}
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    return headers


def production(name: str, mine_id: str) -> dict[str, Any]:
    payload = json.loads((ROOT / "examples" / name).read_text())
    payload["mine_id"] = mine_id
    return payload


def create_user(
    host: str,
    port: int,
    cookie: str,
    csrf: str,
    *,
    username: str,
    password: str,
    role: str,
    mine_scopes: list[str],
) -> None:
    status, _, _ = request(
        host,
        port,
        "POST",
        "/v1/admin/users",
        {
            "username": username,
            "password": password,
            "role": role,
            "mine_scopes": mine_scopes,
        },
        headers=auth_headers(cookie, csrf),
    )
    assert status == 201


def test_admin_user_lifecycle_guards_and_access_updates(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )

        status, denied, _ = request(
            host,
            port,
            "POST",
            "/v1/admin/users/admin/status",
            {"active": False},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 409
        assert denied["error"]["code"] == "cannot_disable_self"
        status, _, _ = request(
            host,
            port,
            "GET",
            "/v1/auth/me",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200

        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="alice",
            password="alice password",
            role="reviewer",
            mine_scopes=["M001"],
        )
        alice_cookie, _, _ = login(
            host,
            port,
            "alice",
            "alice password",
        )

        status, invalid, _ = request(
            host,
            port,
            "POST",
            "/v1/admin/users/alice/access",
            {"role": "supervisor", "mine_scopes": []},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 400
        assert invalid["error"]["code"] == "invalid_user_access"

        status, csrf_denied, _ = request(
            host,
            port,
            "POST",
            "/v1/admin/users/alice/access",
            {"role": "supervisor", "mine_scopes": ["M002", "M001"]},
            headers=auth_headers(admin_cookie),
        )
        assert status == 403
        assert csrf_denied["error"]["code"] == "csrf_invalid"

        status, changed, _ = request(
            host,
            port,
            "POST",
            "/v1/admin/users/alice/access",
            {"role": "supervisor", "mine_scopes": ["M002", "M001"]},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert changed["user"]["role"] == "supervisor"
        assert changed["user"]["mine_scopes"] == ["M001", "M002"]
        assert changed["sessions_revoked"] is True
        assert changed["reauthentication_required"] is False

        status, expired, _ = request(
            host,
            port,
            "GET",
            "/v1/auth/me",
            headers=auth_headers(alice_cookie),
        )
        assert status == 401
        assert expired["error"]["code"] == "session_invalid"

        status, missing, _ = request(
            host,
            port,
            "POST",
            "/v1/admin/users/missing/access",
            {"role": "viewer", "mine_scopes": ["M001"]},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 404
        assert missing["error"]["code"] == "user_not_found"

        status, last_admin, _ = request(
            host,
            port,
            "POST",
            "/v1/admin/users/admin/access",
            {"role": "viewer", "mine_scopes": ["M001"]},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 409
        assert last_admin["error"]["code"] == "last_active_admin"

        status, audit, _ = request(
            host,
            port,
            "GET",
            "/v1/admin/audit",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        actions = [item["action"] for item in audit["items"]]
        assert "user_access_changed" in actions
        assert "admin_user_access_changed" in actions
        assert "admin_self_disable_denied" in actions
        assert "admin_last_active_admin_change_denied" in actions


def test_admin_resetting_own_password_requires_reauthentication(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        status, changed, headers = request(
            host,
            port,
            "POST",
            "/v1/admin/users/admin/reset-password",
            {"new_password": "replacement admin password"},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert changed["sessions_revoked"] is True
        assert changed["reauthentication_required"] is True
        assert "Max-Age=0" in headers["set-cookie"]

        status, expired, _ = request(
            host,
            port,
            "GET",
            "/v1/auth/me",
            headers=auth_headers(admin_cookie),
        )
        assert status == 401
        assert expired["error"]["code"] == "session_invalid"
        login(
            host,
            port,
            "admin",
            "replacement admin password",
        )


def test_batch_preview_is_admin_only_and_does_not_persist(
    tmp_path: Path,
) -> None:
    body = {
        "batch_id": "secure-pilot-preview",
        "portfolio_name": "脱敏试点辖区",
        "expected_mine_ids": ["M001"],
        "analyses": [
            production("production_inconsistent.json", "M001")
        ],
    }

    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="preview-supervisor",
            password="supervisor password",
            role="supervisor",
            mine_scopes=["M001"],
        )
        supervisor_cookie, supervisor_csrf, _ = login(
            host,
            port,
            "preview-supervisor",
            "supervisor password",
        )

        status, denied, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch?preview=1",
            body,
            headers=auth_headers(
                supervisor_cookie,
                supervisor_csrf,
            ),
        )
        assert status == 403
        assert denied["error"]["code"] == "trusted_ingest_required"

        status, preview, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch?preview=1",
            body,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert preview["batch_id"] == body["batch_id"]
        assert "temporal_audit" not in preview

    with sqlite3.connect(tmp_path / "main.db") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM batches"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM cases"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM analysis_feature_windows"
        ).fetchone()[0] == 0


def test_batch_lifecycle_requires_admin_and_csrf(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="batch-supervisor",
            password="supervisor password",
            role="supervisor",
            mine_scopes=["M001"],
        )
        supervisor_cookie, supervisor_csrf, _ = login(
            host,
            port,
            "batch-supervisor",
            "supervisor password",
        )
        body = {
            "batch_id": "secure-lifecycle-batch",
            "portfolio_name": "批次权限测试",
            "expected_mine_ids": ["M001"],
            "analyses": [
                production("production_inconsistent.json", "M001")
            ],
        }
        status, _, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            body,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        action_path = (
            "/v1/analysis-batches/secure-lifecycle-batch/status"
        )
        lifecycle = {
            "active": False,
            "reason": "仅验证批次权限",
            "expected_version": 1,
        }

        status, csrf_denied, _ = request(
            host,
            port,
            "POST",
            action_path,
            lifecycle,
            headers=auth_headers(admin_cookie),
        )
        assert status == 403
        assert csrf_denied["error"]["code"] == "csrf_invalid"

        status, role_denied, _ = request(
            host,
            port,
            "POST",
            action_path,
            lifecycle,
            headers=auth_headers(
                supervisor_cookie,
                supervisor_csrf,
            ),
        )
        assert status == 403
        assert role_denied["error"]["code"] == "permission_denied"

        status, changed, _ = request(
            host,
            port,
            "POST",
            action_path,
            lifecycle,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert changed["changed"] is True
        assert changed["lifecycle"]["active"] is False
        assert changed["lifecycle_chain_valid"] is True


def test_authentication_csrf_and_mine_scope_are_enforced(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        status, readiness, _ = request(
            host,
            port,
            "GET",
            "/ready",
        )
        assert status == 200
        assert readiness["status"] == "ready"

        status, payload, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
        )
        assert status == 401
        assert payload["error"]["code"] == "authentication_required"

        admin_cookie, admin_csrf, principal = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        assert principal["role"] == "admin"
        status, overview, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert overview["operating_mode"] == "trusted_intranet_shadow"
        assert overview["local_trial"] is False
        assert overview["batch_data_mode"] is None

        status, backup, _ = request(
            host,
            port,
            "POST",
            "/v1/admin/backups",
            {"backup_id": "acceptance-001"},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 201
        assert backup["verification"] == "valid"
        assert {
            item["filename"] for item in backup["manifest"]["files"]
        } == {
            "auth.db",
            "evidence.db",
            "governance.db",
            "jobs.db",
            "mineguard.db",
            "source-keys.db",
        }
        status, readiness, _ = request(
            host,
            port,
            "GET",
            "/ready",
        )
        assert status == 200
        assert readiness["status"] == "ready"
        status, verified, _ = request(
            host,
            port,
            "GET",
            "/v1/admin/backups/acceptance-001/verify",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert verified["verification"] == "valid"

        body = {
            "batch_id": "secure-batch",
            "portfolio_name": "安全测试",
            "expected_mine_ids": ["M001"],
            "analyses": [
                production("production_inconsistent.json", "M001")
            ],
        }
        status, payload, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            body,
            headers=auth_headers(admin_cookie),
        )
        assert status == 403
        assert payload["error"]["code"] == "csrf_invalid"

        status, _, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            body,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200

        status, trends, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/trends?days=30",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert trends["analytics"]["expected_report_count"] == 1
        assert trends["analytics"]["mine_risk_ranking"][0]["mine_id"] == "M001"

        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="viewer-m002",
            password="viewer password",
            role="viewer",
            mine_scopes=["M002"],
        )
        viewer_cookie, viewer_csrf, _ = login(
            host,
            port,
            "viewer-m002",
            "viewer password",
        )
        status, cases, _ = request(
            host,
            port,
            "GET",
            "/v1/cases",
            headers=auth_headers(viewer_cookie),
        )
        assert status == 200
        assert cases["total"] == 0

        status, overview, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/overview",
            headers=auth_headers(viewer_cookie),
        )
        assert status == 200
        assert overview["batch"] is None
        status, scoped_trends, _ = request(
            host,
            port,
            "GET",
            "/v1/dashboard/trends?days=30",
            headers=auth_headers(viewer_cookie),
        )
        assert status == 200
        assert scoped_trends["analytics"]["expected_report_count"] == 0
        assert "M001" not in json.dumps(scoped_trends)

        status, changed, headers = request(
            host,
            port,
            "POST",
            "/v1/auth/change-password",
            {
                "current_password": "viewer password",
                "new_password": "viewer replacement password",
            },
            headers=auth_headers(viewer_cookie, viewer_csrf),
        )
        assert status == 200
        assert changed["reauthentication_required"] is True
        assert "Max-Age=0" in headers["set-cookie"]
        status, _, _ = request(
            host,
            port,
            "GET",
            "/v1/auth/me",
            headers=auth_headers(viewer_cookie),
        )
        assert status == 401
        login(
            host,
            port,
            "viewer-m002",
            "viewer replacement password",
        )


def test_double_review_evidence_and_background_job_flow(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        for username, role in (
            ("reviewer-a", "reviewer"),
            ("supervisor-b", "supervisor"),
        ):
            create_user(
                host,
                port,
                admin_cookie,
                admin_csrf,
                username=username,
                password=f"{username} password",
                role=role,
                mine_scopes=["M001"],
            )

        batch = {
            "batch_id": "approval-batch",
            "portfolio_name": "审批测试",
            "expected_mine_ids": ["M001"],
            "analyses": [
                production("production_inconsistent.json", "M001")
            ],
        }
        status, _, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            batch,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        _, cases, _ = request(
            host,
            port,
            "GET",
            "/v1/cases",
            headers=auth_headers(admin_cookie),
        )
        case = cases["items"][0]

        reviewer_cookie, reviewer_csrf, _ = login(
            host,
            port,
            "reviewer-a",
            "reviewer-a password",
        )
        status, submitted, _ = request(
            host,
            port,
            "POST",
            f"/v1/cases/{case['case_id']}/actions",
            {
                "action": "submit_conclusion",
                "expected_version": case["version"],
                "note": "原始记录支持部分技术线索，提交审批。",
                "disposition": "partially_supported",
            },
            headers=auth_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 200
        submitted_case = submitted["case"]
        assert submitted_case["workflow_status"] == "pending_approval"

        status, denied, _ = request(
            host,
            port,
            "POST",
            f"/v1/cases/{case['case_id']}/actions",
            {
                "action": "approve",
                "expected_version": submitted_case["version"],
                "note": "不应允许复核员审批",
            },
            headers=auth_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"

        supervisor_cookie, supervisor_csrf, _ = login(
            host,
            port,
            "supervisor-b",
            "supervisor-b password",
        )
        status, approved, _ = request(
            host,
            port,
            "POST",
            f"/v1/cases/{case['case_id']}/actions",
            {
                "action": "approve",
                "expected_version": submitted_case["version"],
                "note": "已复核原始依据，同意关闭。",
            },
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 200
        assert approved["case"]["workflow_status"] == "closed"

        status, evidence, _ = request(
            host,
            port,
            "POST",
            f"/v1/cases/{case['case_id']}/evidence",
            {"expected_version": approved["case"]["version"]},
            headers=auth_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 201
        assert evidence["verification"]["valid"] is True
        bundle_id = evidence["evidence"]["bundle_id"]

        status, bundle, headers = raw_request(
            host,
            port,
            "GET",
            f"/v1/evidence/{bundle_id}",
            headers=auth_headers(reviewer_cookie),
        )
        assert status == 200
        assert headers["content-type"] == "application/zip"
        assert bundle.startswith(b"PK")

        job_body = {
            "idempotency_key": "secure-job",
            "windows": [
                {
                    "window_id": "M001-20260720",
                    "mine_id": "M001",
                    "payload": production(
                        "production_consistent.json",
                        "M001",
                    ),
                }
            ],
        }
        status, submitted_job, _ = request(
            host,
            port,
            "POST",
            "/v1/analysis-jobs",
            job_body,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 202
        job_id = submitted_job["job"]["job_id"]
        deadline = time.monotonic() + 5
        while True:
            status, job_payload, _ = request(
                host,
                port,
                "GET",
                f"/v1/analysis-jobs/{job_id}",
                headers=auth_headers(admin_cookie),
            )
            assert status == 200
            if job_payload["job"]["status"] == "succeeded":
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)


def test_conclusion_withdrawal_and_reopen_permissions(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        for username, role in (
            ("reviewer-a", "reviewer"),
            ("reviewer-b", "reviewer"),
            ("supervisor-c", "supervisor"),
        ):
            create_user(
                host,
                port,
                admin_cookie,
                admin_csrf,
                username=username,
                password=f"{username} password",
                role=role,
                mine_scopes=["M001"],
            )

        status, _, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            {
                "batch_id": "withdrawal-batch",
                "portfolio_name": "撤回与重开权限测试",
                "expected_mine_ids": ["M001"],
                "analyses": [
                    production("production_inconsistent.json", "M001")
                ],
            },
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        status, cases, _ = request(
            host,
            port,
            "GET",
            "/v1/cases",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        case = cases["items"][0]
        action_path = f"/v1/cases/{case['case_id']}/actions"

        reviewer_a_cookie, reviewer_a_csrf, _ = login(
            host,
            port,
            "reviewer-a",
            "reviewer-a password",
        )
        status, submitted, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "submit_conclusion",
                "expected_version": case["version"],
                "note": "提交技术问题结论。",
                "disposition": "confirmed_technical_issue",
            },
            headers=auth_headers(reviewer_a_cookie, reviewer_a_csrf),
        )
        assert status == 200
        submitted_case = submitted["case"]

        reviewer_b_cookie, reviewer_b_csrf, _ = login(
            host,
            port,
            "reviewer-b",
            "reviewer-b password",
        )
        status, denied, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "withdraw_conclusion",
                "expected_version": submitted_case["version"],
                "note": "无权撤回他人的结论。",
            },
            headers=auth_headers(reviewer_b_cookie, reviewer_b_csrf),
        )
        assert status == 409
        assert denied["error"]["code"] == "invalid_case_action"

        status, missing_reason, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "withdraw_conclusion",
                "expected_version": submitted_case["version"],
            },
            headers=auth_headers(reviewer_a_cookie, reviewer_a_csrf),
        )
        assert status == 409
        assert missing_reason["error"]["code"] == "invalid_case_action"

        status, withdrawn, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "withdraw_conclusion",
                "expected_version": submitted_case["version"],
                "note": "发现设备时钟记录尚未核对，撤回继续复核。",
            },
            headers=auth_headers(reviewer_a_cookie, reviewer_a_csrf),
        )
        assert status == 200
        withdrawn_case = withdrawn["case"]
        assert withdrawn_case["workflow_status"] == "reviewing"
        assert withdrawn_case["disposition"] is None
        assert withdrawn_case["conclusion_by"] is None
        assert withdrawn["events"][-2]["action"] == "submit_conclusion"
        assert withdrawn["events"][-1]["action"] == "withdraw_conclusion"
        assert withdrawn["audit_chain_valid"] is True

        status, resubmitted, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "submit_conclusion",
                "expected_version": withdrawn_case["version"],
                "note": "补充核对完成，再次提交结论。",
                "disposition": "confirmed_technical_issue",
            },
            headers=auth_headers(reviewer_a_cookie, reviewer_a_csrf),
        )
        assert status == 200

        supervisor_cookie, supervisor_csrf, _ = login(
            host,
            port,
            "supervisor-c",
            "supervisor-c password",
        )
        status, approved, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "approve",
                "expected_version": resubmitted["case"]["version"],
                "note": "同意结论并关闭。",
            },
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 200
        assert approved["case"]["workflow_status"] == "closed"

        status, reopen_denied, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "reopen",
                "expected_version": approved["case"]["version"],
                "note": "复核员不应有权重开。",
            },
            headers=auth_headers(reviewer_a_cookie, reviewer_a_csrf),
        )
        assert status == 403
        assert reopen_denied["error"]["code"] == "permission_denied"

        status, reopened, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "reopen",
                "expected_version": approved["case"]["version"],
                "note": "主管决定补充调阅材料，重新打开。",
            },
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 200
        assert reopened["case"]["workflow_status"] == "reviewing"
        assert reopened["events"][-1]["action"] == "reopen"
        assert reopened["audit_chain_valid"] is True


def test_case_archive_requires_approval_and_is_hidden_by_default(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="archive-reviewer",
            password="reviewer password",
            role="reviewer",
            mine_scopes=["M001"],
        )
        reviewer_cookie, reviewer_csrf, _ = login(
            host,
            port,
            "archive-reviewer",
            "reviewer password",
        )

        status, _, _ = request(
            host,
            port,
            "POST",
            "/v1/analyze/production/batch",
            {
                "batch_id": "archive-batch",
                "portfolio_name": "案件软归档测试",
                "expected_mine_ids": ["M001"],
                "analyses": [
                    production("production_inconsistent.json", "M001")
                ],
            },
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        status, listed, _ = request(
            host,
            port,
            "GET",
            "/v1/cases",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        case = listed["items"][0]
        case_id = case["case_id"]
        action_path = f"/v1/cases/{case_id}/actions"

        status, submitted, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "submit_conclusion",
                "expected_version": case["version"],
                "note": "完成原始数据复核，提交结论。",
                "disposition": "confirmed_technical_issue",
            },
            headers=auth_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 200
        status, approved, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "approve",
                "expected_version": submitted["case"]["version"],
                "note": "复核通过并关闭。",
            },
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        closed = approved["case"]

        status, denied, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "archive_case",
                "expected_version": closed["version"],
                "note": "复核员无归档权限。",
            },
            headers=auth_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"

        status, missing_reason, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "archive_case",
                "expected_version": closed["version"],
            },
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 409
        assert missing_reason["error"]["code"] == "invalid_case_action"

        status, archived, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "archive_case",
                "expected_version": closed["version"],
                "note": "案件已闭环，移出日常监管列表。",
            },
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        archived_case = archived["case"]
        assert archived_case["workflow_status"] == "closed"
        assert archived_case["archived_by"] == "admin"
        assert archived_case["archived_reason"] == "案件已闭环，移出日常监管列表。"
        assert archived_case["version"] == closed["version"] + 1
        assert archived["events"][-1]["action"] == "archive_case"
        assert archived["audit_chain_valid"] is True

        status, default_list, _ = request(
            host,
            port,
            "GET",
            "/v1/cases",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert default_list == {"items": [], "total": 0}
        status, archived_list, _ = request(
            host,
            port,
            "GET",
            "/v1/cases?include_archived=1",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert archived_list["total"] == 1
        assert archived_list["items"][0]["case_id"] == case_id
        status, invalid_query, _ = request(
            host,
            port,
            "GET",
            "/v1/cases?include_archived=true",
            headers=auth_headers(admin_cookie),
        )
        assert status == 400
        assert invalid_query["error"]["code"] == "invalid_query"

        status, detail, _ = request(
            host,
            port,
            "GET",
            f"/v1/cases/{case_id}",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert detail["case"]["archived_at"] is not None

        status, restore_denied, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "restore_case",
                "expected_version": archived_case["version"],
                "note": "尝试恢复已归档事项。",
            },
            headers=auth_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403
        assert restore_denied["error"]["code"] == "permission_denied"

        status, restored, _ = request(
            host,
            port,
            "POST",
            action_path,
            {
                "action": "restore_case",
                "expected_version": archived_case["version"],
                "note": "重新纳入常用台账复查。",
            },
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert restored["case"]["workflow_status"] == "closed"
        assert restored["case"]["archived_at"] is None
        assert restored["case"]["version"] == archived_case["version"] + 1
        assert restored["events"][-1]["action"] == "restore_case"
        assert restored["audit_chain_valid"] is True

        status, visible_again, _ = request(
            host,
            port,
            "GET",
            "/v1/cases",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert visible_again["total"] == 1
        assert visible_again["items"][0]["case_id"] == case_id


def test_governed_ingest_derives_trust_fields_and_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_refresh = api_module.refresh_temporal_audit
    refresh_calls: list[set[str] | None] = []

    def fail_each_new_path_once(
        repository: Any,
        *,
        mine_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        refresh_calls.append(
            None if mine_ids is None else set(mine_ids)
        )
        if len(refresh_calls) in {1, 3, 5}:
            raise RuntimeError("simulated temporal refresh failure")
        return original_refresh(repository, mine_ids=mine_ids)

    monkeypatch.setattr(
        api_module,
        "refresh_temporal_audit",
        fail_each_new_path_once,
    )
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="trusted-supervisor",
            password="supervisor password",
            role="supervisor",
            mine_scopes=["M001"],
        )
        supervisor_cookie, supervisor_csrf, _ = login(
            host,
            port,
            "trusted-supervisor",
            "supervisor password",
        )

        start = datetime(2026, 7, 20, tzinfo=UTC)
        end = start + timedelta(days=1)
        metrics = [
            ("reported", "coal.reported_output_t", 1000.0),
            ("transport", "coal.main_transport_t", 1000.0),
            ("wash", "wash.feed_t", 800.0),
            ("sales", "sales.raw_shipped_t", 100.0),
            ("stock", "inventory.raw_change_t", 100.0),
        ]
        secrets_by_source = {
            source_id: f"trusted-secret-{source_id}-0123456789"
            for source_id, _, _ in metrics
        }
        profile = {
            "profile": {
                "profile_id": "trusted-five-flow",
                "version": "2026.1",
                "effective_from": "2026-01-01T00:00:00Z",
                "effective_to": "2027-01-01T00:00:00Z",
                "parameters": {
                    "transport_balance_tolerance": 25.0,
                    "stock_balance_tolerance": 30.0,
                    "transport_slack_penalty": 80.0,
                    "stock_slack_penalty": 90.0,
                    "max_mcs": 4,
                    "max_relaxed_groups": 2,
                    "quality_gate": 60.0,
                },
                "required_metrics": [metric for _, metric, _ in metrics],
                "approved": True,
            }
        }
        status, _, _ = request(
            host,
            port,
            "POST",
            "/v1/governance/profiles",
            profile,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 201

        for index, (source_id, metric, _) in enumerate(metrics, start=1):
            registration = {
                "definition": {
                    "source_id": source_id,
                    "mine_id": "M001",
                    "metric_code": metric,
                    "root_source_group": f"root-{source_id}",
                    "unit": "t",
                    "tolerance_abs": float(10 + index),
                    "reliability": 0.95,
                    "max_delay_seconds": 60.0,
                    "calibration_valid_until": "2026-12-31T00:00:00Z",
                    "active": True,
                },
                "version": 1,
                "effective_from": "2026-01-01T00:00:00Z",
                "hmac_secret": secrets_by_source[source_id],
            }
            status, _, _ = request(
                host,
                port,
                "POST",
                "/v1/governance/sources",
                registration,
                headers=auth_headers(admin_cookie, admin_csrf),
            )
            assert status == 201

        status, denied, _ = request(
            host,
            port,
            "GET",
            "/v1/governance/sources",
            headers=auth_headers(supervisor_cookie),
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"

        observations = []
        for index, (source_id, _, value) in enumerate(metrics, start=1):
            observation = GovernedObservation.signed(
                secret=secrets_by_source[source_id],
                source_id=source_id,
                observation_id=f"trusted-{source_id}-1",
                value=value,
                unit="t",
                observed_at=start + timedelta(minutes=index),
                received_at=start + timedelta(minutes=index, seconds=5),
                sequence_no=1,
                revision=0,
            )
            observations.append(observation.model_dump(mode="json"))
        ingest = {
            "mine_id": "M001",
            "window_start": start.isoformat(),
            "window_end": end.isoformat(),
            "profile_id": "trusted-five-flow",
            "profile_version": "2026.1",
            "operational_context": {
                "regime_code": "longwall",
                "shift_code": "daily",
                "season_code": "summer",
                "maintenance": False,
                "approved_event_codes": [],
                "tags": ["raw-coal"],
            },
            "observations": observations,
        }
        status, result, _ = request(
            host,
            port,
            "POST",
            "/v1/ingest/production",
            ingest,
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 201
        assert result["created"] is True
        governed_request_sha256 = governance_sha256_json(
            GovernedProductionRequest.model_validate_json(
                json.dumps(ingest)
            )
        )
        assert result["batch"]["batch_id"] == (
            f"trusted-{governed_request_sha256[:32]}"
        )
        assert result["governance"]["accepted_count"] == 5
        assert len(result["governance"]["registry_snapshot_hash"]) == 64
        governed_item = result["batch"]["items"][0]
        assert governed_item["technical_status"] == "consistent"
        assert governed_item["review_priority"] == "DATA"
        assert (
            governed_item["analysis"]["data_quality"]["status"]
            == "degraded"
        )
        assert (
            len(
                governed_item["analysis"]["data_quality"][
                    "unverified_dimensions"
                ]
            )
            == 10
        )
        assert "未验证" in governed_item["summary"]
        assert "无需" not in governed_item["summary"]
        assert (
            governed_item["historical_evidence"]["assessment"]["status"]
            == "insufficient_history"
        )
        assert (
            governed_item["historical_evidence"][
                "operational_context"
            ]["regime_code"]
            == "longwall"
        )
        assert (
            governed_item["evidence_fusion"][
                "physical_status_unchanged"
            ]
            is True
        )
        assert (
            result["governance"]["operational_context"]["shift_code"]
            == "daily"
        )
        assert result["temporal_audit"]["status"] == "refresh_failed"

        status, repeated, _ = request(
            host,
            port,
            "POST",
            "/v1/ingest/production",
            ingest,
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 200
        assert repeated["created"] is False
        assert repeated["temporal_audit"]["status"] != "refresh_failed"

        governed_portfolio_request = {
            "batch_id": "trusted-portfolio-20260720-r1",
            "portfolio_name": "可信接入辖区日报",
            "expected_mine_ids": ["M001", "M002"],
            "analyses": [ingest],
        }
        status, governed_batch, _ = request(
            host,
            port,
            "POST",
            "/v1/ingest/production/batch",
            governed_portfolio_request,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 201
        assert governed_batch["partial"] is True
        assert governed_batch["governance"]["accepted_mine_count"] == 1
        assert (
            governed_batch["temporal_audit"]["status"]
            == "refresh_failed"
        )
        by_mine = {
            item["mine_id"]: item
            for item in governed_batch["batch"]["items"]
        }
        assert by_mine["M001"]["technical_status"] == "consistent"
        assert by_mine["M002"]["technical_status"] == "not_received"
        assert any(
            issue["code"] == "idempotent_observation_retry"
            for issue in governed_batch["governance"]["mine_reports"][0][
                "quality_issues"
            ]
        )

        status, repeated_batch, _ = request(
            host,
            port,
            "POST",
            "/v1/ingest/production/batch",
            governed_portfolio_request,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert repeated_batch["created"] is False
        assert (
            repeated_batch["temporal_audit"]["status"]
            != "refresh_failed"
        )

        governed_job_request = {
            "idempotency_key": "trusted-governed-job",
            "windows": [
                {
                    "window_id": "M001-20260720-trusted",
                    "request": ingest,
                }
            ],
        }
        status, trusted_job, _ = request(
            host,
            port,
            "POST",
            "/v1/ingest/production/jobs",
            governed_job_request,
            headers=auth_headers(
                supervisor_cookie,
                supervisor_csrf,
            ),
        )
        assert status == 202
        trusted_job_id = trusted_job["job"]["job_id"]
        deadline = time.monotonic() + 5
        while True:
            status, trusted_job_status, _ = request(
                host,
                port,
                "GET",
                f"/v1/analysis-jobs/{trusted_job_id}",
                headers=auth_headers(supervisor_cookie),
            )
            assert status == 200
            current_status = trusted_job_status["job"]["status"]
            if current_status in {
                "succeeded",
                "failed",
                "partial_failed",
                "cancelled",
            }:
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert current_status == "succeeded"
        first_job_result = trusted_job_status["job"]["outcomes"][0][
            "result"
        ]
        assert (
            first_job_result["batch"]["items"][0]["technical_status"]
            == "consistent"
        )
        assert (
            first_job_result["temporal_audit"]["status"]
            == "refresh_failed"
        )

        retry_job_request = json.loads(
            json.dumps(governed_job_request)
        )
        retry_job_request["idempotency_key"] = (
            "trusted-governed-job-refresh-retry"
        )
        status, retry_job, _ = request(
            host,
            port,
            "POST",
            "/v1/ingest/production/jobs",
            retry_job_request,
            headers=auth_headers(
                supervisor_cookie,
                supervisor_csrf,
            ),
        )
        assert status == 202
        retry_job_id = retry_job["job"]["job_id"]
        deadline = time.monotonic() + 5
        while True:
            status, retry_job_status, _ = request(
                host,
                port,
                "GET",
                f"/v1/analysis-jobs/{retry_job_id}",
                headers=auth_headers(supervisor_cookie),
            )
            assert status == 200
            retry_status = retry_job_status["job"]["status"]
            if retry_status in {
                "succeeded",
                "failed",
                "partial_failed",
                "cancelled",
            }:
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)
        assert retry_status == "succeeded"
        retry_job_result = retry_job_status["job"]["outcomes"][0][
            "result"
        ]
        assert retry_job_result["created"] is False
        assert (
            retry_job_result["temporal_audit"]["status"]
            != "refresh_failed"
        )
        assert refresh_calls == [
            {"M001"},
            {"M001"},
            {"M001"},
            {"M001"},
            {"M001"},
            {"M001"},
        ]

        forged = json.loads(json.dumps(ingest))
        forged["observations"][0]["tolerance_abs"] = 1_000_000
        status, invalid, _ = request(
            host,
            port,
            "POST",
            "/v1/ingest/production",
            forged,
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 400
        assert invalid["error"]["code"] == "validation_error"

        status, denied_job, _ = request(
            host,
            port,
            "POST",
            "/v1/analysis-jobs",
            {
                "idempotency_key": "untrusted-supervisor-job",
                "windows": [
                    {
                        "window_id": "one",
                        "mine_id": "M001",
                        "payload": production(
                            "production_consistent.json",
                            "M001",
                        ),
                    }
                ],
            },
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 403
        assert denied_job["error"]["code"] == "trusted_ingest_required"


def test_analysis_job_soft_archive_restore_scope_query_and_audit(
    tmp_path: Path,
) -> None:
    with secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf, _ = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        create_user(
            host,
            port,
            admin_cookie,
            admin_csrf,
            username="other-mine-supervisor",
            password="other mine supervisor password",
            role="supervisor",
            mine_scopes=["M002"],
        )
        supervisor_cookie, supervisor_csrf, _ = login(
            host,
            port,
            "other-mine-supervisor",
            "other mine supervisor password",
        )

        status, submitted, _ = request(
            host,
            port,
            "POST",
            "/v1/analysis-jobs",
            {
                "idempotency_key": "archive-api-job",
                "windows": [
                    {
                        "window_id": "archive-window",
                        "mine_id": "M001",
                        "payload": production(
                            "production_consistent.json",
                            "M001",
                        ),
                    }
                ],
            },
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 202
        job_id = submitted["job"]["job_id"]
        deadline = time.monotonic() + 5
        while True:
            status, detail, _ = request(
                host,
                port,
                "GET",
                f"/v1/analysis-jobs/{job_id}",
                headers=auth_headers(admin_cookie),
            )
            assert status == 200
            if detail["job"]["status"] == "succeeded":
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)

        status, denied, _ = request(
            host,
            port,
            "POST",
            f"/v1/analysis-jobs/{job_id}/archive",
            {"archived": True, "reason": "超出监管矿区"},
            headers=auth_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"

        status, archived, _ = request(
            host,
            port,
            "POST",
            f"/v1/analysis-jobs/{job_id}/archive",
            {"archived": True, "reason": "季度归档"},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert archived["job"]["archived_at"] is not None
        assert archived["job"]["archived_by"] == "admin"
        assert archived["job"]["archived_reason"] == "季度归档"

        status, active_list, _ = request(
            host,
            port,
            "GET",
            "/v1/analysis-jobs",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert job_id not in {
            item["job_id"] for item in active_list["items"]
        }

        status, all_jobs, _ = request(
            host,
            port,
            "GET",
            "/v1/analysis-jobs?include_archived=1",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert job_id in {item["job_id"] for item in all_jobs["items"]}

        for query in (
            "include_archived=0",
            "include_archived=1&include_archived=1",
            "unknown=1",
        ):
            status, invalid, _ = request(
                host,
                port,
                "GET",
                f"/v1/analysis-jobs?{query}",
                headers=auth_headers(admin_cookie),
            )
            assert status == 400
            assert invalid["error"]["code"] == "invalid_query"

        status, detail, _ = request(
            host,
            port,
            "GET",
            f"/v1/analysis-jobs/{job_id}",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert detail["job"]["archived_at"] is not None

        status, invalid_restore, _ = request(
            host,
            port,
            "POST",
            f"/v1/analysis-jobs/{job_id}/archive",
            {"archived": False},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 400
        assert invalid_restore["error"]["code"] == "validation_error"

        status, restored, _ = request(
            host,
            port,
            "POST",
            f"/v1/analysis-jobs/{job_id}/archive",
            {"archived": False, "reason": "恢复专项复核"},
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 200
        assert restored["job"]["archived_at"] is None

        status, active_list, _ = request(
            host,
            port,
            "GET",
            "/v1/analysis-jobs",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        assert job_id in {
            item["job_id"] for item in active_list["items"]
        }

        status, audit, _ = request(
            host,
            port,
            "GET",
            "/v1/admin/audit",
            headers=auth_headers(admin_cookie),
        )
        assert status == 200
        events = {
            item["action"]: item["detail"]
            for item in audit["items"]
            if item["detail"].get("job_id") == job_id
        }
        assert events["analysis_job_archived"]["reason"] == "季度归档"
        assert events["analysis_job_restored"]["reason"] == "恢复专项复核"
