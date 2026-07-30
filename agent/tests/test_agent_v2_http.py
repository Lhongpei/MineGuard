from __future__ import annotations

import http.client
import json
import threading
import time
from typing import Any

from enterprise_agent.auth import AuthManager, UserAccount, hash_password
from enterprise_agent.http_api import EnterpriseAgentHTTPServer
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository


def _request(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    cookie: str | None = None,
    csrf: str | None = None,
) -> tuple[int, dict[str, Any]]:
    encoded = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if encoded is not None else {}
    if cookie is not None:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    return response.status, json.loads(response.read())


def _account(
    actor_id: str,
    permissions: set[str],
) -> UserAccount:
    return UserAccount(
        actor_id=actor_id,
        name=actor_id,
        role="测试岗位",
        password_hash=hash_password(
            "test-password",
            iterations=100_000,
            salt=(actor_id.encode("utf-8") + b"0" * 16)[:16],
        ),
        permissions=frozenset(permissions),
    )


def _login(
    connection: http.client.HTTPConnection,
    actor_id: str,
) -> tuple[str, str]:
    encoded = json.dumps(
        {"actor_id": actor_id, "password": "test-password"}
    ).encode("utf-8")
    connection.request(
        "POST",
        "/api/v1/auth/login",
        body=encoded,
        headers={"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    payload = json.loads(response.read())
    assert response.status == 200
    set_cookie = response.getheader("Set-Cookie")
    assert set_cookie is not None
    cookie = set_cookie.split(";", 1)[0]
    return cookie, payload["csrf_token"]


def test_agent_v2_http_flow_scheduler_event_and_governance() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(
        {
            "enterprise_id": "enterprise-1",
            "enterprise_name": "测试能源企业",
            "mine_id": "mine-1",
            "mine_name": "测试矿井",
            "window_start": "2026-07-29T00:00:00Z",
            "window_end": "2026-07-30T00:00:00Z",
        },
        actor="operator-1",
    )
    server = EnterpriseAgentHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=5,
    )
    try:
        status, health = _request(connection, "GET", "/api/v1/health")
        assert status == 200
        assert health["agent_v2_available"] is True
        assert health["agent_v2_version"] == "enterprise-agent-flow-v2"
        assert health["agent_v2_scheduler_enabled"] is True
        assert health["agent_v2_governed_learning"] == "proposal_approval_only"

        status, created = _request(
            connection,
            "POST",
            "/api/v1/agent/flows",
            {
                "workflow_name": "daily_coal_health",
                "draft_id": draft["draft_id"],
                "goal_text": "检查当前草稿",
                "client_request_id": "http-flow-1",
            },
        )
        assert status == 202
        flow_id = created["flow"]["flow_id"]
        detail: dict[str, Any] = {}
        for _ in range(200):
            status, payload = _request(
                connection,
                "GET",
                f"/api/v1/agent/flows/{flow_id}",
            )
            assert status == 200
            detail = payload["flow"]
            if detail["status"] in {
                "succeeded",
                "blocked",
                "failed",
                "cancelled",
            }:
                break
            time.sleep(0.01)
        assert detail["integrity"]["valid"] is True
        assert detail["actor_id"] == "local-development"
        assert detail["status"] in {"succeeded", "blocked"}
        assert all(
            step["specialist"]
            in {
                "orchestrator",
                "source",
                "temporal",
                "physical",
                "historical",
                "dissenting_critic",
            }
            for step in detail["steps"]
        )

        status, listing = _request(
            connection,
            "GET",
            "/api/v1/agent/flows?limit=20&offset=0",
        )
        assert status == 200
        assert listing["total"] == 1
        assert listing["flows"][0]["flow_id"] == flow_id

        status, job_payload = _request(
            connection,
            "POST",
            "/api/v1/agent/jobs",
            {
                "name": "每小时煤炭体检",
                "workflow_name": "daily_coal_health",
                "draft_id": draft["draft_id"],
                "schedule_kind": "interval",
                "schedule": {"interval_seconds": 3600},
                "enabled": True,
            },
        )
        assert status == 201
        job = job_payload["job"]
        status, launched = _request(
            connection,
            "POST",
            f"/api/v1/agent/jobs/{job['job_id']}/run",
            {"client_request_id": "manual-job-run-1"},
        )
        assert status == 202
        assert launched["flow"]["trigger"]["type"] == "manual"
        status, current_job_payload = _request(
            connection,
            "GET",
            f"/api/v1/agent/jobs/{job['job_id']}",
        )
        assert status == 200
        current_job = current_job_payload["job"]
        status, updated_payload = _request(
            connection,
            "PATCH",
            f"/api/v1/agent/jobs/{job['job_id']}",
            {
                "expected_revision": current_job["revision"],
                "enabled": False,
            },
        )
        assert status == 200
        updated_job = updated_payload["job"]
        assert updated_job["enabled"] is False
        status, deleted = _request(
            connection,
            "DELETE",
            f"/api/v1/agent/jobs/{job['job_id']}",
            {"expected_revision": updated_job["revision"]},
        )
        assert status == 200
        assert deleted["deleted"] is True

        status, event_job_payload = _request(
            connection,
            "POST",
            "/api/v1/agent/jobs",
            {
                "name": "数据到达即体检",
                "draft_id": draft["draft_id"],
                "schedule_kind": "event",
                "schedule": {"event_type": "coal.data_arrived"},
            },
        )
        assert status == 201
        event_job_id = event_job_payload["job"]["job_id"]
        status, event_payload = _request(
            connection,
            "POST",
            "/api/v1/agent/events",
            {
                "event_type": "coal.data_arrived",
                "client_event_id": "http-event-1",
                "draft_id": draft["draft_id"],
                "payload": {"source_id": "scale-1", "record_count": 3},
            },
        )
        assert status == 202
        assert event_payload["event"]["triggered"]["succeeded"][0][
            "job_id"
        ] == event_job_id

        status, memory_payload = _request(
            connection,
            "POST",
            "/api/v1/agent/memory/proposals",
            {
                "scope_type": "user",
                "key": "preferred-shift-note",
                "value": {"note": "优先核对夜班皮带秤"},
                "reason": "用于后续只读分析提醒",
                "source_refs": [],
            },
        )
        assert status == 201
        proposal = memory_payload["proposal"]
        status, approved = _request(
            connection,
            "POST",
            (
                "/api/v1/agent/memory/proposals/"
                f"{proposal['proposal_id']}/decision"
            ),
            {
                "decision": "approve",
                "expected_revision": proposal["revision"],
                "reason": "本人作用域记忆，经人工确认",
            },
        )
        assert status == 200
        assert approved["memory"]["status"] == "active"

        status, skill_payload = _request(
            connection,
            "POST",
            "/api/v1/agent/skill-proposals",
            {
                "skill_name": "month-end-inventory-check",
                "description": "月末库存只读核对步骤",
                "procedure": "先汇总草稿\n再做确定性预检",
                "allowed_tools": [
                    "draft_summary",
                    "deterministic_preflight",
                ],
                "source_refs": [],
                "reason": "沉淀经人工复核的操作顺序",
            },
        )
        assert status == 201
        assert (
            skill_payload["proposal"]["runtime_activation"]
            == "proposal_only"
        )
        status, skills = _request(
            connection,
            "GET",
            "/api/v1/agent/skill-proposals",
        )
        assert status == 200
        assert skills["count"] == 1
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    assert service._agent_v2 is None
    assert service._agent_jobs is None


def test_agent_v2_http_enforces_actor_scope_and_permission_boundaries() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    draft = service.create_draft(
        {
            "enterprise_id": "enterprise-1",
            "mine_id": "mine-1",
        },
        actor="bootstrap",
    )
    accounts = (
        _account("reader-1", {"read"}),
        _account("editor-1", {"read", "write"}),
        _account(
            "reviewer-1",
            {"read", "write", "confirm", "governance_review", "skill_admin"},
        ),
    )
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,
        auth_manager=AuthManager(accounts, session_ttl_seconds=300),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=5,
    )
    try:
        reader_cookie, reader_csrf = _login(connection, "reader-1")
        editor_cookie, editor_csrf = _login(connection, "editor-1")
        reviewer_cookie, reviewer_csrf = _login(connection, "reviewer-1")

        status, denied = _request(
            connection,
            "POST",
            "/api/v1/agent/jobs",
            {
                "name": "读者不应创建",
                "draft_id": draft["draft_id"],
                "schedule_kind": "interval",
                "schedule": {"interval_seconds": 3600},
            },
            cookie=reader_cookie,
            csrf=reader_csrf,
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"

        status, created_flow = _request(
            connection,
            "POST",
            "/api/v1/agent/flows",
            {
                "draft_id": draft["draft_id"],
                "client_request_id": "editor-private-flow",
            },
            cookie=editor_cookie,
            csrf=editor_csrf,
        )
        assert status == 202
        flow_id = created_flow["flow"]["flow_id"]
        status, hidden = _request(
            connection,
            "GET",
            f"/api/v1/agent/flows/{flow_id}",
            cookie=reader_cookie,
        )
        assert status == 404
        assert hidden["error"]["code"] == "not_found"

        status, created_proposal = _request(
            connection,
            "POST",
            "/api/v1/agent/memory/proposals",
            {
                "scope_type": "draft",
                "scope_id": draft["draft_id"],
                "memory_key": "approved-maintenance-window",
                "value": {"note": "月末检修窗口需单独解释"},
                "reason": "用于草稿体检解释",
                "source_refs": [],
            },
            cookie=editor_cookie,
            csrf=editor_csrf,
        )
        assert status == 201
        proposal = created_proposal["proposal"]

        status, denied_decision = _request(
            connection,
            "POST",
            (
                "/api/v1/agent/memory/proposals/"
                f"{proposal['proposal_id']}/decision"
            ),
            {
                "decision": "approve",
                "expected_revision": proposal["revision"],
                "reason": "越权审批",
            },
            cookie=editor_cookie,
            csrf=editor_csrf,
        )
        assert status == 403
        assert denied_decision["error"]["code"] == "permission_denied"

        status, approved = _request(
            connection,
            "POST",
            (
                "/api/v1/agent/memory/proposals/"
                f"{proposal['proposal_id']}/decision"
            ),
            {
                "decision": "approve",
                "expected_revision": proposal["revision"],
                "reason": "由另一名复核人员核验批准",
            },
            cookie=reviewer_cookie,
            csrf=reviewer_csrf,
        )
        assert status == 200
        assert approved["memory"]["scope_type"] == "draft"
        assert approved["memory"]["status"] == "active"

        status, visible = _request(
            connection,
            "GET",
            "/api/v1/agent/memories",
            cookie=reader_cookie,
        )
        assert status == 200
        assert visible["count"] == 1
        assert visible["memories"][0]["memory_key"] == (
            "approved-maintenance-window"
        )
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
