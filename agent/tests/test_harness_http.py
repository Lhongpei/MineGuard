from __future__ import annotations

import http.client
import json
import threading
import time
from typing import Any

from enterprise_agent.http_api import EnterpriseAgentHTTPServer
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository


def _request(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    encoded = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if encoded else {}
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    return response.status, json.loads(response.read())


def test_harness_http_create_list_detail_cancel_and_health() -> None:
    service = EnterpriseAgentService(Repository(":memory:"))
    server = EnterpriseAgentHTTPServer(("127.0.0.1", 0), service)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1", server.server_address[1], timeout=3
    )
    try:
        status, health = _request(connection, "GET", "/api/v1/health")
        assert status == 200
        assert health["harness_available"] is True
        assert health["harness_version"] == "agent-harness-v1"
        assert health["tool_calling_mode"] == "deterministic"

        status, tools = _request(
            connection, "GET", "/api/v1/agent/tools"
        )
        assert status == 200
        assert tools["count"] >= 10
        assert not any(
            "confirm" in item["name"] or "submit" in item["name"]
            for item in tools["tools"]
        )
        assert all(
            isinstance(item["category"], str)
            and item["evidence_grounding"]
            in {
                "repository_grounded",
                "user_supplied",
                "external_public",
            }
            and isinstance(item["network_access"], bool)
            and isinstance(item["scenario_only"], bool)
            and isinstance(item["allowed_profiles"], list)
            for item in tools["tools"]
        )

        status, created = _request(
            connection,
            "POST",
            "/api/v1/agent/runs",
            {
                "task": "说明确定性能力",
                "mode": "deterministic",
                "actor_id": "forged",
            },
        )
        assert status == 202
        run_id = created["run"]["run_id"]
        for _ in range(200):
            status, detail = _request(
                connection, "GET", f"/api/v1/agent/runs/{run_id}"
            )
            assert status == 200
            if detail["run"]["status"] == "completed":
                break
            time.sleep(0.01)
        assert detail["run"]["actor_id"] == "local-development"
        assert detail["run"]["integrity"]["valid"] is True

        status, listed = _request(
            connection, "GET", "/api/v1/agent/runs?limit=20&offset=0"
        )
        assert status == 200
        assert listed["total"] == 1
        assert listed["runs"][0]["run_id"] == run_id
        assert listed["runs"][0]["tool_calls"] == []

        status, error = _request(
            connection,
            "POST",
            f"/api/v1/agent/runs/{run_id}/cancel",
            {},
        )
        assert status == 409
        assert error["error"]["code"] == "conflict"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
    assert service._harness is None
