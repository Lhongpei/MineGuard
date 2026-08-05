from __future__ import annotations

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from enterprise_connector.client import AgentClient
from enterprise_connector.errors import DeliveryError


class _AgentHandler(BaseHTTPRequestHandler):
    secret = b"s" * 32
    requests: list[dict[str, str]] = []
    committed_events: set[str] = set()
    drop_first_response = True
    error_code: str | None = None
    success_status = 200
    success_body: bytes | None = None
    success_content_type = "application/json"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        request_id = self.headers["X-Enterprise-Connector-Request-Id"]
        timestamp = self.headers["X-Enterprise-Connector-Timestamp"]
        material = (
            "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1\n"
            f"POST\n{self.path}\n"
            f"{timestamp}\n{request_id}\n{hashlib.sha256(body).hexdigest()}"
        ).encode()
        assert hmac.compare_digest(
            self.headers["X-Enterprise-Connector-Signature"],
            hmac.new(type(self).secret, material, hashlib.sha256).hexdigest(),
        )
        payload = json.loads(body)
        event_id = payload["event_id"]
        type(self).requests.append(
            {"request_id": request_id, "event_id": event_id, "timestamp": timestamp}
        )
        type(self).committed_events.add(event_id)
        if type(self).drop_first_response:
            type(self).drop_first_response = False
            self.connection.shutdown(2)
            self.connection.close()
            return
        if type(self).error_code:
            response = json.dumps(
                {"error": {"code": type(self).error_code, "message": "bounded"}}
            ).encode()
            self.send_response(409)
        else:
            response = type(self).success_body
            if response is None:
                response = json.dumps(
                    (
                        {
                            "contract_version": "enterprise-source-health-result/v1",
                            "event_id": event_id,
                            "status": "recorded",
                            "idempotent_replay": True,
                        }
                        if self.path == "/api/v1/machine/source-health"
                        else {
                            "contract_version": (
                                "enterprise-autofill-ingestion-result/v1"
                            ),
                            "event_id": event_id,
                            "status": "completed",
                            "draft_id": "draft-result-1",
                            "ingestion_id": "ingestion-result-1",
                            "idempotent_replay": True,
                        }
                    ),
                    separators=(",", ":"),
                ).encode()
            self.send_response(type(self).success_status)
        self.send_header("Content-Type", type(self).success_content_type)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@pytest.fixture
def agent_server():
    _AgentHandler.requests = []
    _AgentHandler.committed_events = set()
    _AgentHandler.drop_first_response = True
    _AgentHandler.error_code = None
    _AgentHandler.success_status = 200
    _AgentHandler.success_body = None
    _AgentHandler.success_content_type = "application/json"
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AgentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _client(server: ThreadingHTTPServer) -> AgentClient:
    return AgentClient(
        agent_url=f"http://127.0.0.1:{server.server_port}",
        client_id="test-connector",
        secret=b"s" * 32,
        timeout_seconds=1,
        max_response_bytes=10000,
        allowed_hosts=("127.0.0.1",),
        allowed_ports=(server.server_port,),
        allow_private_network=True,
    )


def test_lost_response_retries_with_new_nonce_but_same_business_event(
    agent_server: ThreadingHTTPServer,
) -> None:
    client = _client(agent_server)
    body = b'{"event_id":"cevt_business_once"}'
    with pytest.raises(DeliveryError) as failure:
        client.send("cevt_business_once", body)
    assert failure.value.retryable is True
    assert client.send("cevt_business_once", body) == 200
    assert len(_AgentHandler.committed_events) == 1
    assert [item["event_id"] for item in _AgentHandler.requests] == [
        "cevt_business_once",
        "cevt_business_once",
    ]
    assert _AgentHandler.requests[0]["request_id"] != _AgentHandler.requests[1]["request_id"]


def test_only_allowlisted_409_is_retryable(agent_server: ThreadingHTTPServer) -> None:
    _AgentHandler.drop_first_response = False
    _AgentHandler.error_code = "connector_ingestion_in_progress"
    with pytest.raises(DeliveryError) as in_progress:
        _client(agent_server).send("cevt-1", b'{"event_id":"cevt-1"}')
    assert in_progress.value.retryable is True
    _AgentHandler.error_code = "business_conflict"
    with pytest.raises(DeliveryError) as conflict:
        _client(agent_server).send("cevt-2", b'{"event_id":"cevt-2"}')
    assert conflict.value.retryable is False
    assert conflict.value.code == "business_conflict"
    assert str(conflict.value) == "Agent 返回状态码 409 code=business_conflict: bounded"


@pytest.mark.parametrize("status", [200, 201, 202])
@pytest.mark.parametrize("endpoint", ["autofill", "health"])
def test_versioned_success_contract_accepts_valid_idempotent_2xx(
    agent_server: ThreadingHTTPServer,
    status: int,
    endpoint: str,
) -> None:
    _AgentHandler.drop_first_response = False
    _AgentHandler.success_status = status
    client = _client(agent_server)
    event_id = f"cevt-valid-{endpoint}-{status}"
    body = json.dumps({"event_id": event_id}).encode()
    result = (
        client.send_health(event_id, body)
        if endpoint == "health"
        else client.send(event_id, body)
    )
    assert result == status


@pytest.mark.parametrize("endpoint", ["autofill", "health"])
def test_2xx_html_is_retryable_protocol_error(
    agent_server: ThreadingHTTPServer, endpoint: str
) -> None:
    _AgentHandler.drop_first_response = False
    _AgentHandler.success_body = b"<html>wrong upstream</html>"
    _AgentHandler.success_content_type = "text/html"
    client = _client(agent_server)
    body = b'{"event_id":"cevt-html"}'
    with pytest.raises(DeliveryError) as failure:
        if endpoint == "health":
            client.send_health("cevt-html", body)
        else:
            client.send("cevt-html", body)
    assert failure.value.retryable is True
    assert failure.value.status == 200
    assert failure.value.code == "agent_protocol_error"


@pytest.mark.parametrize("endpoint", ["autofill", "health"])
def test_2xx_wrong_event_id_is_retryable_protocol_error(
    agent_server: ThreadingHTTPServer, endpoint: str
) -> None:
    _AgentHandler.drop_first_response = False
    response = (
        {
            "contract_version": "enterprise-source-health-result/v1",
            "event_id": "cevt-other",
            "status": "recorded",
            "idempotent_replay": True,
        }
        if endpoint == "health"
        else {
            "contract_version": "enterprise-autofill-ingestion-result/v1",
            "event_id": "cevt-other",
            "status": "completed",
            "draft_id": "draft-result-1",
            "ingestion_id": "ingestion-result-1",
            "idempotent_replay": True,
        }
    )
    _AgentHandler.success_body = json.dumps(response).encode()
    client = _client(agent_server)
    body = b'{"event_id":"cevt-expected"}'
    with pytest.raises(DeliveryError) as failure:
        if endpoint == "health":
            client.send_health("cevt-expected", body)
        else:
            client.send("cevt-expected", body)
    assert failure.value.retryable is True
    assert failure.value.code == "agent_protocol_error"
