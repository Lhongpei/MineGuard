from __future__ import annotations

import hashlib
import hmac
import threading
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import uuid4

import pytest

from enterprise_agent.errors import PlatformError
from enterprise_agent.five_quantity_exchange import (
    FiveQuantityPlatformClient,
    FiveQuantityPlatformConfig,
    MineIdentity,
    http_transport_headers,
    sign_message,
    verify_message,
)
from enterprise_agent.util import utc_text

CURRENT_SECRET = "current-message-secret-abcdefghijklmnopqrstuvwxyz"
PREVIOUS_SECRET = "previous-message-secret-abcdefghijklmnopqrstuvwxyz"
TRANSPORT_SECRET = "transport-message-secret-abcdefghijklmnopqrstuvwxyz"


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
        message_hmac_secret=CURRENT_SECRET,
        previous_regulator_key_id="regulator-key-previous",
        previous_message_hmac_secret=PREVIOUS_SECRET,
    )


def government_message(*, key_id: str, secret: str) -> dict[str, Any]:
    message_id = str(uuid4())
    timestamp = utc_text()
    return sign_message(
        {
            "contract_version": "analysis-report-v2",
            "message_type": "analysis_report",
            "message_id": message_id,
            "correlation_id": str(uuid4()),
            "causation_id": str(uuid4()),
            "idempotency_key": f"report.{message_id}",
            "revision": 1,
            "predecessor": None,
            "created_at": timestamp,
            "sender": {
                "system_id": "mineguard-qinyuan",
                "party_id": "regulator-qinyuan",
                "role": "regulatory_platform",
            },
            "recipient": {
                "system_id": "agent-mine-test-001",
                "party_id": "operator-test-001",
                "role": "enterprise_agent",
            },
            "mine_id": "MINE-TEST-001",
            "payload": {"test": "signed"},
            "signature_envelope": {
                "algorithm": "hmac-sha256-v2",
                "canonicalization": "rfc8785-jcs",
                "key_id": key_id,
                "signed_at": timestamp,
                "nonce": "0123456789abcdef0123456789abcdef",
                "payload_sha256": "0" * 64,
                "signature": "0" * 64,
            },
        },
        secret=secret,
    )


def test_government_messages_accept_current_and_previous_rotation_keys() -> None:
    for key_id, secret in (
        ("regulator-key-current", CURRENT_SECRET),
        ("regulator-key-previous", PREVIOUS_SECRET),
    ):
        verify_message(
            government_message(key_id=key_id, secret=secret),
            secret=CURRENT_SECRET,
            identity=identity(),
            expected_contract="analysis-report-v2",
            expected_type="analysis_report",
        )
    unknown = government_message(key_id="unknown-key", secret=PREVIOUS_SECRET)
    with pytest.raises(PlatformError, match="签名"):
        verify_message(
            unknown,
            secret=CURRENT_SECRET,
            identity=identity(),
            expected_contract="analysis-report-v2",
            expected_type="analysis_report",
        )
    tampered = deepcopy(
        government_message(key_id="regulator-key-current", secret=CURRENT_SECRET)
    )
    tampered["payload"]["test"] = "tampered"
    with pytest.raises(PlatformError, match="摘要"):
        verify_message(
            tampered,
            secret=CURRENT_SECRET,
            identity=identity(),
            expected_contract="analysis-report-v2",
            expected_type="analysis_report",
        )


def test_http_transport_signature_covers_exact_path_query_and_body() -> None:
    url = "https://regulator.example/v2/analysis-reports/next?after_cursor=a.b:c-1"
    headers = http_transport_headers(
        method="GET",
        url=url,
        body=b"",
        sender_id="agent-mine-test-001",
        secret=TRANSPORT_SECRET,
        contract_version="five-quantity-exchange-v2",
        timestamp="2026-08-01T00:00:00Z",
        nonce="0123456789abcdef0123456789abcdef",
    )
    body_hash = hashlib.sha256(b"").hexdigest()
    material = "\n".join(
        [
            "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V2",
            "GET",
            "/v2/analysis-reports/next?after_cursor=a.b:c-1",
            "agent-mine-test-001",
            "2026-08-01T00:00:00Z",
            "0123456789abcdef0123456789abcdef",
            "five-quantity-exchange-v2",
            body_hash,
        ]
    ).encode()
    expected = hmac.new(TRANSPORT_SECRET.encode(), material, hashlib.sha256).hexdigest()
    assert headers["X-Exchange-Signature"] == expected
    assert headers["X-Exchange-Content-SHA256"] == body_hash


def test_v3_route_uses_v3_http_domain_for_reused_v2_lifecycle_body() -> None:
    body = b'{"contract_version":"risk-delivery-ack-v2"}'
    url = "https://regulator.example/v3/analysis-reports/report-1/delivery-ack"
    headers = http_transport_headers(
        method="POST",
        url=url,
        body=body,
        sender_id="agent-mine-test-001",
        secret=TRANSPORT_SECRET,
        contract_version="risk-delivery-ack-v2",
        timestamp="2026-08-01T00:00:00Z",
        nonce="0123456789abcdef0123456789abcdef",
    )
    body_hash = hashlib.sha256(body).hexdigest()
    material = "\n".join(
        [
            "MINEGUARD-TEN-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V3",
            "POST",
            "/v3/analysis-reports/report-1/delivery-ack",
            "agent-mine-test-001",
            "2026-08-01T00:00:00Z",
            "0123456789abcdef0123456789abcdef",
            "risk-delivery-ack-v2",
            body_hash,
        ]
    ).encode()
    expected = hmac.new(
        TRANSPORT_SECRET.encode(), material, hashlib.sha256
    ).hexdigest()

    assert headers["X-Exchange-Signature-Version"] == "hmac-sha256-v3"
    assert headers["X-Exchange-Contract-Version"] == "risk-delivery-ack-v2"
    assert headers["X-Exchange-Signature"] == expected


class _Response:
    def __init__(self, request: Any, status: int, raw: bytes):
        self.status = status
        self._url = request.full_url
        self._raw = raw

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._raw

    def geturl(self) -> str:
        return self._url


def test_client_implements_all_seven_paths_and_preserves_opaque_cursor() -> None:
    requests: list[tuple[str, str]] = []

    def opener(request: Any, timeout: float) -> _Response:
        assert timeout == 5
        requests.append((request.get_method(), request.full_url))
        is_ack = request.full_url.endswith("/delivery-ack")
        return _Response(request, 204 if is_ack else 200, b"" if is_ack else b"{}")

    client = FiveQuantityPlatformClient(
        FiveQuantityPlatformConfig(
            base_url="https://regulator.example",
            sender_id="agent-mine-test-001",
            transport_hmac_secret=TRANSPORT_SECRET,
            timeout_seconds=5,
        ),
        opener=opener,
    )
    message_id = str(uuid4())
    report_id = str(uuid4())
    response_id = str(uuid4())
    client.submit({"contract_version": "ten-quantity-submission-v3", "payload": {}})
    client.submission_receipt(message_id)
    client.pull_next(after_cursor="opaque.cursor:0001-next")
    client.analysis_report(report_id)
    client.acknowledge(
        report_id,
        {"contract_version": "risk-delivery-ack-v2", "payload": {}},
    )
    client.respond(
        report_id,
        {"contract_version": "enterprise-risk-response-v2", "payload": {}},
    )
    client.response_receipt(response_id)
    assert [
        (method, url.removeprefix("https://regulator.example"))
        for method, url in requests
    ] == [
        ("POST", "/v3/ten-quantity-submissions"),
        ("GET", f"/v3/ten-quantity-submissions/{message_id}/receipt"),
        ("GET", "/v3/analysis-reports/next?after_cursor=opaque.cursor:0001-next"),
        ("GET", f"/v3/analysis-reports/{report_id}"),
        ("POST", f"/v3/analysis-reports/{report_id}/delivery-ack"),
        ("POST", f"/v3/analysis-reports/{report_id}/responses"),
        ("GET", f"/v3/risk-responses/{response_id}/receipt"),
    ]


def test_client_refuses_to_follow_any_redirect() -> None:
    hits = {"redirect": 0, "target": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/v3/analysis-reports/next":
                hits["redirect"] += 1
                self.send_response(307)
                self.send_header("Location", "/target")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                hits["target"] += 1
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        def log_message(self, *_: Any) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = FiveQuantityPlatformClient(
            FiveQuantityPlatformConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                sender_id="agent-mine-test-001",
                transport_hmac_secret=TRANSPORT_SECRET,
            )
        )
        with pytest.raises(PlatformError, match="HTTP 307"):
            client.pull_next()
        assert hits == {"redirect": 1, "target": 0}
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()


def test_custom_ca_must_be_a_real_non_symlink_file(tmp_path) -> None:
    missing = tmp_path / "missing.pem"
    with pytest.raises(ValueError, match="CA"):
        FiveQuantityPlatformConfig(
            base_url="https://regulator.example",
            sender_id="agent-mine-test-001",
            transport_hmac_secret=TRANSPORT_SECRET,
            ca_bundle_path=str(missing),
        )
    bundle = tmp_path / "ca.pem"
    bundle.write_text("not a certificate")
    link = tmp_path / "link.pem"
    link.symlink_to(bundle)
    with pytest.raises(ValueError, match="符号链接"):
        FiveQuantityPlatformConfig(
            base_url="https://regulator.example",
            sender_id="agent-mine-test-001",
            transport_hmac_secret=TRANSPORT_SECRET,
            ca_bundle_path=str(link),
        )
