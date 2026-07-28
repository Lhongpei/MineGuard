from __future__ import annotations

import io
import json
from urllib.error import HTTPError

import pytest

from enterprise_agent.client import PlatformClient, PlatformClientConfig
from enterprise_agent.errors import PlatformError

TRANSPORT_SECRET = "transport-secret-at-least-32-bytes!"


def _capabilities(
    *,
    submission_path: str = "/v1/enterprise-submissions",
    max_body_bytes: int = 10 * 1024 * 1024,
) -> dict:
    return {
        "contract_version": "enterprise-submission-capabilities-v1",
        "supported_submission_contracts": [
            {
                "version": "enterprise-submission-v1",
                "status": "current",
                "schema_uri": "urn:test:enterprise-submission-v1",
                "submission_path": submission_path,
            }
        ],
        "authentication": {
            "scheme": "hmac-sha256",
            "signature_version": "hmac-sha256-v1",
            "timestamp_tolerance_seconds": 300,
            "nonce_retention_seconds": 600,
        },
        "limits": {
            "max_body_bytes": max_body_bytes,
            "max_observations": 10_000,
        },
        "integrity_algorithms": {
            "submission_payload": "sha-256+rfc8785-jcs",
            "transport_body": "sha-256+raw-http-body",
            "observation_signature": (
                "mineguard-governed-observation-hmac-sha256-v1"
            ),
        },
    }


class Response:
    status = 200

    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int) -> bytes:
        return self.payload


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://[::1]:8080",
        "https://regulator.example",
    ],
)
def test_platform_client_allows_https_or_explicit_loopback(
    base_url: str,
) -> None:
    PlatformClient(
        PlatformClientConfig(
            base_url=base_url,
            client_id="enterprise-client-1",
            transport_hmac_secret=TRANSPORT_SECRET,
        )
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "http://regulator.example",
        "http://192.168.1.20:8080",
        "http://10.0.0.20:8080",
    ],
)
def test_platform_client_rejects_remote_plain_http(
    base_url: str,
) -> None:
    with pytest.raises(ValueError, match="require HTTPS"):
        PlatformClient(
            PlatformClientConfig(
                base_url=base_url,
                client_id="enterprise-client-1",
                transport_hmac_secret=TRANSPORT_SECRET,
            )
        )


def test_client_discovers_capability_signs_and_submits_without_network() -> None:
    requests = []

    def opener(request, **_kwargs):
        requests.append(request)
        if request.get_method() == "GET":
            return Response(_capabilities())
        return Response(
            {
                "contract_version": "enterprise-submission-receipt-v1",
                "submission_contract_version": "enterprise-submission-v1",
                "receipt_id": "018f7b4d-3367-71b0-98d8-84ac388c2e20",
                "submission_id": "018f7b4c-91d2-7a50-9bf6-3e589f13c201",
                "idempotency_key": "enterprise-001-20260727-a",
                "received_at": "2026-07-27T08:05:01Z",
                "status": "accepted",
                "payload_sha256": "a" * 64,
                "regulatory_outcome": "not_determined_at_intake",
                "warnings": [],
                "links": {},
            }
        )

    client = PlatformClient(
        PlatformClientConfig(
            base_url="https://regulator.invalid",
            client_id="enterprise-client-1",
            transport_hmac_secret=TRANSPORT_SECRET,
        ),
        opener=opener,
    )
    receipt = client.submit(
        {
            "contract_version": "enterprise-submission-v1",
            "submission_id": "018f7b4c-91d2-7a50-9bf6-3e589f13c201",
            "payload_sha256": "a" * 64,
        },
        idempotency_key="enterprise-001-20260727-a",
    )
    assert receipt["status"] == "accepted"
    assert len(requests) == 2
    for request in requests:
        assert request.get_header("X-enterprise-signature")
        assert request.get_header("X-enterprise-client-id") == ("enterprise-client-1")
    assert requests[1].get_header("Idempotency-key") == ("enterprise-001-20260727-a")


def test_client_rejects_short_transport_secret_at_startup() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        PlatformClient(
            PlatformClientConfig(
                base_url="https://regulator.example",
                client_id="enterprise-client-1",
                transport_hmac_secret="too-short",
            )
        )


def test_client_rejects_capability_path_drift() -> None:
    def opener(_request, **_kwargs):
        return Response(_capabilities(submission_path="/v2/other-intake"))

    client = PlatformClient(
        PlatformClientConfig(
            base_url="https://regulator.invalid",
            client_id="enterprise-client-1",
            transport_hmac_secret=TRANSPORT_SECRET,
        ),
        opener=opener,
    )
    with pytest.raises(PlatformError, match="提交路径"):
        client.submit(
            {"contract_version": "enterprise-submission-v1"},
            idempotency_key="enterprise-001-path-drift-v1",
        )


def test_client_rejects_body_over_advertised_limit_before_post() -> None:
    requests = []

    def opener(request, **_kwargs):
        requests.append(request)
        return Response(_capabilities(max_body_bytes=1024))

    client = PlatformClient(
        PlatformClientConfig(
            base_url="https://regulator.invalid",
            client_id="enterprise-client-1",
            transport_hmac_secret=TRANSPORT_SECRET,
        ),
        opener=opener,
    )
    with pytest.raises(PlatformError, match="超过监管平台限制"):
        client.submit(
            {
                "contract_version": "enterprise-submission-v1",
                "padding": "x" * 2_000,
            },
            idempotency_key="enterprise-001-body-limit-v1",
        )
    assert len(requests) == 1
    assert requests[0].get_method() == "GET"


def test_client_preserves_safe_actionable_platform_error_contract() -> None:
    requests = []
    remote_error = {
        "contract_version": "enterprise-submission-error-v1",
        "error_id": "018f7b4d-7012-74a0-b7b8-2f9a83518014",
        "occurred_at": "2026-07-27T08:05:01Z",
        "http_status": 403,
        "code": "CONFIRMER_NOT_AUTHORIZED",
        "message": "The confirmer is not registered.",
        "retryable": False,
        "violations": [
            {
                "json_pointer": "/payload/human_confirmation/confirmer_id",
                "rule": "authorized_confirmer",
                "message": "No active registration matches this identity.",
            }
        ],
    }

    def opener(request, **_kwargs):
        requests.append(request)
        if request.get_method() == "GET":
            return Response(_capabilities())
        raise HTTPError(
            request.full_url,
            403,
            "Forbidden",
            hdrs=None,
            fp=io.BytesIO(json.dumps(remote_error).encode()),
        )

    client = PlatformClient(
        PlatformClientConfig(
            base_url="https://regulator.invalid",
            client_id="enterprise-client-1",
            transport_hmac_secret=TRANSPORT_SECRET,
        ),
        opener=opener,
    )
    with pytest.raises(PlatformError) as captured:
        client.submit(
            {
                "contract_version": "enterprise-submission-v1",
                "submission_id": "018f7b4c-91d2-7a50-9bf6-3e589f13c201",
                "payload_sha256": "a" * 64,
            },
            idempotency_key="enterprise-001-error-contract-v1",
        )
    error = captured.value
    assert "确认人姓名、岗位或确认方式未在监管端有效备案" in str(error)
    assert "/payload/human_confirmation/confirmer_id" in str(error)
    assert error.details == {
        "http_status": 403,
        "platform_code": "CONFIRMER_NOT_AUTHORIZED",
        "retryable": False,
        "violations": [
            {
                "json_pointer": "/payload/human_confirmation/confirmer_id",
                "rule": "authorized_confirmer",
                "message": "No active registration matches this identity.",
            }
        ],
        "error_id": "018f7b4d-7012-74a0-b7b8-2f9a83518014",
    }


def test_client_does_not_echo_untrusted_non_contract_error_body() -> None:
    marker = "do-not-expose-secret-response"

    def opener(request, **_kwargs):
        if request.get_method() == "GET":
            return Response(_capabilities())
        raise HTTPError(
            request.full_url,
            500,
            "Internal Server Error",
            hdrs=None,
            fp=io.BytesIO(marker.encode()),
        )

    client = PlatformClient(
        PlatformClientConfig(
            base_url="https://regulator.invalid",
            client_id="enterprise-client-1",
            transport_hmac_secret=TRANSPORT_SECRET,
        ),
        opener=opener,
    )
    with pytest.raises(PlatformError) as captured:
        client.submit(
            {"contract_version": "enterprise-submission-v1"},
            idempotency_key="enterprise-001-untrusted-error-v1",
        )
    assert marker not in str(captured.value)
    assert captured.value.details == {
        "http_status": 500,
        "retryable": True,
    }
