from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from mine_edge.errors import ForwardError
from mine_edge.forwarder import (
    Forwarder,
    TransportResponse,
    UrllibTransport,
    _NoRedirectHandler,
)
from mine_edge.service import EdgeService
from mine_edge.storage import Repository
from mine_edge.wire import (
    CONTRACT_VERSION,
    INGEST_PATH,
    SCHEMA_VERSION,
    signature_headers,
    transport_signature,
    verify_signature,
)


class CaptureTransport:
    def __init__(
        self,
        status: int = 202,
        *,
        receipt_overrides: dict[str, object] | None = None,
        raw_response: bytes | None = None,
    ) -> None:
        self.status = status
        self.receipt_overrides = receipt_overrides or {}
        self.raw_response = raw_response
        self.calls = []

    def post(self, url, body, headers, timeout_seconds):
        self.calls.append((url, body, headers, timeout_seconds))
        if self.raw_response is not None:
            response_body = self.raw_response
        else:
            request = json.loads(body)
            receipt = {
                "schema_version": "edge-telemetry-receipt-v1",
                "receipt_id": "receipt-001",
                "batch_id": request["batch_id"],
                "client_id": request["client_id"],
                "mine_id": request["mine_id"],
                "status": "accepted",
                "received_at": "2026-07-28T00:00:01Z",
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "accepted_observations": len(request["observations"]),
                "rejected_observations": 0,
                "regulatory_outcome": "not_determined_at_intake",
                "links": {
                    "receipt": (
                        f"/v1/edge-telemetry-batches/{request['batch_id']}/receipt"
                    ),
                    "alerts": f"/v1/safety/alerts?mine_id={request['mine_id']}",
                },
            }
            receipt.update(self.receipt_overrides)
            response_body = json.dumps(receipt).encode()
        return TransportResponse(self.status, response_body)


def test_hmac_fixed_vector() -> None:
    body = b'{"hello":"world"}'
    headers = signature_headers(
        body,
        client_id="edge-001",
        secret=b"test-secret",
        timestamp="2026-07-28T00:00:00.000Z",
        nonce="00112233445566778899aabbccddeeff",
    )
    assert headers["X-Edge-Content-SHA256"] == hashlib.sha256(body).hexdigest()
    assert headers["X-Edge-Contract-Version"] == CONTRACT_VERSION
    assert headers["X-Edge-Signature"] == (
        "b4123d4d08bc145bd8b4a88c0ee676a293fe2cd484114d58f78cbba798001438"
    )
    assert verify_signature(body, headers, secret=b"test-secret")
    assert not verify_signature(body + b" ", headers, secret=b"test-secret")


def test_neutral_contract_hmac_fixed_vector() -> None:
    signature = transport_signature(
        b"example-edge-transport-secret-not-for-production",
        client_id="mine-edge-M001",
        timestamp="2026-07-28T10:15:03Z",
        nonce="AAECAwQFBgcICQoLDA0ODw",
        content_sha256=(
            "f289284d73836288cae3191eeac928b62d78c8988418e1016e4f956c08af2aab"
        ),
    )
    assert signature == (
        "8d56b417514d8f78c9d0e5c431880aa5eb5df49b15cbaea1ec59efe1ac0b6001"
    )


def test_forwarder_sends_expected_batch_and_headers(settings, methane_raw) -> None:
    configured = replace(
        settings,
        upstream_url="https://regulator.example",
        upstream_hmac_secret=b"shared-secret-with-at-least-32-bytes",
    )
    repository = Repository(configured.database_path)
    EdgeService(repository, configured).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )
    transport = CaptureTransport()
    result = Forwarder(repository, configured, transport=transport).forward_once()

    assert result.status == "delivered"
    assert result.events == 2
    url, body, headers, timeout = transport.calls[0]
    assert url == "https://regulator.example" + INGEST_PATH
    payload = json.loads(body)
    assert payload["schema_version"] == SCHEMA_VERSION
    assert payload["client_id"] == configured.client_id
    assert payload["sequence_start"] == 0
    assert payload["sequence_end"] == 0
    assert payload["rule_profile"]["sha256"] == "a" * 64
    assert len(payload["observations"]) == 1
    assert len(payload["local_alerts"]) == 1
    assert set(payload) == {
        "schema_version",
        "batch_id",
        "client_id",
        "mine_id",
        "sent_at",
        "sequence_start",
        "sequence_end",
        "rule_profile",
        "observations",
        "local_alerts",
    }
    assert payload["local_alerts"][0]["advisory_only"] is True
    assert "threshold" not in payload["local_alerts"][0]
    assert verify_signature(
        body, headers, secret=b"shared-secret-with-at-least-32-bytes"
    )
    assert timeout == configured.request_timeout_seconds


def test_forwarder_persists_retry(settings, methane_raw) -> None:
    configured = replace(
        settings,
        upstream_url="https://regulator.example",
        upstream_hmac_secret=b"shared-secret-with-at-least-32-bytes",
        forward_base_delay_seconds=7,
    )
    repository = Repository(configured.database_path)
    EdgeService(repository, configured).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )
    result = Forwarder(
        repository, configured, transport=CaptureTransport(status=503)
    ).forward_once()
    assert result.status == "retry_scheduled"
    assert result.retry_after_seconds == 7
    assert repository.stats()["outbox_pending"] == 2
    items = repository.list_outbox(status="pending")
    assert all(item["attempts"] == 1 for item in items)


def test_forwarder_can_drain_persisted_legacy_batch_without_renaming(
    settings, methane_raw
) -> None:
    configured = replace(
        settings,
        upstream_url="https://regulator.example",
        upstream_hmac_secret=b"shared-secret-with-at-least-32-bytes",
    )
    repository = Repository(configured.database_path)
    EdgeService(repository, configured).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )
    allocated = repository.claim_batch(
        limit=configured.forward_batch_size,
        client_id=configured.client_id,
    )
    assert allocated is not None
    legacy_batch_id = "batch_" + "a" * 32
    with repository._connect() as connection:
        connection.execute(
            "UPDATE outbox SET batch_id=? WHERE batch_id=?",
            (legacy_batch_id, allocated.batch_id),
        )

    result = Forwarder(
        repository,
        configured,
        transport=CaptureTransport(),
    ).forward_once()

    assert result.status == "delivered"
    assert result.batch_id == legacy_batch_id
    delivered_ids = {
        item["batch_id"]
        for item in repository.list_outbox(status="delivered")
    }
    assert delivered_ids == {legacy_batch_id}


@pytest.mark.parametrize(
    ("overrides", "error_match"),
    [
        ({"batch_id": "another-batch"}, "batch_id"),
        ({"client_id": "another-client"}, "client_id"),
        ({"mine_id": "another-mine"}, "mine_id"),
        ({"body_sha256": "f" * 64}, "body_sha256"),
    ],
)
def test_forwarder_retries_when_2xx_receipt_is_not_bound_to_request(
    settings, methane_raw, overrides, error_match
) -> None:
    configured = replace(
        settings,
        upstream_url="https://regulator.example",
        upstream_hmac_secret=b"shared-secret-with-at-least-32-bytes",
    )
    repository = Repository(configured.database_path)
    EdgeService(repository, configured).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )
    result = Forwarder(
        repository,
        configured,
        transport=CaptureTransport(receipt_overrides=overrides),
    ).forward_once()

    assert result.status == "retry_scheduled"
    assert error_match in (result.error or "")
    assert repository.stats()["outbox_pending"] == 2
    assert repository.stats()["outbox_delivered"] == 0


@pytest.mark.parametrize(
    "raw_response",
    [
        b"",
        b"not-json",
        b"{}",
        (
            b'{"schema_version":"edge-telemetry-receipt-v1",'
            b'"schema_version":"edge-telemetry-receipt-v1"}'
        ),
    ],
)
def test_forwarder_retries_on_malformed_2xx_receipt(
    settings, methane_raw, raw_response
) -> None:
    configured = replace(
        settings,
        upstream_url="https://regulator.example",
        upstream_hmac_secret=b"shared-secret-with-at-least-32-bytes",
    )
    repository = Repository(configured.database_path)
    EdgeService(repository, configured).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )

    result = Forwarder(
        repository,
        configured,
        transport=CaptureTransport(raw_response=raw_response),
    ).forward_once()

    assert result.status == "retry_scheduled"
    assert "2xx 回执无效" in (result.error or "")
    assert repository.stats()["outbox_pending"] == 2


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": "edge-telemetry-receipt-v2"},
        {"status": ["accepted"]},
        {"received_at": "2026-07-28 00:00:01"},
        {"accepted_observations": True},
        {"regulatory_outcome": "approved"},
        {"links": {"receipt": "/receipt", "alerts": "bad uri"}},
        {"unexpected": "field"},
    ],
)
def test_forwarder_retries_when_2xx_receipt_breaks_schema(
    settings, methane_raw, overrides
) -> None:
    configured = replace(
        settings,
        upstream_url="https://regulator.example",
        upstream_hmac_secret=b"shared-secret-with-at-least-32-bytes",
    )
    repository = Repository(configured.database_path)
    EdgeService(repository, configured).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )

    result = Forwarder(
        repository,
        configured,
        transport=CaptureTransport(receipt_overrides=overrides),
    ).forward_once()

    assert result.status == "retry_scheduled"
    assert "2xx 回执无效" in (result.error or "")
    assert repository.stats()["outbox_pending"] == 2


class _FakeResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.requested_bytes = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, amount: int) -> bytes:
        self.requested_bytes = amount
        return self.body[:amount]


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response

    def open(self, request, timeout):
        return self.response


def test_urllib_transport_returns_raw_body_with_size_limit() -> None:
    response = _FakeResponse(b"receipt")
    transport = UrllibTransport(max_response_bytes=7, opener=_FakeOpener(response))
    result = transport.post("https://example.test", b"{}", {}, 2)
    assert result == TransportResponse(status=200, body=b"receipt")
    assert response.requested_bytes == 8

    oversized = _FakeResponse(b"12345678")
    transport = UrllibTransport(max_response_bytes=7, opener=_FakeOpener(oversized))
    with pytest.raises(ForwardError, match="超过 7 字节"):
        transport.post("https://example.test", b"{}", {}, 2)


def test_redirect_handler_never_replays_signed_request() -> None:
    assert (
        _NoRedirectHandler().redirect_request(
            None,
            None,
            302,
            "Found",
            {"Location": "https://attacker.example"},
            "https://attacker.example",
        )
        is None
    )


def test_unconfigured_forwarder_keeps_queue(settings, methane_raw) -> None:
    repository = Repository(settings.database_path)
    EdgeService(repository, settings).ingest(
        methane_raw, channel="http_poll", source_id="gas"
    )
    result = Forwarder(repository, settings).forward_once()
    assert result.status == "not_configured"
    assert repository.stats()["outbox_pending"] == 2
