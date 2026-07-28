from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mineguard.casework import (
    ExternalSubmissionConflictError,
    LocalRepository,
)
from mineguard.external_submission import (
    AuthorizedConfirmer,
    ExternalAuthenticationError,
    ExternalClient,
    VerifiedEventSnapshot,
    authenticate_external_request,
    enterprise_submission_payload_sha256,
    jcs_canonical_json,
    parse_external_clients,
    sign_transport_headers,
    validate_enterprise_submission_json,
)


CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "contracts"
EXAMPLE_PATH = CONTRACT_ROOT / "examples" / "enterprise-submission-v1.json"
NOW = datetime(2026, 7, 27, 8, 5, tzinfo=UTC)


def example_document() -> dict:
    return json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))


def test_jcs_number_edges_follow_ecmascript_rendering() -> None:
    assert jcs_canonical_json(0.002) == "0.002"
    assert jcs_canonical_json(0.9) == "0.9"
    assert jcs_canonical_json(1e-6) == "0.000001"
    assert jcs_canonical_json(1e-7) == "1e-7"
    assert jcs_canonical_json(1e20) == "100000000000000000000"
    assert jcs_canonical_json(1e21) == "1e+21"
    assert jcs_canonical_json(-0.0) == "0"


def test_payload_hash_and_required_field_provenance_are_enforced() -> None:
    document = example_document()
    document["payload"]["observations"][0]["value"] = 999.0
    with pytest.raises(ValueError, match="payload_sha256"):
        validate_enterprise_submission_json(
            json.dumps(document, ensure_ascii=False)
        )

    document["payload_sha256"] = enterprise_submission_payload_sha256(
        document
    )
    del document["payload"]["observations"][0]["field_provenance"]["value"]
    document["payload_sha256"] = enterprise_submission_payload_sha256(
        document
    )
    with pytest.raises(ValidationError):
        validate_enterprise_submission_json(
            json.dumps(document, ensure_ascii=False)
        )

    with pytest.raises(ValueError, match="I-JSON"):
        validate_enterprise_submission_json(
            '{"contract_version":"enterprise-submission-v1",'
            '"contract_version":"enterprise-submission-v1"}'
        )


def test_confirmation_evidence_and_business_timeline_are_enforced() -> None:
    document = example_document()
    del document["payload"]["human_confirmation"][
        "confirmation_evidence_sha256"
    ]
    document["payload_sha256"] = enterprise_submission_payload_sha256(
        document
    )
    with pytest.raises(ValidationError, match="confirmation_evidence"):
        validate_enterprise_submission_json(
            json.dumps(document, ensure_ascii=False)
        )

    document = example_document()
    document["payload"]["human_confirmation"]["confirmed_at"] = (
        "2026-07-26T23:59:59Z"
    )
    document["submitted_at"] = "2026-07-27T00:00:00Z"
    document["payload_sha256"] = enterprise_submission_payload_sha256(
        document
    )
    with pytest.raises(
        ValidationError,
        match="reporting window",
    ):
        validate_enterprise_submission_json(
            json.dumps(document, ensure_ascii=False)
        )


def test_transport_authentication_verifies_body_scope_and_replay_time() -> None:
    client = ExternalClient(
        client_id="enterprise-client-example",
        enterprise_id="enterprise-001",
        secret=b"example-transport-secret-not-for-production",
        mine_ids=frozenset({"mine-001"}),
        authorized_confirmers=(
            AuthorizedConfirmer(
                confirmer_id="employee-0088",
                confirmer_name="示例确认人",
                confirmer_roles=frozenset({"企业报送负责人"}),
            ),
        ),
        verified_event_snapshots=(
            VerifiedEventSnapshot(
                mine_id="mine-001",
                window_start=datetime(
                    2026, 7, 27, 0, 0, tzinfo=UTC
                ),
                window_end=datetime(
                    2026, 7, 27, 8, 0, tzinfo=UTC
                ),
                event_codes=(),
                evidence_sha256="e" * 64,
            ),
        ),
    )
    body = EXAMPLE_PATH.read_bytes()
    headers = sign_transport_headers(
        client,
        body,
        method="POST",
        path="/v1/enterprise-submissions",
        timestamp=NOW,
        nonce="AAECAwQFBgcICQoLDA0ODw",
    )

    authenticated, request_time, nonce = authenticate_external_request(
        {client.client_id: client},
        headers,
        body,
        method="POST",
        path="/v1/enterprise-submissions",
        now=NOW,
    )
    assert authenticated.client_id == client.client_id
    assert request_time == NOW
    assert nonce == "AAECAwQFBgcICQoLDA0ODw"

    with pytest.raises(ExternalAuthenticationError):
        authenticate_external_request(
            {client.client_id: client},
            headers,
            body + b" ",
            method="POST",
            path="/v1/enterprise-submissions",
            now=NOW,
        )
    with pytest.raises(ExternalAuthenticationError):
        authenticate_external_request(
            {client.client_id: client},
            headers,
            body,
            method="POST",
            path="/v1/enterprise-submissions",
            now=NOW + timedelta(minutes=6),
        )


def test_llm_extraction_provenance_matches_declared_business_pointer() -> None:
    document = example_document()
    llm = document["payload"]["llm_assistance"]
    llm.update(
        {
            "used": True,
            "provider": "deepseek",
            "model": "deepseek-v4-flash",
            "tasks": ["field_extraction"],
            "affected_field_paths": [
                "/payload/enterprise/enterprise_name"
            ],
        }
    )
    provenance = document["payload"]["enterprise"][
        "field_provenance"
    ]["enterprise_name"][0]
    provenance["acquisition_method"] = "llm_extraction"
    provenance["confidence"] = 0.98
    document["payload_sha256"] = enterprise_submission_payload_sha256(
        document
    )
    validate_enterprise_submission_json(
        json.dumps(document, ensure_ascii=False)
    )

    llm["affected_field_paths"] = ["/enterprise_name"]
    document["payload_sha256"] = enterprise_submission_payload_sha256(
        document
    )
    with pytest.raises(
        ValidationError,
        match="LLM-extracted fields",
    ):
        validate_enterprise_submission_json(
            json.dumps(document, ensure_ascii=False)
        )


def test_external_client_environment_is_strict_and_hides_secrets() -> None:
    configured = parse_external_clients(
        json.dumps(
            [
                {
                    "client_id": "agent-001",
                    "enterprise_id": "enterprise-001",
                    "secrets": ["x" * 32, "y" * 32],
                    "mine_ids": ["mine-001"],
                    "authorized_confirmers": [
                        {
                            "confirmer_id": "employee-0088",
                            "confirmer_name": "示例确认人",
                            "confirmer_roles": ["企业报送负责人"],
                        }
                    ],
                    "verified_event_snapshots": [
                        {
                            "mine_id": "mine-001",
                            "window_start": "2026-07-27T00:00:00Z",
                            "window_end": "2026-07-27T08:00:00Z",
                            "event_codes": [],
                            "evidence_sha256": "e" * 64,
                        }
                    ],
                }
            ]
        )
    )
    assert configured["agent-001"].allows_mine("mine-001")
    assert not configured["agent-001"].allows_mine("mine-002")
    assert configured["agent-001"].allows_confirmation(
        validate_enterprise_submission_json(
            EXAMPLE_PATH.read_bytes()
        ).payload.human_confirmation
    )
    assert configured["agent-001"].has_verified_event_snapshot(
        mine_id="mine-001",
        window_start=datetime(2026, 7, 27, 0, 0, tzinfo=UTC),
        window_end=datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
        event_codes=[],
        evidence_sha256={"e" * 64},
    )
    assert not configured["agent-001"].has_verified_event_snapshot(
        mine_id="mine-001",
        window_start=datetime(2026, 7, 27, 0, 0, tzinfo=UTC),
        window_end=datetime(2026, 7, 27, 8, 0, tzinfo=UTC),
        event_codes=["OMITTED-EVENT"],
        evidence_sha256={"e" * 64},
    )
    assert len(configured["agent-001"].verification_secrets) == 2
    assert "x" * 32 not in repr(configured["agent-001"])
    assert "y" * 32 not in repr(configured["agent-001"])

    database_only = parse_external_clients(
        json.dumps(
            [
                {
                    "client_id": "agent-db-only",
                    "enterprise_id": "enterprise-001",
                    "secret": "z" * 32,
                    "mine_ids": ["mine-001"],
                    "authorized_confirmers": [
                        {
                            "confirmer_id": "employee-0088",
                            "confirmer_name": "示例确认人",
                            "confirmer_roles": ["企业报送负责人"],
                        }
                    ],
                }
            ]
        )
    )
    assert database_only["agent-db-only"].verified_event_snapshots == ()

    with pytest.raises(ValueError, match="32 bytes"):
        parse_external_clients(
            json.dumps(
                [
                    {
                        "client_id": "a",
                        "enterprise_id": "e",
                        "secret": "short",
                        "mine_ids": ["*"],
                        "authorized_confirmers": [
                            {
                                "confirmer_id": "operator-001",
                                "confirmer_name": "张三",
                                "confirmer_roles": ["负责人"],
                            }
                        ],
                        "verified_event_snapshots": [
                            {
                                "mine_id": "mine-001",
                                "window_start": "2026-07-27T00:00:00Z",
                                "window_end": "2026-07-27T08:00:00Z",
                                "event_codes": [],
                                "evidence_sha256": "e" * 64,
                            }
                        ],
                    }
                ]
            )
        )

    transport_only = parse_external_clients(
        '[{"client_id":"a","enterprise_id":"e",'
        '"secret":"' + ("x" * 32) + '","mine_ids":["*"]}]'
    )
    assert transport_only["a"].authorized_confirmers == ()


def test_nonce_and_receipt_persistence_are_replay_safe() -> None:
    repository = LocalRepository()
    request_time = datetime.now(UTC)
    try:
        assert repository.claim_external_request_nonce(
            client_id="agent-001",
            nonce="AAECAwQFBgcICQoLDA0ODw",
            request_timestamp=request_time.isoformat(),
            expires_at=(request_time + timedelta(minutes=10)).isoformat(),
        )
        assert not repository.claim_external_request_nonce(
            client_id="agent-001",
            nonce="AAECAwQFBgcICQoLDA0ODw",
            request_timestamp=request_time.isoformat(),
            expires_at=(request_time + timedelta(minutes=10)).isoformat(),
        )
        first = repository.save_external_submission_receipt(
            submission_id="018f7b4c-91d2-7a50-9bf6-3e589f13c201",
            client_id="agent-001",
            enterprise_id="enterprise-001",
            mine_id="mine-001",
            idempotency_key="key-001-0123456789",
            payload_sha256="a" * 64,
            receipt={"status": "accepted", "intake_batch_id": "batch-001"},
        )
        assert first["created"] is True
        retry = repository.save_external_submission_receipt(
            submission_id="018f7b4c-91d2-7a50-9bf6-3e589f13c201",
            client_id="agent-001",
            enterprise_id="enterprise-001",
            mine_id="mine-001",
            idempotency_key="key-001-0123456789",
            payload_sha256="a" * 64,
            receipt={"status": "ignored-on-exact-retry"},
        )
        assert retry["created"] is False
        assert retry["receipt"]["status"] == "accepted"
        with pytest.raises(ExternalSubmissionConflictError):
            repository.save_external_submission_receipt(
                submission_id="018f7b4c-91d2-7a50-9bf6-3e589f13c202",
                client_id="agent-001",
                enterprise_id="enterprise-001",
                mine_id="mine-001",
                idempotency_key="key-001-0123456789",
                payload_sha256="b" * 64,
                receipt={"status": "accepted"},
            )
    finally:
        repository.close()
