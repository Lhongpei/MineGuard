"""Golden-vector conformance for the neutral enterprise submission contract.

The platform is intentionally implemented without importing executable code
from ``contracts/``.  These tests read the frozen JSON example as wire data and
therefore catch drift between the independent platform adapter and the neutral
specification.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mineguard.external_submission import (
    EXTERNAL_SUBMISSION_CONTRACT_VERSION,
    enterprise_submission_payload_sha256,
    to_governed_production_request,
    transport_signature,
    validate_enterprise_submission_json,
)
from mineguard.governance import (
    GovernedObservation,
    GovernedProductionRequest,
    compute_payload_sha256,
)


CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "contracts"
SUBMISSION_EXAMPLE = (
    CONTRACT_ROOT / "examples" / "enterprise-submission-v1.json"
)

PAYLOAD_SHA256 = (
    "f730ae0a8c047c6d094f81eac048f94e46f287bf9cabe7c5b5732f84230b7ac1"
)
OBSERVATION_PAYLOAD_SHA256 = (
    "78a5d9cf36c2b566511bee3364ae714a02479da6ff8b02f2b996de5574c197a9"
)
RAW_BODY_SHA256 = (
    "e4aab1c54596bded8e65dde774774b072f94b9d650629cc37b5eeeb2cda23c3b"
)
TRANSPORT_SIGNATURE = (
    "1f26b2f2541ddefd388dba69fb9d601fb25a7d2448c2f0b021c198edba97795e"
)


def _example() -> tuple[bytes, dict[str, object]]:
    body = SUBMISSION_EXAMPLE.read_bytes()
    return body, json.loads(body)


def test_platform_wire_model_accepts_frozen_contract_example() -> None:
    body, document = _example()

    submission = validate_enterprise_submission_json(body)

    assert EXTERNAL_SUBMISSION_CONTRACT_VERSION == "enterprise-submission-v1"
    assert submission.contract_version == EXTERNAL_SUBMISSION_CONTRACT_VERSION
    assert submission.submission_id == document["submission_id"]
    assert submission.idempotency_key == document["idempotency_key"]
    assert submission.payload.enterprise.enterprise_id == "enterprise-001"
    assert submission.payload.mine.mine_id == "mine-001"
    assert submission.payload.operational_context.regime_code == (
        "NORMAL_PRODUCTION"
    )
    assert submission.payload.operational_context.shift_code == "A"
    assert submission.payload.operational_context.season_code == "SUMMER"
    assert submission.payload.operational_context.maintenance is False
    assert submission.payload.llm_assistance.used is False
    assert submission.payload.human_confirmation.confirmed is True

    # A full JSON-mode round trip makes every frozen field part of the
    # platform's wire model instead of silently dropping unknown audit data.
    assert submission.model_dump(mode="json") == document


def test_platform_payload_digest_matches_frozen_rfc8785_vector() -> None:
    body, document = _example()

    assert hashlib.sha256(body).hexdigest() == RAW_BODY_SHA256
    assert document["payload_sha256"] == PAYLOAD_SHA256
    assert (
        enterprise_submission_payload_sha256(document["payload"])
        == PAYLOAD_SHA256
    )

    damaged = json.loads(body)
    damaged["payload"]["observations"][0]["value"] = 1000.26
    with pytest.raises(ValueError, match="payload_sha256"):
        validate_enterprise_submission_json(
            json.dumps(
                damaged,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )


def test_platform_transport_hmac_matches_frozen_vector() -> None:
    body, _ = _example()
    content_sha256 = hashlib.sha256(body).hexdigest()

    actual = transport_signature(
        b"example-transport-secret-not-for-production",
        method="POST",
        path="/v1/enterprise-submissions",
        client_id="enterprise-client-example",
        timestamp="2026-07-27T08:05:00Z",
        nonce="AAECAwQFBgcICQoLDA0ODw",
        contract_version="enterprise-submission-v1",
        content_sha256=content_sha256,
    )

    assert content_sha256 == RAW_BODY_SHA256
    assert actual == TRANSPORT_SIGNATURE


def test_regulatory_conversion_strips_provenance_from_observations() -> None:
    body, document = _example()
    submission = validate_enterprise_submission_json(body)

    request = to_governed_production_request(submission)

    assert isinstance(request, GovernedProductionRequest)
    assert request.mine_id == "mine-001"
    assert request.profile_id == "coal-balance-default"
    assert request.profile_version == "2026.07"
    assert request.operational_context.regime_code == "NORMAL_PRODUCTION"
    assert len(request.observations) == 1

    observation = request.observations[0]
    assert isinstance(observation, GovernedObservation)
    assert not hasattr(observation, "field_provenance")
    assert "field_provenance" not in observation.model_dump(mode="json")
    assert "provenance" not in observation.model_dump(mode="json")

    wire_observation = document["payload"]["observations"][0]
    expected_governed_fields = {
        key: value
        for key, value in wire_observation.items()
        if key != "field_provenance"
    }
    assert observation.model_dump(mode="json") == expected_governed_fields
    assert observation.payload_sha256 == OBSERVATION_PAYLOAD_SHA256
    assert compute_payload_sha256(observation) == OBSERVATION_PAYLOAD_SHA256

    # Enterprise identity, LLM disclosure, human confirmation and provenance
    # remain intake audit material; none becomes caller-controlled analysis
    # input on the governed request.
    governed_dump = request.model_dump(mode="json")
    assert "enterprise" not in governed_dump
    assert "llm_assistance" not in governed_dump
    assert "human_confirmation" not in governed_dump
    assert "field_provenance" not in governed_dump
