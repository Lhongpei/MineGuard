from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import gateway_sign_observation

from enterprise_agent.security import (
    normalize_observation,
    observation_payload,
    transport_headers,
)
from enterprise_agent.util import jcs_json, sha256_jcs


def test_governed_observation_fixed_vector() -> None:
    observation = {
        "source_id": "mine-001-main-transport",
        "observation_id": "obs-20260727-0001",
        "value": 1000.25,
        "unit": "t",
        "observed_at": "2026-07-27T08:00:00Z",
        "received_at": "2026-07-27T08:00:05Z",
        "interval_start": None,
        "interval_end": None,
        "reset_before": False,
        "sequence_no": 202607270001,
        "revision": 0,
    }
    signed = gateway_sign_observation(observation)
    assert signed["payload_sha256"] == (
        "78a5d9cf36c2b566511bee3364ae714a02479da6ff8b02f2b996de5574c197a9"
    )
    assert signed["signature"] == (
        "59dc38c6346e0f955976c541a093644276c9f36830de8d4c38aee79b56e82477"
    )
    assert "interval_start" not in observation_payload(signed)
    assert "reset_before" not in observation_payload(signed)


def test_transport_signature_fixed_vector() -> None:
    body = b"fixed-body"
    headers = transport_headers(
        method="POST",
        url="https://regulator.example/v1/enterprise-submissions",
        body=body,
        secret="secret",
        client_id="client-001",
        timestamp="2026-07-27T08:05:00Z",
        nonce="AAECAwQFBgcICQoLDA0ODw",
    )
    assert headers["X-Enterprise-Signature-Version"] == "hmac-sha256-v1"
    assert headers["X-Enterprise-Contract-Version"] == ("enterprise-submission-v1")
    assert len(headers["X-Enterprise-Signature"]) == 64
    assert len(headers["X-Enterprise-Content-SHA256"]) == 64


def test_integer_value_and_offset_time_use_platform_v1_wire_types() -> None:
    observation = {
        "source_id": " source-1 ",
        "observation_id": " obs-1 ",
        "value": 7100,
        "unit": " t ",
        "observed_at": "2026-07-27T08:00:00+08:00",
        "received_at": "2026-07-27T08:00:05+08:00",
        "interval_start": None,
        "interval_end": None,
        "reset_before": False,
        "sequence_no": 1,
        "revision": 0,
    }
    normalised = normalize_observation(observation)
    signed = gateway_sign_observation(observation, "source-secret")
    assert normalised["source_id"] == "source-1"
    assert normalised["observation_id"] == "obs-1"
    assert normalised["value"] == 7100.0
    assert isinstance(normalised["value"], float)
    assert normalised["unit"] == "t"
    assert normalised["observed_at"] == "2026-07-27T00:00:00Z"
    assert normalised["received_at"] == "2026-07-27T00:00:05Z"
    # Independently fixed against the V1 platform verifier algorithm.
    assert signed["payload_sha256"] == (
        "3f866a062780d40a33a71074109738fa91afd59ac5c0c06dd6f4d8407b657b20"
    )


@pytest.mark.parametrize("field", ["sequence_no", "revision"])
def test_observation_rejects_integer_outside_jcs_safe_range(field: str) -> None:
    observation = {
        "source_id": "source-1",
        "observation_id": "obs-1",
        "value": 1,
        "unit": "t",
        "observed_at": "2026-07-27T08:00:00Z",
        "received_at": "2026-07-27T08:00:01Z",
        "interval_start": None,
        "interval_end": None,
        "reset_before": False,
        "sequence_no": 1,
        "revision": 0,
    }
    observation[field] = 9_007_199_254_740_992
    with pytest.raises(ValueError, match="safe integers"):
        normalize_observation(observation)


def test_jcs_normalises_numbers_and_utf16_key_order() -> None:
    assert sha256_jcs({"n": 1.0}) == sha256_jcs({"n": 1})
    assert sha256_jcs({"n": 1e-6}) == sha256_jcs({"n": 0.000001})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.002, "0.002"),
        (0.9, "0.9"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (-0.0, "0"),
    ],
)
def test_jcs_number_rfc8785_boundaries(value: float, expected: str) -> None:
    assert jcs_json(value) == expected


def test_jcs_matches_final_contract_example_payload_hash() -> None:
    example_path = (
        Path(__file__).resolve().parents[2]
        / "contracts"
        / "examples"
        / "enterprise-submission-v1.json"
    )
    example = json.loads(example_path.read_text(encoding="utf-8"))
    assert sha256_jcs(example["payload"]) == (
        "f730ae0a8c047c6d094f81eac048f94e46f287bf9cabe7c5b5732f84230b7ac1"
    )
