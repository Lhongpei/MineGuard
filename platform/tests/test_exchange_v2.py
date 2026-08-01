from __future__ import annotations

from copy import deepcopy
from datetime import UTC, timedelta
import hashlib
import json
from pathlib import Path

import pytest

from mineguard.external_submission import jcs_canonical_json
from mineguard.exchange_v2 import (
    EXCHANGE_TRANSPORT_CONTEXT,
    ExchangeAuthenticationError,
    ExchangeClient,
    ExchangeLineageError,
    decode_inbound_message,
    parse_exchange_clients,
    parse_inbound_message,
    sign_exchange_message,
    transport_signature,
    validate_exchange_lineage,
    verify_exchange_message_signature,
)


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "contracts" / "examples"
EXAMPLE_SECRET = b"example-v2-exchange-secret-not-for-production"


@pytest.mark.parametrize(
    "filename, expected_digest",
    [
        (
            "five-quantity-submission-v2.json",
            "cf22a046f2899e4f11dd91f76ef37e2040da6e20f541bf16943946b1300aff35",
        ),
        (
            "risk-delivery-ack-v2.json",
            "7c9a80c12e96a2d216533af95b8c5172d86a0b4ad74a5d3a4cc91ecd3fb0430c",
        ),
        (
            "enterprise-risk-response-v2.json",
            "1785cf19e5a29ef8fb774a37138e6516e2d9d68f8a8ed21af01546dccfbff185",
        ),
    ],
)
def test_platform_wire_mapper_verifies_neutral_fixed_vectors(
    filename: str,
    expected_digest: str,
) -> None:
    body = (EXAMPLES / filename).read_bytes()
    document = json.loads(body)
    decoded = decode_inbound_message(body)
    message = decoded.message
    client = ExchangeClient(
        sender_id=document["sender"]["system_id"],
        party_id=document["sender"]["party_id"],
        mine_id=document["mine_id"],
        secret=EXAMPLE_SECRET,
        message_key_id=document["signature_envelope"]["key_id"],
    )

    assert (
        verify_exchange_message_signature(message, client, decoded.document)
        == expected_digest
    )


def test_application_signature_rejects_changed_payload() -> None:
    document = json.loads((EXAMPLES / "five-quantity-submission-v2.json").read_text())
    document["payload"]["mine"]["mine_name"] = "被改动的名称"
    body = json.dumps(document, ensure_ascii=False).encode()
    message = parse_inbound_message(body)
    client = ExchangeClient(
        sender_id=document["sender"]["system_id"],
        party_id=document["sender"]["party_id"],
        mine_id=document["mine_id"],
        secret=EXAMPLE_SECRET,
        message_key_id=document["signature_envelope"]["key_id"],
    )

    with pytest.raises(ExchangeAuthenticationError):
        verify_exchange_message_signature(message, client)


def test_application_signature_uses_raw_lexical_payload_not_model_dump() -> None:
    document = json.loads((EXAMPLES / "five-quantity-submission-v2.json").read_text())
    document["payload"]["closed_at"] = "2026-08-01T00:00:00+00:00"
    document["payload"]["days"][0]["reported_quantity"]["shifts"]["zero_shift"][
        "start_at"
    ] = "2026-07-28T16:00:00.000+00:00"
    sign_exchange_message(document, EXAMPLE_SECRET)
    body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    decoded = decode_inbound_message(body)
    client = ExchangeClient(
        sender_id=document["sender"]["system_id"],
        party_id=document["sender"]["party_id"],
        mine_id=document["mine_id"],
        secret=EXAMPLE_SECRET,
        message_key_id=document["signature_envelope"]["key_id"],
    )

    assert decoded.message.payload.closed_at.isoformat().endswith("+00:00")
    assert decoded.document["payload"]["closed_at"].endswith("+00:00")
    assert (
        verify_exchange_message_signature(
            decoded.message,
            client,
            decoded.document,
        )
        == hashlib.sha256(jcs_canonical_json(document["payload"]).encode()).hexdigest()
    )


def test_signature_verifier_refuses_to_reconstruct_missing_wire_document() -> None:
    document = json.loads((EXAMPLES / "risk-delivery-ack-v2.json").read_text())
    parsed = parse_inbound_message(json.dumps(document).encode())
    reconstructed_only = type(parsed).model_validate(document)
    client = ExchangeClient(
        sender_id=document["sender"]["system_id"],
        party_id=document["sender"]["party_id"],
        mine_id=document["mine_id"],
        secret=EXAMPLE_SECRET,
        message_key_id=document["signature_envelope"]["key_id"],
    )

    with pytest.raises(ExchangeAuthenticationError):
        verify_exchange_message_signature(reconstructed_only, client)


def test_application_key_id_selects_exact_rotation_key() -> None:
    current_secret = b"current-application-key-material-0000000001"
    previous_secret = b"previous-application-key-material-000000001"
    document = json.loads((EXAMPLES / "risk-delivery-ack-v2.json").read_text())
    document["signature_envelope"]["key_id"] = "enterprise-key-old"
    sign_exchange_message(document, previous_secret)
    decoded = decode_inbound_message(json.dumps(document).encode())
    client = ExchangeClient(
        sender_id=document["sender"]["system_id"],
        party_id=document["sender"]["party_id"],
        mine_id=document["mine_id"],
        secret=current_secret,
        message_key_id="enterprise-key-current",
        previous_message_keys={"enterprise-key-old": previous_secret},
    )

    assert (
        verify_exchange_message_signature(
            decoded.message,
            client,
            decoded.document,
        )
        == document["signature_envelope"]["payload_sha256"]
    )

    spoofed = deepcopy(document)
    spoofed["signature_envelope"]["key_id"] = "enterprise-key-current"
    sign_exchange_message(spoofed, previous_secret)
    spoofed_decoded = decode_inbound_message(json.dumps(spoofed).encode())
    with pytest.raises(ExchangeAuthenticationError):
        verify_exchange_message_signature(
            spoofed_decoded.message,
            client,
            spoofed_decoded.document,
        )


def test_named_key_config_and_single_key_legacy_config_are_supported() -> None:
    common = {
        "sender_id": "agent-mine-001",
        "party_id": "operator-mine-001",
        "mine_id": "MINE-001",
        "transport_secret": "transport-secret-material-that-is-long-enough",
    }
    configured = parse_exchange_clients(
        json.dumps(
            {
                "clients": [
                    {
                        **common,
                        "active_message_key_id": "key-new",
                        "message_keys": {
                            "key-new": "new-message-secret-material-that-is-long-enough",
                            "key-old": "old-message-secret-material-that-is-long-enough",
                        },
                    }
                ]
            }
        )
    )["agent-mine-001"]
    assert configured.message_key_id == "key-new"
    assert set(configured.message_verification_keys) == {"key-new", "key-old"}

    legacy = parse_exchange_clients(
        json.dumps(
            {
                "clients": [
                    {
                        **common,
                        "message_secret": (
                            "legacy-message-secret-material-that-is-long-enough"
                        ),
                    }
                ]
            }
        )
    )["agent-mine-001"]
    assert legacy.message_key_id == "demo-exchange-key"


def test_legacy_rotation_requires_parallel_key_ids() -> None:
    with pytest.raises(ValueError, match="parallel message_key_ids"):
        parse_exchange_clients(
            json.dumps(
                {
                    "clients": [
                        {
                            "sender_id": "agent-mine-001",
                            "party_id": "operator-mine-001",
                            "mine_id": "MINE-001",
                            "message_secrets": ["a" * 32, "b" * 32],
                            "transport_secret": "c" * 32,
                        }
                    ]
                }
            )
        )


@pytest.mark.parametrize(
    "transport_value", [None, "same-message-secret-material-00000000"]
)
def test_client_registry_fails_closed_on_transport_key_reuse_or_omission(
    transport_value: str | None,
) -> None:
    entry = {
        "sender_id": "agent-mine-001",
        "party_id": "operator-mine-001",
        "mine_id": "MINE-001",
        "message_secret": "same-message-secret-material-00000000",
    }
    if transport_value is not None:
        entry["transport_secret"] = transport_value

    with pytest.raises(ValueError, match="transport|must be different"):
        parse_exchange_clients(json.dumps({"clients": [entry]}))


def test_multi_finding_response_is_not_silently_truncated() -> None:
    document = json.loads((EXAMPLES / "enterprise-risk-response-v2.json").read_text())
    second = dict(document["payload"]["finding_responses"][0])
    second["finding_id"] = "33333333-3333-4333-8333-333333333339"
    second["facts"] = "第二项风险的独立事实说明。"
    document["payload"]["finding_responses"].append(second)
    # This test exercises mapping, not signature verification.
    message = parse_inbound_message(json.dumps(document, ensure_ascii=False).encode())

    responses = message.to_store_responses()

    assert [item.finding_id for item in responses] == [
        "33333333-3333-4333-8333-333333333332",
        "33333333-3333-4333-8333-333333333339",
    ]
    assert len({item.response_id for item in responses}) == 2
    assert responses[1].explanation == "第二项风险的独立事实说明。"


@pytest.mark.parametrize(
    "case",
    [
        "ack_revision",
        "response_uuid",
        "timezone",
        "shift_code",
        "optional_null",
        "delivery_cursor",
        "duplicate_shift_code",
        "shift_gap",
        "shift_wrong_local_day",
        "numeric_string",
        "boolean_string",
        "date_number",
        "ack_revision_boolean",
    ],
)
def test_inbound_models_reject_schema_invalid_members(case: str) -> None:
    if case in {"ack_revision", "delivery_cursor", "ack_revision_boolean"}:
        document = json.loads((EXAMPLES / "risk-delivery-ack-v2.json").read_text())
    elif case == "response_uuid":
        document = json.loads(
            (EXAMPLES / "enterprise-risk-response-v2.json").read_text()
        )
    else:
        document = json.loads(
            (EXAMPLES / "five-quantity-submission-v2.json").read_text()
        )

    if case == "ack_revision":
        document["revision"] = 2
        document["predecessor"] = {
            "message_id": "11111111-1111-4111-8111-111111111111",
            "payload_sha256": "0" * 64,
        }
    elif case == "response_uuid":
        document["payload"]["response_id"] = "x" * 36
    elif case == "ack_revision_boolean":
        document["revision"] = True
    elif case == "timezone":
        document["payload"]["timezone"] = "Mars/Olympus"
    elif case == "shift_code":
        document["payload"]["days"][0]["reported_quantity"]["shifts"]["zero_shift"][
            "shift_code"
        ] = "zero shift"
    elif case == "optional_null":
        document["payload"]["sources"][0]["source_location"] = None
    elif case == "delivery_cursor":
        document["payload"]["delivery_cursor"] = "cursor/with/slash"
    elif case == "duplicate_shift_code":
        shifts = document["payload"]["days"][0]["reported_quantity"]["shifts"]
        shifts["eight_shift"]["shift_code"] = shifts["zero_shift"]["shift_code"]
    elif case == "shift_gap":
        document["payload"]["days"][0]["reported_quantity"]["shifts"]["zero_shift"][
            "end_at"
        ] = "2026-07-29T00:01:00Z"
    elif case == "shift_wrong_local_day":
        document["payload"]["days"][0]["reported_quantity"]["shifts"]["zero_shift"][
            "start_at"
        ] = "2026-07-28T15:00:00Z"
    elif case == "numeric_string":
        document["payload"]["days"][0]["reported_quantity"]["daily_total"][
            "production_t"
        ]["value"] = "123"
    elif case == "boolean_string":
        document["payload"]["agent_processing"]["normalization_performed"] = "true"
    else:
        document["payload"]["period_start"] = 0

    with pytest.raises(ValueError):
        parse_inbound_message(json.dumps(document).encode())


def test_three_shift_validation_allows_dst_adjusted_absolute_duration() -> None:
    document = json.loads((EXAMPLES / "five-quantity-submission-v2.json").read_text())
    document["payload"]["reporting_month"] = "2026-03"
    document["payload"]["timezone"] = "America/New_York"
    document["payload"]["period_start"] = "2026-03-08"
    document["payload"]["period_end"] = "2026-03-08"
    document["payload"]["days"] = [document["payload"]["days"][0]]
    day = document["payload"]["days"][0]
    day["date"] = "2026-03-08"
    shifts = day["reported_quantity"]["shifts"]
    shifts["zero_shift"].update(
        {
            "start_at": "2026-03-08T00:00:00-05:00",
            "end_at": "2026-03-08T08:00:00-04:00",
        }
    )
    shifts["eight_shift"].update(
        {
            "start_at": "2026-03-08T08:00:00-04:00",
            "end_at": "2026-03-08T16:00:00-04:00",
        }
    )
    shifts["four_shift"].update(
        {
            "start_at": "2026-03-08T16:00:00-04:00",
            "end_at": "2026-03-09T00:00:00-04:00",
        }
    )
    document["payload"]["closed_at"] = "2026-03-09T00:00:00Z"
    for source in document["payload"]["sources"]:
        source["captured_at"] = "2026-03-09T00:01:00Z"
    document["payload"]["human_confirmation"]["confirmed_at"] = "2026-03-09T00:04:00Z"
    document["created_at"] = "2026-03-09T00:05:00Z"
    document["signature_envelope"]["signed_at"] = "2026-03-09T00:05:00Z"

    message = parse_inbound_message(json.dumps(document).encode())

    first = message.payload.days[0].reported_quantity.shifts.zero_shift
    assert first.end_at.astimezone(UTC) - first.start_at.astimezone(UTC) == timedelta(
        hours=7
    )


def test_duplicate_members_and_non_json_numbers_are_rejected() -> None:
    body = (EXAMPLES / "risk-delivery-ack-v2.json").read_text()
    duplicate = body.replace(
        '"message_type": "risk_delivery_ack",',
        '"message_type": "risk_delivery_ack",\n  "message_type": "risk_delivery_ack",',
        1,
    )
    with pytest.raises(ValueError, match="valid I-JSON"):
        decode_inbound_message(duplicate.encode())

    document = json.loads(body)
    document["payload"]["received_at"] = float("nan")
    with pytest.raises(ValueError, match="valid I-JSON"):
        decode_inbound_message(json.dumps(document).encode())


def _revised_submission_document() -> tuple[dict[str, object], dict[str, object]]:
    predecessor = json.loads(
        (EXAMPLES / "five-quantity-submission-v2.json").read_text()
    )
    current = deepcopy(predecessor)
    current["message_id"] = "66666666-6666-4666-8666-666666666666"
    current["revision"] = 2
    current["predecessor"] = {
        "message_id": predecessor["message_id"],
        "payload_sha256": predecessor["signature_envelope"]["payload_sha256"],
    }
    current["causation_id"] = predecessor["message_id"]
    current["idempotency_key"] = "mine-qy-001.2026-07-31.r2"
    return predecessor, current


def test_strict_lineage_accepts_only_direct_continuation() -> None:
    predecessor, current = _revised_submission_document()
    message = parse_inbound_message(json.dumps(current).encode())

    validate_exchange_lineage(message, predecessor=predecessor)


@pytest.mark.parametrize(
    "case",
    [
        "skipped_revision",
        "wrong_predecessor_id",
        "wrong_predecessor_hash",
        "changed_correlation",
        "changed_mine",
        "unknown_cause",
    ],
)
def test_strict_lineage_rejects_broken_workflow(case: str) -> None:
    predecessor, current = _revised_submission_document()
    if case == "skipped_revision":
        current["revision"] = 3
    elif case == "wrong_predecessor_id":
        current["predecessor"]["message_id"] = "77777777-7777-4777-8777-777777777777"
    elif case == "wrong_predecessor_hash":
        current["predecessor"]["payload_sha256"] = "0" * 64
    elif case == "changed_correlation":
        current["correlation_id"] = "77777777-7777-4777-8777-777777777777"
    elif case == "changed_mine":
        current["mine_id"] = "MINE-QY-OTHER"
        current["payload"]["mine"]["mine_id"] = "MINE-QY-OTHER"
    else:
        current["causation_id"] = "77777777-7777-4777-8777-777777777777"
    message = parse_inbound_message(json.dumps(current).encode())

    with pytest.raises(ExchangeLineageError):
        validate_exchange_lineage(message, predecessor=predecessor)


def test_lineage_binds_initial_ack_to_report_workflow_and_mine() -> None:
    report = json.loads((EXAMPLES / "analysis-report-v2.json").read_text())
    ack = parse_inbound_message((EXAMPLES / "risk-delivery-ack-v2.json").read_bytes())

    validate_exchange_lineage(ack, allowed_causes=(report,))

    wrong_scope = deepcopy(report)
    wrong_scope["mine_id"] = "MINE-QY-OTHER"
    with pytest.raises(ExchangeLineageError, match="another mine"):
        validate_exchange_lineage(ack, allowed_causes=(wrong_scope,))


def test_lineage_supports_revised_response_with_report_as_direct_cause() -> None:
    predecessor = json.loads(
        (EXAMPLES / "enterprise-risk-response-v2.json").read_text()
    )
    report = json.loads((EXAMPLES / "analysis-report-v2.json").read_text())
    current = deepcopy(predecessor)
    current["message_id"] = "77777777-7777-4777-8777-777777777777"
    current["idempotency_key"] = "risk-response.33333333.r2"
    current["revision"] = 2
    current["predecessor"] = {
        "message_id": predecessor["message_id"],
        "payload_sha256": predecessor["signature_envelope"]["payload_sha256"],
    }
    current["payload"]["response_id"] = "88888888-8888-4888-8888-888888888888"
    message = parse_inbound_message(json.dumps(current).encode())

    validate_exchange_lineage(
        message,
        predecessor=predecessor,
        allowed_causes=(report,),
    )


def test_transport_signature_uses_contract_domain_and_exact_query() -> None:
    common = dict(
        method="GET",
        sender_id="agent-mine-qy-001",
        timestamp="2026-08-01T00:00:00Z",
        nonce="AAECAwQFBgcICQoLDA0ODw",
        contract_version="five-quantity-exchange-v2",
        content_sha256=(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
    )

    first = transport_signature(
        EXAMPLE_SECRET,
        request_target="/v2/analysis-reports/next?after_cursor=mine.cursor.1",
        **common,
    )
    second = transport_signature(
        EXAMPLE_SECRET,
        request_target="/v2/analysis-reports/next?after_cursor=mine.cursor.2",
        **common,
    )

    assert EXCHANGE_TRANSPORT_CONTEXT == (
        "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V2"
    )
    assert first != second
