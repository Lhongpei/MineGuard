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
    EXCHANGE_TRANSPORT_CONTEXT_V3,
    ExchangeAuthenticationError,
    ExchangeClient,
    ExchangeLineageError,
    authenticate_transport,
    decode_inbound_message,
    load_exchange_clients,
    parse_exchange_clients,
    parse_inbound_message,
    sign_exchange_message,
    sign_transport_headers,
    transport_signature,
    validate_exchange_lineage,
    validate_production_exchange_clients,
    validate_production_platform_identity,
    verify_exchange_message_signature,
)


ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "contracts" / "examples"
EXAMPLE_SECRET = b"example-v2-exchange-secret-not-for-production"
PRODUCTION_COMPARISON_CONTEXT = {
    "capacity_band": "0.9-1.2Mtpa",
    "mining_method": "underground-longwall",
    "shift_system": "three-shift-eight-hour",
    "coal_type": "thermal-coal",
    "operating_regime": "normal-production",
}


def _production_registry_document() -> dict[str, object]:
    return {
        "clients": [
            {
                "sender_id": "agent-mine-001",
                "party_id": "operator-mine-001",
                "mine_id": "MINE-001",
                "mine_name": "沁源一号煤矿",
                "active_message_key_id": "mine001-msg-2026q3-a7f4",
                "message_keys": {
                    "mine001-msg-2026q3-a7f4": ("mG8xQ2pL9vR4sT7wY3kN6cD1fH5jB0zA"),
                    "mine001-msg-2026q2-b9e1": ("R7cN2yK9mV4qH6xD1sP8aJ3wF5tB0zLu"),
                },
                "transport_secrets": [
                    "uC7nP2aX9dK4qW6rE1vM8sJ3hF5bT0yZ",
                    "L4hV9sQ2nD7xK1mR6pC8wA3jY5tF0zBu",
                ],
                "comparison_context": dict(PRODUCTION_COMPARISON_CONTEXT),
            }
        ]
    }


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
    document = json.loads(
        (EXAMPLES / "five-quantity-submission-v2.json").read_text(encoding="utf-8")
    )
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
    document = json.loads(
        (EXAMPLES / "five-quantity-submission-v2.json").read_text(encoding="utf-8")
    )
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
    document = json.loads(
        (EXAMPLES / "risk-delivery-ack-v2.json").read_text(encoding="utf-8")
    )
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
    document = json.loads(
        (EXAMPLES / "risk-delivery-ack-v2.json").read_text(encoding="utf-8")
    )
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


def test_exchange_clients_can_be_loaded_from_an_absolute_utf8_bom_file(
    tmp_path: Path,
) -> None:
    registry = {
        "clients": [
            {
                "sender_id": "agent-mine-001",
                "party_id": "operator-mine-001",
                "mine_id": "MINE-001",
                "message_secret": "message-secret-material-that-is-long-enough",
                "transport_secret": "transport-secret-material-that-is-long-enough",
            }
        ]
    }
    path = tmp_path / "clients.json"
    path.write_text(json.dumps(registry), encoding="utf-8-sig")

    clients = load_exchange_clients(None, str(path))

    assert set(clients) == {"agent-mine-001"}
    assert clients["agent-mine-001"].mine_id == "MINE-001"


def test_exchange_clients_file_fails_closed_for_ambiguous_or_unsafe_sources(
    tmp_path: Path,
) -> None:
    path = tmp_path / "clients.json"
    path.write_text('{"clients": []}', encoding="utf-8")

    with pytest.raises(ValueError, match="only one"):
        load_exchange_clients('{"clients": []}', str(path))
    with pytest.raises(ValueError, match="only one"):
        load_exchange_clients("", str(path))
    with pytest.raises(ValueError, match="must not be empty"):
        load_exchange_clients(None, "")
    with pytest.raises(ValueError, match="absolute"):
        load_exchange_clients(None, "clients.json")
    with pytest.raises(ValueError, match="4 MiB"):
        load_exchange_clients(None, str(path), maximum_bytes=4)

    link = tmp_path / "clients-link.json"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("the current test account cannot create symbolic links")
    with pytest.raises(ValueError, match="symbolic links"):
        load_exchange_clients(None, str(link))


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


@pytest.mark.parametrize("secret_field", ["message_secret", "transport_secret"])
def test_client_registry_rejects_template_secret_material(
    secret_field: str,
) -> None:
    entry = {
        "sender_id": "agent-mine-001",
        "party_id": "operator-mine-001",
        "mine_id": "MINE-001",
        "message_secret": "valid-message-secret-material-0000000001",
        "transport_secret": "valid-transport-secret-material-000000001",
    }
    entry[secret_field] = "replace-with-independent-random-secret-0001"
    with pytest.raises(ValueError, match="placeholder"):
        parse_exchange_clients(json.dumps({"clients": [entry]}))


def test_production_client_registry_accepts_governed_rotation_material() -> None:
    clients = parse_exchange_clients(json.dumps(_production_registry_document()))

    validate_production_exchange_clients(clients)


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("active_message_low_diversity", "byte diversity"),
        ("previous_message_repeated", "repeated short fragment"),
        ("previous_transport_low_diversity", "byte diversity"),
        ("active_key_id_placeholder", "placeholder message key ID"),
        ("previous_key_id_placeholder", "placeholder message key ID"),
        ("mine_name_missing", "non-placeholder mine_name"),
        ("context_missing", "five comparison_context"),
        ("context_unclassified", "placeholder comparison_context"),
        ("context_replace_me", "placeholder comparison_context"),
        ("secret_reused_during_rotation", "must not be reused"),
    ],
)
def test_production_client_registry_rejects_low_quality_governance(
    case: str,
    message: str,
) -> None:
    document = _production_registry_document()
    entry = document["clients"][0]
    assert isinstance(entry, dict)
    message_keys = entry["message_keys"]
    transport_secrets = entry["transport_secrets"]
    context = entry["comparison_context"]
    assert isinstance(message_keys, dict)
    assert isinstance(transport_secrets, list)
    assert isinstance(context, dict)

    if case == "active_message_low_diversity":
        message_keys["mine001-msg-2026q3-a7f4"] = "a" * 32
    elif case == "previous_message_repeated":
        message_keys["mine001-msg-2026q2-b9e1"] = "0123456789ABCDEF" * 2
    elif case == "previous_transport_low_diversity":
        transport_secrets[1] = "b" * 32
    elif case == "active_key_id_placeholder":
        secret = message_keys.pop("mine001-msg-2026q3-a7f4")
        message_keys["demo-key"] = secret
        entry["active_message_key_id"] = "demo-key"
    elif case == "previous_key_id_placeholder":
        secret = message_keys.pop("mine001-msg-2026q2-b9e1")
        message_keys["test-key"] = secret
    elif case == "mine_name_missing":
        del entry["mine_name"]
    elif case == "context_missing":
        del entry["comparison_context"]
    elif case == "context_unclassified":
        context["coal_type"] = "unclassified"
    elif case == "context_replace_me":
        context["operating_regime"] = "replace-me"
    elif case == "secret_reused_during_rotation":
        message_keys["mine001-msg-2026q2-b9e1"] = message_keys[
            "mine001-msg-2026q3-a7f4"
        ]
    else:  # pragma: no cover - protects the parameter table itself
        raise AssertionError(case)

    # Compatibility parsing remains available for isolated demonstrations;
    # only a production boundary applies the additional quality gate.
    clients = parse_exchange_clients(json.dumps(document))
    with pytest.raises(ValueError, match=message):
        validate_production_exchange_clients(clients)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sender_id", "synthetic-demo-agent"),
        ("party_id", "replace-party"),
        ("mine_id", "DEMO-MINE"),
        ("mine_name", "示例一号煤矿"),
    ],
)
def test_production_client_registry_rejects_placeholder_public_identity(
    field: str,
    value: str,
) -> None:
    document = _production_registry_document()
    entry = document["clients"][0]
    assert isinstance(entry, dict)
    entry[field] = value

    clients = parse_exchange_clients(json.dumps(document))
    with pytest.raises(ValueError, match=f"placeholder {field}"):
        validate_production_exchange_clients(clients)


def test_production_platform_identity_accepts_defaults_and_rejects_collisions() -> None:
    clients = parse_exchange_clients(json.dumps(_production_registry_document()))
    validate_production_platform_identity(
        "mineguard-qinyuan",
        "regulator-qinyuan",
        "regulator-key-v2",
        clients=clients,
    )

    for values, message in (
        (("demo-platform", "regulator-qinyuan", "gov-key-2026q3"), "placeholder"),
        (("mineguard-qinyuan", "replace-party", "gov-key-2026q3"), "placeholder"),
        (("mineguard-qinyuan", "regulator-qinyuan", "test-key"), "placeholder"),
        (("invalid system", "regulator-qinyuan", "gov-key-2026q3"), "invalid"),
        (
            (
                "mineguard-qinyuan",
                "regulator-qinyuan",
                "mine001-msg-2026q3-a7f4",
            ),
            "must not reuse",
        ),
    ):
        with pytest.raises(ValueError, match=message):
            validate_production_platform_identity(*values, clients=clients)


def test_multi_finding_response_is_not_silently_truncated() -> None:
    document = json.loads(
        (EXAMPLES / "enterprise-risk-response-v2.json").read_text(encoding="utf-8")
    )
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
        document = json.loads(
            (EXAMPLES / "risk-delivery-ack-v2.json").read_text(encoding="utf-8")
        )
    elif case == "response_uuid":
        document = json.loads(
            (EXAMPLES / "enterprise-risk-response-v2.json").read_text(
                encoding="utf-8"
            )
        )
    else:
        document = json.loads(
            (EXAMPLES / "five-quantity-submission-v2.json").read_text(
                encoding="utf-8"
            )
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
    document = json.loads(
        (EXAMPLES / "five-quantity-submission-v2.json").read_text(encoding="utf-8")
    )
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
    body = (EXAMPLES / "risk-delivery-ack-v2.json").read_text(encoding="utf-8")
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
        (EXAMPLES / "five-quantity-submission-v2.json").read_text(encoding="utf-8")
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
    report = json.loads(
        (EXAMPLES / "analysis-report-v2.json").read_text(encoding="utf-8")
    )
    ack = parse_inbound_message((EXAMPLES / "risk-delivery-ack-v2.json").read_bytes())

    validate_exchange_lineage(ack, allowed_causes=(report,))

    wrong_scope = deepcopy(report)
    wrong_scope["mine_id"] = "MINE-QY-OTHER"
    with pytest.raises(ExchangeLineageError, match="another mine"):
        validate_exchange_lineage(ack, allowed_causes=(wrong_scope,))


def test_lineage_supports_revised_response_with_report_as_direct_cause() -> None:
    predecessor = json.loads(
        (EXAMPLES / "enterprise-risk-response-v2.json").read_text(encoding="utf-8")
    )
    report = json.loads(
        (EXAMPLES / "analysis-report-v2.json").read_text(encoding="utf-8")
    )
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


def test_v3_route_uses_v3_transport_domain_for_reused_v2_message_contract() -> None:
    client = ExchangeClient(
        sender_id="agent-mine-qy-001",
        party_id="operator-qy-001",
        mine_id="MINE-QY-001",
        secret=b"message-secret-material-that-is-long-enough",
        transport_secret=b"transport-secret-material-that-is-long-enough",
    )
    target = "/v3/analysis-reports/11111111-1111-4111-8111-111111111111/delivery-ack"
    body = b'{"contract_version":"risk-delivery-ack-v2"}'
    headers = sign_transport_headers(
        client,
        method="POST",
        request_target=target,
        body=body,
        contract_version="risk-delivery-ack-v2",
    )

    assert EXCHANGE_TRANSPORT_CONTEXT_V3 == (
        "MINEGUARD-TEN-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V3"
    )
    assert headers["X-Exchange-Signature-Version"] == "hmac-sha256-v3"
    authenticated, _timestamp, _nonce, contract = authenticate_transport(
        {client.sender_id: client},
        headers,
        method="POST",
        request_target=target,
        body=body,
    )
    assert authenticated is client
    assert contract == "risk-delivery-ack-v2"

    absolute_target = f"http://127.0.0.1:8080{target}"
    absolute_headers = sign_transport_headers(
        client,
        method="POST",
        request_target=absolute_target,
        body=body,
        contract_version="risk-delivery-ack-v2",
    )
    assert absolute_headers["X-Exchange-Signature-Version"] == "hmac-sha256-v3"
    assert authenticate_transport(
        {client.sender_id: client},
        absolute_headers,
        method="POST",
        request_target=absolute_target,
        body=body,
    )[0] is client

    with pytest.raises(ExchangeAuthenticationError):
        authenticate_transport(
            {client.sender_id: client},
            headers,
            method="POST",
            request_target=target.replace("/v3/", "/v2/"),
            body=body,
        )
