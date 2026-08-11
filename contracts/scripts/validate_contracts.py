#!/usr/bin/env python3
"""Validate the standalone enterprise-submission contract artifacts.

The baseline checks use only Python's standard library.  If ``jsonschema`` is
installed, examples are additionally validated against Draft 2020-12 schemas.
This script intentionally imports no enterprise-agent or regulatory-platform
code.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import math
from datetime import datetime, timedelta
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


CONTRACT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = {
    "enterprise-agent-provisioning-bundle-v1.json": (
        "provisioning-bundle-v1.schema.json"
    ),
    "platform-client-registration-bundle-v1.json": (
        "provisioning-bundle-v1.schema.json"
    ),
    "enterprise-agent-provisioning-payload-v1.json": (
        "enterprise-agent-provisioning-payload-v1.schema.json"
    ),
    "platform-client-registration-payload-v1.json": (
        "platform-client-registration-payload-v1.schema.json"
    ),
    "model-credential-bundle-v1.json": ("model-credential-bundle-v1.schema.json"),
    "model-credential-profile-v1.json": ("model-credential-profile-v1.schema.json"),
    "model-credential-payload-v1.json": ("model-credential-payload-v1.schema.json"),
    "model-issuer-trust-store-v1.json": ("model-issuer-trust-store-v1.schema.json"),
    "enterprise-autofill-ingestion-v1.json": (
        "enterprise-autofill-ingestion-v1.schema.json"
    ),
    "enterprise-source-health-v1.json": "enterprise-source-health-v1.schema.json",
    "enterprise-submission-v1.json": "enterprise-submission-v1.schema.json",
    "submission-receipt-v1.json": "submission-receipt-v1.schema.json",
    "error-v1.json": "error-v1.schema.json",
    "capabilities-v1.json": "capabilities-v1.schema.json",
    "edge-telemetry-batch-v1.json": "edge-telemetry-batch-v1.schema.json",
    "edge-telemetry-receipt-v1.json": "edge-telemetry-receipt-v1.schema.json",
    "edge-telemetry-capabilities-v1.json": (
        "edge-telemetry-capabilities-v1.schema.json"
    ),
    "five-quantity-submission-v2.json": "five-quantity-submission-v2.schema.json",
    "intake-receipt-v2.json": "intake-receipt-v2.schema.json",
    "analysis-report-v2.json": "analysis-report-v2.schema.json",
    "risk-delivery-ack-v2.json": "risk-delivery-ack-v2.schema.json",
    "enterprise-risk-response-v2.json": "enterprise-risk-response-v2.schema.json",
    "response-receipt-v2.json": "response-receipt-v2.schema.json",
    "ten-quantity-submission-v3.json": "ten-quantity-submission-v3.schema.json",
    "analysis-report-v3.json": "analysis-report-v3.schema.json",
}
EXPECTED_PAYLOAD_SHA256 = (
    "f730ae0a8c047c6d094f81eac048f94e46f287bf9cabe7c5b5732f84230b7ac1"
)
EXPECTED_OBSERVATION_SHA256 = (
    "78a5d9cf36c2b566511bee3364ae714a02479da6ff8b02f2b996de5574c197a9"
)
EXPECTED_OBSERVATION_SIGNATURE = (
    "59dc38c6346e0f955976c541a093644276c9f36830de8d4c38aee79b56e82477"
)
EXPECTED_BODY_SHA256 = (
    "e4aab1c54596bded8e65dde774774b072f94b9d650629cc37b5eeeb2cda23c3b"
)
EXPECTED_TRANSPORT_SIGNATURE = (
    "1f26b2f2541ddefd388dba69fb9d601fb25a7d2448c2f0b021c198edba97795e"
)
EXPECTED_CONNECTOR_VECTORS = {
    "enterprise-autofill-ingestion-v1.json": (
        "/api/v1/machine/autofill",
        "1785475200",
        "creq_example_autofill_001",
        "6ac2d11c104e876dfb9167f5bc48f07ed27ba369ba312ffc17455e827bae2b48",
        "0cb4651311da338f912185efded84d35d427af29d509e439b4163f0f082dad86",
    ),
    "enterprise-source-health-v1.json": (
        "/api/v1/machine/source-health",
        "1785475260",
        "creq_example_health_001",
        "6a39402c350186ba63d1e6505d8b8161894eea2d42d227b5290a15d9ab1bda4e",
        "0e968a5eeb8817be737e890a049fb5617f22bb3569711273b65c706ce832af4c",
    ),
}
CONNECTOR_EXAMPLE_SECRET = b"example-enterprise-connector-secret-not-for-production"
EXPECTED_EDGE_BODY_SHA256 = (
    "f289284d73836288cae3191eeac928b62d78c8988418e1016e4f956c08af2aab"
)
EXPECTED_EDGE_TRANSPORT_SIGNATURE = (
    "8d56b417514d8f78c9d0e5c431880aa5eb5df49b15cbaea1ec59efe1ac0b6001"
)
EXPECTED_V2_VECTORS = {
    "five-quantity-submission-v2.json": (
        "cf22a046f2899e4f11dd91f76ef37e2040da6e20f541bf16943946b1300aff35",
        "39cea3887d4897dc3a76d4a2e3cf0399cc8d20d9d0e7547debe44411396ff5ab",
    ),
    "intake-receipt-v2.json": (
        "ce2c24c7a60b715a99e06b738539052eb5ca7b16c309b8188c4c9c8fab467f1e",
        "5873ab8850fed8ac6821d9b75e47b6ffd3c471ec841ba45ea77f79d79b297339",
    ),
    "analysis-report-v2.json": (
        "689af99d8cafb5799fe7845b020e4b4022c121a8f9219ecdf4b7dbe89b43b1b9",
        "ad317641229a6d9221b4284b2eaf3cd2778c98577b4b46ae6650cd3f7e8953bd",
    ),
    "risk-delivery-ack-v2.json": (
        "7c9a80c12e96a2d216533af95b8c5172d86a0b4ad74a5d3a4cc91ecd3fb0430c",
        "f6919b16c14be7801a242a7a88f88e4075ce91eb655b861c7f1b474f25d25b49",
    ),
    "enterprise-risk-response-v2.json": (
        "1785cf19e5a29ef8fb774a37138e6516e2d9d68f8a8ed21af01546dccfbff185",
        "775d61e71d21d4da6b1b35277c795d56c2e23bc8b6c4abb14d30ffc27cc52a4b",
    ),
    "response-receipt-v2.json": (
        "8a7a585a0bbeffc62f8e866cb590cd6dbb7b84a0594c241a6b75406ec9fba4d8",
        "0ebde843d41519864c2054bb0a15466e94eda602fbd465a80c79b6a1ff0c8eaa",
    ),
}
V2_EXAMPLE_SECRET = b"example-v2-exchange-secret-not-for-production"
V2_FIVE_QUANTITY_GROUPS = {
    "airflow": ["ventilation_m3_min"],
    "electricity": ["electricity_kwh"],
    "blasting_materials": ["detonators_count", "explosives_kg"],
    "mine_entry_personnel": ["mine_entry_persons"],
    "production": ["production_t"],
}
EXPECTED_V3_VECTORS = {
    "ten-quantity-submission-v3.json": (
        "9a5467b816bd4d971ecab3dd4331f49aecc483ab35358b95f08456f8a1765dd3",
        "71381f3e912547d34f33b4748e513448c4c06cec1db6b1f58620202818a05d40",
    ),
    "analysis-report-v3.json": (
        "0a2580eb0ece19c1de0f9b2b9ba0cdc268a3800523c76d7d01eeb735b348b6f0",
        "0c81e6689535ac7e7e18ec305943dd2e7c0e5eabb77fc644e0ae18a9a38fcdf3",
    ),
}
V3_EXAMPLE_SECRET = b"example-v3-exchange-secret-not-for-production"
V3_APPLICATION_SIGNATURE_DOMAIN = "MINEGUARD-TEN-QUANTITY-EXCHANGE-HMAC-SHA256-V3"
V3_HTTP_SIGNATURE_DOMAIN = "MINEGUARD-TEN-QUANTITY-EXCHANGE-HTTP-HMAC-SHA256-V3"
V2_APPLICATION_SIGNATURE_DOMAIN = "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HMAC-SHA256-V2"
V3_TEN_QUANTITY_GROUPS = {
    "airflow": ["ventilation_m3_min"],
    "electricity": ["electricity_kwh"],
    "blasting_materials": ["detonators_count", "explosives_kg"],
    "mine_entry_personnel": ["mine_entry_persons"],
    "production": ["production_t"],
    "extraction": ["extraction_t"],
    "sales": ["sales_t"],
    "transport": ["transport_t"],
    "coal_washing": ["wash_feed_t"],
    "invoicing": ["invoiced_quantity_t"],
}
V3_DAILY_METRICS = [
    metric_code
    for group_metrics in V3_TEN_QUANTITY_GROUPS.values()
    for metric_code in group_metrics
]
V3_SHIFT_REQUIRED_METRICS = V3_DAILY_METRICS[:7]
V3_SHIFT_OPTIONAL_METRICS = V3_DAILY_METRICS[7:]
V3_ENGINE_VERSION = "3.2.0"
V3_RUNTIME_BASE_MODULES = {
    "data_quality",
    "daily_shift_reconciliation",
    "l1_reconciliation",
    "minimal_conflict_set",
    "robust_temporal_baseline",
    "past_only_rolling_mad",
    "past_only_ewma",
    "past_only_cusum",
    "past_only_page_hinkley",
    "temporal_drift",
    "change_point",
    "operating_state_segmentation",
    "evidence_calibration",
}
V3_RUNTIME_RELATIONSHIP_MODULES = {
    "production_extraction_reconciliation",
    "production_sales_reconciliation",
    "production_transport_reconciliation",
    "production_wash_reconciliation",
    "sales_transport_reconciliation",
    "sales_invoice_reconciliation",
}
V3_RUNTIME_CONDITIONAL_MODULES = {
    "anonymous_peer_baseline",
    *V3_RUNTIME_RELATIONSHIP_MODULES,
}
V3_RUNTIME_FINDING_CATEGORIES = {
    "data_quality",
    "joint_consistency",
    "temporal_anomaly",
}
V3_RUNTIME_EVIDENCE_METHODS = {
    "data_completeness",
    "deterministic_reconciliation",
    "l1_reconciliation",
    "robust_temporal_baseline",
    "temporal_drift",
    "change_point",
    "anonymous_peer_baseline",
    "combined_calibration",
}
V3_BUSINESS_SEMANTICS = {
    "sales_t": {
        "basis": "delivered_sales_outbound_tonnage",
        "negative_allowed": False,
    },
    "transport_t": {
        "basis": "mine_outbound_external_transport_net_tonnage",
        "negative_allowed": False,
    },
    "wash_feed_t": {
        "basis": "raw_coal_feed_to_washing_tonnage",
        "negative_allowed": False,
    },
    "invoiced_quantity_t": {
        "basis": "normal_or_blue_invoice_coal_quantity_tonnage",
        "negative_allowed": False,
    },
}
V3_EXPECTED_BODY_SHA256 = (
    "4286f4e0bac39f090d3c3805f233a33de3f322d1c7cbcf5593438410fdd801e4"
)
V3_EXPECTED_TRANSPORT_SIGNATURE = (
    "8db2b067cbe5af7cabfe40cbb0887e42ec0384cbbac48cba3cab6e4ce11b7165"
)
V3_TRANSPORT_EXAMPLE_SECRET = b"example-v3-transport-secret-not-for-production"

PROVISIONING_EXAMPLES = {
    "enterprise-agent-provisioning": (
        "enterprise-agent-provisioning-bundle-v1.json",
        "enterprise-agent-provisioning-payload-v1.json",
    ),
    "platform-client-registration": (
        "platform-client-registration-bundle-v1.json",
        "platform-client-registration-payload-v1.json",
    ),
}
PROVISIONING_AGENT_CONFIG_REQUIRED = {
    "ENTERPRISE_AGENT_FOUR_EYES_REQUIRED",
    "ENTERPRISE_AGENT_PRODUCTION_MODE",
    "ENTERPRISE_AGENT_PUBLIC_ORIGIN",
    "ENTERPRISE_AGENT_SECURE_COOKIE",
    "ENTERPRISE_CAPACITY_BAND",
    "ENTERPRISE_COAL_TYPE",
    "ENTERPRISE_EXCHANGE_HMAC_SECRET",
    "ENTERPRISE_EXCHANGE_KEY_ID",
    "ENTERPRISE_MINE_ID",
    "ENTERPRISE_MINE_NAME",
    "ENTERPRISE_MINING_METHOD",
    "ENTERPRISE_OPERATING_REGIME",
    "ENTERPRISE_OPERATOR_ID",
    "ENTERPRISE_OPERATOR_NAME",
    "ENTERPRISE_REPORTING_TIMEZONE",
    "ENTERPRISE_SHIFT_SYSTEM",
    "ENTERPRISE_SYSTEM_ID",
    "PLATFORM_V3_BASE_URL",
    "PLATFORM_V3_CA_BUNDLE",
    "PLATFORM_V3_SENDER_ID",
    "PLATFORM_V3_TRANSPORT_HMAC_SECRET",
    "REGULATORY_EXCHANGE_KEY_ID",
    "REGULATORY_PARTY_ID",
    "REGULATORY_SYSTEM_ID",
}
PROVISIONING_AGENT_CONFIG_OPTIONAL = {
    "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON",
    "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET",
    "REGULATORY_PREVIOUS_EXCHANGE_KEY_ID",
}
MODEL_CREDENTIAL_EXAMPLE_API_KEY = "EXAMPLE_ONLY_NOT_A_REAL_PROVIDER_CREDENTIAL_2026"
MODEL_CREDENTIAL_EXAMPLE_CIPHERTEXT = "A" * 23
MODEL_CREDENTIAL_EXAMPLE_SIGNATURE = "A" * 86
MODEL_CREDENTIAL_CAPABILITIES = {
    "chat",
    "extraction",
    "coal-news-search",
}
MODEL_CREDENTIAL_EXAMPLES = {
    "bundle": "model-credential-bundle-v1.json",
    "profile": "model-credential-profile-v1.json",
    "payload": "model-credential-payload-v1.json",
    "trust_store": "model-issuer-trust-store-v1.json",
}


class ContractValidationError(RuntimeError):
    """One or more contract artifacts are inconsistent."""


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractValidationError(f"{path}: invalid JSON: {exc}") from exc


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _check_local_links(path: Path, document: Any) -> None:
    for node in _walk(document):
        for keyword in ("$ref", "externalValue"):
            target = node.get(keyword)
            if not isinstance(target, str):
                continue
            if target.startswith(("#", "http://", "https://", "urn:")):
                continue
            file_part = target.split("#", 1)[0]
            resolved = (path.parent / file_part).resolve()
            try:
                resolved.relative_to(CONTRACT_ROOT)
            except ValueError as exc:
                raise ContractValidationError(
                    f"{path}: {keyword} escapes contracts/: {target}"
                ) from exc
            if not resolved.is_file():
                raise ContractValidationError(
                    f"{path}: missing {keyword} target: {target}"
                )


def _jcs_example(value: Any) -> str:
    """Canonicalize the checked example's RFC 8785-compatible value subset.

    All object keys in the example are ASCII and its non-integral numbers have
    a plain ECMAScript/Python representation, so this compact serializer is
    byte-identical to RFC 8785 for this fixed vector. Production clients should
    use a complete, tested RFC 8785 implementation.
    """

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise ContractValidationError(
                "example integer exceeds the RFC 8785 interoperable range"
            )
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractValidationError("non-finite JSON number")
        rendered = json.dumps(value, allow_nan=False, separators=(",", ":"))
        if rendered.endswith(".0"):
            rendered = rendered[:-2]
        return rendered
    if isinstance(value, list):
        return "[" + ",".join(_jcs_example(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not key.isascii() for key in value):
            raise ContractValidationError(
                "fixed example checker expects ASCII object keys"
            )
        members = (
            json.dumps(key, ensure_ascii=False) + ":" + _jcs_example(value[key])
            for key in sorted(value)
        )
        return "{" + ",".join(members) + "}"
    raise ContractValidationError(f"unsupported JSON value: {type(value)!r}")


def _compact_sorted_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _check_fixed_vectors(submission_path: Path, submission: dict[str, Any]) -> None:
    canonical_payload = _jcs_example(submission["payload"]).encode("utf-8")
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    if payload_hash != EXPECTED_PAYLOAD_SHA256:
        raise ContractValidationError(
            f"payload vector changed: expected {EXPECTED_PAYLOAD_SHA256}, "
            f"got {payload_hash}"
        )
    if submission["payload_sha256"] != payload_hash:
        raise ContractValidationError("declared payload_sha256 is incorrect")

    observation = submission["payload"]["observations"][0]
    business_payload = {
        key: value
        for key, value in observation.items()
        if key not in {"field_provenance", "payload_sha256", "signature"}
        and not (
            (key in {"interval_start", "interval_end"} and value is None)
            or (key == "reset_before" and value is False)
        )
    }
    observation_hash = hashlib.sha256(
        _compact_sorted_json(business_payload)
    ).hexdigest()
    if observation_hash != EXPECTED_OBSERVATION_SHA256:
        raise ContractValidationError("observation payload vector changed")
    envelope = {
        "payload": business_payload,
        "payload_sha256": observation_hash,
    }
    material = b"MINEGUARD-GOVERNED-OBSERVATION-V1\x00" + _compact_sorted_json(envelope)
    observation_signature = hmac.new(
        b"example-device-secret-not-for-production",
        material,
        hashlib.sha256,
    ).hexdigest()
    if observation_signature != EXPECTED_OBSERVATION_SIGNATURE:
        raise ContractValidationError("observation signature vector changed")
    if (
        observation["payload_sha256"] != observation_hash
        or observation["signature"] != observation_signature
    ):
        raise ContractValidationError(
            "example observation digest/signature is incorrect"
        )

    body_hash = hashlib.sha256(submission_path.read_bytes()).hexdigest()
    if body_hash != EXPECTED_BODY_SHA256:
        raise ContractValidationError(
            "raw example body changed; update the transport test vector"
        )
    signing_lines = [
        "ENTERPRISE-SUBMISSION-HTTP-HMAC-SHA256-V1",
        "POST",
        "/v1/enterprise-submissions",
        "enterprise-client-example",
        "2026-07-27T08:05:00Z",
        "AAECAwQFBgcICQoLDA0ODw",
        "enterprise-submission-v1",
        body_hash,
    ]
    transport_signature = hmac.new(
        b"example-transport-secret-not-for-production",
        "\n".join(signing_lines).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if transport_signature != EXPECTED_TRANSPORT_SIGNATURE:
        raise ContractValidationError("transport signature vector changed")


def _check_edge_fixed_vectors(
    edge_batch_path: Path,
    edge_batch: dict[str, Any],
    edge_receipt: dict[str, Any],
) -> None:
    body_hash = hashlib.sha256(edge_batch_path.read_bytes()).hexdigest()
    if body_hash != EXPECTED_EDGE_BODY_SHA256:
        raise ContractValidationError(
            "raw edge example body changed; update the edge transport vector"
        )
    signing_lines = [
        "MINE-EDGE-TELEMETRY-HTTP-HMAC-SHA256-V1",
        "POST",
        "/v1/edge-telemetry-batches",
        "mine-edge-M001",
        "2026-07-28T10:15:03Z",
        "AAECAwQFBgcICQoLDA0ODw",
        "edge-telemetry-batch-v1",
        body_hash,
    ]
    transport_signature = hmac.new(
        b"example-edge-transport-secret-not-for-production",
        "\n".join(signing_lines).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if transport_signature != EXPECTED_EDGE_TRANSPORT_SIGNATURE:
        raise ContractValidationError("edge transport signature vector changed")
    client_id = edge_batch.get("client_id")
    batch_id = edge_batch.get("batch_id")
    if (
        not isinstance(client_id, str)
        or not isinstance(batch_id, str)
        or len(client_id) > 88
        or re.fullmatch(
            re.escape(client_id) + r"--batch_[0-9a-f]{32}",
            batch_id,
        )
        is None
    ):
        raise ContractValidationError(
            "edge example batch_id is not scoped to its exact client_id"
        )
    if (
        edge_receipt.get("batch_id") != batch_id
        or edge_receipt.get("client_id") != client_id
        or edge_receipt.get("mine_id") != edge_batch.get("mine_id")
        or edge_receipt.get("body_sha256") != body_hash
    ):
        raise ContractValidationError(
            "edge receipt example is not bound to the batch example"
        )
    observations = edge_batch.get("observations")
    if not isinstance(observations, list):
        raise ContractValidationError("edge example observations must be a list")
    if (
        edge_receipt.get("accepted_observations") != len(observations)
        or edge_receipt.get("rejected_observations") != 0
    ):
        raise ContractValidationError(
            "edge receipt counts do not match the accepted example batch"
        )
    required_extension_metrics = {
        "production.belt_instantaneous_t_h",
        "personnel.area_count",
        "detonator.used_count",
        "source.heartbeat_age_seconds",
        "source.consecutive_failures",
        "source.missing_state",
    }
    example_metrics = {
        item.get("metric_code") for item in observations if isinstance(item, dict)
    }
    if not required_extension_metrics.issubset(example_metrics):
        raise ContractValidationError(
            "edge example no longer exercises all V1 telemetry extensions"
        )
    for index, observation in enumerate(observations):
        if not isinstance(observation, dict):
            raise ContractValidationError(f"edge observation {index} must be an object")
        observed_at = _aware_datetime(
            observation.get("observed_at"),
            f"observations[{index}].observed_at",
        )
        received_at = _aware_datetime(
            observation.get("received_at"),
            f"observations[{index}].received_at",
        )
        if received_at < observed_at:
            raise ContractValidationError(
                f"observations[{index}].received_at predates observed_at"
            )
        interval = observation.get("interval")
        if interval is not None:
            if not isinstance(interval, dict):
                raise ContractValidationError(
                    f"observations[{index}].interval must be an object"
                )
            start = _aware_datetime(
                interval.get("start"),
                f"observations[{index}].interval.start",
            )
            end = _aware_datetime(
                interval.get("end"),
                f"observations[{index}].interval.end",
            )
            if end <= start or end > received_at:
                raise ContractValidationError(
                    f"observations[{index}] has an invalid interval window"
                )
            timezone_name = interval.get("timezone")
            if isinstance(timezone_name, str) and not re.fullmatch(
                r"[+-](?:[01][0-9]|2[0-3]):[0-5][0-9]",
                timezone_name,
            ):
                try:
                    ZoneInfo(timezone_name)
                except (ZoneInfoNotFoundError, ValueError, TypeError) as exc:
                    raise ContractValidationError(
                        f"observations[{index}] has an unknown timezone"
                    ) from exc
        if str(observation.get("metric_code", "")).startswith(
            "source."
        ) and observation.get("location_code") != observation.get("source_id"):
            raise ContractValidationError(
                f"observations[{index}] source health location is ambiguous"
            )


def _check_connector_fixed_vectors() -> None:
    for filename, (
        path,
        timestamp,
        request_id,
        expected_body_sha256,
        expected_signature,
    ) in EXPECTED_CONNECTOR_VECTORS.items():
        body = (CONTRACT_ROOT / "examples" / filename).read_bytes()
        body_sha256 = hashlib.sha256(body).hexdigest()
        if body_sha256 != expected_body_sha256:
            raise ContractValidationError(
                f"{filename}: connector raw-body vector changed; "
                "update its fixed HMAC vector"
            )
        material = "\n".join(
            (
                "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1",
                "POST",
                path,
                timestamp,
                request_id,
                body_sha256,
            )
        ).encode("utf-8")
        signature = hmac.new(
            CONNECTOR_EXAMPLE_SECRET,
            material,
            hashlib.sha256,
        ).hexdigest()
        if signature != expected_signature:
            raise ContractValidationError(
                f"{filename}: connector transport signature vector changed"
            )


def _v2_signature_material(message: dict[str, Any], payload_hash: str) -> bytes:
    signature = message["signature_envelope"]
    predecessor = message.get("predecessor") or {}
    lines = [
        "MINEGUARD-FIVE-QUANTITY-EXCHANGE-HMAC-SHA256-V2",
        message["contract_version"],
        message["message_type"],
        message["message_id"],
        message["correlation_id"],
        message.get("causation_id") or "",
        message["idempotency_key"],
        str(message["revision"]),
        predecessor.get("message_id", ""),
        predecessor.get("payload_sha256", ""),
        message["created_at"],
        message["sender"]["system_id"],
        message["sender"]["party_id"],
        message["sender"]["role"],
        message["recipient"]["system_id"],
        message["recipient"]["party_id"],
        message["recipient"]["role"],
        message["mine_id"],
        signature["algorithm"],
        signature["canonicalization"],
        signature["key_id"],
        signature["signed_at"],
        signature["nonce"],
        payload_hash,
    ]
    return "\n".join(lines).encode("utf-8")


def _check_v2_fixed_vectors(messages: dict[str, dict[str, Any]]) -> None:
    for filename, (
        expected_payload_hash,
        expected_signature,
    ) in EXPECTED_V2_VECTORS.items():
        message = messages[filename]
        payload_hash = hashlib.sha256(
            _jcs_example(message["payload"]).encode("utf-8")
        ).hexdigest()
        if payload_hash != expected_payload_hash:
            raise ContractValidationError(
                f"{filename}: V2 payload vector changed; expected "
                f"{expected_payload_hash}, got {payload_hash}"
            )
        envelope = message["signature_envelope"]
        if envelope["payload_sha256"] != payload_hash:
            raise ContractValidationError(
                f"{filename}: declared V2 payload_sha256 is incorrect"
            )
        calculated_signature = hmac.new(
            V2_EXAMPLE_SECRET,
            _v2_signature_material(message, payload_hash),
            hashlib.sha256,
        ).hexdigest()
        if calculated_signature != expected_signature:
            raise ContractValidationError(f"{filename}: V2 signature vector changed")
        if envelope["signature"] != calculated_signature:
            raise ContractValidationError(
                f"{filename}: declared V2 signature is incorrect"
            )


def _parse_date(value: Any, field: str):
    if not isinstance(value, str):
        raise ContractValidationError(f"{field} must be an ISO date")
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ContractValidationError(f"{field} must be an ISO date") from exc


def _check_v2_submission_semantics(submission: dict[str, Any]) -> None:
    payload = submission["payload"]
    if submission["mine_id"] != payload["mine"]["mine_id"]:
        raise ContractValidationError(
            "V2 submission envelope and payload mine_id differ"
        )
    if submission["correlation_id"] != submission["message_id"]:
        raise ContractValidationError(
            "initial V2 submission correlation_id must equal message_id"
        )
    if submission["causation_id"] is not None:
        raise ContractValidationError("initial V2 submission causation_id must be null")

    period_start = _parse_date(payload["period_start"], "period_start")
    period_end = _parse_date(payload["period_end"], "period_end")
    if period_end < period_start:
        raise ContractValidationError("V2 reporting period ends before it starts")
    days = payload["days"]
    day_values = [_parse_date(day["date"], "days[].date") for day in days]
    if len(day_values) != len(set(day_values)):
        raise ContractValidationError("V2 submission contains duplicate days")
    if day_values != sorted(day_values):
        raise ContractValidationError("V2 submission days must be chronological")
    if any(day < period_start or day > period_end for day in day_values):
        raise ContractValidationError("V2 day falls outside reporting period")
    if any(day.strftime("%Y-%m") != payload["reporting_month"] for day in day_values):
        raise ContractValidationError("V2 day does not match reporting_month")

    sources = payload["sources"]
    source_ids = [source["source_id"] for source in sources]
    if len(source_ids) != len(set(source_ids)):
        raise ContractValidationError("V2 source_id values must be unique")
    source_id_set = set(source_ids)
    modes = {source["acquisition_mode"] for source in sources}
    if modes != {"direct_collection", "manual_import"}:
        raise ContractValidationError(
            "V2 example must exercise equal direct and manual acquisition modes"
        )

    metric_codes = {
        metric_code
        for group_metrics in V2_FIVE_QUANTITY_GROUPS.values()
        for metric_code in group_metrics
    }
    shift_keys = ("zero_shift", "eight_shift", "four_shift")
    for day_index, day in enumerate(days):
        quantity = day["reported_quantity"]
        measurement_sets = [("daily_total", quantity["daily_total"])]
        for shift_key in shift_keys:
            shift = quantity["shifts"][shift_key]
            start = _aware_datetime(
                shift["start_at"], f"days[{day_index}].{shift_key}.start_at"
            )
            end = _aware_datetime(
                shift["end_at"], f"days[{day_index}].{shift_key}.end_at"
            )
            if end <= start:
                raise ContractValidationError(
                    f"days[{day_index}].{shift_key} has a non-positive interval"
                )
            measurement_sets.append((shift_key, shift["measurements"]))
        for set_name, measurements in measurement_sets:
            if set(measurements) != metric_codes:
                raise ContractValidationError(
                    f"days[{day_index}].{set_name} does not contain exact V2 metrics"
                )
            for metric_code, measurement in measurements.items():
                if measurement["metric_code"] != metric_code:
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} code mismatch"
                    )
                if not set(measurement["source_refs"]).issubset(source_id_set):
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} has unknown source"
                    )
                flags = set(measurement["quality_flags"])
                missing_flags = {"missing", "unavailable", "not_applicable"}
                if measurement["value"] is None and not flags & missing_flags:
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} null lacks flag"
                    )
                if measurement["value"] is not None and flags & missing_flags:
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} conflicts with flag"
                    )
                if (
                    metric_code
                    in {
                        "detonators_count",
                        "mine_entry_persons",
                    }
                    and measurement["value"] is not None
                ):
                    if isinstance(measurement["value"], bool) or not isinstance(
                        measurement["value"], int
                    ):
                        raise ContractValidationError(
                            f"{metric_code} must be an integer when present"
                        )


def _check_v2_metric_catalog(common_schema: dict[str, Any]) -> None:
    groups = common_schema.get("x-five-quantity-groups")
    if groups != V2_FIVE_QUANTITY_GROUPS:
        raise ContractValidationError(
            "V2 schema must define the exact five business quantity groups"
        )
    blasting_metrics = groups["blasting_materials"]
    if blasting_metrics != ["detonators_count", "explosives_kg"]:
        raise ContractValidationError(
            "V2 blasting-material quantity must retain detonator count and "
            "explosive mass as separate atomic measurements"
        )
    atomic_metrics = [
        metric_code
        for group_metrics in groups.values()
        for metric_code in group_metrics
    ]
    definitions = common_schema.get("$defs", {})
    metric_enum = definitions.get("metricCode", {}).get("enum", [])
    if len(metric_enum) != len(atomic_metrics) or set(metric_enum) != set(
        atomic_metrics
    ):
        raise ContractValidationError(
            "V2 metricCode enum must exactly match the five-group catalog"
        )
    measurement_set = definitions.get("measurementSet", {})
    required_metrics = measurement_set.get("required", [])
    if len(required_metrics) != len(atomic_metrics) or set(required_metrics) != set(
        atomic_metrics
    ):
        raise ContractValidationError(
            "V2 measurementSet must require every catalog atomic metric"
        )
    properties = measurement_set.get("properties", {})
    if set(properties) != set(atomic_metrics):
        raise ContractValidationError(
            "V2 measurementSet must not add an ungoverned metric or a "
            "unitless blasting-material total"
        )
    entry_constraints = properties["mine_entry_persons"]["allOf"][1]["properties"]
    if (
        entry_constraints.get("metric_code", {}).get("const") != "mine_entry_persons"
        or entry_constraints.get("unit", {}).get("const") != "person"
        or entry_constraints.get("aggregation", {}).get("const") != "sum"
        or entry_constraints.get("value", {}).get("type") != ["integer", "null"]
    ):
        raise ContractValidationError(
            "mine_entry_persons must be integer|null, person and sum"
        )


def _check_v2_workflow_semantics(messages: dict[str, dict[str, Any]]) -> None:
    submission = messages["five-quantity-submission-v2.json"]
    intake = messages["intake-receipt-v2.json"]
    report = messages["analysis-report-v2.json"]
    ack = messages["risk-delivery-ack-v2.json"]
    response = messages["enterprise-risk-response-v2.json"]
    receipt = messages["response-receipt-v2.json"]
    workflow = [submission, intake, report, ack, response, receipt]

    _check_v2_submission_semantics(submission)
    mine_ids = {message["mine_id"] for message in workflow}
    correlations = {message["correlation_id"] for message in workflow}
    if len(mine_ids) != 1 or len(correlations) != 1:
        raise ContractValidationError(
            "V2 example workflow must remain bound to one mine and correlation"
        )
    agent_systems = {
        participant["system_id"]
        for message in workflow
        for participant in (message["sender"], message["recipient"])
        if participant["role"] == "enterprise_agent"
    }
    if len(agent_systems) != 1:
        raise ContractValidationError(
            "V2 workflow must use exactly one enterprise agent for the mine"
        )

    submission_hash = submission["signature_envelope"]["payload_sha256"]
    if (
        intake["causation_id"] != submission["message_id"]
        or intake["payload"]["submission_message_id"] != submission["message_id"]
        or intake["payload"]["received_payload_sha256"] != submission_hash
    ):
        raise ContractValidationError("V2 intake receipt is not bound to submission")
    if (
        report["causation_id"] != submission["message_id"]
        or report["payload"]["submission_message_id"] != submission["message_id"]
    ):
        raise ContractValidationError("V2 analysis report is not bound to submission")
    report_payload = report["payload"]
    if report["mine_id"] != report_payload["mine"]["mine_id"]:
        raise ContractValidationError("V2 analysis report mine binding differs")
    required_modules = {
        "l1_reconciliation",
        "minimal_conflict_set",
        "robust_temporal_baseline",
        "change_point",
    }
    if not required_modules.issubset(report_payload["algorithm"]["modules"]):
        raise ContractValidationError(
            "V2 analysis example must exercise solver and retained temporal modules"
        )
    if (
        ack["causation_id"] != report["message_id"]
        or ack["payload"]["analysis_report_message_id"] != report["message_id"]
        or ack["payload"]["report_id"] != report_payload["report_id"]
        or ack["payload"]["delivery_cursor"] != report_payload["delivery_cursor"]
    ):
        raise ContractValidationError("V2 delivery acknowledgement is misbound")
    if (
        response["causation_id"] != report["message_id"]
        or response["payload"]["analysis_report_message_id"] != report["message_id"]
        or response["payload"]["report_id"] != report_payload["report_id"]
    ):
        raise ContractValidationError("V2 enterprise response is misbound")
    finding_ids = {item["finding_id"] for item in report_payload["findings"]}
    response_finding_ids = {
        item["finding_id"] for item in response["payload"]["finding_responses"]
    }
    if not response_finding_ids.issubset(finding_ids):
        raise ContractValidationError("V2 response references an unknown finding")
    evidence_ids = {item["evidence_id"] for item in response["payload"]["attachments"]}
    referenced_evidence = {
        evidence_id
        for item in response["payload"]["finding_responses"]
        for evidence_id in item["evidence_refs"]
    }
    if not referenced_evidence.issubset(evidence_ids):
        raise ContractValidationError("V2 response references unknown evidence")
    if (
        receipt["causation_id"] != response["message_id"]
        or receipt["payload"]["enterprise_response_message_id"]
        != response["message_id"]
        or receipt["payload"]["response_id"] != response["payload"]["response_id"]
        or receipt["payload"]["report_id"] != report_payload["report_id"]
        or receipt["payload"]["risk_status"] != "not_cleared_by_receipt"
    ):
        raise ContractValidationError("V2 response receipt semantics are invalid")

    forbidden_provenance_keys = {
        "trust_level",
        "trust_score",
        "reliability_weight",
        "acquisition_confidence",
    }
    for filename, message in messages.items():
        for node in _walk(message):
            if forbidden_provenance_keys & set(node):
                raise ContractValidationError(
                    f"{filename}: acquisition must not carry a trust tier"
                )

    _check_v2_fixed_vectors(messages)


def _v3_signature_material(message: dict[str, Any], payload_hash: str) -> bytes:
    signature = message["signature_envelope"]
    predecessor = message.get("predecessor") or {}
    lines = [
        V3_APPLICATION_SIGNATURE_DOMAIN,
        message["contract_version"],
        message["message_type"],
        message["message_id"],
        message["correlation_id"],
        message.get("causation_id") or "",
        message["idempotency_key"],
        str(message["revision"]),
        predecessor.get("message_id", ""),
        predecessor.get("payload_sha256", ""),
        message["created_at"],
        message["sender"]["system_id"],
        message["sender"]["party_id"],
        message["sender"]["role"],
        message["recipient"]["system_id"],
        message["recipient"]["party_id"],
        message["recipient"]["role"],
        message["mine_id"],
        signature["algorithm"],
        signature["canonicalization"],
        signature["key_id"],
        signature["signed_at"],
        signature["nonce"],
        payload_hash,
    ]
    return "\n".join(lines).encode("utf-8")


def _check_v3_fixed_vectors(messages: dict[str, dict[str, Any]]) -> None:
    for filename, (
        expected_payload_hash,
        expected_signature,
    ) in EXPECTED_V3_VECTORS.items():
        message = messages[filename]
        payload_hash = hashlib.sha256(
            _jcs_example(message["payload"]).encode("utf-8")
        ).hexdigest()
        if payload_hash != expected_payload_hash:
            raise ContractValidationError(
                f"{filename}: V3 payload vector changed; expected "
                f"{expected_payload_hash}, got {payload_hash}"
            )
        envelope = message["signature_envelope"]
        if envelope["algorithm"] != "hmac-sha256-v3":
            raise ContractValidationError(
                f"{filename}: V3 application signature version is incorrect"
            )
        if envelope["payload_sha256"] != payload_hash:
            raise ContractValidationError(
                f"{filename}: declared V3 payload_sha256 is incorrect"
            )
        calculated_signature = hmac.new(
            V3_EXAMPLE_SECRET,
            _v3_signature_material(message, payload_hash),
            hashlib.sha256,
        ).hexdigest()
        if calculated_signature != expected_signature:
            raise ContractValidationError(f"{filename}: V3 signature vector changed")
        if envelope["signature"] != calculated_signature:
            raise ContractValidationError(
                f"{filename}: declared V3 signature is incorrect"
            )
    submission_path = CONTRACT_ROOT / "examples" / "ten-quantity-submission-v3.json"
    body_sha256 = hashlib.sha256(submission_path.read_bytes()).hexdigest()
    if body_sha256 != V3_EXPECTED_BODY_SHA256:
        raise ContractValidationError(
            "ten-quantity-submission-v3.json: V3 raw-body vector changed"
        )
    transport_lines = [
        V3_HTTP_SIGNATURE_DOMAIN,
        "POST",
        "/v3/ten-quantity-submissions",
        "agent-mine-qy-001",
        "2026-08-01T00:05:00Z",
        "VGVuUXVhbnRpdHlIVFRQVmVjdG9yMQ",
        "ten-quantity-submission-v3",
        body_sha256,
    ]
    transport_signature = hmac.new(
        V3_TRANSPORT_EXAMPLE_SECRET,
        "\n".join(transport_lines).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if transport_signature != V3_EXPECTED_TRANSPORT_SIGNATURE:
        raise ContractValidationError("V3 HTTP transport signature vector changed")


def _check_v3_metric_catalog(common_schema: dict[str, Any]) -> None:
    groups = common_schema.get("x-ten-quantity-groups")
    if groups != V3_TEN_QUANTITY_GROUPS:
        raise ContractValidationError(
            "V3 schema must define the exact ten business quantity groups"
        )
    if groups["blasting_materials"] != [
        "detonators_count",
        "explosives_kg",
    ]:
        raise ContractValidationError(
            "V3 blasting materials must retain unlike-unit atomic components"
        )
    atomic_metrics = V3_DAILY_METRICS
    if len(groups) != 10 or len(atomic_metrics) != 11 or len(set(atomic_metrics)) != 11:
        raise ContractValidationError(
            "V3 must contain ten groups and eleven unique atomic metrics"
        )
    definitions = common_schema.get("$defs", {})
    metric_enum = definitions.get("metricCode", {}).get("enum", [])
    if metric_enum != atomic_metrics:
        raise ContractValidationError(
            "V3 metricCode order and values must exactly match the group catalog"
        )
    daily_set = definitions.get("dailyMeasurementSet", {})
    shift_set = definitions.get("shiftMeasurementSet", {})
    daily_required = daily_set.get("required", [])
    daily_properties = daily_set.get("properties", {})
    shift_required = shift_set.get("required", [])
    shift_properties = shift_set.get("properties", {})
    if daily_required != V3_DAILY_METRICS or list(daily_properties) != V3_DAILY_METRICS:
        raise ContractValidationError(
            "V3 dailyMeasurementSet must require exactly all eleven catalog metrics"
        )
    if (
        shift_required != V3_SHIFT_REQUIRED_METRICS
        or list(shift_properties) != V3_DAILY_METRICS
        or set(V3_SHIFT_OPTIONAL_METRICS) & set(shift_required)
    ):
        raise ContractValidationError(
            "V3 shiftMeasurementSet must require the first seven metrics and "
            "allow only the final four as optional"
        )
    if common_schema.get("x-daily-required-metrics") != V3_DAILY_METRICS:
        raise ContractValidationError("V3 daily metric metadata drifted")
    if common_schema.get("x-shift-required-metrics") != V3_SHIFT_REQUIRED_METRICS:
        raise ContractValidationError("V3 shift metric metadata drifted")
    if common_schema.get("x-business-semantics") != V3_BUSINESS_SEMANTICS:
        raise ContractValidationError("V3 frozen business semantics drifted")
    if definitions.get("metricCodeList", {}).get("maxItems") != 11:
        raise ContractValidationError("V3 affected metric lists must allow 11 metrics")
    for metric, definition_name in {
        "production_t": "productionMeasurement",
        "extraction_t": "extractionMeasurement",
        "sales_t": "salesMeasurement",
        "transport_t": "transportMeasurement",
        "wash_feed_t": "washFeedMeasurement",
        "invoiced_quantity_t": "invoicedQuantityMeasurement",
    }.items():
        expected_ref = f"#/$defs/{definition_name}"
        if daily_properties.get(metric) != {"$ref": expected_ref}:
            raise ContractValidationError(f"V3 {metric} definition is not governed")
        constraints = definitions[definition_name]["allOf"][1]["properties"]
        if constraints.get("metric_code", {}).get("const") != metric:
            raise ContractValidationError(f"V3 {metric} metric code drifted")
    tonnage_constraints = definitions["tonnageMeasurement"]["allOf"][1]["properties"]
    if (
        tonnage_constraints.get("unit", {}).get("const") != "t"
        or tonnage_constraints.get("aggregation", {}).get("const") != "sum"
        or tonnage_constraints.get("value", {}).get("minimum") != 0
    ):
        raise ContractValidationError("V3 tonnage metrics must be non-negative t/sum")
    for definition_name in (
        "ventilationMeasurement",
        "electricityMeasurement",
        "detonatorMeasurement",
        "explosivesMeasurement",
        "mineEntryMeasurement",
    ):
        value_constraints = definitions[definition_name]["allOf"][1]["properties"][
            "value"
        ]
        if value_constraints.get("minimum") != 0:
            raise ContractValidationError(
                f"V3 {definition_name} must reject negative values"
            )
    for metric, definition_name in {
        "detonators_count": "detonatorMeasurement",
        "mine_entry_persons": "mineEntryMeasurement",
    }.items():
        constraints = definitions[definition_name]["allOf"][1]["properties"]
        if constraints.get("value", {}).get("type") != ["integer", "null"]:
            raise ContractValidationError(f"V3 {metric} must be integer|null")


def _check_v3_report_schema_semantics(report_schema: dict[str, Any]) -> None:
    definitions = report_schema.get("$defs", {})
    module_enum = set(
        definitions.get("algorithm", {})
        .get("properties", {})
        .get("modules", {})
        .get("items", {})
        .get("enum", [])
    )
    expected_modules = V3_RUNTIME_BASE_MODULES | V3_RUNTIME_CONDITIONAL_MODULES
    if module_enum != expected_modules:
        raise ContractValidationError(
            "V3 analysis module enum must exactly match runtime output capability"
        )
    category_enum = set(
        definitions.get("finding", {})
        .get("properties", {})
        .get("category", {})
        .get("enum", [])
    )
    if category_enum != V3_RUNTIME_FINDING_CATEGORIES:
        raise ContractValidationError(
            "V3 finding categories must exactly match runtime wire projections"
        )
    method_enum = set(
        definitions.get("evidence", {})
        .get("properties", {})
        .get("method", {})
        .get("enum", [])
    )
    if method_enum != V3_RUNTIME_EVIDENCE_METHODS:
        raise ContractValidationError(
            "V3 evidence methods must exactly match runtime wire projections"
        )


def _check_v3_openapi_semantics(openapi: dict[str, Any]) -> None:
    if openapi.get("x-http-signing") != {
        "domain": V3_HTTP_SIGNATURE_DOMAIN,
        "signature_version": "hmac-sha256-v3",
    }:
        raise ContractValidationError("V3 OpenAPI HTTP signing metadata drifted")
    expected_application_domains = {
        "ten-quantity-submission-v3": V3_APPLICATION_SIGNATURE_DOMAIN,
        "analysis-report-v3": V3_APPLICATION_SIGNATURE_DOMAIN,
        "intake-receipt-v2": V2_APPLICATION_SIGNATURE_DOMAIN,
        "risk-delivery-ack-v2": V2_APPLICATION_SIGNATURE_DOMAIN,
        "enterprise-risk-response-v2": V2_APPLICATION_SIGNATURE_DOMAIN,
        "response-receipt-v2": V2_APPLICATION_SIGNATURE_DOMAIN,
    }
    if openapi.get("x-application-signing-domains") != expected_application_domains:
        raise ContractValidationError(
            "V3 OpenAPI application signing-domain dispatch drifted"
        )

    expected_parameters = {
        "ContractVersionSubmissionV3": "ten-quantity-submission-v3",
        "ContractVersionExchangeV3": "ten-quantity-exchange-v3",
        "ContractVersionDeliveryAckV2": "risk-delivery-ack-v2",
        "ContractVersionRiskResponseV2": "enterprise-risk-response-v2",
    }
    parameters = openapi.get("components", {}).get("parameters", {})
    for parameter_name, contract_version in expected_parameters.items():
        parameter = parameters.get(parameter_name, {})
        if parameter.get("name") != "X-Exchange-Contract-Version" or parameter.get(
            "schema"
        ) != {"const": contract_version}:
            raise ContractValidationError(
                f"V3 OpenAPI {parameter_name} must freeze {contract_version}"
            )

    operations = {
        ("/v3/ten-quantity-submissions", "post"): (
            "ContractVersionSubmissionV3",
            V3_APPLICATION_SIGNATURE_DOMAIN,
            V2_APPLICATION_SIGNATURE_DOMAIN,
        ),
        ("/v3/ten-quantity-submissions/{message_id}/receipt", "get"): (
            "ContractVersionExchangeV3",
            None,
            V2_APPLICATION_SIGNATURE_DOMAIN,
        ),
        ("/v3/analysis-reports/next", "get"): (
            "ContractVersionExchangeV3",
            None,
            V3_APPLICATION_SIGNATURE_DOMAIN,
        ),
        ("/v3/analysis-reports/{report_id}", "get"): (
            "ContractVersionExchangeV3",
            None,
            V3_APPLICATION_SIGNATURE_DOMAIN,
        ),
        ("/v3/analysis-reports/{report_id}/delivery-ack", "post"): (
            "ContractVersionDeliveryAckV2",
            V2_APPLICATION_SIGNATURE_DOMAIN,
            None,
        ),
        ("/v3/analysis-reports/{report_id}/responses", "post"): (
            "ContractVersionRiskResponseV2",
            V2_APPLICATION_SIGNATURE_DOMAIN,
            V2_APPLICATION_SIGNATURE_DOMAIN,
        ),
        ("/v3/risk-responses/{response_id}/receipt", "get"): (
            "ContractVersionExchangeV3",
            None,
            V2_APPLICATION_SIGNATURE_DOMAIN,
        ),
    }
    paths = openapi.get("paths", {})
    for (path, method), (
        parameter_name,
        request_domain,
        response_domain,
    ) in operations.items():
        operation = paths.get(path, {}).get(method, {})
        parameter_refs = {
            parameter.get("$ref")
            for parameter in operation.get("parameters", [])
            if isinstance(parameter, dict)
        }
        expected_ref = f"#/components/parameters/{parameter_name}"
        if expected_ref not in parameter_refs:
            raise ContractValidationError(
                f"V3 OpenAPI {method.upper()} {path} has a loose contract version"
            )
        if operation.get("x-request-application-signing-domain") != request_domain:
            raise ContractValidationError(
                f"V3 OpenAPI {method.upper()} {path} request signing domain drifted"
            )
        if operation.get("x-response-application-signing-domain") != response_domain:
            raise ContractValidationError(
                f"V3 OpenAPI {method.upper()} {path} response signing domain drifted"
            )


def _check_v3_submission_semantics(submission: dict[str, Any]) -> None:
    payload = submission["payload"]
    if submission["mine_id"] != payload["mine"]["mine_id"]:
        raise ContractValidationError(
            "V3 submission envelope and payload mine_id differ"
        )
    if submission["correlation_id"] != submission["message_id"]:
        raise ContractValidationError(
            "initial V3 submission correlation_id must equal message_id"
        )
    if submission["causation_id"] is not None or submission["predecessor"] is not None:
        raise ContractValidationError(
            "initial V3 submission causation_id and predecessor must be null"
        )
    if submission["revision"] != 1:
        raise ContractValidationError("V3 example submission must be revision 1")
    created_at = _aware_datetime(submission["created_at"], "created_at")
    signed_at = _aware_datetime(
        submission["signature_envelope"]["signed_at"], "signed_at"
    )
    closed_at = _aware_datetime(payload["closed_at"], "closed_at")
    confirmed_at = _aware_datetime(
        payload["human_confirmation"]["confirmed_at"], "confirmed_at"
    )
    if not closed_at <= confirmed_at <= created_at <= signed_at:
        raise ContractValidationError(
            "V3 closing, confirmation, creation and signing times are misordered"
        )

    period_start = _parse_date(payload["period_start"], "period_start")
    period_end = _parse_date(payload["period_end"], "period_end")
    if period_end < period_start:
        raise ContractValidationError("V3 reporting period ends before it starts")
    days = payload["days"]
    day_values = [_parse_date(day["date"], "days[].date") for day in days]
    expected_days = [
        period_start + timedelta(days=offset)
        for offset in range((period_end - period_start).days + 1)
    ]
    if day_values != expected_days:
        raise ContractValidationError(
            "V3 days must chronologically and contiguously cover the period"
        )
    if any(day.strftime("%Y-%m") != payload["reporting_month"] for day in day_values):
        raise ContractValidationError("V3 day does not match reporting_month")

    sources = payload["sources"]
    source_ids = [source["source_id"] for source in sources]
    if len(source_ids) != len(set(source_ids)):
        raise ContractValidationError("V3 source_id values must be unique")
    source_id_set = set(source_ids)
    if {source["acquisition_mode"] for source in sources} != {
        "direct_collection",
        "manual_import",
    }:
        raise ContractValidationError(
            "V3 example must exercise equal direct and manual acquisition modes"
        )
    if any(
        _aware_datetime(source["captured_at"], "source.captured_at") > confirmed_at
        for source in sources
    ):
        raise ContractValidationError("V3 confirmation predates a source capture")

    metric_codes = set(V3_DAILY_METRICS)
    units = {
        "ventilation_m3_min": "m3/min",
        "electricity_kwh": "kWh",
        "detonators_count": "count",
        "explosives_kg": "kg",
        "mine_entry_persons": "person",
        "production_t": "t",
        "extraction_t": "t",
        "sales_t": "t",
        "transport_t": "t",
        "wash_feed_t": "t",
        "invoiced_quantity_t": "t",
    }
    shift_keys = ("zero_shift", "eight_shift", "four_shift")
    missing_flags = {"missing", "unavailable", "not_applicable"}
    for day_index, day in enumerate(days):
        quantity = day["reported_quantity"]
        daily_measurements = quantity["daily_total"]
        if len(daily_measurements) != len(V3_DAILY_METRICS) or set(
            daily_measurements
        ) != set(V3_DAILY_METRICS):
            raise ContractValidationError(
                f"days[{day_index}].daily_total must contain exact V3 metrics"
            )
        measurement_sets = [("daily_total", daily_measurements)]
        for shift_key in shift_keys:
            shift = quantity["shifts"][shift_key]
            start = _aware_datetime(
                shift["start_at"], f"days[{day_index}].{shift_key}.start_at"
            )
            end = _aware_datetime(
                shift["end_at"], f"days[{day_index}].{shift_key}.end_at"
            )
            if end <= start:
                raise ContractValidationError(
                    f"days[{day_index}].{shift_key} has a non-positive interval"
                )
            shift_measurements = shift["measurements"]
            shift_codes = set(shift_measurements)
            if not set(V3_SHIFT_REQUIRED_METRICS) <= shift_codes:
                raise ContractValidationError(
                    f"days[{day_index}].{shift_key} lacks a required V3 metric"
                )
            if not shift_codes <= metric_codes:
                raise ContractValidationError(
                    f"days[{day_index}].{shift_key} contains an unknown V3 metric"
                )
            measurement_sets.append((shift_key, shift_measurements))
        for set_name, measurements in measurement_sets:
            for metric_code, measurement in measurements.items():
                if (
                    measurement["metric_code"] != metric_code
                    or measurement["unit"] != units[metric_code]
                ):
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} code/unit mismatch"
                    )
                if metric_code == "ventilation_m3_min":
                    if measurement["aggregation"] not in {
                        "time_weighted_average",
                        "snapshot",
                    }:
                        raise ContractValidationError(
                            "V3 airflow aggregation is invalid"
                        )
                elif measurement["aggregation"] != "sum":
                    raise ContractValidationError(
                        f"V3 {metric_code} aggregation must be sum"
                    )
                if not set(measurement["source_refs"]) <= source_id_set:
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} has unknown source"
                    )
                value = measurement["value"]
                flags = set(measurement["quality_flags"])
                if value is None and not flags & missing_flags:
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} null lacks flag"
                    )
                if value is None and "reported" in flags:
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} null is reported"
                    )
                if value is not None and flags & missing_flags:
                    raise ContractValidationError(
                        f"days[{day_index}].{set_name}.{metric_code} conflicts with flag"
                    )
                if value is not None and value < 0:
                    raise ContractValidationError(
                        f"V3 {metric_code} cannot be negative"
                    )
                if (
                    metric_code in {"detonators_count", "mine_entry_persons"}
                    and value is not None
                    and (isinstance(value, bool) or not isinstance(value, int))
                ):
                    raise ContractValidationError(
                        f"V3 {metric_code} must be an integer when present"
                    )


def _check_v3_workflow_semantics(messages: dict[str, dict[str, Any]]) -> None:
    submission = messages["ten-quantity-submission-v3.json"]
    report = messages["analysis-report-v3.json"]
    _check_v3_submission_semantics(submission)
    report_payload = report["payload"]
    if (
        report["mine_id"] != submission["mine_id"]
        or report["mine_id"] != report_payload["mine"]["mine_id"]
        or report["correlation_id"] != submission["correlation_id"]
        or report["causation_id"] != submission["message_id"]
        or report_payload["submission_message_id"] != submission["message_id"]
        or report_payload["submission_revision"] != submission["revision"]
        or report_payload["reporting_month"] != submission["payload"]["reporting_month"]
        or report_payload["period_start"] != submission["payload"]["period_start"]
        or report_payload["period_end"] != submission["payload"]["period_end"]
    ):
        raise ContractValidationError("V3 report is not bound to its submission")
    submission_payload_sha256 = hashlib.sha256(
        _jcs_example(submission["payload"]).encode("utf-8")
    ).hexdigest()
    if (
        report_payload["algorithm"]["input_snapshot_sha256"]
        != submission_payload_sha256
    ):
        raise ContractValidationError(
            "V3 report input snapshot is not the submission payload hash"
        )
    algorithm = report_payload["algorithm"]
    if (
        algorithm["engine_id"] != "mineguard-ten-quantity-engine"
        or algorithm["engine_version"] != V3_ENGINE_VERSION
    ):
        raise ContractValidationError("V3 report engine identity or version drifted")
    modules = set(algorithm["modules"])
    allowed_modules = V3_RUNTIME_BASE_MODULES | V3_RUNTIME_CONDITIONAL_MODULES
    if not modules <= allowed_modules:
        raise ContractValidationError(
            "V3 report example contains a module the runtime cannot emit"
        )
    required_modules = V3_RUNTIME_BASE_MODULES | V3_RUNTIME_RELATIONSHIP_MODULES
    if algorithm["peer_snapshot_sha256"] is not None:
        required_modules.add("anonymous_peer_baseline")
    if not required_modules.issubset(modules):
        raise ContractValidationError(
            "V3 report example must exercise solver, soft business relations, "
            "timing and history modules"
        )
    known_metrics = {
        metric for values in V3_TEN_QUANTITY_GROUPS.values() for metric in values
    }
    if any(
        not set(finding["affected_metrics"]) <= known_metrics
        for finding in report_payload["findings"]
    ):
        raise ContractValidationError("V3 report references an unknown metric")
    for finding in report_payload["findings"]:
        if finding["category"] not in V3_RUNTIME_FINDING_CATEGORIES:
            raise ContractValidationError(
                "V3 report uses a finding category the runtime cannot emit"
            )
        for index, evidence in enumerate(finding["evidence"], start=1):
            if evidence["method"] not in V3_RUNTIME_EVIDENCE_METHODS:
                raise ContractValidationError(
                    "V3 report uses an evidence method the runtime cannot emit"
                )
            expected_id = f"EV-{finding['finding_id'][:8]}-{index:03d}"
            if evidence["evidence_id"] != expected_id:
                raise ContractValidationError("V3 evidence ID is not runtime-shaped")
            if evidence["score"] is not None:
                raise ContractValidationError(
                    "V3 runtime does not currently emit an evidence score"
                )
            core = {
                key: value
                for key, value in evidence.items()
                if key not in {"evidence_id", "evidence_sha256"}
            }
            evidence_sha256 = hashlib.sha256(
                _jcs_example(core).encode("utf-8")
            ).hexdigest()
            if evidence["evidence_sha256"] != evidence_sha256:
                raise ContractValidationError("V3 evidence digest is incorrect")
    if report_payload["outcome"] == "normal_candidate":
        if (
            report_payload["findings"]
            or report_payload["response_required"]
            or report_payload["response_due_at"] is not None
        ):
            raise ContractValidationError("V3 normal report has risk response state")
    elif (
        not report_payload["findings"]
        or report_payload["response_required"] is not True
        or report_payload["response_due_at"] is None
    ):
        raise ContractValidationError("V3 non-normal report lacks response state")
    if _aware_datetime(report["created_at"], "report.created_at") > _aware_datetime(
        report["signature_envelope"]["signed_at"], "report.signed_at"
    ):
        raise ContractValidationError("V3 report signature predates report creation")
    forbidden_provenance_keys = {
        "trust_level",
        "trust_score",
        "reliability_weight",
        "acquisition_confidence",
    }
    for filename, message in messages.items():
        for node in _walk(message):
            if forbidden_provenance_keys & set(node):
                raise ContractValidationError(
                    f"{filename}: V3 acquisition must not carry a trust tier"
                )
    _check_v3_fixed_vectors(messages)


def _aware_datetime(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ContractValidationError(f"{field} must be a date-time string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ContractValidationError(f"{field} is not ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractValidationError(f"{field} must include a UTC offset")
    return parsed


def _canonical_model_base_url(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 2048
        or "%" in value
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in value
        )
    ):
        raise ContractValidationError(
            "model credential provider.base_url is not canonical"
        )
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ContractValidationError(
            "model credential provider.base_url is not a valid URL"
        ) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ContractValidationError(
            "model credential provider.base_url must be a plain HTTPS base URL"
        )
    if port is not None and not 1 <= port <= 65_535:
        raise ContractValidationError(
            "model credential provider.base_url has an invalid port"
        )

    hostname = parsed.hostname.lower()
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ContractValidationError(
                "model credential provider.base_url hostname must be ASCII"
            ) from exc
        if any(
            not label
            or len(label) > 63
            or re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                label,
            )
            is None
            for label in hostname.split(".")
        ):
            raise ContractValidationError(
                "model credential provider.base_url hostname is not canonical"
            )
        canonical_host = hostname
    else:
        canonical_host = address.compressed

    path = parsed.path
    if path:
        segments = path[1:].split("/") if path.startswith("/") else []
        if (
            not segments
            or path.endswith("/")
            or "//" in path
            or any(segment in {"", ".", ".."} for segment in segments)
            or re.fullmatch(
                r"/[A-Za-z0-9._~!$&'()*+,;=:@-]+"
                r"(?:/[A-Za-z0-9._~!$&'()*+,;=:@-]+)*",
                path,
            )
            is None
        ):
            raise ContractValidationError(
                "model credential provider.base_url path is not canonical"
            )

    authority_host = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    authority = authority_host if port in {None, 443} else f"{authority_host}:{port}"
    canonical = urlunsplit(("https", authority, path, "", ""))
    if value != canonical:
        raise ContractValidationError(
            "model credential provider.base_url is not canonical"
        )
    return canonical


def _check_model_credential_examples(documents: dict[Path, Any]) -> None:
    example_root = CONTRACT_ROOT / "examples"
    paths = {
        label: example_root / filename
        for label, filename in MODEL_CREDENTIAL_EXAMPLES.items()
    }
    bundle = documents[paths["bundle"]]
    profile = documents[paths["profile"]]
    payload = documents[paths["payload"]]
    trust_store = documents[paths["trust_store"]]
    if not all(
        isinstance(item, dict) for item in (bundle, profile, payload, trust_store)
    ):
        raise ContractValidationError(
            "model credential examples must contain JSON objects"
        )
    protected = bundle.get("protected")
    if not isinstance(protected, dict):
        raise ContractValidationError(
            "model credential examples must contain JSON objects"
        )

    if (
        trust_store.get("format") != "mineguard-model-issuer-trust-store-v1"
        or protected.get("contract_version") != "mineguard-model-credential-bundle-v1"
        or protected.get("bundle_kind") != "enterprise-agent-model-credential"
        or payload.get("kind") != protected.get("bundle_kind")
    ):
        raise ContractValidationError(
            "model credential example kind or contract version drifted"
        )

    profile_to_protected = (
        "credential_id",
        "credential_version",
        "subject",
        "install_before",
        "runtime_not_after",
        "issuer_id",
        "issuer_key_id",
        "issuer_key_epoch",
    )
    for field in profile_to_protected:
        if profile.get(field) != protected.get(field):
            raise ContractValidationError(
                f"model credential profile/protected {field} mismatch"
            )

    payload_to_profile = (
        "credential_id",
        "credential_version",
        "subject",
        "provider",
    )
    for field in payload_to_profile:
        if payload.get(field) != profile.get(field):
            raise ContractValidationError(
                f"model credential payload/profile {field} mismatch"
            )
    if payload.get("bundle_id") != protected.get("bundle_id"):
        raise ContractValidationError(
            "model credential payload/protected bundle_id mismatch"
        )
    uuid_v4 = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
        r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    for field in ("bundle_id", "credential_id"):
        if uuid_v4.fullmatch(str(protected.get(field, ""))) is None:
            raise ContractValidationError(
                f"model credential protected.{field} must be canonical UUIDv4"
            )
    subject = payload.get("subject")
    if not isinstance(subject, dict) or set(subject) != {
        "mine_id",
        "system_id",
        "party_id",
        "pair_id",
    }:
        raise ContractValidationError(
            "model credential subject must bind mine/system/party/pair"
        )
    provisioning_bundle = documents[
        example_root / "enterprise-agent-provisioning-bundle-v1.json"
    ]
    provisioning_payload = documents[
        example_root / "enterprise-agent-provisioning-payload-v1.json"
    ]
    provisioning_protected = provisioning_bundle.get("protected")
    if not isinstance(provisioning_protected, dict) or not isinstance(
        provisioning_protected.get("subject"), dict
    ):
        raise ContractValidationError(
            "enterprise provisioning example lacks its protected subject"
        )
    expected_subject = dict(provisioning_protected["subject"])
    expected_subject["pair_id"] = provisioning_protected.get("pair_id")
    if (
        subject != expected_subject
        or provisioning_payload.get("pair_id") != expected_subject["pair_id"]
    ):
        raise ContractValidationError(
            "model credential example subject is not bound to the verified "
            "enterprise provisioning pair"
        )

    declared_payload_hash = hashlib.sha256(_compact_sorted_json(payload)).hexdigest()
    if protected.get("payload_sha256") != declared_payload_hash:
        raise ContractValidationError(
            "model credential example payload_sha256 is incorrect"
        )
    provider = payload.get("provider")
    if not isinstance(provider, dict):
        raise ContractValidationError(
            "model credential example provider must be an object"
        )
    if set(provider) != {
        "provider_id",
        "protocol",
        "base_url",
        "model",
        "capabilities",
        "timeout_seconds",
        "max_retries",
    }:
        raise ContractValidationError(
            "model credential example provider fields drifted"
        )
    capabilities = provider.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or capabilities != sorted(set(capabilities))
        or not set(capabilities) <= MODEL_CREDENTIAL_CAPABILITIES
    ):
        raise ContractValidationError(
            "model credential example capabilities are invalid"
        )
    if provider.get("base_url") != "https://api.example.invalid/v1":
        raise ContractValidationError(
            "model credential example must use the explicit example HTTPS base URL"
        )
    if provider.get("protocol") != "openai-compatible-chat-completions":
        raise ContractValidationError("model credential example protocol drifted")
    _canonical_model_base_url(provider["base_url"])
    declared_provider_hash = hashlib.sha256(_compact_sorted_json(provider)).hexdigest()
    if protected.get("provider_config_sha256") != declared_provider_hash:
        raise ContractValidationError(
            "model credential example provider_config_sha256 is incorrect"
        )

    utc_time = re.compile(
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
        r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    )
    times: dict[str, datetime] = {}
    for field in ("issued_at", "install_before", "runtime_not_after"):
        value = protected.get(field)
        if not isinstance(value, str) or utc_time.fullmatch(value) is None:
            raise ContractValidationError(
                f"model credential protected.{field} must use canonical UTC Z time"
            )
        times[field] = _aware_datetime(value, f"model credential {field}")
    if not (times["issued_at"] < times["install_before"] < times["runtime_not_after"]):
        raise ContractValidationError(
            "model credential example validity windows are incorrectly ordered"
        )

    if payload.get("api_key") != MODEL_CREDENTIAL_EXAMPLE_API_KEY:
        raise ContractValidationError(
            "model credential payload example must use the documented sentinel key"
        )
    if (
        bundle.get("ciphertext") != MODEL_CREDENTIAL_EXAMPLE_CIPHERTEXT
        or bundle.get("signature") != MODEL_CREDENTIAL_EXAMPLE_SIGNATURE
    ):
        raise ContractValidationError(
            "model credential bundle example must use explicit non-working placeholders"
        )
    for label in ("profile", "bundle"):
        encoded = json.dumps(
            documents[paths[label]],
            ensure_ascii=False,
            sort_keys=True,
        )
        if "api_key" in encoded or MODEL_CREDENTIAL_EXAMPLE_API_KEY in encoded:
            raise ContractValidationError(
                f"model credential {label} example leaked its API key"
            )

    for example_path in example_root.glob("*.json"):
        for node in _walk(documents[example_path]):
            if "api_key" not in node:
                continue
            if (
                example_path != paths["payload"]
                or node is not payload
                or node["api_key"] != MODEL_CREDENTIAL_EXAMPLE_API_KEY
            ):
                raise ContractValidationError(
                    f"{example_path}: unapproved api_key in contract example"
                )

    if set(trust_store) != {"format", "issuers"}:
        raise ContractValidationError("model issuer trust store example fields drifted")
    issuers = trust_store.get("issuers")
    if not isinstance(issuers, list) or not issuers:
        raise ContractValidationError(
            "model issuer trust store example must contain issuers"
        )
    key_ids: list[str] = []
    identities: set[tuple[str, str]] = set()
    issuer_epochs: set[tuple[str, int]] = set()
    fingerprints: set[str] = set()
    for index, issuer in enumerate(issuers):
        if not isinstance(issuer, dict) or set(issuer) != {
            "issuer_id",
            "issuer_key_id",
            "issuer_key_epoch",
            "public_key_pem",
            "public_key_sha256",
        }:
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] fields drifted"
            )
        issuer_id = issuer.get("issuer_id")
        key_id = issuer.get("issuer_key_id")
        key_epoch = issuer.get("issuer_key_epoch")
        fingerprint = issuer.get("public_key_sha256")
        if not all(isinstance(item, str) for item in (issuer_id, key_id, fingerprint)):
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] identity is invalid"
            )
        if type(key_epoch) is not int or not 1 <= key_epoch <= 2_147_483_647:
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] key epoch is invalid"
            )
        identity = (issuer_id, key_id)
        issuer_epoch = (issuer_id, key_epoch)
        if issuer_epoch in issuer_epochs:
            raise ContractValidationError(
                "model issuer trust store example reuses an issuer key epoch"
            )
        if identity in identities or key_id in key_ids or fingerprint in fingerprints:
            raise ContractValidationError(
                "model issuer trust store example contains duplicate anchors"
            )
        pem = issuer.get("public_key_pem")
        if not isinstance(pem, str) or "\r" in pem or "PRIVATE KEY" in pem:
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] PEM is invalid"
            )
        lines = pem.splitlines()
        if (
            len(lines) != 3
            or lines[0] != "-----BEGIN PUBLIC KEY-----"
            or lines[2] != "-----END PUBLIC KEY-----"
            or not pem.endswith("\n")
        ):
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] PEM is not canonical"
            )
        try:
            der = base64.b64decode(lines[1], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] PEM is invalid"
            ) from exc
        ed25519_spki_prefix = bytes.fromhex("302a300506032b6570032100")
        if len(der) != 44 or not der.startswith(ed25519_spki_prefix):
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] is not Ed25519 SPKI"
            )
        actual = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(actual, fingerprint):
            raise ContractValidationError(
                f"model issuer trust store issuer[{index}] fingerprint mismatch"
            )
        identities.add(identity)
        issuer_epochs.add(issuer_epoch)
        key_ids.append(key_id)
        fingerprints.add(fingerprint)
    if key_ids != sorted(key_ids):
        raise ContractValidationError(
            "model issuer trust store example must be sorted by issuer_key_id"
        )
    first = issuers[0]
    if first.get("issuer_id") != profile.get("issuer_id") or first.get(
        "issuer_key_id"
    ) != profile.get("issuer_key_id") or first.get(
        "issuer_key_epoch"
    ) != profile.get("issuer_key_epoch"):
        raise ContractValidationError(
            "model issuer trust store example does not anchor the example profile"
        )


def _optional_jsonschema_validation(documents: dict[Path, Any]) -> str:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry, Resource
    except ImportError:
        return "jsonschema 未安装，已跳过完整 schema 实例校验"

    registry = Registry().with_resources(
        (
            schema["$id"],
            Resource.from_contents(schema),
        )
        for path, schema in documents.items()
        if path.parent == CONTRACT_ROOT / "schemas"
        and isinstance(schema, dict)
        and isinstance(schema.get("$id"), str)
    )

    for example_name, schema_name in EXAMPLES.items():
        example_path = CONTRACT_ROOT / "examples" / example_name
        schema_path = CONTRACT_ROOT / "schemas" / schema_name
        schema = documents[schema_path]
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(
            schema,
            registry=registry,
            format_checker=FormatChecker(),
        )
        errors = sorted(
            validator.iter_errors(documents[example_path]),
            key=lambda item: list(item.absolute_path),
        )
        if errors:
            details = "; ".join(
                f"/{'/'.join(map(str, error.absolute_path))}: {error.message}"
                for error in errors[:20]
            )
            raise ContractValidationError(
                f"{example_path}: schema validation failed: {details}"
            )

    provisioning_schema = documents[
        CONTRACT_ROOT / "schemas" / "provisioning-bundle-v1.schema.json"
    ]
    provisioning_validator = Draft202012Validator(
        provisioning_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    provisioning_example = documents[
        CONTRACT_ROOT / "examples" / "enterprise-agent-provisioning-bundle-v1.json"
    ]

    def clone_provisioning_example() -> dict[str, Any]:
        return json.loads(json.dumps(provisioning_example))

    boundary = clone_provisioning_example()
    boundary["protected"]["profile_version"] = 2_147_483_647
    boundary["protected"]["issued_at"] = "2026-07-27T08:00:00.123456Z"
    boundary["protected"]["expires_at"] = "2026-08-10T00:00:00.1Z"
    boundary["ciphertext"] = "A" * 23
    boundary_errors = list(provisioning_validator.iter_errors(boundary))
    if boundary_errors:
        raise ContractValidationError(
            "provisioning schema rejected its max version, fractional time, "
            "or 17-byte ciphertext boundary"
        )

    invalid_boundaries: list[tuple[str, dict[str, Any]]] = []
    too_large_version = clone_provisioning_example()
    too_large_version["protected"]["profile_version"] = 2_147_483_648
    invalid_boundaries.append(("profile_version above int32", too_large_version))
    excessive_fraction = clone_provisioning_example()
    excessive_fraction["protected"]["issued_at"] = "2026-07-27T08:00:00.1234567Z"
    invalid_boundaries.append(("seven fractional digits", excessive_fraction))
    tag_only_ciphertext = clone_provisioning_example()
    tag_only_ciphertext["ciphertext"] = "A" * 22
    invalid_boundaries.append(("tag-only ciphertext", tag_only_ciphertext))
    for label, invalid in invalid_boundaries:
        if not list(provisioning_validator.iter_errors(invalid)):
            raise ContractValidationError(
                f"provisioning schema accepted invalid boundary: {label}"
            )

    model_bundle_schema = documents[
        CONTRACT_ROOT / "schemas" / "model-credential-bundle-v1.schema.json"
    ]
    model_payload_schema = documents[
        CONTRACT_ROOT / "schemas" / "model-credential-payload-v1.schema.json"
    ]
    model_profile_schema = documents[
        CONTRACT_ROOT / "schemas" / "model-credential-profile-v1.schema.json"
    ]
    model_trust_schema = documents[
        CONTRACT_ROOT / "schemas" / "model-issuer-trust-store-v1.schema.json"
    ]
    model_bundle_validator = Draft202012Validator(
        model_bundle_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    model_payload_validator = Draft202012Validator(
        model_payload_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    model_profile_validator = Draft202012Validator(
        model_profile_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    model_trust_validator = Draft202012Validator(
        model_trust_schema,
        registry=registry,
        format_checker=FormatChecker(),
    )
    model_bundle_example = documents[
        CONTRACT_ROOT / "examples" / "model-credential-bundle-v1.json"
    ]
    model_payload_example = documents[
        CONTRACT_ROOT / "examples" / "model-credential-payload-v1.json"
    ]
    model_profile_example = documents[
        CONTRACT_ROOT / "examples" / "model-credential-profile-v1.json"
    ]
    model_trust_example = documents[
        CONTRACT_ROOT / "examples" / "model-issuer-trust-store-v1.json"
    ]

    model_boundary = json.loads(json.dumps(model_bundle_example))
    model_boundary["protected"]["credential_version"] = 2_147_483_647
    model_boundary["ciphertext"] = "A" * 23
    if list(model_bundle_validator.iter_errors(model_boundary)):
        raise ContractValidationError(
            "model credential schema rejected its max version or "
            "17-byte ciphertext boundary"
        )

    invalid_model_boundaries: list[tuple[str, Any, dict[str, Any]]] = []
    model_too_large_version = json.loads(json.dumps(model_bundle_example))
    model_too_large_version["protected"]["credential_version"] = 2_147_483_648
    invalid_model_boundaries.append(
        (
            "credential_version above int32",
            model_bundle_validator,
            model_too_large_version,
        )
    )
    model_fractional_time = json.loads(json.dumps(model_bundle_example))
    model_fractional_time["protected"]["issued_at"] = "2026-08-11T08:00:00.1Z"
    invalid_model_boundaries.append(
        (
            "fractional issued_at",
            model_bundle_validator,
            model_fractional_time,
        )
    )
    model_tag_only = json.loads(json.dumps(model_bundle_example))
    model_tag_only["ciphertext"] = "A" * 22
    invalid_model_boundaries.append(
        ("tag-only ciphertext", model_bundle_validator, model_tag_only)
    )
    model_short_key = json.loads(json.dumps(model_payload_example))
    model_short_key["api_key"] = "A" * 15
    invalid_model_boundaries.append(
        ("short API key", model_payload_validator, model_short_key)
    )
    model_timeout = json.loads(json.dumps(model_payload_example))
    model_timeout["provider"]["timeout_seconds"] = 121
    invalid_model_boundaries.append(
        ("timeout above maximum", model_payload_validator, model_timeout)
    )
    model_http_base = json.loads(json.dumps(model_profile_example))
    model_http_base["provider"]["base_url"] = "http://api.example.invalid"
    invalid_model_boundaries.append(
        ("non-HTTPS provider URL", model_profile_validator, model_http_base)
    )
    model_query_base = json.loads(json.dumps(model_profile_example))
    model_query_base["provider"]["base_url"] = (
        "https://api.example.invalid/v1?tenant=example"
    )
    invalid_model_boundaries.append(
        ("provider URL query", model_profile_validator, model_query_base)
    )
    model_unknown_capability = json.loads(json.dumps(model_payload_example))
    model_unknown_capability["provider"]["capabilities"] = ["vision"]
    invalid_model_boundaries.append(
        (
            "unknown model capability",
            model_payload_validator,
            model_unknown_capability,
        )
    )
    model_unsorted_capabilities = json.loads(json.dumps(model_payload_example))
    model_unsorted_capabilities["provider"]["capabilities"] = [
        "extraction",
        "chat",
    ]
    invalid_model_boundaries.append(
        (
            "unsorted model capabilities",
            model_payload_validator,
            model_unsorted_capabilities,
        )
    )
    model_non_uuid_credential = json.loads(json.dumps(model_profile_example))
    model_non_uuid_credential["credential_id"] = "mine-provider-main"
    invalid_model_boundaries.append(
        (
            "non-UUID credential_id",
            model_profile_validator,
            model_non_uuid_credential,
        )
    )
    model_missing_pair = json.loads(json.dumps(model_profile_example))
    del model_missing_pair["subject"]["pair_id"]
    invalid_model_boundaries.append(
        ("missing subject pair_id", model_profile_validator, model_missing_pair)
    )
    model_legacy_origin = json.loads(json.dumps(model_profile_example))
    model_legacy_origin["provider"]["api_origin"] = model_legacy_origin["provider"].pop(
        "base_url"
    )
    invalid_model_boundaries.append(
        (
            "legacy provider api_origin",
            model_profile_validator,
            model_legacy_origin,
        )
    )
    model_wrong_trust_format = json.loads(json.dumps(model_trust_example))
    model_wrong_trust_format["format"] = "mineguard-model-issuer-trust-v1"
    invalid_model_boundaries.append(
        (
            "legacy trust store format",
            model_trust_validator,
            model_wrong_trust_format,
        )
    )
    for label, validator, invalid in invalid_model_boundaries:
        if not list(validator.iter_errors(invalid)):
            raise ContractValidationError(
                f"model credential schema accepted invalid boundary: {label}"
            )
    return f"{len(EXAMPLES)} 个示例均通过 Draft 2020-12 schema 校验"


def main() -> int:
    json_paths = sorted(CONTRACT_ROOT.rglob("*.json"))
    if not json_paths:
        raise ContractValidationError("no JSON contract files found")

    documents = {path: _load_json(path) for path in json_paths}
    for path, document in documents.items():
        _check_local_links(path, document)

    ids: dict[str, Path] = {}
    for path in (CONTRACT_ROOT / "schemas").glob("*.json"):
        schema_id = documents[path].get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise ContractValidationError(f"{path}: missing $id")
        if schema_id in ids:
            raise ContractValidationError(
                f"duplicate schema $id in {path} and {ids[schema_id]}"
            )
        ids[schema_id] = path

    for openapi_path in (CONTRACT_ROOT / "openapi").glob("*.json"):
        openapi = documents[openapi_path]
        if openapi.get("openapi") != "3.1.0":
            raise ContractValidationError(
                f"{openapi_path}: OpenAPI document must use version 3.1.0"
            )
    _check_v3_openapi_semantics(
        documents[CONTRACT_ROOT / "openapi" / "ten-quantity-exchange-v3.openapi.json"]
    )

    submission_schema = documents[
        CONTRACT_ROOT / "schemas" / "enterprise-submission-v1.schema.json"
    ]
    observation_properties = submission_schema["$defs"]["governedObservation"][
        "properties"
    ]
    for integer_field in ("sequence_no", "revision"):
        integer_schema = observation_properties[integer_field]
        if (
            integer_schema.get("minimum") != 0
            or integer_schema.get("maximum") != 9_007_199_254_740_991
        ):
            raise ContractValidationError(
                f"{integer_field} must use the cross-language safe integer range"
            )

    submission_path = CONTRACT_ROOT / "examples" / "enterprise-submission-v1.json"
    _check_fixed_vectors(submission_path, documents[submission_path])
    edge_batch_path = CONTRACT_ROOT / "examples" / "edge-telemetry-batch-v1.json"
    _check_edge_fixed_vectors(
        edge_batch_path,
        documents[edge_batch_path],
        documents[CONTRACT_ROOT / "examples" / "edge-telemetry-receipt-v1.json"],
    )
    _check_connector_fixed_vectors()
    v2_messages = {
        filename: documents[CONTRACT_ROOT / "examples" / filename]
        for filename in EXPECTED_V2_VECTORS
    }
    _check_v2_metric_catalog(
        documents[CONTRACT_ROOT / "schemas" / "exchange-common-v2.schema.json"]
    )
    _check_v2_workflow_semantics(v2_messages)
    v3_messages = {
        filename: documents[CONTRACT_ROOT / "examples" / filename]
        for filename in EXPECTED_V3_VECTORS
    }
    _check_v3_metric_catalog(
        documents[CONTRACT_ROOT / "schemas" / "exchange-common-v3.schema.json"]
    )
    _check_v3_report_schema_semantics(
        documents[CONTRACT_ROOT / "schemas" / "analysis-report-v3.schema.json"]
    )
    _check_v3_workflow_semantics(v3_messages)
    _check_model_credential_examples(documents)

    text_suffixes = {".json", ".md", ".py", ".txt", ".yaml", ".yml"}
    all_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in CONTRACT_ROOT.rglob("*")
        if path.is_file()
        and path.suffix.lower() in text_suffixes
        and "__pycache__" not in path.parts
    )
    if re.search(r"\bsk-[A-Za-z0-9_-]{16,}\b", all_text):
        raise ContractValidationError(
            "possible live API credential found in contract artifacts"
        )

    schema_result = _optional_jsonschema_validation(documents)
    print(
        f"OK: {len(json_paths)} 个 JSON 文件可解析；"
        f"{len(ids)} 个 schema ID 唯一；本地引用、V1 三层完整性和 "
        "V2 双向消息、V3 十量提交/报告签名与状态绑定向量及 "
        "企业模型凭据包跨层摘要通过。"
    )
    print(f"OK: {schema_result}。")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
