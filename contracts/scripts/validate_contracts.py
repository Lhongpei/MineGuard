#!/usr/bin/env python3
"""Validate the standalone enterprise-submission contract artifacts.

The baseline checks use only Python's standard library.  If ``jsonschema`` is
installed, examples are additionally validated against Draft 2020-12 schemas.
This script intentionally imports no enterprise-agent or regulatory-platform
code.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from datetime import datetime
from pathlib import Path
import re
import sys
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


CONTRACT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = {
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
CONNECTOR_EXAMPLE_SECRET = (
    b"example-enterprise-connector-secret-not-for-production"
)
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
        "V2 双向消息签名/状态绑定向量通过。"
    )
    print(f"OK: {schema_result}。")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
