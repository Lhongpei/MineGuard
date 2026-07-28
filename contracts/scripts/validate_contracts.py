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
from pathlib import Path
import re
import sys
from typing import Any


CONTRACT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = {
    "enterprise-submission-v1.json": "enterprise-submission-v1.schema.json",
    "submission-receipt-v1.json": "submission-receipt-v1.schema.json",
    "error-v1.json": "error-v1.schema.json",
    "capabilities-v1.json": "capabilities-v1.schema.json",
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
            json.dumps(key, ensure_ascii=False)
            + ":"
            + _jcs_example(value[key])
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
    material = (
        b"MINEGUARD-GOVERNED-OBSERVATION-V1\x00"
        + _compact_sorted_json(envelope)
    )
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


def _optional_jsonschema_validation(documents: dict[Path, Any]) -> str:
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError:
        return "jsonschema 未安装，已跳过完整 schema 实例校验"

    for example_name, schema_name in EXAMPLES.items():
        example_path = CONTRACT_ROOT / "examples" / example_name
        schema_path = CONTRACT_ROOT / "schemas" / schema_name
        schema = documents[schema_path]
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(
            schema,
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
    return "4 个示例均通过 Draft 2020-12 schema 校验"


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

    openapi_path = (
        CONTRACT_ROOT / "openapi" / "enterprise-submission-v1.openapi.json"
    )
    openapi = documents[openapi_path]
    if openapi.get("openapi") != "3.1.0":
        raise ContractValidationError("OpenAPI document must use version 3.1.0")

    submission_schema = documents[
        CONTRACT_ROOT / "schemas" / "enterprise-submission-v1.schema.json"
    ]
    observation_properties = submission_schema["$defs"][
        "governedObservation"
    ]["properties"]
    for integer_field in ("sequence_no", "revision"):
        integer_schema = observation_properties[integer_field]
        if integer_schema.get("minimum") != 0 or integer_schema.get(
            "maximum"
        ) != 9_007_199_254_740_991:
            raise ContractValidationError(
                f"{integer_field} must use the cross-language safe integer range"
            )

    submission_path = (
        CONTRACT_ROOT / "examples" / "enterprise-submission-v1.json"
    )
    _check_fixed_vectors(submission_path, documents[submission_path])

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
        f"{len(ids)} 个 schema ID 唯一；本地引用、三层摘要/签名向量通过。"
    )
    print(f"OK: {schema_result}。")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
