"""Rule-based JSON/CSV import with field-level provenance."""

from __future__ import annotations

import csv
import io
import json
import math
from typing import Any

from .errors import ImportContentError
from .models import blank_observation, provenance_record
from .util import deep_copy_json, sha256_text

_MAX_IMPORT_BYTES = 2 * 1024 * 1024
_TOP_FIELDS = {
    "enterprise_id",
    "enterprise_name",
    "unified_social_credit_code",
    "mine_id",
    "mine_name",
    "window_start",
    "window_end",
    "profile_id",
    "profile_version",
    "notes",
}
_CONTEXT_FIELDS = {
    "regime_code",
    "shift_code",
    "season_code",
    "maintenance",
    "approved_event_codes",
    "tags",
}
_OBS_FIELDS = set(blank_observation())
_ALIASES = {
    "企业编号": "enterprise_id",
    "企业id": "enterprise_id",
    "企业名称": "enterprise_name",
    "统一社会信用代码": "unified_social_credit_code",
    "矿井编号": "mine_id",
    "矿井id": "mine_id",
    "矿井名称": "mine_name",
    "统计开始": "window_start",
    "开始时间": "window_start",
    "统计结束": "window_end",
    "结束时间": "window_end",
    "配置编号": "profile_id",
    "配置版本": "profile_version",
    "工况": "regime_code",
    "班次": "shift_code",
    "季节": "season_code",
    "是否检修": "maintenance",
    "来源编号": "source_id",
    "数据源编号": "source_id",
    "观测编号": "observation_id",
    "指标编码": "metric_code",
    "数值": "value",
    "观测值": "value",
    "单位": "unit",
    "观测时间": "observed_at",
    "接收时间": "received_at",
    "区间开始": "interval_start",
    "区间结束": "interval_end",
    "序号": "sequence_no",
    "修订号": "revision",
    "载荷摘要": "payload_sha256",
    "载荷sha256": "payload_sha256",
    "来源签名": "signature",
    "签名": "signature",
}


def _check_content(content: str) -> None:
    if not isinstance(content, str) or not content.strip():
        raise ImportContentError("导入内容不能为空")
    if len(content.encode("utf-8")) > _MAX_IMPORT_BYTES:
        raise ImportContentError("单次导入内容不能超过 2 MiB")


def _key(raw: Any) -> str:
    if not isinstance(raw, str):
        return ""
    clean = raw.strip()
    return _ALIASES.get(clean, clean.lower())


def _json_scope_key(raw: Any, *, top_level: bool = False) -> str:
    key = _key(raw)
    if top_level:
        if key == "工况信息":
            return "operational_context"
        if key == "观测":
            return "observations"
    return key


def _reject_semantic_duplicates(
    value: dict[str, Any],
    *,
    scope: str,
    top_level: bool = False,
) -> None:
    seen: dict[str, str] = {}
    for original_key in value:
        key = _json_scope_key(original_key, top_level=top_level)
        previous = seen.get(key)
        if previous is not None:
            raise ImportContentError(
                f"JSON {scope}包含含义重复字段：{previous} 与 {original_key}"
            )
        seen[key] = original_key


def _source_name(value: str | None, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str):
        raise ImportContentError("source_name 必须是文件名字符串")
    clean = value.strip()
    if (
        not clean
        or len(clean) > 255
        or clean in {".", ".."}
        or any(character in clean for character in "/\\")
        or any(ord(character) < 32 or ord(character) == 127 for character in clean)
    ):
        raise ImportContentError(
            "source_name 必须是 1-255 字符且不含路径分隔符或控制字符的文件名"
        )
    return clean


def _bool(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "y", "1", "是", "检修"}:
            return True
        if lowered in {"false", "no", "n", "0", "否", "非检修"}:
            return False
    return value


def _number(value: Any, *, integer: bool = False) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) if integer and float(value).is_integer() else value
    if isinstance(value, str):
        clean = value.strip().replace(",", "")
        try:
            parsed = float(clean)
        except ValueError:
            return value
        if not math.isfinite(parsed):
            return value
        if integer and parsed.is_integer():
            return int(parsed)
        return parsed
    return value


def _list_value(value: Any) -> Any:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [
            part.strip()
            for part in value.replace("；", ";")
            .replace("，", ",")
            .split(";" if ";" in value or "；" in value else ",")
            if part.strip()
        ]
    return value


def _normalise_observation(raw: dict[str, Any]) -> dict[str, Any]:
    item = blank_observation()
    for original_key, value in raw.items():
        field = _key(original_key)
        if field not in _OBS_FIELDS:
            continue
        if field == "value":
            value = _number(value)
        elif field in {"sequence_no", "revision"}:
            value = _number(value, integer=True)
        elif field == "reset_before":
            value = _bool(value)
        elif field in {"interval_start", "interval_end"} and value == "":
            value = None
        elif field in {"payload_sha256", "signature"} and isinstance(value, str):
            value = value.strip()
        item[field] = value
    return item


def _provenance(
    *,
    content: str,
    source_kind: str,
    source_name: str,
    locator: str,
    confidence: float,
    method: str,
) -> dict[str, Any]:
    return provenance_record(
        source_kind=source_kind,
        source_name=source_name,
        locator=locator,
        content_sha256=sha256_text(content),
        confidence=confidence,
        extraction_method=method,
    )


def import_json_text(
    content: str, *, source_name: str = "pasted.json"
) -> dict[str, Any]:
    _check_content(content)
    source_name = _source_name(source_name, "pasted.json")
    parse_content = content[1:] if content.startswith("\ufeff") else content

    def object_without_duplicates(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ImportContentError(f"JSON 包含重复字段：{key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ImportContentError(f"JSON 不允许非有限数：{value}")

    try:
        raw = json.loads(
            parse_content,
            object_pairs_hook=object_without_duplicates,
            parse_constant=reject_constant,
        )
    except ImportContentError:
        raise
    except json.JSONDecodeError as error:
        raise ImportContentError(
            f"JSON 格式错误：第 {error.lineno} 行第 {error.colno} 列"
        ) from error
    if not isinstance(raw, dict):
        raise ImportContentError("JSON 顶层必须是对象")
    _reject_semantic_duplicates(raw, scope="顶层", top_level=True)

    patch: dict[str, Any] = {}
    provenance: dict[str, list[dict[str, Any]]] = {}
    for original_key, value in raw.items():
        field = _key(original_key)
        if field in _TOP_FIELDS:
            patch[field] = value
            provenance[f"/{field}"] = [
                _provenance(
                    content=content,
                    source_kind="json",
                    source_name=source_name,
                    locator=f"$.{original_key}",
                    confidence=1.0,
                    method="deterministic_json_key",
                )
            ]
    context_container = (
        "operational_context"
        if "operational_context" in raw
        else "工况信息"
        if "工况信息" in raw
        else None
    )
    if context_container is not None:
        raw_context = raw[context_container]
        if not isinstance(raw_context, dict):
            raise ImportContentError(f"{context_container} 必须是对象")
        _reject_semantic_duplicates(raw_context, scope=context_container)
        context: dict[str, Any] = {}
        for original_key, value in raw_context.items():
            field = _key(original_key)
            if field not in _CONTEXT_FIELDS:
                continue
            if field == "maintenance":
                value = _bool(value)
            elif field in {"approved_event_codes", "tags"}:
                value = _list_value(value)
            context[field] = value
            provenance[f"/operational_context/{field}"] = [
                _provenance(
                    content=content,
                    source_kind="json",
                    source_name=source_name,
                    locator=f"$.{context_container}.{original_key}",
                    confidence=1.0,
                    method="deterministic_json_key",
                )
            ]
        if context:
            patch["operational_context"] = context

    observations_container = (
        "observations"
        if "observations" in raw
        else "观测"
        if "观测" in raw
        else None
    )
    if observations_container is not None:
        raw_observations = raw[observations_container]
        if not isinstance(raw_observations, list) or any(
            not isinstance(item, dict) for item in raw_observations
        ):
            raise ImportContentError(f"{observations_container} 必须是对象数组")
        for index, raw_item in enumerate(raw_observations):
            _reject_semantic_duplicates(
                raw_item,
                scope=f"{observations_container}[{index}]",
            )
        observations = [_normalise_observation(item) for item in raw_observations]
        patch["observations"] = observations
        for index, raw_item in enumerate(raw_observations):
            original_by_field = {
                _key(original_key): original_key for original_key in raw_item
            }
            for field in _OBS_FIELDS:
                if (
                    field in {"payload_sha256", "signature"}
                    and field not in original_by_field
                ):
                    continue
                original_key = original_by_field.get(field, field)
                pointer = f"/observations/{index}/{field}"
                provenance[pointer] = [
                    _provenance(
                        content=content,
                        source_kind="json",
                        source_name=source_name,
                        locator=(
                            f"$.{observations_container}[{index}].{original_key}"
                        ),
                        confidence=1.0,
                        method="deterministic_json_key",
                    )
                ]
    if not patch:
        raise ImportContentError("未识别到可导入字段")
    return {
        "patch": patch,
        "field_provenance": provenance,
        "unmapped_fields": sorted(
            str(key)
            for key in raw
            if _key(key) not in _TOP_FIELDS
            and key not in {"operational_context", "工况信息", "observations", "观测"}
        ),
    }


def import_csv_text(content: str, *, source_name: str = "pasted.csv") -> dict[str, Any]:
    _check_content(content)
    source_name = _source_name(source_name, "pasted.csv")
    parse_content = content[1:] if content.startswith("\ufeff") else content
    try:
        reader = csv.DictReader(io.StringIO(parse_content, newline=""))
        if not reader.fieldnames:
            raise ImportContentError("CSV 缺少表头")
        if (
            len(reader.fieldnames) > 256
            or any(
                not isinstance(header, str)
                or not header.strip()
                or len(header) > 256
                for header in reader.fieldnames
            )
        ):
            raise ImportContentError("CSV 最多 256 列，且表头必须为非空短文本")
        normalised_headers = [_key(header) for header in reader.fieldnames]
        if len(normalised_headers) != len(set(normalised_headers)):
            raise ImportContentError("CSV 包含重复或含义冲突的表头")
        rows = list(reader)
    except csv.Error as error:
        raise ImportContentError(f"CSV 格式错误：{error}") from error
    if not rows:
        raise ImportContentError("CSV 没有数据行")
    if len(rows) > 10_000:
        raise ImportContentError("CSV 最多包含 10000 行")

    patch: dict[str, Any] = {}
    provenance: dict[str, list[dict[str, Any]]] = {}
    observations: list[dict[str, Any]] = []
    mapped_headers = {_key(header): header for header in reader.fieldnames}
    for field in _TOP_FIELDS:
        header = mapped_headers.get(field)
        if header is None:
            continue
        value = next(
            (
                str(row.get(header) or "").strip()
                for row in rows
                if str(row.get(header) or "").strip()
            ),
            "",
        )
        if value:
            patch[field] = value
            provenance[f"/{field}"] = [
                _provenance(
                    content=content,
                    source_kind="csv",
                    source_name=source_name,
                    locator=f"column:{header}",
                    confidence=1.0,
                    method="deterministic_csv_header",
                )
            ]
    context: dict[str, Any] = {}
    for field in _CONTEXT_FIELDS:
        header = mapped_headers.get(field)
        if header is None:
            continue
        value = next(
            (
                str(row.get(header) or "").strip()
                for row in rows
                if str(row.get(header) or "").strip()
            ),
            "",
        )
        if value == "":
            continue
        if field == "maintenance":
            value = _bool(value)
        elif field in {"approved_event_codes", "tags"}:
            value = _list_value(value)
        context[field] = value
        provenance[f"/operational_context/{field}"] = [
            _provenance(
                content=content,
                source_kind="csv",
                source_name=source_name,
                locator=f"column:{header}",
                confidence=1.0,
                method="deterministic_csv_header",
            )
        ]
    if context:
        patch["operational_context"] = context

    observation_headers = {
        field: mapped_headers[field] for field in _OBS_FIELDS if field in mapped_headers
    }
    if observation_headers:
        missing_credentials = {
            "payload_sha256",
            "signature",
        } - set(observation_headers)
        if missing_credentials:
            raise ImportContentError(
                "CSV 观测必须同时包含来源网关给出的 payload_sha256 和 signature；"
                "填报智能体不会代签"
            )
        for index, row in enumerate(rows):
            source = {
                field: row.get(header, "")
                for field, header in observation_headers.items()
            }
            observation = _normalise_observation(source)
            if not observation["payload_sha256"] or not observation["signature"]:
                raise ImportContentError(
                    f"CSV 第 {index + 2} 行缺少来源网关摘要或签名；"
                    "禁止把人工填充值伪装成来源观测"
                )
            observations.append(observation)
            for field in _OBS_FIELDS:
                header = observation_headers.get(field, field)
                provenance[f"/observations/{index}/{field}"] = [
                    _provenance(
                        content=content,
                        source_kind="csv",
                        source_name=source_name,
                        locator=f"row:{index + 2},column:{header}",
                        confidence=1.0,
                        method="deterministic_csv_header",
                    )
                ]
        patch["observations"] = observations
    if not patch:
        raise ImportContentError("未识别到可导入的 CSV 表头")
    known_headers = {
        header
        for header in reader.fieldnames
        if _key(header) in _TOP_FIELDS | _CONTEXT_FIELDS | _OBS_FIELDS
    }
    return {
        "patch": patch,
        "field_provenance": provenance,
        "unmapped_fields": [
            header for header in reader.fieldnames if header not in known_headers
        ],
    }


def import_text(
    format_name: str,
    content: str,
    *,
    source_name: str | None = None,
) -> dict[str, Any]:
    lowered = format_name.lower().strip() if isinstance(format_name, str) else ""
    if lowered == "json":
        return import_json_text(
            content,
            source_name=_source_name(source_name, "pasted.json"),
        )
    if lowered == "csv":
        return import_csv_text(
            content,
            source_name=_source_name(source_name, "pasted.csv"),
        )
    raise ImportContentError("format 仅支持 json 或 csv")


def merge_import(document: dict[str, Any], imported: dict[str, Any]) -> dict[str, Any]:
    result = deep_copy_json(document)
    patch = imported["patch"]
    for key, value in patch.items():
        if key == "operational_context":
            result.setdefault(key, {}).update(deep_copy_json(value))
        else:
            result[key] = deep_copy_json(value)
    provenance = result.setdefault("field_provenance", {})
    if "observations" in patch:
        # Observation arrays are replaced as one source batch.  Do not retain
        # credential provenance from rows that are no longer present or from
        # a new unsigned import.
        for pointer in list(provenance):
            if pointer.startswith("/observations/"):
                provenance.pop(pointer)
    provenance.update(
        deep_copy_json(imported["field_provenance"])
    )
    return result
