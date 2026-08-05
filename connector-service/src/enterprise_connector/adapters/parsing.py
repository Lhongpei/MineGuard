from __future__ import annotations

import csv
import io
import json
from typing import Any

from ..errors import SourceError


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceError(f"JSON 对象包含重复字段：{key}")
        result[key] = value
    return result


def _lookup(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise SourceError(f"records_path 不存在：{path}")
    return current


def parse_records(
    content: bytes,
    *,
    data_format: str,
    records_path: str | None,
    max_records: int,
) -> tuple[dict[str, Any], ...]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SourceError("来源数据必须使用 UTF-8 编码") from exc
    if data_format == "json":
        try:
            parsed: Any = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
        except SourceError:
            raise
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise SourceError(f"JSON 解析失败：{exc}") from exc
        if records_path:
            parsed = _lookup(parsed, records_path)
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            raise SourceError("JSON 数据必须是对象数组或单个对象")
        if len(parsed) > max_records:
            raise SourceError("来源记录数超过 max_records")
        if not all(isinstance(item, dict) for item in parsed):
            raise SourceError("JSON 记录必须全部是对象")
        return tuple(parsed)
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if reader.fieldnames is None:
            raise SourceError("CSV 缺少表头")
        if any(not isinstance(name, str) or not name.strip() for name in reader.fieldnames):
            raise SourceError("CSV 表头不得为空")
        if len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise SourceError("CSV 表头包含重复字段")
        records: list[dict[str, Any]] = []
        for row in reader:
            if None in row:
                raise SourceError("CSV 记录列数超过表头列数")
            records.append(dict(row))
            if len(records) > max_records:
                raise SourceError("来源记录数超过 max_records")
        return tuple(records)
    except csv.Error as exc:
        raise SourceError(f"CSV 解析失败：{exc}") from exc
