"""Small, dependency-free protocol for deterministic agent tools.

The harness owns orchestration, permissions and persistence.  A tool receives
only explicit JSON arguments and a read-only context; it never receives an
HTTP session, actor identity or approval token.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

JSON = None | bool | int | float | str | list["JSON"] | dict[str, "JSON"]
JSONSchema = dict[str, Any]
_SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "enum",
        "items",
        "maximum",
        "maxItems",
        "maxLength",
        "maxProperties",
        "minimum",
        "minItems",
        "minLength",
        "minProperties",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "type",
        "uniqueItems",
    }
)


class RepositoryView(Protocol):
    """The intentionally small read surface available to deterministic tools."""

    def get_draft(
        self, draft_id: str, *, include_deleted: bool = False
    ) -> dict[str, Any]: ...

    def list_drafts(
        self,
        *,
        include_deleted: bool = False,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def historical_observations(
        self,
        *,
        mine_id: str,
        metric_code: str,
        exclude_draft_id: str | None = None,
        before_window_start: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]: ...


@dataclass(frozen=True, slots=True)
class ToolContext:
    repository: RepositoryView | None = None
    max_observations: int = 10_000
    max_history_drafts: int = 1_000


@dataclass(frozen=True, slots=True)
class ToolResult:
    """JSON result plus a short operator-facing summary and optional artifacts."""

    data: dict[str, Any]
    summary: str
    artifacts: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "data": self.data,
            "summary": self.summary,
            "artifacts": list(self.artifacts),
        }


ToolExecutor = Callable[[Mapping[str, Any], ToolContext], ToolResult]


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: JSONSchema
    output_schema: JSONSchema
    execute: ToolExecutor
    mutating: bool = False
    requires_approval: bool = False
    timeout_seconds: float | None = 10.0
    category: str = "general"
    evidence_grounding: str = "user_supplied"
    network_access: bool = False
    scenario_only: bool = False
    allowed_profiles: tuple[str, ...] = ("standard", "chat_read_only")

    def public_definition(self) -> dict[str, Any]:
        """Return the model-visible definition without the Python callable."""

        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "mutating": self.mutating,
            "requires_approval": self.requires_approval,
            "timeout_seconds": self.timeout_seconds,
            "category": self.category,
            "evidence_grounding": self.evidence_grounding,
            "network_access": self.network_access,
            "scenario_only": self.scenario_only,
            "allowed_profiles": list(self.allowed_profiles),
        }


class ToolProtocolError(ValueError):
    def __init__(self, message: str, *, code: str, path: str = "$"):
        super().__init__(message)
        self.code = code
        self.path = path

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": str(self)}


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        )
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict) and all(
            isinstance(key, str) for key in value
        )
    return False


def validate_json_schema(
    value: Any, schema: Mapping[str, Any], path: str = "$"
) -> None:
    """Validate the strict JSON-Schema subset used by built-in tools.

    It deliberately fails closed on schema keywords used by this package.
    Keeping this validator local avoids turning the enterprise agent into a
    dependency-heavy JSON Schema service.
    """

    if "oneOf" in schema:
        matches = 0
        for branch in schema["oneOf"]:
            try:
                validate_json_schema(value, branch, path)
            except ToolProtocolError:
                continue
            matches += 1
        if matches != 1:
            raise ToolProtocolError(
                "值必须且只能匹配一个允许的结构",
                code="schema_one_of",
                path=path,
            )
        return

    expected = schema.get("type")
    expected_types = [expected] if isinstance(expected, str) else expected
    if expected_types and not any(
        _type_matches(value, item) for item in expected_types
    ):
        raise ToolProtocolError(
            f"值类型不符合要求：应为 {' 或 '.join(expected_types)}",
            code="schema_type",
            path=path,
        )

    if "enum" in schema and value not in schema["enum"]:
        raise ToolProtocolError(
            "值不在允许范围内", code="schema_enum", path=path
        )

    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise ToolProtocolError(
                "字符串过短", code="schema_min_length", path=path
            )
        if len(value) > int(schema.get("maxLength", 2**31 - 1)):
            raise ToolProtocolError(
                "字符串过长", code="schema_max_length", path=path
            )
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(str(pattern), value) is None:
            raise ToolProtocolError(
                "字符串格式不符合要求", code="schema_pattern", path=path
            )

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(float(value)):
            raise ToolProtocolError(
                "数值必须有限", code="non_finite_number", path=path
            )
        if "minimum" in schema and value < schema["minimum"]:
            raise ToolProtocolError(
                "数值小于允许下限", code="schema_minimum", path=path
            )
        if "maximum" in schema and value > schema["maximum"]:
            raise ToolProtocolError(
                "数值超过允许上限", code="schema_maximum", path=path
            )

    if isinstance(value, list):
        minimum = int(schema.get("minItems", 0))
        maximum = int(schema.get("maxItems", 2**31 - 1))
        if len(value) < minimum:
            raise ToolProtocolError(
                "数组项目不足", code="schema_min_items", path=path
            )
        if len(value) > maximum:
            raise ToolProtocolError(
                "数组项目过多", code="schema_max_items", path=path
            )
        if schema.get("uniqueItems"):
            from enterprise_agent.util import canonical_json

            encoded = [canonical_json(item) for item in value]
            if len(encoded) != len(set(encoded)):
                raise ToolProtocolError(
                    "数组项目不能重复", code="schema_unique_items", path=path
                )
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for index, item in enumerate(value):
                validate_json_schema(item, item_schema, f"{path}[{index}]")

    if isinstance(value, dict):
        if len(value) < int(schema.get("minProperties", 0)):
            raise ToolProtocolError(
                "对象字段不足",
                code="schema_min_properties",
                path=path,
            )
        if len(value) > int(schema.get("maxProperties", 2**31 - 1)):
            raise ToolProtocolError(
                "对象字段过多",
                code="schema_max_properties",
                path=path,
            )
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                raise ToolProtocolError(
                    f"缺少必填字段 {key}",
                    code="schema_required",
                    path=f"{path}.{key}",
                )
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, child in value.items():
            child_schema = properties.get(key)
            if child_schema is None:
                if additional is False:
                    raise ToolProtocolError(
                        f"不支持字段 {key}",
                        code="schema_additional_property",
                        path=f"{path}.{key}",
                    )
                if isinstance(additional, Mapping):
                    validate_json_schema(child, additional, f"{path}.{key}")
            else:
                validate_json_schema(child, child_schema, f"{path}.{key}")


def validate_schema_definition(
    schema: Mapping[str, Any],
    path: str = "$",
) -> None:
    """Fail closed when a tool declares schema syntax we do not enforce."""

    unknown = set(schema) - _SUPPORTED_SCHEMA_KEYWORDS
    if unknown:
        raise ToolProtocolError(
            "工具结构使用了未实现的 JSON Schema 关键字："
            + ", ".join(sorted(unknown)),
            code="unsupported_schema_keyword",
            path=path,
        )
    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, Mapping):
            raise ToolProtocolError(
                "properties 必须是对象",
                code="invalid_schema_definition",
                path=f"{path}.properties",
            )
        for name, child in properties.items():
            if not isinstance(name, str) or not isinstance(child, Mapping):
                raise ToolProtocolError(
                    "properties 子项结构无效",
                    code="invalid_schema_definition",
                    path=f"{path}.properties",
                )
            validate_schema_definition(child, f"{path}.properties.{name}")
    items = schema.get("items")
    if items is not None:
        if not isinstance(items, Mapping):
            raise ToolProtocolError(
                "items 必须是对象",
                code="invalid_schema_definition",
                path=f"{path}.items",
            )
        validate_schema_definition(items, f"{path}.items")
    branches = schema.get("oneOf")
    if branches is not None:
        if set(schema) != {"oneOf"} or not isinstance(branches, list) or not branches:
            raise ToolProtocolError(
                "oneOf 必须单独使用且至少包含一个分支",
                code="invalid_schema_definition",
                path=f"{path}.oneOf",
            )
        for index, branch in enumerate(branches):
            if not isinstance(branch, Mapping):
                raise ToolProtocolError(
                    "oneOf 分支必须是对象",
                    code="invalid_schema_definition",
                    path=f"{path}.oneOf[{index}]",
                )
            validate_schema_definition(branch, f"{path}.oneOf[{index}]")
    additional = schema.get("additionalProperties")
    if isinstance(additional, Mapping):
        validate_schema_definition(additional, f"{path}.additionalProperties")


class ToolRegistry:
    """Validated, immutable-by-convention registry used by a harness."""

    _FORBIDDEN_NAME_TOKENS = ("confirm", "submit", "确认", "提交")
    _GROUNDING = frozenset(
        {"repository_grounded", "user_supplied", "external_public"}
    )
    _PROFILES = frozenset({"standard", "chat_read_only"})

    def __init__(
        self,
        specs: Sequence[ToolSpec] = (),
        *,
        context: ToolContext | None = None,
    ):
        self._context = context or ToolContext()
        self._specs: dict[str, ToolSpec] = {}
        for spec in specs:
            self.register(spec)

    def register(self, spec: ToolSpec) -> None:
        lowered_name = spec.name.lower()
        if any(token in lowered_name for token in self._FORBIDDEN_NAME_TOKENS):
            raise ToolProtocolError(
                "确认和提交不能注册为模型工具",
                code="forbidden_tool",
                path="$.name",
            )
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", spec.name):
            raise ToolProtocolError(
                "工具名格式不合法", code="invalid_tool_name", path="$.name"
            )
        if spec.name in self._specs:
            raise ToolProtocolError(
                "工具名重复", code="duplicate_tool", path="$.name"
            )
        if spec.mutating and not spec.requires_approval:
            raise ToolProtocolError(
                "写工具必须要求人工批准",
                code="unsafe_tool_spec",
                path="$.requires_approval",
            )
        validate_schema_definition(spec.input_schema, "$.input_schema")
        validate_schema_definition(spec.output_schema, "$.output_schema")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", spec.category):
            raise ToolProtocolError(
                "工具类别格式不合法",
                code="invalid_tool_category",
                path="$.category",
            )
        if spec.evidence_grounding not in self._GROUNDING:
            raise ToolProtocolError(
                "工具证据来源类型不受支持",
                code="invalid_evidence_grounding",
                path="$.evidence_grounding",
            )
        if (
            not spec.allowed_profiles
            or len(spec.allowed_profiles) != len(set(spec.allowed_profiles))
            or any(
                profile not in self._PROFILES
                for profile in spec.allowed_profiles
            )
        ):
            raise ToolProtocolError(
                "工具运行配置不受支持",
                code="invalid_tool_profiles",
                path="$.allowed_profiles",
            )
        self._specs[spec.name] = spec

    def list_specs(self) -> tuple[ToolSpec, ...]:
        return tuple(self._specs[name] for name in sorted(self._specs))

    def get(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError as error:
            raise ToolProtocolError(
                "未知工具", code="tool_not_found", path="$.name"
            ) from error

    def execute(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        spec = self.get(name)
        if spec.mutating or spec.requires_approval:
            raise ToolProtocolError(
                "本注册表只执行无需批准的只读工具",
                code="approval_required",
                path="$.name",
            )
        if not isinstance(arguments, Mapping):
            raise ToolProtocolError(
                "工具参数必须是对象", code="invalid_arguments", path="$"
            )
        material = dict(arguments)
        validate_json_schema(material, spec.input_schema)
        result = spec.execute(material, self._context)
        if not isinstance(result, ToolResult):
            raise ToolProtocolError(
                "工具返回类型错误", code="invalid_tool_result", path="$"
            )
        validate_json_schema(result.data, spec.output_schema)
        validate_json_schema(
            result.as_dict(),
            {
                "type": "object",
                "required": ["data", "summary", "artifacts"],
                "additionalProperties": False,
                "properties": {
                    "data": spec.output_schema,
                    "summary": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 1000,
                    },
                    "artifacts": {
                        "type": "array",
                        "maxItems": 32,
                        "items": {"type": "object"},
                    },
                },
            },
        )
        return result


def strict_object(
    properties: Mapping[str, JSONSchema],
    *,
    required: Sequence[str] = (),
) -> JSONSchema:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": dict(properties),
        "required": list(required),
    }
