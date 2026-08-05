from __future__ import annotations

import math
import os
import re
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import ConfigurationError
from .models import (
    FieldMapping,
    PipelineConfig,
    ServiceConfig,
    Shift,
    SourceConfig,
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_ALLOWED_MAPPING_TYPES = {"preserve", "integer", "number"}
_V2_METRICS = {
    "ventilation_m3_min",
    "electricity_kwh",
    "detonators_count",
    "explosives_kg",
    "mine_entry_persons",
    "production_t",
}
_V2_SCOPES = {"daily_total", "zero_shift", "eight_shift", "four_shift", "current_shift"}

_ROOT_KEYS = {"service", "pipelines"}
_SERVICE_KEYS = {
    "state_db",
    "poll_interval_seconds",
    "agent_url",
    "client_id",
    "secret_env",
    "agent_timeout_seconds",
    "agent_max_response_bytes",
    "agent_allowed_hosts",
    "agent_allowed_ports",
    "agent_allow_private_network",
    "agent_allow_insecure_http",
    "agent_ca_bundle",
    "retry_base_seconds",
    "retry_max_seconds",
    "lease_seconds",
}
_PIPELINE_KEYS = {
    "id",
    "enterprise_id",
    "report_type",
    "period_type",
    "timezone",
    "timestamp_field",
    "scope_field",
    "scope_values",
    "reporting_lag_days",
    "workflow_name",
    "required_sources",
    "sources",
    "mapping",
    "shifts",
}
_SOURCE_COMMON_KEYS = {
    "id",
    "adapter",
    "source_name",
    "source_system",
    "truth_statement",
    "format",
    "records_path",
    "timeout_seconds",
    "stable_seconds",
    "max_bytes",
    "max_records",
    "revision_seed",
    "max_staleness_seconds",
    "max_files_per_poll",
    "max_total_bytes",
    "max_total_records",
    "timestamp_field",
    "period_type",
    "scope_field",
    "scope_values",
    "mapping",
    "shifts",
}
_SOURCE_ADAPTER_KEYS = {
    "file-drop": {"path", "glob"},
    "http-poll": {
        "url",
        "allowed_hosts",
        "allowed_ports",
        "allow_private_network",
        "allow_insecure_http",
        "headers",
        "ca_bundle",
    },
    "sqlite-query": {"database", "query"},
}
_MAPPING_KEYS = {"source", "type", "factor", "offset", "required", "reduce"}
_SHIFT_KEYS = {"name", "start"}


def _table(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{context} 必须是 TOML table")
    return value


def _reject_unknown_keys(
    item: dict[str, Any], allowed: set[str], context: str
) -> None:
    unknown = sorted(set(item) - allowed)
    if unknown:
        raise ConfigurationError(
            f"{context} 包含未知配置项：{', '.join(unknown)}"
        )


def _string(value: Any, context: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise ConfigurationError(f"{context} 必须是非空字符串")
    return value.strip() if nonempty else value


def _identifier(value: Any, context: str) -> str:
    text = _string(value, context)
    if not _ID_RE.fullmatch(text):
        raise ConfigurationError(f"{context} 只能包含字母、数字、点、冒号、下划线或连字符")
    return text


def _positive_number(value: Any, context: str, *, maximum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigurationError(f"{context} 必须是正数")
    result = float(value)
    if not math.isfinite(result):
        raise ConfigurationError(f"{context} 必须是有限正数")
    if maximum is not None and result > maximum:
        raise ConfigurationError(f"{context} 不能大于 {maximum:g}")
    return result


def _positive_int(value: Any, context: str, *, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigurationError(f"{context} 必须是正整数")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{context} 不能大于 {maximum}")
    return value


def _nonnegative_int(value: Any, context: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ConfigurationError(f"{context} 必须是 0-{maximum} 的整数")
    return value


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{context} 必须是 true 或 false")
    return value


def _resolve_path(base: Path, value: Any, context: str) -> Path:
    raw = Path(_string(value, context)).expanduser()
    return (base / raw).resolve() if not raw.is_absolute() else raw.resolve()


def _ca_bundle(base: Path, value: Any, context: str) -> Path | None:
    if value is None:
        return None
    path = _resolve_path(base, value, context)
    if not path.is_file() or not os.access(path, os.R_OK):
        raise ConfigurationError(f"{context} 必须是可读的普通 CA bundle 文件")
    return path


def _string_list(value: Any, context: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ConfigurationError(f"{context} 必须是字符串数组")
    result = tuple(_string(item, f"{context}[]") for item in value)
    if len(set(result)) != len(result):
        raise ConfigurationError(f"{context} 不能包含重复值")
    return result


def _parse_shift(value: Any, context: str) -> Shift:
    item = _table(value, context)
    _reject_unknown_keys(item, _SHIFT_KEYS, context)
    name = _identifier(item.get("name"), f"{context}.name")
    start = _string(item.get("start"), f"{context}.start")
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", start):
        raise ConfigurationError(f"{context}.start 必须使用 HH:MM 24 小时格式")
    hour, minute = (int(part) for part in start.split(":"))
    return Shift(name=name, start_minutes=hour * 60 + minute)


def _parse_mapping(target: str, value: Any, context: str) -> FieldMapping:
    target_parts = target.split(".", 1)
    metric = target_parts[-1]
    if metric not in _V2_METRICS or (len(target_parts) == 2 and target_parts[0] not in _V2_SCOPES):
        raise ConfigurationError(f"{context} 目标必须是六个五量原子字段，或 scope.metric 形式")
    if isinstance(value, str):
        return FieldMapping(target=target, source=_string(value, context), value_type="number")
    item = _table(value, context)
    _reject_unknown_keys(item, _MAPPING_KEYS, context)
    value_type = item.get("type", "preserve")
    if value_type not in _ALLOWED_MAPPING_TYPES:
        raise ConfigurationError(
            f"{context}.type 必须是 {', '.join(sorted(_ALLOWED_MAPPING_TYPES))} 之一"
        )
    factor = item.get("factor", 1.0)
    offset = item.get("offset", 0.0)
    if (
        isinstance(factor, bool)
        or not isinstance(factor, (int, float))
        or not math.isfinite(float(factor))
    ):
        raise ConfigurationError(f"{context}.factor 必须是数字")
    if (
        isinstance(offset, bool)
        or not isinstance(offset, (int, float))
        or not math.isfinite(float(offset))
    ):
        raise ConfigurationError(f"{context}.offset 必须是数字")
    reduce = item.get("reduce", "single")
    if reduce not in {"single", "sum", "average", "latest"}:
        raise ConfigurationError(f"{context}.reduce 必须是 single、sum、average 或 latest")
    return FieldMapping(
        target=target,
        source=_string(item.get("source"), f"{context}.source"),
        value_type=value_type,
        factor=float(factor),
        offset=float(offset),
        required=_boolean(item.get("required", False), f"{context}.required"),
        reduce=reduce,
    )


def _parse_mappings(value: Any, context: str) -> tuple[FieldMapping, ...]:
    table = _table(value, context)
    if not table:
        raise ConfigurationError(f"{context} 不能为空")
    mappings = tuple(
        _parse_mapping(
            _identifier(target, f"{context} key"),
            raw,
            f"{context}.{target}",
        )
        for target, raw in table.items()
    )
    if len({mapping.target for mapping in mappings}) != len(mappings):
        raise ConfigurationError(f"{context} 目标不能重复")
    targets_by_metric: dict[str, list[str]] = {}
    for mapping in mappings:
        targets_by_metric.setdefault(mapping.target.split(".")[-1], []).append(mapping.target)
    for metric, targets in targets_by_metric.items():
        prefixes = [target.split(".", 1)[0] if "." in target else None for target in targets]
        if len(targets) > 1 and (None in prefixes or "current_shift" in prefixes):
            raise ConfigurationError(
                f"{context} 的 {metric} 存在运行期重叠目标；"
                "裸 metric/current_shift 不能和同指标其他 scope 并用"
            )
    return mappings


def _parse_scope_values(value: Any, context: str) -> dict[str, str]:
    table = _table(value, context)
    result = {
        _string(key, f"{context} key"): _string(raw, f"{context}.{key}")
        for key, raw in table.items()
    }
    invalid = sorted(set(result.values()) - (_V2_SCOPES - {"current_shift"}))
    if invalid:
        raise ConfigurationError(
            f"{context} 包含非法 V2 scope：{', '.join(invalid)}"
        )
    return result


def _parse_shifts(value: Any, context: str) -> tuple[Shift, ...]:
    if not isinstance(value, list):
        raise ConfigurationError(f"{context} 必须是数组")
    shifts = tuple(
        sorted(
            (_parse_shift(raw, f"{context}[{index}]") for index, raw in enumerate(value)),
            key=lambda shift: shift.start_minutes,
        )
    )
    if len({shift.name for shift in shifts}) != len(shifts) or len(
        {shift.start_minutes for shift in shifts}
    ) != len(shifts):
        raise ConfigurationError(f"{context} 的 name 和 start 必须唯一")
    return shifts


def _parse_source(value: Any, context: str, base: Path) -> SourceConfig:
    item = _table(value, context)
    source_id = _identifier(item.get("id"), f"{context}.id")
    adapter = item.get("adapter")
    if adapter not in {"file-drop", "http-poll", "sqlite-query"}:
        raise ConfigurationError(f"{context}.adapter 必须是 file-drop、http-poll 或 sqlite-query")
    _reject_unknown_keys(
        item,
        _SOURCE_COMMON_KEYS | _SOURCE_ADAPTER_KEYS[adapter],
        context,
    )
    data_format = item.get("format", "json")
    if data_format not in {"json", "csv"}:
        raise ConfigurationError(f"{context}.format 必须是 json 或 csv")
    timeout = _positive_number(
        item.get("timeout_seconds", 10), f"{context}.timeout_seconds", maximum=60
    )
    max_bytes = _positive_int(
        item.get("max_bytes", 5_000_000), f"{context}.max_bytes", maximum=50_000_000
    )
    max_records = _positive_int(
        item.get("max_records", 10_000), f"{context}.max_records", maximum=100_000
    )
    source_name = _string(item.get("source_name"), f"{context}.source_name")
    if (
        len(source_name) > 255
        or source_name in {".", ".."}
        or any(character in source_name for character in "/\\")
        or any(ord(character) < 32 or ord(character) == 127 for character in source_name)
    ):
        raise ConfigurationError(f"{context}.source_name 必须是无路径分隔符的 1-255 字符文本")
    common: dict[str, Any] = {
        "id": source_id,
        "adapter": adapter,
        "source_name": source_name,
        "source_system": _identifier(item.get("source_system"), f"{context}.source_system"),
        "truth_statement": _string(item.get("truth_statement"), f"{context}.truth_statement"),
        "format": data_format,
        "records_path": item.get("records_path"),
        "timeout_seconds": timeout,
        "stable_seconds": _positive_number(
            item.get("stable_seconds", 2), f"{context}.stable_seconds", maximum=3600
        ),
        "max_bytes": max_bytes,
        "max_records": max_records,
        "revision_seed": _nonnegative_int(
            item.get("revision_seed", 0), f"{context}.revision_seed", maximum=2_147_483_646
        ),
        "max_staleness_seconds": _positive_int(
            item.get("max_staleness_seconds", 3600),
            f"{context}.max_staleness_seconds",
            maximum=2_592_000,
        ),
        "max_files_per_poll": _positive_int(
            item.get("max_files_per_poll", 100),
            f"{context}.max_files_per_poll",
            maximum=10_000,
        ),
        "max_total_bytes": _positive_int(
            item.get("max_total_bytes", 20_000_000),
            f"{context}.max_total_bytes",
            maximum=500_000_000,
        ),
        "max_total_records": _positive_int(
            item.get("max_total_records", 50_000),
            f"{context}.max_total_records",
            maximum=1_000_000,
        ),
        "timestamp_field": (
            _string(item.get("timestamp_field"), f"{context}.timestamp_field")
            if "timestamp_field" in item
            else None
        ),
        "period_type": item.get("period_type") if "period_type" in item else None,
        "scope_field": (
            _string(item.get("scope_field"), f"{context}.scope_field")
            if "scope_field" in item
            else None
        ),
        "scope_values": (
            _parse_scope_values(item.get("scope_values"), f"{context}.scope_values")
            if "scope_values" in item
            else None
        ),
        "mappings": (
            _parse_mappings(item.get("mapping"), f"{context}.mapping")
            if "mapping" in item
            else None
        ),
        "shifts": (
            _parse_shifts(item.get("shifts"), f"{context}.shifts")
            if "shifts" in item
            else None
        ),
    }
    if common["max_staleness_seconds"] < 300:
        raise ConfigurationError(
            f"{context}.max_staleness_seconds 不能小于 300"
        )
    if common["period_type"] not in {None, "daily", "shift"}:
        raise ConfigurationError(f"{context}.period_type 必须是 daily 或 shift")
    if common["records_path"] is not None:
        common["records_path"] = _string(common["records_path"], f"{context}.records_path")

    if adapter == "file-drop":
        root = _resolve_path(base, item.get("path"), f"{context}.path")
        pattern = _string(item.get("glob", f"*.{data_format}"), f"{context}.glob")
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ConfigurationError(f"{context}.glob 不得是绝对路径或包含 ..")
        return SourceConfig(**common, path=root, glob=pattern)

    if adapter == "sqlite-query":
        database = _resolve_path(base, item.get("database"), f"{context}.database")
        query = _string(item.get("query"), f"{context}.query")
        return SourceConfig(**common, database=database, query=query)

    url = _string(item.get("url"), f"{context}.url")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError(f"{context}.url 只允许完整的 http/https URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ConfigurationError(f"{context}.url 不得包含用户信息或 fragment")
    allow_insecure_http = _boolean(
        item.get("allow_insecure_http", False), f"{context}.allow_insecure_http"
    )
    loopback_names = {"localhost", "127.0.0.1", "::1"}
    if (
        parsed.scheme == "http"
        and parsed.hostname not in loopback_names
        and not allow_insecure_http
    ):
        raise ConfigurationError(
            f"{context}.url 非本机 HTTP 会明文传输数据；仅可改用 HTTPS，"
            "或显式设置 allow_insecure_http=true 承担风险"
        )
    hosts = tuple(
        host.lower().rstrip(".")
        for host in _string_list(item.get("allowed_hosts"), f"{context}.allowed_hosts")
    )
    if parsed.hostname.lower().rstrip(".") not in hosts:
        raise ConfigurationError(f"{context}.url 主机必须明确列入 allowed_hosts")
    ports_value = item.get("allowed_ports", [443] if parsed.scheme == "https" else [80])
    if not isinstance(ports_value, list) or not ports_value:
        raise ConfigurationError(f"{context}.allowed_ports 必须是非空端口数组")
    ports = tuple(
        _positive_int(port, f"{context}.allowed_ports[]", maximum=65535) for port in ports_value
    )
    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if actual_port not in ports:
        raise ConfigurationError(f"{context}.url 端口必须明确列入 allowed_ports")
    headers_value = _table(item.get("headers", {}), f"{context}.headers")
    headers: dict[str, str] = {}
    for name, env_ref in headers_value.items():
        header_name = _string(name, f"{context}.headers key")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header_name):
            raise ConfigurationError(f"{context}.headers 包含非法 header 名")
        if header_name.lower() in {"host", "content-length", "connection", "transfer-encoding"}:
            raise ConfigurationError(f"{context}.headers 不允许覆盖 {header_name}")
        ref = _string(env_ref, f"{context}.headers.{header_name}")
        if not ref.startswith("env:") or not _ENV_RE.fullmatch(ref[4:]):
            raise ConfigurationError(f"{context}.headers.{header_name} 必须使用 env:ENV_NAME")
        headers[header_name] = ref[4:]
    return SourceConfig(
        **common,
        url=url,
        allowed_hosts=hosts,
        allowed_ports=ports,
        allow_private_network=_boolean(
            item.get("allow_private_network", False), f"{context}.allow_private_network"
        ),
        allow_insecure_http=allow_insecure_http,
        headers=headers,
        ca_bundle=_ca_bundle(base, item.get("ca_bundle"), f"{context}.ca_bundle"),
    )


def load_config(path: str | os.PathLike[str]) -> ServiceConfig:
    config_path = Path(path).expanduser().resolve()
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"配置文件不存在：{config_path}") from exc
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"无法读取 TOML 配置：{exc}") from exc

    _reject_unknown_keys(raw, _ROOT_KEYS, "配置根")
    base = config_path.parent
    service = _table(raw.get("service"), "service")
    _reject_unknown_keys(service, _SERVICE_KEYS, "service")
    endpoint = _string(service.get("agent_url"), "service.agent_url").rstrip("/")
    endpoint_parts = urlsplit(endpoint)
    if endpoint_parts.scheme not in {"http", "https"} or not endpoint_parts.hostname:
        raise ConfigurationError("service.agent_url 必须是完整的 http/https URL")
    if (
        endpoint_parts.username
        or endpoint_parts.password
        or endpoint_parts.query
        or endpoint_parts.fragment
    ):
        raise ConfigurationError("service.agent_url 不得包含用户信息、query 或 fragment")
    agent_allow_insecure_http = _boolean(
        service.get("agent_allow_insecure_http", False),
        "service.agent_allow_insecure_http",
    )
    if (
        endpoint_parts.scheme == "http"
        and endpoint_parts.hostname not in {"localhost", "127.0.0.1", "::1"}
        and not agent_allow_insecure_http
    ):
        raise ConfigurationError(
            "service.agent_url 非本机 HTTP 会明文传输煤矿数据；请改用 HTTPS，"
            "或显式设置 agent_allow_insecure_http=true"
        )
    agent_hosts = tuple(
        host.lower().rstrip(".")
        for host in _string_list(
            service.get("agent_allowed_hosts", [endpoint_parts.hostname]),
            "service.agent_allowed_hosts",
        )
    )
    if endpoint_parts.hostname.lower().rstrip(".") not in agent_hosts:
        raise ConfigurationError("service.agent_url 主机必须列入 agent_allowed_hosts")
    default_agent_port = 443 if endpoint_parts.scheme == "https" else 80
    port_values = service.get("agent_allowed_ports", [endpoint_parts.port or default_agent_port])
    if not isinstance(port_values, list) or not port_values:
        raise ConfigurationError("service.agent_allowed_ports 必须是非空端口数组")
    agent_ports = tuple(
        _positive_int(port, "service.agent_allowed_ports[]", maximum=65535) for port in port_values
    )
    if (endpoint_parts.port or default_agent_port) not in agent_ports:
        raise ConfigurationError("service.agent_url 端口必须列入 agent_allowed_ports")
    secret_env = _string(service.get("secret_env"), "service.secret_env")
    if not _ENV_RE.fullmatch(secret_env):
        raise ConfigurationError("service.secret_env 必须是合法的全大写环境变量名")

    raw_pipelines = raw.get("pipelines")
    if not isinstance(raw_pipelines, list) or not raw_pipelines:
        raise ConfigurationError("至少需要一个 [[pipelines]]")
    if len(raw_pipelines) != 1:
        raise ConfigurationError(
            "V1 one-mine 合同只允许一个 five-quantity pipeline；"
            "多个上游系统应配为同一 pipeline 下的 sources"
        )
    pipelines: list[PipelineConfig] = []
    pipeline_ids: set[str] = set()
    report_identities: set[tuple[str, str]] = set()
    for index, pipeline_value in enumerate(raw_pipelines):
        context = f"pipelines[{index}]"
        item = _table(pipeline_value, context)
        _reject_unknown_keys(item, _PIPELINE_KEYS, context)
        pipeline_id = _identifier(item.get("id"), f"{context}.id")
        if pipeline_id in pipeline_ids:
            raise ConfigurationError(f"重复的 pipeline id：{pipeline_id}")
        pipeline_ids.add(pipeline_id)
        period_type = item.get("period_type", "daily")
        if period_type not in {"daily", "shift"}:
            raise ConfigurationError(f"{context}.period_type 必须是 daily 或 shift")
        timezone = _string(item.get("timezone", "Asia/Shanghai"), f"{context}.timezone")
        try:
            ZoneInfo(timezone)
        except ZoneInfoNotFoundError as exc:
            raise ConfigurationError(f"{context}.timezone 无效：{timezone}") from exc
        source_values = item.get("sources")
        if not isinstance(source_values, list) or not source_values:
            raise ConfigurationError(f"{context} 至少需要一个 [[pipelines.sources]]")
        sources = tuple(
            _parse_source(source, f"{context}.sources[{source_index}]", base)
            for source_index, source in enumerate(source_values)
        )
        source_ids = [source.id for source in sources]
        if len(set(source_ids)) != len(source_ids):
            raise ConfigurationError(f"{context}.sources 的 id 不能重复")
        required = _string_list(item.get("required_sources"), f"{context}.required_sources")
        unknown_required = sorted(set(required) - set(source_ids))
        if unknown_required:
            raise ConfigurationError(
                f"{context}.required_sources 引用了未知来源：{', '.join(unknown_required)}"
            )
        mappings = _parse_mappings(item.get("mapping"), f"{context}.mapping")
        scope_field = (
            _string(item.get("scope_field"), f"{context}.scope_field")
            if item.get("scope_field") is not None
            else None
        )
        scope_values = _parse_scope_values(
            item.get("scope_values", {}), f"{context}.scope_values"
        )
        shifts = _parse_shifts(item.get("shifts", []), f"{context}.shifts")
        if period_type == "shift" and not shifts:
            raise ConfigurationError(f"{context} 使用 shift 时必须配置 shifts")
        enterprise_id = _identifier(item.get("enterprise_id"), f"{context}.enterprise_id")
        report_type = _identifier(
            item.get("report_type", "five-quantity"), f"{context}.report_type"
        )
        if report_type != "five-quantity":
            raise ConfigurationError(
                f"{context}.report_type 必须是 five-quantity，以匹配 Agent V2 合同"
            )
        workflow_name = _identifier(
            item.get("workflow_name", "daily_coal_health"),
            f"{context}.workflow_name",
        )
        if workflow_name != "daily_coal_health":
            raise ConfigurationError(
                f"{context}.workflow_name 必须是 daily_coal_health，以匹配 Agent 合同"
            )
        for source in sources:
            effective_period_type = source.period_type or period_type
            effective_shifts = source.shifts if source.shifts is not None else shifts
            if effective_period_type == "shift" and not effective_shifts:
                raise ConfigurationError(
                    f"{context}.sources[{source.id}] 有效 period_type=shift 时必须配置 shifts"
                )
        report_identity = (enterprise_id, report_type)
        if report_identity in report_identities:
            raise ConfigurationError(
                f"{context} 与其他 pipeline 复用了 enterprise_id/report_type，"
                "会碰撞同一月度 draft_key"
            )
        report_identities.add(report_identity)
        pipelines.append(
            PipelineConfig(
                id=pipeline_id,
                enterprise_id=enterprise_id,
                report_type=report_type,
                period_type=period_type,
                timezone=timezone,
                timestamp_field=_string(item.get("timestamp_field"), f"{context}.timestamp_field"),
                scope_field=scope_field,
                scope_values=scope_values,
                reporting_lag_days=_nonnegative_int(
                    item.get("reporting_lag_days", 0),
                    f"{context}.reporting_lag_days",
                    maximum=31,
                ),
                workflow_name=workflow_name,
                required_sources=required,
                sources=sources,
                mappings=mappings,
                shifts=shifts,
            )
        )

    client_id = _identifier(service.get("client_id"), "service.client_id")
    if len(client_id) > 64:
        raise ConfigurationError("service.client_id 不能超过 64 字符")
    return ServiceConfig(
        config_path=config_path,
        state_db=_resolve_path(
            base, service.get("state_db", "./state/connector.sqlite3"), "service.state_db"
        ),
        poll_interval_seconds=_positive_number(
            service.get("poll_interval_seconds", 60),
            "service.poll_interval_seconds",
            maximum=86_400,
        ),
        agent_url=endpoint,
        client_id=client_id,
        secret_env=secret_env,
        agent_timeout_seconds=_positive_number(
            service.get("agent_timeout_seconds", 15),
            "service.agent_timeout_seconds",
            maximum=60,
        ),
        agent_max_response_bytes=_positive_int(
            service.get("agent_max_response_bytes", 1_000_000),
            "service.agent_max_response_bytes",
            maximum=10_000_000,
        ),
        agent_allowed_hosts=agent_hosts,
        agent_allowed_ports=agent_ports,
        agent_allow_private_network=_boolean(
            service.get("agent_allow_private_network", False),
            "service.agent_allow_private_network",
        ),
        agent_allow_insecure_http=agent_allow_insecure_http,
        agent_ca_bundle=_ca_bundle(base, service.get("agent_ca_bundle"), "service.agent_ca_bundle"),
        retry_base_seconds=_positive_number(
            service.get("retry_base_seconds", 5), "service.retry_base_seconds", maximum=3600
        ),
        retry_max_seconds=_positive_number(
            service.get("retry_max_seconds", 900), "service.retry_max_seconds", maximum=86_400
        ),
        lease_seconds=_positive_int(
            service.get("lease_seconds", 120), "service.lease_seconds", maximum=3600
        ),
        pipelines=tuple(pipelines),
    )


def require_secret(config: ServiceConfig) -> bytes:
    value = os.environ.get(config.secret_env)
    if not value:
        raise ConfigurationError(f"环境变量 {config.secret_env} 未配置")
    encoded = value.encode("utf-8")
    if len(encoded) < 32:
        raise ConfigurationError(f"环境变量 {config.secret_env} 至少需要 32 字节随机密钥")
    return encoded
