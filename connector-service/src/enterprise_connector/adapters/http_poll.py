from __future__ import annotations

import os
from urllib.parse import urlsplit

from ..errors import SourceError
from ..models import RawBatch, SourceConfig
from ..net import request_bytes
from .parsing import parse_records


def collect_http_poll(config: SourceConfig) -> tuple[RawBatch, ...]:
    assert config.url is not None
    headers: dict[str, str] = {"Accept": "application/json, text/csv;q=0.9"}
    for name, env_name in config.headers.items():
        value = os.environ.get(env_name)
        if not value:
            raise SourceError(f"HTTP 来源所需环境变量 {env_name} 未配置")
        headers[name] = value
    result = request_bytes(
        "GET",
        config.url,
        headers=headers,
        body=None,
        timeout=config.timeout_seconds,
        max_response_bytes=config.max_bytes,
        allowed_hosts=config.allowed_hosts,
        allowed_ports=config.allowed_ports,
        allow_private_network=config.allow_private_network,
        ca_bundle=config.ca_bundle,
    )
    if result.status < 200 or result.status >= 300:
        raise SourceError(f"HTTP 来源返回状态码 {result.status}")
    filename = urlsplit(config.url).path.rsplit("/", 1)[-1] or f"{config.id}.{config.format}"
    return (
        RawBatch(
            source_id=config.id,
            original_filename=filename,
            records=parse_records(
                result.body,
                data_format=config.format,
                records_path=config.records_path,
                max_records=config.max_records,
            ),
        ),
    )
