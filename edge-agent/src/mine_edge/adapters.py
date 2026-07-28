"""Read-only acquisition adapters for common mine-side integration patterns."""

from __future__ import annotations

import abc
import json
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import AdapterError


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so a read token is never forwarded to another URL."""

    def _reject(self, request, response, code, message, headers):
        del message
        response.close()
        raise urllib.error.HTTPError(
            request.full_url,
            code,
            "source redirect refused",
            headers,
            None,
        )

    http_error_301 = _reject
    http_error_302 = _reject
    http_error_303 = _reject
    http_error_307 = _reject
    http_error_308 = _reject


@dataclass(frozen=True, slots=True)
class RawRecord:
    data: dict[str, Any]
    channel: str
    source_id: str


class ReadOnlyAdapter(abc.ABC):
    """Acquisition interface. Implementations may read, but never control."""

    read_only = True

    @abc.abstractmethod
    def poll(self) -> list[RawRecord]:
        raise NotImplementedError


class JsonlAdapter(ReadOnlyAdapter):
    def __init__(self, path: Path | str, *, source_id: str = "jsonl") -> None:
        self.path = Path(path)
        self.source_id = source_id

    def poll(self) -> list[RawRecord]:
        records: list[RawRecord] = []
        try:
            with self.path.open("r", encoding="utf-8-sig") as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise AdapterError(
                            f"{self.path} 第 {line_number} 行不是有效 JSON"
                        ) from error
                    if not isinstance(value, dict):
                        raise AdapterError(
                            f"{self.path} 第 {line_number} 行顶层必须是对象"
                        )
                    records.append(
                        RawRecord(value, "jsonl", f"{self.source_id}:{self.path.name}")
                    )
        except OSError as error:
            raise AdapterError(f"无法只读打开 JSONL：{self.path}: {error}") from error
        return records


class FileDropAdapter(ReadOnlyAdapter):
    """Read *.json and *.jsonl without deleting or moving source files."""

    def __init__(self, directory: Path | str, *, source_id: str = "file-drop") -> None:
        self.directory = Path(directory)
        self.source_id = source_id

    def poll(self) -> list[RawRecord]:
        if not self.directory.is_dir():
            raise AdapterError(f"投递目录不存在：{self.directory}")
        records: list[RawRecord] = []
        files = sorted(
            [
                *self.directory.glob("*.json"),
                *self.directory.glob("*.jsonl"),
            ]
        )
        for path in files:
            if path.suffix == ".jsonl":
                jsonl_records = JsonlAdapter(path, source_id=self.source_id).poll()
                records.extend(
                    RawRecord(
                        record.data,
                        "file_drop",
                        f"{self.source_id}:{path.name}",
                    )
                    for record in jsonl_records
                )
                continue
            try:
                with path.open("r", encoding="utf-8-sig") as stream:
                    value = json.load(stream)
            except (OSError, json.JSONDecodeError) as error:
                raise AdapterError(f"无法读取投递文件 {path}: {error}") from error
            values = value if isinstance(value, list) else [value]
            for index, item in enumerate(values):
                if not isinstance(item, dict):
                    raise AdapterError(f"{path} 第 {index + 1} 项顶层必须是对象")
                records.append(
                    RawRecord(
                        item,
                        "file_drop",
                        f"{self.source_id}:{path.name}",
                    )
                )
        return records


class HttpPollAdapter(ReadOnlyAdapter):
    """Poll a source endpoint with HTTP GET only."""

    def __init__(
        self,
        url: str,
        *,
        source_id: str = "http-poll",
        token: str | None = None,
        timeout_seconds: float = 10,
        ca_file: Path | str | None = None,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise AdapterError("HTTP 轮询地址必须是有效 HTTP(S) URL")
        self.url = url
        self.source_id = source_id
        self.token = token
        self.timeout_seconds = timeout_seconds
        self.ca_file = Path(ca_file) if ca_file else None

    def poll(self) -> list[RawRecord]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.url, headers=headers, method="GET")
        context = (
            ssl.create_default_context(cafile=str(self.ca_file))
            if self.ca_file
            else ssl.create_default_context()
        )
        opener = urllib.request.build_opener(
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=context),
        )
        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                if response.status < 200 or response.status >= 300:
                    raise AdapterError(f"HTTP 轮询返回 {response.status}")
                payload = response.read(10 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if error.code in {301, 302, 303, 307, 308}:
                raise AdapterError(
                    f"HTTP 轮询拒绝重定向（{error.code}）；请配置最终只读 URL"
                ) from error
            raise AdapterError(f"HTTP 轮询返回 {error.code}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise AdapterError(f"HTTP 轮询失败：{error}") from error
        if len(payload) > 10 * 1024 * 1024:
            raise AdapterError("HTTP 轮询响应超过 10 MiB")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdapterError("HTTP 轮询响应不是有效 UTF-8 JSON") from error
        if isinstance(value, dict) and "observations" in value:
            value = value["observations"]
        values = value if isinstance(value, list) else [value]
        records: list[RawRecord] = []
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                raise AdapterError(f"HTTP 轮询第 {index + 1} 项必须是对象")
            records.append(RawRecord(item, "http_poll", self.source_id))
        return records
