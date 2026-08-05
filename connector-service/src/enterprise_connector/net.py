from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from .errors import SourceError

_ALWAYS_BLOCKED = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: bytes


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, resolved_ip: str, timeout: float):
        super().__init__(host, port=port, timeout=timeout)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._resolved_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        resolved_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._resolved_ip = resolved_ip

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._resolved_ip, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _validate_target(
    parts: SplitResult,
    *,
    allowed_hosts: tuple[str, ...],
    allowed_ports: tuple[int, ...],
    allow_private_network: bool,
) -> tuple[str, int, str]:
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise SourceError("URL 只允许 http/https 协议")
    if parts.username or parts.password or parts.fragment:
        raise SourceError("URL 不得包含用户信息或 fragment")
    host = parts.hostname.lower().rstrip(".")
    if host not in allowed_hosts:
        raise SourceError("目标主机不在 allowlist 中")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise SourceError("URL 端口无效") from exc
    if port not in allowed_ports:
        raise SourceError("目标端口不在 allowlist 中")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise SourceError(f"无法解析目标主机：{exc}") from exc
    if not addresses:
        raise SourceError("目标主机未解析出地址")
    validated: list[str] = []
    for address in sorted(addresses):
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if (
            ip in _ALWAYS_BLOCKED
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            raise SourceError("目标解析到禁止访问的地址")
        if not allow_private_network and (ip.is_private or ip.is_loopback or not ip.is_global):
            raise SourceError("目标解析到内网地址，但未显式启用 allow_private_network")
        validated.append(str(ip))
    return host, port, validated[0]


def request_bytes(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None,
    body: bytes | None,
    timeout: float,
    max_response_bytes: int,
    allowed_hosts: tuple[str, ...],
    allowed_ports: tuple[int, ...],
    allow_private_network: bool,
    ca_bundle: Path | None = None,
) -> HTTPResult:
    """Issue one pinned request. Redirects and proxy environment variables are never used."""

    if method not in {"GET", "POST"}:
        raise SourceError("只允许只读 GET 或 Agent POST")
    parts = urlsplit(url)
    host, port, resolved_ip = _validate_target(
        parts,
        allowed_hosts=allowed_hosts,
        allowed_ports=allowed_ports,
        allow_private_network=allow_private_network,
    )
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    outbound_headers = {"Accept-Encoding": "identity", "Connection": "close"}
    for name, value in (headers or {}).items():
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise SourceError("HTTP header 包含非法换行")
        outbound_headers[name] = value
    if body is not None:
        outbound_headers["Content-Length"] = str(len(body))
    connection: http.client.HTTPConnection
    if parts.scheme == "https":
        connection = _PinnedHTTPSConnection(
            host,
            port,
            resolved_ip,
            timeout,
            ssl.create_default_context(cafile=str(ca_bundle) if ca_bundle else None),
        )
    else:
        connection = _PinnedHTTPConnection(host, port, resolved_ip, timeout)
    try:
        connection.request(method, path, body=body, headers=outbound_headers)
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise SourceError("HTTP 重定向被安全策略拒绝")
        encoding = response.getheader("Content-Encoding", "identity").lower().strip()
        if encoding not in {"", "identity"}:
            raise SourceError("不接受压缩响应，避免解压炸弹")
        length_header = response.getheader("Content-Length")
        if length_header:
            try:
                if int(length_header) > max_response_bytes:
                    raise SourceError("HTTP 响应超过大小上限")
            except ValueError as exc:
                raise SourceError("HTTP Content-Length 无效") from exc
        response_body = response.read(max_response_bytes + 1)
        if len(response_body) > max_response_bytes:
            raise SourceError("HTTP 响应超过大小上限")
        return HTTPResult(
            status=response.status,
            headers={key.lower(): value for key, value in response.getheaders()},
            body=response_body,
        )
    except TimeoutError as exc:
        raise SourceError("HTTP 请求超时") from exc
    except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
        raise SourceError(f"HTTP 请求失败：{type(exc).__name__}") from exc
    finally:
        connection.close()
