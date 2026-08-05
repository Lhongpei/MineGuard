"""Standard-library HTTP API and optional static frontend hosting."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import mimetypes
import re
import socket
import sys
import time
from collections.abc import Callable
from datetime import date
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit
from zoneinfo import ZoneInfo

from . import __version__
from .agent_v2.governance import GovernanceAccess
from .auth import (
    SESSION_COOKIE_NAME,
    AuthContext,
    AuthenticationFailed,
    AuthManager,
    LoginThrottled,
    is_loopback,
)
from .errors import AgentError, RequestTooLargeError
from .machine_ingestion import (
    AUTOFILL_PATH,
    SOURCE_HEALTH_PATH,
    ConnectorAuthenticationError,
    ConnectorAuthorizationError,
    ConnectorClient,
    MachineAutofillCoordinator,
    authenticate_connector_request,
    validate_autofill_payload,
    validate_source_health_payload,
)
from .service import EnterpriseAgentService
from .util import parse_aware_datetime, sha256_jcs, utc_now

_MAX_BODY = 2 * 1024 * 1024
_MAX_IMPORT_BODY = 30 * 1024 * 1024
_MAX_MACHINE_BODY = 5 * 1024 * 1024
_MAX_MACHINE_HEALTH_BODY = 64 * 1024
_DRAFT_ROUTE = re.compile(
    r"^/api/v1/drafts/([^/]+)(?:/(import|event-snapshot|assist|questions|validate|reviews|confirm|submit|audit|submissions))?$"
)
_AGENT_RUN_ROUTE = re.compile(r"^/api/v1/agent/runs/([^/]+)(?:/(approve|cancel))?$")
_AGENT_FLOW_ROUTE = re.compile(r"^/api/v1/agent/flows/([^/]+)(?:/(cancel|retry))?$")
_AGENT_JOB_ROUTE = re.compile(r"^/api/v1/agent/jobs/([^/]+)(?:/(run))?$")
_MEMORY_PROPOSAL_ROUTE = re.compile(
    r"^/api/v1/agent/memory/proposals/([^/]+)(?:/(decision))?$"
)
_MEMORY_ROUTE = re.compile(r"^/api/v1/agent/memories/([^/]+)$")
_SKILL_PROPOSAL_ROUTE = re.compile(
    r"^/api/v1/agent/skill-proposals/([^/]+)(?:/(decision))?$"
)
_SKILL_VERSION_ROUTE = re.compile(r"^/api/v1/agent/skill-versions/([^/]+)$")
_CHAT_SESSION_ROUTE = re.compile(r"^/api/v1/chat/sessions/([^/]+)(?:/(messages))?$")
_FQ_DRAFT_ROUTE = re.compile(
    r"^/api/v2/drafts/([^/]+)(?:/(confirm|send-now|ingestions|machine-resume))?$"
)
_FQ_RISK_ROUTE = re.compile(r"^/api/v2/risks/([^/]+)(?:/(chat|response))?$")
_FQ_RESPONSE_ROUTE = re.compile(r"^/api/v2/responses/([^/]+)(?:/(confirm))?$")
_AGENT_V2_PREFIXES = (
    "/api/v1/agent/workflows",
    "/api/v1/agent/flows",
    "/api/v1/agent/jobs",
    "/api/v1/agent/events",
    "/api/v1/agent/memory",
    "/api/v1/agent/memories",
    "/api/v1/agent/skill-proposals",
    "/api/v1/agent/skill-versions",
)


def _is_agent_v2_path(path: str) -> bool:
    return any(
        path == prefix or path.startswith(prefix + "/") for prefix in _AGENT_V2_PREFIXES
    )


class EnterpriseAgentHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        service: EnterpriseAgentService,
        *,
        auth_manager: AuthManager | None = None,
        secure_cookie: bool = False,
        public_origin: str | None = None,
        web_root: Path | None = None,
        connector_clients: tuple[ConnectorClient, ...] = (),
        connector_max_clock_skew_seconds: int = 300,
    ):
        loopback_bind = is_loopback(server_address[0])
        if auth_manager is None:
            if not loopback_bind:
                raise ValueError("非回环监听必须显式配置企业用户认证")
            # Direct construction is retained for tests and explicit local
            # development. The CLI uses configured accounts (or the loopback
            # demo account) instead of this anonymous principal.
            auth_manager = AuthManager(allow_anonymous_local=True)
        if not loopback_bind and (
            auth_manager.account_count == 0 or auth_manager.allow_anonymous_local
        ):
            raise ValueError("非回环监听必须配置逐用户账号且禁止匿名本机身份")
        if not loopback_bind and not secure_cookie:
            raise ValueError("非回环监听必须启用 Secure Cookie 并使用 HTTPS")
        if not loopback_bind and public_origin is None:
            raise ValueError("非回环监听必须配置唯一的 PUBLIC_ORIGIN")
        if (
            public_origin is not None
            and urlsplit(public_origin).scheme == "https"
            and not secure_cookie
        ):
            raise ValueError("配置 HTTPS public origin 时必须启用 Secure Cookie")
        if (
            public_origin is not None
            and urlsplit(public_origin).scheme == "http"
            and secure_cookie
        ):
            raise ValueError("HTTP public origin 不能使用 Secure Cookie")
        if public_origin is not None and (
            auth_manager.allow_anonymous_local or auth_manager.has_temporary_accounts
        ):
            raise ValueError("配置 PUBLIC_ORIGIN 时禁止匿名身份和临时演示账号")
        if not 30 <= connector_max_clock_skew_seconds <= 900:
            raise ValueError("连接器时钟偏差上限必须在 30-900 秒之间")
        if len(connector_clients) > 1:
            raise ValueError("one-mine 模式最多允许 1 个权威机器连接器 client")
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        self.service = service
        self.auth_manager = auth_manager
        self.secure_cookie = secure_cookie
        self.public_origin = public_origin.rstrip("/") if public_origin else None
        self.public_authority = (
            urlsplit(self.public_origin).netloc.lower()
            if self.public_origin is not None
            else None
        )
        self.loopback_bind = loopback_bind
        self.web_root = web_root
        self.connector_clients = tuple(connector_clients)
        self.connector_max_clock_skew_seconds = connector_max_clock_skew_seconds
        # Legacy/read-only service doubles used by embedding callers do not
        # necessarily expose the durable repository.  The coordinator is only
        # meaningful when an authenticated connector has explicitly been
        # configured, so avoid imposing that dependency on every HTTP server.
        self.machine_autofill = (
            MachineAutofillCoordinator(service)
            if self.connector_clients
            else None
        )
        five_quantity_runtime = getattr(self.service, "_five_quantity", None)
        configure_policies = getattr(
            five_quantity_runtime,
            "configure_machine_source_policies",
            None,
        )
        if callable(configure_policies):
            policies = (
                tuple(
                    policy.public_policy()
                    for policy in self.connector_clients[0].allowed_sources
                )
                if self.connector_clients
                else ()
            )
            configure_policies(policies)
        enable_harness = getattr(self.service, "enable_harness", None)
        try:
            # Finish all in-process runtime initialization before binding the
            # listening socket. A successful TCP connect must mean Ctrl-C is
            # already inside the clean foreground shutdown boundary.
            if callable(enable_harness):
                enable_harness()
            super().__init__(server_address, EnterpriseAgentHandler)
        except BaseException:
            disable_harness = getattr(self.service, "disable_harness", None)
            if callable(disable_harness):
                disable_harness()
            raise

    def handle_error(
        self,
        request: Any,
        client_address: tuple[str, int],
    ) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            return
        # Never dump a request, header, body, URL query, secret-bearing
        # exception message, or traceback to a shared production log.
        print(
            "企业端请求处理失败"
            f"（{type(error).__name__ if error is not None else 'UnknownError'}）",
            file=sys.stderr,
        )

    def server_close(self) -> None:
        service = getattr(self, "service", None)
        disable_harness = getattr(service, "disable_harness", None)
        if callable(disable_harness):
            disable_harness()
        super().server_close()


class EnterpriseAgentHandler(BaseHTTPRequestHandler):
    server: EnterpriseAgentHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = f"EnterpriseReportingAgent/{__version__}"
    sys_version = ""

    def log_request(
        self,
        code: int | str = "-",
        size: int | str = "-",
    ) -> None:
        # Deliberately strip the query string: operators sometimes paste
        # credentials into URLs even though this API never requires them.
        path = urlsplit(self.path).path
        print(
            f"{self.client_address[0]} - {self.command} {path} -> {code}",
            file=sys.stderr,
        )

    def log_message(self, format: str, *args: Any) -> None:
        # All ordinary access logging is handled by the query-stripping
        # log_request override. Avoid BaseHTTPRequestHandler's raw request line.
        return

    def _write_body(self, body: bytes) -> None:
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _json(
        self,
        status: int | HTTPStatus,
        payload: dict[str, Any],
        *,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; form-action 'none'; "
            "frame-ancestors 'none'",
        )
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self._write_body(body)

    def _error(
        self,
        status: int | HTTPStatus,
        code: str,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        # Authentication/authorization can reject before a request body is
        # consumed. Closing the HTTP/1.1 connection prevents unread bytes from
        # being interpreted as the next request on a persistent connection.
        self.close_connection = True
        error: dict[str, Any] = {"code": code, "message": message}
        if details:
            error["details"] = details
        self._json(
            status,
            {"error": error},
            headers=(("Connection", "close"),),
        )

    def _session_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE_NAME)
        return morsel.value if morsel is not None else None

    def _authenticate(self) -> AuthContext | None:
        if not self._host_is_allowed():
            self._error(
                HTTPStatus.FORBIDDEN,
                "host_not_allowed",
                "请求主机不在企业端允许范围内",
            )
            return None
        context = self.server.auth_manager.authenticate(
            self._session_token(),
            remote_address=self.client_address[0],
        )
        if context is None:
            self._error(
                HTTPStatus.UNAUTHORIZED,
                "authentication_required",
                "请先登录企业账号",
            )
        return context

    def _require(self, context: AuthContext, permission: str) -> bool:
        if context.principal.must_change_password and permission in {
            "confirm",
            "submit",
            "governance_review",
            "skill_admin",
        }:
            self._error(
                HTTPStatus.FORBIDDEN,
                "credential_rotation_required",
                "临时或待换密账号不能执行确认、提交或治理审批；请由管理员在密钥系统"
                "更新 password_hash、取消 must_change_password 并重启服务",
            )
            return False
        if context.principal.allows(permission):
            return True
        self._error(
            HTTPStatus.FORBIDDEN,
            "permission_denied",
            f"当前企业账号缺少 {permission} 权限",
        )
        return False

    def _host_is_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        if not host or any(character in host for character in "\r\n/\\"):
            return False
        if self.server.public_authority is not None:
            return host.lower() == self.server.public_authority
        if not self.server.loopback_bind:
            return True
        host_name = urlsplit(f"//{host}").hostname
        return host_name is not None and is_loopback(host_name)

    def _origin_is_same(self) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site")
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            return False
        if not self._host_is_allowed():
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            # Non-browser clients do not necessarily send Origin. Session
            # requests still require the unguessable CSRF token below.
            return True
        host = self.headers.get("Host", "")
        if origin == "null":
            return False
        if (
            self.server.public_origin is not None
            and host.lower() == self.server.public_authority
        ):
            return origin == self.server.public_origin
        expected_scheme = "https" if self.server.secure_cookie else "http"
        return origin == f"{expected_scheme}://{host}"

    def _protect_mutation(self, context: AuthContext) -> bool:
        if not self._origin_is_same():
            self._error(
                HTTPStatus.FORBIDDEN,
                "cross_origin_request_denied",
                "仅允许同源页面发起修改请求",
            )
            return False
        supplied = self.headers.get("X-CSRF-Token", "")
        if context.is_session and (
            not supplied
            or not hmac.compare_digest(
                supplied.encode("utf-8"),
                context.csrf_token.encode("ascii"),
            )
        ):
            self._error(
                HTTPStatus.FORBIDDEN,
                "csrf_token_invalid",
                "CSRF 令牌缺失或无效，请刷新页面后重试",
            )
            return False
        if supplied and not hmac.compare_digest(
            supplied.encode("utf-8"),
            context.csrf_token.encode("ascii"),
        ):
            self._error(
                HTTPStatus.FORBIDDEN,
                "csrf_token_invalid",
                "CSRF 令牌无效",
            )
            return False
        return True

    def _raw_body(
        self,
        *,
        optional: bool = False,
        maximum: int = _MAX_BODY,
    ) -> bytes:
        transfer_encoding = self.headers.get("Transfer-Encoding")
        if transfer_encoding:
            raise ValueError("不支持 Transfer-Encoding，请发送 Content-Length")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1:
            raise ValueError("Content-Length 只能出现一次")
        raw_length = lengths[0] if lengths else None
        if raw_length is None:
            if optional:
                return b""
            raise ValueError("请求缺少 Content-Length")
        try:
            length = int(raw_length)
        except ValueError as error:
            raise ValueError("Content-Length 非法") from error
        if length < 0 or length > maximum:
            limit = (
                f"{maximum // 1024} KiB"
                if maximum < 1024 * 1024
                else f"{maximum // (1024 * 1024)} MiB"
            )
            raise RequestTooLargeError(f"请求体不能超过 {limit}")
        if length == 0:
            if optional:
                return b""
            raise ValueError("JSON 请求体不能为空")
        content_type = self.headers.get_content_type().lower()
        if content_type != "application/json" and not content_type.endswith("+json"):
            raise ValueError("请求体 Content-Type 必须是 application/json")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("请求体未完整传输")
        return raw

    @staticmethod
    def _parse_json_object(raw: bytes, *, optional: bool = False) -> dict[str, Any]:
        if not raw and optional:
            return {}

        def reject_duplicate_keys(
            pairs: list[tuple[str, Any]],
        ) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"JSON 包含重复字段：{key}")
                result[key] = value
            return result

        try:
            parsed = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("请求体必须是有效 JSON") from error
        except RecursionError as error:
            raise ValueError("JSON 嵌套层级过深") from error
        if not isinstance(parsed, dict):
            raise ValueError("JSON 顶层必须是对象")
        stack: list[tuple[Any, int]] = [(parsed, 1)]
        node_count = 0
        while stack:
            value, depth = stack.pop()
            node_count += 1
            if node_count > 250_000:
                raise ValueError("JSON 结构节点过多")
            if depth > 64:
                raise ValueError("JSON 嵌套层级不能超过 64")
            if isinstance(value, dict):
                stack.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, list):
                stack.extend((item, depth + 1) for item in value)
        return parsed

    def _body(
        self,
        *,
        optional: bool = False,
        maximum: int = _MAX_BODY,
    ) -> dict[str, Any]:
        return self._parse_json_object(
            self._raw_body(optional=optional, maximum=maximum),
            optional=optional,
        )

    def _cookie(self, token: str, max_age: int) -> str:
        parts = [
            f"{SESSION_COOKIE_NAME}={token}",
            "Path=/",
            f"Max-Age={max_age}",
            "HttpOnly",
            "SameSite=Strict",
        ]
        if self.server.secure_cookie:
            parts.append("Secure")
        return "; ".join(parts)

    def _session_payload(self, context: AuthContext) -> dict[str, Any]:
        return {
            "authenticated": True,
            "principal": context.principal.public_dict(),
            "csrf_token": context.csrf_token,
            "expires_at": context.expires_at,
        }

    def _pagination(
        self,
        *,
        allowed: frozenset[str],
        default_limit: int,
        maximum_limit: int,
        allow_offset: bool,
    ) -> tuple[int, int]:
        query = parse_qs(
            urlsplit(self.path).query,
            keep_blank_values=True,
        )
        unknown = set(query) - allowed
        if unknown:
            raise ValueError("不支持的查询参数：" + ", ".join(sorted(unknown)))
        if any(len(values) != 1 for values in query.values()):
            raise ValueError("分页查询参数不能重复")

        def integer(name: str, default: int, maximum: int) -> int:
            raw = query.get(name, [str(default)])[0]
            try:
                value = int(raw)
            except ValueError as error:
                raise ValueError(f"{name} 必须是整数") from error
            if value < 0 or value > maximum:
                raise ValueError(f"{name} 必须在 0-{maximum} 之间")
            return value

        limit = integer("limit", default_limit, maximum_limit)
        if limit == 0:
            raise ValueError("limit 必须大于 0")
        offset = integer("offset", 0, 1_000_000) if allow_offset else 0
        return limit, offset

    def _boolean_query(self, name: str, *, default: bool = False) -> bool:
        query = parse_qs(
            urlsplit(self.path).query,
            keep_blank_values=True,
        )
        unknown = set(query) - {name}
        if unknown:
            raise ValueError("不支持的查询参数：" + ", ".join(sorted(unknown)))
        if any(len(values) != 1 for values in query.values()):
            raise ValueError("查询参数不能重复")
        raw = query.get(name, [str(default).lower()])[0].lower()
        if raw not in {"true", "false"}:
            raise ValueError(f"{name} 必须是 true 或 false")
        return raw == "true"

    @staticmethod
    def _reject_unknown_fields(
        body: dict[str, Any],
        allowed: frozenset[str],
    ) -> None:
        unknown = set(body) - allowed
        if unknown:
            raise ValueError("不支持的字段：" + ", ".join(sorted(unknown)))

    @staticmethod
    def _governance_access(context: AuthContext) -> GovernanceAccess:
        # The enterprise agent is deployed as one enterprise-side security
        # boundary. User-scoped records remain actor-private even in this mode.
        return GovernanceAccess.single_tenant(
            context.principal.actor_id,
            can_review=context.principal.allows("governance_review"),
            can_manage_skills=context.principal.allows("skill_admin"),
        )

    def _machine_autofill_route(self, method: str) -> None:
        if method != "POST":
            self._method_not_allowed(("POST",))
            return
        if self.path != AUTOFILL_PATH:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request_target",
                "机器自动填报请求路径必须与签名路径完全一致",
            )
            return
        if not self._host_is_allowed():
            self._error(
                HTTPStatus.FORBIDDEN,
                "host_not_allowed",
                "请求主机不在企业端允许范围内",
            )
            return
        if not self.server.connector_clients:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "connector_unavailable",
                "机器自动填报入口尚未配置",
            )
            return

        names = {
            "client_id": "X-Enterprise-Connector-Client",
            "timestamp": "X-Enterprise-Connector-Timestamp",
            "request_id": "X-Enterprise-Connector-Request-Id",
            "signature": "X-Enterprise-Connector-Signature",
        }
        values: dict[str, str] = {}
        for key, name in names.items():
            supplied = self.headers.get_all(name, [])
            if len(supplied) != 1:
                raise ConnectorAuthenticationError()
            values[key] = supplied[0]

        raw = self._raw_body(maximum=_MAX_MACHINE_BODY)
        authenticated = authenticate_connector_request(
            clients=self.server.connector_clients,
            client_id=values["client_id"],
            timestamp=values["timestamp"],
            request_id=values["request_id"],
            signature=values["signature"],
            raw_body=raw,
            maximum_clock_skew_seconds=(
                self.server.connector_max_clock_skew_seconds
            ),
        )
        self.server.service.repository.register_connector_request(
            client_id=authenticated.client_id,
            request_id=authenticated.request_id,
            request_sha256=authenticated.body_sha256,
            request_timestamp=authenticated.timestamp,
        )
        payload = validate_autofill_payload(self._parse_json_object(raw))
        if (
            parse_aware_datetime(
                payload["source"]["observed_at"], "source.observed_at"
            ).timestamp()
            > min(float(authenticated.timestamp), time.time())
            + self.server.connector_max_clock_skew_seconds
        ):
            raise ValueError("source.observed_at 不得晚于已认证请求时间")
        client = next(
            item
            for item in self.server.connector_clients
            if item.client_id == authenticated.client_id
        )
        source = payload["source"]
        source_policy = client.source_policy(
            source["source_id"], source["source_system"]
        )
        if source_policy is None:
            raise ConnectorAuthorizationError(
                "该权威连接器未获准声明此 source_id/source_system 来源"
            )
        result, created = self.server.machine_autofill.ingest(
            authenticated=authenticated,
            payload=payload,
            source_policy=source_policy,
        )
        status = (
            HTTPStatus.ACCEPTED
            if created and result["workflow"]["triggered"]
            else HTTPStatus.CREATED
            if created
            else HTTPStatus.OK
        )
        self._json(status, result)

    def _machine_source_health_route(self, method: str) -> None:
        if method != "POST":
            self._method_not_allowed(("POST",))
            return
        if self.path != SOURCE_HEALTH_PATH:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request_target",
                "机器来源健康请求路径必须与签名路径完全一致",
            )
            return
        if not self._host_is_allowed():
            self._error(
                HTTPStatus.FORBIDDEN,
                "host_not_allowed",
                "请求主机不在企业端允许范围内",
            )
            return
        if not self.server.connector_clients:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "connector_unavailable",
                "机器连接器入口尚未配置",
            )
            return
        names = {
            "client_id": "X-Enterprise-Connector-Client",
            "timestamp": "X-Enterprise-Connector-Timestamp",
            "request_id": "X-Enterprise-Connector-Request-Id",
            "signature": "X-Enterprise-Connector-Signature",
        }
        values: dict[str, str] = {}
        for key, name in names.items():
            supplied = self.headers.get_all(name, [])
            if len(supplied) != 1:
                raise ConnectorAuthenticationError()
            values[key] = supplied[0]
        raw = self._raw_body(maximum=_MAX_MACHINE_HEALTH_BODY)
        authenticated = authenticate_connector_request(
            clients=self.server.connector_clients,
            client_id=values["client_id"],
            timestamp=values["timestamp"],
            request_id=values["request_id"],
            signature=values["signature"],
            raw_body=raw,
            maximum_clock_skew_seconds=(
                self.server.connector_max_clock_skew_seconds
            ),
            path=SOURCE_HEALTH_PATH,
        )
        self.server.service.repository.register_connector_request(
            client_id=authenticated.client_id,
            request_id=authenticated.request_id,
            request_sha256=authenticated.body_sha256,
            request_timestamp=authenticated.timestamp,
        )
        payload = validate_source_health_payload(self._parse_json_object(raw))
        now_epoch = time.time()
        completed_epoch = parse_aware_datetime(
            payload["completed_at"], "completed_at"
        ).timestamp()
        if completed_epoch > min(float(authenticated.timestamp), now_epoch) + (
            self.server.connector_max_clock_skew_seconds
        ):
            raise ValueError("completed_at 不得晚于已认证请求时间")
        if completed_epoch < now_epoch - 30 * 24 * 60 * 60:
            raise ValueError("completed_at 早于允许的 30 天健康事件窗口")
        runtime = getattr(self.server.service, "_five_quantity", None)
        if runtime is None:
            raise ValueError("五量 V2 正式填报运行时未启用")
        expected_draft_key = (
            f"draft:{runtime.identity.operator_id}:five-quantity:monthly:"
            f"{payload['reporting_month']}"
        )
        if payload["draft_key"] != expected_draft_key:
            raise ConnectorAuthorizationError(
                "draft_key 不属于当前经营主体的权威五量月度范围"
            )
        if payload["coverage_as_of"] is not None:
            local_today = utc_now().astimezone(
                ZoneInfo(runtime.identity.timezone)
            ).date()
            if date.fromisoformat(payload["coverage_as_of"]) > local_today:
                raise ValueError("coverage_as_of 不得晚于矿区当前日期")
        client = next(
            item
            for item in self.server.connector_clients
            if item.client_id == authenticated.client_id
        )
        policy = client.source_policy(
            payload["source_id"], payload["source_system"]
        )
        if policy is None:
            raise ConnectorAuthorizationError(
                "该权威连接器未获准声明此 source_id/source_system 来源"
            )
        result, created = (
            self.server.service.repository.record_connector_source_health(
                client_id=authenticated.client_id,
                request_sha256=authenticated.body_sha256,
                payload=payload,
                source_required=policy.required,
                freshness_max_seconds=policy.freshness_max_seconds,
            )
        )
        self._json(HTTPStatus.CREATED if created else HTTPStatus.OK, result)

    def _agent_v2_route(
        self,
        method: str,
        path: str,
        context: AuthContext,
    ) -> bool:
        """Handle durable workflows, scheduling and governed learning APIs."""

        service = self.server.service
        runtime = service.agent_v2
        scheduler = service.agent_jobs

        if path == "/api/v1/agent/workflows":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return True
            if not self._require(context, "read"):
                return True
            items = runtime.public_workflows()
            self._json(
                HTTPStatus.OK,
                {"workflows": items, "items": items, "count": len(items)},
            )
            return True

        if path == "/api/v1/agent/flows":
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                limit, offset = self._pagination(
                    allowed=frozenset({"limit", "offset", "status"}),
                    default_limit=20,
                    maximum_limit=100,
                    allow_offset=True,
                )
                query = parse_qs(
                    urlsplit(self.path).query,
                    keep_blank_values=True,
                )
                status_filter = query.get("status", [None])[0]
                if status_filter == "":
                    status_filter = None
                items, total = runtime.list(
                    actor_id=context.principal.actor_id,
                    limit=limit,
                    offset=offset,
                    status=status_filter,
                )
                next_offset = offset + len(items)
                self._json(
                    HTTPStatus.OK,
                    {
                        "flows": items,
                        "items": items,
                        "count": len(items),
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "has_more": next_offset < total,
                        "next_offset": (next_offset if next_offset < total else None),
                    },
                )
                return True
            if method == "POST":
                if not self._require(context, "read"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset(
                        {
                            "workflow",
                            "workflow_name",
                            "draft_id",
                            "goal",
                            "goal_text",
                            "client_request_id",
                        }
                    ),
                )
                flow = runtime.create(
                    actor_id=context.principal.actor_id,
                    workflow_name=body.get(
                        "workflow_name",
                        body.get("workflow", "daily_coal_health"),
                    ),
                    draft_id=body.get("draft_id"),
                    goal=body.get("goal_text", body.get("goal", "")),
                    client_request_id=body.get("client_request_id"),
                )
                self._json(HTTPStatus.ACCEPTED, {"flow": flow})
                return True
            self._method_not_allowed(("GET", "POST"))
            return True

        flow_match = _AGENT_FLOW_ROUTE.fullmatch(path)
        if flow_match:
            flow_id = unquote(flow_match.group(1))
            action = flow_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(
                    HTTPStatus.OK,
                    {
                        "flow": runtime.get(
                            flow_id,
                            actor_id=context.principal.actor_id,
                        )
                    },
                )
                return True
            if action in {"cancel", "retry"} and method == "POST":
                if not self._require(context, "read"):
                    return True
                body = self._body(optional=True)
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision"}),
                )
                operation = runtime.cancel if action == "cancel" else runtime.retry
                flow = operation(
                    flow_id,
                    actor_id=context.principal.actor_id,
                    expected_revision=body.get("expected_revision"),
                )
                self._json(
                    HTTPStatus.ACCEPTED if action == "retry" else HTTPStatus.OK,
                    {"flow": flow},
                )
                return True
            self._method_not_allowed(("GET",) if action is None else ("POST",))
            return True

        if path == "/api/v1/agent/jobs":
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                limit, offset = self._pagination(
                    allowed=frozenset({"limit", "offset"}),
                    default_limit=20,
                    maximum_limit=100,
                    allow_offset=True,
                )
                items, total = scheduler.list_jobs(
                    actor_id=context.principal.actor_id,
                    limit=limit,
                    offset=offset,
                )
                next_offset = offset + len(items)
                self._json(
                    HTTPStatus.OK,
                    {
                        "jobs": items,
                        "items": items,
                        "count": len(items),
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "has_more": next_offset < total,
                        "next_offset": (next_offset if next_offset < total else None),
                    },
                )
                return True
            if method == "POST":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset(
                        {
                            "name",
                            "workflow_name",
                            "draft_id",
                            "goal_text",
                            "schedule_kind",
                            "schedule",
                            "enabled",
                            "client_request_id",
                        }
                    ),
                )
                job = scheduler.create_job(
                    actor_id=context.principal.actor_id,
                    name=body.get("name"),
                    workflow_name=body.get(
                        "workflow_name",
                        "daily_coal_health",
                    ),
                    draft_id=body.get("draft_id"),
                    goal_text=body.get("goal_text", ""),
                    schedule_kind=body.get("schedule_kind"),
                    schedule=body.get("schedule"),
                    enabled=body.get("enabled", True),
                    client_request_id=body.get("client_request_id"),
                )
                self._json(HTTPStatus.CREATED, {"job": job})
                return True
            self._method_not_allowed(("GET", "POST"))
            return True

        job_match = _AGENT_JOB_ROUTE.fullmatch(path)
        if job_match:
            job_id = unquote(job_match.group(1))
            action = job_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(
                    HTTPStatus.OK,
                    {
                        "job": scheduler.get_job(
                            job_id,
                            actor_id=context.principal.actor_id,
                        )
                    },
                )
                return True
            if action is None and method == "PATCH":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                expected_revision = body.get("expected_revision")
                patch = body.get("patch")
                if patch is None:
                    patch = {
                        key: value
                        for key, value in body.items()
                        if key != "expected_revision"
                    }
                else:
                    self._reject_unknown_fields(
                        body,
                        frozenset({"expected_revision", "patch"}),
                    )
                job = scheduler.update_job(
                    job_id,
                    actor_id=context.principal.actor_id,
                    expected_revision=expected_revision,
                    patch=patch,
                )
                self._json(HTTPStatus.OK, {"job": job})
                return True
            if action is None and method == "DELETE":
                if not self._require(context, "write"):
                    return True
                body = self._body(optional=True)
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision"}),
                )
                job = scheduler.delete_job(
                    job_id,
                    actor_id=context.principal.actor_id,
                    expected_revision=body.get("expected_revision"),
                )
                self._json(HTTPStatus.OK, {"job": job, "deleted": True})
                return True
            if action == "run" and method == "POST":
                if not self._require(context, "write"):
                    return True
                body = self._body(optional=True)
                self._reject_unknown_fields(
                    body,
                    frozenset({"client_request_id"}),
                )
                flow = scheduler.run_now(
                    job_id,
                    actor_id=context.principal.actor_id,
                    client_request_id=body.get("client_request_id"),
                )
                job = scheduler.get_job(
                    job_id,
                    actor_id=context.principal.actor_id,
                )
                self._json(
                    HTTPStatus.ACCEPTED,
                    {"flow": flow, "job": job},
                )
                return True
            self._method_not_allowed(
                ("GET", "PATCH", "DELETE") if action is None else ("POST",)
            )
            return True

        if path == "/api/v1/agent/events":
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                limit, _ = self._pagination(
                    allowed=frozenset({"limit"}),
                    default_limit=20,
                    maximum_limit=100,
                    allow_offset=False,
                )
                items = scheduler.list_trigger_events(
                    actor_id=context.principal.actor_id,
                    limit=limit,
                )
                self._json(
                    HTTPStatus.OK,
                    {"events": items, "items": items, "count": len(items)},
                )
                return True
            if method == "POST":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset(
                        {
                            "event_type",
                            "client_event_id",
                            "draft_id",
                            "payload",
                        }
                    ),
                )
                event = scheduler.emit_event(
                    actor_id=context.principal.actor_id,
                    event_type=body.get("event_type"),
                    client_event_id=body.get("client_event_id"),
                    draft_id=body.get("draft_id"),
                    payload=body.get("payload"),
                )
                self._json(HTTPStatus.ACCEPTED, {"event": event})
                return True
            self._method_not_allowed(("GET", "POST"))
            return True

        access = self._governance_access(context)
        governance = service.governance

        if path == "/api/v1/agent/memory/proposals":
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                limit, offset = self._pagination(
                    allowed=frozenset({"limit", "offset", "status", "scope_type"}),
                    default_limit=100,
                    maximum_limit=200,
                    allow_offset=True,
                )
                query = parse_qs(
                    urlsplit(self.path).query,
                    keep_blank_values=True,
                )
                items = governance.list_memory_proposals(
                    access,
                    status=query.get("status", [None])[0] or None,
                    scope_type=query.get("scope_type", [None])[0] or None,
                    limit=limit,
                    offset=offset,
                )
                self._json(
                    HTTPStatus.OK,
                    {
                        "proposals": items,
                        "items": items,
                        "count": len(items),
                    },
                )
                return True
            if method == "POST":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset(
                        {
                            "scope_type",
                            "scope_id",
                            "key",
                            "memory_key",
                            "value",
                            "source_refs",
                            "reason",
                        }
                    ),
                )
                scope_type = body.get("scope_type", "user")
                scope_id = body.get("scope_id")
                if scope_type == "user" and not scope_id:
                    scope_id = context.principal.actor_id
                refs = body.get("source_refs")
                if not refs:
                    refs = [
                        {
                            "source_type": (
                                "draft" if scope_type == "draft" else "user_input"
                            ),
                            "source_id": (
                                scope_id
                                if scope_type == "draft"
                                else context.principal.actor_id
                            ),
                            "label": "企业端人工发起的受治理记忆提案",
                        }
                    ]
                proposal = governance.create_memory_proposal(
                    access,
                    scope_type=scope_type,
                    scope_id=scope_id,
                    memory_key=body.get("memory_key", body.get("key")),
                    value=body.get("value"),
                    source_refs=refs,
                    reason=body.get("reason"),
                )
                self._json(
                    HTTPStatus.CREATED,
                    {"proposal": proposal},
                )
                return True
            self._method_not_allowed(("GET", "POST"))
            return True

        memory_proposal_match = _MEMORY_PROPOSAL_ROUTE.fullmatch(path)
        if memory_proposal_match:
            proposal_id = unquote(memory_proposal_match.group(1))
            action = memory_proposal_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(
                    HTTPStatus.OK,
                    {
                        "proposal": governance.get_memory_proposal(
                            access,
                            proposal_id,
                        )
                    },
                )
                return True
            if action == "decision" and method == "POST":
                if not self._require(context, "governance_review"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset({"decision", "expected_revision", "reason"}),
                )
                result = governance.decide_memory_proposal(
                    access,
                    proposal_id,
                    decision=body.get("decision"),
                    expected_revision=body.get("expected_revision"),
                    reason=body.get("reason"),
                )
                self._json(HTTPStatus.OK, result)
                return True
            self._method_not_allowed(("GET",) if action is None else ("POST",))
            return True

        if path == "/api/v1/agent/memories":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return True
            if not self._require(context, "read"):
                return True
            limit, offset = self._pagination(
                allowed=frozenset({"limit", "offset", "status", "scope_type"}),
                default_limit=100,
                maximum_limit=200,
                allow_offset=True,
            )
            query = parse_qs(
                urlsplit(self.path).query,
                keep_blank_values=True,
            )
            items = governance.list_memories(
                access,
                status=query.get("status", ["active"])[0] or None,
                scope_type=query.get("scope_type", [None])[0] or None,
                limit=limit,
                offset=offset,
            )
            self._json(
                HTTPStatus.OK,
                {"memories": items, "items": items, "count": len(items)},
            )
            return True

        memory_match = _MEMORY_ROUTE.fullmatch(path)
        if memory_match:
            memory_id = unquote(memory_match.group(1))
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(
                    HTTPStatus.OK,
                    {"memory": governance.get_memory(access, memory_id)},
                )
                return True
            if method == "DELETE":
                if not self._require(context, "governance_review"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision", "reason"}),
                )
                memory = governance.revoke_memory(
                    access,
                    memory_id,
                    expected_revision=body.get("expected_revision"),
                    reason=body.get("reason"),
                )
                self._json(HTTPStatus.OK, {"memory": memory})
                return True
            self._method_not_allowed(("GET", "DELETE"))
            return True

        if path == "/api/v1/agent/skill-proposals":
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                limit, offset = self._pagination(
                    allowed=frozenset({"limit", "offset", "status"}),
                    default_limit=100,
                    maximum_limit=200,
                    allow_offset=True,
                )
                query = parse_qs(
                    urlsplit(self.path).query,
                    keep_blank_values=True,
                )
                items = governance.list_skill_proposals(
                    access,
                    status=query.get("status", [None])[0] or None,
                    limit=limit,
                    offset=offset,
                )
                self._json(
                    HTTPStatus.OK,
                    {
                        "proposals": items,
                        "items": items,
                        "count": len(items),
                    },
                )
                return True
            if method == "POST":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset(
                        {
                            "skill_name",
                            "description",
                            "procedure",
                            "allowed_tools",
                            "source_refs",
                            "reason",
                        }
                    ),
                )
                procedure = body.get("procedure")
                if isinstance(procedure, str):
                    procedure = [
                        line.strip() for line in procedure.splitlines() if line.strip()
                    ]
                refs = body.get("source_refs")
                if not refs:
                    refs = [
                        {
                            "source_type": "user_input",
                            "source_id": context.principal.actor_id,
                            "label": "企业端人工发起的受治理技能提案",
                        }
                    ]
                proposal = governance.create_skill_proposal(
                    access,
                    skill_name=body.get("skill_name"),
                    description=body.get("description"),
                    procedure=procedure,
                    allowed_tools=body.get("allowed_tools")
                    or ["draft_summary", "deterministic_preflight"],
                    source_refs=refs,
                    reason=body.get("reason") or "由企业人员提议，待另一名复核人员审批",
                )
                self._json(
                    HTTPStatus.CREATED,
                    {"proposal": proposal},
                )
                return True
            self._method_not_allowed(("GET", "POST"))
            return True

        skill_proposal_match = _SKILL_PROPOSAL_ROUTE.fullmatch(path)
        if skill_proposal_match:
            proposal_id = unquote(skill_proposal_match.group(1))
            action = skill_proposal_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(
                    HTTPStatus.OK,
                    {
                        "proposal": governance.get_skill_proposal(
                            access,
                            proposal_id,
                        )
                    },
                )
                return True
            if action == "decision" and method == "POST":
                if not self._require(context, "skill_admin"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset({"decision", "expected_revision", "reason"}),
                )
                result = governance.decide_skill_proposal(
                    access,
                    proposal_id,
                    decision=body.get("decision"),
                    expected_revision=body.get("expected_revision"),
                    reason=body.get("reason"),
                )
                self._json(HTTPStatus.OK, result)
                return True
            self._method_not_allowed(("GET",) if action is None else ("POST",))
            return True

        if path == "/api/v1/agent/skill-versions":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return True
            if not self._require(context, "read"):
                return True
            limit, offset = self._pagination(
                allowed=frozenset({"limit", "offset", "status", "skill_name"}),
                default_limit=100,
                maximum_limit=200,
                allow_offset=True,
            )
            query = parse_qs(
                urlsplit(self.path).query,
                keep_blank_values=True,
            )
            status_filter = query.get("status", ["active"])[0]
            items = governance.list_skill_versions(
                access,
                status=status_filter or None,
                skill_name=query.get("skill_name", [None])[0] or None,
                limit=limit,
                offset=offset,
            )
            self._json(
                HTTPStatus.OK,
                {
                    "skill_versions": items,
                    "items": items,
                    "count": len(items),
                },
            )
            return True

        skill_version_match = _SKILL_VERSION_ROUTE.fullmatch(path)
        if skill_version_match:
            version_id = unquote(skill_version_match.group(1))
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(
                    HTTPStatus.OK,
                    {
                        "skill_version": governance.get_skill_version(
                            access,
                            version_id,
                        )
                    },
                )
                return True
            if method == "DELETE":
                if not self._require(context, "skill_admin"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision", "reason"}),
                )
                version = governance.retire_skill_version(
                    access,
                    version_id,
                    expected_revision=body.get("expected_revision"),
                    reason=body.get("reason"),
                )
                self._json(
                    HTTPStatus.OK,
                    {"skill_version": version},
                )
                return True
            self._method_not_allowed(("GET", "DELETE"))
            return True

        return False

    def _five_quantity_route(
        self,
        method: str,
        path: str,
        context: AuthContext,
    ) -> bool:
        """Narrow enterprise UI/API for the one-mine V2 workflow."""

        runtime = getattr(self.server.service, "_five_quantity", None)
        if runtime is None:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "five_quantity_v2_unavailable",
                "当前实例未配置五量 V2 运行时",
            )
            return True
        actor = context.principal.actor_id
        if path == "/api/v2/status":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return True
            if not self._require(context, "read"):
                return True
            self._json(
                HTTPStatus.OK,
                {
                    **runtime.status(),
                    "machine_connector_enabled": bool(
                        self.server.connector_clients
                    ),
                    "connector_client_count": len(
                        self.server.connector_clients
                    ),
                },
            )
            return True
        if path == "/api/v2/imports":
            if method == "GET":
                if not self._require(context, "read"):
                    return True
                include_discarded = self._boolean_query("include_discarded")
                items = runtime.store.list_imports(include_discarded=include_discarded)
                self._json(
                    HTTPStatus.OK,
                    {"items": items, "imports": items, "count": len(items)},
                )
                return True
            if method == "POST":
                if not self._require(context, "write"):
                    return True
                body = self._body(maximum=_MAX_IMPORT_BODY)
                self._reject_unknown_fields(
                    body,
                    frozenset({"filename", "content_base64"}),
                )
                encoded = body.get("content_base64")
                if not isinstance(encoded, str):
                    raise ValueError("content_base64 必须是字符串")
                try:
                    content = base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError) as error:
                    raise ValueError("content_base64 非法") from error
                result = runtime.ingest_bytes(
                    filename=body.get("filename"),
                    content=content,
                    acquisition_mode="manual_import",
                    actor=actor,
                )
                self._json(
                    HTTPStatus.OK if result.get("duplicate") else HTTPStatus.CREATED,
                    result,
                )
                return True
            self._method_not_allowed(("GET", "POST"))
            return True
        if path == "/api/v2/direct-ingest":
            if method != "POST":
                self._method_not_allowed(("POST",))
                return True
            if not self._require(context, "write"):
                return True
            body = self._body(maximum=_MAX_IMPORT_BODY)
            self._reject_unknown_fields(
                body,
                frozenset({"filename", "content_base64"}),
            )
            encoded = body.get("content_base64")
            if not isinstance(encoded, str):
                raise ValueError("content_base64 必须是字符串")
            try:
                content = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError("content_base64 非法") from error
            result = runtime.ingest_bytes(
                filename=body.get("filename"),
                content=content,
                acquisition_mode="direct_collection",
                actor=actor,
            )
            self._json(
                HTTPStatus.OK if result.get("duplicate") else HTTPStatus.CREATED,
                result,
            )
            return True
        if path == "/api/v2/watch/scan":
            if method != "POST":
                self._method_not_allowed(("POST",))
                return True
            if not self._require(context, "write"):
                return True
            self._body(optional=True)
            items = runtime.scan_watched_directories()
            self._json(HTTPStatus.OK, {"items": items, "count": len(items)})
            return True
        if path == "/api/v2/drafts":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return True
            if not self._require(context, "read"):
                return True
            include_discarded = self._boolean_query("include_discarded")
            items = runtime.store.list_drafts(include_discarded=include_discarded)
            self._json(
                HTTPStatus.OK,
                {"items": items, "drafts": items, "count": len(items)},
            )
            return True
        draft_match = _FQ_DRAFT_ROUTE.fullmatch(path)
        if draft_match:
            draft_id = unquote(draft_match.group(1))
            action = draft_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return True
                draft = runtime.store.get_draft(draft_id)
                draft["sync_state"] = runtime.machine_sync_state(draft_id)
                self._json(HTTPStatus.OK, draft)
                return True
            if action is None and method == "PATCH":
                if not self._require(context, "write"):
                    return True
                body = self._body(maximum=_MAX_IMPORT_BODY)
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision", "payload"}),
                )
                result = runtime.save_draft(
                    draft_id,
                    expected_revision=body.get("expected_revision"),
                    payload=body.get("payload"),
                    actor=actor,
                )
                self._json(HTTPStatus.OK, result)
                return True
            if action is None and method == "DELETE":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision", "reason"}),
                )
                result = runtime.discard_draft(
                    draft_id,
                    expected_revision=body.get("expected_revision"),
                    actor=actor,
                    reason=body.get("reason"),
                )
                self._json(
                    HTTPStatus.OK,
                    {"draft": result, "discarded": True},
                )
                return True
            if action == "ingestions" and method == "GET":
                if not self._require(context, "read"):
                    return True
                items = self.server.service.repository.connector_ingestions_for_draft(
                    draft_id
                )
                latest_preflight_item = next(
                    (
                        item
                        for item in items
                        if item.get("preflight") is not None
                    ),
                    None,
                )
                sync_state = runtime.machine_sync_state(draft_id)
                draft = runtime.store.get_draft(draft_id)
                current_payload_sha256 = sha256_jcs(draft["payload"])
                latest_preflight = (
                    dict(latest_preflight_item["preflight"])
                    if latest_preflight_item is not None
                    else None
                )
                if latest_preflight_item is not None:
                    internal = (
                        self.server.service.repository
                        .get_connector_ingestion(
                            latest_preflight_item["ingestion_id"]
                        )
                    )
                    stored = internal.get("workflow_result")
                    preflight_is_current = bool(
                        isinstance(stored, dict)
                        and stored.get("contract_version")
                        == "five-quantity-machine-preflight/v1"
                        and stored.get("bound_revision") == draft["revision"]
                        and stored.get("payload_sha256")
                        == current_payload_sha256
                    )
                    latest_preflight["obsolete"] = not preflight_is_current
                    if not preflight_is_current:
                        latest_preflight["status"] = "attention_required"
                        latest_preflight["warnings"] = [
                            *list(latest_preflight.get("warnings", [])),
                            "预检结果未绑定当前草稿修订版，请在确认时重新检查",
                        ][:20]
                elif sync_state is not None:
                    latest_preflight = {
                        "status": "attention_required",
                        "bound_revision": None,
                        "payload_sha256_prefix": "",
                        "missing_count": None,
                        "missing_day_count": None,
                        "calendar_coverage": None,
                        "arithmetic_mismatch_count": None,
                        "source_count": None,
                        "checked_at": None,
                        "warnings": [
                            "机器草稿缺少可绑定的确定性预检结果，确认时必须重新检查"
                        ],
                        "obsolete": True,
                    }
                health = runtime.machine_source_health(draft_id)
                if latest_preflight is not None:
                    latest_preflight = dict(latest_preflight)
                    latest_preflight["freshness"] = health["freshness"]
                    if health["freshness"]["overall_state"] != "fresh":
                        latest_preflight["status"] = "attention_required"
                        latest_preflight["warnings"] = [
                            *list(latest_preflight.get("warnings", [])),
                            "必需机器来源尚未新鲜且未与当前成功快照完全绑定",
                        ][:20]
                self._json(
                    HTTPStatus.OK,
                    {
                        "items": items,
                        "ingestions": items,
                        "count": len(items),
                        "latest_preflight": latest_preflight,
                        "sync_state": sync_state,
                        "source_health": health["source_health"],
                        "freshness": health["freshness"],
                    },
                )
                return True
            if action == "machine-resume" and method == "POST":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision", "accepted"}),
                )
                result = runtime.resume_machine_sync(
                    draft_id,
                    expected_revision=body.get("expected_revision"),
                    accepted=body.get("accepted") is True,
                    actor=actor,
                )
                self._json(
                    HTTPStatus.OK,
                    {
                        "draft": result,
                        "sync_state": runtime.machine_sync_state(draft_id),
                        "requires_new_event": True,
                    },
                )
                return True
            if action == "confirm" and method == "POST":
                if not self._require(context, "confirm"):
                    return True
                if not self._require(context, "submit"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset(
                        {
                            "expected_revision",
                            "confirmer_name",
                            "confirmer_role",
                            "attestation",
                            "accepted",
                        }
                    ),
                )
                result = runtime.confirm_draft(
                    draft_id,
                    expected_revision=body.get("expected_revision"),
                    actor_id=actor,
                    confirmer_name=body.get("confirmer_name"),
                    confirmer_role=body.get("confirmer_role"),
                    attestation=body.get("attestation"),
                    accepted=body.get("accepted") is True,
                )
                self._json(HTTPStatus.ACCEPTED, result)
                return True
            if action == "send-now" and method == "POST":
                if not self._require(context, "submit"):
                    return True
                self._body(optional=True)
                result = runtime.process_outbox_once()
                self._json(HTTPStatus.OK, {"items": result, "count": len(result)})
                return True
            self._method_not_allowed(
                ("GET", "PATCH", "DELETE")
                if action is None
                else ("GET",)
                if action == "ingestions"
                else ("POST",)
            )
            return True
        if path == "/api/v2/risks":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return True
            if not self._require(context, "read"):
                return True
            items = runtime.store.list_reports()
            self._json(
                HTTPStatus.OK,
                {"items": items, "risks": items, "count": len(items)},
            )
            return True
        if path == "/api/v2/risks/poll":
            if method != "POST":
                self._method_not_allowed(("POST",))
                return True
            if not self._require(context, "read"):
                return True
            self._body(optional=True)
            result = runtime.poll_analysis_once()
            self._json(HTTPStatus.OK, {"result": result})
            return True
        risk_match = _FQ_RISK_ROUTE.fullmatch(path)
        if risk_match:
            report_id = unquote(risk_match.group(1))
            action = risk_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(HTTPStatus.OK, runtime.store.get_report(report_id))
                return True
            if action == "chat" and method == "GET":
                if not self._require(context, "read"):
                    return True
                items = runtime.store.chat_messages(report_id)
                self._json(
                    HTTPStatus.OK,
                    {"items": items, "messages": items, "count": len(items)},
                )
                return True
            if action == "chat" and method == "POST":
                if not self._require(context, "read"):
                    return True
                body = self._body()
                self._reject_unknown_fields(body, frozenset({"question"}))
                self._json(
                    HTTPStatus.OK,
                    runtime.risk_explanation(
                        report_id, body.get("question"), actor=actor
                    ),
                )
                return True
            if action == "response" and method == "POST":
                if not self._require(context, "write"):
                    return True
                self._body(optional=True)
                self._json(
                    HTTPStatus.CREATED,
                    runtime.store.create_response(report_id, actor=actor),
                )
                return True
            self._method_not_allowed(("GET",) if action is None else ("GET", "POST"))
            return True
        response_match = _FQ_RESPONSE_ROUTE.fullmatch(path)
        if response_match:
            response_id = unquote(response_match.group(1))
            action = response_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return True
                self._json(HTTPStatus.OK, runtime.store.get_response(response_id))
                return True
            if action is None and method == "PATCH":
                if not self._require(context, "write"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset({"expected_revision", "document"}),
                )
                self._json(
                    HTTPStatus.OK,
                    runtime.save_response(
                        response_id,
                        expected_revision=body.get("expected_revision"),
                        document=body.get("document"),
                        actor=actor,
                    ),
                )
                return True
            if action == "confirm" and method == "POST":
                if not self._require(context, "confirm"):
                    return True
                if not self._require(context, "submit"):
                    return True
                body = self._body()
                self._reject_unknown_fields(
                    body,
                    frozenset(
                        {
                            "expected_revision",
                            "confirmer_name",
                            "confirmer_role",
                            "attestation",
                            "accepted",
                        }
                    ),
                )
                self._json(
                    HTTPStatus.ACCEPTED,
                    runtime.confirm_response(
                        response_id,
                        expected_revision=body.get("expected_revision"),
                        actor_id=actor,
                        confirmer_name=body.get("confirmer_name"),
                        confirmer_role=body.get("confirmer_role"),
                        attestation=body.get("attestation"),
                        accepted=body.get("accepted") is True,
                    ),
                )
                return True
            self._method_not_allowed(("GET", "PATCH") if action is None else ("POST",))
            return True
        if path == "/api/v2/exchange/run":
            if method != "POST":
                self._method_not_allowed(("POST",))
                return True
            if not self._require(context, "submit"):
                return True
            self._body(optional=True)
            delivered = runtime.process_outbox_once()
            pulled = runtime.poll_analysis_once()
            self._json(HTTPStatus.OK, {"delivered": delivered, "pulled": pulled})
            return True
        if path == "/api/v2/audit":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return True
            if not self._require(context, "read"):
                return True
            self._json(HTTPStatus.OK, runtime.store.audit())
            return True
        return False

    def _dispatch(self, method: str) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == AUTOFILL_PATH:
            self._machine_autofill_route(method)
            return
        if path == SOURCE_HEALTH_PATH:
            self._machine_source_health_route(method)
            return
        if path == "/api/v1/health" and method == "GET":
            llm_configured = self.server.service.llm_provider is not None
            agent_v2_runtime = getattr(
                self.server.service,
                "_agent_v2",
                None,
            )
            skills = getattr(self.server.service, "skills", None)
            skill_available = getattr(skills, "available", None)
            news_available = (
                bool(skill_available("coal-news-search"))
                if callable(skill_available)
                else False
            )
            skill_get = getattr(skills, "get", None)
            news_skill = skill_get("coal-news-search") if callable(skill_get) else None
            news_definition = (
                news_skill.public_definition() if news_skill is not None else {}
            )
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "enterprise-reporting-agent",
                    "version": __version__,
                    "contract_version": "enterprise-submission-v1",
                    "llm_mode": ("configured" if llm_configured else "rules"),
                    "llm_configured": llm_configured,
                    "llm_connection_status": (
                        "configured_unverified" if llm_configured else "not_configured"
                    ),
                    "news_search_available": news_available,
                    "news_search_status": (
                        str(
                            news_definition.get(
                                "runtime_status",
                                "configured_unverified",
                            )
                        )
                        if news_available
                        else "disabled"
                    ),
                    "news_search_providers": (
                        news_definition.get("providers", []) if news_available else []
                    ),
                    "news_search_last_checked_at": (
                        news_definition.get("last_checked_at")
                        if news_available
                        else None
                    ),
                    "news_search_last_provider": (
                        news_definition.get("last_provider") if news_available else None
                    ),
                    "news_ai_summary_configured": llm_configured,
                    "news_ai_summary_status": (
                        "configured_unverified" if llm_configured else "not_configured"
                    ),
                    "news_ai_summary_grounding": "search_title_and_snippet",
                    "platform_configured": (
                        self.server.service.platform_client is not None
                        or getattr(self.server.service, "_five_quantity", None)
                        is not None
                        and getattr(
                            self.server.service._five_quantity,
                            "platform_client",
                            None,
                        )
                        is not None
                    ),
                    "primary_contract_version": "five-quantity-submission-v2",
                    "five_quantity_v2_available": getattr(
                        self.server.service, "_five_quantity", None
                    )
                    is not None,
                    "five_quantity_v2_status": (
                        self.server.service._five_quantity.status()
                        if getattr(self.server.service, "_five_quantity", None)
                        is not None
                        else None
                    ),
                    "authentication_mode": (
                        "anonymous_loopback"
                        if self.server.auth_manager.allow_anonymous_local
                        else "temporary_demo"
                        if self.server.auth_manager.has_temporary_accounts
                        else "configured_accounts"
                    ),
                    "demo_account_enabled": (
                        self.server.auth_manager.has_temporary_accounts
                    ),
                    "harness_available": hasattr(self.server.service, "harness"),
                    "harness_version": getattr(
                        getattr(self.server.service, "harness", None),
                        "version",
                        None,
                    ),
                    "tool_calling_mode": getattr(
                        getattr(self.server.service, "harness", None),
                        "tool_calling_mode",
                        "unavailable",
                    ),
                    "coal_chat_available": getattr(self.server.service, "_chat", None)
                    is not None,
                    "agent_v2_available": getattr(
                        self.server.service,
                        "_agent_v2",
                        None,
                    )
                    is not None,
                    "agent_v2_version": getattr(
                        agent_v2_runtime,
                        "version",
                        None,
                    ),
                    "agent_v2_workflows": (
                        agent_v2_runtime.public_workflows()
                        if agent_v2_runtime is not None
                        else []
                    ),
                    "agent_v2_scheduler_enabled": bool(
                        getattr(
                            getattr(
                                self.server.service,
                                "agent_v2_config",
                                None,
                            ),
                            "scheduler_enabled",
                            False,
                        )
                        and getattr(
                            self.server.service,
                            "_agent_jobs",
                            None,
                        )
                        is not None
                    ),
                    "agent_v2_governed_learning": "proposal_approval_only",
                    "machine_autofill_available": bool(
                        self.server.connector_clients
                    ),
                    "machine_autofill_contract_version": (
                        "enterprise-autofill-ingestion/v1"
                    ),
                },
            )
            return
        if path == "/api/v1/auth/login":
            if method != "POST":
                self._method_not_allowed(("POST",))
                return
            if not self._origin_is_same():
                self._error(
                    HTTPStatus.FORBIDDEN,
                    "cross_origin_request_denied",
                    "仅允许同源页面登录",
                )
                return
            body = self._body()
            try:
                login = self.server.auth_manager.login(
                    body.get("actor_id", ""),
                    body.get("password", ""),
                    remote_address=self.client_address[0],
                )
            except AuthenticationFailed:
                self._error(
                    HTTPStatus.UNAUTHORIZED,
                    "invalid_credentials",
                    "账号或密码错误",
                )
                return
            except LoginThrottled as error:
                self._error(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "login_throttled",
                    str(error),
                )
                return
            token = login.context.session_token
            assert token is not None
            self._json(
                HTTPStatus.OK,
                self._session_payload(login.context),
                headers=(("Set-Cookie", self._cookie(token, login.max_age)),),
            )
            return
        if path.startswith("/api/"):
            context = self._authenticate()
            if context is None:
                return
            if method in {"POST", "PATCH", "DELETE"} and not self._protect_mutation(
                context
            ):
                return
        else:
            context = None
        if path.startswith("/api/v2/"):
            assert context is not None
            if self._five_quantity_route(method, path, context):
                return
            self._error(HTTPStatus.NOT_FOUND, "not_found", "V2 接口不存在")
            return
        if path == "/api/v1/platform-status":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return
            assert context is not None
            if not self._require(context, "read"):
                return
            self._json(HTTPStatus.OK, self.server.service.platform_status())
            return
        if path == "/api/v1/auth/me":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return
            assert context is not None
            self._json(HTTPStatus.OK, self._session_payload(context))
            return
        if path == "/api/v1/auth/logout":
            if method != "POST":
                self._method_not_allowed(("POST",))
                return
            assert context is not None
            self._body(optional=True)
            self.server.auth_manager.logout(context.session_token)
            self._json(
                HTTPStatus.OK,
                {"authenticated": False},
                headers=(("Set-Cookie", self._cookie("", 0)),),
            )
            return
        if (
            path.startswith("/api/v1/agent/")
            and getattr(self.server.service, "_harness", None) is None
        ):
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "harness_unavailable",
                "当前服务实例未启用智能体运行时",
            )
            return
        if (
            _is_agent_v2_path(path)
            and getattr(self.server.service, "_agent_v2", None) is None
        ):
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "agent_v2_unavailable",
                "当前服务未启用耐久煤炭智能体任务流",
            )
            return
        if _is_agent_v2_path(path):
            assert context is not None
            if self._agent_v2_route(method, path, context):
                return
        if (
            path.startswith("/api/v1/chat/")
            and getattr(self.server.service, "_chat", None) is None
        ):
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "coal_chat_unavailable",
                "当前服务实例未启用煤炭对话运行时",
            )
            return
        if path == "/api/v1/chat/sessions":
            assert context is not None
            chat = self.server.service.chat
            if method == "GET":
                if not self._require(context, "read"):
                    return
                limit, offset = self._pagination(
                    allowed=frozenset({"limit", "offset"}),
                    default_limit=20,
                    maximum_limit=100,
                    allow_offset=True,
                )
                items, total = chat.list_sessions(
                    actor_id=context.principal.actor_id,
                    limit=limit,
                    offset=offset,
                )
                next_offset = offset + len(items)
                self._json(
                    HTTPStatus.OK,
                    {
                        "sessions": items,
                        "items": items,
                        "count": len(items),
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "has_more": next_offset < total,
                        "next_offset": (next_offset if next_offset < total else None),
                    },
                )
                return
            if method == "POST":
                if not self._require(context, "read"):
                    return
                body = self._body(optional=True)
                unknown = set(body) - {
                    "title",
                    "draft_id",
                    "client_request_id",
                }
                if unknown:
                    raise ValueError("不支持的字段：" + ", ".join(sorted(unknown)))
                result = chat.create_session(
                    actor_id=context.principal.actor_id,
                    title=body.get("title"),
                    draft_id=body.get("draft_id"),
                    client_request_id=body.get("client_request_id"),
                )
                self._json(HTTPStatus.CREATED, result)
                return
            self._method_not_allowed(("GET", "POST"))
            return
        chat_match = _CHAT_SESSION_ROUTE.fullmatch(path)
        if chat_match:
            assert context is not None
            chat = self.server.service.chat
            session_id = unquote(chat_match.group(1))
            action = chat_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return
                self._json(
                    HTTPStatus.OK,
                    chat.get_session(
                        session_id,
                        actor_id=context.principal.actor_id,
                    ),
                )
                return
            if action is None and method == "DELETE":
                if not self._require(context, "read"):
                    return
                self._json(
                    HTTPStatus.OK,
                    {
                        "session": chat.delete_session(
                            session_id,
                            actor_id=context.principal.actor_id,
                        )
                    },
                )
                return
            if action == "messages" and method == "POST":
                if not self._require(context, "read"):
                    return
                body = self._body()
                unknown = set(body) - {
                    "content",
                    "draft_id",
                    "client_message_id",
                }
                if unknown:
                    raise ValueError("不支持的字段：" + ", ".join(sorted(unknown)))
                result = chat.post_message(
                    session_id,
                    actor_id=context.principal.actor_id,
                    content=body.get("content"),
                    draft_id=body.get("draft_id"),
                    client_message_id=body.get("client_message_id"),
                )
                self._json(HTTPStatus.ACCEPTED, result)
                return
            self._method_not_allowed(("GET", "DELETE") if action is None else ("POST",))
            return
        if path == "/api/v1/agent/tools":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return
            assert context is not None
            if not self._require(context, "read"):
                return
            harness = self.server.service.harness
            tools = harness.public_tools()
            self._json(
                HTTPStatus.OK,
                {"tools": tools, "items": tools, "count": len(tools)},
            )
            return
        if path == "/api/v1/agent/skills":
            if method != "GET":
                self._method_not_allowed(("GET",))
                return
            assert context is not None
            if not self._require(context, "read"):
                return
            skills = self.server.service.skills.list_public()
            self._json(
                HTTPStatus.OK,
                {
                    "skills": skills,
                    "items": skills,
                    "count": len(skills),
                },
            )
            return
        if path == "/api/v1/agent/runs":
            assert context is not None
            harness = self.server.service.harness
            if method == "GET":
                if not self._require(context, "read"):
                    return
                limit, offset = self._pagination(
                    allowed=frozenset({"limit", "offset"}),
                    default_limit=20,
                    maximum_limit=100,
                    allow_offset=True,
                )
                items, total = harness.list(
                    actor_id=context.principal.actor_id,
                    limit=limit,
                    offset=offset,
                )
                next_offset = offset + len(items)
                self._json(
                    HTTPStatus.OK,
                    {
                        "runs": items,
                        "items": items,
                        "count": len(items),
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "has_more": next_offset < total,
                        "next_offset": (next_offset if next_offset < total else None),
                    },
                )
                return
            if method == "POST":
                if not self._require(context, "read"):
                    return
                body = self._body()
                run = harness.create(
                    actor_id=context.principal.actor_id,
                    task=body.get("task"),
                    draft_id=body.get("draft_id"),
                    mode=body.get("mode", "auto"),
                    allow_mutations=context.principal.allows("write"),
                )
                self._json(HTTPStatus.ACCEPTED, {"run": run})
                return
            self._method_not_allowed(("GET", "POST"))
            return
        agent_match = _AGENT_RUN_ROUTE.fullmatch(path)
        if agent_match:
            assert context is not None
            harness = self.server.service.harness
            run_id = unquote(agent_match.group(1))
            action = agent_match.group(2)
            if action is None and method == "GET":
                if not self._require(context, "read"):
                    return
                self._json(
                    HTTPStatus.OK,
                    {
                        "run": harness.get(
                            run_id,
                            actor_id=context.principal.actor_id,
                        )
                    },
                )
                return
            if action == "approve" and method == "POST":
                body = self._body()
                required_permission = (
                    "write" if body.get("decision") == "approve" else "read"
                )
                if not self._require(context, required_permission):
                    return
                run = harness.approve(
                    run_id,
                    approval_id=body.get("approval_id"),
                    decision=body.get("decision"),
                    actor_id=context.principal.actor_id,
                )
                self._json(HTTPStatus.ACCEPTED, {"run": run})
                return
            if action == "cancel" and method == "POST":
                if not self._require(context, "read"):
                    return
                self._body(optional=True)
                run = harness.cancel(
                    run_id,
                    actor_id=context.principal.actor_id,
                )
                self._json(HTTPStatus.OK, {"run": run})
                return
            self._method_not_allowed(("GET",) if action is None else ("POST",))
            return
        if path == "/api/v1/drafts":
            assert context is not None
            if method == "GET":
                if not self._require(context, "read"):
                    return
                limit, offset = self._pagination(
                    allowed=frozenset({"limit", "offset"}),
                    default_limit=50,
                    maximum_limit=200,
                    allow_offset=True,
                )
                items, total = self.server.service.list_drafts(
                    limit=limit,
                    offset=offset,
                )
                next_offset = offset + len(items)
                self._json(
                    HTTPStatus.OK,
                    {
                        "drafts": items,
                        "items": items,
                        "count": len(items),
                        "total": total,
                        "limit": limit,
                        "offset": offset,
                        "has_more": next_offset < total,
                        "next_offset": (next_offset if next_offset < total else None),
                    },
                )
                return
            if method == "POST":
                if not self._require(context, "write"):
                    return
                body = self._body(optional=True)
                values = body.get("draft", body.get("values"))
                if values is None:
                    values = {
                        key: value
                        for key, value in body.items()
                        if key
                        not in {
                            "actor",
                            "actor_id",
                            "name",
                            "role",
                            "permissions",
                            "expected_revision",
                        }
                    }
                created = self.server.service.create_draft(
                    values,
                    actor=context.principal.actor_id,
                )
                review_state = self.server.service.observation_review_state(
                    created["draft_id"],
                    actor=context.principal.actor_id,
                )
                self._json(
                    HTTPStatus.CREATED,
                    {
                        "draft": created,
                        "review_state": review_state,
                        **created,
                    },
                )
                return
            self._method_not_allowed(("GET", "POST"))
            return

        match = _DRAFT_ROUTE.fullmatch(path)
        if match:
            draft_id = unquote(match.group(1))
            action = match.group(2)
            assert context is not None
            self._draft_route(method, draft_id, action, context)
            return
        if path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "not_found", "接口不存在")
            return
        if method == "GET":
            self._static(path)
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found", "资源不存在")

    def _draft_route(
        self,
        method: str,
        draft_id: str,
        action: str | None,
        context: AuthContext,
    ) -> None:
        service = self.server.service
        if action is None:
            if method == "GET":
                if not self._require(context, "read"):
                    return
                draft = service.get_draft(draft_id)
                review_state = service.observation_review_state(
                    draft_id,
                    actor=context.principal.actor_id,
                )
                self._json(
                    HTTPStatus.OK,
                    {"draft": draft, "review_state": review_state, **draft},
                )
                return
            if method == "PATCH":
                if not self._require(context, "write"):
                    return
                body = self._body()
                patch = body.get("patch")
                if patch is None:
                    patch = {
                        key: value
                        for key, value in body.items()
                        if key
                        not in {
                            "actor",
                            "actor_id",
                            "name",
                            "role",
                            "permissions",
                            "expected_revision",
                        }
                    }
                updated = service.patch_draft(
                    draft_id,
                    patch,
                    actor=context.principal.actor_id,
                    expected_revision=body.get("expected_revision"),
                )
                review_state = service.observation_review_state(
                    draft_id,
                    actor=context.principal.actor_id,
                )
                self._json(
                    HTTPStatus.OK,
                    {
                        "draft": updated,
                        "review_state": review_state,
                        **updated,
                    },
                )
                return
            if method == "DELETE":
                if not self._require(context, "write"):
                    return
                body = self._body(optional=True)
                query = parse_qs(urlsplit(self.path).query)
                revision: Any = body.get("expected_revision")
                if revision is None and query.get("expected_revision"):
                    try:
                        revision = int(query["expected_revision"][0])
                    except ValueError as error:
                        raise ValueError("expected_revision 必须是整数") from error
                service.delete_draft(
                    draft_id,
                    actor=context.principal.actor_id,
                    expected_revision=revision,
                )
                self._json(HTTPStatus.OK, {"deleted": True})
                return
            self._method_not_allowed(("GET", "PATCH", "DELETE"))
            return
        if action == "questions" and method == "GET":
            if not self._require(context, "read"):
                return
            questions = service.questions(draft_id)
            self._json(
                HTTPStatus.OK,
                {"questions": questions, "count": len(questions)},
            )
            return
        if action == "validate" and method == "POST":
            if not self._require(context, "read"):
                return
            self._body(optional=True)
            result = service.validate(draft_id)
            result["review_state"] = service.observation_review_state(
                draft_id,
                actor=context.principal.actor_id,
            )
            self._json(HTTPStatus.OK, result)
            return
        if action == "reviews":
            if method == "GET":
                if not self._require(context, "read"):
                    return
                self._json(
                    HTTPStatus.OK,
                    {
                        "review_state": service.observation_review_state(
                            draft_id,
                            actor=context.principal.actor_id,
                        )
                    },
                )
                return
            if method == "POST":
                if not self._require(context, "confirm"):
                    return
                body = self._body()
                observation_ids = body.get("observation_ids")
                if observation_ids is None and "observation_id" in body:
                    observation_ids = [body.get("observation_id")]
                review_state = service.review_observations(
                    draft_id,
                    observation_ids=observation_ids,
                    reviewed=body.get("reviewed"),
                    actor=context.principal.actor_id,
                    expected_revision=body.get("expected_revision"),
                )
                self._json(
                    HTTPStatus.OK,
                    {"review_state": review_state},
                )
                return
            self._method_not_allowed(("GET", "POST"))
            return
        if action == "import" and method == "POST":
            if not self._require(context, "write"):
                return
            body = self._body()
            result = service.import_into_draft(
                draft_id,
                format_name=body.get("format", ""),
                content=body.get("content", ""),
                source_name=body.get("source_name"),
                actor=context.principal.actor_id,
                expected_revision=body.get("expected_revision"),
                source_system=body.get("source_system"),
                original_filename=body.get("original_filename"),
                truth_statement=body.get("truth_statement"),
            )
            result["review_state"] = service.observation_review_state(
                draft_id,
                actor=context.principal.actor_id,
            )
            self._json(HTTPStatus.OK, result)
            return
        if action == "event-snapshot" and method == "POST":
            if not self._require(context, "write"):
                return
            body = self._body()
            snapshot = body.get("snapshot")
            if snapshot is None:
                snapshot = {
                    key: value
                    for key, value in body.items()
                    if key != "expected_revision"
                }
            result = service.import_event_snapshot(
                draft_id,
                snapshot=snapshot,
                actor=context.principal.actor_id,
                expected_revision=body.get("expected_revision"),
            )
            result["review_state"] = service.observation_review_state(
                draft_id,
                actor=context.principal.actor_id,
            )
            self._json(HTTPStatus.OK, result)
            return
        if action == "assist" and method == "POST":
            if not self._require(context, "write"):
                return
            body = self._body(optional=True)
            result = service.assist(
                draft_id,
                content=body.get("content", ""),
                format_name=body.get("format", "text"),
                actor=context.principal.actor_id,
                expected_revision=body.get("expected_revision"),
            )
            result["review_state"] = service.observation_review_state(
                draft_id,
                actor=context.principal.actor_id,
            )
            self._json(HTTPStatus.OK, result)
            return
        if action == "confirm" and method == "POST":
            if not self._require(context, "confirm"):
                return
            body = self._body()
            confirmation = body.get("confirmation")
            if isinstance(confirmation, dict):
                values = {**body, **confirmation}
            else:
                values = body
            requested_method = values.get("confirmation_method") or values.get(
                "method",
                "authenticated_click",
            )
            if requested_method not in {"account", "authenticated_click"}:
                raise ValueError(
                    "内置企业端只能执行登录账号点击确认；数字签名或企业章"
                    "必须接入可验证的外部证明适配器"
                )
            result = service.confirm(
                draft_id,
                actor=context.principal.actor_id,
                confirmer_name=context.principal.name,
                confirmer_role=context.principal.role,
                accepted=values.get("accepted", False),
                attestation=values.get("attestation") or values.get("statement", ""),
                expected_revision=values.get("expected_revision"),
                confirmation_method="authenticated_click",
            )
            review_state = service.observation_review_state(
                draft_id,
                actor=context.principal.actor_id,
            )
            self._json(
                HTTPStatus.OK,
                {
                    "draft": result,
                    "review_state": review_state,
                    **result,
                },
            )
            return
        if action == "submit" and method == "POST":
            if not self._require(context, "submit"):
                return
            body = self._body(optional=True)
            result = service.submit(
                draft_id,
                idempotency_key=body.get("idempotency_key"),
                actor=context.principal.actor_id,
            )
            # The service/CLI retain the immutable request for local recovery,
            # but the browser only needs status, digest, timestamps and the
            # receipt. Do not echo the complete governed envelope.
            public_result = {
                key: value for key, value in result.items() if key != "request"
            }
            self._json(
                HTTPStatus.OK,
                {"submission": public_result, **public_result},
            )
            return
        if action == "audit" and method == "GET":
            if not self._require(context, "read"):
                return
            limit, _ = self._pagination(
                allowed=frozenset({"limit"}),
                default_limit=100,
                maximum_limit=500,
                allow_offset=False,
            )
            integrity = service.repository.verify_audit(draft_id)
            events = service.repository.recent_audit_events(
                draft_id,
                limit=limit,
            )
            self._json(
                HTTPStatus.OK,
                {
                    "events": events,
                    "count": len(events),
                    "total": integrity["event_count"],
                    "limit": limit,
                    "truncated": len(events) < integrity["event_count"],
                    "integrity": integrity,
                },
            )
            return
        if action == "submissions" and method == "GET":
            if not self._require(context, "read"):
                return
            items = service.repository.submission_summaries_for_draft(draft_id)
            self._json(
                HTTPStatus.OK,
                {"submissions": items, "count": len(items)},
            )
            return
        self._method_not_allowed(
            ("POST",)
            if action not in {"questions", "reviews", "audit", "submissions"}
            else ("GET",)
        )

    def _method_not_allowed(self, allowed: tuple[str, ...]) -> None:
        self.close_connection = True
        self._json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {
                "error": {
                    "code": "method_not_allowed",
                    "message": "请求方法不允许",
                }
            },
            headers=(
                ("Allow", ", ".join(allowed)),
                ("Connection", "close"),
            ),
        )

    def _static(self, path: str) -> None:
        root = self.server.web_root
        if root is None or not root.is_dir():
            self._error(
                HTTPStatus.NOT_FOUND,
                "frontend_unavailable",
                "未安装前端静态资源",
            )
            return
        relative = "index.html" if path == "/" else unquote(path.lstrip("/"))
        candidate = (root / relative).resolve()
        resolved_root = root.resolve()
        if candidate != resolved_root and resolved_root not in candidate.parents:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "资源不存在")
            return
        if not candidate.is_file():
            # SPA fallback only for extension-less frontend routes.
            if "." not in Path(relative).name:
                candidate = resolved_root / "index.html"
            if not candidate.is_file():
                self._error(HTTPStatus.NOT_FOUND, "not_found", "资源不存在")
                return
        body = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or (
            "application/octet-stream"
        )
        if content_type.startswith("text/"):
            content_type += "; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; connect-src 'self'; "
            "base-uri 'none'; frame-ancestors 'none'; object-src 'none'; "
            "form-action 'self'",
        )
        self.end_headers()
        self._write_body(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        self._safe_dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._safe_dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._safe_dispatch("POST")

    def do_PATCH(self) -> None:  # noqa: N802
        self._safe_dispatch("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._safe_dispatch("DELETE")

    def _safe_dispatch(self, method: str) -> None:
        try:
            self._dispatch(method)
        except AgentError as error:
            self._error(
                error.status,
                error.code,
                str(error),
                details=getattr(error, "details", None),
            )
        except (TypeError, ValueError) as error:
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", str(error))
        except Exception as error:
            # Fail closed without leaking stack traces or secret-bearing
            # transport exceptions to a browser.
            print(
                f"企业端接口内部错误（{type(error).__name__}）",
                file=sys.stderr,
            )
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "服务内部错误",
            )


def serve(
    service: EnterpriseAgentService,
    *,
    host: str,
    port: int,
    auth_manager: AuthManager | None = None,
    secure_cookie: bool = False,
    public_origin: str | None = None,
    web_root: str | Path | None = None,
    connector_clients: tuple[ConnectorClient, ...] = (),
    connector_max_clock_skew_seconds: int = 300,
    on_started: Callable[[EnterpriseAgentHTTPServer], None] | None = None,
) -> None:
    root = Path(web_root) if web_root is not None else None
    try:
        server = EnterpriseAgentHTTPServer(
            (host, port),
            service,
            auth_manager=auth_manager,
            secure_cookie=secure_cookie,
            public_origin=public_origin,
            web_root=root,
            connector_clients=connector_clients,
            connector_max_clock_skew_seconds=(
                connector_max_clock_skew_seconds
            ),
        )
    except KeyboardInterrupt:
        disable_harness = getattr(service, "disable_harness", None)
        if callable(disable_harness):
            disable_harness()
        return
    except OSError as error:
        if error.errno in {48, 98, 10048}:
            raise ValueError(
                f"端口 {port} 已被占用；请停止旧进程或使用 --port 更换端口"
            ) from error
        raise
    try:
        try:
            if on_started is not None:
                on_started(server)
            server.serve_forever()
        except KeyboardInterrupt:
            # Foreground operation is intentional; Ctrl-C is a normal clean
            # stop and must not frighten an operator with a Python traceback.
            return
    finally:
        try:
            server.server_close()
        finally:
            disable_harness = getattr(service, "disable_harness", None)
            if callable(disable_harness):
                disable_harness()
