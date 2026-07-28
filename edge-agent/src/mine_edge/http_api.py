"""Small dependency-free HTTP API and static operator console."""

from __future__ import annotations

import contextlib
import hmac
import json
import mimetypes
import sysconfig
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .errors import EdgeAgentError, ValidationError
from .models import AlertLevel, ObservationKind
from .scheduler import SourceManager
from .service import EdgeService
from .settings import Settings


def default_web_root() -> Path:
    candidates = (
        Path(__file__).resolve().parents[2] / "web",
        Path(sysconfig.get_path("data")) / "share" / "mine-edge-agent" / "web",
    )
    for candidate in candidates:
        if (candidate / "index.html").is_file():
            return candidate
    return candidates[-1]


class EdgeHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        service: EdgeService,
        settings: Settings,
        web_root: Path,
        source_manager: SourceManager | None = None,
    ) -> None:
        self.service = service
        self.settings = settings
        self.web_root = web_root.resolve()
        self.source_manager = source_manager
        super().__init__(address, EdgeRequestHandler)


class EdgeRequestHandler(BaseHTTPRequestHandler):
    server: EdgeHttpServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Keep standard access logging while avoiding accidental body/token logging.
        super().log_message(format, *args)

    def do_GET(self) -> None:  # noqa: N802
        path, query = self._route()
        try:
            if path == "/api/v1/health":
                health = self.server.service.health()
                sources = (
                    self.server.source_manager.snapshot()
                    if self.server.source_manager is not None
                    else _empty_source_status()
                )
                health["sources_summary"] = sources["summary"]
                health["source_heartbeat"] = sources["heartbeat"]
                if sources["summary"]["attention"] and health["status"] == "ok":
                    health["status"] = "degraded"
                self._json(HTTPStatus.OK, health)
                return
            if path.startswith("/api/"):
                self._require_auth()
            if path == "/api/v1/config":
                self._json(HTTPStatus.OK, self.server.settings.public_dict())
            elif path == "/api/v1/sources":
                sources = (
                    self.server.source_manager.snapshot()
                    if self.server.source_manager is not None
                    else _empty_source_status()
                )
                sources["configuration"] = (
                    self.server.source_manager.configured_sources()
                    if self.server.source_manager is not None
                    else []
                )
                self._json(HTTPStatus.OK, sources)
            elif path == "/api/v1/observations":
                kind = _single(query, "kind")
                if kind:
                    try:
                        ObservationKind(kind)
                    except ValueError as error:
                        raise ValidationError("kind 筛选值无效") from error
                self._json(
                    HTTPStatus.OK,
                    {
                        "items": self.server.service.repository.list_observations(
                            limit=_limit(query), kind=kind
                        )
                    },
                )
            elif path == "/api/v1/alerts":
                level = _single(query, "level")
                if level:
                    try:
                        AlertLevel(level)
                    except ValueError as error:
                        raise ValidationError("level 筛选值无效") from error
                self._json(
                    HTTPStatus.OK,
                    {
                        "items": self.server.service.repository.list_alerts(
                            limit=_limit(query), level=level
                        )
                    },
                )
            elif path == "/api/v1/outbox":
                status = _single(query, "status")
                if status not in {None, "pending", "delivered"}:
                    raise ValidationError("status 必须为 pending 或 delivered")
                self._json(
                    HTTPStatus.OK,
                    {
                        "items": self.server.service.repository.list_outbox(
                            limit=_limit(query), status=status
                        )
                    },
                )
            elif path.startswith("/api/"):
                self._not_found()
            else:
                self._static(path)
        except ValidationError as error:
            self._problem(HTTPStatus.BAD_REQUEST, "invalid_request", str(error))
        except PermissionError as error:
            self._problem(HTTPStatus.UNAUTHORIZED, "unauthorized", str(error))
        except EdgeAgentError as error:
            self._problem(HTTPStatus.UNPROCESSABLE_ENTITY, "edge_agent_error", str(error))
        except Exception:
            self._problem(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "服务处理失败；详情已写入服务日志",
            )
            raise

    def do_POST(self) -> None:  # noqa: N802
        path, _query = self._route()
        try:
            self._require_auth()
            if path == "/api/v1/ingest":
                body = self._read_json()
                if not isinstance(body, dict):
                    raise ValidationError("请求顶层必须是对象")
                source_id = str(body.get("source_id") or "http-ingest").strip()
                raw_values = body.get("observations")
                if raw_values is None:
                    raw_values = [body]
                if not isinstance(raw_values, list) or not all(
                    isinstance(item, dict) for item in raw_values
                ):
                    raise ValidationError("observations 必须是对象数组")
                results = self.server.service.ingest_many(
                    raw_values,
                    channel="http_ingest",
                    source_id=source_id,
                )
                inserted = sum(item.inserted for item in results)
                self._json(
                    HTTPStatus.ACCEPTED,
                    {
                        "accepted": len(results),
                        "inserted": inserted,
                        "duplicates": len(results) - inserted,
                        "results": [item.to_dict() for item in results],
                    },
                )
            elif path == "/api/v1/ingest/manual":
                body = self._read_json()
                if not isinstance(body, dict):
                    raise ValidationError("人工补录顶层必须是对象")
                result = self.server.service.ingest_manual(body)
                self._json(HTTPStatus.CREATED, result.to_dict())
            elif path == "/api/v1/outbox/flush":
                body = self._read_json(allow_empty=True)
                if body is None:
                    body = {}
                if not isinstance(body, dict):
                    raise ValidationError("请求顶层必须是对象")
                try:
                    max_batches = int(body.get("max_batches", 20))
                except (TypeError, ValueError) as error:
                    raise ValidationError("max_batches 必须是整数") from error
                results = self.server.service.forwarder.flush(max_batches=max_batches)
                self._json(
                    HTTPStatus.OK,
                    {"results": [item.to_dict() for item in results]},
                )
            elif (source_action := _source_action(path)) is not None:
                body = self._read_json(allow_empty=True)
                if body not in (None, {}):
                    raise ValidationError("采集来源操作请求体必须为空对象")
                if self.server.source_manager is None:
                    raise ValidationError("连续采集调度器未启用")
                source_id, action = source_action
                if action == "enable":
                    result = self.server.source_manager.enable(source_id)
                elif action == "disable":
                    result = self.server.source_manager.disable(source_id)
                else:
                    result = self.server.source_manager.run_now(source_id)
                self._json(HTTPStatus.OK, result)
            else:
                # There is intentionally no /control, /fan or equipment write API.
                self._not_found()
        except ValidationError as error:
            self._problem(HTTPStatus.BAD_REQUEST, "invalid_request", str(error))
        except PermissionError as error:
            self._problem(HTTPStatus.UNAUTHORIZED, "unauthorized", str(error))
        except EdgeAgentError as error:
            self._problem(HTTPStatus.UNPROCESSABLE_ENTITY, "edge_agent_error", str(error))
        except Exception:
            self._problem(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "服务处理失败；详情已写入服务日志",
            )
            raise

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self._security_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _route(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urlsplit(self.path)
        return parsed.path, parse_qs(parsed.query)

    def _require_auth(self) -> None:
        expected = self.server.settings.api_token
        if not expected:
            return
        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer "):
            raise PermissionError("需要 Bearer API 令牌")
        if not hmac.compare_digest(supplied[7:], expected):
            raise PermissionError("API 令牌无效")

    def _read_json(self, *, allow_empty: bool = False) -> Any:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise ValidationError("Content-Type 必须为 application/json")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError as error:
            raise ValidationError("Content-Length 无效") from error
        if length == 0 and allow_empty:
            return None
        if length <= 0:
            raise ValidationError("请求体不能为空")
        if length > self.server.settings.body_limit_bytes:
            raise ValidationError("请求体超过大小限制")
        body = self.rfile.read(length)
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValidationError("请求体不是有效 UTF-8 JSON") from error

    def _static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        target = (self.server.web_root / relative).resolve()
        try:
            target.relative_to(self.server.web_root)
        except ValueError:
            self._not_found()
            return
        if not target.is_file():
            self._not_found()
            return
        data = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self._security_headers()
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: HTTPStatus, value: Any) -> None:
        data = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._security_headers()
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _problem(
        self, status: HTTPStatus, code: str, message: str
    ) -> None:
        self._json(
            status,
            {
                "error": {
                    "code": code,
                    "message": message,
                }
            },
        )

    def _not_found(self) -> None:
        self._problem(HTTPStatus.NOT_FOUND, "not_found", "接口或资源不存在")

    def _method_not_allowed(self) -> None:
        self._problem(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "边缘智能体不提供该写方法或任何生产设备控制接口",
        )

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )


def _single(query: dict[str, list[str]], name: str) -> str | None:
    values = query.get(name)
    return values[-1] if values else None


def _limit(query: dict[str, list[str]]) -> int:
    raw = _single(query, "limit")
    if raw is None:
        return 100
    try:
        result = int(raw)
    except ValueError as error:
        raise ValidationError("limit 必须是整数") from error
    if not 1 <= result <= 1000:
        raise ValidationError("limit 必须在 1-1000 范围内")
    return result


def _source_action(path: str) -> tuple[str, str] | None:
    prefix = "/api/v1/sources/"
    if not path.startswith(prefix):
        return None
    suffix = path[len(prefix) :]
    parts = suffix.split("/")
    if len(parts) != 2 or not parts[0] or parts[1] not in {
        "enable",
        "disable",
        "run-now",
    }:
        return None
    source_id = unquote(parts[0])
    if not source_id or "/" in source_id or any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in source_id
    ):
        return None
    return source_id, parts[1]


def _empty_source_status() -> dict[str, Any]:
    return {
        "summary": {
            "total": 0,
            "enabled": 0,
            "healthy": 0,
            "starting": 0,
            "degraded": 0,
            "failed": 0,
            "disabled": 0,
            "missing": 0,
            "in_flight": 0,
            "methane_accelerated": 0,
            "attention": 0,
        },
        "items": [],
        "heartbeat": {
            "generated_at": None,
            "latest_source_heartbeat_at": None,
            "signal": "ok",
        },
    }


class ForwardLoop:
    def __init__(self, service: EdgeService, *, interval_seconds: float = 5) -> None:
        self.service = service
        self.interval_seconds = interval_seconds
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="mine-edge-forwarder",
            daemon=True,
        )

    def start(self) -> None:
        if self.service.settings.upstream_url:
            self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=10)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            # Delivery failures are persisted by Forwarder; an unexpected fault
            # must not terminate acquisition.
            with contextlib.suppress(Exception):
                self.service.forwarder.flush(max_batches=20)
            self.stop_event.wait(self.interval_seconds)


def create_server(
    service: EdgeService,
    settings: Settings,
    *,
    host: str | None = None,
    port: int | None = None,
    web_root: Path | None = None,
    source_manager: SourceManager | None = None,
) -> EdgeHttpServer:
    return EdgeHttpServer(
        (host or settings.host, settings.port if port is None else port),
        service,
        settings,
        web_root or default_web_root(),
        source_manager,
    )


def serve(
    service: EdgeService,
    settings: Settings,
    *,
    host: str | None = None,
    port: int | None = None,
    web_root: Path | None = None,
) -> None:
    source_manager = SourceManager(settings.sources, service)
    server = create_server(
        service,
        settings,
        host=host,
        port=port,
        web_root=web_root,
        source_manager=source_manager,
    )
    loop = ForwardLoop(service)
    loop.start()
    source_manager.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        source_manager.stop()
        loop.stop()
        server.server_close()
