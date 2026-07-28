"""Command-line operation for service mode and one-shot collection."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
from pathlib import Path
from typing import Any

from .adapters import FileDropAdapter, HttpPollAdapter, JsonlAdapter
from .errors import EdgeAgentError
from .http_api import default_web_root, serve
from .scheduler import build_adapter
from .service import EdgeService
from .settings import Settings
from .storage import Repository


def _port(value: str) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("端口必须是整数") from error
    if not 1 <= result <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1-65535 范围内")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mine-edge-agent",
        description="矿端只读采集、规则预警与断网续传智能体",
    )
    parser.add_argument("--db", help="覆盖 MINE_EDGE_DB")
    subparsers = parser.add_subparsers(dest="command", required=True)

    server = subparsers.add_parser("serve", help="启动本地 HTTP API 和状态前端")
    server.add_argument("--host")
    server.add_argument("--port", type=_port)
    server.add_argument("--web-root", type=Path)

    once = subparsers.add_parser("run-once", help="执行一次只读采集并尝试上行")
    once.add_argument(
        "--adapter",
        required=True,
        choices=("jsonl", "file-drop", "http-poll"),
    )
    once.add_argument("--source", required=True, help="文件、目录或 HTTP(S) URL")
    once.add_argument("--source-id", default="cli-source")
    once.add_argument("--source-token", help="HTTP poll 的 Bearer 令牌")
    once.add_argument("--ca-file", type=Path, help="HTTP poll 自定义 CA 文件")
    once.add_argument(
        "--no-forward",
        action="store_true",
        help="只入本地队列，本次不尝试上行",
    )

    subparsers.add_parser("status", help="打印健康状态和队列统计")
    subparsers.add_parser("sources", help="校验并列出连续采集来源配置")
    configured_once = subparsers.add_parser(
        "source-run-once",
        help="按 MINE_EDGE_SOURCES_JSON 执行一个来源一次",
    )
    configured_once.add_argument("source_id")
    configured_once.add_argument("--no-forward", action="store_true")
    flush = subparsers.add_parser("flush", help="立即尝试发送到监管接收端")
    flush.add_argument("--max-batches", type=int, default=20)
    return parser


def _service(settings: Settings) -> EdgeService:
    return EdgeService(Repository(settings.database_path), settings)


def _adapter(args: argparse.Namespace, settings: Settings) -> Any:
    if args.adapter == "jsonl":
        return JsonlAdapter(args.source, source_id=args.source_id)
    if args.adapter == "file-drop":
        return FileDropAdapter(args.source, source_id=args.source_id)
    return HttpPollAdapter(
        args.source,
        source_id=args.source_id,
        token=args.source_token,
        timeout_seconds=settings.request_timeout_seconds,
        ca_file=args.ca_file,
    )


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.db:
        os.environ["MINE_EDGE_DB"] = args.db
    try:
        settings = Settings.from_env()
        service = _service(settings)
        if args.command == "serve":
            if args.host:
                settings = dataclasses.replace(settings, host=args.host)
                service = _service(settings)
            settings.validate_server_binding()
            actual_port = args.port if args.port is not None else settings.port
            root = args.web_root or default_web_root()
            upstream_status = (
                "已配置 HMAC 安全转发"
                if settings.upstream_url
                else "未配置，本地缓存"
            )
            threshold_status = (
                "已确认校准"
                if settings.thresholds_calibrated
                else "示例值，禁止直接作为正式处置依据"
            )
            print(
                "\n矿端边缘智能体已启动（只读采集模式）\n"
                f"浏览器：http://{settings.host}:{actual_port}/\n"
                f"健康检查：http://{settings.host}:{actual_port}/api/v1/health\n"
                f"矿井：{settings.mine_id}；客户端：{settings.client_id}\n"
                f"数据库：{settings.database_path}\n"
                f"连续采集来源：{len(settings.sources)} 个"
                f"（启用 {sum(source.enabled for source in settings.sources)} 个）\n"
                f"上行：{upstream_status}\n"
                f"阈值：{threshold_status}\n"
                "本服务不提供任何生产设备控制接口。按 Ctrl+C 安全停止。\n",
                flush=True,
            )
            serve(
                service,
                settings,
                port=actual_port,
                web_root=root,
            )
            return 0
        if args.command == "run-once":
            results = service.run_adapter(_adapter(args, settings))
            result: dict[str, Any] = {
                "acquired": len(results),
                "inserted": sum(item.inserted for item in results),
                "duplicates": sum(item.duplicate for item in results),
                "alerts": sum(len(item.alert_ids) for item in results),
                "results": [item.to_dict() for item in results],
            }
            if not args.no_forward:
                result["forward"] = [
                    item.to_dict() for item in service.forwarder.flush(max_batches=20)
                ]
            _print(result)
            return 0
        if args.command == "status":
            health = service.health()
            health["configured_sources"] = len(settings.sources)
            health["enabled_sources"] = sum(
                source.enabled for source in settings.sources
            )
            _print(health)
            return 0 if service.health()["status"] == "ok" else 1
        if args.command == "sources":
            _print(
                {
                    "count": len(settings.sources),
                    "items": [source.public_dict() for source in settings.sources],
                    "runtime_status": (
                        "serve 运行后通过 GET /api/v1/sources 查看"
                    ),
                }
            )
            return 0
        if args.command == "source-run-once":
            config = next(
                (
                    source
                    for source in settings.sources
                    if source.source_id == args.source_id
                ),
                None,
            )
            if config is None:
                raise EdgeAgentError(f"采集来源不存在：{args.source_id}")
            results = service.run_adapter(build_adapter(config))
            output: dict[str, Any] = {
                "source_id": config.source_id,
                "acquired": len(results),
                "inserted": sum(item.inserted for item in results),
                "duplicates": sum(item.duplicate for item in results),
                "alerts": sum(len(item.alert_ids) for item in results),
            }
            if not args.no_forward:
                output["forward"] = [
                    item.to_dict()
                    for item in service.forwarder.flush(max_batches=20)
                ]
            _print(output)
            return 0
        if args.command == "flush":
            _print(
                {
                    "results": [
                        item.to_dict()
                        for item in service.forwarder.flush(
                            max_batches=args.max_batches
                        )
                    ]
                }
            )
            return 0
    except EdgeAgentError as error:
        _print({"error": {"type": type(error).__name__, "message": str(error)}})
        return 2
    return 1
