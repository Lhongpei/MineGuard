from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import uuid
from pathlib import Path

from . import __version__
from .client import validate_agent_base_url
from .config import load_config
from .errors import ConnectorError
from .service import ConnectorService
from .state import StateStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enterprise-connector",
        description="煤矿企业数据只读采集与 Agent 自动草稿触发服务",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "status", "check"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", required=True, type=Path)
    retry_dead = subparsers.add_parser("retry-dead")
    retry_dead.add_argument("--config", required=True, type=Path)
    retry_dead.add_argument(
        "--event-id",
        help="只重试一个明确事件；省略时仅重试每个来源当前最新的 dead 修订",
    )
    replay = subparsers.add_parser("replay")
    replay.add_argument("--config", required=True, type=Path)
    replay_choice = replay.add_mutually_exclusive_group(required=True)
    replay_choice.add_argument("--event-id", help="重放一个已交付事件的原始规范化快照")
    replay_choice.add_argument(
        "--latest",
        action="store_true",
        help="重放每个 pipeline/月度草稿/source 的最新已交付快照",
    )
    replay.add_argument(
        "--confirm",
        required=True,
        choices=("REPLAY",),
        help="显式输入 REPLAY，确认已核对两库恢复点",
    )
    supersede = subparsers.add_parser("supersede-dead")
    supersede.add_argument("--config", required=True, type=Path)
    supersede.add_argument("--event-id", required=True)
    supersede.add_argument("--reason", required=True)
    supersede.add_argument(
        "--confirm",
        required=True,
        choices=("SUPERSEDE-DEAD",),
        help="确认已修复 Agent 拒绝原因并需要新修订",
    )
    run = subparsers.add_parser("run")
    run.add_argument("--config", required=True, type=Path)
    run.add_argument("--once", action="store_true", help="采集并投递一轮后退出")
    run.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        validate_agent_base_url(config.agent_url)
        longest_operation = max(
            config.agent_timeout_seconds,
            *(
                source.timeout_seconds
                for pipeline in config.pipelines
                for source in pipeline.sources
            ),
        )
        if config.lease_seconds <= longest_operation * 2:
            raise ConnectorError("lease_seconds 必须大于最长 Agent/来源 timeout 的两倍")
        too_slow = [
            f"{pipeline.id}/{source.id}"
            for pipeline in config.pipelines
            for source in pipeline.sources
            if config.poll_interval_seconds * 2 >= source.max_staleness_seconds
        ]
        if too_slow:
            raise ConnectorError(
                "poll_interval_seconds 必须小于每个来源 max_staleness_seconds 的一半："
                + ", ".join(too_slow)
            )
        if args.command == "validate":
            seeded = [
                f"{pipeline.id}/{source.id}={source.revision_seed}"
                for pipeline in config.pipelines
                for source in pipeline.sources
                if source.revision_seed > 0
            ]
            print(
                json.dumps(
                    {
                        "ok": True,
                        "config": str(config.config_path),
                        "pipelines": len(config.pipelines),
                        "sources": sum(len(item.sources) for item in config.pipelines),
                        "source_policies": [
                            {
                                "pipeline_id": pipeline.id,
                                "source_id": source.id,
                                "source_system": source.source_system,
                                "required": source.id in pipeline.required_sources,
                                "freshness_max_seconds": source.max_staleness_seconds,
                                "revision_seed": source.revision_seed,
                            }
                            for pipeline in config.pipelines
                            for source in pipeline.sources
                        ],
                        "warnings": (
                            [
                                "检测到非零 revision_seed 灾备配置："
                                + ", ".join(seeded)
                                + "；必须以 Agent 导入证据和双人记录为依据"
                            ]
                            if seeded
                            else []
                        ),
                    },
                    ensure_ascii=False,
                )
            )
            return 0
        if args.command in {"status", "check", "retry-dead", "replay", "supersede-dead"}:
            store = StateStore(config.state_db)
            maintenance_owner: str | None = None
            try:
                if args.command in {"retry-dead", "replay", "supersede-dead"}:
                    maintenance_owner = f"maintenance-{uuid.uuid4()}"
                    if not store.acquire_lease(maintenance_owner, config.lease_seconds):
                        raise ConnectorError(
                            "常驻 connector-service 仍在运行；请先停止服务再执行恢复操作"
                        )
                if args.command == "retry-dead":
                    count = store.retry_dead(args.event_id)
                    print(json.dumps({"retried": count}, ensure_ascii=False))
                elif args.command == "replay":
                    count = store.replay_delivered(args.event_id, latest=args.latest)
                    print(json.dumps({"replayed": count}, ensure_ascii=False))
                elif args.command == "supersede-dead":
                    result = store.supersede_dead(args.event_id, reason=args.reason)
                    print(json.dumps(result, ensure_ascii=False))
                else:
                    status = store.status()
                    pipeline_status = store.pipeline_status(config.pipelines)
                    status["pipelines"] = pipeline_status
                    unhealthy = (
                        status["observations"]["dead"] > 0
                        or status["health_deliveries"]["dead"] > 0
                        or any(
                            item["required_sources_not_ready"] for item in pipeline_status
                        )
                    )
                    status["overall_status"] = "unhealthy" if unhealthy else "healthy"
                    print(json.dumps(status, ensure_ascii=False, indent=2))
                    if args.command == "check" and unhealthy:
                        return 1
            finally:
                if maintenance_owner is not None:
                    store.release_lease(maintenance_owner)
                store.close()
            return 0

        logging.basicConfig(
            level=getattr(logging, args.log_level),
            format="%(asctime)s %(levelname)s %(message)s",
        )
        service = ConnectorService(config)
        stopping = False

        def stop(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        try:
            service.acquire()
            if args.once:
                result = service.run_cycle()
                return 2 if result.errors else 0
            service.run_forever(lambda: stopping)
            return 0
        finally:
            service.close()
    except (ConnectorError, ValueError) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
