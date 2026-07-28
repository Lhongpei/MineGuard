"""MineGuard command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, ValidationError

from . import __version__
from .aggregation import AggregationRequest, aggregate_measurements
from .api import _load_or_create_secret, serve
from .auth import LocalAuthStore
from .evidence import EvidenceBundleService
from .flow import FlowAnalysisRequest, analyze_material_flow
from .models import PersonnelMatchRequest, ProductionAnalysisRequest
from .operations import BackupManager, OperationsError
from .optimization import analyze_production
from .personnel import match_personnel
from .source_keys import SourceKeyStore
from .safety import SafetyEvaluationRequest, evaluate_safety
from .temporal import TemporalDetectionRequest, detect_temporal_anomalies
from .verification import VerificationRequest, analyze_verification


_DEFAULT_STATE_DIRECTORY = ".mineguard"
_BACKUP_KEY_ID = "local-backup-key"
_JSON_ARGUMENT_HELP = (
    "内联 JSON 文本、JSON 文件路径、@文件路径，或用 - 从标准输入读取"
)


class _CliInputError(ValueError):
    """A configuration error that can be safely reported to the operator."""


@dataclass(frozen=True)
class _StateLayout:
    root: Path
    database: Path
    auth_database: Path
    job_database: Path
    evidence_database: Path
    evidence_directory: Path
    evidence_key: Path
    governance_database: Path
    source_key_directory: Path
    source_key_database: Path
    backup_directory: Path
    backup_key: Path


_DEMO_PRODUCTION: dict[str, Any] = {
    "mine_id": "M001",
    "window_start": "2026-07-20T00:00:00+08:00",
    "window_end": "2026-07-21T00:00:00+08:00",
    "observations": [
        {
            "observation_id": "production-report-20260720",
            "metric_code": "coal.reported_output_t",
            "value": 5000,
            "tolerance_abs": 100,
            "source_group": "production_report",
            "source_reliability": 0.6,
        },
        {
            "observation_id": "main-belt-20260720",
            "metric_code": "coal.main_transport_t",
            "value": 7100,
            "tolerance_abs": 106.5,
            "source_group": "main_belt",
        },
        {
            "observation_id": "wash-feed-20260720",
            "metric_code": "wash.feed_t",
            "value": 6800,
            "tolerance_abs": 136,
            "source_group": "wash_meter",
        },
        {
            "observation_id": "raw-stock-change-20260720",
            "metric_code": "inventory.raw_change_t",
            "value": 250,
            "tolerance_abs": 100,
            "source_group": "stock_survey",
        },
        {
            "observation_id": "raw-sales-20260720",
            "metric_code": "sales.raw_shipped_t",
            "value": 0,
            "tolerance_abs": 1,
            "source_group": "sales_ledger",
        },
    ],
}

_DEMO_PERSONNEL: dict[str, Any] = {
    "session_id": "GATE-A-entry-20260720T080000",
    "faces": [
        {
            "face_track_id": "face-001",
            "event_time": "2026-07-20T08:00:01+08:00",
            "candidate_person_id": "P001",
            "match_probability": 0.97,
            "direction": "entry",
        },
        {
            "face_track_id": "face-002",
            "event_time": "2026-07-20T08:00:06+08:00",
            "candidate_person_id": "P009",
            "match_probability": 0.94,
            "direction": "entry",
        },
        {
            "face_track_id": "face-003",
            "event_time": "2026-07-20T08:00:12+08:00",
            "candidate_person_id": "P003",
            "match_probability": 0.91,
            "direction": "entry",
        },
    ],
    "cards": [
        {
            "card_event_id": "card-event-001",
            "card_id": "CARD-001",
            "bound_person_id": "P001",
            "event_time": "2026-07-20T08:00:02+08:00",
            "direction": "entry",
        },
        {
            "card_event_id": "card-event-002",
            "card_id": "CARD-002",
            "bound_person_id": "P002",
            "event_time": "2026-07-20T08:00:07+08:00",
            "direction": "entry",
        },
    ],
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mineguard",
        description="煤矿多源交叉验证引擎",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="显示版本后退出",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    production = subparsers.add_parser(
        "production",
        help="分析产运储销洗数据",
    )
    production.add_argument(
        "json",
        metavar="JSON",
        help=_JSON_ARGUMENT_HELP,
    )

    flow = subparsers.add_parser(
        "flow",
        help="运行时间展开物料流协调",
    )
    flow.add_argument(
        "json",
        metavar="JSON",
        help=_JSON_ARGUMENT_HELP,
    )

    aggregate = subparsers.add_parser(
        "aggregate",
        help="按计量语义聚合一个窗口的观测",
    )
    aggregate.add_argument(
        "json",
        metavar="JSON",
        help=_JSON_ARGUMENT_HELP,
    )

    temporal = subparsers.add_parser(
        "temporal",
        help="运行时序异常与来源健康检测",
    )
    temporal.add_argument(
        "json",
        metavar="JSON",
        help=_JSON_ARGUMENT_HELP,
    )

    personnel = subparsers.add_parser(
        "personnel",
        help="匹配人脸与定位卡事件",
    )
    personnel.add_argument(
        "json",
        metavar="JSON",
        help=_JSON_ARGUMENT_HELP,
    )

    safety = subparsers.add_parser(
        "safety",
        help="按版本化人员、甲烷和通风规则生成技术预警线索",
    )
    safety.add_argument("json", metavar="JSON", help=_JSON_ARGUMENT_HELP)

    verification = subparsers.add_parser(
        "verify-production",
        help="核验吨煤电耗和吨煤火工品的历史条件偏离",
    )
    verification.add_argument(
        "json",
        metavar="JSON",
        help=_JSON_ARGUMENT_HELP,
    )

    server = subparsers.add_parser("serve", help="启动 JSON HTTP API")
    server.add_argument("--host", default="127.0.0.1", help="监听地址")
    server.add_argument(
        "--port",
        type=_port,
        default=8080,
        help="监听端口（默认 8080）",
    )
    server.add_argument(
        "--state-directory",
        default=_DEFAULT_STATE_DIRECTORY,
        help="统一状态目录（默认 .mineguard）",
    )
    server.add_argument(
        "--database",
        default=None,
        help="兼容选项：仅覆盖主业务 SQLite 路径",
    )
    server.add_argument(
        "--operator",
        default="local-reviewer",
        help="写入本地办理记录的操作人标签（不替代正式身份认证）",
    )
    server.add_argument(
        "--admin-username",
        default="admin",
        help="首次启动时创建的管理员账号（默认 admin）",
    )
    server.add_argument(
        "--no-auth",
        action="store_true",
        help="关闭身份认证（仅限隔离的本机演示环境）",
    )
    server.add_argument(
        "--secure-cookie",
        action="store_true",
        help="为会话 Cookie 启用 Secure 标志（HTTPS 部署时使用）",
    )
    server.add_argument(
        "--backup-key-file",
        default=None,
        help="备份认证密钥路径；应放在状态目录之外并另行保管",
    )
    server.add_argument(
        "--evidence-key-file",
        default=None,
        help="兼容的证据签名密钥文件；通常由 source-keys.db 托管",
    )
    server.add_argument(
        "--map-geojson",
        default=None,
        help=(
            "可选的官方辖区边界 GeoJSON（仅 Polygon/MultiPolygon）；"
            "未提供时继续显示非测绘示意图"
        ),
    )

    backup = subparsers.add_parser(
        "backup",
        help="一致性备份全部六个 SQLite 数据库",
    )
    backup.add_argument("backup_id", help="不可重复的备份标识")
    _add_backup_location_arguments(backup)

    verify_backup = subparsers.add_parser(
        "verify-backup",
        help="离线校验备份 HMAC、哈希和 SQLite 完整性",
    )
    verify_backup.add_argument("backup_id", help="待校验的备份标识")
    _add_backup_location_arguments(verify_backup)

    restore_backup = subparsers.add_parser(
        "restore-backup",
        help="恢复到新的统一状态目录",
    )
    restore_backup.add_argument("backup_id", help="待恢复的备份标识")
    restore_backup.add_argument(
        "--state-directory",
        required=True,
        help="必须为空或不存在的恢复目标目录",
    )
    restore_backup.add_argument(
        "--backup-directory",
        required=True,
        help="包含备份标识子目录的备份根目录",
    )
    restore_backup.add_argument(
        "--key-file",
        required=True,
        help="外部保留的备份认证密钥文件",
    )
    restore_backup.add_argument(
        "--key-id",
        default=_BACKUP_KEY_ID,
        help=f"备份密钥标识（默认 {_BACKUP_KEY_ID}）",
    )

    verify_evidence = subparsers.add_parser(
        "verify-evidence",
        help="离线校验证据 ZIP 的清单、内容哈希与 HMAC",
    )
    verify_evidence.add_argument("bundle", help="证据 ZIP 文件路径")
    verify_evidence.add_argument(
        "--state-directory",
        default=_DEFAULT_STATE_DIRECTORY,
        help="包含 source-keys 的状态目录（默认 .mineguard）",
    )
    verify_evidence.add_argument(
        "--key-id",
        default="local-evidence-key",
        help="证据清单中的密钥标识",
    )

    subparsers.add_parser("demo", help="运行内置生产与人员交叉验证示例")
    return parser


def _add_backup_location_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-directory",
        default=_DEFAULT_STATE_DIRECTORY,
        help="统一状态目录（默认 .mineguard）",
    )
    parser.add_argument(
        "--backup-directory",
        default=None,
        help="备份根目录（默认 STATE/backups）",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="备份认证密钥文件（默认 STATE/backup.key，必须另行外部保留）",
    )
    parser.add_argument(
        "--key-id",
        default=_BACKUP_KEY_ID,
        help=f"备份密钥标识（默认 {_BACKUP_KEY_ID}）",
    )


def _state_layout(value: str | os.PathLike[str]) -> _StateLayout:
    raw = os.fspath(value)
    if not raw.strip():
        raise _CliInputError("状态目录不能为空")
    root = Path(raw).expanduser().resolve()
    if root == Path(root.anchor):
        raise _CliInputError("文件系统根目录不能作为状态目录")
    source_key_directory = root / "source-keys"
    return _StateLayout(
        root=root,
        database=root / "mineguard.db",
        auth_database=root / "auth.db",
        job_database=root / "jobs.db",
        evidence_database=root / "evidence.db",
        evidence_directory=root / "evidence",
        evidence_key=root / "evidence.key",
        governance_database=root / "governance.db",
        source_key_directory=source_key_directory,
        source_key_database=source_key_directory / "source-keys.db",
        backup_directory=root / "backups",
        backup_key=root / "backup.key",
    )


def _resolved_optional_path(
    value: str | os.PathLike[str] | None,
    default: Path,
) -> Path:
    if value is None:
        return default
    raw = os.fspath(value)
    if not raw.strip():
        raise _CliInputError("路径不能为空")
    return Path(raw).expanduser().resolve()


def _initialise_first_admin(
    auth_database: Path,
    username: str,
) -> tuple[str, str | None] | None:
    """Create the first admin and return its password display policy.

    The generated password is returned exactly once.  An environment-sourced
    password is deliberately represented as ``None`` so it cannot be echoed.
    """

    with LocalAuthStore(auth_database) as auth_store:
        if auth_store.list_users():
            return None
        configured_password = os.environ.get("MINEGUARD_ADMIN_PASSWORD")
        generated = not configured_password
        password = configured_password or secrets.token_urlsafe(24)
        if len(password) < 8:
            raise _CliInputError(
                "MINEGUARD_ADMIN_PASSWORD 至少需要 8 个字符"
            )
        user = auth_store.bootstrap_admin(username, password)
    return user.username, password if generated else None


def _report_first_admin(
    bootstrap: tuple[str, str | None] | None,
) -> None:
    if bootstrap is None:
        return
    username, generated_password = bootstrap
    if generated_password is None:
        print(
            "首次管理员已创建；密码来自 MINEGUARD_ADMIN_PASSWORD，"
            "为避免泄露不回显。",
            file=sys.stderr,
        )
        print(f"管理员账号: {username}", file=sys.stderr)
        return
    print(
        "首次管理员已创建。以下随机密码只显示这一次，请立即安全保存：",
        file=sys.stderr,
    )
    print(f"管理员账号: {username}", file=sys.stderr)
    print(f"一次性显示的管理员密码: {generated_password}", file=sys.stderr)


def _read_existing_secret(path: Path) -> bytes:
    try:
        secret = path.read_bytes()
    except FileNotFoundError as error:
        raise _CliInputError(f"备份认证密钥不存在: {path}") from error
    if len(secret) < 32:
        raise _CliInputError("备份认证密钥至少需要 32 字节")
    return secret


def _backup_runtime(
    args: argparse.Namespace,
    *,
    create_key: bool,
) -> tuple[BackupManager, _StateLayout, Path, Path]:
    layout = _state_layout(args.state_directory)
    backup_directory = _resolved_optional_path(
        args.backup_directory,
        layout.backup_directory,
    )
    key_path = _resolved_optional_path(args.key_file, layout.backup_key)
    key = (
        _load_or_create_secret(key_path)
        if create_key
        else _read_existing_secret(key_path)
    )
    return (
        BackupManager(
            backup_directory,
            key,
            args.key_id,
            __version__,
        ),
        layout,
        backup_directory,
        key_path,
    )


def _state_databases(layout: _StateLayout) -> dict[str, Path]:
    return {
        "mineguard.db": layout.database,
        "auth.db": layout.auth_database,
        "jobs.db": layout.job_database,
        "evidence.db": layout.evidence_database,
        "governance.db": layout.governance_database,
        "source-keys.db": layout.source_key_database,
    }


def _run_backup(args: argparse.Namespace) -> None:
    manager, layout, backup_directory, key_path = _backup_runtime(
        args,
        create_key=True,
    )
    manifest = manager.create_backup(
        args.backup_id,
        _state_databases(layout),
    )
    _output(
        {
            "status": "created",
            "backup": manifest,
            "backup_directory": str(backup_directory),
            "key_file": str(key_path),
            "key_retention_required": (
                "备份不包含认证密钥；必须将 key_file 另行离线安全保留"
            ),
        }
    )


def _run_verify_backup(args: argparse.Namespace) -> None:
    manager, _, backup_directory, key_path = _backup_runtime(
        args,
        create_key=False,
    )
    manifest = manager.verify(args.backup_id)
    _output(
        {
            "status": "valid",
            "backup": manifest,
            "backup_directory": str(backup_directory),
            "key_file": str(key_path),
        }
    )


def _copy_backup_key(source: Path, destination: Path) -> None:
    if source.resolve() == destination.resolve():
        return
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with source.open("rb") as source_stream:
            with os.fdopen(descriptor, "wb") as destination_stream:
                shutil.copyfileobj(source_stream, destination_stream)
                destination_stream.flush()
                os.fsync(destination_stream.fileno())
    except BaseException:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise


def _prepare_restored_layout(
    restored_root: Path,
    external_key_file: Path,
) -> _StateLayout:
    layout = _state_layout(restored_root)
    flat_source_key_database = restored_root / "source-keys.db"
    if not flat_source_key_database.is_file():
        raise _CliInputError("备份缺少 source-keys.db")
    layout.source_key_directory.mkdir(mode=0o700)
    flat_source_key_database.replace(layout.source_key_database)
    layout.evidence_directory.mkdir(mode=0o700)
    layout.backup_directory.mkdir(mode=0o700)
    _copy_backup_key(external_key_file, layout.backup_key)
    return layout


def _run_restore_backup(args: argparse.Namespace) -> None:
    target_layout = _state_layout(args.state_directory)
    backup_directory = _resolved_optional_path(
        args.backup_directory,
        target_layout.backup_directory,
    )
    key_path = _resolved_optional_path(args.key_file, target_layout.backup_key)
    key = _read_existing_secret(key_path)
    manager = BackupManager(
        backup_directory,
        key,
        args.key_id,
        __version__,
    )
    target_existed = target_layout.root.exists()
    restored_root = manager.restore(args.backup_id, target_layout.root)
    try:
        layout = _prepare_restored_layout(restored_root, key_path)
    except BaseException:
        shutil.rmtree(restored_root, ignore_errors=True)
        if target_existed:
            restored_root.mkdir(mode=0o700)
        raise
    _output(
        {
            "status": "restored",
            "state_directory": str(layout.root),
            "databases": [
                str(path.relative_to(layout.root))
                for path in _state_databases(layout).values()
            ],
            "next_command": (
                f"mineguard serve --state-directory {layout.root}"
            ),
            "key_retention_required": (
                "backup.key 已复制到恢复目录；外部原件仍必须安全保留"
            ),
        }
    )


def _run_verify_evidence(args: argparse.Namespace) -> int:
    layout = _state_layout(args.state_directory)
    bundle_path = Path(args.bundle).expanduser().resolve()
    try:
        bundle = bundle_path.read_bytes()
    except FileNotFoundError as error:
        raise _CliInputError("证据 ZIP 不存在") from error
    if not layout.source_key_database.is_file():
        raise _CliInputError("状态目录缺少 source-keys.db")
    key_store = SourceKeyStore(layout.source_key_directory)
    try:
        secret = key_store.get_system("evidence-signing-key")
    finally:
        key_store.close()
    if secret is None:
        raise _CliInputError("状态目录缺少证据核验密钥")
    service = EvidenceBundleService(
        lambda key_id: secret if key_id == args.key_id else None,
        signing_key_id=args.key_id,
    )
    verification = service.verify(bundle)
    _output(
        {
            "status": "valid" if verification.valid else "invalid",
            "verification": verification,
            "bundle": str(bundle_path),
        }
    )
    return 0 if verification.valid else 1


def _run_server(args: argparse.Namespace) -> None:
    layout = _state_layout(args.state_directory)
    layout.root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        layout.root.chmod(0o700)
    except OSError:
        pass

    database = _resolved_optional_path(args.database, layout.database)
    backup_key = _resolved_optional_path(
        args.backup_key_file,
        layout.backup_key,
    )
    evidence_key = _resolved_optional_path(
        args.evidence_key_file,
        layout.evidence_key,
    )
    # Create the recovery prerequisite before generating an administrator
    # credential.  This prevents a key-path error from consuming the only
    # display of a freshly generated password.
    _load_or_create_secret(backup_key)
    bootstrap = None
    if not args.no_auth:
        bootstrap = _initialise_first_admin(
            layout.auth_database,
            args.admin_username,
        )
    _report_first_admin(bootstrap)
    print(
        f"MineGuard listening on http://{args.host}:{args.port}",
        file=sys.stderr,
    )
    print(
        f"备份认证密钥: {backup_key}（不在数据库备份内，必须外部保留）",
        file=sys.stderr,
    )
    if args.no_auth:
        print(
            "警告：身份认证已关闭，仅可用于隔离的本机演示环境。",
            file=sys.stderr,
        )
    serve(
        args.host,
        args.port,
        database_path=database,
        local_actor=args.operator,
        auth_required=not args.no_auth,
        auth_database_path=layout.auth_database,
        bootstrap_admin=None,
        secure_cookie=args.secure_cookie,
        job_database_path=layout.job_database,
        evidence_database_path=layout.evidence_database,
        evidence_directory=layout.evidence_directory,
        evidence_key_path=evidence_key,
        governance_database_path=layout.governance_database,
        source_key_directory=layout.source_key_directory,
        backup_directory=layout.backup_directory,
        backup_key_path=backup_key,
        map_geojson_path=args.map_geojson,
    )


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("端口必须是整数") from error
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 0 到 65535 之间")
    return port


def _load_json_argument(value: str) -> str:
    if value == "-":
        return sys.stdin.read()

    if value.startswith("@"):
        path = Path(value[1:])
        return path.read_text(encoding="utf-8")

    try:
        path = Path(value)
        if path.is_file():
            return path.read_text(encoding="utf-8")
    except OSError:
        # Long inline JSON strings are not valid filesystem paths.
        pass
    return value


def _output(payload: Any, *, stream: Any | None = None) -> None:
    if stream is None:
        stream = sys.stdout
    if isinstance(payload, BaseModel):
        payload = payload.model_dump(mode="json")
    json.dump(payload, stream, ensure_ascii=False, indent=2, default=_json_default)
    stream.write("\n")


def _json_default(value: Any) -> Any:
    item = getattr(value, "item", None)
    if callable(item):
        return item()
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def _report_validation_error(error: ValidationError) -> None:
    _output(
        {
            "error": {
                "code": "validation_error",
                "message": "request validation failed",
                "details": error.errors(
                    include_url=False,
                    include_context=False,
                    include_input=False,
                ),
            }
        },
        stream=sys.stderr,
    )


def _analyze_json(
    source: str,
    model_type: type[BaseModel],
    operation: Any,
) -> Any:
    raw_json = _load_json_argument(source)
    request = model_type.model_validate_json(raw_json)
    return operation(request)


def _main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.command == "production":
            _output(
                _analyze_json(
                    args.json,
                    ProductionAnalysisRequest,
                    analyze_production,
                )
            )
        elif args.command == "flow":
            _output(
                _analyze_json(
                    args.json,
                    FlowAnalysisRequest,
                    analyze_material_flow,
                )
            )
        elif args.command == "aggregate":
            _output(
                _analyze_json(
                    args.json,
                    AggregationRequest,
                    aggregate_measurements,
                )
            )
        elif args.command == "temporal":
            _output(
                _analyze_json(
                    args.json,
                    TemporalDetectionRequest,
                    detect_temporal_anomalies,
                )
            )
        elif args.command == "personnel":
            _output(
                _analyze_json(
                    args.json,
                    PersonnelMatchRequest,
                    match_personnel,
                )
            )
        elif args.command == "safety":
            _output(
                _analyze_json(
                    args.json,
                    SafetyEvaluationRequest,
                    evaluate_safety,
                )
            )
        elif args.command == "verify-production":
            _output(
                _analyze_json(
                    args.json,
                    VerificationRequest,
                    analyze_verification,
                )
            )
        elif args.command == "serve":
            _run_server(args)
        elif args.command == "backup":
            _run_backup(args)
        elif args.command == "verify-backup":
            _run_verify_backup(args)
        elif args.command == "restore-backup":
            _run_restore_backup(args)
        elif args.command == "verify-evidence":
            return _run_verify_evidence(args)
        elif args.command == "demo":
            production_request = ProductionAnalysisRequest.model_validate(
                _DEMO_PRODUCTION
            )
            personnel_request = PersonnelMatchRequest.model_validate(
                _DEMO_PERSONNEL
            )
            _output(
                {
                    "production": analyze_production(production_request),
                    "personnel": match_personnel(personnel_request),
                }
            )
        return 0
    except ValidationError as error:
        _report_validation_error(error)
        return 2
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _output(
            {
                "error": {
                    "code": "input_error",
                    "message": str(error),
                }
            },
            stream=sys.stderr,
        )
        return 2
    except _CliInputError as error:
        _output(
            {
                "error": {
                    "code": "configuration_error",
                    "message": str(error),
                }
            },
            stream=sys.stderr,
        )
        return 2
    except OperationsError as error:
        _output(
            {
                "error": {
                    "code": "operation_error",
                    "message": str(error),
                }
            },
            stream=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        _output(
            {
                "error": {
                    "code": "internal_error",
                    "message": str(error),
                }
            },
            stream=sys.stderr,
        )
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI with private-by-default permissions for all new files."""

    previous_umask = os.umask(0o077)
    try:
        return _main(argv)
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
