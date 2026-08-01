"""Production CLI for the government five-quantity V2 product.

Legacy analysis utilities are not imported or installed as a command.  This
keeps the supported runtime independent from the retired edge/safety/casework
stack while old source remains available only for controlled data migration.
"""

from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
from typing import Sequence

from . import __version__
from .auth import LocalAuthStore
from .operations import BackupManager, OperationsError
from .regulatory_v2_demo import (
    DEFAULT_V2_DEMO_STATE_DIRECTORY,
    V2DemoSeedError,
    seed_v2_demo_state,
)
from .regulatory_v2_http import serve


class ProductConfigurationError(ValueError):
    """Safe operator-facing configuration error."""


def _port(value: str) -> int:
    try:
        result = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("端口必须是整数") from error
    if not 1 <= result <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1-65535 之间")
    return result


def _calendar_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("日期必须为 YYYY-MM-DD") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mineguard",
        description="政府五量监管平台 V2（唯一算法、只读业务前端）",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    server = commands.add_parser("serve", help="启动政府 V2 API 与只读大屏")
    server.add_argument("--host", default="127.0.0.1")
    server.add_argument("--port", type=_port, default=8080)
    server.add_argument("--state-directory", default=".mineguard-v2")
    server.add_argument("--admin-username", default="admin")
    server.add_argument(
        "--no-auth",
        action="store_true",
        help="仅限回环地址隔离演示；关闭领导端登录",
    )
    server.add_argument(
        "--secure-cookie", action="store_true", help="HTTPS 代理部署时启用"
    )

    demo = commands.add_parser(
        "seed-v2-demo", help="生成隔离的多矿三个月合成演示数据"
    )
    demo.add_argument(
        "--state-directory", default=DEFAULT_V2_DEMO_STATE_DIRECTORY
    )
    demo.add_argument(
        "--through-month",
        type=_calendar_date,
        help="演示截止月份内任一日期；默认上一个完整自然月",
    )

    backup = commands.add_parser("backup", help="一致性备份 V2 SQLite 状态")
    backup.add_argument("backup_id")
    backup.add_argument("--state-directory", default=".mineguard-v2")
    backup.add_argument("--backup-directory")
    backup.add_argument("--key-file")
    backup.add_argument("--key-id", default="mineguard-v2-backup-key")

    verify = commands.add_parser("verify-backup", help="离线核验备份")
    verify.add_argument("backup_id")
    verify.add_argument("--state-directory", default=".mineguard-v2")
    verify.add_argument("--backup-directory")
    verify.add_argument("--key-file")
    verify.add_argument("--key-id", default="mineguard-v2-backup-key")

    restore = commands.add_parser("restore-backup", help="恢复到新的 V2 状态目录")
    restore.add_argument("backup_id")
    restore.add_argument("--state-directory", required=True)
    restore.add_argument("--backup-directory", required=True)
    restore.add_argument("--key-file", required=True)
    restore.add_argument("--key-id", default="mineguard-v2-backup-key")
    return parser


def _state_root(value: str) -> Path:
    if not value.strip():
        raise ProductConfigurationError("状态目录不能为空")
    root = Path(value).expanduser().resolve()
    if root == Path(root.anchor):
        raise ProductConfigurationError("状态目录不能是文件系统根目录")
    return root


def _load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        value = path.read_bytes()
    except FileNotFoundError:
        value = secrets.token_bytes(32)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            raise
    if len(value) < 32:
        raise ProductConfigurationError("备份认证密钥至少需要 32 字节")
    return value


def _read_key(path: Path) -> bytes:
    try:
        value = path.read_bytes()
    except FileNotFoundError as error:
        raise ProductConfigurationError(f"备份认证密钥不存在：{path}") from error
    if len(value) < 32:
        raise ProductConfigurationError("备份认证密钥至少需要 32 字节")
    return value


def _paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    root = _state_root(args.state_directory)
    backup_directory = (
        Path(args.backup_directory).expanduser().resolve()
        if args.backup_directory
        else root / "backups"
    )
    key_file = (
        Path(args.key_file).expanduser().resolve()
        if args.key_file
        else root / "backup.key"
    )
    return root, backup_directory, key_file


def _bootstrap_admin(
    auth_database: Path,
    username: str,
    *,
    host: str,
) -> tuple[str, str | None] | None:
    with LocalAuthStore(auth_database) as store:
        if store.list_users():
            return None
        configured = os.environ.get("MINEGUARD_ADMIN_PASSWORD")
        if configured:
            password = configured
            display = None
        elif host in {"127.0.0.1", "::1", "localhost"}:
            password = "123123123"
            display = password
        else:
            raise ProductConfigurationError(
                "非本机监听首次启动必须设置 MINEGUARD_ADMIN_PASSWORD"
            )
        if len(password) < 8:
            raise ProductConfigurationError("管理员密码至少需要 8 个字符")
        user = store.bootstrap_admin(username, password)
        return user.username, display


def _serve(args: argparse.Namespace) -> None:
    if args.no_auth and args.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ProductConfigurationError("--no-auth 只能与回环监听地址一起使用")
    root = _state_root(args.state_directory)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = root / "mineguard.db"
    auth_database = root / "auth.db"
    backup_key = root / "backup.key"
    _load_or_create_key(backup_key)
    bootstrap = None
    if not args.no_auth:
        bootstrap = _bootstrap_admin(
            auth_database, args.admin_username, host=args.host
        )
    if bootstrap is not None:
        username, displayed_password = bootstrap
        print(f"首次管理员账号：{username}", file=sys.stderr)
        if displayed_password is not None:
            print(f"本机演示默认密码：{displayed_password}", file=sys.stderr)
        else:
            print("管理员密码来自环境变量，未回显。", file=sys.stderr)
    print(
        f"政府五量监管平台监听 http://{args.host}:{args.port}\n"
        f"状态目录：{root}\n"
        "业务前端只读；按 Ctrl+C 安全停止。",
        file=sys.stderr,
    )
    serve(
        args.host,
        args.port,
        database_path=database,
        auth_database_path=auth_database,
        auth_required=not args.no_auth,
        secure_cookie=args.secure_cookie,
    )


def _manager(
    args: argparse.Namespace, *, create_key: bool
) -> tuple[BackupManager, Path, Path, Path]:
    root, backup_directory, key_file = _paths(args)
    key = _load_or_create_key(key_file) if create_key else _read_key(key_file)
    return (
        BackupManager(backup_directory, key, args.key_id, __version__),
        root,
        backup_directory,
        key_file,
    )


def _backup(args: argparse.Namespace) -> dict[str, object]:
    manager, root, directory, key_file = _manager(args, create_key=True)
    databases = {
        name: path
        for name, path in {
            "mineguard.db": root / "mineguard.db",
            "auth.db": root / "auth.db",
        }.items()
        if path.is_file()
    }
    if not databases:
        raise ProductConfigurationError("状态目录中没有 V2 数据库")
    manifest = manager.create_backup(args.backup_id, databases)
    return {
        "status": "created",
        "backup": manifest,
        "backup_directory": str(directory),
        "key_file": str(key_file),
        "warning": "backup.key 不在备份中，必须另行离线保管",
    }


def _verify(args: argparse.Namespace) -> dict[str, object]:
    manager, _, directory, key_file = _manager(args, create_key=False)
    return {
        "status": "valid",
        "backup": manager.verify(args.backup_id),
        "backup_directory": str(directory),
        "key_file": str(key_file),
    }


def _restore(args: argparse.Namespace) -> dict[str, object]:
    manager, target, _, key_file = _manager(args, create_key=False)
    if target.exists() and any(target.iterdir()):
        raise ProductConfigurationError("恢复目标必须不存在或为空")
    existed = target.exists()
    restored = manager.restore(args.backup_id, target)
    try:
        destination_key = restored / "backup.key"
        if key_file.resolve() != destination_key.resolve():
            descriptor = os.open(
                destination_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with key_file.open("rb") as source, os.fdopen(descriptor, "wb") as sink:
                shutil.copyfileobj(source, sink)
                sink.flush()
                os.fsync(sink.fileno())
    except BaseException:
        if not existed:
            shutil.rmtree(restored, ignore_errors=True)
        raise
    return {
        "status": "restored",
        "state_directory": str(restored),
        "next_command": f"mineguard serve --state-directory {restored}",
    }


def _print(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))


def _seed_demo(args: argparse.Namespace) -> dict[str, object]:
    result = seed_v2_demo_state(
        args.state_directory,
        through_month=args.through_month,
    )
    return result.model_dump(mode="json")


def main(argv: Sequence[str] | None = None) -> int:
    previous_umask = os.umask(0o077)
    try:
        args = _parser().parse_args(argv)
        if args.command == "serve":
            _serve(args)
        elif args.command == "seed-v2-demo":
            _print(_seed_demo(args))
        elif args.command == "backup":
            _print(_backup(args))
        elif args.command == "verify-backup":
            _print(_verify(args))
        elif args.command == "restore-backup":
            _print(_restore(args))
        return 0
    except (
        ProductConfigurationError,
        V2DemoSeedError,
        OperationsError,
        OSError,
        ValueError,
    ) as error:
        _print({"error": {"code": "operation_failed", "message": str(error)}})
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
