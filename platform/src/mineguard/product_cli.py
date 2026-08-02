"""Production CLI for the government five-quantity V2 product.

Legacy analysis utilities are not imported or installed as a command.  This
keeps the supported runtime independent from the retired edge/safety/casework
stack while old source remains available only for controlled data migration.
"""

from __future__ import annotations

import argparse
from datetime import date
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import sys
from typing import Sequence

from . import __version__
from .auth import AuthError, LocalAuthStore, Role
from .instance_lock import StateInstanceLock
from .operations import BackupManager, OperationsError
from .regulatory_v2_demo import (
    DEFAULT_V2_DEMO_STATE_DIRECTORY,
    V2DemoSeedError,
    seed_v2_demo_state,
)
from .regulatory_v2_http import serve


class ProductConfigurationError(ValueError):
    """Safe operator-facing configuration error."""


_DEMO_DEFAULT_PASSWORD = "123123123"
_MIN_PASSWORD_LENGTH = 8
_MINE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ROLE_LABELS = {
    Role.ADMIN: "系统管理员（查看全部煤矿）",
    Role.SUPERVISOR: "辖区监管负责人（只读）",
    Role.REVIEWER: "监管复核人员（只读）",
    Role.VIEWER: "领导查看账号（只读）",
}


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
        description=(
            "MineGuard · 矿安智察——煤矿智能辅助监管系统"
            "（唯一算法、只读业务前端）"
        ),
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

    users = commands.add_parser(
        "user",
        help="管理政府领导端登录账号（独立运维命令，不改变业务数据）",
    )
    user_commands = users.add_subparsers(dest="user_command", required=True)

    user_list = user_commands.add_parser("list", help="列出账号和煤矿查看范围")
    user_list.add_argument("--state-directory", default=".mineguard-v2")

    user_mines = user_commands.add_parser("mines", help="列出可授权的煤矿 ID")
    user_mines.add_argument("--state-directory", default=".mineguard-v2")

    user_add = user_commands.add_parser("add", help="新增领导端账号")
    user_add.add_argument("username")
    user_add.add_argument(
        "--role",
        choices=tuple(role.value for role in Role),
        default=Role.VIEWER.value,
    )
    user_add_scope = user_add.add_mutually_exclusive_group()
    user_add_scope.add_argument(
        "--mine-id",
        dest="mine_scopes",
        action="append",
        default=[],
        help="允许查看的煤矿 ID；非管理员至少指定一次，可重复",
    )
    user_add_scope.add_argument(
        "--all-mines",
        action="store_true",
        help="把当前监管库中的全部煤矿授予该只读账号",
    )
    user_add.add_argument("--state-directory", default=".mineguard-v2")
    user_add.add_argument(
        "--demo-default-password",
        action="store_true",
        help="非交互演示时使用默认初始密码 123123123",
    )

    user_access = user_commands.add_parser(
        "set-access", help="替换账号角色和煤矿查看范围，并撤销其现有会话"
    )
    user_access.add_argument("username")
    user_access.add_argument(
        "--role",
        choices=tuple(role.value for role in Role),
        required=True,
    )
    user_access_scope = user_access.add_mutually_exclusive_group()
    user_access_scope.add_argument(
        "--mine-id",
        dest="mine_scopes",
        action="append",
        default=[],
        help="允许查看的煤矿 ID；非管理员至少指定一次，可重复",
    )
    user_access_scope.add_argument(
        "--all-mines",
        action="store_true",
        help="用当前监管库中的全部煤矿替换账号查看范围",
    )
    user_access.add_argument("--state-directory", default=".mineguard-v2")

    for action, help_text in (
        ("enable", "启用账号"),
        ("disable", "停用账号并撤销其现有会话"),
    ):
        status = user_commands.add_parser(action, help=help_text)
        status.add_argument("username")
        status.add_argument("--state-directory", default=".mineguard-v2")

    reset = user_commands.add_parser(
        "reset-password", help="重置初始密码并撤销该账号现有会话"
    )
    reset.add_argument("username")
    reset.add_argument("--state-directory", default=".mineguard-v2")
    reset.add_argument(
        "--demo-default-password",
        action="store_true",
        help="非交互演示时重置为 123123123",
    )
    return parser


def _state_root(value: str) -> Path:
    if not value.strip():
        raise ProductConfigurationError("状态目录不能为空")
    root = Path(value).expanduser().resolve()
    if root == Path(root.anchor):
        raise ProductConfigurationError("状态目录不能是文件系统根目录")
    return root


def _state_database(args: argparse.Namespace, name: str) -> tuple[Path, Path]:
    root = _state_root(args.state_directory)
    database = root / name
    if not database.is_file():
        raise ProductConfigurationError(
            f"状态目录中不存在 {name}：{root}。"
            "请使用正在运行的 serve 命令对应的同一 --state-directory。"
        )
    return root, database


def _known_mines(root: Path) -> list[dict[str, str]]:
    database = root / "mineguard.db"
    if not database.is_file():
        return []
    with sqlite3.connect(database) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        names: dict[str, str] = {}
        if "v2_submissions" in tables:
            rows = connection.execute(
                """
                SELECT mine_id,mine_name FROM v2_submissions
                ORDER BY period_end DESC,revision DESC,received_at DESC
                """
            )
            for mine_id, mine_name in rows:
                names.setdefault(str(mine_id), str(mine_name))
        if "v2_agent_mine_bindings" in tables:
            for (mine_id,) in connection.execute(
                "SELECT mine_id FROM v2_agent_mine_bindings ORDER BY mine_id"
            ):
                names.setdefault(str(mine_id), str(mine_id))
    return [
        {"mine_id": mine_id, "mine_name": names[mine_id]}
        for mine_id in sorted(names, key=lambda item: (names[item], item))
    ]


def _selected_access(
    args: argparse.Namespace, root: Path
) -> tuple[Role, tuple[str, ...], list[str]]:
    role = Role(args.role)
    if args.all_mines:
        scopes = tuple(item["mine_id"] for item in _known_mines(root))
        if not scopes:
            raise ProductConfigurationError(
                "当前监管库尚无煤矿，不能使用 --all-mines；"
                "请等待首份数据到达或明确指定 --mine-id"
            )
    else:
        scopes = tuple(
            sorted(
                {
                    str(value).strip()
                    for value in args.mine_scopes
                    if str(value).strip()
                }
            )
        )
    if role is Role.ADMIN:
        if scopes:
            raise ProductConfigurationError(
                "admin 自动查看全部煤矿，不应再指定 --mine-id"
            )
    elif not scopes:
        raise ProductConfigurationError(
            "非管理员账号至少需要一个 --mine-id 或 --all-mines；"
            "可先运行 mineguard user mines"
        )
    invalid = [scope for scope in scopes if _MINE_ID.fullmatch(scope) is None]
    if invalid:
        raise ProductConfigurationError(
            f"煤矿 ID 格式不合法：{', '.join(invalid)}"
        )
    known = {item["mine_id"] for item in _known_mines(root)}
    unknown = [scope for scope in scopes if known and scope not in known]
    return role, scopes, unknown


def _new_password(args: argparse.Namespace) -> tuple[str, bool]:
    configured = os.environ.get("MINEGUARD_NEW_USER_PASSWORD")
    used_demo_default = False
    if configured is not None:
        password = configured
    elif args.demo_default_password:
        password = _DEMO_DEFAULT_PASSWORD
        used_demo_default = True
    else:
        try:
            password = getpass.getpass(
                "初始密码（直接回车使用本机演示默认密码 123123123）："
            )
            if not password:
                password = _DEMO_DEFAULT_PASSWORD
                used_demo_default = True
            else:
                confirmation = getpass.getpass("再次输入初始密码：")
                if not secrets.compare_digest(password, confirmation):
                    raise ProductConfigurationError("两次输入的密码不一致")
        except (EOFError, KeyboardInterrupt) as error:
            raise ProductConfigurationError(
                "无法交互读取密码；请设置 MINEGUARD_NEW_USER_PASSWORD，"
                "演示环境也可加 --demo-default-password"
            ) from error
    if len(password) < _MIN_PASSWORD_LENGTH:
        raise ProductConfigurationError(
            f"初始密码至少需要 {_MIN_PASSWORD_LENGTH} 个字符"
        )
    return password, used_demo_default


def _present_user(value: dict[str, object]) -> dict[str, object]:
    rendered = dict(value)
    role = Role(str(value["role"]))
    rendered["role_label"] = _ROLE_LABELS[role]
    return rendered


def _user_operation(args: argparse.Namespace) -> dict[str, object]:
    root, auth_database = _state_database(args, "auth.db")
    if args.user_command == "mines":
        mines = _known_mines(root)
        return {
            "status": "ok",
            "state_directory": str(root),
            "count": len(mines),
            "mines": mines,
        }

    with LocalAuthStore(auth_database) as store:
        if args.user_command == "list":
            users = [_present_user(item) for item in store.list_users()]
            return {
                "status": "ok",
                "state_directory": str(root),
                "count": len(users),
                "users": users,
            }

        if args.user_command == "add":
            role, scopes, unknown = _selected_access(args, root)
            password, used_demo_default = _new_password(args)
            user = store.create_user(args.username, password, role, scopes)
            result: dict[str, object] = {
                "status": "created",
                "state_directory": str(root),
                "user": _present_user(user.to_audit_dict()),
                "restart_required": False,
            }
            warnings = []
            if used_demo_default:
                warnings.append(
                    "当前账号初始密码为 123123123，仅限受控演示；正式使用前请重置。"
                )
            if unknown:
                warnings.append(
                    "以下煤矿尚未出现在当前监管库中，账号将在数据到达后看到它们："
                    + "、".join(unknown)
                )
            if warnings:
                result["warnings"] = warnings
            return result

        if args.user_command == "set-access":
            role, scopes, unknown = _selected_access(args, root)
            user = store.update_user_access(args.username, role, scopes)
            result = {
                "status": "access_updated",
                "state_directory": str(root),
                "user": _present_user(user.to_audit_dict()),
                "sessions_revoked": True,
                "restart_required": False,
            }
            if unknown:
                result["warnings"] = [
                    "以下煤矿尚未出现在当前监管库中，账号将在数据到达后看到它们："
                    + "、".join(unknown)
                ]
            return result

        if args.user_command in {"enable", "disable"}:
            active = args.user_command == "enable"
            user = store.set_user_active(args.username, active)
            return {
                "status": "enabled" if active else "disabled",
                "state_directory": str(root),
                "user": _present_user(user.to_audit_dict()),
                "sessions_revoked": not active,
                "restart_required": False,
            }

        if args.user_command == "reset-password":
            password, used_demo_default = _new_password(args)
            store.reset_password(args.username, password)
            result = {
                "status": "password_reset",
                "state_directory": str(root),
                "username": args.username,
                "sessions_revoked": True,
                "restart_required": False,
            }
            if used_demo_default:
                result["warnings"] = [
                    "密码已重置为 123123123，仅限受控演示；正式使用前请再次重置。"
                ]
            return result

    raise ProductConfigurationError(f"不支持的账号操作：{args.user_command}")


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
    with StateInstanceLock(root):
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
            f"MineGuard · 矿安智察监听 http://{args.host}:{args.port}\n"
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
        elif args.command == "user":
            _print(_user_operation(args))
        return 0
    except (
        AuthError,
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
