"""Command-line entry point for local operation and automation."""

from __future__ import annotations

import argparse
import getpass
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import sys
import sysconfig
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__
from .auth import (
    build_auth_manager,
    hash_password,
    is_loopback,
    production_credential_errors,
    validate_production_password,
)
from .client import PlatformClient
from .environment import (
    load_authoritative_environment_file,
    load_environment_file,
)
from .errors import AgentError
from .five_quantity_exchange import FiveQuantityPlatformClient
from .five_quantity_runtime import FiveQuantityRuntime
from .http_api import serve
from .instance_lock import lock_for_database
from .llm import OpenAICompatibleProvider
from .maintenance import backup_database, restore_database
from .model_api_config import verify_model_api_config
from .model_credentials import (
    plaintext_model_environment_names,
    validate_model_trust_store,
)
from .model_lock_trust import validate_model_lock_against_trust_store
from .provisioning import (
    install_provisioning_bundle,
    verify_provisioning_lock_from_environment,
)
from .service import EnterpriseAgentService
from .settings import Settings
from .skills import build_skill_registry
from .storage import Repository

_PLACEHOLDER_MARKERS = (
    "demo",
    "example",
    "sample",
    "placeholder",
    "not-configured",
    "not_configured",
    "replace-me",
    "replace_me",
    "change-before",
    "change_before",
    "default-secret",
    "test-only",
    "test_only",
)
_DEFAULT_PRODUCTION_IDENTITIES = frozenset(
    {
        "demo-mine-001",
        "demo-operator-001",
        "agent-demo-mine-001",
        "演示煤矿",
        "演示煤矿经营主体",
    }
)
_IDENTITY_PLACEHOLDER_TOKEN = re.compile(
    r"(?:^|[^a-z0-9])(?:demo|example|sample|placeholder|replace(?:-?me)?|"
    r"test|dummy|fake|todo)(?:$|[^a-z0-9])"
)
_RESERVED_PRODUCTION_HOST_SUFFIXES = (
    ".example",
    ".invalid",
    ".test",
    ".localhost",
    ".example.com",
    ".example.net",
    ".example.org",
)


def _placeholder_or_low_quality_secret(value: str) -> str | None:
    folded = value.strip().casefold()
    if any(marker in folded for marker in _PLACEHOLDER_MARKERS):
        return "仍是示例、占位或测试值"
    if len(set(value)) < 10:
        return "字符多样性过低"
    for unit_length in range(1, min(9, len(value) // 4 + 1)):
        unit = value[:unit_length]
        if unit * (len(value) // unit_length) == value:
            return "由短片段重复构成"
    return None


def _placeholder_key_id(value: str) -> bool:
    folded = value.strip().casefold()
    return (
        any(marker in folded for marker in _PLACEHOLDER_MARKERS)
        or folded in {"key", "key-v1", "key-v2", "current-key"}
        or len(set(folded.replace("-", "").replace("_", ""))) < 5
    )


def _placeholder_production_identity(value: str) -> bool:
    folded = value.strip().casefold()
    if not folded or folded in _DEFAULT_PRODUCTION_IDENTITIES:
        return True
    if any(marker in folded for marker in ("演示", "示例", "测试", "占位", "待配置")):
        return True
    if "__" in folded or (folded.startswith("<") and folded.endswith(">")):
        return True
    return _IDENTITY_PLACEHOLDER_TOKEN.search(folded) is not None


def _placeholder_production_url(url: str) -> bool:
    hostname = (urlsplit(url).hostname or "").rstrip(".").casefold()
    if not hostname:
        return True
    if hostname in {
        "example",
        "invalid",
        "test",
        "localhost",
        "example.com",
        "example.net",
        "example.org",
    } or hostname.endswith(_RESERVED_PRODUCTION_HOST_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(hostname)
        return (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
        )
    except ValueError:
        return False


def _json_object(text: str) -> dict[str, Any]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError("必须是有效 JSON") from error
    if not isinstance(parsed, dict):
        raise argparse.ArgumentTypeError("JSON 顶层必须是对象")
    return parsed


def _service(settings: Settings) -> EnterpriseAgentService:
    repository = Repository(settings.database_path)
    human_preparer_actor_ids = frozenset(
        account.actor_id
        for account in settings.users
        if {"read", "write"}.issubset(account.permissions)
        and not (account.permissions & {"confirm", "submit"})
        and not account.temporary_demo
        and not account.must_change_password
    )
    llm_configuration_guard = _model_credential_guard(settings)
    effective_capabilities = (
        frozenset(settings.model_credential_status.capabilities)
        if settings.model_credential_status.managed
        else frozenset({"chat", "extraction", "coal-news-search"})
    )
    llm_provider = (
        OpenAICompatibleProvider(
            settings.llm,
            configuration_guard=llm_configuration_guard,
            allowed_capabilities=effective_capabilities,
        )
        if settings.llm is not None
        and bool(
            effective_capabilities
            & {"chat", "extraction", "coal-news-search"}
        )
        else None
    )
    five_quantity_runtime = FiveQuantityRuntime(
        repository,
        identity=settings.five_quantity_identity,
        platform_client=(
            FiveQuantityPlatformClient(
                settings.five_quantity_platform,
                configuration_guard=(
                    verify_provisioning_lock_from_environment
                    if settings.provisioning_status.managed
                    else None
                ),
            )
            if settings.five_quantity_platform is not None
            else None
        ),
        watched_directories=settings.five_quantity_watch_directories,
        quarantine_directory=settings.five_quantity_quarantine_directory,
        poll_seconds=settings.five_quantity_poll_seconds,
        stable_seconds=settings.five_quantity_stable_seconds,
        llm_provider=llm_provider,
        four_eyes_required=settings.four_eyes_required,
        human_preparer_actor_ids=human_preparer_actor_ids,
    )
    return EnterpriseAgentService(
        repository,
        platform_client=(
            PlatformClient(settings.platform) if settings.platform is not None else None
        ),
        llm_provider=llm_provider,
        skill_registry=build_skill_registry(
            settings.coal_news,
            llm_config=(
                settings.llm
                if "coal-news-search" in effective_capabilities
                else None
            ),
            llm_configuration_guard=llm_configuration_guard,
        ),
        coal_news_config=settings.coal_news,
        agent_v2_config=settings.agent_v2,
        five_quantity_runtime=five_quantity_runtime,
        four_eyes_required=settings.four_eyes_required,
        production_mode=settings.production_mode,
        model_credential_status=settings.model_credential_status.as_dict(),
        model_config_path=settings.model_config_path,
    )


def _model_credential_guard(settings: Settings):
    status = settings.model_credential_status
    if not status.managed:
        return None
    if settings.model_config_path is not None and settings.llm is not None:
        expected_path = settings.model_config_path
        expected_config = settings.llm

        def verify_local() -> object:
            verify_provisioning_lock_from_environment()
            verify_model_api_config(expected_path, expected_config)
            return True

        return verify_local
    return None


def _default_web_root() -> Path:
    # A Nuitka standalone build places data files next to the executable.  Do
    # not derive this location only from ``__file__``: compiled modules may be
    # represented by extension modules inside the distribution directory and
    # wheel ``data-files`` use a different layout again.
    binary_directory = Path(sys.executable).resolve().parent
    candidates = (
        # Native Windows standalone release.
        binary_directory / "web",
        # Editable/source checkout.
        Path(__file__).resolve().parents[2] / "web",
        # Wheel installation via setuptools data-files.
        Path(sysconfig.get_path("data"))
        / "share"
        / "enterprise-reporting-agent"
        / "web",
    )
    for candidate in candidates:
        if (candidate / "index.html").is_file():
            return candidate
    return candidates[-1]


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("端口必须是整数") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1-65535 之间")
    return port


def _startup_banner(
    *,
    server: Any,
    service: EnterpriseAgentService,
    settings: Settings,
    requested_host: str,
    web_root: Path,
) -> None:
    bound_port = int(server.server_address[1])
    if settings.public_origin is not None:
        access = (
            f"浏览器地址：{settings.public_origin}/\n"
            f"监听地址：{requested_host}:{bound_port}（由 HTTPS 反向代理转发）"
        )
    elif is_loopback(requested_host):
        display_host = (
            f"[{requested_host.strip('[]')}]"
            if ":" in requested_host
            else requested_host
        )
        url = f"http://{display_host}:{bound_port}/"
        access = (
            f"浏览器地址：{url}\n"
            f"健康检查：{url}api/v1/health\n"
            "远程 SSH 使用：在自己的电脑另开终端执行\n"
            f"  ssh -N -L {bound_port}:127.0.0.1:{bound_port} "
            "<用户名>@<服务器地址>\n"
            f"然后在自己电脑打开 http://127.0.0.1:{bound_port}/"
        )
    else:
        access = (
            f"监听地址：{requested_host}:{bound_port}\n"
            "浏览器必须通过配置好的 HTTPS 反向代理访问；"
            "不要直接使用明文 HTTP。"
        )
    if settings.users:
        account_status = f"已配置 {len(settings.users)} 个企业账号"
    elif settings.allow_anonymous_local:
        account_status = "匿名本机开发身份（仅限调试）"
    else:
        account_status = "演示账号 demo / 123123123（只能查看和编辑）"
    watched_status = (
        "；".join(settings.five_quantity_watch_directories)
        if settings.five_quantity_watch_directories
        else "未配置（仍可人工上传或调用受控直采 API）"
    )
    print(
        "\n企业可信数据填报智能体已启动（前台运行）\n"
        f"{access}\n"
        f"账号状态：{account_status}\n"
        f"运行模式：{'正式生产' if settings.production_mode else '演示/调试'}；"
        + (
            "业务流程：单一业务管理员\n"
            if not settings.four_eyes_required
            else "业务流程：双人复核\n"
        )
        + f"数据库：{service.repository.path}\n"
        f"本实例煤矿：{settings.five_quantity_identity.mine_name} "
        f"({settings.five_quantity_identity.mine_id})\n"
        f"经营主体：{settings.five_quantity_identity.operator_name} "
        f"({settings.five_quantity_identity.operator_id})\n"
        f"企业智能体：{settings.five_quantity_identity.system_id}（一矿一实例）\n"
        f"前端资源：{web_root.resolve()}\n"
        "十量 V3 监管接口："
        + (
            "已配置；应用消息与运输使用显式、不同的 HMAC 密钥"
            if settings.five_quantity_platform is not None
            else "未配置；当前可导入、复核和可靠排队，不能送达政府"
        )
        + f"\n固定目录：{watched_status}"
        + f"\n异常隔离：{settings.five_quantity_quarantine_directory}"
        + "\n智能模型："
        + (
            (
                "api_admin 模型 API 配置已启用"
                if settings.model_credential_status.source == "api_admin"
                else "受管模型配置已启用"
            )
            if settings.model_credential_status.state in {"managed", "configured"}
            else "受管凭据不可用；模型出站已关闭，报送主线不受影响"
            if settings.model_credential_status.managed
            else "开发配置（非正式）"
            if settings.llm is not None
            else "未配置；本地确定性能力仍可使用"
        )
        + "\n业务前端：收件箱 → 规范化复核报送 → 风险解读回复 → 留痕设置"
        + "\n保持此终端运行；按 Ctrl+C 可安全停止。\n",
        flush=True,
    )
    if settings.five_quantity_demo_secret:
        print(
            "警告：十量 V3 当前使用本机演示消息密钥，只能离线体验；连接监管平台前"
            "必须配置 ENTERPRISE_EXCHANGE_HMAC_SECRET。",
            file=sys.stderr,
        )
def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False))


def _plaintext_model_environment_names() -> tuple[str, ...]:
    """Return configured plaintext model settings without reading out values."""
    return plaintext_model_environment_names()


def _configuration_errors(
    settings: Settings,
    *,
    production: bool,
) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        ZoneInfo(settings.five_quantity_identity.timezone)
    except (ZoneInfoNotFoundError, ValueError):
        errors.append("ENTERPRISE_REPORTING_TIMEZONE 在本机不可用")
    seen_directories: set[str] = set()
    for value in settings.five_quantity_watch_directories:
        path = Path(value).expanduser()
        is_junction = getattr(path, "is_junction", None)
        if (
            path.is_symlink()
            or (callable(is_junction) and is_junction())
            or not path.is_dir()
        ):
            errors.append(f"十量监听目录不存在、不是目录或为重解析点：{path}")
            continue
        resolved = path.resolve()
        if resolved == Path(resolved.anchor):
            errors.append("十量监听目录不能是文件系统根目录")
        folded = str(resolved).casefold()
        if folded in seen_directories:
            errors.append(f"十量监听目录重复：{resolved}")
        seen_directories.add(folded)
    if settings.database_path == ":memory:":
        errors.append("服务配置不能使用内存数据库")
    if not production:
        return tuple(errors)

    plaintext_model_names = _plaintext_model_environment_names()
    if plaintext_model_names:
        errors.append(
            "正式服务禁止通过环境变量配置模型 Key、API 地址、模型或重试参数；"
            "请由 api_admin 在企业端页面配置。发现："
            + ", ".join(plaintext_model_names)
        )
    if os.environ.get("MINEGUARD_AGENT_MODEL_TRUST_STORE", "").strip():
        errors.append(
            "正式服务禁止通过环境变量替换模型签发信任根；"
            "必须使用签名发行版 release-metadata 中固定的 trust store"
        )
    if settings.llm is not None and not settings.model_credential_status.managed:
        errors.append(
            "正式服务启用模型时必须使用 api_admin 的本机受管配置；"
            "开发环境变量只能用于非正式调试"
        )

    if not settings.production_mode:
        errors.append(
            "正式服务必须设置 ENTERPRISE_AGENT_PRODUCTION_MODE=true；"
            "仅不用 demo 账号不等于正式模式"
        )
    if not settings.users:
        errors.append("正式服务必须配置逐用户 ENTERPRISE_AGENT_USERS_JSON")
    else:
        if len(settings.users) != 2:
            errors.append("正式服务必须且只能配置业务管理员和 api_admin")
        if len({account.name.casefold() for account in settings.users}) != len(
            settings.users
        ):
            errors.append("正式服务账号姓名必须唯一")
        business_admins = []
        api_admins = []
        for account in settings.users:
            if _placeholder_production_identity(account.actor_id):
                errors.append(
                    f"正式账号 actor_id 不能使用默认、演示或占位身份："
                    f"{account.actor_id}"
                )
            if _placeholder_production_identity(account.name):
                errors.append(
                    f"正式账号 {account.actor_id} 的 name 不能使用演示、"
                    "测试、示例或占位姓名"
                )
            for defect in production_credential_errors(account):
                errors.append(f"正式账号 {account.actor_id} 的凭据不合格：{defect}")
            if account.actor_id == "api_admin":
                if account.permissions != frozenset({"model_api_admin"}):
                    errors.append("固定账号 api_admin 只能拥有 model_api_admin 权限")
                api_admins.append(account)
            elif account.permissions == frozenset(
                {"read", "write", "confirm", "submit"}
            ):
                business_admins.append(account)
        if len(business_admins) != 1:
            errors.append("正式服务必须配置一个可读写、确认和提交的业务管理员")
        if len(api_admins) != 1:
            errors.append("正式服务必须配置固定且独立的 api_admin")
    if settings.allow_anonymous_local:
        errors.append("正式服务不得启用匿名本机身份")
    if settings.public_origin is None:
        if settings.secure_cookie:
            errors.append("仅本机企业界面必须关闭 Secure Cookie")
    else:
        if not settings.public_origin.startswith("https://"):
            errors.append("对外开放企业界面时必须配置 HTTPS PUBLIC_ORIGIN")
        elif _placeholder_production_url(settings.public_origin):
            errors.append(
                "正式服务 PUBLIC_ORIGIN 不能使用保留、示例、回环或不可路由特殊地址"
            )
        if not settings.secure_cookie:
            errors.append("对外开放企业界面时必须启用 Secure Cookie")
    if not is_loopback(settings.host):
        errors.append("Windows Agent 必须只监听回环地址")
    if settings.five_quantity_platform is None:
        errors.append("正式服务必须完整配置政府 V2 接口及两把不同 HMAC 密钥")
    elif not settings.five_quantity_platform.base_url.startswith("https://"):
        errors.append("正式服务连接政府 V2 平台必须使用 HTTPS")
    elif _placeholder_production_url(settings.five_quantity_platform.base_url):
        errors.append("正式服务政府 V2 地址不能使用保留、示例、回环或不可路由特殊地址")
    if settings.five_quantity_demo_secret:
        errors.append("正式服务不得使用演示应用消息密钥")
    identity = settings.five_quantity_identity
    identity_fields = [
        ("ENTERPRISE_MINE_ID", identity.mine_id),
        ("ENTERPRISE_MINE_NAME", identity.mine_name),
        ("ENTERPRISE_OPERATOR_ID", identity.operator_id),
        ("ENTERPRISE_OPERATOR_NAME", identity.operator_name),
        ("ENTERPRISE_SYSTEM_ID", identity.system_id),
        ("REGULATORY_SYSTEM_ID", identity.regulator_system_id),
        ("REGULATORY_PARTY_ID", identity.regulator_party_id),
    ]
    if settings.five_quantity_platform is not None:
        identity_fields.append(
            ("PLATFORM_V2_SENDER_ID", settings.five_quantity_platform.sender_id)
        )
    for client in settings.connector_clients:
        identity_fields.append(("connector client_id", client.client_id))
        for source in client.allowed_sources:
            identity_fields.extend(
                (
                    ("connector source_id", source.source_id),
                    ("connector source_system", source.source_system),
                )
            )
    for field_name, value in identity_fields:
        if _placeholder_production_identity(value):
            errors.append(f"正式服务字段 {field_name} 不能使用默认、演示或占位身份")
    key_ids = [
        ("企业当前应用签名 key ID", identity.key_id),
        ("政府当前应用验签 key ID", identity.regulator_key_id),
    ]
    key_ids.extend(
        (f"企业历史应用验签 key ID（{item.key_id}）", item.key_id)
        for item in identity.historical_enterprise_signing_keys
    )
    if identity.previous_regulator_key_id is not None:
        key_ids.append(
            ("政府上一把应用验签 key ID", identity.previous_regulator_key_id)
        )
    for label, value in key_ids:
        if _placeholder_key_id(value):
            errors.append(f"{label} 是占位或低质量标识，必须由密钥登记流程签发")
    for index, (left_label, left_value) in enumerate(key_ids):
        for right_label, right_value in key_ids[index + 1 :]:
            if hmac.compare_digest(left_value.encode(), right_value.encode()):
                same_regulator_rotation_slot = {
                    left_label,
                    right_label,
                } == {
                    "政府当前应用验签 key ID",
                    "政府上一把应用验签 key ID",
                }
                if same_regulator_rotation_slot:
                    # The Platform application key ID is a stable global slot.
                    # During one bounded rotation window that slot verifies
                    # first with the current secret, then the previous secret.
                    continue
                errors.append(f"{left_label} 与 {right_label} 不得复用")

    secrets_to_check: list[tuple[str, str]] = [
        ("十量应用消息密钥", identity.message_hmac_secret),
    ]
    secrets_to_check.extend(
        (f"企业历史应用验签密钥（{item.key_id}）", item.secret)
        for item in identity.historical_enterprise_signing_keys
    )
    if identity.previous_message_hmac_secret is not None:
        secrets_to_check.append(
            ("政府上一把应用验签密钥", identity.previous_message_hmac_secret)
        )
    if settings.five_quantity_platform is not None:
        secrets_to_check.append(
            (
                "十量运输密钥",
                settings.five_quantity_platform.transport_hmac_secret,
            )
        )
    if settings.platform is not None and settings.platform.transport_hmac_secret:
        secrets_to_check.append(
            ("通用报送运输密钥", settings.platform.transport_hmac_secret)
        )
    secrets_to_check.extend(
        (f"连接器 {client.client_id} 密钥", client.secret)
        for client in settings.connector_clients
    )
    for label, value in secrets_to_check:
        defect = _placeholder_or_low_quality_secret(value)
        if defect is not None:
            errors.append(f"{label} 不合格：{defect}")
    for index, (left_label, left_value) in enumerate(secrets_to_check):
        for right_label, right_value in secrets_to_check[index + 1 :]:
            if hmac.compare_digest(left_value.encode(), right_value.encode()):
                # Platform application HMAC is bilateral.  After a coordinated
                # rotation, the same retired material is therefore registered
                # in two direction-specific verification namespaces: one for
                # enterprise-authored predecessors and one for regulator-
                # authored receipts.  Selection still uses each envelope's
                # exact, direction-specific key ID; neither namespace may
                # substitute for the other.
                historical_regulator_overlap = (
                    left_label.startswith("企业历史应用验签密钥（")
                    and right_label == "政府上一把应用验签密钥"
                ) or (
                    right_label.startswith("企业历史应用验签密钥（")
                    and left_label == "政府上一把应用验签密钥"
                )
                if historical_regulator_overlap:
                    continue
                errors.append(f"{left_label} 与 {right_label} 不得复用")
    for field, value in identity.comparison_context.items():
        if value.casefold() == "unclassified":
            errors.append(f"正式服务必须配置同类矿分组字段 {field}")
    return tuple(errors)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enterprise-agent",
        description="独立企业可信数据填报智能体",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--db",
        help="覆盖 ENTERPRISE_AGENT_DB",
    )
    parser.add_argument(
        "--env-file",
        help=(
            "从严格 KEY=VALUE UTF-8 文件加载配置；已有进程环境变量优先且文件不会被执行"
        ),
    )
    parser.add_argument(
        "--authoritative-env-file",
        action="store_true",
        help=(
            "Windows 受管服务专用：清除 Agent 配置命名空间后以显式绝对 --env-file 为准"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve_parser = sub.add_parser("serve", help="启动 HTTP API 和前端")
    serve_parser.add_argument("--host")
    serve_parser.add_argument("--port", type=_port)
    serve_parser.add_argument("--web-root")

    password = sub.add_parser(
        "hash-password",
        help="安全生成 ENTERPRISE_AGENT_USERS_JSON 使用的密码摘要",
    )
    password.add_argument(
        "--password-stdin",
        action="store_true",
        help="从标准输入读取一行密码（自动化场景）",
    )
    password.add_argument(
        "--production",
        action="store_true",
        help="按正式账号密码策略校验后再生成摘要",
    )
    password.add_argument(
        "--json",
        action="store_true",
        help="输出可直接复制到用户记录的安全字段（不含明文）",
    )

    create = sub.add_parser("create", help="新建草稿")
    create.add_argument("--actor", required=True)
    create.add_argument("--values", type=_json_object, default={})

    sub.add_parser("list", help="列出草稿")
    show = sub.add_parser("show", help="查看草稿")
    show.add_argument("draft_id")

    patch = sub.add_parser("patch", help="修改草稿")
    patch.add_argument("draft_id")
    patch.add_argument("--actor", required=True)
    patch.add_argument("--revision", type=int)
    patch.add_argument("--values", type=_json_object, required=True)

    importer = sub.add_parser("import", help="导入 JSON 或 CSV")
    importer.add_argument("draft_id")
    importer.add_argument("file", type=Path)
    importer.add_argument("--format", choices=("json", "csv"), required=True)
    importer.add_argument("--actor", required=True)
    importer.add_argument("--revision", type=int)

    questions = sub.add_parser("questions", help="列出缺项问题")
    questions.add_argument("draft_id")
    validate = sub.add_parser("validate", help="执行确定性预检")
    validate.add_argument("draft_id")

    review = sub.add_parser("review", help="逐条记录当前人员已核对来源观测")
    review.add_argument("draft_id")
    review.add_argument("--actor", required=True)
    review.add_argument("--revision", type=int, required=True)
    review_selection = review.add_mutually_exclusive_group(required=True)
    review_selection.add_argument(
        "--observation-id",
        action="append",
        dest="observation_ids",
        help="要核对的观测编号；可重复使用",
    )
    review_selection.add_argument(
        "--all",
        action="store_true",
        help="明确选择当前草稿中的全部观测",
    )
    review.add_argument(
        "--unreview",
        action="store_true",
        help="撤销当前人员对所选观测的核对记录",
    )

    confirm = sub.add_parser("confirm", help="人工确认完整有效草稿")
    confirm.add_argument("draft_id")
    confirm.add_argument("--actor", required=True)
    confirm.add_argument("--name", required=True)
    confirm.add_argument("--role", required=True)
    confirm.add_argument("--attestation", required=True)
    confirm.add_argument(
        "--yes-i-confirm",
        action="store_true",
        help="明确确认所填数据来自原始记录且已核对",
    )
    confirm.add_argument("--revision", type=int)

    submit = sub.add_parser("submit", help="提交已确认草稿")
    submit.add_argument("draft_id")
    submit.add_argument("--idempotency-key")
    submit.add_argument("--actor", default="local-cli")

    audit = sub.add_parser("audit", help="验证并显示追加审计链")
    audit.add_argument("draft_id")

    backup = sub.add_parser(
        "database-backup",
        help="仅创建 SQLite 一致备份；完整灾备还须包含隔离文件",
    )
    backup.add_argument("--output", type=Path, required=True)
    backup.add_argument("--overwrite", action="store_true")

    restore = sub.add_parser(
        "database-restore",
        help="仅离线恢复 SQLite；完整恢复请使用部署脚本",
    )
    restore.add_argument("--input", type=Path, required=True)
    restore.add_argument("--rollback-directory", type=Path, required=True)
    restore.add_argument(
        "--yes-service-stopped",
        action="store_true",
        help="确认本实例服务已停止",
    )
    config_check = sub.add_parser("config-check", help="检查启动或正式服务配置")
    config_check.add_argument("--production", action="store_true")
    sub.add_parser(
        "self-check",
        help="离线检查冻结运行时的配置包密码组件（不读取实例配置）",
    )

    provision_import = sub.add_parser(
        "provision-import",
        help="验签、解密并生成一矿一包的受管企业实例配置",
    )
    provision_import.add_argument("--bundle", type=Path, required=True)
    provision_import.add_argument(
        "--base-env",
        type=Path,
        required=True,
        help="向导预先生成的完整本机环境文件（账号、DB、端口等）",
    )
    provision_import.add_argument(
        "--output-env",
        type=Path,
        required=True,
        help="CreateNew 写入的受管 agent.env staging 文件",
    )
    provision_import.add_argument(
        "--lock-output",
        type=Path,
        required=True,
        help="CreateNew 写入的 provisioning lock staging 文件",
    )
    provision_import.add_argument(
        "--lock-env-path",
        type=Path,
        required=True,
        help="发布后 agent.env 引用的 provisioning lock 最终绝对路径",
    )
    provision_import.add_argument(
        "--secret-store",
        type=Path,
        required=True,
        help="CreateNew 写入的 secret store staging 文件",
    )
    provision_import.add_argument(
        "--secret-store-env-path",
        type=Path,
        required=True,
        help="发布后 agent.env 引用的 secret store 最终绝对路径",
    )
    provision_import.add_argument(
        "--secret-protection",
        choices=("auto", "dpapi-local-machine", "posix-0600"),
        default="auto",
        help="默认 Windows=机器级 DPAPI，Linux=属主 0600 安全文件",
    )
    provision_import.add_argument(
        "--expected-mine-id",
        help="额外固定预期 mine_id，防止现场选错矿包",
    )
    provision_import.add_argument(
        "--expected-system-id",
        help="额外固定预期 Agent system_id，防止现场选错矿包",
    )
    provision_import.add_argument(
        "--current-lock",
        type=Path,
        help="升级时提供现有 lock；仅接受同身份且更高 profile_version",
    )

    model_trust = sub.add_parser(
        "model-trust-check",
        help="离线验证发行版模型签发信任库（不读取企业实例）",
    )
    model_trust.add_argument("--trust-store", type=Path, required=True)
    model_lock_trust = sub.add_parser(
        "model-credential-lock-trust-check",
        help="只读验证现有模型 lock 是否受候选发行信任库认可",
    )
    model_lock_trust.add_argument("--lock", type=Path, required=True)
    model_lock_trust.add_argument("--trust-store", type=Path, required=True)
    return parser


def _self_check() -> dict[str, object]:
    """Exercise provisioning crypto without loading Settings or instance state."""

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        probe = b"enterprise-agent-frozen-runtime-self-check-v1"
        signing_key = Ed25519PrivateKey.generate()
        signature = signing_key.sign(probe)
        signing_key.public_key().verify(signature, probe)

        derived_key = Scrypt(
            salt=b"AgentSelfCheck1",
            length=32,
            n=1024,
            r=8,
            p=1,
        ).derive(b"offline-self-check-only")
        nonce = b"EASelfCheck1"
        aad = b"enterprise-agent-self-check-aad"
        ciphertext = AESGCM(derived_key).encrypt(nonce, probe, aad)
        if AESGCM(derived_key).decrypt(nonce, ciphertext, aad) != probe:
            raise ValueError("AES-GCM round trip mismatch")
    except (ImportError, RuntimeError, ValueError) as error:
        raise AgentError(
            "冻结运行时缺少可用的 Ed25519/AES-GCM/scrypt 配置包密码组件"
        ) from error
    return {
        "status": "ok",
        "provisioning_crypto": "ed25519+aes-256-gcm+scrypt",
    }


def _assert_authoritative_restore_not_blocked(
    environment_file: Path,
    *,
    command: str,
) -> None:
    """Stop managed-service startup while a Windows restore is uncommitted."""

    instance_root = environment_file.resolve().parent.parent
    marker = instance_root / "restore-recovery-block.json"
    if not marker.exists():
        return
    if (
        marker.is_symlink()
        or not marker.is_file()
        or marker.stat().st_size > 1024 * 1024
    ):
        raise ValueError(f"恢复/配置更新阻断标记无效：{marker}")
    try:
        document = json.loads(marker.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"恢复阻断标记无法安全读取：{marker}") from error
    if not isinstance(document, dict) or not isinstance(
        document.get("transaction_id"), str
    ):
        raise ValueError(f"恢复/配置更新阻断标记结构无效：{marker}")
    marker_format = document.get("format")
    if marker_format == "mineguard-enterprise-agent-restore-recovery-block-v1":
        allowed_command = "database-restore"
        environment_name = "MINEGUARD_INTERNAL_RESTORE_TRANSACTION_ID"
        blocked_message = (
            "实例存在未完成恢复阻断标记，禁止启动或执行命令："
            f"{marker}；请保持服务停止并按标记中的精确路径人工恢复"
        )
        mismatch_message = f"恢复阻断标记不属于当前离线恢复事务：{marker}"
    elif marker_format == ("mineguard-enterprise-agent-provisioning-update-block-v1"):
        allowed_command = "config-check"
        environment_name = "MINEGUARD_INTERNAL_PROVISIONING_UPDATE_TRANSACTION_ID"
        blocked_message = (
            "实例存在未完成接入配置更新阻断标记，禁止启动或执行命令："
            f"{marker}；请保持服务停止并执行更新回滚或人工恢复"
        )
        mismatch_message = f"配置更新阻断标记不属于当前更新事务：{marker}"
    else:
        raise ValueError(f"恢复/配置更新阻断标记 format 无效：{marker}")
    if command != allowed_command:
        raise ValueError(blocked_message)
    transaction_id = os.environ.get(environment_name, "")
    if (
        len(transaction_id) != 32
        or any(character not in "0123456789abcdef" for character in transaction_id)
        or not hmac.compare_digest(document["transaction_id"], transaction_id)
    ):
        raise ValueError(mismatch_message)


def _serve_agent(
    args: argparse.Namespace,
    *,
    settings: Settings,
    parser: argparse.ArgumentParser,
) -> int:
    host = args.host or settings.host
    port = args.port or settings.port
    if not is_loopback(host) and not settings.secure_cookie:
        parser.error(
            "监听非本机地址时必须设置 ENTERPRISE_AGENT_SECURE_COOKIE=true，"
            "并在 HTTPS 反向代理后提供服务"
        )
    if not is_loopback(host) and settings.public_origin is None:
        parser.error("监听非本机地址时必须设置唯一的 ENTERPRISE_AGENT_PUBLIC_ORIGIN")
    if (
        settings.public_origin is not None
        and settings.public_origin.startswith("https://")
        and not settings.secure_cookie
    ):
        parser.error(
            "配置 HTTPS ENTERPRISE_AGENT_PUBLIC_ORIGIN 时必须设置 "
            "ENTERPRISE_AGENT_SECURE_COOKIE=true"
        )
    if settings.production_mode:
        production_errors = _configuration_errors(settings, production=True)
        if production_errors:
            parser.error(
                "正式模式配置检查未通过：\n- " + "\n- ".join(production_errors)
            )
    if (
        settings.public_origin is not None
        and settings.public_origin.startswith("http://")
        and settings.secure_cookie
    ):
        parser.error(
            "HTTP ENTERPRISE_AGENT_PUBLIC_ORIGIN 不能设置 "
            "ENTERPRISE_AGENT_SECURE_COOKIE=true"
        )
    auth_manager = build_auth_manager(
        accounts=settings.users,
        bind_host=host,
        allow_anonymous_local=settings.allow_anonymous_local,
        session_ttl_seconds=settings.session_ttl_seconds,
        public_origin_exposed=settings.public_origin is not None,
    )
    if not settings.users and is_loopback(host):
        print(
            "警告：启用仅限本机的演示账号 demo，默认密码为 "
            "123123123；该账号标记为必须修改，正式使用前请配置逐用户账号。",
            file=sys.stderr,
        )
    if settings.allow_anonymous_local:
        print(
            "警告：已启用仅限回环地址的匿名开发身份，不得用于正式环境。",
            file=sys.stderr,
        )
    selected_web = (
        Path(args.web_root).expanduser().resolve()
        if args.web_root
        else _default_web_root()
    )
    if not selected_web.is_dir() or not (selected_web / "index.html").is_file():
        parser.error(
            f"前端资源目录无效：{selected_web}；"
            "请重新安装软件包或通过 --web-root 指定目录"
        )
    with lock_for_database(settings.database_path):
        service = _service(settings)
        service.assert_production_integrity()
        serve(
            service,
            host=host,
            port=port,
            auth_manager=auth_manager,
            secure_cookie=settings.secure_cookie,
            public_origin=settings.public_origin,
            web_root=selected_web,
            connector_clients=settings.connector_clients,
            connector_max_clock_skew_seconds=(
                settings.connector_max_clock_skew_seconds
            ),
            on_started=lambda server: _startup_banner(
                server=server,
                service=service,
                settings=settings,
                requested_host=host,
                web_root=selected_web,
            ),
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command in {
            "self-check",
            "model-trust-check",
            "model-credential-lock-trust-check",
        }:
            if args.env_file or args.authoritative_env_file:
                parser.error(
                    "离线发行/信任检查不接受实例 --env-file 参数"
                )
            if args.command == "self-check":
                _print(_self_check())
            elif args.command == "model-trust-check":
                _print(validate_model_trust_store(args.trust_store))
            else:
                _print(
                    validate_model_lock_against_trust_store(
                        lock_path=args.lock,
                        trust_store_path=args.trust_store,
                    )
                )
            return 0
        if args.authoritative_env_file:
            if not args.env_file:
                parser.error("--authoritative-env-file 必须与显式 --env-file 一起使用")
            authoritative_path = Path(args.env_file).expanduser()
            if not authoritative_path.is_absolute():
                parser.error("--authoritative-env-file 要求 --env-file 使用绝对路径")
            load_authoritative_environment_file(authoritative_path)
            _assert_authoritative_restore_not_blocked(
                authoritative_path,
                command=args.command,
            )
        else:
            selected_environment_file = (
                args.env_file
                or os.environ.get(
                    "ENTERPRISE_AGENT_ENV_FILE",
                    "",
                ).strip()
            )
            if selected_environment_file:
                load_environment_file(selected_environment_file)
        if args.command == "hash-password":
            if args.password_stdin:
                password = sys.stdin.readline().rstrip("\r\n")
            else:
                password = getpass.getpass("密码：")
                confirmation = getpass.getpass("再次输入：")
                if password != confirmation:
                    parser.error("两次输入的密码不一致")
            if args.production:
                validate_production_password(password)
            elif args.json:
                parser.error("--json 仅可与 --production 一起使用")
            encoded_password = hash_password(password)
            if args.json:
                _print(
                    {
                        "password_hash": encoded_password,
                        "credential_provenance": "production_hash_command",
                        "must_change_password": False,
                    }
                )
            else:
                print(encoded_password)
            return 0
        if args.command == "provision-import":
            _print(
                install_provisioning_bundle(
                    bundle_path=args.bundle,
                    base_environment_path=args.base_env,
                    output_environment_path=args.output_env,
                    lock_output_path=args.lock_output,
                    lock_environment_path=args.lock_env_path,
                    secret_store_output_path=args.secret_store,
                    secret_store_environment_path=(args.secret_store_env_path),
                    secret_protection=args.secret_protection,
                    expected_mine_id=args.expected_mine_id,
                    expected_system_id=args.expected_system_id,
                    current_lock_path=args.current_lock,
                ).summary
            )
            return 0
        settings = Settings.from_environment()
        if args.db:
            overridden_state = (
                Path("./data").resolve()
                if args.db == ":memory:"
                else Path(args.db).expanduser().resolve().parent
            )
            settings = Settings(
                **{
                    **settings.__dict__,
                    "database_path": args.db,
                    "five_quantity_quarantine_directory": str(
                        overridden_state / "five-quantity-quarantine"
                    ),
                }
            )
        if args.command == "database-backup":
            _print(
                backup_database(
                    settings.database_path,
                    args.output,
                    overwrite=args.overwrite,
                )
            )
            return 0
        if args.command == "config-check":
            configuration_errors = _configuration_errors(
                settings,
                production=args.production,
            )
            configuration_warnings: list[str] = []
            if not settings.provisioning_status.managed:
                configuration_warnings.append(
                    "当前实例未使用监管签名 provisioning lock；保留兼容的手工配置模式"
                )
            if (
                settings.model_credential_status.managed
                and settings.model_credential_status.state
                not in {"managed", "configured"}
            ):
                configuration_warnings.append(
                    "受管模型配置当前不可用；模型出站已关闭，"
                    "CSV 复核、签名和报送主线仍可运行"
                )
            _print(
                {
                    "valid": not configuration_errors,
                    "mode": "production" if args.production else "runtime",
                    "production_mode": settings.production_mode,
                    "four_eyes_required": settings.four_eyes_required,
                    "errors": list(configuration_errors),
                    "mine_id": settings.five_quantity_identity.mine_id,
                    "system_id": settings.five_quantity_identity.system_id,
                    "enterprise_signing_key_id": (
                        settings.five_quantity_identity.key_id
                    ),
                    "historical_enterprise_verification_key_ids": [
                        item.key_id
                        for item in (
                            settings.five_quantity_identity.historical_enterprise_signing_keys
                        )
                    ],
                    "database_path": str(Path(settings.database_path).resolve()),
                    "port": settings.port,
                    "provisioning": settings.provisioning_status.as_dict(),
                    "model_credential": settings.model_credential_status.as_dict(),
                    "warnings": configuration_warnings,
                }
            )
            return 0 if not configuration_errors else 2
        if args.command == "database-restore":
            if not args.yes_service_stopped:
                parser.error("恢复前必须停止本实例服务并传入 --yes-service-stopped")
            with lock_for_database(settings.database_path):
                _print(
                    restore_database(
                        settings.database_path,
                        args.input,
                        rollback_directory=args.rollback_directory,
                    )
                )
            return 0
        if args.command == "serve":
            return _serve_agent(args, settings=settings, parser=parser)
        if settings.production_mode and args.command in {
            "create",
            "patch",
            "import",
            "review",
            "confirm",
            "submit",
        }:
            raise ValueError(
                "正式模式禁止使用可自行填写 --actor 的变更 CLI；"
                "请登录企业端前端或受认证 HTTP API，由服务端会话确定操作人"
            )
        service = _service(settings)
        if args.command == "create":
            _print(service.create_draft(args.values, actor=args.actor))
        elif args.command == "list":
            items, total = service.list_drafts(limit=200)
            _print({"drafts": items, "count": len(items), "total": total})
        elif args.command == "show":
            _print(service.get_draft(args.draft_id))
        elif args.command == "patch":
            _print(
                service.patch_draft(
                    args.draft_id,
                    args.values,
                    actor=args.actor,
                    expected_revision=args.revision,
                )
            )
        elif args.command == "import":
            _print(
                service.import_into_draft(
                    args.draft_id,
                    format_name=args.format,
                    content=args.file.read_text(encoding="utf-8"),
                    source_name=args.file.name,
                    actor=args.actor,
                    expected_revision=args.revision,
                )
            )
        elif args.command == "questions":
            _print(service.questions(args.draft_id))
        elif args.command == "validate":
            result = service.validate(args.draft_id)
            _print(result)
            return 0 if result["valid"] else 2
        elif args.command == "review":
            observation_ids = args.observation_ids
            if args.all:
                draft = service.get_draft(args.draft_id)
                observation_ids = [
                    observation["observation_id"]
                    for observation in draft.get("observations", [])
                    if isinstance(observation, dict)
                    and isinstance(observation.get("observation_id"), str)
                    and observation["observation_id"]
                ]
                if not observation_ids:
                    raise ValueError("当前草稿没有可核对的有效观测编号")
            _print(
                service.review_observations(
                    args.draft_id,
                    observation_ids=observation_ids,
                    reviewed=not args.unreview,
                    actor=args.actor,
                    expected_revision=args.revision,
                )
            )
        elif args.command == "confirm":
            revision = args.revision
            if revision is None:
                revision = service.get_draft(args.draft_id)["_meta"]["revision"]
            _print(
                service.confirm(
                    args.draft_id,
                    actor=args.actor,
                    confirmer_name=args.name,
                    confirmer_role=args.role,
                    accepted=args.yes_i_confirm,
                    attestation=args.attestation,
                    expected_revision=revision,
                )
            )
        elif args.command == "submit":
            _print(
                service.submit(
                    args.draft_id,
                    idempotency_key=args.idempotency_key,
                    actor=args.actor,
                )
            )
        elif args.command == "audit":
            _print(
                {
                    "events": service.repository.audit_events(args.draft_id),
                    "integrity": service.repository.verify_audit(args.draft_id),
                }
            )
        return 0
    except (AgentError, OSError, sqlite3.Error, ValueError) as error:
        print(f"错误：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
