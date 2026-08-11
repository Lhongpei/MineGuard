"""Offline command line for issuing enterprise-bound model credentials.

This entry point belongs on the operator's signing workstation.  It is not
used by the government Platform and never accepts an API key or private-key
passphrase as a command-line value.
"""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from .model_credentials import (
    PROTOCOL,
    SUPPORTED_MODEL_CAPABILITIES,
    ModelCredentialError,
    read_model_activation_code_file,
    validate_model_trust_store,
)
from .model_issuer import (
    compose_model_trust_store_create_new,
    create_model_credential_bundle,
    issuer_init,
    read_model_api_key_file,
    read_model_issuer_passphrase_file,
    write_model_credential_profile_create_new,
)


def _path(value: Path) -> Path:
    """Give the strict issuer API an unambiguous absolute path."""

    return value.expanduser().resolve()


def _print(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2))


def _passphrase(
    file_path: Path | None,
    *,
    confirmation: bool,
) -> bytes:
    if file_path is not None:
        return read_model_issuer_passphrase_file(_path(file_path))
    first = getpass.getpass("模型签发私钥口令：")
    if confirmation:
        second = getpass.getpass("再次输入模型签发私钥口令：")
        if first != second:
            raise ModelCredentialError("两次输入的模型签发私钥口令不一致")
    try:
        return first.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ModelCredentialError("模型签发私钥口令格式非法") from error


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mineguard-model-issuer",
        description=(
            "MineGuard 厂商离线模型凭据签发工具；不要安装在政府 Platform 主机。"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    initialize = sub.add_parser(
        "issuer-init",
        help="创建加密 Ed25519 私钥、公钥和发行版 trust store",
    )
    initialize.add_argument("--private-key-output", type=Path, required=True)
    initialize.add_argument("--public-key-output", type=Path, required=True)
    initialize.add_argument("--trust-store-output", type=Path, required=True)
    initialize.add_argument("--issuer-id", required=True)
    initialize.add_argument("--issuer-key-id", required=True)
    initialize.add_argument(
        "--issuer-key-epoch",
        type=int,
        required=True,
        help="该 issuer 的严格正整数签发密钥世代；轮换只能递增",
    )
    initialize.add_argument(
        "--passphrase-file",
        type=Path,
        help="0600 口令文件；省略时安全交互输入两次",
    )

    profile = sub.add_parser(
        "profile-create",
        help="生成不含 API Key 的企业专属签发 profile",
    )
    profile.add_argument("--output", type=Path, required=True)
    profile.add_argument(
        "--credential-id",
        default=None,
        help="UUIDv4；首次签发省略则自动生成，轮换必须沿用",
    )
    profile.add_argument("--credential-version", type=int, default=1)
    profile.add_argument("--mine-id", required=True)
    profile.add_argument("--system-id", required=True)
    profile.add_argument("--party-id", required=True)
    profile.add_argument("--pair-id", required=True, help="已验签 .mgprov 的 pair_id")
    profile.add_argument("--provider-id", required=True)
    profile.add_argument("--base-url", required=True)
    profile.add_argument("--model", required=True)
    profile.add_argument(
        "--capability",
        action="append",
        choices=sorted(SUPPORTED_MODEL_CAPABILITIES),
        required=True,
        help="可重复：chat、extraction、coal-news-search",
    )
    profile.add_argument("--timeout-seconds", type=float, default=20.0)
    profile.add_argument("--max-retries", type=int, default=2)
    profile.add_argument(
        "--install-before",
        required=True,
        help="安装截止时间，例如 2026-09-01T00:00:00Z",
    )
    profile.add_argument(
        "--runtime-not-after",
        required=True,
        help="运行截止时间，例如 2027-09-01T00:00:00Z",
    )
    profile.add_argument("--issuer-id", required=True)
    profile.add_argument("--issuer-key-id", required=True)
    profile.add_argument(
        "--issuer-key-epoch",
        type=int,
        required=True,
        help="必须与发行 trust store 中选定密钥的世代一致",
    )

    create = sub.add_parser(
        "create",
        help="由 profile 和独立密钥文件签发 .mgllm",
    )
    create.add_argument("--profile", type=Path, required=True)
    create.add_argument(
        "--api-key-file",
        type=Path,
        required=True,
        help="企业独立 API Key 的 0600 文件；密钥不会进入命令行",
    )
    create.add_argument("--issuer-private-key", type=Path, required=True)
    create.add_argument(
        "--issuer-trust-store",
        type=Path,
        required=True,
        help="将嵌入正式发行版的公钥 trust store；必须匹配签发私钥",
    )
    create.add_argument(
        "--issuer-passphrase-file",
        type=Path,
        help="0600 口令文件；省略时安全交互输入",
    )
    create.add_argument("--bundle-output", type=Path, required=True)
    create.add_argument("--activation-output", type=Path, required=True)
    create.add_argument(
        "--previous-bundle",
        type=Path,
        help="轮换时提供上一版 .mgllm",
    )
    create.add_argument(
        "--previous-activation-code-file",
        type=Path,
        help="轮换时提供上一版激活码文件",
    )
    create.add_argument(
        "--previous-trust-store",
        type=Path,
        help="可选：用指定 trust store 复核上一版签发方",
    )

    trust = sub.add_parser(
        "trust-check",
        help="校验将嵌入发行版的模型签发 trust store",
    )
    trust.add_argument("--trust-store", type=Path, required=True)
    compose = sub.add_parser(
        "trust-compose",
        help="合并新旧受信签发公钥，生成密钥轮换重叠 trust store",
    )
    compose.add_argument(
        "--input",
        type=Path,
        action="append",
        required=True,
        help="输入 trust store；必须重复至少两次",
    )
    compose.add_argument("--output", type=Path, required=True)
    return parser


def _profile_document(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "credential_id": args.credential_id or str(uuid4()),
        "credential_version": args.credential_version,
        "subject": {
            "mine_id": args.mine_id,
            "system_id": args.system_id,
            "party_id": args.party_id,
            "pair_id": args.pair_id,
        },
        "provider": {
            "provider_id": args.provider_id,
            "protocol": PROTOCOL,
            "base_url": args.base_url,
            "model": args.model,
            "capabilities": sorted(set(args.capability)),
            "timeout_seconds": args.timeout_seconds,
            "max_retries": args.max_retries,
        },
        "install_before": args.install_before,
        "runtime_not_after": args.runtime_not_after,
        "issuer_id": args.issuer_id,
        "issuer_key_id": args.issuer_key_id,
        "issuer_key_epoch": args.issuer_key_epoch,
    }


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "issuer-init":
            result = issuer_init(
                private_key_path=_path(args.private_key_output),
                public_key_path=_path(args.public_key_output),
                trust_store_path=_path(args.trust_store_output),
                issuer_id=args.issuer_id,
                issuer_key_id=args.issuer_key_id,
                passphrase=_passphrase(args.passphrase_file, confirmation=True),
                issuer_key_epoch=args.issuer_key_epoch,
            )
            _print(result.summary)
            return 0
        if args.command == "profile-create":
            profile = _profile_document(args)
            output = write_model_credential_profile_create_new(
                _path(args.output), profile
            )
            _print(
                {
                    "valid": True,
                    "profile_path": str(output),
                    "credential_id": profile["credential_id"],
                    "credential_version": profile["credential_version"],
                    "issuer_id": profile["issuer_id"],
                    "issuer_key_id": profile["issuer_key_id"],
                    "issuer_key_epoch": profile["issuer_key_epoch"],
                    **profile["subject"],
                    "provider_id": profile["provider"]["provider_id"],
                    "model": profile["provider"]["model"],
                    "capabilities": profile["provider"]["capabilities"],
                    "secrets_disclosed": False,
                }
            )
            return 0
        if args.command == "create":
            previous_requested = (
                args.previous_bundle is not None
                or args.previous_activation_code_file is not None
                or args.previous_trust_store is not None
            )
            if previous_requested and (
                args.previous_bundle is None
                or args.previous_activation_code_file is None
            ):
                parser.error(
                    "轮换必须同时提供 --previous-bundle 和 "
                    "--previous-activation-code-file"
                )
            previous_activation = (
                read_model_activation_code_file(
                    _path(args.previous_activation_code_file)
                )
                if args.previous_activation_code_file is not None
                else None
            )
            result = create_model_credential_bundle(
                profile_path=_path(args.profile),
                api_key=read_model_api_key_file(_path(args.api_key_file)),
                issuer_private_key_path=_path(args.issuer_private_key),
                issuer_trust_store_path=_path(args.issuer_trust_store),
                issuer_passphrase=_passphrase(
                    args.issuer_passphrase_file,
                    confirmation=False,
                ),
                bundle_output_path=_path(args.bundle_output),
                activation_output_path=_path(args.activation_output),
                previous_bundle_path=(
                    _path(args.previous_bundle)
                    if args.previous_bundle is not None
                    else None
                ),
                previous_activation_code=previous_activation,
                previous_trust_store_path=(
                    _path(args.previous_trust_store)
                    if args.previous_trust_store is not None
                    else None
                ),
            )
            _print(result.summary)
            return 0
        if args.command == "trust-check":
            _print(validate_model_trust_store(_path(args.trust_store)))
            return 0
        if args.command == "trust-compose":
            if len(args.input) < 2:
                parser.error("trust-compose 必须至少提供两个 --input")
            result = compose_model_trust_store_create_new(
                [_path(path) for path in args.input], _path(args.output)
            )
            _print(result.summary)
            return 0
    except ModelCredentialError as error:
        parser.error(str(error))
    parser.error("未知命令")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
