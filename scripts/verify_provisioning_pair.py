#!/usr/bin/env python3
"""Black-box acceptance test for a Platform-generated provisioning pair.

The orchestrator imports neither product.  It drives both public CLIs in
separate subprocesses, proving that Platform can generate/import a pair and
that the independently implemented Agent can consume the matching ``mgprov``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLATFORM_SOURCE = REPOSITORY_ROOT / "platform" / "src"
AGENT_SOURCE = REPOSITORY_ROOT / "agent" / "src"
ISSUER_KEY_ID = "qinyuan-provisioning-key-acceptance"


class AcceptanceError(RuntimeError):
    """The two independent products did not complete the provisioning flow."""


def _clean_environment(source: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith(
            (
                "MINEGUARD_",
                "ENTERPRISE_",
                "PLATFORM_",
                "REGULATORY_",
                "DEEPSEEK_",
                "COAL_NEWS_",
            )
        ):
            environment.pop(name, None)
    environment["PYTHONPATH"] = str(source)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def _run_json(
    *,
    python: str,
    module: str,
    source: Path,
    arguments: list[str],
    input_text: str | None = None,
    extra_environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    environment = _clean_environment(source)
    if extra_environment:
        environment.update(extra_environment)
    completed = subprocess.run(
        [python, "-m", module, *arguments],
        cwd=REPOSITORY_ROOT,
        env=environment,
        input=input_text,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        # Product errors are designed not to include provisioning secrets.  Do
        # not include stdin or any file contents in this diagnostic.
        diagnostic = (completed.stderr or completed.stdout).strip()
        raise AcceptanceError(
            f"{module} exited with {completed.returncode}: {diagnostic[:2000]}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise AcceptanceError(f"{module} did not return one JSON object") from error
    if not isinstance(result, dict):
        raise AcceptanceError(f"{module} returned a non-object JSON result")
    return result


def _utc_text(value: datetime) -> str:
    return (
        value.astimezone(UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _password_record(agent_python: str, password: str) -> dict[str, Any]:
    return _run_json(
        python=agent_python,
        module="enterprise_agent",
        source=AGENT_SOURCE,
        arguments=[
            "hash-password",
            "--password-stdin",
            "--production",
            "--json",
        ],
        input_text=password + "\n",
    )


def _users(agent_python: str) -> str:
    business_admin = _password_record(agent_python, "Acceptance!Business2026")
    api_admin = _password_record(agent_python, "Acceptance!ApiAdmin2026")
    document = [
        {
            "actor_id": "acceptance-business-admin",
            "name": "验收企业管理员",
            "role": "企业管理员",
            "password_hash": business_admin["password_hash"],
            "permissions": ["read", "write", "confirm", "submit"],
            "must_change_password": False,
            "credential_provenance": "production_hash_command",
        },
        {
            "actor_id": "api_admin",
            "name": "API 配置管理员",
            "role": "API 配置管理员",
            "password_hash": api_admin["password_hash"],
            "permissions": ["model_api_admin"],
            "must_change_password": False,
            "credential_provenance": "production_hash_command",
        },
    ]
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def verify(platform_python: str, agent_python: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="mineguard-provisioning-acceptance-") as raw:
        root = Path(raw).resolve()
        private_key = root / "issuer-private.pem"
        public_key = root / "issuer-public.pem"
        passphrase_file = root / "issuer-passphrase.txt"
        passphrase_file.write_text(
            "Acceptance-issuer-passphrase-2026\n", encoding="utf-8"
        )
        issuer = _run_json(
            python=platform_python,
            module="mineguard",
            source=PLATFORM_SOURCE,
            arguments=[
                "provision",
                "issuer-init",
                "--private-key",
                str(private_key),
                "--public-key",
                str(public_key),
                "--passphrase-file",
                str(passphrase_file),
            ],
        )
        fingerprint = str(issuer["public_key_sha256"])
        if len(fingerprint) != 64:
            raise AcceptanceError("Platform returned an invalid SPKI fingerprint")

        profile = {
            "profile_version": 1,
            "expires_at": _utc_text(datetime.now(UTC) + timedelta(days=7)),
            "issuer_id": "qinyuan-provisioning-authority",
            "issuer_key_id": ISSUER_KEY_ID,
            "subject": {
                "mine_id": "MINE-QY-ACCEPTANCE",
                "mine_name": "沁源接入包验收矿",
                "party_id": "operator-qy-acceptance",
                "party_name": "沁源接入包验收企业",
                "system_id": "agent-qy-acceptance",
            },
            "comparison_context": {
                "capacity_band": "0.9-1.2Mtpa",
                "mining_method": "underground-longwall",
                "shift_system": "three-shift-eight-hour",
                "coal_type": "thermal-coal",
                "operating_regime": "normal-production",
            },
            "agent": {
                "platform_base_url": "https://mineguard.qinyuan.gov.cn",
                "reporting_timezone": "Asia/Shanghai",
            },
            "platform_identity": {
                "system_id": "mineguard-qinyuan",
                "party_id": "regulator-qinyuan",
                "key_id": "qinyuan-regulator-application-key",
            },
        }
        profile_path = root / "profile.json"
        profile_path.write_text(
            json.dumps(
                profile,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        enterprise_delivery = root / "enterprise-delivery"
        government_registration = root / "government-registration"
        enterprise_activation = root / "enterprise-activation"
        government_activation = root / "government-activation"
        pair = _run_json(
            python=platform_python,
            module="mineguard",
            source=PLATFORM_SOURCE,
            arguments=[
                "provision",
                "create-pair",
                "--profile",
                str(profile_path),
                "--issuer-private-key",
                str(private_key),
                "--issuer-passphrase-file",
                str(passphrase_file),
                "--enterprise-bundle-directory",
                str(enterprise_delivery),
                "--platform-registration-directory",
                str(government_registration),
                "--enterprise-activation-directory",
                str(enterprise_activation),
                "--platform-activation-directory",
                str(government_activation),
            ],
        )
        if pair.get("issuer_public_key_sha256") != fingerprint:
            raise AcceptanceError("Pair and issuer fingerprints differ")
        if pair.get("layout") != "split-delivery-v1":
            raise AcceptanceError("Pair generator did not use the formal split layout")

        expected_parent = {
            "agent_bundle": enterprise_delivery,
            "issuer_public_key_file": government_registration,
            "platform_registration_bundle": government_registration,
            "provisioning_manifest": government_registration,
            "agent_activation_file": enterprise_activation,
            "platform_activation_file": government_activation,
        }
        for field, parent in expected_parent.items():
            if Path(str(pair[field])).parent != parent:
                raise AcceptanceError(f"{field} escaped its isolated delivery tree")

        manifest = json.loads(
            Path(str(pair["provisioning_manifest"])).read_text(encoding="utf-8")
        )
        serialized_manifest = json.dumps(manifest, ensure_ascii=False)
        if any(
            marker in serialized_manifest
            for marker in ("activation", "hmac_secret", "ciphertext")
        ):
            raise AcceptanceError("Non-secret handover manifest exposes secret material")
        enterprise_package = json.loads(
            Path(str(pair["agent_bundle"])).read_text(encoding="utf-8")
        )
        if (
            enterprise_package.get("format")
            != "mineguard-enterprise-access-package-v1"
        ):
            raise AcceptanceError("Enterprise package is not the simplified access file")
        serialized_enterprise_package = json.dumps(
            enterprise_package, ensure_ascii=False
        ).casefold()
        if ".mgreg" in serialized_enterprise_package:
            raise AcceptanceError("Enterprise package exposes government registration media")

        clients = root / "clients.json"
        registration = _run_json(
            python=platform_python,
            module="mineguard",
            source=PLATFORM_SOURCE,
            arguments=[
                "provision",
                "import-registration",
                "--bundle",
                str(pair["platform_registration_bundle"]),
                "--activation-code-file",
                str(pair["platform_activation_file"]),
                "--issuer-public-key",
                str(public_key),
                "--expected-public-key-sha256",
                fingerprint,
                "--expected-issuer-key-id",
                ISSUER_KEY_ID,
                "--clients-file",
                str(clients),
            ],
        )
        if registration.get("pair_id") != pair.get("pair_id"):
            raise AcceptanceError("Platform registration lost the pair binding")
        trust_environment = {
            "MINEGUARD_PROVISIONING_MANAGED_REQUIRED": "true",
            "MINEGUARD_PROVISIONING_TRUSTED_PUBLIC_KEY_FILE": str(public_key),
            "MINEGUARD_PROVISIONING_EXPECTED_PUBLIC_KEY_SHA256": fingerprint,
            "MINEGUARD_PROVISIONING_EXPECTED_ISSUER_KEY_ID": ISSUER_KEY_ID,
            "MINEGUARD_V2_PLATFORM_SYSTEM_ID": "mineguard-qinyuan",
            "MINEGUARD_V2_PLATFORM_PARTY_ID": "regulator-qinyuan",
            "MINEGUARD_V2_PLATFORM_KEY_ID": "qinyuan-regulator-application-key",
        }
        platform_check = _run_json(
            python=platform_python,
            module="mineguard",
            source=PLATFORM_SOURCE,
            arguments=[
                "config-check",
                "--clients-file",
                str(clients),
                "--production",
            ],
            extra_environment=trust_environment,
        )
        if platform_check.get("client_registry_locked_client_count") != 1:
            raise AcceptanceError("Platform did not enforce the managed registry")

        inbox = root / "inbox"
        inbox.mkdir()
        base_env = root / "base-agent.env"
        base_env.write_text(
            "\n".join(
                (
                    f"ENTERPRISE_AGENT_DB={root / 'agent.db'}",
                    "ENTERPRISE_AGENT_PORT=8090",
                    f"ENTERPRISE_AGENT_USERS_JSON={_users(agent_python)}",
                    f"ENTERPRISE_FIVE_QUANTITY_WATCH_DIRS={inbox}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        agent_env = root / "agent.env"
        agent_lock = root / "agent-provisioning-lock.json"
        agent_store = root / "agent-provisioning-secrets"
        agent_import = _run_json(
            python=agent_python,
            module="enterprise_agent",
            source=AGENT_SOURCE,
            arguments=[
                "provision-import",
                "--bundle",
                str(pair["agent_bundle"]),
                "--base-env",
                str(base_env),
                "--output-env",
                str(agent_env),
                "--lock-output",
                str(agent_lock),
                "--lock-env-path",
                str(agent_lock),
                "--secret-store",
                str(agent_store),
                "--secret-store-env-path",
                str(agent_store),
                "--secret-protection",
                "auto",
                "--expected-mine-id",
                "MINE-QY-ACCEPTANCE",
                "--expected-system-id",
                "agent-qy-acceptance",
            ],
        )
        if agent_import.get("pair_id") != pair.get("pair_id"):
            raise AcceptanceError("Agent import did not consume the matching pair")

        registry = json.loads(clients.read_text(encoding="utf-8"))
        client = registry["clients"][0]
        exchange_secrets = [
            *client["message_keys"].values(),
            *client["transport_secrets"],
        ]
        public_agent_environment = agent_env.read_text(encoding="utf-8")
        if any(secret in public_agent_environment for secret in exchange_secrets):
            raise AcceptanceError("Agent environment contains a plaintext HMAC")

        agent_check = _run_json(
            python=agent_python,
            module="enterprise_agent",
            source=AGENT_SOURCE,
            arguments=[
                "--env-file",
                str(agent_env),
                "--authoritative-env-file",
                "config-check",
                "--production",
            ],
            extra_environment={
                "MINEGUARD_SERVICE_PRODUCTION_MODE": "true",
                "MINEGUARD_SERVICE_FOUR_EYES_REQUIRED": "false",
                "MINEGUARD_SERVICE_PROVISIONING_MANAGED_REQUIRED": "true",
            },
        )
        provisioning = agent_check.get("provisioning")
        if not isinstance(provisioning, dict) or not provisioning.get("managed"):
            raise AcceptanceError("Agent production check did not enforce its lock")
        if provisioning.get("pair_id") != pair.get("pair_id"):
            raise AcceptanceError("Agent runtime lock has the wrong pair ID")

        return {
            "status": "ok",
            "contract": "mineguard-provisioning-bundle-v1",
            "pair_id": pair["pair_id"],
            "profile_version": pair["profile_version"],
            "mine_id": "MINE-QY-ACCEPTANCE",
            "platform_managed_clients": 1,
            "agent_managed": True,
            "secrets_in_agent_environment": False,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform-python", default=sys.executable)
    parser.add_argument("--agent-python", default=sys.executable)
    args = parser.parse_args(argv)
    try:
        result = verify(args.platform_python, args.agent_python)
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
