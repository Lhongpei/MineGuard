from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from enterprise_agent.model_credentials import (
    ModelCredentialError,
    install_model_credential_bundle,
    read_model_activation_code_file,
)
from enterprise_agent.model_issuer import compose_model_trust_store_create_new
from enterprise_agent.model_issuer_cli import main

API_KEY = "sk-enterprise-cli-test-000000000000"
PASSPHRASE = "MineGuard-cli-passphrase-2026"


def _secret_file(path: Path, value: str) -> Path:
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _utc(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def test_offline_cli_issues_and_installs_without_printing_secrets(
    tmp_path: Path,
    capsys,
) -> None:
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    trust_store = tmp_path / "model-trust.json"
    passphrase_file = _secret_file(tmp_path / "issuer.pass", PASSPHRASE)

    assert (
        main(
            [
                "issuer-init",
                "--private-key-output",
                str(private_key),
                "--public-key-output",
                str(public_key),
                "--trust-store-output",
                str(trust_store),
                "--issuer-id",
                "mineguard-model-authority",
                "--issuer-key-id",
                "model-ed25519-2026q3",
                "--issuer-key-epoch",
                "1",
                "--passphrase-file",
                str(passphrase_file),
            ]
        )
        == 0
    )

    now = datetime.now(UTC).replace(microsecond=0)
    pair_id = str(uuid4())
    profile = tmp_path / "enterprise-profile.json"
    assert (
        main(
            [
                "profile-create",
                "--output",
                str(profile),
                "--mine-id",
                "MINE-QY-001",
                "--system-id",
                "AGENT-QY-001",
                "--party-id",
                "ENTERPRISE-QY-001",
                "--pair-id",
                pair_id,
                "--provider-id",
                "deepseek",
                "--base-url",
                "https://api.deepseek.com",
                "--model",
                "deepseek-chat",
                "--capability",
                "extraction",
                "--capability",
                "chat",
                "--install-before",
                _utc(now + timedelta(days=2)),
                "--runtime-not-after",
                _utc(now + timedelta(days=30)),
                "--issuer-id",
                "mineguard-model-authority",
                "--issuer-key-id",
                "model-ed25519-2026q3",
                "--issuer-key-epoch",
                "1",
            ]
        )
        == 0
    )
    profile_document = json.loads(profile.read_text("utf-8"))
    assert profile_document["provider"]["capabilities"] == ["chat", "extraction"]
    assert "api_key" not in profile.read_text("utf-8")

    api_key_file = _secret_file(tmp_path / "enterprise.key", API_KEY)
    bundle = tmp_path / "enterprise.mgllm"
    activation_file = tmp_path / "enterprise.activation"
    assert (
        main(
            [
                "create",
                "--profile",
                str(profile),
                "--api-key-file",
                str(api_key_file),
                "--issuer-private-key",
                str(private_key),
                "--issuer-trust-store",
                str(trust_store),
                "--issuer-passphrase-file",
                str(passphrase_file),
                "--bundle-output",
                str(bundle),
                "--activation-output",
                str(activation_file),
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    activation = read_model_activation_code_file(activation_file)
    assert API_KEY not in output
    assert PASSPHRASE not in output
    assert activation.decode("ascii") not in output
    assert API_KEY not in bundle.read_text("utf-8")

    lock = tmp_path / "model.lock.json"
    store = tmp_path / "model.secret.json"
    installed = install_model_credential_bundle(
        bundle_path=bundle,
        activation_code=activation,
        trust_store_path=trust_store,
        lock_output_path=lock,
        lock_environment_path=lock,
        secret_store_output_path=store,
        secret_store_environment_path=store,
        secret_protection="posix-0600",
        expected_subject=profile_document["subject"],
        now=now,
    )
    assert installed.summary["managed"] is True
    assert installed.summary["pair_id"] == pair_id


def test_cli_has_no_plaintext_api_key_argument() -> None:
    parser_actions = {
        option
        for action in __import__(
            "enterprise_agent.model_issuer_cli", fromlist=["_parser"]
        )
        ._parser()
        ._subparsers._group_actions[0]
        .choices["create"]
        ._actions
        for option in action.option_strings
    }
    assert "--api-key-file" in parser_actions
    assert "--api-key" not in parser_actions
    assert "--issuer-trust-store" in parser_actions


def test_cli_composes_sorted_overlap_trust_store_and_rejects_conflict(
    tmp_path: Path,
    capsys,
) -> None:
    passphrase = _secret_file(tmp_path / "compose.pass", PASSPHRASE)
    stores: list[Path] = []
    for epoch, suffix in enumerate(("q3", "q4"), start=1):
        trust = tmp_path / f"trust-{suffix}.json"
        assert (
            main(
                [
                    "issuer-init",
                    "--private-key-output",
                    str(tmp_path / f"private-{suffix}.pem"),
                    "--public-key-output",
                    str(tmp_path / f"public-{suffix}.pem"),
                    "--trust-store-output",
                    str(trust),
                    "--issuer-id",
                    "mineguard-model-authority",
                    "--issuer-key-id",
                    f"model-ed25519-2026{suffix}",
                    "--issuer-key-epoch",
                    str(epoch),
                    "--passphrase-file",
                    str(passphrase),
                ]
            )
            == 0
        )
        stores.append(trust)
    capsys.readouterr()

    combined = tmp_path / "combined-trust.json"
    assert (
        main(
            [
                "trust-compose",
                "--input",
                str(stores[1]),
                "--input",
                str(stores[0]),
                "--output",
                str(combined),
            ]
        )
        == 0
    )
    document = json.loads(combined.read_text("utf-8"))
    assert [item["issuer_key_id"] for item in document["issuers"]] == [
        "model-ed25519-2026q3",
        "model-ed25519-2026q4",
    ]
    assert [item["issuer_key_epoch"] for item in document["issuers"]] == [1, 2]
    with pytest.raises(FileExistsError):
        compose_model_trust_store_create_new(stores, combined)

    conflict_document = json.loads(stores[1].read_text("utf-8"))
    conflict_document["issuers"][0]["issuer_key_id"] = "model-ed25519-2026q3"
    conflict = tmp_path / "conflict-trust.json"
    conflict.write_text(json.dumps(conflict_document), encoding="utf-8")
    with pytest.raises(ModelCredentialError, match="冲突"):
        compose_model_trust_store_create_new(
            [stores[0], conflict], tmp_path / "must-not-exist.json"
        )

    reused_epoch_document = json.loads(stores[1].read_text("utf-8"))
    reused_epoch_document["issuers"][0]["issuer_key_epoch"] = 1
    reused_epoch = tmp_path / "reused-epoch-trust.json"
    reused_epoch.write_text(json.dumps(reused_epoch_document), encoding="utf-8")
    with pytest.raises(ModelCredentialError, match="冲突"):
        compose_model_trust_store_create_new(
            [stores[0], reused_epoch], tmp_path / "reused-epoch-output.json"
        )
