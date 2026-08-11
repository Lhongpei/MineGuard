from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from enterprise_agent.cli import main
from enterprise_agent.model_credentials import ModelCredentialError
from enterprise_agent.model_lock_trust import (
    validate_model_lock_against_trust_store,
)
from enterprise_agent.settings import Settings
from enterprise_agent.util import canonical_json


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _trust_entry(
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
    key_epoch: int,
) -> dict[str, object]:
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "issuer_id": "mineguard-model-authority",
        "issuer_key_id": key_id,
        "issuer_key_epoch": key_epoch,
        "public_key_pem": pem.decode("ascii"),
        "public_key_sha256": hashlib.sha256(der).hexdigest(),
    }


def _signed_lock(tmp_path: Path) -> tuple[Path, Path]:
    private_key = Ed25519PrivateKey.generate()
    issuer = _trust_entry(
        private_key,
        key_id="model-ed25519-2026q3",
        key_epoch=1,
    )
    trust_store = tmp_path / "candidate-trust.json"
    trust_store.write_text(
        canonical_json(
            {
                "format": "mineguard-model-issuer-trust-store-v1",
                "issuers": [issuer],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    protected = {
        "contract_version": "mineguard-model-credential-bundle-v1",
        "bundle_kind": "enterprise-agent-model-credential",
        "bundle_id": "11111111-1111-4111-8111-111111111111",
        "credential_id": "22222222-2222-4222-8222-222222222222",
        "credential_version": 7,
        "issued_at": "2026-08-11T00:00:00Z",
        "install_before": "2026-08-12T00:00:00Z",
        # Deliberately old: upgrade trust compatibility must not enforce the
        # runtime authorization window or prevent subsequent key rotation.
        "runtime_not_after": "2026-08-13T00:00:00Z",
        "issuer_id": issuer["issuer_id"],
        "issuer_key_id": issuer["issuer_key_id"],
        "issuer_key_epoch": issuer["issuer_key_epoch"],
        "subject": {
            "mine_id": "MINE-QY-001",
            "system_id": "agent-mine-qy-001",
            "party_id": "operator-qy-001",
            "pair_id": "33333333-3333-4333-8333-333333333333",
        },
        "payload_sha256": "a" * 64,
        "provider_config_sha256": "b" * 64,
        "encryption": {
            "algorithm": "aes-256-gcm",
            "kdf": "scrypt",
            "salt": _b64url(b"s" * 16),
            "n": 16_384,
            "r": 8,
            "p": 1,
            "nonce": _b64url(b"n" * 12),
        },
    }
    signed = {
        "protected": protected,
        "ciphertext": _b64url(b"ciphertext-with-tag"),
    }
    envelope = {
        **signed,
        "signature": _b64url(private_key.sign(canonical_json(signed).encode("utf-8"))),
    }
    lock = tmp_path / "model-credential-lock.json"
    lock.write_text(
        canonical_json(
            {
                "format": "mineguard-model-credential-lock-v1",
                "envelope": envelope,
                "issuer": {
                    "issuer_id": issuer["issuer_id"],
                    "issuer_key_id": issuer["issuer_key_id"],
                    "issuer_key_epoch": issuer["issuer_key_epoch"],
                    "public_key_sha256": issuer["public_key_sha256"],
                },
                # These fields are intentionally unusable.  A compatibility
                # preflight that tries to decrypt or HMAC-check must fail.
                "public_payload": {},
                "secret_store": {
                    "path": str(tmp_path / "missing-secret-store.dpapi"),
                    "protection": "dpapi-local-machine-v1",
                },
                "imported_at": "2026-08-11T00:01:00Z",
                "lock_hmac_algorithm": "not-checked-by-trust-preflight",
                "lock_hmac": "not-checked-by-trust-preflight",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return lock, trust_store


def test_candidate_trust_preflight_verifies_signature_without_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock, trust_store = _signed_lock(tmp_path)

    def _secret_access_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("upgrade preflight must not access the secret store")

    monkeypatch.setattr(
        "enterprise_agent.model_credentials._load_secret_store",
        _secret_access_forbidden,
    )
    result = validate_model_lock_against_trust_store(
        lock_path=lock,
        trust_store_path=trust_store,
    )

    assert result["valid"] is True
    assert result["verification_scope"] == "signed-envelope-and-issuer-only"
    assert result["secret_store_accessed"] is False
    assert result["api_key_accessed"] is False
    assert result["credential_version"] == 7
    assert result["issuer_key_epoch"] == 1
    assert "api_key" not in result
    assert "base_url" not in result
    assert "model" not in result


def test_candidate_trust_preflight_rejects_removed_or_changed_issuer_key(
    tmp_path: Path,
) -> None:
    lock, _trust_store = _signed_lock(tmp_path)
    replacement_key = Ed25519PrivateKey.generate()
    replacement_trust = tmp_path / "replacement-trust.json"
    replacement_trust.write_text(
        canonical_json(
            {
                "format": "mineguard-model-issuer-trust-store-v1",
                "issuers": [
                    _trust_entry(
                        replacement_key,
                        key_id="model-ed25519-2026q4",
                        key_epoch=2,
                    )
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ModelCredentialError, match="不在发行版受信列表"):
        validate_model_lock_against_trust_store(
            lock_path=lock,
            trust_store_path=replacement_trust,
        )


def test_candidate_trust_preflight_rejects_tampered_signed_envelope(
    tmp_path: Path,
) -> None:
    lock, trust_store = _signed_lock(tmp_path)
    document = json.loads(lock.read_text(encoding="utf-8"))
    document["envelope"]["protected"]["credential_version"] = 8
    lock.write_text(canonical_json(document) + "\n", encoding="utf-8")

    with pytest.raises(ModelCredentialError, match="签名验证失败"):
        validate_model_lock_against_trust_store(
            lock_path=lock,
            trust_store_path=trust_store,
        )


def test_lock_trust_cli_is_read_only_and_does_not_load_runtime_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lock, trust_store = _signed_lock(tmp_path)

    def _settings_forbidden() -> Settings:
        raise AssertionError("trust preflight must not load runtime Settings")

    monkeypatch.setattr(Settings, "from_environment", _settings_forbidden)
    monkeypatch.setenv(
        "ENTERPRISE_AGENT_ENV_FILE",
        str(tmp_path / "must-not-be-read.env"),
    )
    exit_code = main(
        [
            "model-credential-lock-trust-check",
            "--lock",
            str(lock),
            "--trust-store",
            str(trust_store),
        ]
    )

    assert exit_code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert result["api_key_accessed"] is False


def test_windows_upgrade_runs_all_instance_trust_preflight_before_mutation() -> None:
    project_root = Path(__file__).resolve().parents[1]
    installer = (
        project_root / "deploy" / "windows" / "Install-EnterpriseAgent.ps1"
    ).read_text(encoding="utf-8")
    cli_source = (project_root / "src" / "enterprise_agent" / "cli.py").read_text(
        encoding="utf-8"
    )
    trust_source = (
        project_root / "src" / "enterprise_agent" / "model_lock_trust.py"
    ).read_text(encoding="utf-8")

    definition = installer.index(
        "function Invoke-EAActiveModelTrustCompatibilityPreflight"
    )
    definition_end = installer.index("function Set-EAInstalledInstanceAcls", definition)
    preflight_body = installer[definition:definition_end]
    candidate_version = installer.index("$CandidateReportedVersion = (")
    preflight_call = installer.index(
        "    Invoke-EAActiveModelTrustCompatibilityPreflight `", candidate_version
    )
    first_state_or_install_mutation = installer.index(
        "    New-Item -ItemType Directory -Path $InstallRoot -Force", preflight_call
    )
    first_runtime_switch = installer.index(
        "-SourcePath $RuntimeRoot -SourceParent $InstallRoot", preflight_call
    )
    first_instance_acl_rewrite = installer.index(
        "Set-EAInstalledInstanceAcls -ApplicationRoot $InstallRoot", preflight_call
    )

    assert (
        candidate_version
        < preflight_call
        < first_state_or_install_mutation
        < first_runtime_switch
    )
    assert preflight_call < first_instance_acl_rewrite
    assert "Get-ChildItem -LiteralPath $InstancesRoot -Force" in preflight_body
    assert "Test-RecognizableLegacyInstance" in preflight_body
    assert "incomplete managed model pointer pair" in preflight_body
    assert "model-credential-lock.json" in preflight_body
    assert "Instance model anti-rollback state" in preflight_body
    assert "[IO.Path]::ChangeExtension(" in preflight_body
    assert "model-credentials.dpapi" in preflight_body
    assert "Invoke-EACandidateModelLockTrustCheck" in preflight_body
    assert "MINEGUARD_AGENT_MODEL_TRUST_STORE" in preflight_body
    assert "Stop-Service" not in installer
    assert '"--secret-store"' not in preflight_body
    assert '"model-credential-lock-trust-check"' in installer
    assert '"model-credential-lock-trust-check"' in cli_source
    offline_gate = cli_source.index("        if args.command in {")
    environment_loading = cli_source.index(
        "        if args.authoritative_env_file:", offline_gate
    )
    assert (
        '"model-credential-lock-trust-check",'
        in cli_source[offline_gate:environment_loading]
    )
    assert (
        offline_gate
        < environment_loading
        < cli_source.index("settings = Settings.from_environment()")
    )
    assert "_load_secret_store" not in trust_source
    assert "load_model_credential_lock" not in trust_source
