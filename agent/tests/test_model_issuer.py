from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from enterprise_agent import model_issuer as model_issuer_module
from enterprise_agent.cli import main
from enterprise_agent.model_credentials import (
    ModelCredentialError,
    install_model_credential_bundle,
    load_model_credential_lock,
    model_credential_state_path,
    read_activation_code_file,
    verify_and_decrypt_model_bundle,
)
from enterprise_agent.model_issuer import (
    compose_model_trust_store_create_new,
    create_model_credential_bundle,
    issuer_init,
    read_model_api_key_file,
    read_model_issuer_passphrase_file,
)
from enterprise_agent.util import canonical_json

PASSPHRASE = b"MineGuard issuer passphrase 2026!"
API_KEY_V1 = "sk-enterprise-one-" + "a" * 48
API_KEY_V2 = "sk-enterprise-one-" + "b" * 48
SUBJECT = {
    "mine_id": "MINE-QY-001",
    "system_id": "agent-mine-qy-001",
    "party_id": "operator-qy-001",
    "pair_id": "11111111-1111-4111-8111-111111111111",
}
TEST_SECRET_PROTECTION = (
    "dpapi-local-machine" if os.name == "nt" else "posix-0600"
)
CREDENTIAL_ID = "22222222-2222-4222-8222-222222222222"


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _issuer(tmp_path: Path) -> tuple[Path, Path, Path]:
    private_key = tmp_path / "model-issuer-private.pem"
    public_key = tmp_path / "model-issuer-public.pem"
    trust_store = tmp_path / "model-trust.json"
    issuer_init(
        private_key,
        public_key,
        trust_store,
        "mineguard-model-authority",
        "model-ed25519-2026q3",
        PASSPHRASE,
        issuer_key_epoch=1,
    )
    return private_key, public_key, trust_store


def _profile(
    path: Path,
    *,
    version: int,
    now: datetime,
    subject: dict[str, str] | None = None,
    issuer_id: str = "mineguard-model-authority",
    issuer_key_id: str = "model-ed25519-2026q3",
    issuer_key_epoch: int = 1,
    extra: dict[str, object] | None = None,
) -> Path:
    document: dict[str, object] = {
        "credential_id": CREDENTIAL_ID,
        "credential_version": version,
        "subject": dict(subject or SUBJECT),
        "provider": {
            "provider_id": "deepseek-enterprise-direct",
            "protocol": "openai-compatible-chat-completions",
            "base_url": "https://api.deepseek.com/v1",
            "model": "deepseek-chat",
            "capabilities": ["chat", "coal-news-search", "extraction"],
            "timeout_seconds": 20,
            "max_retries": 2,
        },
        "install_before": (now + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "runtime_not_after": (now + timedelta(days=90))
        .isoformat()
        .replace("+00:00", "Z"),
        "issuer_id": issuer_id,
        "issuer_key_id": issuer_key_id,
        "issuer_key_epoch": issuer_key_epoch,
    }
    if extra:
        document.update(extra)
    path.write_text(canonical_json(document) + "\n", encoding="utf-8")
    return path


def test_issuer_init_creates_encrypted_create_new_material_without_secret_output(
    tmp_path: Path,
) -> None:
    private_key, public_key, trust_store = _issuer(tmp_path)

    assert b"ENCRYPTED PRIVATE KEY" in private_key.read_bytes()
    assert b"PUBLIC KEY" in public_key.read_bytes()
    trust = json.loads(trust_store.read_text(encoding="utf-8"))
    assert trust["format"] == "mineguard-model-issuer-trust-store-v1"
    assert trust["issuers"][0]["issuer_key_id"] == "model-ed25519-2026q3"
    assert trust["issuers"][0]["issuer_key_epoch"] == 1
    if os.name != "nt":
        assert all(
            _mode(path) == 0o600 for path in (private_key, public_key, trust_store)
        )

    hashes = {
        path: path.read_bytes() for path in (private_key, public_key, trust_store)
    }
    with pytest.raises(FileExistsError):
        issuer_init(
            private_key,
            public_key,
            trust_store,
            "mineguard-model-authority",
            "model-ed25519-2026q3",
            PASSPHRASE,
            issuer_key_epoch=1,
        )
    assert all(path.read_bytes() == content for path, content in hashes.items())


def test_created_bundle_round_trips_through_runtime_without_disclosing_secrets(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)
    private_key, _public_key, trust_store = _issuer(tmp_path)
    profile = _profile(tmp_path / "profile.json", version=1, now=now)
    bundle = tmp_path / "mine-qy-v1.mgllm"
    activation = tmp_path / "mine-qy-v1.activation"

    result = create_model_credential_bundle(
        profile,
        API_KEY_V1.encode("utf-8"),
        private_key,
        PASSPHRASE,
        bundle,
        activation,
        issuer_trust_store_path=trust_store,
        now=now,
    )

    verified = verify_and_decrypt_model_bundle(
        bundle_path=bundle,
        activation_code=read_activation_code_file(activation),
        trust_store_path=trust_store,
        expected_subject=SUBJECT,
        now=now,
    )
    assert verified.config.api_key == API_KEY_V1
    assert verified.config.base_url == "https://api.deepseek.com/v1"
    assert verified.config.model == "deepseek-chat"
    assert result.summary["credential_version"] == 1
    assert result.summary["activation_codes_disclosed"] is False
    rendered = canonical_json(result.summary)
    assert API_KEY_V1 not in rendered
    assert PASSPHRASE.decode("utf-8") not in rendered
    assert read_activation_code_file(activation).decode("ascii") not in rendered
    assert API_KEY_V1 not in bundle.read_text(encoding="utf-8")
    if os.name != "nt":
        assert _mode(bundle) == 0o600
        assert _mode(activation) == 0o600


def test_profile_cannot_smuggle_api_key_and_output_transaction_rolls_back(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)
    private_key, _public_key, _trust_store = _issuer(tmp_path)
    invalid_profile = _profile(
        tmp_path / "invalid-profile.json",
        version=1,
        now=now,
        extra={"api_key": API_KEY_V1},
    )
    with pytest.raises(ModelCredentialError, match="未知字段"):
        create_model_credential_bundle(
            invalid_profile,
            API_KEY_V1,
            private_key,
            PASSPHRASE,
            tmp_path / "invalid.mgllm",
            tmp_path / "invalid.activation",
            issuer_trust_store_path=_trust_store,
            now=now,
        )

    valid_profile = _profile(tmp_path / "valid-profile.json", version=1, now=now)
    bundle = tmp_path / "rollback.mgllm"
    activation = tmp_path / "already-exists.activation"
    activation.write_text("do-not-overwrite\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        create_model_credential_bundle(
            valid_profile,
            API_KEY_V1,
            private_key,
            PASSPHRASE,
            bundle,
            activation,
            issuer_trust_store_path=_trust_store,
            now=now,
        )
    assert not bundle.exists()
    assert activation.read_text(encoding="utf-8") == "do-not-overwrite\n"


def test_signer_private_key_must_match_release_trust_store(tmp_path: Path) -> None:
    now = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)
    private_key, _public_key, _trust_store = _issuer(tmp_path)
    rogue_dir = tmp_path / "rogue-trust"
    rogue_dir.mkdir()
    _rogue_private, _rogue_public, rogue_trust = _issuer(rogue_dir)
    profile = _profile(tmp_path / "signer-profile.json", version=1, now=now)
    bundle = tmp_path / "must-not-exist.mgllm"
    activation = tmp_path / "must-not-exist.activation"
    with pytest.raises(ModelCredentialError, match="不匹配"):
        create_model_credential_bundle(
            profile,
            API_KEY_V1,
            private_key,
            PASSPHRASE,
            bundle,
            activation,
            issuer_trust_store_path=rogue_trust,
            now=now,
        )
    assert not bundle.exists()
    assert not activation.exists()


@pytest.mark.parametrize("invalid_epoch", [True, 0, -1, 1.5, "1"])
def test_issuer_key_epoch_is_a_strict_positive_integer(
    tmp_path: Path, invalid_epoch: object
) -> None:
    with pytest.raises(ModelCredentialError, match="严格正整数"):
        issuer_init(
            tmp_path / f"private-{invalid_epoch!s}.pem",
            tmp_path / f"public-{invalid_epoch!s}.pem",
            tmp_path / f"trust-{invalid_epoch!s}.json",
            "mineguard-model-authority",
            "model-ed25519-invalid-epoch",
            PASSPHRASE,
            issuer_key_epoch=invalid_epoch,
        )


def test_profile_key_epoch_must_match_release_trust_entry(tmp_path: Path) -> None:
    now = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)
    private_key, _public_key, trust_store = _issuer(tmp_path)
    profile = _profile(
        tmp_path / "wrong-epoch.profile.json",
        version=1,
        now=now,
        issuer_key_epoch=2,
    )
    with pytest.raises(ModelCredentialError, match="issuer key 不匹配"):
        create_model_credential_bundle(
            profile,
            API_KEY_V1,
            private_key,
            PASSPHRASE,
            tmp_path / "must-not-exist.mgllm",
            tmp_path / "must-not-exist.activation",
            issuer_trust_store_path=trust_store,
            now=now,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX secret modes do not apply")
def test_issuer_secret_input_files_must_be_owner_only(tmp_path: Path) -> None:
    api_file = tmp_path / "api-key.secret"
    passphrase_file = tmp_path / "issuer-passphrase.secret"
    api_file.write_text(API_KEY_V1 + "\n", encoding="utf-8")
    passphrase_file.write_bytes(PASSPHRASE + b"\n")
    api_file.chmod(0o644)
    passphrase_file.chmod(0o640)
    with pytest.raises(ModelCredentialError, match="0600") as failure:
        read_model_api_key_file(api_file)
    with pytest.raises(ModelCredentialError, match="0600"):
        read_model_issuer_passphrase_file(passphrase_file)
    assert API_KEY_V1 not in str(failure.value)
    api_file.chmod(0o600)
    passphrase_file.chmod(0o600)
    assert read_model_api_key_file(api_file).decode("ascii") == API_KEY_V1
    assert read_model_issuer_passphrase_file(passphrase_file) == PASSPHRASE


def test_rotation_keeps_identity_increments_one_and_requires_a_new_api_key(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)
    private_key, _public_key, trust_store = _issuer(tmp_path)
    first_profile = _profile(tmp_path / "profile-v1.json", version=1, now=now)
    first_bundle = tmp_path / "mine-v1.mgllm"
    first_activation = tmp_path / "mine-v1.activation"
    create_model_credential_bundle(
        first_profile,
        API_KEY_V1,
        private_key,
        PASSPHRASE,
        first_bundle,
        first_activation,
        issuer_trust_store_path=trust_store,
        now=now,
    )
    prior_activation = read_activation_code_file(first_activation)
    second_profile = _profile(tmp_path / "profile-v2.json", version=2, now=now)

    with pytest.raises(ModelCredentialError, match="必须更换 API key"):
        create_model_credential_bundle(
            second_profile,
            API_KEY_V1,
            private_key,
            PASSPHRASE,
            tmp_path / "same-key.mgllm",
            tmp_path / "same-key.activation",
            issuer_trust_store_path=trust_store,
            previous_bundle_path=first_bundle,
            previous_activation_code=prior_activation,
            now=now,
        )

    second_bundle = tmp_path / "mine-v2.mgllm"
    second_activation = tmp_path / "mine-v2.activation"
    result = create_model_credential_bundle(
        second_profile,
        API_KEY_V2,
        private_key,
        PASSPHRASE,
        second_bundle,
        second_activation,
        issuer_trust_store_path=trust_store,
        previous_bundle_path=first_bundle,
        previous_activation_code=prior_activation,
        now=now,
    )
    assert result.summary["credential_version"] == 2
    verified = verify_and_decrypt_model_bundle(
        bundle_path=second_bundle,
        activation_code=read_activation_code_file(second_activation),
        trust_store_path=trust_store,
        expected_subject=SUBJECT,
        now=now,
    )
    assert verified.config.api_key == API_KEY_V2

    changed_subject = {**SUBJECT, "system_id": "agent-other-instance"}
    changed_profile = _profile(
        tmp_path / "changed-subject.json",
        version=2,
        now=now,
        subject=changed_subject,
    )
    with pytest.raises(ModelCredentialError, match="不得改变"):
        create_model_credential_bundle(
            changed_profile,
            API_KEY_V2,
            private_key,
            PASSPHRASE,
            tmp_path / "changed.mgllm",
            tmp_path / "changed.activation",
            issuer_trust_store_path=trust_store,
            previous_bundle_path=first_bundle,
            previous_activation_code=prior_activation,
            now=now,
        )


def test_key_rotation_epoch_cannot_roll_back_at_issuer_or_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)
    key_paths: dict[int, tuple[Path, Path]] = {}
    trust_paths: list[Path] = []
    for epoch in (1, 2):
        directory = tmp_path / f"epoch-{epoch}"
        directory.mkdir()
        private_key = directory / "private.pem"
        trust_store = directory / "trust.json"
        issuer_init(
            private_key,
            directory / "public.pem",
            trust_store,
            "mineguard-model-authority",
            f"model-ed25519-epoch-{epoch}",
            PASSPHRASE,
            issuer_key_epoch=epoch,
        )
        key_paths[epoch] = (private_key, trust_store)
        trust_paths.append(trust_store)
    overlap_trust = tmp_path / "overlap-trust.json"
    compose_model_trust_store_create_new(trust_paths, overlap_trust)

    v1_profile = _profile(
        tmp_path / "epoch-2-v1.profile.json",
        version=1,
        now=now,
        issuer_key_id="model-ed25519-epoch-2",
        issuer_key_epoch=2,
    )
    v1_bundle = tmp_path / "epoch-2-v1.mgllm"
    v1_activation = tmp_path / "epoch-2-v1.activation"
    create_model_credential_bundle(
        v1_profile,
        API_KEY_V1,
        key_paths[2][0],
        PASSPHRASE,
        v1_bundle,
        v1_activation,
        issuer_trust_store_path=overlap_trust,
        now=now,
    )
    v2_profile = _profile(
        tmp_path / "epoch-1-v2.profile.json",
        version=2,
        now=now,
        issuer_key_id="model-ed25519-epoch-1",
        issuer_key_epoch=1,
    )
    old_activation = read_activation_code_file(v1_activation)
    with pytest.raises(ModelCredentialError, match="回退 issuer key epoch"):
        create_model_credential_bundle(
            v2_profile,
            API_KEY_V2,
            key_paths[1][0],
            PASSPHRASE,
            tmp_path / "issuer-rejected.mgllm",
            tmp_path / "issuer-rejected.activation",
            issuer_trust_store_path=overlap_trust,
            previous_bundle_path=v1_bundle,
            previous_activation_code=old_activation,
            previous_trust_store_path=overlap_trust,
            now=now,
        )

    # Build a cryptographically valid hostile lower-epoch fixture by bypassing
    # only the issuer-side comparison; runtime import must independently reject it.
    original_decode = model_issuer_module._decode_previous

    def decode_with_forged_previous_epoch(*args, **kwargs):
        payload, protected = original_decode(*args, **kwargs)
        return payload, {**protected, "issuer_key_epoch": 1}

    monkeypatch.setattr(
        model_issuer_module,
        "_decode_previous",
        decode_with_forged_previous_epoch,
    )
    hostile_bundle = tmp_path / "hostile-epoch-1-v2.mgllm"
    hostile_activation = tmp_path / "hostile-epoch-1-v2.activation"
    create_model_credential_bundle(
        v2_profile,
        API_KEY_V2,
        key_paths[1][0],
        PASSPHRASE,
        hostile_bundle,
        hostile_activation,
        issuer_trust_store_path=overlap_trust,
        previous_bundle_path=v1_bundle,
        previous_activation_code=old_activation,
        previous_trust_store_path=overlap_trust,
        now=now,
    )

    current_lock = tmp_path / "current.lock.json"
    install_model_credential_bundle(
        bundle_path=v1_bundle,
        activation_code=old_activation,
        trust_store_path=overlap_trust,
        lock_output_path=current_lock,
        lock_environment_path=current_lock,
        secret_store_output_path=tmp_path / "current.secret.json",
        secret_store_environment_path=tmp_path / "current.secret.json",
        secret_protection=TEST_SECRET_PROTECTION,
        expected_subject=SUBJECT,
        now=now,
    )
    with pytest.raises(ModelCredentialError, match="回退 issuer key epoch"):
        install_model_credential_bundle(
            bundle_path=hostile_bundle,
            activation_code=read_activation_code_file(hostile_activation),
            trust_store_path=overlap_trust,
            lock_output_path=tmp_path / "must-not-exist.lock.json",
            lock_environment_path=tmp_path / "must-not-exist.lock.json",
            secret_store_output_path=tmp_path / "must-not-exist.secret.json",
            secret_store_environment_path=tmp_path / "must-not-exist.secret.json",
            secret_protection=TEST_SECRET_PROTECTION,
            expected_subject=SUBJECT,
            current_lock_path=current_lock,
            now=now,
        )


@pytest.mark.skip(reason="legacy model credential CLI was removed")
def test_cli_rotation_accepts_sanitized_windows_environment_when_old_credential_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The Windows importer can renew an expired but intact old credential.

    Its staging env intentionally omits the active lock/store pointers, so the
    CLI must determine update state from the fixed final files and validate the
    predecessor cryptographically instead of loading it as runtime Settings.
    """

    current = datetime.now(UTC).replace(microsecond=0)
    old_now = current - timedelta(days=200)
    private_key, _public_key, trust_store = _issuer(tmp_path)

    first_profile = _profile(
        tmp_path / "expired-profile-v1.json", version=1, now=old_now
    )
    first_bundle = tmp_path / "expired-v1.mgllm"
    first_activation = tmp_path / "expired-v1.activation"
    create_model_credential_bundle(
        first_profile,
        API_KEY_V1,
        private_key,
        PASSPHRASE,
        first_bundle,
        first_activation,
        issuer_trust_store_path=trust_store,
        now=old_now,
    )
    final_lock = tmp_path / "config" / "model-credential-lock.json"
    final_store = tmp_path / "config" / "model-credentials.store"
    final_lock.parent.mkdir()
    install_model_credential_bundle(
        bundle_path=first_bundle,
        activation_code=read_activation_code_file(first_activation),
        trust_store_path=trust_store,
        lock_output_path=final_lock,
        lock_environment_path=final_lock,
        secret_store_output_path=final_store,
        secret_store_environment_path=final_store,
        secret_protection=TEST_SECRET_PROTECTION,
        expected_subject=SUBJECT,
        now=old_now,
    )
    with pytest.raises(ModelCredentialError, match="有效期"):
        load_model_credential_lock(
            lock_path=final_lock,
            secret_store_path=final_store,
            trust_store_path=trust_store,
            expected_subject=SUBJECT,
            now=current,
        )

    second_profile = _profile(tmp_path / "profile-v2.json", version=2, now=current)
    second_bundle = tmp_path / "renewal-v2.mgllm"
    second_activation = tmp_path / "renewal-v2.activation"
    create_model_credential_bundle(
        second_profile,
        API_KEY_V2,
        private_key,
        PASSPHRASE,
        second_bundle,
        second_activation,
        issuer_trust_store_path=trust_store,
        previous_bundle_path=first_bundle,
        previous_activation_code=read_activation_code_file(first_activation),
        now=current,
    )

    # Deliberately expose only provisioning identity to Settings, matching the
    # model-import.env built by the Windows transaction script.
    fake_settings = SimpleNamespace(
        provisioning_status=SimpleNamespace(managed=True, pair_id=SUBJECT["pair_id"]),
        five_quantity_identity=SimpleNamespace(
            mine_id=SUBJECT["mine_id"],
            system_id=SUBJECT["system_id"],
            operator_id=SUBJECT["party_id"],
        ),
        production_mode=False,
    )
    monkeypatch.setattr(
        "enterprise_agent.cli.Settings.from_environment",
        lambda: fake_settings,
    )
    new_lock = tmp_path / "staging-v2.lock"
    new_store = tmp_path / "staging-v2.store"
    result = main(
        [
            "model-credential-import",
            "--bundle",
            str(second_bundle),
            "--activation-code-file",
            str(second_activation),
            "--trust-store",
            str(trust_store),
            "--lock-output",
            str(new_lock),
            "--lock-env-path",
            str(final_lock),
            "--secret-store",
            str(new_store),
            "--secret-store-env-path",
            str(final_store),
            "--secret-protection",
            TEST_SECRET_PROTECTION,
            "--expected-mine-id",
            SUBJECT["mine_id"],
            "--expected-system-id",
            SUBJECT["system_id"],
            "--expected-party-id",
            SUBJECT["party_id"],
            "--current-lock",
            str(final_lock),
        ]
    )

    assert result == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["credential_version"] == 2
    assert summary["managed"] is True
    # Mirror the Windows transaction's final same-volume switch.  The staged
    # lock deliberately binds the eventual fixed store path, never its staging
    # name.
    model_credential_state_path(final_lock).unlink()
    final_lock.unlink()
    final_store.unlink()
    new_store.replace(final_store)
    model_credential_state_path(new_lock).replace(
        model_credential_state_path(final_lock)
    )
    new_lock.replace(final_lock)
    rotated_config, rotated_status = load_model_credential_lock(
        lock_path=final_lock,
        secret_store_path=final_store,
        trust_store_path=trust_store,
        expected_subject=SUBJECT,
        now=current,
    )
    assert rotated_status.credential_version == 2
    assert rotated_config.api_key == API_KEY_V2
