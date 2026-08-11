from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from enterprise_agent.model_credentials import (
    LOCK_ENVIRONMENT,
    SECRET_STORE_ENVIRONMENT,
    TRUST_STORE_ENVIRONMENT,
    ModelCredentialError,
    install_model_credential_bundle,
    load_managed_model_credential,
    load_model_credential_from_environment,
    load_model_credential_lock,
    model_credential_state_path,
    read_activation_code_file,
    release_model_trust_store_path,
    verify_and_decrypt_model_bundle,
)
from enterprise_agent.model_issuer import (
    create_model_credential_bundle,
    issuer_init,
)
from enterprise_agent.util import canonical_json

NOW = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)
PASSPHRASE = b"MineGuard issuer passphrase 2026!"
API_KEY_V1 = "sk-enterprise-one-" + "a" * 48
API_KEY_V2 = "sk-enterprise-two-" + "b" * 48
CREDENTIAL_ID = "22222222-2222-4222-8222-222222222222"
SUBJECT = {
    "mine_id": "MINE-QY-001",
    "system_id": "agent-mine-qy-001",
    "party_id": "operator-qy-001",
    "pair_id": "11111111-1111-4111-8111-111111111111",
}
PROVIDER = {
    "provider_id": "deepseek-enterprise-direct",
    "protocol": "openai-compatible-chat-completions",
    "base_url": "https://api.deepseek.com/v1",
    "model": "deepseek-chat",
    "capabilities": ["chat", "coal-news-search", "extraction"],
    "timeout_seconds": 20.0,
    "max_retries": 2,
}


@pytest.fixture
def issuer(tmp_path: Path) -> dict[str, Path]:
    private_key = tmp_path / "model-issuer-private.pem"
    public_key = tmp_path / "model-issuer-public.pem"
    trust_store = tmp_path / "model-credential-trust.json"
    issuer_init(
        private_key,
        public_key,
        trust_store,
        "mineguard-model-authority",
        "model-ed25519-2026q3",
        PASSPHRASE,
        issuer_key_epoch=1,
    )
    return {
        "private_key": private_key,
        "public_key": public_key,
        "trust_store": trust_store,
    }


def _profile(
    path: Path,
    *,
    version: int = 1,
    credential_id: str = CREDENTIAL_ID,
    subject: dict[str, str] | None = None,
    provider: dict[str, object] | None = None,
    now: datetime = NOW,
    install_before: datetime | None = None,
    runtime_not_after: datetime | None = None,
    issuer_id: str = "mineguard-model-authority",
    issuer_key_id: str = "model-ed25519-2026q3",
    issuer_key_epoch: int = 1,
) -> Path:
    document = {
        "credential_id": credential_id,
        "credential_version": version,
        "subject": dict(subject or SUBJECT),
        "provider": dict(provider or PROVIDER),
        "install_before": _utc_text(install_before or now + timedelta(days=7)),
        "runtime_not_after": _utc_text(runtime_not_after or now + timedelta(days=90)),
        "issuer_id": issuer_id,
        "issuer_key_id": issuer_key_id,
        "issuer_key_epoch": issuer_key_epoch,
    }
    path.write_text(canonical_json(document) + "\n", encoding="utf-8")
    return path


def _utc_text(value: datetime) -> str:
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _issue(
    tmp_path: Path,
    issuer: dict[str, Path],
    *,
    version: int = 1,
    api_key: str = API_KEY_V1,
    subject: dict[str, str] | None = None,
    credential_id: str = CREDENTIAL_ID,
    now: datetime = NOW,
    install_before: datetime | None = None,
    runtime_not_after: datetime | None = None,
    issuer_id: str = "mineguard-model-authority",
    issuer_key_id: str = "model-ed25519-2026q3",
    issuer_key_epoch: int = 1,
    prefix: str = "v1",
    previous_bundle: Path | None = None,
    previous_activation: bytes | None = None,
):
    profile = _profile(
        tmp_path / f"{prefix}-profile.json",
        version=version,
        credential_id=credential_id,
        subject=subject,
        now=now,
        install_before=install_before,
        runtime_not_after=runtime_not_after,
        issuer_id=issuer_id,
        issuer_key_id=issuer_key_id,
        issuer_key_epoch=issuer_key_epoch,
    )
    bundle = tmp_path / f"{prefix}.mgllm"
    activation_file = tmp_path / f"{prefix}.activation"
    result = create_model_credential_bundle(
        profile,
        api_key,
        issuer["private_key"],
        PASSPHRASE,
        bundle,
        activation_file,
        issuer_trust_store_path=issuer["trust_store"],
        previous_bundle_path=previous_bundle,
        previous_activation_code=previous_activation,
        now=now,
    )
    return bundle, activation_file, result


def _install(
    tmp_path: Path,
    issuer: dict[str, Path],
    bundle: Path,
    activation_file: Path,
    *,
    prefix: str = "installed-v1",
    expected_subject: dict[str, str] | None = None,
    current_lock: Path | None = None,
    now: datetime = NOW,
):
    lock = tmp_path / f"{prefix}-lock.json"
    secret_store = tmp_path / f"{prefix}-secret.json"
    result = install_model_credential_bundle(
        bundle_path=bundle,
        activation_code=read_activation_code_file(activation_file),
        trust_store_path=issuer["trust_store"],
        lock_output_path=lock,
        lock_environment_path=lock,
        secret_store_output_path=secret_store,
        secret_store_environment_path=secret_store,
        expected_subject=expected_subject or SUBJECT,
        current_lock_path=current_lock,
        now=now,
    )
    return lock, secret_store, result


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _managed_environment(
    lock: Path, secret_store: Path, trust_store: Path
) -> dict[str, str]:
    return {
        LOCK_ENVIRONMENT: str(lock),
        SECRET_STORE_ENVIRONMENT: str(secret_store),
        TRUST_STORE_ENVIRONMENT: str(trust_store),
    }


def test_round_trip_import_and_runtime_are_bound_and_do_not_leak(
    tmp_path: Path,
    issuer: dict[str, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "MINEGUARD_AGENT_API_KEY",
        "MINEGUARD_AGENT_BASE_URL",
        "MINEGUARD_AGENT_MODEL",
        "MINEGUARD_AGENT_TIMEOUT_SECONDS",
        "MINEGUARD_AGENT_MAX_RETRIES",
        "DEEPSEEK_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    environment_before = dict(os.environ)

    bundle, activation_file, issued = _issue(tmp_path, issuer)
    lock, secret_store, installed = _install(tmp_path, issuer, bundle, activation_file)
    environment = _managed_environment(lock, secret_store, issuer["trust_store"])
    config, status = load_model_credential_from_environment(
        expected_subject=SUBJECT,
        now=NOW,
        environment=environment,
    )
    managed = load_managed_model_credential(
        lock,
        secret_store_path=secret_store,
        trust_store_path=issuer["trust_store"],
        expected_subject=SUBJECT,
        now=NOW,
    )
    verified = verify_and_decrypt_model_bundle(
        bundle_path=bundle,
        activation_code=read_activation_code_file(activation_file),
        trust_store_path=issuer["trust_store"],
        expected_subject=SUBJECT,
        now=NOW,
    )

    assert config is not None
    assert config.api_key == API_KEY_V1
    assert config.base_url == PROVIDER["base_url"]
    assert config.model == PROVIDER["model"]
    assert managed.config == config
    assert status == managed.status
    assert status.managed is True
    assert status.state == "managed"
    assert status.credential_id == CREDENTIAL_ID
    assert UUID(status.credential_id).version == 4
    assert status.pair_id == SUBJECT["pair_id"]
    assert status.provider_id == PROVIDER["provider_id"]
    assert status.base_url == PROVIDER["base_url"]
    assert status.capabilities == tuple(PROVIDER["capabilities"])
    assert installed.summary["credential_version"] == 1
    assert os.environ == environment_before

    activation = read_activation_code_file(activation_file).decode("ascii")
    non_secret_renderings = (
        bundle.read_text(encoding="utf-8"),
        lock.read_text(encoding="utf-8"),
        issuer["trust_store"].read_text(encoding="utf-8"),
        canonical_json(issued.summary),
        canonical_json(installed.summary),
        canonical_json(status.as_dict()),
        canonical_json(environment),
        repr(config),
        repr(status),
        repr(managed),
        repr(verified),
    )
    for rendered in non_secret_renderings:
        assert API_KEY_V1 not in rendered
        assert activation not in rendered
        assert PASSPHRASE.decode("utf-8") not in rendered


def test_anti_rollback_state_is_required_and_binds_highest_version(
    tmp_path: Path,
    issuer: dict[str, Path],
) -> None:
    bundle_v1, activation_v1, _issued_v1 = _issue(tmp_path, issuer)
    lock_v1, store_v1, installed_v1 = _install(
        tmp_path, issuer, bundle_v1, activation_v1
    )
    state_v1 = model_credential_state_path(lock_v1)
    state_document = json.loads(state_v1.read_text(encoding="utf-8"))

    assert installed_v1.summary["anti_rollback_state_path"] == str(state_v1)
    assert state_document["highest_credential_version"] == 1
    assert state_document["accepted_bundle_id"] == installed_v1.summary["bundle_id"]
    assert len(state_document["accepted_envelope_sha256"]) == 64
    assert "api_key" not in state_document

    missing_state = tmp_path / "temporarily-missing.state.json"
    state_v1.replace(missing_state)
    with pytest.raises(ModelCredentialError, match="防回退状态"):
        load_model_credential_lock(
            lock_path=lock_v1,
            secret_store_path=store_v1,
            trust_store_path=issuer["trust_store"],
            expected_subject=SUBJECT,
            now=NOW,
        )
    missing_state.replace(state_v1)

    bundle_v2, activation_v2, _issued_v2 = _issue(
        tmp_path,
        issuer,
        version=2,
        api_key=API_KEY_V2,
        prefix="v2-watermark",
        previous_bundle=bundle_v1,
        previous_activation=read_activation_code_file(activation_v1),
    )
    staged_lock = tmp_path / "staged-v2.lock.json"
    staged_store = tmp_path / "staged-v2.secret.json"
    install_model_credential_bundle(
        bundle_path=bundle_v2,
        activation_code=read_activation_code_file(activation_v2),
        trust_store_path=issuer["trust_store"],
        lock_output_path=staged_lock,
        lock_environment_path=lock_v1,
        secret_store_output_path=staged_store,
        secret_store_environment_path=store_v1,
        expected_subject=SUBJECT,
        current_lock_path=lock_v1,
        now=NOW,
    )

    # The old lock/store may be restored accidentally, but the independently
    # published highest-version state remains at version 2 and blocks egress.
    state_v1.unlink()
    model_credential_state_path(staged_lock).replace(state_v1)
    with pytest.raises(ModelCredentialError, match="防回退状态"):
        load_model_credential_lock(
            lock_path=lock_v1,
            secret_store_path=store_v1,
            trust_store_path=issuer["trust_store"],
            expected_subject=SUBJECT,
            now=NOW,
        )


def test_wrong_activation_and_tampered_bundle_fail_closed_without_secrets(
    tmp_path: Path, issuer: dict[str, Path]
) -> None:
    bundle, activation_file, _issued = _issue(tmp_path, issuer)
    activation = read_activation_code_file(activation_file)
    replacement = b"B" if activation[:1] != b"B" else b"C"
    wrong_activation = replacement + activation[1:]

    with pytest.raises(ModelCredentialError) as wrong_error:
        verify_and_decrypt_model_bundle(
            bundle_path=bundle,
            activation_code=wrong_activation,
            trust_store_path=issuer["trust_store"],
            expected_subject=SUBJECT,
            now=NOW,
        )
    assert API_KEY_V1 not in str(wrong_error.value)
    assert activation.decode("ascii") not in str(wrong_error.value)
    assert wrong_activation.decode("ascii") not in str(wrong_error.value)

    document = json.loads(bundle.read_text(encoding="utf-8"))
    document["protected"]["subject"]["mine_id"] = "MINE-TAMPERED"
    tampered = tmp_path / "tampered.mgllm"
    tampered.write_text(canonical_json(document) + "\n", encoding="utf-8")
    with pytest.raises(ModelCredentialError, match="签名验证失败"):
        verify_and_decrypt_model_bundle(
            bundle_path=tampered,
            activation_code=activation,
            trust_store_path=issuer["trust_store"],
            now=NOW,
        )


def test_rogue_self_signed_bundle_is_not_a_trust_anchor(
    tmp_path: Path, issuer: dict[str, Path]
) -> None:
    rogue_dir = tmp_path / "rogue"
    rogue_dir.mkdir()
    rogue = {
        "private_key": rogue_dir / "private.pem",
        "public_key": rogue_dir / "public.pem",
        "trust_store": rogue_dir / "trust.json",
    }
    issuer_init(
        rogue["private_key"],
        rogue["public_key"],
        rogue["trust_store"],
        "rogue-model-authority",
        "rogue-ed25519-1",
        PASSPHRASE,
        issuer_key_epoch=1,
    )
    bundle, activation_file, _issued = _issue(
        rogue_dir,
        rogue,
        issuer_id="rogue-model-authority",
        issuer_key_id="rogue-ed25519-1",
        prefix="rogue-v1",
    )

    with pytest.raises(ModelCredentialError, match="不在发行版受信列表"):
        verify_and_decrypt_model_bundle(
            bundle_path=bundle,
            activation_code=read_activation_code_file(activation_file),
            trust_store_path=issuer["trust_store"],
            expected_subject=SUBJECT,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("mine_id", "MINE-OTHER"),
        ("system_id", "agent-other"),
        ("party_id", "operator-other"),
        ("pair_id", "33333333-3333-4333-8333-333333333333"),
    ],
)
def test_every_subject_field_including_pair_is_enforced(
    tmp_path: Path,
    issuer: dict[str, Path],
    field: str,
    replacement: str,
) -> None:
    bundle, activation_file, _issued = _issue(tmp_path, issuer)
    wrong_subject = {**SUBJECT, field: replacement}
    with pytest.raises(ModelCredentialError, match=rf"{field} 不匹配"):
        install_model_credential_bundle(
            bundle_path=bundle,
            activation_code=read_activation_code_file(activation_file),
            trust_store_path=issuer["trust_store"],
            lock_output_path=tmp_path / f"wrong-{field}-lock.json",
            lock_environment_path=tmp_path / f"wrong-{field}-lock.json",
            secret_store_output_path=tmp_path / f"wrong-{field}-secret.json",
            secret_store_environment_path=tmp_path / f"wrong-{field}-secret.json",
            expected_subject=wrong_subject,
            now=NOW,
        )


@pytest.mark.parametrize("target", ["lock", "store"])
def test_tampered_lock_or_store_is_rejected(
    tmp_path: Path, issuer: dict[str, Path], target: str
) -> None:
    bundle, activation_file, _issued = _issue(tmp_path, issuer)
    lock, secret_store, _installed = _install(tmp_path, issuer, bundle, activation_file)
    path = lock if target == "lock" else secret_store
    document = json.loads(path.read_text(encoding="utf-8"))
    if target == "lock":
        document["public_payload"]["provider"]["model"] = "tampered-model"
    else:
        document["credential_version"] = 2
    path.write_text(canonical_json(document) + "\n", encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)

    with pytest.raises(ModelCredentialError):
        load_managed_model_credential(
            lock,
            secret_store_path=secret_store,
            trust_store_path=issuer["trust_store"],
            expected_subject=SUBJECT,
            now=NOW,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode checks do not apply to Windows")
def test_posix_outputs_are_0600_and_relaxed_secret_permissions_fail_closed(
    tmp_path: Path, issuer: dict[str, Path]
) -> None:
    bundle, activation_file, _issued = _issue(tmp_path, issuer)
    lock, secret_store, _installed = _install(tmp_path, issuer, bundle, activation_file)
    for path in (
        issuer["private_key"],
        issuer["public_key"],
        issuer["trust_store"],
        bundle,
        activation_file,
        lock,
        secret_store,
    ):
        assert _mode(path) == 0o600

    os.chmod(secret_store, 0o640)
    with pytest.raises(ModelCredentialError, match="0600"):
        load_managed_model_credential(
            lock,
            secret_store_path=secret_store,
            trust_store_path=issuer["trust_store"],
            expected_subject=SUBJECT,
            now=NOW,
        )


@pytest.mark.parametrize(
    "plaintext_name", ["MINEGUARD_AGENT_API_KEY", "DEEPSEEK_API_KEY"]
)
def test_managed_credential_rejects_plaintext_environment_override(
    tmp_path: Path,
    issuer: dict[str, Path],
    plaintext_name: str,
) -> None:
    bundle, activation_file, _issued = _issue(tmp_path, issuer)
    lock, secret_store, _installed = _install(tmp_path, issuer, bundle, activation_file)
    environment = _managed_environment(lock, secret_store, issuer["trust_store"])
    environment[plaintext_name] = "attacker-controlled-plaintext-key"

    with pytest.raises(ModelCredentialError, match="禁止任何明文模型环境变量覆盖"):
        load_model_credential_from_environment(
            expected_subject=SUBJECT,
            now=NOW,
            environment=environment,
        )


def test_expired_managed_credential_cannot_load(
    tmp_path: Path, issuer: dict[str, Path]
) -> None:
    install_before = NOW + timedelta(minutes=30)
    runtime_not_after = NOW + timedelta(hours=1)
    bundle, activation_file, _issued = _issue(
        tmp_path,
        issuer,
        install_before=install_before,
        runtime_not_after=runtime_not_after,
    )
    lock, secret_store, _installed = _install(
        tmp_path, issuer, bundle, activation_file, now=NOW
    )

    with pytest.raises(ModelCredentialError, match="运行有效期"):
        load_managed_model_credential(
            lock,
            secret_store_path=secret_store,
            trust_store_path=issuer["trust_store"],
            expected_subject=SUBJECT,
            now=NOW + timedelta(hours=2),
        )


def test_rotation_requires_exactly_plus_one_and_never_reuses_old_key(
    tmp_path: Path, issuer: dict[str, Path]
) -> None:
    first_bundle, first_activation_file, _issued = _issue(tmp_path, issuer)
    first_activation = read_activation_code_file(first_activation_file)
    first_lock, _first_secret, _installed = _install(
        tmp_path, issuer, first_bundle, first_activation_file
    )

    with pytest.raises(ModelCredentialError, match="必须更换 API key"):
        _issue(
            tmp_path,
            issuer,
            version=2,
            api_key=API_KEY_V1,
            prefix="same-key-v2",
            previous_bundle=first_bundle,
            previous_activation=first_activation,
        )

    with pytest.raises(ModelCredentialError, match="精确递增 1"):
        _issue(
            tmp_path,
            issuer,
            version=3,
            api_key=API_KEY_V2,
            prefix="skipped-v3",
            previous_bundle=first_bundle,
            previous_activation=first_activation,
        )

    second_bundle, second_activation_file, issued_v2 = _issue(
        tmp_path,
        issuer,
        version=2,
        api_key=API_KEY_V2,
        prefix="v2",
        previous_bundle=first_bundle,
        previous_activation=first_activation,
    )
    second_lock, second_secret, installed_v2 = _install(
        tmp_path,
        issuer,
        second_bundle,
        second_activation_file,
        prefix="installed-v2",
        current_lock=first_lock,
    )
    managed_v2 = load_managed_model_credential(
        second_lock,
        secret_store_path=second_secret,
        trust_store_path=issuer["trust_store"],
        expected_subject=SUBJECT,
        now=NOW,
    )

    assert issued_v2.summary["credential_version"] == 2
    assert installed_v2.summary["credential_version"] == 2
    assert managed_v2.status.credential_version == 2
    assert managed_v2.config.api_key == API_KEY_V2


def test_credential_id_must_be_canonical_uuid4(
    tmp_path: Path, issuer: dict[str, Path]
) -> None:
    non_v4 = "d9428888-122b-11e1-b85c-61cd3cbb3210"
    with pytest.raises(ModelCredentialError, match="credential_id.*UUIDv4"):
        _issue(
            tmp_path,
            issuer,
            credential_id=non_v4,
            prefix="uuid-v1",
        )


def test_frozen_runtime_derives_trust_store_outside_runtime_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_executable = (
        tmp_path / "EnterpriseAgent" / "runtime" / "MineGuardEnterpriseAgent.exe"
    )
    monkeypatch.setattr(
        "enterprise_agent.model_credentials.sys.executable",
        str(fake_executable),
    )
    assert release_model_trust_store_path() == (
        tmp_path
        / "EnterpriseAgent"
        / "release-metadata"
        / "model-credential-trust.json"
    )
