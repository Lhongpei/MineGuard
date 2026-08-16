from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.x509.oid import NameOID

from enterprise_agent.auth import hash_password
from enterprise_agent.cli import _configuration_errors, main
from enterprise_agent.environment import parse_environment_file
from enterprise_agent.five_quantity_exchange import (
    FiveQuantityPlatformClient,
    FiveQuantityPlatformConfig,
)
from enterprise_agent.provisioning import (
    ProvisioningError,
    apply_provisioning_lock,
    install_provisioning_bundle,
    normalize_activation_code,
)
from enterprise_agent.settings import Settings
from enterprise_agent.util import canonical_json

TEST_SECRET_PROTECTION = (
    "dpapi-local-machine" if os.name == "nt" else "posix-0600"
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _time(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _ca() -> bytes:
    key = Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MineGuard Test CA")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, algorithm=None)
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


def _users_json() -> str:
    return canonical_json(
        [
            {
                "actor_id": "preparer-qy-001",
                "name": "正式经办人员",
                "role": "企业经办人",
                "password_hash": hash_password("MineGuard!Prepare2026"),
                "permissions": ["read", "write"],
                "must_change_password": False,
                "credential_provenance": "production_hash_command",
            },
            {
                "actor_id": "reviewer-qy-001",
                "name": "正式复核人员",
                "role": "企业复核负责人",
                "password_hash": hash_password("MineGuard!Review2026"),
                "permissions": ["read", "confirm", "submit"],
                "must_change_password": False,
                "credential_provenance": "production_hash_command",
            },
        ]
    )


def _bundle_fixture(
    tmp_path: Path,
    *,
    expired: bool = False,
    previous: dict[str, object] | None = None,
    profile_version: int | None = None,
    pair_id: str | None = None,
    signing_key: Ed25519PrivateKey | None = None,
    retain_previous: bool = True,
    mine_id: str = "MINE-QY-001",
    issuer_id: str = "mineguard-provisioning-authority",
    issuer_key_id: str = "provisioning-ed25519-2026q3",
    regulatory_key_id: str = "regulator-message-2026q3",
    rotate_keys: bool = True,
    mine_name: str = "沁源青岭煤矿",
    platform_base_url: str = "https://platform.qinyuan.internal",
    extra_config: dict[str, str] | None = None,
) -> dict[str, object]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC).replace(microsecond=0)
    if profile_version is None:
        profile_version = (
            int(previous["profile_version"]) + 1 if previous is not None else 1
        )
    if pair_id is None:
        pair_id = (
            str(previous["pair_id"])
            if previous is not None
            else "11111111-1111-4111-8111-111111111111"
        )
    if signing_key is None and previous is not None:
        inherited_signer = previous["signing_key"]
        assert isinstance(inherited_signer, Ed25519PrivateKey)
        signing_key = inherited_signer
    private_key = signing_key or Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ca_bytes = _ca()
    ca_target = tmp_path / "platform-ca.pem"
    ca_target.write_bytes(ca_bytes)
    os.chmod(ca_target, 0o600)
    application_secret = (
        f"A9!application-secret-v{profile_version}-2026-abcdefghijklmnopqrstuvwxyz"
    )
    transport_secret = (
        f"B8@transport-secret-v{profile_version}-2026-zyxwvutsrqponmlkjihgfedcba"
    )
    enterprise_key_id = f"mine-qy-message-v{profile_version}-2026q3"
    if previous is not None and not rotate_keys:
        application_secret = str(previous["application_secret"])
        transport_secret = str(previous["transport_secret"])
        enterprise_key_id = str(previous["enterprise_key_id"])
    config = {
        "ENTERPRISE_AGENT_FOUR_EYES_REQUIRED": "true",
        "ENTERPRISE_AGENT_PRODUCTION_MODE": "true",
        "ENTERPRISE_AGENT_PUBLIC_ORIGIN": "https://agent.mine.internal",
        "ENTERPRISE_AGENT_SECURE_COOKIE": "true",
        "ENTERPRISE_CAPACITY_BAND": "0.9-1.2Mtpa",
        "ENTERPRISE_COAL_TYPE": "thermal-coal",
        "ENTERPRISE_EXCHANGE_HMAC_SECRET": application_secret,
        "ENTERPRISE_EXCHANGE_KEY_ID": enterprise_key_id,
        "ENTERPRISE_MINE_ID": mine_id,
        "ENTERPRISE_MINE_NAME": mine_name,
        "ENTERPRISE_MINING_METHOD": "underground-longwall",
        "ENTERPRISE_OPERATING_REGIME": "normal-production",
        "ENTERPRISE_OPERATOR_ID": "operator-qy-001",
        "ENTERPRISE_OPERATOR_NAME": "沁源青岭煤业有限公司",
        "ENTERPRISE_REPORTING_TIMEZONE": "Asia/Shanghai",
        "ENTERPRISE_SHIFT_SYSTEM": "three-shift-eight-hour",
        "ENTERPRISE_SYSTEM_ID": "agent-mine-qy-001",
        "PLATFORM_V3_BASE_URL": platform_base_url,
        "PLATFORM_V3_CA_BUNDLE": str(ca_target),
        "PLATFORM_V3_SENDER_ID": "agent-mine-qy-001",
        "PLATFORM_V3_TRANSPORT_HMAC_SECRET": transport_secret,
        "REGULATORY_EXCHANGE_KEY_ID": regulatory_key_id,
        "REGULATORY_PARTY_ID": "regulator-qinyuan",
        "REGULATORY_SYSTEM_ID": "mineguard-qinyuan",
    }
    if previous is not None and retain_previous:
        config.update(
            {
                "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON": canonical_json(
                    [
                        {
                            "key_id": previous["enterprise_key_id"],
                            "secret": previous["application_secret"],
                        }
                    ]
                ),
                "REGULATORY_PREVIOUS_EXCHANGE_KEY_ID": (
                    previous["regulatory_key_id"]
                ),
                "REGULATORY_PREVIOUS_EXCHANGE_HMAC_SECRET": previous[
                    "application_secret"
                ],
            }
        )
    if extra_config:
        config.update(extra_config)
    bundle_id = f"22222222-2222-4222-8222-{profile_version:012d}"
    locked_keys = sorted(config)
    payload = {
        "kind": "enterprise-agent-provisioning",
        "bundle_id": bundle_id,
        "pair_id": pair_id,
        "profile_version": profile_version,
        "config": config,
        "locked_keys": locked_keys,
    }
    activation = _b64url(os.urandom(32)).encode("ascii")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    expires = now - timedelta(minutes=1) if expired else now + timedelta(days=7)
    protected = {
        "contract_version": "mineguard-provisioning-bundle-v1",
        "bundle_kind": "enterprise-agent-provisioning",
        "bundle_id": bundle_id,
        "pair_id": pair_id,
        "profile_version": profile_version,
        "issued_at": _time(now - timedelta(minutes=10 if expired else 1)),
        "expires_at": _time(expires),
        "issuer_id": issuer_id,
        "issuer_key_id": issuer_key_id,
        "subject": {
            "mine_id": config["ENTERPRISE_MINE_ID"],
            "system_id": config["ENTERPRISE_SYSTEM_ID"],
            "party_id": config["ENTERPRISE_OPERATOR_ID"],
        },
        "payload_sha256": hashlib.sha256(
            canonical_json(payload).encode()
        ).hexdigest(),
        "locked_config_sha256": hashlib.sha256(
            canonical_json(config).encode()
        ).hexdigest(),
        "locked_keys": locked_keys,
        "encryption": {
            "algorithm": "aes-256-gcm",
            "kdf": "scrypt",
            "salt": _b64url(salt),
            "n": 16384,
            "r": 8,
            "p": 1,
            "nonce": _b64url(nonce),
        },
    }
    key = Scrypt(salt=salt, length=32, n=16384, r=8, p=1).derive(activation)
    ciphertext = _b64url(
        AESGCM(key).encrypt(
            nonce,
            canonical_json(payload).encode(),
            canonical_json(protected).encode(),
        )
    )
    signed = {"protected": protected, "ciphertext": ciphertext}
    document = {
        **signed,
        "signature": _b64url(
            private_key.sign(canonical_json(signed).encode())
        ),
    }
    bundle_path = tmp_path / "mine.mgprov"
    bundle_path.write_text(canonical_json(document) + "\n", encoding="utf-8")
    public_path = tmp_path / "issuer-public.pem"
    public_path.write_bytes(public_pem)
    base_env = tmp_path / "base.env"
    base_env.write_text(
        "\n".join(
            (
                f"ENTERPRISE_AGENT_DB={tmp_path / 'agent.db'}",
                "ENTERPRISE_AGENT_PORT=8090",
                f"ENTERPRISE_AGENT_USERS_JSON={_users_json()}",
                "PLATFORM_BASE_URL=https://legacy-endpoint.internal",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "bundle": bundle_path,
        "public_key": public_path,
        "public_fingerprint": hashlib.sha256(public_der).hexdigest(),
        "activation": activation,
        "ca": ca_target,
        "ca_sha256": hashlib.sha256(ca_bytes).hexdigest(),
        "base_env": base_env,
        "application_secret": application_secret,
        "transport_secret": transport_secret,
        "enterprise_key_id": enterprise_key_id,
        "pair_id": pair_id,
        "profile_version": profile_version,
        "signing_key": private_key,
        "issuer_id": issuer_id,
        "issuer_key_id": issuer_key_id,
        "regulatory_key_id": regulatory_key_id,
        "mine_id": mine_id,
        "expires_at": expires,
    }


def _install(
    tmp_path: Path,
    fixture: dict[str, object],
    *,
    current_lock: Path | None = None,
    now: datetime | None = None,
):
    env = tmp_path / "agent.env"
    lock = tmp_path / "provisioning-lock.json"
    store = tmp_path / "secrets.json"
    result = install_provisioning_bundle(
        bundle_path=fixture["bundle"],
        activation_code=fixture["activation"],
        issuer_public_key_path=fixture["public_key"],
        expected_public_key_sha256=str(fixture["public_fingerprint"]),
        expected_issuer_key_id=str(fixture["issuer_key_id"]),
        allow_unanchored_test_key=False,
        base_environment_path=fixture["base_env"],
        output_environment_path=env,
        lock_output_path=lock,
        lock_environment_path=lock,
        secret_store_output_path=store,
        secret_store_environment_path=store,
        ca_source_path=fixture["ca"],
        expected_ca_sha256=str(fixture["ca_sha256"]),
        secret_protection=TEST_SECRET_PROTECTION,
        expected_mine_id=str(fixture["mine_id"]),
        expected_system_id="agent-mine-qy-001",
        current_lock_path=current_lock,
        now=now,
    )
    return result, env, lock, store


def test_import_hides_secrets_and_runtime_lock_restores_them(tmp_path: Path) -> None:
    fixture = _bundle_fixture(tmp_path)
    result, env, _lock, store = _install(tmp_path, fixture)

    encoded_env = env.read_text(encoding="utf-8")
    assert str(fixture["application_secret"]) not in encoded_env
    assert str(fixture["transport_secret"]) not in encoded_env
    assert "ENTERPRISE_EXCHANGE_HMAC_SECRET=" not in encoded_env
    assert "PLATFORM_BASE_URL=" not in encoded_env
    assert result.summary["production_ready"] is True
    assert result.summary["mine_id"] == "MINE-QY-001"
    if os.name != "nt":
        assert stat_mode(store) == 0o600

    environment = parse_environment_file(env)
    status = apply_provisioning_lock(environment)
    assert status.managed is True
    assert status.bundle_id == result.summary["bundle_id"]
    assert environment["ENTERPRISE_EXCHANGE_HMAC_SECRET"] == fixture[
        "application_secret"
    ]
    assert environment["PLATFORM_V3_TRANSPORT_HMAC_SECRET"] == fixture[
        "transport_secret"
    ]
    assert environment["PLATFORM_V3_SUBMISSION_PATH"] == (
        "/v3/ten-quantity-submissions"
    )
    assert apply_provisioning_lock(environment).managed is True
    environment["ENTERPRISE_EXCHANGE_HMAC_SECRET"] = "X" * 64
    with pytest.raises(ProvisioningError, match="secret.*覆盖"):
        apply_provisioning_lock(environment)
    environment = parse_environment_file(env)
    environment["PLATFORM_V2_BASE_URL"] = "https://legacy.internal"
    with pytest.raises(ProvisioningError, match="旧版监管端点"):
        apply_provisioning_lock(environment)


def test_settings_starts_from_locked_environment_in_production(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _bundle_fixture(tmp_path)
    _result, env, _lock, _store = _install(tmp_path, fixture)
    values = parse_environment_file(env)
    prefixes = ("ENTERPRISE_", "PLATFORM_", "REGULATORY_", "AGENT_V2_")
    for name in tuple(os.environ):
        if name.startswith(prefixes):
            monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    settings = Settings.from_environment()

    assert settings.provisioning_status.managed is True
    assert settings.five_quantity_identity.mine_id == "MINE-QY-001"
    assert settings.five_quantity_platform is not None
    assert settings.five_quantity_platform.analysis_path == "/v3/analysis-reports"
    assert _configuration_errors(settings, production=True) == ()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_activation_code_has_one_cross_product_normalization_rule() -> None:
    value = _b64url(bytes(range(32))).encode("ascii")
    assert len(value) == 43
    assert normalize_activation_code(value) == value
    assert normalize_activation_code(value + b"\n") == value
    assert normalize_activation_code(value + b"\r\n") == value
    for invalid in (value + b" ", b" " + value, value + b"\n\n", value[:-1]):
        with pytest.raises(ProvisioningError, match="43 字符 Base64URL"):
            normalize_activation_code(invalid)


@pytest.mark.parametrize("invalid_mine_id", ("MINE/QY-001", "MINE@QY-001"))
def test_provisioning_identifiers_match_contract_safe_identifier(
    tmp_path: Path,
    invalid_mine_id: str,
) -> None:
    fixture = _bundle_fixture(tmp_path, mine_id=invalid_mine_id)

    with pytest.raises(ProvisioningError, match="subject.mine_id.*有效标识"):
        _install(tmp_path, fixture)


@pytest.mark.parametrize(
    ("fixture_options", "error_pattern"),
    (
        ({"issuer_id": "demo-authority"}, "issuer_id.*占位标识"),
        ({"mine_id": "test-mine"}, "subject.mine_id.*占位标识"),
        (
            {"regulatory_key_id": "unknown-regulator-key"},
            "REGULATORY_EXCHANGE_KEY_ID.*占位标识",
        ),
        ({"mine_name": "示例煤矿"}, "MINE_NAME.*占位值"),
        ({"mine_name": "沁源\t煤矿"}, "MINE_NAME.*值非法"),
        ({"mine_name": "沁源\u0085煤矿"}, "MINE_NAME.*值非法"),
    ),
)
def test_provisioning_rejects_production_placeholders_and_controls(
    tmp_path: Path,
    fixture_options: dict[str, str],
    error_pattern: str,
) -> None:
    fixture = _bundle_fixture(tmp_path, **fixture_options)

    with pytest.raises(ProvisioningError, match=error_pattern):
        _install(tmp_path, fixture)


def test_provisioning_bundle_cannot_carry_model_api_credentials(
    tmp_path: Path,
) -> None:
    fixture = _bundle_fixture(
        tmp_path,
        extra_config={"MINEGUARD_AGENT_API_KEY": "must-stay-enterprise-local"},
    )

    with pytest.raises(ProvisioningError, match="locked_keys.*(?:非法|未知字段)"):
        _install(tmp_path, fixture)


def test_envelope_rejects_json_boolean_for_integer_kdf_parameter(
    tmp_path: Path,
) -> None:
    fixture = _bundle_fixture(tmp_path)
    bundle_path = Path(str(fixture["bundle"]))
    document = json.loads(bundle_path.read_text(encoding="utf-8"))
    document["protected"]["encryption"]["p"] = True
    signed = {
        "protected": document["protected"],
        "ciphertext": document["ciphertext"],
    }
    signer = fixture["signing_key"]
    assert isinstance(signer, Ed25519PrivateKey)
    document["signature"] = _b64url(
        signer.sign(canonical_json(signed).encode())
    )
    bundle_path.write_text(canonical_json(document) + "\n", encoding="utf-8")

    with pytest.raises(ProvisioningError, match="加密参数不受支持"):
        _install(tmp_path, fixture)


def test_malformed_ipv6_origin_is_a_bounded_provisioning_error(
    tmp_path: Path,
) -> None:
    fixture = _bundle_fixture(
        tmp_path,
        platform_base_url="https://[2001:db8::1",
    )

    with pytest.raises(ProvisioningError, match="端口或主机格式非法"):
        _install(tmp_path, fixture)


def test_https_origin_rejects_zero_port(tmp_path: Path) -> None:
    fixture = _bundle_fixture(
        tmp_path,
        platform_base_url="https://platform.qinyuan.internal:0",
    )

    with pytest.raises(ProvisioningError, match="端口必须为 1-65535"):
        _install(tmp_path, fixture)


@pytest.mark.parametrize(
    "reserved_origin",
    (
        "https://example.com",
        "https://api.example.net",
        "https://mine.example.org",
    ),
)
def test_https_origin_rejects_rfc_example_hosts(
    tmp_path: Path,
    reserved_origin: str,
) -> None:
    fixture = _bundle_fixture(tmp_path, platform_base_url=reserved_origin)

    with pytest.raises(ProvisioningError, match="保留或示例主机"):
        _install(tmp_path, fixture)


def test_runtime_rejects_environment_and_lock_tampering(tmp_path: Path) -> None:
    fixture = _bundle_fixture(tmp_path)
    _result, env, lock, _store = _install(tmp_path, fixture)

    environment = parse_environment_file(env)
    environment["ENTERPRISE_MINE_ID"] = "MINE-ATTACKER"
    with pytest.raises(ProvisioningError, match="覆盖"):
        apply_provisioning_lock(environment)

    with pytest.raises(ProvisioningError, match="lock 缺失"):
        apply_provisioning_lock(
            {"ENTERPRISE_PROVISIONING_MANAGED_REQUIRED": "true"}
        )

    document = json.loads(lock.read_text(encoding="utf-8"))
    document["managed_environment"]["ENTERPRISE_MINE_NAME"] = "被篡改煤矿"
    lock.write_text(canonical_json(document) + "\n", encoding="utf-8")
    os.chmod(lock, 0o600)
    environment = parse_environment_file(env)
    environment["ENTERPRISE_MINE_NAME"] = "被篡改煤矿"
    with pytest.raises(ProvisioningError, match="完整性"):
        apply_provisioning_lock(environment)


def test_import_rejects_wrong_external_fingerprints_and_expiry(
    tmp_path: Path,
) -> None:
    fixture = _bundle_fixture(tmp_path)
    with pytest.raises(ProvisioningError, match="公钥.*不匹配"):
        install_provisioning_bundle(
            bundle_path=fixture["bundle"],
            activation_code=fixture["activation"],
            issuer_public_key_path=fixture["public_key"],
            expected_public_key_sha256="0" * 64,
            expected_issuer_key_id="provisioning-ed25519-2026q3",
            allow_unanchored_test_key=False,
            base_environment_path=fixture["base_env"],
            output_environment_path=tmp_path / "bad.env",
            lock_output_path=tmp_path / "bad.lock",
            lock_environment_path=tmp_path / "bad.lock",
            secret_store_output_path=tmp_path / "bad.store",
            secret_store_environment_path=tmp_path / "bad.store",
            ca_source_path=fixture["ca"],
            expected_ca_sha256=str(fixture["ca_sha256"]),
        )

    with pytest.raises(ProvisioningError, match="issuer_key_id.*不匹配"):
        install_provisioning_bundle(
            bundle_path=fixture["bundle"],
            activation_code=fixture["activation"],
            issuer_public_key_path=fixture["public_key"],
            expected_public_key_sha256=str(fixture["public_fingerprint"]),
            expected_issuer_key_id="wrong-approved-key-id",
            allow_unanchored_test_key=False,
            base_environment_path=fixture["base_env"],
            output_environment_path=tmp_path / "bad-key-id.env",
            lock_output_path=tmp_path / "bad-key-id.lock",
            lock_environment_path=tmp_path / "bad-key-id.lock",
            secret_store_output_path=tmp_path / "bad-key-id.store",
            secret_store_environment_path=tmp_path / "bad-key-id.store",
            ca_source_path=fixture["ca"],
            expected_ca_sha256=str(fixture["ca_sha256"]),
        )

    with pytest.raises(ProvisioningError, match="CA bundle.*不匹配"):
        install_provisioning_bundle(
            bundle_path=fixture["bundle"],
            activation_code=fixture["activation"],
            issuer_public_key_path=fixture["public_key"],
            expected_public_key_sha256=str(fixture["public_fingerprint"]),
            expected_issuer_key_id="provisioning-ed25519-2026q3",
            allow_unanchored_test_key=False,
            base_environment_path=fixture["base_env"],
            output_environment_path=tmp_path / "bad-ca.env",
            lock_output_path=tmp_path / "bad-ca.lock",
            lock_environment_path=tmp_path / "bad-ca.lock",
            secret_store_output_path=tmp_path / "bad-ca.store",
            secret_store_environment_path=tmp_path / "bad-ca.store",
            ca_source_path=fixture["ca"],
            expected_ca_sha256="0" * 64,
        )

    expired_directory = tmp_path / "expired"
    expired_directory.mkdir()
    expired = _bundle_fixture(expired_directory, expired=True)
    with pytest.raises(ProvisioningError, match="安装有效期"):
        _install(expired_directory, expired)

    exact_deadline_directory = tmp_path / "exact-deadline"
    exact_deadline = _bundle_fixture(exact_deadline_directory)
    deadline = exact_deadline["expires_at"]
    assert isinstance(deadline, datetime)
    with pytest.raises(ProvisioningError, match="安装有效期"):
        _install(exact_deadline_directory, exact_deadline, now=deadline)


def test_create_new_outputs_never_overwrite_existing_files(tmp_path: Path) -> None:
    fixture = _bundle_fixture(tmp_path)
    _result, env, _lock, _store = _install(tmp_path, fixture)
    original = env.read_bytes()

    with pytest.raises(FileExistsError):
        _install(tmp_path, fixture)
    assert env.read_bytes() == original


def test_upgrade_requires_exact_version_pair_and_adjacent_key_retention(
    tmp_path: Path,
) -> None:
    first_directory = tmp_path / "v1"
    first = _bundle_fixture(first_directory)
    _result, _env, current_lock, _store = _install(first_directory, first)

    second_directory = tmp_path / "v2"
    second = _bundle_fixture(second_directory, previous=first)
    second_result, _env, _lock, _store = _install(
        second_directory,
        second,
        current_lock=current_lock,
    )
    assert second_result.summary["profile_version"] == 2

    jumped_directory = tmp_path / "jumped"
    jumped = _bundle_fixture(
        jumped_directory,
        previous=first,
        profile_version=3,
    )
    with pytest.raises(ProvisioningError, match="精确递增 1"):
        _install(jumped_directory, jumped, current_lock=current_lock)

    wrong_pair_directory = tmp_path / "wrong-pair"
    wrong_pair = _bundle_fixture(
        wrong_pair_directory,
        previous=first,
        pair_id="33333333-3333-4333-8333-333333333333",
    )
    with pytest.raises(ProvisioningError, match="pair_id"):
        _install(wrong_pair_directory, wrong_pair, current_lock=current_lock)

    no_history_directory = tmp_path / "no-history"
    no_history = _bundle_fixture(
        no_history_directory,
        previous=first,
        retain_previous=False,
    )
    with pytest.raises(ProvisioningError, match="保留紧邻上一版企业应用密钥"):
        _install(no_history_directory, no_history, current_lock=current_lock)

    wrong_subject_directory = tmp_path / "wrong-subject"
    wrong_subject = _bundle_fixture(
        wrong_subject_directory,
        previous=first,
        mine_id="MINE-QY-OTHER",
    )
    with pytest.raises(ProvisioningError, match="不得改变.*身份"):
        _install(wrong_subject_directory, wrong_subject, current_lock=current_lock)

    wrong_signer_directory = tmp_path / "wrong-signer"
    wrong_signer = _bundle_fixture(
        wrong_signer_directory,
        previous=first,
        signing_key=Ed25519PrivateKey.generate(),
    )
    with pytest.raises(ProvisioningError, match="不得切换.*签发公钥"):
        _install(wrong_signer_directory, wrong_signer, current_lock=current_lock)

    wrong_issuer_directory = tmp_path / "wrong-issuer"
    wrong_issuer = _bundle_fixture(
        wrong_issuer_directory,
        previous=first,
        issuer_key_id="provisioning-ed25519-other",
    )
    with pytest.raises(ProvisioningError, match="不得改变 issuer_key_id"):
        _install(wrong_issuer_directory, wrong_issuer, current_lock=current_lock)

    wrong_regulator_directory = tmp_path / "wrong-regulator"
    wrong_regulator = _bundle_fixture(
        wrong_regulator_directory,
        previous=first,
        regulatory_key_id="regulator-message-other",
    )
    with pytest.raises(ProvisioningError, match="政府全局应用 key_id"):
        _install(
            wrong_regulator_directory,
            wrong_regulator,
            current_lock=current_lock,
        )

    not_rotated_directory = tmp_path / "not-rotated"
    not_rotated = _bundle_fixture(
        not_rotated_directory,
        previous=first,
        retain_previous=False,
        rotate_keys=False,
    )
    with pytest.raises(ProvisioningError, match="必须轮换企业当前应用"):
        _install(not_rotated_directory, not_rotated, current_lock=current_lock)


def test_cli_import_outputs_only_non_secret_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _bundle_fixture(tmp_path)
    activation_file = tmp_path / "activation.txt"
    activation_file.write_bytes(bytes(fixture["activation"]) + b"\n")
    env = tmp_path / "cli-agent.env"
    lock = tmp_path / "cli-lock.json"
    store = tmp_path / "cli-secrets.json"

    result = main(
        [
            "provision-import",
            "--bundle",
            str(fixture["bundle"]),
            "--activation-code-file",
            str(activation_file),
            "--issuer-public-key",
            str(fixture["public_key"]),
            "--expected-public-key-sha256",
            str(fixture["public_fingerprint"]),
            "--expected-issuer-key-id",
            "provisioning-ed25519-2026q3",
            "--ca-source",
            str(fixture["ca"]),
            "--expected-ca-sha256",
            str(fixture["ca_sha256"]),
            "--base-env",
            str(fixture["base_env"]),
            "--output-env",
            str(env),
            "--lock-output",
            str(lock),
            "--lock-env-path",
            str(lock),
            "--secret-store",
            str(store),
            "--secret-store-env-path",
            str(store),
            "--secret-protection",
            TEST_SECRET_PROTECTION,
            "--expected-mine-id",
            "MINE-QY-001",
            "--expected-system-id",
            "agent-mine-qy-001",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert '"production_ready": true' in captured.out
    assert "MINE-QY-001" in captured.out
    assert str(fixture["application_secret"]) not in captured.out + captured.err
    assert str(fixture["transport_secret"]) not in captured.out + captured.err
    assert bytes(fixture["activation"]).decode() not in captured.out + captured.err


def test_every_platform_request_rechecks_provisioning_guard() -> None:
    calls: list[str] = []

    def guard() -> None:
        calls.append("guard")
        raise ProvisioningError("封存配置运行时已改变")

    def opener(*_args, **_kwargs):
        raise AssertionError("guard failure must happen before network access")

    client = FiveQuantityPlatformClient(
        FiveQuantityPlatformConfig(
            base_url="https://platform.qinyuan.internal",
            sender_id="agent-mine-qy-001",
            transport_hmac_secret=(
                "transport-runtime-guard-secret-abcdefghijklmnopqrstuvwxyz"
            ),
        ),
        opener=opener,
        configuration_guard=guard,
    )

    with pytest.raises(ProvisioningError, match="运行时已改变"):
        client.pull_next()
    assert calls == ["guard"]
