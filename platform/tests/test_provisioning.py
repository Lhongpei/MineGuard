from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path

import pytest

import mineguard.provisioning as provisioning_module
from mineguard.exchange_v2 import parse_exchange_clients
from mineguard.provisioning import (
    AGENT_BUNDLE_KIND,
    EXPECTED_ISSUER_KEY_ID_ENV,
    EXPECTED_PUBLIC_KEY_SHA256_ENV,
    MANAGED_REQUIRED_ENV,
    REGISTRATION_BUNDLE_KIND,
    TRUSTED_PUBLIC_KEY_FILE_ENV,
    ProvisioningError,
    create_pair,
    decrypt_bundle,
    import_registration,
    issuer_init,
    load_public_key,
    public_key_spki_sha256,
    read_secret_file,
)
from mineguard.product_cli import main as product_main


ISSUER_PASSPHRASE = b"correct horse battery staple 2026"
ISSUER_ID = "qinyuan-provisioning-authority"
ISSUER_KEY_ID = "qinyuan-provisioning-key-2026q3"


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _profile(
    *,
    mine_number: int = 1,
    profile_version: int = 1,
    regulator_key_id: str = "qinyuan-regulator-key-2026q3",
) -> dict[str, object]:
    return {
        "profile_version": profile_version,
        "expires_at": _timestamp(datetime.now(UTC) + timedelta(days=14)),
        "issuer_id": ISSUER_ID,
        "issuer_key_id": ISSUER_KEY_ID,
        "subject": {
            "mine_id": f"MINE-QY-{mine_number:03d}",
            "mine_name": f"沁源正式煤矿{mine_number:03d}",
            "party_id": f"operator-qy-{mine_number:03d}",
            "party_name": f"沁源煤业集团{mine_number:03d}",
            "system_id": f"agent-mine-qy-{mine_number:03d}",
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
            "key_id": regulator_key_id,
        },
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


@pytest.fixture
def issuer(tmp_path: Path) -> dict[str, object]:
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "trusted-provisioning-public-key.pem"
    result = issuer_init(
        private_key_path=private_key,
        public_key_path=public_key,
        passphrase=ISSUER_PASSPHRASE,
    )
    loaded = load_public_key(public_key.read_bytes())
    assert result["public_key_sha256"] == public_key_spki_sha256(loaded)
    assert result["public_key_fingerprint_format"] == "sha256-spki-der"
    return {
        "private": private_key,
        "public": public_key,
        "fingerprint": result["public_key_sha256"],
    }


def _create(
    tmp_path: Path,
    issuer: dict[str, object],
    profile: dict[str, object],
    *,
    label: str,
    previous: dict[str, object] | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    profile_path = tmp_path / f"{label}-profile.json"
    _write_json(profile_path, profile)
    return create_pair(
        profile_path=profile_path,
        issuer_private_key_path=issuer["private"],
        issuer_passphrase=ISSUER_PASSPHRASE,
        enterprise_bundle_directory=tmp_path / f"{label}-enterprise-bundle",
        platform_registration_directory=(
            tmp_path / f"{label}-platform-registration"
        ),
        enterprise_activation_directory=(
            tmp_path / f"{label}-enterprise-activation"
        ),
        platform_activation_directory=(
            tmp_path / f"{label}-platform-activation"
        ),
        previous_registration_bundle_path=(
            previous["platform_registration_bundle"] if previous else None
        ),
        previous_registration_activation_code_path=(
            previous["platform_activation_file"] if previous else None
        ),
        now=now,
    )


def _import(
    pair: dict[str, object],
    issuer: dict[str, object],
    clients_file: Path,
    *,
    allow_update: bool = False,
) -> dict[str, object]:
    return import_registration(
        bundle_path=pair["platform_registration_bundle"],
        activation_code_path=pair["platform_activation_file"],
        issuer_public_key_path=issuer["public"],
        expected_public_key_sha256=str(issuer["fingerprint"]),
        expected_issuer_key_id=ISSUER_KEY_ID,
        clients_file_path=clients_file,
        allow_update=allow_update,
    )


def test_registration_requires_external_spki_fingerprint_and_key_id(
    tmp_path: Path, issuer: dict[str, object], capsys: pytest.CaptureFixture[str]
) -> None:
    pair = _create(tmp_path, issuer, _profile(), label="first")
    clients = tmp_path / "clients.json"
    manifest = json.loads(
        Path(str(pair["provisioning_manifest"])).read_text(encoding="utf-8")
    )
    assert manifest["issuer"]["public_key_sha256"] == issuer["fingerprint"]
    assert set(manifest["artifacts"]) == {
        "agent_bundle",
        "issuer_public_key",
        "platform_registration_bundle",
    }
    assert "activation" not in json.dumps(manifest).casefold()
    assert manifest["artifacts"]["agent_bundle"]["sha256"] == sha256(
        Path(str(pair["agent_bundle"])).read_bytes()
    ).hexdigest()
    public_key_file = Path(str(pair["issuer_public_key_file"]))
    assert public_key_file.read_bytes() == Path(str(issuer["public"])).read_bytes()
    assert manifest["artifacts"]["issuer_public_key"]["sha256"] == sha256(
        public_key_file.read_bytes()
    ).hexdigest()
    assert (
        manifest["artifacts"]["issuer_public_key"]["spki_sha256"]
        == issuer["fingerprint"]
    )
    enterprise_package = json.loads(
        Path(str(pair["agent_bundle"])).read_text(encoding="utf-8")
    )
    assert enterprise_package["format"] == "mineguard-enterprise-access-package-v1"
    assert set(enterprise_package) == {
        "activation_code",
        "agent_bundle",
        "format",
        "issuer_key_id",
        "issuer_public_key_pem",
        "issuer_public_key_sha256",
    }
    assert list(Path(str(pair["agent_bundle"])).parent.iterdir()) == [
        Path(str(pair["agent_bundle"]))
    ]
    assert pair["layout"] == "split-delivery-v1"
    assert pair["legacy_shared_layout"] is False
    delivery_parents = {
        Path(str(pair[key])).parent
        for key in (
            "agent_bundle",
            "platform_registration_bundle",
            "agent_activation_file",
            "platform_activation_file",
        )
    }
    assert len(delivery_parents) == 4

    with pytest.raises(ProvisioningError, match="approved fingerprint"):
        import_registration(
            bundle_path=pair["platform_registration_bundle"],
            activation_code_path=pair["platform_activation_file"],
            issuer_public_key_path=issuer["public"],
            expected_public_key_sha256="0" * 64,
            expected_issuer_key_id=ISSUER_KEY_ID,
            clients_file_path=clients,
        )
    with pytest.raises(ProvisioningError, match="issuer_key_id"):
        import_registration(
            bundle_path=pair["platform_registration_bundle"],
            activation_code_path=pair["platform_activation_file"],
            issuer_public_key_path=issuer["public"],
            expected_public_key_sha256=str(issuer["fingerprint"]),
            expected_issuer_key_id="qinyuan-provisioning-key-other",
            clients_file_path=clients,
        )
    assert not clients.exists()

    assert (
        product_main(
            [
                "provision",
                "import-registration",
                "--bundle",
                str(pair["platform_registration_bundle"]),
                "--activation-code-file",
                str(pair["platform_activation_file"]),
                "--issuer-public-key",
                str(issuer["public"]),
                "--expected-public-key-sha256",
                str(issuer["fingerprint"]),
                "--expected-issuer-key-id",
                ISSUER_KEY_ID,
                "--clients-file",
                str(clients),
            ]
        )
        == 0
    )
    cli_result = json.loads(capsys.readouterr().out)
    assert cli_result["status"] == "created"
    assert cli_result["platform_identity"]["system_id"] == "mineguard-qinyuan"


def test_pairing_does_not_require_comparison_metadata(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    profile = _profile()
    del profile["comparison_context"]
    pair = _create(tmp_path, issuer, profile, label="minimal-onboarding")
    public_key = load_public_key(Path(str(issuer["public"])).read_bytes())
    enterprise_package = json.loads(
        Path(pair["agent_bundle"]).read_text(encoding="utf-8")
    )
    _, agent_payload = decrypt_bundle(
        enterprise_package["agent_bundle"],
        activation_code=enterprise_package["activation_code"].encode("ascii"),
        issuer_public_key=public_key,
        expected_kind=AGENT_BUNDLE_KIND,
    )
    _, registration_payload = decrypt_bundle(
        json.loads(
            Path(pair["platform_registration_bundle"]).read_text(encoding="utf-8")
        ),
        activation_code=read_secret_file(
            pair["platform_activation_file"], label="platform activation"
        ),
        issuer_public_key=public_key,
        expected_kind=REGISTRATION_BUNDLE_KIND,
    )
    assert "comparison_context" not in registration_payload["client"]
    assert not {
        "ENTERPRISE_CAPACITY_BAND",
        "ENTERPRISE_MINING_METHOD",
        "ENTERPRISE_SHIFT_SYSTEM",
        "ENTERPRISE_COAL_TYPE",
        "ENTERPRISE_OPERATING_REGIME",
    } & set(agent_payload["config"])


def test_tampered_bundle_and_wrong_activation_fail_without_registry_write(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    pair = _create(tmp_path, issuer, _profile(), label="first")
    bundle = Path(str(pair["platform_registration_bundle"]))
    activation = Path(str(pair["platform_activation_file"]))
    clients = tmp_path / "clients.json"

    wrong_activation = tmp_path / "wrong.activation"
    code = activation.read_text(encoding="ascii").strip()
    wrong_activation.write_text(("A" if code[0] != "A" else "B") + code[1:] + "\n")
    with pytest.raises(ProvisioningError, match="activation|decryption"):
        import_registration(
            bundle_path=bundle,
            activation_code_path=wrong_activation,
            issuer_public_key_path=issuer["public"],
            expected_public_key_sha256=str(issuer["fingerprint"]),
            expected_issuer_key_id=ISSUER_KEY_ID,
            clients_file_path=clients,
        )

    tampered = json.loads(bundle.read_text(encoding="utf-8"))
    first = tampered["ciphertext"][0]
    tampered["ciphertext"] = ("A" if first != "A" else "B") + tampered[
        "ciphertext"
    ][1:]
    tampered_path = tmp_path / "tampered.mgreg"
    _write_json(tampered_path, tampered)
    with pytest.raises(ProvisioningError, match="signature"):
        import_registration(
            bundle_path=tampered_path,
            activation_code_path=activation,
            issuer_public_key_path=issuer["public"],
            expected_public_key_sha256=str(issuer["fingerprint"]),
            expected_issuer_key_id=ISSUER_KEY_ID,
            clients_file_path=clients,
        )
    assert not clients.exists()


def test_product_cli_create_pair_uses_the_four_directory_interface(
    tmp_path: Path,
    issuer: dict[str, object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile_path = tmp_path / "profile.json"
    passphrase_path = tmp_path / "issuer-passphrase.txt"
    _write_json(profile_path, _profile())
    passphrase_path.write_bytes(ISSUER_PASSPHRASE + b"\n")
    directories = {
        "--enterprise-bundle-directory": tmp_path / "enterprise-bundle",
        "--platform-registration-directory": tmp_path / "platform-registration",
        "--enterprise-activation-directory": tmp_path / "enterprise-activation",
        "--platform-activation-directory": tmp_path / "platform-activation",
    }
    arguments = [
        "provision",
        "create-pair",
        "--profile",
        str(profile_path),
        "--issuer-private-key",
        str(issuer["private"]),
        "--issuer-passphrase-file",
        str(passphrase_path),
    ]
    for option, directory in directories.items():
        arguments.extend((option, str(directory)))
    assert product_main(arguments) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["layout"] == "split-delivery-v1"
    assert result["legacy_shared_layout"] is False
    assert Path(result["issuer_public_key_file"]).parent == directories[
        "--platform-registration-directory"
    ]
    assert Path(result["platform_registration_bundle"]).parent == directories[
        "--platform-registration-directory"
    ]


def test_bundle_issued_too_far_in_future_is_rejected(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    pair = _create(
        tmp_path,
        issuer,
        _profile(),
        label="future",
        now=datetime.now(UTC) + timedelta(hours=1),
    )
    with pytest.raises(ProvisioningError, match="not yet valid"):
        _import(pair, issuer, tmp_path / "clients.json")


def test_managed_policy_rejects_lock_removal_unmanaged_append_and_tamper(
    tmp_path: Path, issuer: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    pair = _create(tmp_path, issuer, _profile(), label="first")
    clients_path = tmp_path / "clients.json"
    _import(pair, issuer, clients_path)
    registry = json.loads(clients_path.read_text(encoding="utf-8"))

    monkeypatch.setenv(MANAGED_REQUIRED_ENV, "true")
    monkeypatch.setenv(TRUSTED_PUBLIC_KEY_FILE_ENV, str(issuer["public"]))
    monkeypatch.setenv(EXPECTED_PUBLIC_KEY_SHA256_ENV, str(issuer["fingerprint"]))
    monkeypatch.setenv(EXPECTED_ISSUER_KEY_ID_ENV, ISSUER_KEY_ID)
    assert len(parse_exchange_clients(json.dumps(registry))) == 1

    missing_lock = deepcopy(registry)
    del missing_lock["provisioning_lock"]
    with pytest.raises(ProvisioningError, match="provisioning_lock is missing"):
        parse_exchange_clients(json.dumps(missing_lock))

    appended = deepcopy(registry)
    extra = deepcopy(appended["clients"][0])
    extra.update(
        {
            "sender_id": "agent-mine-qy-099",
            "mine_id": "MINE-QY-099",
            "party_id": "operator-qy-099",
        }
    )
    appended["clients"].append(extra)
    with pytest.raises(ProvisioningError, match="every client"):
        parse_exchange_clients(json.dumps(appended))

    tampered = deepcopy(registry)
    active_key = tampered["clients"][0]["active_message_key_id"]
    tampered["clients"][0]["message_keys"][active_key] = "Z" * 64
    with pytest.raises(ProvisioningError, match="digest"):
        parse_exchange_clients(json.dumps(tampered))


def test_update_keeps_pair_and_subject_and_retains_immediately_prior_keys(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    first = _create(tmp_path, issuer, _profile(), label="v1")
    clients_path = tmp_path / "clients.json"
    _import(first, issuer, clients_path)

    second = _create(
        tmp_path,
        issuer,
        _profile(profile_version=2),
        label="v2",
        previous=first,
    )
    assert second["pair_id"] == first["pair_id"]
    public_key = load_public_key(Path(str(issuer["public"])).read_bytes())
    _, second_payload = decrypt_bundle(
        json.loads(
            Path(str(second["platform_registration_bundle"])).read_text(
                encoding="utf-8"
            )
        ),
        activation_code=read_secret_file(
            str(second["platform_activation_file"]), label="activation"
        ),
        issuer_public_key=public_key,
        expected_kind=REGISTRATION_BUNDLE_KIND,
    )
    assert len(second_payload["client"]["message_keys"]) == 2
    assert len(second_payload["client"]["transport_secrets"]) == 2
    enterprise_package = json.loads(
        Path(str(second["agent_bundle"])).read_text(encoding="utf-8")
    )
    _, agent_payload = decrypt_bundle(
        enterprise_package["agent_bundle"],
        activation_code=enterprise_package["activation_code"].encode("ascii"),
        issuer_public_key=load_public_key(
            enterprise_package["issuer_public_key_pem"].encode("ascii")
        ),
        expected_kind=AGENT_BUNDLE_KIND,
    )
    assert (
        agent_payload["config"]["REGULATORY_PREVIOUS_EXCHANGE_KEY_ID"]
        == agent_payload["config"]["REGULATORY_EXCHANGE_KEY_ID"]
    )
    assert "ENTERPRISE_HISTORICAL_EXCHANGE_KEYS_JSON" in agent_payload["config"]

    updated = _import(second, issuer, clients_path, allow_update=True)
    assert updated["status"] == "updated"
    registry = json.loads(clients_path.read_text(encoding="utf-8"))
    assert registry["provisioning_lock"]["registrations"][0]["pair_id"] == first[
        "pair_id"
    ]
    assert "issuer_public_key" not in registry["provisioning_lock"]["registrations"][0]
    assert registry["provisioning_lock"]["registrations"][0][
        "issuer_public_key_sha256"
    ] == issuer["fingerprint"]

    with pytest.raises(ProvisioningError, match="profile_version"):
        _import(first, issuer, clients_path, allow_update=True)

    changed_subject = _profile(
        profile_version=3,
    )
    changed_subject["subject"]["party_id"] = "operator-qy-different"
    with pytest.raises(ProvisioningError, match="subject identity"):
        _create(
            tmp_path,
            issuer,
            changed_subject,
            label="bad-v3",
            previous=second,
        )


def test_concurrent_registration_imports_do_not_lose_clients(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    pairs = [
        _create(tmp_path, issuer, _profile(mine_number=index), label=f"mine-{index}")
        for index in range(1, 7)
    ]
    clients_path = tmp_path / "clients.json"
    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(
            executor.map(lambda pair: _import(pair, issuer, clients_path), pairs)
        )
    assert {item["status"] for item in results} == {"created"}
    registry = json.loads(clients_path.read_text(encoding="utf-8"))
    assert len(registry["clients"]) == 6
    assert len(registry["provisioning_lock"]["registrations"]) == 6

    update = _create(
        tmp_path,
        issuer,
        _profile(mine_number=1, profile_version=2),
        label="mine-1-v2",
        previous=pairs[0],
    )
    assert _import(update, issuer, clients_path, allow_update=True)["status"] == "updated"
    registry = json.loads(clients_path.read_text(encoding="utf-8"))
    assert len(registry["clients"]) == 6


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("context_control", "governed non-placeholder"),
        ("invalid_port", "invalid port"),
        ("placeholder_identity", "placeholder identifier"),
        ("placeholder_context", "governed non-placeholder"),
        ("placeholder_context_phrase", "governed non-placeholder"),
        ("placeholder_context_tbd", "governed non-placeholder"),
        ("placeholder_context_instruction", "governed non-placeholder"),
    ],
)
def test_profile_validation_fails_closed_before_writing_bundles(
    tmp_path: Path,
    issuer: dict[str, object],
    mutation: str,
    message: str,
) -> None:
    profile = _profile()
    if mutation == "context_control":
        profile["comparison_context"]["capacity_band"] = "band\nEVIL=value"
    elif mutation == "invalid_port":
        profile["agent"]["platform_base_url"] = "https://platform.internal:abc"
    elif mutation == "placeholder_identity":
        profile["subject"]["mine_id"] = "demo-mine-001"
    elif mutation == "placeholder_context":
        profile["comparison_context"]["coal_type"] = "unclassified"
    elif mutation == "placeholder_context_tbd":
        profile["comparison_context"]["coal_type"] = "tbd"
    elif mutation == "placeholder_context_instruction":
        profile["comparison_context"]["coal_type"] = "请填写真实煤种"
    else:
        profile["comparison_context"]["capacity_band"] = "待补充产能"

    with pytest.raises(ProvisioningError, match=message):
        _create(tmp_path, issuer, profile, label=f"invalid-{mutation}")
    assert not any(
        (tmp_path / f"invalid-{mutation}-{suffix}").exists()
        for suffix in (
            "enterprise-bundle",
            "platform-registration",
            "enterprise-activation",
            "platform-activation",
        )
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("platform_base_url", "https://mineguard.qinyuan.gov.cn:443"),
        ("platform_base_url", "https://mineguard.qinyuan.gov.cn/with path"),
        ("platform_base_url", "https://service.example.net"),
        ("platform_base_url", "https://platform.example"),
        ("platform_base_url", "https://169.254.10.20"),
        ("platform_base_url", "https://0.0.0.0"),
        ("platform_base_url", "https://[malformed"),
    ],
)
def test_profile_rejects_noncanonical_or_unroutable_origins_before_signing(
    tmp_path: Path,
    issuer: dict[str, object],
    field: str,
    value: str,
) -> None:
    profile = _profile()
    profile["agent"][field] = value
    with pytest.raises(ProvisioningError, match="HTTPS|host|address|port"):
        _create(tmp_path, issuer, profile, label=f"invalid-origin-{field}")


def test_trailing_slash_platform_origin_is_canonicalized_for_agent_import(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    profile = _profile()
    profile["agent"]["platform_base_url"] += "/"
    pair = _create(tmp_path, issuer, profile, label="canonical-origin")
    package = json.loads(
        Path(str(pair["agent_bundle"])).read_text(encoding="utf-8")
    )
    _, payload = decrypt_bundle(
        package["agent_bundle"],
        activation_code=package["activation_code"].encode("ascii"),
        issuer_public_key=load_public_key(
            package["issuer_public_key_pem"].encode("ascii")
        ),
        expected_kind=AGENT_BUNDLE_KIND,
    )
    assert payload["config"]["PLATFORM_V3_BASE_URL"] == (
        "https://mineguard.qinyuan.gov.cn"
    )


def test_contract_datetime_profile_version_and_ciphertext_boundaries(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    parsed = provisioning_module._parse_time(  # noqa: SLF001 - contract boundary
        "2026-08-10T12:34:56.123456Z", label="test.time"
    )
    assert parsed.microsecond == 123456
    with pytest.raises(ProvisioningError, match="RFC3339"):
        provisioning_module._parse_time(  # noqa: SLF001 - contract boundary
            "2026-08-10T12:34:56.1234567Z", label="test.time"
        )

    fractional_profile = _profile()
    fractional_expiry = (datetime.now(UTC) + timedelta(days=14)).replace(
        microsecond=123456
    )
    fractional_profile["expires_at"] = fractional_expiry.isoformat().replace(
        "+00:00", "Z"
    )
    fractional_pair = _create(
        tmp_path, issuer, fractional_profile, label="fractional-expiry"
    )
    fractional_envelope = json.loads(
        Path(str(fractional_pair["agent_bundle"])).read_text(encoding="utf-8")
    )["agent_bundle"]
    assert fractional_envelope["protected"]["expires_at"].endswith(".123456Z")

    pair = _create(tmp_path, issuer, _profile(), label="contract-boundaries")
    envelope = json.loads(
        Path(str(pair["platform_registration_bundle"])).read_text(encoding="utf-8")
    )
    envelope["protected"]["issued_at"] = "2026-08-10T12:34:56.1Z"
    envelope["protected"]["expires_at"] = "2026-08-10T12:34:57.000001Z"
    envelope["protected"]["profile_version"] = 2_147_483_647
    envelope["ciphertext"] = "A" * 23
    provisioning_module._validate_envelope(  # noqa: SLF001 - contract boundary
        envelope, expected_kind=REGISTRATION_BUNDLE_KIND
    )

    too_large = deepcopy(envelope)
    too_large["protected"]["profile_version"] = 2_147_483_648
    with pytest.raises(ProvisioningError, match="2147483647"):
        provisioning_module._validate_envelope(  # noqa: SLF001
            too_large, expected_kind=REGISTRATION_BUNDLE_KIND
        )

    tag_only = deepcopy(envelope)
    tag_only["ciphertext"] = "A" * 22
    with pytest.raises(ProvisioningError, match="ciphertext"):
        provisioning_module._validate_envelope(  # noqa: SLF001
            tag_only, expected_kind=REGISTRATION_BUNDLE_KIND
        )

    boolean_kdf_parameter = deepcopy(envelope)
    boolean_kdf_parameter["protected"]["encryption"]["p"] = True
    with pytest.raises(ProvisioningError, match="encryption parameters"):
        provisioning_module._validate_envelope(  # noqa: SLF001
            boolean_kdf_parameter, expected_kind=REGISTRATION_BUNDLE_KIND
        )

    oversized_profile = _profile(profile_version=2_147_483_648)
    with pytest.raises(ProvisioningError, match="2147483647"):
        _create(tmp_path, issuer, oversized_profile, label="oversized-profile")


def test_create_pair_rejects_linked_output_directory(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    profile_path = tmp_path / "profile.json"
    _write_json(profile_path, _profile())
    real_output = tmp_path / "real-output"
    real_output.mkdir()
    linked_output = tmp_path / "linked-output"
    try:
        linked_output.symlink_to(real_output, target_is_directory=True)
    except OSError:
        pytest.skip("test account cannot create directory symlinks")
    with pytest.raises(ProvisioningError, match="symbolic links"):
        create_pair(
            profile_path=profile_path,
            issuer_private_key_path=issuer["private"],
            issuer_passphrase=ISSUER_PASSPHRASE,
            output_directory=linked_output,
            activation_directory=tmp_path / "activation",
        )
    assert list(real_output.iterdir()) == []


def test_create_pair_requires_complete_non_overlapping_split_layout(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    profile_path = tmp_path / "profile.json"
    _write_json(profile_path, _profile())
    common = {
        "profile_path": profile_path,
        "issuer_private_key_path": issuer["private"],
        "issuer_passphrase": ISSUER_PASSPHRASE,
    }
    with pytest.raises(ProvisioningError, match="split delivery requires"):
        create_pair(
            **common,
            enterprise_bundle_directory=tmp_path / "enterprise-bundle",
        )
    with pytest.raises(ProvisioningError, match="separate directory trees"):
        create_pair(
            **common,
            enterprise_bundle_directory=tmp_path / "delivery" / "enterprise",
            platform_registration_directory=tmp_path / "delivery",
            enterprise_activation_directory=tmp_path / "enterprise-activation",
            platform_activation_directory=tmp_path / "platform-activation",
        )
    with pytest.raises(ProvisioningError, match="cannot be mixed"):
        create_pair(
            **common,
            output_directory=tmp_path / "legacy-bundles",
            activation_directory=tmp_path / "legacy-activation",
            enterprise_bundle_directory=tmp_path / "enterprise-bundle-2",
            platform_registration_directory=tmp_path / "platform-registration-2",
            enterprise_activation_directory=tmp_path / "enterprise-activation-2",
            platform_activation_directory=tmp_path / "platform-activation-2",
        )


def test_legacy_two_directory_layout_remains_explicitly_compatible(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    profile_path = tmp_path / "profile.json"
    _write_json(profile_path, _profile())
    pair = create_pair(
        profile_path=profile_path,
        issuer_private_key_path=issuer["private"],
        issuer_passphrase=ISSUER_PASSPHRASE,
        output_directory=tmp_path / "legacy-bundles",
        activation_directory=tmp_path / "legacy-activation",
    )
    assert pair["layout"] == "legacy-shared-v1"
    assert pair["legacy_shared_layout"] is True
    assert Path(str(pair["agent_bundle"])).parent == Path(
        str(pair["platform_registration_bundle"])
    ).parent
    assert Path(str(pair["agent_activation_file"])).parent == Path(
        str(pair["platform_activation_file"])
    ).parent


def test_update_can_reuse_the_same_four_delivery_directories(
    tmp_path: Path, issuer: dict[str, object]
) -> None:
    directories = {
        "enterprise_bundle_directory": tmp_path / "enterprise-bundle",
        "platform_registration_directory": tmp_path / "platform-registration",
        "enterprise_activation_directory": tmp_path / "enterprise-activation",
        "platform_activation_directory": tmp_path / "platform-activation",
    }
    first_profile = tmp_path / "v1-profile.json"
    second_profile = tmp_path / "v2-profile.json"
    _write_json(first_profile, _profile())
    _write_json(second_profile, _profile(profile_version=2))
    common = {
        "issuer_private_key_path": issuer["private"],
        "issuer_passphrase": ISSUER_PASSPHRASE,
        **directories,
    }
    first = create_pair(profile_path=first_profile, **common)
    second = create_pair(
        profile_path=second_profile,
        previous_registration_bundle_path=first["platform_registration_bundle"],
        previous_registration_activation_code_path=first[
            "platform_activation_file"
        ],
        **common,
    )
    assert first["pair_id"] == second["pair_id"]
    assert Path(str(first["agent_activation_file"])).name.endswith(
        "-v1-agent.activation"
    )
    assert Path(str(second["agent_activation_file"])).name.endswith(
        "-v2-agent.activation"
    )
    assert Path(str(first["platform_activation_file"])).name.endswith(
        "-v1-platform.activation"
    )
    assert Path(str(second["platform_activation_file"])).name.endswith(
        "-v2-platform.activation"
    )
    for pair in (first, second):
        for key in ("agent_activation_file", "platform_activation_file"):
            assert Path(str(pair[key])).exists()
