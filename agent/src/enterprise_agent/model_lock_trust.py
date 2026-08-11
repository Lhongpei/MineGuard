"""Read-only compatibility checks for an installed model credential lock.

This module intentionally verifies only the issuer-anchored, signed envelope.
It never opens the local secret store and therefore can be used to decide
whether a candidate release trust store is safe before a Windows upgrade
touches an installed runtime or instance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import model_credentials as credentials


def validate_model_lock_against_trust_store(
    *,
    lock_path: str | Path,
    trust_store_path: str | Path,
) -> dict[str, Any]:
    """Verify a lock's signed envelope and issuer using candidate trust.

    This is deliberately narrower than runtime credential loading: API-key
    decryption, lock HMAC verification and runtime-expiry enforcement remain
    runtime responsibilities.  Upgrade compatibility must still work for an
    expired credential so that an administrator can install a release and
    subsequently rotate that credential.
    """

    lock = credentials._load_lock(lock_path)  # noqa: SLF001
    issuers = credentials._trusted_issuers(trust_store_path)  # noqa: SLF001
    envelope, issuer = credentials._verify_envelope(  # noqa: SLF001
        lock["envelope"], issuers
    )
    protected = envelope["protected"]
    issuer_lock = credentials._strict_object(  # noqa: SLF001
        lock["issuer"],
        {
            "issuer_id",
            "issuer_key_id",
            "issuer_key_epoch",
            "public_key_sha256",
        },
        "模型凭据 lock.issuer",
    )
    expected_issuer = {
        "issuer_id": issuer.issuer_id,
        "issuer_key_id": issuer.issuer_key_id,
        "issuer_key_epoch": issuer.issuer_key_epoch,
        "public_key_sha256": issuer.public_key_sha256,
    }
    if issuer_lock != expected_issuer:
        raise credentials.ModelCredentialError("模型凭据 lock 签发信任绑定不匹配")

    subject = protected["subject"]
    return {
        "valid": True,
        "verification_scope": "signed-envelope-and-issuer-only",
        "secret_store_accessed": False,
        "api_key_accessed": False,
        "format": lock["format"],
        "bundle_id": protected["bundle_id"],
        "credential_id": protected["credential_id"],
        "credential_version": protected["credential_version"],
        "mine_id": subject["mine_id"],
        "system_id": subject["system_id"],
        "party_id": subject["party_id"],
        "pair_id": subject["pair_id"],
        "issuer_id": issuer.issuer_id,
        "issuer_key_id": issuer.issuer_key_id,
        "issuer_key_epoch": issuer.issuer_key_epoch,
        "issuer_public_key_sha256": issuer.public_key_sha256,
        "runtime_not_after": protected["runtime_not_after"],
    }


__all__ = ["validate_model_lock_against_trust_store"]
