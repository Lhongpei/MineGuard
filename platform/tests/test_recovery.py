from __future__ import annotations

import sqlite3
from pathlib import Path

from mineguard.evidence import EvidenceBundleService, EvidenceRepository
from mineguard.operations import BackupManager
from mineguard.source_keys import SourceKeyStore


def _empty_sqlite(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE marker (value TEXT)")
        connection.commit()
    finally:
        connection.close()


def test_backup_restores_evidence_bundle_and_its_verification_key(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    key_store = SourceKeyStore(state / "keys")
    evidence_secret = b"evidence-recovery-secret-32-bytes!"
    key_store.put_system("evidence-signing-key", evidence_secret)
    evidence_repository = EvidenceRepository(
        state / "evidence.db",
        state / "evidence-files",
    )
    service = EvidenceBundleService(
        lambda key_id: (
            evidence_secret if key_id == "local-evidence-key" else None
        ),
        signing_key_id="local-evidence-key",
    )
    bundle, manifest = service.build(
        case={
            "case_id": "case-recovery",
            "version": 1,
            "mine_id": "M001",
            "workflow_status": "closed",
        },
        events=[{"sequence": 1, "action": "created"}],
        run=None,
        engine_version="0.3.0",
        generated_at="2026-07-26T00:00:00Z",
    )
    evidence_repository.save(bundle, manifest, created_by="reviewer")
    evidence_repository.close()
    key_store.close()

    databases = {
        "evidence.db": state / "evidence.db",
        "source-keys.db": state / "keys" / "source-keys.db",
    }
    for name in ("mineguard.db", "auth.db", "jobs.db", "governance.db"):
        _empty_sqlite(state / name)
        databases[name] = state / name

    manager = BackupManager(
        tmp_path / "backups",
        b"external-backup-integrity-key-32!",
        "recovery-key",
        "0.3.0",
    )
    manager.create_backup("recovery-001", databases)
    restored = manager.restore("recovery-001", tmp_path / "restored")

    restored_keys = SourceKeyStore(restored)
    restored_secret = restored_keys.get_system("evidence-signing-key")
    assert restored_secret == evidence_secret
    restored_evidence = EvidenceRepository(
        restored / "evidence.db",
        restored / "empty-evidence-files",
    )
    restored_service = EvidenceBundleService(
        lambda key_id: (
            restored_secret if key_id == "local-evidence-key" else None
        ),
        signing_key_id="local-evidence-key",
    )
    try:
        recovered_bundle = restored_evidence.read(manifest.bundle_id)
        assert recovered_bundle == bundle
        assert restored_service.verify(recovered_bundle).valid
    finally:
        restored_evidence.close()
        restored_keys.close()
