from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from mineguard.evidence import (
    EvidenceBundleService,
    EvidenceConflictError,
    EvidenceError,
    EvidenceRepository,
)


SECRET = b"a-local-test-key-with-enough-entropy"


def _service(secret: bytes = SECRET) -> EvidenceBundleService:
    return EvidenceBundleService(
        lambda key_id: secret if key_id == "local-key-1" else None,
        signing_key_id="local-key-1",
    )


def _case(version: int = 3) -> dict:
    return {
        "case_id": "case-001",
        "version": version,
        "mine_id": "M001",
        "workflow_status": "reviewing",
        "summary": "仅用于测试的技术线索",
    }


def _run() -> dict:
    return {
        "analysis_run_id": "run-001",
        "batch_id": "batch-001",
        "mine_id": "M001",
        "engine_version": "0.3.0",
        "snapshot_hash": "a" * 64,
        "result_hash": "b" * 64,
        "input_snapshot": {"observations": [{"value": 1}]},
        "result": {"status": "inconsistent"},
    }


def _build(service: EvidenceBundleService, *, version: int = 3):
    return service.build(
        case=_case(version),
        events=[{"sequence": 1, "action": "created"}],
        run=_run(),
        engine_version="0.3.0",
        generated_at="2026-07-26T00:00:00Z",
    )


def test_bundle_is_deterministic_and_verifies_offline() -> None:
    service = _service()
    first, manifest = _build(service)
    second, second_manifest = _build(service)

    assert first == second
    assert manifest == second_manifest
    verification = service.verify(first)
    assert verification.valid
    assert verification.errors == []
    assert verification.manifest == manifest
    assert verification.manifest_sha256


def test_analysis_trace_carries_historical_runtime_manifest() -> None:
    service = _service()
    run = _run()
    run["batch_context"] = {
        "runtime_manifest": {
            "schema_version": "mineguard.runtime.v1",
            "application": {"version": "0.3.0"},
            "dependencies": {"scipy": "verified-test-version"},
        }
    }
    bundle, _ = service.build(
        case=_case(),
        events=[],
        run=run,
        engine_version="0.3.0",
        generated_at="2026-07-26T00:00:00Z",
    )

    with zipfile.ZipFile(io.BytesIO(bundle), "r") as archive:
        trace = json.loads(archive.read("analysis_trace.json"))
    assert trace["runtime_manifest"] == run["batch_context"][
        "runtime_manifest"
    ]


def _rewrite_zip(
    bundle: bytes,
    transform,
) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(bundle), "r")
    output = io.BytesIO()
    with source, zipfile.ZipFile(output, "w") as target:
        for entry in source.infolist():
            target.writestr(entry.filename, transform(entry.filename, source.read(entry)))
    return output.getvalue()


def test_artifact_tampering_and_unknown_key_are_rejected() -> None:
    service = _service()
    bundle, _ = _build(service)
    tampered = _rewrite_zip(
        bundle,
        lambda name, content: (
            b'{"tampered":true}' if name == "case.json" else content
        ),
    )

    verification = service.verify(tampered)
    assert not verification.valid
    assert any(
        error.startswith("artifact_") for error in verification.errors
    )

    wrong_key_service = _service(b"different-secret")
    wrong_key = wrong_key_service.verify(bundle)
    assert not wrong_key.valid
    assert "signature_invalid" in wrong_key.errors


def test_extra_archive_entries_and_unsafe_paths_are_rejected() -> None:
    service = _service()
    bundle, _ = _build(service)
    output = io.BytesIO()
    source = zipfile.ZipFile(io.BytesIO(bundle), "r")
    with source, zipfile.ZipFile(output, "w") as target:
        for entry in source.infolist():
            target.writestr(entry.filename, source.read(entry))
        target.writestr("../escape.txt", b"bad")

    verification = service.verify(output.getvalue())
    assert not verification.valid
    assert "unsafe_archive_path" in verification.errors
    assert "artifact_set_mismatch" in verification.errors

    with pytest.raises(EvidenceError):
        service.build(
            case=_case(),
            events=[],
            run=_run(),
            engine_version="0.3.0",
            extra_artifacts={"../bad.txt": ("text/plain", b"bad")},
        )


def test_repository_is_append_only_and_detects_file_changes(
    tmp_path: Path,
) -> None:
    service = _service()
    repository = EvidenceRepository(
        tmp_path / "evidence.sqlite3",
        tmp_path / "bundles",
    )
    try:
        bundle, manifest = _build(service)
        saved = repository.save(
            bundle,
            manifest,
            created_by="reviewer",
        )
        assert repository.read(manifest.bundle_id) == bundle
        same = repository.save(
            bundle,
            manifest,
            created_by="reviewer",
        )
        assert same["bundle_id"] == saved["bundle_id"]

        changed_bundle, changed_manifest = service.build(
            case=_case(),
            events=[{"sequence": 1}, {"sequence": 2}],
            run=_run(),
            engine_version="0.3.0",
            generated_at="2026-07-27T00:00:00Z",
        )
        with pytest.raises(EvidenceConflictError):
            repository.save(
                changed_bundle,
                changed_manifest,
                created_by="reviewer",
            )

        stored_path = (
            (tmp_path / "bundles") / saved["relative_path"]
        )
        stored_path.write_bytes(b"externally changed")
        with pytest.raises(EvidenceError):
            repository.read(manifest.bundle_id)
    finally:
        repository.close()


def test_manifest_chain_can_link_successive_case_versions() -> None:
    service = _service()
    first_bundle, first_manifest = _build(service, version=3)
    first_verification = service.verify(first_bundle)
    assert first_verification.manifest_sha256 is not None

    second_bundle, second_manifest = service.build(
        case=_case(version=4),
        events=[{"sequence": 1}, {"sequence": 2}],
        run=_run(),
        engine_version="0.3.0",
        previous_manifest_sha256=first_verification.manifest_sha256,
        generated_at="2026-07-27T00:00:00Z",
    )

    assert (
        second_manifest.previous_manifest_sha256
        == first_verification.manifest_sha256
    )
    assert service.verify(second_bundle).valid


def test_repository_rehydrates_bundle_from_database_backup_source(
    tmp_path: Path,
) -> None:
    service = _service()
    repository = EvidenceRepository(
        tmp_path / "evidence.sqlite3",
        tmp_path / "bundles",
    )
    try:
        bundle, manifest = _build(service)
        saved = repository.save(bundle, manifest, created_by="reviewer")
        stored_path = (
            (tmp_path / "bundles") / saved["relative_path"]
        )
        stored_path.unlink()

        assert repository.read(manifest.bundle_id) == bundle
        assert stored_path.read_bytes() == bundle
    finally:
        repository.close()
