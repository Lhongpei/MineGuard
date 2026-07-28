"""Deterministic, authenticated evidence bundles for offline verification.

HMAC authentication is suitable for this self-hosted internal edition. It is
not a public-key signature, trusted timestamp, or WORM storage. Production
deployments can replace the signer through the same manifest boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import sqlite3
import tempfile
import threading
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Callable

from pydantic import Field

from .casework import canonical_json
from .models import StrictModel


MAX_BUNDLE_BYTES = 100 * 1024 * 1024
MAX_ARTIFACT_BYTES = 50 * 1024 * 1024
SIGNATURE_ALGORITHM = "HMAC-SHA256"


class EvidenceError(RuntimeError):
    pass


class EvidenceConflictError(EvidenceError):
    pass


class EvidenceNotFoundError(EvidenceError):
    pass


class EvidenceArtifact(StrictModel):
    path: str
    media_type: str
    size_bytes: Annotated[int, Field(ge=0)]
    sha256: str


class EvidenceManifest(StrictModel):
    schema_version: str = "mineguard.evidence.v1"
    bundle_id: str
    case_id: str
    case_version: Annotated[int, Field(ge=1)]
    analysis_run_id: str | None = None
    engine_version: str
    generated_at: str
    previous_manifest_sha256: str | None = None
    artifacts: list[EvidenceArtifact]
    signing_key_id: str
    signature_algorithm: str = SIGNATURE_ALGORITHM
    signature: str


class EvidenceVerification(StrictModel):
    valid: bool
    errors: list[str] = Field(default_factory=list)
    bundle_sha256: str
    manifest_sha256: str | None = None
    manifest: EvidenceManifest | None = None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _json_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def _unsigned_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    return unsigned


class EvidenceBundleService:
    """Build and verify a closed set of canonical JSON evidence artifacts."""

    def __init__(
        self,
        secret_resolver: Callable[[str], bytes | None],
        *,
        signing_key_id: str,
    ) -> None:
        self.secret_resolver = secret_resolver
        self.signing_key_id = signing_key_id

    def build(
        self,
        *,
        case: dict[str, Any],
        events: list[dict[str, Any]],
        run: dict[str, Any] | None,
        engine_version: str,
        previous_manifest_sha256: str | None = None,
        generated_at: str | None = None,
        extra_artifacts: dict[str, tuple[str, bytes]] | None = None,
    ) -> tuple[bytes, EvidenceManifest]:
        secret = self.secret_resolver(self.signing_key_id)
        if not secret:
            raise EvidenceError("evidence signing key is unavailable")
        case_id = str(case["case_id"])
        case_version = int(case["version"])
        artifact_bytes: dict[str, tuple[str, bytes]] = {
            "case.json": ("application/json", _json_bytes(case)),
            "events.json": ("application/json", _json_bytes(events)),
        }
        analysis_run_id: str | None = None
        if run is not None:
            analysis_run_id = str(
                run.get("analysis_run_id") or run.get("run_id")
            )
            artifact_bytes["input_snapshot.json"] = (
                "application/json",
                _json_bytes(
                    run.get("input_snapshot")
                    if "input_snapshot" in run
                    else run.get("input")
                ),
            )
            artifact_bytes["analysis_result.json"] = (
                "application/json",
                _json_bytes(run.get("result")),
            )
            trace = {
                key: run.get(key)
                for key in (
                    "analysis_run_id",
                    "run_id",
                    "batch_id",
                    "mine_id",
                    "technical_status",
                    "snapshot_hash",
                    "input_sha256",
                    "result_hash",
                    "result_sha256",
                    "engine_version",
                    "created_at",
                )
                if run.get(key) is not None
            }
            batch_context = run.get("batch_context")
            if isinstance(batch_context, dict):
                runtime_manifest = batch_context.get("runtime_manifest")
                if isinstance(runtime_manifest, dict):
                    trace["runtime_manifest"] = runtime_manifest
            artifact_bytes["analysis_trace.json"] = (
                "application/json",
                _json_bytes(trace),
            )
        for path, (media_type, content) in (extra_artifacts or {}).items():
            self._validate_artifact_path(path)
            if path in artifact_bytes or path == "manifest.json":
                raise EvidenceError(f"duplicate evidence artifact: {path}")
            if len(content) > MAX_ARTIFACT_BYTES:
                raise EvidenceError(f"evidence artifact is too large: {path}")
            artifact_bytes[path] = (media_type, bytes(content))

        artifacts = [
            EvidenceArtifact(
                path=path,
                media_type=media_type,
                size_bytes=len(content),
                sha256=_sha256(content),
            )
            for path, (media_type, content) in sorted(artifact_bytes.items())
        ]
        created = generated_at or _now()
        identity = {
            "case_id": case_id,
            "case_version": case_version,
            "analysis_run_id": analysis_run_id,
            "engine_version": engine_version,
            "generated_at": created,
            "previous_manifest_sha256": previous_manifest_sha256,
            "artifacts": [
                artifact.model_dump(mode="json") for artifact in artifacts
            ],
            "signing_key_id": self.signing_key_id,
        }
        bundle_id = f"evidence_{_sha256(_json_bytes(identity))[:24]}"
        unsigned = {
            "schema_version": "mineguard.evidence.v1",
            "bundle_id": bundle_id,
            **identity,
            "signature_algorithm": SIGNATURE_ALGORITHM,
        }
        signature = hmac.new(
            secret,
            _json_bytes(unsigned),
            hashlib.sha256,
        ).hexdigest()
        manifest = EvidenceManifest(
            **unsigned,
            signature=signature,
        )
        manifest_bytes = _json_bytes(manifest.model_dump(mode="json"))

        buffer = io.BytesIO()
        with zipfile.ZipFile(
            buffer,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as archive:
            for path, (_, content) in sorted(artifact_bytes.items()):
                self._write_deterministic(archive, path, content)
            self._write_deterministic(
                archive,
                "manifest.json",
                manifest_bytes,
            )
        bundle = buffer.getvalue()
        if len(bundle) > MAX_BUNDLE_BYTES:
            raise EvidenceError("evidence bundle is too large")
        return bundle, manifest

    @staticmethod
    def _write_deterministic(
        archive: zipfile.ZipFile,
        path: str,
        content: bytes,
    ) -> None:
        info = zipfile.ZipInfo(path)
        info.date_time = (1980, 1, 1, 0, 0, 0)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o600 << 16
        archive.writestr(info, content)

    @staticmethod
    def _validate_artifact_path(path: str) -> None:
        candidate = Path(path)
        if (
            not path
            or path.startswith(("/", "\\"))
            or candidate.is_absolute()
            or ".." in candidate.parts
            or "\\" in path
        ):
            raise EvidenceError("unsafe evidence artifact path")

    def verify(self, bundle: bytes) -> EvidenceVerification:
        errors: list[str] = []
        bundle_hash = _sha256(bundle)
        if len(bundle) > MAX_BUNDLE_BYTES:
            return EvidenceVerification(
                valid=False,
                errors=["bundle_too_large"],
                bundle_sha256=bundle_hash,
            )
        try:
            archive = zipfile.ZipFile(io.BytesIO(bundle), mode="r")
        except (zipfile.BadZipFile, OSError):
            return EvidenceVerification(
                valid=False,
                errors=["invalid_zip"],
                bundle_sha256=bundle_hash,
            )

        manifest: EvidenceManifest | None = None
        manifest_hash: str | None = None
        try:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                errors.append("duplicate_archive_entry")
            if "manifest.json" not in names:
                errors.append("manifest_missing")
                return EvidenceVerification(
                    valid=False,
                    errors=errors,
                    bundle_sha256=bundle_hash,
                )
            for entry in entries:
                try:
                    self._validate_artifact_path(entry.filename)
                except EvidenceError:
                    errors.append("unsafe_archive_path")
                if entry.file_size > MAX_ARTIFACT_BYTES:
                    errors.append("artifact_too_large")
            manifest_bytes = archive.read("manifest.json")
            manifest_hash = _sha256(manifest_bytes)
            try:
                manifest = EvidenceManifest.model_validate_json(
                    manifest_bytes
                )
            except Exception:
                errors.append("manifest_invalid")
                return EvidenceVerification(
                    valid=False,
                    errors=errors,
                    bundle_sha256=bundle_hash,
                    manifest_sha256=manifest_hash,
                )

            declared = {artifact.path: artifact for artifact in manifest.artifacts}
            allowed = set(declared) | {"manifest.json"}
            if set(names) != allowed:
                errors.append("artifact_set_mismatch")
            for path, artifact in declared.items():
                if path not in names:
                    errors.append(f"artifact_missing:{path}")
                    continue
                content = archive.read(path)
                if len(content) != artifact.size_bytes:
                    errors.append(f"artifact_size_mismatch:{path}")
                if _sha256(content) != artifact.sha256:
                    errors.append(f"artifact_hash_mismatch:{path}")

            secret = self.secret_resolver(manifest.signing_key_id)
            if not secret:
                errors.append("signing_key_unavailable")
            elif manifest.signature_algorithm != SIGNATURE_ALGORITHM:
                errors.append("signature_algorithm_unsupported")
            else:
                expected = hmac.new(
                    secret,
                    _json_bytes(
                        _unsigned_manifest(
                            manifest.model_dump(mode="json")
                        )
                    ),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(expected, manifest.signature):
                    errors.append("signature_invalid")
        finally:
            archive.close()

        return EvidenceVerification(
            valid=not errors,
            errors=errors,
            bundle_sha256=bundle_hash,
            manifest_sha256=manifest_hash,
            manifest=manifest,
        )


class EvidenceRepository:
    """Append-only evidence metadata with atomic bundle files."""

    def __init__(
        self,
        database_path: str | Path,
        bundle_directory: str | Path,
    ) -> None:
        self.database_path = str(database_path)
        self.bundle_directory = Path(bundle_directory).resolve()
        self.bundle_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        Path(self.database_path).expanduser().resolve().parent.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
            timeout=10,
        )
        self._connection.row_factory = sqlite3.Row
        self._initialize()
        try:
            Path(self.database_path).chmod(0o600)
        except OSError:
            pass

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence_bundles (
                    bundle_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    case_version INTEGER NOT NULL,
                    analysis_run_id TEXT,
                    manifest_sha256 TEXT NOT NULL,
                    bundle_sha256 TEXT NOT NULL,
                    previous_manifest_sha256 TEXT,
                    relative_path TEXT NOT NULL UNIQUE,
                    bundle_blob BLOB,
                    generated_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    UNIQUE(case_id, case_version)
                )
                """
            )
            columns = {
                str(row["name"])
                for row in self._connection.execute(
                    "PRAGMA table_info(evidence_bundles)"
                ).fetchall()
            }
            if "bundle_blob" not in columns:
                self._connection.execute(
                    "ALTER TABLE evidence_bundles ADD COLUMN bundle_blob BLOB"
                )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def latest_manifest_sha256(self, case_id: str) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT manifest_sha256 FROM evidence_bundles "
                "WHERE case_id = ? ORDER BY case_version DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        return str(row["manifest_sha256"]) if row is not None else None

    def save(
        self,
        bundle: bytes,
        manifest: EvidenceManifest,
        *,
        created_by: str,
    ) -> dict[str, Any]:
        verification_hash = _sha256(bundle)
        manifest_hash = _sha256(
            _json_bytes(manifest.model_dump(mode="json"))
        )
        relative = f"{manifest.case_id}/{manifest.bundle_id}.zip"
        target = (self.bundle_directory / relative).resolve()
        if self.bundle_directory not in target.parents:
            raise EvidenceError("unsafe evidence bundle path")
        target.parent.mkdir(parents=True, exist_ok=True)

        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT * FROM evidence_bundles "
                "WHERE case_id = ? AND case_version = ?",
                (manifest.case_id, manifest.case_version),
            ).fetchone()
            if existing is not None:
                if (
                    existing["bundle_sha256"] != verification_hash
                    or existing["manifest_sha256"] != manifest_hash
                ):
                    raise EvidenceConflictError(
                        "case version already has a different evidence bundle"
                    )
                return self._row(existing)

            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=".evidence-",
                suffix=".tmp",
                dir=target.parent,
            )
            try:
                with os.fdopen(file_descriptor, "wb") as stream:
                    stream.write(bundle)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_name, target)
            except Exception:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
                raise

            self._connection.execute(
                """
                INSERT INTO evidence_bundles (
                    bundle_id, case_id, case_version, analysis_run_id,
                    manifest_sha256, bundle_sha256,
                    previous_manifest_sha256, relative_path, generated_at,
                    created_by, bundle_blob
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest.bundle_id,
                    manifest.case_id,
                    manifest.case_version,
                    manifest.analysis_run_id,
                    manifest_hash,
                    verification_hash,
                    manifest.previous_manifest_sha256,
                    relative,
                    manifest.generated_at,
                    created_by,
                    bundle,
                ),
            )
        return self.get(manifest.bundle_id)

    def get(self, bundle_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM evidence_bundles WHERE bundle_id = ?",
                (bundle_id,),
            ).fetchone()
        if row is None:
            raise EvidenceNotFoundError("evidence bundle not found")
        return self._row(row)

    def get_for_case_version(
        self,
        case_id: str,
        case_version: int,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM evidence_bundles "
                "WHERE case_id = ? AND case_version = ?",
                (case_id, case_version),
            ).fetchone()
        return self._row(row) if row is not None else None

    def list_for_case(self, case_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM evidence_bundles WHERE case_id = ? "
                "ORDER BY case_version DESC",
                (case_id,),
            ).fetchall()
        return [self._row(row) for row in rows]

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            key: row[key]
            for key in row.keys()
            if key != "bundle_blob"
        }

    def read(self, bundle_id: str) -> bytes:
        record = self.get(bundle_id)
        path = (self.bundle_directory / record["relative_path"]).resolve()
        if self.bundle_directory not in path.parents:
            raise EvidenceError("unsafe evidence bundle path")
        try:
            content = path.read_bytes()
        except FileNotFoundError:
            with self._lock:
                row = self._connection.execute(
                    "SELECT bundle_blob FROM evidence_bundles "
                    "WHERE bundle_id = ?",
                    (bundle_id,),
                ).fetchone()
            blob = row["bundle_blob"] if row is not None else None
            if blob is None:
                raise EvidenceNotFoundError(
                    "evidence bundle file is missing"
                )
            content = bytes(blob)
            if _sha256(content) == record["bundle_sha256"]:
                path.parent.mkdir(parents=True, exist_ok=True)
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=".evidence-restore-",
                    suffix=".tmp",
                    dir=path.parent,
                )
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary_name, path)
                except Exception:
                    try:
                        os.unlink(temporary_name)
                    except FileNotFoundError:
                        pass
                    raise
        if _sha256(content) != record["bundle_sha256"]:
            raise EvidenceError("stored evidence bundle hash mismatch")
        return content


__all__ = [
    "EvidenceArtifact",
    "EvidenceBundleService",
    "EvidenceConflictError",
    "EvidenceError",
    "EvidenceManifest",
    "EvidenceNotFoundError",
    "EvidenceRepository",
    "EvidenceVerification",
]
