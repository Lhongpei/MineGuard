from __future__ import annotations

import io
import json
import sqlite3
from pathlib import Path

import pytest

from mineguard.operations import (
    BackupExistsError,
    BackupManager,
    BackupVerificationError,
    JsonAuditLogger,
    ReadinessChecker,
    ReadinessCheckResult,
    RestoreTargetError,
    UnsafePathError,
)


def _database(path: Path, values: tuple[str, ...] = ("alpha", "beta")) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO records(value) VALUES (?)",
            [(value,) for value in values],
        )
        connection.commit()
    finally:
        connection.close()


def _manager(tmp_path: Path, key: bytes = b"a-test-key-not-in-source-config") -> BackupManager:
    return BackupManager(
        tmp_path / "backups",
        hmac_key=key,
        key_id="local-2026-01",
        app_version="0.2.0",
    )


def test_backup_verify_and_restore_multiple_databases(tmp_path: Path) -> None:
    primary = tmp_path / "primary.sqlite3"
    audit = tmp_path / "audit.sqlite3"
    _database(primary)
    _database(audit, ("event-1",))
    manager = _manager(tmp_path)

    manifest = manager.create_backup(
        "nightly-001",
        {"primary.sqlite3": primary, "audit.sqlite3": audit},
    )
    assert manifest["app_version"] == "0.2.0"
    assert manifest["key_id"] == "local-2026-01"
    assert {item["filename"] for item in manifest["files"]} == {
        "primary.sqlite3",
        "audit.sqlite3",
    }
    assert manager.verify_backup("nightly-001")

    restored = manager.restore("nightly-001", tmp_path / "restored")
    connection = sqlite3.connect(restored / "primary.sqlite3")
    try:
        assert connection.execute(
            "SELECT value FROM records ORDER BY id"
        ).fetchall() == [("alpha",), ("beta",)]
    finally:
        connection.close()


def test_backup_is_immutable_and_detects_database_tampering(
    tmp_path: Path,
) -> None:
    database = tmp_path / "app.sqlite3"
    _database(database)
    manager = _manager(tmp_path)
    manager.create_backup("fixed-id", database)
    with pytest.raises(BackupExistsError):
        manager.create_backup("fixed-id", database)

    backup_file = tmp_path / "backups" / "fixed-id" / "app.sqlite3"
    with backup_file.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(BackupVerificationError):
        manager.verify("fixed-id")


def test_manifest_tampering_and_wrong_key_are_rejected(tmp_path: Path) -> None:
    database = tmp_path / "app.sqlite3"
    _database(database)
    manager = _manager(tmp_path)
    manager.create_backup("signed", database)

    wrong_key = _manager(tmp_path, key=b"different-key")
    with pytest.raises(BackupVerificationError):
        wrong_key.verify("signed")

    manifest_path = tmp_path / "backups" / "signed" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["app_version"] = "forged"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    )
    with pytest.raises(BackupVerificationError):
        manager.verify("signed")


def test_backup_and_restore_reject_traversal_and_existing_content(
    tmp_path: Path,
) -> None:
    database = tmp_path / "app.sqlite3"
    _database(database)
    manager = _manager(tmp_path)

    with pytest.raises(UnsafePathError):
        manager.create_backup("../escape", database)
    with pytest.raises(UnsafePathError):
        manager.create_backup("safe", {"../escape.sqlite3": database})

    manager.create_backup("safe", database)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("must remain")
    with pytest.raises(RestoreTargetError):
        manager.restore("safe", occupied)
    assert (occupied / "keep.txt").read_text() == "must remain"
    with pytest.raises(RestoreTargetError):
        manager.restore("safe", ".")


def test_restore_accepts_empty_directory_but_never_overwrites_files(
    tmp_path: Path,
) -> None:
    database = tmp_path / "app.sqlite3"
    _database(database)
    manager = _manager(tmp_path)
    manager.create_backup("empty-target", database)

    target = tmp_path / "empty"
    target.mkdir()
    manager.restore("empty-target", target)
    assert (target / "app.sqlite3").is_file()
    with pytest.raises(RestoreTargetError):
        manager.restore("empty-target", target)


def test_readiness_aggregates_and_isolates_exception_details() -> None:
    checker = ReadinessChecker("test-service")
    executed: list[str] = []

    checker.register(
        "database",
        lambda: ReadinessCheckResult("ready", "数据库正常"),
    )

    def broken() -> None:
        raise RuntimeError("password=should-never-be-returned")

    checker.register(
        "queue",
        broken,
        required=False,
        public_error_message="队列暂不可用",
    )
    checker.register(
        "storage",
        lambda: executed.append("storage") or ("ready", "存储正常"),
    )

    result = checker.readiness()
    assert result["status"] == "degraded"
    assert executed == ["storage"]
    assert all(item["duration_ms"] >= 0 for item in result["checks"])
    serialized = json.dumps(result, ensure_ascii=False)
    assert "should-never-be-returned" not in serialized
    assert "RuntimeError" not in serialized
    assert "队列暂不可用" in serialized
    assert checker.liveness()["status"] == "alive"
    assert checker.health()["status"] == "ok"


def test_readiness_required_failure_is_not_ready() -> None:
    checker = ReadinessChecker()
    checker.register("configuration", lambda: False)
    checker.register("optional", lambda: ("degraded", "功能降级"))
    assert checker.check()["status"] == "not_ready"


def test_json_audit_logger_recursively_redacts_and_writes_json_lines() -> None:
    stream = io.StringIO()
    logger = JsonAuditLogger(stream)
    safe = logger.log(
        "case.close",
        "success",
        request_id="req-1",
        actor="reviewer",
        details={
            "password": "p",
            "nested": [
                {
                    "accessToken": "t",
                    "person_id": "P001",
                    "safe": "visible",
                }
            ],
            "headers": {
                "Authorization": "Bearer abc",
                "Cookie": "sid=123",
            },
        },
        metadata={"csrf-token": "x", "count": 3},
    )
    logger.log("case.read", "success", request_id="req-2", actor=None)

    lines = stream.getvalue().splitlines()
    assert len(lines) == 2
    documents = [json.loads(line) for line in lines]
    assert documents[0] == safe
    assert documents[0]["details"]["password"] == "[REDACTED]"
    assert documents[0]["details"]["nested"][0]["accessToken"] == "[REDACTED]"
    assert documents[0]["details"]["nested"][0]["person_id"] == "[REDACTED]"
    assert documents[0]["details"]["nested"][0]["safe"] == "visible"
    assert documents[0]["details"]["headers"]["Authorization"] == "[REDACTED]"
    assert documents[0]["metadata"]["csrf-token"] == "[REDACTED]"
    assert all(document["timestamp"].endswith("Z") for document in documents)


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), -float("inf")])
def test_json_audit_logger_rejects_non_finite_numbers(invalid: float) -> None:
    stream = io.StringIO()
    logger = JsonAuditLogger(stream)
    with pytest.raises(ValueError):
        logger.log("test", "failure", details={"score": invalid})
    assert stream.getvalue() == ""
