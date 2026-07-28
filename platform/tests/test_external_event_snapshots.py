from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import http.client
import json
from pathlib import Path
import threading
from typing import Any

import pytest

from mineguard.api import create_server
from mineguard.casework import (
    ExternalEventSnapshotConflictError,
    LocalRepository,
)


WINDOW_START = datetime(2026, 7, 27, 0, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 7, 27, 8, 0, tzinfo=UTC)
EVIDENCE_SHA256 = "e" * 64


def _snapshot(
    *,
    snapshot_id: str = "event-snapshot-001",
    event_codes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "snapshot_id": snapshot_id,
        "mine_id": "mine-001",
        "window_start": WINDOW_START,
        "window_end": WINDOW_END,
        "event_codes": [] if event_codes is None else event_codes,
        "evidence_sha256": EVIDENCE_SHA256,
        "source_system": "regulator-event-ledger",
        "record_id": f"query-result:{snapshot_id}",
        "created_by": "admin",
    }


def test_event_snapshot_exact_empty_and_nonempty_matches() -> None:
    repository = LocalRepository()
    try:
        empty = repository.save_external_event_snapshot(_snapshot())
        assert empty["created"] is True
        assert empty["event_codes"] == []
        assert empty["hash_valid"] is True
        assert repository.find_external_event_snapshot(
            mine_id="mine-001",
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            event_codes=[],
            evidence_sha256={EVIDENCE_SHA256},
        )["snapshot_id"] == "event-snapshot-001"

        populated = repository.save_external_event_snapshot(
            _snapshot(
                snapshot_id="event-snapshot-002",
                event_codes=["WORK-PERMIT", "MAINTENANCE"],
            )
        )
        assert populated["event_codes"] == [
            "MAINTENANCE",
            "WORK-PERMIT",
        ]
        assert repository.find_external_event_snapshot(
            mine_id="mine-001",
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            event_codes=["WORK-PERMIT", "MAINTENANCE"],
            evidence_sha256={EVIDENCE_SHA256},
        )["snapshot_id"] == "event-snapshot-002"
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("event_codes", "evidence", "window_start", "window_end"),
    [
        (["MAINTENANCE"], EVIDENCE_SHA256, WINDOW_START, WINDOW_END),
        (
            ["MAINTENANCE", "WORK-PERMIT", "UNREPORTED"],
            EVIDENCE_SHA256,
            WINDOW_START,
            WINDOW_END,
        ),
        (["MAINTENANCE", "WORK-PERMIT"], "f" * 64, WINDOW_START, WINDOW_END),
        (
            ["MAINTENANCE", "WORK-PERMIT"],
            EVIDENCE_SHA256,
            WINDOW_START + timedelta(seconds=1),
            WINDOW_END,
        ),
        (
            ["MAINTENANCE", "WORK-PERMIT"],
            EVIDENCE_SHA256,
            WINDOW_START,
            WINDOW_END + timedelta(seconds=1),
        ),
    ],
    ids=[
        "missing-code",
        "extra-code",
        "wrong-digest",
        "wrong-window-start",
        "wrong-window-end",
    ],
)
def test_event_snapshot_requires_every_exact_dimension(
    event_codes: list[str],
    evidence: str,
    window_start: datetime,
    window_end: datetime,
) -> None:
    repository = LocalRepository()
    try:
        repository.save_external_event_snapshot(
            _snapshot(
                event_codes=["WORK-PERMIT", "MAINTENANCE"],
            )
        )
        assert repository.find_external_event_snapshot(
            mine_id="mine-001",
            window_start=window_start,
            window_end=window_end,
            event_codes=event_codes,
            evidence_sha256={evidence},
        ) is None
    finally:
        repository.close()


def test_event_snapshot_is_immutable_and_exact_retry_is_idempotent() -> None:
    repository = LocalRepository()
    try:
        first = repository.save_external_event_snapshot(_snapshot())
        retry = repository.save_external_event_snapshot(_snapshot())
        assert first["content_sha256"] == retry["content_sha256"]
        assert retry["created"] is False

        changed = _snapshot()
        changed["evidence_sha256"] = "f" * 64
        with pytest.raises(ExternalEventSnapshotConflictError):
            repository.save_external_event_snapshot(changed)
    finally:
        repository.close()


@contextmanager
def _secure_server(tmp_path: Path) -> Iterator[tuple[str, int]]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=True,
        auth_database_path=tmp_path / "auth.db",
        bootstrap_admin=("admin", "correct admin password"),
        job_database_path=tmp_path / "jobs.db",
        evidence_database_path=tmp_path / "evidence.db",
        evidence_directory=tmp_path / "evidence",
        governance_database_path=tmp_path / "governance.db",
        source_key_directory=tmp_path / "source-keys",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    encoded = (
        None
        if body is None
        else json.dumps(body, separators=(",", ":")).encode("utf-8")
    )
    request_headers = dict(headers or {})
    if encoded is not None:
        request_headers["Content-Type"] = "application/json"
    try:
        connection.request(
            method,
            path,
            body=encoded,
            headers=request_headers,
        )
        response = connection.getresponse()
        payload = response.read()
        return (
            response.status,
            json.loads(payload) if payload else {},
            {
                name.lower(): value
                for name, value in response.getheaders()
            },
        )
    finally:
        connection.close()


def _login(
    host: str,
    port: int,
    username: str,
    password: str,
) -> tuple[str, str]:
    status, payload, headers = _request(
        host,
        port,
        "POST",
        "/v1/auth/login",
        {"username": username, "password": password},
    )
    assert status == 200
    return (
        headers["set-cookie"].split(";", 1)[0],
        str(payload["csrf_token"]),
    )


def test_admin_event_snapshot_api_requires_config_permission_and_csrf(
    tmp_path: Path,
) -> None:
    with _secure_server(tmp_path) as (host, port):
        admin_cookie, admin_csrf = _login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        admin_headers = {
            "Cookie": admin_cookie,
            "X-CSRF-Token": admin_csrf,
        }
        status, _, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/users",
            {
                "username": "reviewer",
                "password": "correct reviewer password",
                "role": "reviewer",
                "mine_scopes": ["mine-001"],
            },
            headers=admin_headers,
        )
        assert status == 201
        reviewer_cookie, reviewer_csrf = _login(
            host,
            port,
            "reviewer",
            "correct reviewer password",
        )

        api_snapshot = _snapshot()
        api_snapshot.pop("created_by")
        api_snapshot["window_start"] = "2026-07-27T00:00:00Z"
        api_snapshot["window_end"] = "2026-07-27T08:00:00Z"

        status, denied, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-event-snapshots",
            api_snapshot,
            headers={"Cookie": admin_cookie},
        )
        assert status == 403
        assert denied["error"]["code"] == "csrf_invalid"

        reviewer_headers = {
            "Cookie": reviewer_cookie,
            "X-CSRF-Token": reviewer_csrf,
        }
        status, denied, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-event-snapshots",
            api_snapshot,
            headers=reviewer_headers,
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"
        status, _, _ = _request(
            host,
            port,
            "GET",
            "/v1/admin/external-event-snapshots",
            headers={"Cookie": reviewer_cookie},
        )
        assert status == 403

        status, created, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-event-snapshots",
            api_snapshot,
            headers=admin_headers,
        )
        assert status == 201
        assert created["snapshot"]["created_by"] == "admin"
        assert created["snapshot"]["event_codes"] == []
        assert created["snapshot"]["hash_valid"] is True

        status, retried, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-event-snapshots",
            api_snapshot,
            headers=admin_headers,
        )
        assert status == 200
        assert retried["snapshot"]["created"] is False

        conflicting = {**api_snapshot, "evidence_sha256": "f" * 64}
        status, conflict, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-event-snapshots",
            conflicting,
            headers=admin_headers,
        )
        assert status == 409
        assert conflict["error"]["code"] == (
            "external_event_snapshot_conflict"
        )

        status, listed, _ = _request(
            host,
            port,
            "GET",
            "/v1/admin/external-event-snapshots",
            headers={"Cookie": admin_cookie},
        )
        assert status == 200
        assert [item["snapshot_id"] for item in listed["items"]] == [
            "event-snapshot-001"
        ]

        status, audit, _ = _request(
            host,
            port,
            "GET",
            "/v1/admin/audit",
            headers={"Cookie": admin_cookie},
        )
        assert status == 200
        assert any(
            event["action"] == "external_event_snapshot_registered"
            for event in audit["items"]
        )
