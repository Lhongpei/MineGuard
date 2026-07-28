from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import http.client
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Iterator

import pytest

from mineguard.api import create_server
from mineguard.auth import Role
from mineguard.edge_store import (
    EdgeTelemetryRepository,
    InvalidVerificationReferenceActionError,
    VerificationReferenceConflictError,
)
from mineguard.verification import HistoricalVerificationSample


ADMIN_PASSWORD = "correct admin password"
APPROVER_PASSWORD = "correct approver password"
SUPERVISOR_PASSWORD = "correct supervisor password"
APPROVAL_NOTE = "independent source evidence approval confirmed"
DIGESTS = {
    "production": "a" * 64,
    "electricity": "b" * 64,
    "explosives": "c" * 64,
}
EVIDENCE_REFS = [
    "evidence://production/report-001",
    "evidence://electricity/meter-001",
    "evidence://explosives/ledger-001",
]


def _sample(
    sample_id: str = "history-001",
    *,
    mine_id: str = "M001",
) -> dict[str, Any]:
    raw = {
        "sample_id": sample_id,
        "mine_id": mine_id,
        "window_start": "2026-07-01T00:00:00Z",
        "window_end": "2026-07-02T00:00:00Z",
        "available_at": "2026-07-02T01:00:00Z",
        "operating_condition": {
            "regime_code": "normal-production",
            "mining_method": "longwall",
            "seam_code": "3",
            "face_code": "3101",
            "shift_code": "daily",
            "geology_zone": "zone-a",
            "maintenance": False,
        },
        "reported_production_t": 100.0,
        "electricity": {
            "source_id": "production-zone-meter-history",
            "production_zone_kwh": 10_000.0,
            "total_kwh": None,
            "interference": [],
        },
        "explosives": {
            "explosives_used_kg": 10.0,
            "source_id": "explosives-ledger-history",
        },
        "quality_score": 0.98,
        "source_hash_valid": True,
        "compatibility_key": "verification-test-v1",
        "review_label": "verified_normal",
        "human_reviewed": True,
        "reviewed_by": "historical-reviewer",
        "reviewed_at": "2026-07-02T02:00:00Z",
        "review_confidence": 0.99,
    }
    return HistoricalVerificationSample.model_validate_json(
        json.dumps(raw)
    ).model_dump(mode="json")


def _registration(sample: dict[str, Any]) -> dict[str, Any]:
    return {
        "sample": sample,
        "source_digests": DIGESTS,
        "evidence_refs": EVIDENCE_REFS,
    }


def _analysis(
    sample: dict[str, Any],
    *,
    request_id: str,
    mine_id: str = "M001",
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "mine_id": mine_id,
        "window_start": "2026-07-28T00:00:00Z",
        "window_end": "2026-07-29T00:00:00Z",
        "decision_time": "2026-07-29T01:00:00Z",
        "operating_condition": {
            "regime_code": "normal-production",
            "mining_method": "longwall",
            "seam_code": "3",
            "face_code": "3101",
            "shift_code": "daily",
            "geology_zone": "zone-a",
            "maintenance": False,
        },
        "reported_production_t": 100.0,
        "production_source_id": "daily-production-report",
        "electricity": {
            "source_id": "production-zone-meter-current",
            "production_zone_kwh": 10_000.0,
            "total_kwh": None,
            "interference": [],
        },
        "explosives": {
            "explosives_used_kg": 10.0,
            "source_id": "explosives-ledger-current",
        },
        "history": [sample],
        "parameters": {
            "minimum_samples": 3,
            "maximum_samples": 100,
            "compatibility_key": "verification-test-v1",
        },
    }


@contextmanager
def _server(
    tmp_path: Path,
    *,
    auth_required: bool,
) -> Iterator[Any]:
    options: dict[str, Any] = {
        "database_path": tmp_path / "main.db",
        "auth_required": auth_required,
        "auth_database_path": tmp_path / "auth.db",
        "job_database_path": tmp_path / "jobs.db",
        "secure_cookie": False,
    }
    if auth_required:
        options["bootstrap_admin"] = ("admin", ADMIN_PASSWORD)
    server = create_server("127.0.0.1", 0, **options)
    for mine_id in ("M001", "M002"):
        server.edge_repository.upsert_mine(
            {
                "mine_id": mine_id,
                "mine_name": f"测试矿井 {mine_id}",
                "gas_category": "high_gas",
                "approved_underground_personnel": 100,
            },
            actor_id="test",
        )
    if auth_required:
        server.auth_store.create_user(
            "approver",
            APPROVER_PASSWORD,
            Role.ADMIN,
            [],
        )
        server.auth_store.create_user(
            "supervisor",
            SUPERVISOR_PASSWORD,
            Role.SUPERVISOR,
            ["M001"],
        )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _raw_request(
    server: Any,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    host, port = server.server_address[:2]
    connection = http.client.HTTPConnection(host, port, timeout=5)
    encoded = None if body is None else json.dumps(body).encode("utf-8")
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
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        return response.status, response.read(), response_headers
    finally:
        connection.close()


def _json_request(
    server: Any,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    status, raw, _ = _raw_request(
        server,
        method,
        path,
        body,
        headers=headers,
    )
    return status, json.loads(raw)


def _login(
    server: Any,
    username: str,
    password: str,
) -> tuple[str, str]:
    status, raw, response_headers = _raw_request(
        server,
        "POST",
        "/v1/auth/login",
        {"username": username, "password": password},
    )
    assert status == 200
    payload = json.loads(raw)
    cookie = response_headers["set-cookie"].split(";", 1)[0]
    return cookie, payload["csrf_token"]


def _headers(cookie: str, csrf: str | None = None) -> dict[str, str]:
    result = {"Cookie": cookie}
    if csrf is not None:
        result["X-CSRF-Token"] = csrf
    return result


def test_registry_is_immutable_four_eye_idempotent_and_tamper_evident(
    tmp_path: Path,
) -> None:
    repository = EdgeTelemetryRepository(tmp_path / "registry.db")
    sample = _sample()
    try:
        repository.upsert_mine(
            {
                "mine_id": "M001",
                "mine_name": "测试矿井 M001",
                "gas_category": "high_gas",
                "approved_underground_personnel": 100,
            },
            actor_id="test",
        )
        registered, created = (
            repository.register_verification_reference(
                sample=sample,
                source_digests=DIGESTS,
                evidence_refs=EVIDENCE_REFS,
                actor_id="registrar",
            )
        )
        assert created is True
        assert registered["status"] == "draft"
        assert registered["registry_integrity_valid"] is True

        repeated, created = repository.register_verification_reference(
            sample=sample,
            source_digests=DIGESTS,
            evidence_refs=EVIDENCE_REFS,
            actor_id="registrar",
        )
        assert created is False
        assert repeated["sample_sha256"] == registered["sample_sha256"]

        changed_sample = deepcopy(sample)
        changed_sample["reported_production_t"] = 101.0
        with pytest.raises(VerificationReferenceConflictError):
            repository.register_verification_reference(
                sample=changed_sample,
                source_digests=DIGESTS,
                evidence_refs=EVIDENCE_REFS,
                actor_id="registrar",
            )
        changed_digests = {**DIGESTS, "production": "d" * 64}
        with pytest.raises(VerificationReferenceConflictError):
            repository.register_verification_reference(
                sample=sample,
                source_digests=changed_digests,
                evidence_refs=EVIDENCE_REFS,
                actor_id="registrar",
            )

        with pytest.raises(InvalidVerificationReferenceActionError):
            repository.decide_verification_reference(
                sample["sample_id"],
                action="approve",
                expected_sample_sha256=registered["sample_sha256"],
                note=APPROVAL_NOTE,
                actor_id="registrar",
            )
        with pytest.raises(VerificationReferenceConflictError):
            repository.decide_verification_reference(
                sample["sample_id"],
                action="approve",
                expected_sample_sha256="f" * 64,
                note=APPROVAL_NOTE,
                actor_id="approver",
            )

        approved, changed = repository.decide_verification_reference(
            sample["sample_id"],
            action="approve",
            expected_sample_sha256=registered["sample_sha256"],
            note=APPROVAL_NOTE,
            actor_id="approver",
        )
        assert changed is True
        assert approved["status"] == "approved"
        assert approved["registered_by"] == "registrar"
        assert approved["decided_by"] == "approver"
        assert approved["registry_integrity_valid"] is True

        repeated, changed = repository.decide_verification_reference(
            sample["sample_id"],
            action="approve",
            expected_sample_sha256=registered["sample_sha256"],
            note=APPROVAL_NOTE,
            actor_id="approver",
        )
        assert changed is False
        assert repeated["decided_at"] == approved["decided_at"]

        accepted, failures = (
            repository.validate_verification_reference_history(
                [sample],
                expected_mine_id="M001",
            )
        )
        assert failures == []
        assert accepted[0]["sample_sha256"] == registered["sample_sha256"]

        rejected_sample = _sample("history-rejected")
        rejected_draft, _ = (
            repository.register_verification_reference(
                sample=rejected_sample,
                source_digests=DIGESTS,
                evidence_refs=EVIDENCE_REFS,
                actor_id="registrar",
            )
        )
        rejected, changed = repository.decide_verification_reference(
            rejected_sample["sample_id"],
            action="reject",
            expected_sample_sha256=rejected_draft["sample_sha256"],
            note="independent evidence review rejected this sample",
            actor_id="approver",
        )
        assert changed is True
        assert rejected["status"] == "rejected"
        accepted, failures = (
            repository.validate_verification_reference_history(
                [rejected_sample],
                expected_mine_id="M001",
            )
        )
        assert accepted == []
        assert failures[0]["code"] == "reference_not_approved"
        assert failures[0]["status"] == "rejected"

        with pytest.raises(sqlite3.IntegrityError):
            repository._connection.execute(  # noqa: SLF001
                """
                UPDATE verification_reference_samples
                SET sample_json = '{}'
                WHERE sample_id = ?
                """,
                (sample["sample_id"],),
            )
        with pytest.raises(sqlite3.IntegrityError):
            repository._connection.execute(  # noqa: SLF001
                """
                UPDATE verification_reference_events
                SET note = 'tampered'
                WHERE sample_id = ?
                """,
                (sample["sample_id"],),
            )

        repository._connection.execute(  # noqa: SLF001
            """
            UPDATE verification_reference_samples
            SET status = 'rejected'
            WHERE sample_id = ?
            """,
            (sample["sample_id"],),
        )
        accepted, failures = (
            repository.validate_verification_reference_history(
                [sample],
                expected_mine_id="M001",
            )
        )
        assert accepted == []
        assert failures == [
            {
                "sample_id": sample["sample_id"],
                "code": "reference_registry_integrity_failed",
            }
        ]
    finally:
        repository.close()


def test_authenticated_api_requires_registry_permissions_and_exact_approval(
    tmp_path: Path,
) -> None:
    sample = _sample()
    with _server(tmp_path, auth_required=True) as server:
        admin_cookie, admin_csrf = _login(
            server,
            "admin",
            ADMIN_PASSWORD,
        )
        approver_cookie, approver_csrf = _login(
            server,
            "approver",
            APPROVER_PASSWORD,
        )
        supervisor_cookie, supervisor_csrf = _login(
            server,
            "supervisor",
            SUPERVISOR_PASSWORD,
        )
        admin_headers = _headers(admin_cookie, admin_csrf)
        approver_headers = _headers(approver_cookie, approver_csrf)

        status, _ = _json_request(
            server,
            "POST",
            "/v1/admin/verification-references",
            _registration(sample),
            headers=_headers(supervisor_cookie, supervisor_csrf),
        )
        assert status == 403

        unknown_mine_sample = _sample(
            "history-unknown-mine",
            mine_id="M999",
        )
        status, payload = _json_request(
            server,
            "POST",
            "/v1/admin/verification-references",
            _registration(unknown_mine_sample),
            headers=admin_headers,
        )
        assert status == 409
        assert (
            payload["error"]["code"]
            == "verification_reference_mine_not_found"
        )

        status, registered = _json_request(
            server,
            "POST",
            "/v1/admin/verification-references",
            _registration(sample),
            headers=admin_headers,
        )
        assert status == 201
        assert registered["created"] is True
        sample_sha256 = registered["sample_sha256"]

        status, repeated = _json_request(
            server,
            "POST",
            "/v1/admin/verification-references",
            _registration(sample),
            headers=admin_headers,
        )
        assert status == 200
        assert repeated["created"] is False

        status, _ = _json_request(
            server,
            "POST",
            f"/v1/admin/verification-references/{sample['sample_id']}/actions",
            {
                "action": "approve",
                "expected_sample_sha256": sample_sha256,
                "note": APPROVAL_NOTE,
            },
            headers=admin_headers,
        )
        assert status == 409

        status, approved = _json_request(
            server,
            "POST",
            f"/v1/admin/verification-references/{sample['sample_id']}/actions",
            {
                "action": "approve",
                "expected_sample_sha256": sample_sha256,
                "note": APPROVAL_NOTE,
            },
            headers=approver_headers,
        )
        assert status == 200
        assert approved["status"] == "approved"
        assert approved["changed"] is True

        status, repeated = _json_request(
            server,
            "POST",
            f"/v1/admin/verification-references/{sample['sample_id']}/actions",
            {
                "action": "approve",
                "expected_sample_sha256": sample_sha256,
                "note": APPROVAL_NOTE,
            },
            headers=approver_headers,
        )
        assert status == 200
        assert repeated["changed"] is False
        assert repeated["decided_at"] == approved["decided_at"]

        status, _ = _json_request(
            server,
            "GET",
            "/v1/admin/verification-references?mine_id=M001",
            headers=_headers(supervisor_cookie),
        )
        assert status == 403
        status, listed = _json_request(
            server,
            "GET",
            "/v1/admin/verification-references"
            "?mine_id=M001&status=approved",
            headers=_headers(approver_cookie),
        )
        assert status == 200
        assert listed["count"] == 1
        assert listed["items"][0]["registry_integrity_valid"] is True

        unregistered = _sample("history-unregistered")
        status, payload = _json_request(
            server,
            "POST",
            "/v1/analyze/verification",
            _analysis(
                unregistered,
                request_id="verification-unregistered",
            ),
            headers=admin_headers,
        )
        assert status == 409
        assert (
            payload["error"]["details"][0]["code"]
            == "reference_not_registered"
        )

        tampered = deepcopy(sample)
        tampered["reported_production_t"] = 101.0
        status, payload = _json_request(
            server,
            "POST",
            "/v1/analyze/verification",
            _analysis(tampered, request_id="verification-tampered"),
            headers=admin_headers,
        )
        assert status == 409
        assert (
            payload["error"]["details"][0]["code"]
            == "reference_hash_mismatch"
        )

        status, payload = _json_request(
            server,
            "POST",
            "/v1/analyze/verification",
            _analysis(
                sample,
                request_id="verification-wrong-mine",
                mine_id="M002",
            ),
            headers=admin_headers,
        )
        assert status == 409
        assert (
            payload["error"]["details"][0]["code"]
            == "reference_mine_mismatch"
        )

        status, payload = _json_request(
            server,
            "POST",
            "/v1/analyze/verification",
            _analysis(sample, request_id="verification-success"),
            headers=admin_headers,
        )
        assert status == 201
        assert payload["history_governance"]["mode"] == (
            "platform_approved_registry"
        )
        assert payload["history_governance"]["sample_count"] == 1
        assert (
            payload["history_governance"]["approved_references"][0][
                "sample_sha256"
            ]
            == sample_sha256
        )

        status, repeated = _json_request(
            server,
            "POST",
            "/v1/analyze/verification",
            _analysis(sample, request_id="verification-success"),
            headers=admin_headers,
        )
        assert status == 200
        assert repeated["created"] is False
        assert repeated["run_id"] == payload["run_id"]

        status, runs = _json_request(
            server,
            "GET",
            "/v1/verification/runs?mine_id=M001",
            headers=_headers(admin_cookie),
        )
        assert status == 200
        assert runs["count"] == 1
        assert runs["items"][0]["result"]["history_governance"]["mode"] == (
            "platform_approved_registry"
        )


def test_auth_disabled_marks_caller_history_untrusted_in_response_and_store(
    tmp_path: Path,
) -> None:
    sample = _sample("history-dev-unregistered")
    with _server(tmp_path, auth_required=False) as server:
        status, payload = _json_request(
            server,
            "POST",
            "/v1/analyze/verification",
            _analysis(sample, request_id="verification-dev"),
        )
        assert status == 201
        assert payload["history_governance"] == {
            "mode": "caller_supplied_untrusted",
            "sample_count": 1,
            "trusted_for_production": False,
            "note": (
                "authentication is disabled; caller-supplied historical "
                "claims were not approved by the platform registry"
            ),
        }

        status, runs = _json_request(
            server,
            "GET",
            "/v1/verification/runs?mine_id=M001",
        )
        assert status == 200
        assert runs["items"][0]["result"]["history_governance"]["mode"] == (
            "caller_supplied_untrusted"
        )
