from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import threading
from typing import Any

import pytest

from mineguard.api import create_server
from mineguard.casework import (
    AlgorithmRecordIntegrityError,
    ExternalConfirmerRegistrationConflictError,
    LocalRepository,
)


def _registration(
    *,
    registration_id: str = "confirmer-registration-001-v1",
    version: int = 1,
    confirmer_name: str = "张三",
    roles: list[str] | None = None,
    active: bool = True,
) -> dict[str, Any]:
    return {
        "registration_id": registration_id,
        "client_id": "enterprise-client-001",
        "enterprise_id": "enterprise-001",
        "confirmer_id": "operator-001",
        "version": version,
        "confirmer_name": confirmer_name,
        "confirmer_roles": (
            ["复核员", "企业报送负责人"] if roles is None else roles
        ),
        "confirmation_methods": ["authenticated_click"],
        "active": active,
        "source_system": "regulator-confirmer-ledger",
        "record_id": f"confirmer-case:operator-001:v{version}",
        "created_by": "admin",
    }


def test_confirmer_registry_matches_only_current_exact_active_version() -> None:
    repository = LocalRepository()
    try:
        first = repository.save_external_confirmer_registration(
            _registration()
        )
        assert first["created"] is True
        assert first["confirmer_roles"] == ["企业报送负责人", "复核员"]
        assert first["hash_valid"] is True
        retry = repository.save_external_confirmer_registration(
            _registration()
        )
        assert retry["created"] is False
        assert retry["content_sha256"] == first["content_sha256"]

        matched = (
            repository.find_current_external_confirmer_registration(
                client_id="enterprise-client-001",
                enterprise_id="enterprise-001",
                confirmer_id="operator-001",
                confirmer_name="张三",
                confirmer_role="企业报送负责人",
                confirmation_method="authenticated_click",
            )
        )
        assert matched is not None
        assert matched["registration_id"] == "confirmer-registration-001-v1"

        second = repository.save_external_confirmer_registration(
            _registration(
                registration_id="confirmer-registration-001-v2",
                version=2,
                confirmer_name="张三（新备案）",
                roles=["企业报送负责人"],
            )
        )
        assert second["previous_content_sha256"] == first["content_sha256"]
        assert second["version_chain_valid"] is True
        assert (
            repository.find_current_external_confirmer_registration(
                client_id="enterprise-client-001",
                enterprise_id="enterprise-001",
                confirmer_id="operator-001",
                confirmer_name="张三",
                confirmer_role="企业报送负责人",
                confirmation_method="authenticated_click",
            )
            is None
        )
        assert (
            repository.find_current_external_confirmer_registration(
                client_id="enterprise-client-001",
                enterprise_id="enterprise-001",
                confirmer_id="operator-001",
                confirmer_name="张三（新备案）",
                confirmer_role="企业报送负责人",
                confirmation_method="authenticated_click",
            )
            is not None
        )

        third = repository.save_external_confirmer_registration(
            _registration(
                registration_id="confirmer-registration-001-v3",
                version=3,
                confirmer_name="张三（新备案）",
                roles=["企业报送负责人"],
                active=False,
            )
        )
        assert third["active"] is False
        assert (
            repository.find_current_external_confirmer_registration(
                client_id="enterprise-client-001",
                enterprise_id="enterprise-001",
                confirmer_id="operator-001",
                confirmer_name="张三（新备案）",
                confirmer_role="企业报送负责人",
                confirmation_method="authenticated_click",
            )
            is None
        )
        versions = repository.list_external_confirmer_registrations()
        assert [item["version"] for item in versions] == [3, 2, 1]
        assert all(item["hash_valid"] for item in versions)
        assert all(item["version_chain_valid"] for item in versions)
    finally:
        repository.close()


def test_confirmer_registry_rejects_overwrite_gap_and_unverified_method() -> None:
    repository = LocalRepository()
    try:
        repository.save_external_confirmer_registration(_registration())
        overwritten = _registration()
        overwritten["confirmer_name"] = "冒名覆盖"
        with pytest.raises(ExternalConfirmerRegistrationConflictError):
            repository.save_external_confirmer_registration(overwritten)

        same_version_new_id = _registration(
            registration_id="another-registration-id"
        )
        with pytest.raises(ExternalConfirmerRegistrationConflictError):
            repository.save_external_confirmer_registration(
                same_version_new_id
            )

        with pytest.raises(
            ExternalConfirmerRegistrationConflictError,
            match="expected version 2",
        ):
            repository.save_external_confirmer_registration(
                _registration(
                    registration_id="confirmer-registration-001-v3",
                    version=3,
                )
            )

        unsupported = _registration(
            registration_id="confirmer-registration-001-v2",
            version=2,
        )
        unsupported["confirmation_methods"] = ["qualified_e_signature"]
        with pytest.raises(ValueError, match="authenticated_click"):
            repository.save_external_confirmer_registration(unsupported)
    finally:
        repository.close()


def test_confirmer_registry_detects_stored_tampering() -> None:
    repository = LocalRepository()
    try:
        repository.save_external_confirmer_registration(_registration())
        with repository._connection:  # noqa: SLF001 - deliberate tamper test
            repository._connection.execute(  # noqa: SLF001
                """
                UPDATE external_confirmer_registrations
                SET active = 0
                WHERE registration_id = ?
                """,
                ("confirmer-registration-001-v1",),
            )
        with pytest.raises(AlgorithmRecordIntegrityError):
            repository.list_external_confirmer_registrations()
        with pytest.raises(AlgorithmRecordIntegrityError):
            repository.find_current_external_confirmer_registration(
                client_id="enterprise-client-001",
                enterprise_id="enterprise-001",
                confirmer_id="operator-001",
                confirmer_name="张三",
                confirmer_role="企业报送负责人",
                confirmation_method="authenticated_click",
            )
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
    username: str = "admin",
    password: str = "correct admin password",
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


def test_admin_confirmer_registry_api_is_protected_versioned_and_audited(
    tmp_path: Path,
) -> None:
    with _secure_server(tmp_path) as (host, port):
        cookie, csrf = _login(host, port)
        first = _registration()
        first.pop("created_by")

        status, denied, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-confirmers",
            first,
            headers={"Cookie": cookie},
        )
        assert status == 403
        assert denied["error"]["code"] == "csrf_invalid"

        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
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
            headers=headers,
        )
        assert status == 201
        reviewer_cookie, reviewer_csrf = _login(
            host,
            port,
            "reviewer",
            "correct reviewer password",
        )
        reviewer_headers = {
            "Cookie": reviewer_cookie,
            "X-CSRF-Token": reviewer_csrf,
        }
        status, denied, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-confirmers",
            first,
            headers=reviewer_headers,
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"
        status, denied, _ = _request(
            host,
            port,
            "GET",
            "/v1/admin/external-confirmers",
            headers={"Cookie": reviewer_cookie},
        )
        assert status == 403
        assert denied["error"]["code"] == "permission_denied"

        status, created, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-confirmers",
            first,
            headers=headers,
        )
        assert status == 201
        assert created["registration"]["created_by"] == "admin"
        assert created["registration"]["version"] == 1

        status, retried, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-confirmers",
            first,
            headers=headers,
        )
        assert status == 200
        assert retried["registration"]["created"] is False

        disabled = _registration(
            registration_id="confirmer-registration-001-v2",
            version=2,
            active=False,
        )
        disabled.pop("created_by")
        status, response, _ = _request(
            host,
            port,
            "POST",
            "/v1/admin/external-confirmers",
            disabled,
            headers=headers,
        )
        assert status == 201
        assert response["registration"]["active"] is False

        status, listed, _ = _request(
            host,
            port,
            "GET",
            "/v1/admin/external-confirmers",
            headers={"Cookie": cookie},
        )
        assert status == 200
        assert [item["version"] for item in listed["items"]] == [2, 1]
        assert "不可删除或覆盖" in listed["immutability_notice"]

        status, audit, _ = _request(
            host,
            port,
            "GET",
            "/v1/admin/audit",
            headers={"Cookie": cookie},
        )
        assert status == 200
        registration_events = [
            event
            for event in audit["items"]
            if event["action"]
            == "external_confirmer_registration_version_registered"
        ]
        assert len(registration_events) == 3
        assert registration_events[0]["detail"]["content_sha256"]
