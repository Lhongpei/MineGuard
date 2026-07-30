from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from enterprise_agent.auth import (
    AuthManager,
    UserAccount,
    build_auth_manager,
    demo_account,
    hash_password,
)
from enterprise_agent.http_api import EnterpriseAgentHTTPServer


class SpyService:
    llm_provider = None
    platform_client = None

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def list_drafts(
        self,
        *,
        limit: int,
        offset: int,
    ) -> tuple[list[dict[str, Any]], int]:
        self.calls.append(("list", {"limit": limit, "offset": offset}))
        return [], 0

    def create_draft(
        self,
        values: dict[str, Any],
        *,
        actor: str,
    ) -> dict[str, Any]:
        self.calls.append(("create", {"values": values, "actor": actor}))
        return {"draft_id": "draft-1", "_meta": {"revision": 1}}

    def observation_review_state(
        self,
        draft_id: str,
        *,
        actor: str,
    ) -> dict[str, Any]:
        return {
            "revision": 1,
            "reviewer_id": actor,
            "total": 0,
            "reviewed_count": 0,
            "all_reviewed": False,
            "observations": [],
        }

    def confirm(self, draft_id: str, **values: Any) -> dict[str, Any]:
        self.calls.append(("confirm", {"draft_id": draft_id, **values}))
        return {"draft_id": draft_id, "_meta": {"confirmed": True}}

    def review_observations(
        self,
        draft_id: str,
        **values: Any,
    ) -> dict[str, Any]:
        self.calls.append(("reviews", {"draft_id": draft_id, **values}))
        return {
            "revision": values["expected_revision"],
            "reviewer_id": values["actor"],
            "total": len(values["observation_ids"]),
            "reviewed_count": len(values["observation_ids"]),
            "all_reviewed": values["reviewed"],
            "observations": [],
        }

    def submit(
        self,
        draft_id: str,
        *,
        idempotency_key: str | None,
        actor: str,
    ) -> dict[str, Any]:
        self.calls.append(
            (
                "submit",
                {
                    "draft_id": draft_id,
                    "idempotency_key": idempotency_key,
                    "actor": actor,
                },
            )
        )
        return {"draft_id": draft_id, "status": "succeeded"}

    def delete_draft(
        self,
        draft_id: str,
        *,
        actor: str,
        expected_revision: int | None,
    ) -> None:
        self.calls.append(
            (
                "delete",
                {
                    "draft_id": draft_id,
                    "actor": actor,
                    "expected_revision": expected_revision,
                },
            )
        )


def _account(
    actor_id: str,
    *,
    name: str,
    role: str,
    password: str,
    permissions: set[str],
) -> UserAccount:
    return UserAccount(
        actor_id=actor_id,
        name=name,
        role=role,
        password_hash=hash_password(
            password,
            iterations=100_000,
            salt=(actor_id.encode("utf-8") + b"0" * 16)[:16],
        ),
        permissions=frozenset(permissions),
    )


@contextmanager
def _running(
    accounts: tuple[UserAccount, ...],
    *,
    web_root: Path | None = None,
) -> Iterator[tuple[SpyService, http.client.HTTPConnection]]:
    service = SpyService()
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,  # type: ignore[arg-type]
        auth_manager=AuthManager(accounts, session_ttl_seconds=300),
        web_root=web_root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=3,
    )
    try:
        yield service, connection
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _request(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    cookie: str | None = None,
    csrf: str | None = None,
    origin: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    encoded = (
        json.dumps(body, ensure_ascii=False).encode("utf-8")
        if body is not None
        else None
    )
    headers = {"Content-Type": "application/json"} if encoded is not None else {}
    if cookie is not None:
        headers["Cookie"] = cookie
    if csrf is not None:
        headers["X-CSRF-Token"] = csrf
    if origin is not None:
        headers["Origin"] = origin
    headers.update(extra_headers or {})
    connection.request(method, path, body=encoded, headers=headers)
    response = connection.getresponse()
    parsed = json.loads(response.read())
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    return response.status, parsed, response_headers


def _login(
    connection: http.client.HTTPConnection,
    actor_id: str,
    password: str,
) -> tuple[str, str, dict[str, Any], str]:
    status, payload, headers = _request(
        connection,
        "POST",
        "/api/v1/auth/login",
        {"actor_id": actor_id, "password": password},
    )
    assert status == 200
    set_cookie = headers["set-cookie"]
    cookie = set_cookie.split(";", 1)[0]
    return cookie, payload["csrf_token"], payload["principal"], set_cookie


def test_health_discloses_demo_mode_without_disclosing_accounts() -> None:
    with _running((demo_account(),)) as (_, connection):
        status, health, _ = _request(
            connection,
            "GET",
            "/api/v1/health",
        )
        assert status == 200
        assert health["authentication_mode"] == "temporary_demo"
        assert health["demo_account_enabled"] is True
        assert "accounts" not in health


def test_session_login_me_csrf_logout_and_bearer_is_not_authentication() -> None:
    account = _account(
        "operator-1",
        name="张三",
        role="企业经办人",
        password="operator-password",
        permissions={"read", "write"},
    )
    with _running((account,)) as (_, connection):
        status, _, _ = _request(connection, "GET", "/api/v1/drafts")
        assert status == 401
        status, _, _ = _request(
            connection,
            "GET",
            "/api/v1/drafts",
            extra_headers={"Authorization": "Bearer legacy-token"},
        )
        assert status == 401
        status, error, _ = _request(
            connection,
            "GET",
            "/api/v1/drafts",
            extra_headers={"Host": "attacker.example"},
        )
        assert status == 403
        assert error["error"]["code"] == "host_not_allowed"

        cookie, csrf, principal, set_cookie = _login(
            connection,
            "operator-1",
            "operator-password",
        )
        assert principal == {
            "actor_id": "operator-1",
            "name": "张三",
            "role": "企业经办人",
            "permissions": ["read", "write"],
            "authentication_method": "password_session",
            "must_change_password": False,
            "temporary_demo": False,
        }
        assert "HttpOnly" in set_cookie
        assert "SameSite=Strict" in set_cookie
        assert "operator-password" not in json.dumps(principal)

        status, me, _ = _request(
            connection,
            "GET",
            "/api/v1/auth/me",
            cookie=cookie,
        )
        assert status == 200
        assert me["csrf_token"] == csrf

        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {},
            cookie=cookie,
        )
        assert status == 403
        assert error["error"]["code"] == "csrf_token_invalid"

        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {},
            cookie=cookie,
            csrf=csrf,
            origin="https://evil.example",
        )
        assert status == 403
        assert error["error"]["code"] == "cross_origin_request_denied"

        status, _, headers = _request(
            connection,
            "POST",
            "/api/v1/auth/logout",
            {},
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert "Max-Age=0" in headers["set-cookie"]
        status, _, _ = _request(
            connection,
            "GET",
            "/api/v1/auth/me",
            cookie=cookie,
        )
        assert status == 401


def test_authenticated_principal_overrides_actor_and_confirmation_identity() -> None:
    account = _account(
        "confirmer-1",
        name="李审核",
        role="企业报送负责人",
        password="confirm-password",
        permissions={"read", "write", "confirm", "submit"},
    )
    with _running((account,)) as (service, connection):
        cookie, csrf, _, _ = _login(
            connection,
            "confirmer-1",
            "confirm-password",
        )
        status, _, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {
                "actor": "forged-actor",
                "actor_id": "forged-id",
                "values": {"enterprise_name": "测试企业"},
            },
            cookie=cookie,
            csrf=csrf,
            extra_headers={"X-Actor-ID": "forged-header"},
        )
        assert status == 201
        create = service.calls[-1]
        assert create[0] == "create"
        assert create[1]["actor"] == "confirmer-1"

        status, _, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts/draft-1/confirm",
            {
                "actor": "forged-actor",
                "confirmer_name": "伪造姓名",
                "confirmer_role": "伪造岗位",
                "accepted": True,
                "attestation": "本人已经逐项核对所有原始数据。",
                "expected_revision": 2,
                "confirmation_method": "account",
            },
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        confirmation = service.calls[-1]
        assert confirmation[0] == "confirm"
        assert confirmation[1]["actor"] == "confirmer-1"
        assert confirmation[1]["confirmer_name"] == "李审核"
        assert confirmation[1]["confirmer_role"] == "企业报送负责人"
        assert confirmation[1]["confirmation_method"] == "authenticated_click"

        status, _, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts/draft-1/submit",
            {"idempotency_key": "enterprise-001-http-submit-v1"},
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        submission = service.calls[-1]
        assert submission[0] == "submit"
        assert submission[1]["actor"] == "confirmer-1"

        status, reviewed, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts/draft-1/reviews",
            {
                "observation_id": "obs-1",
                "reviewed": True,
                "expected_revision": 2,
                "actor": "forged-reviewer",
            },
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 200
        assert reviewed["review_state"]["reviewer_id"] == "confirmer-1"
        review_call = service.calls[-1]
        assert review_call[0] == "reviews"
        assert review_call[1]["actor"] == "confirmer-1"

        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts/draft-1/confirm",
            {
                "accepted": True,
                "attestation": "本人已经逐项核对所有原始数据。",
                "expected_revision": 2,
                "confirmation_method": "qualified_electronic_signature",
            },
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 400
        assert "外部证明适配器" in error["error"]["message"]


def test_permissions_are_checked_before_business_actions() -> None:
    reader = _account(
        "reader",
        name="只读用户",
        role="监督查看",
        password="reader-password",
        permissions={"read"},
    )
    editor = _account(
        "editor",
        name="编辑用户",
        role="企业经办",
        password="editor-password",
        permissions={"read", "write"},
    )
    with _running((reader, editor)) as (service, connection):
        reader_cookie, reader_csrf, _, _ = _login(
            connection,
            "reader",
            "reader-password",
        )
        status, _, _ = _request(
            connection,
            "GET",
            "/api/v1/drafts",
            cookie=reader_cookie,
        )
        assert status == 200
        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {},
            cookie=reader_cookie,
            csrf=reader_csrf,
        )
        assert status == 403
        assert error["error"]["code"] == "permission_denied"

        editor_cookie, editor_csrf, _, _ = _login(
            connection,
            "editor",
            "editor-password",
        )
        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts/draft-1/confirm",
            {
                "accepted": True,
                "attestation": "本人已经逐项核对所有原始数据。",
                "expected_revision": 2,
            },
            cookie=editor_cookie,
            csrf=editor_csrf,
        )
        assert status == 403
        assert error["error"]["code"] == "permission_denied"
        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts/draft-1/submit",
            {},
            cookie=editor_cookie,
            csrf=editor_csrf,
        )
        assert status == 403
        assert error["error"]["code"] == "permission_denied"
        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts/draft-1/reviews",
            {
                "observation_id": "obs-1",
                "reviewed": True,
                "expected_revision": 1,
            },
            cookie=editor_cookie,
            csrf=editor_csrf,
        )
        assert status == 403
        assert error["error"]["code"] == "permission_denied"
        assert not any(
            call[0] in {"confirm", "submit", "reviews"}
            for call in service.calls
        )

        status, error, _ = _request(
            connection,
            "DELETE",
            "/api/v1/drafts/draft-1",
            {"expected_revision": 1},
            cookie=reader_cookie,
            csrf=reader_csrf,
        )
        assert status == 403
        assert error["error"]["code"] == "permission_denied"
        assert not any(call[0] == "delete" for call in service.calls)

        status, error, _ = _request(
            connection,
            "DELETE",
            "/api/v1/drafts/draft-1",
            {"expected_revision": 1},
            cookie=editor_cookie,
        )
        assert status == 403
        assert error["error"]["code"] == "csrf_token_invalid"
        assert not any(call[0] == "delete" for call in service.calls)

        status, result, _ = _request(
            connection,
            "DELETE",
            "/api/v1/drafts/draft-1",
            {
                "expected_revision": 1,
                "actor": "forged-owner",
            },
            cookie=editor_cookie,
            csrf=editor_csrf,
        )
        assert status == 200
        assert result == {"deleted": True}
        assert service.calls[-1] == (
            "delete",
            {
                "draft_id": "draft-1",
                "actor": "editor",
                "expected_revision": 1,
            },
        )


def test_remote_server_rejects_empty_or_anonymous_auth_manager() -> None:
    service = SpyService()
    with pytest.raises(ValueError, match="逐用户账号"):
        EnterpriseAgentHTTPServer(
            ("0.0.0.0", 0),
            service,  # type: ignore[arg-type]
            auth_manager=AuthManager(),
        )
    with pytest.raises(ValueError, match="逐用户账号"):
        EnterpriseAgentHTTPServer(
            ("0.0.0.0", 0),
            service,  # type: ignore[arg-type]
            auth_manager=AuthManager(allow_anonymous_local=True),
        )
    account = _account(
        "remote-user",
        name="远程用户",
        role="企业经办",
        password="remote-password",
        permissions={"read"},
    )
    with pytest.raises(ValueError, match="Secure Cookie"):
        EnterpriseAgentHTTPServer(
            ("0.0.0.0", 0),
            service,  # type: ignore[arg-type]
            auth_manager=AuthManager((account,)),
            secure_cookie=False,
        )


def test_loopback_https_proxy_accepts_only_configured_public_host_and_origin() -> None:
    account = _account(
        "proxy-user",
        name="代理用户",
        role="企业经办",
        password="proxy-password",
        permissions={"read", "write"},
    )
    service = SpyService()
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,  # type: ignore[arg-type]
        auth_manager=AuthManager((account,)),
        secure_cookie=True,
        public_origin="https://report.enterprise.example",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=3,
    )
    try:
        status, payload, headers = _request(
            connection,
            "POST",
            "/api/v1/auth/login",
            {"actor_id": "proxy-user", "password": "proxy-password"},
            origin="https://report.enterprise.example",
            extra_headers={"Host": "report.enterprise.example"},
        )
        assert status == 200
        assert "Secure" in headers["set-cookie"]
        cookie = headers["set-cookie"].split(";", 1)[0]
        csrf = payload["csrf_token"]

        status, _, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {},
            cookie=cookie,
            csrf=csrf,
            origin="https://report.enterprise.example",
            extra_headers={"Host": "report.enterprise.example"},
        )
        assert status == 201
        status, error, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {},
            cookie=cookie,
            csrf=csrf,
            origin="https://evil.example",
            extra_headers={"Host": "report.enterprise.example"},
        )
        assert status == 403
        assert error["error"]["code"] == "cross_origin_request_denied"
        status, error, _ = _request(
            connection,
            "GET",
            "/api/v1/drafts",
            cookie=cookie,
            extra_headers={"Host": "other.example"},
        )
        assert status == 403
        assert error["error"]["code"] == "host_not_allowed"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_temporary_demo_can_edit_but_cannot_confirm_or_submit() -> None:
    manager = build_auth_manager(
        accounts=(),
        bind_host="127.0.0.1",
        allow_anonymous_local=False,
        session_ttl_seconds=300,
    )
    service = SpyService()
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,  # type: ignore[arg-type]
        auth_manager=manager,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        server.server_address[1],
        timeout=3,
    )
    try:
        cookie, csrf, principal, _ = _login(
            connection,
            "demo",
            "123123123",
        )
        assert principal["temporary_demo"] is True
        assert principal["must_change_password"] is True

        status, _, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {},
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 201
        for action in ("confirm", "submit"):
            status, error, _ = _request(
                connection,
                "POST",
                f"/api/v1/drafts/draft-1/{action}",
                {},
                cookie=cookie,
                csrf=csrf,
            )
            assert status == 403
            assert error["error"]["code"] == "credential_rotation_required"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_served_ui_and_same_origin_auth_api_work_together() -> None:
    account = _account(
        "ui-user",
        name="页面经办人",
        role="企业报送负责人",
        password="ui-user-password",
        permissions={"read", "write", "confirm", "submit"},
    )
    web_root = Path(__file__).resolve().parents[1] / "web"
    with _running((account,), web_root=web_root) as (_, connection):
        connection.request("GET", "/")
        response = connection.getresponse()
        html = response.read().decode("utf-8")
        assert response.status == 200
        assert 'id="loginDialog"' in html
        assert 'id="confirmationActorName"' in html

        cookie, csrf, principal, _ = _login(
            connection,
            "ui-user",
            "ui-user-password",
        )
        assert principal["name"] == "页面经办人"
        status, _, _ = _request(
            connection,
            "POST",
            "/api/v1/drafts",
            {},
            cookie=cookie,
            csrf=csrf,
        )
        assert status == 201
