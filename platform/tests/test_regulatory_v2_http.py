from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import hmac
from http.client import HTTPConnection
import json
from pathlib import Path
import socket
import sqlite3
from threading import Event, Thread
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker
import pytest
from referencing import Registry, Resource

from mineguard.auth import AuthError, LocalAuthStore, Principal, Role
from mineguard.exchange_v2 import (
    ExchangeClient,
    FiveQuantitySubmissionMessage,
    exchange_signature_material,
    sign_exchange_message,
    sign_transport_headers,
)
from mineguard.external_submission import jcs_canonical_json
from mineguard.regulatory_v2_http import (
    RegulatoryV2HTTPServer,
    RegulatoryV2RequestHandler,
    _TEN_QUANTITY_RELATIONSHIP_MODULES,
    _affected_metrics_from_signals,
    _humanize_business_text,
    _humanize_finding_summary,
    create_server,
)
from mineguard.regulatory_v2_store import AuditProjection, RegulatoryV2Store


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
EXAMPLE_SECRET = b"example-v2-exchange-secret-not-for-production"
V3_EXAMPLE_SECRET = b"example-v3-exchange-secret-not-for-production"
FIXED_NOW = datetime(2026, 8, 1, 0, 20, tzinfo=UTC)
LOCAL_CONTROL_TOKEN = "a" * 64
PRODUCTION_MESSAGE_SECRET = b"mG8xQ2pL9vR4sT7wY3kN6cD1fH5jB0zA"
PRODUCTION_TRANSPORT_SECRET = b"uC7nP2aX9dK4qW6rE1vM8sJ3hF5bT0yZ"
PRODUCTION_MESSAGE_KEY_ID = "mineqy001-msg-2026q3-a7f4"
PRODUCTION_COMPARISON_CONTEXT = {
    "capacity_band": "large",
    "mining_method": "underground-longwall",
    "shift_system": "three-shift-eight-hour",
    "coal_type": "bituminous",
    "operating_regime": "normal-production",
}


def _minimal_exchange_client(**overrides: Any) -> ExchangeClient:
    values: dict[str, Any] = {
        "sender_id": "agent-mine-qy-001",
        "party_id": "operator-qy-001",
        "mine_id": "MINE-QY-001",
        "mine_name": "沁源一号煤矿",
        "secret": PRODUCTION_MESSAGE_SECRET,
        "transport_secret": PRODUCTION_TRANSPORT_SECRET,
        "message_key_id": PRODUCTION_MESSAGE_KEY_ID,
        "comparison_context": PRODUCTION_COMPARISON_CONTEXT,
    }
    values.update(overrides)
    return ExchangeClient(**values)


def _seed_ready_production_admin(path: Path) -> None:
    with LocalAuthStore(path) as auth:
        auth.bootstrap_admin("ready-admin", "Ready-Admin-Password-2026!")


def test_production_server_boundary_rejects_insecure_or_incomplete_setup(
    tmp_path: Path,
) -> None:
    auth_database = tmp_path / "production-auth.db"
    _seed_ready_production_admin(auth_database)
    client = _minimal_exchange_client()
    common = {
        "database_path": tmp_path / "production.db",
        "auth_database_path": auth_database,
        "clients": {client.sender_id: client},
        "auth_required": True,
        "secure_cookie": True,
        "production_mode": True,
    }
    for override, message in (
        ({"auth_required": False}, "requires government authentication"),
        ({"secure_cookie": False}, "requires Secure session cookies"),
        ({"clients": {}}, "requires at least one exchange client"),
    ):
        with pytest.raises(ValueError, match=message):
            create_server("127.0.0.1", 0, **(common | override))

    placeholder_client = _minimal_exchange_client(sender_id="demo-agent")
    with pytest.raises(ValueError, match="placeholder sender_id"):
        create_server(
            "127.0.0.1",
            0,
            **(
                common | {"clients": {placeholder_client.sender_id: placeholder_client}}
            ),
        )
    with pytest.raises(ValueError, match="platform_system_id.*placeholder"):
        create_server(
            "127.0.0.1",
            0,
            **(common | {"platform_system_id": "demo-platform"}),
        )
    with pytest.raises(ValueError, match="must not reuse"):
        create_server(
            "127.0.0.1",
            0,
            **(common | {"platform_key_id": PRODUCTION_MESSAGE_KEY_ID}),
        )
    with pytest.raises(ValueError, match="cannot enable legacy V2 intake"):
        create_server(
            "127.0.0.1",
            0,
            **(common | {"allow_legacy_v2_intake": True}),
        )

    empty_auth = tmp_path / "empty-auth.db"
    with pytest.raises(AuthError, match="current password policy"):
        create_server(
            "127.0.0.1",
            0,
            **(common | {"auth_database_path": empty_auth}),
        )

    # The concrete server constructor is also a trust boundary; callers may
    # not bypass create_server and instantiate an insecure production server.
    store = RegulatoryV2Store(tmp_path / "direct-production.db")
    auth = LocalAuthStore(auth_database)
    try:
        with pytest.raises(ValueError, match="requires government authentication"):
            RegulatoryV2HTTPServer(
                ("127.0.0.1", 0),
                store=store,
                auth_store=auth,
                clients={client.sender_id: client},
                auth_required=False,
                secure_cookie=True,
                platform_system_id="mineguard-test",
                platform_party_id="regulator-test",
                platform_key_id="regulator-test-key",
                local_control_token=None,
                clock=lambda: FIXED_NOW,
                production_mode=True,
            )
    finally:
        store.close()
        auth.close()


def test_production_pending_user_can_only_change_password_then_relogin(
    tmp_path: Path,
) -> None:
    auth_database = tmp_path / "pending-auth.db"
    _seed_ready_production_admin(auth_database)
    with LocalAuthStore(auth_database) as auth:
        auth.create_user(
            "pending-admin",
            "Initial-Admin-2026!",
            Role.ADMIN,
            must_change_password=True,
        )
    client = _minimal_exchange_client()
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "pending.db",
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        login_body = json.dumps(
            {"username": "pending-admin", "password": "Initial-Admin-2026!"}
        )
        connection.request(
            "POST",
            "/v2/auth/login",
            body=login_body,
            headers={"Content-Type": "application/json"},
        )
        login = connection.getresponse()
        login_payload = json.loads(login.read())
        assert login.status == 200
        assert login_payload["principal"]["must_change_password"] is True
        assert login_payload["principal"]["password_change_required"] is True
        cookie = login.getheader("Set-Cookie").split(";", 1)[0]
        csrf = login_payload["csrf_token"]

        connection.request("GET", "/v2/regulatory/overview", headers={"Cookie": cookie})
        blocked = connection.getresponse()
        blocked_payload = json.loads(blocked.read())
        assert blocked.status == 403
        assert blocked_payload["code"] == "PASSWORD_CHANGE_REQUIRED"

        connection.request(
            "POST",
            "/v2/auth/change-password",
            body=json.dumps(
                {
                    "current_password": "Wrong-Current-Password-2026!",
                    "new_password": "Final-Admin-2026!",
                }
            ),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": csrf,
            },
        )
        wrong_current = connection.getresponse()
        wrong_payload = json.loads(wrong_current.read())
        assert wrong_current.status == 422
        assert wrong_payload["code"] == "CURRENT_PASSWORD_INVALID"
        assert "当前密码不正确" in wrong_payload["detail"]

        connection.request("GET", "/v2/auth/me", headers={"Cookie": cookie})
        still_authenticated = connection.getresponse()
        still_payload = json.loads(still_authenticated.read())
        assert still_authenticated.status == 200
        assert still_payload["principal"]["password_change_required"] is True

        connection.request(
            "POST",
            "/v2/auth/change-password",
            body=json.dumps(
                {
                    "current_password": "Initial-Admin-2026!",
                    "new_password": "Final-Admin-2026!",
                }
            ),
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "X-CSRF-Token": csrf,
            },
        )
        changed = connection.getresponse()
        assert changed.status == 200
        assert json.loads(changed.read())["login_required"] is True

        connection.request(
            "POST",
            "/v2/auth/login",
            body=json.dumps(
                {"username": "pending-admin", "password": "Final-Admin-2026!"}
            ),
            headers={"Content-Type": "application/json"},
        )
        relogin = connection.getresponse()
        relogin_payload = json.loads(relogin.read())
        assert relogin.status == 200
        assert relogin_payload["principal"]["must_change_password"] is False
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_local_control_shutdown_is_loopback_token_bound_and_graceful(
    tmp_path: Path,
) -> None:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "regulatory.db",
        auth_database_path=tmp_path / "auth.db",
        auth_required=False,
        clients={},
        local_control_token=LOCAL_CONTROL_TOKEN,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    path = "/_mineguard/local-control/shutdown"
    try:
        connection.request("GET", path)
        get_response = connection.getresponse()
        get_response.read()
        assert get_response.status == 404

        connection.request(
            "POST",
            path,
            body=b"",
            headers={"X-MineGuard-Local-Control-Token": "b" * 64},
        )
        wrong_response = connection.getresponse()
        wrong_response.read()
        assert wrong_response.status == 404

        connection.request(
            "POST",
            path,
            body=b"",
            headers={"X-MineGuard-Local-Control-Token": LOCAL_CONTROL_TOKEN},
        )
        accepted = connection.getresponse()
        payload = json.loads(accepted.read())
        assert accepted.status == 202
        assert payload == {"service": "mineguard-v2", "status": "shutting_down"}

        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        connection.close()
        if thread.is_alive():
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()


def test_local_control_shutdown_refuses_non_loopback_listener(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="requires a loopback listener"):
        create_server(
            "0.0.0.0",
            0,
            database_path=tmp_path / "regulatory.db",
            auth_database_path=tmp_path / "auth.db",
            auth_required=False,
            clients={},
            local_control_token=LOCAL_CONTROL_TOKEN,
        )


def test_production_v2_submission_is_authenticated_but_read_only(
    tmp_path: Path,
) -> None:
    document = json.loads(
        (CONTRACTS / "examples" / "five-quantity-submission-v2.json").read_text(
            encoding="utf-8"
        )
    )
    document["payload"]["mine"]["mine_name"] = "沁源一号煤矿"
    document["payload"]["comparison_context"] = PRODUCTION_COMPARISON_CONTEXT
    document["signature_envelope"]["key_id"] = PRODUCTION_MESSAGE_KEY_ID
    sign_exchange_message(document, PRODUCTION_MESSAGE_SECRET)
    body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    client = _minimal_exchange_client()
    auth_database = tmp_path / "v2-read-only-auth.db"
    _seed_ready_production_admin(auth_database)
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "v2-read-only.db",
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
        clock=lambda: FIXED_NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    target = "/v2/five-quantity-submissions"
    headers = sign_transport_headers(
        client,
        method="POST",
        request_target=target,
        body=body,
        contract_version="five-quantity-submission-v2",
        timestamp=FIXED_NOW,
        nonce="bGVnYWN5LXYyLXJlYWQtb25seQ",
    )
    headers["Content-Type"] = "application/json"
    try:
        connection.request("POST", target, body=body, headers=headers)
        response = connection.getresponse()
        problem = json.loads(response.read())

        assert response.status == 410
        assert problem["code"] == "LEGACY_CONTRACT_READ_ONLY"
        assert server.store.list_submissions() == []
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_production_hmac_failure_is_persistently_audited_without_secrets(
    tmp_path: Path,
) -> None:
    submission_body = (
        CONTRACTS / "examples" / "five-quantity-submission-v2.json"
    ).read_bytes()
    client = _minimal_exchange_client()
    auth_database = tmp_path / "security-auth.db"
    _seed_ready_production_admin(auth_database)
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "security-audit.db",
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
        clock=lambda: FIXED_NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    target = "/v2/five-quantity-submissions"
    headers = sign_transport_headers(
        client,
        method="POST",
        request_target=target,
        body=submission_body,
        contract_version="five-quantity-submission-v2",
        timestamp=FIXED_NOW,
        nonce="c2VjdXJpdHktYXVkaXQtbm9uY2U",
    )
    deliberately_invalid_hmac = "d" * 64
    headers["X-Exchange-Signature"] = deliberately_invalid_hmac
    headers["Content-Type"] = "application/json"
    try:
        connection.request("POST", target, body=submission_body, headers=headers)
        response = connection.getresponse()
        problem = json.loads(response.read())
        assert response.status == 401
        assert problem["code"] == "EXCHANGE_AUTHENTICATION_FAILED"

        event = next(
            item
            for item in server.store.list_audit_events(limit=20)
            if item.event_type == "machine_authentication_failed"
        )
        assert event.mine_id == client.mine_id
        assert event.payload == {
            "audit_schema": "machine-security-event-v1",
            "outcome": "rejected",
            "reason_code": "exchange_authentication_failed",
            "request_method": "POST",
            "request_path": target,
            "remote_address": "127.0.0.1",
            "known_sender_id": client.sender_id,
        }
        serialized = json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
        assert deliberately_invalid_hmac not in serialized
        assert PRODUCTION_MESSAGE_SECRET.decode() not in serialized
        assert PRODUCTION_TRANSPORT_SECRET.decode() not in serialized
        assert "X-Exchange-Nonce" not in serialized
        assert server.store.verify_audit_chain() is True
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_repeated_invalid_hmac_is_rate_bounded_with_first_and_summary_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "bounded-security-audit.db"
    submission_body = (
        CONTRACTS / "examples" / "five-quantity-submission-v2.json"
    ).read_bytes()
    client = _minimal_exchange_client()
    auth_database = tmp_path / "bounded-security-auth.db"
    _seed_ready_production_admin(auth_database)
    server = create_server(
        "127.0.0.1",
        0,
        database_path=database,
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
        clock=lambda: FIXED_NOW,
    )
    full_scan_count = 0
    original = server.store._run_full_integrity_check_locked  # noqa: SLF001

    def counted_full_scan() -> bool:
        nonlocal full_scan_count
        full_scan_count += 1
        return original()

    monkeypatch.setattr(
        server.store,
        "_run_full_integrity_check_locked",
        counted_full_scan,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    target = "/v2/five-quantity-submissions"
    headers = sign_transport_headers(
        client,
        method="POST",
        request_target=target,
        body=submission_body,
        contract_version="five-quantity-submission-v2",
        timestamp=FIXED_NOW,
        nonce="Ym91bmRlZC1mYWlsdXJlLW5vbmNl",
    )
    headers["X-Exchange-Signature"] = "c" * 64
    headers["Content-Type"] = "application/json"
    try:
        for _ in range(50):
            connection.request("POST", target, body=submission_body, headers=headers)
            response = connection.getresponse()
            response.read()
            assert response.status == 401

        security_events = [
            event
            for event in server.store.list_audit_events(limit=200)
            if event.event_type
            in {
                "machine_authentication_failed",
                "machine_authentication_failure_summary",
            }
        ]
        assert len(security_events) == 4
        first = next(
            event
            for event in security_events
            if event.event_type == "machine_authentication_failed"
        )
        assert first.payload["known_sender_id"] == client.sender_id
        summaries = [
            event
            for event in security_events
            if event.event_type == "machine_authentication_failure_summary"
        ]
        assert sorted(event.payload["attempt_count"] for event in summaries) == [
            10,
            20,
            40,
        ]
        assert all(event.payload["final"] is False for event in summaries)
        serialized = json.dumps(
            [event.model_dump(mode="json") for event in security_events]
        )
        assert EXAMPLE_SECRET.decode() not in serialized
        assert headers["X-Exchange-Signature"] not in serialized
        assert headers["X-Exchange-Nonce"] not in serialized
        # Fifty unauthenticated requests take only marker/trigger fast paths;
        # none may rescan the historical immutable tables.
        assert full_scan_count == 0
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    # Graceful shutdown adds one exact final summary, still a constant number
    # of immutable events for all fifty rejected requests.
    with RegulatoryV2Store(database, now=lambda: FIXED_NOW) as reopened:
        security_events = [
            event
            for event in reopened.list_audit_events(limit=200)
            if event.event_type
            in {
                "machine_authentication_failed",
                "machine_authentication_failure_summary",
            }
        ]
        assert len(security_events) == 5
        final_summary = next(
            event
            for event in security_events
            if event.event_type == "machine_authentication_failure_summary"
            and event.payload["final"] is True
        )
        assert final_summary.payload["attempt_count"] == 50
        assert final_summary.payload["suppressed_count"] == 49
        assert reopened.verify_integrity() is True


def test_valid_transport_with_invalid_application_signature_does_not_claim_nonce(
    tmp_path: Path,
) -> None:
    submission_body = (
        CONTRACTS / "examples" / "five-quantity-submission-v2.json"
    ).read_bytes()
    submission = json.loads(submission_body)
    submission["signature_envelope"]["key_id"] = PRODUCTION_MESSAGE_KEY_ID
    submission["payload"]["mine"]["mine_name"] = "沁源一号煤矿"
    submission_body = json.dumps(
        submission, ensure_ascii=False, separators=(",", ":")
    ).encode()
    client = _minimal_exchange_client()
    auth_database = tmp_path / "split-key-auth.db"
    _seed_ready_production_admin(auth_database)
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "split-key.db",
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
        clock=lambda: FIXED_NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    target = "/v2/five-quantity-submissions"
    headers = sign_transport_headers(
        client,
        method="POST",
        request_target=target,
        body=submission_body,
        contract_version="five-quantity-submission-v2",
        timestamp=FIXED_NOW,
        nonce="dHJhbnNwb3J0LW9ubHktbm9uY2U",
    )
    headers["Content-Type"] = "application/json"
    try:
        connection.request("POST", target, body=submission_body, headers=headers)
        response = connection.getresponse()
        response.read()
        assert response.status == 401
        assert (
            server.store._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM v2_transport_nonces"
            ).fetchone()[0]
            == 0
        )
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_production_ready_and_machine_intake_fail_closed_after_runtime_tamper(
    tmp_path: Path,
) -> None:
    submission_body = (
        CONTRACTS / "examples" / "five-quantity-submission-v2.json"
    ).read_bytes()
    client = _minimal_exchange_client()
    auth_database = tmp_path / "runtime-integrity-auth.db"
    _seed_ready_production_admin(auth_database)
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "runtime-integrity.db",
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
        clock=lambda: FIXED_NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request("GET", "/readyz")
        healthy = connection.getresponse()
        healthy_payload = json.loads(healthy.read())
        assert healthy.status == 200
        assert healthy_payload["integrity"] == "valid"
        assert healthy_payload["schema_version"] == 1

        login_body = json.dumps(
            {"username": "ready-admin", "password": "Ready-Admin-Password-2026!"}
        )
        connection.request(
            "POST",
            "/v2/auth/login",
            body=login_body,
            headers={"Content-Type": "application/json"},
        )
        login = connection.getresponse()
        login.read()
        assert login.status == 200
        cookie = login.getheader("Set-Cookie").split(";", 1)[0]

        server.store._connection.execute(  # noqa: SLF001 - simulated tampering
            "DROP TRIGGER v2_audit_events_no_update"
        )
        server.store._connection.execute(  # noqa: SLF001 - simulated tampering
            "UPDATE v2_audit_events SET event_hash = ? WHERE sequence = 1",
            ("f" * 64,),
        )

        connection.request("GET", "/v2/regulatory/overview", headers={"Cookie": cookie})
        refused_overview = connection.getresponse()
        overview_problem = json.loads(refused_overview.read())
        assert refused_overview.status == 503
        assert overview_problem["code"] == "AUDIT_INTEGRITY_FAILED"

        connection.request("GET", "/readyz")
        not_ready = connection.getresponse()
        readiness_problem = json.loads(not_ready.read())
        assert not_ready.status == 503
        assert readiness_problem["code"] == "AUDIT_INTEGRITY_FAILED"

        before_nonce_count = server.store._connection.execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM v2_transport_nonces"
        ).fetchone()[0]
        target = "/v2/five-quantity-submissions"
        headers = sign_transport_headers(
            client,
            method="POST",
            request_target=target,
            body=submission_body,
            contract_version="five-quantity-submission-v2",
            timestamp=FIXED_NOW,
            nonce="cnVudGltZS10YW1wZXItbm9uY2U",
        )
        headers["Content-Type"] = "application/json"
        connection.request("POST", target, body=submission_body, headers=headers)
        refused = connection.getresponse()
        refused_problem = json.loads(refused.read())
        assert refused.status == 503
        assert refused_problem["code"] == "AUDIT_INTEGRITY_FAILED"
        assert (
            server.store._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM v2_transport_nonces"
            ).fetchone()[0]
            == before_nonce_count
        )
        assert server.store.list_submissions() == []
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_production_regulatory_reads_and_export_use_checkpoint_fast_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_database = tmp_path / "checkpoint-read-auth.db"
    _seed_ready_production_admin(auth_database)
    client = _minimal_exchange_client()
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "checkpoint-read.db",
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
        clock=lambda: FIXED_NOW,
    )
    full_scan_count = 0
    original = server.store._run_full_integrity_check_locked  # noqa: SLF001

    def counted_full_scan() -> bool:
        nonlocal full_scan_count
        full_scan_count += 1
        return original()

    monkeypatch.setattr(
        server.store,
        "_run_full_integrity_check_locked",
        counted_full_scan,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        login_body = json.dumps(
            {"username": "ready-admin", "password": "Ready-Admin-Password-2026!"}
        )
        connection.request(
            "POST",
            "/v2/auth/login",
            body=login_body,
            headers={"Content-Type": "application/json"},
        )
        login = connection.getresponse()
        login.read()
        assert login.status == 200
        cookie = login.getheader("Set-Cookie").split(";", 1)[0]
        for path in (
            "/v2/regulatory/overview",
            "/v2/regulatory/mines",
            "/v2/regulatory/findings",
            "/v2/regulatory/exchanges",
            "/v2/regulatory/exchanges/export.csv?view=technical&"
            "from=2026-07-01T00:00:00Z&to=2026-08-02T00:00:00Z",
        ):
            connection.request("GET", path, headers={"Cookie": cookie})
            response = connection.getresponse()
            response.read()
            assert response.status == 200, path
        assert full_scan_count == 0
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_machine_get_rechecks_checkpoint_inside_controlled_operation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "machine-read-race.db"
    auth_database = tmp_path / "machine-read-race-auth.db"
    _seed_ready_production_admin(auth_database)
    client = _minimal_exchange_client()
    server = create_server(
        "127.0.0.1",
        0,
        database_path=database,
        auth_database_path=auth_database,
        auth_required=True,
        secure_cookie=True,
        clients={client.sender_id: client},
        production_mode=True,
        clock=lambda: FIXED_NOW,
    )
    original_gate = server.require_machine_write_integrity
    injected = False

    def commit_after_transport_gate() -> None:
        nonlocal injected
        original_gate()
        if not injected:
            injected = True
            with sqlite3.connect(database) as external:
                external.execute(
                    """
                    INSERT INTO v2_agent_mine_bindings(agent_id, mine_id, created_at)
                    VALUES ('racing-agent', 'racing-mine', ?)
                    """,
                    (FIXED_NOW.isoformat(),),
                )

    monkeypatch.setattr(
        server, "require_machine_write_integrity", commit_after_transport_gate
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    target = "/v2/analysis-reports/next"
    headers = sign_transport_headers(
        client,
        method="GET",
        request_target=target,
        body=b"",
        contract_version="five-quantity-exchange-v2",
        timestamp=FIXED_NOW,
        nonce="bWFjaGluZS1yZWFkLXJhY2Utbm9uY2U",
    )
    try:
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        problem = json.loads(response.read())
        assert response.status == 503
        assert problem["code"] == "AUDIT_INTEGRITY_FAILED"
        assert (
            server.store._connection.execute(  # noqa: SLF001
                "SELECT COUNT(*) FROM v2_transport_nonces"
            ).fetchone()[0]
            == 0
        )
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_server_close_drains_admitted_requests_before_closing_sqlite(
    tmp_path: Path,
) -> None:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "drain.db",
        auth_database_path=tmp_path / "drain-auth.db",
        auth_required=False,
        clients={},
    )
    closed = Event()
    assert server.begin_request() is True

    def close_server() -> None:
        server.server_close()
        closed.set()

    thread = Thread(target=close_server, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.draining:
                break
            closed.wait(0.01)
        assert server.draining is True
        assert server.begin_request() is False
        assert closed.wait(0.05) is False
    finally:
        server.end_request()
    assert closed.wait(2) is True
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_partial_request_body_cannot_block_bounded_shutdown(tmp_path: Path) -> None:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "slow-body.db",
        auth_database_path=tmp_path / "slow-body-auth.db",
        auth_required=False,
        clients={},
        request_io_timeout_seconds=30,
        drain_timeout_seconds=0.1,
    )
    serving = Thread(target=server.serve_forever, daemon=True)
    serving.start()
    client = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
    client.sendall(
        b"POST /v2/auth/login HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 100\r\n\r\n{"
    )
    for _ in range(100):
        if server.active_requests == 1:
            break
        Event().wait(0.01)
    assert server.active_requests == 1
    server.shutdown()
    serving.join(timeout=2)
    closed = Event()

    def close_server() -> None:
        server.server_close()
        closed.set()

    closer = Thread(target=close_server, daemon=True)
    closer.start()
    try:
        assert closed.wait(3)
        assert server.active_requests == 0
        assert server._resources_closed is True  # noqa: SLF001
    finally:
        client.close()
        closer.join(timeout=3)


@pytest.mark.parametrize("token", ["short", "A" * 64, "g" * 64])
def test_local_control_token_format_is_fail_closed(
    tmp_path: Path,
    token: str,
) -> None:
    with pytest.raises(ValueError, match="local control token"):
        create_server(
            "127.0.0.1",
            0,
            database_path=tmp_path / f"bad-{token[:4]}.db",
            auth_database_path=tmp_path / f"bad-{token[:4]}-auth.db",
            clients={},
            local_control_token=token,
        )


def test_government_business_text_hides_internal_tokens_but_preserves_ids() -> None:
    rendered = _humanize_business_text(
        "2026-07-01 electricity_per_production偏离anonymous_peer稳健基线；"
        "CUSUM、EWMA、Page-Hinkley、median/MAD均未触发；"
        "unmapped_ratio_signal待核；编号 FINDING_QY_20260705_001"
    )

    for raw in (
        "electricity_per_production",
        "anonymous_peer",
        "unmapped_ratio_signal",
        "CUSUM",
        "EWMA",
        "Page-Hinkley",
        "median/MAD",
    ):
        assert raw not in rendered
    for label in (
        "单位产量电耗",
        "匿名同类矿",
        "其他业务项",
        "持续累积偏移",
        "近期均值越界",
        "均值变化检测",
        "历史稳健范围",
        "FINDING_QY_20260705_001",
    ):
        assert label in rendered


def test_government_finding_summary_groups_repeated_daily_machine_prose() -> None:
    rendered = _humanize_finding_summary(
        "2026-07-01 electricity_per_production偏离anonymous_peer稳健基线；"
        "2026-07-02 electricity_per_production偏离anonymous_peer稳健基线；"
        "2026-07-03 electricity_per_production偏离anonymous_peer稳健基线"
    )

    assert rendered == (
        "多日出现：单位产量电耗偏离匿名同类矿稳健基线。逐日证据见下方。"
    )

    relationship = _humanize_finding_summary(
        "2026-07-01 electricity_per_production 超出anonymous_peer软参考区间；"
        "2026-07-01 的日报、班次或软参考带无法同时成立；"
        "2026-07-02 electricity_per_production 超出anonymous_peer软参考区间；"
        "2026-07-02 的日报、班次或软参考带无法同时成立"
    )
    assert relationship == (
        "多日出现：单位产量电耗超出匿名同类矿软参考区间；"
        "多日出现：日报、班次或软参考带无法同时成立。逐日证据见下方。"
    )


def test_government_business_text_translates_complete_algorithm_phrases_naturally() -> (
    None
):
    rendered = _humanize_business_text(
        "正向 CUSUM 累积偏移超过持续漂移阈值；"
        "EWMA 水平超过控制限；"
        "Page-Hinkley 检测到均值变点；"
        "滚动 median/MAD 基线发生偏离"
    )

    assert rendered == (
        "正向持续累积偏移值超过持续漂移阈值；"
        "近期加权均值超过控制限；"
        "均值变化检测发现均值变点；"
        "滚动历史稳健基线发生偏离"
    )


def test_finding_projection_only_exposes_evidence_for_its_own_category() -> None:
    def signal(message: str, metric: str | None = None) -> SimpleNamespace:
        return SimpleNamespace(message=message, metric=metric)

    item = SimpleNamespace(
        finding=SimpleNamespace(
            finding_id="finding-001",
            submission_id="submission-001",
            mine_id="MINE-QY-001",
            finding_type="risk",
            category="relationship_consistency",
            title="五量关系待核",
            summary="electricity_per_production偏离anonymous_peer稳健基线",
            issued_at=FIXED_NOW,
            result=SimpleNamespace(
                data_quality_signals=[signal("wire_quality_flags存在格式提示")],
                relationship_signals=[
                    signal(
                        "electricity_per_production超出anonymous_peer参考区间",
                        "electricity_per_production",
                    )
                ],
                temporal_signals=[signal("CUSUM发现持续偏移")],
            ),
        ),
        state="open",
        responses=[],
        resolved_by_submission_id=None,
    )

    projected = RegulatoryV2RequestHandler._finding_projection(item)

    assert projected["summary"] == "单位产量电耗偏离匿名同类矿稳健基线"
    assert projected["evidence"] == ["单位产量电耗超出匿名同类矿参考区间"]
    assert projected["affected_metrics"] == ["electricity_kwh", "production_t"]
    serialized = json.dumps(projected, ensure_ascii=False)
    assert "wire_quality_flags" not in serialized
    assert "CUSUM" not in serialized


def test_signal_metric_resolution_keeps_relationships_and_fire_materials_narrow() -> (
    None
):
    relationship = _affected_metrics_from_signals(
        [SimpleNamespace(metric="electricity_per_production")],
        (
            "ventilation_m3_min",
            "electricity_kwh",
            "detonators_count",
            "explosives_kg",
            "mine_entry_persons",
            "production_t",
            "extraction_t",
            "sales_t",
            "transport_t",
            "wash_feed_t",
            "invoiced_quantity_t",
        ),
    )
    fire_materials = _affected_metrics_from_signals(
        [SimpleNamespace(metric="detonators_count,explosives_kg")],
        (
            "ventilation_m3_min",
            "electricity_kwh",
            "detonators_count",
            "explosives_kg",
            "mine_entry_persons",
            "production_t",
            "extraction_t",
            "sales_t",
            "transport_t",
            "wash_feed_t",
            "invoiced_quantity_t",
        ),
    )

    assert relationship == ["electricity_kwh", "production_t"]
    assert fire_materials == ["detonators_count", "explosives_kg"]


def test_v3_report_discloses_every_evaluated_business_chain_relationship() -> None:
    assert set(_TEN_QUANTITY_RELATIONSHIP_MODULES.values()) == {
        "production_extraction_reconciliation",
        "production_sales_reconciliation",
        "production_transport_reconciliation",
        "production_wash_reconciliation",
        "sales_transport_reconciliation",
        "sales_invoice_reconciliation",
    }
    assert all(
        "inventory" not in module
        for module in _TEN_QUANTITY_RELATIONSHIP_MODULES.values()
    )


def _schema_registry() -> Registry:
    resources = []
    for path in (CONTRACTS / "schemas").glob("*.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def _assert_contract(document: dict[str, Any], schema_name: str) -> None:
    schema = json.loads(
        (CONTRACTS / "schemas" / schema_name).read_text(encoding="utf-8")
    )
    errors = list(
        Draft202012Validator(
            schema,
            registry=_schema_registry(),
            format_checker=FormatChecker(),
        ).iter_errors(document)
    )
    assert not errors, [error.message for error in errors]


def _assert_problem(document: dict[str, Any]) -> None:
    openapi = json.loads(
        (
            CONTRACTS / "openapi" / "five-quantity-exchange-v2.openapi.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator(openapi["components"]["schemas"]["Problem"]).validate(document)


def _assert_application_signature(
    document: dict[str, Any],
    *,
    secret: bytes = EXAMPLE_SECRET,
) -> None:
    digest = hashlib.sha256(
        jcs_canonical_json(document["payload"]).encode("utf-8")
    ).hexdigest()
    assert digest == document["signature_envelope"]["payload_sha256"]
    expected = hmac.new(
        secret,
        exchange_signature_material(document, digest),
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(expected, document["signature_envelope"]["signature"])


def _signed_enterprise_message(document: dict[str, Any]) -> bytes:
    document["signature_envelope"]["payload_sha256"] = "0" * 64
    document["signature_envelope"]["signature"] = "0" * 64
    sign_exchange_message(document, EXAMPLE_SECRET)
    return json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("past_only_rolling_mad", "past_only_rolling_mad"),
        ("past_only_ewma", "past_only_ewma"),
        ("past_only_cusum", "past_only_cusum"),
        ("past_only_page_hinkley", "past_only_page_hinkley"),
    ],
)
def test_v2_report_preserves_specific_temporal_evidence_method(
    code: str, expected: str
) -> None:
    assert (
        RegulatoryV2RequestHandler._evidence_method(
            code, f"past_only_temporal_detector:{code}"
        )
        == expected
    )


def test_ten_quantity_v3_submission_and_report_are_end_to_end_and_route_isolated(
    tmp_path: Path,
) -> None:
    import base64

    submission_body = (
        CONTRACTS / "examples" / "ten-quantity-submission-v3.json"
    ).read_bytes()
    submission = json.loads(submission_body)
    client = ExchangeClient(
        sender_id=submission["sender"]["system_id"],
        party_id=submission["sender"]["party_id"],
        mine_id=submission["mine_id"],
        secret=V3_EXAMPLE_SECRET,
        transport_secret=b"example-v3-transport-secret-not-for-production",
        mine_name=submission["payload"]["mine"]["mine_name"],
        comparison_context=submission["payload"]["comparison_context"],
        message_key_id=submission["signature_envelope"]["key_id"],
    )
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "regulatory-v3.db",
        auth_database_path=tmp_path / "auth-v3.db",
        auth_required=False,
        clients={client.sender_id: client},
        clock=lambda: FIXED_NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    nonce_counter = 100

    def request(
        method: str,
        target: str,
        *,
        body: bytes = b"",
        contract_version: str,
    ) -> tuple[int, dict[str, Any] | None]:
        nonlocal nonce_counter
        nonce_counter += 1
        nonce = base64.urlsafe_b64encode(nonce_counter.to_bytes(16, "big"))
        headers = sign_transport_headers(
            client,
            method=method,
            request_target=target,
            body=body,
            contract_version=contract_version,
            timestamp=FIXED_NOW,
            nonce=nonce.decode().rstrip("="),
        )
        if body:
            headers["Content-Type"] = "application/json"
        connection.request(method, target, body=body or None, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw) if raw else None

    try:
        status, intake = request(
            "POST",
            "/v3/ten-quantity-submissions",
            body=submission_body,
            contract_version="ten-quantity-submission-v3",
        )
        assert status == 202
        assert intake is not None
        _assert_contract(intake, "intake-receipt-v2.schema.json")
        _assert_application_signature(intake, secret=V3_EXAMPLE_SECRET)

        stored = server.store.get_submission(submission["message_id"])
        assert stored.quantity_scope == "ten_quantity_v3"
        day = stored.days[0]
        assert day.extraction_t is not None
        assert day.sales_t is not None
        assert day.transport_t is not None
        assert day.wash_feed_t is not None
        assert day.invoiced_quantity_t is not None
        assert day.sales_t.daily_total == 2510.0
        assert day.invoiced_quantity_t.daily_total == 2440.0
        assert day.quality["sales_t"].zero_shift == ("reported",)
        assert day.quality["sales_t"].eight_shift == ()
        assert day.quality["sales_t"].four_shift == ("not_applicable",)

        legacy_status, legacy_payload = request(
            "GET",
            "/v2/analysis-reports/next",
            contract_version="five-quantity-exchange-v2",
        )
        assert legacy_status == 204
        assert legacy_payload is None

        status, report = request(
            "GET",
            "/v3/analysis-reports/next",
            contract_version="ten-quantity-exchange-v3",
        )
        assert status == 200
        assert report is not None
        _assert_contract(report, "analysis-report-v3.schema.json")
        _assert_application_signature(report, secret=V3_EXAMPLE_SECRET)
        assert report["payload"]["algorithm"]["engine_id"] == (
            "mineguard-ten-quantity-engine"
        )
        assert report["payload"]["algorithm"]["engine_version"].startswith("3.")
        assert report["payload"]["algorithm"]["input_snapshot_sha256"] == (
            submission["signature_envelope"]["payload_sha256"]
        )
        assert report["payload"]["outcome"] == "data_insufficient"
        assert report["payload"]["findings"]
        assert all(
            finding["title"].startswith("十量")
            for finding in report["payload"]["findings"]
        )
        assert "inventory_flow_reconciliation" not in report["payload"][
            "algorithm"
        ]["modules"]

        wrong_route_status, wrong_route_problem = request(
            "GET",
            f"/v2/analysis-reports/{report['payload']['report_id']}",
            contract_version="five-quantity-exchange-v2",
        )
        assert wrong_route_status == 404
        assert wrong_route_problem is not None
        assert wrong_route_problem["code"] == "NOT_FOUND"

        receipt_status, receipt = request(
            "GET",
            f"/v3/ten-quantity-submissions/{submission['message_id']}/receipt",
            contract_version="ten-quantity-exchange-v3",
        )
        assert receipt_status == 200
        assert receipt is not None
        _assert_contract(receipt, "intake-receipt-v2.schema.json")
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_complete_two_product_exchange_and_read_only_dashboard(tmp_path: Path) -> None:
    submission_body = (
        CONTRACTS / "examples" / "five-quantity-submission-v2.json"
    ).read_bytes()
    submission = json.loads(submission_body)
    client = ExchangeClient(
        sender_id="agent-mine-qy-001",
        party_id="operator-qy-001",
        mine_id="MINE-QY-001",
        secret=EXAMPLE_SECRET,
        mine_name="示例一号煤矿",
        comparison_context=submission["payload"]["comparison_context"],
    )
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "regulatory.db",
        auth_database_path=tmp_path / "auth.db",
        auth_required=False,
        clients={client.sender_id: client},
        clock=lambda: FIXED_NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    nonce_counter = 0

    def exchange_request(
        method: str,
        target: str,
        *,
        body: bytes = b"",
        contract_version: str,
    ) -> tuple[int, dict[str, Any] | None]:
        nonlocal nonce_counter
        nonce_counter += 1
        nonce = nonce_counter.to_bytes(16, "big")
        import base64

        nonce_text = base64.urlsafe_b64encode(nonce).decode().rstrip("=")
        headers = sign_transport_headers(
            client,
            method=method,
            request_target=target,
            body=body,
            contract_version=contract_version,
            timestamp=FIXED_NOW,
            nonce=nonce_text,
        )
        if body:
            headers["Content-Type"] = "application/json"
        connection.request(method, target, body=body or None, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        payload = json.loads(raw) if raw else None
        return response.status, payload

    try:
        future_envelope = deepcopy(submission)
        future_envelope["created_at"] = "2030-01-01T00:00:00Z"
        future_envelope["signature_envelope"]["signed_at"] = "2030-01-01T00:00:00Z"
        future_status, future_problem = exchange_request(
            "POST",
            "/v2/five-quantity-submissions",
            body=_signed_enterprise_message(future_envelope),
            contract_version="five-quantity-submission-v2",
        )
        assert future_status == 400
        assert future_problem is not None
        assert "future application timestamp" in future_problem["detail"]

        status, intake = exchange_request(
            "POST",
            "/v2/five-quantity-submissions",
            body=submission_body,
            contract_version="five-quantity-submission-v2",
        )
        assert status == 202
        assert intake is not None
        _assert_contract(intake, "intake-receipt-v2.schema.json")
        _assert_application_signature(intake)
        assert intake["payload"]["regulatory_outcome"] == "not_determined_at_intake"

        status, report = exchange_request(
            "GET",
            "/v2/analysis-reports/next",
            contract_version="five-quantity-exchange-v2",
        )
        assert status == 200
        assert report is not None
        _assert_contract(report, "analysis-report-v2.schema.json")
        _assert_application_signature(report)
        assert report["payload"]["outcome"] == "data_insufficient"
        assert report["payload"]["response_required"] is True
        assert report["payload"]["algorithm"]["engine_id"] == (
            "mineguard-five-quantity-engine"
        )
        assert "l1_reconciliation" in report["payload"]["algorithm"]["modules"]
        assert "robust_temporal_baseline" in report["payload"]["algorithm"]["modules"]

        broken_revision = deepcopy(submission)
        broken_revision["message_id"] = str(uuid4())
        broken_revision["correlation_id"] = submission["message_id"]
        broken_revision["causation_id"] = report["message_id"]
        broken_revision["idempotency_key"] = f"revision.{broken_revision['message_id']}"
        broken_revision["revision"] = 2
        broken_revision["predecessor"] = {
            "message_id": submission["message_id"],
            "payload_sha256": "0" * 64,
        }
        broken_revision["created_at"] = "2026-08-01T00:20:30Z"
        broken_revision["signature_envelope"]["signed_at"] = broken_revision[
            "created_at"
        ]
        broken_revision["signature_envelope"]["nonce"] = "BQUFBQUFBQUFBQUFBQUFBQ"
        status, lineage_problem = exchange_request(
            "POST",
            "/v2/five-quantity-submissions",
            body=_signed_enterprise_message(broken_revision),
            contract_version="five-quantity-submission-v2",
        )
        assert status == 409
        assert lineage_problem is not None
        assert lineage_problem["code"] == "LINEAGE_CONFLICT"
        _assert_problem(lineage_problem)

        ack = deepcopy(
            json.loads(
                (
                    CONTRACTS / "examples" / "risk-delivery-ack-v2.json"
                ).read_text(encoding="utf-8")
            )
        )
        ack["message_id"] = str(uuid4())
        ack["correlation_id"] = report["correlation_id"]
        ack["causation_id"] = report["message_id"]
        ack["idempotency_key"] = f"ack.{ack['message_id']}"
        ack["created_at"] = "2026-08-01T00:21:00Z"
        ack["payload"].update(
            {
                "report_id": report["payload"]["report_id"],
                "analysis_report_message_id": report["message_id"],
                "delivery_cursor": report["payload"]["delivery_cursor"],
                "received_at": "2026-08-01T00:20:59Z",
                "local_inbox_record_id": "inbox-test-001",
            }
        )
        ack["signature_envelope"]["signed_at"] = ack["created_at"]
        ack["signature_envelope"]["nonce"] = "AQEBAQEBAQEBAQEBAQEBAQ"
        ack_body = _signed_enterprise_message(ack)
        status, payload = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/delivery-ack",
            body=ack_body,
            contract_version="risk-delivery-ack-v2",
        )
        assert status == 204
        assert payload is None

        conflicting_ack = deepcopy(ack)
        conflicting_ack["message_id"] = str(uuid4())
        conflicting_ack["created_at"] = "2026-08-01T00:21:10Z"
        conflicting_ack["payload"]["local_inbox_record_id"] = "inbox-tampered"
        conflicting_ack["signature_envelope"]["signed_at"] = conflicting_ack[
            "created_at"
        ]
        conflicting_ack["signature_envelope"]["nonce"] = "AwMDAwMDAwMDAwMDAwMDAw"
        status, problem = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/delivery-ack",
            body=_signed_enterprise_message(conflicting_ack),
            contract_version="risk-delivery-ack-v2",
        )
        assert status == 409
        assert problem is not None
        assert problem["status"] == 409
        assert problem["code"] == "IMMUTABLE_CONFLICT"
        assert problem["type"].startswith("/problems/")
        _assert_problem(problem)

        response_message = deepcopy(
            json.loads(
                (
                    CONTRACTS / "examples" / "enterprise-risk-response-v2.json"
                ).read_text(encoding="utf-8")
            )
        )
        response_message["message_id"] = str(uuid4())
        response_message["correlation_id"] = report["correlation_id"]
        response_message["causation_id"] = report["message_id"]
        response_message["idempotency_key"] = (
            f"response.{response_message['message_id']}"
        )
        response_message["created_at"] = "2026-08-01T00:23:00Z"
        response_message["payload"]["response_id"] = str(uuid4())
        response_message["payload"]["report_id"] = report["payload"]["report_id"]
        response_message["payload"]["analysis_report_message_id"] = report["message_id"]
        response_message["payload"]["responded_at"] = "2026-08-01T00:22:59Z"
        response_message["payload"]["finding_responses"] = [
            {
                "finding_id": report["payload"]["findings"][0]["finding_id"],
                "response_kind": "explanation",
                "reason_code": "planned_shutdown",
                "facts": "企业已核对停产检修记录；本说明只作留痕，不申请直接消除风险。",
                "evidence_refs": [],
                "actions": [
                    {
                        "action_type": "investigation",
                        "description": "复核日报与三个班次原始记录。",
                        "status": "completed",
                    }
                ],
                "corrected_submission_message_id": None,
            }
        ]
        response_message["payload"]["attachments"] = []
        response_message["payload"]["agent_assistance"] = {
            "used": False,
            "conversation_id": None,
            "assistance_record_sha256": None,
        }
        response_message["payload"]["human_confirmation"].update(
            {
                "confirmed_at": "2026-08-01T00:22:58Z",
                "content_sha256": "9" * 64,
            }
        )
        response_message["signature_envelope"]["signed_at"] = response_message[
            "created_at"
        ]
        response_message["signature_envelope"]["nonce"] = "AgICAgICAgICAgICAgICAg"

        invalid_correction = deepcopy(response_message)
        invalid_correction["message_id"] = str(uuid4())
        invalid_correction["idempotency_key"] = (
            f"response.{invalid_correction['message_id']}"
        )
        invalid_correction["payload"]["response_id"] = str(uuid4())
        invalid_correction["payload"]["finding_responses"][0][
            "corrected_submission_message_id"
        ] = submission["message_id"]
        invalid_correction["payload"]["finding_responses"][0]["response_kind"] = (
            "correction_submitted"
        )
        invalid_correction["signature_envelope"]["nonce"] = "BAQEBAQEBAQEBAQEBAQEBA"
        status, correction_problem = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/responses",
            body=_signed_enterprise_message(invalid_correction),
            contract_version="enterprise-risk-response-v2",
        )
        assert status == 409
        assert correction_problem is not None
        assert "higher-revision descendant" in correction_problem["detail"]
        _assert_problem(correction_problem)

        response_body = _signed_enterprise_message(response_message)
        status, response_receipt = exchange_request(
            "POST",
            f"/v2/analysis-reports/{report['payload']['report_id']}/responses",
            body=response_body,
            contract_version="enterprise-risk-response-v2",
        )
        assert status == 202
        assert response_receipt is not None
        _assert_contract(response_receipt, "response-receipt-v2.schema.json")
        _assert_application_signature(response_receipt)
        assert response_receipt["payload"]["risk_status"] == ("not_cleared_by_receipt")

        connection.request("GET", "/v2/regulatory/overview")
        overview_response = connection.getresponse()
        overview = json.loads(overview_response.read())
        assert overview_response.status == 200
        assert overview["counts"]["configured_mines"] == 1
        assert overview["counts"]["insufficient_data"] == 1
        assert overview["counts"]["awaiting_response"] == 0
        assert overview["attention_counts"] == {
            "risk_findings": 0,
            "data_to_complete": 1,
            "awaiting_enterprise_response": 0,
            "enterprise_responded_unresolved": 1,
            "cleared_by_reanalysis": 0,
            "total_unresolved": 1,
        }
        assert "severity_counts" not in overview
        assert "highest_severity" not in overview
        assert "notice" not in overview
        assert overview["latest_events"]
        assert overview["latest_events"][0]["event_label"] == "企业已回复"
        assert overview["latest_events"][0]["status"] == "explanation_recorded"
        assert "风险尚未解除" in overview["latest_events"][0]["summary"]
        assert all(
            item["mine_name"] == "示例一号煤矿"
            and item["event_label"]
            and item["status"]
            and "_" not in item["summary"]
            for item in overview["latest_events"]
        )
        assert not {
            "agent_mine_bound",
            "exchange_inbound_recorded",
            "exchange_outbound_recorded",
            "anonymous_peer_snapshot_frozen",
            "baseline_candidate_admitted",
            "baseline_candidate_rejected",
            "finding_automatically_issued",
            "analysis_completed",
        } & {item["event_type"] for item in overview["latest_events"]}

        connection.request("GET", "/v2/regulatory/mines/MINE-QY-001")
        detail_response = connection.getresponse()
        detail = json.loads(detail_response.read())
        assert detail_response.status == 200
        assert detail["mine"]["mine_id"] == "MINE-QY-001"
        assert detail["latest_analysis"]["algorithm_version"].startswith(
            "regulatory-five-quantity-v2"
        )
        assert detail["findings"][0]["finding_type"] == "data_insufficient"
        assert detail["findings"][0]["state"] == "explanation_recorded"

        connection.request(
            "HEAD",
            f"/v2/analysis-reports/{report['payload']['report_id']}",
        )
        head_response = connection.getresponse()
        head_response.read()
        assert head_response.status == 405

        connection.request("POST", "/v2/regulatory/mines", body=b"{}")
        read_only_response = connection.getresponse()
        read_only_response.read()
        assert read_only_response.status == 404
        assert server.store.verify_audit_chain() is True
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_overview_attention_and_business_events_respect_mine_scope(
    tmp_path: Path,
) -> None:
    document = json.loads(
        (CONTRACTS / "examples" / "five-quantity-submission-v2.json").read_text(
            encoding="utf-8"
        )
    )
    first = FiveQuantitySubmissionMessage.model_validate(
        document
    ).to_regulatory_submission()
    second = first.model_copy(
        update={
            "submission_id": str(uuid4()),
            "mine_id": "MINE-OUTSIDE-002",
            "mine_name": "辖区外保密煤矿",
        }
    )
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "regulatory.db",
        auth_database_path=tmp_path / "auth.db",
        auth_required=True,
        clients={},
        clock=lambda: FIXED_NOW,
    )
    try:
        server.store.submit_and_analyze(first)
        server.store.submit_and_analyze(second)
        handler = object.__new__(RegulatoryV2RequestHandler)
        handler.server = server
        scoped = Principal(
            user_id="reviewer-001",
            username="reviewer",
            role=Role.REVIEWER,
            mine_scopes=(first.mine_id,),
            session_id="session-reviewer-001",
        )

        overview = handler._overview(scoped)

        assert overview["counts"]["configured_mines"] == 1
        assert overview["attention_counts"] == {
            "risk_findings": 0,
            "data_to_complete": 1,
            "awaiting_enterprise_response": 1,
            "enterprise_responded_unresolved": 0,
            "cleared_by_reanalysis": 0,
            "total_unresolved": 1,
        }
        assert len(overview["latest_events"]) == 1
        assert overview["latest_events"][0]["mine_id"] == first.mine_id
        assert overview["latest_events"][0]["mine_name"] == first.mine_name
        serialized = json.dumps(overview, ensure_ascii=False)
        assert second.mine_id not in serialized
        assert second.mine_name not in serialized

        admin = Principal(
            user_id="admin-001",
            username="admin",
            role=Role.ADMIN,
            mine_scopes=(),
            session_id="session-admin-001",
        )
        admin_overview = handler._overview(admin)
        assert admin_overview["counts"]["configured_mines"] == 2
        assert admin_overview["attention_counts"]["data_to_complete"] == 2
        assert len(admin_overview["latest_events"]) == 2
        assert {item["mine_id"] for item in admin_overview["latest_events"]} == {
            first.mine_id,
            second.mine_id,
        }
        assert len(server.store.list_audit_events(limit=200)) > len(
            admin_overview["latest_events"]
        )
    finally:
        server.server_close()


def test_revision_resolution_events_share_correlation_and_aggregate(
    tmp_path: Path,
) -> None:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "regulatory.db",
        auth_database_path=tmp_path / "auth.db",
        auth_required=False,
        clients={},
        clock=lambda: FIXED_NOW,
    )
    try:
        handler = object.__new__(RegulatoryV2RequestHandler)
        handler.server = server
        resolving_submission_id = "revision-submission-002"
        resolution_events = [
            AuditProjection(
                sequence=sequence,
                event_id=str(uuid4()),
                event_type="finding_resolved_by_revision_reanalysis",
                aggregate_type="finding",
                aggregate_id=f"finding-{sequence}",
                mine_id="MINE-QY-001",
                payload={
                    "resolving_submission_id": resolving_submission_id,
                    "rule": "normal_candidate_revision_reanalysis_only",
                },
                occurred_at=FIXED_NOW,
                previous_hash="0" * 64,
                event_hash=f"{sequence}" * 64,
            )
            for sequence in (3, 4)
        ]
        events = [
            AuditProjection(
                sequence=1,
                event_id=str(uuid4()),
                event_type="submission_received",
                aggregate_type="submission",
                aggregate_id=resolving_submission_id,
                mine_id="MINE-QY-001",
                payload={"revision": 2, "supersedes_submission_id": "submission-001"},
                occurred_at=FIXED_NOW,
                previous_hash="0" * 64,
                event_hash="1" * 64,
            ),
            AuditProjection(
                sequence=2,
                event_id=str(uuid4()),
                event_type="analysis_completed",
                aggregate_type="analysis_run",
                aggregate_id="analysis-run-002",
                mine_id="MINE-QY-001",
                payload={
                    "submission_id": resolving_submission_id,
                    "decision": "normal_candidate",
                },
                occurred_at=FIXED_NOW,
                previous_hash="1" * 64,
                event_hash="2" * 64,
            ),
            *resolution_events,
            AuditProjection(
                sequence=5,
                event_id=str(uuid4()),
                event_type="analysis_report_automatically_issued",
                aggregate_type="analysis_report",
                aggregate_id="analysis-report-002",
                mine_id="MINE-QY-001",
                payload={
                    "submission_id": resolving_submission_id,
                    "outcome": "normal_candidate",
                    "finding_ids": [],
                },
                occurred_at=FIXED_NOW,
                previous_hash="4" * 64,
                event_hash="5" * 64,
            ),
        ]

        assert len({handler._business_event_key(item) for item in events}) == 1
        handler._audit_events = lambda principal, *, limit: list(reversed(events))
        projected_events = handler._latest_business_events(
            Principal(
                user_id="admin-001",
                username="admin",
                role=Role.ADMIN,
                mine_scopes=(),
                session_id="session-admin-001",
            ),
            mine_names={"MINE-QY-001": "示例一号煤矿"},
            limit=8,
        )

        assert len(projected_events) == 1
        projected = projected_events[0]
        assert projected["event_type"] == "finding_resolved_by_revision_reanalysis"
        assert projected["correlation_id"] == resolving_submission_id
        assert projected["event_label"] == "风险已解除"
        assert projected["status"] == "cleared_by_reanalysis"
        assert "2 项相关风险已解除" in projected["summary"]
    finally:
        server.server_close()
