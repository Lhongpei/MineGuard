from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import threading
from typing import Any

import pytest

from mineguard import api as api_module
from mineguard.api import (
    OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
    create_server,
)
from mineguard.auth import Role


ROOT = Path(__file__).resolve().parents[1]
WORKBOOK = ROOT.parent / "local _test" / "五量基础数据测试（沁源梗阳）.et"


@contextmanager
def running_server(tmp_path: Path) -> Iterator[tuple[Any, str, int]]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=True,
        auth_database_path=tmp_path / "auth.db",
        bootstrap_admin=("admin", "correct admin password"),
        secure_cookie=False,
        job_database_path=tmp_path / "jobs.db",
        evidence_database_path=tmp_path / "evidence.db",
        evidence_directory=tmp_path / "evidence",
        evidence_secret=b"test-evidence-secret-with-32-bytes!",
        governance_database_path=tmp_path / "governance.db",
        source_key_directory=tmp_path / "source-keys",
        backup_directory=tmp_path / "backups",
        backup_secret=b"test-backup-secret-with-32-bytes!!",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield server, str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: Any | None = None,
    *,
    headers: dict[str, str] | None = None,
    content_type: str | None = "application/json",
) -> tuple[int, dict[str, Any], dict[str, str]]:
    connection = http.client.HTTPConnection(host, port, timeout=5)
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    request_headers = dict(headers or {})
    if encoded is not None and content_type is not None:
        request_headers["Content-Type"] = content_type
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
        return (
            response.status,
            json.loads(response.read()),
            response_headers,
        )
    finally:
        connection.close()


def login(
    host: str,
    port: int,
    username: str,
    password: str,
) -> tuple[str, str]:
    status, payload, headers = request(
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


def auth_headers(cookie: str, csrf: str | None = None) -> dict[str, str]:
    result = {"Cookie": cookie}
    if csrf is not None:
        result["X-CSRF-Token"] = csrf
    return result


def analysis_payload(mine_id: str) -> dict[str, Any]:
    if not WORKBOOK.is_file():
        pytest.skip("local five-quantity workbook is unavailable")
    return {
        "mine_id": mine_id,
        "source": {
            "source_id": "operator-upload",
            "filename": WORKBOOK.name,
            "received_at": "2026-07-31T08:00:00Z",
        },
        "report_month": "2026-07",
        "closed_through": "2026-07-30",
        "content_base64": base64.b64encode(WORKBOOK.read_bytes()).decode(
            "ascii"
        ),
    }


def test_route_requires_post_json_login_and_csrf(tmp_path: Path) -> None:
    with running_server(tmp_path) as (_, host, port):
        status, payload, headers = request(
            host,
            port,
            "GET",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
        )
        assert status == 405
        assert headers["allow"] == "POST"
        assert payload["error"]["code"] == "method_not_allowed"

        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            analysis_payload("M001"),
        )
        assert status == 401
        assert payload["error"]["code"] == "authentication_required"

        cookie, _ = login(host, port, "admin", "correct admin password")
        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            analysis_payload("M001"),
            headers=auth_headers(cookie),
        )
        assert status == 403
        assert payload["error"]["code"] == "csrf_invalid"

        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            analysis_payload("M001"),
            headers=auth_headers(cookie),
            content_type="application/octet-stream",
        )
        assert status == 415
        assert payload["error"]["code"] == "unsupported_media_type"


def test_scoped_supervisor_can_analyze_without_persisting(
    tmp_path: Path,
) -> None:
    with running_server(tmp_path) as (server, host, port):
        server.auth_store.create_user(
            "supervisor",
            "supervisor secure password",
            Role.SUPERVISOR,
            ["M001"],
        )
        cookie, csrf = login(
            host,
            port,
            "supervisor",
            "supervisor secure password",
        )
        before_batches = server.repository.list_batches()

        status, payload, headers = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            analysis_payload("M001"),
            headers=auth_headers(cookie, csrf),
        )

        assert status == 200
        assert headers["cache-control"] == "no-store"
        assert payload["mine_id"] == "M001"
        assert payload["trust"] == {
            "input_class": "operator_uploaded_untrusted",
            "persisted": False,
            "eligible_for_history": False,
            "creates_case": False,
            "regulatory_effect": "none",
            "audit_metadata_persisted": True,
            "persistence_statement": (
                "input_and_analysis_result_not_persisted"
            ),
            "audit_metadata_scope": (
                "metadata_only_no_file_or_daily_payload"
            ),
        }
        assert payload["report_month"] == "2026-07"
        assert payload["report_month_source"] == "explicit_request"
        assert len(payload["configuration"]["sha256"]) == 64
        assert payload["configuration"]["method_version"] == (
            payload["method_version"]
        )
        assert payload["overall"]["status"] == "needs_priority_review"
        assert any(
            event["event_code"] == "shift_total_mismatch:electricity"
            and event["period_start"] == "2026-07-13"
            for event in payload["events"]
        )
        assert server.repository.list_batches() == before_batches
        audit = next(
            event
            for event in server.auth_store.list_audit_events()
            if event["action"]
            == "operational_five_quantity_analysis_completed"
        )
        assert audit["detail"]["mine_id"] == "M001"
        assert audit["detail"]["report_month"] == "2026-07"
        assert audit["detail"]["source_sha256"] == payload["source_sha256"]
        assert audit["detail"]["configuration_sha256"] == (
            payload["configuration"]["sha256"]
        )
        audit_text = json.dumps(audit, ensure_ascii=False)
        assert "content_base64" not in audit_text
        assert WORKBOOK.name not in audit_text
        assert payload["source_title"] not in audit_text
        assert "days" not in audit["detail"]

        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            analysis_payload("M002"),
            headers=auth_headers(cookie, csrf),
        )
        assert status == 403
        assert payload["error"]["code"] == "permission_denied"


def test_production_route_requires_explicit_coherent_report_month(
    tmp_path: Path,
) -> None:
    with running_server(tmp_path) as (_, host, port):
        cookie, csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        missing = analysis_payload("M001")
        missing.pop("report_month")
        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            missing,
            headers=auth_headers(cookie, csrf),
        )
        assert status == 400
        assert payload["error"]["code"] == "report_month_required"

        invalid_period = analysis_payload("M001")
        invalid_period["report_month"] = "2026-08"
        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            invalid_period,
            headers=auth_headers(cookie, csrf),
        )
        assert status == 400
        assert payload["error"]["code"] == "invalid_report_period"


def test_reviewer_is_denied_and_parse_failure_uses_stable_code(
    tmp_path: Path,
) -> None:
    with running_server(tmp_path) as (server, host, port):
        server.auth_store.create_user(
            "reviewer",
            "reviewer secure password",
            Role.REVIEWER,
            ["M001"],
        )
        reviewer_cookie, reviewer_csrf = login(
            host,
            port,
            "reviewer",
            "reviewer secure password",
        )
        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            analysis_payload("M001"),
            headers=auth_headers(reviewer_cookie, reviewer_csrf),
        )
        assert status == 403
        assert payload["error"]["code"] == "permission_denied"

        admin_cookie, admin_csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        invalid = analysis_payload("M001")
        invalid["content_base64"] = base64.b64encode(b"not-an-ole-file").decode(
            "ascii"
        )
        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            invalid,
            headers=auth_headers(admin_cookie, admin_csrf),
        )
        assert status == 422
        assert payload["error"]["code"] == "five_quantity_import_failed"
        assert payload["error"]["details"] == [{"code": "not_ole2"}]
        assert "/home/" not in json.dumps(payload)


def test_production_route_rejects_caller_threshold_overrides(
    tmp_path: Path,
) -> None:
    with running_server(tmp_path) as (_, host, port):
        cookie, csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        overridden = analysis_payload("M001")
        overridden["validation"] = {
            "electricity_sum_tolerance": 1_000_000_000_000,
        }
        overridden["analysis_parameters"] = {
            "robust_z_threshold": 100,
            "critical_robust_z_threshold": 100,
        }

        status, payload, _ = request(
            host,
            port,
            "POST",
            OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
            overridden,
            headers=auth_headers(cookie, csrf),
        )

        assert status == 400
        assert payload["error"]["code"] == "governed_parameters_required"
        assert payload["error"]["details"] == [
            {
                "fields": [
                    "analysis_parameters",
                    "validation",
                ]
            }
        ]


def test_success_result_is_not_released_when_required_audit_fails(
    tmp_path: Path,
) -> None:
    with running_server(tmp_path) as (server, host, port):
        cookie, csrf = login(
            host,
            port,
            "admin",
            "correct admin password",
        )
        original = server.auth_store.record_audit_event

        def fail_target_audit(
            action: str,
            **kwargs: Any,
        ) -> None:
            if action == "operational_five_quantity_analysis_completed":
                raise RuntimeError("simulated audit outage")
            original(action, **kwargs)

        server.auth_store.record_audit_event = fail_target_audit
        try:
            status, payload, _ = request(
                host,
                port,
                "POST",
                OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
                analysis_payload("M001"),
                headers=auth_headers(cookie, csrf),
            )
        finally:
            server.auth_store.record_audit_event = original

        assert status == 500
        assert payload["error"]["code"] == "audit_persistence_failed"
        assert "events" not in payload
        assert "days" not in payload


def test_busy_parser_capacity_closes_connection_before_reading_body(
    tmp_path: Path,
) -> None:
    semaphore = api_module._OPERATIONAL_FIVE_QUANTITY_ANALYSIS_SLOTS
    assert semaphore.acquire(blocking=False)
    assert semaphore.acquire(blocking=False)
    try:
        with running_server(tmp_path) as (_, host, port):
            cookie, csrf = login(
                host,
                port,
                "admin",
                "correct admin password",
            )
            status, payload, headers = request(
                host,
                port,
                "POST",
                OPERATIONAL_FIVE_QUANTITY_ANALYSIS_PATH,
                analysis_payload("M001"),
                headers=auth_headers(cookie, csrf),
            )
            assert status == 503
            assert payload["error"]["code"] == "five_quantity_analysis_busy"
            assert headers["retry-after"] == "1"
            assert headers["connection"] == "close"
    finally:
        semaphore.release()
        semaphore.release()
