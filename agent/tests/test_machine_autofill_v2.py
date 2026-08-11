from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from enterprise_agent.errors import ValidationBlockedError
from enterprise_agent.five_quantity_exchange import MineIdentity
from enterprise_agent.five_quantity_runtime import FiveQuantityRuntime
from enterprise_agent.http_api import EnterpriseAgentHTTPServer
from enterprise_agent.machine_ingestion import ConnectorClient, ConnectorSourcePolicy
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.settings import AgentV2Config
from enterprise_agent.storage import Repository
from enterprise_agent.util import sha256_jcs

SECRET = "connector-test-secret-at-least-thirty-two-bytes"
_CANONICAL_DRAFT_KEY = (
    "draft:operator-machine-001:five-quantity:monthly:2026-07"
)
_ALLOWED_SOURCE_IDS = (
    "erp-production",
    "source-a",
    "source-b",
    "source-month",
    "source-auth",
)


def _client(
    *,
    client_id: str = "erp-main",
    secret: str = SECRET,
    required_sources: tuple[str, ...] = (),
) -> ConnectorClient:
    return ConnectorClient(
        client_id=client_id,
        secret=secret,
        allowed_sources=tuple(
            ConnectorSourcePolicy(
                source_id=source_id,
                source_system=f"test-{source_id}",
                required=source_id in required_sources,
            )
            for source_id in _ALLOWED_SOURCE_IDS
        ),
    )


def _identity() -> MineIdentity:
    return MineIdentity(
        mine_id="MINE-MACHINE-001",
        mine_name="机器填报测试煤矿",
        operator_id="operator-machine-001",
        operator_name="机器填报测试企业",
        system_id="agent-machine-001",
        regulator_system_id="mineguard-qinyuan",
        regulator_party_id="regulator-qinyuan",
        key_id="enterprise-machine-key",
        regulator_key_id="regulator-key-v2",
        message_hmac_secret="machine-message-secret-abcdefghijklmnopqrstuvwxyz",
        capacity_band="medium",
        mining_method="underground",
        shift_system="three-shift-eight-hour",
        coal_type="bituminous",
        operating_regime="normal-production",
    )


def _payload(
    *,
    event_id: str,
    source_id: str,
    revision: int,
    csv_text: str,
    draft_key: str = _CANONICAL_DRAFT_KEY,
    trigger: bool = True,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    dates = [
        line.split(",", 1)[0]
        for line in csv_text.splitlines()[1:]
        if line and len(line.split(",", 1)[0]) == 10
    ]
    coverage_as_of = max(dates)
    return {
        "contract_version": "enterprise-autofill-ingestion/v1",
        "event_id": event_id,
        "draft_key": draft_key,
        "source": {
            "source_id": source_id,
            "revision": revision,
            "format": "csv",
            "content": csv_text,
            "source_name": f"{source_id}.csv",
            "source_system": f"test-{source_id}",
            "original_filename": f"{source_id}.csv",
            "observed_at": (observed_at or datetime.now(UTC)).isoformat(),
            "coverage_as_of": coverage_as_of,
            "truth_statement": True,
        },
        "trigger_workflow": trigger,
        "workflow_name": "daily_coal_health",
    }


def _machine_request(
    port: int,
    payload: dict[str, Any],
    *,
    request_id: str,
    client_id: str = "erp-main",
    secret: str = SECRET,
    timestamp: int | None = None,
) -> tuple[int, dict[str, Any]]:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    timestamp_text = str(int(time.time()) if timestamp is None else timestamp)
    body_sha256 = hashlib.sha256(raw).hexdigest()
    material = (
        "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1\n"
        "POST\n/api/v1/machine/autofill\n"
        f"{timestamp_text}\n{request_id}\n{body_sha256}"
    ).encode()
    signature = hmac.new(secret.encode(), material, hashlib.sha256).hexdigest()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            "/api/v1/machine/autofill",
            body=raw,
            headers={
                "Content-Type": "application/json",
                "X-Enterprise-Connector-Client": client_id,
                "X-Enterprise-Connector-Timestamp": timestamp_text,
                "X-Enterprise-Connector-Request-Id": request_id,
                "X-Enterprise-Connector-Signature": signature,
            },
        )
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def _raw_machine_request(
    port: int,
    raw: bytes,
    *,
    request_id: str,
    path: str = "/api/v1/machine/autofill",
    signing_path: str = "/api/v1/machine/autofill",
    signature_override: str | None = None,
) -> tuple[int, dict[str, Any]]:
    timestamp_text = str(int(time.time()))
    body_sha256 = hashlib.sha256(raw).hexdigest()
    material = (
        "ENTERPRISE-CONNECTOR-HMAC-SHA256-V1\n"
        f"POST\n{signing_path}\n"
        f"{timestamp_text}\n{request_id}\n{body_sha256}"
    ).encode()
    signature = signature_override or hmac.new(
        SECRET.encode(), material, hashlib.sha256
    ).hexdigest()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(
            "POST",
            path,
            body=raw,
            headers={
                "Content-Type": "application/json",
                "X-Enterprise-Connector-Client": "erp-main",
                "X-Enterprise-Connector-Timestamp": timestamp_text,
                "X-Enterprise-Connector-Request-Id": request_id,
                "X-Enterprise-Connector-Signature": signature,
            },
        )
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def _health_payload(
    *,
    event_id: str,
    autofill_payload: dict[str, Any],
    outcome: str,
    completed_at: datetime | None = None,
    snapshot_sha256: str | None = None,
    autofill_event_id: str | None = None,
    source_revision: int | None = None,
) -> dict[str, Any]:
    completed = completed_at or datetime.now(UTC)
    nonempty = outcome == "success_nonempty"
    source = autofill_payload["source"]
    return {
        "contract_version": "enterprise-source-health/v1",
        "event_id": event_id,
        "draft_key": autofill_payload["draft_key"],
        "reporting_month": source["coverage_as_of"][:7],
        "source_id": source["source_id"],
        "source_system": source["source_system"],
        "outcome": outcome,
        "attempted_at": (completed - timedelta(seconds=1)).isoformat(),
        "completed_at": completed.isoformat(),
        "record_count": 1 if nonempty else 0,
        "coverage_as_of": source["coverage_as_of"] if nonempty else None,
        "error_code": "source_poll_failed" if outcome == "error" else None,
        "snapshot_sha256": (
            snapshot_sha256
            if nonempty
            else None
        ),
        "autofill_event_id": autofill_event_id if nonempty else None,
        "source_revision": source_revision if nonempty else None,
    }


def _health_request(
    port: int,
    payload: dict[str, Any],
    *,
    request_id: str,
) -> tuple[int, dict[str, Any]]:
    return _raw_machine_request(
        port,
        json.dumps(payload, separators=(",", ":")).encode(),
        request_id=request_id,
        path="/api/v1/machine/source-health",
        signing_path="/api/v1/machine/source-health",
    )


def _get(port: int, path: str) -> tuple[int, dict[str, Any]]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def _server(
    path: Path,
    *,
    clients: tuple[ConnectorClient, ...] | None = None,
) -> tuple[EnterpriseAgentHTTPServer, threading.Thread, FiveQuantityRuntime]:
    repository = Repository(path)
    runtime = FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=path.parent / "quarantine",
    )
    service = EnterpriseAgentService(
        repository,
        five_quantity_runtime=runtime,
        agent_v2_config=AgentV2Config(enabled=False, scheduler_enabled=False),
    )
    server = EnterpriseAgentHTTPServer(
        ("127.0.0.1", 0),
        service,
        connector_clients=clients
        or (_client(),),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, runtime


def _close(server: EnterpriseAgentHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_signed_connector_enters_visible_v2_inbox_and_replays_by_event(
    tmp_path: Path,
) -> None:
    server, thread, runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    body = _payload(
        event_id="evt-july-001",
        source_id="erp-production",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
    )
    try:
        status, service_status = _get(port, "/api/v2/status")
        assert status == 200
        assert service_status["machine_connector_enabled"] is True
        assert service_status["connector_client_count"] == 1

        status, result = _machine_request(port, body, request_id="attempt-001")
        assert status == 202
        draft_id = result["draft_id"]
        assert result["workflow"]["execution_mode"] == (
            "v2_data_readiness_preflight"
        )
        assert result["workflow"]["preflight"]["bound_revision"] == 1
        assert result["workflow"]["preflight"]["missing_count"] > 0
        assert result["import"]["mode"] == "ten_quantity_v3_direct_collection"
        coverage = result["workflow"]["preflight"]["calendar_coverage"]
        assert coverage["kind"] == "partial_window"
        assert coverage["leading_days_outside_window"] == 0
        assert coverage["trailing_days_outside_window"] == 30

        status, draft = _get(port, f"/api/v2/drafts/{draft_id}")
        assert status == 200
        measurement = draft["payload"]["days"][0]["reported_quantity"][
            "daily_total"
        ]["production_t"]
        assert measurement["value"] == 100
        assert draft["payload"]["sources"][0]["acquisition_mode"] == (
            "direct_collection"
        )
        assert draft["payload"]["sources"][0]["source_system"] == (
            "test-erp-production"
        )

        status, evidence = _get(port, f"/api/v2/drafts/{draft_id}/ingestions")
        assert status == 200
        assert evidence["count"] == 1
        assert evidence["latest_preflight"]["bound_revision"] == 1
        assert evidence["freshness"]["overall_state"] == "fresh"
        assert evidence["source_health"][0]["freshness_state"] == "fresh"
        assert evidence["source_health"][0]["coverage_as_of"] == "2026-07-01"
        serialised = json.dumps(evidence, ensure_ascii=False)
        assert SECRET not in serialised
        assert "source.content" not in serialised
        assert "draft_key" not in serialised
        assert "signature" not in serialised

        status, replay = _machine_request(port, body, request_id="attempt-002")
        assert status == 200
        assert replay["draft_id"] == draft_id
        assert replay["idempotent_replay"] is True

        status, error = _machine_request(port, body, request_id="attempt-002")
        assert status == 409
        assert error["error"]["code"] == "conflict"

        # Historical rows retain their original diagnostic label. Reading
        # them never rewrites signed/source history into the new V3 wording.
        ingestion_id = result["ingestion_id"]
        with runtime.store.repository._transaction() as db:
            row = db.execute(
                "SELECT import_summary_json FROM connector_ingestions "
                "WHERE ingestion_id=?",
                (ingestion_id,),
            ).fetchone()
            legacy_summary = json.loads(row[0])
            legacy_summary["mode"] = "five_quantity_v2_direct_collection"
            db.execute(
                "UPDATE connector_ingestions SET import_summary_json=? "
                "WHERE ingestion_id=?",
                (json.dumps(legacy_summary), ingestion_id),
            )
        legacy = runtime.store.repository.get_connector_ingestion(ingestion_id)
        assert legacy["import_summary"]["mode"] == (
            "five_quantity_v2_direct_collection"
        )
    finally:
        _close(server, thread)


def test_latest_source_snapshots_update_remove_and_reject_cross_source_conflict(
    tmp_path: Path,
) -> None:
    server, thread, runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    try:
        first = _payload(
            event_id="evt-a-0",
            source_id="source-a",
            revision=1,
            csv_text="date,production_t\n2026-07-01,100\n",
            trigger=False,
        )
        status, created = _machine_request(port, first, request_id="req-a-0")
        assert status == 201
        draft_id = created["draft_id"]
        assert created["workflow"]["triggered"] is False
        assert created["workflow"]["preflight"]["bound_revision"] == 1
        draft = runtime.store.get_draft(draft_id)
        payload_sha256 = sha256_jcs(draft["payload"])
        assert created["workflow"]["preflight"][
            "payload_sha256_prefix"
        ] == payload_sha256[:12]
        with runtime.store.repository._read() as db:
            stored_preflight = json.loads(
                db.execute(
                    "SELECT workflow_result_json FROM connector_ingestions "
                    "WHERE event_id='evt-a-0'"
                ).fetchone()[0]
            )
        assert stored_preflight["bound_revision"] == draft["revision"]
        assert stored_preflight["payload_sha256"] == payload_sha256
        _status, evidence = _get(
            port, f"/api/v2/drafts/{draft_id}/ingestions"
        )
        assert evidence["latest_preflight"]["obsolete"] is False
        source_health = next(
            item
            for item in evidence["source_health"]
            if item["source_id"] == "source-a"
        )
        assert source_health["source_name"] == "source-a.csv"

        updated = _payload(
            event_id="evt-a-1",
            source_id="source-a",
            revision=2,
            csv_text="date,production_t\n2026-07-01,101\n",
            trigger=False,
        )
        status, update_result = _machine_request(
            port, updated, request_id="req-a-1"
        )
        assert status == 201
        assert update_result["draft_id"] == draft_id
        assert update_result["autofill_preview"]["source_revision"] == 2

        conflicting = _payload(
            event_id="evt-b-0",
            source_id="source-b",
            revision=1,
            csv_text="date,production_t\n2026-07-01,102\n",
            trigger=False,
        )
        status, error = _machine_request(port, conflicting, request_id="req-b-0")
        assert status == 409
        assert error["error"]["code"] == "connector_source_conflict"
        status, evidence = _get(port, f"/api/v2/drafts/{draft_id}/ingestions")
        assert status == 200
        rejected = next(
            item
            for item in evidence["items"]
            if item["event_id"] == "evt-b-0"
        )
        assert rejected["status"] == "rejected"
        assert rejected["rejection"]["code"] == "connector_source_conflict"
        assert rejected["draft_revision"] is None
        assert rejected["preflight"] is None
        assert not {
            "content",
            "content_b64",
            "payload",
            "autofill_preview",
        }.intersection(rejected)
        with runtime.store.repository._read() as db:
            rejected_projection = db.execute(
                "SELECT import_summary_json,draft_payload_sha256,"
                "workflow_result_json,result_json "
                "FROM connector_ingestions WHERE event_id='evt-b-0'"
            ).fetchone()
            rejected_contribution = db.execute(
                "SELECT 1 FROM fq_machine_source_contributions "
                "WHERE source_id='source-b'"
            ).fetchone()
        assert rejected_projection is not None
        assert tuple(rejected_projection) == (None, None, None, None)
        assert rejected_contribution is None

        status, replayed_error = _machine_request(
            port, conflicting, request_id="req-b-replay"
        )
        assert status == 409
        assert replayed_error["error"]["code"] == (
            "connector_source_conflict"
        )
        assert replayed_error["error"]["details"][
            "idempotent_replay"
        ] is True
        _status, draft = _get(port, f"/api/v2/drafts/{draft_id}")
        assert draft["payload"]["days"][0]["reported_quantity"]["daily_total"][
            "production_t"
        ]["value"] == 101

        removed = _payload(
            event_id="evt-a-2",
            source_id="source-a",
            revision=3,
            csv_text="date,production_t\n2026-07-01,\n",
            trigger=False,
        )
        status, _result = _machine_request(port, removed, request_id="req-a-2")
        assert status == 201
        _status, draft = _get(port, f"/api/v2/drafts/{draft_id}")
        assert draft["payload"]["days"][0]["reported_quantity"]["daily_total"][
            "production_t"
        ]["value"] is None
    finally:
        _close(server, thread)


def test_machine_never_overwrites_human_edit_and_month_key_is_bound(
    tmp_path: Path,
) -> None:
    server, thread, runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    try:
        first = _payload(
            event_id="evt-human-0",
            source_id="source-a",
            revision=1,
            csv_text="date,production_t\n2026-07-01,100\n",
            trigger=False,
        )
        status, result = _machine_request(port, first, request_id="human-req-0")
        assert status == 201
        draft = runtime.store.get_draft(result["draft_id"])
        edited = json.loads(json.dumps(draft["payload"]))
        edited["days"][0]["reported_quantity"]["daily_total"]["production_t"][
            "value"
        ] = 105
        edited_draft = runtime.save_draft(
            draft["draft_id"],
            expected_revision=draft["revision"],
            payload=edited,
            actor="human-operator",
        )
        _status, evidence = _get(
            port, f"/api/v2/drafts/{draft['draft_id']}/ingestions"
        )
        assert evidence["latest_preflight"]["obsolete"] is True
        assert evidence["latest_preflight"]["status"] == "attention_required"
        assert any(
            "未绑定当前草稿修订版" in warning
            for warning in evidence["latest_preflight"]["warnings"]
        )

        next_source = _payload(
            event_id="evt-human-1",
            source_id="source-a",
            revision=2,
            csv_text="date,production_t\n2026-07-01,110\n",
            trigger=False,
        )
        status, error = _machine_request(
            port, next_source, request_id="human-req-1"
        )
        assert status == 409
        assert "人工编辑" in error["error"]["message"]
        assert runtime.store.get_draft(draft["draft_id"])["payload"]["days"][0][
            "reported_quantity"
        ]["daily_total"]["production_t"]["value"] == 105

        wrong_month = _payload(
            event_id="evt-wrong-month",
            source_id="source-month",
            revision=1,
            csv_text="date,production_t\n2026-07-01,1\n",
            draft_key=(
                "draft:operator-machine-001:five-quantity:monthly:2026-08"
            ),
            trigger=False,
        )
        status, error = _machine_request(
            port, wrong_month, request_id="wrong-month-req"
        )
        assert status == 409
        assert "draft_key" in error["error"]["message"]

        confirmed = runtime.confirm_draft(
            draft["draft_id"],
            expected_revision=edited_draft["revision"],
            actor_id="human-operator",
            confirmer_name="人工复核员",
            confirmer_role="经办人",
            attestation="已核对人工修订和原始材料",
            accepted=True,
        )
        assert confirmed["status"] == "queued"
        with runtime.store.repository._read() as db:
            audit = db.execute(
                "SELECT details_json FROM fq_audit "
                "WHERE event_type='five_quantity_machine_preflight_recomputed' "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            assert db.execute(
                "SELECT COUNT(*) FROM fq_outbox WHERE aggregate_id=?",
                (draft["draft_id"],),
            ).fetchone()[0] == 1
        assert audit is not None
        audit_details = json.loads(audit["details_json"])
        assert audit_details["reason"] == "obsolete"
        assert audit_details["preflight"]["bound_revision"] == (
            edited_draft["revision"]
        )
        assert audit_details["preflight"]["payload_sha256"] == sha256_jcs(
            edited_draft["payload"]
        )
    finally:
        _close(server, thread)


def test_hmac_failures_are_uniform_and_source_scope_is_enforced(
    tmp_path: Path,
) -> None:
    server, thread, _runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    body = _payload(
        event_id="evt-auth",
        source_id="source-auth",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    try:
        errors = []
        for kwargs in (
            {"secret": "wrong-secret-that-is-still-long-enough-0000"},
            {"client_id": "unknown-client"},
            {"timestamp": int(time.time()) - 1000},
        ):
            status, error = _machine_request(
                port,
                body,
                request_id=f"auth-{len(errors)}",
                **kwargs,
            )
            assert status == 401
            errors.append(error)
        assert errors[0] == errors[1] == errors[2]
        assert SECRET not in json.dumps(errors)

        unauthorized = _payload(
            event_id="evt-auth-unauthorized",
            source_id="source-not-allowed",
            revision=1,
            csv_text="date,production_t\n2026-07-01,101\n",
            trigger=False,
        )
        status, error = _machine_request(
            port,
            unauthorized,
            request_id="auth-scope-denied",
        )
        assert status == 403
        assert error["error"]["code"] == "connector_source_not_allowed"

        status, error = _machine_request(
            port,
            unauthorized,
            request_id="auth-scope-denied",
        )
        assert status == 409
        assert error["error"]["code"] == "conflict"

        status, result = _machine_request(port, body, request_id="auth-valid")
        assert status == 201
        assert result["draft_key"] == _CANONICAL_DRAFT_KEY
    finally:
        _close(server, thread)


def test_server_rejects_multiple_authoritative_clients(tmp_path: Path) -> None:
    repository = Repository(tmp_path / "agent.db")
    runtime = FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=tmp_path / "quarantine",
    )
    service = EnterpriseAgentService(
        repository,
        five_quantity_runtime=runtime,
        agent_v2_config=AgentV2Config(enabled=False, scheduler_enabled=False),
    )
    second_secret = "second-connector-secret-at-least-thirty-two-bytes"
    with pytest.raises(ValueError, match="最多允许 1 个"):
        EnterpriseAgentHTTPServer(
            ("127.0.0.1", 0),
            service,
            connector_clients=(
                _client(),
                _client(client_id="lab-main", secret=second_secret),
            ),
        )


def test_human_pause_explicit_resume_and_discard_replacement(
    tmp_path: Path,
) -> None:
    server, thread, runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    first = _payload(
        event_id="evt-lifecycle-1",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    try:
        status, created = _machine_request(
            port, first, request_id="lifecycle-request-1"
        )
        assert status == 201
        draft_id = created["draft_id"]
        draft = runtime.store.get_draft(draft_id)
        edited = json.loads(json.dumps(draft["payload"]))
        edited["days"][0]["reported_quantity"]["daily_total"][
            "production_t"
        ]["value"] = 105
        draft = runtime.save_draft(
            draft_id,
            expected_revision=draft["revision"],
            payload=edited,
            actor="human-operator",
        )
        assert runtime.machine_sync_state(draft_id)["state"] == "paused"

        resumed = runtime.resume_machine_sync(
            draft_id,
            expected_revision=draft["revision"],
            accepted=True,
            actor="human-supervisor",
        )
        assert resumed["payload"]["days"][0]["reported_quantity"][
            "daily_total"
        ]["production_t"]["value"] == 100
        assert runtime.machine_sync_state(draft_id)["state"] == "active"

        update = _payload(
            event_id="evt-lifecycle-2",
            source_id="source-a",
            revision=2,
            csv_text="date,production_t\n2026-07-01,110\n",
            trigger=False,
        )
        status, updated = _machine_request(
            port, update, request_id="lifecycle-request-2"
        )
        assert status == 201
        assert updated["draft_id"] == draft_id
        active = runtime.store.get_draft(draft_id)
        discarded = runtime.discard_draft(
            draft_id,
            expected_revision=active["revision"],
            actor="human-supervisor",
            reason="本轮草稿作废后重采",
        )
        assert discarded["status"] == "discarded"

        replacement = _payload(
            event_id="evt-lifecycle-3",
            source_id="source-a",
            revision=3,
            csv_text="date,production_t\n2026-07-01,120\n",
            trigger=False,
        )
        status, replaced = _machine_request(
            port, replacement, request_id="lifecycle-request-3"
        )
        assert status == 201
        assert replaced["draft_id"] != draft_id
        assert runtime.store.get_draft(draft_id)["status"] == "discarded"
        assert runtime.machine_sync_state(draft_id)["state"] == "paused"
        assert runtime.machine_sync_state(replaced["draft_id"])["state"] == (
            "active"
        )
    finally:
        _close(server, thread)


def test_v5_connector_upgrade_recovers_machine_baseline_and_idempotency(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agent.db"
    server, thread, runtime = _server(database)
    port = int(server.server_address[1])
    first = _payload(
        event_id="evt-migration-1",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    status, created = _machine_request(
        port, first, request_id="migration-request-1"
    )
    assert status == 201
    draft_id = created["draft_id"]
    draft = runtime.store.get_draft(draft_id)
    edited = json.loads(json.dumps(draft["payload"]))
    edited["days"][0]["reported_quantity"]["daily_total"]["production_t"][
        "value"
    ] = 105
    runtime.save_draft(
        draft_id,
        expected_revision=draft["revision"],
        payload=edited,
        actor="human-before-upgrade",
    )
    _close(server, thread)

    with sqlite3.connect(database) as db:
        db.executescript(
            """
            DROP INDEX IF EXISTS idx_connector_ingestions_draft;
            DROP INDEX IF EXISTS idx_connector_binding_month;
            ALTER TABLE connector_ingestions RENAME TO connector_ingestions_v6;
            ALTER TABLE connector_draft_bindings
                RENAME TO connector_draft_bindings_v6;
            CREATE TABLE connector_draft_bindings (
                client_id TEXT NOT NULL,
                draft_key TEXT NOT NULL,
                draft_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                PRIMARY KEY(client_id,draft_key)
            );
            INSERT INTO connector_draft_bindings
                SELECT client_id,draft_key,draft_id,created_at
                FROM connector_draft_bindings_v6;
            CREATE TABLE connector_ingestions AS
                SELECT ingestion_id,client_id,event_id,request_sha256,draft_key,
                    draft_id,source_id,source_revision,source_name,source_system,
                    source_format,original_filename,truth_statement,
                    trigger_workflow,workflow_name,status,import_summary_json,
                    draft_revision,draft_payload_sha256,workflow_result_json,
                    result_json,lease_owner,lease_expires_at,created_at,
                    updated_at,completed_at
                FROM connector_ingestions_v6;
            DROP TABLE connector_ingestions_v6;
            DROP TABLE connector_draft_bindings_v6;
            UPDATE app_schema_versions SET version=5
                WHERE component='enterprise_agent';
            """
        )

    server, thread, runtime = _server(database)
    port = int(server.server_address[1])
    try:
        status, replay = _machine_request(
            port, first, request_id="migration-request-replay"
        )
        assert status == 200
        assert replay["idempotent_replay"] is True
        assert runtime.machine_sync_state(draft_id)["reason_code"] == (
            "human_changes_detected"
        )

        update = _payload(
            event_id="evt-migration-2",
            source_id="source-a",
            revision=2,
            csv_text="date,production_t\n2026-07-01,110\n",
            trigger=False,
        )
        status, error = _machine_request(
            port, update, request_id="migration-request-2"
        )
        assert status == 409
        assert "人工编辑" in error["error"]["message"]

        paused = runtime.store.get_draft(draft_id)
        runtime.resume_machine_sync(
            draft_id,
            expected_revision=paused["revision"],
            accepted=True,
            actor="migration-reviewer",
        )
        update["event_id"] = "evt-migration-3"
        status, result = _machine_request(
            port, update, request_id="migration-request-3"
        )
        assert status == 201
        assert result["draft_id"] == draft_id
    finally:
        _close(server, thread)


def test_machine_input_fails_closed_for_ambiguous_or_malformed_json(
    tmp_path: Path,
) -> None:
    server, thread, _runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    valid = _payload(
        event_id="evt-robustness",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    try:
        raw = json.dumps(valid, ensure_ascii=False).encode()
        status, error = _raw_machine_request(
            port,
            raw,
            request_id="robust-signature",
            signature_override="é" * 64,
        )
        assert status == 401
        assert error["error"]["code"] == "connector_authentication_failed"

        with_surrogate = json.loads(json.dumps(valid))
        with_surrogate["event_id"] = "evt-surrogate"
        with_surrogate["source"]["content"] = "\ud800"
        raw = json.dumps(with_surrogate, ensure_ascii=True).encode()
        status, error = _raw_machine_request(
            port, raw, request_id="robust-surrogate"
        )
        assert status == 400
        assert "UTF-8" in error["error"]["message"]

        revision_zero = json.loads(json.dumps(valid))
        revision_zero["event_id"] = "evt-revision-zero"
        revision_zero["source"]["revision"] = 0
        status, error = _raw_machine_request(
            port,
            json.dumps(revision_zero).encode(),
            request_id="robust-revision-zero",
        )
        assert status == 400
        assert "正整数" in error["error"]["message"]

        encoded = json.dumps(valid, separators=(",", ":"))
        duplicate = encoded.replace(
            "{",
            '{"event_id":"duplicate-shadow",',
            1,
        ).encode()
        status, error = _raw_machine_request(
            port, duplicate, request_id="robust-duplicate"
        )
        assert status == 400
        assert "重复字段" in error["error"]["message"]
        status, error = _raw_machine_request(
            port, duplicate, request_id="robust-duplicate"
        )
        assert status == 409
        assert error["error"]["code"] == "conflict"

        status, _error = _raw_machine_request(
            port,
            json.dumps(valid).encode(),
            request_id="robust-query",
            path="/api/v1/machine/autofill?unexpected=1",
        )
        assert status == 400
        status, _error = _raw_machine_request(
            port,
            json.dumps(valid).encode(),
            request_id="robust-trailing",
            path="/api/v1/machine/autofill/",
        )
        assert status == 400

        gap = _payload(
            event_id="evt-date-gap",
            source_id="source-a",
            revision=1,
            csv_text=(
                "date,production_t\n"
                "2026-07-01,100\n"
                "2026-07-03,100\n"
            ),
            trigger=True,
        )
        status, error = _machine_request(
            port, gap, request_id="robust-date-gap"
        )
        assert status == 400
        assert "无间断" in error["error"]["message"]
    finally:
        _close(server, thread)


def test_event_replay_survives_process_restart(tmp_path: Path) -> None:
    database = tmp_path / "agent.db"
    body = _payload(
        event_id="evt-restart-replay",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    server, thread, _runtime = _server(database)
    port = int(server.server_address[1])
    status, created = _machine_request(
        port, body, request_id="restart-attempt-1"
    )
    assert status == 201
    _close(server, thread)

    server, thread, runtime = _server(database)
    port = int(server.server_address[1])
    try:
        status, replay = _machine_request(
            port, body, request_id="restart-attempt-2"
        )
        assert status == 200
        assert replay["idempotent_replay"] is True
        assert replay["draft_id"] == created["draft_id"]
        assert len(runtime.store.list_drafts()) == 1
    finally:
        _close(server, thread)


def test_multisource_discard_replacement_supports_same_content_and_aba(
    tmp_path: Path,
) -> None:
    server, thread, runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    source_a_v1 = _payload(
        event_id="evt-multi-a1",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    source_b_old_csv = "date,electricity_kwh\n2026-07-01,200\n"
    source_b_new_csv = "date,electricity_kwh\n2026-07-01,220\n"
    try:
        status, first = _machine_request(
            port, source_a_v1, request_id="multi-request-a1"
        )
        assert status == 201
        original_draft_id = first["draft_id"]
        source_b_v1 = _payload(
            event_id="evt-multi-b1",
            source_id="source-b",
            revision=1,
            csv_text=source_b_old_csv,
            trigger=False,
        )
        status, merged = _machine_request(
            port, source_b_v1, request_id="multi-request-b1"
        )
        assert status == 201
        assert merged["draft_id"] == original_draft_id
        draft = runtime.store.get_draft(original_draft_id)
        runtime.discard_draft(
            original_draft_id,
            expected_revision=draft["revision"],
            actor="multi-reviewer",
            reason="测试多源替代草稿",
        )

        source_a_v2 = _payload(
            event_id="evt-multi-a2",
            source_id="source-a",
            revision=2,
            csv_text="date,production_t\n2026-07-01,110\n",
            trigger=False,
        )
        status, replacement = _machine_request(
            port, source_a_v2, request_id="multi-request-a2"
        )
        assert status == 201
        replacement_id = replacement["draft_id"]
        assert replacement_id != original_draft_id

        source_b_v2_same = _payload(
            event_id="evt-multi-b2",
            source_id="source-b",
            revision=2,
            csv_text=source_b_old_csv,
            trigger=False,
        )
        status, same_content = _machine_request(
            port, source_b_v2_same, request_id="multi-request-b2"
        )
        assert status == 201
        assert same_content["draft_id"] == replacement_id

        source_b_v3_new = _payload(
            event_id="evt-multi-b3",
            source_id="source-b",
            revision=3,
            csv_text=source_b_new_csv,
            trigger=False,
        )
        status, _ = _machine_request(
            port, source_b_v3_new, request_id="multi-request-b3"
        )
        assert status == 201
        source_b_v4_aba = _payload(
            event_id="evt-multi-b4",
            source_id="source-b",
            revision=4,
            csv_text=source_b_old_csv,
            trigger=False,
        )
        status, aba = _machine_request(
            port, source_b_v4_aba, request_id="multi-request-b4"
        )
        assert status == 201
        assert aba["draft_id"] == replacement_id

        final_draft = runtime.store.get_draft(replacement_id)
        day = final_draft["payload"]["days"][0]["reported_quantity"][
            "daily_total"
        ]
        assert day["production_t"]["value"] == 110
        assert day["electricity_kwh"]["value"] == 200
        assert len(final_draft["payload"]["sources"]) == 2
        with runtime.store.repository._read() as db:
            contributions = db.execute(
                """
                SELECT source_id,source_revision,draft_id
                FROM fq_machine_source_contributions
                ORDER BY source_id
                """
            ).fetchall()
            artifacts = db.execute(
                "SELECT source_id,COUNT(*) AS count "
                "FROM fq_machine_source_artifacts GROUP BY source_id"
            ).fetchall()
        assert [row["draft_id"] for row in contributions] == [
            replacement_id,
            replacement_id,
        ]
        assert [int(row["source_revision"]) for row in contributions] == [2, 4]
        assert {row["source_id"]: int(row["count"]) for row in artifacts} == {
            "source-a": 2,
            "source-b": 2,
        }
    finally:
        _close(server, thread)


def test_concurrent_events_create_one_month_draft_without_duplicate_rows(
    tmp_path: Path,
) -> None:
    server, thread, runtime = _server(tmp_path / "agent.db")
    port = int(server.server_address[1])
    source_a = _payload(
        event_id="evt-concurrent-a",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    source_b = _payload(
        event_id="evt-concurrent-b",
        source_id="source-b",
        revision=1,
        csv_text="date,electricity_kwh\n2026-07-01,200\n",
        trigger=False,
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    _machine_request,
                    port,
                    payload,
                    request_id=f"concurrent-request-{index}",
                )
                for index, payload in enumerate((source_a, source_b), start=1)
            ]
            results = [future.result(timeout=10) for future in futures]
        assert [status for status, _ in results] == [201, 201]
        assert len({result["draft_id"] for _, result in results}) == 1
        assert len(runtime.store.list_drafts()) == 1
        with runtime.store.repository._read() as db:
            assert db.execute(
                "SELECT COUNT(*) FROM connector_ingestions"
            ).fetchone()[0] == 2
            assert db.execute(
                "SELECT COUNT(*) FROM connector_draft_bindings"
            ).fetchone()[0] == 1
            assert db.execute(
                "SELECT COUNT(*) FROM fq_machine_source_contributions"
            ).fetchone()[0] == 2
    finally:
        _close(server, thread)


def test_source_health_is_bound_monotonic_dynamic_and_blocks_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server, thread, runtime = _server(
        tmp_path / "agent.db",
        clients=(_client(required_sources=("source-a",)),),
    )
    port = int(server.server_address[1])
    snapshot = _payload(
        event_id="evt-health-snapshot",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=True,
    )
    try:
        status, created = _machine_request(
            port, snapshot, request_id="health-snapshot-request"
        )
        assert status == 202
        draft_id = created["draft_id"]
        draft_before = runtime.store.get_draft(draft_id)
        snapshot_hash = hashlib.sha256(
            snapshot["source"]["content"].encode()
        ).hexdigest()

        base_time = datetime.now(UTC) + timedelta(seconds=1)
        failed = _health_payload(
            event_id="health-error-1",
            autofill_payload=snapshot,
            outcome="error",
            completed_at=base_time,
        )
        status, result = _health_request(
            port, failed, request_id="health-error-request-1"
        )
        assert status == 201
        assert result["applied"] is True
        status, evidence = _get(port, f"/api/v2/drafts/{draft_id}/ingestions")
        assert status == 200
        assert evidence["freshness"]["overall_state"] == "stale"
        source_health = next(
            item
            for item in evidence["source_health"]
            if item["source_id"] == "source-a"
        )
        assert source_health["freshness_state"] == "error"
        assert source_health["error_code"] == "source_poll_failed"
        assert evidence["latest_preflight"]["status"] == "attention_required"

        status, replay = _health_request(
            port, failed, request_id="health-error-request-replay"
        )
        assert status == 200
        assert replay["idempotent_replay"] is True

        older_success = _health_payload(
            event_id="health-old-success",
            autofill_payload=snapshot,
            outcome="success_nonempty",
            completed_at=base_time - timedelta(milliseconds=100),
            snapshot_sha256=snapshot_hash,
            autofill_event_id=snapshot["event_id"],
            source_revision=1,
        )
        status, result = _health_request(
            port, older_success, request_id="health-old-request"
        )
        assert status == 201
        assert result["applied"] is False

        mismatched = _health_payload(
            event_id="health-mismatch",
            autofill_payload=snapshot,
            outcome="success_nonempty",
            completed_at=base_time + timedelta(seconds=1),
            snapshot_sha256="0" * 64,
            autofill_event_id="evt-not-current",
            source_revision=2,
        )
        status, result = _health_request(
            port, mismatched, request_id="health-mismatch-request"
        )
        assert status == 201
        assert result["applied"] is True
        _status, evidence = _get(
            port, f"/api/v2/drafts/{draft_id}/ingestions"
        )
        source_health = next(
            item
            for item in evidence["source_health"]
            if item["source_id"] == "source-a"
        )
        assert source_health["freshness_state"] == "waiting"

        # Simulate a race where the optimistic precheck saw a fresh state.
        # The BEGIN IMMEDIATE transaction must independently re-evaluate it.
        original_health_check = runtime.machine_source_health
        monkeypatch.setattr(
            runtime,
            "machine_source_health",
            lambda _draft_id: {
                "source_health": [],
                "freshness": {
                    "overall_state": "fresh",
                    "stale_required_source_ids": [],
                },
            },
        )
        with pytest.raises(ValidationBlockedError, match="新鲜度"):
            runtime.confirm_draft(
                draft_id,
                expected_revision=draft_before["revision"],
                actor_id="health-reviewer",
                confirmer_name="健康测试复核人",
                confirmer_role="经办人",
                attestation="已核对",
                accepted=True,
            )
        monkeypatch.setattr(
            runtime, "machine_source_health", original_health_check
        )
        assert runtime.store.get_draft(draft_id)["status"] == "ready_review"
        with runtime.store.repository._read() as db:
            assert db.execute(
                "SELECT COUNT(*) FROM fq_outbox WHERE aggregate_id=?",
                (draft_id,),
            ).fetchone()[0] == 0

        restored_time = base_time + timedelta(seconds=2)
        restored = _health_payload(
            event_id="health-restored",
            autofill_payload=snapshot,
            outcome="success_nonempty",
            completed_at=restored_time,
            snapshot_sha256=snapshot_hash,
            autofill_event_id=snapshot["event_id"],
            source_revision=1,
        )
        status, _ = _health_request(
            port, restored, request_id="health-restored-request"
        )
        assert status == 201
        _status, evidence = _get(
            port, f"/api/v2/drafts/{draft_id}/ingestions"
        )
        assert evidence["freshness"]["overall_state"] == "fresh"
        source_health = next(
            item
            for item in evidence["source_health"]
            if item["source_id"] == "source-a"
        )
        assert source_health["freshness_state"] == "fresh"

        policy_dicts = tuple(
            policy.public_policy()
            for policy in server.connector_clients[0].allowed_sources
        )
        boundary = runtime.store.repository.connector_source_health_for_draft(
            draft_id,
            policies=policy_dicts,
            now_epoch=restored_time.timestamp() + 3600,
        )
        source_a = next(
            item
            for item in boundary["source_health"]
            if item["source_id"] == "source-a"
        )
        assert source_a["freshness_state"] == "stale"
        assert boundary["freshness"]["overall_state"] == "stale"
        assert runtime.store.get_draft(draft_id)["revision"] == (
            draft_before["revision"]
        )

        unsafe_error = dict(failed)
        unsafe_error["event_id"] = "health-unsafe-error"
        unsafe_error["completed_at"] = (
            base_time + timedelta(seconds=3)
        ).isoformat()
        unsafe_error["error_code"] = "upstream password=secret"
        status, error = _health_request(
            port, unsafe_error, request_id="health-unsafe-request"
        )
        assert status == 400
        assert "ASCII" in error["error"]["message"]

        raw = json.dumps(restored, separators=(",", ":")).encode()
        status, error = _raw_machine_request(
            port,
            raw,
            request_id="health-wrong-signing-path",
            path="/api/v1/machine/source-health",
        )
        assert status == 401
        assert error["error"]["code"] == "connector_authentication_failed"
    finally:
        _close(server, thread)


def test_delayed_older_autofill_does_not_clear_newer_source_error(
    tmp_path: Path,
) -> None:
    server, thread, runtime = _server(
        tmp_path / "agent.db",
        clients=(_client(required_sources=("source-a",)),),
    )
    port = int(server.server_address[1])
    now = datetime.now(UTC)
    first = _payload(
        event_id="evt-order-first",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        observed_at=now - timedelta(seconds=30),
    )
    delayed = _payload(
        event_id="evt-order-delayed",
        source_id="source-a",
        revision=2,
        csv_text="date,production_t\n2026-07-01,101\n",
        observed_at=now - timedelta(seconds=20),
    )
    try:
        status, created = _machine_request(
            port, first, request_id="order-first-request"
        )
        assert status == 202
        draft_id = created["draft_id"]
        source_error = _health_payload(
            event_id="health-newer-error",
            autofill_payload=first,
            outcome="error",
            completed_at=now - timedelta(seconds=10),
        )
        status, _result = _health_request(
            port, source_error, request_id="health-newer-error-request"
        )
        assert status == 201

        status, updated = _machine_request(
            port, delayed, request_id="order-delayed-request"
        )
        assert status == 202
        assert updated["draft_id"] == draft_id
        _status, evidence = _get(
            port, f"/api/v2/drafts/{draft_id}/ingestions"
        )
        source_health = next(
            item
            for item in evidence["source_health"]
            if item["source_id"] == "source-a"
        )
        assert source_health["outcome"] == "error"
        assert source_health["freshness_state"] == "error"
        assert source_health["error_code"] == "source_poll_failed"
        with pytest.raises(ValidationBlockedError, match="新鲜度"):
            runtime.confirm_draft(
                draft_id,
                expected_revision=runtime.store.get_draft(draft_id)["revision"],
                actor_id="order-reviewer",
                confirmer_name="乱序测试复核人",
                confirmer_role="经办人",
                attestation="已核对",
                accepted=True,
            )
    finally:
        _close(server, thread)


def test_machine_draft_fails_closed_when_active_source_policy_is_missing(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agent.db"
    server, thread, _runtime = _server(
        database,
        clients=(_client(required_sources=("source-a",)),),
    )
    port = int(server.server_address[1])
    snapshot = _payload(
        event_id="evt-policy-present",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
    )
    try:
        status, created = _machine_request(
            port, snapshot, request_id="policy-present-request"
        )
        assert status == 202
        draft_id = created["draft_id"]
    finally:
        _close(server, thread)

    repository = Repository(database)
    restarted = FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=tmp_path / "restarted-quarantine",
    )
    health = restarted.machine_source_health(draft_id)
    assert health["freshness"]["overall_state"] == "stale"
    assert health["freshness"]["stale_required_source_ids"] == ["source-a"]
    assert health["source_health"][0]["freshness_state"] == "unknown"
    draft = restarted.store.get_draft(draft_id)
    with pytest.raises(ValidationBlockedError, match="新鲜度"):
        restarted.confirm_draft(
            draft_id,
            expected_revision=draft["revision"],
            actor_id="restart-reviewer",
            confirmer_name="重启测试复核人",
            confirmer_role="经办人",
            attestation="已核对",
            accepted=True,
        )
    with repository._read() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM fq_outbox WHERE aggregate_id=?",
            (draft_id,),
        ).fetchone()[0] == 0


def test_multisource_draft_blocks_when_restart_policy_omits_one_source(
    tmp_path: Path,
) -> None:
    database = tmp_path / "agent.db"
    server, thread, _runtime = _server(
        database,
        clients=(
            _client(required_sources=("source-a", "source-b")),
        ),
    )
    port = int(server.server_address[1])
    source_a = _payload(
        event_id="evt-policy-a",
        source_id="source-a",
        revision=1,
        csv_text="date,production_t\n2026-07-01,100\n",
        trigger=False,
    )
    source_b = _payload(
        event_id="evt-policy-b",
        source_id="source-b",
        revision=1,
        csv_text="date,electricity_kwh\n2026-07-01,200\n",
        trigger=False,
    )
    try:
        status, first = _machine_request(
            port, source_a, request_id="policy-a-request"
        )
        assert status == 201
        status, second = _machine_request(
            port, source_b, request_id="policy-b-request"
        )
        assert status == 201
        assert second["draft_id"] == first["draft_id"]
        draft_id = first["draft_id"]
    finally:
        _close(server, thread)

    repository = Repository(database)
    restarted = FiveQuantityRuntime(
        repository,
        identity=_identity(),
        quarantine_directory=tmp_path / "partial-policy-quarantine",
    )
    restarted.configure_machine_source_policies(
        (
            ConnectorSourcePolicy(
                source_id="source-a",
                source_system="test-source-a",
                required=True,
            ).public_policy(),
        )
    )
    health = restarted.machine_source_health(draft_id)
    by_source = {
        item["source_id"]: item for item in health["source_health"]
    }
    assert by_source["source-a"]["freshness_state"] == "fresh"
    assert by_source["source-b"]["required"] is True
    assert by_source["source-b"]["freshness_state"] == "unknown"
    assert by_source["source-b"]["error_code"] == "policy_missing"
    assert health["freshness"] == {
        "overall_state": "stale",
        "stale_required_source_ids": ["source-b"],
    }

    draft = restarted.store.get_draft(draft_id)
    with pytest.raises(ValidationBlockedError, match="source-b"):
        restarted.confirm_draft(
            draft_id,
            expected_revision=draft["revision"],
            actor_id="partial-policy-reviewer",
            confirmer_name="漏配来源测试复核人",
            confirmer_role="经办人",
            attestation="已核对",
            accepted=True,
        )
    with repository._read() as db:
        assert db.execute(
            "SELECT COUNT(*) FROM fq_outbox WHERE aggregate_id=?",
            (draft_id,),
        ).fetchone()[0] == 0
