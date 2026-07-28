"""Real-HTTP integration coverage for the enterprise submission boundary."""

from __future__ import annotations

import base64
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import http.client
import json
from pathlib import Path
import threading
from typing import Any

from mineguard.api import MineGuardHTTPServer, create_server
from mineguard.external_submission import (
    SIGNATURE_HEADER,
    AuthorizedConfirmer,
    ExternalClient,
    VerifiedEventSnapshot,
    enterprise_submission_payload_sha256,
    sign_transport_headers,
    validate_enterprise_submission_json,
)
from mineguard.governance import (
    AnalysisProfile,
    GovernedObservation,
    SourceDefinition,
    compute_observation_signature,
)
from mineguard.models import BalanceParameters, MetricCode


CONTRACT_EXAMPLE = (
    Path(__file__).resolve().parents[2]
    / "contracts"
    / "examples"
    / "enterprise-submission-v1.json"
)
CLIENT = ExternalClient(
    client_id="enterprise-client-integration",
    enterprise_id="enterprise-001",
    secret=b"integration-transport-secret-32-bytes-minimum",
    mine_ids=frozenset({"mine-001"}),
    authorized_confirmers=(
        AuthorizedConfirmer(
            confirmer_id="employee-0088",
            confirmer_name="示例确认人",
            confirmer_roles=frozenset({"企业报送负责人"}),
        ),
    ),
    verified_event_snapshots=(
        VerifiedEventSnapshot(
            mine_id="mine-001",
            window_start=datetime(
                2026, 7, 27, 0, 0, tzinfo=UTC
            ),
            window_end=datetime(
                2026, 7, 27, 8, 0, tzinfo=UTC
            ),
            event_codes=(),
            evidence_sha256="e" * 64,
        ),
    ),
)
SOURCE_SECRET = b"integration-source-secret-32-bytes-minimum"
WINDOW_START = datetime(2026, 7, 27, 0, 0, tzinfo=UTC)
WINDOW_END = datetime(2026, 7, 27, 8, 0, tzinfo=UTC)
OBSERVED_AT = datetime(2026, 7, 27, 7, 59, tzinfo=UTC)
RECEIVED_AT = datetime(2026, 7, 27, 7, 59, 5, tzinfo=UTC)

SOURCE_VALUES = {
    MetricCode.REPORTED_PRODUCTION: (
        "mine-001-reported-production",
        1000.0,
    ),
    MetricCode.MAIN_TRANSPORT: (
        "mine-001-main-transport",
        1000.0,
    ),
    MetricCode.WASH_FEED: ("mine-001-wash-feed", 800.0),
    MetricCode.RAW_SALES: ("mine-001-raw-sales", 100.0),
    MetricCode.RAW_INVENTORY_CHANGE: (
        "mine-001-raw-inventory-change",
        100.0,
    ),
}


@contextmanager
def _running_server(
    tmp_path: Path,
) -> Iterator[MineGuardHTTPServer]:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        job_database_path=tmp_path / "jobs.db",
        evidence_database_path=tmp_path / "evidence.db",
        evidence_directory=tmp_path / "evidence",
        governance_database_path=tmp_path / "governance.db",
        source_key_directory=tmp_path / "source-keys",
        external_clients={CLIENT.client_id: CLIENT},
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server  # type: ignore[misc]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(
    server: MineGuardHTTPServer,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any], dict[str, str]]:
    host, port = server.server_address[:2]
    connection = http.client.HTTPConnection(str(host), int(port), timeout=10)
    request_headers = dict(headers or {})
    if body is not None:
        request_headers.setdefault("Content-Type", "application/json")
    try:
        connection.request(
            method,
            path,
            body=body,
            headers=request_headers,
        )
        response = connection.getresponse()
        raw = response.read()
        response_headers = {
            name.lower(): value
            for name, value in response.getheaders()
        }
        return (
            response.status,
            json.loads(raw) if raw else {},
            response_headers,
        )
    finally:
        connection.close()


def _nonce(index: int) -> str:
    raw = bytes((index + offset) % 256 for offset in range(16))
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _register_governance(server: MineGuardHTTPServer) -> None:
    profile = AnalysisProfile(
        profile_id="coal-balance-default",
        version="2026.07",
        effective_from=datetime(2026, 1, 1, tzinfo=UTC),
        effective_to=datetime(2027, 1, 1, tzinfo=UTC),
        parameters=BalanceParameters(
            transport_balance_tolerance=25.0,
            stock_balance_tolerance=30.0,
            transport_slack_penalty=80.0,
            stock_slack_penalty=90.0,
            max_mcs=4,
            max_relaxed_groups=2,
            quality_gate=60.0,
        ),
        required_metrics=list(MetricCode),
        approved=True,
    )
    assert server.governance_repository.register_profile(profile) is True

    for index, (metric, source_value) in enumerate(
        SOURCE_VALUES.items(),
        start=1,
    ):
        source_id, _ = source_value
        definition = SourceDefinition(
            source_id=source_id,
            mine_id="mine-001",
            metric_code=metric,
            root_source_group=f"root-{index}",
            unit="t",
            tolerance_abs=10.0,
            tolerance_rel=0.0,
            resolution=0.1,
            reliability=0.95,
            dependency_domains=[f"domain-{index}"],
            max_delay_seconds=60.0,
            device_health_score=1.0,
            clock_quality_score=1.0,
            calibration_valid_until=datetime(
                2026,
                12,
                31,
                tzinfo=UTC,
            ),
        )
        assert (
            server.governance_repository.register_source(definition)
            is True
        )
        assert server.source_key_store.put(source_id, SOURCE_SECRET) is True


def _provenance(
    *,
    source_id: str,
    observation_id: str,
    field_name: str,
    evidence_sha256: str,
) -> list[dict[str, Any]]:
    cryptographic = field_name in {"payload_sha256", "signature"}
    return [
        {
            "origin_type": (
                "cryptographic_derivation"
                if cryptographic
                else "sensor"
            ),
            "source_system": "integration-trusted-gateway",
            "source_record_id": f"{source_id}:{observation_id}",
            "source_location": f"observation/{field_name}",
            "captured_at": "2026-07-27T08:00:10Z",
            "acquisition_method": (
                "signature_process"
                if cryptographic
                else "device_gateway"
            ),
            "evidence_sha256": evidence_sha256,
        }
    ]


def _submission_document() -> dict[str, Any]:
    document = json.loads(CONTRACT_EXAMPLE.read_text(encoding="utf-8"))
    document["submitted_at"] = (
        datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    template_provenance = document["payload"]["observations"][0][
        "field_provenance"
    ]
    observations: list[dict[str, Any]] = []
    for sequence_no, (source_id, value) in enumerate(
        SOURCE_VALUES.values(),
        start=1,
    ):
        observation_id = f"{source_id}-20260727-0001"
        governed = GovernedObservation.signed(
            secret=SOURCE_SECRET,
            source_id=source_id,
            observation_id=observation_id,
            value=value,
            unit="t",
            observed_at=OBSERVED_AT,
            received_at=RECEIVED_AT,
            interval_start=None,
            interval_end=None,
            reset_before=False,
            sequence_no=sequence_no,
            revision=0,
        )
        wire = governed.model_dump(mode="json")
        field_provenance: dict[str, Any] = {}
        for field_name in template_provenance:
            evidence_sha256 = (
                governed.payload_sha256
                if field_name == "payload_sha256"
                else (
                    hashlib.sha256(
                        governed.signature.encode("ascii")
                    ).hexdigest()
                    if field_name == "signature"
                    else hashlib.sha256(
                        (
                            f"{source_id}:{observation_id}:"
                            f"{field_name}"
                        ).encode("utf-8")
                    ).hexdigest()
                )
            )
            field_provenance[field_name] = _provenance(
                source_id=source_id,
                observation_id=observation_id,
                field_name=field_name,
                evidence_sha256=evidence_sha256,
            )
        wire["field_provenance"] = field_provenance
        observations.append(wire)

    document["payload"]["observations"] = observations
    document["payload_sha256"] = enterprise_submission_payload_sha256(
        document["payload"]
    )
    return document


def _body(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _signed_headers(
    body: bytes,
    *,
    method: str,
    path: str,
    nonce_index: int,
) -> dict[str, str]:
    return sign_transport_headers(
        CLIENT,
        body,
        method=method,
        path=path,
        timestamp=datetime.now(UTC),
        nonce=_nonce(nonce_index),
    )


def test_enterprise_submission_http_lifecycle_and_integrity(
    tmp_path: Path,
) -> None:
    with _running_server(tmp_path) as server:
        # Capability discovery is deliberately public: no cookie, bearer
        # token, client id, or HMAC headers are sent.
        status, capabilities, _ = _request(
            server,
            "GET",
            "/v1/enterprise-submission-capabilities",
        )
        assert status == 200
        assert capabilities["contract_version"] == (
            "enterprise-submission-capabilities-v1"
        )
        assert capabilities["authentication"]["signature_version"] == (
            "hmac-sha256-v1"
        )

        _register_governance(server)
        document = _submission_document()
        body = _body(document)
        post_path = "/v1/enterprise-submissions"

        first_headers = _signed_headers(
            body,
            method="POST",
            path=post_path,
            nonce_index=1,
        )
        status, receipt, response_headers = _request(
            server,
            "POST",
            post_path,
            body=body,
            headers=first_headers,
        )
        assert status == 202
        assert receipt["status"] == "accepted"
        assert receipt["regulatory_outcome"] == (
            "not_determined_at_intake"
        )
        assert receipt["payload_sha256"] == document["payload_sha256"]
        assert response_headers["location"] == receipt["links"]["self"]

        # Successful ingestion proves that every registered source payload
        # digest and source-specific HMAC was accepted. Verify the persisted
        # envelopes independently as well.
        for sequence_no, (source_id, _) in enumerate(
            SOURCE_VALUES.values(),
            start=1,
        ):
            revisions = (
                server.governance_repository.list_observation_revisions(
                    source_id,
                    sequence_no,
                )
            )
            assert len(revisions) == 1
            assert revisions[0].signature == compute_observation_signature(
                revisions[0],
                SOURCE_SECRET,
            )

        retry_headers = _signed_headers(
            body,
            method="POST",
            path=post_path,
            nonce_index=2,
        )
        status, duplicate, _ = _request(
            server,
            "POST",
            post_path,
            body=body,
            headers=retry_headers,
        )
        assert status == 200
        assert duplicate["status"] == "duplicate"
        assert duplicate["receipt_id"] == receipt["receipt_id"]

        # Reusing the already consumed retry nonce is rejected before the
        # idempotency layer.
        status, replay_error, _ = _request(
            server,
            "POST",
            post_path,
            body=body,
            headers=retry_headers,
        )
        assert status == 401
        assert replay_error["code"] == "AUTHENTICATION_FAILED"

        conflict_document = deepcopy(document)
        conflict_document["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c202"
        )
        conflict_body = _body(conflict_document)
        conflict_headers = _signed_headers(
            conflict_body,
            method="POST",
            path=post_path,
            nonce_index=3,
        )
        status, conflict_error, _ = _request(
            server,
            "POST",
            post_path,
            body=conflict_body,
            headers=conflict_headers,
        )
        assert status == 409
        assert conflict_error["code"] == "IDEMPOTENCY_CONFLICT"

        invalid_headers = _signed_headers(
            body,
            method="POST",
            path=post_path,
            nonce_index=4,
        )
        invalid_headers[SIGNATURE_HEADER] = "0" * 64
        status, signature_error, _ = _request(
            server,
            "POST",
            post_path,
            body=body,
            headers=invalid_headers,
        )
        assert status == 401
        assert signature_error["code"] == "AUTHENTICATION_FAILED"

        receipt_path = receipt["links"]["self"]
        get_headers = _signed_headers(
            b"",
            method="GET",
            path=receipt_path,
            nonce_index=5,
        )
        status, fetched_receipt, _ = _request(
            server,
            "GET",
            receipt_path,
            headers=get_headers,
        )
        assert status == 200
        assert fetched_receipt == receipt

        stored = server.repository.get_external_submission_receipt(
            client_id=CLIENT.client_id,
            idempotency_key=document["idempotency_key"],
        )
        assert stored is not None
        assert stored["submission"] == document
        assert stored["body_sha256"] == hashlib.sha256(body).hexdigest()
        assert stored["payload_sha256"] == (
            enterprise_submission_payload_sha256(
                stored["submission"]["payload"]
            )
        )

        batch = server.repository.get_batch(receipt["intake_batch_id"])
        assert batch is not None
        assert batch["integrity_valid"] is True
        assert batch["context"]["external_submission"] == document
        assert batch["context"]["external_body_sha256"] == (
            hashlib.sha256(body).hexdigest()
        )
        confirmer_versions = (
            server.repository.list_external_confirmer_registrations(
                client_id=CLIENT.client_id,
                enterprise_id=CLIENT.enterprise_id,
                confirmer_id="employee-0088",
            )
        )
        assert len(confirmer_versions) == 1
        confirmer_registration = confirmer_versions[0]
        assert batch["context"][
            "external_confirmer_registration"
        ] == {
            "registration_id": confirmer_registration["registration_id"],
            "client_id": CLIENT.client_id,
            "enterprise_id": CLIENT.enterprise_id,
            "confirmer_id": "employee-0088",
            "version": 1,
            "content_sha256": confirmer_registration["content_sha256"],
        }

        # Two independently confirmed submissions with identical governed
        # measurements retain distinct immutable analysis contexts.
        second_document = deepcopy(document)
        second_document["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c203"
        )
        second_document["idempotency_key"] = (
            "enterprise-001-20260727-second"
        )
        second_document["submitted_at"] = (
            datetime.now(UTC).isoformat().replace("+00:00", "Z")
        )
        second_document["payload"]["human_confirmation"][
            "confirmation_evidence_sha256"
        ] = "9" * 64
        second_document["payload_sha256"] = (
            enterprise_submission_payload_sha256(
                second_document["payload"]
            )
        )
        second_body = _body(second_document)
        status, second_receipt, _ = _request(
            server,
            "POST",
            post_path,
            body=second_body,
            headers=_signed_headers(
                second_body,
                method="POST",
                path=post_path,
                nonce_index=6,
            ),
        )
        assert status == 202
        assert second_receipt["intake_batch_id"] != receipt["intake_batch_id"]
        second_batch = server.repository.get_batch(
            second_receipt["intake_batch_id"]
        )
        assert second_batch is not None
        assert second_batch["context"]["external_submission"] == (
            second_document
        )


def test_enterprise_submission_rejects_unregistered_confirmer(
    tmp_path: Path,
) -> None:
    with _running_server(tmp_path) as server:
        document = _submission_document()
        document["payload"]["human_confirmation"]["confirmer_id"] = (
            "unregistered-operator"
        )
        document["payload_sha256"] = enterprise_submission_payload_sha256(
            document["payload"]
        )
        body = _body(document)
        path = "/v1/enterprise-submissions"
        status, response, _ = _request(
            server,
            "POST",
            path,
            body=body,
            headers=_signed_headers(
                body,
                method="POST",
                path=path,
                nonce_index=33,
            ),
        )
        assert status == 403
        assert response["code"] == "CONFIRMER_NOT_AUTHORIZED"
        assert response["violations"][0]["json_pointer"] == (
            "/payload/human_confirmation/confirmer_id"
        )


def test_enterprise_submission_uses_current_db_confirmer_version(
    tmp_path: Path,
) -> None:
    """A DB deactivation wins over the legacy environment migration."""

    with _running_server(tmp_path) as server:
        _register_governance(server)
        assert CLIENT.allows_confirmation(
            # This is deliberately only a legacy/configuration assertion.
            validate_enterprise_submission_json(
                _body(_submission_document())
            ).payload.human_confirmation
        )
        accepted = _submission_document()
        accepted["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c205"
        )
        accepted["idempotency_key"] = (
            "enterprise-001-before-confirmer-disabled"
        )
        accepted["payload_sha256"] = enterprise_submission_payload_sha256(
            accepted["payload"]
        )
        accepted_body = _body(accepted)
        path = "/v1/enterprise-submissions"
        status, first_receipt, _ = _request(
            server,
            "POST",
            path,
            body=accepted_body,
            headers=_signed_headers(
                accepted_body,
                method="POST",
                path=path,
                nonce_index=74,
            ),
        )
        assert status == 202

        server.repository.save_external_confirmer_registration(
            {
                "registration_id": "confirmer-employee-0088-v2-disabled",
                "client_id": CLIENT.client_id,
                "enterprise_id": CLIENT.enterprise_id,
                "confirmer_id": "employee-0088",
                "version": 2,
                "confirmer_name": "示例确认人",
                "confirmer_roles": ["企业报送负责人"],
                "confirmation_methods": ["authenticated_click"],
                "active": False,
                "source_system": "regulator-confirmer-ledger",
                "record_id": "confirmer-case:employee-0088:v2",
                "created_by": "integration-admin",
            }
        )

        # The exact accepted body remains an idempotent receipt lookup after
        # deactivation; its batch is still bound to registry version 1.
        status, duplicate, _ = _request(
            server,
            "POST",
            path,
            body=accepted_body,
            headers=_signed_headers(
                accepted_body,
                method="POST",
                path=path,
                nonce_index=75,
            ),
        )
        assert status == 200
        assert duplicate["status"] == "duplicate"
        assert duplicate["receipt_id"] == first_receipt["receipt_id"]

        document = _submission_document()
        document["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c206"
        )
        document["idempotency_key"] = (
            "enterprise-001-disabled-confirmer"
        )
        document["payload_sha256"] = enterprise_submission_payload_sha256(
            document["payload"]
        )
        body = _body(document)
        status, response, _ = _request(
            server,
            "POST",
            path,
            body=body,
            headers=_signed_headers(
                body,
                method="POST",
                path=path,
                nonce_index=76,
            ),
        )
        assert status == 403
        assert response["code"] == "CONFIRMER_NOT_AUTHORIZED"


def test_enterprise_submission_rejects_false_identity_event_and_stale_time(
    tmp_path: Path,
) -> None:
    path = "/v1/enterprise-submissions"
    with _running_server(tmp_path) as server:
        false_identity = _submission_document()
        false_identity["payload"]["human_confirmation"][
            "confirmer_name"
        ] = "伪造姓名"
        false_identity["payload_sha256"] = (
            enterprise_submission_payload_sha256(
                false_identity["payload"]
            )
        )
        false_identity_body = _body(false_identity)
        status, response, _ = _request(
            server,
            "POST",
            path,
            body=false_identity_body,
            headers=_signed_headers(
                false_identity_body,
                method="POST",
                path=path,
                nonce_index=40,
            ),
        )
        assert status == 403
        assert response["code"] == "CONFIRMER_NOT_AUTHORIZED"

        unverified_event = _submission_document()
        unverified_event["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c204"
        )
        unverified_event["idempotency_key"] = (
            "enterprise-001-unverified-event"
        )
        unverified_event["payload"]["operational_context"][
            "approved_event_codes"
        ] = ["UNVERIFIED-WORK-PERMIT-999"]
        unverified_event["payload_sha256"] = (
            enterprise_submission_payload_sha256(
                unverified_event["payload"]
            )
        )
        event_body = _body(unverified_event)
        status, response, _ = _request(
            server,
            "POST",
            path,
            body=event_body,
            headers=_signed_headers(
                event_body,
                method="POST",
                path=path,
                nonce_index=41,
            ),
        )
        assert status == 422
        assert response["code"] == "EVENT_SNAPSHOT_NOT_VERIFIED"

        future_dated = _submission_document()
        future_dated["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c205"
        )
        future_dated["idempotency_key"] = (
            "enterprise-001-future-submission"
        )
        future_dated["submitted_at"] = (
            (datetime.now(UTC) + timedelta(days=1))
            .isoformat()
            .replace("+00:00", "Z")
        )
        future_body = _body(future_dated)
        status, response, _ = _request(
            server,
            "POST",
            path,
            body=future_body,
            headers=_signed_headers(
                future_body,
                method="POST",
                path=path,
                nonce_index=42,
            ),
        )
        assert status == 422
        assert response["code"] == "SUBMISSION_TIME_INVALID"

        # A legitimately confirmed filing can reach the regulator much later
        # (for example after an outage).  The signed transport time must be
        # fresh, but the immutable business timestamp must not be rewritten.
        _register_governance(server)
        delayed = _submission_document()
        delayed["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c206"
        )
        delayed["idempotency_key"] = (
            "enterprise-001-delayed-first-arrival"
        )
        delayed["submitted_at"] = "2026-07-27T08:05:00Z"
        delayed_body = _body(delayed)
        status, _, _ = _request(
            server,
            "POST",
            path,
            body=delayed_body,
            headers=_signed_headers(
                delayed_body,
                method="POST",
                path=path,
                nonce_index=43,
            ),
        )
        assert status == 202
        stored = server.repository.get_external_submission_receipt(
            client_id=CLIENT.client_id,
            idempotency_key=delayed["idempotency_key"],
        )
        assert stored is not None
        assert stored["submission"]["submitted_at"] == (
            "2026-07-27T08:05:00Z"
        )
        assert stored["body_sha256"] == hashlib.sha256(
            delayed_body
        ).hexdigest()


def test_enterprise_submission_accepts_nonempty_db_event_snapshot(
    tmp_path: Path,
) -> None:
    """The intake source of truth is the repository, not ExternalClient."""

    with _running_server(tmp_path) as server:
        _register_governance(server)
        event_codes = ["MAINTENANCE", "WORK-PERMIT"]
        snapshot = server.repository.save_external_event_snapshot(
            {
                "snapshot_id": "regulator-query-nonempty-001",
                "mine_id": "mine-001",
                "window_start": WINDOW_START,
                "window_end": WINDOW_END,
                "event_codes": list(reversed(event_codes)),
                "evidence_sha256": "e" * 64,
                "source_system": "regulator-event-ledger",
                "record_id": "query-result:nonempty-001",
                "created_by": "integration-admin",
            }
        )
        # CLIENT only contains an empty configured snapshot. This report can
        # therefore succeed only when intake consults the persisted registry.
        assert CLIENT.has_verified_event_snapshot(
            event_codes=event_codes,
            mine_id="mine-001",
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            evidence_sha256={"e" * 64},
        ) is False

        document = _submission_document()
        document["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c299"
        )
        document["idempotency_key"] = (
            "enterprise-001-nonempty-db-snapshot"
        )
        document["payload"]["operational_context"][
            "approved_event_codes"
        ] = event_codes
        document["payload_sha256"] = enterprise_submission_payload_sha256(
            document["payload"]
        )
        body = _body(document)
        path = "/v1/enterprise-submissions"
        status, receipt, _ = _request(
            server,
            "POST",
            path,
            body=body,
            headers=_signed_headers(
                body,
                method="POST",
                path=path,
                nonce_index=73,
            ),
        )
        assert status == 202
        batch = server.repository.get_batch(receipt["intake_batch_id"])
        assert batch is not None
        assert batch["context"]["external_event_snapshot"] == {
            "snapshot_id": snapshot["snapshot_id"],
            "content_sha256": snapshot["content_sha256"],
            "evidence_sha256": snapshot["evidence_sha256"],
        }


def test_enterprise_submission_rejects_wrong_event_evidence_digest(
    tmp_path: Path,
) -> None:
    with _running_server(tmp_path) as server:
        document = _submission_document()
        document["submission_id"] = (
            "018f7b4c-91d2-7a50-9bf6-3e589f13c298"
        )
        document["idempotency_key"] = (
            "enterprise-001-wrong-event-evidence"
        )
        provenance = document["payload"]["operational_context"][
            "field_provenance"
        ]["approved_event_codes"]
        for record in provenance:
            record["evidence_sha256"] = "f" * 64
        document["payload_sha256"] = enterprise_submission_payload_sha256(
            document["payload"]
        )
        body = _body(document)
        path = "/v1/enterprise-submissions"
        status, response, _ = _request(
            server,
            "POST",
            path,
            body=body,
            headers=_signed_headers(
                body,
                method="POST",
                path=path,
                nonce_index=74,
            ),
        )
        assert status == 422
        assert response["code"] == "EVENT_SNAPSHOT_NOT_VERIFIED"
