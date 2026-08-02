from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from io import StringIO
import json
from pathlib import Path
from threading import Thread
from typing import Any, Iterator, Mapping
from urllib.parse import urlencode

import pytest

from mineguard.auth import Role
from mineguard.exchange_v2 import ExchangeClient
from mineguard.regulatory_v2_http import create_server


MINE_A = "TRACE-MINE-A"
MINE_B = "TRACE-MINE-B"
ADMIN_PASSWORD = "admin-password-for-trace-tests"
VIEWER_PASSWORD = "viewer-password-for-trace-tests"
FIXED_NOW = datetime(2026, 8, 2, 12, tzinfo=UTC)
EVENT_TYPES_BY_GROUP = {
    "submission": "submission_received",
    "analysis": "analysis_completed",
    "finding": "finding_automatically_issued",
    "delivery": "analysis_report_delivery_acknowledged",
    "response": "enterprise_response_batch_recorded",
    "reanalysis": "finding_resolved_by_revision_reanalysis",
    "security": "inbox_idempotency_conflict_rejected",
}


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> dict[str, Any]:
        value = json.loads(self.body)
        assert isinstance(value, dict)
        return value


@dataclass
class TraceAPI:
    server: Any
    thread: Thread
    admin_cookie: str
    viewer_cookie: str

    def request(
        self,
        target: str,
        *,
        method: str = "GET",
        cookie: str | None = None,
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> HTTPResult:
        request_headers = dict(headers or {})
        if cookie:
            request_headers["Cookie"] = cookie
        connection = HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=10
        )
        try:
            connection.request(
                method,
                target,
                body=body,
                headers=request_headers,
            )
            response = connection.getresponse()
            payload = response.read()
            response_headers = {
                name.lower(): value for name, value in response.getheaders()
            }
            return HTTPResult(response.status, response_headers, payload)
        finally:
            connection.close()

    def get_json(
        self,
        target: str,
        *,
        cookie: str | None = None,
        expected_status: int = 200,
    ) -> dict[str, Any]:
        response = self.request(
            target,
            cookie=self.admin_cookie if cookie is None else cookie,
        )
        assert response.status == expected_status, response.body.decode(
            "utf-8", errors="replace"
        )
        return response.json()


def _client(sender_id: str, mine_id: str, mine_name: str) -> ExchangeClient:
    return ExchangeClient(
        sender_id=sender_id,
        party_id=f"party-{mine_id.lower()}",
        mine_id=mine_id,
        secret=(f"application-secret-{mine_id}-".encode("ascii") + b"x" * 32),
        transport_secret=(
            f"transport-secret-{mine_id}-".encode("ascii") + b"y" * 32
        ),
        mine_name=mine_name,
    )


def _event_payload(event_group: str, index: int) -> dict[str, Any]:
    common = {
        "correlation_id": f"trace-correlation-{event_group}-{index:02d}",
        # Raw payloads must never be projected into the trace table or export.
        "raw_payload": {"secret": "private-api-key-must-not-leak"},
    }
    if event_group == "submission":
        return {**common, "revision": 1, "submission_id": f"submission-{index}"}
    if event_group == "analysis":
        return {**common, "decision": "normal_candidate"}
    if event_group == "finding":
        return {
            **common,
            "finding_type": "risk",
            "category": "temporal_pattern",
        }
    if event_group == "response":
        return {**common, "finding_ids": [f"finding-{index}"]}
    if event_group == "reanalysis":
        return {**common, "resolving_submission_id": f"revision-{index}"}
    return common


def _append_event(
    server: Any,
    *,
    event_type: str,
    mine_id: str,
    occurred_at: datetime,
    aggregate_id: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, str]:
    with server.store._transaction() as connection:
        server.store._append_audit(
            connection,
            event_type=event_type,
            aggregate_type="trace_contract_fixture",
            aggregate_id=aggregate_id,
            mine_id=mine_id,
            payload=payload or {},
            occurred_at=occurred_at.astimezone(UTC).isoformat(),
        )
        row = connection.execute(
            "SELECT sequence,event_id FROM v2_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    return int(row["sequence"]), str(row["event_id"])


def _seed_trace_events(server: Any) -> None:
    groups = tuple(EVENT_TYPES_BY_GROUP)
    for cycle in range(3):
        for group_index, event_group in enumerate(groups):
            for mine_index, mine_id in enumerate((MINE_A, MINE_B)):
                day = 1 + cycle * len(groups) + group_index
                occurred_at = datetime(2026, 7, day, mine_index, tzinfo=UTC)
                item_index = cycle * len(groups) * 2 + group_index * 2 + mine_index
                _append_event(
                    server,
                    event_type=EVENT_TYPES_BY_GROUP[event_group],
                    mine_id=mine_id,
                    occurred_at=occurred_at,
                    aggregate_id=f"trace-{event_group}-{item_index:02d}",
                    payload=_event_payload(event_group, item_index),
                )

    # These are intentionally technical details.  The default business view
    # must not force leaders to read baseline-engine bookkeeping.
    for index, mine_id in enumerate((MINE_A, MINE_B)):
        _append_event(
            server,
            event_type="baseline_candidate_admitted",
            mine_id=mine_id,
            occurred_at=datetime(2026, 7, 22, index, tzinfo=UTC),
            aggregate_id=f"technical-baseline-{index}",
            payload={
                "run_id": f"run-{index}",
                "raw_payload": {"secret": "private-api-key-must-not-leak"},
            },
        )
        _append_event(
            server,
            event_type="anonymous_peer_snapshot_frozen",
            mine_id=mine_id,
            occurred_at=datetime(2026, 7, 23, index, tzinfo=UTC),
            aggregate_id=f"technical-peer-{index}",
            payload={
                "mine_count": 5,
                "raw_payload": {"secret": "private-api-key-must-not-leak"},
            },
        )


def _login(server: Any, username: str, password: str) -> str:
    body = json.dumps(
        {"username": username, "password": password},
        ensure_ascii=False,
    ).encode("utf-8")
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    try:
        connection.request(
            "POST",
            "/v2/auth/login",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response.read()
        assert response.status == 200
        set_cookie = response.getheader("Set-Cookie")
        assert set_cookie
        return set_cookie.split(";", 1)[0]
    finally:
        connection.close()


@pytest.fixture(scope="module")
def trace_api(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TraceAPI]:
    root = tmp_path_factory.mktemp("regulatory-v2-trace-api")
    clients = {
        "trace-agent-a": _client(
            "trace-agent-a",
            MINE_A,
            # The leading formula marker is deliberate export-security input.
            '=HYPERLINK("https://invalid.example","演示矿")',
        ),
        "trace-agent-b": _client("trace-agent-b", MINE_B, "沁源演示二矿"),
    }
    server = create_server(
        "127.0.0.1",
        0,
        database_path=root / "regulatory.db",
        auth_database_path=root / "auth.db",
        auth_required=True,
        secure_cookie=False,
        clients=clients,
        clock=lambda: FIXED_NOW,
    )
    _seed_trace_events(server)
    server.auth_store.bootstrap_admin("trace-admin", ADMIN_PASSWORD)
    server.auth_store.create_user(
        "trace-mine-a-viewer",
        VIEWER_PASSWORD,
        Role.VIEWER,
        (MINE_A,),
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    api = TraceAPI(
        server=server,
        thread=thread,
        admin_cookie=_login(server, "trace-admin", ADMIN_PASSWORD),
        viewer_cookie=_login(server, "trace-mine-a-viewer", VIEWER_PASSWORD),
    )
    try:
        yield api
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _assert_aware_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    assert parsed.utcoffset() is not None
    return parsed


def _assert_page_contract(page: dict[str, Any]) -> None:
    assert set(page) >= {
        "items",
        "matched_count",
        "has_more",
        "next_cursor",
        "as_of",
        "integrity",
        "applied_filters",
    }
    assert isinstance(page["items"], list)
    assert isinstance(page["matched_count"], int)
    assert page["matched_count"] >= len(page["items"])
    assert isinstance(page["has_more"], bool)
    assert page["integrity"]["valid"] is True
    assert page["integrity"]["scope"] == "complete_chain"
    _assert_aware_iso(page["integrity"]["checked_at"])
    assert set(page["applied_filters"]) >= {
        "view",
        "event_group",
        "mine_id",
        "from",
        "to",
    }
    for item in page["items"]:
        assert set(item) >= {
            "sequence",
            "event_id",
            "event_type",
            "event_group",
            "mine_id",
            "mine_name",
            "event_label",
            "summary",
            "occurred_at",
        }
        _assert_aware_iso(item["occurred_at"])


def test_wallboard_has_a_clean_direct_static_url(trace_api: TraceAPI) -> None:
    response = trace_api.request("/wallboard")

    assert response.status == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-cache"
    page = response.body.decode("utf-8")
    assert 'id="wallboardView"' in page
    assert 'id="wallboardButton"' in page


def _problem_code(response: HTTPResult) -> str:
    return str(response.json().get("code", "")).lower()


def test_exchange_trace_defaults_to_latest_twenty_business_events(
    trace_api: TraceAPI,
) -> None:
    page = trace_api.get_json("/v2/regulatory/exchanges")

    _assert_page_contract(page)
    assert len(page["items"]) == 20
    assert page["matched_count"] > 20
    assert page["has_more"] is True
    assert isinstance(page["next_cursor"], str) and page["next_cursor"]
    assert page["applied_filters"] == {
        "view": "business",
        "event_group": None,
        "mine_id": None,
        "from": None,
        "to": None,
    }
    sequences = [item["sequence"] for item in page["items"]]
    assert sequences == sorted(sequences, reverse=True)
    assert all(
        item["event_type"]
        not in {"baseline_candidate_admitted", "anonymous_peer_snapshot_frozen"}
        for item in page["items"]
    )


def test_exchange_trace_combines_filters_and_uses_half_open_time_window(
    trace_api: TraceAPI,
) -> None:
    parameters = {
        "limit": "1",
        "from": "2026-07-02T00:00:00Z",
        "to": "2026-07-16T00:00:00Z",
        "mine_id": MINE_A,
        "event_group": "analysis",
        "view": "technical",
    }
    page = trace_api.get_json(
        f"/v2/regulatory/exchanges?{urlencode(parameters)}"
    )

    _assert_page_contract(page)
    assert page["matched_count"] == 2
    assert len(page["items"]) == 1
    assert page["has_more"] is True
    assert page["applied_filters"] == {
        "view": "technical",
        "event_group": "analysis",
        "mine_id": MINE_A,
        "from": "2026-07-02T00:00:00.000000Z",
        "to": "2026-07-16T00:00:00.000000Z",
    }
    item = page["items"][0]
    observed = _assert_aware_iso(item["occurred_at"])
    assert datetime(2026, 7, 2, tzinfo=UTC) <= observed
    assert observed < datetime(2026, 7, 16, tzinfo=UTC)
    assert item["mine_id"] == MINE_A
    assert item["event_group"] == "analysis"

    second_parameters = {**parameters, "cursor": page["next_cursor"]}
    second = trace_api.get_json(
        f"/v2/regulatory/exchanges?{urlencode(second_parameters)}"
    )
    assert second["as_of"] == page["as_of"]
    assert second["matched_count"] == page["matched_count"]
    assert second["has_more"] is False
    assert second["next_cursor"] is None
    assert second["items"][0]["event_id"] != item["event_id"]


def test_technical_view_contains_more_detail_than_business_view(
    trace_api: TraceAPI,
) -> None:
    business = trace_api.get_json(
        "/v2/regulatory/exchanges?limit=100&view=business"
    )
    technical = trace_api.get_json(
        "/v2/regulatory/exchanges?limit=100&view=technical"
    )

    assert technical["matched_count"] > business["matched_count"]
    assert {
        "baseline_candidate_admitted",
        "anonymous_peer_snapshot_frozen",
    }.issubset({item["event_type"] for item in technical["items"]})
    assert not {
        "baseline_candidate_admitted",
        "anonymous_peer_snapshot_frozen",
    } & {item["event_type"] for item in business["items"]}


def test_cursor_freezes_snapshot_when_new_events_arrive(
    trace_api: TraceAPI,
) -> None:
    initial = trace_api.get_json(
        "/v2/regulatory/exchanges?limit=100&view=technical"
    )
    expected_ids = {item["event_id"] for item in initial["items"]}
    assert len(expected_ids) == initial["matched_count"]

    first = trace_api.get_json(
        "/v2/regulatory/exchanges?limit=5&view=technical"
    )
    _, inserted_event_id = _append_event(
        trace_api.server,
        event_type="submission_received",
        mine_id=MINE_A,
        occurred_at=FIXED_NOW + timedelta(minutes=1),
        aggregate_id="arrived-after-frozen-snapshot",
        payload={"revision": 1},
    )

    observed_ids: list[str] = [item["event_id"] for item in first["items"]]
    page = first
    while page["has_more"]:
        assert page["next_cursor"]
        page = trace_api.get_json(
            "/v2/regulatory/exchanges?"
            + urlencode(
                {
                    "limit": 5,
                    "view": "technical",
                    "cursor": page["next_cursor"],
                }
            )
        )
        assert page["as_of"] == first["as_of"]
        assert page["matched_count"] == first["matched_count"]
        observed_ids.extend(item["event_id"] for item in page["items"])

    assert len(observed_ids) == len(set(observed_ids))
    assert set(observed_ids) == expected_ids
    assert inserted_event_id not in observed_ids

    refreshed = trace_api.get_json(
        "/v2/regulatory/exchanges?limit=100&view=technical"
    )
    assert inserted_event_id in {item["event_id"] for item in refreshed["items"]}


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "limit=not-a-number",
        "limit=10&limit=20",
        "view=business&view=technical",
        f"mine_id={MINE_A}&mine_id={MINE_B}",
        "view=summary",
        "event_group=baseline",
        "from=2026-07-01T00%3A00%3A00",
        "to=2026-07-01",
        "from=2026-07-20T00%3A00%3A00Z&to=2026-07-01T00%3A00%3A00Z",
        "cursor=not-a-valid-cursor",
        "unexpected_parameter=true",
    ],
)
def test_exchange_trace_rejects_ambiguous_or_invalid_queries(
    trace_api: TraceAPI,
    query: str,
) -> None:
    response = trace_api.request(
        f"/v2/regulatory/exchanges?{query}",
        cookie=trace_api.admin_cookie,
    )

    assert response.status == 400
    assert _problem_code(response) == "invalid_request"


def test_cursor_cannot_be_reused_after_filters_change(trace_api: TraceAPI) -> None:
    first = trace_api.get_json(
        "/v2/regulatory/exchanges?"
        + urlencode({"limit": 2, "view": "technical", "mine_id": MINE_A})
    )
    cursor = first["next_cursor"]
    assert cursor

    changed_queries = (
        {"limit": 2, "view": "technical", "mine_id": MINE_B},
        {
            "limit": 2,
            "view": "technical",
            "mine_id": MINE_A,
            "event_group": "analysis",
        },
        {"limit": 2, "view": "business", "mine_id": MINE_A},
        {
            "limit": 2,
            "view": "technical",
            "mine_id": MINE_A,
            "from": "2026-07-01T00:00:00Z",
        },
    )
    for filters in changed_queries:
        response = trace_api.request(
            "/v2/regulatory/exchanges?"
            + urlencode({**filters, "cursor": cursor}),
            cookie=trace_api.admin_cookie,
        )
        assert response.status == 400
        assert _problem_code(response) == "invalid_request"

    tampered = f"{cursor[:-1]}{'A' if cursor[-1] != 'A' else 'B'}"
    tampered_response = trace_api.request(
        "/v2/regulatory/exchanges?"
        + urlencode(
            {
                "limit": 2,
                "view": "technical",
                "mine_id": MINE_A,
                "cursor": tampered,
            }
        ),
        cookie=trace_api.admin_cookie,
    )
    assert tampered_response.status == 400
    assert _problem_code(tampered_response) == "invalid_request"


def test_exchange_trace_and_export_enforce_mine_scope(trace_api: TraceAPI) -> None:
    scoped = trace_api.get_json(
        "/v2/regulatory/exchanges?limit=100&view=technical",
        cookie=trace_api.viewer_cookie,
    )

    assert scoped["items"]
    assert {item["mine_id"] for item in scoped["items"]} == {MINE_A}
    serialized = json.dumps(scoped, ensure_ascii=False)
    assert MINE_B not in serialized
    assert "沁源演示二矿" not in serialized

    for target in (
        "/v2/regulatory/exchanges?" + urlencode({"mine_id": MINE_B}),
        "/v2/regulatory/exchanges/export.csv?"
        + urlencode(
            {
                "mine_id": MINE_B,
                "from": "2026-07-01T00:00:00Z",
                "to": "2026-08-01T00:00:00Z",
            }
        ),
    ):
        response = trace_api.request(target, cookie=trace_api.viewer_cookie)
        assert response.status == 404
        assert MINE_B not in response.body.decode("utf-8", errors="replace")


def _csv_rows(response: HTTPResult) -> tuple[list[str], list[dict[str, str]]]:
    assert response.body.startswith(b"\xef\xbb\xbf")
    decoded = response.body.decode("utf-8-sig")
    assert "\r\n" in decoded
    assert "\n" not in decoded.replace("\r\n", "")
    reader = csv.DictReader(StringIO(decoded, newline=""))
    assert reader.fieldnames is not None
    return list(reader.fieldnames), list(reader)


def _header(
    fieldnames: list[str],
    *accepted: str,
) -> str:
    selected = next((name for name in accepted if name in fieldnames), None)
    assert selected is not None, (accepted, fieldnames)
    return selected


def test_csv_export_reuses_filters_is_safe_and_writes_access_audit(
    trace_api: TraceAPI,
) -> None:
    filters = {
        "from": "2026-07-01T00:00:00Z",
        "to": "2026-07-22T00:00:00Z",
        "mine_id": MINE_A,
        "event_group": "security",
        "view": "technical",
    }
    query = urlencode(filters)
    page = trace_api.get_json(
        f"/v2/regulatory/exchanges?limit=100&{query}"
    )
    before = trace_api.server.auth_store.list_audit_events(limit=1000)

    response = trace_api.request(
        f"/v2/regulatory/exchanges/export.csv?{query}",
        cookie=trace_api.admin_cookie,
    )

    assert response.status == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    assert ".csv" in disposition.lower()
    fieldnames, rows = _csv_rows(response)
    assert len(rows) == page["matched_count"] == 3
    assert response.headers["x-mineguard-row-count"] == str(len(rows))
    snapshot_sequence = int(
        response.headers["x-mineguard-snapshot-sequence"]
    )
    assert {
        "留痕序号",
        "时间（北京时间）",
        "UTC时间",
        "煤矿名称",
        "煤矿编号",
        "业务环节",
        "事件",
        "摘要",
        "事件编号",
        "前序哈希",
        "事件哈希",
    }.issubset(fieldnames)
    correlation_header = _header(fieldnames, "完整关联编号", "关联编号")
    integrity_header = _header(
        fieldnames,
        "导出时完整链校验结果",
        "完整链校验结果",
        "完整链校验",
    )
    assert correlation_header
    assert integrity_header

    event_ids = {row["事件编号"] for row in rows}
    assert event_ids == {item["event_id"] for item in page["items"]}
    sequences = [int(row["留痕序号"]) for row in rows]
    assert sequences == sorted(sequences, reverse=True)
    assert len(sequences) == len(set(sequences))
    assert all(sequence <= snapshot_sequence for sequence in sequences)
    assert {row["煤矿编号"] for row in rows} == {MINE_A}
    assert {row["业务环节"] for row in rows} == {"接入与安全拦截"}
    assert all(row[integrity_header] == "完整留痕链校验通过" for row in rows)

    # A CSV cell must not begin with a spreadsheet formula marker.  The mine
    # name in this fixture deliberately begins with '=' and must be escaped.
    assert all(
        not cell.startswith(("=", "+", "-", "@"))
        for row in rows
        for cell in row.values()
    )
    decoded = response.body.decode("utf-8-sig")
    assert "private-api-key-must-not-leak" not in decoded
    assert "raw_payload" not in decoded
    assert "secret" not in decoded.casefold()

    after = trace_api.server.auth_store.list_audit_events(limit=1000)
    new_events = {item["seq"]: item for item in after} | {}
    previous_sequences = {item["seq"] for item in before}
    export_audits = [
        item
        for sequence, item in new_events.items()
        if sequence not in previous_sequences
        and item["action"] == "regulatory_exchange_trace_exported"
    ]
    assert len(export_audits) == 1
    audit = export_audits[0]
    assert audit["username"] == "trace-admin"
    audit_text = json.dumps(audit, ensure_ascii=False)
    for expected in (MINE_A, "security", "technical"):
        assert expected in audit_text
    assert "private-api-key-must-not-leak" not in audit_text


def test_csv_export_refuses_when_complete_integrity_check_fails(
    trace_api: TraceAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trace_api.server, "integrity_valid", False)
    monkeypatch.setattr(trace_api.server.store, "verify_integrity", lambda: False)
    monkeypatch.setattr(trace_api.server.store, "verify_audit_chain", lambda: False)

    response = trace_api.request(
        "/v2/regulatory/exchanges/export.csv?"
        + urlencode(
            {
                "view": "technical",
                "from": "2026-07-01T00:00:00Z",
                "to": "2026-08-01T00:00:00Z",
            }
        ),
        cookie=trace_api.admin_cookie,
    )

    assert response.status == 409
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("application/problem+json")
    assert "integrity" in _problem_code(response)


def test_csv_export_rejects_more_than_ten_thousand_matching_rows(
    tmp_path: Path,
) -> None:
    client = _client("bulk-agent", MINE_A, "批量导出演示矿")
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "bulk-regulatory.db",
        auth_database_path=tmp_path / "bulk-auth.db",
        auth_required=False,
        clients={client.sender_id: client},
        clock=lambda: FIXED_NOW,
    )
    occurred_at = datetime(2026, 7, 1, tzinfo=UTC).isoformat()
    with server.store._transaction() as connection:
        for index in range(10_001):
            server.store._append_audit(
                connection,
                event_type="submission_received",
                aggregate_type="bulk_trace_contract_fixture",
                aggregate_id=f"bulk-submission-{index:05d}",
                mine_id=MINE_A,
                payload={"revision": 1},
                occurred_at=occurred_at,
            )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=20)
    try:
        # 10,001 matching business events exceed the hard export maximum.  The
        # endpoint must fail rather than silently truncate.
        connection.request(
            "GET",
            "/v2/regulatory/exchanges/export.csv?"
            + urlencode(
                {
                    "view": "technical",
                    "from": "2026-07-01T00:00:00Z",
                    "to": "2026-07-02T00:00:00Z",
                }
            ),
        )
        response = connection.getresponse()
        body = response.read()
        assert response.status == 422
        assert response.getheader("Cache-Control") == "no-store"
        problem = json.loads(body)
        assert "too_large" in str(problem.get("code", "")).casefold()
        assert "10000" in str(problem)
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
