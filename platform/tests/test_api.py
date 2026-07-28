from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from mineguard.api import MineGuardRequestHandler, create_server


@contextmanager
def running_server() -> Iterator[tuple[str, int]]:
    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield str(host), int(port)
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
) -> tuple[int, dict[str, Any]]:
    status, response_body, _ = raw_request(host, port, method, path, body)
    return status, json.loads(response_body)


def raw_request(
    host: str,
    port: int,
    method: str,
    path: str,
    body: Any | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    connection = http.client.HTTPConnection(host, port, timeout=2)
    encoded = None if body is None else json.dumps(body).encode()
    headers = {} if encoded is None else {"Content-Type": "application/json"}
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        response_headers = {
            name.lower(): value for name, value in response.getheaders()
        }
        return response.status, response.read(), response_headers
    finally:
        connection.close()


def assert_static_security_headers(headers: dict[str, str]) -> None:
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-frame-options"] == "DENY"
    content_security_policy = headers["content-security-policy"]
    assert "default-src 'self'" in content_security_policy
    assert "object-src 'none'" in content_security_policy
    assert "base-uri 'none'" in content_security_policy
    assert "frame-ancestors 'none'" in content_security_policy


def test_frontend_index_returns_html() -> None:
    with running_server() as (host, port):
        status, body, headers = raw_request(host, port, "GET", "/?mine=M001")

    assert status == 200
    assert b"<html" in body.lower()
    assert headers["content-type"] == "text/html; charset=utf-8"
    assert_static_security_headers(headers)
    assert int(headers["content-length"]) == len(body)


@pytest.mark.parametrize(
    ("path", "expected_content_type"),
    [
        ("/assets/styles.css", "text/css; charset=utf-8"),
        ("/assets/app.js?v=1", "application/javascript; charset=utf-8"),
    ],
)
def test_frontend_assets_have_explicit_content_types(
    path: str,
    expected_content_type: str,
) -> None:
    with running_server() as (host, port):
        status, body, headers = raw_request(host, port, "GET", path)

    assert status == 200
    assert body
    assert headers["content-type"] == expected_content_type
    assert_static_security_headers(headers)


@pytest.mark.parametrize(
    "path",
    [
        "/assets/missing.js",
        "/assets/%2e%2e/api.py",
        "/web/index.html",
    ],
)
def test_frontend_only_serves_allowlisted_paths(path: str) -> None:
    with running_server() as (host, port):
        status, payload = request(host, port, "GET", path)

    assert status == 404
    assert payload["error"]["code"] == "not_found"


def test_health() -> None:
    with running_server() as (host, port):
        status, body, headers = raw_request(host, port, "GET", "/health")

    assert status == 200
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert headers["x-content-type-options"] == "nosniff"
    payload = json.loads(body)
    assert payload == {"status": "ok"}


def test_structured_access_log_does_not_expand_query_string(
    capfd: pytest.CaptureFixture[str],
) -> None:
    with running_server() as (host, port):
        status, _, headers = raw_request(
            host,
            port,
            "GET",
            "/health?token=must-not-appear",
        )

    assert status == 200
    lines = [
        line
        for line in capfd.readouterr().err.splitlines()
        if line.strip()
    ]
    record = json.loads(lines[-1])
    assert record["path"] == "/health"
    assert record["status"] == 200
    assert record["request_id"] == headers["x-request-id"]
    assert "must-not-appear" not in json.dumps(record)


def test_analysis_get_still_requires_post() -> None:
    with running_server() as (host, port):
        status, body, headers = raw_request(
            host,
            port,
            "GET",
            "/v1/analyze/production",
        )

    assert status == 405
    assert headers["allow"] == "POST"
    assert json.loads(body)["error"]["code"] == "method_not_allowed"


def test_frontend_route_rejects_post() -> None:
    with running_server() as (host, port):
        status, body, headers = raw_request(host, port, "POST", "/", {})

    assert status == 405
    assert headers["allow"] == "GET"
    assert json.loads(body)["error"]["code"] == "method_not_allowed"


def test_unknown_route_returns_404() -> None:
    with running_server() as (host, port):
        status, payload = request(host, port, "GET", "/missing")

    assert status == 404
    assert payload["error"]["code"] == "not_found"


def test_validation_error_returns_400() -> None:
    with running_server() as (host, port):
        status, payload = request(
            host,
            port,
            "POST",
            "/v1/analyze/production",
            {"mine_id": "M001"},
        )

    assert status == 400
    assert payload["error"]["code"] == "validation_error"
    assert payload["error"]["details"]


def test_production_analysis_returns_200() -> None:
    observations = [
        ("production", "coal.reported_output_t", 5000, 100, "report"),
        ("transport", "coal.main_transport_t", 7100, 106.5, "belt"),
        ("wash", "wash.feed_t", 6800, 136, "wash_meter"),
        ("sales", "sales.raw_shipped_t", 0, 1, "sales_ledger"),
        ("stock", "inventory.raw_change_t", 250, 100, "stock_survey"),
    ]
    body = {
        "mine_id": "M001",
        "window_start": "2026-07-20T00:00:00+08:00",
        "window_end": "2026-07-21T00:00:00+08:00",
        "observations": [
            {
                "observation_id": observation_id,
                "metric_code": metric_code,
                "value": value,
                "tolerance_abs": tolerance,
                "source_group": source_group,
            }
            for (
                observation_id,
                metric_code,
                value,
                tolerance,
                source_group,
            ) in observations
        ],
    }

    with running_server() as (host, port):
        status, payload = request(
            host,
            port,
            "POST",
            "/v1/analyze/production",
            body,
        )

    assert status == 200
    assert payload["mine_id"] == "M001"
    assert payload["status"] == "inconsistent"
    assert payload["reasonable_production_range"] == [6993.5, 7206.5]


def test_personnel_analysis_returns_200() -> None:
    with running_server() as (host, port):
        status, payload = request(
            host,
            port,
            "POST",
            "/v1/analyze/personnel",
            {
                "session_id": "gate-a",
                "faces": [
                    {
                        "face_track_id": "face-1",
                        "event_time": "2026-07-20T08:00:01+08:00",
                        "candidate_person_id": "P001",
                        "match_probability": 0.97,
                        "direction": "entry",
                    }
                ],
                "cards": [
                    {
                        "card_event_id": "card-event-1",
                        "card_id": "CARD-001",
                        "bound_person_id": "P001",
                        "event_time": "2026-07-20T08:00:02+08:00",
                        "direction": "entry",
                    }
                ],
            },
        )

    assert status == 200
    assert payload["session_id"] == "gate-a"
    assert payload["matches"][0]["status"] == "identity_confirmed"


def test_analysis_exception_returns_500() -> None:
    path = "/v1/analyze/production"
    model_type, original = MineGuardRequestHandler._post_routes[path]

    def fail(_: Any) -> Any:
        raise RuntimeError("sensitive solver detail")

    MineGuardRequestHandler._post_routes[path] = (model_type, fail)
    try:
        with running_server() as (host, port):
            status, payload = request(
                host,
                port,
                "POST",
                path,
                {
                    "mine_id": "M001",
                    "window_start": "2026-07-20T00:00:00Z",
                    "window_end": "2026-07-21T00:00:00Z",
                    "observations": [
                        {
                            "observation_id": "production",
                            "metric_code": "coal.reported_output_t",
                            "value": 1,
                            "tolerance_abs": 1,
                            "source_group": "report",
                        }
                    ],
                },
            )
    finally:
        MineGuardRequestHandler._post_routes[path] = (model_type, original)

    assert status == 500
    assert payload == {
        "error": {
            "code": "internal_error",
            "message": "internal server error",
        }
    }
