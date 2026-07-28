from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from mineguard.edge_store import EdgeTelemetryRepository
from mineguard.notifications import (
    SafetyNotificationDispatcher,
    parse_safety_webhooks,
)


SECRET = b"notification-test-secret-at-least-32-bytes"


class _Receiver(BaseHTTPRequestHandler):
    received: list[tuple[dict[str, str], dict[str, object]]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        self.__class__.received.append(
            (
                {key.lower(): value for key, value in self.headers.items()},
                json.loads(body),
            )
        )
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class _FailingReceiver(_Receiver):
    received: list[tuple[dict[str, str], dict[str, object]]] = []
    response_status = 503

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        self.__class__.received.append(
            (
                {key.lower(): value for key, value in self.headers.items()},
                json.loads(body),
            )
        )
        self.send_response(self.__class__.response_status)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _RedirectReceiver(_Receiver):
    received: list[tuple[dict[str, str], dict[str, object]]] = []
    redirect_url = ""

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        self.__class__.received.append(
            (
                {key.lower(): value for key, value in self.headers.items()},
                json.loads(body),
            )
        )
        self.send_response(307)
        self.send_header("Location", self.__class__.redirect_url)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _webhook_json(url: str, *, minimum_level: str = "blue") -> str:
    return json.dumps(
        [
            {
                "webhook_id": "county-command",
                "url": url,
                "minimum_level": minimum_level,
                "secret_base64": base64.b64encode(SECRET).decode(),
            }
        ]
    )


def _webhooks_json(
    entries: list[tuple[str, str, str]],
) -> str:
    return json.dumps(
        [
            {
                "webhook_id": webhook_id,
                "url": url,
                "minimum_level": minimum_level,
                "secret_base64": base64.b64encode(SECRET).decode(),
            }
            for webhook_id, url, minimum_level in entries
        ]
    )


def _create_alert(repository: EdgeTelemetryRepository) -> dict[str, object]:
    return repository.upsert_platform_alert(
        mine_id="M001",
        category="methane",
        rule_code="methane:T1",
        level="red",
        title="甲烷预警",
        summary="请立即人工核查",
        location_code="T1",
        detected_at=datetime.now(UTC),
        observation_ids=["obs-1"],
        details={"production_control_permitted": False},
        rule_profile={"version": "v1", "fingerprint": "a" * 64},
    )


def test_webhook_configuration_rejects_plain_remote_http() -> None:
    with pytest.raises(ValueError, match="invalid"):
        parse_safety_webhooks(
            _webhook_json("http://example.com/receive")
        )


def test_webhook_configuration_rejects_unsigned_query_component() -> None:
    with pytest.raises(ValueError, match="invalid"):
        parse_safety_webhooks(
            _webhook_json("https://example.com/receive?tenant=unsafe")
        )


@pytest.mark.parametrize(
    "webhook_id,url",
    [
        ("bad/id", "https://example.com/receive"),
        ("valid", " https://example.com/receive"),
        ("valid", "https://user@example.com/receive"),
        ("valid", "https://example.com:/receive"),
        ("valid", "https://example.com:99999/receive"),
        ("valid", "https://例子.example/receive"),
        ("valid", "https://example.com/receive#fragment"),
    ],
)
def test_webhook_configuration_rejects_ambiguous_targets(
    webhook_id: str,
    url: str,
) -> None:
    document = json.loads(_webhook_json(url))
    document[0]["webhook_id"] = webhook_id
    with pytest.raises(ValueError, match="invalid"):
        parse_safety_webhooks(json.dumps(document))


def test_durable_outbox_dispatches_signed_idempotent_payload() -> None:
    receiver = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    _Receiver.received.clear()
    thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    thread.start()
    repository = EdgeTelemetryRepository()
    try:
        port = receiver.server_address[1]
        webhooks = parse_safety_webhooks(
            _webhook_json(f"http://127.0.0.1:{port}/safety")
        )
        alert = _create_alert(repository)
        pending = repository.list_notifications(status="pending")
        assert len(pending) == 1
        assert pending[0]["alert_id"] == alert["alert_id"]

        dispatcher = SafetyNotificationDispatcher(repository, webhooks)
        assert dispatcher.dispatch_once() == 1

        delivered = repository.list_notifications(status="delivered")
        assert len(delivered) == 1
        headers, payload = _Receiver.received[0]
        assert headers["x-mineguard-notification-id"] == (
            payload["notification_id"]
        )
        assert len(headers["x-mineguard-signature"]) == 64
        assert payload["regulatory_outcome"] == "not_determined"
        assert payload["technical_warning"]["advisory_only"] is True
        assert delivered[0]["delivery_summary"] == {
            "target_count": 1,
            "status_counts": {"delivered": 1},
            "all_delivered": True,
        }
    finally:
        repository.close()
        receiver.shutdown()
        receiver.server_close()
        thread.join(timeout=2)


def test_level_filter_marks_low_level_notification_complete() -> None:
    repository = EdgeTelemetryRepository()
    try:
        repository.upsert_platform_alert(
            mine_id="M001",
            category="data_quality",
            rule_code="missing-profile",
            level="blue",
            title="参数待配置",
            summary="请配置",
            location_code="profile",
            detected_at=datetime.now(UTC),
            observation_ids=["obs-1"],
            details={},
            rule_profile={"version": "v1", "fingerprint": "a" * 64},
        )
        webhooks = parse_safety_webhooks(
            _webhook_json(
                "http://127.0.0.1:9/unreachable",
                minimum_level="orange",
            )
        )
        dispatcher = SafetyNotificationDispatcher(repository, webhooks)
        assert dispatcher.dispatch_once() == 1
        assert len(repository.list_notifications(status="delivered")) == 1
    finally:
        repository.close()


def test_each_webhook_retries_independently_without_resending_success() -> None:
    successful = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    failing = ThreadingHTTPServer(("127.0.0.1", 0), _FailingReceiver)
    _Receiver.received.clear()
    _FailingReceiver.received.clear()
    _FailingReceiver.response_status = 503
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (successful, failing)
    ]
    for thread in threads:
        thread.start()
    repository = EdgeTelemetryRepository()
    try:
        _create_alert(repository)
        webhooks = parse_safety_webhooks(
            _webhooks_json(
                [
                    (
                        "successful-target",
                        (
                            "http://127.0.0.1:"
                            f"{successful.server_address[1]}/safety"
                        ),
                        "blue",
                    ),
                    (
                        "recovering-target",
                        (
                            "http://127.0.0.1:"
                            f"{failing.server_address[1]}/safety"
                        ),
                        "blue",
                    ),
                ]
            )
        )
        dispatcher = SafetyNotificationDispatcher(repository, webhooks)
        started_at = datetime.now(UTC)
        assert dispatcher.dispatch_once(now=started_at) == 0

        pending = repository.list_notifications()
        assert len(pending) == 1
        assert pending[0]["status"] == "retry"
        statuses = {
            item["webhook_id"]: item["status"]
            for item in pending[0]["deliveries"]
        }
        assert statuses == {
            "recovering-target": "retry",
            "successful-target": "delivered",
        }
        assert len(_Receiver.received) == 1
        assert len(_FailingReceiver.received) == 1

        _FailingReceiver.response_status = 204
        assert (
            dispatcher.dispatch_once(now=started_at + timedelta(seconds=10))
            == 1
        )
        delivered = repository.list_notifications(status="delivered")
        assert len(delivered) == 1
        assert len(_Receiver.received) == 1
        assert len(_FailingReceiver.received) == 2
        first_payload = _Receiver.received[0][1]
        recovered_payload = _FailingReceiver.received[-1][1]
        assert (
            first_payload["notification_id"]
            == recovered_payload["notification_id"]
        )
    finally:
        repository.close()
        for server in (successful, failing):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_redirect_is_not_followed_and_is_recorded_as_stable_error() -> None:
    destination = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    redirect = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectReceiver)
    _Receiver.received.clear()
    _RedirectReceiver.received.clear()
    _RedirectReceiver.redirect_url = (
        f"http://127.0.0.1:{destination.server_address[1]}/unexpected"
    )
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (destination, redirect)
    ]
    for thread in threads:
        thread.start()
    repository = EdgeTelemetryRepository()
    try:
        _create_alert(repository)
        webhooks = parse_safety_webhooks(
            _webhook_json(
                f"http://127.0.0.1:{redirect.server_address[1]}/safety"
            )
        )
        dispatcher = SafetyNotificationDispatcher(repository, webhooks)
        assert dispatcher.dispatch_once() == 0
        item = repository.list_notifications()[0]
        assert item["status"] == "retry"
        assert item["deliveries"][0]["last_error"] == (
            "webhook_redirect_forbidden"
        )
        assert len(_RedirectReceiver.received) == 1
        assert _Receiver.received == []
    finally:
        repository.close()
        for server in (destination, redirect):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_dead_target_can_be_requeued_without_touching_delivered_target() -> None:
    repository = EdgeTelemetryRepository()
    try:
        _create_alert(repository)
        now = datetime.now(UTC)
        repository.materialize_notification_deliveries(
            {"delivered-target": "blue", "dead-target": "blue"},
            now=now,
        )
        claimed = repository.claim_notification_deliveries(
            {"delivered-target", "dead-target"},
            now=now,
        )
        by_target = {item["webhook_id"]: item for item in claimed}
        notification_id = claimed[0]["notification_id"]
        repository.mark_notification_delivery_delivered(
            notification_id,
            "delivered-target",
        )
        repository.mark_notification_delivery_failed(
            notification_id,
            "dead-target",
            error_code="webhook_http_5xx",
            maximum_attempts=1,
        )
        dead = repository.get_notification(notification_id)
        assert dead is not None
        assert dead["status"] == "dead"

        assert (
            repository.retry_notification_deliveries(
                notification_id,
                webhook_id="dead-target",
                now=now + timedelta(seconds=1),
            )
            == 1
        )
        retried = repository.get_notification(notification_id)
        assert retried is not None
        deliveries = {
            item["webhook_id"]: item for item in retried["deliveries"]
        }
        assert deliveries["delivered-target"]["status"] == "delivered"
        assert deliveries["dead-target"]["status"] == "retry"
        assert deliveries["dead-target"]["attempt_cycle"] == 0
        assert deliveries["dead-target"]["manual_retry_count"] == 1
        assert by_target["dead-target"]["delivery_attempts"] == 1
    finally:
        repository.close()


def test_restart_recovers_inflight_target_without_replaying_delivered(
    tmp_path: Path,
) -> None:
    database = tmp_path / "notifications.db"
    repository = EdgeTelemetryRepository(database)
    _create_alert(repository)
    repository.materialize_notification_deliveries(
        {"inflight-target": "blue", "complete-target": "blue"}
    )
    claimed = repository.claim_notification_deliveries(
        {"inflight-target", "complete-target"}
    )
    notification_id = claimed[0]["notification_id"]
    repository.mark_notification_delivery_delivered(
        notification_id,
        "complete-target",
    )
    repository.close()

    recovered = EdgeTelemetryRepository(database)
    try:
        item = recovered.get_notification(notification_id)
        assert item is not None
        deliveries = {
            delivery["webhook_id"]: delivery
            for delivery in item["deliveries"]
        }
        assert deliveries["complete-target"]["status"] == "delivered"
        assert deliveries["inflight-target"]["status"] == "retry"
        assert deliveries["inflight-target"]["last_error"] == (
            "worker_restarted_during_delivery"
        )
    finally:
        recovered.close()


def test_removed_configured_target_becomes_visible_dead_letter() -> None:
    repository = EdgeTelemetryRepository()
    try:
        _create_alert(repository)
        repository.materialize_notification_deliveries(
            {"removed-target": "blue", "current-target": "blue"}
        )
        changed = repository.fail_unconfigured_notification_deliveries(
            {"current-target"}
        )
        assert changed == 1
        item = repository.list_notifications()[0]
        deliveries = {
            delivery["webhook_id"]: delivery
            for delivery in item["deliveries"]
        }
        assert deliveries["removed-target"]["status"] == "dead"
        assert deliveries["removed-target"]["last_error"] == (
            "webhook_not_configured"
        )
        assert deliveries["current-target"]["status"] == "pending"
        health = repository.notification_delivery_health()
        assert health["dead"] == 1
        assert health["pending"] == 1
    finally:
        repository.close()


def test_legacy_retry_attempt_count_is_inherited_on_target_expansion(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-notifications.db"
    repository = EdgeTelemetryRepository(database)
    _create_alert(repository)
    notification_id = repository.list_notifications()[0]["notification_id"]
    repository.close()
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            """
            UPDATE safety_notification_outbox
            SET status = 'retry', attempts = 5
            WHERE notification_id = ?
            """,
            (notification_id,),
        )
        connection.commit()
    finally:
        connection.close()

    migrated = EdgeTelemetryRepository(database)
    try:
        migrated.materialize_notification_deliveries(
            {"county-command": "blue"}
        )
        item = migrated.get_notification(notification_id)
        assert item is not None
        assert item["attempts"] == 5
        assert item["deliveries"][0]["attempts"] == 5
        assert item["deliveries"][0]["attempt_cycle"] == 5
    finally:
        migrated.close()
