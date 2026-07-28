"""Optional signed webhook delivery for safety alert notifications."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import hmac
import ipaddress
import json
import re
import threading
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .edge_store import EdgeTelemetryRepository


_LEVEL_RANK = {"blue": 1, "yellow": 2, "orange": 3, "red": 4}
_SIGNATURE_CONTEXT = "MINEGUARD-SAFETY-WEBHOOK-HMAC-SHA256-V1"
_WEBHOOK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class NotificationDeliveryError(RuntimeError):
    """Stable local error code without remote response data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Webhook destinations are signed exactly and must never redirect."""

    def redirect_request(  # type: ignore[override]
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


_NO_REDIRECT_OPENER = build_opener(_NoRedirectHandler())


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class SafetyWebhook:
    webhook_id: str
    url: str
    secret: bytes = field(repr=False)
    minimum_level: str = "blue"
    timeout_seconds: float = 5.0

    def accepts(self, level: str) -> bool:
        return _LEVEL_RANK[level] >= _LEVEL_RANK[self.minimum_level]


def parse_safety_webhooks(value: str | None) -> tuple[SafetyWebhook, ...]:
    if value is None or not value.strip():
        return ()
    try:
        document = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(
            "MINEGUARD_SAFETY_WEBHOOKS_JSON must be valid JSON"
        ) from error
    entries = (
        document.get("webhooks")
        if isinstance(document, dict)
        else document
    )
    if not isinstance(entries, list):
        raise ValueError("safety webhooks must be a JSON array")
    result: list[SafetyWebhook] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("safety webhook entries must be objects")
        webhook_id = str(item.get("webhook_id") or "")
        url = str(item.get("url") or "")
        minimum_level = str(item.get("minimum_level") or "blue")
        secret_text = item.get("secret_base64")
        timeout = item.get("timeout_seconds", 5)
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as error:
            raise ValueError("safety webhook entry is invalid") from error
        hostname = parsed.hostname or ""
        loopback = _is_loopback_host(hostname)
        url_is_ascii = True
        try:
            url.encode("ascii")
        except UnicodeEncodeError:
            url_is_ascii = False
        if (
            _WEBHOOK_ID.fullmatch(webhook_id) is None
            or webhook_id in seen
            or not url
            or url != url.strip()
            or len(url) > 2048
            or not url_is_ascii
            or any(ord(character) < 0x20 for character in url)
            or "\\" in url
            or parsed.scheme not in {"https", "http"}
            or (parsed.scheme == "http" and not loopback)
            or not hostname
            or "%" in hostname
            or parsed.username is not None
            or parsed.password is not None
            or port == 0
            or parsed.netloc.endswith(":")
            or parsed.query
            or parsed.fragment
            or minimum_level not in _LEVEL_RANK
            or not isinstance(secret_text, str)
            or not isinstance(timeout, int | float)
            or isinstance(timeout, bool)
            or not 0.5 <= float(timeout) <= 30.0
        ):
            raise ValueError("safety webhook entry is invalid")
        try:
            secret = base64.b64decode(secret_text, validate=True)
        except (ValueError, base64.binascii.Error) as error:
            raise ValueError(
                "safety webhook secret_base64 is invalid"
            ) from error
        if len(secret) < 32:
            raise ValueError(
                "safety webhook secret must contain at least 32 bytes"
            )
        seen.add(webhook_id)
        result.append(
            SafetyWebhook(
                webhook_id=webhook_id,
                url=url,
                secret=secret,
                minimum_level=minimum_level,
                timeout_seconds=float(timeout),
            )
        )
    return tuple(result)


def _body(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _signature(
    webhook: SafetyWebhook,
    *,
    notification_id: str,
    body_sha256: str,
) -> str:
    path = urlsplit(webhook.url).path or "/"
    material = "\n".join(
        (
            _SIGNATURE_CONTEXT,
            "POST",
            path,
            webhook.webhook_id,
            notification_id,
            body_sha256,
        )
    ).encode("utf-8")
    return hmac.new(webhook.secret, material, hashlib.sha256).hexdigest()


class SafetyNotificationDispatcher:
    """Durable target-level outbox worker with isolated retries."""

    def __init__(
        self,
        repository: EdgeTelemetryRepository,
        webhooks: tuple[SafetyWebhook, ...],
        *,
        poll_seconds: float = 2.0,
    ) -> None:
        self._repository = repository
        self._webhooks = webhooks
        self._poll_seconds = max(0.2, poll_seconds)
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_worker_error: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self._webhooks)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_worker_error(self) -> str | None:
        return self._last_worker_error

    def start(self) -> None:
        if not self._webhooks or self.is_running():
            return
        self._stop.clear()
        self._wake.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="mineguard-safety-notifications",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        self._thread = None

    def wake(self) -> None:
        """Promptly process a newly requeued target."""
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.dispatch_once()
                self._last_worker_error = None
            except Exception as error:
                # Keep the worker alive. Readiness exposes only the exception
                # class, never configuration, URLs or remote response data.
                self._last_worker_error = type(error).__name__
            self._wake.wait(self._poll_seconds)
            self._wake.clear()

    def dispatch_once(self, *, now: datetime | None = None) -> int:
        if not self._webhooks:
            return 0
        by_id = {
            webhook.webhook_id: webhook for webhook in self._webhooks
        }
        self._repository.fail_unconfigured_notification_deliveries(
            set(by_id),
            now=now,
        )
        completed = self._repository.materialize_notification_deliveries(
            {
                webhook.webhook_id: webhook.minimum_level
                for webhook in self._webhooks
            },
            now=now,
        )
        touched_notifications: set[str] = set()
        for item in self._repository.claim_notification_deliveries(
            set(by_id),
            limit=20,
            now=now,
        ):
            webhook = by_id[item["webhook_id"]]
            touched_notifications.add(str(item["notification_id"]))
            try:
                self._deliver(webhook, item)
                self._repository.mark_notification_delivery_delivered(
                    item["notification_id"],
                    webhook.webhook_id,
                )
            except Exception as error:
                # Store a stable class code, never a URL, secret, remote body,
                # stack trace or other potentially sensitive detail.
                error_code = (
                    error.code
                    if isinstance(error, NotificationDeliveryError)
                    else type(error).__name__
                )
                self._repository.mark_notification_delivery_failed(
                    item["notification_id"],
                    webhook.webhook_id,
                    error_code=error_code,
                )
        completed += sum(
            1
            for notification_id in touched_notifications
            if (
                (
                    self._repository.get_notification(notification_id)
                    or {}
                ).get("status")
                == "delivered"
            )
        )
        return completed

    @staticmethod
    def _deliver(
        webhook: SafetyWebhook,
        item: dict[str, Any],
    ) -> None:
        encoded = _body(item["payload"])
        digest = hashlib.sha256(encoded).hexdigest()
        request = Request(
            webhook.url,
            data=encoded,
            method="POST",
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-MineGuard-Webhook-Id": webhook.webhook_id,
                "X-MineGuard-Notification-Id": item["notification_id"],
                "X-MineGuard-Content-SHA256": digest,
                "X-MineGuard-Signature-Version": "hmac-sha256-v1",
                "X-MineGuard-Signature": _signature(
                    webhook,
                    notification_id=item["notification_id"],
                    body_sha256=digest,
                ),
            },
        )
        try:
            with _NO_REDIRECT_OPENER.open(
                request,
                timeout=webhook.timeout_seconds,
            ) as response:
                status = int(response.status)
                response.read(1024)
        except HTTPError as error:
            error.read(1024)
            code = int(error.code)
            if 300 <= code < 400:
                stable_code = "webhook_redirect_forbidden"
            elif 400 <= code < 500:
                stable_code = "webhook_http_4xx"
            elif 500 <= code < 600:
                stable_code = "webhook_http_5xx"
            else:
                stable_code = "webhook_http_error"
            raise NotificationDeliveryError(stable_code) from error
        except (URLError, TimeoutError, OSError) as error:
            raise NotificationDeliveryError(
                "webhook_transport_error"
            ) from error
        if not 200 <= status < 300:
            raise NotificationDeliveryError("webhook_non_success")
