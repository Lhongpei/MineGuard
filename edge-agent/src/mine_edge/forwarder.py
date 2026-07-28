"""Durable upstream batch delivery using raw-body HMAC authentication."""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import urllib.error
import urllib.request
from typing import Any, Protocol

from .errors import ForwardError
from .models import utc_now
from .settings import Settings, validate_upstream_url
from .storage import Repository
from .wire import (
    INGEST_PATH,
    EdgeBatch,
    parse_edge_receipt,
    signature_headers,
    valid_legacy_batch_id,
)

MAX_RECEIPT_BYTES = 64 * 1024


@dataclasses.dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    body: bytes


class Transport(Protocol):
    def post(
        self, url: str, body: bytes, headers: dict[str, str], timeout_seconds: int
    ) -> TransportResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into an HTTPError without replaying signed headers."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class UrllibTransport:
    def __init__(
        self,
        *,
        max_response_bytes: int = MAX_RECEIPT_BYTES,
        opener: Any | None = None,
    ) -> None:
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes 必须大于零")
        self.max_response_bytes = max_response_bytes
        self._opener = opener or urllib.request.build_opener(_NoRedirectHandler())

    def post(
        self, url: str, body: bytes, headers: dict[str, str], timeout_seconds: int
    ) -> TransportResponse:
        request = urllib.request.Request(
            url,
            data=body,
            headers={**headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=timeout_seconds) as response:
                response_body = response.read(self.max_response_bytes + 1)
                if len(response_body) > self.max_response_bytes:
                    raise ForwardError(
                        f"监管回执超过 {self.max_response_bytes} 字节上限"
                    )
                return TransportResponse(
                    status=int(response.status),
                    body=response_body,
                )
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode("utf-8", errors="replace")
            raise ForwardError(f"上行返回 HTTP {error.code}: {detail}") from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ForwardError(f"上行连接失败：{error}") from error


@dataclasses.dataclass(frozen=True, slots=True)
class ForwardResult:
    status: str
    batch_id: str | None = None
    events: int = 0
    retry_after_seconds: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


class Forwarder:
    def __init__(
        self,
        repository: Repository,
        settings: Settings,
        *,
        transport: Transport | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.upstream_url = validate_upstream_url(settings.upstream_url)
        self.transport = transport or UrllibTransport()

    def forward_once(self) -> ForwardResult:
        if not self.upstream_url:
            return ForwardResult(status="not_configured")
        if not self.settings.upstream_hmac_secret:
            return ForwardResult(
                status="configuration_error",
                error="未配置上行 HMAC 密钥",
            )
        claimed = self.repository.claim_batch(
            limit=self.settings.forward_batch_size,
            client_id=self.settings.client_id,
        )
        if claimed is None:
            return ForwardResult(status="empty")
        observations = [
            record.payload
            for record in claimed.records
            if record.event_type == "observation"
        ]
        alerts = [
            record.payload
            for record in claimed.records
            if record.event_type == "local_alert"
        ]
        if not observations:
            error = "待发送批次不含观测，无法满足 edge-telemetry-batch-v1"
            delay = self.repository.mark_batch_failed(
                claimed.batch_id,
                error=error,
                base_delay_seconds=self.settings.forward_base_delay_seconds,
                max_delay_seconds=self.settings.forward_max_delay_seconds,
            )
            return ForwardResult(
                status="retry_scheduled",
                batch_id=claimed.batch_id,
                events=len(claimed.records),
                retry_after_seconds=delay,
                error=error,
            )
        sequences = [int(item["sequence_no"]) for item in observations]
        batch = EdgeBatch(
            batch_id=claimed.batch_id,
            client_id=self.settings.client_id,
            mine_id=self.settings.mine_id,
            sent_at=utc_now(),
            observations=observations,
            local_alerts=alerts,
            sequence_start=min(sequences),
            sequence_end=max(sequences),
            rule_profile={
                "profile_id": self.settings.rule_profile_id,
                "version": self.settings.rule_profile_version,
                "sha256": self.settings.rule_profile_sha256,
            },
        )
        body = batch.to_bytes()
        headers = signature_headers(
            body,
            client_id=self.settings.client_id,
            secret=self.settings.upstream_hmac_secret,
        )
        url = self.upstream_url + INGEST_PATH
        try:
            response = self.transport.post(
                url,
                body,
                headers,
                self.settings.request_timeout_seconds,
            )
            if not isinstance(response, TransportResponse):
                raise ForwardError("上行传输实现未返回状态码和原始回执")
            if not 200 <= response.status < 300:
                raise ForwardError(f"上行返回 HTTP {response.status}")
            try:
                receipt = parse_edge_receipt(
                    response.body,
                    allow_legacy_batch_id=valid_legacy_batch_id(
                        claimed.batch_id,
                        self.settings.client_id,
                    ),
                )
            except ValueError as error:
                raise ForwardError(f"上行 2xx 回执无效：{error}") from error
            expected_sha256 = hashlib.sha256(body).hexdigest()
            if receipt.batch_id != claimed.batch_id:
                raise ForwardError("上行回执 batch_id 与请求不匹配")
            if receipt.client_id != self.settings.client_id:
                raise ForwardError("上行回执 client_id 与请求不匹配")
            if receipt.mine_id != self.settings.mine_id:
                raise ForwardError("上行回执 mine_id 与请求不匹配")
            if not hmac.compare_digest(receipt.body_sha256, expected_sha256):
                raise ForwardError("上行回执 body_sha256 与原始请求体不匹配")
        except ForwardError as error:
            delay = self.repository.mark_batch_failed(
                claimed.batch_id,
                error=str(error),
                base_delay_seconds=self.settings.forward_base_delay_seconds,
                max_delay_seconds=self.settings.forward_max_delay_seconds,
            )
            return ForwardResult(
                status="retry_scheduled",
                batch_id=claimed.batch_id,
                events=len(claimed.records),
                retry_after_seconds=delay,
                error=str(error),
            )
        self.repository.mark_batch_delivered(claimed.batch_id)
        return ForwardResult(
            status="delivered",
            batch_id=claimed.batch_id,
            events=len(claimed.records),
        )

    def flush(self, *, max_batches: int = 20) -> list[ForwardResult]:
        results: list[ForwardResult] = []
        for _ in range(max(1, min(max_batches, 100))):
            result = self.forward_once()
            results.append(result)
            if result.status != "delivered":
                break
        return results
