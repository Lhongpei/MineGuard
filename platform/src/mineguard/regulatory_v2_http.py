"""HTTP boundary for the V2 two-product regulatory workflow.

The leadership surface in this module is deliberately read-only.  Its only
business mutations are authenticated machine-to-machine exchange messages
sent by one mine's independently deployed enterprise agent.
"""

from __future__ import annotations

import base64
import csv
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import mimetypes
import os
from pathlib import Path
import re
from threading import BoundedSemaphore
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, quote, urlsplit
from uuid import NAMESPACE_URL, uuid4, uuid5
from zoneinfo import ZoneInfo

from pydantic import ValidationError

from .auth import (
    CsrfValidationError,
    InvalidCredentialsError,
    InvalidSessionError,
    LocalAuthStore,
    LoginRateLimitedError,
    Principal,
    Role,
    clear_session_cookie_header,
    session_cookie_header,
)
from .exchange_v2 import (
    EXCHANGE_NONCE_RETENTION_SECONDS,
    EnterpriseRiskResponseMessage,
    ExchangeAuthenticationError,
    ExchangeClient,
    ExchangeLineageError,
    FiveQuantitySubmissionMessage,
    RiskDeliveryAckMessage,
    authenticate_transport,
    decode_inbound_message,
    load_exchange_clients,
    sign_exchange_message,
    validate_exchange_lineage,
    verify_exchange_message_signature,
)
from .external_submission import jcs_canonical_json
from .regulatory_v2 import DecisionStatus, METRICS
from .regulatory_v2_store import (
    AnalysisReport,
    AuditProjection,
    ExchangeMessageInput,
    FindingProjection,
    OutboxItem,
    RegulatoryV2ConflictError,
    RegulatoryV2NotFoundError,
    RegulatoryV2Store,
    ResponseBatchReceipt,
)


_SESSION_COOKIE = "mineguard_session"
_MAX_JSON_BYTES = 32 * 1024 * 1024
_UUID_PATH = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
_SUBMISSION_RECEIPT = re.compile(
    rf"^/v2/five-quantity-submissions/(?P<id>{_UUID_PATH})/receipt$"
)
_REPORT = re.compile(rf"^/v2/analysis-reports/(?P<id>{_UUID_PATH})$")
_REPORT_ACK = re.compile(rf"^/v2/analysis-reports/(?P<id>{_UUID_PATH})/delivery-ack$")
_REPORT_RESPONSE = re.compile(rf"^/v2/analysis-reports/(?P<id>{_UUID_PATH})/responses$")
_RESPONSE_RECEIPT = re.compile(rf"^/v2/risk-responses/(?P<id>{_UUID_PATH})/receipt$")
_MINE_DETAIL = re.compile(
    r"^/v2/regulatory/mines/(?P<id>[A-Za-z0-9][A-Za-z0-9._:-]{0,127})$"
)
_OVERVIEW_BUSINESS_EVENT_LIMIT = 8
_OVERVIEW_AUDIT_SCAN_LIMIT = 512
_TRACE_DEFAULT_LIMIT = 20
_TRACE_MAX_LIMIT = 100
_TRACE_EXPORT_LIMIT = 10_000
_TRACE_MINE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TRACE_EVENT_GROUPS: dict[str, frozenset[str]] = {
    "submission": frozenset({"submission_received"}),
    "analysis": frozenset({"analysis_completed"}),
    "finding": frozenset({"finding_automatically_issued", "issued"}),
    "delivery": frozenset(
        {
            "analysis_report_automatically_issued",
            "analysis_report_delivery_acknowledged",
        }
    ),
    "response": frozenset(
        {
            "enterprise_explanation_recorded",
            "enterprise_response_batch_recorded",
            "explanation_recorded",
        }
    ),
    "reanalysis": frozenset(
        {
            "finding_resolved_by_revision_reanalysis",
            "resolved_by_revision",
        }
    ),
    "security": frozenset(
        {"agent_mine_bound", "inbox_idempotency_conflict_rejected"}
    ),
}
_TRACE_BUSINESS_EVENT_TYPES = frozenset().union(*_TRACE_EVENT_GROUPS.values())
_TRACE_EVENT_GROUP_LABELS = {
    "submission": "企业报送",
    "analysis": "政府研判",
    "finding": "风险形成",
    "delivery": "结果送达",
    "response": "企业回复",
    "reanalysis": "修订重算与解除",
    "security": "接入与安全拦截",
    "technical": "技术留痕",
    "system": "系统留痕",
}
_TRACE_STATUS_LABELS = {
    "connected": "连接已建立",
    "received": "已接收",
    "analyzing": "正在研判",
    "normal_candidate": "暂未发现异常",
    "risk": "存在风险线索",
    "insufficient_data": "数据待补充",
    "delivered": "已送达",
    "explanation_recorded": "企业已回复、风险未解除",
    "cleared_by_reanalysis": "修订重算已解除",
    "reference_admitted": "已纳入历史参考",
    "reference_rejected": "未纳入历史参考",
    "updated": "已更新",
    "rejected": "已拦截",
    "information": "已记录",
}


@dataclass(frozen=True)
class _TraceQuery:
    limit: int
    cursor: str | None
    mine_id: str | None
    event_group: str | None
    view: str
    occurred_from: datetime | None
    occurred_before: datetime | None

    def applied_filters(self) -> dict[str, Any]:
        return {
            "view": self.view,
            "event_group": self.event_group,
            "mine_id": self.mine_id,
            "from": (
                None if self.occurred_from is None else _iso(self.occurred_from)
            ),
            "to": (
                None if self.occurred_before is None else _iso(self.occurred_before)
            ),
        }


def _trace_event_group(event_type: str) -> str:
    for group, event_types in _TRACE_EVENT_GROUPS.items():
        if event_type in event_types:
            return group
    if event_type in {
        "exchange_inbound_recorded",
        "exchange_outbound_recorded",
        "anonymous_peer_snapshot_frozen",
        "baseline_candidate_admitted",
        "baseline_candidate_rejected",
    }:
        return "technical"
    return "system"
_BUSINESS_TEXT_LABELS = {
    "ventilation_m3_min": "风量",
    "wind_m3_min": "风量",
    "electricity_kwh": "电量",
    "detonators_count": "火工品量（雷管）",
    "explosives_kg": "火工品量（炸药）",
    "mine_entry_persons": "入井人员量",
    "labor_persons": "入井人员量",
    "production_t": "产量",
    "ventilation_per_production": "单位产量风量",
    "electricity_per_production": "单位产量电耗",
    "detonators_per_production": "单位产量雷管用量",
    "explosives_per_production": "单位产量炸药用量",
    "mine_entry_persons_per_production": "单位产量入井人员量",
    "labor_per_production": "单位产量入井人员量",
    "anonymous_peer": "匿名同类矿",
    "same_mine_history": "本矿历史",
    "within_submission": "本期数据",
    "wire_quality_flags": "报送质量标记",
    "required_metric_completeness": "五量完整性规则",
    "declared_vs_inferred_operating_state": "申报与推断工况",
    "weighted_l1": "加权偏差协调",
    "median_mad": "稳健中位数基线",
    "robust_half_window_median_drift": "窗口中位数漂移",
    "sse_bic_step_vs_linear": "变化点与趋势比较",
    "strict_profile_mcs_diagnostic_not_causation": "最小冲突集诊断",
    "state_aware_context_rule_not_physical_violation": "工况上下文规则",
    "qualified_measurement_requires_review": "测量值需复核",
    "incomplete_five_quantity_days": "五量日数据不完整",
    "soft_reference_interval_exceeded": "超出软参考区间",
    "robust_temporal_outlier": "稳健时序偏离",
    "strict_counterfactual_conflict_set": "最小放宽组合",
}
_LOWER_SNAKE_CASE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?![A-Za-z0-9_])"
)
_DATED_FINDING_CLAUSE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s*(.+)$")


def _humanize_business_text(value: Any) -> str:
    """Render algorithm/storage tokens as controlled government-facing text."""

    rendered = _LOWER_SNAKE_CASE_TOKEN.sub(
        lambda matched: _BUSINESS_TEXT_LABELS.get(
            matched.group(1), "其他业务项"
        ),
        str(value or ""),
    )
    # Prefer whole-phrase translations where a literal acronym replacement
    # would repeat the following Chinese noun (for example, "CUSUM 累积偏移").
    for technical_phrase, business_phrase in (
        ("CUSUM 累积偏移", "持续累积偏移值"),
        ("EWMA 水平", "近期加权均值"),
        ("Page-Hinkley 检测到", "均值变化检测发现"),
        ("median/MAD 基线", "历史稳健基线"),
    ):
        rendered = rendered.replace(technical_phrase, business_phrase)
    for technical_term, business_term in (
        ("CUSUM", "持续累积偏移"),
        ("EWMA", "近期均值越界"),
        ("Page-Hinkley", "均值变化检测"),
        ("median/MAD", "历史稳健范围"),
    ):
        rendered = rendered.replace(technical_term, business_term)
    return re.sub(r"(?<=[\u3400-\u9fff])\s+(?=[\u3400-\u9fff])", "", rendered)


def _humanize_finding_summary(value: Any) -> str:
    rendered = _humanize_business_text(value)
    clauses = [item.strip() for item in rendered.split("；") if item.strip()]
    dated: list[tuple[str, str]] = []
    for clause in clauses:
        matched = _DATED_FINDING_CLAUSE.fullmatch(clause)
        if matched is None:
            return rendered
        body = re.sub(r"^的(?=[\u3400-\u9fff])", "", matched.group(2).strip())
        dated.append((matched.group(1), body))
    if len(dated) < 3:
        return rendered
    groups: dict[str, tuple[int, str]] = {}
    for observed_date, body in dated:
        count, first_date = groups.get(body, (0, observed_date))
        groups[body] = (count + 1, first_date)
    if len(groups) > 3:
        return rendered
    summaries = [
        f"多日出现：{body}" if count > 1 else f"{first_date} {body}"
        for body, (count, first_date) in groups.items()
    ]
    return f"{'；'.join(summaries)}。逐日证据见下方。"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return (
        value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _hash_json(value: Any) -> str:
    return sha256(jcs_canonical_json(value).encode("utf-8")).hexdigest()


def _stable_uuid(label: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"mineguard:v2:{label}"))


def _message_nonce(message_id: str) -> str:
    raw = sha256(f"mineguard:v2:message-nonce:{message_id}".encode()).digest()[:16]
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _semantic_engine_version(method_version: str) -> str:
    matched = re.search(r"v([1-9][0-9]*\.[0-9]+\.[0-9]+)$", method_version)
    if matched is None:
        raise ValueError("algorithm method_version lacks a semantic version suffix")
    return matched.group(1)


def _principal_json(principal: Principal) -> dict[str, Any]:
    return {
        "user_id": principal.user_id,
        "username": principal.username,
        "role": principal.role.value,
        "mine_scopes": list(principal.mine_scopes),
        "business_access": "read_only",
    }


class RegulatoryV2HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        store: RegulatoryV2Store,
        auth_store: LocalAuthStore,
        clients: Mapping[str, ExchangeClient],
        auth_required: bool,
        secure_cookie: bool,
        platform_system_id: str,
        platform_party_id: str,
        platform_key_id: str,
        clock: Callable[[], datetime],
    ) -> None:
        self.store = store
        self.auth_store = auth_store
        self.clients = dict(clients)
        self.auth_required = auth_required
        self.secure_cookie = secure_cookie
        self.platform_system_id = platform_system_id
        self.platform_party_id = platform_party_id
        self.platform_key_id = platform_key_id
        self.clock = clock
        self.integrity_valid = store.verify_integrity()
        self.integrity_checked_at = clock()
        self.analysis_slots = {
            sender_id: BoundedSemaphore(1) for sender_id in self.clients
        }
        self._resources_closed = False
        super().__init__(address, RegulatoryV2RequestHandler)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            if not self._resources_closed:
                self._resources_closed = True
                self.store.close()
                self.auth_store.close()


class RegulatoryV2RequestHandler(BaseHTTPRequestHandler):
    server: RegulatoryV2HTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        super().log_message(format, *args)

    def do_GET(self) -> None:  # noqa: N802
        self._guard(self._dispatch_get)

    def do_HEAD(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/v2/regulatory/exchanges/export.csv" or path.startswith(
            "/v2/analysis-reports"
        ) or path.startswith(
            "/v2/five-quantity-submissions"
        ) or path.startswith("/v2/risk-responses"):
            self._send_empty(405, {"Allow": "GET, POST, OPTIONS"})
            return
        self._guard(lambda: self._dispatch_get(head_only=True))

    def do_POST(self) -> None:  # noqa: N802
        self._guard(self._dispatch_post)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_empty(204, {"Allow": "GET, HEAD, POST, OPTIONS"})

    def _guard(self, operation: Callable[[], None]) -> None:
        try:
            operation()
        except ExchangeAuthenticationError:
            self._send_error(401, "exchange_authentication_failed", "交换认证失败")
        except LoginRateLimitedError as error:
            self._send_error(
                429,
                "login_rate_limited",
                "登录尝试过多，请稍后重试",
                headers={"Retry-After": str(error.retry_after_seconds)},
            )
        except (InvalidCredentialsError, InvalidSessionError):
            self._send_error(401, "authentication_required", "请先登录")
        except CsrfValidationError:
            self._send_error(403, "csrf_failed", "请求校验失败")
        except RegulatoryV2ConflictError as error:
            self._send_error(409, "immutable_conflict", str(error))
        except ExchangeLineageError as error:
            self._send_error(409, "lineage_conflict", str(error))
        except RegulatoryV2NotFoundError:
            self._send_error(404, "not_found", "未找到当前身份可访问的记录")
        except ValidationError as error:
            self._send_error(
                422,
                "contract_validation_failed",
                "报文不符合 V2 契约",
                detail=error.errors(include_url=False),
            )
        except (ValueError, json.JSONDecodeError) as error:
            self._send_error(400, "invalid_request", str(error))
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as error:  # pragma: no cover - defensive HTTP boundary
            self.log_error("unhandled V2 request error: %r", error)
            self._send_error(500, "internal_error", "服务暂时无法完成请求")

    # ------------------------------------------------------------------
    # Routing

    def _dispatch_get(self, *, head_only: bool = False) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/healthz":
            self._send_json(
                200, {"status": "ok", "service": "mineguard-v2"}, head_only=head_only
            )
            return
        if path == "/readyz":
            if not self.server.clients:
                self._send_error(
                    503,
                    "not_ready",
                    "尚未配置任何一矿一智能体交换身份",
                )
                return
            self.server.store.list_mine_overviews()
            self._send_json(
                200,
                {
                    "status": "ready",
                    "service": "mineguard-v2",
                    "configured_mines": len(self.server.clients),
                },
                head_only=head_only,
            )
            return
        if path in {
            "/",
            "/index.html",
            "/wallboard",
            "/assets/app.js",
            "/assets/styles.css",
        }:
            self._serve_static(path, head_only=head_only)
            return
        if path == "/v2/auth/me":
            principal = self._government_principal()
            self._send_json(
                200, {"principal": _principal_json(principal)}, head_only=head_only
            )
            return
        if path == "/v2/auth/csrf":
            if not self.server.auth_required:
                self._send_json(
                    200, {"csrf_token": "local-no-auth"}, head_only=head_only
                )
                return
            token = self._session_token()
            principal, csrf_token = self.server.auth_store.issue_csrf(token)
            self._send_json(
                200,
                {"principal": _principal_json(principal), "csrf_token": csrf_token},
                head_only=head_only,
            )
            return
        if path == "/v2/regulatory/overview":
            principal = self._government_principal()
            self._send_json(200, self._overview(principal), head_only=head_only)
            return
        if path == "/v2/regulatory/mines":
            principal = self._government_principal()
            self._send_json(
                200, {"items": self._mine_rows(principal)}, head_only=head_only
            )
            return
        mine_match = _MINE_DETAIL.fullmatch(path)
        if mine_match:
            principal = self._government_principal()
            self._send_json(
                200,
                self._mine_detail(principal, mine_match.group("id")),
                head_only=head_only,
            )
            return
        if path == "/v2/regulatory/findings":
            principal = self._government_principal()
            limit = self._single_int_query(
                parsed.query, "limit", default=100, maximum=1000
            )
            self._send_json(
                200,
                {"items": self._finding_rows(principal, limit=limit)},
                head_only=head_only,
            )
            return
        if path == "/v2/regulatory/exchanges/export.csv":
            principal = self._government_principal()
            self._export_trace_csv(principal, parsed.query)
            return
        if path == "/v2/regulatory/exchanges":
            principal = self._government_principal()
            self._send_json(200, self._trace_page(principal, parsed.query), head_only=head_only)
            return

        if path == "/v2/analysis-reports/next":
            client = self._machine_auth(
                body=b"", expected_contract="five-quantity-exchange-v2"
            )
            after_cursor = self._single_query(parsed.query, "after_cursor")
            after_sequence = self._cursor_sequence(client.mine_id, after_cursor)
            item = self._next_response_required_report(client.mine_id, after_sequence)
            if item is None:
                self._send_empty(204)
                return
            message = self._analysis_report_message(client, item.aggregate_id, item)
            self._send_json(200, message, head_only=head_only)
            return
        receipt_match = _SUBMISSION_RECEIPT.fullmatch(path)
        if receipt_match:
            self._reject_query(parsed.query)
            client = self._machine_auth(
                body=b"", expected_contract="five-quantity-exchange-v2"
            )
            submission_receipt = self.server.store.get_submission_receipt(
                receipt_match.group("id"), mine_id=client.mine_id
            )
            inbound = self._exchange_message(
                direction="inbound",
                message_type="five_quantity_submission",
                predicate=lambda item: (
                    item.get("message_id") == submission_receipt.submission_id
                ),
                mine_id=client.mine_id,
            )
            assert inbound is not None
            self._send_json(
                200,
                self._intake_receipt_message(client, inbound, submission_receipt),
                head_only=head_only,
            )
            return
        report_match = _REPORT.fullmatch(path)
        if report_match:
            self._reject_query(parsed.query)
            client = self._machine_auth(
                body=b"", expected_contract="five-quantity-exchange-v2"
            )
            self._send_json(
                200,
                self._analysis_report_message(client, report_match.group("id")),
                head_only=head_only,
            )
            return
        response_match = _RESPONSE_RECEIPT.fullmatch(path)
        if response_match:
            self._reject_query(parsed.query)
            client = self._machine_auth(
                body=b"", expected_contract="five-quantity-exchange-v2"
            )
            response_receipt = self.server.store.get_response_batch_receipt(
                response_match.group("id"), mine_id=client.mine_id
            )
            self._send_json(
                200,
                self._response_receipt_message(client, response_receipt),
                head_only=head_only,
            )
            return
        self._send_error(404, "not_found", "接口不存在")

    def _dispatch_post(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/v2/auth/login":
            self._reject_query(parsed.query)
            payload = self._read_json(limit=64 * 1024)
            if not self.server.auth_required:
                self._send_json(
                    200,
                    {
                        "principal": _principal_json(self._no_auth_principal()),
                        "csrf_token": "local-no-auth",
                    },
                )
                return
            result = self.server.auth_store.login(
                str(payload.get("username", "")),
                str(payload.get("password", "")),
                client_id=self.client_address[0],
            )
            max_age = max(
                0,
                int((result.absolute_expires_at - self.server.clock()).total_seconds()),
            )
            self._send_json(
                200,
                {
                    "principal": _principal_json(result.principal),
                    "csrf_token": result.csrf_token,
                },
                headers={
                    "Set-Cookie": session_cookie_header(
                        result.session_token,
                        max_age_seconds=max_age,
                        secure=self.server.secure_cookie,
                        cookie_name=_SESSION_COOKIE,
                    )
                },
            )
            return
        if path == "/v2/auth/logout":
            self._reject_query(parsed.query)
            self._read_body(limit=64 * 1024)
            if self.server.auth_required:
                token = self._session_token()
                self.server.auth_store.validate_csrf(
                    token, self.headers.get("X-CSRF-Token"), method="POST"
                )
                self.server.auth_store.logout(token)
            self._send_empty(
                204,
                {
                    "Set-Cookie": clear_session_cookie_header(
                        secure=self.server.secure_cookie,
                        cookie_name=_SESSION_COOKIE,
                    )
                },
            )
            return

        body = self._read_body()
        if path == "/v2/five-quantity-submissions":
            self._reject_query(parsed.query)
            client = self._machine_auth(body=body)
            decoded = decode_inbound_message(body)
            message = decoded.message
            if not isinstance(message, FiveQuantitySubmissionMessage):
                raise ValueError("this path requires five_quantity_submission")
            self._assert_message_binding(message, client)
            self._validate_governed_context(message, client)
            payload_hash = verify_exchange_message_signature(
                message, client, decoded.document
            )
            self._validate_submission_time(message)
            self._validate_submission_lineage(message, client)
            document = decoded.document
            slot = self.server.analysis_slots[client.sender_id]
            if not slot.acquire(blocking=False):
                self._send_error(
                    429,
                    "analysis_concurrency_limited",
                    "该煤矿已有分析任务正在执行，请稍后按同一幂等键重试",
                    headers={"Retry-After": "2"},
                )
                return
            try:
                submission_receipt = self.server.store.submit_and_analyze(
                    message.to_regulatory_submission(),
                    agent_id=client.sender_id,
                    idempotency_key=message.idempotency_key,
                    exchange_message=ExchangeMessageInput(
                        message_id=message.message_id,
                        direction="inbound",
                        message_type=message.message_type,
                        mine_id=message.mine_id,
                        agent_id=client.sender_id,
                        body=document,
                        exchanged_at=message.created_at,
                    ),
                )
            finally:
                slot.release()
            outbound = self._intake_receipt_message(
                client,
                document,
                submission_receipt,
                received_payload_sha256=payload_hash,
            )
            self._send_json(
                200 if submission_receipt.idempotent_replay else 202, outbound
            )
            return

        ack_match = _REPORT_ACK.fullmatch(path)
        if ack_match:
            self._reject_query(parsed.query)
            client = self._machine_auth(body=body)
            decoded = decode_inbound_message(body)
            message = decoded.message
            if not isinstance(message, RiskDeliveryAckMessage):
                raise ValueError("this path requires risk_delivery_ack")
            self._assert_message_binding(message, client)
            verify_exchange_message_signature(message, client, decoded.document)
            if message.payload.report_id != ack_match.group("id"):
                raise ValueError("path report_id differs from acknowledgement")
            item = self._report_outbox_item(client.mine_id, message.payload.report_id)
            if item.message_id != message.payload.analysis_report_message_id:
                raise ValueError(
                    "acknowledgement does not reference the issued report message"
                )
            issued = self.server.store.get_exchange_message(
                item.message_id, mine_id=client.mine_id, direction="outbound"
            ).body
            validate_exchange_lineage(message, allowed_causes=(issued,))
            self.server.store.record_delivery_ack(
                message.to_store_ack(),
                sender_id=client.sender_id,
                idempotency_key=message.idempotency_key,
                exchange_message=ExchangeMessageInput(
                    message_id=message.message_id,
                    direction="inbound",
                    message_type=message.message_type,
                    mine_id=message.mine_id,
                    agent_id=client.sender_id,
                    body=decoded.document,
                    exchanged_at=message.created_at,
                ),
            )
            self._send_empty(204)
            return

        response_match = _REPORT_RESPONSE.fullmatch(path)
        if response_match:
            self._reject_query(parsed.query)
            client = self._machine_auth(body=body)
            decoded = decode_inbound_message(body)
            message = decoded.message
            if not isinstance(message, EnterpriseRiskResponseMessage):
                raise ValueError("this path requires enterprise_risk_response")
            self._assert_message_binding(message, client)
            verify_exchange_message_signature(message, client, decoded.document)
            if message.payload.report_id != response_match.group("id"):
                raise ValueError("path report_id differs from enterprise response")
            item = self._report_outbox_item(client.mine_id, message.payload.report_id)
            if item.message_id != message.payload.analysis_report_message_id:
                raise ValueError(
                    "response does not reference the issued report message"
                )
            issued = self.server.store.get_exchange_message(
                item.message_id, mine_id=client.mine_id, direction="outbound"
            ).body
            self._validate_response_lineage(message, issued, client)
            self._validate_corrected_submission_references(message, client)
            response_receipt = self.server.store.record_enterprise_response_batch(
                message.payload.response_id,
                message.payload.report_id,
                message.mine_id,
                message.to_store_responses(),
                sender_id=client.sender_id,
                idempotency_key=message.idempotency_key,
                exchange_message=ExchangeMessageInput(
                    message_id=message.message_id,
                    direction="inbound",
                    message_type=message.message_type,
                    mine_id=message.mine_id,
                    agent_id=client.sender_id,
                    body=decoded.document,
                    exchanged_at=message.created_at,
                ),
            )
            outbound = self._response_receipt_message(client, response_receipt)
            self._send_json(
                200 if response_receipt.idempotent_replay else 202, outbound
            )
            return
        self._send_error(404, "not_found", "接口不存在")

    # ------------------------------------------------------------------
    # Authentication and contract binding

    def _machine_auth(
        self,
        *,
        body: bytes,
        expected_contract: str | None = None,
    ) -> ExchangeClient:
        client, request_time, nonce, contract_version = authenticate_transport(
            self.server.clients,
            dict(self.headers.items()),
            method=self.command,
            request_target=self.path,
            body=body,
            now=self.server.clock(),
        )
        if expected_contract is not None and contract_version != expected_contract:
            raise ExchangeAuthenticationError("exchange authentication failed")
        if expected_contract is None:
            try:
                document = json.loads(body)
                body_contract = document["contract_version"]
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise ValueError("POST body lacks contract_version") from error
            if contract_version != body_contract:
                raise ExchangeAuthenticationError("exchange authentication failed")
        expiry = self.server.clock().astimezone(UTC) + timedelta(
            seconds=EXCHANGE_NONCE_RETENTION_SECONDS
        )
        if not self.server.store.claim_transport_nonce(
            client.sender_id,
            nonce,
            request_time=request_time,
            expires_at=expiry,
        ):
            raise ExchangeAuthenticationError("exchange authentication failed")
        return client

    def _assert_message_binding(self, message: Any, client: ExchangeClient) -> None:
        if (
            message.sender.system_id != client.sender_id
            or message.sender.party_id != client.party_id
            or message.sender.role != "enterprise_agent"
            or message.recipient.system_id != self.server.platform_system_id
            or message.recipient.party_id != self.server.platform_party_id
            or message.recipient.role != "regulatory_platform"
            or message.mine_id != client.mine_id
        ):
            raise ExchangeAuthenticationError("exchange authentication failed")

    def _validate_governed_context(
        self,
        message: FiveQuantitySubmissionMessage,
        client: ExchangeClient,
    ) -> None:
        if client.comparison_context is None:
            raise ValueError(
                "government client registry lacks the mine comparison_context"
            )
        if message.payload.comparison_context.model_dump() != dict(
            client.comparison_context
        ):
            raise RegulatoryV2ConflictError(
                "self-reported comparison context differs from government registry"
            )
        if (
            client.mine_name is not None
            and message.payload.mine.mine_name != client.mine_name
        ):
            raise RegulatoryV2ConflictError(
                "self-reported mine name differs from government registry"
            )

    def _validate_submission_lineage(
        self,
        message: FiveQuantitySubmissionMessage,
        client: ExchangeClient,
    ) -> None:
        if message.revision == 1:
            if message.correlation_id != message.message_id:
                raise ExchangeLineageError(
                    "initial submission correlation_id must equal message_id"
                )
            validate_exchange_lineage(message)
            return
        assert message.predecessor is not None
        try:
            predecessor = self.server.store.get_exchange_message(
                message.predecessor.message_id,
                mine_id=client.mine_id,
                direction="inbound",
            ).body
        except RegulatoryV2NotFoundError as error:
            raise ExchangeLineageError(
                "direct predecessor is not a verified submission in this mine"
            ) from error
        if predecessor.get("message_type") != "five_quantity_submission":
            raise ExchangeLineageError(
                "direct predecessor is not a five-quantity submission"
            )
        causes: list[Mapping[str, Any]] = []
        if message.causation_id != message.predecessor.message_id:
            try:
                cause = self.server.store.get_exchange_message(
                    str(message.causation_id), mine_id=client.mine_id
                ).body
            except RegulatoryV2NotFoundError as error:
                raise ExchangeLineageError(
                    "causation_id is not a verified message in this mine"
                ) from error
            if cause.get("message_type") not in {
                "analysis_report",
                "enterprise_risk_response",
                "five_quantity_submission",
            }:
                raise ExchangeLineageError(
                    "causation message type cannot trigger a correction"
                )
            causes.append(cause)
        validate_exchange_lineage(
            message,
            predecessor=predecessor,
            allowed_causes=causes,
        )

    def _validate_response_lineage(
        self,
        message: EnterpriseRiskResponseMessage,
        issued_report: Mapping[str, Any],
        client: ExchangeClient,
    ) -> None:
        if message.revision == 1:
            validate_exchange_lineage(message, allowed_causes=(issued_report,))
            return
        assert message.predecessor is not None
        try:
            predecessor = self.server.store.get_exchange_message(
                message.predecessor.message_id,
                mine_id=client.mine_id,
                direction="inbound",
            ).body
        except RegulatoryV2NotFoundError as error:
            raise ExchangeLineageError(
                "response predecessor is not a verified message in this mine"
            ) from error
        if (
            predecessor.get("message_type") != "enterprise_risk_response"
            or predecessor.get("payload", {}).get("report_id")
            != message.payload.report_id
        ):
            raise ExchangeLineageError(
                "response revision must directly continue the same report response"
            )
        validate_exchange_lineage(
            message,
            predecessor=predecessor,
            allowed_causes=(issued_report,),
        )

    def _validate_submission_time(
        self,
        message: FiveQuantitySubmissionMessage,
    ) -> None:
        now = self.server.clock().astimezone(UTC)
        maximum_future = now + timedelta(minutes=5)
        if (
            message.created_at > maximum_future
            or message.signature_envelope.signed_at > maximum_future
            or message.payload.closed_at > maximum_future
        ):
            raise ValueError("submission contains a future application timestamp")
        local_today = now.astimezone(ZoneInfo(message.payload.timezone)).date()
        if message.payload.period_end > local_today:
            raise ValueError("future reporting periods cannot be analysed")
        last_shift_end = max(
            shift.end_at
            for day in message.payload.days
            for shift in (
                day.reported_quantity.shifts.zero_shift,
                day.reported_quantity.shifts.eight_shift,
                day.reported_quantity.shifts.four_shift,
            )
        )
        if message.payload.closed_at < last_shift_end:
            raise ValueError("report cannot close before its final shift ends")

    def _government_principal(self) -> Principal:
        if not self.server.auth_required:
            return self._no_auth_principal()
        return self.server.auth_store.authenticate(self._session_token())

    @staticmethod
    def _no_auth_principal() -> Principal:
        return Principal(
            user_id="local-no-auth",
            username="local-demo",
            role=Role.ADMIN,
            mine_scopes=(),
            session_id="local-no-auth",
        )

    def _session_token(self) -> str:
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get(_SESSION_COOKIE)
        if morsel is None or not morsel.value:
            raise InvalidSessionError("session token is required")
        return morsel.value

    # ------------------------------------------------------------------
    # Signed outbound messages

    def _base_outbound_message(
        self,
        client: ExchangeClient,
        *,
        contract_version: str,
        message_type: str,
        message_id: str,
        correlation_id: str,
        causation_id: str,
        idempotency_key: str,
        created_at: datetime,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        timestamp = _iso(created_at)
        message = {
            "contract_version": contract_version,
            "message_type": message_type,
            "message_id": message_id,
            "correlation_id": correlation_id,
            "causation_id": causation_id,
            "idempotency_key": idempotency_key,
            "revision": 1,
            "predecessor": None,
            "created_at": timestamp,
            "sender": {
                "system_id": self.server.platform_system_id,
                "party_id": self.server.platform_party_id,
                "role": "regulatory_platform",
            },
            "recipient": {
                "system_id": client.sender_id,
                "party_id": client.party_id,
                "role": "enterprise_agent",
            },
            "mine_id": client.mine_id,
            "payload": payload,
            "signature_envelope": {
                "algorithm": "hmac-sha256-v2",
                "canonicalization": "rfc8785-jcs",
                "key_id": self.server.platform_key_id,
                "signed_at": timestamp,
                "nonce": _message_nonce(message_id),
                "payload_sha256": "0" * 64,
                "signature": "0" * 64,
            },
        }
        return sign_exchange_message(message, client.secret)

    def _intake_receipt_message(
        self,
        client: ExchangeClient,
        inbound: Mapping[str, Any],
        receipt: Any,
        *,
        received_payload_sha256: str | None = None,
    ) -> dict[str, Any]:
        existing = self._exchange_message(
            direction="outbound",
            message_type="intake_receipt",
            predicate=lambda item: (
                item.get("payload", {}).get("submission_message_id")
                == inbound["message_id"]
            ),
            mine_id=client.mine_id,
            required=False,
        )
        if existing is not None:
            return existing
        message_id = _stable_uuid(f"intake-message:{inbound['message_id']}")
        payload = {
            "receipt_id": _stable_uuid(f"intake-receipt:{inbound['message_id']}"),
            "submission_message_id": inbound["message_id"],
            "submission_revision": inbound["revision"],
            "received_payload_sha256": received_payload_sha256
            or inbound["signature_envelope"]["payload_sha256"],
            "received_at": _iso(receipt.received_at),
            "intake_status": "accepted",
            "analysis_state": "queued",
            "regulatory_outcome": "not_determined_at_intake",
            "analysis_run_id": receipt.run_id,
        }
        message = self._base_outbound_message(
            client,
            contract_version="intake-receipt-v2",
            message_type="intake_receipt",
            message_id=message_id,
            correlation_id=inbound["correlation_id"],
            causation_id=inbound["message_id"],
            idempotency_key=f"intake.{inbound['message_id']}",
            created_at=receipt.received_at,
            payload=payload,
        )
        self._record_outbound(client, message, receipt.received_at)
        return message

    def _analysis_report_message(
        self,
        client: ExchangeClient,
        report_id: str,
        outbox_item: OutboxItem | None = None,
    ) -> dict[str, Any]:
        existing = self._exchange_message(
            direction="outbound",
            message_type="analysis_report",
            predicate=lambda item: (
                item.get("payload", {}).get("report_id") == report_id
            ),
            mine_id=client.mine_id,
            required=False,
        )
        if existing is not None:
            return existing
        report = self.server.store.get_analysis_report(
            report_id, mine_id=client.mine_id
        )
        item = outbox_item or self._report_outbox_item(client.mine_id, report_id)
        inbound = self._exchange_message(
            direction="inbound",
            message_type="five_quantity_submission",
            predicate=lambda value: value.get("message_id") == report.submission_id,
            mine_id=client.mine_id,
        )
        assert inbound is not None
        result = report.result
        run_metadata = self.server.store.get_run_metadata(report.run_id)
        history_bands = [
            item.model_dump(mode="json")
            for item in result.references.accepted_history_bands
        ]
        peer_bands = [
            item.model_dump(mode="json")
            for item in result.references.accepted_peer_bands
        ]
        payload = {
            "report_id": report.report_id,
            "submission_message_id": report.submission_id,
            "submission_revision": inbound["revision"],
            "mine": inbound["payload"]["mine"],
            "reporting_month": inbound["payload"]["reporting_month"],
            "period_start": inbound["payload"]["period_start"],
            "period_end": inbound["payload"]["period_end"],
            "issued_at": _iso(report.issued_at),
            "algorithm": {
                "engine_id": "mineguard-five-quantity-engine",
                "engine_version": _semantic_engine_version(result.method_version),
                "algorithm_run_id": report.run_id,
                "config_sha256": result.configuration_sha256,
                "input_snapshot_sha256": result.algorithm_input_sha256,
                "own_history_snapshot_sha256": (
                    _hash_json(history_bands) if history_bands else None
                ),
                "peer_snapshot_sha256": _hash_json(peer_bands) if peer_bands else None,
                "started_at": _iso(
                    datetime.fromisoformat(run_metadata["started_at"])
                ),
                "completed_at": _iso(
                    datetime.fromisoformat(run_metadata["completed_at"])
                ),
                "modules": [
                    "data_quality",
                    "daily_shift_reconciliation",
                    "l1_reconciliation",
                    "minimal_conflict_set",
                    "robust_temporal_baseline",
                    "past_only_rolling_mad",
                    "past_only_ewma",
                    "past_only_cusum",
                    "past_only_page_hinkley",
                    "temporal_drift",
                    "change_point",
                    "operating_state_segmentation",
                    "anonymous_peer_baseline",
                    "evidence_calibration",
                ],
            },
            "outcome": (
                "data_insufficient"
                if report.outcome is DecisionStatus.INSUFFICIENT_DATA
                else report.outcome.value
            ),
            "summary": ("；".join(result.decision_reasons) or "分析完成")[:4000],
            "findings": [
                self._wire_finding(finding_id, report)
                for finding_id in report.finding_ids
            ],
            "response_required": report.response_required,
            "response_due_at": (
                _iso(report.issued_at + timedelta(days=3))
                if report.response_required
                else None
            ),
            "delivery_cursor": report.delivery_cursor,
        }
        message = self._base_outbound_message(
            client,
            contract_version="analysis-report-v2",
            message_type="analysis_report",
            message_id=item.message_id,
            correlation_id=inbound["correlation_id"],
            causation_id=inbound["message_id"],
            idempotency_key=f"analysis.{report.report_id}",
            created_at=report.issued_at,
            payload=payload,
        )
        self._record_outbound(client, message, report.issued_at)
        return message

    def _wire_finding(self, finding_id: str, report: AnalysisReport) -> dict[str, Any]:
        projection = self.server.store.get_finding(finding_id, mine_id=report.mine_id)
        finding = projection.finding
        result = finding.result
        if finding.category == "data_quality":
            signals = list(result.data_quality_signals)
            category = "data_quality"
        elif finding.category == "relationship_consistency":
            signals = list(result.relationship_signals)
            category = "joint_consistency"
        elif finding.category == "temporal_pattern":
            signals = list(result.temporal_signals)
            category = "temporal_anomaly"
        else:
            signals = list(result.data_quality_signals)
            category = "data_quality"
        evidence: list[dict[str, Any]] = []
        for index, signal in enumerate(signals[:100], start=1):
            core = {
                "method": self._evidence_method(signal.code, signal.basis),
                "summary": signal.message[:2000],
                "observed_value": signal.observed,
                "expected_min": signal.expected_lower,
                "expected_max": signal.expected_upper,
                "score": None,
            }
            evidence.append(
                {
                    "evidence_id": f"EV-{finding_id[:8]}-{index:03d}",
                    **core,
                    "evidence_sha256": _hash_json(core),
                }
            )
        if not evidence:
            for index, reason in enumerate(finding.decision_reasons[:100], start=1):
                core = {
                    "method": "data_completeness"
                    if finding.finding_type == "data_insufficient"
                    else "combined_calibration",
                    "summary": reason[:2000],
                    "observed_value": None,
                    "expected_min": None,
                    "expected_max": None,
                    "score": None,
                }
                evidence.append(
                    {
                        "evidence_id": f"EV-{finding_id[:8]}-{index:03d}",
                        **core,
                        "evidence_sha256": _hash_json(core),
                    }
                )
        dates = sorted(
            {signal.date.isoformat() for signal in signals if signal.date is not None}
        ) or [
            self.server.store.get_submission(
                report.submission_id
            ).period_end.isoformat()
        ]
        metrics = sorted(
            {signal.metric for signal in signals if signal.metric in METRICS}
        ) or list(METRICS)
        return {
            "finding_id": finding.finding_id,
            "category": category,
            "severity": "medium"
            if finding.finding_type == "data_insufficient"
            else "high",
            "title": finding.title[:256],
            "summary": finding.summary[:4000] or "需要企业核对并回复",
            "affected_dates": dates,
            "affected_shifts": [],
            "affected_metrics": metrics,
            "evidence": evidence,
            "requires_response": True,
        }

    @staticmethod
    def _evidence_method(code: str, basis: str) -> str:
        text = f"{code} {basis}".lower()
        if "complet" in text or "missing" in text:
            return "data_completeness"
        if "shift" in text or "daily" in text:
            return "deterministic_reconciliation"
        if "rolling_mad" in text:
            return "past_only_rolling_mad"
        if "page_hinkley" in text:
            return "past_only_page_hinkley"
        if "cusum" in text:
            return "past_only_cusum"
        if "ewma" in text:
            return "past_only_ewma"
        if "change" in text:
            return "change_point"
        if "drift" in text:
            return "temporal_drift"
        if "peer" in text:
            return "anonymous_peer_baseline"
        if "history" in text or "temporal" in text:
            return "robust_temporal_baseline"
        return "l1_reconciliation"

    def _response_receipt_message(
        self,
        client: ExchangeClient,
        receipt: ResponseBatchReceipt,
    ) -> dict[str, Any]:
        existing = self._exchange_message(
            direction="outbound",
            message_type="response_receipt",
            predicate=lambda item: (
                item.get("payload", {}).get("response_id") == receipt.wire_response_id
            ),
            mine_id=client.mine_id,
            required=False,
        )
        if existing is not None:
            return existing
        inbound = self._exchange_message(
            direction="inbound",
            message_type="enterprise_risk_response",
            predicate=lambda item: (
                item.get("payload", {}).get("response_id") == receipt.wire_response_id
            ),
            mine_id=client.mine_id,
        )
        assert inbound is not None
        corrected = [
            item.get("corrected_submission_message_id")
            for item in inbound["payload"]["finding_responses"]
            if item.get("corrected_submission_message_id") is not None
        ]
        reanalysis_run_id: str | None = None
        if corrected:
            reanalysis_run_id = self.server.store.get_submission_receipt(
                corrected[0], mine_id=client.mine_id
            ).run_id
            disposition = "reanalysis_completed"
        elif all(
            item["response_kind"] == "clarification_request"
            for item in inbound["payload"]["finding_responses"]
        ):
            disposition = "clarification_recorded"
        else:
            disposition = "explanation_recorded"
        message_id = _stable_uuid(
            f"response-receipt-message:{receipt.wire_response_id}"
        )
        payload = {
            "receipt_id": _stable_uuid(f"response-receipt:{receipt.wire_response_id}"),
            "enterprise_response_message_id": inbound["message_id"],
            "response_id": receipt.wire_response_id,
            "report_id": receipt.report_id,
            "recorded_at": _iso(receipt.recorded_at),
            "receipt_status": "accepted",
            "disposition": disposition,
            "risk_status": "not_cleared_by_receipt",
            "accepted_finding_ids": receipt.finding_ids,
            "reanalysis_run_id": reanalysis_run_id,
        }
        message = self._base_outbound_message(
            client,
            contract_version="response-receipt-v2",
            message_type="response_receipt",
            message_id=message_id,
            correlation_id=inbound["correlation_id"],
            causation_id=inbound["message_id"],
            idempotency_key=f"response-receipt.{receipt.wire_response_id}",
            created_at=receipt.recorded_at,
            payload=payload,
        )
        self._record_outbound(client, message, receipt.recorded_at)
        return message

    def _record_outbound(
        self,
        client: ExchangeClient,
        message: dict[str, Any],
        exchanged_at: datetime,
    ) -> None:
        self.server.store.record_exchange_message(
            ExchangeMessageInput(
                message_id=message["message_id"],
                direction="outbound",
                message_type=message["message_type"],
                mine_id=client.mine_id,
                agent_id=client.sender_id,
                body=message,
                exchanged_at=exchanged_at,
            )
        )

    def _validate_corrected_submission_references(
        self,
        response: EnterpriseRiskResponseMessage,
        client: ExchangeClient,
    ) -> None:
        report = self.server.store.get_analysis_report(
            response.payload.report_id, mine_id=client.mine_id
        )
        corrected_references = {
            item.corrected_submission_message_id
            for item in response.payload.finding_responses
            if item.corrected_submission_message_id is not None
        }
        if len(corrected_references) > 1:
            raise RegulatoryV2ConflictError(
                "one enterprise response may reference only one corrected "
                "submission; send separate response revisions otherwise"
            )
        for item in response.payload.finding_responses:
            reference = item.corrected_submission_message_id
            if reference is None:
                continue
            self.server.store.get_submission_receipt(reference, mine_id=client.mine_id)
            corrected = self._exchange_message(
                direction="inbound",
                message_type="five_quantity_submission",
                predicate=lambda message: message.get("message_id") == reference,
                mine_id=client.mine_id,
            )
            assert corrected is not None
            if corrected["correlation_id"] != response.correlation_id:
                raise RegulatoryV2ConflictError(
                    "corrected submission belongs to another workflow"
                )
            if not self.server.store.is_strict_submission_descendant(
                reference,
                report.submission_id,
                mine_id=client.mine_id,
            ):
                raise RegulatoryV2ConflictError(
                    "corrected submission must be a higher-revision descendant "
                    "of the report submission"
                )

    # ------------------------------------------------------------------
    # Store lookup helpers

    def _exchange_message(
        self,
        *,
        direction: str,
        message_type: str,
        predicate: Callable[[dict[str, Any]], bool],
        mine_id: str,
        required: bool = True,
    ) -> dict[str, Any] | None:
        cursor = 0
        while True:
            rows = self.server.store.list_exchange_messages(
                mine_id=mine_id,
                direction=direction,  # type: ignore[arg-type]
                after_sequence=cursor,
                limit=1000,
            )
            for row in rows:
                if row.message_type == message_type and predicate(row.body):
                    return row.body
            if len(rows) < 1000:
                break
            cursor = rows[-1].sequence
        if required:
            raise RegulatoryV2NotFoundError("signed exchange message not found")
        return None

    def _report_outbox_item(self, mine_id: str, report_id: str) -> OutboxItem:
        cursor = 0
        while True:
            page = self.server.store.poll_analysis_reports(
                mine_id, after_sequence=cursor, limit=1000
            )
            for item in page.items:
                if item.aggregate_id == report_id:
                    return item
            if not page.has_more:
                break
            cursor = page.next_cursor
        raise RegulatoryV2NotFoundError("analysis report not found in outbox scope")

    def _next_response_required_report(
        self,
        mine_id: str,
        after_sequence: int,
    ) -> OutboxItem | None:
        cursor = after_sequence
        while True:
            page = self.server.store.poll_analysis_reports(
                mine_id, after_sequence=cursor, limit=1000
            )
            for item in page.items:
                if bool(item.payload.get("response_required")):
                    return item
            if not page.has_more:
                return None
            cursor = page.next_cursor

    @staticmethod
    def _cursor_sequence(mine_id: str, value: str | None) -> int:
        if value is None:
            return 0
        prefix = f"v2.{sha256(mine_id.encode()).hexdigest()[:12]}."
        suffix = value.removeprefix(prefix)
        if not value.startswith(prefix) or len(suffix) != 20 or not suffix.isdigit():
            raise ValueError("after_cursor is not valid for the authenticated mine")
        return int(suffix)

    # ------------------------------------------------------------------
    # Government read-only projections

    def _visible_mines(self, principal: Principal) -> set[str] | None:
        return None if principal.role is Role.ADMIN else set(principal.mine_scopes)

    def _mine_rows(self, principal: Principal) -> list[dict[str, Any]]:
        visible = self._visible_mines(principal)
        overview_by_id = {
            item.mine_id: item for item in self.server.store.list_mine_overviews()
        }
        client_by_mine = {item.mine_id: item for item in self.server.clients.values()}
        mine_ids = set(overview_by_id) | set(client_by_mine)
        if visible is not None:
            mine_ids &= visible
        rows: list[dict[str, Any]] = []
        for mine_id in sorted(mine_ids):
            overview = overview_by_id.get(mine_id)
            client = client_by_mine.get(mine_id)
            if overview is None:
                rows.append(
                    {
                        "mine_id": mine_id,
                        "mine_name": (client.mine_name if client else None) or mine_id,
                        "status": "not_reported",
                        "completeness_rate": 0.0,
                        "finding_count": 0,
                        "response_status": "—",
                        "trend": [],
                        "data_as_of": None,
                    }
                )
                continue
            detail = self.server.store.mine_detail_projection(mine_id, limit=100)
            latest_report = (
                detail.analysis_reports[0] if detail.analysis_reports else None
            )
            coverage = (
                latest_report.result.coverage if latest_report is not None else None
            )
            facts = sorted(detail.daily_facts, key=lambda item: item["date"])[-30:]
            rows.append(
                {
                    "mine_id": mine_id,
                    "mine_name": overview.mine_name,
                    "report_month": (
                        overview.latest_period_end.strftime("%Y-%m")
                        if overview.latest_period_end
                        else None
                    ),
                    "status": (
                        overview.latest_decision.value
                        if overview.latest_decision is not None
                        else "not_reported"
                    ),
                    "completeness_rate": (
                        coverage.completeness_ratio if coverage is not None else 0.0
                    ),
                    "finding_count": (
                        overview.open_finding_count
                        + overview.explanation_recorded_finding_count
                    ),
                    "open_finding_count": overview.open_finding_count,
                    "response_status": (
                        "open"
                        if overview.open_finding_count
                        else "explanation_recorded"
                        if overview.explanation_recorded_finding_count
                        else "—"
                    ),
                    "data_as_of": (
                        overview.latest_period_end.isoformat()
                        if overview.latest_period_end
                        else None
                    ),
                    "updated_at": (
                        _iso(overview.latest_audit_at)
                        if overview.latest_audit_at is not None
                        else None
                    ),
                    "trend": [item.get("production_t") for item in facts],
                }
            )
        return rows

    def _overview(self, principal: Principal) -> dict[str, Any]:
        rows = self._mine_rows(principal)
        visible = self._visible_mines(principal)
        finding_counts = self.server.store.finding_summary_counts(
            mine_ids=sorted(visible) if visible is not None else None
        )
        counts = {
            "configured_mines": len(rows),
            "reporting_mines": sum(item["status"] != "not_reported" for item in rows),
            "normal_candidate": sum(
                item["status"] == "normal_candidate" for item in rows
            ),
            "risk": sum(item["status"] == "risk" for item in rows),
            "insufficient_data": sum(
                item["status"] == "insufficient_data" for item in rows
            ),
            "awaiting_response": finding_counts["open"],
            "overdue": 0,
        }
        attention_counts = {
            "risk_findings": finding_counts["risk"],
            "data_to_complete": finding_counts["data_insufficient"],
            "awaiting_enterprise_response": finding_counts["open"],
            "enterprise_responded_unresolved": finding_counts["explanation_recorded"],
            "cleared_by_reanalysis": finding_counts["cleared_by_reanalysis"],
            "total_unresolved": (
                finding_counts["risk"] + finding_counts["data_insufficient"]
            ),
        }
        mine_names = {item["mine_id"]: item["mine_name"] for item in rows}
        events = self._latest_business_events(
            principal,
            mine_names=mine_names,
            limit=_OVERVIEW_BUSINESS_EVENT_LIMIT,
        )
        return {
            "counts": counts,
            "attention_counts": attention_counts,
            "as_of": _iso(self.server.clock()),
            "latest_events": events,
        }

    def _latest_business_events(
        self,
        principal: Principal,
        *,
        mine_names: Mapping[str, str],
        limit: int,
    ) -> list[dict[str, Any]]:
        """Project raw audit traffic into a short list of business milestones.

        One submission produces several transport, analysis, baseline and report
        audit rows in a single transaction.  The leadership overview scans well
        beyond its display limit, groups those rows by business milestone and
        exposes only the result that a regulator needs to read.  The underlying
        exchange/audit endpoint remains available for the complete machine trace.
        """

        events = self._audit_events(
            principal,
            limit=max(_OVERVIEW_AUDIT_SCAN_LIMIT, limit * 32),
        )
        grouped: dict[tuple[str, str, str], list[AuditProjection]] = {}
        for event in events:
            key = self._business_event_key(event)
            if key is not None:
                grouped.setdefault(key, []).append(event)

        projected: list[tuple[int, dict[str, Any]]] = []
        for group in grouped.values():
            row = self._business_event_projection(group, mine_names=mine_names)
            if row is not None:
                projected.append((max(item.sequence for item in group), row))
        projected.sort(key=lambda item: item[0], reverse=True)
        return [row for _, row in projected[:limit]]

    @staticmethod
    def _business_event_key(
        item: AuditProjection,
    ) -> tuple[str, str, str] | None:
        mine_id = item.mine_id or ""
        payload = item.payload
        if item.event_type in {
            "submission_received",
            "analysis_completed",
            "finding_automatically_issued",
            "analysis_report_automatically_issued",
        }:
            submission_id = payload.get("submission_id")
            if submission_id is None and item.event_type == "submission_received":
                submission_id = item.aggregate_id
            return ("analysis", mine_id, str(submission_id or item.aggregate_id))
        if item.event_type in {
            "enterprise_explanation_recorded",
            "enterprise_response_batch_recorded",
        }:
            return ("enterprise_response", mine_id, item.aggregate_id)
        if item.event_type == "analysis_report_delivery_acknowledged":
            return ("delivery", mine_id, item.aggregate_id)
        if item.event_type == "finding_resolved_by_revision_reanalysis":
            resolving_submission_id = payload.get("resolving_submission_id")
            return (
                "analysis",
                mine_id,
                str(resolving_submission_id or item.aggregate_id),
            )
        if item.event_type == "inbox_idempotency_conflict_rejected":
            return ("rejected_exchange", mine_id, item.aggregate_id)
        return None

    def _business_event_projection(
        self,
        events: list[AuditProjection],
        *,
        mine_names: Mapping[str, str],
    ) -> dict[str, Any] | None:
        by_type: dict[str, list[AuditProjection]] = {}
        for event in events:
            by_type.setdefault(event.event_type, []).append(event)

        resolutions = by_type.get("finding_resolved_by_revision_reanalysis", [])
        if resolutions:
            return self._presented_audit_row(
                resolutions[0],
                mine_names=mine_names,
                event_label="风险已解除",
                status="cleared_by_reanalysis",
                summary=(
                    "修订数据经同一算法重新分析通过，"
                    f"{len(resolutions)} 项相关风险已解除。"
                ),
            )

        report = next(
            iter(by_type.get("analysis_report_automatically_issued", [])), None
        )
        analysis = next(iter(by_type.get("analysis_completed", [])), None)
        submission = next(iter(by_type.get("submission_received", [])), None)
        finding_events = by_type.get("finding_automatically_issued", [])
        if report is not None or analysis is not None or submission is not None:
            anchor = report or analysis or submission
            assert anchor is not None
            decision = (
                report.payload.get("outcome") if report is not None else None
            ) or (analysis.payload.get("decision") if analysis is not None else None)
            finding_ids = report.payload.get("finding_ids") if report else None
            finding_count = max(
                len(finding_events),
                len(finding_ids) if isinstance(finding_ids, list) else 0,
            )
            if decision == "risk":
                event_label = "发现风险线索"
                status = "risk"
                summary = (
                    f"本期五量数据研判发现 {finding_count} 项风险线索，"
                    "等待企业核实或提交修订数据。"
                    if finding_count
                    else "本期五量数据研判发现风险线索，等待企业核实或提交修订数据。"
                )
            elif decision == "insufficient_data":
                event_label = "数据待补充"
                status = "insufficient_data"
                summary = (
                    "本期数据不完整，暂不能作出判断；"
                    f"已形成 {finding_count} 项数据补充要求。"
                    if finding_count
                    else "本期数据不完整，暂不能作出判断，请企业补充或核对数据。"
                )
            elif decision == "normal_candidate":
                event_label = "研判完成"
                status = "normal_candidate"
                summary = "本期五量数据研判完成，暂未发现需要企业核实的风险线索。"
            elif finding_events:
                event_label = "形成待核事项"
                finding_type = finding_events[0].payload.get("finding_type")
                status = (
                    "insufficient_data"
                    if finding_type == "data_insufficient"
                    else "risk"
                )
                summary = f"系统已形成 {len(finding_events)} 项待企业核实事项。"
            else:
                event_label = "数据已接收"
                status = "analyzing"
                revision = submission.payload.get("revision") if submission else None
                summary = (
                    f"已收到企业提交的第 {revision} 版修订数据，系统正在重新分析。"
                    if isinstance(revision, int) and revision > 1
                    else "已收到企业本期五量数据，系统正在分析。"
                )
            return self._presented_audit_row(
                anchor,
                mine_names=mine_names,
                event_label=event_label,
                status=status,
                summary=summary,
            )

        response_batch = next(
            iter(by_type.get("enterprise_response_batch_recorded", [])), None
        )
        explanation = next(
            iter(by_type.get("enterprise_explanation_recorded", [])), None
        )
        if response_batch is not None or explanation is not None:
            anchor = response_batch or explanation
            assert anchor is not None
            finding_ids = anchor.payload.get("finding_ids")
            count = len(finding_ids) if isinstance(finding_ids, list) else 1
            return self._presented_audit_row(
                anchor,
                mine_names=mine_names,
                event_label="企业已回复",
                status="explanation_recorded",
                summary=(
                    f"企业已回复 {count} 项待核实事项；说明已追加留痕，"
                    "相关风险尚未解除。"
                ),
            )

        delivery = next(
            iter(by_type.get("analysis_report_delivery_acknowledged", [])), None
        )
        if delivery is not None:
            return self._presented_audit_row(
                delivery,
                mine_names=mine_names,
                event_label="企业已收悉",
                status="delivered",
                summary="企业端已确认收到本次研判结果。",
            )

        rejected = next(
            iter(by_type.get("inbox_idempotency_conflict_rejected", [])), None
        )
        if rejected is not None:
            return self._presented_audit_row(
                rejected,
                mine_names=mine_names,
                event_label="冲突报送已拦截",
                status="rejected",
                summary=(
                    "同一业务编号对应了不同报送内容，本笔数据已拒收且未进入分析。"
                ),
            )
        return None

    def _presented_audit_row(
        self,
        item: AuditProjection,
        *,
        mine_names: Mapping[str, str],
        event_label: str,
        status: str,
        summary: str,
    ) -> dict[str, Any]:
        row = self._audit_row(item)
        row.update(
            {
                "mine_name": mine_names.get(
                    item.mine_id or "", item.mine_id or "辖区系统"
                ),
                "event_label": event_label,
                "status": status,
                "summary": summary,
                "integrity_valid": self.server.integrity_valid,
            }
        )
        return row

    def _mine_detail(self, principal: Principal, mine_id: str) -> dict[str, Any]:
        visible = self._visible_mines(principal)
        if visible is not None and mine_id not in visible:
            raise RegulatoryV2NotFoundError("mine is outside principal scope")
        detail = self.server.store.mine_detail_projection(mine_id, limit=200)
        report = detail.analysis_reports[0] if detail.analysis_reports else None
        latest_run = detail.runs[0] if detail.runs else {}
        latest_submission = detail.submissions[0] if detail.submissions else {}
        findings = [self._finding_projection(item) for item in detail.findings]
        responses = [
            response.model_dump(mode="json")
            for item in detail.findings
            for response in item.responses
        ]
        result = report.result if report is not None else None
        return {
            "mine": {
                "mine_id": detail.overview.mine_id,
                "mine_name": detail.overview.mine_name,
                "status": (
                    detail.overview.latest_decision.value
                    if detail.overview.latest_decision is not None
                    else "not_reported"
                ),
                "data_as_of": (
                    detail.overview.latest_period_end.isoformat()
                    if detail.overview.latest_period_end
                    else None
                ),
            },
            "latest_submission": {
                **latest_submission,
                "report_month": str(latest_submission.get("period_end", ""))[:7],
                "data_as_of": latest_submission.get("period_end"),
            },
            "latest_analysis": {
                "status": result.decision.value if result else None,
                "algorithm_version": result.method_version if result else None,
                "configuration_sha256": result.configuration_sha256 if result else None,
                "solver_status": (
                    f"{result.reconciliation.solver_status} · "
                    f"{','.join(result.reconciliation.solver_methods_attempted)} · "
                    f"MCS {len(result.reconciliation.minimal_conflict_sets)} 组"
                    if result
                    else None
                ),
                "temporal_status": (
                    f"{len(result.temporal_signals)} 条时序信号" if result else None
                ),
                "peer_sample_count": (
                    max(
                        (
                            item.mine_count or 0
                            for item in result.references.accepted_peer_bands
                        ),
                        default=0,
                    )
                    if result
                    else 0
                ),
                "baseline_eligible": (
                    bool(latest_run.get("baseline_eligible"))
                    if latest_run.get("baseline_eligible") is not None
                    else None
                ),
                "baseline_reference_candidate": (
                    bool(latest_run.get("baseline_reference_candidate"))
                    if latest_run.get("baseline_reference_candidate") is not None
                    else None
                ),
                "baseline_rule_version": latest_run.get("baseline_rule_version"),
            },
            "response_summary": {
                "open": sum(item["state"] == "open" for item in findings),
                "delivered": sum(
                    event.event_type == "analysis_report_delivery_acknowledged"
                    for event in detail.audit_events
                ),
                "replied": len(responses),
                "last_response_at": next(
                    (
                        _iso(event.occurred_at)
                        for event in reversed(detail.audit_events)
                        if "response" in event.event_type
                    ),
                    None,
                ),
            },
            "daily_series": [
                {**item, "wind_m3_min": item.get("ventilation_m3_min")}
                for item in sorted(detail.daily_facts, key=lambda value: value["date"])
            ],
            "findings": findings,
            "responses": responses,
            "timeline": [
                {
                    **self._audit_row(item),
                    "mine_name": detail.overview.mine_name,
                }
                for item in reversed(detail.audit_events)
            ],
        }

    def _finding_rows(
        self, principal: Principal, *, limit: int
    ) -> list[dict[str, Any]]:
        visible = self._visible_mines(principal)
        if visible is None:
            projections = self.server.store.list_findings(limit=limit)
        else:
            projections = [
                finding
                for mine_id in visible
                for finding in self.server.store.list_findings(
                    mine_id=mine_id, limit=limit
                )
            ]
            projections.sort(
                key=lambda item: (
                    item.finding.issued_at,
                    item.finding.finding_id,
                ),
                reverse=True,
            )
            projections = projections[:limit]
        rows = [self._finding_projection(item) for item in projections]
        mine_names = {
            item.mine_id: item.mine_name
            for item in self.server.store.list_mine_overviews()
        }
        for item in rows:
            item["mine_name"] = mine_names.get(item["mine_id"], item["mine_id"])
        return rows

    @staticmethod
    def _finding_projection(item: FindingProjection) -> dict[str, Any]:
        finding = item.finding
        # A card only explains the category that created it.  Mixing every
        # signal from the same analysis run made, for example, a time-series
        # risk appear to be caused by an unrelated data-format warning.
        signals_by_category = {
            "data_quality": finding.result.data_quality_signals,
            "data_completeness": finding.result.data_quality_signals,
            "relationship_consistency": finding.result.relationship_signals,
            "temporal_pattern": finding.result.temporal_signals,
        }
        signals = signals_by_category.get(finding.category, ())
        return {
            "finding_id": finding.finding_id,
            "mine_id": finding.mine_id,
            "finding_type": finding.finding_type,
            # Kept for older API consumers. The leadership UI uses finding_type
            # because risk/data-insufficient are categories, not audited grades.
            "severity": "medium"
            if finding.finding_type == "data_insufficient"
            else "high",
            "category": finding.category,
            "title": _humanize_business_text(finding.title),
            "summary": _humanize_finding_summary(finding.summary),
            "state": item.state,
            "issued_at": _iso(finding.issued_at),
            "evidence": [
                _humanize_business_text(signal.message) for signal in signals[:20]
            ],
            "response_count": len(item.responses),
            "resolved_by_submission_id": item.resolved_by_submission_id,
        }

    def _audit_events(
        self, principal: Principal, *, limit: int
    ) -> list[AuditProjection]:
        visible = self._visible_mines(principal)
        if visible is None:
            return self.server.store.list_audit_events(limit=limit, newest_first=True)
        rows = [
            event
            for mine_id in sorted(visible)
            for event in self.server.store.list_audit_events(
                mine_id=mine_id, limit=limit, newest_first=True
            )
        ]
        rows.sort(key=lambda item: item.sequence, reverse=True)
        return rows[:limit]

    def _mine_name_map(self, principal: Principal) -> dict[str, str]:
        visible = self._visible_mines(principal)
        names = {
            item.mine_id: item.mine_name
            for item in self.server.store.list_mine_overviews()
            if visible is None or item.mine_id in visible
        }
        for client in self.server.clients.values():
            if visible is None or client.mine_id in visible:
                names.setdefault(client.mine_id, client.mine_name or client.mine_id)
        return names

    def _trace_rows(self, principal: Principal, *, limit: int) -> list[dict[str, Any]]:
        rows = self._audit_events(principal, limit=limit)
        mine_names = self._mine_name_map(principal)
        return [
            {
                **self._audit_row(item),
                "mine_name": mine_names.get(
                    item.mine_id or "", item.mine_id or "辖区系统"
                ),
                "integrity_valid": self.server.integrity_valid,
            }
            for item in rows
        ]

    @staticmethod
    def _parse_trace_timestamp(value: str, name: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{name} must be an RFC3339 timestamp") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(f"{name} must include a timezone")
        return parsed.astimezone(UTC)

    @classmethod
    def _parse_trace_query(cls, query: str, *, for_export: bool) -> _TraceQuery:
        allowed = {"mine_id", "event_group", "view", "from", "to"}
        if not for_export:
            allowed.update({"limit", "cursor"})
        pairs = (
            parse_qsl(query, keep_blank_values=True, strict_parsing=True)
            if query
            else []
        )
        values: dict[str, str] = {}
        for key, value in pairs:
            if key not in allowed:
                raise ValueError(f"unsupported trace query parameter: {key}")
            if key in values:
                raise ValueError(f"trace query parameter is repeated: {key}")
            if not value:
                raise ValueError(f"{key} cannot be empty")
            values[key] = value

        raw_limit = values.get("limit")
        if raw_limit is None:
            limit = _TRACE_EXPORT_LIMIT if for_export else _TRACE_DEFAULT_LIMIT
        else:
            try:
                limit = int(raw_limit)
            except ValueError as error:
                raise ValueError("limit must be an integer") from error
            if not 1 <= limit <= _TRACE_MAX_LIMIT:
                raise ValueError("limit is outside the allowed range")

        view = values.get("view", "business")
        if view not in {"business", "technical"}:
            raise ValueError("view must be business or technical")
        event_group = values.get("event_group")
        if event_group is not None and event_group not in _TRACE_EVENT_GROUPS:
            raise ValueError("event_group is not supported")
        mine_id = values.get("mine_id")
        if mine_id is not None and _TRACE_MINE_ID.fullmatch(mine_id) is None:
            raise ValueError("mine_id has an invalid format")
        cursor = values.get("cursor")
        if cursor is not None and len(cursor) > 1024:
            raise ValueError("cursor is too long")

        occurred_from = (
            None
            if values.get("from") is None
            else cls._parse_trace_timestamp(values["from"], "from")
        )
        occurred_before = (
            None
            if values.get("to") is None
            else cls._parse_trace_timestamp(values["to"], "to")
        )
        if occurred_from is not None and occurred_before is not None:
            if occurred_from >= occurred_before:
                raise ValueError("from must be earlier than to")
            if occurred_before - occurred_from > timedelta(days=366):
                raise ValueError("trace time window cannot exceed 366 days")
        if for_export and (occurred_from is None or occurred_before is None):
            raise ValueError("export requires both from and to")
        return _TraceQuery(
            limit=limit,
            cursor=cursor,
            mine_id=mine_id,
            event_group=event_group,
            view=view,
            occurred_from=occurred_from,
            occurred_before=occurred_before,
        )

    def _trace_scope(
        self, principal: Principal, mine_id: str | None
    ) -> tuple[str, ...] | None:
        visible = self._visible_mines(principal)
        if mine_id is not None:
            if visible is not None and mine_id not in visible:
                raise RegulatoryV2NotFoundError("mine is outside principal scope")
            return (mine_id,)
        return None if visible is None else tuple(sorted(visible))

    @staticmethod
    def _trace_event_types(query: _TraceQuery) -> tuple[str, ...] | None:
        if query.event_group is not None:
            return tuple(sorted(_TRACE_EVENT_GROUPS[query.event_group]))
        if query.view == "business":
            return tuple(sorted(_TRACE_BUSINESS_EVENT_TYPES))
        return None

    @staticmethod
    def _trace_filter_fingerprint(
        query: _TraceQuery, mine_ids: tuple[str, ...] | None
    ) -> str:
        return sha256(
            _canonical_bytes(
                {
                    "filters": query.applied_filters(),
                    "scope": "all" if mine_ids is None else list(mine_ids),
                }
            )
        ).hexdigest()

    @staticmethod
    def _encode_trace_cursor(
        *, snapshot: int, before: int, fingerprint: str
    ) -> str:
        payload = _canonical_bytes(
            {"v": 1, "snapshot": snapshot, "before": before, "fp": fingerprint}
        )
        return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_trace_cursor(value: str) -> tuple[int, int, str]:
        try:
            padded = value + "=" * (-len(value) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("v") != 1:
                raise ValueError
            snapshot = int(payload["snapshot"])
            before = int(payload["before"])
            fingerprint = str(payload["fp"])
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("cursor is invalid") from error
        if snapshot < 0 or before <= 0 or not re.fullmatch(
            r"[0-9a-f]{64}", fingerprint
        ):
            raise ValueError("cursor is invalid")
        return snapshot, before, fingerprint

    def _trace_page(
        self, principal: Principal, raw_query: str
    ) -> dict[str, Any]:
        query = self._parse_trace_query(raw_query, for_export=False)
        mine_ids = self._trace_scope(principal, query.mine_id)
        event_types = self._trace_event_types(query)
        fingerprint = self._trace_filter_fingerprint(query, mine_ids)
        snapshot_sequence: int | None = None
        before_sequence: int | None = None
        if query.cursor is not None:
            snapshot_sequence, before_sequence, cursor_fingerprint = (
                self._decode_trace_cursor(query.cursor)
            )
            if cursor_fingerprint != fingerprint:
                raise ValueError("cursor does not match the current filters or scope")
        page = self.server.store.list_audit_events_page(
            mine_ids=mine_ids,
            event_types=event_types,
            occurred_from=query.occurred_from,
            occurred_before=query.occurred_before,
            snapshot_sequence=snapshot_sequence,
            before_sequence=before_sequence,
            limit=query.limit,
        )
        mine_names = self._mine_name_map(principal)
        items = [
            {
                **self._audit_row(item),
                "mine_name": mine_names.get(
                    item.mine_id or "", item.mine_id or "辖区系统"
                ),
            }
            for item in page.items
        ]
        now = self.server.clock()
        if (
            now < self.server.integrity_checked_at
            or now - self.server.integrity_checked_at >= timedelta(seconds=60)
        ):
            self.server.integrity_valid = self.server.store.verify_integrity()
            self.server.integrity_checked_at = now
        next_cursor = None
        if page.has_more and page.next_before_sequence is not None:
            next_cursor = self._encode_trace_cursor(
                snapshot=page.snapshot_sequence,
                before=page.next_before_sequence,
                fingerprint=fingerprint,
            )
        return {
            "items": items,
            "matched_count": page.matched_count,
            "has_more": page.has_more,
            "next_cursor": next_cursor,
            "as_of": _iso(now),
            "integrity": {
                "valid": self.server.integrity_valid,
                "scope": "complete_chain",
                "checked_at": _iso(self.server.integrity_checked_at),
            },
            "applied_filters": query.applied_filters(),
        }

    @staticmethod
    def _safe_csv_cell(value: Any) -> str:
        text = "" if value is None else str(value)
        text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        probe = text.lstrip(" \u00a0\u200b\ufeff")
        if probe.startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    def _trace_export_items(
        self,
        query: _TraceQuery,
        mine_ids: tuple[str, ...] | None,
    ) -> tuple[list[AuditProjection], int, int] | None:
        event_types = self._trace_event_types(query)
        first = self.server.store.list_audit_events_page(
            mine_ids=mine_ids,
            event_types=event_types,
            occurred_from=query.occurred_from,
            occurred_before=query.occurred_before,
            limit=1000,
        )
        if first.matched_count > _TRACE_EXPORT_LIMIT:
            self._send_error(
                422,
                "export_too_large",
                "当前筛选结果超过 10000 条，请缩小煤矿或时间范围后再导出",
                detail={
                    "matched_count": first.matched_count,
                    "maximum": _TRACE_EXPORT_LIMIT,
                },
            )
            return None
        rows = list(first.items)
        page = first
        while page.has_more:
            if page.next_before_sequence is None:
                raise RuntimeError("audit page has_more without a next cursor")
            page = self.server.store.list_audit_events_page(
                mine_ids=mine_ids,
                event_types=event_types,
                occurred_from=query.occurred_from,
                occurred_before=query.occurred_before,
                snapshot_sequence=first.snapshot_sequence,
                before_sequence=page.next_before_sequence,
                limit=1000,
            )
            rows.extend(page.items)
        if len(rows) != first.matched_count:
            raise RuntimeError("audit export snapshot count changed unexpectedly")
        return rows, first.snapshot_sequence, first.matched_count

    def _export_trace_csv(self, principal: Principal, raw_query: str) -> None:
        query = self._parse_trace_query(raw_query, for_export=True)
        mine_ids = self._trace_scope(principal, query.mine_id)
        integrity_valid = self.server.store.verify_integrity()
        checked_at = self.server.clock()
        self.server.integrity_valid = integrity_valid
        self.server.integrity_checked_at = checked_at
        if not integrity_valid:
            self._send_error(
                409,
                "audit_integrity_failed",
                "完整留痕链校验未通过，已停止导出，请联系系统管理员核验",
            )
            return
        collected = self._trace_export_items(query, mine_ids)
        if collected is None:
            return
        rows, snapshot_sequence, matched_count = collected
        mine_names = self._mine_name_map(principal)
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\r\n")
        writer.writerow(
            [
                "留痕序号",
                "时间（北京时间）",
                "UTC时间",
                "煤矿名称",
                "煤矿编号",
                "业务环节",
                "事件",
                "状态",
                "关联编号",
                "摘要",
                "完整链校验",
                "事件编号",
                "前序哈希",
                "事件哈希",
            ]
        )
        shanghai = ZoneInfo("Asia/Shanghai")
        for item in rows:
            event_label, status, summary = self._audit_presentation(item)
            correlation_id = (
                item.payload.get("correlation_id")
                or item.payload.get("submission_id")
                or item.payload.get("resolving_submission_id")
                or item.aggregate_id
            )
            group = _trace_event_group(item.event_type)
            values = [
                item.sequence,
                item.occurred_at.astimezone(shanghai).strftime("%Y-%m-%d %H:%M:%S"),
                _iso(item.occurred_at),
                mine_names.get(item.mine_id or "", item.mine_id or "辖区系统"),
                item.mine_id or "",
                _TRACE_EVENT_GROUP_LABELS[group],
                event_label,
                _TRACE_STATUS_LABELS.get(status, "已记录"),
                correlation_id,
                summary,
                "完整留痕链校验通过",
                item.event_id,
                item.previous_hash,
                item.event_hash,
            ]
            writer.writerow([self._safe_csv_cell(value) for value in values])
        encoded = b"\xef\xbb\xbf" + stream.getvalue().encode("utf-8")
        exported_at = self.server.clock().astimezone(UTC)
        ascii_filename = (
            "mineguard-exchange-trace-"
            f"{exported_at.strftime('%Y%m%d-%H%M%S')}.csv"
        )
        chinese_filename = (
            "MineGuard_双系统交换留痕_"
            f"{exported_at.astimezone(shanghai).strftime('%Y%m%d_%H%M%S')}.csv"
        )
        export_sha256 = sha256(encoded).hexdigest()
        self.server.auth_store.record_audit_event(
            "regulatory_exchange_trace_exported",
            principal=principal,
            client_id=self.client_address[0],
            detail={
                "filters": query.applied_filters(),
                "snapshot_sequence": snapshot_sequence,
                "row_count": matched_count,
                "first_sequence": rows[0].sequence if rows else None,
                "last_sequence": rows[-1].sequence if rows else None,
                "export_sha256": export_sha256,
                "chain_integrity": "valid",
                "filename": ascii_filename,
            },
        )
        self._send_bytes(
            200,
            encoded,
            content_type="text/csv; charset=utf-8",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": (
                    f'attachment; filename="{ascii_filename}"; '
                    f"filename*=UTF-8''{quote(chinese_filename, safe='')}"
                ),
                "X-Download-Options": "noopen",
                "X-MineGuard-Snapshot-Sequence": str(snapshot_sequence),
                "X-MineGuard-Row-Count": str(matched_count),
            },
        )

    @staticmethod
    def _audit_row(item: AuditProjection) -> dict[str, Any]:
        event_label, status, summary = RegulatoryV2RequestHandler._audit_presentation(
            item
        )
        return {
            "sequence": item.sequence,
            "event_id": item.event_id,
            "event_type": item.event_type,
            "event_group": _trace_event_group(item.event_type),
            "mine_id": item.mine_id,
            "message_id": item.aggregate_id,
            "correlation_id": item.payload.get("correlation_id")
            or item.payload.get("submission_id")
            or item.payload.get("resolving_submission_id")
            or item.aggregate_id,
            "event_label": event_label,
            "status": status,
            "summary": summary,
            "occurred_at": _iso(item.occurred_at),
        }

    @staticmethod
    def _audit_presentation(item: AuditProjection) -> tuple[str, str, str]:
        event_type = item.event_type
        payload = item.payload
        decision = item.payload.get("decision") or item.payload.get("outcome")
        decision_summaries = {
            "normal_candidate": (
                "研判完成",
                "本期五量数据研判完成，暂未发现需要企业核实的风险线索。",
            ),
            "risk": (
                "发现风险线索",
                "本期五量数据研判发现风险线索，等待企业核实或提交修订数据。",
            ),
            "insufficient_data": (
                "数据待补充",
                "本期数据不完整，暂不能作出判断，请企业补充或核对数据。",
            ),
        }
        if (
            event_type
            in {
                "analysis_completed",
                "analysis_report_automatically_issued",
            }
            and decision in decision_summaries
        ):
            label, summary = decision_summaries[str(decision)]
            finding_ids = payload.get("finding_ids")
            if isinstance(finding_ids, list) and finding_ids:
                if decision == "risk":
                    summary = (
                        f"本期五量数据研判发现 {len(finding_ids)} 项风险线索，"
                        "等待企业核实或提交修订数据。"
                    )
                elif decision == "insufficient_data":
                    summary = (
                        "本期数据不完整，暂不能作出判断；"
                        f"已形成 {len(finding_ids)} 项数据补充要求。"
                    )
            return label, str(decision), summary

        if event_type == "agent_mine_bound":
            return (
                "报送关系已建立",
                "connected",
                "企业报送端已与本矿建立固定报送关系。",
            )
        if event_type == "exchange_inbound_recorded":
            return "收到企业消息", "received", "企业交换消息已安全接收并留痕。"
        if event_type == "exchange_outbound_recorded":
            return "监管消息已发出", "delivered", "监管结果或回执已发送至企业端。"
        if event_type == "submission_received":
            revision = payload.get("revision")
            summary = (
                f"已收到企业提交的第 {revision} 版修订数据，系统正在重新分析。"
                if isinstance(revision, int) and revision > 1
                else "已收到企业本期五量数据，系统正在分析。"
            )
            return "数据已接收", "analyzing", summary
        if event_type == "finding_automatically_issued":
            category = {
                "data_quality": "数据质量",
                "relationship_consistency": "五量关系协调",
                "temporal_pattern": "五量时序变化",
                "data_completeness": "数据完整性",
            }.get(str(payload.get("category")), "数据")
            status = (
                "insufficient_data"
                if payload.get("finding_type") == "data_insufficient"
                else "risk"
            )
            return (
                "形成待核事项",
                status,
                f"系统已形成 1 项{category}待企业核实事项。",
            )
        if event_type == "enterprise_explanation_recorded":
            return (
                "企业已回复",
                "explanation_recorded",
                "企业说明已追加留痕，相关风险尚未解除。",
            )
        if event_type == "enterprise_response_batch_recorded":
            finding_ids = payload.get("finding_ids")
            count = len(finding_ids) if isinstance(finding_ids, list) else 1
            return (
                "企业已回复",
                "explanation_recorded",
                f"企业已回复 {count} 项待核实事项；相关风险尚未解除。",
            )
        if event_type == "analysis_report_delivery_acknowledged":
            return "企业已收悉", "delivered", "企业端已确认收到本次研判结果。"
        if event_type == "finding_resolved_by_revision_reanalysis":
            return (
                "风险已解除",
                "cleared_by_reanalysis",
                "修订数据经同一算法重新分析通过，相关风险已解除。",
            )
        if event_type == "baseline_candidate_admitted":
            return (
                "已纳入历史参考",
                "reference_admitted",
                "本期数据符合参考样本条件，可用于后续同矿历史比较。",
            )
        if event_type == "baseline_candidate_rejected":
            return (
                "未纳入历史参考",
                "reference_rejected",
                "本期数据不作为后续历史参考样本，不影响本次研判结论。",
            )
        if event_type == "anonymous_peer_snapshot_frozen":
            mine_count = payload.get("mine_count")
            summary = (
                f"本轮分析已固定 {mine_count} 座同类矿的匿名参考样本。"
                if isinstance(mine_count, int)
                else "本轮分析使用的同类矿匿名参考样本已固定。"
            )
            return "同类矿参考已更新", "updated", summary
        if event_type == "inbox_idempotency_conflict_rejected":
            return (
                "冲突报送已拦截",
                "rejected",
                "同一业务编号对应了不同报送内容，本笔数据已拒收且未进入分析。",
            )
        return "系统状态已更新", "information", "系统已记录一项审计事件。"

    @staticmethod
    def _audit_summary(item: AuditProjection) -> str:
        return RegulatoryV2RequestHandler._audit_presentation(item)[2]

    # ------------------------------------------------------------------
    # HTTP helpers

    def _read_body(self, *, limit: int = _MAX_JSON_BYTES) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("chunked request bodies are not accepted")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ValueError("Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as error:
            raise ValueError("invalid Content-Length") from error
        if length < 0 or length > limit:
            raise ValueError("request body is too large")
        return self.rfile.read(length)

    def _read_json(self, *, limit: int = _MAX_JSON_BYTES) -> dict[str, Any]:
        body = self._read_body(limit=limit)
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("request body must be valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    @staticmethod
    def _reject_query(query: str) -> None:
        if query:
            raise ValueError("this route does not accept query parameters")

    @staticmethod
    def _single_query(query: str, name: str) -> str | None:
        if "%" in query:
            raise ValueError("encoded query values are not accepted by this V2 route")
        values = (
            parse_qsl(query, keep_blank_values=True, strict_parsing=True)
            if query
            else []
        )
        if any(key != name for key, _ in values) or len(values) > 1:
            raise ValueError("query parameters do not match the V2 contract")
        if not values:
            return None
        if not values[0][1]:
            raise ValueError(f"{name} cannot be empty")
        return values[0][1]

    def _single_int_query(
        self,
        query: str,
        name: str,
        *,
        default: int,
        maximum: int,
    ) -> int:
        value = self._single_query(query, name)
        if value is None:
            return default
        try:
            parsed = int(value)
        except ValueError as error:
            raise ValueError(f"{name} must be an integer") from error
        if not 1 <= parsed <= maximum:
            raise ValueError(f"{name} is outside the allowed range")
        return parsed

    def _serve_static(self, path: str, *, head_only: bool) -> None:
        name = {
            "/": "index.html",
            "/index.html": "index.html",
            "/wallboard": "index.html",
            "/assets/app.js": "app.js",
            "/assets/styles.css": "styles.css",
        }[path]
        resource = Path(__file__).with_name("regulatory_web") / name
        try:
            body = resource.read_bytes()
        except FileNotFoundError as error:
            raise RegulatoryV2NotFoundError("frontend asset not found") from error
        content_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        self._send_bytes(
            200,
            body,
            content_type=f"{content_type}; charset=utf-8",
            head_only=head_only,
            headers={
                "Cache-Control": "no-cache"
            },
        )

    def _send_json(
        self,
        status: int,
        value: Any,
        *,
        headers: Mapping[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        self._send_bytes(
            status,
            _canonical_bytes(value),
            content_type="application/json; charset=utf-8",
            headers={"Cache-Control": "no-store", **dict(headers or {})},
            head_only=head_only,
        )

    def _send_empty(
        self,
        status: int,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self._send_bytes(status, b"", headers=headers)

    def _send_error(
        self,
        status: int,
        code: str,
        message: str,
        *,
        detail: Any | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        normalized_code = re.sub(r"[^A-Z0-9_]", "_", code.upper())
        detail_text = message
        if detail is not None:
            rendered = json.dumps(
                detail,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            detail_text = f"{message}：{rendered}"
        payload = {
            "type": f"/problems/{code.lower().replace('_', '-')}",
            "title": message[:256] or "请求失败",
            "status": status,
            "code": normalized_code[:128],
            "detail": detail_text[:2000] or "请求失败",
            "trace_id": self.headers.get("X-Request-ID") or str(uuid4()),
        }
        self._send_bytes(
            status,
            _canonical_bytes(payload),
            content_type="application/problem+json; charset=utf-8",
            headers={"Cache-Control": "no-store", **dict(headers or {})},
        )

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str | None = None,
        headers: Mapping[str, str] | None = None,
        head_only: bool = False,
    ) -> None:
        self.send_response(status)
        if content_type is not None:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'",
        )
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if not head_only and body:
            self.wfile.write(body)


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    database_path: str | Path = ".mineguard/mineguard.db",
    auth_database_path: str | Path = ".mineguard/auth.db",
    auth_required: bool = True,
    secure_cookie: bool = False,
    clients: Mapping[str, ExchangeClient] | None = None,
    platform_system_id: str | None = None,
    platform_party_id: str | None = None,
    platform_key_id: str | None = None,
    clock: Callable[[], datetime] = _utc_now,
    **_: Any,
) -> RegulatoryV2HTTPServer:
    registry = (
        dict(clients)
        if clients is not None
        else load_exchange_clients(
            os.environ.get("MINEGUARD_V2_CLIENTS_JSON"),
            os.environ.get("MINEGUARD_V2_CLIENTS_FILE"),
        )
    )
    store = RegulatoryV2Store(database_path, now=clock)
    auth_store = LocalAuthStore(auth_database_path, clock=clock)
    try:
        for client in registry.values():
            store.bind_agent_to_mine(client.sender_id, client.mine_id)
        return RegulatoryV2HTTPServer(
            (host, port),
            store=store,
            auth_store=auth_store,
            clients=registry,
            auth_required=auth_required,
            secure_cookie=secure_cookie,
            platform_system_id=platform_system_id
            or os.environ.get("MINEGUARD_V2_PLATFORM_SYSTEM_ID", "mineguard-qinyuan"),
            platform_party_id=platform_party_id
            or os.environ.get("MINEGUARD_V2_PLATFORM_PARTY_ID", "regulator-qinyuan"),
            platform_key_id=platform_key_id
            or os.environ.get("MINEGUARD_V2_PLATFORM_KEY_ID", "regulator-key-v2"),
            clock=clock,
        )
    except BaseException:
        store.close()
        auth_store.close()
        raise


def serve(host: str = "127.0.0.1", port: int = 8080, **kwargs: Any) -> None:
    server = create_server(host, port, **kwargs)
    try:
        server.serve_forever()
    finally:
        server.server_close()


__all__ = ["RegulatoryV2HTTPServer", "create_server", "serve"]
