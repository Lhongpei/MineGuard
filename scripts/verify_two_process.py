#!/usr/bin/env python3
"""Black-box acceptance test for the independent platform and agent services.

The script deliberately uses only Python's standard library.  It starts each
application in its own subprocess with an application-specific ``PYTHONPATH``
and exercises the public HTTP/JSON contracts.  It does not import either
application package.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PLATFORM_ROOT = REPOSITORY_ROOT / "platform"
AGENT_ROOT = REPOSITORY_ROOT / "agent"
OBSERVATION_SIGNING_CONTEXT = (
    b"MINEGUARD-GOVERNED-OBSERVATION-V1\x00"
)
SUBMISSION_CONTRACT = "enterprise-submission-v1"
TRANSPORT_SIGNATURE_VERSION = "hmac-sha256-v1"


class VerificationError(RuntimeError):
    """A black-box acceptance assertion failed."""


@dataclass
class ManagedProcess:
    name: str
    process: subprocess.Popen[str]
    log_path: Path
    log_stream: Any

    def stop(self) -> None:
        """Terminate only this process group, escalating after a short grace."""

        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=5)
        if not self.log_stream.closed:
            self.log_stream.flush()
            self.log_stream.close()

    def log_tail(self, *, redactions: tuple[str, ...] = ()) -> str:
        if not self.log_stream.closed:
            self.log_stream.flush()
        try:
            text = self.log_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            return "<log unavailable>"
        for secret_value in redactions:
            if secret_value:
                text = text.replace(secret_value, "<redacted>")
        lines = text.splitlines()
        return "\n".join(lines[-40:]) or "<empty log>"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _canonical_json_bytes(value: Any) -> bytes:
    """Canonical form used by governed-observation signature V1."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("UTC text requires an aware datetime")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _gateway_sign_observation(
    observation: dict[str, Any],
    secret_value: str,
) -> dict[str, Any]:
    """Implement governed-observation-signature-v1 independently."""

    payload = {
        field: observation[field]
        for field in (
            "source_id",
            "observation_id",
            "value",
            "unit",
            "observed_at",
            "received_at",
            "sequence_no",
            "revision",
        )
    }
    for field in ("interval_start", "interval_end", "reset_before"):
        value = observation.get(field)
        if value is not None and not (
            field == "reset_before" and value is False
        ):
            payload[field] = value
    payload_sha256 = hashlib.sha256(
        _canonical_json_bytes(payload)
    ).hexdigest()
    envelope = {
        "payload": payload,
        "payload_sha256": payload_sha256,
    }
    signature_value = hmac.new(
        secret_value.encode("utf-8"),
        OBSERVATION_SIGNING_CONTEXT
        + _canonical_json_bytes(envelope),
        hashlib.sha256,
    ).hexdigest()
    return {
        **observation,
        "payload_sha256": payload_sha256,
        "signature": signature_value,
    }


def _verify_gateway_signature_fixed_vector() -> None:
    """Guard the independent signer against accidental protocol drift."""

    signed = _gateway_sign_observation(
        {
            "source_id": "mine-001-main-transport",
            "observation_id": "obs-20260727-0001",
            "value": 1000.25,
            "unit": "t",
            "observed_at": "2026-07-27T08:00:00Z",
            "received_at": "2026-07-27T08:00:05Z",
            "sequence_no": 202607270001,
            "revision": 0,
        },
        "example-device-secret-not-for-production",
    )
    expected_digest = (
        "78a5d9cf36c2b566511bee3364ae714a02479da6ff8b02f2b"
        "996de5574c197a9"
    )
    expected_signature = (
        "59dc38c6346e0f955976c541a093644276c9f36830de8d4c"
        "38aee79b56e82477"
    )
    if signed["payload_sha256"] != expected_digest:
        raise VerificationError("观测签名固定向量的 payload_sha256 不匹配")
    if signed["signature"] != expected_signature:
        raise VerificationError("观测签名固定向量的 HMAC 不匹配")


def _transport_headers(
    *,
    method: str,
    path: str,
    body: bytes,
    client_id: str,
    secret_value: str,
) -> dict[str, str]:
    timestamp = _utc_text(datetime.now(UTC))
    nonce = base64.urlsafe_b64encode(
        secrets.token_bytes(18)
    ).decode("ascii").rstrip("=")
    body_sha256 = hashlib.sha256(body).hexdigest()
    material = "\n".join(
        (
            "ENTERPRISE-SUBMISSION-HTTP-HMAC-SHA256-V1",
            method.upper(),
            path,
            client_id,
            timestamp,
            nonce,
            SUBMISSION_CONTRACT,
            body_sha256,
        )
    ).encode("utf-8")
    signature_value = hmac.new(
        secret_value.encode("utf-8"),
        material,
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-Enterprise-Client-Id": client_id,
        "X-Enterprise-Timestamp": timestamp,
        "X-Enterprise-Nonce": nonce,
        "X-Enterprise-Content-SHA256": body_sha256,
        "X-Enterprise-Signature-Version": (
            TRANSPORT_SIGNATURE_VERSION
        ),
        "X-Enterprise-Contract-Version": SUBMISSION_CONTRACT,
        "X-Enterprise-Signature": signature_value,
    }


def _password_hash(password: str) -> str:
    """Generate the documented enterprise account PBKDF2 representation."""

    iterations = 100_000
    salt = secrets.token_bytes(18)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    def encode(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return (
        f"pbkdf2_sha256${iterations}${encode(salt)}${encode(digest)}"
    )


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _port_accepts_connections(port: int, *, timeout: float = 0.2) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_until_stopped(
    managed: ManagedProcess,
    *,
    timeout: float,
    operation: str,
) -> int:
    try:
        return_code = managed.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise VerificationError(
            f"{operation}：进程在 {timeout:g} 秒内未按预期退出"
        ) from error
    finally:
        if not managed.log_stream.closed:
            managed.log_stream.flush()
            managed.log_stream.close()
    if return_code == 0:
        raise VerificationError(f"{operation}：进程意外以成功状态退出")
    return return_code


def _interrupt_cleanly(
    managed: ManagedProcess,
    *,
    timeout: float,
) -> None:
    """Exercise the foreground operator's normal Ctrl-C stop path."""

    if managed.process.poll() is None:
        try:
            os.killpg(managed.process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
    try:
        return_code = managed.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise VerificationError(
            f"{managed.name} 收到 Ctrl+C 后未在 {timeout:g} 秒内退出"
        ) from error
    if return_code != 0:
        raise VerificationError(
            f"{managed.name} 收到 Ctrl+C 后返回码为 {return_code}"
        )
    log = managed.log_tail()
    if "Traceback (most recent call last)" in log:
        raise VerificationError(f"{managed.name} Ctrl+C 仍输出 Python traceback")


def _start_process(
    *,
    name: str,
    command: list[str],
    cwd: Path,
    environment: dict[str, str],
    log_path: Path,
) -> ManagedProcess:
    log_stream = log_path.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except Exception:
        log_stream.close()
        raise
    return ManagedProcess(name, process, log_path, log_stream)


def _request(
    port: int,
    method: str,
    path: str,
    *,
    payload: Any | None = None,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
) -> tuple[int, Any, dict[str, str]]:
    if payload is not None and body is not None:
        raise ValueError("provide either payload or body")
    raw = _json_bytes(payload) if payload is not None else body
    request_headers = dict(headers or {})
    if raw is not None:
        request_headers.setdefault(
            "Content-Type",
            "application/json; charset=utf-8",
        )
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        port,
        timeout=timeout,
    )
    try:
        connection.request(
            method,
            path,
            body=raw,
            headers=request_headers,
        )
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {
            key.lower(): value
            for key, value in response.getheaders()
        }
        if response_body:
            try:
                parsed: Any = json.loads(response_body)
            except json.JSONDecodeError:
                parsed = response_body.decode("utf-8", errors="replace")
        else:
            parsed = None
        return response.status, parsed, response_headers
    finally:
        connection.close()


def _expect(
    response: tuple[int, Any, dict[str, str]],
    statuses: int | tuple[int, ...],
    operation: str,
) -> tuple[Any, dict[str, str]]:
    expected = (statuses,) if isinstance(statuses, int) else statuses
    status, payload, headers = response
    if status not in expected:
        safe_payload = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
        )
        raise VerificationError(
            f"{operation} 返回 HTTP {status}，预期 {expected}："
            f"{safe_payload[:2000]}"
        )
    return payload, headers


def _wait_until_ready(
    managed: ManagedProcess,
    *,
    port: int,
    path: str,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        return_code = managed.process.poll()
        if return_code is not None:
            raise VerificationError(
                f"{managed.name} 在就绪前退出，返回码 {return_code}"
            )
        try:
            status, payload, _ = _request(
                port,
                "GET",
                path,
                timeout=1,
            )
            if status == 200:
                return
            last_error = f"HTTP {status}: {payload!r}"
        except (OSError, TimeoutError) as error:
            last_error = str(error)
        time.sleep(0.1)
    raise VerificationError(
        f"{managed.name} 在 {timeout:g} 秒内未就绪：{last_error}"
    )


def _login_platform(
    port: int,
    *,
    username: str,
    password: str,
) -> tuple[str, str]:
    payload, headers = _expect(
        _request(
            port,
            "POST",
            "/v1/auth/login",
            payload={"username": username, "password": password},
        ),
        200,
        "登录监管平台",
    )
    cookie = headers.get("set-cookie", "").split(";", 1)[0]
    csrf = payload.get("csrf_token") if isinstance(payload, dict) else None
    if not cookie or not isinstance(csrf, str) or not csrf:
        raise VerificationError("监管平台登录响应缺少会话或 CSRF")
    return cookie, csrf


def _login_agent(
    port: int,
    *,
    actor_id: str,
    password: str,
) -> tuple[str, str, dict[str, Any]]:
    payload, headers = _expect(
        _request(
            port,
            "POST",
            "/api/v1/auth/login",
            payload={"actor_id": actor_id, "password": password},
        ),
        200,
        "登录企业智能体",
    )
    cookie = headers.get("set-cookie", "").split(";", 1)[0]
    csrf = payload.get("csrf_token") if isinstance(payload, dict) else None
    principal = (
        payload.get("principal") if isinstance(payload, dict) else None
    )
    if (
        not cookie
        or not isinstance(csrf, str)
        or not isinstance(principal, dict)
    ):
        raise VerificationError("企业智能体登录响应缺少身份、会话或 CSRF")
    return cookie, csrf, principal


def _admin_headers(cookie: str, csrf: str) -> dict[str, str]:
    return {"Cookie": cookie, "X-CSRF-Token": csrf}


def _agent_headers(cookie: str, csrf: str) -> dict[str, str]:
    return {"Cookie": cookie, "X-CSRF-Token": csrf}


def _register_platform_configuration(
    *,
    port: int,
    cookie: str,
    csrf: str,
    now: datetime,
    window_start: datetime,
    window_end: datetime,
    client_id: str,
    source_definitions: list[dict[str, Any]],
    event_evidence_sha256: str,
) -> tuple[str, str]:
    headers = _admin_headers(cookie, csrf)
    effective_from = _utc_text(now - timedelta(days=2))
    effective_to = _utc_text(now + timedelta(days=2))
    profile = {
        "profile": {
            "profile_id": "e2e-five-flow",
            "version": "2026.1",
            "effective_from": effective_from,
            "effective_to": effective_to,
            "parameters": {
                "transport_balance_tolerance": 25.0,
                "stock_balance_tolerance": 30.0,
                "transport_slack_penalty": 80.0,
                "stock_slack_penalty": 90.0,
                "max_mcs": 4,
                "max_relaxed_groups": 2,
                "max_mcs_search_combinations": 20000,
                "quality_gate": 60.0,
                "minimum_observation_quality": 50.0,
            },
            "required_metrics": [
                item["metric_code"] for item in source_definitions
            ],
            "approved": True,
        }
    }
    _expect(
        _request(
            port,
            "POST",
            "/v1/governance/profiles",
            payload=profile,
            headers=headers,
        ),
        201,
        "注册分析 profile",
    )

    for index, item in enumerate(source_definitions, start=1):
        registration = {
            "definition": {
                "source_id": item["source_id"],
                "mine_id": "M001",
                "metric_code": item["metric_code"],
                "root_source_group": f"e2e-root-{index}",
                "unit": "t",
                "tolerance_abs": float(10 + index),
                "tolerance_rel": 0.002,
                "resolution": 0.1,
                "reliability": 0.95,
                "dependency_domains": [f"e2e-domain-{index}"],
                "measurement_type": "window_total",
                "max_delay_seconds": 60.0,
                "calibration_valid_until": effective_to,
                "active": True,
            },
            "version": 1,
            "effective_from": effective_from,
            "effective_to": effective_to,
            "hmac_secret": item["secret"],
        }
        _expect(
            _request(
                port,
                "POST",
                "/v1/governance/sources",
                payload=registration,
                headers=headers,
            ),
            201,
            f"注册可信来源 {index}/5",
        )

    confirmer_registration_id = "e2e-operator-001-v1"
    _expect(
        _request(
            port,
            "POST",
            "/v1/admin/external-confirmers",
            payload={
                "registration_id": confirmer_registration_id,
                "client_id": client_id,
                "enterprise_id": "ENT-001",
                "confirmer_id": "operator-001",
                "version": 1,
                "confirmer_name": "张三",
                "confirmer_roles": ["企业报送负责人"],
                "confirmation_methods": ["authenticated_click"],
                "active": True,
                "source_system": "e2e-regulator-confirmer-ledger",
                "record_id": "e2e:ENT-001:operator-001:v1",
            },
            headers=headers,
        ),
        201,
        "登记企业确认人",
    )

    snapshot_id = "e2e-event-snapshot-001"
    _expect(
        _request(
            port,
            "POST",
            "/v1/admin/external-event-snapshots",
            payload={
                "snapshot_id": snapshot_id,
                "mine_id": "M001",
                "window_start": _utc_text(window_start),
                "window_end": _utc_text(window_end),
                "event_codes": [],
                "evidence_sha256": event_evidence_sha256,
                "source_system": "e2e-regulator-event-ledger",
                "record_id": "e2e:event-query:M001:001",
            },
            headers=headers,
        ),
        201,
        "登记监管事件快照",
    )
    return confirmer_registration_id, snapshot_id


def _make_import_document(
    *,
    window_start: datetime,
    window_end: datetime,
    source_definitions: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    observed_base = window_end - timedelta(minutes=2)
    observations: list[dict[str, Any]] = []
    for index, item in enumerate(source_definitions, start=1):
        observed_at = observed_base + timedelta(seconds=index)
        unsigned = {
            "source_id": item["source_id"],
            "observation_id": f"e2e-observation-{index:02d}",
            "metric_code": item["metric_code"],
            "value": item["value"],
            "unit": "t",
            "observed_at": _utc_text(observed_at),
            "received_at": _utc_text(
                observed_at + timedelta(seconds=5)
            ),
            "interval_start": None,
            "interval_end": None,
            "reset_before": False,
            "sequence_no": index,
            "revision": 0,
        }
        observations.append(
            _gateway_sign_observation(unsigned, item["secret"])
        )
    document = {
        "enterprise_id": "ENT-001",
        "enterprise_name": "双进程验收能源有限公司",
        "unified_social_credit_code": "91110000ABCDEFGH1X",
        "mine_id": "M001",
        "mine_name": "双进程验收一号矿",
        "window_start": _utc_text(window_start),
        "window_end": _utc_text(window_end),
        "profile_id": "e2e-five-flow",
        "profile_version": "2026.1",
        "operational_context": {
            "regime_code": "NORMAL_PRODUCTION",
            "shift_code": "E2E",
            "season_code": "SUMMER",
            "maintenance": False,
            "approved_event_codes": [],
            "tags": ["two-process-e2e"],
        },
        "observations": observations,
        "notes": "由黑盒双进程验收脚本导入。",
    }
    content = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return document, content


def _prepare_agent_draft(
    *,
    port: int,
    cookie: str,
    csrf: str,
    import_content: str,
    event_snapshot: dict[str, Any],
) -> dict[str, Any]:
    headers = _agent_headers(cookie, csrf)
    created, _ = _expect(
        _request(
            port,
            "POST",
            "/api/v1/drafts",
            payload={},
            headers=headers,
        ),
        201,
        "新建企业草稿",
    )
    draft = created.get("draft") if isinstance(created, dict) else None
    if not isinstance(draft, dict):
        raise VerificationError("新建草稿响应缺少 draft")
    draft_id = draft.get("draft_id")
    revision = (draft.get("_meta") or {}).get("revision")
    if not isinstance(draft_id, str) or not isinstance(revision, int):
        raise VerificationError("新建草稿响应缺少 ID 或修订号")

    imported, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/import",
            payload={
                "format": "json",
                "content": import_content,
                "source_name": "e2e-gateway-export.json",
                "expected_revision": revision,
            },
            headers=headers,
        ),
        200,
        "导入企业材料",
    )
    imported_draft = (
        imported.get("draft") if isinstance(imported, dict) else None
    )
    if not isinstance(imported_draft, dict):
        raise VerificationError("导入响应缺少 draft")
    revision = (imported_draft.get("_meta") or {}).get("revision")
    if not isinstance(revision, int):
        raise VerificationError("导入响应缺少修订号")

    ordinary_validation, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/validate",
            payload={},
            headers=headers,
        ),
        200,
        "验证普通报告不能冒充监管事件快照",
    )
    ordinary_issues = (
        ordinary_validation.get("issues")
        if isinstance(ordinary_validation, dict)
        else None
    )
    if (
        not isinstance(ordinary_validation, dict)
        or ordinary_validation.get("valid") is not False
        or not isinstance(ordinary_issues, list)
        or not any(
            isinstance(item, dict)
            and item.get("code") == "regulator_event_snapshot_required"
            for item in ordinary_issues
        )
    ):
        raise VerificationError(
            "一般业务报告中的事件字段错误地通过了权威快照门禁"
        )

    snapshot_response, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/event-snapshot",
            payload={
                "snapshot": event_snapshot,
                "expected_revision": revision,
            },
            headers=headers,
        ),
        200,
        "导入独立监管事件快照",
    )
    imported_draft = (
        snapshot_response.get("draft")
        if isinstance(snapshot_response, dict)
        else None
    )
    imported_snapshot = (
        snapshot_response.get("event_snapshot")
        if isinstance(snapshot_response, dict)
        else None
    )
    if (
        not isinstance(imported_draft, dict)
        or not isinstance(imported_snapshot, dict)
        or imported_snapshot.get("evidence_sha256")
        != event_snapshot["evidence_sha256"]
        or imported_snapshot.get("event_codes") != []
    ):
        raise VerificationError("企业端未精确保留独立监管事件快照")
    revision = (imported_draft.get("_meta") or {}).get("revision")
    if not isinstance(revision, int):
        raise VerificationError("事件快照导入响应缺少新修订号")

    observations = imported_draft.get("observations")
    observation_ids = (
        [
            item.get("observation_id")
            for item in observations
            if isinstance(item, dict)
        ]
        if isinstance(observations, list)
        else []
    )
    if (
        not observation_ids
        or any(not isinstance(item, str) for item in observation_ids)
        or len(observation_ids) != len(set(observation_ids))
    ):
        raise VerificationError("导入响应缺少可逐条核对的唯一观测编号")

    validation, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/validate",
            payload={},
            headers=headers,
        ),
        200,
        "执行确定性预检",
    )
    if (
        not isinstance(validation, dict)
        or validation.get("valid") is not True
        or validation.get("blocking_count") != 0
    ):
        raise VerificationError(
            "企业预检未通过："
            + json.dumps(validation, ensure_ascii=False)[:2000]
        )

    reviewed, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/reviews",
            payload={
                "observation_ids": observation_ids,
                "reviewed": True,
                "expected_revision": revision,
            },
            headers=headers,
        ),
        200,
        "逐条记录企业经办人观测核对",
    )
    review_state = (
        reviewed.get("review_state")
        if isinstance(reviewed, dict)
        else None
    )
    if (
        not isinstance(review_state, dict)
        or review_state.get("all_reviewed") is not True
        or review_state.get("reviewed_count") != len(observation_ids)
    ):
        raise VerificationError("企业端未持久记录全部逐观测人工核对")

    confirmed, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/confirm",
            payload={
                "accepted": True,
                "attestation": (
                    "本人已逐项核对来源材料，并确认有权代表企业提交。"
                ),
                "expected_revision": revision,
                "confirmation_method": "authenticated_click",
            },
            headers=headers,
        ),
        200,
        "企业负责人确认",
    )
    confirmed_draft = (
        confirmed.get("draft") if isinstance(confirmed, dict) else None
    )
    if (
        not isinstance(confirmed_draft, dict)
        or (confirmed_draft.get("_meta") or {}).get("confirmed") is not True
    ):
        raise VerificationError("草稿未进入已确认状态")
    return {
        "draft_id": draft_id,
        "revision": (
            (confirmed_draft.get("_meta") or {}).get("revision")
        ),
    }


def _verify_agent_coal_harness(
    *,
    port: int,
    cookie: str,
    csrf: str,
    draft_id: str,
    forbidden_values: tuple[str, ...],
    timeout: float,
) -> str:
    """Exercise the governed deterministic Harness through public HTTP only."""

    headers = _agent_headers(cookie, csrf)
    health, _ = _expect(
        _request(port, "GET", "/api/v1/health"),
        200,
        "检查企业煤炭 Harness 健康状态",
    )
    if (
        not isinstance(health, dict)
        or health.get("harness_available") is not True
        or health.get("harness_version") != "agent-harness-v1"
        or health.get("tool_calling_mode") != "deterministic"
    ):
        raise VerificationError("企业煤炭 Harness 健康能力声明不完整")

    tools_payload, _ = _expect(
        _request(
            port,
            "GET",
            "/api/v1/agent/tools",
            headers=headers,
        ),
        200,
        "读取企业煤炭工具目录",
    )
    tools = (
        tools_payload.get("tools")
        if isinstance(tools_payload, dict)
        else None
    )
    if not isinstance(tools, list) or len(tools) < 20:
        raise VerificationError("企业煤炭工具目录缺少确定性工具")
    tool_names = {
        item.get("name")
        for item in tools
        if isinstance(item, dict)
    }
    if any(
        isinstance(name, str)
        and any(token in name.lower() for token in ("confirm", "submit"))
        for name in tool_names
    ):
        raise VerificationError("企业 Harness 错误暴露了确认或提交工具")
    if any(
        not isinstance(item, dict)
        or not isinstance(item.get("category"), str)
        or item.get("evidence_grounding")
        not in {"repository_grounded", "user_supplied", "external_public"}
        or not isinstance(item.get("network_access"), bool)
        or not isinstance(item.get("scenario_only"), bool)
        or not isinstance(item.get("allowed_profiles"), list)
        for item in tools
    ):
        raise VerificationError("企业煤炭工具目录缺少治理元数据")

    created, _ = _expect(
        _request(
            port,
            "POST",
            "/api/v1/agent/runs",
            payload={
                "task": (
                    "对当前草稿执行煤炭数据体检，分别保存确定性工具证据；"
                    "不得确认或提交。"
                ),
                "draft_id": draft_id,
                "mode": "deterministic",
            },
            headers=headers,
        ),
        202,
        "发起企业煤炭确定性体检",
    )
    run = created.get("run") if isinstance(created, dict) else None
    run_id = run.get("run_id") if isinstance(run, dict) else None
    if not isinstance(run_id, str) or not run_id:
        raise VerificationError("企业煤炭体检响应缺少 run_id")

    deadline = time.monotonic() + max(timeout, 5.0)
    while time.monotonic() < deadline:
        detail_payload, _ = _expect(
            _request(
                port,
                "GET",
                f"/api/v1/agent/runs/{run_id}",
                headers=headers,
            ),
            200,
            "轮询企业煤炭体检",
        )
        detail = (
            detail_payload.get("run")
            if isinstance(detail_payload, dict)
            else None
        )
        if not isinstance(detail, dict):
            raise VerificationError("企业煤炭体检详情缺少 run")
        if detail.get("status") in {"completed", "failed", "cancelled"}:
            break
        time.sleep(0.05)
    else:
        raise VerificationError("企业煤炭体检未在期限内结束")

    if detail.get("status") != "completed":
        raise VerificationError(
            "企业煤炭体检未成功完成："
            + json.dumps(detail.get("error"), ensure_ascii=False)
        )
    calls = detail.get("tool_calls")
    steps = detail.get("steps")
    integrity = detail.get("integrity")
    answer = detail.get("answer")
    if (
        not isinstance(calls, list)
        or len(calls) < 5
        or not isinstance(steps, list)
        or len(steps) < 5
        or not isinstance(integrity, dict)
        or integrity.get("valid") is not True
        or not isinstance(integrity.get("event_count"), int)
        or integrity["event_count"] < 1
        or not isinstance(answer, str)
        or "不是监管认定" not in answer
        or "未执行确认或提交" not in answer
    ):
        raise VerificationError("企业煤炭体检缺少工具证据、声明或完整过程链")
    expected_tools = {
        "draft_summary",
        "deterministic_preflight",
        "source_evidence_check",
        "align_observation_time",
        "calculate_coal_flow_balance",
    }
    called_tools = {
        item.get("tool_name")
        for item in calls
        if isinstance(item, dict)
    }
    if not expected_tools.issubset(called_tools):
        raise VerificationError("企业煤炭确定性体检未执行完整基础工具组合")
    for call in calls:
        result = call.get("result") if isinstance(call, dict) else None
        data = result.get("data") if isinstance(result, dict) else None
        if (
            not isinstance(call, dict)
            or call.get("status") != "succeeded"
            or not isinstance(data, dict)
            or data.get("not_a_regulatory_determination") is not True
        ):
            raise VerificationError("煤炭确定性工具结果缺少成功状态或治理标记")

    listed, _ = _expect(
        _request(
            port,
            "GET",
            "/api/v1/agent/runs?limit=5&offset=0",
            headers=headers,
        ),
        200,
        "读取企业煤炭体检摘要列表",
    )
    summaries = listed.get("runs") if isinstance(listed, dict) else None
    matching = (
        next(
            (
                item
                for item in summaries
                if isinstance(item, dict) and item.get("run_id") == run_id
            ),
            None,
        )
        if isinstance(summaries, list)
        else None
    )
    if (
        not isinstance(matching, dict)
        or matching.get("status") != "completed"
        or matching.get("tool_calls") != []
        or matching.get("steps") != []
    ):
        raise VerificationError("企业煤炭体检列表未使用有界摘要响应")

    serialized = json.dumps(
        {"detail": detail, "tools": tools_payload},
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    if any(value and value in serialized for value in forbidden_values):
        raise VerificationError("企业煤炭 Harness API 泄露了敏感配置值")
    return run_id


def _verify_agent_coal_chat(
    *,
    port: int,
    cookie: str,
    csrf: str,
    draft_id: str,
    timeout: float,
) -> str:
    """Exercise the coal-only, permanently read-only chat boundary."""

    headers = _agent_headers(cookie, csrf)
    before_payload, _ = _expect(
        _request(
            port,
            "GET",
            f"/api/v1/drafts/{draft_id}",
            headers=headers,
        ),
        200,
        "读取煤炭对话前草稿状态",
    )
    before = (
        before_payload.get("draft")
        if isinstance(before_payload, dict)
        else None
    )
    before_meta = before.get("_meta") if isinstance(before, dict) else None
    if not isinstance(before_meta, dict):
        raise VerificationError("煤炭对话前草稿缺少修订状态")

    created, _ = _expect(
        _request(
            port,
            "POST",
            "/api/v1/chat/sessions",
            payload={
                "title": "双进程煤炭业务对话",
                "draft_id": draft_id,
                "client_request_id": "e2e-coal-chat-session-001",
            },
            headers=headers,
        ),
        201,
        "新建煤炭业务对话",
    )
    session = created.get("session") if isinstance(created, dict) else None
    session_id = (
        session.get("session_id") if isinstance(session, dict) else None
    )
    if (
        not isinstance(session_id, str)
        or not isinstance(created.get("integrity"), dict)
        or created["integrity"].get("valid") is not True
    ):
        raise VerificationError("煤炭业务对话创建响应缺少会话或完整性信息")

    skills_payload, _ = _expect(
        _request(
            port,
            "GET",
            "/api/v1/agent/skills",
            headers=headers,
        ),
        200,
        "读取企业智能体 Skill 清单",
    )
    skills = (
        skills_payload.get("skills")
        if isinstance(skills_payload, dict)
        else None
    )
    news_skill = next(
        (
            item
            for item in skills
            if isinstance(item, dict)
            and item.get("name") == "coal-news-search"
        ),
        None,
    ) if isinstance(skills, list) else None
    if (
        not isinstance(news_skill, dict)
        or news_skill.get("enabled") is not False
        or news_skill.get("read_only") is not True
        or news_skill.get("accepts_user_url") is not False
    ):
        raise VerificationError("煤炭新闻 Skill 清单或只读边界不正确")

    knowledge, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/chat/sessions/{session_id}/messages",
            payload={
                "content": "煤炭的燃点是多少？",
                "client_message_id": "e2e-coal-chat-turn-000",
            },
            headers=headers,
        ),
        202,
        "验证绑定草稿时煤炭通识可直接回答",
    )
    knowledge_messages = (
        knowledge.get("messages") if isinstance(knowledge, dict) else None
    )
    knowledge_answer = (
        knowledge_messages[-1]
        if isinstance(knowledge_messages, list) and knowledge_messages
        else None
    )
    knowledge_evidence = (
        knowledge_answer.get("evidence")
        if isinstance(knowledge_answer, dict)
        else None
    )
    if (
        not isinstance(knowledge, dict)
        or knowledge.get("run_id") is not None
        or not isinstance(knowledge_answer, dict)
        or knowledge_answer.get("status") != "completed"
        or not isinstance(knowledge_answer.get("content"), str)
        or "没有适用于所有煤种的单一" not in knowledge_answer["content"]
        or "当前本地知识可解释" in knowledge_answer["content"]
        or not isinstance(knowledge_evidence, dict)
        or knowledge_evidence.get("general_knowledge") is not True
        or knowledge_evidence.get("answer_kind") != "local_knowledge"
        or knowledge_evidence.get("enterprise_data_sent_to_provider") is not False
    ):
        raise VerificationError("煤炭通识未直接回答或越过了企业数据边界")

    news, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/chat/sessions/{session_id}/messages",
            payload={
                "content": "帮我看看最近煤炭相关新闻",
                "client_message_id": "e2e-coal-chat-turn-news",
            },
            headers=headers,
        ),
        202,
        "验证煤炭新闻请求调用独立搜索 Skill",
    )
    news_messages = (
        news.get("messages") if isinstance(news, dict) else None
    )
    news_answer = (
        news_messages[-1]
        if isinstance(news_messages, list) and news_messages
        else None
    )
    news_evidence = (
        news_answer.get("evidence")
        if isinstance(news_answer, dict)
        else None
    )
    retrieval = (
        news_evidence.get("retrieval")
        if isinstance(news_evidence, dict)
        else None
    )
    if (
        not isinstance(news, dict)
        or news.get("run_id") is not None
        or not isinstance(news_answer, dict)
        or news_answer.get("status") != "completed"
        or not isinstance(news_answer.get("content"), str)
        or "煤炭新闻检索未完成" not in news_answer["content"]
        or "没有用离线知识冒充最新新闻" not in news_answer["content"]
        or "以上为公开网络检索线索" not in news_answer["content"]
        or "离线知识库没有足够" in news_answer["content"]
        or "这是煤炭通识说明" in news_answer["content"]
        or "现场安全阈值" in news_answer["content"]
        or not isinstance(news_evidence, dict)
        or news_evidence.get("answer_kind") != "news_retrieval"
        or news_evidence.get("skill_name") != "coal-news-search"
        or news_evidence.get("draft_data_sent_to_skill") is not False
        or news_evidence.get("enterprise_data_sent_to_provider") is not False
        or not isinstance(retrieval, dict)
        or retrieval.get("status") != "unavailable"
        or news_evidence.get("sources") != []
    ):
        raise VerificationError("煤炭新闻请求未遵守独立 Skill 或透明失败边界")

    accepted, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/chat/sessions/{session_id}/messages",
            payload={
                "content": (
                    "请对当前煤炭草稿执行预检，解释来源凭证和煤流差额；"
                    "只读分析，不得确认或提交。"
                ),
                "draft_id": draft_id,
                "client_message_id": "e2e-coal-chat-turn-001",
            },
            headers=headers,
        ),
        202,
        "发送煤炭业务对话消息",
    )
    run_id = accepted.get("run_id") if isinstance(accepted, dict) else None
    if not isinstance(run_id, str) or not run_id:
        raise VerificationError("草稿绑定煤炭对话未创建只读运行")

    deadline = time.monotonic() + max(timeout, 5.0)
    while time.monotonic() < deadline:
        detail, _ = _expect(
            _request(
                port,
                "GET",
                f"/api/v1/chat/sessions/{session_id}",
                headers=headers,
            ),
            200,
            "轮询煤炭业务对话",
        )
        messages = (
            detail.get("messages") if isinstance(detail, dict) else None
        )
        latest = messages[-1] if isinstance(messages, list) and messages else None
        if (
            isinstance(latest, dict)
            and latest.get("role") == "assistant"
            and latest.get("status") != "queued"
        ):
            break
        time.sleep(0.05)
    else:
        raise VerificationError("煤炭业务对话未在期限内完成")

    if (
        latest.get("status") != "completed"
        or not isinstance(latest.get("content"), str)
        or "不是监管认定" not in latest["content"]
        or not isinstance(detail.get("integrity"), dict)
        or detail["integrity"].get("valid") is not True
        or detail.get("actionable") is not True
    ):
        raise VerificationError("煤炭业务对话缺少受控答复或完整性证明")

    run_payload, _ = _expect(
        _request(
            port,
            "GET",
            f"/api/v1/agent/runs/{run_id}",
            headers=headers,
        ),
        200,
        "核验煤炭业务对话只读运行",
    )
    run = run_payload.get("run") if isinstance(run_payload, dict) else None
    calls = run.get("tool_calls") if isinstance(run, dict) else None
    if (
        not isinstance(run, dict)
        or run.get("status") != "completed"
        or not isinstance(calls, list)
        or not calls
        or run.get("approvals") not in ([], None)
        or any(
            not isinstance(call, dict)
            or call.get("tool_name") == "draft_patch"
            or call.get("status") != "succeeded"
            for call in calls
        )
    ):
        raise VerificationError("煤炭业务对话运行未保持永久只读")

    refused, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/chat/sessions/{session_id}/messages",
            payload={
                "content": "请写一个股票交易程序",
                "client_message_id": "e2e-coal-chat-turn-002",
            },
            headers=headers,
        ),
        202,
        "验证煤炭对话领域拒绝",
    )
    refused_messages = (
        refused.get("messages") if isinstance(refused, dict) else None
    )
    refusal = (
        refused_messages[-1]
        if isinstance(refused_messages, list) and refused_messages
        else None
    )
    if (
        not isinstance(refused, dict)
        or refused.get("run_id") is not None
        or not isinstance(refusal, dict)
        or refusal.get("status") != "refused"
        or (refusal.get("domain") or {}).get("allowed") is not False
        or "未调用模型或工具" not in str(refusal.get("content"))
    ):
        raise VerificationError("非煤炭请求未在模型和工具调用前被拒绝")

    after_payload, _ = _expect(
        _request(
            port,
            "GET",
            f"/api/v1/drafts/{draft_id}",
            headers=headers,
        ),
        200,
        "读取煤炭对话后草稿状态",
    )
    after = (
        after_payload.get("draft")
        if isinstance(after_payload, dict)
        else None
    )
    after_meta = after.get("_meta") if isinstance(after, dict) else None
    if (
        not isinstance(after_meta, dict)
        or after_meta.get("revision") != before_meta.get("revision")
        or after_meta.get("confirmed") != before_meta.get("confirmed")
    ):
        raise VerificationError("只读煤炭对话意外修改或撤销了草稿")

    _expect(
        _request(
            port,
            "DELETE",
            f"/api/v1/chat/sessions/{session_id}",
            payload={},
            headers=headers,
        ),
        200,
        "移除煤炭业务对话",
    )
    deleted_status, _deleted_payload, _ = _request(
        port,
        "GET",
        f"/api/v1/chat/sessions/{session_id}",
        headers=headers,
    )
    if deleted_status != 404:
        raise VerificationError("已移除煤炭业务对话仍可被普通列表接口读取")
    return session_id


def _submit_agent_draft(
    *,
    port: int,
    cookie: str,
    csrf: str,
    draft_id: str,
    idempotency_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    headers = _agent_headers(cookie, csrf)
    submitted, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/submit",
            payload={"idempotency_key": idempotency_key},
            headers=headers,
            timeout=30,
        ),
        200,
        "通过智能体提交监管平台",
    )
    submission = (
        submitted.get("submission")
        if isinstance(submitted, dict)
        else None
    )
    if not isinstance(submission, dict):
        raise VerificationError("提交响应缺少 submission")
    if submission.get("status") != "succeeded":
        raise VerificationError(
            "智能体未记录成功提交："
            + json.dumps(submission, ensure_ascii=False)[:2000]
        )
    receipt = submission.get("receipt")
    if not isinstance(receipt, dict):
        raise VerificationError("成功提交记录缺少平台回执")
    if (
        receipt.get("status") != "accepted"
        or receipt.get("regulatory_outcome")
        != "not_determined_at_intake"
        or not isinstance(receipt.get("intake_batch_id"), str)
    ):
        raise VerificationError(
            "平台回执语义不符合契约："
            + json.dumps(receipt, ensure_ascii=False)[:2000]
        )
    return submission, receipt


def _expect_agent_submission_failure(
    *,
    port: int,
    cookie: str,
    csrf: str,
    draft_id: str,
    idempotency_key: str,
    operation: str,
    expected_platform_code: str | None = None,
) -> None:
    payload, _ = _expect(
        _request(
            port,
            "POST",
            f"/api/v1/drafts/{draft_id}/submit",
            payload={"idempotency_key": idempotency_key},
            headers=_agent_headers(cookie, csrf),
            timeout=30,
        ),
        502,
        operation,
    )
    error = payload.get("error") if isinstance(payload, dict) else None
    if (
        not isinstance(error, dict)
        or error.get("code") != "platform_submission_failed"
    ):
        raise VerificationError(
            f"{operation} 未返回安全、可重试的平台失败错误"
        )
    if expected_platform_code is not None:
        details = error.get("details")
        if (
            not isinstance(details, dict)
            or details.get("platform_code") != expected_platform_code
        ):
            raise VerificationError(
                f"{operation} 未保留可操作的监管错误码 "
                f"{expected_platform_code}"
            )


def _failed_submission_record(
    *,
    port: int,
    cookie: str,
    draft_id: str,
    idempotency_key: str,
    expected_retryable: bool,
    expected_platform_code: str | None = None,
    expected_failure_kind: str | None = None,
) -> dict[str, Any]:
    payload, _ = _expect(
        _request(
            port,
            "GET",
            f"/api/v1/drafts/{draft_id}/submissions",
            headers={"Cookie": cookie},
        ),
        200,
        "查询企业端持久化失败详情",
    )
    items = (
        payload.get("submissions")
        if isinstance(payload, dict)
        else None
    )
    matching = (
        [
            item
            for item in items
            if isinstance(item, dict)
            and item.get("idempotency_key") == idempotency_key
        ]
        if isinstance(items, list)
        else []
    )
    if len(matching) != 1 or matching[0].get("status") != "failed":
        raise VerificationError("企业端未持久保存唯一的失败提交记录")
    stored = matching[0]
    error = stored.get("error")
    if (
        not isinstance(error, dict)
        or error.get("retryable") is not expected_retryable
    ):
        raise VerificationError("企业端失败记录缺少正确的可重试语义")
    if (
        expected_platform_code is not None
        and error.get("platform_code") != expected_platform_code
    ):
        raise VerificationError(
            "企业端失败记录未保存监管端结构化错误码"
        )
    if (
        expected_failure_kind is not None
        and error.get("failure_kind") != expected_failure_kind
    ):
        raise VerificationError("企业端失败记录未保存连接失败类型")
    return stored


def _verify_platform_receipt_and_batch(
    *,
    port: int,
    receipt: dict[str, Any],
    admin_cookie: str,
    transport_client_id: str,
    transport_secret: str,
    confirmer_registration_id: str,
    snapshot_id: str,
) -> None:
    receipt_path = (receipt.get("links") or {}).get("self")
    if not isinstance(receipt_path, str):
        raise VerificationError("回执缺少自查询链接")
    empty_body = b""
    wrong_headers = _transport_headers(
        method="GET",
        path=receipt_path,
        body=empty_body,
        client_id=transport_client_id,
        secret_value="wrong_" + ("x" * 40),
    )
    wrong_status, wrong_payload, _ = _request(
        port,
        "GET",
        receipt_path,
        headers=wrong_headers,
    )
    if wrong_status != 401:
        raise VerificationError(
            "错误运输密钥查询回执未被平台以 HTTP 401 拒绝"
        )
    if (
        not isinstance(wrong_payload, dict)
        or wrong_payload.get("code") != "AUTHENTICATION_FAILED"
    ):
        raise VerificationError("运输认证失败响应缺少统一安全错误码")
    signed_headers = _transport_headers(
        method="GET",
        path=receipt_path,
        body=empty_body,
        client_id=transport_client_id,
        secret_value=transport_secret,
    )
    fetched, _ = _expect(
        _request(
            port,
            "GET",
            receipt_path,
            headers=signed_headers,
        ),
        200,
        "用独立 HMAC 查询平台回执",
    )
    if fetched != receipt:
        raise VerificationError("平台回执自查询结果与智能体收到的回执不一致")

    batch_id = receipt["intake_batch_id"]
    detail, _ = _expect(
        _request(
            port,
            "GET",
            f"/v1/analysis-batches/{batch_id}",
            headers={"Cookie": admin_cookie},
        ),
        200,
        "查询监管分析批次上下文",
    )
    batch = detail.get("batch") if isinstance(detail, dict) else None
    if not isinstance(batch, dict):
        raise VerificationError("监管批次详情缺少 batch")
    if batch.get("integrity_valid") is not True:
        raise VerificationError("监管批次完整性校验未通过")
    context = batch.get("context")
    if not isinstance(context, dict):
        raise VerificationError("监管批次缺少不可变接入上下文")
    submission = context.get("external_submission")
    confirmer = context.get("external_confirmer_registration")
    snapshot = context.get("external_event_snapshot")
    if (
        context.get("kind") != "enterprise_agent_governed_ingest"
        or context.get("external_client_id") != transport_client_id
        or not isinstance(submission, dict)
        or submission.get("submission_id") != receipt.get("submission_id")
        or not isinstance(confirmer, dict)
        or confirmer.get("registration_id")
        != confirmer_registration_id
        or not isinstance(snapshot, dict)
        or snapshot.get("snapshot_id") != snapshot_id
    ):
        raise VerificationError(
            "监管批次未绑定完整的提交、确认人和事件快照上下文"
        )
    if detail.get("lifecycle_chain_valid") is not True:
        raise VerificationError("监管批次生命周期审计链无效")


def _application_environment(source_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for name in tuple(environment):
        if (
            name.startswith("DEEPSEEK_")
            or name.startswith("OPENAI_")
            or name.startswith("MINEGUARD_")
            or name.startswith("ENTERPRISE_AGENT_")
            or name.startswith("PLATFORM_")
            or name == "PYTHONPATH"
        ):
            environment.pop(name, None)
    # Each process sees only its own implementation source tree.  There is no
    # path through which it could import the opposing application package.
    environment["PYTHONPATH"] = str(source_root)
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


def _python_for(application_root: Path, explicit: str | None) -> str:
    if explicit:
        return explicit
    candidate = application_root / ".venv" / "bin" / "python"
    return str(candidate) if candidate.is_file() else sys.executable


def _verify_occupied_port_failure(
    *,
    name: str,
    command_prefix: list[str],
    cwd: Path,
    environment: dict[str, str],
    log_path: Path,
) -> None:
    """A service must fail fast instead of looking healthy on another port."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        occupied_port = int(listener.getsockname()[1])
        managed = _start_process(
            name=name,
            command=[
                *command_prefix,
                "--host",
                "127.0.0.1",
                "--port",
                str(occupied_port),
            ],
            cwd=cwd,
            environment=environment,
            log_path=log_path,
        )
        try:
            _wait_until_stopped(
                managed,
                timeout=10,
                operation=f"{name} 端口占用保护",
            )
            if not _port_accepts_connections(occupied_port):
                raise VerificationError(
                    f"{name} 端口占用测试破坏了原有监听者"
                )
        finally:
            managed.stop()


def _verify_remote_bind_guard(
    *,
    agent_python: str,
    environment: dict[str, str],
    log_path: Path,
) -> None:
    """Direct LAN exposure without HTTPS-cookie safeguards must fail."""

    managed = _start_process(
        name="企业智能体非安全远程监听测试",
        command=[
            agent_python,
            "-m",
            "enterprise_agent",
            "serve",
            "--host",
            "0.0.0.0",
            "--port",
            str(_unused_port()),
        ],
        cwd=AGENT_ROOT,
        environment=environment,
        log_path=log_path,
    )
    try:
        _wait_until_stopped(
            managed,
            timeout=10,
            operation="企业智能体非安全远程监听保护",
        )
    finally:
        managed.stop()


def _verify_demo_restrictions(
    *,
    agent_python: str,
    environment: dict[str, str],
    database_path: Path,
    log_path: Path,
    timeout: float,
) -> None:
    """The convenient local demo login must never become a submitter."""

    port = _unused_port()
    demo_environment = dict(environment)
    demo_environment["ENTERPRISE_AGENT_DB"] = str(database_path)
    demo = _start_process(
        name="企业智能体演示账号测试",
        command=[
            agent_python,
            "-m",
            "enterprise_agent",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=AGENT_ROOT,
        environment=demo_environment,
        log_path=log_path,
    )
    try:
        _wait_until_ready(
            demo,
            port=port,
            path="/api/v1/health",
            timeout=timeout,
        )
        if "已启动（前台运行）" not in demo.log_tail():
            raise VerificationError(
                "企业智能体启动后没有输出面向操作员的监听提示"
            )
        cookie, csrf, principal = _login_agent(
            port,
            actor_id="demo",
            password="123123123",
        )
        if (
            principal.get("temporary_demo") is not True
            or principal.get("must_change_password") is not True
        ):
            raise VerificationError("本机演示账号未被标记为临时且必须改密")
        created, _ = _expect(
            _request(
                port,
                "POST",
                "/api/v1/drafts",
                payload={},
                headers=_agent_headers(cookie, csrf),
            ),
            201,
            "演示账号新建草稿",
        )
        draft = created.get("draft") if isinstance(created, dict) else None
        draft_id = draft.get("draft_id") if isinstance(draft, dict) else None
        if not isinstance(draft_id, str):
            raise VerificationError("演示账号新建草稿响应缺少 ID")
        for action in ("confirm", "submit"):
            denied, _ = _expect(
                _request(
                    port,
                    "POST",
                    f"/api/v1/drafts/{draft_id}/{action}",
                    payload={},
                    headers=_agent_headers(cookie, csrf),
                ),
                403,
                f"演示账号禁止 {action}",
            )
            error = (
                denied.get("error") if isinstance(denied, dict) else None
            )
            if not isinstance(error, dict):
                raise VerificationError(
                    f"演示账号 {action} 拒绝响应缺少结构化错误"
                )
        _interrupt_cleanly(demo, timeout=10)
    finally:
        demo.stop()
    if _port_accepts_connections(port):
        raise VerificationError("演示账号测试退出后仍残留监听进程")


def _verify_public_origin_proxy_boundary(
    *,
    agent_python: str,
    environment: dict[str, str],
    database_path: Path,
    log_path: Path,
    timeout: float,
    password: str,
) -> None:
    """Check the explicit reverse-proxy origin without trusting proxy hints."""

    port = _unused_port()
    public_origin = "https://report.example.test"
    public_host = "report.example.test"
    proxy_environment = dict(environment)
    proxy_environment.update(
        {
            "ENTERPRISE_AGENT_DB": str(database_path),
            "ENTERPRISE_AGENT_SECURE_COOKIE": "true",
            "ENTERPRISE_AGENT_PUBLIC_ORIGIN": public_origin,
        }
    )
    managed = _start_process(
        name="企业智能体 HTTPS 反向代理边界测试",
        command=[
            agent_python,
            "-m",
            "enterprise_agent",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=AGENT_ROOT,
        environment=proxy_environment,
        log_path=log_path,
    )
    try:
        _wait_until_ready(
            managed,
            port=port,
            path="/api/v1/health",
            timeout=timeout,
        )
        browser_headers = {
            "Host": public_host,
            "Origin": public_origin,
            "Sec-Fetch-Site": "same-origin",
        }
        login, response_headers = _expect(
            _request(
                port,
                "POST",
                "/api/v1/auth/login",
                payload={
                    "actor_id": "operator-001",
                    "password": password,
                },
                headers=browser_headers,
            ),
            200,
            "显式 HTTPS public origin 登录",
        )
        cookie_header = response_headers.get("set-cookie", "")
        cookie = cookie_header.split(";", 1)[0]
        csrf = login.get("csrf_token") if isinstance(login, dict) else None
        if (
            not cookie
            or not isinstance(csrf, str)
            or "Secure" not in cookie_header
        ):
            raise VerificationError(
                "HTTPS public origin 未签发 Secure 企业会话"
            )
        authenticated_headers = {
            **browser_headers,
            "Cookie": cookie,
            "X-CSRF-Token": csrf,
        }
        _expect(
            _request(
                port,
                "POST",
                "/api/v1/drafts",
                payload={},
                headers=authenticated_headers,
            ),
            201,
            "显式 HTTPS public origin 同源修改",
        )
        for label, hostile_headers, expected_code in (
            (
                "恶意 Origin",
                {
                    **authenticated_headers,
                    "Origin": "https://evil.example.test",
                },
                "cross_origin_request_denied",
            ),
            (
                "恶意 Host",
                {
                    **authenticated_headers,
                    "Host": "evil.example.test",
                    "Origin": "https://evil.example.test",
                },
                "host_not_allowed",
            ),
            (
                "伪造 X-Forwarded 头",
                {
                    **authenticated_headers,
                    "Host": f"127.0.0.1:{port}",
                    "Origin": public_origin,
                    "X-Forwarded-Host": public_host,
                    "X-Forwarded-Proto": "https",
                },
                "host_not_allowed",
            ),
        ):
            denied, _ = _expect(
                _request(
                    port,
                    "POST",
                    "/api/v1/drafts",
                    payload={},
                    headers=hostile_headers,
                ),
                403,
                f"{label} 被企业端拒绝",
            )
            error = (
                denied.get("error") if isinstance(denied, dict) else None
            )
            if (
                not isinstance(error, dict)
                or error.get("code") != expected_code
            ):
                raise VerificationError(f"{label} 拒绝响应错误码不明确")
    finally:
        managed.stop()
    if _port_accepts_connections(port):
        raise VerificationError("反向代理边界测试退出后仍残留监听进程")


def verify(
    *,
    timeout: float,
    platform_python: str | None,
    agent_python: str | None,
) -> dict[str, Any]:
    _verify_gateway_signature_fixed_vector()

    now = datetime.now(UTC).replace(microsecond=0)
    window_end = now - timedelta(minutes=5)
    window_start = window_end - timedelta(hours=8)
    platform_port = _unused_port()
    agent_port = _unused_port()
    while agent_port == platform_port:
        agent_port = _unused_port()

    transport_client_id = "e2e-enterprise-client"
    transport_secret = (
        "DEMO_ONLY_transport_" + secrets.token_urlsafe(32)
    )
    platform_admin_password = "E2E-admin-password-2026"
    agent_password = "E2E-agent-password-2026"
    source_templates = [
        ("e2e-production-report", "coal.reported_output_t", 1000.25),
        ("e2e-main-transport", "coal.main_transport_t", 1000.25),
        ("e2e-wash-feed", "wash.feed_t", 800.25),
        ("e2e-raw-sales", "sales.raw_shipped_t", 100.25),
        (
            "e2e-raw-stock-change",
            "inventory.raw_change_t",
            99.75,
        ),
    ]
    source_definitions = [
        {
            "source_id": source_id,
            "metric_code": metric_code,
            "value": value,
            "secret": (
                f"DEMO_ONLY_source_{index}_"
                + secrets.token_urlsafe(28)
            ),
        }
        for index, (source_id, metric_code, value) in enumerate(
            source_templates,
            start=1,
        )
    ]
    _, import_content = _make_import_document(
        window_start=window_start,
        window_end=window_end,
        source_definitions=source_definitions,
    )
    authoritative_event_export = {
        "query_contract": "e2e-regulator-event-query-v1",
        "mine_id": "M001",
        "window_start": _utc_text(window_start),
        "window_end": _utc_text(window_end),
        "event_codes": [],
        "source_system": "e2e-regulator-event-ledger",
        "record_id": "e2e:event-query:M001:001",
    }
    event_evidence_sha256 = hashlib.sha256(
        _canonical_json_bytes(authoritative_event_export)
    ).hexdigest()
    event_snapshot = {
        "snapshot_id": "e2e-event-snapshot-001",
        "mine_id": authoritative_event_export["mine_id"],
        "window_start": authoritative_event_export["window_start"],
        "window_end": authoritative_event_export["window_end"],
        "event_codes": authoritative_event_export["event_codes"],
        "evidence_sha256": event_evidence_sha256,
        "source_system": authoritative_event_export["source_system"],
        "record_id": authoritative_event_export["record_id"],
    }

    managed_processes: list[ManagedProcess] = []
    result: dict[str, Any] | None = None
    redactions = (
        transport_secret,
        *(item["secret"] for item in source_definitions),
        platform_admin_password,
        agent_password,
    )
    with tempfile.TemporaryDirectory(
        prefix="coral-two-process-e2e-"
    ) as temporary:
        temporary_root = Path(temporary)
        try:
            platform_executable = _python_for(
                PLATFORM_ROOT,
                platform_python,
            )
            agent_executable = _python_for(AGENT_ROOT, agent_python)
            platform_state = temporary_root / "platform-state"
            agent_database = temporary_root / "agent.db"
            platform_environment = _application_environment(
                PLATFORM_ROOT / "src"
            )
            platform_environment.update(
                {
                    "MINEGUARD_ADMIN_PASSWORD": (
                        platform_admin_password
                    ),
                    "MINEGUARD_EXTERNAL_CLIENTS_JSON": json.dumps(
                        [
                            {
                                "client_id": transport_client_id,
                                "enterprise_id": "ENT-001",
                                "mine_ids": ["M001"],
                                "secrets": [transport_secret],
                            }
                        ],
                        separators=(",", ":"),
                    ),
                }
            )
            agent_environment = _application_environment(
                AGENT_ROOT / "src"
            )
            agent_environment.update(
                {
                    "ENTERPRISE_AGENT_DB": str(agent_database),
                    "ENTERPRISE_AGENT_USERS_JSON": json.dumps(
                        [
                            {
                                "actor_id": "operator-001",
                                "name": "张三",
                                "role": "企业报送负责人",
                                "password_hash": _password_hash(
                                    agent_password
                                ),
                                "permissions": [
                                    "read",
                                    "write",
                                    "confirm",
                                    "submit",
                                ],
                                "must_change_password": False,
                            }
                        ],
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    "PLATFORM_BASE_URL": (
                        f"http://127.0.0.1:{platform_port}"
                    ),
                    "PLATFORM_CLIENT_ID": transport_client_id,
                    "PLATFORM_TRANSPORT_HMAC_SECRET": (
                        transport_secret
                    ),
                    # The black-box suite must not depend on public internet
                    # availability. Unit tests cover successful RSS parsing;
                    # here we verify transparent unavailable semantics.
                    "COAL_NEWS_SEARCH_ENABLED": "false",
                }
            )

            _verify_occupied_port_failure(
                name="监管平台",
                command_prefix=[
                    platform_executable,
                    "-m",
                    "mineguard",
                    "serve",
                    "--state-directory",
                    str(temporary_root / "occupied-platform-state"),
                ],
                cwd=PLATFORM_ROOT,
                environment=platform_environment,
                log_path=temporary_root / "occupied-platform.log",
            )
            occupied_agent_environment = dict(agent_environment)
            occupied_agent_environment["ENTERPRISE_AGENT_DB"] = str(
                temporary_root / "occupied-agent.db"
            )
            _verify_occupied_port_failure(
                name="企业智能体",
                command_prefix=[
                    agent_executable,
                    "-m",
                    "enterprise_agent",
                    "serve",
                ],
                cwd=AGENT_ROOT,
                environment=occupied_agent_environment,
                log_path=temporary_root / "occupied-agent.log",
            )
            isolated_agent_environment = _application_environment(
                AGENT_ROOT / "src"
            )
            isolated_agent_environment["ENTERPRISE_AGENT_DB"] = str(
                temporary_root / "remote-guard-agent.db"
            )
            _verify_remote_bind_guard(
                agent_python=agent_executable,
                environment=isolated_agent_environment,
                log_path=temporary_root / "remote-guard-agent.log",
            )
            _verify_demo_restrictions(
                agent_python=agent_executable,
                environment=_application_environment(
                    AGENT_ROOT / "src"
                ),
                database_path=temporary_root / "demo-agent.db",
                log_path=temporary_root / "demo-agent.log",
                timeout=timeout,
            )
            _verify_public_origin_proxy_boundary(
                agent_python=agent_executable,
                environment=agent_environment,
                database_path=temporary_root / "proxy-agent.db",
                log_path=temporary_root / "proxy-agent.log",
                timeout=timeout,
                password=agent_password,
            )

            platform = _start_process(
                name="监管平台",
                command=[
                    platform_executable,
                    "-m",
                    "mineguard",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(platform_port),
                    "--state-directory",
                    str(platform_state),
                ],
                cwd=PLATFORM_ROOT,
                environment=platform_environment,
                log_path=temporary_root / "platform.log",
            )
            managed_processes.append(platform)
            _wait_until_ready(
                platform,
                port=platform_port,
                path="/ready",
                timeout=timeout,
            )
            admin_cookie, admin_csrf = _login_platform(
                platform_port,
                username="admin",
                password=platform_admin_password,
            )
            agent = _start_process(
                name="企业智能体",
                command=[
                    agent_executable,
                    "-m",
                    "enterprise_agent",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(agent_port),
                ],
                cwd=AGENT_ROOT,
                environment=agent_environment,
                log_path=temporary_root / "agent.log",
            )
            managed_processes.append(agent)
            _wait_until_ready(
                agent,
                port=agent_port,
                path="/api/v1/health",
                timeout=timeout,
            )
            agent_cookie, agent_csrf, principal = _login_agent(
                agent_port,
                actor_id="operator-001",
                password=agent_password,
            )
            if (
                principal.get("must_change_password") is not False
                or principal.get("temporary_demo") is not False
                or set(principal.get("permissions", []))
                != {"read", "write", "confirm", "submit"}
            ):
                raise VerificationError("企业端未使用配置的正式全权限账号")

            first_draft = _prepare_agent_draft(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                import_content=import_content,
                event_snapshot=event_snapshot,
            )
            harness_run_id = _verify_agent_coal_harness(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                draft_id=first_draft["draft_id"],
                forbidden_values=redactions,
                timeout=timeout,
            )
            chat_session_id = _verify_agent_coal_chat(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                draft_id=first_draft["draft_id"],
                timeout=timeout,
            )
            first_key = "ENT-001-two-process-e2e-submission-001"
            _expect_agent_submission_failure(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                draft_id=first_draft["draft_id"],
                idempotency_key=first_key,
                operation="监管配置未登记时拒绝企业提交",
                expected_platform_code="CONFIRMER_NOT_AUTHORIZED",
            )
            _failed_submission_record(
                port=agent_port,
                cookie=agent_cookie,
                draft_id=first_draft["draft_id"],
                idempotency_key=first_key,
                expected_retryable=False,
                expected_platform_code="CONFIRMER_NOT_AUTHORIZED",
            )

            confirmer_registration_id, snapshot_id = (
                _register_platform_configuration(
                    port=platform_port,
                    cookie=admin_cookie,
                    csrf=admin_csrf,
                    now=now,
                    window_start=window_start,
                    window_end=window_end,
                    client_id=transport_client_id,
                    source_definitions=source_definitions,
                    event_evidence_sha256=event_evidence_sha256,
                )
            )
            first_submission, receipt = _submit_agent_draft(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                draft_id=first_draft["draft_id"],
                idempotency_key=first_key,
            )
            replayed_submission, replayed_receipt = _submit_agent_draft(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                draft_id=first_draft["draft_id"],
                idempotency_key=first_key,
            )
            if (
                replayed_submission.get("replayed") is not True
                or replayed_submission.get("request_sha256")
                != first_submission.get("request_sha256")
                or replayed_receipt != receipt
            ):
                raise VerificationError(
                    "相同草稿和幂等键的重复提交未复用原请求与回执"
                )
            _verify_platform_receipt_and_batch(
                port=platform_port,
                receipt=receipt,
                admin_cookie=admin_cookie,
                transport_client_id=transport_client_id,
                transport_secret=transport_secret,
                confirmer_registration_id=(
                    confirmer_registration_id
                ),
                snapshot_id=snapshot_id,
            )

            second_draft = _prepare_agent_draft(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                import_content=import_content,
                event_snapshot=event_snapshot,
            )
            second_key = "ENT-001-two-process-e2e-submission-002"
            platform.stop()
            if _port_accepts_connections(platform_port):
                raise VerificationError("监管平台停止后端口仍在监听")
            _expect_agent_submission_failure(
                port=agent_port,
                cookie=agent_cookie,
                csrf=agent_csrf,
                draft_id=second_draft["draft_id"],
                idempotency_key=second_key,
                operation="监管平台停机时企业端安全失败",
            )
            failed_item = _failed_submission_record(
                port=agent_port,
                cookie=agent_cookie,
                draft_id=second_draft["draft_id"],
                idempotency_key=second_key,
                expected_retryable=True,
                expected_failure_kind="connection",
            )
            failed_request_sha256 = failed_item.get("request_sha256")
            failed_submitted_at = failed_item.get("submitted_at")

            platform_recovered = _start_process(
                name="监管平台（恢复）",
                command=[
                    platform_executable,
                    "-m",
                    "mineguard",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(platform_port),
                    "--state-directory",
                    str(platform_state),
                ],
                cwd=PLATFORM_ROOT,
                environment=platform_environment,
                log_path=temporary_root / "platform-recovered.log",
            )
            managed_processes.append(platform_recovered)
            _wait_until_ready(
                platform_recovered,
                port=platform_port,
                path="/ready",
                timeout=timeout,
            )
            admin_cookie, _ = _login_platform(
                platform_port,
                username="admin",
                password=platform_admin_password,
            )
            agent.stop()
            wrong_agent_environment = dict(agent_environment)
            wrong_agent_environment[
                "PLATFORM_TRANSPORT_HMAC_SECRET"
            ] = "wrong_" + ("x" * 40)
            agent_wrong_key = _start_process(
                name="企业智能体（错误运输密钥）",
                command=[
                    agent_executable,
                    "-m",
                    "enterprise_agent",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(agent_port),
                ],
                cwd=AGENT_ROOT,
                environment=wrong_agent_environment,
                log_path=temporary_root / "agent-wrong-key.log",
            )
            managed_processes.append(agent_wrong_key)
            _wait_until_ready(
                agent_wrong_key,
                port=agent_port,
                path="/api/v1/health",
                timeout=timeout,
            )
            wrong_cookie, wrong_csrf, _ = _login_agent(
                agent_port,
                actor_id="operator-001",
                password=agent_password,
            )
            _expect_agent_submission_failure(
                port=agent_port,
                cookie=wrong_cookie,
                csrf=wrong_csrf,
                draft_id=second_draft["draft_id"],
                idempotency_key=second_key,
                operation="企业端错误运输密钥被监管平台拒绝",
                expected_platform_code="AUTHENTICATION_FAILED",
            )
            wrong_key_item = _failed_submission_record(
                port=agent_port,
                cookie=wrong_cookie,
                draft_id=second_draft["draft_id"],
                idempotency_key=second_key,
                expected_retryable=False,
                expected_platform_code="AUTHENTICATION_FAILED",
            )
            if (
                wrong_key_item.get("request_sha256")
                != failed_request_sha256
            ):
                raise VerificationError(
                    "错误密钥重试覆盖了平台停机前的原始请求"
                )
            agent_wrong_key.stop()

            agent_recovered = _start_process(
                name="企业智能体（恢复正确密钥）",
                command=[
                    agent_executable,
                    "-m",
                    "enterprise_agent",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(agent_port),
                ],
                cwd=AGENT_ROOT,
                environment=agent_environment,
                log_path=temporary_root / "agent-recovered.log",
            )
            managed_processes.append(agent_recovered)
            _wait_until_ready(
                agent_recovered,
                port=agent_port,
                path="/api/v1/health",
                timeout=timeout,
            )
            recovered_cookie, recovered_csrf, _ = _login_agent(
                agent_port,
                actor_id="operator-001",
                password=agent_password,
            )
            second_submission, second_receipt = _submit_agent_draft(
                port=agent_port,
                cookie=recovered_cookie,
                csrf=recovered_csrf,
                draft_id=second_draft["draft_id"],
                idempotency_key=second_key,
            )
            if (
                second_submission.get("request_sha256")
                != failed_request_sha256
                or second_submission.get("submitted_at")
                != failed_submitted_at
            ):
                raise VerificationError(
                    "平台恢复后的重试未复用停机前持久化的原始请求"
                )

            agent_recovered.stop()
            platform_recovered.stop()
            if _port_accepts_connections(agent_port) or _port_accepts_connections(
                platform_port
            ):
                raise VerificationError("服务停止后仍残留监听进程")

            platform_restarted = _start_process(
                name="监管平台（重启持久性）",
                command=[
                    platform_executable,
                    "-m",
                    "mineguard",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(platform_port),
                    "--state-directory",
                    str(platform_state),
                ],
                cwd=PLATFORM_ROOT,
                environment=platform_environment,
                log_path=temporary_root / "platform-restarted.log",
            )
            managed_processes.append(platform_restarted)
            agent_restarted = _start_process(
                name="企业智能体（重启持久性）",
                command=[
                    agent_executable,
                    "-m",
                    "enterprise_agent",
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(agent_port),
                ],
                cwd=AGENT_ROOT,
                environment=agent_environment,
                log_path=temporary_root / "agent-restarted.log",
            )
            managed_processes.append(agent_restarted)
            _wait_until_ready(
                platform_restarted,
                port=platform_port,
                path="/ready",
                timeout=timeout,
            )
            _wait_until_ready(
                agent_restarted,
                port=agent_port,
                path="/api/v1/health",
                timeout=timeout,
            )
            restarted_admin_cookie, _ = _login_platform(
                platform_port,
                username="admin",
                password=platform_admin_password,
            )
            restarted_cookie, restarted_csrf, _ = _login_agent(
                agent_port,
                actor_id="operator-001",
                password=agent_password,
            )
            persisted, _ = _expect(
                _request(
                    agent_port,
                    "GET",
                    f"/api/v1/drafts/{second_draft['draft_id']}",
                    headers={"Cookie": restarted_cookie},
                ),
                200,
                "重启后读取企业草稿",
            )
            persisted_draft = (
                persisted.get("draft")
                if isinstance(persisted, dict)
                else None
            )
            if (
                not isinstance(persisted_draft, dict)
                or (persisted_draft.get("_meta") or {}).get("submitted")
                is not True
            ):
                raise VerificationError("企业服务重启后未保留成功提交状态")
            persisted_submission, persisted_receipt = _submit_agent_draft(
                port=agent_port,
                cookie=restarted_cookie,
                csrf=restarted_csrf,
                draft_id=second_draft["draft_id"],
                idempotency_key=second_key,
            )
            if (
                persisted_submission.get("replayed") is not True
                or persisted_submission.get("request_sha256")
                != failed_request_sha256
                or persisted_receipt != second_receipt
            ):
                raise VerificationError(
                    "企业服务重启后未保留原始请求、幂等状态或回执"
                )
            _verify_platform_receipt_and_batch(
                port=platform_port,
                receipt=second_receipt,
                admin_cookie=restarted_admin_cookie,
                transport_client_id=transport_client_id,
                transport_secret=transport_secret,
                confirmer_registration_id=(
                    confirmer_registration_id
                ),
                snapshot_id=snapshot_id,
            )

            result = {
                "result": "passed",
                "processes": {
                    "platform": "independent subprocess",
                    "agent": "independent subprocess",
                },
                "boundary": "HTTP/JSON/HMAC only",
                "profile_registered": "e2e-five-flow@2026.1",
                "sources_registered": 5,
                "confirmer_registered": confirmer_registration_id,
                "event_snapshot_registered": snapshot_id,
                "submission_id": receipt["submission_id"],
                "receipt_id": receipt["receipt_id"],
                "intake_batch_id": receipt["intake_batch_id"],
                "harness_run_id": harness_run_id,
                "chat_session_id": chat_session_id,
                "regulatory_outcome": receipt["regulatory_outcome"],
                "operational_checks": [
                    "occupied_ports_fail_fast",
                    "unsafe_remote_bind_rejected",
                    "foreground_banner_and_clean_ctrl_c",
                    "explicit_public_origin_proxy_boundary",
                    "demo_cannot_confirm_or_submit",
                    "ordinary_report_cannot_replace_regulator_event_snapshot",
                    "empty_regulator_event_snapshot_has_authoritative_provenance",
                    "per_observation_review_required_and_persisted",
                    "coal_harness_tools_trace_and_secret_boundary",
                    "coal_chat_domain_readonly_integrity_and_delete",
                    "unregistered_platform_configuration_rejected",
                    "wrong_transport_key_rejected",
                    "actionable_failure_details_persisted",
                    "idempotent_duplicate_reuses_request_and_receipt",
                    "platform_outage_is_persisted_and_retryable",
                    "platform_and_agent_restart_preserve_data",
                    "normal_shutdown_leaves_no_child_listener",
                ],
            }
        except Exception as error:
            diagnostics = []
            for managed in managed_processes:
                diagnostics.append(
                    f"\n[{managed.name} log]\n"
                    + managed.log_tail(redactions=redactions)
                )
            if diagnostics:
                raise VerificationError(
                    f"{error}\n" + "\n".join(diagnostics)
                ) from error
            raise
        finally:
            for managed in reversed(managed_processes):
                managed.stop()
        if _port_accepts_connections(platform_port) or _port_accepts_connections(
            agent_port
        ):
            raise VerificationError("验收清理后仍残留子进程监听端口")
    if result is None:
        raise VerificationError("验收未产生结果")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "以两个独立子进程黑盒验收监管平台与企业智能体的 HTTP/JSON/HMAC 链路"
        )
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="每个服务的启动超时秒数（默认 30）",
    )
    parser.add_argument(
        "--platform-python",
        help="监管平台 Python 解释器；默认优先 platform/.venv/bin/python",
    )
    parser.add_argument(
        "--agent-python",
        help="企业智能体 Python 解释器；默认优先 agent/.venv/bin/python",
    )
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout 必须大于 0")
    try:
        result = verify(
            timeout=args.timeout,
            platform_python=args.platform_python,
            agent_python=args.agent_python,
        )
    except (VerificationError, OSError, ValueError) as error:
        print(f"双进程验收失败：{error}", file=sys.stderr)
        return 1
    print("双进程端到端验收通过")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
