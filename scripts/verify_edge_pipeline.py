#!/usr/bin/env python3
"""Black-box acceptance test for mine-edge-agent -> MineGuard.

The verifier intentionally imports neither application's source code.  It
starts both applications as independent subprocesses, communicates only over
HTTP, and uses temporary databases and a temporary shared HMAC key.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
PLATFORM_DIR = ROOT / "platform"
EDGE_DIR = ROOT / "edge-agent"
MINE_ID = "M001"
CLIENT_ID = "mine-edge-M001"


class VerificationError(RuntimeError):
    pass


@dataclass
class ManagedProcess:
    name: str
    process: subprocess.Popen[bytes]
    log_path: Path
    log_stream: Any

    def assert_running(self) -> None:
        code = self.process.poll()
        if code is not None:
            raise VerificationError(
                f"{self.name} exited unexpectedly with code {code}\n"
                f"{self.tail()}"
            )

    def tail(self, lines: int = 80) -> str:
        try:
            content = self.log_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError as error:
            return f"[cannot read {self.log_path}: {error}]"
        selected = "\n".join(content[-lines:])
        return f"--- {self.name} log ({self.log_path}) ---\n{selected}"

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log_stream.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "启动独立 platform/edge-agent 进程，验收 HMAC 上行、"
            "断网续传、回执和监管独立预警"
        )
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=40,
        help="每个阶段最长等待秒数（默认 40）",
    )
    parser.add_argument(
        "--keep-temp",
        action="store_true",
        help="成功或失败后保留临时数据库和日志",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="输出每个验收步骤",
    )
    return parser


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _clean_environment(prefix: str) -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(prefix)
    }
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


def _start(
    name: str,
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log_path: Path,
) -> ManagedProcess:
    log_stream = log_path.open("wb")
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except Exception:
        log_stream.close()
        raise
    return ManagedProcess(name, process, log_path, log_stream)


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request(
    method: str,
    url: str,
    *,
    document: Any | None = None,
    timeout: float = 3,
) -> tuple[int, Any]:
    data = None
    headers = {"Accept": "application/json"}
    if document is not None:
        data = json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            raw = response.read()
            value = json.loads(raw) if raw else None
            return int(response.status), value
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            value = json.loads(raw) if raw else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = raw.decode("utf-8", errors="replace")
        return int(error.code), value


def _expect(
    method: str,
    url: str,
    *,
    expected: set[int],
    document: Any | None = None,
) -> Any:
    try:
        status, body = _request(method, url, document=document)
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise VerificationError(f"{method} {url} failed: {error}") from error
    if status not in expected:
        rendered = json.dumps(body, ensure_ascii=False)[:4000]
        raise VerificationError(
            f"{method} {url} returned HTTP {status}, expected "
            f"{sorted(expected)}: {rendered}"
        )
    return body


def _wait_http(
    name: str,
    url: str,
    process: ManagedProcess,
    *,
    timeout: float,
) -> Any:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        process.assert_running()
        try:
            status, body = _request("GET", url, timeout=1)
            if status == 200:
                return body
            last_error = f"HTTP {status}: {body}"
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            last_error = str(error)
        time.sleep(0.15)
    raise VerificationError(
        f"timed out waiting for {name} at {url}: {last_error}\n"
        f"{process.tail()}"
    )


def _wait_until(
    description: str,
    function: Callable[[], Any | None],
    processes: list[ManagedProcess],
    *,
    timeout: float,
) -> Any:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        for process in processes:
            process.assert_running()
        try:
            value = function()
            if value is not None:
                return value
        except (
            OSError,
            TimeoutError,
            urllib.error.URLError,
            VerificationError,
        ) as error:
            last_error = error
        time.sleep(0.2)
    suffix = f": {last_error}" if last_error else ""
    raise VerificationError(f"timed out waiting for {description}{suffix}")


def _platform_environment(
    *,
    secret_base64: str,
    platform_source: Path,
) -> dict[str, str]:
    environment = _clean_environment("MINEGUARD_")
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(
            None,
            (
                str(platform_source),
                environment.get("PYTHONPATH", ""),
            ),
        )
    )
    environment["MINEGUARD_EDGE_CLIENTS_JSON"] = json.dumps(
        [
            {
                "client_id": CLIENT_ID,
                "mine_ids": [MINE_ID],
                "secrets": [secret_base64],
            }
        ],
        separators=(",", ":"),
    )
    return environment


def _edge_environment(
    *,
    secret_base64: str,
    edge_source: Path,
    database: Path,
    platform_port: int,
) -> dict[str, str]:
    environment = _clean_environment("MINE_EDGE_")
    environment["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(edge_source), environment.get("PYTHONPATH", "")))
    )
    environment.update(
        {
            "MINE_EDGE_MINE_ID": MINE_ID,
            "MINE_EDGE_CLIENT_ID": CLIENT_ID,
            "MINE_EDGE_DB": str(database),
            "MINE_EDGE_LOCAL_TIMEZONE": "+08:00",
            "MINE_EDGE_UPSTREAM_URL": f"http://127.0.0.1:{platform_port}",
            "MINE_EDGE_UPSTREAM_HMAC_SECRET_BASE64": secret_base64,
            "MINE_EDGE_FORWARD_BASE_DELAY_SECONDS": "1",
            "MINE_EDGE_FORWARD_MAX_DELAY_SECONDS": "4",
            "MINE_EDGE_REQUEST_TIMEOUT_SECONDS": "2",
            "MINE_EDGE_THRESHOLDS_CALIBRATED": "true",
            # Deliberately make the local personnel result RED at 100 people.
            # The platform profile below has capacity 100 and independently
            # produces ORANGE. This proves local_alerts are not trusted.
            "MINE_EDGE_THRESHOLDS_JSON": json.dumps(
                {
                    "personnel_capacity": {"underground-total": 50},
                    "personnel_ratio": {
                        "blue": 0.8,
                        "yellow": 0.9,
                        "orange": 1.0,
                        "red": 1.1,
                    },
                    "methane_percent": {
                        "blue": 0.5,
                        "yellow": 0.8,
                        "orange": 1.0,
                        "red": 1.5,
                    },
                    "airflow_minimum": {},
                    "airflow_ratio": {
                        "blue": 0.95,
                        "yellow": 0.9,
                        "orange": 0.8,
                        "red": 0.7,
                    },
                },
                separators=(",", ":"),
            ),
            "MINE_EDGE_RULE_PROFILE_ID": "blackbox-local-profile",
            "MINE_EDGE_RULE_PROFILE_VERSION": "1",
        }
    )
    return environment


def _sample_observations() -> list[dict[str, Any]]:
    observed_at = (
        datetime.now(UTC) - timedelta(seconds=2)
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    quality = {
        "valid": True,
        "completeness": 1.0,
        "timeliness": 1.0,
        "device_health": "healthy",
        "clock_synchronized": True,
        "flags": [],
    }
    return [
        {
            "event_id": "blackbox-personnel-1001",
            "kind": "personnel",
            "metric": "personnel.underground_count",
            "value": 100,
            "unit": "person",
            "location_code": "underground-total",
            "observed_at": observed_at,
            "sequence_no": 1001,
            "revision": 0,
            "source_record_id": "personnel-positioning:1001",
            "status_code": "online",
            "quality": quality,
        },
        {
            "event_id": "blackbox-methane-1002",
            "kind": "methane",
            "metric": "methane.concentration_percent",
            "value": 0.2,
            "unit": "%",
            "location_code": "working-face-return-t2",
            "observed_at": observed_at,
            "sequence_no": 1002,
            "revision": 0,
            "source_record_id": "safety-monitor:1002",
            "status_code": "online",
            "quality": quality,
        },
        {
            "event_id": "blackbox-airflow-1003",
            "kind": "ventilation",
            "metric": "ventilation.airflow_m3_min",
            "value": 9000,
            "unit": "m3/min",
            "location_code": "main-return",
            "observed_at": observed_at,
            "sequence_no": 1003,
            "revision": 0,
            "source_record_id": "main-fan-plc:1003",
            "status_code": "online",
            "quality": quality,
        },
    ]


def _verify(args: argparse.Namespace, temporary: Path) -> dict[str, Any]:
    for required in (
        PLATFORM_DIR / "src" / "mineguard",
        EDGE_DIR / "src" / "mine_edge",
    ):
        if not required.is_dir():
            raise VerificationError(f"required source directory missing: {required}")

    platform_port = _free_port()
    edge_port = _free_port()
    while edge_port == platform_port:
        edge_port = _free_port()
    platform_url = f"http://127.0.0.1:{platform_port}"
    edge_url = f"http://127.0.0.1:{edge_port}"
    shared_secret = secrets.token_bytes(32)
    secret_base64 = base64.b64encode(shared_secret).decode("ascii")
    processes: list[ManagedProcess] = []
    checks: list[str] = []

    def progress(message: str) -> None:
        if args.verbose:
            print(f"[edge-pipeline] {message}", flush=True)

    try:
        progress("starting edge-agent while regulator endpoint is offline")
        edge = _start(
            "edge-agent",
            [
                sys.executable,
                "-u",
                "-m",
                "mine_edge",
                "--db",
                str(temporary / "edge.sqlite3"),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(edge_port),
            ],
            cwd=EDGE_DIR,
            environment=_edge_environment(
                secret_base64=secret_base64,
                edge_source=EDGE_DIR / "src",
                database=temporary / "edge.sqlite3",
                platform_port=platform_port,
            ),
            log_path=temporary / "edge.log",
        )
        processes.append(edge)
        edge_health = _wait_http(
            "edge-agent",
            f"{edge_url}/api/v1/health",
            edge,
            timeout=args.timeout,
        )
        if edge_health.get("production_control_api") is not False:
            raise VerificationError("edge health did not assert no control API")
        checks.append("edge_started_read_only")

        progress("ingesting personnel, methane and ventilation observations")
        ingest = _expect(
            "POST",
            f"{edge_url}/api/v1/ingest",
            expected={202},
            document={
                "source_id": "blackbox-gateway",
                "observations": _sample_observations(),
            },
        )
        if ingest.get("inserted") != 3 or ingest.get("accepted") != 3:
            raise VerificationError(f"unexpected edge ingest result: {ingest}")
        checks.append("three_safety_observations_ingested")

        local_alerts = _expect(
            "GET",
            f"{edge_url}/api/v1/alerts?limit=20",
            expected={200},
        ).get("items", [])
        local_personnel = [
            item
            for item in local_alerts
            if item.get("rule_id") == "personnel-overcapacity-v1"
        ]
        if not local_personnel or local_personnel[0].get("level") != "red":
            raise VerificationError(
                "test setup failed to produce the deliberate local RED alert"
            )
        checks.append("local_red_alert_created")

        progress("forcing an offline delivery failure")
        offline_flush = _expect(
            "POST",
            f"{edge_url}/api/v1/outbox/flush",
            expected={200},
            document={"max_batches": 20},
        )
        first_result = (offline_flush.get("results") or [{}])[0]
        if first_result.get("status") != "retry_scheduled":
            raise VerificationError(
                f"offline send did not schedule retry: {offline_flush}"
            )
        pending = _expect(
            "GET",
            f"{edge_url}/api/v1/outbox?status=pending&limit=100",
            expected={200},
        ).get("items", [])
        if len(pending) != 4 or not all(item.get("attempts", 0) >= 1 for item in pending):
            raise VerificationError(
                f"expected three observations plus one local alert in retry queue: {pending}"
            )
        offline_batch_ids = {item.get("batch_id") for item in pending}
        if None in offline_batch_ids or len(offline_batch_ids) != 1:
            raise VerificationError(
                f"retry records did not retain one stable batch id: {pending}"
            )
        offline_batch_id = str(next(iter(offline_batch_ids)))
        checks.append("offline_outbox_persisted_with_stable_batch")

        progress("starting platform on the previously unavailable endpoint")
        platform = _start(
            "platform",
            [
                sys.executable,
                "-u",
                "-m",
                "mineguard",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(platform_port),
                "--state-directory",
                str(temporary / "platform-state"),
                "--no-auth",
            ],
            cwd=PLATFORM_DIR,
            environment=_platform_environment(
                secret_base64=secret_base64,
                platform_source=PLATFORM_DIR / "src",
            ),
            log_path=temporary / "platform.log",
        )
        processes.append(platform)
        _wait_http(
            "platform",
            f"{platform_url}/health",
            platform,
            timeout=args.timeout,
        )
        checks.append("platform_started_with_independent_hmac_registry")

        progress("configuring regulator-owned mine safety profile")
        profile = _expect(
            "POST",
            f"{platform_url}/v1/admin/mines",
            expected={200},
            document={
                "mine_id": MINE_ID,
                "mine_name": "黑盒验收一矿",
                "gas_category": "high_gas",
                "approved_underground_personnel": 100,
                "approved_capacity_tpy": 1_000_000,
                "enabled": True,
            },
        )
        if profile.get("approved_underground_personnel") != 100:
            raise VerificationError(f"mine profile was not persisted: {profile}")
        checks.append("platform_mine_profile_configured")

        progress("waiting for automatic retry or forcing a due retry")

        def delivered_outbox() -> list[dict[str, Any]] | None:
            # A manual flush is safe and makes the check fast once backoff is due.
            _expect(
                "POST",
                f"{edge_url}/api/v1/outbox/flush",
                expected={200},
                document={"max_batches": 20},
            )
            health = _expect(
                "GET",
                f"{edge_url}/api/v1/health",
                expected={200},
            )
            if health.get("stats", {}).get("outbox_pending") != 0:
                return None
            return _expect(
                "GET",
                f"{edge_url}/api/v1/outbox?status=delivered&limit=100",
                expected={200},
            ).get("items", [])

        delivered = _wait_until(
            "edge outbox recovery",
            delivered_outbox,
            processes,
            timeout=args.timeout,
        )
        if len(delivered) != 4:
            raise VerificationError(f"unexpected delivered outbox: {delivered}")
        delivered_batch_ids = {item.get("batch_id") for item in delivered}
        if delivered_batch_ids != {offline_batch_id}:
            raise VerificationError(
                "retry changed batch id: "
                f"offline={offline_batch_id}, delivered={delivered_batch_ids}"
            )
        checks.append("offline_outbox_recovered_without_batch_change")

        progress("reading immutable platform receipt")
        receipt = _expect(
            "GET",
            (
                f"{platform_url}/v1/edge-telemetry-batches/"
                f"{offline_batch_id}/receipt"
            ),
            expected={200},
        )
        if (
            receipt.get("status") not in {"accepted", "duplicate"}
            or receipt.get("batch_id") != offline_batch_id
            or receipt.get("client_id") != CLIENT_ID
            or receipt.get("mine_id") != MINE_ID
            or receipt.get("accepted_observations") != 3
            or receipt.get("rejected_observations") != 0
            or receipt.get("regulatory_outcome")
            != "not_determined_at_intake"
        ):
            raise VerificationError(f"invalid platform receipt: {receipt}")
        checks.append("platform_receipt_verified")

        progress("verifying regulator recalculation ignores local alert level")

        def platform_dashboard() -> dict[str, Any] | None:
            dashboard = _expect(
                "GET",
                f"{platform_url}/v1/dashboard/safety",
                expected={200},
            )
            personnel = [
                item
                for item in dashboard.get("alerts", [])
                if item.get("category") == "personnel"
            ]
            return {"dashboard": dashboard, "personnel": personnel} if personnel else None

        evaluated = _wait_until(
            "platform safety recalculation",
            platform_dashboard,
            processes,
            timeout=args.timeout,
        )
        dashboard = evaluated["dashboard"]
        personnel_alert = evaluated["personnel"][0]
        if personnel_alert.get("source") != "platform_recalculation":
            raise VerificationError(
                f"alert did not originate in regulator calculation: {personnel_alert}"
            )
        if personnel_alert.get("level") != "orange":
            raise VerificationError(
                "expected platform ORANGE from approved capacity 100 while "
                f"edge supplied local RED: {personnel_alert}"
            )
        if any(
            item.get("source") != "platform_recalculation"
            for item in dashboard.get("alerts", [])
        ):
            raise VerificationError("platform dashboard exposed a trusted local alert")
        if (
            personnel_alert.get("details", {}).get("production_control_permitted")
            is not False
        ):
            raise VerificationError("platform alert did not preserve advisory-only boundary")
        checks.append("platform_recalculated_orange_instead_of_local_red")

        return {
            "status": "passed",
            "checks": checks,
            "temporary_directory": str(temporary),
            "temporary_directory_retained": bool(args.keep_temp),
            "edge": {
                "url": edge_url,
                "ingested": ingest["inserted"],
                "local_personnel_level": local_personnel[0]["level"],
                "outbox_events_recovered": len(delivered),
                "stable_batch_id": offline_batch_id,
            },
            "platform": {
                "url": platform_url,
                "receipt_id": receipt.get("receipt_id"),
                "accepted_observations": receipt.get("accepted_observations"),
                "regulatory_outcome": receipt.get("regulatory_outcome"),
                "personnel_level": personnel_alert.get("level"),
                "alert_source": personnel_alert.get("source"),
            },
        }
    except Exception as error:
        diagnostics = [str(error)]
        for process in processes:
            diagnostics.append(process.tail())
        try:
            if processes:
                status, body = _request(
                    "GET",
                    f"{edge_url}/api/v1/outbox?limit=100",
                    timeout=1,
                )
                diagnostics.append(
                    "edge outbox diagnostic "
                    f"HTTP {status}: {json.dumps(body, ensure_ascii=False)[:5000]}"
                )
        except Exception as diagnostic_error:
            diagnostics.append(f"could not read edge outbox: {diagnostic_error}")
        raise VerificationError("\n".join(diagnostics)) from error
    finally:
        for process in reversed(processes):
            process.stop()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.timeout <= 0:
        print("--timeout 必须大于零", file=sys.stderr)
        return 2
    temporary_owner: tempfile.TemporaryDirectory[str] | None = None
    if args.keep_temp:
        temporary = Path(tempfile.mkdtemp(prefix="edge-pipeline-"))
    else:
        temporary_owner = tempfile.TemporaryDirectory(prefix="edge-pipeline-")
        temporary = Path(temporary_owner.name)
    try:
        result = _verify(args, temporary)
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        if args.keep_temp:
            print(f"临时目录已保留：{temporary}", file=sys.stderr)
        return 0
    except (VerificationError, OSError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "temporary_directory": str(temporary),
                    "error": str(error),
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        if args.keep_temp:
            print(f"临时目录已保留：{temporary}", file=sys.stderr)
        return 1
    finally:
        if temporary_owner is not None:
            temporary_owner.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
