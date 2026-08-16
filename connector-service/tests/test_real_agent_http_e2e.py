from __future__ import annotations

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
from conftest import write_config

import enterprise_connector.service as connector_service_module
from enterprise_connector.config import load_config
from enterprise_connector.errors import DeliveryError
from enterprise_connector.service import ConnectorService


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_port(process: subprocess.Popen[bytes], port: int) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=2)
            raise AssertionError(
                f"Agent exited {process.returncode}: {stdout.decode()} {stderr.decode()}"
            )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("Agent did not start")


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Stop the real Agent and any Windows venv-launcher child process."""

    if process.poll() is not None:
        process.communicate(timeout=2)
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    else:
        process.terminate()
    try:
        process.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def test_connector_writes_and_revises_one_real_v3_monthly_draft(
    tmp_path: Path,
    source_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    agent_src = repository / "agent" / "src"
    port = _free_port()
    agent_db = tmp_path / "agent.sqlite3"
    secret = "connector-e2e-secret-at-least-thirty-two-bytes"
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(agent_src),
            "ENTERPRISE_AGENT_CONNECTOR_CLIENTS_JSON": json.dumps(
                [
                    {
                        "client_id": "test-connector",
                        "secret": secret,
                        "permissions": ["autofill"],
                        "allowed_sources": {
                            "ledger": {
                                "source_system": "mes-ledger",
                                "required": True,
                                "freshness_max_seconds": 3600,
                            }
                        },
                    }
                ]
            ),
            "ENTERPRISE_OPERATOR_ID": "operator-qy-001",
            "ENTERPRISE_MINE_ID": "mine-qy-001",
            "ENTERPRISE_MINE_NAME": "端到端测试煤矿",
            "ENTERPRISE_OPERATOR_NAME": "端到端测试煤业",
            "ENTERPRISE_SYSTEM_ID": "agent-mine-qy-001",
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "enterprise_agent",
            "--db",
            str(agent_db),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--web-root",
            str(repository / "agent" / "web"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    try:
        _wait_for_port(process, port)
        monkeypatch.setenv("TEST_CONNECTOR_SECRET", secret)
        config = load_config(write_config(tmp_path / "connector.toml", source_db, agent_port=port))
        service = ConnectorService(config)
        try:
            service.acquire()
            first = service.run_cycle()
            assert first.delivered == 1 and first.errors == 0
            assert first.health_delivered == 2
            repeated = service.run_cycle()
            assert repeated.delivered == 0 and repeated.duplicate == 1
            assert repeated.health_delivered == 0
        finally:
            service.close()

        connection = sqlite3.connect(agent_db)
        connection.row_factory = sqlite3.Row
        drafts = connection.execute("SELECT * FROM fq_drafts").fetchall()
        assert len(drafts) == 1
        draft_id = drafts[0]["draft_id"]
        payload = json.loads(drafts[0]["payload_json"])
        assert drafts[0]["contract_version"] == "ten-quantity-submission-v3"
        assert payload["reporting_month"] == "2026-07"
        day_29 = next(item for item in payload["days"] if item["date"] == "2026-07-29")
        assert day_29["reported_quantity"]["daily_total"]["production_t"]["value"] == 350.0
        assert day_29["reported_quantity"]["daily_total"]["extraction_t"]["value"] == 355.0
        assert (
            day_29["reported_quantity"]["daily_total"]["invoiced_quantity_t"]["value"]
            == 285.0
        )
        assert connection.execute("SELECT COUNT(*) FROM connector_ingestions").fetchone()[0] == 1
        connection.close()

        upstream = sqlite3.connect(source_db)
        upstream.execute("UPDATE five_quantity SET production = 355 WHERE scope = 'daily_total'")
        upstream.commit()
        upstream.close()

        restarted = ConnectorService(config)
        try:
            restarted.acquire()
            revision = restarted.run_cycle()
            assert revision.delivered == 1 and revision.errors == 0
            assert revision.health_delivered == 1
        finally:
            restarted.close()

        connection = sqlite3.connect(agent_db)
        connection.row_factory = sqlite3.Row
        drafts = connection.execute("SELECT * FROM fq_drafts").fetchall()
        assert len(drafts) == 1 and drafts[0]["draft_id"] == draft_id
        assert drafts[0]["revision"] == 2
        revised = json.loads(drafts[0]["payload_json"])
        revised_day_29 = next(item for item in revised["days"] if item["date"] == "2026-07-29")
        assert revised_day_29["reported_quantity"]["daily_total"]["production_t"]["value"] == 355.0
        assert (
            connection.execute(
                "SELECT source_revision FROM fq_machine_source_contributions"
            ).fetchone()[0]
            == 2
        )
        contribution = connection.execute(
            """
            SELECT event_id,source_revision,content_sha256
            FROM fq_machine_source_contributions WHERE source_id='ledger'
            """
        ).fetchone()
        health = connection.execute(
            """
            SELECT autofill_event_id,source_revision,snapshot_sha256,outcome
            FROM connector_source_health
            WHERE source_id='ledger' AND reporting_month='2026-07'
            """
        ).fetchone()
        assert tuple(health[:3]) == tuple(contribution[:3])
        assert health["outcome"] == "success_nonempty"
        connection.close()
        local = sqlite3.connect(config.state_db)
        local.row_factory = sqlite3.Row
        local_observation = local.execute(
            """
            SELECT event_id,source_revision,delivered_content_sha256
            FROM observations WHERE source_id='ledger' ORDER BY sequence DESC LIMIT 1
            """
        ).fetchone()
        assert tuple(local_observation) == tuple(contribution)
        local.close()
    finally:
        _terminate_process_tree(process)


def test_error_before_autofill_then_same_content_health_recovery_is_fresh(
    tmp_path: Path,
    source_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    agent_src = repository / "agent" / "src"
    port = _free_port()
    agent_db = tmp_path / "agent-recovery.sqlite3"
    secret = "connector-e2e-secret-at-least-thirty-two-bytes"
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONPATH": str(agent_src),
            "ENTERPRISE_AGENT_CONNECTOR_CLIENTS_JSON": json.dumps(
                [
                    {
                        "client_id": "test-connector",
                        "secret": secret,
                        "permissions": ["autofill"],
                        "allowed_sources": {
                            "ledger": {
                                "source_system": "mes-ledger",
                                "required": True,
                                "freshness_max_seconds": 3600,
                            }
                        },
                    }
                ]
            ),
            "ENTERPRISE_OPERATOR_ID": "operator-qy-001",
            "ENTERPRISE_MINE_ID": "mine-qy-001",
            "ENTERPRISE_MINE_NAME": "恢复链路测试煤矿",
            "ENTERPRISE_OPERATOR_NAME": "恢复链路测试煤业",
            "ENTERPRISE_SYSTEM_ID": "agent-mine-qy-001",
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "enterprise_agent",
            "--db",
            str(agent_db),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--web-root",
            str(repository / "agent" / "web"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    service: ConnectorService | None = None
    try:
        _wait_for_port(process, port)
        monkeypatch.setenv("TEST_CONNECTOR_SECRET", secret)
        config = load_config(
            write_config(tmp_path / "connector-recovery.toml", source_db, agent_port=port)
        )
        july_draft = "draft:operator-qy-001:five-quantity:monthly:2026-07"
        monkeypatch.setattr(
            connector_service_module,
            "_current_reporting_target",
            lambda _pipeline, _timestamp: (july_draft, "2026-07", "2026-07-31"),
        )
        service = ConnectorService(config)
        service.acquire()
        real_send_health = service.client.send_health

        def retry_snapshot_health(event_id: str, body: bytes) -> int:
            if json.loads(body)["outcome"] == "success_nonempty":
                raise DeliveryError("temporary health outage", retryable=True, status=503)
            return real_send_health(event_id, body)

        monkeypatch.setattr(service.client, "send_health", retry_snapshot_health)
        waiting = service.run_cycle()
        assert waiting.discovered == 1 and waiting.delivered == 0
        assert waiting.health_retried == 1
        service.store.connection.execute(
            """
            UPDATE health_deliveries SET next_attempt_at=?
            WHERE outcome='success_nonempty' AND status='pending'
            """,
            (time.time() + 3600,),
        )

        upstream = sqlite3.connect(source_db)
        upstream.execute("ALTER TABLE five_quantity RENAME TO five_quantity_unavailable")
        upstream.commit()
        upstream.close()
        monkeypatch.setattr(service.client, "send_health", real_send_health)
        degraded = service.run_cycle()
        assert degraded.source_errors == 1
        assert degraded.health_delivered == 1
        assert degraded.delivered == 1

        upstream = sqlite3.connect(source_db)
        upstream.execute("ALTER TABLE five_quantity_unavailable RENAME TO five_quantity")
        upstream.commit()
        upstream.close()
        recovered = service.run_cycle()
        assert recovered.duplicate == 1 and recovered.delivered == 0
        assert recovered.health_delivered == 1 and recovered.errors == 0
        service.close()
        service = None

        connection = sqlite3.connect(agent_db)
        connection.row_factory = sqlite3.Row
        draft = connection.execute("SELECT * FROM fq_drafts").fetchone()
        assert draft is not None
        ingestion = connection.execute(
            "SELECT * FROM connector_ingestions ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        assert ingestion is not None and ingestion["trigger_workflow"] == 0
        preflight = json.loads(ingestion["workflow_result_json"])
        assert preflight["bound_revision"] == draft["revision"] == ingestion["draft_revision"]
        assert preflight["payload_sha256"] == hashlib.sha256(
            draft["payload_json"].encode("utf-8")
        ).hexdigest()
        contribution = connection.execute(
            """
            SELECT event_id,source_revision,content_sha256
            FROM fq_machine_source_contributions WHERE source_id='ledger'
            """
        ).fetchone()
        health = connection.execute(
            """
            SELECT autofill_event_id,source_revision,snapshot_sha256,outcome
            FROM connector_source_health
            WHERE source_id='ledger' AND reporting_month='2026-07'
            """
        ).fetchone()
        assert contribution is not None and health is not None
        assert tuple(health[:3]) == tuple(contribution)
        assert health["outcome"] == "success_nonempty"
        draft_id = str(draft["draft_id"])
        connection.close()

        health_script = r"""
import json, sys
from enterprise_agent.storage import Repository
repository = Repository(sys.argv[1])
result = repository.connector_source_health_for_draft(
    sys.argv[2],
    policies=({
        "source_id": "ledger",
        "source_system": "mes-ledger",
        "required": True,
        "freshness_max_seconds": 3600,
    },),
)
print(json.dumps(result))
"""
        evaluated = subprocess.run(
            [sys.executable, "-c", health_script, str(agent_db), draft_id],
            capture_output=True,
            env=environment,
            timeout=20,
            check=False,
        )
        assert evaluated.returncode == 0, evaluated.stderr.decode()
        source_health = json.loads(evaluated.stdout)
        assert source_health["freshness"]["overall_state"] == "fresh"
        assert source_health["source_health"][0]["freshness_state"] == "fresh"
    finally:
        if service is not None:
            service.close()
        _terminate_process_tree(process)
