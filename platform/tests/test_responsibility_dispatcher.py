from datetime import UTC, datetime, timedelta

from mineguard.api import create_server
from mineguard.edge_store import EdgeTelemetryRepository
from mineguard.responsibility import SafetyResponsibilityDispatcher


def test_dispatcher_routes_existing_alert_and_escalates_after_restart() -> None:
    repository = EdgeTelemetryRepository()
    try:
        alert = repository.upsert_platform_alert(
            mine_id="M001",
            category="methane",
            rule_code="dispatcher-test",
            level="red",
            title="责任调度测试",
            summary="仅用于后台责任调度测试。",
            location_code="t1",
            detected_at=datetime.now(UTC) - timedelta(minutes=10),
            observation_ids=["dispatcher-observation"],
            details={"advisory_only": True},
            rule_profile={
                "version": "approved-test-v1",
                "fingerprint": "a" * 64,
            },
        )
        repository.upsert_responsibility_route(
            route_id="dispatcher-route",
            mine_id="M001",
            category="methane",
            minimum_level="orange",
            primary_user_id="primary-id",
            primary_username="primary",
            backup_user_id="backup-id",
            backup_username="backup",
            escalation_minutes=1,
            enabled=True,
            actor_id="admin",
        )
        dispatcher = SafetyResponsibilityDispatcher(
            repository,
            poll_seconds=0.01,
        )
        first = dispatcher.run_once()
        recipients = repository.list_alert_recipients(alert["alert_id"])
        assert first["routed"] == 1
        assert recipients[0]["recipient_role"] == "primary"

        assigned_at = datetime.fromisoformat(
            recipients[0]["assigned_at"].replace("Z", "+00:00")
        )
        changed = repository.escalate_responsibilities(
            now=assigned_at + timedelta(minutes=2)
        )
        assert changed == 1

        restarted = SafetyResponsibilityDispatcher(
            repository,
            poll_seconds=0.01,
        )
        assert restarted.run_once()["escalated"] == 0
    finally:
        repository.close()


def test_http_server_starts_and_stops_responsibility_worker(tmp_path) -> None:
    server = create_server(
        "127.0.0.1",
        0,
        database_path=tmp_path / "main.db",
        auth_required=False,
        auth_database_path=tmp_path / "auth.db",
        job_database_path=tmp_path / "jobs.db",
        responsibility_poll_seconds=0.01,
    )
    dispatcher = server.responsibility_dispatcher
    try:
        assert dispatcher.is_running()
        readiness = server.readiness.readiness()
        checks = {item["name"]: item for item in readiness["checks"]}
        assert (
            checks["safety_responsibility_worker"]["status"]
            == "ready"
        )
    finally:
        server.server_close()
    assert not dispatcher.is_running()
