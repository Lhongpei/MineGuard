from datetime import UTC, datetime, timedelta
import sqlite3

from mineguard.edge_store import EdgeTelemetryRepository


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


def _route(repository: EdgeTelemetryRepository) -> None:
    repository.upsert_responsibility_route(
        route_id="m001-personnel-yellow",
        mine_id="M001",
        category="personnel",
        minimum_level="yellow",
        primary_user_id="user-primary",
        primary_username="primary",
        backup_user_id="user-backup",
        backup_username="backup",
        escalation_minutes=5,
        enabled=True,
        actor_id="admin",
    )


def _alert(
    repository: EdgeTelemetryRepository,
    *,
    rule_code: str,
    level: str = "yellow",
    operational: bool = True,
) -> dict:
    return repository.upsert_platform_alert(
        mine_id="M001",
        category="personnel",
        rule_code=rule_code,
        level=level,
        title="人员预警测试",
        summary="仅用于责任路由自动测试。",
        location_code="underground-total",
        detected_at=NOW,
        observation_ids=[f"observation-{rule_code}"],
        details={"advisory_only": True},
        rule_profile={
            "version": "approved-test-v1",
            "fingerprint": "a" * 64,
            "approval_status": "approved",
        },
        operational=operational,
    )


def test_operational_alert_is_routed_and_escalated_when_unread() -> None:
    repository = EdgeTelemetryRepository()
    try:
        _route(repository)
        alert = _alert(repository, rule_code="unread")
        recipients = repository.list_alert_recipients(alert["alert_id"])
        listed = repository.list_alerts(mine_ids={"M001"})

        assert alert["assignee"] == "primary"
        assert [item["recipient_role"] for item in recipients] == ["primary"]
        assert listed[0]["recipients"][0]["username"] == "primary"
        assert repository.responsibility_health() == {
            "unrouted": 0,
            "unread_primary": 1,
            "unread_observer": 0,
            "escalated": 0,
            "sla_overdue_escalated": 0,
        }

        assigned_at = datetime.fromisoformat(
            recipients[0]["assigned_at"].replace("Z", "+00:00")
        )
        changed = repository.escalate_responsibilities(
            now=assigned_at + timedelta(minutes=6)
        )
        detail = repository.get_alert(alert["alert_id"])
        notifications = repository.list_notifications()
    finally:
        repository.close()

    assert changed == 1
    assert detail is not None
    assert detail["audit_chain_valid"] is True
    assert [item["recipient_role"] for item in detail["recipients"]] == [
        "primary",
        "backup",
    ]
    assert any(
        event["event_type"] == "responsibility_escalated"
        for event in detail["events"]
    )
    assert any(
        item["event_type"] == "responsibility_escalated"
        for item in notifications
    )


def test_read_receipt_prevents_escalation_and_is_idempotent() -> None:
    repository = EdgeTelemetryRepository()
    try:
        _route(repository)
        alert = _alert(repository, rule_code="read")
        recipient = repository.list_alert_recipients(alert["alert_id"])[0]
        assigned_at = datetime.fromisoformat(
            recipient["assigned_at"].replace("Z", "+00:00")
        )
        first = repository.mark_alert_read(
            alert["alert_id"],
            user_id="user-primary",
            username="primary",
        )
        duplicate = repository.mark_alert_read(
            alert["alert_id"],
            user_id="user-primary",
            username="primary",
        )
        changed = repository.escalate_responsibilities(
            now=assigned_at + timedelta(minutes=60)
        )
        detail = repository.get_alert(alert["alert_id"])
    finally:
        repository.close()

    assert first["version"] == alert["version"] + 1
    assert duplicate["version"] == first["version"]
    assert changed == 0
    assert detail is not None
    assert len(
        [
            event
            for event in detail["events"]
            if event["event_type"] == "read_receipt"
        ]
    ) == 1
    assert detail["recipients"][0]["read_at"] is not None


def test_all_matching_routes_receive_independent_route_records() -> None:
    repository = EdgeTelemetryRepository()
    try:
        routes = (
            (
                "county-wide",
                None,
                None,
                "shared-user",
                "county-backup",
            ),
            (
                "mine-wide",
                "M001",
                None,
                "mine-user",
                "mine-backup",
            ),
            (
                "mine-personnel",
                "M001",
                "personnel",
                "shared-user",
                "personnel-backup",
            ),
        )
        for route_id, mine_id, category, primary, backup in routes:
            repository.upsert_responsibility_route(
                route_id=route_id,
                mine_id=mine_id,
                category=category,
                minimum_level="yellow",
                primary_user_id=primary,
                primary_username=primary,
                backup_user_id=backup,
                backup_username=backup,
                escalation_minutes=5,
                enabled=True,
                actor_id="admin",
            )
        alert = _alert(repository, rule_code="parallel")
        recipients = repository.list_alert_recipients(alert["alert_id"])

        assert alert["assignee"] == "shared-user"
        assert sorted(
            (
                item["route_id"],
                item["recipient_role"],
                item["username"],
            )
            for item in recipients
        ) == [
            ("county-wide", "observer", "shared-user"),
            ("mine-personnel", "primary", "shared-user"),
            ("mine-wide", "observer", "mine-user"),
        ]
        assert len({item["recipient_id"] for item in recipients}) == 3
        assert repository.responsibility_health()["unread_observer"] == 2

        repository.mark_alert_read(
            alert["alert_id"],
            user_id="mine-user",
            username="mine-user",
        )
        assigned_at = max(
            datetime.fromisoformat(
                item["assigned_at"].replace("Z", "+00:00")
            )
            for item in recipients
        )
        escalated = repository.escalate_responsibilities(
            now=assigned_at + timedelta(minutes=6)
        )
        detail = repository.get_alert(alert["alert_id"])
    finally:
        repository.close()

    assert escalated == 2
    assert detail is not None
    backups = {
        item["route_id"]: item["username"]
        for item in detail["recipients"]
        if item["recipient_role"] == "backup"
    }
    assert backups == {
        "county-wide": "county-backup",
        "mine-personnel": "personnel-backup",
    }
    route_events = [
        item
        for item in detail["events"]
        if item["event_type"] == "responsibility_escalated"
    ]
    assert {item["payload"]["route_id"] for item in route_events} == {
        "county-wide",
        "mine-personnel",
    }


def test_new_route_reconciles_open_alert_once_and_keeps_one_primary() -> None:
    repository = EdgeTelemetryRepository()
    try:
        repository.upsert_responsibility_route(
            route_id="county",
            mine_id=None,
            category=None,
            minimum_level="yellow",
            primary_user_id="county-user",
            primary_username="county-user",
            backup_user_id=None,
            backup_username=None,
            escalation_minutes=30,
            enabled=True,
            actor_id="admin",
        )
        alert = _alert(repository, rule_code="late-route")
        repository.upsert_responsibility_route(
            route_id="mine-personnel",
            mine_id="M001",
            category="personnel",
            minimum_level="yellow",
            primary_user_id="mine-user",
            primary_username="mine-user",
            backup_user_id=None,
            backup_username=None,
            escalation_minutes=30,
            enabled=True,
            actor_id="admin",
        )
        first = repository.route_unassigned_alerts()
        duplicate = repository.route_unassigned_alerts()
        detail = repository.get_alert(alert["alert_id"])
        notifications = repository.list_notifications()
    finally:
        repository.close()

    assert first == 1
    assert duplicate == 0
    assert detail is not None
    assert detail["assignee"] == "mine-user"
    assert [
        (item["route_id"], item["recipient_role"])
        for item in detail["recipients"]
    ] == [
        ("county", "observer"),
        ("mine-personnel", "primary"),
    ]
    assert len(
        [
            item
            for item in detail["events"]
            if item["event_type"] == "auto_assigned"
        ]
    ) == 2
    assert len(
        [
            item
            for item in notifications
            if item["event_type"] == "auto_assigned"
        ]
    ) == 1


def test_deleted_route_null_projection_is_not_counted_as_current() -> None:
    repository = EdgeTelemetryRepository()
    try:
        _route(repository)
        alert = _alert(repository, rule_code="route-deleted")
        with repository._transaction() as connection:  # noqa: SLF001
            connection.execute(
                """
                DELETE FROM safety_responsibility_routes
                WHERE route_id = 'm001-personnel-yellow'
                """
            )
        stale = repository.list_alert_recipients(alert["alert_id"])
        health_before_reconcile = repository.responsibility_health()
        reconciled = repository.route_unassigned_alerts()
        detail = repository.get_alert(alert["alert_id"])
        health_after_reconcile = repository.responsibility_health()
    finally:
        repository.close()

    assert stale[0]["route_id"] is None
    assert health_before_reconcile["unrouted"] == 1
    assert health_before_reconcile["unread_primary"] == 0
    assert reconciled == 1
    assert detail is not None
    assert detail["assignee"] is None
    assert detail["recipients"] == []
    assert health_after_reconcile["unrouted"] == 1


def test_legacy_recipient_migration_preserves_fk_and_audit(
    tmp_path,
) -> None:
    database_path = tmp_path / "legacy-recipients.db"
    repository = EdgeTelemetryRepository(database_path)
    try:
        _route(repository)
        alert = _alert(repository, rule_code="legacy-migration")
        alert_id = alert["alert_id"]
    finally:
        repository.close()

    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.executescript(
            """
            DROP INDEX idx_safety_recipients_unread;
            CREATE TABLE legacy_recipients (
                alert_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                recipient_role TEXT NOT NULL,
                route_id TEXT,
                assigned_at TEXT NOT NULL,
                read_at TEXT,
                escalated_at TEXT,
                PRIMARY KEY (alert_id, user_id, recipient_role)
            );
            INSERT INTO legacy_recipients
            SELECT alert_id, user_id, username, recipient_role,
                   route_id, assigned_at, read_at, escalated_at
            FROM safety_alert_recipients;
            DROP TABLE safety_alert_recipients;
            ALTER TABLE legacy_recipients
                RENAME TO safety_alert_recipients;
            CREATE INDEX idx_safety_recipients_unread
                ON safety_alert_recipients(
                    recipient_role, read_at, assigned_at
                );
            """
        )
        connection.execute(
            """
            INSERT INTO safety_alert_recipients(
                alert_id, user_id, username, recipient_role,
                route_id, assigned_at, read_at, escalated_at
            ) VALUES (?, ?, ?, 'primary', ?, ?, NULL, NULL)
            """,
            (
                alert_id,
                "legacy-duplicate",
                "legacy-duplicate",
                "m001-personnel-yellow",
                "2027-01-01T00:00:00Z",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    migrated = EdgeTelemetryRepository(database_path)
    try:
        before_reconcile = migrated.get_alert(alert_id)
        reconciled = migrated.route_unassigned_alerts()
        detail = migrated.get_alert(alert_id)
        foreign_key_errors = migrated._connection.execute(  # noqa: SLF001
            "PRAGMA foreign_key_check"
        ).fetchall()
    finally:
        migrated.close()

    assert detail is not None
    assert before_reconcile is not None
    assert len(before_reconcile["recipients"]) == 1
    assert before_reconcile["recipients"][0]["username"] == (
        "legacy-duplicate"
    )
    assert reconciled == 1
    assert detail["audit_chain_valid"] is True
    assert len(detail["recipients"]) == 1
    assert detail["recipients"][0]["username"] == "primary"
    assert detail["recipients"][0]["recipient_id"].startswith("recipient-")
    assert foreign_key_errors == []


def test_shadow_and_below_threshold_alerts_do_not_enter_route() -> None:
    repository = EdgeTelemetryRepository()
    try:
        _route(repository)
        shadow = _alert(
            repository,
            rule_code="shadow",
            operational=False,
        )
        blue = _alert(
            repository,
            rule_code="blue",
            level="blue",
        )
    finally:
        repository.close()

    assert shadow["assignee"] is None
    assert blue["assignee"] is None


def test_due_at_escalation_is_once_only_and_survives_restart(
    tmp_path,
) -> None:
    database_path = tmp_path / "sla.db"
    repository = EdgeTelemetryRepository(database_path)
    try:
        _route(repository)
        alert = _alert(
            repository,
            rule_code="sla-overdue",
            level="red",
        )
        repository.mark_alert_read(
            alert["alert_id"],
            user_id="user-primary",
            username="primary",
        )
        due_at = datetime.fromisoformat(
            alert["due_at"].replace("Z", "+00:00")
        )

        first = repository.escalate_overdue_alerts(
            now=due_at + timedelta(seconds=1)
        )
        duplicate = repository.escalate_overdue_alerts(
            now=due_at + timedelta(hours=1)
        )
        detail = repository.get_alert(alert["alert_id"])
        notifications = repository.list_notifications()
    finally:
        repository.close()

    restarted = EdgeTelemetryRepository(database_path)
    try:
        after_restart = restarted.escalate_overdue_alerts(
            now=due_at + timedelta(days=1)
        )
        stored = restarted.get_alert(alert["alert_id"])
        assert stored is not None
        resolved = restarted.apply_alert_action(
            alert["alert_id"],
            action="resolve",
            expected_version=stored["version"],
            actor_id="resolver",
            note="第一轮核查完毕。",
        )
        closed = restarted.apply_alert_action(
            alert["alert_id"],
            action="close",
            expected_version=resolved["version"],
            actor_id="closer",
            note="由独立复核人关闭。",
        )
        assert closed["status"] == "closed"
        reopened = _alert(
            restarted,
            rule_code="sla-overdue",
            level="red",
        )
        reopened_due_at = datetime.fromisoformat(
            reopened["due_at"].replace("Z", "+00:00")
        )
        second_cycle = restarted.escalate_overdue_alerts(
            now=reopened_due_at + timedelta(seconds=1)
        )
        reopened_detail = restarted.get_alert(alert["alert_id"])
    finally:
        restarted.close()

    assert first == 1
    assert duplicate == 0
    assert after_restart == 0
    assert second_cycle == 1
    assert detail is not None
    assert detail["audit_chain_valid"] is True
    assert [
        item["event_type"]
        for item in detail["events"]
        if item["event_type"] == "sla_overdue_escalated"
    ] == ["sla_overdue_escalated"]
    assert any(
        item["recipient_role"] == "backup"
        for item in detail["recipients"]
    )
    sla_notification = next(
        item
        for item in notifications
        if item["event_type"] == "sla_overdue_escalated"
    )
    warning = sla_notification["payload"]["technical_warning"]
    assert warning["due_at"] == alert["due_at"]
    assert warning["approval_status"] == "approved"
    assert reopened_detail is not None
    assert len(
        [
            item
            for item in reopened_detail["events"]
            if item["event_type"] == "sla_overdue_escalated"
        ]
    ) == 2
