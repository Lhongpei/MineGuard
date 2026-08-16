from __future__ import annotations

import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from enterprise_agent.errors import ConflictError, ImportContentError, NotFoundError
from enterprise_agent.five_quantity_csv_persistence import (
    CSV_MAPPING_PROFILE_CONTRACT,
)
from enterprise_agent.five_quantity_exchange import MineIdentity
from enterprise_agent.five_quantity_import import inspect_five_quantity_csv
from enterprise_agent.five_quantity_runtime import FiveQuantityRuntime
from enterprise_agent.storage import Repository


def identity(*, mine_id: str = "MINE-CSV-001") -> MineIdentity:
    return MineIdentity(
        mine_id=mine_id,
        mine_name=f"{mine_id} 测试煤矿",
        operator_id=f"OP-{mine_id}",
        operator_name="CSV 持久化测试企业",
        system_id=f"AGENT-{mine_id}",
        regulator_system_id="REGULATOR-CSV",
        regulator_party_id="REGULATOR-PARTY-CSV",
        key_id=f"KEY-{mine_id}",
        regulator_key_id="REGULATOR-KEY-CSV",
        message_hmac_secret="csv-preview-message-secret-1234567890",
    )


def csv_bytes(*, production_header: str = "产量") -> bytes:
    return (
        f"日期,{production_header},电量\n"
        "2026-07-01,=1+1,96000\n"
    ).encode()


def runtime(tmp_path: Path, *, mine_id: str = "MINE-CSV-001") -> FiveQuantityRuntime:
    repository = Repository(tmp_path / "agent.db")
    return FiveQuantityRuntime(
        repository,
        identity=identity(mine_id=mine_id),
        quarantine_directory=tmp_path / f"quarantine-{mine_id}",
        csv_preview_directory=tmp_path / "preview-evidence",
    )


def create_preview(
    subject: FiveQuantityRuntime,
    *,
    content: bytes | None = None,
    filename: str = "七月五量.csv",
    now: datetime | None = None,
) -> dict:
    raw = content or csv_bytes()
    inspection = inspect_five_quantity_csv(filename=filename, content=raw)
    return subject.csv_persistence.create_preview(
        original_filename=filename,
        content=raw,
        inspection=inspection,
        actor="operator-1",
        now=now,
    )


def mapping(*, header: str = "产量", metric: str = "production_t") -> dict:
    units = {
        "production_t": "t",
        "electricity_kwh": "kWh",
    }
    return {
        "schema_version": CSV_MAPPING_PROFILE_CONTRACT,
        "columns": [
            {
                "source_header": header,
                "metric": metric,
                "scope": "daily_total",
                "shift": None,
                "unit": units[metric],
            }
        ],
    }


def test_preview_retains_inert_evidence_and_consumes_only_into_draft(
    tmp_path: Path,
) -> None:
    subject = runtime(tmp_path)
    now = datetime(2026, 8, 6, 1, 0, tzinfo=UTC)
    content = csv_bytes()
    preview = create_preview(subject, content=content, now=now)

    assert preview["status"] == "active"
    assert preview["revision"] == 1
    assert preview["inspection"]["content_sha256"] == preview["content_sha256"]
    assert "payload" not in preview
    assert "evidence_relpath" not in preview
    assert subject.csv_persistence.read_preview_evidence(
        preview["preview_id"], actor="operator-1", now=now
    ) == content

    evidence_files = list(
        subject.csv_persistence.mine_evidence_directory.glob("*.csv")
    )
    assert len(evidence_files) == 1
    assert evidence_files[0].read_bytes() == content
    if os.name != "nt":
        assert evidence_files[0].stat().st_mode & 0o111 == 0
        assert evidence_files[0].stat().st_mode & 0o077 == 0

    consumed = subject.csv_persistence.consume_preview(
        preview["preview_id"],
        expected_revision=preview["revision"],
        expected_inspection_sha256=preview["inspection_sha256"],
        resulting_draft_id="draft-csv-1",
        actor="operator-1",
        now=now + timedelta(seconds=1),
    )
    assert consumed["status"] == "consumed"
    assert consumed["resulting_draft_id"] == "draft-csv-1"
    assert consumed["revision"] == 2

    # Idempotent replay returns the same state and never creates an outbox item.
    replay = subject.csv_persistence.consume_preview(
        preview["preview_id"],
        expected_revision=1,
        expected_inspection_sha256=preview["inspection_sha256"],
        resulting_draft_id="draft-csv-1",
        actor="operator-1",
        now=now + timedelta(seconds=2),
    )
    assert replay["revision"] == 2
    with subject.store.repository._read() as db:
        assert db.execute("SELECT COUNT(*) FROM fq_outbox").fetchone()[0] == 0
        audit_types = [
            row["event_type"]
            for row in db.execute("SELECT event_type FROM fq_audit ORDER BY sequence")
        ]
    assert audit_types == [
        "five_quantity_csv_preview_created",
        "five_quantity_csv_preview_consumed",
    ]
    assert subject.store.audit()["valid"] is True


def test_preview_is_actor_and_mine_scoped_expires_and_rechecks_raw_hash(
    tmp_path: Path,
) -> None:
    first = runtime(tmp_path, mine_id="MINE-CSV-A")
    now = datetime(2026, 8, 6, 2, 0, tzinfo=UTC)
    preview = create_preview(first, now=now)

    with pytest.raises(NotFoundError):
        first.csv_persistence.get_preview(
            preview["preview_id"], actor="operator-2", now=now
        )
    second = FiveQuantityRuntime(
        first.store.repository,
        identity=identity(mine_id="MINE-CSV-B"),
        quarantine_directory=tmp_path / "quarantine-b",
        csv_preview_directory=tmp_path / "preview-evidence",
    )
    with pytest.raises(NotFoundError):
        second.csv_persistence.get_preview(
            preview["preview_id"], actor="operator-1", now=now
        )

    evidence = next(first.csv_persistence.mine_evidence_directory.glob("*.csv"))
    evidence.write_bytes(csv_bytes().replace(b"96000", b"96001"))
    with pytest.raises(ConflictError, match="完整性"):
        first.csv_persistence.read_preview_evidence(
            preview["preview_id"], actor="operator-1", now=now
        )

    with pytest.raises(NotFoundError):
        first.csv_persistence.get_preview(
            preview["preview_id"],
            actor="operator-1",
            now=now + timedelta(minutes=16),
        )
    expired = first.csv_persistence.get_preview(
        preview["preview_id"],
        actor="operator-1",
        include_terminal=True,
        now=now + timedelta(minutes=16),
    )
    assert expired["status"] == "expired"
    with pytest.raises(ConflictError, match="失效"):
        first.csv_persistence.consume_preview(
            preview["preview_id"],
            expected_revision=expired["revision"],
            expected_inspection_sha256=preview["inspection_sha256"],
            resulting_draft_id="draft-expired",
            actor="operator-1",
            now=now + timedelta(minutes=16),
        )


def test_preview_rejects_forged_inspection_unsafe_name_and_oversize(
    tmp_path: Path,
) -> None:
    subject = runtime(tmp_path)
    content = csv_bytes()
    inspection = inspect_five_quantity_csv(filename="safe.csv", content=content)
    forged_schema = {**inspection, "schema_fingerprint": "0" * 64}
    with pytest.raises(ConflictError, match="确定性检查结果"):
        subject.csv_persistence.create_preview(
            original_filename="safe.csv",
            content=content,
            inspection=forged_schema,
            actor="operator-1",
        )
    forged_digest = {**inspection, "content_sha256": "1" * 64}
    with pytest.raises(ConflictError, match="摘要"):
        subject.csv_persistence.create_preview(
            original_filename="safe.csv",
            content=content,
            inspection=forged_digest,
            actor="operator-1",
        )
    with pytest.raises(ImportContentError, match="文件名"):
        subject.csv_persistence.create_preview(
            original_filename="../safe.csv",
            content=content,
            inspection=inspection,
            actor="operator-1",
        )
    with pytest.raises(ImportContentError, match="20 MiB"):
        subject.csv_persistence.create_preview(
            original_filename="safe.csv",
            content=b"x" * (20 * 1024 * 1024 + 1),
            inspection=inspection,
            actor="operator-1",
        )


def test_mapping_advice_retains_no_raw_values_and_records_llm_success(
    tmp_path: Path,
) -> None:
    subject = runtime(tmp_path)
    content = (
        "业务日,原煤完成量,当日总电耗,内部备注\n"
        "2026-08-01,2600,96000,SECRET-RAW-COAL-VALUE\n"
    ).encode()
    filename = "erp.csv"
    inspection = inspect_five_quantity_csv(filename=filename, content=content)
    advice = {
        "schema_version": "five-quantity-csv-mapping-advice-v1",
        "content_sha256": inspection["content_sha256"],
        "columns": [
            {
                "source_index": 1,
                "target_metric": "production_t",
                "target_period": "daily_total",
                "source": "llm",
                "confidence": 0.92,
                "status": "needs_review",
            },
            {
                "source_index": 2,
                "target_metric": "electricity_kwh",
                "target_period": "daily_total",
                "source": "llm",
                "confidence": 0.91,
                "status": "needs_review",
            },
            {
                "source_index": 3,
                "target_metric": None,
                "target_period": None,
                "source": "deterministic",
                "confidence": 0.0,
                "status": "unmapped",
            },
        ],
        "llm": {
            "attempted": True,
            "succeeded": True,
            "error_code": None,
            "output_sha256": "a" * 64,
        },
    }

    preview = subject.csv_persistence.create_preview(
        original_filename=filename,
        content=content,
        inspection=inspection,
        mapping_advice=advice,
        actor="operator-1",
    )

    assert preview["mapping_advice"] == advice
    assert len(preview["mapping_advice_sha256"]) == 64
    with subject.store.repository._read() as db:
        row = db.execute(
            """SELECT inspection_json,mapping_advice_json,
                      mapping_advice_sha256 FROM fq_csv_previews
               WHERE preview_id=?""",
            (preview["preview_id"],),
        ).fetchone()
    assert row is not None
    persisted_metadata = str(row["inspection_json"]) + str(
        row["mapping_advice_json"]
    )
    for raw_value in ("2600", "96000", "SECRET-RAW-COAL-VALUE"):
        assert raw_value not in persisted_metadata
    assert row["mapping_advice_sha256"] == preview["mapping_advice_sha256"]


@pytest.mark.parametrize(
    ("llm_status", "message"),
    [
        (
            {
                "attempted": False,
                "succeeded": True,
                "error_code": None,
                "output_sha256": "a" * 64,
            },
            "成功状态",
        ),
        (
            {
                "attempted": True,
                "succeeded": True,
                "error_code": None,
                "output_sha256": None,
            },
            "output_sha256",
        ),
        (
            {
                "attempted": True,
                "succeeded": True,
                "error_code": "csv_mapping_llm_failed",
                "output_sha256": "a" * 64,
            },
            "error_code",
        ),
    ],
)
def test_mapping_advice_rejects_inconsistent_llm_success(
    tmp_path: Path,
    llm_status: dict,
    message: str,
) -> None:
    subject = runtime(tmp_path)
    content = (
        "日期,原煤完成量\n"
        "2026-08-01,2600\n"
    ).encode()
    filename = "erp.csv"
    inspection = inspect_five_quantity_csv(filename=filename, content=content)
    advice = {
        "schema_version": "five-quantity-csv-mapping-advice-v1",
        "content_sha256": inspection["content_sha256"],
        "columns": [
            {
                "source_index": 1,
                "target_metric": "production_t",
                "target_period": "daily_total",
                "source": "llm",
                "confidence": 0.92,
                "status": "needs_review",
            }
        ],
        "llm": llm_status,
    }

    with pytest.raises(ValueError, match=message):
        subject.csv_persistence.create_preview(
            original_filename=filename,
            content=content,
            inspection=inspection,
            mapping_advice=advice,
            actor="operator-1",
        )


def test_mapping_advice_is_immutable_after_preview_creation(tmp_path: Path) -> None:
    subject = runtime(tmp_path)
    preview = create_preview(subject)

    with (
        subject.store.repository._transaction() as db,
        pytest.raises(sqlite3.IntegrityError, match="immutable"),
    ):
        db.execute(
            """UPDATE fq_csv_previews
               SET mapping_advice_json='{}',mapping_advice_sha256=?
               WHERE preview_id=?""",
            ("0" * 64, preview["preview_id"]),
        )

    persisted = subject.csv_persistence.get_preview(
        preview["preview_id"], actor="operator-1"
    )
    assert persisted["mapping_advice"] == preview["mapping_advice"]
    assert persisted["mapping_advice_sha256"] == preview["mapping_advice_sha256"]


def test_approved_mapping_is_whitelisted_versioned_and_schema_bound(
    tmp_path: Path,
) -> None:
    subject = runtime(tmp_path)
    preview = create_preview(subject)
    fingerprint = preview["schema_fingerprint"]

    with pytest.raises(ValueError, match="明确批准"):
        subject.csv_persistence.approve_mapping_profile(
            profile_name="ERP 月报",
            schema_fingerprint=fingerprint,
            mapping=mapping(),
            approved_by="reviewer-1",
            human_approved=False,
        )
    first = subject.csv_persistence.approve_mapping_profile(
        profile_name="ERP 月报",
        schema_fingerprint=fingerprint,
        mapping=mapping(),
        approved_by="reviewer-1",
        human_approved=True,
    )
    assert first["revision"] == 1
    assert first["approved_mappings"][0] == {
        "source_header": "产量",
        "metric": "production_t",
        "scope": "daily_total",
        "shift": None,
        "unit": "t",
        "profile_id": first["profile_id"],
        "profile_revision": 1,
    }
    assert subject.csv_persistence.list_mapping_profiles(
        schema_fingerprint=fingerprint
    )[0]["profile_id"] == first["profile_id"]
    assert (
        subject.csv_persistence.list_mapping_profiles(
            schema_fingerprint="f" * 64
        )
        == []
    )

    second = subject.csv_persistence.approve_mapping_profile(
        profile_name="ERP 月报",
        schema_fingerprint=fingerprint,
        mapping=mapping(header="电量", metric="electricity_kwh"),
        approved_by="reviewer-2",
        human_approved=True,
    )
    assert second["revision"] == 2
    assert subject.csv_persistence.list_mapping_profiles(
        schema_fingerprint=fingerprint
    )[0]["profile_id"] == second["profile_id"]
    versions = subject.csv_persistence.list_mapping_profiles(
        schema_fingerprint=fingerprint, include_retired=True
    )
    assert [(item["revision"], item["status"]) for item in versions] == [
        (2, "active"),
        (1, "retired"),
    ]

    for invalid in (
        mapping(header="=cmd"),
        {
            "schema_version": CSV_MAPPING_PROFILE_CONTRACT,
            "columns": [
                mapping()["columns"][0],
                {**mapping(header="产量2")["columns"][0]},
            ],
        },
        {
            "schema_version": CSV_MAPPING_PROFILE_CONTRACT,
            "columns": [{**mapping()["columns"][0], "expression": "1+1"}],
        },
    ):
        with pytest.raises(ValueError):
            subject.csv_persistence.approve_mapping_profile(
                profile_name="非法配置",
                schema_fingerprint=fingerprint,
                mapping=invalid,
                approved_by="reviewer-1",
                human_approved=True,
            )


def test_profile_cannot_be_reused_for_different_header_fingerprint(
    tmp_path: Path,
) -> None:
    subject = runtime(tmp_path)
    first_preview = create_preview(subject)
    profile = subject.csv_persistence.approve_mapping_profile(
        profile_name="同名业务导出",
        schema_fingerprint=first_preview["schema_fingerprint"],
        mapping=mapping(),
        approved_by="reviewer-1",
        human_approved=True,
    )
    different = create_preview(
        subject,
        content=csv_bytes(production_header="原煤产量(吨)"),
        filename="另一个系统.csv",
    )
    assert different["schema_fingerprint"] != first_preview["schema_fingerprint"]
    with pytest.raises(NotFoundError, match="整套表头"):
        subject.csv_persistence.consume_preview(
            different["preview_id"],
            expected_revision=different["revision"],
            expected_inspection_sha256=different["inspection_sha256"],
            resulting_draft_id="draft-wrong-profile",
            actor="operator-1",
            mapping_profile_id=profile["profile_id"],
        )


def test_schema_initialization_is_idempotent_and_rows_are_retained(
    tmp_path: Path,
) -> None:
    first = runtime(tmp_path)
    preview = create_preview(first)
    reopened = FiveQuantityRuntime(
        Repository(tmp_path / "agent.db"),
        identity=identity(),
        quarantine_directory=tmp_path / "quarantine-reopened",
        csv_preview_directory=tmp_path / "preview-evidence",
    )
    assert reopened.csv_persistence.get_preview(
        preview["preview_id"], actor="operator-1"
    )["content_sha256"] == preview["content_sha256"]
    with (
        reopened.store.repository._transaction() as db,
        pytest.raises(sqlite3.IntegrityError, match="retained"),
    ):
        db.execute(
            "DELETE FROM fq_csv_previews WHERE preview_id=?",
            (preview["preview_id"],),
        )
