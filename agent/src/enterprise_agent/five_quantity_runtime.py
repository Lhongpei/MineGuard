"""Durable one-mine V2 reporting and risk-response runtime."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import threading
import time
import uuid
from contextlib import suppress
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from .errors import ConflictError, NotFoundError, PlatformError, ValidationBlockedError
from .five_quantity_exchange import (
    HTTP_SIGNING_CONTEXT,
    MESSAGE_SIGNING_CONTEXT,
    FiveQuantityPlatformClient,
    MineIdentity,
    sign_message,
    verify_message,
)
from .five_quantity_import import (
    ALLOWED_SUFFIXES,
    MAX_IMPORT_BYTES,
    METRICS,
    SHIFT_KEYS,
    import_five_quantity_bytes,
)
from .util import jcs_json, parse_aware_datetime, sha256_jcs, utc_now, utc_text

ZERO_HASH = "0" * 64
_DRAFT_PAYLOAD_KEYS = {
    "mine",
    "reporting_month",
    "timezone",
    "period_start",
    "period_end",
    "closed_at",
    "comparison_context",
    "days",
    "sources",
    "agent_processing",
}
_FINAL_PAYLOAD_KEYS = _DRAFT_PAYLOAD_KEYS | {"human_confirmation"}
_MEASUREMENT_KEYS = {
    "metric_code",
    "value",
    "unit",
    "aggregation",
    "quality_flags",
    "source_refs",
}
_MISSING_FLAGS = {"missing", "unavailable", "not_applicable"}
_ALLOWED_FLAGS = {
    "reported",
    "missing",
    "unavailable",
    "not_applicable",
    "partial",
    "unit_converted",
    "corrected",
    "source_format_warning",
}
_UNITS = {
    "ventilation_m3_min": "m3/min",
    "electricity_kwh": "kWh",
    "detonators_count": "count",
    "explosives_kg": "kg",
    "mine_entry_persons": "person",
    "production_t": "t",
}
_AGGREGATIONS = {
    "ventilation_m3_min": frozenset({"time_weighted_average", "snapshot"}),
    "electricity_kwh": frozenset({"sum"}),
    "detonators_count": frozenset({"sum"}),
    "explosives_kg": frozenset({"sum"}),
    "mine_entry_persons": frozenset({"sum"}),
    "production_t": frozenset({"sum"}),
}
_METRIC_LABELS = {
    "ventilation_m3_min": "风量",
    "electricity_kwh": "电量",
    "detonators_count": "火工品量（雷管）",
    "explosives_kg": "火工品量（炸药）",
    "mine_entry_persons": "入井人员量",
    # Reports created before the canonical rename remain explainable.
    "labor_persons": "入井人员量",
    "production_t": "产量",
}
_COMPARISON_KEYS = {
    "capacity_band",
    "mining_method",
    "shift_system",
    "coal_type",
    "operating_regime",
}
_RESPONSE_KINDS = {
    "explanation",
    "correction_submitted",
    "clarification_request",
    "unable_to_determine",
}
_REASON_CODES = {
    "equipment_maintenance",
    "power_outage",
    "planned_shutdown",
    "restart_transition",
    "geology_change",
    "production_plan_change",
    "shift_arrangement",
    "ventilation_adjustment",
    "blasting_plan_change",
    "meter_or_source_error",
    "transcription_or_mapping_error",
    "other",
    "unknown_under_investigation",
}
_ACTION_TYPES = {"investigation", "data_correction", "corrective", "preventive"}
_ACTION_STATUSES = {"planned", "in_progress", "completed", "not_applicable"}


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是对象")
    return value


def _text(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{label} 必须是 1-{maximum} 字符")
    if any(
        ord(character) < 32 and character not in {"\n", "\t"} for character in value
    ):
        raise ValueError(f"{label} 包含控制字符")
    return value.strip()


def _iso_date(value: Any, label: str) -> date:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是 ISO 日期")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} 必须是 ISO 日期") from error


def _uuid_text(value: Any, label: str) -> str:
    text = _text(value, label, 64)
    try:
        uuid.UUID(text)
    except (ValueError, AttributeError) as error:
        raise ValueError(f"{label} 必须是 UUID") from error
    return text


def _identifier_text(value: Any, label: str) -> str:
    text = _text(value, label, 128)
    if not text[0].isalnum() or any(
        not (character.isascii() and (character.isalnum() or character in "._:-"))
        for character in text
    ):
        raise ValueError(f"{label} 必须是安全标识")
    return text


def _sha256_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} 必须是小写 SHA-256")
    return value


def validate_five_quantity_payload(
    payload: dict[str, Any],
    *,
    identity: MineIdentity,
    confirmed: bool,
) -> None:
    """Local independent validation matching the neutral V2 wire contract."""

    expected_keys = _FINAL_PAYLOAD_KEYS if confirmed else _DRAFT_PAYLOAD_KEYS
    if not isinstance(payload, dict) or set(payload) != expected_keys:
        raise ValueError("五量 payload 字段不完整或包含未知字段")
    mine = _object(payload["mine"], "mine")
    if mine != identity.mine:
        raise ValueError("草稿矿井/经营主体与本实例启动身份不一致")
    context = _object(payload["comparison_context"], "comparison_context")
    if set(context) != _COMPARISON_KEYS or context != identity.comparison_context:
        raise ValueError("同类矿上下文必须与本实例受控配置完全一致")
    reporting_month = payload["reporting_month"]
    if (
        not isinstance(reporting_month, str)
        or len(reporting_month) != 7
        or reporting_month[4] != "-"
    ):
        raise ValueError("reporting_month 格式非法")
    start = _iso_date(payload["period_start"], "period_start")
    end = _iso_date(payload["period_end"], "period_end")
    if end < start:
        raise ValueError("period_end 不能早于 period_start")
    if payload["timezone"] != identity.timezone:
        raise ValueError("timezone 与本实例配置不一致")
    parse_aware_datetime(payload["closed_at"], "closed_at")
    days = payload["days"]
    if not isinstance(days, list) or not 1 <= len(days) <= 366:
        raise ValueError("days 必须包含 1-366 个日报")
    dates: list[date] = []
    sources = payload["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 512:
        raise ValueError("sources 必须包含 1-512 个来源")
    source_ids: set[str] = set()
    for index, source_value in enumerate(sources):
        source = _object(source_value, f"sources[{index}]")
        required = {
            "source_id",
            "acquisition_mode",
            "source_system",
            "source_record_id",
            "source_location",
            "captured_at",
            "media_type",
            "evidence_sha256",
            "normalization",
        }
        if set(source) != required:
            raise ValueError(f"sources[{index}] 字段不完整")
        source_id = _text(source["source_id"], f"sources[{index}].source_id", 128)
        if source_id in source_ids:
            raise ValueError("source_id 不得重复")
        source_ids.add(source_id)
        if source["acquisition_mode"] not in {"manual_import", "direct_collection"}:
            raise ValueError("acquisition_mode 只能追溯人工导入或直采")
        if len(str(source["evidence_sha256"])) != 64:
            raise ValueError("来源证据摘要非法")
        parse_aware_datetime(source["captured_at"], "source.captured_at")
        if any(
            forbidden in source
            for forbidden in ("trust_level", "trust_score", "reliability_weight")
        ):
            raise ValueError("采集方式不得带信任等级或算法权重")
    for day_index, day_value in enumerate(days):
        day = _object(day_value, f"days[{day_index}]")
        if set(day) != {"date", "operating_state", "reported_quantity"}:
            raise ValueError(f"days[{day_index}] 字段非法")
        current_date = _iso_date(day["date"], f"days[{day_index}].date")
        if (
            not start <= current_date <= end
            or current_date.strftime("%Y-%m") != reporting_month
        ):
            raise ValueError("日报日期超出月报期间")
        dates.append(current_date)
        if day["operating_state"] not in {
            "producing",
            "stopped",
            "maintenance",
            "restarting",
            "unknown",
        }:
            raise ValueError("operating_state 非法")
        quantity = _object(day["reported_quantity"], "reported_quantity")
        if set(quantity) != {"daily_total", "shifts"}:
            raise ValueError("reported_quantity 字段非法")
        shifts = _object(quantity["shifts"], "shifts")
        if set(shifts) != set(SHIFT_KEYS):
            raise ValueError("必须显式提供零点、八点、四点三个班次")
        sets: list[dict[str, Any]] = [_object(quantity["daily_total"], "daily_total")]
        for shift_key in SHIFT_KEYS:
            shift = _object(shifts[shift_key], shift_key)
            if set(shift) != {"shift_code", "start_at", "end_at", "measurements"}:
                raise ValueError(f"{shift_key} 字段非法")
            shift_start = parse_aware_datetime(shift["start_at"], "shift.start_at")
            shift_end = parse_aware_datetime(shift["end_at"], "shift.end_at")
            if shift_end <= shift_start:
                raise ValueError("班次结束必须晚于开始")
            sets.append(_object(shift["measurements"], f"{shift_key}.measurements"))
        for measurements in sets:
            if set(measurements) != set(METRICS):
                raise ValueError(
                    "每个日报/班次必须显式包含五类业务量；"
                    "火工品量须分别填写雷管和炸药子项"
                )
            for metric in METRICS:
                measurement = _object(measurements[metric], metric)
                if set(measurement) != _MEASUREMENT_KEYS:
                    raise ValueError(f"{metric} 测量字段非法")
                if (
                    measurement["metric_code"] != metric
                    or measurement["unit"] != _UNITS[metric]
                ):
                    raise ValueError(f"{metric} 编码或单位非法")
                if measurement["aggregation"] not in _AGGREGATIONS[metric]:
                    allowed = " / ".join(sorted(_AGGREGATIONS[metric]))
                    raise ValueError(
                        f"{metric}.aggregation 非法，应为 {allowed}"
                    )
                value = measurement["value"]
                if value is not None:
                    if isinstance(value, bool) or not isinstance(value, (int, float)):
                        raise ValueError(f"{metric}.value 必须是数字或 null")
                    if not 0 <= float(value) <= 1_000_000_000_000_000:
                        raise ValueError(f"{metric}.value 超出范围")
                    if metric in {
                        "detonators_count",
                        "mine_entry_persons",
                    } and not isinstance(value, int):
                        raise ValueError(f"{metric} 非空时必须是整数")
                flags = measurement["quality_flags"]
                if (
                    not isinstance(flags, list)
                    or not flags
                    or len(flags) != len(set(flags))
                    or not set(flags).issubset(_ALLOWED_FLAGS)
                ):
                    raise ValueError(f"{metric}.quality_flags 非法")
                if value is None and not set(flags) & _MISSING_FLAGS:
                    raise ValueError(f"{metric} 为 null 时必须说明缺失原因")
                if value is not None and set(flags) & _MISSING_FLAGS:
                    raise ValueError(f"{metric} 非空值与缺失标志冲突")
                refs = measurement["source_refs"]
                if (
                    not isinstance(refs, list)
                    or not refs
                    or not set(refs).issubset(source_ids)
                ):
                    raise ValueError(f"{metric}.source_refs 引用了未知来源")
    if dates != sorted(dates) or len(dates) != len(set(dates)):
        raise ValueError("days 必须按日期升序且不得重复")
    if dates[0] != start or dates[-1] != end:
        raise ValueError("period_start/end 必须等于首尾日报日期")
    processing = _object(payload["agent_processing"], "agent_processing")
    required_processing = {
        "normalization_performed",
        "model_assistance_used",
        "processing_record_sha256",
    }
    optional_processing = required_processing | {"model_output_sha256"}
    if not required_processing.issubset(processing) or not set(processing).issubset(
        optional_processing
    ):
        raise ValueError("agent_processing 字段非法")
    if (
        processing["model_assistance_used"] is True
        and "model_output_sha256" not in processing
    ):
        raise ValueError("模型参与时必须记录模型输出摘要")
    if confirmed:
        confirmation = _object(payload["human_confirmation"], "human_confirmation")
        if (
            set(confirmation)
            != {
                "confirmed",
                "confirmer_id",
                "confirmer_name",
                "role",
                "confirmed_at",
                "content_sha256",
            }
            or confirmation["confirmed"] is not True
        ):
            raise ValueError("human_confirmation 非法")


def _audit_hash(
    previous_hash: str,
    sequence: int,
    event_type: str,
    actor: str,
    occurred_at: str,
    details: dict[str, Any],
) -> str:
    return hashlib.sha256(
        jcs_json(
            {
                "previous_hash": previous_hash,
                "sequence": sequence,
                "event_type": event_type,
                "actor": actor,
                "occurred_at": occurred_at,
                "details": details,
            }
        ).encode("utf-8")
    ).hexdigest()


class FiveQuantityStore:
    """V2 tables isolated from legacy draft tables in the same local database."""

    def __init__(self, repository: Any):
        self.repository = repository
        self._initialize()

    def _initialize(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS fq_imports (
                import_id TEXT PRIMARY KEY,
                content_sha256 TEXT NOT NULL UNIQUE,
                filename TEXT NOT NULL,
                acquisition_mode TEXT NOT NULL CHECK (
                    acquisition_mode IN ('manual_import','direct_collection')
                ),
                source_path TEXT,
                status TEXT NOT NULL,
                error_message TEXT,
                draft_id TEXT,
                suggestions_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS fq_drafts (
                draft_id TEXT PRIMARY KEY,
                import_id TEXT NOT NULL UNIQUE,
                revision INTEGER NOT NULL CHECK (revision >= 1),
                submission_revision INTEGER NOT NULL CHECK (submission_revision >= 1),
                correlation_id TEXT,
                predecessor_message_id TEXT,
                predecessor_payload_sha256 TEXT,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                confirmation_json TEXT,
                submission_message_id TEXT UNIQUE,
                receipt_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(import_id) REFERENCES fq_imports(import_id)
            )""",
            """CREATE TABLE IF NOT EXISTS fq_outbox (
                message_id TEXT PRIMARY KEY,
                message_kind TEXT NOT NULL,
                aggregate_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                body_json TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                receipt_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE INDEX IF NOT EXISTS idx_fq_outbox_due
                ON fq_outbox(status, next_attempt_at)""",
            """CREATE TABLE IF NOT EXISTS fq_inbox (
                message_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE,
                correlation_id TEXT NOT NULL,
                delivery_cursor TEXT NOT NULL,
                body_json TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,
                received_at TEXT NOT NULL,
                acknowledged_at TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS fq_responses (
                response_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE,
                revision INTEGER NOT NULL CHECK (revision >= 1),
                status TEXT NOT NULL,
                document_json TEXT NOT NULL,
                confirmation_json TEXT,
                message_id TEXT UNIQUE,
                receipt_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(report_id) REFERENCES fq_inbox(report_id)
            )""",
            """CREATE TABLE IF NOT EXISTS fq_chat_messages (
                message_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user','assistant')),
                content TEXT NOT NULL,
                tools_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(report_id) REFERENCES fq_inbox(report_id)
            )""",
            """CREATE INDEX IF NOT EXISTS idx_fq_chat_report
                ON fq_chat_messages(report_id, created_at)""",
            """CREATE TABLE IF NOT EXISTS fq_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS fq_audit (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                details_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )""",
            """CREATE TRIGGER IF NOT EXISTS fq_audit_no_update
                BEFORE UPDATE ON fq_audit BEGIN
                    SELECT RAISE(ABORT, 'fq_audit is append-only');
                END""",
            """CREATE TRIGGER IF NOT EXISTS fq_audit_no_delete
                BEFORE DELETE ON fq_audit BEGIN
                    SELECT RAISE(ABORT, 'fq_audit is append-only');
                END""",
        )
        with self.repository._transaction() as db:
            for statement in statements:
                db.execute(statement)
            db.execute(
                "UPDATE fq_outbox SET status='failed', "
                "last_error='recovered_after_restart' WHERE status='sending'"
            )

    @staticmethod
    def _loads(value: str | None) -> Any:
        return json.loads(value) if value is not None else None

    def _append_audit(
        self,
        db: Any,
        event_type: str,
        actor: str,
        details: dict[str, Any],
    ) -> None:
        previous = db.execute(
            "SELECT sequence,event_hash FROM fq_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = str(previous["event_hash"]) if previous else ZERO_HASH
        occurred_at = utc_text()
        event_hash = _audit_hash(
            previous_hash, sequence, event_type, actor, occurred_at, details
        )
        db.execute(
            "INSERT INTO fq_audit VALUES (?,?,?,?,?,?,?)",
            (
                sequence,
                event_type,
                actor,
                occurred_at,
                jcs_json(details),
                previous_hash,
                event_hash,
            ),
        )

    def create_import(
        self,
        imported: dict[str, Any],
        *,
        source_path: str | None,
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_imports WHERE content_sha256=?",
                (imported["content_sha256"],),
            ).fetchone()
            if existing is not None:
                result = dict(existing)
                result["duplicate"] = True
                return result
            import_id = str(uuid.uuid4())
            draft_id = str(uuid.uuid4())
            db.execute(
                """INSERT INTO fq_imports(
                    import_id,content_sha256,filename,acquisition_mode,source_path,
                    status,error_message,draft_id,suggestions_json,created_at
                ) VALUES (?,?,?,?,?,'ready_review',NULL,?,?,?)""",
                (
                    import_id,
                    imported["content_sha256"],
                    imported["filename"],
                    imported["acquisition_mode"],
                    source_path,
                    draft_id,
                    jcs_json(imported["suggestions"]),
                    now,
                ),
            )
            db.execute(
                """INSERT INTO fq_drafts(
                    draft_id,import_id,revision,submission_revision,status,
                    payload_json,created_at,updated_at
                ) VALUES (?,?,1,1,'ready_review',?,?,?)""",
                (draft_id, import_id, jcs_json(imported["payload"]), now, now),
            )
            self._append_audit(
                db,
                "five_quantity_imported",
                actor,
                {
                    "import_id": import_id,
                    "draft_id": draft_id,
                    "content_sha256": imported["content_sha256"],
                    "acquisition_mode": imported["acquisition_mode"],
                },
            )
            return {
                "import_id": import_id,
                "draft_id": draft_id,
                "status": "ready_review",
                "duplicate": False,
            }

    def record_quarantine(
        self,
        *,
        filename: str,
        content_sha256: str,
        acquisition_mode: str,
        source_path: str | None,
        error_message: str,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_imports WHERE content_sha256=?", (content_sha256,)
            ).fetchone()
            if existing is not None:
                return dict(existing)
            import_id = str(uuid.uuid4())
            db.execute(
                """INSERT INTO fq_imports(
                    import_id,content_sha256,filename,acquisition_mode,source_path,
                    status,error_message,draft_id,suggestions_json,created_at
                ) VALUES (?,?,?,?,?,'quarantined',?,NULL,'[]',?)""",
                (
                    import_id,
                    content_sha256,
                    filename[:255],
                    acquisition_mode,
                    source_path,
                    error_message[:1000],
                    now,
                ),
            )
            self._append_audit(
                db,
                "five_quantity_quarantined",
                "system-watcher",
                {
                    "import_id": import_id,
                    "content_sha256": content_sha256,
                    "error": error_message[:500],
                },
            )
            return {"import_id": import_id, "status": "quarantined"}

    def list_imports(
        self, limit: int = 100, *, include_discarded: bool = False
    ) -> list[dict[str, Any]]:
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_imports "
                + ("" if include_discarded else "WHERE status!='discarded' ")
                + "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                **dict(row),
                "suggestions": self._loads(row["suggestions_json"]),
                "suggestions_json": None,
            }
            for row in rows
        ]

    def _draft(self, row: Any) -> dict[str, Any]:
        return {
            "draft_id": row["draft_id"],
            "import_id": row["import_id"],
            "revision": row["revision"],
            "submission_revision": row["submission_revision"],
            "status": row["status"],
            "payload": self._loads(row["payload_json"]),
            "confirmation": self._loads(row["confirmation_json"]),
            "submission_message_id": row["submission_message_id"],
            "receipt": self._loads(row["receipt_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_draft(self, draft_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("五量草稿不存在")
        return self._draft(row)

    def list_drafts(
        self, limit: int = 100, *, include_discarded: bool = False
    ) -> list[dict[str, Any]]:
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_drafts "
                + ("" if include_discarded else "WHERE status!='discarded' ")
                + "ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._draft(row) for row in rows]

    def discard_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        now = utc_text()
        reason = _text(reason, "放弃原因", 1000)
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("五量草稿不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("草稿修订号已变化，请刷新后重试")
            if row["status"] == "discarded":
                return self._draft(row)
            outbox = db.execute(
                "SELECT 1 FROM fq_outbox WHERE aggregate_id=? "
                "AND message_kind='submission' LIMIT 1",
                (draft_id,),
            ).fetchone()
            if (
                row["status"] != "ready_review"
                or row["confirmation_json"] is not None
                or row["submission_message_id"] is not None
                or outbox is not None
            ):
                raise ConflictError("已确认、已入发送队列或已送达的草稿不能放弃")
            revision = expected_revision + 1
            db.execute(
                "UPDATE fq_drafts SET status='discarded',revision=?,updated_at=? "
                "WHERE draft_id=?",
                (revision, now, draft_id),
            )
            db.execute(
                "UPDATE fq_imports SET status='discarded' WHERE import_id=?",
                (row["import_id"],),
            )
            self._append_audit(
                db,
                "five_quantity_draft_discarded",
                actor,
                {
                    "draft_id": draft_id,
                    "import_id": row["import_id"],
                    "revision": revision,
                    "reason": reason,
                },
            )
        return self.get_draft(draft_id)

    def replace_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        payload: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("五量草稿不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("草稿已被其他操作修改，请刷新后重试")
            if row["status"] in {"queued", "submitted", "discarded"}:
                raise ConflictError("已报送或已放弃草稿不可覆盖，请创建新版本")
            revision = expected_revision + 1
            db.execute(
                """UPDATE fq_drafts SET revision=?,status='ready_review',
                    payload_json=?,confirmation_json=NULL,updated_at=?
                    WHERE draft_id=?""",
                (revision, jcs_json(payload), now, draft_id),
            )
            self._append_audit(
                db,
                "five_quantity_review_saved",
                actor,
                {
                    "draft_id": draft_id,
                    "revision": revision,
                    "payload_sha256": sha256_jcs(payload),
                },
            )
        return self.get_draft(draft_id)

    def confirm_and_enqueue(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        confirmation: dict[str, Any],
        message: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        message_json = jcs_json(message)
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_drafts WHERE draft_id=?", (draft_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("五量草稿不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("草稿修订号已变化")
            if row["status"] == "discarded":
                raise ConflictError("已放弃草稿不能确认或报送")
            if row["status"] in {"queued", "submitted"}:
                existing = db.execute(
                    "SELECT * FROM fq_outbox WHERE aggregate_id=? "
                    "AND message_kind='submission'",
                    (draft_id,),
                ).fetchone()
                if existing is None:
                    raise ConflictError("草稿状态与 outbox 不一致")
                return dict(existing)
            db.execute(
                """UPDATE fq_drafts SET status='queued',confirmation_json=?,
                    submission_message_id=?,correlation_id=?,updated_at=?
                    WHERE draft_id=?""",
                (
                    jcs_json(confirmation),
                    message["message_id"],
                    message["correlation_id"],
                    now,
                    draft_id,
                ),
            )
            db.execute(
                """INSERT INTO fq_outbox(
                    message_id,message_kind,aggregate_id,idempotency_key,body_json,
                    body_sha256,status,next_attempt_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,'queued',?,?,?)""",
                (
                    message["message_id"],
                    "submission",
                    draft_id,
                    message["idempotency_key"],
                    message_json,
                    hashlib.sha256(message_json.encode("utf-8")).hexdigest(),
                    now,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "five_quantity_confirmed_and_queued",
                actor,
                {
                    "draft_id": draft_id,
                    "message_id": message["message_id"],
                    "payload_sha256": message["signature_envelope"]["payload_sha256"],
                },
            )
        return self.get_draft(draft_id)

    def due_outbox(self, limit: int = 20) -> list[dict[str, Any]]:
        now = utc_text()
        with self.repository._transaction() as db:
            rows = db.execute(
                """SELECT * FROM fq_outbox
                   WHERE status IN ('queued','failed') AND next_attempt_at<=?
                   ORDER BY created_at LIMIT ?""",
                (now, limit),
            ).fetchall()
            result = []
            for row in rows:
                db.execute(
                    "UPDATE fq_outbox SET status='sending',"
                    "attempts=attempts+1,updated_at=? "
                    "WHERE message_id=?",
                    (now, row["message_id"]),
                )
                item = dict(row)
                item["body"] = self._loads(row["body_json"])
                item["attempts"] = int(row["attempts"]) + 1
                result.append(item)
            return result

    def outbox_succeeded(
        self, message_id: str, *, receipt: dict[str, Any] | None
    ) -> None:
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_outbox WHERE message_id=?", (message_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("outbox 消息不存在")
            db.execute(
                """UPDATE fq_outbox SET status='succeeded',receipt_json=?,
                    last_error=NULL,updated_at=? WHERE message_id=?""",
                (jcs_json(receipt) if receipt is not None else None, now, message_id),
            )
            kind = row["message_kind"]
            if kind == "submission":
                db.execute(
                    "UPDATE fq_drafts SET status='submitted',"
                    "receipt_json=?,updated_at=? "
                    "WHERE draft_id=?",
                    (jcs_json(receipt), now, row["aggregate_id"]),
                )
            elif kind == "delivery_ack":
                inbox = db.execute(
                    "SELECT delivery_cursor FROM fq_inbox WHERE report_id=?",
                    (row["aggregate_id"],),
                ).fetchone()
                if inbox is None:
                    raise ConflictError("ack 对应的 inbox 风险不存在")
                db.execute(
                    "UPDATE fq_inbox SET status='acknowledged',acknowledged_at=? "
                    "WHERE report_id=?",
                    (now, row["aggregate_id"]),
                )
                db.execute(
                    """INSERT INTO fq_settings(setting_key,setting_value,updated_at)
                       VALUES ('analysis_cursor',?,?)
                       ON CONFLICT(setting_key) DO UPDATE SET
                         setting_value=excluded.setting_value,
                         updated_at=excluded.updated_at""",
                    (inbox["delivery_cursor"], now),
                )
            elif kind == "risk_response":
                db.execute(
                    "UPDATE fq_responses SET status='submitted',"
                    "receipt_json=?,updated_at=? "
                    "WHERE response_id=?",
                    (jcs_json(receipt), now, row["aggregate_id"]),
                )
            self._append_audit(
                db,
                "five_quantity_outbox_delivered",
                "system-exchange",
                {"message_id": message_id, "kind": kind},
            )

    def outbox_failed(self, message_id: str, *, error: str, attempts: int) -> None:
        delay_seconds = min(3600, max(5, 5 * (2 ** min(attempts - 1, 9))))
        next_attempt = utc_text(utc_now() + timedelta(seconds=delay_seconds))
        with self.repository._transaction() as db:
            db.execute(
                """UPDATE fq_outbox SET status='failed',last_error=?,
                    next_attempt_at=?,updated_at=? WHERE message_id=?""",
                (error[:1000], next_attempt, utc_text(), message_id),
            )

    def last_cursor(self) -> str | None:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT setting_value FROM fq_settings "
                "WHERE setting_key='analysis_cursor'"
            ).fetchone()
        return str(row["setting_value"]) if row else None

    def store_report_with_ack(
        self, report: dict[str, Any], ack: dict[str, Any]
    ) -> dict[str, Any]:
        payload = report["payload"]
        now = utc_text()
        report_json = jcs_json(report)
        ack_json = jcs_json(ack)
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_inbox WHERE message_id=? OR report_id=?",
                (report["message_id"], payload["report_id"]),
            ).fetchone()
            if existing is not None:
                if (
                    existing["body_sha256"]
                    != hashlib.sha256(report_json.encode("utf-8")).hexdigest()
                ):
                    raise ConflictError("同一风险消息身份出现不同内容")
                return {"duplicate": True, **dict(existing)}
            db.execute(
                """INSERT INTO fq_inbox(
                    message_id,report_id,correlation_id,delivery_cursor,body_json,
                    body_sha256,status,received_at
                ) VALUES (?,?,?,?,?,?,'stored',?)""",
                (
                    report["message_id"],
                    payload["report_id"],
                    report["correlation_id"],
                    payload["delivery_cursor"],
                    report_json,
                    hashlib.sha256(report_json.encode("utf-8")).hexdigest(),
                    now,
                ),
            )
            db.execute(
                """INSERT INTO fq_outbox(
                    message_id,message_kind,aggregate_id,idempotency_key,body_json,
                    body_sha256,status,next_attempt_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,'queued',?,?,?)""",
                (
                    ack["message_id"],
                    "delivery_ack",
                    payload["report_id"],
                    ack["idempotency_key"],
                    ack_json,
                    hashlib.sha256(ack_json.encode("utf-8")).hexdigest(),
                    now,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "analysis_report_stored",
                "system-exchange",
                {
                    "report_id": payload["report_id"],
                    "message_id": report["message_id"],
                    "outcome": payload["outcome"],
                },
            )
            return {"duplicate": False, "report_id": payload["report_id"]}

    def _report(self, row: Any) -> dict[str, Any]:
        message = self._loads(row["body_json"])
        return {
            "report_id": row["report_id"],
            "message_id": row["message_id"],
            "status": row["status"],
            "delivery_cursor": row["delivery_cursor"],
            "received_at": row["received_at"],
            "acknowledged_at": row["acknowledged_at"],
            "report": message,
        }

    def list_reports(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_inbox ORDER BY received_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._report(row) for row in rows]

    def get_report(self, report_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM fq_inbox WHERE report_id=?", (report_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("风险报告不存在")
        return self._report(row)

    def create_response(self, report_id: str, *, actor: str) -> dict[str, Any]:
        report_record = self.get_report(report_id)
        findings = report_record["report"]["payload"]["findings"]
        now = utc_text()
        document = {
            "response_id": str(uuid.uuid4()),
            "report_id": report_id,
            "analysis_report_message_id": report_record["message_id"],
            "responded_at": now,
            "finding_responses": [
                {
                    "finding_id": finding["finding_id"],
                    "response_kind": "unable_to_determine",
                    "reason_code": "unknown_under_investigation",
                    "facts": "待企业人员核对并填写具体事实。",
                    "evidence_refs": [],
                    "actions": [],
                    "corrected_submission_message_id": None,
                }
                for finding in findings
            ],
            "attachments": [],
            "agent_assistance": {
                "used": False,
                "conversation_id": None,
                "assistance_record_sha256": None,
            },
        }
        with self.repository._transaction() as db:
            existing = db.execute(
                "SELECT * FROM fq_responses WHERE report_id=?", (report_id,)
            ).fetchone()
            if existing is not None:
                return self._response(existing)
            db.execute(
                """INSERT INTO fq_responses(
                    response_id,report_id,revision,status,document_json,created_at,updated_at
                ) VALUES (?,?,1,'draft',?,?,?)""",
                (document["response_id"], report_id, jcs_json(document), now, now),
            )
            self._append_audit(
                db,
                "risk_response_draft_created",
                actor,
                {"response_id": document["response_id"], "report_id": report_id},
            )
        return self.get_response(document["response_id"])

    def _response(self, row: Any) -> dict[str, Any]:
        return {
            "response_id": row["response_id"],
            "report_id": row["report_id"],
            "revision": row["revision"],
            "status": row["status"],
            "document": self._loads(row["document_json"]),
            "confirmation": self._loads(row["confirmation_json"]),
            "message_id": row["message_id"],
            "receipt": self._loads(row["receipt_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_response(self, response_id: str) -> dict[str, Any]:
        with self.repository._read() as db:
            row = db.execute(
                "SELECT * FROM fq_responses WHERE response_id=?", (response_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("风险回复不存在")
        return self._response(row)

    def replace_response(
        self,
        response_id: str,
        *,
        expected_revision: int,
        document: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_responses WHERE response_id=?", (response_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("风险回复不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("风险回复已被其他操作修改")
            if row["status"] in {"queued", "submitted"}:
                raise ConflictError("已发送的风险回复不可覆盖")
            revision = expected_revision + 1
            db.execute(
                """UPDATE fq_responses SET revision=?,status='draft',document_json=?,
                    confirmation_json=NULL,updated_at=? WHERE response_id=?""",
                (revision, jcs_json(document), now, response_id),
            )
            self._append_audit(
                db,
                "risk_response_saved",
                actor,
                {"response_id": response_id, "revision": revision},
            )
        return self.get_response(response_id)

    def confirm_response_and_enqueue(
        self,
        response_id: str,
        *,
        expected_revision: int,
        confirmation: dict[str, Any],
        message: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        now = utc_text()
        message_json = jcs_json(message)
        with self.repository._transaction() as db:
            row = db.execute(
                "SELECT * FROM fq_responses WHERE response_id=?", (response_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("风险回复不存在")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("风险回复修订号已变化")
            if row["status"] in {"queued", "submitted"}:
                return self._response(row)
            db.execute(
                """UPDATE fq_responses SET status='queued',document_json=?,
                    confirmation_json=?,message_id=?,updated_at=?
                    WHERE response_id=?""",
                (
                    jcs_json(message["payload"]),
                    jcs_json(confirmation),
                    message["message_id"],
                    now,
                    response_id,
                ),
            )
            db.execute(
                """INSERT INTO fq_outbox(
                    message_id,message_kind,aggregate_id,idempotency_key,body_json,
                    body_sha256,status,next_attempt_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,'queued',?,?,?)""",
                (
                    message["message_id"],
                    "risk_response",
                    response_id,
                    message["idempotency_key"],
                    message_json,
                    hashlib.sha256(message_json.encode("utf-8")).hexdigest(),
                    now,
                    now,
                    now,
                ),
            )
            self._append_audit(
                db,
                "risk_response_confirmed_and_queued",
                actor,
                {"response_id": response_id, "message_id": message["message_id"]},
            )
        return self.get_response(response_id)

    def append_chat(
        self,
        *,
        report_id: str,
        actor_id: str,
        question: str,
        answer: str,
        tools: list[str],
    ) -> list[dict[str, Any]]:
        now = utc_text()
        with self.repository._transaction() as db:
            for role, content, used_tools in (
                ("user", question, []),
                ("assistant", answer, tools),
            ):
                db.execute(
                    "INSERT INTO fq_chat_messages VALUES (?,?,?,?,?,?,?)",
                    (
                        str(uuid.uuid4()),
                        report_id,
                        actor_id,
                        role,
                        content,
                        jcs_json(used_tools),
                        now,
                    ),
                )
            self._append_audit(
                db,
                "risk_chat_turn",
                actor_id,
                {
                    "report_id": report_id,
                    "question_sha256": hashlib.sha256(question.encode()).hexdigest(),
                    "tools": tools,
                },
            )
        return self.chat_messages(report_id)

    def chat_messages(self, report_id: str) -> list[dict[str, Any]]:
        self.get_report(report_id)
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_chat_messages WHERE report_id=? "
                "ORDER BY created_at,rowid",
                (report_id,),
            ).fetchall()
        return [
            {
                "message_id": row["message_id"],
                "role": row["role"],
                "content": row["content"],
                "tools": self._loads(row["tools_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def audit(self, limit: int = 200) -> dict[str, Any]:
        with self.repository._read() as db:
            rows = db.execute(
                "SELECT * FROM fq_audit ORDER BY sequence LIMIT ?", (limit,)
            ).fetchall()
        previous = ZERO_HASH
        valid = True
        events = []
        for row in rows:
            details = self._loads(row["details_json"])
            expected = _audit_hash(
                previous,
                row["sequence"],
                row["event_type"],
                row["actor"],
                row["occurred_at"],
                details,
            )
            if row["previous_hash"] != previous or row["event_hash"] != expected:
                valid = False
            previous = row["event_hash"]
            events.append({**dict(row), "details": details, "details_json": None})
        return {"valid": valid, "head_hash": previous, "events": events}


def _validate_analysis_report(report: dict[str, Any], identity: MineIdentity) -> None:
    payload = _object(report.get("payload"), "analysis payload")
    required = {
        "report_id",
        "submission_message_id",
        "submission_revision",
        "mine",
        "reporting_month",
        "period_start",
        "period_end",
        "issued_at",
        "algorithm",
        "outcome",
        "summary",
        "findings",
        "response_required",
        "response_due_at",
        "delivery_cursor",
    }
    if set(payload) != required or payload["mine"] != identity.mine:
        raise PlatformError("算法报告 payload 字段或矿井绑定非法")
    if payload["outcome"] not in {"risk", "data_insufficient"}:
        raise PlatformError("企业风险收件箱只接收需要回复的风险/数据不足报告")
    if payload["response_required"] is not True:
        raise PlatformError("风险报告必须明确要求回复")
    findings = payload["findings"]
    if not isinstance(findings, list) or not findings:
        raise PlatformError("风险报告缺少结构化 finding")
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(
            finding.get("finding_id"), str
        ):
            raise PlatformError("风险 finding 结构非法")
        if finding["finding_id"] in finding_ids:
            raise PlatformError("风险 finding_id 重复")
        finding_ids.add(finding["finding_id"])
        if finding.get("requires_response") is not True:
            raise PlatformError("投递到企业的 finding 必须要求回复")
        if not isinstance(finding.get("evidence"), list) or not finding["evidence"]:
            raise PlatformError("风险 finding 缺少算法证据")
    algorithm = _object(payload["algorithm"], "algorithm")
    if algorithm.get("engine_id") != "mineguard-five-quantity-engine":
        raise PlatformError("报告不是政府唯一五量监管引擎输出")


def _validate_response_document(
    document: dict[str, Any], report: dict[str, Any]
) -> None:
    required = {
        "response_id",
        "report_id",
        "analysis_report_message_id",
        "responded_at",
        "finding_responses",
        "attachments",
        "agent_assistance",
    }
    if not isinstance(document, dict) or set(document) != required:
        raise ValueError("风险回复草稿字段非法")
    _uuid_text(document["response_id"], "response_id")
    _uuid_text(document["report_id"], "report_id")
    _uuid_text(document["analysis_report_message_id"], "analysis_report_message_id")
    parse_aware_datetime(document["responded_at"], "responded_at")
    report_message = report["report"]
    if (
        document["report_id"] != report["report_id"]
        or document["analysis_report_message_id"] != report_message["message_id"]
    ):
        raise ValueError("风险回复与报告绑定不一致")
    findings = {item["finding_id"] for item in report_message["payload"]["findings"]}
    responses = document["finding_responses"]
    if (
        not isinstance(responses, list)
        or not 1 <= len(responses) <= 100
        or any(not isinstance(item, dict) for item in responses)
        or {item.get("finding_id") for item in responses} != findings
    ):
        raise ValueError("必须逐项回复当前报告的全部 finding")
    attachments = document["attachments"]
    if not isinstance(attachments, list) or len(attachments) > 100:
        raise ValueError("attachments 必须是最多 100 项的数组")
    attachment_ids: set[str] = set()
    for index, attachment in enumerate(attachments):
        if not isinstance(attachment, dict) or set(attachment) != {
            "evidence_id",
            "title",
            "media_type",
            "size_bytes",
            "sha256",
            "retention_location",
        }:
            raise ValueError(f"attachments[{index}] 字段非法")
        evidence_id = _identifier_text(
            attachment["evidence_id"], f"attachments[{index}].evidence_id"
        )
        if evidence_id in attachment_ids:
            raise ValueError("附件 evidence_id 不得重复")
        attachment_ids.add(evidence_id)
        _text(attachment["title"], f"attachments[{index}].title", 256)
        _text(attachment["media_type"], f"attachments[{index}].media_type", 128)
        size = attachment["size_bytes"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= 1_073_741_824
        ):
            raise ValueError("附件 size_bytes 非法")
        _sha256_text(attachment["sha256"], f"attachments[{index}].sha256")
        if attachment["retention_location"] != "enterprise_local":
            raise ValueError("附件原件必须保留在企业侧")
    for item in responses:
        if set(item) != {
            "finding_id",
            "response_kind",
            "reason_code",
            "facts",
            "evidence_refs",
            "actions",
            "corrected_submission_message_id",
        }:
            raise ValueError("finding response 字段非法")
        _uuid_text(item["finding_id"], "finding_id")
        if item["response_kind"] not in _RESPONSE_KINDS:
            raise ValueError("response_kind 非法")
        if item["reason_code"] not in _REASON_CODES:
            raise ValueError("reason_code 非法")
        _text(item.get("facts"), "企业事实说明", 8000)
        refs = item["evidence_refs"]
        if (
            not isinstance(refs, list)
            or len(refs) > 50
            or len(refs) != len(set(refs))
            or any(not isinstance(ref, str) for ref in refs)
            or not set(refs).issubset(attachment_ids)
        ):
            raise ValueError("回复引用了未声明的证据")
        actions = item["actions"]
        if not isinstance(actions, list) or len(actions) > 50:
            raise ValueError("actions 必须是最多 50 项的数组")
        for action in actions:
            if not isinstance(action, dict) or set(action) != {
                "action_type",
                "description",
                "status",
            }:
                raise ValueError("整改措施字段非法")
            if action["action_type"] not in _ACTION_TYPES:
                raise ValueError("action_type 非法")
            if action["status"] not in _ACTION_STATUSES:
                raise ValueError("action status 非法")
            _text(action["description"], "整改措施说明", 2000)
        corrected = item.get("corrected_submission_message_id")
        if item["response_kind"] == "correction_submitted":
            _uuid_text(corrected, "更正报表消息编号")
        elif corrected is not None:
            raise ValueError("非更正回复不得携带更正报表消息编号")
    assistance = document["agent_assistance"]
    if not isinstance(assistance, dict) or set(assistance) != {
        "used",
        "conversation_id",
        "assistance_record_sha256",
    }:
        raise ValueError("agent_assistance 字段非法")
    if not isinstance(assistance["used"], bool):
        raise ValueError("agent_assistance.used 必须是布尔值")
    if assistance["used"]:
        _text(assistance["conversation_id"], "conversation_id", 128)
        _sha256_text(assistance["assistance_record_sha256"], "assistance_record_sha256")
    elif (
        assistance["conversation_id"] is not None
        or assistance["assistance_record_sha256"] is not None
    ):
        raise ValueError("未使用智能体时不得声明辅助记录")


class FiveQuantityRuntime:
    def __init__(
        self,
        repository: Any,
        *,
        identity: MineIdentity,
        platform_client: FiveQuantityPlatformClient | None = None,
        watched_directories: tuple[str, ...] = (),
        quarantine_directory: str | Path | None = None,
        poll_seconds: float = 5.0,
        stable_seconds: float = 2.0,
        auto_start: bool = False,
    ):
        self.store = FiveQuantityStore(repository)
        self.identity = identity
        self.platform_client = platform_client
        self.poll_seconds = max(0.5, min(float(poll_seconds), 60.0))
        self.stable_seconds = max(0.5, min(float(stable_seconds), 60.0))
        self.watched_directories = self._watched(watched_directories)
        self.quarantine_directory = self._quarantine_directory(
            quarantine_directory,
            repository=repository,
            watched=self.watched_directories,
        )
        self._watch_state: dict[str, tuple[int, int, float]] = {}
        self._processed_paths: dict[str, tuple[int, int]] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        if auto_start:
            self.start()

    @staticmethod
    def _watched(values: tuple[str, ...]) -> tuple[Path, ...]:
        result = []
        for value in values:
            path = Path(value).expanduser()
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f"五量监听目录无效或为符号链接：{path}")
            resolved = path.resolve()
            if resolved == Path(resolved.anchor):
                raise ValueError("拒绝把文件系统根目录设为监听目录")
            result.append(resolved)
        if len(result) != len(set(result)):
            raise ValueError("五量监听目录不得重复")
        return tuple(result)

    @staticmethod
    def _quarantine_directory(
        value: str | Path | None,
        *,
        repository: Any,
        watched: tuple[Path, ...],
    ) -> Path:
        if value is None:
            repository_path = str(getattr(repository, "path", ":memory:"))
            state_directory = (
                Path("./data").resolve()
                if repository_path == ":memory:"
                else Path(repository_path).resolve().parent
            )
            candidate = state_directory / "five-quantity-quarantine"
        else:
            candidate = Path(value).expanduser()
        if candidate.is_symlink():
            raise ValueError("五量隔离目录不能是符号链接")
        resolved = candidate.resolve()
        if resolved == Path(resolved.anchor):
            raise ValueError("拒绝把文件系统根目录设为五量隔离目录")
        for source in watched:
            if resolved == source or resolved.is_relative_to(source):
                raise ValueError(
                    "五量隔离目录必须位于 Agent 状态目录，不能放在来源目录中"
                )
        resolved.mkdir(parents=True, mode=0o700, exist_ok=True)
        if resolved.is_symlink() or not resolved.is_dir():
            raise ValueError("五量隔离目录创建失败或不是普通目录")
        with suppress(OSError):
            os.chmod(resolved, 0o700)
        return resolved

    @staticmethod
    def _write_quarantine_file(path: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise OSError("隔离文件写入失败")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="five-quantity-exchange",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=min(5.0, self.poll_seconds + 1))
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            with suppress(Exception):
                self.scan_watched_directories()
            with suppress(Exception):
                self.process_outbox_once()
            with suppress(Exception):
                self.poll_analysis_once()
            self._stop.wait(self.poll_seconds)

    def ingest_bytes(
        self,
        *,
        filename: str,
        content: bytes,
        acquisition_mode: str,
        actor: str,
        source_path: str | None = None,
    ) -> dict[str, Any]:
        imported = import_five_quantity_bytes(
            filename=filename,
            content=content,
            acquisition_mode=acquisition_mode,
            identity=self.identity,
        )
        validate_five_quantity_payload(
            imported["payload"], identity=self.identity, confirmed=False
        )
        result = self.store.create_import(
            imported, source_path=source_path, actor=actor
        )
        if result.get("draft_id"):
            result["draft"] = self.store.get_draft(result["draft_id"])
        return result

    @staticmethod
    def _read_no_follow(path: Path) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("监听目标不是普通文件")
            if info.st_size <= 0 or info.st_size > MAX_IMPORT_BYTES:
                raise ValueError("监听文件为空或超过 20 MiB")
            chunks = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) != info.st_size:
                raise ValueError("读取期间文件发生变化")
            return content
        finally:
            os.close(descriptor)

    def scan_watched_directories(self) -> list[dict[str, Any]]:
        results = []
        now = time.monotonic()
        for directory in self.watched_directories:
            for path in sorted(directory.iterdir()):
                if path.is_symlink() or path.suffix.casefold() not in ALLOWED_SUFFIXES:
                    continue
                result: dict[str, Any] | None = None
                try:
                    info = path.stat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                fingerprint = (info.st_size, info.st_mtime_ns)
                key = str(path)
                if self._processed_paths.get(key) == fingerprint:
                    continue
                prior = self._watch_state.get(key)
                if prior is None or prior[:2] != fingerprint:
                    self._watch_state[key] = (*fingerprint, now)
                    continue
                if now - prior[2] < self.stable_seconds:
                    continue
                try:
                    content = self._read_no_follow(path)
                    result = self.ingest_bytes(
                        filename=path.name,
                        content=content,
                        acquisition_mode="direct_collection",
                        actor="system-watcher",
                        source_path=str(path),
                    )
                except Exception as error:
                    with suppress(Exception):
                        content = self._read_no_follow(path)
                        digest = hashlib.sha256(content).hexdigest()
                        target = self.quarantine_directory / (
                            f"{digest[:16]}-{path.name}"
                        )
                        self._write_quarantine_file(target, content)
                        result = self.store.record_quarantine(
                            filename=path.name,
                            content_sha256=digest,
                            acquisition_mode="direct_collection",
                            source_path=str(path),
                            error_message=str(error),
                        )
                    if result is None:
                        continue
                self._processed_paths[key] = fingerprint
                results.append(result)
        return results

    def save_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        payload: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        validate_five_quantity_payload(payload, identity=self.identity, confirmed=False)
        return self.store.replace_draft(
            draft_id,
            expected_revision=expected_revision,
            payload=payload,
            actor=actor,
        )

    def discard_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        return self.store.discard_draft(
            draft_id,
            expected_revision=expected_revision,
            actor=actor,
            reason=reason,
        )

    def _base_message(
        self,
        *,
        contract_version: str,
        message_type: str,
        payload: dict[str, Any],
        correlation_id: str,
        causation_id: str | None,
        revision: int = 1,
        predecessor: dict[str, str] | None = None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        message_id = str(uuid.uuid4())
        now = utc_text()
        message = {
            "contract_version": contract_version,
            "message_type": message_type,
            "message_id": message_id,
            "correlation_id": correlation_id,
            "causation_id": causation_id,
            "idempotency_key": idempotency_key,
            "revision": revision,
            "predecessor": predecessor,
            "created_at": now,
            "sender": {
                "system_id": self.identity.system_id,
                "party_id": self.identity.operator_id,
                "role": "enterprise_agent",
            },
            "recipient": {
                "system_id": self.identity.regulator_system_id,
                "party_id": self.identity.regulator_party_id,
                "role": "regulatory_platform",
            },
            "mine_id": self.identity.mine_id,
            "payload": payload,
            "signature_envelope": {
                "algorithm": "hmac-sha256-v2",
                "canonicalization": "rfc8785-jcs",
                "key_id": self.identity.key_id,
                "signed_at": now,
                "nonce": os.urandom(16).hex(),
                "payload_sha256": ZERO_HASH,
                "signature": ZERO_HASH,
            },
        }
        if message_type == "five_quantity_submission" and revision == 1:
            message["correlation_id"] = message_id
        return sign_message(message, secret=self.identity.message_hmac_secret)

    def confirm_draft(
        self,
        draft_id: str,
        *,
        expected_revision: int,
        actor_id: str,
        confirmer_name: str,
        confirmer_role: str,
        attestation: str,
        accepted: bool,
    ) -> dict[str, Any]:
        if accepted is not True:
            raise ValidationBlockedError("必须由企业人员明确确认后才能报送")
        draft = self.store.get_draft(draft_id)
        if draft["revision"] != expected_revision:
            raise ConflictError("草稿修订号已变化")
        payload = json.loads(jcs_json(draft["payload"]))
        confirmed_at = utc_text()
        confirmation_record = {
            "actor_id": _text(actor_id, "actor_id", 128),
            "confirmer_name": _text(confirmer_name, "confirmer_name", 128),
            "role": _text(confirmer_role, "confirmer_role", 128),
            "attestation": _text(attestation, "attestation", 1000),
            "confirmed_at": confirmed_at,
            "draft_revision": expected_revision,
            "payload_sha256": sha256_jcs(payload),
        }
        confirmation = {
            "confirmed": True,
            "confirmer_id": actor_id,
            "confirmer_name": confirmer_name.strip(),
            "role": confirmer_role.strip(),
            "confirmed_at": confirmed_at,
            "content_sha256": sha256_jcs(confirmation_record),
        }
        payload["human_confirmation"] = confirmation
        validate_five_quantity_payload(payload, identity=self.identity, confirmed=True)
        idempotency = (
            f"fq.{self.identity.mine_id}.{payload['reporting_month']}."
            f"r{draft['submission_revision']}"
        )
        message = self._base_message(
            contract_version="five-quantity-submission-v2",
            message_type="five_quantity_submission",
            payload=payload,
            correlation_id=str(uuid.uuid4()),
            causation_id=None,
            revision=draft["submission_revision"],
            predecessor=None,
            idempotency_key=idempotency,
        )
        self.store.confirm_and_enqueue(
            draft_id,
            expected_revision=expected_revision,
            confirmation=confirmation_record,
            message=message,
            actor=actor_id,
        )
        return self.store.get_draft(draft_id)

    def process_outbox_once(self) -> list[dict[str, Any]]:
        if self.platform_client is None:
            return []
        results = []
        for item in self.store.due_outbox():
            message = item["body"]
            try:
                if item["message_kind"] == "submission":
                    receipt = self.platform_client.submit(message)
                    verify_message(
                        receipt,
                        secret=self.identity.message_hmac_secret,
                        identity=self.identity,
                        expected_contract="intake-receipt-v2",
                        expected_type="intake_receipt",
                    )
                    if (
                        receipt["causation_id"] != message["message_id"]
                        or receipt["payload"].get("submission_message_id")
                        != message["message_id"]
                        or receipt["payload"].get("received_payload_sha256")
                        != message["signature_envelope"]["payload_sha256"]
                    ):
                        raise PlatformError("接收回执未正确绑定报送消息")
                elif item["message_kind"] == "delivery_ack":
                    self.platform_client.acknowledge(item["aggregate_id"], message)
                    receipt = None
                elif item["message_kind"] == "risk_response":
                    response = self.store.get_response(item["aggregate_id"])
                    receipt = self.platform_client.respond(
                        response["report_id"], message
                    )
                    verify_message(
                        receipt,
                        secret=self.identity.message_hmac_secret,
                        identity=self.identity,
                        expected_contract="response-receipt-v2",
                        expected_type="response_receipt",
                    )
                    if (
                        receipt["causation_id"] != message["message_id"]
                        or receipt["payload"].get("enterprise_response_message_id")
                        != message["message_id"]
                        or receipt["payload"].get("risk_status")
                        != "not_cleared_by_receipt"
                    ):
                        raise PlatformError("风险回复回执绑定或风险状态非法")
                else:
                    raise ValueError("未知 outbox 消息类型")
                self.store.outbox_succeeded(item["message_id"], receipt=receipt)
                results.append(
                    {"message_id": item["message_id"], "status": "succeeded"}
                )
            except Exception as error:
                self.store.outbox_failed(
                    item["message_id"], error=str(error), attempts=item["attempts"]
                )
                results.append({"message_id": item["message_id"], "status": "failed"})
        return results

    def poll_analysis_once(self) -> dict[str, Any] | None:
        if self.platform_client is None:
            return None
        report = self.platform_client.pull_next(after_cursor=self.store.last_cursor())
        if report is None:
            return None
        verify_message(
            report,
            secret=self.identity.message_hmac_secret,
            identity=self.identity,
            expected_contract="analysis-report-v2",
            expected_type="analysis_report",
        )
        _validate_analysis_report(report, self.identity)
        payload = report["payload"]
        ack_payload = {
            "report_id": payload["report_id"],
            "analysis_report_message_id": report["message_id"],
            "delivery_cursor": payload["delivery_cursor"],
            "received_at": utc_text(),
            "local_inbox_record_id": f"INBOX-{report['message_id']}",
            "delivery_status": "stored",
        }
        ack = self._base_message(
            contract_version="risk-delivery-ack-v2",
            message_type="risk_delivery_ack",
            payload=ack_payload,
            correlation_id=report["correlation_id"],
            causation_id=report["message_id"],
            idempotency_key=f"delivery-ack.{report['message_id']}",
        )
        return self.store.store_report_with_ack(report, ack)

    def risk_explanation(
        self, report_id: str, question: str, *, actor: str
    ) -> dict[str, Any]:
        question = _text(question, "问题", 2000)
        if any(
            phrase in question.casefold()
            for phrase in ("股票", "天气", "写代码", "游戏", "娱乐", "体育比分")
        ):
            answer = (
                "该对话只解释当前煤矿五量风险报告，请围绕异常日期、指标、"
                "证据、原因或回复材料提问。"
            )
            tools: list[str] = []
        else:
            record = self.store.get_report(report_id)
            payload = record["report"]["payload"]
            findings = payload["findings"]
            metric_codes = sorted(
                {
                    metric
                    for finding in findings
                    for metric in finding.get("affected_metrics", [])
                }
            )
            metrics = [_METRIC_LABELS.get(metric, metric) for metric in metric_codes]
            dates = sorted(
                {
                    day
                    for finding in findings
                    for day in finding.get("affected_dates", [])
                }
            )
            methods = sorted(
                {
                    evidence.get("method")
                    for finding in findings
                    for evidence in finding.get("evidence", [])
                    if evidence.get("method")
                }
            )
            tools = ["report_summary", "affected_scope", "evidence_method_explainer"]
            method_text = []
            if "l1_reconciliation" in methods:
                method_text.append(
                    "L1 求解器在联合约束下寻找最小必要调整；超阈值表示"
                    "多项数据难以同时协调，不等于自动认定造假"
                )
            if "minimal_conflict_set" in methods:
                method_text.append("最小冲突集用于缩小需要核对的日期和指标组合")
            if any(
                method in methods
                for method in (
                    "robust_temporal_baseline",
                    "past_only_rolling_mad",
                    "past_only_ewma",
                    "past_only_cusum",
                    "past_only_page_hinkley",
                    "temporal_drift",
                    "change_point",
                )
            ):
                method_text.append(
                    "时序模块只使用当前日期以前的本矿同工况历史：Rolling MAD"
                    "检查稳健离群，EWMA 检查持续偏移，CUSUM 和 Page-Hinkley"
                    "检查累积变化，并结合漂移与变化点复核"
                )
            if "anonymous_peer_baseline" in methods:
                method_text.append("同类矿证据只使用匿名统计区间，不展示其他煤矿明细")
            checklist = "；".join(
                [
                    "核对原表对应日期和班次",
                    "确认单位及日报与班次口径",
                    "查找检修、停复产、供电或生产计划记录",
                    "如数值有误先提交更正报表，再在回复中引用更正消息",
                ]
            )
            answer = (
                f"报告结论：{payload['summary']}\n"
                f"涉及日期：{'、'.join(dates) or '报告未列明'}；"
                f"涉及指标：{'、'.join(metrics) or '报告未列明'}。\n"
                + ("；".join(method_text) + "。\n" if method_text else "")
                + f"建议核对：{checklist}。企业原因说明只会被记录，"
                "不能直接消除风险；更正数据需由政府同一算法重算。"
            )
        messages = self.store.append_chat(
            report_id=report_id,
            actor_id=actor,
            question=question,
            answer=answer,
            tools=tools,
        )
        return {"answer": answer, "tools": tools, "messages": messages}

    def save_response(
        self,
        response_id: str,
        *,
        expected_revision: int,
        document: dict[str, Any],
        actor: str,
    ) -> dict[str, Any]:
        current = self.store.get_response(response_id)
        if document.get("response_id") != response_id:
            raise ValueError("response_id 不得修改")
        report = self.store.get_report(current["report_id"])
        _validate_response_document(document, report)
        return self.store.replace_response(
            response_id,
            expected_revision=expected_revision,
            document=document,
            actor=actor,
        )

    def confirm_response(
        self,
        response_id: str,
        *,
        expected_revision: int,
        actor_id: str,
        confirmer_name: str,
        confirmer_role: str,
        attestation: str,
        accepted: bool,
    ) -> dict[str, Any]:
        if accepted is not True:
            raise ValidationBlockedError("必须由企业人员明确确认风险回复")
        response = self.store.get_response(response_id)
        if response["revision"] != expected_revision:
            raise ConflictError("风险回复修订号已变化")
        report = self.store.get_report(response["report_id"])
        document = json.loads(jcs_json(response["document"]))
        chat_messages = self.store.chat_messages(response["report_id"])
        if chat_messages:
            document["agent_assistance"] = {
                "used": True,
                "conversation_id": f"risk-chat:{response['report_id']}",
                "assistance_record_sha256": sha256_jcs(chat_messages),
            }
        _validate_response_document(document, report)
        confirmed_at = utc_text()
        confirmation_record = {
            "actor_id": _text(actor_id, "actor_id", 128),
            "confirmer_name": _text(confirmer_name, "confirmer_name", 128),
            "role": _text(confirmer_role, "confirmer_role", 128),
            "attestation": _text(attestation, "attestation", 1000),
            "confirmed_at": confirmed_at,
            "response_revision": expected_revision,
            "document_sha256": sha256_jcs(document),
        }
        human = {
            "confirmed": True,
            "confirmer_id": actor_id,
            "confirmer_name": confirmer_name.strip(),
            "role": confirmer_role.strip(),
            "confirmed_at": confirmed_at,
            "content_sha256": sha256_jcs(confirmation_record),
        }
        document["responded_at"] = confirmed_at
        document["human_confirmation"] = human
        message = self._base_message(
            contract_version="enterprise-risk-response-v2",
            message_type="enterprise_risk_response",
            payload=document,
            correlation_id=report["report"]["correlation_id"],
            causation_id=report["message_id"],
            revision=1,
            idempotency_key=f"risk-response.{report['report_id']}.{response_id}.r1",
        )
        return self.store.confirm_response_and_enqueue(
            response_id,
            expected_revision=expected_revision,
            confirmation=confirmation_record,
            message=message,
            actor=actor_id,
        )

    def status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "mine_id": self.identity.mine_id,
            "mine_name": self.identity.mine_name,
            "operator_id": self.identity.operator_id,
            "system_id": self.identity.system_id,
            "platform_configured": self.platform_client is not None,
            "watched_directories": [str(path) for path in self.watched_directories],
            "quarantine_directory": str(self.quarantine_directory),
            "acquisition_modes": ["manual_import", "direct_collection"],
            "acquisition_trust_tiering": False,
            "message_signature_domain": MESSAGE_SIGNING_CONTEXT,
            "transport_signature_domain": HTTP_SIGNING_CONTEXT,
            "distinct_application_and_transport_secrets": (
                self.platform_client is not None
                and not hmac.compare_digest(
                    self.identity.message_hmac_secret.encode("utf-8"),
                    self.platform_client.config.transport_hmac_secret.encode("utf-8"),
                )
            ),
            "regulator_verification_key_ids": [
                self.identity.regulator_key_id,
                *(
                    [self.identity.previous_regulator_key_id]
                    if self.identity.previous_regulator_key_id is not None
                    else []
                ),
            ],
            "last_acknowledged_cursor": self.store.last_cursor(),
        }
