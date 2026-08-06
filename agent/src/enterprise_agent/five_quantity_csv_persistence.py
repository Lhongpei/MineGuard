"""Mine-scoped persistence for inert CSV previews and approved mappings.

This module is intentionally enterprise-local.  It stores raw CSV bytes as
non-executable, content-addressed evidence and stores only a masked inspection
in SQLite.  It has no confirmation, outbox, submission, model, tool, or
regulatory-platform API.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import math
import os
import stat
import unicodedata
import uuid
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import ConflictError, ImportContentError, NotFoundError
from .five_quantity_exchange import MineIdentity
from .five_quantity_import import (
    MAX_IMPORT_BYTES,
    MAX_ROWS,
    METRICS,
    PERIOD_KEYS,
    SHIFT_KEYS,
    UNITS,
    inspect_five_quantity_csv,
)
from .five_quantity_mapping import (
    INSPECTION_CONTRACT_VERSION,
    map_csv_inspection,
)
from .util import jcs_json, sha256_jcs, utc_now, utc_text

CSV_MAPPING_PROFILE_CONTRACT = "five-quantity-approved-column-mapping-profile-v1"
DEFAULT_PREVIEW_TTL_SECONDS = 15 * 60
MIN_PREVIEW_TTL_SECONDS = 60
MAX_PREVIEW_TTL_SECONDS = 60 * 60
MAX_INSPECTION_BYTES = 512 * 1024
MAX_MAPPING_ADVICE_BYTES = 256 * 1024
MAX_MAPPING_ENTRIES = 256

_AuditSink = Callable[[Any, str, str, dict[str, Any]], None]
_FORMULA_PREFIXES = ("=", "+", "-", "@")
_PROFILE_SCOPES = frozenset({"daily_total", "shift"})


def _safe_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} 必须是字符串")
    result = value.strip()
    if not result or len(result) > maximum:
        raise ValueError(f"{label} 必须为 1-{maximum} 个字符")
    if any(ord(character) < 32 or ord(character) == 127 for character in result):
        raise ValueError(f"{label} 包含控制字符")
    return result


def _safe_filename(value: Any) -> str:
    name = _safe_text(value, "original_filename", 255)
    if name in {".", ".."} or any(character in name for character in "/\\"):
        raise ImportContentError("CSV 文件名非法")
    if not name.casefold().endswith(".csv"):
        raise ImportContentError("CSV 预览原件必须使用 .csv 扩展名")
    return name


def _safe_identifier(value: Any, label: str) -> str:
    result = _safe_text(value, label, 128)
    if not result[0].isascii() or not result[0].isalnum() or any(
        not (
            character.isascii()
            and (character.isalnum() or character in "._:-")
        )
        for character in result
    ):
        raise ValueError(f"{label} 必须是安全标识")
    return result


def _sha256_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} 必须是小写 SHA-256")
    return value


def _normalise_header(value: Any) -> str:
    header = _safe_text(value, "source_header", 256)
    normal = unicodedata.normalize("NFKC", header).strip().casefold()
    result = "".join(normal.split())
    if not result or result.startswith(_FORMULA_PREFIXES):
        raise ValueError("source_header 不安全或疑似公式")
    return result


def _detect_csv_metadata(content: bytes) -> tuple[str, str]:
    if content.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ImportContentError(
            "CSV 预览不接受 UTF-16；请另存为 CSV UTF-8 或 GB18030"
        )
    if content.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    else:
        try:
            content.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            try:
                content.decode("gb18030")
                encoding = "gb18030"
            except UnicodeDecodeError as error:
                raise ImportContentError(
                    "CSV 文本必须是 UTF-8 或 GB18030"
                ) from error
    text = content.decode(encoding)
    if "\x00" in text:
        raise ImportContentError("CSV 包含 NUL 控制字符")
    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",\t;")
        delimiter = str(dialect.delimiter)
    except csv.Error:
        delimiter = ","
    return encoding, delimiter


def _validate_inspection(
    value: Any,
    *,
    filename: str,
    content: bytes,
) -> tuple[dict[str, Any], str, str]:
    if not isinstance(value, dict):
        raise ValueError("inspection 必须是对象")
    required = {
        "contract_version",
        "content_sha256",
        "schema_fingerprint",
        "filename",
        "byte_size",
        "encoding",
        "delimiter",
        "header_row",
        "data_start_row",
        "date_column",
        "columns",
        "row_count",
        "valid_day_count",
        "detected_months",
        "warnings",
    }
    if set(value) != required:
        raise ValueError("inspection 字段不完整或包含未知字段")
    if value.get("contract_version") != INSPECTION_CONTRACT_VERSION:
        raise ValueError("inspection contract_version 不受支持")
    content_hash = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(
        _sha256_text(value.get("content_sha256"), "inspection.content_sha256"),
        content_hash,
    ):
        raise ConflictError("inspection 与 CSV 原件摘要不一致")
    schema_fingerprint = _sha256_text(
        value.get("schema_fingerprint"), "inspection.schema_fingerprint"
    )
    if value.get("filename") != filename or value.get("byte_size") != len(content):
        raise ConflictError("inspection 与 CSV 原件元数据不一致")
    encoding, delimiter = _detect_csv_metadata(content)
    if value.get("encoding") != encoding or value.get("delimiter") != delimiter:
        raise ConflictError("inspection 与 CSV 编码或分隔符不一致")
    row_count = value.get("row_count")
    if (
        isinstance(row_count, bool)
        or not isinstance(row_count, int)
        or not 0 <= row_count <= MAX_ROWS
    ):
        raise ValueError("inspection.row_count 非法")
    # This performs the strict, bounded nested inspection validation without
    # invoking a model or materialising any business value.
    map_csv_inspection(value)
    actual = inspect_five_quantity_csv(filename=filename, content=content)
    if not hmac.compare_digest(sha256_jcs(value), sha256_jcs(actual)):
        raise ConflictError("inspection 不是该 CSV 原件的确定性检查结果")
    canonical = json.loads(jcs_json(actual))
    if len(jcs_json(canonical).encode("utf-8")) > MAX_INSPECTION_BYTES:
        raise ValueError("inspection 超过安全大小限制")
    return canonical, content_hash, schema_fingerprint


def _validate_mapping_advice(
    value: Any,
    *,
    inspection: dict[str, Any],
) -> dict[str, Any]:
    if value is None:
        value = {
            "schema_version": "five-quantity-csv-mapping-advice-v1",
            "content_sha256": inspection["content_sha256"],
            "columns": [],
            "llm": {
                "attempted": False,
                "succeeded": False,
                "error_code": None,
                "output_sha256": None,
            },
        }
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "content_sha256",
        "columns",
        "llm",
    }:
        raise ValueError("mapping_advice 字段非法")
    if value["schema_version"] != "five-quantity-csv-mapping-advice-v1":
        raise ValueError("mapping_advice schema_version 不受支持")
    if not hmac.compare_digest(
        _sha256_text(value["content_sha256"], "mapping_advice.content_sha256"),
        inspection["content_sha256"],
    ):
        raise ConflictError("mapping_advice 与 CSV inspection 不一致")
    allowed_indexes = {
        int(item["source_index"]): item for item in inspection["columns"]
    }
    columns = value["columns"]
    if not isinstance(columns, list) or len(columns) > MAX_MAPPING_ENTRIES:
        raise ValueError("mapping_advice columns 非法")
    clean_columns: list[dict[str, Any]] = []
    seen: set[int] = set()
    for index, raw in enumerate(columns):
        if not isinstance(raw, dict) or set(raw) != {
            "source_index",
            "target_metric",
            "target_period",
            "source",
            "confidence",
            "status",
        }:
            raise ValueError(f"mapping_advice columns[{index}] 字段非法")
        source_index = raw["source_index"]
        if (
            isinstance(source_index, bool)
            or not isinstance(source_index, int)
            or source_index not in allowed_indexes
            or source_index in seen
        ):
            raise ValueError("mapping_advice source_index 非法或重复")
        metric = raw["target_metric"]
        period = raw["target_period"]
        if (metric is None) != (period is None):
            raise ValueError("mapping_advice 目标必须完整或同时为空")
        if metric is not None and (metric not in METRICS or period not in PERIOD_KEYS):
            raise ValueError("mapping_advice 目标不在五量白名单")
        source = raw["source"]
        if source not in {"deterministic", "rule", "approved_profile", "llm"}:
            raise ValueError("mapping_advice source 非法")
        confidence = raw["confidence"]
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
            or not 0 <= float(confidence) <= 1
        ):
            raise ValueError("mapping_advice confidence 非法")
        status = raw["status"]
        if status not in {"mapped", "needs_review", "unmapped", "blocked"}:
            raise ValueError("mapping_advice status 非法")
        seen.add(source_index)
        clean_columns.append(
            {
                "source_index": source_index,
                "target_metric": metric,
                "target_period": period,
                "source": source,
                "confidence": float(confidence),
                "status": status,
            }
        )
    llm = value["llm"]
    if not isinstance(llm, dict) or set(llm) != {
        "attempted",
        "succeeded",
        "error_code",
        "output_sha256",
    }:
        raise ValueError("mapping_advice llm 字段非法")
    if not isinstance(llm["attempted"], bool) or not isinstance(
        llm["succeeded"], bool
    ):
        raise ValueError("mapping_advice llm 状态非法")
    if llm["succeeded"] and not llm["attempted"]:
        raise ValueError("mapping_advice llm 成功状态非法")
    error_code = llm["error_code"]
    if error_code is not None and (
        not isinstance(error_code, str)
        or not error_code
        or len(error_code) > 128
    ):
        raise ValueError("mapping_advice llm error_code 非法")
    output_hash = llm["output_sha256"]
    if output_hash is not None:
        output_hash = _sha256_text(output_hash, "mapping_advice.llm.output_sha256")
    if llm["succeeded"] and output_hash is None:
        raise ValueError("mapping_advice llm 成功时必须包含 output_sha256")
    if llm["succeeded"] and error_code is not None:
        raise ValueError("mapping_advice llm 成功时 error_code 必须为空")
    if any(item["source"] == "llm" for item in clean_columns) and not llm[
        "succeeded"
    ]:
        raise ValueError("mapping_advice 声明模型建议但没有成功模型记录")
    canonical = {
        "schema_version": "five-quantity-csv-mapping-advice-v1",
        "content_sha256": inspection["content_sha256"],
        "columns": sorted(clean_columns, key=lambda item: item["source_index"]),
        "llm": {
            "attempted": llm["attempted"],
            "succeeded": llm["succeeded"],
            "error_code": error_code,
            "output_sha256": output_hash,
        },
    }
    if len(jcs_json(canonical).encode("utf-8")) > MAX_MAPPING_ADVICE_BYTES:
        raise ValueError("mapping_advice 超过安全大小限制")
    return canonical


def _validate_mapping_document(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "columns"}:
        raise ValueError("mapping profile 字段非法")
    if value.get("schema_version") != CSV_MAPPING_PROFILE_CONTRACT:
        raise ValueError("mapping profile schema_version 不受支持")
    columns = value.get("columns")
    if not isinstance(columns, list) or not 1 <= len(columns) <= MAX_MAPPING_ENTRIES:
        raise ValueError("mapping profile 必须包含 1-256 个批准字段")
    result: list[dict[str, Any]] = []
    seen_headers: set[str] = set()
    seen_targets: set[tuple[str, str, str | None]] = set()
    for index, raw in enumerate(columns):
        if not isinstance(raw, dict) or set(raw) != {
            "source_header",
            "metric",
            "scope",
            "shift",
            "unit",
        }:
            raise ValueError(f"mapping columns[{index}] 字段非法")
        header = _normalise_header(raw.get("source_header"))
        if header in seen_headers:
            raise ValueError("mapping profile 包含重复来源表头")
        metric = raw.get("metric")
        if metric not in METRICS:
            raise ValueError(f"mapping columns[{index}].metric 不在白名单")
        scope = raw.get("scope")
        shift = raw.get("shift")
        if scope not in _PROFILE_SCOPES:
            raise ValueError(f"mapping columns[{index}].scope 非法")
        if scope == "daily_total" and shift is not None:
            raise ValueError("日合计映射的 shift 必须为 null")
        if scope == "shift" and shift not in SHIFT_KEYS:
            raise ValueError("班次映射的 shift 不在白名单")
        if raw.get("unit") != UNITS[metric]:
            raise ValueError(f"mapping columns[{index}].unit 不是规范单位")
        target = (str(metric), str(scope), None if shift is None else str(shift))
        if target in seen_targets:
            raise ValueError("mapping profile 包含重复目标")
        seen_headers.add(header)
        seen_targets.add(target)
        result.append(
            {
                "source_header": header,
                "metric": metric,
                "scope": scope,
                "shift": shift,
                "unit": UNITS[metric],
            }
        )
    result.sort(
        key=lambda item: (
            item["source_header"],
            item["metric"],
            item["scope"],
            item["shift"] or "",
        )
    )
    return {
        "schema_version": CSV_MAPPING_PROFILE_CONTRACT,
        "columns": result,
    }


class FiveQuantityCsvPersistence:
    """Durable preview state and immutable human-approved mapping versions."""

    def __init__(
        self,
        repository: Any,
        *,
        identity: MineIdentity,
        evidence_directory: str | Path | None = None,
        audit_sink: _AuditSink | None = None,
    ) -> None:
        self.repository = repository
        self.identity = identity
        self._audit_sink = audit_sink
        self.evidence_root = self._resolve_evidence_root(evidence_directory)
        instance_material = "\n".join(
            (identity.mine_id, identity.operator_id, identity.system_id)
        ).encode("utf-8")
        instance_hash = hashlib.sha256(instance_material).hexdigest()
        mine_directory = "instance-" + instance_hash[:24]
        self.mine_evidence_directory = self.evidence_root / mine_directory
        self._ensure_private_directory(self.mine_evidence_directory)
        self._initialize()

    def _resolve_evidence_root(self, value: str | Path | None) -> Path:
        if value is None:
            repository_path = str(getattr(self.repository, "path", ":memory:"))
            state_directory = (
                Path("./data").resolve()
                if repository_path == ":memory:"
                else Path(repository_path).resolve().parent
            )
            candidate = state_directory / "five-quantity-preview-evidence"
        else:
            candidate = Path(value).expanduser()
        if candidate.is_symlink():
            raise ValueError("CSV preview evidence_directory 不能是符号链接")
        resolved = candidate.resolve()
        if resolved == Path(resolved.anchor):
            raise ValueError("拒绝把文件系统根目录设为 CSV preview evidence_directory")
        self._ensure_private_directory(resolved)
        return resolved

    @staticmethod
    def _ensure_private_directory(path: Path) -> None:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise ValueError("CSV preview evidence_directory 不安全")
        with suppress(OSError):
            os.chmod(path, 0o700)

    def _initialize(self) -> None:
        statements = (
            """CREATE TABLE IF NOT EXISTS fq_csv_mapping_profiles (
                profile_id TEXT PRIMARY KEY,
                mine_id TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                schema_fingerprint TEXT NOT NULL,
                profile_name TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                status TEXT NOT NULL CHECK(status IN ('active','retired')),
                mapping_json TEXT NOT NULL,
                mapping_sha256 TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                retired_by TEXT,
                retired_at TEXT,
                retirement_reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(
                    mine_id,operator_id,schema_fingerprint,profile_name,revision
                ),
                UNIQUE(profile_id,mine_id,operator_id,schema_fingerprint)
            )""",
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_fq_csv_profile_active_schema
                ON fq_csv_mapping_profiles(
                    mine_id,operator_id,schema_fingerprint,profile_name
                ) WHERE status='active'""",
            """CREATE TABLE IF NOT EXISTS fq_csv_previews (
                preview_id TEXT PRIMARY KEY,
                mine_id TEXT NOT NULL,
                operator_id TEXT NOT NULL,
                owner_actor TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                byte_size INTEGER NOT NULL CHECK(byte_size > 0),
                encoding TEXT NOT NULL,
                delimiter TEXT NOT NULL,
                schema_fingerprint TEXT NOT NULL,
                evidence_relpath TEXT NOT NULL,
                inspection_json TEXT NOT NULL,
                inspection_sha256 TEXT NOT NULL,
                mapping_advice_json TEXT NOT NULL,
                mapping_advice_sha256 TEXT NOT NULL,
                status TEXT NOT NULL CHECK(
                    status IN ('active','consumed','expired')
                ),
                revision INTEGER NOT NULL CHECK(revision >= 1),
                expires_at TEXT NOT NULL,
                mapping_profile_id TEXT,
                resulting_draft_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                consumed_at TEXT,
                expired_at TEXT,
                FOREIGN KEY(
                    mapping_profile_id,mine_id,operator_id,schema_fingerprint
                ) REFERENCES fq_csv_mapping_profiles(
                    profile_id,mine_id,operator_id,schema_fingerprint
                )
            )""",
            """CREATE INDEX IF NOT EXISTS idx_fq_csv_preview_owner_state
                ON fq_csv_previews(
                    mine_id,operator_id,owner_actor,status,expires_at
                )""",
            """CREATE INDEX IF NOT EXISTS idx_fq_csv_preview_content
                ON fq_csv_previews(mine_id,operator_id,content_sha256)""",
            """CREATE TRIGGER IF NOT EXISTS fq_csv_profiles_no_delete
                BEFORE DELETE ON fq_csv_mapping_profiles BEGIN
                    SELECT RAISE(ABORT, 'fq_csv_mapping_profiles is retained');
                END""",
            """CREATE TRIGGER IF NOT EXISTS fq_csv_profile_mapping_immutable
                BEFORE UPDATE OF profile_id,mine_id,operator_id,
                    schema_fingerprint,profile_name,revision,mapping_json,
                    mapping_sha256,approved_by,approved_at,created_at
                ON fq_csv_mapping_profiles BEGIN
                    SELECT RAISE(ABORT, 'approved CSV mapping is immutable');
                END""",
            """CREATE TRIGGER IF NOT EXISTS fq_csv_previews_no_delete
                BEFORE DELETE ON fq_csv_previews BEGIN
                    SELECT RAISE(ABORT, 'fq_csv_previews is retained');
                END""",
            """CREATE TRIGGER IF NOT EXISTS fq_csv_preview_evidence_immutable
                BEFORE UPDATE OF preview_id,mine_id,operator_id,owner_actor,
                    original_filename,content_sha256,byte_size,encoding,delimiter,
                    schema_fingerprint,evidence_relpath,inspection_json,
                    inspection_sha256,mapping_advice_json,
                    mapping_advice_sha256,expires_at,created_at
                ON fq_csv_previews BEGIN
                    SELECT RAISE(ABORT, 'CSV preview evidence is immutable');
                END""",
        )
        with self.repository._transaction() as db:
            for statement in statements:
                db.execute(statement)

    def _audit(
        self,
        db: Any,
        event_type: str,
        actor: str,
        details: dict[str, Any],
    ) -> None:
        if self._audit_sink is not None:
            self._audit_sink(db, event_type, actor, details)

    @staticmethod
    def _now(value: datetime | None) -> datetime:
        current = value or utc_now()
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("now 必须带时区")
        return current.astimezone(UTC)

    def _evidence_path(self, digest: str) -> Path:
        return self.mine_evidence_directory / f"{_sha256_text(digest, 'digest')}.csv"

    @staticmethod
    def _read_regular_file(path: Path) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or not 0 < info.st_size <= MAX_IMPORT_BYTES
            ):
                raise ConflictError("CSV preview 原件文件不安全")
            chunks: list[bytes] = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) != info.st_size:
                raise ConflictError("读取期间 CSV preview 原件发生变化")
            return content
        finally:
            os.close(descriptor)

    def _store_evidence(self, content: bytes, digest: str) -> str:
        path = self._evidence_path(digest)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            existing = self._read_regular_file(path)
            if len(existing) != len(content) or not hmac.compare_digest(
                hashlib.sha256(existing).hexdigest(), digest
            ):
                raise ConflictError("已有 CSV preview 原件摘要不一致") from None
        else:
            try:
                offset = 0
                while offset < len(content):
                    written = os.write(descriptor, content[offset:])
                    if written <= 0:
                        raise OSError("CSV preview 原件写入失败")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            with suppress(OSError):
                os.chmod(path, 0o600)
        return f"{self.mine_evidence_directory.name}/{digest}.csv"

    def _expire_due(self, db: Any, now: datetime) -> int:
        now_text = utc_text(now)
        rows = db.execute(
            """SELECT preview_id,revision FROM fq_csv_previews
               WHERE mine_id=? AND operator_id=? AND status='active'
                 AND expires_at<=? ORDER BY expires_at,preview_id""",
            (self.identity.mine_id, self.identity.operator_id, now_text),
        ).fetchall()
        for row in rows:
            revision = int(row["revision"]) + 1
            db.execute(
                """UPDATE fq_csv_previews SET status='expired',revision=?,
                       updated_at=?,expired_at=? WHERE preview_id=?""",
                (revision, now_text, now_text, row["preview_id"]),
            )
            self._audit(
                db,
                "five_quantity_csv_preview_expired",
                "system-preview-expiry",
                {
                    "preview_id": str(row["preview_id"]),
                    "revision": revision,
                },
            )
        return len(rows)

    @staticmethod
    def _decode_preview(row: Any) -> dict[str, Any]:
        return {
            "preview_id": str(row["preview_id"]),
            "mine_id": str(row["mine_id"]),
            "operator_id": str(row["operator_id"]),
            "owner_actor": str(row["owner_actor"]),
            "original_filename": str(row["original_filename"]),
            "content_sha256": str(row["content_sha256"]),
            "byte_size": int(row["byte_size"]),
            "encoding": str(row["encoding"]),
            "delimiter": str(row["delimiter"]),
            "schema_fingerprint": str(row["schema_fingerprint"]),
            "inspection": json.loads(str(row["inspection_json"])),
            "inspection_sha256": str(row["inspection_sha256"]),
            "mapping_advice": json.loads(str(row["mapping_advice_json"])),
            "mapping_advice_sha256": str(row["mapping_advice_sha256"]),
            "status": str(row["status"]),
            "revision": int(row["revision"]),
            "expires_at": str(row["expires_at"]),
            "mapping_profile_id": row["mapping_profile_id"],
            "resulting_draft_id": row["resulting_draft_id"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "consumed_at": row["consumed_at"],
            "expired_at": row["expired_at"],
        }

    def create_preview(
        self,
        *,
        original_filename: str,
        content: bytes,
        inspection: dict[str, Any],
        actor: str,
        mapping_advice: dict[str, Any] | None = None,
        ttl_seconds: int = DEFAULT_PREVIEW_TTL_SECONDS,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        filename = _safe_filename(original_filename)
        actor_id = _safe_text(actor, "actor", 128)
        if not isinstance(content, bytes) or not content:
            raise ImportContentError("CSV preview 原件不能为空")
        if len(content) > MAX_IMPORT_BYTES:
            raise ImportContentError("CSV preview 原件不能超过 20 MiB")
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not MIN_PREVIEW_TTL_SECONDS
            <= ttl_seconds
            <= MAX_PREVIEW_TTL_SECONDS
        ):
            raise ValueError("preview ttl 必须在 60-3600 秒之间")
        canonical, content_hash, schema_fingerprint = _validate_inspection(
            inspection,
            filename=filename,
            content=content,
        )
        canonical_advice = _validate_mapping_advice(
            mapping_advice,
            inspection=canonical,
        )
        evidence_relpath = self._store_evidence(content, content_hash)
        current = self._now(now)
        created_at = utc_text(current)
        expires_at = utc_text(current + timedelta(seconds=ttl_seconds))
        preview_id = str(uuid.uuid4())
        inspection_hash = sha256_jcs(canonical)
        mapping_advice_hash = sha256_jcs(canonical_advice)
        with self.repository._transaction() as db:
            self._expire_due(db, current)
            db.execute(
                """INSERT INTO fq_csv_previews(
                    preview_id,mine_id,operator_id,owner_actor,
                    original_filename,content_sha256,byte_size,encoding,delimiter,
                    schema_fingerprint,evidence_relpath,inspection_json,
                    inspection_sha256,mapping_advice_json,mapping_advice_sha256,
                    status,revision,expires_at,
                    created_at,updated_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active',1,?,?,?)""",
                (
                    preview_id,
                    self.identity.mine_id,
                    self.identity.operator_id,
                    actor_id,
                    filename,
                    content_hash,
                    len(content),
                    canonical["encoding"],
                    canonical["delimiter"],
                    schema_fingerprint,
                    evidence_relpath,
                    jcs_json(canonical),
                    inspection_hash,
                    jcs_json(canonical_advice),
                    mapping_advice_hash,
                    expires_at,
                    created_at,
                    created_at,
                ),
            )
            self._audit(
                db,
                "five_quantity_csv_preview_created",
                actor_id,
                {
                    "preview_id": preview_id,
                    "content_sha256": content_hash,
                    "byte_size": len(content),
                    "schema_fingerprint": schema_fingerprint,
                    "inspection_sha256": inspection_hash,
                    "mapping_advice_sha256": mapping_advice_hash,
                    "expires_at": expires_at,
                    "submission_enqueued": False,
                },
            )
            row = db.execute(
                "SELECT * FROM fq_csv_previews WHERE preview_id=?", (preview_id,)
            ).fetchone()
        assert row is not None
        return self._decode_preview(row)

    def get_preview(
        self,
        preview_id: str,
        *,
        actor: str,
        include_terminal: bool = False,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        actor_id = _safe_text(actor, "actor", 128)
        current = self._now(now)
        with self.repository._transaction() as db:
            self._expire_due(db, current)
            row = db.execute(
                """SELECT * FROM fq_csv_previews WHERE preview_id=?
                   AND mine_id=? AND operator_id=? AND owner_actor=?""",
                (
                    preview_id,
                    self.identity.mine_id,
                    self.identity.operator_id,
                    actor_id,
                ),
            ).fetchone()
        if row is None or (not include_terminal and row["status"] != "active"):
            raise NotFoundError("有效 CSV preview 不存在")
        return self._decode_preview(row)

    def read_preview_evidence(
        self,
        preview_id: str,
        *,
        actor: str,
        allow_consumed: bool = False,
        now: datetime | None = None,
    ) -> bytes:
        preview = self.get_preview(
            preview_id,
            actor=actor,
            include_terminal=allow_consumed,
            now=now,
        )
        allowed = {"active", "consumed"} if allow_consumed else {"active"}
        if preview["status"] not in allowed:
            raise ConflictError("CSV preview 原件已不可用于建稿")
        content = self._read_regular_file(
            self._evidence_path(str(preview["content_sha256"]))
        )
        actual_hash = hashlib.sha256(content).hexdigest()
        if len(content) != preview["byte_size"] or not hmac.compare_digest(
            actual_hash, preview["content_sha256"]
        ):
            raise ConflictError("CSV preview 原件完整性校验失败")
        return content

    def consume_preview(
        self,
        preview_id: str,
        *,
        expected_revision: int,
        expected_inspection_sha256: str,
        resulting_draft_id: str,
        actor: str,
        mapping_profile_id: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        actor_id = _safe_text(actor, "actor", 128)
        draft_id = _safe_identifier(resulting_draft_id, "resulting_draft_id")
        inspection_hash = _sha256_text(
            expected_inspection_sha256, "expected_inspection_sha256"
        )
        current = self._now(now)
        now_text = utc_text(current)
        with self.repository._transaction() as db:
            self._expire_due(db, current)
            row = db.execute(
                """SELECT * FROM fq_csv_previews WHERE preview_id=?
                   AND mine_id=? AND operator_id=? AND owner_actor=?""",
                (
                    preview_id,
                    self.identity.mine_id,
                    self.identity.operator_id,
                    actor_id,
                ),
            ).fetchone()
            if row is None:
                raise NotFoundError("CSV preview 不存在")
            if row["status"] == "consumed":
                if (
                    row["resulting_draft_id"] == draft_id
                    and hmac.compare_digest(
                        str(row["inspection_sha256"]), inspection_hash
                    )
                ):
                    return self._decode_preview(row)
                raise ConflictError("CSV preview 已被另一草稿消费")
            if row["status"] != "active":
                raise ConflictError("CSV preview 已失效")
            if int(row["revision"]) != expected_revision:
                raise ConflictError("CSV preview 修订号已变化")
            if not hmac.compare_digest(
                str(row["inspection_sha256"]), inspection_hash
            ):
                raise ConflictError("CSV preview inspection 摘要已变化")
            if mapping_profile_id is not None:
                profile = db.execute(
                    """SELECT 1 FROM fq_csv_mapping_profiles
                       WHERE profile_id=? AND mine_id=? AND operator_id=?
                         AND schema_fingerprint=? AND status='active'""",
                    (
                        mapping_profile_id,
                        self.identity.mine_id,
                        self.identity.operator_id,
                        row["schema_fingerprint"],
                    ),
                ).fetchone()
                if profile is None:
                    raise NotFoundError(
                        "该 CSV 整套表头没有可用的已批准 mapping profile"
                    )
            revision = expected_revision + 1
            db.execute(
                """UPDATE fq_csv_previews SET status='consumed',revision=?,
                       mapping_profile_id=?,resulting_draft_id=?,updated_at=?,
                       consumed_at=? WHERE preview_id=?""",
                (
                    revision,
                    mapping_profile_id,
                    draft_id,
                    now_text,
                    now_text,
                    preview_id,
                ),
            )
            self._audit(
                db,
                "five_quantity_csv_preview_consumed",
                actor_id,
                {
                    "preview_id": preview_id,
                    "content_sha256": str(row["content_sha256"]),
                    "inspection_sha256": inspection_hash,
                    "mapping_advice_sha256": str(
                        row["mapping_advice_sha256"]
                    ),
                    "schema_fingerprint": str(row["schema_fingerprint"]),
                    "mapping_profile_id": mapping_profile_id,
                    "resulting_draft_id": draft_id,
                    "revision": revision,
                    "submission_enqueued": False,
                },
            )
            updated = db.execute(
                "SELECT * FROM fq_csv_previews WHERE preview_id=?", (preview_id,)
            ).fetchone()
        assert updated is not None
        return self._decode_preview(updated)

    @staticmethod
    def _decode_profile(row: Any) -> dict[str, Any]:
        mapping = json.loads(str(row["mapping_json"]))
        profile_id = str(row["profile_id"])
        revision = int(row["revision"])
        return {
            "profile_id": profile_id,
            "mine_id": str(row["mine_id"]),
            "operator_id": str(row["operator_id"]),
            "schema_fingerprint": str(row["schema_fingerprint"]),
            "profile_name": str(row["profile_name"]),
            "revision": revision,
            "status": str(row["status"]),
            "mapping": mapping,
            "approved_mappings": [
                {
                    **item,
                    "profile_id": profile_id,
                    "profile_revision": revision,
                }
                for item in mapping["columns"]
            ],
            "mapping_sha256": str(row["mapping_sha256"]),
            "approved_by": str(row["approved_by"]),
            "approved_at": str(row["approved_at"]),
            "retired_by": row["retired_by"],
            "retired_at": row["retired_at"],
            "retirement_reason": row["retirement_reason"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def approve_mapping_profile(
        self,
        *,
        profile_name: str,
        schema_fingerprint: str,
        mapping: dict[str, Any],
        approved_by: str,
        human_approved: bool,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if human_approved is not True:
            raise ValueError("必须由企业人员明确批准 mapping profile")
        name = _safe_text(profile_name, "profile_name", 128)
        fingerprint = _sha256_text(schema_fingerprint, "schema_fingerprint")
        actor = _safe_text(approved_by, "approved_by", 128)
        canonical = _validate_mapping_document(mapping)
        mapping_hash = sha256_jcs(canonical)
        current = self._now(now)
        now_text = utc_text(current)
        with self.repository._transaction() as db:
            existing = db.execute(
                """SELECT * FROM fq_csv_mapping_profiles WHERE mine_id=?
                   AND operator_id=? AND schema_fingerprint=?
                   AND profile_name=? AND status='active'""",
                (
                    self.identity.mine_id,
                    self.identity.operator_id,
                    fingerprint,
                    name,
                ),
            ).fetchone()
            if existing is not None and hmac.compare_digest(
                str(existing["mapping_sha256"]), mapping_hash
            ):
                result = self._decode_profile(existing)
                result["duplicate"] = True
                return result
            maximum = db.execute(
                """SELECT MAX(revision) AS revision
                   FROM fq_csv_mapping_profiles WHERE mine_id=? AND operator_id=?
                     AND schema_fingerprint=? AND profile_name=?""",
                (
                    self.identity.mine_id,
                    self.identity.operator_id,
                    fingerprint,
                    name,
                ),
            ).fetchone()
            revision = (
                int(maximum["revision"]) + 1
                if maximum is not None and maximum["revision"] is not None
                else 1
            )
            if existing is not None:
                db.execute(
                    """UPDATE fq_csv_mapping_profiles SET status='retired',
                       retired_by=?,retired_at=?,retirement_reason='superseded',
                       updated_at=? WHERE profile_id=?""",
                    (actor, now_text, now_text, existing["profile_id"]),
                )
            profile_id = str(uuid.uuid4())
            db.execute(
                """INSERT INTO fq_csv_mapping_profiles(
                    profile_id,mine_id,operator_id,schema_fingerprint,
                    profile_name,revision,status,mapping_json,mapping_sha256,
                    approved_by,approved_at,created_at,updated_at
                ) VALUES (?,?,?,?,?,?,'active',?,?,?,?,?,?)""",
                (
                    profile_id,
                    self.identity.mine_id,
                    self.identity.operator_id,
                    fingerprint,
                    name,
                    revision,
                    jcs_json(canonical),
                    mapping_hash,
                    actor,
                    now_text,
                    now_text,
                    now_text,
                ),
            )
            self._audit(
                db,
                "five_quantity_csv_mapping_profile_approved",
                actor,
                {
                    "profile_id": profile_id,
                    "schema_fingerprint": fingerprint,
                    "revision": revision,
                    "mapping_sha256": mapping_hash,
                    "mapping_count": len(canonical["columns"]),
                    "human_approved": True,
                },
            )
            row = db.execute(
                "SELECT * FROM fq_csv_mapping_profiles WHERE profile_id=?",
                (profile_id,),
            ).fetchone()
        assert row is not None
        result = self._decode_profile(row)
        result["duplicate"] = False
        return result

    def list_mapping_profiles(
        self,
        *,
        schema_fingerprint: str,
        include_retired: bool = False,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        fingerprint = _sha256_text(schema_fingerprint, "schema_fingerprint")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 500
        ):
            raise ValueError("mapping profile limit 必须在 1-500 之间")
        with self.repository._read() as db:
            rows = db.execute(
                """SELECT * FROM fq_csv_mapping_profiles WHERE mine_id=?
                   AND operator_id=? AND schema_fingerprint=? """
                + ("" if include_retired else "AND status='active' ")
                + "ORDER BY profile_name,revision DESC LIMIT ?",
                (
                    self.identity.mine_id,
                    self.identity.operator_id,
                    fingerprint,
                    limit,
                ),
            ).fetchall()
        return [self._decode_profile(row) for row in rows]

    def expire_previews(self, *, now: datetime | None = None) -> int:
        current = self._now(now)
        with self.repository._transaction() as db:
            return self._expire_due(db, current)
