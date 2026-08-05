from __future__ import annotations

import re
import sqlite3
import time

from ..errors import SourceError
from ..models import RawBatch, SourceConfig

_READ_PREFIX = re.compile(r"^\s*(?:SELECT|WITH)\b", re.IGNORECASE)


def _authorize(action: int, _arg1: str, _arg2: str, _database: str, _trigger: str) -> int:
    denied = {
        sqlite3.SQLITE_ALTER_TABLE,
        sqlite3.SQLITE_ANALYZE,
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_TEMP_INDEX,
        sqlite3.SQLITE_CREATE_TEMP_TABLE,
        sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
        sqlite3.SQLITE_CREATE_TEMP_VIEW,
        sqlite3.SQLITE_CREATE_TRIGGER,
        sqlite3.SQLITE_CREATE_VIEW,
        sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_DETACH,
        sqlite3.SQLITE_DROP_INDEX,
        sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_DROP_TEMP_INDEX,
        sqlite3.SQLITE_DROP_TEMP_TABLE,
        sqlite3.SQLITE_DROP_TEMP_TRIGGER,
        sqlite3.SQLITE_DROP_TEMP_VIEW,
        sqlite3.SQLITE_DROP_TRIGGER,
        sqlite3.SQLITE_DROP_VIEW,
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_PRAGMA,
        sqlite3.SQLITE_REINDEX,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_UPDATE,
    }
    return sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK


def _validate_query(query: str) -> None:
    if not _READ_PREFIX.match(query):
        raise SourceError("SQLite query 只允许 SELECT/只读 WITH")
    stripped = query.strip()
    if ";" in stripped.rstrip(";"):
        raise SourceError("SQLite query 只允许一条语句")


def collect_sqlite_query(config: SourceConfig) -> tuple[RawBatch, ...]:
    assert config.database is not None and config.query is not None
    _validate_query(config.query)
    if not config.database.is_file():
        raise SourceError(f"SQLite 来源不存在：{config.database}")
    uri = f"{config.database.as_uri()}?mode=ro"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=config.timeout_seconds)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.set_authorizer(_authorize)
        deadline = time.monotonic() + config.timeout_seconds
        connection.set_progress_handler(
            lambda: 1 if time.monotonic() >= deadline else 0,
            1_000,
        )
        cursor = connection.execute(config.query)
        column_names = [item[0] for item in (cursor.description or ())]
        if any(not isinstance(name, str) or not name.strip() for name in column_names):
            raise SourceError("SQLite 查询返回了空列名")
        if len(set(column_names)) != len(column_names):
            raise SourceError("SQLite 查询返回了重复列名，请使用唯一 AS 别名")
        rows: list[dict[str, object]] = []
        for row in cursor:
            rows.append(dict(row))
            if len(rows) > config.max_records:
                raise SourceError("SQLite 来源记录数超过 max_records")
    except SourceError:
        raise
    except sqlite3.Error as exc:
        raise SourceError(f"SQLite 只读查询失败：{exc}") from exc
    finally:
        if connection is not None:
            connection.close()
    return (
        RawBatch(
            source_id=config.id,
            original_filename=config.database.name,
            records=tuple(rows),
        ),
    )
