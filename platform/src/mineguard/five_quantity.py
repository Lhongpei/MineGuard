"""Strict importer for the WPS/BIFF8 five-quantity collection workbook.

The importer deliberately stops at ingestion and deterministic quality checks.
It does not infer a mine identity from the workbook title, execute formulas, or
depend on the enterprise agent.  Formula cells are read only through the cached
value stored in the BIFF8 file.
"""

from __future__ import annotations

import base64
import binascii
from collections import Counter
from datetime import date, timedelta
from decimal import Decimal
from enum import StrEnum
import hashlib
import io
import math
from pathlib import PurePath
import re
import struct
from typing import Annotated, Literal

import olefile
from pydantic import AwareDatetime, Field, field_validator, model_validator
import xlrd

from .models import StrictModel


CalendarDate = date


MAX_ET_FILE_BYTES = 5 * 1024 * 1024
MAX_WORKBOOK_STREAM_BYTES = 10 * 1024 * 1024
MAX_BASE64_CHARACTERS = ((MAX_ET_FILE_BYTES + 2) // 3) * 4 + 16
MAX_WORKBOOK_SHEETS = 16
MAX_DATA_ROWS = 370
MAX_BIFF_RECORDS = 100_000
MAX_FORMULA_CELLS = 8_192
EXPECTED_COLUMN_COUNT = 18
OLE2_SIGNATURE = bytes.fromhex("D0CF11E0A1B11AE1")

_TOP_HEADERS = {
    0: "日期",
    1: "风量",
    2: "用工量",
    6: "用电量",
    10: "火工品量",
    14: "产量",
}
_SHIFT_HEADERS = ("零点班", "八点班", "四点班", "日统计")
_TITLE_PLACEHOLDER_RE = re.compile(
    r"(?:X{2,}|Ｘ{2,}|某煤矿|测试矿|示例|样例|模板)",
    re.IGNORECASE,
)
_DATE_TEXT_RE = re.compile(r"^(\d{4})[./-](\d{1,2})[./-](\d{1,2})$")
_EXPLOSIVE_PART_RE = re.compile(
    r"^(雷管|炸药)\s*[:：]\s*"
    r"(\d+(?:\.\d+)?)\s*"
    r"(?:枚|发|个|千克|公斤|kg)?$",
    re.IGNORECASE,
)


class FiveQuantityImportErrorCode(StrEnum):
    INVALID_BASE64 = "invalid_base64"
    FILE_TOO_SMALL = "file_too_small"
    FILE_TOO_LARGE = "file_too_large"
    HASH_MISMATCH = "hash_mismatch"
    NOT_OLE2 = "not_ole2"
    UNSAFE_ACTIVE_CONTENT = "unsafe_active_content"
    OLE_PARSE_FAILED = "ole_parse_failed"
    WORKBOOK_STREAM_MISSING = "workbook_stream_missing"
    WORKBOOK_STREAM_TOO_LARGE = "workbook_stream_too_large"
    WORKBOOK_PARSE_FAILED = "workbook_parse_failed"
    TOO_MANY_SHEETS = "too_many_sheets"
    NO_DATA_SHEET = "no_data_sheet"
    MULTIPLE_DATA_SHEETS = "multiple_data_sheets"
    INVALID_TABLE_SHAPE = "invalid_table_shape"
    INVALID_HEADER = "invalid_header"
    INVALID_TITLE = "invalid_title"
    INVALID_DATE_CELL = "invalid_date_cell"
    DUPLICATE_DATE = "duplicate_date"
    DATES_NOT_ASCENDING = "dates_not_ascending"
    MULTIPLE_CALENDAR_MONTHS = "multiple_calendar_months"
    BIFF_STRUCTURE_LIMIT_EXCEEDED = "biff_structure_limit_exceeded"
    INVALID_NUMERIC_CELL = "invalid_numeric_cell"
    INVALID_EXPLOSIVES_CELL = "invalid_explosives_cell"


class ReportMonthSource(StrEnum):
    EXPLICIT_REQUEST = "explicit_request"
    INFERRED_FROM_WORKBOOK_DATES = "inferred_from_workbook_dates"


class FiveQuantityImportFailure(ValueError):
    """Stable, caller-safe failure raised for an invalid import document."""

    def __init__(
        self,
        code: FiveQuantityImportErrorCode,
        message: str,
    ) -> None:
        self.code = code
        self.public_message = message
        super().__init__(f"{code.value}: {message}")


class FiveQuantitySourceMetadata(StrictModel):
    source_id: Annotated[str, Field(min_length=1, max_length=200)]
    filename: Annotated[str, Field(min_length=1, max_length=255)]
    received_at: AwareDatetime
    submitted_by: Annotated[str | None, Field(max_length=200)] = None
    origin_system: Annotated[str | None, Field(max_length=200)] = None
    expected_sha256: Annotated[
        str | None,
        Field(pattern=r"^[0-9a-fA-F]{64}$"),
    ] = None

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        if PurePath(value).name != value or "\x00" in value:
            raise ValueError("filename must be a plain file name")
        return value


class FiveQuantityUnits(StrictModel):
    """Declared units; ``None`` is an explicit declaration of unknown."""

    ventilation: Annotated[str | None, Field(max_length=50)] = None
    labor: Annotated[str | None, Field(max_length=50)] = None
    electricity: Annotated[str | None, Field(max_length=50)] = None
    detonators: Annotated[str | None, Field(max_length=50)] = None
    explosives: Annotated[str | None, Field(max_length=50)] = None
    production: Annotated[str | None, Field(max_length=50)] = None


class FiveQuantityValidationParameters(StrictModel):
    labor_sum_tolerance: Annotated[float, Field(ge=0, le=1e9)] = 0.0
    electricity_sum_tolerance: Annotated[
        float,
        Field(ge=0, le=1e12),
    ] = 0.01
    detonator_sum_tolerance: Annotated[
        float,
        Field(ge=0, le=1e9),
    ] = 0.0
    explosive_sum_tolerance: Annotated[
        float,
        Field(ge=0, le=1e12),
    ] = 0.001
    production_sum_tolerance: Annotated[
        float,
        Field(ge=0, le=1e12),
    ] = 0.01


class FiveQuantityImportRequest(StrictModel):
    """An import request with one, and only one, content representation."""

    mine_id: Annotated[str, Field(min_length=1, max_length=200)]
    source: FiveQuantitySourceMetadata
    closed_through: CalendarDate
    report_month: Annotated[
        str | None,
        Field(pattern=r"^\d{4}-(?:0[1-9]|1[0-2])$"),
    ] = None
    units: FiveQuantityUnits = Field(default_factory=FiveQuantityUnits)
    validation: FiveQuantityValidationParameters = Field(
        default_factory=FiveQuantityValidationParameters
    )
    content_bytes: Annotated[
        bytes | None,
        Field(max_length=MAX_ET_FILE_BYTES),
    ] = None
    content_base64: Annotated[
        str | None,
        Field(max_length=MAX_BASE64_CHARACTERS),
    ] = None

    @field_validator("content_bytes", mode="before")
    @classmethod
    def require_real_bytes(cls, value: object) -> object:
        if value is not None and not isinstance(value, bytes):
            raise ValueError("content_bytes must be bytes")
        return value

    @field_validator("content_base64", mode="before")
    @classmethod
    def require_base64_text(cls, value: object) -> object:
        if value is not None and not isinstance(value, str):
            raise ValueError("content_base64 must be text")
        return value

    @field_validator("report_month")
    @classmethod
    def require_calendar_report_month(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            date.fromisoformat(f"{value}-01")
        except ValueError as exc:
            raise ValueError(
                "report_month must identify a valid calendar month"
            ) from exc
        return value

    @model_validator(mode="after")
    def require_exactly_one_content(self) -> "FiveQuantityImportRequest":
        supplied = sum(
            item is not None
            for item in (self.content_bytes, self.content_base64)
        )
        if supplied != 1:
            raise ValueError(
                "exactly one of content_bytes or content_base64 is required"
            )
        return self


RawCellValue = str | float | int | bool | None


class RawCellKind(StrEnum):
    EMPTY = "empty"
    TEXT = "text"
    NUMBER = "number"
    DATE = "date"
    BOOLEAN = "boolean"
    ERROR = "error"
    BLANK = "blank"
    UNKNOWN = "unknown"


class FiveQuantityRawCell(StrictModel):
    column_index: Annotated[int, Field(ge=1, le=EXPECTED_COLUMN_COUNT)]
    cell_kind: RawCellKind
    raw_value: RawCellValue
    is_blank: bool
    is_formula: bool
    formula_cached_value: RawCellValue = None


class ShiftNumericValues(StrictModel):
    zero_shift: float | None
    eight_shift: float | None
    four_shift: float | None
    daily_total: float | None


class ExplosiveUsage(StrictModel):
    detonators: float | None
    explosives: float | None
    raw_text: str | None
    is_blank: bool


class ShiftExplosiveValues(StrictModel):
    zero_shift: ExplosiveUsage
    eight_shift: ExplosiveUsage
    four_shift: ExplosiveUsage
    daily_total: ExplosiveUsage


class ReconciliationStatus(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"
    INCOMPLETE = "incomplete"


class DailyReconciliation(StrictModel):
    metric: Literal[
        "labor",
        "electricity",
        "detonators",
        "explosives",
        "production",
    ]
    shift_sum: float | None
    daily_total: float | None
    difference_daily_minus_shifts: float | None
    tolerance: Annotated[float, Field(ge=0)]
    status: ReconciliationStatus


class FiveQuantityDay(StrictModel):
    date: CalendarDate
    source_row_number: Annotated[int, Field(ge=4)]
    is_closed: bool
    ventilation: float | None
    labor: ShiftNumericValues
    electricity: ShiftNumericValues
    explosives: ShiftExplosiveValues
    production: ShiftNumericValues
    reconciliations: list[DailyReconciliation]
    raw_cells: Annotated[
        list[FiveQuantityRawCell],
        Field(min_length=EXPECTED_COLUMN_COUNT, max_length=EXPECTED_COLUMN_COUNT),
    ]


class FindingSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class FiveQuantityQualityFinding(StrictModel):
    code: str
    severity: FindingSeverity
    message: str
    date: CalendarDate | None = None
    source_row_number: int | None = None
    metric: str | None = None
    observed: float | int | str | None = None
    expected: float | int | str | None = None
    difference: float | None = None


class FiveQuantityQualitySummary(StrictModel):
    closed_day_count: Annotated[int, Field(ge=0)]
    open_day_count: Annotated[int, Field(ge=0)]
    error_count: Annotated[int, Field(ge=0)]
    warning_count: Annotated[int, Field(ge=0)]
    info_count: Annotated[int, Field(ge=0)]
    findings: list[FiveQuantityQualityFinding]


class FiveQuantityImportResult(StrictModel):
    schema_version: Literal["five_quantity_import.v1"] = (
        "five_quantity_import.v1"
    )
    mine_id: str
    identity_binding: Literal["explicit_request_mine_id"] = (
        "explicit_request_mine_id"
    )
    source: FiveQuantitySourceMetadata
    source_title: str
    source_sha256: str
    sheet_name: str
    report_month: Annotated[
        str,
        Field(pattern=r"^\d{4}-(?:0[1-9]|1[0-2])$"),
    ]
    report_month_source: ReportMonthSource
    closed_through: CalendarDate
    validation: FiveQuantityValidationParameters = Field(
        default_factory=FiveQuantityValidationParameters
    )
    units: FiveQuantityUnits
    unknown_unit_fields: list[str]
    formula_cell_count: Annotated[int, Field(ge=0)]
    days: list[FiveQuantityDay]
    quality: FiveQuantityQualitySummary

    @model_validator(mode="before")
    @classmethod
    def infer_legacy_report_month(cls, value: object) -> object:
        if not isinstance(value, dict) or "report_month" in value:
            return value
        days = value.get("days")
        if not isinstance(days, list) or not days:
            return value
        first_day = days[0]
        first_date = (
            first_day.date
            if isinstance(first_day, FiveQuantityDay)
            else first_day.get("date")
            if isinstance(first_day, dict)
            else None
        )
        if not isinstance(first_date, date):
            return value
        enriched = dict(value)
        enriched["report_month"] = first_date.strftime("%Y-%m")
        enriched["report_month_source"] = (
            ReportMonthSource.INFERRED_FROM_WORKBOOK_DATES
        )
        return enriched


def import_five_quantity_et(
    request: FiveQuantityImportRequest,
) -> FiveQuantityImportResult:
    """Parse one WPS ``.et`` BIFF8 workbook and run deterministic checks."""

    content = _request_content(request)
    digest = hashlib.sha256(content).hexdigest()
    if (
        request.source.expected_sha256 is not None
        and digest != request.source.expected_sha256.lower()
    ):
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.HASH_MISMATCH,
            "文件 SHA-256 与来源元数据不一致",
        )

    workbook_stream, formula_coordinates = _inspect_ole2(content)
    del workbook_stream  # The inspection read is intentionally bounded.
    book = _open_workbook(content)
    try:
        if book.nsheets > MAX_WORKBOOK_SHEETS:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.TOO_MANY_SHEETS,
                f"工作表数量不得超过 {MAX_WORKBOOK_SHEETS}",
            )
        populated = [
            (index, book.sheet_by_index(index))
            for index in range(book.nsheets)
            if _sheet_is_populated(book.sheet_by_index(index))
        ]
        if not populated:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.NO_DATA_SHEET,
                "工作簿没有非空数据表",
            )
        if len(populated) != 1:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.MULTIPLE_DATA_SHEETS,
                "工作簿必须且只能包含一个非空数据表",
            )
        sheet_index, sheet = populated[0]
        title = _validate_template(sheet)
        sheet_formula_coordinates = formula_coordinates.get(
            sheet_index,
            set(),
        )
        days = _parse_days(
            sheet,
            book.datemode,
            request.closed_through,
            sheet_formula_coordinates,
            request.validation,
        )
        report_month, report_month_source = _resolve_report_month(
            request.report_month,
            days,
        )
    finally:
        book.release_resources()

    findings = _quality_findings(
        days=days,
        title=title,
        report_month=report_month,
        closed_through=request.closed_through,
        units=request.units,
        formula_cell_count=len(sheet_formula_coordinates),
    )
    counts = Counter(finding.severity for finding in findings)
    unknown_units = [
        name
        for name, value in request.units.model_dump().items()
        if value is None
    ]

    return FiveQuantityImportResult(
        mine_id=request.mine_id,
        source=request.source,
        source_title=title,
        source_sha256=digest,
        sheet_name=sheet.name,
        report_month=report_month,
        report_month_source=report_month_source,
        closed_through=request.closed_through,
        validation=request.validation,
        units=request.units,
        unknown_unit_fields=unknown_units,
        formula_cell_count=len(sheet_formula_coordinates),
        days=days,
        quality=FiveQuantityQualitySummary(
            closed_day_count=sum(day.is_closed for day in days),
            open_day_count=sum(not day.is_closed for day in days),
            error_count=counts[FindingSeverity.ERROR],
            warning_count=counts[FindingSeverity.WARNING],
            info_count=counts[FindingSeverity.INFO],
            findings=findings,
        ),
    )


def _resolve_report_month(
    requested_report_month: str | None,
    days: list[FiveQuantityDay],
) -> tuple[str, ReportMonthSource]:
    if not days:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_TABLE_SHAPE,
            "五量月报至少需要一个明确的日期行",
        )
    if requested_report_month is None:
        report_month_start = days[0].date.replace(day=1)
        source = ReportMonthSource.INFERRED_FROM_WORKBOOK_DATES
    else:
        report_month_start = date.fromisoformat(
            f"{requested_report_month}-01"
        )
        source = ReportMonthSource.EXPLICIT_REQUEST

    month_key = (report_month_start.year, report_month_start.month)
    if len(days) > 31 or any(
        (day.date.year, day.date.month) != month_key for day in days
    ):
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.MULTIPLE_CALENDAR_MONTHS,
            "表内所有日期必须属于同一个 report_month",
        )
    return report_month_start.strftime("%Y-%m"), source


def _report_month_bounds(report_month: str) -> tuple[date, date]:
    start = date.fromisoformat(f"{report_month}-01")
    if start.month == 12:
        following_month = date(start.year + 1, 1, 1)
    else:
        following_month = date(start.year, start.month + 1, 1)
    return start, following_month - timedelta(days=1)


def _request_content(request: FiveQuantityImportRequest) -> bytes:
    if request.content_bytes is not None:
        content = request.content_bytes
    else:
        assert request.content_base64 is not None
        try:
            content = base64.b64decode(
                request.content_base64,
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.INVALID_BASE64,
                "content_base64 不是规范的 Base64",
            ) from exc
    if len(content) < len(OLE2_SIGNATURE):
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.FILE_TOO_SMALL,
            "文件过小，不能构成 OLE2 工作簿",
        )
    if len(content) > MAX_ET_FILE_BYTES:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.FILE_TOO_LARGE,
            f"文件不得超过 {MAX_ET_FILE_BYTES} 字节",
        )
    return content


def _inspect_ole2(
    content: bytes,
) -> tuple[bytes, dict[int, set[tuple[int, int]]]]:
    if not content.startswith(OLE2_SIGNATURE):
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.NOT_OLE2,
            "文件不是 OLE2/BIFF8 工作簿",
        )
    try:
        ole = olefile.OleFileIO(
            io.BytesIO(content),
            raise_defects=olefile.DEFECT_INCORRECT,
        )
    except (OSError, IOError, ValueError) as exc:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.OLE_PARSE_FAILED,
            "OLE2 容器损坏或不受支持",
        ) from exc
    try:
        paths = ole.listdir(streams=True, storages=True)
        if len(paths) > 32:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.UNSAFE_ACTIVE_CONTENT,
                "工作簿包含过多 OLE 对象或流",
            )
        folded_parts = {
            part.casefold()
            for path in paths
            for part in path
        }
        unsafe_parts = {
            "objectpool",
            "embeddings",
            "ole10native",
            "package",
            "encryptedpackage",
            "encryptioninfo",
        }
        if (
            "vba" in folded_parts
            or "_vba_project_cur" in folded_parts
            or any("macros" in part for part in folded_parts)
            or any(part in unsafe_parts for part in folded_parts)
            or any(len(path) > 1 for path in paths)
        ):
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.UNSAFE_ACTIVE_CONTENT,
                "工作簿包含不允许导入的宏、嵌入对象或活动内容",
            )
        stream_name = next(
            (
                name
                for name in ("Workbook", "Book")
                if ole.exists(name) and ole.get_type(name) == olefile.STGTY_STREAM
            ),
            None,
        )
        if stream_name is None:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.WORKBOOK_STREAM_MISSING,
                "OLE2 容器缺少 Workbook 流",
            )
        stream_size = ole.get_size(stream_name)
        if stream_size > MAX_WORKBOOK_STREAM_BYTES:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.WORKBOOK_STREAM_TOO_LARGE,
                "Workbook 流超过安全上限",
            )
        workbook_stream = ole.openstream(stream_name).read(
            MAX_WORKBOOK_STREAM_BYTES + 1
        )
        if len(workbook_stream) > MAX_WORKBOOK_STREAM_BYTES:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.WORKBOOK_STREAM_TOO_LARGE,
                "Workbook 流超过安全上限",
            )
        if _biff_global_contains_record(workbook_stream, 0x002F):
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.UNSAFE_ACTIVE_CONTENT,
                "不允许导入加密工作簿",
            )
    except FiveQuantityImportFailure:
        raise
    except (OSError, IOError, ValueError) as exc:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.OLE_PARSE_FAILED,
            "读取 OLE2 容器失败",
        ) from exc
    finally:
        ole.close()
    return workbook_stream, _formula_coordinates_by_sheet(workbook_stream)


def _biff_global_contains_record(
    workbook_stream: bytes,
    target_record_id: int,
) -> bool:
    """Inspect the bounded BIFF global stream without evaluating content."""

    position = 0
    record_budget = 1_000_000
    while position + 4 <= len(workbook_stream) and record_budget:
        record_budget -= 1
        record_id, record_length = struct.unpack_from(
            "<HH",
            workbook_stream,
            position,
        )
        record_end = position + 4 + record_length
        if record_end > len(workbook_stream):
            return False
        if record_id == target_record_id:
            return True
        position = record_end
        if record_id == 0x000A:
            return False
    return False


def _formula_coordinates_by_sheet(
    workbook_stream: bytes,
) -> dict[int, set[tuple[int, int]]]:
    """Return formula coordinates without evaluating any BIFF expression."""

    sheet_offsets: list[int] = []
    position = 0
    length = len(workbook_stream)
    global_record_count = 0
    while position + 4 <= length:
        global_record_count += 1
        if global_record_count > MAX_BIFF_RECORDS:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.BIFF_STRUCTURE_LIMIT_EXCEEDED,
                "BIFF 记录数量超过安全上限",
            )
        record_id, record_length = struct.unpack_from(
            "<HH",
            workbook_stream,
            position,
        )
        record_end = position + 4 + record_length
        if record_end > length:
            break
        if record_id == 0x0085 and record_length >= 4:  # BOUNDSHEET
            sheet_offsets.append(
                struct.unpack_from("<I", workbook_stream, position + 4)[0]
            )
            if len(sheet_offsets) > MAX_WORKBOOK_SHEETS:
                raise FiveQuantityImportFailure(
                    FiveQuantityImportErrorCode.TOO_MANY_SHEETS,
                    f"工作表数量不得超过 {MAX_WORKBOOK_SHEETS}",
                )
        position = record_end
        if record_id == 0x000A:  # EOF of workbook globals
            break

    if len(set(sheet_offsets)) != len(sheet_offsets) or any(
        offset + 4 > length for offset in sheet_offsets
    ):
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.WORKBOOK_PARSE_FAILED,
            "BIFF 工作表目录损坏或不受支持",
        )

    # Scan each physical sheet segment once.  The BOUNDSHEET order is the tab
    # order and need not equal physical stream order, so preserve its original
    # index while sorting offsets.  This keeps work linear in stream size even
    # for hostile directory records.
    result: dict[int, set[tuple[int, int]]] = {
        index: set() for index in range(len(sheet_offsets))
    }
    physical_sheets = sorted(
        (offset, index) for index, offset in enumerate(sheet_offsets)
    )
    sheet_record_count = 0
    formula_cell_count = 0
    for physical_index, (offset, index) in enumerate(physical_sheets):
        coordinates: set[tuple[int, int]] = set()
        position = offset
        segment_end = (
            physical_sheets[physical_index + 1][0]
            if physical_index + 1 < len(physical_sheets)
            else length
        )
        first_record = True
        while position + 4 <= segment_end:
            sheet_record_count += 1
            if sheet_record_count > MAX_BIFF_RECORDS:
                raise FiveQuantityImportFailure(
                    FiveQuantityImportErrorCode.BIFF_STRUCTURE_LIMIT_EXCEEDED,
                    "BIFF 记录数量超过安全上限",
                )
            record_id, record_length = struct.unpack_from(
                "<HH",
                workbook_stream,
                position,
            )
            record_end = position + 4 + record_length
            if record_end > segment_end:
                raise FiveQuantityImportFailure(
                    FiveQuantityImportErrorCode.WORKBOOK_PARSE_FAILED,
                    "BIFF 工作表记录边界损坏",
                )
            if first_record:
                first_record = False
                if record_id != 0x0809:  # BIFF8 BOF
                    raise FiveQuantityImportFailure(
                        FiveQuantityImportErrorCode.WORKBOOK_PARSE_FAILED,
                        "BIFF 工作表起始记录损坏或不是 BIFF8",
                    )
            if record_id == 0x0006 and record_length >= 6:  # FORMULA
                row_index, column_index = struct.unpack_from(
                    "<HH",
                    workbook_stream,
                    position + 4,
                )
                coordinates.add((row_index, column_index))
                formula_cell_count += 1
                if formula_cell_count > MAX_FORMULA_CELLS:
                    raise FiveQuantityImportFailure(
                        FiveQuantityImportErrorCode.BIFF_STRUCTURE_LIMIT_EXCEEDED,
                        "公式单元格数量超过安全上限",
                    )
            position = record_end
            if record_id == 0x000A:  # EOF of this sheet substream
                break
        result[index] = coordinates
    return result


def _open_workbook(content: bytes) -> xlrd.book.Book:
    try:
        return xlrd.open_workbook(
            file_contents=content,
            on_demand=True,
            formatting_info=False,
        )
    except (xlrd.XLRDError, OSError, ValueError, IndexError) as exc:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.WORKBOOK_PARSE_FAILED,
            "BIFF8 工作簿损坏或不受支持",
        ) from exc


def _sheet_is_populated(sheet: xlrd.sheet.Sheet) -> bool:
    return sheet.nrows > 0 and sheet.ncols > 0


def _validate_template(sheet: xlrd.sheet.Sheet) -> str:
    if (
        sheet.ncols != EXPECTED_COLUMN_COUNT
        or sheet.nrows < 4
        or sheet.nrows > MAX_DATA_ROWS + 3
    ):
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_TABLE_SHAPE,
            "五量表必须为 18 列、3 行复合表头且数据行不超过安全上限",
        )
    title = _normalized_text(sheet.cell_value(0, 0))
    if not title:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_TITLE,
            "首行标题不能为空",
        )
    for column_index, expected in _TOP_HEADERS.items():
        if _normalized_text(sheet.cell_value(1, column_index)) != expected:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.INVALID_HEADER,
                f"第 2 行第 {column_index + 1} 列表头必须为“{expected}”",
            )
    for group_start in (2, 6, 10, 14):
        for offset, expected in enumerate(_SHIFT_HEADERS):
            column_index = group_start + offset
            if _normalized_text(sheet.cell_value(2, column_index)) != expected:
                raise FiveQuantityImportFailure(
                    FiveQuantityImportErrorCode.INVALID_HEADER,
                    f"第 3 行第 {column_index + 1} 列表头必须为“{expected}”",
                )
    return title


def _normalized_text(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", "", value)


def _parse_days(
    sheet: xlrd.sheet.Sheet,
    datemode: int,
    closed_through: date,
    formula_coordinates: set[tuple[int, int]],
    validation: FiveQuantityValidationParameters,
) -> list[FiveQuantityDay]:
    days: list[FiveQuantityDay] = []
    dates: list[date] = []
    for row_index in range(3, sheet.nrows):
        raw_cells = [
            _raw_cell(
                sheet.cell(row_index, column_index),
                column_index,
                (row_index, column_index) in formula_coordinates,
            )
            for column_index in range(EXPECTED_COLUMN_COUNT)
        ]
        observed_date = _parse_date_cell(
            sheet.cell(row_index, 0),
            datemode,
            row_index,
        )
        if observed_date in dates:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.DUPLICATE_DATE,
                f"第 {row_index + 1} 行日期重复",
            )
        if dates and observed_date <= dates[-1]:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.DATES_NOT_ASCENDING,
                f"第 {row_index + 1} 行日期未严格递增",
            )
        dates.append(observed_date)

        ventilation = _numeric_cell(sheet, row_index, 1, "风量")
        labor = _numeric_group(sheet, row_index, 2, "用工量")
        electricity = _numeric_group(sheet, row_index, 6, "用电量")
        explosives = _explosive_group(sheet, row_index, 10)
        production = _numeric_group(sheet, row_index, 14, "产量")

        reconciliations = [
            _reconcile_numeric(
                "labor",
                labor,
                validation.labor_sum_tolerance,
            ),
            _reconcile_numeric(
                "electricity",
                electricity,
                validation.electricity_sum_tolerance,
            ),
            _reconcile_explosives(
                "detonators",
                explosives,
                validation.detonator_sum_tolerance,
            ),
            _reconcile_explosives(
                "explosives",
                explosives,
                validation.explosive_sum_tolerance,
            ),
            _reconcile_numeric(
                "production",
                production,
                validation.production_sum_tolerance,
            ),
        ]
        days.append(
            FiveQuantityDay(
                date=observed_date,
                source_row_number=row_index + 1,
                is_closed=observed_date <= closed_through,
                ventilation=ventilation,
                labor=labor,
                electricity=electricity,
                explosives=explosives,
                production=production,
                reconciliations=reconciliations,
                raw_cells=raw_cells,
            )
        )
    return days


def _parse_date_cell(
    cell: xlrd.sheet.Cell,
    datemode: int,
    row_index: int,
) -> date:
    try:
        if cell.ctype == xlrd.XL_CELL_DATE:
            return xlrd.xldate_as_datetime(cell.value, datemode).date()
        if cell.ctype == xlrd.XL_CELL_NUMBER:
            return xlrd.xldate_as_datetime(cell.value, datemode).date()
        if cell.ctype == xlrd.XL_CELL_TEXT:
            match = _DATE_TEXT_RE.fullmatch(cell.value.strip())
            if match is not None:
                return date(*(int(part) for part in match.groups()))
    except (ValueError, OverflowError, xlrd.XLDateError) as exc:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_DATE_CELL,
            f"第 {row_index + 1} 行日期无效",
        ) from exc
    raise FiveQuantityImportFailure(
        FiveQuantityImportErrorCode.INVALID_DATE_CELL,
        f"第 {row_index + 1} 行日期必须为明确的年月日",
    )


def _numeric_group(
    sheet: xlrd.sheet.Sheet,
    row_index: int,
    start_column: int,
    metric_name: str,
) -> ShiftNumericValues:
    values = [
        _numeric_cell(
            sheet,
            row_index,
            start_column + offset,
            metric_name,
        )
        for offset in range(4)
    ]
    return ShiftNumericValues(
        zero_shift=values[0],
        eight_shift=values[1],
        four_shift=values[2],
        daily_total=values[3],
    )


def _numeric_cell(
    sheet: xlrd.sheet.Sheet,
    row_index: int,
    column_index: int,
    metric_name: str,
) -> float | None:
    cell = sheet.cell(row_index, column_index)
    if cell.ctype in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK):
        return None
    if cell.ctype != xlrd.XL_CELL_NUMBER:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_NUMERIC_CELL,
            f"第 {row_index + 1} 行第 {column_index + 1} 列"
            f"“{metric_name}”必须为数值或空白",
        )
    value = float(cell.value)
    if not math.isfinite(value) or value < 0 or value > 1e15:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_NUMERIC_CELL,
            f"第 {row_index + 1} 行第 {column_index + 1} 列"
            f"“{metric_name}”超出允许范围",
        )
    return value


def _explosive_group(
    sheet: xlrd.sheet.Sheet,
    row_index: int,
    start_column: int,
) -> ShiftExplosiveValues:
    values = [
        _explosive_cell(sheet, row_index, start_column + offset)
        for offset in range(4)
    ]
    return ShiftExplosiveValues(
        zero_shift=values[0],
        eight_shift=values[1],
        four_shift=values[2],
        daily_total=values[3],
    )


def _explosive_cell(
    sheet: xlrd.sheet.Sheet,
    row_index: int,
    column_index: int,
) -> ExplosiveUsage:
    cell = sheet.cell(row_index, column_index)
    if cell.ctype in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK):
        return ExplosiveUsage(
            detonators=None,
            explosives=None,
            raw_text=None,
            is_blank=True,
        )
    if cell.ctype != xlrd.XL_CELL_TEXT:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_EXPLOSIVES_CELL,
            f"第 {row_index + 1} 行第 {column_index + 1} 列"
            "火工品必须同时明确“雷管”和“炸药”",
        )
    raw_text = cell.value
    parts = [
        part.strip()
        for part in re.split(r"[\r\n;；]+", raw_text)
        if part.strip()
    ]
    parsed: dict[str, float] = {}
    for part in parts:
        match = _EXPLOSIVE_PART_RE.fullmatch(part)
        if match is None:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.INVALID_EXPLOSIVES_CELL,
                f"第 {row_index + 1} 行第 {column_index + 1} 列"
                "火工品格式无法解析",
            )
        label, number = match.group(1), match.group(2)
        key = "detonators" if label == "雷管" else "explosives"
        if key in parsed:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.INVALID_EXPLOSIVES_CELL,
                f"第 {row_index + 1} 行第 {column_index + 1} 列"
                "火工品字段重复",
            )
        try:
            value = float(number)
        except (OverflowError, ValueError) as exc:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.INVALID_EXPLOSIVES_CELL,
                f"第 {row_index + 1} 行第 {column_index + 1} 列"
                "火工品数值超出允许范围",
            ) from exc
        if not math.isfinite(value) or value > 1e15:
            raise FiveQuantityImportFailure(
                FiveQuantityImportErrorCode.INVALID_EXPLOSIVES_CELL,
                f"第 {row_index + 1} 行第 {column_index + 1} 列"
                "火工品数值超出允许范围",
            )
        parsed[key] = value
    if set(parsed) != {"detonators", "explosives"}:
        raise FiveQuantityImportFailure(
            FiveQuantityImportErrorCode.INVALID_EXPLOSIVES_CELL,
            f"第 {row_index + 1} 行第 {column_index + 1} 列"
            "火工品必须同时明确“雷管”和“炸药”",
        )
    return ExplosiveUsage(
        detonators=parsed["detonators"],
        explosives=parsed["explosives"],
        raw_text=raw_text,
        is_blank=False,
    )


def _reconcile_numeric(
    metric: Literal["labor", "electricity", "production"],
    values: ShiftNumericValues,
    tolerance: float,
) -> DailyReconciliation:
    shifts = (values.zero_shift, values.eight_shift, values.four_shift)
    if values.daily_total is None or any(value is None for value in shifts):
        return DailyReconciliation(
            metric=metric,
            shift_sum=None,
            daily_total=values.daily_total,
            difference_daily_minus_shifts=None,
            tolerance=tolerance,
            status=ReconciliationStatus.INCOMPLETE,
        )
    shift_sum, difference = _decimal_reconciliation(
        values.daily_total,
        tuple(value for value in shifts if value is not None),
    )
    return DailyReconciliation(
        metric=metric,
        shift_sum=shift_sum,
        daily_total=values.daily_total,
        difference_daily_minus_shifts=difference,
        tolerance=tolerance,
        status=(
            ReconciliationStatus.MATCH
            if abs(difference) <= tolerance
            else ReconciliationStatus.MISMATCH
        ),
    )


def _reconcile_explosives(
    metric: Literal["detonators", "explosives"],
    values: ShiftExplosiveValues,
    tolerance: float,
) -> DailyReconciliation:
    records = (
        values.zero_shift,
        values.eight_shift,
        values.four_shift,
    )
    shifts = tuple(getattr(item, metric) for item in records)
    daily_total = getattr(values.daily_total, metric)
    if daily_total is None or any(value is None for value in shifts):
        return DailyReconciliation(
            metric=metric,
            shift_sum=None,
            daily_total=daily_total,
            difference_daily_minus_shifts=None,
            tolerance=tolerance,
            status=ReconciliationStatus.INCOMPLETE,
        )
    shift_sum, difference = _decimal_reconciliation(
        daily_total,
        tuple(value for value in shifts if value is not None),
    )
    return DailyReconciliation(
        metric=metric,
        shift_sum=shift_sum,
        daily_total=daily_total,
        difference_daily_minus_shifts=difference,
        tolerance=tolerance,
        status=(
            ReconciliationStatus.MATCH
            if abs(difference) <= tolerance
            else ReconciliationStatus.MISMATCH
        ),
    )


def _raw_cell(
    cell: xlrd.sheet.Cell,
    column_index: int,
    is_formula: bool,
) -> FiveQuantityRawCell:
    kind_map = {
        xlrd.XL_CELL_EMPTY: RawCellKind.EMPTY,
        xlrd.XL_CELL_TEXT: RawCellKind.TEXT,
        xlrd.XL_CELL_NUMBER: RawCellKind.NUMBER,
        xlrd.XL_CELL_DATE: RawCellKind.DATE,
        xlrd.XL_CELL_BOOLEAN: RawCellKind.BOOLEAN,
        xlrd.XL_CELL_ERROR: RawCellKind.ERROR,
        xlrd.XL_CELL_BLANK: RawCellKind.BLANK,
    }
    kind = kind_map.get(cell.ctype, RawCellKind.UNKNOWN)
    is_blank = cell.ctype in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK)
    raw_value: RawCellValue
    if is_blank:
        raw_value = None
    elif isinstance(cell.value, (str, bool, int, float)):
        raw_value = cell.value
    else:
        raw_value = str(cell.value)
    return FiveQuantityRawCell(
        column_index=column_index + 1,
        cell_kind=kind,
        raw_value=raw_value,
        is_blank=is_blank,
        is_formula=is_formula,
        formula_cached_value=raw_value if is_formula else None,
    )


def _decimal_reconciliation(
    daily_total: float,
    shifts: tuple[float, ...],
) -> tuple[float, float]:
    """Preserve spreadsheet decimal intent instead of binary float noise."""

    decimal_sum = sum((Decimal(str(value)) for value in shifts), Decimal(0))
    decimal_difference = Decimal(str(daily_total)) - decimal_sum
    return float(decimal_sum), float(decimal_difference)


def _quality_findings(
    *,
    days: list[FiveQuantityDay],
    title: str,
    report_month: str,
    closed_through: date,
    units: FiveQuantityUnits,
    formula_cell_count: int,
) -> list[FiveQuantityQualityFinding]:
    findings: list[FiveQuantityQualityFinding] = []

    if _TITLE_PLACEHOLDER_RE.search(title):
        findings.append(
            FiveQuantityQualityFinding(
                code="DOCUMENT_TITLE_PLACEHOLDER",
                severity=FindingSeverity.WARNING,
                message="文档标题包含占位或样例身份；企业身份仍以请求 mine_id 为准",
                observed=title,
                expected="正式企业标题",
            )
        )

    closed_days = [day for day in days if day.is_closed]
    open_days = [day for day in days if not day.is_closed]
    if open_days:
        findings.append(
            FiveQuantityQualityFinding(
                code="OPEN_ROWS_EXCLUDED",
                severity=FindingSeverity.INFO,
                message="closed_through 之后的数据行未参与缺失和一致性校验",
                observed=len(open_days),
                expected=f"日期不晚于 {closed_through.isoformat()}",
            )
        )

    report_month_start, report_month_end = _report_month_bounds(
        report_month
    )
    present_dates = {day.date for day in days}
    cursor = report_month_start
    final_closed = min(closed_through, report_month_end)
    while cursor <= final_closed:
        if cursor not in present_dates:
            findings.append(
                FiveQuantityQualityFinding(
                    code="MISSING_CALENDAR_DATE",
                    severity=FindingSeverity.ERROR,
                    message="report_month 闭账范围内缺少整日数据行",
                    date=cursor,
                )
            )
        cursor += timedelta(days=1)

    for day in closed_days:
        _append_missing_findings(findings, day)
        for reconciliation in day.reconciliations:
            if reconciliation.status is ReconciliationStatus.MISMATCH:
                assert (
                    reconciliation.difference_daily_minus_shifts is not None
                )
                findings.append(
                    FiveQuantityQualityFinding(
                        code="SHIFT_TOTAL_MISMATCH",
                        severity=FindingSeverity.ERROR,
                        message="日统计与三个班次之和不一致",
                        date=day.date,
                        source_row_number=day.source_row_number,
                        metric=reconciliation.metric,
                        observed=reconciliation.daily_total,
                        expected=reconciliation.shift_sum,
                        difference=(
                            reconciliation.difference_daily_minus_shifts
                        ),
                    )
                )

    _append_explosives_findings(findings, closed_days)
    _append_wind_findings(findings, closed_days)

    unknown_units = [
        name for name, value in units.model_dump().items() if value is None
    ]
    if unknown_units:
        findings.append(
            FiveQuantityQualityFinding(
                code="UNDECLARED_UNITS",
                severity=FindingSeverity.WARNING,
                message="部分指标单位未声明，禁止据此直接跨企业比较",
                observed=",".join(unknown_units),
                expected="逐指标声明单位或明确保持 unknown",
            )
        )
    if formula_cell_count:
        findings.append(
            FiveQuantityQualityFinding(
                code="FORMULA_CACHED_VALUES_USED",
                severity=FindingSeverity.INFO,
                message="公式未执行；导入值来自 BIFF8 已保存的公式缓存",
                observed=formula_cell_count,
            )
        )
    return findings


def _append_missing_findings(
    findings: list[FiveQuantityQualityFinding],
    day: FiveQuantityDay,
) -> None:
    values: list[tuple[str, str, float | None]] = [
        ("ventilation", "daily", day.ventilation),
    ]
    for metric_name in ("labor", "electricity", "production"):
        group = getattr(day, metric_name)
        values.extend(
            (
                (metric_name, "zero_shift", group.zero_shift),
                (metric_name, "eight_shift", group.eight_shift),
                (metric_name, "four_shift", group.four_shift),
                (metric_name, "daily_total", group.daily_total),
            )
        )
    for shift_name in (
        "zero_shift",
        "eight_shift",
        "four_shift",
        "daily_total",
    ):
        usage = getattr(day.explosives, shift_name)
        values.extend(
            (
                ("detonators", shift_name, usage.detonators),
                ("explosives", shift_name, usage.explosives),
            )
        )
    for metric_name, position, value in values:
        if value is None:
            findings.append(
                FiveQuantityQualityFinding(
                    code="MISSING_REQUIRED_VALUE",
                    severity=FindingSeverity.ERROR,
                    message=f"闭账日缺少 {metric_name}.{position}",
                    date=day.date,
                    source_row_number=day.source_row_number,
                    metric=f"{metric_name}.{position}",
                )
            )


def _append_explosives_findings(
    findings: list[FiveQuantityQualityFinding],
    days: list[FiveQuantityDay],
) -> None:
    usages = [
        getattr(day.explosives, shift_name)
        for day in days
        for shift_name in (
            "zero_shift",
            "eight_shift",
            "four_shift",
            "daily_total",
        )
    ]
    quantities = [
        value
        for usage in usages
        for value in (usage.detonators, usage.explosives)
    ]
    if quantities and all(value is not None for value in quantities) and all(
        value == 0 for value in quantities
    ):
        has_production = any(
            (day.production.daily_total or 0) > 0 for day in days
        )
        findings.append(
            FiveQuantityQualityFinding(
                code=(
                    "EXPLOSIVES_ALL_ZERO_WITH_PRODUCTION"
                    if has_production
                    else "EXPLOSIVES_ALL_ZERO"
                ),
                severity=(
                    FindingSeverity.WARNING
                    if has_production
                    else FindingSeverity.INFO
                ),
                message=(
                    "闭账范围火工品全为零且存在产量；需以工艺标签或领退库凭证说明"
                    if has_production
                    else "闭账范围火工品全部明确填报为零"
                ),
                observed=0,
            )
        )


def _append_wind_findings(
    findings: list[FiveQuantityQualityFinding],
    days: list[FiveQuantityDay],
) -> None:
    values = [day.ventilation for day in days if day.ventilation is not None]
    if len(values) < 5:
        return
    unique_count = len(set(values))
    duplicate_ratio = 1.0 - unique_count / len(values)
    if duplicate_ratio >= 0.5:
        findings.append(
            FiveQuantityQualityFinding(
                code="WIND_REPEATED_VALUES",
                severity=FindingSeverity.WARNING,
                message="风量精确重复比例较高，需确认是设定值还是实测值",
                observed=round(duplicate_ratio, 6),
                expected="<0.5",
            )
        )

    runs: list[tuple[float, int]] = []
    for value in values:
        if runs and value == runs[-1][0]:
            previous_value, count = runs[-1]
            runs[-1] = (previous_value, count + 1)
        else:
            runs.append((value, 1))
    long_runs = [run for run in runs if run[1] >= 3]
    if len(long_runs) >= 2 and len({value for value, _ in long_runs}) >= 2:
        findings.append(
            FiveQuantityQualityFinding(
                code="WIND_STEP_PATTERN",
                severity=FindingSeverity.WARNING,
                message="风量呈多个连续恒定台阶，需核对采样频率和数据来源",
                observed=len(long_runs),
                expected="连续实测或附设定值变更记录",
            )
        )


__all__ = [
    "DailyReconciliation",
    "ExplosiveUsage",
    "FindingSeverity",
    "FiveQuantityDay",
    "FiveQuantityImportErrorCode",
    "FiveQuantityImportFailure",
    "FiveQuantityImportRequest",
    "FiveQuantityImportResult",
    "FiveQuantityQualityFinding",
    "FiveQuantityQualitySummary",
    "FiveQuantityRawCell",
    "FiveQuantitySourceMetadata",
    "FiveQuantityUnits",
    "FiveQuantityValidationParameters",
    "ReconciliationStatus",
    "ReportMonthSource",
    "ShiftExplosiveValues",
    "ShiftNumericValues",
    "import_five_quantity_et",
]
