from __future__ import annotations

import base64
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
from types import SimpleNamespace

from pydantic import ValidationError
import pytest

from mineguard.five_quantity import (
    FiveQuantityImportErrorCode,
    FiveQuantityImportFailure,
    FiveQuantityImportRequest,
    import_five_quantity_et,
)
from mineguard import five_quantity


ROOT = Path(__file__).resolve().parents[1]
LOCAL_FIXTURES = ROOT.parent / "local _test"
XX_WORKBOOK = LOCAL_FIXTURES / "五量基础数据测试.et"
GENGYANG_WORKBOOK = LOCAL_FIXTURES / "五量基础数据测试（沁源梗阳）.et"


def _fixture_bytes(path: Path) -> bytes:
    if not path.is_file():
        pytest.skip(f"local ET fixture is unavailable: {path.name}")
    return path.read_bytes()


def _request(
    content: bytes,
    *,
    filename: str,
    mine_id: str = "mine-explicit-001",
    closed_through: date = date(2026, 7, 30),
    report_month: str | None = None,
    as_base64: bool = False,
    expected_sha256: str | None = None,
) -> FiveQuantityImportRequest:
    payload: dict[str, object] = {
        "mine_id": mine_id,
        "source": {
            "source_id": f"fixture:{filename}",
            "filename": filename,
            "received_at": datetime(
                2026,
                7,
                31,
                1,
                0,
                tzinfo=timezone.utc,
            ),
            "origin_system": "local-test-fixture",
            "expected_sha256": expected_sha256,
        },
        "closed_through": closed_through,
        "units": {},
    }
    if report_month is not None:
        payload["report_month"] = report_month
    if as_base64:
        payload["content_base64"] = base64.b64encode(content).decode("ascii")
    else:
        payload["content_bytes"] = content
    return FiveQuantityImportRequest.model_validate(payload)


def _finding_codes(result: object) -> list[str]:
    return [
        finding.code
        for finding in result.quality.findings  # type: ignore[attr-defined]
    ]


def _complete_day(
    observed_date: date,
    *,
    is_closed: bool = True,
) -> five_quantity.FiveQuantityDay:
    numeric = {
        "zero_shift": 1.0,
        "eight_shift": 1.0,
        "four_shift": 1.0,
        "daily_total": 3.0,
    }
    usage = {
        "detonators": 0.0,
        "explosives": 0.0,
        "raw_text": "雷管：0\n炸药：0",
        "is_blank": False,
    }
    return five_quantity.FiveQuantityDay.model_validate(
        {
            "date": observed_date,
            "source_row_number": observed_date.day + 3,
            "is_closed": is_closed,
            "ventilation": 100.0,
            "labor": numeric,
            "electricity": numeric,
            "explosives": {
                "zero_shift": usage,
                "eight_shift": usage,
                "four_shift": usage,
                "daily_total": usage,
            },
            "production": numeric,
            "reconciliations": [],
            "raw_cells": [
                {
                    "column_index": index,
                    "cell_kind": "number",
                    "raw_value": 0.0,
                    "is_blank": False,
                    "is_formula": False,
                }
                for index in range(1, 19)
            ],
        }
    )


class _FakeSheet:
    name = "Sheet1"
    nrows = 4
    ncols = 18


class _FakeBook:
    nsheets = 1
    datemode = 0

    def __init__(self) -> None:
        self.sheet = _FakeSheet()
        self.released = False

    def sheet_by_index(self, index: int) -> _FakeSheet:
        assert index == 0
        return self.sheet

    def release_resources(self) -> None:
        self.released = True


def _patch_minimal_import(
    monkeypatch: pytest.MonkeyPatch,
    days: list[five_quantity.FiveQuantityDay],
) -> _FakeBook:
    book = _FakeBook()
    monkeypatch.setattr(
        five_quantity,
        "_inspect_ole2",
        lambda content: (b"", {0: set()}),
    )
    monkeypatch.setattr(five_quantity, "_open_workbook", lambda content: book)
    monkeypatch.setattr(
        five_quantity,
        "_validate_template",
        lambda sheet: "合成煤矿五量基础数据采集表",
    )
    monkeypatch.setattr(
        five_quantity,
        "_parse_days",
        lambda *args, **kwargs: days,
    )
    return book


def test_xx_workbook_preserves_zero_blank_formula_and_explicit_identity() -> None:
    content = _fixture_bytes(XX_WORKBOOK)
    before = hashlib.sha256(content).hexdigest()

    result = import_five_quantity_et(
        _request(
            content,
            filename=XX_WORKBOOK.name,
            mine_id="regulator-bound-mine-id",
        )
    )

    assert result.mine_id == "regulator-bound-mine-id"
    assert result.identity_binding == "explicit_request_mine_id"
    assert result.source_title == "XX煤矿五量基础数据采集表"
    assert result.source_sha256 == before
    assert result.report_month == "2026-07"
    assert result.report_month_source == "inferred_from_workbook_dates"
    assert len(result.days) == 31
    assert result.quality.closed_day_count == 30
    assert result.quality.open_day_count == 1
    assert result.days[-1].is_closed is False

    july_first = result.days[0]
    assert july_first.production.daily_total == 0
    assert july_first.electricity.zero_shift is None
    assert july_first.raw_cells[6].is_blank is True
    assert july_first.raw_cells[17].is_formula is True
    assert july_first.raw_cells[17].formula_cached_value == 0

    codes = _finding_codes(result)
    assert "DOCUMENT_TITLE_PLACEHOLDER" in codes
    assert "EXPLOSIVES_ALL_ZERO_WITH_PRODUCTION" in codes
    assert "MISSING_REQUIRED_VALUE" in codes
    assert "OPEN_ROWS_EXCLUDED" in codes
    assert hashlib.sha256(XX_WORKBOOK.read_bytes()).hexdigest() == before


def test_gengyang_workbook_finds_deterministic_reconciliation_anomalies() -> None:
    content = _fixture_bytes(GENGYANG_WORKBOOK)
    before = hashlib.sha256(content).hexdigest()
    result = import_five_quantity_et(
        _request(
            content,
            filename=GENGYANG_WORKBOOK.name,
            mine_id="mine-qinyuan-gengyang",
            as_base64=True,
            expected_sha256=before,
        )
    )

    july_thirteenth = next(
        day for day in result.days if day.date == date(2026, 7, 13)
    )
    electricity = next(
        item
        for item in july_thirteenth.reconciliations
        if item.metric == "electricity"
    )
    assert electricity.shift_sum == pytest.approx(56_212)
    assert electricity.daily_total == pytest.approx(45_707)
    assert electricity.difference_daily_minus_shifts == pytest.approx(-10_505)
    assert electricity.status == "mismatch"

    mismatches = [
        finding
        for finding in result.quality.findings
        if finding.code == "SHIFT_TOTAL_MISMATCH"
        and finding.metric == "electricity"
    ]
    assert {finding.date for finding in mismatches} >= {
        date(2026, 7, 3),
        date(2026, 7, 13),
        date(2026, 7, 19),
    }
    codes = _finding_codes(result)
    assert "DOCUMENT_TITLE_PLACEHOLDER" not in codes
    assert "EXPLOSIVES_ALL_ZERO_WITH_PRODUCTION" in codes
    assert "WIND_REPEATED_VALUES" in codes
    assert "WIND_STEP_PATTERN" in codes
    assert set(result.unknown_unit_fields) == {
        "ventilation",
        "labor",
        "electricity",
        "detonators",
        "explosives",
        "production",
    }
    assert hashlib.sha256(GENGYANG_WORKBOOK.read_bytes()).hexdigest() == before


def test_request_requires_exactly_one_content_representation() -> None:
    common = {
        "mine_id": "mine-1",
        "source": {
            "source_id": "src-1",
            "filename": "month.et",
            "received_at": "2026-07-31T00:00:00Z",
        },
        "closed_through": "2026-07-30",
    }
    with pytest.raises(ValidationError, match="exactly one"):
        FiveQuantityImportRequest.model_validate(common)
    with pytest.raises(ValidationError, match="exactly one"):
        FiveQuantityImportRequest.model_validate(
            {
                **common,
                "content_bytes": b"12345678",
                "content_base64": "MTIzNDU2Nzg=",
            }
        )


@pytest.mark.parametrize(
    ("report_month", "expected_source"),
    [
        ("2026-07", "explicit_request"),
        (None, "inferred_from_workbook_dates"),
    ],
)
def test_report_month_is_explicit_or_inferred_and_echoed_without_et_fixture(
    monkeypatch: pytest.MonkeyPatch,
    report_month: str | None,
    expected_source: str,
) -> None:
    days = [_complete_day(date(2026, 7, 1))]
    book = _patch_minimal_import(monkeypatch, days)

    result = import_five_quantity_et(
        _request(
            b"12345678",
            filename="synthetic.et",
            closed_through=date(2026, 7, 1),
            report_month=report_month,
        )
    )

    assert result.report_month == "2026-07"
    assert result.report_month_source == expected_source
    assert result.model_dump(mode="json")["report_month_source"] == (
        expected_source
    )
    assert book.released is True


@pytest.mark.parametrize("report_month", ["2026-00", "2026-13", "0000-01"])
def test_report_month_rejects_invalid_calendar_values(
    report_month: str,
) -> None:
    with pytest.raises(ValidationError):
        _request(
            b"12345678",
            filename="synthetic.et",
            report_month=report_month,
        )


def test_all_workbook_dates_must_match_resolved_report_month() -> None:
    july = _complete_day(date(2026, 7, 31))
    august = _complete_day(date(2026, 8, 1))

    with pytest.raises(FiveQuantityImportFailure) as inferred_error:
        five_quantity._resolve_report_month(None, [july, august])
    assert (
        inferred_error.value.code
        is FiveQuantityImportErrorCode.MULTIPLE_CALENDAR_MONTHS
    )

    with pytest.raises(FiveQuantityImportFailure) as explicit_error:
        five_quantity._resolve_report_month("2026-07", [august])
    assert (
        explicit_error.value.code
        is FiveQuantityImportErrorCode.MULTIPLE_CALENDAR_MONTHS
    )


def test_missing_whole_day_scan_covers_month_start_and_closed_month_end() -> None:
    days = [
        _complete_day(date(2026, 7, 2)),
        _complete_day(date(2026, 7, 30)),
    ]

    findings = five_quantity._quality_findings(
        days=days,
        title="合成煤矿五量基础数据采集表",
        report_month="2026-07",
        closed_through=date(2026, 7, 31),
        units=five_quantity.FiveQuantityUnits(
            ventilation="m3/min",
            labor="person-shift",
            electricity="kWh",
            detonators="count",
            explosives="kg",
            production="t",
        ),
        formula_cell_count=0,
    )
    missing_dates = {
        finding.date
        for finding in findings
        if finding.code == "MISSING_CALENDAR_DATE"
    }

    assert date(2026, 7, 1) in missing_dates
    assert date(2026, 7, 31) in missing_dates
    assert date(2026, 8, 1) not in missing_dates


def test_missing_whole_day_scan_stops_at_closed_through() -> None:
    findings = five_quantity._quality_findings(
        days=[
            _complete_day(date(2026, 7, 2)),
            _complete_day(date(2026, 7, 30), is_closed=False),
        ],
        title="合成煤矿五量基础数据采集表",
        report_month="2026-07",
        closed_through=date(2026, 7, 3),
        units=five_quantity.FiveQuantityUnits(),
        formula_cell_count=0,
    )
    missing_dates = {
        finding.date
        for finding in findings
        if finding.code == "MISSING_CALENDAR_DATE"
    }

    assert missing_dates == {date(2026, 7, 1), date(2026, 7, 3)}


@pytest.mark.parametrize(
    "number",
    ["9" * 400, "NaN", "Inf", "-Inf"],
)
def test_nonfinite_explosives_number_has_stable_import_error(
    number: str,
) -> None:
    sheet = SimpleNamespace(
        cell=lambda row, column: SimpleNamespace(
            ctype=five_quantity.xlrd.XL_CELL_TEXT,
            value=f"雷管：{number}\n炸药：0",
        )
    )

    with pytest.raises(FiveQuantityImportFailure) as error:
        five_quantity._explosive_cell(sheet, 3, 10)

    assert (
        error.value.code
        is FiveQuantityImportErrorCode.INVALID_EXPLOSIVES_CELL
    )
    assert error.value.public_message


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_numeric_cells_have_stable_import_error(
    value: float,
) -> None:
    sheet = SimpleNamespace(
        cell=lambda row, column: SimpleNamespace(
            ctype=five_quantity.xlrd.XL_CELL_NUMBER,
            value=value,
        )
    )

    with pytest.raises(FiveQuantityImportFailure) as error:
        five_quantity._numeric_cell(sheet, 3, 1, "风量")

    assert (
        error.value.code
        is FiveQuantityImportErrorCode.INVALID_NUMERIC_CELL
    )


def test_json_transport_accepts_base64_but_rejects_content_bytes_text() -> None:
    content = _fixture_bytes(GENGYANG_WORKBOOK)
    payload = {
        "mine_id": "mine-1",
        "source": {
            "source_id": "src-1",
            "filename": GENGYANG_WORKBOOK.name,
            "received_at": "2026-07-31T00:00:00Z",
        },
        "closed_through": "2026-07-30",
        "content_base64": base64.b64encode(content).decode("ascii"),
    }
    request = FiveQuantityImportRequest.model_validate_json(
        json.dumps(payload, ensure_ascii=False)
    )
    assert request.content_bytes is None
    assert import_five_quantity_et(request).days

    payload.pop("content_base64")
    payload["content_bytes"] = "must-not-be-coerced"
    with pytest.raises(ValidationError, match="must be bytes"):
        FiveQuantityImportRequest.model_validate_json(
            json.dumps(payload, ensure_ascii=False)
        )


def test_invalid_base64_and_non_ole_fail_with_stable_codes() -> None:
    invalid_base64 = _request(
        b"12345678",
        filename="month.et",
        as_base64=True,
    ).model_copy(update={"content_base64": "!!!!!!!!"})
    with pytest.raises(FiveQuantityImportFailure) as base64_error:
        import_five_quantity_et(invalid_base64)
    assert (
        base64_error.value.code
        is FiveQuantityImportErrorCode.INVALID_BASE64
    )

    with pytest.raises(FiveQuantityImportFailure) as ole_error:
        import_five_quantity_et(
            _request(b"12345678", filename="month.et")
        )
    assert ole_error.value.code is FiveQuantityImportErrorCode.NOT_OLE2


def test_expected_digest_is_enforced_before_workbook_parse() -> None:
    content = _fixture_bytes(GENGYANG_WORKBOOK)
    with pytest.raises(FiveQuantityImportFailure) as error:
        import_five_quantity_et(
            _request(
                content,
                filename=GENGYANG_WORKBOOK.name,
                expected_sha256="0" * 64,
            )
        )
    assert error.value.code is FiveQuantityImportErrorCode.HASH_MISMATCH


def test_formula_prescan_rejects_excessive_boundsheets_before_nested_scan() -> None:
    boundsheet = struct.pack("<HHI", 0x0085, 4, 0)
    stream = boundsheet * 17 + struct.pack("<HH", 0x000A, 0)

    with pytest.raises(FiveQuantityImportFailure) as error:
        five_quantity._formula_coordinates_by_sheet(stream)

    assert error.value.code is FiveQuantityImportErrorCode.TOO_MANY_SHEETS
