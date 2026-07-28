from __future__ import annotations

import base64
from datetime import UTC, datetime
import hashlib
from io import BytesIO
from pathlib import Path
import zipfile

import pytest

from mineguard.edge_store import (
    EdgeTelemetryRepository,
    SafetyAttachmentConflictError,
)
from mineguard.safety_attachments import (
    MAX_SAFETY_ATTACHMENT_BYTES,
    SafetyAttachmentValidationError,
    attachment_content_disposition,
    validate_safety_attachment,
)


PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"


def _alert(repository: EdgeTelemetryRepository) -> dict[str, object]:
    return repository.upsert_platform_alert(
        mine_id="M001",
        category="attachment-test",
        rule_code="attachment:test",
        level="yellow",
        title="附件测试预警",
        summary="核对附件闭环",
        location_code="test",
        detected_at=datetime.now(UTC),
        observation_ids=["attachment-observation"],
        details={"advisory_only": True},
        rule_profile={"version": "test-v1", "fingerprint": "a" * 64},
    )


def _validated(
    content: bytes = PDF,
    *,
    filename: str = "../../报告\u202eexe\r\n.exe",
    media_type: str = "application/pdf",
):
    return validate_safety_attachment(
        filename=filename,
        media_type=media_type,
        content_base64=base64.b64encode(content).decode(),
        expected_sha256=hashlib.sha256(content).hexdigest(),
    )


def test_attachment_validation_sanitizes_name_and_checks_hash() -> None:
    attachment = _validated()
    assert attachment.content == PDF
    assert attachment.filename.endswith(".pdf")
    assert "/" not in attachment.filename
    assert "\\" not in attachment.filename
    assert "\r" not in attachment.filename
    assert "\n" not in attachment.filename
    assert "\u202e" not in attachment.filename
    assert attachment.sha256 == hashlib.sha256(PDF).hexdigest()

    disposition = attachment_content_disposition(
        attachment.filename,
        "safety-attachment-test",
    )
    assert disposition.startswith("attachment;")
    assert "\r" not in disposition
    assert "\n" not in disposition
    disposition.encode("ascii")


@pytest.mark.parametrize(
    ("media_type", "content", "code"),
    [
        (
            "text/html",
            b"<script>alert(1)</script>",
            "attachment_media_type_not_allowed",
        ),
        (
            "application/pdf",
            b"MZ executable",
            "attachment_content_type_mismatch",
        ),
        (
            "text/plain",
            b"safe\x00unsafe",
            "attachment_content_type_mismatch",
        ),
    ],
)
def test_attachment_validation_rejects_unsafe_content(
    media_type: str,
    content: bytes,
    code: str,
) -> None:
    with pytest.raises(SafetyAttachmentValidationError) as captured:
        _validated(
            content,
            filename="evidence.bin",
            media_type=media_type,
        )
    assert captured.value.code == code


def test_attachment_validation_rejects_hash_and_size_mismatch() -> None:
    encoded = base64.b64encode(PDF).decode()
    with pytest.raises(SafetyAttachmentValidationError) as captured:
        validate_safety_attachment(
            filename="evidence.pdf",
            media_type="application/pdf",
            content_base64=encoded,
            expected_sha256="0" * 64,
        )
    assert captured.value.code == "attachment_sha256_mismatch"

    oversized = b"A" * (MAX_SAFETY_ATTACHMENT_BYTES + 1)
    with pytest.raises(SafetyAttachmentValidationError) as captured:
        _validated(
            oversized,
            filename="oversized.txt",
            media_type="text/plain",
        )
    assert captured.value.code == "attachment_too_large"


def _xlsx(entries: dict[str, bytes]) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(
        stream,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "[Content_Types].xml",
            b"<Types xmlns='http://schemas.openxmlformats.org/"
            b"package/2006/content-types'/>",
        )
        archive.writestr("xl/workbook.xml", b"<workbook/>")
        for name, content in entries.items():
            archive.writestr(name, content)
    return stream.getvalue()


def test_ooxml_validation_accepts_structure_and_rejects_macro_member() -> None:
    valid = _xlsx({"xl/worksheets/sheet1.xml": b"<worksheet/>"})
    attachment = _validated(
        valid,
        filename="核查表.xlsx",
        media_type=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
    )
    assert attachment.filename.endswith(".xlsx")

    unsafe = _xlsx({"xl/vbaProject.bin": b"macro"})
    with pytest.raises(SafetyAttachmentValidationError) as captured:
        _validated(
            unsafe,
            filename="macro.xlsx",
            media_type=(
                "application/vnd.openxmlformats-officedocument."
                "spreadsheetml.sheet"
            ),
        )
    assert captured.value.code == "attachment_unsafe_archive"


def test_repository_stores_immutable_content_and_appends_hash_event(
    tmp_path: Path,
) -> None:
    database = tmp_path / "attachments.db"
    repository = EdgeTelemetryRepository(database)
    try:
        alert = _alert(repository)
        validated = _validated(filename="现场 核查.pdf")
        attachment = repository.add_alert_attachment(
            str(alert["alert_id"]),
            filename=validated.filename,
            media_type=validated.media_type,
            content=validated.content,
            content_sha256=validated.sha256,
            actor_id="reviewer-1",
            note="现场材料核对",
        )
        assert attachment["size_bytes"] == len(PDF)
        assert attachment["alert_version"] == int(alert["version"]) + 1

        listed = repository.list_alert_attachments(
            str(alert["alert_id"])
        )
        assert len(listed) == 1
        assert "content" not in listed[0]
        stored = repository.get_alert_attachment(
            str(alert["alert_id"]),
            str(attachment["attachment_id"]),
        )
        assert stored is not None
        assert stored["content"] == PDF

        detail = repository.get_alert(str(alert["alert_id"]))
        assert detail is not None
        assert detail["attachment_count"] == 1
        assert detail["audit_chain_valid"] is True
        assert detail["events"][-1]["event_type"] == "attachment_added"
        assert detail["events"][-1]["payload"]["sha256"] == (
            validated.sha256
        )

        with pytest.raises(SafetyAttachmentConflictError):
            repository.add_alert_attachment(
                str(alert["alert_id"]),
                filename="duplicate.pdf",
                media_type=validated.media_type,
                content=validated.content,
                content_sha256=validated.sha256,
                actor_id="reviewer-1",
            )
    finally:
        repository.close()

    reopened = EdgeTelemetryRepository(database)
    try:
        assert len(
            reopened.list_alert_attachments(str(alert["alert_id"]))
        ) == 1
    finally:
        reopened.close()
