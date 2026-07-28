"""Validation helpers for immutable safety-alert attachments."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import PurePath
import re
import unicodedata
from urllib.parse import quote
import zipfile


MAX_SAFETY_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_SAFETY_ATTACHMENT_BASE64_CHARS = (
    (MAX_SAFETY_ATTACHMENT_BYTES + 2) // 3
) * 4

ALLOWED_SAFETY_ATTACHMENT_TYPES: dict[str, tuple[str, ...]] = {
    "application/pdf": (".pdf",),
    "image/jpeg": (".jpg", ".jpeg"),
    "image/png": (".png",),
    "text/plain": (".txt",),
    "text/csv": (".csv",),
    (
        "application/vnd.openxmlformats-officedocument."
        "spreadsheetml.sheet"
    ): (".xlsx",),
    (
        "application/vnd.openxmlformats-officedocument."
        "wordprocessingml.document"
    ): (".docx",),
}

_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_UNSAFE_ARCHIVE_SUFFIXES = {
    ".bat",
    ".bin",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
}


class SafetyAttachmentValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ValidatedSafetyAttachment:
    filename: str
    media_type: str
    content: bytes
    sha256: str

    @property
    def size_bytes(self) -> int:
        return len(self.content)


def _sanitize_filename(filename: str, media_type: str) -> str:
    normalized = unicodedata.normalize("NFKC", filename)
    normalized = normalized.replace("\\", "/").split("/")[-1]
    normalized = "".join(
        "_"
        if (
            ord(character) < 32
            or ord(character) == 127
            or unicodedata.category(character).startswith("C")
        )
        else character
        for character in normalized
    )
    normalized = re.sub(r'[<>:"|?*]', "_", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip(" .")
    if not normalized:
        normalized = "attachment"
    allowed_extensions = ALLOWED_SAFETY_ATTACHMENT_TYPES[media_type]
    suffix = PurePath(normalized).suffix.casefold()
    if suffix not in allowed_extensions:
        normalized = f"{normalized}{allowed_extensions[0]}"
    stem = PurePath(normalized).stem
    suffix = PurePath(normalized).suffix.casefold()
    if stem.casefold() in _WINDOWS_RESERVED_NAMES:
        stem = f"_{stem}"
    maximum_stem_length = max(1, 160 - len(suffix))
    stem = stem[:maximum_stem_length].rstrip(" .") or "attachment"
    return f"{stem}{suffix}"


def _validate_text(content: bytes) -> None:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise SafetyAttachmentValidationError(
            "attachment_content_type_mismatch",
            "text attachments must be valid UTF-8",
        ) from error
    if "\x00" in text:
        raise SafetyAttachmentValidationError(
            "attachment_content_type_mismatch",
            "text attachments must not contain NUL bytes",
        )
    if any(
        ord(character) < 32 and character not in {"\t", "\r", "\n"}
        for character in text
    ):
        raise SafetyAttachmentValidationError(
            "attachment_content_type_mismatch",
            "text attachments contain unsupported control characters",
        )


def _validate_ooxml(content: bytes, media_type: str) -> None:
    expected_root = (
        "xl/"
        if media_type.endswith("spreadsheetml.sheet")
        else "word/"
    )
    try:
        with zipfile.ZipFile(BytesIO(content)) as archive:
            members = archive.infolist()
            if not members or len(members) > 2000:
                raise SafetyAttachmentValidationError(
                    "attachment_content_type_mismatch",
                    "office attachment structure is invalid",
                )
            names = {member.filename for member in members}
            if (
                "[Content_Types].xml" not in names
                or not any(name.startswith(expected_root) for name in names)
            ):
                raise SafetyAttachmentValidationError(
                    "attachment_content_type_mismatch",
                    "office attachment does not match its declared type",
                )
            total_uncompressed = 0
            for member in members:
                name = member.filename.replace("\\", "/")
                parts = PurePath(name).parts
                if (
                    name.startswith("/")
                    or ".." in parts
                    or any(
                        name.casefold().endswith(suffix)
                        for suffix in _UNSAFE_ARCHIVE_SUFFIXES
                    )
                    or name.casefold().endswith("vbaproject.bin")
                ):
                    raise SafetyAttachmentValidationError(
                        "attachment_unsafe_archive",
                        "office attachment contains an unsafe member",
                    )
                total_uncompressed += int(member.file_size)
                if total_uncompressed > 50 * 1024 * 1024:
                    raise SafetyAttachmentValidationError(
                        "attachment_unsafe_archive",
                        "office attachment expands beyond the safe limit",
                    )
            if archive.testzip() is not None:
                raise SafetyAttachmentValidationError(
                    "attachment_content_type_mismatch",
                    "office attachment is corrupt",
                )
    except zipfile.BadZipFile as error:
        raise SafetyAttachmentValidationError(
            "attachment_content_type_mismatch",
            "office attachment must be a valid OOXML package",
        ) from error


def _validate_content_signature(content: bytes, media_type: str) -> None:
    if media_type == "application/pdf":
        valid = content.startswith(b"%PDF-")
    elif media_type == "image/png":
        valid = content.startswith(b"\x89PNG\r\n\x1a\n") and content.endswith(
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
    elif media_type == "image/jpeg":
        valid = content.startswith(b"\xff\xd8\xff") and content.endswith(
            b"\xff\xd9"
        )
    elif media_type in {"text/plain", "text/csv"}:
        _validate_text(content)
        return
    else:
        _validate_ooxml(content, media_type)
        return
    if not valid:
        raise SafetyAttachmentValidationError(
            "attachment_content_type_mismatch",
            "attachment bytes do not match the declared media type",
        )


def validate_safety_attachment(
    *,
    filename: str,
    media_type: str,
    content_base64: str,
    expected_sha256: str,
) -> ValidatedSafetyAttachment:
    normalized_type = media_type.strip().casefold()
    if normalized_type not in ALLOWED_SAFETY_ATTACHMENT_TYPES:
        raise SafetyAttachmentValidationError(
            "attachment_media_type_not_allowed",
            "attachment media type is not allowed",
        )
    if (
        not content_base64
        or len(content_base64) > MAX_SAFETY_ATTACHMENT_BASE64_CHARS
    ):
        raise SafetyAttachmentValidationError(
            "attachment_too_large",
            "attachment exceeds the 5 MiB decoded limit",
        )
    try:
        content = base64.b64decode(content_base64, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise SafetyAttachmentValidationError(
            "attachment_base64_invalid",
            "attachment content_base64 is invalid",
        ) from error
    if not content:
        raise SafetyAttachmentValidationError(
            "attachment_empty",
            "attachment must not be empty",
        )
    if len(content) > MAX_SAFETY_ATTACHMENT_BYTES:
        raise SafetyAttachmentValidationError(
            "attachment_too_large",
            "attachment exceeds the 5 MiB decoded limit",
        )
    digest = sha256(content).hexdigest()
    if digest != expected_sha256:
        raise SafetyAttachmentValidationError(
            "attachment_sha256_mismatch",
            "attachment sha256 does not match decoded content",
        )
    _validate_content_signature(content, normalized_type)
    return ValidatedSafetyAttachment(
        filename=_sanitize_filename(filename, normalized_type),
        media_type=normalized_type,
        content=content,
        sha256=digest,
    )


def attachment_content_disposition(
    filename: str,
    attachment_id: str,
) -> str:
    suffix = PurePath(filename).suffix.casefold()
    safe_identifier = re.sub(
        r"[^A-Za-z0-9._-]",
        "_",
        attachment_id,
    )[:128] or "safety-attachment"
    fallback = f"{safe_identifier}{suffix}"
    encoded = quote(filename, safe="")
    return (
        f'attachment; filename="{fallback}"; '
        f"filename*=UTF-8''{encoded}"
    )


__all__ = [
    "ALLOWED_SAFETY_ATTACHMENT_TYPES",
    "MAX_SAFETY_ATTACHMENT_BASE64_CHARS",
    "MAX_SAFETY_ATTACHMENT_BYTES",
    "SafetyAttachmentValidationError",
    "ValidatedSafetyAttachment",
    "attachment_content_disposition",
    "validate_safety_attachment",
]
