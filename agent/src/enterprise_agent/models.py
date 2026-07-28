"""Versioned enterprise-side draft and submission models.

The models are ordinary JSON dictionaries at the wire/storage boundary.  These
constructors provide safe defaults without coupling this package to a platform
model library.
"""

from __future__ import annotations

from typing import Any

from .util import random_id, utc_text

DRAFT_SCHEMA_VERSION = "enterprise-submission-draft/v1"
SUBMISSION_SCHEMA_VERSION = "enterprise-submission-v1"


def new_draft(
    *,
    enterprise_id: str = "",
    mine_id: str = "",
    profile_id: str = "",
    profile_version: str = "",
) -> dict[str, Any]:
    return {
        "schema_version": DRAFT_SCHEMA_VERSION,
        "draft_id": random_id("draft"),
        "enterprise_id": enterprise_id.strip(),
        "enterprise_name": "",
        "unified_social_credit_code": "",
        "mine_id": mine_id.strip(),
        "mine_name": "",
        "window_start": "",
        "window_end": "",
        "profile_id": profile_id.strip(),
        "profile_version": profile_version.strip(),
        "operational_context": {
            "regime_code": "",
            "shift_code": "",
            "season_code": "",
            "maintenance": None,
            "approved_event_codes": [],
            "tags": [],
        },
        "observations": [],
        # Source material itself is deliberately not copied into the draft.
        # This bounded manifest keeps enough metadata for the operator-facing
        # source list to survive a reload; field_provenance remains the
        # authoritative field-level evidence record.
        "imports": [],
        "field_provenance": {},
        "llm_assistance": {
            "used": False,
            "provider": None,
            "model": None,
            "run_id": None,
            "suggestion_only": True,
        },
        "notes": "",
    }


def provenance_record(
    *,
    source_kind: str,
    source_name: str,
    locator: str,
    content_sha256: str,
    confidence: float,
    extraction_method: str,
) -> dict[str, Any]:
    return {
        "source_kind": source_kind,
        "source_name": source_name,
        "locator": locator,
        "content_sha256": content_sha256,
        "confidence": confidence,
        "extraction_method": extraction_method,
        "recorded_at": utc_text(),
    }


def blank_observation() -> dict[str, Any]:
    return {
        "source_id": "",
        "observation_id": "",
        "metric_code": "",
        "value": None,
        "unit": "t",
        "observed_at": "",
        "received_at": "",
        "interval_start": None,
        "interval_end": None,
        "reset_before": False,
        "sequence_no": 0,
        "revision": 0,
        # Issued by the source gateway.  The reporting agent only stores and
        # forwards these credentials; it never creates them.
        "payload_sha256": "",
        "signature": "",
    }
