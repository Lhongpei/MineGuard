from __future__ import annotations

import hashlib
import hmac
from typing import Any

import pytest

from enterprise_agent.security import observation_payload
from enterprise_agent.service import EnterpriseAgentService
from enterprise_agent.storage import Repository
from enterprise_agent.util import canonical_json, sha256_json

SOURCE_ID = "mine-001-main-transport"
SOURCE_SECRET = "example-device-secret-not-for-production"
_SOURCE_SIGNING_CONTEXT = b"MINEGUARD-GOVERNED-OBSERVATION-V1\x00"


def gateway_sign_observation(
    observation: dict[str, Any],
    secret: str = SOURCE_SECRET,
) -> dict[str, Any]:
    """Test-only stand-in for a source gateway outside the agent."""

    payload = observation_payload(observation)
    payload_sha256 = sha256_json(payload)
    envelope = {
        "payload": payload,
        "payload_sha256": payload_sha256,
    }
    signature = hmac.new(
        secret.encode("utf-8"),
        _SOURCE_SIGNING_CONTEXT
        + canonical_json(envelope).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        **observation,
        "payload_sha256": payload_sha256,
        "signature": signature,
    }


def complete_values() -> dict[str, Any]:
    return {
        "enterprise_id": "enterprise-001",
        "enterprise_name": "示例能源有限公司",
        "unified_social_credit_code": "91110000ABCDEFGH1X",
        "mine_id": "mine-001",
        "mine_name": "示例一号矿",
        "window_start": "2026-07-27T00:00:00Z",
        "window_end": "2026-07-27T08:00:00Z",
        "profile_id": "coal-balance-default",
        "profile_version": "2026.07",
        "operational_context": {
            "regime_code": "NORMAL_PRODUCTION",
            "shift_code": "A",
            "season_code": "SUMMER",
            "maintenance": False,
            "approved_event_codes": [],
            "tags": [],
        },
        "observations": [
            gateway_sign_observation(
                {
                "source_id": SOURCE_ID,
                "observation_id": "obs-20260727-0001",
                "metric_code": "coal.main_transport_t",
                "value": 1000.25,
                "unit": "t",
                "observed_at": "2026-07-27T08:00:00Z",
                "received_at": "2026-07-27T08:00:05Z",
                "interval_start": None,
                "interval_end": None,
                "reset_before": False,
                "sequence_no": 202607270001,
                "revision": 0,
                }
            )
        ],
    }


def event_snapshot_for(draft: dict[str, Any]) -> dict[str, Any]:
    return {
        "snapshot_id": f"{draft['mine_id']}-window-event-snapshot",
        "mine_id": draft["mine_id"],
        "window_start": draft["window_start"],
        "window_end": draft["window_end"],
        "event_codes": list(
            draft["operational_context"]["approved_event_codes"]
        ),
        "evidence_sha256": "e" * 64,
        "source_system": "regulator-event-ledger",
        "record_id": f"query-result:{draft['mine_id']}",
    }


def ensure_event_snapshot(
    service: EnterpriseAgentService,
    draft: dict[str, Any],
    *,
    actor: str = "operator-1",
) -> dict[str, Any]:
    if not all(
        isinstance(draft.get(field), str) and draft[field]
        for field in ("mine_id", "window_start", "window_end")
    ):
        return draft
    records = draft.get("field_provenance", {}).get(
        "/operational_context/approved_event_codes",
        [],
    )
    if any(
        isinstance(record, dict)
        and record.get("extraction_method")
        == "regulator_event_snapshot_import"
        for record in records
    ):
        return draft
    return service.import_event_snapshot(
        draft["draft_id"],
        snapshot=event_snapshot_for(draft),
        actor=actor,
        expected_revision=draft["_meta"]["revision"],
    )["draft"]


@pytest.fixture
def values() -> dict[str, Any]:
    return complete_values()


@pytest.fixture
def service() -> EnterpriseAgentService:
    return EnterpriseAgentService(Repository(":memory:"))
