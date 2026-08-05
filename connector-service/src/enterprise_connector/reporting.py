from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

from .models import PipelineConfig


def reporting_cutoff(pipeline: PipelineConfig, moment: datetime) -> date:
    """Return the enterprise-local inclusive reporting cutoff date."""

    aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
    local = aware.astimezone(ZoneInfo(pipeline.timezone))
    return local.date() - timedelta(days=pipeline.reporting_lag_days)


def reporting_target(pipeline: PipelineConfig, timestamp: float) -> tuple[str, str, str]:
    cutoff = reporting_cutoff(pipeline, datetime.fromtimestamp(timestamp, UTC))
    month = cutoff.strftime("%Y-%m")
    draft_key = f"draft:{pipeline.enterprise_id}:five-quantity:monthly:{month}"
    return draft_key, month, cutoff.isoformat()
