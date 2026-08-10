"""Independent ten-quantity V3 wire catalog used by the connector.

The connector intentionally does not import the enterprise Agent.  These
constants mirror the published interface so mapping validation and emitted
source snapshots cannot silently disagree.  Ten business quantities use
eleven atomic fields because detonator count and explosive mass have different
units and must never be added together.
"""

from __future__ import annotations

TEN_QUANTITY_SUBMISSION_CONTRACT = "ten-quantity-submission-v3"
TEN_QUANTITY_SOURCE_CONTRACT = "enterprise-connector-ten-quantity-source/v1"

LEGACY_V2_METRICS = (
    "ventilation_m3_min",
    "electricity_kwh",
    "detonators_count",
    "explosives_kg",
    "mine_entry_persons",
    "production_t",
)

METRICS = (
    *LEGACY_V2_METRICS,
    "extraction_t",
    "sales_t",
    "transport_t",
    "wash_feed_t",
    "invoiced_quantity_t",
)

UNITS = {
    "ventilation_m3_min": "m3/min",
    "electricity_kwh": "kWh",
    "detonators_count": "count",
    "explosives_kg": "kg",
    "mine_entry_persons": "person",
    "production_t": "t",
    "extraction_t": "t",
    "sales_t": "t",
    "transport_t": "t",
    "wash_feed_t": "t",
    "invoiced_quantity_t": "t",
}

AGGREGATIONS = {
    metric: "time_weighted_average" if metric == "ventilation_m3_min" else "sum"
    for metric in METRICS
}

INTEGER_METRICS = frozenset({"detonators_count", "mine_entry_persons"})

# V3 daily totals explicitly carry every atom.  The first seven operational
# atoms are required per shift by the Agent; commercial/logistics figures are
# commonly daily-ledger values and may therefore remain explicit null/missing
# in the connector's shift snapshots.
REQUIRED_SHIFT_METRICS = frozenset((*LEGACY_V2_METRICS, "extraction_t"))

__all__ = [
    "AGGREGATIONS",
    "INTEGER_METRICS",
    "LEGACY_V2_METRICS",
    "METRICS",
    "REQUIRED_SHIFT_METRICS",
    "TEN_QUANTITY_SOURCE_CONTRACT",
    "TEN_QUANTITY_SUBMISSION_CONTRACT",
    "UNITS",
]
