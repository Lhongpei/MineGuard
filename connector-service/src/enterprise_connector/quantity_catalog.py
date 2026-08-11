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

SCOPES = ("daily_total", "zero_shift", "eight_shift", "four_shift")
SHIFT_SCOPES = SCOPES[1:]

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
OPTIONAL_SHIFT_METRICS = frozenset(METRICS) - REQUIRED_SHIFT_METRICS

_SHIFT_NAME_ALIASES = {
    "zero": "zero_shift",
    "zero_shift": "zero_shift",
    "eight": "eight_shift",
    "eight_shift": "eight_shift",
    "four": "four_shift",
    "four_shift": "four_shift",
}


def dynamic_mapping_scopes(
    *,
    period_type: str,
    scope_field: str | None,
    scope_values: dict[str, str],
    shift_names: tuple[str, ...],
) -> frozenset[str]:
    """Return the statically declared scopes for an unscoped mapping.

    A configured ``scope_field`` makes an unscoped/current-shift target follow
    each source row.  Non-empty ``scope_values`` is the source's declaration
    of which cadences it supplies.  An empty table means the source promises
    to emit the canonical scope values directly, so all four scopes are
    possible.  Without a scope field, cadence follows ``period_type``.
    """

    if scope_field:
        if scope_values:
            return frozenset(scope_values.values())
        return frozenset(SCOPES)
    if period_type == "daily":
        return frozenset({"daily_total"})
    return frozenset(
        scope
        for name in shift_names
        if (scope := _SHIFT_NAME_ALIASES.get(name)) is not None
    )


def mapping_target_scopes(
    target: str,
    *,
    period_type: str,
    scope_field: str | None,
    scope_values: dict[str, str],
    shift_names: tuple[str, ...],
    observed_scopes: frozenset[str] = frozenset(),
) -> frozenset[str]:
    """Resolve a mapping target without losing explicit scope information."""

    parts = target.split(".", 1)
    if len(parts) == 2 and parts[0] != "current_shift":
        return frozenset({parts[0]})
    declared = dynamic_mapping_scopes(
        period_type=period_type,
        scope_field=scope_field,
        scope_values=scope_values,
        shift_names=shift_names,
    )
    # A canonical scope actually observed in the current snapshot proves that
    # a dynamic mapping applies there even when a legacy scope_values table did
    # not enumerate the identity mapping explicitly.
    return declared | (observed_scopes & frozenset(SCOPES))

__all__ = [
    "AGGREGATIONS",
    "INTEGER_METRICS",
    "LEGACY_V2_METRICS",
    "METRICS",
    "OPTIONAL_SHIFT_METRICS",
    "REQUIRED_SHIFT_METRICS",
    "SCOPES",
    "SHIFT_SCOPES",
    "TEN_QUANTITY_SOURCE_CONTRACT",
    "TEN_QUANTITY_SUBMISSION_CONTRACT",
    "UNITS",
    "dynamic_mapping_scopes",
    "mapping_target_scopes",
]
