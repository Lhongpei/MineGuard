"""Enterprise-local catalog for the current ten regulatory quantities.

The government platform owns an independent implementation of the same wire
catalog.  This module is intentionally small and data-only so CSV parsing,
local validation and the enterprise UI cannot silently drift from one another.

Ten business quantities are represented by eleven atomic measurements because
detonator count and explosive mass have incompatible units and must never be
added into a unitless blasting-material total.
"""

from __future__ import annotations

TEN_QUANTITY_CATALOG_VERSION = "ten-quantity-catalog-v1"
TEN_QUANTITY_SUBMISSION_CONTRACT = "ten-quantity-submission-v3"
TEN_QUANTITY_SUBMISSION_MESSAGE_TYPE = "ten_quantity_submission"
TEN_QUANTITY_ANALYSIS_CONTRACT = "analysis-report-v3"

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

BUSINESS_GROUPS: dict[str, tuple[str, ...]] = {
    "airflow": ("ventilation_m3_min",),
    "electricity": ("electricity_kwh",),
    "blasting_materials": ("detonators_count", "explosives_kg"),
    "mine_entry_personnel": ("mine_entry_persons",),
    "production": ("production_t",),
    "extraction": ("extraction_t",),
    "sales": ("sales_t",),
    "transport": ("transport_t",),
    "washing": ("wash_feed_t",),
    "invoicing": ("invoiced_quantity_t",),
}

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
    "ventilation_m3_min": "time_weighted_average",
    **{metric: "sum" for metric in METRICS if metric != "ventilation_m3_min"},
}

METRIC_LABELS = {
    "ventilation_m3_min": "风量",
    "electricity_kwh": "电量",
    "detonators_count": "火工品量（雷管）",
    "explosives_kg": "火工品量（炸药）",
    "mine_entry_persons": "入井人员量",
    "labor_persons": "入井人员量",
    "production_t": "产量（企业报表）",
    "extraction_t": "开采量（采掘计量）",
    "sales_t": "销售量",
    "transport_t": "运输量（出矿/外运）",
    "wash_feed_t": "洗煤量（入洗原煤）",
    "invoiced_quantity_t": "开票量（吨）",
}

# The first seven atomic operating measurements (including extraction) are
# mandatory per shift. Sales, outbound transportation, wash feed and invoiced
# tonnage are mandatory only at daily-total level.
REQUIRED_SHIFT_METRICS = frozenset((*LEGACY_V2_METRICS, "extraction_t"))
OPTIONAL_SHIFT_METRICS = frozenset(METRICS) - REQUIRED_SHIFT_METRICS

# Stable ordered views used by the deliberately compact daily-entry template.
DAILY_TEMPLATE_METRICS = METRICS
SHIFT_TEMPLATE_METRICS = tuple(
    metric for metric in METRICS if metric in REQUIRED_SHIFT_METRICS
)

__all__ = [
    "AGGREGATIONS",
    "BUSINESS_GROUPS",
    "DAILY_TEMPLATE_METRICS",
    "LEGACY_V2_METRICS",
    "METRICS",
    "METRIC_LABELS",
    "OPTIONAL_SHIFT_METRICS",
    "REQUIRED_SHIFT_METRICS",
    "SHIFT_TEMPLATE_METRICS",
    "TEN_QUANTITY_ANALYSIS_CONTRACT",
    "TEN_QUANTITY_CATALOG_VERSION",
    "TEN_QUANTITY_SUBMISSION_CONTRACT",
    "TEN_QUANTITY_SUBMISSION_MESSAGE_TYPE",
    "UNITS",
]
