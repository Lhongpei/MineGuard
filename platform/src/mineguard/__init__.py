"""MineGuard 多源交叉验证与监管核查闭环生产候选版。"""

from .aggregation import (
    AggregationRequest,
    AggregationResult,
    aggregate_measurements,
)
from .flow import (
    FlowAnalysisRequest,
    FlowAnalysisResult,
    analyze_material_flow,
)
from .models import ProductionAnalysisRequest, ProductionAnalysisResult
from .optimization import analyze_production
from .operational_five_quantity import (
    OperationalFiveQuantityFileRequest,
    OperationalFiveQuantityResult,
    analyze_operational_five_quantity_file,
)
from .portfolio import (
    PortfolioAnalysisRequest,
    PortfolioAnalysisResult,
    analyze_production_portfolio,
)
from .temporal import (
    TemporalDetectionRequest,
    TemporalDetectionResult,
    detect_temporal_anomalies,
)

__all__ = [
    "AggregationRequest",
    "AggregationResult",
    "FlowAnalysisRequest",
    "FlowAnalysisResult",
    "OperationalFiveQuantityFileRequest",
    "OperationalFiveQuantityResult",
    "PortfolioAnalysisRequest",
    "PortfolioAnalysisResult",
    "ProductionAnalysisRequest",
    "ProductionAnalysisResult",
    "TemporalDetectionRequest",
    "TemporalDetectionResult",
    "aggregate_measurements",
    "analyze_material_flow",
    "analyze_operational_five_quantity_file",
    "analyze_production",
    "analyze_production_portfolio",
    "detect_temporal_anomalies",
]

__version__ = "0.6.1"
