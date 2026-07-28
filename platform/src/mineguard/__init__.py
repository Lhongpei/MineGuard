"""MineGuard 多源交叉验证内网影子运行版。"""

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
    "PortfolioAnalysisRequest",
    "PortfolioAnalysisResult",
    "ProductionAnalysisRequest",
    "ProductionAnalysisResult",
    "TemporalDetectionRequest",
    "TemporalDetectionResult",
    "aggregate_measurements",
    "analyze_material_flow",
    "analyze_production",
    "analyze_production_portfolio",
    "detect_temporal_anomalies",
]

__version__ = "0.5.0"
