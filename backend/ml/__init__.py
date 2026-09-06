"""
PhishShield TR - ML Package
Sprint 6-7: Machine Learning and Feature Pipeline

Modules:
- schema: Feature definitions for ML model
- features: Unified SiteFeatures dataclass
- feature_collector: Orchestrates feature collection
- extractor: Feature extraction for ML model
- dataset: Training data collection
- model: ML model (RandomForest)
- predictor: Hybrid prediction
- explainer: AI explanation generation
- collectors: Individual feature collectors
"""

from .schema import ML_FEATURES, get_feature_names, get_feature_schema, FeatureGroup
from .features import (
    SiteFeatures,
    DomainFeatures,
    ThreatFeatures,
    BrandFeatures,
    FormFeatures,
    ContentFeatures,
    BehaviorFeatures,
    SSLFeatures,
    ThreatLevel,
)
from .feature_collector import FeatureCollector, feature_collector
from .extractor import feature_extractor
from .dataset import dataset_collector
from .model import phishing_model
from .predictor import hybrid_predictor
from .explainer import ml_explainer

__all__ = [
    # Schema
    "ML_FEATURES",
    "get_feature_names",
    "get_feature_schema",
    "FeatureGroup",
    # Features
    "SiteFeatures",
    "DomainFeatures",
    "ThreatFeatures",
    "BrandFeatures",
    "FormFeatures",
    "ContentFeatures",
    "BehaviorFeatures",
    "SSLFeatures",
    "ThreatLevel",
    # Collectors
    "FeatureCollector",
    "feature_collector",
    # Components
    "feature_extractor",
    "dataset_collector",
    "phishing_model",
    "hybrid_predictor",
    "ml_explainer",
]
