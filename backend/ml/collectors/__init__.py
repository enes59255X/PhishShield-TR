"""
PhishShield TR - Feature Collectors
Sprint 7.1: Collect features from all analyzers

Collectors:
- domain_features.py: Domain age, structure features
- threat_features.py: Threat intelligence features
- brand_features.py: Brand impersonation features
- form_features.py: Form analysis features
- content_features.py: Content/text features
"""

from .domain_features import DomainFeatureCollector
from .threat_features import ThreatFeatureCollector
from .brand_features import BrandFeatureCollector
from .form_features import FormFeatureCollector
from .content_features import ContentFeatureCollector

__all__ = [
    "DomainFeatureCollector",
    "ThreatFeatureCollector",
    "BrandFeatureCollector",
    "FormFeatureCollector",
    "ContentFeatureCollector",
]
