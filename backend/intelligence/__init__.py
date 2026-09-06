"""
PhishShield TR - Intelligence Module
Domain classification and threat intelligence
"""

from intelligence.site_classifier import (
    SiteType,
    classify_site_type,
    is_trusted_domain,
    get_trust_level,
    GOVERNMENT_DOMAINS,
    TRUSTED_PLATFORMS,
    TRUSTED_SERVICES,
    OFFICIAL_COMPANY_DOMAINS
)

from intelligence.trust_policy import (
    apply_trust_override,
    get_suppressed_signals,
    get_confidence_boost,
    get_platform_explanation,
    PLATFORM_EXPLANATIONS
)

from intelligence.url_classifier import (
    classify_url_fast,
    is_trusted_platform,
    get_trusted_explanation,
    URLClassification,
    SiteType as URLSiteType
)

from intelligence.fusion_engine import (
    FusionEngine,
    FusionResult,
    fusion_engine,
    ThreatSource
)

from intelligence.confidence_engine import (
    ConfidenceEngine,
    ConfidenceResult,
    confidence_engine,
    ConfidenceLevel
)

__all__ = [
    "SiteType",
    "classify_site_type",
    "is_trusted_domain",
    "get_trust_level",
    "GOVERNMENT_DOMAINS",
    "TRUSTED_PLATFORMS",
    "TRUSTED_SERVICES",
    "OFFICIAL_COMPANY_DOMAINS",
    "apply_trust_override",
    "get_suppressed_signals",
    "get_confidence_boost",
    "get_platform_explanation",
    "PLATFORM_EXPLANATIONS",
    "classify_url_fast",
    "is_trusted_platform",
    "get_trusted_explanation",
    "URLClassification",
    "URLSiteType",
    "FusionEngine",
    "FusionResult",
    "fusion_engine",
    "ThreatSource",
    "ConfidenceEngine",
    "ConfidenceResult",
    "confidence_engine",
    "ConfidenceLevel",
]
