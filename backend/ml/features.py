"""
PhishShield TR - Site Features
Sprint 7.1: Unified Feature Schema for Fusion Engine

Purpose:
- Create unified feature format from all analyzers
- Structured output for ML and Fusion Engine
- Clean separation of feature types
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum


class ThreatLevel(Enum):
    """Threat confidence levels"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DomainFeatures:
    """Domain-related features"""
    age_days: int = -1
    age_category: str = "unknown"
    is_new_domain: bool = False
    is_suspicious_age: bool = False
    length: int = 0
    subdomain_count: int = 0
    hyphen_count: int = 0
    number_count: int = 0
    has_underscore: bool = False
    tld: str = ""
    is_suspicious_tld: bool = False
    is_ip_based: bool = False
    is_punycode: bool = False


@dataclass
class ThreatFeatures:
    """Threat intelligence features"""
    matched: bool = False
    source: Optional[str] = None
    category: Optional[str] = None
    confidence: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.NONE
    first_seen_days: Optional[int] = None


@dataclass
class BrandFeatures:
    """Brand impersonation features"""
    matched: bool = False
    brand_name: Optional[str] = None
    brand_category: Optional[str] = None
    similarity_score: float = 0.0
    is_impostor: bool = False
    is_typosquat: bool = False
    match_type: str = "none"
    confidence: float = 0.0


@dataclass
class FormFeatures:
    """Form analysis features"""
    has_login_form: bool = False
    has_password_field: bool = False
    has_credential_fields: bool = False
    has_payment_fields: bool = False
    has_otp_field: bool = False
    has_external_submit: bool = False
    external_domain: Optional[str] = None
    hidden_field_count: int = 0
    autocomplete_disabled: bool = False
    form_count: int = 0
    form_risk_score: int = 0


@dataclass
class ContentFeatures:
    """Content analysis features"""
    urgency_word_count: int = 0
    has_urgency: bool = False
    has_sms_style: bool = False
    bank_word_count: int = 0
    cargo_word_count: int = 0
    reward_word_count: int = 0
    investment_word_count: int = 0
    external_script_count: int = 0
    iframe_count: int = 0
    has_obfuscation: bool = False
    phone_count: int = 0
    has_english_text: bool = False


@dataclass
class BehaviorFeatures:
    """Behavior analysis features"""
    redirect_count: int = 0
    has_meta_refresh: bool = False
    right_click_disabled: bool = False
    text_copy_disabled: bool = False
    popup_count: int = 0
    has_form_autosubmit: bool = False


@dataclass
class SSLFeatures:
    """SSL/TLS features"""
    has_ssl: bool = False
    is_valid: bool = False
    expires_soon: bool = False
    self_signed: bool = False
    issuer: Optional[str] = None
    days_until_expiry: int = -1


@dataclass
class SiteFeatures:
    """
    Unified feature container for all analysis results.

    This is the standard output format that all analyzers should produce.
    Used by Fusion Engine and ML Pipeline.
    """
    url: str = ""
    domain: str = ""  # String domain like "garanti-login-secure.xyz"

    # Feature groups
    domain_features: DomainFeatures = field(default_factory=DomainFeatures)
    threat: ThreatFeatures = field(default_factory=ThreatFeatures)
    brand: BrandFeatures = field(default_factory=BrandFeatures)
    form: FormFeatures = field(default_factory=FormFeatures)
    content: ContentFeatures = field(default_factory=ContentFeatures)
    behavior: BehaviorFeatures = field(default_factory=BehaviorFeatures)
    ssl: SSLFeatures = field(default_factory=SSLFeatures)

    # Overall scores
    raw_risk_score: int = 0
    signal_score: int = 0
    correlation_bonus: int = 0

    # Site classification
    site_type: str = "unknown"
    is_trusted: bool = False
    trust_fast_path: bool = False

    # Meta
    analysis_signals: List[str] = field(default_factory=list)
    applied_rules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "url": self.url,
            "domain": self.domain,
            "domain_features": self.domain_features.__dict__,
            "threat_features": self.threat.__dict__,
            "brand_features": self.brand.__dict__,
            "form_features": self.form.__dict__,
            "content_features": self.content.__dict__,
            "behavior_features": self.behavior.__dict__,
            "ssl_features": self.ssl.__dict__,
            "raw_risk_score": self.raw_risk_score,
            "signal_score": self.signal_score,
            "correlation_bonus": self.correlation_bonus,
            "site_type": self.site_type,
            "is_trusted": self.is_trusted,
            "trust_fast_path": self.trust_fast_path,
            "analysis_signals": self.analysis_signals,
            "applied_rules": self.applied_rules,
        }

    def get_risk_score(self) -> int:
        """Get final risk score"""
        if self.trust_fast_path or self.is_trusted:
            return 0
        return self.raw_risk_score

    def get_threat_indicators(self) -> List[str]:
        """Get list of threat indicators"""
        indicators = []

        if self.threat.matched:
            indicators.append(f"threat:{self.threat.source}")

        if self.brand.is_impostor:
            indicators.append(f"brand:{self.brand.brand_name}")

        if self.form.has_external_submit:
            indicators.append("form:external_submit")

        if self.domain_features.is_new_domain:
            indicators.append("domain:new")

        if self.content.has_urgency:
            indicators.append("content:urgency")

        return indicators
