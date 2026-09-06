"""
PhishShield TR - Canonical Result Structure
V3 Canonical Result adapter/normalizer

This module provides a consistent result structure that normalizes
output from the analysis engine into a canonical format.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from enum import Enum

class SiteType(Enum):
    """Site classification types"""
    OFFICIAL_GOVERNMENT = "OFFICIAL_GOVERNMENT"
    OFFICIAL_COMPANY = "OFFICIAL_COMPANY"
    TRUSTED_PLATFORM = "TRUSTED_PLATFORM"
    TRUSTED_SERVICE = "TRUSTED_SERVICE"
    UNKNOWN = "UNKNOWN"
    SUSPICIOUS = "SUSPICIOUS"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"

class Decision(Enum):
    """Analysis decision codes"""
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DANGER = "DANGER"
    UNKNOWN = "UNKNOWN"

@dataclass
class DecisionInfo:
    """Decision information"""
    code: str
    label: str
    level: str

@dataclass
class SiteInfo:
    """Site information"""
    type: str
    domain: str
    normalized_url: str = ""

@dataclass
class Flags:
    """Result flags"""
    is_safe: bool = False
    is_caution: bool = False
    is_danger: bool = False
    is_unknown: bool = False

@dataclass
class Summary:
    """Human-readable summary"""
    title: str
    message: str

@dataclass
class CanonicalResult:
    """
    Canonical result structure for PhishShield TR V3
    
    This is the standard output format that all analysis paths must produce.
    """
    # Core fields
    risk_score: int = 0
    decision: DecisionInfo = field(default_factory=lambda: DecisionInfo("UNKNOWN", "Bilinmiyor", "unknown"))
    confidence: float = 0.0
    
    # Site information
    site: SiteInfo = field(default_factory=lambda: SiteInfo("UNKNOWN", "", ""))
    
    # Flags
    flags: Flags = field(default_factory=Flags)
    
    # Summary
    summary: Summary = field(default_factory=lambda: Summary("Bilinmiyor", ""))
    
    # Analysis details
    signals: List[str] = field(default_factory=list)
    correlations: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Legacy compatibility (deprecated - will be removed in V4)
    legacy: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return asdict(self)
    
    @classmethod
    def from_analysis_result(cls, analysis_result: Dict) -> "CanonicalResult":
        """
        Create CanonicalResult from analysis/analyzer.py output
        
        This is the adapter/normalizer that ensures consistent output.
        """
        # Extract core fields
        risk_score = analysis_result.get("risk_score", analysis_result.get("score", 0))
        
        # Get decision info
        status = analysis_result.get("status", "Bilinmiyor")
        emoji = analysis_result.get("emoji", "⚪")
        
        # Map status to Decision
        if status in ["GÜVENLİ", "SAFE"]:
            decision_code = Decision.SAFE.value
            decision_label = "GÜVENLİ"
            decision_level = "safe"
            is_safe, is_caution, is_danger, is_unknown = True, False, False, False
        elif status in ["DİKKATLİ OL", "CAUTION"]:
            decision_code = Decision.CAUTION.value
            decision_label = "DİKKATLİ OL"
            decision_level = "caution"
            is_safe, is_caution, is_danger, is_unknown = False, True, False, False
        elif status in ["TEHLİKELİ", "DANGER"]:
            decision_code = Decision.DANGER.value
            decision_label = "TEHLİKELİ"
            decision_level = "danger"
            is_safe, is_caution, is_danger, is_unknown = False, False, True, False
        else:
            decision_code = Decision.UNKNOWN.value
            decision_label = "Bilinmiyor"
            decision_level = "unknown"
            is_safe, is_caution, is_danger, is_unknown = False, False, False, True
        
        # Site type (will be enhanced in Phase 2)
        site_type = analysis_result.get("site_type", SiteType.UNKNOWN.value)
        domain = analysis_result.get("domain", analysis_result.get("url", ""))
        if domain:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(domain if "://" in domain else f"https://{domain}")
                domain = parsed.netloc or domain
            except:
                pass
        
        # Summary
        description = analysis_result.get("description", "")
        if not description:
            if is_safe:
                description = "Bu site güvenilir görünüyor."
            elif is_danger:
                description = "Bu site phishing veya dolandırıcılık riski taşıyor!"
            elif is_caution:
                description = "Bu sitede bazı şüpheli işaretler bulundu."
            else:
                description = "Analiz sonucu belirsiz."
        
        # Create canonical result
        return cls(
            risk_score=risk_score,
            decision=DecisionInfo(decision_code, decision_label, decision_level),
            confidence=analysis_result.get("confidence", 0.0),
            site=SiteInfo(
                type=site_type,
                domain=domain,
                normalized_url=analysis_result.get("url", "")
            ),
            flags=Flags(
                is_safe=is_safe,
                is_caution=is_caution,
                is_danger=is_danger,
                is_unknown=is_unknown
            ),
            summary=Summary(
                title=f"{emoji} {decision_label}",
                message=description
            ),
            signals=analysis_result.get("signals", []),
            correlations=analysis_result.get("correlation_rules_applied", []),
            recommendations=analysis_result.get("recommendations", []),
            legacy={
                "risk_level": analysis_result.get("risk_level", ""),
                "threat_type": analysis_result.get("threat_type", ""),
                "reasons": analysis_result.get("reasons", []),
                "sub_scores": analysis_result.get("sub_scores", {}),
                "version": analysis_result.get("version", "3.0.0"),
                "analysis_version": "3.0.0"
            }
        )


def normalize_result(analysis_result: Dict) -> CanonicalResult:
    """
    Main entry point - normalize analysis result to canonical format
    
    Usage:
        result = normalize_result(analysis_output)
        return result.to_dict()
    """
    return CanonicalResult.from_analysis_result(analysis_result)


def create_safe_result(domain: str, url: str = "", confidence: float = 0.99) -> CanonicalResult:
    """Factory method for safe results"""
    return CanonicalResult(
        risk_score=0,
        decision=DecisionInfo("SAFE", "GÜVENLİ", "safe"),
        confidence=confidence,
        site=SiteInfo(type=SiteType.TRUSTED_PLATFORM.value, domain=domain, normalized_url=url),
        flags=Flags(is_safe=True),
        summary=Summary(title="🟢 GÜVENLİ", message="Bu site güvenilir görünüyor."),
        recommendations=["Site güvenli görünüyor.", "Bilgilerinizi girebilirsiniz."]
    )


def create_danger_result(domain: str, url: str, risk_score: int, 
                         threat_type: str = "", confidence: float = 0.95) -> CanonicalResult:
    """Factory method for danger results"""
    return CanonicalResult(
        risk_score=risk_score,
        decision=DecisionInfo("DANGER", "TEHLİKELİ", "danger"),
        confidence=confidence,
        site=SiteInfo(type=SiteType.BRAND_IMPERSONATION.value, domain=domain, normalized_url=url),
        flags=Flags(is_danger=True),
        summary=Summary(
            title="🔴 TEHLİKELİ", 
            message="Bu site phishing veya dolandırıcılık riski taşıyor!"
        ),
        recommendations=[
            "⚠️ Bu site tehlikeli görünüyor",
            "Bilgilerinizi girmeyin",
            "Siteyi hemen kapatın"
        ]
    )


def create_caution_result(domain: str, url: str, risk_score: int,
                          reason: str = "", confidence: float = 0.5) -> CanonicalResult:
    """Factory method for caution results"""
    return CanonicalResult(
        risk_score=risk_score,
        decision=DecisionInfo("CAUTION", "DİKKATLİ OL", "caution"),
        confidence=confidence,
        site=SiteInfo(type=SiteType.UNKNOWN.value, domain=domain, normalized_url=url),
        flags=Flags(is_caution=True),
        summary=Summary(
            title="🟡 DİKKATLİ OL",
            message=reason or "Bu sitede bazı şüpheli işaretler bulundu."
        ),
        recommendations=[
            "Dikkatli olun",
            "URL'yi kontrol edin",
            "Şifre girmeden önce emin olun"
        ]
    )
