"""
PhishShield TR - Trust Policy Layer
Phase 2: Trust override logic for verified safe platforms

This layer provides SAFE overrides for trusted platforms,
suppressing low-severity false positives.
"""

from typing import Dict, List, Optional, Tuple
from detection.decision import Decision, DecisionResult
from detection.signals import SignalSeverity
from intelligence.site_classifier import SiteType


SIGNALS_TO_SUPPRESS_FOR_TRUSTED = {
    SignalSeverity.LOW: [
        "phone_pattern",
        "english_text",
        "generic_social_engineering",
        "suspicious_tld",
        "known_safe_domain",
        "trusted_platform",
    ],
    SignalSeverity.MEDIUM: [],
    SignalSeverity.HIGH: [],
    SignalSeverity.CRITICAL: [],
}

SIGNALS_TO_SUPPRESS_FOR_GOVERNMENT = {
    SignalSeverity.LOW: [
        "phone_pattern",
        "english_text",
        "generic_social_engineering",
        "suspicious_tld",
        "known_safe_domain",
        "gov_domain",
    ],
    SignalSeverity.MEDIUM: [],
    SignalSeverity.HIGH: [],
    SignalSeverity.CRITICAL: [],
}


PLATFORM_EXPLANATIONS = {
    "chatgpt.com": "ChatGPT resmi yapay zeka platformu doğrulandı.",
    "chat.openai.com": "OpenAI resmi platformu doğrulandı.",
    "openai.com": "OpenAI resmi platformu doğrulandı.",
    "claude.ai": "Claude yapay zeka platformu doğrulandı.",
    "github.com": "GitHub güvenilir yazılım geliştirme platformu.",
    "gitlab.com": "GitLab güvenilir yazılım geliştirme platformu.",
    "linkedin.com": "LinkedIn güvenilir profesyonel ağ platformu.",
    "whatsapp.com": "WhatsApp Meta'nın güvenilir mesajlaşma platformu.",
    "instagram.com": "Instagram Meta'nın güvenilir sosyal medya platformu.",
    "facebook.com": "Facebook Meta'nın güvenilir sosyal medya platformu.",
    "twitter.com": "X (Twitter) güvenilir sosyal medya platformu.",
    "x.com": "X (Twitter) güvenilir sosyal medya platformu.",
    "youtube.com": "YouTube Google's güvenilir video platformu.",
    "google.com": "Google güvenilir arama motoru.",
    "microsoft.com": "Microsoft güvenilir teknoloji şirketi.",
    "apple.com": "Apple güvenilir teknoloji şirketi.",
    "amazon.com": "Amazon güvenilir e-ticaret platformu.",
    "paypal.com": "PayPal güvenilir ödeme platformu.",
    "turkiye.gov.tr": "Türkiye Cumhuriyeti resmi devlet portalsı.",
    "cimer.gov.tr": "CİMER resmi devlet iletişim platformu.",
    "eba.gov.tr": "EBA resmi eğitim platformu.",
    "e-devlet": "e-Devlet resmi devlet hizmet platformu.",
}


def get_suppressed_signals(site_type: SiteType) -> List[str]:
    """Get list of signals to suppress for a given site type"""
    if site_type == SiteType.TRUSTED_PLATFORM:
        suppress_list = []
        for signals in SIGNALS_TO_SUPPRESS_FOR_TRUSTED.values():
            suppress_list.extend(signals)
        return suppress_list
    elif site_type == SiteType.OFFICIAL_GOVERNMENT:
        suppress_list = []
        for signals in SIGNALS_TO_SUPPRESS_FOR_GOVERNMENT.values():
            suppress_list.extend(signals)
        return suppress_list
    return []


def get_confidence_boost(site_type: SiteType) -> float:
    """Get confidence boost for trusted site types"""
    if site_type == SiteType.TRUSTED_PLATFORM:
        return 0.15
    elif site_type == SiteType.OFFICIAL_GOVERNMENT:
        return 0.20
    return 0.0


def get_platform_explanation(matched_domain: Optional[str]) -> str:
    """Get explanation text for a trusted platform"""
    if matched_domain and matched_domain in PLATFORM_EXPLANATIONS:
        return PLATFORM_EXPLANATIONS[matched_domain]
    return "Güvenilir platform olarak doğrulandı."


def apply_trust_override(
    site_type: SiteType,
    matched_domain: Optional[str],
    current_score: int,
    current_confidence: float,
    signals: List[str],
) -> Tuple[Decision, int, float, List[str]]:
    """
    Apply trust policy override if applicable.
    
    Returns:
        Tuple of (decision, risk_score, confidence, suppressed_signals)
    """
    if site_type == SiteType.TRUSTED_PLATFORM:
        suppress_list = get_suppressed_signals(SiteType.TRUSTED_PLATFORM)
        suppressed = [s for s in signals if s in suppress_list]
        remaining_signals = [s for s in signals if s not in suppress_list]
        
        confidence_boost = get_confidence_boost(SiteType.TRUSTED_PLATFORM)
        new_confidence = min(current_confidence + confidence_boost, 1.0)
        
        return (
            Decision.SAFE,
            0,
            new_confidence,
            suppressed
        )
    
    elif site_type == SiteType.OFFICIAL_GOVERNMENT:
        suppress_list = get_suppressed_signals(SiteType.OFFICIAL_GOVERNMENT)
        suppressed = [s for s in signals if s in suppress_list]
        
        confidence_boost = get_confidence_boost(SiteType.OFFICIAL_GOVERNMENT)
        new_confidence = min(current_confidence + confidence_boost, 1.0)
        
        return (
            Decision.SAFE,
            0,
            new_confidence,
            suppressed
        )
    
    elif site_type == SiteType.BRAND_IMPERSONATION:
        return (
            Decision.DANGER,
            100,
            current_confidence,
            []
        )
    
    return (
        Decision.CAUTION if current_score >= 50 else Decision.SAFE,
        current_score,
        current_confidence,
        []
    )
