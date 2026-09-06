"""
PhishShield TR - Explanation Generator
Creates human-readable explanations for analysis results
"""

from typing import Dict, List, Optional
from detection.decision import Decision, DecisionResult
from detection.signals import SIGNAL_DEFINITIONS, SignalSeverity

EMOJI_MAP = {
    Decision.SAFE: "🟢",
    Decision.CAUTION: "🟡",
    Decision.DANGER: "🔴"
}

DECISION_TEXT = {
    Decision.SAFE: "GÜVENLİ",
    Decision.CAUTION: "DİKKATLİ OL",
    Decision.DANGER: "TEHLİKELİ"
}

DECISION_DESCRIPTIONS = {
    Decision.SAFE: "Bu site güvenilir görünüyor.",
    Decision.CAUTION: "Bu sitede bazı şüpheli işaretler bulundu.",
    Decision.DANGER: "Bu site phishing/dolandırıcılık riski taşıyor!"
}

TRUSTED_PLATFORM_EXPLANATIONS = {
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
    "youtube.com": "YouTube Google'ın güvenilir video platformu.",
    "google.com": "Google güvenilir arama motoru.",
    "microsoft.com": "Microsoft güvenilir teknoloji şirketi.",
    "apple.com": "Apple güvenilir teknoloji şirketi.",
    "amazon.com": "Amazon güvenilir e-ticaret platformu.",
    "paypal.com": "PayPal güvenilir ödeme platformu.",
}

GOVERNMENT_EXPLANATIONS = {
    "turkiye.gov.tr": "Türkiye Cumhuriyeti resmi devlet portalsı.",
    "cimer.gov.tr": "CİMER resmi devlet iletişim platformu.",
    "eba.gov.tr": "EBA resmi eğitim platformu.",
    "gib.gov.tr": "Gelir İdaresi Başkanlığı resmi vergi portalı.",
    "sgk.gov.tr": "Sosyal Güvenlik Kurumu resmi portalı.",
    "nvi.gov.tr": "Nüfus ve Vatandaşlık İşleri resmi portalı.",
}

BRAND_IMPERSONATION_EXPLANATIONS = {
    "garanti": "Garanti markası taklidi tespit edildi.",
    "akbank": "Akbank markası taklidi tespit edildi.",
    "isbank": "İş Bankası markası taklidi tespit edildi.",
    "ziraat": "Ziraat Bankası markası taklidi tespit edildi.",
    "vakifbank": "VakıfBank markası taklidi tespit edildi.",
    "halkbank": "Halkbank markası taklidi tespit edildi.",
    "edevlet": "e-Devlet taklidi tespit edildi.",
    "uyap": "UYAP taklidi tespit edildi.",
}


def get_trusted_platform_message(matched_domain: Optional[str]) -> str:
    """Get explanation message for trusted platforms"""
    if matched_domain and matched_domain in TRUSTED_PLATFORM_EXPLANATIONS:
        return TRUSTED_PLATFORM_EXPLANATIONS[matched_domain]
    return "Güvenilir platform olarak doğrulandı."


def get_government_message(matched_domain: Optional[str]) -> str:
    """Get explanation message for government sites"""
    if matched_domain and matched_domain in GOVERNMENT_EXPLANATIONS:
        return GOVERNMENT_EXPLANATIONS[matched_domain]
    return "Resmi devlet kurumu olarak doğrulandı."


def get_brand_impersonation_message(domain: str) -> str:
    """Get explanation message for brand impersonation"""
    domain_lower = domain.lower()
    for brand, message in BRAND_IMPERSONATION_EXPLANATIONS.items():
        if brand in domain_lower:
            return message
    return "Bilinen marka taklidi tespit edildi."

def generate_explanation(result: DecisionResult) -> Dict:
    """Generate comprehensive explanation for the user"""
    
    emoji = EMOJI_MAP.get(result.decision, "⚪")
    decision_text = DECISION_TEXT.get(result.decision, "BİLİNMEYEN")
    description = DECISION_DESCRIPTIONS.get(result.decision, "")
    
    # Build positive factors
    positive_factors = []
    if result.technical_details.get("severity_breakdown"):
        severity = result.technical_details["severity_breakdown"]
        if severity.get("LOW", 0) > 0:
            positive_factors.append("✓ Düşük riskli sinyaller tespit edildi")
    
    # Build warning factors
    warning_factors = []
    for pattern in result.threat_patterns:
        if pattern.startswith("🚨"):
            warning_factors.append(pattern)
        elif pattern.startswith("⚠️"):
            warning_factors.append(pattern)
    
    # Technical summary
    technical_summary = []
    if result.reasoning:
        technical_summary = result.reasoning[:3]
    
    return {
        "emoji": emoji,
        "decision_text": decision_text,
        "decision_description": description,
        "risk_score": result.risk_score,
        "confidence": result.confidence,
        "positive_factors": positive_factors,
        "warning_factors": result.threat_patterns if result.decision == Decision.DANGER else warning_factors,
        "technical_summary": technical_summary,
        "recommendations": result.recommendations
    }

def format_popup_response(
    result: DecisionResult,
    site_type: str = None,
    matched_domain: str = None,
    domain: str = None
) -> Dict:
    """Format response for extension popup"""
    
    explanation = generate_explanation(result)
    
    # Get better description for trusted platforms
    description = explanation["decision_description"]
    if site_type == "TRUSTED_PLATFORM" and matched_domain:
        description = get_trusted_platform_message(matched_domain)
    elif site_type == "OFFICIAL_GOVERNMENT" and matched_domain:
        description = get_government_message(matched_domain)
    elif site_type == "BRAND_IMPERSONATION" and domain:
        description = get_brand_impersonation_message(domain)
    
    return {
        "status": explanation["decision_text"],
        "emoji": explanation["emoji"],
        "description": description,
        "risk_score": explanation["risk_score"],
        "confidence": explanation["confidence"],
        "is_safe": result.decision == Decision.SAFE,
        "is_danger": result.decision == Decision.DANGER,
        "is_caution": result.decision == Decision.CAUTION,
        "positive_factors": explanation["positive_factors"],
        "warning_factors": explanation["warning_factors"],
        "recommendations": explanation["recommendations"],
        "show_details": True
    }

def generate_technical_report(result: DecisionResult, all_signals: List[str]) -> str:
    """Generate detailed technical report for advanced users"""
    
    lines = []
    lines.append("=" * 50)
    lines.append("PHISHSHIELD TR - DETAYLI TEKNİK ANALİZ")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Karar: {EMOJI_MAP.get(result.decision)} {DECISION_TEXT.get(result.decision)}")
    lines.append(f"Risk Skoru: {result.risk_score}/100")
    lines.append(f"Güven: {result.confidence}%")
    lines.append("")
    
    lines.append("-" * 50)
    lines.append("TEŞHİS EDİLEN SİNYALLER")
    lines.append("-" * 50)
    
    severity_groups = {s: [] for s in SignalSeverity}
    for signal in all_signals:
        sev = SIGNAL_DEFINITIONS.get(signal, {}).get("severity", SignalSeverity.LOW)
        desc = SIGNAL_DEFINITIONS.get(signal, {}).get("description", signal)
        weight = SIGNAL_DEFINITIONS.get(signal, {}).get("weight", 0)
        severity_groups[sev].append((signal, desc, weight))
    
    for sev in [SignalSeverity.CRITICAL, SignalSeverity.HIGH, SignalSeverity.MEDIUM, SignalSeverity.LOW]:
        signals = severity_groups[sev]
        if signals:
            lines.append(f"\n{sev.value} ({len(signals)} adet):")
            for sig, desc, weight in signals:
                sign = "+" if weight > 0 else ""
                lines.append(f"  {sign}{weight} - {desc}")
    
    if result.threat_patterns:
        lines.append("")
        lines.append("-" * 50)
        lines.append("TEHDİT KALIPLARI")
        lines.append("-" * 50)
        for pattern in result.threat_patterns:
            lines.append(f"  {pattern}")
    
    if result.technical_details.get("correlation_rules_applied"):
        lines.append("")
        lines.append("-" * 50)
        lines.append("KORELASYON KURALLARI")
        lines.append("-" * 50)
        for rule in result.technical_details["correlation_rules_applied"]:
            lines.append(f"  ✓ {rule}")
    
    if result.reasoning:
        lines.append("")
        lines.append("-" * 50)
        lines.append("ANALİZ GEREKÇELERİ")
        lines.append("-" * 50)
        for reason in result.reasoning:
            lines.append(f"  • {reason}")
    
    lines.append("")
    lines.append("=" * 50)
    
    return "\n".join(lines)
