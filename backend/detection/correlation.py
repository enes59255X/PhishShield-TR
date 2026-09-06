"""
PhishShield TR - Correlation Engine
Analyzes signal combinations to detect complex attack patterns
"""

from typing import Dict, List, Set, Tuple
from detection.signals import SIGNAL_DEFINITIONS, SignalSeverity

class CorrelationRule:
    def __init__(self, name: str, signals: List[str], correlation_bonus: int, 
                 final_severity: SignalSeverity = None, description: str = ""):
        self.name = name
        self.signals = set(signals)
        self.correlation_bonus = correlation_bonus
        self.final_severity = final_severity
        self.description = description

CORRELATION_RULES = [
    # CRITICAL Combinations
    CorrelationRule(
        name="bank_phishing_full",
        signals=["bank_impostor", "has_login_form", "password_field", "domain_mismatch"],
        correlation_bonus=60,
        final_severity=SignalSeverity.CRITICAL,
        description="Banka taklidi + sahte giris formu + domain uyusmazligi"
    ),
    CorrelationRule(
        name="credential_harvesting",
        signals=["has_login_form", "external_post_action"],
        correlation_bonus=70,
        final_severity=SignalSeverity.CRITICAL,
        description="Kimlik avi: form verisi harici domaine gidiyor"
    ),
    CorrelationRule(
        name="egov_phishing_full",
        signals=["gov_impostor", "has_credential_form", "domain_mismatch"],
        correlation_bonus=65,
        final_severity=SignalSeverity.CRITICAL,
        description="e-Devlet taklidi + kimlik formu + domain uyusmazligi"
    ),
    CorrelationRule(
        name="cargo_scam_payment",
        signals=["cargo_brand", "payment_form", "urgency_text", "suspicious_domain"],
        correlation_bonus=70,
        final_severity=SignalSeverity.CRITICAL,
        description="Kargo soygunu: odeme formu + aciliyet + supheli domain"
    ),
    CorrelationRule(
        name="investment_scam",
        signals=["investment_keyword", "urgency_text", "has_credential_form", "suspicious_domain"],
        correlation_bonus=65,
        final_severity=SignalSeverity.CRITICAL,
        description="Yatirim dolandiriciligi:担保 + aciliyet + kimlik talebi"
    ),
    CorrelationRule(
        name="refund_scam",
        signals=["refund_keyword", "bank_account_field", "urgency_text", "suspicious_domain"],
        correlation_bonus=60,
        final_severity=SignalSeverity.CRITICAL,
        description="Iade dolandi: para iadesi vaadi + banka bilgisi"
    ),
    
    # HIGH Combinations
    CorrelationRule(
        name="brand_typo_combo",
        signals=["brand_keyword", "typosquatting"],
        correlation_bonus=35,
        description="Marka adi + typosquatting kombinasyonu"
    ),
    CorrelationRule(
        name="login_suspicious_redirect",
        signals=["has_login_form", "suspicious_redirect"],
        correlation_bonus=30,
        description="Giris formu + supheli yonlendirme"
    ),
    CorrelationRule(
        name="password_external_domain",
        signals=["password_field", "external_post_action"],
        correlation_bonus=45,
        description="Sifre alani + harici domaine post"
    ),
    CorrelationRule(
        name="cargo_tracking_scam",
        signals=["cargo_brand", "tracking_keyword", "payment_request"],
        correlation_bonus=40,
        description="Kargo takip soygunu"
    ),
    CorrelationRule(
        name="ecommerce_fake_discount",
        signals=["ecommerce_brand", "discount_urgency", "payment_form"],
        correlation_bonus=35,
        description="Sashte indirim/eticaret soygunu"
    ),
    CorrelationRule(
        name="lottery_scam",
        signals=["lottery_keyword", "winner_selection", "personal_info_request"],
        correlation_bonus=40,
        description="Piyango/mutfakat dolandi"
    ),
    CorrelationRule(
        name="job_fraud",
        signals=["job_keyword", "registration_fee", "personal_doc_request"],
        correlation_bonus=45,
        description="Is ilani dolandi"
    ),
    
    # MEDIUM Combinations  
    CorrelationRule(
        name="multiple_suspicious_forms",
        signals=["suspicious_form_fields", "external_scripts"],
        correlation_bonus=20,
        description="Coklu supheli form + harici script"
    ),
    CorrelationRule(
        name="urgent_login",
        signals=["urgency_text", "has_login_form"],
        correlation_bonus=15,
        description="Aciliyet hissettirme + giris formu"
    ),
]

class CorrelationEngine:
    def __init__(self):
        self.rules = CORRELATION_RULES
        self.signal_bonuses: Dict[str, int] = {}
        self.applied_rules: List[str] = []
        
    def analyze(self, detected_signals: List[str]) -> Tuple[int, List[str], List[str]]:
        """
        Analyze signal combinations and return:
        - Total correlation bonus
        - List of applied rule names
        - List of high-confidence threat patterns
        """
        signal_set = set(detected_signals)
        total_bonus = 0
        applied_rules = []
        threat_patterns = []
        
        for rule in self.rules:
            matched = signal_set.intersection(rule.signals)
            if len(matched) >= 2:
                match_ratio = len(matched) / len(rule.signals)
                if match_ratio >= 0.6:
                    rule_bonus = int(rule.correlation_bonus * match_ratio)
                    total_bonus += rule_bonus
                    applied_rules.append(rule.name)
                    
                    if rule.final_severity == SignalSeverity.CRITICAL:
                        threat_patterns.append(f"🚨 {rule.description}")
                    elif rule.final_severity == SignalSeverity.HIGH:
                        threat_patterns.append(f"⚠️ {rule.description}")
                    elif rule.correlation_bonus >= 40:
                        threat_patterns.append(f"⚠️ {rule.description}")
        
        self.signal_bonuses = {}
        self.applied_rules = applied_rules
        
        return total_bonus, applied_rules, threat_patterns
    
    def get_pattern_names(self) -> List[str]:
        return [r.name for r in self.rules]
    
    def explain_correlation(self, applied_rules: List[str]) -> str:
        explanations = []
        for rule in self.rules:
            if rule.name in applied_rules:
                explanations.append(f"  + {rule.correlation_bonus} puan: {rule.description}")
        return "\n".join(explanations) if explanations else ""


def calculate_signal_score(signals: List[str]) -> Dict:
    """
    Calculate score from signals with correlation bonuses
    """
    from detection.signals import get_signal_weight
    
    base_score = 0
    for signal in signals:
        base_score += get_signal_weight(signal)
    
    engine = CorrelationEngine()
    correlation_bonus, applied_rules, patterns = engine.analyze(signals)
    
    final_score = max(0, min(100, base_score + correlation_bonus))
    
    return {
        "base_score": base_score,
        "correlation_bonus": correlation_bonus,
        "final_score": final_score,
        "applied_rules": applied_rules,
        "patterns": patterns,
        "explanation": engine.explain_correlation(applied_rules)
    }
