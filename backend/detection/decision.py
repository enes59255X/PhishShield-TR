"""
PhishShield TR - Decision Engine
Determines final decision (SAFE/CAUTION/DANGER) based on all signals and analysis
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from detection.signals import SIGNAL_DEFINITIONS, SignalSeverity
from threat_intel.models import ThreatMatch

class Decision(Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DANGER = "DANGER"

@dataclass
class DecisionResult:
    decision: Decision
    confidence: int
    risk_score: int
    reasoning: List[str]
    threat_patterns: List[str]
    recommendations: List[str]
    technical_details: Dict

RISK_THRESHOLDS = {
    "safe_max": 19,
    "caution_max": 39,
    "danger_min": 70
}

CONFIDENCE_WEIGHTS = {
    SignalSeverity.CRITICAL: 40,
    SignalSeverity.HIGH: 25,
    SignalSeverity.MEDIUM: 10,
    SignalSeverity.LOW: 3
}

class DecisionEngine:
    def __init__(self):
        self.decision = None
        self.confidence = 0
        self.reasoning = []
        self.threat_patterns = []
        
    def make_decision(
        self,
        risk_score: int,
        signals: List[str],
        correlation_bonus: int,
        applied_rules: List[str],
        brand_match: bool = False,
        known_safe: bool = False,
        usom_listed: bool = False,
        threat_match: Optional[ThreatMatch] = None
    ) -> DecisionResult:
        
        self.reasoning = []
        self.threat_patterns = []
        confidence_factors = []
        
        # === 1. HARD OVERRIDES ===
        
        # Threat Intelligence match (OpenPhish, URLhaus, etc.)
        if threat_match and threat_match.is_threat:
            source_bonus = SIGNAL_DEFINITIONS.get("threat_intel_match", {}).get("threat_intel_bonus", {}).get(threat_match.source, 35)
            confidence = 50 + source_bonus
            
            source_name = threat_match.source.upper() if threat_match.source else "Tehdit Veritabani"
            return DecisionResult(
                decision=Decision.DANGER,
                confidence=min(99, confidence),
                risk_score=100,
                reasoning=[f"{source_name} tehdit veritabaninda bulundu", f"Tehdit kategorisi: {threat_match.category}"],
                threat_patterns=[f"🚨 {source_name} Zararli Domain"],
                recommendations=["Bu site tehlikeli bulundu", "Bilgilerinizi girmeyiniz", "Sayfayı kapatin"],
                technical_details={
                    "threat_match": threat_match.to_dict(),
                    "override": True,
                    "confidence_breakdown": {"base": 50, "source_bonus": source_bonus}
                }
            )
        
        if usom_listed:
            return DecisionResult(
                decision=Decision.DANGER,
                confidence=100,
                risk_score=100,
                reasoning=["USOM bilinen zararli listen", "Otomatik tehlikeli karari"],
                threat_patterns=["🚨 USOM Zararli Domain"],
                recommendations=["Bu site USOM tarafindan engellenmistir", "Girmeyiniz"],
                technical_details={"usom_listed": True, "override": True}
            )
        
        if known_safe:
            return DecisionResult(
                decision=Decision.SAFE,
                confidence=95,
                risk_score=0,
                reasoning=["Bilinen guvenli domain", "Otomatik guvenli karari"],
                threat_patterns=[],
                recommendations=["Bu site guvenilir"],
                technical_details={"known_safe": True, "override": True}
            )
        
        # === 2. SIGNAL-BASED CONFIDENCE ===
        severity_counts = {s: 0 for s in SignalSeverity}
        for signal in signals:
            sev = SIGNAL_DEFINITIONS.get(signal, {}).get("severity", SignalSeverity.LOW)
            severity_counts[sev] += 1
        
        confidence = 0
        for severity, count in severity_counts.items():
            confidence += count * CONFIDENCE_WEIGHTS[severity]
        confidence = min(100, confidence)
        
        # === 3. BRAND MISMATCH CHECK ===
        if brand_match and any(s in signals for s in ["domain_mismatch", "typosquatting", "suspicious_domain"]):
            confidence += 30
            self.reasoning.append("Marka taklidi + domain uyusmazligi tespit edildi")
            self.threat_patterns.append("🚨 Marka taklitli sahte site")
        
        # === 4. CORRELATION PATTERNS ===
        if applied_rules:
            for rule in applied_rules:
                if "phishing" in rule.lower() or "credential" in rule.lower():
                    confidence += 25
                    self.threat_patterns.append(f"🚨 {rule}")
        
        # === 5. FINAL DECISION ===
        decision = self._determine_decision(risk_score, confidence, signals)
        
        # === 6. REASONING ===
        self._build_reasoning(signals, risk_score, brand_match)
        
        # === 7. RECOMMENDATIONS ===
        recommendations = self._get_recommendations(decision, signals)
        
        confidence = min(100, confidence)
        
        return DecisionResult(
            decision=decision,
            confidence=confidence,
            risk_score=risk_score,
            reasoning=self.reasoning,
            threat_patterns=self.threat_patterns,
            recommendations=recommendations,
            technical_details={
                "signal_count": len(signals),
                "severity_breakdown": {s.value: c for s, c in severity_counts.items()},
                "correlation_rules_applied": applied_rules,
                "confidence_breakdown": confidence_factors
            }
        )
    
    def _determine_decision(self, risk_score: int, confidence: int, signals: List[str]) -> Decision:
        """Determine final decision based on score and confidence"""
        
        critical_signals = ["usom_listed", "known_phishing_domain", "credential_harvesting_external_post"]
        has_critical = any(s in signals for s in critical_signals)
        
        if has_critical or risk_score >= RISK_THRESHOLDS["danger_min"]:
            return Decision.DANGER
        
        if risk_score <= RISK_THRESHOLDS["safe_max"]:
            if confidence < 30:
                return Decision.SAFE
            elif confidence < 60:
                return Decision.CAUTION
        
        if risk_score <= RISK_THRESHOLDS["caution_max"]:
            if confidence >= 70:
                return Decision.DANGER
            return Decision.CAUTION
        
        return Decision.CAUTION
    
    def _build_reasoning(self, signals: List[str], risk_score: int, brand_match: bool):
        """Build human-readable reasoning"""
        
        if risk_score >= 70:
            self.reasoning.append(f"Yuksek risk skoru ({risk_score})")
        
        critical_found = [s for s in signals if SIGNAL_DEFINITIONS.get(s, {}).get("severity") == SignalSeverity.CRITICAL]
        if critical_found:
            for sig in critical_found[:2]:
                desc = SIGNAL_DEFINITIONS.get(sig, {}).get("description", "")
                self.reasoning.append(f"Kritik: {desc}")
        
        high_found = [s for s in signals if SIGNAL_DEFINITIONS.get(s, {}).get("severity") == SignalSeverity.HIGH]
        if high_found:
            for sig in high_found[:3]:
                desc = SIGNAL_DEFINITIONS.get(sig, {}).get("description", "")
                self.reasoning.append(f"Onemli: {desc}")
        
        if brand_match:
            self.reasoning.append("Marka eslesmesi pozitif")
    
    def _get_recommendations(self, decision: Decision, signals: List[str]) -> List[str]:
        """Get actionable recommendations based on decision"""
        
        recommendations = []
        
        if decision == Decision.SAFE:
            recommendations = [
                "Site guvenli gorunuyor",
                "Bilgilerinizi girebilirsiniz"
            ]
        
        elif decision == Decision.CAUTION:
            recommendations = [
                "Dikkatli olun",
                "URL'yi kontrol edin",
                "Sifre girmeden once emin olun"
            ]
            if any("external_post" in s for s in signals):
                recommendations.append("Form verisi baskasina gidiyor - dikkat!")
        
        else:  # DANGER
            recommendations = [
                "⚠️ Bu site tehlikeli gorunuyor",
                "Bilgilerinizi girmeyin",
                "Siteyi hemen kapatin"
            ]
        
        return recommendations


def make_final_decision(
    risk_score: int,
    signals: List[str],
    correlation_bonus: int = 0,
    applied_rules: List[str] = None,
    brand_match: bool = False,
    known_safe: bool = False,
    usom_listed: bool = False,
    threat_match: Optional[ThreatMatch] = None
) -> DecisionResult:
    """Main entry point for decision making"""
    
    engine = DecisionEngine()
    return engine.make_decision(
        risk_score=risk_score,
        signals=signals,
        correlation_bonus=correlation_bonus,
        applied_rules=applied_rules or [],
        brand_match=brand_match,
        known_safe=known_safe,
        usom_listed=usom_listed,
        threat_match=threat_match
    )
