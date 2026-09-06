"""
PhishShield TR - Confidence Engine
Sprint 7.3: Separates risk assessment from decision confidence

Purpose:
- Risk Score: How dangerous does this look? (0-100)
- Confidence: How sure are we about this assessment? (0-99%)

Examples:
- Garanti phishing: Risk=92, Confidence=97% → DANGER (sure)
- Unknown blog with phone: Risk=45, Confidence=25% → CAUTION (unsure)
- ChatGPT: Risk=0, Confidence=99% → SAFE (very sure)
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum

from ml.features import SiteFeatures, ThreatLevel


class ConfidenceLevel(Enum):
    """Confidence levels for decisions"""
    VERY_HIGH = "very_high"  # 90-99%
    HIGH = "high"           # 70-89%
    MEDIUM = "medium"       # 50-69%
    LOW = "low"             # 30-49%
    VERY_LOW = "very_low"   # 0-29%


@dataclass
class ConfidenceResult:
    """Result of confidence assessment"""
    risk_score: int
    confidence: int
    confidence_level: ConfidenceLevel

    decision: str
    decision_reason: str

    factors: List[str]
    evidence: List[str]

    needs_more_analysis: bool
    recommendation: str


class ConfidenceEngine:
    """
    Confidence Engine

    Separates WHAT we think (risk score) from HOW SURE we are (confidence).

    Key principle:
    - High risk + High confidence = DANGER
    - High risk + Low confidence = Needs more analysis
    - Low risk + High confidence = SAFE
    - Medium risk + Medium confidence = CAUTION
    """

    CONFIDENCE_THRESHOLDS = {
        ConfidenceLevel.VERY_HIGH: 90,
        ConfidenceLevel.HIGH: 70,
        ConfidenceLevel.MEDIUM: 50,
        ConfidenceLevel.LOW: 30,
        ConfidenceLevel.VERY_LOW: 0,
    }

    RISK_THRESHOLDS = {
        "safe_max": 25,
        "caution_max": 50,
        "danger_min": 70,
    }

    def assess(
        self,
        fusion_result,
        features: SiteFeatures
    ) -> ConfidenceResult:
        """
        Assess confidence in the decision.

        Args:
            fusion_result: Result from FusionEngine
            features: SiteFeatures for detailed analysis

        Returns:
            ConfidenceResult with detailed confidence breakdown
        """
        risk_score = fusion_result.final_score
        confidence = fusion_result.confidence

        # Determine confidence level
        confidence_level = self._get_confidence_level(confidence)

        # Analyze confidence factors
        factors = self._analyze_confidence_factors(fusion_result, features)

        # Build evidence list
        evidence = self._build_evidence(fusion_result, features)

        # Determine if more analysis needed
        needs_more = self._needs_more_analysis(
            risk_score, confidence, features, factors
        )

        # Make final decision with confidence
        decision, reason = self._make_confident_decision(
            risk_score, confidence, features
        )

        # Build recommendation
        recommendation = self._build_recommendation(
            decision, risk_score, confidence, needs_more
        )

        return ConfidenceResult(
            risk_score=risk_score,
            confidence=confidence,
            confidence_level=confidence_level,
            decision=decision,
            decision_reason=reason,
            factors=factors,
            evidence=evidence,
            needs_more_analysis=needs_more,
            recommendation=recommendation
        )

    def _get_confidence_level(self, confidence: int) -> ConfidenceLevel:
        """Determine confidence level from percentage"""
        if confidence >= 90:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 70:
            return ConfidenceLevel.HIGH
        elif confidence >= 50:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 30:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.VERY_LOW

    def _analyze_confidence_factors(
        self,
        fusion_result,
        features: SiteFeatures
    ) -> List[str]:
        """Analyze what factors affect confidence"""
        factors = []

        # Threat intel match increases confidence significantly
        if features.threat.matched:
            factors.append(f"Tehdit veritabani eslesmesi ({features.threat.source})")
            factors.append(f"Tehdit guvenilirligi: {int(features.threat.confidence * 100)}%")

        # Multiple high-scoring components = higher confidence
        high_components = 0
        if fusion_result.threat_score > 70:
            high_components += 1
        if fusion_result.brand_score > 70:
            high_components += 1
        if fusion_result.form_score > 70:
            high_components += 1

        if high_components >= 2:
            factors.append(f"Coklu tehdit isareti ({high_components} adet)")
        elif high_components == 0 and fusion_result.final_score < 40:
            factors.append("Dusuk tehdit profili")

        # Brand impersonation with similarity = higher confidence
        if features.brand.is_impostor:
            factors.append(f"Marka taklidi tespit edildi ({features.brand.brand_name})")
            if features.brand.similarity_score > 0.8:
                factors.append("Yuksek benzerlik orani")

        # External submit with credentials = very high confidence
        if features.form.has_external_submit and features.form.has_credential_fields:
            factors.append("Harici adrese kimlik gonderimi")

        # New domain + brand = suspicious
        if features.domain_features.is_new_domain and features.brand.is_impostor:
            factors.append("Yeni domain + marka taklidi")

        # Known trusted platform = very high confidence
        if features.trust_fast_path or features.is_trusted:
            factors.append("Guvenilir platform dogrulandi")

        # Low signal count = lower confidence
        if len(features.analysis_signals) < 3:
            factors.append("Az sinyal - düsük guven")

        return factors

    def _build_evidence(
        self,
        fusion_result,
        features: SiteFeatures
    ) -> List[str]:
        """Build list of evidence supporting the assessment"""
        evidence = []

        # Positive evidence (reduces risk)
        if features.is_trusted or features.trust_fast_path:
            evidence.append("[+] Guvenilir platform")

        if features.threat.matched:
            evidence.append(f"[+] Tehdit veritabaninda bulundu ({features.threat.source})")

        # Negative evidence (increases risk)
        if features.brand.is_impostor:
            evidence.append(f"[-] Marka taklidi: {features.brand.brand_name}")

        if features.form.has_external_submit:
            evidence.append("[-] Form harici adrese gonderiyor")

        if features.domain_features.is_suspicious_tld:
            evidence.append(f"[-] Supheli TLD: {features.domain_features.tld}")

        if features.domain_features.is_new_domain:
            evidence.append("[-] Yeni kayitli domain")

        if features.content.has_urgency:
            evidence.append("[-] Aciliyet hissettirme")

        if features.content.has_sms_style:
            evidence.append("[-] SMS phishing sablonu")

        return evidence

    def _needs_more_analysis(
        self,
        risk_score: int,
        confidence: int,
        features: SiteFeatures,
        factors: List[str]
    ) -> bool:
        """Determine if more analysis is needed"""
        # High risk but low confidence = need more
        if risk_score >= 50 and confidence < 50:
            return True

        # Medium risk with very low confidence
        if 30 <= risk_score <= 60 and confidence < 30:
            return True

        # Unknown domain with brand name present
        if features.domain_features.is_new_domain and features.brand.is_impostor:
            if confidence < 60:
                return True

        # Suspicious but no clear pattern
        if risk_score >= 40 and len(factors) < 2:
            return True

        return False

    def _make_confident_decision(
        self,
        risk_score: int,
        confidence: int,
        features: SiteFeatures
    ) -> tuple:
        """Make decision considering both risk and confidence"""
        confidence_level = self._get_confidence_level(confidence)

        # === CERTAIN CASES ===

        # Very high confidence + high risk = definitely danger
        if confidence_level in [ConfidenceLevel.VERY_HIGH, ConfidenceLevel.HIGH]:
            if risk_score >= self.RISK_THRESHOLDS["danger_min"]:
                return "DANGER", "Yuksel risk + yuksek guvenilirlik"

            if risk_score <= self.RISK_THRESHOLDS["safe_max"]:
                return "SAFE", "Dusuk risk + yuksek guvenilirlik"

        # Very low confidence in either direction
        if confidence_level == ConfidenceLevel.VERY_LOW:
            if risk_score >= 60:
                return "CAUTION", "Yuksel risk ama dusunuk guvenilirlik"
            return "SAFE", "Dusuk guvenilirlik ama tehdit yok"

        # === UNCERTAIN CASES ===

        # High risk + low/medium confidence
        if risk_score >= self.RISK_THRESHOLDS["danger_min"]:
            if confidence_level in [ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW]:
                return "CAUTION", "Yuksel risk gorunuyor ama daha fazla analiz lazim"

        # Medium risk
        if self.RISK_THRESHOLDS["safe_max"] < risk_score <= self.RISK_THRESHOLDS["caution_max"]:
            if confidence_level == ConfidenceLevel.LOW:
                return "CAUTION", "Belirsiz risk + dusunuk guvenilirlik"

        # === DEFAULT CASES ===
        if risk_score >= self.RISK_THRESHOLDS["danger_min"]:
            return "DANGER", "Yuksel risk skoru"

        if risk_score <= self.RISK_THRESHOLDS["safe_max"]:
            return "SAFE", "Dusuk risk skoru"

        return "CAUTION", "Orta risk seviyesi"

    def _build_recommendation(
        self,
        decision: str,
        risk_score: int,
        confidence: int,
        needs_more: bool
    ) -> str:
        """Build actionable recommendation"""
        if needs_more:
            return "Daha fazla analiz gerekiyor"

        if decision == "SAFE":
            if confidence >= 90:
                return "Site guvenli gorunuyor - yuksek guvenilirlik"
            return "Site guvenli gorunuyor"

        if decision == "DANGER":
            if confidence >= 90:
                return "WARNING: Tehlikeli site tespit edildi - bilgilerinizi girmeyin"
            return "WARNING: Dikkat - site tehlikeli olabilir"

        return "Dikkatli olun - site tam olarak dogrulanamadi"


# Singleton instance
confidence_engine = ConfidenceEngine()
