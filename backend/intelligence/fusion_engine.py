"""
PhishShield TR - Intelligence Fusion Engine
Sprint 7.2: Combines all analysis sources into unified risk assessment

Purpose:
- Weighted combination of all detection engines
- Rule-based + ML-ready scoring
- Clear separation of threat sources
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from enum import Enum

from ml.features import SiteFeatures, ThreatLevel


class ThreatSource(Enum):
    """Analysis threat sources with weights"""
    THREAT_INTEL = "threat_intel"
    BRAND_IMPERSONATION = "brand"
    FORM_BEHAVIOR = "form"
    DOMAIN_INTELLIGENCE = "domain"
    CONTENT_SIGNALS = "content"
    RULE_ENGINE = "rule"


@dataclass
class FusionResult:
    """Result of fusion engine analysis"""
    final_score: int
    decision: str  # SAFE, CAUTION, DANGER
    confidence: int
    threat_level: ThreatLevel

    # Component scores
    threat_score: int
    brand_score: int
    form_score: int
    domain_score: int
    content_score: int
    rule_score: int

    # Weights used
    weights: Dict[str, float]

    # Details
    indicators: List[str]
    threat_patterns: List[str]
    recommendations: List[str]

    # Feature reference
    features: Optional[SiteFeatures] = None


class FusionEngine:
    """
    Intelligence Fusion Engine

    Combines all detection sources with weighted scoring.

    Default weights (can be adjusted):
    - Threat Intel: 35% (highest - known threats)
    - Brand Impersonation: 25%
    - Form Behavior: 20%
    - Domain Intelligence: 10%
    - Content Signals: 10%
    """

    DEFAULT_WEIGHTS = {
        ThreatSource.THREAT_INTEL: 0.35,
        ThreatSource.BRAND_IMPERSONATION: 0.25,
        ThreatSource.FORM_BEHAVIOR: 0.20,
        ThreatSource.DOMAIN_INTELLIGENCE: 0.10,
        ThreatSource.CONTENT_SIGNALS: 0.10,
    }

    THRESHOLDS = {
        "safe_max": 25,
        "caution_max": 50,
        "danger_min": 70
    }

    def __init__(self, weights: Dict[str, float] = None):
        """
        Initialize Fusion Engine.

        Args:
            weights: Custom weights for threat sources.
                    If None, uses DEFAULT_WEIGHTS.
        """
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()

    def fuse(self, features: SiteFeatures) -> FusionResult:
        """
        Fuse all features into final risk assessment.

        Args:
            features: SiteFeatures from FeatureCollector

        Returns:
            FusionResult with final score and decision
        """
        # Fast path for trusted platforms
        if features.trust_fast_path or features.is_trusted:
            return self._build_trusted_result(features)

        # Calculate component scores
        threat_score = self._calculate_threat_score(features)
        brand_score = self._calculate_brand_score(features)
        form_score = self._calculate_form_score(features)
        domain_score = self._calculate_domain_score(features)
        content_score = self._calculate_content_score(features)
        rule_score = self._calculate_rule_score(features)

        # Weighted fusion
        final_score = self._fuse_scores(
            threat_score, brand_score, form_score,
            domain_score, content_score, rule_score
        )

        # Boost for critical patterns
        final_score = self._apply_pattern_boost(
            final_score, features, threat_score,
            brand_score, form_score
        )

        # Calculate confidence
        confidence = self._calculate_confidence(
            features, threat_score, brand_score,
            form_score, domain_score, content_score
        )

        # Determine threat level
        threat_level = self._get_threat_level(final_score, confidence)

        # Make decision
        decision = self._make_decision(final_score, confidence, features)

        # Build indicators and patterns
        indicators = self._build_indicators(features, threat_score, brand_score, form_score)
        threat_patterns = self._build_threat_patterns(features)
        recommendations = self._build_recommendations(decision, features)

        return FusionResult(
            final_score=final_score,
            decision=decision,
            confidence=confidence,
            threat_level=threat_level,
            threat_score=threat_score,
            brand_score=brand_score,
            form_score=form_score,
            domain_score=domain_score,
            content_score=content_score,
            rule_score=rule_score,
            weights=self.weights,
            indicators=indicators,
            threat_patterns=threat_patterns,
            recommendations=recommendations,
            features=features
        )

    def _build_trusted_result(self, features: SiteFeatures) -> FusionResult:
        """Build result for trusted platforms"""
        return FusionResult(
            final_score=0,
            decision="SAFE",
            confidence=99,
            threat_level=ThreatLevel.NONE,
            threat_score=0,
            brand_score=0,
            form_score=0,
            domain_score=0,
            content_score=0,
            rule_score=0,
            weights=self.weights,
            indicators=["trusted_platform"],
            threat_patterns=[],
            recommendations=["Güvenilir platform doğrulandı"],
            features=features
        )

    def _calculate_threat_score(self, features: SiteFeatures) -> int:
        """Calculate score from threat intelligence"""
        if features.threat.matched:
            # Base score + confidence multiplier
            base = 100
            confidence_mult = features.threat.confidence

            # Source credibility bonus
            source_bonus = self._get_source_bonus(features.threat.source)

            return min(100, int(base * confidence_mult) + source_bonus)

        return 0

    def _get_source_bonus(self, source: Optional[str]) -> int:
        """Get bonus score for threat source"""
        bonuses = {
            "usom": 20,
            "openphish": 15,
            "urlhaus": 10,
            "phishTank": 10,
        }
        return bonuses.get(source.lower() if source else "", 5)

    def _calculate_brand_score(self, features: SiteFeatures) -> int:
        """Calculate score from brand impersonation detection"""
        if features.brand.is_impostor:
            base = 70

            # Similarity bonus
            similarity_bonus = int(features.brand.similarity_score * 20)

            # Category bonus (banking/government = higher risk)
            category_mult = self._get_category_multiplier(features.brand.brand_category)

            return min(100, base + similarity_bonus + category_mult)

        return 0

    def _get_category_multiplier(self, category: Optional[str]) -> int:
        """Get risk multiplier for brand category"""
        multipliers = {
            "BANKING": 20,
            "GOVERNMENT": 20,
            "PAYMENT": 15,
            "ECOMMERCE": 10,
            "CARGO": 10,
        }
        return multipliers.get(category, 5)

    def _calculate_form_score(self, features: SiteFeatures) -> int:
        """Calculate score from form behavior analysis"""
        score = 0

        if features.form.has_external_submit:
            score += 40

        if features.form.has_password_field:
            score += 25

        if features.form.has_credential_fields:
            score += 20

        if features.form.has_payment_fields:
            score += 30

        if features.form.hidden_field_count > 0:
            score += 15

        if features.form.form_risk_score > 50:
            score = max(score, features.form.form_risk_score)

        return min(100, score)

    def _calculate_domain_score(self, features: SiteFeatures) -> int:
        """Calculate score from domain intelligence"""
        score = 0

        # Suspicious TLD
        if features.domain_features.is_suspicious_tld:
            score += 25

        # New domain
        if features.domain_features.is_new_domain:
            score += 30

        # IP-based domain
        if features.domain_features.is_ip_based:
            score += 40

        # Punycode
        if features.domain_features.is_punycode:
            score += 50

        # Excessive subdomains
        if features.domain_features.subdomain_count > 3:
            score += 20

        # Many hyphens (suspicious pattern)
        if features.domain_features.hyphen_count > 3:
            score += 15

        return min(100, score)

    def _calculate_content_score(self, features: SiteFeatures) -> int:
        """Calculate score from content signals"""
        score = 0

        # Urgency
        if features.content.has_urgency:
            score += 20

        # SMS style (high risk)
        if features.content.has_sms_style:
            score += 30

        # Many bank keywords
        if features.content.bank_word_count > 3:
            score += 25

        # Many cargo keywords
        if features.content.cargo_word_count > 2:
            score += 20

        # Reward/lottery keywords
        if features.content.reward_word_count > 2:
            score += 30

        # Obfuscation
        if features.content.has_obfuscation:
            score += 25

        return min(100, score)

    def _calculate_rule_score(self, features: SiteFeatures) -> int:
        """Calculate score from correlation rules"""
        score = 0

        # Applied rules bonus
        if features.applied_rules:
            score += len(features.applied_rules) * 15

        # Correlation bonus from analysis
        if features.correlation_bonus > 0:
            score = max(score, features.correlation_bonus)

        return min(100, score)

    def _fuse_scores(
        self,
        threat: int,
        brand: int,
        form: int,
        domain: int,
        content: int,
        rule: int
    ) -> int:
        """Fuse component scores using weighted average"""
        weighted_sum = (
            threat * self.weights.get(ThreatSource.THREAT_INTEL, 0.35) +
            brand * self.weights.get(ThreatSource.BRAND_IMPERSONATION, 0.25) +
            form * self.weights.get(ThreatSource.FORM_BEHAVIOR, 0.20) +
            domain * self.weights.get(ThreatSource.DOMAIN_INTELLIGENCE, 0.10) +
            content * self.weights.get(ThreatSource.CONTENT_SIGNALS, 0.10)
        )

        # Add rule score (flat bonus)
        final = weighted_sum + rule * 0.05

        return min(100, int(final))

    def _apply_pattern_boost(
        self,
        base_score: int,
        features: SiteFeatures,
        threat: int,
        brand: int,
        form: int
    ) -> int:
        """Apply boost for critical attack patterns"""
        score = base_score

        # Bank/Government impersonation + password field = high risk
        if features.brand.is_impostor and features.form.has_password_field:
            if features.brand.brand_category in ["BANKING", "GOVERNMENT", "PAYMENT"]:
                score = max(score, 75)

        # Credential harvest with external submit
        if features.form.has_credential_fields and features.form.has_external_submit:
            score = max(score, 80)

        # High brand score alone should push score up
        if brand >= 70:
            score = max(score, int(brand * 0.7))

        # High form score with external submit
        if form >= 50 and features.form.has_external_submit:
            score = max(score, 70)

        return min(100, score)

    def _calculate_confidence(
        self,
        features: SiteFeatures,
        threat: int,
        brand: int,
        form: int,
        domain: int,
        content: int
    ) -> int:
        """
        Calculate confidence in the decision.

        Higher confidence when:
        - Threat intel match (high certainty)
        - Multiple independent sources agree
        - Strong brand impersonation signals
        """
        confidence = 50  # Base confidence

        # Threat intel match increases confidence significantly
        if features.threat.matched:
            confidence += 30
            confidence += int(features.threat.confidence * 20)

        # Multiple high scores = higher confidence
        high_scores = sum(1 for s in [threat, brand, form, domain, content] if s > 50)
        confidence += high_scores * 10

        # Known phishing patterns
        if features.brand.is_impostor and features.form.has_external_submit:
            confidence += 20

        # Low signal count = lower confidence
        if len(features.analysis_signals) < 3:
            confidence -= 10

        return min(99, max(20, confidence))

    def _get_threat_level(self, score: int, confidence: int) -> ThreatLevel:
        """Determine threat level"""
        if score >= 80 and confidence >= 70:
            return ThreatLevel.CRITICAL
        elif score >= 60 and confidence >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 20:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def _make_decision(self, score: int, confidence: int, features: SiteFeatures) -> str:
        """Make final decision"""
        # Hard overrides
        if features.threat.matched and features.threat.confidence > 0.8:
            return "DANGER"

        if score >= self.THRESHOLDS["danger_min"]:
            return "DANGER"

        # Brand impersonation + form risk = DANGER (high confidence)
        if features.brand.is_impostor and features.form.has_password_field:
            if features.brand.brand_category in ["BANKING", "GOVERNMENT", "PAYMENT"]:
                return "DANGER"

        # Credential harvesting with external submit
        if features.form.has_credential_fields and features.form.has_external_submit:
            return "DANGER"

        if score <= self.THRESHOLDS["safe_max"]:
            if confidence < 40:
                return "SAFE"
            return "CAUTION"

        if score <= self.THRESHOLDS["caution_max"]:
            if confidence >= 70:
                return "DANGER"
            return "CAUTION"

        return "CAUTION"

    def _build_indicators(
        self,
        features: SiteFeatures,
        threat: int,
        brand: int,
        form: int
    ) -> List[str]:
        """Build list of threat indicators"""
        indicators = []

        if features.threat.matched:
            indicators.append(f"Tehdit eslesmesi: {features.threat.source}")

        if features.brand.is_impostor:
            indicators.append(f"Marka taklidi: {features.brand.brand_name}")

        if features.form.has_external_submit:
            indicators.append("Form harici adrese gonderiyor")

        if features.domain_features.is_suspicious_tld:
            indicators.append(f"Supheli TLD: {features.domain_features.tld}")

        if features.domain_features.is_new_domain:
            indicators.append("Yeni domain")

        if features.content.has_urgency:
            indicators.append("Aciliyet hissettirme")

        return indicators

    def _build_threat_patterns(self, features: SiteFeatures) -> List[str]:
        """Build threat pattern descriptions"""
        patterns = []

        # Bank phishing
        if features.brand.is_impostor and features.brand.brand_category == "BANKING":
            if features.form.has_password_field:
                patterns.append("Banka kimlik avı")

        # Credential harvesting
        if features.form.has_credential_fields and features.form.has_external_submit:
            patterns.append("Kimlik bilgi toplama")

        # Cargo scam
        if features.brand.brand_category == "CARGO":
            if features.form.has_payment_fields:
                patterns.append("Kargo dolandırıcılığı")

        return patterns

    def _build_recommendations(self, decision: str, features: SiteFeatures) -> List[str]:
        """Build actionable recommendations"""
        if decision == "SAFE":
            return ["Site guvenli gorunuyor"]

        recommendations = []

        if decision == "DANGER":
            recommendations.append("⚠️ Dikkat - tehlikeli site olabilir")
            recommendations.append("Bilgilerinizi girmeyin")

        if features.brand.is_impostor:
            recommendations.append(f"'{features.brand.brand_name}' taklit ediliyor")

        if features.form.has_external_submit:
            recommendations.append("Form verisi baskasina gidiyor")

        if features.threat.matched:
            recommendations.append("Tehdit veritabaninda bulundu")

        return recommendations if recommendations else ["Dikkatli olun"]


# Singleton instance
fusion_engine = FusionEngine()
