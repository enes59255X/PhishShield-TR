"""
PhishShield TR - Hybrid Analyzer
Sprint 10: Combines Rule-based Fusion Engine with ML Model

Purpose:
- Combine fusion score with ML prediction
- Override with threat intel for known threats
- Provide unified confidence scoring
"""

import os
import pickle
from dataclasses import dataclass
from typing import Optional, Dict, Any

import numpy as np

from ml.feature_schema import FeatureVector, FeatureSchema
from ml.explainer import ml_explainer
from ml.trainer import ModelTrainer
from intelligence.fusion_engine import FusionResult


@dataclass
class HybridResult:
    """
    Result from hybrid analysis combining Fusion Engine and ML.
    """
    # Scores
    fusion_score: int           # From rule-based fusion engine (0-100)
    ml_probability: float      # From ML model (0.0-1.0)
    ml_confidence: float       # ML model's confidence (0.0-1.0)
    final_score: int           # Combined final score (0-100)

    # Decision
    decision: str              # SAFE, CAUTION, DANGER
    confidence: int            # Overall confidence (0-99%)
    confidence_level: str       # VERY_HIGH, HIGH, MEDIUM, LOW, VERY_LOW

    # Details
    threat_override: bool       # True if threat intel override applied
    fusion_contribution: float # Weight of fusion in final score
    ml_contribution: float     # Weight of ML in final score

    # Component scores
    component_scores: Dict[str, int]

    # Recommendation
    recommendation: str
    reasons: list

    # Explanations (Sprint 12)
    explanation: Optional[str] = None  # Human-readable explanation


class HybridAnalyzer:
    """
    Hybrid Analyzer

    Combines:
    1. Rule-based Fusion Engine (domain expertise)
    2. ML RandomForest Model (pattern recognition)

    Formula:
        Final Score = (Fusion Score × 0.70) + (ML Score × 0.30)

    Threat Intel Override:
        If threat_matched == True: Final = 100, Decision = DANGER
    """

    # Weights for combining scores
    FUSION_WEIGHT = 0.70
    ML_WEIGHT = 0.30

    # Threat intel override threshold
    THREAT_OVERRIDE = True  # Always override on known threats

    # Decision thresholds
    SAFE_THRESHOLD = 25
    CAUTION_THRESHOLD = 60
    DANGER_THRESHOLD = 75

    def __init__(self, model_path: str = None):
        """
        Initialize Hybrid Analyzer.

        Args:
            model_path: Path to trained ML model
        """
        if model_path is None:
            model_path = os.path.join(
                os.path.dirname(__file__),
                "models",
                "phishing_rf.pkl"
            )
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self) -> bool:
        """Load ML model from disk"""
        if not os.path.exists(self.model_path):
            print(f"Model not found at {self.model_path}")
            print("Training new model...")
            return self._train_model()

        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            print(f"ML model loaded from {self.model_path}")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return self._train_model()

    def _train_model(self) -> bool:
        """Train new model if none available"""
        try:
            trainer = ModelTrainer(self.model_path)
            trainer.train(n_samples=5000)
            trainer.save_model()
            self.model = trainer.model
            return True
        except ImportError:
            print("scikit-learn not installed. ML analysis disabled.")
            return False

    def analyze(
        self,
        fusion_result: FusionResult,
        features
    ) -> HybridResult:
        """
        Perform hybrid analysis.

        Args:
            fusion_result: Result from FusionEngine
            features: SiteFeatures object

        Returns:
            HybridResult with combined analysis
        """
        # Check for threat intel override
        threat_override = self._check_threat_override(fusion_result, features)

        # Get ML probability
        ml_probability, ml_confidence = self._get_ml_prediction(features)

        # Calculate final score
        if threat_override:
            final_score = 100
            fusion_contribution = 1.0
            ml_contribution = 0.0
        else:
            ml_score = int(ml_probability * 100)
            final_score = int(
                (fusion_result.final_score * self.FUSION_WEIGHT) +
                (ml_score * self.ML_WEIGHT)
            )
            fusion_contribution = self.FUSION_WEIGHT
            ml_contribution = self.ML_WEIGHT

        # Make decision
        decision, recommendation = self._make_decision(
            final_score, ml_probability, threat_override
        )

        # Calculate confidence
        confidence = self._calculate_confidence(
            fusion_result, ml_confidence, threat_override
        )

        # Build reasons
        reasons = self._build_reasons(fusion_result, features, ml_probability)

        # Component scores dict for explanations
        component_scores_dict = {
            "threat": fusion_result.threat_score,
            "brand": fusion_result.brand_score,
            "form": fusion_result.form_score,
            "domain": fusion_result.domain_score,
            "content": fusion_result.content_score,
        }

        # Generate explanation (Sprint 12)
        explanation = self._generate_explanation(
            decision, final_score, fusion_result.final_score,
            ml_probability, ml_confidence, component_scores_dict, features, reasons
        )

        return HybridResult(
            fusion_score=fusion_result.final_score,
            ml_probability=ml_probability,
            ml_confidence=ml_confidence,
            final_score=min(100, final_score),
            decision=decision,
            confidence=confidence,
            confidence_level=self._get_confidence_level(confidence),
            threat_override=threat_override,
            fusion_contribution=fusion_contribution,
            ml_contribution=ml_contribution,
            component_scores=component_scores_dict,
            recommendation=recommendation,
            reasons=reasons,
            explanation=explanation
        )

    def _check_threat_override(self, fusion_result: FusionResult, features) -> bool:
        """Check if threat intel override should apply"""
        if not self.THREAT_OVERRIDE:
            return False

        # Override if known threat in database
        if hasattr(features, 'threat') and features.threat.matched:
            if features.threat.source in ['usom', 'openphish', 'urlhaus', 'phishTank']:
                return True

        return False

    def _get_ml_prediction(self, features) -> tuple:
        """
        Get ML model prediction.

        Returns:
            Tuple of (probability, confidence)
        """
        if self.model is None:
            return 0.5, 0.5

        try:
            # Create feature vector
            feature_vec = FeatureVector.from_site_features(features)
            X = feature_vec.to_array()

            # Get prediction
            proba = self.model.predict_proba(X)[0]

            # probability of phishing (class 1)
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

            # Get confidence (max probability)
            confidence = float(max(proba))

            return phishing_prob, confidence

        except Exception as e:
            print(f"ML prediction error: {e}")
            return 0.5, 0.5

    def _make_decision(
        self,
        final_score: int,
        ml_probability: float,
        threat_override: bool
    ) -> tuple:
        """Make final decision"""
        if threat_override:
            return "DANGER", "Bilinen tehdit: Site tehdit veritabaninda bulundu"

        if final_score >= self.DANGER_THRESHOLD:
            return "DANGER", " Yuksek risk tespit edildi - dikkatli olun"

        if final_score >= self.CAUTION_THRESHOLD:
            if ml_probability > 0.8:
                return "DANGER", " ML modeli yuksek phishing olasiligi bildirdi"
            return "CAUTION", " Orta-yuksek risk - dikkatli olun"

        if final_score >= self.SAFE_THRESHOLD:
            return "CAUTION", " Supheli ozellikler tespit edildi"

        return "SAFE", " Site guvenli gorunuyor"

    def _calculate_confidence(
        self,
        fusion_result: FusionResult,
        ml_confidence: float,
        threat_override: bool
    ) -> int:
        """Calculate overall confidence"""
        if threat_override:
            return 99

        # Base confidence from fusion
        fusion_confidence = fusion_result.confidence

        # Combine with ML confidence
        combined = (fusion_confidence * 0.6) + (ml_confidence * 100 * 0.4)

        return min(99, max(20, int(combined)))

    def _get_confidence_level(self, confidence: int) -> str:
        """Get confidence level name"""
        if confidence >= 90:
            return "VERY_HIGH"
        elif confidence >= 70:
            return "HIGH"
        elif confidence >= 50:
            return "MEDIUM"
        elif confidence >= 30:
            return "LOW"
        return "VERY_LOW"

    def _build_reasons(
        self,
        fusion_result: FusionResult,
        features,
        ml_probability: float
    ) -> list:
        """Build list of reasons for the decision"""
        reasons = []

        # Threat match
        if hasattr(features, 'threat') and features.threat.matched:
            reasons.append(f"Tehdit veritabaninda eslesme: {features.threat.source}")

        # Brand impersonation
        if hasattr(features, 'brand') and features.brand.is_impostor:
            reasons.append(f"Marka taklidi: {features.brand.brand_name or 'Bilinmeyen'}")

        # External submit
        if hasattr(features, 'form') and features.form.has_external_submit:
            reasons.append("Form disariya veri gonderiyor")

        # Suspicious TLD
        if hasattr(features, 'domain_features'):
            if features.domain_features.is_suspicious_tld:
                reasons.append(f"Supheli alan adi: {features.domain_features.tld}")
            if features.domain_features.is_new_domain:
                reasons.append("Yeni kayitli domain")

        # ML indicator
        if ml_probability > 0.7:
            reasons.append(f"ML phishing olasiligi: %{int(ml_probability * 100)}")

        return reasons if reasons else ["Genel tehdit analizi tamamlandi"]

    def _generate_explanation(
        self,
        decision: str,
        final_score: int,
        fusion_score: int,
        ml_probability: float,
        ml_confidence: float,
        component_scores: Dict[str, int],
        features,
        reasons: list
    ) -> str:
        """Generate human-readable explanation"""
        try:
            exp_result = ml_explainer.explain(
                decision=decision,
                final_score=final_score,
                fusion_score=fusion_score,
                ml_probability=ml_probability,
                ml_confidence=ml_confidence,
                component_scores=component_scores,
                features=features,
                reasons=reasons
            )
            return exp_result.summary
        except Exception as e:
            return f"Analiz tamamlandi. Score: {final_score}/100"


# Singleton instance
hybrid_analyzer = HybridAnalyzer()
