"""
PhishShield TR - ML Predictor
Sprint 6: Combines ML predictions with rule engine for final decision
"""

from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from .extractor import feature_extractor
from .model import phishing_model


@dataclass
class MLPrediction:
    """Result of ML prediction"""
    probability: float  # 0.0 - 1.0
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0.0 - 1.0
    model_ready: bool
    top_features: List[Dict] = None
    
    def __post_init__(self):
        if self.top_features is None:
            self.top_features = []


@dataclass
class HybridDecision:
    """Final decision combining rule engine and ML"""
    # Final decision
    decision: str  # SAFE, CAUTION, DANGER
    risk_score: int  # 0-100
    
    # Decision sources
    rule_based_score: int
    ml_probability: float  # 0.0 - 1.0
    threat_intel_match: bool
    
    # Confidence
    confidence: int  # 0-100
    
    # Details
    primary_reason: str
    signals: List[str]
    ml_prediction: MLPrediction = None
    
    # Attack pattern
    attack_pattern: str = ""
    attack_description: str = ""


class HybridPredictor:
    """
    Hybrid prediction system combining:
    1. Rule-based analysis (existing)
    2. ML model prediction
    3. Threat intelligence
    
    Priority order (highest to lowest):
    1. Threat Intel Match -> DANGER
    2. Hard Rules -> DANGER
    3. ML High Probability -> DANGER
    4. Correlation Patterns -> DANGER/CAUTION
    5. ML Low Probability -> SAFE
    """
    
    # ML model weights
    ML_WEIGHT = 0.4  # ML contributes 40% to final decision
    RULE_WEIGHT = 0.6  # Rules contribute 60%
    
    # Thresholds
    ML_HIGH_THRESHOLD = 0.75  # Above this = likely phishing
    ML_LOW_THRESHOLD = 0.25  # Below this = likely safe
    RULE_HIGH_THRESHOLD = 60  # Above this = suspicious
    RULE_LOW_THRESHOLD = 20  # Below this = likely safe
    
    def __init__(self):
        self.model = phishing_model
        self.feature_extractor = feature_extractor
    
    def predict(
        self,
        url: str,
        analysis_result: Dict,
        rule_decision: str,
        rule_risk_score: int,
        rule_signals: List[str],
        brand_result: Optional[Dict] = None,
        form_result: Optional[Dict] = None,
        threat_result: Optional[Dict] = None,
        correlation_result: Optional[Dict] = None
    ) -> HybridDecision:
        """
        Make hybrid prediction combining all signals.
        
        Args:
            url: Analyzed URL
            analysis_result: Main analysis result
            rule_decision: Rule-based decision
            rule_risk_score: Rule-based risk score
            rule_signals: Detected signals
            brand_result: Brand matcher result
            form_result: Form analyzer result
            threat_result: Threat intel result
            correlation_result: Correlation engine result
        
        Returns:
            HybridDecision with final verdict
        """
        # 1. Extract features
        features = self.feature_extractor.extract(
            url=url,
            analysis_result=analysis_result,
            brand_result=brand_result,
            form_result=form_result,
            threat_result=threat_result
        )
        
        # 2. Get ML prediction
        ml_pred = self._get_ml_prediction(features)
        
        # 3. Get attack pattern from correlation
        attack_pattern = ""
        attack_description = ""
        if correlation_result:
            attack_pattern = correlation_result.get("primary_pattern", "")
            attack_description = correlation_result.get("description", "")
        
        # 4. Determine threat intel match
        threat_intel_match = threat_result.get("is_threat", False) if threat_result else False
        
        # 5. Make final decision
        final_decision, final_score, primary_reason = self._fuse_decision(
            rule_score=rule_risk_score,
            rule_decision=rule_decision,
            ml_prob=ml_pred.probability,
            ml_ready=ml_pred.model_ready,
            threat_match=threat_intel_match,
            signals=rule_signals,
            correlation=correlation_result
        )
        
        # 6. Calculate confidence
        confidence = self._calculate_confidence(
            rule_score=rule_risk_score,
            ml_prob=ml_pred.probability,
            threat_match=threat_intel_match,
            ml_ready=ml_pred.model_ready
        )
        
        return HybridDecision(
            decision=final_decision,
            risk_score=final_score,
            rule_based_score=rule_risk_score,
            ml_probability=ml_pred.probability,
            threat_intel_match=threat_intel_match,
            confidence=confidence,
            primary_reason=primary_reason,
            signals=rule_signals,
            ml_prediction=ml_pred,
            attack_pattern=attack_pattern,
            attack_description=attack_description
        )
    
    def _get_ml_prediction(self, features: Dict[str, Any]) -> MLPrediction:
        """Get ML model prediction"""
        if not self.model.is_ready():
            return MLPrediction(
                probability=0.5,
                risk_level="UNKNOWN",
                confidence=0.0,
                model_ready=False
            )
        
        try:
            # Extract feature vector
            feature_vector = self.feature_extractor.to_feature_vector(features)
            
            # Predict
            proba, risk_level = self.model.predict_single(feature_vector)
            
            # Calculate confidence based on model certainty
            # If probability is close to 0.5, we're uncertain
            uncertainty = abs(proba - 0.5) * 2  # 0.0 to 1.0
            confidence = uncertainty
            
            return MLPrediction(
                probability=proba,
                risk_level=risk_level,
                confidence=confidence,
                model_ready=True,
                top_features=self.model.get_feature_importance()[:5]
            )
        except Exception as e:
            print(f"ML prediction error: {e}")
            return MLPrediction(
                probability=0.5,
                risk_level="ERROR",
                confidence=0.0,
                model_ready=False
            )
    
    def _fuse_decision(
        self,
        rule_score: int,
        rule_decision: str,
        ml_prob: float,
        ml_ready: bool,
        threat_match: bool,
        signals: List[str],
        correlation: Optional[Dict]
    ) -> Tuple[str, int, str]:
        """
        Fuse rule-based and ML decisions.
        
        Returns:
            Tuple of (decision, risk_score, primary_reason)
        """
        primary_reason = ""
        
        # 1. Threat Intel always wins
        if threat_match:
            return "DANGER", 100, "Tehdit veritabaninda eslesme tespit edildi"
        
        # 2. Hard rule overrides
        if rule_decision == "DANGER" and rule_score >= 85:
            if "bank" in str(correlation):
                return "DANGER", 100, "Banka phishing saldirisi tespit edildi"
            if "gov" in str(correlation):
                return "DANGER", 100, "Devlet kurumu phishing saldirisi tespit edildi"
            if "credential" in str(correlation):
                return "DANGER", 100, "Kimlik avI saldirisi tespit edildi"
            return "DANGER", rule_score, "Yuksek risk skoru nedeniyle tehlikeli"
        
        # 3. ML-based decision (if model is ready)
        if ml_ready:
            # Calculate fused score
            fused_score = self.RULE_WEIGHT * rule_score + self.ML_WEIGHT * (ml_prob * 100)
            
            if ml_prob >= self.ML_HIGH_THRESHOLD:
                if rule_score >= self.RULE_HIGH_THRESHOLD:
                    # Both agree -> definitely dangerous
                    return "DANGER", int(fused_score), "Kural ve ML modeli tehlikeli buldu"
                else:
                    # ML says dangerous but rules not sure
                    return "CAUTION", int(fused_score), "ML modeli supheli sonuc verdi"
            
            elif ml_prob <= self.ML_LOW_THRESHOLD:
                if rule_score <= self.RULE_LOW_THRESHOLD:
                    # Both agree -> safe
                    return "SAFE", int(fused_score), "Guvenli site olarak degerlendirildi"
                else:
                    # Rules suspicious but ML says safe
                    return "CAUTION", int(rule_score * 0.7), "ML modeli guvenli ama kural sinirinda"
        
        # 4. Pure rule-based fallback
        if rule_score >= 70:
            return "DANGER", rule_score, "Kurallara gore tehlikeli"
        elif rule_score >= 40:
            return "CAUTION", rule_score, "Orta riskli site"
        else:
            return "SAFE", rule_score, "Dusuk riskli site"
    
    def _calculate_confidence(
        self,
        rule_score: int,
        ml_prob: float,
        threat_match: bool,
        ml_ready: bool
    ) -> int:
        """Calculate confidence in the decision (0-100)"""
        if threat_match:
            return 95  # Very confident due to threat intel
        
        if not ml_ready:
            # No ML, rely on rules
            if rule_score >= 80 or rule_score <= 20:
                return 80
            else:
                return 60
        
        # Both sources agree = high confidence
        rule_high = rule_score >= 70
        rule_low = rule_score <= 30
        ml_high = ml_prob >= 0.7
        ml_low = ml_prob <= 0.3
        
        if (rule_high and ml_high) or (rule_low and ml_low):
            return 90
        elif (rule_high and ml_low) or (rule_low and ml_high):
            return 50  # Disagreement
        else:
            return 70  # Moderate agreement


# Singleton instance
hybrid_predictor = HybridPredictor()
