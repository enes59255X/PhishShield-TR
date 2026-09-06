"""
PhishShield TR - Correlation Engine V2
Sprint 5: Advanced signal correlation for attack pattern detection
"""

from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum


class AttackPattern(Enum):
    """Known attack patterns"""
    BANK_PHISHING = "BANK_PHISHING"
    GOV_PHISHING = "GOV_PHISHING"
    CARGO_SCAM = "CARGO_SCAM"
    ECOSCAM = "ECOSCAM"
    REWARD_SCAM = "REWARD_SCAM"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    PAYMENT_FRAUD = "PAYMENT_FRAUD"
    CREDENTIAL_HARVEST = "CREDENTIAL_HARVEST"
    UNKNOWN = "UNKNOWN"


@dataclass
class CorrelationResult:
    """Result of signal correlation"""
    primary_pattern: AttackPattern
    pattern_score: int
    matched_rules: List[str]
    threat_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    confidence: float
    indicators: List[str]
    description: str


class CorrelationEngineV2:
    """
    V2 Correlation Engine that combines multiple signals
    to detect sophisticated attack patterns.
    
    Key features:
    - Multi-signal correlation
    - Attack pattern matching
    - Temporal analysis
    - Risk amplification
    """
    
    # Attack patterns with their required signals
    ATTACK_PATTERNS = {
        AttackPattern.BANK_PHISHING: {
            "required_signals": {"bank_brand_match", "password_field"},
            "amplifiers": {"external_submit", "new_domain", "suspicious_tld"},
            "base_score": 85,
            "threat_level": "CRITICAL",
            "description": "Banka phishing saldirisi"
        },
        AttackPattern.GOV_PHISHING: {
            "required_signals": {"gov_brand_match", "credential_fields"},
            "amplifiers": {"external_submit", "new_domain"},
            "base_score": 90,
            "threat_level": "CRITICAL",
            "description": "Devlet kurumu phishing saldirisi"
        },
        AttackPattern.CARGO_SCAM: {
            "required_signals": {"cargo_brand_match", "payment_fields"},
            "amplifiers": {"external_submit", "suspicious_tld", "new_domain"},
            "base_score": 80,
            "threat_level": "CRITICAL",
            "description": "Kargo/servis scam saldirisi"
        },
        AttackPattern.REWARD_SCAM: {
            "required_signals": {"brand_impostor", "suspicious_tld"},
            "amplifiers": {"urgency_text", "external_submit", "new_domain"},
            "base_score": 75,
            "threat_level": "HIGH",
            "description": "Odul/cayinti scam saldirisi"
        },
        AttackPattern.ACCOUNT_TAKEOVER: {
            "required_signals": {"brand_impostor", "login_form_detected"},
            "amplifiers": {"external_submit", "autocomplete_disabled"},
            "base_score": 80,
            "threat_level": "HIGH",
            "description": "Hesap ele gecirme saldirisi"
        },
        AttackPattern.PAYMENT_FRAUD: {
            "required_signals": {"payment_fields", "brand_impostor"},
            "amplifiers": {"external_submit", "new_domain", "suspicious_tld"},
            "base_score": 90,
            "threat_level": "CRITICAL",
            "description": "Odeme fraud saldirisi"
        },
        AttackPattern.CREDENTIAL_HARVEST: {
            "required_signals": {"credential_harvesting_external", "password_field"},
            "amplifiers": {"hidden_form_fields", "js_obfuscation"},
            "base_score": 95,
            "threat_level": "CRITICAL",
            "description": "Kimlik avi saldirisi"
        },
    }
    
    # Signal weights for correlation
    SIGNAL_WEIGHTS = {
        # Critical signals
        "threat_intel_match": 50,
        "credential_harvesting_external": 45,
        "bank_brand_match": 40,
        "gov_brand_match": 40,
        "new_domain": 30,
        "external_submit": 35,
        "password_field": 20,
        "hidden_form_fields": 25,
        "js_obfuscation": 15,
        
        # High signals
        "brand_impostor": 25,
        "fake_login_page": 25,
        "typosquatting": 20,
        "payment_fields": 20,
        "suspicious_tld": 15,
        "autocomplete_disabled": 15,
        "urgency_text": 10,
        
        # Medium signals
        "credential_fields": 15,
        "external_scripts": 10,
        "domain_mismatch": 15,
        
        # Low signals
        "contact_phone": 5,
        "english_content": 3,
    }
    
    def __init__(self):
        self._pattern_cache: Dict[str, List[AttackPattern]] = {}
    
    def correlate(self, signals: List[str], context: Dict = None) -> CorrelationResult:
        """
        Correlate signals to detect attack patterns.
        
        Args:
            signals: List of detected signals
            context: Additional context (domain, brand_info, etc.)
        
        Returns:
            CorrelationResult with pattern detection
        """
        signal_set = set(signals)
        context = context or {}
        
        best_pattern = AttackPattern.UNKNOWN
        best_score = 0
        matched_rules = []
        indicators = []
        
        # Check each attack pattern
        for pattern, config in self.ATTACK_PATTERNS.items():
            required = config["required_signals"]
            amplifiers = config.get("amplifiers", [])
            
            # Check if all required signals are present
            if required.issubset(signal_set):
                score = config["base_score"]
                rules_matched = []
                
                # Add required signals to indicators
                for sig in required:
                    indicators.append(f"[REQUIRED] {sig}")
                    rules_matched.append(f"required:{sig}")
                
                # Count amplifiers
                amplifier_count = len(amplifiers & signal_set)
                score += amplifier_count * 10
                
                for amp in amplifiers & signal_set:
                    indicators.append(f"[AMPLIFIER] {amp}")
                    rules_matched.append(f"amplifier:{amp}")
                
                if score > best_score:
                    best_score = score
                    best_pattern = pattern
                    matched_rules = rules_matched
        
        # If no specific pattern, do generic correlation
        if best_pattern == AttackPattern.UNKNOWN:
            best_score = self._calculate_generic_score(signal_set)
            indicators.extend(self._get_top_signals(signal_set, 5))
        
        # Cap at 100
        best_score = min(100, best_score)
        
        # Determine threat level
        threat_level = self._get_threat_level(best_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(signal_set, best_pattern, matched_rules)
        
        # Get description
        if best_pattern != AttackPattern.UNKNOWN:
            description = self.ATTACK_PATTERNS[best_pattern]["description"]
        else:
            description = self._generate_description(signal_set)
        
        return CorrelationResult(
            primary_pattern=best_pattern,
            pattern_score=best_score,
            matched_rules=matched_rules,
            threat_level=threat_level,
            confidence=confidence,
            indicators=indicators,
            description=description
        )
    
    def _calculate_generic_score(self, signal_set: Set[str]) -> int:
        """Calculate score without specific pattern match"""
        score = 0
        
        for signal in signal_set:
            score += self.SIGNAL_WEIGHTS.get(signal, 0)
        
        # Apply diminishing returns for too many signals
        if len(signal_set) > 8:
            score = int(score * 0.8)
        
        return min(100, score)
    
    def _get_top_signals(self, signal_set: Set[str], n: int) -> List[str]:
        """Get top N signals by weight"""
        sorted_signals = sorted(
            signal_set,
            key=lambda s: self.SIGNAL_WEIGHTS.get(s, 0),
            reverse=True
        )
        return sorted_signals[:n]
    
    def _get_threat_level(self, score: int) -> str:
        """Map score to threat level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_confidence(
        self,
        signal_set: Set[str],
        pattern: AttackPattern,
        matched_rules: List[str]
    ) -> float:
        """Calculate confidence in the correlation"""
        if pattern == AttackPattern.UNKNOWN:
            # Generic correlation has lower confidence
            return min(0.8, len(signal_set) * 0.05 + 0.3)
        
        config = self.ATTACK_PATTERNS[pattern]
        required = config["required_signals"]
        
        # Base confidence from required signals
        confidence = 0.5
        
        # Required signals found
        confidence += 0.3
        
        # Amplifiers found
        amplifiers = config.get("amplifiers", [])
        amplifier_count = len(amplifiers & signal_set)
        confidence += min(0.2, amplifier_count * 0.05)
        
        return min(0.99, confidence)
    
    def _generate_description(self, signal_set: Set[str]) -> str:
        """Generate human-readable description"""
        if "bank_brand_match" in signal_set:
            return "Banka markasi ile ilgili phishing girisimi"
        elif "gov_brand_match" in signal_set:
            return "Devlet kurumu taklidi girisimi"
        elif "cargo_brand_match" in signal_set:
            return "Kargo/firma taklidi girisimi"
        elif "payment_fields" in signal_set:
            return "Odeme bilgiisi toplama girisimi"
        elif "external_submit" in signal_set:
            return "Harici adrese veri gonderimi"
        elif "new_domain" in signal_set:
            return "Yeni olusturulmus domain"
        else:
            return "Supheli aktivite tespit edildi"
    
    def get_pattern_description(self, pattern: AttackPattern) -> str:
        """Get description for an attack pattern"""
        if pattern in self.ATTACK_PATTERNS:
            return self.ATTACK_PATTERNS[pattern]["description"]
        return "Bilinmeyen saldirI tipi"


# Singleton instance
correlation_engine_v2 = CorrelationEngineV2()
