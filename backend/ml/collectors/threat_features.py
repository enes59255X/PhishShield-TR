"""
PhishShield TR - Threat Feature Collector
Sprint 7.1: Collects threat intelligence features
"""

from typing import Dict, Optional
from ml.features import ThreatFeatures, ThreatLevel


class ThreatFeatureCollector:
    """
    Collects threat intelligence features.
    """

    SOURCE_CREDIBILITY = {
        "usom": 10,
        "openphish": 8,
        "urlhaus": 7,
        "phishTank": 7,
        "googleSafeBrowsing": 6,
    }

    def collect(self, analysis_result: Dict, threat_match=None) -> ThreatFeatures:
        """
        Collect threat features.

        Args:
            analysis_result: Main analysis result
            threat_match: ThreatMatch object from threat_reputation (optional)

        Returns:
            ThreatFeatures object
        """
        features = ThreatFeatures()

        # Check threat_match object
        if threat_match and hasattr(threat_match, 'is_threat'):
            features.matched = threat_match.is_threat
            if features.matched:
                features.source = threat_match.source
                features.category = threat_match.category
                features.confidence = threat_match.confidence or 0.0
                features.threat_level = self._get_threat_level(threat_match)
                features.first_seen_days = getattr(threat_match, 'first_seen_days', None)

        # Check analysis_result for threat intel info
        threat_intel = analysis_result.get("threat_intel", {})
        if threat_intel:
            if threat_intel.get("matched"):
                features.matched = True
                features.source = threat_intel.get("source")
                features.category = threat_intel.get("category")
                features.confidence = threat_intel.get("confidence", 0.0)
                features.threat_level = self._level_from_confidence(features.confidence)

        # Check signals for threat indicators
        signals = analysis_result.get("signals", [])
        if "threat_intel_match" in signals:
            features.matched = True
            if not features.source:
                features.source = "signal_detected"

        return features

    def _get_threat_level(self, threat_match) -> ThreatLevel:
        """Determine threat level from threat match"""
        confidence = threat_match.confidence or 0.0

        if confidence >= 0.9:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.7:
            return ThreatLevel.HIGH
        elif confidence >= 0.5:
            return ThreatLevel.MEDIUM
        elif confidence > 0:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def _level_from_confidence(self, confidence: float) -> ThreatLevel:
        """Map confidence to threat level"""
        if confidence >= 0.9:
            return ThreatLevel.CRITICAL
        elif confidence >= 0.7:
            return ThreatLevel.HIGH
        elif confidence >= 0.5:
            return ThreatLevel.MEDIUM
        elif confidence > 0:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def get_source_score(self, source: str) -> int:
        """Get credibility score for threat source"""
        return self.SOURCE_CREDIBILITY.get(source.lower(), 5)
