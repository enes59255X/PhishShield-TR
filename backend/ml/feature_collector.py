"""
PhishShield TR - Feature Collector
Sprint 7.1: Main feature collection orchestrator

Combines all collectors to produce unified SiteFeatures.
"""

from typing import Dict, Optional
from urllib.parse import urlparse

from ml.features import (
    SiteFeatures,
    DomainFeatures,
    ThreatFeatures,
    BrandFeatures,
    FormFeatures,
    ContentFeatures,
    BehaviorFeatures,
    SSLFeatures,
)

from ml.collectors import (
    DomainFeatureCollector,
    ThreatFeatureCollector,
    BrandFeatureCollector,
    FormFeatureCollector,
    ContentFeatureCollector,
)


class FeatureCollector:
    """
    Main orchestrator for feature collection.

    Collects all features from analysis results and produces
    a unified SiteFeatures object for Fusion Engine.
    """

    def __init__(self):
        self.domain_collector = DomainFeatureCollector()
        self.threat_collector = ThreatFeatureCollector()
        self.brand_collector = BrandFeatureCollector()
        self.form_collector = FormFeatureCollector()
        self.content_collector = ContentFeatureCollector()

    def collect(
        self,
        url: str,
        analysis_result: Dict,
        brand_result: Optional[Dict] = None,
        form_result: Optional[Dict] = None,
        domain_age_result: Optional[Dict] = None,
        threat_match=None,
    ) -> SiteFeatures:
        """
        Collect all features into unified SiteFeatures.

        Args:
            url: The analyzed URL
            analysis_result: Main analysis result from analyzer.py
            brand_result: Brand matcher result (optional)
            form_result: Form analyzer result (optional)
            domain_age_result: Domain age analyzer result (optional)
            threat_match: ThreatMatch object (optional)

        Returns:
            SiteFeatures object with all features
        """
        features = SiteFeatures()

        # Basic URL info
        features.url = url
        parsed = urlparse(url)
        features.domain = parsed.netloc.lower()

        # Trust fast path check
        features.trust_fast_path = analysis_result.get("trust_fast_path", False)
        features.is_trusted = analysis_result.get("site_type") == "TRUSTED_PLATFORM"
        features.site_type = analysis_result.get("site_type", "unknown")

        # Scores
        features.raw_risk_score = analysis_result.get("score", 0)
        features.signal_score = self._calculate_signal_score(analysis_result)
        features.correlation_bonus = analysis_result.get("correlation_bonus", 0)

        # Meta info
        features.analysis_signals = analysis_result.get("signals", [])
        features.applied_rules = analysis_result.get("correlation_rules_applied", [])

        # Collect all feature groups
        features.domain_features = self.domain_collector.collect(url, analysis_result, domain_age_result)
        features.threat = self.threat_collector.collect(analysis_result, threat_match)
        features.brand = self.brand_collector.collect(analysis_result, brand_result)
        features.form = self.form_collector.collect(analysis_result, form_result)
        features.content = self.content_collector.collect(analysis_result)

        # Behavior features
        features.behavior = self._collect_behavior_features(analysis_result)

        # SSL features
        features.ssl = self._collect_ssl_features(analysis_result)

        return features

    def _calculate_signal_score(self, analysis_result: Dict) -> int:
        """Calculate score from signals"""
        signals = analysis_result.get("signals", [])

        # Simple scoring based on signal count and severity
        score = 0
        high_signals = ["bank_impostor", "gov_impostor", "known_phishing_domain",
                       "piran_scam", "cargo_brand", "credential_harvesting_external_post"]

        for signal in signals:
            if signal in high_signals:
                score += 25
            else:
                score += 5

        return min(100, score)

    def _collect_behavior_features(self, analysis_result: Dict) -> BehaviorFeatures:
        """Collect behavior features"""
        features = BehaviorFeatures()

        sub_scores = analysis_result.get("sub_scores", {})
        reasons = analysis_result.get("reasons", [])
        reasons_text = " ".join(reasons).lower()

        # Redirect count
        features.redirect_count = sub_scores.get("behavior_analysis", 0) // 10

        # Meta refresh
        features.has_meta_refresh = "meta refresh" in reasons_text

        # Right click disabled
        features.right_click_disabled = "right click" in reasons_text

        # Text copy disabled
        features.text_copy_disabled = "copy" in reasons_text and "disabled" in reasons_text

        # Popup count
        popup_count = reasons_text.count("popup")
        features.popup_count = popup_count

        return features

    def _collect_ssl_features(self, analysis_result: Dict) -> SSLFeatures:
        """Collect SSL features"""
        features = SSLFeatures()

        url = analysis_result.get("url", "")

        # Has SSL
        features.has_ssl = url.startswith("https")

        # SSL score
        sub_scores = analysis_result.get("sub_scores", {})
        ssl_score = sub_scores.get("ssl_cert", 0)
        features.is_valid = ssl_score > 50

        # SSL errors
        reasons = analysis_result.get("reasons", [])
        reasons_text = " ".join(reasons).lower()

        if "ssl" in reasons_text and "error" in reasons_text:
            features.expires_soon = True

        if "self signed" in reasons_text:
            features.self_signed = True

        return features


# Singleton instance
feature_collector = FeatureCollector()
