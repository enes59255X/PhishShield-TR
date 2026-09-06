"""
PhishShield TR - Domain Feature Collector
Sprint 7.1: Collects domain-related features
"""

import re
from urllib.parse import urlparse
from typing import Dict, Optional
from ml.features import DomainFeatures


class DomainFeatureCollector:
    """
    Collects domain features from analysis results.
    """

    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".click", ".link", ".gq", ".tk", ".ml", ".cf", ".ga",
        ".pw", ".ru", ".cn", ".su", ".cc", ".to", ".ws", ".biz", ".info",
        ".online", ".site", ".website", ".space", ".fun", ".icu", ".rest"
    }

    def collect(self, url: str, analysis_result: Dict, domain_age_result: Optional[Dict] = None) -> DomainFeatures:
        """
        Collect domain features from analysis results.

        Args:
            url: The analyzed URL
            analysis_result: Main analysis result
            domain_age_result: Domain age analyzer result (optional)

        Returns:
            DomainFeatures object
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        features = DomainFeatures()

        # Domain structure features
        features.length = len(domain)
        features.subdomain_count = self._count_subdomains(domain)
        features.hyphen_count = domain.count("-")
        features.number_count = self._count_numbers(domain)
        features.has_underscore = "_" in domain

        # TLD
        features.tld = "." + domain.split(".")[-1] if "." in domain else ""
        features.is_suspicious_tld = features.tld in self.SUSPICIOUS_TLDS

        # Special domain types
        features.is_ip_based = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain))
        features.is_punycode = domain.startswith("xn--")

        # Domain age features
        if domain_age_result:
            features.age_days = domain_age_result.get("age_days", -1)
            features.age_category = domain_age_result.get("age_category", "unknown")
            features.is_suspicious_age = domain_age_result.get("is_suspicious", False)
            features.is_new_domain = features.age_days >= 0 and features.age_days < 30
        else:
            # Try to get from analysis result
            sub_scores = analysis_result.get("sub_scores", {})
            domain_score = sub_scores.get("domain_age", 0)

            # If domain age score is low, domain is likely new
            if domain_score > 30:
                features.is_new_domain = True
                features.is_suspicious_age = True

        return features

    def _count_subdomains(self, domain: str) -> int:
        """Count number of subdomains"""
        parts = domain.split(".")
        # TLD is last part, SLD is second last
        if len(parts) >= 3:
            return max(0, len(parts) - 2)
        return 0

    def _count_numbers(self, domain: str) -> int:
        """Count numbers in domain"""
        return sum(1 for c in domain if c.isdigit())
