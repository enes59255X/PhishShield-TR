"""
PhishShield TR - Brand Feature Collector
Sprint 7.1: Collects brand impersonation features
"""

from typing import Dict, Optional
from ml.features import BrandFeatures


class BrandFeatureCollector:
    """
    Collects brand impersonation features.
    """

    BRAND_CATEGORIES = {
        "BANKING": ["garanti", "akbank", "isbank", "ziraat", "halkbank", "vakifbank",
                   "kuveytturk", "denizbank", "ingbank", "teb", "qnb", "fibabanka", "hsbc"],
        "GOVERNMENT": ["edevlet", "turkiye", "gov", "usom", "gib", "sgk", "osym", "eba", "meb", "cimer"],
        "CARGO": ["yurtici", "aras", "ptt", "ups", "dhl", "fedex", "mng", "surat", "kargo"],
        "ECOMMERCE": ["trendyol", "hepsiburada", "n11", "gittigidiyor", "amazon", "hepsiburada"],
        "SOCIAL": ["facebook", "instagram", "twitter", "linkedin", "whatsapp", "telegram"],
        "PAYMENT": ["paypal", "stripe", "iyzico", "paycell"],
    }

    def collect(self, analysis_result: Dict, brand_result: Optional[Dict] = None) -> BrandFeatures:
        """
        Collect brand features.

        Args:
            analysis_result: Main analysis result
            brand_result: Brand matcher result (optional)

        Returns:
            BrandFeatures object
        """
        features = BrandFeatures()

        # Get from brand_result if available
        if brand_result:
            features.matched = brand_result.get("is_impostor", False) or brand_result.get("brand_name") is not None
            features.brand_name = brand_result.get("brand_name")
            features.brand_category = brand_result.get("brand_category")
            features.similarity_score = brand_result.get("similarity_score", 0.0)
            features.is_impostor = brand_result.get("is_impostor", False)
            features.is_typosquat = brand_result.get("match_type") == "typosquat"
            features.match_type = brand_result.get("match_type", "none")
            features.confidence = brand_result.get("confidence", 0.0)

        # Extract from analysis result signals
        signals = analysis_result.get("signals", [])
        domain = analysis_result.get("domain", "")

        if not features.matched:
            # Check signals for brand indicators
            brand_indicators = {
                "bank_impostor": "BANKING",
                "gov_impostor": "GOVERNMENT",
                "cargo_brand": "CARGO",
                "ecommerce_brand": "ECOMMERCE",
            }

            for signal, category in brand_indicators.items():
                if signal in signals:
                    features.matched = True
                    features.brand_category = category
                    features.is_impostor = True
                    break

        # Determine category from domain if not set
        if features.matched and not features.brand_category and domain:
            features.brand_category = self._detect_brand_category(domain)

        return features

    def _detect_brand_category(self, domain: str) -> Optional[str]:
        """Detect brand category from domain"""
        domain_lower = domain.lower()

        for category, keywords in self.BRAND_CATEGORIES.items():
            for keyword in keywords:
                if keyword in domain_lower:
                    return category

        return None

    def get_category_weight(self, category: Optional[str]) -> float:
        """Get risk weight for brand category"""
        weights = {
            "BANKING": 1.0,
            "GOVERNMENT": 1.0,
            "PAYMENT": 0.9,
            "ECOMMERCE": 0.7,
            "CARGO": 0.6,
            "SOCIAL": 0.5,
        }
        return weights.get(category, 0.3)
