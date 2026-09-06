"""
PhishShield TR - ML Feature Schema
Sprint 10: Standardized feature vector for ML models

Purpose:
- Define exact feature vector format for ML model input
- Ensure consistent feature ordering and naming
- Provide conversion from SiteFeatures to ML vector
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import numpy as np


class FeatureSchema:
    """
    Standardized feature vector schema for ML models.

    Feature indices (for model input array):
    0-7:   Domain features
    8-12:  Threat features
    13-17: Brand features
    18-25: Form features
    26-34: Content features
    35-39: Behavior features
    40-44: SSL features
    45-47: Meta features
    """

    DOMAIN_FEATURES = [
        "domain_age_days",      # 0: Domain age in days (-1 = unknown)
        "domain_length",        # 1: Domain character length
        "subdomain_count",      # 2: Number of subdomains
        "hyphen_count",         # 3: Hyphens in domain
        "number_count",         # 4: Numbers in domain
        "has_suspicious_tld",   # 5: 1 if suspicious TLD
        "is_ip_based",          # 6: 1 if IP address instead of domain
        "is_new_domain",        # 7: 1 if domain < 30 days old
    ]

    THREAT_FEATURES = [
        "threat_matched",       # 8: 1 if in threat database
        "threat_confidence",    # 9: 0.0-1.0 confidence
        "usom_match",          # 10: 1 if USOM match
        "openphish_match",      # 11: 1 if OpenPhish match
        "urlhaus_match",        # 12: 1 if URLhaus match
    ]

    BRAND_FEATURES = [
        "brand_matched",        # 13: 1 if brand impersonation detected
        "brand_similarity",     # 14: 0.0-1.0 similarity score
        "is_banking_brand",     # 15: 1 if banking brand
        "is_gov_brand",         # 16: 1 if government brand
        "is_payment_brand",     # 17: 1 if payment brand
    ]

    FORM_FEATURES = [
        "has_login_form",       # 18: 1 if login form present
        "has_password_field",   # 19: 1 if password input
        "has_credential_fields",# 20: 1 if credential fields
        "has_payment_fields",   # 21: 1 if payment fields
        "has_external_submit",   # 22: 1 if form submits externally
        "hidden_field_count",   # 23: Number of hidden fields
        "autocomplete_disabled",# 24: 1 if autocomplete disabled
        "form_count",          # 25: Number of forms on page
    ]

    CONTENT_FEATURES = [
        "has_urgency",         # 26: 1 if urgency language
        "has_sms_style",       # 27: 1 if SMS phishing style
        "bank_word_count",      # 28: Count of bank keywords
        "cargo_word_count",     # 29: Count of cargo keywords
        "reward_word_count",    # 30: Count of reward keywords
        "has_obfuscation",      # 31: 1 if obfuscated content
        "phone_count",          # 32: Phone numbers found
        "has_english_text",     # 33: 1 if English text on Turkish page
        "external_script_count",# 34: External scripts loaded
    ]

    BEHAVIOR_FEATURES = [
        "redirect_count",       # 35: Number of redirects
        "has_meta_refresh",     # 36: 1 if meta refresh detected
        "right_click_disabled", # 37: 1 if right click disabled
        "text_copy_disabled",   # 38: 1 if text copy disabled
        "popup_count",          # 39: Number of popups
    ]

    SSL_FEATURES = [
        "has_ssl",              # 40: 1 if HTTPS
        "ssl_valid",            # 41: 1 if SSL valid
        "ssl_self_signed",      # 42: 1 if self-signed cert
        "ssl_expires_soon",     # 43: 1 if expiring soon
        "ssl_issuer_trusted",   # 44: 1 if trusted issuer
    ]

    META_FEATURES = [
        "signal_count",         # 45: Number of threat signals
        "rule_count",           # 46: Number of correlation rules
        "trust_level",          # 47: 0=unknown, 1=trusted
    ]

    ALL_FEATURES = (
        DOMAIN_FEATURES +
        THREAT_FEATURES +
        BRAND_FEATURES +
        FORM_FEATURES +
        CONTENT_FEATURES +
        BEHAVIOR_FEATURES +
        SSL_FEATURES +
        META_FEATURES
    )

    FEATURE_COUNT = len(ALL_FEATURES)  # 48 features

    # Feature ranges for normalization
    NUMERIC_RANGES = {
        "domain_age_days": (0, 3650),      # 0-10 years
        "domain_length": (4, 100),
        "subdomain_count": (0, 10),
        "hyphen_count": (0, 10),
        "number_count": (0, 20),
        "hidden_field_count": (0, 10),
        "form_count": (0, 20),
        "bank_word_count": (0, 20),
        "cargo_word_count": (0, 10),
        "reward_word_count": (0, 10),
        "phone_count": (0, 20),
        "external_script_count": (0, 20),
        "redirect_count": (0, 10),
        "popup_count": (0, 10),
        "signal_count": (0, 20),
        "rule_count": (0, 10),
        "threat_confidence": (0.0, 1.0),
        "brand_similarity": (0.0, 1.0),
    }


@dataclass
class FeatureVector:
    """
    Standardized feature vector for ML model input.

    Converted from SiteFeatures for ML inference.
    """
    features: np.ndarray  # Shape: (FEATURE_COUNT,)

    def __init__(self, features: List[float] = None):
        if features is None:
            features = [0.0] * FeatureSchema.FEATURE_COUNT
        self.features = np.array(features, dtype=np.float32)

    @classmethod
    def from_site_features(cls, site_features) -> "FeatureVector":
        """
        Create feature vector from SiteFeatures object.

        Args:
            site_features: SiteFeatures from feature_collector

        Returns:
            FeatureVector ready for ML model input
        """
        f = site_features

        values = []

        # Domain features (0-7)
        values.append(min(f.domain_features.age_days if f.domain_features.age_days > 0 else 365, 3650))  # age_days
        values.append(f.domain_features.length)  # domain_length
        values.append(min(f.domain_features.subdomain_count, 10))  # subdomain_count
        values.append(min(f.domain_features.hyphen_count, 10))  # hyphen_count
        values.append(min(f.domain_features.number_count, 20))  # number_count
        values.append(1.0 if f.domain_features.is_suspicious_tld else 0.0)  # has_suspicious_tld
        values.append(1.0 if f.domain_features.is_ip_based else 0.0)  # is_ip_based
        values.append(1.0 if f.domain_features.is_new_domain else 0.0)  # is_new_domain

        # Threat features (8-12)
        values.append(1.0 if f.threat.matched else 0.0)  # threat_matched
        values.append(f.threat.confidence if f.threat.confidence else 0.0)  # threat_confidence
        values.append(1.0 if f.threat.source == "usom" else 0.0)  # usom_match
        values.append(1.0 if f.threat.source == "openphish" else 0.0)  # openphish_match
        values.append(1.0 if f.threat.source == "urlhaus" else 0.0)  # urlhaus_match

        # Brand features (13-17)
        values.append(1.0 if f.brand.matched else 0.0)  # brand_matched
        values.append(f.brand.similarity_score if f.brand.similarity_score else 0.0)  # brand_similarity
        values.append(1.0 if f.brand.brand_category == "BANKING" else 0.0)  # is_banking_brand
        values.append(1.0 if f.brand.brand_category == "GOVERNMENT" else 0.0)  # is_gov_brand
        values.append(1.0 if f.brand.brand_category == "PAYMENT" else 0.0)  # is_payment_brand

        # Form features (18-25)
        values.append(1.0 if f.form.has_login_form else 0.0)  # has_login_form
        values.append(1.0 if f.form.has_password_field else 0.0)  # has_password_field
        values.append(1.0 if f.form.has_credential_fields else 0.0)  # has_credential_fields
        values.append(1.0 if f.form.has_payment_fields else 0.0)  # has_payment_fields
        values.append(1.0 if f.form.has_external_submit else 0.0)  # has_external_submit
        values.append(float(min(f.form.hidden_field_count, 10)))  # hidden_field_count
        values.append(1.0 if f.form.autocomplete_disabled else 0.0)  # autocomplete_disabled
        values.append(float(min(f.form.form_count, 20)))  # form_count

        # Content features (26-34)
        values.append(1.0 if f.content.has_urgency else 0.0)  # has_urgency
        values.append(1.0 if f.content.has_sms_style else 0.0)  # has_sms_style
        values.append(float(min(f.content.bank_word_count, 20)))  # bank_word_count
        values.append(float(min(f.content.cargo_word_count, 10)))  # cargo_word_count
        values.append(float(min(f.content.reward_word_count, 10)))  # reward_word_count
        values.append(1.0 if f.content.has_obfuscation else 0.0)  # has_obfuscation
        values.append(float(min(f.content.phone_count, 20)))  # phone_count
        values.append(1.0 if f.content.has_english_text else 0.0)  # has_english_text
        values.append(float(min(f.content.external_script_count, 20)))  # external_script_count

        # Behavior features (35-39)
        values.append(float(min(f.behavior.redirect_count, 10)))  # redirect_count
        values.append(1.0 if f.behavior.has_meta_refresh else 0.0)  # has_meta_refresh
        values.append(1.0 if f.behavior.right_click_disabled else 0.0)  # right_click_disabled
        values.append(1.0 if f.behavior.text_copy_disabled else 0.0)  # text_copy_disabled
        values.append(float(min(f.behavior.popup_count, 10)))  # popup_count

        # SSL features (40-44)
        values.append(1.0 if f.ssl.has_ssl else 0.0)  # has_ssl
        values.append(1.0 if f.ssl.is_valid else 0.0)  # ssl_valid
        values.append(1.0 if f.ssl.self_signed else 0.0)  # ssl_self_signed
        values.append(1.0 if f.ssl.expires_soon else 0.0)  # ssl_expires_soon
        values.append(1.0 if f.ssl.issuer and "trusted" in str(f.ssl.issuer).lower() else 0.0)  # ssl_issuer_trusted

        # Meta features (45-47)
        values.append(float(len(f.analysis_signals)))  # signal_count
        values.append(float(len(f.applied_rules)))  # rule_count
        values.append(1.0 if f.is_trusted or f.trust_fast_path else 0.0)  # trust_level

        return cls(values)

    def to_array(self) -> np.ndarray:
        """Convert to numpy array for model input"""
        return self.features.reshape(1, -1)

    def get_feature_dict(self) -> Dict[str, float]:
        """Get features as dictionary"""
        return dict(zip(FeatureSchema.ALL_FEATURES, self.features.tolist()))

    @staticmethod
    def normalize(value: float, feature_name: str) -> float:
        """Normalize a single feature value"""
        if feature_name not in FeatureSchema.NUMERIC_RANGES:
            return value

        min_val, max_val = FeatureSchema.NUMERIC_RANGES[feature_name]
        if max_val == min_val:
            return 0.0

        normalized = (value - min_val) / (max_val - min_val)
        return max(0.0, min(1.0, normalized))
