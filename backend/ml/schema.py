"""
PhishShield TR - ML Feature Schema
Sprint 6: Defines all features for ML model
"""

from dataclasses import dataclass
from typing import List, Dict, Any
from enum import Enum


class FeatureGroup(Enum):
    """Feature group categories"""
    DOMAIN = "domain"
    BRAND = "brand"
    FORM = "form"
    CONTENT = "content"
    BEHAVIOR = "behavior"
    THREAT = "threat"
    SSL = "ssl"


@dataclass
class FeatureDefinition:
    """Definition of a single feature"""
    name: str
    group: FeatureGroup
    type: str  # int, float, bool, str
    description: str
    min_value: Any = None
    max_value: Any = None


# All ML features
ML_FEATURES: List[FeatureDefinition] = [
    # DOMAIN FEATURES
    FeatureDefinition("url_length", FeatureGroup.DOMAIN, "int", "Total URL length", 0, 500),
    FeatureDefinition("domain_length", FeatureGroup.DOMAIN, "int", "Domain length", 0, 100),
    FeatureDefinition("subdomain_count", FeatureGroup.DOMAIN, "int", "Number of subdomains", 0, 10),
    FeatureDefinition("hyphen_count", FeatureGroup.DOMAIN, "int", "Number of hyphens in domain", 0, 20),
    FeatureDefinition("number_count", FeatureGroup.DOMAIN, "int", "Numbers in domain", 0, 20),
    FeatureDefinition("digit_ratio", FeatureGroup.DOMAIN, "float", "Ratio of digits to domain length", 0.0, 1.0),
    FeatureDefinition("has_underscore", FeatureGroup.DOMAIN, "bool", "Has underscore in domain"),
    FeatureDefinition("tld_type", FeatureGroup.DOMAIN, "str", "TLD category (com, xyz, etc)"),
    FeatureDefinition("domain_age_days", FeatureGroup.DOMAIN, "int", "Domain age in days", -1, 3650),
    FeatureDefinition("is_new_domain", FeatureGroup.DOMAIN, "bool", "Domain less than 30 days old"),
    FeatureDefinition("is_recent_domain", FeatureGroup.DOMAIN, "bool", "Domain less than 90 days old"),
    
    # BRAND FEATURES
    FeatureDefinition("has_brand_match", FeatureGroup.BRAND, "bool", "Brand keyword detected"),
    FeatureDefinition("brand_similarity", FeatureGroup.BRAND, "float", "Brand similarity score", 0.0, 1.0),
    FeatureDefinition("is_bank_brand", FeatureGroup.BRAND, "bool", "Banking brand detected"),
    FeatureDefinition("is_gov_brand", FeatureGroup.BRAND, "bool", "Government brand detected"),
    FeatureDefinition("is_cargo_brand", FeatureGroup.BRAND, "bool", "Cargo brand detected"),
    FeatureDefinition("is_ecommerce_brand", FeatureGroup.BRAND, "bool", "E-commerce brand detected"),
    FeatureDefinition("is_impostor", FeatureGroup.BRAND, "bool", "Brand impersonation detected"),
    FeatureDefinition("is_typosquat", FeatureGroup.BRAND, "bool", "Typosquatting detected"),
    
    # FORM FEATURES
    FeatureDefinition("has_login_form", FeatureGroup.FORM, "bool", "Login form detected"),
    FeatureDefinition("has_password_field", FeatureGroup.FORM, "bool", "Password field present"),
    FeatureDefinition("has_credential_fields", FeatureGroup.FORM, "bool", "Credential fields present"),
    FeatureDefinition("has_payment_fields", FeatureGroup.FORM, "bool", "Payment fields present"),
    FeatureDefinition("has_otp_field", FeatureGroup.FORM, "bool", "OTP field present"),
    FeatureDefinition("has_external_submit", FeatureGroup.FORM, "bool", "Form submits to external domain"),
    FeatureDefinition("hidden_field_count", FeatureGroup.FORM, "int", "Number of hidden fields", 0, 20),
    FeatureDefinition("has_autocomplete_off", FeatureGroup.FORM, "bool", "Autocomplete disabled"),
    FeatureDefinition("form_count", FeatureGroup.FORM, "int", "Total form count", 0, 50),
    
    # CONTENT FEATURES
    FeatureDefinition("urgency_word_count", FeatureGroup.CONTENT, "int", "Urgency words found", 0, 50),
    FeatureDefinition("has_urgency", FeatureGroup.CONTENT, "bool", "Urgency text detected"),
    FeatureDefinition("has_sms_style", FeatureGroup.CONTENT, "bool", "SMS style text detected"),
    FeatureDefinition("bank_word_count", FeatureGroup.CONTENT, "int", "Banking keywords count", 0, 50),
    FeatureDefinition("cargo_word_count", FeatureGroup.CONTENT, "int", "Cargo keywords count", 0, 50),
    FeatureDefinition("reward_word_count", FeatureGroup.CONTENT, "int", "Reward/lottery words", 0, 50),
    FeatureDefinition("external_script_count", FeatureGroup.CONTENT, "int", "External scripts", 0, 20),
    FeatureDefinition("iframe_count", FeatureGroup.CONTENT, "int", "Iframe count", 0, 10),
    FeatureDefinition("has_obfuscation", FeatureGroup.CONTENT, "bool", "JS obfuscation detected"),
    
    # BEHAVIOR FEATURES
    FeatureDefinition("redirect_count", FeatureGroup.BEHAVIOR, "int", "Number of redirects", 0, 20),
    FeatureDefinition("has_meta_refresh", FeatureGroup.BEHAVIOR, "bool", "Meta refresh redirect"),
    FeatureDefinition("right_click_disabled", FeatureGroup.BEHAVIOR, "bool", "Right click disabled"),
    FeatureDefinition("text_copy_disabled", FeatureGroup.BEHAVIOR, "bool", "Text copy disabled"),
    
    # THREAT FEATURES
    FeatureDefinition("threat_intel_match", FeatureGroup.THREAT, "bool", "Found in threat database"),
    FeatureDefinition("threat_source_score", FeatureGroup.THREAT, "int", "Threat source credibility", 0, 10),
    FeatureDefinition("is_suspicious_tld", FeatureGroup.THREAT, "bool", "Suspicious TLD"),
    
    # SSL FEATURES
    FeatureDefinition("has_ssl", FeatureGroup.SSL, "bool", "Has HTTPS"),
    FeatureDefinition("ssl_valid", FeatureGroup.SSL, "bool", "SSL certificate valid"),
    FeatureDefinition("ssl_expires_soon", FeatureGroup.SSL, "bool", "SSL expires within 30 days"),
]


def get_feature_names() -> List[str]:
    """Get list of all feature names"""
    return [f.name for f in ML_FEATURES]


def get_feature_by_group(group: FeatureGroup) -> List[str]:
    """Get features by group"""
    return [f.name for f in ML_FEATURES if f.group == group]


def get_feature_schema() -> Dict[str, str]:
    """Get feature name to type mapping"""
    return {f.name: f.type for f in ML_FEATURES}
