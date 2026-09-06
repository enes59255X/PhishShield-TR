"""
PhishShield TR - Feature Extractor
Sprint 6: Extracts ML features from analysis results
"""

from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import re

from .schema import ML_FEATURES, FeatureGroup, get_feature_schema


class FeatureExtractor:
    """
    Extracts ML-ready features from analysis results.
    
    Takes raw analysis data and extracts structured features
    that can be fed into ML models.
    """
    
    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".click", ".link", ".gq", ".tk", ".ml", ".cf", ".ga",
        ".pw", ".ru", ".cn", ".su", ".cc", ".to", ".ws", ".biz", ".info",
        ".online", ".site", ".website", ".space", ".fun", ".icu", ".rest"
    }
    
    URGENCY_WORDS = [
        "acil", "hemen", "son", "warning", "urgent", "immediate", "süre",
        "bitiş", "expires", "limited", "fırsat", "kaçır", "bekleme"
    ]
    
    BANK_WORDS = [
        "garanti", "akbank", "isbank", "ziraat", "halkbank", "vakifbank",
        "qnb", "ing", "teb", "hsbc", "banka", "kredi", "kart", "hesap"
    ]
    
    CARGO_WORDS = [
        "kargo", "cargo", "gonderi", "teslimat", "ptt", "aras", "yurtici",
        "mng", "ups", "dhl", "fedex", "kurye"
    ]
    
    REWARD_WORDS = [
        "odul", "hediye", "cekilis", "kazan", "promosyon", "indirim",
        "reward", "gift", "prize", "winner", "lottery", "free"
    ]
    
    def __init__(self):
        self.feature_schema = get_feature_schema()
    
    def extract(
        self,
        url: str,
        analysis_result: Dict,
        brand_result: Optional[Dict] = None,
        form_result: Optional[Dict] = None,
        domain_age_result: Optional[Dict] = None,
        threat_result: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Extract features from all analysis components.
        
        Args:
            url: The analyzed URL
            analysis_result: Main analysis result from analyzer.py
            brand_result: Brand matcher result
            form_result: Form analyzer result
            domain_age_result: Domain age analyzer result
            threat_result: Threat intel result
        
        Returns:
            Dict of feature_name -> value
        """
        features = {}
        
        # URL parsing
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # DOMAIN FEATURES
        features.update(self._extract_domain_features(domain, url))
        
        # BRAND FEATURES
        features.update(self._extract_brand_features(brand_result, domain))
        
        # FORM FEATURES
        features.update(self._extract_form_features(form_result))
        
        # CONTENT FEATURES
        content_text = self._get_content_text(analysis_result)
        features.update(self._extract_content_features(content_text, analysis_result))
        
        # BEHAVIOR FEATURES
        features.update(self._extract_behavior_features(analysis_result))
        
        # THREAT FEATURES
        features.update(self._extract_threat_features(threat_result, analysis_result))
        
        # SSL FEATURES
        features.update(self._extract_ssl_features(analysis_result))
        
        # DOMAIN AGE
        features.update(self._extract_domain_age_features(domain_age_result))
        
        return features
    
    def _extract_domain_features(self, domain: str, url: str) -> Dict[str, Any]:
        """Extract domain-related features"""
        features = {}
        
        # URL length
        features["url_length"] = len(url)
        
        # Domain length
        features["domain_length"] = len(domain)
        
        # Subdomain count
        parts = domain.split(".")
        features["subdomain_count"] = max(0, len(parts) - 2)
        
        # Hyphen count
        hyphen_count = domain.count("-")
        features["hyphen_count"] = hyphen_count
        
        # Number count
        number_count = sum(c.isdigit() for c in domain)
        features["number_count"] = number_count
        
        # Digit ratio
        features["digit_ratio"] = number_count / len(domain) if len(domain) > 0 else 0
        
        # Has underscore
        features["has_underscore"] = "_" in domain
        
        # TLD type
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        features["tld_type"] = tld
        
        # Is suspicious TLD
        features["is_suspicious_tld"] = tld in self.SUSPICIOUS_TLDS
        
        return features
    
    def _extract_brand_features(self, brand_result: Optional[Dict], domain: str) -> Dict[str, Any]:
        """Extract brand-related features"""
        features = {
            "has_brand_match": False,
            "brand_similarity": 0.0,
            "is_bank_brand": False,
            "is_gov_brand": False,
            "is_cargo_brand": False,
            "is_ecommerce_brand": False,
            "is_impostor": False,
            "is_typosquat": False
        }
        
        if not brand_result:
            return features
        
        features["has_brand_match"] = brand_result.get("is_impostor", False) or brand_result.get("brand_name") is not None
        features["brand_similarity"] = brand_result.get("similarity_score", 0.0)
        features["is_impostor"] = brand_result.get("is_impostor", False)
        
        category = brand_result.get("brand_category", "").upper()
        features["is_bank_brand"] = category == "BANKING"
        features["is_gov_brand"] = category == "GOVERNMENT"
        features["is_cargo_brand"] = category == "CARGO"
        features["is_ecommerce_brand"] = category == "ECOMMERCE"
        
        match_type = brand_result.get("match_type", "")
        features["is_typosquat"] = match_type == "typosquat"
        
        return features
    
    def _extract_form_features(self, form_result: Optional[Dict]) -> Dict[str, Any]:
        """Extract form-related features"""
        features = {
            "has_login_form": False,
            "has_password_field": False,
            "has_credential_fields": False,
            "has_payment_fields": False,
            "has_otp_field": False,
            "has_external_submit": False,
            "hidden_field_count": 0,
            "has_autocomplete_off": False,
            "form_count": 0
        }
        
        if not form_result:
            return features
        
        features["has_login_form"] = form_result.get("has_login_form", False)
        features["has_password_field"] = form_result.get("has_password_field", False)
        features["has_credential_fields"] = form_result.get("has_credential_fields", False)
        features["has_payment_fields"] = form_result.get("has_payment_fields", False)
        features["has_external_submit"] = form_result.get("has_external_submit", False)
        features["hidden_field_count"] = len(form_result.get("hidden_fields", []))
        features["autocomplete_disabled"] = form_result.get("autocomplete_disabled", False)
        features["form_count"] = form_result.get("form_count", 0)
        
        # Check for OTP in signals
        signals = form_result.get("signals", [])
        features["has_otp_field"] = "otp_field" in signals
        
        return features
    
    def _extract_content_features(self, content_text: str, analysis_result: Dict) -> Dict[str, Any]:
        """Extract content-based features"""
        features = {
            "urgency_word_count": 0,
            "has_urgency": False,
            "has_sms_style": False,
            "bank_word_count": 0,
            "cargo_word_count": 0,
            "reward_word_count": 0,
            "external_script_count": 0,
            "iframe_count": 0,
            "has_obfuscation": False
        }
        
        if not content_text:
            return features
        
        content_lower = content_text.lower()
        
        # Count urgency words
        urgency_count = sum(1 for word in self.URGENCY_WORDS if word in content_lower)
        features["urgency_word_count"] = urgency_count
        features["has_urgency"] = urgency_count > 0
        
        # SMS style detection
        features["has_sms_style"] = self._detect_sms_style(content_text)
        
        # Count keyword categories
        features["bank_word_count"] = sum(1 for word in self.BANK_WORDS if word in content_lower)
        features["cargo_word_count"] = sum(1 for word in self.CARGO_WORDS if word in content_lower)
        features["reward_word_count"] = sum(1 for word in self.REWARD_WORDS if word in content_lower)
        
        # External scripts
        reasons = analysis_result.get("reasons", [])
        external_script_count = sum(1 for r in reasons if "external script" in r.lower())
        features["external_script_count"] = external_script_count
        
        # Iframes
        iframe_count = sum(1 for r in reasons if "iframe" in r.lower())
        features["iframe_count"] = iframe_count
        
        # JS obfuscation
        features["has_obfuscation"] = analysis_result.get("sub_scores", {}).get("js_obfuscation", 0) > 10
        
        return features
    
    def _extract_behavior_features(self, analysis_result: Dict) -> Dict[str, Any]:
        """Extract behavior-based features"""
        features = {
            "redirect_count": 0,
            "has_meta_refresh": False,
            "right_click_disabled": False,
            "text_copy_disabled": False
        }
        
        sub_scores = analysis_result.get("sub_scores", {})
        reasons = analysis_result.get("reasons", [])
        
        # Redirect count (from behavior analysis)
        features["redirect_count"] = sub_scores.get("behavior_analysis", 0) // 10
        
        # Meta refresh
        features["has_meta_refresh"] = any("meta refresh" in r.lower() for r in reasons)
        
        # Right click disabled
        features["right_click_disabled"] = any("right click" in r.lower() for r in reasons)
        
        return features
    
    def _extract_threat_features(self, threat_result: Optional[Dict], analysis_result: Dict) -> Dict[str, Any]:
        """Extract threat intelligence features"""
        features = {
            "threat_intel_match": False,
            "threat_source_score": 0,
        }
        
        if threat_result and threat_result.get("is_threat"):
            features["threat_intel_match"] = True
            
            source = threat_result.get("source", "").lower()
            if source == "usom":
                features["threat_source_score"] = 10
            elif source == "openphish":
                features["threat_source_score"] = 8
            elif source == "urlhaus":
                features["threat_source_score"] = 7
            else:
                features["threat_source_score"] = 5
        
        return features
    
    def _extract_ssl_features(self, analysis_result: Dict) -> Dict[str, Any]:
        """Extract SSL-related features"""
        features = {
            "has_ssl": False,
            "ssl_valid": False,
            "ssl_expires_soon": False
        }
        
        sub_scores = analysis_result.get("sub_scores", {})
        reasons = analysis_result.get("reasons", [])
        
        # Has SSL (URL starts with https)
        features["has_ssl"] = analysis_result.get("url", "").startswith("https")
        
        # SSL valid (from SSL analysis)
        features["ssl_valid"] = sub_scores.get("ssl_cert", 0) > 50
        
        # SSL error
        features["ssl_expires_soon"] = any("ssl" in r.lower() and "error" in r.lower() for r in reasons)
        
        return features
    
    def _extract_domain_age_features(self, domain_age_result: Optional[Dict]) -> Dict[str, Any]:
        """Extract domain age features"""
        features = {
            "domain_age_days": -1,
            "is_new_domain": False,
            "is_recent_domain": False
        }
        
        if not domain_age_result:
            return features
        
        features["domain_age_days"] = domain_age_result.get("age_days", -1)
        features["is_new_domain"] = domain_age_result.get("is_suspicious", False)
        features["is_recent_domain"] = domain_age_result.get("age_category") in ["new", "recent"]
        
        return features
    
    def _get_content_text(self, analysis_result: Dict) -> str:
        """Extract text content from analysis result"""
        reasons = analysis_result.get("reasons", [])
        threat_type = analysis_result.get("threat_type", "")
        return " ".join(reasons) + " " + threat_type
    
    def _detect_sms_style(self, text: str) -> bool:
        """Detect if text is formatted like SMS"""
        sms_indicators = [
            r"\b\d{10,}\b",  # Long number sequences
            r"(?:sayın|sevgili|degerli)",  # Turkish SMS greetings
            r"(?:teslimat|kargo|gonderi)",  # Cargo-related
            r"(?:odeme|odemeniz|bakiye)",  # Payment-related
        ]
        
        for pattern in sms_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        
        return False
    
    def to_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """
        Convert feature dict to ordered feature vector for ML model.
        
        Returns:
            List of feature values in schema order
        """
        vector = []
        for feature_def in ML_FEATURES:
            value = features.get(feature_def.name)
            
            # Convert to float
            if value is None:
                if feature_def.type == "bool":
                    value = 0.0
                elif feature_def.type == "int":
                    value = 0
                elif feature_def.type == "float":
                    value = 0.0
                else:
                    value = 0
            
            if feature_def.type == "bool":
                vector.append(1.0 if value else 0.0)
            else:
                vector.append(float(value))
        
        return vector


# Singleton instance
feature_extractor = FeatureExtractor()
