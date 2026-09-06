"""
PhishShield TR - Brand Similarity Engine
Sprint 5: Detects brand impersonation in domains and content
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class BrandMatchResult:
    """Result of brand matching analysis"""
    brand_name: Optional[str] = None
    brand_category: Optional[str] = None
    is_impostor: bool = False
    similarity_score: float = 0.0
    match_type: str = "none"  # exact, substring, typosquat, combo
    detected_keywords: List[str] = None
    confidence: float = 0.0
    risk_score: int = 0
    
    def __post_init__(self):
        if self.detected_keywords is None:
            self.detected_keywords = []


class BrandMatcher:
    """
    Detects brand impersonation attempts.
    
    Matches:
    - Bank brands (Garanti, Akbank, İşbank, etc.)
    - Government brands (e-Devlet, GİB, SGK, etc.)
    - E-commerce (Trendyol, Hepsiburada, etc.)
    - Cargo companies (Aras, PTT, Yurtiçi, etc.)
    - Social media and tech platforms
    """
    
    # Brand database with official domains and keywords
    BRANDS = {
        # Banking - CRITICAL (high risk)
        "Garanti BBVA": {
            "keywords": ["garanti", "garantibbva", "garantibank"],
            "official_domains": ["garanti.com.tr", "garantibbva.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "Akbank": {
            "keywords": ["akbank", "akbnk"],
            "official_domains": ["akbank.com", "akbank.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "İşbank": {
            "keywords": ["isbank", "isbankasi", "isbank.com"],
            "official_domains": ["isbank.com.tr", "isbankasi.com"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "Ziraat Bank": {
            "keywords": ["ziraat", "ziraatbank"],
            "official_domains": ["ziraat.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "Halkbank": {
            "keywords": ["halkbank", "halk bankasi"],
            "official_domains": ["halkbank.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "VakıfBank": {
            "keywords": ["vakifbank", "vakifbankasi"],
            "official_domains": ["vakifbank.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "QNB Finansbank": {
            "keywords": ["qnb", "qnbbank", "finansbank"],
            "official_domains": ["qnb.com.tr", "finansbank.com"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "TEB": {
            "keywords": ["teb", "turkelectronikbank"],
            "official_domains": ["teb.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "ING Bank": {
            "keywords": ["ing", "ingbank"],
            "official_domains": ["ing.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        "HSBC": {
            "keywords": ["hsbc"],
            "official_domains": ["hsbc.com.tr"],
            "category": "BANKING",
            "risk_level": "CRITICAL"
        },
        
        # Government - CRITICAL
        "e-Devlet": {
            "keywords": ["edevlet", "edevlat", "edevletkapisi", "turkiye.gov.tr"],
            "official_domains": ["turkiye.gov.tr", "edevlet.gov.tr"],
            "category": "GOVERNMENT",
            "risk_level": "CRITICAL"
        },
        "GİB": {
            "keywords": ["gib", "gelirler", "vergidairesi"],
            "official_domains": ["gib.gov.tr"],
            "category": "GOVERNMENT",
            "risk_level": "CRITICAL"
        },
        "SGK": {
            "keywords": ["sgk", "sosyalguvenlik"],
            "official_domains": ["sgk.gov.tr"],
            "category": "GOVERNMENT",
            "risk_level": "CRITICAL"
        },
        "E-Okul": {
            "keywords": ["eokul", "e-okul", "meb", "milliegitim"],
            "official_domains": ["e-okul.com", "meb.gov.tr"],
            "category": "GOVERNMENT",
            "risk_level": "HIGH"
        },
        "UYAP": {
            "keywords": ["uyap", "uyapkapis", "adliye"],
            "official_domains": ["uyap.gov.tr"],
            "category": "GOVERNMENT",
            "risk_level": "CRITICAL"
        },
        
        # E-Commerce - HIGH
        "Trendyol": {
            "keywords": ["trendyol", "ty", "trendy"],
            "official_domains": ["trendyol.com"],
            "category": "ECOMMERCE",
            "risk_level": "HIGH"
        },
        "Hepsiburada": {
            "keywords": ["hepsiburada", "hb", "hb.com"],
            "official_domains": ["hepsiburada.com"],
            "category": "ECOMMERCE",
            "risk_level": "HIGH"
        },
        "N11": {
            "keywords": ["n11", "n11.com"],
            "official_domains": ["n11.com"],
            "category": "ECOMMERCE",
            "risk_level": "HIGH"
        },
        "Amazon": {
            "keywords": ["amazon"],
            "official_domains": ["amazon.com.tr", "amazon.com"],
            "category": "ECOMMERCE",
            "risk_level": "HIGH"
        },
        
        # Cargo - HIGH
        "Aras Kargo": {
            "keywords": ["aras", "araskargo", "aras-kargo"],
            "official_domains": ["araskargo.com.tr"],
            "category": "CARGO",
            "risk_level": "HIGH"
        },
        "PTT": {
            "keywords": ["ptt", "pttkargo", "posta"],
            "official_domains": ["ptt.gov.tr", "ptt.com.tr"],
            "category": "CARGO",
            "risk_level": "HIGH"
        },
        "Yurtiçi Kargo": {
            "keywords": ["yurtici", "yurticikargo", "yurtiçi"],
            "official_domains": ["yurticikargo.com"],
            "category": "CARGO",
            "risk_level": "HIGH"
        },
        "MNG Kargo": {
            "keywords": ["mng", "mngkargo"],
            "official_domains": ["mngkargo.com"],
            "category": "CARGO",
            "risk_level": "HIGH"
        },
        "UPS": {
            "keywords": ["ups", "upskargo"],
            "official_domains": ["ups.com.tr"],
            "category": "CARGO",
            "risk_level": "MEDIUM"
        },
        "DHL": {
            "keywords": ["dhl", "dhlkargo"],
            "official_domains": ["dhl.com.tr"],
            "category": "CARGO",
            "risk_level": "MEDIUM"
        },
        
        # Social Media / Tech - MEDIUM
        "LinkedIn": {
            "keywords": ["linkedin", "linked-in"],
            "official_domains": ["linkedin.com"],
            "category": "TECH",
            "risk_level": "MEDIUM"
        },
        "Instagram": {
            "keywords": ["instagram", "insta"],
            "official_domains": ["instagram.com"],
            "category": "SOCIAL",
            "risk_level": "MEDIUM"
        },
        "Facebook": {
            "keywords": ["facebook", "fb"],
            "official_domains": ["facebook.com"],
            "category": "SOCIAL",
            "risk_level": "MEDIUM"
        },
        "WhatsApp": {
            "keywords": ["whatsapp", "wa.me"],
            "official_domains": ["whatsapp.com"],
            "category": "SOCIAL",
            "risk_level": "LOW"
        },
        
        # Streaming - LOW
        "Netflix": {
            "keywords": ["netflix", "netflx"],
            "official_domains": ["netflix.com"],
            "category": "STREAMING",
            "risk_level": "MEDIUM"
        },
        "Spotify": {
            "keywords": ["spotify", "spotfy"],
            "official_domains": ["spotify.com"],
            "category": "STREAMING",
            "risk_level": "LOW"
        },
    }
    
    # Typosquatting patterns
    TYPOSQUATTING_PATTERNS = [
        # Extra letters
        (r'g00gle', 'google'),
        (r'garantti', 'garanti'),
        (r'akbannk', 'akbank'),
        (r'isbanck', 'isbank'),
        # Missing letters
        (r'gooogle', 'google'),
        (r'garantii', 'garanti'),
        # Swapped letters
        (r'googel', 'google'),
        (r'garanti', 'garanti'),  # Common ones
    ]
    
    def __init__(self):
        self._build_keyword_index()
    
    def _build_keyword_index(self):
        """Build inverted index of keywords -> brands"""
        self.keyword_index: Dict[str, str] = {}
        for brand_name, brand_data in self.BRANDS.items():
            for keyword in brand_data["keywords"]:
                self.keyword_index[keyword.lower()] = brand_name
    
    def analyze_domain(self, domain: str) -> BrandMatchResult:
        """
        Analyze a domain for brand impersonation.
        
        Args:
            domain: Domain to check (e.g., "garanti-login.xyz")
        
        Returns:
            BrandMatchResult with findings
        """
        domain_lower = domain.lower()
        result = BrandMatchResult()
        
        # Check exact match (shouldn't be impostor)
        for brand_name, brand_data in self.BRANDS.items():
            for official in brand_data["official_domains"]:
                if domain_lower == official or domain_lower.endswith('.' + official):
                    result.brand_name = brand_name
                    result.brand_category = brand_data["category"]
                    result.is_impostor = False
                    result.match_type = "official"
                    result.confidence = 1.0
                    return result
        
        # Check keywords
        detected_brands = []
        for keyword, brand_name in self.keyword_index.items():
            if keyword in domain_lower:
                detected_brands.append(brand_name)
        
        if not detected_brands:
            return result
        
        # Use the highest risk brand found
        best_match = self._select_best_brand(detected_brands)
        brand_data = self.BRANDS[best_match]
        
        result.brand_name = best_match
        result.brand_category = brand_data["category"]
        result.is_impostor = True
        result.match_type = self._detect_match_type(domain_lower, best_match)
        result.detected_keywords = [kw for kw in brand_data["keywords"] if kw in domain_lower]
        
        # Calculate similarity and risk
        result.similarity_score = self._calculate_similarity(domain_lower, best_match)
        result.confidence = self._calculate_confidence(result)
        result.risk_score = self._calculate_risk_score(result, brand_data)
        
        return result
    
    def analyze_content(self, text: str, domain: str) -> BrandMatchResult:
        """
        Analyze page content for brand mentions.
        
        Args:
            text: Page text content
            domain: Page domain
        
        Returns:
            BrandMatchResult
        """
        text_lower = text.lower()
        result = self.analyze_domain(domain)
        
        if result.is_impostor:
            # Content analysis could increase or decrease confidence
            brand_data = self.BRANDS.get(result.brand_name, {})
            brand_text = result.brand_name.lower()
            
            # If brand name appears many times in content, likely impersonating
            mentions = text_lower.count(brand_text)
            if mentions > 5:
                result.confidence = min(1.0, result.confidence + 0.2)
                result.risk_score = min(100, result.risk_score + 10)
        
        return result
    
    def _select_best_brand(self, brands: List[str]) -> str:
        """Select the most relevant brand from detected brands"""
        # Prefer higher risk categories
        priority = {"BANKING": 4, "GOVERNMENT": 3, "ECOMMERCE": 2, "CARGO": 2, "SOCIAL": 1, "TECH": 1, "STREAMING": 0}
        
        def get_priority(b: str) -> int:
            brand_data = self.BRANDS.get(b, {})
            return priority.get(brand_data.get("category", ""), 0)
        
        return max(brands, key=get_priority)
    
    def _detect_match_type(self, domain: str, brand_name: str) -> str:
        """Detect how the brand is being impersonated"""
        brand_data = self.BRANDS.get(brand_name, {})
        keywords = brand_data.get("keywords", [])
        
        # Check for typo patterns
        for pattern, _ in self.TYPOSQUATTING_PATTERNS:
            if re.search(pattern, domain):
                return "typosquat"
        
        # Check for keyword + extra words (login, secure, etc.)
        for keyword in keywords:
            if keyword in domain:
                # Has brand keyword + suspicious additions
                if any(x in domain for x in ['login', 'giris', 'secure', 'security', 'account', 'update', 'verify', 'signin', 'uyelik']):
                    return "login_page"
                return "substring"
        
        return "unknown"
    
    def _calculate_similarity(self, domain: str, brand_name: str) -> float:
        """Calculate similarity score between domain and brand"""
        brand_data = self.BRANDS.get(brand_name, {})
        keywords = brand_data.get("keywords", [])
        
        if not keywords:
            return 0.0
        
        # Best keyword match
        best_match = 0.0
        for keyword in keywords:
            if keyword in domain:
                # Length-based similarity
                match_len = len(keyword)
                domain_len = len(domain)
                ratio = match_len / domain_len
                best_match = max(best_match, ratio)
        
        return best_match
    
    def _calculate_confidence(self, result: BrandMatchResult) -> float:
        """Calculate confidence in the detection"""
        confidence = 0.5  # Base
        
        # More keywords = higher confidence
        confidence += min(0.2, len(result.detected_keywords) * 0.05)
        
        # Higher similarity = higher confidence
        confidence += result.similarity_score * 0.2
        
        # Specific match types
        if result.match_type == "typosquat":
            confidence += 0.15
        elif result.match_type == "login_page":
            confidence += 0.2
        
        return min(0.99, confidence)
    
    def _calculate_risk_score(self, result: BrandMatchResult, brand_data: Dict) -> int:
        """Calculate risk score based on brand and match"""
        base_risk = {
            "CRITICAL": 50,
            "HIGH": 35,
            "MEDIUM": 20,
            "LOW": 10
        }.get(brand_data.get("risk_level", "MEDIUM"), 25)
        
        # Match type bonus
        match_bonus = {
            "typosquat": 20,
            "login_page": 25,
            "substring": 10,
            "unknown": 5
        }.get(result.match_type, 0)
        
        # Keyword count bonus
        keyword_bonus = min(15, len(result.detected_keywords) * 5)
        
        return min(100, base_risk + match_bonus + keyword_bonus)
    
    def get_signals(self, result: BrandMatchResult) -> List[str]:
        """Convert brand match to signal list"""
        signals = []
        
        if not result.is_impostor:
            return signals
        
        signals.append("brand_impostor")
        
        if result.brand_category == "BANKING":
            signals.append("bank_brand_match")
        elif result.brand_category == "GOVERNMENT":
            signals.append("gov_brand_match")
        elif result.brand_category == "ECOMMERCE":
            signals.append("ecommerce_brand_match")
        elif result.brand_category == "CARGO":
            signals.append("cargo_brand_match")
        
        if result.match_type == "typosquat":
            signals.append("typosquatting")
        elif result.match_type == "login_page":
            signals.append("fake_login_page")
        
        return signals


# Singleton instance
brand_matcher = BrandMatcher()
