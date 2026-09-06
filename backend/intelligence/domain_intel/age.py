"""
PhishShield TR - Domain Age Analyzer
Sprint 11: Analyzes domain age for phishing detection

Phishing domains are typically newly registered:
- Legitimate sites: Usually > 180 days old
- Phishing sites: Often < 30 days old
- Suspicious: 30-90 days
"""

import socket
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


@dataclass
class DomainAgeResult:
    """Result of domain age analysis"""
    domain: str
    age_days: int  # -1 if unknown
    registration_date: Optional[datetime]
    expiration_date: Optional[datetime]
    days_until_expiry: int
    age_category: str  # "new", "recent", "established", "unknown"
    risk_level: int  # 0-100

    # Details
    is_new_domain: bool
    is_expiring_soon: bool
    is_free_domain: bool  # Free TLDs often used for phishing

    # WHOIS info
    registrar: Optional[str]
    nameservers: list

    # Risk info
    risk_reasons: list = None

    def __post_init__(self):
        if self.risk_reasons is None:
            self.risk_reasons = []


class DomainAgeAnalyzer:
    """
    Analyzes domain age and registration patterns.

    Risk scoring:
    - < 7 days: Very high risk (100)
    - 7-30 days: High risk (80)
    - 30-90 days: Medium risk (50)
    - 90-180 days: Low risk (25)
    - > 180 days: Minimal risk (0)
    """

    # Age thresholds in days
    AGE_THRESHOLDS = {
        "very_new": 7,
        "new": 30,
        "recent": 90,
        "established": 180,
    }

    # Free/spam TLDs commonly used for phishing
    FREE_TLDS = {
        ".xyz", ".top", ".click", ".link", ".gq", ".tk", ".ml", ".cf", ".ga",
        ".pw", ".ru", ".cn", ".su", ".cc", ".to", ".ws", ".biz", ".info",
        ".online", ".site", ".website", ".space", ".fun", ".icu", ".rest",
        ".click", ".loan", ".work", ".date", ".racing", ".download", ".bid",
        ".win", ".review", ".stream", ".trade", ".accountant", ".bar", ".click",
        ".download", ".faith", ".faith", ".loan", ".racing", ".review",
        ".stream", ".trade", ".win", ".date", ".party", ".cricket", ".science",
        ".accountant", ".faith", ".work"
    }

    def __init__(self):
        self.cache: Dict[str, DomainAgeResult] = {}

    def analyze(self, domain: str, use_cache: bool = True) -> DomainAgeResult:
        """
        Analyze domain age.

        Args:
            domain: Domain to analyze (e.g., "example.com")
            use_cache: Use cached results if available

        Returns:
            DomainAgeResult with age analysis
        """
        # Clean domain
        domain = self._clean_domain(domain)

        # Check cache
        if use_cache and domain in self.cache:
            return self.cache[domain]

        # Perform analysis
        result = self._analyze_domain(domain)

        # Cache result
        if use_cache:
            self.cache[domain] = result

        return result

    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize domain"""
        domain = domain.lower().strip()

        # Remove protocol
        if "://" in domain:
            domain = domain.split("://")[1]

        # Remove path
        if "/" in domain:
            domain = domain.split("/")[0]

        # Remove port
        if ":" in domain:
            domain = domain.split(":")[0]

        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    def _analyze_domain(self, domain: str) -> DomainAgeResult:
        """Perform actual domain age analysis"""
        result = DomainAgeResult(
            domain=domain,
            age_days=-1,
            registration_date=None,
            expiration_date=None,
            days_until_expiry=-1,
            age_category="unknown",
            risk_level=0,
            is_new_domain=False,
            is_expiring_soon=False,
            is_free_domain=self._is_free_tld(domain),
            registrar=None,
            nameservers=[]
        )

        if not WHOIS_AVAILABLE:
            result.age_category = "whois_unavailable"
            result.risk_level = 15
            result.risk_reasons = ["WHOIS bilgisi cekilemedi"] if hasattr(result, 'risk_reasons') else None
            return result

        try:
            # Try WHOIS lookup
            w = whois.whois(domain)

            # Registration date
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    result.registration_date = w.creation_date[0]
                else:
                    result.registration_date = w.creation_date

            # Expiration date
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    result.expiration_date = w.expiration_date[0]
                else:
                    result.expiration_date = w.expiration_date

            # Calculate age
            if result.registration_date:
                try:
                    result.age_days = (datetime.now() - result.registration_date.replace(tzinfo=None)).days
                except (AttributeError, TypeError):
                    result.age_days = -1

            # Days until expiry
            if result.expiration_date:
                try:
                    result.days_until_expiry = (result.expiration_date.replace(tzinfo=None) - datetime.now()).days
                    result.is_expiring_soon = result.days_until_expiry < 30
                except (AttributeError, TypeError):
                    result.days_until_expiry = -1

            # Determine category
            result.age_category = self._get_age_category(result.age_days)
            result.is_new_domain = result.age_days < self.AGE_THRESHOLDS["new"]

            # Calculate risk
            result.risk_level = self._calculate_risk(result)

            # Registrar
            if w.registrar:
                result.registrar = str(w.registrar)

            # Nameservers
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    result.nameservers = [str(ns) for ns in w.name_servers]
                else:
                    result.nameservers = [str(w.name_servers)]

        except (socket.gaierror, socket.timeout):
            # DNS resolution error
            result.age_category = "unresolvable"
            result.risk_level = 20

        except Exception as e:
            # Other errors - domain might be too new or private
            result.age_category = "unknown"
            result.risk_level = 10

        return result

    def _is_free_tld(self, domain: str) -> bool:
        """Check if domain uses a free/spam TLD"""
        tld = "." + domain.split(".")[-1] if "." in domain else ""
        return tld.lower() in self.FREE_TLDS

    def _get_age_category(self, age_days: int) -> str:
        """Get age category from days"""
        if age_days < 0:
            return "unknown"
        if age_days < self.AGE_THRESHOLDS["very_new"]:
            return "very_new"
        if age_days < self.AGE_THRESHOLDS["new"]:
            return "new"
        if age_days < self.AGE_THRESHOLDS["recent"]:
            return "recent"
        if age_days < self.AGE_THRESHOLDS["established"]:
            return "established"
        return "old"

    def _calculate_risk(self, result: DomainAgeResult) -> int:
        """Calculate risk score from domain age"""
        if result.age_days < 0:
            # Unknown age - moderate risk
            return 20

        # Age-based risk
        age_risk = 0
        if result.age_days < self.AGE_THRESHOLDS["very_new"]:
            age_risk = 100
        elif result.age_days < self.AGE_THRESHOLDS["new"]:
            age_risk = 80
        elif result.age_days < self.AGE_THRESHOLDS["recent"]:
            age_risk = 50
        elif result.age_days < self.AGE_THRESHOLDS["established"]:
            age_risk = 25
        else:
            age_risk = 0

        # Free TLD bonus
        if result.is_free_domain:
            age_risk = min(100, age_risk + 10)

        # Expiring soon bonus
        if result.is_expiring_soon:
            age_risk = min(100, age_risk + 15)

        return age_risk

    def get_risk_description(self, result: DomainAgeResult) -> str:
        """Get human-readable risk description"""
        if result.age_category == "very_new":
            return f"Cok yeni domain ({result.age_days} gun) - yuksek risk"
        if result.age_category == "new":
            return f"Yeni domain ({result.age_days} gun) - Dikkatli olun"
        if result.age_category == "recent":
            return f"Yeni sayilabilecek domain ({result.age_days} gun)"
        if result.age_category == "established":
            return f"Olgun domain ({result.age_days} gun)"
        if result.age_category == "old":
            return f"Uzun suredir aktif domain ({result.age_days} gun)"
        if result.age_category == "unknown":
            return "Domain yasi bilinmiyor"
        if result.age_category == "private":
            return "Private/whois guard kullanan domain"
        return "Domain analizi yapilamadi"


# Singleton instance
domain_age_analyzer = DomainAgeAnalyzer()
