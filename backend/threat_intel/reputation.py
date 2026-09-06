"""
PhishShield TR - Threat Reputation Engine
Sprint 4: Core threat lookup and matching logic
"""

from typing import Optional
from urllib.parse import urlparse

from .models import ThreatMatch, ThreatSeverity
from .threat_db import threat_db
from .cache import threat_cache


class ThreatReputation:
    """
    Threat Reputation Engine.
    
    Main entry point for checking URLs/domains against threat intelligence.
    
    Features:
    - Fast in-memory cache lookup
    - SQLite database for persistence
    - Subdomain matching (evil.google.com matches google.com threat)
    - No typo matching (google-security.com does NOT match google.com)
    """
    
    # Trusted domains that should never be flagged
    TRUSTED_DOMAINS = {
        "google.com", "youtube.com", "facebook.com", "twitter.com", "linkedin.com",
        "github.com", "microsoft.com", "apple.com", "amazon.com", "chatgpt.com",
        "openai.com", "anthropic.com", "turkiye.gov.tr", "gov.tr", "edu.tr",
        "garanti.com.tr", "akbank.com", "isbank.com", "yapikredi.com.tr",
        "hsbc.com.tr", "qnb.com.tr", "ziraatbank.com.tr", " denominations.com"
    }
    
    def __init__(self):
        self.cache = threat_cache
    
    def check_url(self, url: str) -> ThreatMatch:
        """
        Check if a URL is a known threat.
        
        Args:
            url: URL to check
        
        Returns:
            ThreatMatch with details if found, empty match if clean
        """
        domain = self._extract_domain(url)
        if not domain:
            return ThreatMatch(is_threat=False)
        
        return self.check_domain(domain)
    
    def check_domain(self, domain: str) -> ThreatMatch:
        """
        Check if a domain is a known threat.
        
        Domain matching rules:
        - Exact match: evil.google.com == evil.google.com ✓
        - Subdomain match: evil.google.com contains google.com ✓
        - Parent match: google.com is parent of evil.google.com ✓
        - NO typo match: google-security.com does NOT match google.com ✗
        
        Args:
            domain: Domain to check
        
        Returns:
            ThreatMatch with details if found, empty match if clean
        """
        domain_lower = domain.lower()
        
        # Check trusted domains first
        if self._is_trusted(domain_lower):
            return ThreatMatch(is_threat=False)
        
        # Check cache first
        cached = self.cache.get(domain_lower)
        if cached is not None:
            return cached
        
        # Check database
        match = self._check_database(domain_lower)
        
        # Cache the result
        self.cache.set(domain_lower, match)
        
        return match
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            parsed = urlparse(url)
            if parsed.netloc:
                domain = parsed.netloc.split(':')[0].lower()
                return domain
        except:
            pass
        return None
    
    def _is_trusted(self, domain: str) -> bool:
        """Check if domain is in trusted list"""
        # Exact match
        if domain in self.TRUSTED_DOMAINS:
            return True
        
        # Check if it's a subdomain of a trusted domain
        for trusted in self.TRUSTED_DOMAINS:
            if domain.endswith('.' + trusted):
                return True
        
        return False
    
    def _check_database(self, domain: str) -> ThreatMatch:
        """
        Check database for domain threat.
        
        Uses three strategies:
        1. Exact match
        2. Subdomain match (check if any parent is a threat)
        3. Reverse subdomain (check if domain is parent of any threat)
        """
        # Strategy 1: Exact match
        match = threat_db.is_threat(domain)
        if match and match.is_threat:
            return match
        
        # Strategy 2: Check parent domains (subdomain of a threat)
        # E.g., evil.phase.google.com -> check google.com
        match = threat_db.check_subdomain(domain)
        if match and match.is_threat:
            return match
        
        # Strategy 3: Direct parent check
        # E.g., google.com.check.evil.com -> check google.com
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            parent = '.'.join(parts[i:])
            match = threat_db.is_threat(parent)
            if match and match.is_threat:
                # Adjust confidence - subdomain is slightly less certain
                match.confidence *= 0.95
                return match
        
        return ThreatMatch(is_threat=False)
    
    def add_to_threat_db(
        self,
        domain: str,
        source: str,
        category: str = "phishing",
        severity: str = "critical",
        confidence: float = 0.9
    ) -> bool:
        """
        Manually add a domain to the threat database.
        
        Returns:
            True if added, False if already existed
        """
        return threat_db.add_threat(
            domain=domain,
            source=source,
            category=category,
            severity=severity,
            confidence=confidence
        )
    
    def get_stats(self):
        """Get reputation engine statistics"""
        return {
            "cache_stats": self.cache.get_stats(),
            "db_stats": threat_db.get_stats().to_dict(),
            "trusted_domains": len(self.TRUSTED_DOMAINS)
        }


# Singleton instance
threat_reputation = ThreatReputation()
