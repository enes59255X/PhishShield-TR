"""
PhishShield TR - Domain Age Analyzer
Sprint 5: Detects newly registered domains (phishing indicator)
"""

import socket
import whois
from datetime import datetime, timedelta
from typing import Optional, Dict
from dataclasses import dataclass


@dataclass
class DomainAgeResult:
    """Result of domain age analysis"""
    domain: str
    creation_date: Optional[datetime] = None
    age_days: Optional[int] = None
    age_category: str = "unknown"  # new, recent, established, old
    risk_score: int = 0
    is_suspicious: bool = False
    error: Optional[str] = None
    
    # WHOIS data (if available)
    registrar: Optional[str] = None
    expiration_date: Optional[datetime] = None
    nameservers: list = None
    
    def __post_init__(self):
        if self.nameservers is None:
            self.nameservers = []


class DomainAgeAnalyzer:
    """
    Analyzes domain age to detect phishing sites.
    
    Key insight: Most phishing domains are newly registered
    Legitimate sites tend to be established
    
    Age thresholds:
    - NEW: < 30 days (very suspicious)
    - RECENT: 30-90 days (somewhat suspicious)
    - ESTABLISHED: 90-365 days (normal)
    - OLD: > 365 days (generally safe)
    """
    
    THRESHOLDS = {
        "new_max": 30,        # days
        "recent_max": 90,     # days
        "established_max": 365 # days
    }
    
    RISK_SCORES = {
        "new": 40,
        "recent": 20,
        "established": 0,
        "old": -10,
        "unknown": 10
    }
    
    def __init__(self):
        self._cache: Dict[str, DomainAgeResult] = {}
        self._cache_duration = timedelta(hours=1)
    
    def analyze(self, domain: str) -> DomainAgeResult:
        """
        Analyze domain age.
        
        Args:
            domain: Domain to analyze (e.g., "example.com")
        
        Returns:
            DomainAgeResult with findings
        """
        # Check cache first
        if domain in self._cache:
            cached = self._cache[domain]
            # Cache valid for 1 hour
            if datetime.now() - getattr(cached, '_cached_at', datetime.min) < self._cache_duration:
                return cached
        
        result = DomainAgeResult(domain=domain)
        
        try:
            # Clean domain
            domain = self._clean_domain(domain)
            
            # Try WHOIS lookup
            w = whois.whois(domain)
            
            if w.domain_name:
                if isinstance(w.domain_name, list):
                    result.domain = w.domain_name[0].lower()
                else:
                    result.domain = w.domain_name.lower()
            
            # Get creation date
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    result.creation_date = w.creation_date[0]
                else:
                    result.creation_date = w.creation_date
            
            # Calculate age
            if result.creation_date:
                result.age_days = (datetime.now() - result.creation_date).days
                result.age_category = self._categorize_age(result.age_days)
                result.risk_score = self.RISK_SCORES.get(result.age_category, 10)
                result.is_suspicious = result.age_days < self.THRESHOLDS["new_max"]
            
            # Additional WHOIS data
            if w.registrar:
                result.registrar = w.registrar
            
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    result.expiration_date = w.expiration_date[0]
                else:
                    result.expiration_date = w.expiration_date
            
            if w.name_servers:
                if isinstance(w.name_servers, list):
                    result.nameservers = w.name_servers
                else:
                    result.nameservers = [w.name_servers]
                    
        except whois.parser.PywhoisError as e:
            result.error = f"WHOIS error: {str(e)}"
            result.risk_score = 5  # Minor risk for lookup failure
        except socket.gaierror:
            result.error = "DNS resolution failed"
            result.risk_score = 5
        except Exception as e:
            result.error = f"Analysis error: {str(e)}"
            result.risk_score = 5
        
        # Cache result
        result._cached_at = datetime.now()
        self._cache[domain] = result
        
        return result
    
    def _clean_domain(self, domain: str) -> str:
        """Clean domain string"""
        domain = domain.lower().strip()
        # Remove protocol
        if '://' in domain:
            domain = domain.split('://')[1]
        # Remove path
        if '/' in domain:
            domain = domain.split('/')[0]
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    
    def _categorize_age(self, days: int) -> str:
        """Categorize domain age"""
        if days < 0:
            return "future"  # Invalid
        if days < self.THRESHOLDS["new_max"]:
            return "new"
        if days < self.THRESHOLDS["recent_max"]:
            return "recent"
        if days < self.THRESHOLDS["established_max"]:
            return "established"
        return "old"
    
    def get_signals(self, result: DomainAgeResult) -> list:
        """Convert domain age to signal list"""
        signals = []
        
        if result.age_category == "new":
            signals.append("new_domain")
            signals.append("new_domain_phishing_indicator")
        elif result.age_category == "recent":
            signals.append("recent_domain")
        
        if result.is_suspicious:
            signals.append("domain_age_anomaly")
        
        return signals


# Singleton instance
domain_age_analyzer = DomainAgeAnalyzer()
