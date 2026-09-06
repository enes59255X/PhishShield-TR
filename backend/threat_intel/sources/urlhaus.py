"""
PhishShield TR - URLhaus Source
Sprint 4: URLhaus feed integration
"""

import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Optional

from ..models import ThreatMatch, ThreatSeverity


class URLhausSource:
    """URLhaus threat intelligence source"""
    
    SOURCE_NAME = "urlhaus"
    FEED_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
    
    def __init__(self):
        self.name = "URLhaus"
        self.source_type = "urlhaus"
        self.threat_level = 7
        self.last_update: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.enabled = True
    
    async def fetch(self) -> List[str]:
        """
        Fetch domains from URLhaus hostfile.
        
        Returns:
            List of malicious domains
        """
        domains = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.FEED_URL,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.strip().split('\n'):
                            line = line.strip()
                            # Skip comments and empty lines
                            if line.startswith('#') or not line:
                                continue

                            # Extract domain from hostfile format:
                            # "127.0.0.1 domain.com # comment"
                            parts = line.split()
                            if len(parts) >= 2:
                                # IP is first part, domain is second
                                domain = self._clean_domain(parts[1])
                                if domain:
                                    domains.append(domain)
                        
                        self.last_update = datetime.now()
                        self.last_error = None
                    else:
                        self.last_error = f"HTTP {response.status}"
        except Exception as e:
            self.last_error = str(e)
        
        return domains
    
    def _clean_domain(self, domain: str) -> Optional[str]:
        """Clean and validate domain"""
        domain = domain.strip().lower()
        # Remove any comments after domain
        if '#' in domain:
            domain = domain.split('#')[0].strip()
        # Remove port
        if ':' in domain:
            domain = domain.split(':')[0]
        # Basic validation
        if domain and '.' in domain and not domain.startswith('.'):
            return domain
        return None
    
    def to_threat_match(self, domain: str) -> ThreatMatch:
        """Convert domain to ThreatMatch"""
        return ThreatMatch(
            is_threat=True,
            domain=domain,
            source=self.SOURCE_NAME,
            category="malware",
            severity=ThreatSeverity.CRITICAL.value,
            confidence=0.90,
            first_seen=self.last_update,
            last_seen=self.last_update,
            tags=["malware", "urlhaus"],
            reference_url=f"https://urlhaus.abuse.ch/"
        )
    
    def get_status(self) -> Dict:
        """Get source status"""
        return {
            "name": self.name,
            "status": "OK" if self.last_error is None else "ERROR",
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "last_error": self.last_error,
            "threat_level": self.threat_level
        }
