"""
PhishShield TR - OpenPhish Source
Sprint 4: OpenPhish feed integration
"""

import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Optional

from ..models import ThreatMatch, ThreatSeverity


class OpenPhishSource:
    """OpenPhish threat intelligence source"""
    
    SOURCE_NAME = "openphish"
    FEED_URL = "https://openphish.com/feed.txt"
    
    def __init__(self):
        self.name = "OpenPhish"
        self.source_type = "openphish"
        self.threat_level = 8
        self.last_update: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.enabled = True
    
    async def fetch(self) -> List[str]:
        """
        Fetch domains from OpenPhish feed.
        
        Returns:
            List of phishing domains
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
                            if line and not line.startswith('#'):
                                # Extract domain from URL
                                domain = self._extract_domain(line)
                                if domain:
                                    domains.append(domain)
                        
                        self.last_update = datetime.now()
                        self.last_error = None
                    else:
                        self.last_error = f"HTTP {response.status}"
        except Exception as e:
            self.last_error = str(e)
        
        return domains
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            if not url.startswith('http'):
                url = 'https://' + url
            parsed = urlparse(url)
            if parsed.netloc:
                # Remove port if present
                domain = parsed.netloc.split(':')[0]
                return domain.lower()
        except:
            pass
        return None
    
    def to_threat_match(self, domain: str) -> ThreatMatch:
        """Convert domain to ThreatMatch"""
        return ThreatMatch(
            is_threat=True,
            domain=domain,
            source=self.SOURCE_NAME,
            category="phishing",
            severity=ThreatSeverity.CRITICAL.value,
            confidence=0.95,
            first_seen=self.last_update,
            last_seen=self.last_update,
            tags=["phishing", "openphish"],
            reference_url=f"https://openphish.com/feed.txt"
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
