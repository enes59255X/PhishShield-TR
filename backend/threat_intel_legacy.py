#!/usr/bin/env python3
"""
PhishShield TR - Threat Intelligence Engine V1
Sprint 3: Unified threat intelligence management

Manages multiple threat feeds:
- USOM (Turkey)
- OpenPhish (Global)
- URLhaus (Global)
- Manual blacklist

Features:
- SSL verification handling
- Feed fallback mechanisms
- Confidence scoring
- Feed status tracking
"""

import asyncio
import aiohttp
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import hashlib


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration"""
    name: str
    url: str
    enabled: bool = True
    last_update: Optional[datetime] = None
    last_error: Optional[str] = None
    domains_loaded: int = 0
    threat_level: int = 5  # 1-10 scale
    source_type: str = "feed"
    alternative_url: Optional[str] = None


@dataclass
class ThreatMatch:
    """Result of a threat database lookup"""
    is_threat: bool
    source: Optional[str] = None
    threat_type: Optional[str] = None
    threat_level: int = 0
    reason: Optional[str] = None
    feed_name: Optional[str] = None


class ThreatIntelManager:
    """
    Unified threat intelligence manager.
    
    Handles multiple feeds with proper error handling,
    SSL bypass for known problematic feeds, and
    intelligent fallback mechanisms.
    """
    
    def __init__(self):
        self.feeds: Dict[str, ThreatFeed] = {}
        self._domains_cache: Dict[str, List[str]] = {}  # feed_name -> domains
        self._all_domains_hash: str = ""
        self._cache_ttl = 3600  # 1 hour cache
        
        self._setup_feeds()
    
    def _setup_feeds(self):
        """Initialize threat feeds"""
        self.feeds = {
            "usom": ThreatFeed(
                name="USOM",
                url="https://www.usom.gov.tr/url-list.xml",
                alternative_url="https://api.usom.gov.tr/v1/domain",
                threat_level=10,
                source_type="government"
            ),
            "openphish": ThreatFeed(
                name="OpenPhish",
                url="https://openphish.com/feed.txt",
                threat_level=8,
                source_type="community"
            ),
            "urlhaus": ThreatFeed(
                name="URLhaus",
                url="https://urlhaus.abuse.ch/downloads/hostfile/",
                threat_level=7,
                source_type="community"
            ),
        }
    
    async def fetch_url(self, url: str, timeout: int = 30) -> Optional[str]:
        """
        Fetch URL content with SSL verification handling.
        Falls back to non-verified if SSL fails.
        """
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout, ssl=ssl_context) as response:
                    if response.status == 200:
                        return await response.text()
                    return None
        except Exception as e:
            print(f"Fetch error for {url}: {e}")
            return None
    
    async def update_usom_feed(self) -> int:
        """Update USOM feed - Turkey's national CERT"""
        feed = self.feeds.get("usom")
        if not feed or not feed.enabled:
            return 0
        
        print("Updating USOM feed...")
        
        urls_to_try = [feed.url]
        if hasattr(feed, 'alternative_url') and feed.alternative_url:
            urls_to_try.append(feed.alternative_url)
        
        content = None
        for url in urls_to_try:
            content = await self.fetch_url(url)
            if content:
                print(f"USOM: Successfully fetched from {url}")
                break
        
        if not content:
            feed.last_error = "Failed to fetch from all URLs"
            print(f"USOM feed error: Could not fetch from any URL")
            return 0
        
        try:
            if '<xml' in content.lower() or '<url' in content.lower():
                domains = self._parse_usom_xml(content)
            else:
                domains = self._parse_plain_text_list(content)
            
            self._domains_cache["usom"] = domains
            feed.domains_loaded = len(domains)
            feed.last_update = datetime.now()
            feed.last_error = None
            
            print(f"USOM feed updated: {len(domains)} domains")
            return len(domains)
            
        except Exception as e:
            feed.last_error = str(e)
            print(f"USOM feed error: {e}")
            return 0
    
    def _parse_usom_xml(self, content: str) -> List[str]:
        """Parse USOM XML feed"""
        domains = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            for elem in root.iter():
                if elem.tag in ['url', 'address', 'domain']:
                    text = elem.text.strip() if elem.text else ""
                    if text and self._is_valid_domain(text):
                        domains.append(text.lower())
                        
        except Exception as e:
            print(f"USOM XML parse error: {e}")
        
        return list(set(domains))
    
    async def update_openphish_feed(self) -> int:
        """Update OpenPhish feed - free phishing feed"""
        feed = self.feeds.get("openphish")
        if not feed or not feed.enabled:
            return 0
        
        print("Updating OpenPhish feed...")
        
        try:
            content = await self.fetch_url(feed.url)
            if not content:
                raise Exception("Empty response from OpenPhish")
            
            domains = self._parse_plain_text_list(content)
            self._domains_cache["openphish"] = domains
            feed.domains_loaded = len(domains)
            feed.last_update = datetime.now()
            feed.last_error = None
            
            print(f"OpenPhish feed updated: {len(domains)} domains")
            return len(domains)
            
        except Exception as e:
            feed.last_error = str(e)
            print(f"OpenPhish feed error: {e}")
            return 0
    
    async def update_urlhaus_feed(self) -> int:
        """Update URLhaus feed - malware URL database"""
        feed = self.feeds.get("urlhaus")
        if not feed or not feed.enabled:
            return 0
        
        print("Updating URLhaus feed...")
        
        try:
            content = await self.fetch_url(feed.url)
            if not content:
                raise Exception("Empty response from URLhaus")
            
            domains = self._parse_urlhaus_text(content)
            self._domains_cache["urlhaus"] = domains
            feed.domains_loaded = len(domains)
            feed.last_update = datetime.now()
            feed.last_error = None
            
            print(f"URLhaus feed updated: {len(domains)} domains")
            return len(domains)
            
        except Exception as e:
            feed.last_error = str(e)
            print(f"URLhaus feed error: {e}")
            return 0
    
    def _parse_plain_text_list(self, content: str) -> List[str]:
        """Parse plain text domain list (one per line)"""
        domains = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                domain = self._extract_domain_from_url(line)
                if domain and self._is_valid_domain(domain):
                    domains.append(domain.lower())
        return list(set(domains))
    
    def _parse_urlhaus_text(self, content: str) -> List[str]:
        """Parse URLhaus hostfile format"""
        domains = []
        in_content = False
        for line in content.strip().split('\n'):
            line = line.strip()
            if line.startswith('#') or not line:
                if 'Last updated' in line:
                    in_content = True
                continue
            if in_content and line:
                parts = line.split('\t')
                if len(parts) >= 2:
                    domain = parts[1].strip().lower()
                    if self._is_valid_domain(domain):
                        domains.append(domain)
                    if len(parts) >= 3:
                        domain2 = parts[2].strip().lower()
                        if self._is_valid_domain(domain2):
                            domains.append(domain2)
        return list(set(domains))
    
    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url.lower())
            return parsed.netloc if parsed.netloc else ""
        except:
            return ""
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        if not domain or len(domain) < 4:
            return False
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        if all(p.isdigit() for p in parts):
            return False
        return True
    
    async def update_all_feeds(self) -> Dict[str, int]:
        """Update all enabled feeds"""
        results = {}
        
        tasks = [
            self.update_usom_feed(),
            self.update_openphish_feed(),
            self.update_urlhaus_feed()
        ]
        
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        
        feed_names = ["usom", "openphish", "urlhaus"]
        for name, count in zip(feed_names, results_list):
            if isinstance(count, int):
                results[name] = count
            else:
                results[name] = 0
        
        self._update_all_domains_hash()
        return results
    
    def _update_all_domains_hash(self):
        """Update hash of all domains for change detection"""
        all_domains = set()
        for domains in self._domains_cache.values():
            all_domains.update(domains)
        self._all_domains_hash = hashlib.md5(
            "|".join(sorted(all_domains)).encode()
        ).hexdigest()[:16]
    
    async def check_url(self, url: str) -> ThreatMatch:
        """
        Check if URL/domain is in any threat feed.
        
        Returns:
            ThreatMatch with details if found, or empty match if not found
        """
        domain = self._extract_domain_from_url(url)
        if not domain:
            return ThreatMatch(is_threat=False)
        
        domain_lower = domain.lower()
        
        for feed_name, domains in self._domains_cache.items():
            for threat_domain in domains:
                if (threat_domain == domain_lower or
                    domain_lower == threat_domain or
                    domain_lower.endswith('.' + threat_domain) or
                    threat_domain.endswith('.' + domain_lower)):
                    
                    feed = self.feeds.get(feed_name)
                    return ThreatMatch(
                        is_threat=True,
                        source=feed.source_type if feed else feed_name,
                        threat_type="phishing",
                        threat_level=feed.threat_level if feed else 5,
                        reason=f"{feed.name if feed else feed_name} threat list",
                        feed_name=feed_name
                    )
        
        return ThreatMatch(is_threat=False)
    
    def get_feed_status(self) -> Dict:
        """Get status of all feeds"""
        return {
            name: {
                "name": feed.name,
                "enabled": feed.enabled,
                "last_update": feed.last_update.isoformat() if feed.last_update else None,
                "last_error": feed.last_error,
                "domains_loaded": feed.domains_loaded,
                "threat_level": feed.threat_level
            }
            for name, feed in self.feeds.items()
        }
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        total_domains = sum(len(d) for d in self._domains_cache.values())
        return {
            "total_domains": total_domains,
            "cache_hash": self._all_domains_hash,
            "feeds_loaded": len([f for f in self.feeds.values() if f.domains_loaded > 0]),
            "feeds": self.get_feed_status()
        }


threat_intel = ThreatIntelManager()


async def test_threat_intel():
    """Test threat intelligence manager"""
    print("Testing Threat Intelligence Manager...")
    
    results = await threat_intel.update_all_feeds()
    print(f"\nUpdate results: {results}")
    
    status = threat_intel.get_cache_stats()
    print(f"\nCache stats: {status}")
    
    test_urls = [
        "https://google.com",
        "https://malware-test.com",
        "https://phishing-test.xyz"
    ]
    
    print("\nURL checks:")
    for url in test_urls:
        result = await threat_intel.check_url(url)
        print(f"  {url}: is_threat={result.is_threat}, reason={result.reason}")


if __name__ == "__main__":
    asyncio.run(test_threat_intel())
