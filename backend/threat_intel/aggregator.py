"""
PhishShield TR - Threat Feed Aggregator
Sprint 4: Manages updates from multiple threat intelligence sources
"""

import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import hashlib

from .sources import OpenPhishSource, URLhausSource, USOMSource
from .threat_db import threat_db
from .models import ThreatMatch


class ThreatAggregator:
    """
    Aggregates threat intelligence from multiple sources.
    
    Features:
    - Periodic feed updates
    - Database persistence
    - Source status tracking
    - Cache management
    """
    
    UPDATE_INTERVAL = timedelta(hours=24)  # Update feeds every 24 hours
    
    def __init__(self):
        self.sources = {
            "openphish": OpenPhishSource(),
            "urlhaus": URLhausSource(),
            "sgb": USOMSource(),  # Siber Guvenlik Baskanligi
        }
        # SGB source is enabled - it uses the working API
        self.sources["sgb"].enabled = True
        self._last_update: Optional[datetime] = None
        self._update_in_progress = False
        self._domains_cache: Dict[str, List[str]] = {}
        self._cache_hash: str = ""
    
    @property
    def domains_cache(self) -> Dict[str, List[str]]:
        """Get cached domains"""
        return self._domains_cache
    
    async def update_all_feeds(self, force: bool = False) -> Dict[str, int]:
        """
        Update all threat feeds.
        
        Args:
            force: Force update even if recently updated
        
        Returns:
            Dict mapping source name to number of domains loaded
        """
        if self._update_in_progress:
            return {name: len(domains) for name, domains in self._domains_cache.items()}
        
        self._update_in_progress = True
        
        try:
            # Check if update is needed
            if not force and self._should_use_cache():
                return {name: len(domains) for name, domains in self._domains_cache.items()}
            
            results = {}
            
            # Update each source concurrently
            tasks = []
            for name, source in self.sources.items():
                if source.enabled:
                    tasks.append(self._update_source(name, source))
            
            source_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, (name, source) in enumerate(self.sources.items()):
                if not source.enabled:
                    results[name] = 0
                    continue
                
                try:
                    result = source_results[i]
                    if isinstance(result, Exception):
                        results[name] = 0
                        continue
                    
                    results[name] = result
                except Exception as e:
                    results[name] = 0
            
            # Build consolidated cache
            self._domains_cache = {}
            for name, count in results.items():
                if count > 0:
                    # Get domains from database
                    self._domains_cache[name] = self._get_domains_from_db(name)
            
            # Update cache hash
            self._update_cache_hash()
            
            self._last_update = datetime.now()
            
            return results
            
        finally:
            self._update_in_progress = False
    
    async def _update_source(self, name: str, source) -> int:
        """Update a single source"""
        try:
            # Fetch domains from source
            domains = await source.fetch()
            
            if domains:
                # Store in database
                for domain in domains:
                    threat_db.add_threat(
                        domain=domain,
                        source=name,
                        category="phishing" if name != "urlhaus" else "malware",
                        severity="critical",
                        confidence=0.9 if name == "sgb" else 0.85
                    )
                
                # Update source status
                threat_db.update_source_status(
                    source=name,
                    status="OK" if source.last_error is None else "ERROR",
                    error=source.last_error,
                    domains_loaded=len(domains)
                )
            else:
                threat_db.update_source_status(
                    source=name,
                    status="ERROR",
                    error=source.last_error or "No domains fetched",
                    domains_loaded=0
                )
            
            return len(domains)
            
        except asyncio.CancelledError:
            print(f"Source {name} update cancelled")
            raise
        except Exception as e:
            threat_db.update_source_status(
                source=name,
                status="ERROR",
                error=str(e),
                domains_loaded=0
            )
            return 0
    
    def _should_use_cache(self) -> bool:
        """Check if we should use cached data"""
        if not self._last_update:
            return False
        if not self._domains_cache:
            return False
        return datetime.now() - self._last_update < self.UPDATE_INTERVAL
    
    def _get_domains_from_db(self, source: str) -> List[str]:
        """Get domains from database for a source"""
        try:
            return threat_db.get_domains_by_source(source)
        except Exception:
            # Fallback to in-memory cache if DB fails
            return self._domains_cache.get(source, [])
    
    def _update_cache_hash(self):
        """Update the cache hash for change detection"""
        all_domains = []
        for domains in self._domains_cache.values():
            all_domains.extend(domains)
        
        domain_str = ",".join(sorted(set(all_domains)))
        self._cache_hash = hashlib.md5(domain_str.encode()).hexdigest()
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        total = sum(len(domains) for domains in self._domains_cache.values())
        
        source_stats = {}
        for name, source in self.sources.items():
            source_stats[name] = {
                "name": source.name,
                "enabled": source.enabled,
                "last_update": source.last_update.isoformat() if source.last_update else None,
                "last_error": source.last_error,
                "domains_loaded": len(self._domains_cache.get(name, [])),
                "threat_level": source.threat_level
            }
        
        return {
            "total_domains": total,
            "cache_hash": self._cache_hash,
            "sources": source_stats,
            "last_update": self._last_update.isoformat() if self._last_update else None,
            "cache_age_hours": (
                (datetime.now() - self._last_update).total_seconds() / 3600
                if self._last_update else None
            )
        }


# Singleton instance
threat_aggregator = ThreatAggregator()
