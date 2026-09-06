"""
PhishShield TR - Threat Intelligence Cache
Sprint 4: In-memory cache for threat lookups
"""

import time
from typing import Dict, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta

from .models import ThreatMatch


@dataclass
class CacheEntry:
    """Cache entry for threat lookups"""
    domain: str
    match: Optional[ThreatMatch]
    timestamp: float
    ttl: int = 300  # 5 minutes default
    
    def is_expired(self) -> bool:
        return time.time() - self.timestamp > self.ttl


class ThreatCache:
    """
    In-memory cache for threat lookups.
    
    Features:
    - Domain-based lookup
    - TTL expiration
    - LRU-style eviction (simple)
    """
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 300):
        self._cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._hits = 0
        self._misses = 0
    
    def get(self, domain: str) -> Optional[ThreatMatch]:
        """
        Get threat match from cache.
        
        Args:
            domain: Domain to lookup
        
        Returns:
            ThreatMatch if found and not expired, None otherwise
        """
        domain_lower = domain.lower()
        
        if domain_lower in self._cache:
            entry = self._cache[domain_lower]
            if not entry.is_expired():
                self._hits += 1
                return entry.match
            else:
                # Expired, remove it
                del self._cache[domain_lower]
        
        self._misses += 1
        return None
    
    def set(self, domain: str, match: ThreatMatch, ttl: int = None):
        """
        Store threat match in cache.
        
        Args:
            domain: Domain key
            match: ThreatMatch to store
            ttl: Time to live in seconds (default: 5 minutes)
        """
        if len(self._cache) >= self.max_size:
            # Simple eviction: remove oldest 10%
            self._evict_oldest()
        
        self._cache[domain.lower()] = CacheEntry(
            domain=domain.lower(),
            match=match,
            timestamp=time.time(),
            ttl=ttl or self.default_ttl
        )
    
    def _evict_oldest(self):
        """Evict oldest 10% of entries"""
        if not self._cache:
            return
        
        # Sort by timestamp
        sorted_entries = sorted(
            self._cache.items(),
            key=lambda x: x[1].timestamp
        )
        
        # Remove oldest 10%
        remove_count = max(1, len(sorted_entries) // 10)
        for i in range(remove_count):
            del self._cache[sorted_entries[i][0]]
    
    def invalidate(self, domain: str):
        """Remove domain from cache"""
        domain_lower = domain.lower()
        if domain_lower in self._cache:
            del self._cache[domain_lower]
    
    def clear(self):
        """Clear all cache entries"""
        self._cache.clear()
        self._hits = 0
        self._misses = 0
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total = self._hits + self._misses
        hit_rate = self._hits / total if total > 0 else 0.0
        
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(hit_rate * 100, 2)
        }


# Singleton instance
threat_cache = ThreatCache()
