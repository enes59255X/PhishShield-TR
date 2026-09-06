"""
PhishShield TR - Cache Manager V2
Phase 3: Cache with version control

This module provides versioned caching for analysis results.
Cache keys include:
- normalized URL
- analysis version
- HTML hash (for page-specific cache)
"""

import json
import hashlib
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Analysis version - increment this when algorithm changes
ANALYSIS_VERSION = "3.0.0"

# Cache configuration
CACHE_TTL_SECONDS = 300  # 5 minutes
CACHE_DIR = "cache"

@dataclass
class CacheEntry:
    """Cache entry structure"""
    url: str
    normalized_url: str
    domain: str
    analysis_version: str
    result: Dict
    created_at: float
    expires_at: float
    html_hash: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> "CacheEntry":
        return cls(**data)
    
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class CacheManager:
    """
    Versioned cache manager for PhishShield TR
    
    Features:
    - Version-aware cache keys
    - Domain and URL caching
    - TTL-based expiration
    - HTML hash for page-specific caching
    """
    
    def __init__(self, ttl_seconds: int = CACHE_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._memory_cache: Dict[str, CacheEntry] = {}
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent cache keys"""
        parsed = urlparse(url.lower().strip())
        # Remove fragment, trailing slash, default ports
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        normalized = normalized.rstrip('/')
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url.lower())
        return parsed.netloc
    
    def _generate_cache_key(self, url: str, version: str = ANALYSIS_VERSION) -> str:
        """Generate versioned cache key"""
        normalized = self._normalize_url(url)
        key_string = f"{version}:{normalized}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _generate_domain_key(self, domain: str, version: str = ANALYSIS_VERSION) -> str:
        """Generate versioned domain cache key"""
        key_string = f"{version}:domain:{domain}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, url: str, use_domain_cache: bool = True) -> Optional[Dict]:
        """
        Get cached result for URL
        
        Args:
            url: URL to look up
            use_domain_cache: If True, check domain-level cache first
        
        Returns:
            Cached result or None if not found/expired
        """
        now = time.time()
        
        # Check URL-level cache
        url_key = self._generate_cache_key(url)
        if url_key in self._memory_cache:
            entry = self._memory_cache[url_key]
            if not entry.is_expired():
                print(f"📋 CACHE HIT (URL): {url}")
                return entry.result
            else:
                del self._memory_cache[url_key]
        
        # Check domain-level cache if enabled
        if use_domain_cache:
            domain = self._extract_domain(url)
            domain_key = self._generate_domain_key(domain)
            
            if domain_key in self._memory_cache:
                entry = self._memory_cache[domain_key]
                if not entry.is_expired():
                    print(f"📋 CACHE HIT (DOMAIN): {domain}")
                    return entry.result
                else:
                    del self._memory_cache[domain_key]
        
        return None
    
    def set(self, url: str, result: Dict, html_hash: Optional[str] = None) -> None:
        """
        Cache a result for URL
        
        Args:
            url: URL that was analyzed
            result: Analysis result to cache
            html_hash: Optional HTML content hash for page-specific caching
        """
        now = time.time()
        normalized = self._normalize_url(url)
        domain = self._extract_domain(url)
        
        # URL-level cache entry
        url_key = self._generate_cache_key(url)
        url_entry = CacheEntry(
            url=url,
            normalized_url=normalized,
            domain=domain,
            analysis_version=ANALYSIS_VERSION,
            result=result,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            html_hash=html_hash
        )
        self._memory_cache[url_key] = url_entry
        
        # Domain-level cache entry (for same-domain URLs)
        domain_key = self._generate_domain_key(domain)
        domain_entry = CacheEntry(
            url=url,
            normalized_url=normalized,
            domain=domain,
            analysis_version=ANALYSIS_VERSION,
            result=result,
            created_at=now,
            expires_at=now + self.ttl_seconds,
            html_hash=html_hash
        )
        self._memory_cache[domain_key] = domain_entry
        
        print(f"💾 CACHE SET: {url} (version={ANALYSIS_VERSION})")
    
    def invalidate(self, url: str) -> None:
        """Invalidate cache for URL"""
        url_key = self._generate_cache_key(url)
        domain = self._extract_domain(url)
        domain_key = self._generate_domain_key(domain)
        
        if url_key in self._memory_cache:
            del self._memory_cache[url_key]
        if domain_key in self._memory_cache:
            del self._memory_cache[domain_key]
        
        print(f"🗑️ CACHE INVALIDATED: {url}")
    
    def clear(self) -> None:
        """Clear all cache"""
        count = len(self._memory_cache)
        self._memory_cache.clear()
        print(f"🗑️ CACHE CLEARED: {count} entries removed")
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        now = time.time()
        expired = sum(1 for e in self._memory_cache.values() if e.is_expired())
        valid = len(self._memory_cache) - expired
        
        return {
            "total_entries": len(self._memory_cache),
            "valid_entries": valid,
            "expired_entries": expired,
            "analysis_version": ANALYSIS_VERSION,
            "ttl_seconds": self.ttl_seconds
        }
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count of removed entries"""
        now = time.time()
        expired_keys = [
            k for k, v in self._memory_cache.items() 
            if now > v.expires_at
        ]
        for key in expired_keys:
            del self._memory_cache[key]
        
        if expired_keys:
            print(f"🧹 CLEANUP: {len(expired_keys)} expired entries removed")
        
        return len(expired_keys)


# Global cache manager instance
cache_manager = CacheManager()


def get_cache() -> CacheManager:
    """Get the global cache manager instance"""
    return cache_manager


def invalidate_url_cache(url: str) -> None:
    """Convenience function to invalidate URL cache"""
    cache_manager.invalidate(url)


def clear_all_cache() -> None:
    """Convenience function to clear all cache"""
    cache_manager.clear()
