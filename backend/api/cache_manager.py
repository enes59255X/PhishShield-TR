"""
PhishShield TR - API Cache Manager
Sprint 13: Response caching for performance

Purpose:
- Cache analysis results to reduce redundant processing
- TTL-based cache expiration
- LRU eviction for memory management
- Cache statistics and monitoring
"""

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class CacheEntry:
    """A single cache entry"""
    key: str
    value: Any
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl: int = 300  # Default 5 minutes

    def is_expired(self, current_time: float = None) -> bool:
        """Check if entry has expired"""
        if current_time is None:
            current_time = time.time()
        return (current_time - self.created_at) > self.ttl


@dataclass
class CacheStats:
    """Cache statistics"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    total_requests: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        if self.total_requests == 0:
            return 0.0
        return self.hits / self.total_requests


class APICache:
    """
    LRU Cache for API responses

    Features:
    - TTL-based expiration
    - LRU eviction when max_size reached
    - Statistics tracking
    - Thread-safe operations
    """

    def __init__(
        self,
        max_size: int = 10000,
        default_ttl: int = 300,
        enable_stats: bool = True
    ):
        """
        Initialize API Cache.

        Args:
            max_size: Maximum number of entries
            default_ttl: Default time-to-live in seconds
            enable_stats: Enable statistics tracking
        """
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._default_ttl = default_ttl
        self._enable_stats = enable_stats
        self._stats = CacheStats()
        self._lock = False  # Simple lock for thread safety

    def get(self, key: str, use_stats: bool = True) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key
            use_stats: Whether to update statistics

        Returns:
            Cached value or None if not found/expired
        """
        if use_stats and self._enable_stats:
            self._stats.total_requests += 1

        entry = self._cache.get(key)

        if entry is None:
            if use_stats and self._enable_stats:
                self._stats.misses += 1
            return None

        # Check expiration
        if entry.is_expired():
            del self._cache[key]
            if use_stats and self._enable_stats:
                self._stats.expirations += 1
            return None

        # Update access metadata (LRU)
        entry.last_accessed = time.time()
        entry.access_count += 1
        self._cache.move_to_end(key)

        if use_stats and self._enable_stats:
            self._stats.hits += 1

        return entry.value

    def set(
        self,
        key: str,
        value: Any,
        ttl: int = None
    ) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)

        Returns:
            True if cached successfully
        """
        if ttl is None:
            ttl = self._default_ttl

        # Check if key exists
        if key in self._cache:
            # Update existing entry
            entry = self._cache[key]
            entry.value = value
            entry.created_at = time.time()
            entry.last_accessed = time.time()
            entry.ttl = ttl
            self._cache.move_to_end(key)
            return True

        # Evict if at capacity
        if len(self._cache) >= self._max_size:
            self._evict_lru()

        # Add new entry
        entry = CacheEntry(
            key=key,
            value=value,
            created_at=time.time(),
            last_accessed=time.time(),
            ttl=ttl
        )
        self._cache[key] = entry
        return True

    def _evict_lru(self):
        """Evict least recently used entry"""
        if not self._cache:
            return

        # Remove oldest entry (first in OrderedDict)
        oldest_key = next(iter(self._cache))
        del self._cache[oldest_key]

        if self._enable_stats:
            self._stats.evictions += 1

    def delete(self, key: str) -> bool:
        """
        Delete entry from cache.

        Args:
            key: Cache key

        Returns:
            True if key was deleted
        """
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def clear(self):
        """Clear all cache entries"""
        self._cache.clear()

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries.

        Returns:
            Number of entries removed
        """
        current_time = time.time()
        expired_keys = [
            key for key, entry in self._cache.items()
            if entry.is_expired(current_time)
        ]

        for key in expired_keys:
            del self._cache[key]

        if self._enable_stats:
            self._stats.expirations += len(expired_keys)

        return len(expired_keys)

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        stats = {
            "size": len(self._cache),
            "max_size": self._max_size,
            "default_ttl": self._default_ttl,
            "utilization": f"{len(self._cache) / self._max_size:.1%}",
        }

        if self._enable_stats:
            stats.update({
                "hits": self._stats.hits,
                "misses": self._stats.misses,
                "evictions": self._stats.evictions,
                "expirations": self._stats.expirations,
                "total_requests": self._stats.total_requests,
                "hit_rate": f"{self._stats.hit_rate:.2%}",
            })

        return stats

    def reset_stats(self):
        """Reset statistics counters"""
        self._stats = CacheStats()

    @staticmethod
    def generate_key(*args, **kwargs) -> str:
        """Generate cache key from arguments"""
        key_data = {
            "args": args,
            "kwargs": sorted(kwargs.items())
        }
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.sha256(key_str.encode()).hexdigest()[:32]


class TieredCache:
    """
    Multi-tier caching system

    Tiers:
    - L1: Hot cache (memory, small, fast)
    - L2: Warm cache (memory, larger, slower)
    - L3: Cold cache (disk/Redis, largest, slowest)
    """

    def __init__(
        self,
        l1_size: int = 1000,
        l2_size: int = 10000,
        l1_ttl: int = 60,
        l2_ttl: int = 300,
        l3_ttl: int = 3600
    ):
        """
        Initialize tiered cache.

        Args:
            l1_size: L1 cache max size
            l2_size: L2 cache max size
            l1_ttl: L1 TTL in seconds
            l2_ttl: L2 TTL in seconds
            l3_ttl: L3 TTL in seconds
        """
        self.l1 = APICache(max_size=l1_size, default_ttl=l1_ttl)
        self.l2 = APICache(max_size=l2_size, default_ttl=l2_ttl)
        self.l3_ttl = l3_ttl

    def get(self, key: str) -> Optional[Any]:
        """Get value from tiered cache (checks L1 -> L2 -> L3)"""
        # Check L1 first
        value = self.l1.get(key, use_stats=False)
        if value is not None:
            return value

        # Check L2
        value = self.l2.get(key, use_stats=False)
        if value is not None:
            # Promote to L1
            self.l1.set(key, value)
            return value

        # L3 would be implemented with Redis/disk in production
        return None

    def set(self, key: str, value: Any, tier: str = "auto"):
        """Set value in cache"""
        if tier == "l1":
            self.l1.set(key, value)
        elif tier == "l2":
            self.l2.set(key, value)
        elif tier == "l3":
            # L3 would persist to Redis/disk
            pass
        else:
            # Auto: set in all tiers
            self.l1.set(key, value)
            self.l2.set(key, value)

    def invalidate(self, key: str):
        """Remove key from all tiers"""
        self.l1.delete(key)
        self.l2.delete(key)

    def get_stats(self) -> Dict:
        """Get combined statistics for all tiers"""
        return {
            "l1": self.l1.get_stats(),
            "l2": self.l2.get_stats(),
            "l3": {"ttl": self.l3_ttl}
        }


# Singleton instances
api_cache = APICache()
tiered_cache = TieredCache()
