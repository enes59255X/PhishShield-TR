"""
PhishShield TR - Threat Intelligence Package
Sprint 4: Modular threat intelligence system

Architecture:
- sources/: Individual feed integrations (OpenPhish, URLhaus, USOM)
- models.py: Data models (ThreatMatch, ThreatStats)
- cache.py: In-memory cache for fast lookups
- threat_db.py: SQLite persistence layer
- aggregator.py: Feed update coordination
- reputation.py: Core threat lookup engine

Usage:
    from threat_intel import threat_reputation, threat_aggregator
    
    # Check a URL
    match = threat_reputation.check_url("https://evil.google.com/login")
    if match.is_threat:
        print(f"Threat found: {match.source}")
    
    # Update feeds
    await threat_aggregator.update_all_feeds()
"""

import asyncio
from typing import Optional

from .models import ThreatMatch, ThreatStats, ThreatSeverity, ThreatCategory, ThreatSource
from .threat_db import ThreatDatabase, threat_db
from .cache import ThreatCache, threat_cache
from .aggregator import ThreatAggregator, threat_aggregator
from .reputation import ThreatReputation, threat_reputation


# Simple async wrapper for sync code
def check_url(url: str) -> ThreatMatch:
    """Synchronous URL check"""
    return threat_reputation.check_url(url)


def check_domain(domain: str) -> ThreatMatch:
    """Synchronous domain check"""
    return threat_reputation.check_domain(domain)


async def update_feeds(force: bool = False) -> dict:
    """Update all threat feeds"""
    return await threat_aggregator.update_all_feeds(force=force)


def get_stats() -> dict:
    """Get threat intelligence statistics"""
    return {
        "reputation": threat_reputation.get_stats(),
        "aggregator": threat_aggregator.get_cache_stats(),
        "database": threat_db.get_stats().to_dict()
    }


__all__ = [
    # Models
    "ThreatMatch",
    "ThreatStats",
    "ThreatSeverity",
    "ThreatCategory",
    "ThreatSource",
    # Core classes
    "ThreatDatabase",
    "ThreatCache",
    "ThreatAggregator",
    "ThreatReputation",
    "ThreatIntel",
    # Singleton instances
    "threat_db",
    "threat_cache",
    "threat_aggregator",
    "threat_reputation",
    "threat_intel",
    # Convenience functions
    "check_url",
    "check_domain",
    "update_feeds",
    "get_stats",
]


# Legacy wrapper for backward compatibility with app.py
class ThreatIntel:
    """
    Legacy wrapper class providing unified threat intel interface.
    Compatible with app.py expectations.
    """
    
    async def check_url(self, url: str) -> ThreatMatch:
        """Check a URL against threat database"""
        return threat_reputation.check_url(url)
    
    async def check_domain(self, domain: str) -> ThreatMatch:
        """Check a domain against threat database"""
        return threat_reputation.check_domain(domain)
    
    async def update_all_feeds(self, force: bool = False) -> dict:
        """Update all threat intelligence feeds"""
        return await threat_aggregator.update_all_feeds(force=force)
    
    def get_cache_stats(self) -> dict:
        """Get cache statistics"""
        return threat_aggregator.get_cache_stats()
    
    def get_stats(self) -> dict:
        """Get overall statistics"""
        return {
            "reputation": threat_reputation.get_stats(),
            "aggregator": threat_aggregator.get_cache_stats(),
            "database": threat_db.get_stats().to_dict()
        }


# Singleton instance for backward compatibility
threat_intel = ThreatIntel()
