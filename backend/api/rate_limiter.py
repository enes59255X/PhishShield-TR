"""
PhishShield TR - API Rate Limiter
Sprint 13: Rate limiting for API protection

Purpose:
- Prevent API abuse
- Per-client rate limiting
- Different limits for different tiers
- Graceful degradation
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional
from enum import Enum


class RateLimitTier(Enum):
    """Rate limit tiers"""
    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


@dataclass
class RateLimitConfig:
    """Rate limit configuration per tier"""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_allowance: int = 10


@dataclass
class RateLimitStatus:
    """Current rate limit status for a client"""
    client_id: str
    tier: RateLimitTier

    # Request counts
    minute_count: int = 0
    hour_count: int = 0
    day_count: int = 0

    # Timestamps
    minute_reset: float = 0
    hour_reset: float = 0
    day_reset: float = 0

    # Status
    is_limited: bool = False
    retry_after: int = 0
    current_tier: str = "free"

    # Limits for this tier
    limits: RateLimitConfig = field(default_factory=RateLimitConfig)


class RateLimiter:
    """
    API Rate Limiter

    Implements token bucket algorithm with per-tier limits.
    """

    # Default limits per tier
    TIER_CONFIGS = {
        RateLimitTier.FREE: RateLimitConfig(
            requests_per_minute=30,
            requests_per_hour=500,
            requests_per_day=5000,
            burst_allowance=5
        ),
        RateLimitTier.BASIC: RateLimitConfig(
            requests_per_minute=60,
            requests_per_hour=1000,
            requests_per_day=10000,
            burst_allowance=10
        ),
        RateLimitTier.PREMIUM: RateLimitConfig(
            requests_per_minute=120,
            requests_per_hour=5000,
            requests_per_day=50000,
            burst_allowance=20
        ),
        RateLimitTier.ENTERPRISE: RateLimitConfig(
            requests_per_minute=300,
            requests_per_hour=20000,
            requests_per_day=200000,
            burst_allowance=50
        ),
    }

    def __init__(self):
        self._clients: Dict[str, RateLimitStatus] = defaultdict(self._create_default_status)
        self._minute_window = 60  # 1 minute
        self._hour_window = 3600  # 1 hour
        self._day_window = 86400  # 1 day

    def _create_default_status(self) -> RateLimitStatus:
        """Create default rate limit status for new client"""
        return RateLimitStatus(
            client_id="",
            tier=RateLimitTier.FREE,
            minute_reset=time.time() + self._minute_window,
            hour_reset=time.time() + self._hour_window,
            day_reset=time.time() + self._day_window,
            limits=self.TIER_CONFIGS[RateLimitTier.FREE]
        )

    def check_rate_limit(
        self,
        client_id: str,
        tier: RateLimitTier = None
    ) -> RateLimitStatus:
        """
        Check if client is within rate limits.

        Args:
            client_id: Unique client identifier (IP, API key, etc.)
            tier: Client tier (defaults to FREE)

        Returns:
            RateLimitStatus with current state
        """
        if tier is None:
            tier = RateLimitTier.FREE

        status = self._clients[client_id]
        status.client_id = client_id
        status.tier = tier
        status.limits = self.TIER_CONFIGS[tier]
        status.current_tier = tier.value

        current_time = time.time()

        # Reset counters if window expired
        self._reset_expired_windows(status, current_time)

        # Check if already limited
        if status.is_limited:
            if current_time >= status.retry_after:
                status.is_limited = False
                status.retry_after = 0
            else:
                return status

        # Increment counters
        status.minute_count += 1
        status.hour_count += 1
        status.day_count += 1

        # Check limits and apply penalty if exceeded
        self._check_and_apply_limit(status, current_time)

        return status

    def _reset_expired_windows(self, status: RateLimitStatus, current_time: float):
        """Reset counters for expired time windows"""
        # Minute window expired
        if current_time >= status.minute_reset:
            status.minute_count = 0
            status.minute_reset = current_time + self._minute_window

        # Hour window expired
        if current_time >= status.hour_reset:
            status.hour_count = 0
            status.hour_reset = current_time + self._hour_window

        # Day window expired
        if current_time >= status.day_reset:
            status.day_count = 0
            status.day_reset = current_time + self._day_window

    def _check_and_apply_limit(self, status: RateLimitStatus, current_time: float):
        """Check if limits are exceeded and apply penalty"""
        limits = status.limits

        # Check minute limit
        if status.minute_count > limits.requests_per_minute:
            status.is_limited = True
            status.retry_after = status.minute_reset
            return

        # Check hour limit
        if status.hour_count > limits.requests_per_hour:
            status.is_limited = True
            status.retry_after = status.hour_reset
            return

        # Check day limit
        if status.day_count > limits.requests_per_day:
            status.is_limited = True
            status.retry_after = status.day_reset
            return

    def get_remaining_requests(self, client_id: str) -> Dict[str, int]:
        """Get remaining requests for client"""
        status = self._clients.get(client_id)
        if not status:
            return {
                "minute": self.TIER_CONFIGS[RateLimitTier.FREE].requests_per_minute,
                "hour": self.TIER_CONFIGS[RateLimitTier.FREE].requests_per_hour,
                "day": self.TIER_CONFIGS[RateLimitTier.FREE].requests_per_day
            }

        return {
            "minute": max(0, status.limits.requests_per_minute - status.minute_count),
            "hour": max(0, status.limits.requests_per_hour - status.hour_count),
            "day": max(0, status.limits.requests_per_day - status.day_count)
        }

    def get_tier_info(self, tier: RateLimitTier) -> Dict:
        """Get information about a tier"""
        config = self.TIER_CONFIGS[tier]
        return {
            "tier": tier.value,
            "requests_per_minute": config.requests_per_minute,
            "requests_per_hour": config.requests_per_hour,
            "requests_per_day": config.requests_per_day,
            "burst_allowance": config.burst_allowance
        }

    def reset_client(self, client_id: str):
        """Reset rate limit for a client"""
        if client_id in self._clients:
            del self._clients[client_id]

    def get_stats(self) -> Dict:
        """Get overall rate limiter statistics"""
        total_clients = len(self._clients)
        limited_clients = sum(1 for s in self._clients.values() if s.is_limited)

        return {
            "total_clients": total_clients,
            "limited_clients": limited_clients,
            "tiers": {
                tier.value: sum(1 for s in self._clients.values() if s.tier == tier)
                for tier in RateLimitTier
            }
        }


# Singleton instance
rate_limiter = RateLimiter()
