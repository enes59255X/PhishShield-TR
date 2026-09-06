"""
Enhanced Rate Limiter - PhishShield TR V3

Advanced rate limiting with multiple strategies and tier support.
"""

import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict
import threading


class RateLimitTier(Enum):
    """Rate limit tiers"""
    FREE = "free"
    BASIC = "basic"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_minute: int
    requests_per_hour: int
    requests_per_day: int
    burst_size: int
    concurrent_requests: int


class RateLimitResult:
    """Result of rate limit check"""
    def __init__(
        self,
        allowed: bool,
        remaining: int,
        reset_at: float,
        tier: str,
        retry_after: Optional[int] = None
    ):
        self.allowed = allowed
        self.remaining = remaining
        self.reset_at = reset_at
        self.tier = tier
        self.retry_after = retry_after

    def to_dict(self) -> Dict:
        return {
            "allowed": self.allowed,
            "remaining": self.remaining,
            "reset_at": self.reset_at,
            "tier": self.tier,
            "retry_after": self.retry_after,
        }


class TokenBucket:
    """
    Token bucket algorithm for rate limiting.
    
    Features:
    - Burst handling
    - Smooth rate limiting
    - Thread-safe
    """

    def __init__(
        self,
        capacity: int,
        refill_rate: float,
        initial_tokens: Optional[float] = None
    ):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = initial_tokens if initial_tokens is not None else capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed
        """
        with self.lock:
            self._refill()
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False

    def _refill(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now

    def get_tokens(self) -> float:
        """Get current token count"""
        with self.lock:
            self._refill()
            return self.tokens


class SlidingWindowCounter:
    """
    Sliding window counter algorithm.
    
    More accurate than fixed window, less memory than sliding window log.
    """

    def __init__(self, window_size: int, max_count: int):
        self.window_size = window_size
        self.max_count = max_count
        self.windows: Dict[int, int] = defaultdict(int)
        self.lock = threading.Lock()

    def increment(self) -> Tuple[bool, int]:
        """
        Increment counter and check limit.
        
        Returns:
            Tuple of (allowed, current_count)
        """
        with self.lock:
            now = int(time.time())
            window_start = now - self.window_size
            
            self._cleanup(window_start)
            
            total = sum(self.windows.values())
            
            if total >= self.max_count:
                return False, total
            
            self.windows[now] += 1
            return True, total + 1

    def _cleanup(self, before: int):
        """Remove expired windows"""
        expired = [w for w in self.windows if w < before]
        for w in expired:
            del self.windows[w]

    def get_count(self) -> int:
        """Get current count"""
        with self.lock:
            now = int(time.time())
            window_start = now - self.window_size
            self._cleanup(window_start)
            return sum(self.windows.values())


class RateLimiter:
    """
    Advanced rate limiter with multiple strategies.
    
    Features:
    - Token bucket for API endpoints
    - Sliding window for user limits
    - Per-client tracking
    - Tier-based limits
    - Automatic cleanup
    """

    DEFAULT_CONFIGS = {
        RateLimitTier.FREE: RateLimitConfig(
            requests_per_minute=10,
            requests_per_hour=200,
            requests_per_day=500,
            burst_size=5,
            concurrent_requests=2
        ),
        RateLimitTier.BASIC: RateLimitConfig(
            requests_per_minute=60,
            requests_per_hour=2000,
            requests_per_day=10000,
            burst_size=20,
            concurrent_requests=10
        ),
        RateLimitTier.PREMIUM: RateLimitConfig(
            requests_per_minute=300,
            requests_per_hour=10000,
            requests_per_day=100000,
            burst_size=50,
            concurrent_requests=50
        ),
        RateLimitTier.ENTERPRISE: RateLimitConfig(
            requests_per_minute=1000,
            requests_per_hour=50000,
            requests_per_day=500000,
            burst_size=200,
            concurrent_requests=200
        ),
    }

    def __init__(self):
        self._minute_counters: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(60, 10000)
        )
        self._hour_counters: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(3600, 100000)
        )
        self._day_counters: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(86400, 1000000)
        )
        self._buckets: Dict[str, TokenBucket] = {}
        self._client_tiers: Dict[str, RateLimitTier] = {}
        self._lock = threading.Lock()

    def check_rate_limit(
        self,
        client_id: str,
        tier: RateLimitTier = RateLimitTier.FREE
    ) -> RateLimitResult:
        """
        Check if request is within rate limits.
        
        Args:
            client_id: Unique client identifier
            tier: Client's rate limit tier
            
        Returns:
            RateLimitResult with allowed status and metadata
        """
        config = self.DEFAULT_CONFIGS.get(tier, self.DEFAULT_CONFIGS[RateLimitTier.FREE])
        
        with self._lock:
            minute_ok, minute_count = self._minute_counters[client_id].increment()
            hour_ok, hour_count = self._hour_counters[client_id].increment()
            day_ok, day_count = self._day_counters[client_id].increment()
            
            if not minute_ok:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_at=time.time() + 60,
                    tier=tier.value,
                    retry_after=60
                )
            
            if not hour_ok:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_at=time.time() + 3600,
                    tier=tier.value,
                    retry_after=3600
                )
            
            if not day_ok:
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_at=time.time() + 86400,
                    tier=tier.value,
                    retry_after=86400
                )
            
            minute_remaining = max(0, config.requests_per_minute - minute_count)
            
            return RateLimitResult(
                allowed=True,
                remaining=minute_remaining,
                reset_at=time.time() + 60,
                tier=tier.value
            )

    def set_client_tier(self, client_id: str, tier: RateLimitTier):
        """Set a client's rate limit tier"""
        with self._lock:
            self._client_tiers[client_id] = tier

    def get_client_tier(self, client_id: str) -> RateLimitTier:
        """Get a client's rate limit tier"""
        return self._client_tiers.get(client_id, RateLimitTier.FREE)

    def reset_client(self, client_id: str):
        """Reset all limits for a client"""
        with self._lock:
            if client_id in self._minute_counters:
                del self._minute_counters[client_id]
            if client_id in self._hour_counters:
                del self._hour_counters[client_id]
            if client_id in self._day_counters:
                del self._day_counters[client_id]
            if client_id in self._buckets:
                del self._buckets[client_id]

    def get_stats(self, client_id: str) -> Dict:
        """Get rate limit stats for a client"""
        with self._lock:
            return {
                "minute_requests": self._minute_counters[client_id].get_count(),
                "hour_requests": self._hour_counters[client_id].get_count(),
                "day_requests": self._day_counters[client_id].get_count(),
                "tier": self.get_client_tier(client_id).value,
            }


def get_client_identifier(
    remote_ip: str,
    api_key: Optional[str] = None,
    user_id: Optional[str] = None
) -> str:
    """
    Generate a unique client identifier.
    
    Priority:
    1. user_id (authenticated user)
    2. api_key (API key)
    3. remote_ip (fallback)
    
    Args:
        remote_ip: Client's IP address
        api_key: API key if available
        user_id: User ID if authenticated
        
    Returns:
        Client identifier string
    """
    if user_id:
        return f"user:{user_id}"
    if api_key:
        import hashlib
        return f"key:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"
    return f"ip:{remote_ip}"
