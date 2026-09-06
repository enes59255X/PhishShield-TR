"""
PhishShield TR - Statistics Collector
Sprint 13: Real-time monitoring and statistics

Purpose:
- Collect and aggregate analysis statistics
- Track threat patterns over time
- Provide dashboard-ready metrics
- Time-series data for trends
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any


@dataclass
class AnalysisRecord:
    """Single analysis record"""
    timestamp: float
    url: str
    domain: str
    decision: str
    score: int
    threat_matched: bool
    brand_impostor: bool
    form_external: bool
    analysis_time_ms: float
    cache_hit: bool


@dataclass
class TimeWindowStats:
    """Statistics for a time window"""
    total_requests: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    threats_detected: int = 0
    safe_sites: int = 0
    danger_sites: int = 0
    caution_sites: int = 0
    avg_score: float = 0.0
    avg_analysis_time_ms: float = 0.0

    # Decision breakdown
    decisions: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Threat sources
    threat_sources: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Top detected brands
    detected_brands: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Top TLDs
    tld_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


class StatsCollector:
    """
    Statistics Collector for PhishShield TR

    Collects:
    - Request counts and rates
    - Threat detection statistics
    - Performance metrics
    - Pattern analysis
    """

    def __init__(self, retention_hours: int = 24):
        """
        Initialize Stats Collector.

        Args:
            retention_hours: How long to retain detailed records
        """
        self._retention_hours = retention_hours
        self._records: List[AnalysisRecord] = []

        # Rolling windows (in seconds)
        self._windows = {
            "1m": 60,
            "5m": 300,
            "15m": 900,
            "1h": 3600,
            "24h": 86400,
        }

        # Aggregated stats per window
        self._window_stats: Dict[str, TimeWindowStats] = {
            name: TimeWindowStats() for name in self._windows
        }

        # Counters
        self._total_requests = 0
        self._total_threats = 0
        self._total_safe = 0
        self._start_time = time.time()

        # Domain blacklist tracking
        self._domain_request_counts: Dict[str, int] = defaultdict(int)
        self._domain_threat_counts: Dict[str, int] = defaultdict(int)

    def record_analysis(
        self,
        url: str,
        domain: str,
        decision: str,
        score: int,
        threat_matched: bool,
        brand_impostor: bool = False,
        form_external: bool = False,
        analysis_time_ms: float = 0.0,
        cache_hit: bool = False,
        threat_source: str = None,
        brand_name: str = None
    ):
        """
        Record an analysis result.

        Args:
            url: Analyzed URL
            domain: Extracted domain
            decision: SAFE, CAUTION, or DANGER
            score: Final risk score
            threat_matched: Whether threat was matched
            brand_impostor: Whether brand impersonation detected
            form_external: Whether form sends data externally
            analysis_time_ms: Time taken for analysis
            cache_hit: Whether result was from cache
            threat_source: Source of threat match
            brand_name: Detected brand name
        """
        # Create record
        record = AnalysisRecord(
            timestamp=time.time(),
            url=url,
            domain=domain,
            decision=decision,
            score=score,
            threat_matched=threat_matched,
            brand_impostor=brand_impostor,
            form_external=form_external,
            analysis_time_ms=analysis_time_ms,
            cache_hit=cache_hit
        )

        # Store record
        self._records.append(record)
        self._total_requests += 1

        # Update counters
        if decision == "DANGER":
            self._total_threats += 1
        elif decision == "SAFE":
            self._total_safe += 1

        # Track domain
        self._domain_request_counts[domain] += 1
        if threat_matched or decision == "DANGER":
            self._domain_threat_counts[domain] += 1

        # Update window stats
        self._update_window_stats(record, threat_source, brand_name)

        # Cleanup old records
        self._cleanup_old_records()

    def _update_window_stats(
        self,
        record: AnalysisRecord,
        threat_source: str = None,
        brand_name: str = None
    ):
        """Update statistics for all time windows"""
        current_time = time.time()

        for window_name, window_seconds in self._windows.items():
            window = self._window_stats[window_name]
            window.total_requests += 1

            # Cache stats
            if record.cache_hit:
                window.cache_hits += 1
            else:
                window.cache_misses += 1

            # Decision counts
            window.decisions[record.decision] += 1

            # Score tracking
            window.avg_score = (
                (window.avg_score * (window.total_requests - 1) + record.score)
                / window.total_requests
            )

            # Analysis time
            window.avg_analysis_time_ms = (
                (window.avg_analysis_time_ms * (window.total_requests - 1) + record.analysis_time_ms)
                / window.total_requests
            )

            # Threat stats
            if record.threat_matched:
                window.threats_detected += 1

            # Decision breakdown
            if record.decision == "SAFE":
                window.safe_sites += 1
            elif record.decision == "DANGER":
                window.danger_sites += 1
            elif record.decision == "CAUTION":
                window.caution_sites += 1

            # Threat source
            if threat_source:
                window.threat_sources[threat_source] += 1

            # Brand tracking
            if brand_name:
                window.detected_brands[brand_name] += 1

            # TLD tracking
            if record.domain:
                tld = record.domain.split('.')[-1] if '.' in record.domain else record.domain
                window.tld_counts[tld] += 1

    def _cleanup_old_records(self):
        """Remove records older than retention period"""
        cutoff_time = time.time() - (self._retention_hours * 3600)
        self._records = [r for r in self._records if r.timestamp >= cutoff_time]

    def get_summary(self) -> Dict[str, Any]:
        """Get overall summary statistics"""
        uptime_seconds = time.time() - self._start_time

        return {
            "uptime_seconds": int(uptime_seconds),
            "uptime_hours": f"{uptime_seconds / 3600:.1f}",
            "total_requests": self._total_requests,
            "total_threats": self._total_threats,
            "total_safe": self._total_safe,
            "threat_rate": f"{self._total_threats / max(1, self._total_requests):.2%}",
            "requests_per_minute": self._total_requests / max(1, uptime_seconds / 60),
        }

    def get_window_stats(self, window: str = "1h") -> Dict[str, Any]:
        """Get statistics for a specific time window"""
        if window not in self._window_stats:
            window = "1h"

        stats = self._window_stats[window]
        total = stats.total_requests or 1

        return {
            "window": window,
            "total_requests": stats.total_requests,
            "cache_hit_rate": f"{stats.cache_hits / total:.2%}",
            "threats_detected": stats.threats_detected,
            "decision_breakdown": dict(stats.decisions),
            "threat_sources": dict(stats.threat_sources),
            "top_brands": dict(sorted(
                stats.detected_brands.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "top_tlds": dict(sorted(
                stats.tld_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "avg_score": f"{stats.avg_score:.1f}",
            "avg_analysis_time_ms": f"{stats.avg_analysis_time_ms:.1f}",
            "danger_rate": f"{stats.danger_sites / total:.2%}",
        }

    def get_all_windows(self) -> Dict[str, Dict]:
        """Get statistics for all time windows"""
        return {window: self.get_window_stats(window) for window in self._windows}

    def get_top_threats(self, limit: int = 10) -> List[Dict]:
        """Get most frequently detected threats"""
        threat_domains = sorted(
            self._domain_threat_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]

        return [
            {
                "domain": domain,
                "count": count,
                "request_count": self._domain_request_counts[domain]
            }
            for domain, count in threat_domains
        ]

    def get_trends(self, hours: int = 24) -> Dict[str, Any]:
        """Get trend data for the specified hours"""
        cutoff_time = time.time() - (hours * 3600)
        recent_records = [r for r in self._records if r.timestamp >= cutoff_time]

        if not recent_records:
            return {"message": "No data for trend analysis"}

        # Group by hour
        hourly_data = defaultdict(lambda: {"total": 0, "threats": 0, "danger": 0})

        for record in recent_records:
            hour_key = datetime.fromtimestamp(record.timestamp).strftime("%Y-%m-%d %H:00")
            hourly_data[hour_key]["total"] += 1
            if record.threat_matched:
                hourly_data[hour_key]["threats"] += 1
            if record.decision == "DANGER":
                hourly_data[hour_key]["danger"] += 1

        return {
            "hours": hours,
            "hourly": dict(sorted(hourly_data.items())),
            "peak_hour": max(hourly_data.items(), key=lambda x: x[1]["total"])[0] if hourly_data else None,
        }

    def reset(self):
        """Reset all statistics"""
        self._records.clear()
        self._total_requests = 0
        self._total_threats = 0
        self._total_safe = 0
        self._start_time = time.time()
        self._domain_request_counts.clear()
        self._domain_threat_counts.clear()
        for window in self._window_stats.values():
            *window.__dict__.values(),

        # Reset window stats
        self._window_stats = {
            name: TimeWindowStats() for name in self._windows
        }


# Singleton instance
stats_collector = StatsCollector()
