"""
PhishShield TR - Dashboard Data Provider
Sprint 14: Real-time dashboard data for monitoring

Purpose:
- Provide dashboard-ready data structures
- Aggregate statistics for visualization
- Support multiple dashboard types (overview, detailed, alerts)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from .stats_collector import stats_collector


@dataclass
class GaugeMetric:
    """Single gauge metric for dashboard"""
    name: str
    value: float
    unit: str = ""
    trend: str = "stable"  # up, down, stable
    trend_value: float = 0.0
    status: str = "normal"  # normal, warning, critical


@dataclass
class TimeSeriesPoint:
    """Single point in time series data"""
    timestamp: float
    value: float


@dataclass
class TimeSeriesMetric:
    """Time series metric for charts"""
    name: str
    unit: str = ""
    points: List[TimeSeriesPoint] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)


@dataclass
class TopListItem:
    """Item in a top-N list"""
    rank: int
    label: str
    value: float
    percentage: float = 0.0


@dataclass
class DashboardOverview:
    """Overview dashboard data"""
    # Key metrics
    total_requests: GaugeMetric
    threats_detected: GaugeMetric
    danger_rate: GaugeMetric
    avg_analysis_time: GaugeMetric
    cache_hit_rate: GaugeMetric

    # Time series
    requests_over_time: TimeSeriesMetric
    threats_over_time: TimeSeriesMetric
    decisions_over_time: TimeSeriesMetric

    # Top lists
    top_threat_sources: List[TopListItem]
    top_detected_brands: List[TopListItem]
    top_tlds: List[TopListItem]
    top_suspicious_domains: List[TopListItem]

    # System status
    system_status: str  # healthy, degraded, critical
    uptime_hours: float
    last_updated: float


class DashboardProvider:
    """
    Dashboard Data Provider

    Provides formatted data for dashboard consumption.
    """

    def __init__(self):
        self.stats = stats_collector

    def get_overview(self) -> DashboardOverview:
        """
        Get overview dashboard data.

        Returns:
            DashboardOverview with all key metrics
        """
        summary = self.stats.get_summary()

        # Get window stats
        window_1h = self.stats.get_window_stats("1h")
        window_1m = self.stats.get_window_stats("1m")

        # Calculate metrics
        total_requests = summary["total_requests"]
        total_threats = summary["total_threats"]
        threat_rate = summary["threat_rate"]
        requests_per_min = summary["requests_per_minute"]

        # Get trends (comparing 1h vs previous 1h would require historical data)
        # For now, calculate from 1h stats
        h1_requests = window_1h["total_requests"]

        # Decision breakdown
        decisions = window_1h.get("decision_breakdown", {})
        danger_count = decisions.get("DANGER", 0)
        caution_count = decisions.get("CAUTION", 0)
        safe_count = decisions.get("SAFE", 0)

        # Determine status
        if total_requests == 0:
            system_status = "healthy"
        elif h1_requests > 1000:
            system_status = "degraded"
        else:
            system_status = "healthy"

        # Build gauge metrics
        total_requests_gauge = GaugeMetric(
            name="Toplam İstek",
            value=total_requests,
            trend="up",
            trend_value=h1_requests,
            status="normal"
        )

        threats_gauge = GaugeMetric(
            name="Tespit Edilen Tehdit",
            value=total_threats,
            trend="up" if total_threats > 0 else "stable",
            trend_value=window_1h["threats_detected"],
            status="warning" if total_threats > 10 else "normal"
        )

        danger_rate_gauge = GaugeMetric(
            name="Tehdit Oranı",
            value=float(threat_rate.rstrip("%")) if isinstance(threat_rate, str) else threat_rate * 100,
            unit="%",
            trend="stable",
            status="critical" if float(threat_rate.rstrip("%")) > 20 else "normal" if float(threat_rate.rstrip("%")) < 5 else "warning"
        )

        avg_time_gauge = GaugeMetric(
            name="Ort. Analiz Süresi",
            value=float(window_1h["avg_analysis_time_ms"].rstrip(" ms")) if isinstance(window_1h["avg_analysis_time_ms"], str) else window_1h["avg_analysis_time_ms"],
            unit="ms",
            trend="stable",
            status="warning" if float(window_1h["avg_analysis_time_ms"].rstrip(" ms")) > 500 else "normal"
        )

        cache_hit_rate_gauge = GaugeMetric(
            name="Cache Hit Oranı",
            value=float(window_1h["cache_hit_rate"].rstrip("%")) if isinstance(window_1h["cache_hit_rate"], str) else window_1h["cache_hit_rate"] * 100,
            unit="%",
            trend="stable",
            status="normal"
        )

        # Time series data
        requests_ts = TimeSeriesMetric(
            name="İstekler",
            unit="istek",
            points=[TimeSeriesPoint(timestamp=datetime.now().timestamp(), value=h1_requests)]
        )

        threats_ts = TimeSeriesMetric(
            name="Tehditler",
            unit="tehdit",
            points=[TimeSeriesPoint(timestamp=datetime.now().timestamp(), value=window_1h["threats_detected"])]
        )

        decisions_ts = TimeSeriesMetric(
            name="Kararlar",
            unit="karar",
            points=[
                TimeSeriesPoint(timestamp=datetime.now().timestamp(), value=danger_count),
                TimeSeriesPoint(timestamp=datetime.now().timestamp(), value=caution_count),
                TimeSeriesPoint(timestamp=datetime.now().timestamp(), value=safe_count),
            ],
            labels=["Tehlikeli", "Dikkat", "Güvenli"]
        )

        # Top lists
        top_threats = self.stats.get_top_threats(limit=5)
        top_threat_sources = []
        threat_sources = window_1h.get("threat_sources", {})
        total_threat_source = sum(threat_sources.values()) or 1
        for i, (source, count) in enumerate(sorted(threat_sources.items(), key=lambda x: x[1], reverse=True)[:5], 1):
            top_threat_sources.append(TopListItem(
                rank=i,
                label=source,
                value=count,
                percentage=count / total_threat_source * 100
            ))

        top_brands = []
        brands = window_1h.get("top_brands", {})
        for i, (brand, count) in enumerate(list(brands.items())[:5], 1):
            top_brands.append(TopListItem(
                rank=i,
                label=brand,
                value=count,
                percentage=count / max(1, sum(brands.values())) * 100
            ))

        top_tlds = []
        tlds = window_1h.get("top_tlds", {})
        for i, (tld, count) in enumerate(list(tlds.items())[:5], 1):
            top_tlds.append(TopListItem(
                rank=i,
                label=f".{tld}",
                value=count,
                percentage=count / max(1, sum(tlds.values())) * 100
            ))

        top_suspicious = []
        for i, threat in enumerate(top_threats[:5], 1):
            top_suspicious.append(TopListItem(
                rank=i,
                label=threat["domain"],
                value=threat["count"],
                percentage=threat["count"] / max(1, sum(t["count"] for t in top_threats)) * 100
            ))

        return DashboardOverview(
            total_requests=total_requests_gauge,
            threats_detected=threats_gauge,
            danger_rate=danger_rate_gauge,
            avg_analysis_time=avg_time_gauge,
            cache_hit_rate=cache_hit_rate_gauge,
            requests_over_time=requests_ts,
            threats_over_time=threats_ts,
            decisions_over_time=decisions_ts,
            top_threat_sources=top_threat_sources,
            top_detected_brands=top_brands,
            top_tlds=top_tlds,
            top_suspicious_domains=top_suspicious,
            system_status=system_status,
            uptime_hours=float(summary["uptime_hours"]),
            last_updated=datetime.now().timestamp()
        )

    def get_summary_cards(self) -> List[Dict[str, Any]]:
        """
        Get summary card data for dashboard grid.

        Returns:
            List of card dictionaries
        """
        summary = self.stats.get_summary()
        window_1h = self.stats.get_window_stats("1h")
        window_1m = self.stats.get_window_stats("1m")

        cards = [
            {
                "id": "total_requests",
                "title": "Toplam İstek",
                "value": f"{summary['total_requests']:,}",
                "subtitle": f"1 saat: {window_1h['total_requests']}",
                "icon": "requests",
                "status": "normal"
            },
            {
                "id": "threats_detected",
                "title": "Tespit Edilen Tehdit",
                "value": f"{summary['total_threats']:,}",
                "subtitle": f"1 saat: {window_1h['threats_detected']}",
                "icon": "threat",
                "status": "warning" if summary['total_threats'] > 10 else "normal"
            },
            {
                "id": "danger_rate",
                "title": "Tehdit Oranı",
                "value": summary['threat_rate'],
                "subtitle": "Son 1 saat",
                "icon": "danger",
                "status": "critical" if float(summary['threat_rate'].rstrip("%")) > 20 else "normal"
            },
            {
                "id": "avg_time",
                "title": "Ort. Analiz Süresi",
                "value": window_1h["avg_analysis_time_ms"],
                "subtitle": "Son 1 saat",
                "icon": "speed",
                "status": "warning" if float(window_1h["avg_analysis_time_ms"].rstrip(" ms")) > 500 else "normal"
            },
            {
                "id": "cache_hit",
                "title": "Cache Hit",
                "value": window_1h["cache_hit_rate"],
                "subtitle": "Son 1 saat",
                "icon": "cache",
                "status": "normal"
            },
            {
                "id": "uptime",
                "title": "Sistem Çalışma Süresi",
                "value": summary["uptime_hours"],
                "subtitle": "saattir aktif",
                "icon": "uptime",
                "status": "normal"
            },
        ]

        return cards

    def get_threat_map_data(self) -> Dict[str, Any]:
        """
        Get data for threat map visualization.

        Returns:
            Threat map data structure
        """
        top_threats = self.stats.get_top_threats(limit=20)

        return {
            "nodes": [
                {
                    "id": f"threat_{i}",
                    "label": t["domain"],
                    "size": min(t["count"] * 10, 50),
                    "threat_count": t["count"]
                }
                for i, t in enumerate(top_threats)
            ],
            "total_threats": len(top_threats),
            "total_blocked_requests": sum(t["count"] for t in top_threats)
        }


# Singleton instance
dashboard_provider = DashboardProvider()
