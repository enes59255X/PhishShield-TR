"""
PhishShield TR - Monitoring Package
Sprint 13-14: Real-time Statistics, Dashboard, and Alerting

Modules:
- stats_collector: Statistics collection and aggregation
- dashboard: Dashboard data provider
- alerting: Alert management system
- realtime: Real-time updates (WebSocket/SSE)
"""

from .stats_collector import (
    StatsCollector,
    stats_collector,
)

from .dashboard import (
    DashboardProvider,
    dashboard_provider,
    GaugeMetric,
    TimeSeriesMetric,
    TopListItem,
    DashboardOverview,
)

from .alerting import (
    AlertManager,
    alert_manager,
    Alert,
    AlertRule,
    AlertChannel,
    AlertSeverity,
    AlertCategory,
)

from .realtime import (
    RealtimeManager,
    realtime_manager,
    ClientConnection,
    BroadcastMessage,
    ConnectionType,
    EventTypes,
    Channels,
)

__all__ = [
    # Stats
    "StatsCollector",
    "stats_collector",
    # Dashboard
    "DashboardProvider",
    "dashboard_provider",
    "GaugeMetric",
    "TimeSeriesMetric",
    "TopListItem",
    "DashboardOverview",
    # Alerting
    "AlertManager",
    "alert_manager",
    "Alert",
    "AlertRule",
    "AlertChannel",
    "AlertSeverity",
    "AlertCategory",
    # Realtime
    "RealtimeManager",
    "realtime_manager",
    "ClientConnection",
    "BroadcastMessage",
    "ConnectionType",
    "EventTypes",
    "Channels",
]
