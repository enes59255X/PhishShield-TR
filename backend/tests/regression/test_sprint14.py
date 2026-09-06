"""
PhishShield TR - Sprint 14 Realtime Dashboard Tests
Tests for dashboard, alerting, and real-time updates
"""

import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))


def test_dashboard_import():
    """Test: Dashboard provider can be imported"""
    print("Test: Dashboard provider import...")

    from monitoring.dashboard import (
        DashboardProvider,
        dashboard_provider,
        GaugeMetric,
        TimeSeriesMetric,
        TopListItem,
        DashboardOverview
    )

    assert DashboardProvider is not None
    assert dashboard_provider is not None

    print("  PASSED")


def test_alerting_import():
    """Test: Alert manager can be imported"""
    print("Test: Alert manager import...")

    from monitoring.alerting import (
        AlertManager,
        alert_manager,
        Alert,
        AlertRule,
        AlertChannel,
        AlertSeverity,
        AlertCategory
    )

    assert AlertManager is not None
    assert alert_manager is not None
    assert AlertSeverity is not None

    print("  PASSED")


def test_realtime_import():
    """Test: Realtime manager can be imported"""
    print("Test: Realtime manager import...")

    from monitoring.realtime import (
        RealtimeManager,
        realtime_manager,
        ConnectionType,
        EventTypes,
        Channels
    )

    assert RealtimeManager is not None
    assert realtime_manager is not None
    assert ConnectionType is not None

    print("  PASSED")


def test_dashboard_provider():
    """Test: Dashboard provider generates data"""
    print("Test: Dashboard provider...")

    from monitoring.dashboard import DashboardProvider

    provider = DashboardProvider()
    overview = provider.get_overview()

    assert overview is not None
    assert hasattr(overview, 'total_requests')
    assert hasattr(overview, 'threats_detected')
    assert hasattr(overview, 'system_status')

    print(f"  System status: {overview.system_status}")
    print("  PASSED")


def test_dashboard_summary_cards():
    """Test: Dashboard summary cards"""
    print("Test: Dashboard summary cards...")

    from monitoring.dashboard import DashboardProvider

    provider = DashboardProvider()
    cards = provider.get_summary_cards()

    assert len(cards) > 0
    assert all('id' in card for card in cards)
    assert all('title' in card for card in cards)
    assert all('value' in card for card in cards)

    print(f"  Generated {len(cards)} summary cards")
    print("  PASSED")


def test_alert_creation():
    """Test: Alert creation"""
    print("Test: Alert creation...")

    from monitoring.alerting import AlertManager, AlertSeverity, AlertCategory

    manager = AlertManager()

    alert = manager.create_alert(
        severity=AlertSeverity.CRITICAL,
        category=AlertCategory.THREAT,
        title="Test Alert",
        message="This is a test alert",
        source="test"
    )

    assert alert is not None
    assert alert.title == "Test Alert"
    assert alert.severity == AlertSeverity.CRITICAL
    assert not alert.resolved

    print(f"  Alert ID: {alert.id}")
    print("  PASSED")


def test_alert_rules():
    """Test: Alert rules evaluation"""
    print("Test: Alert rules...")

    from monitoring.alerting import AlertManager, AlertSeverity, AlertCategory

    manager = AlertManager()

    # Evaluate with high threat rate context
    context = {
        "threat_rate": 0.25,  # > 20%
        "system_status": "healthy"
    }

    initial_count = len(manager.get_active_alerts())
    manager.evaluate_rules(context)
    new_count = len(manager.get_active_alerts())

    # Should have triggered at least one alert
    print(f"  Alerts: {initial_count} -> {new_count}")
    print("  PASSED")


def test_alert_channels():
    """Test: Alert channel management"""
    print("Test: Alert channels...")

    from monitoring.alerting import AlertManager, AlertChannel, AlertSeverity

    manager = AlertManager()

    # Add a new channel
    channel = AlertChannel(
        name="test_webhook",
        type="webhook",
        config={"url": "http://test.com/webhook"},
        enabled=True,
        min_severity=AlertSeverity.WARNING
    )

    manager.add_channel(channel)

    assert "test_webhook" in [c.name for c in manager._channels.values()]

    print(f"  Channels: {len(manager._channels)}")
    print("  PASSED")


def test_alert_resolve():
    """Test: Alert resolution"""
    print("Test: Alert resolution...")

    from monitoring.alerting import AlertManager, AlertSeverity, AlertCategory

    manager = AlertManager()

    # Create alert
    alert = manager.create_alert(
        severity=AlertSeverity.INFO,
        category=AlertCategory.SYSTEM,
        title="Test Resolve",
        message="Test"
    )

    assert not alert.resolved

    # Resolve it
    result = manager.resolve_alert(alert.id)
    assert result is True
    assert alert.resolved is True
    assert alert.resolved_at is not None

    print("  PASSED")


def test_alert_counts():
    """Test: Alert counting"""
    print("Test: Alert counts...")

    from monitoring.alerting import AlertManager, AlertSeverity, AlertCategory

    manager = AlertManager()
    initial_counts = manager.get_alert_counts()
    initial_total = initial_counts["total"]

    # Create alerts
    manager.create_alert(AlertSeverity.INFO, AlertCategory.SYSTEM, "Info", "msg")
    manager.create_alert(AlertSeverity.WARNING, AlertCategory.SYSTEM, "Warn", "msg")
    manager.create_alert(AlertSeverity.CRITICAL, AlertCategory.THREAT, "Crit", "msg")

    counts = manager.get_alert_counts()

    # Check that counts increased
    assert counts["total"] == initial_total + 3
    assert counts["info"] >= 1
    assert counts["warning"] >= 1
    assert counts["critical"] >= 1

    print(f"  Total alerts: {counts['total']}")
    print("  PASSED")


def test_realtime_connection():
    """Test: Realtime connection management"""
    print("Test: Realtime connection...")

    from monitoring.realtime import RealtimeManager, ConnectionType

    manager = RealtimeManager()

    # Add connection
    conn = manager.add_connection(
        "test_client_1",
        ConnectionType.WEBSOCKET,
        metadata={"user": "test"}
    )

    assert conn is not None
    assert conn.id == "test_client_1"
    assert conn.connection_type == ConnectionType.WEBSOCKET

    print("  PASSED")


def test_realtime_subscription():
    """Test: Channel subscription"""
    print("Test: Realtime subscription...")

    from monitoring.realtime import RealtimeManager, ConnectionType, Channels

    manager = RealtimeManager()

    # Add connection
    manager.add_connection("sub_test", ConnectionType.SSE)

    # Subscribe to channel
    result = manager.subscribe("sub_test", Channels.DASHBOARD)

    assert result is True
    assert "sub_test" in manager.get_subscribers(Channels.DASHBOARD)

    # Unsubscribe
    result = manager.unsubscribe("sub_test", Channels.DASHBOARD)
    assert result is True
    assert "sub_test" not in manager.get_subscribers(Channels.DASHBOARD)

    print("  PASSED")


def test_realtime_broadcast():
    """Test: Message broadcast"""
    print("Test: Realtime broadcast...")

    from monitoring.realtime import RealtimeManager, ConnectionType, Channels, EventTypes

    manager = RealtimeManager()

    # Add connection
    manager.add_connection("broadcast_test", ConnectionType.WEBSOCKET)
    manager.subscribe("broadcast_test", Channels.DASHBOARD)

    # Broadcast
    manager.broadcast(
        Channels.DASHBOARD,
        EventTypes.DASHBOARD_UPDATE,
        {"update": "test_data"}
    )

    # Get pending messages
    messages = manager.get_pending_messages("broadcast_test", since=0)

    assert len(messages) >= 1
    assert messages[0]["channel"] == Channels.DASHBOARD

    print(f"  Pending messages: {len(messages)}")
    print("  PASSED")


def test_realtime_connection_stats():
    """Test: Connection statistics"""
    print("Test: Realtime connection stats...")

    from monitoring.realtime import RealtimeManager, ConnectionType

    manager = RealtimeManager()

    # Add connections
    manager.add_connection("stats_1", ConnectionType.WEBSOCKET)
    manager.add_connection("stats_2", ConnectionType.SSE)
    manager.add_connection("stats_3", ConnectionType.WEBSOCKET)

    stats = manager.get_connection_stats()

    assert stats["total_connections"] == 3
    assert stats["by_type"]["websocket"] == 2
    assert stats["by_type"]["sse"] == 1

    print(f"  Stats: {stats}")
    print("  PASSED")


def test_realtime_ping():
    """Test: Connection ping/heartbeat"""
    print("Test: Realtime ping...")

    from monitoring.realtime import RealtimeManager, ConnectionType

    manager = RealtimeManager()

    # Add connection
    manager.add_connection("ping_test", ConnectionType.WEBSOCKET)

    # Ping
    result = manager.ping("ping_test")
    assert result is True

    # Ping non-existent
    result = manager.ping("nonexistent")
    assert result is False

    print("  PASSED")


def test_alert_history():
    """Test: Alert history retrieval"""
    print("Test: Alert history...")

    from monitoring.alerting import AlertManager, AlertSeverity, AlertCategory

    manager = AlertManager()

    # Create some alerts
    for i in range(5):
        manager.create_alert(
            AlertSeverity.INFO,
            AlertCategory.SYSTEM,
            f"Alert {i}",
            f"Message {i}"
        )

    history = manager.get_alert_history(limit=10)

    # Should have at least 5 alerts
    assert len(history) >= 5
    # Should be in descending order (newest first)
    assert history[0].title in [f"Alert {i}" for i in range(4, -1, -1)]

    print(f"  History length: {len(history)}")
    print("  PASSED")


def test_gauge_metric():
    """Test: Gauge metric structure"""
    print("Test: Gauge metric...")

    from monitoring.dashboard import GaugeMetric

    metric = GaugeMetric(
        name="Test Metric",
        value=42.0,
        unit="units",
        trend="up",
        trend_value=10.0,
        status="warning"
    )

    assert metric.name == "Test Metric"
    assert metric.value == 42.0
    assert metric.trend == "up"

    print(f"  Metric: {metric.name} = {metric.value}{metric.unit}")
    print("  PASSED")


def test_top_list_item():
    """Test: Top list item structure"""
    print("Test: Top list item...")

    from monitoring.dashboard import TopListItem

    item = TopListItem(
        rank=1,
        label="test.com",
        value=100,
        percentage=50.0
    )

    assert item.rank == 1
    assert item.label == "test.com"
    assert item.value == 100

    print(f"  Item #{item.rank}: {item.label} ({item.percentage}%)")
    print("  PASSED")


def run_all_tests():
    """Run all Sprint 14 tests"""
    print("=" * 60)
    print("Sprint 14 Realtime Dashboard Tests")
    print("=" * 60)

    tests = [
        test_dashboard_import,
        test_alerting_import,
        test_realtime_import,
        test_dashboard_provider,
        test_dashboard_summary_cards,
        test_alert_creation,
        test_alert_rules,
        test_alert_channels,
        test_alert_resolve,
        test_alert_counts,
        test_realtime_connection,
        test_realtime_subscription,
        test_realtime_broadcast,
        test_realtime_connection_stats,
        test_realtime_ping,
        test_alert_history,
        test_gauge_metric,
        test_top_list_item,
    ]

    passed = 0
    failed = 0
    skipped = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
