"""
PhishShield TR - Alerting System
Sprint 14: Real-time alerting for threats and system events

Purpose:
- Generate alerts for critical events
- Support multiple alert channels
- Alert grouping and deduplication
- Alert history and management
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Any
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertCategory(Enum):
    """Alert categories"""
    THREAT = "threat"
    SYSTEM = "system"
    PERFORMANCE = "performance"
    SECURITY = "security"
    MAINTENANCE = "maintenance"


@dataclass
class Alert:
    """Single alert instance"""
    id: str
    severity: AlertSeverity
    category: AlertCategory
    title: str
    message: str
    timestamp: float
    resolved: bool = False
    resolved_at: float = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    source: str = "system"


@dataclass
class AlertRule:
    """Rule for triggering alerts"""
    name: str
    condition: Callable[[Dict], bool]
    severity: AlertSeverity
    category: AlertCategory
    title_template: str
    message_template: str
    cooldown_seconds: int = 300
    enabled: bool = True


@dataclass
class AlertChannel:
    """Channel for sending alerts"""
    name: str
    type: str  # email, slack, webhook, log
    config: Dict[str, Any]
    enabled: bool = True
    min_severity: AlertSeverity = AlertSeverity.WARNING


class AlertManager:
    """
    Alert Management System

    Manages alert generation, routing, and history.
    """

    def __init__(self):
        self._alerts: Dict[str, Alert] = {}
        self._alert_history: List[Alert] = []
        self._alert_counts: Dict[AlertSeverity, int] = defaultdict(int)
        self._channels: Dict[str, AlertChannel] = {}
        self._rules: List[AlertRule] = []
        self._last_triggered: Dict[str, float] = {}  # rule_name -> last_triggered
        self._alert_counter: int = 0  # Unique ID counter

        # Setup default channels
        self._setup_default_channels()

        # Setup default rules
        self._setup_default_rules()

    def _setup_default_channels(self):
        """Setup default alert channels"""
        self.add_channel(AlertChannel(
            name="log",
            type="log",
            config={"level": "INFO"},
            enabled=True,
            min_severity=AlertSeverity.INFO
        ))

    def _setup_default_rules(self):
        """Setup default alert rules"""
        # High threat rate alert
        self.add_rule(AlertRule(
            name="high_threat_rate",
            condition=lambda ctx: ctx.get("threat_rate", 0) > 0.2,
            severity=AlertSeverity.CRITICAL,
            category=AlertCategory.THREAT,
            title_template="Yüksek Tehdit Oranı",
            message_template="Tehdit oranı %{threat_rate} olarak tespit edildi. Dikkatli olun!"
        ))

        # New threat source detected
        self.add_rule(AlertRule(
            name="new_threat_source",
            condition=lambda ctx: ctx.get("new_threat_source_detected", False),
            severity=AlertSeverity.WARNING,
            category=AlertCategory.THREAT,
            title_template="Yeni Tehdit Kaynağı",
            message_template="'{source}' kaynağından yeni tehdit tespit edildi."
        ))

        # System degraded
        self.add_rule(AlertRule(
            name="system_degraded",
            condition=lambda ctx: ctx.get("system_status") == "degraded",
            severity=AlertSeverity.WARNING,
            category=AlertCategory.SYSTEM,
            title_template="Sistem Performansı Düştü",
            message_template="Sistem yüksek yük altında. Performans iyileştirmesi gerekebilir."
        ))

        # Critical system status
        self.add_rule(AlertRule(
            name="system_critical",
            condition=lambda ctx: ctx.get("system_status") == "critical",
            severity=AlertSeverity.EMERGENCY,
            category=AlertCategory.SYSTEM,
            title_template="Sistem Kritik Durumda!",
            message_template="Sistem kritik performans sorunları yaşıyor. Acil müdahale gerekli!"
        ))

    def add_channel(self, channel: AlertChannel):
        """Add an alert channel"""
        self._channels[channel.name] = channel

    def add_rule(self, rule: AlertRule):
        """Add an alert rule"""
        self._rules.append(rule)

    def create_alert(
        self,
        severity: AlertSeverity,
        category: AlertCategory,
        title: str,
        message: str,
        source: str = "system",
        tags: List[str] = None,
        metadata: Dict[str, Any] = None
    ) -> Alert:
        """
        Create and trigger a new alert.

        Args:
            severity: Alert severity
            category: Alert category
            title: Alert title
            message: Alert message
            source: Alert source
            tags: Alert tags
            metadata: Additional metadata

        Returns:
            Created Alert
        """
        self._alert_counter += 1
        alert_id = f"alert_{self._alert_counter}_{int(time.time() * 1000)}"

        alert = Alert(
            id=alert_id,
            severity=severity,
            category=category,
            title=title,
            message=message,
            timestamp=time.time(),
            source=source,
            tags=tags or [],
            metadata=metadata or {}
        )

        self._alerts[alert_id] = alert
        self._alert_history.append(alert)
        self._alert_counts[severity] += 1

        # Send to channels
        self._send_to_channels(alert)

        return alert

    def _send_to_channels(self, alert: Alert):
        """Send alert to configured channels"""
        for channel in self._channels.values():
            if not channel.enabled:
                continue

            if alert.severity.value < channel.min_severity.value:
                continue

            if channel.type == "log":
                self._send_to_log_channel(alert, channel)
            elif channel.type == "webhook":
                self._send_to_webhook(alert, channel)

    def _send_to_log_channel(self, alert: Alert, channel: AlertChannel):
        """Send alert to log channel"""
        log_level = channel.config.get("level", "INFO")
        print(f"[{log_level}] Alert: {alert.title} - {alert.message}")

    def _send_to_webhook(self, alert: Alert, channel: AlertChannel):
        """Send alert to webhook"""
        # Would implement actual webhook call here
        pass

    def evaluate_rules(self, context: Dict[str, Any]):
        """
        Evaluate all rules against context.

        Args:
            context: Current system context
        """
        for rule in self._rules:
            if not rule.enabled:
                continue

            # Check cooldown
            last_triggered = self._last_triggered.get(rule.name, 0)
            if time.time() - last_triggered < rule.cooldown_seconds:
                continue

            # Evaluate condition
            try:
                if rule.condition(context):
                    self.create_alert(
                        severity=rule.severity,
                        category=rule.category,
                        title=rule.title_template.format(**context),
                        message=rule.message_template.format(**context),
                        source=f"rule:{rule.name}"
                    )
                    self._last_triggered[rule.name] = time.time()
            except Exception:
                pass

    def get_active_alerts(
        self,
        severity: AlertSeverity = None,
        category: AlertCategory = None
    ) -> List[Alert]:
        """
        Get active (unresolved) alerts.

        Args:
            severity: Filter by severity
            category: Filter by category

        Returns:
            List of active alerts
        """
        alerts = [a for a in self._alerts.values() if not a.resolved]

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        if category:
            alerts = [a for a in alerts if a.category == category]

        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)

    def get_alert_counts(self) -> Dict[str, int]:
        """Get count of alerts by severity"""
        return {
            "total": len(self._alerts),
            "active": len(self.get_active_alerts()),
            "info": self._alert_counts[AlertSeverity.INFO],
            "warning": self._alert_counts[AlertSeverity.WARNING],
            "critical": self._alert_counts[AlertSeverity.CRITICAL],
            "emergency": self._alert_counts[AlertSeverity.EMERGENCY],
        }

    def resolve_alert(self, alert_id: str) -> bool:
        """
        Mark alert as resolved.

        Args:
            alert_id: Alert ID to resolve

        Returns:
            True if resolved
        """
        alert = self._alerts.get(alert_id)
        if not alert:
            return False

        alert.resolved = True
        alert.resolved_at = time.time()
        return True

    def get_alert_history(
        self,
        limit: int = 100,
        severity: AlertSeverity = None
    ) -> List[Alert]:
        """
        Get alert history.

        Args:
            limit: Maximum number of alerts
            severity: Filter by severity

        Returns:
            List of historical alerts
        """
        history = sorted(self._alert_history, key=lambda a: a.timestamp, reverse=True)

        if severity:
            history = [a for a in history if a.severity == severity]

        return history[:limit]

    def clear_resolved_alerts(self):
        """Remove resolved alerts from active list"""
        self._alerts = {
            aid: alert for aid, alert in self._alerts.items()
            if not alert.resolved
        }


# Singleton instance
alert_manager = AlertManager()
