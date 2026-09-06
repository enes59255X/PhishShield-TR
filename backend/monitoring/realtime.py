"""
PhishShield TR - Real-time Updates
Sprint 14: WebSocket and SSE support for live updates

Purpose:
- Push real-time updates to dashboard clients
- Support WebSocket and Server-Sent Events (SSE)
- Connection management and heartbeats
- Broadcast capabilities
"""

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Callable, Any, Optional
from enum import Enum


class ConnectionType(Enum):
    """Connection type for real-time updates"""
    WEBSOCKET = "websocket"
    SSE = "sse"
    POLLING = "polling"


@dataclass
class ClientConnection:
    """Single client connection"""
    id: str
    connection_type: ConnectionType
    connected_at: float
    last_activity: float
    subscribed_channels: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BroadcastMessage:
    """Message to broadcast to clients"""
    channel: str
    event_type: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)


class RealtimeManager:
    """
    Real-time Update Manager

    Manages client connections and broadcasts updates.
    """

    def __init__(self):
        self._connections: Dict[str, ClientConnection] = {}
        self._channels: Dict[str, Set[str]] = defaultdict(set)  # channel -> connection_ids
        self._message_queue: List[BroadcastMessage] = []
        self._max_queue_size = 1000
        self._heartbeat_interval = 30  # seconds

        # Event handlers
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)

    def add_connection(
        self,
        connection_id: str,
        connection_type: ConnectionType = ConnectionType.WEBSOCKET,
        metadata: Dict[str, Any] = None
    ) -> ClientConnection:
        """
        Add a new client connection.

        Args:
            connection_id: Unique connection ID
            connection_type: Type of connection
            metadata: Additional connection metadata

        Returns:
            ClientConnection
        """
        connection = ClientConnection(
            id=connection_id,
            connection_type=connection_type,
            connected_at=time.time(),
            last_activity=time.time(),
            metadata=metadata or {}
        )

        self._connections[connection_id] = connection
        return connection

    def remove_connection(self, connection_id: str):
        """
        Remove a client connection.

        Args:
            connection_id: Connection ID to remove
        """
        if connection_id not in self._connections:
            return

        connection = self._connections[connection_id]

        # Remove from all channels
        for channel in connection.subscribed_channels:
            if channel in self._channels:
                self._channels[channel].discard(connection_id)

        del self._connections[connection_id]

    def subscribe(self, connection_id: str, channel: str) -> bool:
        """
        Subscribe connection to a channel.

        Args:
            connection_id: Connection ID
            channel: Channel name

        Returns:
            True if subscribed
        """
        if connection_id not in self._connections:
            return False

        connection = self._connections[connection_id]
        connection.subscribed_channels.add(channel)
        self._channels[channel].add(connection_id)
        return True

    def unsubscribe(self, connection_id: str, channel: str) -> bool:
        """
        Unsubscribe connection from a channel.

        Args:
            connection_id: Connection ID
            channel: Channel name

        Returns:
            True if unsubscribed
        """
        if connection_id not in self._connections:
            return False

        connection = self._connections[connection_id]
        connection.subscribed_channels.discard(channel)
        if channel in self._channels:
            self._channels[channel].discard(connection_id)
        return True

    def broadcast(
        self,
        channel: str,
        event_type: str,
        data: Dict[str, Any]
    ):
        """
        Broadcast message to all subscribers of a channel.

        Args:
            channel: Channel name
            event_type: Event type
            data: Event data
        """
        message = BroadcastMessage(
            channel=channel,
            event_type=event_type,
            data=data
        )

        # Add to queue
        self._message_queue.append(message)

        # Trim queue if needed
        if len(self._message_queue) > self._max_queue_size:
            self._message_queue = self._message_queue[-self._max_queue_size:]

        # Trigger handlers
        for handler in self._handlers.get(channel, []):
            try:
                handler(message)
            except Exception:
                pass

        # Also trigger wildcard handlers
        for handler in self._handlers.get("*", []):
            try:
                handler(message)
            except Exception:
                pass

    def on_message(self, channel: str, handler: Callable[[BroadcastMessage], None]):
        """
        Register handler for channel messages.

        Args:
            channel: Channel name (or * for all)
            handler: Handler function
        """
        self._handlers[channel].append(handler)

    def get_subscribers(self, channel: str) -> List[str]:
        """Get list of connection IDs subscribed to channel"""
        return list(self._channels.get(channel, set()))

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        by_type = defaultdict(int)
        for conn in self._connections.values():
            by_type[conn.connection_type.value] += 1

        return {
            "total_connections": len(self._connections),
            "by_type": dict(by_type),
            "total_channels": len(self._channels),
            "channel_subscriptions": {
                channel: len(subs)
                for channel, subs in self._channels.items()
            },
            "queue_size": len(self._message_queue)
        }

    def get_pending_messages(
        self,
        connection_id: str,
        since: float = 0
    ) -> List[Dict[str, Any]]:
        """
        Get pending messages for a connection (for polling).

        Args:
            connection_id: Connection ID
            since: Get messages after this timestamp

        Returns:
            List of message dictionaries
        """
        if connection_id not in self._connections:
            return []

        connection = self._connections[connection_id]
        subscribed = connection.subscribed_channels

        messages = []
        for msg in self._message_queue:
            if msg.timestamp <= since:
                continue
            if msg.channel not in subscribed:
                continue
            messages.append({
                "channel": msg.channel,
                "type": msg.event_type,
                "data": msg.data,
                "timestamp": msg.timestamp
            })

        # Update last activity
        connection.last_activity = time.time()

        return messages

    def cleanup_stale_connections(self, timeout_seconds: int = 300) -> int:
        """
        Remove stale connections.

        Args:
            timeout_seconds: Connection timeout

        Returns:
            Number of connections removed
        """
        current_time = time.time()
        stale_ids = []

        for conn_id, conn in self._connections.items():
            if current_time - conn.last_activity > timeout_seconds:
                stale_ids.append(conn_id)

        for conn_id in stale_ids:
            self.remove_connection(conn_id)

        return len(stale_ids)

    def ping(self, connection_id: str) -> bool:
        """
        Ping a connection to keep it alive.

        Args:
            connection_id: Connection ID

        Returns:
            True if pinged
        """
        if connection_id not in self._connections:
            return False

        self._connections[connection_id].last_activity = time.time()
        return True


# Singleton instance
realtime_manager = RealtimeManager()


class EventTypes:
    """Event type constants for real-time updates"""
    # Dashboard events
    DASHBOARD_UPDATE = "dashboard:update"
    METRIC_UPDATE = "metric:update"
    ALERT_CREATED = "alert:created"
    ALERT_RESOLVED = "alert:resolved"

    # Threat events
    THREAT_DETECTED = "threat:detected"
    BRAND_IMPERSONATION = "threat:brand_impersonation"
    PHISHING_CAMPAIGN = "threat:phishing_campaign"

    # System events
    SYSTEM_STATUS = "system:status"
    PERFORMANCE_WARNING = "system:performance_warning"
    FEED_UPDATE = "system:feed_update"

    # Connection events
    CONNECTED = "connection:connected"
    DISCONNECTED = "connection:disconnected"


class Channels:
    """Channel constants for subscriptions"""
    DASHBOARD = "dashboard"
    ALERTS = "alerts"
    THREATS = "threats"
    SYSTEM = "system"
    METRICS = "metrics"
