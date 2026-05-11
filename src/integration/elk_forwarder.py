"""ELK Stack Forwarder for sending alerts to Elasticsearch.

Sends alert data to Logstash via TCP, which then processes
and forwards to Elasticsearch for long-term storage and analysis.
"""

from __future__ import annotations

import json
import logging
import socket
import os
from datetime import datetime, UTC
from typing import Any

LOGGER = logging.getLogger(__name__)

# Default ELK configuration
DEFAULT_ELK_HOST = "localhost"
DEFAULT_ELK_PORT = 5044
DEFAULT_BUFFER_SIZE = 8192


class ELKForwarder:
    """Forwards alerts to ELK Stack via Logstash TCP input.
    
    Sends JSON-formatted alerts to Logstash, which processes them
    and forwards to Elasticsearch for indexing and visualization.
    
    Attributes:
        host: Logstash host address.
        port: Logstash TCP port.
        enabled: Whether forwarding is enabled.
        _socket: Active socket connection (None if not connected).
    """

    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        enabled: bool | None = None,
    ) -> None:
        """Initialize the ELK Forwarder.
        
        Args:
            host: Logstash host. Defaults to ELK_HOST env var or 'localhost'.
            port: Logstash port. Defaults to ELK_PORT env var or 5044.
            enabled: Whether to enable forwarding. Defaults to ELK_ENABLED env var.
        """
        self._host = host or os.getenv("ELK_HOST", DEFAULT_ELK_HOST)
        self._port = port or int(os.getenv("ELK_PORT", DEFAULT_ELK_PORT))
        self._enabled = (
            enabled if enabled is not None
            else os.getenv("ELK_ENABLED", "false").lower() == "true"
        )
        self._socket: socket.socket | None = None
        
        if self._enabled:
            LOGGER.info(
                "ELK Forwarder initialized: %s:%d",
                self._host,
                self._port,
            )
        else:
            LOGGER.debug("ELK Forwarder disabled")

    @property
    def is_enabled(self) -> bool:
        """Check if ELK forwarding is enabled."""
        return self._enabled

    def _connect(self) -> bool:
        """Establish connection to Logstash.
        
        Returns:
            True if connection successful, False otherwise.
        """
        if self._socket is not None:
            return True
            
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(5.0)
            self._socket.connect((self._host, self._port))
            LOGGER.debug("Connected to Logstash at %s:%d", self._host, self._port)
            return True
        except socket.error as e:
            LOGGER.warning("Failed to connect to Logstash: %s", e)
            self._socket = None
            return False

    def _disconnect(self) -> None:
        """Close the connection to Logstash."""
        if self._socket is not None:
            try:
                self._socket.close()
            except socket.error:
                pass
            self._socket = None

    def forward_alert(self, alert: dict[str, Any]) -> bool:
        """Forward a single alert to Logstash.
        
        Args:
            alert: Alert dictionary to forward.
            
        Returns:
            True if forwarded successfully, False otherwise.
        """
        if not self._enabled:
            return False
        
        # Add metadata
        alert["@timestamp"] = datetime.now(UTC).isoformat()
        alert["indexed_by"] = "ainids-elk-forwarder"
        alert["forwarder_version"] = "1.0.0"
        
        # Serialize to JSON
        try:
            message = json.dumps(alert, default=str) + "\n"
            encoded = message.encode("utf-8")
        except (TypeError, ValueError) as e:
            LOGGER.error("Failed to serialize alert: %s", e)
            return False
        
        # Send to Logstash
        try:
            if not self._connect():
                return False
            
            self._socket.sendall(encoded)  # type: ignore
            LOGGER.debug("Forwarded alert %s to ELK", alert.get("id", "unknown"))
            return True
        except socket.error as e:
            LOGGER.warning("Failed to forward alert: %s", e)
            self._disconnect()
            return False

    def forward_batch(self, alerts: list[dict[str, Any]]) -> tuple[int, int]:
        """Forward multiple alerts to Logstash.
        
        Args:
            alerts: List of alert dictionaries to forward.
            
        Returns:
            Tuple of (successful_count, failed_count).
        """
        if not self._enabled:
            return (0, len(alerts))
        
        success = 0
        failed = 0
        
        for alert in alerts:
            if self.forward_alert(alert):
                success += 1
            else:
                failed += 1
        
        LOGGER.info(
            "Batch forward complete: %d succeeded, %d failed",
            success,
            failed,
        )
        return (success, failed)

    def flush(self) -> None:
        """Flush and close the connection."""
        self._disconnect()

    def __enter__(self) -> ELKForwarder:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.flush()


# Global forwarder instance (lazy initialization)
_forwarder: ELKForwarder | None = None


def get_forwarder() -> ELKForwarder:
    """Get or create the global ELK forwarder instance.
    
    Returns:
        ELKForwarder singleton instance.
    """
    global _forwarder
    if _forwarder is None:
        _forwarder = ELKForwarder()
    return _forwarder


def forward_alert_to_elk(alert: dict[str, Any]) -> bool:
    """Convenience function to forward an alert using the global forwarder.
    
    Args:
        alert: Alert dictionary to forward.
        
    Returns:
        True if forwarded successfully, False otherwise.
    """
    return get_forwarder().forward_alert(alert)
