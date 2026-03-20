"""Tests for ELK Forwarder module."""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import Mock, patch, MagicMock

import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.integration.elk_forwarder import (
    ELKForwarder,
    get_forwarder,
    forward_alert_to_elk,
)


class TestELKForwarder:
    """Test cases for ELKForwarder class."""

    def test_initialization_disabled_by_default(self):
        """Test that forwarder is disabled when no env vars set."""
        with patch.dict(os.environ, {}, clear=True):
            forwarder = ELKForwarder()
            assert forwarder.is_enabled is False

    def test_initialization_enabled_from_env(self):
        """Test enabling via environment variable."""
        with patch.dict(os.environ, {"ELK_ENABLED": "true", "ELK_HOST": "elk.local", "ELK_PORT": "5045"}):
            forwarder = ELKForwarder()
            assert forwarder.is_enabled is True

    def test_initialization_with_custom_params(self):
        """Test initialization with custom host/port."""
        forwarder = ELKForwarder(
            host="custom-host",
            port=5050,
            enabled=True,
        )
        assert forwarder.is_enabled is True

    def test_forward_alert_disabled(self):
        """Test that forward_alert returns False when disabled."""
        forwarder = ELKForwarder(enabled=False)
        result = forwarder.forward_alert({"id": "test", "message": "hello"})
        assert result is False

    @patch("socket.socket")
    def test_forward_alert_success(self, mock_socket_class):
        """Test successful alert forwarding."""
        # Setup mock socket
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        
        forwarder = ELKForwarder(host="localhost", port=5044, enabled=True)
        alert = {"id": "test-alert", "rf_label": "DDoS", "threat_score": 85}
        
        result = forwarder.forward_alert(alert)
        
        assert result is True
        mock_socket.connect.assert_called_once_with(("localhost", 5044))
        mock_socket.sendall.assert_called_once()
        
        # Verify the message format
        sent_data = mock_socket.sendall.call_args[0][0]
        sent_json = json.loads(sent_data.decode("utf-8"))
        assert sent_json["id"] == "test-alert"
        assert sent_json["@timestamp"] is not None
        assert sent_json["indexed_by"] == "ainids-elk-forwarder"

    @patch("socket.socket")
    def test_forward_alert_connection_failure(self, mock_socket_class):
        """Test handling of connection failure."""
        import socket as socket_module
        
        mock_socket = MagicMock()
        mock_socket.connect.side_effect = socket_module.error("Connection refused")
        mock_socket_class.return_value = mock_socket
        
        forwarder = ELKForwarder(host="localhost", port=5044, enabled=True)
        result = forwarder.forward_alert({"id": "test"})
        
        assert result is False

    @patch("socket.socket")
    def test_forward_batch(self, mock_socket_class):
        """Test batch forwarding."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        
        forwarder = ELKForwarder(host="localhost", port=5044, enabled=True)
        alerts = [
            {"id": "alert-1"},
            {"id": "alert-2"},
            {"id": "alert-3"},
        ]
        
        success, failed = forwarder.forward_batch(alerts)
        
        assert success == 3
        assert failed == 0
        assert mock_socket.sendall.call_count == 3

    @patch("socket.socket")
    def test_forward_batch_partial_failure(self, mock_socket_class):
        """Test batch forwarding with some failures."""
        import socket as socket_module
        
        mock_socket = MagicMock()
        # Fail on second send
        mock_socket.sendall.side_effect = [
            None,
            socket_module.error("Send failed"),
            None,
        ]
        mock_socket_class.return_value = mock_socket
        
        forwarder = ELKForwarder(host="localhost", port=5044, enabled=True)
        alerts = [
            {"id": "alert-1"},
            {"id": "alert-2"},
            {"id": "alert-3"},
        ]
        
        success, failed = forwarder.forward_batch(alerts)
        
        assert success == 2
        assert failed == 1

    @patch("socket.socket")
    def test_flush_closes_socket(self, mock_socket_class):
        """Test that flush closes the connection."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        
        forwarder = ELKForwarder(host="localhost", port=5044, enabled=True)
        forwarder.forward_alert({"id": "test"})  # Establish connection
        forwarder.flush()
        
        mock_socket.close.assert_called_once()

    @patch("socket.socket")
    def test_context_manager(self, mock_socket_class):
        """Test using forwarder as context manager."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        
        with ELKForwarder(host="localhost", port=5044, enabled=True) as forwarder:
            forwarder.forward_alert({"id": "test"})
        
        mock_socket.close.assert_called_once()

    @patch("socket.socket")
    def test_alert_metadata_added(self, mock_socket_class):
        """Test that @timestamp and indexed_by are added to alerts."""
        mock_socket = MagicMock()
        mock_socket_class.return_value = mock_socket
        
        forwarder = ELKForwarder(host="localhost", port=5044, enabled=True)
        alert = {"id": "test", "src_ip": "192.168.1.1"}
        
        forwarder.forward_alert(alert)
        
        sent_data = mock_socket.sendall.call_args[0][0]
        sent_json = json.loads(sent_data.decode("utf-8"))
        
        assert "@timestamp" in sent_json
        assert sent_json["indexed_by"] == "ainids-elk-forwarder"
        assert sent_json["forwarder_version"] == "1.0.0"


class TestGlobalFunctions:
    """Test module-level functions."""

    def test_get_forwarder_singleton(self):
        """Test that get_forwarder returns same instance."""
        # Reset global
        import src.integration.elk_forwarder as module
        module._forwarder = None
        
        with patch.dict(os.environ, {}, clear=True):
            f1 = get_forwarder()
            f2 = get_forwarder()
            
            assert f1 is f2
            assert f1.is_enabled is False

    def test_forward_alert_to_elk_convenience(self):
        """Test the convenience function."""
        import src.integration.elk_forwarder as module
        module._forwarder = None
        
        with patch.dict(os.environ, {}, clear=True):
            result = forward_alert_to_elk({"id": "test"})
            assert result is False  # Disabled by default
