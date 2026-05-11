"""Tests for Alert Enricher module.

TDD RED Phase: These tests should fail until enricher.py is implemented.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, UTC
from unittest.mock import MagicMock, patch, Mock
from dataclasses import dataclass

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestEnrichedAlert:
    """Test EnrichedAlert dataclass."""

    def test_creation(self):
        """Test creating EnrichedAlert."""
        from src.integration.enricher import EnrichedAlert

        alert = EnrichedAlert(
            alert_id="alert-123",
            timestamp="2026-03-19T14:32:15Z",
            src_ip="203.0.113.50",
            dst_ip="192.168.1.100",
            dst_port=443,
            protocol="TCP",
            rf_label="DDoS",
            rf_confidence=0.99,
            xgb_label="DDoS",
            xgb_confidence=0.98,
            if_anomaly=True,
            ae_anomaly=True,
            final_verdict="Attack",
            combined_confidence=0.985,
            ti_score=75,
            ti_reputation="bad",
            ti_sources=["VirusTotal", "AbuseIPDB"],
            ti_country="RU",
            ti_asn="AS12345",
            status="new",
        )

        assert alert.alert_id == "alert-123"
        assert alert.src_ip == "203.0.113.50"
        assert alert.ti_score == 75
        assert alert.ti_reputation == "bad"
        assert len(alert.ti_sources) == 2
        assert alert.status == "new"

    def test_immutable(self):
        """Test that EnrichedAlert is immutable."""
        from src.integration.enricher import EnrichedAlert

        alert = EnrichedAlert(
            alert_id="alert-456",
            timestamp="2026-03-19T14:32:15Z",
            src_ip="10.0.0.1",
            dst_ip="192.168.1.1",
            dst_port=80,
            protocol="TCP",
            rf_label="Normal Traffic",
            rf_confidence=0.95,
            xgb_label="Normal Traffic",
            xgb_confidence=0.94,
            if_anomaly=False,
            ae_anomaly=False,
            final_verdict="Benign",
            combined_confidence=0.945,
            ti_score=0,
            ti_reputation="clean",
            ti_sources=[],
            ti_country="",
            ti_asn="",
            status="new",
        )

        with pytest.raises(AttributeError):
            alert.ti_score = 50


class TestAlertEnricher:
    """Test AlertEnricher class."""

    @pytest.fixture
    def mock_ti_client(self):
        """Create a mock ThreatIntelClient."""
        from src.integration.ti_client import ThreatIntelResult

        mock_client = MagicMock()
        mock_client.lookup_ip.return_value = ThreatIntelResult(
            ip="203.0.113.50",
            is_malicious=True,
            threat_score=75,
            sources=["VirusTotal", "AbuseIPDB"],
            country="RU",
            asn="AS12345",
            reputation="bad",
            last_seen="",
            cached=False,
        )
        return mock_client

    @pytest.fixture
    def enricher(self, mock_ti_client):
        """Create AlertEnricher instance with mock TI client."""
        from src.integration.enricher import AlertEnricher

        return AlertEnricher(ti_client=mock_ti_client)

    @pytest.fixture
    def sample_alert(self):
        """Create a sample alert dictionary."""
        return {
            "id": "alert-123",
            "timestamp": "2026-03-19T14:32:15Z",
            "src_ip": "203.0.113.50",
            "dst_ip": "192.168.1.100",
            "dst_port": 443,
            "protocol": "TCP",
            "rf_label": "DDoS",
            "rf_confidence": 0.99,
            "xgb_label": "DDoS",
            "xgb_confidence": 0.98,
            "if_anomaly": True,
            "ae_anomaly": True,
            "final_verdict": "Attack",
            "combined_confidence": 0.985,
        }

    def test_enrich_alert_returns_enriched_alert(self, enricher, sample_alert):
        """Test enrich_alert returns EnrichedAlert."""
        from src.integration.enricher import EnrichedAlert

        result = enricher.enrich_alert(sample_alert)

        assert isinstance(result, EnrichedAlert)
        assert result.alert_id == "alert-123"
        assert result.src_ip == "203.0.113.50"

    def test_enrich_alert_adds_ti_data(self, enricher, sample_alert, mock_ti_client):
        """Test enrich_alert adds threat intelligence data."""
        result = enricher.enrich_alert(sample_alert)

        # Verify TI client was called
        mock_ti_client.lookup_ip.assert_called_once_with("203.0.113.50")

        # Verify TI data was added
        assert result.ti_score == 75
        assert result.ti_reputation == "bad"
        assert "VirusTotal" in result.ti_sources
        assert result.ti_country == "RU"
        assert result.ti_asn == "AS12345"

    def test_enrich_alert_preserves_original_data(self, enricher, sample_alert):
        """Test enrich_alert preserves original alert data."""
        result = enricher.enrich_alert(sample_alert)

        assert result.rf_label == "DDoS"
        assert result.rf_confidence == 0.99
        assert result.xgb_label == "DDoS"
        assert result.final_verdict == "Attack"
        assert result.combined_confidence == 0.985

    def test_enrich_alert_handles_missing_ti_gracefully(self, sample_alert):
        """Test enrich_alert handles TI lookup failure gracefully."""
        from src.integration.enricher import AlertEnricher

        mock_client = MagicMock()
        mock_client.lookup_ip.side_effect = Exception("API Error")

        enricher = AlertEnricher(ti_client=mock_client)
        result = enricher.enrich_alert(sample_alert)

        # Should still return result with default TI values
        assert result.ti_score == 0
        assert result.ti_reputation == "unknown"
        assert result.ti_sources == []

    def test_enrich_alert_sets_default_status(self, enricher, sample_alert):
        """Test enrich_alert sets default status to 'new'."""
        result = enricher.enrich_alert(sample_alert)

        assert result.status == "new"

    def test_enrich_alert_with_existing_status(self, enricher, sample_alert):
        """Test enrich_alert preserves existing status."""
        sample_alert["status"] = "investigating"

        result = enricher.enrich_alert(sample_alert)

        assert result.status == "investigating"

    def test_enrich_batch_alerts(self, enricher, sample_alert, mock_ti_client):
        """Test enriching multiple alerts in batch."""
        alerts = [
            sample_alert,
            {
                **sample_alert,
                "id": "alert-456",
                "src_ip": "198.51.100.25",
            },
        ]

        # Set up different TI responses for different IPs
        from src.integration.ti_client import ThreatIntelResult

        def lookup_side_effect(ip):
            if ip == "203.0.113.50":
                return ThreatIntelResult(
                    ip=ip,
                    is_malicious=True,
                    threat_score=75,
                    sources=["VirusTotal"],
                    country="RU",
                    asn="AS12345",
                    reputation="bad",
                    last_seen="",
                    cached=False,
                )
            else:
                return ThreatIntelResult(
                    ip=ip,
                    is_malicious=False,
                    threat_score=10,
                    sources=["OTX"],
                    country="US",
                    asn="AS54321",
                    reputation="clean",
                    last_seen="",
                    cached=False,
                )

        mock_ti_client.lookup_ip.side_effect = lookup_side_effect

        results = enricher.enrich_batch(alerts)

        assert len(results) == 2
        assert results[0].ti_score == 75
        assert results[1].ti_score == 10

    def test_enrich_alert_with_minimal_data(self, enricher):
        """Test enrich_alert handles minimal alert data."""
        minimal_alert = {
            "id": "alert-minimal",
            "timestamp": "2026-03-19T14:32:15Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "final_verdict": "Benign",
        }

        result = enricher.enrich_alert(minimal_alert)

        assert result.alert_id == "alert-minimal"
        assert result.src_ip == "10.0.0.1"
        # Missing fields should have defaults
        assert result.rf_label == ""
        assert result.rf_confidence == 0.0
        assert result.protocol == "TCP"

    def test_to_dict_conversion(self, enricher, sample_alert):
        """Test EnrichedAlert can be converted to dict."""
        result = enricher.enrich_alert(sample_alert)

        result_dict = enricher.to_dict(result)

        assert isinstance(result_dict, dict)
        assert result_dict["alert_id"] == "alert-123"
        assert result_dict["ti_score"] == 75
        assert result_dict["ti_sources"] == ["VirusTotal", "AbuseIPDB"]


class TestAlertEnricherCaching:
    """Test AlertEnricher caching behavior."""

    @pytest.fixture
    def mock_ti_client(self):
        """Create a mock ThreatIntelClient with caching simulation."""
        from src.integration.ti_client import ThreatIntelResult

        call_count = {"count": 0}

        def lookup_with_cache(ip):
            call_count["count"] += 1
            return ThreatIntelResult(
                ip=ip,
                is_malicious=False,
                threat_score=10,
                sources=["OTX"],
                country="US",
                asn="AS12345",
                reputation="clean",
                last_seen="",
                cached=call_count["count"] > 1,  # First call is not cached
            )

        mock_client = MagicMock()
        mock_client.lookup_ip.side_effect = lookup_with_cache
        mock_client._call_count = call_count
        return mock_client

    def test_ti_client_caching_used(self, mock_ti_client):
        """Test that TI client caching is utilized."""
        from src.integration.enricher import AlertEnricher

        enricher = AlertEnricher(ti_client=mock_ti_client)

        alert = {
            "id": "alert-1",
            "timestamp": "2026-03-19T14:32:15Z",
            "src_ip": "1.1.1.1",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "final_verdict": "Benign",
        }

        # Enrich same IP twice
        result1 = enricher.enrich_alert(alert)
        result2 = enricher.enrich_alert(alert)

        # TI client should be called twice (caching is handled by TI client)
        assert mock_ti_client.lookup_ip.call_count == 2


class TestAlertEnricherValidation:
    """Test AlertEnricher input validation."""

    @pytest.fixture
    def enricher(self):
        """Create AlertEnricher with mock TI client."""
        from src.integration.enricher import AlertEnricher
        from src.integration.ti_client import ThreatIntelResult

        mock_client = MagicMock()
        mock_client.lookup_ip.return_value = ThreatIntelResult(
            ip="0.0.0.0",
            is_malicious=False,
            threat_score=0,
            sources=[],
            country="",
            asn="",
            reputation="clean",
            last_seen="",
            cached=False,
        )
        return AlertEnricher(ti_client=mock_client)

    def test_enrich_alert_requires_id(self, enricher):
        """Test enrich_alert requires alert ID."""
        alert_without_id = {
            "timestamp": "2026-03-19T14:32:15Z",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "final_verdict": "Benign",
        }

        with pytest.raises(ValueError, match="id"):
            enricher.enrich_alert(alert_without_id)

    def test_enrich_alert_requires_src_ip(self, enricher):
        """Test enrich_alert requires source IP."""
        alert_without_ip = {
            "id": "alert-123",
            "timestamp": "2026-03-19T14:32:15Z",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "final_verdict": "Benign",
        }

        with pytest.raises(ValueError, match="src_ip"):
            enricher.enrich_alert(alert_without_ip)

    def test_enrich_alert_validates_ip_format(self, enricher):
        """Test enrich_alert validates IP address format."""
        alert_with_invalid_ip = {
            "id": "alert-123",
            "timestamp": "2026-03-19T14:32:15Z",
            "src_ip": "not-an-ip",
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "final_verdict": "Benign",
        }

        with pytest.raises(ValueError, match="Invalid IP"):
            enricher.enrich_alert(alert_with_invalid_ip)
