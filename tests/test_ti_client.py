"""Tests for Threat Intelligence Client module.

TDD RED Phase: These tests should fail until ti_client.py is implemented.
"""

from __future__ import annotations

import os
import sys
import sqlite3
from datetime import datetime, UTC, timedelta
from unittest.mock import MagicMock, patch, Mock
import json

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestThreatIntelResult:
    """Test ThreatIntelResult dataclass."""

    def test_creation(self):
        """Test creating ThreatIntelResult."""
        from src.integration.ti_client import ThreatIntelResult

        result = ThreatIntelResult(
            ip="192.168.1.1",
            is_malicious=True,
            threat_score=75,
            sources=["VirusTotal", "AbuseIPDB"],
            country="US",
            asn="AS12345",
            reputation="bad",
            last_seen="2026-03-19T12:00:00Z",
            cached=False,
        )

        assert result.ip == "192.168.1.1"
        assert result.is_malicious is True
        assert result.threat_score == 75
        assert len(result.sources) == 2
        assert result.country == "US"
        assert result.cached is False

    def test_immutable(self):
        """Test that ThreatIntelResult is immutable."""
        from src.integration.ti_client import ThreatIntelResult

        result = ThreatIntelResult(
            ip="10.0.0.1",
            is_malicious=False,
            threat_score=0,
            sources=[],
            country="",
            asn="",
            reputation="clean",
            last_seen="",
            cached=True,
        )

        with pytest.raises(AttributeError):
            result.threat_score = 50


class TestThreatIntelClient:
    """Test ThreatIntelClient class."""

    @pytest.fixture
    def ti_client(self, tmp_path):
        """Create ThreatIntelClient instance with temp cache."""
        from src.integration.ti_client import ThreatIntelClient

        cache_path = tmp_path / "ti_cache.db"
        return ThreatIntelClient(
            cache_db_path=str(cache_path),
            vt_api_key="test_vt_key",
            abuseipdb_api_key="test_abuse_key",
        )

    def test_init_creates_cache_db(self, ti_client, tmp_path):
        """Test that init creates SQLite cache database."""
        cache_path = tmp_path / "ti_cache.db"
        assert cache_path.exists()

    def test_cache_table_exists(self, ti_client, tmp_path):
        """Test that cache table is created."""
        cache_path = tmp_path / "ti_cache.db"
        conn = sqlite3.connect(str(cache_path))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ti_cache'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_lookup_ip_returns_result(self, ti_client):
        """Test lookup_ip returns ThreatIntelResult."""
        from src.integration.ti_client import ThreatIntelResult

        # Mock all API calls
        with patch.object(ti_client, "_check_virustotal") as mock_vt:
            with patch.object(ti_client, "_check_abuseipdb") as mock_abuse:
                with patch.object(ti_client, "_check_otx") as mock_otx:
                    mock_vt.return_value = {
                        "malicious": 5,
                        "total": 90,
                        "country": "US",
                        "asn": "AS12345",
                    }
                    mock_abuse.return_value = {
                        "reports": 10,
                        "confidence_score": 50,
                    }
                    mock_otx.return_value = {
                        "pulses": 2,
                        "reputation": "suspicious",
                    }

                    result = ti_client.lookup_ip("8.8.8.8")

                    assert isinstance(result, ThreatIntelResult)
                    assert result.ip == "8.8.8.8"

    def test_lookup_ip_caches_result(self, ti_client, tmp_path):
        """Test that lookup_ip caches result."""
        with patch.object(ti_client, "_check_virustotal") as mock_vt:
            with patch.object(ti_client, "_check_abuseipdb") as mock_abuse:
                with patch.object(ti_client, "_check_otx") as mock_otx:
                    mock_vt.return_value = {"malicious": 0, "total": 90}
                    mock_abuse.return_value = {"reports": 0, "confidence_score": 0}
                    mock_otx.return_value = {"pulses": 0, "reputation": "clean"}

                    # First lookup
                    result1 = ti_client.lookup_ip("1.1.1.1")
                    assert result1.cached is False

                    # Second lookup should be cached
                    result2 = ti_client.lookup_ip("1.1.1.1")
                    assert result2.cached is True

                    # VT should only be called once
                    assert mock_vt.call_count == 1

    def test_cache_expiry(self, ti_client, tmp_path):
        """Test that cache expires after TTL."""
        from src.integration.ti_client import DEFAULT_CACHE_TTL_SECONDS

        with patch.object(ti_client, "_check_virustotal") as mock_vt:
            with patch.object(ti_client, "_check_abuseipdb") as mock_abuse:
                with patch.object(ti_client, "_check_otx") as mock_otx:
                    mock_vt.return_value = {"malicious": 0, "total": 90}
                    mock_abuse.return_value = {"reports": 0, "confidence_score": 0}
                    mock_otx.return_value = {"pulses": 0, "reputation": "clean"}

                    # First lookup
                    ti_client.lookup_ip("2.2.2.2")

                    # Manually expire the cache entry
                    cache_path = tmp_path / "ti_cache.db"
                    conn = sqlite3.connect(str(cache_path))
                    old_time = (
                        datetime.now(UTC) - timedelta(seconds=DEFAULT_CACHE_TTL_SECONDS + 100)
                    ).isoformat()
                    conn.execute(
                        "UPDATE ti_cache SET timestamp = ? WHERE ip = ?",
                        (old_time, "2.2.2.2"),
                    )
                    conn.commit()
                    conn.close()

                    # Second lookup should NOT be cached (expired)
                    result = ti_client.lookup_ip("2.2.2.2")
                    assert result.cached is False
                    assert mock_vt.call_count == 2

    def test_threat_score_calculation(self, ti_client):
        """Test threat score calculation from multiple sources."""
        with patch.object(ti_client, "_check_virustotal") as mock_vt:
            with patch.object(ti_client, "_check_abuseipdb") as mock_abuse:
                with patch.object(ti_client, "_check_otx") as mock_otx:
                    # High malicious signals
                    mock_vt.return_value = {"malicious": 30, "total": 90}
                    mock_abuse.return_value = {"reports": 100, "confidence_score": 80}
                    mock_otx.return_value = {"pulses": 10, "reputation": "malicious"}

                    result = ti_client.lookup_ip("evil.ip")

                    assert result.threat_score > 50  # Should be high
                    assert result.is_malicious is True

    def test_clean_ip_low_score(self, ti_client):
        """Test clean IP has low threat score."""
        with patch.object(ti_client, "_check_virustotal") as mock_vt:
            with patch.object(ti_client, "_check_abuseipdb") as mock_abuse:
                with patch.object(ti_client, "_check_otx") as mock_otx:
                    # Clean signals
                    mock_vt.return_value = {"malicious": 0, "total": 90}
                    mock_abuse.return_value = {"reports": 0, "confidence_score": 0}
                    mock_otx.return_value = {"pulses": 0, "reputation": "clean"}

                    result = ti_client.lookup_ip("clean.ip")

                    assert result.threat_score < 20  # Should be low
                    assert result.is_malicious is False

    def test_api_error_handling(self, ti_client):
        """Test graceful handling of API errors."""
        with patch.object(ti_client, "_check_virustotal") as mock_vt:
            with patch.object(ti_client, "_check_abuseipdb") as mock_abuse:
                with patch.object(ti_client, "_check_otx") as mock_otx:
                    # VT fails, others work
                    mock_vt.side_effect = Exception("API Error")
                    mock_abuse.return_value = {"reports": 5, "confidence_score": 30}
                    mock_otx.return_value = {"pulses": 1, "reputation": "suspicious"}

                    result = ti_client.lookup_ip("test.ip")

                    # Should still return result from other sources
                    assert result is not None
                    assert "AbuseIPDB" in result.sources
                    assert "VirusTotal" not in result.sources


class TestVirusTotalAPI:
    """Test VirusTotal API integration."""

    @pytest.fixture
    def ti_client(self, tmp_path):
        """Create ThreatIntelClient instance."""
        from src.integration.ti_client import ThreatIntelClient

        return ThreatIntelClient(
            cache_db_path=str(tmp_path / "cache.db"),
            vt_api_key="test_key",
        )

    def test_virustotal_request_format(self, ti_client):
        """Test VirusTotal API request format."""
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                        "country": "US",
                        "asn": 15169,
                    }
                }
            }
            mock_get.return_value = mock_response

            ti_client._check_virustotal("8.8.8.8")

            # Verify request was made correctly
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            assert "8.8.8.8" in call_args[0][0]
            assert "x-apikey" in call_args[1]["headers"]


class TestAbuseIPDBAPI:
    """Test AbuseIPDB API integration."""

    @pytest.fixture
    def ti_client(self, tmp_path):
        """Create ThreatIntelClient instance."""
        from src.integration.ti_client import ThreatIntelClient

        return ThreatIntelClient(
            cache_db_path=str(tmp_path / "cache.db"),
            abuseipdb_api_key="test_key",
        )

    def test_abuseipdb_request_format(self, ti_client):
        """Test AbuseIPDB API request format."""
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "data": {
                    "totalReports": 5,
                    "abuseConfidenceScore": 30,
                    "countryCode": "US",
                }
            }
            mock_get.return_value = mock_response

            ti_client._check_abuseipdb("8.8.8.8")

            # Verify request was made correctly
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            assert "8.8.8.8" in str(call_args)
            assert "Key" in call_args[1]["headers"]


class TestOTXAPI:
    """Test AlienVault OTX API integration (no key required)."""

    @pytest.fixture
    def ti_client(self, tmp_path):
        """Create ThreatIntelClient instance."""
        from src.integration.ti_client import ThreatIntelClient

        return ThreatIntelClient(
            cache_db_path=str(tmp_path / "cache.db"),
        )

    def test_otx_request_format(self, ti_client):
        """Test OTX API request format."""
        with patch("requests.get") as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "pulse_info": {"count": 3},
                "reputation": 5,
            }
            mock_get.return_value = mock_response

            ti_client._check_otx("8.8.8.8")

            # Verify request was made
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            assert "8.8.8.8" in call_args[0][0]
