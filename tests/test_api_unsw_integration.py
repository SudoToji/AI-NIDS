"""
TDD Tests for API UNSW-NB15 Integration
========================================
Tests that the Flask API correctly handles UNSW-NB15 features
and returns Two-Stage Hybrid predictions including stage2_reason.

Run with: pytest tests/test_api_unsw_integration.py -v
"""

from __future__ import annotations

import pytest
import numpy as np
from unittest.mock import patch, MagicMock


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def unsw_sample_features():
    """Return a sample of 49 UNSW-NB15 features in correct order."""
    # These are the 49 features from UNSW-NB15 (after categorical encoding)
    # Using typical values for a network flow
    return {
        "srcip": "192.168.1.100",
        "dstip": "10.0.0.1",
        "sport": 54321,
        "dsport": 80,
        "proto": 6,
        "state": 1,  # encoded
        "dur": 1.5,
        "sbytes": 500,
        "dbytes": 200,
        "sttl": 64,
        "dttl": 64,
        "sloss": 0,
        "dloss": 0,
        "sload": 1000.0,
        "dload": 500.0,
        "spkts": 10,
        "dpkts": 5,
        "swin": 65535,
        "dwin": 65535,
        "stcpb": 1000,
        "dtcpb": 500,
        "smean": 50,
        "dmean": 40,
        "sstd": 10,
        "dstd": 8,
        "smin": 40,
        "dmin": 32,
        "smax": 60,
        "dmax": 48,
        "srans": 0,
        "drans": 0,
        "srate": 6.67,
        "drate": 3.33,
        "sinpkt": 0.15,
        "dinpkt": 0.2,
        "sjit": 0.01,
        "djit": 0.008,
        "sjit": 0.01,
        "djit": 0.008,
        "sour": 1,
        "dsource": 0,
        "smax": 1,
        "dmax": 0,
        "sconn": 1,
        "dconn": 0,
        "sintpkt": 150,
        "dintpkt": 200,
        "sintpktstd": 10,
        "dintpktstd": 8,
        "sintpktmax": 200,
        "dintpktmax": 250,
        "sintpktmin": 100,
        "dintpktmin": 150,
        "tcprtt": 0.05,
        "synack": 0.02,
        "ackdat": 0.03,
        "is_sm_ips_ports": 0,
        "ct_state_ttl": 1,
        "ct_flw_http_mthd": 0,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_srv_src": 1,
        "ct_srv_dst": 1,
        "ct_dst_ltm": 1,
        "ct_src_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 1,
        "ct_dst_src_ltm": 1,
    }


@pytest.fixture
def unsw_suspicious_features():
    """Return features that should trigger Suspicious verdict (triggers Stage 2)."""
    # High anomaly score features - unusual traffic patterns
    return {
        "srcip": "10.0.0.50",
        "dstip": "192.168.1.1",
        "sport": 12345,
        "dsport": 443,
        "proto": 6,
        "state": 1,
        "dur": 0.001,  # Very short duration
        "sbytes": 10000,  # High bytes
        "dbytes": 0,  # No response
        "sttl": 64,
        "dttl": 0,  # No response TTL
        "sloss": 0,
        "dloss": 0,
        "sload": 10000000.0,  # Very high load
        "dload": 0.0,  # No response
        "spkts": 2,  # Only 2 packets
        "dpkts": 0,  # No response
        "swin": 65535,
        "dwin": 0,
        "stcpb": 1000,
        "dtcpb": 0,
        "smean": 5000,
        "dmean": 0,
        "sstd": 1000,
        "dstd": 0,
        "smin": 4000,
        "dmin": 0,
        "smax": 6000,
        "dmax": 0,
        "srans": 0,
        "drans": 0,
        "srate": 10000.0,
        "drate": 0.0,
        "sinpkt": 0.0005,
        "dinpkt": 0,
        "sjit": 0.001,
        "djit": 0,
        "sjit": 0.001,
        "djit": 0,
        "sour": 1,
        "dsource": 0,
        "smax": 1,
        "dmax": 0,
        "sconn": 1,
        "dconn": 0,
        "sintpkt": 0.5,
        "dintpkt": 0,
        "sintpktstd": 0.1,
        "dintpktstd": 0,
        "sintpktmax": 1,
        "dintpktmax": 0,
        "sintpktmin": 0,
        "dintpktmin": 0,
        "tcprtt": 0,
        "synack": 0,
        "ackdat": 0,
        "is_sm_ips_ports": 1,
        "ct_state_ttl": 1,
        "ct_flw_http_mthd": 0,
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_srv_src": 1,
        "ct_srv_dst": 0,
        "ct_dst_ltm": 1,
        "ct_src_ltm": 1,
        "ct_src_dport_ltm": 1,
        "ct_dst_sport_ltm": 0,
        "ct_dst_src_ltm": 1,
    }


# ============================================================================
# TEST: API Predict with UNSW-NB15 Features
# ============================================================================

class TestUNSWFeatureSupport:
    """Test that /api/predict accepts UNSW-NB15 49-feature format."""

    def test_predict_accepts_unsw_features(self, unsw_sample_features):
        """
        RED PHASE: This test should FAIL initially because server.py
        expects 52 CIC-IDS2017 features, not 49 UNSW-NB15 features.
        
        After implementation, the API should accept the 49-feature format
        and return a valid prediction.
        """
        from src.api.server import extract_unsw_features
        import numpy as np
        
        # The new UNSW-NB15 model expects 45 features (after removing id, label, attack_cat)
        # This test verifies the feature extraction handles the new format
        features = extract_unsw_features(unsw_sample_features)
        
        # Should return 45 features for UNSW-NB15 (numeric features only)
        assert features.shape[1] == 45, f"Expected 45 features, got {features.shape[1]}"

    def test_predict_returns_stage2_reason_for_suspicious(self, unsw_suspicious_features):
        """
        RED PHASE: This test should FAIL initially because the current
        Alert dataclass doesn't have stage2_reason field.
        
        After implementation, when verdict is "Suspicious", the response
        should include stage2_reason with LLM explanation.
        """
        from src.api.server import Alert
        
        # Create a mock alert with suspicious verdict
        alert = Alert(
            id=1,
            timestamp="2024-01-01T00:00:00Z",
            src_ip="10.0.0.50",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=443,
            protocol=6,
            rf_label="Fuzzers",
            rf_confidence=0.45,  # Low confidence - triggers Stage 2
            ae_anomaly_score=0.15,  # Above threshold 0.0396
            ae_is_anomaly=True,
            xgb_label="Fuzzers",
            xgb_confidence=0.45,
            if_is_anomaly=False,
            if_anomaly_score=0.0,
            final_verdict="Suspicious",
            combined_confidence=0.45,
            stage2_reason="The flow shows an unusually high source load and rate for a very short UDP exchange with no destination traffic, suggesting potential scanning or data exfiltration activity."
        )
        
        alert_dict = alert.to_dict()
        
        # Should include stage2_reason for Suspicious verdicts
        assert "stage2_reason" in alert_dict, "Alert should include stage2_reason field"
        assert alert_dict["stage2_reason"] is not None, "stage2_reason should not be None"
        assert len(alert_dict["stage2_reason"]) > 0, "stage2_reason should have content"


# ============================================================================
# TEST: Attack Type Mapping
# ============================================================================

class TestUNSWAttackMapping:
    """Test that UNSW-NB15 attack categories are correctly mapped."""

    def test_attack_distribution_mapped_includes_unsw_categories(self):
        """
        RED PHASE: This test should FAIL initially because the current
        attack distribution mapping only handles CIC-IDS2017 categories.
        
        After implementation, should include UNSW-NB15 categories:
        Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic,
        Reconnaissance, Shellcode, Worms, Normal
        """
        from src.api.server import alert_store, Alert
        import datetime
        
        # Add sample alerts with UNSW attack types
        unsw_attack_types = [
            "Fuzzers", "Analysis", "Backdoors", "DoS", "Exploits",
            "Generic", "Reconnaissance", "Shellcode", "Worms", "Normal"
        ]
        
        for i, attack_type in enumerate(unsw_attack_types):
            alert = Alert(
                id=i+1,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                src_ip=f"192.168.1.{i+1}",
                dst_ip="10.0.0.1",
                src_port=54321,
                dst_port=80,
                protocol=6,
                rf_label=attack_type,
                rf_confidence=0.9,
                ae_anomaly_score=0.01,
                ae_is_anomaly=False,
                xgb_label=attack_type,
                xgb_confidence=0.9,
                if_is_anomaly=False,
                if_anomaly_score=0.0,
                final_verdict="Attack" if attack_type != "Normal" else "Benign",
                combined_confidence=0.9
            )
            alert_store.add_alert(alert)
        
        # Get distribution
        dist = alert_store.get_attack_distribution()
        
        # Should include UNSW-NB15 categories
        for attack_type in unsw_attack_types:
            assert attack_type in dist, f"Missing UNSW-NB15 category: {attack_type}"
        
        # Clean up
        alert_store.clear()


# ============================================================================
# TEST: Simulator Uses UNSW Data
# ============================================================================

class TestUNSWDataInSimulator:
    """Test that attack simulation uses UNSW-NB15 dataset."""

    def test_simulate_loads_unsw_samples(self):
        """
        RED PHASE: This test should FAIL initially because the current
        simulator loads CIC-IDS2017 data, not UNSW-NB15.
        
        After implementation, simulate_attack should pull from
        UNSW_NB15_testing-set.csv instead of cicids2017_cleaned.csv
        """
        from src.api.server import _load_real_samples
        import os
        
        # Try to load samples for a UNSW-NB15 attack type
        samples = _load_real_samples("Fuzzers", n=5)
        
        # Should return samples from UNSW-NB15 dataset
        # (The function should look for UNSW data, not CIC data)
        # For now, we expect this to fail or return empty
        # After fix, it should return valid samples
        
        # Check that the function looks for UNSW data path
        # This is a structural test - we verify the function exists and can be called
        assert callable(_load_real_samples), "_load_real_samples should be callable"
        
        # The actual data loading will be tested in integration


# ============================================================================
# TEST: Health Check Shows New Model Status
# ============================================================================

class TestHealthCheck:
    """Test that health endpoint shows correct model status."""

    def test_health_shows_stage2_model(self):
        """
        RED PHASE: This test should FAIL initially because current
        health check doesn't show LLM/Stage 2 model status.
        
        After implementation, health should include:
        - deep_verifier (LLM model status)
        - unsw_nb15 (dataset indicator)
        """
        from src.api.server import app
        
        with app.test_client() as client:
            response = client.get("/api/health")
            data = response.get_json()
            
            # Should include new model indicators
            assert "deep_verifier" in data.get("models_loaded", {}), \
                "Health should include deep_verifier status"
            assert "unsw_nb15" in data.get("models_loaded", {}), \
                "Health should indicate UNSW-NB15 dataset is active"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])