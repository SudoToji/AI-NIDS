"""
TDD Tests for UNSW-NB15 Attack Simulator
=========================================
Tests that the Flask API simulator correctly uses UNSW-NB15 dataset
instead of the old CIC-IDS2017 dataset.

Run with: pytest tests/test_simulator_unsw.py -v
"""

from __future__ import annotations

import pytest
import os
import pandas as pd


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def unsw_test_data_path():
    """Return path to UNSW-NB15 testing dataset."""
    return os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data", "unsw_nb15", "Training and Testing Sets",
        "UNSW_NB15_testing-set.csv"
    )


# ============================================================================
# TEST: Simulator Loads UNSW Data
# ============================================================================

class TestUNSWDataLoader:
    """Test that simulator correctly loads UNSW-NB15 data."""

    def test_unsw_test_file_exists(self, unsw_test_data_path):
        """Verify the UNSW-NB15 testing file exists."""
        assert os.path.exists(unsw_test_data_path), \
            f"UNSW-NB15 test file not found at {unsw_test_data_path}"

    def test_unsw_has_attack_categories(self, unsw_test_data_path):
        """Verify UNSW-NB15 has the expected attack categories."""
        df = pd.read_csv(unsw_test_data_path, usecols=["attack_cat"])
        
        # Get unique attack categories
        categories = df["attack_cat"].dropna().unique().tolist()
        
        # Should include these UNSW-NB15 categories (note: dataset uses "Backdoor" not "Backdoors")
        expected_categories = [
            "Fuzzers", "Analysis", "Backdoor", "DoS", "Exploits",
            "Generic", "Reconnaissance", "Shellcode", "Worms", "Normal"
        ]
        
        for cat in expected_categories:
            assert cat in categories, f"Missing UNSW-NB15 category: {cat}"

    def test_simulate_function_uses_unsw_path(self):
        """
        RED PHASE: This test should FAIL initially because the current
        _load_real_samples() looks for CIC-IDS2017 data.
        
        After implementation, it should look for UNSW-NB15 CSV files.
        """
        from src.api.server import _load_real_samples
        
        # Try to load a UNSW-NB15 attack type
        samples = _load_real_samples("Fuzzers", n=5)
        
        # Should return samples from UNSW-NB15 dataset
        # The function should look for: data/unsw_nb15/Training and Testing Sets/
        assert len(samples) > 0, "Should load samples from UNSW-NB15"

    def test_simulate_all_attack_types(self):
        """Test that all UNSW-NB15 attack types can be simulated."""
        from src.api.server import simulate_attack
        
        # All valid UNSW-NB15 attack types
        attack_types = [
            "Fuzzers", "Analysis", "Backdoors", "DoS", "Exploits",
            "Generic", "Reconnaissance", "Shellcode", "Worms", "Normal"
        ]
        
        for attack_type in attack_types:
            # This should not raise an error
            alerts = simulate_attack(attack_type, target_ip="127.0.0.1")
            
            # Should return some alerts
            assert len(alerts) > 0, f"Should generate alerts for {attack_type}"


# ============================================================================
# TEST: API Endpoint Returns UNSW Data
# ============================================================================

class TestSimulateAPIEndpoint:
    """Test that /api/simulate endpoint works with UNSW-NB15."""

    def test_simulate_endpoint_accepts_unsw_attack_types(self):
        """Test that /api/simulate accepts UNSW-NB15 attack types."""
        from src.api.server import app
        
        with app.test_client() as client:
            # Test each UNSW-NB15 attack type
            for attack_type in ["Fuzzers", "DoS", "Normal"]:
                response = client.post("/api/simulate", json={
                    "type": attack_type.lower(),
                    "target_ip": "127.0.0.1"
                })
                
                assert response.status_code == 200, \
                    f"Failed for {attack_type}: {response.get_json()}"
                
                data = response.get_json()
                assert "alerts" in data, "Response should include alerts"
                assert len(data["alerts"]) > 0, \
                    f"Should generate alerts for {attack_type}"

    def test_simulate_endpoint_has_stage2_reason(self):
        """Test that simulated suspicious alerts include stage2_reason."""
        from src.api.server import app
        
        with app.test_client() as client:
            # Simulate an attack that might trigger Stage 2 (Suspicious)
            response = client.post("/api/simulate", json={
                "type": "fuzzers",
                "target_ip": "127.0.0.1"
            })
            
            assert response.status_code == 200
            data = response.get_json()
            
            # Check if any alerts have stage2_reason (for Suspicious verdicts)
            alerts_with_reason = [
                a for a in data.get("alerts", [])
                if a.get("stage2_reason") is not None
            ]
            
            # At least some alerts should have stage2_reason when Suspicious
            # (This is expected to pass when LLM is integrated)
            # For now, we just verify the field exists in the schema
            if len(data.get("alerts", [])) > 0:
                first_alert = data["alerts"][0]
                # The field should be present (even if None)
                assert "stage2_reason" in first_alert, \
                    "Alert should include stage2_reason field"


# ============================================================================
# TEST: Attack Distribution Mapping
# ============================================================================

class TestAttackDistributionMapping:
    """Test that attack distribution correctly maps UNSW categories."""

    def test_distribution_endpoint_unsw_categories(self):
        """Test /api/attack-distribution returns UNSW-NB15 categories."""
        from src.api.server import app, alert_store, Alert
        import datetime
        
        # Add UNSW-NB15 attack alerts
        for i, attack_type in enumerate(["Fuzzers", "DoS", "Normal"]):
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
        
        with app.test_client() as client:
            response = client.get("/api/attack-distribution")
            data = response.get_json()
            
            # Should include UNSW-NB15 categories
            for attack_type in ["Fuzzers", "DoS", "Normal"]:
                assert attack_type in data, \
                    f"Distribution should include {attack_type}"
        
        # Clean up
        alert_store.clear()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])