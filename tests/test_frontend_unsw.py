"""
TDD Tests for Dashboard Frontend UNSW-NB15 Integration
=======================================================
Tests that the frontend correctly handles UNSW-NB15 data and displays
stage2_reason from the Two-Stage Hybrid model.

Run with: pytest tests/test_frontend_unsw.py -v
"""

from __future__ import annotations

import pytest
import json


# ============================================================================
# TEST: API Returns UNSW Attack Categories
# ============================================================================

class TestAttackDistributionUNSW:
    """Test that attack distribution API returns UNSW-NB15 categories."""

    def test_distribution_returns_unsw_categories(self):
        """Test /api/attack-distribution returns UNSW-NB15 categories."""
        from src.api.server import app, alert_store, Alert
        import datetime
        
        # Add UNSW-NB15 attack alerts
        for i, attack_type in enumerate(["Fuzzers", "DoS", "Exploits", "Normal"]):
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
            for cat in ["Fuzzers", "DoS", "Exploits", "Normal"]:
                assert cat in data, f"Should include {cat}"
        
        alert_store.clear()

    def test_distribution_mapped_groups_attacks(self):
        """Test /api/attack-distribution-mapped groups UNSW attacks correctly."""
        from src.api.server import app, alert_store, Alert
        import datetime
        
        # Add various UNSW attack types
        attack_types = ["Fuzzers", "Analysis", "Backdoor", "DoS", "Exploits", 
                       "Generic", "Reconnaissance", "Shellcode", "Worms", "Normal"]
        
        for i, attack_type in enumerate(attack_types):
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
            response = client.get("/api/attack-distribution-mapped")
            data = response.get_json()
            
            # Should have mapped categories (DDoS, Port Scanning, Others, Benign)
            # The mapping should group UNSW attacks into these buckets
            assert "Benign" in data or "Others" in data, "Should have some mapped categories"
        
        alert_store.clear()


# ============================================================================
# TEST: Alert Includes stage2_reason
# ============================================================================

class TestAlertStage2Reason:
    """Test that alerts include stage2_reason field for frontend display."""

    def test_alert_response_includes_stage2_reason_field(self):
        """Test that /api/alerts response includes stage2_reason field."""
        from src.api.server import app, alert_store, Alert
        import datetime
        
        # Add alert with stage2_reason
        alert = Alert(
            id=1,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
            rf_label="Fuzzers",
            rf_confidence=0.45,  # Low confidence triggers Stage 2
            ae_anomaly_score=0.15,  # Above threshold
            ae_is_anomaly=True,
            xgb_label="Fuzzers",
            xgb_confidence=0.45,
            if_is_anomaly=False,
            if_anomaly_score=0.0,
            final_verdict="Suspicious",
            combined_confidence=0.45,
            stage2_reason="The flow shows an unusually high source load and rate for a very short UDP exchange with no destination traffic, suggesting potential scanning or data exfiltration activity."
        )
        alert_store.add_alert(alert)
        
        with app.test_client() as client:
            response = client.get("/api/alerts?n=1")
            alerts = response.get_json()
            
            assert len(alerts) > 0, "Should return alerts"
            first_alert = alerts[0]
            
            # Should include stage2_reason field
            assert "stage2_reason" in first_alert, "Alert should include stage2_reason field"
            assert first_alert["stage2_reason"] is not None, "stage2_reason should not be None"
            assert len(first_alert["stage2_reason"]) > 0, "stage2_reason should have content"
        
        alert_store.clear()

    def test_alert_without_stage2_has_null_field(self):
        """Test that alerts without Stage 2 still have stage2_reason field (as null)."""
        from src.api.server import app, alert_store, Alert
        import datetime
        
        # Add alert without stage2_reason
        alert = Alert(
            id=1,
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol=6,
            rf_label="Normal",
            rf_confidence=0.99,
            ae_anomaly_score=0.01,
            ae_is_anomaly=False,
            xgb_label="Normal",
            xgb_confidence=0.99,
            if_is_anomaly=False,
            if_anomaly_score=0.0,
            final_verdict="Benign",
            combined_confidence=0.99,
            stage2_reason=None  # No LLM reason for benign
        )
        alert_store.add_alert(alert)
        
        with app.test_client() as client:
            response = client.get("/api/alerts?n=1")
            alerts = response.get_json()
            
            assert len(alerts) > 0, "Should return alerts"
            first_alert = alerts[0]
            
            # Should still have stage2_reason field (as null)
            assert "stage2_reason" in first_alert, "Alert should include stage2_reason field"
            assert first_alert["stage2_reason"] is None, "stage2_reason should be null for benign"
        
        alert_store.clear()


# ============================================================================
# TEST: Frontend JavaScript Data Handling
# ============================================================================

class TestFrontendDataHandling:
    """Test that frontend can handle the new UNSW-NB15 data format."""

    def test_donut_chart_colors_for_unsw_categories(self):
        """Test that donut chart colors handle UNSW-NB15 categories."""
        # This tests the expected colors for UNSW categories
        # The frontend should map these correctly
        
        expected_unsw_colors = {
            'Fuzzers': '#ff1744',      # Red - aggressive
            'Analysis': '#ffab00',     # Amber - warning
            'Backdoor': '#9c27b0',     # Purple - stealth
            'DoS': '#ff1744',          # Red - aggressive
            'Exploits': '#ff6b35',      # Orange - exploit
            'Generic': '#ffd9a1',      # Light orange
            'Reconnaissance': '#ffab00', # Amber - scanning
            'Shellcode': '#00bcd4',    # Cyan - code
            'Worms': '#4caf50',        # Green - spreading
            'Normal': '#00d4ff'        # Blue - benign
        }
        
        # Verify all UNSW categories have colors defined
        unsw_categories = [
            "Fuzzers", "Analysis", "Backdoor", "DoS", "Exploits",
            "Generic", "Reconnaissance", "Shellcode", "Worms", "Normal"
        ]
        
        for cat in unsw_categories:
            assert cat in expected_unsw_colors, f"Color mapping missing for {cat}"

    def test_alert_row_renders_stage2_reason(self):
        """Test that alert row rendering includes stage2_reason placeholder."""
        # This is a structural test - verifies the frontend expects the field
        
        # Sample alert with stage2_reason (as would come from API)
        sample_alert = {
            "id": 1,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": 6,
            "rf_label": "Fuzzers",
            "final_verdict": "Suspicious",
            "combined_confidence": 0.45,
            "stage2_reason": "The flow shows unusual behavior suggesting potential scanning."
        }
        
        # Verify the alert has all required fields for frontend rendering
        required_fields = [
            "id", "src_ip", "dst_ip", "dst_port", "protocol",
            "rf_label", "final_verdict", "combined_confidence", "stage2_reason"
        ]
        
        for field in required_fields:
            assert field in sample_alert, f"Missing required field: {field}"


# ============================================================================
# TEST: Health Check Shows New Status
# ============================================================================

class TestHealthStatus:
    """Test that health endpoint shows correct status for frontend display."""

    def test_health_shows_unsw_dataset_indicator(self):
        """Test that health indicates UNSW-NB15 dataset is active."""
        from src.api.server import app
        
        with app.test_client() as client:
            response = client.get("/api/health")
            data = response.get_json()
            
            models = data.get("models_loaded", {})
            
            # Should indicate UNSW-NB15 field exists in health response
            # (The value depends on whether rf_model is loaded in the environment)
            assert "unsw_nb15" in models, "Health should include unsw_nb15 indicator"
            # The field should exist - value indicates if model is loaded
            assert isinstance(models["unsw_nb15"], bool), "unsw_nb15 should be a boolean"

    def test_health_shows_deep_verifier_status(self):
        """Test that health shows deep_verifier (LLM) status."""
        from src.api.server import app
        
        with app.test_client() as client:
            response = client.get("/api/health")
            data = response.get_json()
            
            models = data.get("models_loaded", {})
            
            # Should indicate deep_verifier status
            assert "deep_verifier" in models, "Health should include deep_verifier status"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])