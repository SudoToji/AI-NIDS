"""Tests for Hybrid Predictor."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models.hybrid_predictor import (
    HybridPredictor,
    HybridPrediction,
    Verdict,
    _load_autoencoder,
    _load_rf_model,
    _load_rf_metadata,
    _load_scaler,
)


@pytest.fixture
def mock_model_dir(tmp_path, monkeypatch):
    """Create temporary model files for testing."""
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    
    monkeypatch.chdir(tmp_path)
    
    return model_dir


class TestVerdictConstants:
    """Test Verdict class constants."""

    def test_verdict_constants(self):
        assert Verdict.BENIGN == "Benign"
        assert Verdict.SUSPICIOUS == "Suspicious"
        assert Verdict.ATTACK == "Attack"


class TestHybridPrediction:
    """Test HybridPrediction dataclass."""

    def test_creation(self):
        pred = HybridPrediction(
            rf_label="DDoS",
            rf_confidence=0.95,
            ae_anomaly_score=0.5,
            ae_is_anomaly=True,
            final_verdict=Verdict.ATTACK,
            combined_confidence=0.9,
            timestamp="2024-01-01T00:00:00",
        )
        
        assert pred.rf_label == "DDoS"
        assert pred.rf_confidence == 0.95
        assert pred.final_verdict == Verdict.ATTACK

    def test_immutable(self):
        pred = HybridPrediction(
            rf_label="Benign",
            rf_confidence=0.8,
            ae_anomaly_score=0.1,
            ae_is_anomaly=False,
            final_verdict=Verdict.BENIGN,
            combined_confidence=0.8,
            timestamp="2024-01-01T00:00:00",
        )
        
        with pytest.raises(AttributeError):
            pred.rf_label = "DDoS"


class TestHybridPredictor:
    """Test HybridPredictor class."""

    def test_compute_fusion_both_attack(self):
        """Test fusion when both models detect attack."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="DDoS",
            rf_confidence=0.9,
            ae_is_anomaly=True,
        )
        
        assert verdict == Verdict.ATTACK
        assert confidence == pytest.approx(0.95)

    def test_compute_fusion_both_benign(self):
        """Test fusion when both models detect benign."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="Normal Traffic",
            rf_confidence=0.85,
            ae_is_anomaly=False,
        )
        
        assert verdict == Verdict.BENIGN
        assert confidence == 0.85

    def test_compute_fusion_suspicious_rf_attack(self):
        """Test fusion when only RF detects attack."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="DDoS",
            rf_confidence=0.9,
            ae_is_anomaly=False,
        )
        
        assert verdict == Verdict.SUSPICIOUS
        assert confidence == pytest.approx(0.7)

    def test_compute_fusion_suspicious_ae_anomaly(self):
        """Test fusion when only AE detects anomaly."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="Normal Traffic",
            rf_confidence=0.8,
            ae_is_anomaly=True,
        )
        
        assert verdict == Verdict.SUSPICIOUS
        assert confidence == pytest.approx(0.65)


class TestPredictorIntegration:
    """Integration tests with mocked models."""

    @pytest.fixture
    def predictor_with_mocks(self):
        """Create predictor with mocked internal components."""
        with patch("src.models.hybrid_predictor._load_rf_model") as rf_mock, \
             patch("src.models.hybrid_predictor._load_rf_metadata") as meta_mock, \
             patch("src.models.hybrid_predictor._load_autoencoder") as ae_mock, \
             patch("src.models.hybrid_predictor._load_scaler") as scaler_mock:
            
            rf_mock.return_value = MagicMock()
            meta_mock.return_value = {
                "class_labels": ["Benign", "Attack"],
                "thresholds": {},
            }
            
            ae_model = MagicMock()
            ae_model.input_shape = (None, 52)
            ae_mock.return_value = (ae_model, 0.1)
            
            scaler_mock.return_value = MagicMock()
            
            predictor = HybridPredictor(
                rf_model_path="dummy.pkl",
                rf_metadata_path="dummy_meta.pkl",
                ae_model_path="dummy.keras",
                ae_threshold_path="dummy_thresh.npy",
                scaler_path="dummy_scaler.pkl",
            )
            
            predictor._class_labels = ["Benign", "Attack"]
            predictor._input_dim = 52
            
            return predictor

    def test_predict_with_array(self, predictor_with_mocks):
        """Test prediction with numpy array input."""
        predictor = predictor_with_mocks
        
        with patch.object(predictor, "_predict_rf") as rf_mock, \
             patch.object(predictor, "_predict_autoencoder") as ae_mock:
            
            rf_mock.return_value = ("Attack", 0.9)
            ae_mock.return_value = (0.5, True)
            
            sample = np.random.randn(1, 52).astype(np.float32)
            result = predictor.predict(sample)
            
            assert result.rf_label == "Attack"
            assert result.rf_confidence == 0.9
            assert result.final_verdict == Verdict.ATTACK

    def test_predict_dimension_mismatch(self, predictor_with_mocks):
        """Test prediction raises on dimension mismatch."""
        predictor = predictor_with_mocks
        
        sample = np.random.randn(1, 10).astype(np.float32)
        
        with pytest.raises(ValueError, match="Feature dimension mismatch"):
            predictor.predict(sample)

    def test_predict_1d_array_reshaping(self, predictor_with_mocks):
        """Test 1D array gets reshaped correctly."""
        predictor = predictor_with_mocks
        
        with patch.object(predictor, "_predict_rf") as rf_mock, \
             patch.object(predictor, "_predict_autoencoder") as ae_mock:
            
            rf_mock.return_value = ("Benign", 0.95)
            ae_mock.return_value = (0.01, False)
            
            sample = np.random.randn(52).astype(np.float32)
            result = predictor.predict(sample)
            
            assert result.rf_label == "Benign"
            rf_mock.assert_called_once()
