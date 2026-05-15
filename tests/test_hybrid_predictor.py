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
)


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
            stage2_reason="Verified by LLM"
        )
        
        assert pred.rf_label == "DDoS"
        assert pred.rf_confidence == 0.95
        assert pred.final_verdict == Verdict.ATTACK
        assert pred.stage2_reason == "Verified by LLM"

    def test_immutable(self):
        pred = HybridPrediction(
            rf_label="Benign",
            rf_confidence=0.8,
            ae_anomaly_score=0.1,
            ae_is_anomaly=False,
            final_verdict=Verdict.BENIGN,
            combined_confidence=0.8,
            timestamp="2024-01-01T00:00:00",
            stage2_reason=None
        )
        
        with pytest.raises(AttributeError):
            pred.rf_label = "DDoS"


class TestHybridPredictor:
    """Test HybridPredictor class."""

    def test_compute_fusion_highly_confident_normal(self):
        """Test fusion: 99% confident normal + normal AE -> BENIGN."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="Normal",
            rf_confidence=0.99,
            xgb_label="Normal",
            xgb_confidence=0.99,
            ae_is_anomaly=False,
            if_is_anomaly=False,
        )
        
        assert verdict == Verdict.BENIGN

    def test_compute_fusion_highly_confident_attack(self):
        """Test fusion: 99% confident attack -> ATTACK."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="DDoS",
            rf_confidence=0.99,
            xgb_label="DDoS",
            xgb_confidence=0.95,
            ae_is_anomaly=True,
            if_is_anomaly=False,
        )
        
        assert verdict == Verdict.ATTACK

    def test_compute_fusion_low_confidence_suspicious(self):
        """Test fusion: RF confidence < 0.90 -> SUSPICIOUS."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="Normal",
            rf_confidence=0.85,
            xgb_label="Normal",
            xgb_confidence=0.85,
            ae_is_anomaly=False,
            if_is_anomaly=False,
        )
        
        assert verdict == Verdict.SUSPICIOUS

    def test_compute_fusion_ae_anomaly_suspicious(self):
        """Test fusion: RF says Normal 99% but AE anomaly -> SUSPICIOUS."""
        predictor = HybridPredictor.__new__(HybridPredictor)
        
        verdict, confidence = predictor._compute_fusion(
            rf_label="Normal",
            rf_confidence=0.99,
            xgb_label="Normal",
            xgb_confidence=0.99,
            ae_is_anomaly=True,
            if_is_anomaly=False,
        )
        
        assert verdict == Verdict.SUSPICIOUS


class TestPredictorIntegration:
    """Integration tests with mocked models."""

    @pytest.fixture
    def predictor_with_mocks(self):
        """Create predictor with mocked internal components."""
        with patch("src.models.hybrid_predictor.joblib.load") as joblib_mock, \
             patch("src.models.hybrid_predictor.keras.models.load_model") as ae_mock:
            
            rf_model = MagicMock()
            rf_model.predict_proba.return_value = np.array([[0.5, 0.5]])
            joblib_mock.side_effect = [
                rf_model,  # RF model
                {"class_labels": ["Benign", "Attack"]},  # RF metadata
                MagicMock(),  # Scaler
            ]
            
            ae_model = MagicMock()
            ae_model.input_shape = (None, 52)
            ae_mock.return_value = ae_model
            
            # Mock threshold file
            with patch("os.path.exists", return_value=True), \
                 patch("numpy.load", return_value=np.array([0.1])):
                
                predictor = HybridPredictor(
                    rf_model_path="dummy.pkl",
                    rf_metadata_path="dummy_meta.pkl",
                    ae_model_path="dummy.keras",
                    ae_threshold_path="dummy_thresh.npy",
                    scaler_path="dummy_scaler.pkl",
                )
                
                predictor._rf_model = rf_model
                predictor._class_labels = ["Benign", "Attack"]
                predictor._input_dim = 52
                predictor._scaler = MagicMock()
                predictor._scaler.transform.return_value = np.zeros((1, 52), dtype=np.float32)
                predictor._ae_model = ae_model
                predictor._ae_threshold = 0.1
                
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
            assert result.final_verdict == Verdict.SUSPICIOUS

    @patch("src.models.deep_verifier.DeepVerifier")
    def test_predict_triggers_stage_2_on_suspicious(self, mock_verifier_class, predictor_with_mocks):
        """Test that Stage 2 is triggered when Stage 1 says SUSPICIOUS."""
        predictor = predictor_with_mocks
        predictor.use_stage2 = True
        
        mock_verifier_instance = MagicMock()
        mock_verifier_instance.verify_flow.return_value = (Verdict.ATTACK, "Confirmed by LLM")
        predictor.verifier = mock_verifier_instance
        
        with patch.object(predictor, "_compute_fusion") as fusion_mock, \
             patch.object(predictor, "_predict_rf") as rf_mock, \
             patch.object(predictor, "_predict_autoencoder") as ae_mock:
            
            fusion_mock.return_value = (Verdict.SUSPICIOUS, 0.8)
            rf_mock.return_value = ("Normal", 0.8)
            ae_mock.return_value = (0.5, True)
            
            sample = np.random.randn(1, 52).astype(np.float32)
            result = predictor.predict(sample)
            
            assert result.final_verdict == Verdict.ATTACK
            assert result.stage2_reason == "Confirmed by LLM"
            mock_verifier_instance.verify_flow.assert_called_once()
            
    @patch("src.models.deep_verifier.DeepVerifier")
    def test_predict_skips_stage_2_on_confident(self, mock_verifier_class, predictor_with_mocks):
        """Test that Stage 2 is skipped when Stage 1 is confident."""
        predictor = predictor_with_mocks
        predictor.use_stage2 = True
        
        mock_verifier_instance = MagicMock()
        predictor.verifier = mock_verifier_instance
        
        with patch.object(predictor, "_compute_fusion") as fusion_mock, \
             patch.object(predictor, "_predict_rf") as rf_mock, \
             patch.object(predictor, "_predict_autoencoder") as ae_mock:
            
            fusion_mock.return_value = (Verdict.ATTACK, 0.99)
            rf_mock.return_value = ("DDoS", 0.99)
            ae_mock.return_value = (0.5, True)
            
            sample = np.random.randn(1, 52).astype(np.float32)
            result = predictor.predict(sample)
            
            assert result.final_verdict == Verdict.ATTACK
            assert result.stage2_reason is None
            mock_verifier_instance.verify_flow.assert_not_called()

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
