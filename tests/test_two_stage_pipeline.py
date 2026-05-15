"""Test the 2-stage pipeline: Stage 1 (ML) → Stage 2 (LLM) → Final Verdict."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models.hybrid_predictor import HybridPredictor, HybridPrediction, Verdict
from src.models.deep_verifier import DeepVerifier


class TestDeepVerifierUnit:
    """Test DeepVerifier in isolation (no real API)."""

    def test_format_prompt(self):
        """Test that features are formatted into a readable prompt."""
        verifier = DeepVerifier(api_key="dummy")
        features = {"src_ip": "10.0.0.1", "dst_port": 443, "proto": "tcp", "dur": 0.5}
        prompt = verifier._format_prompt(features, "Suspicious")

        assert "Suspicious" in prompt
        assert "src_ip" in prompt
        assert "443" in prompt
        assert "tcp" in prompt

    def test_verify_flow_api_error_fallback(self):
        """Test that API errors gracefully fall back to Stage 1 verdict."""
        verifier = DeepVerifier(api_key="invalid-key")
        features = {"src_ip": "10.0.0.1", "dst_port": 80, "proto": "tcp"}

        # With invalid key, the API will fail → should fall back
        verdict, reason = verifier.verify_flow(features, Verdict.SUSPICIOUS)

        assert verdict == Verdict.SUSPICIOUS
        assert "Failed" in reason or "API Error" in reason

    def test_verify_flow_mock_success(self):
        """Test successful LLM response parsing."""
        verifier = DeepVerifier(api_key="dummy")

        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"verdict": "Attack", "reason": "High packet rate indicates DDoS."}'

        with patch.object(verifier.client.chat.completions, "create", return_value=mock_response):
            features = {"src_ip": "10.0.0.1", "dst_port": 80, "proto": "tcp", "dur": 0.01}
            verdict, reason = verifier.verify_flow(features, "Suspicious")

            assert verdict == Verdict.ATTACK
            assert "DDoS" in reason

    def test_verify_flow_mock_benign(self):
        """Test LLM verdict maps to Benign."""
        verifier = DeepVerifier(api_key="dummy")

        mock_response = MagicMock()
        mock_response.choices[0].message.content = '{"verdict": "Benign", "reason": "Normal web browsing pattern."}'

        with patch.object(verifier.client.chat.completions, "create", return_value=mock_response):
            features = {"src_ip": "10.0.0.1", "dst_port": 443, "proto": "tcp"}
            verdict, reason = verifier.verify_flow(features, "Suspicious")

            assert verdict == Verdict.BENIGN
            assert "browsing" in reason

    def test_verify_flow_mock_invalid_json(self):
        """Test that invalid JSON response falls back safely."""
        verifier = DeepVerifier(api_key="dummy")

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "not json at all"

        with patch.object(verifier.client.chat.completions, "create", return_value=mock_response):
            features = {"src_ip": "10.0.0.1"}
            verdict, reason = verifier.verify_flow(features, "Suspicious")

            # Should fall back to Stage 1 verdict
            assert verdict == "Suspicious"


class TestTwoStagePipeline:
    """Test the full 2-stage pipeline: ML → LLM → Final result."""

    @pytest.fixture
    def mock_predictor(self):
        """Create a HybridPredictor with all models mocked + Stage 2 enabled."""
        with patch("src.models.hybrid_predictor.joblib.load") as joblib_mock, \
             patch("src.models.hybrid_predictor.keras.models.load_model") as ae_mock:

            rf_model = MagicMock()
            rf_model.predict_proba.return_value = np.array([[0.85, 0.15]])  # Low confidence → triggers Stage 2
            joblib_mock.side_effect = [
                rf_model,  # RF model
                {"class_labels": ["Normal", "Attack"]},  # RF metadata
                MagicMock(),  # Scaler
            ]

            ae_model = MagicMock()
            ae_model.input_shape = (None, 52)
            ae_mock.return_value = ae_model

            with patch("os.path.exists", return_value=True), \
                 patch("numpy.load", return_value=np.array([0.1])):

                predictor = HybridPredictor(use_stage2=True)
                predictor._rf_model = rf_model
                predictor._class_labels = ["Normal", "Attack"]
                predictor._input_dim = 52
                predictor._scaler = MagicMock()
                predictor._scaler.transform.return_value = np.zeros((1, 52), dtype=np.float32)
                predictor._ae_model = ae_model
                predictor._ae_threshold = 0.1

                # Mock the verifier
                predictor.verifier = MagicMock()
                predictor.use_stage2 = True

                return predictor

    def test_stage_1_suspicious_triggers_stage_2(self, mock_predictor):
        """When Stage 1 says SUSPICIOUS, Stage 2 (LLM) is called."""
        with patch.object(mock_predictor, "_predict_rf") as rf_mock, \
             patch.object(mock_predictor, "_predict_autoencoder") as ae_mock:

            # Stage 1: low confidence → SUSPICIOUS
            rf_mock.return_value = ("Normal", 0.85)
            ae_mock.return_value = (0.5, True)  # AE anomaly

            mock_predictor.verifier.verify_flow.return_value = (Verdict.ATTACK, "Confirmed DDoS pattern")

            sample = np.random.randn(1, 52).astype(np.float32)
            result = mock_predictor.predict(sample)

            # Verify Stage 2 was called
            mock_predictor.verifier.verify_flow.assert_called_once()
            assert result.final_verdict == Verdict.ATTACK
            assert result.stage2_reason == "Confirmed DDoS pattern"
            assert result.rf_label == "Normal"  # Stage 1 said Normal
            assert result.rf_confidence == 0.85

    def test_stage_1_confident_attack_skips_stage_2(self, mock_predictor):
        """When Stage 1 is confident it's an ATTACK, Stage 2 is skipped."""
        with patch.object(mock_predictor, "_predict_rf") as rf_mock, \
             patch.object(mock_predictor, "_predict_autoencoder") as ae_mock:

            # Stage 1: high confidence attack
            rf_mock.return_value = ("Attack", 0.99)
            ae_mock.return_value = (0.5, True)

            sample = np.random.randn(1, 52).astype(np.float32)
            result = mock_predictor.predict(sample)

            # Stage 2 should NOT be called
            mock_predictor.verifier.verify_flow.assert_not_called()
            assert result.final_verdict == Verdict.ATTACK
            assert result.stage2_reason is None

    def test_stage_1_confident_benign_skips_stage_2(self, mock_predictor):
        """When Stage 1 is confident it's BENIGN, Stage 2 is skipped."""
        with patch.object(mock_predictor, "_predict_rf") as rf_mock, \
             patch.object(mock_predictor, "_predict_autoencoder") as ae_mock:

            # Stage 1: high confidence benign, no AE anomaly
            rf_mock.return_value = ("Normal", 0.99)
            ae_mock.return_value = (0.01, False)

            sample = np.random.randn(1, 52).astype(np.float32)
            result = mock_predictor.predict(sample)

            # Stage 2 should NOT be called
            mock_predictor.verifier.verify_flow.assert_not_called()
            assert result.final_verdict == Verdict.BENIGN
            assert result.stage2_reason is None

    def test_stage_2_fallback_on_api_error(self, mock_predictor):
        """When Stage 2 API fails, verdict falls back to Stage 1."""
        with patch.object(mock_predictor, "_predict_rf") as rf_mock, \
             patch.object(mock_predictor, "_predict_autoencoder") as ae_mock:

            rf_mock.return_value = ("Normal", 0.85)
            ae_mock.return_value = (0.5, True)

            # Simulate API error
            mock_predictor.verifier.verify_flow.return_value = (
                Verdict.SUSPICIOUS,
                "Stage 2 Verification Failed (API Error: timeout). Falling back to Stage 1."
            )

            sample = np.random.randn(1, 52).astype(np.float32)
            result = mock_predictor.predict(sample)

            assert result.final_verdict == Verdict.SUSPICIOUS
            assert "Failed" in result.stage2_reason

    def test_stage_2_overrides_stage_1(self, mock_predictor):
        """Stage 2 can override Stage 1's verdict."""
        with patch.object(mock_predictor, "_predict_rf") as rf_mock, \
             patch.object(mock_predictor, "_predict_autoencoder") as ae_mock:

            # Stage 1 says SUSPICIOUS (low confidence Normal + AE anomaly)
            rf_mock.return_value = ("Normal", 0.85)
            ae_mock.return_value = (0.5, True)

            # Stage 2 says it's actually BENIGN
            mock_predictor.verifier.verify_flow.return_value = (Verdict.BENIGN, "Normal traffic pattern")

            sample = np.random.randn(1, 52).astype(np.float32)
            result = mock_predictor.predict(sample)

            assert result.final_verdict == Verdict.BENIGN
            assert result.stage2_reason == "Normal traffic pattern"
            assert mock_predictor.verifier.verify_flow.call_count == 1


class TestTwoStageEndToEnd:
    """End-to-end test with real models but mocked LLM."""

    def test_full_pipeline_with_real_models_mocked_llm(self):
        """Test the full pipeline: real RF + AE → mocked LLM → final verdict."""
        # Skip if model files don't exist (e.g., not trained yet)
        model_path = os.path.join(os.path.dirname(__file__), "..", "models", "rf_model.pkl")
        if not os.path.exists(model_path):
            pytest.skip("Model files not found - run training first")

        with patch("src.models.deep_verifier.OpenAI") as mock_openai:
            # Mock LLM response
            mock_response = MagicMock()
            mock_response.choices[0].message.content = '{"verdict": "Attack", "reason": "High packet rate and short IAT indicate DDoS."}'
            mock_openai.return_value.chat.completions.create.return_value = mock_response

            # Load real models
            from src.models.hybrid_predictor import HybridPredictor

            predictor = HybridPredictor(use_stage2=True)

            # Create a synthetic malicious-looking sample
            # Use zeros as a baseline - this should trigger the models
            sample = np.zeros((1, predictor._input_dim), dtype=np.float32)

            result = predictor.predict(sample)

            # Verify the pipeline ran
            assert result.rf_label is not None
            assert result.rf_confidence is not None
            assert result.ae_anomaly_score is not None
            assert result.final_verdict in [Verdict.BENIGN, Verdict.SUSPICIOUS, Verdict.ATTACK]

            # If Stage 1 was SUSPICIOUS, Stage 2 should have been called
            if result.final_verdict == Verdict.SUSPICIOUS:
                mock_openai.return_value.chat.completions.create.assert_called_once()

            print(f"\n=== 2-Stage Pipeline Result ===")
            print(f"Stage 1 (RF): {result.rf_label} (confidence: {result.rf_confidence:.4f})")
            print(f"Stage 1 (AE): anomaly_score={result.ae_anomaly_score:.6f}, is_anomaly={result.ae_is_anomaly}")
            print(f"Final Verdict: {result.final_verdict}")
            print(f"Stage 2 Reason: {result.stage2_reason}")
