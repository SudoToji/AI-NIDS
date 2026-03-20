"""Tests for Ensemble Voting module."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.models.ensemble_voting import (
    EnsemblePredictor,
    EnsembleResult,
    ModelPrediction,
    VotingStrategy,
    _majority_vote,
    _plurality_vote,
    _weighted_vote,
    predict_ensemble,
)


class TestVotingStrategies:
    """Test individual voting strategy functions."""

    def test_majority_vote_all_agree(self):
        """Test majority vote when all models agree."""
        labels = ["DDoS", "DDoS", "DDoS"]
        confidences = [0.9, 0.85, 0.88]

        label, confidence, agreement = _majority_vote(labels, confidences)

        assert label == "DDoS"
        assert abs(float(confidence) - 0.8766666666666666) < 0.001  # Allow small floating point diff
        assert agreement == pytest.approx(1.0)

    def test_majority_vote_with_winner(self):
        """Test majority vote with clear winner."""
        labels = ["DDoS", "DDoS", "Benign"]
        confidences = [0.9, 0.85, 0.95]

        label, confidence, agreement = _majority_vote(labels, confidences)

        assert label == "DDoS"
        assert agreement == pytest.approx(2 / 3)

    def test_majority_vote_all_different(self):
        """Test majority vote when all labels differ."""
        labels = ["DDoS", "Benign", "PortScan"]
        confidences = [0.9, 0.85, 0.88]

        label, confidence, agreement = _majority_vote(labels, confidences)

        # All have same count, first alphabetically wins (counter behavior)
        assert agreement == pytest.approx(1 / 3)

    def test_plurality_vote_with_winner(self):
        """Test plurality vote - winner doesn't need majority."""
        labels = ["DDoS", "DDoS", "Benign", "Benign"]
        confidences = [0.9, 0.85, 0.95, 0.88]

        label, confidence, agreement = _plurality_vote(labels, confidences)

        # Should be tie between DDoS and Benign, first one wins
        assert label in ["DDoS", "Benign"]
        assert agreement == pytest.approx(0.5)

    def test_plurality_vote_all_different(self):
        """Test plurality vote with all different labels."""
        labels = ["DDoS", "Benign", "PortScan"]
        confidences = [0.9, 0.85, 0.88]

        label, confidence, agreement = _plurality_vote(labels, confidences)

        # All have count 1, first alphabetically wins
        assert agreement == pytest.approx(1 / 3)

    def test_weighted_vote_by_confidence(self):
        """Test weighted vote considers confidence."""
        labels = ["DDoS", "Benign", "Benign"]
        confidences = [0.99, 0.6, 0.6]  # DDoS has much higher confidence

        label, confidence, agreement = _weighted_vote(labels, confidences)

        # Despite DDoS having only 1 vote, its high confidence might win
        # With these values: DDoS weight = 0.99, Benign weight = 1.2
        assert label == "Benign"  # Benign has higher total weight
        assert agreement == pytest.approx(2 / 3)

    def test_weighted_vote_with_clear_winner(self):
        """Test weighted vote with clear high-confidence winner."""
        labels = ["DDoS", "Benign", "Benign"]
        confidences = [0.99, 0.5, 0.5]

        label, confidence, agreement = _weighted_vote(labels, confidences)

        # DDoS weight = 0.99, Benign weight = 1.0
        assert label == "Benign"  # Benign still wins by weight


class TestModelPrediction:
    """Test ModelPrediction dataclass."""

    def test_creation(self):
        """Test creating ModelPrediction."""
        mp = ModelPrediction(
            model_name="Random Forest",
            predicted_label="DDoS",
            confidence=0.95,
            is_anomaly=False,
            anomaly_score=0.0,
        )

        assert mp.model_name == "Random Forest"
        assert mp.predicted_label == "DDoS"
        assert mp.confidence == 0.95

    def test_immutable(self):
        """Test that ModelPrediction is immutable."""
        mp = ModelPrediction(
            model_name="XGBoost",
            predicted_label="Benign",
            confidence=0.8,
            is_anomaly=False,
            anomaly_score=0.0,
        )

        with pytest.raises(AttributeError):
            mp.confidence = 0.9


class TestEnsembleResult:
    """Test EnsembleResult dataclass."""

    def test_creation(self):
        """Test creating EnsembleResult."""
        predictions = (
            ModelPrediction("RF", "DDoS", 0.9, False, 0.0),
            ModelPrediction("XGB", "DDoS", 0.85, False, 0.0),
            ModelPrediction("IF", "Normal", 0.95, False, 0.05),
        )

        result = EnsembleResult(
            final_verdict="Attack",
            final_confidence=0.9,
            model_predictions=predictions,
            agreement_score=0.67,
            timestamp="2024-01-01T00:00:00Z",
            voting_strategy="majority",
        )

        assert result.final_verdict == "Attack"
        assert result.final_confidence == 0.9
        assert len(result.model_predictions) == 3


class TestPredictEnsembleIntegration:
    """Integration tests with mocked models."""

    @pytest.fixture
    def mock_models(self, tmp_path):
        """Create mock models for testing using actual sklearn models."""
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        from xgboost import XGBClassifier
        import joblib

        # Create dummy RF with actual training
        rf = RandomForestClassifier(n_estimators=10, random_state=42)
        X_train = np.random.randn(100, 52).astype(np.float32)
        y_train = np.random.randint(0, 3, 100)
        rf.fit(X_train, y_train)
        rf_path = tmp_path / "rf.pkl"
        joblib.dump(rf, rf_path)
        joblib.dump({"class_labels": ["Benign", "DDoS", "PortScan"]}, tmp_path / "rf_meta.pkl")

        # Create dummy XGB with actual training
        xgb = XGBClassifier(n_estimators=10, random_state=42, verbosity=0)
        xgb.fit(X_train, y_train)
        xgb.save_model(str(tmp_path / "xgb.json"))
        joblib.dump({"class_labels": ["Benign", "DDoS", "PortScan"]}, tmp_path / "xgb_meta.pkl")

        # Create dummy IF with actual training
        if_model = IsolationForest(n_estimators=10, random_state=42)
        if_model.fit(X_train)
        joblib.dump(if_model, tmp_path / "if.pkl")
        joblib.dump({"contamination": 0.1}, tmp_path / "if_meta.pkl")

        # Create scaler
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        scaler.fit(X_train)
        joblib.dump(scaler, tmp_path / "scaler.pkl")

        return {
            "rf_path": str(rf_path),
            "rf_meta": str(tmp_path / "rf_meta.pkl"),
            "xgb_path": str(tmp_path / "xgb.json"),
            "xgb_meta": str(tmp_path / "xgb_meta.pkl"),
            "if_path": str(tmp_path / "if.pkl"),
            "if_meta": str(tmp_path / "if_meta.pkl"),
            "scaler_path": str(tmp_path / "scaler.pkl"),
            "X_test": X_train[:1],  # Use actual data for testing
        }

    def test_predict_returns_ensemble_result(self, mock_models):
        """Test that predict_ensemble returns EnsembleResult."""
        from sklearn.preprocessing import StandardScaler
        import joblib

        # Create a real scaler that transforms data correctly
        X_test = mock_models["X_test"]
        
        with patch.dict(
            os.environ,
            {
                "RF_MODEL_PATH": mock_models["rf_path"],
                "RF_METADATA_PATH": mock_models["rf_meta"],
                "XGB_MODEL_PATH": mock_models["xgb_path"],
                "XGB_METADATA_PATH": mock_models["xgb_meta"],
                "IF_MODEL_PATH": mock_models["if_path"],
                "IF_METADATA_PATH": mock_models["if_meta"],
                "SCALER_PATH": mock_models["scaler_path"],
            },
        ):
            result = predict_ensemble(X_test)

            assert isinstance(result, EnsembleResult)
            assert hasattr(result, "final_verdict")
            assert hasattr(result, "final_confidence")
            assert hasattr(result, "model_predictions")
            assert hasattr(result, "agreement_score")

    def test_model_predictions_count(self, mock_models):
        """Test that all three models contribute predictions."""
        X_test = mock_models["X_test"]

        with patch.dict(
            os.environ,
            {
                "RF_MODEL_PATH": mock_models["rf_path"],
                "RF_METADATA_PATH": mock_models["rf_meta"],
                "XGB_MODEL_PATH": mock_models["xgb_path"],
                "XGB_METADATA_PATH": mock_models["xgb_meta"],
                "IF_MODEL_PATH": mock_models["if_path"],
                "IF_METADATA_PATH": mock_models["if_meta"],
                "SCALER_PATH": mock_models["scaler_path"],
            },
        ):
            result = predict_ensemble(X_test)

            assert len(result.model_predictions) == 3
            model_names = [p.model_name for p in result.model_predictions]
            assert "Random Forest" in model_names
            assert "XGBoost" in model_names
            assert "Isolation Forest" in model_names

    def test_dict_features_input(self, mock_models):
        """Test prediction with dict features."""
        # Create a real scaler and test
        X_test = mock_models["X_test"]
        
        with patch.dict(
            os.environ,
            {
                "RF_MODEL_PATH": mock_models["rf_path"],
                "RF_METADATA_PATH": mock_models["rf_meta"],
                "XGB_MODEL_PATH": mock_models["xgb_path"],
                "XGB_METADATA_PATH": mock_models["xgb_meta"],
                "IF_MODEL_PATH": mock_models["if_path"],
                "IF_METADATA_PATH": mock_models["if_meta"],
                "SCALER_PATH": mock_models["scaler_path"],
            },
        ):
            # Use first sample as dict
            feature_dict = {f"feat_{i}": float(X_test[0, i]) for i in range(52)}
            result = predict_ensemble(feature_dict)

            assert isinstance(result, EnsembleResult)

    def test_different_voting_strategies(self, mock_models):
        """Test using different voting strategies."""
        X_test = mock_models["X_test"]

        with patch.dict(
            os.environ,
            {
                "RF_MODEL_PATH": mock_models["rf_path"],
                "RF_METADATA_PATH": mock_models["rf_meta"],
                "XGB_MODEL_PATH": mock_models["xgb_path"],
                "XGB_METADATA_PATH": mock_models["xgb_meta"],
                "IF_MODEL_PATH": mock_models["if_path"],
                "IF_METADATA_PATH": mock_models["if_meta"],
                "SCALER_PATH": mock_models["scaler_path"],
            },
        ):
            result_majority = predict_ensemble(X_test, VotingStrategy.MAJORITY)
            result_plurality = predict_ensemble(X_test, VotingStrategy.PLURALITY)
            result_weighted = predict_ensemble(X_test, VotingStrategy.WEIGHTED)

            assert result_majority.voting_strategy == "majority"
            assert result_plurality.voting_strategy == "plurality"
            assert result_weighted.voting_strategy == "weighted"


class TestEnsemblePredictorClass:
    """Test EnsemblePredictor class."""

    def test_lazy_loading(self, tmp_path):
        """Test that models are loaded lazily on first prediction."""
        predictor = EnsemblePredictor()
        assert predictor._models_loaded is False

    def test_strategy_setting(self):
        """Test that strategy is set correctly."""
        predictor = EnsemblePredictor(strategy=VotingStrategy.WEIGHTED)
        assert predictor.strategy == VotingStrategy.WEIGHTED

    def test_default_strategy(self):
        """Test default strategy is MAJORITY."""
        predictor = EnsemblePredictor()
        assert predictor.strategy == VotingStrategy.MAJORITY


class TestErrorHandling:
    """Test error handling."""

    def test_missing_rf_model(self, tmp_path):
        """Test error when RF model is missing."""
        with patch.dict(
            os.environ,
            {
                "RF_MODEL_PATH": str(tmp_path / "nonexistent.pkl"),
                "RF_METADATA_PATH": str(tmp_path / "rf_meta.pkl"),
                "XGB_MODEL_PATH": str(tmp_path / "xgb.json"),
                "XGB_METADATA_PATH": str(tmp_path / "xgb_meta.pkl"),
                "IF_MODEL_PATH": str(tmp_path / "if.pkl"),
                "IF_METADATA_PATH": str(tmp_path / "if_meta.pkl"),
                "SCALER_PATH": str(tmp_path / "scaler.pkl"),
            },
        ):
            with pytest.raises(FileNotFoundError, match="Random Forest"):
                predict_ensemble(np.zeros(52).reshape(1, -1))
