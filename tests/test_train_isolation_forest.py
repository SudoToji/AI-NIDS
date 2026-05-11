"""Tests for Isolation Forest training module."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.features.extractor import DatasetSplit


class TestIsolationForestModule:
    """Test Isolation Forest module imports and structure."""

    def test_module_imports(self):
        """Test that train_isolation_forest module can be imported."""
        from src.models import train_isolation_forest

        assert hasattr(train_isolation_forest, "train_isolation_forest")
        assert hasattr(train_isolation_forest, "load_isolation_forest")
        assert hasattr(train_isolation_forest, "predict_anomalies")
        assert hasattr(train_isolation_forest, "IsolationForestMetrics")

    def test_default_values(self):
        """Test default hyperparameter values."""
        from src.models.train_isolation_forest import (
            DEFAULT_CONTAMINATION,
            DEFAULT_MAX_SAMPLES,
            DEFAULT_N_ESTIMATORS,
            DEFAULT_RANDOM_STATE,
        )

        assert DEFAULT_CONTAMINATION == 0.1
        assert DEFAULT_N_ESTIMATORS == 100
        assert DEFAULT_MAX_SAMPLES == 256
        assert DEFAULT_RANDOM_STATE == 42


class TestHelperFunctions:
    """Test helper functions."""

    def test_resolve_path_with_relative(self):
        """Test _resolve_path with relative path."""
        from src.models.train_isolation_forest import PROJECT_ROOT, _resolve_path

        result = _resolve_path("NONEXISTENT_ENV", "models/test.pkl")
        assert result == os.path.join(PROJECT_ROOT, "models/test.pkl")

    def test_resolve_float_valid(self):
        """Test _resolve_float with valid float."""
        from src.models.train_isolation_forest import _resolve_float

        with patch.dict(os.environ, {"TEST_FLOAT": "0.05"}):
            result = _resolve_float("TEST_FLOAT", 0.1)
            assert result == 0.05

    def test_resolve_float_invalid(self):
        """Test _resolve_float with invalid value."""
        from src.models.train_isolation_forest import _resolve_float

        with patch.dict(os.environ, {"TEST_FLOAT": "not_a_number"}):
            result = _resolve_float("TEST_FLOAT", 0.1)
            assert result == 0.1

    def test_resolve_int_valid(self):
        """Test _resolve_int with valid integer."""
        from src.models.train_isolation_forest import _resolve_int

        with patch.dict(os.environ, {"TEST_INT": "200"}):
            result = _resolve_int("TEST_INT", 100)
            assert result == 200

    def test_resolve_int_invalid(self):
        """Test _resolve_int with invalid value."""
        from src.models.train_isolation_forest import _resolve_int

        with patch.dict(os.environ, {"TEST_INT": "not_a_number"}):
            result = _resolve_int("TEST_INT", 100)
            assert result == 100


class TestIsolationForestMetrics:
    """Test IsolationForestMetrics dataclass."""

    def test_metrics_creation(self):
        """Test creating metrics object."""
        from src.models.train_isolation_forest import IsolationForestMetrics

        metrics = IsolationForestMetrics(
            n_trained_samples=1000,
            n_detected_anomalies=50,
            anomaly_rate=0.05,
            contamination=0.1,
        )

        assert metrics.n_trained_samples == 1000
        assert metrics.n_detected_anomalies == 50
        assert metrics.anomaly_rate == 0.05
        assert metrics.contamination == 0.1

    def test_metrics_immutable(self):
        """Test that metrics are immutable."""
        from src.models.train_isolation_forest import IsolationForestMetrics

        metrics = IsolationForestMetrics(
            n_trained_samples=1000,
            n_detected_anomalies=50,
            anomaly_rate=0.05,
            contamination=0.1,
        )

        with pytest.raises(AttributeError):
            metrics.n_trained_samples = 2000


class TestTrainIsolationForestIntegration:
    """Integration tests with mocked data."""

    @pytest.fixture
    def mock_split(self):
        """Create mock dataset split."""
        np.random.seed(42)
        n_samples = 100
        n_features = 52
        n_classes = 3

        x_train = np.random.randn(n_samples, n_features).astype(np.float32)
        x_test = np.random.randn(n_samples // 5, n_features).astype(np.float32)
        y_train = np.random.randint(0, n_classes, n_samples)
        y_test = np.random.randint(0, n_classes, n_samples // 5)

        encoder = LabelEncoder()
        encoder.classes_ = np.array(["Normal Traffic", "DDoS", "Port Scanning"])

        scaler = StandardScaler()
        scaler.fit(x_train)

        return DatasetSplit(
            x_train=x_train,
            x_test=x_test,
            y_train=y_train,
            y_test=y_test,
            label_encoder=encoder,
            scaler=scaler,
        )

    @pytest.fixture
    def mock_benign_data(self):
        """Create mock benign data for IF training."""
        np.random.seed(42)
        return np.random.randn(50, 52).astype(np.float32)

    def test_train_returns_model_and_metrics(self, mock_split, mock_benign_data, tmp_path):
        """Test that train_isolation_forest returns model and metrics."""
        from src.models.train_isolation_forest import (
            IsolationForestMetrics,
            train_isolation_forest,
        )

        with patch(
            "src.models.train_isolation_forest.prepare_splits", return_value=mock_split
        ), patch(
            "src.models.train_isolation_forest.filter_benign", return_value=mock_benign_data
        ), patch.dict(
            os.environ,
            {
                "IF_MODEL_PATH": str(tmp_path / "if_model.pkl"),
                "IF_METADATA_PATH": str(tmp_path / "if_metadata.pkl"),
                "IF_N_ESTIMATORS": "10",
            },
        ):
            model, metrics = train_isolation_forest()

            assert isinstance(model, IsolationForest)
            assert isinstance(metrics, IsolationForestMetrics)

    def test_metrics_structure(self, mock_split, mock_benign_data, tmp_path):
        """Test metrics contain required fields."""
        from src.models.train_isolation_forest import train_isolation_forest

        with patch(
            "src.models.train_isolation_forest.prepare_splits", return_value=mock_split
        ), patch(
            "src.models.train_isolation_forest.filter_benign", return_value=mock_benign_data
        ), patch.dict(
            os.environ,
            {
                "IF_MODEL_PATH": str(tmp_path / "if_model.pkl"),
                "IF_METADATA_PATH": str(tmp_path / "if_metadata.pkl"),
                "IF_N_ESTIMATORS": "10",
            },
        ):
            _, metrics = train_isolation_forest()

            assert hasattr(metrics, "n_trained_samples")
            assert hasattr(metrics, "n_detected_anomalies")
            assert hasattr(metrics, "anomaly_rate")
            assert hasattr(metrics, "contamination")

    def test_saves_model_file(self, mock_split, mock_benign_data, tmp_path):
        """Test model file is saved."""
        from src.models.train_isolation_forest import train_isolation_forest

        model_path = tmp_path / "if_model.pkl"

        with patch(
            "src.models.train_isolation_forest.prepare_splits", return_value=mock_split
        ), patch(
            "src.models.train_isolation_forest.filter_benign", return_value=mock_benign_data
        ), patch.dict(
            os.environ,
            {
                "IF_MODEL_PATH": str(model_path),
                "IF_METADATA_PATH": str(tmp_path / "if_metadata.pkl"),
                "IF_N_ESTIMATORS": "10",
            },
        ):
            train_isolation_forest()

            assert model_path.exists()

    def test_saves_metadata_file(self, mock_split, mock_benign_data, tmp_path):
        """Test metadata file is saved."""
        import joblib

        from src.models.train_isolation_forest import train_isolation_forest

        metadata_path = tmp_path / "if_metadata.pkl"

        with patch(
            "src.models.train_isolation_forest.prepare_splits", return_value=mock_split
        ), patch(
            "src.models.train_isolation_forest.filter_benign", return_value=mock_benign_data
        ), patch.dict(
            os.environ,
            {
                "IF_MODEL_PATH": str(tmp_path / "if_model.pkl"),
                "IF_METADATA_PATH": str(metadata_path),
                "IF_N_ESTIMATORS": "10",
            },
        ):
            train_isolation_forest()

            assert metadata_path.exists()

            metadata = joblib.load(metadata_path)
            assert "contamination" in metadata
            assert "n_estimators" in metadata
            assert "max_samples" in metadata

    def test_metadata_values(self, mock_split, mock_benign_data, tmp_path):
        """Test metadata contains correct values from env."""
        import joblib

        from src.models.train_isolation_forest import train_isolation_forest

        with patch(
            "src.models.train_isolation_forest.prepare_splits", return_value=mock_split
        ), patch(
            "src.models.train_isolation_forest.filter_benign", return_value=mock_benign_data
        ), patch.dict(
            os.environ,
            {
                "IF_MODEL_PATH": str(tmp_path / "if_model.pkl"),
                "IF_METADATA_PATH": str(tmp_path / "if_metadata.pkl"),
                "IF_N_ESTIMATORS": "50",
                "IF_MAX_SAMPLES": "128",
                "IF_CONTAMINATION": "0.05",
            },
        ):
            train_isolation_forest()

            metadata = joblib.load(tmp_path / "if_metadata.pkl")
            assert metadata["n_estimators"] == 50
            assert metadata["max_samples"] == 128
            assert metadata["contamination"] == 0.05


class TestLoadIsolationForest:
    """Test loading Isolation Forest model."""

    def test_load_model(self, tmp_path):
        """Test loading a saved model."""
        import joblib

        from src.models.train_isolation_forest import load_isolation_forest

        # Create and save a dummy model
        model = IsolationForest(n_estimators=10, random_state=42)
        model.fit(np.random.randn(50, 52))

        model_path = tmp_path / "if_model.pkl"
        joblib.dump(model, model_path)

        # Load it back
        loaded_model, metadata = load_isolation_forest(
            model_path=str(model_path),
            metadata_path=str(tmp_path / "if_metadata.pkl"),
        )

        assert isinstance(loaded_model, IsolationForest)

    def test_load_raises_on_missing_model(self, tmp_path):
        """Test loading raises FileNotFoundError for missing model."""
        from src.models.train_isolation_forest import load_isolation_forest

        with pytest.raises(FileNotFoundError):
            load_isolation_forest(
                model_path=str(tmp_path / "nonexistent.pkl"),
                metadata_path=str(tmp_path / "metadata.pkl"),
            )


class TestPredictAnomalies:
    """Test anomaly prediction."""

    def test_predict_returns_scores_and_mask(self):
        """Test predict_anomalies returns scores and mask."""
        from src.models.train_isolation_forest import predict_anomalies

        # Create and train a simple model
        np.random.seed(42)
        X_train = np.random.randn(50, 5)
        X_test = np.random.randn(10, 5)

        model = IsolationForest(n_estimators=10, random_state=42)
        model.fit(X_train)

        scores, is_anomaly = predict_anomalies(model, X_test)

        assert scores.shape == (10,)
        assert is_anomaly.shape == (10,)
        assert scores.dtype == np.float32
        assert is_anomaly.dtype == bool

    def test_scores_in_range(self):
        """Test that anomaly scores are in [0, 1] range."""
        from src.models.train_isolation_forest import predict_anomalies

        np.random.seed(42)
        X_train = np.random.randn(100, 5)
        X_test = np.random.randn(20, 5)

        model = IsolationForest(n_estimators=10, random_state=42)
        model.fit(X_train)

        scores, _ = predict_anomalies(model, X_test)

        assert np.all(scores >= 0)
        assert np.all(scores <= 1)

    def test_scores_higher_for_anomalies(self):
        """Test that anomalies get higher scores."""
        from src.models.train_isolation_forest import predict_anomalies

        np.random.seed(42)

        # Normal training data
        normal_data = np.random.randn(100, 5)

        # Create some outliers
        outliers = np.random.uniform(low=-10, high=10, size=(10, 5))

        model = IsolationForest(n_estimators=50, contamination=0.1, random_state=42)
        model.fit(normal_data)

        normal_scores, _ = predict_anomalies(model, np.random.randn(10, 5))
        outlier_scores, _ = predict_anomalies(model, outliers)

        # Outliers should generally have higher anomaly scores
        assert np.mean(outlier_scores) > np.mean(normal_scores)

    def test_scores_for_single_sample(self):
        """Test prediction for a single sample."""
        from src.models.train_isolation_forest import predict_anomalies

        np.random.seed(42)
        X_train = np.random.randn(50, 5)
        single_sample = np.random.randn(1, 5)

        model = IsolationForest(n_estimators=10, random_state=42)
        model.fit(X_train)

        scores, is_anomaly = predict_anomalies(model, single_sample)

        assert scores.shape == (1,)
        assert is_anomaly.shape == (1,)
