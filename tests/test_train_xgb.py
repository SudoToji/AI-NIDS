"""Tests for XGBoost training module."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from sklearn.preprocessing import LabelEncoder, StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.features.extractor import DatasetSplit


class TestTrainXGBoostModule:
    """Test XGBoost training module imports and structure."""

    def test_module_imports(self):
        """Test that train_xgb module can be imported."""
        from src.models import train_xgb

        assert hasattr(train_xgb, "train_xgboost")
        assert hasattr(train_xgb, "FAST_PARAMS")
        assert hasattr(train_xgb, "DEFAULT_N_ESTIMATORS")

    def test_fast_params_structure(self):
        """Test FAST_PARAMS contains expected keys."""
        from src.models.train_xgb import FAST_PARAMS

        assert "n_estimators" in FAST_PARAMS
        assert "max_depth" in FAST_PARAMS
        assert "learning_rate" in FAST_PARAMS
        assert "objective" in FAST_PARAMS
        assert "n_jobs" in FAST_PARAMS

    def test_default_values(self):
        """Test default hyperparameter values."""
        from src.models.train_xgb import (
            DEFAULT_LEARNING_RATE,
            DEFAULT_MAX_DEPTH,
            DEFAULT_N_ESTIMATORS,
        )

        assert DEFAULT_N_ESTIMATORS == 150
        assert DEFAULT_MAX_DEPTH == 8
        assert DEFAULT_LEARNING_RATE == 0.1


class TestHelperFunctions:
    """Test helper functions."""

    def test_resolve_path_with_relative(self):
        """Test _resolve_path with relative path."""
        from src.models.train_xgb import PROJECT_ROOT, _resolve_path

        result = _resolve_path("NONEXISTENT_ENV", "models/test.pkl")
        assert result == os.path.join(PROJECT_ROOT, "models/test.pkl")

    def test_resolve_path_with_absolute(self):
        """Test _resolve_path with absolute path."""
        from src.models.train_xgb import _resolve_path

        if os.name == "nt":
            abs_path = "C:\\test\\model.pkl"
        else:
            abs_path = "/tmp/model.pkl"

        with patch.dict(os.environ, {"TEST_PATH": abs_path}):
            result = _resolve_path("TEST_PATH", "default.pkl")
            assert result == abs_path

    def test_resolve_int_valid(self):
        """Test _resolve_int with valid integer."""
        from src.models.train_xgb import _resolve_int

        with patch.dict(os.environ, {"TEST_INT": "200"}):
            result = _resolve_int("TEST_INT", 100)
            assert result == 200

    def test_resolve_int_invalid(self):
        """Test _resolve_int with invalid value."""
        from src.models.train_xgb import _resolve_int

        with patch.dict(os.environ, {"TEST_INT": "not_a_number"}):
            result = _resolve_int("TEST_INT", 100)
            assert result == 100

    def test_resolve_float_valid(self):
        """Test _resolve_float with valid float."""
        from src.models.train_xgb import _resolve_float

        with patch.dict(os.environ, {"TEST_FLOAT": "0.05"}):
            result = _resolve_float("TEST_FLOAT", 0.1)
            assert result == 0.05

    def test_resolve_bool_true(self):
        """Test _resolve_bool with true values."""
        from src.models.train_xgb import _resolve_bool

        for value in ["1", "true", "yes", "on", "TRUE", "Yes"]:
            with patch.dict(os.environ, {"TEST_BOOL": value}):
                result = _resolve_bool("TEST_BOOL", False)
                assert result is True

    def test_resolve_bool_false(self):
        """Test _resolve_bool with false values."""
        from src.models.train_xgb import _resolve_bool

        for value in ["0", "false", "no", "off"]:
            with patch.dict(os.environ, {"TEST_BOOL": value}):
                result = _resolve_bool("TEST_BOOL", True)
                assert result is False


class TestGetHyperparams:
    """Test hyperparameter configuration."""

    def test_get_hyperparams_defaults(self):
        """Test _get_hyperparams returns correct defaults."""
        from src.models.train_xgb import _get_hyperparams

        params = _get_hyperparams(num_classes=7)

        assert params["n_estimators"] == 150
        assert params["max_depth"] == 8
        assert params["learning_rate"] == 0.1
        assert params["num_class"] == 7

    def test_get_hyperparams_from_env(self):
        """Test _get_hyperparams reads from environment."""
        from src.models.train_xgb import _get_hyperparams

        with patch.dict(
            os.environ,
            {
                "XGB_N_ESTIMATORS": "200",
                "XGB_MAX_DEPTH": "10",
                "XGB_LEARNING_RATE": "0.05",
            },
        ):
            params = _get_hyperparams(num_classes=5)

            assert params["n_estimators"] == 200
            assert params["max_depth"] == 10
            assert params["learning_rate"] == 0.05
            assert params["num_class"] == 5


class TestTrainXGBoostIntegration:
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

    def test_train_xgboost_returns_model_and_metrics(self, mock_split, tmp_path):
        """Test that train_xgboost returns a model and metrics dict."""
        from xgboost import XGBClassifier

        from src.models.train_xgb import train_xgboost

        with patch("src.models.train_xgb.prepare_splits", return_value=mock_split), patch.dict(
            os.environ,
            {
                "XGB_MODEL_PATH": str(tmp_path / "xgb_model.json"),
                "XGB_METADATA_PATH": str(tmp_path / "xgb_metadata.pkl"),
                "XGB_FEATURE_IMPORTANCE_PATH": str(tmp_path / "xgb_importance.png"),
                "XGB_N_ESTIMATORS": "10",  # Fast training
            },
        ):
            model, metrics = train_xgboost()

            assert isinstance(model, XGBClassifier)
            assert isinstance(metrics, dict)

    def test_train_xgboost_metrics_structure(self, mock_split, tmp_path):
        """Test metrics dict contains required keys."""
        from src.models.train_xgb import train_xgboost

        with patch("src.models.train_xgb.prepare_splits", return_value=mock_split), patch.dict(
            os.environ,
            {
                "XGB_MODEL_PATH": str(tmp_path / "xgb_model.json"),
                "XGB_METADATA_PATH": str(tmp_path / "xgb_metadata.pkl"),
                "XGB_FEATURE_IMPORTANCE_PATH": str(tmp_path / "xgb_importance.png"),
                "XGB_N_ESTIMATORS": "10",
            },
        ):
            _, metrics = train_xgboost()

            assert "accuracy" in metrics
            assert "weighted_f1" in metrics
            assert "macro_f1" in metrics
            assert "per_class_f1" in metrics
            assert isinstance(metrics["per_class_f1"], dict)

    def test_train_xgboost_saves_model_file(self, mock_split, tmp_path):
        """Test model file is saved."""
        from src.models.train_xgb import train_xgboost

        model_path = tmp_path / "xgb_model.json"

        with patch("src.models.train_xgb.prepare_splits", return_value=mock_split), patch.dict(
            os.environ,
            {
                "XGB_MODEL_PATH": str(model_path),
                "XGB_METADATA_PATH": str(tmp_path / "xgb_metadata.pkl"),
                "XGB_FEATURE_IMPORTANCE_PATH": str(tmp_path / "xgb_importance.png"),
                "XGB_N_ESTIMATORS": "10",
            },
        ):
            train_xgboost()

            assert model_path.exists()

    def test_train_xgboost_saves_metadata_file(self, mock_split, tmp_path):
        """Test metadata file is saved."""
        import joblib

        from src.models.train_xgb import train_xgboost

        metadata_path = tmp_path / "xgb_metadata.pkl"

        with patch("src.models.train_xgb.prepare_splits", return_value=mock_split), patch.dict(
            os.environ,
            {
                "XGB_MODEL_PATH": str(tmp_path / "xgb_model.json"),
                "XGB_METADATA_PATH": str(metadata_path),
                "XGB_FEATURE_IMPORTANCE_PATH": str(tmp_path / "xgb_importance.png"),
                "XGB_N_ESTIMATORS": "10",
            },
        ):
            train_xgboost()

            assert metadata_path.exists()

            metadata = joblib.load(metadata_path)
            assert "class_labels" in metadata
            assert "params" in metadata

    def test_train_xgboost_saves_feature_importance(self, mock_split, tmp_path):
        """Test feature importance plot is saved."""
        from src.models.train_xgb import train_xgboost

        importance_path = tmp_path / "xgb_importance.png"

        with patch("src.models.train_xgb.prepare_splits", return_value=mock_split), patch.dict(
            os.environ,
            {
                "XGB_MODEL_PATH": str(tmp_path / "xgb_model.json"),
                "XGB_METADATA_PATH": str(tmp_path / "xgb_metadata.pkl"),
                "XGB_FEATURE_IMPORTANCE_PATH": str(importance_path),
                "XGB_N_ESTIMATORS": "10",
            },
        ):
            train_xgboost()

            assert importance_path.exists()

    def test_model_has_required_methods(self, mock_split, tmp_path):
        """Test trained model has predict and predict_proba methods."""
        from src.models.train_xgb import train_xgboost

        with patch("src.models.train_xgb.prepare_splits", return_value=mock_split), patch.dict(
            os.environ,
            {
                "XGB_MODEL_PATH": str(tmp_path / "xgb_model.json"),
                "XGB_METADATA_PATH": str(tmp_path / "xgb_metadata.pkl"),
                "XGB_FEATURE_IMPORTANCE_PATH": str(tmp_path / "xgb_importance.png"),
                "XGB_N_ESTIMATORS": "10",
            },
        ):
            model, _ = train_xgboost()

            assert hasattr(model, "predict")
            assert hasattr(model, "predict_proba")
            assert callable(model.predict)
            assert callable(model.predict_proba)

    def test_model_can_predict(self, mock_split, tmp_path):
        """Test trained model can make predictions."""
        from src.models.train_xgb import train_xgboost

        with patch("src.models.train_xgb.prepare_splits", return_value=mock_split), patch.dict(
            os.environ,
            {
                "XGB_MODEL_PATH": str(tmp_path / "xgb_model.json"),
                "XGB_METADATA_PATH": str(tmp_path / "xgb_metadata.pkl"),
                "XGB_FEATURE_IMPORTANCE_PATH": str(tmp_path / "xgb_importance.png"),
                "XGB_N_ESTIMATORS": "10",
            },
        ):
            model, _ = train_xgboost()

            # Test prediction
            sample = np.random.randn(1, 52).astype(np.float32)
            prediction = model.predict(sample)
            proba = model.predict_proba(sample)

            assert prediction.shape == (1,)
            assert proba.shape == (1, 3)  # 3 classes
            assert np.isclose(proba.sum(), 1.0, atol=1e-5)
