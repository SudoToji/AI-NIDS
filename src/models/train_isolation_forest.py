"""Isolation Forest anomaly detection for CIC-IDS2017."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest as SklearnIF

from src.features.extractor import FEATURE_COLUMNS, filter_benign, prepare_splits

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Environment variable names
MODEL_PATH_ENV = "IF_MODEL_PATH"
METADATA_PATH_ENV = "IF_METADATA_PATH"
CONTAMINATION_ENV = "IF_CONTAMINATION"
N_ESTIMATORS_ENV = "IF_N_ESTIMATORS"
MAX_SAMPLES_ENV = "IF_MAX_SAMPLES"
RANDOM_STATE_ENV = "IF_RANDOM_STATE"

# Default paths
DEFAULT_MODEL_PATH = "models/if_model.pkl"
DEFAULT_METADATA_PATH = "models/if_metadata.pkl"

# Default hyperparameters
DEFAULT_CONTAMINATION = 0.1  # 10% expected anomalies
DEFAULT_N_ESTIMATORS = 100
DEFAULT_MAX_SAMPLES = 256
DEFAULT_RANDOM_STATE = 42


def _resolve_path(env_key: str, default_path: str) -> str:
    """Resolve file path from environment variable or default."""
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)


def _resolve_float(env_key: str, default_value: float) -> float:
    """Resolve float from environment variable or default."""
    try:
        return float(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


def _resolve_int(env_key: str, default_value: int) -> int:
    """Resolve integer from environment variable or default."""
    try:
        return int(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


@dataclass(frozen=True)
class IsolationForestMetrics:
    """Metrics from Isolation Forest training."""

    n_trained_samples: int
    n_detected_anomalies: int
    anomaly_rate: float
    contamination: float


def train_isolation_forest() -> Tuple[SklearnIF, IsolationForestMetrics]:
    """Train Isolation Forest on CIC-IDS2017 benign traffic.

    Isolation Forest is trained ONLY on benign traffic to detect anomalies.
    It identifies data points that are few or different - characteristic of attacks.

    Configure via environment variables:
        - IF_CONTAMINATION: Expected anomaly rate (default: 0.1)
        - IF_N_ESTIMATORS: Number of trees (default: 100)
        - IF_MAX_SAMPLES: Subsample size (default: 256)
        - IF_MODEL_PATH: Output model path
        - IF_METADATA_PATH: Output metadata path

    Returns:
        Tuple of (trained IsolationForest, metrics)

    Example:
        >>> model, metrics = train_isolation_forest()
        >>> print(f"Detected {metrics.n_detected_anomalies} anomalies")
    """
    # Prepare data splits
    split = prepare_splits()

    LOGGER.info(
        "Training Isolation Forest on %d rows with %d features",
        split.x_train.shape[0],
        split.x_train.shape[1],
    )

    # Filter to benign-only traffic for training
    benign_train = filter_benign(split.x_train, split.y_train, split.label_encoder)

    LOGGER.info("Using %d benign samples for Isolation Forest training", benign_train.shape[0])

    # Get hyperparameters from env
    contamination = _resolve_float(CONTAMINATION_ENV, DEFAULT_CONTAMINATION)
    n_estimators = _resolve_int(N_ESTIMATORS_ENV, DEFAULT_N_ESTIMATORS)
    max_samples = _resolve_int(MAX_SAMPLES_ENV, DEFAULT_MAX_SAMPLES)
    random_state = _resolve_int(RANDOM_STATE_ENV, DEFAULT_RANDOM_STATE)

    LOGGER.info(
        "Isolation Forest params: contamination=%.2f, n_estimators=%d, max_samples=%d",
        contamination,
        n_estimators,
        max_samples,
    )

    # Train Isolation Forest
    model = SklearnIF(
        contamination=contamination,
        n_estimators=n_estimators,
        max_samples=max_samples,
        random_state=random_state,
        n_jobs=-1,
    )

    model.fit(benign_train)
    LOGGER.info("Isolation Forest training complete")

    # Evaluate on test set
    predictions = model.predict(split.x_test)
    n_anomalies = int(np.sum(predictions == -1))
    total_samples = len(predictions)
    anomaly_rate = float(n_anomalies / total_samples)

    LOGGER.info(
        "Isolation Forest detected %d anomalies out of %d samples (%.2f%%)",
        n_anomalies,
        total_samples,
        anomaly_rate * 100,
    )

    # Save model
    model_path = _resolve_path(MODEL_PATH_ENV, DEFAULT_MODEL_PATH)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    LOGGER.info("Saved Isolation Forest model to %s", model_path)

    # Save metadata
    metadata_path = _resolve_path(METADATA_PATH_ENV, DEFAULT_METADATA_PATH)
    os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
    metadata = {
        "contamination": contamination,
        "n_estimators": n_estimators,
        "max_samples": max_samples,
        "random_state": random_state,
        "n_features": int(split.x_train.shape[1]),
        "n_trained_samples": int(benign_train.shape[0]),
    }
    joblib.dump(metadata, metadata_path)
    LOGGER.info("Saved Isolation Forest metadata to %s", metadata_path)

    metrics = IsolationForestMetrics(
        n_trained_samples=int(benign_train.shape[0]),
        n_detected_anomalies=n_anomalies,
        anomaly_rate=anomaly_rate,
        contamination=contamination,
    )

    return model, metrics


def load_isolation_forest(
    model_path: str | None = None,
    metadata_path: str | None = None,
) -> Tuple[SklearnIF, Dict]:
    """Load a trained Isolation Forest from disk.

    Args:
        model_path: Optional path to model file
        metadata_path: Optional path to metadata file

    Returns:
        Tuple of (model, metadata dict)

    Raises:
        FileNotFoundError: If model file doesn't exist
    """
    model_path = _resolve_path(MODEL_PATH_ENV, model_path or DEFAULT_MODEL_PATH)
    metadata_path = _resolve_path(METADATA_PATH_ENV, metadata_path or DEFAULT_METADATA_PATH)

    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Isolation Forest model not found at {model_path}")

    model = joblib.load(model_path)
    LOGGER.info("Loaded Isolation Forest model from %s", model_path)

    metadata = {}
    if os.path.exists(metadata_path):
        metadata = joblib.load(metadata_path)
        LOGGER.info("Loaded metadata: %s", metadata)
    else:
        LOGGER.warning("Metadata file not found at %s", metadata_path)

    return model, metadata


def predict_anomalies(
    model: SklearnIF,
    features: np.ndarray,
) -> Tuple[np.ndarray, np.ndarray]:
    """Predict anomalies using Isolation Forest.

    Args:
        model: Trained IsolationForest model
        features: Feature array of shape (n_samples, n_features)

    Returns:
        Tuple of (anomaly_scores, is_anomaly_mask)
        - anomaly_scores: Anomaly scores (lower = more anomalous)
        - is_anomaly_mask: Boolean mask where True = anomaly
    """
    # decision_function returns: higher = normal, lower = anomaly
    # score_samples is the negative of decision_function
    anomaly_scores = model.decision_function(features)

    # Convert to probability-like score (0-1, higher = more anomalous)
    # sklearn's decision_function is unbounded, so we need to normalize
    # Typical range is roughly [-0.5, 0.5] for well-behaved data
    min_score = np.min(anomaly_scores)
    max_score = np.max(anomaly_scores)

    if max_score - min_score > 1e-10:
        normalized_scores = (anomaly_scores - min_score) / (max_score - min_score)
        # Invert: higher = more anomalous
        anomaly_probability = 1.0 - normalized_scores
    else:
        anomaly_probability = np.full_like(anomaly_scores, 0.5)

    # Binary prediction: -1 = anomaly, 1 = normal
    predictions = model.predict(features)
    is_anomaly = predictions == -1

    return anomaly_probability.astype(np.float32), is_anomaly


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    model, metrics = train_isolation_forest()
    print(f"\nIsolation Forest trained successfully!")
    print(f"  Trained on: {metrics.n_trained_samples} samples")
    print(f"  Detected anomalies: {metrics.n_detected_anomalies}")
    print(f"  Anomaly rate: {metrics.anomaly_rate * 100:.2f}%")
