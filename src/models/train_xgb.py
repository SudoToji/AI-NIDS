"""XGBoost training for CIC-IDS2017."""

from __future__ import annotations

import logging
import os
from typing import Dict, Tuple

import joblib
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

from src.features.extractor import FEATURE_COLUMNS, prepare_splits

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Environment variable names
MODEL_PATH_ENV = "XGB_MODEL_PATH"
METADATA_PATH_ENV = "XGB_METADATA_PATH"
FEATURE_IMPORTANCE_PATH_ENV = "XGB_FEATURE_IMPORTANCE_PATH"
ENABLE_TUNING_ENV = "XGB_ENABLE_TUNING"
N_ESTIMATORS_ENV = "XGB_N_ESTIMATORS"
MAX_DEPTH_ENV = "XGB_MAX_DEPTH"
LEARNING_RATE_ENV = "XGB_LEARNING_RATE"

# Default paths
DEFAULT_MODEL_PATH = "models/xgb_model.json"
DEFAULT_METADATA_PATH = "models/xgb_metadata.pkl"
DEFAULT_FEATURE_IMPORTANCE_PATH = "models/xgb_feature_importance.png"

# Default hyperparameters (CPU-optimized, fast training)
DEFAULT_N_ESTIMATORS = 150
DEFAULT_MAX_DEPTH = 8
DEFAULT_LEARNING_RATE = 0.1

FAST_PARAMS = {
    "n_estimators": DEFAULT_N_ESTIMATORS,
    "max_depth": DEFAULT_MAX_DEPTH,
    "learning_rate": DEFAULT_LEARNING_RATE,
    "objective": "multi:softprob",
    "tree_method": "hist",  # CPU-optimized histogram method
    "n_jobs": -1,
    "random_state": 42,
    "verbosity": 1,
}


def _resolve_path(env_key: str, default_path: str) -> str:
    """Resolve file path from environment variable or default."""
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)


def _resolve_int(env_key: str, default_value: int) -> int:
    """Resolve integer from environment variable or default."""
    try:
        return int(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


def _resolve_float(env_key: str, default_value: float) -> float:
    """Resolve float from environment variable or default."""
    try:
        return float(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


def _resolve_bool(env_key: str, default: bool = False) -> bool:
    """Resolve boolean from environment variable or default."""
    raw_value = os.getenv(env_key)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _get_hyperparams(num_classes: int) -> Dict:
    """Get XGBoost hyperparameters from env vars or defaults."""
    params = FAST_PARAMS.copy()
    params["n_estimators"] = _resolve_int(N_ESTIMATORS_ENV, DEFAULT_N_ESTIMATORS)
    params["max_depth"] = _resolve_int(MAX_DEPTH_ENV, DEFAULT_MAX_DEPTH)
    params["learning_rate"] = _resolve_float(LEARNING_RATE_ENV, DEFAULT_LEARNING_RATE)
    params["num_class"] = num_classes
    return params


def _save_feature_importance(model: XGBClassifier) -> None:
    """Save feature importance plot."""
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(range(len(importances)), importances[indices])
    ax.set_xticks(range(len(importances)))
    ax.set_xticklabels([FEATURE_COLUMNS[idx] for idx in indices], rotation=90, fontsize=8)
    ax.set_title("XGBoost Feature Importance")
    ax.set_ylabel("Importance")
    fig.tight_layout()

    output_path = _resolve_path(FEATURE_IMPORTANCE_PATH_ENV, DEFAULT_FEATURE_IMPORTANCE_PATH)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig.savefig(output_path)
    plt.close(fig)
    LOGGER.info("Saved feature importance plot to %s", output_path)


def train_xgboost() -> Tuple[XGBClassifier, Dict[str, float]]:
    """Train XGBoost classifier on CIC-IDS2017 dataset.

    Uses CPU-optimized settings by default. Configure via environment variables:
        - XGB_N_ESTIMATORS: Number of trees (default: 150)
        - XGB_MAX_DEPTH: Max tree depth (default: 8)
        - XGB_LEARNING_RATE: Learning rate (default: 0.1)
        - XGB_MODEL_PATH: Output model path
        - XGB_METADATA_PATH: Output metadata path

    Returns:
        Tuple of (trained XGBClassifier, metrics dict)

    Example:
        >>> model, metrics = train_xgboost()
        >>> print(f"Accuracy: {metrics['accuracy']:.4f}")
    """
    # Prepare data splits
    split = prepare_splits()
    class_labels = list(split.label_encoder.classes_)
    num_classes = len(class_labels)

    LOGGER.info(
        "Training XGBoost on %d rows with %d features (%d classes)",
        split.x_train.shape[0],
        split.x_train.shape[1],
        num_classes,
    )

    # Get hyperparameters
    params = _get_hyperparams(num_classes)
    LOGGER.info("XGBoost params: %s", params)

    # Train model
    model = XGBClassifier(**params)
    model.fit(
        split.x_train,
        split.y_train,
        eval_set=[(split.x_test, split.y_test)],
        verbose=True,
    )

    # Evaluate
    y_pred = model.predict(split.x_test)
    report = classification_report(
        split.y_test,
        y_pred,
        target_names=class_labels,
        output_dict=True,
        zero_division=0,
    )

    LOGGER.info(
        "Classification report:\n%s",
        classification_report(split.y_test, y_pred, target_names=class_labels, zero_division=0),
    )

    # Save model
    model_path = _resolve_path(MODEL_PATH_ENV, DEFAULT_MODEL_PATH)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save_model(model_path)
    LOGGER.info("Saved XGBoost model to %s", model_path)

    # Save metadata
    metadata_path = _resolve_path(METADATA_PATH_ENV, DEFAULT_METADATA_PATH)
    os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
    joblib.dump({"class_labels": class_labels, "params": params}, metadata_path)
    LOGGER.info("Saved XGBoost metadata to %s", metadata_path)

    # Save feature importance
    _save_feature_importance(model)

    # Build metrics dict
    per_class_f1 = {
        label: float(report[label]["f1-score"])
        for label in class_labels
        if label in report
    }
    metrics = {
        "accuracy": float(report.get("accuracy", 0.0)),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "macro_f1": float(report.get("macro avg", {}).get("f1-score", 0.0)),
        "per_class_f1": per_class_f1,
    }

    return model, metrics


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_xgboost()
