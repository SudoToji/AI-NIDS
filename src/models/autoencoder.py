"""Autoencoder anomaly detector training for CIC-IDS2017."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict

import numpy as np
import tensorflow as tf
from sklearn.metrics import precision_recall_curve, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from tensorflow import keras
from tensorflow.keras import layers

from src.features.extractor import filter_benign, prepare_splits

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MODEL_PATH_ENV = "AE_MODEL_PATH"
DEFAULT_MODEL_PATH = "models/autoencoder.keras"
THRESHOLD_PATH_ENV = "AE_THRESHOLD_PATH"
DEFAULT_THRESHOLD_PATH = "models/autoencoder_threshold.npy"

EPOCHS_ENV = "AE_EPOCHS"
BATCH_SIZE_ENV = "AE_BATCH_SIZE"
VALIDATION_SIZE_ENV = "AE_VALIDATION_SIZE"
THRESHOLD_OBJECTIVE_ENV = "AE_THRESHOLD_OBJECTIVE"
THRESHOLD_BETA_ENV = "AE_THRESHOLD_BETA"

DEFAULT_EPOCHS = 15
DEFAULT_BATCH_SIZE = 512
DEFAULT_VALIDATION_SIZE = 0.15
DEFAULT_THRESHOLD_OBJECTIVE = "f1"
DEFAULT_THRESHOLD_BETA = 2.0
BENIGN_LABEL = "Normal Traffic"


@dataclass(frozen=True)
class AutoencoderArtifacts:
    """Container for trained autoencoder artifacts."""

    model: keras.Model
    threshold: float


def _resolve_path(env_key: str, default_path: str) -> str:
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)


def _resolve_int(env_key: str, default_value: int) -> int:
    try:
        return int(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


def _resolve_float(env_key: str, default_value: float) -> float:
    try:
        return float(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


def build_autoencoder(input_dim: int) -> keras.Model:
    """Build the autoencoder architecture."""

    inputs = keras.Input(shape=(input_dim,))
    encoded = layers.Dense(32, activation="relu")(inputs)
    encoded = layers.Dense(16, activation="relu")(encoded)
    encoded = layers.Dense(8, activation="relu")(encoded)

    decoded = layers.Dense(16, activation="relu")(encoded)
    decoded = layers.Dense(32, activation="relu")(decoded)
    decoded = layers.Dense(input_dim, activation="linear")(decoded)

    autoencoder = keras.Model(inputs, decoded, name="cicids_autoencoder")
    autoencoder.compile(optimizer=keras.optimizers.Adam(learning_rate=1e-3), loss="mse")
    return autoencoder


def _reconstruction_errors(model: keras.Model, x: np.ndarray, batch_size: int) -> np.ndarray:
    reconstruction = model.predict(x, batch_size=batch_size, verbose=0)
    return np.mean(np.square(x - reconstruction), axis=1)


def _choose_threshold_from_validation(
    validation_errors: np.ndarray,
    validation_labels: np.ndarray,
    benign_index: int,
) -> float:
    """Choose a threshold using labeled validation data.

    Default behavior maximizes anomaly F1. Set AE_THRESHOLD_OBJECTIVE=recall
    to prefer higher anomaly recall, or AE_THRESHOLD_OBJECTIVE=fbeta with
    AE_THRESHOLD_BETA>1 to weight recall more strongly.
    """

    y_true = (validation_labels != benign_index).astype(int)
    objective = os.getenv(THRESHOLD_OBJECTIVE_ENV, DEFAULT_THRESHOLD_OBJECTIVE).strip().lower()
    beta = _resolve_float(THRESHOLD_BETA_ENV, DEFAULT_THRESHOLD_BETA)

    precisions, recalls, thresholds = precision_recall_curve(y_true, validation_errors)
    if thresholds.size == 0:
        fallback = float(np.quantile(validation_errors, 0.95))
        LOGGER.warning("Validation thresholds were empty. Falling back to 95th percentile %.4f", fallback)
        return fallback

    precisions = precisions[:-1]
    recalls = recalls[:-1]

    if objective == "recall":
        target_floor = 0.90
        candidates = np.where(recalls >= target_floor)[0]
        if candidates.size > 0:
            best_index = int(candidates[np.argmax(precisions[candidates])])
        else:
            best_index = int(np.argmax(recalls))
    elif objective == "fbeta":
        beta_sq = beta ** 2
        scores = (1 + beta_sq) * precisions * recalls / np.clip((beta_sq * precisions) + recalls, 1e-12, None)
        best_index = int(np.argmax(scores))
    else:
        scores = 2 * precisions * recalls / np.clip(precisions + recalls, 1e-12, None)
        best_index = int(np.argmax(scores))

    threshold = float(thresholds[best_index])
    y_pred = (validation_errors > threshold).astype(int)
    LOGGER.info(
        "Selected threshold %.4f using objective=%s (precision=%.4f recall=%.4f f1=%.4f)",
        threshold,
        objective,
        precision_score(y_true, y_pred, zero_division=0),
        recall_score(y_true, y_pred, zero_division=0),
        f1_score(y_true, y_pred, zero_division=0),
    )
    return threshold


def train_autoencoder() -> AutoencoderArtifacts:
    """Train the autoencoder on benign traffic only and tune threshold on labeled validation data."""

    split = prepare_splits()
    benign_index = list(split.label_encoder.classes_).index(BENIGN_LABEL)

    validation_size = _resolve_float(VALIDATION_SIZE_ENV, DEFAULT_VALIDATION_SIZE)
    x_model_train, x_val, y_model_train, y_val = train_test_split(
        split.x_train,
        split.y_train,
        test_size=validation_size,
        random_state=42,
        stratify=split.y_train,
    )

    x_benign = filter_benign(x_model_train, y_model_train, split.label_encoder)
    model = build_autoencoder(x_benign.shape[1])

    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=3,
            restore_best_weights=True,
        )
    ]

    epochs = _resolve_int(EPOCHS_ENV, DEFAULT_EPOCHS)
    batch_size = _resolve_int(BATCH_SIZE_ENV, DEFAULT_BATCH_SIZE)

    LOGGER.info(
        "Training autoencoder on %d benign samples for up to %d epochs (batch_size=%d)",
        x_benign.shape[0],
        epochs,
        batch_size,
    )
    model.fit(
        x_benign,
        x_benign,
        epochs=epochs,
        batch_size=batch_size,
        validation_split=0.1,
        callbacks=callbacks,
        verbose=1,
        shuffle=True,
    )

    validation_errors = _reconstruction_errors(model, x_val, batch_size)
    threshold = _choose_threshold_from_validation(validation_errors, y_val, benign_index)

    model_path = _resolve_path(MODEL_PATH_ENV, DEFAULT_MODEL_PATH)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    model.save(model_path)
    LOGGER.info("Saved autoencoder to %s", model_path)

    threshold_path = _resolve_path(THRESHOLD_PATH_ENV, DEFAULT_THRESHOLD_PATH)
    os.makedirs(os.path.dirname(threshold_path), exist_ok=True)
    np.save(threshold_path, np.array([threshold], dtype=np.float32))
    LOGGER.info("Saved threshold to %s", threshold_path)

    return AutoencoderArtifacts(model=model, threshold=threshold)


def predict_anomaly(model: keras.Model, sample: np.ndarray, threshold: float) -> Dict[str, float | bool]:
    """Compute anomaly score for a single sample."""

    if sample.ndim == 1:
        sample = sample.reshape(1, -1)

    reconstruction = model.predict(sample, verbose=0)
    error = float(np.mean(np.square(sample - reconstruction)))
    return {"anomaly_score": error, "is_anomaly": error > threshold}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    tf.get_logger().setLevel("ERROR")
    train_autoencoder()
