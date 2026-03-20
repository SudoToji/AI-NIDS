"""Ensemble Voting - Combines RF, XGBoost, and Isolation Forest predictions."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from src.models.hybrid_predictor import HybridPrediction, Verdict

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Model paths
RF_MODEL_PATH_ENV = "RF_MODEL_PATH"
RF_METADATA_PATH_ENV = "RF_METADATA_PATH"
XGB_MODEL_PATH_ENV = "XGB_MODEL_PATH"
XGB_METADATA_PATH_ENV = "XGB_METADATA_PATH"
IF_MODEL_PATH_ENV = "IF_MODEL_PATH"
IF_METADATA_PATH_ENV = "IF_METADATA_PATH"
SCALER_PATH_ENV = "SCALER_PATH"

DEFAULT_RF_MODEL_PATH = "models/rf_model.pkl"
DEFAULT_RF_METADATA_PATH = "models/rf_metadata.pkl"
DEFAULT_XGB_MODEL_PATH = "models/xgb_model.json"
DEFAULT_XGB_METADATA_PATH = "models/xgb_metadata.pkl"
DEFAULT_IF_MODEL_PATH = "models/if_model.pkl"
DEFAULT_IF_METADATA_PATH = "models/if_metadata.pkl"
DEFAULT_SCALER_PATH = "models/scaler.pkl"


class VotingStrategy(Enum):
    """Available voting strategies."""

    MAJORITY = "majority"  # Simple majority vote
    WEIGHTED = "weighted"  # Weight by model confidence
    PLURALITY = "plurality"  # Most votes wins (even if < 50%)


@dataclass(frozen=True)
class ModelPrediction:
    """Single model prediction result."""

    model_name: str
    predicted_label: str
    confidence: float
    is_anomaly: bool
    anomaly_score: float


@dataclass(frozen=True)
class EnsembleResult:
    """Final ensemble prediction result."""

    final_verdict: str
    final_confidence: float
    model_predictions: tuple[ModelPrediction, ...]
    agreement_score: float  # How much models agree (0-1)
    timestamp: str
    voting_strategy: str


def _resolve_path(env_key: str, default_path: str) -> str:
    """Resolve file path from environment variable or default."""
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)


def _load_models() -> tuple:
    """Load all ensemble models.

    Returns:
        Tuple of (rf_model, rf_metadata, xgb_model, xgb_metadata, if_model, if_metadata, scaler)
    """
    # Load Random Forest
    rf_path = _resolve_path(RF_MODEL_PATH_ENV, DEFAULT_RF_MODEL_PATH)
    rf_meta_path = _resolve_path(RF_METADATA_PATH_ENV, DEFAULT_RF_METADATA_PATH)

    if not os.path.exists(rf_path):
        raise FileNotFoundError(f"Random Forest model not found at {rf_path}")
    rf_model = joblib.load(rf_path)
    rf_metadata = joblib.load(rf_meta_path) if os.path.exists(rf_meta_path) else {}
    LOGGER.info("Loaded Random Forest model")

    # Load XGBoost
    xgb_path = _resolve_path(XGB_MODEL_PATH_ENV, DEFAULT_XGB_MODEL_PATH)
    xgb_meta_path = _resolve_path(XGB_METADATA_PATH_ENV, DEFAULT_XGB_METADATA_PATH)

    if not os.path.exists(xgb_path):
        raise FileNotFoundError(f"XGBoost model not found at {xgb_path}")

    from xgboost import XGBClassifier

    xgb_model = XGBClassifier()
    xgb_model.load_model(xgb_path)
    xgb_metadata = joblib.load(xgb_meta_path) if os.path.exists(xgb_meta_path) else {}
    LOGGER.info("Loaded XGBoost model")

    # Load Isolation Forest
    if_path = _resolve_path(IF_MODEL_PATH_ENV, DEFAULT_IF_MODEL_PATH)
    if_meta_path = _resolve_path(IF_METADATA_PATH_ENV, DEFAULT_IF_METADATA_PATH)

    if not os.path.exists(if_path):
        raise FileNotFoundError(f"Isolation Forest model not found at {if_path}")
    if_model = joblib.load(if_path)
    if_metadata = joblib.load(if_meta_path) if os.path.exists(if_meta_path) else {}
    LOGGER.info("Loaded Isolation Forest model")

    # Load scaler
    scaler_path = _resolve_path(SCALER_PATH_ENV, DEFAULT_SCALER_PATH)
    scaler = joblib.load(scaler_path)
    LOGGER.info("Loaded scaler")

    return rf_model, rf_metadata, xgb_model, xgb_metadata, if_model, if_metadata, scaler


def _predict_rf(
    model: RandomForestClassifier,
    metadata: Dict,
    features: np.ndarray,
) -> tuple:
    """Get Random Forest prediction and confidence."""
    probabilities = model.predict_proba(features)[0]
    predicted_class = np.argmax(probabilities)
    confidence = float(probabilities[predicted_class])

    class_labels = metadata.get("class_labels", [])
    label = class_labels[predicted_class] if class_labels else str(predicted_class)

    return label, confidence


def _predict_xgb(model, metadata: Dict, features: np.ndarray) -> tuple:
    """Get XGBoost prediction and confidence."""
    probabilities = model.predict_proba(features)[0]
    predicted_class = np.argmax(probabilities)
    confidence = float(probabilities[predicted_class])

    class_labels = metadata.get("class_labels", [])
    label = class_labels[predicted_class] if class_labels else str(predicted_class)

    return label, confidence


def _predict_if(model, features: np.ndarray) -> tuple:
    """Get Isolation Forest anomaly detection."""
    # decision_function: higher = normal, lower = anomaly
    scores = model.decision_function(features)[0]
    prediction = model.predict(features)[0]  # -1 = anomaly, 1 = normal
    is_anomaly = prediction == -1

    # Normalize score to 0-1 range (higher = more anomalous)
    anomaly_score = max(0.0, min(1.0, 0.5 - scores))

    return is_anomaly, float(anomaly_score)


def _majority_vote(labels: List[str], confidences: List[float]) -> tuple:
    """Simple majority voting."""
    from collections import Counter

    votes = Counter(labels)
    most_common = votes.most_common()

    # Get the label with most votes
    best_label = most_common[0][0]

    # Find the average confidence of models that voted for this label
    indices = [i for i, l in enumerate(labels) if l == best_label]
    best_confidence = np.mean([confidences[i] for i in indices])

    # Calculate agreement score
    agreement = most_common[0][1] / len(labels)

    return best_label, best_confidence, agreement


def _plurality_vote(labels: List[str], confidences: List[float]) -> tuple:
    """Plurality voting - winner doesn't need majority."""
    from collections import Counter

    votes = Counter(labels)
    most_common = votes.most_common()[0]

    best_label = most_common[0]
    indices = [i for i, l in enumerate(labels) if l == best_label]
    best_confidence = np.mean([confidences[i] for i in indices])
    agreement = most_common[1] / len(labels)

    return best_label, best_confidence, agreement


def _weighted_vote(labels: List[str], confidences: List[float]) -> tuple:
    """Weighted voting by confidence."""
    from collections import defaultdict

    label_weights = defaultdict(float)
    label_counts = defaultdict(int)

    for label, confidence in zip(labels, confidences):
        label_weights[label] += confidence
        label_counts[label] += 1

    # Find label with highest weighted confidence
    best_label = max(label_weights.keys(), key=lambda l: label_weights[l])
    best_confidence = label_weights[best_label] / label_counts[best_label]
    agreement = label_counts[best_label] / len(labels)

    return best_label, best_confidence, agreement


def predict_ensemble(
    features: np.ndarray | Dict,
    strategy: VotingStrategy = VotingStrategy.MAJORITY,
) -> EnsembleResult:
    """Run ensemble prediction combining RF, XGBoost, and IF.

    Args:
        features: Either numpy array (pre-scaled) or dict of feature values
        strategy: Voting strategy to use (majority, weighted, plurality)

    Returns:
        EnsembleResult with combined prediction

    Example:
        >>> result = predict_ensemble(feature_dict)
        >>> print(f"Verdict: {result.final_verdict}")
    """
    # Load models
    rf_model, rf_metadata, xgb_model, xgb_metadata, if_model, if_metadata, scaler = _load_models()

    # Prepare features
    if isinstance(features, dict):
        from src.features.extractor import FEATURE_COLUMNS

        feature_vector = np.array(
            [[features.get(col, 0.0) for col in FEATURE_COLUMNS]], dtype=np.float32
        )
        feature_vector = scaler.transform(feature_vector)
    else:
        if features.ndim == 1:
            feature_vector = features.reshape(1, -1)
        else:
            feature_vector = features.astype(np.float32)

    # Get predictions from each model
    rf_label, rf_confidence = _predict_rf(rf_model, rf_metadata, feature_vector)
    xgb_label, xgb_confidence = _predict_xgb(xgb_model, xgb_metadata, feature_vector)
    if_is_anomaly, if_anomaly_score = _predict_if(if_model, feature_vector)

    # Build model predictions
    model_predictions = (
        ModelPrediction(
            model_name="Random Forest",
            predicted_label=rf_label,
            confidence=rf_confidence,
            is_anomaly=False,
            anomaly_score=0.0,
        ),
        ModelPrediction(
            model_name="XGBoost",
            predicted_label=xgb_label,
            confidence=xgb_confidence,
            is_anomaly=False,
            anomaly_score=0.0,
        ),
        ModelPrediction(
            model_name="Isolation Forest",
            predicted_label="Anomaly" if if_is_anomaly else "Normal",
            confidence=1.0 - if_anomaly_score,
            is_anomaly=if_is_anomaly,
            anomaly_score=if_anomaly_score,
        ),
    )

    # Get labels and confidences for voting
    labels = [p.predicted_label for p in model_predictions]
    confidences = [p.confidence for p in model_predictions]

    # Apply voting strategy
    if strategy == VotingStrategy.MAJORITY:
        final_label, final_confidence, agreement = _majority_vote(labels, confidences)
    elif strategy == VotingStrategy.PLURALITY:
        final_label, final_confidence, agreement = _plurality_vote(labels, confidences)
    elif strategy == VotingStrategy.WEIGHTED:
        final_label, final_confidence, agreement = _weighted_vote(labels, confidences)
    else:
        raise ValueError(f"Unknown voting strategy: {strategy}")

    # Determine final verdict
    # If IF detects anomaly, potentially upgrade verdict
    if if_is_anomaly and final_label in ["Normal Traffic", "Normal", "Benign"]:
        if if_anomaly_score > 0.7:  # High anomaly confidence
            final_verdict = "Suspicious (IF Detected)"
            final_confidence = min(final_confidence + 0.1, 0.99)
        else:
            final_verdict = final_label
    elif final_label in ["DDoS", "DoS", "Port Scanning", "Brute Force", "Web Attacks", "Bots"]:
        final_verdict = "Attack"
    elif final_label in ["Normal Traffic", "Normal", "Benign"]:
        final_verdict = "Benign"
    else:
        final_verdict = final_label

    LOGGER.debug(
        "Ensemble prediction: RF=%s, XGB=%s, IF=%s -> %s (%.2f)",
        rf_label,
        xgb_label,
        "Anomaly" if if_is_anomaly else "Normal",
        final_verdict,
        final_confidence,
    )

    return EnsembleResult(
        final_verdict=final_verdict,
        final_confidence=final_confidence,
        model_predictions=model_predictions,
        agreement_score=agreement,
        timestamp=datetime.now(timezone.utc).isoformat(),
        voting_strategy=strategy.value,
    )


class EnsemblePredictor:
    """Ensemble predictor class with cached models."""

    def __init__(self, strategy: VotingStrategy = VotingStrategy.MAJORITY):
        """Initialize ensemble predictor.

        Args:
            strategy: Voting strategy to use
        """
        self.strategy = strategy
        self._models_loaded = False
        self._models = None

    def _ensure_models(self):
        """Lazy load models on first prediction."""
        if not self._models_loaded:
            self._models = _load_models()
            self._models_loaded = True

    def predict(self, features: np.ndarray | Dict) -> EnsembleResult:
        """Run ensemble prediction.

        Args:
            features: Either numpy array (pre-scaled) or dict of feature values

        Returns:
            EnsembleResult with combined prediction
        """
        self._ensure_models()
        return predict_ensemble(features, self.strategy)


def load_ensemble_predictor(
    strategy: VotingStrategy = VotingStrategy.MAJORITY,
) -> EnsemblePredictor:
    """Convenience function to create EnsemblePredictor.

    Args:
        strategy: Voting strategy to use

    Returns:
        Configured EnsemblePredictor instance
    """
    return EnsemblePredictor(strategy=strategy)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Test with sample prediction
    LOGGER.info("Testing Ensemble Predictor...")

    # Create sample features (52 values)
    sample_features = {col: 0.0 for col in range(52)}

    try:
        result = predict_ensemble(sample_features, VotingStrategy.MAJORITY)
        LOGGER.info(f"Final verdict: {result.final_verdict}")
        LOGGER.info(f"Confidence: {result.final_confidence:.2f}")
        LOGGER.info(f"Agreement: {result.agreement_score:.2f}")
        LOGGER.info("\nModel predictions:")
        for mp in result.model_predictions:
            LOGGER.info(f"  {mp.model_name}: {mp.predicted_label} ({mp.confidence:.2f})")
    except FileNotFoundError as e:
        LOGGER.error(f"Model file not found: {e}")
        LOGGER.info("Please train all models first (RF, XGBoost, IF)")
