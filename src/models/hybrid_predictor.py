"""Hybrid ML Engine - Fuses Random Forest and Autoencoder predictions."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict

import joblib
import numpy as np
from sklearn.preprocessing import LabelEncoder
from tensorflow import keras

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

RF_MODEL_PATH_ENV = "RF_MODEL_PATH"
RF_METADATA_PATH_ENV = "RF_METADATA_PATH"
AE_MODEL_PATH_ENV = "AE_MODEL_PATH"
AE_THRESHOLD_PATH_ENV = "AE_THRESHOLD_PATH"
SCALER_PATH_ENV = "SCALER_PATH"

DEFAULT_RF_MODEL_PATH = "models/rf_model.pkl"
DEFAULT_RF_METADATA_PATH = "models/rf_metadata.pkl"
DEFAULT_AE_MODEL_PATH = "models/autoencoder.keras"
DEFAULT_AE_THRESHOLD_PATH = "models/autoencoder_threshold.npy"
DEFAULT_SCALER_PATH = "models/scaler.pkl"


@dataclass(frozen=True)
class HybridPrediction:
    """Container for fused model predictions."""

    rf_label: str
    rf_confidence: float
    ae_anomaly_score: float
    ae_is_anomaly: bool
    final_verdict: Verdict
    combined_confidence: float
    timestamp: str


class Verdict:
    """Verdict classification constants."""

    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    ATTACK = "Attack"


def _resolve_path(env_key: str, default_path: str) -> str:
    """Resolve file path from environment variable or default."""
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)


def _load_rf_model(model_path: str) -> tuple:
    """Load Random Forest model and metadata.
    
    Returns:
        Tuple of (model, metadata_dict)
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Random Forest model not found at {model_path}")
    
    model = joblib.load(model_path)
    LOGGER.info("Loaded Random Forest model from %s", model_path)
    return model


def _load_rf_metadata(metadata_path: str) -> Dict:
    """Load Random Forest metadata (class labels, thresholds)."""
    if not os.path.exists(metadata_path):
        LOGGER.warning("RF metadata not found at %s, using defaults", metadata_path)
        return {"class_labels": [], "thresholds": {}}
    
    metadata = joblib.load(metadata_path)
    LOGGER.info("Loaded RF metadata with %d classes", len(metadata.get("class_labels", [])))
    return metadata


def _load_autoencoder(model_path: str, threshold_path: str) -> tuple:
    """Load Keras Autoencoder model and threshold.
    
    Returns:
        Tuple of (model, threshold_float)
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Autoencoder model not found at {model_path}")
    
    model = keras.models.load_model(model_path, compile=False)
    LOGGER.info("Loaded Autoencoder model from %s", model_path)
    
    if not os.path.exists(threshold_path):
        LOGGER.warning("AE threshold not found at %s, using default 0.5", threshold_path)
        threshold = 0.5
    else:
        threshold_arr = np.load(threshold_path)
        threshold = float(threshold_arr[0])
        LOGGER.info("Loaded AE threshold: %.4f", threshold)
    
    return model, threshold


def _load_scaler(scaler_path: str):
    """Load StandardScaler for feature preprocessing."""
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler not found at {scaler_path}")
    
    scaler = joblib.load(scaler_path)
    LOGGER.info("Loaded scaler from %s", scaler_path)
    return scaler


class HybridPredictor:
    """Fuses Random Forest classifier and Autoencoder anomaly detector.
    
    This class loads both trained models and provides unified prediction
    by combining their outputs using decision fusion logic.
    
    Decision Fusion Rules:
        - RF attack + AE anomaly  → Attack (high confidence)
        - RF attack XOR AE anomaly → Suspicious (medium confidence)
        - Both benign → Benign
    
    Example:
        >>> predictor = HybridPredictor()
        >>> result = predictor.predict(sample_features)
        >>> print(result.final_verdict, result.combined_confidence)
    """

    def __init__(
        self,
        rf_model_path: str | None = None,
        rf_metadata_path: str | None = None,
        ae_model_path: str | None = None,
        ae_threshold_path: str | None = None,
        scaler_path: str | None = None,
    ):
        """Initialize HybridPredictor by loading all models.
        
        Args:
            rf_model_path: Path to Random Forest .pkl file
            rf_metadata_path: Path to RF metadata .pkl file
            ae_model_path: Path to Keras Autoencoder .keras file
            ae_threshold_path: Path to AE threshold .npy file
            scaler_path: Path to StandardScaler .pkl file
            
        Raises:
            FileNotFoundError: If required model files are missing
        """
        rf_path = _resolve_path(RF_MODEL_PATH_ENV, rf_model_path or DEFAULT_RF_MODEL_PATH)
        rf_meta = _resolve_path(RF_METADATA_PATH_ENV, rf_metadata_path or DEFAULT_RF_METADATA_PATH)
        ae_path = _resolve_path(AE_MODEL_PATH_ENV, ae_model_path or DEFAULT_AE_MODEL_PATH)
        ae_thresh = _resolve_path(AE_THRESHOLD_PATH_ENV, ae_threshold_path or DEFAULT_AE_THRESHOLD_PATH)
        scaler = _resolve_path(SCALER_PATH_ENV, scaler_path or DEFAULT_SCALER_PATH)
        
        self._rf_model = _load_rf_model(rf_path)
        self._rf_metadata = _load_rf_metadata(rf_meta)
        self._class_labels: list[str] = self._rf_metadata.get("class_labels", [])
        self._thresholds: Dict[str, float] = self._rf_metadata.get("thresholds", {})
        
        self._ae_model, self._ae_threshold = _load_autoencoder(ae_path, ae_thresh)
        self._scaler = _load_scaler(scaler)
        
        self._input_dim = self._ae_model.input_shape[-1]
        LOGGER.info(
            "HybridPredictor initialized: %d classes, AE threshold=%.4f, input_dim=%d",
            len(self._class_labels),
            self._ae_threshold,
            self._input_dim,
        )

    def _predict_rf(self, features: np.ndarray) -> tuple:
        """Get Random Forest prediction and confidence.
        
        Returns:
            Tuple of (label, confidence)
        """
        probabilities = self._rf_model.predict_proba(features)
        
        thresholds = self._thresholds
        if thresholds:
            predictions = np.argmax(probabilities, axis=1)
            sorted_indices = np.argsort(probabilities, axis=1)
            class_to_index = {label: idx for idx, label in enumerate(self._class_labels)}
            
            for label, threshold in thresholds.items():
                class_index = class_to_index.get(label)
                if class_index is None:
                    continue
                
                force_mask = probabilities[:, class_index] >= threshold
                predictions[force_mask] = class_index
                
                demote_mask = (predictions == class_index) & (~force_mask)
                if np.any(demote_mask):
                    predictions[demote_mask] = sorted_indices[demote_mask, -2]
            
            predicted_class = predictions[0]
            confidence = float(probabilities[0, predicted_class])
        else:
            predicted_class = np.argmax(probabilities[0])
            confidence = float(probabilities[0, predicted_class])
        
        label = self._class_labels[predicted_class] if self._class_labels else str(predicted_class)
        return label, confidence

    def _predict_autoencoder(self, features: np.ndarray) -> tuple:
        """Get Autoencoder anomaly score and detection result.
        
        Returns:
            Tuple of (anomaly_score, is_anomaly_bool)
        """
        reconstruction = self._ae_model.predict(features, verbose=0)
        mse = float(np.mean(np.square(features - reconstruction)))
        
        is_anomaly = mse > self._ae_threshold
        return mse, is_anomaly

    def _compute_fusion(
        self,
        rf_label: str,
        rf_confidence: float,
        ae_is_anomaly: bool,
    ) -> tuple:
        """Compute final verdict and combined confidence.
        
        Decision fusion logic (RF-primary approach):
        - RF says attack → Attack (high confidence from RF)
        - RF says benign + AE anomaly → Suspicious (potential zero-day)
        - RF says benign + AE normal → Benign
        """
        rf_is_attack = rf_label not in {"Benign", "Normal Traffic", "Normal"}
        
        if rf_is_attack:
            verdict = Verdict.ATTACK
            combined_confidence = rf_confidence
        elif ae_is_anomaly:
            verdict = Verdict.SUSPICIOUS
            combined_confidence = min(rf_confidence + 0.2, 0.99)
        else:
            verdict = Verdict.BENIGN
            combined_confidence = rf_confidence
        
        return verdict, combined_confidence

    def predict(self, features: np.ndarray | Dict) -> HybridPrediction:
        """Run hybrid prediction on input features.
        
        Args:
            features: Either a numpy array of scaled features or a dict
                     with feature values. If dict, will be scaled first.
                     
        Returns:
            HybridPrediction with all model outputs and fused verdict
            
        Example:
            >>> # With numpy array (pre-scaled)
            >>> result = predictor.predict(features_array)
            
            >>> # With dict (auto-scaled)
            >>> result = predictor.predict({"feature1": 0.5, "feature2": -0.3, ...})
        """
        if isinstance(features, dict):
            from src.features.extractor import FEATURE_COLUMNS
            
            feature_vector = np.array([[features.get(col, 0.0) for col in FEATURE_COLUMNS]], dtype=np.float32)
            feature_vector = self._scaler.transform(feature_vector)
        else:
            if features.ndim == 1:
                feature_vector = features.reshape(1, -1)
            else:
                feature_vector = features.astype(np.float32)
        
        if feature_vector.shape[1] != self._input_dim:
            raise ValueError(
                f"Feature dimension mismatch: expected {self._input_dim}, got {feature_vector.shape[1]}"
            )
        
        rf_label, rf_confidence = self._predict_rf(feature_vector)
        ae_score, ae_is_anomaly = self._predict_autoencoder(feature_vector)
        
        verdict, combined_confidence = self._compute_fusion(rf_label, rf_confidence, ae_is_anomaly)
        
        LOGGER.debug(
            "Prediction: RF=%s (%.2f), AE=%.4f (%s) → %s (%.2f)",
            rf_label,
            rf_confidence,
            ae_score,
            ae_is_anomaly,
            verdict,
            combined_confidence,
        )
        
        return HybridPrediction(
            rf_label=rf_label,
            rf_confidence=rf_confidence,
            ae_anomaly_score=ae_score,
            ae_is_anomaly=ae_is_anomaly,
            final_verdict=verdict,
            combined_confidence=combined_confidence,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def predict_batch(self, features: np.ndarray) -> list[HybridPrediction]:
        """Run predictions on multiple samples.
        
        Args:
            features: 2D numpy array of shape (n_samples, n_features)
            
        Returns:
            List of HybridPrediction objects
        """
        return [self.predict(features[i]) for i in range(len(features))]

    @property
    def class_labels(self) -> list[str]:
        """Get list of RF class labels."""
        return self._class_labels.copy()

    @property
    def ae_threshold(self) -> float:
        """Get Autoencoder anomaly threshold."""
        return self._ae_threshold


def load_predictor() -> HybridPredictor:
    """Convenience function to create a HybridPredictor with default paths.
    
    Returns:
        Configured HybridPredictor instance
    """
    return HybridPredictor()


__all__ = [
    "HybridPredictor",
    "HybridPrediction",
    "Verdict",
    "load_predictor",
]
