"""Hybrid ML Engine - Fuses Random Forest and Autoencoder predictions."""
from __future__ import annotations
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict
import joblib
import numpy as np
from tensorflow import keras

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

DEFAULT_RF_MODEL_PATH = "models/rf_model.pkl"
DEFAULT_RF_METADATA_PATH = "models/rf_metadata.pkl"
DEFAULT_AE_MODEL_PATH = "models/autoencoder.keras"
DEFAULT_AE_THRESHOLD_PATH = "models/autoencoder_threshold.npy"
DEFAULT_SCALER_PATH = "models/scaler.pkl"

@dataclass(frozen=True)
class HybridPrediction:
    rf_label: str
    rf_confidence: float
    ae_anomaly_score: float
    ae_is_anomaly: bool
    final_verdict: str
    combined_confidence: float
    timestamp: str
    stage2_reason: str | None = None

class Verdict:
    BENIGN = "Benign"
    SUSPICIOUS = "Suspicious"
    ATTACK = "Attack"

def _resolve_path(env_key, default_path):
    return os.path.join(PROJECT_ROOT, default_path)

class HybridPredictor:
    def __init__(self, rf_model_path=None, rf_metadata_path=None, ae_model_path=None, ae_threshold_path=None, scaler_path=None, use_stage2=False):
        self.use_stage2 = use_stage2
        self.verifier = None
        if self.use_stage2:
            try:
                from src.models.deep_verifier import DeepVerifier
                self.verifier = DeepVerifier()
            except Exception as e:
                LOGGER.error("Failed to load DeepVerifier: %s", e)
                self.use_stage2 = False
        
        self._rf_model = joblib.load(_resolve_path("RF_MODEL_PATH", DEFAULT_RF_MODEL_PATH))
        self._rf_metadata = joblib.load(_resolve_path("RF_METADATA_PATH", DEFAULT_RF_METADATA_PATH))
        self._class_labels = self._rf_metadata.get("class_labels", [])
        
        self._ae_model = keras.models.load_model(_resolve_path("AE_MODEL_PATH", DEFAULT_AE_MODEL_PATH), compile=False)
        
        threshold_path = _resolve_path("AE_THRESHOLD_PATH", DEFAULT_AE_THRESHOLD_PATH)
        if os.path.exists(threshold_path):
            self._ae_threshold = float(np.load(threshold_path)[0])
        else:
            self._ae_threshold = 0.5
            
        self._scaler = joblib.load(_resolve_path("SCALER_PATH", DEFAULT_SCALER_PATH))
        self._input_dim = self._ae_model.input_shape[-1]

    def _predict_rf(self, features):
        probs = self._rf_model.predict_proba(features)[0]
        idx = np.argmax(probs)
        return self._class_labels[idx], float(probs[idx])

    def _predict_autoencoder(self, features):
        reconstruction = self._ae_model.predict(features, verbose=0)
        mse = float(np.mean(np.square(features - reconstruction)))
        return mse, mse > self._ae_threshold

    def _compute_fusion(self, rf_label, rf_confidence, xgb_label="Normal", xgb_confidence=1.0, ae_is_anomaly=False, if_is_anomaly=False):
        rf_is_attack = rf_label not in {"Benign", "Normal Traffic", "Normal"}
        if ae_is_anomaly or if_is_anomaly:
            if not rf_is_attack and rf_confidence >= 0.99:
                return Verdict.SUSPICIOUS, 0.80
        if rf_confidence < 0.90:
            return Verdict.SUSPICIOUS, rf_confidence
        if rf_is_attack and rf_confidence >= 0.99:
            return Verdict.ATTACK, rf_confidence
        if not rf_is_attack and rf_confidence >= 0.99 and not ae_is_anomaly and not if_is_anomaly:
            return Verdict.BENIGN, rf_confidence
        return Verdict.SUSPICIOUS, rf_confidence

    def predict(self, features, raw_features=None):
        if isinstance(features, dict):
            feature_vector = np.array([list(features.values())], dtype=np.float32)
            feature_vector = self._scaler.transform(feature_vector)
        else:
            if features.ndim == 1:
                feature_vector = features.reshape(1, -1)
            else:
                feature_vector = features
            feature_vector = feature_vector.astype(np.float32)
            
        rf_label, rf_conf = self._predict_rf(feature_vector)
        ae_score, ae_anomaly = self._predict_autoencoder(feature_vector)
        verdict, conf = self._compute_fusion(rf_label, rf_conf, ae_is_anomaly=ae_anomaly)
        
        stage2_reason = None
        if verdict == Verdict.SUSPICIOUS and self.use_stage2 and self.verifier is not None:
            if raw_features is not None:
                feature_dict = raw_features
            elif isinstance(features, dict):
                feature_dict = features
            else:
                feature_dict = {f"feature_{i}": v for i, v in enumerate(feature_vector.flatten())}
            
            verdict, stage2_reason = self.verifier.verify_flow(feature_dict, verdict)
            
        return HybridPrediction(rf_label, rf_conf, ae_score, ae_anomaly, verdict, conf, datetime.now(timezone.utc).isoformat(), stage2_reason)
