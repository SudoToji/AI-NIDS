"""Random Forest training for UNSW-NB15."""
from __future__ import annotations
import logging
import os
from typing import Dict, Tuple
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from src.features.unsw_processor import load_and_preprocess_unsw

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MODEL_PATH_ENV = "RF_MODEL_PATH"
DEFAULT_MODEL_PATH = "models/rf_model.pkl"
METADATA_PATH_ENV = "RF_METADATA_PATH"
DEFAULT_METADATA_PATH = "models/rf_metadata.pkl"

FAST_PARAMS = {'n_estimators': 120, 'max_depth': 20, 'min_samples_split': 4, 'min_samples_leaf': 2, 'max_features': 'sqrt'}

def _resolve_path(env_key, default_path):
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)

def predict_with_thresholds(model, x, class_labels, thresholds=None):
    probabilities = model.predict_proba(x)
    return np.argmax(probabilities, axis=1)

def train_random_forest():
    train_path = os.path.join(PROJECT_ROOT, "data", "unsw_nb15", "Training and Testing Sets", "UNSW_NB15_training-set.csv")
    test_path = os.path.join(PROJECT_ROOT, "data", "unsw_nb15", "Training and Testing Sets", "UNSW_NB15_testing-set.csv")
    split = load_and_preprocess_unsw(train_path, test_path)
    
    x_train_full = split.x_train
    y_train_full = split.y_train_multi
    x_test = split.x_test
    y_test = split.y_test_multi
    class_labels = list(np.unique(np.concatenate((y_train_full, y_test))))
    
    LOGGER.info("Training Random Forest on %d rows with %d features", x_train_full.shape[0], x_train_full.shape[1])
    
    model = RandomForestClassifier(random_state=42, n_jobs=-1, class_weight="balanced_subsample", **FAST_PARAMS)
    model.fit(x_train_full, y_train_full)
    
    y_pred = model.predict(x_test)
    LOGGER.info("Classification report:\n%s", classification_report(y_test, y_pred, target_names=class_labels, zero_division=0))
    
    model_path = _resolve_path(MODEL_PATH_ENV, DEFAULT_MODEL_PATH)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    
    # Save the scaler here too so we can use it!
    scaler_path = _resolve_path("SCALER_PATH", "models/scaler.pkl")
    joblib.dump(split.scaler, scaler_path)
    
    metadata_path = _resolve_path(METADATA_PATH_ENV, DEFAULT_METADATA_PATH)
    joblib.dump({"class_labels": class_labels, "thresholds": {}}, metadata_path)
    
    return model, {}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_random_forest()