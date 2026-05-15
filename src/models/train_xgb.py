"""XGBoost training for UNSW-NB15 (42 features)."""
from __future__ import annotations
import logging
import os
from typing import Tuple
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import classification_report
from src.features.unsw_processor import load_and_preprocess_unsw

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

FAST_PARAMS = {
    'n_estimators': 100, 'max_depth': 10, 'learning_rate': 0.1,
    'subsample': 0.8, 'colsample_bytree': 0.8, 'random_state': 42,
    'verbosity': 0, 'n_jobs': -1
}

def train_xgboost() -> Tuple[XGBClassifier, dict]:
    train_path = os.path.join(PROJECT_ROOT, "data", "unsw_nb15", "Training and Testing Sets", "UNSW_NB15_training-set.csv")
    test_path = os.path.join(PROJECT_ROOT, "data", "unsw_nb15", "Training and Testing Sets", "UNSW_NB15_testing-set.csv")
    split = load_and_preprocess_unsw(train_path, test_path)
    class_labels = list(np.unique(np.concatenate((split.y_train_multi, split.y_test_multi))))
    
    LOGGER.info("Training XGBoost on %d rows with %d features", split.x_train.shape[0], split.x_train.shape[1])
    
    # Encode string labels to integers for XGBoost
    label_map = {l: i for i, l in enumerate(class_labels)}
    y_train_int = np.array([label_map[l] for l in split.y_train_multi])
    y_test_int = np.array([label_map[l] for l in split.y_test_multi])
    
    xgb = XGBClassifier(**FAST_PARAMS)
    xgb.fit(split.x_train, y_train_int)
    
    y_pred_int = xgb.predict(split.x_test)
    y_pred = np.array([class_labels[i] for i in y_pred_int])
    LOGGER.info("Classification report:\n%s", classification_report(split.y_test_multi, y_pred, target_names=class_labels, zero_division=0))
    
    model_path = os.path.join(PROJECT_ROOT, "models", "xgb_model.json")
    xgb.save_model(model_path)
    LOGGER.info("Saved XGBoost model to %s", model_path)
    
    metadata_path = os.path.join(PROJECT_ROOT, "models", "xgb_metadata.pkl")
    joblib.dump({"class_labels": class_labels, "label_map": label_map}, metadata_path)
    LOGGER.info("Saved XGB metadata to %s", metadata_path)
    
    return xgb, {"class_labels": class_labels, "label_map": label_map}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_xgboost()
