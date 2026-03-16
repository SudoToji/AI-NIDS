"""Random Forest training for CIC-IDS2017."""

from __future__ import annotations

import logging
import os
from typing import Dict, Tuple

import joblib
import matplotlib.pyplot as plt
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, train_test_split
from sklearn.utils.class_weight import compute_class_weight

try:
    from tqdm.auto import tqdm
except ImportError:  # pragma: no cover
    tqdm = None

from src.features.extractor import FEATURE_COLUMNS, prepare_splits

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

MODEL_PATH_ENV = "RF_MODEL_PATH"
DEFAULT_MODEL_PATH = "models/rf_model.pkl"
METADATA_PATH_ENV = "RF_METADATA_PATH"
DEFAULT_METADATA_PATH = "models/rf_metadata.pkl"
FEATURE_IMPORTANCE_PATH_ENV = "RF_FEATURE_IMPORTANCE_PATH"
DEFAULT_FEATURE_IMPORTANCE_PATH = "models/rf_feature_importance.png"
ENABLE_TUNING_ENV = "RF_ENABLE_TUNING"
CV_FOLDS_ENV = "RF_CV_FOLDS"
SEARCH_ITER_ENV = "RF_SEARCH_ITER"
SHOW_PROGRESS_ENV = "SHOW_PROGRESS"
RF_PROGRESS_STEP_ENV = "RF_PROGRESS_STEP"
RF_THRESHOLD_TUNING_ENV = "RF_THRESHOLD_TUNING"
RF_VALIDATION_SIZE_ENV = "RF_VALIDATION_SIZE"

DEFAULT_CV_FOLDS = 3
DEFAULT_SEARCH_ITER = 8
DEFAULT_RF_PROGRESS_STEP = 10
DEFAULT_RF_VALIDATION_SIZE = 0.1
BOT_LABEL = "Bots"

PARAM_DISTRIBUTIONS = {
    "n_estimators": [120, 180, 240],
    "max_depth": [12, 20, None],
    "min_samples_split": [2, 4, 8],
    "min_samples_leaf": [1, 2, 4],
    "max_features": ["sqrt", "log2"],
}

FAST_PARAMS = {
    "n_estimators": 120,
    "max_depth": 20,
    "min_samples_split": 4,
    "min_samples_leaf": 2,
    "max_features": "sqrt",
}


def _resolve_path(env_key: str, default_path: str) -> str:
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)


def _resolve_int(env_key: str, default_value: int) -> int:
    try:
        return int(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


def _resolve_bool(env_key: str, default: bool = False) -> bool:
    raw_value = os.getenv(env_key)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _resolve_float(env_key: str, default_value: float) -> float:
    try:
        return float(os.getenv(env_key, default_value))
    except ValueError:
        LOGGER.warning("Invalid %s value. Using default %s", env_key, default_value)
        return default_value


def _predict_from_probabilities(
    probabilities: np.ndarray,
    class_labels: list[str],
    thresholds: Dict[str, float] | None = None,
) -> np.ndarray:
    predictions = np.argmax(probabilities, axis=1)
    if not thresholds:
        return predictions

    sorted_indices = np.argsort(probabilities, axis=1)
    class_to_index = {label: index for index, label in enumerate(class_labels)}

    for label, threshold in thresholds.items():
        class_index = class_to_index.get(label)
        if class_index is None:
            continue

        force_mask = probabilities[:, class_index] >= threshold
        predictions[force_mask] = class_index

        demote_mask = (predictions == class_index) & (~force_mask)
        if np.any(demote_mask):
            predictions[demote_mask] = sorted_indices[demote_mask, -2]

    return predictions


def predict_with_thresholds(
    model: RandomForestClassifier,
    x: np.ndarray,
    class_labels: list[str],
    thresholds: Dict[str, float] | None = None,
) -> np.ndarray:
    probabilities = model.predict_proba(x)
    return _predict_from_probabilities(probabilities, class_labels, thresholds)


def _tune_thresholds(
    model: RandomForestClassifier,
    x_val: np.ndarray,
    y_val: np.ndarray,
    class_labels: list[str],
) -> Dict[str, float]:
    if BOT_LABEL not in class_labels:
        return {}

    bot_index = class_labels.index(BOT_LABEL)
    probabilities = model.predict_proba(x_val)
    y_true = (y_val == bot_index).astype(int)

    best_threshold = None
    best_metrics = None
    for threshold in np.linspace(0.05, 0.99, 48):
        predictions = _predict_from_probabilities(probabilities, class_labels, {BOT_LABEL: float(threshold)})
        y_pred = (predictions == bot_index).astype(int)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_true,
            y_pred,
            average="binary",
            zero_division=0,
        )
        metrics = (f1, precision, recall)
        if best_metrics is None or metrics > best_metrics:
            best_threshold = float(threshold)
            best_metrics = metrics

    if best_threshold is None or best_metrics is None:
        return {}

    LOGGER.info(
        "Selected %s threshold %.2f (precision=%.4f recall=%.4f f1=%.4f)",
        BOT_LABEL,
        best_threshold,
        best_metrics[1],
        best_metrics[2],
        best_metrics[0],
    )
    return {BOT_LABEL: best_threshold}


def _fit_fast_model_with_progress(
    model: RandomForestClassifier,
    x_train,
    y_train,
) -> RandomForestClassifier:
    show_progress = _resolve_bool(SHOW_PROGRESS_ENV, default=True)
    if not show_progress or tqdm is None:
        model.fit(x_train, y_train)
        return model

    classes = np.unique(y_train)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=y_train)
    class_weight = {int(cls): float(weight) for cls, weight in zip(classes, weights)}

    total_estimators = int(model.n_estimators)
    progress_step = max(1, min(_resolve_int(RF_PROGRESS_STEP_ENV, DEFAULT_RF_PROGRESS_STEP), total_estimators))
    model.set_params(warm_start=True, n_estimators=0, class_weight=class_weight)

    trained_estimators = 0
    with tqdm(total=total_estimators, desc="Training RF trees", unit="tree") as progress:
        while trained_estimators < total_estimators:
            trained_estimators = min(trained_estimators + progress_step, total_estimators)
            model.set_params(n_estimators=trained_estimators)
            model.fit(x_train, y_train)
            progress.update(trained_estimators - progress.n)

    model.set_params(warm_start=False)
    return model


def _build_base_model() -> RandomForestClassifier:
    return RandomForestClassifier(
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )


def train_random_forest() -> Tuple[RandomForestClassifier, Dict[str, float]]:
    """Train a Random Forest classifier.

    By default this uses a faster fixed-parameter model. Set RF_ENABLE_TUNING=1
    to run a small randomized hyperparameter search.
    """

    split = prepare_splits()
    class_labels = list(split.label_encoder.classes_)
    LOGGER.info(
        "Training Random Forest on %d rows with %d features",
        split.x_train.shape[0],
        split.x_train.shape[1],
    )

    enable_tuning = _resolve_bool(ENABLE_TUNING_ENV, default=False)
    enable_threshold_tuning = _resolve_bool(RF_THRESHOLD_TUNING_ENV, default=True)
    validation_size = _resolve_float(RF_VALIDATION_SIZE_ENV, DEFAULT_RF_VALIDATION_SIZE)
    base_model = _build_base_model()
    thresholds: Dict[str, float] = {}

    x_model_train = split.x_train
    y_model_train = split.y_train
    x_val = None
    y_val = None
    if enable_threshold_tuning:
        x_model_train, x_val, y_model_train, y_val = train_test_split(
            split.x_train,
            split.y_train,
            test_size=validation_size,
            random_state=42,
            stratify=split.y_train,
        )
        LOGGER.info("Reserved %d rows for threshold tuning", len(y_val))

    if enable_tuning:
        cv_folds = _resolve_int(CV_FOLDS_ENV, DEFAULT_CV_FOLDS)
        search_iter = _resolve_int(SEARCH_ITER_ENV, DEFAULT_SEARCH_ITER)
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        search = RandomizedSearchCV(
            estimator=base_model,
            param_distributions=PARAM_DISTRIBUTIONS,
            n_iter=search_iter,
            scoring="f1_weighted",
            cv=cv,
            n_jobs=-1,
            verbose=3,
            random_state=42,
        )
        LOGGER.info(
            "Starting randomized search with %d iterations and %d-fold CV",
            search_iter,
            cv_folds,
        )
        search.fit(x_model_train, y_model_train)
        tuned_model: RandomForestClassifier = search.best_estimator_
        LOGGER.info("Best parameters: %s", search.best_params_)
        if x_val is not None and y_val is not None:
            thresholds = _tune_thresholds(tuned_model, x_val, y_val, class_labels)
        tuned_params = {**base_model.get_params(), **search.best_params_}
        model = RandomForestClassifier(**tuned_params)
        model.fit(split.x_train, split.y_train)
    else:
        fast_params = {**base_model.get_params(), **FAST_PARAMS}
        if x_val is not None and y_val is not None:
            threshold_model = RandomForestClassifier(**fast_params)
            LOGGER.info("Training threshold-tuning Random Forest with params: %s", FAST_PARAMS)
            threshold_model = _fit_fast_model_with_progress(threshold_model, x_model_train, y_model_train)
            thresholds = _tune_thresholds(threshold_model, x_val, y_val, class_labels)
        model = RandomForestClassifier(**fast_params)
        LOGGER.info("Training final Random Forest with params: %s", FAST_PARAMS)
        model = _fit_fast_model_with_progress(model, split.x_train, split.y_train)

    y_pred = predict_with_thresholds(model, split.x_test, class_labels, thresholds)
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

    model_path = _resolve_path(MODEL_PATH_ENV, DEFAULT_MODEL_PATH)
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    LOGGER.info("Saved Random Forest model to %s", model_path)

    metadata_path = _resolve_path(METADATA_PATH_ENV, DEFAULT_METADATA_PATH)
    os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
    joblib.dump({"class_labels": class_labels, "thresholds": thresholds}, metadata_path)
    LOGGER.info("Saved Random Forest metadata to %s", metadata_path)

    _save_feature_importance(model)

    return model, {
        "accuracy": float(report.get("accuracy", 0.0)),
        "weighted_f1": float(report.get("weighted avg", {}).get("f1-score", 0.0)),
        "bots_f1": float(report.get(BOT_LABEL, {}).get("f1-score", 0.0)),
        "bots_precision": float(report.get(BOT_LABEL, {}).get("precision", 0.0)),
        "bots_recall": float(report.get(BOT_LABEL, {}).get("recall", 0.0)),
    }


def _save_feature_importance(model: RandomForestClassifier) -> None:
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(range(len(importances)), importances[indices])
    ax.set_xticks(range(len(importances)))
    ax.set_xticklabels([FEATURE_COLUMNS[idx] for idx in indices], rotation=90, fontsize=8)
    ax.set_title("Random Forest Feature Importance")
    ax.set_ylabel("Importance")
    fig.tight_layout()

    output_path = _resolve_path(FEATURE_IMPORTANCE_PATH_ENV, DEFAULT_FEATURE_IMPORTANCE_PATH)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fig.savefig(output_path)
    plt.close(fig)
    LOGGER.info("Saved feature importance plot to %s", output_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_random_forest()
