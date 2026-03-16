"""Feature extraction and preprocessing utilities for CIC-IDS2017."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Iterable, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

try:
    from tqdm.auto import tqdm
except ImportError:  # pragma: no cover
    tqdm = None

LOGGER = logging.getLogger(__name__)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

DATA_PATH_ENV = "CICIDS_DATA_PATH"
SCALER_PATH_ENV = "SCALER_PATH"
TEST_SIZE_ENV = "TEST_SIZE"
RANDOM_STATE_ENV = "RANDOM_STATE"
MAX_ROWS_ENV = "MAX_ROWS"
MAX_SAMPLES_PER_CLASS_ENV = "MAX_SAMPLES_PER_CLASS"
SHOW_PROGRESS_ENV = "SHOW_PROGRESS"
LOAD_CHUNK_SIZE_ENV = "LOAD_CHUNK_SIZE"

DEFAULT_DATA_PATH = "data/processed/cicids2017_cleaned.csv"
DEFAULT_SCALER_PATH = "models/scaler.pkl"
DEFAULT_TEST_SIZE = 0.2
DEFAULT_RANDOM_STATE = 42
DEFAULT_MAX_ROWS = 200_000
DEFAULT_MAX_SAMPLES_PER_CLASS = 30_000
DEFAULT_LOAD_CHUNK_SIZE = 100_000

LABEL_COLUMN = "Attack Type"

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Subflow Fwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Max",
    "Idle Min",
]


@dataclass(frozen=True)
class DatasetSplit:
    """Container for train/test splits."""

    x_train: np.ndarray
    x_test: np.ndarray
    y_train: np.ndarray
    y_test: np.ndarray
    label_encoder: LabelEncoder
    scaler: StandardScaler


def _resolve_project_path(path_value: str) -> str:
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)


def _get_env_path(env_key: str, default: str) -> str:
    return _resolve_project_path(os.getenv(env_key, default))


def _get_env_float(env_key: str, default: float) -> float:
    try:
        return float(os.getenv(env_key, default))
    except ValueError:
        LOGGER.warning("Invalid %s value, using default %s", env_key, default)
        return default


def _get_env_int(env_key: str, default: int) -> int:
    try:
        return int(os.getenv(env_key, default))
    except ValueError:
        LOGGER.warning("Invalid %s value, using default %s", env_key, default)
        return default


def _get_env_optional_int(env_key: str, default: int | None = None) -> int | None:
    raw_value = os.getenv(env_key)
    if raw_value is None:
        return default

    normalized = raw_value.strip().lower()
    if normalized in {"", "none", "null", "false", "0", "off", "no"}:
        return None

    try:
        value = int(raw_value)
    except ValueError:
        LOGGER.warning("Invalid %s value, using default %s", env_key, default)
        return default

    return value if value > 0 else None


def _get_env_bool(env_key: str, default: bool = True) -> bool:
    raw_value = os.getenv(env_key)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def _count_csv_rows(path: str) -> int | None:
    if tqdm is None:
        return None

    line_count = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            line_count += chunk.count(b"\n")

    return max(line_count - 1, 0)


def _validate_columns(df: pd.DataFrame, required: Iterable[str]) -> None:
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")


def load_dataset(path: str | None = None) -> pd.DataFrame:
    """Load CIC-IDS2017 dataset with memory-friendlier dtypes."""

    data_path = path or _get_env_path(DATA_PATH_ENV, DEFAULT_DATA_PATH)
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Dataset not found at {data_path}")

    LOGGER.info("Loading dataset from %s", data_path)
    dtype_map = {column: np.float32 for column in FEATURE_COLUMNS}
    dtype_map[LABEL_COLUMN] = "string"
    show_progress = _get_env_bool(SHOW_PROGRESS_ENV, default=True)
    chunk_size = _get_env_int(LOAD_CHUNK_SIZE_ENV, DEFAULT_LOAD_CHUNK_SIZE)

    if show_progress and tqdm is not None:
        total_rows = _count_csv_rows(data_path)
        reader = pd.read_csv(
            data_path,
            usecols=FEATURE_COLUMNS + [LABEL_COLUMN],
            dtype=dtype_map,
            low_memory=False,
            chunksize=chunk_size,
        )
        chunks = []
        with tqdm(total=total_rows, desc="Loading dataset", unit="rows") as progress:
            for chunk in reader:
                chunk.columns = chunk.columns.str.strip()
                chunks.append(chunk)
                progress.update(len(chunk))
        df = pd.concat(chunks, ignore_index=True)
    else:
        df = pd.read_csv(
            data_path,
            usecols=FEATURE_COLUMNS + [LABEL_COLUMN],
            dtype=dtype_map,
            low_memory=False,
        )
        df.columns = df.columns.str.strip()

    LOGGER.info("Loaded dataset with shape %s", df.shape)
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Remove rows with non-finite values and missing labels."""

    df = df.copy()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(axis=0, inplace=True)
    df = df[df[LABEL_COLUMN].astype(str).str.len() > 0]
    return df


def sample_dataset(
    df: pd.DataFrame,
    *,
    max_rows: int | None = None,
    max_samples_per_class: int | None = None,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> pd.DataFrame:
    """Down-sample the dataset to keep training practical on modest hardware."""

    sampled = df

    if max_samples_per_class is not None:
        LOGGER.info("Applying per-class cap of %d rows", max_samples_per_class)
        grouped = list(sampled.groupby(LABEL_COLUMN, sort=False))
        group_iterator = grouped
        if _get_env_bool(SHOW_PROGRESS_ENV, default=True) and tqdm is not None:
            group_iterator = tqdm(grouped, desc="Sampling classes", unit="class")

        sampled_groups = []
        for _, group in group_iterator:
            sampled_groups.append(
                group.sample(
                    n=min(len(group), max_samples_per_class),
                    random_state=random_state,
                )
            )
        sampled = pd.concat(sampled_groups, ignore_index=True)
        LOGGER.info("Shape after per-class cap: %s", sampled.shape)

    if max_rows is not None and len(sampled) > max_rows:
        LOGGER.info("Applying global row cap of %d rows", max_rows)
        sampled, _ = train_test_split(
            sampled,
            train_size=max_rows,
            random_state=random_state,
            stratify=sampled[LABEL_COLUMN],
        )
        sampled = sampled.reset_index(drop=True)
        LOGGER.info("Shape after global cap: %s", sampled.shape)

    return sampled


def encode_labels(labels: pd.Series) -> Tuple[np.ndarray, LabelEncoder]:
    """Encode attack labels into integer values."""

    encoder = LabelEncoder()
    encoded = encoder.fit_transform(labels.astype(str))
    return encoded, encoder


def scale_features(features: pd.DataFrame, scaler: StandardScaler | None = None) -> Tuple[np.ndarray, StandardScaler]:
    """Scale numeric feature columns using StandardScaler."""

    scaler = scaler or StandardScaler()
    scaled = scaler.fit_transform(features).astype(np.float32)
    return scaled, scaler


def save_scaler(scaler: StandardScaler, path: str | None = None) -> str:
    """Persist scaler to disk."""

    scaler_path = path or _get_env_path(SCALER_PATH_ENV, DEFAULT_SCALER_PATH)
    os.makedirs(os.path.dirname(scaler_path), exist_ok=True)
    joblib.dump(scaler, scaler_path)
    LOGGER.info("Saved scaler to %s", scaler_path)
    return scaler_path


def load_scaler(path: str | None = None) -> StandardScaler:
    """Load a saved scaler from disk."""

    scaler_path = path or _get_env_path(SCALER_PATH_ENV, DEFAULT_SCALER_PATH)
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"Scaler not found at {scaler_path}")
    return joblib.load(scaler_path)


def prepare_splits(
    path: str | None = None,
    test_size: float | None = None,
    random_state: int | None = None,
    scaler_path: str | None = None,
) -> DatasetSplit:
    """Prepare train/test splits with scaling and label encoding."""

    seed = random_state if random_state is not None else _get_env_int(RANDOM_STATE_ENV, DEFAULT_RANDOM_STATE)
    max_rows = _get_env_optional_int(MAX_ROWS_ENV, DEFAULT_MAX_ROWS)
    max_samples_per_class = _get_env_optional_int(
        MAX_SAMPLES_PER_CLASS_ENV,
        DEFAULT_MAX_SAMPLES_PER_CLASS,
    )

    df = load_dataset(path)
    _validate_columns(df, FEATURE_COLUMNS + [LABEL_COLUMN])

    df = clean_dataset(df)
    LOGGER.info("Shape after cleaning: %s", df.shape)
    df = sample_dataset(
        df,
        max_rows=max_rows,
        max_samples_per_class=max_samples_per_class,
        random_state=seed,
    )

    labels = df[LABEL_COLUMN]
    features = df[FEATURE_COLUMNS]

    y_encoded, encoder = encode_labels(labels)
    test_fraction = test_size if test_size is not None else _get_env_float(TEST_SIZE_ENV, DEFAULT_TEST_SIZE)

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        y_encoded,
        test_size=test_fraction,
        random_state=seed,
        stratify=y_encoded,
    )

    LOGGER.info("Train/test shapes before scaling: x_train=%s x_test=%s", x_train.shape, x_test.shape)
    x_train_scaled, scaler = scale_features(x_train)
    x_test_scaled = scaler.transform(x_test).astype(np.float32)
    save_scaler(scaler, scaler_path)

    return DatasetSplit(
        x_train=x_train_scaled,
        x_test=x_test_scaled,
        y_train=y_train,
        y_test=y_test,
        label_encoder=encoder,
        scaler=scaler,
    )


def filter_benign(x: np.ndarray, y: np.ndarray, label_encoder: LabelEncoder) -> np.ndarray:
    """Filter features to benign-only rows for autoencoder training."""

    benign_label = "Normal Traffic"
    if benign_label not in label_encoder.classes_:
        raise ValueError("Benign label not found in label encoder classes.")

    benign_index = int(np.where(label_encoder.classes_ == benign_label)[0][0])
    benign = x[y == benign_index]
    LOGGER.info("Selected %d benign rows for autoencoder training", benign.shape[0])
    return benign


def extract_live_features(flow: Dict) -> pd.DataFrame:
    """Extract CIC-IDS2017-style features from a live network flow.
    
    This function computes the same 52 features used in training from
    a flow dictionary produced by the packet sniffer.
    
    Args:
        flow: Dictionary containing flow data with keys:
            - src_ip, dst_ip, src_port, dst_port, protocol
            - packets: list of {timestamp, size, flags, direction}
            - start_time, end_time
            
    Returns:
        DataFrame with exactly FEATURE_COLUMNS (52 features)
        
    Example:
        >>> flow_dict = {
        ...     "src_ip": "192.168.1.100",
        ...     "dst_ip": "10.0.0.1",
        ...     "src_port": 45678,
        ...     "dst_port": 80,
        ...     "protocol": 6,
        ...     "packets": [
        ...         {"timestamp": 1.0, "size": 60, "flags": 0x02, "direction": "fwd"},
        ...         {"timestamp": 1.1, "size": 500, "flags": 0x10, "direction": "bwd"},
        ...     ],
        ...     "start_time": 1.0,
        ...     "end_time": 1.1,
        ... }
        >>> features_df = extract_live_features(flow_dict)
    """
    packets = flow.get("packets", [])
    
    if not packets:
        LOGGER.warning("Empty flow received, returning zeros")
        return pd.DataFrame(np.zeros((1, len(FEATURE_COLUMNS))), columns=FEATURE_COLUMNS)
    
    timestamps = np.array([p["timestamp"] for p in packets])
    sizes = np.array([p["size"] for p in packets])
    directions = np.array([1 if p["direction"] == "fwd" else 0 for p in packets])
    flags = np.array([p.get("flags", 0) for p in packets])
    
    start_time = timestamps[0]
    end_time = timestamps[-1]
    duration = max(end_time - start_time, 1e-6)
    
    fwd_packets = packets if all(p["direction"] == "fwd" for p in packets) else []
    bwd_packets = packets if all(p["direction"] == "bwd" for p in packets) else []
    
    fwd_sizes = np.array([p["size"] for p in packets if p["direction"] == "fwd"])
    bwd_sizes = np.array([p["size"] for p in packets if p["direction"] == "bwd"])
    
    fwd_times = np.array([p["timestamp"] - start_time for p in packets if p["direction"] == "fwd"])
    bwd_times = np.array([p["timestamp"] - start_time for p in packets if p["direction"] == "bwd"])
    
    features = {
        "Destination Port": flow.get("dst_port", 0),
        "Flow Duration": duration * 1000,
        "Total Fwd Packets": len(fwd_packets) if fwd_packets else len([p for p in packets if p["direction"] == "fwd"]),
        "Total Length of Fwd Packets": float(np.sum(fwd_sizes)) if len(fwd_sizes) > 0 else 0.0,
        "Fwd Packet Length Max": float(np.max(fwd_sizes)) if len(fwd_sizes) > 0 else 0.0,
        "Fwd Packet Length Min": float(np.min(fwd_sizes)) if len(fwd_sizes) > 0 else 0.0,
        "Fwd Packet Length Mean": float(np.mean(fwd_sizes)) if len(fwd_sizes) > 0 else 0.0,
        "Fwd Packet Length Std": float(np.std(fwd_sizes)) if len(fwd_sizes) > 1 else 0.0,
        "Bwd Packet Length Max": float(np.max(bwd_sizes)) if len(bwd_sizes) > 0 else 0.0,
        "Bwd Packet Length Min": float(np.min(bwd_sizes)) if len(bwd_sizes) > 0 else 0.0,
        "Bwd Packet Length Mean": float(np.mean(bwd_sizes)) if len(bwd_sizes) > 0 else 0.0,
        "Bwd Packet Length Std": float(np.std(bwd_sizes)) if len(bwd_sizes) > 1 else 0.0,
        "Flow Bytes/s": float(np.sum(sizes)) / duration if duration > 0 else 0.0,
        "Flow Packets/s": float(len(packets)) / duration if duration > 0 else 0.0,
        "Flow IAT Mean": _compute_iat_mean(timestamps),
        "Flow IAT Std": _compute_iat_std(timestamps),
        "Flow IAT Max": _compute_iat_max(timestamps),
        "Flow IAT Min": _compute_iat_min(timestamps),
        "Fwd IAT Total": float(np.sum(fwd_times)) if len(fwd_times) > 0 else 0.0,
        "Fwd IAT Mean": float(np.mean(fwd_times)) if len(fwd_times) > 0 else 0.0,
        "Fwd IAT Std": float(np.std(fwd_times)) if len(fwd_times) > 1 else 0.0,
        "Fwd IAT Max": float(np.max(fwd_times)) if len(fwd_times) > 0 else 0.0,
        "Fwd IAT Min": float(np.min(fwd_times)) if len(fwd_times) > 0 else 0.0,
        "Bwd IAT Total": float(np.sum(bwd_times)) if len(bwd_times) > 0 else 0.0,
        "Bwd IAT Mean": float(np.mean(bwd_times)) if len(bwd_times) > 0 else 0.0,
        "Bwd IAT Std": float(np.std(bwd_times)) if len(bwd_times) > 1 else 0.0,
        "Bwd IAT Max": float(np.max(bwd_times)) if len(bwd_times) > 0 else 0.0,
        "Bwd IAT Min": float(np.min(bwd_times)) if len(bwd_times) > 0 else 0.0,
        "Fwd Header Length": sum(40 for p in packets if p["direction"] == "fwd"),
        "Bwd Header Length": sum(40 for p in packets if p["direction"] == "bwd"),
        "Fwd Packets/s": float(len([p for p in packets if p["direction"] == "fwd"])) / duration if duration > 0 else 0.0,
        "Bwd Packets/s": float(len([p for p in packets if p["direction"] == "bwd"])) / duration if duration > 0 else 0.0,
        "Min Packet Length": float(np.min(sizes)),
        "Max Packet Length": float(np.max(sizes)),
        "Packet Length Mean": float(np.mean(sizes)),
        "Packet Length Std": float(np.std(sizes)) if len(sizes) > 1 else 0.0,
        "Packet Length Variance": float(np.var(sizes)) if len(sizes) > 1 else 0.0,
        "FIN Flag Count": int(np.sum((flags & 0x01) != 0)),
        "PSH Flag Count": int(np.sum((flags & 0x08) != 0)),
        "ACK Flag Count": int(np.sum((flags & 0x10) != 0)),
        "Average Packet Size": float(np.mean(sizes)),
        "Subflow Fwd Bytes": float(np.sum(fwd_sizes)),
        "Init_Win_bytes_forward": 64240,
        "Init_Win_bytes_backward": 65535,
        "act_data_pkt_fwd": len(fwd_packets) if fwd_packets else len([p for p in packets if p["direction"] == "fwd"]),
        "min_seg_size_forward": 40,
        "Active Mean": 0.0,
        "Active Max": 0.0,
        "Active Min": 0.0,
        "Idle Mean": 0.0,
        "Idle Max": 0.0,
        "Idle Min": 0.0,
    }
    
    return pd.DataFrame([features])[FEATURE_COLUMNS]


def _compute_iat_mean(timestamps: np.ndarray) -> float:
    """Compute mean inter-arrival time."""
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(timestamps)
    return float(np.mean(iats)) if len(iats) > 0 else 0.0


def _compute_iat_std(timestamps: np.ndarray) -> float:
    """Compute std of inter-arrival time."""
    if len(timestamps) < 3:
        return 0.0
    iats = np.diff(timestamps)
    return float(np.std(iats)) if len(iats) > 0 else 0.0


def _compute_iat_max(timestamps: np.ndarray) -> float:
    """Compute max inter-arrival time."""
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(timestamps)
    return float(np.max(iats)) if len(iats) > 0 else 0.0


def _compute_iat_min(timestamps: np.ndarray) -> float:
    """Compute min inter-arrival time."""
    if len(timestamps) < 2:
        return 0.0
    iats = np.diff(timestamps)
    return float(np.min(iats)) if len(iats) > 0 else 0.0


__all__ = [
    "DatasetSplit",
    "FEATURE_COLUMNS",
    "LABEL_COLUMN",
    "load_dataset",
    "clean_dataset",
    "sample_dataset",
    "encode_labels",
    "scale_features",
    "save_scaler",
    "load_scaler",
    "prepare_splits",
    "filter_benign",
    "extract_live_features",
]
