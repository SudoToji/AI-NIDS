"""
UNSW-NB15 Dataset Processor
===========================
Handles loading, categorical encoding, scaling, and splitting
of the UNSW-NB15 dataset for model training.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

LOGGER = logging.getLogger(__name__)

@dataclass(frozen=True)
class UNSWSplit:
    """Immutable container for the processed dataset splits."""
    x_train: np.ndarray
    x_val: np.ndarray
    x_test: np.ndarray
    
    y_train_bin: np.ndarray
    y_val_bin: np.ndarray
    y_test_bin: np.ndarray
    
    y_train_multi: np.ndarray
    y_val_multi: np.ndarray
    y_test_multi: np.ndarray
    
    scaler: StandardScaler
    label_encoders: Dict[str, LabelEncoder]
    feature_names: list[str]


class SafeLabelEncoder(LabelEncoder):
    """A LabelEncoder that handles unseen categories gracefully."""
    def transform(self, y):
        # Handle unseen labels by assigning them to a special 'unknown' category (-1)
        check = np.array([item if item in self.classes_ else 'unknown_cat' for item in y])
        
        # If 'unknown_cat' is not in classes, we temporarily add it
        if 'unknown_cat' not in self.classes_:
            self.classes_ = np.append(self.classes_, 'unknown_cat')
            
        return super().transform(check)


def load_and_preprocess_unsw(
    train_path: str, 
    test_path: str, 
    val_size: float = 0.2, 
    random_state: int = 42
) -> UNSWSplit:
    """
    Loads and processes the UNSW-NB15 dataset.
    
    Args:
        train_path: Path to the training CSV.
        test_path: Path to the testing CSV.
        val_size: Proportion of training data to use for validation.
        random_state: Seed for reproducibility.
        
    Returns:
        UNSWSplit object containing all processed data and scalers.
    """
    LOGGER.info(f"Loading train data from {train_path}")
    df_train = pd.read_csv(train_path)
    
    LOGGER.info(f"Loading test data from {test_path}")
    df_test = pd.read_csv(test_path)
    
    # Standardize column names (strip whitespace, lowercase)
    df_train.columns = df_train.columns.str.strip().str.lower()
    df_test.columns = df_test.columns.str.strip().str.lower()
    
    # Fill missing values in attack_cat with 'Normal'
    df_train['attack_cat'] = df_train['attack_cat'].fillna('Normal').replace(' ', 'Normal')
    df_test['attack_cat'] = df_test['attack_cat'].fillna('Normal').replace(' ', 'Normal')
    
    # Strip whitespace from attack categories to prevent duplicates (e.g., 'Backdoor' vs 'Backdoor ')
    df_train['attack_cat'] = df_train['attack_cat'].str.strip()
    df_test['attack_cat'] = df_test['attack_cat'].str.strip()
    
    # 1. Drop IDs
    if 'id' in df_train.columns:
        df_train = df_train.drop(columns=['id'])
    if 'id' in df_test.columns:
        df_test = df_test.drop(columns=['id'])
        
    # 2. Separate Targets
    y_train_bin = df_train.pop('label').to_numpy(dtype=np.int32)
    y_test_bin = df_test.pop('label').to_numpy(dtype=np.int32)
    
    y_train_multi = df_train.pop('attack_cat').to_numpy(dtype=object)
    y_test_multi = df_test.pop('attack_cat').to_numpy(dtype=object)
    
    # 3. Identify Categorical Columns
    categorical_cols = df_train.select_dtypes(include=['object', 'category']).columns.tolist()
    
    # 4. Encode Categorical Columns
    encoders = {}
    for col in categorical_cols:
        # Convert to string and fill NaNs
        df_train[col] = df_train[col].astype(str).fillna('missing')
        df_test[col] = df_test[col].astype(str).fillna('missing')
        
        encoder = SafeLabelEncoder()
        # Fit on train with the explicit unknown category included
        classes = df_train[col].unique().tolist()
        classes.append('unknown_cat')
        encoder.fit(classes)
        
        df_train[col] = encoder.transform(df_train[col]).astype(np.float32)
        df_test[col] = encoder.transform(df_test[col]).astype(np.float32)
        encoders[col] = encoder
        
    # Save feature names before converting to numpy
    feature_names = df_train.columns.tolist()
    
    # 5. Create Validation Split
    X_train_full = df_train.to_numpy(dtype=np.float32)
    
    # Only stratify if we have enough samples in the validation set to cover all classes
    n_samples = len(y_train_bin)
    val_samples = int(n_samples * val_size)
    n_classes = len(np.unique(y_train_bin))
    
    stratify_target = y_train_bin if val_samples >= n_classes else None
    
    X_train, X_val, y_train_bin, y_val_bin, y_train_multi, y_val_multi = train_test_split(
        X_train_full, y_train_bin, y_train_multi, 
        test_size=val_size, 
        random_state=random_state,
        stratify=stratify_target
    )
    
    X_test = df_test.to_numpy(dtype=np.float32)
    
    # 6. Scale Numerical Features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val = scaler.transform(X_val)
    X_test = scaler.transform(X_test)
    
    LOGGER.info(f"Processed splits - Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")
    
    return UNSWSplit(
        x_train=X_train,
        x_val=X_val,
        x_test=X_test,
        y_train_bin=y_train_bin,
        y_val_bin=y_val_bin,
        y_test_bin=y_test_bin,
        y_train_multi=y_train_multi,
        y_val_multi=y_val_multi,
        y_test_multi=y_test_multi,
        scaler=scaler,
        label_encoders=encoders,
        feature_names=feature_names
    )
