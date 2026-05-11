"""
Tests for the UNSW-NB15 Data Processor.
"""
import pytest
import os
import pandas as pd
import numpy as np
from src.features.unsw_processor import load_and_preprocess_unsw, UNSWSplit

@pytest.fixture
def mock_unsw_data(tmp_path):
    """Creates mock train and test CSVs for UNSW-NB15."""
    # Create train
    train_df = pd.DataFrame({
        "id": [1, 2, 3, 4, 5],
        "dur": [0.1, 0.2, 0.3, 0.4, 0.5],
        "proto": ["tcp", "udp", "tcp", "tcp", "udp"],
        "service": ["http", "-", "dns", "http", "-"],
        "state": ["FIN", "INT", "FIN", "FIN", "INT"],
        "spkts": [10, 2, 10, 15, 2],
        "attack_cat": ["Normal", "Normal", "Exploits", "DoS", "Normal"],
        "label": [0, 0, 1, 1, 0]
    })
    
    # Create test
    test_df = pd.DataFrame({
        "id": [1, 2, 3],
        "dur": [0.15, 0.25, 0.35],
        "proto": ["tcp", "udp", "icmp"],  # icmp is new in test!
        "service": ["http", "-", "-"],
        "state": ["FIN", "INT", "INT"],
        "spkts": [12, 2, 1],
        "attack_cat": ["Normal", "Exploits", "Normal"],
        "label": [0, 1, 0]
    })
    
    train_path = tmp_path / "mock_train.csv"
    test_path = tmp_path / "mock_test.csv"
    
    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)
    
    return str(train_path), str(test_path)

def test_load_and_preprocess_unsw(mock_unsw_data):
    """Test that the processor correctly loads, encodes, scales, and splits."""
    train_path, test_path = mock_unsw_data
    
    # Run processor with a 20% validation split
    split = load_and_preprocess_unsw(train_path, test_path, val_size=0.2, random_state=42)
    
    # Check output type
    assert isinstance(split, UNSWSplit)
    
    # Check shapes (5 train rows -> 4 train, 1 val. 3 test rows)
    assert len(split.x_train) == 4
    assert len(split.x_val) == 1
    assert len(split.x_test) == 3
    
    # Check targets are separated and correct types
    assert isinstance(split.y_train_bin, np.ndarray)
    assert isinstance(split.y_train_multi, np.ndarray)
    
    # Check that 'id', 'label', 'attack_cat' were removed from features
    # 8 original cols - 3 removed = 5 feature columns
    assert split.x_train.shape[1] == 5
    
    # Check that unknown categories in test (like 'icmp') are handled
    assert not np.isnan(split.x_test).any()
    
    # Check scaler and encoders are present
    assert hasattr(split.scaler, "transform")
    assert "proto" in split.label_encoders
