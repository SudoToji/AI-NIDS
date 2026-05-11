"""
Tests for the simulated SIEM stream feed.
"""
import pytest
import os
import pandas as pd
from src.simulator.siem_streamer import SIEMStreamer

@pytest.fixture
def mock_csv(tmp_path):
    """Creates a small mock UNSW-NB15 CSV for testing."""
    df = pd.DataFrame({
        "srcip": ["192.168.1.1", "10.0.0.1"],
        "dstip": ["192.168.1.2", "10.0.0.2"],
        "sport": [12345, 80],
        "dsport": [80, 443],
        "proto": ["tcp", "udp"],
        "attack_cat": ["Normal", "DoS"],
        "Label": [0, 1]
    })
    
    file_path = tmp_path / "mock_unsw.csv"
    df.to_csv(file_path, index=False)
    return str(file_path)

def test_siem_streamer_initialization(mock_csv):
    """Test that the streamer initializes correctly with a valid file."""
    streamer = SIEMStreamer(mock_csv)
    assert streamer.file_path == mock_csv

def test_siem_streamer_missing_file():
    """Test that initialization fails with a FileNotFoundError for missing files."""
    with pytest.raises(FileNotFoundError):
        SIEMStreamer("non_existent_file.csv")

def test_siem_stream_events(mock_csv):
    """Test that the stream yields dictionaries correctly."""
    streamer = SIEMStreamer(mock_csv)
    events = list(streamer.stream_events(limit=2))
    
    assert len(events) == 2
    
    # Check first event structure
    assert isinstance(events[0], dict)
    assert events[0]["srcip"] == "192.168.1.1"
    assert events[0]["Label"] == 0
    
    # Check second event
    assert events[1]["attack_cat"] == "DoS"
    assert events[1]["Label"] == 1
