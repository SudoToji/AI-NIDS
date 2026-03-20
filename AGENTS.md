# AGENTS.md - AI-NIDS Project Guidelines

## Project Overview
This is a Python-based Network Intrusion Detection System (AI-NIDS) using machine learning (Random Forest) and deep learning (Autoencoder) on the CIC-IDS2017 dataset.

## Project Structure (Updated March 2026)
```
Project/
├── src/
│   ├── capture/
│   │   ├── __init__.py
│   │   └── sniffer.py          # Live packet sniffer with 5-tuple flow assembly
│   ├── features/
│   │   ├── __init__.py
│   │   └── extractor.py        # Feature extraction (updated with extract_live_features)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── autoencoder.py       # Autoencoder anomaly detector
│   │   ├── train_rf.py         # Random Forest classifier
│   │   └── hybrid_predictor.py # Hybrid RF+AE fusion (NEW)
│   └── dashboard/
│       ├── __init__.py
│       └── app.py              # Streamlit dashboard (NEW)
├── models/                     # Trained model artifacts
│   ├── rf_model.pkl           # Random Forest (99.76% accuracy)
│   ├── rf_metadata.pkl        # Class labels
│   ├── autoencoder.keras       # Trained autoencoder
│   ├── autoencoder_threshold.npy
│   ├── scaler.pkl             # StandardScaler
│   └── rf_feature_importance.png
├── data/                       # Dataset files (CIC-IDS2017)
├── logs/                       # Alert database
├── tests/
│   └── test_hybrid_predictor.py
├── alert_manager.py            # Alert storage & management (NEW - in root)
├── dashboard/                  # Legacy dashboard location (use src/dashboard)
├── Dockerfile                 # Docker container (NEW)
├── docker-compose.yml         # Docker Compose (NEW)
├── requirements.txt           # Python dependencies (NEW)
├── .gitignore
├── AGENTS.md
├── AI-NIDS-PROJECT-PLAN.md
└── progress.md
```

## What Was Built (March 2026 Session)

### 1. HybridPredictor (`src/models/hybrid_predictor.py`)
- Fuses Random Forest + Autoencoder predictions
- Decision fusion logic:
  - RF says Attack → Attack verdict
  - RF says Benign + AE anomaly → Suspicious (possible zero-day)
  - RF says Benign + AE normal → Benign
- Uses frozen dataclasses for immutable results
- Supports both numpy array and dict input

### 2. PacketSniffer (`src/capture/sniffer.py`)
- Live packet capture using Scapy
- 5-tuple flow assembly (src_ip, dst_ip, src_port, dst_port, protocol)
- Configurable flow timeout (default 60s)
- Thread-safe with callbacks for completed flows

### 3. Live Feature Extraction (`src/features/extractor.py`)
- Added `extract_live_features()` function
- Converts flow dict to 52 CIC-IDS2017-style features
- Computes packet statistics, IAT, flags, etc.

### 4. Streamlit Dashboard (`src/dashboard/app.py`)
- Live metrics: Total Alerts, Attacks, Suspicious, Benign
- Attack distribution donut chart
- Attack rate gauge
- Alert timeline (line chart)
- Top attackers bar chart
- Recent alerts table (color-coded)
- IP blocking functionality
- CSV export
- Auto-refresh (configurable 1-10s)
- Demo mode with generated data

### 5. AlertManager (`alert_manager.py`)
- SQLite database for persistent storage
- In-memory deque for fast dashboard reads (last 500 alerts)
- Thread-safe with locking
- Methods:
  - `add_alert()` - Store new alert
  - `get_recent_alerts()` - Get last N alerts
  - `get_top_attackers()` - Top N attacking IPs
  - `get_attack_distribution()` - Attack type counts
  - `block_ip()` - Block malicious IP
  - `get_blocked_ips()` - List blocked IPs
  - `export_csv()` - Export to CSV

### 6. Docker Setup
- `Dockerfile` - Python 3.11-slim with all dependencies
- `docker-compose.yml` - Container with NET_ADMIN, NET_RAW capabilities

### 7. Tests (`tests/test_hybrid_predictor.py`)
- 10 tests for HybridPredictor
- Tests for fusion logic, prediction, error handling

## Model Performance

### 4-Model Ensemble Architecture

The system uses a **4-model ensemble** for robust intrusion detection:

1. **Random Forest Classifier**
   - Accuracy: 99.76% on 7 classes
   - Classes: Bots, Brute Force, DDoS, DoS, Normal Traffic, Port Scanning, Web Attacks
   - Votes: 1 (attack/benign classification)

2. **XGBoost Classifier**
   - Secondary classification model
   - Votes: 1 (attack/benign classification)
   - Provides ensemble diversity

3. **Autoencoder**
   - Trained on benign traffic only
   - Threshold: 0.2 (Youden's J statistic optimization)
   - Votes: 0.5 (if anomaly AND low classifier confidence)
   - Used for zero-day anomaly detection

4. **Isolation Forest**
   - Anomaly score normalized to 0-1 range
   - Votes: 0.5 (if anomaly score > 0.5 AND low classifier confidence)
   - Additional layer for outlier detection

### Ensemble Voting Logic

```
Verdict = Attack    when attack_votes >= 2
Verdict = Suspicious when attack_votes >= 1 AND (AE anomaly OR IF anomaly > 0.6)
Verdict = Benign    otherwise
```

### Alert Dataclass Fields

Each alert now includes predictions from all models:
- `rf_label`, `rf_confidence` - Random Forest classification
- `xgb_label`, `xgb_confidence` - XGBoost classification
- `ae_anomaly_score`, `ae_is_anomaly` - Autoencoder anomaly
- `if_anomaly_score`, `if_is_anomaly` - Isolation Forest anomaly
- `final_verdict`, `combined_confidence` - Ensemble result

## GitHub Repository
- **URL**: https://github.com/SudoToji/AI-NIDS
- **Type**: Private repository
- **Contains**: All source code, trained models, Docker configs

## Build/Lint/Test Commands

### Running the Project
```bash
# Activate virtual environment
# Windows:
venv\Scripts\activate
# Unix/Mac:
source venv/bin/activate

# Train Random Forest model
python -m src.models.train_rf

# Train Autoencoder model
python -m src.models.autoencoder
```

### Running the Dashboard
```bash
# Activate venv first
streamlit run src/dashboard/app.py
# Open http://localhost:8501
```

### Testing
```bash
# Run all tests
pytest

# Run a single test file
pytest tests/test_hybrid_predictor.py

# Run a single test function
pytest tests/test_hybrid_predictor.py::TestHybridPredictor::test_compute_fusion_both_attack

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=src --cov-report=term-missing
```

### Docker
```bash
# Build and run
docker-compose up --build

# Or just run
docker-compose up
```

### Linting & Type Checking
```bash
# Run ruff linter
ruff check src/

# Run ruff with auto-fix
ruff check src/ --fix

# Format code with ruff
ruff format src/
```

## Code Style Guidelines

### General Principles
- Use Python 3.12+ features (type hints, dataclasses)
- Always use `from __future__ import annotations` for forward references
- 4-space indentation (no tabs)
- Maximum line length: 88 characters (ruff default)
- Use meaningful, descriptive names

### Imports
```python
# Standard library first, then third-party, then local
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.features.extractor import filter_benign, prepare_splits
```

**Rules:**
- Group imports: stdlib, third-party, local
- Sort alphabetically within groups
- Use absolute imports from package root
- Avoid wildcard imports (`from x import *`)

### Type Hints
```python
# Always use type hints for function signatures
def train_model(path: str, max_rows: int | None = None) -> ModelArtifact:
    ...

# Use | for Union (Python 3.10+)
param: int | None = None

# Use typing module for older code
from typing import Optional, List, Dict
def func(arg: Optional[str] = None) -> List[int]:
    ...
```

### Naming Conventions
- **Classes**: `PascalCase` (e.g., `DatasetSplit`, `AutoencoderArtifacts`)
- **Functions/variables**: `snake_case` (e.g., `train_model`, `feature_columns`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_BATCH_SIZE`, `LABEL_COLUMN`)
- **Private functions**: Leading underscore (e.g., `_build_model()`)
- **Files**: `snake_case.py`

### Dataclasses
Use frozen dataclasses for immutable data containers:
```python
from dataclasses import dataclass

@dataclass(frozen=True)
class DatasetSplit:
    x_train: np.ndarray
    x_test: np.ndarray
    y_train: np.ndarray
    y_test: np.ndarray
    label_encoder: LabelEncoder
    scaler: StandardScaler
```

### Error Handling
- Use specific exception types
- Include meaningful error messages
- Log warnings for recoverable issues
```python
if not os.path.exists(path):
    raise FileNotFoundError(f"Dataset not found at {path}")

try:
    value = int(os.getenv(key))
except ValueError:
    LOGGER.warning("Invalid %s value, using default %s", key, default)
    return default
```

### Logging
- Use module-level logger
- Use appropriate log levels (DEBUG, INFO, WARNING, ERROR)
```python
LOGGER = logging.getLogger(__name__)

LOGGER.info("Training model on %d samples", count)
LOGGER.warning("Falling back to default value")
```

### Configuration
- Use environment variables with defaults
- Provide env var names as constants
```python
MODEL_PATH_ENV = "AE_MODEL_PATH"
DEFAULT_MODEL_PATH = "models/autoencoder.keras"

def _resolve_path(env_key: str, default_path: str) -> str:
    path_value = os.getenv(env_key, default_path)
    return path_value if os.path.isabs(path_value) else os.path.join(PROJECT_ROOT, path_value)
```

### Documentation
- Use docstrings for public functions/classes
- Follow Google or NumPy style
```python
def load_dataset(path: str | None = None) -> pd.DataFrame:
    """Load CIC-IDS2017 dataset with memory-friendlier dtypes.
    
    Args:
        path: Optional path to dataset CSV. Defaults to env var or data/processed/.
        
    Returns:
        DataFrame with loaded data.
        
    Raises:
        FileNotFoundError: If dataset file doesn't exist.
    """
```

### Testing Guidelines
- Place tests in `tests/` directory mirroring src structure
- Name test files `test_<module>.py`
- Name test functions `test_<description>`
- Use pytest fixtures for shared setup
- Test both success and failure cases
```python
def test_load_dataset_with_valid_path(tmp_path):
    """Test loading dataset with valid path."""
    csv_path = tmp_path / "test.csv"
    csv_path.write_text("col1,col2\n1,2\n")
    
    result = load_dataset(str(csv_path))
    assert len(result) == 1

def test_load_dataset_raises_on_missing_file():
    """Test that missing file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_dataset("nonexistent.csv")
```

### Performance Considerations
- Use `np.float32` instead of `np.float64` for memory efficiency
- Use chunked reading for large datasets
- Use `n_jobs=-1` for parallelizable scikit-learn operations
- Cache computed values where appropriate

## Future Work (From AI-NIDS-PROJECT-PLAN.md)

### Phase 3: Backend & Alert System
- Integrate HybridPredictor with AlertManager
- Connect PacketSniffer → HybridPredictor → AlertManager pipeline
- Add real-time alert notifications

### Phase 4: Dashboard & Simulator
- Enhance Streamlit dashboard
- Add attack simulator for testing
- Add GeoIP for attack visualization

### TriCoAlign-0.5B Integration (Optional)
- Could add LLM-based explanations for attacks
- Not needed for core detection - RF already at 99.76%
- Could be used as explanation layer

---

## Recent Changes (March 2026 - Dashboard & API)

### 1. Migration from Streamlit to Flask + Custom Dashboard

#### Why
- Streamlit had limited customization
- Wanted a fully custom UI
- Better control over real-time updates

#### What Changed
- Replaced `src/dashboard/app.py` (Streamlit) with `dashboard.html` (Flask + Vanilla JS)
- Added Flask API server in `src/api/server.py`
- Dashboard uses Tailwind CSS with custom styling

#### New Dashboard Features
- Attack Distribution donut chart
- Attack Rate gauge
- Alert Timeline chart
- Top Attackers list
- Recent Alerts table with IP blocking
- Attack simulation buttons

### 2. Model Fixes

#### Problem: Predictions Not Working
- Model wasn't predicting correctly after switching to Flask API
- Root cause: wrong feature order in `extract_features()`

#### Fixes Applied
1. **Feature Extraction** (`src/api/server.py:extract_features`)
   - Fixed mapping from packet data to 52 CIC-IDS2017 features
   - Added proper feature order matching `FEATURE_COLUMNS`

2. **Real Data Simulation** (`src/api/server.py:simulate_attack`)
   - Changed from synthetic data to real CIC-IDS2017 samples
   - Model now correctly identifies attack types

3. **Autoencoder Threshold** (saved to `models/autoencoder_threshold.npy`)
   - Changed from 0.5 to 0.2 (optimal based on Youden's J statistic)
   - Now actually catches anomalies

4. **Verdict Logic** (`src/api/server.py:predict_hybrid`)
   - Improved fusion logic: RF with high confidence → trust it
   - Suspicious only when RF uncertain + AE anomaly

### 3. API Endpoints Added

| Endpoint | Description |
|----------|-------------|
| `/api/attack-distribution-mapped` | Dashboard-friendly attack categories |
| `/api/timeline` | Time-series data for charts |
| `/api/health` | Model status check |

### 4. Live Capture Support

Added live packet capture capability:
- Uses Scapy for packet sniffing
- Assembles 5-tuple flows
- Extracts CIC-IDS2017 features
- Run with `LIVE_CAPTURE=true` environment variable

### 5. Windows Attack Testing

Created `test_attack.py` for Windows testing:
- DDoS simulation
- Port Scan simulation
- Brute Force simulation
- Normal traffic simulation

### 6. Code Quality

- Fixed API endpoints (CORS, routing)
- Fixed dashboard JavaScript (proper API calls)
- Added timeline API endpoint
- Fixed distribution chart rendering

### 7. Ensemble Model Expansion (Latest)

Added XGBoost and Isolation Forest for improved detection:
- **XGBoost** (`xgb_model.json`, `xgb_metadata.pkl`): Secondary classifier
- **Isolation Forest** (`if_model.pkl`, `if_metadata.pkl`): Anomaly detector
- Updated Alert dataclass with new fields
- Ensemble voting: RF(1) + XGB(1) + AE(0.5) + IF(0.5) = 4 votes max

### 8. Threat Intelligence Integration

New `/api/ti/lookup/<ip>` endpoint:
- Integrates with VirusTotal, AbuseIPDB, AlienVault OTX
- Returns threat score (0-100), reputation label, and source details
- Mock data fallback when TI services unavailable
- Dashboard shows TI scores in investigation panel

---

## Running the Project

```bash
# Activate virtual environment
cd "C:\Users\Mazen\Desktop\project"
venv\Scripts\activate

# Start server
python -m src.api.server

# Open dashboard
# http://localhost:5000
```

### Testing Attacks

```bash
# Option 1: Dashboard buttons
# Click attack buttons in sidebar

# Option 2: Test script
python test_attack.py
# Select attack type 1-5

# Option 3: Live capture
set LIVE_CAPTURE=true
python -m src.api.server
```

---

## Model Performance

| Metric | Value |
|--------|-------|
| Random Forest Accuracy | 99.76% |
| XGBoost | Secondary classifier |
| Autoencoder Threshold | 0.2 |
| Isolation Forest | Anomaly detection layer |
| Ensemble Voting | 4 models (RF + XGB + AE + IF) |
| Attack Classes | 7 (DDoS, DoS, Port Scanning, Brute Force, Web Attacks, Bots, Normal Traffic) |
| Alert Storage | 1000 in-memory |
| Alert Storage | 1000 in-memory |
