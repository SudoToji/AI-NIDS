# AGENTS.md - AI-NIDS Project Guidelines

## Project Overview
This is a Python-based Network Intrusion Detection System (AI-NIDS) using machine learning (Random Forest) and deep learning (Autoencoder) on the CIC-IDS2017 dataset.

## Project Structure
```
Project/
├── src/
│   ├── features/extractor.py    # Feature extraction & preprocessing
│   └── models/
│       ├── autoencoder.py       # Autoencoder anomaly detector
│       └── train_rf.py          # Random Forest classifier
├── models/                      # Trained model artifacts
├── data/                        # Dataset files
├── venv/                        # Python virtual environment
└── AGENTS.md                    # This file
```

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

### Testing
This project uses **pytest** for testing. Tests are located in a `tests/` directory (create if not exists).

```bash
# Run all tests
pytest

# Run a single test file
pytest tests/test_extractor.py

# Run a single test function
pytest tests/test_extractor.py::test_load_dataset

# Run tests matching a pattern
pytest -k "test_load"

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=src --cov-report=term-missing
```

### Linting & Type Checking
```bash
# Run ruff linter
ruff check src/

# Run ruff with auto-fix
ruff check src/ --fix

# Run mypy type checker
mypy src/

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
