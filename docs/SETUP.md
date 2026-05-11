# Setup Guide

This guide covers installation, configuration, and deployment of AI-NIDS.

## Prerequisites

### Software Requirements

- **Python**: 3.11 or higher
- **Operating System**: Windows 10/11, Linux, or macOS
- **Package Manager**: pip (comes with Python)
- **Git**: For version control (optional)

### For Live Capture (Optional)

- **Npcap** (Windows): https://npcap.com/dist/npcap-1.78.exe
- **libpcap** (Linux/macOS): Usually pre-installed

## Installation

### 1. Clone or Download the Project

```bash
# If using git
git clone <repository-url>
cd project

# Or extract the ZIP file to your desired location
cd "C:\Users\Mazen\Desktop\project"
```

### 2. Create Virtual Environment

**Windows:**
```bash
# Create virtual environment
python -m venv venv

# Activate it
venv\Scripts\activate
```

**Linux/macOS:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate
```

### 3. Install Dependencies

```bash
# Upgrade pip (recommended)
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt
```

### 4. Environment Configuration

Create a `.env` file in the project root for API keys (optional):

```env
# VirusTotal API (optional - for threat intelligence)
VIRUSTOTAL_API_KEY=your_api_key_here

# AbuseIPDB API (optional - for threat intelligence)
ABUSEIPDB_API_KEY=your_api_key_here

# OpenRouter API (required for Stage 2 LLM deep verification)
# Get free key at: https://openrouter.ai/
OPENROUTER_API_KEY=your_openrouter_key_here

# Live Capture Mode (set to true to enable packet capture)
LIVE_CAPTURE=false

# Network Interface (for live capture on Linux/macOS)
# SNIFF_IFACE=eth0

# Flow Timeout (seconds)
# FLOW_TIMEOUT=60

# Maximum alerts to store in memory
# ALERT_MAX_SIZE=1000

# Max rows for training (memory optimization)
# MAX_ROWS=200000

# Max samples per class for training
# MAX_SAMPLES_PER_CLASS=30000
```

## Running the Application

### Start the API Server

```bash
python -m src.api.server
```

The dashboard will be available at: http://localhost:5000

### Test the System

```bash
# Run attack simulation script
python test_attack.py
```

## Docker Deployment

### Build and Run

```bash
# Build and start the container
docker-compose up --build

# Or just run (if already built)
docker-compose up
```

### Docker Requirements

- Docker Engine 20.10+
- Docker Compose 2.0+

The Docker container runs with:
- `NET_ADMIN` capability (for packet capture)
- `NET_RAW` capability (for raw socket access)
- Port 5000 exposed

## Dataset Setup

The system uses the **UNSW-NB15** dataset in the `data/unsw_nb15/` directory:

```
data/
└── unsw_nb15/
    └── Training and Testing Sets/
        ├── UNSW_NB15_training-set.csv
        └── UNSW_NB15_testing-set.csv
```

### Download Dataset

1. Visit: https://www.unsw.adfa.edu.au/unsw-nb15-dataset/
2. Download `UNSW-NB15 training and testing set`
3. Extract CSV files to `data/unsw_nb15/Training and Testing Sets/`

## Model Training

Models are pre-trained. To retrain:

### Random Forest

```bash
python -m src.models.train_rf
```

### Autoencoder

```bash
python -m src.models.autoencoder
```

### Two-Stage Pipeline Evaluation

```bash
python -m src.simulator.evaluate_pipeline
```

## Troubleshooting

### Import Errors

If you encounter import errors:
```bash
pip install -r requirements.txt --force-reinstall
```

### Model Loading Errors

Ensure models exist in `models/` directory:
- `rf_model.pkl` (Random Forest - UNSW-NB15)
- `autoencoder.keras` (Autoencoder - UNSW-NB15)
- `scaler.pkl` (Feature scaler)
- `autoencoder_threshold.npy` (AE threshold: 0.0396)

### Npcap Installation (Windows)

1. Download from: https://npcap.com/dist/npcap-1.78.exe
2. Run installer as Administrator
3. Select "WinPcap API-compatible Mode"
4. Complete installation

### Permission Errors (Linux)

For live capture, you may need to:
```bash
# Add user to pcap group
sudo usermod -aG pcap $USER

# Or run with sudo (not recommended for production)
sudo python -m src.api.server
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_hybrid_predictor.py

# Run with coverage
pytest --cov=src --cov-report=term-missing
```

### Code Quality

```bash
# Run linter
ruff check src/

# Auto-fix issues
ruff check src/ --fix

# Format code
ruff format src/
```

## Production Considerations

### Security

- [ ] Use HTTPS instead of HTTP
- [ ] Set API keys via environment variables
- [ ] Implement rate limiting
- [ ] Add authentication to API endpoints
- [ ] Run in isolated network environment

### Performance

- [ ] Use a reverse proxy (nginx)
- [ ] Enable Gunicorn/Uvicorn workers
- [ ] Consider Redis for alert storage
- [ ] Use database instead of in-memory storage

### Monitoring

- [ ] Set up log aggregation
- [ ] Add health check monitoring
- [ ] Configure alerts for high attack rates
- [ ] Track model performance over time
