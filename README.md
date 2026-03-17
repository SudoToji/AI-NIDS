# AI-NIDS: Network Intrusion Detection System

A machine learning-based network intrusion detection system using Random Forest and Autoencoder models trained on the CIC-IDS2017 dataset.

## Features

- **Real-time Detection**: Monitor network traffic and detect attacks in real-time
- **Multiple Attack Types**: Detects DDoS, Port Scanning, Brute Force, Web Attacks, Bots, DoS
- **Hybrid ML Approach**: Combines Random Forest (classification) with Autoencoder (anomaly detection)
- **Web Dashboard**: Clean, modern UI for monitoring alerts and attack patterns
- **REST API**: Programmatic access to predictions and alerts

## Quick Start

### Prerequisites

- Python 3.11+
- Windows (with Npcap for live capture) or Linux/macOS

### Installation

```bash
# Clone or navigate to project
cd "C:\Users\Mazen\Desktop\project"

# Activate virtual environment
venv\Scripts\activate

# Install dependencies (if needed)
pip install -r requirements.txt
```

### Running the Server

```bash
# Start the Flask API and dashboard
python -m src.api.server
```

Then open `http://localhost:5000` in your browser.

### Testing Attacks

Use the built-in simulation buttons on the dashboard sidebar, or run the test script:

```bash
python test_attack.py
```

Select an attack type (1-5) to simulate and watch the dashboard detect it in real-time.

## Project Structure

```
Project/
├── src/
│   ├── api/
│   │   └── server.py           # Flask API server + dashboard
│   ├── capture/
│   │   └── sniffer.py         # Live packet capture
│   ├── features/
│   │   └── extractor.py       # Feature extraction
│   └── models/
│       ├── train_rf.py         # Random Forest training
│       └── autoencoder.py     # Autoencoder training
├── models/                    # Trained models
│   ├── rf_model.pkl         # Random Forest (99.76% accuracy)
│   ├── rf_metadata.pkl       # Class labels
│   ├── autoencoder.keras    # Trained autoencoder
│   ├── autoencoder_threshold.npy
│   └── scaler.pkl          # Feature scaler
├── data/                     # CIC-IDS2017 dataset
├── dashboard.html           # Web dashboard
├── test_attack.py          # Attack simulation script
├── requirements.txt         # Python dependencies
└── README.md              # This file
```

## Architecture

### Hybrid Detection Model

1. **Random Forest Classifier** (Primary)
   - Multiclass classification: DDoS, DoS, Port Scanning, Brute Force, Web Attacks, Bots, Normal Traffic
   - Accuracy: ~99.76%

2. **Autoencoder Anomaly Detector** (Secondary)
   - Trained on benign traffic only
   - Flags suspicious/unknown patterns
   - Threshold: 0.2

### Detection Flow

```
Network Packet → Flow Assembly → Feature Extraction → ML Prediction → Alert
```

## API Endpoints

| Endpoint | Method | Description |
|---------|--------|-------------|
| `/api/health` | GET | Check API and model status |
| `/api/stats` | GET | Dashboard statistics |
| `/api/alerts` | GET | Recent alerts |
| `/api/attack-distribution` | GET | Attack type distribution |
| `/api/attack-distribution-mapped` | GET | Mapped for dashboard |
| `/api/timeline` | GET | Timeline data |
| `/api/top-attackers` | GET | Top attacking IPs |
| `/api/blocked-ips` | GET | List blocked IPs |
| `/api/block-ip` | POST | Block an IP |
| `/api/predict` | POST | Predict on packet data |
| `/api/simulate` | POST | Run attack simulation |
| `/api/clear` | POST | Clear all alerts |

## Attack Types Detected

| Attack Type | Description |
|-------------|-------------|
| DDoS | Distributed Denial of Service |
| DoS | Denial of Service (Slowloris, etc.) |
| Port Scanning | Network reconnaissance |
| Brute Force | SSH/FTP credential attacks |
| Web Attacks | HTTP-based attacks |
| Bots | Compromised host activity |
| Normal Traffic | Legitimate traffic |

## Live Capture

To capture real network traffic:

1. Install Npcap: https://npcap.com/dist/npcap-1.78.exe
2. Run with live capture enabled:

```bash
set LIVE_CAPTURE=true
python -m src.api.server
```

**Note**: Requires administrator privileges and Npcap installed.

## Training Models

If you need to retrain the models:

```bash
# Train Random Forest
python -m src.models.train_rf

# Train Autoencoder
python -m src.models.autoencoder
```

## Performance

- **Random Forest**: 99.76% accuracy on CIC-IDS2017
- **Autoencoder**: Used for anomaly detection (threshold: 0.2)
- **Dashboard**: Auto-refreshes every 3 seconds
- **Alert Storage**: Last 1000 alerts in memory

## Tech Stack

- **Backend**: Flask
- **ML**: Scikit-learn, TensorFlow
- **Capture**: Scapy
- **Frontend**: Tailwind CSS, Vanilla JS
- **Data**: CIC-IDS2017 Dataset

## License

MIT License

## Credits

- CIC-IDS2017 Dataset: Canadian Institute for Cybersecurity
- Models trained on preprocessed CIC-IDS2017 features
