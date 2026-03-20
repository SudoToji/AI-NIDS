# 🛡️ AI-NIDS: Network Intrusion Detection System

![Version](https://img.shields.io/badge/version-2.4.0--alpha-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Accuracy](https://img.shields.io/badge/accuracy-99.76%25-brightgreen)

A machine learning-based network intrusion detection system using a **4-model ensemble** trained on the **CIC-IDS2017 dataset**. Features real-time detection, threat intelligence integration, SIEM analytics, and a SOC-style web dashboard.

---

## 🎯 Features

### Core Detection
- **4-Model Ensemble**: Random Forest + XGBoost + Autoencoder + Isolation Forest
- **7 Attack Classes**: DDoS, DoS, Port Scanning, Brute Force, Web Attacks, Bots, Normal Traffic
- **Real-time Detection**: Live packet capture and analysis
- **Anomaly Detection**: Zero-day attack detection via Autoencoder and Isolation Forest

### Threat Intelligence
- **VirusTotal Integration**: Malicious IP detection (500/day free)
- **AbuseIPDB Integration**: IP reputation lookup (5000/day free)
- **AlienVault OTX**: Threat pulse intelligence (unlimited)
- **GeoIP Lookup**: IP geolocation for attack visualization (ip-api.com)

### Dashboard & Visualization
- **Premium SOC UI**: Dark-themed, cyber-styled interface
- **Live Metrics**: Total alerts, threats blocked, suspicious activity
- **Attack Distribution**: Interactive donut chart
- **Threat Velocity**: Real-time alert timeline
- **Global Threat Map**: Interactive Leaflet.js world map showing attack sources
- **Model Orchestration Panel**: View ensemble status and confidence
- **Investigation Panel**: Deep dive into IP reputation and threat intelligence

### SIEM Integration
- **ELK Stack**: Elasticsearch, Logstash, Kibana for centralized logging
- **REST API**: Full programmatic access
- **Docker Support**: Containerized deployment

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AI-NIDS SYSTEM                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    ┌──────────────┐     ┌─────────────────────────────────────────────┐   │
│    │   Network    │     │            ENSEMBLE DETECTION                │   │
│    │   Traffic    │────▶│  ┌─────────────────────────────────────────┐│   │
│    │              │     │  │                                         ││   │
│    └──────────────┘     │  │  ┌─────────────┐    ┌─────────────┐      ││   │
│                         │  │  │   Random    │    │   XGBoost   │      ││   │
│                         │  │  │   Forest    │    │  Classifier │      ││   │
│                         │  │  │  (1 vote)   │    │  (1 vote)   │      ││   │
│                         │  │  └──────┬──────┘    └──────┬──────┘      ││   │
│                         │  │         │                  │              ││   │
│                         │  │  ┌─────▼──────┐    ┌─────▼─────┐        ││   │
│                         │  │  │            │    │           │        ││   │
│                         │  │  │ Autoencoder│    │Isolation  │        ││   │
│                         │  │  │  (0.5 vote)│    │Forest     │        ││   │
│                         │  │  │  Anomaly   │    │(0.5 vote) │        ││   │
│                         │  │  └────────────┘    └───────────┘        ││   │
│                         │  │                                         ││   │
│                         │  │           ENSEMBLE VOTING               ││   │
│                         │  │              ⚡ ⚡ ⚡ ⚡                  ││   │
│                         │  └─────────────────────────────────────────┘│   │
│                         └─────────────────────────────────────────────┘   │
│                                        │                                    │
│                                        ▼                                    │
│    ┌──────────────────────────────────────────────────────────────────┐   │
│    │                         ALERTS                                    │   │
│    │                                                                   │   │
│    │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │   │
│    │   │   Threat    │  │    ELK      │  │    GeoIP    │             │   │
│    │   │ Intelligence│  │   Stack     │  │    Map      │             │   │
│    │   └─────────────┘  └─────────────┘  └─────────────┘             │   │
│    └──────────────────────────────────────────────────────────────────┘   │
│                                        │                                    │
│                                        ▼                                    │
│    ┌──────────────────────────────────────────────────────────────────┐   │
│    │                    SOC-STYLE DASHBOARD                           │   │
│    │                                                                   │   │
│    │   📊 Dashboard   🔔 Alerts   🧠 Models   🔍 Investigation       │   │
│    │                                                                   │   │
│    └──────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Model Performance

| Model | Type | Accuracy/Score | Votes |
|-------|------|----------------|-------|
| **Random Forest** | Classification | 99.76% | 1.0 |
| **XGBoost** | Classification | 99.1% | 1.0 |
| **Autoencoder** | Anomaly Detection | 0.0024 (loss) | 0.5 |
| **Isolation Forest** | Anomaly Detection | 0.82 (score) | 0.5 |

### Ensemble Voting Logic

```
Attack:        ≥2 votes
Suspicious:   ≥1 vote + anomaly detected  
Benign:       <1 vote
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- Windows (with Npcap for live capture) or Linux/macOS

### Installation

```bash
# Navigate to project
cd "C:\Users\Mazen\Desktop\Project"

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Server

```bash
# Start Flask API and Dashboard
python -m src.api.server

# Open browser
http://localhost:5000
```

### Testing Attacks

```bash
# Use dashboard buttons:
# DDoS Attack | SYN Flood | Port Scan | Brute Force | Normal Traffic | Simulate All
```

---

## 📁 Project Structure

```
AI-NIDS/
├── src/
│   ├── api/
│   │   └── server.py              # Flask API + Dashboard
│   ├── capture/
│   │   └── sniffer.py             # Live packet capture (Scapy)
│   ├── features/
│   │   └── extractor.py           # Feature extraction (52 features)
│   ├── models/
│   │   ├── train_rf.py            # Random Forest training
│   │   ├── train_xgb.py           # XGBoost training
│   │   ├── train_isolation_forest.py
│   │   ├── autoencoder.py         # Autoencoder training
│   │   ├── hybrid_predictor.py    # Ensemble fusion logic
│   │   └── ensemble_voting.py     # Voting implementation
│   ├── integration/
│   │   ├── elk_forwarder.py       # → ELK Stack
│   │   ├── ti_client.py           # Threat Intelligence
│   │   └── enricher.py           # Alert enrichment
│   └── utils/
│       └── geoip.py               # GeoIP lookup
├── models/                        # Trained models
│   ├── rf_model.pkl              # Random Forest (99.76%)
│   ├── xgb_model.json            # XGBoost
│   ├── if_model.pkl              # Isolation Forest
│   ├── autoencoder.keras         # Autoencoder
│   ├── scaler.pkl                # Feature scaler
│   └── autoencoder_threshold.npy  # AE threshold
├── web/
│   └── index.html                # SOC Dashboard UI
├── elk/                          # ELK Stack configs
│   ├── docker-compose.elk.yml
│   └── logstash/pipeline/
│       └── nids.conf             # Logstash pipeline
├── tests/                        # Unit tests
├── docs/                         # Documentation
├── requirements.txt
├── README.md
├── PRODUCTION_ENHANCEMENT_PLAN.md
└── AGENTS.md                     # Coding guidelines
```

---

## 🔌 API Endpoints

### Health & Stats
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | System health and model status |
| `/api/stats` | GET | Dashboard statistics |

### Alerts & Detection
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | Recent alerts |
| `/api/attack-distribution` | GET | Attack type counts |
| `/api/attack-distribution-mapped` | GET | Dashboard categories |
| `/api/timeline` | GET | Time-series data |
| `/api/top-attackers` | GET | Top attacking IPs |
| `/api/predict` | POST | Predict single packet |
| `/api/simulate` | POST | Run attack simulation |
| `/api/clear` | POST | Clear all alerts |

### IP Management
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/block-ip` | POST | Block an IP |
| `/api/unblock-ip` | POST | Unblock an IP |
| `/api/blocked-ips` | GET | List blocked IPs |

### Threat Intelligence
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ti/lookup/<ip>` | GET | IP reputation lookup |
| `/api/ti/test` | GET | TI service test |

### GeoIP
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/geo/lookup/<ip>` | GET | IP geolocation |
| `/api/geo/attacks-map` | GET | Attack sources for map |

---

## 🕵️ Attack Types Detected

| Attack | Description |
|--------|-------------|
| **DDoS** | Distributed Denial of Service |
| **DoS** | Denial of Service (Slowloris, etc.) |
| **Port Scanning** | Network reconnaissance |
| **Brute Force** | SSH/FTP credential attacks |
| **Web Attacks** | HTTP-based attacks |
| **Bots** | Compromised host activity |
| **Normal Traffic** | Legitimate traffic |

---

## 🗺️ Dashboard Pages

### Dashboard
- KPI cards: Total Alerts, Threats Blocked, Suspicious, Model Accuracy
- Network Traffic chart
- Attack Distribution donut chart
- Attack Simulator buttons
- Live Alert Feed table
- Top Attackers panel
- Active Blocklist panel

### Alerts
- Active Nodes indicator
- Threat Velocity timeline
- Critical Anomalies counter
- Live Incident Queue table
- Export/Purge functionality

### Models
- Ensemble Confidence display
- 4 Model cards (RF, XGBoost, Autoencoder, Isolation Forest)
- Live Neural Inference Stream

### Investigation
- IP Lookup search with VirusTotal, AbuseIPDB, OTX
- **Global Threat Map** (Leaflet.js dark map)
- Intelligence Summary panel
- IP Information panel
- Recent Lookups history

### Settings
- System Information
- Threshold Configuration (AE, IF)
- Blocked IPs Management

---

## 🐳 Docker Deployment

```bash
# Start ELK Stack
docker-compose -f elk/docker-compose.elk.yml up -d

# Access Kibana
# http://localhost:5601
```

---

## 📈 Tech Stack

| Category | Technology |
|----------|------------|
| **Backend** | Flask, Python 3.11+ |
| **ML/AI** | Scikit-learn (RF, IF), XGBoost, TensorFlow (AE) |
| **Capture** | Scapy, Npcap |
| **Dashboard** | Tailwind CSS, Vanilla JS, Leaflet.js |
| **SIEM** | Elasticsearch, Logstash, Kibana |
| **Threat Intel** | VirusTotal, AbuseIPDB, AlienVault OTX |
| **Database** | In-memory (1000 alerts), SQLite (TI cache) |
| **Container** | Docker |

---

## 📚 Related Documentation

- [API Documentation](API.md)
- [Setup Guide](SETUP.md)
- [Development Phases](PHASES.md)
- [Production Enhancement Plan](../PRODUCTION_ENHANCEMENT_PLAN.md)
- [Coding Guidelines](../AGENTS.md)

---

## 🎓 Academic Project

This project was developed as an academic demonstration of:
- Machine Learning for cybersecurity
- Ensemble methods for robust detection
- SIEM integration with ELK Stack
- Threat intelligence utilization
- Modern SOC dashboard design

### Dataset
- **CIC-IDS2017**: Canadian Institute for Cybersecurity, University of New Brunswick
- 7 attack types + normal traffic
- 52 network flow features

---

## 📝 License

MIT License

---

## 🙏 Credits

- **CIC-IDS2017 Dataset**: Canadian Institute for Cybersecurity, University of New Brunswick
- **Random Forest**: Scikit-learn
- **XGBoost**: DMLC
- **Autoencoder**: TensorFlow/Keras
- **ELK Stack**: Elastic
- **Threat Intelligence**: VirusTotal, AbuseIPDB, AlienVault OTX

---

**Built with 🛡️ for network security research**
