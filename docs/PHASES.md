# Development Phases

## Overview

AI-NIDS was developed in multiple phases, each building on the previous one to create a complete network intrusion detection system.

---

## Phase 1: Offline Training ✅

**Objective**: Train machine learning models on CIC-IDS2017 dataset

### Completed Tasks

| Task | Status | Details |
|------|--------|---------|
| Data Loading & Preprocessing | ✅ | Loaded CIC-IDS2017, cleaned, encoded labels |
| Random Forest Training | ✅ | 99.76% accuracy on 7-class classification |
| XGBoost Training | ✅ | Secondary classifier for ensemble |
| Autoencoder Training | ✅ | Anomaly detection on benign traffic |
| Isolation Forest Training | ✅ | Additional anomaly detection layer |
| Feature Scaler | ✅ | StandardScaler fitted on training data |

### Model Artifacts

```
models/
├── rf_model.pkl           # Random Forest (primary)
├── rf_metadata.pkl         # Class labels & thresholds
├── xgb_model.json          # XGBoost (secondary)
├── xgb_metadata.pkl        # XGBoost labels
├── if_model.pkl            # Isolation Forest
├── if_metadata.pkl         # IF metadata
├── autoencoder.keras       # Trained autoencoder
├── autoencoder_threshold.npy
└── scaler.pkl              # Feature scaler
```

### Attack Classes

1. DDoS
2. DoS
3. Port Scanning
4. Brute Force
5. Web Attacks
6. Bots
7. Normal Traffic

---

## Phase 2: Real-Time Capture ✅

**Objective**: Enable live packet capture and feature extraction

### Completed Tasks

| Task | Status | Details |
|------|--------|---------|
| Packet Sniffer | ✅ | Scapy-based live capture |
| Flow Assembly | ✅ | 5-tuple flow grouping |
| Live Feature Extraction | ✅ | 52 CIC-IDS2017-style features |
| Flow Timeout | ✅ | 60-second configurable timeout |

### Sniffer Features

- Thread-safe packet handling
- Configurable network interface
- Graceful shutdown support
- Flow statistics tracking

---

## Phase 3: Backend & Alert System ✅

**Objective**: Build API and alert management

### Completed Tasks

| Task | Status | Details |
|------|--------|---------|
| Flask API Server | ✅ | REST endpoints for all operations |
| Alert Storage | ✅ | In-memory deque (last 1000 alerts) |
| IP Blocking | ✅ | Block/unblock malicious IPs |
| Statistics Endpoint | ✅ | Dashboard metrics |
| Threat Intelligence | ✅ | VirusTotal, AbuseIPDB, OTX integration |

### API Endpoints

- `GET /api/health` - Model status
- `GET /api/stats` - Dashboard statistics
- `GET /api/alerts` - Recent alerts
- `GET /api/attack-distribution` - Attack types
- `GET /api/timeline` - Time-series data
- `GET /api/top-attackers` - Top sources
- `POST /api/block-ip` - Block IP
- `POST /api/predict` - Single prediction
- `POST /api/simulate` - Attack simulation
- `GET /api/ti/lookup/<ip>` - Threat intelligence

---

## Phase 4: Dashboard & Simulator ✅

**Objective**: Create web UI and attack simulation

### Completed Tasks

| Task | Status | Details |
|------|--------|---------|
| Web Dashboard | ✅ | Tailwind CSS, vanilla JS |
| Attack Distribution Chart | ✅ | Donut chart |
| Alert Timeline | ✅ | Line chart |
| Top Attackers | ✅ | Bar chart |
| Attack Simulator | ✅ | One-click attack buttons |
| IP Investigation | ✅ | Investigation panel |

### Dashboard Features

- Real-time metrics (Total, Attacks, Suspicious, Benign)
- Attack rate gauge
- Distribution charts
- Alert timeline
- Top attackers list
- Recent alerts table
- IP blocking
- CSV export
- Threat intelligence lookup
- Attack simulation buttons

---

## Phase 5: Integration ✅

**Objective**: Connect all components and add integrations

### Completed Tasks

| Task | Status | Details |
|------|--------|---------|
| Ensemble Voting | ✅ | 4-model fusion logic |
| ELK Integration | ✅ | Elasticsearch, Logstash, Kibana |
| Docker Deployment | ✅ | Containerized deployment |
| Threat Intelligence | ✅ | Multi-source lookup |

### Ensemble Logic

```
Verdict = Attack    when attack_votes >= 2
Verdict = Suspicious when attack_votes >= 1 AND (AE anomaly OR IF anomaly > 0.6)
Verdict = Benign    otherwise
```

**Vote Weights:**
- Random Forest: 1 vote
- XGBoost: 1 vote
- Autoencoder: 0.5 vote
- Isolation Forest: 0.5 vote

---

## Future Enhancements

### Planned Features

1. **LIME/SHAP Explainability** - "Why was this flagged?" per prediction
2. **GeoIP Visualization** - World map of attack sources
3. **Slack/Telegram Alerts** - Push notifications
4. **Zeek Integration** - Rich flow logs
5. **Model Retraining** - Online learning
6. **Database Storage** - PostgreSQL/SQLite for persistence

### Nice-to-Have

- [ ] Raspberry Pi deployment guide
- [ ] MITRE ATT&CK mapping
- [ ] Custom attack signatures
- [ ] Multi-tenancy support
- [ ] API rate limiting
- [ ] JWT authentication

---

## Development Timeline

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Offline Training | ✅ Complete |
| Phase 2 | Real-Time Capture | ✅ Complete |
| Phase 3 | Backend & Alerting | ✅ Complete |
| Phase 4 | Dashboard & Simulator | ✅ Complete |
| Phase 5 | Integration | ✅ Complete |

---

## Release Information

- **Current Version**: 1.0.0
- **Last Updated**: March 2026
- **License**: MIT
- **Repository**: https://github.com/SudoToji/AI-NIDS
