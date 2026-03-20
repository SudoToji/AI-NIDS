# AI-NIDS Academic Enhancement Plan
### Simplified for Student Project (Zero Budget)

---

**Project**: AI-NIDS → Student SOC Analytics Platform  
**Current State**: ML-based NIDS with RF (99.76%) + Autoencoder hybrid detection  
**Target State**: Academic demonstration platform with enhanced ML, integrated SIEM, and functional SOC dashboard  
**Document Version**: 2.1 (Student Edition - Phase 1 & 2 Complete)  
**Last Updated**: March 2026  
**Scope**: 1-2 students, 3-6 months  
**Budget**: $0 (Free/Open-Source Only)

---

## Executive Summary

This document outlines a **realistic enhancement plan** for the AI-NIDS project adapted for academic constraints. The current implementation provides excellent detection accuracy (~99.76%) using Random Forest and Autoencoder models. The proposed plan adds:

- **2 new ML models** (XGBoost, Isolation Forest)
- **Local ELK Stack SIEM integration**
- **Enhanced dashboard with threat investigation**
- **Free threat intelligence feeds**

All while using **100% free and open-source tools** with **no cloud dependencies**.

## Phase Completion Status

| Phase | Status | Completion Date | Notes |
|-------|--------|-----------------|-------|
| Phase 1: ML Enhancements | ✅ **COMPLETE** | March 2026 | RF + XGB + AE + IF ensemble |
| Phase 2: SIEM Integration | ✅ **COMPLETE** | March 2026 | ELK Stack + TI integration |
| Phase 3: Dashboard & Polish | 🔄 **IN PROGRESS** | - | Investigation UI + TI panel |

### Phase 2 Completed Components

**ELK Stack:**
- Elasticsearch 8.12.0 (port 9200)
- Logstash 8.12.0 (port 5044)
- Kibana 8.12.0 (port 5601)
- Daily index pattern: `ainids-alerts-YYYY.MM.DD`

**Threat Intelligence:**
- VirusTotal integration (500/day)
- AbuseIPDB integration (5000/day)
- AlienVault OTX integration (unlimited)
- SQLite caching (24hr TTL)

**Integration Files:**
- `src/integration/elk_forwarder.py` - Alert forwarding
- `src/integration/ti_client.py` - TI lookup
- `src/integration/enricher.py` - Alert enrichment
- `elk/docker-compose.elk.yml` - Stack deployment
- `elk/logstash/pipeline/nids.conf` - Processing pipeline

---

## Technology Stack (Free Only)

### Core Technologies (Already in Use)
| Tool | Purpose | Status |
|------|---------|--------|
| Python 3.11+ | Backend | ✅ |
| Scikit-learn | ML (RF) | ✅ |
| TensorFlow/Keras | Deep Learning (AE) | ✅ |
| Flask | API Server | ✅ |
| Tailwind CSS | Dashboard UI | ✅ |
| SQLite | Alert Storage | ✅ |
| Docker | Containerization | ✅ |

### New Free Technologies
| Tool | Purpose | Cost | Install Size |
|------|---------|------|--------------|
| **ELK Stack** (Elasticsearch, Logstash, Kibana) | SIEM | Free | ~2GB |
| **Wazuh** | HIDS + SIEM agent | Free | ~1GB |
| **XGBoost** | Gradient Boosting ML | Free | <50MB |
| **Isolation Forest** (Scikit-learn) | Unsupervised ML | Free | Built-in |
| **VirusTotal API** | Threat Intel | Free tier (500/day) | API only |
| **AbuseIPDB API** | IP Reputation | Free tier (5000/day) | API only |
| **OTX (AlienVault)** | Threat Intel | Free tier | API only |
| **Grafana** | Monitoring | Free | ~500MB |
| **MaxMind GeoLite2** | IP Geolocation | Free tier | ~50MB |

---

## Project Goals (MVP vs Nice-to-Have)

### MVP (Must Have) - Core Deliverables

| # | Goal | Complexity | Time | Priority |
|---|------|------------|------|----------|
| 1 | Add XGBoost classifier | LOW | 15h | P1 |
| 2 | Add Isolation Forest detector | MEDIUM | 20h | P1 |
| 3 | Ensemble voting (RF + XGB + IF + AE) | MEDIUM | 15h | P1 |
| 4 | ELK Stack integration (local) | MEDIUM | 25h | P1 |
| 5 | Threat intelligence enrichment (free APIs) | MEDIUM | 20h | P1 |
| 6 | Enhanced dashboard with investigation UI | MEDIUM | 30h | P1 |

### Nice-to-Have (Stretch Goals)

| # | Goal | Complexity | Time | Priority |
|---|------|------------|------|----------|
| 1 | Automated alert response (SOAR-lite) | HIGH | 40h | P2 |
| 2 | GeoIP attack map visualization | MEDIUM | 15h | P2 |
| 3 | Model retraining pipeline | HIGH | 35h | P2 |
| 4 | Attack timeline/chain analysis | MEDIUM | 20h | P2 |
| 5 | Grafana dashboards | LOW | 10h | P2 |

---

## 3-Phase Implementation Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ACADEMIC TIMELINE (6 MONTHS)                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 1: ML ENHANCEMENTS          │  PHASE 2: SIEM INTEGRATION             │
│  Months 1-2                       │  Months 3-4                             │
│  ─────────────────────            │  ───────────────────────               │
│  • XGBoost model (15h)            │  • ELK Stack setup (10h)               │
│  • Isolation Forest (20h)         │  • Log forwarding (10h)               │
│  • Ensemble voting (15h)          │  • Kibana dashboards (15h)            │
│  • Testing & validation (10h)    │  • TI enrichment (20h)                │
│                                   │  • Testing (10h)                      │
│  Total: ~60 hours                 │  Total: ~65 hours                      │
│                                   │                                        │
│  ════════════════════════════════╪══════════════════════════════════════  │
│                                    │                                        │
│  PHASE 3: DASHBOARD & POLISH      │  BUFFER (Final Month)                  │
│  Months 4-5                       │  Month 6                                │
│  ─────────────────────            │  ─────────────────────                 │
│  • Investigation UI (15h)         │  • Bug fixes                           │
│  • TI panel integration (10h)     │  • Documentation                       │
│  • Alert management UI (10h)      │  • Demo prep                           │
│  • Testing & polish (15h)         │  • Presentation                        │
│                                   │                                        │
│  Total: ~50 hours                 │  Total: ~25 hours                      │
│                                                                             │
│  GRAND TOTAL: ~200 hours                                                 │
│  (100h per student if 2 students)                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: ML Enhancements (Months 1-2)

### 1.1 XGBoost Classifier

**File**: `src/models/xgboost_classifier.py`

```python
# Purpose: Gradient boosting alternative to Random Forest
# Advantage: Often outperforms RF on imbalanced data
# Use Case: Multi-class classification

# Implementation using xgboost library
from xgboost import XGBClassifier

# Configuration
params = {
    'n_estimators': 100,
    'max_depth': 6,
    'learning_rate': 0.1,
    'objective': 'multi:softmax',
    'num_class': 7,
    'n_jobs': -1
}
```

**Implementation Steps**:
1. Install xgboost: `pip install xgboost`
2. Create `src/models/xgboost_classifier.py`
3. Create training script `src/models/train_xgb.py`
4. Evaluate and compare with existing RF
5. Add to ensemble voter

**Estimated Time**: 15 hours
**Dependencies**: None (standalone)

---

### 1.2 Isolation Forest (Unsupervised)

**File**: `src/models/isolation_forest.py`

```python
# Purpose: Unsupervised anomaly detection
# Advantage: No labeled data needed; detects novel attacks
# Use Case: Zero-day detection, new attack patterns

from sklearn.ensemble import IsolationForest

# Train on BENIGN traffic only (like autoencoder)
# Detects deviations from "normal" behavior

# Decision fusion:
# if RF+XGB agree "Attack" → ATTACK
# elif IF flags anomaly → SUSPICIOUS (potential zero-day)
# elif AE flags anomaly → SUSPICIOUS
# else → BENIGN
```

**Implementation Steps**:
1. Create `src/models/isolation_forest.py`
2. Train on benign traffic subset
3. Tune contamination threshold
4. Integrate with HybridPredictor
5. Create `src/models/train_if.py`

**Estimated Time**: 20 hours
**Dependencies**: None (standalone)

---

### 1.3 Ensemble Voting System

**File**: `src/models/ensemble_voter.py`

```
┌─────────────────────────────────────────────────────────┐
│                  Ensemble Voting Logic                   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  │
│  │   RF    │  │  XGBoost│  │   IF    │  │   AE    │  │
│  │ 99.76%  │  │  ~99.5% │  │ anomaly │  │ anomaly │  │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  │
│       │            │            │            │         │
│       └────────────┴─────┬──────┴────────────┘         │
│                          │                              │
│                   ┌──────▼──────┐                       │
│                   │  Weighted  │                       │
│                   │   Voting   │                       │
│                   └──────┬──────┘                       │
│                          │                              │
│            ┌─────────────┼─────────────┐               │
│            │             │             │                │
│            ▼             ▼             ▼                │
│      ┌──────────┐  ┌───────────┐  ┌──────────┐         │
│      │ ATTACK   │  │SUSPICIOUS │  │  BENIGN  │         │
│      │ (≥2 models│  │(1 anomaly │  │ (≥2 models│        │
│      │ agree)   │  │ flag only)│  │ agree)   │         │
│      └──────────┘  └───────────┘  └──────────┘         │
│                                                          │
│  Weights:                                                │
│  - RF: 0.40 (strongest accuracy)                        │
│  - XGBoost: 0.30 (diversity)                            │
│  - IF: 0.15 (zero-day flag)                             │
│  - AE: 0.15 (anomaly flag)                              │
└─────────────────────────────────────────────────────────┘
```

**Implementation Steps**:
1. Update `src/models/hybrid_predictor.py`
2. Add XGBoost and IF results
3. Implement weighted voting
4. Add confidence scoring
5. Update API to return ensemble results

**Estimated Time**: 15 hours
**Dependencies**: Requires 1.1 and 1.2

---

### Phase 1 Tasks Summary

| Task | Hours | Deliverable |
|------|-------|-------------|
| XGBoost model | 15 | `xgb_model.pkl` |
| Isolation Forest | 20 | `if_model.pkl` |
| Ensemble voting | 15 | Updated `HybridPredictor` |
| Testing & validation | 10 | Test suite, comparison metrics |
| **Phase 1 Total** | **60h** | |

---

## Phase 2: SIEM Integration (Months 3-4)

### 2.1 Local ELK Stack Setup

```
┌─────────────────────────────────────────────────────────┐
│              ELK Stack (Local Deployment)                │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐               │
│  │ Logstash│───▶│Elastic- │───▶│ Kibana  │               │
│  │         │    │search   │    │         │               │
│  └────┬────┘    └─────────┘    └─────────┘               │
│       │                                                  │
│       │                                                  │
│  ┌────▼────┐                                            │
│  │ Flask   │ (your existing API)                         │
│  │ API     │                                            │
│  └─────────┘                                            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Setup Steps**:

1. **Install Docker Desktop** (Windows/Mac) or native Linux
2. **Create `docker-compose.elk.yml`**:

```yaml
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data
  
  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    volumes:
      - ./elk/logstash/pipeline:/usr/share/logstash/pipeline
    depends_on:
      - elasticsearch
  
  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

volumes:
  es_data:
```

3. **Create Logstash pipeline** (`elk/logstash/pipeline/nids.conf`):

```conf
input {
  tcp {
    port => 5044
    codec => json_lines
  }
}

filter {
  if [alert_type] == "attack" {
    mutate {
      add_tag => ["threat"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "nids-alerts-%{+YYYY.MM.dd}"
  }
}
```

**Estimated Time**: 10 hours
**Dependencies**: None (setup phase)

---

### 2.2 Flask → ELK Forwarding

**File**: `src/integration/elk_forwarder.py`

```python
# Purpose: Send alerts from Flask API to ELK Stack
# Method: TCP socket to Logstash

import json
import socket
from datetime import datetime

class ELKForwarder:
    def __init__(self, host='localhost', port=5044):
        self.host = host
        self.port = port
    
    def forward_alert(self, alert: dict):
        """Send alert to Logstash via TCP"""
        # Add metadata
        alert['@timestamp'] = datetime.utcnow().isoformat()
        alert['index'] = 'nids-alerts'
        
        # Send via TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            sock.sendall((json.dumps(alert) + '\n').encode())
```

**Integration**:
1. Update `alert_manager.py` to optionally forward to ELK
2. Add ELK toggle in dashboard
3. Configure in `config.py`

**Estimated Time**: 10 hours
**Dependencies**: 2.1

---

### 2.3 Kibana Dashboards

**Dashboards to Create**:

| Dashboard | Purpose | Complexity |
|-----------|---------|------------|
| **SOC Overview** | KPI cards, attack trends | LOW |
| **Alert Investigation** | Searchable alert table | MEDIUM |
| **Threat Map** | GeoIP visualization | MEDIUM |
| **Model Performance** | Detection accuracy over time | LOW |

**Setup Steps**:
1. Open Kibana at http://localhost:5601
2. Create index pattern: `nids-alerts-*`
3. Import saved objects (optional)
4. Create visualizations
5. Build dashboards

**Estimated Time**: 15 hours
**Dependencies**: 2.1, 2.2

---

### 2.4 Threat Intelligence Integration

**Files**: 
- `src/integration/ti_client.py`
- `src/integration/enricher.py`

```
┌─────────────────────────────────────────────────────────┐
│           Free Threat Intelligence Sources              │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ VirusTotal  │  │ AbuseIPDB   │  │    OTX      │   │
│  │ Free tier   │  │ Free tier   │  │ Free tier   │   │
│  │ 500/day     │  │ 5000/day    │  │ Unlimited   │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                │                 │            │
│         └────────────────┼─────────────────┘            │
│                          │                              │
│                   ┌──────▼──────┐                       │
│                   │   TI Cache   │                       │
│                   │  (SQLite 1hr)│                       │
│                   └──────┬──────┘                       │
│                          │                              │
│                          ▼                              │
│                   ┌──────────────┐                     │
│                   │ Alert Enrich │                     │
│                   └──────────────┘                     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

**Implementation**:

1. **`src/integration/ti_client.py`**:

```python
import requests
from typing import Optional

class ThreatIntelClient:
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    
    def __init__(self, vt_key: str, abuseipdb_key: str):
        self.vt_key = vt_key
        self.abuseipdb_key = abuseipdb_key
    
    def check_ip_virustotal(self, ip: str) -> dict:
        """Check IP against VirusTotal (500 req/day free)"""
        # Implementation here
        pass
    
    def check_ip_abuseipdb(self, ip: str) -> dict:
        """Check IP against AbuseIPDB (5000 req/day free)"""
        # Implementation here
        pass
    
    def check_ip_otx(self, ip: str) -> dict:
        """Check IP against AlienVault OTX (free, no key needed)"""
        # Implementation here
        pass
```

2. **`src/integration/enricher.py`**:

```python
class AlertEnricher:
    def enrich(self, alert: dict) -> dict:
        """Add threat intelligence to alert"""
        ip = alert.get('src_ip')
        
        # Check TI sources (with caching)
        ti_data = self.ti_client.get_all(ip)
        
        # Add to alert
        alert['ti_score'] = ti_data.get('score', 0)
        alert['ti_sources'] = ti_data.get('sources', [])
        alert['ti_reputation'] = ti_data.get('reputation', 'unknown')
        
        return alert
```

**API Keys Required** (Free):
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/account/api

**Estimated Time**: 20 hours
**Dependencies**: None (standalone)

---

### Phase 2 Tasks Summary

| Task | Hours | Deliverable |
|------|-------|-------------|
| ELK Stack setup | 10 | Running ELK container |
| Flask → ELK forwarding | 10 | `elk_forwarder.py` |
| Kibana dashboards | 15 | 4 working dashboards |
| TI integration | 20 | `ti_client.py`, `enricher.py` |
| Testing | 10 | Integration tests |
| **Phase 2 Total** | **65h** | |

---

## Phase 3: Dashboard & Polish (Months 4-5)

### 3.1 Enhanced Dashboard Architecture

**Keep**: Flask + Tailwind + Vanilla JS (no React)
**Add**: Investigation panel, TI integration

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ENHANCED DASHBOARD                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ Navigation: [Dashboard] [Investigation] [Threat Intel] [Settings] │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
│  ┌──────────────────────────────────┐ ┌───────────────────────────────┐ │
│  │     METRICS CARDS               │ │      ATTACK DISTRIBUTION      │ │
│  │  ┌───────┐ ┌───────┐ ┌───────┐  │ │         ┌─────────┐            │ │
│  │  │ Total │ │Attack │ │Susp.  │  │ │        ╱  DDoS    ╲           │ │
│  │  │ 1,234 │ │  156  │ │  23   │  │ │       │   28%     │            │ │
│  │  └───────┘ └───────┘ └───────┘  │ │        ╲          ╱           │ │
│  └──────────────────────────────────┘ │         └─────────┘          │ │
│                                        └───────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    RECENT ALERTS (with Investigation)              │  │
│  │  ┌──────────────────────────────────────────────────────────────┐ │  │
│  │  │ [🔍] │ IP           │ Type      │ Time      │ Actions        │ │  │
│  │  ├──────────────────────────────────────────────────────────────┤ │  │
│  │  │ [🔍] │ 203.0.113.50 │ DDoS      │ 14:32:15  │ [View] [Block] │ │  │
│  │  │ [🔍] │ 198.51.100.x │ PortScan  │ 14:31:02  │ [View] [Block] │ │  │
│  │  └──────────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Investigation Panel

**New File**: `templates/investigation.html`

```
┌─────────────────────────────────────────────────────────────────────────┐
│  THREAT INVESTIGATION WORKSPACE                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Selected Alert: 203.0.113.50                                           │
│                                                                          │
│  ┌───────────────────────┐ ┌───────────────────────────────────────────┐ │
│  │   ALERT DETAILS       │ │           THREAT INTELLIGENCE            │ │
│  │                       │ │                                           │ │
│  │  Time: 14:32:15 UTC   │ │  🟢 VirusTotal: 0/90 detections          │ │
│  │  Verdict: ATTACK       │ │  🟡 AbuseIPDB: 12 reports                │ │
│  │                       │ │  🔴 Country: Russia                       │ │
│  │  Models:              │ │                                           │ │
│  │  • RF: DDoS (99.2%)   │ │  ┌─────────────────────────────────────┐  │ │
│  │  • XGB: DDoS (98.8%)  │ │  │ ASN: AS12345 RUSSIA-TELECOM        │  │ │
│  │  • IF: Anomaly         │ │  │ Netblock: 203.0.112.0/24           │  │ │
│  │  • AE: Anomaly         │ │  │ First Seen: 2025-06-15             │  │ │
│  │                       │ │  └─────────────────────────────────────┘  │ │
│  │  Actions:             │ │                                           │ │
│  │  [Block IP]           │ │                                           │ │
│  │  [Add to Watchlist]   │ │                                           │ │
│  └───────────────────────┘ └───────────────────────────────────────────┘ │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │              IP WHOIS & REVERSE DNS                                 │ │
│  │  (Fetched from free APIs)                                           │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Implementation Steps**:
1. Add investigation tab to Flask routes
2. Create investigation.html template
3. Add TI lookup buttons
4. Implement IP WHOIS lookup (free API)
5. Add GeoIP display

**Estimated Time**: 15 hours

---

### 3.3 Threat Intel Panel

**New File**: `templates/threat_intel.html`

Features:
- IP lookup form
- VirusTotal results display
- AbuseIPDB results display
- OTX pulse indicators
- Cached results table

**Estimated Time**: 10 hours

---

### 3.4 Alert Management UI

**Enhancements**:
- Pagination for alerts
- Filter by type, severity, time
- Bulk actions (block multiple IPs)
- Export to CSV
- Alert status (new, acknowledged, resolved)

**Estimated Time**: 10 hours

---

### Phase 3 Tasks Summary

| Task | Hours | Deliverable |
|------|-------|-------------|
| Investigation UI | 15 | `investigation.html` |
| Threat Intel panel | 10 | `threat_intel.html` |
| Alert management UI | 10 | Enhanced `alerts.html` |
| Testing & polish | 15 | Bug fixes, UX improvements |
| **Phase 3 Total** | **50h** | |

---

## Final Month: Buffer & Documentation (Month 6)

| Task | Hours | Purpose |
|------|-------|---------|
| Bug fixes | 10 | Stabilize MVP |
| Documentation | 8 | README, setup guide |
| Demo prep | 5 | Attack simulations |
| Presentation | 7 | Academic presentation |
| **Total** | **30h** | |

---

## Complete Time Breakdown

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TOTAL TIME ESTIMATE                              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  Phase 1: ML Enhancements              │  60 hours                     │
│  ├── XGBoost classifier                │   15h                         │
│  ├── Isolation Forest                  │   20h                         │
│  ├── Ensemble voting                   │   15h                         │
│  └── Testing & validation              │   10h                         │
│                                                                        │
│  Phase 2: SIEM Integration             │  65 hours                     │
│  ├── ELK Stack setup                   │   10h                         │
│  ├── Flask → ELK forwarding            │   10h                         │
│  ├── Kibana dashboards                 │   15h                         │
│  ├── Threat intelligence               │   20h                         │
│  └── Testing                           │   10h                         │
│                                                                        │
│  Phase 3: Dashboard & Polish            │  50 hours                     │
│  ├── Investigation UI                   │   15h                         │
│  ├── Threat Intel panel                │   10h                         │
│  ├── Alert management UI               │   10h                         │
│  └── Testing & polish                  │   15h                         │
│                                                                        │
│  Final Month: Buffer                   │  30 hours                     │
│  ├── Bug fixes                         │   10h                         │
│  ├── Documentation                     │    8h                         │
│  ├── Demo prep                        │    5h                         │
│  └── Presentation                     │    7h                         │
│                                                                        │
│  ════════════════════════════════════════════════════════════════════  │
│  GRAND TOTAL                          │ 205 hours                     │
│                                                                        │
│  If 2 students working together:      │ ~100 hours each              │
│  If 1 student working alone:          │ ~35 hours/month (part-time)  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## File Structure (Simplified)

```
AI-NIDS/
├── src/
│   ├── capture/
│   │   └── sniffer.py              # Live packet capture
│   ├── features/
│   │   └── extractor.py            # Feature extraction
│   ├── models/
│   │   ├── autoencoder.py          # ✅ Existing
│   │   ├── train_rf.py             # ✅ Existing
│   │   ├── xgboost_classifier.py   # 🆕 NEW
│   │   ├── isolation_forest.py     # 🆕 NEW
│   │   ├── hybrid_predictor.py     # ✅ Update with ensemble
│   │   └── train_ensemble.py       # 🆕 NEW
│   ├── integration/
│   │   ├── elk_forwarder.py        # 🆕 NEW
│   │   ├── ti_client.py            # 🆕 NEW
│   │   └── enricher.py             # 🆕 NEW
│   └── api/
│       └── server.py               # ✅ Existing (update)
├── dashboard/
│   ├── app.py                      # ✅ Existing (update)
│   ├── templates/
│   │   ├── dashboard.html          # ✅ Existing (update)
│   │   ├── investigation.html      # 🆕 NEW
│   │   └── threat_intel.html       # 🆕 NEW
│   └── static/
│       └── css/, js/
├── elk/                            # 🆕 NEW
│   ├── docker-compose.elk.yml
│   └── logstash/
│       └── pipeline/
│           └── nids.conf
├── models/                         # ✅ Existing
│   ├── rf_model.pkl
│   ├── autoencoder.keras
│   ├── xgb_model.pkl              # 🆕 NEW
│   └── if_model.pkl               # 🆕 NEW
├── data/                           # ✅ Existing
├── tests/                          # ✅ Existing (update)
├── requirements.txt                # ✅ Existing (update)
├── docker-compose.yml              # ✅ Existing (update)
└── README.md                       # 🆕 Create
```

---

## Dependencies Overview

```
Phase 1 (ML)
    │
    ├── scikit-learn (existing)
    ├── xgboost (NEW: pip install xgboost)
    └── tensorflow (existing)

Phase 2 (SIEM)
    │
    ├── Docker Desktop (free download)
    ├── ELK Stack containers (free)
    ├── requests (pip install requests)
    └── python-dotenv (pip install python-dotenv)

Phase 3 (Dashboard)
    │
    ├── flask (existing)
    ├── tailwind (CDN, free)
    └── chart.js (CDN, free)
```

---

## Learning Objectives

By completing this project, students will gain:

### Machine Learning
- [ ] Understanding ensemble methods (voting classifiers)
- [ ] Experience with supervised vs unsupervised learning
- [ ] Practical XGBoost implementation
- [ ] Anomaly detection with Isolation Forest

### Security Operations
- [ ] SIEM concepts and implementation (ELK Stack)
- [ ] Threat intelligence integration
- [ ] Alert enrichment and investigation workflows
- [ ] Real-time security monitoring

### Software Engineering
- [ ] Flask API development
- [ ] Docker containerization
- [ ] Database integration (SQLite → ELK)
- [ ] Full-stack dashboard development

### DevOps & Tools
- [ ] ELK Stack deployment and configuration
- [ ] Logstash pipeline creation
- [ ] Kibana dashboard building
- [ ] API integration patterns

---

## Comparison: Original vs Student Plan

| Aspect | Original (Enterprise) | Student Edition |
|--------|------------------------|-----------------|
| **Duration** | 12 months | 6 months |
| **Team Size** | 5-10 engineers | 1-2 students |
| **Budget** | $100K+/year | $0 |
| **ML Models** | 6 models | 4 models |
| **Frontend** | React + TypeScript | Flask + Tailwind |
| **SIEM** | Splunk + QRadar | ELK Stack only |
| **TI Sources** | MISP + paid feeds | Free APIs only |
| **Cloud** | AWS/GCP/Azure | None (local only) |
| **SOAR** | Full automation | Python scripts only |

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| ELK Stack too resource-heavy | MEDIUM | LOW | Use minimal config, increase RAM if needed |
| TI API rate limits | LOW | MEDIUM | Implement caching, queue requests |
| Model performance degrades | LOW | HIGH | Keep existing RF+AE as fallback |
| Integration complexity | MEDIUM | MEDIUM | Start with simple forwarding, iterate |
| Time management | HIGH | HIGH | Strict adherence to timeline, cut features if needed |

---

## Success Criteria

### Phase 1 Complete When: ✅ COMPLETED (March 2026)
- [x] XGBoost model trained and saved (`xgb_model.json`)
- [x] Isolation Forest model trained and saved (`if_model.pkl`)
- [x] Ensemble voting returns combined predictions (`ensemble_voting.py`)
- [x] All models pass unit tests

### Phase 2 Complete When: ✅ COMPLETED (March 2026)
- [x] ELK Stack running locally (`elk/docker-compose.elk.yml`)
- [x] Alerts visible in Kibana (index pattern: `ainids-alerts-*`)
- [x] TI lookup returns results from 2+ sources (`/api/ti/lookup/<ip>`)
- [x] Alerts enriched with TI data (`src/integration/enricher.py`)

### Phase 2 Implementation Summary

| Component | File | Status |
|-----------|------|--------|
| ELK Docker Compose | `elk/docker-compose.elk.yml` | ✅ |
| Logstash Pipeline | `elk/logstash/pipeline/nids.conf` | ✅ |
| Kibana Config | `elk/kibana/kibana.yml` | ✅ |
| ELK Forwarder | `src/integration/elk_forwarder.py` | ✅ |
| TI Client | `src/integration/ti_client.py` | ✅ |
| Alert Enricher | `src/integration/enricher.py` | ✅ |
| API Keys Support | `.env` | ✅ |

### Phase 3 Complete When: 🔄 IN PROGRESS
- [x] Investigation page loads with alert details
- [x] TI panel shows lookup results
- [x] Alert filtering and pagination working
- [ ] Dashboard runs without errors (known bug: table refresh)

### Phase 3 Complete When:
- [ ] Investigation page loads with alert details
- [ ] TI panel shows lookup results
- [ ] Alert filtering and pagination working
- [ ] Dashboard runs without errors

### Final Project Complete When:
- [ ] Live demo shows full pipeline
- [ ] Documentation complete
- [ ] Presentation ready
- [ ] Code cleaned and commented

---

## Quick Start Commands

```bash
# Setup
git clone https://github.com/SudoToji/AI-NIDS.git
cd AI-NIDS
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Train Models
python -m src.models.train_rf
python -m src.models.train_ensemble

# Start ELK Stack
docker-compose -f elk/docker-compose.elk.yml up -d

# Start Dashboard
python -m src.api.server
# Open http://localhost:5000
```

---

## Appendix: Free API Keys

| Service | Sign Up URL | Free Tier |
|---------|-------------|-----------|
| VirusTotal | https://www.virustotal.com/gui/join-us | 500 req/day |
| AbuseIPDB | https://www.abuseipdb.com/account/api | 5000 req/day |
| OTX (AlienVault) | https://otx.alienvault.com/api | Unlimited |
| GeoLite2 | https://dev.maxmind.com/geoip/geolite2-free | 1000 req/day |

---

*Document Version: 2.1 - Student Edition (Phase 1 & 2 Complete)*  
*Last Updated: March 2026*
