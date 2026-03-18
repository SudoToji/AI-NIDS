# AI-NIDS Future Improvements

A comprehensive roadmap for expanding attack detection capabilities and dashboard features.

---

## Table of Contents

1. [Research Overview](#research-overview)
2. [Similar Open Source Projects](#similar-open-source-projects)
3. [Available Datasets](#available-datasets)
4. [Attack Detection Expansion Plan](#attack-detection-expansion-plan)
5. [Dashboard Enhancements](#dashboard-enhancements)
6. [Implementation Roadmap](#implementation-roadmap)

---

## Research Overview

This document outlines a plan to enhance the AI-NIDS project by:
- Adding support for more attack types
- Integrating additional machine learning models
- Improving the dashboard with advanced visualizations

### Key Sources
- [CIC-IDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [UNSW-NB15 Dataset](https://www.unsw.adfa.edu.au/unsw-nb15-dataset/)
- [CSE-CIC-IDS2018 Dataset](https://www.unb.ca/cic/datasets/ids-2018.html)
- [arXiv: Machine Learning on CICIDS2017](https://arxiv.org/pdf/2506.19877)
- [Applied Intelligence: IDS Comparative Study](https://link.springer.com/article/10.1007/s10489-025-06422-4)

---

## Similar Open Source Projects

### Top Projects Found

| Project | Stars | Language | Key Features |
|---------|-------|----------|--------------|
| [GraphIDS](https://github.com/lorenzo9uerra/GraphIDS) | 30 | Python | Graph Neural Networks, Self-supervised learning (NeurIPS 2025) |
| [NIDShield-v2](https://github.com/akhilsamvarghese/NidShield-v2) | 2 | Jupyter | Dynamic learning, ML ensemble |
| [ml_nids](https://github.com/adamhelmi/ml_nids) | 2 | Python/PowerShell | Full ML pipeline, NSL-KDD dataset |
| [ThreatDetectAI](https://github.com/cadenshokat/ThreatDetectAI) | 1 | Python | Isolation Forest, KMeans, DBSCAN |
| [jakubporada/Network-IDS-ML](https://github.com/jakubporada/Network-IDS-ML) | 1 | Jupyter/JS | 99.99% DDoS detection accuracy |
| [nids-anomaly](https://github.com/waheeb71/nids-anomaly) | - | Python | Real-time anomaly detection |

### Lessons Learned

1. **Ensemble methods** work best (RF + XGBoost)
2. **Graph-based approaches** are emerging (GraphIDS NeurIPS 2025)
3. **Real-time processing** requires efficient feature extraction
4. **Multiple datasets** improve detection coverage

---

## Available Datasets

### Comparison Table

| Dataset | Attack Types | Records | Features | Year |
|---------|-------------|---------|----------|------|
| **CIC-IDS2017** | 14 | 2.5M+ | 80+ | 2017 |
| **CSE-CIC-IDS2018** | 12 | 16M+ | 80+ | 2018 |
| **UNSW-NB15** | 9 | 2.5M+ | 49 | 2015 |
| **NF-ToN-IoT-v3** | 34 | 46M+ | 55 | 2023 |
| **BigFlow-NIDS** | 34 | 67M+ | 55 | 2026 |
| **NSL-KDD** | 22 | 125K+ | 41 | 2009 |

### Recommended Datasets

1. **For Web Attacks**: UNSW-NB15 (XSS, SQLi, Brute Force)
2. **For Botnet**: CSE-CIC-IDS2018 (Bot, DDoS)
3. **For Comprehensive**: BigFlow-NIDS (34 attack types)

---

## Attack Detection Expansion Plan

### Phase 1: Enhance Current Model (Quick Win)

| Priority | Attack Category | Dataset | Model Type | Estimated Accuracy | Effort |
|----------|----------------|---------|------------|-------------------|--------|
| HIGH | Brute Force (SSH/FTP) | CIC-IDS2017 | Extend RF | 97%+ | Low |
| HIGH | Web Attacks (XSS, SQLi) | UNSW-NB15 | New RF | 95%+ | Medium |
| HIGH | Botnet Detection | CSE-CIC-IDS2018 | New RF | 96%+ | Medium |
| MEDIUM | Malware Traffic | CIC-IDS2017 | Autoencoder | 94%+ | Low |
| MEDIUM | Ransomware | UNSW-NB15 | XGBoost | 93%+ | Medium |
| LOW | DNS Tunneling | CSE-CIC-IDS2018 | RF | 91%+ | Medium |

### Phase 2: Add New Detection Models

| Model | Architecture | Use Case | Advantages |
|-------|--------------|----------|------------|
| **XGBoost** | Gradient Boosting | Classification | Often outperforms RF |
| **LightGBM** | Gradient Boosting | Large-scale | Faster training |
| **Autoencoder v2** | Deep Neural Network | Anomaly detection | Detects novel attacks |
| **Isolation Forest** | Tree-based anomaly | Zero-day detection | Unsupervised |
| **LSTM** | Recurrent Neural Net | Temporal patterns | Attack sequences |

### Phase 3: Advanced Techniques

| Technique | Description | Reference |
|-----------|-------------|-----------|
| **Graph Neural Networks** | Model network as graphs | [GraphIDS](https://github.com/lorenzo9uerra/GraphIDS) |
| **Transformer/BERT** | NLP for network logs | [NIDS with BERT](https://github.com/Eldrago12/NIDS) |
| **Ensemble Stacking** | Combine multiple models | XGB + RF + AE |

### Attack Labels to Add

```python
ATTACK_TYPES = [
    # Current
    "Benign",
    "DDoS",
    "DoS",
    "Port Scan",
    
    # NEW - Phase 1
    "Brute Force",      # SSH/FTP
    "Web Attack",       # XSS, SQLi
    "Bot",              # Botnet
    
    # NEW - Phase 2  
    "Infiltration",
    "Backdoor",
    "Shellcode",
    "Worm",
    "Ransomware",
]
```

### Ensemble Prediction Example

```python
def ensemble_predict(packet_features):
    """Combine predictions from multiple models."""
    
    # Get predictions
    rf_pred = rf_model.predict(features)
    rf_proba = rf_model.predict_proba(features)
    
    xgb_pred = xgb_model.predict(features)
    xgb_proba = xgb_model.predict_proba(features)
    
    ae_score = autoencoder.predict(features)
    is_anomaly = ae_score > threshold
    
    # Weighted voting
    if rf_pred == xgb_pred:
        final_pred = rf_pred
    elif is_anomaly:
        final_pred = "Suspicious"
    else:
        # Trust RF with high confidence
        if max(rf_proba) > 0.9:
            final_pred = rf_pred
        else:
            final_pred = "Suspicious"
    
    return final_pred
```

---

## Dashboard Enhancements

### 1. Attack Location Tracking (GeoIP)

#### Installation

```bash
pip install geoip2
```

Download GeoLite2 database from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/)

#### Implementation

```python
# server.py
import geoip2.database

# Load GeoIP database
geoip_reader = geoip2.database.Reader('GeoLite2-Country.mmdef')

def enrich_alert_with_geo(alert: Alert) -> dict:
    """Add geographic information to alert."""
    try:
        response = geoip_reader.country(alert.src_ip)
        return {
            **alert.to_dict(),
            'country': response.country.name,
            'country_code': response.country.iso_code,
            'continent': response.continent.name
        }
    except:
        return {**alert.to_dict(), 'country': 'Unknown'}
```

#### Add to API

```python
@app.route("/api/alerts-geo")
def get_alerts_with_geo():
    """Return alerts with geographic data."""
    alerts = alert_store.get_recent(n=100)
    return jsonify([enrich_alert_with_geo(a) for a in alerts])
```

### 2. World Map Visualization

#### Add to dashboard.html

```html
<!-- Include Leaflet CSS/JS -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<!-- Map Container -->
<div id="attack-map" class="h-96 rounded-xl"></div>

<script>
// Initialize map
const map = L.map('attack-map').setView([20, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap'
}).addTo(map);

// Attack markers
function updateAttackMap(alerts) {
    alerts.forEach(alert => {
        if (alert.country && alert.country !== 'Unknown') {
            L.marker([lat, lng])
                .addTo(map)
                .bindPopup(`${alert.src_ip} - ${alert.rf_label}`);
        }
    });
}
</script>
```

### 3. Advanced Visualizations

| Feature | Library | Description |
|---------|---------|-------------|
| **World Map** | Leaflet.js | Attack origins on map |
| **Heatmap** | Leaflet.heat | Density visualization |
| **Network Graph** | D3.js / Vis.js | Source → Target connections |
| **Time Series** | Chart.js | Detailed timeline |

### 4. Alerting Integrations

```python
# Email alerts
import smtplib
from email.mime.text import MIMEText

def send_alert_email(alert, recipients):
    msg = MIMEText(f"Attack detected from {alert.src_ip}")
    msg['Subject'] = f"NIDS Alert: {alert.rf_label}"
    
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, recipients, msg.as_string())

# Slack webhook
def send_slack_alert(alert):
    webhook_url = os.getenv('SLACK_WEBHOOK_URL')
    payload = {
        'text': f"🚨 *Attack Detected*\nType: {alert.rf_label}\nSource: {alert.src_ip}"
    }
    requests.post(webhook_url, json=payload)
```

---

## Implementation Roadmap

### Timeline

```
Month 1: Attack Detection Expansion
├── Week 1: Expand RF labels + retrain (LOW EFFORT)
├── Week 2: Add Brute Force model
├── Week 3: Add Web Attack model (XSS, SQLi)
└── Week 4: Add Botnet detection model

Month 2: Dashboard Enhancements
├── Week 1: GeoIP integration
├── Week 2: World map visualization
├── Week 3: Advanced charts
└── Week 4: Alert integrations (email/Slack)

Month 3: Advanced Models
├── Week 1-2: XGBoost ensemble
├── Week 3-4: Isolation Forest for zero-day
```

### Quick Wins (Low Effort)

| Task | Impact | Time |
|------|--------|------|
| Add more attack labels to RF | High | 1-2 hours |
| Lower AE threshold | Medium | 5 minutes |
| Add GeoIP to alerts | High | 2-3 hours |
| Add country flags to UI | Medium | 1 hour |

### Medium Effort Tasks

| Task | Impact | Time |
|------|--------|------|
| Train XGBoost model | High | 1-2 days |
| World map with markers | High | 4-8 hours |
| Add UNSW-NB15 web attack model | High | 2-3 days |

### Long-term Goals

| Task | Impact | Time |
|------|--------|------|
| Graph Neural Network | Very High | 1-2 weeks |
| Real-time packet capture | Very High | 1-2 weeks |
| Production deployment | High | 1 week |

---

## Resources

### Datasets
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)
- [UNSW-NB15](https://www.unsw.adfa.edu.au/unsw-nb15-dataset/)
- [BigFlow-NIDS](https://data.mendeley.com/datasets/nv729tbdgz)

### Research Papers
- [Evaluating ML on CICIDS2017 (arXiv 2025)](https://arxiv.org/pdf/2506.19877)
- [Advanced IDS Comparative Study (Springer 2025)](https://link.springer.com/article/10.1007/s10489-025-06422-4)
- [XGBoost for DDoS Detection (Nature 2026)](https://www.nature.com/articles/s41598-025-33851-5)

### Libraries
- [GeoIP2 Python](https://pypi.org/project/geoip2/)
- [Leaflet.js](https://leafletjs.com/)
- [XGBoost](https://xgboost.readthedocs.io/)
- [LightGBM](https://lightgbm.readthedocs.io/)

---

## Contributing

Feel free to contribute! Open an issue or submit a PR.

---

*Last Updated: March 2026*
*Version: 1.0*
