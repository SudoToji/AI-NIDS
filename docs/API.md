# API Documentation

AI-NIDS provides a REST API for programmatic access to predictions, alerts, and threat intelligence.

## Base URL

```
http://localhost:5000
```

## Endpoints

### Health Check

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Check API and all model statuses |

**Response:**
```json
{
  "status": "healthy",
  "models_loaded": {
    "random_forest": true,
    "autoencoder": true,
    "scaler": true,
    "xgboost": true,
    "isolation_forest": true
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Dashboard Statistics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Dashboard statistics |

**Response:**
```json
{
  "total": 100,
  "attacks": 45,
  "suspicious": 10,
  "benign": 45,
  "attack_rate": 55.0
}
```

### Alerts

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | Recent alerts with multi-model predictions |

**Query Parameters:**
- `n` (int, default: 100): Number of alerts to return

**Response:**
```json
[
  {
    "id": 1,
    "timestamp": "2024-01-01T12:00:00Z",
    "src_ip": "192.168.1.100",
    "dst_ip": "192.168.1.1",
    "src_port": 54321,
    "dst_port": 80,
    "protocol": 6,
    "rf_label": "DDoS",
    "rf_confidence": 0.99,
    "ae_anomaly_score": 0.15,
    "ae_is_anomaly": false,
    "xgb_label": "DDoS",
    "xgb_confidence": 0.98,
    "if_is_anomaly": false,
    "if_anomaly_score": 0.2,
    "final_verdict": "Attack",
    "combined_confidence": 0.99
  }
]
```

### Attack Distribution

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/attack-distribution` | GET | Attack type distribution |
| `/api/attack-distribution-mapped` | GET | Mapped for dashboard |

**Response (mapped):**
```json
{
  "DDoS": 25,
  "Port Scanning": 15,
  "Others": 10,
  "Benign": 50
}
```

### Timeline

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/timeline` | GET | Timeline data for charts |

**Query Parameters:**
- `minutes` (int, default: 60): Time window in minutes

**Response:**
```json
{
  "timestamps": ["11:00", "11:05", "11:10"],
  "attacks": [5, 8, 3],
  "suspicious": [1, 2, 0],
  "benign": [10, 15, 20]
}
```

### Top Attackers

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/top-attackers` | GET | Top attacking IPs |

**Query Parameters:**
- `n` (int, default: 10): Number of top attackers to return

**Response:**
```json
[
  {"src_ip": "192.168.1.100", "alert_count": 45},
  {"src_ip": "192.168.1.101", "alert_count": 30}
]
```

### IP Blocking

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/blocked-ips` | GET | List blocked IPs |
| `/api/block-ip` | POST | Block an IP |
| `/api/unblock-ip` | POST | Unblock an IP |

**Block IP Request:**
```json
{
  "ip": "192.168.1.100"
}
```

**Response:**
```json
{
  "ip": "192.168.1.100",
  "blocked": true
}
```

### Prediction

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/predict` | POST | Predict on packet data |

**Request:**
```json
{
  "src_ip": "192.168.1.100",
  "dst_ip": "192.168.1.1",
  "src_port": 54321,
  "dst_port": 80,
  "protocol": 6,
  "flow_duration": 255000,
  "packet_count": 500,
  "byte_count": 25000
}
```

**Response:** Same as alert object

### Attack Simulation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/simulate` | POST | Run attack simulation |

**Request:**
```json
{
  "type": "ddos",
  "target_ip": "127.0.0.1"
}
```

**Valid Types:**
- `normal` - Normal traffic
- `ddos` - Distributed Denial of Service
- `synflood` - SYN Flood attack
- `portscan` - Port Scanning
- `slowloris` - Slowloris attack
- `bruteforce` - Brute Force attack
- `webattacks` - Web Attacks

**Response:**
```json
{
  "type": "ddos",
  "target_ip": "127.0.0.1",
  "alerts_generated": 30,
  "alerts": [...]
}
```

### Clear Alerts

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/clear` | POST | Clear all alerts |

**Response:**
```json
{
  "success": true
}
```

## Threat Intelligence

### IP Lookup

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/ti/lookup/<ip>` | GET | Threat Intelligence lookup |
| `/api/ti/test` | GET | Test TI endpoint |

**Response:**
```json
{
  "ip": "192.168.1.100",
  "score": 75,
  "reputation_label": "Malicious",
  "is_malicious": true,
  "sources": {
    "virustotal": {"malicious": 8, "total": 90},
    "abuseipdb": {"reports": 45, "confidence": 75},
    "otx": {"pulses": 12}
  },
  "country": "XX",
  "asn": "AS12345",
  "cached": false
}
```

### Reputation Labels

| Label | Description |
|-------|-------------|
| `Clean` | No threat indicators |
| `Suspicious` | Some suspicious activity |
| `Malicious` | Known malicious IP |
| `Internal` | Private/internal IP address |

## Error Responses

All endpoints may return error responses:

```json
{
  "error": "Error message description"
}
```

**Status Codes:**
- `200` - Success
- `400` - Bad Request (invalid input)
- `404` - Not Found
- `500` - Internal Server Error

## Model Prediction Fields

Each alert includes predictions from all four models:

| Field | Description |
|-------|-------------|
| `rf_label` | Random Forest classification label |
| `rf_confidence` | Random Forest confidence (0-1) |
| `xgb_label` | XGBoost classification label |
| `xgb_confidence` | XGBoost confidence (0-1) |
| `ae_anomaly_score` | Autoencoder reconstruction error |
| `ae_is_anomaly` | Autoencoder anomaly detection result |
| `if_anomaly_score` | Isolation Forest anomaly score (0-1) |
| `if_is_anomaly` | Isolation Forest anomaly detection result |
| `final_verdict` | Ensemble verdict (Attack/Suspicious/Benign) |
| `combined_confidence` | Combined confidence score (0-1) |
