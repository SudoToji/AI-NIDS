# Requirements: AI-NIDS

**Defined:** 2026-05-07
**Core Value:** Detect network intrusions with high accuracy and provide explainable verdicts through LLM reasoning.

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Capture

- [ ] **CAP-01**: User can capture live network packets via Scapy
- [ ] **CAP-02**: User can process captured packets into network flows

### Features

- [ ] **FEAT-01**: System can extract 49 UNSW-NB15 features from network flows
- [ ] **FEAT-02**: Features are normalized using standard scaler

### Detection

- [ ] **DET-01**: Random Forest can classify network traffic as normal/attack
- [ ] **DET-02**: XGBoost can classify network traffic as normal/attack
- [ ] **DET-03**: Autoencoder can detect anomalies in network traffic
- [ ] **DET-04**: Ensemble voting combines RF + XGB + AE predictions
- [ ] **DET-05**: HybridPredictor fuses all model predictions

### Verification

- [ ] **VER-01**: DeepVerifier (LLM) analyzes uncertain predictions
- [ ] **VER-02**: LLM provides explainable verdict with reasoning

### Alerts

- [ ] **ALERT-01**: System generates alerts for detected attacks
- [ ] **ALERT-02**: Alerts are stored and retrievable
- [ ] **ALERT-03**: Dashboard displays alerts with details

### Dashboard

- [ ] **DASH-01**: Web dashboard shows detection status
- [ ] **DASH-02**: Dashboard displays real-time alerts
- [ ] **DASH-03**: Dashboard shows attack investigation tools

### Simulation

- [ ] **SIM-01**: Attack simulator can generate synthetic attacks
- [ ] **SIM-02**: Simulator can feed to detection pipeline for testing

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Integration

- **INT-01**: Threat intelligence integration (VirusTotal)
- **INT-02**: ELK stack logging integration
- **INT-03**: GeoIP enrichment for alert sources

### Performance

- **PERF-01**: Real-time detection under high load
- **PERF-02**: Distributed detection across multiple sensors

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Mobile app | Web dashboard sufficient for v1 |
| Hardware IDS | Software-only for v1 |
| 5G analysis | Focus on LAN/WAN for v1 |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| CAP-01 | Phase 1 | Pending |
| CAP-02 | Phase 1 | Pending |
| FEAT-01 | Phase 1 | Pending |
| FEAT-02 | Phase 1 | Pending |
| DET-01 | Phase 1 | Pending |
| DET-02 | Phase 1 | Pending |
| DET-03 | Phase 1 | Pending |
| DET-04 | Phase 1 | Pending |
| DET-05 | Phase 1 | Pending |
| VER-01 | Phase 1 | Pending |
| VER-02 | Phase 1 | Pending |
| ALERT-01 | Phase 1 | Pending |
| ALERT-02 | Phase 1 | Pending |
| ALERT-03 | Phase 1 | Pending |
| DASH-01 | Phase 1 | Pending |
| DASH-02 | Phase 1 | Pending |
| DASH-03 | Phase 1 | Pending |
| SIM-01 | Phase 1 | Pending |
| SIM-02 | Phase 1 | Pending |

**Coverage:**
- v1 requirements: 19 total
- Mapped to phases: 0
- Unmapped: 19 ⚠️

---
*Requirements defined: 2026-05-07*
*Last updated: 2026-05-07 after initial definition*