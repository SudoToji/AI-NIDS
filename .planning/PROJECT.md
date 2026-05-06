# AI-NIDS

## What This Is

AI-powered Network Intrusion Detection System using a Two-Stage Hybrid architecture. Combines traditional ML models (Random Forest, XGBoost, Autoencoder) with LLM-based deep verification for accurate attack detection with explainable results.

## Core Value

Detect network intrusions with high accuracy and provide explainable verdicts through LLM reasoning.

## Requirements

### Validated

- ✓ Live packet capture via Scapy — existing
- ✓ Feature extraction (49 UNSW-NB15 features) — existing
- ✓ Random Forest classification — existing
- ✓ XGBoost classification — existing
- ✓ Autoencoder anomaly detection — existing
- ✓ Ensemble voting (RF + XGB + AE) — existing
- ✓ HybridPredictor combining all models — existing
- ✓ DeepVerifier (LLM Stage 2) for uncertain predictions — existing
- ✓ Alert storage and retrieval — existing
- ✓ Web dashboard (Streamlit) — existing
- ✓ Attack simulation for testing — existing

### Active

- [ ] [New requirement 1]
- [ ] [New requirement 2]

### Out of Scope

- [Feature] — [why]

## Context

**Technical Environment:**
- Python 3.11+ with TensorFlow/Keras, scikit-learn
- UNSW-NB15 dataset (migrated from CIC-IDS2017)
- OpenRouter API for LLM calls

**Known Issues:**
- RF shows 68% accuracy on UNSW-NB15 (vs 99.76% on CIC-IDS2017) — may need tuning
- Multi-processing limitations on Windows

## Constraints

- **Tech Stack**: Python 3.11+, TensorFlow, scikit-learn — Already established
- **API Dependency**: OpenRouter for LLM — DeepVerifier requires API key

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Two-Stage Hybrid | Balance speed (ML) with accuracy (LLM) | ✓ Good |
| UNSW-NB15 Dataset | More diverse attack types than CIC-IDS2017 | — Pending |

---

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---

*Last updated: 2026-05-07 after initialization*