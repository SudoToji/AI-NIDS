# AI-NIDS AGENTS.md

## Running the Server

```bash
# Windows
run.bat

# Or manually
venv\Scripts\python.exe -m src.api.server
```

API: http://localhost:5000

## Dataset: UNSW-NB15

**42 features, 9 attack categories + Normal** (`data/unsw_nb15/`)

The scaler (`unsw_scaler.pkl`, RF, XGBoost, Autoencoder, Isolation Forest are all trained on UNSW-NB15. Legacy CIC-IDS2017 references (52 features) in comments are obsolete.

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `src/api` | Flask REST API server |
| `src/models` | ML training scripts |
| `src/features` | UNSW-NB15 feature extraction |
| `src/integration` | Threat intel, ELK forwarder |
| `src/detector` | Live capture, alert manager |
| `src/simulator` | Attack simulation, evaluation |
| `web` | Dashboard HTML files |
| `models` | Pre-trained model files |
| `data/unsw_nb15` | UNSW-NB15 dataset |

## Model Training (Required Before Running)

Model files are gitignored — train them first:

```bash
# 1. Random Forest (RF)
python -m src.models.train_rf

# 2. XGBoost (XGB) — UNSW-NB15, 42 features
python -m src.models.train_xgb

# Models saved to: models/rf_model.pkl, rf_metadata.pkl, xgb_model.json, xgb_metadata.pkl
```

**Autoencoder and Isolation Forest** — training scripts exist but need implementation.

## Common Issues & Fixes

| Issue | Cause | Fix |
|-------|-------|-----|
| All attacks show "Benign" | Model files missing | Train models above |
| XGBoost import error | Package version conflict | `pip install --force-reinstall xgboost` |
| "Feature shape mismatch, expected: 52, got 42" | XGB model trained on wrong dataset | Retrain XGB on UNSW-NB15 |
| No attack types detected | RF model missing (only XGB running) | Train RF model |
| Simulator shows "Using synthetic simulation" | UNSW dataset not found at `data/unsw_nb15/Training\ and\ Testing\ Sets/` | Download UNSW-NB15 dataset |
| Scaler "feature names" warnings | StandardScaler fitted without column names (cosmetic, safe) | Ignore |

## Two-Stage Pipeline (LLM Stage 2)

Stage 2 LLM verification triggers when Stage 1 returns `Suspicious`:

```bash
# Requires OPENROUTER_API_KEY in .env
# Gets a free key at: https://openrouter.ai/
```

## Important Commands

```bash
# API server
python -m src.api.server

# Run all tests
pytest

# Run a specific test
pytest tests/test_two_stage_pipeline.py -v

# Train models
python -m src.models.train_rf
python -m src.models.train_xgb

# Lint
ruff check src/

# Simulate attacks via API
curl -X POST http://localhost:5000/api/simulate -H "Content-Type: application/json" -d '{"type":"dos","target_ip":"127.0.0.1"}'
```

## Env Variables (`.env`)

```
OPENROUTER_API_KEY=    # LLM Stage 2 verification (optional)
VIRUSTOTAL_API_KEY=     # Threat intel (optional)
ABUSEIPDB_API_KEY=      # Threat intel (optional)
LIVE_CAPTURE=false      # Enable packet capture (requires Npcap)
```

## Testing Notes

- Tests are in `tests/` directory
- Some tests require OpenRouter API key — mock or skip if unavailable
- Models must exist in `models/` for integration tests
- `test_hybrid_predictor.py` and `test_ensemble_voting.py` are stale (reference old API), skip them

## Architecture Summary

- **Detection pipeline**: data → feature extraction → RF + XGBoost ensemble → verdict
- **Anomaly detectors** (disabled if missing): Autoencoder, Isolation Forest
- **Stage 2 verification**: OpenRouter LLM for ambiguous flows
- **Threat intel**: OTX (AlienVault), VirusTotal, AbuseIPDB (optional)
- **Dashboard**: HTML/JS with Plotly, auto-refresh via `/api/stats`
- **Storage**: In-memory alerts (lost on restart)
