# AI-NIDS: Network Intrusion Detection System

Multi-model NIDS using **UNSW-NB15** dataset with Random Forest + XGBoost ensemble and optional LLM-based Stage 2 verification.

## Quick Start

```bash
# 1. Setup
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 2. Train models (model files are gitignored)
python -m src.models.train_rf
python -m src.models.train_xgb

# 3. Run
run.bat
# Dashboard: http://localhost:5000
```

## Architecture

- **Dataset**: UNSW-NB15 (42 features, 9 attack categories + Normal)
- **Ensemble**: Random Forest + XGBoost
- **Anomaly Detectors**: Autoencoder + Isolation Forest (optional)
- **Stage 2**: LLM verification via OpenRouter for suspicious flows
- **Frontend**: HTML/JS dashboard with Plotly, Leaflet map

## Simulator

Test detection via API:

```bash
curl -X POST http://localhost:5000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"type":"dos","target_ip":"127.0.0.1"}'
```

**Supported types**: `fuzzers`, `analysis`, `backdoor`, `dos`, `exploits`, `generic`, `reconnaissance`, `shellcode`, `worms`, `normal`, `all`

## Model Training

| Model | Command | Required | Output |
|-------|---------|----------|--------|
| Random Forest | `python -m src.models.train_rf` | Yes | `rf_model.pkl`, `rf_metadata.pkl` |
| XGBoost | `python -m src.models.train_xgb` | Yes | `xgb_model.json`, `xgb_metadata.pkl` |

## Environment

See `.env` for configuration. Requires `OPENROUTER_API_KEY` for LLM Stage 2.

## Project Structure

```
src/api/         — Flask REST API
src/models/      — Training scripts + predictor
src/features/    — UNSW-NB15 feature extraction
src/detector/    — Live capture + alert manager
src/integration/ — Threat intel, ELK forwarder
src/simulator/   — Attack simulation
web/             — Dashboard HTML/CSS/JS
models/          — Trained model files (gitignored)
docs/            — API docs, setup guide
```

## See Also

- `AGENTS.md` — Troubleshooting, commands, common issues
- `docs/SETUP.md` — Full setup guide
- `docs/API.md` — API reference
