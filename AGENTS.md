# AI-NIDS AGENTS.md

## Running the Server

```bash
# Windows
run.bat

# Or manually
venv\Scripts\python.exe -m src.api.server
```

API: http://localhost:5000

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `src/api` | Flask REST API server |
| `src/models` | ML models (RF, Autoencoder, XGBoost, Isolation Forest) |
| `src/features` | UNSW-NB15 feature extraction |
| `src/integration` | Threat intel, ELK forwarder |
| `src/detector` | Live capture, alert manager |
| `src/simulator` | Attack simulation, evaluation |
| `web` | Dashboard HTML files |
| `models` | Pre-trained model files (`.pkl`, `.keras`) |
| `data/unsw_nb15` | UNSW-NB15 dataset |

## Important Commands

```bash
# API server entry point (runs from venv)
python -m src.api.server

# Run tests
pytest

# Lint
ruff check src/

# Train RF model
python -m src.models.train_rf

# Train Autoencoder
python -m src.models.autoencoder
```

## Context Files

- `.planning/` — Phase planning docs and decisions
- `graphify-out/` — Knowledge graph for codebase exploration
- `docs/SETUP.md` — Full setup guide with troubleshooting

## Env Variables (`.env`)

```
OPENROUTER_API_KEY=    # Required for LLM deep verification (optional)
VIRUSTOTAL_API_KEY=   # Threat intel (optional)
ABUSEIPDB_API_KEY=    # Threat intel (optional)
LIVE_CAPTURE=false    # Enable packet capture
```

## Testing Notes

- Tests are in `tests/` directory
- Some tests require OpenRouter API key (mock or skip if unavailable)
- Models must exist in `models/` for integration tests

## Architecture Summary

- **Detection pipeline**: capture → features → hybrid model → ensemble voting → alerts
- **Threat intel**: OTX (AlienVault), VirusTotal, AbuseIPDB (optional)
- **Dashboard**: HTML/JS with Plotly, auto-refresh via `/api/stats`
- **Storage**: SQLite alerts.db (in-memory alerts)