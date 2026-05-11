# Backend (API) Codemap

**Last Updated:** 2026-05-06
**Entry Points:** `src/api/server.py`

## Architecture

RESTful Flask API serving the AI-NIDS dashboard and integrations.

## Key Modules

| Module | Purpose | Exports | Dependencies |
|--------|---------|---------|--------------|
| `src/api/server.py` | Main web server | `app` | Flask, Models |
| `src/integration/ti_client.py` | Threat Intel | `TIClient` | requests |
| `src/integration/elk_forwarder.py`| ELK Integration | `ELKForwarder` | elasticsearch |

## Data Flow

API endpoints receive requests from Web Dashboard, pull data from internal DB/memory, and trigger model predictions or simulations.

## External Dependencies
- Flask
- Requests
- Elasticsearch
