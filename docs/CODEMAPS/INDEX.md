# System Architecture Codemap

**Last Updated:** 2026-05-06
**Entry Points:** `src/api/server.py`, `src/detector/live_capture.py`

## Architecture

```
[Web UI] <--> [API Server] <--> [Hybrid Predictor]
                   |                  |
           [Threat Intel]     [Feature Extractor]
                   |                  |
              [ELK Stack]      [Packet Sniffer]
```

## Key Modules

| Module | Purpose | Exports | Dependencies |
|--------|---------|---------|--------------|
| `src/api` | REST API | `server.py` | Flask, Models, Integration |
| `src/models` | ML Models | `hybrid_predictor.py`, `autoencoder.py`, `deep_verifier.py` | TF/Keras, scikit-learn |
| `src/features` | Data Processing | `extractor.py`, `unsw_processor.py` | pandas, numpy |
| `src/integration` | External APIs | `ti_client.py`, `elk_forwarder.py` | requests |
| `src/simulator` | Testing/Sim | `attack_sim.py`, `evaluator.py` | scapy |
| `web` | Dashboard | HTML files (`index.html`, `simulator.html`) | JS, CSS, REST API |

## Data Flow

1. Packet Sniffer captures network traffic
2. Feature Extractor converts to ML features
3. Hybrid Predictor classifies (Normal vs Attack)
4. Threat Intelligence enriches with IP data
5. Alert Manager saves to DB and API Server
6. Web Dashboard displays to user

## Related Areas
- [Backend (API)](backend.md)
- [Models](models.md)
- [Frontend](frontend.md)