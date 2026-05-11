# Project Name

AI-NIDS: Network Intrusion Detection System

## Setup

```bash
# Installation
npm install

# Environment variables
cp .env.example .env.local
# Fill in: OPENAI_API_KEY, REDIS_URL, etc.

# Development
npm run dev

# Build
npm run build
```

## Architecture

See [docs/CODEMAPS/INDEX.md](docs/CODEMAPS/INDEX.md) for detailed architecture.

### Key Directories

- `src/api` - REST API server
- `src/models` - Machine learning models (Autoencoder, Deep Verifier, Ensemble Voting, etc.)
- `src/features` - Feature extractors and processor
- `src/integration` - Threat intelligence and ELK integrations
- `src/capture` - Packet sniffing and live capture
- `src/simulator` - Attack simulator and evaluation
- `web` - Dashboard HTML/JS/CSS UI files

## Features

- Core Detection
- Threat Intelligence 
- Dashboard & Visualization
- Integration

## Documentation

- [Setup Guide](docs/GUIDES/setup.md)
- [API Reference](docs/GUIDES/api.md)
- [Architecture](docs/CODEMAPS/INDEX.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)