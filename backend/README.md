# NetGuard Pro Backend (Flask)

## Quickstart

1. Create venv and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

2. Run the server:

```bash
python -m backend.api.app
```

3. Health check:

```bash
curl http://localhost:8000/health
```

## API Endpoints
- POST `/api/ingest` { "packet": { ... } }
- GET `/api/incidents`
- POST `/api/scan` { "ip": "1.2.3.4" }
- POST `/api/analyze` { "packet": { ... } }