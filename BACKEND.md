# ARGUS TI backend

The backend provides a read-only FastAPI service, PostgreSQL-compatible data
models, versioned migrations, seeded demonstration records, optional bearer
authentication, and a STIX ingestion worker.

## Local API

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8001
```

Open `http://127.0.0.1:8001/docs` for interactive API documentation. The
dashboard served on port `8000` automatically loads `/api/dashboard/bootstrap`
and falls back to its bundled demonstration arrays when the API is unavailable.

## PostgreSQL development stack

From the repository root:

```bash
docker compose up --build
```

The API is available at `http://127.0.0.1:8001`.

## STIX ingestion worker

Ingest one local STIX 2.1 bundle:

```bash
cd backend
python -m app.worker --once --file /path/to/bundle.json
```

Ingest one remote bundle:

```bash
python -m app.worker --once --url https://approved.example/bundle.json
```

To run the scheduled development worker, set `STIX_FEED_URL` and use:

```bash
docker compose --profile ingestion up --build
```

The worker upserts intrusion sets, ATT&CK techniques, indicators, and `uses`
relationships. Every attempt is recorded in `ingestion_runs` with status and
item counts.

## Authentication

Development is unauthenticated by default. To require a bearer token:

```dotenv
AUTH_REQUIRED=true
API_AUTH_TOKEN=replace-with-a-long-random-token
```

The health endpoint remains public. Data endpoints require
`Authorization: Bearer <token>`. The dashboard asks for the token after a 401
response and keeps it in browser session storage only.

## API surface

- `GET /api/health`
- `GET /api/dashboard/bootstrap`
- `GET /api/actors`
- `GET /api/actors/{actor_id}`
- `GET /api/campaigns`
- `GET /api/iocs`
- `GET /api/attack/techniques`
- `GET /api/reports`
- `GET /api/ingestion/runs`

## Migrations and tests

```bash
cd backend
alembic upgrade head
pytest
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the production Compose stack and
operational requirements.
