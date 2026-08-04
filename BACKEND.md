# ARGUS TI backend

The backend provides a read-only FastAPI service, PostgreSQL-compatible data
models, versioned migrations, seeded demonstration records, optional bearer
authentication, and source-aware MITRE ATT&CK and Malpedia ingestion.

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
and falls back to bundled demonstration records when the API is unavailable.

## PostgreSQL development stack

From the repository root:

```bash
docker compose up --build
```

The API is available at `http://127.0.0.1:8001`.

## MITRE and Malpedia sync

Run both source adapters once:

```bash
cd backend
python -m app.worker --once --source all
```

Run a single adapter:

```bash
python -m app.worker --once --source mitre
python -m app.worker --once --source malpedia
```

Configuration:

```dotenv
MITRE_STIX_URL=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
MALPEDIA_BASE_URL=https://malpedia.caad.fkie.fraunhofer.de
MALPEDIA_API_TOKEN=
INGESTION_INTERVAL_SECONDS=3600
```

Malpedia actor endpoints do not require registration. If a token is provided,
the backend sends `Authorization: apitoken <token>` as documented by Malpedia.
Never put this token in `index.html` or another browser-delivered file.

The identity merge order is:

1. Existing source external ID
2. MITRE ATT&CK group ID
3. Case-insensitive canonical name or alias
4. New actor profile

Each actor may have multiple `actor_sources` records. These retain the source
name, external ID, public profile URL, and last successful sync time. MITRE
contributes descriptions and ATT&CK technique relationships; Malpedia enriches
aliases, country/sponsor metadata when existing fields are unknown, and its
actor profile link. Empty source fields never erase populated actor fields.

To run scheduled syncs in Docker:

```bash
docker compose --profile ingestion up --build
```

The legacy custom STIX workflow remains available:

```bash
python -m app.worker --once --source stix --file /path/to/bundle.json
python -m app.worker --once --source stix --url https://approved.example/bundle.json
```

Every attempt is recorded in `ingestion_runs` with status and item counts.

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

Actor responses include `source_profiles`, for example:

```json
{
  "source_name": "Malpedia",
  "external_id": "apt28",
  "profile_url": "https://malpedia.caad.fkie.fraunhofer.de/actor/apt28",
  "last_synced_at": "2026-08-04T18:00:00Z"
}
```

## Migrations and tests

```bash
cd backend
alembic upgrade head
pytest
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the production Compose stack and
operational requirements.
