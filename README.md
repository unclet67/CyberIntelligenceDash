# ARGUS TI

ARGUS TI is an interactive threat-intelligence dashboard for exploring threat
actors, campaigns, indicators of compromise (IOCs), ATT&CK techniques, and
analytical reports.

The project currently includes a standalone browser dashboard and a backend
foundation built with FastAPI and SQLAlchemy. The bundled intelligence records
are demonstration data and should not be treated as current operational
reporting.

## Current capabilities

- Browse threat-actor profiles, aliases, confidence, and attribution
- Explore campaigns by actor, sector, and activity status
- Filter IP, domain, hash, and URL indicators
- Review ATT&CK technique coverage
- Display actor timelines and report metadata
- Serve seeded data through a read-only REST API
- Run locally with SQLite or with PostgreSQL through Docker Compose

## Architecture

```text
Threat-intelligence sources (planned)
                  |
                  v
        Ingestion and validation
                  |
                  v
             PostgreSQL
                  |
                  v
          FastAPI REST API
                  |
                  v
         ARGUS TI dashboard
```

The frontend still uses embedded demonstration arrays. Connecting
`index.html` to the API is the next integration milestone.

## Quick start: dashboard

From the repository root, start a local static server:

```bash
python3 -m http.server 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in a browser.

## Quick start: API

Python 3.11 or newer is required.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
uvicorn app.main:app --reload --port 8001
```

Useful local URLs:

- API information: [http://127.0.0.1:8001](http://127.0.0.1:8001)
- Interactive API documentation: [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs)
- Health check: [http://127.0.0.1:8001/api/health](http://127.0.0.1:8001/api/health)

The default development configuration creates and seeds a local SQLite
database on first startup.

## Run with PostgreSQL

Docker Desktop or another Docker-compatible runtime is required.

```bash
docker compose up --build
```

This starts PostgreSQL and exposes the API on port `8001`.

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Verify API and database availability |
| `GET` | `/api/actors` | List and filter threat actors |
| `GET` | `/api/actors/{actor_id}` | Retrieve a detailed actor profile |
| `GET` | `/api/campaigns` | List campaigns by actor or status |
| `GET` | `/api/iocs` | List and filter indicators |
| `GET` | `/api/attack/techniques` | List ATT&CK techniques |
| `GET` | `/api/reports` | List report metadata |

## Database migrations

From the `backend` directory:

```bash
alembic upgrade head
```

Production deployments should apply migrations before starting the API and
set `SEED_ON_STARTUP=false` after loading approved data.

## Tests

```bash
cd backend
pytest
```

The test suite covers health checks, seeded actor data, actor details,
campaign and IOC filters, ATT&CK techniques, and reports.

## Project structure

```text
.
├── index.html                 # Current standalone dashboard
├── BACKEND.md                 # Detailed backend instructions
├── docker-compose.yml         # API and PostgreSQL services
└── backend/
    ├── app/                   # FastAPI application and data models
    ├── alembic/               # Database migrations
    ├── tests/                 # API tests
    ├── .env.example           # Local configuration template
    ├── Dockerfile
    └── pyproject.toml
```

## Security and data-quality notes

- Bundled records are seed data for development and demonstration.
- Validate attribution, timestamps, and provenance before operational use.
- Treat indicators as potentially harmful data; do not automatically visit
  URLs or execute referenced files.
- Keep API keys and database credentials in `.env` or a managed secret store.
- The current API is read-only and does not yet implement authentication.
- Restrict CORS origins and disable automatic seeding in production.

## Roadmap

- Replace frontend arrays with API requests
- Add source-backed ingestion and normalization
- Preserve record-level provenance and confidence history
- Add authentication and role-based authorization
- Add pagination, audit logging, and rate limiting
- Add deployment and monitoring workflows

See [BACKEND.md](BACKEND.md) for additional backend setup details.
