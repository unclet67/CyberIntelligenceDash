# ARGUS TI

ARGUS TI is an interactive threat-intelligence dashboard for exploring threat
actors, campaigns, indicators of compromise (IOCs), ATT&CK techniques, and
analytical reports.

The project includes a browser dashboard, a read-only FastAPI service,
PostgreSQL-compatible persistence, a STIX ingestion worker, optional bearer
authentication, and containerized development and production stacks.

The bundled records are demonstration data and must not be treated as current
operational reporting.

## Capabilities

- Browse threat-actor profiles, aliases, confidence, and attribution
- Explore campaigns by actor, sector, and status
- Filter IP, domain, hash, and URL indicators
- Review ATT&CK technique coverage and report metadata
- Load live API records with an automatic demonstration-data fallback
- Ingest STIX 2.1 intrusion sets, techniques, indicators, and relationships
- Audit ingestion attempts and item counts
- Require bearer-token authentication for data endpoints
- Run with SQLite locally or PostgreSQL through Docker

## Architecture

```text
Approved STIX sources
         |
         v
Ingestion and validation worker
         |
         v
     PostgreSQL
         |
         v
 FastAPI read API
         |
         v
 ARGUS TI dashboard
```

## Quick start

Start the API:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8001
```

In a second terminal, serve the dashboard:

```bash
python3 -m http.server 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). API documentation is
available at [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs).

## Docker development

```bash
docker compose up --build
```

To include the scheduled ingestion worker, configure `STIX_FEED_URL` and run:

```bash
docker compose --profile ingestion up --build
```

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Verify API and database availability |
| `GET` | `/api/dashboard/bootstrap` | Load the complete dashboard contract |
| `GET` | `/api/actors` | List and filter threat actors |
| `GET` | `/api/actors/{actor_id}` | Retrieve a detailed actor profile |
| `GET` | `/api/campaigns` | List campaigns by actor or status |
| `GET` | `/api/iocs` | List and filter indicators |
| `GET` | `/api/attack/techniques` | List ATT&CK techniques |
| `GET` | `/api/reports` | List report metadata |
| `GET` | `/api/ingestion/runs` | Review ingestion history |

## Tests

```bash
cd backend
pytest
```

The suite covers the API, seed collections, filters, authentication, frontend
contract, STIX normalization, audit records, and idempotent ingestion.

## Project structure

```text
.
├── index.html
├── BACKEND.md
├── DEPLOYMENT.md
├── docker-compose.yml
├── docker-compose.production.yml
├── deploy/
└── backend/
    ├── app/
    ├── alembic/
    └── tests/
```

## Security and data quality

- Validate attribution, timestamps, confidence, and provenance before use.
- Do not automatically visit indicators or execute referenced files.
- Keep tokens and database credentials out of Git and in a secret store.
- Enable authentication, TLS, restricted CORS, and outbound allowlists in
  production.
- Set `SEED_ON_STARTUP=false` before loading approved production data.
- Back up PostgreSQL and monitor health and failed ingestion runs.

See [BACKEND.md](BACKEND.md) for API and worker instructions and
[DEPLOYMENT.md](DEPLOYMENT.md) for production deployment.
