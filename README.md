# ARGUS TI

ARGUS TI is an interactive threat-intelligence dashboard for exploring threat
actors, campaigns, indicators of compromise (IOCs), ATT&CK techniques, and
analytical reports.

The project includes a browser dashboard, a read-only FastAPI service,
PostgreSQL-compatible persistence, source-aware ingestion workers, optional
bearer authentication, and containerized development and production stacks.

The bundled records are demonstration data and must not be treated as current
operational reporting.

## Capabilities

- Browse threat-actor profiles, aliases, confidence, and attribution
- Merge MITRE ATT&CK and Malpedia metadata into one actor profile
- Preserve per-source external IDs, profile links, and last-sync timestamps
- Ingest recent ThreatFox IOCs with confidence, malware, tags, and expiration
- Explore campaigns by actor, sector, and status
- Filter IP, domain, hash, and URL indicators
- Review ATT&CK technique coverage and report metadata
- Load live API records with an automatic demonstration-data fallback
- Audit ingestion attempts and item counts
- Require bearer-token authentication for data endpoints
- Run with SQLite locally or PostgreSQL through Docker

## Architecture

```text
MITRE ATT&CK STIX   Malpedia actor API   ThreatFox IOC API
         \                  /
          v                v
       Source-aware ingestion and identity merge
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

## Sync live intelligence

MITRE and Malpedia can be synchronized without credentials:

```bash
cd backend
python -m app.worker --once --source mitre
python -m app.worker --once --source malpedia
```

ThreatFox requires a free abuse.ch Auth-Key. Create one through the
[abuse.ch Authentication Portal](https://auth.abuse.ch/), then place it in
`backend/.env` without committing it:

```dotenv
ABUSECH_AUTH_KEY=your-auth-key
THREATFOX_DAYS=7
```

Apply migrations and synchronize recent IOCs:

```bash
alembic upgrade head
python -m app.worker --once --source threatfox
```

`--source all` synchronizes MITRE, Malpedia, and ThreatFox when the Auth-Key is
configured. Without the key, the worker safely skips ThreatFox. The IOC API
hides records after their six-month freshness window by default; use
`include_inactive=true` only for historical review.

Source documentation:

- [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data)
- [Malpedia API](https://malpedia.caad.fkie.fraunhofer.de/usage/api)
- [ThreatFox API](https://threatfox.abuse.ch/api/)

## Docker development

```bash
docker compose up --build
```

Include the scheduled actor and IOC synchronization worker with:

```bash
docker compose --profile ingestion up --build
```

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Verify API and database availability |
| `GET` | `/api/dashboard/bootstrap` | Load the complete dashboard contract |
| `GET` | `/api/actors` | List threat actors and their source profiles |
| `GET` | `/api/actors/{actor_id}` | Retrieve a merged actor profile |
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
contract, STIX normalization, source-aware actor and IOC merging, freshness filtering, audit records, and
idempotent ingestion.

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
- Keep API tokens and database credentials out of Git and in a secret store.
- Feed credentials are backend-only and are never sent to the dashboard.
- Review confidence and age before operationally blocking any indicator.
- Enable authentication, TLS, restricted CORS, and outbound allowlists in production.
- Set `SEED_ON_STARTUP=false` before loading approved production data.
- Back up PostgreSQL and monitor health and failed ingestion runs.

See [BACKEND.md](BACKEND.md) for API and worker instructions and
[DEPLOYMENT.md](DEPLOYMENT.md) for production deployment.
