# ARGUS TI backend foundation

This directory adds a read-only API and PostgreSQL-ready data layer to the
standalone dashboard. SQLite is the default for a zero-setup local run;
Docker Compose uses PostgreSQL.

## Local development

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
uvicorn app.main:app --reload --port 8001
```

Open `http://127.0.0.1:8001/docs` for the interactive API documentation.
The database is created and seeded on first startup.

Run tests with:

```bash
pytest
```

## PostgreSQL with Docker

From the repository root:

```bash
docker compose up --build
```

The API will be available at `http://127.0.0.1:8001`.

## Database migrations

Run migrations from `backend/` after setting `DATABASE_URL`:

```bash
alembic upgrade head
```

For production, use migrations before starting the service and set
`SEED_ON_STARTUP=false` after loading approved data.

## API surface

- `GET /api/health`
- `GET /api/actors`
- `GET /api/actors/{actor_id}`
- `GET /api/campaigns`
- `GET /api/iocs`
- `GET /api/attack/techniques`
- `GET /api/reports`

The next integration step is replacing the hard-coded arrays in `index.html`
with requests to these endpoints.
