# Production deployment

The production Compose stack runs four services: Nginx for the dashboard,
FastAPI for the API, PostgreSQL for persistence, and a scheduled STIX ingestion
worker.

## Prepare secrets

```bash
cp .env.production.example .env.production
```

Replace every placeholder. Use long random values for `POSTGRES_PASSWORD` and
`API_AUTH_TOKEN`, and configure only an approved STIX bundle URL.

## Start the stack

```bash
docker compose --env-file .env.production -f docker-compose.production.yml up --build -d
```

The default public address is `http://127.0.0.1:8080`. The API requires a
Bearer token in production. The dashboard asks for that token on the first
authenticated API request and stores it only for the current browser session.

## Operational requirements

- Terminate TLS in front of the published port before internet exposure.
- Use a managed secret store instead of an environment file where available.
- Back up the PostgreSQL volume and test restoration.
- Pin and scan container images in the deployment environment.
- Restrict the STIX source allowlist and outbound network access.
- Monitor `/api/health`, container restarts, and ingestion run failures.
