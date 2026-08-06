# Production deployment

The production Compose stack runs four services: Nginx for the dashboard,
FastAPI for the API, PostgreSQL for persistence, and a scheduled intelligence
ingestion worker for MITRE ATT&CK, Malpedia, and ThreatFox.

## Prepare secrets

```bash
cp .env.production.example .env.production
```

Replace every placeholder. Use long random values for `POSTGRES_PASSWORD` and
`API_AUTH_TOKEN`. Obtain `ABUSECH_AUTH_KEY` from
<https://auth.abuse.ch/>. Keep all credentials in the backend environment or a
managed secret store; never place them in `index.html`.

## Start the stack

```bash
docker compose --env-file .env.production -f docker-compose.production.yml up --build -d
```

The default public address is `http://127.0.0.1:8080`. The API requires a
Bearer token in production. The dashboard asks for that token on the first
authenticated API request and stores it only for the current browser session.

## Operational requirements

- Terminate TLS in front of the published port before internet exposure.
- Confirm the abuse.ch community API fair-use terms fit the deployment; obtain
  a commercial subscription when required.
- Use a managed secret store instead of an environment file where available.
- Back up the PostgreSQL volume and test restoration.
- Pin and scan container images in the deployment environment.
- Restrict feed destinations and outbound network access.
- Monitor `/api/health`, container restarts, and ingestion run failures.
- Validate confidence, age, and internal telemetry before blocking an IOC.
