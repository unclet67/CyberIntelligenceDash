from app.config import settings


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "database": "reachable"}


def test_lists_seeded_actors(client):
    response = client.get("/api/actors")
    assert response.status_code == 200
    assert len(response.json()) == 12
    assert any(actor["name"] == "APT28" for actor in response.json())


def test_actor_detail_and_missing_actor(client):
    response = client.get("/api/actors/a1")
    assert response.status_code == 200
    assert response.json()["mitre_id"] == "G0007"
    assert response.json()["aliases"]
    assert client.get("/api/actors/not-real").status_code == 404


def test_filters_campaigns_and_indicators(client):
    campaigns = client.get("/api/campaigns", params={"status": "active", "actor_id": "a1"})
    assert campaigns.status_code == 200
    assert all(item["status"] == "active" and item["actor_id"] == "a1" for item in campaigns.json())

    indicators = client.get("/api/iocs", params={"type": "domain"})
    assert indicators.status_code == 200
    assert all(item["type"] == "DOMAIN" for item in indicators.json())
    assert all(item["source_name"] for item in indicators.json())


def test_bootstrap_contains_complete_demo_collections(client):
    response = client.get("/api/dashboard/bootstrap")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["actors"]) == 12
    assert len(payload["campaigns"]) == 17
    assert len(payload["indicators"]) == 12
    assert len(payload["reports"]) == 8
    assert payload["techniques"]


def test_lists_techniques_reports_and_ingestion_runs(client):
    assert client.get("/api/attack/techniques").json()
    assert client.get("/api/reports").json()
    response = client.get("/api/ingestion/runs")
    assert response.status_code == 200
    assert response.json() == []


def test_optional_bearer_authentication(client):
    original_required = settings.auth_required
    original_token = settings.api_auth_token
    settings.auth_required = True
    settings.api_auth_token = "test-secret"
    try:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/actors").status_code == 401
        response = client.get("/api/actors", headers={"Authorization": "Bearer test-secret"})
        assert response.status_code == 200
    finally:
        settings.auth_required = original_required
        settings.api_auth_token = original_token
