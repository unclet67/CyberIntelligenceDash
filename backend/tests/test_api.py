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


def test_lists_techniques_and_reports(client):
    techniques = client.get("/api/attack/techniques")
    reports = client.get("/api/reports")
    assert techniques.status_code == 200 and techniques.json()
    assert reports.status_code == 200 and reports.json()
