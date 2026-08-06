from datetime import datetime, timezone

from sqlalchemy import select

from app.config import settings
from app.ingestion import ingest_threatfox_iocs
from app.models import Indicator, IndicatorSource, IngestionRun
from app.worker import fetch_threatfox_payload


THREATFOX_PAYLOAD = {
    "query_status": "ok",
    "data": [
        {
            "id": "90001",
            "ioc": "198.51.100.42:443",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Botnet command-and-control server",
            "ioc_type": "ip:port",
            "malware": "win.cobalt_strike",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 75,
            "first_seen": "2026-08-03 12:00:00 UTC",
            "last_seen": None,
            "reference": "https://example.test/report/90001",
            "tags": ["C2", "test"],
        },
        {
            "id": "90002",
            "ioc": "a" * 64,
            "threat_type": "payload_delivery",
            "ioc_type": "sha256_hash",
            "malware": "win.test",
            "malware_printable": "Test Malware",
            "confidence_level": 100,
            "first_seen": "2026-08-04 01:02:03 UTC",
            "last_seen": "2026-08-04 02:03:04 UTC",
            "reference": None,
            "tags": None,
        },
    ],
}


def test_threatfox_ingestion_is_contextual_and_idempotent(db_session):
    first = ingest_threatfox_iocs(db_session, THREATFOX_PAYLOAD)
    assert first.status == "completed"
    assert first.items_seen == 2
    assert first.items_written == 2

    ip = db_session.scalar(select(Indicator).where(Indicator.value == "198.51.100.42:443"))
    assert ip is not None
    assert ip.type == "IP"
    assert ip.confidence == "Medium"
    assert ip.confidence_score == 75
    assert ip.threat_type == "botnet_cc"
    assert ip.malware == "Cobalt Strike"
    assert ip.tags == ["C2", "test"]
    assert ip.reference_url == "https://example.test/report/90001"
    assert ip.expires_at > ip.first_seen
    assert ip.is_active is True

    profiles = db_session.scalars(select(IndicatorSource).where(IndicatorSource.indicator_id == ip.id)).all()
    assert len(profiles) == 1
    assert profiles[0].source.name == "ThreatFox"
    assert profiles[0].external_id == "90001"

    second = ingest_threatfox_iocs(db_session, THREATFOX_PAYLOAD)
    assert second.status == "completed"
    assert len(db_session.scalars(select(Indicator).where(Indicator.value == "198.51.100.42:443")).all()) == 1
    assert len(db_session.scalars(select(IndicatorSource).where(IndicatorSource.indicator_id == ip.id)).all()) == 1
    assert len(db_session.scalars(select(IngestionRun).where(IngestionRun.source.has(name="ThreatFox"))).all()) == 2


def test_ioc_api_returns_threatfox_context_and_hides_expired(client, db_session):
    ingest_threatfox_iocs(db_session, THREATFOX_PAYLOAD)
    response = client.get("/api/iocs", params={"type": "ip"})
    assert response.status_code == 200
    item = next(row for row in response.json() if row["value"] == "198.51.100.42:443")
    assert item["malware"] == "Cobalt Strike"
    assert item["confidence_score"] == 75
    assert item["source_name"] == "ThreatFox"
    assert item["source_profiles"][0]["external_id"] == "90001"

    indicator = db_session.scalar(select(Indicator).where(Indicator.value == "198.51.100.42:443"))
    indicator.expires_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
    db_session.commit()
    assert all(row["value"] != indicator.value for row in client.get("/api/iocs").json())
    inactive = client.get("/api/iocs", params={"include_inactive": "true"}).json()
    assert any(row["value"] == indicator.value for row in inactive)


def test_threatfox_client_keeps_auth_key_in_backend(monkeypatch):
    observed = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return THREATFOX_PAYLOAD

    def fake_post(url, **kwargs):
        observed["url"] = url
        observed.update(kwargs)
        return Response()

    monkeypatch.setattr(settings, "abusech_auth_key", "test-auth-key")
    monkeypatch.setattr(settings, "threatfox_days", 99)
    monkeypatch.setattr("app.worker.httpx.post", fake_post)
    assert fetch_threatfox_payload() == THREATFOX_PAYLOAD
    assert observed["headers"]["Auth-Key"] == "test-auth-key"
    assert observed["json"] == {"query": "get_iocs", "days": 7}
