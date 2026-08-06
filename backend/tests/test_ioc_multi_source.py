from sqlalchemy import select

from app.ingestion import ingest_threatfox_iocs
from app.models import Indicator, IndicatorSource


def test_threatfox_enriches_existing_indicator_without_losing_provenance(db_session):
    payload = {
        "query_status": "ok",
        "data": [
            {
                "id": "existing-demo-ioc",
                "ioc": "185.220.101.42",
                "ioc_type": "ip",
                "threat_type": "botnet_cc",
                "malware_printable": "Example RAT",
                "confidence_level": 90,
                "first_seen": "2026-08-04 00:00:00 UTC",
                "tags": ["C2"],
            }
        ],
    }

    ingest_threatfox_iocs(db_session, payload)
    matches = db_session.scalars(
        select(Indicator).where(Indicator.type == "IP", Indicator.value == "185.220.101.42")
    ).all()
    assert len(matches) == 1
    profiles = db_session.scalars(
        select(IndicatorSource).where(IndicatorSource.indicator_id == matches[0].id)
    ).all()
    assert {profile.source.name for profile in profiles} == {"Internal Telemetry", "ThreatFox"}
    assert matches[0].malware == "Example RAT"
    assert matches[0].confidence_score == 90
