from sqlalchemy import select

from app.ingestion import ingest_stix_bundle
from app.models import Actor, Indicator, IngestionRun, Technique


STIX_BUNDLE = {
    "type": "bundle",
    "id": "bundle--11111111-1111-4111-8111-111111111111",
    "objects": [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "name": "Test Actor",
            "aliases": ["Test Alias"],
            "description": "A test-only actor.",
            "external_references": [{"source_name": "example", "external_id": "G9999"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--22222222-2222-4222-8222-222222222222",
            "name": "Test Technique",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            "external_references": [{"source_name": "example", "external_id": "T9999"}],
        },
        {
            "type": "indicator",
            "id": "indicator--33333333-3333-4333-8333-333333333333",
            "pattern_type": "stix",
            "pattern": "[domain-name:value = 'example.test']",
        },
        {
            "type": "relationship",
            "id": "relationship--44444444-4444-4444-8444-444444444444",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "target_ref": "attack-pattern--22222222-2222-4222-8222-222222222222",
        },
    ],
}


def test_stix_ingestion_is_audited_and_idempotent(db_session):
    first = ingest_stix_bundle(db_session, STIX_BUNDLE, source_name="Test Bundle")
    assert first.status == "completed"
    assert first.items_seen == 4
    assert first.items_written == 3

    actor = db_session.scalar(select(Actor).where(Actor.mitre_id == "G9999"))
    assert actor and actor.aliases[0].name == "Test Alias"
    assert [technique.id for technique in actor.techniques] == ["T9999"]
    indicator = db_session.scalar(select(Indicator).where(Indicator.external_id.like("indicator--%")))
    assert indicator and indicator.type == "DOMAIN" and indicator.value == "example.test"

    second = ingest_stix_bundle(db_session, STIX_BUNDLE, source_name="Test Bundle")
    assert second.status == "completed"
    assert len(db_session.scalars(select(Actor).where(Actor.mitre_id == "G9999")).all()) == 1
    assert len(db_session.scalars(select(Technique).where(Technique.id == "T9999")).all()) == 1
    assert len(db_session.scalars(select(IngestionRun)).all()) == 2
