from sqlalchemy import select

from app.ingestion import ingest_malpedia_actors, ingest_stix_bundle
from app.models import Actor, ActorSource


MITRE_ACTOR_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "intrusion-set",
            "id": "intrusion-set--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "name": "Fusion Test",
            "aliases": ["Fusion Bear"],
            "description": "MITRE-backed test actor.",
            "external_references": [{"source_name": "mitre-attack", "external_id": "G9998"}],
        }
    ],
}

MALPEDIA_ACTORS = {
    "fusion_test": {
        "value": "Fusion Group",
        "meta": {
            "country": "RU",
            "synonyms": ["Fusion Bear", "Fusion Crew"],
            "refs": ["https://attack.mitre.org/groups/G9998/"],
        },
    }
}


def test_mitre_and_malpedia_merge_into_one_actor_with_two_sources(db_session):
    ingest_stix_bundle(
        db_session,
        MITRE_ACTOR_BUNDLE,
        source_name="MITRE ATT&CK",
        source_url="https://attack.mitre.org/",
    )
    ingest_malpedia_actors(db_session, MALPEDIA_ACTORS)

    actors = db_session.scalars(select(Actor).where(Actor.mitre_id == "G9998")).all()
    assert len(actors) == 1
    actor = actors[0]
    assert {alias.name for alias in actor.aliases} >= {"Fusion Bear", "Fusion Crew", "Fusion Group"}
    assert actor.country == "Russia"

    profiles = db_session.scalars(select(ActorSource).where(ActorSource.actor_id == actor.id)).all()
    assert {profile.source.name for profile in profiles} == {"MITRE ATT&CK", "Malpedia"}
    assert {profile.external_id for profile in profiles} == {
        "intrusion-set--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "fusion_test",
    }


def test_actor_api_returns_both_source_profiles(client, db_session):
    ingest_stix_bundle(db_session, MITRE_ACTOR_BUNDLE, source_name="MITRE ATT&CK")
    ingest_malpedia_actors(db_session, MALPEDIA_ACTORS)
    response = client.get("/api/actors/G9998")
    assert response.status_code == 200
    payload = response.json()
    assert {profile["source_name"] for profile in payload["source_profiles"]} == {
        "MITRE ATT&CK",
        "Malpedia",
    }
    assert next(
        profile["external_id"]
        for profile in payload["source_profiles"]
        if profile["source_name"] == "Malpedia"
    ) == "fusion_test"
