import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import Actor, ActorAlias, Indicator, IngestionRun, Source, Technique


def _external_reference(item: dict[str, Any], prefix: str) -> str | None:
    for reference in item.get("external_references", []):
        external_id = reference.get("external_id")
        if isinstance(external_id, str) and external_id.upper().startswith(prefix):
            return external_id.upper()
    return None


def _indicator_parts(pattern: str) -> tuple[str, str]:
    lowered = pattern.lower()
    indicator_type = "STIX"
    if "ipv4-addr:value" in lowered or "ipv6-addr:value" in lowered:
        indicator_type = "IP"
    elif "domain-name:value" in lowered:
        indicator_type = "DOMAIN"
    elif "file:hashes" in lowered:
        indicator_type = "HASH"
    elif "url:value" in lowered:
        indicator_type = "URL"
    match = re.search(r"=\s*'([^']+)'", pattern)
    return indicator_type, match.group(1) if match else pattern


def ingest_stix_bundle(
    session: Session,
    bundle: dict[str, Any],
    *,
    source_name: str,
    source_url: str | None = None,
) -> IngestionRun:
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected a STIX bundle with an objects array")

    source = session.scalar(select(Source).where(Source.name == source_name))
    if source is None:
        source = Source(name=source_name, url=source_url)
        session.add(source)
    elif source_url:
        source.url = source_url
    session.flush()

    run = IngestionRun(
        source=source,
        started_at=datetime.now(timezone.utc),
        status="running",
        items_seen=len(bundle["objects"]),
    )
    session.add(run)
    session.commit()
    run_id = run.id

    actor_by_stix: dict[str, Actor] = {}
    technique_by_stix: dict[str, Technique] = {}
    written = 0
    try:
        for item in bundle["objects"]:
            object_type = item.get("type")
            stix_id = item.get("id")
            if not isinstance(stix_id, str):
                continue

            if object_type == "intrusion-set":
                mitre_id = _external_reference(item, "G")
                name = str(item.get("name") or stix_id)
                actor_conditions = [Actor.external_id == stix_id, Actor.name == name]
                if mitre_id:
                    actor_conditions.append(Actor.mitre_id == mitre_id)
                actor = session.scalar(select(Actor).where(or_(*actor_conditions)))
                if actor is None:
                    actor = Actor(
                        id=mitre_id or f"stix-{stix_id.split('--')[-1][:24]}",
                        name=name,
                        mitre_id=mitre_id,
                        country="Unknown",
                        sponsor="Unattributed",
                        motivation="Unknown",
                        severity="medium",
                        confidence="Medium",
                        description=str(item.get("description") or "Imported STIX intrusion set."),
                        external_id=stix_id,
                        source=source,
                    )
                    session.add(actor)
                else:
                    actor.external_id = stix_id
                    actor.source = source
                    if item.get("description"):
                        actor.description = str(item["description"])
                known_aliases = {alias.name for alias in actor.aliases}
                for alias in item.get("aliases", []):
                    if isinstance(alias, str) and alias not in known_aliases and alias != actor.name:
                        actor.aliases.append(ActorAlias(name=alias))
                actor_by_stix[stix_id] = actor
                written += 1

            elif object_type == "attack-pattern":
                attack_id = _external_reference(item, "T")
                if not attack_id:
                    continue
                technique = session.get(Technique, attack_id)
                phases = item.get("kill_chain_phases") or []
                tactic = str(phases[0].get("phase_name", "Unknown")).replace("-", " ").title() if phases else "Unknown"
                if technique is None:
                    technique = Technique(
                        id=attack_id,
                        name=str(item.get("name") or attack_id),
                        tactic=tactic,
                        external_id=stix_id,
                    )
                    session.add(technique)
                else:
                    technique.name = str(item.get("name") or technique.name)
                    technique.tactic = tactic
                    technique.external_id = stix_id
                technique_by_stix[stix_id] = technique
                written += 1

            elif object_type == "indicator" and isinstance(item.get("pattern"), str):
                indicator_type, value = _indicator_parts(item["pattern"])
                indicator = session.scalar(
                    select(Indicator).where(
                        or_(Indicator.external_id == stix_id, (Indicator.type == indicator_type) & (Indicator.value == value))
                    )
                )
                if indicator is None:
                    indicator = Indicator(
                        type=indicator_type,
                        value=value,
                        external_id=stix_id,
                        source=source,
                        confidence="Medium",
                    )
                    session.add(indicator)
                else:
                    indicator.external_id = stix_id
                    indicator.source = source
                written += 1

        session.flush()
        for item in bundle["objects"]:
            if item.get("type") != "relationship" or item.get("relationship_type") != "uses":
                continue
            actor = actor_by_stix.get(str(item.get("source_ref")))
            technique = technique_by_stix.get(str(item.get("target_ref")))
            if actor and technique and technique not in actor.techniques:
                actor.techniques.append(technique)

        run = session.get(IngestionRun, run_id)
        run.status = "completed"
        run.items_written = written
        run.completed_at = datetime.now(timezone.utc)
        session.commit()
        return run
    except Exception as exc:
        session.rollback()
        failed_run = session.get(IngestionRun, run_id)
        failed_run.status = "failed"
        failed_run.error = str(exc)[:4000]
        failed_run.completed_at = datetime.now(timezone.utc)
        session.commit()
        raise
