import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .models import Actor, ActorAlias, ActorSource, Indicator, IndicatorSource, IngestionRun, Source, Technique


COUNTRY_NAMES = {
    "CN": "China",
    "IR": "Iran",
    "KP": "North Korea",
    "RU": "Russia",
    "US": "United States",
}


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


def _source_and_run(
    session: Session, *, source_name: str, source_url: str | None, items_seen: int
) -> tuple[Source, int]:
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
        items_seen=items_seen,
    )
    session.add(run)
    session.commit()
    return source, run.id


def _finish_run(session: Session, run_id: int, items_written: int) -> IngestionRun:
    run = session.get(IngestionRun, run_id)
    if run is None:
        raise RuntimeError("Ingestion audit record disappeared")
    run.status = "completed"
    run.items_written = items_written
    run.completed_at = datetime.now(timezone.utc)
    session.commit()
    return run


def _fail_run(session: Session, run_id: int, exc: Exception) -> None:
    session.rollback()
    run = session.get(IngestionRun, run_id)
    if run is None:
        return
    run.status = "failed"
    run.error = str(exc)[:4000]
    run.completed_at = datetime.now(timezone.utc)
    session.commit()


def _clean_names(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        name = value.strip()[:160]
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            result.append(name)
    return result


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _find_actor(
    session: Session,
    *,
    source: Source,
    external_id: str,
    mitre_id: str | None,
    names: list[str],
) -> Actor | None:
    actor = session.scalar(
        select(Actor)
        .join(ActorSource)
        .where(ActorSource.source_id == source.id, ActorSource.external_id == external_id)
    )
    if actor is not None:
        return actor
    if mitre_id:
        actor = session.scalar(select(Actor).where(Actor.mitre_id == mitre_id))
        if actor is not None:
            return actor
    normalized = [name.casefold() for name in names]
    if not normalized:
        return None
    return session.scalar(
        select(Actor)
        .outerjoin(ActorAlias)
        .where(or_(func.lower(Actor.name).in_(normalized), func.lower(ActorAlias.name).in_(normalized)))
        .limit(1)
    )


def _record_actor_source(
    session: Session,
    *,
    actor: Actor,
    source: Source,
    external_id: str,
    profile_url: str | None,
) -> ActorSource:
    profile = session.scalar(
        select(ActorSource).where(
            ActorSource.actor_id == actor.id,
            ActorSource.source_id == source.id,
        )
    )
    if profile is None:
        profile = ActorSource(actor=actor, source=source, external_id=external_id)
        session.add(profile)
    else:
        profile.external_id = external_id
    profile.profile_url = profile_url
    profile.last_synced_at = datetime.now(timezone.utc)
    return profile


def _merge_aliases(actor: Actor, names: Iterable[Any]) -> None:
    known = {actor.name.casefold(), *(alias.name.casefold() for alias in actor.aliases)}
    for alias in _clean_names(names):
        key = alias.casefold()
        if key not in known:
            actor.aliases.append(ActorAlias(name=alias))
            known.add(key)


def ingest_stix_bundle(
    session: Session,
    bundle: dict[str, Any],
    *,
    source_name: str,
    source_url: str | None = None,
) -> IngestionRun:
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected a STIX bundle with an objects array")

    source, run_id = _source_and_run(
        session, source_name=source_name, source_url=source_url, items_seen=len(bundle["objects"])
    )
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
                names = _clean_names([name, *_as_list(item.get("aliases"))])
                actor = _find_actor(
                    session,
                    source=source,
                    external_id=stix_id,
                    mitre_id=mitre_id,
                    names=names,
                )
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
                    session.flush()
                else:
                    if mitre_id and not actor.mitre_id:
                        actor.mitre_id = mitre_id
                    if not actor.external_id or actor.external_id.startswith("demo:"):
                        actor.external_id = stix_id
                    if item.get("description"):
                        actor.description = str(item["description"])
                _merge_aliases(actor, names)
                _record_actor_source(
                    session,
                    actor=actor,
                    source=source,
                    external_id=stix_id,
                    profile_url=f"https://attack.mitre.org/groups/{mitre_id}/" if mitre_id else source_url,
                )
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
        return _finish_run(session, run_id, written)
    except Exception as exc:
        _fail_run(session, run_id, exc)
        raise


def _malpedia_records(payload: Any) -> list[tuple[str, dict[str, Any]]]:
    if isinstance(payload, dict) and isinstance(payload.get("actors"), (dict, list)):
        payload = payload["actors"]
    if isinstance(payload, dict):
        return [(str(key), value) for key, value in payload.items() if isinstance(value, dict)]
    if isinstance(payload, list):
        records = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            actor_id = item.get("id") or item.get("actor_id") or item.get("slug")
            if actor_id:
                records.append((str(actor_id), item))
        return records
    raise ValueError("Expected Malpedia actor metadata as an object or array")


def _malpedia_mitre_id(record: dict[str, Any], meta: dict[str, Any]) -> str | None:
    candidates = [
        record.get("mitre_id"),
        record.get("mitre-attack"),
        meta.get("mitre_id"),
        meta.get("mitre-attack"),
        meta.get("external_id"),
    ]
    match = re.search(r"\bG\d{4}\b", " ".join(str(value) for value in candidates if value), re.IGNORECASE)
    if match:
        return match.group(0).upper()
    for reference in _as_list(meta.get("refs")):
        match = re.search(r"/groups/(G\d{4})", str(reference), re.IGNORECASE)
        if match:
            return match.group(1).upper()
    return None


def ingest_malpedia_actors(
    session: Session,
    payload: Any,
    *,
    source_name: str = "Malpedia",
    source_url: str = "https://malpedia.caad.fkie.fraunhofer.de",
) -> IngestionRun:
    records = _malpedia_records(payload)
    source, run_id = _source_and_run(
        session, source_name=source_name, source_url=source_url, items_seen=len(records)
    )
    written = 0
    try:
        for external_id, record in records:
            external_id = external_id.strip()[:160]
            meta = record.get("meta") if isinstance(record.get("meta"), dict) else {}
            name = str(record.get("value") or record.get("name") or meta.get("name") or external_id).strip()[:160]
            aliases = _clean_names([
                name,
                *_as_list(record.get("synonyms")),
                *_as_list(record.get("aliases")),
                *_as_list(meta.get("synonyms")),
                *_as_list(meta.get("aliases")),
            ])
            mitre_id = _malpedia_mitre_id(record, meta)
            actor = _find_actor(
                session,
                source=source,
                external_id=external_id,
                mitre_id=mitre_id,
                names=aliases,
            )
            if actor is None:
                actor_id = f"malpedia-{re.sub(r'[^a-z0-9_-]+', '-', external_id.casefold())}"[:64]
                actor = Actor(
                    id=actor_id,
                    name=name,
                    mitre_id=mitre_id,
                    country="Unknown",
                    sponsor="Unattributed",
                    motivation="Unknown",
                    severity="medium",
                    confidence="Medium",
                    description=str(record.get("description") or meta.get("description") or "Imported Malpedia actor profile."),
                    source=source,
                )
                session.add(actor)
                session.flush()
            elif mitre_id and not actor.mitre_id:
                actor.mitre_id = mitre_id

            country = meta.get("country") or record.get("country")
            if actor.country == "Unknown" and isinstance(country, str) and country.strip():
                actor.country = COUNTRY_NAMES.get(country.strip().upper(), country.strip())
            sponsor = meta.get("cfr-suspected-state-sponsor") or meta.get("suspected-state-sponsor")
            if actor.sponsor == "Unattributed" and isinstance(sponsor, str) and sponsor.strip():
                actor.sponsor = sponsor.strip()
            _merge_aliases(actor, aliases)
            _record_actor_source(
                session,
                actor=actor,
                source=source,
                external_id=external_id,
                profile_url=f"{source_url.rstrip('/')}/actor/{external_id}",
            )
            written += 1
        return _finish_run(session, run_id, written)
    except Exception as exc:
        _fail_run(session, run_id, exc)
        raise


THREATFOX_SOURCE_NAME = "ThreatFox"
THREATFOX_SOURCE_URL = "https://threatfox.abuse.ch/"
THREATFOX_RETENTION_DAYS = 180


def _threatfox_type(ioc_type: Any) -> str | None:
    normalized = str(ioc_type or "").strip().lower()
    if normalized in {"ip", "ip:port"}:
        return "IP"
    if normalized in {"domain", "hostname"}:
        return "DOMAIN"
    if normalized == "url":
        return "URL"
    if normalized in {"md5_hash", "sha1_hash", "sha256_hash", "sha512_hash", "hash"}:
        return "HASH"
    return None


def _threatfox_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    cleaned = value.strip()
    try:
        if cleaned.endswith(" UTC"):
            return datetime.strptime(cleaned, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _confidence(score: int | None) -> str:
    if score is None:
        return "Medium"
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def _safe_reference(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    reference = value.strip()[:1000]
    return reference if reference.startswith(("https://", "http://")) else None


def _record_indicator_source(
    session: Session,
    *,
    indicator: Indicator,
    source: Source,
    external_id: str,
    reference_url: str | None,
    confidence_score: int | None,
    first_seen: datetime | None,
    last_seen: datetime | None,
    expires_at: datetime,
    synced_at: datetime,
) -> IndicatorSource:
    profile = session.scalar(
        select(IndicatorSource).where(
            IndicatorSource.indicator_id == indicator.id,
            IndicatorSource.source_id == source.id,
        )
    )
    if profile is None:
        profile = IndicatorSource(indicator=indicator, source=source, external_id=external_id, last_synced_at=synced_at)
        session.add(profile)
    profile.external_id = external_id
    profile.reference_url = reference_url
    profile.confidence_score = confidence_score
    profile.first_seen = first_seen
    profile.last_seen = last_seen
    profile.expires_at = expires_at
    profile.last_synced_at = synced_at
    profile.is_active = True
    return profile


def ingest_threatfox_iocs(
    session: Session,
    payload: dict[str, Any],
    *,
    source_name: str = THREATFOX_SOURCE_NAME,
    source_url: str = THREATFOX_SOURCE_URL,
) -> IngestionRun:
    records = payload.get("data")
    if payload.get("query_status") != "ok" or not isinstance(records, list):
        raise ValueError(f"ThreatFox query failed: {payload.get('query_status', 'invalid response')}")

    source, run_id = _source_and_run(
        session, source_name=source_name, source_url=source_url, items_seen=len(records)
    )
    written = 0
    synced_at = datetime.now(timezone.utc)
    try:
        for record in records:
            if not isinstance(record, dict):
                continue
            external_id = str(record.get("id") or "").strip()[:160]
            value = str(record.get("ioc") or "").strip()[:1000]
            indicator_type = _threatfox_type(record.get("ioc_type"))
            if not external_id or not value or not indicator_type:
                continue

            profile = session.scalar(
                select(IndicatorSource).where(
                    IndicatorSource.source_id == source.id,
                    IndicatorSource.external_id == external_id,
                )
            )
            indicator = profile.indicator if profile else session.scalar(
                select(Indicator).where(Indicator.type == indicator_type, Indicator.value == value)
            )
            score_value = record.get("confidence_level")
            try:
                confidence_score = max(0, min(int(score_value), 100)) if score_value is not None else None
            except (TypeError, ValueError):
                confidence_score = None
            first_seen = _threatfox_time(record.get("first_seen"))
            last_seen = _threatfox_time(record.get("last_seen"))
            expires_at = (first_seen or synced_at) + timedelta(days=THREATFOX_RETENTION_DAYS)
            reference_url = _safe_reference(record.get("reference"))
            tags = _clean_names(_as_list(record.get("tags")))
            malware = str(record.get("malware_printable") or record.get("malware") or "").strip()[:160] or None
            threat_type = str(record.get("threat_type") or "").strip()[:120] or None

            if indicator is None:
                indicator = Indicator(
                    type=indicator_type,
                    value=value,
                    external_id=f"threatfox:{external_id}",
                    source=source,
                    confidence=_confidence(confidence_score),
                    tags=[],
                )
                session.add(indicator)
                session.flush()
            elif not indicator.external_id or indicator.external_id.startswith("demo:"):
                indicator.external_id = f"threatfox:{external_id}"

            indicator.confidence = _confidence(confidence_score)
            indicator.confidence_score = confidence_score
            indicator.threat_type = threat_type or indicator.threat_type
            indicator.malware = malware or indicator.malware
            indicator.tags = sorted(set([*(indicator.tags or []), *tags]), key=str.casefold)
            indicator.reference_url = reference_url or indicator.reference_url
            if first_seen and (indicator.first_seen is None or _utc(first_seen) < _utc(indicator.first_seen)):
                indicator.first_seen = first_seen
            if last_seen and (indicator.last_seen is None or _utc(last_seen) > _utc(indicator.last_seen)):
                indicator.last_seen = last_seen
            indicator.expires_at = expires_at
            indicator.last_synced_at = synced_at
            indicator.is_active = True
            _record_indicator_source(
                session,
                indicator=indicator,
                source=source,
                external_id=external_id,
                reference_url=reference_url,
                confidence_score=confidence_score,
                first_seen=first_seen,
                last_seen=last_seen,
                expires_at=expires_at,
                synced_at=synced_at,
            )
            written += 1
        return _finish_run(session, run_id, written)
    except Exception as exc:
        _fail_run(session, run_id, exc)
        raise
