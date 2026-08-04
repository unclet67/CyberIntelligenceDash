from datetime import date, datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Actor, ActorAlias, ActorEvent, Campaign, Indicator, Report, Source, Technique


ACTORS = [
    ("a1", "APT28", "G0007", "Russia", "GRU Unit 26165", "Espionage", "critical", "High", ["Fancy Bear", "Sofacy", "Sednit", "Forest Blizzard"]),
    ("a2", "APT33", "G0064", "Iran", "IRGC-linked", "Espionage", "high", "Medium", ["Elfin", "Refined Kitten", "Magnallium"]),
    ("a3", "APT41", "G0096", "China", "MSS-linked", "IP Theft", "critical", "High", ["Double Dragon", "BARIUM", "Wicked Panda", "Brass Typhoon"]),
    ("a4", "LAZARUS GROUP", "G0032", "North Korea", "Reconnaissance General Bureau", "Financial Gain", "high", "High", ["Hidden Cobra", "ZINC", "Diamond Sleet"]),
    ("a5", "APT-C-23", None, "Unknown", "Unattributed", "Espionage", "medium", "Low", ["Arid Viper", "Desert Falcon"]),
    ("a6", "SANDWORM TEAM", "G0034", "Russia", "GRU Unit 74455", "Sabotage", "low", "Medium", ["ELECTRUM", "Telebots", "Voodoo Bear"]),
    ("a7", "APT29", "G0016", "Russia", "SVR", "Espionage", "critical", "High", ["Cozy Bear", "The Dukes", "Midnight Blizzard"]),
    ("a8", "OILRIG", "G0049", "Iran", "MOIS", "Espionage", "high", "High", ["APT34", "Helix Kitten", "Crambus"]),
    ("a9", "KIMSUKY", "G0094", "North Korea", "Reconnaissance General Bureau", "Espionage", "medium", "Medium", ["Black Banshee", "Thallium", "Emerald Sleet"]),
    ("a10", "TURLA", "G0010", "Russia", "FSB Center 16", "Espionage", "high", "High", ["Snake", "Venomous Bear", "Secret Blizzard"]),
    ("a11", "MUSTANG PANDA", "G0129", "China", "Assessed state-tasked", "Espionage", "medium", "Medium", ["Bronze President", "Stately Taurus", "Red Lich"]),
    ("a12", "SCATTERED SPIDER", "G1015", "Unknown", "Financially motivated", "Financial Gain", "high", "High", ["Muddled Libra", "Octo Tempest", "UNC3944"]),
]

CAMPAIGNS = [
    ("c1", "Operation Frostline", "a1", "Government", "active", "2026-03-02"),
    ("c2", "Operation Cinderbolt", "a1", "Defense", "active", "2026-01-14"),
    ("c3", "Operation Greyveil", "a1", "Media & NGOs", "dormant", "2025-11-09"),
    ("c4", "Operation Ashwind", "a2", "Energy", "active", "2026-02-20"),
    ("c5", "Operation Palefire", "a2", "Aviation", "dormant", "2025-12-01"),
    ("c6", "Operation Longspindle", "a3", "Telecom", "active", "2026-04-18"),
    ("c7", "Operation Ironloom", "a3", "Manufacturing", "active", "2026-03-22"),
    ("c8", "Operation Ledgerfall", "a4", "Financial Services", "active", "2026-05-05"),
    ("c9", "Operation Faintmark", "a5", "Telecom", "dormant", "2026-06-10"),
    ("c10", "Operation Stillwater", "a6", "Utilities", "dormant", "2026-04-02"),
    ("c11", "Operation Cloudveil", "a7", "Technology", "active", "2026-05-02"),
    ("c12", "Operation Duskwire", "a7", "Government", "active", "2026-04-18"),
    ("c13", "Operation Sandtunnel", "a8", "Government", "active", "2026-06-20"),
    ("c14", "Operation Inkwell", "a9", "Academia", "active", "2026-06-12"),
    ("c15", "Operation Serpentrelay", "a10", "Defense", "dormant", "2026-03-15"),
    ("c16", "Operation Bambooline", "a11", "Media & NGOs", "dormant", "2026-02-28"),
    ("c17", "Operation Sockpuppet", "a12", "Technology", "active", "2026-07-25"),
]

INDICATORS = [
    ("IP", "185.220.101.42", "a1", "High", "Internal Telemetry"),
    ("DOMAIN", "cdn-assets-sync.org", "a3", "High", "OSINT Feed"),
    ("HASH", "e3b0c44298fc1c149afb1234abcd", "a1", "Medium", "Sandbox Detonation"),
    ("URL", "hxxps://npm-package-cdn.io/verify", "a4", "High", "Partner Share"),
    ("IP", "45.155.204.71", "a5", "Low", "OSINT Feed"),
    ("DOMAIN", "update-cdn-svc.net", "a1", "High", "Internal Telemetry"),
    ("IP", "91.219.237.18", "a1", "Medium", "Partner Share"),
    ("HASH", "a94a8fe5ccb19ba61c4c087a99a1", "a2", "High", "Sandbox Detonation"),
    ("DOMAIN", "secure-billing-portal.com", "a2", "Medium", "OSINT Feed"),
    ("IP", "103.224.182.9", "a3", "High", "Internal Telemetry"),
    ("IP", "194.32.78.5", "a6", "Low", "OSINT Feed"),
    ("URL", "hxxps://secure-auth-verify.net/login", "a4", "Medium", "Partner Share"),
]

TECHNIQUES = [
    ("T1595", "Active Scanning", "Reconnaissance"),
    ("T1566.001", "Phishing: Attachment", "Initial Access"),
    ("T1566.002", "Phishing: Link", "Initial Access"),
    ("T1195.002", "Supply Chain Compromise", "Initial Access"),
    ("T1059.001", "PowerShell", "Execution"),
    ("T1547.001", "Boot or Logon Autostart", "Persistence"),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    ("T1110", "Brute Force", "Credential Access"),
    ("T1082", "System Information Discovery", "Discovery"),
    ("T1071.001", "Web Protocols", "Command and Control"),
    ("T1105", "Ingress Tool Transfer", "Command and Control"),
    ("T1486", "Data Encrypted for Impact", "Impact"),
]


def seed_database(session: Session) -> bool:
    if session.scalar(select(func.count()).select_from(Actor)):
        return False

    sources = {name: Source(name=name) for name in {row[4] for row in INDICATORS}}
    session.add_all(sources.values())
    techniques = {item[0]: Technique(id=item[0], name=item[1], tactic=item[2]) for item in TECHNIQUES}
    session.add_all(techniques.values())

    actors: dict[str, Actor] = {}
    for actor_id, name, mitre_id, country, sponsor, motivation, severity, confidence, aliases in ACTORS:
        actor = Actor(
            id=actor_id,
            name=name,
            mitre_id=mitre_id,
            country=country,
            sponsor=sponsor,
            motivation=motivation,
            severity=severity,
            confidence=confidence,
            description=f"Seed profile for {name}; replace with source-backed production reporting.",
            aliases=[ActorAlias(name=alias) for alias in aliases],
        )
        actors[actor_id] = actor
        session.add(actor)

    actors["a1"].techniques.extend([techniques["T1566.001"], techniques["T1059.001"], techniques["T1027"], techniques["T1071.001"]])
    actors["a3"].techniques.extend([techniques["T1195.002"], techniques["T1105"]])
    actors["a4"].techniques.extend([techniques["T1566.002"], techniques["T1486"]])
    actors["a1"].events.append(ActorEvent(
        observed_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
        title="New C2 infrastructure identified",
        detail="Demonstration timeline event imported from the standalone dashboard.",
    ))

    for campaign_id, name, actor_id, sector, status, first_seen in CAMPAIGNS:
        session.add(Campaign(
            id=campaign_id,
            name=name,
            actor_id=actor_id,
            sector=sector,
            status=status,
            first_seen=date.fromisoformat(first_seen),
        ))

    observed = datetime(2026, 7, 30, tzinfo=timezone.utc)
    for indicator_type, value, actor_id, confidence, source_name in INDICATORS:
        session.add(Indicator(
            type=indicator_type,
            value=value,
            actor_id=actor_id,
            source=sources[source_name],
            confidence=confidence,
            first_seen=observed,
            last_seen=observed,
        ))

    reports = [
        ("APT28 — Actor Profile", "Actor Profile", "APT28", "PDF"),
        ("Operation Frostline — Campaign Brief", "Campaign Brief", "Operation Frostline", "PDF"),
        ("Energy Sector Exposure Assessment", "Sector Assessment", "Energy", "DOCX"),
        ("Q3 ATT&CK Coverage Summary", "Coverage Report", "All Actors", "PDF"),
    ]
    for title, report_type, related, report_format in reports:
        session.add(Report(
            title=title,
            type=report_type,
            related=related,
            published_at=observed,
            format=report_format,
        ))

    session.commit()
    return True
