import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from .config import settings
from .database import Base, SessionLocal, engine
from .ingestion import ingest_malpedia_actors, ingest_stix_bundle

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("argus.ingestion")


def fetch_json(url: str, *, api_token: str | None = None) -> Any:
    headers = {"Accept": "application/json"}
    if api_token:
        headers["Authorization"] = f"apitoken {api_token}"
    response = httpx.get(
        url,
        headers=headers,
        timeout=settings.request_timeout_seconds,
        follow_redirects=True,
    )
    response.raise_for_status()
    return response.json()


def load_bundle(*, file_path: str | None, url: str | None) -> tuple[dict[str, Any], str, str | None]:
    if file_path:
        path = Path(file_path)
        return json.loads(path.read_text()), path.name, None
    if url:
        return fetch_json(url), f"STIX feed: {url[:140]}", url
    raise ValueError("Supply --file or --url for a custom STIX feed")


def run_stix(*, file_path: str | None = None, url: str | None = None, source_name: str | None = None) -> None:
    bundle, inferred_name, source_url = load_bundle(file_path=file_path, url=url)
    name = source_name or inferred_name
    with SessionLocal() as session:
        run = ingest_stix_bundle(session, bundle, source_name=name, source_url=source_url)
        logger.info("ingestion completed source=%s seen=%s written=%s", name, run.items_seen, run.items_written)


def run_malpedia() -> None:
    url = f"{settings.malpedia_base_url.rstrip('/')}/api/get/actors"
    payload = fetch_json(url, api_token=settings.malpedia_api_token)
    with SessionLocal() as session:
        run = ingest_malpedia_actors(session, payload, source_url=settings.malpedia_base_url)
        logger.info("ingestion completed source=Malpedia seen=%s written=%s", run.items_seen, run.items_written)


def run_selected(source: str, *, file_path: str | None = None, url: str | None = None) -> None:
    if file_path or source == "stix":
        run_stix(file_path=file_path, url=url or settings.stix_feed_url)
        return
    tasks = []
    if source in {"all", "mitre"}:
        tasks.append(("MITRE ATT&CK", lambda: run_stix(url=url or settings.mitre_stix_url, source_name="MITRE ATT&CK")))
    if source in {"all", "malpedia"}:
        tasks.append(("Malpedia", run_malpedia))
    failures = []
    for name, task in tasks:
        try:
            task()
        except Exception as exc:
            failures.append((name, exc))
            logger.exception("ingestion failed source=%s", name)
    if failures:
        names = ", ".join(name for name, _ in failures)
        raise RuntimeError(f"Ingestion failed for: {names}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync MITRE ATT&CK and Malpedia actor data into ARGUS TI")
    parser.add_argument("--source", choices=("all", "mitre", "malpedia", "stix"), default="all")
    parser.add_argument("--file", help="Local STIX bundle JSON file")
    parser.add_argument("--url", help="Override the selected remote URL")
    parser.add_argument("--once", action="store_true", help="Run once instead of on an interval")
    parser.add_argument("--interval", type=int, default=settings.ingestion_interval_seconds)
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    if args.once or args.file:
        run_selected(args.source, file_path=args.file, url=args.url)
        return
    while True:
        try:
            run_selected(args.source, url=args.url)
        except Exception:
            logger.exception("scheduled ingestion cycle failed")
        time.sleep(max(args.interval, 60))


if __name__ == "__main__":
    main()
