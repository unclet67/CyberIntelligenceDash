import argparse
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

from .config import settings
from .database import Base, SessionLocal, engine
from .ingestion import ingest_stix_bundle

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("argus.ingestion")


def load_bundle(*, file_path: str | None, url: str | None) -> tuple[dict[str, Any], str, str | None]:
    if file_path:
        path = Path(file_path)
        return json.loads(path.read_text()), path.name, None
    if url:
        response = httpx.get(url, timeout=settings.request_timeout_seconds, follow_redirects=True)
        response.raise_for_status()
        return response.json(), f"STIX feed: {url[:140]}", url
    raise ValueError("Set STIX_FEED_URL or supply --url/--file")


def run_once(*, file_path: str | None = None, url: str | None = None) -> None:
    bundle, source_name, source_url = load_bundle(file_path=file_path, url=url or settings.stix_feed_url)
    with SessionLocal() as session:
        run = ingest_stix_bundle(session, bundle, source_name=source_name, source_url=source_url)
        logger.info(
            "ingestion completed source=%s seen=%s written=%s",
            source_name,
            run.items_seen,
            run.items_written,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a STIX 2.1 bundle into ARGUS TI")
    parser.add_argument("--file", help="Local STIX bundle JSON file")
    parser.add_argument("--url", help="Remote STIX bundle URL")
    parser.add_argument("--once", action="store_true", help="Run once instead of on an interval")
    parser.add_argument("--interval", type=int, default=settings.ingestion_interval_seconds)
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    if args.once or args.file:
        run_once(file_path=args.file, url=args.url)
        return
    while True:
        try:
            run_once(url=args.url)
        except Exception:
            logger.exception("ingestion run failed")
        time.sleep(max(args.interval, 60))


if __name__ == "__main__":
    main()
