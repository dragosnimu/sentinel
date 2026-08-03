"""CISA Known Exploited Vulnerabilities — fetch, mirror, look up.

The catalog is ~1 MB of JSON, a few thousand CVEs. Fetched over HTTPS and cached
in `kev_catalog`, refreshed at most once a day. A scan looks up its CVEs against
the local mirror, so it works — and stays fast — even when cisa.gov is
unreachable. If the very first fetch fails, KEV enrichment is simply absent for
that run, never a scan failure.
"""

from __future__ import annotations

from datetime import date, datetime

import httpx

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
_MAX_AGE_HOURS = 24


def _parse_date(raw: str | None) -> date | None:
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d").date()
    except ValueError:
        return None


async def _age_hours(db: Database) -> float | None:
    row = await db.fetchval("SELECT max(updated_at) FROM kev_catalog")
    if row is None:
        return None
    return (datetime.now(row.tzinfo) - row).total_seconds() / 3600


async def refresh(db: Database, *, force: bool = False) -> int:
    """Refresh the mirror if it is older than a day. Returns rows written (0 if
    fresh or the fetch failed — never raises into a scan)."""
    if not force:
        age = await _age_hours(db)
        if age is not None and age < _MAX_AGE_HOURS:
            return 0
    try:
        async with httpx.AsyncClient(timeout=30, http2=False) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001 - a feed outage must not fail the scan
        log.warning("KEV refresh failed", extra={"detail": str(exc)})
        return 0

    rows = 0
    for item in data.get("vulnerabilities", []):
        cve = item.get("cveID")
        if not cve:
            continue
        await db.execute(
            """
            INSERT INTO kev_catalog (cve, vendor, product, name, added_date, due_date, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, now())
            ON CONFLICT (cve) DO UPDATE SET
                vendor = EXCLUDED.vendor, product = EXCLUDED.product,
                name = EXCLUDED.name, added_date = EXCLUDED.added_date,
                due_date = EXCLUDED.due_date, updated_at = now()
            """,
            cve, item.get("vendorProject"), item.get("product"),
            item.get("vulnerabilityName"),
            _parse_date(item.get("dateAdded")), _parse_date(item.get("dueDate")))
        rows += 1
    log.info("KEV catalog refreshed", extra={"rows": rows})
    return rows


async def lookup(db: Database, cves: list[str]) -> dict[str, date | None]:
    """CVEs from `cves` that are on the KEV list, mapped to their due date."""
    if not cves:
        return {}
    rows = await db.fetch(
        "SELECT cve, due_date FROM kev_catalog WHERE cve = ANY($1::text[])", cves)
    return {r["cve"]: r["due_date"] for r in rows}
