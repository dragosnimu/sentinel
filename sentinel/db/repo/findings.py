"""Findings and scan runs — the durable record of what the scanners saw.

A finding is keyed by `finding_key` (a stable hash of scanner + asset + package
+ cve + location), so the same vulnerability seen on ten nightly runs is one row
whose `last_seen` moves forward, not ten rows. When a scanner completes, anything
it used to report for that (scanner, asset) but did not this time is marked
resolved — a fix landed, or the package was removed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database


def finding_key(scanner: str, asset_id: int | None, package: str | None,
                cve: str | None, location: str | None) -> str:
    material = "|".join(str(x or "") for x in (scanner, asset_id, package, cve, location))
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass
class ScanRun:
    id: int
    scanner: str
    target: str
    status: str
    findings_count: int
    started_at: datetime
    finished_at: datetime | None


async def start_scan(db: Database, scanner: str, target: str, *,
                     asset_id: int | None = None, triggered_by: str = "schedule") -> int:
    return int(await db.fetchval(
        """
        INSERT INTO scans (scanner, target, asset_id, triggered_by, status)
        VALUES ($1, $2, $3, $4, 'running') RETURNING id
        """,
        scanner, target, asset_id, triggered_by))


async def finish_scan(db: Database, scan_id: int, *, status: str, findings_count: int = 0,
                      new_findings: int = 0, resolved_findings: int = 0,
                      exit_code: int | None = None, error: str | None = None,
                      db_version: str | None = None) -> None:
    await db.execute(
        """
        UPDATE scans SET status = $2, findings_count = $3, new_findings = $4,
            resolved_findings = $5, exit_code = $6, error = $7, db_version = $8,
            finished_at = now(),
            duration_ms = (extract(epoch from (now() - started_at)) * 1000)::int
        WHERE id = $1
        """,
        scan_id, status, findings_count, new_findings, resolved_findings,
        exit_code, error, db_version)


async def upsert_finding(db: Database, f: dict[str, Any]) -> bool:
    """Insert or refresh one finding. Returns True if it is newly seen (or was
    resolved and has reappeared), False if it was already open."""
    row = await db.fetchrow(
        """
        INSERT INTO findings
            (finding_key, asset_id, scanner, cve, advisory_id, title, description,
             severity, cvss, cvss_vector, epss, kev, kev_due_date, package,
             installed_version, fixed_version, location, ecosystem, priority,
             scan_id, raw)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
        ON CONFLICT (finding_key) DO UPDATE SET
            last_seen = now(),
            -- A finding that was resolved but is seen again reopens.
            status = CASE WHEN findings.status = 'resolved' THEN 'open' ELSE findings.status END,
            resolved_at = NULL,
            severity = EXCLUDED.severity, cvss = EXCLUDED.cvss, epss = EXCLUDED.epss,
            kev = EXCLUDED.kev, priority = EXCLUDED.priority,
            fixed_version = EXCLUDED.fixed_version, scan_id = EXCLUDED.scan_id,
            raw = EXCLUDED.raw
        RETURNING (xmax = 0) AS is_new, status
        """,
        f["finding_key"], f.get("asset_id"), f["scanner"], f.get("cve"),
        f.get("advisory_id"), f.get("title"), f.get("description"),
        f.get("severity", "medium"), f.get("cvss"), f.get("cvss_vector"),
        f.get("epss"), f.get("kev", False), f.get("kev_due_date"), f.get("package"),
        f.get("installed_version"), f.get("fixed_version"), f.get("location"),
        f.get("ecosystem"), f.get("priority", 0), f.get("scan_id"),
        json.dumps(f.get("raw", {})),
    )
    return bool(row["is_new"])


async def mark_resolved_absent(db: Database, scanner: str, asset_id: int | None,
                               seen_keys: list[str]) -> int:
    """Findings this scanner used to report for the asset but did not this run
    are resolved. Passing an empty seen list resolves them all — correct when a
    scan comes back clean."""
    rows = await db.fetch(
        """
        UPDATE findings SET status = 'resolved', resolved_at = now(),
            resolution = 'absent_from_latest_scan'
        WHERE scanner = $1 AND asset_id IS NOT DISTINCT FROM $2
          AND status IN ('open','patch_planned','deferred')
          AND finding_key <> ALL($3::text[])
        RETURNING id
        """,
        scanner, asset_id, seen_keys or [""])
    return len(rows)


async def open_counts(db: Database) -> dict[str, int]:
    rows = await db.fetch(
        "SELECT severity, count(*) AS n FROM findings WHERE status = 'open' GROUP BY severity")
    counts = {r["severity"]: int(r["n"]) for r in rows}
    counts["total"] = sum(counts.values())
    counts["kev"] = int(await db.fetchval(
        "SELECT count(*) FROM findings WHERE status = 'open' AND kev") or 0)
    return counts


async def list_open(db: Database, *, limit: int = 100) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT f.id, f.cve, f.advisory_id, f.title, f.severity, f.cvss, f.epss,
               f.kev, f.priority, f.package, f.installed_version, f.fixed_version,
               f.scanner, f.location, f.status, f.last_seen, a.name AS asset_name
        FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.status = 'open'
        ORDER BY f.priority DESC, f.severity DESC, f.last_seen DESC
        LIMIT $1
        """,
        limit)
    return [dict(r) for r in rows]
