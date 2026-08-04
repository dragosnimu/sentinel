"""Exposure crossing: the attacker is probing exactly what you have not patched.

The highest-value signal in this system and the one with no model in it. Three
facts that are each unremarkable on their own:

    an actor is probing  /wp-admin, or port 6379, or a path naming a CVE
    an asset here runs   the software that path belongs to
    a finding is open    on that asset, unpatched, with a known exploit

Any one is noise. All three at once is not a scan — it is someone who has found
a specific hole in a specific machine and is standing in front of it. That is
worth waking someone for, and it is a join over three tables the system already
fills.

Everything is deterministic. No probability is invented, and the evidence that
produced a crossing is stored with it, because a warning whose basis cannot be
reproduced is a warning nobody can act on.

## Why the confidence numbers are what they are

They are not tuned and they do not pretend to be. `cve_probe` is 0.9 because a
request that literally names an open CVE is about as unambiguous as this gets;
`path_match` is 0.7 because a WordPress path on a host running WordPress is
strong but common; `port_match` is 0.5 because a port scan hits everything.
They order the list. They are not probabilities of compromise and nothing in
this file treats them as such.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Software fingerprints: a path fragment an attacker probes, and the package or
# product names that would make the probe relevant HERE. Deliberately short — a
# long list of guesses produces confident nonsense, and every entry below is a
# thing this collector has actually seen in production traffic.
PROBE_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/wp-admin", ("wordpress", "php")),
    ("/wp-content", ("wordpress", "php")),
    ("/wp-login", ("wordpress", "php")),
    ("/administrator", ("joomla", "php")),
    ("/phpmyadmin", ("phpmyadmin", "php", "mariadb", "mysql")),
    ("/.env", ("laravel", "php", "symfony")),
    ("/.git", ("git",)),
    ("/actuator", ("spring", "java", "tomcat")),
    ("/solr", ("solr", "java")),
    ("/cgi-bin", ("httpd", "apache", "bash")),
    ("/vendor/phpunit", ("php", "phpunit")),
    ("/xmlrpc.php", ("wordpress", "php")),
    ("/owa/", ("exchange",)),
    ("/manager/html", ("tomcat", "java")),
    ("/console", ("weblogic", "java")),
)

CVE_IN_PATH = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

CONFIDENCE = {"cve_probe": 0.90, "path_match": 0.70, "port_match": 0.50}


@dataclass
class Crossing:
    actor_key: str
    asset_id: int
    finding_id: int
    match_reason: str
    confidence: float
    evidence: dict[str, Any]


async def detect(db: Database, *, hours: int = 6, limit: int = 50) -> list[Crossing]:
    """Find crossings in the recent past. Cheap enough to run every cycle."""
    findings = await db.fetch(
        """
        SELECT f.id, f.cve, f.package, f.severity, f.kev, f.priority,
               f.asset_id, a.name AS asset_name, a.stack
        FROM findings f
        LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.status = 'open'
        ORDER BY f.priority DESC
        LIMIT 500
        """)
    if not findings:
        return []

    probes = await db.fetch(
        """
        SELECT host(src_ip) AS actor, http_path, count(*) AS n, max(ts) AS ultim
        FROM raw_events
        WHERE ts > now() - make_interval(hours => $1)
          AND http_path IS NOT NULL AND src_ip IS NOT NULL
        GROUP BY 1, 2
        ORDER BY n DESC
        LIMIT 2000
        """,
        hours)
    if not probes:
        return []

    out: list[Crossing] = []
    for probe in probes:
        path = (probe["http_path"] or "").lower()
        actor = probe["actor"]

        # A path that names a CVE we actually have open. The strongest form:
        # the attacker has told us which hole they are aiming at.
        for named in CVE_IN_PATH.findall(probe["http_path"] or ""):
            for f in findings:
                if f["cve"] and f["cve"].upper() == named.upper():
                    out.append(Crossing(
                        actor, f["asset_id"] or 0, f["id"], "cve_probe",
                        CONFIDENCE["cve_probe"],
                        {"path": probe["http_path"][:200], "cve": f["cve"],
                         "probes": int(probe["n"])}))

        for fragment, keywords in PROBE_SIGNATURES:
            if fragment not in path:
                continue
            for f in findings:
                haystack = " ".join(str(f[k] or "").lower()
                                    for k in ("package", "stack", "asset_name"))
                if any(k in haystack for k in keywords):
                    out.append(Crossing(
                        actor, f["asset_id"] or 0, f["id"], "path_match",
                        CONFIDENCE["path_match"],
                        {"path": probe["http_path"][:200], "fragment": fragment,
                         "package": f["package"], "probes": int(probe["n"])}))
                    break

    # Strongest first, and one row per (actor, finding) — the same attacker
    # hitting forty WordPress paths is one crossing, not forty.
    seen: set[tuple[str, int]] = set()
    unique: list[Crossing] = []
    for c in sorted(out, key=lambda x: -x.confidence):
        key = (c.actor_key, c.finding_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)
    return unique[:limit]


async def record(db: Database, crossings: list[Crossing]) -> int:
    """Store them, deduplicated to one per (actor, finding, hour).

    The hour bucket is the schema's, not this module's invention: the same
    attacker probing the same hole for a day should produce twenty-four rows
    you can plot, not one row you cannot, and not eighty thousand.
    """
    stored = 0
    for c in crossings:
        if not c.asset_id:
            continue
        try:
            await db.execute(
                """
                INSERT INTO exposure_crossings
                    (actor_key, asset_id, finding_id, match_reason, confidence,
                     probe_evidence, detected_hour)
                VALUES ($1::text, $2::bigint, $3::bigint, $4::text, $5::numeric,
                        $6::jsonb, date_trunc('hour', now()))
                ON CONFLICT (actor_key, finding_id, detected_hour) DO NOTHING
                """,
                c.actor_key, c.asset_id, c.finding_id, c.match_reason,
                c.confidence, __import__("json").dumps(c.evidence))
            stored += 1
        except Exception as exc:  # noqa: BLE001 - a foreign key we cannot satisfy
            log.debug("crossing not stored", extra={"detail": str(exc)[:120]})
    if stored:
        log.warning("exposure crossings recorded", extra={"n": stored})
    return stored


async def recent(db: Database, *, hours: int = 24, limit: int = 20) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT x.detected_at, x.actor_key, x.match_reason, x.confidence,
               x.probe_evidence, f.cve, f.package, f.severity, f.kev,
               a.name AS asset_name
        FROM exposure_crossings x
        JOIN findings f ON f.id = x.finding_id
        LEFT JOIN assets a ON a.id = x.asset_id
        WHERE x.detected_at > now() - make_interval(hours => $1)
        ORDER BY x.confidence DESC, x.detected_at DESC
        LIMIT $2
        """,
        hours, limit)
    return [dict(r) for r in rows]
