"""The numbers behind the dashboard.

One module, one round of queries, so the page renders from a single snapshot
rather than a dozen scattered calls that can disagree with each other by a few
seconds. Everything here is a plain aggregate; the interpretation lives in
insights.py.
"""

from __future__ import annotations

from typing import Any

from sentinel.db.engine import Database


async def kpis(db: Database) -> dict[str, Any]:
    """The headline counters, all over the same 24-hour window."""
    ev = await db.fetchrow(
        """
        SELECT count(*) AS total,
               count(*) FILTER (WHERE action IN ('auth_fail','alert')) AS ostile,
               count(DISTINCT host(src_ip)) FILTER (WHERE src_ip IS NOT NULL) AS ips
        FROM raw_events WHERE ts > now() - interval '24 hours'
        """
    )
    inc = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE status IN ('open','acknowledged')) AS deschise,
               count(*) FILTER (WHERE status IN ('open','acknowledged')
                                  AND severity IN ('high','critical')) AS grave
        FROM incidents
        """
    )
    fnd = await db.fetchrow(
        """
        SELECT count(*) FILTER (WHERE status = 'open') AS deschise,
               count(*) FILTER (WHERE status = 'open' AND kev) AS kev
        FROM findings
        """
    )
    blocked = int(await db.fetchval("SELECT count(*) FROM blocklist WHERE active") or 0)
    return {
        "evenimente_24h": int(ev["total"] or 0),
        "ostile_24h": int(ev["ostile"] or 0),
        "atacatori_24h": int(ev["ips"] or 0),
        "incidente_deschise": int(inc["deschise"] or 0),
        "incidente_grave": int(inc["grave"] or 0),
        "vuln_deschise": int(fnd["deschise"] or 0),
        "vuln_kev": int(fnd["kev"] or 0),
        "blocate": blocked,
    }


async def sources(db: Database) -> list[dict[str, Any]]:
    """Which collectors are actually producing. A zero row here is the fastest
    way to spot a silent collector."""
    rows = await db.fetch(
        """
        SELECT source,
               count(*) FILTER (WHERE ts > now() - interval '24 hours') AS ev_24h,
               max(ts) AS ultim
        FROM raw_events WHERE ts > now() - interval '7 days'
        GROUP BY source ORDER BY ev_24h DESC
        """
    )
    return [dict(r) for r in rows]


async def top_attackers(db: Database, limit: int = 10) -> list[dict[str, Any]]:
    """Ranked by how many independent collectors saw them, then by volume —
    breadth is a better signal of intent than a single loud source."""
    rows = await db.fetch(
        """
        SELECT host(src_ip) AS ip,
               count(*) AS ev,
               count(DISTINCT source) AS surse,
               string_agg(DISTINCT source, '+' ORDER BY source) AS care,
               max(geo_country) AS tara,
               max(ts) AS ultim,
               EXISTS (SELECT 1 FROM blocklist b
                       WHERE b.ip = raw_events.src_ip AND b.active) AS blocat
        FROM raw_events
        WHERE ts > now() - interval '48 hours' AND src_ip IS NOT NULL
          AND action IN ('auth_fail','alert')
        GROUP BY src_ip
        ORDER BY count(DISTINCT source) DESC, count(*) DESC
        LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def targeted_accounts(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT username, count(*) AS n, count(DISTINCT host(src_ip)) AS ips
        FROM raw_events
        WHERE source = 'sshd' AND action = 'auth_fail' AND username IS NOT NULL
          AND ts > now() - interval '7 days'
        GROUP BY 1 ORDER BY n DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def probed_paths(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    rows = await db.fetch(
        """
        SELECT http_path, count(*) AS n, count(DISTINCT host(src_ip)) AS ips
        FROM raw_events
        WHERE source = 'nginx' AND http_status = 404 AND http_path IS NOT NULL
          AND ts > now() - interval '7 days' AND http_path <> '/'
        GROUP BY 1 ORDER BY n DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def ids_signatures(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    """Real threat signatures only — engine diagnostics are dropped at the
    collector, but older rows predate that filter."""
    rows = await db.fetch(
        """
        SELECT raw->>'signature' AS sig, count(*) AS n,
               count(DISTINCT host(src_ip)) AS ips
        FROM raw_events
        WHERE source = 'suricata' AND ts > now() - interval '7 days'
          AND raw->>'signature' NOT LIKE 'SURICATA %'
        GROUP BY 1 ORDER BY n DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def hourly_activity(db: Database) -> list[dict[str, Any]]:
    """24 hourly buckets for the sparkline. Gaps are filled with zero so the
    shape is honest: a quiet hour must look quiet, not be skipped."""
    rows = await db.fetch(
        """
        SELECT date_trunc('hour', ts) AS ora, count(*) AS n
        FROM raw_events
        WHERE ts > now() - interval '24 hours' AND action IN ('auth_fail','alert')
        GROUP BY 1 ORDER BY 1
        """
    )
    by_hour = {r["ora"]: int(r["n"]) for r in rows}
    if not by_hour:
        return []
    peak = max(by_hour.values()) or 1
    return [{"ora": k, "n": v, "pct": round(v * 100 / peak)} for k, v in sorted(by_hour.items())]


async def by_country(db: Database, limit: int = 7) -> list[dict[str, Any]]:
    """Where the hostile traffic comes from. `pct` is relative to the top row so
    the bars are comparable at a glance rather than against an invisible total."""
    rows = await db.fetch(
        """
        SELECT geo_country AS tara, count(*) AS ev,
               count(DISTINCT host(src_ip)) AS ips
        FROM raw_events
        WHERE ts > now() - interval '7 days' AND geo_country IS NOT NULL
          AND action IN ('auth_fail','alert')
        GROUP BY 1 ORDER BY ev DESC LIMIT $1
        """,
        limit,
    )
    out = [dict(r) for r in rows]
    peak = max((r["ev"] for r in out), default=1) or 1
    for r in out:
        r["pct"] = round(r["ev"] * 100 / peak)
    return out


async def by_asn(db: Database, limit: int = 6) -> list[dict[str, Any]]:
    """Hostile traffic by network operator. A large event count from very few
    addresses is the signature of concentrated attacker infrastructure — far
    more actionable than the country, which is usually just where a VPS sits."""
    rows = await db.fetch(
        """
        SELECT geo_as_org AS operator, geo_asn AS asn, count(*) AS ev,
               count(DISTINCT host(src_ip)) AS ips
        FROM raw_events
        WHERE ts > now() - interval '7 days' AND geo_as_org IS NOT NULL
          AND action IN ('auth_fail','alert')
        GROUP BY 1, 2 ORDER BY ev DESC LIMIT $1
        """,
        limit,
    )
    out = [dict(r) for r in rows]
    peak = max((r["ev"] for r in out), default=1) or 1
    for r in out:
        r["pct"] = round(r["ev"] * 100 / peak)
    return out


async def deltas(db: Database) -> dict[str, dict[str, Any]]:
    """Today against the same window yesterday, for the KPI chips. `dir` is
    spelled out so the arrow, not only the colour, carries the direction."""
    row = await db.fetchrow(
        """
        SELECT
          count(*) FILTER (WHERE ts > now() - interval '24 hours'
                             AND action IN ('auth_fail','alert')) AS ostile_azi,
          count(*) FILTER (WHERE ts <= now() - interval '24 hours'
                             AND action IN ('auth_fail','alert')) AS ostile_ieri,
          count(DISTINCT host(src_ip)) FILTER (WHERE ts > now() - interval '24 hours') AS ips_azi,
          count(DISTINCT host(src_ip)) FILTER (WHERE ts <= now() - interval '24 hours') AS ips_ieri
        FROM raw_events WHERE ts > now() - interval '48 hours' AND src_ip IS NOT NULL
        """
    )

    def chip(now_v: int, prev_v: int) -> dict[str, Any]:
        if not prev_v:
            return {"dir": "flat", "pct": None, "text": "fără referință"}
        change = (now_v - prev_v) * 100 / prev_v
        if abs(change) < 5:
            return {"dir": "flat", "pct": 0, "text": "≈ la fel"}
        direction = "up" if change > 0 else "down"
        arrow = "↑" if change > 0 else "↓"
        # A percentage in the thousands is arithmetically correct and completely
        # useless: it means the comparison window was nearly empty (a collector
        # was down, or old rows were pruned), not that attacks grew 37-fold.
        # Say that instead of rendering a number that reads as a bug.
        if abs(change) >= 900:
            return {"dir": direction, "pct": None, "text": f"{arrow} de la o bază foarte mică"}
        return {"dir": direction, "pct": abs(round(change)), "text": f"{arrow} {abs(round(change))}%"}

    return {
        "ostile": chip(int(row["ostile_azi"] or 0), int(row["ostile_ieri"] or 0)),
        "atacatori": chip(int(row["ips_azi"] or 0), int(row["ips_ieri"] or 0)),
    }


async def activity_feed(db: Database, limit: int = 10) -> list[dict[str, Any]]:
    """Latest meaningful events across incidents, blocks and scans — the "what
    just happened" column. Deliberately mixed rather than one table per kind:
    the useful question is chronological, not categorical."""
    rows = await db.fetch(
        """
        (SELECT 'incident' AS kind, i.id, i.severity AS lvl, i.title AS txt,
                COALESCE(i.actor_key, '') AS meta, i.last_detection_at AS at
         FROM incidents i
         WHERE i.status IN ('open','acknowledged')
         ORDER BY i.last_detection_at DESC LIMIT $1)
        UNION ALL
        (SELECT 'block', b.id, CASE WHEN b.active THEN 'high' ELSE 'info' END,
                CASE WHEN b.active THEN 'IP blocat: ' ELSE 'IP deblocat: ' END || host(b.ip),
                COALESCE(b.created_by, ''), b.blocked_at
         FROM blocklist b ORDER BY b.blocked_at DESC LIMIT 4)
        UNION ALL
        (SELECT 'scan', s.id,
                CASE WHEN s.status = 'failed' THEN 'high' ELSE 'info' END,
                'Scanare ' || s.scanner || ': ' || s.findings_count || ' rezultate',
                s.status, COALESCE(s.finished_at, s.started_at)
         FROM scans s ORDER BY s.started_at DESC LIMIT 3)
        ORDER BY at DESC LIMIT $1
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def service_health(db: Database) -> dict[str, int]:
    rows = await db.fetch(
        """
        SELECT COALESCE(s.status, 'necunoscut') AS stare, count(*) AS n
        FROM assets a
        LEFT JOIN LATERAL (
            SELECT status FROM health_samples h
            WHERE h.asset_id = a.id ORDER BY ts DESC LIMIT 1
        ) s ON true
        GROUP BY 1
        """
    )
    return {r["stare"]: int(r["n"]) for r in rows}
