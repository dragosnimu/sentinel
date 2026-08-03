#!/usr/bin/env python3
"""Current state of the server and of Sentinel itself.

Answers "is anything wrong right now" in one call: service health, host
capacity, blocklist size, open incidents, AI queue depth and budget, threat
intel freshness, and Sentinel's own units.

Reads the database plus /proc. Does not shell out.

Usage:
    health_snapshot.py
    health_snapshot.py --format table
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import _common as c

SENTINEL_UNITS = (
    "sentinel-ingest",
    "sentinel-detect",
    "sentinel-ai",
    "sentinel-telegram",
    "sentinel-web",
    "sentinel-executor",
)


def host_capacity() -> dict[str, Any]:
    """Read capacity straight from /proc so this works even if ingestion is stuck."""
    out: dict[str, Any] = {}

    try:
        meminfo = {
            k.strip(): int(v.split()[0])
            for k, _, v in (
                line.partition(":") for line in Path("/proc/meminfo").read_text().splitlines()
            )
            if v.strip()
        }
        out["mem_total_mb"] = meminfo.get("MemTotal", 0) // 1024
        out["mem_available_mb"] = meminfo.get("MemAvailable", 0) // 1024
        out["swap_total_mb"] = meminfo.get("SwapTotal", 0) // 1024
        out["swap_free_mb"] = meminfo.get("SwapFree", 0) // 1024
        # Sentinel shares this host with whatever it was installed to protect.
        # Low MemAvailable is the single most likely cause of an unexplained
        # outage, because the OOM killer picks the largest process — usually
        # the application, not Sentinel.
        out["mem_pressure"] = (
            "critical"
            if out["mem_available_mb"] < 500
            else "warning"
            if out["mem_available_mb"] < 1024
            else "ok"
        )
    except OSError as exc:
        out["mem_error"] = str(exc)

    try:
        load1, load5, load15 = os.getloadavg()
        out["load"] = {"1m": round(load1, 2), "5m": round(load5, 2), "15m": round(load15, 2)}
        out["cpu_count"] = os.cpu_count()
    except OSError as exc:
        out["load_error"] = str(exc)

    disks = {}
    for mount in ("/", "/var", "/var/backups/sentinel", "/var/lib/pgsql"):
        try:
            st = os.statvfs(mount)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        free = st.f_bavail * st.f_frsize
        if total == 0:
            continue
        disks[mount] = {
            "total_gb": round(total / 1024**3, 2),
            "free_gb": round(free / 1024**3, 2),
            "used_pct": round(100 * (1 - free / total), 1),
            "inodes_used_pct": (
                round(100 * (1 - st.f_favail / st.f_files), 1) if st.f_files else None
            ),
        }
    out["disks"] = disks
    return out


def sentinel_files() -> dict[str, Any]:
    """Facts a database query cannot tell you."""
    panic = Path("/etc/sentinel/PANIC")
    return {
        "panic_file_present": panic.exists(),
        "panic_note": (
            "PANIC file exists — the root watchdog flushes the blocklist within 60s "
            "and auto-blocking stays off until it is removed."
            if panic.exists()
            else None
        ),
        "config_present": Path("/etc/sentinel/sentinel.yaml").exists(),
        "executor_socket_present": Path("/run/sentinel/executor.sock").exists(),
        "suricata_eve_present": Path("/var/log/suricata/eve.json").exists(),
    }


async def build() -> dict[str, Any]:
    conn = await c.connect()
    try:
        services = await conn.fetch(
            """
            SELECT DISTINCT ON (h.asset_id)
                   a.name AS asset, a.kind, a.is_internet_exposed, a.criticality,
                   h.status, h.latency_ms, h.http_status, h.error, h.ts
            FROM health_samples h
            JOIN assets a ON a.id = h.asset_id
            WHERE h.ts >= now() - interval '10 minutes'
            ORDER BY h.asset_id, h.ts DESC
            """
        )
        incidents = await conn.fetch(
            """
            SELECT COALESCE(ai_severity, severity) AS severity, count(*) AS n
            FROM incidents
            WHERE status IN ('open', 'acknowledged')
            GROUP BY 1
            """
        )
        blocks = await conn.fetchrow(
            """
            SELECT count(*) FILTER (WHERE active) AS active,
                   count(*) FILTER (WHERE active AND expires_at IS NULL) AS permanent,
                   count(*) FILTER (WHERE blocked_at >= now() - interval '1 hour') AS last_hour,
                   max(blocked_at) AS most_recent
            FROM blocklist
            """
        )
        findings = await conn.fetchrow(
            """
            SELECT count(*) FILTER (WHERE status = 'open' AND severity = 'critical') AS critical,
                   count(*) FILTER (WHERE status = 'open' AND severity = 'high')     AS high,
                   count(*) FILTER (WHERE status = 'open' AND kev)                   AS kev_open,
                   count(*) FILTER (WHERE status = 'open')                           AS total_open
            FROM findings
            """
        )
        ai_queue = await conn.fetch(
            """
            SELECT state, count(*) AS n, min(enqueued_at) AS oldest
            FROM ai_jobs
            WHERE state IN ('queued', 'running', 'failed')
            GROUP BY state
            """
        )
        budget = await conn.fetchrow(
            """
            SELECT round(COALESCE(sum(cost_usd) FILTER
                     (WHERE at >= date_trunc('day', now())), 0)::numeric, 4)   AS today_usd,
                   round(COALESCE(sum(cost_usd) FILTER
                     (WHERE at >= date_trunc('month', now())), 0)::numeric, 4) AS month_usd,
                   max(at) AS last_call
            FROM ai_usage
            """
        )
        ingest = await conn.fetchrow(
            """
            SELECT count(*) AS events_last_5m, max(ts) AS newest_event
            FROM raw_events
            WHERE ts >= now() - interval '5 minutes'
            """
        )
        feeds = await conn.fetch(
            """
            SELECT name, last_refresh, entry_count,
                   (now() - last_refresh) AS staleness
            FROM intel_feeds
            ORDER BY last_refresh
            """
        )
        db_size = await conn.fetchval("SELECT pg_database_size(current_database())")
    finally:
        await conn.close()

    incident_counts = {r["severity"]: r["n"] for r in incidents}
    services_d = c.rows_to_dicts(services)
    down = [s for s in services_d if s["status"] == "down"]
    degraded = [s for s in services_d if s["status"] == "degraded"]

    capacity = host_capacity()
    files = sentinel_files()

    problems: list[str] = []
    if down:
        problems.append(f"{len(down)} service(s) down: {', '.join(s['asset'] for s in down)}")
    if capacity.get("mem_pressure") == "critical":
        problems.append(
            f"MemAvailable {capacity.get('mem_available_mb')} MB — critical. "
            "The OOM killer will pick the largest process, which is usually the "
            "application this host exists to run rather than Sentinel."
        )
    for mount, d in capacity.get("disks", {}).items():
        if d["used_pct"] > 85:
            problems.append(f"disk {mount} at {d['used_pct']}%")
    if incident_counts.get("critical"):
        problems.append(f"{incident_counts['critical']} open critical incident(s)")
    if findings and findings["kev_open"]:
        problems.append(f"{findings['kev_open']} open KEV-listed finding(s)")
    if files["panic_file_present"]:
        problems.append("PANIC file present — blocking is disabled")
    queue = {r["state"]: r["n"] for r in ai_queue}
    if queue.get("queued", 0) > 50:
        problems.append(f"AI queue depth {queue['queued']} — the worker may be stuck")
    if ingest and (ingest["events_last_5m"] or 0) == 0:
        problems.append("no events ingested in the last 5 minutes — check sentinel-ingest")

    return {
        "problems": problems or ["none"],
        "services": {
            "total": len(services_d),
            "down": [s["asset"] for s in down],
            "degraded": [s["asset"] for s in degraded],
            "detail": services_d,
        },
        "incidents_open": incident_counts,
        "blocklist": c.rows_to_dicts([blocks])[0] if blocks else {},
        "findings": c.rows_to_dicts([findings])[0] if findings else {},
        "capacity": capacity,
        "ingestion": c.rows_to_dicts([ingest])[0] if ingest else {},
        "ai": {
            "queue": queue,
            "budget": c.rows_to_dicts([budget])[0] if budget else {},
        },
        "intel_feeds": c.rows_to_dicts(feeds),
        "database_size_gb": round((db_size or 0) / 1024**3, 3),
        "sentinel_units_expected": list(SENTINEL_UNITS),
        "files": files,
        "note": (
            "systemd unit states are not queryable from this read-only context. "
            "If a unit is suspected down, the operator can check with "
            "`systemctl status 'sentinel-*'`."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    c.add_format_arg(parser)
    args = parser.parse_args()
    snapshot = c.run(build())
    if args.format == "table":
        # A snapshot is nested; a table would lose the structure. Show the
        # headline and the service list, then fall back to JSON for the rest.
        print("PROBLEMS:")
        for p in snapshot["problems"]:
            print(f"  - {p}")
        print()
        c.emit(snapshot["services"]["detail"], "table")
        return
    c.emit(snapshot, "json")


if __name__ == "__main__":
    c.main_wrapper(main)
