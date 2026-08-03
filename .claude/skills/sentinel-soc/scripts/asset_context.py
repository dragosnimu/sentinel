#!/usr/bin/env python3
"""Everything known about one asset.

Call this before writing a patch plan. It gives you the asset's stack, service
unit, webroot, repository, databases, open findings, recent incidents,
availability, and the history of previous patches on it — which is the fastest
way to learn that the last attempt on this asset rolled back and why.

It reports what the *database* knows. Before writing a plan, still read the real
files on disk: the database records what discovery saw last night, not what is
installed right now.

Usage:
    asset_context.py --asset-id 12
    asset_context.py --name blog.example.com
"""

from __future__ import annotations

import argparse
from typing import Any

import _common as c


async def build(asset_id: int | None, name: str | None) -> dict[str, Any]:
    conn = await c.connect()
    try:
        if asset_id is not None:
            asset = await conn.fetchrow("SELECT * FROM assets WHERE id = $1", asset_id)
        else:
            asset = await conn.fetchrow("SELECT * FROM assets WHERE name = $1", name)
        if asset is None:
            available = await conn.fetch("SELECT id, name FROM assets ORDER BY name LIMIT 50")
            c.die(
                "asset not found. Known assets: "
                + ", ".join(f"{r['id']}:{r['name']}" for r in available)
            )

        aid = asset["id"]

        findings = await conn.fetch(
            """
            SELECT id, cve, severity, cvss, epss, kev, priority, package,
                   installed_version, fixed_version, location, status,
                   first_seen, (now() - first_seen) AS age
            FROM findings
            WHERE asset_id = $1 AND status IN ('open', 'patch_planned', 'deferred')
            ORDER BY priority DESC
            LIMIT 100
            """,
            aid,
        )

        incidents = await conn.fetch(
            """
            SELECT id, severity, ai_severity, status, title, actor_key,
                   detection_count, first_detection_at, resolved_at
            FROM incidents
            WHERE asset_id = $1 AND first_detection_at >= now() - interval '30 days'
            ORDER BY first_detection_at DESC
            LIMIT 25
            """,
            aid,
        )

        availability = await conn.fetch(
            """
            SELECT day, uptime_pct, p50_latency_ms, p95_latency_ms,
                   down_samples, incidents_count
            FROM availability_rollup
            WHERE asset_id = $1 AND day >= (now() - interval '30 days')::date
            ORDER BY day DESC
            """,
            aid,
        )

        current_health = await conn.fetchrow(
            """
            SELECT status, latency_ms, http_status, error, ts
            FROM health_samples
            WHERE asset_id = $1
            ORDER BY ts DESC
            LIMIT 1
            """,
            aid,
        )

        # Previous patch attempts. The most useful field here is why one failed.
        patches = await conn.fetch(
            """
            SELECT p.id, p.plan_id, p.status, p.risk_level, p.requires_reboot,
                   p.estimated_downtime_s, p.created_at, p.approved_at,
                   e.id AS execution_id, e.result, e.rollback_reason,
                   e.started_at, e.finished_at
            FROM patch_plans p
            LEFT JOIN patch_executions e ON e.plan_id = p.id
            WHERE p.asset_id = $1
            ORDER BY p.created_at DESC
            LIMIT 15
            """,
            aid,
        )

        restore_points = await conn.fetch(
            """
            SELECT id, path, size_bytes, created_at, verified_at, retention_hold,
                   (now() - created_at) AS age
            FROM restore_points
            WHERE asset_id = $1
            ORDER BY created_at DESC
            LIMIT 10
            """,
            aid,
        )

        scans = await conn.fetch(
            """
            SELECT scanner, status, findings_count, started_at, finished_at, duration_ms
            FROM scans
            WHERE target = $1 OR target = $2
            ORDER BY started_at DESC
            LIMIT 10
            """,
            asset["name"],
            str(aid),
        )

        drift = await conn.fetch(
            """
            SELECT field, discovered_value, inventory_value, detected_at
            FROM asset_drift
            WHERE asset_id = $1 AND resolved_at IS NULL
            """,
            aid,
        )
    finally:
        await conn.close()

    asset_d = c.rows_to_dicts([asset])[0]

    notes: list[str] = []
    if asset_d.get("protected"):
        notes.append(
            "PROTECTED asset. No automated patch plan may be generated for it. "
            "Return an error object explaining that manual intervention is required."
        )
    if not asset_d.get("confirmed_by_operator"):
        notes.append(
            "Not confirmed by the operator. Active scanning (DAST) is not authorised "
            "for this asset."
        )
    if not asset_d.get("databases"):
        notes.append(
            "No databases recorded. Verify on disk before concluding a file-only "
            "backup is sufficient — discovery misses SQLite files and embedded stores."
        )
    if drift:
        notes.append(
            f"{len(drift)} unresolved inventory drift entries. The recorded values "
            "below may be stale; read the real files."
        )

    return {
        "asset": asset_d,
        "open_findings": c.rows_to_dicts(findings),
        "recent_incidents": c.rows_to_dicts(incidents),
        "current_health": c.rows_to_dicts([current_health])[0] if current_health else None,
        "availability_30d": c.rows_to_dicts(availability),
        "patch_history": c.rows_to_dicts(patches),
        "restore_points": c.rows_to_dicts(restore_points),
        "recent_scans": c.rows_to_dicts(scans),
        "inventory_drift": c.rows_to_dicts(drift),
        "notes": notes,
        "verify_on_disk": [
            "systemctl cat <unit>",
            "nginx -T   (find the real server_name, root and proxy_pass)",
            "rpm -q <package>   or the stack's own version command",
            "ls -la <webroot>   and the lockfile for the stack",
            "df -h /var/backups/sentinel   before sizing a backup",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--asset-id", type=int)
    group.add_argument("--name")
    c.add_format_arg(parser)
    args = parser.parse_args()

    context = c.run(build(args.asset_id, args.name))
    c.emit(context, "json" if args.format == "table" else args.format)


if __name__ == "__main__":
    c.main_wrapper(main)
