"""The incident-campaign layer: the same rule family in flight, read as one row.

An incident is one (actor, rule, 15-minute window). A campaign groups the
incidents sharing a rule family — the part of `fingerprint` before the first
`:` — because that is the grouping actually measured to work. On the host
this was measured on, 968 open incidents collapse to 14 campaigns grouped by
family, and the 67 active in the last 24h collapse to 5. Grouping by network
was measured and rejected first: by /24 the same 968 barely move (822
groups), by ASN they barely move either (391) — most `ids.suricata`
incidents come from distinct actors in distinct networks, which is
background internet noise hitting the same front, not one attacker's
infrastructure. `asset_id` is NULL on all but one incident on that host and
is deliberately left out of the key.

## Why `incident_campaigns`, not `campaigns`

`0008_baselines.sql` already created a table named `campaigns` — actor
clustering by /24, ASN, user agent, JA4, path sequence and timing, part of
the prediction layer, declared in schema but never wired to any Python code.
This module's table needed a different name to avoid a straight `CREATE
TABLE campaigns` collision on every host that has already run 0008 (all of
them). The two are unrelated groupings — this one is by rule family, that one
is by actor similarity — and 0008's `campaigns` is untouched.

## The unique partial index is what makes `attach_incident` safe

`incident_campaigns_key_active_idx` (migration 0039) mirrors
`incidents_fingerprint_open_idx` (0001_core.sql): at most one row with
`status = 'active'` per `campaign_key`, enforced by the database, not by
code. `attach_incident` relies on it for
`INSERT ... ON CONFLICT (campaign_key) WHERE status = 'active'` — a
SELECT-then-INSERT here would lose a race between two detections landing on
the same family at the same instant.

## A quiet campaign never reactivates

Same decision, for the same reason, as `close_stale_incidents` in
`maintenance_service.py`: the partial index covers only `active`, so new
activity on a family that has gone quiet opens a NEW campaign rather than
resurrecting the old one. A front that goes silent for a day and comes back
is a new event, not a continuation — collapsing the two would make
`first_seen_at` lie about when the wave that is actually being read started.
"""

from __future__ import annotations

from typing import Any

from sentinel.db.engine import Database

#: Below this many hours of silence, an `active` campaign is left alone.
#: Absolute, not derived from another constant — a threshold written as
#: `SOMETHING_ELSE + 8` drifts silently the moment someone moves
#: `SOMETHING_ELSE` for an unrelated reason.
CAMPAIGN_QUIET_HOURS = 24

#: Same order as `SEVERITIES` in `incidents.py`, spelled out again here
#: because it has to live inside a SQL literal (`array_position` needs an
#: actual array, not a Python list bound as a parameter).
_SEVERITY_ORDER_SQL = "ARRAY['info','low','medium','high','critical']"


async def attach_incident(db: Database, incident_id: int, rule_family: str, severity: str) -> int:
    """Link `incident_id` to the active campaign for `rule_family`, creating
    one if none is active, and recompute counters from the incidents that
    actually reference each campaign touched. Returns the new campaign id.

    `incident_count`/`actor_count` are RECOMPUTED (`count(*)`,
    `count(DISTINCT actor_key)`) on every call, never incremented. An
    incremented counter silently diverges from reality the first time a call
    is retried or an incident moves to a different campaign; a recomputed one
    cannot, by construction — see `CLAUDE.md` on this exact class of bug.

    ## Moving an incident recomputes BOTH ends, not just the destination

    An incident that was already attached to a campaign can move: its old
    campaign went `quiet` (or `closed`), the partial index then let a NEW
    active row open for the same family (see the module docstring), and the
    next detection on this same incident attaches it there instead. Found in
    round 1 review with the default production thresholds (medium incidents
    close at 7 days, campaigns go quiet at `CAMPAIGN_QUIET_HOURS` = 24h) — not
    a theoretical case. Recomputing only the destination left the SOURCE
    campaign's stored counters wrong forever: `quiet_stale` promises those
    rows "stay on record", and a wrong record is worse than none, because
    nothing about a `quiet` row's shape says it might be lying. So both the
    destination and — when it differs and existed — the incident's PREVIOUS
    campaign are recomputed in the same transaction.

    The previous campaign's `last_activity_at` is deliberately NOT touched:
    losing a member is an accounting correction, not new activity on that
    front, and bumping it would make an abandoned `quiet` row look freshly
    active. Its `severity` falls back to whatever it already was if the
    recompute leaves it with zero members — see `_recompute`.

    All statements run inside one transaction, so a concurrent call
    attaching a different incident to either campaign cannot observe this
    one half-done.

    Caller's responsibility, not this function's: if this raises, the
    incident that triggered it must already have been written. Campaign
    membership is a reading convenience; losing it must never cost the
    detection it was derived from. See `incidents.upsert_incident`.
    """
    async with db.transaction() as conn:
        campaign_id = await conn.fetchval(
            """
            INSERT INTO incident_campaigns (campaign_key, severity, title)
            VALUES ($1, $2, $3)
            ON CONFLICT (campaign_key) WHERE status = 'active'
            DO UPDATE SET last_activity_at = now()
            RETURNING id
            """,
            rule_family, severity, f"Campanie: {rule_family}",
        )

        old_campaign_id = await conn.fetchval(
            "SELECT campaign_id FROM incidents WHERE id = $1", incident_id)

        await conn.execute(
            "UPDATE incidents SET campaign_id = $2 WHERE id = $1",
            incident_id, campaign_id,
        )

        await _recompute(conn, campaign_id, bump_activity=True)
        if old_campaign_id is not None and old_campaign_id != campaign_id:
            await _recompute(conn, old_campaign_id, bump_activity=False)
    return int(campaign_id)


async def _recompute(conn, campaign_id: int, *, bump_activity: bool) -> None:
    """Recompute one campaign row's `incident_count`/`actor_count`/`severity`
    from the incidents that actually point at it right now — never from the
    row's own previous value, which is exactly the increment-drift bug this
    module exists to avoid.

    `severity` uses `COALESCE(sub.top_severity, c.severity)`: when the
    campaign has been emptied (its last incident just moved elsewhere),
    `array_agg` over zero rows is NULL, and `incident_campaigns.severity` is
    `NOT NULL` — writing NULL there would fail the whole transaction. Falling
    back to the existing value keeps the emptied row's last known severity
    rather than crashing the caller over a row that is, by design, staying on
    record with stale-but-valid data (see `quiet_stale`).

    `bump_activity` is False for a campaign an incident just LEFT: that is a
    bookkeeping correction, not activity on that front, and treating it as
    activity would make an abandoned `quiet` campaign look freshly alive.
    """
    extra = ", last_activity_at = now()" if bump_activity else ""
    await conn.execute(
        f"""
        UPDATE incident_campaigns c
           SET incident_count = sub.incident_count,
               actor_count = sub.actor_count,
               severity = COALESCE(sub.top_severity, c.severity){extra}
          FROM (
              SELECT count(*) AS incident_count,
                     count(DISTINCT actor_key) AS actor_count,
                     (array_agg(severity ORDER BY array_position(
                          {_SEVERITY_ORDER_SQL}, severity) DESC))[1] AS top_severity
                FROM incidents WHERE campaign_id = $1
          ) sub
         WHERE c.id = $1
        """,
        campaign_id,
    )


async def quiet_stale(db: Database, quiet_hours: int = CAMPAIGN_QUIET_HOURS) -> int:
    """Move `active` campaigns with no new activity in `quiet_hours` to
    `quiet`. Returns how many were moved.

    Does not close and does not delete anything: `quiet` is a read-time
    signal ("this front has gone silent, but stays on record"), not a
    resolution. See the module docstring for why a quieted campaign never
    comes back to `active` — new activity opens a new row instead.
    """
    rows = await db.fetch(
        """
        UPDATE incident_campaigns
           SET status = 'quiet', quieted_at = now()
         WHERE status = 'active'
           AND last_activity_at < now() - ($1::int * interval '1 hour')
         RETURNING id
        """,
        int(quiet_hours),
    )
    return len(rows)


async def active_campaigns(db: Database) -> list[dict[str, Any]]:
    """Every campaign currently `active`, worst severity first — what the
    dashboard and the Telegram summary read. Small by construction (14 rows
    measured on the host this was designed against): every incident maps to
    exactly one active campaign per family, and there are far fewer families
    than incidents."""
    rows = await db.fetch(
        f"""
        SELECT id, campaign_key, severity, title, first_seen_at, last_activity_at,
               incident_count, actor_count
          FROM incident_campaigns
         WHERE status = 'active'
         ORDER BY array_position({_SEVERITY_ORDER_SQL}, severity) DESC, last_activity_at DESC
        """
    )
    return [dict(r) for r in rows]
