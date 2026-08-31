"""The detection → actor → incident write path, and the reads the UI and bot need.

The three tables move together: a rule match is a *detection*, attributed to an
*actor* (an IP, for now), and folded into an *incident* deduplicated by
fingerprint. The unique partial index on `incidents(fingerprint) WHERE status IN
(open, acknowledged)` is what makes an ongoing brute-force one incident that grows
rather than a thousand identical alerts — the single most important property here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sentinel.db.engine import Database
from sentinel.db.repo import incident_campaigns as camp_repo
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def severity_at_least(sev: str, floor: str) -> bool:
    return _SEV_RANK.get(sev, 0) >= _SEV_RANK.get(floor, 0)


# --- actors ---------------------------------------------------------------
async def upsert_actor(
    db: Database,
    actor_key: str,
    *,
    src_ip: str | None = None,
    user_agent: str | None = None,
    country: str | None = None,
    asn: int | None = None,
    asset_id: int | None = None,
    reputation: list[str] | None = None,
    is_known_scanner: bool | None = None,
) -> None:
    """`reputation`/`is_known_scanner` are the caller's CURRENT read of the
    feeds (see `detect/engine.py:_apply`, which looks them up via
    `sentinel.intel.reputation.lookup` on every detection). `None` for either
    means "the caller did not look up" — leave the existing value alone —
    never "clear it"; a lookup failure must not erase a real scanner flag that
    was set on a previous, successful detection. When a value IS supplied it
    OVERWRITES rather than merges with history: unlike `countries`/`asns`
    (append-only, since "this actor was once seen from FR" stays true forever),
    reputation is a claim about what the feeds say RIGHT NOW, and an
    accumulating array would keep a category from a feed entry removed months
    ago on the row forever."""
    await db.execute(
        """
        INSERT INTO actors (actor_key, kind, member_ips, last_seen, detection_count,
                            user_agents, countries, asns, targeted_assets,
                            reputation, is_known_scanner)
        VALUES ($1, 'ip',
                CASE WHEN $2::inet IS NULL THEN '{}'::inet[] ELSE ARRAY[$2::inet] END,
                now(), 1,
                CASE WHEN $3::text IS NULL THEN '{}'::text[] ELSE ARRAY[$3] END,
                CASE WHEN $4::text IS NULL THEN '{}'::text[] ELSE ARRAY[$4] END,
                CASE WHEN $5::int  IS NULL THEN '{}'::int[]  ELSE ARRAY[$5] END,
                CASE WHEN $6::bigint IS NULL THEN '{}'::bigint[] ELSE ARRAY[$6] END,
                COALESCE($7::text[], '{}'::text[]),
                COALESCE($8::boolean, false))
        ON CONFLICT (actor_key) DO UPDATE SET
            last_seen        = now(),
            detection_count  = actors.detection_count + 1,
            -- COALESCE(..., '{}') because array_agg over an empty set returns
            -- NULL, and these columns are NOT NULL. Merging two empty arrays must
            -- yield an empty array, not a constraint violation.
            countries        = COALESCE((SELECT array_agg(DISTINCT c) FROM unnest(actors.countries || EXCLUDED.countries) c), '{}'::text[]),
            asns             = COALESCE((SELECT array_agg(DISTINCT a) FROM unnest(actors.asns || EXCLUDED.asns) a), '{}'::int[]),
            user_agents      = COALESCE((SELECT array_agg(DISTINCT u) FROM unnest((actors.user_agents || EXCLUDED.user_agents)[1:20]) u), '{}'::text[]),
            targeted_assets  = COALESCE((SELECT array_agg(DISTINCT t) FROM unnest(actors.targeted_assets || EXCLUDED.targeted_assets) t), '{}'::bigint[]),
            reputation       = CASE WHEN $7::text[]  IS NULL THEN actors.reputation      ELSE $7::text[]  END,
            is_known_scanner = CASE WHEN $8::boolean IS NULL THEN actors.is_known_scanner ELSE $8::boolean END
        """,
        actor_key, src_ip, user_agent, country, asn, asset_id, reputation, is_known_scanner,
    )


async def actor_is_allowlisted(db: Database, actor_key: str) -> bool:
    return bool(await db.fetchval("SELECT is_allowlisted FROM actors WHERE actor_key = $1", actor_key))


async def actor_flags(db: Database, actor_key: str) -> dict[str, Any]:
    """What the decider consults before an auto-block: the two boolean gates
    plus the hostile-category list that only ever LOWERS the local-evidence
    threshold (see `respond/decider.py`, guard 2 — never arms a block by
    itself). A missing actor (never seen the enrichment pass) reads as
    allowlisted=false, known_scanner=false, reputation=[] — absence of
    reputation, not evidence of innocence, and the decider treats it exactly
    like any other actor with no feed match: no threshold change."""
    row = await db.fetchrow(
        "SELECT is_allowlisted, is_known_scanner, reputation FROM actors WHERE actor_key = $1",
        actor_key)
    if row is None:
        return {"is_allowlisted": False, "is_known_scanner": False, "reputation": []}
    return {"is_allowlisted": bool(row["is_allowlisted"]),
            "is_known_scanner": bool(row["is_known_scanner"]),
            "reputation": list(row["reputation"] or [])}


async def set_auto_action(db: Database, incident_id: int, action: str) -> None:
    """Record what the auto-block decider chose. The push loop reads this to
    shape the alert (block button vs. 'blocked, unblock?' vs. why it was skipped)."""
    await db.execute(
        "UPDATE incidents SET auto_action = $2, auto_action_at = now() WHERE id = $1",
        incident_id, action)


# --- detections + incidents ----------------------------------------------
async def record_detection(
    db: Database,
    *,
    rule_id: str,
    rule_family: str,
    severity: str,
    actor_key: str | None,
    src_ip: str | None,
    dst_port: int | None,
    asset_id: int | None,
    evidence: dict[str, Any],
    event_ids: list[int],
) -> int:
    return int(
        await db.fetchval(
            """
            INSERT INTO detections (rule_id, rule_family, severity, actor_key, src_ip,
                                    dst_port, asset_id, evidence, event_ids)
            VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8::jsonb, $9)
            RETURNING id
            """,
            rule_id, rule_family, severity, actor_key, src_ip, dst_port, asset_id,
            json.dumps(evidence), event_ids,
        )
    )


async def upsert_incident(
    db: Database,
    *,
    fingerprint: str,
    severity: str,
    title: str,
    summary: str,
    actor_key: str | None,
    asset_id: int | None,
) -> tuple[int, bool]:
    """Create the incident or fold this detection into the open one.

    Returns (incident_id, is_new). is_new is True only when a fresh incident was
    opened — the caller uses it to decide whether this warrants a new-incident
    Telegram push versus a quiet update. Severity only ever ratchets UP: a
    brute-force that escalates to a critical count must not be quietly downgraded
    by a later, smaller batch.

    Also attaches the incident to its campaign (`campaigns.attach_incident`,
    keyed by the rule family — the part of `fingerprint` before the first
    `:`). Campaign attachment is a reading convenience, not the detection
    itself: if it raises, the incident this function just wrote must still
    come back to the caller, so the call is wrapped and a failure only logs a
    warning. A detection lost because grouping failed would be far worse than
    a missing campaign.
    """
    row = await db.fetchrow(
        """
        INSERT INTO incidents (fingerprint, severity, title, summary, actor_key, asset_id)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (fingerprint) WHERE status IN ('open','acknowledged')
        DO UPDATE SET
            detection_count   = incidents.detection_count + 1,
            last_detection_at = now(),
            severity          = CASE
                WHEN array_position(ARRAY['info','low','medium','high','critical'], $2)
                   > array_position(ARRAY['info','low','medium','high','critical'], incidents.severity)
                THEN $2 ELSE incidents.severity END,
            summary           = $4
        RETURNING id, (xmax = 0) AS is_new
        """,
        fingerprint, severity, title, summary, actor_key, asset_id,
    )
    incident_id, is_new = int(row["id"]), bool(row["is_new"])

    try:
        await camp_repo.attach_incident(db, incident_id, fingerprint.split(":", 1)[0], severity)
    except Exception as exc:  # noqa: BLE001 - detection must survive a grouping failure
        log.warning("campaign attach failed", extra={"incident_id": incident_id, "detail": str(exc)})

    return incident_id, is_new


async def link_detection(db: Database, detection_id: int, incident_id: int) -> None:
    await db.execute("UPDATE detections SET incident_id = $2 WHERE id = $1", detection_id, incident_id)


async def add_timeline(db: Database, incident_id: int, kind: str, actor: str, detail: dict[str, Any]) -> None:
    await db.execute(
        "INSERT INTO incident_timeline (incident_id, kind, actor, detail) VALUES ($1, $2, $3, $4::jsonb)",
        incident_id, kind, actor, json.dumps(detail),
    )


# --- cursor for the detect engine -----------------------------------------
async def get_detect_cursor(db: Database) -> int:
    return int(await db.fetchval(
        "SELECT cursor FROM collector_cursors WHERE name = 'detect:events'"
    ) or 0)


async def set_detect_cursor(db: Database, event_id: int) -> None:
    await db.execute(
        """
        INSERT INTO collector_cursors (name, cursor, updated_at)
        VALUES ('detect:events', $1::text, now())
        ON CONFLICT (name) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now()
        """,
        str(event_id),
    )


# --- reads for the UI and the bot -----------------------------------------
@dataclass
class IncidentRow:
    id: int
    fingerprint: str
    status: str
    severity: str
    title: str
    summary: str | None
    actor_key: str | None
    detection_count: int
    first_detection_at: datetime
    last_detection_at: datetime
    ai_severity: str | None
    notified_at: datetime | None
    auto_action: str | None


def _incident(row: Any) -> IncidentRow:
    d = dict(row)
    return IncidentRow(**{k: d[k] for k in IncidentRow.__dataclass_fields__})


_INCIDENT_COLS = """
    id, fingerprint, status, severity, title, summary, actor_key, detection_count,
    first_detection_at, last_detection_at, ai_severity, notified_at, auto_action
"""


# Sort orders offered in the UI. Whitelisted rather than interpolated: the value
# arrives from a query string and goes straight into ORDER BY.
SORTS = {
    # Newest first — what you want while something is happening right now.
    "recent": "last_detection_at DESC, id DESC",
    # Severity first, newest within a level — what you want when catching up,
    # because a critical from this morning outranks a medium from a minute ago.
    "severitate": ("array_position(ARRAY['info','low','medium','high','critical'], severity) DESC, "
                   "last_detection_at DESC"),
    "vechi": "last_detection_at ASC, id ASC",
    "detectii": "detection_count DESC, last_detection_at DESC",
}
DEFAULT_SORT = "recent"


async def list_incidents(db: Database, *, status: str | None = None, limit: int = 100,
                         sort: str = DEFAULT_SORT) -> list[IncidentRow]:
    order = SORTS.get(sort, SORTS[DEFAULT_SORT])
    where = "" if status is None else "WHERE status = $2"
    args: list[Any] = [limit] + ([status] if status else [])
    rows = await db.fetch(
        f"""
        SELECT {_INCIDENT_COLS} FROM incidents {where}
        ORDER BY (status IN ('open','acknowledged')) DESC, {order}
        LIMIT $1
        """,
        *args,
    )
    return [_incident(r) for r in rows]


async def get_incident(db: Database, incident_id: int) -> IncidentRow | None:
    row = await db.fetchrow(f"SELECT {_INCIDENT_COLS} FROM incidents WHERE id = $1", incident_id)
    return _incident(row) if row else None


async def untriaged(db: Database, *, min_severity: str = "high", limit: int = 10) -> list[IncidentRow]:
    """Open incidents at/above the floor that the AI has not looked at yet."""
    floor = _SEV_RANK.get(min_severity, 3)
    rows = await db.fetch(
        f"""
        SELECT {_INCIDENT_COLS} FROM incidents
        WHERE ai_analyzed_at IS NULL
          AND status IN ('open','acknowledged')
          AND array_position(ARRAY['info','low','medium','high','critical'], severity) - 1 >= $1
        ORDER BY array_position(ARRAY['info','low','medium','high','critical'], severity) DESC,
                 last_detection_at DESC
        LIMIT $2
        """,
        floor, limit,
    )
    return [_incident(r) for r in rows]


CLOSED_STATUSES = ("resolved", "false_positive", "suppressed")
SETTABLE_STATUSES = ("acknowledged", *CLOSED_STATUSES, "open")


async def set_status(db: Database, incident_id: int, status: str, *, by: str,
                     note: str | None = None) -> bool:
    """Move one incident along. Returns False for an unknown status rather than
    raising, so a tampered form value cannot 500 the page.

    Closing is not deletion: the row keeps its evidence and timeline. If the same
    actor trips the same rule again, `upsert_incident` will not match this row
    (its conflict target covers only open/acknowledged) and a NEW incident is
    raised — which is the honest outcome, since something you closed came back.
    """
    if status not in SETTABLE_STATUSES:
        return False
    await db.execute(
        """
        UPDATE incidents SET
            status = $2,
            acknowledged_by = CASE WHEN $2 = 'acknowledged' THEN $3 ELSE acknowledged_by END,
            acknowledged_at = CASE WHEN $2 = 'acknowledged' THEN now() ELSE acknowledged_at END,
            resolved_at     = CASE WHEN $2 = ANY($5::text[]) THEN now() ELSE NULL END,
            resolution_note = COALESCE($4, resolution_note)
        WHERE id = $1
        """,
        incident_id, status, by, note, list(CLOSED_STATUSES))
    await add_timeline(db, incident_id, "status", by,
                       {"status": status, "note": note})
    return True


async def bulk_close(db: Database, *, rule: str, status: str, by: str,
                     older_than_hours: int = 0, note: str | None = None) -> int:
    """Close every open incident from one rule at once.

    This exists because a noisy rule produces hundreds of incidents, and closing
    them one at a time is how a queue stops being read at all. Scoped to a single
    rule on purpose: a blanket "close everything" would hide the one incident
    that mattered along with the 400 that did not.
    """
    if status not in CLOSED_STATUSES:
        return 0
    rows = await db.fetch(
        """
        UPDATE incidents SET status = $2, resolved_at = now(),
            resolution_note = COALESCE($4, 'închis în masă')
        WHERE status IN ('open', 'acknowledged')
          AND split_part(fingerprint, ':', 1) = $1
          AND last_detection_at < now() - make_interval(hours => $5)
        RETURNING id
        """,
        rule, status, by, note, older_than_hours)
    for r in rows:
        await add_timeline(db, r["id"], "status", by,
                           {"status": status, "bulk": True, "rule": rule})
    return len(rows)


async def open_rules(db: Database) -> list[dict[str, Any]]:
    """Which rules have open incidents, for the bulk-close chooser."""
    rows = await db.fetch(
        """
        SELECT split_part(fingerprint, ':', 1) AS regula, count(*) AS n,
               max(last_detection_at) AS ultim
        FROM incidents WHERE status IN ('open','acknowledged')
        GROUP BY 1 ORDER BY n DESC
        """
    )
    return [dict(r) for r in rows]


async def get_ai_verdict(db: Database, incident_id: int) -> dict[str, Any] | None:
    raw = await db.fetchval("SELECT ai_verdict FROM incidents WHERE id = $1", incident_id)
    if not raw:
        return None
    return json.loads(raw) if isinstance(raw, str) else raw


async def set_ai_verdict(db: Database, incident_id: int, *, ai_severity: str | None,
                         verdict: dict[str, Any], confidence: float | None) -> None:
    await db.execute(
        """
        UPDATE incidents SET ai_severity = $2, ai_verdict = $3::jsonb,
            ai_confidence = $4, ai_analyzed_at = now()
        WHERE id = $1
        """,
        incident_id, ai_severity, json.dumps(verdict), confidence)
    await add_timeline(db, incident_id, "ai_verdict", "ai", verdict)


async def incident_detections(db: Database, incident_id: int, limit: int = 20) -> list[dict]:
    rows = await db.fetch(
        """
        SELECT ts, rule_id, severity, host(src_ip) AS src_ip, evidence
        FROM detections WHERE incident_id = $1 ORDER BY ts DESC LIMIT $2
        """,
        incident_id, limit,
    )
    return [dict(r) for r in rows]


async def open_counts(db: Database) -> dict[str, int]:
    rows = await db.fetch(
        """
        SELECT severity, count(*) AS n FROM incidents
        WHERE status IN ('open','acknowledged') GROUP BY severity
        """
    )
    out = {s: 0 for s in SEVERITIES}
    for r in rows:
        out[r["severity"]] = r["n"]
    out["total"] = sum(out[s] for s in SEVERITIES)
    return out


async def unnotified(db: Database, *, min_severity: str = "medium", limit: int = 20) -> list[IncidentRow]:
    """New incidents the bot has not pushed yet, at or above the severity floor."""
    floor = _SEV_RANK.get(min_severity, 2)
    rows = await db.fetch(
        f"""
        SELECT {_INCIDENT_COLS} FROM incidents
        WHERE notified_at IS NULL
          AND array_position(ARRAY['info','low','medium','high','critical'], severity) - 1 >= $1
        ORDER BY first_detection_at
        LIMIT $2
        """,
        floor, limit,
    )
    return [_incident(r) for r in rows]


async def mark_notified(db: Database, incident_id: int) -> None:
    await db.execute("UPDATE incidents SET notified_at = now() WHERE id = $1", incident_id)
