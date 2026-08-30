"""Propose blocking a /24, not a single address, when the address itself is the
wrong unit — several distinct hosts in the same prefix are behaving the same
way in the same window, and blocking one at a time is chasing a botnet /32 by
/32 while it rotates through the rest of its own subnet.

Measured on this host, 30 august 2026 (distinct addresses per /24, actions
auth_fail / alert): at a 1h window nothing ever reaches 3 distinct addresses;
at 6h only 2 prefixes do; at 24h about 6 (5 with 3-4 addresses, 1 with 5-9); at
7 days the bucket balloons to 256 (114 with 3-4, 81 with 5-9, 61 with 10+) —
but that is an entire week folded into one snapshot, not a daily rate, and
turning this rule on against a week-wide bucket the first time it runs would
open all 256 at once. **Window: 24h. Threshold: 3 distinct addresses.** That
matches the point in the data where the signal stabilises into a small,
steady number — about 6 candidate prefixes a day here — instead of either
nothing (1h, 6h) or a backlog (7d). A count of 2735 prefixes have exactly ONE
hostile address in the 7-day bucket; a threshold of 3 excludes all of those by
construction — including the operator's own networks, each contributing
exactly one hostile address in the 7-day window (an agent's own failed key
auth, an operator's own failed login).

**What actually protects those two networks today is not the allowlist guard
below — measured on the production host, the `allowlist` TABLE has 0 rows,
confirmed and 0 unconfirmed, and nothing in this codebase ever writes to it
(`grep -rn "INSERT INTO allowlist"` is empty).** The real protection today is
two things: the threshold of 3 above (both operator networks show exactly one
hostile address in the 7-day bucket), and `response.extra_allowlist`, which
DOES hold the operator's address on this host and IS read by
this rule (see `cidr_cluster` below). The `_overlaps_any` guard against the
`allowlist` table is still correct code — for the day someone starts writing
confirmed entries into it, or for another install that already has some — but
saying it protects this host's operator today, when the table is empty, would
be the exact pattern this repository is named after (see commit `0122ee0`).
This rule does not write to `allowlist`; that is out of scope here.

Guards, each argued where it is enforced:

* **density, not volume** — `_severity_for` below reads `distinct_addrs`
  only. A prefix with a single address and 30 000 events is one loud host and
  a `/32` job, not this rule's; distinct_addrs=1 never clears the floor no
  matter how many events came with it.
* **the whole interval against BOTH allowlists, not one address in it** —
  `_overlaps_any` checks the *candidate network* for overlap with every
  confirmed, unexpired row in the `allowlist` table AND every entry in
  `response.extra_allowlist`. `respond/actions.py:is_allowlisted` answers "is
  this one address protected"; the question here is the reverse — "does the
  /24 I am about to propose touch anything protected at all" — and a single
  protected address anywhere inside it is enough to drop the whole proposal,
  unconditionally, regardless of how many hostile addresses the rest of the
  prefix has.
* **never wider than /24** — the SQL only ever masks to /24, but `build_specs`
  re-parses every candidate with `strict=True` and refuses anything wider
  (lower prefixlen) as a second, independent check: a `/16` on this host is
  65 536 addresses on the strength of a few dozen; that is an outage waiting
  to be armed, not a defense, so it does not get to reach the decider even if
  a future change to the query above widened the mask by mistake.
* **mandatory expiry** — this rule does not decide that; the auto-block
  decider does (`respond/decider.py` guard 4), because a spec here carries no
  TTL field at all — expiry is a property of the *block*, not the detection.
* **CIDR blocks stay observe-only** — likewise the decider's job
  (`allow_cidr_blocks` guard 3): this rule only ever produces a proposal, the
  actual arm/observe split happens after it, the same as every other rule.
* **severity follows whether the proposal is actionable, not just its size**
  — see `_severity_for`.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.detect.spec import DetectionSpec
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

CIDR_WINDOW_HOURS = 24
CIDR_MIN_DISTINCT = 3
CIDR_PREFIX_LEN = 24
# Highest first, same shape as SSH_THRESHOLDS in rules.py. 25+ distinct hosts
# hitting the same /24 in a single day has no precedent in the measured data
# (the 24h bucket tops out at "5-9"); it is a deliberately conservative jump to
# critical for a scale this host has not yet shown, not a value read off a
# sample of it. Used only once auto-block is armed for CIDR — see
# `_severity_for`.
CIDR_SEVERITY_ARMED = ((25, "critical"), (CIDR_MIN_DISTINCT, "high"))


def _severity_for(distinct_addrs: int, armed: bool) -> str | None:
    """Severity follows whether the proposal can be ACTED on, not only its
    scale.

    Measured on the production host, last 7 days: 23.3 `high` alerts/day and
    4.9 `critical`. `allow_cidr_blocks` defaults to false and is false on this
    host, so every proposal from this rule comes out `observed` — there is no
    button: `telegram/bot.py:_incident_block_kb` parses `actor_key` as a plain
    address and returns no keyboard for anything with a `/` in it (confirmed).
    Marking that `high` would have pushed ~6 unactionable alerts/day to a
    channel that already pushes 23.3 actionable ones — +26% noise for zero
    available action, straight back into the volume this repository spent its
    last two days pulling down from 9.31/h to 0.66/h.

    So: while `allow_cidr_blocks` is false, everything above the floor is
    `medium` — below `telegram.min_severity` (`high` on this host), so the
    incident still exists on the page and in selfcheck for whoever goes
    looking, but nobody's phone rings for a decision that cannot be made yet.
    The moment `allow_cidr_blocks` flips true, the same cluster IS a decision,
    and severity follows that switch back up to the CIDR_SEVERITY_ARMED
    tiers — the same shape every other actionable rule in this file uses.
    This is not a quieter threshold dressed up as a design choice: it is the
    same threshold, gated on whether there is anything to do with it yet.
    """
    if not armed:
        return "medium" if distinct_addrs >= CIDR_MIN_DISTINCT else None
    for threshold, sev in CIDR_SEVERITY_ARMED:
        if distinct_addrs >= threshold:
            return sev
    return None


def _overlaps_any(candidate: ipaddress.IPv4Network | ipaddress.IPv6Network,
                   protected: list[str]) -> bool:
    """True if `candidate` touches ANY protected entry — a single protected
    address inside the /24 is enough. `overlaps()` is symmetric, so this also
    catches an allowlisted network wider than the candidate. `protected` is
    the UNION of the `allowlist` table and `response.extra_allowlist` — see
    the module docstring for which of the two actually has rows today."""
    for raw in protected:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if candidate.overlaps(net):
            return True
    return False


def build_specs(rows: list[dict[str, Any]], protected: list[str],
                 *, armed: bool) -> list[DetectionSpec]:
    """Pure: turn aggregated rows (one per candidate /24 that already cleared
    CIDR_MIN_DISTINCT in the SQL's HAVING) into proposals. Kept separate from
    the query so the guards above are unit-testable without a database.
    `armed` is `cfg.response.auto_block.allow_cidr_blocks`, passed down for
    `_severity_for` — see its docstring for why severity depends on it."""
    specs: list[DetectionSpec] = []
    for r in rows:
        distinct = int(r["distinct_addrs"])
        sev = _severity_for(distinct, armed)
        if sev is None:
            continue  # belt-and-suspenders: the SQL already enforces the floor

        prefix = r["prefix_cidr"]
        try:
            net = ipaddress.ip_network(prefix, strict=True)
        except ValueError:
            log.error("cidr candidate is not an aligned network", extra={"prefix": prefix})
            continue
        if net.prefixlen < CIDR_PREFIX_LEN:
            # Wider than /24 should never happen — the query only ever masks
            # to /24 — but a rule that can silently propose a /16 on a bug is
            # a rule that can silently arm one, so this is checked, not assumed.
            log.error("cidr candidate wider than /24, refusing to propose",
                       extra={"prefix": prefix, "prefixlen": net.prefixlen})
            continue

        if _overlaps_any(net, protected):
            continue

        events = int(r.get("events") or 0)
        sample_ips = list(r.get("sample_ips") or [])[:10]
        specs.append(DetectionSpec(
            rule_id="net.cidr_cluster", rule_family="net", severity=sev,
            src_ip=None, actor_key=str(net),
            fingerprint=f"net.cidr_cluster:{net}",
            title=f"Cluster ostil în {net}",
            summary=(f"{distinct} adrese distincte din {net} cu autentificări eșuate sau "
                     f"alerte IDS în ultimele {CIDR_WINDOW_HOURS}h, {events} evenimente în total"),
            evidence={
                "distinct_addrs": distinct, "events": events,
                "window_hours": CIDR_WINDOW_HOURS, "sample_ips": sample_ips,
                "country": r.get("country"), "asn": r.get("asn"),
            },
            event_ids=list(r.get("event_ids") or [])[:200],
        ))
    return specs


async def cidr_cluster(db: Database, cursor: int, cfg: Config) -> list[DetectionSpec]:
    """One row per /24 with a fresh hostile address since `cursor` and at
    least CIDR_MIN_DISTINCT distinct hostile addresses in the trailing
    CIDR_WINDOW_HOURS. IPv4 only — /24 grouping and the measured thresholds
    above are both IPv4-specific; IPv6 addresses never enter fresh_ips.

    Takes `cfg` — unlike the other rules in `rules.py` — because the
    allowlist guard needs `cfg.response.extra_allowlist`, which the shared
    `rule(db, cursor)` signature in `detect/engine.py` has no way to carry.
    `detect/engine.py:run_once` calls this one separately for exactly that
    reason; see the comment there.
    """
    rows = await db.fetch(
        """
        WITH fresh_ips AS (
            SELECT DISTINCT src_ip FROM raw_events
            WHERE id > $1 AND src_ip IS NOT NULL AND family(src_ip) = 4
              AND ((source = 'sshd' AND action = 'auth_fail')
                OR (source = 'suricata' AND action = 'alert'))
        ),
        fresh AS (
            SELECT DISTINCT set_masklen(src_ip::cidr, $4::int) AS prefix FROM fresh_ips
        )
        SELECT host(f.prefix) || '/' || $4::text AS prefix_cidr,
               count(DISTINCT e.src_ip) AS distinct_addrs,
               count(*) AS events,
               array_agg(DISTINCT host(e.src_ip)) AS sample_ips,
               array_agg(e.id ORDER BY e.id DESC) AS event_ids,
               max(e.geo_country) AS country, max(e.geo_asn) AS asn
        FROM fresh f
        JOIN raw_events e
          ON family(e.src_ip) = 4
         AND set_masklen(e.src_ip::cidr, $4::int) = f.prefix
         AND e.ts > now() - make_interval(hours => $2)
         AND ((e.source = 'sshd' AND e.action = 'auth_fail')
           OR (e.source = 'suricata' AND e.action = 'alert'))
        GROUP BY f.prefix
        HAVING count(DISTINCT e.src_ip) >= $3
        """,
        cursor, CIDR_WINDOW_HOURS, CIDR_MIN_DISTINCT, CIDR_PREFIX_LEN,
    )
    if not rows:
        return []

    allow_rows = await db.fetch(
        """
        SELECT host(cidr) || '/' || masklen(cidr) AS net FROM allowlist
         WHERE confirmed = true AND (expires_at IS NULL OR expires_at > now())
        """
    )
    # Table first, then the operator's config-managed additions — see the
    # module docstring for which of the two has rows on the production host
    # today. Both are addresses/CIDRs as plain strings; _overlaps_any parses
    # either shape (a bare address is treated as a /32).
    protected = [r["net"] for r in allow_rows] + list(cfg.response.extra_allowlist)

    armed = cfg.response.auto_block.allow_cidr_blocks
    return build_specs([dict(r) for r in rows], protected, armed=armed)


# Not consumed by detect/engine.py's generic RULES loop (see cidr_cluster's
# docstring for why) — kept as a named export for anything that wants the
# function without reaching into the module directly.
CIDR_RULES = (cidr_cluster,)
