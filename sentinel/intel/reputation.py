"""Reputation feeds — fetch, mirror, look up, and expire.

Same shape as `kev.py` next to it: read a public list over HTTPS, keep a local
mirror, never let a feed outage or a slow mirror touch the ingest or detect
path. `intel_feeds` (0006) already carries a circuit breaker — `failures`,
`disabled_until`, `last_error`, `last_success`, `entry_count` — this module
drives it, it does not invent a second one. `refresh_all` is called from
`sentinel/services/maintenance_service.py:refresh_intel`, once an hour,
alongside KEV: no new systemd unit, for the same reason KEV needed none — the
maintenance timer already exists, already isolates a network-dependent step
from the ones that are not (see that module's docstring), and a feed that
needs fetching once an hour has no argument for its own daemon.

## Ships with `intel_feeds` EMPTY

No feed is inserted here, none is enabled by default. A tool that pulls
third-party IP lists onto a host without an operator having chosen to is a
supply-chain surface, not a feature — the same reasoning `deploy/install.sh`
already applies to `scan.containers` (§3.14 of the architecture doc). Turning
one on is `INSERT INTO intel_feeds (...) VALUES (...)`, or a future admin
script; neither belongs in a migration, where a wrong or since-moved URL would
sit in the schema looking like it was already vetted.

Three feeds are proposed, one per NON-scanner category actually reachable
without an account or an API key (`kev.py`'s own bar):

  * **Spamhaus DROP** (`drop`) — professional spammer/cybercriminal netblocks,
    hijacked or leased. Plain-text CIDR list, no registration, updated
    continuously. Confidence high (≈90): Spamhaus is conservative about what
    it lists, and false positives there are rare enough to be newsworthy.
  * **blocklist.de** (`botnet`/`compromised`) — hosts its own sensor network
    has directly observed attacking SSH, mail, or web services. Plain-text,
    one IP per line, no registration. Confidence moderate (≈65): individual
    hosts behind CGNAT or shared/dynamic hosting can rotate onto a listed
    address after the attacker has moved on, which the feed's own TTL does not
    fully cover.
  * **Tor Project bulk exit list** (`tor`) — the project's own list of
    current exit relays, i.e. addresses that are Tor exits by definition, not
    by inference. Confidence very high (≈95) for "this address is a Tor
    exit"; it says nothing about intent, which is exactly why `category=tor`
    only ever lowers the local-evidence threshold in `respond/decider.py` and
    never blocks by itself — see that module's docstring for the argument
    that applies to every category here, not just this one.

`category=scanner` is deliberately NOT proposed with a URL here. It has the
INVERSE effect of the three above — it suppresses a block, via
`actors.is_known_scanner` (see `_apply` in `detect/engine.py`) — so a wrong or
stale entry there is a missed real attacker, not a noisy false positive. The
research-scanner lists that exist (Shodan, Censys, Rapid7 Sonar publish their
own ranges so defenders can exclude them) are not a single stable flat-file
URL in the way Spamhaus/blocklist.de/Tor are; picking one well enough to
recommend it live is a decision for whoever turns it on, not for this file.

None of the three above is inserted by this migration or this module — they
are argued here so the operator has the reasoning next to the code that would
fetch them, not so the fetch happens on its own.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from sentinel.db.engine import Database
from sentinel.logging_setup import get_logger

log = get_logger(__name__)

# Refuse a feed larger than this rather than truncate it — same argument as
# `trivy_fs.MAX_FINDINGS`: a truncated list would still upsert `last_success`
# and look like a clean refresh, while quietly covering a fraction of what the
# feed actually publishes. A refusal leaves the PREVIOUS good mirror in place
# (the DELETE+INSERT below never runs) and is visible as `last_error` in
# `intel_feeds`, hence in `/selfcheck` via `check_reputation_feeds`.
MAX_ENTRIES_PER_FEED = 100_000

# Past this age since a feed's last successful fetch, its entries no longer
# describe the internet of today and lookups stop returning them — see
# `lookup` and `snapshot` below. The rows themselves are NOT deleted: they are
# the evidence a stale-feed finding in /selfcheck points at.
MAX_FEED_AGE_H = 48

# Three consecutive failures trip the breaker already described in 0006's
# column comments; this is where that number is enforced.
CIRCUIT_FAILURES = 3
CIRCUIT_COOLDOWN = timedelta(hours=1)

_TIMEOUT_S = 30


def _parse_plain_list(text: str) -> set[str]:
    """One IP or CIDR per line — the format Spamhaus DROP, blocklist.de, and
    the Tor bulk exit list all use. `#`/`;` comment lines and blank lines are
    ignored; a trailing comment after whitespace on a data line is dropped by
    taking only the first token, since some mirrors annotate entries that way
    (`198.51.100.0/24 ; example-note`)."""
    out: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        token = line.split()[0]
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        out.add(str(net))
    return out


_PARSERS = {"plain": _parse_plain_list}


async def _fetch_feed(url: str, fmt: str) -> set[str]:
    parser = _PARSERS.get(fmt)
    if parser is None:
        raise ValueError(f"unknown feed format: {fmt!r}")
    async with httpx.AsyncClient(timeout=_TIMEOUT_S, http2=False) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return parser(resp.text)


async def _record_failure(db: Database, name: str, detail: str) -> None:
    row = await db.fetchrow(
        """
        UPDATE intel_feeds SET last_refresh = now(), failures = failures + 1,
               last_error = $2
         WHERE name = $1
        RETURNING failures
        """,
        name, detail[:500])
    failures = int(row["failures"]) if row else 0
    if failures >= CIRCUIT_FAILURES:
        until = datetime.now(timezone.utc) + CIRCUIT_COOLDOWN
        await db.execute(
            "UPDATE intel_feeds SET disabled_until = $2 WHERE name = $1", name, until)
        log.warning("reputation feed circuit breaker tripped",
                    extra={"feed": name, "failures": failures,
                           "disabled_until": until.isoformat()})
    else:
        log.warning("reputation feed refresh failed",
                    extra={"feed": name, "failures": failures, "detail": detail})


async def _refresh_one(db: Database, feed: dict[str, Any]) -> int:
    """Returns entries written, or -1 on failure/refusal (never raises —
    `refresh_all` must survive one bad feed the same way `maintenance_service`
    survives one bad step)."""
    name = feed["name"]
    try:
        entries = await _fetch_feed(feed["url"], feed["format"])
    except Exception as exc:  # noqa: BLE001 - a feed outage must not fail the pass
        await _record_failure(db, name, str(exc))
        return -1

    if len(entries) > MAX_ENTRIES_PER_FEED:
        await _record_failure(
            db, name,
            f"{len(entries)} intrări peste plafonul de {MAX_ENTRIES_PER_FEED}; "
            f"refuzat, nu trunchiat — mirorul anterior rămâne în vigoare")
        return -1

    parsed: list[tuple[str, str]] = []
    for raw in entries:
        try:
            ipaddress.ip_network(raw)  # already canonical from _parse_plain_list
        except ValueError:
            continue
        parsed.append((name, raw))

    async with db.transaction() as conn:
        await conn.execute("DELETE FROM intel_feed_entries WHERE feed_name = $1", name)
        if parsed:
            await conn.executemany(
                "INSERT INTO intel_feed_entries (feed_name, network) VALUES ($1, $2::cidr)",
                parsed)
        await conn.execute(
            """
            UPDATE intel_feeds
               SET last_refresh = now(), last_success = now(), entry_count = $2,
                   failures = 0, disabled_until = NULL, last_error = NULL
             WHERE name = $1
            """,
            name, len(parsed))
    log.info("reputation feed refreshed", extra={"feed": name, "entries": len(parsed)})
    return len(parsed)


async def refresh_all(db: Database) -> dict[str, int]:
    """Refresh every enabled feed whose circuit breaker is not currently
    tripped. Maps feed name to entries written, or -1 for a feed that failed
    or was refused this pass. Never raises — see `_refresh_one`."""
    feeds = await db.fetch(
        "SELECT name, url, format FROM intel_feeds "
        "WHERE enabled AND (disabled_until IS NULL OR disabled_until <= now())")
    result: dict[str, int] = {}
    for feed in feeds:
        result[feed["name"]] = await _refresh_one(db, dict(feed))
    return result


async def _fresh_feeds(db: Database, *, now: datetime | None = None) -> dict[str, dict[str, Any]]:
    """Every ENABLED feed's metadata, keyed by name, restricted to the ones
    that are FRESH per `_is_fresh`. Freshness is decided here, in Python, not
    in a SQL WHERE clause: `lookup`/`snapshot` below both call this, so the two
    can never disagree about what "fresh" means, and — the actual reason for
    the split — `_is_fresh` becomes a plain function a test can drive with a
    fixed clock, without a live database. A `now() - last_success` comparison
    buried in SQL cannot be exercised that way."""
    now = now or datetime.now(timezone.utc)
    rows = await db.fetch(
        "SELECT name, category, confidence, last_success FROM intel_feeds WHERE enabled")
    return {r["name"]: dict(r) for r in rows if _is_fresh(r["last_success"], now=now)}


def _is_fresh(last_success: datetime | None, *, now: datetime | None = None) -> bool:
    """A feed with no successful fetch yet, or none within `MAX_FEED_AGE_H`,
    no longer describes the internet of today — see the module docstring."""
    if last_success is None:
        return False
    now = now or datetime.now(timezone.utc)
    return (now - last_success) <= timedelta(hours=MAX_FEED_AGE_H)


async def lookup(db: Database, ip: str | None) -> list[str]:
    """Categories of every FRESH, enabled feed whose entries contain `ip` —
    used by `detect/engine.py:_apply` when it upserts an actor, which happens
    once per DETECTION, not per raw event (see `enrich/reputation.py`'s
    docstring for why the per-event ingest path needs a different, in-memory
    answer to the same question instead of calling this)."""
    if not ip:
        return []
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return []
    feeds = await _fresh_feeds(db)
    if not feeds:
        return []
    rows = await db.fetch(
        """
        SELECT DISTINCT feed_name FROM intel_feed_entries
         WHERE feed_name = ANY($1::text[]) AND $2::inet <<= network
        """,
        list(feeds), ip)
    return sorted({feeds[r["feed_name"]]["category"] for r in rows if r["feed_name"] in feeds})


async def snapshot(db: Database) -> list[tuple[str, str, int]]:
    """`(network, category, confidence)` for every entry of every FRESH,
    enabled feed — what `enrich.reputation.ReputationEnricher` loads into
    memory. Kept next to `lookup` so the two never disagree about what
    "fresh" means; both filter through `_fresh_feeds`/`_is_fresh`."""
    feeds = await _fresh_feeds(db)
    if not feeds:
        return []
    rows = await db.fetch(
        "SELECT feed_name, network FROM intel_feed_entries WHERE feed_name = ANY($1::text[])",
        list(feeds))
    return [(str(r["network"]), feeds[r["feed_name"]]["category"],
             int(feeds[r["feed_name"]]["confidence"]))
            for r in rows if r["feed_name"] in feeds]
