"""The /24 proposer (sentinel/detect/cidr.py) is the only place that ever asks
the auto-block decider to consider a range instead of one address. Its guards
are pure functions precisely so a mistake in any of them shows up here, not
three weeks later as an operator's own subnet on the blocklist page.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from sentinel.detect.cidr import (
    CIDR_MIN_DISTINCT,
    CIDR_WINDOW_HOURS,
    _overlaps_any,
    _severity_for,
    build_specs,
    cidr_cluster,
)


def _row(prefix="65.49.1.0/24", distinct=202, events=5000, event_ids=None, sample_ips=None):
    return {
        "prefix_cidr": prefix,
        "distinct_addrs": distinct,
        "events": events,
        "sample_ips": sample_ips or [],
        "event_ids": event_ids or [1, 2, 3],
        "country": None,
        "asn": None,
    }


def _cfg(*, allow_cidr_blocks=False, extra_allowlist=None):
    return SimpleNamespace(response=SimpleNamespace(
        extra_allowlist=extra_allowlist or [],
        auto_block=SimpleNamespace(allow_cidr_blocks=allow_cidr_blocks),
    ))


class _FakeDB:
    """Answers `fetch` for cidr_cluster: the aggregation query returns `rows`
    unconditionally, the allowlist-table query returns `allow_rows` (empty by
    default — the production table has 0 rows, and that must not be the thing
    a test relies on to prove the guard works)."""

    def __init__(self, rows, allow_rows=None):
        self._rows = rows
        self._allow_rows = allow_rows if allow_rows is not None else []

    async def fetch(self, sql, *args):
        if "FROM allowlist" in sql:
            return self._allow_rows
        return self._rows


def _run_cidr_cluster(db, cfg):
    return asyncio.run(cidr_cluster(db, 0, cfg))


# --- severity thresholds -----------------------------------------------------

def test_severity_floor_matches_the_measured_threshold():
    """The 24h window measured on the host has nothing below 3 distinct
    addresses worth an incident; below the floor this must stay silent, or a
    single opportunistic scanner pair would spam a proposal every day."""
    assert _severity_for(CIDR_MIN_DISTINCT - 1, armed=True) is None
    assert _severity_for(CIDR_MIN_DISTINCT, armed=True) == "high"
    assert _severity_for(202, armed=True) == "critical"


# --- severity follows actionability, in both directions ---------------------

def test_severity_is_medium_and_below_telegram_threshold_when_not_armed():
    """allow_cidr_blocks=false (the value on this host today) means every
    proposal comes out 'observed' with no button — telegram/bot.py's
    _incident_block_kb builds no keyboard for a CIDR actor_key. Pushing that
    as 'high' would have added ~6 unactionable alerts/day to the 23.3/day of
    actionable ones already measured on the host. Observe mode must floor at
    'medium', which sits below this host's telegram.min_severity ('high')."""
    assert _severity_for(CIDR_MIN_DISTINCT, armed=False) == "medium"
    assert _severity_for(202, armed=False) == "medium"  # scale does not matter unarmed
    assert _severity_for(CIDR_MIN_DISTINCT - 1, armed=False) is None  # floor still applies


def test_severity_returns_to_the_armed_tiers_once_cidr_blocking_is_armed():
    """Falsifies the previous test the other way: the moment allow_cidr_blocks
    flips true, the same cluster IS an actionable decision again, and severity
    must follow it back up — this is a switch, not a permanent downgrade."""
    assert _severity_for(CIDR_MIN_DISTINCT, armed=True) == "high"
    assert _severity_for(25, armed=True) == "critical"


def test_build_specs_threads_armed_through_to_severity():
    unarmed = build_specs([_row(distinct=202)], protected=[], armed=False)
    armed = build_specs([_row(distinct=202)], protected=[], armed=True)
    assert unarmed[0].severity == "medium"
    assert armed[0].severity == "critical"


# --- the operator's own most aggressive measured prefix ----------------------

def test_202_distinct_addresses_is_proposed():
    """65.49.1.0/24 (202 distinct hostile addresses, the most aggressive
    prefix measured) must produce a proposal — a detector that misses its own
    best example is not a detector."""
    specs = build_specs([_row(prefix="65.49.1.0/24", distinct=202)], protected=[], armed=True)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.actor_key == "65.49.1.0/24"
    assert spec.severity == "critical"
    assert spec.src_ip is None
    assert "/" in spec.fingerprint


# --- density, not volume -----------------------------------------------------

def test_single_address_with_huge_event_count_is_not_proposed():
    """A prefix with ONE hostile address and 30 000 events is a loud host, not
    a coordinated /24 — this rule counts distinct addresses, never events. A
    detector that read `events` instead would have proposed blocking the
    entire /24 around every noisy scanner on the internet."""
    specs = build_specs(
        [_row(prefix="198.51.100.0/24", distinct=1, events=30_000)], protected=[], armed=True)
    assert specs == []


# --- allowlist covers the whole interval, not one address in it -------------

def test_prefix_containing_an_allowlisted_address_is_never_proposed():
    """A protected address anywhere inside the /24 must veto the whole
    proposal, however many hostile addresses the rest of the range has —
    checking only the reporting address (as `is_allowlisted` does for a single
    IP) would still fire on an operator's own subnet the moment three OTHER
    hosts in it misbehaved."""
    specs = build_specs(
        [_row(prefix="198.51.100.0/24", distinct=50, events=5000)],
        protected=["198.51.100.7/32"], armed=True,
    )
    assert specs == []


def test_prefix_with_no_allowlist_overlap_is_unaffected():
    """Falsifies the allowlist guard the other way: an unrelated allowlist
    entry must not suppress a real proposal — a guard that matches everything
    would pass the previous test for the wrong reason."""
    specs = build_specs(
        [_row(prefix="198.51.100.0/24", distinct=50, events=5000)],
        protected=["203.0.113.0/24"], armed=True,
    )
    assert len(specs) == 1


def test_wider_allowlisted_network_also_vetoes():
    """`overlaps()` must catch containment in both directions: an allowlisted
    /20 that swallows the candidate /24 is exactly as protective as a single
    address inside it."""
    specs = build_specs(
        [_row(prefix="198.51.100.0/24", distinct=50)],
        protected=["198.51.96.0/20"], armed=True,
    )
    assert specs == []


# --- never wider than /24 ----------------------------------------------------

def test_a_wider_than_24_candidate_is_refused_even_if_it_qualifies():
    """Defense in depth against a future bug in the query that masks wider
    than /24: a /16 covers 65 536 addresses on the strength of a few dozen —
    an outage waiting to be armed, not a defense — so build_specs refuses it
    independently of what the SQL is supposed to have already enforced."""
    specs = build_specs([_row(prefix="65.49.0.0/16", distinct=202)], protected=[], armed=True)
    assert specs == []


def test_an_unaligned_candidate_is_refused():
    """A network string with host bits set (e.g. a masking bug that kept the
    original host octet) is not a valid /24 and must not become a firewall
    rule for the wrong range."""
    specs = build_specs([_row(prefix="65.49.1.5/24", distinct=202)], protected=[], armed=True)
    assert specs == []


# --- _overlaps_any in isolation ----------------------------------------------

def test_overlaps_any_ignores_unparsable_allowlist_rows():
    """A garbled allowlist row must not crash the whole detection pass — it is
    skipped, not fatal, the same posture as a rule that fails elsewhere in the
    engine."""
    import ipaddress

    candidate = ipaddress.ip_network("65.49.1.0/24")
    assert _overlaps_any(candidate, ["not-a-network", "65.49.1.128/25"]) is True
    assert _overlaps_any(candidate, ["not-a-network"]) is False


# --- cidr_cluster: extra_allowlist protects even with an empty allowlist table

def test_extra_allowlist_protects_a_prefix_even_when_the_allowlist_table_is_empty():
    """Measured on the production host: the `allowlist` table has 0 rows, 0
    confirmed, and nothing ever writes to it — but `response.extra_allowlist`
    holds the operator's own address, and it falls inside one of the two
    prefixes this rule's own threshold data shows carrying exactly one hostile
    address. If cidr_cluster only ever consulted the empty table, this
    address would be completely unprotected the day a /24 around it happens
    to clear the threshold for real."""
    db = _FakeDB(
        rows=[_row(prefix="203.0.113.0/24", distinct=50, events=1000)],
        allow_rows=[],  # the table really is empty on the host
    )
    cfg = _cfg(extra_allowlist=["203.0.113.9"])
    specs = _run_cidr_cluster(db, cfg)
    assert specs == []


def test_extra_allowlist_does_not_suppress_an_unrelated_prefix():
    """Falsifies the previous test the other way: an extra_allowlist entry
    for a DIFFERENT network must not blanket-suppress every proposal — a
    guard that matched everything would pass the previous test by accident."""
    db = _FakeDB(rows=[_row(prefix="203.0.113.0/24", distinct=50, events=1000)], allow_rows=[])
    cfg = _cfg(extra_allowlist=["198.51.100.9"])
    specs = _run_cidr_cluster(db, cfg)
    assert len(specs) == 1


def test_cidr_cluster_severity_follows_allow_cidr_blocks_in_both_directions():
    """End-to-end version of the severity toggle: cidr_cluster must read
    cfg.response.auto_block.allow_cidr_blocks and produce 'medium' while it
    is false, 'high' (or above) once it flips true — same rows, same DB."""
    db = _FakeDB(rows=[_row(prefix="203.0.113.0/24", distinct=50, events=1000)], allow_rows=[])

    unarmed = _run_cidr_cluster(db, _cfg(allow_cidr_blocks=False))
    assert len(unarmed) == 1
    assert unarmed[0].severity == "medium"

    armed = _run_cidr_cluster(db, _cfg(allow_cidr_blocks=True))
    assert len(armed) == 1
    assert armed[0].severity in ("high", "critical")


# --- wiring: cidr_cluster is deliberately outside the generic RULES loop ----

def test_cidr_cluster_is_not_in_the_generic_rules_tuple():
    """cidr_cluster needs cfg, which the uniform rule(db, cursor) protocol in
    detect/engine.py's main loop cannot supply. If it ever ends up back in
    RULES too, the loop's `except Exception` swallows the resulting TypeError,
    logs once, and the rule quietly never runs from that path — a silent
    failure of exactly the kind this repository keeps finding after the fact."""
    from sentinel.detect.rules import RULES

    assert cidr_cluster not in RULES


def test_engine_calls_cidr_cluster_with_cfg_before_the_cursor_advances():
    """cfg.response.extra_allowlist only reaches the allowlist guard if
    detect/engine.py actually passes cfg through — this pins the call so a
    future refactor cannot quietly drop the third argument back to the
    two-argument shape every other rule uses."""
    import inspect

    from sentinel.detect import engine

    src = inspect.getsource(engine.run_once)
    assert "cidr_cluster(db, cursor, cfg)" in src
    assert src.index("cidr_cluster(db, cursor, cfg)") < src.index("set_detect_cursor")
