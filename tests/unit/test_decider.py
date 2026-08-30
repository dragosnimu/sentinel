"""The auto-block decider is the one place a detection becomes a firewall rule.
Its guards are the difference between a security tool and a self-inflicted
outage, so each one is pinned here. No real DB or executor: a stub answers the
few queries a decision needs, and enforcement is only ever reached in the armed
paths that these tests drive deliberately.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from sentinel.respond import decider


class _StubDB:
    """Answers exactly the reads the decider makes. `flags` is what actor_flags
    resolves to; counters keep the caps from tripping unless a test asks."""

    def __init__(self, *, flags=None, active_count=0, auto_recent=0, is_active=False,
                 active_cidrs=0):
        self.flags = flags or {"is_allowlisted": False, "is_known_scanner": False,
                                "reputation": []}
        self.active_count = active_count
        self.auto_recent = auto_recent
        self._is_active = is_active
        self.active_cidrs = active_cidrs
        self.updates: list[tuple] = []

    async def fetchrow(self, sql, *args):
        if "is_allowlisted, is_known_scanner" in sql:
            return self.flags
        return None

    async def fetchval(self, sql, *args):
        # Checked before the generic "WHERE active" branch below: count_active
        # and count_active_cidrs both contain that substring, and only the
        # latter also mentions masklen.
        if "masklen(ip)" in sql:
            return self.active_cidrs
        if "WHERE active" in sql and "created_by" not in sql:
            return self.active_count
        if "created_by LIKE 'auto:%'" in sql:
            return self.auto_recent
        if "AND active LIMIT 1" in sql:
            return 1 if self._is_active else None
        return 0

    async def execute(self, sql, *args):
        self.updates.append((sql, args))
        return "UPDATE 1"


def _cfg(*, enabled, min_severity="high", max_per_minute=60, max_elements=20000,
         skip_known_scanners=True, allow_cidr_blocks=False, default_ttl_s=86400,
         max_active_cidrs=20):
    return SimpleNamespace(response=SimpleNamespace(auto_block=SimpleNamespace(
        enabled=enabled, min_severity=min_severity, max_per_minute=max_per_minute,
        max_elements=max_elements, skip_known_scanners=skip_known_scanners,
        allow_cidr_blocks=allow_cidr_blocks, default_ttl_s=default_ttl_s,
        max_active_cidrs=max_active_cidrs)))


def _spec(actor_key="203.0.113.53", severity="high"):
    return SimpleNamespace(
        actor_key=actor_key, src_ip=actor_key, rule_id="auth.ssh_bruteforce",
        severity=severity)


def _decide(db, cfg, spec):
    return asyncio.run(decider._decide(db, cfg, spec, 1))


def test_is_ip():
    assert decider._is_ip("203.0.113.53")
    assert decider._is_ip("2001:db8::1")
    assert not decider._is_ip("campaign:abc")
    assert not decider._is_ip(None)


def test_is_ip_accepts_an_aligned_prefix_but_not_a_sloppy_one():
    """`_is_ip` must recognise a properly masked /24 — otherwise every CIDR
    proposal dies at guard 1 and the CIDR guard at guard 3 is unreachable code,
    which is exactly the bug this change fixes (verified below)."""
    assert decider._is_ip("65.49.1.0/24")
    assert not decider._is_ip("65.49.1.5/24")  # host bits set past the mask


def test_non_ip_actor_is_observe_only():
    assert _decide(_StubDB(), _cfg(enabled=True), _spec(actor_key="campaign:abc")) == "observed"


def test_below_severity_gate_never_arms():
    # medium < high gate: observe even when armed.
    assert _decide(_StubDB(), _cfg(enabled=True), _spec(severity="medium")) == "observed"


def test_disabled_is_always_observe():
    # A high-sev IP with every guard clear still only observes while disabled.
    assert _decide(_StubDB(), _cfg(enabled=False), _spec()) == "observed"


def test_allowlisted_actor_skipped_when_armed():
    db = _StubDB(flags={"is_allowlisted": True, "is_known_scanner": False,
                         "reputation": []})
    assert _decide(db, _cfg(enabled=True), _spec()) == "skipped:allowlisted"


def test_known_scanner_skipped_when_armed():
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": True,
                         "reputation": []})
    assert _decide(db, _cfg(enabled=True), _spec()) == "skipped:known_scanner"


def test_known_scanner_not_skipped_if_option_off():
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": True,
                         "reputation": []}, is_active=True)
    # skip_known_scanners off -> passes that guard; is_active short-circuits to
    # "blocked" without touching the executor.
    assert _decide(db, _cfg(enabled=True, skip_known_scanners=False), _spec()) == "blocked"


def test_max_elements_cap_when_armed():
    db = _StubDB(active_count=20000)
    assert _decide(db, _cfg(enabled=True, max_elements=20000), _spec()) == "skipped:max_elements"


def test_rate_cap_when_armed():
    db = _StubDB(auto_recent=60)
    assert _decide(db, _cfg(enabled=True, max_per_minute=60), _spec()) == "skipped:rate_cap"


def test_already_active_is_not_reblocked():
    db = _StubDB(is_active=True)
    assert _decide(db, _cfg(enabled=True), _spec()) == "blocked"


# --- CIDR-specific guards (function 02) -------------------------------------

def test_cidr_default_config_is_observed_not_blocked():
    """The shipped default (allow_cidr_blocks=false, ships disabled) must turn
    a /24 proposal into 'observed', never 'blocked' — this is the whole point
    of shipping the detector before the operator arms it."""
    db = _StubDB()
    assert _decide(db, _cfg(enabled=False), _spec(actor_key="65.49.1.0/24")) == "observed"


def test_cidr_guard_is_reached_and_stops_the_block_when_armed():
    """With auto-block armed but allow_cidr_blocks still off, a /24 must be
    stopped by name at guard 3 ('skipped:cidr_not_allowed'), not merely land on
    'observed' for the unrelated reason that guard 1 failed to recognise it as
    an address. Before the guard-1 fix this returned 'observed' regardless of
    allow_cidr_blocks, silently making guard 3 dead code."""
    db = _StubDB()
    cfg = _cfg(enabled=True, allow_cidr_blocks=False)
    assert _decide(db, cfg, _spec(actor_key="65.49.1.0/24")) == "skipped:cidr_not_allowed"


def test_cidr_without_a_ttl_is_refused_when_armed():
    """0002's schema comment: only an operator creates a permanent block, and
    auto-block never does — a range even less so. A misconfigured
    default_ttl_s of 0 must refuse the range rather than place a permanent
    one nobody decided on."""
    db = _StubDB()
    cfg = _cfg(enabled=True, allow_cidr_blocks=True, default_ttl_s=0)
    assert _decide(db, cfg, _spec(actor_key="65.49.1.0/24")) == "skipped:cidr_requires_ttl"


def test_cidr_without_a_ttl_is_observed_when_disabled():
    db = _StubDB()
    cfg = _cfg(enabled=False, allow_cidr_blocks=True, default_ttl_s=0)
    assert _decide(db, cfg, _spec(actor_key="65.49.1.0/24")) == "observed"


def test_max_active_cidrs_cap_when_armed():
    """A separate, tighter ceiling than max_elements: a handful of /24s covers
    thousands of addresses without the raw element count coming close to
    max_elements, so this cap needs its own trip wire."""
    db = _StubDB(active_cidrs=5)
    cfg = _cfg(enabled=True, allow_cidr_blocks=True, max_active_cidrs=5)
    assert _decide(db, cfg, _spec(actor_key="65.49.1.0/24")) == "skipped:max_active_cidrs"


def test_max_active_cidrs_cap_does_not_throttle_single_ip_blocks():
    """Falsifies the cap the other way: it must only ever gate CIDR actor
    keys. A cap that also counted against ordinary /32 auto-blocks would
    quietly stop unrelated single-IP blocking once a few ranges were active."""
    db = _StubDB(active_cidrs=999, is_active=True)
    cfg = _cfg(enabled=True, max_active_cidrs=1)
    assert _decide(db, cfg, _spec()) == "blocked"  # plain IP, unaffected


# --- Reputation moves the threshold, never the decision (function 03) ------

def test_lower_by_one_shifts_down_one_tier():
    assert decider._lower_by_one("high") == "medium"
    assert decider._lower_by_one("medium") == "low"


def test_lower_by_one_never_drops_below_low():
    """Even the maximally hostile address must still clear SOME local
    threshold — a floor of 'info' would mean any single event from a
    hostile-tagged address, however trivial, could arm a block."""
    assert decider._lower_by_one("low") == "low"


def test_reputation_alone_without_enough_local_evidence_stays_observed():
    """A hostile-feed address with a detection too weak even for the LOWERED
    gate must not be armed — reputation shortens the local-evidence
    requirement, it never waives it. If this failed, a single bad feed entry
    could arm a block with essentially no evidence from this host at all."""
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": False,
                         "reputation": ["botnet"]})
    # min_severity="high" -> lowered to "medium" by the botnet tag; "low" is
    # still below that lowered floor, so this must stay observed.
    assert _decide(db, _cfg(enabled=True, min_severity="high"),
                   _spec(severity="low")) == "observed"


def test_reputation_lowers_the_threshold_and_arms_one_tier_earlier():
    """The concrete case CLAUDE.md asks for: the same local evidence
    (`medium`) that is ordinarily below the `high` gate must arm a block once
    the address is tagged with a hostile reputation category. `is_active=True`
    short-circuits to 'blocked' without touching the executor, same as the
    other already-past-guard-5 tests in this file."""
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": False,
                         "reputation": ["botnet"]}, is_active=True)
    assert _decide(db, _cfg(enabled=True, min_severity="high"),
                   _spec(severity="medium")) == "blocked"


def test_without_reputation_the_same_medium_severity_stays_observed():
    """Falsifies the lowering the other way: WITHOUT a hostile tag, the same
    `medium` detection against the same `high` gate must NOT arm — otherwise
    the test above would be proving nothing about reputation at all, just
    that `medium` always arms."""
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": False,
                         "reputation": []})
    assert _decide(db, _cfg(enabled=True, min_severity="high"),
                   _spec(severity="medium")) == "observed"


def test_scanner_category_does_not_lower_the_threshold():
    """`scanner` has the OPPOSITE effect (protects via `is_known_scanner`,
    guard 5) and must never also count as a hostile category at guard 2 — an
    address tagged only `scanner` (no is_known_scanner flag set, an
    inconsistency that must not matter here) must not get an earlier gate."""
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": False,
                         "reputation": ["scanner"]})
    assert _decide(db, _cfg(enabled=True, min_severity="high"),
                   _spec(severity="medium")) == "observed"


def test_allowlisted_wins_over_a_hostile_reputation_tag():
    """CLAUDE.md's exact case: an address on `response.extra_allowlist`
    (reflected here as `actors.is_allowlisted`) that is ALSO on a hostile feed
    must never be touched — guard 5's allowlist check runs unconditionally
    after guard 2 and does not care whether reputation lowered the severity
    floor. Severity is `high` here — enough to arm WITHOUT any lowering — so
    a failure of this guard would prove reputation can override an explicit
    allowlist, not merely fail to help it."""
    db = _StubDB(flags={"is_allowlisted": True, "is_known_scanner": False,
                         "reputation": ["botnet"]})
    assert _decide(db, _cfg(enabled=True, min_severity="high"),
                   _spec(severity="high")) == "skipped:allowlisted"
