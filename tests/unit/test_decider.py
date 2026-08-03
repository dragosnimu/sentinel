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

    def __init__(self, *, flags=None, active_count=0, auto_recent=0, is_active=False):
        self.flags = flags or {"is_allowlisted": False, "is_known_scanner": False}
        self.active_count = active_count
        self.auto_recent = auto_recent
        self._is_active = is_active
        self.updates: list[tuple] = []

    async def fetchrow(self, sql, *args):
        if "is_allowlisted, is_known_scanner" in sql:
            return self.flags
        return None

    async def fetchval(self, sql, *args):
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
         skip_known_scanners=True, allow_cidr_blocks=False, default_ttl_s=86400):
    return SimpleNamespace(response=SimpleNamespace(auto_block=SimpleNamespace(
        enabled=enabled, min_severity=min_severity, max_per_minute=max_per_minute,
        max_elements=max_elements, skip_known_scanners=skip_known_scanners,
        allow_cidr_blocks=allow_cidr_blocks, default_ttl_s=default_ttl_s)))


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


def test_non_ip_actor_is_observe_only():
    assert _decide(_StubDB(), _cfg(enabled=True), _spec(actor_key="campaign:abc")) == "observed"


def test_below_severity_gate_never_arms():
    # medium < high gate: observe even when armed.
    assert _decide(_StubDB(), _cfg(enabled=True), _spec(severity="medium")) == "observed"


def test_disabled_is_always_observe():
    # A high-sev IP with every guard clear still only observes while disabled.
    assert _decide(_StubDB(), _cfg(enabled=False), _spec()) == "observed"


def test_allowlisted_actor_skipped_when_armed():
    db = _StubDB(flags={"is_allowlisted": True, "is_known_scanner": False})
    assert _decide(db, _cfg(enabled=True), _spec()) == "skipped:allowlisted"


def test_known_scanner_skipped_when_armed():
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": True})
    assert _decide(db, _cfg(enabled=True), _spec()) == "skipped:known_scanner"


def test_known_scanner_not_skipped_if_option_off():
    db = _StubDB(flags={"is_allowlisted": False, "is_known_scanner": True}, is_active=True)
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
