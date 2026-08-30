"""`check_reputation_feeds`: the circuit breaker and freshness state written by
`sentinel/intel/reputation.py` must reach `/selfcheck`, not just sit in
`intel_feeds.last_error` where nobody reads it — see that check's docstring
for the CLAUDE.md failure it exists to close.
"""

from __future__ import annotations

import asyncio

from sentinel.intel.reputation import MAX_FEED_AGE_H
from sentinel.selfcheck import checks


def run(c):
    return asyncio.run(c)


class _DB:
    def __init__(self, rows):
        self._rows = rows

    async def fetch(self, sql, *a):
        return self._rows


def _row(**over):
    base = {
        "name": "example-feed", "category": "botnet", "confidence": 70,
        "entry_count": 100, "failures": 0, "last_error": None,
        "last_refresh": None, "last_success": "recent", "disabled_until": None,
        "circuit_tripped": False, "success_age_s": 3600.0,
    }
    base.update(over)
    return base


def test_no_enabled_feeds_is_ok_not_unknown():
    """The shipped default — `intel_feeds` empty or every row disabled — is a
    DECISION the operator made, not a scan that never ran; it must read `ok`,
    the same distinction `check_last_scan` draws for `scan.enabled: false`."""
    results = run(checks.check_reputation_feeds(_DB([])))
    assert len(results) == 1
    assert results[0].status == "ok"
    assert results[0].key == "intel:feeds"


def test_circuit_breaker_tripped_is_degraded_and_named():
    """A feed whose circuit breaker has fired must be visible here, under its
    own key — the exact gap the check's docstring names: a field written to
    `intel_feeds` that nobody ever reads is the CLAUDE.md failure pattern."""
    results = run(checks.check_reputation_feeds(_DB([
        _row(name="dead-feed", circuit_tripped=True, failures=3,
             last_error="connection refused")])))
    assert len(results) == 1
    r = results[0]
    assert r.key == "intel:feed:dead-feed"
    assert r.status == "degraded"
    assert "3" in r.detail


def test_never_succeeded_is_degraded():
    results = run(checks.check_reputation_feeds(_DB([
        _row(name="new-feed", last_success=None, failures=1)])))
    assert results[0].status == "degraded"
    assert "niciodată" in results[0].title


def test_stale_feed_past_the_freshness_threshold_is_degraded():
    """A feed last refreshed more than MAX_FEED_AGE_H ago must be flagged —
    and the message must say its category no longer has effect, or an
    operator reading 'degraded' with no further explanation would not know
    this is exactly the freshness guard CLAUDE.md's task required."""
    stale_seconds = (MAX_FEED_AGE_H + 1) * 3600
    results = run(checks.check_reputation_feeds(_DB([
        _row(name="stale-feed", success_age_s=stale_seconds)])))
    r = results[0]
    assert r.status == "degraded"
    assert "nu mai are efect" in r.detail


def test_fresh_healthy_feed_is_ok_with_facts():
    """Falsifies the three degraded cases above: a feed within the freshness
    window, never tripped, with a successful fetch, must read `ok` and carry
    the entry count and category an operator would want to see."""
    results = run(checks.check_reputation_feeds(_DB([
        _row(name="good-feed", entry_count=250, category="drop", confidence=90,
             success_age_s=3600.0)])))
    r = results[0]
    assert r.status == "ok"
    assert r.facts["entries"] == 250
    assert r.facts["category"] == "drop"


def test_each_enabled_feed_gets_its_own_key():
    """One feed's failure must not obscure another's health — a shared key
    would let a degraded feed hide behind a healthy one's 'ok', or vice versa."""
    results = run(checks.check_reputation_feeds(_DB([
        _row(name="feed-a", circuit_tripped=True, failures=3),
        _row(name="feed-b", success_age_s=100.0),
    ])))
    keys = {r.key: r.status for r in results}
    assert keys == {"intel:feed:feed-a": "degraded", "intel:feed:feed-b": "ok"}
