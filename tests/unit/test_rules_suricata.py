"""`suricata_alert` carrying the transport protocol into evidence (F3).

Without `evidence["protocols"]`, the decider's `source_is_authentic` guard
(`respond/decider.py`) has no way to tell a UDP/ICMP-only Suricata alert —
trivially spoofable, no handshake, no reply needed — from one backed by a real
TCP exchange. If this silently stopped being populated, that guard would fall
back to "unknown", which the guard treats as unauthenticated (fail-safe) —
so the operator-visible failure of a regression here is every single-hit
severity-1 alert losing its auto-block eligibility, not a wrong block.
"""

from __future__ import annotations

import asyncio

from sentinel.detect.rules import SURICATA_WINDOW_MIN, suricata_alert


def run(c):
    return asyncio.run(c)


class _DB:
    """Answers exactly the one query `suricata_alert` issues, and records the
    SQL text so a test can pin what the query actually asks for — not merely
    that some query with `source = 'suricata'` in it ran."""

    def __init__(self, rows):
        self._rows = rows
        self.last_sql: str | None = None

    async def fetch(self, sql, *args):
        assert "source = 'suricata'" in sql
        self.last_sql = sql
        return self._rows


def _row(**kw):
    base = {
        "ip": "203.0.113.9", "hits": 1, "min_sev": 1,
        "sigs": ["ET SCAN Suspicious inbound"], "protocols": ["UDP"],
        "event_ids": [1], "dport": 53,
    }
    base.update(kw)
    return base


def test_evidence_carries_the_distinct_protocols_seen():
    db = _DB([_row(protocols=["UDP"])])
    specs = run(suricata_alert(db, 0))
    assert len(specs) == 1
    assert specs[0].evidence["protocols"] == ["UDP"]


def test_query_aggregates_distinct_protocols_aliased_as_protocols():
    """Pins the SQL itself, not just the stub's canned row: `_DB.fetch` above
    returns whatever `_row()` says regardless of what the query actually
    selects, so a fixture-only assertion stays green even if
    `array_agg(DISTINCT e.proto) ... AS protocols` were dropped from the real
    query in `detect/rules.py` — the decider's `source_is_authentic` guard
    would then read `evidence.get("protocols")` as always absent and refuse
    every single-hit severity-1 alert (see the module docstring above)."""
    db = _DB([_row()])
    run(suricata_alert(db, 0))
    assert db.last_sql is not None, "the suricata_alert query was never issued"
    assert "array_agg(DISTINCT e.proto)" in db.last_sql
    assert "AS protocols" in db.last_sql


def test_evidence_carries_every_distinct_protocol_when_mixed():
    """A source with both a UDP and a TCP alert in the window must show BOTH
    — collapsing to one, or dropping the TCP one, would make a genuinely
    corroborated source look spoofable-only to the decider."""
    db = _DB([_row(protocols=["TCP", "UDP"])])
    specs = run(suricata_alert(db, 0))
    assert set(specs[0].evidence["protocols"]) == {"TCP", "UDP"}


def test_evidence_protocols_is_empty_list_not_none_when_column_is_null():
    """`array_agg(...) FILTER (...)` returns SQL NULL, not an empty array, when
    every row was filtered out. `None` would make the decider guard's `.get`
    logic error-prone (falsy checks conflating "no protocols" with "key
    absent"); an explicit `[]` is unambiguous and matches every other list
    field this rule already returns (`sigs`, `event_ids`)."""
    db = _DB([_row(protocols=None)])
    specs = run(suricata_alert(db, 0))
    assert specs[0].evidence["protocols"] == []


def test_evidence_carries_the_window_used_to_group_hits():
    """The decider needs the SAME window the rule used to look for TCP
    corroboration — a mismatched, hard-coded window in two places is exactly
    the kind of drift that silently makes a guard too strict or too loose."""
    db = _DB([_row()])
    specs = run(suricata_alert(db, 0))
    assert specs[0].evidence["window_min"] == SURICATA_WINDOW_MIN
