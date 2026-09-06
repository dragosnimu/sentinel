"""F04's novelty signal is a new `Dimension` in the existing behaviour-profile
engine (`predict/behaviour.py`), not a new detector. `detect/novelty.py`'s
`unseen_before` and `composition_shift` already iterate `bh.DIMENSIONS`
generically — if this dimension isn't registered there with the right
source/action/key, the "a destination never contacted before" signal the
whole feature is built around silently never fires, with no error to say so.
"""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

from sentinel.predict import behaviour as bh


def test_outbound_dst_dimension_is_registered():
    dims = {d.name: d for d in bh.DIMENSIONS}
    assert "outbound_dst" in dims
    dim = dims["outbound_dst"]
    assert dim.source == "conntrack"
    assert dim.action == "connect"


def test_outbound_dst_key_is_the_destination_address():
    dim = bh.BY_NAME["outbound_dst"]
    row = {"dst_ip": "93.184.216.34"}
    assert dim.key_of(row) == "93.184.216.34"


def test_outbound_dst_key_is_none_without_a_destination():
    # A row from a different source/action pairing would not carry dst_ip at
    # all; the shared `_s` helper must treat that as "no key", not crash the
    # observe() loop for every other dimension sharing the same query.
    dim = bh.BY_NAME["outbound_dst"]
    assert dim.key_of({"dst_ip": None}) is None


def test_outbound_dst_is_not_high_severity_on_the_default_three_day_warmup():
    """Locks in the 6 Sep 2026 measurement in `collectors/conntrack.py`'s
    module docstring: on the production host, `outbound_dst` was still
    reporting new destinations (671, 355, 59, 19, 7, 4/day across its first
    six days) two days after it went "warm" under the shared 3-day default,
    and had already raised 16 unactionable HIGH incidents by then. A silent
    revert of either field back to the shared defaults (e.g. someone
    "simplifying" this Dimension to match the others) would reproduce
    exactly that — this test is what makes such a revert fail loudly instead
    of waiting for the next flood of bare-IP HIGH alerts to notice."""
    dim = bh.BY_NAME["outbound_dst"]
    assert dim.severity == "medium"
    # Pinned to the exact measured value, not `> 3`: a mutation that lowered
    # this to 4 (still "> 3", still wrong — day six of the measurement was
    # still nonzero) left this assertion green before this fix, which is
    # exactly the kind of silent regression `warmup_days` existing at all is
    # supposed to prevent.
    assert dim.warmup_days == 14, (
        "14 is RATE_LOOKBACK_HOURS/24 from detect/novelty.py, the same "
        "'enough history' constant this rule family already trusts — "
        "any other value needs its own measurement, not a guess")


# ---------------------------------------------------------------------------
# observe(): the decision, not the source text
# ---------------------------------------------------------------------------
#
# A previous version of this test did `assert "dst_ip" in inspect.getsource(
# bh.observe)` — text presence, not behaviour. Reproduced during review: with
# `dst_ip` removed from the real SELECT and the bare word left behind in a SQL
# comment on the same line, that assertion still passed while `key_of` raised
# `KeyError: 'dst_ip'` on every real row — and because `observe()` has no
# per-dimension try/except, that exception propagates out of the WHOLE call,
# so all seven dimensions stop learning on one bad edit, not just this one.
#
# `_FakeDB` below does not just hand back canned rows: it parses the actual
# column list out of the SQL text `observe()` sends and returns ONLY those
# columns from a full ground-truth record. Remove `dst_ip` from the real
# query — even leaving the word in a comment between SELECT and FROM — and
# the returned row will not have a `dst_ip` key, `key_of` raises for real, and
# this test fails with the same exception `_learn()`'s try/except would log in
# production.
_SELECT_COLUMNS = re.compile(r"SELECT\s+(.*?)\s+FROM", re.IGNORECASE | re.DOTALL)


class _FakeDB:
    """Just enough of `Database` to drive `observe()` for ONE dimension,
    reflecting back only the columns the real query text actually asks for.
    """

    def __init__(self, rows_by_source_action: dict[tuple[str, str], list[dict]]):
        self._rows_by_source_action = rows_by_source_action
        self._seen_keys: set[tuple[str, str]] = set()

    async def fetch(self, sql, *args):
        cursor, source, action = args
        full_rows = self._rows_by_source_action.get((source, action), [])
        m = _SELECT_COLUMNS.search(sql)
        columns = [c.strip() for c in m.group(1).split(",")] if m else []
        return [{c: r.get(c) for c in columns} for r in full_rows]

    async def fetchval(self, sql, *args):
        if "behaviour_profiles" in sql:
            dimension, key, _n = args
            seen = (dimension, key)
            is_new = seen not in self._seen_keys
            self._seen_keys.add(seen)
            return is_new
        return None

    async def execute(self, sql, *args):
        return None

    async def fetchrow(self, sql, *args):
        return None


def test_observe_learns_a_real_outbound_dst_row():
    """The behavioural guarantee `test_observe_query_selects_dst_ip` only
    pretended to check: a real row with a destination address is learned as
    ONE new key for the `outbound_dst` dimension."""
    row = {"id": 1, "username": None, "process": None, "geo_asn": None,
           "geo_country": None, "dst_ip": "93.184.216.34",
           "ts": datetime.now(timezone.utc)}
    db = _FakeDB({("conntrack", "connect"): [row]})

    result = asyncio.run(bh.observe(db, cursor=0))

    assert result.get("outbound_dst") == {
        "observations": 1, "new_keys": 1, "distinct": 1}

