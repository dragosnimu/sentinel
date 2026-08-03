"""Closing an incident, and the sort control.

The sort value arrives from a query string and is interpolated into ORDER BY —
the one place in this codebase where a request parameter reaches SQL text. It is
whitelisted, and that whitelist is pinned here.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.db.repo import incidents as inc

NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)


class _StubDB:
    def __init__(self, rows=None):
        self.sql: list[str] = []
        self.args: list[tuple] = []
        self._rows = rows or []

    async def execute(self, sql, *a):
        self.sql.append(sql); self.args.append(a); return "UPDATE 1"

    async def fetch(self, sql, *a):
        self.sql.append(sql); self.args.append(a); return self._rows

    async def fetchval(self, sql, *a):
        return 0


def run(c):
    return asyncio.run(c)


# --- sort whitelist ---------------------------------------------------------
def test_sort_default_is_newest_first():
    assert inc.DEFAULT_SORT == "recent"
    assert inc.SORTS["recent"].startswith("last_detection_at DESC")


def test_unknown_sort_falls_back_and_never_reaches_sql():
    db = _StubDB()
    evil = "id; DROP TABLE incidents --"
    run(inc.list_incidents(db, sort=evil))
    joined = " ".join(db.sql)
    assert "DROP TABLE" not in joined
    assert "last_detection_at DESC" in joined      # fell back to the default


def test_every_offered_sort_is_a_known_column_expression():
    # A future edit must not slip a raw string in: each value has to reference a
    # real column, never a parameter or a function of user input.
    for expr in inc.SORTS.values():
        assert any(col in expr for col in
                   ("last_detection_at", "severity", "detection_count", "id"))
        assert ";" not in expr and "--" not in expr


def test_open_incidents_always_sort_above_closed_ones():
    db = _StubDB()
    run(inc.list_incidents(db, sort="vechi"))
    assert "status IN ('open','acknowledged')) DESC" in db.sql[0]


# --- status transitions -----------------------------------------------------
def test_set_status_rejects_anything_not_whitelisted():
    db = _StubDB()
    assert run(inc.set_status(db, 1, "deleted", by="web:x")) is False
    assert run(inc.set_status(db, 1, "'; DROP TABLE incidents --", by="web:x")) is False
    assert db.sql == []                            # nothing was executed at all


def test_set_status_accepts_the_real_transitions():
    for s in ("acknowledged", "resolved", "false_positive", "suppressed", "open"):
        db = _StubDB()
        assert run(inc.set_status(db, 1, s, by="web:operator")) is True
        assert "UPDATE incidents" in db.sql[0]
        # Every change is written to the timeline: who, what, when.
        assert "incident_timeline" in db.sql[1]


def test_closing_records_a_resolved_timestamp_only_for_closing_states():
    db = _StubDB()
    run(inc.set_status(db, 1, "acknowledged", by="web:x"))
    sql = db.sql[0]
    assert "resolved_at" in sql and "acknowledged_at" in sql
    # The CASE keys off the closing set, so acknowledging must not stamp resolved.
    assert "CLOSED" not in sql  # implementation detail: passed as a parameter
    assert list(inc.CLOSED_STATUSES) in [list(x) for a in db.args for x in a
                                         if isinstance(x, list)]


# --- bulk close -------------------------------------------------------------
def test_bulk_close_refuses_a_non_closing_status():
    db = _StubDB()
    assert run(inc.bulk_close(db, rule="ids.suricata", status="open", by="web:x")) == 0
    assert db.sql == []


def test_bulk_close_is_scoped_to_one_rule():
    db = _StubDB(rows=[{"id": 1}, {"id": 2}, {"id": 3}])
    n = run(inc.bulk_close(db, rule="ids.suricata", status="resolved", by="web:x"))
    assert n == 3
    sql = db.sql[0]
    # Scoped: a blanket close would hide the one incident that mattered.
    assert "split_part(fingerprint, ':', 1) = $1" in sql
    assert "status IN ('open', 'acknowledged')" in sql
    assert db.args[0][0] == "ids.suricata"


def test_bulk_close_can_spare_recent_incidents():
    db = _StubDB(rows=[])
    run(inc.bulk_close(db, rule="ids.suricata", status="resolved", by="x",
                       older_than_hours=24))
    assert "make_interval(hours =>" in db.sql[0]
    assert 24 in db.args[0]


# --- template ---------------------------------------------------------------
def test_incident_pages_render_with_actions():
    jinja2 = pytest.importorskip("jinja2")
    tpl = Path(__file__).resolve().parents[2] / "sentinel" / "web" / "templates"
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(tpl)), autoescape=True)
    user = type("U", (), {"username": "operator", "role": "owner"})()
    row = type("R", (), {
        "id": 7, "severity": "high", "title": "Brute-force SSH", "summary": "x",
        "actor_key": "1.2.3.4", "status": "open", "detection_count": 30,
        "first_detection_at": NOW, "last_detection_at": NOW, "notified_at": NOW,
        "ai_severity": None, "auto_action": "observed", "sev_dot": "bad",
    })()

    lst = env.get_template("incidents.html").render(
        user=user, active="incidents", rows=[row], counts={"total": 1, "high": 1},
        filter_status=None, sort="recent", sorts=inc.SORTS, status_ro={"open": "deschis"},
        can_act=True, msg=None, csrf_token="t",
        open_rules=[{"regula": "ids.suricata", "n": 485, "ultim": NOW}], version="1")
    assert "Rezolvă" in lst and "Închidere în masă" in lst
    assert "ids.suricata (485 deschise)" in lst
    assert 'sort=severitate' in lst          # the sort control is present

    det = env.get_template("incident.html").render(
        user=user, active="incidents", inc=row, detections=[], verdict=None,
        status_ro={"open": "deschis"}, can_act=True, csrf_token="t",
        request=type("Q", (), {"query_params": {}})(), version="1")
    assert "Fals-pozitiv" in det and "Rezolvat" in det


def test_viewer_sees_no_action_buttons():
    jinja2 = pytest.importorskip("jinja2")
    tpl = Path(__file__).resolve().parents[2] / "sentinel" / "web" / "templates"
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(str(tpl)), autoescape=True)
    user = type("U", (), {"username": "obs", "role": "viewer"})()
    html = env.get_template("incidents.html").render(
        user=user, active="incidents", rows=[], counts={"total": 0},
        filter_status=None, sort="recent", sorts=inc.SORTS, status_ro={},
        can_act=False, msg=None, csrf_token="t", open_rules=[], version="1")
    assert "Închidere în masă" not in html
    assert "Rezolvă" not in html
