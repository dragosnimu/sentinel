"""How the risk pass is plugged into the scan and the hourly maintenance.

The pure decisions are in `test_risk.py` and the SQL is in
`tests/integration/test_risk_intel_pg.py`. What is left, and what breaks quietly
if it is wrong, is the plumbing:

  * the scan must run the pass AFTER every scanner and BEFORE plans are drafted
    and the announcement is built (plans order by `priority`; the announcement
    carries the colour), and hand it the keys of this scan's NEW findings so it
    does not announce them a second time as "became red";
  * a pass that fails must not fail the scan;
  * the hourly maintenance must run it last (it touches the network and the unit
    has a 900 s limit) and report a failed pass as a failed step;
  * with `intel.enabled: false` nothing may reach the network.
"""

from __future__ import annotations

import asyncio
import inspect
from datetime import date
from types import SimpleNamespace

import pytest

from sentinel.intel import epss as epss_mod
from sentinel.intel import osv as osv_mod
from sentinel.intel import redhat as redhat_mod
from sentinel.scan import enrich, orchestrator, risk
from sentinel.services import maintenance_service as ms


def run(coro):
    return asyncio.run(coro)


def _cfg(**scan):
    base = dict(enabled=True, os_packages=True, filesystem=False, containers=False)
    base.update(scan)
    return SimpleNamespace(scan=SimpleNamespace(**base),
                           platform=SimpleNamespace(family="rhel"))


def _patch_scan(monkeypatch, order: list[str], *, new_items):
    async def no_refresh(_db):
        order.append("kev")

    async def os_scan(_db, _family, _triggered):
        order.append("scanner")
        return {"status": "completed", "new_items": new_items}

    async def plans(_db, _cfg):
        order.append("plans")
        return {"status": "disabled"}

    async def announce(_cfg, items):
        order.append("announce")
        announce.items = list(items)
        return 1

    announce.items = []
    monkeypatch.setattr(orchestrator.kev, "refresh", no_refresh)
    monkeypatch.setattr(orchestrator, "_run_os_packages", os_scan)
    monkeypatch.setattr(orchestrator, "_draft_plans", plans)
    monkeypatch.setattr(orchestrator.announce, "announce", announce)
    return announce


def test_the_pass_runs_after_the_scanners_and_before_plans_and_the_announcement(monkeypatch):
    order: list[str] = []
    seen: dict = {}
    item = {"finding_key": "k1", "cve": "CVE-2026-0001", "package": "p", "severity": "high"}
    announce = _patch_scan(monkeypatch, order, new_items=[item])
    assessment = risk.assess({"scanner": "dnf", "ecosystem": "rpm", "cve": "CVE-2026-0001",
                              "severity": "high", "cvss": 7.5,
                              "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
                             risk.Intel(kev={"CVE-2026-0001": date(2026, 10, 9)}, kev_usable=True))

    async def fake_run(_db, _cfg, **kw):
        order.append("risk")
        seen.update(kw)
        return {"status": "completed", "findings": 1, "assessed": {"k1": assessment}}

    monkeypatch.setattr(orchestrator.enrich, "run", fake_run)
    summary = run(orchestrator.run_all(object(), _cfg()))

    assert order == ["kev", "scanner", "risk", "plans", "announce"]
    assert seen["new_keys"] == {"k1"}
    assert "assessed" not in summary["risk"], "the Assessment objects must not reach the journal line"
    # the announcement item now carries the colour and the real priority
    sent = announce.items[0]
    assert sent["risk_color"] == assessment.color == "amber"
    assert sent["priority"] == assessment.priority and sent["priority"] >= 60
    assert sent["kev"] is True


def test_a_failed_pass_does_not_stop_the_scan_or_the_announcement(monkeypatch):
    order: list[str] = []
    item = {"finding_key": "k1", "cve": "CVE-2026-0001"}
    _patch_scan(monkeypatch, order, new_items=[item])

    async def failed(_db, _cfg, **kw):
        return {"status": "failed", "error": "boom", "assessed": {}}

    monkeypatch.setattr(orchestrator.enrich, "run", failed)
    summary = run(orchestrator.run_all(object(), _cfg()))
    assert order[-2:] == ["plans", "announce"]
    assert summary["risk"]["status"] == "failed"
    assert summary["announced"]["findings"] == 1


def test_a_disabled_scan_does_not_run_the_pass_here():
    """The hourly maintenance runs it regardless; the scan entry point does not."""
    out = run(orchestrator.run_all(object(), _cfg(enabled=False)))
    assert out == {"skipped": {"reason": "scan disabled"}}


def test_maintenance_runs_the_risk_pass_last_and_a_failed_pass_fails_its_step(monkeypatch):
    src = inspect.getsource(ms.run)
    steps = [line.split('"')[1] for line in src.splitlines() if "await _step(rep," in line]
    assert steps[-1] == "risk", steps

    async def failed(_db, _cfg, **kw):
        return {"status": "failed", "error": "boom"}
    monkeypatch.setattr(enrich, "run", failed)
    rep = ms.Report()
    result = run(ms._step(rep, "risk", ms.assess_risk(object(), object())))
    assert result.ok is False and "boom" in result.detail


def test_a_successful_maintenance_pass_reports_colours_and_sources(monkeypatch):
    async def done(_db, _cfg, **kw):
        return {"status": "completed", "findings": 812, "changed": 3,
                "colors": {"red": 1, "amber": 3, "grey": 25, "green": 783},
                "sources": {"epss": {"status": "fresh"}, "redhat": {"errors": 0, "aborted": False},
                            "osv": {"aborted": True}},
                "assessed": {"k": object()}}
    monkeypatch.setattr(enrich, "run", done)
    detail, facts = run(ms.assess_risk(object(), object()))
    assert ("812 constatări evaluate (Acum 1 · Curând 3 · Nedecis 25 · "
            "Ciclul obișnuit / De urmărit* 783); 3 schimbate") in detail
    assert "surse cu probleme: osv" in detail
    assert "assessed" not in facts and facts["sources"]["epss"] == "fresh"


# ---------------------------------------------------------------------------
# enrich: what reaches the network, and when
# ---------------------------------------------------------------------------
class _NoNetwork:
    def __init__(self, monkeypatch):
        self.calls: list[str] = []
        for module, fn in ((epss_mod, "refresh"), (redhat_mod, "ensure"), (osv_mod, "ensure")):
            async def boom(*a, _name=f"{module.__name__}.{fn}", **kw):
                self.calls.append(_name)
                return {"status": "failed"}
            monkeypatch.setattr(module, fn, boom)


class _Db:
    """Returns one open rpm finding, empty mirrors, and records writes."""

    def __init__(self):
        self.writes: list = []

    async def fetch(self, sql, *a):
        if "FROM findings f" in sql and "status = ANY" in sql:
            return [{"id": 1, "finding_key": "k1", "scanner": "dnf", "ecosystem": "rpm",
                     "cve": "CVE-2026-0001", "advisory_id": None, "package": "p",
                     "severity": "high", "cvss": None, "cvss_vector": None, "epss": None,
                     "epss_percentile": None, "kev": False, "kev_due_date": None,
                     "priority": 40, "risk": {}, "risk_color": "grey", "risk_decision": None,
                     "risk_score": None, "risk_changed_at": None,
                     "risk_red_announced_at": None, "fix_pending_reboot": False}]
        return []

    async def fetchval(self, sql, *a):
        return None

    async def fetchrow(self, sql, *a):
        return None

    async def execute(self, sql, *a):
        self.writes.append(("execute", sql))
        return "UPDATE 0"

    def transaction(self):
        db = self

        class _Tx:
            async def __aenter__(self):
                return db

            async def __aexit__(self, *exc):
                return False

        return _Tx()

    async def executemany(self, sql, rows):
        self.writes.append(("executemany", len(rows)))


def test_with_intel_disabled_nothing_reaches_the_network(monkeypatch):
    guard = _NoNetwork(monkeypatch)
    cfg = SimpleNamespace(intel=SimpleNamespace(enabled=False, epss=True),
                          scan=SimpleNamespace(announce_new=True))
    out = run(enrich.run(_Db(), cfg))
    assert guard.calls == [], guard.calls
    assert out["status"] == "completed" and out["colors"] == {"grey": 1}


def test_the_epss_switch_alone_stops_only_epss(monkeypatch):
    guard = _NoNetwork(monkeypatch)
    cfg = SimpleNamespace(intel=SimpleNamespace(enabled=True, epss=False),
                          scan=SimpleNamespace(announce_new=True))
    run(enrich.run(_Db(), cfg))
    assert "sentinel.intel.epss.refresh" not in guard.calls
    assert "sentinel.intel.redhat.ensure" in guard.calls     # the rpm CVE still asks Red Hat


def test_with_everything_on_the_pass_asks_epss_and_red_hat_for_what_it_found(monkeypatch):
    """Positive control for the two tests above: "nothing reached the network" only
    means something if the same pass DOES reach it when the switches are on."""
    guard = _NoNetwork(monkeypatch)
    cfg = SimpleNamespace(intel=SimpleNamespace(enabled=True, epss=True),
                          scan=SimpleNamespace(announce_new=True))
    run(enrich.run(_Db(), cfg))
    assert "sentinel.intel.epss.refresh" in guard.calls
    assert "sentinel.intel.redhat.ensure" in guard.calls


def test_a_database_that_cannot_be_read_gives_a_failed_pass_not_an_exception():
    class Broken:
        async def fetch(self, *a):
            raise RuntimeError("connection reset")

        async def execute(self, *a):
            raise RuntimeError("still broken")

    out = run(enrich.run(Broken(), SimpleNamespace()))
    assert out["status"] == "failed" and "connection reset" in out["error"]
    assert out["assessed"] == {}


def test_the_pass_never_leaves_a_finding_green_when_every_source_is_down(monkeypatch):
    """The whole point, end to end through `enrich._run`: with all three sources
    failing, the finding is grey (not green) and the pass still completes."""
    _NoNetwork(monkeypatch)
    cfg = SimpleNamespace(intel=SimpleNamespace(enabled=True, epss=True),
                          scan=SimpleNamespace(announce_new=True))
    db = _Db()
    out = run(enrich.run(db, cfg))
    a = out["assessed"]["k1"]
    assert a.color == "grey" and out["colors"] == {"grey": 1}
    assert ("executemany", 1) in db.writes


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------
def test_osv_is_asked_only_for_what_the_other_sources_cannot_answer():
    rh_ok = {"CVE-2026-0001": redhat_mod.Row("found", 5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                             "3.1", "Low", None, (), (), None)}
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    base = {"cve": "CVE-2026-0001", "advisory_id": None, "ecosystem": "npm", "cvss_vector": None}
    assert enrich._needs_osv(base, {}) == "CVE-2026-0001"                       # no vector anywhere
    assert enrich._needs_osv({**base, "cvss_vector": vec}, {}) is None          # scanner has one
    assert enrich._needs_osv({**base, "ecosystem": "rpm"}, rh_ok) is None       # Red Hat has one
    assert enrich._needs_osv({**base, "ecosystem": "rpm"}, {}) == "CVE-2026-0001"
    # an advisory with no CVE is asked for its alias even when it has a vector
    ghsa = {"cve": None, "advisory_id": "GHSA-2xp9-vwfh-vxw4", "ecosystem": "npm", "cvss_vector": vec}
    assert enrich._needs_osv(ghsa, {}) == "GHSA-2xp9-vwfh-vxw4"
    assert enrich._needs_osv({**ghsa, "advisory_id": "not an id"}, {}) is None
    assert enrich._needs_osv({"cve": None, "advisory_id": None}, {}) is None


@pytest.mark.parametrize("value,expected", [
    ({"a": 1}, {"a": 1}), ('{"a": 1}', {"a": 1}), (b'{"a": 1}', {"a": 1}),
    ("{not json", {}), ("[1]", {}), (None, {}), (5, {}),
])
def test_jsonb_arrives_as_text_or_dict_and_is_read_either_way(value, expected):
    assert enrich._as_dict(value) == expected


def test_the_default_asset_is_exposed_with_medium_mission():
    """The one input the tree is most sensitive to. A change here repaints the
    page (measured: 4 non-green findings at 3, 277 at 5), so it must be a
    deliberate edit that a test notices."""
    assert enrich.DEFAULT_EXPOSED is True and enrich.DEFAULT_CRITICALITY == 3
    assert risk.mission_for(enrich.DEFAULT_CRITICALITY) == "medium"


def test_the_repository_default_priority_is_the_grey_band():
    from sentinel.db.repo import findings as fx
    assert fx.UNASSESSED_PRIORITY == risk.UNASSESSED_PRIORITY
    from pathlib import Path
    migration = Path(risk.__file__).resolve().parents[1] / "db" / "migrations" / "0047_risk_intel.sql"
    text = migration.read_text(encoding="utf-8")
    assert f"SET priority = {risk.UNASSESSED_PRIORITY}" in text
