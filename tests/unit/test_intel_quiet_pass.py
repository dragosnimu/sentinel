"""A source with nothing due is quiet, not failing -- and a failing one still rings.

The defect this file prevents, in the operator's terms. Red Hat, OSV and CISA keep
the answers they got for a week (two days for a CVE CISA has not evaluated yet).
For that long NOTHING is due, so a pass asks nobody and used to write nothing:
`intel_state.last_ok_at` stood still, and after 36 hours `check_risk_intel` said
"căutările eșuează" and rang `degraded` on Telegram. Measured on production on
2 October 2026: every row of every source was fetched between 14:04 and 15:04 that
day, and the next batch was not due before 15:04 on 4 October, eleven hours after the
check would have rung. A page about something that was not wrong, on both hosts,
that no one on the host could fix.

The two directions are tested together, through the real passes and the real check
on a virtual clock, because either alone is satisfied by a wrong fix:

  * quiet for a week: never `bad` (a fix that merely raises the threshold passes the
    second test and fails this one at hour 168 -- see the horizon below);
  * asked and failed: still `degraded` 37 hours after the last real answer (a fix that
    makes the quiet pass look like an answer passes the first test and fails this one).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from sentinel.intel import mirror, osv, redhat
from sentinel.selfcheck import checks

FIX = Path(__file__).parent.parent / "fixtures" / "intel"
T0 = datetime(2026, 10, 2, 14, 4, tzinfo=timezone.utc)
CVE = "CVE-2024-6501"          # the fixture carries a CVSS vector: re-asked every 7 days
NEW_CVE = "CVE-2026-0002"      # a finding that arrives later and was never asked


def _run(coro):
    return asyncio.run(coro)


class ClockDB:
    """`intel_state` and `vuln_intel` with the semantics of the real SQL, on a clock in
    hours. `mirror._upsert` is a CASE on its second argument: `last_ok_at` moves only when
    that is true, `last_attempt_at` always. The age columns are what `check_risk_intel`
    asks Postgres for (`now() - last_ok_at`, `now() - last_attempt_at`)."""

    def __init__(self) -> None:
        self.hour = 0.0
        self.state: dict[str, dict[str, Any]] = {}
        self.vuln: dict[tuple[str, str], dict[str, Any]] = {}

    @property
    def now(self) -> datetime:
        return T0 + timedelta(hours=self.hour)

    async def fetch(self, sql: str, *args: Any):
        if "FROM vuln_intel" in sql:
            source, ids = args
            return [{"vuln_id": i, **self.vuln[(source, i)]}
                    for i in ids if (source, i) in self.vuln]
        assert "FROM intel_state" in sql
        rows = []
        for source, st in sorted(self.state.items()):
            ok, attempt = st["ok"], st["attempt"]
            rows.append({
                "source": source, "last_attempt_at": "x", "last_ok_at": ok,
                "last_error": st["error"], "detail": st["detail"],
                "ok_age_s": None if ok is None else (self.hour - ok) * 3600,
                "attempt_age_s": (self.hour - attempt) * 3600})
        return rows

    async def execute(self, sql: str, *args: Any):
        if "INSERT INTO vuln_intel" in sql:
            vid, source, status, _score, vector = args[:5]
            self.vuln[(source, vid)] = {"status": status, "cvss_vector": vector,
                                        "fetched_at": self.now}
            return
        assert "INSERT INTO intel_state" in sql
        source, answered, error, detail = args
        st = self.state.setdefault(source, {"ok": None, "attempt": 0.0, "error": None,
                                            "detail": "{}"})
        st["attempt"] = self.hour
        if answered:
            st["ok"] = self.hour
        st["error"], st["detail"] = error, detail


def _service(*, up: bool = True, urls: list[str] | None = None):
    record = json.loads((FIX / "redhat_CVE-2024-6501.json").read_text(encoding="utf-8"))

    def handler(request: httpx.Request) -> httpx.Response:
        if urls is not None:
            urls.append(request.url.path)
        return httpx.Response(200, json=record) if up else httpx.Response(503)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _pass(db: ClockDB, ids: set[str], *, up: bool = True, urls: list[str] | None = None):
    async def go():
        async with _service(up=up, urls=urls) as http:
            await redhat.ensure(db, ids, http=http, now=db.now, pause_s=0)
            await mirror.record(db, "risk", ok=True)     # `enrich._run` always ends so
    return _run(go())


def _verdict(db: ClockDB, key: str = "risk:redhat"):
    return {r.key: r for r in _run(checks.check_risk_intel(db))}[key]


def test_a_week_of_nothing_due_never_rings_and_the_next_due_batch_is_asked_again():
    """The page that rings for nothing. One answered pass at hour 0; then an hourly pass
    for a week in which every row is still fresh. `check_risk_intel` must not be `bad` at
    any hour (before the fix it was `degraded` from hour 37 to hour 168), `last_ok_at` must
    stay the hour of the real answer (a quiet pass is not an answer), and at hour 168, when
    the row falls due, the source is asked again and the answer is what moves it."""
    db = ClockDB()
    urls: list[str] = []
    _pass(db, {CVE}, urls=urls)
    assert len(urls) == 1 and db.state["redhat"]["ok"] == 0.0
    for hour in range(1, 168):
        db.hour = float(hour)
        _pass(db, {CVE}, urls=urls)
        out = _verdict(db)
        assert not out.bad, f"hour {hour}: {out.status} {out.detail}"
    assert len(urls) == 1, "nothing was due, so nobody was asked"
    assert db.state["redhat"]["ok"] == 0.0, "a pass that asked nobody must not claim an answer"
    assert "nimic la termen" in _verdict(db).detail and "ultimul răspuns real" in _verdict(db).detail
    db.hour = 168.0
    _pass(db, {CVE}, urls=urls)
    assert len(urls) == 2 and db.state["redhat"]["ok"] == 168.0
    assert _verdict(db).status == "ok"


def test_a_source_that_was_asked_and_failed_still_rings_at_the_same_bound():
    """The other direction: quiet must not become a place for a failure to hide. A new
    finding arrives at hour 5, the source answers 503 from then on, and every hourly pass
    asks again (the CVE is still due, because a failed request writes nothing). The last
    real answer is hour 0, so the bound is the old one: `ok` up to hour 36, `degraded` from
    hour 37, and it stays so. A fix that let a quiet pass move `last_ok_at`, or that read
    `idle` from a pass that had asked, would leave this `ok`."""
    db = ClockDB()
    _pass(db, {CVE})
    states = {}
    for hour in range(1, 90):
        db.hour = float(hour)
        _pass(db, {CVE} | ({NEW_CVE} if hour >= 5 else set()), up=hour < 5)
        states[hour] = _verdict(db).status
    assert all(states[h] == "ok" for h in range(1, 37)), states
    assert all(states[h] == "degraded" for h in range(37, 90)), states
    assert json.loads(db.state["redhat"]["detail"])["idle"] is False, (
        "a pass that asked and failed was recorded as quiet")
    assert db.state["redhat"]["ok"] == 0.0 and db.state["redhat"]["error"]


def test_a_pass_that_stops_reaching_the_source_is_not_hidden_by_its_last_quiet_record():
    """`idle` in the row says "the last pass found nothing due", which is only worth what the
    pass behind it is worth. Hourly quiet passes up to hour 10, then the pass stops reaching
    the source (maintenance off, the step skipped). The old row still says `idle`, but its
    own attempt is old: past 36 hours it is `degraded`, and it says the pass stopped, not that
    the lookups fail."""
    db = ClockDB()
    _pass(db, {CVE})
    for hour in range(1, 11):
        db.hour = float(hour)
        _pass(db, {CVE})
    db.hour = 10 + 36.0
    assert _verdict(db).status == "ok"
    db.hour = 10 + 37.0
    out = _verdict(db)
    assert out.status == "degraded" and "nicio trecere" in out.detail
    assert "nu e o eroare a căutărilor" in out.detail


def test_a_quiet_pass_is_recorded_for_osv_as_well():
    """Same loop, other source: OSV has its own `ensure`, and a copy of the fix in only one
    of the two (Red Hat) would leave the other ringing for nothing."""
    db = ClockDB()
    ids = {"CVE-2024-22640"}
    payload = json.loads((FIX / "osv_trimmed.json").read_text(encoding="utf-8"))["CVE-2024-22640"]

    async def go(hour: float):
        db.hour = hour
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json=payload))) as http:
            return await osv.ensure(db, ids, http=http, now=db.now, pause_s=0)
    first = _run(go(0.0))
    assert first["asked"] == 1
    quiet = _run(go(50.0))
    assert quiet["asked"] == 0 and quiet["idle"] is True
    assert db.state["osv"]["ok"] == 0.0 and db.state["osv"]["attempt"] == 50.0
    assert json.loads(db.state["osv"]["detail"])["idle"] is True


def test_record_idle_marks_the_row_quiet_whatever_the_caller_passes():
    """`record_idle` owns the flag: a caller that hands over a detail without it (or with
    `idle: false`, copied from a summary) still produces a quiet row, and `last_ok_at` stays.
    The check reads nothing else to tell quiet from a failure."""
    db = ClockDB()
    _run(mirror.record(db, "redhat", ok=True))
    db.hour = 5.0
    _run(mirror.record_idle(db, "redhat"))
    assert json.loads(db.state["redhat"]["detail"])["idle"] is True
    _run(mirror.record_idle(db, "redhat", {"idle": False, "asked": 0}))
    assert json.loads(db.state["redhat"]["detail"])["idle"] is True
    assert db.state["redhat"]["ok"] == 0.0 and db.state["redhat"]["attempt"] == 5.0
