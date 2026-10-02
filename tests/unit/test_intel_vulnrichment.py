"""CISA Vulnrichment: reading the points CISA published, and what a bad day leaves behind.

Failures this file prevents, in the operator's terms:

  * a parser that stops finding CISA's container (an id changed, a field renamed)
    and reports every CVE as "CISA has evaluated nothing": Exploitation then falls
    to `none` for the whole host, the pass says "success", and the page looks calmer
    than it is. Parsed here from RECORDED real responses, not hand-written ones;
  * a request that merely FAILED written down as "CISA has no data";
  * a vocabulary word CISA's tree does not use (or a different tree's role) stored
    as if it were one of ours;
  * a good evaluation overwritten with "nothing" by one truncated response;
  * the blind-parser alarm that rang once and was wiped by the next ordinary hourly
    pass (so "CISA Vulnrichment: ok" meant "the last pass answered", not "the parser
    still sees points"), or that was never evaluated at all because a normal pass asks
    5-6 CVEs and the old trigger needed 20;
  * a control pinned to one CVE that goes permanently "unreadable" the day that record
    is withdrawn.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinel.intel import mirror, vulnrichment as vr
from sentinel.selfcheck import checks

FIX = Path(__file__).parent.parent / "fixtures" / "intel"
NOW = datetime(2026, 10, 2, 3, 15, tzinfo=timezone.utc)


def _record(cve: str) -> dict[str, Any]:
    return json.loads((FIX / f"cveawg_{cve}.json").read_text(encoding="utf-8"))


def _cisa_metric(payload: dict[str, Any]) -> dict[str, Any]:
    for container in payload["containers"]["adp"]:
        if container["providerMetadata"]["orgId"] == vr.CISA_ADP_ORG_ID:
            return container["metrics"][0]["other"]["content"]
    raise AssertionError("fixture has no CISA container")


# ---------------------------------------------------------------------------
# Parsing recorded real responses (cveawg.mitre.org, 2 October 2026)
# ---------------------------------------------------------------------------
def test_the_nextjs_middleware_bypass_parses_to_what_cisa_publishes():
    """CVE-2025-29927: Exploitation none, Automatable yes, Technical Impact total,
    evaluated 2025-04-08 — the values read off the live service."""
    rec = vr.parse(_record("CVE-2025-29927"))
    assert (rec["exploitation"], rec["automatable"], rec["technical_impact"]) == (
        "none", "yes", "total")
    assert rec["ssvc_at"] == datetime(2025, 4, 8, 15, 16, 38, 515188, tzinfo=timezone.utc)
    assert rec["ssvc_version"] == "2.0.3"


def test_a_kev_listed_cve_reads_as_active():
    rec = vr.parse(_record("CVE-2025-39964"))
    assert rec["exploitation"] == "active"
    assert rec["ssvc_at"].date().isoformat() == "2026-09-18"


def test_a_cve_cisa_has_not_evaluated_parses_to_all_none_and_is_not_an_error():
    """CVE-2025-40075 exists but carries no CISA container. That is an ANSWER
    ("unpublished"), recorded as `found` with no points."""
    rec = vr.parse(_record("CVE-2025-40075"))
    assert rec == {"exploitation": None, "automatable": None, "technical_impact": None,
                   "ssvc_at": None, "ssvc_version": None}


@pytest.mark.parametrize("payload", [None, [], "x", 3, {}, {"cveMetadata": "x"}])
def test_something_that_is_not_a_cve_record_is_unreadable(payload):
    assert vr.parse(payload) is None


def test_another_providers_ssvc_block_is_not_cisas():
    """A different container (the CVE Program's own, a vendor's) that carries an
    `ssvc` metric must not be read as CISA's evaluation."""
    payload = _record("CVE-2025-29927")
    payload["containers"]["adp"][0]["providerMetadata"]["orgId"] = "not-the-cisa-container"
    assert vr.parse(payload)["exploitation"] is None


def test_another_decision_tree_is_not_ours():
    """The Deployer tree has other points and other words; only the Coordinator
    role matches the table in `ssvc.py`."""
    payload = _record("CVE-2025-29927")
    _cisa_metric(payload)["role"] = "CISA Deployer"
    assert vr.parse(payload)["exploitation"] is None


def test_a_word_outside_the_vocabulary_is_dropped_not_stored():
    """`public poc` is not `poc`; the column has a CHECK, and one odd word must not
    abort the whole batch of writes."""
    payload = _record("CVE-2025-29927")
    _cisa_metric(payload)["options"] = [{"Exploitation": "public poc"},
                                        {"Automatable": "yes"},
                                        {"Technical Impact": "TOTAL"}]
    rec = vr.parse(payload)
    assert (rec["exploitation"], rec["automatable"], rec["technical_impact"]) == (
        None, "yes", None)


def test_the_newest_evaluation_wins_when_cisa_published_more_than_one():
    payload = _record("CVE-2025-29927")
    older = copy.deepcopy(payload["containers"]["adp"][0]["metrics"][0])
    older["other"]["content"]["timestamp"] = "2024-01-01T00:00:00Z"
    older["other"]["content"]["options"] = [{"Exploitation": "active"}]
    payload["containers"]["adp"][0]["metrics"].insert(0, older)
    assert vr.parse(payload)["exploitation"] == "none"


@pytest.mark.parametrize("stamp", [
    "2025-04-08T15:16:38Z", "2025-04-08T15:16:38.5Z", "2025-04-08T15:16:38.515Z",
    "2025-04-08T15:16:38.515188Z", "2025-04-08T15:16:38.123456789Z",
    "2025-04-08T15:16:38.5+00:00",
])
def test_every_rfc3339_fraction_length_yields_the_evaluation_date(stamp):
    """Python 3.10's `fromisoformat` refuses fractions that are not 3 or 6 digits. A
    timestamp lost that way leaves a CISA-sourced point with no "evaluated on", which
    is exactly the date that tells the operator a `none` is a year old."""
    payload = _record("CVE-2025-29927")
    _cisa_metric(payload)["timestamp"] = stamp
    rec = vr.parse(payload)
    assert rec["ssvc_at"] is not None and rec["ssvc_at"].date().isoformat() == "2025-04-08"


def test_a_malformed_timestamp_is_no_timestamp_not_an_exception():
    payload = _record("CVE-2025-29927")
    _cisa_metric(payload)["timestamp"] = "yesterday"
    rec = vr.parse(payload)
    assert rec["exploitation"] == "none" and rec["ssvc_at"] is None


# ---------------------------------------------------------------------------
# The loop: what is written, what is not, and the blind-parser canary
# ---------------------------------------------------------------------------
class FakeDB:
    def __init__(self, existing: dict[str, dict[str, Any]] | None = None) -> None:
        self.rows: dict[str, dict[str, Any]] = {}
        self.existing = existing or {}
        self.states: dict[str, tuple] = {}
        #: `intel_state.last_ok_at` as `mirror.record` writes it: it moves only on a
        #: success, so a failed attempt leaves the previous confirmation (or none).
        self.confirmed: dict[str, bool] = {}

    async def fetch(self, sql: str, *args: Any):
        assert "FROM vulnrichment" in sql
        (ids,) = args
        return [{"cve": i, **self.existing[i]} for i in ids if i in self.existing]

    async def execute(self, sql: str, *args: Any):
        if "INSERT INTO vulnrichment" in sql:
            self.rows[args[0]] = {"status": args[1], "exploitation": args[2],
                                  "automatable": args[3], "technical_impact": args[4]}
        else:
            assert "INSERT INTO intel_state" in sql
            self.states[args[0]] = args[1:]
            if args[1]:
                self.confirmed[args[0]] = True

    async def fetchrow(self, sql: str, *args: Any):
        """`mirror.state`: the previous verdict row, as the database would give it."""
        assert "FROM intel_state" in sql
        if args[0] not in self.states:
            return None
        _ok, error, detail = self.states[args[0]]
        return {"last_attempt_at": "x", "last_ok_at": "x" if self.confirmed.get(args[0]) else None,
                "last_error": error, "detail": detail}

    def intel_rows(self) -> list[dict[str, Any]]:
        """`intel_state` as the self-check reads it, a fresh success being 6 minutes old."""
        return [{"source": source, "last_attempt_at": "x",
                 "last_ok_at": "x" if self.confirmed.get(source) else None,
                 "last_error": error, "detail": detail,
                 "ok_age_s": 360 if self.confirmed.get(source) else None}
                for source, (_ok, error, detail) in self.states.items()]


class _IntelDB:
    """What `check_risk_intel` needs: the `intel_state` rows."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    async def fetch(self, sql: str, *args: Any):
        assert "FROM intel_state" in sql
        return self._rows


def _vulnrichment_check(db: FakeDB):
    """The self-check's verdict on the source, from the state the passes left behind."""
    out = _run(checks.check_risk_intel(_IntelDB(db.intel_rows())))
    return {r.key: r for r in out}["risk:vulnrichment"]


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _run(coro):
    return asyncio.run(coro)


def test_a_404_is_remembered_but_a_503_is_not():
    """`not_found` is a statement about the CVE; a 503 is a statement about the
    server. Writing the second as the first would hide the CVE until the next
    refresh, with Exploitation resting on "CISA has nothing"."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("CVE-2026-0001"):
            return httpx.Response(404, json={"error": "CVE_RECORD_DNE"})
        if request.url.path.endswith("CVE-2026-0002"):
            return httpx.Response(503, text="busy")
        return httpx.Response(200, json=_record("CVE-2025-29927"))
    db = FakeDB()
    out = _run(vr.ensure(db, {"CVE-2026-0001", "CVE-2026-0002", "CVE-2025-29927"},
                         http=_client(handler), now=NOW, pause_s=0))
    assert out["found"] == 1 and out["not_found"] == 1 and out["errors"] == 1
    assert db.rows["CVE-2026-0001"]["status"] == "not_found"
    assert "CVE-2026-0002" not in db.rows
    assert db.rows["CVE-2025-29927"]["exploitation"] == "none"


def test_the_request_goes_to_the_cve_service_with_the_validated_id_only():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(404)
    _run(vr.ensure(FakeDB(), {"CVE-2025-29927", "../../etc/passwd", "CVE-2026-1 ", "ghsa-x"},
                   http=_client(handler), now=NOW, pause_s=0))
    # The host batch asks only the one valid id; the control (a fixed, trusted list, asked
    # on every pass) adds its own candidates, and nothing else is ever requested.
    allowed = {f"https://cveawg.mitre.org/api/cve/{c}"
               for c in {"CVE-2025-29927", *vr.CANARY_CONTROL_CVES}}
    assert set(seen) <= allowed and "https://cveawg.mitre.org/api/cve/CVE-2025-29927" in seen
    assert not any("passwd" in u or "ghsa" in u or "CVE-2026-1" in u for u in seen)


def test_an_unreadable_answer_is_an_error_and_a_network_exception_does_not_escape():
    def html(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>captive portal</html>")

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")
    for handler in (html, boom):
        db = FakeDB()
        out = _run(vr.ensure(db, {"CVE-2026-0001"}, http=_client(handler), now=NOW, pause_s=0))
        assert out["errors"] == 1 and db.rows == {}


def test_a_dead_source_is_given_up_on_after_five_failures_in_a_row():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(503)
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 21)}
    db = FakeDB()
    out = _run(vr.ensure(db, ids, http=_client(handler), now=NOW, pause_s=0))
    host = [path for path in seen
            if not any(path.endswith(c) for c in vr.CANARY_CONTROL_CVES)]
    assert len(host) == mirror.MAX_CONSECUTIVE_ERRORS
    assert out["aborted"] is True and db.states["vulnrichment"][0] is False


def _unenriched_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=_record("CVE-2025-40075"))


FIRST, SECOND, THIRD = vr.CANARY_CONTROL_CVES


def _service(*, blind: bool = False, status: dict[str, int] | None = None,
             stripped: frozenset[str] = frozenset(), raises: frozenset[str] = frozenset(),
             urls: list[str] | None = None, host_points: bool = False):
    """The CVE service as seen by the pass. Host CVEs come back as CISA has not evaluated
    them (the normal Debian-kernel shape); the control candidates carry their recorded
    real points, unless the world is `blind` (nothing has points: a parser that no longer
    finds the container), a candidate is `stripped` (still readable, points gone: re-scored
    or withdrawn), `raises` (a network failure) or has an HTTP `status` of its own. With `host_points`
    the host's own CVEs come back WITH CISA points: the parser demonstrably works."""
    status = status or {}

    def handler(request: httpx.Request) -> httpx.Response:
        cve = request.url.path.rsplit("/", 1)[-1]
        if urls is not None:
            urls.append(cve)
        if cve in raises:
            raise httpx.ReadTimeout("slow")
        if cve in status:
            return httpx.Response(status[cve])
        if cve in vr.CANARY_CONTROL_CVES:
            if not blind and cve not in stripped:
                return httpx.Response(200, json=_record(cve))
        elif host_points:
            return httpx.Response(200, json=_record(FIRST))
        return httpx.Response(200, json=_record("CVE-2025-40075"))
    return handler


def _ids(first: int, last: int) -> set[str]:
    return {f"CVE-2026-{n:04d}" for n in range(first, last + 1)}


def _pass(db: FakeDB, ids: set[str], handler, **kw):
    return _run(vr.ensure(db, ids, http=_client(handler), now=NOW, pause_s=0, **kw))


def _canary(db: FakeDB) -> dict[str, Any]:
    return json.loads(db.states[vr.CANARY_SOURCE][2])


def test_a_pass_that_gets_many_cves_and_no_cisa_points_is_marked_blind():
    """The silent failure. 30 CVE records arrive, none with a CISA container, and the
    control CVEs, which are known to carry points, come back without them too: either
    CISA stopped publishing (it did not) or the parser stopped seeing it. Without this
    flag the pass reports success and every CVE reads as "not evaluated"."""
    db = FakeDB()
    out = _pass(db, _ids(1, 30), _service(blind=True))
    assert out["canary"] == "control_blind" and out["with_points"] == 0
    ok, error, _ = db.states[vr.CANARY_SOURCE]
    assert ok is False and "parserul" in error and FIRST in error
    assert _canary(db)["canary"] == "control_blind"
    assert _vulnrichment_check(db).status == "degraded"


def test_a_blind_parser_is_still_blind_after_the_next_ordinary_pass():
    """THE defect, reproduced with the suite's own fake database. Pass 1 (30 CVEs, zero
    points) raised the alarm; pass 2 (5 CVEs, zero points) ended with `record(ok=True,
    detail=<its own summary>)`, which replaces `intel_state.detail` wholesale, so the alarm
    was gone and the self-check said "CISA Vulnrichment: ok" while every CVE still read
    "CISA has evaluated nothing". The hourly pass is what runs in steady state: the alarm
    lived at most one hour, in exactly the world it exists for. Both passes must end red."""
    db = FakeDB()
    blind = _service(blind=True)
    first = _pass(db, _ids(1, 30), blind)
    assert first["canary"] == "control_blind"
    assert _vulnrichment_check(db).status == "degraded"
    second = _pass(db, _ids(31, 35), blind)
    # the thing that used to erase the alarm DID happen: the lookups row is a success
    assert second["found"] == 5 and second["with_points"] == 0
    assert db.states[vr.SOURCE][0] is True
    # and the alarm survived it
    assert second["canary"] == "control_blind"
    assert _canary(db)["canary"] == "control_blind"
    assert db.states[vr.CANARY_SOURCE][0] is False
    check = _vulnrichment_check(db)
    assert check.status == "degraded", "the success of an ordinary pass cleared the alarm"
    assert "controlul pozitiv" in check.detail


@pytest.mark.parametrize("batch", [0, 1, 5, vr.CANARY_MIN - 1, vr.CANARY_MIN + 10])
def test_the_control_is_asked_on_every_pass_whatever_the_batch_holds(batch):
    """A normal production pass asks 5-6 CVEs and the old trigger needed 20 found without
    points, so in a blind world the verdict was almost never computed: "ok" meant "the last
    pass answered". Now it is computed on every pass, including one with nothing due (all
    fresh) and one of a single CVE. Healthy world: one extra request, verdict ok. Blind
    world: the verdict is blind however few CVEs came."""
    # batch 0 = nothing due: five CVEs, all fetched a moment ago
    ids = _ids(1, batch or 5)
    fresh = {c: {"status": "found", "exploitation": "none", "automatable": "yes",
                 "technical_impact": "total", "fetched_at": NOW} for c in ids}
    urls: list[str] = []
    db = FakeDB(existing=fresh if batch == 0 else None)
    healthy = _pass(db, ids, _service(urls=urls))
    assert healthy["canary"] == "control_ok"
    assert urls.count(FIRST) == 1 and len(urls) == batch + 1, (
        "a healthy pass costs exactly one extra request")
    assert _canary(db)["control_cve"] == FIRST
    urls.clear()
    blind = _pass(FakeDB(existing=fresh if batch == 0 else None), ids,
                  _service(blind=True, urls=urls))
    assert blind["canary"] == "control_blind"
    assert {FIRST, SECOND, THIRD} <= set(urls)


def test_only_a_confirmation_clears_the_alarm_not_a_pass_that_merely_answers():
    """Blind, then a pass in which the control cannot be read (the CVE service answers the
    host's CVEs but 503s the candidates), then a healthy one. The middle pass must not turn
    the source green: nothing confirmed the parser. Only the third, which asks the control
    and gets points, does."""
    db = FakeDB()
    _pass(db, _ids(1, 30), _service(blind=True))
    assert _vulnrichment_check(db).status == "degraded"
    down = _service(status={FIRST: 503, SECOND: 503, THIRD: 503})
    mid = _pass(db, _ids(31, 36), down)
    assert mid["canary"] == "control_unreadable" and mid["found"] == 6
    assert _vulnrichment_check(db).status == "degraded", (
        "a pass that only answered cleared an alarm nobody had disproved")
    healed = _pass(db, _ids(37, 41), _service())
    assert healed["canary"] == "control_ok"
    assert _vulnrichment_check(db).status == "ok"


def test_a_batch_without_points_is_not_a_blind_parser_when_the_control_still_has_points():
    """The false alarm this prevents: a `linux-libc-dev` bump brings 20-30 Debian
    kernel CVEs, of which CISA has evaluated about 7%, so the whole batch can come
    back without points (0.93^20 is 23%) while the parser is perfectly fine. An alarm
    that fires on the COMPOSITION of a batch trains the operator to ignore it, and then
    the day the parser really is blind nobody reads it. The control CVE, asked live in
    the same pass, tells the two apart."""
    urls: list[str] = []
    db = FakeDB()
    out = _pass(db, _ids(1, 30), _service(urls=urls))
    assert out["canary"] == "control_ok" and out["with_points"] == 0
    assert out["suspect_batch"] is True
    assert FIRST in urls, "the control was never asked: nothing was checked"
    assert not (set(vr.CANARY_CONTROL_CVES) & set(db.rows)), (
        "the control is not a host CVE: never stored")
    assert db.states[vr.CANARY_SOURCE][0] is True
    assert _vulnrichment_check(db).status == "ok"


def test_the_control_is_never_stored_even_when_it_is_also_a_host_cve():
    """CVE-2025-29927 is an open finding on the production host: the host batch asks it on
    its own account and stores it as host data. The control path must add nothing: the same
    CVE asked for the control is not written a second time, and a control candidate that
    is NOT in the batch never appears in `vulnrichment`."""
    db = FakeDB()
    _pass(db, {FIRST, "CVE-2026-0001"}, _service())
    assert set(db.rows) == {FIRST, "CVE-2026-0001"}
    db2 = FakeDB()
    _pass(db2, {"CVE-2026-0001"}, _service())
    assert set(db2.rows) == {"CVE-2026-0001"}


@pytest.mark.parametrize("how", ["404", "503", "stripped", "raises"])
def test_one_retired_candidate_does_not_raise_the_alarm(how):
    """The control used to be pinned to ONE live CVE. The day that record is withdrawn
    (404), re-scored without its ADP container (found, no points) or briefly unreachable,
    every suspect batch reported "control unreadable" forever. Now the next candidate is
    asked; the parser is called blind only if EVERY candidate that can be read comes back
    without points."""
    kw = {"404": {"status": {FIRST: 404}}, "503": {"status": {FIRST: 503}},
          "stripped": {"stripped": frozenset({FIRST})},
          "raises": {"raises": frozenset({FIRST})}}[how]
    db = FakeDB()
    out = _pass(db, _ids(1, 30), _service(**kw))
    assert out["canary"] == "control_ok"
    detail = _canary(db)
    assert detail["control_cve"] == SECOND and detail["asked"] == [FIRST, SECOND]
    assert _vulnrichment_check(db).status == "ok"


def test_the_parser_is_blind_only_when_every_readable_candidate_lacks_points():
    db = FakeDB()
    out = _pass(db, _ids(1, 3), _service(blind=True))
    assert out["canary"] == "control_blind"
    assert _canary(db)["asked"] == [FIRST, SECOND, THIRD]
    # one unreadable, the others readable-without-points: still blind, and it says so
    db2 = FakeDB()
    out = _pass(db2, _ids(1, 3), _service(blind=True, status={FIRST: 404}))
    assert out["canary"] == "control_blind"
    error = db2.states[vr.CANARY_SOURCE][1]
    assert SECOND in error and THIRD in error and FIRST in error


ALL_STRIPPED = frozenset(vr.CANARY_CONTROL_CVES)


def test_candidates_without_points_beside_a_host_batch_with_points_are_not_a_blind_parser():
    """The false statement this prevents. All three candidates come back found-without-points
    (re-scored, ADP container dropped) while the host's own CVEs in the SAME pass, through the
    same parser, parse to points. The old verdict was `control_blind`: the self-check said
    "the parser or the response shape has changed", and the operator hunted a parser bug that
    does not exist and could only get out by editing the candidate list and deploying. It must
    say what is true: the candidates are spent, replace them."""
    db = FakeDB()
    out = _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    assert out["with_points"] == 6
    assert out["canary"] == "control_exhausted"
    detail = _canary(db)
    assert detail["canary"] == "control_exhausted" and detail["exhausted_proof_at"]
    assert "CANARY_CONTROL_CVES" in db.states[vr.CANARY_SOURCE][1]
    assert "schimbat" not in db.states[vr.CANARY_SOURCE][1]
    check = _vulnrichment_check(db)
    assert check.status == "degraded"        # never confirmed: no clock to wait on
    assert "CANARY_CONTROL_CVES" in check.action
    assert "niciun punct SSVC în răspunsuri" not in check.title


def test_the_same_candidates_on_a_quiet_pass_stay_exhausted_not_blind():
    """The edge a per-pass rule gets wrong. Most hourly passes ask ~5 CVEs of which few have
    points, so a batch with points is the exception. Pass 1 (batch with points) proves the
    candidates are spent; pass 2 (a batch with none) cannot prove anything either way, and
    judged alone it would say `control_blind` -- the same false "the parser broke", on every
    quiet pass, flipping back on the next. The proof is kept in the row."""
    db = FakeDB()
    first = _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    proof = _canary(db)["exhausted_proof_at"]
    quiet = _pass(db, _ids(7, 12), _service(stripped=ALL_STRIPPED))
    assert (first["canary"], quiet["canary"]) == ("control_exhausted", "control_exhausted")
    assert quiet["with_points"] == 0
    assert _canary(db)["exhausted_proof_at"] == proof
    assert _vulnrichment_check(db).action.startswith("Înlocuiește")


def test_the_proof_survives_a_pass_in_which_the_control_cannot_be_read():
    """Exhausted, then an outage of the CVE service (all candidates 503), then the service
    back with the candidates still spent and a quiet batch. Without carrying the proof
    through the unreadable pass this is `control_blind` again."""
    db = FakeDB()
    _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    proof = _canary(db)["exhausted_proof_at"]
    down = _pass(db, _ids(7, 9), _service(status={c: 503 for c in vr.CANARY_CONTROL_CVES}))
    assert down["canary"] == "control_unreadable"
    assert _canary(db)["exhausted_proof_at"] == proof
    back = _pass(db, _ids(10, 12), _service(stripped=ALL_STRIPPED))
    assert back["canary"] == "control_exhausted"


def test_a_confirmation_clears_the_proof_so_a_later_real_blindness_is_still_blind():
    """The proof says "these candidates were spent", nothing more. Once a candidate gives
    points again (a control_ok) the proof goes; if every candidate then loses its points on
    a quiet pass, nothing separates a dead list from a blind parser and the answer is the
    loud one, `control_blind`: the day the parser really breaks must not be filed under a
    list that needs replacing."""
    db = FakeDB()
    _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    assert _pass(db, _ids(7, 9), _service())["canary"] == "control_ok"
    assert "exhausted_proof_at" not in _canary(db)
    blind = _pass(db, _ids(10, 12), _service(stripped=ALL_STRIPPED))
    assert blind["canary"] == "control_blind"
    assert _vulnrichment_check(db).status == "degraded"


REPLACEMENT = ("CVE-2024-11111", "CVE-2024-22222", "CVE-2024-33333")


def test_replacing_the_candidates_discards_a_proof_recorded_under_the_old_ones(monkeypatch):
    """The false diagnosis that outlived its fix. The proof said "the OLD candidates are
    spent"; the operator replaced `CANARY_CONTROL_CVES` and delivered. In a world that is
    genuinely blind `control_ok` never comes, so nothing ever cleared the proof, and the
    alarm kept saying "replace the candidates" for candidates that HAD just been replaced
    (reproduced: three passes after the replacement, still `control_exhausted`). The action
    it printed changed nothing, and the real cause -- a parser that sees no points -- was
    filed under a list that did not need touching. After the replacement the first quiet pass
    must say `control_blind`, with no proof carried."""
    db = FakeDB()
    first = _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    assert first["canary"] == "control_exhausted"
    assert _canary(db)["exhausted_candidates"] == list(vr.CANARY_CONTROL_CVES)
    monkeypatch.setattr(vr, "CANARY_CONTROL_CVES", REPLACEMENT)
    for n in range(3):
        quiet = _pass(db, _ids(10 + 3 * n, 12 + 3 * n), _service(blind=True))
        assert quiet["canary"] == "control_blind", f"pass {n + 1} after the replacement"
        assert "exhausted_proof_at" not in _canary(db)
        assert "CANARY_CONTROL_CVES" not in db.states[vr.CANARY_SOURCE][1]
    assert _vulnrichment_check(db).action.startswith("journalctl"), (
        "the operator was still sent to edit a list he had just edited")


def test_a_proof_is_written_under_the_current_list_and_survives_while_the_list_is_unchanged(
        monkeypatch):
    """The other half, so the repair is not "never keep a proof". After a replacement a NEW
    proof (the host's own CVEs parse to points, the new candidates do not) is tied to the new
    list and survives the quiet passes that follow, exactly as the old one did."""
    db = FakeDB()
    monkeypatch.setattr(vr, "CANARY_CONTROL_CVES", REPLACEMENT)
    stripped = frozenset(REPLACEMENT)
    first = _pass(db, _ids(1, 6), _service(stripped=stripped, host_points=True))
    assert first["canary"] == "control_exhausted"
    assert _canary(db)["exhausted_candidates"] == list(REPLACEMENT)
    quiet = _pass(db, _ids(7, 9), _service(stripped=stripped))
    assert quiet["canary"] == "control_exhausted"
    assert _canary(db)["exhausted_candidates"] == list(REPLACEMENT)


def test_reordering_the_candidates_does_not_discard_the_proof(monkeypatch):
    """Same three records in another order prove the same thing: they are all spent. Only a
    different SET of candidates (one added, one swapped, one removed) is a different claim."""
    db = FakeDB()
    _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    monkeypatch.setattr(vr, "CANARY_CONTROL_CVES", tuple(reversed(vr.CANARY_CONTROL_CVES)))
    quiet = _pass(db, _ids(7, 9), _service(stripped=ALL_STRIPPED))
    assert quiet["canary"] == "control_exhausted"
    for changed in (vr.CANARY_CONTROL_CVES + ("CVE-2024-44444",),
                    vr.CANARY_CONTROL_CVES[:2],
                    vr.CANARY_CONTROL_CVES[:2] + ("CVE-2024-44444",)):
        monkeypatch.setattr(vr, "CANARY_CONTROL_CVES", changed)
        assert _pass(db, _ids(10, 12), _service(blind=True))["canary"] == "control_blind", changed
        # restore a proof under the ORIGINAL list for the next variant
        monkeypatch.setattr(vr, "CANARY_CONTROL_CVES", (FIRST, SECOND, THIRD))
        _pass(db, _ids(13, 18), _service(stripped=ALL_STRIPPED, host_points=True))


def test_a_proof_with_no_recorded_list_is_not_trusted():
    """A row written by code that did not record the list (or edited by hand) cannot be tied
    to anything. "Cannot tell" falls to the loud `control_blind`, as an unreadable row does."""
    db = FakeDB()
    _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    detail = _canary(db)
    del detail["exhausted_candidates"]
    db.states[vr.CANARY_SOURCE] = (False, "x", json.dumps(detail))
    assert _pass(db, _ids(7, 9), _service(stripped=ALL_STRIPPED))["canary"] == "control_blind"


def test_the_proof_discarded_on_replacement_also_goes_through_an_unreadable_pass(monkeypatch):
    """The carried-through path (`unreadable` keeps the proof) must apply the same rule, or
    an outage of the CVE service right after the replacement would resurrect the old proof."""
    db = FakeDB()
    _pass(db, _ids(1, 6), _service(stripped=ALL_STRIPPED, host_points=True))
    monkeypatch.setattr(vr, "CANARY_CONTROL_CVES", REPLACEMENT)
    down = _pass(db, _ids(7, 9), _service(status={c: 503 for c in REPLACEMENT}))
    assert down["canary"] == "control_unreadable"
    assert "exhausted_proof_at" not in _canary(db)
    back = _pass(db, _ids(10, 12), _service(blind=True))
    assert back["canary"] == "control_blind"


def test_an_unreadable_previous_verdict_falls_to_blind_not_to_exhausted():
    """If the row holding the proof cannot be read, "cannot tell" must not become the
    reassuring verdict: the pass says `control_blind`, loud, and the next one with a
    readable row can correct it."""
    class Unreadable(FakeDB):
        async def fetchrow(self, sql: str, *args: Any):
            raise RuntimeError("connection reset")
    db = Unreadable()
    out = _pass(db, _ids(1, 3), _service(stripped=ALL_STRIPPED))
    assert out["canary"] == "control_blind"


def test_the_control_still_runs_when_the_lookups_of_the_same_pass_raise(monkeypatch):
    """`ensure` documents that the control is asked on EVERY pass. The one way a pass gets
    to the control after its lookups blew up is the `except` branch falling through; a
    `return` there would leave the verdict untouched for as long as the lookups kept
    failing, and the self-check would keep reading an hour-old "ok" (until the three-hour
    bound) while nothing was being checked."""
    async def boom(*a: Any, **k: Any):
        raise RuntimeError("db went away")
    monkeypatch.setattr(vr, "due", boom)
    db = FakeDB()
    out = _pass(db, _ids(1, 3), _service())
    assert out["status"] == "failed" and "db went away" in out["error"]
    assert db.states[vr.SOURCE][0] is False
    assert out["canary"] == "control_ok"
    assert db.states[vr.CANARY_SOURCE][0] is True


@pytest.mark.parametrize("handler_kw", [
    {"status": {c: s for c, s in zip(vr.CANARY_CONTROL_CVES, (503, 404, 429))}},
    {"raises": frozenset(vr.CANARY_CONTROL_CVES)},
])
def test_a_control_that_cannot_be_read_is_unknown_not_clean(handler_kw):
    """If every candidate fails (a 503, the records gone, a network error) nothing can be
    said about the parser. "Cannot tell" must not be recorded as "fine" and must not look
    like a proven blind parser either: it is its own verdict, with its reason, and the
    exception raised by the transport does not escape the pass."""
    db = FakeDB()
    out = _pass(db, _ids(1, 30), _service(**handler_kw))
    assert out["canary"] == "control_unreadable"
    ok, error, _ = db.states[vr.CANARY_SOURCE]
    assert ok is False and "nu se poate spune" in error and FIRST in error
    assert db.confirmed.get(vr.CANARY_SOURCE) is None


def test_a_small_pass_without_points_is_not_called_blind():
    """Five brand-new CVEs CISA has not got to yet are normal, whatever the control says:
    the batch alone decides nothing."""
    db = FakeDB()
    out = _pass(db, _ids(1, 5), _service())
    assert out["canary"] == "control_ok" and out["suspect_batch"] is False
    assert _vulnrichment_check(db).status == "ok"


def test_a_big_pass_with_points_is_not_blind():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_record("CVE-2025-29927"))
    db = FakeDB()
    out = _pass(db, _ids(1, 30), handler)
    assert out["canary"] == "control_ok" and out["with_points"] == 30
    assert out["suspect_batch"] is False


def test_the_candidates_carry_points_in_the_recorded_service_responses():
    """A control is only a control if it parses to points. Checked against recorded real
    responses, one per candidate, so a future edit of the list to a CVE CISA has not
    evaluated cannot turn every pass into a permanent false alarm, and there are several
    of them so that one retirement is survivable."""
    assert len(vr.CANARY_CONTROL_CVES) >= 2
    assert len(set(vr.CANARY_CONTROL_CVES)) == len(vr.CANARY_CONTROL_CVES)
    for cve in vr.CANARY_CONTROL_CVES:
        assert mirror.CVE_ID.match(cve)
        rec = vr.parse(_record(cve))
        assert rec is not None and (rec["exploitation"], rec["automatable"],
                                    rec["technical_impact"]) != (None, None, None), cve


def test_the_cisa_container_is_found_when_it_is_not_the_first_adp_container():
    """CVE-2023-38545 lists the CVE Program's own container before CISA's and a vendor's
    after it: a parser that read `adp[0]` would see no points on a perfectly good
    control and call itself blind."""
    payload = _record("CVE-2023-38545")
    names = [c["providerMetadata"]["shortName"] for c in payload["containers"]["adp"]]
    assert names.index("CISA-ADP") not in (0, len(names) - 1)
    assert vr.parse(payload)["exploitation"] == "poc"


def test_the_canary_source_is_one_the_table_will_accept():
    """`mirror.record` swallows a database error on purpose (a state log must not break a
    scan), so a source name the `intel_state_source_check` constraint rejects is not an
    error anywhere: the verdict is simply never written, and the self-check says
    "unknown" for ever. Every source the code writes must be in the NEWEST definition of
    the constraint."""
    from sentinel.db import migrate
    from sentinel.intel import epss, osv, redhat
    latest = None
    for path in sorted(migrate.MIGRATIONS_DIR.glob("*.sql")):
        text = path.read_text(encoding="utf-8")
        if "ADD CONSTRAINT intel_state_source_check" in text:
            latest = text
    assert latest is not None
    clause = latest.split("ADD CONSTRAINT intel_state_source_check", 1)[1].split(";", 1)[0]
    accepted = set(re.findall(r"'([a-z_]+)'", clause))
    written = {epss.SOURCE, osv.SOURCE, redhat.SOURCE, vr.SOURCE, vr.CANARY_SOURCE, "risk"}
    assert written <= accepted, written - accepted


# ---------------------------------------------------------------------------
# When a CVE is asked again
# ---------------------------------------------------------------------------
def test_what_is_fresh_is_not_asked_again_but_stale_and_unevaluated_are():
    day = timedelta(days=1)
    pts = {"exploitation": "none", "automatable": "yes", "technical_impact": "total"}
    none = {"exploitation": None, "automatable": None, "technical_impact": None}
    existing = {
        "CVE-2026-0001": {"status": "found", **pts, "fetched_at": NOW - 6 * day},
        "CVE-2026-0002": {"status": "found", **pts, "fetched_at": NOW - 8 * day},
        "CVE-2026-0003": {"status": "found", **none, "fetched_at": NOW - 1 * day},
        "CVE-2026-0004": {"status": "found", **none, "fetched_at": NOW - 3 * day},
        "CVE-2026-0005": {"status": "not_found", **none, "fetched_at": NOW - 2 * day},
        "CVE-2026-0006": {"status": "not_found", **none, "fetched_at": NOW - 8 * day},
    }
    ids = {f"CVE-2026-000{n}" for n in range(1, 8)}
    due = _run(vr.due(FakeDB(existing), ids, now=NOW))
    assert due == ["CVE-2026-0002", "CVE-2026-0004", "CVE-2026-0006", "CVE-2026-0007"]
