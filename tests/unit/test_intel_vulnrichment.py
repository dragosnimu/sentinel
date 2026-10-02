"""CISA Vulnrichment: reading the points CISA published, and what a bad day leaves behind.

Failures this file prevents, in the operator's terms:

  * a parser that stops finding CISA's container (an id changed, a field renamed)
    and reports every CVE as "CISA has evaluated nothing": Exploitation then falls
    to `none` for the whole host, the pass says "success", and the page looks calmer
    than it is. Parsed here from RECORDED real responses, not hand-written ones;
  * a request that merely FAILED written down as "CISA has no data";
  * a vocabulary word CISA's tree does not use (or a different tree's role) stored
    as if it were one of ours;
  * a good evaluation overwritten with "nothing" by one truncated response.
"""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinel.intel import mirror, vulnrichment as vr

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
    assert seen == ["https://cveawg.mitre.org/api/cve/CVE-2025-29927"]


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
    assert len(seen) == mirror.MAX_CONSECUTIVE_ERRORS
    assert out["aborted"] is True and db.states["vulnrichment"][0] is False


def _unenriched_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=_record("CVE-2025-40075"))


def test_a_pass_that_gets_many_cves_and_no_cisa_points_is_marked_blind():
    """The silent failure. 30 CVE records arrive, none with a CISA container: either
    CISA stopped publishing (it did not) or the parser stopped seeing it. Without
    this flag the pass reports success and every CVE reads as "not evaluated"."""
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 31)}
    db = FakeDB()
    out = _run(vr.ensure(db, ids, http=_client(_unenriched_handler), now=NOW, pause_s=0))
    assert out["blind"] is True and out["with_points"] == 0
    assert out["canary"] == "control_blind"
    ok, error = db.states["vulnrichment"][0], db.states["vulnrichment"][1]
    assert ok is False and "parserul" in error and vr.CANARY_CONTROL_CVE in error
    assert json.loads(db.states["vulnrichment"][2])["blind"] is True


def _batch_without_points_but_a_control_that_has_them(control_status: int = 200):
    """A host batch of 30 CVEs CISA has not evaluated (the shape of a `linux-libc-dev`
    bump: 7% of Debian kernel CVEs carry CISA points) while the control CVE, asked in
    the same pass, answers like the real service does. Returns (summary, db, urls)."""
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(request.url.path.rsplit("/", 1)[-1])
        if request.url.path.endswith(vr.CANARY_CONTROL_CVE):
            if control_status != 200:
                return httpx.Response(control_status)
            return httpx.Response(200, json=_record("CVE-2025-29927"))
        return httpx.Response(200, json=_record("CVE-2025-40075"))
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 31)}
    db = FakeDB()
    out = _run(vr.ensure(db, ids, http=_client(handler), now=NOW, pause_s=0))
    return out, db, urls


def test_a_batch_without_points_is_not_a_blind_parser_when_the_control_still_has_points():
    """The false alarm this prevents: a `linux-libc-dev` bump brings 20-30 Debian
    kernel CVEs, of which CISA has evaluated about 7%, so the whole batch can come
    back without points (0.93^20 is 23%) while the parser is perfectly fine. The old
    canary called that "parser blind", marked the source `degraded` and, because
    unevaluated CVEs are asked again only after two days, held it there. An alarm
    that fires on the COMPOSITION of a batch trains the operator to ignore it, and
    then the day the parser really is blind nobody reads it. The control CVE, asked
    live in the same pass, tells the two apart."""
    out, db, urls = _batch_without_points_but_a_control_that_has_them()
    assert "blind" not in out
    assert out["canary"] == "control_ok" and out["with_points"] == 0
    assert vr.CANARY_CONTROL_CVE in urls, "the control was never asked: nothing was checked"
    assert vr.CANARY_CONTROL_CVE not in db.rows, "the control is not a host CVE: never stored"
    # The state the self-check reads is the normal pass's, not a `blind` one.
    assert json.loads(db.states["vulnrichment"][2]).get("blind") is None
    assert db.states["vulnrichment"][0] is True


@pytest.mark.parametrize("status", [503, 404])
def test_a_control_that_cannot_be_read_is_unknown_not_clean(status):
    """If the control itself fails (a 503, or the record gone), nothing can be said
    about the parser. "Cannot tell" must not be recorded as "fine": the old alarm
    stays raised, and its text says the control was unreadable, so the operator can
    tell this apart from a proven blind parser."""
    out, db, _ = _batch_without_points_but_a_control_that_has_them(status)
    assert out["blind"] is True and out["canary"] == "control_unreadable"
    ok, error, detail = db.states["vulnrichment"]
    assert ok is False and "nu se poate spune" in error and vr.CANARY_CONTROL_CVE in error
    assert json.loads(detail)["blind"] is True


def test_a_control_that_raises_does_not_escape_and_is_unknown():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(vr.CANARY_CONTROL_CVE):
            raise httpx.ReadTimeout("slow")
        return httpx.Response(200, json=_record("CVE-2025-40075"))
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 31)}
    out = _run(vr.ensure(FakeDB(), ids, http=_client(handler), now=NOW, pause_s=0))
    assert out["blind"] is True and out["canary"] == "control_unreadable"


def _recording(urls: list[str], record: str):
    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(request.url.path.rsplit("/", 1)[-1])
        return httpx.Response(200, json=_record(record))
    return handler


def test_the_control_is_asked_only_when_the_batch_is_suspicious():
    """No extra request on a normal pass: a small batch without points (five brand
    new CVEs), or a big one that has them."""
    urls: list[str] = []
    small = {f"CVE-2026-{n:04d}" for n in range(1, 6)}
    _run(vr.ensure(FakeDB(), small, http=_client(_recording(urls, "CVE-2025-40075")),
                   now=NOW, pause_s=0))
    assert vr.CANARY_CONTROL_CVE not in urls and len(urls) == 5
    urls.clear()
    big = {f"CVE-2026-{n:04d}" for n in range(1, 31)}
    _run(vr.ensure(FakeDB(), big, http=_client(_recording(urls, "CVE-2025-29927")),
                   now=NOW, pause_s=0))
    assert vr.CANARY_CONTROL_CVE not in urls and len(urls) == 30


def test_the_control_cve_really_carries_points_in_the_recorded_service_response():
    """The control is only a control if it parses to points. Checked against the
    recorded real response, so a future edit of the constant to a CVE CISA has not
    evaluated cannot turn every suspicious batch into a permanent false alarm."""
    rec = vr.parse(_record(vr.CANARY_CONTROL_CVE))
    assert rec is not None and (rec["exploitation"], rec["automatable"],
                                rec["technical_impact"]) != (None, None, None)


def test_a_small_pass_without_points_is_not_called_blind():
    """Five brand-new CVEs CISA has not got to yet are normal; the canary needs a
    sample big enough to mean something."""
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 6)}
    out = _run(vr.ensure(FakeDB(), ids, http=_client(_unenriched_handler), now=NOW, pause_s=0))
    assert "blind" not in out


def test_a_big_pass_with_points_is_not_blind():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_record("CVE-2025-29927"))
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 31)}
    out = _run(vr.ensure(FakeDB(), ids, http=_client(handler), now=NOW, pause_s=0))
    assert "blind" not in out and out["with_points"] == 30


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
