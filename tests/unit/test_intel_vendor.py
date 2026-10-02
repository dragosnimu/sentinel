"""Red Hat and OSV lookups: parsing real answers, and what a bad day leaves behind.

Two failures this file prevents, in the operator's terms:

  * a request that merely FAILED (timeout, 5xx, rate limit) written down as "the
    vendor has no data" — the CVE would stay unscored for a week, grey, with no
    sign that anything had ever gone wrong;
  * an answer for the wrong vulnerability attributed to ours — a score on a
    finding that is not about that CVE.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinel.intel import mirror, osv, redhat

FIX = Path(__file__).parent.parent / "fixtures" / "intel"
NOW = datetime(2026, 10, 2, 3, 15, tzinfo=timezone.utc)


def _rh() -> dict[str, Any]:
    return json.loads((FIX / "redhat_CVE-2024-6501.json").read_text(encoding="utf-8"))


def _osv() -> dict[str, Any]:
    return json.loads((FIX / "osv_trimmed.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Red Hat: the answer from the brief, parsed
# ---------------------------------------------------------------------------
def test_redhat_answer_for_cve_2024_6501_parses_to_what_the_brief_measured():
    """CVSS3 3.1, the vector, severity Low, the written justification, and the
    advisory — the values read off the live API on 2 Oct 2026."""
    rec = redhat.parse(_rh())
    assert rec is not None
    assert rec["cvss_score"] == 3.1
    assert rec["cvss_vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L"
    assert rec["cvss_version"] == "3.1"
    assert rec["severity"] == "Low"
    assert "very unlikely to have a production system running NetworkManager" in rec["justification"]
    assert rec["advisories"] == ["RHSA-2024:9317"]    # listed twice upstream, kept once


def test_a_redhat_record_without_cvss3_is_found_but_unrated():
    """About 1 in 70 Red Hat records has no CVSS3 block yet. That is "found,
    unrated" (re-asked daily), not an error and not a score of zero."""
    payload = _rh()
    del payload["cvss3"]
    rec = redhat.parse(payload)
    assert rec["cvss_score"] is None and rec["cvss_vector"] is None
    assert rec["severity"] == "Low"


@pytest.mark.parametrize("payload", [None, [], "x", 3])
def test_a_redhat_answer_that_is_not_an_object_is_unreadable(payload):
    assert redhat.parse(payload) is None


def test_redhat_text_is_cleaned_and_bounded_before_it_is_stored():
    """The statement is prose from the network that ends up in Telegram and the
    panel and is stored in a column: control characters out, length capped."""
    payload = _rh()
    payload["statement"] = "line1\x00\x07\n\n  line2   " + "x" * 5000
    rec = redhat.parse(payload)
    assert "\x00" not in rec["justification"] and "\n" not in rec["justification"]
    assert rec["justification"].startswith("line1 line2 ")
    assert len(rec["justification"]) <= redhat.MAX_JUSTIFICATION


def test_a_redhat_score_outside_zero_to_ten_is_dropped():
    """The column has CHECK (0..10); one bad answer must not abort the batch."""
    payload = _rh()
    payload["cvss3"]["cvss3_base_score"] = "11.5"
    assert redhat.parse(payload)["cvss_score"] is None
    payload["cvss3"]["cvss3_base_score"] = "NaN"
    assert redhat.parse(payload)["cvss_score"] is None


def test_an_advisory_id_that_is_not_an_advisory_id_is_not_kept():
    payload = _rh()
    payload["affected_release"].append({"advisory": "RHSA-2024:1\"><script>"})
    assert redhat.parse(payload)["advisories"] == ["RHSA-2024:9317"]


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------
def test_osv_ghsa_with_a_cve_alias_yields_the_alias_and_a_computed_score():
    """The path that gives 7 of the 17 open GHSA advisories an EPSS and a KEV
    answer: the alias. The score is computed from the vector OSV returns."""
    rec = osv.parse(_osv()["GHSA-2x7j-588g-ccc2"], "GHSA-2x7j-588g-ccc2")
    assert rec["aliases"] == ["CVE-2026-92596"]
    assert rec["cvss_vector"].startswith("CVSS:3.")
    assert rec["cvss_score"] is not None and 0 < rec["cvss_score"] <= 10
    assert rec["severity"] == "HIGH"


def test_osv_v4_vector_is_kept_without_a_number():
    """GHSA-2xp9 (a Next.js RCE) arrives with a CVSS v4 vector only. Its
    decision points can be read from the vector; its number cannot be computed."""
    rec = osv.parse(_osv()["GHSA-2xp9-vwfh-vxw4"], "GHSA-2xp9-vwfh-vxw4")
    assert rec["cvss_vector"].startswith("CVSS:4.0/")
    assert rec["cvss_score"] is None and rec["cvss_version"] == "4.0"
    assert rec["aliases"] == []          # no CVE: no EPSS, no KEV for this one
    assert rec["severity"] == "CRITICAL"


def test_osv_prefers_a_v3_vector_over_v4_when_both_exist():
    payload = _osv()["GHSA-2x7j-588g-ccc2"]
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    payload = {**payload, "severity": [{"type": "CVSS_V4", "score": v4}] + payload["severity"]}
    assert osv.parse(payload, "GHSA-2x7j-588g-ccc2")["cvss_version"].startswith("3.")


def test_an_osv_answer_for_another_id_is_refused():
    """A redirect or an error page served as 200 must not hand its scores to
    the id we asked about."""
    assert osv.parse(_osv()["CVE-2024-22640"], "CVE-2025-99999") is None
    assert osv.parse({"id": "CVE-2024-22640"}, "CVE-2025-99999") is None
    assert osv.parse([], "CVE-2024-22640") is None


def test_osv_aliases_are_validated_ids_only():
    payload = {**_osv()["GHSA-2x7j-588g-ccc2"],
               "aliases": ["CVE-2026-92596", "CVE-2026-92596", "<b>x</b>", "PYSEC-1", 7]}
    assert osv.parse(payload, "GHSA-2x7j-588g-ccc2")["aliases"] == ["CVE-2026-92596"]


@pytest.mark.parametrize("value,ok", [
    ("CVE-2026-29063", True), ("GHSA-2xp9-vwfh-vxw4", True),
    ("ghsa-2xp9-vwfh-vxw4", False), ("CVE-26-1", False), ("CVE-2026-29063/../x", False),
    ("", False), (None, False), (5, False),
])
def test_only_well_formed_ids_can_reach_a_url(value, ok):
    """The id is placed in the path of an HTTP request and comes out of a
    scanner's output."""
    assert osv.valid_id(value) is ok


# ---------------------------------------------------------------------------
# The shared loop: budget, circuit breaker, what is and is not written
# ---------------------------------------------------------------------------
class FakeDB:
    def __init__(self, existing: dict[str, dict[str, Any]] | None = None) -> None:
        self.rows: dict[tuple[str, str], dict[str, Any]] = {}
        self.existing = existing or {}
        self.states: dict[str, tuple] = {}

    async def fetch(self, sql: str, *args: Any):
        assert "FROM vuln_intel" in sql
        source, ids = args
        return [{"vuln_id": i, **self.existing[i]} for i in ids if i in self.existing]

    async def execute(self, sql: str, *args: Any):
        if "INSERT INTO vuln_intel" in sql:
            vid, source, status = args[0], args[1], args[2]
            self.rows[(vid, source)] = {"status": status, "score": args[3], "vector": args[4]}
        else:
            assert "INSERT INTO intel_state" in sql
            self.states[args[0]] = args[1:]


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _run(coro):
    return asyncio.run(coro)


def test_a_404_is_remembered_but_a_503_is_not():
    """`not_found` is a statement about the CVE; a 503 is a statement about the
    server. Writing the second as the first hides the CVE for a week."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("CVE-2026-0001.json"):
            return httpx.Response(404, json={"message": "Not Found"})
        if request.url.path.endswith("CVE-2026-0002.json"):
            return httpx.Response(503, text="busy")
        return httpx.Response(200, json=_rh())
    db = FakeDB()
    out = _run(redhat.ensure(db, {"CVE-2026-0001", "CVE-2026-0002", "CVE-2024-6501"},
                             http=_client(handler), now=NOW, pause_s=0))
    assert out["found"] == 1 and out["not_found"] == 1 and out["errors"] == 1
    assert db.rows[("CVE-2026-0001", "redhat")]["status"] == "not_found"
    assert ("CVE-2026-0002", "redhat") not in db.rows
    assert db.rows[("CVE-2024-6501", "redhat")]["score"] == 3.1


def test_a_partial_failure_still_counts_as_a_working_source_but_keeps_its_error():
    """Half the answers arrived: `last_ok_at` moves, and the error is not erased
    ("half worked" is not "worked")."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503) if "0002" in request.url.path else httpx.Response(404)
    db = FakeDB()
    _run(redhat.ensure(db, {"CVE-2026-0001", "CVE-2026-0002"}, http=_client(handler),
                       now=NOW, pause_s=0))
    ok, error = db.states["redhat"][0], db.states["redhat"][1]
    assert ok is True and error and "503" in error


def test_a_dead_source_is_given_up_on_after_five_failures_in_a_row():
    """No point asking the sixth time of a server that said 503 five times; the
    rest wait for the next pass instead of being lost."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(503)
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 21)}
    db = FakeDB()
    out = _run(redhat.ensure(db, ids, http=_client(handler), now=NOW, pause_s=0))
    assert len(seen) == mirror.MAX_CONSECUTIVE_ERRORS
    assert out["aborted"] is True and out["deferred"] == 15
    assert db.rows == {} and db.states["redhat"][0] is False


def test_the_per_pass_budget_defers_the_rest_instead_of_dropping_it():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)
    ids = {f"CVE-2026-{n:04d}" for n in range(1, 11)}
    db = FakeDB()
    out = _run(redhat.ensure(db, ids, http=_client(handler), now=NOW, budget=4, pause_s=0))
    assert out["asked"] == 4 and out["deferred"] == 6 and len(db.rows) == 4


def test_an_answer_that_cannot_be_read_is_an_error_not_a_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>captive portal</html>")
    db = FakeDB()
    out = _run(redhat.ensure(db, {"CVE-2026-0001"}, http=_client(handler), now=NOW, pause_s=0))
    assert out["errors"] == 1 and db.rows == {}


def test_a_network_exception_inside_the_loop_does_not_escape():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")
    out = _run(osv.ensure(FakeDB(), {"CVE-2026-0001"}, http=_client(handler), now=NOW, pause_s=0))
    assert out["errors"] == 1


def test_ids_that_are_not_ids_are_never_requested():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(404)
    _run(osv.ensure(FakeDB(), {"../../etc/passwd", "CVE-2026-0001 ", "ghsa-x"},
                    http=_client(handler), now=NOW, pause_s=0))
    assert seen == []


def test_what_is_already_fresh_is_not_asked_again_but_stale_and_unrated_are():
    """`due` is the politeness rule: found rows live a week, unrated ones a day,
    not_found a week, never-asked rows are always due."""
    day = timedelta(days=1)
    existing = {
        "CVE-2026-0001": {"status": "found", "cvss_vector": "CVSS:3.1/x", "fetched_at": NOW - 2 * day},
        "CVE-2026-0002": {"status": "found", "cvss_vector": "CVSS:3.1/x", "fetched_at": NOW - 8 * day},
        "CVE-2026-0003": {"status": "found", "cvss_vector": None, "fetched_at": NOW - 2 * day},
        "CVE-2026-0004": {"status": "not_found", "cvss_vector": None, "fetched_at": NOW - 2 * day},
        "CVE-2026-0005": {"status": "not_found", "cvss_vector": None, "fetched_at": NOW - 8 * day},
    }
    ids = {f"CVE-2026-000{n}" for n in range(1, 7)}
    due = _run(mirror.due(FakeDB(existing), "redhat", ids, found_days=7, unrated_days=1,
                          not_found_days=7, now=NOW))
    assert due == ["CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0005", "CVE-2026-0006"]
