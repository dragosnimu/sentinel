"""`check_risk_intel`: a dead risk source must not look like a live one.

The mirrors keep their last values when a download fails, so the page stays
coloured and nothing looks wrong — until a CVE that EPSS would have flagged is
missed. `mirror.record` writes every attempt into `intel_state`; this check is the
only place that row is read. The failure it closes, in the operator's terms: a
colour that stopped moving three days ago, with nothing saying so.
"""

from __future__ import annotations

import asyncio
import json

from sentinel.intel import epss
from sentinel.selfcheck import checks


def run(c):
    return asyncio.run(c)


class _DB:
    def __init__(self, rows):
        self._rows = rows

    async def fetch(self, sql, *a):
        assert "FROM intel_state" in sql
        return self._rows


def _row(source, ok_h=1.0, error=None, detail=None):
    return {"source": source, "last_attempt_at": "x", "last_ok_at": None if ok_h is None else "x",
            "last_error": error, "detail": json.dumps(detail or {}),
            "ok_age_s": None if ok_h is None else ok_h * 3600}


def _by_key(results):
    return {r.key: r for r in results}


def test_no_evaluation_at_all_is_unknown_not_ok():
    """No row for `risk` means nothing has ever been evaluated: every finding is
    grey. "Nothing recorded" must not read as "nothing wrong"."""
    out = _by_key(run(checks.check_risk_intel(_DB([]))))
    assert out["risk:pass"].status == "unknown"
    assert "GRI" in out["risk:pass"].detail


def test_a_healthy_pass_is_ok_and_names_the_grey_count_without_alarming():
    rows = [_row("risk", 0.5, detail={"colors": {"red": 1, "grey": 25, "green": 783}, "findings": 809}),
            _row("epss", 5.0), _row("vulnrichment", 2.0), _row("redhat", 3.0), _row("osv", 3.0)]
    out = _by_key(run(checks.check_risk_intel(_DB(rows))))
    assert {r.status for r in out.values()} == {"ok"}
    assert "risk:vulnrichment" in out      # the loop over sources must not skip it
    assert "25 constatări sunt GRI" in out["risk:pass"].detail
    assert out["risk:pass"].facts["colors"]["grey"] == 25


def test_the_grey_count_alone_never_degrades_anything():
    """25 greys is an honest state, not a fault; alerting on it would be the noise
    two days were spent removing."""
    rows = [_row("risk", 0.2, detail={"colors": {"grey": 800}}), _row("epss", 1.0)]
    assert all(not r.bad for r in run(checks.check_risk_intel(_DB(rows))))


def test_a_pass_that_stopped_running_degrades_then_goes_down():
    base = run(checks.check_risk_intel(_DB([_row("risk", checks.RISK_PASS_DEGRADED_H + 1)])))
    assert _by_key(base)["risk:pass"].status == "degraded"
    old = run(checks.check_risk_intel(_DB([_row("risk", checks.RISK_PASS_DOWN_H + 1)])))
    assert _by_key(old)["risk:pass"].status == "down"
    assert "vechi" in _by_key(old)["risk:pass"].detail


def test_a_pass_that_never_succeeded_says_so():
    out = _by_key(run(checks.check_risk_intel(_DB([_row("risk", None, error="boom")]))))
    assert out["risk:pass"].status == "degraded" and "boom" in out["risk:pass"].detail


def test_epss_without_a_row_is_unknown_once_the_pass_exists():
    out = _by_key(run(checks.check_risk_intel(_DB([_row("risk", 0.1)]))))
    assert out["risk:epss"].status == "unknown"
    assert "risk_score" in out["risk:epss"].detail
    assert "GRI" not in out["risk:epss"].detail, (
        "EPSS is no longer a decision point: its absence must not be reported as "
        "greying the findings, which would send the operator after the wrong cause")


def test_vulnrichment_without_a_row_is_unknown_once_the_pass_exists():
    """Without it no CVE has Exploitation and every finding with a CVE is grey: the
    one source whose silence changes the colours."""
    out = _by_key(run(checks.check_risk_intel(_DB([_row("risk", 0.1)]))))
    assert out["risk:vulnrichment"].status == "unknown"
    assert "GRI" in out["risk:vulnrichment"].detail


def test_a_blind_vulnrichment_parser_degrades_even_though_the_source_answers():
    """The loud failure (HTTP 503) is easy. The quiet one is a 200 response whose
    CISA container the parser no longer finds: every CVE then reads "CISA has
    evaluated nothing", Exploitation falls to "not in KEV", and the pass reports
    success. `ensure` marks it `blind` when 20+ CVEs arrive with zero points AND a
    control CVE known to carry points did not confirm the parser (it came back
    without points, or could not be read). The text says so: an operator who reads
    "zero points" alone cannot tell this from a Debian batch."""
    rows = [_row("risk", 0.1), _row("vulnrichment", 0.1, error="20 CVE-uri primite",
                                    detail={"blind": True, "asked": 40,
                                            "canary": "control_blind"})]
    out = _by_key(run(checks.check_risk_intel(_DB(rows))))
    assert out["risk:vulnrichment"].status == "degraded"
    assert "zero puncte SSVC" in out["risk:vulnrichment"].detail
    assert "controlul pozitiv" in out["risk:vulnrichment"].detail


def test_a_healthy_vulnrichment_is_ok_and_a_stale_or_aborted_one_degrades():
    ok = _by_key(run(checks.check_risk_intel(_DB([_row("risk", 0.1), _row("vulnrichment", 2.0)]))))
    assert ok["risk:vulnrichment"].status == "ok"
    stale = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("vulnrichment", checks.VENDOR_DEGRADED_H + 1, error="HTTP 503")]))))
    assert stale["risk:vulnrichment"].status == "degraded"
    aborted = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("vulnrichment", 1.0, error="HTTP 503",
                                 detail={"aborted": True})]))))
    assert aborted["risk:vulnrichment"].status == "degraded"
    assert "eșecuri consecutive" in aborted["risk:vulnrichment"].detail


def test_stale_epss_degrades_and_past_the_usable_age_is_down():
    """After `epss.MAX_AGE_DAYS` the values are no longer used (the findings keep
    their colour but lose the ordering number), so the check must say "down", not
    just "degraded"."""
    soft = _by_key(run(checks.check_risk_intel(_DB([_row("risk", 0.1),
                                                    _row("epss", checks.EPSS_DEGRADED_H + 1,
                                                         error="HTTP 503")]))))
    assert soft["risk:epss"].status == "degraded" and "HTTP 503" in soft["risk:epss"].detail
    hard = _by_key(run(checks.check_risk_intel(_DB([_row("risk", 0.1),
                                                    _row("epss", epss.MAX_AGE_DAYS * 24 + 1)]))))
    assert hard["risk:epss"].status == "down"
    assert "nu mai sunt folosite" in hard["risk:epss"].detail


def test_a_vendor_that_aborted_after_consecutive_failures_degrades():
    rows = [_row("risk", 0.1), _row("redhat", 1.0, error="HTTP 503",
                                    detail={"aborted": True, "errors": 5, "deferred": 15})]
    out = _by_key(run(checks.check_risk_intel(_DB(rows))))
    assert out["risk:redhat"].status == "degraded"
    assert "eșecuri consecutive" in out["risk:redhat"].detail


def test_a_partial_vendor_failure_stays_ok_but_keeps_its_warning():
    rows = [_row("risk", 0.1), _row("osv", 1.0, error="HTTP 503", detail={"errors": 1})]
    out = _by_key(run(checks.check_risk_intel(_DB(rows))))
    assert out["risk:osv"].status == "ok" and "HTTP 503" in out["risk:osv"].detail


def test_a_vendor_never_asked_for_is_not_reported_at_all():
    """No Red Hat row on a host with no rpm findings is "not needed", not "down"."""
    out = _by_key(run(checks.check_risk_intel(_DB([_row("risk", 0.1), _row("epss", 1.0)]))))
    assert "risk:redhat" not in out and "risk:osv" not in out


def test_the_check_is_registered():
    """A check written and never added to `CHECKS` never runs, in silence."""
    names = [name for name, _ in checks.CHECKS]
    assert "risk" in names
    assert dict(checks.CHECKS)["risk"] is checks.check_risk_intel
