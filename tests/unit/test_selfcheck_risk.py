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


def _row(source, ok_h=1.0, error=None, detail=None, attempt_h=None):
    """`attempt_h`: age of the last PASS (`last_attempt_at`); `None` leaves the column out,
    as a row from before the quiet-pass record would."""
    row = {"source": source, "last_attempt_at": "x", "last_ok_at": None if ok_h is None else "x",
           "last_error": error, "detail": json.dumps(detail or {}),
           "ok_age_s": None if ok_h is None else ok_h * 3600}
    if attempt_h is not None:
        row["attempt_age_s"] = attempt_h * 3600
    return row


def _by_key(results):
    return {r.key: r for r in results}


def _canary(verdict="control_ok", ok_h=0.2, error=None, **detail):
    """The control's own row (`vulnrichment_canary`): `ok_h` is the age of the last
    CONFIRMATION (`last_ok_at`), not of the last attempt."""
    return _row("vulnrichment_canary", ok_h, error=error,
                detail={"canary": verdict, "control_cve": "CVE-2025-29927", **detail})


def _vr(*rows, lookups_h=0.2):
    """The state of the source: the lookups row plus whatever the control left."""
    return _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("vulnrichment", lookups_h), *rows]))))["risk:vulnrichment"]


def test_no_evaluation_at_all_is_unknown_not_ok():
    """No row for `risk` means nothing has ever been evaluated: every finding is
    grey. "Nothing recorded" must not read as "nothing wrong"."""
    out = _by_key(run(checks.check_risk_intel(_DB([]))))
    assert out["risk:pass"].status == "unknown"
    assert "GRI" in out["risk:pass"].detail


def test_a_healthy_pass_is_ok_and_names_the_grey_count_without_alarming():
    rows = [_row("risk", 0.5, detail={"colors": {"red": 1, "grey": 25, "green": 783}, "findings": 809}),
            _row("epss", 5.0), _row("vulnrichment", 2.0), _canary(), _row("redhat", 3.0),
            _row("osv", 3.0)]
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
    success. The control (CVEs known to carry points, asked live on every pass) came back
    without points. The text says so, and it says the alarm stays until a control
    confirms the parser."""
    out = _vr(_canary("control_blind", ok_h=None, error="controlul vine FĂRĂ puncte"))
    assert out.status == "degraded"
    assert "controlul pozitiv" in out.detail and "fără puncte SSVC" in out.detail
    assert "până când o nouă încercare" in out.detail.lower()


def test_the_lookups_succeeding_does_not_clear_a_blind_verdict():
    """The lookups row is fresh and clean (an ordinary pass answered a minute ago); the
    control row says blind. The check must read the control, not the lookups: this is the
    pairing that used to say "ok" within the hour."""
    out = _vr(_canary("control_blind", ok_h=None, error="x"), lookups_h=0.01)
    assert out.status == "degraded"


def test_ok_needs_a_confirmation_and_not_just_answers_from_the_source():
    """"CISA Vulnrichment: ok" claims the parser still sees points. With no control row
    that is not a fact, only the lookups answering: unknown, not ok."""
    out = _vr()
    assert out.status == "unknown" and "controlul pozitiv nu a rulat" in out.detail
    ok = _vr(_canary())
    assert ok.status == "ok" and "CVE-2025-29927" in ok.detail


def test_an_ok_verdict_goes_stale_when_nothing_reconfirms_it():
    """`control_ok` written 30 hours ago and no attempt since (the pass stopped reaching
    the step, the source was switched off): the verdict is still "ok" in the row, but the
    claim "the parser sees points" has no evidence younger than the bound."""
    fresh = _vr(_canary(ok_h=checks.CANARY_UNCONFIRMED_H - 0.5))
    assert fresh.status == "ok"
    stale = _vr(_canary(ok_h=checks.CANARY_UNCONFIRMED_H + 0.5))
    assert stale.status == "degraded" and "reconfirmat" in stale.detail


def test_an_unreadable_control_is_unknown_for_as_long_as_the_lookups_branch_would_tolerate():
    """The CVE service is outside the host: three hourly passes that cannot reach it are an
    upstream fact the operator cannot fix, and `degraded` rings on Telegram. The lookups
    branch of the SAME check key tolerates `VENDOR_DEGRADED_H` for the same fact, so the
    control gets the same bound: `unknown` (not announced, not "ok") until then, `degraded`
    after. Before this, three hours of an upstream outage paged the operator about something
    nothing on the host could change, while the lookups stayed quiet for 36."""
    recent = _vr(_canary("control_unreadable", ok_h=1.0, error="503"))
    assert recent.status == "unknown" and "ultima confirmare acum" in recent.detail
    just_past_three = _vr(_canary("control_unreadable", ok_h=checks.CANARY_UNCONFIRMED_H + 1,
                                  error="503"))
    assert just_past_three.status == "unknown" and not just_past_three.bad, (
        "an upstream outage of four hours paged the operator")
    inside = _vr(_canary("control_unreadable", ok_h=checks.VENDOR_DEGRADED_H - 1, error="503"))
    assert inside.status == "unknown"
    old = _vr(_canary("control_unreadable", ok_h=checks.VENDOR_DEGRADED_H + 1, error="503"))
    assert old.status == "degraded"
    never = _vr(_canary("control_unreadable", ok_h=None, error="503"))
    assert never.status == "degraded" and "niciodată" in never.detail, (
        "with no confirmation there is no start of the outage to measure from")


def test_the_two_thresholds_for_one_external_fact_cannot_drift_apart():
    """The control and the lookups both fail when the CVE service is down. If the control's
    bound were shorter it would ring first and the operator would hear about one outage in
    two voices; if longer, an outage the lookups already call degraded would show `unknown`
    here. They are one number."""
    assert checks.CANARY_UNREADABLE_H == checks.VENDOR_DEGRADED_H


def test_an_outage_past_the_bound_is_one_alarm_not_two():
    """Lookups AND control both past 36 hours (the service has been down for two days): the
    key `risk:vulnrichment` carries ONE result, the lookups' one, not a second about the
    control."""
    out = run(checks.check_risk_intel(_DB([
        _row("risk", 0.1), _row("vulnrichment", checks.VENDOR_DEGRADED_H + 2, error="HTTP 503"),
        _canary("control_unreadable", ok_h=checks.VENDOR_DEGRADED_H + 2, error="503")])))
    mine = [r for r in out if r.key == "risk:vulnrichment"]
    assert len(mine) == 1 and mine[0].status == "degraded"
    assert "căutările eșuează" in mine[0].title


def test_an_unreadable_control_beside_a_suspect_batch_is_degraded_at_once():
    """The old alarm, kept whole: 20+ CVEs and not one point, and the control cannot be
    read to tell a Debian batch from a blind parser. That combination was "blind" before and
    still is, whatever confirmation is on record. The service answered for 20+ CVEs in that
    very pass, so it is not the upstream outage the grace period is for."""
    out = _vr(_canary("control_unreadable", ok_h=0.5, error="503", suspect_batch=True))
    assert out.status == "degraded"


def test_an_ok_verdict_that_nothing_renews_still_goes_stale_at_three_hours():
    """`stale` keeps the short bound: its cause is the hourly pass no longer reaching the
    control, which is a fact about the host. Only the unreadable branch got the long one."""
    assert _vr(_canary(ok_h=checks.CANARY_UNCONFIRMED_H + 0.5)).status == "degraded"
    assert checks.CANARY_UNCONFIRMED_H < checks.CANARY_UNREADABLE_H


def test_exhausted_candidates_name_the_list_to_replace_not_a_broken_parser():
    """All three candidates lost their points while the host's own CVEs still parse to
    points. Saying "the parser changed" (what `blind` says) sends the operator to the wrong
    code. This says what to edit, and says the parser is not what is judged broken. Degraded
    (it rings): nothing upstream will heal a spent candidate list, only the operator can,
    and an `unknown` is never announced, so the lost cover would stay silent."""
    old = _vr(_canary("control_exhausted", ok_h=checks.CANARY_UNCONFIRMED_H + 1,
                      error="candidatele controlului au rămas fără puncte SSVC"))
    assert old.status == "degraded"
    assert "CANARY_CONTROL_CVES" in old.action
    assert "NU e dat drept orb" in old.detail
    assert "schimbat" not in old.detail and "formatul" not in old.detail
    from sentinel.selfcheck import runner
    text = runner.format_alert([old], [])
    assert "CANARY_CONTROL_CVES" in text and "parser orb" not in text
    never = _vr(_canary("control_exhausted", ok_h=None, error="x"))
    assert never.status == "degraded"
    fresh = _vr(_canary("control_exhausted", ok_h=1.0, error="x"))
    assert fresh.status == "unknown" and not fresh.bad, (
        "one pass of candidates without points (a record being re-scored) must not page")


def test_a_blind_verdict_still_names_the_parser():
    """The counterpart: `blind` keeps its own words, so the two states cannot be confused."""
    out = _vr(_canary("control_blind", ok_h=None, error="x"))
    assert "formatul" in out.detail and "CANARY_CONTROL_CVES" not in out.action


def test_a_healthy_vulnrichment_is_ok_and_a_stale_or_aborted_one_degrades():
    ok = _vr(_canary())
    assert ok.status == "ok"
    stale = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("vulnrichment", checks.VENDOR_DEGRADED_H + 1, error="HTTP 503"),
         _canary()]))))
    assert stale["risk:vulnrichment"].status == "degraded"
    aborted = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("vulnrichment", 1.0, error="HTTP 503",
                                 detail={"aborted": True}), _canary()]))))
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


def _quiet(source, ok_h, attempt_h=0.2, **extra):
    """A row as `mirror.record_idle` leaves it: the last REAL answer is `ok_h` old, the last
    pass (which asked nobody) is `attempt_h` old."""
    return _row(source, ok_h, detail={"idle": True, "asked": 0, **extra}, attempt_h=attempt_h)


def test_a_quiet_week_is_not_a_failing_source_for_redhat_and_osv():
    """The page that rang for nothing: the last real answer 40 hours ago (past the old
    36-hour bound), the pass an hour ago, and it had nothing due. Nothing failed, so it is
    `ok` and says why the answer is old. The SAME ages without the quiet record -- a pass
    that asked and failed leaves `idle` unset -- are `degraded`: the bound did not move."""
    rows = [_row("risk", 0.1), _quiet("redhat", 40.0), _quiet("osv", 100.0)]
    out = _by_key(run(checks.check_risk_intel(_DB(rows))))
    for key in ("risk:redhat", "risk:osv"):
        assert out[key].status == "ok" and not out[key].bad, out[key].detail
        assert "nimic la termen" in out[key].detail and "ultimul răspuns real" in out[key].detail
        assert out[key].facts["idle"] is True
    failing = [_row("risk", 0.1), _row("redhat", 40.0, error="HTTP 503", attempt_h=0.2),
               _row("osv", 100.0, error="HTTP 503", attempt_h=0.2)]
    out = _by_key(run(checks.check_risk_intel(_DB(failing))))
    assert out["risk:redhat"].status == "degraded" and out["risk:osv"].status == "degraded"
    assert out["risk:redhat"].facts["idle"] is False


def test_a_quiet_record_whose_pass_is_old_is_not_a_quiet_source():
    """`idle` only says what the LAST pass found. If that pass is itself older than the
    bound, nothing has reached the source for a day and a half, and the check says so
    instead of "ok": the quiet record does not outlive the pass that wrote it. Text says
    the pass stopped; it must not send the operator after a lookup error that is not there."""
    out = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _quiet("redhat", 80.0, attempt_h=checks.VENDOR_DEGRADED_H + 1)]))))
    assert out["risk:redhat"].status == "degraded"
    assert "nicio trecere" in out["risk:redhat"].detail
    assert "nu e o eroare a căutărilor" in out["risk:redhat"].detail
    inside = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _quiet("redhat", 80.0, attempt_h=checks.VENDOR_DEGRADED_H - 1)]))))
    assert inside["risk:redhat"].status == "ok"


def test_a_row_without_the_attempt_age_is_never_read_as_quiet():
    """The check cannot know how old the pass is when the column is missing: "cannot read"
    must not turn into "quiet". Same for an `idle` flag that is not literally true."""
    no_age = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("redhat", 60.0, detail={"idle": True})]))))
    assert no_age["risk:redhat"].status == "degraded"
    for flag in ("true", 1, "yes"):
        out = _by_key(run(checks.check_risk_intel(_DB(
            [_row("risk", 0.1), _row("redhat", 60.0, detail={"idle": flag}, attempt_h=0.2)]))))
        assert out["risk:redhat"].status == "degraded", flag


def test_an_aborted_pass_is_never_quiet_whatever_else_the_row_says():
    rows = [_row("risk", 0.1), _row("redhat", 1.0, error="HTTP 503", attempt_h=0.1,
                                     detail={"idle": True, "aborted": True})]
    out = _by_key(run(checks.check_risk_intel(_DB(rows))))
    assert out["risk:redhat"].status == "degraded" and "eșecuri consecutive" in out["risk:redhat"].detail


def test_an_aborted_vulnrichment_pass_is_never_quiet_either():
    """Same rule on the CISA branch, which has its own copy of the condition."""
    out = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _row("vulnrichment", 1.0, error="HTTP 503", attempt_h=0.1,
                                 detail={"idle": True, "aborted": True}), _canary()]))))
    assert out["risk:vulnrichment"].status == "degraded"
    assert "eșecuri consecutive" in out["risk:vulnrichment"].detail


def test_a_source_that_has_never_answered_but_had_nothing_to_ask_is_ok_and_does_not_crash():
    """A quiet pass can create the row before any answer exists (every id filtered out):
    `last_ok_at` is NULL. The old text formatted `age * 60` on that and would raise; the
    honest reading is "nothing was due yet", not "never answered" (a failure) and not a
    crashed check (which the runner would turn into `unknown` for the WHOLE `risk` group)."""
    out = _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _quiet("redhat", None), _quiet("osv", None),
         _quiet("vulnrichment", None), _canary()]))))
    for key in ("risk:redhat", "risk:osv", "risk:vulnrichment"):
        assert out[key].status == "ok", (key, out[key].detail)
        assert "nicio căutare n-a fost necesară" in out[key].detail


def test_a_quiet_vulnrichment_still_answers_to_the_control():
    """Quiet lookups say nothing about the PARSER, and the parser is what the key is for: a
    blind control is `degraded` whatever the lookups row says, and an unconfirmed one is not
    `ok`. The control row, not the lookups, decides these."""
    ok = _vr_quiet(_canary())
    assert ok.status == "ok" and "nimic la termen" in ok.detail and "CVE-2025-29927" in ok.detail
    assert _vr_quiet(_canary("control_blind", ok_h=None, error="x")).status == "degraded"
    assert _vr_quiet().status == "unknown"
    exhausted = _vr_quiet(_canary("control_exhausted", ok_h=None, error="x"))
    assert exhausted.status == "degraded" and "nimic de cerut" in exhausted.detail


def _vr_quiet(*rows, lookups_h=60.0):
    return _by_key(run(checks.check_risk_intel(_DB(
        [_row("risk", 0.1), _quiet("vulnrichment", lookups_h), *rows]))))["risk:vulnrichment"]


def test_the_check_is_registered():
    """A check written and never added to `CHECKS` never runs, in silence."""
    names = [name for name, _ in checks.CHECKS]
    assert "risk" in names
    assert dict(checks.CHECKS)["risk"] is checks.check_risk_intel
