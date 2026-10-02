"""The traffic light: SSVC decision, two axes, the ordering number.

What goes wrong for the operator if these are wrong, in order of how quietly it
happens:

  * a finding nobody could evaluate shown green ("safe") — the failure the brief
    names as unacceptable: a CVE without a score is not a safe one;
  * the ordering number averaging instead of multiplying, so a CVSS 9.8 with
    EPSS 0.001 outranks a CVSS 5.0 with EPSS 0.6;
  * a colour drawn from a threshold we invented instead of the published tree, or
    Exploitation (an OBSERVATION) derived from EPSS (a FORECAST);
  * the Red Hat score attributed to the scanner (or the reverse), so the page
    names a deciding source that did not decide.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone

import pytest

from sentinel.intel import epss as epss_mod
from sentinel.intel import osv as osv_mod
from sentinel.intel import redhat as redhat_mod
from sentinel.intel import vulnrichment as vr_mod
from sentinel.scan import risk, ssvc

TODAY = date(2026, 10, 2)

WIDE_OPEN_TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"      # 9.8, auto, total
WIDE_OPEN_DOS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"          # 7.5, auto, partial
LOCAL_TOTAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"            # 7.8, not auto, total


def epss(p: float, pct: float = 0.5, days_old: int = 1) -> epss_mod.Row:
    return epss_mod.Row(p, pct, date.fromordinal(TODAY.toordinal() - days_old))


def vr(exploitation="none", automatable=None, technical_impact=None,
       at=datetime(2026, 9, 1, tzinfo=timezone.utc), status="found") -> vr_mod.Row:
    """What CISA published for a CVE. The default is the everyday case: CISA looked
    and saw no exploitation, and published nothing about the other two points
    (so they fall back to the CVSS vector)."""
    published = status == "found" and (
        exploitation or automatable or technical_impact) is not None
    return vr_mod.Row(status, exploitation, automatable, technical_impact,
                      at if published else None, "2.0.3" if published else None, at)


def intel(**kw) -> risk.Intel:
    """By default CISA has published `none` for the test CVE: the base state of the
    bulk of the findings. A test about an UNKNOWN passes `vulnrichment={}`."""
    base = dict(epss={}, redhat={}, osv={}, kev={}, kev_usable=True, today=TODAY,
                vulnrichment={"CVE-2026-0001": vr()})
    base.update(kw)
    return risk.Intel(**base)


def active(cve="CVE-2026-0001"):
    return {cve: vr("active")}


def finding(**kw) -> dict:
    base = dict(scanner="trivy_image", ecosystem="npm", cve="CVE-2026-0001",
                advisory_id=None, severity="high", cvss=7.5, cvss_vector=WIDE_OPEN_DOS,
                kev=False, kev_due_date=None, risk={}, fix_pending_reboot=False)
    base.update(kw)
    return base


def rh_row(score=7.5, vector=WIDE_OPEN_DOS, severity="Important", status="found"):
    return redhat_mod.Row(status, score, vector, "3.1", severity, "because", (), (), None)


# ---------------------------------------------------------------------------
# The tree, end to end, on cases measured on the production host (2 Oct 2026)
# ---------------------------------------------------------------------------
def test_an_exploited_automatable_total_cve_is_red():
    """CISA says exploitation is active (not in KEV), network/no privileges,
    confidentiality+integrity lost: the tree says Act, and the page says it was
    CISA who said so."""
    a = risk.assess(finding(cvss=9.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
                    intel(vulnrichment=active(), epss={"CVE-2026-0001": epss(0.5)}))
    assert (a.color, a.decision) == ("red", "act")
    assert a.risk["points"]["exploitation"] == {"value": "active", "basis": "vulnrichment",
                                                "as_of": "2026-09-01"}


def test_a_high_epss_never_becomes_observed_exploitation_but_a_stale_photograph_lifts_the_colour():
    """CVE-2025-29927 (Next.js middleware bypass), the one red of round 1: EPSS
    0.992, not in KEV, and CISA publishes Exploitation `none` (as of 2025-04-08,
    542 days before the test's `today`). Two things are true at once and the page
    must keep them apart:

      * SSVC's Exploitation is what was OBSERVED; EPSS is a forecast, and a
        forecast must not turn into an observation. The point stays `none`,
        basis `vulnrichment`, dated; the SSVC decision stays Track;
      * but the observation EPSS contradicts was never refreshed, and Sentinel's
        OWN rule (not SSVC's, not FIRST's) keeps the colour from sinking below
        amber. The operator sees amber, EPSS 99.2%, and the record says
        `epss_overlay` with the decision SSVC would have given.

    Before the rule, this row was green Track and ranked 40th of 812 on the real
    host: an exploit-public auth bypass sorted below 22 grey rows."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    stale_none = {"CVE-2026-0001": vr("none", "yes", "total",
                                      at=datetime(2025, 4, 8, 15, 16, tzinfo=timezone.utc))}
    a = risk.assess(finding(cvss=9.1, cvss_vector=vector),
                    intel(vulnrichment=stale_none,
                          epss={"CVE-2026-0001": epss(0.99225, 0.99936)}))
    assert (a.color, a.decision) == ("amber", "attend")
    assert a.risk["points"]["exploitation"] == {"value": "none", "basis": "vulnrichment",
                                                "as_of": "2025-04-08"}
    assert a.risk["overlay"] == {
        "basis": "epss_overlay", "floor": "attend", "ssvc_decision": "track",
        "epss": 0.99225, "observation_as_of": "2025-04-08", "observation_age_days": 542,
        "min_epss": 0.5, "min_age_days": 180}
    assert a.risk["epss"]["p"] == pytest.approx(0.99225)
    assert a.risk["likelihood_basis"] == "epss"
    assert a.score == pytest.approx(0.91 * 0.99225, rel=1e-3)
    assert 60 <= a.priority < 80, "an overlay row belongs to the amber band"
    # The same facts with a FRESH photograph: nothing to overlay, the tree decides.
    fresh = {"CVE-2026-0001": vr("none", "yes", "total",
                                 at=datetime(2026, 9, 1, tzinfo=timezone.utc))}
    b = risk.assess(finding(cvss=9.1, cvss_vector=vector),
                    intel(vulnrichment=fresh, epss={"CVE-2026-0001": epss(0.99225, 0.99936)}))
    assert (b.color, b.decision) == ("green", "track") and "overlay" not in b.risk
    # What moves the colour for real is what CISA publishes.
    now_active = risk.assess(finding(cvss=9.1, cvss_vector=vector),
                             intel(vulnrichment={"CVE-2026-0001": vr("active", "yes", "total")},
                                   epss={"CVE-2026-0001": epss(0.99225, 0.99936)}))
    assert (now_active.color, now_active.decision) == ("red", "act")
    assert "overlay" not in now_active.risk


def test_a_kev_listed_cve_is_active_exploitation_whatever_its_epss():
    """CVE-2026-53266 on `linux-libc-dev`: KEV, EPSS 0.006, local/complex."""
    a = risk.assess(finding(cvss=7.5, cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"),
                    intel(epss={"CVE-2026-0001": epss(0.00645)}, kev={"CVE-2026-0001": date(2026, 10, 9)}))
    assert a.risk["points"]["exploitation"] == {"value": "active", "basis": "kev"}
    assert (a.color, a.decision) == ("amber", "attend")     # active/no/total/medium
    assert a.kev is True and a.kev_due == date(2026, 10, 9)


def test_an_exploited_full_disclosure_of_the_component_is_amber_not_red():
    """Citrix-Bleed shape: KEV, network/no privileges, confidentiality lost and
    integrity untouched (C:H/I:N), no CISA value for Technical Impact so the vector
    decides. CVSS `C:H` is total loss within the COMPONENT; SSVC's `total` is "all
    information on the SYSTEM". CISA calls 19 of the 20 such CVEs on the host
    `partial`, so the fallback says `partial` and the tree gives Attend. The
    version that read `C:H` alone as `total` painted these red, and as a whole
    disagreed with CISA on 40 of 189 CVEs (10 with `and`); the operator would have
    seen Act on a heuristic CISA's own practice does not share."""
    a = risk.assess(finding(cvss=9.1, kev=True,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
                    intel(epss={"CVE-2026-0001": epss(0.5)}))
    assert a.risk["points"]["technical_impact"] == {"value": "partial", "basis": "cvss_vector"}
    assert (a.color, a.decision) == ("amber", "attend")      # active / yes / partial / medium


def test_a_local_kev_with_component_disclosure_is_green_but_still_a_kev():
    """CVE-2024-53150 on the real Red Hat vector (AV:L/AC:L/PR:L/UI:N C:H/I:N/A:H):
    in KEV, local, so not automatable, and `partial` (CISA itself publishes
    `partial` for this CVE). The tree says Track: the row is green, which is a
    decision of the tree and is why the flag, the 🔥 and the KEV card exist
    separately from the colour. What must NOT happen is the KEV disappearing
    from the row because the colour is quiet."""
    a = risk.assess(finding(cvss=7.1, kev=True,
                            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H"),
                    intel(epss={"CVE-2026-0001": epss(0.001)}))
    assert (a.color, a.decision) == ("green", "track")
    assert a.kev is True and a.risk["points"]["exploitation"]["value"] == "active"
    assert a.risk["kev"] == {"due": None}


def test_a_cisa_active_partial_automatable_cve_is_amber():
    """Exploited per CISA, availability only, network/no privileges: Attend."""
    a = risk.assess(finding(), intel(vulnrichment=active()))
    assert (a.color, a.decision) == ("amber", "attend")


def test_a_high_epss_with_cisa_none_stays_green_for_a_partial_cve_too():
    """CVE-2023-45288 (Go HTTP/2): EPSS 0.92, availability only, CISA `none` as of
    2024-04-05. Round 1 made this one amber from the forecast alone."""
    a = risk.assess(finding(), intel(epss={"CVE-2026-0001": epss(0.91969, 0.998)}))
    assert (a.color, a.decision) == ("green", "track")


def test_the_everyday_cve_is_green_track():
    """A CVSS 7.5 network DoS with EPSS 0.4% — the bulk of the 812 open
    findings. The tree says "standard update timeline", and so does the page."""
    a = risk.assess(finding(), intel(epss={"CVE-2026-0001": epss(0.004)}))
    assert (a.color, a.decision) == ("green", "track")


def test_epss_never_picks_the_colour_nor_any_decision_point():
    """The colour is `ssvc.decide(...)` of the four points, and EPSS is not one of
    them: for every EPSS value (and with none at all) the points, the decision
    and the colour are identical. EPSS only moves the ordering number.

    The one exception is Sentinel's own overlay (CISA's evaluation older than 180
    days AND EPSS >= 0.5), and it is excluded here on purpose by the photograph's
    age (31 days): the tests below pin the overlay, including that it never touches
    `points`."""
    baseline = risk.assess(finding(), intel())
    for p in (0.0, 0.0001, 0.02, 0.3, 0.49, 0.5, 0.7, 0.89, 0.9, 0.99, 1.0):
        a = risk.assess(finding(), intel(epss={"CVE-2026-0001": epss(p)}))
        assert a.risk["points"] == baseline.risk["points"], p
        assert (a.decision, a.color) == (baseline.decision, baseline.color), p
        pts = a.risk["points"]
        assert a.decision == ssvc.decide(pts["exploitation"]["value"],
                                         pts["automatable"]["value"],
                                         pts["technical_impact"]["value"],
                                         pts["mission"]["value"])
        assert a.color == ssvc.COLOR_OF[a.decision]
    assert baseline.score is None, "no EPSS must mean no ordering number, not a zero"


def test_the_unpublished_default_moves_no_colour_at_medium_mission_but_does_at_high():
    """`UNPUBLISHED_EXPLOITATION` is Sentinel's own choice (no source says what to
    put when CISA has not evaluated a CVE and it is not in KEV), and what the
    docstring tells the operator about it is that it is harmless at the mission
    every finding gets today and load-bearing one level up. That statement is
    about the SSVC table, so pin it there: if the table is ever swapped (the
    module says it can be), the operator is not left trusting a "does not matter"
    that stopped being true."""
    def colours(mission, exploitation):
        return {(auto, ti): ssvc.COLOR_OF[ssvc.TABLE[(exploitation, auto, ti, mission)]]
                for auto in ssvc.AUTOMATABLE for ti in ssvc.TECHNICAL_IMPACT}
    assert colours("medium", "none") == colours("medium", "poc")
    assert colours("low", "none") == colours("low", "poc")
    assert colours("high", "none") != colours("high", "poc")


# ---------------------------------------------------------------------------
# Sentinel's own rule: a high EPSS beside a CISA observation nobody refreshed
# ---------------------------------------------------------------------------
TODAY_MINUS = lambda days: datetime.combine(  # noqa: E731 - a one-line date helper
    date.fromordinal(TODAY.toordinal() - days), datetime.min.time(), tzinfo=timezone.utc)


def stale_photo(exploitation="none", age_days=543, **kw):
    return {"CVE-2026-0001": vr(exploitation, at=TODAY_MINUS(age_days), **kw)}


def test_the_overlay_needs_an_observation_older_than_180_days_and_exactly_that():
    """Age 180 is not "older than 180": a rule that fires one day early turns
    every row with a half-year-old photograph amber and the operator learns to
    read amber as noise; one that fires a day late is the same defect, quieter."""
    for age, lifted in ((179, False), (180, False), (181, True), (543, True)):
        a = risk.assess(finding(), intel(vulnrichment=stale_photo(age_days=age),
                                         epss={"CVE-2026-0001": epss(0.9)}))
        assert (a.color == "amber") is lifted, age
        assert ("overlay" in a.risk) is lifted, age
        if lifted:
            assert a.risk["overlay"]["observation_age_days"] == age


def test_the_age_is_the_age_of_the_cisa_evaluation_not_of_the_download():
    """The mirror re-asks a CVE every 7 days, so `fetched_at` is always recent while
    `ssvc_at` is the day CISA looked. Measured on the host: an evaluation downloaded
    this morning can be 542 days old. An age taken from the download would make
    every row look fresh and the rule would never fire in production, while every
    test that builds both dates equal would stay green."""
    row = vr_mod.Row("found", "none", "yes", "total", TODAY_MINUS(542), "2.0.3", TODAY_MINUS(0))
    a = risk.assess(finding(), intel(vulnrichment={"CVE-2026-0001": row},
                                     epss={"CVE-2026-0001": epss(0.9)}))
    assert a.color == "amber"
    assert a.risk["overlay"]["observation_age_days"] == 542
    recent = vr_mod.Row("found", "none", "yes", "total", TODAY_MINUS(10), "2.0.3", TODAY_MINUS(400))
    b = risk.assess(finding(), intel(vulnrichment={"CVE-2026-0001": recent},
                                     epss={"CVE-2026-0001": epss(0.9)}))
    assert b.color == "green", "an old DOWNLOAD of a recent evaluation is not a stale photograph"


def test_the_overlay_needs_epss_of_at_least_one_half_and_exactly_that():
    """0.5 is "more likely than not" in words. 0.4999 stays green, 0.5 lifts: the
    boundary is `>=`, and a test on one side only would let `>` pass."""
    for p, lifted in ((0.0, False), (0.04561, False), (0.4999, False), (0.5, True),
                      (0.5918, True), (1.0, True)):
        a = risk.assess(finding(), intel(vulnrichment=stale_photo(),
                                         epss={"CVE-2026-0001": epss(p)}))
        assert (a.color == "amber") is lifted, p


def test_the_overlay_is_not_applied_without_a_fresh_epss():
    """No EPSS, or one too old to use, is not a probability of 0.5: the row stays
    what the tree says, exactly as it did before the rule existed (an unknown
    EPSS never made a row grey, and it does not make one amber either)."""
    for epss_map in ({}, {"CVE-2026-0001": epss(0.99, days_old=30)}):
        a = risk.assess(finding(), intel(vulnrichment=stale_photo(), epss=epss_map))
        assert (a.color, a.decision) == ("green", "track") and "overlay" not in a.risk


def test_the_overlay_covers_a_stale_poc_too_and_leaves_active_and_kev_alone():
    """`none` and `poc` are observations EPSS can contradict. `active` is the
    strongest observation there is, and KEV is refreshed daily: neither is a
    stale photograph, and the tree's decision for them is not second-guessed."""
    hot = {"CVE-2026-0001": epss(0.9)}
    poc = risk.assess(finding(), intel(vulnrichment=stale_photo("poc"), epss=hot))
    assert poc.color == "amber" and poc.risk["overlay"]["ssvc_decision"] == "track"
    # active / no / partial / medium is Track: a stale CISA `active` must not be lifted.
    f = finding(cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", cvss=5.5)
    act = risk.assess(f, intel(vulnrichment=stale_photo("active", automatable="no",
                                                        technical_impact="partial"),
                               epss=hot))
    assert (act.color, act.decision) == ("green", "track") and "overlay" not in act.risk
    kev = risk.assess(f, intel(vulnrichment=stale_photo("none", automatable="no",
                                                        technical_impact="partial"),
                               epss=hot, kev={"CVE-2026-0001": date(2026, 10, 9)}))
    assert kev.risk["points"]["exploitation"]["basis"] == "kev"
    assert "overlay" not in kev.risk


def test_the_overlay_needs_an_observation_to_contradict():
    """A CVE CISA never evaluated (`kev_absent`) has no photograph, stale or not:
    Sentinel's own `none` is an assumption, not an observation, and this rule is
    about observations. It is a different question (the operator may want it) and
    it is NOT answered silently here."""
    a = risk.assess(finding(), intel(vulnrichment={"CVE-2026-0001": vr(None)},
                                     epss={"CVE-2026-0001": epss(0.99)}))
    assert a.risk["points"]["exploitation"]["basis"] == "kev_absent"
    assert (a.color, a.decision) == ("green", "track") and "overlay" not in a.risk


def test_the_overlay_never_rewrites_a_decision_point_nor_hides_what_ssvc_said():
    """`points` stays what CISA/KEV/the vector said (so the page keeps saying who
    decided what), and the SSVC decision is recoverable from the record: the
    tree applied to `points` equals `overlay.ssvc_decision`."""
    base = risk.assess(finding(), intel(vulnrichment=stale_photo()))
    a = risk.assess(finding(), intel(vulnrichment=stale_photo(),
                                     epss={"CVE-2026-0001": epss(0.9)}))
    assert a.risk["points"] == base.risk["points"]
    pts = a.risk["points"]
    assert a.risk["overlay"]["ssvc_decision"] == ssvc.decide(
        pts["exploitation"]["value"], pts["automatable"]["value"],
        pts["technical_impact"]["value"], pts["mission"]["value"])
    assert a.decision == risk.OVERLAY_FLOOR and a.color == ssvc.COLOR_OF[a.decision]


def test_the_overlay_never_lowers_a_colour_and_leaves_amber_and_red_unrecorded():
    """A floor: an Attend or Act row is untouched, and no `overlay` key appears on
    a row it did not change (the key means "this colour is Sentinel's, not SSVC's")."""
    hot = {"CVE-2026-0001": epss(0.9)}
    # high mission makes the same row Attend by itself (none / yes / partial / high)
    attend = risk.assess(finding(), intel(vulnrichment=stale_photo(), epss=hot),
                         criticality=5)
    assert (attend.color, attend.decision) == ("amber", "attend")
    assert "overlay" not in attend.risk
    act = risk.assess(finding(cvss=9.1, cvss_vector=WIDE_OPEN_TOTAL),
                      intel(vulnrichment=active(), epss=hot))
    assert (act.color, act.decision) == ("red", "act") and "overlay" not in act.risk


def test_the_overlay_does_not_turn_grey_into_amber():
    """Unknown is not a decision. A row whose Technical Impact and Automatable
    are unknown is grey whatever the EPSS says, and keeps saying what is missing."""
    a = risk.assess(finding(cvss=None, cvss_vector=None),
                    intel(vulnrichment=stale_photo(), epss={"CVE-2026-0001": epss(0.99)}))
    assert a.color == "grey" and a.decision is None
    assert "overlay" not in a.risk and a.risk["missing"] == ["cvss"]


def test_an_undated_evaluation_is_treated_as_stale_not_as_fine():
    """A CISA value whose evaluation date could not be read cannot be shown to be
    fresh. The page then says the date is unknown instead of a number of days."""
    row = vr("none", at=TODAY_MINUS(10))
    undated = vr_mod.Row("found", "none", None, None, None, "2.0.3", row.fetched_at)
    a = risk.assess(finding(), intel(vulnrichment={"CVE-2026-0001": undated},
                                     epss={"CVE-2026-0001": epss(0.9)}))
    assert a.color == "amber"
    assert a.risk["overlay"]["observation_age_days"] is None
    assert a.risk["overlay"]["observation_as_of"] is None


def test_the_floor_is_applied_before_the_reboot_demotion_so_the_overlay_can_say_reboot():
    """An overlay-lifted Attend whose fix is installed and waiting for a restart must
    drop one step like every other row. The floor used to be applied AFTER the
    demotion, so the overlay was the one row type whose colour could never say "the
    fix is installed, a reboot is pending": it stayed amber with the reboot mark while
    a KEV row in the same state went down. Four days were spent on exactly that
    distinction. Floor first (Track -> Attend), demotion on the result (Attend ->
    Track*, green); the record keeps both steps so nothing is hidden."""
    pending = risk.assess(finding(fix_pending_reboot=True),
                          intel(vulnrichment=stale_photo(), epss={"CVE-2026-0001": epss(0.9)}))
    assert (pending.color, pending.decision) == ("green", "track_star")
    assert pending.risk["reboot_pending"] is True
    assert pending.risk["decision_before_reboot"] == "attend"
    assert pending.risk["overlay"]["ssvc_decision"] == "track"
    # the same facts with the fix not waiting for a restart: still the lifted amber
    live = risk.assess(finding(),
                       intel(vulnrichment=stale_photo(), epss={"CVE-2026-0001": epss(0.9)}))
    assert (live.color, live.decision) == ("amber", "attend")
    # one step down, the same step a tree-decided Attend takes
    tree_attend = risk.assess(finding(fix_pending_reboot=True),
                              intel(vulnrichment=stale_photo(), epss={"CVE-2026-0001": epss(0.9)}),
                              criticality=5)
    assert tree_attend.decision == "track_star" and "overlay" not in tree_attend.risk
    # a lowered row is no longer Attend: it must not keep the lifted amber band
    assert (risk.priority_of(ssvc.TRACK_STAR, 0.0) <= pending.priority
            <= risk.priority_of(ssvc.TRACK_STAR, 1.0))


#: Cells (automatable, technical impact, mission) where the published tree says `track`
#: even when Exploitation is `active`. Written out by hand, from the CISA table, NOT
#: derived from `ssvc.TABLE`, so that a change to the table is seen here as a change.
_TRACK_EVEN_IF_ACTIVE = {("no", "partial", "low"), ("no", "partial", "medium"),
                         ("no", "total", "low")}
_MISSION_CRITICALITY = {"low": 1, "medium": 3, "high": 5}


def _overlay_cell(exploitation, automatable, technical, mission, **kw):
    """One cell of the tree with everything the overlay needs: a CISA evaluation
    older than 180 days (all three points published, so the cell is exactly the one
    named) and a fresh EPSS of 0.99."""
    photo = {"CVE-2026-0001": vr(exploitation, automatable, technical, at=TODAY_MINUS(543))}
    return risk.assess(finding(**kw), intel(vulnrichment=photo,
                                            epss={"CVE-2026-0001": epss(0.99)}),
                       criticality=_MISSION_CRITICALITY[mission])


def test_the_published_table_has_exactly_these_cells_where_active_is_still_track():
    """The premise of the next two tests, checked against the table itself: if CISA
    republishes the tree and this set changes, the bound must be looked at again."""
    derived = {(a, t, m) for a in ssvc.AUTOMATABLE for t in ssvc.TECHNICAL_IMPACT
               for m in ssvc.MISSION
               if ssvc.decide("active", a, t, m) == ssvc.TRACK}
    assert derived == _TRACK_EVEN_IF_ACTIVE


@pytest.mark.parametrize("exploitation", ["none", "poc"])
@pytest.mark.parametrize("automatable,technical,mission", sorted(_TRACK_EVEN_IF_ACTIVE))
def test_the_floor_never_claims_more_than_the_tree_would_under_active_exploitation(
        exploitation, automatable, technical, mission):
    """Six cells, all `automatable: no`, where a fixed `attend` floor exceeded CISA's
    own verdict: a stale `none`/`poc` beside EPSS 0.99 turned the row amber although
    the tree says Track even if the CVE were confirmed exploited. Sentinel's rule is
    its own, but it must not out-shout the tree under the worst observation: here the
    floor is Track, so there is nothing to lift, no `overlay`, no amber."""
    a = _overlay_cell(exploitation, automatable, technical, mission)
    assert ssvc.decide("active", automatable, technical, mission) == ssvc.TRACK
    assert a.decision in (ssvc.TRACK, ssvc.TRACK_STAR)
    assert a.color == "green" and "overlay" not in a.risk


def test_the_overlay_never_exceeds_the_tree_under_active_exploitation_in_any_cell():
    """The property over the whole space the overlay can touch (stale none/poc x every
    automatable x impact x mission, EPSS 0.99): the final decision is never above what
    the tree would say with Exploitation `active`, and the rows the rule DOES lift are
    exactly those where the tree under none/poc is below Attend and under active it
    reaches it."""
    lifted_cells = set()
    for exploitation in ("none", "poc"):
        for automatable in ssvc.AUTOMATABLE:
            for technical in ssvc.TECHNICAL_IMPACT:
                for mission in ssvc.MISSION:
                    a = _overlay_cell(exploitation, automatable, technical, mission)
                    worst = ssvc.decide("active", automatable, technical, mission)
                    tree = ssvc.decide(exploitation, automatable, technical, mission)
                    rank = ssvc.DECISIONS.index
                    assert rank(a.decision) <= rank(worst), (exploitation, automatable,
                                                            technical, mission)
                    assert rank(a.decision) >= rank(tree)
                    if "overlay" in a.risk:
                        lifted_cells.add((exploitation, automatable, technical, mission))
                        assert a.decision == "attend" == a.risk["overlay"]["floor"]
    expected = {(e, a, t, m)
                for e in ("none", "poc") for a in ssvc.AUTOMATABLE
                for t in ssvc.TECHNICAL_IMPACT for m in ssvc.MISSION
                if ssvc.DECISIONS.index(ssvc.decide(e, a, t, m)) < ssvc.DECISIONS.index("attend")
                and ssvc.DECISIONS.index(ssvc.decide("active", a, t, m)) >= ssvc.DECISIONS.index("attend")}
    assert lifted_cells == expected and lifted_cells, "the overlay lifted nothing at all"


def test_the_overlay_row_sorts_with_the_amber_band_not_among_the_greens():
    """The point of the rule, in the operator's terms: the row leaves the green
    band. Band bounds are the ones every other amber row lives in."""
    lifted = risk.assess(finding(), intel(vulnrichment=stale_photo(),
                                          epss={"CVE-2026-0001": epss(0.9)}))
    green = risk.assess(finding(), intel(vulnrichment={"CVE-2026-0001": vr()},
                                         epss={"CVE-2026-0001": epss(0.9)}))
    assert green.color == "green" and lifted.color == "amber"
    assert lifted.priority > green.priority and lifted.priority >= 60


# ---------------------------------------------------------------------------
# Unknown is grey, never green
# ---------------------------------------------------------------------------
def test_a_cve_nobody_asked_cisa_about_is_grey_not_green():
    """No row in `vulnrichment` means "not asked yet" (first pass, or the source is
    down), which is not the same as "CISA looked and published nothing". Reading
    the first as the second would show every CVE of a fresh install as Track."""
    a = risk.assess(finding(), intel(vulnrichment={}))
    assert a.color == "grey" and a.decision is None and a.score is None
    assert a.risk["missing"] == ["vulnrichment"]
    assert a.risk["possible"] == ["track", "attend"]


def test_a_cve_cisa_has_not_evaluated_is_an_answer_not_a_gap():
    """CISA has evaluated 196 of the host's 406 open CVEs (48%; 13 of 185 Debian
    ones). A CVE that exists but carries no CISA points (or that the CVE service
    answered 404 for) must still get a colour, with the weaker basis named: "grey"
    would bury the page under the half that CISA has not got to. The vector decides Automatable/Technical Impact, and Exploitation is
    `UNPUBLISHED_EXPLOITATION` because the KEV mirror is fresh and does not list it."""
    for row in (vr(None), vr(None, status="not_found")):
        a = risk.assess(finding(), intel(vulnrichment={"CVE-2026-0001": row}))
        assert a.color == "green" and "missing" not in a.risk
        pts = a.risk["points"]
        assert pts["exploitation"] == {"value": "none", "basis": "kev_absent"}
        assert pts["automatable"]["basis"] == pts["technical_impact"]["basis"] == "cvss_vector"


def test_the_unpublished_default_is_one_switch_and_none_means_grey(monkeypatch):
    """The choice above is Sentinel's, so it must be reversible in one line: with
    `UNPUBLISHED_EXPLOITATION = None` a CVE CISA has not evaluated is grey, with the
    reason named."""
    monkeypatch.setattr(risk, "UNPUBLISHED_EXPLOITATION", None)
    a = risk.assess(finding(), intel(vulnrichment={"CVE-2026-0001": vr(None)}))
    assert a.color == "grey" and a.risk["missing"] == ["exploitation_unpublished"]


def test_a_stale_epss_value_does_not_make_a_row_grey_but_is_not_used_to_order():
    """EPSS is no longer a decision point, so an old value cannot leave a row
    undecided; it also cannot be used as a probability, so there is no ordering
    number, and the page says the value was too old."""
    a = risk.assess(finding(), intel(epss={"CVE-2026-0001": epss(0.001, days_old=9)}))
    assert a.color == "green" and a.score is None
    assert a.risk["epss"]["stale"] is True and "missing" not in a.risk


def test_a_cve_epss_has_not_scored_still_gets_a_colour():
    row = epss_mod.Row(None, None, date(2026, 10, 1))
    a = risk.assess(finding(), intel(epss={"CVE-2026-0001": row}))
    assert a.color == "green" and a.score is None and "missing" not in a.risk


def test_without_a_vector_the_point_is_unknown_and_so_is_the_colour():
    """Even with exploitation known: an automatable/total flaw and a local DoS
    land on different colours, and without the vector nobody can say which."""
    a = risk.assess(finding(cvss=None, cvss_vector=None, severity="high"),
                    intel(vulnrichment=active()))
    assert a.color == "grey"
    assert "cvss" in a.risk["missing"]
    assert a.risk["possible"] == ["track", "act"]


def test_a_score_without_a_vector_still_measures_importance_but_stays_grey():
    a = risk.assess(finding(cvss=7.5, cvss_vector=None), intel())
    assert a.color == "grey"
    assert a.importance == 0.75
    assert "cvss_vector" in a.risk["missing"]


def test_an_unreadable_vector_is_the_same_as_none():
    a = risk.assess(finding(cvss_vector="AV:N/AC:L/Au:N/C:P/I:P/A:P"),   # CVSS v2
                    intel())
    assert a.color == "grey"


def test_a_missing_kev_mirror_makes_no_in_kev_claim():
    """With an empty or month-old KEV table, "not in KEV" cannot be said."""
    a = risk.assess(finding(), intel(kev_usable=False))
    assert a.color == "grey" and "kev_mirror" in a.risk["missing"]


def test_a_kev_hit_is_still_red_or_amber_with_a_dead_mirror():
    """What the scanner already marked KEV needs no mirror to be believed."""
    a = risk.assess(finding(kev=True), intel(kev_usable=False))
    assert a.risk["points"]["exploitation"]["value"] == "active"
    assert a.color != "grey"


def test_an_advisory_without_a_cve_has_nothing_to_look_up_and_is_grey():
    a = risk.assess(finding(cve=None, advisory_id="GHSA-8h8q-6873-q5fj"), intel())
    assert a.color == "grey" and "cve" in a.risk["missing"]


def test_a_ghsa_with_a_cve_alias_is_evaluated_through_the_alias():
    """7 of the 17 open GHSA ids have an alias; through it they get KEV, CISA's
    points and EPSS, and the page says that the CVE came from the alias."""
    row = osv_mod.Row("found", None, None, None, "HIGH", ("CVE-2026-92596",), None)
    a = risk.assess(finding(cve=None, advisory_id="GHSA-2x7j-588g-ccc2"),
                    intel(osv={"GHSA-2x7j-588g-ccc2": row},
                          vulnrichment={"CVE-2026-92596": vr()},
                          epss={"CVE-2026-92596": epss(0.004)}))
    assert a.color == "green"
    assert a.risk["cve"] == "CVE-2026-92596" and a.risk["cve_via"] == "GHSA-2x7j-588g-ccc2"


def test_grey_always_sorts_above_green_and_below_amber():
    """The brief: a CVE without a score is not a safe one. The best green and
    the worst grey must never swap places."""
    best_green = risk.priority_of(ssvc.TRACK_STAR, 1.0)
    worst_grey = risk.priority_of(None, 0.0)
    best_grey = risk.priority_of(None, 1.0)
    worst_amber = risk.priority_of(ssvc.ATTEND, 0.0)
    assert best_green < worst_grey
    assert best_grey < worst_amber


def test_the_bands_do_not_overlap_and_stay_within_zero_to_hundred():
    seen = []
    for dec, lifted in ((ssvc.TRACK, False), (ssvc.TRACK_STAR, False), (None, False),
                        (ssvc.ATTEND, True), (ssvc.ATTEND, False), (ssvc.ACT, False)):
        lo = risk.priority_of(dec, 0.0, lifted=lifted)
        hi = risk.priority_of(dec, 1.0, lifted=lifted)
        assert 0 <= lo <= hi <= 100
        seen.append((lo, hi))
    for (_, hi), (lo, _) in zip(seen, seen[1:]):
        assert hi < lo
    assert seen[-1][1] == 100
    assert risk.priority_of(None, None) == risk.UNASSESSED_PRIORITY == 40
    # the two halves of amber together are the 60..79 band the migration documents
    assert risk.priority_of(ssvc.ATTEND, 0.0, lifted=True) == 60
    assert risk.priority_of(ssvc.ATTEND, 1.0) == 79


def test_lifted_only_means_something_for_attend():
    """`lifted` is a sub-band of amber; passing it for any other decision must not move
    that decision into amber's priorities."""
    for dec in (ssvc.ACT, ssvc.TRACK_STAR, ssvc.TRACK, None):
        assert risk.priority_of(dec, 0.5, lifted=True) == risk.priority_of(dec, 0.5)


def test_an_observed_exploitation_ranks_above_a_predicted_one():
    """The operator's decision: what was OBSERVED goes before what is PREDICTED.
    On the real host CVE-2025-29927 (EPSS 0.992 x CVSS 9.1 = 0.903, no observation
    since 2025) stood 1st of 812 at priority 77, above both KEV rows (75 and 74),
    because inside amber the order was probability x impact and a KEV is only 1.0 x
    7.5. A forecast sat above a confirmed exploitation. Same facts here, through
    `assess`: the KEV row must outrank the overlay row, and so must the WORST possible
    tree-decided Attend outrank the BEST possible lifted one."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    photo = {"CVE-2026-0001": vr("none", "yes", "total", at=TODAY_MINUS(542))}
    lifted = risk.assess(finding(cvss=9.1, cvss_vector=vector),
                         intel(vulnrichment=photo, epss={"CVE-2026-0001": epss(0.99225)}))
    kev = risk.assess(finding(cvss=7.5, cvss_vector=WIDE_OPEN_DOS, kev=True),
                      intel(kev={"CVE-2026-0001": date(2026, 10, 9)},
                            epss={"CVE-2026-0001": epss(0.006)}))
    assert (lifted.color, lifted.decision) == ("amber", "attend") and "overlay" in lifted.risk
    assert (kev.color, kev.decision) == ("amber", "attend") and "overlay" not in kev.risk
    assert lifted.score > kev.score, "the premise: the forecast scores higher"
    assert kev.priority > lifted.priority
    # not only for this pair: the whole range
    assert risk.priority_of(ssvc.ATTEND, 0.0) > risk.priority_of(ssvc.ATTEND, 1.0, lifted=True)
    # and the lifted row is still amber and still above every grey
    assert 60 <= lifted.priority < 80 and lifted.priority > risk.priority_of(None, 1.0)




# ---------------------------------------------------------------------------
# Multiply, do not average
# ---------------------------------------------------------------------------
def test_the_ordering_number_is_probability_times_impact():
    """The brief's own pair: CVSS 9.8 / EPSS 0.001 against CVSS 5.0 / EPSS 0.6.
    A mean would call them equal (0.49 vs 0.55 on a 0..1 scale, near-equal);
    the product says what the operator means — the second is far likelier to
    hurt."""
    hi_cvss = risk.assess(finding(cvss=9.8, cvss_vector=WIDE_OPEN_TOTAL),
                          intel(epss={"CVE-2026-0001": epss(0.001)}))
    hi_epss = risk.assess(finding(cvss=5.0, cvss_vector=WIDE_OPEN_DOS),
                          intel(epss={"CVE-2026-0001": epss(0.6)}))
    assert hi_cvss.score == pytest.approx(0.98 * 0.001, rel=1e-3)
    assert hi_epss.score == pytest.approx(0.5 * 0.6, rel=1e-3)
    assert hi_epss.score > 100 * hi_cvss.score


def test_kev_counts_as_certain_probability_in_the_ordering_number():
    a = risk.assess(finding(kev=True, cvss=7.5), intel(epss={"CVE-2026-0001": epss(0.001)}))
    assert a.risk["likelihood"] == 1.0 and a.risk["likelihood_basis"] == "kev"
    assert a.score == pytest.approx(0.75)


def test_within_one_colour_the_number_orders_and_the_colour_does_not_move():
    lo = risk.assess(finding(cvss=4.0), intel(epss={"CVE-2026-0001": epss(0.001)}))
    hi = risk.assess(finding(cvss=9.0), intel(epss={"CVE-2026-0001": epss(0.3)}))
    assert lo.color == hi.color == "green"
    assert hi.score > lo.score


# ---------------------------------------------------------------------------
# Pending reboot: urgency down one step, importance untouched
# ---------------------------------------------------------------------------
def test_a_pending_reboot_lowers_urgency_one_step_and_leaves_importance_alone():
    base = finding(cvss=7.5, cvss_vector=WIDE_OPEN_TOTAL)
    iv = intel(vulnrichment=active())
    live = risk.assess(base, iv)
    pending = risk.assess({**base, "fix_pending_reboot": True}, iv)
    assert (live.decision, pending.decision) == ("act", "attend")
    assert (live.color, pending.color) == ("red", "amber")
    assert pending.importance == live.importance
    assert pending.risk["decision_before_reboot"] == "act"
    assert pending.risk["reboot_pending"] is True


def test_a_pending_reboot_cannot_turn_a_grey_into_anything():
    a = risk.assess(finding(fix_pending_reboot=True), intel(vulnrichment={}))
    assert a.color == "grey" and "decision_before_reboot" not in a.risk


def test_a_pending_reboot_on_track_stays_track():
    a = risk.assess(finding(fix_pending_reboot=True), intel(epss={"CVE-2026-0001": epss(0.001)}))
    assert a.decision == "track"


# ---------------------------------------------------------------------------
# Where the CVSS came from, and saying so
# ---------------------------------------------------------------------------
def test_an_rpm_finding_is_scored_by_red_hat_and_the_page_can_say_so():
    f = finding(scanner="dnf", ecosystem="rpm", cvss=None, cvss_vector=None, severity="medium")
    a = risk.assess(f, intel(redhat={"CVE-2026-0001": rh_row(3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L", "Low")},
                             epss={"CVE-2026-0001": epss(0.0045, 0.3682)}))
    assert a.risk["cvss"] == {"source": "redhat", "score": 3.1,
                              "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L",
                              "version": "3.1", "vendor_severity": "Low"}
    assert a.cvss_score == 3.1 and a.write_cvss is True
    assert a.importance == 0.31


def test_the_vendor_is_preferred_over_the_scanners_own_for_rpm():
    f = finding(scanner="trivy_image", ecosystem="rpm", cvss=9.9,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    a = risk.assess(f, intel(redhat={"CVE-2026-0001": rh_row(5.0, LOCAL_TOTAL)},
                             epss={"CVE-2026-0001": epss(0.001)}))
    assert a.risk["cvss"]["source"] == "redhat"
    assert a.write_cvss is False       # the scanner's value is left where it is


def test_a_non_rpm_finding_never_consults_red_hat():
    f = finding(ecosystem="npm")
    a = risk.assess(f, intel(redhat={"CVE-2026-0001": rh_row(1.0, LOCAL_TOTAL)},
                             epss={"CVE-2026-0001": epss(0.001)}))
    assert a.risk["cvss"]["source"] == "trivy" and a.cvss_score == 7.5


def test_osv_fills_the_gap_for_a_finding_the_scanner_could_not_score():
    f = finding(cvss=None, cvss_vector=None)
    row = osv_mod.Row("found", 7.5, WIDE_OPEN_DOS, "3.1", "HIGH", (), None)
    a = risk.assess(f, intel(osv={"CVE-2026-0001": row}, epss={"CVE-2026-0001": epss(0.004)}))
    assert a.color == "green" and a.risk["cvss"]["source"] == "osv"
    assert a.write_cvss is True and a.cvss_vector == WIDE_OPEN_DOS


def test_the_scanners_evidence_beats_osv():
    row = osv_mod.Row("found", 1.0, LOCAL_TOTAL, "3.1", "LOW", (), None)
    a = risk.assess(finding(), intel(osv={"CVE-2026-0001": row}, epss={"CVE-2026-0001": epss(0.004)}))
    assert a.risk["cvss"]["source"] == "trivy"


def test_what_we_wrote_into_the_columns_last_time_is_not_taken_for_the_scanners():
    """Red Hat's vector sits in `findings.cvss_vector` after the first pass. The
    next pass reads that column back; if it took it for trivy's, the page would
    credit Red Hat's evaluation to the scanner (and, if Red Hat's row later
    vanished, keep deciding on it with no source behind it)."""
    prior = {"cvss": {"source": "redhat", "score": 7.5, "vector": WIDE_OPEN_DOS}}
    f = finding(scanner="dnf", ecosystem="rpm", cvss=7.5, cvss_vector=WIDE_OPEN_DOS, risk=prior)
    a = risk.assess(f, intel(epss={"CVE-2026-0001": epss(0.004)}))     # no redhat row any more
    assert "cvss" in a.risk["missing"] and a.color == "grey"


def test_a_scanner_value_that_differs_from_what_we_wrote_is_the_scanners():
    prior = {"cvss": {"source": "redhat", "score": 5.0, "vector": LOCAL_TOTAL}}
    f = finding(cvss=7.5, cvss_vector=WIDE_OPEN_DOS, risk=prior)
    a = risk.assess(f, intel(epss={"CVE-2026-0001": epss(0.004)}))
    assert a.risk["cvss"]["source"] == "trivy"


def test_a_v4_vector_decides_but_importance_is_an_estimate_and_says_so():
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    f = finding(cvss=None, cvss_vector=None, severity="critical")
    row = osv_mod.Row("found", None, v4, "4.0", "CRITICAL", (), None)
    a = risk.assess(f, intel(osv={"CVE-2026-0001": row}, vulnrichment=active()))
    assert a.color == "red"
    assert a.importance == 0.95 and a.risk["importance_basis"] == "severity"
    assert a.risk["cvss"]["estimated"] is True and a.risk["cvss"]["score"] is None


def test_an_unrated_redhat_record_falls_through_to_the_next_source():
    f = finding(scanner="dnf", ecosystem="rpm", cvss=None, cvss_vector=None)
    unrated = rh_row(None, None, "Low")
    row = osv_mod.Row("found", 7.5, WIDE_OPEN_DOS, "3.1", None, (), None)
    a = risk.assess(f, intel(redhat={"CVE-2026-0001": unrated}, osv={"CVE-2026-0001": row},
                             epss={"CVE-2026-0001": epss(0.004)}))
    assert a.risk["cvss"]["source"] == "osv"


def test_a_not_found_vendor_answer_is_not_a_score():
    f = finding(scanner="dnf", ecosystem="rpm", cvss=None, cvss_vector=None)
    a = risk.assess(f, intel(redhat={"CVE-2026-0001": rh_row(status="not_found")},
                             epss={"CVE-2026-0001": epss(0.004)}))
    assert a.color == "grey"


# ---------------------------------------------------------------------------
# The other two decision points
# ---------------------------------------------------------------------------
def test_a_host_that_is_not_exposed_cannot_be_automatably_attacked():
    """SSVC's own guidance: if the system is not reachable from the internet,
    reconnaissance cannot be automated, so Automatable is `no`."""
    iv = intel(vulnrichment=active())
    open_ = risk.assess(finding(), iv, exposed=True)
    closed = risk.assess(finding(), iv, exposed=False)
    assert open_.risk["points"]["automatable"]["value"] == "yes"
    assert closed.risk["points"]["automatable"] == {"value": "no", "basis": "asset_not_exposed"}
    assert closed.risk["exposed"] is False


@pytest.mark.parametrize("criticality,mission", [(1, "low"), (2, "low"), (3, "medium"),
                                                 (4, "high"), (5, "high")])
def test_mission_follows_asset_criticality(criticality, mission):
    assert risk.mission_for(criticality) == mission
    a = risk.assess(finding(), intel(epss={"CVE-2026-0001": epss(0.004)}), criticality=criticality)
    assert a.risk["points"]["mission"]["value"] == mission


def test_an_essential_mission_changes_the_colour_of_an_automatable_cve():
    """The single most consequential input of the tree, measured on the host:
    812 open findings are 4 non-green with Mission=medium and 277 with
    Mission=high. The test pins the mechanism (not the count)."""
    iv = intel(epss={"CVE-2026-0001": epss(0.004)})
    assert risk.assess(finding(), iv, criticality=3).color == "green"
    assert risk.assess(finding(), iv, criticality=5).color == "amber"


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    {"cve": 12345}, {"severity": None}, {"cvss": "high"}, {"risk": "{not json"},
    {"cvss_vector": b"bytes"}, {"scanner": None}, {"kev_due_date": object()},
])
def test_assess_never_raises_on_a_strange_row(bad):
    """A row the scanner wrote strangely must not stop the nightly scan: it comes
    out grey (or evaluated), never as an exception."""
    a = risk.assess(finding(**bad), intel())
    assert a.color in ("grey", "green", "amber", "red")
    assert 0 <= a.priority <= 100


def test_risk_json_is_structured_facts_only_so_it_can_travel_to_the_external_witness():
    """`findings.risk` is shipped to the aggregator, whose edge scores
    command-line-shaped text and stops a stream permanently after a few 403s.
    Everything in it is a number, an enum word, an id, a date or a CVSS vector
    (vectors already travel in `findings.cvss_vector`). The vendor's prose
    stays local."""
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    scenarios = {
        # Red Hat (the only source with prose), unrated epss path
        "redhat": (finding(scanner="dnf", ecosystem="rpm", cvss=None, cvss_vector=None),
                   intel(redhat={"CVE-2026-0001": rh_row()},
                         epss={"CVE-2026-0001": epss(0.5, 0.9)})),
        # a KEV hit, with a pending reboot, an unexposed asset
        "kev": (finding(kev=True, fix_pending_reboot=True),
                intel(kev={"CVE-2026-0001": date(2026, 10, 9)},
                      epss={"CVE-2026-0001": epss(0.006)})),
        # grey: nothing known (missing/possible lists)
        "grey": (finding(cvss=None, cvss_vector=None), intel()),
        # an advisory resolved through an OSV alias, v4 vector, estimated importance
        "alias": (finding(cve=None, advisory_id="GHSA-2x7j-588g-ccc2", cvss=None,
                          cvss_vector=None, severity="critical"),
                  intel(osv={"GHSA-2x7j-588g-ccc2": osv_mod.Row(
                      "found", None, v4, "4.0", "CRITICAL", ("CVE-2026-92596",), None)},
                      epss={"CVE-2026-92596": epss(0.95)})),
        "stale": (finding(), intel(epss={"CVE-2026-0001": epss(0.1, days_old=30)})),
        # Sentinel's overlay: a record of numbers, dates and enum words
        "overlay": (finding(), intel(vulnrichment=stale_photo(),
                                     epss={"CVE-2026-0001": epss(0.9)})),
    }
    allowed = re.compile(r"^[A-Za-z0-9_:.\-/ ]{1,100}$")

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                assert allowed.match(k), k
                yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)
        elif isinstance(node, str):
            yield node

    for name, (f, iv) in scenarios.items():
        a = risk.assess(f, iv, exposed=(name != "kev"))
        strings = list(walk(a.risk))
        assert strings, name
        assert all(allowed.match(s) for s in strings), (name, strings)
        dumped = json.dumps(a.risk)
        assert "justification" not in dumped and "because" not in dumped, name


def test_a_vector_only_osv_record_is_not_taken_for_the_scanners_on_the_next_pass():
    """Found by rehearsing the pass on production's real findings: OSV returns a
    CVSS v4 vector with no score, so `findings.cvss` stays NULL beside the vector we
    wrote. If "no score" never equalled "no score", the next pass took our own vector
    for the scanner's, flipped the named source from OSV to trivy, and rewrote the
    row (7 "changed" rows on a pass that should change nothing) with the wrong
    deciding source on the page."""
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    row = osv_mod.Row("found", None, v4, "4.0", "CRITICAL", (), None)
    iv = intel(osv={"CVE-2026-0001": row}, epss={"CVE-2026-0001": epss(0.004)})
    f = finding(cvss=None, cvss_vector=None, severity="critical")
    first = risk.assess(f, iv)
    assert first.risk["cvss"]["source"] == "osv" and first.write_cvss is True

    # What the pass stored, read back as the next pass sees the row.
    stored = {**f, "cvss": first.cvss_score, "cvss_vector": first.cvss_vector,
              "risk": first.risk}
    second = risk.assess(stored, iv)
    assert second.risk == first.risk, "the second pass rewrote the row"
    assert second.risk["cvss"]["source"] == "osv"


def test_two_missing_scores_are_the_same_value():
    assert risk._same_number(None, None) is True
    assert risk._same_number(None, 7.5) is False and risk._same_number(7.5, None) is False
    assert risk._same_number(7.5, "7.5") is True and risk._same_number("x", 7.5) is False


# ---------------------------------------------------------------------------
# CISA's published points: used first, the vector only as a fallback
# ---------------------------------------------------------------------------
def test_published_automatable_and_impact_beat_the_vector_heuristics():
    """The vector says "wide open, total" (Automatable yes, Technical Impact total).
    CISA, who looked at the CVE, says no and partial. Measured on 189 of the host's
    CVEs, the vector rule disagrees with CISA's Automatable on 38 and with the
    Technical Impact on 10 (read as `C:H and I:H`) or 40 (as `C:H or I:H`).
    The published value decides, and the page names who said it."""
    row = {"CVE-2026-0001": vr("active", "no", "partial")}
    a = risk.assess(finding(cvss_vector=WIDE_OPEN_TOTAL, cvss=9.8), intel(vulnrichment=row))
    pts = a.risk["points"]
    assert (pts["automatable"]["value"], pts["automatable"]["basis"]) == ("no", "vulnrichment")
    assert (pts["technical_impact"]["value"], pts["technical_impact"]["basis"]) == (
        "partial", "vulnrichment")
    assert pts["technical_impact"]["as_of"] == "2026-09-01"
    assert (a.color, a.decision) == ("green", "track")     # active / no / partial / medium


def test_the_vector_fills_only_the_point_cisa_did_not_publish():
    row = {"CVE-2026-0001": vr("none", automatable="no")}      # no Technical Impact
    a = risk.assess(finding(cvss_vector=WIDE_OPEN_TOTAL, cvss=9.8), intel(vulnrichment=row))
    pts = a.risk["points"]
    assert pts["automatable"]["basis"] == "vulnrichment"
    assert (pts["technical_impact"]["value"], pts["technical_impact"]["basis"]) == (
        "total", "cvss_vector")


def test_a_cve_with_all_three_points_published_needs_no_cvss_to_be_decided():
    """CISA's points are the tree's inputs; a missing CVSS vector no longer leaves
    the row undecided. The importance axis falls back to the severity (and says so),
    and `missing` does not list a CVSS the decision did not need."""
    row = {"CVE-2026-0001": vr("none", "yes", "total")}
    a = risk.assess(finding(cvss=None, cvss_vector=None, severity="high"),
                    intel(vulnrichment=row))
    assert a.color == "green" and a.decision == "track"
    assert "missing" not in a.risk
    assert a.risk["importance_basis"] == "severity" and a.risk["cvss"]["estimated"] is True


def test_kev_beats_a_stale_published_none():
    """KEV is refreshed daily; a CISA evaluation is a snapshot (CVE-2024-53150 was
    evaluated after it entered KEV, but a CVE added to KEV last week may still
    carry last month's `none`). In KEV means active."""
    stale = {"CVE-2026-0001": vr("none", at=datetime(2025, 1, 1, tzinfo=timezone.utc))}
    a = risk.assess(finding(), intel(vulnrichment=stale, kev={"CVE-2026-0001": date(2026, 10, 9)}))
    assert a.risk["points"]["exploitation"] == {"value": "active", "basis": "kev"}


def test_a_published_active_counts_as_certain_probability_like_kev():
    a = risk.assess(finding(cvss=7.5), intel(vulnrichment=active(),
                                             epss={"CVE-2026-0001": epss(0.001)}))
    assert a.risk["likelihood"] == 1.0 and a.risk["likelihood_basis"] == "vulnrichment"
    assert a.score == pytest.approx(0.75)


def test_published_active_needs_no_kev_mirror_but_published_none_does():
    """"Active" can only be revised upward, so it stands with a dead KEV mirror;
    "none" or "poc" is a claim that KEV may have overtaken, and cannot be made
    without a fresh mirror."""
    assert risk.assess(finding(), intel(vulnrichment=active(), kev_usable=False)).color == "amber"
    a = risk.assess(finding(), intel(kev_usable=False))
    assert a.color == "grey" and a.risk["missing"] == ["kev_mirror"]


@pytest.mark.parametrize("name,f,iv", [
    ("published", finding(), intel(vulnrichment={"CVE-2026-0001": vr("poc", "yes", "total")})),
    ("unpublished", finding(), intel(vulnrichment={"CVE-2026-0001": vr(None)})),
    ("kev", finding(kev=True), intel()),
    ("vector-only", finding(), intel(vulnrichment={"CVE-2026-0001": vr(None, status="not_found")})),
])
def test_every_known_decision_point_names_the_source_that_decided_it(name, f, iv):
    """Provenance: a point with a value and no `basis` is a claim with no author,
    and a CISA-sourced point without its `as_of` hides how old the snapshot is."""
    a = risk.assess(f, iv, exposed=True)
    for key, point in a.risk["points"].items():
        assert point["value"] is not None, (name, key)
        assert point["basis"] in {"kev", "vulnrichment", "kev_absent", "cvss_vector",
                                  "asset_criticality", "asset_not_exposed"}, (name, key, point)
        if point["basis"] == "vulnrichment":
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", point["as_of"]), (name, key, point)
        else:
            assert "as_of" not in point, (name, key, point)
