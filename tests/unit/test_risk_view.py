"""The words the operator reads for a colour.

The failure these tests prevent: the same finding described differently on two
screens ("roșu" in the panel, "galben" in the bot), or EPSS shown rounded to
"0%" — which reads as "impossible" — when the probability is 0.05%, or a grey
that does not say what is missing and so cannot be acted on.
"""

from __future__ import annotations

import pytest

from sentinel.scan import risk_view as rv


@pytest.mark.parametrize("p,pct,expected", [
    (0.0045, 0.3682, "0,45% (percentila 37)"),
    (0.153, 0.92, "15,3% (percentila 92)"),                # FIRST's own example form
    (0.99225, 0.99936, "99,2% (percentila 100)"),
    (0.0005, None, "0,05%"),
    (0.00004, None, "<0,01%"),
    (0.0, None, "<0,01%"),
    (1, None, "100,0%"),
    (0.1225, None, "12,3%"),          # an exact half: rounds up, in both languages
    (0.00125, None, "0,13%"),
    (0.00145, None, "0,15%"),          # 0.145: binary toFixed would say 0,14
    (0.00405, None, "0,41%"),
    (0.00615, None, "0,62%"),
    ("0.0045", "0.3682", "0,45% (percentila 37)"),         # numeric(5,4) arrives as str/Decimal
    (None, None, "fără EPSS"),
    ("garbage", None, "fără EPSS"),
    (True, None, "fără EPSS"),
    (float("nan"), None, "fără EPSS"),
])
def test_epss_is_shown_as_a_whole_probability_with_percentile_never_rounded_to_zero(p, pct, expected):
    """FIRST: show the probability WITH the percentile, unbinned. Under 1% two
    decimals, because 0.45% and 0.05% are not the same risk and "0%" says the
    event is impossible."""
    assert rv.fmt_epss(p, pct) == expected


@pytest.mark.parametrize("cvss,expected", [
    ({"score": 3.1, "source": "redhat"}, "CVSS 3,1 (Red Hat)"),
    ({"score": 7.5, "source": "trivy"}, "CVSS 7,5 (trivy)"),
    ({"score": 9.8, "source": "osv"}, "CVSS 9,8 (OSV)"),
    ({"score": 7.5, "source": "mystery"}, "CVSS 7,5"),
    ({"score": None, "estimated": True}, "CVSS fără scor numeric (importanță estimată din severitate)"),
    ({"score": None}, "fără CVSS"),
    (None, "fără CVSS"),
    ("x", "fără CVSS"),
])
def test_cvss_names_the_source_that_decided_it(cvss, expected):
    assert rv.fmt_cvss(cvss) == expected


def test_headline_pairs_colour_and_decision_and_never_makes_up_a_green():
    assert rv.headline("red", "act") == "🔴 Acum"
    assert rv.headline("amber", "attend") == "🟡 Curând"
    assert rv.headline("green", "track_star") == "🟢 De urmărit*"
    assert rv.headline("green", "track") == "🟢 Ciclul obișnuit"
    assert rv.headline("grey", None) == "⚪ Nedecis"
    assert rv.headline("nonsense", None) == "⚪ Nedecis"


def test_track_and_track_star_do_not_read_the_same():
    """The operator's table proposed "De urmărit" for BOTH, which leaves an asterisk as the
    only difference between a row SSVC says to follow closely and one it says to leave in
    the normal cycle. A reader who sees a green list full of "De urmărit" learns to skip
    the word, and the starred ones are the ones that ask for a closer look."""
    track, star = rv.DECISION_LABEL_RO["track"], rv.DECISION_LABEL_RO["track_star"]
    assert track != star and track.rstrip("*") != star.rstrip("*")
    assert star.endswith("*") and not track.endswith("*")


def test_every_decision_keeps_its_ssvc_name_for_traceability():
    """The labels lead with what to do, so the CISA name must still be reachable: without
    it nobody can look a row up in the published tree."""
    assert {d: rv.ssvc_name(d) for d in ("act", "attend", "track_star", "track")} == {
        "act": "Act", "attend": "Attend", "track_star": "Track*", "track": "Track"}
    assert rv.ssvc_name(None) is None and rv.ssvc_name("bogus") is None
    for decision, name in (("act", "Act"), ("attend", "Attend"), ("track", "Track")):
        assert any(f"Decizie CISA SSVC: {name}" in line
                   for line in rv.why_lines({"decision": decision})), decision


def test_a_grey_cell_says_only_what_is_missing_and_the_detail_says_the_rest():
    """The failure the operator rejected: a paragraph where a label belongs ("lipsește CVE
    (fără el nu există EPSS sau KEV); ar putea fi între Track și Attend", six lines tall in
    a narrow column). The cell keeps the missing datum; the long reasoning moved to the
    detail, which is where `why_lines` already is."""
    risk = {"decision": None, "missing": ["cve"], "possible": ["track", "attend"]}
    assert rv.grey_reason(risk) == "fără CVE"
    assert rv.reason_line("grey", risk) == "fără CVE"
    detail = rv.grey_detail(risk)
    assert detail == ("lipsește CVE (fără el nu există EPSS sau KEV); "
                      "ar putea fi între Track și Attend")
    # The state's name in the detail line is the label source's, not a literal repeated here.
    assert f"{rv.COLOR_STATE_RO['grey']}: " + detail in rv.why_lines(risk),         "the long reasoning went nowhere"
    assert "ar putea" not in rv.grey_reason(risk)


def test_a_grey_with_several_missing_data_lists_each_once_and_unknown_codes_stay_visible():
    risk = {"decision": None, "missing": ["cve", "kev_mirror", "cve"]}
    assert rv.grey_reason(risk) == "fără CVE, KEV nelegibil"
    # A code the vocabulary does not know shows as itself: it must not vanish, and a grey
    # with nothing to say must not read as fine.
    assert rv.grey_reason({"decision": None, "missing": ["something_new"]}) == "something_new"
    assert rv.grey_reason({"decision": None, "missing": []}) == "decizia nu se poate lua"
    # `assessment_error` has no short form; its full phrase is already short.
    assert rv.grey_reason({"decision": None, "missing": ["assessment_error"]}) == (
        "evaluarea a eșuat")


def test_a_grey_whose_whole_range_is_one_decision_says_so_in_the_detail():
    """Not a green, but a grey that can be dismissed in one glance."""
    risk = {"decision": None, "missing": ["cvss"], "possible": ["track", "track"]}
    assert rv.grey_detail(risk).endswith("oricum ar fi Track")


def test_a_decided_row_has_no_grey_text_and_the_cell_label_is_never_a_green():
    assert rv.grey_reason({"decision": "track"}) is None
    assert rv.grey_detail({"decision": "track"}) is None
    assert "Nedecis" not in " ".join(rv.why_lines({"decision": "track"}))
    assert rv.headline("grey", None).startswith("⚪")


def _codes_risk_py_can_emit() -> set[str]:
    """The `missing` codes written in `risk.py`, READ FROM ITS SOURCE rather than
    listed here: a hand-kept list is how a code added in one file reaches the
    operator as a bare token because nobody remembered the other."""
    import ast
    from pathlib import Path

    tree = ast.parse((Path(rv.__file__).parent / "risk.py").read_text(encoding="utf-8"))
    codes: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append" and isinstance(node.func.value, ast.Name)
                and node.func.value.id in ("missing", "problems")
                and node.args and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            codes.add(node.args[0].value)
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == "missing"
                        and isinstance(value, ast.List)):
                    codes |= {e.value for e in value.elts
                              if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return codes


def test_every_missing_code_the_assessor_can_emit_has_words():
    """A code without a translation would reach the operator as a bare token."""
    emitted = _codes_risk_py_can_emit()
    # Positive control: the reader found the codes (an empty set would pass for ever).
    assert {"cvss", "cvss_vector", "cve", "kev_mirror", "vulnrichment",
            "exploitation_unpublished", "assessment_error"} <= emitted, emitted
    assert emitted <= set(rv._MISSING_RO), emitted - set(rv._MISSING_RO)
    for code in emitted:
        text = rv.grey_reason({"decision": None, "missing": [code]})
        assert code not in text, text
        assert code not in rv.grey_detail({"decision": None, "missing": [code]})
        # The list row must not fall back to "fără date" either — the old NAME of the state,
        # which `assessment_error` used to reach because it had no short form (the exemption
        # that stood here was the defect, written down as a rule).
        assert rv.one_liner("grey", {"missing": [code]}) != "fără date", code


def test_a_decided_finding_has_no_grey_reason_and_an_unevaluated_one_says_so():
    assert rv.grey_reason({"decision": "track"}) is None
    assert rv.grey_reason({}) == "încă neevaluată"
    assert rv.grey_reason(None) == "încă neevaluată"
    assert rv.grey_detail({}) == "încă neevaluată"


def test_one_liner_gives_the_strongest_single_reason():
    kev = {"points": {"exploitation": {"value": "active", "basis": "kev"}}, "reboot_pending": True}
    assert rv.one_liner("amber", kev) == "exploatat activ (KEV) 🔁"
    epss = {"points": {"exploitation": {"value": "active", "basis": "epss"}},
            "epss": {"p": 0.92}}
    assert rv.one_liner("amber", epss) == "EPSS 92,0%"
    assert rv.one_liner("grey", {"missing": ["epss"]}) == "fără EPSS"
    assert rv.one_liner("grey", {"missing": ["cve"]}) == "fără CVE"
    assert rv.one_liner("green", {}) == "neevaluat"


def test_counts_line_orders_red_amber_grey_green_and_always_mentions_grey():
    """Grey is never left out: "no grey" is a fact worth stating, and silence
    about it is how unknowns hide."""
    assert rv.counts_line({"red": 1, "amber": 3, "grey": 25, "green": 783}) == (
        "🔴 1 · 🟡 3 · ⚪ 25 · 🟢 783")
    assert rv.counts_line({"green": 5}) == "⚪ 0 · 🟢 5"
    assert rv.counts_line({}) == "—"


def test_why_lines_cover_points_sources_axes_and_the_reboot_note():
    risk = {
        "points": {"exploitation": {"value": "active", "basis": "kev"},
                   "automatable": {"value": "no", "basis": "cvss_vector"},
                   "technical_impact": {"value": "total", "basis": "cvss_vector"},
                   "mission": {"value": "medium", "basis": "asset_criticality"}},
        "decision": "attend", "reboot_pending": True, "decision_before_reboot": "act",
        "cvss": {"score": 7.5, "source": "redhat"},
        "epss": {"p": 0.0045, "percentile": 0.3682, "date": "2026-10-01"},
    }
    lines = rv.why_lines(risk)
    text = "\n".join(lines)
    assert "exploatat activ · neautomatizabil · impact total · misiune medie" in text
    assert "CVSS 7,5 (Red Hat) · EPSS 0,45% (percentila 37), din 2026-10-01" in text
    assert "exploatare: CISA KEV" in text
    assert "urgența a coborât o treaptă (de la Act); importanța a rămas aceeași" in text


def test_a_published_point_says_who_published_it_and_when():
    """CISA's Exploitation is a snapshot (CVE-2025-29927 reads `none` as of
    2025-04-08). A line that says "CISA Vulnrichment" without the date would let
    a year-old `none` read as today's."""
    risk = {"points": {"exploitation": {"value": "none", "basis": "vulnrichment",
                                        "as_of": "2025-04-08"},
                       "automatable": {"value": "yes", "basis": "vulnrichment",
                                       "as_of": "2025-04-08"},
                       "technical_impact": {"value": "total", "basis": "cvss_vector"},
                       "mission": {"value": "medium", "basis": "asset_criticality"}},
            "decision": "track"}
    text = "\n".join(rv.why_lines(risk))
    assert ("exploatare: CISA Vulnrichment (CISA-ADP, din înregistrarea CVE), "
            "evaluat la 2025-04-08") in text
    assert "impact tehnic: vector CVSS" in text and "evaluat la" not in text.split("impact tehnic")[1]
    unpublished = {"points": {"exploitation": {"value": "none", "basis": "kev_absent"}}}
    assert "presupunere" in "\n".join(rv.why_lines(unpublished))


def test_a_cisa_active_row_names_cisa_as_the_reason():
    active = {"points": {"exploitation": {"value": "active", "basis": "vulnrichment",
                                          "as_of": "2026-09-18"}}, "reboot_pending": True}
    assert rv.one_liner("amber", active) == "exploatat activ (CISA) 🔁"


def test_an_unknown_point_is_shown_as_unknown_not_left_out():
    risk = {"points": {"exploitation": {"value": None}, "automatable": {"value": "yes"},
                       "technical_impact": {"value": None}, "mission": {"value": "medium"}}}
    assert rv.points_line(risk) == "? exploatare · automatizabil · ? impact · misiune medie"


def test_a_risk_that_cannot_be_read_gives_text_not_an_exception():
    for bad in (None, {}, [], "x", {"points": "x"}, {"points": {"exploitation": 5}}):
        assert isinstance(rv.points_line(bad), str)
        assert isinstance(rv.why_lines(bad), list)
        assert isinstance(rv.one_liner("green", bad), str)


def test_dot_classes_exist_in_the_stylesheet():
    """A class name that is not in `sentinel.css` paints an invisible dot; the
    stylesheet is served `immutable`, so inventing a class means a new asset
    digest to ship."""
    from pathlib import Path
    css = (Path(__file__).parent.parent.parent / "sentinel" / "web" / "static" / "css"
           / "sentinel.css").read_text(encoding="utf-8")
    for cls in rv.DOT_CLASS.values():
        assert f".dot-{cls}" in css


# ---------------------------------------------------------------------------
# Sentinel's own rule must be labelled as Sentinel's, on every line that shows it
# ---------------------------------------------------------------------------
OVERLAY_RISK = {
    "decision": "attend",
    "points": {"exploitation": {"value": "none", "basis": "vulnrichment", "as_of": "2025-04-08"},
               "automatable": {"value": "yes", "basis": "vulnrichment", "as_of": "2025-04-08"},
               "technical_impact": {"value": "total", "basis": "vulnrichment",
                                    "as_of": "2025-04-08"},
               "mission": {"value": "medium", "basis": "asset_criticality"}},
    "epss": {"p": 0.99225, "percentile": 0.99936},
    "overlay": {"basis": "epss_overlay", "floor": "attend", "ssvc_decision": "track",
                "epss": 0.99225, "observation_as_of": "2025-04-08",
                "observation_age_days": 542, "min_epss": 0.5, "min_age_days": 180},
}


def test_an_overlay_row_does_not_pass_for_an_ssvc_decision_in_its_label():
    """The failure: an amber that SSVC did not give, shown as "🟡 Curând" like every
    other amber. The operator would read a published tree's verdict into a Sentinel
    threshold. The label says whose it is — in the six-word form the operator asked
    for, which must still be enough to tell the two apart at a glance."""
    lifted = rv.headline("amber", "attend", OVERLAY_RISK)
    assert lifted == "🟡 Curând · regula Sentinel"
    assert rv.headline("amber", "attend") == "🟡 Curând"        # no risk: unchanged
    assert rv.headline("amber", "attend", {"decision": "attend"}) == "🟡 Curând"
    assert lifted != rv.headline("amber", "attend")
    # The tree's own name must NOT sit beside the marker: "Attend · regula Sentinel" would
    # say the tree decided what it did not.
    assert "Attend" not in lifted
    assert not any("Decizie CISA SSVC" in line for line in rv.why_lines(OVERLAY_RISK))


def test_the_overlay_label_is_ignored_on_any_colour_it_does_not_explain():
    """A leftover `overlay` in a row whose colour is no longer amber (corrupt row,
    half-read replica) must not put Sentinel's tag on a green or a red."""
    for color, decision in (("green", "track"), ("red", "act"), ("grey", None)):
        assert "Sentinel" not in rv.headline(color, decision, OVERLAY_RISK)
        assert "Sentinel" not in rv.one_liner(color, OVERLAY_RISK)
        assert "CISA veche" not in (rv.reason_line(color, OVERLAY_RISK) or "")
    assert rv.headline("amber", "attend", {"overlay": {"basis": "something_else"}}) == (
        "🟡 Curând")
    assert rv.headline("amber", "attend", {"overlay": "x"}) == "🟡 Curând"


@pytest.mark.parametrize("color", ["green", "red", "grey"])
def test_the_overlay_guard_holds_when_colour_and_decision_disagree(color):
    """The test above pairs each colour with the decision that goes with it, so
    `headline`'s own `decision == "attend"` check turns the tag away first and the colour
    guard inside `overlay_of` is never what stops it. A row whose decision says Attend
    while its colour is not amber (a half-read replica, a row written by an older version)
    reaches the guard itself: without it the operator reads "regula Sentinel" on a green
    or a red, a lie about whose verdict that is. The Python/TypeScript parity test covers
    this too, but it is skipped wherever `aggregator/node_modules` is absent (every clean
    clone), which is exactly where nothing else would notice the guard gone."""
    assert rv.overlay_of(OVERLAY_RISK, color) is None
    assert rv.overlay_of(OVERLAY_RISK, "amber") is OVERLAY_RISK["overlay"]
    assert "Sentinel" not in rv.headline(color, "attend", OVERLAY_RISK)


def test_the_overlay_reason_fits_the_telegram_list_column_even_with_the_reboot_mark():
    """Telegram cuts the reason at `MAX_REASON_LIST` characters. A label cut in the
    middle ("regula Sent") is worse than none. The worst case is an EPSS that rounds to
    100,0% (EPSS tops out at 0.99999, which `fmt_epss` shows as 100,0%) with the reboot
    mark: measured, not assumed."""
    from sentinel.telegram import views
    worst = {**OVERLAY_RISK, "reboot_pending": True,
             "overlay": {**OVERLAY_RISK["overlay"], "epss": 0.99999}}
    assert rv.fmt_epss(0.99999) == "100,0%"
    for risk in (OVERLAY_RISK, {**OVERLAY_RISK, "reboot_pending": True}, worst):
        reason = rv.one_liner("amber", risk)
        assert reason.startswith(rv.OVERLAY_TAG_RO), reason
        assert len(reason) <= views.MAX_REASON_LIST, reason
    assert rv.one_liner("amber", worst) == "regula Sentinel · EPSS 100,0% 🔁"
    # Every other reason the list can carry fits too, in its longest form.
    longest = [
        rv.one_liner("amber", {"reboot_pending": True,
                               "points": {"exploitation": {"value": "active", "basis": "kev"}}}),
        rv.one_liner("amber", {"reboot_pending": True,
                               "points": {"exploitation": {"value": "active",
                                                           "basis": "vulnrichment"}}}),
        rv.one_liner("amber", {"reboot_pending": True, "epss": {"p": 0.99999}}),
        *(rv.one_liner("grey", {"missing": [code]})
          for code in {*rv._MISSING_SHORT_RO, *rv._MISSING_RO}),
    ]
    assert all(len(text) <= views.MAX_REASON_LIST for text in longest), longest


def test_the_detail_says_in_plain_words_whose_rule_it_is_why_and_what_ssvc_said():
    """`/vuln` and the panel's detail: Sentinel's name, "not SSVC, not FIRST", the
    age and the EPSS that triggered it with their thresholds, and the decision the
    published tree gave on its own."""
    lines = rv.why_lines(OVERLAY_RISK)
    sentence = next(line for line in lines if "SENTINEL" in line)
    assert "nu a SSVC, nu a FIRST" in sentence
    assert "e din 2025-04-08 (542 de zile; prag: peste 180)" in sentence
    assert "EPSS e 99,2% (prag: cel puțin 50%)" in sentence
    assert "SSVC singur ar fi dat Track." in sentence
    # An undated evaluation says so instead of inventing an age.
    undated = {**OVERLAY_RISK, "overlay": {**OVERLAY_RISK["overlay"],
                                           "observation_as_of": None,
                                           "observation_age_days": None}}
    assert "n-are dată" in next(line for line in rv.why_lines(undated) if "SENTINEL" in line)
    # No overlay, no sentence.
    plain = {k: v for k, v in OVERLAY_RISK.items() if k != "overlay"}
    assert not any("SENTINEL" in line for line in rv.why_lines(plain))


def test_a_lifted_row_lowered_by_a_reboot_says_the_attend_it_fell_from_was_sentinels():
    """The floor is applied before the reboot demotion, so a row Sentinel's rule lifted
    to Attend and whose fix then waits for a restart is Track* (green) with `overlay` and
    `decision_before_reboot = attend` in its record. The detail line "lowered one step
    from Attend" would send the operator looking for a CISA verdict that was never given:
    it must say the Attend was Sentinel's. A KEV row lowered from Act must not carry
    that tag, and the green row must not wear the amber label."""
    lowered = {**OVERLAY_RISK, "decision": "track_star", "reboot_pending": True,
               "decision_before_reboot": "attend"}
    line = next(x for x in rv.why_lines(lowered) if "repornire" in x)
    assert "de la Attend, urcat de regula Sentinel, nu SSVC" in line
    assert "Sentinel" not in rv.headline("green", "track_star", lowered)
    assert not any("SENTINEL" in x for x in rv.why_lines(lowered)), (
        "the amber explanation belongs to an amber row")
    kev = {"decision": "attend", "reboot_pending": True, "decision_before_reboot": "act",
           "points": {"exploitation": {"value": "active", "basis": "kev"}}}
    kev_line = next(x for x in rv.why_lines(kev) if "repornire" in x)
    assert "Sentinel" not in kev_line and "de la Act)" in kev_line


# ---------------------------------------------------------------------------
# The cell's second line: a reason, or nothing — never a repeat of the EPSS column
# ---------------------------------------------------------------------------
def test_a_green_whose_only_reason_is_a_low_epss_gets_no_second_line():
    """The operator rejected "Track* — de urmărit · EPSS 0,24%": a number that tells the
    reader nothing to act on, repeated from the EPSS column beside it. A line that says
    nothing is not drawn at all (an empty `<br>` would still cost a row of height)."""
    low = {"decision": "track", "epss": {"p": 0.0024},
           "points": {"exploitation": {"value": "none", "basis": "kev_absent"}}}
    assert rv.reason_line("green", low) is None
    assert rv.reason_line("green", {"decision": "track"}) is None
    # ... while the Telegram list, which needs SOMETHING between its separators, keeps it.
    assert rv.one_liner("green", low) == "EPSS 0,24%"


def test_a_green_with_an_epss_at_or_above_the_rule_threshold_keeps_its_line():
    """CISA says nothing is exploited, EPSS says it almost certainly is: that tension is
    news on a green row, and dropping every EPSS-only line would hide exactly it. The
    threshold is the Sentinel rule's own, not a number invented for the page."""
    from sentinel.scan import risk
    assert rv.NOTEWORTHY_EPSS == risk.OVERLAY_MIN_EPSS
    just_under = {"decision": "track", "epss": {"p": 0.4999}}
    at = {"decision": "track", "epss": {"p": 0.5}}
    high = {"decision": "track", "epss": {"p": 0.99225}}
    assert rv.reason_line("green", just_under) is None
    assert rv.reason_line("green", at) == "EPSS 50,0%"
    assert rv.reason_line("green", high) == "EPSS 99,2%"


def test_an_amber_or_red_whose_reason_is_epss_keeps_it_whatever_the_value():
    """On amber/red the EPSS IS why the row is there (SSVC's own exploitation point can
    come from EPSS); only a green may drop it."""
    epss = {"decision": "attend", "epss": {"p": 0.0024},
            "points": {"exploitation": {"value": "active", "basis": "epss"}}}
    assert rv.reason_line("amber", epss) == "EPSS 0,24%"
    assert rv.reason_line("red", epss) == "EPSS 0,24%"


def test_the_exploitation_reasons_read_as_what_is_known_not_as_a_bare_acronym():
    """"KEV" alone under "Curând" is the pair the operator could not parse."""
    kev = {"points": {"exploitation": {"value": "active", "basis": "kev"}}}
    cisa = {"points": {"exploitation": {"value": "active", "basis": "vulnrichment"}}}
    assert rv.reason_line("red", kev) == "exploatat activ (KEV)"
    assert rv.reason_line("red", cisa) == "exploatat activ (CISA)"
    assert rv.reason_line("red", {**kev, "reboot_pending": True}) == "exploatat activ (KEV)", (
        "the reboot mark is drawn from `reboot_pending` by the table, not carried by the text")


def test_the_overlay_reason_names_the_fact_and_not_the_rule_the_label_already_names():
    """The old reason, "regula Sentinel (EPSS)", repeated the marker above it and said
    nothing about WHY. Now it states the fact: an EPSS near certainty beside a CISA
    evaluation that is old (or undated — which cannot be proven fresh, but is not known
    to be 180 days old either)."""
    assert rv.reason_line("amber", OVERLAY_RISK) == "EPSS 99,2%, CISA veche"
    undated = {**OVERLAY_RISK, "overlay": {**OVERLAY_RISK["overlay"],
                                           "observation_as_of": None,
                                           "observation_age_days": None}}
    assert rv.reason_line("amber", undated) == "EPSS 99,2%, CISA nedatată"
    assert "Sentinel" not in rv.reason_line("amber", OVERLAY_RISK), (
        "the marker is already in the label above; repeating it is the old defect")


def test_a_grey_always_has_a_reason_line_so_it_cannot_read_as_fine():
    for risk in (None, {}, {"decision": None}, {"decision": None, "missing": ["epss"]},
                 {"decision": "act"}):                 # inconsistent: grey colour, a decision
        text = rv.reason_line("grey", risk)
        assert isinstance(text, str) and text, risk
    assert rv.reason_line("grey", {}) == "încă neevaluată"
    assert rv.reason_line("green", {}) == "neevaluat"


def test_the_label_and_reason_widths_stay_short_enough_for_one_line():
    """The failure: a RISC cell six lines tall ("🟡 Attend — accelerat (regula Sentinel, nu
    SSVC)" over "regula Sentinel (EPSS)" in a column that also had to hold eight others).
    The longest label is the lifted amber, and the reason lines are phrases, not
    paragraphs. Widths are in characters; the cell is given `min-width: 17rem`, which at
    the page's 0.97rem sans fits the longest label beside its dot and reboot tag."""
    labels = [rv.headline(c, d) for c in ("red", "amber", "green", "grey")
              for d in ("act", "attend", "track_star", "track", None)]
    labels.append(rv.headline("amber", "attend", OVERLAY_RISK))
    assert max(map(len, labels)) <= 27, max(labels, key=len)
    assert len(rv.headline("amber", "attend", OVERLAY_RISK)) == len("🟡 Curând · regula Sentinel")
    reasons = [rv.reason_line("amber", OVERLAY_RISK), rv.reason_line("red", {
                   "points": {"exploitation": {"value": "active", "basis": "vulnrichment"}}}),
               *(rv.reason_line("grey", {"decision": None, "missing": [code]})
                 for code in rv._MISSING_SHORT_RO),
               rv.reason_line("grey", {"decision": None, "missing": ["cve", "kev_mirror"]})]
    assert max(map(len, reasons)) <= 32, max(reasons, key=len)


# ---------------------------------------------------------------------------
# KEV: "no" is only said when somebody looked
# ---------------------------------------------------------------------------
def test_kev_says_yes_with_the_due_date_and_no_only_when_the_list_was_consulted():
    """The failure: a "nu" in the KEV column for a row that has no CVE, or whose KEV mirror
    could not be read — reassurance about exactly what was not checked."""
    evaluated = {"decision": "track", "missing": []}
    assert rv.fmt_kev(True, "2026-10-12", evaluated) == "da — 2026-10-12"
    assert rv.fmt_kev(True, None, evaluated) == "da"
    assert rv.fmt_kev(True, "", None) == "da", "a row that IS in the catalogue is a yes, evaluated or not"
    assert rv.fmt_kev(False, None, evaluated) == "nu"
    assert rv.fmt_kev(False, None, {"decision": None, "missing": ["epss"]}) == "nu"
    for unknown in (None, {}, {"decision": None, "missing": ["cve"]},
                    {"decision": None, "missing": ["epss", "kev_mirror"]}):
        assert rv.fmt_kev(False, None, unknown) == "nu se știe", unknown


def test_kev_says_it_does_not_know_for_a_row_whose_assessment_crashed():
    """A crashed assessment (`risk._unassessable`) keeps the PREVIOUS `kev` flag; nobody looked
    the CVE up today. A "nu" there would be the reassurance about what was not checked that the
    rule above forbids. The risk is built by the producer itself, so a renamed marker
    cannot leave this test passing on a vocabulary the pass no longer writes."""
    from sentinel.scan import risk as risk_mod
    crashed = risk_mod._unassessable({"cve": "CVE-2026-1", "kev": False}, "KeyError: x").risk
    assert crashed["missing"] == ["assessment_error"]
    assert rv.fmt_kev(False, None, crashed) == "nu se știe"
    # ... while a yes stays a yes: the old flag said "in the catalogue", and that was a lookup.
    assert rv.fmt_kev(True, "2026-10-12", crashed) == "da — 2026-10-12"
