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
    assert rv.headline("red", "act") == "🔴 Act — acum"
    assert rv.headline("amber", "attend") == "🟡 Attend — accelerat"
    assert rv.headline("green", "track_star") == "🟢 Track* — de urmărit"
    assert rv.headline("green", "track") == "🟢 Track — ciclul obișnuit"
    assert rv.headline("grey", None) == "⚪ fără date"
    assert rv.headline("nonsense", None) == "⚪ fără date"


def test_a_grey_says_what_is_missing_and_how_bad_it_could_be():
    risk = {"decision": None, "missing": ["epss"], "possible": ["track", "attend"]}
    assert rv.grey_reason(risk) == (
        "lipsește EPSS (nu există încă pentru acest CVE); ar putea fi între Track și Attend")


def test_a_grey_whose_whole_range_is_one_decision_says_so():
    """Not a green, but a grey that can be dismissed in one glance."""
    risk = {"decision": None, "missing": ["cvss"], "possible": ["track", "track"]}
    assert rv.grey_reason(risk).endswith("oricum ar fi Track")


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
        # The short reason must not be the generic one either (assessment_error is
        # a fault, not a missing input, and is the one allowed to be generic).
        assert (rv.one_liner("grey", {"missing": [code]}) != "fără date"
                or code == "assessment_error"), code


def test_a_decided_finding_has_no_grey_reason_and_an_unevaluated_one_says_so():
    assert rv.grey_reason({"decision": "track"}) is None
    assert rv.grey_reason({}) == "încă neevaluată"
    assert rv.grey_reason(None) == "încă neevaluată"


def test_one_liner_gives_the_strongest_single_reason():
    kev = {"points": {"exploitation": {"value": "active", "basis": "kev"}}, "reboot_pending": True}
    assert rv.one_liner("amber", kev) == "KEV 🔁"
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
    assert "urgența a coborât o treaptă (de la Act — acum); importanța a rămas aceeași" in text


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
    assert rv.one_liner("amber", active) == "CISA: exploatat 🔁"


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
    """The failure: an amber that SSVC did not give, shown as "🟡 Attend —
    accelerat" like every other Attend. The operator would read a published
    tree's verdict into a Sentinel threshold. The label says whose it is."""
    assert rv.headline("amber", "attend", OVERLAY_RISK) == (
        "🟡 Attend — accelerat (regula Sentinel, nu SSVC)")
    assert rv.headline("amber", "attend") == "🟡 Attend — accelerat"        # no risk: unchanged
    assert rv.headline("amber", "attend", {"decision": "attend"}) == "🟡 Attend — accelerat"


def test_the_overlay_label_is_ignored_on_any_colour_it_does_not_explain():
    """A leftover `overlay` in a row whose colour is no longer amber (corrupt row,
    half-read replica) must not put Sentinel's tag on a green or a red."""
    for color, decision in (("green", "track"), ("red", "act"), ("grey", None)):
        assert "Sentinel" not in rv.headline(color, decision, OVERLAY_RISK)
        assert rv.one_liner(color, OVERLAY_RISK) != rv.OVERLAY_REASON_RO
    assert rv.headline("amber", "attend", {"overlay": {"basis": "something_else"}}) == (
        "🟡 Attend — accelerat")
    assert rv.headline("amber", "attend", {"overlay": "x"}) == "🟡 Attend — accelerat"


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
    middle ("regula Sentinel (EP") is worse than none."""
    from sentinel.telegram import views
    for risk in (OVERLAY_RISK, {**OVERLAY_RISK, "reboot_pending": True}):
        reason = rv.one_liner("amber", risk)
        assert reason.startswith(rv.OVERLAY_REASON_RO)
        assert len(reason) <= views.MAX_REASON_LIST, reason


def test_the_detail_says_in_plain_words_whose_rule_it_is_why_and_what_ssvc_said():
    """`/vuln` and the panel's detail: Sentinel's name, "not SSVC, not FIRST", the
    age and the EPSS that triggered it with their thresholds, and the decision the
    published tree gave on its own."""
    lines = rv.why_lines(OVERLAY_RISK)
    sentence = next(line for line in lines if "SENTINEL" in line)
    assert "nu a SSVC, nu a FIRST" in sentence
    assert "e din 2025-04-08 (542 de zile; prag: peste 180)" in sentence
    assert "EPSS e 99,2% (prag: cel puțin 50%)" in sentence
    assert "SSVC singur ar fi dat Track — ciclul obișnuit" in sentence
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
    assert "de la Attend — accelerat, urcat de regula Sentinel, nu SSVC" in line
    assert "Sentinel" not in rv.headline("green", "track_star", lowered)
    assert not any("SENTINEL" in x for x in rv.why_lines(lowered)), (
        "the amber explanation belongs to an amber row")
    kev = {"decision": "attend", "reboot_pending": True, "decision_before_reboot": "act",
           "points": {"exploitation": {"value": "active", "basis": "kev"}}}
    kev_line = next(x for x in rv.why_lines(kev) if "repornire" in x)
    assert "Sentinel" not in kev_line and "de la Act — acum" in kev_line
